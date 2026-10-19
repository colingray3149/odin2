//! Production projection bridge from a live `odin-browser` session into Huginn.

use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use odin_browser::capability::ActivationStructure;
use odin_browser::session::{
    BrowserHandle, BrowserSession, PreparedActionView, SessionEvent, SessionTeardown,
    TakeoverLeaseExpiry,
};
use odin_browser::StructuralAction;
use odin_domain::huginn::{
    ArtifactKind, ArtifactRef, BrowserDownloadStatus, BrowserDownloadView, BrowserSessionState,
    BrowserSessionView, ContentSource, HuginnMessage, ObjectKind, ObjectRef, Revision,
    RevisionSource,
};
use odin_domain::{CapabilityId, CommandId, Digest, EffectClass};
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::kube::view::{freshness, object_snapshot};
use crate::read_model::MaterializedReadModel;
use crate::service::{BrowserArtifactKind, FsExternalContentIndex, FsPublishedArtifactStore};
use crate::streams::{BoundedMultiplexer, MultiplexedItem};

const TIMELINE_DISPLAY_NAME: &str = "browser-action-timeline.jsonl";
const TIMELINE_MEDIA_TYPE: &str = "application/x-ndjson";

/// Explicit bounds for the projection control queue and redacted action timeline.
#[derive(Clone, Copy, Debug)]
pub struct BrowserProjectionConfig {
    pub command_capacity: NonZeroUsize,
    pub max_timeline_records: NonZeroUsize,
    pub max_timeline_bytes: NonZeroUsize,
}

/// Terminal state recorded for a prepared action. Arguments and page data are
/// intentionally absent from the durable timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BrowserActionOutcome {
    Applied,
    Denied,
    Failed,
    Unknown,
    Abandoned,
}

/// Digest-only durable evidence for one browser action decision/result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserActionRecord {
    pub command_id: CommandId,
    pub action_id: u64,
    pub action: StructuralAction,
    pub policy_action: StructuralAction,
    pub activation: ActivationStructure,
    pub capability_id: CapabilityId,
    pub capability_version: u64,
    pub effect_class: EffectClass,
    pub approval_required: bool,
    pub arguments_digest: Digest,
    pub policy_revision: u64,
    pub policy_digest: Digest,
    pub control_revision: u64,
    pub outcome: BrowserActionOutcome,
    pub observed_at: OffsetDateTime,
}

impl BrowserActionRecord {
    pub fn from_prepared(
        command_id: CommandId,
        prepared: &PreparedActionView,
        outcome: BrowserActionOutcome,
        observed_at: OffsetDateTime,
    ) -> Self {
        Self {
            command_id,
            action_id: prepared.action_id.0,
            action: prepared.descriptor.action,
            policy_action: prepared.policy_action,
            activation: prepared.descriptor.activation,
            capability_id: prepared.rule.capability_id.clone(),
            capability_version: prepared.rule.capability_version,
            effect_class: prepared.rule.effect_class,
            approval_required: prepared.rule.approval_required,
            arguments_digest: prepared.arguments_digest,
            policy_revision: prepared.policy_binding.revision,
            policy_digest: prepared.policy_binding.digest,
            control_revision: prepared.control_revision,
            outcome,
            observed_at,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BrowserProjectionError {
    #[error("browser projection is no longer accepting commands")]
    Closed,
    #[error("browser projection {stage} failed: {detail}")]
    Stage { stage: &'static str, detail: String },
    #[error("browser projection task failed: {0}")]
    Join(String),
}

fn stage_error(stage: &'static str, error: impl std::fmt::Display) -> BrowserProjectionError {
    BrowserProjectionError::Stage {
        stage,
        detail: error.to_string(),
    }
}

/// Marks page facts stale without replacing a failure already reported by the browser facade.
fn decorate_terminal_cause(view: &mut BrowserSessionView, error: &BrowserProjectionError) {
    view.failure.get_or_insert_with(|| error.to_string());
    view.stale = true;
}

enum ProjectionCommand {
    RecordAction {
        record: BrowserActionRecord,
        response: oneshot::Sender<Result<ArtifactRef, BrowserProjectionError>>,
    },
    Shutdown,
}

/// Cloneable command-side access to a projected session. Browser operations
/// still go directly through the real serialized `odin-browser` handle.
#[derive(Clone)]
pub struct BrowserProjectionHandle {
    browser: BrowserHandle,
    commands: mpsc::Sender<ProjectionCommand>,
    terminal: watch::Receiver<Option<Result<(), BrowserProjectionError>>>,
    rejected_frames: Arc<AtomicU64>,
    expiry_observation: Arc<Mutex<Option<TakeoverLeaseExpiry>>>,
}

impl BrowserProjectionHandle {
    pub fn browser(&self) -> &BrowserHandle {
        &self.browser
    }

    pub fn browser_handle(&self) -> BrowserHandle {
        self.browser.clone()
    }

    /// Number of visual frames rejected before projection, saturated at `u64::MAX`.
    pub fn rejected_frames(&self) -> u64 {
        self.rejected_frames.load(Ordering::Relaxed)
    }

    /// Takes the sole lease-expiry cancellation observation delivered by the
    /// session pump. Exactly one coordinator call wins.
    pub fn take_expiry_observation(
        &self,
    ) -> Result<Option<TakeoverLeaseExpiry>, BrowserProjectionError> {
        self.expiry_observation
            .lock()
            .map_err(|_| BrowserProjectionError::Stage {
                stage: "takeover lease expiry",
                detail: "expiry observation slot is unavailable".to_owned(),
            })
            .map(|mut observation| observation.take())
    }

    pub async fn record_action(
        &self,
        record: BrowserActionRecord,
    ) -> Result<ArtifactRef, BrowserProjectionError> {
        let (response, result) = oneshot::channel();
        self.commands
            .send(ProjectionCommand::RecordAction { record, response })
            .await
            .map_err(|_| BrowserProjectionError::Closed)?;
        result.await.map_err(|_| BrowserProjectionError::Closed)?
    }

    /// Waits until the projected session reaches a terminal view or the
    /// projection fails without consuming its owner or stopping command intake.
    pub async fn wait_terminal(&self) -> Result<(), BrowserProjectionError> {
        let mut terminal = self.terminal.clone();
        loop {
            if let Some(result) = terminal.borrow().clone() {
                return result;
            }
            terminal
                .changed()
                .await
                .map_err(|_| BrowserProjectionError::Closed)?;
        }
    }
}

/// Owner of the event-pump task and explicit, exactly-once session shutdown.
pub struct BrowserProjection {
    handle: BrowserProjectionHandle,
    task: Option<JoinHandle<Result<SessionTeardown, BrowserProjectionError>>>,
}

impl BrowserProjection {
    pub fn spawn(
        session: BrowserSession,
        read_model: Arc<MaterializedReadModel>,
        multiplexer: Arc<BoundedMultiplexer>,
        artifacts: Arc<FsPublishedArtifactStore>,
        external_content: Arc<FsExternalContentIndex>,
        config: BrowserProjectionConfig,
    ) -> Self {
        let browser = session.handle();
        let (commands, receiver) = mpsc::channel(config.command_capacity.get());
        let (terminal_signal, terminal) = watch::channel(None);
        let rejected_frames = Arc::new(AtomicU64::new(0));
        let expiry_observation = Arc::new(Mutex::new(None));
        let task_browser = browser.clone();
        let task = tokio::spawn(run_projection(
            session,
            task_browser,
            receiver,
            terminal_signal,
            Arc::clone(&rejected_frames),
            Arc::clone(&expiry_observation),
            ProjectionContext {
                read_model,
                multiplexer,
                artifacts,
                external_content,
                config,
            },
        ));
        Self {
            handle: BrowserProjectionHandle {
                browser,
                commands,
                terminal,
                rejected_frames,
                expiry_observation,
            },
            task: Some(task),
        }
    }

    pub fn handle(&self) -> BrowserProjectionHandle {
        self.handle.clone()
    }

    pub fn browser_handle(&self) -> BrowserHandle {
        self.handle.browser_handle()
    }

    pub fn rejected_frames(&self) -> u64 {
        self.handle.rejected_frames()
    }

    pub async fn record_action(
        &self,
        record: BrowserActionRecord,
    ) -> Result<ArtifactRef, BrowserProjectionError> {
        self.handle.record_action(record).await
    }

    /// Requests graceful termination, waits for the event pump, and returns
    /// the real browser teardown evidence. The pump calls `BrowserSession::shutdown`
    /// on every exit path, including projection failure and sender drop.
    pub async fn shutdown(mut self) -> Result<SessionTeardown, BrowserProjectionError> {
        let _ = self.handle.commands.send(ProjectionCommand::Shutdown).await;
        let task = self.task.take().ok_or(BrowserProjectionError::Closed)?;
        task.await
            .map_err(|error| BrowserProjectionError::Join(error.to_string()))?
    }
}

struct TimelineState {
    records: VecDeque<Vec<u8>>,
    total_bytes: usize,
    artifact: Option<ArtifactRef>,
    max_records: usize,
    max_bytes: usize,
}

impl TimelineState {
    fn new(config: BrowserProjectionConfig) -> Self {
        Self {
            records: VecDeque::new(),
            total_bytes: 0,
            artifact: None,
            max_records: config.max_timeline_records.get(),
            max_bytes: config.max_timeline_bytes.get(),
        }
    }

    async fn append(
        &mut self,
        store: Arc<FsPublishedArtifactStore>,
        session_id: odin_domain::huginn::BrowserSessionId,
        record: BrowserActionRecord,
    ) -> Result<ArtifactRef, BrowserProjectionError> {
        let mut encoded = serde_json::to_vec(&record)
            .map_err(|error| stage_error("timeline serialization", error))?;
        encoded.push(b'\n');
        if encoded.len() > self.max_bytes {
            return Err(BrowserProjectionError::Stage {
                stage: "timeline bound",
                detail: "one redacted action record exceeds the configured byte bound".to_owned(),
            });
        }
        while self.records.len() >= self.max_records
            || self.total_bytes.saturating_add(encoded.len()) > self.max_bytes
        {
            let Some(expired) = self.records.pop_front() else {
                break;
            };
            self.total_bytes = self.total_bytes.saturating_sub(expired.len());
        }
        self.total_bytes = self.total_bytes.checked_add(encoded.len()).ok_or_else(|| {
            BrowserProjectionError::Stage {
                stage: "timeline bound",
                detail: "timeline byte accounting overflowed".to_owned(),
            }
        })?;
        self.records.push_back(encoded);

        let mut document = Vec::with_capacity(self.total_bytes);
        for record in &self.records {
            document.extend_from_slice(record);
        }
        let byte_len = document.len() as u64;
        let digest = Digest::hash(&document);
        let artifact = tokio::task::spawn_blocking(move || {
            store.publish_browser_artifact(
                session_id,
                BrowserArtifactKind::Timeline,
                TIMELINE_DISPLAY_NAME.to_owned(),
                TIMELINE_MEDIA_TYPE.to_owned(),
                digest,
                document,
            )
        })
        .await
        .map_err(|error| stage_error("timeline publication task", error))?
        .map_err(|error| stage_error("timeline publication", error))?;
        if artifact.kind != ArtifactKind::File
            || artifact.display_name != TIMELINE_DISPLAY_NAME
            || artifact.media_type != TIMELINE_MEDIA_TYPE
            || artifact.byte_len != byte_len
            || artifact.content_digest != digest
        {
            return Err(BrowserProjectionError::Stage {
                stage: "timeline binding",
                detail: "published timeline artifact does not match its JSONL bytes".to_owned(),
            });
        }
        self.artifact = Some(artifact.clone());
        Ok(artifact)
    }
}

struct PumpState {
    read_model: Arc<MaterializedReadModel>,
    multiplexer: Arc<BoundedMultiplexer>,
    artifacts: Arc<FsPublishedArtifactStore>,
    external_content: Arc<FsExternalContentIndex>,
    session_id: odin_domain::huginn::BrowserSessionId,
    stream_id: odin_domain::huginn::StreamId,
    timeline: TimelineState,
    rejected_frames: Arc<AtomicU64>,
    expiry_observation: Arc<Mutex<Option<TakeoverLeaseExpiry>>>,
    latest_session: Option<BrowserSessionView>,
    terminal_failure: Option<BrowserProjectionError>,
}

enum EventFlow {
    Continue,
    Terminal,
}

impl PumpState {
    fn terminal_result(&self) -> Result<(), BrowserProjectionError> {
        self.terminal_failure.clone().map_or(Ok(()), Err)
    }

    async fn project_event(
        &mut self,
        event: SessionEvent,
        browser: &BrowserHandle,
    ) -> Result<EventFlow, BrowserProjectionError> {
        match event {
            SessionEvent::Frame(record) => {
                let revision = Revision::new(record.view.frame_number.get());
                if revision.checked_next().is_none() {
                    return Err(BrowserProjectionError::Stage {
                        stage: "frame read-model update",
                        detail: "latest-frame revision leaves no revision for terminal tombstone"
                            .to_owned(),
                    });
                }
                let retention = self
                    .artifacts
                    .lease_browser_artifact(&record.frame.content.artifact_id)
                    .map_err(|error| stage_error("frame artifact retention", error))?;
                let snapshot = object_snapshot(
                    ObjectKind::Browser,
                    format!("{}:latest-frame", self.session_id),
                    revision,
                    RevisionSource::Browser,
                    record.view.captured_at,
                    false,
                    &record.view,
                );
                self.read_model
                    .upsert(snapshot.clone())
                    .map_err(|error| stage_error("frame read-model update", error))?;
                let produced_at = record.frame.produced_at;
                self.multiplexer
                    .publish(
                        MultiplexedItem::with_retention(
                            record.frame,
                            HuginnMessage::ObjectSnapshot(snapshot),
                            retention,
                        ),
                        produced_at,
                    )
                    .map_err(|error| stage_error("frame stream publication", error))?;
                Ok(EventFlow::Continue)
            }
            SessionEvent::Session(view) => {
                let terminal = matches!(
                    view.state,
                    BrowserSessionState::Closed | BrowserSessionState::Failed
                );
                let terminal_failure = (view.state == BrowserSessionState::Failed).then(|| {
                    BrowserProjectionError::Stage {
                        stage: "browser session",
                        detail: view
                            .failure
                            .clone()
                            .unwrap_or_else(|| "browser session failed".to_owned()),
                    }
                });
                self.project_session(view)?;
                if terminal {
                    self.terminal_failure = terminal_failure;
                    Ok(EventFlow::Terminal)
                } else {
                    Ok(EventFlow::Continue)
                }
            }
            SessionEvent::TakeoverLeaseExpired(expiry) => {
                let mut observation =
                    self.expiry_observation
                        .lock()
                        .map_err(|_| BrowserProjectionError::Stage {
                            stage: "takeover lease expiry",
                            detail: "expiry observation slot is unavailable".to_owned(),
                        })?;
                if observation.is_some() {
                    return Err(BrowserProjectionError::Stage {
                        stage: "takeover lease expiry",
                        detail: "previous expiry observation was not consumed".to_owned(),
                    });
                }
                *observation = Some(expiry);
                Ok(EventFlow::Continue)
            }
            SessionEvent::ControlFailure { code } => Err(BrowserProjectionError::Stage {
                stage: "browser control",
                detail: code.to_owned(),
            }),
            SessionEvent::Download(view) => {
                self.project_download(view).await?;
                Ok(EventFlow::Continue)
            }
            SessionEvent::Quarantined(record) => {
                let view = browser
                    .download_views()
                    .await
                    .into_iter()
                    .find(|view| view.download_id == record.download_id)
                    .ok_or_else(|| BrowserProjectionError::Stage {
                        stage: "download quarantine projection",
                        detail: "quarantined download view is unavailable".to_owned(),
                    })?;
                self.project_download(view).await?;
                Ok(EventFlow::Continue)
            }
            SessionEvent::FrameRejected { .. } => {
                let _ = self.rejected_frames.fetch_update(
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                    |count| Some(count.saturating_add(1)),
                );
                Ok(EventFlow::Continue)
            }
            SessionEvent::DownloadRejected { reason, .. } => Err(BrowserProjectionError::Stage {
                stage: "browser download",
                detail: reason,
            }),
            SessionEvent::EventsDropped { count } => Err(BrowserProjectionError::Stage {
                stage: "browser event delivery",
                detail: format!("bounded worker event queue dropped {count} events"),
            }),
            SessionEvent::Protocol(_) => Ok(EventFlow::Continue),
        }
    }

    fn project_session(
        &mut self,
        mut view: BrowserSessionView,
    ) -> Result<(), BrowserProjectionError> {
        let object = ObjectRef {
            kind: ObjectKind::Browser,
            id: view.session_id.to_string(),
        };
        let current = self
            .read_model
            .current_revision(&object)
            .map_err(|error| stage_error("session revision", error))?
            .map(Revision::get)
            .or_else(|| self.latest_session.as_ref().map(|latest| latest.revision));
        view.revision = match current {
            Some(current) => {
                current
                    .checked_add(1)
                    .ok_or_else(|| BrowserProjectionError::Stage {
                        stage: "session revision",
                        detail: "browser session projection revision overflowed".to_owned(),
                    })?
            }
            None => view.revision.max(1),
        }
        .max(view.revision);
        view.action_timeline = self.timeline.artifact.clone();
        let snapshot = object_snapshot(
            ObjectKind::Browser,
            view.session_id.to_string(),
            Revision::new(view.revision),
            RevisionSource::Browser,
            view.updated_at,
            view.stale,
            &view,
        );
        self.read_model
            .upsert(snapshot)
            .map_err(|error| stage_error("session read-model update", error))?;
        self.latest_session = Some(view);
        Ok(())
    }

    async fn project_download(
        &self,
        view: BrowserDownloadView,
    ) -> Result<(), BrowserProjectionError> {
        if view.status == BrowserDownloadStatus::Complete {
            let artifact_id = view
                .content
                .as_ref()
                .ok_or_else(|| BrowserProjectionError::Stage {
                    stage: "download binding",
                    detail: "completed browser download has no artifact".to_owned(),
                })?
                .artifact_id
                .clone();
            let source = ContentSource::BrowserDownload {
                session: view.session_id,
                item: view.download_id,
            };
            let external_content = Arc::clone(&self.external_content);
            tokio::task::spawn_blocking(move || external_content.register(source, artifact_id))
                .await
                .map_err(|error| stage_error("download content alias task", error))?
                .map_err(|error| stage_error("download content alias", error))?;
        }
        let snapshot = object_snapshot(
            ObjectKind::Browser,
            view.download_id.to_string(),
            Revision::new(view.revision),
            RevisionSource::Browser,
            view.started_at,
            false,
            &view,
        );
        self.read_model
            .upsert(snapshot)
            .map_err(|error| stage_error("download read-model update", error))?;
        Ok(())
    }

    async fn record_action(
        &mut self,
        record: BrowserActionRecord,
    ) -> Result<ArtifactRef, BrowserProjectionError> {
        let artifact = self
            .timeline
            .append(Arc::clone(&self.artifacts), self.session_id, record)
            .await?;
        let latest = self
            .latest_session
            .clone()
            .ok_or_else(|| BrowserProjectionError::Stage {
                stage: "timeline projection",
                detail: "browser session view is unavailable".to_owned(),
            })?;
        self.project_session(latest)?;
        let artifact_store = Arc::clone(&self.artifacts);
        let session_id = self.session_id;
        let artifact_id = artifact.artifact_id.clone();
        tokio::task::spawn_blocking(move || {
            artifact_store.acknowledge_browser_timeline(session_id, &artifact_id)
        })
        .await
        .map_err(|error| stage_error("timeline acknowledgement task", error))?
        .map_err(|error| stage_error("timeline acknowledgement", error))?;
        Ok(artifact)
    }

    fn retire_latest_frame(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<(), BrowserProjectionError> {
        let object = ObjectRef {
            kind: ObjectKind::Browser,
            id: format!("{}:latest-frame", self.session_id),
        };
        let Some(current) = self
            .read_model
            .current_revision(&object)
            .map_err(|error| stage_error("frame read-model retirement", error))?
        else {
            return Ok(());
        };
        let next = current
            .checked_next()
            .ok_or_else(|| BrowserProjectionError::Stage {
                stage: "frame read-model retirement",
                detail: "latest-frame revision overflowed".to_owned(),
            })?;
        self.read_model
            .remove(
                object,
                next,
                RevisionSource::Browser,
                freshness(observed_at, true),
            )
            .map_err(|error| stage_error("frame read-model retirement", error))?;
        Ok(())
    }
}

/// Shared read-model stores and configuration one browser projection pump runs against.
struct ProjectionContext {
    read_model: Arc<MaterializedReadModel>,
    multiplexer: Arc<BoundedMultiplexer>,
    artifacts: Arc<FsPublishedArtifactStore>,
    external_content: Arc<FsExternalContentIndex>,
    config: BrowserProjectionConfig,
}

async fn run_projection(
    mut session: BrowserSession,
    browser: BrowserHandle,
    mut commands: mpsc::Receiver<ProjectionCommand>,
    terminal_signal: watch::Sender<Option<Result<(), BrowserProjectionError>>>,
    rejected_frames: Arc<AtomicU64>,
    expiry_observation: Arc<Mutex<Option<TakeoverLeaseExpiry>>>,
    context: ProjectionContext,
) -> Result<SessionTeardown, BrowserProjectionError> {
    let mut state = PumpState {
        read_model: context.read_model,
        multiplexer: context.multiplexer,
        artifacts: context.artifacts,
        external_content: context.external_content,
        session_id: browser.session_id(),
        stream_id: browser.frames().stream_id(),
        rejected_frames,
        expiry_observation,
        timeline: TimelineState::new(context.config),
        latest_session: None,
        terminal_failure: None,
    };
    let mut failure = None;
    let mut terminal = false;

    match session.next_event().await {
        Some(event) => match state.project_event(event, &browser).await {
            Ok(EventFlow::Continue) => {}
            Ok(EventFlow::Terminal) => {
                terminal = true;
                terminal_signal.send_replace(Some(state.terminal_result()));
            }
            Err(error) => {
                terminal_signal.send_replace(Some(Err(error.clone())));
                failure = Some(error);
            }
        },
        None => {
            let error = BrowserProjectionError::Stage {
                stage: "browser event delivery",
                detail: "event stream ended before the initial session view".to_owned(),
            };
            terminal_signal.send_replace(Some(Err(error.clone())));
            failure = Some(error);
        }
    }

    while failure.is_none() {
        tokio::select! {
            command = commands.recv() => match command {
                Some(ProjectionCommand::RecordAction { record, response }) => {
                    match state.record_action(record).await {
                        Ok(artifact) => {
                            let _ = response.send(Ok(artifact));
                        }
                        Err(error) => {
                            let _ = response.send(Err(error.clone()));
                            terminal_signal.send_replace(Some(Err(error.clone())));
                            failure = Some(error);
                        }
                    }
                }
                Some(ProjectionCommand::Shutdown) | None => break,
            },
            event = session.next_event(), if !terminal => match event {
                Some(event) => match state.project_event(event, &browser).await {
                    Ok(EventFlow::Continue) => {}
                    Ok(EventFlow::Terminal) => {
                        terminal = true;
                        terminal_signal.send_replace(Some(state.terminal_result()));
                    }
                    Err(error) => {
                        terminal_signal.send_replace(Some(Err(error.clone())));
                        failure = Some(error);
                    }
                },
                None => {
                    let error = BrowserProjectionError::Stage {
                        stage: "browser event delivery",
                        detail: "event stream ended while the session was active".to_owned(),
                    };
                    terminal_signal.send_replace(Some(Err(error.clone())));
                    failure = Some(error);
                }
            }
        }
    }

    let shutdown = session
        .shutdown()
        .await
        .map_err(|error| stage_error("session shutdown", error));
    let final_projection = match browser.latest_view().await {
        Some(mut view) => {
            // Huginn-visible terminal cause: the facade's view stays the
            // control-truth source while the projection layers the observed
            // terminal failure onto the same existing view fields, so the
            // read model carries WHY the capsule reached terminal, not just
            // that it did.
            if let Some(error) = failure.as_ref() {
                decorate_terminal_cause(&mut view, error);
            }
            state.project_session(view)
        }
        None => Err(BrowserProjectionError::Stage {
            stage: "session shutdown projection",
            detail: "terminal browser session view is unavailable".to_owned(),
        }),
    };
    let termination_at = OffsetDateTime::now_utc();
    let frame_retirement = state.retire_latest_frame(termination_at);
    let stream_closure = state
        .multiplexer
        .close_stream(&state.stream_id, termination_at)
        .map_err(|error| stage_error("stream closure", error));
    let artifact_store = Arc::clone(&state.artifacts);
    let session_id = state.session_id;
    let artifact_retirement = tokio::task::spawn_blocking({
        let artifact_store = Arc::clone(&artifact_store);
        move || artifact_store.retire_browser_session(session_id)
    })
    .await
    .map_err(|error| stage_error("browser artifact retirement task", error))
    .and_then(|result| result.map_err(|error| stage_error("browser artifact retirement", error)));
    let terminal_failure = state.terminal_failure.clone();
    drop(state);
    let retirement_flush =
        tokio::task::spawn_blocking(move || artifact_store.flush_browser_retirements())
            .await
            .map_err(|error| stage_error("browser artifact retirement flush task", error))
            .and_then(|result| {
                result.map_err(|error| stage_error("browser artifact retirement flush", error))
            });

    let mut errors = Vec::new();
    if let Some(error) = failure {
        errors.push(error.to_string());
    }
    if let Err(error) = &shutdown {
        errors.push(error.to_string());
    }
    if let Err(error) = final_projection {
        errors.push(error.to_string());
    }
    if let Err(error) = frame_retirement {
        errors.push(error.to_string());
    }
    if let Err(error) = stream_closure {
        errors.push(error.to_string());
    }
    if let Err(error) = artifact_retirement {
        errors.push(error.to_string());
    }
    if let Err(error) = retirement_flush {
        errors.push(error.to_string());
    }
    let result = if errors.is_empty() {
        terminal_failure.map_or(shutdown, Err)
    } else {
        if let Some(error) = terminal_failure {
            errors.insert(0, error.to_string());
        }
        Err(BrowserProjectionError::Stage {
            stage: "termination",
            detail: errors.join("; "),
        })
    };
    terminal_signal.send_replace(Some(match &result {
        Ok(_) => Ok(()),
        Err(error) => Err(error.clone()),
    }));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{BrowserSessionId, BrowserTakeoverStatus, StreamId};
    use uuid::Uuid;

    fn active_view() -> BrowserSessionView {
        BrowserSessionView {
            session_id: BrowserSessionId::new(Uuid::new_v4()).expect("session id"),
            revision: 1,
            state: BrowserSessionState::Active,
            isolated_profile: "profile".to_owned(),
            current_url: None,
            current_origin: None,
            page_title: None,
            frame_stream_id: StreamId::parse("00000000-0000-4000-8000-000000000010")
                .expect("stream id"),
            takeover: BrowserTakeoverStatus::Available,
            action_timeline: None,
            opened_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            stale: false,
            failure: None,
        }
    }

    #[test]
    fn projection_failure_layers_the_typed_cause_onto_the_huginn_visible_view() {
        let error = BrowserProjectionError::Stage {
            stage: "browser event delivery",
            detail: "event stream ended while the session was active".to_owned(),
        };
        let mut view = active_view();
        decorate_terminal_cause(&mut view, &error);
        assert!(view.stale, "a failed terminal marks the page facts stale");
        assert_eq!(
            view.failure.as_deref(),
            Some(
                "browser projection browser event delivery failed: event stream ended \
                  while the session was active"
            ),
            "the read model must carry the actual terminal cause, not just closure"
        );
    }

    #[test]
    fn a_facade_reported_cause_is_never_overwritten() {
        let error = BrowserProjectionError::Closed;
        let mut view = active_view();
        view.failure = Some("facade cause".to_owned());
        decorate_terminal_cause(&mut view, &error);
        assert_eq!(view.failure.as_deref(), Some("facade cause"));
        assert!(view.stale);
    }
}
