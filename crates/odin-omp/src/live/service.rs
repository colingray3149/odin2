use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, DeviceId, EventSeq,
    HistoryPage, HistoryQuery, LiveCommand, LiveError, LiveEventBody, LiveEventStream,
    LiveSessionId, LiveSessionState, LiveSessionSummary, OmpLivePlane, OpenSessionRequest,
    RosterRevision, SeatLiveState, SeatRoster, SeatRosterEntry, SessionListCursor, SessionListPage,
    SessionListQuery, SubscribeRequest, TerminalControlLeaseId, TerminalControlRequest,
    TerminalControlStatus, TerminalInput, TerminalResize, TerminalTargetSource as WireTargetSource,
    TerminalTargetStatus as WireTargetStatus, TransferChunk, TransferId, TransferStatus,
    UploadManifest,
};
use odin_domain::{ArtifactId, CommandId, ProjectId, SeatId};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::live::lane_artifacts::LaneArtifact;

use super::ledger::{live_error, LiveLedger, REPLAY_PAGE_EVENTS};
use super::supervisor::{LiveSupervisor, PARK_IDLE_LIMIT};
use super::transfer::TransferManager;

static LIVE: std::sync::OnceLock<std::sync::Weak<OmpLiveService>> = std::sync::OnceLock::new();

/// Events an ended session's replay may have in flight before the sender waits.
const REPLAY_CHANNEL_EVENTS: usize = 64;

pub struct OmpLiveService {
    ledger: Arc<dyn LiveLedger>,
    supervisor: Arc<LiveSupervisor>,
    transfers: Arc<TransferManager>,
    /// Retires a session and opens its successor when the declared rollover
    /// bound or new information says so. `None` in fixtures: those seats
    /// declare no fresh bound, so the command path never calls it.
    handoff: std::sync::Mutex<Option<Arc<dyn FreshHandoff>>>,
    /// Delegation rows, so a child or stall event wakes its parent session
    /// rather than every session of the seat. Absent in fixtures that do
    /// not route delegated events.
    links: std::sync::Mutex<Option<crate::host_tools::delegation::DelegationLinkLedger>>,
}

/// Gathers the seat's task notes, project memory, and repository state,
/// retires the session, and opens the successor. `owner_text` is the exact
/// opener text a new-information replacement must carry into the successor
/// brief; a rollover-bound replacement passes an empty string. The
/// implementation lives with the runtime factory, which holds the brain.
#[async_trait]
pub trait FreshHandoff: Send + Sync {
    async fn handoff(
        &self,
        supervisor: &LiveSupervisor,
        session: LiveSessionId,
        completed_rollovers: u32,
        new_information: bool,
        owner_text: &str,
    ) -> Result<Option<super::supervisor::FreshSession>, LiveError>;

    /// Admit the original command before retiring the current session.
    async fn handoff_command(
        &self,
        supervisor: &LiveSupervisor,
        command: LiveCommand,
        owner_text: &str,
    ) -> Result<Option<CommandReceipt>, LiveError>;
}

impl OmpLiveService {
    /// Returns the exact admitted command, or `None` when safe to admit it.
    /// Existing entries are observed on replay, never re-executed.
    pub async fn command_entry(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<super::ledger::CommandJournalEntry>, LiveError> {
        self.ledger.command(command).await.map_err(live_error)
    }

    /// Whether a durable session manifest exists for this id: initialize
    /// distinguishes an absent manifest (idempotent original open) from a
    /// present-but-parked session (recovery path).
    pub async fn session_manifest_present(
        &self,
        session_id: LiveSessionId,
    ) -> Result<bool, LiveError> {
        match self.ledger.session(session_id).await {
            Ok(_) => Ok(true),
            Err(super::ledger::LedgerError::SessionMissing(_)) => Ok(false),
            Err(error) => Err(live_error(error)),
        }
    }

    pub fn new(
        ledger: Arc<dyn LiveLedger>,
        supervisor: Arc<LiveSupervisor>,
        transfers: Arc<TransferManager>,
    ) -> Self {
        Self {
            ledger,
            supervisor,
            transfers,
            handoff: std::sync::Mutex::new(None),
            links: std::sync::Mutex::new(None),
        }
    }

    /// Installs the fresh-session handoff. A seat whose policy declares a
    /// fresh bound or new-information retirement uses it; others never do.
    pub fn set_fresh_handoff(&self, handoff: Arc<dyn FreshHandoff>) {
        if let Ok(mut slot) = self.handoff.lock() {
            *slot = Some(handoff);
        }
    }

    /// Installs the delegation rows a child or stall wake uses to find its
    /// parent session. Without it, a session-routed event whose subject is
    /// not itself live falls back to every live session of the seat.
    pub fn set_delegation_links(&self, links: crate::host_tools::delegation::DelegationLinkLedger) {
        if let Ok(mut slot) = self.links.lock() {
            *slot = Some(links);
        }
    }

    pub fn supervisor(&self) -> &Arc<LiveSupervisor> {
        &self.supervisor
    }

    /// Remembers this service so declared event watches can prompt a seat
    /// without each pump taking a new parameter. A second install is ignored.
    pub fn install_live(service: &Arc<Self>) {
        let _ = LIVE.set(Arc::downgrade(service));
    }

    pub fn installed() -> Option<Arc<Self>> {
        LIVE.get().and_then(|weak| weak.upgrade())
    }

    /// Prompts every applicable live session of `seat`. `route` names the
    /// event's project (`project:<id>`, a repo watch) or the delegated
    /// session it concerns (`session:<uuid>`, a child, stall, or workload
    /// whose parent or launcher is known). A named project wakes only that
    /// project's sessions; a named session wakes its parent when that parent
    /// is one of this seat's live sessions, otherwise the sessions on the
    /// child's project. An unrouted event wakes every live session of the
    /// seat. A running session is followed up; an idle one is prompted.
    /// Failed, ended, and detached sessions are not live. No owner
    /// text: an event wake is not new owner information and does not retire
    /// the session. `Ok(false)` when no applicable session accepted the wake.
    /// A session whose event head moved under the prompt is retried; a
    /// session that refused for any other reason is reported, and the other
    /// applicable sessions are still prompted.
    pub async fn wake_seat(
        &self,
        seat: &SeatId,
        id: &str,
        text: &str,
        route: Option<&WakeRoute>,
    ) -> Result<bool, LiveError> {
        use odin_domain::huginn::{LiveContentBlock, LiveMessage};
        let summaries = self.supervisor.summaries().await?;
        let projects = self.session_projects(&summaries).await?;
        let parent = route.and_then(|route| self.delegation_parent(route));
        let targets = wake_targets(&summaries, &projects, seat, route, parent.as_ref());
        if targets.is_empty() {
            return Ok(false);
        }
        let message = LiveMessage::new(vec![LiveContentBlock::Text(text.to_owned())])
            .map_err(|error| LiveError::unavailable("seat_wake", error))?;
        let mut delivered = false;
        let mut first_error = None;
        for summary in targets {
            match self.prompt_wake(&summary, id, message.clone()).await {
                Ok(true) => delivered = true,
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(
                        "seat wake for {seat} session {} refused: {error}",
                        summary.session_id
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if delivered {
            Ok(true)
        } else {
            first_error.map_or(Ok(false), Err)
        }
    }

    /// The parent session of a delegated child named by `route`, when the
    /// link ledger is installed and the row parses as a live session.
    /// A missing row or an unreadable ledger leaves routing to the project
    /// or the whole seat; it does not invent a parent.
    fn delegation_parent(&self, route: &WakeRoute) -> Option<LiveSessionId> {
        let WakeRoute::Session(session) = route else {
            return None;
        };
        let links = self.links.lock().ok()?.clone()?;
        let link = links.load(session).ok()??;
        crate::host_tools::delegation::live_session_id(&link.parent).ok()
    }

    /// Project of every tracked session, read from its durable manifest.
    /// A missing manifest is skipped: that session cannot be routed by
    /// project and is not guessed into another project's wake.
    async fn session_projects(
        &self,
        summaries: &[LiveSessionSummary],
    ) -> Result<std::collections::BTreeMap<LiveSessionId, ProjectId>, LiveError> {
        let mut projects = std::collections::BTreeMap::new();
        for summary in summaries {
            match self.ledger.session(summary.session_id).await {
                Ok(session) => {
                    projects.insert(summary.session_id, session.manifest.project_id);
                }
                Err(super::ledger::LedgerError::SessionMissing(_)) => {}
                Err(error) => return Err(live_error(error)),
            }
        }
        Ok(projects)
    }

    /// Prompts one idle session, or follows up when it is already in a turn.
    /// The epoch and event head are refreshed when they moved between the
    /// roster read and admission. A rejected command is a typed refusal, not
    /// a delivered wake. The command id is a bounded digest of the event,
    /// session, and head, so a replay of the same wake is a duplicate.
    async fn prompt_wake(
        &self,
        summary: &LiveSessionSummary,
        id: &str,
        message: odin_domain::huginn::LiveMessage,
    ) -> Result<bool, LiveError> {
        use odin_domain::huginn::{CommandReceipt, CommandRejection, LiveCommand, LiveCommandBody};
        let actor = self.supervisor.actor(summary.session_id).await?;
        let mut current = actor.summary().unwrap_or_else(|_| summary.clone());
        for attempt in 1..=WAKE_HEAD_ATTEMPTS {
            let body = match current.state {
                LiveSessionState::Idle | LiveSessionState::Starting => LiveCommandBody::Prompt {
                    message: message.clone(),
                    owner_text: None,
                },
                LiveSessionState::Running | LiveSessionState::RequiresAction => {
                    LiveCommandBody::FollowUp {
                        message: message.clone(),
                        owner_text: None,
                    }
                }
                _ => return Ok(false),
            };
            let command_id = wake_command_id(id, current.session_id, current.event_head)?;
            let receipt = actor
                .command(LiveCommand {
                    command_id,
                    session_id: current.session_id,
                    expected_epoch: current.epoch,
                    expected_event_head: Some(current.event_head),
                    body,
                })
                .await?;
            match receipt {
                CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. } => {
                    return Ok(true);
                }
                CommandReceipt::Rejected { reason, .. }
                    if matches!(
                        reason,
                        CommandRejection::EventHeadMismatch { .. }
                            | CommandRejection::EpochMismatch { .. }
                    ) && attempt < WAKE_HEAD_ATTEMPTS =>
                {
                    current = actor.summary()?;
                }
                CommandReceipt::Rejected { reason, .. } => {
                    return Err(LiveError::Conflict {
                        code: "seat_wake_rejected".to_owned(),
                        message: reason.to_string(),
                    });
                }
            }
        }
        Err(LiveError::Conflict {
            code: "seat_wake_head_race".to_owned(),
            message: format!(
                "session {} moved during the wake and did not accept it",
                summary.session_id
            ),
        })
    }

    pub async fn acquire_terminal_control(
        &self,
        operation_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.terminal(request.session_id)
            .await?
            .acquire_control(operation_id, device, request)
            .await
    }

    pub async fn write_terminal(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        self.terminal(session)
            .await?
            .write_input(operation_id, input)
            .await
    }

    pub async fn resize_terminal(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        self.terminal(session)
            .await?
            .resize(operation_id, resize)
            .await
    }

    pub async fn release_terminal_control(
        &self,
        operation_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        self.terminal(session)
            .await?
            .release_control(operation_id, lease)
            .await
    }

    pub async fn register_egress(&self, artifact: LaneArtifact) -> Result<ArtifactRef, LiveError> {
        let artifact = self.transfers.register_egress(artifact).await?;
        if !artifact_published(&*self.ledger, artifact.session_id, &artifact.artifact_id).await? {
            self.supervisor
                .actor(artifact.session_id)
                .await?
                .append(LiveEventBody::ArtifactPublished(artifact.clone()))
                .await?;
        }
        Ok(artifact)
    }
    async fn terminal(
        &self,
        session: LiveSessionId,
    ) -> Result<Arc<super::zellij::ZellijLiveAdapter>, LiveError> {
        self.supervisor
            .actor(session)
            .await?
            .terminal()
            .cloned()
            .ok_or_else(|| LiveError::Unsupported {
                operation: "terminal_unavailable_for_headless_session".to_owned(),
            })
    }
}

impl OmpLiveService {
    fn fresh_handoff(&self) -> Option<Arc<dyn FreshHandoff>> {
        self.handoff.lock().ok().and_then(|slot| slot.clone())
    }
}

#[async_trait]
impl OmpLivePlane for OmpLiveService {
    async fn terminal_snapshot(
        &self,
        session: LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        let actor = self.supervisor.actor(session).await?;
        let summary = actor.summary()?;
        // Failed still has a process until the actor exits. Ended, and a
        // process already stopping, are gone.
        if actor.stopping() || summary.state == LiveSessionState::Ended {
            return Err(LiveError::unavailable(
                "terminal_session_closed",
                format!("live session {session} is stopping or ended"),
            ));
        }
        let terminal = actor.terminal().ok_or_else(|| LiveError::Unsupported {
            operation: "terminal_unavailable_for_headless_session".to_owned(),
        })?;
        let snapshot = terminal.snapshot().await?;
        if actor.stopping() {
            return Err(LiveError::unavailable(
                "terminal_session_closed",
                format!("live session {session} began stopping during the snapshot"),
            ));
        }
        Ok(snapshot)
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        let summaries = self.supervisor.summaries().await?;
        let now = OffsetDateTime::now_utc();
        let mut revision_bytes = Vec::new();
        let mut seats = Vec::new();
        for binding in self.supervisor.bindings().await {
            let active_sessions = current_sessions(&summaries, &binding.seat_id, now);
            revision_bytes.extend_from_slice(binding.seat_id.as_str().as_bytes());
            for session in &active_sessions {
                revision_bytes.extend_from_slice(&session.event_head.get().to_le_bytes());
                revision_bytes.extend_from_slice(&session.epoch.get().to_le_bytes());
            }
            let state = seat_state(&active_sessions);
            seats.push(SeatRosterEntry {
                seat_id: binding.seat_id,
                slice_id: binding.slice_id,
                display_name: binding.display_name,
                state,
                active_sessions,
                launch_options: binding.launch_options,
                diagnostic: None,
            });
        }
        let digest = blake3::hash(&revision_bytes);
        let mut revision = [0u8; 8];
        revision.copy_from_slice(&digest.as_bytes()[..8]);
        Ok(SeatRoster::new(
            RosterRevision::new(u64::from_le_bytes(revision)),
            now,
            seats,
        ))
    }

    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        // One bounded unified durable page from the supervisor: every
        // session has a durable row, the ledger scan is source-bounded to
        // limit+1 metadata rows, and the returned cursor is the last
        // scanned id whenever more rows exist — no skipped or duplicated
        // history.
        let after = match &query.cursor {
            Some(cursor) => Some(LiveSessionId::parse(cursor.as_str()).map_err(|error| {
                LiveError::InvalidRequest {
                    code: "invalid_session_list_cursor".to_owned(),
                    message: format!("session list cursor is not a session id: {error}"),
                }
            })?),
            None => None,
        };
        let (mut sessions, next_after) = self
            .supervisor
            .session_summaries_page(
                query.seat_id.as_ref(),
                query.include_ended,
                after,
                usize::from(query.limit.get()),
            )
            .await?;
        sessions.sort_by_key(|summary| summary.session_id);
        // Preserve scan progress even when filters leave the page empty.
        let next_cursor = next_after
            .map(|session_id| SessionListCursor::new(session_id.to_string()))
            .transpose()
            .map_err(|error| LiveError::unavailable("omp_live_service", error))?;
        Ok(SessionListPage::new(sessions, next_cursor))
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.ledger.history(query).await.map_err(live_error)
    }

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        if request.subscriptions.is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "empty_subscription".to_owned(),
                message: "at least one session subscription is required".to_owned(),
            });
        }
        let mut streams = Vec::with_capacity(request.subscriptions.len());
        for subscription in request.subscriptions {
            match self.supervisor.actor(subscription.session_id).await {
                Ok(actor) => streams.push(actor.subscribe(subscription.event_after).await?),
                Err(LiveError::NotFound { .. }) => streams.push(finite_replay(
                    self.supervisor.runtime(),
                    Arc::clone(&self.ledger),
                    subscription.session_id,
                    subscription.event_after,
                )),
                Err(error) => return Err(error),
            }
        }
        Ok(Box::pin(stream::select_all(streams)))
    }

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<odin_domain::huginn::LiveSessionSummary, LiveError> {
        self.supervisor.open(request).await
    }

    async fn open_session_owned(
        &self,
        request: OpenSessionRequest,
        cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> (Result<LiveSessionSummary, LiveError>, bool) {
        self.supervisor.open_owned(request, cancellation).await
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        // A crash after admit_fresh leaves a durable reservation. Drain it
        // before this command can be rejected as fresh_handoff_pending.
        self.supervisor.resume_pending_handoffs().await?;
        if declared_owner_text(&command).is_some() {
            if let Some(receipt) = self.supervisor.resume_fresh_command(&command).await? {
                return Ok(receipt);
            }
        }
        let actor = match self.supervisor.actor(command.session_id).await {
            Ok(actor) => actor,
            Err(LiveError::NotFound { .. }) => {
                // The supervisor owns parked-session admission and recovery
                // under one gate: exact replay first, then full validation,
                // journaling, capacity, and the single reclaim effect.
                return self.supervisor.recover_parked_command(command).await;
            }
            Err(error) => return Err(error),
        };
        // Only declared owner information retires. A heartbeat, a child
        // report, and a routine wake carry no owner text, so they never
        // open a fresh session. The policy still decides whether owner
        // information retires at all. When it does, the exact owner text
        // rides in the successor brief, and this command is acknowledged
        // only after that successor accepts the brief.
        if let Some(owner_text) = declared_owner_text(&command) {
            if let Some(handoff) = self.fresh_handoff() {
                if let Some(receipt) = handoff
                    .handoff_command(&self.supervisor, command.clone(), owner_text)
                    .await?
                {
                    return Ok(receipt);
                }
            }
        }
        actor.command(command).await
    }

    /// Shared recovery surface: rehydrates one durable session in place
    /// under the same session identity (fresh authority-verified child,
    /// durable transcript resumed). Works whether or not a previous actor
    /// existed; a truthfully Ended session refuses typed.
    async fn reclaim_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.supervisor.resume_pending_handoffs().await?;
        self.supervisor.reclaim(session_id).await
    }

    async fn begin_upload(&self, manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        self.transfers.begin(manifest).await
    }

    async fn upload_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        self.transfers.write_chunk(transfer, chunk).await
    }

    async fn commit_upload(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        let artifact = self.transfers.commit(transfer).await?;
        self.supervisor
            .actor(artifact.session_id)
            .await?
            .append(LiveEventBody::ArtifactPublished(artifact.clone()))
            .await?;
        Ok(artifact)
    }

    async fn cancel_transfer(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        self.transfers.cancel(command_id, transfer).await
    }

    async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError> {
        self.transfers
            .grant_download_credit(command_id, transfer, chunks)
            .await
    }

    async fn read_artifact(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        self.transfers.read(request).await
    }

    async fn acquire_terminal_control(
        &self,
        command_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        OmpLiveService::acquire_terminal_control(self, command_id, device, request).await
    }

    async fn write_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError> {
        OmpLiveService::write_terminal(self, command_id, session, input).await
    }

    async fn resize_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError> {
        OmpLiveService::resize_terminal(self, command_id, session, resize).await
    }

    async fn release_terminal_control(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        OmpLiveService::release_terminal_control(self, command_id, session, lease).await
    }

    async fn bind_terminal_target(
        &self,
        zellij_session: String,
    ) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .bind_terminal_target(zellij_session)
            .await
            .map(wire_terminal_target_status)
    }

    async fn unbind_terminal_target(&self) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .clear_terminal_target()
            .await
            .map(wire_terminal_target_status)
    }

    async fn terminal_target_status(&self) -> Result<WireTargetStatus, LiveError> {
        self.supervisor
            .terminal_target_status()
            .await
            .map(wire_terminal_target_status)
    }
}

/// How a declared watcher event names the sessions it concerns.
/// `Project` is a repository identity (`repo_watch`). `Session` is the
/// delegated child, stalled worker, or launching session the event is
/// about; its parent is preferred when that parent is live on the seat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WakeRoute {
    Project(ProjectId),
    Session(LiveSessionId),
}

impl WakeRoute {
    /// `push:<project>:...` names that project. A child, stall, or workload
    /// id that embeds a live-session uuid names that session, whether the
    /// producer separated it with colons (`resumed:{uuid}:...`) or hyphens
    /// (`child-{uuid}-{key}`, `stalled-{uuid}`). Anything else is unrouted
    /// and wakes every applicable session of the seat.
    pub fn from_event_id(id: &str) -> Option<Self> {
        if let Some(rest) = id.strip_prefix("push:") {
            let project = rest
                .split(':')
                .next()
                .filter(|project| !project.is_empty())?;
            return ProjectId::new(project).ok().map(Self::Project);
        }
        let uuid = embedded_session_uuid(id)?;
        LiveSessionId::new(uuid).ok().map(Self::Session)
    }
}

/// The first live-session uuid in `id`. A colon field is tried whole
/// (`resumed:{uuid}:cause`), then every 36-character window, so a hyphenated
/// producer (`child-{uuid}-{key}`, `stalled-{uuid}`) names the same session.
fn embedded_session_uuid(id: &str) -> Option<uuid::Uuid> {
    id.split(':')
        .find_map(|part| uuid::Uuid::parse_str(part).ok())
        .or_else(|| {
            let bytes = id.as_bytes();
            bytes.windows(36).find_map(|window| {
                let candidate = std::str::from_utf8(window).ok()?;
                uuid::Uuid::parse_str(candidate).ok()
            })
        })
}

/// Retries when the session's event head moves under the wake prompt.
const WAKE_HEAD_ATTEMPTS: u32 = 4;

/// A prompt applies to an idle or starting session; a follow-up applies
/// while a turn is running. Failed, ended, and detached sessions are not
/// event-wake targets: a failed session is not a live supervisor.
fn wake_accepts(state: LiveSessionState) -> bool {
    matches!(
        state,
        LiveSessionState::Idle
            | LiveSessionState::Starting
            | LiveSessionState::Running
            | LiveSessionState::RequiresAction
    )
}

/// Bounded command identity for one event at one session head. The event id
/// itself can exceed the command-id ceiling, so the id is its digest.
fn wake_command_id(
    id: &str,
    session: LiveSessionId,
    head: odin_domain::huginn::EventSeq,
) -> Result<CommandId, LiveError> {
    let digest = blake3::hash(id.as_bytes());
    CommandId::new(format!("wake:{}:{session}:{}", digest.to_hex(), head))
        .map_err(|error| LiveError::unavailable("seat_wake", error))
}

/// The seat's applicable live sessions for one event, in session-id order.
/// A project route keeps that project. A session route keeps `parent` when
/// that parent is one of this seat's live sessions; otherwise it keeps the
/// named session's own project. No route, or a route whose identity is not
/// among the tracked sessions, keeps every live session of the seat so the
/// event is not dropped.
fn wake_targets(
    summaries: &[LiveSessionSummary],
    projects: &std::collections::BTreeMap<LiveSessionId, ProjectId>,
    seat: &SeatId,
    route: Option<&WakeRoute>,
    parent: Option<&LiveSessionId>,
) -> Vec<LiveSessionSummary> {
    let live: Vec<LiveSessionSummary> = summaries
        .iter()
        .filter(|summary| summary.seat_id == *seat && wake_accepts(summary.state))
        .cloned()
        .collect();
    if let Some(parent) = parent {
        if let Some(summary) = live.iter().find(|summary| summary.session_id == *parent) {
            return vec![summary.clone()];
        }
    }
    let project = match route {
        Some(WakeRoute::Project(project)) => Some(project.clone()),
        Some(WakeRoute::Session(session)) => projects.get(session).cloned(),
        None => None,
    };
    let mut targets: Vec<LiveSessionSummary> = match &project {
        Some(project) => live
            .into_iter()
            .filter(|summary| projects.get(&summary.session_id) == Some(project))
            .collect(),
        None => live,
    };
    targets.sort_by_key(|summary| summary.session_id);
    targets
}

/// The owner's exact words on a prompt or follow-up, or `None` when the
/// command carries none. Whitespace-only text is not owner information.
/// The returned string is the stored field, not a trimmed copy.
fn declared_owner_text(command: &LiveCommand) -> Option<&str> {
    use odin_domain::huginn::LiveCommandBody;
    match &command.body {
        LiveCommandBody::Prompt { owner_text, .. }
        | LiveCommandBody::FollowUp { owner_text, .. } => {
            owner_text.as_deref().filter(|text| !text.trim().is_empty())
        }
        _ => None,
    }
}

/// `seat`'s current sessions, the only ones its roster entry and health
/// reflect: every tracked session except a failed or processless one that is
/// superseded (the seat started a later session) or idle past
/// [`PARK_IDLE_LIMIT`]. Those stay durable history (`sessions`).
fn current_sessions(
    summaries: &[LiveSessionSummary],
    seat: &SeatId,
    now: OffsetDateTime,
) -> Vec<LiveSessionSummary> {
    let seat_sessions: Vec<_> = summaries
        .iter()
        .filter(|summary| summary.seat_id == *seat)
        .collect();
    seat_sessions
        .iter()
        .filter(|summary| {
            !matches!(
                summary.state,
                LiveSessionState::Failed | LiveSessionState::Detached
            ) || (now - summary.updated_at <= PARK_IDLE_LIMIT
                && seat_sessions
                    .iter()
                    .all(|other| other.started_at <= summary.started_at))
        })
        .map(|summary| (*summary).clone())
        .collect()
}

/// A seat's health: the highest-priority state of its current sessions.
fn seat_state(sessions: &[LiveSessionSummary]) -> SeatLiveState {
    SeatLiveState::highest_priority(sessions.iter().map(|summary| match summary.state {
        LiveSessionState::RequiresAction => SeatLiveState::RequiresAction,
        LiveSessionState::Starting | LiveSessionState::Running | LiveSessionState::Aborting => {
            SeatLiveState::Running
        }
        LiveSessionState::Idle | LiveSessionState::Detached => SeatLiveState::Idle,
        LiveSessionState::Failed => SeatLiveState::Degraded,
        LiveSessionState::Ended => SeatLiveState::Offline,
    }))
}

/// Converts the supervisor's terminal target status into the shared wire
/// type. The conversion is total and lossless: the wire struct mirrors the
/// supervisor struct field for field.
fn wire_terminal_target_status(status: super::target::TerminalTargetStatus) -> WireTargetStatus {
    WireTargetStatus {
        bound: status.bound,
        zellij_session: status.zellij_session,
        source: status.source.map(|source| match source {
            super::target::TerminalTargetSource::ChatRegistration => {
                WireTargetSource::ChatRegistration
            }
        }),
        registered_at: status.registered_at,
        replaced: status.replaced,
    }
}

/// The pages of one session's journal after a cursor, oldest first, up to its head.
struct HistoryPages<'a> {
    ledger: &'a dyn LiveLedger,
    session: LiveSessionId,
    cursor: EventSeq,
    done: bool,
}

impl<'a> HistoryPages<'a> {
    fn new(ledger: &'a dyn LiveLedger, session: LiveSessionId, after: EventSeq) -> Self {
        Self {
            ledger,
            session,
            cursor: after,
            done: false,
        }
    }

    /// The next non-empty page; `None` once the head is reached.
    async fn next(&mut self) -> Result<Option<HistoryPage>, LiveError> {
        if self.done {
            return Ok(None);
        }
        let page = self
            .ledger
            .history(HistoryQuery {
                session_id: self.session,
                after: self.cursor,
                limit: REPLAY_PAGE_EVENTS,
            })
            .await
            .map_err(live_error)?;
        self.cursor = page.next_after;
        self.done = page.events.is_empty() || page.next_after >= page.head;
        Ok((!page.events.is_empty()).then_some(page))
    }
}

async fn artifact_published(
    ledger: &dyn LiveLedger,
    session: LiveSessionId,
    artifact: &ArtifactId,
) -> Result<bool, LiveError> {
    let mut pages = HistoryPages::new(ledger, session, EventSeq::new(0));
    while let Some(page) = pages.next().await? {
        if page.events.iter().any(|event| {
            matches!(
                &event.body,
                LiveEventBody::ArtifactPublished(published)
                    if &published.artifact_id == artifact
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The journal of a session no longer live, streamed to its head on the daemon's runtime:
/// a request-scoped caller runtime that ends mid-replay must not truncate it silently.
fn finite_replay(
    runtime: &tokio::runtime::Handle,
    ledger: Arc<dyn LiveLedger>,
    session: LiveSessionId,
    after: EventSeq,
) -> LiveEventStream {
    let (sender, receiver) = mpsc::channel(REPLAY_CHANNEL_EVENTS);
    runtime.spawn(async move {
        let mut pages = HistoryPages::new(ledger.as_ref(), session, after);
        loop {
            match pages.next().await {
                Ok(Some(page)) => {
                    for event in page.events {
                        if sender.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                }
                Ok(None) => return,
                Err(error) => {
                    let _ = sender.send(Err(error)).await;
                    return;
                }
            }
        }
    });
    Box::pin(ReceiverStream::new(receiver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_domain::huginn::{ModelName, ProviderName, SessionEpoch, TerminalSeq};

    #[test]
    fn superseded_and_old_failures_never_keep_a_seat_degraded() {
        let now = OffsetDateTime::now_utc();
        let session = |n: u128, seat: &str, state, started_hours_ago: i64| LiveSessionSummary {
            session_id: LiveSessionId::new(uuid::Uuid::from_u128(n)).expect("session"),
            epoch: SessionEpoch::new(1),
            seat_id: SeatId::new(seat).expect("seat"),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("glm-flash").expect("model"),
            title: None,
            state,
            started_at: now - time::Duration::hours(started_hours_ago),
            updated_at: now - time::Duration::hours(started_hours_ago),
            failed_at: Some(now - time::Duration::hours(started_hours_ago)),
            event_head: EventSeq::new(1),
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
            quiet_seconds: 600,
        };
        let summaries = [
            // Kubert: one failure four days old.
            session(1, "kubert", LiveSessionState::Failed, 96),
            // Architect: a failure the seat moved past with a new session.
            session(2, "architect", LiveSessionState::Failed, 3),
            session(3, "architect", LiveSessionState::Running, 1),
            // Gungnir: two recent failures; only the latest is current.
            session(4, "gungnir", LiveSessionState::Failed, 3),
            session(5, "gungnir", LiveSessionState::Failed, 1),
        ];
        let health = |seat: &str| {
            let current = current_sessions(&summaries, &SeatId::new(seat).unwrap(), now);
            let ids: Vec<u128> = current
                .iter()
                .map(|summary| summary.session_id.as_uuid().as_u128())
                .collect();
            (ids, seat_state(&current))
        };
        assert_eq!(health("kubert"), (vec![], SeatLiveState::Offline));
        assert_eq!(health("architect"), (vec![3], SeatLiveState::Running));
        assert_eq!(health("gungnir"), (vec![5], SeatLiveState::Degraded));
    }

    #[test]
    fn a_wake_routes_by_project_and_never_picks_a_failed_session() {
        let now = OffsetDateTime::now_utc();
        let session = |n: u128, seat: &str, state| LiveSessionSummary {
            session_id: LiveSessionId::new(uuid::Uuid::from_u128(n)).expect("session"),
            epoch: SessionEpoch::new(1),
            seat_id: SeatId::new(seat).expect("seat"),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("glm-flash").expect("model"),
            title: None,
            state,
            started_at: now,
            updated_at: now,
            failed_at: None,
            event_head: EventSeq::new(1),
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
            quiet_seconds: 600,
        };
        let summaries = [
            session(1, "supervisor", LiveSessionState::Idle),
            session(2, "supervisor", LiveSessionState::Failed),
            session(3, "supervisor", LiveSessionState::Running),
            session(4, "sinmara", LiveSessionState::Idle),
        ];
        let projects = [
            (summaries[0].session_id, ProjectId::new("odin").unwrap()),
            (summaries[1].session_id, ProjectId::new("odin").unwrap()),
            (summaries[2].session_id, ProjectId::new("alpha").unwrap()),
            (summaries[3].session_id, ProjectId::new("odin").unwrap()),
        ]
        .into_iter()
        .collect();
        let seat = SeatId::new("supervisor").unwrap();
        let ids = |targets: Vec<LiveSessionSummary>| {
            targets
                .into_iter()
                .map(|summary| summary.session_id.as_uuid().as_u128())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(wake_targets(
                &summaries,
                &projects,
                &seat,
                Some(&WakeRoute::Project(ProjectId::new("odin").unwrap())),
                None,
            )),
            vec![1]
        );
        assert_eq!(
            ids(wake_targets(
                &summaries,
                &projects,
                &seat,
                Some(&WakeRoute::Project(ProjectId::new("alpha").unwrap())),
                None,
            )),
            vec![3]
        );
        assert!(wake_targets(
            &summaries,
            &projects,
            &seat,
            Some(&WakeRoute::Project(ProjectId::new("rig").unwrap())),
            None,
        )
        .is_empty());
        assert_eq!(
            ids(wake_targets(&summaries, &projects, &seat, None, None)),
            vec![1, 3]
        );
        let child = LiveSessionId::new(uuid::Uuid::from_u128(9)).unwrap();
        assert_eq!(
            ids(wake_targets(
                &summaries,
                &projects,
                &seat,
                Some(&WakeRoute::Session(child)),
                None,
            )),
            vec![1, 3],
            "an unknown child must not be dropped onto the first session"
        );
        assert_eq!(
            ids(wake_targets(
                &summaries,
                &projects,
                &seat,
                Some(&WakeRoute::Session(child)),
                Some(&summaries[2].session_id),
            )),
            vec![3],
            "a known parent takes the wake even when another project is first"
        );
        assert_eq!(
            ids(wake_targets(
                &summaries,
                &projects,
                &seat,
                Some(&WakeRoute::Session(child)),
                Some(&summaries[1].session_id),
            )),
            vec![1, 3],
            "a failed parent is not a wake target"
        );
        assert_eq!(
            WakeRoute::from_event_id("push:alpha:main:abc"),
            Some(WakeRoute::Project(ProjectId::new("alpha").unwrap()))
        );
        assert_eq!(
            WakeRoute::from_event_id(&format!("child-{child}-turn")),
            Some(WakeRoute::Session(child))
        );
        assert_eq!(
            WakeRoute::from_event_id(&format!("stalled-{child}")),
            Some(WakeRoute::Session(child))
        );
        assert_eq!(
            WakeRoute::from_event_id(&format!("resumed:{child}:cause")),
            Some(WakeRoute::Session(child))
        );
        let command = wake_command_id(
            &format!("workload-{child}:crash-loop"),
            child,
            EventSeq::new(u64::MAX),
        )
        .expect("bounded command id");
        assert!(command.as_str().len() <= 128);
    }

    /// An ended session's journal replays in order to its head, from any cursor, and then stops.
    #[tokio::test]
    async fn an_ended_sessions_journal_replays_to_its_head_and_stops() {
        use crate::live::ledger::fs::FsLiveLedger;
        use crate::live::ledger::NewLiveEvent;
        use futures_util::StreamExt;
        use odin_domain::huginn::{SessionManifest, SessionStateChanged};
        use odin_domain::{EventId, NodeId, SliceId};

        let root = tempfile::tempdir().expect("tempdir");
        let ledger = Arc::new(FsLiveLedger::open(root.path()).expect("ledger"));
        let session = LiveSessionId::new(uuid::Uuid::from_u128(7)).expect("session");
        ledger
            .create_session(SessionManifest {
                session_id: session,
                seat_id: SeatId::new("seat:replay").expect("seat"),
                slice_id: SliceId::new("slice:replay").expect("slice"),
                project_id: ProjectId::new("project:replay").expect("project"),
                provider: ProviderName::new("fixture").expect("provider"),
                model: ModelName::new("fixture-model").expect("model"),
                title: None,
                target_node: NodeId::new("node:replay").expect("node"),
                open_tab: false,
                workload: None,
                served_revision: None,
                harness: None,
            })
            .await
            .expect("session");
        for index in 0..3 {
            ledger
                .append(
                    SessionEpoch::new(1),
                    NewLiveEvent {
                        session_id: session,
                        event_id: EventId::new(format!("event:replay-{index}")).expect("event"),
                        occurred_at: OffsetDateTime::now_utc(),
                        body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                            previous: LiveSessionState::Idle,
                            current: LiveSessionState::Running,
                            reason: None,
                        }),
                    },
                )
                .await
                .expect("event");
        }
        let replay = |after: u64| {
            finite_replay(
                &tokio::runtime::Handle::current(),
                ledger.clone(),
                session,
                EventSeq::new(after),
            )
            .map(|event| event.expect("replayed event").sequence.get())
            .collect::<Vec<_>>()
        };
        let all = tokio::time::timeout(std::time::Duration::from_secs(5), replay(0))
            .await
            .expect("the replay stops at the head");
        assert!(
            all.len() >= 3 && all.windows(2).all(|pair| pair[0] < pair[1]),
            "{all:?}"
        );
        let from = all[1];
        assert_eq!(replay(from).await, all[2..]);
    }
}
