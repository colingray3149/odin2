//! Private bounded JSONL client for the sole Playwright worker.
//!
//! The worker is a mechanism adapter, not an authority boundary.  This module
//! bounds each line before allocation, caps outstanding calls with a semaphore,
//! correlates decimal request identifiers, retains cancelled dispatched calls
//! until their terminal response, and bounds queued event storage by bytes.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;

use odin_kernel::stop::WorkerId;
use odin_kernel::StopAuthority;

use crate::capability::ReadKind;
use crate::config::{WorkerLimits, MAX_WORKER_MESSAGE_BYTES_CEILING};
/// Statically compiled worker bytes, materialized create-once inside the
/// marked runtime root before Node is spawned.
pub(crate) const WORKER_SOURCE: &[u8] = include_bytes!("../worker/worker.cjs");

const PROTOCOL_VERSION: u8 = 1;
const READY_NAME: &str = "odin-playwright-worker";
const CALL_QUEUED: u8 = 0;
const CALL_CANCELLED: u8 = 1;
const CALL_DISPATCHED: u8 = 2;
const CALL_COMPLETED: u8 = 3;
const EVENT_QUEUE_SLOT_OVERHEAD_BYTES: usize = 1024;
const MAX_EVENT_QUEUE_RETAINED_BYTES: usize =
    MAX_WORKER_MESSAGE_BYTES_CEILING as usize + EVENT_QUEUE_SLOT_OVERHEAD_BYTES;

/// The only methods accepted by the embedded worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum WorkerMethod {
    Launch,
    ObservePage,
    Read,
    Preflight,
    Dispatch,
    ReleaseBinding,
    StageDownload,
    CancelDownload,
    StopFrames,
    CloseBrowser,
    Shutdown,
}

impl WorkerMethod {
    const fn possibly_mutating(self) -> bool {
        matches!(
            self,
            Self::Launch
                | Self::Dispatch
                | Self::StageDownload
                | Self::CancelDownload
                | Self::CloseBrowser
                | Self::Shutdown
        )
    }
}

/// Static error codes are the only failure detail accepted from JavaScript.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum WorkerErrorCode {
    InvalidEnvelope,
    InvalidMethod,
    InvalidParams,
    ProtocolViolation,
    BrowserLaunchFailed,
    FrameProducerStartFailed,
    BrowserClosed,
    OperationFailed,
    StaleBinding,
    BindingMissing,
    BindingIdMismatch,
    BindingBusy,
    AmbiguousSelector,
    MissingTarget,
    TargetDisconnected,
    TargetStructureChanged,
    ExpectedTargetMismatch,
    RequestDigestMismatch,
    DocumentChanged,
    BoundExceeded,
    InputStateUncertain,
    DownloadUnknown,
    DownloadRejected,
    DeadlineExceeded,
    CancelledBeforeDispatch,
    OutcomeUncertain,
    Internal,
}

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum WorkerError {
    #[error("worker channel is overloaded")]
    Overloaded,
    #[error("worker JSONL message exceeds its configured byte limit")]
    MessageTooLarge,
    #[error("worker channel is closed")]
    Disconnected,
    #[error("worker transport failed")]
    Transport,
    #[error("worker protocol message is malformed")]
    Malformed,
    #[error("worker rejected the operation: {code:?}")]
    Remote { code: WorkerErrorCode, fatal: bool },
    #[error("worker operation may have taken effect before cancellation: {code:?}")]
    UncertainMutation { code: WorkerErrorCode, fatal: bool },
    #[error("worker operation exceeded its deadline before dispatch")]
    DeadlineExceeded,
    #[error("worker event stream has already been taken")]
    EventStreamAlreadyTaken,
    #[error("worker channel shutdown exceeded its deadline")]
    ShutdownTimeout,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(crate) enum WorkerEvent {
    Frame {
        #[serde(rename = "capturedAt")]
        captured_at: u64,
        #[serde(rename = "jpegBase64")]
        jpeg_base64: String,
        #[serde(rename = "keyFrame")]
        key_frame: bool,
        #[serde(rename = "maskedRuntimeValueRegions")]
        masked_runtime_value_regions: u32,
    },
    DownloadBegin {
        #[serde(rename = "downloadId")]
        download_id: String,
        #[serde(rename = "suggestedFilename")]
        suggested_filename: String,
        #[serde(rename = "sourceUrl")]
        source_url: String,
        #[serde(rename = "expectedBytes")]
        expected_bytes: Option<u64>,
    },
    DownloadProgress {
        #[serde(rename = "downloadId")]
        download_id: String,
        state: WorkerDownloadState,
        #[serde(rename = "receivedBytes")]
        received_bytes: u64,
    },
    Protocol {
        name: String,
        #[serde(rename = "sessionScoped")]
        session_scoped: bool,
    },
}

/// Closed download states emitted by the worker.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum WorkerDownloadState {
    InProgress,
    Completed,
    Cancelled,
    Failed,
}

/// Sole consumer of the bounded event queue. Non-critical events drop newest;
/// critical download identity and terminal events fail the worker channel.
pub(crate) struct WorkerEventStream {
    events: mpsc::Receiver<WorkerEvent>,
    dropped_events: Arc<AtomicU64>,
}

impl WorkerEventStream {
    pub(crate) async fn next(&mut self) -> Option<WorkerEvent> {
        self.events.recv().await
    }

    pub(crate) fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LaunchParams {
    pub(crate) playwright_module_root: String,
    pub(crate) chromium_executable: String,
    pub(crate) user_data_dir: String,
    pub(crate) download_root: String,
    pub(crate) chromium_arguments: Vec<String>,
    pub(crate) viewport_width: u32,
    pub(crate) viewport_height: u32,
    pub(crate) max_message_bytes: u32,
    pub(crate) max_encoded_frame_bytes: u32,
    pub(crate) max_decoded_frame_bytes: u32,
    pub(crate) max_active_downloads: u32,
    pub(crate) max_download_file_bytes: u64,
    pub(crate) max_download_total_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LaunchResult {
    pub(crate) browser_launched: bool,
    pub(crate) frame_producer_started: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservePageParams {}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ObservePageResult {
    pub(crate) before: WorkerPageIdentity,
    pub(crate) after: WorkerPageIdentity,
    pub(crate) page_title: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerPageIdentity {
    pub(crate) display_url: String,
    pub(crate) origin: String,
    pub(crate) url_token: String,
    pub(crate) document_token: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadParams {
    pub(crate) kind: ReadKind,
    pub(crate) max_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReadResult {
    pub(crate) before: WorkerPageIdentity,
    pub(crate) after: WorkerPageIdentity,
    pub(crate) data: WorkerReadData,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum WorkerReadData {
    Text { text: String },
    Links { links: Vec<WorkerLink> },
    Tables { tables: Vec<WorkerTable> },
    Accessibility { root: WorkerAccessibilityNode },
    SanitizedDom { root: WorkerDomNode },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerLink {
    pub(crate) display_url: String,
    pub(crate) url_token: String,
    pub(crate) text: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerTable {
    pub(crate) caption: Option<String>,
    pub(crate) rows: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerAccessibilityNode {
    pub(crate) role: String,
    pub(crate) name: String,
    pub(crate) children: Vec<WorkerAccessibilityNode>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerDomNode {
    pub(crate) tag: String,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) text: Option<String>,
    pub(crate) children: Vec<WorkerDomNode>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PreflightParams {
    pub(crate) request_digest: String,
    pub(crate) selector: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PreflightResult {
    pub(crate) binding_id: String,
    pub(crate) document_token: String,
    pub(crate) target: Option<WorkerElementStructure>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerElementStructure {
    pub(crate) tag: String,
    pub(crate) input_type: Option<String>,
    pub(crate) in_form: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DispatchParams {
    pub(crate) binding_id: String,
    pub(crate) request_digest: String,
    pub(crate) document_token: String,
    pub(crate) expected_target: Option<WorkerElementStructure>,
    pub(crate) action: WorkerAction,
    pub(crate) max_screenshot_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum WorkerAction {
    Navigate { url: String },
    Back,
    Forward,
    Reload,
    Fill { selector: String, text: String },
    Activate { selector: String },
    SubmitForm { selector: String },
    PressKey { key: String },
    Scroll { delta_x: i32, delta_y: i32 },
    Screenshot,
    Close,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DispatchResult {
    pub(crate) navigation: Option<WorkerNavigation>,
    pub(crate) screenshot_base64: Option<String>,
    pub(crate) target_closed: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct WorkerNavigation {
    pub(crate) display_url: String,
    pub(crate) origin: String,
    pub(crate) url_token: String,
    pub(crate) document_token: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReleaseBindingParams {
    pub(crate) binding_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StageDownloadParams {
    pub(crate) download_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StageDownloadResult {
    pub(crate) download_id: String,
    pub(crate) received_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CancelDownloadParams {
    pub(crate) download_id: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptyParams {}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Ack {
    pub(crate) acknowledged: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestEnvelope<'a, P> {
    v: u8,
    id: &'a str,
    method: WorkerMethod,
    deadline_ms: u64,
    params: &'a P,
}

#[derive(Serialize)]
struct CancelEnvelope<'a> {
    v: u8,
    cancel: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyEnvelope {
    v: u8,
    ready: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessEnvelope {
    v: u8,
    id: String,
    ok: bool,
    result: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureEnvelope {
    v: u8,
    id: String,
    ok: bool,
    error: FailureBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureBody {
    code: WorkerErrorCode,
    uncertain: bool,
    fatal: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventEnvelope {
    v: u8,
    event: WorkerEvent,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IncomingEnvelope {
    Success(SuccessEnvelope),
    Failure(FailureEnvelope),
    Event(EventEnvelope),
}

struct CallCancellation {
    id: String,
    state: Arc<AtomicU8>,
    cancel_permit: Option<mpsc::OwnedPermit<ActorMail>>,
    active: bool,
}

impl CallCancellation {
    /// Returns true unless cancellation won while the call was still queued.
    /// A completed state is still uncertain until this caller observes the
    /// correlated terminal response.
    fn cancel(&mut self) -> bool {
        if !self.active {
            return false;
        }
        self.active = false;
        let may_have_dispatched = self
            .state
            .compare_exchange(
                CALL_QUEUED,
                CALL_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err();
        if let Some(permit) = self.cancel_permit.take() {
            let _ = permit.send(ActorMail::Cancel {
                id: std::mem::take(&mut self.id),
            });
        }
        may_have_dispatched
    }
}

impl Drop for CallCancellation {
    fn drop(&mut self) {
        let _ = self.cancel();
    }
}

enum ActorMail {
    Call {
        id: String,
        method: WorkerMethod,
        deadline_ms: u64,
        params: Value,
        respond: oneshot::Sender<Result<Value, WorkerError>>,
        state: Arc<AtomicU8>,
        permit: OwnedSemaphorePermit,
    },
    Cancel {
        id: String,
    },
    Close {
        respond: oneshot::Sender<Result<(), WorkerError>>,
    },
}

struct PendingCall {
    respond: oneshot::Sender<Result<Value, WorkerError>>,
    state: Arc<AtomicU8>,
    method: WorkerMethod,
    _permit: OwnedSemaphorePermit,
}

/// Cloneable, bounded caller front for the worker actor.
#[derive(Clone, Debug)]
pub(crate) struct WorkerCaller {
    tx: mpsc::Sender<ActorMail>,
    ids: Arc<AtomicU64>,
    slots: Arc<Semaphore>,
}

/// The worker's stdin sink: the kernel StopAuthority for locally owned
/// workers — the kernel retains the child handle — or the write half of an
/// established relayed stream for a remote worker. Closing either half is
/// the graceful remote stop: the worker exits on stdin EOF.
pub(crate) struct WorkerStdinHandle {
    pub(crate) sink: WorkerStdinSink,
}

pub(crate) enum WorkerStdinSink {
    Authority {
        authority: Arc<StopAuthority>,
        worker_id: WorkerId,
    },
    Relayed(Box<dyn AsyncWrite + Unpin + Send>),
}

impl WorkerCaller {
    pub(crate) async fn call<P, R>(
        &self,
        method: WorkerMethod,
        params: &P,
        deadline: Duration,
    ) -> Result<R, WorkerError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| WorkerError::Overloaded)?;
        let params = serde_json::to_value(params).map_err(|_| WorkerError::Malformed)?;
        // Reserve cancellation capacity before dispatch. The request cannot
        // enter the actor unless its eventual Cancel envelope is guaranteed a
        // bounded control-queue slot.
        let cancel_permit = self
            .tx
            .clone()
            .try_reserve_owned()
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => WorkerError::Overloaded,
                mpsc::error::TrySendError::Closed(_) => WorkerError::Disconnected,
            })?;
        let id = self.next_id();
        let state = Arc::new(AtomicU8::new(CALL_QUEUED));
        let (respond, response) = oneshot::channel();
        let mut cancellation = CallCancellation {
            id: id.clone(),
            state: Arc::clone(&state),
            cancel_permit: Some(cancel_permit),
            active: true,
        };
        if let Err(error) = self.tx.try_send(ActorMail::Call {
            id,
            method,
            deadline_ms: duration_millis(deadline),
            params,
            respond,
            state: Arc::clone(&state),
            permit,
        }) {
            cancellation.active = false;
            return Err(match error {
                mpsc::error::TrySendError::Full(_) => WorkerError::Overloaded,
                mpsc::error::TrySendError::Closed(_) => WorkerError::Disconnected,
            });
        }

        let result = match tokio::time::timeout(deadline, response).await {
            Ok(Ok(result)) => {
                cancellation.active = false;
                result
            }
            Ok(Err(_)) => {
                let may_have_dispatched = cancellation.cancel();
                if may_have_dispatched && method.possibly_mutating() {
                    Err(WorkerError::UncertainMutation {
                        code: WorkerErrorCode::OutcomeUncertain,
                        fatal: false,
                    })
                } else {
                    Err(WorkerError::Disconnected)
                }
            }
            Err(_) => {
                let may_have_dispatched = cancellation.cancel();
                if may_have_dispatched && method.possibly_mutating() {
                    Err(WorkerError::UncertainMutation {
                        code: WorkerErrorCode::DeadlineExceeded,
                        fatal: false,
                    })
                } else {
                    Err(WorkerError::DeadlineExceeded)
                }
            }
        }?;
        serde_json::from_value(result).map_err(|_| WorkerError::Malformed)
    }

    fn next_id(&self) -> String {
        loop {
            let id = self.ids.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id.to_string();
            }
        }
    }
}

/// Live worker channel: caller, sole event consumer, and actor task.
pub(crate) struct WorkerConnection {
    caller: WorkerCaller,
    event_stream: Option<WorkerEventStream>,
    actor: JoinHandle<Result<(), WorkerError>>,
}

impl WorkerConnection {
    /// Validates the worker's first line as the protocol handshake, then starts
    /// the correlated actor. Stdin is the worker's stdin sink — the kernel's
    /// StopAuthority for a local worker or the relayed stream — and stdout is
    /// the launched worker pipe.
    pub(crate) async fn connect(
        stdin: WorkerStdinHandle,
        stdout: Box<dyn AsyncRead + Unpin + Send>,
        limits: WorkerLimits,
        deadline: Duration,
    ) -> Result<Self, WorkerError> {
        let max_message_bytes = limits.max_message_bytes.get() as usize;
        if max_message_bytes > MAX_WORKER_MESSAGE_BYTES_CEILING as usize {
            return Err(WorkerError::MessageTooLarge);
        }
        let mut lines = BoundedLines::new(stdout, max_message_bytes);
        let ready_line = tokio::time::timeout(deadline, lines.next())
            .await
            .map_err(|_| WorkerError::DeadlineExceeded)??
            .ok_or(WorkerError::Disconnected)?;
        let ready: ReadyEnvelope =
            serde_json::from_slice(&ready_line).map_err(|_| WorkerError::Malformed)?;
        if ready.v != PROTOCOL_VERSION || ready.ready != READY_NAME {
            return Err(WorkerError::Malformed);
        }

        let depth = limits.max_in_flight_requests.get() as usize;
        // At most `depth` calls can hold permits. Reserve a second bounded
        // tranche for one cancellation per admitted call; Drop can therefore
        // always enqueue cancellation without awaiting.
        let (mail_tx, mail_rx) = mpsc::channel(depth.saturating_mul(2).saturating_add(1));
        let (incoming_tx, incoming_rx) = mpsc::channel(depth);
        // Charge every slot for its maximum payload plus conservative channel
        // and enum/String overhead. This keeps the configured count from
        // multiplying a large line limit into an unbounded retained footprint.
        let event_slot_bytes = max_message_bytes.saturating_add(EVENT_QUEUE_SLOT_OVERHEAD_BYTES);
        let byte_limited_event_depth = MAX_EVENT_QUEUE_RETAINED_BYTES / event_slot_bytes;
        let event_depth =
            (limits.max_event_queue_depth.get() as usize).min(byte_limited_event_depth.max(1));
        debug_assert!(
            event_depth.saturating_mul(event_slot_bytes) <= MAX_EVENT_QUEUE_RETAINED_BYTES
        );
        let (event_tx, event_rx) = mpsc::channel(event_depth);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let reader = tokio::spawn(read_incoming(lines, incoming_tx));
        let actor = tokio::spawn(run_actor(
            stdin,
            mail_rx,
            incoming_rx,
            event_tx,
            Arc::clone(&dropped_events),
            reader,
            max_message_bytes,
        ));
        Ok(Self {
            caller: WorkerCaller {
                tx: mail_tx,
                ids: Arc::new(AtomicU64::new(1)),
                slots: Arc::new(Semaphore::new(depth)),
            },
            event_stream: Some(WorkerEventStream {
                events: event_rx,
                dropped_events,
            }),
            actor,
        })
    }

    pub(crate) fn caller(&self) -> WorkerCaller {
        self.caller.clone()
    }

    pub(crate) fn take_event_stream(&mut self) -> Result<WorkerEventStream, WorkerError> {
        self.event_stream
            .take()
            .ok_or(WorkerError::EventStreamAlreadyTaken)
    }

    /// Closes stdin and accepts success only after the reader observes orderly
    /// EOF and the actor itself exits successfully.
    pub(crate) async fn close(mut self, deadline: Duration) -> Result<(), WorkerError> {
        self.event_stream.take();
        let stop_at = tokio::time::Instant::now()
            .checked_add(deadline)
            .ok_or(WorkerError::ShutdownTimeout)?;
        let (respond, acknowledged) = oneshot::channel();
        match tokio::time::timeout_at(stop_at, self.caller.tx.send(ActorMail::Close { respond }))
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return match tokio::time::timeout_at(stop_at, &mut self.actor).await {
                    Ok(Ok(Err(error))) => Err(error),
                    Ok(Ok(Ok(()))) => Ok(()),
                    Ok(Err(_)) => Err(WorkerError::Malformed),
                    Err(_) => {
                        self.actor.abort();
                        let _ = self.actor.await;
                        Err(WorkerError::ShutdownTimeout)
                    }
                };
            }
            Err(_) => {
                self.actor.abort();
                let _ = self.actor.await;
                return Err(WorkerError::ShutdownTimeout);
            }
        }

        let _acknowledged = match tokio::time::timeout_at(stop_at, acknowledged).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(WorkerError::Disconnected),
            Err(_) => {
                self.actor.abort();
                let _ = self.actor.await;
                return Err(WorkerError::ShutdownTimeout);
            }
        };
        let actor_result = match tokio::time::timeout_at(stop_at, &mut self.actor).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(WorkerError::Malformed),
            Err(_) => {
                self.actor.abort();
                let _ = self.actor.await;
                return Err(WorkerError::ShutdownTimeout);
            }
        };
        actor_result
    }
}

async fn read_incoming(
    mut lines: BoundedLines<Box<dyn AsyncRead + Unpin + Send>>,
    incoming: mpsc::Sender<Result<IncomingEnvelope, WorkerError>>,
) {
    loop {
        let item = match lines.next().await {
            Ok(Some(line)) => serde_json::from_slice::<IncomingEnvelope>(&line)
                .map_err(|_| WorkerError::Malformed),
            Ok(None) => return,
            Err(error) => {
                let _ = incoming.send(Err(error)).await;
                return;
            }
        };
        if incoming.send(item).await.is_err() {
            return;
        }
    }
}

async fn run_actor(
    stdin: WorkerStdinHandle,
    mut mail: mpsc::Receiver<ActorMail>,
    mut incoming: mpsc::Receiver<Result<IncomingEnvelope, WorkerError>>,
    events: mpsc::Sender<WorkerEvent>,
    dropped_events: Arc<AtomicU64>,
    reader: JoinHandle<()>,
    max_message_bytes: usize,
) -> Result<(), WorkerError> {
    let mut stdin = Some(stdin);
    let mut pending = HashMap::<String, PendingCall>::new();
    let mut channel_error = WorkerError::Disconnected;
    let mut close_response = None;
    let mut orderly_eof = false;
    let mut shutdown_acknowledged = false;
    loop {
        tokio::select! {
            biased;
            message = incoming.recv() => {
                let Some(message) = message else {
                    orderly_eof = close_response.is_some() || shutdown_acknowledged;
                    break;
                };
                match message {
                    Ok(IncomingEnvelope::Success(response)) => {
                        if response.v != PROTOCOL_VERSION || !response.ok || !valid_request_id(&response.id) {
                            channel_error = WorkerError::Malformed;
                            break;
                        }
                        let Some(call) = pending.remove(&response.id) else {
                            channel_error = WorkerError::Malformed;
                            break;
                        };
                        shutdown_acknowledged |= call.method == WorkerMethod::Shutdown;
                        call.state.store(CALL_COMPLETED, Ordering::Release);
                        let _ = call.respond.send(Ok(response.result));
                    }
                    Ok(IncomingEnvelope::Failure(response)) => {
                        if response.v != PROTOCOL_VERSION || response.ok || !valid_request_id(&response.id) {
                            channel_error = WorkerError::Malformed;
                            break;
                        }
                        let Some(call) = pending.remove(&response.id) else {
                            channel_error = WorkerError::Malformed;
                            break;
                        };
                        call.state.store(CALL_COMPLETED, Ordering::Release);
                        let error = if response.error.uncertain {
                            WorkerError::UncertainMutation {
                                code: response.error.code,
                                fatal: response.error.fatal,
                            }
                        } else {
                            WorkerError::Remote {
                                code: response.error.code,
                                fatal: response.error.fatal,
                            }
                        };
                        let _ = call.respond.send(Err(error));
                    }
                    Ok(IncomingEnvelope::Event(envelope)) => {
                        if envelope.v != PROTOCOL_VERSION || !valid_event(&envelope.event, max_message_bytes) {
                            channel_error = WorkerError::Malformed;
                            break;
                        }
                        match events.try_send(envelope.event) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(event)) => {
                                if critical_event(&event) {
                                    channel_error = WorkerError::Overloaded;
                                    break;
                                }
                                dropped_events.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(mpsc::error::TrySendError::Closed(event)) => {
                                if critical_event(&event) {
                                    channel_error = WorkerError::Disconnected;
                                    break;
                                }
                                dropped_events.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(error) => {
                        channel_error = error;
                        break;
                    }
                }
            }
            message = mail.recv(), if close_response.is_none() => {
                let Some(message) = message else { break; };
                match message {
                    ActorMail::Call { id, method, deadline_ms, params, respond, state, permit } => {
                        if state.compare_exchange(
                            CALL_QUEUED,
                            CALL_DISPATCHED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ).is_err() {
                            let _ = respond.send(Err(WorkerError::DeadlineExceeded));
                            continue;
                        }
                        let envelope = RequestEnvelope {
                            v: PROTOCOL_VERSION,
                            id: &id,
                            method,
                            deadline_ms,
                            params: &params,
                        };
                        let line = match encode_line(&envelope, max_message_bytes) {
                            Ok(line) => line,
                            Err(error) => {
                                state.store(CALL_COMPLETED, Ordering::Release);
                                let _ = respond.send(Err(error));
                                continue;
                            }
                        };
                        pending.insert(id, PendingCall { respond, state, method, _permit: permit });
                        let Some(handle) = stdin.as_mut() else {
                            channel_error = WorkerError::Disconnected;
                            break;
                        };
                        if write_worker_line(handle, line).await.is_err() {
                            channel_error = WorkerError::Transport;
                            break;
                        }
                    }
                    ActorMail::Cancel { id } => {
                        if pending.contains_key(&id) {
                            let envelope = CancelEnvelope { v: PROTOCOL_VERSION, cancel: &id };
                            let line = match encode_line(&envelope, max_message_bytes) {
                                Ok(line) => line,
                                Err(error) => {
                                    channel_error = error;
                                    break;
                                }
                            };
                            let Some(handle) = stdin.as_mut() else {
                                channel_error = WorkerError::Disconnected;
                                break;
                            };
                            if write_worker_line(handle, line).await.is_err() {
                                channel_error = WorkerError::Transport;
                                break;
                            }
                        }
                    }
                    ActorMail::Close { respond } => {
                        mail.close();
                        let Some(handle) = stdin.take() else {
                            channel_error = WorkerError::Disconnected;
                            let _ = respond.send(Err(channel_error.clone()));
                            break;
                        };
                        if close_worker_stdin(handle).await.is_err() {
                            channel_error = WorkerError::Transport;
                            let _ = respond.send(Err(channel_error.clone()));
                            break;
                        }
                        close_response = Some(respond);
                    }
                }
            }
        }
    }

    for (_, call) in pending {
        call.state.store(CALL_COMPLETED, Ordering::Release);
        let error = if call.method.possibly_mutating() {
            WorkerError::UncertainMutation {
                code: WorkerErrorCode::OutcomeUncertain,
                fatal: false,
            }
        } else {
            channel_error.clone()
        };
        let _ = call.respond.send(Err(error));
    }
    let actor_result = if orderly_eof {
        reader.await.map_err(|_| WorkerError::Transport)
    } else {
        reader.abort();
        let _ = reader.await;
        Err(channel_error)
    };
    if let Some(respond) = close_response {
        let _ = respond.send(actor_result.clone());
    }
    actor_result
}

async fn write_worker_line(
    handle: &mut WorkerStdinHandle,
    bytes: Vec<u8>,
) -> Result<(), WorkerError> {
    match &mut handle.sink {
        WorkerStdinSink::Authority {
            authority,
            worker_id,
        } => {
            let authority = Arc::clone(authority);
            let worker_id = worker_id.clone();
            tokio::task::spawn_blocking(move || {
                authority
                    .write_worker_stdin(&worker_id, &bytes)
                    .map_err(|_| WorkerError::Transport)
            })
            .await
            .map_err(|_| WorkerError::Transport)?
        }
        WorkerStdinSink::Relayed(writer) => writer
            .write_all(&bytes)
            .await
            .map_err(|_| WorkerError::Transport),
    }
}

/// Closes the stdin half. The authority path closes the kernel's retained
/// writer; the relayed path shuts the stream's write half down, which the
/// transport carries as remote stdin EOF. Dropping the handle afterwards
/// releases the half entirely.
async fn close_worker_stdin(handle: WorkerStdinHandle) -> Result<(), WorkerError> {
    match handle.sink {
        WorkerStdinSink::Authority {
            authority,
            worker_id,
        } => tokio::task::spawn_blocking(move || {
            authority
                .close_worker_stdin(&worker_id)
                .map_err(|_| WorkerError::Transport)
        })
        .await
        .map_err(|_| WorkerError::Transport)?,
        WorkerStdinSink::Relayed(mut writer) => {
            writer.shutdown().await.map_err(|_| WorkerError::Transport)
        }
    }
}

fn encode_line<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>, WorkerError> {
    let mut encoded = serde_json::to_vec(value).map_err(|_| WorkerError::Malformed)?;
    if encoded.len().saturating_add(1) > max {
        return Err(WorkerError::MessageTooLarge);
    }
    encoded.push(b'\n');
    Ok(encoded)
}

fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 20
        && id.as_bytes().iter().all(u8::is_ascii_digit)
        && id != "0"
        && !id.starts_with('0')
}

fn valid_event(event: &WorkerEvent, max: usize) -> bool {
    const MAX_ID: usize = 64;
    const MAX_FRAGMENT: usize = 16 * 1024;
    match event {
        WorkerEvent::Frame {
            jpeg_base64,
            key_frame,
            ..
        } => *key_frame && jpeg_base64.len() <= max,
        WorkerEvent::DownloadBegin {
            download_id,
            suggested_filename,
            source_url,
            ..
        } => {
            valid_component(download_id, MAX_ID)
                && suggested_filename.len() <= MAX_FRAGMENT
                && source_url.len() <= MAX_FRAGMENT
        }
        WorkerEvent::DownloadProgress { download_id, .. } => valid_component(download_id, MAX_ID),
        WorkerEvent::Protocol { name, .. } => {
            name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }
    }
}

fn critical_event(event: &WorkerEvent) -> bool {
    matches!(
        event,
        WorkerEvent::DownloadBegin { .. }
            | WorkerEvent::DownloadProgress {
                state: WorkerDownloadState::Completed
                    | WorkerDownloadState::Cancelled
                    | WorkerDownloadState::Failed,
                ..
            }
    )
}

fn valid_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().clamp(1, u64::MAX as u128) as u64
}

/// Async line decoder which rejects an oversized line before extending its
/// owned accumulator beyond the configured bound.  `BufReader`'s fixed
/// internal buffer is transport storage, never attacker-sized allocation.
struct BoundedLines<R> {
    reader: BufReader<R>,
    accumulated: Vec<u8>,
    max: usize,
}

impl<R: AsyncRead + Unpin> BoundedLines<R> {
    fn new(reader: R, max: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            accumulated: Vec::with_capacity(max.min(8 * 1024)),
            max,
        }
    }

    async fn next(&mut self) -> Result<Option<Vec<u8>>, WorkerError> {
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| WorkerError::Transport)?;
            if available.is_empty() {
                if self.accumulated.is_empty() {
                    return Ok(None);
                }
                return Err(WorkerError::Malformed);
            }
            if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
                let mut content_end = newline;
                if content_end > 0 && available[content_end - 1] == b'\r' {
                    content_end -= 1;
                }
                if self.accumulated.len().saturating_add(content_end) > self.max {
                    return Err(WorkerError::MessageTooLarge);
                }
                self.accumulated
                    .extend_from_slice(&available[..content_end]);
                self.reader.consume(newline + 1);
                if self.accumulated.is_empty() {
                    return Err(WorkerError::Malformed);
                }
                return Ok(Some(std::mem::take(&mut self.accumulated)));
            }
            if self.accumulated.len().saturating_add(available.len()) > self.max {
                return Err(WorkerError::MessageTooLarge);
            }
            let consumed = available.len();
            self.accumulated.extend_from_slice(available);
            self.reader.consume(consumed);
        }
    }
}
