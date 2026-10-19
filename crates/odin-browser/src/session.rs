//! Playwright-backed browser session facade.
//!
//! The facade keeps mutable control truth behind one
//! `Arc<tokio::sync::Mutex<State>>`, serializing control operations and
//! retaining at most one pending prepared action. The sole typed worker event
//! stream stays on the owning [`BrowserSession`]. Waiting for idle event
//! delivery never holds the control-state guard. Lifecycle transitions remain
//! explicit: `Live` can become `TargetClosed` after an executed close or
//! `InputUncertain` after an unconfirmed paired-input release; any active
//! phase becomes `Stopped` on explicit shutdown. Dropping the last
//! session/handle alias stops owned WorkerIds through StopAuthority and
//! deliberately leaves the profile.
//!
//! Policy shape, capability assignment, effect classes, approval authority,
//! and command/action journaling live above this crate. The narrow takeover
//! generation is the exception: its canonical browser-owned snapshot is
//! CAS-persisted through `odin-ledger` so a replacement host fences the old
//! holder before launching. The facade verifies the policy and control
//! revisions a prepared action was bound to are still current at execute time,
//! the retained worker binding is revalidated by the dispatch helper, and a
//! supplied [`ConsumedApproval`] names the capability and canonical arguments
//! digest of the exact prepared request. Typed worker events are routed
//! exhaustively and never leave the facade raw: frames enter the bounded frame
//! stream; downloads enter the bounded quarantine/scanner manager only after
//! Rust admission; page
//! observations taken after launch, navigation, and text entry build the public
//! session view; protocol notices carry only a bounded name and scope. Action
//! screenshots are published and checked against the returned artifact binding
//! before they are reported.

#[path = "session/actions.rs"]
mod actions;
#[path = "session/control.rs"]
mod control;
#[path = "session/events.rs"]
mod events;
#[path = "session/handle.rs"]
mod handle;
#[path = "session/lifecycle.rs"]
mod lifecycle;
#[path = "session/reads.rs"]
mod reads;
#[path = "session/runtime.rs"]
pub(crate) mod runtime;
#[path = "session/state.rs"]
mod state;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::artifact::ArtifactRef;
use odin_domain::huginn::browser::{BrowserDownloadView, BrowserSessionView, BrowserTakeoverView};
use odin_domain::huginn::ids::{BrowserSessionId, DeviceId, DownloadId, StreamId};
use odin_domain::{CapabilityId, Digest};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::capability::{
    ActionRequest, ArtifactPublisher, CapabilityError, DomBinding, NavigationObservation,
    PolicyBinding, StructuralDescriptor,
};
use crate::config::{ConfigError, FrameLimits};
use crate::download::{DownloadError, DownloadManager, QuarantineRecord};
use crate::policy::{ActionRule, BrowserPolicySnapshot, PolicyInvalidation, StructuralAction};
use crate::profile::ProfileError;
use crate::safety::BrowserSafetyGate;
use crate::stream::{FrameRecord, FrameStream, FrameStreamError};
use crate::takeover::{TakeoverCoordinator, TakeoverError};
use crate::worker::WorkerEventStream;

// --- Errors -----------------------------------------------------------------

/// Exact, metadata-safe stage of a browser mechanism startup failure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BrowserLaunchStage {
    XvfbReadiness,
    WorkerSpawn,
    WorkerHandshake,
    BrowserLaunch,
    FrameProducerStart,
    WorkerExited,
    XvfbExited,
}

impl BrowserLaunchStage {
    /// Stable public code. Every value is static and contains no process,
    /// filesystem, or transport detail.
    pub const fn code(self) -> &'static str {
        match self {
            Self::XvfbReadiness => "xvfb-readiness",
            Self::WorkerSpawn => "worker-spawn",
            Self::WorkerHandshake => "worker-handshake",
            Self::BrowserLaunch => "browser-launch",
            Self::FrameProducerStart => "frame-producer-start",
            Self::WorkerExited => "worker-exited",
            Self::XvfbExited => "xvfb-exited",
        }
    }
}

impl fmt::Display for BrowserLaunchStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

/// Typed failures of one browser session. [`SessionError::LaunchStage`] is
/// reserved for mechanism startup; `Transport` and `Timeout` retain their
/// post-launch operation semantics.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("browser launch failed: {0}")]
    Launch(String),
    #[error("browser launch failed during {stage}")]
    LaunchStage { stage: BrowserLaunchStage },
    #[error("browser shutdown failed: {0}")]
    Shutdown(String),
    #[error("browser worker transport failure: {0}")]
    Transport(String),
    #[error("browser operation `{operation}` exceeded its deadline")]
    Timeout { operation: &'static str },
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(transparent)]
    Capability(Box<CapabilityError>),
    #[error("policy rejected the update: {0}")]
    Policy(#[from] crate::policy::BrowserPolicyError),
    #[error("takeover transition rejected: {0}")]
    Takeover(#[from] TakeoverError),
    #[error("frame admission rejected: {0}")]
    Frame(#[source] Box<FrameStreamError>),
    #[error("download handling failed: {0}")]
    Download(#[from] DownloadError),
    #[error("browser outbound payload was blocked by the session safety gate")]
    OutboundBlocked {
        field: String,
        protected_label: Option<String>,
        code: &'static str,
    },
    #[error("session is stopped")]
    Stopped,
    #[error("session page is closed; only shutdown remains")]
    TargetClosed,
    #[error("paired browser input release was not confirmed; only shutdown remains safe")]
    InputUncertain,
    #[error("no pending action with id {action_id}")]
    UnknownAction { action_id: ActionId },
    #[error("another prepared action ({held}) is still pending")]
    PendingActionExists { held: ActionId },
    #[error("structural action `{action:?}` has no rule in the active policy")]
    PolicyUnmapped { action: StructuralAction },
    #[error("action {action_id} was bound to a superseded policy revision")]
    StalePolicyBinding { action_id: ActionId },
    #[error("action {action_id} was bound to a superseded control revision")]
    StaleControlBinding { action_id: ActionId },
    #[error("structural action `{action:?}` requires kernel approval before dispatch")]
    ApprovalRequired { action: StructuralAction },
    #[error("approval for action {action_id} does not match the prepared request")]
    ApprovalMismatch { action_id: ActionId },
    #[error("session control revision overflowed")]
    ControlRevisionOverflow,
    #[error("browser durable control state is unavailable")]
    DurableControlUnavailable,
    #[error("browser durable control state is invalid")]
    DurableControlInvalid,
    #[error("browser durable control state changed concurrently")]
    DurableControlStale,
    #[error("browser takeover expiry has not yet been observed")]
    TakeoverExpiryUnobserved,
    #[error("navigation target host is outside the session's declared hosts")]
    NavigateHostDenied,
}

impl From<CapabilityError> for SessionError {
    fn from(error: CapabilityError) -> Self {
        Self::Capability(Box::new(error))
    }
}

impl From<FrameStreamError> for SessionError {
    fn from(error: FrameStreamError) -> Self {
        Self::Frame(Box::new(error))
    }
}

// --- Public facade types ------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    /// Runtime is live; reads, actions, frames, and takeover all operate.
    Live,
    /// The page was closed by an executed `Close` action.
    TargetClosed,
    /// A paired input release could not be confirmed. No further worker-backed
    /// work may run; only explicit teardown remains safe.
    InputUncertain,
    /// Terminal; the runtime is gone (teardown or drop fallback).
    Stopped,
}

/// Identifier of one prepared action, unique within a session.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ActionId(pub u64);

impl fmt::Display for ActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Bounded deadlines and byte bounds for every operation. Mechanical
/// resource bounds only; no site, format, or effect decision lives here.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// Whole-read deadline (observation, extraction, projection).
    pub read: Duration,
    /// Read-only preflight deadline during action preparation.
    pub preflight: Duration,
    /// Authorized dispatch deadline, including revalidation round trips.
    pub dispatch: Duration,
    /// Hard byte ceiling applied to action screenshots.
    pub max_screenshot_bytes: usize,
}

impl SessionLimits {
    fn validate(&self) -> Result<(), SessionError> {
        for (name, deadline) in [
            ("read", self.read),
            ("preflight", self.preflight),
            ("dispatch", self.dispatch),
        ] {
            if deadline.is_zero() {
                return Err(SessionError::Launch(format!(
                    "session {name} deadline must be non-zero"
                )));
            }
        }
        if self.max_screenshot_bytes == 0 {
            return Err(SessionError::Launch(
                "session screenshot byte bound must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Stream and publication wiring supplied by the composing layer. The same
/// durable publisher accepts frame, screenshot, and completed-download bytes;
/// each path verifies its returned artifact binding before projection.
///
/// `stream: false` disables frame publication and retention for the session;
/// actions, observations, and screenshots remain available.
#[derive(Clone)]
pub struct FrameWiring {
    pub stream_id: StreamId,
    pub limits: FrameLimits,
    pub publisher: Arc<dyn ArtifactPublisher>,
    pub stream: bool,
}

/// Approval evidence supplied by the kernel after durably consuming an exact
/// approval. Verified against the active rule and the prepared request's
/// canonical digest; the facade never mints one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedApproval {
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
}

/// Read-only result of action preparation: everything the journaling
/// authority needs (rule, bindings, canonical digest) plus the pending
/// [`ActionId`]. No mutation has been sent to the browser at this point.
#[derive(Clone, Debug)]
pub struct PreparedActionView {
    pub action_id: ActionId,
    pub request: ActionRequest,
    /// Structural action used only to select the higher authority's rule.
    /// The original request and descriptor retain their wire-level action.
    pub policy_action: StructuralAction,
    pub descriptor: StructuralDescriptor,
    pub dom_binding: DomBinding,
    pub policy_binding: PolicyBinding,
    pub control_revision: u64,
    pub arguments_digest: Digest,
    pub rule: ActionRule,
    pub prepared_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub struct ExecutedAction {
    pub action_id: ActionId,
    pub request: ActionRequest,
    pub policy_binding: PolicyBinding,
    pub control_revision: u64,
    pub navigation: Option<NavigationObservation>,
    /// Durable raster artifact checked against the exact captured PNG bytes.
    pub screenshot: Option<ArtifactRef>,
}

/// One routed event from the bounded typed-worker queue. Every event either
/// reaches a typed bounded subsystem — frames, downloads, or the page view —
/// or is retained as bounded redacted protocol evidence. No raw protocol
/// payload, page text, or host path ever appears in a public event.
#[derive(Clone, Debug)]
pub enum SessionEvent {
    /// A validated frame: decoded JPEG bytes published through the durable
    /// artifact publisher and retained by the bounded stream.
    Frame(FrameRecord),
    /// A worker frame that could not be admitted. The reason is bounded
    /// mechanism text, never page or payload content.
    FrameRejected {
        reason: String,
    },
    Download(BrowserDownloadView),
    Quarantined(QuarantineRecord),
    DownloadRejected {
        download_id: Option<DownloadId>,
        reason: String,
    },
    /// The newest session view, built from a bounded page observation after
    /// launch, navigation, or text entry, or from a lifecycle transition.
    /// Views supersede: while the consumer has not pumped, only the newest
    /// view is retained and its `revision` shows the jump.
    Session(BrowserSessionView),
    /// Lossless bounded control fact produced when the production lease timer
    /// or an admission check retires a held takeover.
    TakeoverLeaseExpired(TakeoverLeaseExpiry),
    /// Static failure code for a control transition the session could not
    /// commit durably. The projection treats this as terminal and shuts the
    /// runtime down; no worker mutation follows it.
    ControlFailure {
        code: &'static str,
    },
    /// Redacted evidence for a protocol notice no typed subsystem consumed.
    Protocol(ProtocolObservation),
    /// The bounded worker event queue dropped `count` events before delivery.
    /// A delivery fact; never control truth.
    EventsDropped {
        count: u64,
    },
}

/// Bounded, redacted evidence of one worker protocol notice. Carries only the
/// stable notice name and whether it is session-scoped; no raw protocol
/// parameters can leave the private worker client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolObservation {
    pub method: String,
    pub session_scoped: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbandonedAction {
    pub action_id: ActionId,
}

/// Exact observed facts of one takeover control-lease expiry. Produced by the
/// production session timer, by control-admission checks, and by the sealed
/// local supervision entry point — never by a remote command. After the
/// retirement no holder survives, the takeover revision has advanced, and the
/// in-flight owner work is cancelled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TakeoverLeaseExpiry {
    /// Device whose lease was retired.
    pub holder: DeviceId,
    /// Durable session control revision minted for the lease generation (the
    /// retired token). Unlike the takeover-local revision, this never resets
    /// across a store-backed reopen.
    pub lease_token: u64,
    /// Controller truth after retirement: available with an advanced
    /// revision and no holder.
    pub view: BrowserTakeoverView,
    /// Holder after the transition, derived from the returned controller
    /// truth. Real expiry returns `None`.
    pub holder_after_expiry: Option<DeviceId>,
    /// The in-flight owner action cancelled with the lease, if one was
    /// pending. Its session slot is removed and worker-binding release is
    /// attempted idempotently in the same serialized transition.
    pub cancelled_action: Option<AbandonedAction>,
    /// Actual remaining pending-action count after the serialized expiry
    /// cleanup. The facade permits at most one pending action.
    pub outstanding_after_expiry: u64,
    /// Control revision after the expiry bump. Every action or frame token
    /// bound to a lower value is stale and is rejected at execute time.
    pub control_revision: u64,
}

/// One atomic snapshot of serialized browser control truth for exact
/// expiry/restart holder, token, revision, and pending-action observation.
/// Reading it never substitutes for the internal durable CAS owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserControlSnapshot {
    /// Session control generation stamped onto frames and prepared actions.
    pub control_revision: u64,
    /// Per-session takeover status and its independent coordinator revision.
    pub takeover: BrowserTakeoverView,
    /// Current remote device holder; `None` when available or locally reclaimed.
    pub remote_holder: Option<DeviceId>,
    /// Durable token of the held lease; `None` when no remote holder survives.
    pub lease_token: Option<u64>,
    /// Current held lease deadline; `None` when no remote holder survives.
    pub lease_deadline: Option<OffsetDateTime>,
    /// Sole in-flight prepared action, if any.
    pub pending_action: Option<ActionId>,
}

/// Outcome of a compare-and-swap policy update.
#[derive(Clone, Debug)]
pub struct PolicyUpdateReport {
    pub snapshot: BrowserPolicySnapshot,
    pub invalidation: PolicyInvalidation,
    /// Pending action abandoned because the update superseded its binding.
    pub abandoned: Option<ActionId>,
    pub control_revision: u64,
}

/// Observable facts of an explicit, bounded runtime teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionTeardown {
    pub profile_id: String,
    pub frame_producer_stopped: bool,
    pub browser_close_attempted: bool,
    pub worker_channel_closed: bool,
    pub worker_owned: bool,
    pub worker_term_sent: bool,
    pub worker_kill_sent: bool,
    pub worker_reaped: bool,
    pub xvfb_owned: bool,
    pub xvfb_term_sent: bool,
    pub xvfb_kill_sent: bool,
    pub xvfb_reaped: bool,
    pub profile_removed: bool,
    /// Remote-exit evidence is absent for local workers, whose exit is confirmed by reaping.
    pub relayed_exit: Option<String>,
}

impl From<runtime::RuntimeTeardown> for SessionTeardown {
    fn from(teardown: runtime::RuntimeTeardown) -> Self {
        Self {
            profile_id: teardown.profile_id,
            frame_producer_stopped: teardown.frame_producer_stopped,
            browser_close_attempted: teardown.browser_close_attempted,
            worker_channel_closed: teardown.worker_channel_closed,
            worker_owned: teardown.worker_owned,
            worker_term_sent: teardown.worker_term_sent,
            worker_kill_sent: teardown.worker_kill_sent,
            worker_reaped: teardown.worker_reaped,
            xvfb_owned: teardown.xvfb_owned,
            xvfb_term_sent: teardown.xvfb_term_sent,
            xvfb_kill_sent: teardown.xvfb_kill_sent,
            xvfb_reaped: teardown.xvfb_reaped,
            profile_removed: teardown.profile_removed,
            relayed_exit: teardown.relayed_exit,
        }
    }
}

// --- Serialized session state -------------------------------------------------

/// Latest observed page facts retained for the session view. Only the
/// redacted display URL (no userinfo, query, or fragment), origin, and
/// clipped title are kept.
struct ObservedPage {
    url_display: String,
    origin: String,
    title: String,
}

/// The one pending prepared action. Carries no authority: dispatch happens
/// only through [`BrowserHandle::execute_action`] after the higher authority
/// has decided and, where required, consumed an approval.
struct PendingAction {
    id: ActionId,
    request: ActionRequest,
    policy_action: StructuralAction,
    preflight: actions::ActionPreflight,
    policy: PolicyBinding,
    control_revision: u64,
}

/// Mutable session control truth. Guarded by one tokio mutex so each control
/// operation and each delivered event are routed serially. Waiting for the next
/// worker event happens outside this state and never holds the guard.
struct State {
    phase: SessionPhase,
    runtime: Option<runtime::BrowserRuntime>,
    policy: BrowserPolicySnapshot,
    gate: Arc<BrowserSafetyGate>,
    takeover: TakeoverCoordinator,
    /// Durable control-generation token of the currently held remote lease.
    /// `None` exactly when no remote holder survives.
    takeover_lease_token: Option<u64>,
    /// Bumped by every policy update and takeover transition. Stamped onto
    /// frames and prepared actions and revalidated before dispatch.
    control_revision: u64,
    /// Store-backed authority generation. Production sessions always carry
    /// this owner; fixture-only fresh launches may remain in-memory.
    durable_control: Option<control::DurableControlOwner>,
    /// Sole undelivered expiry fact. A new lease cannot be admitted until its
    /// exact cancellation observation is consumed.
    lease_expiry_unreported: Option<TakeoverLeaseExpiry>,
    pending: Option<PendingAction>,
    next_action_id: u64,
    limits: SessionLimits,
    worker_command_deadline: Duration,
    frames: Arc<FrameStream>,
    downloads: DownloadManager,
    publisher: Arc<dyn ArtifactPublisher>,
    stream_id: StreamId,
    /// Opaque isolated-profile id for the session view; never a path.
    profile_id: String,
    /// Declared navigation allowlist enforced per action (exact host
    /// equality, the composition's declaration — never page content).
    /// `None` admits every navigation, exactly like a session composed
    /// without a declared scope.
    navigate_hosts: Option<std::collections::BTreeSet<String>>,
    opened_at: OffsetDateTime,
    view_revision: u64,
    view: Option<BrowserSessionView>,
    view_unreported: bool,
    page: Option<ObservedPage>,
}

// The session actor holds this state's tokio guard across awaits, so every
// session future keeps `Send` only while `State` stays `Sync`. A non-`Sync`
// field here otherwise surfaces as an unexplainable spawn-bound failure in a
// downstream consumer's `tokio::spawn`, not at this owning seam.
const _: () = {
    const fn assert_sync<T: ?Sized + Sync>() {}
    assert_sync::<State>();
};

// --- BrowserSession -----------------------------------------------------------

/// One live browser session. Owns the runtime and sole typed worker
/// event-consumer capability; hands out cheap [`BrowserHandle`] control/read
/// aliases and frame stream readers, and performs the explicit bounded
/// shutdown. Dropping the last session/handle alias drops the state and
/// runtime, whose `Drop` stops owned WorkerIds through StopAuthority and
/// leaves the marked profile on disk.
pub struct BrowserSession {
    // Declared first so implicit drop closes the receiver before the final
    // state alias can drop the runtime and its worker client.
    events: WorkerEventStream,
    state: Arc<Mutex<State>>,
    frames: Arc<FrameStream>,
    session_id: BrowserSessionId,
    dropped_seen: u64,
}

// --- BrowserHandle ------------------------------------------------------------

/// Cloneable control/read handle to one serialized session. Every method
/// locks the state for the operation's duration, so calls from any number of
/// tasks are strictly ordered. It cannot consume worker events or admit frames.
#[derive(Clone)]
pub struct BrowserHandle {
    state: Arc<Mutex<State>>,
    frames: Arc<FrameStream>,
    session_id: BrowserSessionId,
}
