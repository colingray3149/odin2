//! Delegation capability identities and runtime provisioning and lifecycle interfaces.

use std::time::{Duration, Instant};

use odin_domain::huginn::LiveSessionId;
use odin_domain::{CommandId, LaneId, ProjectId, RunId, SeatId, SessionId};
use serde::{Deserialize, Serialize};

use crate::host_tools::operations::SessionOperationBinding;
pub const TASK_CREATE_TOOL: &str = "task_create";
pub const TASK_READ_TOOL: &str = "task_read";
pub const TASK_CREATE_CAPABILITY: &str = "task.create";
pub const TASK_READ_CAPABILITY: &str = "task.read";
pub const TASK_CREATE_HANDLER_ID: &str = "odin_task.create";
pub const TASK_CREATE_EVIDENCE_ID: &str = "odin_task.create_evidence";
pub const TASK_READ_HANDLER_ID: &str = "odin_task.read";
pub const TASK_READ_EVIDENCE_ID: &str = "odin_task.read_evidence";
pub const TASK_PAUSE_TOOL: &str = "task_pause";
pub const TASK_PAUSE_CAPABILITY: &str = "task.pause";
pub const TASK_PAUSE_HANDLER_ID: &str = "odin_task.pause";
pub const TASK_PAUSE_EVIDENCE_ID: &str = "odin_task.pause_evidence";
pub const TASK_STEER_TOOL: &str = "task_steer";
pub const TASK_STEER_CAPABILITY: &str = "task.steer";
pub const TASK_STEER_HANDLER_ID: &str = "odin_task.steer";
pub const TASK_STEER_EVIDENCE_ID: &str = "odin_task.steer_evidence";

/// Maximum governed delegation depth. A root session's children are depth
/// one; a seat answering another seat's ask may delegate one level more.
/// Depth-two children are leaves.
pub const MAX_DELEGATION_DEPTH: u8 = 2;

/// Only a child answering another seat may delegate; same-seat workers and
/// children at the maximum depth are leaves. Returns the new child's depth.
pub fn nested_child_depth(
    caller_depth: u8,
    asked_by: Option<&SeatId>,
    caller_seat: &SeatId,
) -> Result<u8, &'static str> {
    let answering_another_seat = asked_by.is_some_and(|asker| asker != caller_seat);
    if !answering_another_seat {
        return Err("delegated workers cannot create tasks; a worker is a leaf");
    }
    let depth = caller_depth.saturating_add(1);
    if depth > MAX_DELEGATION_DEPTH {
        return Err("delegation depth is bounded at two levels; this child is a leaf");
    }
    Ok(depth)
}

/// Whether `task_create` is on a session's surface: every root session
/// (`link` is `None`), and a delegated child [`nested_child_depth`] lets
/// delegate. `seat` is the session's own seat.
pub fn holds_task_create(link: Option<&super::DelegationLink>, seat: &SeatId) -> bool {
    link.is_none_or(|link| nested_child_depth(link.depth, link.parent_seat.as_ref(), seat).is_ok())
}

/// Parent authority rechecked before each child effect: token, accepted plan,
/// and delegation depth. Derived from the runtime binding, not wire input.
#[derive(Clone)]
pub struct ParentSessionLink {
    pub session: SessionId,
    pub binding: SessionOperationBinding,
    /// The parent run whose accepted plan the child inherited.
    pub run: RunId,
    /// The parent's delegation depth (0 for a root session).
    pub depth: u8,
}

/// Both session IDs use the same canonical UUID representation.
pub(crate) fn live_session_id(session: &SessionId) -> Result<LiveSessionId, String> {
    let uuid = uuid::Uuid::parse_str(session.as_str())
        .map_err(|error| format!("session {session} is not a live session identity: {error}"))?;
    LiveSessionId::new(uuid)
        .map_err(|error| format!("session {session} is not a live session identity: {error}"))
}

/// The open command determines the child session ID; the title also names its Zellij tab.
#[derive(Clone, Copy, Debug)]
pub struct ChildOpen<'a> {
    pub command: &'a CommandId,
    /// The validated in-scope project.
    pub project: &'a ProjectId,
    pub title: &'a str,
    /// The request's one-delegation launch choice, resolved again through
    /// [`ChildAuthorityProvisioner::seat_worker_profile`].
    pub launch: Option<&'a super::links::WorkerLane>,
}

/// Longest child title, in characters.
const CHILD_TITLE_CHARS: usize = 48;

/// The operator-facing purpose of a delegated child: the first non-blank
/// line of its prompt, whitespace-collapsed and bounded at a word boundary.
pub fn child_title(prompt: &str) -> String {
    let line = prompt
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    let mut title = String::with_capacity(CHILD_TITLE_CHARS);
    for word in line.split_whitespace() {
        let needed = title.chars().count() + usize::from(!title.is_empty()) + word.chars().count();
        if needed > CHILD_TITLE_CHARS {
            if title.is_empty() {
                title.extend(word.chars().take(CHILD_TITLE_CHARS));
            }
            break;
        }
        if !title.is_empty() {
            title.push(' ');
        }
        title.push_str(word);
    }
    title
}

/// Runtime provisioning from the parent's pinned configuration.
/// The link must be durable before minting a token or opening the child idle.
/// The returned session ID must derive from the open command.
pub trait ChildAuthorityProvisioner: Send + Sync {
    /// Provisions one governed child for the already-durable parent link.
    ///
    /// `parent_seat`/`parent_lane` are the calling parent session's
    /// configured seat and lane;
    /// `parent_session` its bridge identity; `child` the host-minted open
    /// command, in-scope project and purpose title. The child
    /// token and session binding derive from the parent's pinned snapshot —
    /// same allowed seat scope, fixed configured worker provider/model, and
    /// no capability the worker cannot hold. The parent's own operation
    /// binding is recomposed from the parent's own generation at every child
    /// build; it is never carried through the delegation request.
    fn provision_child(
        &self,
        parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &SessionId,
        child: ChildOpen<'_>,
    ) -> Result<LiveSessionId, String>;

    /// Resolves a declared launch option before writing the link row.
    /// Uses `requested`, then the seat's chosen launch, then its first option.
    /// The resolved pair is passed through composition and minting without reordering.
    fn seat_worker_profile(
        &self,
        target_seat: &SeatId,
        requested: Option<&super::links::WorkerLane>,
    ) -> Result<(String, String), String>;

    /// Provisions one governed child on the TARGET seat for the
    /// already-durable parent link: the child composes from the target
    /// seat's pinned composition and opens with the target seat's resolved
    /// worker profile — passed explicitly from the one
    /// [`Self::seat_worker_profile`] resolution, never the `[delegation]`
    /// route and never a request-named provider/model.
    fn provision_child_for_seat(
        &self,
        parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &SessionId,
        child: ChildOpen<'_>,
        target_seat: &SeatId,
    ) -> Result<LiveSessionId, String>;

    /// Read-only readiness check before approval, using the same composition,
    /// launch, and terminal checks as provisioning. Must not reserve capacity,
    /// mint tokens, open sessions, clone capsules, or write stores.
    /// `None` selects same-seat provisioning; `Some` selects the target seat.
    /// Provisioning repeats these checks after approval.
    fn preflight_child(
        &self,
        parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &SessionId,
        child_project: &ProjectId,
        target_seat: Option<&SeatId>,
        launch: Option<&super::links::WorkerLane>,
    ) -> Result<(), String>;
}

/// Nonblocking lifecycle snapshot of one child session, read from the live
/// supervisor. `state` is the supervisor's own summary state when known.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildLifecycleSnapshot {
    /// Whether the supervisor currently owns a live actor for the child.
    pub active: bool,
    /// The supervisor-reported session state, when a summary exists.
    pub state: Option<odin_domain::huginn::LiveSessionState>,
    /// The supervisor-reported ownership epoch, when a summary exists.
    pub epoch: Option<i64>,
    /// When a live child settled, in unix ms: for an `Idle` child when it
    /// went idle, for a `Failed` child when it first entered `Failed`
    /// (later journaled events never move it). `None` while it works, in
    /// any other state, or when it is not live.
    pub settled_since_ms: Option<u64>,
    /// While a live child works (`Running`), when it last made journaled
    /// progress, in unix ms: a working child quiet for long is stalled.
    pub quiet_since_ms: Option<u64>,
    /// When a live child rests (idle or failed) because its latest turn
    /// ended on an error Odin answers — a stalled stream, a usage-limit
    /// refusal, a rejected key, or a context refusal — that error's event,
    /// kind and origin (see [`provider_turn_fault`]).
    pub provider_fault: Option<ProviderTurnFault>,
}

/// What a provider error that ended a child's turn means for the worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFaultKind {
    /// OMP gave up on a stream that went silent: the lane may answer the
    /// next request (the Retry rung resumes it, a repeat moves the lane).
    Stall,
    /// The provider refused the request over its usage limit (429, quota).
    UsageLimit,
    /// The provider rejected the key the lane uses (401/403).
    RejectedKey,
    /// The request does not fit the lane model's context window.
    ContextOverflow,
    /// Odin's extension refused the request for another context reason (an
    /// unusable declaration, the model not matching the declared lane).
    ContextGuard,
}

impl ProviderFaultKind {
    /// The cause as logged and recorded (`cause=` on the log line).
    pub fn cause(self) -> &'static str {
        match self {
            Self::Stall => "provider_stall",
            Self::UsageLimit => "usage_limit",
            Self::RejectedKey => "rejected_key",
            Self::ContextOverflow => "context_overflow",
            Self::ContextGuard => "context_guard",
        }
    }

    /// The failure in plain words, never the provider's raw body.
    pub fn plain(self) -> &'static str {
        match self {
            Self::Stall => "its model stream stopped answering",
            Self::UsageLimit => "its model provider says it is over its usage limit",
            Self::RejectedKey => "its model provider rejected the key it uses",
            Self::ContextOverflow => "its request was larger than its model's context window",
            Self::ContextGuard => "Odin's context guard could not admit its request on this model",
        }
    }

    /// Whether the same lane would refuse the next request too: a refusal is
    /// never re-sent to its lane — the next request goes to another one.
    pub fn refuses_lane(self) -> bool {
        !matches!(self, Self::Stall)
    }
}

/// The kind of a provider error, by its HTTP status when the frame carried
/// one, otherwise by what the message says. Status digits in the message
/// are not a status. `None` for anything else (an outage, a bad request),
/// which no lane change answers.
pub fn provider_fault_kind(message: &str, status: Option<u16>) -> Option<ProviderFaultKind> {
    let lower = message.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|needle| lower.contains(needle));
    if lower.contains("stream stalled") {
        Some(ProviderFaultKind::Stall)
    } else if has(&[
        "context size has been exceeded",
        "context_length_exceeded",
        "contextwindowexceeded",
        "maximum context length",
        "exceeds the context window",
        "exceed_context_size",
    ]) {
        Some(ProviderFaultKind::ContextOverflow)
    } else if status == Some(429) {
        Some(ProviderFaultKind::UsageLimit)
    } else if matches!(status, Some(401 | 403)) {
        Some(ProviderFaultKind::RejectedKey)
    } else if has(&[
        "quota",
        "rate limit",
        "rate_limit",
        "ratelimiterror",
        "usage limit",
        "insufficient_quota",
        "too many requests",
    ]) {
        Some(ProviderFaultKind::UsageLimit)
    } else if has(&[
        "unauthorized",
        "forbidden",
        "invalid api key",
        "invalid_api_key",
        "incorrect api key",
        "authenticationerror",
        "authentication fail",
    ]) {
        Some(ProviderFaultKind::RejectedKey)
    } else {
        None
    }
}

/// The error code of the extension's authenticated refusal of a request
/// over the lane's declared context window.
const CONTEXT_REFUSAL_WINDOW_EXCEEDED: &str = "context_refusal.window_exceeded";

/// The error code prefix of every authenticated context refusal.
const CONTEXT_REFUSAL_PREFIX: &str = "context_refusal.";

/// Who ended a child's turn on a fault Odin answers. Both leave the child
/// `Failed`; only an authenticated context refusal is answered by the typed
/// rollover, while a provider-reported overflow is a lane refusal like any
/// other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFaultOrigin {
    /// The model provider failed the turn (OMP's `provider_turn_error`).
    Provider,
    /// Odin's own extension refused the request before it left (an
    /// authenticated `context_refusal.*`).
    ContextRefusal,
}

/// The error event that ended the child's latest turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderTurnFault {
    pub event: u64,
    pub kind: ProviderFaultKind,
    pub origin: ProviderFaultOrigin,
}

/// Finds a recoverable provider or context error after the latest user or
/// assistant message. Failed turns need recovery even though they are not running.
pub fn provider_turn_fault(events: &[odin_domain::huginn::LiveEvent]) -> Option<ProviderTurnFault> {
    use odin_domain::huginn::LiveEventBody;
    let mut fault = None;
    for event in events {
        match &event.body {
            LiveEventBody::UserMessage(_) | LiveEventBody::AssistantMessage(_) => fault = None,
            LiveEventBody::Error(error) if error.code == "provider_turn_error" => {
                fault = provider_fault_kind(&error.message, error.error_status).map(|kind| {
                    ProviderTurnFault {
                        event: event.sequence.get(),
                        kind,
                        origin: ProviderFaultOrigin::Provider,
                    }
                });
            }
            // Odin's own extension refused the request before it left: it
            // does not fit the lane's declared window.
            LiveEventBody::Error(error) if error.code.starts_with(CONTEXT_REFUSAL_PREFIX) => {
                fault = Some(ProviderTurnFault {
                    event: event.sequence.get(),
                    kind: if error.code == CONTEXT_REFUSAL_WINDOW_EXCEEDED {
                        ProviderFaultKind::ContextOverflow
                    } else {
                        ProviderFaultKind::ContextGuard
                    },
                    origin: ProviderFaultOrigin::ContextRefusal,
                });
            }
            _ => {}
        }
    }
    fault
}

/// One delegation refused because the daemon was about to reload.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeferredDelegation {
    pub caller_seat: SeatId,
    pub target_seat: Option<SeatId>,
    pub title: Option<String>,
    pub prompt: String,
    pub deferred_at_ms: u64,
}

/// Stop outcomes let the report pump settle absent sessions without retrying them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildStop {
    /// The live actor completed teardown.
    Ended,
    /// No live incarnation existed; the stop wrote a durable `Ended` transition.
    SettledAbsent,
    /// The session was already durably terminal, or never existed:
    /// nothing was ended and nothing was written.
    AlreadyTerminal,
}

/// A command's delivery status from its durable journal or transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryVerdict {
    /// Journaled `Applied`, or a completion event in the transcript.
    Delivered,
    /// Rejected before journaling, or completed as `Failed`/`Cancelled`.
    Refused(String),
    /// Journaled without an outcome, or the transcript could not be read.
    /// Keep the recorded attempt; do not retry under a fresh command ID.
    Unsettled,
}

/// Control error prefix for an unknown delivery outcome; retain the recorded
/// attempt rather than retrying under a fresh command ID.
pub const INDETERMINATE_DELIVERY: &str = "indeterminate delivery";

/// The typed prefix of an `open_delivery` error whose target session has
/// ended: no attempt can ever reach it, so the caller stops retrying.
pub const TARGET_ENDED: &str = "delivery target ended";
/// Supervisor-facing control seam of the governed delegation.
///
/// Implemented by the Odin runtime over the live supervisor. Implementations
/// must keep every method bounded; the owner calls them from the host-tool
/// executor's blocking context.
pub trait ChildSessionControl: Send + Sync {
    /// Whether the supervisor currently owns a live actor for `child`.
    fn snapshot(&self, child: LiveSessionId) -> Result<ChildLifecycleSnapshot, String>;

    /// Sends one bounded prompt to the opened child session.
    fn prompt(&self, child: LiveSessionId, message: &str) -> Result<(), String>;

    /// Whether the daemon restarts shortly to activate a publication: a
    /// child opened now could not run a turn until it has.
    fn reload_pending(&self) -> bool {
        false
    }

    /// Records one creation a pending reload deferred, so the delegating
    /// side is woken after the restart to delegate it again.
    fn defer_until_reload(&self, _deferred: &DeferredDelegation) -> Result<(), String> {
        Err("this runtime records no deferred delegations".to_owned())
    }

    /// Opens one delivery attempt: mints the command id at the target's
    /// current epoch and head (its live actor's, or its journal's when it
    /// is parked, which `deliver` then reopens) and returns the EXACT
    /// command, so the caller can record it durably BEFORE dispatching.
    /// An ended target fails with the [`TARGET_ENDED`] prefix.
    fn open_delivery(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<odin_domain::huginn::LiveCommand, String> {
        let _ = (child, body);
        Err("this control opens no delivery attempts".to_owned())
    }

    /// Dispatches a new or recorded command. On `Unsettled` or infrastructure
    /// failure, retain the attempt: an unreachable actor does not establish its outcome.
    fn deliver(
        &self,
        command: odin_domain::huginn::LiveCommand,
    ) -> Result<DeliveryVerdict, String> {
        let _ = command;
        Err("this control delivers no commands".to_owned())
    }
    /// Applies one live command (pause, resume, steer, follow-up) to the
    /// child's actor at its current epoch and head; `Err` carries the
    /// actor's rejection (e.g. the command does not apply in its state).
    fn command(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<(), String> {
        let _ = body;
        Err(format!(
            "live commands to {child} are not supported by this control"
        ))
    }

    /// Rolls one failed child into a FRESH incarnation of the same session
    /// (the typed context-refusal rollover): planned retirement, epoch + 1,
    /// a new empty conversation, and ONE journaled continuity brief built
    /// from the session's durable rows under its declared rollover policy.
    /// `refusal_event` is the provider error event the rollover answers
    /// (journaled evidence). `Ok` carries the fresh epoch and the child is
    /// Running again; the one bounded call never retries and never holds a
    /// turn-length await.
    fn rollover(&self, child: LiveSessionId, refusal_event: u64) -> Result<u64, String> {
        let _ = (child, refusal_event);
        Err("context-refusal rollover is not supported by this control".to_owned())
    }

    /// The child seat's next declared launch option after `current` — the
    /// lane a repeatedly stalled child falls back to. The options after
    /// `current` in declaration order, then those before it, skipping every
    /// option naming `current`'s pair. `Ok(None)`: the seat declares no
    /// other lane.
    fn next_launch_option(
        &self,
        child: LiveSessionId,
        current: &super::links::WorkerLane,
    ) -> Result<Option<super::links::WorkerLane>, String> {
        let _ = (child, current);
        Ok(None)
    }

    /// Waits for teardown, or durably settles a session with no live incarnation.
    /// Used for create-path cleanup and parent-initiated stops.
    fn stop_child(&self, child: LiveSessionId) -> Result<ChildStop, String>;

    /// Awaits one child's live actor until it is observed stopped or the
    /// budget expires; `Ok(false)` is an honest timeout, never a success.
    fn await_stop(&self, child: LiveSessionId, budget: Duration) -> Result<bool, String>;

    /// Retires the calling session's exact capsule authority through the
    /// pool's StopAuthority chain as part of the bounded stop closure; the
    /// coordinator calls it after every delegated child is verified stopped,
    /// so a session never claims success while its own private backend may
    /// still run. The deadline is the coordinator's original stop deadline.
    fn retire_capsule_on_stop(
        &self,
        session: LiveSessionId,
        deadline: Instant,
    ) -> Result<(), String>;

    /// The child's full last observed human-readable answer in `epoch`.
    /// `None` reads all retained epochs for whole-workload reports. A new
    /// incarnation must not publish an earlier incarnation's text as its
    /// answer. Presentation bounds belong to the caller; unreadability is
    /// `Err`, not absence.
    fn last_answer(
        &self,
        child: LiveSessionId,
        epoch: Option<i64>,
    ) -> Result<Option<String>, String>;

    /// The newest lines of the child's terminal screen, credentials
    /// withheld; `Ok(None)` when it has no live tab.
    fn screen(&self, child: LiveSessionId) -> Result<Option<String>, String> {
        let _ = child;
        Ok(None)
    }

    /// The child's work since its base commit; `Ok(None)` when it has no Git capsule.
    fn branch(
        &self,
        child: LiveSessionId,
    ) -> Result<Option<super::vocabulary::TaskBranchReport>, String> {
        let _ = child;
        Ok(None)
    }

    /// The last typed `Result` event and its sequence, not a result inferred from prose.
    /// `Ok(None)` means no result was observed; read failures return `Err`.
    fn last_result(
        &self,
        child: LiveSessionId,
    ) -> Result<Option<super::vocabulary::TaskResultReport>, String>;

    /// The live workload (pod) sessions resting between turns, idle or
    /// failed, each with the launch operation that created its pod. A pod
    /// session is no delegation link, so this is how its settled run is
    /// found. Default: none.
    fn resting_workload_sessions(
        &self,
    ) -> Result<Vec<(LiveSessionId, String, WorkloadRest)>, String> {
        Ok(Vec::new())
    }

    /// Every ended workload (pod) session with the launch operation that
    /// created its pod, read from the durable ledger: the carrier-release
    /// backlog that outlives a session's resting-scan visibility — a
    /// release that failed, or a daemon that died between the session's
    /// end and its release — enumerable independent of session liveness.
    fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String>;
}

/// How a workload (pod) session rests between turns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadRest {
    /// Idle after a turn: its last answer is the run's result.
    Idle,
    /// Failed at `since_ms` (unix milliseconds of its last event); a new
    /// turn would hand it on.
    Failed { since_ms: u64 },
}

/// One child's observed stop outcome, reported by the bounded parent stop.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChildStopRecord {
    pub child: LiveSessionId,
    /// Whether its live actor was observed stopped within the budget.
    pub stopped: bool,
    /// Re-pointed to a successor vehicle and left running. Not a stop.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub handed_off: bool,
    /// Failure detail when the child was not stopped.
    pub detail: Option<String>,
}

/// Bounded parent stop seam held weakly by the bridge.
///
/// Implemented by the governed owner; the bridge stores a [`std::sync::Weak`]
/// so an owner that strongly owns the supervisor cannot form a reference
/// cycle through the session actor back into the bridge.
pub trait ChildStopCoordinator: Send + Sync {
    /// Stops every live child delegated by `parent`; returns `Err` if any child
    /// cannot be confirmed stopped.
    fn await_children_on_stop(
        &self,
        parent: LiveSessionId,
        budget: Duration,
    ) -> Result<Vec<ChildStopRecord>, String>;
}
