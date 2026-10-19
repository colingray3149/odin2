//! Requests and responses for delegation tools.

use odin_domain::huginn::LiveSessionId;
use odin_domain::{CommandId, LaneId, ProjectId, RunId, SeatId, SessionId};
use serde::{Deserialize, Serialize};

use super::links::{DelegationPhase, WorkerLane};

/// One validated `task.create` request, host-derived from the dispatch scope.
#[derive(Clone, Debug)]
pub struct TaskCreateRequest {
    pub caller_session: SessionId,
    /// The calling run; its accepted plan authorizes the delegation.
    pub caller_run: RunId,
    /// The calling seat, for binding reconstruction.
    pub caller_seat: SeatId,
    /// The calling lane, for binding reconstruction.
    pub caller_lane: LaneId,
    /// The requested child project; must be inside the approved scope.
    pub project: ProjectId,
    pub prompt: String,
    /// The caller's own statement of the task's purpose (a seat ask's
    /// subject); absent, the first line of the prompt titles the child.
    pub title: Option<String>,
    /// Handler-selected target seat, never model input. `None` uses the configured
    /// same-seat worker; `Some` uses the target seat's resolved launch profile.
    pub target_seat: Option<SeatId>,
    /// One of the target seat's declared launch options for this delegation
    /// only; `None` uses the seat's chosen launch. The seat's choice is untouched.
    pub launch: Option<WorkerLane>,
}

/// Returned after the child opens, inherits its plan, and receives the prompt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskCreateReceipt {
    pub child_session: LiveSessionId,
    /// The child run carrying the inherited accepted plan.
    pub child_run: RunId,
    pub command_id: CommandId,
    pub project: ProjectId,
    /// The fixed configured worker provider.
    pub provider: String,
    /// The fixed configured worker model.
    pub model: String,
    /// Whether the child plan acceptance was recorded (inherited).
    pub plan_accepted: bool,
    pub prompt_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct TaskReadRequest {
    /// The calling session. The delegating parent session may read the child,
    /// and so may any later session of that parent seat.
    pub caller_session: SessionId,
    /// The calling seat, from the verified dispatch scope.
    pub caller_seat: SeatId,
    pub child: LiveSessionId,
    /// Whether the report carries the child's current terminal screen.
    pub screen: bool,
}

/// Lifecycle state from the supervisor and durable delegation row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskReadReport {
    pub child: LiveSessionId,
    /// The durable phase of the delegation row.
    pub phase: DelegationPhase,
    /// Whether the supervisor currently owns a live actor.
    pub active: bool,
    /// Supervisor-reported state, when known.
    pub state: Option<String>,
    /// Supervisor-reported epoch, when known.
    pub epoch: Option<i64>,
    /// Latest durable answer, limited to the output ceiling; `None` means absent.
    pub answer: Option<String>,
    /// Last typed `Result` event and its sequence; `None` means none was observed.
    #[serde(default)]
    pub result: Option<TaskResultReport>,
    pub project: ProjectId,
    /// The fixed configured worker provider.
    pub provider: String,
    /// The fixed configured worker model.
    pub model: String,
    /// Delegation depth (1 = worker of a root session).
    pub depth: u8,
    /// The lane (`provider/model`) at each recovered stall, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stalls: Vec<String>,
    /// The seat's declared lane the worker was moved to after a repeated
    /// stall; absent while it runs on `provider`/`model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub switched_to: Option<String>,
    /// The newest lines of the child's terminal screen, credentials
    /// withheld, when the read asked for it and the child has a tab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<String>,
    /// The child's capsule change against its base, while it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<TaskBranchReport>,
}

/// A worker's branch and base with `git diff --stat` and the bounded diff between them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskBranchReport {
    pub branch: String,
    pub base: String,
    pub stat: String,
    pub diff: String,
    pub truncated: bool,
}

/// The child's last durable `Result` event, not a result inferred from prose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskResultReport {
    /// Summary limited to the task.read output ceiling.
    pub summary: Option<String>,
    /// The artifact ids the typed result event declared, in order.
    pub artifacts: Vec<String>,
    /// Sequence of the `Result` event this report projects.
    pub event_sequence: u64,
}

/// Typed task-owner failure, preserving whether a child effect may have started.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskToolFailure {
    /// Stable snake-case rejection kind.
    pub kind: &'static str,
    pub detail: String,
    /// Distinguishes post-open failures from pre-effect rejections.
    pub effect_may_have_started: bool,
}

impl TaskToolFailure {
    pub(super) fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
            effect_may_have_started: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskControl {
    /// Stop the worker at a safe point, keeping its transcript.
    Pause,
    /// Continue a paused worker from where it stopped.
    Resume,
    /// End the worker: its session, harness and tab stop.
    Stop,
    /// Redirect the worker: mid-turn when it is working, otherwise as the
    /// instruction it continues with (a paused worker resumes with it).
    Steer(String),
}

#[derive(Clone, Debug)]
pub struct TaskControlRequest {
    pub caller_session: SessionId,
    /// The calling seat. The delegating parent session, any later session
    /// of the parent's seat (a rollover successor), or the seat the worker
    /// escalated to may control it — nobody else.
    pub caller_seat: SeatId,
    pub child: LiveSessionId,
    pub control: TaskControl,
}

/// What a control did, in the order the commands were applied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskControlReport {
    pub child: LiveSessionId,
    /// The worker's state before the control.
    pub before: String,
    /// The live commands applied, in order (empty: nothing needed doing).
    pub applied: Vec<String>,
    /// One plain sentence on the outcome.
    pub outcome: String,
}
