//! Seat delegation through the configured governed task owner.
//!
//! Targets come from admitted capability contracts, not model input.
//! The caller's live seat, lane, session, and accepted plan determine authorization.
//! Same-seat and cross-seat requests share the same task-owner checks and result mapping.

use std::sync::Arc;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{LaneId, ProjectId, RunId, SeatId, SessionId};
use odin_omp::host_tools::delegation::{
    DelegationPhase, TaskCreateReceipt, TaskCreateRequest, TaskOwner, TaskReadReport,
    TaskReadRequest, TaskToolFailure,
};

/// One typed seat-delegation request. The `target` seat is the admitted
/// contract's declared delegation target — never model input and never a
/// compiled constant.
#[derive(Clone, Debug)]
pub struct SeatAskRequest {
    /// The delegating Odin session (a real session under the caller seat).
    pub session: SessionId,
    /// The calling run whose accepted plan authorizes the delegation.
    pub run: RunId,
    /// The calling session's seat from the live dispatch scope.
    pub caller_seat: SeatId,
    /// The live session lane used with `caller_seat` to resolve the operation binding.
    pub caller_lane: LaneId,
    /// The requested child project; must sit inside the approved scope and,
    /// for a cross-seat target, be a configured project of the target seat.
    pub project: ProjectId,
    /// The exact worker prompt bytes.
    pub prompt: String,
    /// What the ask is about (its declared subject): titles the child's
    /// session and Zellij tab.
    pub title: Option<String>,
    /// The declared delegation target from the admitted contract.
    pub target: SeatId,
    /// One of the target's declared launch options for this ask only;
    /// the seat's choice is untouched.
    pub launch: Option<odin_omp::host_tools::delegation::WorkerLane>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SeatAskOutcome {
    /// A real child session exists: the link row is durable, the plan is
    /// inherited, and the prompt was dispatched.
    Accepted(SeatTaskAccepted),
    /// Rejected before creating a child; `kind` is a stable error id.
    Rejected { kind: String, detail: String },
    /// A child opened before the failure and may have produced effects.
    Uncertain { kind: String, detail: String },
}

/// Projection of the durable delegation receipt onto the seat-delegation
/// surface.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeatTaskAccepted {
    pub child_session: String,
    pub child_run: String,
    pub command_id: String,
    pub project: String,
    pub provider: String,
    pub model: String,
    pub plan_accepted: bool,
    pub prompt_bytes: usize,
}

impl SeatTaskAccepted {
    fn project(receipt: TaskCreateReceipt) -> Self {
        Self {
            child_session: receipt.child_session.to_string(),
            child_run: receipt.child_run.to_string(),
            command_id: receipt.command_id.to_string(),
            project: receipt.project.to_string(),
            provider: receipt.provider,
            model: receipt.model,
            plan_accepted: receipt.plan_accepted,
            prompt_bytes: receipt.prompt_bytes,
        }
    }
}

pub struct SeatDelegator {
    owner: Arc<dyn TaskOwner>,
    max_prompt_bytes: usize,
}

impl SeatDelegator {
    /// Uses the configured prompt limit; each request supplies its live caller seat and lane.
    pub fn new(owner: Arc<dyn TaskOwner>, max_prompt_bytes: usize) -> Self {
        Self {
            owner,
            max_prompt_bytes,
        }
    }

    /// Records on the worker's task row that it escalated to `target`, so
    /// that seat may deliver the decision with `task_steer`.
    pub fn escalate(
        &self,
        child: odin_domain::huginn::LiveSessionId,
        target: odin_domain::SeatId,
    ) -> Result<(), TaskToolFailure> {
        self.owner.escalate_task(child, target)
    }

    /// Checks prompt limits and task-owner readiness without creating a child; execution rechecks them.
    pub fn preflight(&self, request: &SeatAskRequest) -> Result<(), TaskToolFailure> {
        if request.prompt.trim().is_empty() {
            return Err(TaskToolFailure {
                kind: "empty_prompt",
                detail: "the delegated task prompt must not be empty".to_owned(),
                effect_may_have_started: false,
            });
        }
        if request.prompt.len() > self.max_prompt_bytes {
            return Err(TaskToolFailure {
                kind: "prompt_too_large",
                detail: format!(
                    "the delegated task prompt exceeds the configured bound of {} bytes",
                    self.max_prompt_bytes
                ),
                effect_may_have_started: false,
            });
        }
        let target_seat = (request.target != request.caller_seat).then(|| request.target.clone());
        self.owner.preflight_task(&TaskCreateRequest {
            caller_session: request.session.clone(),
            caller_run: request.run.clone(),
            caller_seat: request.caller_seat.clone(),
            caller_lane: request.caller_lane.clone(),
            project: request.project.clone(),
            prompt: request.prompt.clone(),
            title: request.title.clone(),
            target_seat,
            launch: request.launch.clone(),
        })
    }

    /// Uses `target_seat: None` for same-seat workers; other targets use their configured launch route.
    pub fn ask(&self, request: &SeatAskRequest) -> SeatAskOutcome {
        if request.prompt.trim().is_empty() {
            return SeatAskOutcome::Rejected {
                kind: "empty_prompt".to_owned(),
                detail: "the delegated task prompt must not be empty".to_owned(),
            };
        }
        if request.prompt.len() > self.max_prompt_bytes {
            return SeatAskOutcome::Rejected {
                kind: "prompt_too_large".to_owned(),
                detail: format!(
                    "the delegated task prompt exceeds the configured bound of {} bytes",
                    self.max_prompt_bytes
                ),
            };
        }
        let target_seat = (request.target != request.caller_seat).then(|| request.target.clone());
        match self.owner.create_task(TaskCreateRequest {
            caller_session: request.session.clone(),
            caller_run: request.run.clone(),
            caller_seat: request.caller_seat.clone(),
            caller_lane: request.caller_lane.clone(),
            project: request.project.clone(),
            prompt: request.prompt.clone(),
            title: request.title.clone(),
            target_seat,
            launch: request.launch.clone(),
        }) {
            Ok(receipt) => SeatAskOutcome::Accepted(SeatTaskAccepted::project(receipt)),
            Err(TaskToolFailure {
                kind,
                detail,
                effect_may_have_started,
            }) => {
                if effect_may_have_started {
                    SeatAskOutcome::Uncertain {
                        kind: kind.to_owned(),
                        detail,
                    }
                } else {
                    SeatAskOutcome::Rejected {
                        kind: kind.to_owned(),
                        detail,
                    }
                }
            }
        }
    }

    /// Waits until the child settles or the deadline expires, returning its latest report either way.
    pub fn await_answer(
        &self,
        caller_seat: &SeatId,
        session: &SessionId,
        child: &str,
        wait: std::time::Duration,
    ) -> Result<TaskReadReport, TaskToolFailure> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let report = self.status(caller_seat, session, child)?;
            let settled = !matches!(
                report.phase,
                DelegationPhase::Provisioning | DelegationPhase::Running
            );
            if settled || std::time::Instant::now() >= deadline {
                return Ok(report);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }

    /// Reads child status without waiting; only the delegating parent session may read it.
    pub fn status(
        &self,
        caller_seat: &SeatId,
        session: &SessionId,
        child: &str,
    ) -> Result<TaskReadReport, TaskToolFailure> {
        let child = LiveSessionId::parse(child).map_err(|error| TaskToolFailure {
            kind: "invalid_child",
            detail: format!("the delegated child session id is invalid: {error}"),
            effect_may_have_started: false,
        })?;
        self.owner.read_task(TaskReadRequest {
            caller_session: session.clone(),
            caller_seat: caller_seat.clone(),
            child,
            screen: false,
        })
    }
}
