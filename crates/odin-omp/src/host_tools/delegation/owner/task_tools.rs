//! Task creation, lifecycle reads, controls, and escalation.

use odin_domain::huginn::LiveSessionId;
use odin_domain::SeatId;

use super::{GovernedTaskOwner, TaskOwner};
use crate::host_tools::delegation::contracts::{live_session_id, MAX_DELEGATION_DEPTH};
use crate::host_tools::delegation::links::{DelegationLink, DelegationPhase};
use crate::host_tools::delegation::vocabulary::{
    TaskControl, TaskControlReport, TaskControlRequest, TaskCreateReceipt, TaskCreateRequest,
    TaskReadReport, TaskReadRequest, TaskToolFailure, TASK_READ_ANSWER_CHARS,
};

impl GovernedTaskOwner {
    /// Whether the caller delegated `link`'s child or one of its delegators:
    /// the exact session, or any session of that seat.
    fn is_ancestor(
        &self,
        link: &DelegationLink,
        caller_session: &odin_domain::SessionId,
        caller_seat: &SeatId,
    ) -> Result<bool, TaskToolFailure> {
        let mut link = link.clone();
        for _ in 0..MAX_DELEGATION_DEPTH {
            if link.parent == *caller_session || link.parent_seat.as_ref() == Some(caller_seat) {
                return Ok(true);
            }
            let parent = live_session_id(&link.parent)
                .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?;
            match self
                .links
                .load(&parent)
                .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
            {
                Some(above) => link = above,
                None => return Ok(false),
            }
        }
        Ok(false)
    }

    /// An active delegated caller who shares the target's delegating parent
    /// and project. A fresh replacement keeps that parent link, so it remains
    /// a sibling. A different parent or project is not.
    fn is_active_sibling(
        &self,
        target: &DelegationLink,
        caller_session: &odin_domain::SessionId,
    ) -> Result<bool, TaskToolFailure> {
        // A caller that is not a live session has no delegation link.
        let Ok(caller) = live_session_id(caller_session) else {
            return Ok(false);
        };
        let Some(caller_link) = self
            .links
            .load(&caller)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
        else {
            return Ok(false);
        };
        if !caller_link.phase.is_live() {
            return Ok(false);
        }
        Ok(caller_link.parent == target.parent && caller_link.project == target.project)
    }
}
impl GovernedTaskOwner {
    /// Applies one typed raise of the worker's declared lane budget. The
    /// shared raise store is the admission authority and is updated under
    /// its lock before this returns, so two simultaneous steers cannot
    /// both pass a stale cap and a later one cannot lower an earlier one.
    /// The row records the same raise second, as history, without rewriting
    /// project or pending_report. An exact-limit, below-floor, or
    /// undeclared value is refused by the limit key; the worker is not steered.
    fn raise_lane_budget(
        &self,
        child: LiveSessionId,
        link: &mut DelegationLink,
        raise: odin_registry::LaneBudgetRaise,
    ) -> Result<TaskControlReport, TaskToolFailure> {
        let Some(lane) = link.lane.clone() else {
            return Err(TaskToolFailure::new(
                "lane_undeclared",
                "this worker has no lane; task.steer cannot raise a budget",
            ));
        };
        let declared = self.declared_lane_limits(&lane)?;
        let applied = odin_registry::RaisedLaneBudgets::commit(
            self.links.huginn_root(),
            lane.as_str(),
            &declared,
            raise,
        )
        .map_err(|error| TaskToolFailure::new(error.kind(), error.detail().to_owned()))?;
        self.write_link(&child, |fresh| {
            if !fresh.budget_raises.contains(&raise) {
                fresh.budget_raises.push(raise);
            }
            true
        })
        .map_err(|error| TaskToolFailure::new("link_persistence_failed", error))?;
        if !link.budget_raises.contains(&raise) {
            link.budget_raises.push(raise);
        }
        Ok(TaskControlReport {
            child,
            before: format!("{:?}", link.phase),
            applied: vec![format!("raise:{}", raise.kind.key())],
            outcome: format!(
                "{} raised to {applied}; the worker was not steered",
                raise.kind.key()
            ),
        })
    }
}

impl TaskOwner for GovernedTaskOwner {
    fn acknowledge_inline_answer(&self, child: LiveSessionId, key: &str) -> Result<(), String> {
        let snapshot = self.control.snapshot(child)?;
        if !self
            .settled_turn(child, &snapshot)
            .is_some_and(|turn| turn.key == key)
        {
            return Ok(());
        }
        self.write_link(&child, |link| {
            if link.reported_answer.as_deref() == Some(key) {
                return false;
            }
            if link
                .pending_report
                .as_ref()
                .is_some_and(|pending| pending.key != key)
            {
                return false;
            }
            link.reported_answer = Some(key.to_owned());
            link.pending_report = None;
            true
        })
        .map(|_| ())
    }

    fn child_moved_past(&self, child: LiveSessionId, key: &str) -> bool {
        let Ok(snapshot) = self.control.snapshot(child) else {
            return false;
        };
        snapshot.active
            && !self
                .settled_turn(child, &snapshot)
                .is_some_and(|turn| turn.key == key)
    }

    fn escalate_task(&self, child: LiveSessionId, target: SeatId) -> Result<(), TaskToolFailure> {
        let link = self
            .links
            .load(&child)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
            .ok_or_else(|| {
                TaskToolFailure::new("not_a_task", format!("{child} is not a delegated worker"))
            })?;
        self.write_link(&link.child, |fresh| {
            fresh.escalated_to = Some(target);
            fresh.escalation_open = true;
            true
        })
        .map(|_| ())
        .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))
    }

    fn control_task(
        &self,
        request: TaskControlRequest,
    ) -> Result<TaskControlReport, TaskToolFailure> {
        use odin_domain::huginn::{LiveCommandBody as Body, LiveSessionState as State};
        let child = request.child;
        let mut link = self
            .links
            .load(&child)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
            .ok_or_else(|| {
                TaskToolFailure::new("not_a_task", format!("{child} is not a delegated worker"))
            })?;
        let authorized = link.parent == request.caller_session
            || link.parent_seat.as_ref() == Some(&request.caller_seat)
            || link.escalated_to.as_ref() == Some(&request.caller_seat)
            || self.is_ancestor(&link, &request.caller_session, &request.caller_seat)?
            || self.is_active_sibling(&link, &request.caller_session)?;
        if !authorized {
            return Err(TaskToolFailure::new(
                "not_the_parent",
                format!(
                    "worker {child} was delegated by seat {} (session {}) and escalated to {}; \
                     seat {} may not control it",
                    link.parent_seat
                        .as_ref()
                        .map_or("unknown", |seat| seat.as_str()),
                    link.parent,
                    link.escalated_to
                        .as_ref()
                        .map_or("nobody", |seat| seat.as_str()),
                    request.caller_seat
                ),
            ));
        }
        if let TaskControl::RaiseLaneBudget(raise) = request.control {
            return self.raise_lane_budget(child, &mut link, raise);
        }
        if link.phase == DelegationPhase::Ended {
            if request.control != TaskControl::Stop {
                return Err(TaskToolFailure::new(
                    "not_running",
                    format!("worker {child} has ended"),
                ));
            }
            self.run_completion_capture(&mut link);
            return Ok(TaskControlReport {
                child,
                before: "Ended".to_owned(),
                applied: Vec::new(),
                outcome: "already ended; pending task learning capture retried".to_owned(),
            });
        }
        let snapshot = self
            .control
            .snapshot(child)
            .map_err(|error| TaskToolFailure::new("supervisor_unavailable", error))?;
        let mut state = match (snapshot.active, snapshot.state) {
            (true, Some(state)) => state,
            (false, Some(State::Failed)) if request.control != TaskControl::Stop => {
                return Err(TaskToolFailure::new(
                    "not_running",
                    format!("worker {child} has failed and is not running; start a new task"),
                ));
            }
            (_, state) => {
                return Err(TaskToolFailure::new(
                    "not_running",
                    format!(
                        "worker {child} is not running (last state {})",
                        state.map_or("unknown".to_owned(), |state| format!("{state:?}"))
                    ),
                ))
            }
        };
        let mut restarted = false;
        if state == State::Failed && request.control != TaskControl::Stop {
            match self.restart_failed_child(&link, link.switched_to.as_ref()) {
                Ok(true) => restarted = true,
                Ok(false) => {
                    return Err(TaskToolFailure::new(
                        "restart_stopped",
                        format!("worker {child} was not restarted; a parent stop landed first"),
                    ));
                }
                Err(error) => {
                    return Err(TaskToolFailure::new(
                        "restart_failed",
                        format!(
                            "worker {child} is failed and could not be restarted: {error}; start a new task"
                        ),
                    ));
                }
            }
            let refreshed = self
                .control
                .snapshot(child)
                .map_err(|error| TaskToolFailure::new("supervisor_unavailable", error))?;
            state = match (refreshed.active, refreshed.state) {
                (true, Some(state)) => state,
                (_, other) => {
                    return Err(TaskToolFailure::new(
                        "not_running",
                        format!(
                            "worker {child} did not come back after restart (last state {}); start a new task",
                            other.map_or("unknown".to_owned(), |state| format!("{state:?}"))
                        ),
                    ))
                }
            };
        }
        let text = |text: String| {
            odin_domain::huginn::LiveMessage::new(vec![
                odin_domain::huginn::LiveContentBlock::Text(text),
            ])
            .map_err(|error| TaskToolFailure::new("invalid_message", error.to_string()))
        };
        let instruction = |message: &str| {
            text(format!(
                "Change of plan from your coordinator: {message}\nContinue the task with this change."
            ))
        };
        if request.control == TaskControl::Stop {
            self.control
                .stop_child(child)
                .map_err(|error| TaskToolFailure::new("command_refused", error))?;
            link.phase = DelegationPhase::Ended;
            self.write_link(&link.child, |fresh| {
                fresh.phase = DelegationPhase::Ended;
                true
            })
            .map_err(|error| TaskToolFailure::new("link_persistence_failed", error))?;
            self.run_completion_capture(&mut link);
            tracing::info!(
                "odin-omp: delegated child stopped by its parent child={child} seat={}",
                request.caller_seat
            );
            self.settle_escalation_wait(child, &request.caller_seat)?;
            return Ok(TaskControlReport {
                child,
                before: format!("{state:?}"),
                applied: vec!["Stop".to_owned()],
                outcome: "stopped; its session and tab are closed".to_owned(),
            });
        }
        // A slash command (/clear, /model …) is typed as it is: wrapped in
        // an instruction it would be plain text to the harness.
        let instruction = |message: &str| {
            if message.starts_with('/') {
                text(message.to_owned())
            } else {
                instruction(message)
            }
        };
        let working = matches!(state, State::Running | State::RequiresAction);
        let (plan, outcome): (Vec<Body>, &str) = match (&request.control, state) {
            (TaskControl::Pause, _) if working => {
                (vec![Body::Pause], "paused; it keeps its work so far")
            }
            (TaskControl::Pause, State::Detached) => (Vec::new(), "it was already paused"),
            (TaskControl::Resume, State::Detached) => (
                vec![
                    Body::Resume,
                    Body::Prompt {
                        message: text("Continue the task from where you stopped.".to_owned())?,
                        owner_text: None,
                    },
                ],
                "resumed where it stopped",
            ),
            (TaskControl::Steer(message), _) if working => (
                vec![Body::Steer {
                    message: text(message.clone())?,
                }],
                "redirected mid-task",
            ),
            (TaskControl::Steer(message), State::Detached) => (
                vec![
                    Body::Resume,
                    Body::Prompt {
                        message: instruction(message)?,
                        owner_text: Some(message.clone()),
                    },
                ],
                "resumed with the new instruction",
            ),
            (TaskControl::Steer(message), State::Idle) => (
                vec![Body::Prompt {
                    message: instruction(message)?,
                    owner_text: Some(message.clone()),
                }],
                "it had finished its last step; it continues with the new instruction",
            ),
            (TaskControl::Resume, State::Idle) if restarted => (
                vec![Body::Prompt {
                    message: text("Continue the task from where you stopped.".to_owned())?,
                    owner_text: None,
                }],
                "restarted from the failed turn and continued",
            ),
            (TaskControl::Pause, State::Idle) if restarted => (
                Vec::new(),
                "restarted from the failed turn; it is idle, so pause does not apply",
            ),
            (control, State::Failed) => {
                return Err(TaskToolFailure::new(
                    "not_applicable",
                    format!(
                        "worker {child} is Failed; {control:?} does not apply. Start a new task"
                    ),
                ))
            }
            (control, state) => {
                return Err(TaskToolFailure::new(
                    "not_applicable",
                    format!("worker {child} is {state:?}; {control:?} does not apply"),
                ))
            }
        };
        let mut applied = Vec::new();
        for body in plan {
            let kind = format!("{:?}", body.kind());
            self.control
                .command(child, body)
                .map_err(|error| TaskToolFailure {
                    kind: "command_refused",
                    detail: format!(
                        "worker {child}: {kind} was refused after {applied:?}: {error}"
                    ),
                    effect_may_have_started: !applied.is_empty(),
                })?;
            applied.push(kind);
        }
        self.settle_escalation_wait(child, &request.caller_seat)?;
        Ok(TaskControlReport {
            child,
            before: format!("{state:?}"),
            applied,
            outcome: outcome.to_owned(),
        })
    }

    fn create_task(
        &self,
        request: TaskCreateRequest,
    ) -> Result<TaskCreateReceipt, TaskToolFailure> {
        self.create_governed(request)
    }

    fn preflight_task(&self, request: &TaskCreateRequest) -> Result<(), TaskToolFailure> {
        self.preflight_governed(request)
    }

    fn read_task(&self, request: TaskReadRequest) -> Result<TaskReadReport, TaskToolFailure> {
        let mut link = self
            .links
            .load(&request.child)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
            .ok_or_else(|| {
                TaskToolFailure::new(
                    "child_unknown",
                    format!("no delegation row names child {}", request.child),
                )
            })?;
        if !self.is_ancestor(&link, &request.caller_session, &request.caller_seat)?
            && !self.is_active_sibling(&link, &request.caller_session)?
        {
            let seat = link.parent_seat.as_ref().map_or_else(
                || "no recorded seat".to_owned(),
                |seat| format!("seat {seat}"),
            );
            return Err(TaskToolFailure::new(
                "child_not_owned",
                format!(
                    "worker {} was delegated by session {} ({seat}), and neither it nor any \
                     delegator above it is this session or seat {}",
                    request.child, link.parent, request.caller_seat
                ),
            ));
        }
        let snapshot = self.reconcile(&mut link)?;
        self.run_completion_capture(&mut link);
        // Share the report pump's typed settlement and full-answer key. Never
        // derive settlement from a durable row phase or the presence of old prose.
        let settled = self.settled_turn(link.child, &snapshot);
        let latest_settled_turn =
            settled
                .as_ref()
                .map(|turn| super::super::vocabulary::TaskSettledTurn {
                    key: turn.key.clone(),
                    failed: turn.failed,
                });
        // A history read failure must stay distinguishable from a child that has not answered.
        let answer = match settled.map(|turn| turn.answer) {
            Some(answer) => Some(answer),
            None => self
                .control
                .last_answer(link.child, snapshot.epoch)
                .map_err(|error| {
                    TaskToolFailure::new(
                        "result_read_failed",
                        format!("the child's durable history could not be read: {error}"),
                    )
                })?,
        }
        .map(|mut text| {
            if let Some((end, _)) = text.char_indices().nth(TASK_READ_ANSWER_CHARS) {
                text.truncate(end);
            }
            text
        });
        let screen = match request.screen {
            true => self
                .control
                .screen(link.child)
                .map_err(|error| TaskToolFailure::new("screen_read_failed", error))?,
            false => None,
        };
        // Use the typed result event, not prose; read failures must remain distinguishable from absence.
        let result = match self.control.last_result(link.child) {
            Ok(result) => result,
            Err(error) => {
                return Err(TaskToolFailure::new(
                    "result_read_failed",
                    format!("the child's durable history could not be read: {error}"),
                ));
            }
        };
        // A stopped child's capsule is retired; its work went out with its hand-back.
        let branch = match snapshot.active {
            true => self
                .control
                .branch(link.child)
                .map_err(|error| TaskToolFailure::new("branch_read_failed", error))?,
            false => None,
        };
        Ok(TaskReadReport {
            child: link.child,
            phase: link.phase,
            active: snapshot.active,
            state: snapshot.state.map(|state| format!("{state:?}")),
            epoch: snapshot.epoch,
            answer,
            latest_settled_turn,
            result,
            project: link.project,
            switched_to: link.switched_to.as_ref().map(ToString::to_string),
            stalls: link.stalls,
            provider: link.provider,
            model: link.model,
            depth: link.depth,
            screen,
            branch,
        })
    }
}

impl GovernedTaskOwner {
    /// The escalation target's applied control ends the idle-timeout wait. `escalated_to` stays.
    fn settle_escalation_wait(
        &self,
        child: LiveSessionId,
        caller: &SeatId,
    ) -> Result<(), TaskToolFailure> {
        self.write_link(&child, |fresh| {
            if fresh.escalation_open && fresh.escalated_to.as_ref() == Some(caller) {
                fresh.escalation_open = false;
                true
            } else {
                false
            }
        })
        .map(|_| ())
        .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))
    }
}
