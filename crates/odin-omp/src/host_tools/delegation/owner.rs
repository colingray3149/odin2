//! Governed delegation ownership: authority, durable parent links, lifecycle,
//! task controls, and terminal learning capture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use odin_domain::huginn::LiveSessionId;
use odin_domain::{
    CommandId, Digest, DomainError, LaneId, ProjectId, RunId, SeatId, SessionId, TodoId,
};
use odin_ledger::lane_run::read_run;
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::host_tools::operations::SeatOperationPolicy;
use crate::host_tools::HostToolError;

use super::contracts::{
    child_title, live_session_id, ChildAuthorityProvisioner, ChildLifecycleSnapshot, ChildOpen,
    ChildSessionControl, ChildStop, DeferredDelegation, DeliveryVerdict, WorkloadRest,
};
use super::links::{
    DelegationLink, DelegationLinkLedger, DelegationPhase, PendingReportDelivery,
    DELEGATION_LINK_SCHEMA,
};
use super::vocabulary::{
    TaskControlReport, TaskControlRequest, TaskCreateReceipt, TaskCreateRequest, TaskReadReport,
    TaskReadRequest, TaskResultReport, TaskToolFailure,
};

mod capture;
mod reports;
mod task_tools;

const CHILD_PLAN_OBJECTIVE: &str = "Execute the delegated implementation task";
/// Lets the 15-second report pump relay settled answers before slot reuse.
pub(crate) const SETTLED_CHILD_YIELD_MS: u64 = 60_000;
const CHILD_PLAN_TODO_TITLE: &str = "Execute the delegated task to completion";
const CHILD_PLAN_TODO_ID: &str = "todo:delegated-task";

#[derive(Clone, Debug)]
pub struct TaskCompletionFacts {
    /// The delegating parent's seat, from the verified dispatch scope.
    pub parent_seat: SeatId,
    pub parent_session: SessionId,
    pub child: LiveSessionId,
    /// Typed result from the child's durable history.
    pub result: TaskResultReport,
}

/// Reviews an exact child/result identity idempotently, including after a
/// crash between capture and link persistence. Failure stays retryable.
pub trait TaskLearningCapture: Send + Sync {
    fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String>;
}

/// Records each durable typed Result without ending its resumable task.
/// Capture runs only once another owner has durably ended the child.
pub trait CompletionEventObserver: Send + Sync {
    fn result_persisted(&self, child: LiveSessionId, sequence: u64);
}

pub trait TaskOwner: Send + Sync {
    fn create_task(&self, request: TaskCreateRequest)
        -> Result<TaskCreateReceipt, TaskToolFailure>;

    /// Reads lifecycle state without waiting for completion.
    fn read_task(&self, request: TaskReadRequest) -> Result<TaskReadReport, TaskToolFailure>;

    /// Checks admission and readiness without mutating state, before approval.
    /// Execution repeats the checks after approval.
    fn preflight_task(&self, request: &TaskCreateRequest) -> Result<(), TaskToolFailure>;

    /// Records an escalation so the target seat may steer the child.
    fn escalate_task(&self, child: LiveSessionId, target: SeatId) -> Result<(), TaskToolFailure> {
        let _ = target;
        Err(TaskToolFailure::new(
            "control_unsupported",
            format!("this task owner cannot record an escalation of {child}"),
        ))
    }

    /// Pauses, resumes, or steers one delegated worker of the caller.
    fn control_task(
        &self,
        request: TaskControlRequest,
    ) -> Result<TaskControlReport, TaskToolFailure> {
        Err(TaskToolFailure::new(
            "control_unsupported",
            format!("this task owner cannot control worker {}", request.child),
        ))
    }
}

/// Single-assignment bridge, installed before listener startup; unbound calls fail closed.
#[derive(Default)]
pub struct TaskOwnerSlot {
    owner: RwLock<Option<Arc<dyn TaskOwner>>>,
}

impl TaskOwnerSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds the concrete owner exactly once.
    pub fn bind(&self, owner: Arc<dyn TaskOwner>) -> Result<(), HostToolError> {
        let mut binding = self.owner.write().map_err(|_| HostToolError::Catalog {
            detail: "task owner slot is poisoned".to_owned(),
        })?;
        if binding.is_some() {
            return Err(HostToolError::Catalog {
                detail: "task owner is already bound".to_owned(),
            });
        }
        *binding = Some(owner);
        Ok(())
    }

    pub fn is_bound(&self) -> Result<bool, HostToolError> {
        self.owner
            .read()
            .map(|owner| owner.is_some())
            .map_err(|_| HostToolError::Catalog {
                detail: "task owner slot is poisoned".to_owned(),
            })
    }

    pub(super) fn owner(&self) -> Result<Arc<dyn TaskOwner>, HostToolError> {
        self.owner
            .read()
            .map_err(|_| HostToolError::Catalog {
                detail: "task owner slot is poisoned".to_owned(),
            })?
            .clone()
            .ok_or_else(|| HostToolError::Catalog {
                detail: "task owner is not bound".to_owned(),
            })
    }
}

/// Delegation limits and routes fixed from validated host configuration.
#[derive(Clone)]
pub struct DelegationGovernance {
    /// Fixed registry provider id of the worker route.
    pub provider: String,
    /// Fixed registry-declared worker model.
    pub model: String,
    /// Per-parent concurrent child ceiling.
    pub max_children_per_session: usize,
    /// Hard UTF-8 byte ceiling on one child prompt.
    pub max_prompt_bytes: usize,
    /// The exact approved child scope (project → configured root).
    pub approved_projects: BTreeMap<ProjectId, PathBuf>,
    /// Per-(seat, lane) policies used to reconstruct the parent's binding.
    pub operation_bindings: BTreeMap<(SeatId, LaneId), SeatOperationPolicy>,
}

/// One settled pod run: its answer and the launch operation of its pod.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettledPod {
    pub session: LiveSessionId,
    /// Names this exact answer: a new turn yields a new key.
    pub key: String,
    /// The last answer; for a failed run, what it said before failing
    /// (possibly nothing).
    pub answer: String,
    pub operation: String,
    /// The pod's agent session failed and nothing handed it on.
    pub failed: bool,
}

/// How long a failed pod session may wait for a new turn to hand it on
/// before its run settles as failed and its pod is released.
pub const FAILED_POD_GRACE_MS: u64 = 120_000;

/// A child whose latest turn answered or failed.
#[derive(Clone, Debug)]
pub struct SettledChild {
    pub child: LiveSessionId,
    /// Names this exact answer: a new turn yields a new key. A failure is
    /// named by its incarnation's epoch instead, never by its partial text.
    pub key: String,
    /// The last answer; for a failure, the last text the child wrote
    /// (possibly nothing) — partial work, never its task result.
    pub answer: String,
    /// The observed session failed; this does not establish successful completion.
    pub failed: bool,
}

/// Active stop calls and ended children awaiting review.
#[derive(Default)]
struct OpenStop {
    proofs: usize,
    deferred: BTreeSet<LiveSessionId>,
}

/// Defers reviews until the session's last stop call closes.
/// Unwinding leaves capture pending for a later caller.
pub(super) struct StopScope<'a> {
    owner: &'a GovernedTaskOwner,
    session: LiveSessionId,
    open: bool,
}

impl StopScope<'_> {
    /// Returns deferred children only when the session's last stop call closes.
    pub(super) fn close(mut self) -> BTreeSet<LiveSessionId> {
        if self.open {
            self.open = false;
            self.owner.leave_stop(self.session)
        } else {
            BTreeSet::new()
        }
    }
}

impl Drop for StopScope<'_> {
    fn drop(&mut self) {
        if self.open {
            let stranded = self.owner.leave_stop(self.session);
            if !stranded.is_empty() {
                tracing::warn!(
                    "odin-omp: delegation capture deferred children={stranded:?} reason=the stop \
                     of {} unwound before its review",
                    self.session
                );
            }
        }
    }
}

/// Enforces link → token/open → plan → inherit → prompt ordering and task bounds.
pub struct GovernedTaskOwner {
    provisioner: Arc<dyn ChildAuthorityProvisioner>,
    pub(super) control: Arc<dyn ChildSessionControl>,
    pub(super) links: DelegationLinkLedger,
    ledger: Arc<Mutex<Ledger>>,
    governance: DelegationGovernance,
    sequence: AtomicU64,
    /// Optional task review, composed by the Odin runtime; `None` never
    /// disables a delegation.
    learning: Option<Arc<dyn TaskLearningCapture>>,
    result_wake: tokio::sync::Notify,
    /// Serializes fresh-row mutations through [`Self::write_link`], never callbacks.
    observing: parking_lot::Mutex<()>,
    /// Serializes terminal reviews through their durable sequence marker.
    /// Separate from row mutation so review callbacks cannot block report writes.
    capturing: parking_lot::Mutex<()>,
    /// Defers child reviews until all stop calls finish; never locked across callbacks or reads.
    stopping: parking_lot::Mutex<BTreeMap<LiveSessionId, OpenStop>>,
    /// Serializes duplicate and ceiling checks with insertion to prevent concurrent over-admission.
    creating: std::sync::Mutex<()>,
}

impl GovernedTaskOwner {
    /// Wakes the report pump when a delegated child's typed result is durable.
    pub fn result_wake(&self) -> &tokio::sync::Notify {
        &self.result_wake
    }

    /// The worker route's declared provider id. Gateway accounting uses this
    /// instead of a fixed name.
    pub(super) fn declared_provider(&self) -> &str {
        &self.governance.provider
    }

    pub fn new(
        provisioner: Arc<dyn ChildAuthorityProvisioner>,
        control: Arc<dyn ChildSessionControl>,
        links: DelegationLinkLedger,
        ledger: Arc<Mutex<Ledger>>,
        governance: DelegationGovernance,
    ) -> Self {
        Self {
            provisioner,
            control,
            links,
            ledger,
            governance,
            sequence: AtomicU64::new(1),
            learning: None,
            result_wake: tokio::sync::Notify::new(),
            observing: parking_lot::Mutex::new(()),
            capturing: parking_lot::Mutex::new(()),
            stopping: parking_lot::Mutex::new(BTreeMap::new()),
            creating: std::sync::Mutex::new(()),
        }
    }

    /// Binds the task review once while the runtime wires the owner.
    pub fn with_learning(mut self, learning: Option<Arc<dyn TaskLearningCapture>>) -> Self {
        self.learning = learning;
        self
    }

    /// Reloads, mutates, and persists under the row lock so whole-row writes
    /// preserve concurrent result receipts, capture markers, and report intents.
    /// Slow callbacks run outside this lock. `Ok(None)` means absent or unchanged.
    pub(super) fn write_link(
        &self,
        child: &LiveSessionId,
        mutate: impl FnOnce(&mut DelegationLink) -> bool,
    ) -> Result<Option<()>, String> {
        let _observing = self.observing.lock();
        let Some(mut fresh) = self.links.load(child)? else {
            return Ok(None);
        };
        if !mutate(&mut fresh) {
            return Ok(None);
        }
        self.links.persist(&fresh)?;
        Ok(Some(()))
    }

    /// Defers child reviews until the session's last stop call finishes its timed work.
    pub(super) fn open_stop(&self, session: LiveSessionId) -> StopScope<'_> {
        let open = self.learning.is_some();
        if open {
            self.stopping.lock().entry(session).or_default().proofs += 1;
        }
        StopScope {
            owner: self,
            session,
            open,
        }
    }

    fn leave_stop(&self, session: LiveSessionId) -> BTreeSet<LiveSessionId> {
        let mut stopping = self.stopping.lock();
        let Some(scope) = stopping.get_mut(&session) else {
            return BTreeSet::new();
        };
        scope.proofs = scope.proofs.saturating_sub(1);
        if scope.proofs > 0 {
            return BTreeSet::new();
        }
        stopping
            .remove(&session)
            .map(|scope| scope.deferred)
            .unwrap_or_default()
    }

    /// Retries terminal capture for other completion owners.
    pub fn capture_pending_completion(&self, child: &LiveSessionId) -> Result<(), String> {
        let mut link = self
            .links
            .load(child)?
            .ok_or_else(|| format!("no delegation row names child {child}"))?;
        self.run_completion_capture(&mut link);
        Ok(())
    }

    /// Raises the durable result sequence before attempting terminal capture.
    fn observe_result(&self, child: &LiveSessionId, sequence: u64) {
        // Keep slow history reads and review callbacks outside the row mutation lock.
        if let Err(error) = self.write_link(child, |link| match link.learning_result_sequence {
            Some(existing) if existing >= sequence => false,
            _ => {
                link.learning_result_sequence = Some(sequence);
                true
            }
        }) {
            tracing::error!(
                "odin-omp: delegation result not annotated child={child} sequence={sequence}: {error}"
            );
        }
        if let Ok(Some(mut link)) = self.links.load(child) {
            self.run_completion_capture(&mut link);
        }
    }

    /// Settled turns of children created within `window_ms`, keyed by answer or failed incarnation.
    pub fn settled_children(
        &self,
        parent_seat: &SeatId,
        window_ms: u64,
    ) -> Result<Vec<SettledChild>, String> {
        let now = Self::clock_ms();
        let mut settled = Vec::new();
        for row in self.links.all_rows()? {
            let link = row.link;
            if link.parent_seat.as_ref() != Some(parent_seat)
                || link.phase != DelegationPhase::Running
                || now.saturating_sub(link.created_at_ms) > window_ms
            {
                continue;
            }
            let snapshot = match self.control.snapshot(link.child) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::error!(
                        "odin-omp: delegation child unreadable child={} reason={error}",
                        link.child
                    );
                    continue;
                }
            };
            settled.extend(self.settled_turn(link.child, &snapshot));
        }
        Ok(settled)
    }

    /// Delivers settled turns to worker parents once per answer or failed incarnation.
    /// The conversation seat uses its own report path.
    pub fn report_to_worker_parents(
        &self,
        conversation_seat: &SeatId,
        window_ms: u64,
    ) -> Result<Vec<LiveSessionId>, String> {
        let now = Self::clock_ms();
        let mut reported = Vec::new();
        for row in self.links.all_rows()? {
            let link = row.link;
            if link.parent_seat.is_none()
                || link.parent_seat.as_ref() == Some(conversation_seat)
                || link.phase != DelegationPhase::Running
                || now.saturating_sub(link.created_at_ms) > window_ms
            {
                continue;
            }
            let Ok(snapshot) = self.control.snapshot(link.child) else {
                continue;
            };
            let Some(turn) = self.settled_turn(link.child, &snapshot) else {
                continue;
            };
            let key = turn.key;
            if link.reported_answer.as_deref() == Some(key.as_str())
                || (key.starts_with("failed-")
                    && link.reported_answer.as_deref() == Some("failed-unproved"))
            {
                continue;
            }
            let parent = LiveSessionId::parse(link.parent.as_str()).map_err(|error| {
                format!("delegation parent {} is invalid: {error}", link.parent)
            })?;
            let excerpt: String = turn.answer.chars().take(4000).collect();
            let text = if turn.failed {
                let said = if excerpt.is_empty() {
                    "No partial work is available.".to_owned()
                } else {
                    format!("The last text it wrote (partial work, not its result):\n{excerpt}")
                };
                format!(
                    "Work you delegated (task {}) was observed failing its latest turn; this is \
                     not successful task completion. {said}\n\
                     Check its current task state first: it may already have recovered since \
                     this report was captured. Treat any partial text as incomplete work, not \
                     a final result. If it is still failed and you choose to re-delegate, use \
                     task_pause action stop for this exact child and await success first. If \
                     you lack task_pause, ask an authorized coordinator; do not claim cleanup \
                     or a completed learning review.",
                    link.child
                )
            } else {
                format!(
                    "Work you delegated (task {}) just finished a turn. Its answer:\n{excerpt}\n\
                     Carry on with your task from here. A finished turn is not final task cleanup. \
                     Keep incomplete work or an escalation resumable. Only once you accept the \
                     final task result with no continuation remaining, use task_pause action stop \
                     for this exact child and await success before claiming cleanup. If you lack \
                     task_pause, hand this exact child to an authorized coordinator for teardown; \
                     do not claim it is stopped.",
                    link.child
                )
            };
            let message = odin_domain::huginn::LiveMessage::new(vec![
                odin_domain::huginn::LiveContentBlock::Text(text),
            ])
            .map_err(|error| error.to_string())?;
            // Persist before dispatch and replay the same command ID after an uncertain outcome.
            if !self.settle_report(&link, parent, message, &key, conversation_seat) {
                continue;
            }
            tracing::info!(
                "odind: delegated child reported child={} parent={parent} seat={}",
                link.child,
                link.parent_seat.as_ref().map_or("", |seat| seat.as_str())
            );
            reported.push(link.child);
        }
        Ok(reported)
    }
    /// Replay any pending report before opening a fresh attempt for `key`.
    /// Only delivery marks its recorded key; refusal clears the attempt, while
    /// unknown outcomes retain it. Choose Prompt/FollowUp from the current parent state.
    /// Ended parents hand reporting to the conversation seat.
    fn settle_report(
        &self,
        link: &DelegationLink,
        parent: LiveSessionId,
        mut message: odin_domain::huginn::LiveMessage,
        key: &str,
        conversation_seat: &SeatId,
    ) -> bool {
        use odin_domain::huginn::LiveCommandBody::{FollowUp, Prompt};

        let mut observed_report = link.reported_answer.as_deref();
        if let Some(pending) = &link.pending_report {
            match self.control.deliver(pending.command.clone()) {
                Ok(DeliveryVerdict::Delivered) => {
                    // Mark the recorded answer; only a newer answer needs
                    // another attempt after this delivery.
                    let marked =
                        self.mark_reported(&link.child, &pending.key, &pending.command.command_id);
                    if pending.key == key {
                        return marked;
                    }
                    if !marked {
                        return false;
                    }
                    observed_report = Some(pending.key.as_str());
                }
                Ok(DeliveryVerdict::Unsettled) => {
                    // Ambiguity preserves the exact attempt without marking the answer.
                    tracing::error!(
                        "odind: delegated child report attempt unsettled child={} \
                         parent={parent} command={} — keeping the recorded attempt",
                        link.child,
                        pending.command.command_id
                    );
                    return false;
                }
                Ok(DeliveryVerdict::Refused(reason)) => {
                    // Confirmed non-delivery permits a new attempt with the recorded message.
                    if pending.key == key {
                        if let Prompt { message: recorded } | FollowUp { message: recorded } =
                            &pending.command.body
                        {
                            message = recorded.clone();
                        }
                    }
                    tracing::error!(
                        "odind: delegated child report attempt not delivered child={} \
                         parent={parent} command={} reason={reason}",
                        link.child,
                        pending.command.command_id
                    );
                    let _ = self.write_link(&link.child, |fresh| match &fresh.pending_report {
                        Some(recorded)
                            if recorded.command.command_id == pending.command.command_id =>
                        {
                            fresh.pending_report = None;
                            true
                        }
                        _ => false,
                    });
                }
                Err(error) => {
                    // An unreachable actor does not establish the delivery outcome.
                    tracing::error!(
                        "odind: delegated child report attempt undecided child={} \
                         parent={parent} command={} reason={error}",
                        link.child,
                        pending.command.command_id
                    );
                    return false;
                }
            }
        }
        // Persist before dispatch only if the observed report generation is still current.
        let body = self.report_body(parent, message);
        let command = match self.control.open_delivery(parent, body) {
            Ok(command) => command,
            Err(error) if error.starts_with(super::TARGET_ENDED) => {
                tracing::error!(
                    "odind: delegated child report undeliverable child={} parent={parent} \
                     reason={error}; reporting it to the conversation instead",
                    link.child
                );
                if let Err(error) = self.write_link(&link.child, |fresh| {
                    fresh.parent_seat = Some(conversation_seat.clone());
                    true
                }) {
                    tracing::error!(
                        "odind: delegated child {} not handed to the conversation: {error}",
                        link.child
                    );
                }
                return false;
            }
            Err(error) => {
                tracing::error!(
                    "odind: delegated child report not attempted child={} parent={parent} \
                     reason={error}",
                    link.child
                );
                return false;
            }
        };
        let installed = self.write_link(&link.child, |fresh| {
            if fresh.pending_report.is_some()
                || fresh.reported_answer.as_deref() != observed_report
                || fresh.reported_answer.as_deref() == Some(key)
            {
                return false;
            }
            fresh.pending_report = Some(PendingReportDelivery {
                command: command.clone(),
                key: key.to_owned(),
            });
            true
        });
        match installed {
            Ok(Some(())) => {}
            Ok(None) => {
                tracing::info!(
                    "odind: delegated child report attempt raced child={} parent={parent} — \
                     another scan recorded an attempt; deferring to it",
                    link.child
                );
                return false;
            }
            Err(error) => {
                tracing::error!(
                    "odind: delegated child report intent not persisted child={} reason={error} — \
                     not dispatching",
                    link.child
                );
                return false;
            }
        }
        match self.control.deliver(command.clone()) {
            Ok(DeliveryVerdict::Delivered) => {
                self.mark_reported(&link.child, key, &command.command_id)
            }
            Ok(DeliveryVerdict::Unsettled) => {
                // The recorded attempt stands; a later pass replays it
                // under the same journal identity.
                tracing::error!(
                    "odind: delegated child report attempt unsettled child={} parent={parent} \
                     command={}",
                    link.child,
                    command.command_id
                );
                false
            }
            Ok(DeliveryVerdict::Refused(reason)) => {
                tracing::error!(
                    "odind: delegated child report not delivered child={} parent={parent} \
                     reason={reason}",
                    link.child
                );
                let _ = self.write_link(&link.child, |fresh| match &fresh.pending_report {
                    Some(recorded) if recorded.command.command_id == command.command_id => {
                        fresh.pending_report = None;
                        true
                    }
                    _ => false,
                });
                false
            }
            Err(error) => {
                // Infrastructure failure: the attempt stands.
                tracing::error!(
                    "odind: delegated child report attempt undecided child={} parent={parent} \
                     command={} reason={error}",
                    link.child,
                    command.command_id
                );
                false
            }
        }
    }

    /// The delivery body for one report message: a FollowUp into the
    /// parent's running turn, a Prompt to an idle one — derived at
    /// attempt-open time, because a replayed attempt delivered earlier in
    /// this same pass can have started the parent's turn, and a Prompt
    /// into a running turn would be refused by the actor.
    fn report_body(
        &self,
        parent: LiveSessionId,
        message: odin_domain::huginn::LiveMessage,
    ) -> odin_domain::huginn::LiveCommandBody {
        let running = self.control.snapshot(parent).is_ok_and(|parent_snapshot| {
            parent_snapshot.active
                && parent_snapshot.state != Some(odin_domain::huginn::LiveSessionState::Idle)
        });
        if running {
            odin_domain::huginn::LiveCommandBody::FollowUp { message }
        } else {
            odin_domain::huginn::LiveCommandBody::Prompt { message }
        }
    }

    /// A delayed completion must not replace a newer answer's marker.
    fn mark_reported(
        &self,
        child: &LiveSessionId,
        key: &str,
        delivered: &odin_domain::CommandId,
    ) -> bool {
        let marked = self.write_link(child, |fresh| {
            if !fresh.pending_report.as_ref().is_some_and(|recorded| {
                recorded.command.command_id == *delivered && recorded.key == key
            }) {
                return false;
            }
            fresh.reported_answer = Some(key.to_owned());
            fresh.pending_report = None;
            true
        });
        match marked {
            Ok(Some(())) => true,
            Ok(None) => false,
            Err(error) => {
                tracing::error!(
                    "odind: delegated child report marker not persisted child={child} \
                     reason={error}"
                );
                false
            }
        }
    }
    /// Idle pod sessions with an answer, or sessions failed for [`FAILED_POD_GRACE_MS`].
    /// A pod run is one task, so its settled turn is its result.
    pub fn settled_workloads(&self) -> Result<Vec<SettledPod>, String> {
        let now = Self::clock_ms();
        let mut settled = Vec::new();
        for (session, operation, rest) in self.control.resting_workload_sessions()? {
            let failed = match rest {
                WorkloadRest::Idle => false,
                WorkloadRest::Failed { since_ms }
                    if now.saturating_sub(since_ms) >= FAILED_POD_GRACE_MS =>
                {
                    true
                }
                WorkloadRest::Failed { .. } => continue,
            };
            let answer = match self.control.last_answer(session, None) {
                Ok(Some(answer)) => answer,
                _ if failed => String::new(),
                _ => continue,
            };
            let digest = Digest::hash(answer.as_bytes()).to_string();
            let hash = &digest.trim_start_matches("blake3:")[..12];
            let key = if failed {
                format!("failed-{hash}")
            } else {
                hash.to_owned()
            };
            settled.push(SettledPod {
                session,
                key,
                answer,
                operation,
                failed,
            });
        }
        Ok(settled)
    }

    /// Ends one reported pod session; its carrier Job is deleted with it
    /// (the workload harness's stop action). A session whose incarnation is
    /// gone settles through its durable journal
    /// ([`ChildStop::SettledAbsent`] / [`ChildStop::AlreadyTerminal`]) —
    /// exactly once, never retried; only its carrier release stays pending.
    pub fn end_workload(&self, session: LiveSessionId) -> Result<ChildStop, String> {
        self.control.stop_child(session)
    }

    /// Every ended workload (pod) session with its launch operation, from
    /// the durable ledger: the carrier-release backlog a failed release
    /// or a daemon death between end and release leaves behind.
    pub fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String> {
        self.control.ended_workload_sessions()
    }

    /// Delivers one message to a delegated child session through the
    /// supervisor — the kernel's route for findings about the child's own
    /// work. A session that is not a delegated child is refused.
    pub fn notify_child(&self, child: LiveSessionId, message: &str) -> Result<(), String> {
        if self.links.load(&child)?.is_none() {
            return Err(format!("{child} is not a delegated child session"));
        }
        self.control.prompt(child, message)
    }

    pub(super) fn clock_ms() -> u64 {
        let now = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        u64::try_from(now.max(0)).unwrap_or(0)
    }

    /// Derives the child run identity for one child session — the same
    /// derivation the bridge runtime uses for every live session.
    pub fn child_run_for(child: &LiveSessionId) -> Result<RunId, DomainError> {
        RunId::new(format!("run:live:{child}"))
    }

    /// Read-only admission checks shared by preflight and execution.
    /// Returns the dispatch prompt and child depth; concurrency is checked separately.
    fn verify_binding_gates(
        &self,
        request: &TaskCreateRequest,
    ) -> Result<(String, u8), TaskToolFailure> {
        // Only a child answering another seat may delegate another level.
        let caller_link = self
            .links
            .load(
                &live_session_id(&request.caller_session)
                    .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?,
            )
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?;
        let depth = match &caller_link {
            None => 1,
            Some(link) => super::contracts::nested_child_depth(
                link.depth,
                link.parent_seat.as_ref(),
                &request.caller_seat,
            )
            .map_err(|detail| TaskToolFailure::new("depth_exceeded", detail))?,
        };
        // The accepted parent plan supplies operator approval.
        let parent_accepted = {
            let ledger = self.ledger.lock().map_err(|_| {
                TaskToolFailure::new("ledger_poisoned", "operation ledger lock is poisoned")
            })?;
            ledger
                .plan_is_accepted(&request.caller_run)
                .map_err(|error| TaskToolFailure::new("ledger_failed", error.to_string()))?
        };
        if !parent_accepted {
            return Err(TaskToolFailure::new(
                "plan_not_accepted",
                "the calling run has no recorded accepted plan; delegation requires actual operator approval",
            ));
        }
        // Preflight and execution must measure the same prompt bytes.
        let child_delegates = request
            .target_seat
            .as_ref()
            .is_some_and(|target| *target != request.caller_seat)
            && depth < super::contracts::MAX_DELEGATION_DEPTH;
        let prompt = Self::governed_prompt(
            &request.prompt,
            self.governance.max_prompt_bytes,
            child_delegates,
        )?;
        if !self
            .governance
            .approved_projects
            .contains_key(&request.project)
        {
            let approved: BTreeSet<String> = self
                .governance
                .approved_projects
                .keys()
                .map(|project| project.to_string())
                .collect();
            return Err(TaskToolFailure::new(
                "project_out_of_scope",
                format!(
                    "project {} is not inside the parent's approved scope {approved:?}",
                    request.project
                ),
            ));
        }
        Ok((prompt, depth))
    }

    /// Same-seat requests use the configured worker; cross-seat requests resolve
    /// a declared launch option from the target seat before creating the link.
    fn resolve_worker_route(
        &self,
        request: &TaskCreateRequest,
    ) -> Result<(String, String), TaskToolFailure> {
        match &request.target_seat {
            None if request.launch.is_some() => Err(TaskToolFailure::new(
                "launch_invalid",
                "a launch choice names another seat's declared launch option; the same-seat \
                 worker route runs the configured worker",
            )),
            None => Ok((
                self.governance.provider.clone(),
                self.governance.model.clone(),
            )),
            Some(target_seat) => {
                if *target_seat == request.caller_seat {
                    return Err(TaskToolFailure::new(
                        "target_seat_invalid",
                        format!(
                            "the cross-seat target {target_seat} equals the calling seat; \
                             use the same-seat worker route instead"
                        ),
                    ));
                }
                self.provisioner
                    .seat_worker_profile(target_seat, request.launch.as_ref())
                    .map_err(|detail| {
                        TaskToolFailure::new(
                            "target_seat_unavailable",
                            format!(
                                "the target seat {target_seat} serves no declared worker \
                                 launch: {detail}"
                            ),
                        )
                    })
            }
        }
    }

    /// Wraps and validates the same prompt bytes for execution and preflight.
    /// `delegates` permits a cross-seat child below the depth limit to delegate.
    fn governed_prompt(
        prompt: &str,
        max_bytes: usize,
        delegates: bool,
    ) -> Result<String, TaskToolFailure> {
        if prompt.trim().is_empty() {
            return Err(TaskToolFailure::new(
                "prompt_empty",
                "the worker prompt must not be empty",
            ));
        }
        let role = if delegates {
            "You are answering another seat's request for this unit. Do the work with the provided tools; when you hold task_create you may hand bounded parts of it to your own workers (they cannot delegate further) and you own their results."
        } else {
            "You are the delegated implementation worker for this unit, not its delegator. Implement it yourself with the provided tools. Do not delegate again; worker depth is limited to one."
        };
        let prompt = format!(
            "{role} Use context_read for workpack documents, or /workspace/context inside capsule_eval_run. Preserve existing unrelated changes. Explicit task limits apply to memory too: this learning habit grants no extra write scope. Before you report, if you hold memory_remember and this unit taught you something a later session needs (a tool quirk, a recipe that worked, a correction to a lesson you hold), save it once and retire contradicted lessons with memory_forget only within the permitted learning scope; skip this when learning is excluded or nothing is new. Report actual changes and checks concisely.\n\nAssigned task:\n{prompt}"
        );
        let prompt_bytes = prompt.len();
        if prompt_bytes > max_bytes {
            return Err(TaskToolFailure::new(
                "prompt_too_large",
                format!("prompt is {prompt_bytes} bytes; the configured ceiling is {max_bytes}"),
            ));
        }
        Ok(prompt)
    }

    /// Provisioning always counts; running rows count only while their child is active.
    fn counts_against_ceiling(phase: DelegationPhase, child_active: bool) -> bool {
        matches!(phase, DelegationPhase::Provisioning)
            || (matches!(phase, DelegationPhase::Running) && child_active)
    }

    /// When a counted child has settled — idle or failed for the yield grace,
    /// so its answer or failure has been relayed — it may give its place to a
    /// new delegation: the settled-since instant, else `None` (it works).
    fn yields_place(snapshot: &ChildLifecycleSnapshot, now_ms: u64) -> Option<u64> {
        snapshot.settled_since_ms.filter(|since| {
            snapshot.active && now_ms.saturating_sub(*since) >= SETTLED_CHILD_YIELD_MS
        })
    }

    /// Ends one settled child so a new delegation can take its place: the
    /// same retirement the idle timeout applies, just earlier.
    fn yield_settled_child(
        &self,
        link: &mut DelegationLink,
        settled_since: u64,
    ) -> Result<(), String> {
        self.control.stop_child(link.child)?;
        self.write_link(&link.child, |fresh| {
            fresh.phase = DelegationPhase::Ended;
            true
        })?;
        link.phase = DelegationPhase::Ended;
        self.run_completion_capture(link);
        tracing::info!(
            "odind: delegated child yielded child={} parent={} idle_s={} reason=\"a new \
             delegation needs its place under the worker ceiling\"",
            link.child,
            link.parent,
            Self::clock_ms().saturating_sub(settled_since) / 1000
        );
        Ok(())
    }

    /// Verifies the calling session's (seat, lane) route is a configured
    /// operation binding before any link row exists. The parent's own
    /// operation binding is recomposed from the parent's own authority
    /// generation at every child build — it is never reconstructed here
    /// from the startup table, and never carried through the request.
    fn caller_route(&self, request: &TaskCreateRequest) -> Result<(), TaskToolFailure> {
        if self
            .governance
            .operation_bindings
            .contains_key(&(request.caller_seat.clone(), request.caller_lane.clone()))
        {
            return Ok(());
        }
        Err(TaskToolFailure::new(
            "binding_missing",
            "the calling session has no configured operation binding for its seat and lane",
        ))
    }

    /// Reuses an active child's receipt for the same prompt and project.
    /// Answered, ended, or failed children do not prevent a new delegation.
    fn working_duplicate(
        &self,
        request: &TaskCreateRequest,
        prompt: &str,
    ) -> Result<Option<DelegationLink>, TaskToolFailure> {
        let digest = Digest::hash(prompt.as_bytes());
        Ok(self
            .links
            .children_of(&request.caller_session)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
            .into_iter()
            .find(|row| {
                row.prompt_digest == digest
                    && row.project == request.project
                    && match row.phase {
                        DelegationPhase::Provisioning => true,
                        // Idle is also "opened, prompt not yet applied": a
                        // live child is working until its turn produced a
                        // result and it went idle.
                        DelegationPhase::Running => {
                            self.control.snapshot(row.child).is_ok_and(|snapshot| {
                                snapshot.active
                                    && snapshot.state
                                        != Some(odin_domain::huginn::LiveSessionState::Failed)
                                    && (snapshot.state
                                        != Some(odin_domain::huginn::LiveSessionState::Idle)
                                        || row.learning_result_sequence.is_none())
                            })
                        }
                        _ => false,
                    }
            }))
    }

    fn create_governed(
        &self,
        request: TaskCreateRequest,
    ) -> Result<TaskCreateReceipt, TaskToolFailure> {
        let (prompt, depth) = self.verify_binding_gates(&request)?;
        let prompt_bytes = prompt.len();
        let creating = self
            .creating
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some(link) = self.working_duplicate(&request, &prompt)? {
            tracing::warn!(
                "odind: delegated task replayed child={} parent={} reason=\"the same prompt is \
                 still being worked\"",
                link.child,
                link.parent
            );
            return Ok(TaskCreateReceipt {
                child_session: link.child,
                child_run: link.child_run,
                command_id: link.command,
                project: link.project,
                provider: link.provider,
                model: link.model,
                plan_accepted: true,
                prompt_bytes,
            });
        }
        // A child opened before the pending reload could never start: refuse
        // now, start nothing, and have the delegator woken after it.
        if self.control.reload_pending() {
            let deferred = DeferredDelegation {
                caller_seat: request.caller_seat.clone(),
                target_seat: request.target_seat.clone(),
                title: request.title.clone(),
                prompt: request.prompt.clone(),
                deferred_at_ms: u64::try_from(
                    time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
                )
                .unwrap_or(0),
            };
            let detail = match self.control.defer_until_reload(&deferred) {
                Ok(()) => "Odin restarts within about a minute to activate what was just \
                           published; a worker opened now could not start until then, so \
                           nothing was started. You will be woken right after the restart to \
                           delegate this again."
                    .to_owned(),
                Err(error) => format!(
                    "Odin restarts within about a minute to activate what was just published, \
                     so nothing was started; delegate this again after the restart (the \
                     deferral could not be recorded: {error})"
                ),
            };
            return Err(TaskToolFailure::new("odin_reloading", detail));
        }
        // Reconcile before counting children against the concurrency ceiling.
        let mut active_children = 0usize;
        let now_ms = Self::clock_ms();
        let mut settled = Vec::new();
        for mut row in self
            .links
            .children_of(&request.caller_session)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
        {
            if !matches!(
                row.phase,
                DelegationPhase::Provisioning | DelegationPhase::Running
            ) {
                continue;
            }
            let snapshot = self.reconcile(&mut row)?;
            if Self::counts_against_ceiling(row.phase, snapshot.active) {
                active_children += 1;
                if let Some(since) = Self::yields_place(&snapshot, now_ms) {
                    settled.push((since, row));
                }
            }
        }
        // Reuse slots from settled children, longest idle first.
        settled.sort_by_key(|(since, _)| *since);
        for (since, mut row) in settled {
            if active_children < self.governance.max_children_per_session {
                break;
            }
            match self.yield_settled_child(&mut row, since) {
                Ok(()) => active_children -= 1,
                Err(error) => tracing::error!(
                    "odind: settled delegated child {} did not yield: {error}",
                    row.child
                ),
            }
        }
        if active_children >= self.governance.max_children_per_session {
            return Err(TaskToolFailure::new(
                "concurrency_ceiling",
                format!(
                    "the parent already has {active_children} active worker(s); the configured ceiling is {}",
                    self.governance.max_children_per_session
                ),
            ));
        }

        let child_command = CommandId::new(format!(
            "odin.task.create:{}:{}:{}",
            request.caller_session.as_str(),
            Self::clock_ms(),
            self.sequence.fetch_add(1, Ordering::Relaxed),
        ))
        .map_err(|error| TaskToolFailure::new("identity_invalid", error.to_string()))?;
        let child = crate::live::supervisor::session_id_for(&child_command)
            .map_err(|error| TaskToolFailure::new("identity_invalid", error.to_string()))?;
        let child_run = Self::child_run_for(&child)
            .map_err(|error| TaskToolFailure::new("identity_invalid", error.to_string()))?;

        let (worker_provider, worker_model) = self.resolve_worker_route(&request)?;

        // Persist the link before minting a token or opening the child.
        let mut link = DelegationLink {
            schema: DELEGATION_LINK_SCHEMA.to_owned(),
            child,
            parent: request.caller_session.clone(),
            parent_seat: Some(request.caller_seat.clone()),
            parent_run: request.caller_run.clone(),
            child_run: child_run.clone(),
            command: child_command.clone(),
            project: request.project.clone(),
            provider: worker_provider.clone(),
            model: worker_model.clone(),
            prompt_digest: Digest::hash(prompt.as_bytes()),
            // Retain the original assignment, not dispatch framing, for rollover.
            assignment: request.prompt.clone(),
            rollover_admissions: 0,
            depth,
            phase: DelegationPhase::Provisioning,
            created_at_ms: Self::clock_ms(),
            learning_capture_sequence: None,
            escalated_to: None,
            escalation_open: false,
            learning_result_sequence: None,
            learning_proposal_id: None,
            stall_retries: 0,
            stalls: Vec::new(),
            switched_to: None,
            handled_stall_event: None,
            refusals: Vec::new(),
            gateway_fallbacks: Vec::new(),
            reported_answer: None,
            pending_report: None,
        };
        self.links
            .persist(&link)
            .map_err(|error| TaskToolFailure::new("link_persistence_failed", error))?;
        drop(creating);

        // Token/open: the runtime provisions against the durable row.
        self.caller_route(&request)?;
        let title = child_title(request.title.as_deref().unwrap_or(&request.prompt));
        let child_open = ChildOpen {
            command: &child_command,
            project: &request.project,
            title: &title,
            launch: request.launch.as_ref(),
        };
        let provision_error = match &request.target_seat {
            None => self
                .provisioner
                .provision_child(
                    &request.caller_seat,
                    &request.caller_lane,
                    &request.caller_session,
                    child_open,
                )
                .err(),
            Some(target_seat) => self
                .provisioner
                .provision_child_for_seat(
                    &request.caller_seat,
                    &request.caller_lane,
                    &request.caller_session,
                    child_open,
                    target_seat,
                )
                .err(),
        };
        if let Some(error) = provision_error {
            link.phase = DelegationPhase::Failed;
            let _ = self.write_link(&link.child, |fresh| {
                fresh.phase = DelegationPhase::Failed;
                true
            });
            return Err(TaskToolFailure::new(
                "provisioning_failed",
                format!("the runtime refused the governed child: {error}"),
            ));
        }

        // Child task plan, then inherited acceptance, then the prompt. The
        // real bridge must have created the child run during provisioning.
        // Keep the ledger guard inside this setup scope so every failure can
        // release it before stopping the real child.
        let now = OffsetDateTime::now_utc();
        let child_setup = (|| -> Result<(), TaskToolFailure> {
            let mut ledger = self.ledger.lock().map_err(|_| {
                TaskToolFailure::new("ledger_poisoned", "operation ledger lock is poisoned")
            })?;
            if read_run(ledger.connection(), &child_run)
                .map_err(|error| TaskToolFailure::new("ledger_failed", error.to_string()))?
                .is_none()
            {
                return Err(TaskToolFailure::new(
                    "provisioning_failed",
                    format!(
                        "the runtime reported child {} without its required bridge run {child_run}",
                        link.child
                    ),
                ));
            }
            ledger
                .replace_plan(
                    &child_run,
                    CHILD_PLAN_OBJECTIVE,
                    &[TodoSpec {
                        id: TodoId::new(CHILD_PLAN_TODO_ID).map_err(|error| {
                            TaskToolFailure::new("identity_invalid", error.to_string())
                        })?,
                        title: CHILD_PLAN_TODO_TITLE.to_owned(),
                        status: TodoStatus::Pending,
                    }],
                    0,
                    now,
                )
                .map_err(|error| TaskToolFailure::new("plan_failed", error.to_string()))?;
            ledger
                .inherit_plan_acceptance(&request.caller_run, &child_run, now)
                .map_err(|error| {
                    TaskToolFailure::new(
                        "plan_inheritance_failed",
                        format!(
                            "the child plan was created for {child_run} but acceptance inheritance failed: {error}"
                        ),
                    )
                })?;
            Ok(())
        })();
        if let Err(failure) = child_setup {
            return Err(self.fail_open_child(&mut link, failure));
        }
        link.phase = DelegationPhase::Running;
        if let Err(error) = self.write_link(&link.child, |fresh| {
            fresh.phase = DelegationPhase::Running;
            true
        }) {
            return Err(self.fail_open_child(
                &mut link,
                TaskToolFailure::new("link_persistence_failed", error),
            ));
        }
        if let Err(error) = self.control.prompt(link.child, &prompt) {
            let failure = TaskToolFailure::new(
                "prompt_failed",
                format!(
                    "the child opened idle with an inherited plan, but the prompt failed: {error}"
                ),
            );
            return Err(self.fail_open_child(&mut link, failure));
        }
        Ok(TaskCreateReceipt {
            child_session: link.child,
            child_run: link.child_run,
            command_id: link.command,
            project: link.project,
            provider: link.provider,
            model: link.model,
            plan_accepted: true,
            prompt_bytes,
        })
    }

    /// Checks admission and readiness without writing rows or reserving resources.
    /// Execution repeats the checks after approval.
    fn preflight_governed(&self, request: &TaskCreateRequest) -> Result<(), TaskToolFailure> {
        let (prompt, _) = self.verify_binding_gates(request)?;
        if self.working_duplicate(request, &prompt)?.is_some() {
            return Ok(());
        }
        // Count without persisting; settled children that would yield do not block.
        let mut active_children = 0usize;
        let now_ms = Self::clock_ms();
        for row in self
            .links
            .children_of(&request.caller_session)
            .map_err(|error| TaskToolFailure::new("link_ledger_failed", error))?
        {
            if !matches!(
                row.phase,
                DelegationPhase::Provisioning | DelegationPhase::Running
            ) {
                continue;
            }
            let (child_active, yields) = if matches!(row.phase, DelegationPhase::Running) {
                let snapshot = self
                    .control
                    .snapshot(row.child)
                    .map_err(|error| TaskToolFailure::new("lifecycle_unavailable", error))?;
                (
                    snapshot.active,
                    Self::yields_place(&snapshot, now_ms).is_some(),
                )
            } else {
                (true, false)
            };
            if Self::counts_against_ceiling(row.phase, child_active) && !yields {
                active_children += 1;
            }
        }
        if active_children >= self.governance.max_children_per_session {
            return Err(TaskToolFailure::new(
                "concurrency_ceiling",
                format!(
                    "the parent already has {active_children} active worker(s); the configured ceiling is {}",
                    self.governance.max_children_per_session
                ),
            ));
        }
        self.resolve_worker_route(request)?;
        self.caller_route(request)?;
        self.provisioner
            .preflight_child(
                &request.caller_seat,
                &request.caller_lane,
                &request.caller_session,
                &request.project,
                request.target_seat.as_ref(),
                request.launch.as_ref(),
            )
            .map_err(|detail| TaskToolFailure::new("surface_unavailable", detail))
    }
}

impl CompletionEventObserver for GovernedTaskOwner {
    /// Durable result notification; not a final-task acknowledgment.
    fn result_persisted(&self, child: LiveSessionId, sequence: u64) {
        self.observe_result(&child, sequence);
        self.result_wake.notify_one();
    }
}
