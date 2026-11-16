//! Delegation fixtures and lifecycle, ordering, and stop tests.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Mutex as StdMutex};
use std::time::Duration;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{
    CommandId, Digest, LaneId, ProjectId, RunId, SeatId, SessionId, SliceId, TodoId,
};
use odin_ledger::lane_run::{create_lane, create_run, read_run, NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use serde_json::json;
use time::OffsetDateTime;

use crate::host_tools::operations::SeatOperationPolicy;
use crate::host_tools::HostToolError;

const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

/// A stop budget no loaded test machine spends: the tests assert order, not speed.
const STOP_BUDGET: Duration = Duration::from_secs(30);

type DeliveryHook = Box<dyn Fn(&odin_domain::huginn::LiveCommand) + Send + Sync>;
type ChildBridgeStop = Arc<dyn Fn(LiveSessionId) -> Result<(), String> + Send + Sync>;

struct FakeControl {
    snapshots: StdMutex<BTreeMap<String, ChildLifecycleSnapshot>>,
    prompts: Mutex<Vec<String>>,
    stops: Mutex<Vec<String>>,
    stop_failures: StdMutex<BTreeMap<String, String>>,
    pinned_active: StdMutex<BTreeSet<String>>,
    retires: Mutex<Vec<String>>,
    on_stop: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// The stopped child's own bridge stop, run before the stop answers —
    /// as the real bridge does, it invokes the same stop coordinator for
    /// that child, whose own delegated children then stop first.
    child_bridge_stop: StdMutex<Option<ChildBridgeStop>>,
    /// Test seam: fires inside every dispatched command — the
    /// deterministic stand-in for a concurrent whole-row writer landing
    /// mid-dispatch, while the dispatching scan holds its stale snapshot.
    on_command: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    on_open_delivery: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    ended_targets: StdMutex<BTreeSet<LiveSessionId>>,
    /// Inspect durable intent before either refusal or command execution.
    on_delivery: Mutex<Option<DeliveryHook>>,
    /// Command IDs rejected before admission; their bodies never execute.
    refused_deliveries: StdMutex<BTreeSet<String>>,
    /// One-shot writer after a lifecycle scan has loaded its row snapshot.
    on_snapshot: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    /// Command-id prefixes whose dispatch stays durably unsettled: the
    /// fixture's stand-in for a journaled-but-unfinished command.
    indeterminate: StdMutex<BTreeSet<String>>,
    /// The command ids whose body has executed once — the journaled
    /// command. A repeat hand-off is the actor's Duplicate receipt: the
    /// body never runs twice.
    executed: StdMutex<BTreeSet<String>>,
    /// The exact command ids handed to `deliver`, in order — every
    /// hand-off, the replays of a recorded attempt included.
    delivered: StdMutex<Vec<String>>,
    /// Mints `fixture-report-{n}` command ids in `open_delivery`.
    opened: std::sync::atomic::AtomicU64,
    prompt_failure: Mutex<Option<String>>,
    next_stop_failure: Mutex<Option<String>>,
    results: Mutex<BTreeMap<String, TaskResultReport>>,
    answers: StdMutex<BTreeMap<String, String>>,
    failures: StdMutex<BTreeMap<String, SessionFailure>>,
    answer_errors: StdMutex<BTreeMap<String, String>>,
    /// The cursors each `last_answer_after` scan was paged from, in order.
    answer_afters: StdMutex<Vec<u64>>,
    /// The durable head a child's next answer scan reports reaching.
    answer_heads: StdMutex<BTreeMap<String, u64>>,
    snapshot_failures: StdMutex<BTreeMap<String, String>>,
    resting_pods: StdMutex<Vec<(LiveSessionId, String, WorkloadRest)>>,
    ended_pods: StdMutex<Vec<(LiveSessionId, String)>>,
    commands: StdMutex<Vec<String>>,
    /// The text of every Prompt command, in order.
    prompted: StdMutex<Vec<String>>,
    reload_pending: std::sync::atomic::AtomicBool,
    deferred: StdMutex<Vec<DeferredDelegation>>,
    /// The worker seat's declared launch options, in order.
    lanes: StdMutex<Vec<super::WorkerLane>>,
    /// Every context rollover the owner asked for: (child, refusal event),
    /// in order.
    rollover_calls: StdMutex<Vec<(String, u64)>>,
    /// The next rollover's scripted verdict.
    rollover_failure: StdMutex<Option<String>>,
    /// An action run inside the rollover (the parent-stop race).
    on_rollover: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl FakeControl {
    fn new() -> Self {
        Self {
            snapshots: StdMutex::new(BTreeMap::new()),
            prompts: Mutex::new(Vec::new()),
            prompted: StdMutex::new(Vec::new()),
            stops: Mutex::new(Vec::new()),
            stop_failures: StdMutex::new(BTreeMap::new()),
            pinned_active: StdMutex::new(BTreeSet::new()),
            retires: Mutex::new(Vec::new()),
            on_stop: Mutex::new(None),
            child_bridge_stop: StdMutex::new(None),
            on_command: Mutex::new(None),
            on_open_delivery: Mutex::new(None),
            ended_targets: StdMutex::new(BTreeSet::new()),
            on_delivery: Mutex::new(None),
            refused_deliveries: StdMutex::new(BTreeSet::new()),
            on_snapshot: Mutex::new(None),
            indeterminate: StdMutex::new(BTreeSet::new()),
            executed: StdMutex::new(BTreeSet::new()),
            delivered: StdMutex::new(Vec::new()),
            opened: std::sync::atomic::AtomicU64::new(0),
            prompt_failure: Mutex::new(None),
            next_stop_failure: Mutex::new(None),
            results: Mutex::new(BTreeMap::new()),
            answers: StdMutex::new(BTreeMap::new()),
            failures: StdMutex::new(BTreeMap::new()),
            answer_errors: StdMutex::new(BTreeMap::new()),
            answer_afters: StdMutex::new(Vec::new()),
            answer_heads: StdMutex::new(BTreeMap::new()),
            snapshot_failures: StdMutex::new(BTreeMap::new()),
            resting_pods: StdMutex::new(Vec::new()),
            ended_pods: StdMutex::new(Vec::new()),
            commands: StdMutex::new(Vec::new()),
            reload_pending: std::sync::atomic::AtomicBool::new(false),
            deferred: StdMutex::new(Vec::new()),
            lanes: StdMutex::new(Vec::new()),
            rollover_calls: StdMutex::new(Vec::new()),
            rollover_failure: StdMutex::new(None),
            on_rollover: Mutex::new(None),
        }
    }

    fn set_state(&self, child: &LiveSessionId, state: odin_domain::huginn::LiveSessionState) {
        self.snapshots.lock().expect("snapshot lock").insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: true,
                state: Some(state),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: None,
            },
        );
    }

    /// Every hand-off of a command id naming `prefix` answers unsettled
    /// — the journal row carries no readable outcome — until
    /// [`Self::resolves_delivery`] lets it answer.
    fn leaves_delivery_indeterminate(&self, prefix: &str) {
        self.indeterminate
            .lock()
            .expect("indeterminate lock")
            .insert(prefix.to_owned());
    }

    fn set(&self, child: &LiveSessionId, active: bool) {
        self.snapshots.lock().expect("snapshot lock").insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active,
                state: Some(if active {
                    odin_domain::huginn::LiveSessionState::Idle
                } else {
                    odin_domain::huginn::LiveSessionState::Ended
                }),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: None,
            },
        );
    }
    fn fail_stop(&self, child: &LiveSessionId, detail: &str) {
        self.stop_failures
            .lock()
            .expect("stop failure lock")
            .insert(child.to_string(), detail.to_owned());
    }

    fn pin_active(&self, child: &LiveSessionId) {
        self.pinned_active
            .lock()
            .expect("pinned-active lock")
            .insert(child.to_string());
    }
    fn on_first_stop(&self, action: Box<dyn Fn() + Send + Sync>) {
        *self.on_stop.lock().expect("on-stop lock") = Some(action);
    }

    fn on_command(&self, action: Box<dyn Fn() + Send + Sync>) {
        *self.on_command.lock().expect("on-command lock") = Some(action);
    }

    /// Fails the next prompt dispatch once; the owner must stop the
    /// already-opened child on that path.
    fn fail_next_prompt(&self, detail: &str) {
        *self.prompt_failure.lock().expect("prompt failure lock") = Some(detail.to_owned());
    }
}

impl ChildSessionControl for FakeControl {
    fn reload_pending(&self) -> bool {
        self.reload_pending
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn defer_until_reload(&self, deferred: &DeferredDelegation) -> Result<(), String> {
        self.deferred
            .lock()
            .expect("deferred lock")
            .push(deferred.clone());
        Ok(())
    }

    /// Records the command and moves the snapshot the way the live actor
    /// would (control effects and the next turn start).
    fn command(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<(), String> {
        use odin_domain::huginn::{LiveCommandBody as Body, LiveSessionState as State};
        let state = self.snapshot(child)?.state;
        body.validate_applicability(&state.unwrap_or(State::Ended))
            .map_err(|reason| format!("{reason:?}"))?;
        let next = match &body {
            Body::Pause => Some(State::Detached),
            Body::Resume => Some(State::Idle),
            Body::Restart => Some(State::Idle),
            Body::Prompt { .. } => Some(State::Running),
            Body::Abort {
                scope: odin_domain::huginn::AbortScope::CurrentTurn,
            } => Some(State::Idle),
            _ => None,
        };
        if let Some(next) = next {
            self.set_state(&child, next);
        }
        if let Body::Prompt { message, .. } = &body {
            self.prompted
                .lock()
                .expect("prompted lock")
                .push(format!("{message:?}"));
        }
        self.commands
            .lock()
            .expect("command lock")
            .push(format!("{:?}", body.kind()));
        if let Some(action) = self.on_command.lock().expect("on-command lock").as_ref() {
            action();
        }
        Ok(())
    }

    /// Records the rollover and moves the snapshot the way the live actor
    /// would: same child identity, epoch + 1, running again with an empty
    /// conversation and no stale fault.
    fn rollover(&self, child: LiveSessionId, refusal_event: u64) -> Result<u64, String> {
        self.rollover_calls
            .lock()
            .expect("rollover lock")
            .push((child.to_string(), refusal_event));
        if let Some(action) = self.on_rollover.lock().expect("on-rollover lock").as_ref() {
            action();
        }
        if let Some(detail) = self
            .rollover_failure
            .lock()
            .expect("rollover failure lock")
            .clone()
        {
            return Err(detail);
        }
        let epoch = self
            .snapshot(child)?
            .epoch
            .map(|epoch| epoch + 1)
            .unwrap_or(2);
        if let Some(snapshot) = self
            .snapshots
            .lock()
            .expect("snapshot lock")
            .get_mut(&child.to_string())
        {
            snapshot.epoch = Some(epoch);
            snapshot.state = Some(odin_domain::huginn::LiveSessionState::Idle);
            snapshot.provider_fault = None;
        }
        u64::try_from(epoch).map_err(|_| "epoch exceeds u64".to_owned())
    }

    /// Mints the fixture's exact attempt command at epoch 1, head 0.
    fn open_delivery(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<odin_domain::huginn::LiveCommand, String> {
        let action = self.on_open_delivery.lock().expect("open hook").take();
        if let Some(action) = action {
            action();
        }
        let serial = self
            .opened
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.ended_targets.lock().expect("ended").contains(&child) {
            return Err(format!(
                "{}: session {child} has ended",
                super::TARGET_ENDED
            ));
        }
        Ok(odin_domain::huginn::LiveCommand {
            command_id: CommandId::new(format!("fixture-report-{serial}"))
                .map_err(|error| error.to_string())?,
            session_id: child,
            expected_epoch: odin_domain::huginn::SessionEpoch::new(1),
            expected_event_head: Some(odin_domain::huginn::EventSeq::new(0)),
            body,
        })
    }

    /// Executes each command ID once, even when its outcome remains unreadable.
    /// Replays return the scripted journal outcome without repeating the body.
    fn deliver(
        &self,
        command: odin_domain::huginn::LiveCommand,
    ) -> Result<DeliveryVerdict, String> {
        self.delivered
            .lock()
            .expect("delivered lock")
            .push(command.command_id.to_string());
        if let Some(action) = self.on_delivery.lock().expect("delivery hook").as_ref() {
            action(&command);
        }
        if self
            .refused_deliveries
            .lock()
            .expect("refused ids")
            .contains(command.command_id.as_str())
        {
            return Ok(DeliveryVerdict::Refused(
                "scripted stale epoch before admission".to_owned(),
            ));
        }
        let unsettled = self
            .indeterminate
            .lock()
            .expect("indeterminate lock")
            .iter()
            .any(|prefix| command.command_id.as_str().starts_with(prefix));
        if !self
            .executed
            .lock()
            .expect("executed lock")
            .contains(command.command_id.as_str())
        {
            self.command(command.session_id, command.body)?;
            self.executed
                .lock()
                .expect("executed lock")
                .insert(command.command_id.to_string());
        }
        Ok(if unsettled {
            DeliveryVerdict::Unsettled
        } else {
            DeliveryVerdict::Delivered
        })
    }

    fn next_launch_option(
        &self,
        _child: LiveSessionId,
        current: &super::WorkerLane,
    ) -> Result<Option<super::WorkerLane>, String> {
        Ok(super::next_declared_lane(
            &self.lanes.lock().expect("lanes lock"),
            current,
        ))
    }

    fn snapshot(&self, child: LiveSessionId) -> Result<ChildLifecycleSnapshot, String> {
        let action = self.on_snapshot.lock().expect("snapshot hook").take();
        if let Some(action) = action {
            action();
        }
        if let Some(error) = self
            .snapshot_failures
            .lock()
            .expect("snapshot failure lock")
            .get(&child.to_string())
            .cloned()
        {
            return Err(error);
        }
        Ok(self
            .snapshots
            .lock()
            .expect("snapshot lock")
            .get(&child.to_string())
            .cloned()
            .unwrap_or(ChildLifecycleSnapshot {
                active: false,
                state: None,
                epoch: None,
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: None,
            }))
    }

    fn prompt(&self, child: LiveSessionId, message: &str) -> Result<(), String> {
        self.set(&child, true);
        if let Some(detail) = self
            .prompt_failure
            .lock()
            .expect("prompt failure lock")
            .take()
        {
            return Err(detail);
        }
        self.prompts
            .lock()
            .expect("prompt lock")
            .push(message.to_owned());
        Ok(())
    }

    fn stop_child(&self, child: LiveSessionId) -> Result<ChildStop, String> {
        self.stops
            .lock()
            .expect("stop lock")
            .push(child.to_string());
        if let Some(action) = self.on_stop.lock().expect("on-stop lock").as_ref() {
            action();
        }
        if let Some(detail) = self
            .stop_failures
            .lock()
            .expect("stop failure lock")
            .get(&child.to_string())
            .cloned()
        {
            return Err(detail);
        }
        if let Some(detail) = self
            .next_stop_failure
            .lock()
            .expect("next stop failure lock")
            .take()
        {
            return Err(detail);
        }
        let bridge = self
            .child_bridge_stop
            .lock()
            .expect("child bridge stop lock")
            .clone();
        if let Some(bridge) = bridge {
            bridge(child)?;
        }
        if !self
            .pinned_active
            .lock()
            .expect("pinned-active lock")
            .contains(&child.to_string())
        {
            self.set(&child, false);
        }
        Ok(ChildStop::Ended)
    }

    fn await_stop(&self, child: LiveSessionId, _budget: Duration) -> Result<bool, String> {
        if self
            .pinned_active
            .lock()
            .expect("pinned-active lock")
            .contains(&child.to_string())
        {
            return Ok(false);
        }
        self.set(&child, false);
        Ok(true)
    }

    fn retire_capsule_on_stop(
        &self,
        session: LiveSessionId,
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        if std::time::Instant::now() >= deadline {
            return Err("capsule retirement deadline elapsed".to_owned());
        }
        self.retires
            .lock()
            .expect("retire lock")
            .push(session.to_string());
        Ok(())
    }

    /// Each child's terminal shows its own id, so a read of the wrong child is visible.
    fn screen(&self, child: LiveSessionId) -> Result<Option<String>, String> {
        Ok(Some(format!("terminal of {child}")))
    }
    fn last_answer_after(
        &self,
        child: LiveSessionId,
        _epoch: Option<i64>,
        after: u64,
    ) -> Result<super::LastAnswerScan, String> {
        if let Some(error) = self
            .answer_errors
            .lock()
            .expect("answer error lock")
            .get(&child.to_string())
            .cloned()
        {
            return Err(error);
        }
        self.answer_afters
            .lock()
            .expect("answer after lock")
            .push(after);
        let head = self
            .answer_heads
            .lock()
            .expect("head lock")
            .get(&child.to_string())
            .copied()
            .unwrap_or(0);
        // The fixture has no durable history: only installed answers exist.
        let answer = self
            .answers
            .lock()
            .expect("answer lock")
            .get(&child.to_string())
            .cloned();
        let reset = answer.is_some();
        Ok(super::LastAnswerScan {
            answer,
            head,
            reset,
        })
    }

    fn last_failure(&self, child: LiveSessionId) -> Result<Option<SessionFailure>, String> {
        Ok(self
            .failures
            .lock()
            .expect("failure lock")
            .get(&child.to_string())
            .cloned())
    }

    fn resting_workload_sessions(
        &self,
    ) -> Result<Vec<(LiveSessionId, String, WorkloadRest)>, String> {
        Ok(self.resting_pods.lock().expect("pod lock").clone())
    }

    fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String> {
        Ok(self.ended_pods.lock().expect("ended pod lock").clone())
    }

    fn last_result(&self, child: LiveSessionId) -> Result<Option<TaskResultReport>, String> {
        Ok(self
            .results
            .lock()
            .expect("result lock")
            .get(&child.to_string())
            .cloned())
    }
}

struct RecordingProvisioner {
    calls: Mutex<Vec<String>>,
    titles: Mutex<Vec<String>>,
    result: Result<(), String>,
    preflight_calls: Mutex<Vec<String>>,
    preflight_result: Mutex<Result<(), String>>,
    ledger: Arc<Mutex<Ledger>>,
    control: Arc<FakeControl>,
    bridge_creates_child_run: bool,
}

impl ChildAuthorityProvisioner for RecordingProvisioner {
    fn seat_worker_profile(
        &self,
        _target_seat: &SeatId,
        requested: Option<&super::WorkerLane>,
    ) -> Result<(String, String), String> {
        Ok(requested.map_or_else(
            || ("gateway".to_owned(), "glm-flash".to_owned()),
            |lane| (lane.provider.clone(), lane.model.clone()),
        ))
    }

    fn preflight_child(
        &self,
        _parent_seat: &SeatId,
        _parent_lane: &LaneId,
        parent_session: &SessionId,
        child_project: &ProjectId,
        target_seat: Option<&SeatId>,
        _launch: Option<&super::WorkerLane>,
    ) -> Result<(), String> {
        // Readiness is independent of provisioning and must not mutate its state.
        self.preflight_calls
            .lock()
            .expect("preflight call lock")
            .push(format!(
                "{parent_session}|{child_project}|{}",
                target_seat
                    .map(|seat| seat.as_str().to_owned())
                    .unwrap_or_default()
            ));
        self.preflight_result
            .lock()
            .expect("preflight result lock")
            .clone()
    }

    fn provision_child(
        &self,
        _parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &SessionId,
        child: ChildOpen<'_>,
    ) -> Result<LiveSessionId, String> {
        let (child_command, child_project) = (child.command, child.project);
        self.calls
            .lock()
            .expect("provision call lock")
            .push(format!("{parent_session}|{child_command}|{child_project}"));
        self.titles
            .lock()
            .expect("provision title lock")
            .push(child.title.to_owned());
        match &self.result {
            Ok(()) => {
                let child = crate::live::supervisor::session_id_for(child_command)
                    .map_err(|error| error.to_string())?;
                // Mirror supervisor.open/ensure_bridge_run: the bound run
                // is durable at the next per-lane attempt before return.
                if self.bridge_creates_child_run {
                    self.create_child_run(parent_lane, &child, child_command)?;
                }
                self.control.set(&child, true);
                Ok(child)
            }
            Err(detail) => Err(detail.clone()),
        }
    }

    fn provision_child_for_seat(
        &self,
        _parent_seat: &SeatId,
        parent_lane: &LaneId,
        _parent_session: &SessionId,
        child: ChildOpen<'_>,
        target_seat: &SeatId,
    ) -> Result<LiveSessionId, String> {
        let child_command = child.command;
        self.titles
            .lock()
            .expect("provision title lock")
            .push(child.title.to_owned());
        self.calls
            .lock()
            .expect("provision call lock")
            .push(format!("cross-seat:{target_seat}|{child_command}"));
        match &self.result {
            Ok(()) => {
                let child = crate::live::supervisor::session_id_for(child_command)
                    .map_err(|error| error.to_string())?;
                if self.bridge_creates_child_run {
                    self.create_child_run(parent_lane, &child, child_command)?;
                }
                self.control.set(&child, true);
                Ok(child)
            }
            Err(detail) => Err(detail.clone()),
        }
    }
}

impl RecordingProvisioner {
    /// Mirrors the fixture's `provision_child` bridge-run creation for the
    /// cross-seat route.
    fn create_child_run(
        &self,
        parent_lane: &LaneId,
        child: &LiveSessionId,
        child_command: &CommandId,
    ) -> Result<(), String> {
        let child_run = GovernedTaskOwner::child_run_for(child).map_err(|e| e.to_string())?;
        let guard = self
            .ledger
            .lock()
            .map_err(|_| "fixture ledger lock is poisoned".to_owned())?;
        let attempt_number: i64 = guard
            .connection()
            .query_row(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM runs WHERE lane_id = ?1",
                [parent_lane.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| format!("fixture could not select the next child attempt: {error}"))?;
        create_run(
            guard.connection(),
            &NewRun {
                run_id: child_run,
                lane_id: parent_lane.clone(),
                attempt_number,
                workflow_id: Some(format!("live:delegated:{child}")),
                workflow_version: Some(1),
                input_hash: Digest::hash(child_command.as_str().as_bytes()).to_string(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: NOW,
            },
        )
        .map_err(|error| format!("fixture could not create the child run: {error}"))?;
        Ok(())
    }
}

struct OwnerFixture {
    root: tempfile::TempDir,
    owner: Arc<GovernedTaskOwner>,
    ledger: Arc<Mutex<Ledger>>,
    links: DelegationLinkLedger,
    control: Arc<FakeControl>,
    provisioner: Arc<dyn ChildAuthorityProvisioner>,
    recording: Arc<RecordingProvisioner>,
    governance: DelegationGovernance,
    parent_run: RunId,
    caller_session: SessionId,
    project: ProjectId,
}

fn fixture_with(
    accepted_parent_plan: bool,
    provision_result: Result<(), String>,
    max_children: usize,
    bridge_creates_child_run: bool,
) -> OwnerFixture {
    fixture_with_preflight(
        accepted_parent_plan,
        provision_result,
        Ok(()),
        max_children,
        bridge_creates_child_run,
    )
}

/// Configures readiness independently of provisioning to exercise changes between them.
fn fixture_with_preflight(
    accepted_parent_plan: bool,
    provision_result: Result<(), String>,
    preflight_result: Result<(), String>,
    max_children: usize,
    bridge_creates_child_run: bool,
) -> OwnerFixture {
    let root_dir = tempfile::tempdir().expect("fixture root");
    let root = root_dir.path().to_path_buf();
    let links = DelegationLinkLedger::open(root.join("links")).expect("link ledger");
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger")));
    let parent_run =
        RunId::new("run:live:00000000-0000-4000-8000-0000000000a0").expect("parent run");
    {
        // The parent run row exists in production because the parent
        // bridge created it; the fixture reproduces that durable state.
        let guard = ledger.lock().expect("ledger lock");
        let lane_id = LaneId::new("lane.odin").expect("lane");
        // runs.lane_id references lanes(lane_id), so the parent lane row
        // is seeded first through the same lane_run API production uses.
        create_lane(
            guard.connection(),
            &NewLane {
                lane_id: lane_id.clone(),
                seat_id: SeatId::new("seat.architect").expect("seat"),
                project_id: None,
                template_id: "template:dev".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at: NOW,
                retained: false,
            },
        )
        .expect("parent lane row");
        create_run(
            guard.connection(),
            &NewRun {
                run_id: parent_run.clone(),
                lane_id,
                attempt_number: 1,
                workflow_id: Some("live:fixture".to_owned()),
                workflow_version: Some(1),
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: NOW,
            },
        )
        .expect("parent run row");
    }
    if accepted_parent_plan {
        let mut guard = ledger.lock().expect("ledger lock");
        let plan = guard
            .replace_plan(
                &parent_run,
                "Parent objective",
                &[TodoSpec {
                    id: TodoId::new("todo:parent").expect("todo id"),
                    title: "Parent todo".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                NOW,
            )
            .expect("parent plan");
        guard
            .accept_plan(&parent_run, plan.revision, "operator:fixture", NOW)
            .expect("accept parent plan");
    }
    let control = Arc::new(FakeControl::new());
    let mut approved = BTreeMap::new();
    let seat = SeatId::new("seat.architect").expect("seat");
    let lane = LaneId::new("lane.odin").expect("lane");
    let mut operation_bindings = BTreeMap::new();
    operation_bindings.insert(
        (seat.clone(), lane.clone()),
        SeatOperationPolicy {
            policy: odin_kernel::PolicyContext {
                seat_id: seat,
                slice_id: SliceId::new("slice.fixture").expect("slice"),
                lane_id: lane,
                seat_revision: Digest::hash(b"seat"),
                slice_revision: Digest::hash(b"slice"),
                capability_policy_digest: Digest::hash(b"admission"),
                seat_tool_refs: BTreeSet::new(),
                slice_capabilities: BTreeSet::new(),
                project_capabilities: BTreeSet::new(),
                lane_capabilities: BTreeSet::new(),
                denied_capabilities: BTreeSet::new(),
                denied_tools: BTreeSet::new(),
                seat_categories: BTreeSet::new(),
                adapter_health: Default::default(),
                resource_constraints: BTreeMap::new(),
                seat_hints: BTreeMap::new(),
            },
            context_policy_digest: Digest::hash(b"context"),
        },
    );
    // A second seat on the same lane exercises cross-seat delegation.
    let asked_seat = SeatId::new("seat.gungnir").expect("seat");
    let mut asked_binding = operation_bindings
        .values()
        .next()
        .cloned()
        .expect("architect binding");
    asked_binding.policy.seat_id = asked_seat.clone();
    operation_bindings.insert(
        (asked_seat, LaneId::new("lane.odin").expect("lane")),
        asked_binding,
    );
    approved.insert(
        ProjectId::new("project.odin").expect("project id"),
        root.join("odin"),
    );
    approved.insert(
        ProjectId::new("project.dots").expect("project id"),
        root.join("dotfiles"),
    );
    let governance = DelegationGovernance {
        provider: "gateway".to_owned(),
        model: "glm-flash".to_owned(),
        max_children_per_session: max_children,
        max_prompt_bytes: 4_096,
        approved_projects: approved,
        operation_bindings,
        registry: None,
    };
    let recording = Arc::new(RecordingProvisioner {
        calls: Mutex::new(Vec::new()),
        titles: Mutex::new(Vec::new()),
        result: provision_result,
        preflight_calls: Mutex::new(Vec::new()),
        preflight_result: Mutex::new(preflight_result),
        ledger: Arc::clone(&ledger),
        control: Arc::clone(&control),
        bridge_creates_child_run,
    });
    let provisioner: Arc<dyn ChildAuthorityProvisioner> = recording.clone();
    let owner = Arc::new(GovernedTaskOwner::new(
        Arc::clone(&provisioner),
        control.clone(),
        links.clone(),
        Arc::clone(&ledger),
        governance.clone(),
    ));
    OwnerFixture {
        root: root_dir,
        provisioner,
        recording,
        control: Arc::clone(&control),
        links: links.clone(),
        ledger: Arc::clone(&ledger),
        governance: governance.clone(),
        owner,
        parent_run,
        caller_session: SessionId::new("00000000-0000-4000-8000-0000000000a1")
            .expect("caller session"),
        project: ProjectId::new("project.odin").expect("project id"),
    }
}

/// A worker lane on the gateway provider.
fn gateway_lane(model: &str) -> super::WorkerLane {
    super::WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    }
}

fn request(fixture: &OwnerFixture) -> TaskCreateRequest {
    TaskCreateRequest {
        caller_session: fixture.caller_session.clone(),
        caller_run: fixture.parent_run.clone(),
        caller_seat: SeatId::new("seat.architect").expect("seat"),
        caller_lane: LaneId::new("lane.odin").expect("lane"),
        project: fixture.project.clone(),
        prompt: "Implement the governed worker lifecycle.".to_owned(),
        title: None,
        target_seat: None,
        launch: None,
    }
}

/// [`request`] with a distinct prompt: a second, different unit of work.
fn request_n(fixture: &OwnerFixture, n: usize) -> TaskCreateRequest {
    TaskCreateRequest {
        prompt: format!("Implement the governed worker lifecycle, part {n}."),
        ..request(fixture)
    }
}

/// A running depth-one row for `command`'s child, as the owner writes it; tests override
/// the fields they care about.
fn sample_link(fixture: &OwnerFixture, command: &str) -> DelegationLink {
    let command = CommandId::new(command).expect("command");
    let child = crate::live::supervisor::session_id_for(&command).expect("child session");
    DelegationLink {
        schema: DELEGATION_LINK_SCHEMA.to_owned(),
        child,
        parent: fixture.caller_session.clone(),
        parent_run: fixture.parent_run.clone(),
        parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
        child_run: GovernedTaskOwner::child_run_for(&child).expect("child run"),
        command,
        project: fixture.project.clone(),
        lane: None,
        provider: "gateway".to_owned(),
        model: "glm-flash".to_owned(),
        prompt_digest: Digest::hash(b"prompt"),
        depth: 1,
        phase: DelegationPhase::Running,
        created_at_ms: 1,
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
        assignment: String::new(),
        rollover_admissions: 0,
        pending_report: None,
        budget_raises: Vec::new(),
    }
}

#[test]
fn link_ledger_roundtrips_and_rejects_foreign_schemas() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let link = DelegationLink {
        phase: DelegationPhase::Provisioning,
        ..sample_link(&fixture, "odin.task.create:roundtrip")
    };
    let mut changes = fixture.links.subscribe_persists();
    let version = fixture.links.persist_version().expect("persist version");
    fixture.links.persist(&link).expect("persist");
    let loaded = fixture.links.load(&link.child).expect("load").expect("row");
    assert_eq!(loaded, link);
    assert!(changes.has_changed().expect("open channel"));
    assert!(fixture.links.persist_version().expect("persist version") > version);
    changes.borrow_and_update();
    let clone = fixture.links.clone();
    let mut changed = link.clone();
    changed.phase = DelegationPhase::Running;
    clone
        .persist(&changed)
        .expect("persist through shared clone");
    assert!(changes.has_changed().expect("shared notification channel"));
    let rows = fixture.links.all_rows().expect("atomic link snapshot");
    assert_eq!(rows[0].link.phase, DelegationPhase::Running);
    assert_eq!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("children")
            .len(),
        1
    );
    let mut foreign = link.clone();
    foreign.schema = "odin.delegation-link.v0".to_owned();
    assert!(fixture.links.persist(&foreign).is_err());
}

#[test]
fn create_links_one_running_child_and_accepts_its_plan_before_the_prompt() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    assert!(receipt.plan_accepted);
    let prompts = fixture.control.prompts.lock().expect("prompts");
    assert!(prompts[0].starts_with("You are the delegated implementation worker"));

    assert_eq!(receipt.prompt_bytes, prompts[0].len());
    drop(prompts);
    assert_eq!(receipt.provider, "gateway");
    assert_eq!(receipt.model, "glm-flash");
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].phase, DelegationPhase::Running);
    assert_eq!(rows[0].depth, 1);
    assert_eq!(rows[0].child, receipt.child_session);
    assert_eq!(
        fixture.control.prompts.lock().expect("prompts").len(),
        1,
        "exactly one bounded prompt is dispatched"
    );
    {
        let ledger = fixture.ledger.lock().expect("ledger lock");
        assert!(
            ledger
                .plan_is_accepted(&receipt.child_run)
                .expect("child acceptance"),
            "the child run inherits acceptance before the prompt"
        );
    }
}

#[test]
fn a_child_opens_titled_by_its_purpose() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let mut ask = request(&fixture);
    ask.prompt = "  \nRun a quick GPU smoke test on the pc and report the result plainly.\n\
                  Use the declared gpu-smoke profile."
        .to_owned();
    fixture.owner.create_task(ask).expect("receipt");
    // A seat ask states its subject: that is the purpose, not the
    // "Subject: …" line its prompt template opens with.
    let mut ask = request(&fixture);
    ask.prompt = "Subject: gpu check\nUrgency: low\nTarget seat: kubert\n\nRun it.".to_owned();
    ask.title = Some("Quick GPU smoke test on the pc".to_owned());
    fixture.owner.create_task(ask).expect("receipt");
    assert_eq!(
        fixture.recording.titles.lock().expect("titles").as_slice(),
        [
            "Run a quick GPU smoke test on the pc and report",
            "Quick GPU smoke test on the pc"
        ]
    );
}

#[test]
fn an_idle_pod_with_an_answer_is_settled_and_ended() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let answered = LiveSessionId::new(uuid::Uuid::from_u128(0xa1)).expect("session");
    let silent = LiveSessionId::new(uuid::Uuid::from_u128(0xa2)).expect("session");
    *fixture.control.resting_pods.lock().expect("pod lock") = vec![
        (answered, "op-launch-a".to_owned(), WorkloadRest::Idle),
        (silent, "op-launch-b".to_owned(), WorkloadRest::Idle),
    ];
    fixture.control.answers.lock().expect("answer lock").insert(
        answered.to_string(),
        "1. 2510.00001 rotating detonation".to_owned(),
    );
    let settled = fixture.owner.settled_workloads().expect("scan");
    assert_eq!(settled.len(), 1, "only the answered pod settled");
    assert_eq!(settled[0].session, answered);
    assert_eq!(settled[0].operation, "op-launch-a", "the pod to release");
    assert_eq!(settled[0].answer, "1. 2510.00001 rotating detonation");
    assert!(!settled[0].failed);
    fixture.owner.end_workload(answered).expect("ended");
    assert!(fixture
        .control
        .stops
        .lock()
        .expect("stop lock")
        .contains(&answered.to_string()));
}

#[test]
fn a_pod_refused_on_its_window_is_rolled_over_before_it_settles() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let past = GovernedTaskOwner::clock_ms() - FAILED_POD_GRACE_MS - 1_000;
    let windowed = LiveSessionId::new(uuid::Uuid::from_u128(0xc1)).expect("session");
    let provider = LiveSessionId::new(uuid::Uuid::from_u128(0xc2)).expect("session");
    *fixture.control.resting_pods.lock().expect("pod lock") = vec![
        (
            windowed,
            "op-w".to_owned(),
            WorkloadRest::Failed { since_ms: past },
        ),
        (
            provider,
            "op-p".to_owned(),
            WorkloadRest::Failed { since_ms: past },
        ),
    ];
    {
        let mut failures = fixture.control.failures.lock().expect("failure lock");
        failures.insert(
            windowed.to_string(),
            SessionFailure {
                event: 209,
                code: "context_refusal.window_exceeded".to_owned(),
                message: "the request is larger than the window".to_owned(),
            },
        );
        failures.insert(
            provider.to_string(),
            SessionFailure {
                event: 210,
                code: "provider".to_owned(),
                message: "upstream error".to_owned(),
            },
        );
    }
    let settled = fixture.owner.settled_workloads().expect("scan");
    assert_eq!(
        *fixture.control.rollover_calls.lock().expect("rollover"),
        [(windowed.to_string(), 209)],
        "only the window refusal rolls over"
    );
    assert_eq!(
        settled.iter().map(|pod| pod.session).collect::<Vec<_>>(),
        [provider],
        "the rolled pod is not settled; the provider failure settles past its grace"
    );
}

#[test]
fn a_pod_failed_past_the_grace_settles_as_failed() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let now = GovernedTaskOwner::clock_ms();
    let said = LiveSessionId::new(uuid::Uuid::from_u128(0xb1)).expect("session");
    let mute = LiveSessionId::new(uuid::Uuid::from_u128(0xb2)).expect("session");
    let fresh = LiveSessionId::new(uuid::Uuid::from_u128(0xb3)).expect("session");
    let past = now - FAILED_POD_GRACE_MS - 1_000;
    *fixture.control.resting_pods.lock().expect("pod lock") = vec![
        (
            said,
            "op-a".to_owned(),
            WorkloadRest::Failed { since_ms: past },
        ),
        (
            mute,
            "op-b".to_owned(),
            WorkloadRest::Failed { since_ms: past },
        ),
        (
            fresh,
            "op-c".to_owned(),
            WorkloadRest::Failed { since_ms: now },
        ),
    ];
    for session in [said, fresh] {
        fixture
            .control
            .answers
            .lock()
            .expect("answer lock")
            .insert(session.to_string(), "Method: a neural ODE".to_owned());
    }
    let settled = fixture.owner.settled_workloads().expect("scan");
    let found: Vec<(LiveSessionId, &str, &str, bool)> = settled
        .iter()
        .map(|pod| {
            (
                pod.session,
                pod.operation.as_str(),
                pod.answer.as_str(),
                pod.failed,
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            (said, "op-a", "Method: a neural ODE", true),
            (mute, "op-b", "", true),
        ],
        "a failed pod within the grace waits to be handed on"
    );
    assert!(settled.iter().all(|pod| pod.key.starts_with("failed-")));
}

/// A working child hears once that its time limit is near, while it can still save its work; a young child
/// and a child that already rested hear nothing.
#[test]
fn a_working_child_is_warned_once_before_its_time_limit() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let limit = std::time::Duration::from_secs(3600);
    let scan = || {
        fixture
            .owner
            .retire_timed_out_children(limit, None)
            .expect("scan")
    };
    let age = |seconds: u64| {
        let created = GovernedTaskOwner::clock_ms() - seconds * 1000;
        fixture
            .owner
            .write_link(&child, |link| {
                link.created_at_ms = created;
                true
            })
            .expect("row aged");
    };
    {
        let mut snapshots = fixture.control.snapshots.lock().expect("snapshot lock");
        snapshots
            .get_mut(&child.to_string())
            .expect("snapshot")
            .state = Some(odin_domain::huginn::LiveSessionState::Running);
    }
    let steers = || {
        fixture
            .control
            .commands
            .lock()
            .expect("commands")
            .iter()
            .filter(|kind| kind.as_str() == "Steer")
            .count()
    };
    age(600);
    scan();
    assert_eq!(
        steers(),
        0,
        "a child with most of its time left hears nothing"
    );
    age(3600 - 300);
    let (retired, failures) = scan();
    assert!(retired.is_empty() && failures.is_empty());
    assert_eq!(steers(), 1, "five minutes before the limit it is told");
    scan();
    assert_eq!(steers(), 1, "and told only once");
    assert!(fixture.control.stops.lock().expect("stops").is_empty());
}

#[test]
fn a_child_past_its_declared_timeout_is_ended() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(std::time::Duration::from_secs(3600), None)
        .expect("scan");
    assert!(
        retired.is_empty() && failures.is_empty(),
        "a young child stays"
    );
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(std::time::Duration::ZERO, None)
        .expect("scan");
    assert_eq!(
        retired.iter().map(|out| out.child).collect::<Vec<_>>(),
        vec![receipt.child_session]
    );
    assert!(failures.is_empty());
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[receipt.child_session.to_string()]
    );
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows[0].phase, DelegationPhase::Ended);
}

#[test]
fn a_finished_child_idle_past_its_declared_bound_is_ended() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let idle = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let working = fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect("receipt")
        .child_session;
    let now = GovernedTaskOwner::clock_ms();
    let snapshot = |settled_since_ms: Option<u64>| ChildLifecycleSnapshot {
        active: true,
        state: Some(if settled_since_ms.is_some() {
            odin_domain::huginn::LiveSessionState::Idle
        } else {
            odin_domain::huginn::LiveSessionState::Running
        }),
        epoch: Some(1),
        settled_since_ms,
        quiet_since_ms: None,
        provider_fault: None,
    };
    {
        let mut snapshots = fixture.control.snapshots.lock().expect("snapshot lock");
        snapshots.insert(idle.to_string(), snapshot(Some(now - 20 * 60 * 1000)));
        snapshots.insert(working.to_string(), snapshot(None));
    }
    fixture.control.answers.lock().expect("answers").insert(
        idle.to_string(),
        "The requested change is complete.".to_owned(),
    );
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(
            std::time::Duration::from_secs(3600),
            Some(std::time::Duration::from_secs(600)),
        )
        .expect("scan");
    assert_eq!(
        retired.iter().map(|out| out.child).collect::<Vec<_>>(),
        vec![idle]
    );
    assert!(retired[0].idle, "ended for resting, not for age");
    assert!(failures.is_empty());
    assert_eq!(
        retired[0]
            .finished
            .as_ref()
            .map(|turn| turn.answer.as_str()),
        Some("The requested change is complete."),
        "retirement retains the settled result instead of reporting unfinished work",
    );
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[idle.to_string()]
    );
}

#[test]
fn an_explicit_parent_stop_during_stall_recovery_wins() {
    parent_stop_during_stall_recovery(false);
    parent_stop_during_stall_recovery(true);
}

#[test]
fn a_stalled_child_is_resumed_then_ended_once_its_retries_are_spent() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let stalled = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let busy = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let now = GovernedTaskOwner::clock_ms();
    let working = |quiet_since_ms: u64| ChildLifecycleSnapshot {
        active: true,
        state: Some(odin_domain::huginn::LiveSessionState::Running),
        epoch: Some(1),
        settled_since_ms: None,
        quiet_since_ms: Some(quiet_since_ms),
        provider_fault: None,
    };
    let stall = std::time::Duration::from_secs(300);
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(busy.to_string(), working(now));
    for _ in 0..super::MAX_STALL_RETRIES {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(stalled.to_string(), working(now - 10 * 60 * 1000));
        let pass = fixture.owner.recover_stalled_children(stall).expect("pass");
        assert_eq!(pass.resumed, vec![stalled]);
        assert!(pass.ended.is_empty() && pass.failures.is_empty());
    }
    let aborts = fixture
        .control
        .commands
        .lock()
        .expect("command lock")
        .iter()
        .filter(|kind| kind.contains("AbortCurrentTurn"))
        .count();
    assert_eq!(aborts, usize::from(super::MAX_STALL_RETRIES));
    assert!(fixture
        .control
        .prompts
        .lock()
        .expect("prompt lock")
        .last()
        .is_some_and(|prompt| prompt.contains("made no progress")));
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(stalled.to_string(), working(now - 10 * 60 * 1000));
    let pass = fixture.owner.recover_stalled_children(stall).expect("pass");
    assert!(pass.resumed.is_empty());
    assert_eq!(
        pass.ended
            .iter()
            .map(|out| (out.child, out.parent_seat.clone(), out.stalls.len()))
            .collect::<Vec<_>>(),
        vec![(
            stalled,
            Some(SeatId::new("seat.architect").expect("seat")),
            usize::from(super::MAX_STALL_RETRIES) + 1
        )]
    );
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[stalled.to_string()],
        "the child still making progress is never touched"
    );
}

fn mark_child_stalled(control: &FakeControl, child: LiveSessionId) {
    control.snapshots.lock().expect("snapshots").insert(
        child.to_string(),
        ChildLifecycleSnapshot {
            active: true,
            state: Some(odin_domain::huginn::LiveSessionState::Running),
            epoch: Some(1),
            settled_since_ms: None,
            quiet_since_ms: Some(0),
            provider_fault: None,
        },
    );
}

fn parent_stop_during_stall_recovery(switching: bool) {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    *fixture.control.lanes.lock().expect("lanes") = vec![
        WorkerLane {
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
        },
        WorkerLane {
            provider: "gateway".to_owned(),
            model: "zai-glm".to_owned(),
        },
    ];
    if switching {
        mark_child_stalled(&fixture.control, child);
        assert_eq!(
            owner
                .recover_stalled_children(Duration::ZERO)
                .expect("first retry")
                .resumed,
            [child]
        );
    }
    let prompts_before = fixture.control.prompts.lock().expect("prompts").len();
    let caller_session = fixture.caller_session.clone();
    let caller_seat = request(&fixture).caller_seat;
    let stopping_owner = Arc::downgrade(&owner);
    let commands = AtomicU64::new(0);
    fixture.control.on_command(Box::new(move || {
        // Abort is command one; SetModel is command two. The real parent
        // Stop lands synchronously inside that exact applied command,
        // before recovery can persist its stale row or send a continuation.
        let ordinal = commands.fetch_add(1, Ordering::SeqCst) + 1;
        if ordinal == if switching { 2 } else { 1 } {
            stopping_owner
                .upgrade()
                .expect("owner")
                .control_task(TaskControlRequest {
                    caller_session: caller_session.clone(),
                    caller_seat: caller_seat.clone(),
                    child,
                    control: TaskControl::Stop,
                })
                .expect("explicit parent stop");
        }
    }));
    mark_child_stalled(&fixture.control, child);
    let pass = owner
        .recover_stalled_children(Duration::ZERO)
        .expect("raced recovery");
    assert!(pass.resumed.is_empty() && pass.ended.is_empty() && pass.refused.is_empty());
    assert!(
        pass.failures.is_empty(),
        "parent stop is not a recovery failure"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(
        row.stall_retries,
        u8::from(switching),
        "a stopped recovery earns no retry"
    );
    assert_eq!(
        fixture.control.prompts.lock().expect("prompts").len(),
        prompts_before
    );
    assert!(!fixture.control.snapshot(child).expect("snapshot").active);
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        [child.to_string()]
    );
    // Abort has no result to capture, but a later result must remain eligible.
    owner
        .capture_pending_completion(&child)
        .expect("pending scan");
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    assert_eq!(row.learning_result_sequence, None);
    assert_eq!(row.learning_capture_sequence, None);
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    owner.result_persisted(child, 54);
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
    let again = owner
        .recover_stalled_children(Duration::ZERO)
        .expect("rescan");
    assert!(again.resumed.is_empty() && again.ended.is_empty());
    assert_eq!(fixture.recording.calls.lock().expect("provisions").len(), 1);
}

#[test]
fn stall_retry_budget_survives_reload_without_duplicate_task_or_end_report() {
    for fallback in [false, true] {
        let fixture = fixture_with(true, Ok(()), 2, true);
        if fallback {
            *fixture.control.lanes.lock().expect("lanes") = vec![
                WorkerLane {
                    provider: "gateway".to_owned(),
                    model: "glm-flash".to_owned(),
                },
                WorkerLane {
                    provider: "gateway".to_owned(),
                    model: "zai-glm".to_owned(),
                },
            ];
        }
        let child = fixture
            .owner
            .create_task(request(&fixture))
            .expect("create")
            .child_session;
        let budget = MAX_STALL_RETRIES + u8::from(fallback);
        let mut end_reports = 0;
        for attempt in 0..budget + 3 {
            // Reopen the on-disk link ledger and reconstruct the owner on
            // every pass, including duplicate scans after the budget ends.
            let links =
                DelegationLinkLedger::open(fixture.root.path().join("links")).expect("reopen");
            let owner = GovernedTaskOwner::new(
                fixture.provisioner.clone(),
                fixture.control.clone(),
                links.clone(),
                fixture.ledger.clone(),
                fixture.governance.clone(),
            );
            if attempt <= budget {
                mark_child_stalled(&fixture.control, child);
            }
            let pass = owner
                .recover_stalled_children(Duration::ZERO)
                .expect("recover");
            assert!(pass.failures.is_empty() && pass.refused.is_empty());
            assert_eq!(pass.resumed.len(), usize::from(attempt < budget));
            end_reports += pass.ended.len();
            let row = links.load(&child).expect("load").expect("row");
            assert_eq!(row.stall_retries, (attempt + 1).min(budget));
            assert_eq!(row.switched_to.is_some(), fallback && attempt >= 1);
            assert_eq!(
                row.phase,
                if attempt < budget {
                    DelegationPhase::Running
                } else {
                    DelegationPhase::Ended
                }
            );
            assert_eq!(links.all_rows().expect("rows").len(), 1);
            assert_eq!(row.learning_capture_sequence, None);
        }
        assert_eq!(
            end_reports, 1,
            "only the budget-exhausting pass reports the end"
        );
        assert_eq!(fixture.control.stops.lock().expect("stops").len(), 1);
        assert_eq!(fixture.recording.calls.lock().expect("provisions").len(), 1);
        assert_eq!(
            fixture
                .control
                .commands
                .lock()
                .expect("commands")
                .iter()
                .filter(|kind| kind.contains("AbortCurrentTurn"))
                .count(),
            usize::from(budget)
        );
    }
}

#[test]
fn a_repeatedly_stalled_child_moves_to_the_seats_next_declared_lane() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = gateway_lane;
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("zai-glm"), lane("glm-flash")];
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let now = GovernedTaskOwner::clock_ms();
    let stall = std::time::Duration::from_secs(300);
    let stall_once = || {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(
                child.to_string(),
                ChildLifecycleSnapshot {
                    active: true,
                    state: Some(odin_domain::huginn::LiveSessionState::Running),
                    epoch: Some(1),
                    settled_since_ms: None,
                    quiet_since_ms: Some(now - 10 * 60 * 1000),
                    provider_fault: None,
                },
            );
        fixture.owner.recover_stalled_children(stall).expect("pass")
    };
    let set_models = || {
        fixture
            .control
            .commands
            .lock()
            .expect("command lock")
            .iter()
            .filter(|kind| kind.contains("SetModel"))
            .count()
    };

    let first = stall_once();
    assert_eq!(first.resumed, vec![child]);
    assert!(
        first.switched.is_empty(),
        "one stall retries on the same lane"
    );
    assert_eq!(set_models(), 0);

    let second = stall_once();
    assert_eq!(second.resumed, vec![child]);
    assert_eq!(
        second.switched,
        vec![super::LaneSwitch {
            child,
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            from: lane("glm-flash"),
            to: lane("zai-glm"),
            cause: super::ProviderFaultKind::Stall,
        }],
        "the next declared option wraps past the end of the list"
    );
    assert_eq!(set_models(), 1);

    let third = stall_once();
    assert_eq!(
        third.resumed,
        vec![child],
        "the switch earns one more retry"
    );
    assert_eq!(set_models(), 1, "a worker falls back once");

    let fourth = stall_once();
    assert!(fourth.resumed.is_empty());
    assert_eq!(
        fourth.ended[0].stalls,
        vec![
            "gateway/glm-flash",
            "gateway/glm-flash",
            "gateway/zai-glm",
            "gateway/zai-glm"
        ]
    );
    let rates = fixture.owner.lane_stall_rates().expect("rates");
    for model in ["gateway/glm-flash", "gateway/zai-glm"] {
        assert_eq!(
            rates[model],
            super::LaneStallRate {
                workers: 1,
                stalled_workers: 1,
                stalls: 2,
                ..Default::default()
            }
        );
    }
}

#[test]
fn a_gateway_fallback_is_recorded_on_the_row_and_in_the_lane_rates() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let mut row = fixture.links.load(&child).expect("load").expect("row");
    row.model = "kimi-k31".to_owned();
    fixture.links.persist(&row).expect("persist");
    let served = |requests: u64| {
        move |asked: &odin_domain::huginn::LiveSessionId, _since: u64| {
            assert_eq!(*asked, child);
            Ok(BTreeMap::from([
                ("kimi-k31".to_owned(), 0),
                ("zai-glm".to_owned(), requests),
            ]))
        }
    };

    let (first, failures) = fixture
        .owner
        .observe_gateway_fallbacks(&served(9))
        .expect("pass");
    assert!(failures.is_empty());
    let fallback = super::GatewayFallback {
        lane: "gateway/kimi-k31".to_owned(),
        served: "zai-glm".to_owned(),
        requests: 9,
    };
    assert_eq!(
        first,
        vec![super::FallbackSeen {
            child,
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            fallback: fallback.clone(),
            first: true,
        }]
    );
    let (again, _) = fixture
        .owner
        .observe_gateway_fallbacks(&served(9))
        .expect("pass");
    assert!(again.is_empty(), "an unchanged count is not reported twice");
    let (grown, _) = fixture
        .owner
        .observe_gateway_fallbacks(&served(17))
        .expect("pass");
    assert_eq!(grown.len(), 1);
    assert!(!grown[0].first);
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(
        row.gateway_fallbacks,
        vec![super::GatewayFallback {
            requests: 17,
            ..fallback
        }]
    );
    let rates = fixture.owner.lane_stall_rates().expect("rates");
    assert_eq!(rates["gateway/kimi-k31"].fallback_workers, 1);
    assert_eq!(rates["gateway/kimi-k31"].fallback_requests, 17);

    let own = super::gateway_fallbacks_seen(
        &row,
        &BTreeMap::from([("kimi-k31".to_owned(), 40)]),
        &row.provider,
    );
    assert_eq!(
        own, row.gateway_fallbacks,
        "the worker's own lane is no fallback"
    );
}

#[test]
fn a_refused_request_rotates_at_the_next_request_with_lineage() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = gateway_lane;
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("glm-flash"), lane("kimi-k31")];
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let stall = std::time::Duration::from_secs(300);
    let refused = |event: u64, kind: super::ProviderFaultKind| {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(
                child.to_string(),
                ChildLifecycleSnapshot {
                    active: true,
                    state: Some(odin_domain::huginn::LiveSessionState::Idle),
                    epoch: Some(1),
                    settled_since_ms: Some(GovernedTaskOwner::clock_ms()),
                    quiet_since_ms: None,
                    provider_fault: Some(super::ProviderTurnFault {
                        event,
                        kind,
                        origin: super::ProviderFaultOrigin::Provider,
                    }),
                },
            );
        fixture.owner.recover_stalled_children(stall).expect("pass")
    };
    let row = || {
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .into_iter()
            .find(|row| row.child == child)
            .expect("row")
    };

    let first = refused(40, super::ProviderFaultKind::RejectedKey);
    assert_eq!(
        first.switched,
        vec![super::LaneSwitch {
            child,
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            from: lane("glm-flash"),
            to: lane("kimi-k31"),
            cause: super::ProviderFaultKind::RejectedKey,
        }],
        "the first refusal moves the next request to the next declared lane"
    );
    assert!(first.refused.is_empty() && first.ended.is_empty());
    assert_eq!(
        fixture
            .control
            .commands
            .lock()
            .expect("command lock")
            .iter()
            .filter(|command| command.contains("SetModel"))
            .count(),
        1,
        "the lane is switched before the next request"
    );
    assert!(
        fixture
            .control
            .prompts
            .lock()
            .expect("prompts")
            .iter()
            .any(|prompt| prompt.contains("was refused")),
        "the next request is the resume on the new lane"
    );
    assert!(
        refused(40, super::ProviderFaultKind::RejectedKey)
            .switched
            .is_empty(),
        "one refusal is answered once"
    );
    let link = row();
    assert_eq!(link.switched_to, Some(lane("kimi-k31")));
    assert_eq!(link.stall_retries, 0, "a refusal is not a stall retry");
    assert_eq!(
        link.refusals,
        vec![super::LaneRefusal {
            lane: "gateway/glm-flash".to_owned(),
            cause: "rejected_key".to_owned(),
            event: 40,
            next: Some("gateway/kimi-k31".to_owned()),
        }]
    );

    let second = refused(52, super::ProviderFaultKind::UsageLimit);
    assert!(
        second.switched.is_empty(),
        "a lane that already refused is never rotated back to"
    );
    assert_eq!(
        second.refused,
        vec![super::RefusedOut {
            child,
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            lane: lane("kimi-k31"),
            cause: super::ProviderFaultKind::UsageLimit,
        }]
    );
    let link = row();
    assert_eq!(link.phase, DelegationPhase::Ended);
    assert_eq!(link.refusals.len(), 2);
    assert_eq!(link.refusals[1].next, None);
    assert!(fixture
        .control
        .stops
        .lock()
        .expect("stops")
        .contains(&child.to_string()));
}

#[test]
fn missing_bridge_run_releases_ledger_and_stops_the_child() {
    let fixture = fixture_with(true, Ok(()), 2, false);
    let bridge_ledger = Arc::clone(&fixture.ledger);
    fixture.control.on_first_stop(Box::new(move || {
        assert!(
            bridge_ledger.try_lock().is_ok(),
            "child stop must run after the bridge ledger guard is released"
        );
    }));
    let failure = fixture
        .owner
        .create_task(request(&fixture))
        .expect_err("a child without its bridge run must fail setup");
    assert_eq!(failure.kind, "provisioning_failed");
    assert!(
        failure.detail.contains("without its required bridge run"),
        "{}",
        failure.detail
    );
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows.len(), 1, "the durable failed link remains as evidence");
    let row = &rows[0];
    assert_eq!(row.phase, DelegationPhase::Failed);
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[row.child.to_string()],
        "setup failure must stop the real opened child"
    );
    assert!(
        fixture.control.prompts.lock().expect("prompts").is_empty(),
        "the child is never prompted without a real bridge run"
    );
    let ledger = fixture.ledger.lock().expect("ledger lock");
    assert!(
        read_run(ledger.connection(), &row.child_run)
            .expect("child run lookup")
            .is_none(),
        "the owner must not fabricate a caller-lane child run"
    );
}

#[test]
fn a_seat_answering_an_ask_fans_out_one_level_and_its_workers_are_leaves() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let asked = fixture
        .owner
        .create_task(request(&fixture))
        .expect("the asked seat's session");
    let as_asked_seat = |session: &LiveSessionId, run: &RunId, half: &str| TaskCreateRequest {
        caller_session: SessionId::new(session.to_string()).expect("session"),
        caller_run: run.clone(),
        caller_seat: SeatId::new("seat.gungnir").expect("seat"),
        caller_lane: LaneId::new("lane.odin").expect("lane"),
        project: fixture.project.clone(),
        prompt: format!("implement the {half} half of the refactor"),
        title: None,
        target_seat: None,
        launch: None,
    };
    let first = fixture
        .owner
        .create_task(as_asked_seat(
            &asked.child_session,
            &asked.child_run,
            "first",
        ))
        .expect("a seat answering another seat's ask may delegate");
    let second = fixture
        .owner
        .create_task(as_asked_seat(
            &asked.child_session,
            &asked.child_run,
            "second",
        ))
        .expect("two parallel workers");
    assert_ne!(first.child_session, second.child_session);
    let rows = fixture
        .links
        .children_of(&SessionId::new(asked.child_session.to_string()).expect("session"))
        .expect("rows");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.depth == 2));
    let failure = fixture
        .owner
        .create_task(as_asked_seat(
            &first.child_session,
            &first.child_run,
            "third",
        ))
        .expect_err("a worker of the asked seat is a leaf");
    assert_eq!(failure.kind, "depth_exceeded");
}

#[test]
fn task_create_is_on_the_surface_exactly_where_the_law_lets_a_session_delegate() {
    use crate::host_tools::delegation::holds_task_create;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let sinmara = SeatId::new("sinmara").expect("seat");
    let gungnir = SeatId::new("gungnir").expect("seat");
    let asked = DelegationLink {
        parent_seat: Some(sinmara.clone()),
        model: "grok".to_owned(),
        ..sample_link(&fixture, "odin.task.create:surface")
    };
    assert!(
        holds_task_create(None, &sinmara),
        "a root session delegates"
    );
    assert!(
        holds_task_create(Some(&asked), &gungnir),
        "a seat answering another seat's ask fans out"
    );
    let worker = DelegationLink {
        parent_seat: Some(gungnir.clone()),
        depth: 2,
        ..asked.clone()
    };
    assert!(
        !holds_task_create(Some(&worker), &gungnir),
        "a worker is a leaf"
    );
    let same_seat = DelegationLink {
        parent_seat: Some(gungnir.clone()),
        ..asked.clone()
    };
    assert!(!holds_task_create(Some(&same_seat), &gungnir));
    let legacy = DelegationLink {
        parent_seat: None,
        ..asked
    };
    assert!(
        !holds_task_create(Some(&legacy), &gungnir),
        "an unattributed row is never guessed"
    );
}


#[test]
fn concurrency_ceiling_counts_only_live_workers() {
    let fixture = fixture_with(true, Ok(()), 1, true);
    fixture
        .owner
        .create_task(request(&fixture))
        .expect("first worker");
    let failure = fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect_err("second concurrent worker must fail");
    assert_eq!(failure.kind, "concurrency_ceiling");
    // Once the worker is observed inactive, the bound frees up.
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    fixture.control.set(&rows[0].child, false);
    fixture
        .owner
        .create_task(request_n(&fixture, 3))
        .expect("a worker observed inactive frees the bound");
}

#[test]
fn a_settled_worker_yields_its_place_to_a_new_delegation() {
    let fixture = fixture_with(true, Ok(()), 1, true);
    fixture
        .owner
        .create_task(request(&fixture))
        .expect("first worker");
    let child = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows")[0]
        .child;
    let idle_since = |ago_ms: u64| {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(
                child.to_string(),
                ChildLifecycleSnapshot {
                    active: true,
                    state: Some(odin_domain::huginn::LiveSessionState::Idle),
                    epoch: Some(1),
                    settled_since_ms: Some(GovernedTaskOwner::clock_ms() - ago_ms),
                    quiet_since_ms: None,
                    provider_fault: None,
                },
            );
    };
    // Just settled: its answer may not be relayed yet — it keeps its place.
    idle_since(5_000);
    assert_eq!(
        fixture
            .owner
            .create_task(request_n(&fixture, 2))
            .expect_err("a just-settled worker still counts")
            .kind,
        "concurrency_ceiling"
    );
    // Settled past the grace: it yields, and the new worker opens.
    idle_since(super::owner::SETTLED_CHILD_YIELD_MS + 1_000);
    fixture
        .owner
        .preflight_task(&request_n(&fixture, 2))
        .expect("the preflight sees the place a settled worker yields");
    fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect("a settled worker yields its place");
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    let yielded = rows.iter().find(|row| row.child == child).expect("old row");
    assert_eq!(yielded.phase, DelegationPhase::Ended);
    assert!(
        fixture
            .control
            .stops
            .lock()
            .expect("stops")
            .contains(&child.to_string()),
        "the yielded worker is stopped"
    );
}

#[test]
fn provisioning_failure_marks_the_row_failed_without_a_child() {
    let fixture = fixture_with(true, Err("pinned snapshot unavailable".to_owned()), 2, true);
    let failure = fixture
        .owner
        .create_task(request(&fixture))
        .expect_err("provisioning failure must fail honestly");
    assert_eq!(failure.kind, "provisioning_failed");
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows.len(), 1, "the durable row remains as evidence");
    assert_eq!(rows[0].phase, DelegationPhase::Failed);
    assert!(fixture.control.prompts.lock().expect("prompts").is_empty());
}

#[test]
fn read_is_parent_scoped_and_reports_real_lifecycle() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let report = fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child: receipt.child_session,
            screen: false,
        })
        .expect("report");
    assert_eq!(report.phase, DelegationPhase::Running);
    assert!(report.active);
    assert_eq!(report.model, "glm-flash");
    assert_eq!(
        report.screen, None,
        "the screen is read only when asked for"
    );
    let with_screen = fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child: receipt.child_session,
            screen: true,
        })
        .expect("report with the screen");
    assert_eq!(
        with_screen.screen,
        Some(format!("terminal of {}", receipt.child_session)),
        "the screen is the asked child's terminal"
    );
    let other = SessionId::new("00000000-0000-4000-8000-0000000000ff").expect("session");
    fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: other,
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child: receipt.child_session,
            screen: false,
        })
        .expect("a later session of the parent seat may read the child");
    let foreign = fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: SessionId::new("00000000-0000-4000-8000-0000000000fe")
                .expect("session"),
            caller_seat: SeatId::new("seat.other").expect("seat"),
            child: receipt.child_session,
            screen: false,
        })
        .expect_err("a different seat must not read the row");
    assert_eq!(foreign.kind, "child_not_owned");
    assert!(
        foreign.detail.contains("seat seat.architect") && foreign.detail.contains("seat.other"),
        "the refusal names the delegating seat and the caller: {}",
        foreign.detail
    );
}

#[test]
fn an_ancestor_seat_reads_its_grandchild_row() {
    use odin_domain::huginn::LiveSessionState;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let command = CommandId::new("odin.task.create:grandchild").expect("command");
    let grandchild = crate::live::supervisor::session_id_for(&command).expect("grandchild");
    let child_row = fixture.links.load(&child).expect("row").expect("child row");
    fixture
        .links
        .persist(&DelegationLink {
            child: grandchild,
            parent: SessionId::new(child.to_string()).expect("child session"),
            parent_seat: Some(SeatId::new("seat.gungnir").expect("seat")),
            child_run: GovernedTaskOwner::child_run_for(&grandchild).expect("run"),
            command,
            depth: 2,
            ..child_row
        })
        .expect("grandchild row");
    fixture.control.snapshots.lock().expect("snapshots").insert(
        grandchild.to_string(),
        ChildLifecycleSnapshot {
            active: false,
            state: Some(LiveSessionState::Ended),
            epoch: Some(1),
            settled_since_ms: None,
            quiet_since_ms: None,
            provider_fault: None,
        },
    );
    let read = |seat: &str| {
        fixture.owner.read_task(TaskReadRequest {
            caller_session: SessionId::new("00000000-0000-4000-8000-0000000000fd")
                .expect("session"),
            caller_seat: SeatId::new(seat).expect("seat"),
            child: grandchild,
            screen: false,
        })
    };
    let report = read("seat.architect").expect("the root seat reads its grandchild");
    assert_eq!(report.depth, 2);
    read("seat.gungnir").expect("the delegating seat reads its child");
    assert_eq!(
        read("seat.other").expect_err("an unrelated seat").kind,
        "child_not_owned"
    );
}

#[test]
fn task_read_bounds_presentation_without_cutting_settled_workload_answers() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let answer = format!("{}Citation(s): exact durable tail.", "文".repeat(8300));
    fixture
        .control
        .answers
        .lock()
        .expect("answers")
        .insert(receipt.child_session.to_string(), answer.clone());
    fixture.control.resting_pods.lock().expect("pods").push((
        receipt.child_session,
        "op-full-answer".to_owned(),
        WorkloadRest::Idle,
    ));
    let report = fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child: receipt.child_session,
            screen: false,
        })
        .expect("report");
    assert_eq!(
        report.answer,
        Some("文".repeat(super::vocabulary::TASK_READ_ANSWER_CHARS))
    );
    let pods = fixture
        .owner
        .settled_workloads()
        .expect("settled workloads");
    assert_eq!(pods.len(), 1);
    assert_eq!(pods[0].answer, answer);
    assert_eq!(
        pods[0].answer.chars().skip(8300).collect::<String>(),
        "Citation(s): exact durable tail."
    );
}

fn parent_live_session(fixture: &OwnerFixture) -> LiveSessionId {
    LiveSessionId::new(uuid::Uuid::parse_str(fixture.caller_session.as_str()).expect("parent uuid"))
        .expect("parent live session")
}

#[test]
fn parent_stop_requests_child_stop_and_marks_the_row_ended() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("bounded child stop");
    assert_eq!(records.len(), 1);
    assert!(records[0].stopped);
    assert_eq!(records[0].child, receipt.child_session);
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[receipt.child_session.to_string()],
        "the parent stop must initiate the child stop"
    );
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows[0].phase, DelegationPhase::Ended);
}

#[test]
fn parent_stop_fails_when_the_child_cannot_stop() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    fixture
        .control
        .fail_stop(&receipt.child_session, "bridge refused the stop");
    fixture.control.pin_active(&receipt.child_session);
    let error = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_millis(20))
        .expect_err("an unverified child must fail the parent stop");
    assert!(
        error.contains(&receipt.child_session.to_string()),
        "the failure must name the child: {error}"
    );
    assert!(error.contains("bridge refused the stop"));
    assert!(error.contains("did not stop within the bounded budget"));
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(
        rows[0].phase,
        DelegationPhase::Running,
        "an unverified child must stay running, not ended"
    );
    assert!(
        fixture.control.retires.lock().expect("retires").is_empty(),
        "a failed stop must keep the parent capsule registered"
    );
}

#[test]
fn parent_stop_retires_the_parent_capsule_after_children() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .owner
        .create_task(request(&fixture))
        .expect("worker");
    fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("bounded child stop");
    assert_eq!(
        fixture.control.retires.lock().expect("retires").as_slice(),
        &[fixture.caller_session.to_string()],
        "the stopping session retires its own capsule after the children"
    );
}

/// A task review that records, per review, whether the root's capsule had already
/// retired: a review is a model call, so it must never run inside the stop deadline.
struct RecordingReview {
    control: Arc<FakeControl>,
    parent: String,
    reviewed: Mutex<Vec<(LiveSessionId, u64, bool)>>,
}

impl TaskLearningCapture for RecordingReview {
    fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
        let retired = self
            .control
            .retires
            .lock()
            .expect("retires")
            .contains(&self.parent);
        self.reviewed.lock().expect("reviewed").push((
            facts.child,
            facts.result.event_sequence,
            retired,
        ));
        Ok(())
    }
}

fn review_owner(fixture: &OwnerFixture) -> (Arc<GovernedTaskOwner>, Arc<RecordingReview>) {
    let review = Arc::new(RecordingReview {
        control: fixture.control.clone(),
        parent: fixture.caller_session.to_string(),
        reviewed: Mutex::new(Vec::new()),
    });
    let owner = GovernedTaskOwner::new(
        fixture.provisioner.clone(),
        fixture.control.clone(),
        fixture.links.clone(),
        fixture.ledger.clone(),
        fixture.governance.clone(),
    )
    .with_learning(Some(Arc::clone(&review) as Arc<dyn TaskLearningCapture>));
    (Arc::new(owner), review)
}

/// A seat answering the root's ask creates its own worker: the supported
/// depth-two leaf.
fn asked_seat_request(fixture: &OwnerFixture, asked: &TaskCreateReceipt) -> TaskCreateRequest {
    TaskCreateRequest {
        caller_session: SessionId::new(asked.child_session.to_string()).expect("session"),
        caller_run: asked.child_run.clone(),
        caller_seat: SeatId::new("seat.gungnir").expect("seat"),
        caller_lane: LaneId::new("lane.odin").expect("lane"),
        project: fixture.project.clone(),
        prompt: "implement the leaf half of the refactor".to_owned(),
        title: None,
        target_seat: None,
        launch: None,
    }
}

fn assert_captured(fixture: &OwnerFixture, child: LiveSessionId, sequence: u64) {
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_capture_sequence, Some(sequence));
}

/// A synchronous review must not consume the parent's capsule-retirement
/// deadline; the stopped child's result must still be captured afterward.
#[test]
fn a_child_review_runs_only_after_the_parent_capsule_retired() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = review_owner(&fixture);
    let child = owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    install_completion_result(&fixture, child, 39);
    let records = owner
        .await_children_on_stop(parent_live_session(&fixture), STOP_BUDGET)
        .expect("the parent capsule retires within its stop deadline");
    assert_eq!(records.len(), 1);
    assert!(records[0].stopped);
    assert_eq!(
        fixture.control.retires.lock().expect("retires").as_slice(),
        &[fixture.caller_session.to_string()]
    );
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(child, 39, true)],
        "the stopped child is reviewed once, after the parent capsule retired"
    );
    assert_captured(&fixture, child, 39);
}

/// Results arriving during a stop update the marker but wait for review until the stop finishes.
#[test]
fn a_result_landing_during_a_stop_waits_for_the_root_proof() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, review) = review_owner(&fixture);
    let asked = owner
        .create_task(request(&fixture))
        .expect("the asked seat's session");
    let leaf = owner
        .create_task(asked_seat_request(&fixture, &asked))
        .expect("its worker")
        .child_session;
    install_completion_result(&fixture, leaf, 39);
    let weak = Arc::downgrade(&owner);
    let links = fixture.links.clone();
    let control = Arc::downgrade(&fixture.control);
    let asked_session = asked.child_session;
    let bridge: ChildBridgeStop = Arc::new(move |child: LiveSessionId| -> Result<(), String> {
        let owner = weak
            .upgrade()
            .ok_or_else(|| "the stop coordinator is gone".to_owned())?;
        owner
            .await_children_on_stop(child, Duration::from_secs(5))
            .map(|_| ())?;
        if child == asked_session {
            // The leaf is Ended; its newer result lands before the asked
            // seat's stop answers the root.
            let control = control
                .upgrade()
                .ok_or_else(|| "the fixture control is gone".to_owned())?;
            control.results.lock().expect("results").insert(
                leaf.to_string(),
                TaskResultReport {
                    summary: Some("result 54: the leaf's final report".to_owned()),
                    artifacts: Vec::new(),
                    event_sequence: 54,
                },
            );
            owner.result_persisted(leaf, 54);
            let row = links.load(&leaf).expect("load").expect("row");
            assert_eq!(row.phase, DelegationPhase::Ended);
            assert_eq!(row.learning_result_sequence, Some(54));
            assert_eq!(
                row.learning_capture_sequence, None,
                "a deferred result never reads as captured"
            );
        }
        Ok(())
    });
    *fixture
        .control
        .child_bridge_stop
        .lock()
        .expect("child bridge stop lock") = Some(bridge);
    owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(5))
        .expect("bounded stop");
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(leaf, 54, true)],
        "the leaf is reviewed once, at its newest result, after the root retired"
    );
    assert_captured(&fixture, leaf, 54);
}

#[test]
fn overlapping_stops_of_one_session_review_only_after_the_last_proof() {
    use std::sync::mpsc;
    type Proof = std::thread::JoinHandle<Result<Vec<ChildStopRecord>, String>>;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = review_owner(&fixture);
    let child = owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    install_completion_result(&fixture, child, 39);
    let root = parent_live_session(&fixture);
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    let entered_rx = Mutex::new(entered_rx);
    let release_rx = Mutex::new(release_rx);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let second: Arc<Mutex<Option<Proof>>> = Arc::new(Mutex::new(None));
    let spawned = Arc::clone(&second);
    let weak = Arc::downgrade(&owner);
    let bridge: ChildBridgeStop = Arc::new(move |_child: LiveSessionId| -> Result<(), String> {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            // Start an overlapping stop before the first child's stop returns.
            let owner = weak
                .upgrade()
                .ok_or_else(|| "the stop coordinator is gone".to_owned())?;
            *spawned.lock().expect("second proof") = Some(std::thread::spawn(move || {
                owner.await_children_on_stop(root, Duration::from_secs(5))
            }));
            entered_rx
                .lock()
                .expect("entered")
                .recv()
                .map_err(|error| error.to_string())?;
        } else {
            // Keep the second stop open until released.
            entered_tx
                .lock()
                .expect("entered")
                .send(())
                .map_err(|error| error.to_string())?;
            release_rx
                .lock()
                .expect("release")
                .recv()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    *fixture
        .control
        .child_bridge_stop
        .lock()
        .expect("child bridge stop lock") = Some(bridge);
    owner
        .await_children_on_stop(root, Duration::from_secs(5))
        .expect("the first proof");
    assert!(
        review.reviewed.lock().expect("reviewed").is_empty(),
        "no review while the second proof of the root is still open"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_result_sequence, Some(39));
    assert_eq!(row.learning_capture_sequence, None);
    release_tx.send(()).expect("release the second proof");
    second
        .lock()
        .expect("second proof")
        .take()
        .expect("the second proof started")
        .join()
        .expect("the second proof returns")
        .expect("the second proof");
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(child, 39, true)]
    );
    assert_captured(&fixture, child, 39);
}

#[test]
fn prompt_failure_stops_the_opened_child_and_keeps_the_row_terminal() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .control
        .fail_next_prompt("bridge rejected the prompt");
    let failure = fixture
        .owner
        .create_task(request(&fixture))
        .expect_err("a failed prompt must fail the delegation honestly");
    assert_eq!(failure.kind, "prompt_failed");
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].phase, DelegationPhase::Failed);
    assert!(!fixture.control.snapshot(rows[0].child).unwrap().active);
}

/// A resting worker is Idle and refuses a FollowUp: its report review turn
/// must arrive as a Prompt, or settlement can never start and the report
/// dies with the pod. The page images ride the turn either way.
#[test]
fn a_resting_worker_receives_its_report_review_as_a_prompt() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("worker");
    // The worker finished its turn: its bridge is up and it rests Idle.
    fixture.control.set_state(
        &child.child_session,
        odin_domain::huginn::LiveSessionState::Idle,
    );
    fixture
        .owner
        .follow_up_with_images(
            child.child_session,
            "Review pages 1-2 of /export/report.pdf.",
            &[("image/jpeg".to_owned(), "cGFnZQ==".to_owned())],
        )
        .expect("the review turn starts on a resting worker");
    let commands = fixture.control.commands.lock().expect("command log");
    assert_eq!(
        commands.last().map(String::as_str),
        Some("Prompt"),
        "an idle worker takes the review as a Prompt, not a refused FollowUp"
    );
    drop(commands);
    let prompted = fixture.control.prompted.lock().expect("prompted log");
    let text = prompted.last().expect("the review turn was recorded");
    assert!(
        text.contains("Review pages 1-2"),
        "the review text rides the turn: {text}"
    );
    assert!(
        text.contains("image/jpeg"),
        "the page images ride the turn: {text}"
    );
}

#[test]
fn unbound_task_owner_slot_fails_every_owner_path_closed() {
    let slot = Arc::new(TaskOwnerSlot::new());
    assert!(
        !slot.is_bound().expect("slot binding state reads"),
        "a fresh slot is unbound"
    );
    let error = match slot.owner() {
        Ok(_) => panic!("an unbound slot yields no owner"),
        Err(error) => error,
    };
    assert!(
        matches!(error, HostToolError::Catalog { ref detail }
                    if detail.contains("task owner is not bound")),
        "unexpected owner-path outcome: {error:?}"
    );
}

/// Records the real capture boundary, including the durable stop ordering.
struct VerifiedStopCapture {
    links: DelegationLinkLedger,
    control: Arc<FakeControl>,
    attempts: Mutex<Vec<(LiveSessionId, u64)>>,
    reviewed: Mutex<Vec<(LiveSessionId, u64)>>,
    fail: std::sync::atomic::AtomicBool,
}

impl TaskLearningCapture for VerifiedStopCapture {
    fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
        let row = self.links.load(&facts.child)?.expect("capture row");
        assert_eq!(
            row.phase,
            DelegationPhase::Ended,
            "Ended must be durable first"
        );
        assert!(
            !self.control.snapshot(facts.child)?.active,
            "teardown must finish first"
        );
        assert_eq!(facts.parent_session, row.parent);
        assert_eq!(Some(&facts.parent_seat), row.parent_seat.as_ref());
        assert_eq!(
            row.learning_result_sequence,
            Some(facts.result.event_sequence)
        );
        let identity = (facts.child, facts.result.event_sequence);
        self.attempts.lock().expect("attempts").push(identity);
        if self.fail.load(Ordering::SeqCst) {
            return Err("review registration unavailable".to_owned());
        }
        self.reviewed.lock().expect("reviewed").push(identity);
        Ok(())
    }
}

fn completion_owner(
    fixture: &OwnerFixture,
    capture: &Arc<VerifiedStopCapture>,
) -> Arc<GovernedTaskOwner> {
    Arc::new(
        GovernedTaskOwner::new(
            fixture.provisioner.clone(),
            fixture.control.clone(),
            fixture.links.clone(),
            fixture.ledger.clone(),
            fixture.governance.clone(),
        )
        .with_learning(Some(Arc::clone(capture) as Arc<dyn TaskLearningCapture>)),
    )
}

fn verified_stop_capture(fixture: &OwnerFixture) -> Arc<VerifiedStopCapture> {
    Arc::new(VerifiedStopCapture {
        links: fixture.links.clone(),
        control: fixture.control.clone(),
        attempts: Mutex::new(Vec::new()),
        reviewed: Mutex::new(Vec::new()),
        fail: std::sync::atomic::AtomicBool::new(false),
    })
}

fn install_completion_result(fixture: &OwnerFixture, child: LiveSessionId, sequence: u64) {
    fixture.control.results.lock().expect("results").insert(
        child.to_string(),
        TaskResultReport {
            summary: Some(format!(
                "result {sequence}: implementation and merge reported complete"
            )),
            artifacts: vec![format!("artifact-{sequence}")],
            event_sequence: sequence,
        },
    );
}

fn completion_control(
    fixture: &OwnerFixture,
    child: LiveSessionId,
    control: TaskControl,
) -> TaskControlRequest {
    TaskControlRequest {
        caller_session: fixture.caller_session.clone(),
        caller_seat: request(fixture).caller_seat,
        child,
        control,
    }
}

#[test]
fn running_idle_results_need_verified_explicit_stop_before_latest_capture() {
    use odin_domain::huginn::LiveSessionState as State;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    fixture.control.set_state(&child, State::Idle);
    install_completion_result(&fixture, child, 39);
    owner.result_persisted(child, 39);
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.learning_result_sequence, Some(39));
    assert_eq!(row.learning_capture_sequence, None);
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    assert!(fixture.control.stops.lock().expect("stops").is_empty());
    owner
        .control_task(completion_control(
            &fixture,
            child,
            TaskControl::Steer("address the remaining review".to_owned()),
        ))
        .expect("an idle answer remains resumable");
    assert_eq!(
        fixture.control.snapshot(child).expect("snapshot").state,
        Some(State::Running)
    );
    fixture.control.set_state(&child, State::Idle);
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    owner.result_persisted(child, 39);
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    let links = fixture.links.clone();
    let pending = capture.clone();
    fixture.control.on_first_stop(Box::new(move || {
        let row = links.load(&child).expect("load during stop").expect("row");
        assert_eq!(row.phase, DelegationPhase::Running);
        assert_eq!(row.learning_result_sequence, Some(54));
        assert_eq!(row.learning_capture_sequence, None);
        assert!(pending.attempts.lock().expect("attempts").is_empty());
    }));
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("verified stop");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_capture_sequence, Some(54));
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("duplicate stop");
    owner.result_persisted(child, 39);
    owner.result_persisted(child, 54);
    owner
        .capture_pending_completion(&child)
        .expect("duplicate scan");
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        [child.to_string()]
    );
}

#[test]
fn stale_lifecycle_row_cannot_resurrect_stopped_child_or_erase_capture_identity() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    install_completion_result(&fixture, child, 39);
    owner.result_persisted(child, 39);
    let stale = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(stale.phase, DelegationPhase::Running);
    assert_eq!(stale.learning_capture_sequence, None);
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("stop");
    fixture.links.persist(&stale).expect("late lifecycle write");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_result_sequence, Some(54));
    assert_eq!(row.learning_capture_sequence, Some(54));
    owner.capture_pending_completion(&child).expect("rescan");
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
}

/// Missing results stay pending; read-only proposal IDs disappear on rewrite.
#[test]
fn completion_capture_is_durable_idempotent_and_observer_driven() {
    use crate::host_tools::delegation::CompletionEventObserver;

    struct RecordingCapture {
        reviewed: Mutex<Vec<u64>>,
    }
    impl crate::host_tools::delegation::TaskLearningCapture for RecordingCapture {
        fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
            self.reviewed
                .lock()
                .expect("reviewed lock")
                .push(facts.result.event_sequence);
            Ok(())
        }
    }

    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = Arc::new(RecordingCapture {
        reviewed: Mutex::new(Vec::new()),
    });
    let owner = Arc::new(
        GovernedTaskOwner::new(
            fixture.provisioner.clone(),
            fixture.control.clone(),
            fixture.links.clone(),
            fixture.ledger.clone(),
            fixture.governance.clone(),
        )
        .with_learning(Some(Arc::clone(&capture) as Arc<dyn TaskLearningCapture>)),
    );
    let receipt = owner.create_task(request(&fixture)).expect("create");

    // The child published a typed result; the row is marked Ended without
    // anyone ever calling task.read (no-read completion path).
    let result = TaskResultReport {
        summary: Some("implemented the change; checks pass".to_owned()),
        artifacts: vec!["artifact-alpha".to_owned()],
        event_sequence: 7,
    };
    fixture
        .control
        .results
        .lock()
        .expect("results lock")
        .insert(receipt.child_session.to_string(), result.clone());
    let mut link = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    link.phase = DelegationPhase::Ended;
    fixture.links.persist(&link).expect("persist");

    // The completion-event observer — the production caller wired into
    // the live session actor — captures WITHOUT task.read or parent stop,
    // and durably annotates the row with the result sequence first.
    owner.result_persisted(receipt.child_session, result.event_sequence);
    assert!(
        futures_util::FutureExt::now_or_never(owner.result_wake().notified()).is_some(),
        "a durable result wakes the report pump at once"
    );
    let row = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    assert_eq!(
        row.learning_capture_sequence,
        Some(result.event_sequence),
        "the capture persisted its exact result sequence"
    );
    owner.result_persisted(receipt.child_session, result.event_sequence);
    owner
        .capture_pending_completion(&receipt.child_session)
        .expect("repeat scan");
    assert_eq!(
        *capture.reviewed.lock().expect("reviewed lock"),
        vec![result.event_sequence],
        "one typed result is reviewed exactly once"
    );
}

#[test]
fn preflight_refuses_missing_surface_before_any_effect() {
    let fixture = fixture_with_preflight(
        true,
        Ok(()),
        Err("zellij_session brain-m6b was not found".to_owned()),
        2,
        true,
    );
    let failure = fixture
        .owner
        .preflight_task(&request(&fixture))
        .expect_err("a missing declared surface refuses at preflight");
    assert_eq!(failure.kind, "surface_unavailable");
    assert!(
        failure.detail.contains("not found"),
        "the readiness refusal names the missing surface: {}",
        failure.detail
    );
    assert!(
        !failure.effect_may_have_started,
        "a preflight refusal is provably pre-effect"
    );
    // The readiness observation ran, and no mutating provision path did.
    assert!(!fixture
        .recording
        .preflight_calls
        .lock()
        .expect("preflight calls")
        .is_empty());
    assert!(
        fixture
            .recording
            .calls
            .lock()
            .expect("provision calls")
            .is_empty(),
        "preflight never provisions: the executed provision path never ran"
    );
    assert!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .is_empty(),
        "preflight persists no link row"
    );
    assert!(
        fixture.control.prompts.lock().expect("prompts").is_empty(),
        "preflight dispatches no prompt"
    );
}

/// Preflight on a ready surface observes and consumes nothing; the executed
/// create then follows the normal single path (one row, one provision, one
/// prompt).
#[test]
fn preflight_ready_observes_then_execution_consumes_once() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .owner
        .preflight_task(&request(&fixture))
        .expect("ready surface passes preflight");
    assert!(
        fixture
            .recording
            .calls
            .lock()
            .expect("provision calls")
            .is_empty(),
        "a passing preflight still never provisions"
    );
    assert!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .is_empty(),
        "a passing preflight persists no link row and reserves no slot"
    );
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("execution follows the normal path");
    assert_eq!(
        fixture
            .recording
            .calls
            .lock()
            .expect("provision calls")
            .len(),
        1,
        "exactly one provisioning act consumed the dispatch"
    );
    assert_eq!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .len(),
        1
    );
    assert_eq!(
        fixture.control.prompts.lock().expect("prompts").len(),
        1,
        "exactly one prompt is dispatched"
    );
    assert_eq!(
        receipt.prompt_bytes,
        fixture.control.prompts.lock().expect("prompts")[0].len()
    );
}

#[test]
fn preflight_binding_laws_refuse_before_readiness() {
    // Parent plan missing.
    let fixture = fixture_with(false, Ok(()), 2, true);
    let failure = fixture
        .owner
        .preflight_task(&request(&fixture))
        .expect_err("no accepted plan refuses");
    assert_eq!(failure.kind, "plan_not_accepted");
    // Preflight measures the same prompt bytes as execution.
    let fixture = fixture_with(true, Ok(()), 2, true);
    let mut oversized = request(&fixture);
    oversized.prompt = "x".repeat(8_192);
    let failure = fixture
        .owner
        .preflight_task(&oversized)
        .expect_err("an oversized prompt refuses");
    assert_eq!(failure.kind, "prompt_too_large");
    // Project scope.
    let mut foreign = request(&fixture);
    foreign.project = ProjectId::new("project.foreign").expect("project id");
    let failure = fixture
        .owner
        .preflight_task(&foreign)
        .expect_err("an out-of-scope project refuses");
    assert_eq!(failure.kind, "project_out_of_scope");
    // Cross-seat target equal to the caller.
    let mut self_target = request(&fixture);
    self_target.target_seat = Some(SeatId::new("seat.architect").expect("seat"));
    let failure = fixture
        .owner
        .preflight_task(&self_target)
        .expect_err("the caller's own seat is not a cross-seat target");
    assert_eq!(failure.kind, "target_seat_invalid");
    assert!(
        fixture
            .recording
            .preflight_calls
            .lock()
            .expect("preflight calls")
            .is_empty(),
        "binding laws refuse before the readiness observation runs"
    );
}

#[test]
fn a_parent_pauses_steers_and_resumes_its_worker() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    use odin_domain::huginn::LiveSessionState as State;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let parent_seat = request(&fixture).caller_seat;
    let control = |control: TaskControl| {
        fixture.owner.control_task(TaskControlRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: parent_seat.clone(),
            child,
            control,
        })
    };
    let commands = || fixture.control.commands.lock().expect("commands").clone();

    fixture.control.set_state(&child, State::Running);
    let paused = control(TaskControl::Pause).expect("pause");
    assert_eq!(paused.applied, ["Pause"]);
    assert_eq!(
        control(TaskControl::Pause).expect("again").applied,
        Vec::<String>::new()
    );

    let steered = control(TaskControl::Steer("use GMRES instead".to_owned())).expect("steer");
    assert_eq!(steered.before, "Detached");
    assert_eq!(steered.applied, ["Resume", "Prompt"]);
    assert_eq!(commands(), ["Pause", "Resume", "Prompt"]);

    // Working again: a steer lands mid-turn.
    assert_eq!(
        control(TaskControl::Steer("and log residuals".to_owned()))
            .expect("mid-turn")
            .applied,
        ["Steer"]
    );
    let refused = control(TaskControl::Resume).unwrap_err();
    assert_eq!(refused.kind, "not_applicable", "{refused:?}");

    // Another seat gains control only after the worker escalates to it.
    let coordinator = odin_domain::SeatId::new("coordinator-fixture").expect("seat");
    let from_coordinator = |control: TaskControl| {
        fixture.owner.control_task(TaskControlRequest {
            caller_session: odin_domain::SessionId::new("00000000-0000-4000-8000-0000000000aa")
                .expect("session"),
            caller_seat: coordinator.clone(),
            child,
            control,
        })
    };
    let stranger = from_coordinator(TaskControl::Pause).unwrap_err();
    assert_eq!(stranger.kind, "not_the_parent");
    assert_eq!(
        commands(),
        ["Pause", "Resume", "Prompt", "Steer"],
        "nothing more applied"
    );
    fixture
        .owner
        .escalate_task(child, coordinator.clone())
        .expect("escalation recorded");
    assert_eq!(
        from_coordinator(TaskControl::Steer("the owner chose option 2".to_owned()))
            .expect("the escalation target answers")
            .applied,
        ["Steer"]
    );
}

/// A parent types into a harness session it opened and ends it. A slash
/// command reaches the harness verbatim rather than wrapped in an
/// instruction, and stop closes the child for good.
#[test]
fn a_parent_types_slash_commands_verbatim_and_stops_its_worker() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    use odin_domain::huginn::LiveSessionState as State;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let control = |control: TaskControl| {
        owner.control_task(TaskControlRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: request(&fixture).caller_seat,
            child,
            control,
        })
    };
    fixture.control.set_state(&child, State::Idle);
    control(TaskControl::Steer("/clear".to_owned())).expect("slash command");
    fixture.control.set_state(&child, State::Idle);
    control(TaskControl::Steer("now add a test".to_owned())).expect("instruction");
    let prompted = fixture.control.prompted.lock().expect("prompted").clone();
    assert!(
        prompted[0].contains("\"/clear\"") && !prompted[0].contains("Change of plan"),
        "{prompted:?}"
    );
    assert!(prompted[1].contains("Change of plan"), "{prompted:?}");
    fixture.control.set_state(&child, State::Idle);
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    assert!(capture.reviewed.lock().expect("reviewed").is_empty());

    let stopped = control(TaskControl::Stop).expect("stop");
    assert_eq!(stopped.applied, ["Stop"]);
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        [child.to_string()]
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_capture_sequence, Some(54));
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
}

/// A seat ask names one of the target seat's declared launch options for
/// this delegation only; the same-seat worker route takes no launch choice.
#[test]
fn a_launch_choice_opens_the_child_on_that_option_only_for_this_delegation() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let terminal = super::WorkerLane {
        provider: "fixture-cli".to_owned(),
        model: "fixture-model".to_owned(),
    };
    let mut asked = request(&fixture);
    asked.target_seat = Some(SeatId::new("seat.gungnir").expect("seat"));
    asked.launch = Some(terminal.clone());
    let receipt = fixture.owner.create_task(asked).expect("cross-seat ask");
    assert_eq!(
        (receipt.provider.as_str(), receipt.model.as_str()),
        ("fixture-cli", "fixture-model")
    );
    let mut same_seat = request(&fixture);
    same_seat.launch = Some(terminal);
    assert_eq!(
        fixture
            .owner
            .create_task(same_seat)
            .expect_err("the same-seat route runs the configured worker")
            .kind,
        "launch_invalid"
    );
}

/// The detector behind the provider-stall rung: only OMP's "stream stalled"
/// error ending the latest turn counts; a later prompt or answer clears it.
#[test]
fn only_a_stream_stall_ending_the_latest_turn_marks_it_stalled() {
    use odin_domain::huginn::{
        EventSeq, LiveContentBlock, LiveEvent, LiveEventBody, LiveMessage, SessionEpoch,
        SessionError,
    };
    use odin_domain::EventId;
    let session = odin_domain::huginn::LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9")
        .expect("session id");
    let event = |sequence: u64, body: LiveEventBody| {
        LiveEvent::new(
            1,
            EventId::new(format!("event:{sequence}")).expect("event id"),
            session,
            SessionEpoch::new(1),
            EventSeq::new(sequence),
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time"),
            body,
        )
        .expect("event")
    };
    let message =
        || LiveMessage::new(vec![LiveContentBlock::Text("go on".to_owned())]).expect("message");
    let error = |message: &str| {
        LiveEventBody::Error(SessionError {
            code: "provider_turn_error".to_owned(),
            message: message.to_owned(),
            retryable: false,
            error_status: None,
        })
    };
    let stalled = error("OpenAI completions stream stalled while waiting for the next event");
    let fault = |events: &[LiveEvent]| {
        super::provider_turn_fault(events).map(|fault| (fault.event, fault.kind))
    };
    use super::ProviderFaultKind::{ContextOverflow, RejectedKey, Stall, UsageLimit};
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(2, stalled.clone())
        ]),
        Some((2, Stall))
    );
    assert_eq!(
        fault(&[
            event(1, stalled.clone()),
            event(2, LiveEventBody::UserMessage(message()))
        ]),
        None,
        "a resumed turn is not stalled"
    );
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(
                2,
                error("401 litellm.AuthenticationError: Incorrect API key provided")
            )
        ]),
        Some((2, RejectedKey)),
        "a rejected key is a refusal, not a stall"
    );
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(2, error("429 litellm.RateLimitError: insufficient_quota"))
        ]),
        Some((2, UsageLimit))
    );
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(2, error("500 internal server error"))
        ]),
        None,
        "an outage is not answered by a lane change"
    );
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(
                2,
                error(
                    "500 litellm.APIConnectionError: APIConnectionError: OpenAIException - \
                     Context size has been exceeded."
                )
            )
        ]),
        Some((2, ContextOverflow)),
        "a request over the model's window is never re-sent to that lane"
    );
    assert!(ContextOverflow.refuses_lane());
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(
                2,
                LiveEventBody::Error(SessionError {
                    code: "context_refusal.window_exceeded".to_owned(),
                    message: "request requires 44540 byte tokens, exceeding the declared \
                              window 32768"
                        .to_owned(),
                    retryable: true,
                    error_status: None,
                })
            )
        ]),
        Some((2, ContextOverflow)),
        "an extension context refusal is a lane refusal, not silence"
    );
    assert_eq!(
        fault(&[
            event(1, LiveEventBody::UserMessage(message())),
            event(
                2,
                LiveEventBody::Error(SessionError {
                    code: "context_refusal.model_identity_mismatch".to_owned(),
                    message: "the resolved model carries tokenizer unresolved".to_owned(),
                    retryable: false,
                    error_status: None,
                })
            )
        ]),
        Some((2, super::ProviderFaultKind::ContextGuard)),
        "every authenticated context refusal is answered"
    );
    assert!(super::ProviderFaultKind::ContextGuard.refuses_lane());
}

#[test]
fn a_child_failed_on_a_context_refusal_rolls_a_fresh_incarnation_and_the_task_continues() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = gateway_lane;
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("glm-flash"), lane("kimi-k31")];
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let failed_on_refusal = |epoch: i64| ChildLifecycleSnapshot {
        active: true,
        state: Some(odin_domain::huginn::LiveSessionState::Failed),
        epoch: Some(epoch),
        settled_since_ms: None,
        quiet_since_ms: None,
        provider_fault: Some(super::ProviderTurnFault {
            event: 15,
            kind: super::ProviderFaultKind::ContextOverflow,
            origin: super::ProviderFaultOrigin::ContextRefusal,
        }),
    };
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(child.to_string(), failed_on_refusal(1));
    let pass = fixture
        .owner
        .recover_stalled_children(std::time::Duration::from_secs(300))
        .expect("pass");
    assert!(pass.refused.is_empty(), "the parent is not told of an end");
    assert!(pass.ended.is_empty() && pass.switched.is_empty());
    assert!(
        fixture.control.stops.lock().expect("stops").is_empty(),
        "a rolled child is not stopped"
    );
    assert_eq!(
        *fixture.control.rollover_calls.lock().expect("rollover"),
        vec![(child.to_string(), 15)],
        "exactly one fresh incarnation answers the refusal event"
    );
    let row = fixture.links.load(&child).expect("row").expect("link");
    assert_eq!(row.phase, DelegationPhase::Running, "one task continues");
    assert_eq!(row.handled_stall_event, Some(15));
    assert_eq!(
        row.refusals,
        vec![super::LaneRefusal {
            lane: "gateway/glm-flash".to_owned(),
            cause: "context_overflow".to_owned(),
            event: 15,
            next: Some("gateway/glm-flash".to_owned()),
        }],
        "the same lane carries the rollover lineage"
    );
    assert!(fixture
        .control
        .commands
        .lock()
        .expect("commands")
        .iter()
        .all(|command| !command.contains("SetModel")));
    // A fresh incarnation that reports the SAME refusal event again is
    // answered once (the durable handled-event guard), never rolled into a
    // loop.
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(child.to_string(), failed_on_refusal(2));
    let pass = fixture
        .owner
        .recover_stalled_children(std::time::Duration::from_secs(300))
        .expect("pass");
    assert_eq!(
        fixture
            .control
            .rollover_calls
            .lock()
            .expect("rollover")
            .len(),
        1,
        "one refusal event is answered once"
    );
    assert!(pass.refused.is_empty() && pass.ended.is_empty() && pass.failures.is_empty());
}

#[test]
fn a_third_distinct_context_overflow_ends_the_child_and_its_parent_is_told() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = super::WorkerLane {
        provider: "gateway".to_owned(),
        model: "glm-flash".to_owned(),
    };
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let failed_on_refusal = |epoch: i64, event: u64| ChildLifecycleSnapshot {
        active: true,
        state: Some(odin_domain::huginn::LiveSessionState::Failed),
        epoch: Some(epoch),
        settled_since_ms: None,
        quiet_since_ms: None,
        provider_fault: Some(super::ProviderTurnFault {
            event,
            kind: super::ProviderFaultKind::ContextOverflow,
            origin: super::ProviderFaultOrigin::ContextRefusal,
        }),
    };
    for (epoch, event) in [(1, 11), (2, 12)] {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(child.to_string(), failed_on_refusal(epoch, event));
        let pass = fixture
            .owner
            .recover_stalled_children(std::time::Duration::from_secs(300))
            .expect("pass");
        assert!(
            pass.refused.is_empty() && pass.ended.is_empty(),
            "rolls over"
        );
        let row = fixture.links.load(&child).expect("row").expect("link");
        assert_eq!(row.phase, DelegationPhase::Running, "the task continues");
    }
    assert_eq!(
        *fixture.control.rollover_calls.lock().expect("rollover"),
        vec![(child.to_string(), 11), (child.to_string(), 12)],
        "two admissions across two distinct events and epochs"
    );
    // The fresh incarnation of the SECOND admission overflows again: the
    // budget is spent, so no third respawn happens.
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(child.to_string(), failed_on_refusal(3, 13));
    let pass = fixture
        .owner
        .recover_stalled_children(std::time::Duration::from_secs(300))
        .expect("pass");
    assert_eq!(
        fixture
            .control
            .rollover_calls
            .lock()
            .expect("rollover")
            .len(),
        2,
        "the spent budget admits no third rollover"
    );
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        vec![child.to_string()],
        "the child is verifiably stopped"
    );
    assert_eq!(pass.refused.len(), 1, "its parent is told, typed");
    assert_eq!(pass.refused[0].child, child);
    assert_eq!(
        pass.refused[0].cause,
        super::ProviderFaultKind::ContextOverflow
    );
    let row = fixture.links.load(&child).expect("row").expect("link");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.rollover_admissions, 2, "the spent budget is durable");
    let lineage: Vec<(u64, Option<String>)> = row
        .refusals
        .iter()
        .map(|refusal| (refusal.event, refusal.next.clone()))
        .collect();
    assert_eq!(
        lineage,
        vec![
            (11, Some(lane.to_string())),
            (12, Some(lane.to_string())),
            (13, None),
        ],
        "the exhausting event is durable lineage with no successor lane"
    );
}

#[test]
fn asking_again_while_the_worker_is_on_it_replays_its_receipt() {
    let fixture = fixture_with(true, Ok(()), 3, true);
    let first = fixture.owner.create_task(request(&fixture)).expect("first");
    fixture.control.set_state(
        &first.child_session,
        odin_domain::huginn::LiveSessionState::Running,
    );
    let again = fixture.owner.create_task(request(&fixture)).expect("again");
    assert_eq!(again.child_session, first.child_session);
    assert_eq!(again.command_id, first.command_id);
    assert_eq!(fixture.recording.calls.lock().expect("calls").len(), 1);
    fixture.control.set_state(
        &first.child_session,
        odin_domain::huginn::LiveSessionState::Idle,
    );
    let replayed = fixture
        .owner
        .create_task(request(&fixture))
        .expect("idle before any result");
    assert_eq!(
        replayed.child_session, first.child_session,
        "an idle child with no result yet has not taken its prompt"
    );
    let mut row = fixture
        .links
        .load(&first.child_session)
        .expect("load")
        .expect("row");
    row.learning_result_sequence = Some(7);
    fixture.links.persist(&row).expect("persist");
    let fresh = fixture.owner.create_task(request(&fixture)).expect("fresh");
    assert_ne!(fresh.child_session, first.child_session);
    assert_eq!(fixture.recording.calls.lock().expect("calls").len(), 2);
}

#[test]
fn a_worker_parent_hears_each_settled_child_turn_once() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let child = receipt.child_session;
    let parent = parent_live_session(&fixture);
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .set_state(&parent, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .answers
        .lock()
        .expect("answer lock")
        .insert(child.to_string(), "Verdict: approve.".to_owned());
    let architect = SeatId::new("seat.architect").expect("seat");
    assert!(
        fixture
            .owner
            .report_to_worker_parents(&architect, u64::MAX)
            .expect("scan")
            .is_empty(),
        "the conversation seat's children are its wakes' to report"
    );
    let sinmara = SeatId::new("sinmara").expect("seat");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&sinmara, u64::MAX)
            .expect("scan"),
        vec![child]
    );
    let prompted = fixture.control.prompted.lock().expect("prompted").clone();
    assert_eq!(prompted.len(), 1);
    assert!(prompted[0].contains("Verdict: approve."), "{prompted:?}");
    assert!(fixture.control.stops.lock().expect("stops").is_empty());
    assert_eq!(
        fixture
            .links
            .load(&child)
            .expect("load")
            .expect("row")
            .phase,
        DelegationPhase::Running
    );
    assert!(fixture.control.snapshot(child).expect("snapshot").active);
    fixture
        .control
        .set_state(&parent, odin_domain::huginn::LiveSessionState::Idle);
    assert!(
        fixture
            .owner
            .report_to_worker_parents(&sinmara, u64::MAX)
            .expect("scan")
            .is_empty(),
        "one settled turn is reported once"
    );
}

#[test]
fn an_unsettled_report_attempt_is_replayed_under_its_recorded_identity() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture.owner.create_task(request(&fixture)).expect("child");
    let child = receipt.child_session;
    let parent = parent_live_session(&fixture);
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .set_state(&parent, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .answers
        .lock()
        .expect("answer lock")
        .insert(child.to_string(), "Verdict: approve.".to_owned());
    fixture
        .control
        .leaves_delivery_indeterminate("fixture-report-");
    let sinmara = SeatId::new("sinmara").expect("seat");

    // The first pass records the attempt durably and dispatches it; the
    // dispatch stays unsettled, so nothing is marked.
    assert!(fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("scan")
        .is_empty());
    let attempt = fixture.links.load(&child).expect("load").expect("row");
    let recorded = attempt
        .pending_report
        .as_ref()
        .expect("the attempt is durably recorded");
    assert_eq!(recorded.key, attempt_key("Verdict: approve."));
    assert_eq!(recorded.command.command_id.as_str(), "fixture-report-0");
    assert!(attempt.reported_answer.is_none(), "undecided is unmarked");
    assert_eq!(
        fixture.control.delivered.lock().expect("delivered").len(),
        1
    );

    // The next pass replays the SAME identity — no fresh id is minted and
    // no second prompt is dispatched while the attempt stays undecided.
    assert!(fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("scan")
        .is_empty());
    assert_eq!(
        *fixture.control.delivered.lock().expect("delivered"),
        vec!["fixture-report-0".to_owned(), "fixture-report-0".to_owned()],
        "the replay carries the recorded journal identity, never a fresh id"
    );
    assert_eq!(
        fixture
            .control
            .opened
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an unsettled attempt is never replaced while its executor lives"
    );
    let attempt = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(
        attempt
            .pending_report
            .as_ref()
            .expect("attempt kept")
            .command
            .command_id
            .as_str(),
        "fixture-report-0"
    );
}

/// The settled key of one answer, as the report scan derives it.
fn attempt_key(answer: &str) -> String {
    settled_key(Some(answer), None)
}

#[test]
fn a_successor_handoff_keeps_delegated_children_running() {
    use odin_domain::huginn::{
        EventSeq, LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage, SessionEpoch,
    };
    use odin_registry::{LaneBudgetKind, LaneBudgetRaise};
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let parent = parent_live_session(&fixture);
    fixture
        .owner
        .write_link(&child, |row| {
            row.pending_report = Some(super::links::PendingReportDelivery {
                command: LiveCommand {
                    command_id: CommandId::new("report-before-handoff").expect("command"),
                    session_id: parent,
                    expected_epoch: SessionEpoch::new(1),
                    expected_event_head: Some(EventSeq::new(1)),
                    body: LiveCommandBody::Prompt {
                        message: LiveMessage::new(vec![LiveContentBlock::Text(
                            "lane moved".to_owned(),
                        )])
                        .expect("message"),
                        owner_text: None,
                        wake: false,
                    },
                },
                key: "lane-moved".to_owned(),
            });
            row.budget_raises = vec![LaneBudgetRaise {
                kind: LaneBudgetKind::WallSeconds,
                value: 7_200,
            }];
            true
        })
        .expect("stamp");
    let successor = SessionId::new("00000000-0000-4000-8000-0000000000b2").expect("successor");
    fixture
        .links
        .arm_successor(&fixture.caller_session, &successor)
        .expect("arm");
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("handoff");
    assert_eq!(records.len(), 1);
    assert!(records[0].handed_off);
    assert!(!records[0].stopped);
    assert!(fixture.control.stops.lock().expect("stops").is_empty());
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.parent, successor);
    assert!(
        row.pending_report.is_none(),
        "a report aimed at the retiring parent is not replayed"
    );
    assert_eq!(
        row.budget_raises,
        vec![LaneBudgetRaise {
            kind: LaneBudgetKind::WallSeconds,
            value: 7_200,
        }]
    );
    assert_eq!(row.phase, DelegationPhase::Running);
    assert!(fixture
        .links
        .armed_successor(&fixture.caller_session)
        .expect("arm read")
        .is_none());
}

#[test]
fn a_child_waiting_on_live_work_or_an_unreadable_snapshot_is_not_ended() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    let fixture = fixture_with(true, Ok(()), 4, true);
    let waiting = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let escalated = fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect("receipt")
        .child_session;
    let unreadable = fixture
        .owner
        .create_task(request_n(&fixture, 3))
        .expect("receipt")
        .child_session;
    let now = GovernedTaskOwner::clock_ms();
    let idle = ChildLifecycleSnapshot {
        active: true,
        state: Some(odin_domain::huginn::LiveSessionState::Idle),
        epoch: Some(1),
        settled_since_ms: Some(now - 20 * 60 * 1000),
        quiet_since_ms: None,
        provider_fault: None,
    };
    {
        let mut snapshots = fixture.control.snapshots.lock().expect("snapshot lock");
        snapshots.insert(waiting.to_string(), idle.clone());
        snapshots.insert(escalated.to_string(), idle);
    }
    let mut grandchild = fixture.links.load(&waiting).expect("load").expect("row");
    grandchild.child = LiveSessionId::new(
        uuid::Uuid::parse_str("00000000-0000-4000-8000-0000000000c1").expect("uuid"),
    )
    .expect("grandchild");
    grandchild.parent = SessionId::new(waiting.to_string()).expect("parent");
    grandchild.phase = DelegationPhase::Running;
    fixture.links.persist(&grandchild).expect("grandchild");
    fixture
        .owner
        .escalate_task(escalated, SeatId::new("seat.colin").expect("seat"))
        .expect("escalate");
    fixture
        .control
        .snapshot_failures
        .lock()
        .expect("snapshot failures")
        .insert(unreadable.to_string(), "supervisor unavailable".to_owned());
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(Duration::from_secs(3600), Some(Duration::from_secs(600)))
        .expect("scan");
    assert!(retired.is_empty(), "{retired:?}");
    assert_eq!(failures.len(), 1);
    fixture
        .owner
        .control_task(TaskControlRequest {
            caller_session: SessionId::new("00000000-0000-4000-8000-0000000000ee")
                .expect("session"),
            caller_seat: SeatId::new("seat.colin").expect("seat"),
            child: escalated,
            control: TaskControl::Steer("the answer is yes".to_owned()),
        })
        .expect("target answers");
    fixture
        .control
        .set_state(&escalated, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .get_mut(&escalated.to_string())
        .expect("snapshot")
        .settled_since_ms = Some(GovernedTaskOwner::clock_ms() - 20 * 60 * 1000);
    let (retired, _) = fixture
        .owner
        .retire_timed_out_children(Duration::from_secs(3600), Some(Duration::from_secs(600)))
        .expect("second scan");
    assert_eq!(
        retired.iter().map(|out| out.child).collect::<Vec<_>>(),
        vec![escalated]
    );
    assert_eq!(
        fixture
            .links
            .load(&waiting)
            .expect("load")
            .expect("row")
            .phase,
        DelegationPhase::Running
    );
}

#[test]
fn a_failed_child_is_restarted_before_a_steer() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Failed);
    let report = fixture
        .owner
        .control_task(completion_control(
            &fixture,
            child,
            TaskControl::Steer("look at the tests".to_owned()),
        ))
        .expect("steer");
    assert_eq!(
        fixture
            .control
            .commands
            .lock()
            .expect("commands")
            .as_slice(),
        ["Restart", "Prompt"]
    );
    assert!(report.outcome.contains("instruction"), "{}", report.outcome);
}

/// Each rule of the provider-fault classifier once: a status wins over message digits, a
/// context overflow wins over a limit, and an ordinary outage is no fault Odin answers.
#[test]
fn provider_faults_are_classified_by_status_then_message() {
    use super::ProviderFaultKind::{ContextOverflow, RejectedKey, Stall, UsageLimit};
    for (message, status, expected) in [
        ("stream stalled after 90s", None, Some(Stall)),
        (
            "litellm.APIError: prepayment credits depleted",
            Some(402),
            Some(UsageLimit),
        ),
        (
            "402 litellm.APIError: prepayment credits depleted",
            None,
            Some(UsageLimit),
        ),
        ("prepayment service unavailable", Some(503), None),
        ("upstream busy", Some(429), Some(UsageLimit)),
        ("no", Some(401), Some(RejectedKey)),
        ("no", Some(403), Some(RejectedKey)),
        ("Rate limit reached for this key", None, Some(UsageLimit)),
        ("Too Many Requests", None, Some(UsageLimit)),
        ("insufficient_quota", None, Some(UsageLimit)),
        ("Invalid API key provided", None, Some(RejectedKey)),
        ("Unauthorized", None, Some(RejectedKey)),
        (
            "Context size has been exceeded.",
            Some(500),
            Some(ContextOverflow),
        ),
        (
            "maximum context length is 8192 tokens",
            None,
            Some(ContextOverflow),
        ),
        (
            "rate limit; exceed_context_size",
            None,
            Some(ContextOverflow),
        ),
        ("request 4012 failed", None, None),
        ("the gateway is unreachable", Some(502), None),
    ] {
        assert_eq!(
            provider_fault_kind(message, status),
            expected,
            "{message:?} status {status:?}"
        );
    }
}

/// A worker parent that ended can never take its child's report: the child
/// is handed to the conversation, whose report pass picks it up, and the
/// worker-parent pass never tries that parent again.
#[test]
fn a_report_to_an_ended_parent_goes_to_the_conversation_once() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Idle);
    fixture
        .control
        .answers
        .lock()
        .expect("answer lock")
        .insert(child.to_string(), "Done.".to_owned());
    let parent = parent_live_session(&fixture);
    fixture
        .control
        .ended_targets
        .lock()
        .expect("ended")
        .insert(parent);
    let sinmara = SeatId::new("sinmara").expect("seat");
    let reported = fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("pass");
    assert!(reported.is_empty());
    let opened = fixture
        .control
        .opened
        .load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(opened, 1);
    let settled = fixture
        .owner
        .settled_children(&sinmara, u64::MAX)
        .expect("conversation pass");
    assert_eq!(
        settled
            .iter()
            .map(|settled| settled.child)
            .collect::<Vec<_>>(),
        vec![child]
    );
    fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("second pass");
    assert_eq!(
        fixture
            .control
            .opened
            .load(std::sync::atomic::Ordering::SeqCst),
        opened,
        "the ended parent is not tried again"
    );
}

/// An owner over `fixture` whose registry declares the fixture lane's wall at `wall_seconds`.
fn owner_with_lane_wall(
    fixture: &OwnerFixture,
    wall_seconds: u32,
) -> (Arc<GovernedTaskOwner>, tempfile::TempDir) {
    let source = format!(
        r#"schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "Wall budget fixture lane."
project = "odin"
default_seat = "architect"
requires_independent_review = false

[limits]
wall_seconds = {wall_seconds}
"#
    );
    let lane = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Lane,
        "lane.odin",
        "registry/lanes/lane.odin/lane.toml",
        &source,
    )
    .expect("fixture lane parses");
    let snapshot = odin_registry::Snapshot::build(1, vec![lane]).expect("snapshot");
    let mut bytes = serde_json::to_vec_pretty(&snapshot).expect("snapshot json");
    bytes.push(b'\n');
    let root = tempfile::tempdir().expect("registry root");
    let revisions = root.path().join("revisions");
    fs::create_dir_all(&revisions).expect("revisions");
    fs::write(root.path().join("snapshot.json"), &bytes).expect("snapshot");
    fs::write(revisions.join(format!("{:020}.snapshot.json", 1)), &bytes).expect("versioned");
    let receipt = json!({
        "schema": odin_registry::PUBLICATION_RECEIPT_SCHEMA,
        "outcome": "published",
        "revision": 1,
        "previous_revision": null,
        "commit": "commit-1",
        "tree": "tree-1",
        "snapshot_hash": snapshot.hash,
    });
    fs::write(
        revisions.join(format!("{:020}.receipt.json", 1)),
        serde_json::to_vec_pretty(&receipt).expect("receipt json"),
    )
    .expect("receipt");
    let pin = odin_registry::SnapshotHandle::open(odin_registry::SnapshotStore::new(
        root.path().join("snapshot.json"),
    ))
    .expect("pinned registry");
    let governance = DelegationGovernance {
        registry: Some(Arc::new(pin)),
        ..fixture.governance.clone()
    };
    let owner = GovernedTaskOwner::new(
        fixture.provisioner.clone(),
        fixture.control.clone(),
        fixture.links.clone(),
        fixture.ledger.clone(),
        governance,
    );
    (Arc::new(owner), root)
}

/// Makes `child`'s row look `age_ms` old, so its lane wall window opened that long ago.
fn age_row(fixture: &OwnerFixture, child: &LiveSessionId, age_ms: u64) {
    let started = GovernedTaskOwner::clock_ms().saturating_sub(age_ms);
    fixture
        .links
        .update(child, |row| {
            row.created_at_ms = started;
            true
        })
        .expect("age the row");
}

#[test]
fn a_spent_lane_wall_refuses_a_new_child_and_ends_a_running_one() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, _registry) = owner_with_lane_wall(&fixture, 600);
    let child = owner
        .create_task(request(&fixture))
        .expect("the first worker opens the window")
        .child_session;
    assert!(
        owner.create_task(request_n(&fixture, 2)).is_ok(),
        "a window with time left admits"
    );

    age_row(&fixture, &child, 700_000);
    let refused = owner
        .create_task(request_n(&fixture, 3))
        .expect_err("the window is spent");
    assert_eq!(refused.kind, "exact_limit");
    assert_eq!(
        fixture.links.all_rows().expect("rows").len(),
        2,
        "the refusal wrote no row"
    );

    let pass = owner
        .recover_stalled_children(Duration::from_secs(3_600))
        .expect("recovery pass");
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(
        pass.ended.iter().map(|out| out.child).collect::<Vec<_>>(),
        [child],
        "only the worker past its window is ended"
    );
    assert_eq!(
        fixture
            .links
            .load(&child)
            .expect("load")
            .expect("row")
            .phase,
        DelegationPhase::Ended
    );
    assert!(fixture
        .control
        .stops
        .lock()
        .expect("stops")
        .contains(&child.to_string()));
}

#[test]
fn a_steer_raise_lifts_the_lane_wall_and_a_value_below_it_is_refused_by_name() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, _registry) = owner_with_lane_wall(&fixture, 600);
    let child = owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    age_row(&fixture, &child, 700_000);
    assert_eq!(
        owner
            .create_task(request_n(&fixture, 2))
            .expect_err("spent")
            .kind,
        "exact_limit"
    );
    let steer = |value: u32| {
        owner.control_task(TaskControlRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child,
            control: TaskControl::RaiseLaneBudget(odin_registry::LaneBudgetRaise {
                kind: odin_registry::LaneBudgetKind::WallSeconds,
                value,
            }),
        })
    };

    let below = steer(100).expect_err("a value below the declared wall is refused");
    assert!(below.detail.contains("wall"), "{below:?}");
    let report = steer(3_600).expect("a raise above the wall applies");
    assert_eq!(
        report.applied,
        [format!(
            "raise:{}",
            odin_registry::LaneBudgetKind::WallSeconds.key()
        )]
    );
    assert!(
        fixture.control.prompts.lock().expect("prompts").len() == 1,
        "the worker is not steered by a raise"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.budget_raises.len(), 1, "the row keeps the raise");
    owner
        .create_task(request_n(&fixture, 2))
        .expect("the raised wall admits the next worker");
}

#[test]
fn a_lane_budget_raise_on_an_undeclared_wall_is_refused_by_name() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    let refused = fixture
        .owner
        .control_task(TaskControlRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child,
            control: TaskControl::RaiseLaneBudget(odin_registry::LaneBudgetRaise {
                kind: odin_registry::LaneBudgetKind::WallSeconds,
                value: 3_600,
            }),
        })
        .expect_err("a lane that declares no wall has nothing to raise");
    assert!(refused.detail.contains("wall"), "{refused:?}");
    assert!(fixture
        .links
        .load(&child)
        .expect("load")
        .expect("row")
        .budget_raises
        .is_empty());
}

#[test]
fn a_task_read_reports_an_unreadable_history_instead_of_a_missing_answer() {
    use super::owner::TaskOwner;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    // Mid-turn: nothing has settled, so the answer comes from the history read itself.
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Running);
    fixture
        .control
        .answer_errors
        .lock()
        .expect("answer errors")
        .insert(child.to_string(), "history segment unreadable".to_owned());
    let failure = fixture
        .owner
        .read_task(TaskReadRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: SeatId::new("seat.architect").expect("seat"),
            child,
            screen: false,
        })
        .expect_err("an unreadable history is not an absent answer");
    assert_eq!(failure.kind, "result_read_failed");
    assert!(failure.detail.contains("history segment unreadable"));
}

#[test]
fn a_create_without_a_configured_binding_writes_no_row() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let mut unbound = request(&fixture);
    unbound.caller_lane = LaneId::new("lane.unconfigured").expect("lane");
    let refused = fixture
        .owner
        .create_task(unbound)
        .expect_err("no operation binding for this seat and lane");
    assert_eq!(refused.kind, "binding_missing");
    assert!(fixture.links.all_rows().expect("rows").is_empty());
}

#[test]
fn a_delegated_child_is_notified_and_any_other_session_is_refused() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    fixture
        .owner
        .notify_child(child, "the review found a defect")
        .expect("a delegated child is told");
    assert_eq!(
        fixture
            .control
            .prompts
            .lock()
            .expect("prompts")
            .last()
            .map(String::as_str),
        Some("the review found a defect")
    );
    let stranger = LiveSessionId::new(uuid::Uuid::from_u128(0xdead)).expect("session");
    let refused = fixture
        .owner
        .notify_child(stranger, "not yours")
        .expect_err("a session that is not a delegated child is refused");
    assert!(refused.contains("not a delegated child"), "{refused}");
}
