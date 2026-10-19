//! Delegation fixtures and lifecycle, ordering, and stop tests.

use super::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Mutex as StdMutex};
use std::time::Duration;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{
    CommandId, Digest, LaneId, ProjectId, RunId, Scope, SeatId, SessionId, SliceId, TodoId,
};
use odin_ledger::lane_run::{create_lane, create_run, read_run, NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use serde_json::json;
use time::OffsetDateTime;

use crate::host_tools::operations::SeatOperationPolicy;
use crate::host_tools::{HostTool, HostToolError};

const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

fn now_nanos() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos().max(0)).unwrap_or(0)
}

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
    answer_errors: StdMutex<BTreeMap<String, String>>,
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
            answer_errors: StdMutex::new(BTreeMap::new()),
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

    /// Advances the snapshot epoch without changing delivery outcomes.
    fn set_epoch(&self, child: &LiveSessionId, epoch: i64) {
        let mut snapshots = self.snapshots.lock().expect("snapshot lock");
        let snapshot =
            snapshots
                .entry(child.to_string())
                .or_insert_with(|| ChildLifecycleSnapshot {
                    active: true,
                    state: Some(odin_domain::huginn::LiveSessionState::Idle),
                    epoch: Some(1),
                    settled_since_ms: None,
                    quiet_since_ms: None,
                    provider_fault: None,
                });
        snapshot.epoch = Some(epoch);
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

    /// Makes recorded outcomes readable without executing their bodies again.
    fn resolves_delivery(&self, prefix: &str) {
        self.indeterminate
            .lock()
            .expect("indeterminate lock")
            .remove(prefix);
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

    fn fail_rollover(&self, detail: &str) {
        *self.rollover_failure.lock().expect("rollover failure lock") = Some(detail.to_owned());
    }

    fn on_rollover(&self, action: Box<dyn Fn() + Send + Sync>) {
        *self.on_rollover.lock().expect("on-rollover lock") = Some(action);
    }

    fn on_command(&self, action: Box<dyn Fn() + Send + Sync>) {
        *self.on_command.lock().expect("on-command lock") = Some(action);
    }
    /// Fails the next prompt dispatch once; the owner must stop the
    /// already-opened child on that path.
    fn fail_next_prompt(&self, detail: &str) {
        *self.prompt_failure.lock().expect("prompt failure lock") = Some(detail.to_owned());
    }
    fn fail_next_stop(&self, detail: &str) {
        *self
            .next_stop_failure
            .lock()
            .expect("next stop failure lock") = Some(detail.to_owned());
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
        if let Body::Prompt { message } = &body {
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

    fn screen(&self, _child: LiveSessionId) -> Result<Option<String>, String> {
        Ok(Some("> what is this project?\n● A CFD solver.".to_owned()))
    }

    fn last_answer(
        &self,
        child: LiveSessionId,
        _epoch: Option<i64>,
    ) -> Result<Option<String>, String> {
        if let Some(error) = self
            .answer_errors
            .lock()
            .expect("answer error lock")
            .get(&child.to_string())
            .cloned()
        {
            return Err(error);
        }
        // The fixture has no durable history: only installed answers exist.
        Ok(self
            .answers
            .lock()
            .expect("answer lock")
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
    _root: PathBuf,
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

impl Drop for OwnerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self._root);
    }
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
    let root = std::env::temp_dir().join(format!(
        "odin-omp-delegation-{}-{}-{}",
        std::process::id(),
        NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        now_nanos(),
    ));
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
        _root: root,
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

#[test]
fn link_ledger_roundtrips_and_rejects_foreign_schemas() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let command = CommandId::new("odin.task.create:roundtrip").expect("command");
    let child = crate::live::supervisor::session_id_for(&command).expect("child session");
    let link = DelegationLink {
        schema: DELEGATION_LINK_SCHEMA.to_owned(),
        child,
        parent: fixture.caller_session.clone(),
        parent_run: fixture.parent_run.clone(),
        parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
        child_run: GovernedTaskOwner::child_run_for(&child).expect("child run"),
        command,
        project: fixture.project.clone(),
        provider: "gateway".to_owned(),
        model: "glm-flash".to_owned(),
        prompt_digest: Digest::hash(b"prompt"),
        depth: 1,
        phase: DelegationPhase::Provisioning,
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
    };
    let mut changes = fixture.links.subscribe_persists();
    let version = fixture.links.persist_version().expect("persist version");
    fixture.links.persist(&link).expect("persist");
    let loaded = fixture.links.load(&link.child).expect("load").expect("row");
    assert_eq!(loaded, link);
    assert!(changes.has_changed().expect("open channel"));
    assert!(fixture.links.persist_version().expect("persist version") > version);
    changes.borrow_and_update();
    let previous_digest = fixture.links.all_rows().expect("initial snapshot")[0]
        .row_digest
        .clone();
    let clone = fixture.links.clone();
    let mut changed = link.clone();
    changed.phase = DelegationPhase::Running;
    clone
        .persist(&changed)
        .expect("persist through shared clone");
    assert!(changes.has_changed().expect("shared notification channel"));
    let rows = fixture.links.all_rows().expect("atomic link snapshot");
    assert_eq!(rows[0].link.phase, DelegationPhase::Running);
    assert_ne!(rows[0].row_digest, previous_digest);
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
fn create_happy_path_orders_link_before_provision_and_prompt() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    assert!(receipt.plan_accepted);
    let prompts = fixture.control.prompts.lock().expect("prompts");
    assert!(prompts[0].starts_with("You are the delegated implementation worker"));
    assert!(prompts[0].contains("Do not delegate again"));
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
fn a_pending_reload_defers_the_delegation_and_opens_nothing() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .control
        .reload_pending
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let failure = fixture
        .owner
        .create_task(request(&fixture))
        .expect_err("deferred");
    assert_eq!(failure.kind, "odin_reloading");
    assert!(fixture.control.prompts.lock().expect("prompts").is_empty());
    assert!(fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows")
        .is_empty());
    let deferred = fixture.control.deferred.lock().expect("deferred");
    assert_eq!(deferred.len(), 1);
    assert_eq!(deferred[0].prompt, request(&fixture).prompt);
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
fn a_child_title_is_the_first_line_bounded_at_a_word() {
    assert_eq!(child_title("fix it"), "fix it");
    assert_eq!(child_title("\n\n  spaced   words  \nrest"), "spaced words");
    assert_eq!(child_title(""), "");
    let long_word = "x".repeat(80);
    assert_eq!(child_title(&long_word).chars().count(), 48);
    assert!(child_title(&"word ".repeat(40)).chars().count() <= 48);
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
    assert_eq!(retired, vec![receipt.child_session]);
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
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(
            std::time::Duration::from_secs(3600),
            Some(std::time::Duration::from_secs(600)),
        )
        .expect("scan");
    assert_eq!(retired, vec![idle]);
    assert!(failures.is_empty());
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[idle.to_string()]
    );
}

/// Failed turns use the idle timeout; stop failures retain running rows for a later pass.
#[test]
fn a_failed_child_settled_past_the_idle_bound_is_ended() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let children: Vec<LiveSessionId> = (1..=4)
        .map(|n| {
            fixture
                .owner
                .create_task(request_n(&fixture, n))
                .expect("receipt")
                .child_session
        })
        .collect();
    let [old, young, stuck, working] = children[..] else {
        panic!("four children");
    };
    let idle = std::time::Duration::from_secs(600);
    let idle_ms = u64::try_from(idle.as_millis()).expect("idle ms");
    let now = GovernedTaskOwner::clock_ms();
    let snapshot = |state, settled_since_ms| ChildLifecycleSnapshot {
        active: true,
        state: Some(state),
        epoch: Some(1),
        settled_since_ms,
        quiet_since_ms: None,
        provider_fault: None,
    };
    {
        use odin_domain::huginn::LiveSessionState::{Failed, Running};
        let mut snapshots = fixture.control.snapshots.lock().expect("snapshot lock");
        snapshots.insert(old.to_string(), snapshot(Failed, Some(now - idle_ms)));
        snapshots.insert(
            young.to_string(),
            snapshot(Failed, Some(now - idle_ms + 60_000)),
        );
        snapshots.insert(stuck.to_string(), snapshot(Failed, Some(now - idle_ms)));
        snapshots.insert(working.to_string(), snapshot(Running, None));
    }
    fixture
        .control
        .fail_stop(&stuck, "the actor did not confirm the stop");
    let (retired, failures) = fixture
        .owner
        .retire_timed_out_children(std::time::Duration::from_secs(3600), Some(idle))
        .expect("scan");
    assert_eq!(retired, vec![old]);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].starts_with(&stuck.to_string()));
    let mut stops = fixture.control.stops.lock().expect("stops").clone();
    stops.sort();
    let mut expected = [old.to_string(), stuck.to_string()];
    expected.sort();
    assert_eq!(
        stops, expected,
        "the young and working children are untouched"
    );
    let phases: BTreeMap<LiveSessionId, DelegationPhase> = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows")
        .into_iter()
        .map(|row| (row.child, row.phase))
        .collect();
    assert_eq!(phases[&old], DelegationPhase::Ended);
    assert_eq!(phases[&young], DelegationPhase::Running);
    assert_eq!(
        phases[&stuck],
        DelegationPhase::Running,
        "an unverified stop keeps the failed child owned"
    );
    assert_eq!(phases[&working], DelegationPhase::Running);
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
fn explicit_parent_stop_during_stall_abort_wins_without_capture() {
    parent_stop_during_stall_recovery(false);
}

#[test]
fn explicit_parent_stop_during_lane_switch_prevents_continuation() {
    parent_stop_during_stall_recovery(true);
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
        let budget = 2 + u8::from(fallback);
        assert_eq!(MAX_STALL_RETRIES, 2);
        let mut end_reports = 0;
        for attempt in 0..budget + 3 {
            // Reopen the on-disk link ledger and reconstruct the owner on
            // every pass, including duplicate scans after the budget ends.
            let links = DelegationLinkLedger::open(fixture._root.join("links")).expect("reopen");
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
    let lane = |model: &str| super::WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    };
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

/// A provider-ended stall needs no abort; each error is handled only once.
#[test]
fn a_turn_the_provider_ended_on_a_stalled_stream_is_a_stall() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = |model: &str| super::WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    };
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("glm-flash"), lane("kimi-k28")];
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let stall = std::time::Duration::from_secs(300);
    let ended_on = |event: Option<u64>| {
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
                    provider_fault: event.map(|event| super::ProviderTurnFault {
                        event,
                        kind: super::ProviderFaultKind::Stall,
                        origin: super::ProviderFaultOrigin::Provider,
                    }),
                },
            );
        fixture.owner.recover_stalled_children(stall).expect("pass")
    };
    let commands = |kind: &str| {
        fixture
            .control
            .commands
            .lock()
            .expect("command lock")
            .iter()
            .filter(|command| command.contains(kind))
            .count()
    };

    assert!(
        ended_on(None).resumed.is_empty(),
        "an idle child whose turn ended normally is not stalled"
    );
    let first = ended_on(Some(40));
    assert_eq!(first.resumed, vec![child], "the stalled turn is resumed");
    assert_eq!(commands("Abort"), 0, "an ended turn needs no abort");
    assert!(
        ended_on(Some(40)).resumed.is_empty(),
        "one stalled turn is answered once"
    );
    let second = ended_on(Some(52));
    assert_eq!(second.resumed, vec![child]);
    assert_eq!(
        second.switched,
        vec![super::LaneSwitch {
            child,
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            from: lane("glm-flash"),
            to: lane("kimi-k28"),
            cause: super::ProviderFaultKind::Stall,
        }],
        "a repeated stall moves the worker to the next declared lane"
    );
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
    row.model = "kimi-k28".to_owned();
    fixture.links.persist(&row).expect("persist");
    let served = |requests: u64| {
        move |asked: &odin_domain::huginn::LiveSessionId, _since: u64| {
            assert_eq!(*asked, child);
            Ok(BTreeMap::from([
                ("kimi-k28".to_owned(), 0),
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
        lane: "gateway/kimi-k28".to_owned(),
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
    assert_eq!(rates["gateway/kimi-k28"].fallback_workers, 1);
    assert_eq!(rates["gateway/kimi-k28"].fallback_requests, 17);

    let own = super::gateway_fallbacks_seen(
        &row,
        &BTreeMap::from([("kimi-k28".to_owned(), 40)]),
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
    let lane = |model: &str| super::WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    };
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("glm-flash"), lane("kimi-k28")];
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
            to: lane("kimi-k28"),
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
    assert_eq!(link.switched_to, Some(lane("kimi-k28")));
    assert_eq!(link.stall_retries, 0, "a refusal is not a stall retry");
    assert_eq!(
        link.refusals,
        vec![super::LaneRefusal {
            lane: "gateway/glm-flash".to_owned(),
            cause: "rejected_key".to_owned(),
            event: 40,
            next: Some("gateway/kimi-k28".to_owned()),
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
            lane: lane("kimi-k28"),
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
fn missing_parent_plan_fails_before_any_link() {
    let fixture = fixture_with(false, Ok(()), 2, true);
    let failure = fixture
        .owner
        .create_task(request(&fixture))
        .expect_err("delegation without an accepted plan must fail");
    assert_eq!(failure.kind, "plan_not_accepted");
    assert!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .is_empty(),
        "no link row may exist for a rejected delegation"
    );
}

#[test]
fn worker_escalation_is_rejected_by_depth_law() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    let worker_request = TaskCreateRequest {
        caller_session: SessionId::new(receipt.child_session.to_string()).expect("session"),
        caller_run: receipt.child_run.clone(),
        caller_seat: SeatId::new("seat.architect").expect("seat"),
        caller_lane: LaneId::new("lane.odin").expect("lane"),
        project: fixture.project.clone(),
        prompt: "escalate".to_owned(),
        title: None,
        target_seat: None,
        launch: None,
    };
    let failure = fixture
        .owner
        .create_task(worker_request)
        .expect_err("worker escalation must fail");
    assert_eq!(failure.kind, "depth_exceeded");
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
    let prompts = fixture.control.prompts.lock().expect("prompts");
    assert!(
        prompts[1..]
            .iter()
            .all(|prompt| prompt.contains("Do not delegate again")),
        "the asked seat's workers are told they are leaves"
    );
}

#[test]
fn a_cross_seat_ask_is_told_it_may_hand_work_to_its_own_workers() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let mut ask = request(&fixture);
    ask.target_seat = Some(SeatId::new("seat.gungnir").expect("seat"));
    fixture.owner.create_task(ask).expect("cross-seat ask");
    let prompts = fixture.control.prompts.lock().expect("prompts");
    assert!(prompts[0].starts_with("You are answering another seat's request"));
    assert!(!prompts[0].contains("Do not delegate again"));
}

#[test]
fn the_nested_delegation_law() {
    use crate::host_tools::delegation::nested_child_depth;
    let sinmara = SeatId::new("sinmara").expect("seat");
    let gungnir = SeatId::new("gungnir").expect("seat");
    assert_eq!(nested_child_depth(1, Some(&sinmara), &gungnir), Ok(2));
    assert!(nested_child_depth(1, Some(&gungnir), &gungnir).is_err());
    assert!(nested_child_depth(1, None, &gungnir).is_err());
    assert!(nested_child_depth(2, Some(&sinmara), &gungnir).is_err());
}

#[test]
fn task_create_is_on_the_surface_exactly_where_the_law_lets_a_session_delegate() {
    use crate::host_tools::delegation::holds_task_create;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let sinmara = SeatId::new("sinmara").expect("seat");
    let gungnir = SeatId::new("gungnir").expect("seat");
    let command = CommandId::new("odin.task.create:surface").expect("command");
    let child = crate::live::supervisor::session_id_for(&command).expect("child session");
    let asked = DelegationLink {
        schema: DELEGATION_LINK_SCHEMA.to_owned(),
        child,
        parent: fixture.caller_session.clone(),
        parent_run: fixture.parent_run.clone(),
        parent_seat: Some(sinmara.clone()),
        child_run: GovernedTaskOwner::child_run_for(&child).expect("child run"),
        command,
        project: fixture.project.clone(),
        provider: "gateway".to_owned(),
        model: "grok".to_owned(),
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
fn out_of_scope_project_and_oversized_prompt_fail_honestly() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let mut unscoped = request(&fixture);
    unscoped.project = ProjectId::new("project.parsec").expect("project id");
    let failure = fixture
        .owner
        .create_task(unscoped)
        .expect_err("out-of-scope project must fail");
    assert_eq!(failure.kind, "project_out_of_scope");

    let mut oversized = request(&fixture);
    oversized.prompt = "x".repeat(4_097);
    let failure = fixture
        .owner
        .create_task(oversized)
        .expect_err("oversized prompt must fail");
    assert_eq!(failure.kind, "prompt_too_large");
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
fn a_failed_worker_settled_past_the_grace_yields_its_place() {
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
    let failed_since = |ago_ms: u64| {
        fixture
            .control
            .snapshots
            .lock()
            .expect("snapshot lock")
            .insert(
                child.to_string(),
                ChildLifecycleSnapshot {
                    active: true,
                    state: Some(odin_domain::huginn::LiveSessionState::Failed),
                    epoch: Some(1),
                    settled_since_ms: Some(GovernedTaskOwner::clock_ms() - ago_ms),
                    quiet_since_ms: None,
                    provider_fault: None,
                },
            );
    };
    let phase = || {
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .into_iter()
            .find(|row| row.child == child)
            .expect("failed row")
            .phase
    };
    // Just failed: its failure may not be reported yet — it keeps its place.
    failed_since(5_000);
    assert_eq!(
        fixture
            .owner
            .create_task(request_n(&fixture, 2))
            .expect_err("a just-failed worker still counts")
            .kind,
        "concurrency_ceiling"
    );
    // Past the grace but its stop fails: it is not released.
    failed_since(super::owner::SETTLED_CHILD_YIELD_MS);
    fixture
        .control
        .fail_next_stop("the actor did not confirm the stop");
    assert_eq!(
        fixture
            .owner
            .create_task(request_n(&fixture, 2))
            .expect_err("an unstopped failed worker still counts")
            .kind,
        "concurrency_ceiling"
    );
    assert_eq!(phase(), DelegationPhase::Running);
    // Past the grace: it yields, and the new worker opens.
    fixture
        .owner
        .preflight_task(&request_n(&fixture, 2))
        .expect("the preflight sees the place a failed worker yields");
    fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect("a failed worker yields its place");
    assert_eq!(phase(), DelegationPhase::Ended);
    assert_eq!(
        fixture.control.stops.lock().expect("stops").as_slice(),
        &[child.to_string(), child.to_string()],
        "the failed worker is stopped again after the unverified stop"
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
        with_screen.screen.as_deref(),
        Some("> what is this project?\n● A CFD solver.")
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
}

#[test]
fn steering_a_failed_inactive_worker_says_to_start_a_new_task() {
    use super::owner::TaskOwner;
    use super::vocabulary::{TaskControl, TaskControlRequest};
    use odin_domain::huginn::LiveSessionState;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: false,
                state: Some(LiveSessionState::Failed),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: None,
            },
        );
    let failure = fixture
        .owner
        .control_task(TaskControlRequest {
            caller_session: fixture.caller_session.clone(),
            caller_seat: request(&fixture).caller_seat,
            child,
            control: TaskControl::Steer("continue".to_owned()),
        })
        .expect_err("a dead failed worker cannot be steered");
    assert_eq!(failure.kind, "not_running");
    assert!(
        failure.detail.contains("start a new task"),
        "{}",
        failure.detail
    );
    assert!(fixture
        .control
        .commands
        .lock()
        .expect("commands")
        .is_empty());
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
    assert_eq!(report.answer, Some("文".repeat(8192)));
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
fn parent_stop_recognizes_an_already_inactive_child() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    fixture.control.set(&receipt.child_session, false);
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("an inactive child needs no stop request");
    assert_eq!(records.len(), 1);
    assert!(records[0].stopped);
    assert_eq!(
        records[0].detail.as_deref(),
        Some("already inactive when the parent stopped")
    );
    assert!(
        fixture.control.stops.lock().expect("stops").is_empty(),
        "an already inactive child must not be stopped again"
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
fn parent_stop_reports_every_unverified_child_and_keeps_its_row_running() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let first = fixture
        .owner
        .create_task(request(&fixture))
        .expect("first worker");
    let second = fixture
        .owner
        .create_task(request_n(&fixture, 2))
        .expect("second worker");
    fixture.control.set(&first.child_session, false);
    fixture
        .control
        .fail_stop(&second.child_session, "stop channel closed");
    fixture.control.pin_active(&second.child_session);
    let error = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_millis(20))
        .expect_err("one unverified child must fail the whole parent stop");
    assert!(
        error.contains(&second.child_session.to_string()),
        "the failure must name the unverified child: {error}"
    );
    assert!(
        !error.contains(&first.child_session.to_string()),
        "an already inactive child is not a failure: {error}"
    );
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    let ended = rows
        .iter()
        .find(|row| row.child == first.child_session)
        .expect("first row");
    let running = rows
        .iter()
        .find(|row| row.child == second.child_session)
        .expect("second row");
    assert_eq!(ended.phase, DelegationPhase::Ended);
    assert_eq!(running.phase, DelegationPhase::Running);
}

#[test]
fn stop_request_failure_resolves_when_the_child_is_observed_stopped() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt");
    fixture
        .control
        .fail_stop(&receipt.child_session, "pane termination raced the stop");
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("the observed stop resolves the failed request");
    assert_eq!(records.len(), 1);
    assert!(records[0].stopped);
    let detail = records[0].detail.clone().expect("resolution detail");
    assert!(detail.contains("observed stopped"), "{detail}");
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows[0].phase, DelegationPhase::Ended);
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

#[test]
fn parent_capsule_retirement_keeps_the_original_expired_deadline() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::ZERO)
        .expect_err("no fresh capsule retirement budget after parent deadline");
    assert!(fixture.control.retires.lock().expect("retires").is_empty());
}

/// A task review that takes `delay` — the model call a real review is — and
/// records, per review, whether the root's capsule had already retired.
struct SlowReview {
    control: Arc<FakeControl>,
    parent: String,
    delay: Duration,
    reviewed: Mutex<Vec<(LiveSessionId, u64, bool)>>,
}

impl TaskLearningCapture for SlowReview {
    fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
        std::thread::sleep(self.delay);
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

fn slow_review_owner(
    fixture: &OwnerFixture,
    delay: Duration,
) -> (Arc<GovernedTaskOwner>, Arc<SlowReview>) {
    let review = Arc::new(SlowReview {
        control: fixture.control.clone(),
        parent: fixture.caller_session.to_string(),
        delay,
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

/// Every child stop runs that child's own bridge stop through `owner` first,
/// as production composes one owner as every bridge's stop coordinator.
fn bridge_stops_through(fixture: &OwnerFixture, owner: &Arc<GovernedTaskOwner>) {
    let owner = Arc::downgrade(owner);
    let bridge: ChildBridgeStop = Arc::new(move |child: LiveSessionId| -> Result<(), String> {
        owner
            .upgrade()
            .ok_or_else(|| "the stop coordinator is gone".to_owned())?
            .await_children_on_stop(child, Duration::from_millis(500))
            .map(|_| ())
    });
    *fixture
        .control
        .child_bridge_stop
        .lock()
        .expect("child bridge stop lock") = Some(bridge);
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
fn a_slow_child_review_never_spends_the_parent_capsule_retirement_deadline() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::from_millis(800));
    let child = owner
        .create_task(request(&fixture))
        .expect("worker")
        .child_session;
    install_completion_result(&fixture, child, 39);
    let records = owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_millis(500))
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

/// Nested reviews must wait until the root finishes capsule retirement.
#[test]
fn a_nested_leaf_review_never_spends_the_root_capsule_retirement_deadline() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::from_millis(800));
    let asked = owner
        .create_task(request(&fixture))
        .expect("the asked seat's session");
    let leaf = owner
        .create_task(asked_seat_request(&fixture, &asked))
        .expect("its worker")
        .child_session;
    install_completion_result(&fixture, asked.child_session, 41);
    install_completion_result(&fixture, leaf, 39);
    bridge_stops_through(&fixture, &owner);
    let records = owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_millis(500))
        .expect("the root capsule retires within its stop deadline");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].child, asked.child_session);
    assert!(records[0].stopped);
    assert_eq!(
        fixture.control.retires.lock().expect("retires").as_slice(),
        &[
            leaf.to_string(),
            asked.child_session.to_string(),
            fixture.caller_session.to_string()
        ],
        "each level retires its own capsule, innermost first"
    );
    let mut reviewed = review.reviewed.lock().expect("reviewed").clone();
    reviewed.sort();
    let mut expected = vec![(asked.child_session, 41, true), (leaf, 39, true)];
    expected.sort();
    assert_eq!(
        reviewed, expected,
        "each level is reviewed once, after the root capsule retired"
    );
    assert_captured(&fixture, asked.child_session, 41);
    assert_captured(&fixture, leaf, 39);
}

/// Results arriving during a stop update the marker but wait for review until the stop finishes.
#[test]
fn a_result_landing_during_a_stop_waits_for_the_root_proof() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
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
fn a_failed_stop_still_reviews_the_children_it_ended() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
    let first = owner
        .create_task(request(&fixture))
        .expect("first worker")
        .child_session;
    let second = owner
        .create_task(request_n(&fixture, 2))
        .expect("second worker")
        .child_session;
    install_completion_result(&fixture, first, 39);
    install_completion_result(&fixture, second, 40);
    fixture.control.fail_stop(&second, "stop channel closed");
    fixture.control.pin_active(&second);
    owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_millis(20))
        .expect_err("an unproved child fails the parent stop");
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(first, 39, false)]
    );
    assert_captured(&fixture, first, 39);
    let row = fixture.links.load(&second).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.learning_capture_sequence, None);
    assert!(fixture.control.retires.lock().expect("retires").is_empty());
}

/// Deferral must record a newer result without marking it captured before review.
#[test]
fn a_late_result_handed_to_a_stop_never_reads_as_captured() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
    let old = owner
        .create_task(request(&fixture))
        .expect("first worker")
        .child_session;
    install_completion_result(&fixture, old, 39);
    owner
        .control_task(completion_control(&fixture, old, TaskControl::Stop))
        .expect("verified stop");
    assert_captured(&fixture, old, 39);
    let live = owner
        .create_task(request_n(&fixture, 2))
        .expect("second worker")
        .child_session;
    install_completion_result(&fixture, old, 54);
    let weak = Arc::downgrade(&owner);
    let links = fixture.links.clone();
    let bridge: ChildBridgeStop = Arc::new(move |child: LiveSessionId| -> Result<(), String> {
        let owner = weak
            .upgrade()
            .ok_or_else(|| "the stop coordinator is gone".to_owned())?;
        owner
            .await_children_on_stop(child, Duration::from_secs(5))
            .map(|_| ())?;
        if child == live {
            owner.capture_pending_completion(&old)?;
            let row = links.load(&old).expect("load").expect("row");
            assert_eq!(row.learning_result_sequence, Some(54));
            assert_eq!(
                row.learning_capture_sequence,
                Some(39),
                "the earlier capture stands; 54 is pending, never manufactured"
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
        [(old, 39, false), (old, 54, true)]
    );
    assert_captured(&fixture, old, 54);
}

/// Unknown lineage keeps capture pending while any stop is open.
#[test]
fn an_unproved_lineage_keeps_the_capture_pending_through_a_stop() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
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
    let asked_session = asked.child_session;
    let bridge: ChildBridgeStop = Arc::new(move |child: LiveSessionId| -> Result<(), String> {
        if child == asked_session {
            let mut row = links.load(&asked_session)?.expect("asked row");
            row.depth = 5;
            links.persist(&row)?;
        }
        weak.upgrade()
            .ok_or_else(|| "the stop coordinator is gone".to_owned())?
            .await_children_on_stop(child, Duration::from_secs(5))
            .map(|_| ())
    });
    *fixture
        .control
        .child_bridge_stop
        .lock()
        .expect("child bridge stop lock") = Some(bridge);
    owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(5))
        .expect("bounded stop");
    assert!(
        review.reviewed.lock().expect("reviewed").is_empty(),
        "nothing with an unproved lineage is reviewed during or for the stop"
    );
    let row = fixture.links.load(&leaf).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_capture_sequence, None);
    owner
        .capture_pending_completion(&leaf)
        .expect("later owner");
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(leaf, 39, true)]
    );
    assert_captured(&fixture, leaf, 39);
}

#[test]
fn an_unwound_stop_leaves_its_handed_children_pending_not_trapped() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
    let asked = owner
        .create_task(request(&fixture))
        .expect("the asked seat's session");
    let leaf = owner
        .create_task(asked_seat_request(&fixture, &asked))
        .expect("its worker")
        .child_session;
    install_completion_result(&fixture, leaf, 39);
    let weak = Arc::downgrade(&owner);
    let asked_session = asked.child_session;
    let bridge: ChildBridgeStop = Arc::new(move |child: LiveSessionId| -> Result<(), String> {
        weak.upgrade()
            .ok_or_else(|| "the stop coordinator is gone".to_owned())?
            .await_children_on_stop(child, Duration::from_secs(5))?;
        if child == asked_session {
            panic!("the asked seat's bridge stop crashed after its own proof");
        }
        Ok(())
    });
    *fixture
        .control
        .child_bridge_stop
        .lock()
        .expect("child bridge stop lock") = Some(bridge);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(5))
    }));
    assert!(unwound.is_err(), "the root stop unwound");
    assert!(review.reviewed.lock().expect("reviewed").is_empty());
    let row = fixture.links.load(&leaf).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_result_sequence, Some(39));
    assert_eq!(row.learning_capture_sequence, None);
    owner
        .capture_pending_completion(&leaf)
        .expect("later owner");
    assert_eq!(
        *review.reviewed.lock().expect("reviewed"),
        [(leaf, 39, false)]
    );
    assert_captured(&fixture, leaf, 39);
}

#[test]
fn overlapping_stops_of_one_session_review_only_after_the_last_proof() {
    use std::sync::mpsc;
    type Proof = std::thread::JoinHandle<Result<Vec<ChildStopRecord>, String>>;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let (owner, review) = slow_review_owner(&fixture, Duration::ZERO);
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
fn parent_stop_catches_a_child_that_lands_during_the_stop() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let first = fixture
        .owner
        .create_task(request(&fixture))
        .expect("first worker");
    let links = fixture.links.clone();
    let control = Arc::clone(&fixture.control);
    let second_command = CommandId::new("odin.task.create:late-race").expect("late command");
    let second_child = crate::live::supervisor::session_id_for(&second_command)
        .map_err(|error| error.to_string())
        .expect("late child session");
    fixture.control.on_first_stop(Box::new(move || {
        let link = DelegationLink {
            schema: DELEGATION_LINK_SCHEMA.to_owned(),
            child: second_child,
            parent: SessionId::new("00000000-0000-4000-8000-0000000000a1").expect("caller session"),
            parent_seat: Some(SeatId::new("seat.architect").expect("seat")),
            parent_run: RunId::new("run:live:00000000-0000-4000-8000-0000000000a0")
                .expect("parent run"),
            child_run: GovernedTaskOwner::child_run_for(&second_child).expect("child run"),
            command: second_command.clone(),
            project: ProjectId::new("project.odin").expect("project id"),
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
            prompt_digest: Digest::hash(b"prompt"),
            depth: 1,
            phase: DelegationPhase::Running,
            created_at_ms: 2,
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
        };
        links.persist(&link).expect("late row");
        control.set(&second_child, true);
    }));
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("the late child must be caught by the stop enumeration");
    assert_eq!(records.len(), 2, "both the worker and the late child stop");
    assert!(records.iter().all(|record| record.stopped));
    let stops = fixture.control.stops.lock().expect("stops");
    assert!(stops.contains(&first.child_session.to_string()));
    assert!(stops.contains(&second_child.to_string()));
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.phase == DelegationPhase::Ended));
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

/// A failed stop must leave the row visible to later parent cleanup.
#[test]
fn prompt_failure_with_unverified_stop_keeps_the_row_counted_live() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    fixture
        .control
        .fail_next_prompt("bridge rejected the prompt");
    fixture
        .control
        .fail_next_stop("pane termination raced the failure stop");
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
    assert_eq!(
        rows[0].phase,
        DelegationPhase::Running,
        "a possibly live child must stay counted live, not hidden behind Failed"
    );
    let records = fixture
        .owner
        .await_children_on_stop(parent_live_session(&fixture), Duration::from_secs(1))
        .expect("the barrier must own the possibly live child");
    assert_eq!(records.len(), 1);
    assert!(records[0].stopped);
    assert_eq!(records[0].child, rows[0].child);
    let rows = fixture
        .links
        .children_of(&fixture.caller_session)
        .expect("rows");
    assert_eq!(rows[0].phase, DelegationPhase::Ended);
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
fn refused_explicit_stop_keeps_result_live_and_pending() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    fixture.control.fail_next_stop("verified teardown refused");
    assert_eq!(
        owner
            .control_task(completion_control(&fixture, child, TaskControl::Stop))
            .expect_err("failed stop")
            .kind,
        "command_refused"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.learning_result_sequence, Some(54));
    assert_eq!(row.learning_capture_sequence, None);
    assert!(fixture.control.snapshot(child).expect("snapshot").active);
    owner
        .capture_pending_completion(&child)
        .expect("pending scan");
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("retry verified stop");
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
}

#[test]
fn ended_stop_retries_failed_capture_after_reopen_without_resurrection() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    capture.fail.store(true, Ordering::SeqCst);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    install_completion_result(&fixture, child, 54);
    owner.result_persisted(child, 54);
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("stop succeeds despite capture failure");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_capture_sequence, None);
    assert_eq!(*capture.attempts.lock().expect("attempts"), [(child, 54)]);
    assert!(capture.reviewed.lock().expect("reviewed").is_empty());
    drop(owner);
    let owner = completion_owner(&fixture, &capture);
    let mut foreign = completion_control(&fixture, child, TaskControl::Stop);
    foreign.caller_session = SessionId::new("session:foreign").expect("session");
    foreign.caller_seat = SeatId::new("seat.foreign").expect("seat");
    capture.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        owner.control_task(foreign).expect_err("foreign owner").kind,
        "not_the_parent"
    );
    assert!(capture.reviewed.lock().expect("reviewed").is_empty());
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("authorized ended retry");
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 54)]);
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        [child.to_string()]
    );
    assert!(!fixture.control.snapshot(child).expect("snapshot").active);
    assert!(owner
        .control_task(completion_control(
            &fixture,
            child,
            TaskControl::Steer("resume".to_owned())
        ))
        .is_err());
    assert_eq!(
        fixture
            .links
            .load(&child)
            .expect("load")
            .expect("row")
            .learning_capture_sequence,
        Some(54)
    );
}

#[test]
fn capture_defers_when_typed_history_lags_the_observed_latest_result() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    install_completion_result(&fixture, child, 39);
    owner.result_persisted(child, 54);
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("stop");
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_result_sequence, Some(54));
    assert_eq!(row.learning_capture_sequence, None);
    install_completion_result(&fixture, child, 54);
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("retry latest payload");
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

#[test]
fn stopped_child_captures_late_and_newer_results_once_under_duplicate_observation() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = verified_stop_capture(&fixture);
    let owner = completion_owner(&fixture, &capture);
    let child = owner
        .create_task(request(&fixture))
        .expect("create")
        .child_session;
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("stop before result flush");
    assert!(capture.attempts.lock().expect("attempts").is_empty());
    assert_eq!(
        fixture
            .links
            .load(&child)
            .expect("load")
            .expect("row")
            .learning_capture_sequence,
        None
    );
    install_completion_result(&fixture, child, 39);
    owner.result_persisted(child, 39);
    assert_eq!(*capture.reviewed.lock().expect("reviewed"), [(child, 39)]);
    install_completion_result(&fixture, child, 54);
    // The typed history has advanced before an older notification arrives.
    // Capture must bind the latest payload, never relabel result39 as result54.
    let barrier = Arc::new(std::sync::Barrier::new(4));
    std::thread::scope(|scope| {
        for sequence in [39, 54] {
            let owner = owner.clone();
            let barrier = barrier.clone();
            scope.spawn(move || {
                barrier.wait();
                owner.result_persisted(child, sequence);
            });
        }
        let owner = owner.clone();
        let stop_barrier = barrier.clone();
        let stop = completion_control(&fixture, child, TaskControl::Stop);
        scope.spawn(move || {
            stop_barrier.wait();
            owner.control_task(stop).expect("concurrent ended retry");
        });
        barrier.wait();
    });
    owner.result_persisted(child, 39);
    owner
        .capture_pending_completion(&child)
        .expect("duplicate scan");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.learning_result_sequence, Some(54));
    assert_eq!(row.learning_capture_sequence, Some(54));
    assert_eq!(
        *capture.reviewed.lock().expect("reviewed"),
        [(child, 39), (child, 54)]
    );
    assert_eq!(
        *fixture.control.stops.lock().expect("stops"),
        [child.to_string()]
    );
    assert!(!fixture.control.snapshot(child).expect("snapshot").active);
}

#[test]
fn terminal_capture_allows_fresh_row_writes_and_preserves_report_intent() {
    use odin_domain::huginn::{
        EventSeq, LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage, SessionEpoch,
    };

    struct MutatingCapture {
        owner: Mutex<std::sync::Weak<GovernedTaskOwner>>,
        attempts: Mutex<Vec<u64>>,
    }

    impl TaskLearningCapture for MutatingCapture {
        fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
            self.attempts
                .lock()
                .expect("attempts")
                .push(facts.result.event_sequence);
            let owner = self
                .owner
                .lock()
                .expect("owner")
                .upgrade()
                .expect("owner alive");
            // Capture must release the row lock during review and preserve concurrent mutations.
            owner.write_link(&facts.child, |row| {
                row.learning_result_sequence = Some(54);
                row.reported_answer = Some("previous-answer".to_owned());
                row.pending_report = Some(super::links::PendingReportDelivery {
                    command: LiveCommand {
                        command_id: CommandId::new("report-during-capture").expect("command"),
                        session_id: facts.child,
                        expected_epoch: SessionEpoch::new(0),
                        expected_event_head: Some(EventSeq::new(0)),
                        body: LiveCommandBody::Prompt {
                            message: LiveMessage::new(vec![LiveContentBlock::Text(
                                "Pending child answer".to_owned(),
                            )])
                            .expect("message"),
                        },
                    },
                    key: "pending-answer".to_owned(),
                });
                true
            })?;
            Ok(())
        }
    }

    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = Arc::new(MutatingCapture {
        owner: Mutex::new(std::sync::Weak::new()),
        attempts: Mutex::new(Vec::new()),
    });
    let owner = Arc::new(
        GovernedTaskOwner::new(
            fixture.provisioner.clone(),
            fixture.control.clone(),
            fixture.links.clone(),
            fixture.ledger.clone(),
            fixture.governance.clone(),
        )
        .with_learning(Some(capture.clone() as Arc<dyn TaskLearningCapture>)),
    );
    *capture.owner.lock().expect("owner") = Arc::downgrade(&owner);
    let child = owner
        .create_task(request(&fixture))
        .expect("child")
        .child_session;
    install_completion_result(&fixture, child, 39);
    owner
        .control_task(completion_control(&fixture, child, TaskControl::Stop))
        .expect("stop and capture");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.learning_result_sequence, Some(54));
    assert_eq!(row.learning_capture_sequence, Some(39));
    assert_eq!(row.reported_answer.as_deref(), Some("previous-answer"));
    let pending = row.pending_report.expect("intent survives capture marker");
    assert_eq!(pending.key, "pending-answer");
    assert_eq!(pending.command.command_id.as_str(), "report-during-capture");
    owner
        .capture_pending_completion(&child)
        .expect("lagging history");
    assert_eq!(*capture.attempts.lock().expect("attempts"), [39]);
    install_completion_result(&fixture, child, 54);
    owner
        .capture_pending_completion(&child)
        .expect("newer result");
    owner
        .capture_pending_completion(&child)
        .expect("duplicate result");
    assert_eq!(*capture.attempts.lock().expect("attempts"), [39, 54]);
    assert_eq!(
        fixture
            .links
            .load(&child)
            .expect("load")
            .expect("row")
            .learning_capture_sequence,
        Some(54)
    );
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
    let seat = SeatId::new("seat.architect").expect("seat");

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

    // (1) The completion-event observer — the production caller wired into
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

    let mut legacy = serde_json::to_value(&row).expect("row json");
    legacy["learning_proposal_id"] = serde_json::json!("6f1c0a52-3b7e-4c1d-9a2b-0c4d5e6f7a8b");
    let legacy: DelegationLink = serde_json::from_value(legacy).expect("a legacy row loads");
    assert!(
        serde_json::to_value(&legacy)
            .expect("rewritten row")
            .get("learning_proposal_id")
            .is_none(),
        "a rewritten row drops the retired proposal id"
    );

    // (3) Ordering: a terminal row scanned BEFORE the typed result exists
    // stays pending (no evaluated-absent suppression); a later durable
    // Result event still captures.
    let mut late = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    late.child = {
        let command = CommandId::new("command:late-capture").expect("command");
        let late_child = crate::live::supervisor::session_id_for(&command).expect("session");
        let late_link = DelegationLink {
            schema: DELEGATION_LINK_SCHEMA.to_owned(),
            child: late_child,
            parent: fixture.caller_session.clone(),
            parent_seat: Some(seat.clone()),
            parent_run: RunId::new("run:live:00000000-0000-4000-8000-0000000000a0").expect("run"),
            child_run: GovernedTaskOwner::child_run_for(&late_child).expect("run"),
            command,
            project: fixture.project.clone(),
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
            prompt_digest: Digest::hash(b"prompt"),
            depth: 1,
            phase: DelegationPhase::Ended,
            created_at_ms: 3,
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
        };
        fixture.links.persist(&late_link).expect("persist");
        late_child
    };
    let late_child = late.child;
    drop(late);
    // No result yet; leave capture pending.
    owner
        .capture_pending_completion(&late_child)
        .expect("pending scan");
    let mid_row = fixture.links.load(&late_child).expect("load").expect("row");
    assert_eq!(
        mid_row.learning_capture_sequence, None,
        "absence at one scan never permanently suppresses a later event"
    );
    // The typed result event is then durably appended; the observer fires.
    let late_result = TaskResultReport {
        summary: Some("late result lands after the first scan".to_owned()),
        artifacts: Vec::new(),
        event_sequence: 11,
    };
    fixture
        .control
        .results
        .lock()
        .expect("results lock")
        .insert(late_child.to_string(), late_result.clone());
    owner.result_persisted(late_child, late_result.event_sequence);
    let late_row = fixture.links.load(&late_child).expect("load").expect("row");
    assert_eq!(
        late_row.learning_capture_sequence,
        Some(late_result.event_sequence),
        "a later Result event captures; no permanent evaluated-absent marker exists"
    );
}

fn fixture_contract() -> odin_kernel::CapabilityContract {
    use std::num::NonZeroU32;
    odin_kernel::CapabilityContract {
        id: odin_domain::CapabilityId::new("task.create").expect("capability id"),
        delegate_to: None,
        version: 1,
        tool_name: odin_domain::knowledge::ToolName::new("task_create").expect("tool name"),
        description: "delegation preflight fixture".to_owned(),
        handler: odin_kernel::HandlerBinding::Builtin {
            name: "odin_task.create".to_owned(),
        },
        input_schema_ref: "fixture.input".to_owned(),
        output_schema_ref: "fixture.output".to_owned(),
        effect_class: odin_domain::EffectClass::R1,
        seat_tags: BTreeSet::new(),
        timeout_seconds: NonZeroU32::new(30).expect("timeout"),
        idempotency: odin_kernel::IdempotencyPolicy::Required,
        retry: odin_kernel::RetryPolicy { max_attempts: 1 },
        approval: odin_kernel::ApprovalRequirement::None,
        evidence_extractor: odin_kernel::HandlerBinding::Builtin {
            name: "odin_task.create_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
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

#[test]
fn preflight_rerun_after_readiness_disappears_refuses_read_only() {
    let fixture = fixture_with_preflight(true, Ok(()), Ok(()), 2, true);
    fixture
        .owner
        .preflight_task(&request(&fixture))
        .expect("the surface is ready when the approval is requested");
    // Readiness changes while the operator decision is pending.
    *fixture
        .recording
        .preflight_result
        .lock()
        .expect("preflight result lock") = Err("zellij_session brain-m6b was not found".to_owned());
    let failure = fixture
        .owner
        .preflight_task(&request(&fixture))
        .expect_err("the approved retry's preflight refuses on the dead surface");
    assert_eq!(failure.kind, "surface_unavailable");
    assert!(
        !failure.effect_may_have_started,
        "the refusal is pre-effect: the approved row stays unspent"
    );
    assert!(
        fixture
            .recording
            .calls
            .lock()
            .expect("provision calls")
            .is_empty(),
        "no child was provisioned on the refused retry"
    );
    assert!(
        fixture
            .links
            .children_of(&fixture.caller_session)
            .expect("rows")
            .is_empty(),
        "no link row exists for the refused retry"
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

/// Inactive children stop counting without preflight changing their durable rows.
#[test]
fn preflight_concurrency_observes_live_truth_without_reconciling() {
    let fixture = fixture_with(true, Ok(()), 1, true);
    let receipt = fixture
        .owner
        .create_task(request(&fixture))
        .expect("one child fills the ceiling");
    let second = fixture
        .owner
        .preflight_task(&request_n(&fixture, 2))
        .expect_err("the live child fills the ceiling");
    assert_eq!(second.kind, "concurrency_ceiling");
    // The child goes inactive; execution would durably end the row, but
    // preflight only observes: the ceiling now passes and the row is
    // untouched.
    fixture.control.set(&receipt.child_session, false);
    fixture
        .owner
        .preflight_task(&request_n(&fixture, 2))
        .expect("an unowned running child no longer counts, observed read-only");
    let row = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    assert_eq!(
        row.phase,
        DelegationPhase::Running,
        "preflight never reconciles or persists the row"
    );
}

#[test]
fn preflight_enforces_depth_law_before_readiness() {
    let fixture = fixture_with(true, Ok(()), 4, true);
    let receipt = fixture.owner.create_task(request(&fixture)).expect("child");
    let mut worker_request = request(&fixture);
    worker_request.caller_session =
        SessionId::new(receipt.child_session.to_string()).expect("worker session");
    let failure = fixture
        .owner
        .preflight_task(&worker_request)
        .expect_err("a delegated worker can never delegate");
    assert_eq!(failure.kind, "depth_exceeded");
    assert!(
        fixture
            .recording
            .preflight_calls
            .lock()
            .expect("preflight calls")
            .is_empty(),
        "the depth refusal never reaches the readiness observation"
    );
}

/// Tool surface: `task_create`'s preflight derives the request exactly like
/// `invoke_prepared` and maps the owner's refusal to the typed delegation
/// error; the unbound slot fails closed.
#[test]
fn task_create_tool_preflight_forwards_the_owner_gate() {
    let fixture = fixture_with_preflight(
        true,
        Ok(()),
        Err("zellij_session brain-m6b was not found".to_owned()),
        2,
        true,
    );
    let slot = Arc::new(TaskOwnerSlot::new());
    slot.bind(fixture.owner.clone())
        .expect("bind fixture owner");
    let tool = TaskCreateTool::new(slot).expect("tool");
    let scope = Scope {
        seat: Some(SeatId::new("seat.architect").expect("seat")),
        project: None,
        lane: Some(LaneId::new("lane.odin").expect("lane")),
        run: Some(fixture.parent_run.clone()),
        attempt: None,
        session: Some(fixture.caller_session.clone()),
        node: None,
    };
    let arguments = json!({
        "prompt": "Implement the governed worker lifecycle.",
        "project": "project.odin",
    });
    let contract = fixture_contract();
    let error = tool
        .preflight(&contract, &scope, &arguments)
        .expect_err("the missing surface refuses through the tool preflight");
    match error {
        HostToolError::Delegation { tool: name, detail } => {
            assert_eq!(name, "task_create");
            assert!(
                detail.contains("surface_unavailable"),
                "the tool surfaces the typed readiness refusal: {detail}"
            );
        }
        other => panic!("expected the typed delegation refusal, got {other:?}"),
    }
    // Scope validation precedes consulting the owner.
    let mut unbound_scope = scope.clone();
    unbound_scope.seat = None;
    assert!(
        matches!(
            tool.preflight(&contract, &unbound_scope, &arguments),
            Err(HostToolError::Scope {
                tool: "task_create",
                ..
            })
        ),
        "a scope without a seat refuses typed"
    );
    // A scope-bound but unbound slot fails closed.
    let unbound_tool = TaskCreateTool::new(Arc::new(TaskOwnerSlot::new())).expect("unbound tool");
    assert!(
        matches!(
            unbound_tool.preflight(&contract, &scope, &arguments),
            Err(HostToolError::Catalog { .. })
        ),
        "the unbound owner slot fails closed"
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
        from_coordinator(TaskControl::Steer("Colin chose option 2".to_owned()))
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
        provider: "codex-cli".to_owned(),
        model: "fixture-model".to_owned(),
    };
    let mut asked = request(&fixture);
    asked.target_seat = Some(SeatId::new("seat.gungnir").expect("seat"));
    asked.launch = Some(terminal.clone());
    let receipt = fixture.owner.create_task(asked).expect("cross-seat ask");
    assert_eq!(
        (receipt.provider.as_str(), receipt.model.as_str()),
        ("codex-cli", "fixture-model")
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

/// Only OMP options are live `SetModel` fallbacks, wrapping past launches
/// of other harnesses. A worker on a harness-only lane has no OMP fallback.
#[test]
fn a_stalled_omp_worker_falls_back_only_to_omp_launch_options() {
    use odin_domain::huginn::{HarnessBinding, LiveLaunchOption, ModelName, ProviderName};
    let option = |provider: &str, model: &str, harness: Option<&str>| LiveLaunchOption {
        provider: ProviderName::new(provider).expect("provider"),
        model: ModelName::new(model).expect("model"),
        skeleton_ref: "gungnir-native".to_owned(),
        container_id: odin_domain::ContainerId::new("gungnir-native").expect("container"),
        harness: harness.map(|environment| HarnessBinding {
            harness: "codex".to_owned(),
            environment: environment.to_owned(),
            account: None,
        }),
    };
    let gungnir = [
        option("gateway", "glm-flash", None),
        option("gateway", "kimi-k28", None),
        option("codex-cli", "fixture-model", Some("fleet-authority")),
        option("codex-cli", "fixture-model-small", Some("laptop-ssh")),
    ];
    let lane = |provider: &str, model: &str| super::WorkerLane {
        provider: provider.to_owned(),
        model: model.to_owned(),
    };
    assert_eq!(
        super::next_switchable_lane(&gungnir, &lane("gateway", "kimi-k28")),
        Some(lane("gateway", "glm-flash")),
        "the next OMP option, wrapping past the harness options"
    );
    assert_eq!(
        super::next_switchable_lane(&gungnir, &lane("gateway", "glm-flash")),
        Some(lane("gateway", "kimi-k28"))
    );
    assert_eq!(
        super::next_switchable_lane(&gungnir, &lane("codex-cli", "fixture-model")),
        None,
        "a harness worker has no OMP fallback"
    );
    assert_eq!(
        super::next_switchable_lane(&gungnir[..1], &lane("gateway", "glm-flash")),
        None
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

/// Fault origin distinguishes provider overflow from authenticated context refusal.
#[test]
fn a_fault_names_whether_the_provider_or_odin_s_context_guard_ended_the_turn() {
    use super::ProviderFaultKind::{ContextGuard, ContextOverflow, Stall};
    use super::ProviderFaultOrigin::{ContextRefusal, Provider};
    use odin_domain::huginn::{EventSeq, LiveEvent, LiveEventBody, SessionEpoch, SessionError};
    let session = odin_domain::huginn::LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9")
        .expect("session id");
    let fault = |code: &str, message: &str| {
        let event = LiveEvent::new(
            1,
            odin_domain::EventId::new("event:2").expect("event id"),
            session,
            SessionEpoch::new(1),
            EventSeq::new(2),
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time"),
            LiveEventBody::Error(SessionError {
                code: code.to_owned(),
                message: message.to_owned(),
                retryable: false,
                error_status: None,
            }),
        )
        .expect("event");
        super::provider_turn_fault(&[event]).map(|fault| (fault.kind, fault.origin))
    };
    assert_eq!(
        fault(
            "provider_turn_error",
            "OpenAI completions stream stalled while waiting for the next event"
        ),
        Some((Stall, Provider))
    );
    assert_eq!(
        fault(
            "provider_turn_error",
            "500 litellm.APIConnectionError: OpenAIException - Context size has been exceeded."
        ),
        Some((ContextOverflow, Provider)),
        "the provider's own overflow is a lane refusal"
    );
    assert_eq!(
        fault(
            "context_refusal.window_exceeded",
            "request requires 44540 byte tokens, exceeding the declared window 32768"
        ),
        Some((ContextOverflow, ContextRefusal)),
        "the extension's refusal of the declared window is answered by rollover"
    );
    assert_eq!(
        fault(
            "context_refusal.model_identity_mismatch",
            "the resolved model carries tokenizer unresolved"
        ),
        Some((ContextGuard, ContextRefusal))
    );
}

#[test]
fn a_child_failed_on_a_context_refusal_rolls_a_fresh_incarnation_and_the_task_continues() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let lane = |model: &str| super::WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    };
    *fixture.control.lanes.lock().expect("lanes lock") = vec![lane("glm-flash"), lane("kimi-k28")];
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
fn a_parent_stop_during_a_context_rollover_wins_and_the_row_ends() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: true,
                state: Some(odin_domain::huginn::LiveSessionState::Failed),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: Some(super::ProviderTurnFault {
                    event: 209,
                    kind: super::ProviderFaultKind::ContextOverflow,
                    origin: super::ProviderFaultOrigin::ContextRefusal,
                }),
            },
        );
    let links = fixture.links.clone();
    let race_control = Arc::clone(&fixture.control);
    fixture.control.on_rollover(Box::new(move || {
        let mut row = links.load(&child).expect("row").expect("link");
        row.phase = DelegationPhase::Ended;
        links.persist(&row).expect("persist");
        race_control.set(&child, false);
    }));
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
        1
    );
    assert!(
        pass.refused.is_empty(),
        "no refusal report: the stop owns the end"
    );
    assert!(pass.failures.is_empty());
    let row = fixture.links.load(&child).expect("row").expect("link");
    assert_eq!(row.phase, DelegationPhase::Ended, "the parent stop wins");
}

#[test]
fn a_failed_context_rollover_falls_back_to_an_honest_end() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: true,
                state: Some(odin_domain::huginn::LiveSessionState::Failed),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: Some(super::ProviderTurnFault {
                    event: 209,
                    kind: super::ProviderFaultKind::ContextOverflow,
                    origin: super::ProviderFaultOrigin::ContextRefusal,
                }),
            },
        );
    fixture.control.fail_rollover(
        "context-refusal rollover needs the session's declared [live.rollover] configuration",
    );
    let pass = fixture
        .owner
        .recover_stalled_children(std::time::Duration::from_secs(300))
        .expect("pass");
    assert_eq!(pass.refused.len(), 1, "its parent is told");
    assert_eq!(pass.refused[0].child, child);
    assert_eq!(
        pass.refused[0].cause,
        super::ProviderFaultKind::ContextOverflow
    );
    let row = fixture.links.load(&child).expect("row").expect("link");
    assert_eq!(row.phase, DelegationPhase::Ended);
    assert_eq!(row.refusals.len(), 1);
    assert_eq!(row.refusals[0].event, 209);
}

/// Both rollover lineage writes must preserve a report intent and result
/// observation published after recovery loaded its stale delegation row.
#[test]
fn context_rollover_preserves_a_concurrent_report_intent_and_result_observation() {
    use super::lifecycle::MAX_ROLLOVER_ADMISSIONS;

    for admissions in [0, MAX_ROLLOVER_ADMISSIONS] {
        let fixture = fixture_with(true, Ok(()), 2, true);
        let child = fixture
            .owner
            .create_task(request(&fixture))
            .expect("child")
            .child_session;
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
            .expect("answers")
            .insert(child.to_string(), "Approve.".to_owned());
        fixture
            .control
            .leaves_delivery_indeterminate("fixture-report-");
        assert!(fixture
            .owner
            .report_to_worker_parents(&SeatId::new("sinmara").expect("seat"), u64::MAX)
            .expect("report scan")
            .is_empty());
        let mut row = fixture.links.load(&child).expect("load").expect("row");
        let pending = row.pending_report.take().expect("recorded intent");
        row.rollover_admissions = admissions;
        fixture.links.persist(&row).expect("stale scan baseline");

        fixture.control.snapshots.lock().expect("snapshots").insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: true,
                state: Some(odin_domain::huginn::LiveSessionState::Failed),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: Some(super::ProviderTurnFault {
                    event: 209,
                    kind: super::ProviderFaultKind::ContextOverflow,
                    origin: super::ProviderFaultOrigin::ContextRefusal,
                }),
            },
        );
        let links = fixture.links.clone();
        let concurrent_pending = pending.clone();
        *fixture.control.on_snapshot.lock().expect("snapshot hook") = Some(Box::new(move || {
            // all_rows has already returned the old row to recovery.
            let mut current = links.load(&child).expect("load").expect("row");
            assert!(current.pending_report.is_none());
            assert!(current.learning_result_sequence.is_none());
            current.pending_report = Some(concurrent_pending);
            current.learning_result_sequence = Some(7);
            links
                .persist(&current)
                .expect("concurrent report and observation");
        }));

        let pass = fixture
            .owner
            .recover_stalled_children(Duration::from_secs(300))
            .expect("recovery");
        assert!(pass.failures.is_empty(), "{:?}", pass.failures);
        let row = fixture.links.load(&child).expect("load").expect("row");
        let retained = row
            .pending_report
            .expect("concurrent intent survives rollover");
        assert_eq!(
            retained.command, pending.command,
            "exact journaled command survives"
        );
        assert_eq!(retained.key, pending.key, "exact answer key survives");
        assert_eq!(row.learning_result_sequence, Some(7));
        assert!(row.reported_answer.is_none());
        assert_eq!(row.handled_stall_event, Some(209));
        assert_eq!(row.refusals.len(), 1);
        assert_eq!(row.refusals[0].event, 209);
        let rollovers = fixture.control.rollover_calls.lock().expect("rollovers");
        if admissions == 0 {
            assert_eq!(row.phase, DelegationPhase::Running);
            assert_eq!(row.rollover_admissions, 1);
            assert!(row.refusals[0].next.is_some());
            assert_eq!(*rollovers, vec![(child.to_string(), 209)]);
            assert!(pass.refused.is_empty() && pass.ended.is_empty());
            assert!(fixture.control.stops.lock().expect("stops").is_empty());
        } else {
            assert_eq!(row.phase, DelegationPhase::Ended);
            assert_eq!(row.rollover_admissions, MAX_ROLLOVER_ADMISSIONS);
            assert!(row.refusals[0].next.is_none());
            assert!(rollovers.is_empty());
            assert_eq!(pass.refused.len(), 1);
            assert_eq!(pass.refused[0].child, child);
            assert_eq!(
                pass.refused[0].cause,
                super::ProviderFaultKind::ContextOverflow
            );
            assert_eq!(
                *fixture.control.stops.lock().expect("stops"),
                vec![child.to_string()]
            );
        }
    }
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

/// The assignment and the rollover budget live on the durable row, not in
/// any in-memory scan state: a daemon restart that reopens the same
/// ledger reads both back, so the delegated requirements survive restart
/// and the spent admissions are never reset.
#[test]
fn a_rolled_over_workers_assignment_and_budget_survive_a_restart() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let row = fixture.links.load(&child).expect("row").expect("link");
    assert_eq!(
        row.assignment, "Implement the governed worker lifecycle.",
        "the exact admitted prompt is durable at admission"
    );
    assert_eq!(row.rollover_admissions, 0);
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .insert(
            child.to_string(),
            ChildLifecycleSnapshot {
                active: true,
                state: Some(odin_domain::huginn::LiveSessionState::Failed),
                epoch: Some(1),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: Some(super::ProviderTurnFault {
                    event: 15,
                    kind: super::ProviderFaultKind::ContextOverflow,
                    origin: super::ProviderFaultOrigin::ContextRefusal,
                }),
            },
        );
    fixture
        .owner
        .recover_stalled_children(std::time::Duration::from_secs(300))
        .expect("pass");
    // A restart: the same ledger root reopened by a new process.
    let reopened = DelegationLinkLedger::open(fixture._root.join("links")).expect("reopen ledger");
    let row = reopened.load(&child).expect("row").expect("link");
    assert_eq!(
        row.assignment, "Implement the governed worker lifecycle.",
        "the assignment is durable beyond any conversation tail"
    );
    assert_eq!(
        row.rollover_admissions, 1,
        "restart cannot reset the budget"
    );
    assert_eq!(row.handled_stall_event, Some(15));
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
fn asking_again_while_the_first_worker_is_still_provisioning_replays_it() {
    let fixture = fixture_with(true, Ok(()), 3, true);
    let first = fixture.owner.create_task(request(&fixture)).expect("first");
    let mut row = fixture
        .links
        .load(&first.child_session)
        .expect("load")
        .expect("row");
    row.phase = DelegationPhase::Provisioning;
    fixture.links.persist(&row).expect("persist");
    let again = fixture.owner.create_task(request(&fixture)).expect("again");
    assert_eq!(again.child_session, first.child_session);
    assert_eq!(fixture.recording.calls.lock().expect("calls").len(), 1);
}

/// A report intent that cannot be durably recorded is never dispatched
/// (a dispatch without a durable attempt would be unreplayable), the scan
/// itself still completes, and once the intent can be recorded the next
/// pass reports every settled child.
#[test]
fn an_unrecordable_report_intent_defers_the_dispatch() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = fixture_with(true, Ok(()), 2, true);
    let mut children = Vec::new();
    for prompt in ["Review the change.", "Run the checks."] {
        let mut asked = request(&fixture);
        asked.prompt = prompt.to_owned();
        let child = fixture
            .owner
            .create_task(asked)
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
            .insert(child.to_string(), format!("Done: {prompt}"));
        children.push(child);
    }
    fixture.control.set_state(
        &parent_live_session(&fixture),
        odin_domain::huginn::LiveSessionState::Idle,
    );
    let links = fixture._root.join("links");
    std::fs::set_permissions(&links, std::fs::Permissions::from_mode(0o500)).expect("chmod");
    let reported = fixture
        .owner
        .report_to_worker_parents(&SeatId::new("sinmara").expect("seat"), u64::MAX)
        .expect("scan completes even when no intent can be recorded");
    assert!(
        reported.is_empty(),
        "nothing is dispatched without its durable attempt record"
    );
    assert!(fixture
        .control
        .prompted
        .lock()
        .expect("prompted")
        .is_empty());
    std::fs::set_permissions(&links, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let mut reported = fixture
        .owner
        .report_to_worker_parents(&SeatId::new("sinmara").expect("seat"), u64::MAX)
        .expect("next pass");
    reported.sort();
    children.sort();
    assert_eq!(reported, children, "the deferred answers are reported");
}

#[test]
fn a_worker_parent_hears_its_child_s_settled_turn_once() {
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

/// The observer runs on another thread while report dispatch is in flight;
/// both its sequence annotation and the report marker must survive.
#[test]
fn a_report_marker_preserves_a_concurrent_completion_observation() {
    use crate::host_tools::delegation::CompletionEventObserver;
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
    let owner = Arc::downgrade(&fixture.owner);
    fixture.control.on_command(Box::new(move || {
        let owner = owner.upgrade().expect("owner");
        std::thread::spawn(move || {
            owner.result_persisted(child, 7);
        })
        .join()
        .expect("completion observer");
    }));
    let sinmara = SeatId::new("sinmara").expect("seat");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&sinmara, u64::MAX)
            .expect("scan"),
        vec![child]
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert!(
        row.reported_answer.is_some(),
        "the delivery intent survived the observer's whole-row write"
    );
    assert_eq!(
        row.learning_result_sequence,
        Some(7),
        "the observer's raised sequence survived the marker write"
    );

    assert!(
        row.pending_report.is_none(),
        "the delivered attempt retires with the marker"
    );
    // The marked answer is reported once: no later pass re-sends it.
    fixture
        .control
        .set_state(&parent, odin_domain::huginn::LiveSessionState::Idle);
    assert!(fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("scan")
        .is_empty());
    assert_eq!(fixture.control.prompted.lock().expect("prompted").len(), 1);
}

/// The reverse interleaving: the pending completion capture's whole-row
/// write lands after a report marker already did (the marker was
/// persisted inside the capture's own slow window). The capture's write
/// must also go through the shared mutation lock on the FRESH row, or it
/// erases the delivery intent and the next scan re-reports an answer the
/// parent already heard.
#[test]
fn a_completion_capture_preserves_a_landed_report_marker() {
    use crate::host_tools::delegation::CompletionEventObserver;

    struct ReportingCapture {
        links: DelegationLinkLedger,
        key: &'static str,
    }
    impl TaskLearningCapture for ReportingCapture {
        fn capture_task_completion(&self, facts: &TaskCompletionFacts) -> Result<(), String> {
            // The concurrent report scan: it delivers the answer and marks
            // the row while this capture is running — the capture's own
            // row snapshot predates the marker.
            let mut scanned = self.links.load(&facts.child).expect("load").expect("row");
            scanned.reported_answer = Some(self.key.to_owned());
            self.links.persist(&scanned).expect("marker persist");
            Ok(())
        }
    }
    let fixture = fixture_with(true, Ok(()), 2, true);
    let capture = Arc::new(ReportingCapture {
        links: fixture.links.clone(),
        key: "abc123def456",
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
    let result = TaskResultReport {
        summary: Some("implemented the change; checks pass".to_owned()),
        artifacts: Vec::new(),
        event_sequence: 7,
    };
    fixture
        .control
        .results
        .lock()
        .expect("results lock")
        .insert(receipt.child_session.to_string(), result);
    let mut link = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    link.phase = DelegationPhase::Ended;
    fixture.links.persist(&link).expect("persist");

    owner.result_persisted(receipt.child_session, 7);
    let row = fixture
        .links
        .load(&receipt.child_session)
        .expect("load")
        .expect("row");
    assert_eq!(
        row.learning_capture_sequence,
        Some(7),
        "the capture persisted its exact result sequence"
    );
    assert_eq!(
        row.reported_answer.as_deref(),
        Some("abc123def456"),
        "the marker persisted during the capture survived its whole-row write"
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

/// An unresolved attempt stays unresolved across recovery and across a
/// newer answer: an epoch advance does not prove the attempt failed to
/// deliver (a crash AFTER dispatch is still ambiguous), so no fresh id is
/// ever minted, nothing is marked, and the recorded attempt is never
/// overwritten — a newer answer waits behind it.
#[test]
fn an_unresolved_attempt_survives_recovery_and_a_newer_answer() {
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
    assert!(fixture
        .owner
        .report_to_worker_parents(&sinmara, u64::MAX)
        .expect("scan")
        .is_empty());

    // The parent recovers (its epoch advances past the recorded attempt)
    // and the child later produces a NEWER answer. Neither authorizes a
    // fresh id: the recorded attempt's ambiguity is not decidable.
    fixture.control.set_epoch(&parent, 2);
    fixture
        .control
        .answers
        .lock()
        .expect("answer lock")
        .insert(child.to_string(), "Revised verdict: reject.".to_owned());
    assert!(
        fixture
            .owner
            .report_to_worker_parents(&sinmara, u64::MAX)
            .expect("scan")
            .is_empty(),
        "an unresolved attempt is never replaced or decided"
    );
    let delivered = fixture.control.delivered.lock().expect("delivered").clone();
    assert_eq!(
        delivered,
        vec!["fixture-report-0".to_owned(), "fixture-report-0".to_owned()],
        "only the recorded identity is ever replayed"
    );
    assert_eq!(
        fixture
            .control
            .opened
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "no fresh attempt is opened behind an unresolved one"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    let recorded = row
        .pending_report
        .as_ref()
        .expect("the recorded attempt survives recovery and the newer answer");
    assert_eq!(recorded.command.command_id.as_str(), "fixture-report-0");
    assert_eq!(recorded.key, attempt_key("Verdict: approve."));
    assert!(row.reported_answer.is_none(), "nothing is marked");

    // The recorded attempt then RESOLVES as delivered: the replay marks
    // ITS OWN (older) answer and retires, and the newer answer is
    // delivered in the same pass under a fresh attempt.
    fixture.control.resolves_delivery("fixture-report-");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&sinmara, u64::MAX)
            .expect("scan"),
        vec![child]
    );
    // Duplicate delivery deduplicates execution, not invocation; assert command identities.
    let delivered = fixture.control.delivered.lock().expect("delivered").clone();
    assert!(
        delivered
            .iter()
            .all(|id| matches!(id.as_str(), "fixture-report-0" | "fixture-report-1")),
        "every hand-off carried a journaled identity — the recorded attempt's or its one fresh successor"
    );
    assert_eq!(
        delivered
            .iter()
            .filter(|id| id.as_str() == "fixture-report-1")
            .count(),
        1,
        "the newer answer was tendered exactly once, under its fresh attempt"
    );
    assert!(
        delivered
            .last()
            .is_some_and(|id| id.as_str() == "fixture-report-1"),
        "the fresh attempt's hand-off followed the recorded attempt's resolution"
    );
    assert_eq!(
        fixture
            .control
            .opened
            .load(std::sync::atomic::Ordering::SeqCst),
        2,
        "resolution minted exactly one fresh attempt behind the recorded one"
    );
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(
        row.reported_answer.as_deref(),
        Some(attempt_key("Revised verdict: reject.").as_str()),
        "the newer answer is the marked one"
    );
    assert!(
        row.pending_report.is_none(),
        "both the replayed and the fresh attempt retired"
    );
    // The recorded attempt's Prompt ran the then-idle parent's turn at
    // its FIRST hand-off — the Unsettled verdict hid the outcome, not
    // the execution; the fresh attempt found that turn running and
    // delivered the newer answer as a FollowUp into it: each body
    // executed exactly once.
    assert_eq!(
        *fixture.control.commands.lock().expect("commands"),
        vec!["Prompt".to_owned(), "FollowUp".to_owned()],
        "both answers reached the parent, each in the body its state allows"
    );
}

/// The blake3 12-character answer key exactly as the scan derives it.
fn attempt_key(answer: &str) -> String {
    let digest = Digest::hash(answer.as_bytes()).to_string();
    digest.trim_start_matches("blake3:")[..12].to_owned()
}

#[test]
fn a_stale_report_scan_cannot_redispatch_an_answer_marked_by_another_scan() {
    for newer_answer in ["Approve.", "Reject the updated change."] {
        let fixture = fixture_with(true, Ok(()), 2, true);
        let child = fixture
            .owner
            .create_task(request(&fixture))
            .expect("child")
            .child_session;
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
            .expect("answers")
            .insert(child.to_string(), "Approve.".to_owned());
        let owner = Arc::downgrade(&fixture.owner);
        let control = Arc::downgrade(&fixture.control);
        *fixture.control.on_open_delivery.lock().expect("open hook") = Some(Box::new(move || {
            let owner = owner.upgrade().expect("owner");
            control
                .upgrade()
                .expect("control")
                .answers
                .lock()
                .expect("answers")
                .insert(child.to_string(), newer_answer.to_owned());
            let reported = std::thread::spawn(move || {
                owner
                    .report_to_worker_parents(&SeatId::new("sinmara").expect("seat"), u64::MAX)
                    .expect("competing scan")
            })
            .join()
            .expect("competing thread");
            assert_eq!(reported, vec![child]);
        }));
        let seat = SeatId::new("sinmara").expect("seat");
        assert!(fixture
            .owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("stale scan")
            .is_empty());
        assert!(fixture
            .owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("next scan")
            .is_empty());
        assert_eq!(
            fixture.control.delivered.lock().expect("deliveries").len(),
            1
        );
        let prompts = fixture.control.prompted.lock().expect("prompts");
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains(newer_answer));
        let row = fixture.links.load(&child).expect("load").expect("row");
        assert_eq!(row.reported_answer, Some(attempt_key(newer_answer)));
        assert!(row.pending_report.is_none());
    }
}

#[test]
fn completion_observer_preserves_an_unsettled_report_identity() {
    use crate::host_tools::delegation::CompletionEventObserver;

    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("child")
        .child_session;
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
        .expect("answers")
        .insert(child.to_string(), "Approve.".to_owned());
    fixture
        .control
        .leaves_delivery_indeterminate("fixture-report-");
    let owner = Arc::downgrade(&fixture.owner);
    fixture.control.on_command(Box::new(move || {
        let owner = owner.upgrade().expect("owner");
        std::thread::spawn(move || owner.result_persisted(child, 7))
            .join()
            .expect("observer");
    }));
    let seat = SeatId::new("sinmara").expect("seat");
    assert!(fixture
        .owner
        .report_to_worker_parents(&seat, u64::MAX)
        .expect("scan")
        .is_empty());
    let row = fixture.links.load(&child).expect("load").expect("row");
    let pending = row.pending_report.expect("intent survives observer");
    assert_eq!(row.learning_result_sequence, Some(7));
    assert!(row.reported_answer.is_none());
    fixture.control.resolves_delivery("fixture-report-");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("replay"),
        vec![child]
    );
    let deliveries = fixture.control.delivered.lock().expect("deliveries");
    assert_eq!(
        deliveries.as_slice(),
        &[
            pending.command.command_id.to_string(),
            pending.command.command_id.to_string()
        ]
    );
    assert_eq!(fixture.control.prompted.lock().expect("prompts").len(), 1);
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.learning_result_sequence, Some(7));
    assert_eq!(row.reported_answer.as_deref(), Some(pending.key.as_str()));
    assert!(row.pending_report.is_none());
}

#[test]
fn a_delayed_delivery_cannot_replace_a_newer_report_marker() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("child")
        .child_session;
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
        .expect("answers")
        .insert(child.to_string(), "Old answer.".to_owned());
    let links = fixture.links.clone();
    fixture.control.on_command(Box::new(move || {
        let mut row = links.load(&child).expect("load").expect("row");
        row.reported_answer = Some(attempt_key("New answer."));
        row.pending_report = None;
        links.persist(&row).expect("newer delivered marker");
    }));
    fixture
        .owner
        .report_to_worker_parents(&SeatId::new("sinmara").expect("seat"), u64::MAX)
        .expect("old delivery completes");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.reported_answer, Some(attempt_key("New answer.")));
    assert!(row.pending_report.is_none());
}

/// The crash boundary here is the durable owner intent, BEFORE any
/// supervisor admission. The fake scripts the restarted parent's stale
/// epoch refusal; it does not claim to exercise a live actor restart.
#[test]
fn a_preadmission_report_intent_replays_before_a_refused_identity_is_replaced() {
    assert_preadmission_report_replacement(false, false);
}

#[test]
fn a_refused_same_answer_report_preserves_its_message_with_current_parent_mode() {
    assert_preadmission_report_replacement(false, true);
    assert_preadmission_report_replacement(true, false);
    assert_preadmission_report_replacement(true, true);
}

fn assert_preadmission_report_replacement(original_follow_up: bool, parent_running: bool) {
    use odin_domain::huginn::{
        EventSeq, LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage, LiveSessionState,
        SessionEpoch,
    };

    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("child")
        .child_session;
    let parent = parent_live_session(&fixture);
    let answer = "Verdict: approve.";
    let key = attempt_key(answer);
    fixture.control.set_state(&child, LiveSessionState::Idle);
    fixture.control.set_state(
        &parent,
        if parent_running {
            LiveSessionState::Running
        } else {
            LiveSessionState::Idle
        },
    );
    fixture
        .control
        .answers
        .lock()
        .expect("answers")
        .insert(child.to_string(), answer.to_owned());
    let recorded_message = LiveMessage::new(vec![LiveContentBlock::Text(format!(
        "Work you delegated (task {child}) just finished a turn. Its answer:\n{answer}\n\
         Carry on with your task from here."
    ))])
    .expect("message");
    let original = LiveCommand {
        command_id: CommandId::new("report-before-admission").expect("command id"),
        session_id: parent,
        expected_epoch: SessionEpoch::new(0),
        expected_event_head: Some(EventSeq::new(0)),
        body: if original_follow_up {
            LiveCommandBody::FollowUp {
                message: recorded_message.clone(),
            }
        } else {
            LiveCommandBody::Prompt {
                message: recorded_message.clone(),
            }
        },
    };
    let mut row = fixture.links.load(&child).expect("load").expect("row");
    row.pending_report = Some(super::links::PendingReportDelivery {
        command: original.clone(),
        key: key.clone(),
    });
    fixture
        .links
        .persist(&row)
        .expect("intent durable before admission");
    assert!(fixture
        .control
        .delivered
        .lock()
        .expect("deliveries")
        .is_empty());
    assert!(fixture
        .control
        .executed
        .lock()
        .expect("executed")
        .is_empty());
    assert_eq!(fixture.control.opened.load(Ordering::SeqCst), 0);

    // Reconstruct the owner and reopen its on-disk link ledger. The run
    // ledger is the fixture's in-memory ledger, not a simulated FS restart.
    let reopened = DelegationLinkLedger::open(fixture._root.join("links")).expect("reopen links");
    let owner = GovernedTaskOwner::new(
        fixture.provisioner.clone(),
        fixture.control.clone(),
        reopened.clone(),
        fixture.ledger.clone(),
        fixture.governance.clone(),
    );
    fixture
        .control
        .refused_deliveries
        .lock()
        .expect("refused ids")
        .insert(original.command_id.to_string());
    let observed_original = original.clone();
    let observed_key = key.clone();
    let disk_root = fixture._root.join("links");
    *fixture.control.on_delivery.lock().expect("delivery hook") = Some(Box::new(move |command| {
        // Read through an independent ledger handle rather than the owner's cache.
        let disk = DelegationLinkLedger::open(disk_root.clone()).expect("read durable intent");
        let row = disk.load(&child).expect("load").expect("row");
        assert!(row.reported_answer.is_none(), "no marker before execution");
        let pending = row.pending_report.expect("intent precedes every hand-off");
        assert_eq!(pending.command, *command);
        assert_eq!(
            pending.key, observed_key,
            "replacement carries the same answer"
        );
        if command.command_id == observed_original.command_id {
            assert_eq!(
                *command, observed_original,
                "replay preserves the entire old envelope"
            );
        } else {
            assert_eq!(command.command_id.as_str(), "fixture-report-0");
            assert_eq!(command.expected_epoch, SessionEpoch::new(1));
            if original_follow_up == parent_running {
                assert_eq!(command.body, observed_original.body);
            }
            let expected_body = if parent_running {
                LiveCommandBody::FollowUp {
                    message: recorded_message.clone(),
                }
            } else {
                LiveCommandBody::Prompt {
                    message: recorded_message.clone(),
                }
            };
            assert_eq!(command.body, expected_body);
        }
    }));
    let seat = SeatId::new("sinmara").expect("seat");
    assert_eq!(
        owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("recovered scan"),
        vec![child]
    );
    assert_eq!(
        fixture
            .control
            .delivered
            .lock()
            .expect("deliveries")
            .as_slice(),
        &[
            original.command_id.to_string(),
            "fixture-report-0".to_owned()
        ]
    );
    assert_eq!(
        *fixture.control.executed.lock().expect("executed"),
        BTreeSet::from(["fixture-report-0".to_owned()])
    );
    assert_eq!(
        fixture.control.prompted.lock().expect("prompts").len(),
        usize::from(!parent_running)
    );
    let row = reopened.load(&child).expect("load").expect("row");
    assert_eq!(row.reported_answer, Some(key));
    assert!(row.pending_report.is_none());
    assert!(owner
        .report_to_worker_parents(&seat, u64::MAX)
        .expect("subsequent scan")
        .is_empty());
    assert_eq!(
        fixture.control.delivered.lock().expect("deliveries").len(),
        2
    );
    assert_eq!(
        fixture.control.prompted.lock().expect("prompts").len(),
        usize::from(!parent_running)
    );
    assert_eq!(fixture.control.opened.load(Ordering::SeqCst), 1);
}

#[test]
fn a_successor_handoff_keeps_delegated_children_running() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
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
    assert_eq!(retired, vec![escalated]);
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
fn an_unopened_successor_supersede_carries_children_to_the_next_session() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    let b = SessionId::new("00000000-0000-4000-8000-0000000000b2").expect("b");
    let c = SessionId::new("00000000-0000-4000-8000-0000000000c3").expect("c");
    fixture
        .links
        .repoint_children(&fixture.caller_session, &b)
        .expect("A to B");
    fixture.links.repoint_children(&b, &c).expect("B to C");
    fixture
        .links
        .repoint_children(&fixture.caller_session, &c)
        .expect("A stragglers");
    let row = fixture.links.load(&child).expect("load").expect("row");
    assert_eq!(row.parent, c);
    assert_eq!(row.phase, DelegationPhase::Running);
    assert!(fixture.control.stops.lock().expect("stops").is_empty());
}
#[test]
fn asking_again_after_a_failed_child_starts_a_new_worker() {
    let fixture = fixture_with(true, Ok(()), 3, true);
    let first = fixture.owner.create_task(request(&fixture)).expect("first");
    fixture.control.set_state(
        &first.child_session,
        odin_domain::huginn::LiveSessionState::Failed,
    );
    let again = fixture.owner.create_task(request(&fixture)).expect("again");
    assert_ne!(again.child_session, first.child_session);
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

#[test]
fn a_status_code_classifies_the_fault_and_message_digits_do_not() {
    use odin_domain::huginn::{EventSeq, LiveEvent, LiveEventBody, SessionEpoch, SessionError};
    let session = LiveSessionId::new(
        uuid::Uuid::parse_str("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9").expect("uuid"),
    )
    .expect("session");
    let event = |status: Option<u16>, message: &str| {
        LiveEvent::new(
            1,
            odin_domain::EventId::new("event:2").expect("event id"),
            session,
            SessionEpoch::new(1),
            EventSeq::new(2),
            time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time"),
            LiveEventBody::Error(SessionError {
                code: "provider_turn_error".to_owned(),
                message: message.to_owned(),
                retryable: false,
                error_status: status,
            }),
        )
        .expect("event")
    };
    let kind = |status, message: &str| {
        super::provider_turn_fault(&[event(status, message)]).map(|fault| fault.kind)
    };
    assert_eq!(
        kind(Some(429), "upstream busy"),
        Some(super::ProviderFaultKind::UsageLimit)
    );
    assert_eq!(
        kind(Some(401), "no"),
        Some(super::ProviderFaultKind::RejectedKey)
    );
    assert_eq!(kind(None, "request 4012 failed"), None);
    assert_eq!(
        kind(Some(500), "Context size has been exceeded."),
        Some(super::ProviderFaultKind::ContextOverflow)
    );
}

#[test]
fn a_failed_child_with_an_unproved_epoch_is_reported_once() {
    let fixture = fixture_with(true, Ok(()), 2, true);
    let child = fixture
        .owner
        .create_task(request(&fixture))
        .expect("receipt")
        .child_session;
    fixture
        .control
        .set_state(&child, odin_domain::huginn::LiveSessionState::Failed);
    fixture
        .control
        .snapshots
        .lock()
        .expect("snapshot lock")
        .get_mut(&child.to_string())
        .expect("snapshot")
        .epoch = None;
    fixture.control.set_state(
        &parent_live_session(&fixture),
        odin_domain::huginn::LiveSessionState::Idle,
    );
    let seat = SeatId::new("sinmara").expect("seat");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("report"),
        vec![child]
    );
    assert!(fixture
        .owner
        .report_to_worker_parents(&seat, u64::MAX)
        .expect("second report")
        .is_empty());
}

#[test]
fn a_history_read_error_on_a_finished_child_is_reported_once() {
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
        .answer_errors
        .lock()
        .expect("answer errors")
        .insert(child.to_string(), "history segment unreadable".to_owned());
    fixture.control.set_state(
        &parent_live_session(&fixture),
        odin_domain::huginn::LiveSessionState::Idle,
    );
    let seat = SeatId::new("sinmara").expect("seat");
    assert_eq!(
        fixture
            .owner
            .report_to_worker_parents(&seat, u64::MAX)
            .expect("report"),
        vec![child]
    );
    let prompted = fixture.control.prompted.lock().expect("prompted").clone();
    assert!(
        prompted[0].contains("history segment unreadable"),
        "{prompted:?}"
    );
    assert!(fixture
        .owner
        .report_to_worker_parents(&seat, u64::MAX)
        .expect("second report")
        .is_empty());
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
