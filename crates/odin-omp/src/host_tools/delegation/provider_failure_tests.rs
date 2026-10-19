//! Provider-failure recovery through session actors and a filesystem ledger.
//! Commands use the actor's current epoch and head; worker-parent reports use
//! a second actor through `open_delivery` and `deliver`.

use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveCommandKind, LiveContentBlock, LiveError, LiveEvent, LiveEventBody,
    LiveMessage, LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName,
    PermissionDecision, PermissionRequestId, ProviderName,
};
use odin_domain::{
    ApprovalId, CommandId, Digest, LaneId, NodeId, ProjectId, RunId, SeatId, SessionId, TodoId,
};
use odin_ledger::lane_run::{create_lane, create_run, NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use serde_json::json;
use time::OffsetDateTime;

use super::*;
use crate::bridge::{ObservedFrame, TypedFrameFailure};
use crate::live::control::LiveControlBackend;
use crate::live::ledger::LiveLedger;
use crate::live::session_actor::tests::spawn_fixture_with_control;
use crate::live::session_actor::SessionActorHandle;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

const STALL: (u16, &str) = (
    500,
    "OpenAI completions stream stalled while waiting for the next event",
);
const USAGE_LIMIT: (u16, &str) = (429, "429 litellm.RateLimitError: insufficient_quota");
const REJECTED_KEY: (u16, &str) = (
    401,
    "401 litellm.AuthenticationError: Incorrect API key provided",
);
const PROVIDER_OVERFLOW: (u16, &str) = (
    500,
    "500 litellm.APIConnectionError: APIConnectionError: OpenAIException - Context size has \
     been exceeded.",
);
/// An outage that lane rotation cannot resolve.
const OUTAGE: (u16, &str) = (
    500,
    "500 litellm.APIConnectionError: APIConnectionError: OpenAIException -",
);

/// Wide enough that every row the harness creates is inside the report window.
const WINDOW_MS: u64 = 3_600_000;
const PARTIAL: &str = "partial-work-marker-31";

/// The key a successful answer is reported under (the owner's digest rule).
fn success_key(answer: &str) -> String {
    let digest = Digest::hash(answer.as_bytes()).to_string();
    digest.trim_start_matches("blake3:")[..12].to_owned()
}

/// A report with its child's identity removed, so reports of different
/// children over the same prose can be compared.
fn without_child(report: &str, child: LiveSessionId) -> String {
    report.replace(&child.to_string(), "<child>")
}

/// The child's bridge: records every effect the actor applies to it.
#[derive(Default)]
struct ChildBackend {
    prompts: AtomicU64,
    restarts: AtomicU64,
    set_models: Mutex<Vec<String>>,
    rollovers: Mutex<Vec<u64>>,
    /// The text of every prompt and follow-up the actor delivered.
    messages: Mutex<Vec<String>>,
    /// Incarnations the bridge advanced (restart, rollover): the journal
    /// opens at epoch 1 and reclaims one per advance.
    advances: AtomicU64,
}

impl ChildBackend {
    fn record(&self, message: &LiveMessage) {
        let text = message
            .content
            .iter()
            .filter_map(|block| match block {
                LiveContentBlock::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        self.messages.lock().expect("messages").push(text);
    }
}

#[async_trait]
impl LiveControlBackend for ChildBackend {
    async fn prompt(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.record(message);
        Ok(())
    }
    async fn follow_up(&self, message: &LiveMessage) -> Result<(), LiveError> {
        self.record(message);
        Ok(())
    }
    async fn steer(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), LiveError> {
        self.restarts.fetch_add(1, Ordering::SeqCst);
        self.advances.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn rollover_fresh(
        &self,
        refusal_event: u64,
        _selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<i64, LiveError> {
        self.rollovers
            .lock()
            .expect("rollovers")
            .push(refusal_event);
        let advanced = self.advances.fetch_add(1, Ordering::SeqCst) + 2;
        Ok(i64::try_from(advanced).expect("epoch"))
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError> {
        self.set_models
            .lock()
            .expect("set models")
            .push(format!("{provider}/{model}"));
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn bridge_ready(&self) -> bool {
        true
    }
}

type AfterCommand = Box<dyn Fn(LiveCommandKind) + Send + Sync>;

/// A worker parent: a second real actor that child reports are delivered to.
struct PeerActor {
    actor: SessionActorHandle,
    id: LiveSessionId,
    journal: Arc<dyn LiveLedger>,
    backend: Arc<ChildBackend>,
}

fn read_history(
    runtime: &tokio::runtime::Handle,
    journal: &Arc<dyn LiveLedger>,
    session_id: LiveSessionId,
    after: EventSeq,
    limit: u16,
) -> Result<Vec<LiveEvent>, String> {
    runtime
        .block_on(journal.history(HistoryQuery {
            session_id,
            after,
            limit: NonZeroU16::new(limit).ok_or("history limit")?,
        }))
        .map(|page| page.events)
        .map_err(|error| error.to_string())
}

fn read_all_events(
    runtime: &tokio::runtime::Handle,
    journal: &Arc<dyn LiveLedger>,
    session_id: LiveSessionId,
) -> Result<Vec<LiveEvent>, String> {
    let mut after = EventSeq::new(0);
    let mut events = Vec::new();
    loop {
        let page = read_history(runtime, journal, session_id, after, 128)?;
        let Some(last) = page.last().map(|event| event.sequence) else {
            return Ok(events);
        };
        after = last;
        events.extend(page);
    }
}

/// The supervisor adapter's view of ONE live child over its real actor:
/// liveness, state and the journal-tail fault read as
/// `SupervisorChildControl::snapshot` reads them, and every command sent at
/// the actor's epoch and head with its journaled outcome as the answer.
struct ActorControl {
    runtime: tokio::runtime::Handle,
    actor: SessionActorHandle,
    child: LiveSessionId,
    journal: Arc<dyn LiveLedger>,
    lanes: Vec<WorkerLane>,
    issued: AtomicU64,
    commands: Mutex<Vec<LiveCommandKind>>,
    /// Runs after each applied command: the parent-stop race.
    after_command: Mutex<Option<AfterCommand>>,
    peer: Option<PeerActor>,
    /// Delivery attempts opened against the peer.
    opened: AtomicU64,
    /// The peer's actor takes the dispatched command, but its outcome is
    /// not durably readable: the verdict is `Unsettled`.
    hold_outcome: AtomicBool,
    /// The child's history cannot be read for its answer.
    answer_unreadable: AtomicBool,
    /// Omits the snapshot's incarnation epoch.
    epoch_unproved: AtomicBool,
    /// How long ago the resting child's settled instant is reported to be.
    /// The owner reads the wall clock, which no test can advance; this ages
    /// the instant instead, so a past-grace case is reachable without sleeping.
    settled_age_ms: AtomicU64,
}

impl ActorControl {
    fn summary(&self) -> LiveSessionSummary {
        self.actor.summary().expect("child summary")
    }

    fn history(&self, after: EventSeq, limit: u16) -> Result<Vec<LiveEvent>, String> {
        read_history(&self.runtime, &self.journal, self.child, after, limit)
    }

    fn all_events(&self) -> Result<Vec<LiveEvent>, String> {
        read_all_events(&self.runtime, &self.journal, self.child)
    }

    fn peer(&self, session: LiveSessionId) -> Result<&PeerActor, String> {
        self.peer
            .as_ref()
            .filter(|peer| peer.id == session)
            .ok_or_else(|| format!("{session} is not a session this fixture controls"))
    }

    fn peer_completion(
        &self,
        peer: &PeerActor,
        command_id: &CommandId,
    ) -> Result<Option<CommandOutcome>, String> {
        Ok(read_all_events(&self.runtime, &peer.journal, peer.id)?
            .into_iter()
            .find_map(|event| match event.body {
                LiveEventBody::ControlCompleted(outcome) if outcome_id(&outcome) == command_id => {
                    Some(outcome)
                }
                _ => None,
            }))
    }
}

fn outcome_id(outcome: &CommandOutcome) -> &CommandId {
    match outcome {
        CommandOutcome::Applied { command_id }
        | CommandOutcome::Failed { command_id, .. }
        | CommandOutcome::Cancelled { command_id, .. } => command_id,
        CommandOutcome::ToolDenied { command_id, .. } => command_id,
    }
}

fn delivery_verdict(outcome: Option<&CommandOutcome>) -> DeliveryVerdict {
    match outcome {
        Some(CommandOutcome::Applied { .. }) => DeliveryVerdict::Delivered,
        Some(_) => {
            DeliveryVerdict::Refused("the journaled outcome is not an applied one".to_owned())
        }
        None => DeliveryVerdict::Unsettled,
    }
}

impl ChildSessionControl for ActorControl {
    fn snapshot(&self, child: LiveSessionId) -> Result<ChildLifecycleSnapshot, String> {
        if let Some(peer) = self.peer.as_ref().filter(|peer| peer.id == child) {
            let summary = peer.actor.summary().map_err(|error| error.to_string())?;
            return Ok(ChildLifecycleSnapshot {
                active: !peer.actor.exited() && summary.state != LiveSessionState::Ended,
                state: Some(summary.state),
                epoch: i64::try_from(summary.epoch.get()).ok(),
                settled_since_ms: None,
                quiet_since_ms: None,
                provider_fault: None,
            });
        }
        assert_eq!(child, self.child);
        let summary = self.summary();
        let active = !self.actor.exited() && summary.state != LiveSessionState::Ended;
        let ms = |at: OffsetDateTime| u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok();
        let at_ms = || ms(summary.updated_at);
        let settled_at = match summary.state {
            LiveSessionState::Idle => at_ms(),
            LiveSessionState::Failed => summary.failed_at.and_then(ms),
            _ => None,
        };
        let resting = matches!(
            summary.state,
            LiveSessionState::Idle | LiveSessionState::Failed
        );
        let provider_fault = if active && resting {
            const TAIL: u16 = 24;
            let after = EventSeq::new(summary.event_head.get().saturating_sub(u64::from(TAIL)));
            provider_turn_fault(&self.history(after, TAIL)?)
        } else {
            None
        };
        let epoch = i64::try_from(summary.epoch.get()).map_err(|error| error.to_string())?;
        Ok(ChildLifecycleSnapshot {
            active,
            state: Some(summary.state),
            epoch: (!self.epoch_unproved.load(Ordering::SeqCst)).then_some(epoch),
            settled_since_ms: settled_at
                .filter(|_| active)
                .map(|since| since.saturating_sub(self.settled_age_ms.load(Ordering::SeqCst))),
            quiet_since_ms: (active && summary.state == LiveSessionState::Running)
                .then(at_ms)
                .flatten(),
            provider_fault,
        })
    }

    fn command(&self, child: LiveSessionId, body: LiveCommandBody) -> Result<(), String> {
        assert_eq!(child, self.child);
        let kind = body.kind();
        let summary = self.summary();
        let serial = self.issued.fetch_add(1, Ordering::SeqCst);
        let command = LiveCommand {
            command_id: CommandId::new(format!("fixture-control-{serial}"))
                .map_err(|error| error.to_string())?,
            session_id: child,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body,
        };
        let receipt = self
            .runtime
            .block_on(self.actor.command(command))
            .map_err(|error| error.to_string())?;
        let command_id = match receipt {
            CommandReceipt::Accepted { command_id } => command_id,
            other => {
                return Err(format!(
                    "{kind:?} to worker {child} (state {:?}) was not admitted: {other:?}",
                    summary.state
                ))
            }
        };
        let failed =
            self.history(summary.event_head, 256)?
                .into_iter()
                .find_map(|event| match event.body {
                    LiveEventBody::ControlCompleted(CommandOutcome::Failed {
                        command_id: id,
                        error,
                    }) if id == command_id => Some(error),
                    _ => None,
                });
        if let Some(error) = failed {
            return Err(format!(
                "{kind:?} to worker {child} failed: {}: {}",
                error.code, error.message
            ));
        }
        self.commands.lock().expect("commands").push(kind);
        if let Some(after) = self.after_command.lock().expect("after command").as_ref() {
            after(kind);
        }
        Ok(())
    }

    fn prompt(&self, child: LiveSessionId, message: &str) -> Result<(), String> {
        let text = LiveMessage::new(vec![LiveContentBlock::Text(message.to_owned())])
            .map_err(|error| error.to_string())?;
        self.command(child, LiveCommandBody::Prompt { message: text })?;
        Ok(())
    }

    fn rollover(&self, child: LiveSessionId, refusal_event: u64) -> Result<u64, String> {
        assert_eq!(child, self.child);
        let summary = self
            .runtime
            .block_on(self.actor.rollover_fresh(refusal_event))
            .map_err(|error| error.to_string())?;
        Ok(summary.epoch.get())
    }

    fn next_launch_option(
        &self,
        _child: LiveSessionId,
        current: &WorkerLane,
    ) -> Result<Option<WorkerLane>, String> {
        Ok(next_declared_lane(&self.lanes, current))
    }

    fn stop_child(&self, child: LiveSessionId) -> Result<ChildStop, String> {
        assert_eq!(child, self.child);
        self.runtime
            .block_on(self.actor.end())
            .map_err(|error| error.to_string())?;
        Ok(ChildStop::Ended)
    }

    fn await_stop(&self, child: LiveSessionId, _budget: Duration) -> Result<bool, String> {
        Ok(!self.snapshot(child)?.active)
    }

    fn retire_capsule_on_stop(
        &self,
        _session: LiveSessionId,
        _deadline: std::time::Instant,
    ) -> Result<(), String> {
        Ok(())
    }

    fn last_answer(
        &self,
        child: LiveSessionId,
        epoch: Option<i64>,
    ) -> Result<Option<String>, String> {
        let epoch = epoch
            .map(u64::try_from)
            .transpose()
            .map_err(|error| error.to_string())?;
        assert_eq!(child, self.child);
        if self.answer_unreadable.load(Ordering::SeqCst) {
            return Err("the child's history is unreadable".to_owned());
        }
        // Read the requested incarnation through the actual durable history.
        let mut answer = None;
        for event in self.all_events()? {
            if epoch.is_some_and(|epoch| event.epoch.get() != epoch) {
                continue;
            }
            if let LiveEventBody::AssistantMessage(message) = event.body {
                let text = message
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        LiveContentBlock::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                if !text.trim().is_empty() {
                    answer = Some(text);
                }
            }
        }
        Ok(answer)
    }

    fn open_delivery(
        &self,
        child: LiveSessionId,
        body: LiveCommandBody,
    ) -> Result<LiveCommand, String> {
        let peer = self.peer(child)?;
        let summary = peer.actor.summary().map_err(|error| error.to_string())?;
        let serial = self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(LiveCommand {
            command_id: CommandId::new(format!("fixture-report-{serial}"))
                .map_err(|error| error.to_string())?,
            session_id: child,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body,
        })
    }

    fn deliver(&self, command: LiveCommand) -> Result<DeliveryVerdict, String> {
        let peer = self.peer(command.session_id)?;
        let receipt = self
            .runtime
            .block_on(peer.actor.command(command))
            .map_err(|error| error.to_string())?;
        let verdict = match receipt {
            CommandReceipt::Rejected { reason, .. } => {
                DeliveryVerdict::Refused(format!("rejected: {reason:?}"))
            }
            CommandReceipt::Accepted { command_id } => {
                delivery_verdict(self.peer_completion(peer, &command_id)?.as_ref())
            }
            CommandReceipt::Duplicate {
                command_id,
                prior_outcome,
            } => {
                let journaled = match prior_outcome {
                    Some(outcome) => Some(*outcome),
                    None => self.peer_completion(peer, &command_id)?,
                };
                delivery_verdict(journaled.as_ref())
            }
        };
        if self.hold_outcome.load(Ordering::SeqCst) && verdict == DeliveryVerdict::Delivered {
            return Ok(DeliveryVerdict::Unsettled);
        }
        Ok(verdict)
    }

    fn last_result(&self, _child: LiveSessionId) -> Result<Option<TaskResultReport>, String> {
        Ok(None)
    }

    fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String> {
        Ok(Vec::new())
    }
}

/// The rows here are written directly: nothing is provisioned.
struct NoProvisioning;

impl ChildAuthorityProvisioner for NoProvisioning {
    fn provision_child(
        &self,
        _parent_seat: &SeatId,
        _parent_lane: &LaneId,
        _parent_session: &SessionId,
        _child: ChildOpen<'_>,
    ) -> Result<LiveSessionId, String> {
        Err("nothing is provisioned here".to_owned())
    }

    fn seat_worker_profile(
        &self,
        _target_seat: &SeatId,
        _requested: Option<&WorkerLane>,
    ) -> Result<(String, String), String> {
        Err("nothing is provisioned here".to_owned())
    }

    fn provision_child_for_seat(
        &self,
        _parent_seat: &SeatId,
        _parent_lane: &LaneId,
        _parent_session: &SessionId,
        _child: ChildOpen<'_>,
        _target_seat: &SeatId,
    ) -> Result<LiveSessionId, String> {
        Err("nothing is provisioned here".to_owned())
    }

    fn preflight_child(
        &self,
        _parent_seat: &SeatId,
        _parent_lane: &LaneId,
        _parent_session: &SessionId,
        _child_project: &ProjectId,
        _target_seat: Option<&SeatId>,
        _launch: Option<&WorkerLane>,
    ) -> Result<(), String> {
        Err("nothing is provisioned here".to_owned())
    }
}

fn governed_parent_run() -> RunId {
    RunId::new("run:live:00000000-0000-4000-8000-0000000000a0").expect("parent run")
}

/// The durable state the parent bridge leaves in production: the parent's
/// lane and run rows, and the operator-accepted plan delegation requires.
fn seed_accepted_parent_plan(ledger: &Mutex<Ledger>) {
    let seeded_at = OffsetDateTime::UNIX_EPOCH;
    let mut guard = ledger.lock().expect("ledger lock");
    let lane_id = LaneId::new("lane.odin").expect("lane");
    create_lane(
        guard.connection(),
        &NewLane {
            lane_id: lane_id.clone(),
            seat_id: parent_seat(),
            project_id: None,
            template_id: "template:dev".to_owned(),
            backend: "local_omp".to_owned(),
            created_by: "operator".to_owned(),
            created_at: seeded_at,
            retained: false,
        },
    )
    .expect("parent lane row");
    let parent_run = governed_parent_run();
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
            created_at: seeded_at,
        },
    )
    .expect("parent run row");
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
            seeded_at,
        )
        .expect("parent plan");
    guard
        .accept_plan(&parent_run, plan.revision, "operator:fixture", seeded_at)
        .expect("accept parent plan");
}

fn lane(model: &str) -> WorkerLane {
    WorkerLane {
        provider: "gateway".to_owned(),
        model: model.to_owned(),
    }
}

fn parent_seat() -> SeatId {
    SeatId::new("seat.architect").expect("seat")
}

/// One delegated worker on a real actor, launched on `gateway/glm-flash`
/// with `gateway/kimi-k28` declared after it, and its owner.
struct Harness {
    backend: Arc<ChildBackend>,
    control: Arc<ActorControl>,
    owner: Arc<GovernedTaskOwner>,
    links: DelegationLinkLedger,
    parent: SessionId,
    roots: Vec<PathBuf>,
    // Last: the actor's task lives on it.
    runtime: tokio::runtime::Runtime,
}

impl Drop for Harness {
    fn drop(&mut self) {
        for root in &self.roots {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

impl Harness {
    fn new() -> Self {
        Self::build(false, false)
    }

    /// The child's parent is a second real actor, so a report to it is
    /// delivered, journaled and settled by that actor.
    fn with_worker_parent() -> Self {
        Self::build(true, false)
    }

    /// Seeds approval and project scope so creation reaches the concurrency check.
    fn governed() -> Self {
        Self::build(false, true)
    }

    fn build(worker_parent: bool, governed: bool) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let backend = Arc::new(ChildBackend::default());
        let bridge = Arc::clone(&backend);
        let fixture = runtime.block_on(spawn_fixture_with_control(move |_, _| {
            bridge as Arc<dyn LiveControlBackend>
        }));
        let child = fixture.session_id;
        let root = std::env::temp_dir().join(format!(
            "odin-omp-provider-failure-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::SeqCst)
        ));
        let links = DelegationLinkLedger::open(root.join("links")).expect("link ledger");
        let peer_fixture = worker_parent.then(|| {
            let backend = Arc::new(ChildBackend::default());
            let bridge = Arc::clone(&backend);
            let fixture = runtime.block_on(spawn_fixture_with_control(move |_, _| {
                bridge as Arc<dyn LiveControlBackend>
            }));
            (fixture, backend)
        });
        let parent = match &peer_fixture {
            Some((fixture, _)) => {
                let id = fixture.session_id.to_string();
                SessionId::new(id.as_str()).expect("worker parent")
            }
            None => SessionId::new("00000000-0000-4000-8000-0000000000a1").expect("parent"),
        };
        let mut roots = vec![root.clone(), fixture.root.clone()];
        let peer = peer_fixture.map(|(fixture, backend)| {
            roots.push(fixture.root.clone());
            PeerActor {
                actor: fixture.handle.clone(),
                id: fixture.session_id,
                journal: Arc::clone(&fixture.ledger) as Arc<dyn LiveLedger>,
                backend,
            }
        });
        let command = CommandId::new(format!("odin.task.create:{child}")).expect("command");
        links
            .persist(&DelegationLink {
                schema: DELEGATION_LINK_SCHEMA.to_owned(),
                child,
                parent: parent.clone(),
                parent_seat: Some(parent_seat()),
                parent_run: RunId::new("run:live:00000000-0000-4000-8000-0000000000a0")
                    .expect("parent run"),
                child_run: GovernedTaskOwner::child_run_for(&child).expect("child run"),
                command,
                project: ProjectId::new("project.odin").expect("project"),
                provider: "gateway".to_owned(),
                model: "glm-flash".to_owned(),
                prompt_digest: Digest::hash(b"Perform one bounded task."),
                depth: 1,
                phase: DelegationPhase::Running,
                created_at_ms: GovernedTaskOwner::clock_ms(),
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
                assignment: "Perform one bounded task.".to_owned(),
                rollover_admissions: 0,
                pending_report: None,
            })
            .expect("running row");
        let control = Arc::new(ActorControl {
            runtime: runtime.handle().clone(),
            actor: fixture.handle.clone(),
            child,
            journal: Arc::clone(&fixture.ledger) as Arc<dyn LiveLedger>,
            lanes: vec![lane("glm-flash"), lane("kimi-k28")],
            issued: AtomicU64::new(0),
            commands: Mutex::new(Vec::new()),
            after_command: Mutex::new(None),
            peer,
            opened: AtomicU64::new(0),
            hold_outcome: AtomicBool::new(false),
            answer_unreadable: AtomicBool::new(false),
            epoch_unproved: AtomicBool::new(false),
            settled_age_ms: AtomicU64::new(0),
        });
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger")));
        let mut approved_projects = BTreeMap::new();
        if governed {
            seed_accepted_parent_plan(&ledger);
            approved_projects.insert(
                ProjectId::new("project.odin").expect("project"),
                root.join("odin"),
            );
        }
        let owner = Arc::new(GovernedTaskOwner::new(
            Arc::new(NoProvisioning),
            control.clone(),
            links.clone(),
            ledger,
            DelegationGovernance {
                provider: "gateway".to_owned(),
                model: "glm-flash".to_owned(),
                max_children_per_session: 1,
                max_prompt_bytes: 4_096,
                approved_projects,
                operation_bindings: BTreeMap::new(),
            },
        ));
        Self {
            backend,
            control,
            owner,
            links,
            parent,
            roots,
            runtime,
        }
    }

    fn child(&self) -> LiveSessionId {
        self.control.child
    }

    /// A second delegation from the child's parent, over the same project.
    fn create_request(&self, prompt: &str) -> TaskCreateRequest {
        TaskCreateRequest {
            caller_session: self.parent.clone(),
            caller_run: governed_parent_run(),
            caller_seat: parent_seat(),
            caller_lane: LaneId::new("lane.odin").expect("lane"),
            project: ProjectId::new("project.odin").expect("project"),
            prompt: prompt.to_owned(),
            title: None,
            target_seat: None,
            launch: None,
        }
    }

    /// Reports the resting child's settled instant as `ms` old.
    fn age_settled_child(&self, ms: u64) {
        self.control.settled_age_ms.store(ms, Ordering::SeqCst);
    }

    fn settled(&self) -> Vec<SettledChild> {
        self.owner
            .settled_children(&parent_seat(), WINDOW_MS)
            .expect("settled children")
    }

    /// The worker-parent report pass; the conversation seat is a different
    /// seat from the child's parent.
    fn report_up(&self) -> Vec<LiveSessionId> {
        self.owner
            .report_to_worker_parents(
                &SeatId::new("seat.conversation").expect("conversation seat"),
                WINDOW_MS,
            )
            .expect("worker-parent report pass")
    }

    /// What the worker parent's actor was delivered, in order.
    fn parent_messages(&self) -> Vec<String> {
        self.control
            .peer
            .as_ref()
            .expect("a worker parent")
            .backend
            .messages
            .lock()
            .expect("messages")
            .clone()
    }

    fn results_journaled(&self) -> usize {
        self.control
            .all_events()
            .expect("child history")
            .iter()
            .filter(|event| matches!(event.body, LiveEventBody::Result(_)))
            .count()
    }

    fn state(&self) -> LiveSessionState {
        self.control.summary().state
    }

    fn row(&self) -> DelegationLink {
        self.links.load(&self.child()).expect("load").expect("row")
    }

    fn ingest(&self, frame: serde_json::Value, journal_failure: Option<TypedFrameFailure>) {
        let decoded = crate::frames::RpcFrameDecoder::default()
            .push_physical_line(format!("{frame}\n").as_bytes())
            .expect("pinned frame decodes")
            .expect("one whole frame");
        self.runtime
            .block_on(self.control.actor.ingest_omp(ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure,
            }))
            .expect("the actor journals the frame");
    }

    /// Emits a failed assistant message in `agent_end`, optionally also in `turn_end`.
    fn provider_failed_turn(&self, (status, error): (u16, &str), round: bool) {
        let failed = json!({
            "role": "assistant",
            "stopReason": "error",
            "errorStatus": status,
            "errorMessage": error,
            "content": [{"type": "text", "text": "Partial answer from a failed request."}]
        });
        self.ingest(json!({"type": "agent_start"}), None);
        if round {
            self.ingest(json!({"type": "turn_end", "message": failed.clone()}), None);
        }
        self.ingest(
            json!({
                "type": "agent_end",
                "isTerminal": true,
                "yielded": true,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                    failed
                ]
            }),
            None,
        );
    }

    fn failed_message((status, error): (u16, &str), text: &str) -> serde_json::Value {
        json!({
            "role": "assistant",
            "stopReason": "error",
            "errorStatus": status,
            "errorMessage": error,
            "content": [{"type": "text", "text": text}]
        })
    }

    /// The same failed turn, but its partial text reached the journal as the
    /// assistant message OMP ended before the terminal `agent_end`.
    fn provider_failed_turn_journaling_partial(&self, fault: (u16, &str), text: &str) {
        let failed = Self::failed_message(fault, text);
        self.ingest(json!({"type": "agent_start"}), None);
        self.ingest(
            json!({"type": "message_end", "message": failed.clone()}),
            None,
        );
        self.ingest(json!({"type": "turn_end", "message": failed.clone()}), None);
        self.ingest(
            json!({
                "type": "agent_end",
                "isTerminal": true,
                "yielded": true,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                    failed
                ]
            }),
            None,
        );
    }

    /// A message OMP ends after the session already settled Failed.
    fn late_partial(&self, fault: (u16, &str), text: &str) {
        self.ingest(
            json!({"type": "message_end", "message": Self::failed_message(fault, text)}),
            None,
        );
    }

    fn answered_turn(&self, text: &str) {
        let answer = json!({
            "role": "assistant",
            "stopReason": "stop",
            "content": [{"type": "text", "text": text}]
        });
        self.ingest(json!({"type": "agent_start"}), None);
        self.ingest(
            json!({"type": "message_end", "message": answer.clone()}),
            None,
        );
        self.ingest(
            json!({
                "type": "agent_end",
                "isTerminal": true,
                "messages": [
                    {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                    answer
                ]
            }),
            None,
        );
    }

    /// Odin's extension refused the turn's request before it left; the
    /// bridge authenticated the refusal under the current binding.
    fn context_refused_turn(&self, code: &str) {
        let epoch = self.control.summary().epoch;
        self.ingest(json!({"type": "agent_start"}), None);
        self.ingest(
            json!({
                "type": "extension_error",
                "extensionPath": "/nix/store/trusted-odin-extension/index.ts",
                "event": "before_provider_request",
                "error": "odin.context_refusal.v1|{...}"
            }),
            Some(TypedFrameFailure {
                code: code.to_owned(),
                detail: "request requires 44540 byte tokens, exceeding the declared window 32768"
                    .to_owned(),
                epoch: Some(epoch),
            }),
        );
    }

    fn fault_event(&self, kind: ProviderFaultKind) -> u64 {
        let fault = self
            .control
            .snapshot(self.child())
            .expect("snapshot")
            .provider_fault
            .expect("a fault Odin answers");
        assert_eq!(fault.kind, kind);
        fault.event
    }

    fn recover(&self) -> StallPass {
        self.owner
            .recover_stalled_children(Duration::from_secs(300))
            .expect("recovery pass")
    }

    /// The commands the actor applied since the last drain.
    fn applied(&self) -> Vec<LiveCommandKind> {
        std::mem::take(&mut *self.control.commands.lock().expect("commands"))
    }

    fn set_models(&self) -> Vec<String> {
        self.backend.set_models.lock().expect("set models").clone()
    }

    /// Settles the resumed turn without a new message (an operator turn
    /// abort), so the journal tail still ends on the answered fault.
    fn settle_without_answer(&self) {
        self.control
            .command(
                self.child(),
                LiveCommandBody::Abort {
                    scope: odin_domain::huginn::AbortScope::CurrentTurn,
                },
            )
            .expect("turn abort");
        assert_eq!(self.state(), LiveSessionState::Idle);
        self.applied();
    }

    /// The explicit parent stop lands inside the first applied `kind`.
    fn stop_inside(&self, kind: LiveCommandKind) {
        let owner = Arc::downgrade(&self.owner);
        let request = TaskControlRequest {
            caller_session: self.parent.clone(),
            caller_seat: parent_seat(),
            child: self.child(),
            control: TaskControl::Stop,
        };
        *self.control.after_command.lock().expect("after command") =
            Some(Box::new(move |applied: LiveCommandKind| {
                if applied == kind {
                    owner
                        .upgrade()
                        .expect("owner")
                        .control_task(request.clone())
                        .expect("explicit parent stop");
                }
            }));
    }
}

#[test]
fn a_failed_provider_stall_is_restarted_resumed_moved_and_ended_within_its_budget() {
    let harness = Harness::new();
    let child = harness.child();

    harness.provider_failed_turn(STALL, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let first = harness.fault_event(ProviderFaultKind::Stall);
    let pass = harness.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(pass.resumed, [child], "the failed stall is resumed");
    assert!(pass.switched.is_empty() && pass.ended.is_empty() && pass.refused.is_empty());
    assert_eq!(
        harness.applied(),
        [LiveCommandKind::Restart, LiveCommandKind::Prompt],
        "the admitted restart comes before the continuation"
    );
    assert_eq!(harness.state(), LiveSessionState::Running);
    let row = harness.row();
    assert_eq!(row.stall_retries, 1);
    assert_eq!(row.stalls, ["gateway/glm-flash"]);
    assert_eq!(row.handled_stall_event, Some(first));
    assert!(
        harness.set_models().is_empty(),
        "one stall stays on its lane"
    );

    // The same error, read again from the tail, is answered once.
    harness.settle_without_answer();
    assert_eq!(harness.fault_event(ProviderFaultKind::Stall), first);
    let again = harness.recover();
    assert!(again.resumed.is_empty() && again.switched.is_empty() && again.failures.is_empty());
    assert!(harness.applied().is_empty());
    assert_eq!(harness.row().stall_retries, 1);

    harness.provider_failed_turn(STALL, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let pass = harness.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(pass.resumed, [child]);
    assert_eq!(
        pass.switched,
        [LaneSwitch {
            child,
            parent_seat: Some(parent_seat()),
            from: lane("glm-flash"),
            to: lane("kimi-k28"),
            cause: ProviderFaultKind::Stall,
        }],
        "a repeated stall moves the worker to the next declared lane"
    );
    assert_eq!(
        harness.applied(),
        [
            LiveCommandKind::Restart,
            LiveCommandKind::SetModel,
            LiveCommandKind::Prompt
        ]
    );
    assert_eq!(harness.set_models(), ["gateway/kimi-k28"]);

    harness.provider_failed_turn(STALL, true);
    let pass = harness.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(pass.resumed, [child], "the switch earns one more retry");
    assert!(pass.switched.is_empty(), "a worker falls back once");
    assert_eq!(
        harness.set_models(),
        ["gateway/kimi-k28", "gateway/kimi-k28"],
        "the restarted incarnation is put back on the row's lane"
    );

    harness.provider_failed_turn(STALL, true);
    let pass = harness.recover();
    assert!(pass.resumed.is_empty());
    assert_eq!(
        pass.ended,
        [StalledOut {
            child,
            parent_seat: Some(parent_seat()),
            stalls: vec![
                "gateway/glm-flash".to_owned(),
                "gateway/glm-flash".to_owned(),
                "gateway/kimi-k28".to_owned(),
                "gateway/kimi-k28".to_owned(),
            ],
        }]
    );
    assert_eq!(harness.backend.restarts.load(Ordering::SeqCst), 3);
    assert_eq!(harness.row().phase, DelegationPhase::Ended);
    assert_eq!(harness.state(), LiveSessionState::Ended);
}

#[test]
fn a_failed_provider_refusal_is_restarted_onto_the_next_lane_with_lineage() {
    for (refusal, kind, cause) in [
        (USAGE_LIMIT, ProviderFaultKind::UsageLimit, "usage_limit"),
        (REJECTED_KEY, ProviderFaultKind::RejectedKey, "rejected_key"),
    ] {
        let harness = Harness::new();
        let child = harness.child();
        harness.provider_failed_turn(refusal, true);
        assert_eq!(harness.state(), LiveSessionState::Failed);
        let event = harness.fault_event(kind);
        let pass = harness.recover();
        assert!(pass.failures.is_empty(), "{:?}", pass.failures);
        assert!(
            pass.refused.is_empty() && pass.ended.is_empty(),
            "a refused lane is rotated, not the task ended"
        );
        assert_eq!(
            pass.switched,
            [LaneSwitch {
                child,
                parent_seat: Some(parent_seat()),
                from: lane("glm-flash"),
                to: lane("kimi-k28"),
                cause: kind,
            }]
        );
        assert_eq!(
            harness.applied(),
            [
                LiveCommandKind::Restart,
                LiveCommandKind::SetModel,
                LiveCommandKind::Prompt
            ],
            "restart, then the lane, then the next request"
        );
        assert_eq!(harness.set_models(), ["gateway/kimi-k28"]);
        assert_eq!(harness.state(), LiveSessionState::Running);
        let row = harness.row();
        assert_eq!(row.switched_to, Some(lane("kimi-k28")));
        assert_eq!(row.stall_retries, 0, "a refusal is not a stall retry");
        assert_eq!(
            row.refusals,
            [LaneRefusal {
                lane: "gateway/glm-flash".to_owned(),
                cause: cause.to_owned(),
                event,
                next: Some("gateway/kimi-k28".to_owned()),
            }]
        );

        harness.settle_without_answer();
        let again = harness.recover();
        assert!(again.switched.is_empty() && again.refused.is_empty());
        assert!(harness.applied().is_empty(), "one refusal is answered once");

        harness.provider_failed_turn(USAGE_LIMIT, true);
        let pass = harness.recover();
        assert!(pass.switched.is_empty());
        assert_eq!(
            pass.refused,
            [RefusedOut {
                child,
                parent_seat: Some(parent_seat()),
                lane: lane("kimi-k28"),
                cause: ProviderFaultKind::UsageLimit,
            }]
        );
        assert!(
            harness.applied().is_empty(),
            "an ended child is not restarted first"
        );
        assert_eq!(harness.backend.restarts.load(Ordering::SeqCst), 1);
        let row = harness.row();
        assert_eq!(row.phase, DelegationPhase::Ended);
        assert_eq!(row.refusals.len(), 2);
        assert_eq!(row.refusals[1].next, None);
        assert_eq!(harness.state(), LiveSessionState::Ended);
    }
}

#[test]
fn a_provider_overflow_rotates_while_an_authenticated_refusal_keeps_its_route() {
    let provider = Harness::new();
    provider.provider_failed_turn(PROVIDER_OVERFLOW, true);
    assert_eq!(provider.state(), LiveSessionState::Failed);
    provider.fault_event(ProviderFaultKind::ContextOverflow);
    let pass = provider.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(pass.switched.len(), 1);
    assert_eq!(pass.switched[0].cause, ProviderFaultKind::ContextOverflow);
    assert_eq!(pass.switched[0].to, lane("kimi-k28"));
    assert!(
        provider
            .backend
            .rollovers
            .lock()
            .expect("rollovers")
            .is_empty(),
        "a provider-reported overflow is a lane refusal, never the typed rollover"
    );
    assert_eq!(
        provider.applied(),
        [
            LiveCommandKind::Restart,
            LiveCommandKind::SetModel,
            LiveCommandKind::Prompt
        ]
    );
    assert_eq!(provider.row().rollover_admissions, 0);

    let refused = Harness::new();
    refused.context_refused_turn("context_refusal.window_exceeded");
    assert_eq!(refused.state(), LiveSessionState::Failed);
    let event = refused.fault_event(ProviderFaultKind::ContextOverflow);
    let pass = refused.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert!(pass.switched.is_empty() && pass.refused.is_empty() && pass.ended.is_empty());
    assert_eq!(
        *refused.backend.rollovers.lock().expect("rollovers"),
        [event]
    );
    assert!(
        refused.applied().is_empty(),
        "the rollover is no client command"
    );
    assert_eq!(refused.backend.restarts.load(Ordering::SeqCst), 0);
    let row = refused.row();
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.rollover_admissions, 1);
    assert_eq!(row.refusals[0].next, Some("gateway/glm-flash".to_owned()));
    assert_eq!(refused.state(), LiveSessionState::Idle);
    assert_eq!(refused.control.summary().epoch.get(), 2);

    let guarded = Harness::new();
    guarded.context_refused_turn("context_refusal.model_identity_mismatch");
    guarded.fault_event(ProviderFaultKind::ContextGuard);
    let pass = guarded.recover();
    assert_eq!(pass.refused.len(), 1);
    assert_eq!(pass.refused[0].cause, ProviderFaultKind::ContextGuard);
    assert!(guarded.applied().is_empty());
    assert_eq!(guarded.backend.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(guarded.row().phase, DelegationPhase::Ended);
}

#[test]
fn a_parent_stop_during_the_restart_of_a_failed_child_wins() {
    for fault in [STALL, USAGE_LIMIT] {
        let harness = Harness::new();
        harness.provider_failed_turn(fault, true);
        harness.stop_inside(LiveCommandKind::Restart);
        let pass = harness.recover();
        assert!(
            pass.failures.is_empty(),
            "parent stop is not a recovery failure"
        );
        assert!(pass.resumed.is_empty() && pass.switched.is_empty());
        assert!(pass.ended.is_empty() && pass.refused.is_empty());
        assert_eq!(harness.applied(), [LiveCommandKind::Restart]);
        assert_eq!(harness.backend.prompts.load(Ordering::SeqCst), 0);
        assert!(harness.set_models().is_empty());
        let row = harness.row();
        assert_eq!(row.phase, DelegationPhase::Ended, "the parent stop wins");
        assert_eq!(row.stall_retries, 0, "a stopped recovery earns no retry");
        assert!(row.stalls.is_empty() && row.refusals.is_empty() && row.switched_to.is_none());
        assert_eq!(harness.state(), LiveSessionState::Ended);
        let again = harness.recover();
        assert!(again.resumed.is_empty() && again.failures.is_empty());
        assert!(harness.applied().is_empty());
    }
}

#[test]
fn a_failed_outage_is_not_restarted_or_rotated() {
    let harness = Harness::new();
    harness.provider_failed_turn(OUTAGE, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    assert_eq!(
        harness
            .control
            .snapshot(harness.child())
            .expect("snapshot")
            .provider_fault,
        None
    );
    let pass = harness.recover();
    assert!(pass.resumed.is_empty() && pass.switched.is_empty() && pass.failures.is_empty());
    assert!(pass.ended.is_empty() && pass.refused.is_empty());
    assert!(harness.applied().is_empty());
    assert_eq!(harness.backend.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let row = harness.row();
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.handled_stall_event, None);
}

#[test]
fn a_failure_only_in_the_terminal_message_is_answered_like_any_other() {
    let harness = Harness::new();
    harness.provider_failed_turn(USAGE_LIMIT, false);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    harness.fault_event(ProviderFaultKind::UsageLimit);
    let pass = harness.recover();
    assert!(pass.failures.is_empty(), "{:?}", pass.failures);
    assert_eq!(pass.switched.len(), 1);
    assert_eq!(pass.switched[0].cause, ProviderFaultKind::UsageLimit);
    assert_eq!(
        harness.applied(),
        [
            LiveCommandKind::Restart,
            LiveCommandKind::SetModel,
            LiveCommandKind::Prompt
        ]
    );
}

#[test]
fn a_failed_outage_with_no_text_is_published_as_failed_without_a_result_or_a_retry() {
    let harness = Harness::new();
    harness.provider_failed_turn(OUTAGE, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    assert_eq!(
        harness
            .control
            .snapshot(harness.child())
            .expect("snapshot")
            .provider_fault,
        None,
        "an outage is not a fault Odin answers"
    );
    assert_eq!(
        harness.control.last_answer(
            harness.child(),
            Some(
                harness
                    .control
                    .summary()
                    .epoch
                    .get()
                    .try_into()
                    .expect("fixture epoch")
            )
        ),
        Ok(None),
        "the turn journaled no text"
    );

    let settled = harness.settled();
    assert_eq!(settled.len(), 1, "the failed child is published");
    assert_eq!(settled[0].child, harness.child());
    assert!(settled[0].failed);
    assert_eq!(
        harness.settled()[0].key,
        settled[0].key,
        "the same failure is named the same way on every scan"
    );

    assert_eq!(
        harness.results_journaled(),
        0,
        "a failure journals no Result"
    );
    let row = harness.row();
    assert_eq!(row.phase, DelegationPhase::Running);
    assert_eq!(row.learning_result_sequence, None);
    assert_eq!(row.learning_capture_sequence, None);

    let pass = harness.recover();
    assert!(pass.resumed.is_empty() && pass.switched.is_empty() && pass.failures.is_empty());
    assert!(pass.ended.is_empty() && pass.refused.is_empty());
    assert!(harness.applied().is_empty());
    assert_eq!(harness.backend.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.backend.prompts.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness.state(),
        LiveSessionState::Failed,
        "the child is not stopped"
    );
}

/// Partial work survives as failed context: the text the failed turn
/// journaled stays the child's last answer (failed Pod reports keep it too),
/// the conversation report carries it as the failed child's, under a key
/// that is not the digest a successful answer with the same prose would
/// take, and prose arriving later in the same incarnation is not a new
/// failure.
#[test]
fn partial_text_of_a_failed_turn_is_failed_context_under_a_failure_key() {
    let harness = Harness::new();
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    assert_eq!(
        harness.control.last_answer(
            harness.child(),
            Some(
                harness
                    .control
                    .summary()
                    .epoch
                    .get()
                    .try_into()
                    .expect("fixture epoch")
            )
        ),
        Ok(Some(PARTIAL.to_owned())),
        "failed partial work is not cleared"
    );

    let settled = harness.settled();
    assert_eq!(settled.len(), 1);
    assert!(settled[0].failed);
    assert!(settled[0].answer.contains(PARTIAL));
    assert_ne!(
        settled[0].key,
        success_key(PARTIAL),
        "a failure is never named like a successful answer"
    );
    assert_eq!(harness.results_journaled(), 0);
    assert_eq!(harness.row().learning_result_sequence, None);
    assert_eq!(harness.row().learning_capture_sequence, None);

    harness.late_partial(OUTAGE, "different prose of the same failed incarnation");
    let later = harness.settled();
    assert_eq!(later.len(), 1);
    assert!(later[0].failed);
    assert_eq!(
        later[0].key, settled[0].key,
        "changing prose is not a new failure"
    );
}

#[test]
fn a_failed_child_is_delivered_once_to_its_worker_parent_as_failed_context() {
    let harness = Harness::with_worker_parent();
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    let key = harness.settled()[0].key.clone();

    assert_eq!(harness.report_up(), [harness.child()]);
    let delivered = harness.parent_messages();
    assert_eq!(delivered.len(), 1);
    assert!(delivered[0].contains(PARTIAL));
    let row = harness.row();
    assert_eq!(row.reported_answer.as_deref(), Some(key.as_str()));
    assert_eq!(row.pending_report, None);
    assert_eq!(row.learning_result_sequence, None);
    assert_eq!(row.learning_capture_sequence, None);
    assert_eq!(row.phase, DelegationPhase::Running);

    assert!(harness.report_up().is_empty(), "one failure, one delivery");
    assert_eq!(harness.parent_messages().len(), 1);
    assert_eq!(harness.control.opened.load(Ordering::SeqCst), 1);

    assert_eq!(harness.state(), LiveSessionState::Failed);
    assert!(harness.applied().is_empty());
    assert_eq!(harness.backend.restarts.load(Ordering::SeqCst), 0);
    assert_eq!(harness.results_journaled(), 0);

    let answered = Harness::with_worker_parent();
    answered.answered_turn(PARTIAL);
    assert_eq!(answered.report_up(), [answered.child()]);
    let success = answered.parent_messages();
    assert_eq!(success.len(), 1);
    assert_ne!(
        without_child(&delivered[0], harness.child()),
        without_child(&success[0], answered.child()),
        "a failed child's report is not a successful task result"
    );
    assert_eq!(
        answered.row().reported_answer,
        Some(success_key(PARTIAL)),
        "a successful answer keeps its digest key"
    );
}

/// The recorded report attempt stays immutable. A delivery whose outcome is
/// not durably readable is kept under its exact journal identity; prose
/// that arrives meanwhile does not rename the failure, and the next pass
/// replays the recorded command, settles it, and delivers nothing twice.
#[test]
fn an_unsettled_failed_report_is_replayed_under_its_recorded_identity() {
    let harness = Harness::with_worker_parent();
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);

    harness.control.hold_outcome.store(true, Ordering::SeqCst);
    assert!(
        harness.report_up().is_empty(),
        "an unsettled attempt is not delivered"
    );
    let recorded = harness
        .row()
        .pending_report
        .expect("the attempt is recorded durably");
    assert_eq!(harness.row().reported_answer, None);
    assert_eq!(
        harness.parent_messages().len(),
        1,
        "the parent's actor took it"
    );

    harness.late_partial(OUTAGE, "prose that arrives while the attempt is pending");
    harness.control.hold_outcome.store(false, Ordering::SeqCst);
    assert_eq!(harness.report_up(), [harness.child()]);
    let row = harness.row();
    assert_eq!(row.pending_report, None);
    assert_eq!(row.reported_answer, Some(recorded.key.clone()));
    assert_eq!(
        harness.parent_messages().len(),
        1,
        "the replay is the recorded command, not a second delivery"
    );
    assert_eq!(
        harness.control.opened.load(Ordering::SeqCst),
        1,
        "no fresh attempt was opened for the same failure"
    );
    assert!(harness.report_up().is_empty());
    assert_eq!(harness.parent_messages().len(), 1);
}

/// Recovery epoch: a real restart reclaims the child's epoch. A child that
/// fails again in the new incarnation is a new failure — reported again
/// under a distinct key — even over identical partial prose, while the
/// restarted child, running, publishes nothing.
#[test]
fn a_restarted_child_that_fails_again_is_a_distinct_failure() {
    let harness = Harness::with_worker_parent();
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    let first_epoch = harness.control.summary().epoch.get();
    let first = harness.settled();
    assert_eq!(first.len(), 1);
    assert!(first[0].failed);
    assert_eq!(harness.report_up(), [harness.child()]);
    assert_eq!(harness.parent_messages().len(), 1);

    harness
        .control
        .command(harness.child(), LiveCommandBody::Restart)
        .expect("the actor admits the restart");
    assert_eq!(harness.state(), LiveSessionState::Idle);
    assert!(
        harness.settled().is_empty(),
        "the new incarnation has not answered; old failed text is not a success"
    );
    assert!(harness.report_up().is_empty());
    harness
        .control
        .prompt(harness.child(), "Continue the bounded task.")
        .expect("the restarted child is resumed");
    assert_eq!(harness.state(), LiveSessionState::Running);
    assert!(harness.control.summary().epoch.get() > first_epoch);
    assert!(
        harness.settled().is_empty(),
        "a working child is not published"
    );
    assert!(harness.report_up().is_empty());

    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let second = harness.settled();
    assert_eq!(second.len(), 1);
    assert!(second[0].failed);
    assert_ne!(
        second[0].key, first[0].key,
        "a new incarnation's failure is not the old one"
    );
    assert_eq!(harness.report_up(), [harness.child()]);
    assert_eq!(harness.parent_messages().len(), 2);
    assert_eq!(harness.row().reported_answer, Some(second[0].key.clone()));
    assert!(harness.report_up().is_empty());
    assert_eq!(harness.parent_messages().len(), 2);
}

/// Missing history or epoch must not turn a failed child into a successful report.
#[test]
fn an_unprovable_failure_is_never_reported_as_a_successful_answer() {
    let unreadable = Harness::with_worker_parent();
    unreadable.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    unreadable
        .control
        .answer_unreadable
        .store(true, Ordering::SeqCst);
    assert!(unreadable.settled().iter().all(|child| child.failed));
    unreadable.report_up();
    let row = unreadable.row();
    assert_eq!(row.learning_result_sequence, None);
    assert_eq!(row.learning_capture_sequence, None);
    assert_eq!(unreadable.results_journaled(), 0);

    let unproved = Harness::with_worker_parent();
    unproved.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    unproved
        .control
        .epoch_unproved
        .store(true, Ordering::SeqCst);
    let settled = unproved.settled();
    assert_eq!(settled.len(), 1);
    assert!(settled[0].failed);
    assert_eq!(settled[0].key, "failed-unproved");
    assert_eq!(unproved.report_up(), [unproved.child()]);
    assert_eq!(unproved.parent_messages().len(), 1);
    assert!(
        unproved.parent_messages()[0].contains("failing"),
        "an unproved failure is not delivered as a successful answer: {:?}",
        unproved.parent_messages()
    );
    assert!(unproved.report_up().is_empty());
    assert_eq!(
        unproved.row().reported_answer.as_deref(),
        Some("failed-unproved")
    );
    assert_eq!(unproved.row().pending_report, None);
}

#[test]
fn an_unproved_failure_reports_once_and_a_failure_after_restart_reports_again() {
    let harness = Harness::with_worker_parent();
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    harness.control.epoch_unproved.store(true, Ordering::SeqCst);
    assert_eq!(harness.report_up(), [harness.child()]);
    assert_eq!(harness.parent_messages().len(), 1);
    harness
        .control
        .epoch_unproved
        .store(false, Ordering::SeqCst);
    harness
        .owner
        .restart_failed_child(&harness.row(), None)
        .expect("restart");
    harness
        .control
        .prompt(harness.child(), "Continue the bounded task.")
        .expect("resume");
    harness.provider_failed_turn_journaling_partial(OUTAGE, PARTIAL);
    assert_eq!(harness.report_up(), [harness.child()]);
    assert_eq!(harness.parent_messages().len(), 2);
    assert!(harness.report_up().is_empty());
}
#[test]
fn healthy_working_and_successful_children_keep_their_reports() {
    let fresh = Harness::with_worker_parent();
    assert!(
        fresh.settled().is_empty(),
        "an idle child with no answer has nothing to report"
    );
    assert!(fresh.report_up().is_empty());

    let working = Harness::with_worker_parent();
    working.ingest(json!({"type": "agent_start"}), None);
    assert_eq!(working.state(), LiveSessionState::Running);
    assert!(working.settled().is_empty());
    assert!(working.report_up().is_empty());
    assert!(working.parent_messages().is_empty());

    let done = Harness::with_worker_parent();
    done.answered_turn(PARTIAL);
    assert_eq!(done.state(), LiveSessionState::Idle);
    assert_eq!(done.results_journaled(), 1);
    let settled = done.settled();
    assert_eq!(settled.len(), 1);
    assert!(!settled[0].failed);
    assert_eq!(settled[0].key, success_key(PARTIAL));
    assert_eq!(settled[0].answer, PARTIAL);
    assert_eq!(done.report_up(), [done.child()]);
    assert_eq!(done.row().reported_answer, Some(success_key(PARTIAL)));
    assert!(done.report_up().is_empty());
    assert_eq!(done.parent_messages().len(), 1);
}

/// Ages the settled instant because the owner's wall clock cannot be advanced by the test.
#[test]
fn a_failed_child_is_retired_by_the_existing_idle_budget() {
    let harness = Harness::new();
    let child = harness.child();
    harness.provider_failed_turn(OUTAGE, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let snapshot = harness.control.snapshot(child).expect("snapshot");
    assert!(snapshot.active);
    assert!(
        snapshot.settled_since_ms.is_some(),
        "a failed child is settled, from the instant it failed"
    );

    let (idle, hard) = (Duration::from_secs(300), Duration::from_secs(3_600));
    let (retired, failures) = harness
        .owner
        .retire_timed_out_children(hard, Some(idle))
        .expect("retirement pass");
    assert!(retired.is_empty() && failures.is_empty());
    assert_eq!(harness.row().phase, DelegationPhase::Running);
    assert_eq!(harness.state(), LiveSessionState::Failed);

    harness.age_settled_child(300_000 + 1_000);
    let (retired, failures) = harness
        .owner
        .retire_timed_out_children(hard, Some(idle))
        .expect("retirement pass");
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(retired, [child], "the failed child is ended by the budget");
    assert_eq!(harness.row().phase, DelegationPhase::Ended);
    assert!(
        !harness.control.snapshot(child).expect("snapshot").active,
        "its actor is torn down"
    );
}

/// Reaching `binding_missing` shows that the concurrency check admitted a new child.
#[test]
fn a_failed_child_yields_its_place_to_a_new_delegation_after_the_grace() {
    use super::owner::SETTLED_CHILD_YIELD_MS;

    let harness = Harness::governed();
    let child = harness.child();
    harness.provider_failed_turn(OUTAGE, true);
    assert_eq!(harness.state(), LiveSessionState::Failed);
    let kind_of = |failure: TaskToolFailure| failure.kind;
    let request = || harness.create_request("Implement the second unit.");

    assert_eq!(
        kind_of(harness.owner.preflight_task(&request()).expect_err("held")),
        "concurrency_ceiling",
        "a just-failed child still counts"
    );
    assert_eq!(
        kind_of(harness.owner.create_task(request()).expect_err("held")),
        "concurrency_ceiling"
    );
    assert_eq!(harness.row().phase, DelegationPhase::Running);
    assert_eq!(harness.state(), LiveSessionState::Failed);

    harness.age_settled_child(SETTLED_CHILD_YIELD_MS + 1_000);
    assert_eq!(
        kind_of(
            harness
                .owner
                .preflight_task(&request())
                .expect_err("past the ceiling")
        ),
        "binding_missing",
        "the preflight sees the place a settled failed child yields"
    );
    assert_eq!(harness.row().phase, DelegationPhase::Running);
    assert_eq!(
        harness.state(),
        LiveSessionState::Failed,
        "the preflight is read-only"
    );
    assert_eq!(
        kind_of(
            harness
                .owner
                .create_task(request())
                .expect_err("past the ceiling")
        ),
        "binding_missing"
    );
    assert_eq!(
        harness.row().phase,
        DelegationPhase::Ended,
        "the failed child gave its place"
    );
    assert!(
        !harness.control.snapshot(child).expect("snapshot").active,
        "and its actor is torn down"
    );

    let working = Harness::governed();
    working.ingest(json!({"type": "agent_start"}), None);
    assert_eq!(working.state(), LiveSessionState::Running);
    working.age_settled_child(SETTLED_CHILD_YIELD_MS + 1_000);
    assert_eq!(
        working
            .owner
            .create_task(working.create_request("Implement the second unit."))
            .expect_err("a working child never yields")
            .kind,
        "concurrency_ceiling"
    );
    assert_eq!(working.row().phase, DelegationPhase::Running);
    assert_eq!(working.state(), LiveSessionState::Running);
}
