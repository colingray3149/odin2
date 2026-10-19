//! Model commands use the live plane's seat-scoped listings and session actor.

use futures_util::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_domain::huginn::{
    CommandOutcome, CommandReceipt, LiveCommand, LiveCommandBody, LiveError, LiveEventBody,
    LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, OmpLivePlane, ProviderName,
    SessionEpoch, SessionListQuery, SessionManifest, SessionOpened, SessionStateChanged,
    SessionSubscription, SubscribeRequest,
};
use odin_domain::{CommandId, ContainerId, EventId, NodeId, ProjectId, SeatId, SliceId};
use odin_hermes::runtime::{
    select_target_session, HuginnReadRoute, ModelCommandRoute, ModelRouteError, ModelSetCommand,
    SeatSessionSurvey,
};
use odin_omp::live::control::LiveControlBackend;
use odin_omp::live::lane_artifacts::{FsLaneArtifactPort, LaneTransferBridge};
use odin_omp::live::ledger::fs::FsLiveLedger;
use odin_omp::live::ledger::{LiveLedger, NewLiveEvent};
use odin_omp::live::service::OmpLiveService;
use odin_omp::live::supervisor::{
    LiveSeatBinding, LiveSessionLauncher, LiveSupervisor, SessionRuntime,
};
use odin_omp::live::target::{
    TerminalTargetAdmin, TerminalTargetRegistry, TerminalTargetSnapshot, TerminalTargetStatus,
};
use odin_omp::live::transfer::{RegistryTransferLaneResolver, TransferManager};
use tempfile::TempDir;
use time::OffsetDateTime;

use super::DaemonModelCommandRoute;

/// Arbitrary declared identities: no production name is load-bearing.
const SEAT: &str = "route-fixture";
const SLICE: &str = "route-fixture-work";
const PROJECT: &str = "route-fixture-research";
const NODE: &str = "route-fixture-node";

fn seat() -> SeatId {
    SeatId::new(SEAT).expect("seat id")
}

fn provider() -> ProviderName {
    ProviderName::new("fixture-provider").expect("provider name")
}

fn launch() -> odin_domain::huginn::LiveLaunchOption {
    odin_domain::huginn::LiveLaunchOption {
        provider: provider(),
        model: ModelName::new("fixture-model").expect("model name"),
        skeleton_ref: "route-fixture".to_owned(),
        container_id: ContainerId::new("route-fixture-native").expect("container id"),
        harness: None,
    }
}

/// Accepts control calls without starting a provider process.
struct NullBackend(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl LiveControlBackend for NullBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(&self, _: &odin_domain::huginn::LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn follow_up(&self, _: &odin_domain::huginn::LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn steer(&self, _: &odin_domain::huginn::LiveMessage) -> Result<(), LiveError> {
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
        Ok(())
    }
    async fn rehome(&self, _: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(&self, _: &ProviderName, _: &ModelName) -> Result<(), LiveError> {
        self.0.fetch_add(1, Ordering::SeqCst);
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
        _: &odin_domain::huginn::PermissionRequestId,
        _: odin_domain::huginn::PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &odin_domain::ApprovalId,
        _: u64,
        _: odin_domain::huginn::ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

struct OpenLauncher(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl LiveSessionLauncher for OpenLauncher {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _manifest: &SessionManifest,
        _epoch: SessionEpoch,
        _reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Ok(SessionRuntime {
            control: Arc::new(NullBackend(Arc::clone(&self.0))),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// A supervisor with one seat and a backend that records model switches.
async fn plane() -> (
    TempDir,
    Arc<OmpLiveService>,
    odin_domain::huginn::LiveLaunchOption,
    Arc<AtomicUsize>,
) {
    let root = TempDir::new().expect("route fixture root");
    let ledger = live_ledger(&root);
    let switches = Arc::new(AtomicUsize::new(0));
    let supervisor = LiveSupervisor::new(
        Arc::clone(&ledger),
        Arc::new(OpenLauncher(Arc::clone(&switches))),
        8,
        None,
    );
    let omp = serve(&root, ledger, supervisor).await;
    (root, omp, launch(), switches)
}

fn live_ledger(root: &TempDir) -> Arc<dyn LiveLedger> {
    Arc::new(FsLiveLedger::open(root.path().join("live-ledger")).expect("live ledger"))
}

async fn serve(
    root: &TempDir,
    ledger: Arc<dyn LiveLedger>,
    supervisor: Arc<LiveSupervisor>,
) -> Arc<OmpLiveService> {
    let resolver = Arc::new(RegistryTransferLaneResolver::read_only(Arc::clone(&ledger)));
    let lane_port = Arc::new(
        FsLaneArtifactPort::open(root.path().join("lane-artifacts")).expect("lane artifact port"),
    );
    let bridge = Arc::new(LaneTransferBridge::new(lane_port));
    let transfers = Arc::new(
        TransferManager::open(
            root.path().join("live-transfers"),
            Arc::clone(&ledger),
            resolver,
            bridge,
        )
        .expect("transfer manager"),
    );
    supervisor
        .bind(LiveSeatBinding {
            seat_id: seat(),
            slice_id: SliceId::new(SLICE).expect("slice id"),
            display_name: "Route fixture".to_owned(),
            launch_options: vec![launch()],
            allowed_nodes: vec![NodeId::new(NODE).expect("node id")],
            max_sessions: 4,
            turn_budget: None,
        })
        .await
        .expect("bind fixture seat");
    Arc::new(OmpLiveService::new(ledger, supervisor, transfers))
}

async fn open_session(
    omp: &OmpLiveService,
    launch: &odin_domain::huginn::LiveLaunchOption,
    tag: &str,
) -> LiveSessionSummary {
    omp.open_session(odin_domain::huginn::OpenSessionRequest {
        command_id: CommandId::new(format!("command:model-route-open:{tag}")).expect("command id"),
        seat_id: seat(),
        project_id: ProjectId::new(PROJECT).expect("project id"),
        slice_id: SliceId::new(SLICE).expect("slice id"),
        provider: launch.provider.clone(),
        model: launch.model.clone(),
        title: None,
        target_node: NodeId::new(NODE).expect("node id"),
        open_tab: false,
        initial_prompt: None,
        workload: None,
        served_revision: None,
    })
    .await
    .expect("fixture session opens")
}

fn survey(route: &DaemonModelCommandRoute, seat: &SeatId) -> SeatSessionSurvey {
    route
        .survey_seat(seat)
        .expect("the fixture route must not refuse its survey")
}

fn receipt_of(outcome: Result<CommandReceipt, ModelRouteError>) -> serde_json::Value {
    serde_json::to_value(outcome.expect("the route must not refuse its command")).unwrap()
}

fn switch_command(
    command_id: &str,
    session: &LiveSessionSummary,
    epoch: SessionEpoch,
) -> ModelSetCommand {
    ModelSetCommand {
        command_id: CommandId::new(command_id).expect("command id"),
        session_id: session.session_id,
        expected_epoch: epoch,
        provider: provider(),
        model: ModelName::new("fixture-switched").expect("model name"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_surveys_the_plane_and_switches_exactly_once() {
    let (_root, omp, launch, switches) = plane().await;
    let route = DaemonModelCommandRoute {
        plane: Arc::clone(&omp),
        vehicle: None,
        handle: tokio::runtime::Handle::current(),
        seat_launch: odin_omp::live::seat_launch::SeatLaunchStore::new(
            &std::env::temp_dir().join("odin-seat-launch-test"),
        ),
    };

    let empty = survey(&route, &seat());
    assert!(empty.live_sessions.is_empty());
    assert!(empty.declared_vehicle.is_none());
    let refusal = select_target_session(&empty, &seat()).expect_err("an empty seat refuses typed");
    assert!(matches!(refusal, ModelRouteError::Refused(_)));

    // The plane's own projection is seat-scoped: another seat surveys
    // nothing even while this seat holds a live session.
    let opened = open_session(&omp, &launch, "one").await;
    let foreign = SeatId::new("route-fixture-other").expect("seat id");
    assert!(survey(&route, &foreign).live_sessions.is_empty());

    let single = survey(&route, &seat());
    assert_eq!(single.live_sessions.len(), 1);
    assert_eq!(single.live_sessions[0].session_id, opened.session_id);
    assert_eq!(single.live_sessions[0].state, LiveSessionState::Idle);
    let target = select_target_session(&single, &seat()).expect("unique session");
    assert_eq!(target.session_id, opened.session_id);
    assert_eq!(target.epoch, opened.epoch);

    // A DM-issued tool executes during its caller's active turn. The
    // command must not require that same turn to finish first.
    omp.command(LiveCommand {
        command_id: CommandId::new("command:model-route-prompt").unwrap(),
        session_id: target.session_id,
        expected_epoch: target.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Prompt {
            message: odin_domain::huginn::LiveMessage::new(vec![
                odin_domain::huginn::LiveContentBlock::Text("switch your model".to_owned()),
            ])
            .unwrap(),
        },
    })
    .await
    .unwrap();
    wait_applied(&omp, target, "command:model-route-prompt").await;
    assert_eq!(
        survey(&route, &seat()).live_sessions[0].state,
        LiveSessionState::Running
    );

    // The governed command lands at the REAL session actor: accepted with
    // the journaled command id.
    let receipt = receipt_of(route.command_set_model(switch_command(
        "command:model-route-switch",
        target,
        target.epoch,
    )));
    assert_eq!(receipt["status"], "accepted");
    assert_eq!(receipt["commandId"], "command:model-route-switch");
    wait_applied(&omp, target, "command:model-route-switch").await;
    assert_eq!(switches.load(Ordering::SeqCst), 1);
    let switched = survey(&route, &seat());
    assert_eq!(switched.live_sessions[0].model.as_str(), "fixture-switched");
    assert_eq!(switched.live_sessions[0].state, LiveSessionState::Running);

    // The SAME command id replays as the plane's own duplicate — exactly
    // once at the effect.
    let duplicate = receipt_of(route.command_set_model(switch_command(
        "command:model-route-switch",
        target,
        target.epoch,
    )));
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(switches.load(Ordering::SeqCst), 1);

    // A moved epoch is the plane's typed pre-journal rejection: nothing
    // switched, and the refusal is the receipt.
    let rejected = receipt_of(route.command_set_model(switch_command(
        "command:model-route-stale",
        target,
        SessionEpoch::new(999),
    )));
    assert_eq!(rejected["status"], "rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route_survey_lists_only_non_ended_sessions() {
    let (_root, omp, launch, _switches) = plane().await;
    let route = DaemonModelCommandRoute {
        plane: Arc::clone(&omp),
        vehicle: None,
        handle: tokio::runtime::Handle::current(),
        seat_launch: odin_omp::live::seat_launch::SeatLaunchStore::new(
            &std::env::temp_dir().join("odin-seat-launch-test"),
        ),
    };
    let closed = open_session(&omp, &launch, "ended").await;
    let survivor = open_session(&omp, &launch, "live").await;
    // Terminate the first session through the real plane command seam.
    let receipt = omp
        .command(LiveCommand {
            command_id: CommandId::new("command:model-route-close").expect("command id"),
            session_id: closed.session_id,
            expected_epoch: closed.epoch,
            expected_event_head: None,
            body: LiveCommandBody::Abort {
                scope: odin_domain::huginn::AbortScope::Session,
            },
        })
        .await
        .expect("abort command");
    assert_eq!(
        serde_json::to_value(&receipt).unwrap()["status"],
        "accepted"
    );
    wait_applied(&omp, &closed, "command:model-route-close").await;
    let current = survey(&route, &seat());
    assert_eq!(current.live_sessions.len(), 1);
    assert_eq!(current.live_sessions[0].session_id, survivor.session_id);
}

async fn wait_applied(omp: &OmpLiveService, session: &LiveSessionSummary, id: &str) {
    let mut events = omp
        .subscribe(SubscribeRequest {
            subscriptions: vec![SessionSubscription {
                session_id: session.session_id,
                event_after: session.event_head,
                terminal_after: None,
            }],
        })
        .await
        .unwrap();
    tokio::time::timeout(StdDuration::from_secs(5), async {
        while let Some(event) = events.next().await {
            if let LiveEventBody::ControlCompleted(CommandOutcome::Applied { command_id }) =
                event.unwrap().body
            {
                if command_id.as_str() == id {
                    return;
                }
            }
        }
        panic!("command event stream ended before application");
    })
    .await
    .expect("command must complete");
}

/// The production terminal-target registry with nothing declared: `status`
/// reads its real unbound binding.
struct UnboundTargets(TerminalTargetRegistry);

#[async_trait::async_trait]
impl TerminalTargetAdmin for UnboundTargets {
    async fn register_chat_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        self.0.register_chat(zellij_session)
    }

    async fn clear_chat_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.0.clear_chat()
    }

    async fn terminal_target_status(&self) -> TerminalTargetStatus {
        self.0.status()
    }

    async fn resolve_target(&self) -> Result<TerminalTargetSnapshot, LiveError> {
        self.0.resolve()
    }
}

/// [`OpenLauncher`] with a terminal-target admin wired, as the daemon's
/// composed launcher has.
struct TargetedLauncher(OpenLauncher, Arc<UnboundTargets>);

#[async_trait::async_trait]
impl LiveSessionLauncher for TargetedLauncher {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.0.open(manifest, epoch, reclaim).await
    }

    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        Some(self.1.clone())
    }
}

/// One fixture-seat session an earlier daemon lifetime journaled, its last
/// transition `last` at `at`, with no actor in this daemon.
async fn journal_session(
    ledger: &dyn LiveLedger,
    tag: &str,
    last: LiveSessionState,
    at: OffsetDateTime,
) -> LiveSessionId {
    let session_id = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session id");
    let manifest: SessionManifest = serde_json::from_value(serde_json::json!({
        "sessionId": session_id, "seatId": SEAT, "sliceId": SLICE, "projectId": PROJECT,
        "provider": "fixture-provider", "model": "fixture-model", "title": null,
        "targetNode": NODE, "openTab": false
    }))
    .expect("manifest");
    ledger
        .create_session(manifest.clone())
        .await
        .expect("create");
    let mut bodies = vec![
        LiveEventBody::SessionOpened(SessionOpened {
            manifest: Box::new(manifest),
        }),
        LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Starting,
            current: LiveSessionState::Idle,
            reason: None,
        }),
    ];
    if last != LiveSessionState::Idle {
        bodies.push(LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Idle,
            current: last,
            reason: None,
        }));
    }
    for (index, body) in bodies.into_iter().enumerate() {
        ledger
            .append(
                SessionEpoch::new(1),
                NewLiveEvent {
                    session_id,
                    event_id: EventId::new(format!("{tag}-{index}")).expect("event id"),
                    occurred_at: at,
                    body,
                },
            )
            .await
            .expect("append");
    }
    session_id
}

async fn listed(omp: &OmpLiveService, include_ended: bool) -> Vec<LiveSessionId> {
    let page = omp
        .sessions(SessionListQuery {
            seat_id: None,
            include_ended,
            cursor: None,
            limit: std::num::NonZeroU16::new(128).expect("non-zero"),
        })
        .await
        .expect("durable listing");
    assert!(page.next_cursor.is_none(), "the fixture fits one page");
    page.sessions
        .iter()
        .map(|summary| summary.session_id)
        .collect()
}

/// Cold resumable history remains available for recovery but must not count as live sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn huginn_status_counts_the_live_roster_not_durable_history() {
    let root = TempDir::new().expect("route fixture root");
    let ledger = live_ledger(&root);
    let now = OffsetDateTime::now_utc();
    let cold = journal_session(
        &*ledger,
        "cold",
        LiveSessionState::Idle,
        now - time::Duration::days(3),
    )
    .await;
    let warm = journal_session(
        &*ledger,
        "warm",
        LiveSessionState::Idle,
        now - time::Duration::minutes(30),
    )
    .await;
    let ended = journal_session(
        &*ledger,
        "ended",
        LiveSessionState::Ended,
        now - time::Duration::minutes(30),
    )
    .await;
    let supervisor = LiveSupervisor::discover(
        Arc::clone(&ledger),
        Arc::new(TargetedLauncher(
            OpenLauncher(Arc::new(AtomicUsize::new(0))),
            Arc::new(UnboundTargets(TerminalTargetRegistry::new())),
        )),
        8,
        None,
    )
    .await
    .expect("discover");
    let omp = serve(&root, Arc::clone(&ledger), Arc::clone(&supervisor)).await;
    let live = open_session(&omp, &launch(), "status-live").await;
    let route = super::DaemonHuginnReadRoute {
        plane: Arc::clone(&omp),
        supervisor: Arc::clone(&supervisor),
        node: NODE.to_owned(),
        handle: tokio::runtime::Handle::current(),
    };

    let status = route.status().expect("status");
    assert_eq!(status["liveSessions"], 1, "{status}");
    let mut current: Vec<LiveSessionId> = omp
        .roster()
        .await
        .expect("roster")
        .seats
        .into_iter()
        .flat_map(|seat| seat.active_sessions)
        .map(|summary| summary.session_id)
        .collect();
    current.sort();
    assert_eq!(
        current,
        vec![live.session_id],
        "the surface the count describes"
    );

    let mut durable = listed(&omp, false).await;
    durable.sort();
    let mut resumable = vec![cold, warm, live.session_id];
    resumable.sort();
    assert_eq!(durable, resumable, "cold stays durably listed, never live");
    assert!(listed(&omp, true).await.contains(&ended));
    assert!(
        supervisor.parked(cold).await.expect("parked").is_none(),
        "a status read never warms a cold session"
    );

    omp.command(LiveCommand {
        command_id: CommandId::new("command:status-close").expect("command id"),
        session_id: live.session_id,
        expected_epoch: live.epoch,
        expected_event_head: None,
        body: LiveCommandBody::Abort {
            scope: odin_domain::huginn::AbortScope::Session,
        },
    })
    .await
    .expect("abort command");
    wait_applied(&omp, &live, "command:status-close").await;
    let status = route.status().expect("status after the end");
    assert_eq!(status["liveSessions"], 1, "{status}");
    assert!(!listed(&omp, false).await.contains(&live.session_id));
    assert!(listed(&omp, true).await.contains(&live.session_id));
}
