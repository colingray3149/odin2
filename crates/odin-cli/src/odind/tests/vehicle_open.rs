//! Capacity failures must leave serving active while the vehicle retries with the same identity.
//! Credentials are isolated in subprocess environments.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::future::Future;
use std::time::Duration as StdDuration;

use odin_domain::huginn::{
    AbortScope, ApprovalDecision, CommandReceipt, LiveCommand, LiveCommandBody, LiveError,
    LiveMessage, LiveSessionId, LiveSessionState, ModelName, OmpLivePlane, OpenSessionRequest,
    PermissionDecision, PermissionRequestId, ProviderName, SessionEpoch, SessionManifest,
};
use odin_domain::{ApprovalId, CommandId, NodeId};
use odin_hermes::runtime::HermesRuntime;
use odin_huginn::browser::BrowserProjectionError;
use odin_huginn::incidents::{IncidentStatusView, IncidentView};
use odin_huginn::read_model::MaterializedReadModel;
use odin_omp::live::control::LiveControlBackend;
use odin_omp::live::supervisor::{LiveSessionLauncher, SessionRuntime};
use time::OffsetDateTime;

use crate::authority::DeclaredConversationBinding;
use crate::live::browser_capsule_tests::{
    arm_real_huginn_service, authenticated_bootstrap, first_authenticated_bootstrap,
};
use crate::live::hermes_routes::bind;
use crate::live::hermes_routes::tests::{gate_fixture_with, GateFixture};
use crate::live::orchestrate_serving;
use crate::live::serving::{ServingShutdown, ShutdownOutcome};
use crate::live::vehicle_open::{arm_vehicle_open_lane, VehicleRetrySchedule};

/// The published incident cards once one reports Resolved, or the last
/// observation at the bound. The resolution is published asynchronously
/// after the governed open returns, so a single read races the publisher
/// under load; callers still assert the exact card.
async fn incidents_once_resolved(read_model: &Arc<MaterializedReadModel>) -> Vec<IncidentView> {
    let deadline = tokio::time::Instant::now() + StdDuration::from_secs(10);
    loop {
        let cards = published_incidents(read_model).await;
        if cards
            .iter()
            .any(|view| view.status == IncidentStatusView::Resolved)
            || tokio::time::Instant::now() >= deadline
        {
            return cards;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
}

pub(crate) async fn published_incidents(
    read_model: &Arc<MaterializedReadModel>,
) -> Vec<IncidentView> {
    let mut views = Vec::new();
    for object in read_model
        .objects_of_kind(odin_domain::huginn::ObjectKind::Status)
        .expect("incident objects")
    {
        if let Some(snapshot) = read_model.get(&object).expect("incident snapshot") {
            views.push(serde_json::from_value(snapshot.value).expect("incident view"));
        }
    }
    views
}

async fn open_vehicle_card(read_model: &Arc<MaterializedReadModel>) -> IncidentView {
    for _ in 0..100 {
        for candidate in published_incidents(read_model).await {
            if candidate.failure_signature == "odind.conversation.vehicle.open" {
                return candidate;
            }
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    panic!("the lane never published the open-failure card");
}

/// Omit browser supervision to isolate vehicle-open behavior.
fn spawn_serving(
    serve: impl Future<Output = std::io::Result<()>> + Send + 'static,
    pumps: tokio::task::JoinSet<Result<(), String>>,
    signal_stop: impl Future<Output = ()> + Send + 'static,
) -> tokio::task::JoinHandle<(Result<(), String>, ShutdownOutcome)> {
    tokio::spawn(async move {
        let (result, accounting) = orchestrate_serving(
            Ok(serve),
            pumps,
            signal_stop,
            None::<(
                std::pin::Pin<Box<dyn Future<Output = Result<(), BrowserProjectionError>> + Send>>,
                fn() -> std::pin::Pin<Box<dyn Future<Output = Vec<String>> + Send>>,
            )>,
            ServingShutdown::detached(),
        )
        .await;
        (result, accounting.outcome)
    })
}

/// The subprocess arm selector: only the child ever carries the credential
/// variable; the orchestrating parent does not touch the env.
const LANE_MODE_VAR: &str = "ODIN_VEHICLE_LANE_MODE";
const LANE_TEST_PATH: &str =
    "live::vehicle_open::tests::vehicle_lane_failure_is_nonfatal_and_recovers_through_the_governed_path";

/// Inject launch failures after admission and durable open journaling.
struct TogglableLaunch {
    open_ok: AtomicBool,
}

#[async_trait::async_trait]
impl LiveSessionLauncher for TogglableLaunch {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _manifest: &SessionManifest,
        _epoch: SessionEpoch,
        _reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        if self.open_ok.load(Ordering::SeqCst) {
            Ok(SessionRuntime {
                control: Arc::new(LaneNullBackend),
                terminal: None,
                observations: None,
                failed_notices: None,
            })
        } else {
            Err(LiveError::Unsupported {
                operation: "vehicle lane regression: launches toggled off".to_owned(),
            })
        }
    }
}

/// Accept control calls without running a provider process.
struct LaneNullBackend;

#[async_trait::async_trait]
impl LiveControlBackend for LaneNullBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn follow_up(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn steer(&self, _: &LiveMessage) -> Result<(), LiveError> {
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
        _: &PermissionRequestId,
        _: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &ApprovalId,
        _: u64,
        _: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

fn recorded_session_id(fixture: &GateFixture) -> LiveSessionId {
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fixture.record_path).expect("record"))
            .expect("record json");
    let session = record["sessionId"].as_str().expect("record session");
    LiveSessionId::parse(session).expect("record session id")
}

/// Fill global capacity with live sessions without exhausting the seat's own capacity.
async fn stage_full_roster(fixture: &GateFixture) {
    let binding: DeclaredConversationBinding = fixture.binding();
    let DeclaredConversationBinding {
        ownership,
        vehicle: Some((seat_binding, _lane)),
        ..
    } = &binding
    else {
        panic!("the fixture declares a served vehicle");
    };
    let launch_pair = seat_binding.launch_options[0].clone();
    let mut seat_capacity = seat_binding.clone();
    // Keep the seat limit above the global limit to isolate global-capacity refusal.
    seat_capacity.max_sessions += 2;
    fixture
        .supervisor
        .bind(seat_capacity)
        .await
        .expect("seat binding");
    for index in 0..2 {
        let summary = fixture
            .omp
            .open_session(OpenSessionRequest {
                command_id: CommandId::new(format!("command:vehicle-lane-aux-{index}"))
                    .expect("aux command"),
                seat_id: seat_binding.seat_id.clone(),
                project_id: ownership.project.clone(),
                slice_id: seat_binding.slice_id.clone(),
                provider: launch_pair.provider.clone(),
                model: launch_pair.model.clone(),
                title: None,
                target_node: NodeId::new("laptop").expect("node id"),
                open_tab: false,
                initial_prompt: None,
                workload: None,
                served_revision: None,
            })
            .await
            .expect("the aux open holds a live incarnation");
        assert_ne!(summary.state, LiveSessionState::Failed);
        assert_ne!(summary.state, LiveSessionState::Ended);
    }
    let roster = fixture.supervisor.summaries().await.expect("roster");
    assert_eq!(roster.len(), 2, "two live aux sessions are tracked");
}

/// Frees the staged roster through the EXISTING governed online path: a
/// whole-session Abort settles each dead tracked session durably — the
/// same governed surface an operator runs today.
async fn governed_abort_staged_roster(fixture: &GateFixture) {
    for (index, summary) in fixture
        .supervisor
        .summaries()
        .await
        .expect("roster")
        .into_iter()
        .enumerate()
    {
        let _: CommandReceipt = fixture
            .omp
            .command(LiveCommand {
                command_id: CommandId::new(format!("command:vehicle-lane-abort-{index}"))
                    .expect("abort command"),
                session_id: summary.session_id,
                expected_epoch: summary.epoch,
                expected_event_head: Some(summary.event_head),
                body: LiveCommandBody::Abort {
                    scope: AbortScope::Session,
                },
            })
            .await
            .expect("the governed abort settles the dead tracked session");
        assert!(fixture
            .supervisor
            .terminal_summary(summary.session_id)
            .await
            .expect("the retired session is readable")
            .is_some());
    }
}

async fn recovery_case() {
    let launch = Arc::new(TogglableLaunch {
        open_ok: AtomicBool::new(true),
    });
    // No retained record: initialize must attempt the original open against a full roster.
    let fixture = gate_fixture_with(2, launch.clone(), false).await;
    let gateway = fixture
        .runtime
        .gateway()
        .as_ref()
        .expect("the declared surface composes a gateway");
    assert!(
        !gateway.credential_absent(),
        "this case requires the armed (credential-present) state"
    );
    stage_full_roster(&fixture).await;

    let hermes_runtime: Option<Arc<HermesRuntime>> = fixture.hermes_runtime_arg();
    let bound = bind(
        &hermes_runtime,
        Some(fixture.binding()),
        &fixture.omp,
        &fixture.supervisor,
        &fixture.config,
        &fixture.manifest,
        &fixture.ledger_path,
        &fixture.pin,
        &fixture.read_model,
        &None,
        &Default::default(),
        &fixture_delegation_links(),
        None,
        Arc::clone(&fixture.operation_store),
        Arc::clone(&fixture.operation_clock),
        &fixture.session_pool,
    )
    .await
    .expect("bind composes the route")
    .expect("the armed surface composes the conversation route");
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        4096,
        8192,
        OffsetDateTime::now_utc(),
    ));
    let mut pumps = tokio::task::JoinSet::new();
    arm_vehicle_open_lane(
        &mut pumps,
        Some(bound),
        Arc::clone(&read_model),
        VehicleRetrySchedule::new(
            2,
            StdDuration::from_millis(30),
            StdDuration::from_millis(60),
        ),
    );

    // The production resource-limit cause travels the card verbatim, and
    // the limit refuses BEFORE admission: no vehicle row exists.
    let card = open_vehicle_card(&read_model).await;
    // The card is Open if the test observed it inside the escalation
    // window, Escalated after — both are the lane's lawful progression on
    // the SAME id; the cause carries the production limit either way.
    assert!(
        matches!(
            card.status,
            IncidentStatusView::Open | IncidentStatusView::Escalated
        ),
        "the card tracks the retry lane: {:?}",
        card.status
    );
    let cause = card.observed_state["cause"].as_str().expect("cause");
    assert!(
        cause.contains("already tracked"),
        "the card carries the production resource-limit cause verbatim: {cause}"
    );
    let sessions = fixture.ledger.sessions().await.expect("durable sessions");
    assert_eq!(
        sessions.len(),
        2,
        "the resource limit refuses BEFORE admission: no vehicle row exists"
    );
    let recorded = recorded_session_id(&fixture);
    assert!(
        !sessions
            .iter()
            .any(|session| session.manifest.session_id == recorded),
        "the durable record names the vehicle identity the lane converges on, and \
         that identity has no row yet"
    );

    // Recovery: free capacity through the governed online path, then the
    // capped lane's next attempt opens the SAME governed identity.
    launch.open_ok.store(true, Ordering::SeqCst);
    governed_abort_staged_roster(&fixture).await;
    let mut roster = None;
    for _ in 0..100 {
        let tracked = fixture
            .supervisor
            .summaries()
            .await
            .expect("tracked roster");
        if let Some(vehicle) = tracked.first() {
            roster = Some(vehicle.clone());
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    let vehicle = roster.expect("the capped lane re-opens the vehicle");
    assert_eq!(
        vehicle.session_id, recorded,
        "the retry converges on the SAME durable identity, never a replacement"
    );
    assert_ne!(
        vehicle.state,
        LiveSessionState::Failed,
        "the governed open holds a live incarnation"
    );
    assert_ne!(vehicle.state, LiveSessionState::Ended);

    // The ONE card resolved in place on the SAME id: Open rev1, then the
    // in-place status mutation only (Resolved if the governed recovery beat
    // the escalation window, else Escalated rev2 then Resolved) — bounded
    // history either way, one card id for the lane lifetime.
    let cards = incidents_once_resolved(&read_model).await;
    assert_eq!(
        cards.len(),
        1,
        "bounded history: the open card is updated in place, never duplicated"
    );
    assert_eq!(cards[0].incident_id, card.incident_id);
    assert_eq!(cards[0].status, IncidentStatusView::Resolved);
    assert!(
        cards[0].revision == 2 || cards[0].revision == 3,
        "at most one escalation update before the resolution: {}",
        cards[0].revision
    );

    // The owning shutdown cancels the parked lane.
    pumps.abort_all();
    let cancel = pumps
        .join_next()
        .await
        .expect("the lane task exists")
        .expect_err("an aborted task joins with a cancel error");
    assert!(cancel.is_cancelled(), "shutdown cancels the parked lane");
}

/// Exercise vehicle recovery while authenticated Huginn requests continue serving.
async fn serving_case() {
    let launch = Arc::new(TogglableLaunch {
        open_ok: AtomicBool::new(true),
    });
    let fixture = gate_fixture_with(2, launch.clone(), false).await;
    stage_full_roster(&fixture).await;

    let hermes_runtime: Option<Arc<HermesRuntime>> = fixture.hermes_runtime_arg();
    let bound = bind(
        &hermes_runtime,
        Some(fixture.binding()),
        &fixture.omp,
        &fixture.supervisor,
        &fixture.config,
        &fixture.manifest,
        &fixture.ledger_path,
        &fixture.pin,
        &fixture.read_model,
        &None,
        &Default::default(),
        &fixture_delegation_links(),
        None,
        Arc::clone(&fixture.operation_store),
        Arc::clone(&fixture.operation_clock),
        &fixture.session_pool,
    )
    .await
    .expect("bind composes the route")
    .expect("the armed surface composes the conversation route");

    // Reserve an ephemeral serving port for the real Huginn service.
    let probe_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    let address = probe_listener.local_addr().expect("serving address");
    drop(probe_listener);
    let (serve, bearer) = arm_real_huginn_service(&fixture, address).await;
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        4096,
        8192,
        OffsetDateTime::now_utc(),
    ));
    let mut pumps = tokio::task::JoinSet::new();
    arm_vehicle_open_lane(
        &mut pumps,
        Some(bound),
        Arc::clone(&read_model),
        VehicleRetrySchedule::new(
            50,
            StdDuration::from_millis(30),
            StdDuration::from_millis(60),
        ),
    );

    let (stop_signal, signal_stop) = tokio::sync::oneshot::channel::<()>();
    let signal_stop = async move {
        let _ = signal_stop.await;
    };
    // No browser capsule in this fixture: the orchestration's supervision
    // slot stays typed-empty.
    let node = spawn_serving(serve, pumps, signal_stop);

    // The vehicle-open failure happens against the full roster — and the
    // daemon keeps actually serving: a fresh AUTHENTICATED request answers
    // usefully after the card is open.
    let card = open_vehicle_card(&read_model).await;
    let (status, body) = first_authenticated_bootstrap(address, &bearer).await;
    assert_eq!(
        status, 200,
        "after the vehicle-open failure Huginn must still serve an authenticated \
         bootstrap (the pre-fix source exited the daemon instead): {body}"
    );
    assert!(
        body.contains("maxFrameBytes"),
        "post-failure bootstrap must carry its typed payload: {body}"
    );

    // Governed recovery frees capacity; the capped lane re-opens the SAME
    // recorded identity and resolves the ONE card — while Huginn keeps
    // answering.
    launch.open_ok.store(true, Ordering::SeqCst);
    governed_abort_staged_roster(&fixture).await;
    let recorded = recorded_session_id(&fixture);
    let mut recovered = false;
    for _ in 0..100 {
        let tracked = fixture
            .supervisor
            .summaries()
            .await
            .expect("tracked roster");
        if tracked
            .first()
            .is_some_and(|vehicle| vehicle.session_id == recorded)
        {
            recovered = true;
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    assert!(
        recovered,
        "the capped lane re-opens the SAME recorded identity under the serving \
         orchestration"
    );
    let cards = incidents_once_resolved(&read_model).await;
    assert_eq!(cards.len(), 1, "one card id for the lane lifetime");
    assert_eq!(cards[0].incident_id, card.incident_id);
    assert_eq!(cards[0].status, IncidentStatusView::Resolved);
    let (status, body) = authenticated_bootstrap(address, &bearer)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "after the same-identity recovery the daemon must still accept and \
             answer connections: {error}"
            )
        });
    assert_eq!(
        status, 200,
        "authenticated Huginn must still serve after the recovery: {body}"
    );

    // A real stop lands cleanly through the production orchestration seam.
    stop_signal
        .send(())
        .expect("the serving select waits for the stop");
    let (result, outcome) = tokio::time::timeout(StdDuration::from_secs(10), node)
        .await
        .expect("the serving select returns on stop")
        .expect("the serving select task joins");
    assert_eq!(
        outcome,
        ShutdownOutcome::Drained { tracked: 1 },
        "the owning shutdown must join the vehicle-open pump"
    );
    assert!(result.is_ok(), "the stop path stays clean: {result:?}");
}

#[tokio::test]
async fn vehicle_lane_failure_is_nonfatal_and_recovers_through_the_governed_path() {
    match std::env::var(LANE_MODE_VAR).as_deref() {
        Ok("recovery") => recovery_case().await,
        Ok("serving") => serving_case().await,
        _ => {
            // Orchestrator: the children drive the REAL bind + lane path
            // under subprocess env isolation. This process never touches
            // the credential variable, so concurrent tests are unaffected.
            let harness = std::env::current_exe().expect("test harness path");
            let run = |mode: &str| {
                let mut command = Command::new(&harness);
                command
                    .args([
                        "--exact",
                        LANE_TEST_PATH,
                        "--test-threads",
                        "1",
                        "--nocapture",
                    ])
                    .env(LANE_MODE_VAR, mode)
                    .env_remove(odin_hermes::runtime::DISCORD_TOKEN_ENV)
                    .env(
                        odin_hermes::runtime::DISCORD_TOKEN_ENV,
                        "fixture-gateway-token",
                    );
                command.output().expect("lane child harness")
            };
            for mode in ["recovery", "serving"] {
                let child = run(mode);
                assert!(
                    child.status.success(),
                    "the {mode} child must stay nonfatal and recover governed: {}{}",
                    String::from_utf8_lossy(&child.stdout),
                    String::from_utf8_lossy(&child.stderr),
                );
            }
        }
    }
}

fn fixture_delegation_links() -> odin_omp::host_tools::delegation::DelegationLinkLedger {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "odind-fixture-links-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    odin_omp::host_tools::delegation::DelegationLinkLedger::open(root).expect("fixture link ledger")
}
