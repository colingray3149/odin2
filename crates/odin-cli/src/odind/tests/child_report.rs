//! Whole delegated-work reports and durable carrier-release retries.

use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::LiveSessionId;
use odin_omp::host_tools::delegation::ChildSessionControl as _;
use odin_omp::live::supervisor::LiveSupervisor;
use time::OffsetDateTime;

/// This durable-read fixture must never launch or provision a session.
struct ReportReadOnly;

#[async_trait::async_trait]
impl odin_omp::live::supervisor::LiveSessionLauncher for ReportReadOnly {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &odin_domain::huginn::SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<odin_omp::live::supervisor::SessionRuntime, odin_domain::huginn::LiveError> {
        panic!("report read must not launch a session")
    }
}

impl odin_omp::host_tools::delegation::ChildAuthorityProvisioner for ReportReadOnly {
    fn provision_child(
        &self,
        _: &odin_domain::SeatId,
        _: &odin_domain::LaneId,
        _: &odin_domain::SessionId,
        _: odin_omp::host_tools::delegation::ChildOpen<'_>,
    ) -> Result<LiveSessionId, String> {
        panic!("report read must not provision a child")
    }

    fn seat_worker_profile(
        &self,
        _: &odin_domain::SeatId,
        _: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(String, String), String> {
        panic!("report read must not resolve a worker")
    }

    fn provision_child_for_seat(
        &self,
        _: &odin_domain::SeatId,
        _: &odin_domain::LaneId,
        _: &odin_domain::SessionId,
        _: odin_omp::host_tools::delegation::ChildOpen<'_>,
        _: &odin_domain::SeatId,
    ) -> Result<LiveSessionId, String> {
        panic!("report read must not provision a seat")
    }

    fn preflight_child(
        &self,
        _: &odin_domain::SeatId,
        _: &odin_domain::LaneId,
        _: &odin_domain::SessionId,
        _: &odin_domain::ProjectId,
        _: Option<&odin_domain::SeatId>,
        _: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(), String> {
        panic!("report read must not preflight a child")
    }
}

/// Journal settlement must survive restarts independently of carrier release.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reported_pod_without_a_live_session_settles_once_in_its_journal() {
    use odin_domain::huginn::{SessionEpoch, SessionManifest};
    use odin_omp::host_tools::delegation::WorkloadRest;
    use odin_omp::live::ledger::fs::FsLiveLedger;
    use odin_omp::live::supervisor::LiveSessionLauncher;

    struct NoLaunch;
    #[async_trait::async_trait]
    impl LiveSessionLauncher for NoLaunch {
        fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
            None
        }

        async fn open(
            &self,
            _manifest: &SessionManifest,
            _epoch: SessionEpoch,
            _reclaim: bool,
        ) -> Result<odin_omp::live::supervisor::SessionRuntime, odin_domain::huginn::LiveError>
        {
            Err(odin_domain::huginn::LiveError::Unsupported {
                operation: "no launches in this fixture".to_owned(),
            })
        }
    }
    let control_over = |supervisor: &Arc<LiveSupervisor>| {
        let supervisor_cell: crate::live_authority::SupervisorHandle =
            Arc::new(std::sync::OnceLock::new());
        supervisor_cell
            .set(Arc::downgrade(supervisor))
            .expect("supervisor handle");
        let pool_cell: crate::live_authority::SessionPoolHandle =
            Arc::new(std::sync::OnceLock::new());
        Arc::new(crate::live_authority::SupervisorChildControl::new(
            supervisor_cell,
            pool_cell,
        ))
    };

    let session = LiveSessionId::parse("00000000-0000-4000-8000-00000000c0de").expect("session id");
    let operation = "op-absent-pod";
    let root = tempfile::tempdir().expect("tempdir");
    fixture_resting_pod(root.path(), session, operation).await;

    // Discovery must work from the journal without launching a session.
    let supervisor = LiveSupervisor::discover(
        Arc::new(FsLiveLedger::open(root.path()).expect("reopen")),
        Arc::new(NoLaunch),
        256,
        None,
    )
    .await
    .expect("discover");
    let control = control_over(&supervisor);
    assert_eq!(
        control.resting_workload_sessions().expect("resting scan"),
        vec![(session, operation.to_owned(), WorkloadRest::Idle)],
        "the unsettled pod is offered to the report decision exactly once"
    );

    assert_eq!(
        control.stop_child(session).expect("settle"),
        odin_omp::host_tools::delegation::ChildStop::SettledAbsent,
        "the missing active session settles through its journal"
    );
    assert_eq!(
        control.stop_child(session).expect("settle again"),
        odin_omp::host_tools::delegation::ChildStop::AlreadyTerminal,
        "a repeated stop writes nothing and stays settled"
    );

    // Only one concurrent caller may settle and report the pod.
    let race_root = tempfile::tempdir().expect("race tempdir");
    let raced = LiveSessionId::parse("00000000-0000-4000-8000-00000000c0df").expect("session id");
    fixture_resting_pod(race_root.path(), raced, "op-race-pod").await;
    let raced_supervisor = LiveSupervisor::discover(
        Arc::new(FsLiveLedger::open(race_root.path()).expect("race ledger")),
        Arc::new(NoLaunch),
        256,
        None,
    )
    .await
    .expect("race discover");
    let raced_control = control_over(&raced_supervisor);
    let (first, second) = tokio::join!(
        tokio::task::spawn_blocking({
            let control = Arc::clone(&raced_control);
            move || control.stop_child(raced)
        }),
        tokio::task::spawn_blocking({
            let control = Arc::clone(&raced_control);
            move || control.stop_child(raced)
        }),
    );
    let decisions = [
        first.expect("race join").expect("race settle"),
        second.expect("race join").expect("race settle"),
    ];
    assert_eq!(
        (
            decisions
                .iter()
                .filter(|decision| **decision
                    == odin_omp::host_tools::delegation::ChildStop::SettledAbsent)
                .count(),
            decisions
                .iter()
                .filter(|decision| **decision
                    == odin_omp::host_tools::delegation::ChildStop::AlreadyTerminal)
                .count(),
        ),
        (1, 1),
        "exactly one concurrent caller settles the absent pod"
    );
    assert_eq!(
        settled_absent_markers(&raced_supervisor, raced).await,
        1,
        "the concurrent settlement journals its marker exactly once"
    );
    drop(raced_control);
    drop(raced_supervisor);
    drop(race_root);
    // The settled run is carrier-release backlog, and its release stays
    // independently pending until the run proves released — retried
    // round after round, exactly like the pump drives it.
    let pending: Vec<(LiveSessionId, String)> =
        control.ended_workload_sessions().expect("release backlog");
    assert_eq!(
        pending,
        vec![(session, operation.to_owned())],
        "the settled pod seeds the release backlog"
    );
    let ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger"),
    ));
    let bus = odin_process::BusAddress::unix_socket(root.path().join("stop-bus.sock"))
        .expect("bus address");
    let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
    let stops = Arc::new(odin_kernel::stop::StopAuthority::new(
        Arc::clone(&ledger),
        channel,
    ));
    let cell = crate::kube::KubeRuntimeCell::new(crate::kube::CellInputs {
        config: odin_kube::config::KubeConfig {
            kubeconfig: root.path().join("kubeconfig"),
            cluster: "unit-cluster".to_owned(),
            namespace: "unit-namespace".to_owned(),
            allowed_nodes: std::collections::BTreeSet::new(),
            request_timeout: Duration::from_secs(5),
            teardown_timeout: Duration::from_secs(5),
        },
        ledger,
        stops,
        artifact_root: root.path().join("artifacts"),
        snapshot: Arc::new(
            odin_registry::Snapshot::build(1, Vec::new()).expect("fixture snapshot"),
        ),
        config_revision: 1,
        launch_binding: None,
        workload_identity: crate::kube::WorkloadExtensionIdentity {
            artifact: odin_domain::ArtifactId::new(
                odin_domain::Digest::hash(b"absent-pod-identity").to_string(),
            )
            .expect("artifact id"),
            deployment: Default::default(),
        },
    });
    let mut pending = pending;
    super::drain_pending_pod_releases(&cell, &mut pending).await;
    assert_eq!(pending.len(), 1, "the release stays pending");
    super::drain_pending_pod_releases(&cell, &mut pending).await;
    assert_eq!(
        pending.len(),
        1,
        "the release is retried independently of the settlement"
    );

    // Another daemon restart: the settlement survives it durably — the
    // resting scan never offers the pod again (no repeated report, no
    // repeated settlement log), the backlog still seeds, and the journal
    // carries the terminal marker exactly once.
    drop(control);
    drop(supervisor);
    let supervisor = LiveSupervisor::discover(
        Arc::new(FsLiveLedger::open(root.path()).expect("reopen after settle")),
        Arc::new(NoLaunch),
        256,
        None,
    )
    .await
    .expect("rediscover");
    let control = control_over(&supervisor);
    assert!(
        control
            .resting_workload_sessions()
            .expect("resting scan")
            .is_empty(),
        "the settled pod is never offered to the report decision again"
    );
    assert_eq!(
        control.stop_child(session).expect("settle across restart"),
        odin_omp::host_tools::delegation::ChildStop::AlreadyTerminal,
        "the settlement survives the restart without a new write"
    );
    assert_eq!(
        settled_absent_markers(&supervisor, session).await,
        1,
        "the durable terminal marker is journaled exactly once"
    );
}

/// Journals one resting workload pod's durable state exactly as a dead
/// daemon leaves it: the manifest with its launch operation, the Idle
/// transition, and the whole answer — no live actor anywhere.
async fn fixture_resting_pod(root: &std::path::Path, session: LiveSessionId, operation: &str) {
    fixture_resting_pod_answer(
        root,
        session,
        operation,
        "The run finished; the answer is whole.",
        false,
    )
    .await;
}

async fn fixture_resting_pod_answer(
    root: &std::path::Path,
    session: LiveSessionId,
    operation: &str,
    answer: &str,
    failed: bool,
) {
    use odin_domain::huginn::{
        LiveContentBlock, LiveEventBody, LiveMessage, LiveSessionState, ModelName, ProviderName,
        SessionEpoch, SessionManifest, SessionStateChanged, WorkloadSessionBinding,
    };
    use odin_domain::{EventId, NodeId, ProjectId, SeatId, SliceId};
    use odin_omp::live::ledger::{fs::FsLiveLedger, LiveLedger, NewLiveEvent};

    let ledger: Arc<dyn LiveLedger> = Arc::new(FsLiveLedger::open(root).expect("ledger"));
    ledger
        .create_session(SessionManifest {
            session_id: session,
            seat_id: SeatId::new("seat:absent-pod").expect("seat id"),
            slice_id: SliceId::new("slice:absent-pod").expect("slice id"),
            project_id: ProjectId::new("project:absent-pod").expect("project id"),
            provider: ProviderName::new("fixture").expect("provider name"),
            model: ModelName::new("fixture-model").expect("model name"),
            title: None,
            target_node: NodeId::new("node:absent-pod").expect("node id"),
            open_tab: false,
            workload: Some(WorkloadSessionBinding {
                profile: "research-read".to_owned(),
                snapshot_revision: 1,
                operation: operation.to_owned(),
                inputs: Vec::new(),
                launching_run: None,
            }),
            served_revision: None,
            harness: None,
        })
        .await
        .expect("fixture session");
    let now = if failed {
        // The restarted scan reports a failed workload only after its
        // existing takeover grace; seed that durable age, never wait it out.
        let grace = i64::try_from(odin_omp::host_tools::delegation::FAILED_POD_GRACE_MS)
            .expect("grace fits the journal timestamp");
        OffsetDateTime::now_utc() - time::Duration::milliseconds(grace + 1)
    } else {
        OffsetDateTime::now_utc()
    };
    let event = |id: String, body| NewLiveEvent {
        session_id: session,
        event_id: EventId::new(id).expect("event id"),
        occurred_at: now,
        body,
    };
    ledger
        .append(
            SessionEpoch::new(1),
            event(
                format!("absent-pod:settled:{session}"),
                LiveEventBody::SessionStateChanged(SessionStateChanged {
                    previous: LiveSessionState::Starting,
                    current: if failed {
                        LiveSessionState::Failed
                    } else {
                        LiveSessionState::Idle
                    },
                    reason: Some("fixture".to_owned()),
                }),
            ),
        )
        .await
        .expect("fixture idle");
    ledger
        .append(
            SessionEpoch::new(1),
            event(
                format!("absent-pod:answer:{session}"),
                LiveEventBody::AssistantMessage(
                    LiveMessage::new(vec![LiveContentBlock::Text(answer.to_owned())])
                        .expect("message"),
                ),
            ),
        )
        .await
        .expect("fixture answer");
}

/// How many durable `settled-absent` terminal markers the session's
/// journal carries: the exactly-once settlement observable.
async fn settled_absent_markers(supervisor: &Arc<LiveSupervisor>, session: LiveSessionId) -> usize {
    use odin_domain::huginn::{EventSeq, HistoryQuery};
    use odin_domain::EventId;

    let settled_marker = EventId::new(format!("settled-absent:{session}")).expect("event id");
    let (mut after, mut markers) = (EventSeq::new(0), 0usize);
    loop {
        let page = supervisor
            .history(HistoryQuery {
                session_id: session,
                after,
                limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
            })
            .await
            .expect("history");
        if page.events.is_empty() {
            break;
        }
        for event in &page.events {
            after = event.sequence;
            markers += usize::from(event.event_id == settled_marker);
        }
        if page.next_after >= page.head {
            break;
        }
    }
    markers
}

/// Ended sessions leave the resting scan, so carrier release needs its own retry queue.
#[tokio::test]
async fn a_failed_carrier_release_stays_pending_and_is_retried() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = Arc::new(std::sync::Mutex::new(
        odin_ledger::Ledger::open_in_memory().expect("ledger"),
    ));
    let bus = odin_process::BusAddress::unix_socket(dir.path().join("stop-bus.sock"))
        .expect("bus address");
    let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
    let stops = Arc::new(odin_kernel::stop::StopAuthority::new(
        Arc::clone(&ledger),
        channel,
    ));
    let cell = crate::kube::KubeRuntimeCell::new(crate::kube::CellInputs {
        config: odin_kube::config::KubeConfig {
            kubeconfig: dir.path().join("kubeconfig"),
            cluster: "unit-cluster".to_owned(),
            namespace: "unit-namespace".to_owned(),
            allowed_nodes: std::collections::BTreeSet::new(),
            request_timeout: Duration::from_secs(5),
            teardown_timeout: Duration::from_secs(5),
        },
        ledger,
        stops,
        artifact_root: dir.path().join("artifacts"),
        snapshot: Arc::new(
            odin_registry::Snapshot::build(1, Vec::new()).expect("fixture snapshot"),
        ),
        config_revision: 1,
        launch_binding: None,
        workload_identity: crate::kube::WorkloadExtensionIdentity {
            artifact: odin_domain::ArtifactId::new(
                odin_domain::Digest::hash(b"release-backlog-identity").to_string(),
            )
            .expect("artifact id"),
            deployment: Default::default(),
        },
    });
    let session = odin_domain::huginn::LiveSessionId::parse("00000000-0000-4000-8000-00000000c0a1")
        .expect("session id");
    let mut pending = vec![(session, "op-000000000000000000000000c0a1".to_owned())];
    super::drain_pending_pod_releases(&cell, &mut pending).await;
    assert_eq!(pending.len(), 1, "a failed release stays queued");
    super::drain_pending_pod_releases(&cell, &mut pending).await;
    assert_eq!(
        pending.len(),
        1,
        "the queued release is retried, not dropped"
    );
}

/// Preserve multibyte text and tail sections through durable scheduling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_pod_report_queues_whole_through_the_real_schedule_store() {
    assert_long_pod_report(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_pod_preserves_its_whole_partial_answer_in_the_schedule_store() {
    assert_long_pod_report(true).await;
}

async fn assert_long_pod_report(failed: bool) {
    // Include combining characters and distinct tail sections to detect truncation.
    let mut answer = format!(
        "The PDF text ends at the references. {}",
        "方".repeat(1_953)
    );
    answer.push_str("ψ̂ is the bias-corrected estimate, so λ grows with the corrected model.");
    let pad = 4_660usize.saturating_sub(answer.chars().count());
    answer.push_str(&"文".repeat(pad));
    answer.push_str("Limitations the paper itself states\n\nThe ablation holds only under …");
    let pad = 8_300usize.saturating_sub(answer.chars().count());
    answer.push_str(&"结".repeat(pad));
    answer
        .push_str("Citation(s): ChemNODE 2026; the full reference list runs through the appendix.");
    assert!(answer.chars().count() > 8_265, "{}", answer.chars().count());
    assert_eq!(
        answer.chars().skip(1_990).take(2).collect::<String>(),
        "ψ̂",
        "the old 2,000-char cut lands mid-glyph"
    );
    let limitations_at = answer.split("Limitations").next().unwrap().chars().count();
    assert!(
        limitations_at > 4_000,
        "Limitations sits at char {limitations_at}"
    );

    let session = odin_domain::huginn::LiveSessionId::parse("a472c813-76e1-48a0-a5c4-04b766666224")
        .expect("session id");
    // Start from durable history to exercise the supervisor's report reader.
    let history_root = tempfile::tempdir().expect("history tempdir");
    fixture_resting_pod_answer(
        history_root.path(),
        session,
        "op-live-dm05",
        &answer,
        failed,
    )
    .await;
    let supervisor = LiveSupervisor::discover(
        Arc::new(
            odin_omp::live::ledger::fs::FsLiveLedger::open(history_root.path()).expect("reopen"),
        ),
        Arc::new(ReportReadOnly),
        256,
        None,
    )
    .await
    .expect("discover durable answer");
    let supervisor_cell = Arc::new(std::sync::OnceLock::new());
    supervisor_cell
        .set(Arc::downgrade(&supervisor))
        .expect("supervisor handle");
    let control = Arc::new(crate::live_authority::SupervisorChildControl::new(
        supervisor_cell,
        Arc::new(std::sync::OnceLock::new()),
    ));
    assert_eq!(
        control.last_answer(session, None).expect("durable answer"),
        Some(answer.clone())
    );
    let owner = odin_omp::host_tools::delegation::GovernedTaskOwner::new(
        Arc::new(ReportReadOnly),
        control,
        odin_omp::host_tools::delegation::DelegationLinkLedger::open(
            history_root.path().join("links"),
        )
        .expect("links"),
        Arc::new(std::sync::Mutex::new(
            odin_ledger::Ledger::open_in_memory().expect("ledger"),
        )),
        odin_omp::host_tools::delegation::DelegationGovernance {
            provider: "fixture".to_owned(),
            model: "fixture".to_owned(),
            max_children_per_session: 1,
            max_prompt_bytes: 8192,
            approved_projects: Default::default(),
            operation_bindings: Default::default(),
        },
    );
    let pods = owner.settled_workloads().expect("settled workloads");
    assert_eq!(pods.len(), 1);
    let pod = &pods[0];
    assert_eq!(pod.session, session);
    assert_eq!(pod.operation, "op-live-dm05");
    assert_eq!(pod.failed, failed);
    assert_eq!(pod.answer, answer);
    assert_eq!(
        pod.answer.chars().skip(8300).collect::<String>(),
        "Citation(s): ChemNODE 2026; the full reference list runs through the appendix."
    );
    let text = super::pod_report_text(pod);

    // The production enqueue into a real Hermes schedule store (the wake
    // is persisted under the Hermes state directory, not echoed by a
    // mock), exactly as the pump queues it.
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().to_path_buf(),
        None,
        None,
        None,
        Vec::new(),
    )
    .expect("hermes settings");
    let ledgers = odin_hermes::runtime::HermesLedgers {
        conversation: odin_ledger::Ledger::open_in_memory().expect("ledger"),
        adapter: std::sync::Arc::new(parking_lot::Mutex::new(
            odin_ledger::Ledger::open_in_memory().expect("ledger"),
        )),
        purchase: std::sync::Arc::new(std::sync::Mutex::new(
            odin_ledger::Ledger::open_in_memory().expect("ledger"),
        )),
    };
    let runtime = odin_hermes::runtime::HermesRuntime::open(
        settings,
        ledgers,
        &std::collections::BTreeMap::new(),
        None,
        8,
        std::collections::BTreeMap::new(),
        None,
    )
    .expect("hermes runtime");
    let added = runtime
        .wake_once(&format!("pod-{}-{}", pod.session, pod.key), &text)
        .expect("the real schedule store accepts the whole report");
    assert!(added, "the pod report is queued once under its key");

    let store = odin_hermes::schedule::ScheduleStore::open(dir.path()).expect("store");
    let id = format!("pod-{}-{}", pod.session, pod.key);
    let row = store
        .list()
        .expect("list")
        .into_iter()
        .find(|row| row.id == id)
        .expect("the pod report row is queued");
    assert!(
        row.text.contains(&answer),
        "the persisted report must retain the entire journaled answer, including its Unicode and citation tail"
    );
}

/// The launcher supplies observation frames while control calls have no effects.
struct FrameBackend;

#[async_trait::async_trait]
impl odin_omp::live::control::LiveControlBackend for FrameBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(
        &self,
        _: &odin_domain::huginn::LiveMessage,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn follow_up(
        &self,
        _: &odin_domain::huginn::LiveMessage,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn steer(
        &self,
        _: &odin_domain::huginn::LiveMessage,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn pause(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn rehome(&self, _: &odin_domain::NodeId) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn set_model(
        &self,
        _: &odin_domain::huginn::ProviderName,
        _: &odin_domain::huginn::ModelName,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn decide_permission(
        &self,
        _: &odin_domain::huginn::PermissionRequestId,
        _: odin_domain::huginn::PermissionDecision,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &odin_domain::ApprovalId,
        _: u64,
        _: odin_domain::huginn::ApprovalDecision,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        Ok(())
    }
}

/// Opens real actors whose observation stream the test owns, like the
/// bridge pump does in production.
#[derive(Default)]
struct FrameLauncher {
    feeds: std::sync::Mutex<
        std::collections::BTreeMap<
            LiveSessionId,
            tokio::sync::broadcast::Sender<odin_omp::bridge::ObservedFrame>,
        >,
    >,
}

impl FrameLauncher {
    fn feed(&self, session: LiveSessionId, frame: serde_json::Value) {
        let decoded = odin_omp::frames::RpcFrameDecoder::default()
            .push_physical_line(format!("{frame}\n").as_bytes())
            .expect("scripted frame decodes")
            .expect("complete frame");
        self.feeds
            .lock()
            .expect("feeds")
            .get(&session)
            .expect("the session was opened through this launcher")
            .send(odin_omp::bridge::ObservedFrame {
                class: odin_omp::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            })
            .expect("the actor holds its observation receiver");
    }
}

#[async_trait::async_trait]
impl odin_omp::live::supervisor::LiveSessionLauncher for FrameLauncher {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        manifest: &odin_domain::huginn::SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<odin_omp::live::supervisor::SessionRuntime, odin_domain::huginn::LiveError> {
        let (feed, observations) = tokio::sync::broadcast::channel(64);
        self.feeds
            .lock()
            .expect("feeds")
            .insert(manifest.session_id, feed);
        Ok(odin_omp::live::supervisor::SessionRuntime {
            control: Arc::new(FrameBackend),
            terminal: None,
            observations: Some(observations),
            failed_notices: None,
        })
    }
}

const PUMP_OUTAGE: &str = "500 litellm.APIConnectionError: APIConnectionError: OpenAIException -";
/// OMP's own give-up on a silent stream: a fault Odin answers.
const PUMP_STALL: &str = "OpenAI completions stream stalled while waiting for the next event";
const PUMP_PARTIAL: &str = "partial-work-marker-77";
/// Real elapsed time put between a failure and the late traffic behind it,
/// so the failure instant and the newest event instant cannot coincide.
const FAILURE_AGE_GAP_MS: u64 = 300;

/// Optionally journal partial assistant text before failing the provider turn.
fn pump_failed_turn(launcher: &FrameLauncher, session: LiveSessionId, partial: Option<&str>) {
    pump_failed_turn_with(launcher, session, PUMP_OUTAGE, partial);
}

fn pump_failed_turn_with(
    launcher: &FrameLauncher,
    session: LiveSessionId,
    error: &str,
    partial: Option<&str>,
) {
    let failed = serde_json::json!({
        "role": "assistant",
        "stopReason": "error",
        "errorStatus": 500,
        "errorMessage": error,
        "content": [{"type": "text", "text": partial.unwrap_or("Partial answer from a failed request.")}]
    });
    launcher.feed(session, serde_json::json!({"type": "agent_start"}));
    if partial.is_some() {
        launcher.feed(
            session,
            serde_json::json!({"type": "message_end", "message": failed.clone()}),
        );
    }
    launcher.feed(
        session,
        serde_json::json!({"type": "turn_end", "message": failed.clone()}),
    );
    launcher.feed(
        session,
        serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "yielded": true,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                failed
            ]
        }),
    );
}

/// One turn that completes normally with `text` as its answer.
fn pump_answered_turn(launcher: &FrameLauncher, session: LiveSessionId, text: &str) {
    let answer = serde_json::json!({
        "role": "assistant",
        "stopReason": "stop",
        "content": [{"type": "text", "text": text}]
    });
    launcher.feed(session, serde_json::json!({"type": "agent_start"}));
    launcher.feed(
        session,
        serde_json::json!({"type": "message_end", "message": answer.clone()}),
    );
    launcher.feed(
        session,
        serde_json::json!({
            "type": "agent_end",
            "isTerminal": true,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "Perform one bounded task."}]},
                answer
            ]
        }),
    );
}

async fn await_state(
    supervisor: &Arc<LiveSupervisor>,
    session: LiveSessionId,
    wanted: odin_domain::huginn::LiveSessionState,
) {
    for _ in 0..200 {
        let actor = supervisor.actor(session).await.expect("live actor");
        if actor.summary().expect("summary").state == wanted {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the child never reached {wanted:?}");
}

async fn results_journaled(supervisor: &Arc<LiveSupervisor>, session: LiveSessionId) -> usize {
    use odin_domain::huginn::{EventSeq, HistoryQuery, LiveEventBody};

    let (mut after, mut results) = (EventSeq::new(0), 0usize);
    loop {
        let page = supervisor
            .history(HistoryQuery {
                session_id: session,
                after,
                limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
            })
            .await
            .expect("history");
        if page.events.is_empty() {
            break;
        }
        for event in &page.events {
            after = event.sequence;
            results += usize::from(matches!(event.body, LiveEventBody::Result(_)));
        }
        if page.next_after >= page.head {
            break;
        }
    }
    results
}

/// The report rows the schedule store holds for one child, oldest first.
fn child_report_rows(state: &std::path::Path, child: LiveSessionId) -> Vec<(String, String)> {
    let prefix = format!("child-{child}-");
    odin_hermes::schedule::ScheduleStore::open(state)
        .expect("store")
        .list()
        .expect("list")
        .into_iter()
        .filter(|row| row.id.starts_with(&prefix))
        .map(|row| (row.id, row.text))
        .collect()
}

async fn await_report_rows(
    state: &std::path::Path,
    child: LiveSessionId,
    count: usize,
) -> Vec<(String, String)> {
    for _ in 0..200 {
        let rows = child_report_rows(state, child);
        if rows.len() >= count {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the pump never queued {count} report(s) for the child");
}

/// A real pump over real actors: the supervisor owns the children, the
/// production `SupervisorChildControl` reads them, and the reports land in a
/// real Hermes schedule store.
struct PumpFixture {
    _root: tempfile::TempDir,
    state: tempfile::TempDir,
    supervisor: Arc<LiveSupervisor>,
    launcher: Arc<FrameLauncher>,
    control: Arc<crate::live_authority::SupervisorChildControl>,
    owner: Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>,
    links: odin_omp::host_tools::delegation::DelegationLinkLedger,
    pumps: tokio::task::JoinSet<Result<(), String>>,
    opened: usize,
}

fn pump_seat() -> odin_domain::SeatId {
    odin_domain::SeatId::new("seat.architect").expect("seat")
}

impl PumpFixture {
    async fn start() -> Self {
        use odin_omp::live::ledger::fs::FsLiveLedger;

        let root = tempfile::tempdir().expect("root");
        let launcher = Arc::new(FrameLauncher::default());
        let supervisor = LiveSupervisor::new(
            Arc::new(FsLiveLedger::open(root.path().join("live")).expect("live ledger")),
            launcher.clone() as Arc<dyn odin_omp::live::supervisor::LiveSessionLauncher>,
            8,
            None,
        );
        supervisor
            .bind(odin_omp::live::supervisor::LiveSeatBinding {
                seat_id: pump_seat(),
                slice_id: odin_domain::SliceId::new("slice:pump").expect("slice id"),
                display_name: "Pump fixture".to_owned(),
                launch_options: vec![odin_domain::huginn::LiveLaunchOption {
                    provider: odin_domain::huginn::ProviderName::new("fixture")
                        .expect("provider name"),
                    model: odin_domain::huginn::ModelName::new("fixture-model")
                        .expect("model name"),
                    skeleton_ref: "pump-fixture".to_owned(),
                    container_id: odin_domain::ContainerId::new("pump-native").expect("container"),
                    harness: None,
                }],
                allowed_nodes: vec![odin_domain::NodeId::new("node:pump").expect("node id")],
                max_sessions: 8,
                turn_budget: None,
            })
            .await
            .expect("bind fixture seat");
        let supervisor_cell: crate::live_authority::SupervisorHandle =
            Arc::new(std::sync::OnceLock::new());
        supervisor_cell
            .set(Arc::downgrade(&supervisor))
            .expect("supervisor handle");
        let pool_cell: crate::live_authority::SessionPoolHandle =
            Arc::new(std::sync::OnceLock::new());
        let control = Arc::new(crate::live_authority::SupervisorChildControl::new(
            supervisor_cell,
            pool_cell,
        ));
        let links =
            odin_omp::host_tools::delegation::DelegationLinkLedger::open(root.path().join("links"))
                .expect("links");
        let owner = Arc::new(odin_omp::host_tools::delegation::GovernedTaskOwner::new(
            Arc::new(ReportReadOnly),
            control.clone(),
            links.clone(),
            Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("ledger"),
            )),
            odin_omp::host_tools::delegation::DelegationGovernance {
                provider: "fixture".to_owned(),
                model: "fixture".to_owned(),
                max_children_per_session: 1,
                max_prompt_bytes: 8192,
                approved_projects: Default::default(),
                operation_bindings: Default::default(),
            },
        ));

        let state = tempfile::tempdir().expect("hermes state");
        let settings = odin_hermes::config::HermesSettings::new(
            state.path().to_path_buf(),
            None,
            None,
            None,
            Vec::new(),
        )
        .expect("hermes settings");
        let ledgers = odin_hermes::runtime::HermesLedgers {
            conversation: odin_ledger::Ledger::open_in_memory().expect("ledger"),
            adapter: std::sync::Arc::new(parking_lot::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("ledger"),
            )),
            purchase: std::sync::Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open_in_memory().expect("ledger"),
            )),
        };
        let runtime = odin_hermes::runtime::HermesRuntime::open(
            settings,
            ledgers,
            &std::collections::BTreeMap::new(),
            None,
            8,
            std::collections::BTreeMap::new(),
            None,
        )
        .expect("hermes runtime");
        let desk = Arc::new(crate::incidents::IncidentDesk::new(
            Arc::new(odin_huginn::read_model::MaterializedReadModel::new(
                1024,
                OffsetDateTime::now_utc(),
            )),
            None,
            None,
        ));
        let mut pumps = tokio::task::JoinSet::new();
        super::arm_child_report_pump(
            &mut pumps,
            runtime,
            owner.clone(),
            pump_seat(),
            None,
            None,
            desk,
        );
        Self {
            _root: root,
            state,
            supervisor,
            launcher,
            control,
            owner,
            links,
            pumps,
            opened: 0,
        }
    }

    /// Opens one real child actor, delegated by the pump's seat.
    async fn delegate(&mut self) -> LiveSessionId {
        self.opened += 1;
        let opened = self.opened;
        let summary = self
            .supervisor
            .open(odin_domain::huginn::OpenSessionRequest {
                command_id: odin_domain::CommandId::new(format!("command:pump-child-{opened}"))
                    .expect("command id"),
                seat_id: pump_seat(),
                project_id: odin_domain::ProjectId::new("project.odin").expect("project"),
                slice_id: odin_domain::SliceId::new("slice:pump").expect("slice id"),
                provider: odin_domain::huginn::ProviderName::new("fixture").expect("provider name"),
                model: odin_domain::huginn::ModelName::new("fixture-model").expect("model name"),
                title: None,
                target_node: odin_domain::NodeId::new("node:pump").expect("node id"),
                open_tab: false,
                initial_prompt: None,
                workload: None,
                served_revision: None,
            })
            .await
            .expect("open the child");
        let child = summary.session_id;
        self.links
            .persist(&odin_omp::host_tools::delegation::DelegationLink {
                schema: odin_omp::host_tools::delegation::DELEGATION_LINK_SCHEMA.to_owned(),
                child,
                parent: odin_domain::SessionId::new("00000000-0000-4000-8000-0000000000a1")
                    .expect("parent"),
                parent_seat: Some(pump_seat()),
                parent_run: odin_domain::RunId::new(
                    "run:live:00000000-0000-4000-8000-0000000000a0",
                )
                .expect("parent run"),
                child_run: odin_omp::host_tools::delegation::GovernedTaskOwner::child_run_for(
                    &child,
                )
                .expect("child run"),
                command: odin_domain::CommandId::new(format!("odin.task.create:{child}"))
                    .expect("command"),
                project: odin_domain::ProjectId::new("project.odin").expect("project"),
                provider: "fixture".to_owned(),
                model: "fixture".to_owned(),
                prompt_digest: odin_domain::Digest::hash(b"Perform one bounded task."),
                depth: 1,
                phase: odin_omp::host_tools::delegation::DelegationPhase::Running,
                created_at_ms: u64::try_from(
                    OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
                )
                .expect("clock"),
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
        child
    }

    fn wake(&self) {
        self.owner.result_wake().notify_one();
    }

    async fn control_call<T: Send + 'static>(
        &self,
        call: impl FnOnce(Arc<crate::live_authority::SupervisorChildControl>) -> T + Send + 'static,
    ) -> T {
        let control = Arc::clone(&self.control);
        tokio::task::spawn_blocking(move || call(control))
            .await
            .expect("control call")
    }

    async fn finish(&mut self) {
        self.pumps.abort_all();
        while let Some(outcome) = self.pumps.join_next().await {
            match outcome {
                Err(error) if error.is_cancelled() => {}
                Ok(Ok(())) => {}
                other => panic!("report pump failed before shutdown: {other:?}"),
            }
        }
        self.supervisor
            .shutdown()
            .await
            .expect("all fixture actors stop");
    }
}

impl Drop for PumpFixture {
    fn drop(&mut self) {
        self.pumps.abort_all();
    }
}

/// Wait for observable reports and joined shutdown rather than assuming sleeps allow consumption.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_child_is_reported_once_per_incarnation_through_the_real_pump() {
    use odin_domain::huginn::{LiveCommandBody, LiveSessionState};

    let mut fixture = PumpFixture::start().await;
    let child = fixture.delegate().await;
    pump_failed_turn(&fixture.launcher, child, Some(PUMP_PARTIAL));
    await_state(&fixture.supervisor, child, LiveSessionState::Failed).await;
    fixture.wake();
    let first = await_report_rows(fixture.state.path(), child, 1).await;
    assert_eq!(first.len(), 1);
    assert!(first[0].1.contains(PUMP_PARTIAL));
    assert_eq!(results_journaled(&fixture.supervisor, child).await, 0);

    fixture
        .control_call(move |control| control.command(child, LiveCommandBody::Restart))
        .await
        .expect("the actor admits the restart");
    await_state(&fixture.supervisor, child, LiveSessionState::Idle).await;
    let fresh_answer = fixture
        .control_call(move |control| {
            let snapshot = control.snapshot(child).expect("current incarnation");
            control.last_answer(child, snapshot.epoch)
        })
        .await
        .expect("current-incarnation history");
    assert_eq!(fresh_answer, None, "old failed text is not a fresh answer");
    fixture
        .control_call(move |control| control.prompt(child, "Continue the bounded task."))
        .await
        .expect("the restarted child takes its prompt");
    await_state(&fixture.supervisor, child, LiveSessionState::Running).await;
    let second_partial = format!("{PUMP_PARTIAL} second incarnation");
    pump_failed_turn(&fixture.launcher, child, Some(&second_partial));
    await_state(&fixture.supervisor, child, LiveSessionState::Failed).await;
    fixture.wake();
    let both = await_report_rows(fixture.state.path(), child, 2).await;
    assert!(both[1].1.contains(&second_partial));
    assert_eq!(results_journaled(&fixture.supervisor, child).await, 0);
    fixture.finish().await;

    let retained = child_report_rows(fixture.state.path(), child);
    assert_eq!(retained, both);
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0], first[0], "the first report is immutable");
    assert_ne!(retained[0].0, retained[1].0, "distinct failed incarnations");
}

/// A successful report and joined shutdown delimit when the working child must remain unreported.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn working_and_answered_children_keep_their_pump_reports() {
    use odin_domain::huginn::LiveSessionState;

    let mut fixture = PumpFixture::start().await;
    let working = fixture.delegate().await;
    let answered = fixture.delegate().await;
    fixture
        .launcher
        .feed(working, serde_json::json!({"type": "agent_start"}));
    await_state(&fixture.supervisor, working, LiveSessionState::Running).await;
    let answer = "The task is done and this is the whole answer.";
    pump_answered_turn(&fixture.launcher, answered, answer);
    tokio::time::timeout(Duration::from_secs(10), async {
        while results_journaled(&fixture.supervisor, answered).await != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the actual turn result, not the initial Idle state");
    await_state(&fixture.supervisor, answered, LiveSessionState::Idle).await;
    fixture.wake();
    let rows = await_report_rows(fixture.state.path(), answered, 1).await;
    assert!(rows[0].1.contains(answer));
    fixture.finish().await;

    let retained = child_report_rows(fixture.state.path(), answered);
    assert_eq!(retained.len(), 1);
    assert_eq!(retained, rows);
    assert!(child_report_rows(fixture.state.path(), working).is_empty());
}

fn unix_ms(at: OffsetDateTime) -> u64 {
    u64::try_from(at.unix_timestamp_nanos() / 1_000_000).expect("clock after the epoch")
}

async fn summary_of(
    supervisor: &Arc<LiveSupervisor>,
    session: LiveSessionId,
) -> odin_domain::huginn::LiveSessionSummary {
    supervisor
        .actor(session)
        .await
        .expect("live actor")
        .summary()
        .expect("summary")
}

/// The journal sequence of the child's provider-turn error event.
async fn provider_error_sequence(supervisor: &Arc<LiveSupervisor>, session: LiveSessionId) -> u64 {
    use odin_domain::huginn::{EventSeq, HistoryQuery, LiveEventBody};

    let page = supervisor
        .history(HistoryQuery {
            session_id: session,
            after: EventSeq::new(0),
            limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
        })
        .await
        .expect("history");
    let errors: Vec<u64> = page
        .events
        .iter()
        .filter(|event| {
            matches!(&event.body, LiveEventBody::Error(error) if error.code == "provider_turn_error")
        })
        .map(|event| event.sequence.get())
        .collect();
    assert_eq!(errors.len(), 1, "one provider error in the journal");
    errors[0]
}

/// Traffic that journals behind an already failed child without leaving
/// `Failed`; the journal head moving is the positive observation that it
/// landed.
async fn late_assistant_text(fixture: &PumpFixture, session: LiveSessionId, text: &str) {
    let before = summary_of(&fixture.supervisor, session).await.event_head;
    fixture.launcher.feed(
        session,
        serde_json::json!({
            "type": "message_end",
            "message": {"role": "assistant", "content": [{"type": "text", "text": text}]}
        }),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while summary_of(&fixture.supervisor, session).await.event_head == before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the late frame journals");
}

/// Later traffic must not move the first-failure timestamp.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_real_child_control_snapshots_an_answerable_fault_and_the_first_failure_instant() {
    use odin_domain::huginn::LiveSessionState;
    use odin_omp::host_tools::delegation::{
        ProviderFaultKind, ProviderFaultOrigin, ProviderTurnFault,
    };

    let mut fixture = PumpFixture::start().await;
    let stalled = fixture.delegate().await;
    let outage = fixture.delegate().await;
    pump_failed_turn_with(&fixture.launcher, stalled, PUMP_STALL, Some(PUMP_PARTIAL));
    pump_failed_turn(&fixture.launcher, outage, None);
    await_state(&fixture.supervisor, stalled, LiveSessionState::Failed).await;
    await_state(&fixture.supervisor, outage, LiveSessionState::Failed).await;

    let failure = summary_of(&fixture.supervisor, stalled).await;
    let failed_at = unix_ms(
        failure
            .failed_at
            .expect("the actor records the failure instant"),
    );
    let error_event = provider_error_sequence(&fixture.supervisor, stalled).await;
    let snapshot = fixture
        .control_call(move |control| control.snapshot(stalled))
        .await
        .expect("the real snapshot");
    assert!(snapshot.active);
    assert_eq!(snapshot.state, Some(LiveSessionState::Failed));
    assert_eq!(
        snapshot.epoch,
        Some(i64::try_from(failure.epoch.get()).expect("epoch"))
    );
    assert_eq!(snapshot.settled_since_ms, Some(failed_at));
    assert_eq!(snapshot.quiet_since_ms, None);
    assert_eq!(
        snapshot.provider_fault,
        Some(ProviderTurnFault {
            event: error_event,
            kind: ProviderFaultKind::Stall,
            origin: ProviderFaultOrigin::Provider,
        }),
        "the fault is the journaled error event itself, answered as a stall"
    );

    // Real elapsed time puts the late traffic strictly after the failure, so
    // `updated_at` and `failed_at` cannot coincide.
    tokio::time::sleep(Duration::from_millis(FAILURE_AGE_GAP_MS)).await;
    late_assistant_text(&fixture, stalled, "late diagnostic prose").await;
    let after = summary_of(&fixture.supervisor, stalled).await;
    assert_eq!(after.state, LiveSessionState::Failed);
    assert!(
        unix_ms(after.updated_at) >= failed_at + FAILURE_AGE_GAP_MS,
        "late traffic moved the newest-event instant"
    );
    assert_eq!(after.failed_at, failure.failed_at);
    let later = fixture
        .control_call(move |control| control.snapshot(stalled))
        .await
        .expect("the real snapshot after late traffic");
    assert_eq!(
        later.settled_since_ms,
        Some(failed_at),
        "late traffic does not postpone the first failure instant"
    );

    let unanswered = summary_of(&fixture.supervisor, outage).await;
    let outage_snapshot = fixture
        .control_call(move |control| control.snapshot(outage))
        .await
        .expect("the real outage snapshot");
    assert_eq!(outage_snapshot.state, Some(LiveSessionState::Failed));
    assert_eq!(
        outage_snapshot.settled_since_ms,
        Some(unix_ms(unanswered.failed_at.expect("failure instant")))
    );
    assert_eq!(outage_snapshot.provider_fault, None);
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_child_is_retired_by_the_idle_budget_from_its_first_failure() {
    use odin_domain::huginn::LiveSessionState;
    use odin_omp::host_tools::delegation::DelegationPhase;

    let mut fixture = PumpFixture::start().await;
    let failed = fixture.delegate().await;
    let working = fixture.delegate().await;
    pump_failed_turn(&fixture.launcher, failed, Some(PUMP_PARTIAL));
    fixture
        .launcher
        .feed(working, serde_json::json!({"type": "agent_start"}));
    await_state(&fixture.supervisor, failed, LiveSessionState::Failed).await;
    await_state(&fixture.supervisor, working, LiveSessionState::Running).await;
    tokio::time::sleep(Duration::from_millis(FAILURE_AGE_GAP_MS)).await;
    late_assistant_text(&fixture, failed, "late diagnostic prose").await;

    // Elapsed since the failure is at least the gap; elapsed since the late
    // frame is only the retirement call's own latency.
    let idle = Duration::from_millis(FAILURE_AGE_GAP_MS / 2);
    let owner = Arc::clone(&fixture.owner);
    let (retired, failures) = tokio::task::spawn_blocking(move || {
        owner.retire_timed_out_children(Duration::from_secs(3600), Some(idle))
    })
    .await
    .expect("retirement scan")
    .expect("retirement scan succeeds");
    assert!(failures.is_empty(), "no stop failed: {failures:?}");
    assert_eq!(retired, vec![failed], "only the failed child is retired");

    let row = fixture
        .links
        .load(&failed)
        .expect("row read")
        .expect("failed child's row");
    assert_eq!(row.phase, DelegationPhase::Ended);
    let ended = fixture
        .control_call(move |control| control.snapshot(failed))
        .await
        .expect("snapshot after retirement");
    assert!(
        !ended.active || ended.state == Some(LiveSessionState::Ended),
        "the failed child is torn down: {ended:?}"
    );
    let still = fixture
        .links
        .load(&working)
        .expect("row read")
        .expect("working child's row");
    assert_eq!(still.phase, DelegationPhase::Running);
    assert_eq!(
        summary_of(&fixture.supervisor, working).await.state,
        LiveSessionState::Running
    );
    fixture.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_and_an_answered_child_with_the_same_prose_queue_different_reports() {
    use odin_domain::huginn::LiveSessionState;
    use odin_omp::host_tools::delegation::SettledChild;

    let prose = "the same observed prose in both children";
    let mut fixture = PumpFixture::start().await;
    let failed = fixture.delegate().await;
    let answered = fixture.delegate().await;
    pump_failed_turn(&fixture.launcher, failed, Some(prose));
    pump_answered_turn(&fixture.launcher, answered, prose);
    await_state(&fixture.supervisor, failed, LiveSessionState::Failed).await;
    tokio::time::timeout(Duration::from_secs(10), async {
        while results_journaled(&fixture.supervisor, answered).await != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the answered child's actual turn result");
    await_state(&fixture.supervisor, answered, LiveSessionState::Idle).await;
    fixture.wake();
    let failed_rows = await_report_rows(fixture.state.path(), failed, 1).await;
    let answered_rows = await_report_rows(fixture.state.path(), answered, 1).await;
    assert_eq!(results_journaled(&fixture.supervisor, failed).await, 0);
    assert_eq!(results_journaled(&fixture.supervisor, answered).await, 1);
    fixture.finish().await;

    let key_of = |child: LiveSessionId, id: &str| {
        id.strip_prefix(&format!("child-{child}-"))
            .expect("row id names its child")
            .to_owned()
    };
    let rendering = |child: LiveSessionId, id: &str, failed: bool| {
        super::settled_child_report(&SettledChild {
            child,
            key: key_of(child, id),
            answer: prose.to_owned(),
            failed,
        })
    };
    let (failed_id, failed_text) = &failed_rows[0];
    let (answered_id, answered_text) = &answered_rows[0];
    assert_eq!(
        failed_text,
        &rendering(failed, failed_id, true),
        "the failed child queues the failed rendering"
    );
    assert_ne!(
        failed_text,
        &rendering(failed, failed_id, false),
        "not the success-shaped rendering of its own prose"
    );
    assert_eq!(
        answered_text,
        &rendering(answered, answered_id, false),
        "the answered child queues the success rendering"
    );
    assert_ne!(answered_text, &rendering(answered, answered_id, true));
    assert_ne!(
        key_of(failed, failed_id),
        key_of(answered, answered_id),
        "a failure is keyed by its incarnation, an answer by its text"
    );
}
