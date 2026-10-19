// Followers must not replay cluster mutations or register artifact transfers.

use std::path::Path;
use std::sync::Arc;

use odin_huginn::NodePosture;
use tempfile::TempDir;

use crate::kube::{kube_reconcile_tick, KUBE_SURFACE_LANE, KUBE_SURFACE_SESSION};
use crate::pumps::arm_egress_lane_pumps;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::net::{TcpListener, TcpStream};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::Duration as StdDuration;

use odin_domain::huginn::{
    ArtifactDirection, ArtifactKind, KubeJobLabels, KubeStagingProjection, LiveError,
    LiveSessionId, SessionEpoch, SessionManifest, TransferManifest, TransferManifestInit,
};
use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, SliceId, TaskId};
use odin_kube::{JobAction, JobLaunch, JobReconciler, KubeClient, KubeConfig};
use odin_ledger::Ledger;
use odin_omp::live::lane_artifacts::{FsLaneArtifactPort, LaneTransferBridge};
use odin_omp::live::ledger::fs::FsLiveLedger;
use odin_omp::live::ledger::{BlobKind, BlobSource, LiveLedger, SessionBlob};
use odin_omp::live::service::OmpLiveService;
use odin_omp::live::supervisor::{LiveSessionLauncher, LiveSupervisor, SessionRuntime};
use odin_omp::live::transfer::{
    RegistryTransferLaneResolver, SeatTransferLanes, TransferLaneResolver, TransferManager,
};
use odin_types::{OperationId, WorkerId};

/// A closed local port confines durable effects to the operation journal.
async fn kube_journal_fixture(
    dir: &Path,
) -> (
    Arc<StdMutex<Ledger>>,
    Arc<odin_huginn::kube::KubeControl>,
    Arc<odin_huginn::read_model::MaterializedReadModel>,
    JobAction,
) {
    kube_control_on(dir, "http://127.0.0.1:9", StdDuration::from_secs(2)).await
}

async fn kube_control_on(
    dir: &Path,
    cluster_url: &str,
    request_timeout: StdDuration,
) -> (
    Arc<StdMutex<Ledger>>,
    Arc<odin_huginn::kube::KubeControl>,
    Arc<odin_huginn::read_model::MaterializedReadModel>,
    JobAction,
) {
    let config = KubeConfig {
        kubeconfig: dir.join("kubeconfig"),
        cluster: "laptop".to_owned(),
        namespace: "default".to_owned(),
        allowed_nodes: BTreeSet::from(["laptop".to_owned()]),
        request_timeout,
        teardown_timeout: StdDuration::from_secs(2),
    };
    let client = KubeClient {
        client: kube::Client::try_from(kube::Config::new(
            cluster_url.parse().expect("cluster uri"),
        ))
        .expect("lazy kube client"),
        config,
    };
    let store = Arc::new(StdMutex::new(
        Ledger::open(dir.join("kube-journal.sqlite3")).expect("disposable ledger"),
    ));
    let channel =
        odin_kernel::recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel");
    let stops = Arc::new(odin_kernel::StopAuthority::new(Arc::clone(&store), channel));
    let artifact_root = dir.join("artifacts");
    std::fs::create_dir_all(&artifact_root).expect("artifact root");
    let reconciler = JobReconciler::new(
        client.clone(),
        Arc::clone(&store),
        stops,
        Arc::default(),
        artifact_root,
    )
    .expect("reconciler");
    let session = LiveSessionId::parse(KUBE_SURFACE_SESSION).expect("surface session");
    let lane = LaneId::new(KUBE_SURFACE_LANE).expect("surface lane");
    let catalog = odin_huginn::kube::KubeCatalog::new(
        odin_huginn::kube::SurfaceArtifacts::new(
            session,
            lane,
            NonZeroU64::new(65_536).expect("nonzero"),
            NonZeroU64::new(1_048_576).expect("nonzero"),
        ),
        NonZeroUsize::new(256).expect("nonzero"),
        NonZeroU64::new(16_384).expect("nonzero"),
        NonZeroU64::new(128).expect("nonzero"),
    );
    let control = Arc::new(odin_huginn::kube::KubeControl::new(
        catalog,
        Arc::new(reconciler),
        Arc::clone(&store),
        client,
    ));
    let read_model = Arc::new(odin_huginn::read_model::MaterializedReadModel::with_limits(
        65_536,
        131_072,
        time::OffsetDateTime::now_utc(),
    ));
    let action = JobAction {
        run_id: RunId::new("run:follower-journal-regression").expect("run id"),
        kind: odin_domain::huginn::KubeOperationKind::Create,
        expected_resource_version: odin_domain::huginn::KubeResourceVersion::new("1042")
            .expect("resource version"),
        operation_id: OperationId::new("op-follower-journal-regression").expect("operation"),
        idempotency_digest: Digest::hash(b"follower-journal-regression"),
        target_node: None,
    };
    (store, control, read_model, action)
}

fn seed_pending_admitted_create(
    store: &StdMutex<Ledger>,
    action: &JobAction,
    cluster: &str,
    namespace: &str,
) {
    // Recovery expects serialized `JobLaunch`, not the `JobAction` command.
    let launch = JobLaunch {
        labels: KubeJobLabels {
            task_id: TaskId::new("run-follower-journal-task").expect("task id"),
            run_id: action.run_id.clone(),
            attempt_id: AttemptId::new("run-follower-journal-attempt").expect("attempt id"),
            seat_id: SeatId::new("colin").expect("seat id"),
            project_id: ProjectId::new("odin").expect("project id"),
            lane_id: LaneId::new(KUBE_SURFACE_LANE).expect("lane id"),
            model: "follower-journal-model".to_owned(),
            budget_policy_digest: Digest::hash(b"follower-journal-budget-policy"),
            container_identity: Digest::hash(b"follower-journal-image"),
        },
        worker_id: WorkerId::new("worker-follower-journal").expect("worker id"),
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        image: "registry.example/follower-journal:v1".to_owned(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["echo follower-journal-launch".to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: None,
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: action.operation_id.clone(),
        idempotency_digest: action.idempotency_digest,
    };
    let mut value = serde_json::to_value(&launch).expect("launch json");
    {
        let object = value.as_object_mut().expect("json object");
        object.remove("operation_id");
        object.remove("idempotency_digest");
        object.remove("worker_id");
    }
    let fingerprint =
        Digest::hash(&serde_json::to_vec(&value).expect("fingerprint bytes")).to_string();
    let now = odin_ledger::encode_utc(time::OffsetDateTime::now_utc()).expect("ledger timestamp");
    store
        .lock()
        .expect("ledger lock")
        .with_tx(|tx| {
            tx.execute(
                "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
                     idempotency_digest,fingerprint,request_json,state,created_at,updated_at) \
                     VALUES(?1,?2,?3,?4,'create',?5,?6,?7,'pending',?8,?8)",
                rusqlite::params![
                    action.operation_id.as_str(),
                    action.run_id.as_str(),
                    cluster,
                    namespace,
                    action.idempotency_digest.to_string(),
                    fingerprint,
                    serde_json::to_string(&launch).expect("request json"),
                    now,
                ],
            )?;
            Ok(())
        })
        .expect("seed pending admitted create");
}

fn journal_row_state(store: &StdMutex<Ledger>, operation: &str) -> String {
    store
        .lock()
        .expect("ledger lock")
        .with_tx(|tx| {
            Ok(tx.query_row(
                "SELECT state FROM kube_job_operations WHERE operation_id=?1",
                [operation],
                |row| row.get::<_, String>(0),
            )?)
        })
        .expect("journal row")
}

fn journal_attempt_count(store: &StdMutex<Ledger>) -> i64 {
    store
        .lock()
        .expect("ledger lock")
        .with_tx(|tx| {
            Ok(
                tx.query_row("SELECT COUNT(*) FROM kube_job_attempts", [], |row| {
                    row.get::<_, i64>(0)
                })?,
            )
        })
        .expect("attempt count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follower_kube_tick_never_redrives_pending_admitted_journal() {
    let dir = TempDir::new().expect("fixture dir");
    let (store, control, _read_model, action) = kube_journal_fixture(dir.path()).await;
    seed_pending_admitted_create(&store, &action, "laptop", "default");

    kube_reconcile_tick(
        NodePosture::Follower,
        &control,
        &mut crate::pumps::WatchLog::default(),
    )
    .await;

    assert_eq!(
        journal_row_state(&store, action.operation_id.as_str()),
        "pending",
        "a follower tick must leave the admitted journal row untouched"
    );
    assert_eq!(
        journal_attempt_count(&store),
        0,
        "a demoted node must not re-drive admitted cluster mutations"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authoritative_kube_tick_redrives_pending_admitted_journal() {
    let dir = TempDir::new().expect("fixture dir");
    let (store, control, _read_model, action) = kube_journal_fixture(dir.path()).await;
    seed_pending_admitted_create(&store, &action, "laptop", "default");

    kube_reconcile_tick(
        NodePosture::Authoritative,
        &control,
        &mut crate::pumps::WatchLog::default(),
    )
    .await;

    assert!(
        journal_attempt_count(&store) >= 1,
        "the authoritative tick re-drives the pending admitted create (positive control)"
    );
}

struct RecordingApi {
    port: u16,
    paths: Arc<StdMutex<Vec<String>>>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RecordingApi {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback api");
        let port = listener.local_addr().expect("bound port").port();
        let paths = Arc::new(StdMutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_paths = Arc::clone(&paths);
        let thread_stopped = Arc::clone(&stopped);
        let thread = std::thread::Builder::new()
            .name("kube-api-stand-in".to_owned())
            .spawn(move || {
                for stream in listener.incoming() {
                    if thread_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(stream) = stream else { break };
                    record_request(&thread_paths, stream);
                }
            })
            .expect("api thread");
        Self {
            port,
            paths,
            stopped,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn take_paths(&self) -> Vec<String> {
        std::mem::take(&mut self.paths.lock().expect("paths"))
    }
}

impl Drop for RecordingApi {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            thread.join().expect("api thread exits");
        }
    }
}

fn record_request(paths: &StdMutex<Vec<String>>, mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(StdDuration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(StdDuration::from_millis(500)));
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = std::io::BufReader::new(cloned);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 && !line.trim().is_empty() {
        line.clear();
    }
    if let Some(target) = request_line.split_whitespace().nth(1) {
        paths.lock().expect("paths").push(target.to_owned());
    }
    let _ = stream.write_all(
        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reconcile_pass_lists_nothing() {
    let api = RecordingApi::bind();
    let dir = TempDir::new().expect("fixture dir");
    let (_store, control, _read_model, _action) =
        kube_control_on(dir.path(), &api.url(), StdDuration::from_millis(200)).await;
    kube_reconcile_tick(
        NodePosture::Follower,
        &control,
        &mut crate::pumps::WatchLog::default(),
    )
    .await;
    let reconcile = api.take_paths();
    assert!(
        reconcile.is_empty(),
        "the reconcile pass lists nothing: {reconcile:?}"
    );
}

struct EgressLauncherStub;

#[async_trait::async_trait]
impl LiveSessionLauncher for EgressLauncherStub {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _manifest: &SessionManifest,
        _epoch: odin_domain::huginn::SessionEpoch,
        _reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Err(LiveError::Unsupported {
            operation: "egress regression stub".to_owned(),
        })
    }
}

struct EgressFixture {
    service: Arc<OmpLiveService>,
    bridge: Arc<LaneTransferBridge>,
    lane: LaneId,
    artifact: odin_omp::live::lane_artifacts::LaneArtifact,
    sinmara_root: std::path::PathBuf,
    artifacts_dir: std::path::PathBuf,
}

/// A real live-transfer composition over disposable storage: durable
/// ledger (session + blob), seat lane registry, filesystem Sinmara lane
/// port, durable transfer manager, and the real OMP live service.
async fn egress_fixture(dir: &Path) -> EgressFixture {
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(FsLiveLedger::open(dir.join("live-ledger")).expect("live ledger"));
    let session_id = LiveSessionId::parse("00000000-0000-4000-8000-00000000e6a5").expect("session");
    let seat = SeatId::new("seat:egress-fixture").expect("seat");
    ledger
        .create_session(SessionManifest {
            session_id,
            seat_id: seat.clone(),
            slice_id: SliceId::new("slice:egress-fixture").expect("slice"),
            project_id: ProjectId::new("project:egress-fixture").expect("project"),
            provider: odin_domain::huginn::ProviderName::new("fixture").expect("provider"),
            model: odin_domain::huginn::ModelName::new("fixture-model").expect("model"),
            title: None,
            target_node: odin_domain::NodeId::new("laptop").expect("node"),
            open_tab: false,
            workload: None,
            served_revision: None,
            harness: None,
        })
        .await
        .expect("fixture session");
    let blob = ledger
        .store_blob(BlobSource::Bytes(SessionBlob {
            session_id,
            epoch: SessionEpoch::new(1),
            kind: BlobKind::Transfer,
            bytes: b"hello".to_vec(),
        }))
        .await
        .expect("fixture blob");
    let manifest = TransferManifest::new(TransferManifestInit {
        transfer_id: odin_domain::huginn::TransferId::parse("00000000-0000-4000-8000-00000000b105")
            .expect("transfer id"),
        session_id,
        kind: ArtifactKind::File,
        direction: ArtifactDirection::SessionToDevice,
        display_name: "fixture.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        byte_len: 5,
        chunk_len: NonZeroU32::new(5).expect("nonzero"),
        content_digest: blob.digest,
    })
    .expect("manifest");
    let lane = LaneId::new("egress-fixture-lane").expect("lane");
    let mut seats = BTreeMap::new();
    seats.insert(
        seat,
        SeatTransferLanes {
            file_ingress: LaneId::new("egress-fixture-ingress").expect("lane"),
            file_egress: lane.clone(),
            render_ingress: LaneId::new("egress-fixture-render-ingress").expect("lane"),
            render_egress: LaneId::new("egress-fixture-render-egress").expect("lane"),
        },
    );
    let resolver =
        Arc::new(RegistryTransferLaneResolver::new(Arc::clone(&ledger), seats).expect("resolver"));
    let sinmara_root = dir.join("sinmara");
    let port = Arc::new(FsLaneArtifactPort::open(&sinmara_root).expect("port"));
    let bridge = Arc::new(LaneTransferBridge::new(port));
    let transfers_root = dir.join("live-transfers");
    let transfers = Arc::new(
        TransferManager::open(
            &transfers_root,
            Arc::clone(&ledger),
            resolver,
            Arc::clone(&bridge),
        )
        .expect("transfers"),
    );
    let supervisor =
        LiveSupervisor::new(Arc::clone(&ledger), Arc::new(EgressLauncherStub), 256, None);
    let service = Arc::new(OmpLiveService::new(ledger, supervisor, transfers));
    let artifact = odin_omp::live::lane_artifacts::LaneArtifact {
        lane_id: lane.clone(),
        manifest,
        blob,
    };
    let artifacts_dir = transfers_root.join("artifacts");
    EgressFixture {
        service,
        bridge,
        lane,
        artifact,
        sinmara_root,
        artifacts_dir,
    }
}

/// Match the producer's atomic rename so readers never observe a partial artifact.
fn publish_lane_artifact(fixture: &EgressFixture) {
    let directory = fixture
        .sinmara_root
        .join(fixture.lane.as_str())
        .join("egress");
    std::fs::create_dir_all(&directory).expect("egress lane dir");
    let path = directory.join(format!("{}.cbor", fixture.artifact.manifest.transfer_id));
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        odin_omp::live::ledger::encode_cbor(&fixture.artifact).expect("cbor"),
    )
    .expect("stage egress artifact");
    std::fs::rename(&temporary, &path).expect("publish egress artifact");
}

fn durable_artifact_count(fixture: &EgressFixture) -> usize {
    std::fs::read_dir(&fixture.artifacts_dir)
        .expect("artifacts dir")
        .count()
}

#[tokio::test]
async fn follower_arms_no_egress_lane_pumps_and_registers_nothing() {
    let dir = TempDir::new().expect("fixture dir");
    let fixture = egress_fixture(dir.path()).await;
    let mut pumps: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    let mut lanes = std::collections::BTreeSet::new();
    lanes.insert(fixture.lane.clone());

    arm_egress_lane_pumps(
        &mut pumps,
        &fixture.bridge,
        &fixture.service,
        lanes,
        NodePosture::Follower,
    )
    .await
    .expect("arming decision");

    assert!(pumps.is_empty(), "a follower must arm no egress lane pump");
    publish_lane_artifact(&fixture);
    tokio::time::sleep(StdDuration::from_millis(250)).await;
    assert_eq!(
        durable_artifact_count(&fixture),
        0,
        "a demoted node must never register lane egress (no durable transfer record)"
    );
}

#[tokio::test]
async fn authoritative_egress_lane_pump_registers_published_artifact() {
    let dir = TempDir::new().expect("fixture dir");
    let fixture = egress_fixture(dir.path()).await;
    let mut pumps: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    let mut lanes = std::collections::BTreeSet::new();
    lanes.insert(fixture.lane.clone());

    arm_egress_lane_pumps(
        &mut pumps,
        &fixture.bridge,
        &fixture.service,
        lanes,
        NodePosture::Authoritative,
    )
    .await
    .expect("arming decision");
    assert_eq!(pumps.len(), 1, "the authoritative node arms its lane pump");

    publish_lane_artifact(&fixture);
    for _ in 0..40 {
        if durable_artifact_count(&fixture) > 0 {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    assert_eq!(
        durable_artifact_count(&fixture),
        1,
        "the authoritative egress pump registers the lane artifact durably"
    );
    pumps.abort_all();
}

/// Followers serve no seats; only the authoritative resolver requires a nonempty seat set.
#[tokio::test]
async fn read_only_follower_transfer_lane_registry_composes_empty_and_denies() {
    let dir = TempDir::new().expect("fixture dir");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(FsLiveLedger::open(dir.path().join("live")).expect("live ledger opens"));
    let Err(authority_error) =
        RegistryTransferLaneResolver::new(Arc::clone(&ledger), BTreeMap::new())
    else {
        panic!("an authority lane registry refuses an empty seat set");
    };
    assert!(
        authority_error.to_string().contains("lane_registry_empty"),
        "unexpected authority refusal: {authority_error}"
    );

    let resolver = RegistryTransferLaneResolver::read_only(Arc::clone(&ledger));
    let manifest = TransferManifest::new(TransferManifestInit {
        transfer_id: odin_domain::huginn::TransferId::parse("00000000-0000-4000-8000-00000000b105")
            .expect("transfer id"),
        session_id: LiveSessionId::parse("00000000-0000-4000-8000-00000000f011")
            .expect("session id"),
        kind: ArtifactKind::File,
        direction: ArtifactDirection::SessionToDevice,
        display_name: "fixture.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        byte_len: 5,
        chunk_len: NonZeroU32::new(5).expect("nonzero"),
        content_digest: Digest::hash(b"fixture"),
    })
    .expect("manifest");
    let denial = resolver
        .lane_for(&manifest)
        .await
        .expect_err("a follower resolves no transfer lane");
    assert!(
        matches!(denial, LiveError::NotFound { .. }),
        "unexpected follower lane lookup outcome: {denial}"
    );
}
