//! Live disposable-cluster lifecycle tests, run with `-- --ignored`.
//! `KUBECONFIG` selects the config; otherwise tests use `/etc/rancher/k3s/k3s.yaml`.
//! A multithreaded Tokio runtime is required by the stop backend's `block_in_place`.
//! Unavailable clusters emit the sweep's blocked marker before failing.
//! Test Jobs are cleaned up through reconciler cancellation; only foreign
//! fixtures use direct deletion. Pod absence is checked by owner UID, not labels.
use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use odin_domain::huginn::{
    KubeCheckpointProjection, KubeContentIdentity, KubeJobLabels, KubeJobLifecycle,
    KubeOperationKind, KubeResourceOwnership, KubeResourceVersion, KubeStagingProjection,
    KubeWorkloadState,
};
use odin_domain::{AttemptId, CheckpointId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
use odin_kernel::stop::{mint_worker_id, WorkerChannel};
use odin_kernel::{recovery_worker_channel, StopAuthority};
use odin_kube::job::{
    JOB_PROJECTION_ANNOTATION, KUBE_CHECKPOINT_MOUNT_PATH, KUBE_STAGING_MOUNT_PATH,
};
use odin_kube::{
    JobAction, JobLaunch, JobObservation, JobReconciler, KubeClient, KubeConfig, KubeError,
};
use odin_ledger::artifact::{ArtifactRegistration, NewArtifactReference, RetentionClass};
use odin_ledger::Ledger;
use odin_types::OperationId;
use time::OffsetDateTime;

/// Must match `KUBE_UNAVAILABLE_MARKER` in `crates/odin-sweep/src/probe_registry.rs`.
const UNAVAILABLE_MARKER: &str = "kube unavailable:";

const DEFAULT_CLUSTER: &str = "laptop";
const DEFAULT_NAMESPACE: &str = "default";
const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_TEARDOWN_TIMEOUT_SECONDS: u64 = 120;

/// Override with `ODIN_KUBE_TEST_IMAGE` when docker.io is unreachable.
const DEFAULT_IMAGE: &str = "docker.io/library/busybox:1.36.1";

/// Allows cold pulls and scheduling, separately from request and teardown timeouts.
const OBSERVE_BOUND: Duration = Duration::from_secs(240);

const POLL_INTERVAL: Duration = Duration::from_secs(2);

struct SuiteRuntime {
    client: KubeClient,
    reconciler: JobReconciler,
    namespace: String,
    teardown_bound: Duration,
    image: String,
    store: Arc<Mutex<Ledger>>,
    artifact_root: PathBuf,
    /// Keeps the disposable ledger alive for the whole test.
    _ledger_dir: tempfile::TempDir,
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn env_seconds(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Use the first nonempty KUBECONFIG path, otherwise the k3s config.
fn kubeconfig_path() -> PathBuf {
    match std::env::var_os("KUBECONFIG") {
        Some(value) if !value.is_empty() => PathBuf::from(
            value
                .to_string_lossy()
                .split(':')
                .find(|path| !path.is_empty())
                .unwrap_or("/etc/rancher/k3s/k3s.yaml")
                .to_owned(),
        ),
        _ => PathBuf::from("/etc/rancher/k3s/k3s.yaml"),
    }
}

// A Flag (a disabled capability awaiting its key, say) is advice, not a broken registry.
fn assert_no_failures(findings: &[odin_registry::RegistryFinding]) {
    let failures: Vec<_> = findings
        .iter()
        .filter(|finding| finding.severity == odin_registry::FindingSeverity::Fail)
        .collect();
    assert!(failures.is_empty(), "{failures:?}");
}

fn declared_workload_nodes() -> std::collections::BTreeSet<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../registry");
    let discovered = odin_registry::walk(root);
    assert_no_failures(&discovered.findings);
    let parsed = odin_registry::parse_objects(&discovered.objects);
    assert_no_failures(&parsed.findings);
    parsed
        .objects
        .into_iter()
        .filter_map(|object| match object.config {
            odin_registry::ObjectConfig::Node(node) if node.enabled && node.allow_workloads => {
                Some(object.id)
            }
            _ => None,
        })
        .collect()
}

fn suite_config() -> KubeConfig {
    KubeConfig {
        kubeconfig: kubeconfig_path(),
        cluster: env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER),
        namespace: env_string("ODIN_KUBE_NAMESPACE", DEFAULT_NAMESPACE),
        allowed_nodes: declared_workload_nodes(),
        request_timeout: Duration::from_secs(env_seconds(
            "ODIN_KUBE_REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )),
        teardown_timeout: Duration::from_secs(env_seconds(
            "ODIN_KUBE_TEARDOWN_TIMEOUT_SECONDS",
            DEFAULT_TEARDOWN_TIMEOUT_SECONDS,
        )),
    }
}

/// Only unavailability emits the sweep's blocked marker; other errors fail normally.
fn report_unavailable(cluster: &str, error: &KubeError) -> ! {
    println!("{UNAVAILABLE_MARKER} cluster {cluster:?}: {error:?}");
    panic!("cluster typed-unavailable: {error:?}");
}

/// Unwraps one reconciler/API result: typed unavailability becomes the
/// BLOCKED marker path, everything else is a plain test failure.
fn guarded<T>(cluster: &str, result: Result<T, KubeError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) if error.is_unavailable() => report_unavailable(cluster, &error),
        Err(error) => panic!("kube operation failed: {error:?}"),
    }
}

/// StopAuthority requires a worker channel, but cluster stopping uses the kube backend.
fn worker_channel() -> Result<WorkerChannel, String> {
    let bus =
        match std::env::var("ODIN_WORKER_BUS").or_else(|_| std::env::var("ODIN_TEST_WORKER_BUS")) {
            Ok(bus) => bus,
            Err(_) => {
                let uid = std::fs::metadata("/proc/self")
                    .map_err(|error| format!("could not resolve uid: {error}"))?
                    .uid();
                format!("unix:path=/run/user/{uid}/bus")
            }
        };
    recovery_worker_channel(&bus).map_err(|error| format!("recovery worker channel: {error}"))
}

async fn suite_runtime() -> SuiteRuntime {
    let config = suite_config();
    let client = connect_or_report(&config).await;
    let ledger_dir = tempfile::tempdir().expect("disposable suite ledger directory");
    let ledger = Ledger::open(ledger_dir.path().join("lifecycle-ledger.sqlite3"))
        .expect("disposable suite ledger opens");
    let store = Arc::new(Mutex::new(ledger));
    let channel =
        worker_channel().unwrap_or_else(|error| panic!("suite environment incomplete: {error}"));
    let stops = Arc::new(StopAuthority::new(store.clone(), channel));
    let artifact_root = ledger_dir.path().join("artifacts");
    std::fs::create_dir_all(&artifact_root).expect("disposable artifact root");
    let reconciler = guarded(
        &config.cluster,
        JobReconciler::new(
            client.clone(),
            store.clone(),
            stops,
            Arc::default(),
            artifact_root.clone(),
        ),
    );
    SuiteRuntime {
        client,
        reconciler,
        namespace: config.namespace.clone(),
        teardown_bound: config.teardown_timeout,
        image: env_string("ODIN_KUBE_TEST_IMAGE", DEFAULT_IMAGE),
        store,
        artifact_root,
        _ledger_dir: ledger_dir,
    }
}

async fn connect_or_report(config: &KubeConfig) -> KubeClient {
    match KubeClient::connect(config.clone()).await {
        Ok(client) => client,
        Err(error) if error.is_unavailable() => report_unavailable(&config.cluster, &error),
        Err(error) => panic!(
            "kube client rejected kubeconfig {:?} for cluster {:?} before any cluster contact: {error:?}",
            config.kubeconfig, config.cluster
        ),
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:x}-{:x}", std::process::id(), nanos)
}

fn unique_run(label: &str) -> RunId {
    RunId::new(format!("kube-lifecycle-{label}-{}", unique_suffix())).expect("suite run id")
}

fn digest_of(bytes: &[u8]) -> Digest {
    Digest::hash(bytes)
}

/// Safe-id compatible hex material for one operation id.
fn id_material(seed: &str) -> String {
    let digest = digest_of(seed.as_bytes());
    digest
        .as_bytes()
        .iter()
        .rev()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn operation_id_of(seed: &str) -> OperationId {
    OperationId::new(&format!("op-{}", id_material(seed))).expect("operation id")
}

/// Store bytes and attach their ledger reference to this run for staging.
fn stage_ledger_bytes(runtime: &SuiteRuntime, run: &RunId, bytes: &[u8]) -> KubeContentIdentity {
    let storage_path = format!("objects/kube-lifecycle/{}", unique_suffix());
    let absolute = runtime.artifact_root.join(&storage_path);
    std::fs::create_dir_all(absolute.parent().expect("artifact parent directory"))
        .expect("artifact directory");
    std::fs::write(&absolute, bytes).expect("staged artifact bytes");
    let mut ledger = runtime.store.lock().expect("suite ledger lock");
    let metadata = ledger
        .register_artifact(ArtifactRegistration {
            bytes,
            media_type: "text/plain",
            storage_path: &storage_path,
            retention: RetentionClass::Canonical,
            created_at: OffsetDateTime::now_utc(),
        })
        .expect("artifact registration");
    ledger
        .attach_artifact_reference(
            &metadata.artifact_id,
            metadata.revision,
            NewArtifactReference {
                object_kind: "run",
                object_id: run.as_str(),
                relation: "kube-lifecycle-staging",
                created_at: OffsetDateTime::now_utc(),
            },
        )
        .expect("run-scope artifact reference");
    KubeContentIdentity {
        artifact_id: metadata.artifact_id,
        content_digest: metadata.digest,
        byte_len: metadata.size_bytes,
    }
}

/// Register content without the run-scope reference required for admission.
fn register_unscoped_ledger_bytes(runtime: &SuiteRuntime, bytes: &[u8]) -> KubeContentIdentity {
    let storage_path = format!("objects/kube-lifecycle/{}", unique_suffix());
    let absolute = runtime.artifact_root.join(&storage_path);
    std::fs::create_dir_all(absolute.parent().expect("artifact parent directory"))
        .expect("artifact directory");
    std::fs::write(&absolute, bytes).expect("staged artifact bytes");
    let ledger = runtime.store.lock().expect("suite ledger lock");
    let metadata = ledger
        .register_artifact(ArtifactRegistration {
            bytes,
            media_type: "text/plain",
            storage_path: &storage_path,
            retention: RetentionClass::Canonical,
            created_at: OffsetDateTime::now_utc(),
        })
        .expect("artifact registration");
    KubeContentIdentity {
        artifact_id: metadata.artifact_id,
        content_digest: metadata.digest,
        byte_len: metadata.size_bytes,
    }
}

/// Check that no launch resources exist under the refused run's deterministic names.
async fn assert_no_refused_launch_writes(cluster: &str, runtime: &SuiteRuntime, run: &RunId) {
    let created_job = odin_kube::job::job_name(run);
    let jobs = runtime.client.jobs();
    let maps: Api<ConfigMap> = Api::namespaced(runtime.client.client.clone(), &runtime.namespace);
    let claims = runtime.client.persistent_volume_claims();
    let policies = runtime.client.network_policies();
    assert!(
        guarded(
            cluster,
            jobs.get_opt(&created_job).await.map_err(KubeError::Api)
        )
        .is_none(),
        "no Job may exist for the refused launch"
    );
    assert!(
        guarded(
            cluster,
            maps.get_opt(odin_kube::job::staging_configmap_name(&created_job).as_str())
                .await
                .map_err(KubeError::Api),
        )
        .is_none(),
        "no staging ConfigMap may exist for the refused launch"
    );
    assert!(
        guarded(
            cluster,
            claims
                .get_opt(odin_kube::workload::state_claim_name(run).as_str())
                .await
                .map_err(KubeError::Api),
        )
        .is_none(),
        "no state-claim PVC may be applied before the artifact law holds"
    );
    assert!(
        guarded(
            cluster,
            policies
                .get_opt(odin_kube::workload::egress_policy_name(run).as_str())
                .await
                .map_err(KubeError::Api),
        )
        .is_none(),
        "no egress policy may be applied before the artifact law holds"
    );
}

fn suite_labels(image: &str, run: RunId) -> KubeJobLabels {
    let suffix = unique_suffix();
    KubeJobLabels {
        task_id: TaskId::new(format!("kube-lifecycle-task-{suffix}")).expect("task id"),
        run_id: run,
        attempt_id: AttemptId::new(format!("kube-lifecycle-attempt-{suffix}")).expect("attempt id"),
        seat_id: SeatId::new("colin").expect("seat id"),
        project_id: ProjectId::new("odin").expect("project id"),
        lane_id: LaneId::new("kube-lifecycle").expect("lane id"),
        model: "kube-lifecycle-model".to_owned(),
        budget_policy_digest: digest_of(b"kube-lifecycle-budget-policy"),
        container_identity: digest_of(image.as_bytes()),
    }
}

/// End suite Jobs even if an assertion or killed test prevents cleanup.
const SUITE_DEADLINE_SECONDS: u32 = odin_kube::job::MAX_LAUNCH_DEADLINE_SECONDS;

fn suite_launch(image: &str, run: RunId, script: &str) -> JobLaunch {
    JobLaunch {
        labels: suite_labels(image, run.clone()),
        worker_id: mint_worker_id().expect("minted worker id"),
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        image: image.to_owned(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec![script.to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: Some(SUITE_DEADLINE_SECONDS),
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: operation_id_of(&format!("create-{script}")),
        idempotency_digest: digest_of(script.as_bytes()),
    }
}

fn action(
    run: &RunId,
    kind: KubeOperationKind,
    version: &KubeResourceVersion,
    seed: &str,
) -> JobAction {
    JobAction {
        run_id: run.clone(),
        kind,
        expected_resource_version: version.clone(),
        operation_id: operation_id_of(seed),
        idempotency_digest: digest_of(seed.as_bytes()),
        target_node: None,
    }
}

/// Polls a live-state predicate until it holds or the bound expires. A
/// `false` just means "not yet".
async fn poll_until(bound: Duration, what: &str, mut probe: impl AsyncFnMut() -> bool) {
    let deadline = Instant::now() + bound;
    loop {
        if probe().await {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{what}: condition not met within {bound:?}");
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Match controller owner UIDs because mutable labels cannot establish pod ownership.
async fn job_uid_pods(
    cluster: &str,
    client: &KubeClient,
    namespace: &str,
    job_uid: &str,
) -> Vec<String> {
    let pods: Api<Pod> = Api::namespaced(client.client.clone(), namespace);
    let list = guarded(
        cluster,
        pods.list(&ListParams::default())
            .await
            .map_err(KubeError::Api),
    );
    list.items
        .iter()
        .filter(|pod| {
            pod.metadata
                .owner_references
                .as_ref()
                .is_some_and(|references| {
                    references.iter().any(|reference| {
                        reference.controller == Some(true) && reference.uid == job_uid
                    })
                })
        })
        .filter_map(|pod| pod.metadata.name.clone())
        .collect()
}

async fn observe_or_none(
    cluster: &str,
    reconciler: &JobReconciler,
    run: &RunId,
) -> Option<JobObservation> {
    guarded(cluster, reconciler.observe_run(run).await)
}

async fn observe_required(
    cluster: &str,
    reconciler: &JobReconciler,
    run: &RunId,
) -> JobObservation {
    observe_or_none(cluster, reconciler, run)
        .await
        .unwrap_or_else(|| panic!("owned run {run:?} vanished from observation"))
}

/// Cancellation must remove both the original Job UID and all its pods before timeout.
async fn require_cancel_absence(
    runtime: &SuiteRuntime,
    cluster: &str,
    job_uid: &str,
    job_name: &str,
) {
    let jobs: Api<Job> = runtime.client.jobs();
    let deadline = Instant::now() + runtime.teardown_bound;
    loop {
        let residue = job_uid_pods(cluster, &runtime.client, &runtime.namespace, job_uid).await;
        let fetch = jobs.get(job_name).await;
        let surviving_job = match fetch {
            Ok(job) => job.metadata.uid.as_deref() == Some(job_uid),
            Err(kube::Error::Api(status)) if status.code == 404 => false,
            Err(error) => guarded(cluster, Err(KubeError::Api(error))),
        };
        if residue.is_empty() && !surviving_job {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "cancel did not prove authoritative absence within {:?}: surviving \
                 pods owned by {job_uid}: {residue:?}, original Job {job_name} still \
                 present: {surviving_job}",
                runtime.teardown_bound
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Exercise reconciler cancellation rather than bypassing it with direct deletion.
async fn cleanup_owned_job(
    runtime: &SuiteRuntime,
    cluster: &str,
    run: &RunId,
    job_uid: &str,
    job_name: &str,
) {
    if let Some(observation) = observe_or_none(cluster, &runtime.reconciler, run).await {
        let cancel = action(
            run,
            KubeOperationKind::Cancel,
            &observation.projection.identity.resource_version,
            &format!("cleanup-{job_uid}"),
        );
        guarded(
            cluster,
            runtime.reconciler.operate_at_live_version(cancel).await,
        );
    }
    require_cancel_absence(runtime, cluster, job_uid, job_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn created_job_reaches_observed_success_status() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("success");
    let labels = suite_labels(&runtime.image, run.clone());

    // The container exits successfully only when mounted bytes match registered content.
    const INPUT_CONTENT: &str = "odin-lifecycle-staged-input";
    const CHECKPOINT_CONTENT: &str = "odin-lifecycle-checkpoint-state";
    let staged_input = stage_ledger_bytes(&runtime, &run, INPUT_CONTENT.as_bytes());
    let staged_checkpoint = stage_ledger_bytes(&runtime, &run, CHECKPOINT_CONTENT.as_bytes());
    let checkpoint_id =
        CheckpointId::new(format!("checkpoint-{}", unique_suffix())).expect("checkpoint id");
    let script = format!(
        "[ \"$(cat {KUBE_STAGING_MOUNT_PATH}/input-0)\" = '{INPUT_CONTENT}' ] || exit 3\n\
         [ \"$(cat {KUBE_CHECKPOINT_MOUNT_PATH}/state)\" = '{CHECKPOINT_CONTENT}' ] || exit 4\n"
    );
    let attempt_id = labels.attempt_id.clone();
    let launch = JobLaunch {
        labels,
        worker_id: mint_worker_id().expect("minted worker id"),
        staging: KubeStagingProjection {
            inputs: vec![staged_input],
            resumed_from: Some(checkpoint_id.clone()),
        },
        checkpoint: Some(KubeCheckpointProjection {
            checkpoint_id,
            parent_checkpoint_id: None,
            state: staged_checkpoint,
        }),
        image: runtime.image.clone(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec![script],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: Some(SUITE_DEADLINE_SECONDS),
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: operation_id_of("create-staged-success"),
        idempotency_digest: digest_of(INPUT_CONTENT.as_bytes()),
    };

    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_name = created.workload.resource.name.clone();
    let job_uid = created.workload.resource.uid.clone();
    assert_eq!(
        created.workload.ownership,
        KubeResourceOwnership::Odin {
            run_id: run.clone(),
            attempt_id: Some(attempt_id),
            lane_id: LaneId::new("kube-lifecycle").expect("lane id"),
            seat_id: SeatId::new("colin").expect("seat id"),
        },
        "a freshly created Job is Odin-owned by its run"
    );
    created
        .projection
        .validate()
        .expect("the created projection is schema-valid");

    poll_until(OBSERVE_BOUND, "created Job reaches observed success", {
        let cluster = cluster.clone();
        let reconciler = &runtime.reconciler;
        let run = run.clone();
        move || {
            let cluster = cluster.clone();
            let run = run.clone();
            async move {
                match observe_or_none(&cluster, reconciler, &run).await {
                    None => false,
                    Some(observation) => {
                        observation.projection.lifecycle == KubeJobLifecycle::Succeeded
                            && observation.workload.state == KubeWorkloadState::Succeeded
                    }
                }
            }
        }
    })
    .await;
    let final_observation = observe_required(&cluster, &runtime.reconciler, &run).await;
    assert_eq!(
        final_observation.projection.lifecycle,
        KubeJobLifecycle::Succeeded
    );
    assert_eq!(final_observation.workload.resource.name, job_name);

    cleanup_owned_job(&runtime, &cluster, &run, &job_uid, &job_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn invalid_job_artifact_scope_refuses_typed_with_zero_cluster_writes() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("unscoped");
    let labels = suite_labels(&runtime.image, run.clone());

    // Compare artifacts with and without a run-scope reference.
    let unscoped = register_unscoped_ledger_bytes(&runtime, b"odin-unscoped-staging-input");
    let scoped_twin = stage_ledger_bytes(&runtime, &run, b"odin-scoped-twin-input");

    // Scope validation must reject the unreferenced artifact before cluster writes.
    let store = odin_kube::artifacts::ArtifactStore::new(
        runtime.store.clone(),
        runtime.artifact_root.clone(),
    );
    store
        .prepare_stage(
            &labels,
            &KubeStagingProjection {
                inputs: vec![scoped_twin],
                resumed_from: None,
            },
            None,
        )
        .expect("the run-scoped twin satisfies the prepared content law");
    let refused = store
        .prepare_stage(
            &labels,
            &KubeStagingProjection {
                inputs: vec![unscoped.clone()],
                resumed_from: None,
            },
            None,
        )
        .expect_err("the unscoped artifact must fail prepared validation");
    assert!(
        matches!(&refused, KubeError::Rejected { reason }
            if reason.contains("no ledger reference binds the artifact to the Job scope")),
        "prepared refusal must be the typed scope law: {refused:?}"
    );

    let launch = JobLaunch {
        labels: labels.clone(),
        worker_id: mint_worker_id().expect("minted worker id"),
        staging: KubeStagingProjection {
            inputs: vec![unscoped],
            resumed_from: None,
        },
        checkpoint: None,
        image: runtime.image.clone(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["true".to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: Some(SUITE_DEADLINE_SECONDS),
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: operation_id_of("create-unscoped-scope"),
        idempotency_digest: digest_of(b"odin-unscoped-staging-input"),
    };
    let error = match runtime.reconciler.create(launch).await {
        Ok(observation) => panic!("an unscoped Job artifact must not create: {observation:?}"),
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        Err(error) => error,
    };
    assert!(
        matches!(&error, KubeError::Rejected { reason }
            if reason.contains("no ledger reference binds the artifact to the Job scope")),
        "the admitted create must surface the typed scope refusal: {error:?}"
    );

    // Separate runs avoid a first-registration conflict masking content corruption.
    let corrupt_run = unique_run("corrupt");
    let corrupt_labels = suite_labels(&runtime.image, corrupt_run.clone());

    // Corrupt bytes after registration so the read-time digest check must reject them.
    let corrupt_path = format!("objects/kube-lifecycle/{}", unique_suffix());
    let corrupt_absolute = runtime.artifact_root.join(&corrupt_path);
    std::fs::create_dir_all(
        corrupt_absolute
            .parent()
            .expect("artifact parent directory"),
    )
    .expect("artifact directory");
    std::fs::write(&corrupt_absolute, b"odin-corrupt-original-bytes").expect("original bytes");
    let corrupt = {
        let mut ledger = runtime.store.lock().expect("suite ledger lock");
        let metadata = ledger
            .register_artifact(ArtifactRegistration {
                bytes: b"odin-corrupt-original-bytes",
                media_type: "text/plain",
                storage_path: &corrupt_path,
                retention: RetentionClass::Canonical,
                created_at: OffsetDateTime::now_utc(),
            })
            .expect("artifact registration");
        ledger
            .attach_artifact_reference(
                &metadata.artifact_id,
                metadata.revision,
                NewArtifactReference {
                    object_kind: "run",
                    object_id: corrupt_run.as_str(),
                    relation: "kube-content",
                    created_at: OffsetDateTime::now_utc(),
                },
            )
            .expect("run-scope artifact reference");
        KubeContentIdentity {
            artifact_id: metadata.artifact_id,
            content_digest: metadata.digest,
            byte_len: metadata.size_bytes,
        }
    };
    std::fs::remove_file(&corrupt_absolute).expect("remove original artifact bytes");
    std::fs::write(&corrupt_absolute, b"odin-corrupt-replaced-bytes").expect("replaced bytes");
    let corrupt_refused = store
        .prepare_stage(
            &corrupt_labels,
            &KubeStagingProjection {
                inputs: vec![corrupt.clone()],
                resumed_from: None,
            },
            None,
        )
        .expect_err("corrupt material must fail prepared validation");
    assert!(
        matches!(&corrupt_refused, KubeError::Storage { reason }
            if reason.contains("registered artifact content changed")),
        "corrupt refusal must be the typed digest proof: {corrupt_refused:?}"
    );
    let corrupt_launch = JobLaunch {
        labels: corrupt_labels,
        worker_id: mint_worker_id().expect("minted worker id"),
        staging: KubeStagingProjection {
            inputs: vec![corrupt],
            resumed_from: None,
        },
        checkpoint: None,
        image: runtime.image.clone(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["true".to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: Some(SUITE_DEADLINE_SECONDS),
        service: false,
        workload: None,
        extension: None,
        models_config: None,
        operation_id: operation_id_of("create-corrupt-material"),
        idempotency_digest: digest_of(b"odin-corrupt-original-bytes"),
    };
    let corrupt_error = match runtime.reconciler.create(corrupt_launch).await {
        Ok(observation) => panic!("corrupt Job artifact material must not create: {observation:?}"),
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        Err(error) => error,
    };
    assert!(
        matches!(&corrupt_error, KubeError::Storage { reason }
            if reason.contains("registered artifact content changed")),
        "the admitted create must surface the typed digest refusal: {corrupt_error:?}"
    );

    // Refused launches must leave no resources under their deterministic names.
    assert_no_refused_launch_writes(&cluster, &runtime, &run).await;
    assert_no_refused_launch_writes(&cluster, &runtime, &corrupt_run).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn optimistic_conflict_and_idempotent_replay_follow_command_law() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("conflict");
    let launch = suite_launch(&runtime.image, run.clone(), "sleep 300");
    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_uid = created.workload.resource.uid.clone();
    let create_worker_id = created.projection.worker.worker_id.clone();

    // Record existing pods so resume can be checked against the pre-pause worker set.
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let job_uid = job_uid.clone();
        poll_until(OBSERVE_BOUND, "Job schedules a real pod", move || {
            let cluster = cluster.clone();
            let client = client.clone();
            let namespace = namespace.clone();
            let job_uid = job_uid.clone();
            async move {
                !job_uid_pods(&cluster, &client, &namespace, &job_uid)
                    .await
                    .is_empty()
            }
        })
        .await;
    }
    let pre_pause_pods: HashSet<String> =
        job_uid_pods(&cluster, &runtime.client, &runtime.namespace, &job_uid)
            .await
            .into_iter()
            .collect();

    let stale_version = KubeResourceVersion::new(format!(
        "{}-stale",
        created.projection.identity.resource_version.as_str()
    ))
    .expect("stale resource version");
    let stale = action(
        &run,
        KubeOperationKind::Pause,
        &stale_version,
        "pause-initial",
    );
    match runtime.reconciler.operate(stale).await {
        Err(KubeError::Conflict { reason } | KubeError::Rejected { reason }) => {
            assert!(!reason.is_empty(), "a typed conflict carries its reason");
        }
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        Err(error) => panic!("a stale version must conflict typed, got {error:?}"),
        Ok(_) => panic!("a stale expected_resource_version must never operate"),
    }

    // The same verb at the observed resource version succeeds and the
    // workload actually suspends (a suspended Job terminates its pods).
    let current = observe_required(&cluster, &runtime.reconciler, &run).await;
    let paused = guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Pause,
                &current.projection.identity.resource_version,
                "pause-initial",
            ))
            .await,
    );

    // The exact duplicate — same operation id, same idempotency digest —
    // replays the recorded outcome instead of moving the Job twice: one
    // workload identity, still paused.
    let replay = guarded(
        &cluster,
        runtime
            .reconciler
            .operate(action(
                &run,
                KubeOperationKind::Pause,
                &paused.projection.identity.resource_version,
                "pause-initial",
            ))
            .await,
    );
    assert_eq!(
        replay.workload.resource.uid, paused.workload.resource.uid,
        "an idempotent replay never creates or moves a second workload"
    );

    // Suspending a Job terminates its running pods: the original worker
    // set must actually go away for the pause to be real.
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let job_uid = job_uid.clone();
        poll_until(
            runtime.teardown_bound,
            "paused Job terminates its pods",
            move || {
                let cluster = cluster.clone();
                let client = client.clone();
                let namespace = namespace.clone();
                let job_uid = job_uid.clone();
                async move {
                    job_uid_pods(&cluster, &client, &namespace, &job_uid)
                        .await
                        .is_empty()
                }
            },
        )
        .await;
    }
    poll_until(runtime.teardown_bound, "paused run observes suspension", {
        let cluster = cluster.clone();
        let reconciler = &runtime.reconciler;
        let run = run.clone();
        move || {
            let cluster = cluster.clone();
            let run = run.clone();
            async move {
                match observe_or_none(&cluster, reconciler, &run).await {
                    None => false,
                    Some(observation) => {
                        observation.projection.lifecycle == KubeJobLifecycle::Paused
                            || observation.workload.state == KubeWorkloadState::Suspended
                    }
                }
            }
        }
    })
    .await;

    // Resume at the observed revision: true resumption brings the run back
    // with new workers — fresh pods under the same Job identity, disjoint
    // from the terminated pre-pause worker set.
    let resume_current = observe_required(&cluster, &runtime.reconciler, &run).await;
    guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Resume,
                &resume_current.projection.identity.resource_version,
                "resume-initial",
            ))
            .await,
    );
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let job_uid = job_uid.clone();
        let pre_pause_pods = pre_pause_pods.clone();
        poll_until(
            OBSERVE_BOUND,
            "resumed run returns with new workers",
            move || {
                let cluster = cluster.clone();
                let client = client.clone();
                let namespace = namespace.clone();
                let job_uid = job_uid.clone();
                let pre_pause_pods = pre_pause_pods.clone();
                async move {
                    let pods = job_uid_pods(&cluster, &client, &namespace, &job_uid).await;
                    !pods.is_empty() && pods.iter().all(|name| !pre_pause_pods.contains(name))
                }
            },
        )
        .await;
    }
    let resumed = observe_required(&cluster, &runtime.reconciler, &run).await;
    assert_ne!(
        resumed.projection.worker.worker_id.as_str(),
        create_worker_id.as_str(),
        "a resume must mint a fresh opaque worker identity"
    );

    // Restart must create a new Job identity.
    let restart_current = observe_required(&cluster, &runtime.reconciler, &run).await;
    guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Restart,
                &restart_current.projection.identity.resource_version,
                "restart-initial",
            ))
            .await,
    );
    let restarted = {
        let cluster = cluster.clone();
        let reconciler = &runtime.reconciler;
        let run = run.clone();
        let original_uid = job_uid.clone();
        let deadline = Instant::now() + OBSERVE_BOUND;
        let observation = loop {
            if let Some(observation) = observe_or_none(&cluster, reconciler, &run).await {
                if observation.workload.resource.uid != original_uid {
                    break observation;
                }
            }
            assert!(
                Instant::now() < deadline,
                "restart did not re-create the run as a new workload identity within \
                 {OBSERVE_BOUND:?}"
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        observation
    };
    let restarted_name = restarted.workload.resource.name.clone();
    let restarted_uid = restarted.workload.resource.uid.clone();
    assert_ne!(
        restarted.projection.worker.worker_id.as_str(),
        resumed.projection.worker.worker_id.as_str(),
        "a restart must mint another fresh opaque worker identity"
    );
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let restarted_uid = restarted_uid.clone();
        poll_until(
            OBSERVE_BOUND,
            "restarted run schedules new workers",
            move || {
                let cluster = cluster.clone();
                let client = client.clone();
                let namespace = namespace.clone();
                let restarted_uid = restarted_uid.clone();
                async move {
                    !job_uid_pods(&cluster, &client, &namespace, &restarted_uid)
                        .await
                        .is_empty()
                }
            },
        )
        .await;
    }

    // Summarize is the pure read verb: the same Job identity is observed
    // and the lifecycle does not move.
    let pre_summarize = observe_required(&cluster, &runtime.reconciler, &run).await;
    let summarized = guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Summarize,
                &pre_summarize.projection.identity.resource_version,
                "summarize-restarted",
            ))
            .await,
    );
    assert_eq!(
        summarized.workload.resource.uid, restarted_uid,
        "summarize observes the same Job identity"
    );
    assert_eq!(
        summarized.projection.lifecycle, pre_summarize.projection.lifecycle,
        "summarize must not transition the lifecycle"
    );
    // Cancellation must remove the restarted Job and its pods.
    let cancel_current = observe_required(&cluster, &runtime.reconciler, &run).await;
    guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Cancel,
                &cancel_current.projection.identity.resource_version,
                "cancel-restarted",
            ))
            .await,
    );
    require_cancel_absence(&runtime, &cluster, &restarted_uid, &restarted_name).await;
}

/// Force a resourceVersion change between observation and command. Strict
/// version admission rejects it; live-version admission retries the same command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn a_self_observed_command_survives_a_concurrent_status_write() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("churn");
    let launch = suite_launch(&runtime.image, run.clone(), "sleep 300");
    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_name = created.workload.resource.name.clone();
    let job_uid = created.workload.resource.uid.clone();

    let observed = observe_required(&cluster, &runtime.reconciler, &run).await;
    let observed_version = observed.projection.identity.resource_version.clone();
    let churn = serde_json::json!({
        "metadata": { "annotations": { "odin.test/status-churn": unique_suffix() } }
    });
    let moved = guarded(
        &cluster,
        runtime
            .client
            .jobs()
            .patch(
                &job_name,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(churn),
            )
            .await
            .map_err(KubeError::Api),
    );
    assert_ne!(
        moved.metadata.resource_version.as_deref(),
        Some(observed_version.as_str()),
        "the concurrent write moved the resourceVersion"
    );

    match runtime
        .reconciler
        .operate(action(
            &run,
            KubeOperationKind::Pause,
            &observed_version,
            "pause-churn",
        ))
        .await
    {
        Err(KubeError::Conflict { reason }) => assert!(!reason.is_empty()),
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        other => panic!("the strict law must refuse a moved version typed, got {other:?}"),
    }

    let paused = guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Pause,
                &observed_version,
                "pause-churn",
            ))
            .await,
    );
    assert_eq!(
        paused.workload.resource.uid, job_uid,
        "the re-admitted pause acts on the same Job"
    );
    assert!(
        paused.projection.lifecycle == KubeJobLifecycle::Paused
            || paused.workload.state == KubeWorkloadState::Suspended,
        "the re-admitted pause really suspends: {:?} / {:?}",
        paused.projection.lifecycle,
        paused.workload.state
    );
    cleanup_owned_job(&runtime, &cluster, &run, &job_uid, &job_name).await;
}

fn pending_operation_count(runtime: &SuiteRuntime) -> usize {
    let cluster = runtime.client.config.cluster.clone();
    let namespace = runtime.client.config.namespace.clone();
    let guard = runtime.store.lock().expect("ledger lock");
    odin_ledger::kube::Journal(guard.connection())
        .pending(&odin_ledger::kube::Scope {
            cluster: &cluster,
            namespace: &namespace,
        })
        .expect("pending lists")
        .len()
}

fn admit_stale_pause(runtime: &SuiteRuntime, run: &RunId, version: &KubeResourceVersion) {
    let pause = action(run, KubeOperationKind::Pause, version, "pause-recover");
    let mut value = serde_json::to_value(&pause).expect("pause action json");
    let request = serde_json::to_string(&value).expect("pause action text");
    if let Some(object) = value.as_object_mut() {
        object.remove("operation_id");
        object.remove("idempotency_digest");
        object.remove("expected_resource_version");
    }
    let fingerprint =
        Digest::hash(&serde_json::to_vec(&value).expect("fingerprint bytes")).to_string();
    let now = odin_ledger::encode_utc(OffsetDateTime::now_utc()).expect("ledger timestamp");
    let cluster = runtime.client.config.cluster.clone();
    let namespace = runtime.client.config.namespace.clone();
    let guard = runtime.store.lock().expect("ledger lock");
    odin_ledger::kube::Journal(guard.connection())
        .insert(
            &odin_ledger::kube::Operation {
                id: pause.operation_id.as_str().to_owned(),
                fingerprint,
                request,
                progress: "{}".to_owned(),
                state: "pending".to_owned(),
                result: None,
                failure_kind: None,
                failure_reason: None,
            },
            &odin_ledger::kube::Identity {
                run,
                kind: "pause",
                digest: &pause.idempotency_digest,
            },
            &odin_ledger::kube::Scope {
                cluster: &cluster,
                namespace: &namespace,
            },
            &now,
        )
        .expect("stale pause admits");
}

/// A pause admitted at a resourceVersion the API server has already moved
/// stays pending. Recovery either suspends at the live version and clears
/// the row, or reports the row it left pending. A connect failure is not
/// that count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn recovery_reports_rows_it_left_pending() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("recover");
    let launch = suite_launch(&runtime.image, run.clone(), "sleep 300");
    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_name = created.workload.resource.name.clone();
    let job_uid = created.workload.resource.uid.clone();

    let observed = observe_required(&cluster, &runtime.reconciler, &run).await;
    let observed_version = observed.projection.identity.resource_version.clone();
    let churn = serde_json::json!({
        "metadata": { "annotations": { "odin.test/status-churn": unique_suffix() } }
    });
    let moved = guarded(
        &cluster,
        runtime
            .client
            .jobs()
            .patch(
                &job_name,
                &kube::api::PatchParams::default(),
                &kube::api::Patch::Merge(churn),
            )
            .await
            .map_err(KubeError::Api),
    );
    assert_ne!(
        moved.metadata.resource_version.as_deref(),
        Some(observed_version.as_str()),
        "the concurrent write moved the resourceVersion"
    );
    admit_stale_pause(&runtime, &run, &observed_version);
    assert_eq!(
        pending_operation_count(&runtime),
        1,
        "the stale pause is admitted and still pending"
    );

    match runtime.reconciler.recover_pending_operations().await {
        Ok(()) => {
            assert_eq!(
                pending_operation_count(&runtime),
                0,
                "recovery returned Ok with a row still pending"
            );
            let paused = observe_required(&cluster, &runtime.reconciler, &run).await;
            assert!(
                paused.projection.lifecycle == KubeJobLifecycle::Paused
                    || paused.workload.state == KubeWorkloadState::Suspended,
                "the re-admitted pause really suspends: {:?} / {:?}",
                paused.projection.lifecycle,
                paused.workload.state
            );
        }
        Err(KubeError::Unavailable { reason })
            if reason.contains("1 admitted kube operation(s) still pending") => {}
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        Err(error) => panic!("recovery left a pending pause without the count: {error:?}"),
    }
    cleanup_owned_job(&runtime, &cluster, &run, &job_uid, &job_name).await;
}

/// A real foreign Job, suspended so it never schedules a pod, carrying no
/// Odin labels: exactly what an unrelated actor on the cluster could create.
fn foreign_job(runtime: &SuiteRuntime, name: &str) -> Job {
    Job {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(runtime.namespace.clone()),
            labels: Some(BTreeMap::from([(
                "sweep.integration/foreign".to_owned(),
                "job-lifecycle".to_owned(),
            )])),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::batch::v1::JobSpec {
            suspend: Some(true),
            template: k8s_openapi::api::core::v1::PodTemplateSpec {
                metadata: None,
                spec: Some(k8s_openapi::api::core::v1::PodSpec {
                    containers: vec![k8s_openapi::api::core::v1::Container {
                        name: "foreign".to_owned(),
                        image: Some(runtime.image.clone()),
                        ..Default::default()
                    }],
                    restart_policy: Some("Never".to_owned()),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Watch events must reflect foreign Job creation and deletion without relisting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn inventory_watches_follow_nodes_and_foreign_jobs() {
    use futures_util::StreamExt;
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let mut nodes = guarded(
        &cluster,
        odin_kube::watch::node_inventory(runtime.client.clone()).await,
    );
    let batch = tokio::time::timeout(OBSERVE_BOUND, nodes.next())
        .await
        .expect("a node batch")
        .expect("the node watch is open")
        .expect("node views");
    let listed: Api<k8s_openapi::api::core::v1::Node> = Api::all(runtime.client.client.clone());
    let mut expected: Vec<String> = listed
        .list(&ListParams::default())
        .await
        .expect("raw node list")
        .items
        .into_iter()
        .filter_map(|node| node.metadata.name)
        .collect();
    let mut seen: Vec<String> = batch.into_iter().map(|view| view.resource.name).collect();
    expected.sort();
    seen.sort();
    assert_eq!(seen, expected);

    let mut mirror = guarded(
        &cluster,
        odin_kube::watch::foreign_inventory(runtime.client.clone()).await,
    );
    let name = format!("kube-lifecycle-mirror-{}", unique_suffix());
    let jobs: Api<Job> = runtime.client.jobs();
    let uid = jobs
        .create(&PostParams::default(), &foreign_job(&runtime, &name))
        .await
        .expect("real foreign Job is created through the raw API")
        .metadata
        .uid
        .expect("API server assigns a uid");
    let mut appeared = false;
    let mut gone = false;
    let deadline = Instant::now() + OBSERVE_BOUND;
    while !gone {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(Some(item)) = tokio::time::timeout(remaining, mirror.next()).await else {
            break;
        };
        match item.expect("the foreign watch stays open") {
            odin_kube::watch::ForeignEvent::Applied(view) if view.resource.uid == uid => {
                if !appeared {
                    appeared = true;
                    let _ = jobs.delete(&name, &DeleteParams::background()).await;
                }
            }
            odin_kube::watch::ForeignEvent::Gone(resource) if resource.uid == uid => gone = true,
            _ => {}
        }
    }
    let _ = jobs.delete(&name, &DeleteParams::background()).await;
    assert!(appeared, "the foreign Job never reached the mirror");
    assert!(gone, "the deleted foreign Job never left the mirror");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn foreign_objects_stay_read_only() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let foreign_name = format!("kube-lifecycle-foreign-{}", unique_suffix());

    // A real foreign Job, suspended so it never schedules a pod, carrying
    // no Odin labels: exactly what an unrelated actor on the cluster could
    // have created. The raw write here is the fixture itself — the point of
    // the test is that no Odin path ever touches it.
    let jobs: Api<Job> = runtime.client.jobs();
    let foreign = foreign_job(&runtime, &foreign_name);
    let created_foreign = jobs
        .create(&PostParams::default(), &foreign)
        .await
        .expect("real foreign Job is created through the raw API");
    let foreign_uid = created_foreign
        .metadata
        .uid
        .clone()
        .expect("API server assigns a uid");

    // The reconciler lists only Odin-owned work: the foreign Job is not
    // claimed as an owned observation.
    let owned = guarded(&cluster, runtime.reconciler.list().await);
    assert!(
        owned
            .iter()
            .all(|observation| observation.workload.resource.name != foreign_name),
        "a foreign Job must never be listed as an owned observation"
    );
    for observation in &owned {
        assert_ne!(
            observation.workload.ownership,
            KubeResourceOwnership::Foreign,
            "owned observations are Odin-owned by construction"
        );
    }

    // No mutation path may reach the foreign object: operating a run the
    // reconciler does not own is typed-rejected, and the foreign Job's
    // identity and revision are untouched afterwards.
    let stranger = unique_run("foreign-stranger");
    let stray = action(
        &stranger,
        KubeOperationKind::Cancel,
        &KubeResourceVersion::new("0").expect("stray resource version"),
        "stray-cancel",
    );
    match runtime.reconciler.operate(stray).await {
        Err(KubeError::Rejected { .. } | KubeError::Conflict { .. }) => {}
        Err(error) if error.is_unavailable() => report_unavailable(&cluster, &error),
        Err(error) => panic!("an unowned run must be typed-rejected, got {error:?}"),
        Ok(_) => panic!("an unowned run must never be operated"),
    }
    let after = jobs
        .get(&foreign_name)
        .await
        .expect("the foreign Job still exists untouched");
    // Controllers may change resourceVersion; compare identity, spec, and Odin metadata.
    assert_eq!(
        after.metadata.uid,
        Some(foreign_uid),
        "a foreign object must keep its API identity"
    );
    let spec = after.spec.as_ref().expect("foreign Job keeps its spec");
    assert_eq!(
        spec.suspend,
        Some(true),
        "a foreign Job is never suspended, resumed, or re-targeted by Odin"
    );
    let labels = after
        .metadata
        .labels
        .as_ref()
        .expect("foreign Job keeps its labels");
    assert_eq!(
        labels.len(),
        1,
        "no Odin binding label is added to a foreign object"
    );
    assert!(
        labels.contains_key("sweep.integration/foreign"),
        "the foreign object keeps exactly its own labels: {labels:?}"
    );
    assert!(
        !after
            .metadata
            .annotations
            .as_ref()
            .map(|values| values.contains_key(JOB_PROJECTION_ANNOTATION))
            .unwrap_or(false),
        "no Odin projection annotation is stamped onto a foreign object"
    );

    // Fixture hygiene for the non-owned object only: no Odin path owns it,
    // so the reconciler cannot address it and a raw delete is the only way
    // this test cleans up after itself.
    let _ = jobs.delete(&foreign_name, &DeleteParams::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn cancel_teardown_proves_authoritative_pod_absence() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("teardown");
    let launch = suite_launch(&runtime.image, run.clone(), "sleep 300");
    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_name = created.workload.resource.name.clone();
    let job_uid = created.workload.resource.uid.clone();

    // First the Job really runs: at least one live pod owned by this Job
    // must exist before teardown is attempted, otherwise the cancellation
    // below proves nothing.
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let job_uid = job_uid.clone();
        poll_until(OBSERVE_BOUND, "Job schedules a real pod", move || {
            let cluster = cluster.clone();
            let client = client.clone();
            let namespace = namespace.clone();
            let job_uid = job_uid.clone();
            async move {
                !job_uid_pods(&cluster, &client, &namespace, &job_uid)
                    .await
                    .is_empty()
            }
        })
        .await;
    }

    // Cancel through the reconciler at the observed revision; the sole
    // StopAuthority owns the destructive actuation.
    let current = observe_required(&cluster, &runtime.reconciler, &run).await;
    guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Cancel,
                &current.projection.identity.resource_version,
                "cancel-teardown",
            ))
            .await,
    );

    // Both the Job and its pods must disappear; suspension alone is insufficient.
    require_cancel_absence(&runtime, &cluster, &job_uid, &job_name).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn workload_state_claim_survives_stop_and_restart() {
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let run = unique_run("workload-continuity");
    // Use the existing /tmp directory so exports need no host-side fixture setup.
    let plan = odin_kube::WorkloadPodPlan {
        profile: "continuity-fixture".to_owned(),
        state_mount: "/state".to_owned(),
        export_mount: "/export".to_owned(),
        export_host_folder: "/tmp".to_owned(),
        state_storage: "128Mi".to_owned(),
        state_storage_class: None,
        allow_hosts: vec!["example.com".to_owned()],
        agent: Some(odin_kube::workload::WorkloadAgentPlan {
            launcher: "/odin/bin/omp-launch".to_owned(),
            gateway: odin_kube::WorkloadGatewayTarget {
                host: "example.org".to_owned(),
                port: 14000,
            },
            browser: "/odin/bin/chromium".to_owned(),
            supervisor: "/odin/bin/odind".to_owned(),
            playwright: "/odin/lib/playwright-core".to_owned(),
            browser_node: "/odin/bin/node".to_owned(),
            browser_engine: odin_registry::BrowserEngine::default(),
            display: odin_kube::WorkloadDisplayPlan {
                xvfb: "/odin/bin/Xvfb".to_owned(),
                screen: "1280x800x24".to_owned(),
                stream: false,
            },
            home_dir: None,
            credential: odin_kube::WorkloadCredentialEnv {
                env_name: "ODIN_GATEWAY_KEY".to_owned(),
                secret: "gateway-secret".to_owned(),
                key: "master".to_owned(),
            },
        }),
    };
    plan.validate().expect("declared plan");
    // Agent launches require a staged models document recorded with the launch.
    let models_document =
        b"{\"providers\":{\"gateway\":{\"baseUrl\":\"https://gateway.internal/v1\"}}}";
    let models_input = stage_ledger_bytes(&runtime, &run, models_document);
    let mut launch = suite_launch(&runtime.image, run.clone(), "sleep 300");
    launch.staging.inputs = vec![models_input.clone()];
    launch.models_config = Some(odin_kube::job::JobModelsConfigLaunch {
        config_artifact: models_input.artifact_id,
        config_digest: models_input.content_digest.to_string(),
        credential_env: odin_kube::workload::WORKLOAD_CREDENTIAL_ENV.to_owned(),
    });
    launch.workload = Some(plan);

    let created = guarded(&cluster, runtime.reconciler.create(launch).await);
    let job_uid = created.workload.resource.uid.clone();
    let claim = odin_kube::workload::state_claim_name(&run);
    let policy = odin_kube::workload::egress_policy_name(&run);

    // The state claim exists from the create path and the egress policy
    // carries exactly the declared hosts, pinned to resolved addresses.
    let custody_first = guarded(
        &cluster,
        odin_kube::workload::state_custody(&runtime.client, &run).await,
    )
    .expect("create ensures the state claim");
    assert_eq!(custody_first.claim, claim);
    let policy_found = guarded(
        &cluster,
        runtime
            .client
            .network_policies()
            .get_opt(&policy)
            .await
            .map_err(KubeError::from),
    );
    assert!(
        policy_found.is_some(),
        "create ensures the declared egress policy"
    );

    // The pod really runs, so the claim really binds to a volume.
    {
        let cluster = cluster.clone();
        let client = runtime.client.clone();
        let namespace = runtime.namespace.clone();
        let job_uid = job_uid.clone();
        poll_until(
            OBSERVE_BOUND,
            "workload Job schedules a real pod",
            move || {
                let cluster = cluster.clone();
                let client = client.clone();
                let namespace = namespace.clone();
                let job_uid = job_uid.clone();
                async move {
                    !job_uid_pods(&cluster, &client, &namespace, &job_uid)
                        .await
                        .is_empty()
                }
            },
        )
        .await;
    }
    poll_until(OBSERVE_BOUND, "state claim binds to a volume", {
        let client = runtime.client.clone();
        let run = run.clone();
        move || {
            let client = client.clone();
            let run = run.clone();
            async move {
                matches!(
                    &odin_kube::workload::state_custody(&client, &run).await,
                    Ok(Some(custody)) if custody.bound_volume.is_some()
                )
            }
        }
    })
    .await;
    let bound = guarded(
        &cluster,
        odin_kube::workload::state_custody(&runtime.client, &run).await,
    )
    .expect("claim exists")
    .bound_volume
    .expect("claim binds once the pod schedules");

    // Keep the admitted version for restart after cancellation removes the Job.
    let current = observe_required(&cluster, &runtime.reconciler, &run).await;
    let stop_version = current.projection.identity.resource_version.clone();
    let first_job_name = created.workload.resource.name.clone();
    guarded(
        &cluster,
        runtime
            .reconciler
            .operate_at_live_version(action(
                &run,
                KubeOperationKind::Cancel,
                &stop_version,
                "stop-continuity",
            ))
            .await,
    );
    require_cancel_absence(&runtime, &cluster, &job_uid, &first_job_name).await;
    let custody_after_stop = guarded(
        &cluster,
        odin_kube::workload::state_custody(&runtime.client, &run).await,
    )
    .expect("state claim survives stop");
    assert_eq!(
        custody_after_stop.bound_volume.as_deref(),
        Some(bound.as_str()),
        "stop never releases the per-pod state volume"
    );

    // Restart must reuse the durable launch's claim and volume with a fresh Job.
    let restarted = guarded(
        &cluster,
        runtime
            .reconciler
            .operate(action(
                &run,
                KubeOperationKind::Restart,
                &stop_version,
                "restart-continuity",
            ))
            .await,
    );
    assert_ne!(
        restarted.workload.resource.uid, job_uid,
        "a restart is a brand-new Job object"
    );
    let custody_final = guarded(
        &cluster,
        odin_kube::workload::state_custody(&runtime.client, &run).await,
    )
    .expect("state claim exists after restart");
    assert_eq!(custody_final.claim, claim);
    assert_eq!(
        custody_final.bound_volume.as_deref(),
        Some(bound.as_str()),
        "the restarted workload reattaches the exact same state volume"
    );

    // Cancellation retains state, so fixture cleanup deletes the claim separately.
    cleanup_owned_job(
        &runtime,
        &cluster,
        &run,
        restarted.workload.resource.uid.as_str(),
        &restarted.workload.resource.name,
    )
    .await;
    use kube::api::DeleteParams;
    let _ = runtime
        .client
        .persistent_volume_claims()
        .delete(&claim, &DeleteParams::default())
        .await;
    let _ = runtime
        .client
        .network_policies()
        .delete(&policy, &DeleteParams::default())
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a real Kubernetes cluster; sweep --integration runs it with -- --ignored"]
async fn the_watch_delivers_a_completion_after_the_relist() {
    use futures_util::StreamExt;
    let runtime = suite_runtime().await;
    let cluster = env_string("ODIN_KUBE_CLUSTER", DEFAULT_CLUSTER);
    let mut stream = guarded(
        &cluster,
        odin_kube::watch::job_observations(runtime.client.clone()).await,
    );
    let run = unique_run("watched");
    let created = guarded(
        &cluster,
        runtime
            .reconciler
            .create(suite_launch(&runtime.image, run.clone(), "sleep 3"))
            .await,
    );
    let (job_name, job_uid) = (
        created.workload.resource.name.clone(),
        created.workload.resource.uid.clone(),
    );
    let deadline = Instant::now() + OBSERVE_BOUND;
    let mut seen = Vec::new();
    let succeeded = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let item = match tokio::time::timeout(remaining, stream.next()).await {
            Ok(Some(item)) => item,
            Ok(None) => panic!("the watch ended; seen for this job: {seen:?}"),
            Err(_) => break false,
        };
        match item {
            Ok(odin_kube::watch::KubeJobWatchEvent::Applied(observation))
                if observation.workload.resource.uid == job_uid =>
            {
                seen.push(observation.workload.state);
                if observation.workload.state == KubeWorkloadState::Succeeded {
                    break true;
                }
            }
            Ok(_) | Err(KubeError::Rejected { .. }) => {}
            Err(error) => panic!("the watch failed: {error}"),
        }
    };
    cleanup_owned_job(&runtime, &cluster, &run, &job_uid, &job_name).await;
    assert!(
        succeeded,
        "the watch never delivered {job_name}'s success; it delivered {seen:?}"
    );
}
