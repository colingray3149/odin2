//! The pause, resume, restart and cancel capabilities against a loopback API: the real cell, control,
//! reconciler, journal and stop authority; only the cluster is simulated. Each test asserts the Job the
//! API holds afterwards and the state `kube.workload.summarize` projects.

use std::sync::{Arc, Mutex};

use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, Scope, SeatId, TaskId};
use odin_omp::host_tools::HostInvocation;
use odin_types::OperationId;
use serde_json::{json, Value};

use crate::kube::{CellInputs, WorkloadExtensionIdentity};
use crate::kube_runtime::fake_api::FakeKubeApi;
use crate::kube_runtime::KubeCommandCoordinator;
use crate::KubeRuntimeCell;

const RUN: &str = "run:live:job-verbs";
const SEAT: &str = "kubert";

struct Harness {
    _dir: tempfile::TempDir,
    api: FakeKubeApi,
    coordinator: KubeCommandCoordinator,
    version: String,
    next_operation: u32,
}

fn scope() -> Scope {
    Scope {
        seat: Some(SeatId::new(SEAT).expect("seat id")),
        ..Scope::default()
    }
}

/// A Job running on the fake cluster, launched through the real control.
async fn running_job() -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let api = FakeKubeApi::start().await;
    let ledger = Arc::new(Mutex::new(
        odin_ledger::Ledger::open(dir.path().join("ledger.sqlite3")).expect("ledger"),
    ));
    let channel =
        odin_kernel::recovery_worker_channel("unix:path=/run/user/0/bus").expect("channel");
    let stops = Arc::new(odin_kernel::StopAuthority::new(
        Arc::clone(&ledger),
        channel,
    ));
    let artifact_root = dir.path().join("artifacts");
    std::fs::create_dir_all(&artifact_root).expect("artifact root");
    let snapshot = odin_registry::Snapshot::build(1, Vec::new()).expect("empty snapshot");
    let cell = KubeRuntimeCell::new(CellInputs {
        config: api.config(dir.path()),
        ledger: Arc::clone(&ledger),
        stops: Arc::clone(&stops),
        artifact_root: artifact_root.clone(),
        snapshot: Arc::new(snapshot),
        config_revision: 1,
        launch_binding: None,
        workload_identity: WorkloadExtensionIdentity {
            artifact: odin_domain::ArtifactId::new(Digest::hash(b"job-verbs-identity").to_string())
                .expect("artifact id"),
            deployment: Default::default(),
        },
    });
    cell.parts()
        .await
        .expect("the cell connects to the loopback API");
    let launch = odin_kube::JobLaunch {
        label: None,
        labels: odin_domain::huginn::KubeJobLabels {
            task_id: TaskId::new("task-job-verbs").expect("task id"),
            run_id: RunId::new(RUN).expect("run id"),
            attempt_id: AttemptId::new("attempt-job-verbs").expect("attempt id"),
            seat_id: SeatId::new(SEAT).expect("seat id"),
            project_id: ProjectId::new("odin").expect("project id"),
            lane_id: LaneId::new("kubert-odin").expect("lane id"),
            model: "kubert-mini".to_owned(),
            budget_policy_digest: Digest::hash(b"job-verbs-budget"),
            container_identity: Digest::hash(b"job-verbs-image"),
        },
        worker_id: odin_kernel::stop::mint_worker_id().expect("worker id"),
        budget_lane: None,
        extension: None,
        models_config: None,
        staging: Default::default(),
        checkpoint: None,
        image: "localhost/odin-workload:job-verbs".to_owned(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["sleep 600".to_owned()],
        node_selector: Default::default(),
        initial_target_node: None,
        admitted_node: None,
        campaign_reservation: None,
        gpu_count: 0,
        gpu_min_vram_gib: None,
        gpu_vram_gib: None,
        tolerate: Default::default(),
        deadline_seconds: Some(600),
        service: false,
        workload: None,
        continue_from: None,
        operation_id: OperationId::new("op-000000000000000000000000000000a0").expect("operation"),
        idempotency_digest: Digest::hash(b"job-verbs-create"),
    };
    // The seat-limit admission belongs to the create path; these tests drive the verbs on a Job that exists.
    let created = odin_kube::JobReconciler::new(
        api.client(dir.path()),
        ledger,
        stops,
        Arc::default(),
        artifact_root,
    )
    .expect("reconciler")
    .create(launch)
    .await
    .expect("the Job is created");
    assert_eq!(api.jobs().len(), 1);
    Harness {
        version: created
            .projection
            .identity
            .resource_version
            .as_str()
            .to_owned(),
        coordinator: KubeCommandCoordinator::new(Some(cell)),
        api,
        _dir: dir,
        next_operation: 1,
    }
}

impl Harness {
    /// One verb through the capability handler at the version the caller last saw; the settlement's
    /// version is the one the next verb must present.
    async fn verb(&mut self, tool: &'static str, verb: &'static str) -> Value {
        let operation =
            OperationId::new(&format!("op-{:032x}", self.next_operation)).expect("operation");
        self.next_operation += 1;
        let settled = self
            .coordinator
            .mutate(
                tool,
                verb,
                190,
                operation,
                HostInvocation {
                    scope: scope(),
                    arguments: json!({"runId": RUN, "expectedResourceVersion": self.version}),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{verb} was refused: {error:?}"));
        assert_eq!(settled["status"], "accepted", "{settled}");
        self.version = settled["resourceVersion"]
            .as_str()
            .expect("settled version")
            .to_owned();
        settled
    }

    fn job(&self) -> Value {
        self.api
            .jobs()
            .into_values()
            .next()
            .expect("the Job is held")
    }

    /// The state `kube.workload.summarize` projects for the run.
    async fn projected_state(&self) -> Option<String> {
        let rows = self
            .coordinator
            .summarize(
                "odin_kube.workload.summarize",
                HostInvocation {
                    scope: scope(),
                    arguments: json!({"runId": RUN}),
                },
            )
            .await
            .expect("summarize answers");
        rows["runs"]
            .as_array()?
            .first()
            .map(|row| row["state"].as_str().expect("state").to_owned())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_suspends_the_job_and_the_projection_says_so() {
    let mut run = running_job().await;
    assert_ne!(run.job()["spec"]["suspend"], true);
    run.verb("odin_kube.workload.pause", "pause").await;
    assert_eq!(run.job()["spec"]["suspend"], true);
    assert_eq!(run.projected_state().await.as_deref(), Some("suspended"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resume_unsuspends_a_paused_job() {
    let mut run = running_job().await;
    run.verb("odin_kube.workload.pause", "pause").await;
    run.verb("odin_kube.workload.resume", "resume").await;
    assert_eq!(run.job()["spec"]["suspend"], false);
    assert_ne!(run.projected_state().await.as_deref(), Some("suspended"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_deletes_the_job_and_nothing_is_left_to_summarize() {
    let mut run = running_job().await;
    run.verb("odin_kube.workload.cancel", "cancel").await;
    assert!(run.api.jobs().is_empty(), "{:?}", run.api.jobs().keys());
    assert_eq!(run.projected_state().await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_recreates_the_job_from_its_launch() {
    let mut run = running_job().await;
    let before = run.job()["metadata"]["uid"].clone();
    run.verb("odin_kube.workload.restart", "restart").await;
    let after = run.job();
    assert_ne!(
        after["metadata"]["uid"], before,
        "a new Job replaced the old one"
    );
    assert_eq!(run.api.jobs().len(), 1);
}
