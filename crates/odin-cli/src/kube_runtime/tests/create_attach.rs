use std::cell::Cell;
use std::collections::VecDeque;
use std::future::Future;
use std::rc::Rc;
use std::time::Duration;

use odin_domain::huginn::{
    KubeJobIdentity, KubeJobLabels, KubeJobLifecycle, KubeJobProjection, KubeJobProjectionSchema,
    KubeOperationKind, KubeOperationProjection, KubeResourceOwnership, KubeResourceRef,
    KubeResourceVersion, KubeResources, KubeStagingProjection, KubeUid, KubeWorkerBinding,
    KubeWorkloadState, KubeWorkloadView,
};
use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
use odin_kube::workload::WorkloadPlacement;
use odin_kube::{JobObservation, KubeError};
use odin_omp::host_tools::HostToolError;
use odin_types::{OperationId, WorkerId};
use serde_json::Value;
use time::OffsetDateTime;

use super::{settle_applied_create, CarrierProbe};
use crate::kube_runtime::evidence::{
    mutation_settlement, summarize_row, MutationOutput, MutationStatus, AGENT_POD_REPORT,
};
use crate::kube_runtime::WorkloadSessionOpenError;

const TOOL: &str = "odin_kube.workload.create";
const BRIDGE_CODE: &str = "omp_bridge_start";
const BRIDGE_DETAIL: &str = "remote harness attach failed: workload carrier is not running";

fn run() -> RunId {
    RunId::new("run.partial-receipt-proof").expect("run id")
}

fn operation() -> OperationId {
    OperationId::new("op-22c426c10000000000000000feedface").expect("operation id")
}

fn applied_observation() -> JobObservation {
    let worker_id = WorkerId::new("worker-partial-receipt").expect("worker id");
    let resource_version = KubeResourceVersion::new("104207").expect("resource version");
    let container_identity = Digest::hash(b"partial-receipt-container");
    let projection = KubeJobProjection {
        schema: KubeJobProjectionSchema::V1,
        identity: KubeJobIdentity {
            uid: KubeUid::new("4c60f59e-d150-4c5f-b72f-475c20eb2fd9").expect("job uid"),
            resource_version: resource_version.clone(),
        },
        labels: KubeJobLabels {
            task_id: TaskId::new("task-partial-receipt").expect("task id"),
            run_id: run(),
            attempt_id: AttemptId::new("attempt-partial-receipt").expect("attempt id"),
            seat_id: SeatId::new("operator").expect("seat id"),
            project_id: ProjectId::new("life").expect("project id"),
            lane_id: LaneId::new("kubert-odin").expect("lane id"),
            model: "partial-receipt-model".to_owned(),
            budget_policy_digest: Digest::hash(b"partial-receipt-budget"),
            container_identity,
        },
        staging: KubeStagingProjection {
            inputs: Vec::new(),
            resumed_from: None,
        },
        checkpoint: None,
        lifecycle: KubeJobLifecycle::Running,
        worker: KubeWorkerBinding {
            worker_id: worker_id.clone(),
            container_identity,
        },
        operation: Some(KubeOperationProjection {
            operation_id: operation(),
            worker_id,
            kind: KubeOperationKind::Create,
            expected_resource_version: resource_version,
            idempotency_digest: Digest::hash(b"partial-receipt-idempotency"),
        }),
    };
    JobObservation {
        projection,
        workload: KubeWorkloadView {
            resource: KubeResourceRef {
                cluster: "unit-cluster".to_owned(),
                api_version: "batch/v1".to_owned(),
                kind: "Job".to_owned(),
                namespace: Some("unit-namespace".to_owned()),
                name: "odin-partial-receipt-job".to_owned(),
                uid: "4c60f59e-d150-4c5f-b72f-475c20eb2fd9".to_owned(),
            },
            profile: None,
            ownership: KubeResourceOwnership::Odin {
                run_id: run(),
                attempt_id: Some(AttemptId::new("attempt-partial-receipt").expect("attempt id")),
                lane_id: LaneId::new("kubert-odin").expect("lane id"),
                seat_id: SeatId::new("operator").expect("seat id"),
            },
            revision: 1,
            state: KubeWorkloadState::Running,
            node_id: None,
            containers: Vec::new(),
            requested: KubeResources::default(),
            limit: KubeResources::default(),
            usage: KubeResources::default(),
            started_at: None,
            finished_at: None,
            observed_at: OffsetDateTime::UNIX_EPOCH,
            usage_stale: true,
            stale: false,
        },
    }
}

fn applied_result() -> MutationOutput {
    mutation_settlement(
        TOOL,
        MutationStatus::Accepted,
        run().as_str(),
        operation().as_str(),
        &applied_observation(),
    )
    .expect("the applied settlement projects")
    .with_report(AGENT_POD_REPORT)
}

fn placement(phase: Option<&'static str>) -> WorkloadPlacement {
    WorkloadPlacement {
        pod: "odin-partial-receipt-carrier".to_owned(),
        node: None,
        phase: phase.map(str::to_owned),
        timeline: odin_kube::pod_phase::PodTimeline::default(),
    }
}

fn probe(workload: Option<KubeWorkloadState>, pod: Option<&'static str>) -> CarrierProbe {
    CarrierProbe {
        workload,
        pod: Some(placement(pod)),
    }
}

async fn settle<R, RF, A, AF>(
    receipt: &MutationOutput,
    read: R,
    attach: A,
) -> Result<Value, HostToolError>
where
    R: FnMut() -> RF,
    RF: Future<Output = Result<CarrierProbe, KubeError>>,
    A: FnOnce() -> AF,
    AF: Future<Output = Result<(), WorkloadSessionOpenError>>,
{
    let end = tokio::time::Instant::now() + Duration::from_secs(60);
    settle_applied_create(
        TOOL,
        receipt,
        read,
        attach,
        |_| {},
        end,
        Duration::from_secs(5),
    )
    .await
}

#[tokio::test(start_paused = true)]
async fn pending_then_running_attaches_exactly_once() {
    let receipt = applied_result();
    let reads = Rc::new(Cell::new(0u32));
    let script = Rc::new(std::cell::RefCell::new(VecDeque::from(vec![
        probe(Some(KubeWorkloadState::Pending), None),
        probe(Some(KubeWorkloadState::Running), None),
        probe(Some(KubeWorkloadState::Running), Some("Running")),
    ])));
    let attaches = Rc::new(Cell::new(0u32));
    let read_reads = Rc::clone(&reads);
    let read_script = Rc::clone(&script);
    let attach_count = Rc::clone(&attaches);
    let settlement =
        settle(
            &receipt,
            move || {
                read_reads.set(read_reads.get() + 1);
                let next = read_script.borrow_mut().pop_front();
                async move {
                    Ok::<CarrierProbe, KubeError>(next.expect("the scripted probe list is long"))
                }
            },
            move || {
                attach_count.set(attach_count.get() + 1);
                async { Ok(()) }
            },
        )
        .await
        .expect("a ready carrier completes the create");
    assert_eq!(settlement["status"], "accepted");
    assert_eq!(settlement["jobName"], "odin-partial-receipt-job");
    assert_eq!(settlement["resourceVersion"], "104207");
    assert_eq!(settlement["workerId"], "worker-partial-receipt");
    assert_eq!(settlement["operationId"], operation().as_str());
    assert_eq!(reads.get(), 3);
    assert_eq!(attaches.get(), 1, "the attach happens at most once");
}

#[tokio::test(start_paused = true)]
async fn attach_failure_reports_created_run_and_cause() {
    let outcome = settle(
        &applied_result(),
        || async { Ok(probe(Some(KubeWorkloadState::Running), Some("Running"))) },
        || async {
            Err(WorkloadSessionOpenError {
                code: BRIDGE_CODE.to_owned(),
                detail: BRIDGE_DETAIL.to_owned(),
            })
        },
    )
    .await;
    let HostToolError::Uncertain { detail, .. } = outcome.expect_err("attach failed") else {
        panic!("created workload must not be reported as rejected");
    };
    assert!(detail.contains(run().as_str()));
    assert!(detail.contains("was created"));
    assert!(detail.contains(BRIDGE_DETAIL));
}

#[tokio::test(start_paused = true)]
async fn terminal_carrier_skips_attach() {
    let attaches = Cell::new(0);
    let outcome = settle(
        &applied_result(),
        || async { Ok(probe(Some(KubeWorkloadState::Failed), Some("Failed"))) },
        || {
            attaches.set(attaches.get() + 1);
            async { Ok(()) }
        },
    )
    .await;
    assert!(matches!(outcome, Err(HostToolError::Uncertain { .. })));
    assert_eq!(attaches.get(), 0);
}

#[tokio::test(start_paused = true)]
async fn pending_carrier_times_out_without_attach() {
    let attaches = Cell::new(0);
    let outcome = settle(
        &applied_result(),
        || async { Ok(probe(Some(KubeWorkloadState::Running), Some("Pending"))) },
        || {
            attaches.set(attaches.get() + 1);
            async { Ok(()) }
        },
    )
    .await;
    assert!(matches!(outcome, Err(HostToolError::Uncertain { .. })));
    assert_eq!(attaches.get(), 0);
}

#[test]
fn a_summary_row_says_who_launched_a_run_and_when_it_ran() {
    let mut observation = applied_observation();
    observation.workload.state = KubeWorkloadState::Succeeded;
    observation.workload.started_at = Some(OffsetDateTime::UNIX_EPOCH + Duration::from_secs(60));
    observation.workload.finished_at = Some(OffsetDateTime::UNIX_EPOCH + Duration::from_secs(90));
    let row = serde_json::to_value(summarize_row(TOOL, &observation).expect("row")).unwrap();
    assert_eq!(row["seat"], "operator");
    assert_eq!(row["startedAt"], "1970-01-01T00:01:00Z");
    assert_eq!(row["finishedAt"], "1970-01-01T00:01:30Z");
    assert_eq!(row["state"], "succeeded");
}
