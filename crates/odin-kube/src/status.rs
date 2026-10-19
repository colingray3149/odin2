//! Job and workload projections from observed `batch/v1` objects.
//!
//! The projection annotation supplies the admitted binding; UID,
//! resourceVersion, and lifecycle come from the observed object.
//! Workers stop through the kernel's [`StopAuthority`], not pod names or PIDs.

use std::collections::BTreeMap;

use crate::client::KubeError;
use crate::job::{
    expected_binding_labels, verify_binding_labels, JobObservation, JOB_PROJECTION_ANNOTATION,
    KUBE_LABEL_STAGED, KUBE_STAGED_TRUE,
};
use crate::placement::{container_resources, pod_limits, pod_requests};
use k8s_openapi::api::batch::v1;
use odin_domain::huginn::{
    KubeContainerView, KubeJobIdentity, KubeJobLifecycle, KubeJobProjection, KubeResourceOwnership,
    KubeResourceRef, KubeResourceVersion, KubeResources, KubeUid, KubeWorkloadState,
    KubeWorkloadView,
};
use odin_domain::Digest;
use time::OffsetDateTime;

pub use odin_kernel::stop::{mint_worker_id, CorrelationId, WorkerId};
pub use odin_kernel::{StopAuthority, StopAuthorityError};

/// Prefer a running pod's node, then the newest scheduled pod's node.
/// Returns `None` if none was scheduled; Jobs themselves do not carry placement.
pub fn bound_node(pods: &[k8s_openapi::api::core::v1::Pod]) -> Option<odin_domain::NodeId> {
    let scheduled = |pod: &&k8s_openapi::api::core::v1::Pod| {
        pod.spec
            .as_ref()
            .and_then(|spec| spec.node_name.as_deref())
            .is_some_and(|node| !node.is_empty())
    };
    let running = pods.iter().filter(scheduled).find(|pod| {
        pod.status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Running")
    });
    let pod = running.or_else(|| {
        pods.iter()
            .filter(scheduled)
            .max_by_key(|pod| pod.metadata.creation_timestamp.as_ref().map(|time| time.0))
    })?;
    let node = pod.spec.as_ref()?.node_name.as_deref()?;
    odin_domain::NodeId::new(node).ok()
}

/// The node the named Job's pod is bound to, read off the API server with
/// one bounded `job-name` pod list. `Ok(None)`: no pod was ever scheduled.
pub async fn job_node(
    client: &crate::client::KubeClient,
    job: &str,
) -> Result<Option<odin_domain::NodeId>, crate::client::KubeError> {
    let pods = list_pods(client, &format!("job-name={job}")).await?;
    Ok(bound_node(&pods))
}

/// Every Job's bound node from one bounded pod list, keyed by Job name.
pub async fn job_nodes(
    client: &crate::client::KubeClient,
) -> Result<std::collections::HashMap<String, odin_domain::NodeId>, crate::client::KubeError> {
    let mut by_job: std::collections::HashMap<String, Vec<k8s_openapi::api::core::v1::Pod>> =
        std::collections::HashMap::new();
    for pod in list_pods(client, "job-name").await? {
        if let Some(job) = pod
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get("job-name"))
            .cloned()
        {
            by_job.entry(job).or_default().push(pod);
        }
    }
    Ok(by_job
        .into_iter()
        .filter_map(|(job, pods)| Some((job, bound_node(&pods)?)))
        .collect())
}

async fn list_pods(
    client: &crate::client::KubeClient,
    selector: &str,
) -> Result<Vec<k8s_openapi::api::core::v1::Pod>, crate::client::KubeError> {
    let listing = tokio::time::timeout(
        client.config.request_timeout,
        client
            .pods()
            .list(&kube::api::ListParams::default().labels(selector)),
    )
    .await
    .map_err(|_| crate::client::KubeError::unavailable("kube pod list timed out"))??;
    if listing.metadata.continue_.is_some() {
        return Err(crate::client::KubeError::unavailable(
            "kube pod list came back chunked; a partial list cannot place workloads",
        ));
    }
    Ok(listing.items)
}

/// Project one observed `batch/v1` Job into the validated domain projection
/// and the observed workload view.
///
/// `revision` is the reconciler's persisted observation ordinal; Kubernetes
/// resourceVersions are opaque and must not become numeric Huginn revisions.
///
/// - The binding schema is deserialized with the domain schema itself
///   (`deny_unknown_fields` plus `KubeJobProjection::validate`); anything
///   that does not round-trip is `KubeError::Rejected`.
/// - UID and resourceVersion come from the observed metadata. An annotation
///   naming a different UID is rejected.
/// - A recorded operation claim is kept only while its
///   `expected_resource_version` still equals the observed resourceVersion;
///   once the API server moved past it the claim is settled or superseded
///   and projects as `None`.
/// - Lifecycle is derived from observed status conditions only for terminal
///   verdicts: `Complete=True` means succeeded and `Failed=True` means
///   failed. Bare `succeeded`/`failed` counters never terminate a Job
///   (failed pods retry under the Job's backoff); the `Suspended`
///   condition, `active` counter, deletion timestamp, `spec.suspend`, and
///   the staging marker label resolve every non-terminal phase.
/// - A Job object carries no measured usage and no container runtime state:
///   usage projects as the domain's unobserved zero with `usage_stale: true`
///   (never workload `stale`, which stays a departure marker), and
///   readiness/restart facts stay at their unobserved defaults. Pod-level
///   observation supplies live values, never invention.
pub fn observe_job(
    cluster: &str,
    job: &v1::Job,
    revision: u64,
) -> Result<JobObservation, KubeError> {
    let metadata = &job.metadata;
    let encoded = metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(JOB_PROJECTION_ANNOTATION))
        .ok_or_else(|| {
            rejected("Job is not Odin-bound: missing odin.dev/job-projection annotation")
        })?;
    let mut projection: KubeJobProjection = serde_json::from_str(encoded)
        .map_err(|error| rejected(&format!("Job projection fails domain schema: {error}")))?;

    let observed_uid = KubeUid::new(metadata.uid.clone().unwrap_or_default())
        .map_err(|error| rejected(&format!("Job metadata.uid invalid: {error}")))?;
    if projection.identity.uid != observed_uid {
        return Err(rejected(
            "Job projection annotation is bound to a different Job UID",
        ));
    }
    let observed_rv =
        KubeResourceVersion::new(metadata.resource_version.clone().unwrap_or_default())
            .map_err(|error| rejected(&format!("Job metadata.resourceVersion invalid: {error}")))?;

    check_binding_labels(metadata, &projection)?;

    projection.operation = projection
        .operation
        .take()
        .filter(|operation| operation.expected_resource_version == observed_rv);
    projection.identity = KubeJobIdentity {
        uid: observed_uid,
        resource_version: observed_rv,
    };
    let lifecycle = observe_lifecycle(
        metadata.deletion_timestamp.is_some(),
        job.spec.as_ref(),
        job.status.as_ref(),
        metadata.labels.as_ref(),
    );
    projection.lifecycle = lifecycle;
    projection
        .validate()
        .map_err(|error| rejected(&format!("Observed Job projection invalid: {error}")))?;

    let (containers, requested, limit) = template_containers(job.spec.as_ref())?;
    let started_at = job
        .status
        .as_ref()
        .and_then(|status| status.start_time.as_ref())
        .and_then(|time| observed_time(&time.0));
    let finished_at = finished_time(job.status.as_ref());

    let workload = KubeWorkloadView {
        resource: KubeResourceRef {
            cluster: cluster.to_owned(),
            api_version: "batch/v1".to_owned(),
            kind: "Job".to_owned(),
            namespace: metadata.namespace.clone(),
            name: metadata.name.clone().unwrap_or_default(),
            uid: projection.identity.uid.as_str().to_owned(),
        },
        profile: metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(crate::workload::WORKLOAD_LABEL))
            .cloned(),
        ownership: KubeResourceOwnership::Odin {
            run_id: projection.labels.run_id.clone(),
            attempt_id: Some(projection.labels.attempt_id.clone()),
            lane_id: projection.labels.lane_id.clone(),
            seat_id: projection.labels.seat_id.clone(),
        },
        revision,
        state: workload_state(lifecycle),
        // A Job object carries no node placement; the bound pod's nodeName
        // is observed on pods, never guessed here.
        node_id: None,
        containers,
        requested,
        limit,
        usage: KubeResources::default(),
        // The Job object exposes no usage metrics (metrics-server is
        // disabled): the zeros above mean unobserved, and `usage_stale`
        // marks that absence explicitly instead of claiming a measured
        // zero. Workload `stale` stays false: the Job is observed and live.
        usage_stale: true,
        started_at,
        finished_at,
        observed_at: OffsetDateTime::now_utc(),
        stale: false,
    };

    Ok(JobObservation {
        projection,
        workload,
    })
}

/// When a Job finished: its completion time, or — a failed Job has none —
/// when its Failed condition became true.
fn finished_time(status: Option<&v1::JobStatus>) -> Option<OffsetDateTime> {
    let status = status?;
    status
        .completion_time
        .as_ref()
        .or_else(|| {
            status.conditions.as_ref()?.iter().find_map(|condition| {
                (condition.type_ == "Failed" && condition.status == "True")
                    .then_some(condition.last_transition_time.as_ref())
                    .flatten()
            })
        })
        .and_then(|time| observed_time(&time.0))
}

/// Foreign Jobs need no Odin binding. Invalid resource quantities produce
/// unobserved zero reservations rather than blocking other observations.
pub fn observe_foreign_job(cluster: &str, job: &v1::Job, revision: u64) -> KubeWorkloadView {
    let metadata = &job.metadata;
    let lifecycle = observe_lifecycle(
        metadata.deletion_timestamp.is_some(),
        job.spec.as_ref(),
        job.status.as_ref(),
        metadata.labels.as_ref(),
    );
    let started_at = job
        .status
        .as_ref()
        .and_then(|status| status.start_time.as_ref())
        .and_then(|time| observed_time(&time.0));
    let finished_at = finished_time(job.status.as_ref());
    let (containers, requested, limit) = template_containers(job.spec.as_ref()).unwrap_or_default();

    KubeWorkloadView {
        resource: KubeResourceRef {
            cluster: cluster.to_owned(),
            api_version: "batch/v1".to_owned(),
            kind: "Job".to_owned(),
            namespace: metadata.namespace.clone(),
            name: metadata.name.clone().unwrap_or_default(),
            uid: metadata.uid.clone().unwrap_or_default(),
        },
        profile: None,
        ownership: KubeResourceOwnership::Foreign,
        revision,
        state: workload_state(lifecycle),
        // A Job object carries no node placement; the bound pod's nodeName
        // is observed on pods, never guessed here.
        node_id: None,
        containers,
        requested,
        limit,
        usage: KubeResources::default(),
        // A Job object exposes no usage metrics; the zeros mean unobserved
        // and `usage_stale` marks that absence. Workload `stale` stays
        // false: the Job is observed and live.
        usage_stale: true,
        started_at,
        finished_at,
        observed_at: OffsetDateTime::now_utc(),
        stale: false,
    }
}

/// Derive the observed lifecycle from real Job status. Order matters:
/// deletion first, then the two terminal Job conditions (`Complete=True`,
/// `Failed=True`) — bare `failed`/`succeeded` pod counters are retry
/// bookkeeping and never terminate the Job — then the `Suspended`
/// condition before `spec.suspend`, activeness before transport phases,
/// and the staging marker before plain pending.
fn observe_lifecycle(
    deleting: bool,
    spec: Option<&v1::JobSpec>,
    status: Option<&v1::JobStatus>,
    labels: Option<&BTreeMap<String, String>>,
) -> KubeJobLifecycle {
    if deleting {
        return KubeJobLifecycle::Cancelling;
    }
    if let Some(status) = status {
        let condition = |type_: &str| {
            status.conditions.as_ref().is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == type_ && condition.status == "True")
            })
        };
        if condition("Complete") {
            return KubeJobLifecycle::Succeeded;
        }
        if condition("Failed") {
            return KubeJobLifecycle::Failed;
        }
        if condition("Suspended") {
            return KubeJobLifecycle::Paused;
        }
        if status.active.unwrap_or(0) > 0 {
            return KubeJobLifecycle::Running;
        }
    }
    if spec.is_some_and(|spec| spec.suspend == Some(true)) {
        return KubeJobLifecycle::Paused;
    }
    let staged = labels
        .and_then(|labels| labels.get(KUBE_LABEL_STAGED))
        .is_some_and(|value| value == KUBE_STAGED_TRUE);
    if !staged {
        return KubeJobLifecycle::Staging;
    }
    KubeJobLifecycle::Pending
}

fn workload_state(lifecycle: KubeJobLifecycle) -> KubeWorkloadState {
    match lifecycle {
        KubeJobLifecycle::Pending | KubeJobLifecycle::Staging => KubeWorkloadState::Pending,
        KubeJobLifecycle::Running => KubeWorkloadState::Running,
        KubeJobLifecycle::Paused => KubeWorkloadState::Suspended,
        KubeJobLifecycle::Succeeded => KubeWorkloadState::Succeeded,
        KubeJobLifecycle::Failed => KubeWorkloadState::Failed,
        KubeJobLifecycle::Cancelling => KubeWorkloadState::Terminating,
        // A retired Job has been deleted; the API server can no longer
        // surface it for observation.
        KubeJobLifecycle::Retired => KubeWorkloadState::Unknown,
    }
}

/// Cross-check every one of the eleven required binding labels the Job
/// owner stamps onto the object against the authoritative annotation
/// binding. Absence or mismatch of any of them is a binding violation.
fn check_binding_labels(
    metadata: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    projection: &KubeJobProjection,
) -> Result<(), KubeError> {
    let Some(labels) = metadata.labels.as_ref() else {
        return Err(rejected("Job carries none of the required binding labels"));
    };
    let expected = expected_binding_labels(&projection.labels, &projection.worker.worker_id);
    verify_binding_labels(labels, &expected).map_err(|reason| {
        rejected(&format!(
            "Job binding labels disagree with the projection annotation: {reason}"
        ))
    })
}

/// Project pod-template containers and their scheduler reservations.
/// Per-container requests and limits come from the placement owner's exact
/// quantity parser; the workload totals are the pod reservations the
/// scheduler actually computes (`pod_requests`/`pod_limits`: sidecar-aware
/// init peaks, pod-level resources, and overhead included), so observation
/// and placement admission can never disagree about one workload.
fn template_containers(
    spec: Option<&v1::JobSpec>,
) -> Result<(Vec<KubeContainerView>, KubeResources, KubeResources), KubeError> {
    let pod_spec = spec.and_then(|spec| spec.template.spec.as_ref());
    let Some(pod_spec) = pod_spec else {
        return Ok((
            Vec::new(),
            KubeResources::default(),
            KubeResources::default(),
        ));
    };
    let mut containers = Vec::new();
    for container in pod_spec
        .containers
        .iter()
        .chain(pod_spec.init_containers.iter().flatten())
    {
        let (requested, limit) = container_resources(container)?;
        let image = container.image.clone().unwrap_or_default();
        containers.push(KubeContainerView {
            name: container.name.clone(),
            image_digest: image_digest(&image),
            image,
            // The Job object carries no live container status; runtime
            // readiness and restarts are observed on pods, not here.
            ready: false,
            restart_count: 0,
            requested,
            limit,
            usage: KubeResources::default(),
        });
    }
    Ok((containers, pod_requests(pod_spec)?, pod_limits(pod_spec)?))
}

/// Extract the content digest from a `repo@sha256:<hex>` image reference.
fn image_digest(image: &str) -> Option<Digest> {
    let digest = image.split('@').nth(1)?;
    let hex = digest.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(Digest::new(bytes))
}

/// Exact native conversion of the API server's jiff `Timestamp` into the
/// domain's `OffsetDateTime`: seconds and subsecond nanoseconds carried over
/// losslessly, never re-parsed through a string round-trip.
fn observed_time(timestamp: &k8s_openapi::jiff::Timestamp) -> Option<OffsetDateTime> {
    let total = timestamp.as_nanosecond();
    let seconds = i64::try_from(total.div_euclid(1_000_000_000)).ok()?;
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .replace_nanosecond(u32::try_from(total.rem_euclid(1_000_000_000)).ok()?)
        .ok()
}

fn rejected(reason: &str) -> KubeError {
    KubeError::Rejected {
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn condition(type_: &str) -> v1::JobCondition {
        v1::JobCondition {
            type_: type_.to_owned(),
            status: "True".to_owned(),
            ..Default::default()
        }
    }

    fn staged_labels(staged: &str) -> Option<BTreeMap<String, String>> {
        Some(BTreeMap::from([(
            KUBE_LABEL_STAGED.to_owned(),
            staged.to_owned(),
        )]))
    }

    /// Only terminal Job conditions end the workload; failed pods can retry.
    #[test]
    fn failed_pod_counter_never_terminates() {
        let retrying = v1::JobStatus {
            failed: Some(3),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&retrying), staged_labels("true").as_ref()),
            KubeJobLifecycle::Pending
        );
        let between_retries = v1::JobStatus {
            failed: Some(1),
            active: Some(0),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(
                false,
                None,
                Some(&between_retries),
                staged_labels("false").as_ref()
            ),
            KubeJobLifecycle::Staging
        );
    }

    #[test]
    fn terminal_conditions_resolve_lifecycle() {
        let complete = v1::JobStatus {
            conditions: Some(vec![condition("Complete")]),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&complete), None),
            KubeJobLifecycle::Succeeded
        );
        let failed = v1::JobStatus {
            conditions: Some(vec![condition("Failed")]),
            failed: Some(9),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&failed), None),
            KubeJobLifecycle::Failed
        );
        // Failure conditions outrank a live pod counter: the Job is doomed.
        let doomed = v1::JobStatus {
            conditions: Some(vec![condition("Failed")]),
            active: Some(1),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&doomed), None),
            KubeJobLifecycle::Failed
        );
    }

    #[test]
    fn non_terminal_phases_resolve_in_order() {
        let spec = v1::JobSpec::default();
        assert_eq!(
            observe_lifecycle(true, None, None, None),
            KubeJobLifecycle::Cancelling
        );
        let suspended = v1::JobStatus {
            conditions: Some(vec![condition("Suspended")]),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&suspended), None),
            KubeJobLifecycle::Paused
        );
        let running = v1::JobStatus {
            active: Some(1),
            ..Default::default()
        };
        assert_eq!(
            observe_lifecycle(false, None, Some(&running), None),
            KubeJobLifecycle::Running
        );
        let mut suspended_spec = spec.clone();
        suspended_spec.suspend = Some(true);
        assert_eq!(
            observe_lifecycle(false, Some(&suspended_spec), None, None),
            KubeJobLifecycle::Paused
        );
        assert_eq!(
            observe_lifecycle(false, Some(&spec), None, staged_labels("false").as_ref()),
            KubeJobLifecycle::Staging
        );
        assert_eq!(
            observe_lifecycle(false, Some(&spec), None, staged_labels("true").as_ref()),
            KubeJobLifecycle::Pending
        );
    }

    /// Foreign Jobs use the same lifecycle parsing without Odin binding metadata.
    #[test]
    fn foreign_job_projects_readonly() {
        let mut job = v1::Job {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("someone-elses-job".to_owned()),
                namespace: Some("other".to_owned()),
                uid: Some("12345678-90ab-cdef-1234-567890abcdef".to_owned()),
                resource_version: Some("42".to_owned()),
                ..Default::default()
            },
            spec: Some(v1::JobSpec {
                suspend: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let view = observe_foreign_job("prod", &job, 7);
        assert_eq!(view.ownership, KubeResourceOwnership::Foreign);
        assert_eq!(view.revision, 7);
        assert_eq!(view.state, KubeWorkloadState::Suspended);
        assert_eq!(view.resource.name, "someone-elses-job");
        assert_eq!(view.resource.uid, "12345678-90ab-cdef-1234-567890abcdef");
        // Terminal conditions resolve identically for foreign objects.
        job.status = Some(v1::JobStatus {
            conditions: Some(vec![condition("Complete")]),
            ..Default::default()
        });
        let view = observe_foreign_job("prod", &job, 8);
        assert_eq!(view.state, KubeWorkloadState::Succeeded);
        // A Job carries no usage metrics: usage-stale by design, never
        // workload-stale while the object is observed and live.
        assert!(!view.stale);
        assert!(view.usage_stale);
    }

    #[test]
    fn a_jobs_node_is_its_running_pods_node() {
        use k8s_openapi::api::core::v1::{Pod, PodSpec, PodStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
        let pod = |node: Option<&str>, phase: &str, created: i64| Pod {
            metadata: kube::api::ObjectMeta {
                creation_timestamp: Some(Time(
                    k8s_openapi::jiff::Timestamp::from_second(created).expect("time"),
                )),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: node.map(str::to_owned),
                ..Default::default()
            }),
            status: Some(PodStatus {
                phase: Some(phase.to_owned()),
                ..Default::default()
            }),
        };
        let named = |pods: &[Pod]| super::bound_node(pods).map(|node| node.to_string());
        assert_eq!(named(&[pod(None, "Pending", 3)]), None);
        assert_eq!(
            named(&[
                pod(Some("mini"), "Failed", 1),
                pod(Some("pc"), "Running", 0)
            ]),
            Some("pc".to_owned())
        );
        assert_eq!(
            named(&[pod(Some("mini"), "Failed", 1), pod(Some("pc"), "Failed", 2)]),
            Some("pc".to_owned())
        );
        assert_eq!(named(&[]), None);
    }
}
