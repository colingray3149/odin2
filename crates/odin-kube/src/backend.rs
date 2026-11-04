//! UID-guarded Job release, suspension, and foreground deletion.

use std::future::Future;
use std::time::{Duration, Instant};

use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, Preconditions};
use odin_domain::huginn::KubeJobProjection;
use odin_kernel::stop::{
    JobReleaseEvidence, JobWorkerBackend, JobWorkerBackendFault, JobWorkerIdentity, WorkerId,
};
use odin_ledger::stop::{
    JobFaultProbe, JobFaultProbeKind, JobPodResidue, JobStopAction, JobStopEvidenceBody,
    JOB_BACKEND_TAG, JOB_STOP_EVIDENCE_SCHEMA,
};

use crate::client::{KubeClient, KubeError};
use crate::job::{bounded_label_value, JOB_LABEL_WORKER_ID, JOB_PROJECTION_ANNOTATION};

// Pace API observations while Kubernetes reaps the Job's pods.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const POD_PAGE_LIMIT: u32 = 500;
const MAX_POD_PAGES: usize = 32;
// Bound retries when the Job controller keeps changing resourceVersion.
const MAX_SUSPEND_PATCHES: u32 = 8;

enum JobPresence {
    Gone,
    // Avoid putting the full Job object on the stack for every match.
    Exact(Box<Job>),
}

enum PatchOutcome {
    Applied,
    /// `404`: nothing by that name remains, or the UID no longer matches.
    Gone,
    /// `409`: the resourceVersion precondition missed; re-observe first.
    Conflicted,
}

pub(crate) struct KubernetesJobBackend {
    client: KubeClient,
    runtime: tokio::runtime::Handle,
}

impl KubernetesJobBackend {
    // Synchronous authority calls must reuse a multithreaded parent runtime.
    pub(crate) fn new(client: KubeClient) -> Result<Self, KubeError> {
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                return Err(KubeError::rejected(
                    "Kubernetes job backend requires an ambient Tokio runtime; it reuses the parent multithread runtime instead of building one",
                ))
            }
        };
        if matches!(
            runtime.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::CurrentThread
        ) {
            return Err(KubeError::rejected(
                "Kubernetes job backend requires a multithreaded Tokio runtime; a current-thread runtime cannot host the blocking stop ladder",
            ));
        }
        Ok(Self { client, runtime })
    }

    // Yield the current worker while the captured runtime drives API requests.
    fn run<Step>(&self, step: Step) -> Result<Step::Output, JobWorkerBackendFault>
    where
        Step: Future,
    {
        if let Ok(ambient) = tokio::runtime::Handle::try_current() {
            if matches!(
                ambient.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::CurrentThread
            ) {
                return Err(JobWorkerBackendFault::Unavailable {
                    reason: "job backend cannot block inside a current-thread runtime; it was constructed under a multithread runtime".to_owned(),
                });
            }
        }
        Ok(tokio::task::block_in_place(|| self.runtime.block_on(step)))
    }
}

fn probe(kind: JobFaultProbeKind) -> JobFaultProbe {
    JobFaultProbe {
        probe: kind,
        detected: true,
    }
}

impl JobWorkerBackend for KubernetesJobBackend {
    fn tag(&self) -> &'static str {
        JOB_BACKEND_TAG
    }

    fn release(
        &self,
        worker_id: &WorkerId,
        identity: &JobWorkerIdentity,
    ) -> Result<JobReleaseEvidence, JobWorkerBackendFault> {
        self.run(release_worker(&self.client, worker_id, identity))?
    }

    fn stop(
        &self,
        worker_id: &WorkerId,
        identity: &JobWorkerIdentity,
        action: JobStopAction,
    ) -> Result<JobStopEvidenceBody, JobWorkerBackendFault> {
        self.run(stop_worker(&self.client, worker_id, identity, action))?
    }
}

async fn release_worker(
    client: &KubeClient,
    worker_id: &WorkerId,
    identity: &JobWorkerIdentity,
) -> Result<JobReleaseEvidence, JobWorkerBackendFault> {
    validate_identity(client, identity)
        .map_err(|reason| JobWorkerBackendFault::Invalid { reason })?;
    let jobs = job_api(client, identity);
    let request = client.request_timeout();
    let mut patches = 0;
    loop {
        let job = match observe_job(&jobs, identity, request)
            .await
            .map_err(|error| JobWorkerBackendFault::Unavailable {
                reason: format!("Job release query failed: {error}"),
            })? {
            JobPresence::Exact(job) => job,
            JobPresence::Gone => {
                return Err(JobWorkerBackendFault::Conflict {
                    reason: "Job release failed: registered Job is absent or replaced".to_owned(),
                });
            }
        };
        verify_binding(&job, worker_id, identity)
            .map_err(|reason| JobWorkerBackendFault::Conflict { reason })?;
        match job_suspension(&job) {
            Some(false) => {
                return Ok(JobReleaseEvidence {
                    backend: JOB_BACKEND_TAG.to_owned(),
                    cluster: identity.cluster.clone(),
                    namespace: identity.namespace.clone(),
                    job_name: identity.job_name.clone(),
                    job_uid: identity.job_uid.clone(),
                    job_present: true,
                    job_suspended: Some(false),
                    evidence_complete: true,
                    fault_probes: Vec::new(),
                    missing: None,
                });
            }
            Some(true) => {}
            None => {
                return Err(JobWorkerBackendFault::Invalid {
                    reason: "Job release failed: suspension state is missing".to_owned(),
                });
            }
        }
        if patches == MAX_SUSPEND_PATCHES {
            return Err(JobWorkerBackendFault::Conflict {
                reason: "Job release exceeded the resourceVersion retry limit".to_owned(),
            });
        }
        let resource_version = job
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| JobWorkerBackendFault::Invalid {
                reason: "Job release requires a resourceVersion".to_owned(),
            })?;
        patch_suspend(&jobs, identity, resource_version, false, request)
            .await
            .map_err(|error| JobWorkerBackendFault::Unavailable {
                reason: format!("Job release patch failed: {error}"),
            })?;
        patches += 1;
    }
}

// Observe both the registered Job and its UID-owned pods before settling.
async fn stop_worker(
    client: &KubeClient,
    worker_id: &WorkerId,
    identity: &JobWorkerIdentity,
    action: JobStopAction,
) -> Result<JobStopEvidenceBody, JobWorkerBackendFault> {
    if let Err(reason) = validate_identity(client, identity) {
        return Err(JobWorkerBackendFault::Invalid { reason });
    }
    let jobs = job_api(client, identity);
    let pods = pod_api(client, identity);
    let request = client.request_timeout();
    let deadline = Instant::now() + client.teardown_timeout();
    let mut probes: Vec<JobFaultProbe> = Vec::new();
    let mut job_absent;
    let mut job_suspended;
    let mut residue;
    // One deletion per observed Job generation: the delete is re-issued only
    // when the observed resourceVersion is not the one already deleted.
    let mut deleted_rv: Option<String> = None;
    let mut suspend_patches = 0u32;

    loop {
        match observe_job(&jobs, identity, request)
            .await
            .map_err(|error| JobWorkerBackendFault::Unavailable {
                reason: format!("Job stop query failed: {error}"),
            })? {
            JobPresence::Gone => {
                job_absent = true;
                job_suspended = None;
            }
            JobPresence::Exact(job) => {
                job_absent = false;
                job_suspended = job_suspension(&job);
                let resource_version = job.metadata.resource_version.clone().unwrap_or_default();
                let deleting = job.metadata.deletion_timestamp.is_some();
                match action {
                    JobStopAction::Delete => {
                        if !deleting
                            && !resource_version.is_empty()
                            && deleted_rv.as_deref() != Some(resource_version.as_str())
                        {
                            request_delete(&jobs, identity, &resource_version, request)
                                .await
                                .map_err(|error| JobWorkerBackendFault::Unavailable {
                                    reason: format!("Job stop deletion failed: {error}"),
                                })?;
                            deleted_rv = Some(resource_version);
                        }
                    }
                    JobStopAction::Suspend => {
                        if !deleting
                            && job_suspended != Some(true)
                            && !resource_version.is_empty()
                            && suspend_patches < MAX_SUSPEND_PATCHES
                        {
                            suspend_patches += 1;
                            patch_suspend(&jobs, identity, &resource_version, true, request)
                                .await
                                .map_err(|error| JobWorkerBackendFault::Unavailable {
                                    reason: format!("Job stop suspension failed: {error}"),
                                })?;
                        }
                    }
                }
            }
        }
        residue = list_owned_pods(&pods, identity, request)
            .await
            .map_err(|error| JobWorkerBackendFault::Unavailable {
                reason: format!("Job stop pod inventory failed: {error}"),
            })?;
        let workload_settled = match action {
            JobStopAction::Delete => job_absent,
            JobStopAction::Suspend => job_absent || job_suspended == Some(true),
        };
        if workload_settled && residue.is_empty() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL.min(deadline - now)).await;
    }

    if !job_absent && matches!(action, JobStopAction::Delete) {
        probes.push(probe(JobFaultProbeKind::JobPresent));
    }
    if matches!(action, JobStopAction::Suspend) && !job_absent && job_suspended != Some(true) {
        probes.push(probe(JobFaultProbeKind::JobNotSuspended));
    }
    if !residue.is_empty() {
        probes.push(probe(JobFaultProbeKind::PodResidue));
    }
    residue.sort_by(|left, right| (&left.name, &left.uid).cmp(&(&right.name, &right.uid)));
    Ok(JobStopEvidenceBody {
        schema: JOB_STOP_EVIDENCE_SCHEMA.to_owned(),
        worker_id: worker_id.as_str().to_owned(),
        backend: JOB_BACKEND_TAG.to_owned(),
        cluster: identity.cluster.clone(),
        namespace: identity.namespace.clone(),
        job_name: identity.job_name.clone(),
        job_uid: identity.job_uid.clone(),
        job_absent,
        job_suspended,
        pod_residue: residue,
        evidence_complete: true,
        fault_probes: probes,
    })
}

fn job_api(client: &KubeClient, identity: &JobWorkerIdentity) -> kube::Api<Job> {
    kube::Api::namespaced(client.client.clone(), &identity.namespace)
}

fn pod_api(client: &KubeClient, identity: &JobWorkerIdentity) -> kube::Api<Pod> {
    kube::Api::namespaced(client.client.clone(), &identity.namespace)
}

fn job_suspension(job: &Job) -> Option<bool> {
    job.spec.as_ref().and_then(|spec| spec.suspend)
}

// A replacement at the same name belongs to another Job and must not be touched.
async fn observe_job(
    jobs: &kube::Api<Job>,
    identity: &JobWorkerIdentity,
    request: Duration,
) -> Result<JobPresence, KubeError> {
    let job = match tokio::time::timeout(request, jobs.get(&identity.job_name)).await {
        Err(_) => {
            return Err(KubeError::unavailable(
                "registered Job observation timed out",
            ))
        }
        Ok(Ok(job)) => job,
        Ok(Err(kube::Error::Api(status))) if status.code == 404 => {
            return Ok(JobPresence::Gone);
        }
        Ok(Err(error)) => return Err(error.into()),
    };
    if job.metadata.uid.as_deref() != Some(identity.job_uid.as_str()) {
        return Ok(JobPresence::Gone);
    }
    Ok(JobPresence::Exact(Box::new(job)))
}

// resourceVersion rejects writes racing a Job controller update.
async fn patch_suspend(
    jobs: &kube::Api<Job>,
    identity: &JobWorkerIdentity,
    resource_version: &str,
    suspend: bool,
    request: Duration,
) -> Result<PatchOutcome, KubeError> {
    let patch = serde_json::json!({
        "metadata": { "resourceVersion": resource_version },
        "spec": { "suspend": suspend },
    });
    let outcome = tokio::time::timeout(
        request,
        jobs.patch(
            &identity.job_name,
            &PatchParams::default(),
            &Patch::Strategic(&patch),
        ),
    )
    .await;
    match outcome {
        Err(_) => Err(KubeError::unavailable("Job suspend patch timed out")),
        Ok(Ok(_)) => Ok(PatchOutcome::Applied),
        Ok(Err(kube::Error::Api(status))) if status.code == 404 => Ok(PatchOutcome::Gone),
        Ok(Err(kube::Error::Api(status))) if status.code == 409 => Ok(PatchOutcome::Conflicted),
        Ok(Err(error)) => Err(error.into()),
    }
}

// Foreground deletion reaps pods; UID and resourceVersion prevent deleting a replacement.
async fn request_delete(
    jobs: &kube::Api<Job>,
    identity: &JobWorkerIdentity,
    resource_version: &str,
    request: Duration,
) -> Result<(), KubeError> {
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(identity.job_uid.clone()),
            resource_version: Some(resource_version.to_owned()),
        }),
        ..DeleteParams::foreground()
    };
    match tokio::time::timeout(request, jobs.delete(&identity.job_name, &params)).await {
        Err(_) => Err(KubeError::unavailable("Job deletion request timed out")),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(kube::Error::Api(status))) if status.code == 404 || status.code == 409 => Ok(()),
        Ok(Err(error)) => Err(error.into()),
    }
}

// Labels are mutable, so find the Job's pods by their owner UID instead.
async fn list_owned_pods(
    pods: &kube::Api<Pod>,
    identity: &JobWorkerIdentity,
    request: Duration,
) -> Result<Vec<JobPodResidue>, KubeError> {
    let mut residue = Vec::new();
    let mut continue_token: Option<String> = None;
    for _ in 0..MAX_POD_PAGES {
        let mut params = ListParams::default().limit(POD_PAGE_LIMIT);
        if let Some(token) = continue_token.as_deref() {
            params = params.continue_token(token);
        }
        let page = match tokio::time::timeout(request, pods.list(&params)).await {
            Err(_) => return Err(KubeError::unavailable("namespace pod inventory timed out")),
            Ok(Ok(page)) => page,
            Ok(Err(error)) => return Err(error.into()),
        };
        residue.extend(
            page.items
                .into_iter()
                .filter_map(|pod| owned_residue(pod, &identity.job_uid)),
        );
        continue_token = page.metadata.continue_.filter(|token| !token.is_empty());
        if continue_token.is_none() {
            return Ok(residue);
        }
    }
    Err(KubeError::unavailable(
        "namespace pod inventory exceeds the residue observation bound",
    ))
}

fn owned_residue(pod: Pod, job_uid: &str) -> Option<JobPodResidue> {
    let owned = pod
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| owner.kind == "Job" && owner.uid == job_uid)
        });
    if !owned {
        return None;
    }
    Some(JobPodResidue {
        name: pod.metadata.name.clone().unwrap_or_default(),
        uid: pod.metadata.uid.clone().unwrap_or_default(),
        phase: pod.status.as_ref().and_then(|status| status.phase.clone()),
    })
}

fn validate_identity(client: &KubeClient, identity: &JobWorkerIdentity) -> Result<(), String> {
    if identity.cluster != client.config.cluster {
        return Err(format!(
            "backend is bound to cluster {:?}; the registered worker names cluster {:?}",
            client.config.cluster, identity.cluster
        ));
    }
    if identity.namespace.trim().is_empty() {
        return Err("registered namespace is empty".to_owned());
    }
    if identity.job_name.trim().is_empty() {
        return Err("registered Job name is empty".to_owned());
    }
    if identity.job_uid.trim().is_empty() {
        return Err("registered Job UID is empty".to_owned());
    }
    Ok(())
}

fn verify_binding(
    job: &Job,
    worker_id: &WorkerId,
    identity: &JobWorkerIdentity,
) -> Result<(), String> {
    let metadata = &job.metadata;
    if metadata.namespace.as_deref() != Some(identity.namespace.as_str()) {
        return Err(format!(
            "Job namespace {:?} is not the registered {:?}",
            metadata.namespace.as_deref().unwrap_or_default(),
            identity.namespace
        ));
    }
    if metadata.name.as_deref() != Some(identity.job_name.as_str()) {
        return Err(format!(
            "Job name {:?} is not the registered {:?}",
            metadata.name.as_deref().unwrap_or_default(),
            identity.job_name
        ));
    }
    let labels = metadata
        .labels
        .as_ref()
        .ok_or_else(|| "registered Job carries no labels".to_owned())?;
    let expected = bounded_label_value(worker_id.as_str());
    if labels.get(JOB_LABEL_WORKER_ID).map(String::as_str) != Some(expected.as_str()) {
        return Err(format!(
            "binding label {JOB_LABEL_WORKER_ID:?} does not bind worker {:?}",
            worker_id.as_str()
        ));
    }
    let encoded = metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(JOB_PROJECTION_ANNOTATION))
        .ok_or_else(|| {
            format!("registered Job carries no {JOB_PROJECTION_ANNOTATION} annotation")
        })?;
    let projection: KubeJobProjection = serde_json::from_str(encoded).map_err(|error| {
        format!("Job projection annotation does not round-trip the domain schema: {error}")
    })?;
    if projection.worker.worker_id != *worker_id {
        return Err("Job projection binds a different worker incarnation".to_owned());
    }
    if projection.identity.uid.as_str() != identity.job_uid {
        return Err("Job projection annotation is bound to a different UID".to_owned());
    }
    Ok(())
}
