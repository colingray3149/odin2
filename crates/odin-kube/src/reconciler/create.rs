//! Create suspended Jobs, register their API identity, then release them.

use std::sync::Arc;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Affinity, Capabilities, Container, EnvVar, EnvVarSource, NodeAffinity, NodeSelector,
    NodeSelectorRequirement, NodeSelectorTerm, PodSecurityContext, PodSpec, PodTemplateSpec,
    ResourceRequirements, SeccompProfile, SecretKeySelector, SecurityContext,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use odin_domain::huginn::{
    KubeJobIdentity, KubeJobLifecycle, KubeJobProjection, KubeResourceVersion, KubeResources,
    KubeUid,
};
use odin_domain::{Digest, RunId};
use odin_kernel::{JobWorkerIdentity, JobWorkerRegistration};
use odin_ledger::worker::JobWorkerPhase;
use odin_types::{CorrelationId, WorkerId};
use serde_json::json;

use super::{JobReconciler, WORKER_RUN_AS_USER};
use crate::artifacts::StagedVolumes;
use crate::client::KubeError;
use crate::job::{
    bounded_label_value, expected_binding_labels, verify_binding_labels, worker_id_label,
    JobLaunch, JobObservation, JOB_PROJECTION_ANNOTATION, KUBE_LABEL_STAGED, KUBE_STAGED_TRUE,
};
use crate::journal::{storage, Progress};

// Installed at the kubelet seccomp root on every fleet node by dotfiles.
const BROWSER_SECCOMP_PROFILE: &str = "odin-workload.json";

const WORKER_CPU_MILLIS: u64 = 2_000;
const WORKER_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const WORKER_EPHEMERAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(crate) const WORKER_RESERVATION: KubeResources = KubeResources {
    cpu_millis: WORKER_CPU_MILLIS,
    memory_bytes: WORKER_MEMORY_BYTES,
    ephemeral_storage_bytes: WORKER_EPHEMERAL_BYTES,
    gpu_count: 0,
};

fn quantity_millis(millis: u64) -> Quantity {
    Quantity(format!("{millis}m"))
}

fn quantity_bytes(bytes: u64) -> Quantity {
    Quantity(bytes.to_string())
}

// GPUs are requested by the worker container only.
fn worker_reservation(launch: &JobLaunch) -> KubeResources {
    KubeResources {
        gpu_count: launch.gpu_count,
        ..WORKER_RESERVATION
    }
}

// Placement must account for both the worker and browser container reservations.
fn launch_reservation(launch: &JobLaunch) -> KubeResources {
    let worker = worker_reservation(launch);
    if !launch
        .workload
        .as_ref()
        .is_some_and(|plan| plan.agent.is_some())
    {
        return worker;
    }
    let browser = WORKER_RESERVATION;
    KubeResources {
        cpu_millis: worker.cpu_millis + browser.cpu_millis,
        memory_bytes: worker.memory_bytes + browser.memory_bytes,
        ephemeral_storage_bytes: worker.ephemeral_storage_bytes + browser.ephemeral_storage_bytes,
        gpu_count: worker.gpu_count,
    }
}

pub(crate) fn bounded_resources(reservation: KubeResources) -> ResourceRequirements {
    let mut requests: std::collections::BTreeMap<String, Quantity> = [
        ("cpu".to_owned(), quantity_millis(reservation.cpu_millis)),
        (
            "memory".to_owned(),
            quantity_bytes(reservation.memory_bytes),
        ),
        (
            "ephemeral-storage".to_owned(),
            quantity_bytes(reservation.ephemeral_storage_bytes),
        ),
    ]
    .into_iter()
    .collect();
    if reservation.gpu_count > 0 {
        // The scheduler allocates GPUs through the device-plugin resource name.
        requests.insert(
            "nvidia.com/gpu".to_owned(),
            Quantity(reservation.gpu_count.to_string()),
        );
    }
    ResourceRequirements {
        limits: Some(requests.clone()),
        requests: Some(requests),
        ..Default::default()
    }
}

/// Shared security settings for Job containers and state-carry helpers.
pub(crate) fn worker_security() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_owned()]),
            add: None,
        }),
        run_as_non_root: Some(true),
        ..Default::default()
    }
}

pub(crate) fn worker_pod_security() -> PodSecurityContext {
    PodSecurityContext {
        run_as_non_root: Some(true),
        run_as_user: Some(WORKER_RUN_AS_USER),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_owned(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// Chromium needs clone/unshare for its user-namespace sandbox; RuntimeDefault blocks them.
// The fleet profile permits them without enabling the setuid helper.
fn browser_security() -> SecurityContext {
    let mut confined = worker_security();
    confined.seccomp_profile = Some(SeccompProfile {
        type_: "Localhost".to_owned(),
        localhost_profile: Some(BROWSER_SECCOMP_PROFILE.to_owned()),
    });
    confined
}

/// In-place restarts a service pod gets before its Job fails for good.
const SERVICE_BACKOFF_LIMIT: i32 = 100;

// Publish suspended so the API identity can be registered before the worker starts.
pub(super) fn build_suspended_job(
    launch: &JobLaunch,
    staged: &StagedVolumes,
    node: &str,
) -> Result<Job, KubeError> {
    launch
        .validate()
        .map_err(|reason| KubeError::Rejected { reason })?;
    let mut labels = launch.binding_label_map();
    // Staging publishes and verifies ConfigMaps before this template references them.
    labels.insert(KUBE_LABEL_STAGED.to_owned(), KUBE_STAGED_TRUE.to_owned());
    if let Some(plan) = &launch.workload {
        labels.insert(
            crate::workload::WORKLOAD_LABEL.to_owned(),
            bounded_label_value(&plan.profile),
        );
    }
    // Pod templates are immutable, so worker IDs belong only on Job metadata.
    // Pod watches use run/task labels and owner UID across worker replacements.
    let incarnation_key = worker_id_label(&launch.worker_id).0;
    let template_labels: std::collections::BTreeMap<_, _> = labels
        .iter()
        .filter(|(key, _)| key != &incarnation_key)
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let mut volumes = staged.volumes.clone();
    let mut mounts = staged.mounts.clone();
    if let Some(plan) = &launch.workload {
        crate::workload::inject_pod_volumes(plan, &launch.labels.run_id, &mut volumes, &mut mounts);
    }
    let mut env = Vec::new();
    if let Some(plan) = &launch.workload {
        env.push(EnvVar {
            name: "HOME".to_owned(),
            // Default to the state mount so the agent home survives restart and rehome.
            value: Some(plan.home().to_owned()),
            value_from: None,
        });
        // Kubernetes injects credentials from a Secret; staged config contains only the env name.
        if let Some(agent) = &plan.agent {
            env.push(EnvVar {
                name: agent.credential.env_name.clone(),
                value: None,
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: agent.credential.secret.clone(),
                        key: agent.credential.key.clone(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
            });
        }
    }
    let container = Container {
        name: crate::job::JOB_WORKER_CONTAINER.to_owned(),
        image: Some(launch.image.clone()),
        command: Some(
            launch
                .command
                .iter()
                .map(|arg| crate::job::shell_argv_channel_encoding(arg))
                .collect(),
        ),
        args: Some(
            launch
                .args
                .iter()
                .map(|arg| crate::job::shell_argv_channel_encoding(arg))
                .collect(),
        ),
        env: (!env.is_empty()).then_some(env),
        volume_mounts: Some(mounts),
        resources: Some(bounded_resources(worker_reservation(launch))),
        security_context: Some(worker_security()),
        ..Default::default()
    };
    let containers = vec![container];
    let mut init_containers = Vec::new();
    if let Some((plan, browser_command)) = launch
        .workload
        .as_ref()
        .and_then(|plan| Some((plan, plan.browser_command()?)))
    {
        // A native sidecar stops when the worker exits, allowing the Job to complete.
        // It receives no worker environment; image-defined ENV still applies.
        volumes.push(crate::workload::WorkloadPodPlan::browser_socket_volume());
        init_containers.push(Container {
            name: crate::workload::BROWSER_CONTAINER.to_owned(),
            restart_policy: Some("Always".to_owned()),
            image: Some(launch.image.clone()),
            command: Some(
                browser_command
                    .iter()
                    .map(|arg| crate::job::shell_argv_channel_encoding(arg))
                    .collect(),
            ),
            args: None,
            env: None,
            volume_mounts: Some(plan.browser_volume_mounts()),
            resources: Some(bounded_resources(WORKER_RESERVATION)),
            security_context: Some(browser_security()),
            ..Default::default()
        });
    }
    let spec = PodSpec {
        // A service restarts its worker in place on failure; a job never
        // restarts (its terminal state is the result).
        restart_policy: Some(if launch.service { "OnFailure" } else { "Never" }.to_owned()),
        // Keep the browser supervisor's process tree separate from the worker's.
        share_process_namespace: Some(false),
        automount_service_account_token: Some(false),
        containers,
        init_containers: (!init_containers.is_empty()).then_some(init_containers),
        volumes: Some(volumes),
        security_context: Some(worker_pod_security()),
        node_selector: (!launch.node_selector.is_empty()).then(|| launch.node_selector.clone()),
        // Use node affinity, not node_name, so scheduler resource checks still apply.
        affinity: Some(Affinity {
            node_affinity: Some(NodeAffinity {
                required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                    node_selector_terms: vec![NodeSelectorTerm {
                        match_fields: Some(vec![NodeSelectorRequirement {
                            key: "metadata.name".to_owned(),
                            operator: "In".to_owned(),
                            values: Some(vec![node.to_owned()]),
                        }]),
                        ..Default::default()
                    }],
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    Ok(Job {
        metadata: ObjectMeta {
            name: Some(launch.job_name()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(JobSpec {
            suspend: Some(true),
            // Cap service restarts while allowing Kubernetes to back off between failures.
            backoff_limit: Some(if launch.service {
                SERVICE_BACKOFF_LIMIT
            } else {
                0
            }),
            active_deadline_seconds: launch.deadline_seconds.map(i64::from),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(template_labels),
                    ..Default::default()
                }),
                spec: Some(spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

// Stable across replays so worker registration is idempotent.
// CorrelationId requires lowercase hex without the digest's `blake3:` prefix.
fn job_worker_correlation(run: &RunId) -> Result<CorrelationId, KubeError> {
    let serialized =
        Digest::hash(format!("odin.kube.job-worker:{}", run.as_str()).as_bytes()).to_string();
    let hex = serialized
        .strip_prefix("blake3:")
        .ok_or_else(|| storage("domain digest serialization carries no blake3: prefix"))?;
    CorrelationId::new(&hex[..32]).map_err(|error| storage(error.to_string()))
}

impl JobReconciler {
    pub(super) async fn create_job(
        &self,
        launch: &JobLaunch,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<JobObservation, KubeError> {
        self.create_job_on(
            launch,
            launch.initial_target_node.as_deref(),
            operation,
            progress,
        )
        .await
    }

    // Restart uses its supplied target, including None, rather than inheriting the initial target.
    pub(super) async fn create_job_on(
        &self,
        launch: &JobLaunch,
        target: Option<&str>,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<JobObservation, KubeError> {
        // Reject conflicting run definitions before staging or API writes.
        self.journal.save_launch(launch)?;
        let name = launch.job_name();
        let job = match self.get_job(&name).await? {
            Some(job) => job,
            None => {
                crate::placement::require_placement_authority(
                    &self.client.config.allowed_nodes,
                    target,
                )?;
                // Refused launch content and a refused egress host both settle
                // before any PVC, policy, ConfigMap, or Job write.
                launch
                    .validate()
                    .map_err(|reason| KubeError::Rejected { reason })?;
                let prepared = self.artifacts.prepare_stage(
                    &launch.labels,
                    &launch.staging,
                    launch.checkpoint.as_ref(),
                )?;

                // Hosts resolve before the claim exists, so a refusal leaves
                // no volume. The claim is created next, then the resolved policy.
                if let Some(plan) = &launch.workload {
                    let resolved = crate::workload::resolve_declared_hosts(plan).await?;
                    crate::workload::ensure_state_claim(&self.client, &launch.labels.run_id, plan)
                        .await?;
                    crate::workload::ensure_resolved_egress_policy(
                        &self.client,
                        &launch.labels.run_id,
                        &resolved,
                    )
                    .await?;
                    if let Some(target) = target {
                        crate::workload::verify_state_admits_node(
                            &self.client,
                            &launch.labels.run_id,
                            plan,
                            target,
                        )
                        .await?;
                    }
                }
                // The Job template is immutable, so publish its mounted files first.
                let staged = self.artifacts.stage(&self.client, &name, prepared).await?;
                self.journal
                    .save_staged_paths(&launch.labels.run_id, &staged.staged_paths)?;
                let node = crate::placement::choose_node(
                    &self.client,
                    &launch.node_selector,
                    launch_reservation(launch),
                    target,
                )
                .await?;
                let desired = build_suspended_job(launch, &staged, &node)?;
                match self.create_job_object(&desired).await {
                    Ok(job) => job,
                    // A replayed or concurrent create won the race; resume
                    // from the observable object instead of failing.
                    Err(KubeError::Conflict { .. }) => {
                        self.get_job(&name)
                            .await?
                            .ok_or_else(|| KubeError::Conflict {
                                reason: "Job creation raced an existing object that is now gone"
                                    .to_owned(),
                            })?
                    }
                    Err(error) => return Err(error),
                }
            }
        };
        self.bind_worker(&job, launch, operation).await?;
        if progress.prior.is_none() {
            let bound = self
                .get_job(&name)
                .await?
                .ok_or_else(|| KubeError::unavailable("bound Job disappeared before release"))?;
            progress.prior = Some(self.owned_observation(&bound)?);
            self.journal.progress(operation, progress)?;
        }
        self.release_worker(&launch.worker_id).await?;
        let live = self
            .get_job(&name)
            .await?
            .ok_or_else(|| KubeError::rejected("released Job disappeared from the API"))?;
        self.owned_observation(&live)
    }

    async fn create_job_object(&self, desired: &Job) -> Result<Job, KubeError> {
        let result = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().create(&PostParams::default(), desired),
        )
        .await
        .map_err(|_| KubeError::unavailable("Job create timed out"))?;
        match result {
            Err(kube::Error::Api(error)) if error.code == 409 => Err(KubeError::Conflict {
                reason: "Job already exists".to_owned(),
            }),
            other => other.map_err(Into::into),
        }
    }

    // Register the API UID before release; only stopped workers may be replaced.
    pub(super) async fn bind_worker(
        &self,
        job: &Job,
        launch: &JobLaunch,
        operation: &str,
    ) -> Result<(), KubeError> {
        let name = launch.job_name();
        // The ten run-identity labels must match exactly; only the worker
        // incarnation label may legitimately differ before a rebind.
        let incarnation = worker_id_label(&launch.worker_id);
        let identity_labels: Vec<(&'static str, String)> =
            expected_binding_labels(&launch.labels, &launch.worker_id)
                .into_iter()
                .filter(|(key, _)| *key != incarnation.0)
                .collect();
        verify_binding_labels(
            job.metadata
                .labels
                .as_ref()
                .ok_or_else(|| KubeError::rejected("Job carries no binding labels"))?,
            &identity_labels,
        )
        .map_err(|reason| KubeError::Rejected { reason })?;
        let uid = job
            .metadata
            .uid
            .clone()
            .ok_or_else(|| KubeError::rejected("Job has no API UID"))?;
        let resource_version = job
            .metadata
            .resource_version
            .clone()
            .ok_or_else(|| KubeError::rejected("Job has no resourceVersion"))?;
        let annotation = bound_projection(job)?;
        let prior = annotation
            .as_ref()
            .map(|projection| &projection.worker.worker_id);
        match prior {
            Some(bound) if *bound == launch.worker_id => {}
            Some(bound) => {
                if self.worker_phase(bound)? != Some(JobWorkerPhase::Stopped) {
                    return Err(KubeError::rejected(format!(
                        "prior worker incarnation {} has not settled as stopped; a fresh incarnation cannot adopt the Job",
                        bound.as_str()
                    )));
                }
            }
            None => {
                let labeled = job
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|values| values.get(incarnation.0));
                if labeled.is_some_and(|value| *value != incarnation.1) {
                    return Err(KubeError::rejected(
                        "Job carries a foreign worker incarnation label with no projection record",
                    ));
                }
            }
        }
        let identity = JobWorkerIdentity {
            cluster: self.client.config.cluster.clone(),
            namespace: self.client.config.namespace.clone(),
            job_name: name.clone(),
            job_uid: uid.clone(),
        };
        let correlation = job_worker_correlation(&launch.labels.run_id)?;
        self.stops
            .register_job_worker(JobWorkerRegistration {
                worker_id: &launch.worker_id,
                identity: &identity,
                correlation_id: &correlation,
                operation_id: operation,
            })
            .map_err(storage)?;
        if prior.is_some_and(|bound| *bound == launch.worker_id) {
            return Ok(());
        }
        // UID guards the metadata apply without racing the controller's status writes.
        let projection = launch.projection(
            KubeJobIdentity {
                uid: KubeUid::new(uid.clone()).map_err(|error| storage(error.to_string()))?,
                resource_version: KubeResourceVersion::new(resource_version)
                    .map_err(|error| storage(error.to_string()))?,
            },
            KubeJobLifecycle::Paused,
            None,
        );
        let payload = serde_json::to_string(&projection).map_err(storage)?;
        let claim = json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": name,
                "uid": uid,
                "labels": { incarnation.0: incarnation.1 },
                "annotations": { JOB_PROJECTION_ANNOTATION: payload },
            }
        });
        self.apply_job(&name, claim).await.map(drop)
    }

    fn worker_phase(&self, worker_id: &WorkerId) -> Result<Option<JobWorkerPhase>, KubeError> {
        Ok(self
            .stops
            .job_worker_status(worker_id)
            .map_err(storage)?
            .map(|(_, phase)| phase))
    }

    pub(super) async fn release_worker(&self, worker_id: &WorkerId) -> Result<(), KubeError> {
        if self.worker_phase(worker_id)? == Some(JobWorkerPhase::Released) {
            return Ok(());
        }
        let stops = Arc::clone(&self.stops);
        let worker = worker_id.clone();
        tokio::task::spawn_blocking(move || stops.release_job_worker(&worker))
            .await
            .map_err(|error| storage(error.to_string()))?
            .map_err(storage)?;
        Ok(())
    }
}

fn bound_projection(job: &Job) -> Result<Option<KubeJobProjection>, KubeError> {
    job.metadata
        .annotations
        .as_ref()
        .and_then(|values| values.get(JOB_PROJECTION_ANNOTATION))
        .map(|payload| {
            serde_json::from_str::<KubeJobProjection>(payload).map_err(|error| {
                KubeError::rejected(format!(
                    "Job carries an unreadable projection record: {error}"
                ))
            })
        })
        .transpose()
}

#[cfg(test)]
mod binding_record_tests {
    use super::*;

    #[test]
    fn an_unreadable_binding_record_is_rejected_not_absent() {
        let mut job = Job::default();
        assert!(bound_projection(&job).expect("no record").is_none());
        job.metadata.annotations = Some(
            [(JOB_PROJECTION_ANNOTATION.to_owned(), "{corrupt".to_owned())]
                .into_iter()
                .collect(),
        );
        let error = bound_projection(&job).expect_err("a corrupt record cannot read as no prior");
        assert!(matches!(error, KubeError::Rejected { .. }), "{error}");
    }
}

#[cfg(test)]
mod job_worker_correlation_tests {
    use odin_domain::RunId;
    use odin_types::ids::CORRELATION_ID_HEX_LEN;

    use super::job_worker_correlation;

    #[test]
    fn correlation_is_the_digest_body_not_the_prefixed_serialization() {
        let run = RunId::new("run-correlation-regression").expect("valid run id");

        let correlation =
            job_worker_correlation(&run).expect("the digest body is valid correlation hex");
        assert_eq!(
            correlation.as_str().len(),
            CORRELATION_ID_HEX_LEN,
            "the correlation is a fixed-length hex token"
        );
        assert!(
            correlation
                .as_str()
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "the correlation is 32 lowercase hex digits: {correlation}"
        );

        // Replays must reuse the correlation for idempotent worker registration.
        let replayed =
            job_worker_correlation(&run).expect("the digest body is valid correlation hex");
        assert_eq!(replayed, correlation);
    }
}

#[cfg(test)]
mod launch_shape_tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::core::v1::{ConfigMap, Volume, VolumeMount};
    use odin_domain::huginn::{KubeJobLabels, KubeStagingProjection};
    use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
    use odin_types::{OperationId, WorkerId};

    use super::{
        build_suspended_job, launch_reservation, StagedVolumes, WORKER_CPU_MILLIS,
        WORKER_MEMORY_BYTES,
    };
    use crate::job::JobLaunch;
    use odin_domain::huginn::KubeResources;

    fn launch(gpu_count: u32, deadline_seconds: Option<u32>) -> JobLaunch {
        JobLaunch {
            labels: KubeJobLabels {
                task_id: TaskId::new("run-launch-shape-task").expect("task id"),
                run_id: RunId::new("run-launch-shape").expect("run id"),
                attempt_id: AttemptId::new("run-launch-shape-attempt").expect("attempt id"),
                seat_id: SeatId::new("kubert").expect("seat id"),
                project_id: ProjectId::new("odin").expect("project id"),
                lane_id: LaneId::new("launch-shape-tests").expect("lane id"),
                model: "launch-shape-model".to_owned(),
                budget_policy_digest: Digest::hash(b"launch-shape-budget"),
                container_identity: Digest::hash(b"launch-shape-image"),
            },
            worker_id: WorkerId::new("worker-launch-shape").expect("worker id"),
            staging: KubeStagingProjection {
                inputs: Vec::new(),
                resumed_from: None,
            },
            checkpoint: None,
            image: "nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0-ubuntu22.04".to_owned(),
            command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
            args: vec!["'/cuda-samples/sample'".to_owned()],
            node_selector: BTreeMap::new(),
            initial_target_node: None,
            gpu_count,
            deadline_seconds,
            service: false,
            workload: None,
            extension: None,
            models_config: None,
            operation_id: OperationId::new("op-launch-shape").expect("operation id"),
            idempotency_digest: Digest::hash(b"launch-shape"),
        }
    }

    fn workload_plan() -> crate::workload::WorkloadPodPlan {
        let plan = crate::workload::WorkloadPodPlan {
            profile: "browser-container-fixture".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            allow_hosts: vec![],
            agent: Some(crate::workload::WorkloadAgentPlan {
                launcher: "/odin/bin/omp-launch".to_owned(),
                gateway: crate::workload::WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 14000,
                },
                browser: "/odin/bin/chromium".to_owned(),
                supervisor: "/odin/bin/odind".to_owned(),
                playwright: "/odin/lib/playwright-core".to_owned(),
                browser_node: "/odin/bin/node".to_owned(),
                browser_engine: odin_registry::BrowserEngine::default(),
                display: crate::workload::WorkloadDisplayPlan {
                    xvfb: "/odin/bin/Xvfb".to_owned(),
                    screen: "1280x800x24".to_owned(),
                    stream: true,
                },
                home_dir: None,
                credential: crate::workload::WorkloadCredentialEnv {
                    env_name: "ODIN_GATEWAY_KEY".to_owned(),
                    secret: "gateway-secret".to_owned(),
                    key: "master".to_owned(),
                },
            }),
        };
        plan.validate().expect("declared workload plan");
        plan
    }

    fn staged() -> StagedVolumes {
        StagedVolumes {
            volumes: Vec::<Volume>::new(),
            mounts: Vec::<VolumeMount>::new(),
            configmaps: Vec::<ConfigMap>::new(),
            staged_paths: std::collections::BTreeMap::new(),
        }
    }

    fn requests(
        job: &k8s_openapi::api::batch::v1::Job,
    ) -> &std::collections::BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>
    {
        job.spec
            .as_ref()
            .expect("job spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec")
            .containers[0]
            .resources
            .as_ref()
            .expect("bounded resources")
            .requests
            .as_ref()
            .expect("requests map")
    }

    #[test]
    fn workload_pods_run_the_dedicated_browser_container_with_the_served_argv() {
        let mut launch = launch(0, None);
        launch.staging.inputs = vec![crate::job::KubeContentIdentity {
            artifact_id: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            content_digest: odin_domain::Digest::hash(b"staging-models-bytes"),
            byte_len: 128,
        }];
        launch.models_config = Some(crate::job::JobModelsConfigLaunch {
            config_artifact: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            config_digest: odin_domain::Digest::hash(b"staging-models-bytes").to_string(),
            credential_env: "ODIN_GATEWAY_KEY".to_owned(),
        });
        launch.workload = Some(workload_plan());
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let spec = job
            .spec
            .as_ref()
            .expect("job spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec");
        assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
        assert_eq!(spec.share_process_namespace, Some(false));
        assert_eq!(spec.automount_service_account_token, Some(false));
        assert_eq!(
            spec.containers.len(),
            1,
            "the worker is the one main container"
        );
        let init = spec.init_containers.as_ref().expect("init containers");
        assert_eq!(init.len(), 1, "the dedicated browser sidecar");
        let browser = init
            .iter()
            .find(|container| container.name == crate::workload::BROWSER_CONTAINER)
            .expect("the dedicated browser container");
        // The kubelet stops a native sidecar when the worker exits so the Job can complete.
        assert_eq!(browser.restart_policy.as_deref(), Some("Always"));
        assert_eq!(browser.image.as_deref(), Some(launch.image.as_str()));
        assert_eq!(
            browser.command.as_ref().expect("browser command"),
            &[
                "/odin/bin/odind",
                "browser-serve",
                "--node",
                "/odin/bin/node",
                "--xvfb",
                "/odin/bin/Xvfb",
                "--screen",
                "1280x800x24",
                "--state-dir",
                "/state/browser",
                "--socket",
                "/run/odin-browser/relay.sock",
            ]
        );
        assert_eq!(browser.args, None);
        // Do not pass the worker's HOME or credentials to the browser container.
        assert_eq!(browser.env, None);
        let mounts = browser.volume_mounts.as_ref().expect("browser mounts");
        assert_eq!(mounts.len(), 2, "state volume plus private socket only");
        assert_eq!(mounts[0].name, crate::workload::WORKLOAD_STATE_VOLUME);
        assert_eq!(mounts[0].mount_path, "/state");
        assert_eq!(mounts[1].name, crate::workload::BROWSER_SOCKET_VOLUME);
        assert_eq!(mounts[1].mount_path, crate::workload::BROWSER_SOCKET_DIR);
        let volumes = spec.volumes.as_ref().expect("volumes");
        assert!(volumes.iter().any(
            |volume| volume.name == crate::workload::BROWSER_SOCKET_VOLUME
                && volume.empty_dir.is_some()
        ));
        // The worker container must NOT mount the private socket volume.
        let worker = spec
            .containers
            .iter()
            .find(|container| container.name == crate::job::JOB_WORKER_CONTAINER)
            .expect("the worker container");
        assert!(worker
            .volume_mounts
            .as_ref()
            .expect("worker mounts")
            .iter()
            .all(|mount| mount.name != crate::workload::BROWSER_SOCKET_VOLUME));
    }

    #[test]
    fn the_browser_container_runs_under_the_fleet_browser_seccomp_profile() {
        let mut launch = launch(0, None);
        launch.staging.inputs = vec![crate::job::KubeContentIdentity {
            artifact_id: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            content_digest: odin_domain::Digest::hash(b"staging-models-bytes"),
            byte_len: 128,
        }];
        launch.models_config = Some(crate::job::JobModelsConfigLaunch {
            config_artifact: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            config_digest: odin_domain::Digest::hash(b"staging-models-bytes").to_string(),
            credential_env: "ODIN_GATEWAY_KEY".to_owned(),
        });
        launch.workload = Some(workload_plan());
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let spec = job
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .expect("pod spec");
        let profile = |name: &str| {
            spec.containers
                .iter()
                .chain(spec.init_containers.iter().flatten())
                .find(|container| container.name == name)
                .and_then(|container| container.security_context.as_ref())
                .and_then(|context| context.seccomp_profile.clone())
        };
        let browser = profile(crate::workload::BROWSER_CONTAINER).expect("browser profile");
        assert_eq!(browser.type_, "Localhost");
        assert_eq!(
            browser.localhost_profile.as_deref(),
            Some("odin-workload.json")
        );
        // The worker keeps the pod's RuntimeDefault.
        assert_eq!(profile(&spec.containers[0].name), None);
    }

    #[test]
    fn browser_container_reservation_is_bounded_and_accounted_once() {
        let mut launch = launch(0, None);
        launch.staging.inputs = vec![crate::job::KubeContentIdentity {
            artifact_id: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            content_digest: odin_domain::Digest::hash(b"staging-models-bytes"),
            byte_len: 128,
        }];
        launch.models_config = Some(crate::job::JobModelsConfigLaunch {
            config_artifact: odin_domain::ArtifactId::new("staging-models-browser-fixture")
                .expect("artifact id"),
            config_digest: odin_domain::Digest::hash(b"staging-models-bytes").to_string(),
            credential_env: "ODIN_GATEWAY_KEY".to_owned(),
        });
        launch.workload = Some(workload_plan());
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let spec = job
            .spec
            .as_ref()
            .expect("job spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec");
        let total = launch_reservation(&launch);
        let mut summed = KubeResources::default();
        // The scheduler counts native sidecar requests for the entire pod lifetime.
        for container in spec
            .containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
        {
            let resources = container.resources.as_ref().expect("bounded resources");
            let requests = resources.requests.as_ref().expect("requests map");
            let cpu = requests.get("cpu").expect("cpu").0.clone();
            let millis: u64 = cpu
                .strip_suffix('m')
                .and_then(|value| value.parse().ok())
                .expect("cpu millis quantity");
            summed.cpu_millis += millis;
            let memory = requests.get("memory").expect("memory").0.clone();
            summed.memory_bytes += memory.parse::<u64>().expect("memory bytes");
            let storage = requests
                .get("ephemeral-storage")
                .expect("ephemeral")
                .0
                .clone();
            summed.ephemeral_storage_bytes += storage.parse::<u64>().expect("storage bytes");
        }
        assert_eq!(
            summed.cpu_millis, total.cpu_millis,
            "per-container cpu sums to the placement-advertised total"
        );
        assert_eq!(
            summed.memory_bytes, total.memory_bytes,
            "per-container memory sums to the placement-advertised total"
        );
        assert_eq!(
            summed.ephemeral_storage_bytes, total.ephemeral_storage_bytes,
            "per-container ephemeral storage sums to the advertised total"
        );
        assert!(
            total.cpu_millis > WORKER_CPU_MILLIS && total.memory_bytes > WORKER_MEMORY_BYTES,
            "the browser container adds accounted reservation beyond the worker"
        );
    }

    #[test]
    fn container_profile_launches_keep_the_worker_only_pod_shape() {
        let launch = launch(0, None);
        assert!(launch.workload.is_none());
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let spec = job
            .spec
            .as_ref()
            .expect("job spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec");
        assert_eq!(spec.containers.len(), 1);
        assert_eq!(spec.containers[0].name, crate::job::JOB_WORKER_CONTAINER);
        assert_eq!(spec.share_process_namespace, Some(false));
    }

    #[test]
    fn gpu_reservation_rides_requests_limits_and_the_deadline() {
        let launch = launch(1, Some(300));
        assert_eq!(launch_reservation(&launch).gpu_count, 1);
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let requests = requests(&job);
        assert_eq!(
            requests
                .get("nvidia.com/gpu")
                .map(|quantity| quantity.0.as_str()),
            Some("1"),
            "the GPU reservation must appear as an explicit scheduler request"
        );
        let limits = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
            .resources
            .as_ref()
            .unwrap()
            .limits
            .as_ref()
            .unwrap();
        assert_eq!(
            limits
                .get("nvidia.com/gpu")
                .map(|quantity| quantity.0.as_str()),
            Some("1"),
            "requests == limits keeps the reservation bounded"
        );
        assert_eq!(
            job.spec.as_ref().unwrap().active_deadline_seconds,
            Some(300),
            "the declared wall-clock ceiling rides the Job spec"
        );
    }

    #[test]
    fn gpu_free_launch_keeps_the_historical_shape() {
        let launch = launch(0, None);
        assert_eq!(launch_reservation(&launch).gpu_count, 0);
        let job = build_suspended_job(&launch, &staged(), "mini").expect("suspended job");
        let requests = requests(&job);
        assert!(
            !requests.contains_key("nvidia.com/gpu"),
            "a GPU-free launch never requests devices"
        );
        for key in ["cpu", "memory", "ephemeral-storage"] {
            assert!(requests.contains_key(key), "the fixed ceiling stays: {key}");
        }
        assert_eq!(
            job.spec.as_ref().unwrap().active_deadline_seconds,
            None,
            "an undeclared deadline stays unset"
        );
    }

    // Matches Kubernetes third_party/forked/golang/expansion/expand.go.
    // Decode $$ and known $(name) references; preserve unknown names and other dollar forms.
    fn kubelet_channel_decode(
        input: &str,
        mapping: &BTreeMap<&'static str, &'static str>,
    ) -> String {
        let operator = '$';
        let chars: Vec<char> = input.chars().collect();
        let mut out = String::new();
        let mut cursor = 0;
        while cursor < chars.len() {
            if chars[cursor] == operator && cursor + 1 < chars.len() {
                let next = chars[cursor + 1];
                if next == operator {
                    out.push(operator);
                    cursor += 2;
                    continue;
                }
                if next == '(' {
                    if let Some(close) = chars[cursor + 2..].iter().position(|&c| c == ')') {
                        let name: String = chars[cursor + 2..cursor + 2 + close].iter().collect();
                        match mapping.get(name.as_str()) {
                            Some(value) => out.push_str(value),
                            None => out.push_str(&format!("{operator}({name})")),
                        }
                        cursor += 3 + close;
                        continue;
                    }
                    out.push(operator);
                    out.push('(');
                    cursor += 2;
                    continue;
                }
                out.push(operator);
                out.push(next);
                cursor += 2;
                continue;
            }
            out.push(chars[cursor]);
            cursor += 1;
        }
        out
    }

    #[test]
    fn the_shared_projection_delivers_declared_argv_bytes_and_keeps_intentional_expansion() {
        // Create and restart both encode argv through build_suspended_job.
        let mut launch = launch(0, None);
        launch.args = vec![
            "report $$ literal bytes".to_owned(),
            "$(HOME) turn".to_owned(),
            "$(ODIN_UNDEFINED) stay".to_owned(),
            "$PATH ${X} $?".to_owned(),
        ];
        let job = build_suspended_job(&launch, &staged(), "pc").expect("suspended job");
        let container = &job
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0];
        // Escape literal $$ without changing intentional expansion forms.
        assert_eq!(
            container.command,
            Some(vec!["/bin/sh".to_owned(), "-c".to_owned()])
        );
        assert_eq!(
            container.args,
            Some(vec![
                "report $$$$ literal bytes".to_owned(),
                "$(HOME) turn".to_owned(),
                "$(ODIN_UNDEFINED) stay".to_owned(),
                "$PATH ${X} $?".to_owned(),
            ]),
            "the projection encodes only the collapsed $$ pair"
        );
        // Kubelet expansion must preserve literal dollars while substituting known env names.
        let pod_env = BTreeMap::from([("HOME", "/state")]);
        let delivered: Vec<String> = container
            .args
            .as_ref()
            .unwrap()
            .iter()
            .map(|arg| kubelet_channel_decode(arg, &pod_env))
            .collect();
        assert_eq!(
            delivered,
            vec![
                "report $$ literal bytes".to_owned(),
                "/state turn".to_owned(),
                "$(ODIN_UNDEFINED) stay".to_owned(),
                "$PATH ${X} $?".to_owned(),
            ],
            "the container must receive the declared argv bytes; intentional \
             env substitution must survive the channel"
        );
    }

    // Only the Kubernetes API is simulated; placement, journaling, and lifecycle paths are real.
    #[derive(Default)]
    struct PlacementApiState {
        objects: BTreeMap<String, serde_json::Value>,
        requests: Vec<(String, String)>,
        created_jobs: Vec<serde_json::Value>,
        nodes: Vec<serde_json::Value>,
        revision: u64,
    }

    struct PlacementApi {
        port: u16,
        state: std::sync::Arc<std::sync::Mutex<PlacementApiState>>,
        stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    fn placement_node(name: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1", "kind": "Node",
            "metadata": {"name": name, "uid": format!("node-{name}"),
                "labels": {"odin.capability/portable": "true"}},
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "allocatable": {"cpu": "16", "memory": "32Gi",
                    "ephemeral-storage": "64Gi", "pods": "100"}
            }
        })
    }

    fn merge_api_object(value: &mut serde_json::Value, patch: serde_json::Value) {
        match (value, patch) {
            (serde_json::Value::Object(value), serde_json::Value::Object(patch)) => {
                for (key, field) in patch {
                    merge_api_object(value.entry(key).or_insert(serde_json::Value::Null), field);
                }
            }
            (value, patch) => *value = patch,
        }
    }

    impl PlacementApiState {
        fn respond(
            &mut self,
            method: &str,
            path: &str,
            query: &str,
            body: serde_json::Value,
        ) -> (u16, serde_json::Value) {
            use serde_json::json;
            self.requests.push((method.to_owned(), path.to_owned()));
            if method == "GET" && path == "/api/v1/nodes" {
                return (
                    200,
                    json!({"apiVersion":"v1", "kind":"NodeList", "items":self.nodes}),
                );
            }
            if method == "GET" && path.starts_with("/api/v1/nodes/") {
                if let Some(node) = self
                    .nodes
                    .iter()
                    .find(|node| node["metadata"]["name"].as_str() == path.rsplit('/').next())
                {
                    return (200, node.clone());
                }
            }
            if method == "GET" && path.ends_with("/pods") {
                return (
                    200,
                    json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                );
            }
            if method == "POST" {
                let mut object = body;
                let name = object["metadata"]["name"]
                    .as_str()
                    .expect("object name")
                    .to_owned();
                let key = format!("{path}/{name}");
                if self.objects.contains_key(&key) {
                    return (
                        409,
                        json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
                        "reason":"AlreadyExists", "message":"fixture object exists", "code":409}),
                    );
                }
                self.revision += 1;
                object["metadata"]["uid"] = json!(format!("uid-{}", self.revision));
                object["metadata"]["resourceVersion"] = json!(self.revision.to_string());
                object["metadata"]["namespace"] = json!("default");
                if path.ends_with("/jobs") {
                    self.created_jobs.push(object.clone());
                }
                self.objects.insert(key, object.clone());
                return (201, object);
            }
            if method == "PATCH" {
                let object = self.objects.get_mut(path).expect("patch existing object");
                if let Some(version) = body["metadata"]["resourceVersion"].as_str() {
                    assert_eq!(
                        object["metadata"]["resourceVersion"], version,
                        "CAS version"
                    );
                }
                if let Some(uid) = body["metadata"]["uid"].as_str() {
                    assert_eq!(object["metadata"]["uid"], uid, "UID precondition");
                }
                merge_api_object(object, body);
                self.revision += 1;
                object["metadata"]["resourceVersion"] = json!(self.revision.to_string());
                return (200, object.clone());
            }
            if method == "DELETE" {
                let Some(object) = self.objects.remove(path) else {
                    return (
                        404,
                        json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
                        "reason":"NotFound", "message":"fixture object absent", "code":404}),
                    );
                };
                if let Some(uid) = body["preconditions"]["uid"].as_str() {
                    assert_eq!(uid, object["metadata"]["uid"].as_str().unwrap_or(""));
                }
                if let Some(version) = body["preconditions"]["resourceVersion"].as_str() {
                    assert_eq!(
                        version,
                        object["metadata"]["resourceVersion"].as_str().unwrap_or("")
                    );
                }
                return (200, object);
            }
            if method == "GET" && collection_path(path) {
                let items: Vec<_> = self
                    .objects
                    .iter()
                    .filter(|(key, _)| key.starts_with(&format!("{path}/")))
                    .map(|(_, object)| object.clone())
                    .filter(|object| selector_matches(query, object))
                    .collect();
                let kind = match path.rsplit('/').next().unwrap_or("List") {
                    "jobs" => "JobList",
                    "persistentvolumeclaims" => "PersistentVolumeClaimList",
                    "networkpolicies" => "NetworkPolicyList",
                    "configmaps" => "ConfigMapList",
                    "pods" => "PodList",
                    other => other,
                };
                return (
                    200,
                    json!({"apiVersion":"v1", "kind": kind, "items": items}),
                );
            }
            if let Some(object) = self.objects.get(path) {
                assert_eq!(method, "GET");
                return (200, object.clone());
            }
            assert_eq!(method, "GET", "unhandled API effect {method} {path}");
            (
                404,
                json!({"apiVersion":"v1", "kind":"Status", "status":"Failure",
                "reason":"NotFound", "message":"fixture object absent", "code":404}),
            )
        }
    }

    fn collection_path(path: &str) -> bool {
        matches!(
            path.rsplit('/').next(),
            Some(
                "jobs"
                    | "pods"
                    | "persistentvolumeclaims"
                    | "networkpolicies"
                    | "configmaps"
                    | "nodes"
            )
        )
    }

    fn selector_matches(query: &str, object: &serde_json::Value) -> bool {
        let Some(raw) = query.split('&').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == "labelSelector").then_some(value)
        }) else {
            return true;
        };
        let selector = percent_decode(raw);
        if selector.is_empty() {
            return true;
        }
        let labels = &object["metadata"]["labels"];
        selector.split(',').all(|term| {
            let term = term.trim();
            if let Some((key, value)) = term.split_once('=') {
                labels[key].as_str() == Some(value)
            } else {
                !labels[term].is_null()
            }
        })
    }

    fn percent_decode(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let bytes = raw.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte as char);
                    index += 3;
                    continue;
                }
            }
            out.push(bytes[index] as char);
            index += 1;
        }
        out
    }

    impl PlacementApi {
        fn bind() -> Self {
            use std::io::{BufRead, Read, Write};
            use std::sync::{atomic::Ordering, Arc, Mutex};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback API");
            let port = listener.local_addr().expect("API address").port();
            let state = Arc::new(Mutex::new(PlacementApiState {
                nodes: vec![placement_node("mini"), placement_node("pc")],
                ..Default::default()
            }));
            let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let serving_state = Arc::clone(&state);
            let serving_stopped = Arc::clone(&stopped);
            let thread = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if serving_stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let mut stream = stream.expect("API connection");
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                        .expect("read bound");
                    stream
                        .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                        .expect("write bound");
                    let mut reader = std::io::BufReader::new(stream.try_clone().expect("reader"));
                    let mut request = String::new();
                    if reader.read_line(&mut request).expect("request line") == 0 {
                        continue;
                    }
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).expect("header");
                        if line.trim().is_empty() {
                            break;
                        }
                        if let Some((key, value)) = line.split_once(':') {
                            if key.eq_ignore_ascii_case("content-length") {
                                length = value.trim().parse::<usize>().expect("body length");
                            }
                        }
                    }
                    let mut bytes = vec![0; length];
                    reader.read_exact(&mut bytes).expect("request body");
                    let body = if bytes.is_empty() {
                        serde_json::Value::Null
                    } else {
                        serde_json::from_slice(&bytes).expect("JSON API body")
                    };
                    let mut parts = request.split_whitespace();
                    let method = parts.next().expect("method");
                    let target = parts.next().expect("path");
                    let (path, query) = target.split_once('?').unwrap_or((target, ""));
                    let (code, response) = serving_state
                        .lock()
                        .expect("API state")
                        .respond(method, path, query, body);
                    let response = serde_json::to_vec(&response).expect("response JSON");
                    write!(stream, "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).expect("response header");
                    stream.write_all(&response).expect("response body");
                }
            });
            Self {
                port,
                state,
                stopped,
                thread: Some(thread),
            }
        }
    }

    impl Drop for PlacementApi {
        fn drop(&mut self) {
            self.stopped
                .store(true, std::sync::atomic::Ordering::Release);
            let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
            if let Some(thread) = self.thread.take() {
                thread.join().expect("API thread");
            }
        }
    }

    struct PlacementFixture {
        api: PlacementApi,
        reconciler: super::JobReconciler,
        ledger: std::sync::Arc<std::sync::Mutex<odin_ledger::Ledger>>,
        artifact_root: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    impl PlacementFixture {
        fn new(allowed: &[&str]) -> Self {
            let api = PlacementApi::bind();
            let dir = tempfile::tempdir().expect("scratch directory");
            let ledger = std::sync::Arc::new(std::sync::Mutex::new(
                odin_ledger::Ledger::open(dir.path().join("placement.sqlite3"))
                    .expect("scratch ledger"),
            ));
            let channel = odin_kernel::recovery_worker_channel(
                "unix:path=/tmp/odin-placement-test-absent-bus.sock",
            )
            .expect("recovery channel");
            let stops =
                std::sync::Arc::new(odin_kernel::StopAuthority::new(ledger.clone(), channel));
            let client = crate::KubeClient {
                client: kube::Client::try_from(kube::Config::new(
                    format!("http://127.0.0.1:{}", api.port)
                        .parse()
                        .expect("API URI"),
                ))
                .expect("client"),
                config: crate::KubeConfig {
                    kubeconfig: dir.path().join("unused-kubeconfig"),
                    cluster: "placement-fixture".to_owned(),
                    namespace: "default".to_owned(),
                    allowed_nodes: allowed.iter().map(|name| (*name).to_owned()).collect(),
                    request_timeout: std::time::Duration::from_secs(2),
                    teardown_timeout: std::time::Duration::from_secs(2),
                },
            };
            let artifact_root = dir.path().join("artifacts");
            std::fs::create_dir_all(&artifact_root).expect("artifact root");
            let reconciler = super::JobReconciler::new(
                client,
                ledger.clone(),
                stops,
                std::sync::Arc::default(),
                artifact_root.clone(),
            )
            .expect("reconciler");
            Self {
                api,
                reconciler,
                ledger,
                artifact_root,
                _dir: dir,
            }
        }

        fn checkpoint(&self, launch: &mut JobLaunch) {
            use odin_ledger::artifact::{
                ArtifactRegistration, NewArtifactReference, RetentionClass,
            };
            let bytes = b"counter=41\n";
            let path = "counter-state";
            std::fs::write(self.artifact_root.join(path), bytes).expect("checkpoint bytes");
            let mut ledger = self.ledger.lock().expect("ledger");
            let metadata = ledger
                .register_artifact(ArtifactRegistration {
                    bytes,
                    media_type: "text/plain",
                    storage_path: path,
                    retention: RetentionClass::Canonical,
                    created_at: time::OffsetDateTime::now_utc(),
                })
                .expect("checkpoint registration");
            ledger
                .attach_artifact_reference(
                    &metadata.artifact_id,
                    metadata.revision,
                    NewArtifactReference {
                        object_kind: "run",
                        object_id: launch.labels.run_id.as_str(),
                        relation: "checkpoint",
                        created_at: time::OffsetDateTime::now_utc(),
                    },
                )
                .expect("checkpoint scope");
            let checkpoint_id =
                odin_domain::CheckpointId::new("placement-checkpoint").expect("checkpoint id");
            launch.staging.resumed_from = Some(checkpoint_id.clone());
            launch.checkpoint = Some(odin_domain::huginn::KubeCheckpointProjection {
                checkpoint_id,
                parent_checkpoint_id: None,
                state: odin_domain::huginn::KubeContentIdentity {
                    artifact_id: metadata.artifact_id,
                    content_digest: metadata.digest,
                    byte_len: metadata.size_bytes,
                },
            });
        }
    }

    fn portable_launch() -> JobLaunch {
        let mut launch = launch(0, Some(300));
        launch.initial_target_node = Some("mini".to_owned());
        launch
            .node_selector
            .insert("odin.capability/portable".to_owned(), "true".to_owned());
        let mut plan = workload_plan();
        plan.agent = None;
        plan.profile = "state-counter".to_owned();
        launch.workload = Some(plan);
        launch
    }

    fn restart_action(
        launch: &JobLaunch,
        observation: &crate::JobObservation,
        target: Option<&str>,
    ) -> crate::JobAction {
        crate::JobAction {
            run_id: launch.labels.run_id.clone(),
            kind: odin_domain::huginn::KubeOperationKind::Restart,
            expected_resource_version: observation.projection.identity.resource_version.clone(),
            operation_id: OperationId::new("op-placement-restart").expect("operation"),
            idempotency_digest: Digest::hash(b"placement-restart"),
            target_node: target.map(str::to_owned),
        }
    }

    fn mark_job_complete(state: &mut PlacementApiState, job: &str) {
        state.objects.get_mut(job).expect("job")["status"] = serde_json::json!({
            "conditions": [{"type": "Complete", "status": "True"}]
        });
    }

    fn assert_placement(job: &serde_json::Value, node: &str, launch: &JobLaunch) {
        let spec = &job["spec"]["template"]["spec"];
        assert!(
            spec["nodeName"].is_null(),
            "the scheduler must retain admission"
        );
        assert_eq!(
            spec["nodeSelector"],
            serde_json::to_value(&launch.node_selector).expect("selector")
        );
        assert_eq!(
            spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                ["nodeSelectorTerms"][0]["matchFields"][0],
            serde_json::json!({"key":"metadata.name", "operator":"In", "values":[node]})
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initial_target_mini_rehomes_to_pc_preserving_shared_state_and_profile() {
        let fixture = PlacementFixture::new(&["alpha", "mini", "pc"]);
        // Without a target directive, placement would select alpha instead of mini.
        fixture
            .api
            .state
            .lock()
            .expect("API state")
            .nodes
            .push(placement_node("alpha"));
        let mut launch = portable_launch();
        fixture.checkpoint(&mut launch);
        let first = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("targeted create");
        let claim_path = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        let (claim, staged) = {
            let mut state = fixture.api.state.lock().expect("API state");
            assert_placement(&state.created_jobs[0], "mini", &launch);
            // A shared PV can move to pc without replacing its claim or checkpoint.
            state
                .objects
                .get_mut(&claim_path)
                .expect("created state claim")["spec"]["volumeName"] =
                serde_json::json!("counter-volume");
            state.objects.insert("/api/v1/persistentvolumes/counter-volume".to_owned(), serde_json::json!({
                "apiVersion":"v1", "kind":"PersistentVolume", "metadata":{"name":"counter-volume"},
                "spec":{"capacity":{"storage":"2Gi"}, "accessModes":["ReadWriteOnce"]}
            }));
            let staged: Vec<_> = state
                .objects
                .iter()
                .filter(|(path, _)| path.contains("/configmaps/"))
                .map(|(path, value)| (path.clone(), value.clone()))
                .collect();
            assert!(
                !staged.is_empty(),
                "real checkpoint staging created a ConfigMap"
            );
            (state.objects[&claim_path].clone(), staged)
        };
        let second = fixture
            .reconciler
            .operate(restart_action(&launch, &first, Some("pc")))
            .await
            .expect("explicit rehome");
        assert_ne!(
            first.projection.identity.uid,
            second.projection.identity.uid
        );
        assert_ne!(
            first.projection.worker.worker_id,
            second.projection.worker.worker_id
        );
        let stored = fixture
            .reconciler
            .stored_launch(&launch.labels.run_id)
            .expect("stored launch")
            .expect("admitted launch");
        assert_eq!(stored.node_selector, launch.node_selector);
        assert_eq!(
            stored.initial_target_node.as_deref(),
            Some("mini"),
            "immutable admission record, not a permanent pin"
        );
        assert_eq!(stored.workload, launch.workload);
        assert_eq!(stored.checkpoint, launch.checkpoint);
        assert_eq!(stored.image, launch.image);
        assert_eq!(stored.command, launch.command);
        assert_eq!(stored.args, launch.args);
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(state.created_jobs.len(), 2);
        assert_placement(&state.created_jobs[1], "pc", &launch);
        assert_eq!(
            state.objects[&claim_path], claim,
            "same bound claim retains state custody"
        );
        for (path, configmap) in staged {
            assert_eq!(
                state.objects[&path], configmap,
                "checkpoint bytes survive rehome"
            );
        }
        let first_spec = &state.created_jobs[0]["spec"]["template"]["spec"];
        let second_spec = &state.created_jobs[1]["spec"]["template"]["spec"];
        assert_eq!(first_spec["volumes"], second_spec["volumes"]);
        assert_eq!(first_spec["containers"], second_spec["containers"]);
        assert_eq!(
            state
                .requests
                .iter()
                .filter(|(method, _)| method == "DELETE")
                .count(),
            1,
            "only the old Job is deleted through StopAuthority"
        );
        assert_eq!(
            std::fs::read(fixture.artifact_root.join("counter-state")).expect("checkpoint bytes"),
            b"counter=41\n"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ordinary_restart_does_not_reuse_initial_target() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = portable_launch();
        let first = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("initial mini");
        fixture.api.state.lock().expect("API state").nodes[0]["spec"]["unschedulable"] =
            serde_json::json!(true);
        fixture
            .reconciler
            .operate(restart_action(&launch, &first, None))
            .await
            .expect("ordinary restart selects eligible pc");
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(state.created_jobs.len(), 2);
        assert_placement(&state.created_jobs[0], "mini", &launch);
        assert_placement(&state.created_jobs[1], "pc", &launch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refused_initial_targets_never_fall_back() {
        for (allowed, unavailable) in [
            (vec!["pc"], false),
            (vec![], false),
            (vec!["mini", "pc"], true),
        ] {
            let fixture = PlacementFixture::new(&allowed);
            let launch = portable_launch();
            if unavailable {
                fixture.api.state.lock().expect("API state").nodes[0]["status"]["conditions"][0]
                    ["status"] = serde_json::json!("False");
            }
            let error = fixture
                .reconciler
                .create(launch)
                .await
                .expect_err("mini is not admissible even though pc is ready");
            if unavailable {
                assert!(error.is_unavailable(), "{error:?}");
            } else {
                assert!(
                    matches!(error, crate::KubeError::Rejected { .. }),
                    "{error:?}"
                );
            }
            let state = fixture.api.state.lock().expect("API state");
            assert!(state.created_jobs.is_empty(), "must not fall back to pc");
            if !unavailable {
                assert!(
                    state.requests.iter().all(|(method, _)| method == "GET"),
                    "authority rejection precedes all cluster effects"
                );
            }
        }
    }

    impl PlacementFixture {
        /// Builds an agent launch whose only varying field is the gateway host.
        fn agent_launch(&self, gateway_host: &str) -> JobLaunch {
            use odin_ledger::artifact::NewArtifactReference;
            let mut launch = portable_launch();
            let mut plan = workload_plan();
            plan.profile = "state-counter".to_owned();
            plan.agent.as_mut().expect("agent plan").gateway.host = gateway_host.to_owned();
            plan.validate().expect("declared workload plan");
            launch.workload = Some(plan);
            let metadata = self
                .reconciler
                .artifacts
                .register_bytes(br#"{"providers":{}}"#, "models-config")
                .expect("models document registration");
            self.ledger
                .lock()
                .expect("ledger")
                .attach_artifact_reference(
                    &metadata.artifact_id,
                    metadata.revision,
                    NewArtifactReference {
                        object_kind: "run",
                        object_id: launch.labels.run_id.as_str(),
                        relation: "models-config",
                        created_at: time::OffsetDateTime::now_utc(),
                    },
                )
                .expect("models document run scope");
            launch.staging.inputs = vec![crate::job::KubeContentIdentity {
                artifact_id: metadata.artifact_id.clone(),
                content_digest: metadata.digest,
                byte_len: metadata.size_bytes,
            }];
            launch.models_config = Some(crate::job::JobModelsConfigLaunch {
                config_artifact: metadata.artifact_id,
                config_digest: metadata.digest.to_string(),
                credential_env: "ODIN_GATEWAY_KEY".to_owned(),
            });
            launch
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_inadmissible_resolved_gateway_refuses_before_any_cluster_write() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        // 127.0.0.1 needs no DNS; the allowlist is empty.
        let launch = fixture.agent_launch("127.0.0.1");
        let plan = launch.workload.as_ref().expect("workload plan");
        assert!(plan.allow_hosts.is_empty());
        launch
            .validate()
            .expect("every declaration other than the resolved gateway is valid");
        fixture
            .reconciler
            .artifacts
            .prepare_stage(&launch.labels, &launch.staging, launch.checkpoint.as_ref())
            .expect("the staged models document is admitted, so staging cannot be the refusal");
        let foreign_path =
            "/api/v1/namespaces/default/persistentvolumeclaims/odin-state-foreign-bound";
        {
            let mut state = fixture.api.state.lock().expect("API state");
            state.objects.insert(
                foreign_path.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"PersistentVolumeClaim",
                    "metadata":{"name":"odin-state-foreign-bound", "uid":"foreign-uid",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id":"some-other-run"}},
                    "spec":{"resources":{"requests":{"storage":"128Mi"}},
                        "volumeName":"pvc-foreign"},
                    "status":{"phase":"Bound"}
                }),
            );
        }
        let before = fixture.api.state.lock().expect("API state").objects.clone();

        let error = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect_err("a gateway no pod can reach is refused");
        assert!(
            matches!(error, crate::KubeError::Rejected { .. }),
            "{error:?}"
        );

        let state = fixture.api.state.lock().expect("API state");
        let writes: Vec<_> = state
            .requests
            .iter()
            .filter(|(method, _)| method != "GET")
            .collect();
        assert!(
            writes.is_empty(),
            "egress admission precedes the first cluster write: {writes:?}"
        );
        assert!(state.created_jobs.is_empty());
        assert_eq!(
            state.objects, before,
            "no claim, policy, ConfigMap, or Job appears and the foreign claim is untouched"
        );
        drop(state);

        assert_eq!(
            fixture
                .reconciler
                .stored_launch(&launch.labels.run_id)
                .expect("stored launch")
                .expect("the admitted launch stays durably registered")
                .workload,
            launch.workload
        );
        assert!(
            matches!(
                fixture
                    .reconciler
                    .journal
                    .operation_outcome(launch.operation_id.as_str()),
                Ok(Some(Err(crate::KubeError::Rejected { .. })))
            ),
            "the refusal settles the admitted operation as a typed rejection"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_admissible_literal_gateway_runs_the_same_launch_through_every_effect() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("the identical launch with an admissible gateway is created");

        let claim_path = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(state.created_jobs.len(), 1);
        assert!(state.objects.contains_key(&claim_path));
        assert!(state
            .objects
            .keys()
            .any(|path| path.contains("/configmaps/")));
        let policies: Vec<_> = state
            .objects
            .iter()
            .filter(|(path, _)| path.contains("/networkpolicies/"))
            .map(|(_, policy)| policy)
            .collect();
        assert_eq!(policies.len(), 1);
        assert!(
            policies[0]["spec"]["egress"]
                .as_array()
                .expect("egress rules")
                .iter()
                .any(|rule| rule["to"][0]["ipBlock"]["cidr"] == "192.0.2.10/32"
                    && rule["ports"][0]["port"] == 14000
                    && rule["ports"][0]["protocol"] == "TCP"),
            "the resolved gateway is pinned on its declared port: {}",
            policies[0]
        );
    }

    fn watched_job(state: &PlacementApiState, job: &str) -> crate::job::JobObservation {
        let object = state.objects.get(job).expect("watched Job").clone();
        let parsed: k8s_openapi::api::batch::v1::Job =
            serde_json::from_value(object).expect("Job JSON");
        crate::status::observe_job("placement-fixture", &parsed, 1).expect("observation")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_finished_run_whose_job_is_gone_drops_policy_maps_and_claim() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("launch");
        let run = &launch.labels.run_id;
        let claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(run)
        );
        let policy = format!(
            "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies/{}",
            crate::workload::egress_policy_name(run)
        );
        let job = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(run)
        );
        let label = crate::job::bounded_label_value(run.as_str());
        {
            let mut state = fixture.api.state.lock().expect("API state");
            mark_job_complete(&mut state, &job);
        }
        let observation = watched_job(&fixture.api.state.lock().expect("API state"), &job);
        fixture
            .reconciler
            .note_watched_job(&observation)
            .await
            .expect("Applied marks a Complete Job");
        {
            let mut state = fixture.api.state.lock().expect("API state");
            assert_eq!(
                state.objects[&claim]["metadata"]["annotations"][crate::artifacts::RUN_FINISHED],
                "true"
            );
            state.objects.get_mut(&job).expect("job")["metadata"]["deletionTimestamp"] =
                serde_json::json!("2026-01-01T00:00:00Z");
        }
        let deleting = watched_job(&fixture.api.state.lock().expect("API state"), &job);
        fixture
            .reconciler
            .note_watched_job(&deleting)
            .await
            .expect("deletionTimestamp does not clear the finished mark");
        assert_eq!(
            fixture.api.state.lock().expect("API state").objects[&claim]["metadata"]["annotations"]
                [crate::artifacts::RUN_FINISHED],
            "true"
        );
        fixture
            .reconciler
            .reap_watched_deletion(Some(&label))
            .await
            .expect("Deleted while the Job is still there does not reap");
        assert!(fixture
            .api
            .state
            .lock()
            .expect("API state")
            .objects
            .contains_key(&claim));
        fixture
            .api
            .state
            .lock()
            .expect("API state")
            .objects
            .remove(&job);
        fixture
            .reconciler
            .reap_watched_deletion(Some(&label))
            .await
            .expect("Deleted after the Job is gone drops residue");
        let state = fixture.api.state.lock().expect("API state");
        assert!(!state.objects.contains_key(&claim), "claim deleted");
        assert!(!state.objects.contains_key(&policy), "policy deleted");
        assert!(
            !state
                .objects
                .keys()
                .any(|path| path.contains("/configmaps/")),
            "staging maps deleted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_or_unfinished_run_keeps_policy_maps_and_claim() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("launch");
        let run = &launch.labels.run_id;
        let claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(run)
        );
        let job = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(run)
        );
        let label = crate::job::bounded_label_value(run.as_str());
        let observation = watched_job(&fixture.api.state.lock().expect("API state"), &job);
        fixture
            .reconciler
            .note_watched_job(&observation)
            .await
            .expect("a live Job is not finished");
        assert!(
            fixture.api.state.lock().expect("API state").objects[&claim]["metadata"]["annotations"]
                [crate::artifacts::RUN_FINISHED]
                .is_null(),
            "no finished mark on a live Job"
        );
        fixture
            .api
            .state
            .lock()
            .expect("API state")
            .objects
            .remove(&job);
        fixture
            .reconciler
            .reap_watched_deletion(Some(&label))
            .await
            .expect("a gone Job that was never terminal is not finished residue");
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            state.objects.contains_key(&claim),
            "no finished mark, so the claim stays"
        );
        assert!(state
            .objects
            .keys()
            .any(|path| path.contains("/configmaps/")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_in_flight_restart_keeps_the_claim_after_the_job_is_gone() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        let created = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("launch");
        let action = restart_action(&launch, &created, None);
        fixture
            .reconciler
            .journal
            .begin(
                &action.operation_id,
                &action.run_id,
                action.kind,
                &action.idempotency_digest,
                &action,
            )
            .expect("restart stays pending");
        let claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        let job = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(&launch.labels.run_id)
        );
        let label = crate::job::bounded_label_value(launch.labels.run_id.as_str());
        {
            let mut state = fixture.api.state.lock().expect("API state");
            mark_job_complete(&mut state, &job);
        }
        let observation = watched_job(&fixture.api.state.lock().expect("API state"), &job);
        fixture
            .reconciler
            .note_watched_job(&observation)
            .await
            .expect("an in-flight restart is not marked finished");
        fixture
            .api
            .state
            .lock()
            .expect("API state")
            .objects
            .remove(&job);
        fixture
            .reconciler
            .reap_watched_deletion(Some(&label))
            .await
            .expect("Deleted skips the in-flight restart");
        assert!(
            fixture
                .api
                .state
                .lock()
                .expect("API state")
                .objects
                .contains_key(&claim),
            "restart still needs the claim"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unregistered_deleted_label_drops_residue_without_a_finished_mark() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let label = "suite-orphan-run";
        let claim = "/api/v1/namespaces/default/persistentvolumeclaims/odin-state-suite-orphan";
        let map = "/api/v1/namespaces/default/configmaps/suite-orphan-staging";
        let other = "/api/v1/namespaces/default/configmaps/other-run-staging";
        {
            let mut state = fixture.api.state.lock().expect("API state");
            state.objects.insert(
                claim.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"PersistentVolumeClaim",
                    "metadata":{"name":"odin-state-suite-orphan", "uid":"orphan-uid",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id": label}},
                    "spec":{"accessModes":["ReadWriteOnce"],
                        "resources":{"requests":{"storage":"1Gi"}}}
                }),
            );
            state.objects.insert(
                map.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"ConfigMap",
                    "metadata":{"name":"suite-orphan-staging", "uid":"orphan-map",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id": label}}
                }),
            );
            state.objects.insert(
                other.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"ConfigMap",
                    "metadata":{"name":"other-run-staging", "uid":"other-map",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id": "other-run"}}
                }),
            );
        }
        fixture
            .reconciler
            .reap_watched_deletion(Some(label))
            .await
            .expect("Deleted of an unregistered label drops its residue");
        assert!(
            !fixture
                .api
                .state
                .lock()
                .expect("API state")
                .objects
                .contains_key(claim),
            "orphan claim deleted without a finished mark or a journal scan"
        );
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            !state.objects.contains_key(map),
            "orphan map deleted by the same run-id label"
        );
        assert!(
            state.objects.contains_key(other),
            "a different run-id label stays"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_residue_sweep_drops_only_the_marked_run_whose_job_is_gone() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let finished = fixture.agent_launch("192.0.2.10");
        let mut live = finished.clone();
        live.labels.run_id = RunId::new("run-launch-shape-live").expect("run id");
        live.worker_id = WorkerId::new("worker-launch-shape-live").expect("worker id");
        live.operation_id = OperationId::new("op-launch-shape-live").expect("operation id");
        live.idempotency_digest = Digest::hash(b"launch-shape-live");
        fixture
            .ledger
            .lock()
            .expect("ledger")
            .attach_artifact_reference(
                &live.models_config.as_ref().expect("models").config_artifact,
                2,
                odin_ledger::artifact::NewArtifactReference {
                    object_kind: "run",
                    object_id: live.labels.run_id.as_str(),
                    relation: "models-config",
                    created_at: time::OffsetDateTime::now_utc(),
                },
            )
            .expect("live run artifact scope");
        fixture
            .reconciler
            .create(finished.clone())
            .await
            .expect("finished launch");
        fixture
            .reconciler
            .create(live.clone())
            .await
            .expect("live launch");
        let finished_job = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(&finished.labels.run_id)
        );
        let finished_claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&finished.labels.run_id)
        );
        let live_claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&live.labels.run_id)
        );
        let finished_map = format!(
            "/api/v1/namespaces/default/configmaps/{}",
            crate::job::staging_configmap_name(&crate::job::job_name(&finished.labels.run_id))
        );
        let live_map = format!(
            "/api/v1/namespaces/default/configmaps/{}",
            crate::job::staging_configmap_name(&crate::job::job_name(&live.labels.run_id))
        );
        let marked_only = "/api/v1/namespaces/default/configmaps/marked-map-only";
        let unmarked = "/api/v1/namespaces/default/configmaps/live-map-only";
        {
            let mut state = fixture.api.state.lock().expect("API state");
            mark_job_complete(&mut state, &finished_job);
        }
        let observation = watched_job(&fixture.api.state.lock().expect("API state"), &finished_job);
        fixture
            .reconciler
            .note_watched_job(&observation)
            .await
            .expect("Applied marks only the Complete Job");
        {
            let mut state = fixture.api.state.lock().expect("API state");
            state.objects.remove(&finished_job);
            // No claim, policy, or Job: only a labelled list can find this map.
            state.objects.insert(
                marked_only.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"ConfigMap",
                    "metadata":{"name":"marked-map-only", "uid":"marked-map",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id": "marked-map-only"},
                        "annotations":{"odin.dev/run-finished": "true"}}
                }),
            );
            state.objects.insert(
                unmarked.to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"ConfigMap",
                    "metadata":{"name":"live-map-only", "uid":"unmarked-map",
                        "resourceVersion":"1", "namespace":"default",
                        "labels":{"odin.dev/run-id": "live-map-only"}}
                }),
            );
        }
        fixture
            .reconciler
            .reap_marked_residue()
            .await
            .expect("sweep of outstanding marked residue");
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            !state.objects.contains_key(&finished_claim),
            "the marked run whose Job is gone is reaped"
        );
        assert!(
            state.objects.contains_key(&live_claim),
            "the live run is not historical residue"
        );
        assert!(
            !state.objects.contains_key(&finished_map),
            "finished staging map is gone"
        );
        assert!(
            state.objects.contains_key(&live_map),
            "live staging map stays"
        );
        assert!(
            !state.objects.contains_key(marked_only),
            "a marked map with no claim is reaped"
        );
        assert!(
            state.objects.contains_key(unmarked),
            "an unmarked labelled map stays"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hashed_run_id_sweep_marks_the_real_claim_while_the_job_is_live() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let mut launch = fixture.agent_launch("192.0.2.10");
        // Longer than a Kubernetes label, so the Job's run-id label is the hash.
        let run_id = format!("run-overlong-{}", "a".repeat(64));
        launch.labels.run_id = RunId::new(&run_id).expect("run id");
        launch.worker_id = WorkerId::new("worker-launch-shape-hashed").expect("worker id");
        launch.operation_id = OperationId::new("op-launch-shape-hashed").expect("operation id");
        launch.idempotency_digest = Digest::hash(b"launch-shape-hashed");
        let label = crate::job::bounded_label_value(launch.labels.run_id.as_str());
        assert_ne!(
            label,
            launch.labels.run_id.as_str(),
            "the fixture must hash the RunId or this regression cannot show the bug"
        );
        fixture
            .ledger
            .lock()
            .expect("ledger")
            .attach_artifact_reference(
                &launch
                    .models_config
                    .as_ref()
                    .expect("models")
                    .config_artifact,
                2,
                odin_ledger::artifact::NewArtifactReference {
                    object_kind: "run",
                    object_id: launch.labels.run_id.as_str(),
                    relation: "models-config",
                    created_at: time::OffsetDateTime::now_utc(),
                },
            )
            .expect("hashed run artifact scope");
        fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("hashed launch");
        let job = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(&launch.labels.run_id)
        );
        let claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        {
            let mut state = fixture.api.state.lock().expect("API state");
            mark_job_complete(&mut state, &job);
        }
        fixture
            .reconciler
            .reap_marked_residue()
            .await
            .expect("sweep marks the live finished Job from its projection");
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            state.objects.contains_key(&job),
            "a live Job is the guard, not residue"
        );
        assert_eq!(
            state.objects[&job]["metadata"]["labels"]["odin.dev/run-id"].as_str(),
            Some(label.as_str()),
            "the live Job is addressed by the hashed label"
        );
        assert_eq!(
            state.objects[&claim]["metadata"]["annotations"]["odin.dev/run-finished"].as_str(),
            Some("true"),
            "the finished mark names the real claim, not the hashed label"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_clears_policy_maps_and_claim_before_the_run_is_terminal() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        let created = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("launch");
        let claim = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        fixture
            .reconciler
            .operate(crate::JobAction {
                run_id: launch.labels.run_id.clone(),
                kind: odin_domain::huginn::KubeOperationKind::Cancel,
                expected_resource_version: created.projection.identity.resource_version,
                operation_id: OperationId::new("op-placement-cancel").expect("operation"),
                idempotency_digest: Digest::hash(b"placement-cancel"),
                target_node: None,
            })
            .await
            .expect("cancel");
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            !state.objects.contains_key(&claim),
            "cancel deletes the claim without a finished mark"
        );
        assert!(
            !state
                .objects
                .keys()
                .any(|path| path.contains("/networkpolicies/") || path.contains("/configmaps/")),
            "cancel deletes policy and maps"
        );
    }
}
