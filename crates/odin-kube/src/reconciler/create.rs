//! Create suspended Jobs, register their API identity, then release them.

use std::sync::Arc;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Affinity, Capabilities, Container, EnvVar, EnvVarSource, HostPathVolumeSource, NodeAffinity,
    NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, PodDNSConfig, PodSecurityContext,
    PodSpec, PodTemplateSpec, ResourceRequirements, SeccompProfile, SecurityContext, Toleration,
    Volume, VolumeMount,
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
mod transport;
use transport::{protected_pins, transport_sidecar, tun_volume};

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

// The transport sidecar only tunnels packets, so it reserves a lean share, not a worker's.
pub(crate) const TRANSPORT_RESERVATION: KubeResources = KubeResources {
    cpu_millis: 250,
    memory_bytes: 256 * 1024 * 1024,
    ephemeral_storage_bytes: 256 * 1024 * 1024,
    gpu_count: 0,
};

fn quantity_millis(millis: u64) -> Quantity {
    Quantity(format!("{millis}m"))
}

fn quantity_bytes(bytes: u64) -> Quantity {
    Quantity(bytes.to_string())
}

// GPUs are requested by the worker container only; a profile may declare its CPU and memory.
fn worker_reservation(launch: &JobLaunch) -> KubeResources {
    let declared = launch.workload.as_ref().and_then(|plan| plan.resources);
    KubeResources {
        cpu_millis: declared.map_or(WORKER_CPU_MILLIS, |resources| {
            u64::from(resources.cpu) * 1_000
        }),
        memory_bytes: declared.map_or(WORKER_MEMORY_BYTES, |resources| resources.memory_bytes),
        gpu_count: launch.gpu_count,
        ..WORKER_RESERVATION
    }
}

// Placement must account for the worker, the browser container when one runs, and a
// protected transport sidecar; each extra container reserves only what it runs with.
pub(crate) fn launch_reservation(launch: &JobLaunch) -> KubeResources {
    let worker = worker_reservation(launch);
    let Some(plan) = launch.workload.as_ref() else {
        return worker;
    };
    let browser = u64::from(plan.browser_command().is_some());
    let transport = u64::from(plan.vpn.is_some());
    KubeResources {
        cpu_millis: worker.cpu_millis
            + browser * WORKER_CPU_MILLIS
            + transport * TRANSPORT_RESERVATION.cpu_millis,
        memory_bytes: worker.memory_bytes
            + browser * WORKER_MEMORY_BYTES
            + transport * TRANSPORT_RESERVATION.memory_bytes,
        ephemeral_storage_bytes: worker.ephemeral_storage_bytes
            + browser * WORKER_EPHEMERAL_BYTES
            + transport * TRANSPORT_RESERVATION.ephemeral_storage_bytes,
        gpu_count: worker.gpu_count,
    }
}

fn launch_data(launch: &JobLaunch) -> &[crate::workload::WorkloadDataMount] {
    launch
        .workload
        .as_ref()
        .map_or(&[], |plan| plan.data.as_slice())
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
    pins: Option<(Vec<std::net::IpAddr>, u16, Vec<std::net::IpAddr>)>,
    deadline: Option<i64>,
) -> Result<Job, KubeError> {
    launch
        .validate()
        .map_err(|reason| KubeError::Rejected { reason })?;
    let mut labels = launch.binding_label_map();
    // Staging publishes and verifies ConfigMaps before this template references them.
    labels.insert(KUBE_LABEL_STAGED.to_owned(), KUBE_STAGED_TRUE.to_owned());
    if let Some(lane) = &launch.budget_lane {
        labels.insert(
            crate::job::JOB_LABEL_BUDGET_LANE.to_owned(),
            bounded_label_value(lane.as_str()),
        );
    }
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
        if plan.control.is_some() {
            let (volume, mount) = crate::control::control_volume(&launch.job_name());
            volumes.push(volume);
            mounts.push(mount);
        }
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
        env.extend(plan.gateway_env());
        // Workload admission resolves the image to an immutable OCI reference. Expose
        // its manifest digest, not the independently calculated profile identity.
        if plan.agent.is_none() {
            if let Some((_, digest)) = launch.image.rsplit_once('@') {
                if digest.strip_prefix("sha256:").is_some_and(|hex| {
                    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                }) {
                    env.push(EnvVar {
                        name: "ODIN_IMAGE_DIGEST".to_owned(),
                        value: Some(digest.to_owned()),
                        value_from: None,
                    });
                }
            }
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
    let protected = launch
        .workload
        .as_ref()
        .is_some_and(|plan| plan.transport == odin_registry::WorkloadTransport::VpnRequired);
    if protected {
        let plan = launch.workload.as_ref().expect("protected plan");
        let vpn = plan.vpn.as_ref().ok_or_else(|| {
            KubeError::rejected(
                "vpn-required workload has no resolved transport binding; refusing direct \
                 fallback",
            )
        })?;
        let (gateway, gateway_port, allow) = pins.ok_or_else(|| {
            KubeError::rejected("vpn-required workload has no resolved transport pins")
        })?;
        volumes.push(tun_volume());
        volumes.push(Volume {
            name: "odin-vpn-ready".to_owned(),
            empty_dir: Some(k8s_openapi::api::core::v1::EmptyDirVolumeSource::default()),
            ..Default::default()
        });
        init_containers.push(transport_sidecar(
            &launch.image,
            &vpn.command(&gateway, gateway_port, &allow, plan.network_open),
        ));
    }
    if let Some((plan, browser_command)) = launch
        .workload
        .as_ref()
        .and_then(|plan| Some((plan, plan.browser_command()?)))
    {
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
    let protected_dns = launch
        .workload
        .as_ref()
        .and_then(|plan| plan.vpn.as_ref())
        .filter(|_| protected)
        .map(|vpn| vpn.dns);
    let spec = PodSpec {
        termination_grace_period_seconds: launch
            .workload
            .as_ref()
            .and_then(|plan| plan.termination_grace_seconds)
            .map(i64::from),
        restart_policy: Some(if launch.service { "OnFailure" } else { "Never" }.to_owned()),
        share_process_namespace: Some(false),
        automount_service_account_token: Some(false),
        dns_policy: protected.then(|| "None".to_owned()),
        dns_config: protected_dns.map(|dns| PodDNSConfig {
            nameservers: Some(vec![dns.to_string()]),
            searches: Some(vec![]),
            options: Some(vec![]),
        }),
        containers,
        init_containers: (!init_containers.is_empty()).then_some(init_containers),
        volumes: Some(volumes),
        security_context: Some(worker_pod_security()),
        node_selector: (!launch.node_selector.is_empty()).then(|| launch.node_selector.clone()),
        tolerations: (!launch.tolerate.is_empty()).then(|| {
            launch
                .tolerate
                .iter()
                .map(|name| Toleration {
                    key: Some(format!(
                        "{}{name}",
                        odin_registry::schema::NODE_TAINT_PREFIX
                    )),
                    operator: Some("Exists".to_owned()),
                    effect: Some("NoSchedule".to_owned()),
                    ..Default::default()
                })
                .collect()
        }),
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
            annotations: launch.label.as_ref().map(|label| {
                std::collections::BTreeMap::from([(
                    crate::job::JOB_LABEL_ANNOTATION.to_owned(),
                    label.clone(),
                )])
            }),
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
            active_deadline_seconds: deadline.or(launch.deadline_seconds.map(i64::from)),
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
    let hex = Digest::hash(format!("odin.kube.job-worker:{}", run.as_str()).as_bytes()).hex();
    CorrelationId::new(&hex[..32]).map_err(|error| storage(error.to_string()))
}

/// Campaign authority is immutable; all creation paths use the same node and wall-clock end.
pub(super) fn campaign_deadline(
    launch: &JobLaunch,
    target: Option<&str>,
) -> Result<Option<i64>, KubeError> {
    let Some(reservation) = &launch.campaign_reservation else {
        return Ok(None);
    };
    if target.is_some_and(|node| node != reservation.approved_node) {
        return Err(KubeError::rejected(
            "campaign recreation must use its approved node",
        ));
    }
    let now = k8s_openapi::jiff::Timestamp::now().as_second();
    let remaining = reservation.expires_at_unix_seconds.saturating_sub(now);
    if remaining <= 0 {
        return Err(KubeError::rejected("campaign compute budget is exhausted"));
    }
    Ok(Some(
        remaining.min(i64::from(
            launch
                .deadline_seconds
                .ok_or_else(|| KubeError::rejected("campaign deadline is missing"))?,
        )),
    ))
}

impl JobReconciler {
    /// Read-only: whether a launch's new Job would be admitted and has room on a node. Runs
    /// before any journal or API write, so a refusal leaves no pending create. An existing Job
    /// already holds its node's room, so it is never re-checked and answers `None`; otherwise
    /// the node the Job would land on.
    pub async fn room_for(&self, launch: &JobLaunch) -> Result<Option<String>, KubeError> {
        launch
            .validate()
            .map_err(|reason| KubeError::Rejected { reason })?;
        campaign_deadline(launch, launch.initial_target_node.as_deref())?;
        if self.get_job(&launch.job_name()).await?.is_some() {
            return Ok(None);
        }
        // The same seat and lane limits a create checks first: a launch they refuse is not held.
        self.admit_fresh(launch, Some(&launch.labels.run_id))
            .await?;
        let state_node = self.admit_continuation(launch).await?;
        crate::placement::choose_node(
            &self.client,
            &launch.node_requirements(),
            launch_reservation(launch),
            launch
                .initial_target_node
                .as_deref()
                .or(state_node.as_deref()),
            launch_data(launch),
        )
        .await
        .map(Some)
    }

    /// Refuses a continuation unless it names another finished run of the same profile, seat,
    /// lane, and project whose state claim still exists. Returns the node holding that state.
    pub(super) async fn admit_continuation(
        &self,
        launch: &JobLaunch,
    ) -> Result<Option<String>, KubeError> {
        let Some(from) = &launch.continue_from else {
            return Ok(None);
        };
        let Some(plan) = &launch.workload else {
            return Err(KubeError::rejected(
                "continueFrom takes over a run's state; this profile declares no state",
            ));
        };
        if from == &launch.labels.run_id {
            return Err(KubeError::rejected("a run cannot continue from itself"));
        }
        let stored = self.journal.load_launch(from)?.ok_or_else(|| {
            KubeError::rejected(format!("continueFrom run {from} is not a known pod run"))
        })?;
        let profile = stored
            .workload
            .as_ref()
            .map(|stored| stored.profile.as_str());
        if profile != Some(plan.profile.as_str()) {
            return Err(KubeError::rejected(format!(
                "continueFrom run {from} ran profile {}, not {}",
                profile.unwrap_or("(none)"),
                plan.profile
            )));
        }
        let (old, new) = (&stored.labels, &launch.labels);
        if old.seat_id != new.seat_id
            || old.lane_id != new.lane_id
            || old.project_id != new.project_id
        {
            return Err(KubeError::rejected(format!(
                "continueFrom run {from} belongs to seat {}, lane {}, project {}; this launch is \
                 seat {}, lane {}, project {}",
                old.seat_id, old.lane_id, old.project_id, new.seat_id, new.lane_id, new.project_id
            )));
        }
        if let Some(job) = self.get_job(&crate::job::job_name(from)).await? {
            if !super::orphans::job_finished(&job) {
                return Err(KubeError::rejected(format!(
                    "continueFrom run {from} is still live (running or paused); cancel it or let \
                     it finish first"
                )));
            }
        }
        let mut holder =
            crate::workload::state_binding(&self.client, &launch.labels.run_id).await?;
        if holder.is_none() {
            holder = crate::workload::state_binding(&self.client, from).await?;
        }
        if holder.is_none() {
            holder = crate::workload::continued_state_binding(&self.client, &launch.labels.run_id)
                .await?;
        }
        let holder = holder.ok_or_else(|| {
            KubeError::rejected(format!(
                "continueFrom run {from}'s state claim is gone; there is no state to continue from"
            ))
        })?;
        let node = holder
            .admitted_nodes
            .filter(|nodes| nodes.len() == 1)
            .and_then(|mut nodes| nodes.pop());
        if let (Some(target), Some(node)) = (launch.initial_target_node.as_deref(), node.as_deref())
        {
            if target != node {
                return Err(KubeError::rejected(format!(
                    "continueFrom run {from}'s state is on {node}, not target node {target}"
                )));
            }
        }
        Ok(node)
    }

    pub(super) async fn create_job(
        &self,
        launch: &JobLaunch,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<JobObservation, KubeError> {
        self.create_job_on(
            launch,
            launch
                .admitted_node
                .as_deref()
                .or(launch.initial_target_node.as_deref()),
            None,
            operation,
            progress,
        )
        .await
    }

    // Restart uses its supplied target, including None, rather than inheriting the initial target.
    // A restart passes the old Job's remaining time; the admitted launch keeps its declared deadline.
    pub(super) async fn create_job_on(
        &self,
        launch: &JobLaunch,
        target: Option<&str>,
        deadline: Option<i64>,
        operation: &str,
        progress: &mut Progress,
    ) -> Result<JobObservation, KubeError> {
        let campaign_remaining = campaign_deadline(launch, target)?;
        let target = launch
            .campaign_reservation
            .as_ref()
            .map(|reservation| reservation.approved_node.as_str())
            .or(target);
        let deadline = match (deadline, campaign_remaining) {
            (Some(existing), Some(remaining)) => Some(existing.min(remaining)),
            (None, Some(remaining)) => Some(remaining),
            (existing, None) => existing,
        };
        // Reject conflicting run definitions before staging or API writes.
        self.journal.save_launch(launch)?;
        let name = launch.job_name();
        let mut unresolved_hosts = std::collections::BTreeMap::new();
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
                // Boxed: the continuation's futures would otherwise enlarge every create's.
                Box::pin(self.admit_continuation(launch)).await?;
                let prepared = self.artifacts.prepare_stage(
                    &launch.labels,
                    &launch.staging,
                    launch.checkpoint.as_ref(),
                )?;

                // Hosts resolve before the claim exists, so a refusal leaves
                // no volume. The claim is created next, then the resolved policy.
                let mut target = target.map(str::to_owned);
                if let Some(plan) = &launch.workload {
                    let resolved = crate::workload::resolve_declared_hosts(plan).await?;
                    if let Some(from) = &launch.continue_from {
                        // Node-local state pins the continuation to the node that holds it.
                        let nodes = Box::pin(crate::workload::hand_over_state_claim(
                            &self.client,
                            from,
                            &launch.labels.run_id,
                            plan,
                        ))
                        .await?;
                        if let ([node], None) = (nodes.as_slice(), &target) {
                            target = Some(node.clone());
                        }
                    }
                    crate::workload::ensure_state_claim(&self.client, &launch.labels.run_id, plan)
                        .await?;
                    crate::workload::ensure_resolved_egress_policy(
                        &self.client,
                        &launch.labels.run_id,
                        &resolved,
                    )
                    .await?;
                    unresolved_hosts = resolved.unresolved;
                    if let Some(target) = target.as_deref() {
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
                if launch
                    .workload
                    .as_ref()
                    .is_some_and(|plan| plan.control.is_some())
                {
                    crate::control::ensure_control_map(&self.client, &name, &launch.labels).await?;
                }
                self.journal
                    .save_staged_paths(&launch.labels.run_id, &staged.staged_paths)?;
                let node = crate::placement::choose_node(
                    &self.client,
                    &launch.node_requirements(),
                    launch_reservation(launch),
                    target.as_deref(),
                    launch_data(launch),
                )
                .await?;
                let pins = match launch.workload.as_ref() {
                    Some(plan)
                        if plan.transport == odin_registry::WorkloadTransport::VpnRequired =>
                    {
                        Some(protected_pins(plan).await?)
                    }
                    _ => None,
                };
                let desired = build_suspended_job(launch, &staged, &node, pins, deadline)?;
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
        if launch.workload.is_some() {
            crate::workload::own_egress_policy(&self.client, &launch.labels.run_id, &job).await?;
        }
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
        let mut observation = self.owned_observation(&live)?;
        observation.unresolved_hosts = unresolved_hosts;
        Ok(observation)
    }

    async fn create_job_object(&self, desired: &Job) -> Result<Job, KubeError> {
        let result = tokio::time::timeout(
            self.client.config.request_timeout,
            self.client.jobs().create(&PostParams::default(), desired),
        )
        .await
        .map_err(|error| KubeError::unavailable(format!("Job create timed out: {error}")))?;
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
mod job_worker_correlation_tests {}

#[cfg(test)]
mod launch_shape_tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::core::v1::{ConfigMap, Volume, VolumeMount};
    use odin_domain::huginn::{KubeJobLabels, KubeStagingProjection};
    use odin_domain::{AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
    use odin_types::{OperationId, WorkerId};

    use super::{
        build_suspended_job, launch_reservation, StagedVolumes, TRANSPORT_RESERVATION,
        WORKER_CPU_MILLIS, WORKER_MEMORY_BYTES,
    };
    use crate::job::JobLaunch;

    fn launch(gpu_count: u32, deadline_seconds: Option<u32>) -> JobLaunch {
        JobLaunch {
            label: None,
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
            budget_lane: None,
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
            admitted_node: None,
            campaign_reservation: None,
            gpu_count,
            gpu_min_vram_gib: None,
            gpu_vram_gib: None,
            tolerate: Default::default(),
            deadline_seconds,
            service: false,
            workload: None,
            extension: None,
            models_config: None,
            continue_from: None,
            operation_id: OperationId::new("op-launch-shape").expect("operation id"),
            idempotency_digest: Digest::hash(b"launch-shape"),
        }
    }

    #[test]
    fn campaign_binding_survives_serialization_and_restricts_node_and_budget() {
        let mut launch = launch(0, Some(300));
        let mut plan = workload_plan();
        plan.agent = None;
        plan.resources = Some(crate::workload::WorkloadResources {
            cpu: 2,
            memory_bytes: 1024,
            shm_bytes: None,
        });
        launch.workload = Some(plan);
        launch.initial_target_node = Some("mini".to_owned());
        let now = k8s_openapi::jiff::Timestamp::now().as_second();
        launch.campaign_reservation = Some(crate::job::CampaignReservation {
            approved_node: "mini".to_owned(),
            core_millis_seconds: 600_000,
            expires_at_unix_seconds: now + 60,
        });
        launch.validate().expect("valid campaign binding");
        let encoded = serde_json::to_string(&launch).unwrap();
        let replay: JobLaunch = serde_json::from_str(&encoded).unwrap();
        assert_eq!(replay, launch);
        assert!(super::campaign_deadline(&replay, Some("other")).is_err());
        assert!(super::campaign_deadline(&replay, None).unwrap().unwrap() <= 60);
        launch
            .campaign_reservation
            .as_mut()
            .unwrap()
            .core_millis_seconds -= 1;
        assert!(launch.validate().is_err());
        launch
            .campaign_reservation
            .as_mut()
            .unwrap()
            .expires_at_unix_seconds = now - 1;
        assert!(super::campaign_deadline(&launch, None).is_err());
    }

    fn workload_plan() -> crate::workload::WorkloadPodPlan {
        let plan = crate::workload::WorkloadPodPlan {
            resources: None,
            termination_grace_seconds: None,
            data: Vec::new(),
            control: None,
            keep_finished_seconds: None,
            on_yield: Default::default(),
            script_gateway: None,
            profile: "browser-container-fixture".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            state_carry: true,
            allow_hosts: vec![],
            network_open: false,
            transport: odin_registry::WorkloadTransport::Direct,
            vpn: None,
            report_pdf: false,
            report_downloads_root: None,
            export_deliver_root: None,
            company: None,
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
        let job = build_suspended_job(&launch, &staged(), "pc", None, None).expect("suspended job");
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
    fn a_protected_plan_launches_an_isolated_transport_sidecar() {
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
        let mut plan = workload_plan();
        plan.transport = odin_registry::WorkloadTransport::VpnRequired;
        plan.network_open = true;
        plan.agent.as_mut().expect("agent").gateway.host = "100.64.0.12".to_owned();
        plan.vpn = Some(crate::workload::WorkloadVpnTransportPlan {
            endpoint: "192.168.15.5".parse().expect("endpoint"),
            port: 8421,
            dns: "198.18.0.1".parse().expect("dns"),
            launcher: "/odin/bin/odin-vpn-tun".to_owned(),
            resolver: None,
            forwarded: None,
        });
        plan.validate().expect("protected plan");
        launch.workload = Some(plan);
        let job = build_suspended_job(
            &launch,
            &staged(),
            "pc",
            Some((
                vec!["100.64.0.12".parse().expect("gateway")],
                14000,
                Vec::new(),
            )),
            None,
        )
        .expect("protected job");
        let spec = job.spec.expect("spec").template.spec.expect("pod spec");
        assert_eq!(spec.dns_policy.as_deref(), Some("None"));
        assert_eq!(
            spec.dns_config.expect("dns").nameservers,
            Some(vec!["198.18.0.1".to_owned()])
        );
        let transport = spec
            .init_containers
            .expect("sidecars")
            .into_iter()
            .find(|container| container.name == "transport")
            .expect("transport sidecar");
        let added = transport
            .security_context
            .as_ref()
            .expect("security")
            .capabilities
            .as_ref()
            .expect("capabilities")
            .add
            .as_ref()
            .expect("added");
        assert_eq!(added.as_slice(), ["NET_ADMIN"]);
        let requests = transport
            .resources
            .as_ref()
            .and_then(|resources| resources.requests.as_ref())
            .expect("transport requests");
        assert_eq!(requests["cpu"].0, "250m");
        let worker = &spec.containers[0];
        assert!(worker
            .security_context
            .as_ref()
            .and_then(|context| context.capabilities.as_ref())
            .and_then(|caps| caps.add.as_ref())
            .is_none_or(|added| added.is_empty()));
    }

    #[test]
    fn a_declared_reservation_adds_only_the_containers_the_pod_runs() {
        let gib = 1024 * 1024 * 1024;
        let mut plan = workload_plan();
        plan.resources = Some(crate::workload::WorkloadResources {
            cpu: 1,
            memory_bytes: gib,
            shm_bytes: None,
        });
        let mut launch = launch(0, None);
        // Obscura runs no browser container and no transport: the declared worker alone.
        plan.agent.as_mut().expect("agent").browser_engine = odin_registry::BrowserEngine::Obscura;
        launch.workload = Some(plan.clone());
        let request = launch_reservation(&launch);
        assert_eq!((request.cpu_millis, request.memory_bytes), (1_000, gib));
        // Chromium adds one browser container share.
        plan.agent.as_mut().expect("agent").browser_engine =
            odin_registry::BrowserEngine::ChromiumHeadless;
        launch.workload = Some(plan.clone());
        let request = launch_reservation(&launch);
        assert_eq!(request.cpu_millis, 1_000 + WORKER_CPU_MILLIS);
        assert_eq!(request.memory_bytes, gib + WORKER_MEMORY_BYTES);
        // A protected pod adds the lean transport share, not a worker's.
        plan.transport = odin_registry::WorkloadTransport::VpnRequired;
        plan.vpn = Some(crate::workload::WorkloadVpnTransportPlan {
            endpoint: "192.168.15.5".parse().expect("endpoint"),
            port: 8421,
            dns: "198.18.0.1".parse().expect("dns"),
            launcher: "/odin/bin/odin-vpn-tun".to_owned(),
            resolver: None,
            forwarded: None,
        });
        launch.workload = Some(plan);
        let request = launch_reservation(&launch);
        assert_eq!(
            request.cpu_millis,
            1_000 + WORKER_CPU_MILLIS + TRANSPORT_RESERVATION.cpu_millis
        );
        assert_eq!(
            request.memory_bytes,
            gib + WORKER_MEMORY_BYTES + TRANSPORT_RESERVATION.memory_bytes
        );
    }

    #[test]
    fn a_profile_reservation_is_requested_and_fits_placement() {
        let gib = 1024 * 1024 * 1024;
        let mut launch = launch(0, None);
        let mut plan = workload_plan();
        plan.agent = None;
        plan.resources = Some(crate::workload::WorkloadResources {
            cpu: 6,
            memory_bytes: 4 * gib,
            shm_bytes: None,
        });
        launch.workload = Some(plan);
        let job = build_suspended_job(&launch, &staged(), "pc", None, None).expect("suspended job");
        let spec = job
            .spec
            .as_ref()
            .expect("job spec")
            .template
            .spec
            .as_ref()
            .expect("pod spec");
        let worker = &spec.containers[0];
        let requests = worker
            .resources
            .as_ref()
            .and_then(|resources| resources.requests.as_ref())
            .expect("worker requests");
        assert_eq!(requests["cpu"].0, "6000m");
        assert_eq!(requests["memory"].0, (4 * gib).to_string());
        let request = launch_reservation(&launch);
        assert_eq!(request.cpu_millis, 6_000);
        assert_eq!(request.memory_bytes, 4 * gib);
        // The placement fit check reads the same declared request: a 4-CPU node
        // refuses it, an 8-CPU node with the same memory admits it.
        let node = |cpu: &str| -> k8s_openapi::api::core::v1::Node {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "v1",
                "kind": "Node",
                "metadata": { "name": "pc", "labels": { "node-restriction.kubernetes.io/odin-trust": "fleet" } },
                "status": {
                    "conditions": [{ "type": "Ready", "status": "True" }],
                    "allocatable": {
                        "cpu": cpu, "memory": "8Gi", "ephemeral-storage": "8Gi", "pods": "10"
                    }
                }
            }))
            .expect("node fixture")
        };
        let allowed = std::collections::BTreeSet::from(["pc".to_owned()]);
        let labels = crate::placement::NodeRequirements::default();
        assert!(crate::placement::select_node(
            vec![node("4")],
            &[],
            &allowed,
            &labels,
            request,
            None,
        )
        .is_err());
        assert_eq!(
            crate::placement::select_node(vec![node("8")], &[], &allowed, &labels, request, None)
                .expect("the 8-CPU node fits"),
            "pc"
        );
    }

    fn pod_spec(launch: &JobLaunch) -> k8s_openapi::api::core::v1::PodSpec {
        build_suspended_job(launch, &staged(), "pc", None, None)
            .expect("suspended job")
            .spec
            .and_then(|spec| spec.template.spec)
            .expect("pod spec")
    }

    #[test]
    fn script_worker_receives_the_admitted_image_manifest_digest() {
        let mut launch = launch(0, None);
        let digest = format!("sha256:{}", "a".repeat(64));
        launch.image = format!("registry.example/worker:tag@{digest}");
        let mut plan = workload_plan();
        plan.agent = None;
        launch.workload = Some(plan);

        let pod = pod_spec(&launch);
        let env = pod.containers[0].env.as_ref().expect("worker environment");
        let matching: Vec<_> = env
            .iter()
            .filter(|var| var.name == "ODIN_IMAGE_DIGEST")
            .collect();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].value.as_deref(), Some(digest.as_str()));
        assert!(matching[0].value_from.is_none());

        // The value comes from the resolved image, not the profile identity or a tag.
        launch.image = format!("registry.example/other@sha256:{}", "b".repeat(64));
        let pod = pod_spec(&launch);
        let value = pod.containers[0]
            .env
            .as_ref()
            .unwrap()
            .iter()
            .find(|var| var.name == "ODIN_IMAGE_DIGEST")
            .unwrap();
        assert_eq!(
            value.value.as_deref(),
            launch.image.split_once('@').map(|(_, digest)| digest)
        );
    }

    #[test]
    fn image_digest_is_not_injected_for_agents_or_unpinned_images() {
        let mut launch = launch(0, None);
        launch.image = format!("registry.example/worker@sha256:{}", "a".repeat(64));
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
        let has_digest = |pod: &k8s_openapi::api::core::v1::PodSpec| {
            pod.containers[0]
                .env
                .iter()
                .flatten()
                .any(|var| var.name == "ODIN_IMAGE_DIGEST")
        };
        assert!(!has_digest(&pod_spec(&launch)));
        launch.workload.as_mut().unwrap().agent = None;
        launch.models_config = None;
        for image in [
            "registry.example/worker:tag",
            "registry.example/worker@sha256:bad",
        ] {
            launch.image = image.to_owned();
            assert!(!has_digest(&pod_spec(&launch)));
        }
        launch.workload = None;
        assert!(!has_digest(&pod_spec(&launch)));
    }

    #[test]
    fn a_declared_shm_mounts_a_memory_backed_dev_shm() {
        let gib = 1024 * 1024 * 1024;
        let mut launch = launch(0, None);
        let mut plan = workload_plan();
        plan.agent = None;
        plan.resources = Some(crate::workload::WorkloadResources {
            cpu: 2,
            memory_bytes: 4 * gib,
            shm_bytes: Some(gib),
        });
        launch.workload = Some(plan);
        let spec = pod_spec(&launch);
        let volume = spec
            .volumes
            .iter()
            .flatten()
            .find_map(|volume| {
                volume
                    .empty_dir
                    .as_ref()
                    .filter(|_| volume.name == "odin-shm")
            })
            .expect("shm volume");
        assert_eq!(volume.medium.as_deref(), Some("Memory"));
        assert_eq!(
            volume.size_limit.as_ref().map(|q| q.0.clone()),
            Some(gib.to_string())
        );
        let mounted = |container: &k8s_openapi::api::core::v1::Container| {
            container
                .volume_mounts
                .iter()
                .flatten()
                .any(|mount| mount.mount_path == "/dev/shm")
        };
        assert!(mounted(&spec.containers[0]));
        assert!(!spec.init_containers.iter().flatten().any(mounted));
    }

    #[test]
    fn declared_data_mounts_are_read_only_host_paths() {
        let mut launch = launch(0, None);
        let mut plan = workload_plan();
        plan.agent = None;
        plan.data = vec![crate::workload::WorkloadDataMount {
            name: "stage".to_owned(),
            host_path: "/srv/project/stage".to_owned(),
            pod_path: "/stage".to_owned(),
        }];
        launch.workload = Some(plan);
        let spec = pod_spec(&launch);
        let volume = spec
            .volumes
            .iter()
            .flatten()
            .find(|volume| volume.name == "odin-data-stage")
            .and_then(|volume| volume.host_path.as_ref())
            .expect("data volume");
        assert_eq!(volume.path, "/srv/project/stage");
        let mount = spec.containers[0]
            .volume_mounts
            .iter()
            .flatten()
            .find(|mount| mount.mount_path == "/stage")
            .expect("data mount");
        assert_eq!(mount.read_only, Some(true));
        assert_eq!(mount.recursive_read_only.as_deref(), Some("IfPossible"));
    }

    #[test]
    fn a_declared_stop_grace_reaches_the_pod_spec() {
        let mut launch = launch(0, None);
        let mut plan = workload_plan();
        plan.agent = None;
        launch.workload = Some(plan.clone());
        assert_eq!(pod_spec(&launch).termination_grace_period_seconds, None);
        plan.termination_grace_seconds = Some(120);
        launch.workload = Some(plan);
        assert_eq!(
            pod_spec(&launch).termination_grace_period_seconds,
            Some(120)
        );
    }

    #[test]
    fn a_profile_with_data_only_lands_on_nodes_declaring_the_root() {
        let data = [crate::workload::WorkloadDataMount {
            name: "stage".to_owned(),
            host_path: "/srv/project/stage/sweep-1".to_owned(),
            pod_path: "/stage".to_owned(),
        }];
        let config = crate::KubeConfig {
            kubeconfig: "/nonexistent/kubeconfig".into(),
            cluster: "fixture".to_owned(),
            namespace: "default".to_owned(),
            allowed_nodes: ["mini", "pc"].map(str::to_owned).into(),
            node_data_roots: [(
                "pc".to_owned(),
                std::collections::BTreeSet::from(["/srv/project/stage".to_owned()]),
            )]
            .into(),
            request_timeout: std::time::Duration::from_secs(5),
            teardown_timeout: std::time::Duration::from_secs(5),
            vpn_transport: None,
        };
        assert_eq!(
            crate::placement::data_admitting(&config, &data),
            std::collections::BTreeSet::from(["pc".to_owned()])
        );
        assert!(crate::placement::node_covers(&config, "mini", &[]));
        assert!(!crate::placement::node_covers(&config, "mini", &data));
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
                "labels": {"odin.capability/portable": "true", "node-restriction.kubernetes.io/odin-trust": "fleet"}},
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
                    // A merge patch's null removes the field (RFC 7386).
                    if field.is_null() {
                        value.remove(&key);
                        continue;
                    }
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
                    "persistentvolumes" => "PersistentVolumeList",
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
                    | "persistentvolumes"
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
                    node_data_roots: Default::default(),
                    request_timeout: std::time::Duration::from_secs(2),
                    teardown_timeout: std::time::Duration::from_secs(2),
                    vpn_transport: None,
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
    async fn admitted_node_rehomes_to_pc_preserving_shared_state_and_profile() {
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
        launch.initial_target_node = None;
        launch.admitted_node = Some("mini".to_owned());
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
            None,
            "host selection does not change the caller's declaration"
        );
        assert_eq!(stored.admitted_node.as_deref(), Some("mini"));
        assert_eq!(stored.workload, launch.workload);
        assert_eq!(stored.checkpoint, launch.checkpoint);
        assert_eq!(stored.image, launch.image);
        assert_eq!(stored.command, launch.command);
        assert_eq!(stored.args, launch.args);
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(state.created_jobs.len(), 2);
        assert_placement(&state.created_jobs[1], "pc", &launch);
        // The sim never starts the old Job, so the restart keeps the launch's own deadline.
        assert_eq!(
            state.created_jobs[1]["spec"]["activeDeadlineSeconds"],
            serde_json::json!(300)
        );
        assert_eq!(
            state.objects[&claim_path], claim,
            "same bound claim retains its state binding"
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
    async fn caller_target_remains_distinct_from_host_selection() {
        let fixture = PlacementFixture::new(&["alpha", "mini"]);
        fixture
            .api
            .state
            .lock()
            .expect("API state")
            .nodes
            .push(placement_node("alpha"));
        let launch = portable_launch();
        fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("targeted create");
        let state = fixture.api.state.lock().expect("API state");
        assert_placement(&state.created_jobs[0], "mini", &launch);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restart_with_target_refuses_a_non_carry_state() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let mut launch = portable_launch();
        launch.workload.as_mut().expect("plan").state_carry = false;
        let first = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("targeted create");
        let claim_path = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&launch.labels.run_id)
        );
        {
            let mut state = fixture.api.state.lock().expect("API state");
            // A node-local volume on mini: moving it to pc would tar the state.
            state
                .objects
                .get_mut(&claim_path)
                .expect("created state claim")["spec"]["volumeName"] =
                serde_json::json!("local-volume");
            state.objects.insert("/api/v1/persistentvolumes/local-volume".to_owned(), serde_json::json!({
                "apiVersion":"v1", "kind":"PersistentVolume", "metadata":{"name":"local-volume"},
                "spec":{"capacity":{"storage":"2Gi"}, "accessModes":["ReadWriteOnce"],
                    "nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[
                        {"key":"kubernetes.io/hostname","operator":"In","values":["mini"]}]}]}}}
            }));
        }
        let refused = fixture
            .reconciler
            .operate(restart_action(&launch, &first, Some("pc")))
            .await
            .expect_err("a non-carry state does not rehome");
        assert!(
            refused.to_string().contains("state.carry = false"),
            "names the cause: {refused}"
        );
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(state.created_jobs.len(), 1, "the old Job keeps running");
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
            .reap_marked_residue(time::OffsetDateTime::now_utc())
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
    async fn a_finished_job_is_deleted_after_its_grace_and_its_residue_follows() {
        let finished = time::macros::datetime!(2026-10-20 12:00 UTC);
        let complete = serde_json::json!({
            "completionTime": "2026-10-20T12:00:00Z",
            "conditions": [{"type": "Complete", "status": "True"}]
        });
        let failed = serde_json::json!({
            "conditions": [{"type": "Failed", "status": "True",
                "lastTransitionTime": "2026-10-20T12:00:00Z"}]
        });
        for (ended, status) in [("Complete", complete), ("Failed", failed)] {
            let fixture = PlacementFixture::new(&["mini", "pc"]);
            let launch = fixture.agent_launch("192.0.2.10");
            fixture
                .reconciler
                .create(launch.clone())
                .await
                .expect("launch");
            let run = &launch.labels.run_id;
            let job = format!(
                "/apis/batch/v1/namespaces/default/jobs/{}",
                crate::job::job_name(run)
            );
            let claim = format!(
                "/api/v1/namespaces/default/persistentvolumeclaims/{}",
                crate::workload::state_claim_name(run)
            );
            let policy = format!(
                "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies/{}",
                crate::workload::egress_policy_name(run)
            );
            fixture
                .api
                .state
                .lock()
                .expect("API state")
                .objects
                .get_mut(&job)
                .expect("job")["status"] = status;
            fixture
                .reconciler
                .reap_marked_residue(finished + time::Duration::hours(23))
                .await
                .expect("sweep inside the grace");
            assert!(
                fixture
                    .api
                    .state
                    .lock()
                    .expect("API state")
                    .objects
                    .contains_key(&job),
                "a {ended} Job 23 h old is still listed"
            );
            fixture
                .reconciler
                .reap_marked_residue(finished + time::Duration::hours(25))
                .await
                .expect("sweep past the grace");
            assert!(
                !fixture
                    .api
                    .state
                    .lock()
                    .expect("API state")
                    .objects
                    .contains_key(&job),
                "a {ended} Job 25 h old is deleted"
            );
            fixture
                .reconciler
                .reap_marked_residue(finished + time::Duration::hours(25))
                .await
                .expect("the next sweep reaps the gone run's residue");
            let state = fixture.api.state.lock().expect("API state");
            assert!(
                !state.objects.contains_key(&claim),
                "{ended}: claim deleted"
            );
            assert!(
                !state.objects.contains_key(&policy),
                "{ended}: policy deleted"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_paused_run_suspends_its_job_and_resume_starts_it_again() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let launch = fixture.agent_launch("192.0.2.10");
        let created = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("launch");
        let act = |kind, observation: &crate::JobObservation, op: &str| crate::JobAction {
            run_id: launch.labels.run_id.clone(),
            kind,
            expected_resource_version: observation.projection.identity.resource_version.clone(),
            operation_id: OperationId::new(op).expect("operation"),
            idempotency_digest: Digest::hash(op.as_bytes()),
            target_node: None,
        };
        let paused = fixture
            .reconciler
            .operate(act(
                odin_domain::huginn::KubeOperationKind::Pause,
                &created,
                "op-placement-pause",
            ))
            .await
            .expect("pause");
        let job_path = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            crate::job::job_name(&launch.labels.run_id)
        );
        let suspended = |fixture: &PlacementFixture| {
            fixture.api.state.lock().expect("API state").objects[&job_path]["spec"]["suspend"]
                .as_bool()
        };
        assert_eq!(suspended(&fixture), Some(true), "pause suspends the Job");
        {
            let mut state = fixture.api.state.lock().expect("API state");
            let job = state.objects.get_mut(&job_path).expect("suspended Job");
            job["status"]["startTime"] = serde_json::json!("2026-01-01T00:00:00Z");
            job["status"]["conditions"] = serde_json::json!([{
                "type": "Suspended", "status": "True",
                "lastTransitionTime": "2026-01-01T00:01:00Z"
            }]);
        }
        fixture
            .reconciler
            .operate(act(
                odin_domain::huginn::KubeOperationKind::Resume,
                &paused,
                "op-placement-resume",
            ))
            .await
            .expect("resume");
        assert_eq!(suspended(&fixture), Some(false), "resume releases the Job");
        let state = fixture.api.state.lock().expect("API state");
        assert_eq!(
            state.objects[&job_path]["spec"]["activeDeadlineSeconds"],
            serde_json::json!(launch.deadline_seconds),
            "resume retains the original deadline for Kubernetes to restart"
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

    /// The finished first run whose claim holds node-local state on pc, and its continuation.
    async fn finished_run_with_state_on_pc(fixture: &PlacementFixture) -> (JobLaunch, JobLaunch) {
        let first = portable_launch();
        fixture
            .reconciler
            .create(first.clone())
            .await
            .expect("first run");
        let claim_path = format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&first.labels.run_id)
        );
        {
            let mut state = fixture.api.state.lock().expect("API state");
            state.objects.get_mut(&claim_path).expect("first claim")["spec"]["volumeName"] =
                serde_json::json!("counter-volume");
            state.objects.insert(
                "/api/v1/persistentvolumes/counter-volume".to_owned(),
                serde_json::json!({
                    "apiVersion":"v1", "kind":"PersistentVolume",
                    "metadata":{"name":"counter-volume", "uid":"counter-volume-uid"},
                    "spec":{"capacity":{"storage":"2Gi"}, "accessModes":["ReadWriteOnce"],
                        "storageClassName":"local-path",
                        "persistentVolumeReclaimPolicy":"Delete",
                        "claimRef":{"namespace":"default", "name":
                            crate::workload::state_claim_name(&first.labels.run_id),
                            "uid":"first-claim-uid"},
                        "nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchFields":[
                            {"key":"metadata.name", "operator":"In", "values":["pc"]}]}]}}}
                }),
            );
        }
        let mut next = first.clone();
        next.labels.run_id = RunId::new("run-launch-shape-next").expect("run id");
        next.worker_id = WorkerId::new("worker-launch-shape-next").expect("worker id");
        next.operation_id = OperationId::new("op-launch-shape-next").expect("operation id");
        next.idempotency_digest = Digest::hash(b"launch-shape-next");
        next.initial_target_node = None;
        next.continue_from = Some(first.labels.run_id.clone());
        (first, next)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continuation_recovers_after_old_claim_was_released() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let (first, next) = finished_run_with_state_on_pc(&fixture).await;
        {
            let mut state = fixture.api.state.lock().expect("API state");
            let job = format!(
                "/apis/batch/v1/namespaces/default/jobs/{}",
                first.job_name()
            );
            mark_job_complete(&mut state, &job);
            let claim = format!(
                "/api/v1/namespaces/default/persistentvolumeclaims/{}",
                crate::workload::state_claim_name(&first.labels.run_id)
            );
            state.objects.remove(&claim);
            let pv = state
                .objects
                .get_mut("/api/v1/persistentvolumes/counter-volume")
                .unwrap();
            pv["metadata"]["annotations"] = serde_json::json!({
                crate::workload::CONTINUED_BY: crate::workload::state_claim_name(&next.labels.run_id)
            });
            pv["spec"]["persistentVolumeReclaimPolicy"] = serde_json::json!("Retain");
        }
        fixture
            .reconciler
            .create(next.clone())
            .await
            .expect("replayed handover");
        let state = fixture.api.state.lock().expect("API state");
        let new_claim = crate::workload::state_claim_name(&next.labels.run_id);
        let claim = &state.objects
            [&format!("/api/v1/namespaces/default/persistentvolumeclaims/{new_claim}")];
        assert_eq!(claim["spec"]["volumeName"], "counter-volume");
        let pv = &state.objects["/api/v1/persistentvolumes/counter-volume"];
        assert_eq!(pv["spec"]["claimRef"]["name"], new_claim);
        assert_eq!(pv["spec"]["persistentVolumeReclaimPolicy"], "Delete");
        assert!(pv["metadata"]["annotations"][crate::workload::CONTINUED_BY].is_null());
        assert_placement(&state.created_jobs[1], "pc", &next);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continue_from_reuses_the_finished_runs_claim_on_its_node() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let (first, next) = finished_run_with_state_on_pc(&fixture).await;
        {
            let mut state = fixture.api.state.lock().expect("API state");
            let job = format!(
                "/apis/batch/v1/namespaces/default/jobs/{}",
                crate::job::job_name(&first.labels.run_id)
            );
            mark_job_complete(&mut state, &job);
        }
        fixture
            .reconciler
            .create(next.clone())
            .await
            .expect("continuation");
        let state = fixture.api.state.lock().expect("API state");
        let claims = "/api/v1/namespaces/default/persistentvolumeclaims";
        let new_claim = crate::workload::state_claim_name(&next.labels.run_id);
        assert!(
            !state.objects.contains_key(&format!(
                "{claims}/{}",
                crate::workload::state_claim_name(&first.labels.run_id)
            )),
            "the finished run's claim is released"
        );
        let claim = &state.objects[&format!("{claims}/{new_claim}")];
        assert_eq!(claim["spec"]["volumeName"], "counter-volume");
        assert_eq!(
            claim["metadata"]["labels"][crate::job::JOB_LABEL_RUN_ID],
            crate::job::bounded_label_value(next.labels.run_id.as_str())
        );
        let pv = &state.objects["/api/v1/persistentvolumes/counter-volume"];
        assert_eq!(pv["spec"]["claimRef"]["name"], new_claim.as_str());
        assert_eq!(pv["spec"]["persistentVolumeReclaimPolicy"], "Delete");
        assert!(pv["metadata"]["annotations"][crate::workload::CONTINUED_BY].is_null());
        // No target was named: the volume's node places the continuation.
        assert_placement(&state.created_jobs[1], "pc", &next);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continuation_refuses_a_different_target_before_moving_state() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let (first, mut next) = finished_run_with_state_on_pc(&fixture).await;
        {
            let mut state = fixture.api.state.lock().expect("API state");
            let job = format!(
                "/apis/batch/v1/namespaces/default/jobs/{}",
                crate::job::job_name(&first.labels.run_id)
            );
            mark_job_complete(&mut state, &job);
        }
        next.initial_target_node = Some("mini".to_owned());
        let error = fixture
            .reconciler
            .create(next)
            .await
            .expect_err("wrong node");
        assert!(error.to_string().contains("not target node"), "{error}");
        let state = fixture.api.state.lock().expect("API state");
        assert!(state.objects.contains_key(&format!(
            "/api/v1/namespaces/default/persistentvolumeclaims/{}",
            crate::workload::state_claim_name(&first.labels.run_id)
        )));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn continue_from_refuses_a_live_unknown_or_foreign_run() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let (first, next) = finished_run_with_state_on_pc(&fixture).await;
        let refusal = |result: Result<Option<String>, crate::KubeError>| match result {
            Err(crate::KubeError::Rejected { reason }) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        };
        let live = refusal(fixture.reconciler.room_for(&next).await);
        assert!(live.contains("still live"), "{live}");
        let mut unknown = next.clone();
        unknown.continue_from = Some(RunId::new("run-never-launched").expect("run id"));
        let unknown = refusal(fixture.reconciler.room_for(&unknown).await);
        assert!(unknown.contains("not a known pod run"), "{unknown}");
        let mut foreign = next.clone();
        foreign.workload.as_mut().expect("plan").profile = "other-profile".to_owned();
        let foreign = refusal(fixture.reconciler.room_for(&foreign).await);
        assert!(foreign.contains("ran profile state-counter"), "{foreign}");
        let state = fixture.api.state.lock().expect("API state");
        assert!(
            state.objects.contains_key(&format!(
                "/api/v1/namespaces/default/persistentvolumeclaims/{}",
                crate::workload::state_claim_name(&first.labels.run_id)
            )),
            "a refused continuation leaves the finished run's state alone"
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn campaign_create_and_resume_release_with_current_wall_deadline() {
        let fixture = PlacementFixture::new(&["mini", "pc"]);
        let mut launch = portable_launch();
        launch.workload.as_mut().unwrap().resources = Some(crate::workload::WorkloadResources {
            cpu: 2,
            memory_bytes: 1024,
            shm_bytes: None,
        });
        let expiry = k8s_openapi::jiff::Timestamp::now().as_second() + 120;
        launch.campaign_reservation = Some(crate::job::CampaignReservation {
            approved_node: "mini".to_owned(),
            core_millis_seconds: 600_000,
            expires_at_unix_seconds: expiry,
        });
        let created = fixture
            .reconciler
            .create(launch.clone())
            .await
            .expect("create campaign");
        let job_path = format!(
            "/apis/batch/v1/namespaces/default/jobs/{}",
            launch.job_name()
        );
        {
            let state = fixture.api.state.lock().unwrap();
            let spec = &state.objects[&job_path]["spec"];
            assert_eq!(spec["suspend"], false);
            assert!(spec["activeDeadlineSeconds"].as_i64().unwrap() <= 120);
        }
        let action = |kind, observation: &crate::JobObservation, op: &str| crate::JobAction {
            run_id: launch.labels.run_id.clone(),
            kind,
            expected_resource_version: observation.projection.identity.resource_version.clone(),
            operation_id: OperationId::new(op).unwrap(),
            idempotency_digest: Digest::hash(op.as_bytes()),
            target_node: None,
        };
        let paused = fixture
            .reconciler
            .operate(action(
                odin_domain::huginn::KubeOperationKind::Pause,
                &created,
                "op-campaign-pause",
            ))
            .await
            .expect("pause");
        // Simulate a stale deadline left on the suspended Job before release.
        fixture
            .api
            .state
            .lock()
            .unwrap()
            .objects
            .get_mut(&job_path)
            .unwrap()["spec"]["activeDeadlineSeconds"] = serde_json::json!(300);
        fixture
            .reconciler
            .operate(action(
                odin_domain::huginn::KubeOperationKind::Resume,
                &paused,
                "op-campaign-resume",
            ))
            .await
            .expect("resume");
        let state = fixture.api.state.lock().unwrap();
        let spec = &state.objects[&job_path]["spec"];
        assert_eq!(spec["suspend"], false);
        let remaining = spec["activeDeadlineSeconds"].as_i64().unwrap();
        assert!(
            remaining > 0
                && remaining <= expiry - k8s_openapi::jiff::Timestamp::now().as_second() + 1
        );
    }
}
