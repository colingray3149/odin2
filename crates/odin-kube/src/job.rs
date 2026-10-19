//! Job launches come from trusted host profiles, never model-supplied images or argv.
//!
//! [`JOB_PROJECTION_ANNOTATION`] stores the serialized `KubeJobProjection`.
//! Observation validates its labels and rebuilds identity and lifecycle from live metadata
//! and status. The annotation is attached after the API server assigns the Job UID.
//! [`KUBE_LABEL_STAGED`] records whether staging and checkpoint ConfigMaps are verified.

/// Reject excess GPU reservations before staging or contacting the API server.
pub const MAX_LAUNCH_GPU_COUNT: u32 = 8;

/// Deadline range for container-profile launches; workloads use their profile limits.
pub const MIN_LAUNCH_DEADLINE_SECONDS: u32 = 30;
pub const MAX_LAUNCH_DEADLINE_SECONDS: u32 = 3_600;

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use odin_domain::{extension_policy, ArtifactId, Digest, RunId};
use odin_types::{OperationId, WorkerId};

pub use odin_domain::huginn::{
    KubeCheckpointProjection, KubeContentIdentity, KubeJobIdentity, KubeJobLabels,
    KubeJobLifecycle, KubeJobProjection, KubeJobProjectionSchema, KubeOperationKind,
    KubeOperationProjection, KubeResourceVersion, KubeStagingProjection, KubeWorkerBinding,
    KubeWorkloadView,
};

pub const JOB_PROJECTION_ANNOTATION: &str = "odin.dev/job-projection";
pub const JOB_LABEL_RUN_ID: &str = "odin.dev/run-id";
pub const JOB_LABEL_TASK_ID: &str = "odin.dev/task-id";
pub const JOB_LABEL_ATTEMPT_ID: &str = "odin.dev/attempt-id";
pub const JOB_LABEL_SEAT_ID: &str = "odin.dev/seat-id";
pub const JOB_LABEL_PROJECT_ID: &str = "odin.dev/project-id";
pub const JOB_LABEL_LANE_ID: &str = "odin.dev/lane-id";
pub const JOB_LABEL_MODEL: &str = "odin.dev/model";
pub const JOB_LABEL_BUDGET_POLICY_DIGEST: &str = "odin.dev/budget-policy-digest";
pub const JOB_LABEL_CONTAINER_IDENTITY: &str = "odin.dev/container-identity";
pub const JOB_LABEL_WORKER_ID: &str = "odin.dev/worker-id";
/// `true` after staging and checkpoint ConfigMaps pass digest checks.
pub const KUBE_LABEL_STAGED: &str = "odin.dev/staged";
pub const KUBE_STAGED_TRUE: &str = "true";
pub const KUBE_STAGED_FALSE: &str = "false";

/// Exec-attach targets this container rather than discovering one.
pub const JOB_WORKER_CONTAINER: &str = "odin-worker";
/// Existence selector for Jobs carrying the run-id label.
pub const KUBE_OWNED_SELECTOR: &str = JOB_LABEL_RUN_ID;

/// Kubernetes label values are at most 63 characters.
const LABEL_VALUE_BOUND: usize = 63;

pub const KUBE_STAGING_MOUNT_PATH: &str = "/var/run/odin/staging";
pub const KUBE_CHECKPOINT_MOUNT_PATH: &str = "/var/run/odin/checkpoint";
pub const KUBE_STAGING_VOLUME: &str = "odin-staging";
pub const KUBE_CHECKPOINT_VOLUME: &str = "odin-checkpoint";

pub fn staging_configmap_name(job_name: &str) -> String {
    format!("{job_name}-staging")
}

pub fn checkpoint_configmap_name(job_name: &str) -> String {
    format!("{job_name}-checkpoint")
}

/// A DNS-safe name stable across restarts; recreated Jobs receive new UIDs.
pub fn job_name(run_id: &RunId) -> String {
    let digest = Digest::hash(format!("odin-kube/job/v1/{}", run_id.as_str()).as_bytes());
    let bytes = digest.as_bytes();
    let mut name = String::with_capacity(5 + 32);
    name.push_str("odin-");
    for byte in &bytes[..16] {
        name.push(hex_nibble(byte >> 4));
        name.push(hex_nibble(byte & 0x0f));
    }
    name
}

fn hex_nibble(value: u8) -> char {
    char::from_digit((value & 0x0f) as u32, 16).expect("nibble")
}

/// True when `value` is a legal Kubernetes label value: 1..=63 bytes,
/// alphanumeric first and last, `[alnum]-._` inside.
fn valid_label_value(value: &str) -> bool {
    if value.is_empty() || value.len() > LABEL_VALUE_BOUND {
        return false;
    }
    let bound = value.as_bytes();
    let alnum = |byte: u8| byte.is_ascii_alphanumeric();
    let inner = |byte: u8| alnum(byte) || matches!(byte, b'-' | b'.' | b'_');
    alnum(bound[0]) && alnum(bound[bound.len() - 1]) && bound.iter().all(|byte| inner(*byte))
}

/// Preserves valid labels; otherwise encodes the full digest without truncation.
/// The `b` prefix and zero-padded final base64 character ensure alphanumeric endpoints.
pub fn bounded_label_value(value: &str) -> String {
    if valid_label_value(value) {
        return value.to_owned();
    }
    let digest = Digest::hash(value.as_bytes());
    format!("b{}", URL_SAFE_NO_PAD.encode(digest.as_bytes()))
}
pub fn binding_labels(labels: &KubeJobLabels) -> Vec<(&'static str, String)> {
    let mut out = Vec::with_capacity(10);
    let mut push = |key: &'static str, value: &str| out.push((key, bounded_label_value(value)));
    push(JOB_LABEL_RUN_ID, labels.run_id.as_str());
    push(JOB_LABEL_TASK_ID, labels.task_id.as_str());
    push(JOB_LABEL_ATTEMPT_ID, labels.attempt_id.as_str());
    push(JOB_LABEL_SEAT_ID, labels.seat_id.as_str());
    push(JOB_LABEL_PROJECT_ID, labels.project_id.as_str());
    push(JOB_LABEL_LANE_ID, labels.lane_id.as_str());
    push(JOB_LABEL_MODEL, &labels.model);
    push(
        JOB_LABEL_BUDGET_POLICY_DIGEST,
        &labels.budget_policy_digest.to_string(),
    );
    push(
        JOB_LABEL_CONTAINER_IDENTITY,
        &labels.container_identity.to_string(),
    );
    out
}

pub fn worker_id_label(worker_id: &WorkerId) -> (&'static str, String) {
    (JOB_LABEL_WORKER_ID, bounded_label_value(worker_id.as_str()))
}

pub fn expected_binding_labels(
    labels: &KubeJobLabels,
    worker_id: &WorkerId,
) -> Vec<(&'static str, String)> {
    let mut out = binding_labels(labels);
    out.push(worker_id_label(worker_id));
    out
}

/// Rejects missing or mismatched labels; unrelated labels are allowed.
pub fn verify_binding_labels(
    observed: &BTreeMap<String, String>,
    expected: &[(&'static str, String)],
) -> Result<(), String> {
    for (key, value) in expected {
        match observed.get(*key) {
            Some(observed_value) if observed_value == value => {}
            Some(observed_value) => {
                return Err(format!(
                    "Job label {key} is {observed_value:?}, binding requires {value:?}"
                ));
            }
            None => return Err(format!("Job is missing required binding label {key}")),
        }
    }
    Ok(())
}

/// Kubelet collapses `$$`, so double each pair to preserve literal bytes.
/// `$(VAR)` retains Kubernetes environment substitution semantics.
pub(crate) fn shell_argv_channel_encoding(arg: &str) -> String {
    arg.replace("$$", "$$$$")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobExtensionLaunch {
    /// Persisted in-image verifier path; recovery must not substitute current configuration.
    pub verifier: String,
    /// Must match `--trusted-extension` and the policy's `extension.path`.
    pub trusted_extension: String,
    /// Policy bytes mounted read-only at the journaled staging path.
    pub policy_artifact: ArtifactId,
    /// BLAKE3 digest checked by the in-pod verifier against ODIN_EXTENSION_POLICY.
    pub policy_digest: String,
}

/// Provider catalog whose `baseUrl` is the served endpoint and `apiKey` is an env name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobModelsConfigLaunch {
    /// Document bytes mounted read-only at the journaled staging path.
    pub config_artifact: ArtifactId,
    /// BLAKE3 digest checked before copying the document into the session directory.
    pub config_digest: String,
    /// Environment variable named by `apiKey`; SecretKeyRef supplies its value.
    pub credential_env: String,
}

/// Host-assembled launch from a published profile and kernel-issued worker identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobLaunch {
    pub labels: KubeJobLabels,
    pub worker_id: WorkerId,
    /// Required by workload session carriers; absent for container-profile launches.
    #[serde(default)]
    pub extension: Option<JobExtensionLaunch>,
    /// Required for agent pods because the in-pod OMP has no built-in gateway provider.
    #[serde(default)]
    pub models_config: Option<JobModelsConfigLaunch>,
    /// Read-only inputs published before Job creation so retries reuse the same content.
    #[serde(default)]
    pub staging: KubeStagingProjection,
    pub checkpoint: Option<KubeCheckpointProjection>,
    pub image: String,
    pub command: Vec<String>,
    pub args: Vec<String>,
    pub node_selector: BTreeMap<String, String>,
    /// Initial placement only; restart must supply its own rehome target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_target_node: Option<String>,
    /// GPU requests equal limits; zero reserves no GPU and the scheduler assigns devices.
    #[serde(default)]
    pub gpu_count: u32,
    /// Enforced by the Job controller via `activeDeadlineSeconds`; `None` sets no deadline.
    #[serde(default)]
    pub deadline_seconds: Option<u32>,
    /// Restarts the worker in place on failure using `restartPolicy: OnFailure`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub service: bool,
    /// State, export, and egress configuration; absent for container-profile launches.
    #[serde(default)]
    pub workload: Option<crate::workload::WorkloadPodPlan>,
    pub operation_id: OperationId,
    pub idempotency_digest: Digest,
}

impl JobLaunch {
    pub fn job_name(&self) -> String {
        job_name(&self.labels.run_id)
    }

    pub fn binding_label_map(&self) -> BTreeMap<String, String> {
        expected_binding_labels(&self.labels, &self.worker_id)
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect()
    }

    pub fn worker_binding(&self) -> KubeWorkerBinding {
        KubeWorkerBinding {
            worker_id: self.worker_id.clone(),
            container_identity: self.labels.container_identity,
        }
    }

    /// Supplies the annotation after the API server assigns identity; `operation` tracks an open claim.
    pub fn projection(
        &self,
        identity: KubeJobIdentity,
        lifecycle: KubeJobLifecycle,
        operation: Option<KubeOperationProjection>,
    ) -> KubeJobProjection {
        KubeJobProjection {
            schema: KubeJobProjectionSchema::V1,
            identity,
            labels: self.labels.clone(),
            staging: self.staging.clone(),
            checkpoint: self.checkpoint.clone(),
            lifecycle,
            worker: self.worker_binding(),
            operation,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.image.trim().is_empty() {
            return Err("job launch requires a nonempty container image".to_owned());
        }
        if self.command.is_empty() {
            return Err("job launch requires a nonempty container command".to_owned());
        }
        if self.command.iter().any(String::is_empty) || self.args.iter().any(String::is_empty) {
            return Err("job launch argv elements must be nonempty".to_owned());
        }
        if let Some(target) = &self.initial_target_node {
            let bytes = target.as_bytes();
            let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
            if bytes.is_empty()
                || bytes.len() > 63
                || !alnum(bytes[0])
                || !alnum(bytes[bytes.len() - 1])
                || !bytes
                    .iter()
                    .all(|byte| alnum(*byte) || matches!(byte, b'-' | b'.'))
            {
                return Err("job launch initial target must be a lowercase node name of 1..=63 bytes with alphanumeric endpoints".to_owned());
            }
        }
        if self.gpu_count > MAX_LAUNCH_GPU_COUNT {
            return Err(format!(
                "job launch reserves {}/{MAX_LAUNCH_GPU_COUNT} GPUs: beyond the declared bound",
                self.gpu_count
            ));
        }
        if let Some(deadline) = self.deadline_seconds {
            // Agent sessions use workload lifetime limits rather than container smoke limits.
            let (min, max) = if self.workload.is_some() {
                (
                    odin_registry::schema::MIN_WORKLOAD_DEADLINE_SECONDS,
                    odin_registry::schema::MAX_WORKLOAD_DEADLINE_SECONDS,
                )
            } else {
                (MIN_LAUNCH_DEADLINE_SECONDS, MAX_LAUNCH_DEADLINE_SECONDS)
            };
            if !(min..=max).contains(&deadline) {
                return Err(format!(
                    "job launch deadline {deadline}s is outside the declared bound {min}..={max}s"
                ));
            }
        }
        if let Some(extension) = &self.extension {
            if self.workload.is_none() {
                return Err("job launch extension binding requires a workload plan".to_owned());
            }
            if !odin_registry::schema::valid_pod_path(&extension.verifier) {
                return Err(format!(
                    "job launch extension verifier {:?} is not an absolute in-image path",
                    extension.verifier
                ));
            }
            if !odin_registry::schema::valid_pod_path(&extension.trusted_extension) {
                return Err(format!(
                    "job launch extension binding {:?} is not an absolute in-image path",
                    extension.trusted_extension
                ));
            }
            extension_policy::validate_digest(&extension.policy_digest)
                .map_err(|error| format!("job launch extension binding rejected: {error}"))?;
            let staged = self
                .staging
                .inputs
                .iter()
                .filter(|input| input.artifact_id == extension.policy_artifact)
                .collect::<Vec<_>>();
            if staged.len() != 1 || staged[0].content_digest.to_string() != extension.policy_digest
            {
                return Err(
                    "job launch extension binding does not match exactly one staging input"
                        .to_owned(),
                );
            }
        }
        if let Some(workload) = &self.workload {
            workload
                .validate()
                .map_err(|reason| format!("job launch workload binding rejected: {reason}"))?;
        }
        // Only agent pods need a models document: the launcher has no built-in gateway provider.
        let runs_agent = self
            .workload
            .as_ref()
            .map(|workload| workload.agent.is_some());
        match (runs_agent, &self.models_config) {
            (None | Some(false), None) => {}
            (None, Some(_)) => {
                return Err(
                    "job launch models binding requires a workload plan: the models document \
                     rides the workload session only"
                        .to_owned(),
                );
            }
            (Some(false), Some(_)) => {
                return Err(
                    "job launch models binding on a script pod: a script pod runs no agent and \
                     carries no models document"
                        .to_owned(),
                );
            }
            (Some(true), None) => {
                return Err(
                    "job launch agent pod requires a models document: the in-pod launcher has \
                     no built-in gateway provider"
                        .to_owned(),
                );
            }
            (Some(true), Some(models)) => {
                extension_policy::validate_digest(&models.config_digest)
                    .map_err(|error| format!("job launch models binding rejected: {error}"))?;
                if models.credential_env.trim().is_empty() {
                    return Err(
                        "job launch models binding requires a nonempty credential env name"
                            .to_owned(),
                    );
                }
                let staged = self
                    .staging
                    .inputs
                    .iter()
                    .filter(|input| input.artifact_id == models.config_artifact)
                    .collect::<Vec<_>>();
                if staged.len() != 1 || staged[0].content_digest.to_string() != models.config_digest
                {
                    return Err(
                        "job launch models binding does not match exactly one staging input"
                            .to_owned(),
                    );
                }
            }
        }
        Ok(())
    }
}

/// Addresses a run, not a Kubernetes object; the reconciler resolves the Job.
/// A stale resource version conflicts rather than overwriting; only restart uses `target_node`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobAction {
    pub run_id: RunId,
    pub kind: KubeOperationKind,
    pub expected_resource_version: KubeResourceVersion,
    pub operation_id: OperationId,
    pub idempotency_digest: Digest,
    pub target_node: Option<String>,
}

impl JobAction {
    pub fn job_name(&self) -> String {
        job_name(&self.run_id)
    }

    pub fn rehome_target(&self) -> Option<&str> {
        match self.kind {
            KubeOperationKind::Restart => self.target_node.as_deref(),
            _ => None,
        }
    }

    /// True when the action must never mutate cluster state
    /// ([`KubeOperationKind::Summarize`]).
    pub fn is_pure(&self) -> bool {
        matches!(self.kind, KubeOperationKind::Summarize)
    }

    /// Operation projection recorded in the annotation while this action's
    /// claim is open on `resource_version`.
    pub fn operation(
        &self,
        worker_id: WorkerId,
        resource_version: KubeResourceVersion,
    ) -> KubeOperationProjection {
        KubeOperationProjection {
            operation_id: self.operation_id.clone(),
            worker_id,
            kind: self.kind,
            expected_resource_version: resource_version,
            idempotency_digest: self.idempotency_digest,
        }
    }
}

/// Combines the stored projection with a workload view rebuilt from live status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct JobObservation {
    pub projection: KubeJobProjection,
    pub workload: KubeWorkloadView,
}

#[cfg(test)]
mod launch_bound_tests {
    use super::{JobLaunch, MAX_LAUNCH_GPU_COUNT, MIN_LAUNCH_DEADLINE_SECONDS};
    use odin_domain::huginn::{KubeContentIdentity, KubeJobLabels, KubeStagingProjection};
    use odin_domain::{ArtifactId, AttemptId, Digest, LaneId, ProjectId, RunId, SeatId, TaskId};
    use odin_types::{OperationId, WorkerId};

    fn launch(gpu_count: u32, deadline_seconds: Option<u32>) -> JobLaunch {
        JobLaunch {
            labels: KubeJobLabels {
                task_id: TaskId::new("run-bound-task").expect("task id"),
                run_id: RunId::new("run-bound").expect("run id"),
                attempt_id: AttemptId::new("run-bound-attempt").expect("attempt id"),
                seat_id: SeatId::new("kubert").expect("seat id"),
                project_id: ProjectId::new("odin").expect("project id"),
                lane_id: LaneId::new("bound-tests").expect("lane id"),
                model: "bound-test-model".to_owned(),
                budget_policy_digest: Digest::hash(b"bound-test-budget"),
                container_identity: Digest::hash(b"bound-test-image"),
            },
            worker_id: WorkerId::new("worker-bound").expect("worker id"),
            staging: KubeStagingProjection {
                inputs: Vec::new(),
                resumed_from: None,
            },
            checkpoint: None,
            extension: None,
            models_config: None,
            image: "registry.example/worker:v1".to_owned(),
            command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
            args: vec!["'/bin/true'".to_owned()],
            node_selector: std::collections::BTreeMap::new(),
            initial_target_node: None,
            gpu_count,
            deadline_seconds,
            service: false,
            workload: None,
            operation_id: OperationId::new("op-bound").expect("operation id"),
            idempotency_digest: Digest::hash(b"bound"),
        }
    }

    #[test]
    fn initial_target_preserves_the_historical_absent_wire_shape() {
        let original = launch(0, None);
        let old_shape = serde_json::to_value(&original).expect("launch encodes");
        assert!(old_shape.get("initial_target_node").is_none());
        let recovered: JobLaunch = serde_json::from_value(old_shape.clone())
            .expect("historical launch without a target decodes");
        assert_eq!(recovered, original);
        assert_eq!(
            serde_json::to_value(&recovered).expect("launch encodes"),
            old_shape
        );

        let mut targeted = original.clone();
        targeted.initial_target_node = Some("mini".to_owned());
        let targeted_shape = serde_json::to_value(&targeted).expect("targeted launch encodes");
        assert_eq!(targeted_shape["initial_target_node"], "mini");
        assert_eq!(targeted.node_selector, original.node_selector);
        assert_eq!(
            serde_json::from_value::<JobLaunch>(targeted_shape).expect("targeted launch decodes"),
            targeted
        );
    }

    #[test]
    fn initial_target_obeys_the_bounded_node_name_contract() {
        let mut targeted = launch(0, None);
        for name in [
            "", "Mini", "-mini", "mini-", ".mini", "mini.", "mini_pc", "mini/pc",
        ] {
            targeted.initial_target_node = Some(name.to_owned());
            assert!(targeted.validate().is_err(), "invalid target {name:?}");
        }
        targeted.initial_target_node = Some("a".repeat(64));
        assert!(targeted.validate().is_err());
        for name in ["m", "mini", "mini.pc", "node-1"] {
            targeted.initial_target_node = Some(name.to_owned());
            targeted.validate().expect("valid initial target");
        }
        targeted.initial_target_node = Some("a".repeat(63));
        targeted.validate().expect("maximum length target");
    }

    #[test]
    fn a_bounded_gpu_smoke_launch_is_lawful() {
        launch(1, Some(300))
            .validate()
            .expect("one GPU for 300s is inside the declared bound");
    }

    #[test]
    fn reservations_beyond_the_bound_are_rejected_before_any_effect() {
        let error = launch(MAX_LAUNCH_GPU_COUNT + 1, None)
            .validate()
            .expect_err("the GPU ceiling is hard");
        assert!(error.contains("GPUs"));

        for deadline in [MIN_LAUNCH_DEADLINE_SECONDS - 1, 3_601] {
            let error = launch(0, Some(deadline))
                .validate()
                .expect_err("the deadline window is hard");
            assert!(error.contains("deadline"), "deadline {deadline}: {error}");
        }
    }

    #[test]
    fn a_workload_binding_rides_the_launch_and_is_validated_with_it() {
        let models_input = KubeContentIdentity {
            artifact_id: ArtifactId::new("bound-test-models").expect("artifact id"),
            content_digest: Digest::hash(b"bound-test-models-bytes"),
            byte_len: 96,
        };
        let models = crate::job::JobModelsConfigLaunch {
            config_artifact: models_input.artifact_id.clone(),
            config_digest: Digest::hash(b"bound-test-models-bytes").to_string(),
            credential_env: "ODIN_GATEWAY_KEY".to_owned(),
        };
        let mut launch = launch(0, None);
        launch.staging.inputs = vec![models_input];
        launch.models_config = Some(models.clone());
        launch.workload = Some(crate::workload::WorkloadPodPlan {
            profile: "profile-under-test".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            allow_hosts: vec!["example.com".to_owned()],
            agent: Some(crate::workload::WorkloadAgentPlan {
                launcher: "/odin/bin/omp-launch".to_owned(),
                gateway: crate::workload::WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 4000,
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
                    env_name: "ODIN_GATEWAY_KEY".into(),
                    secret: "gateway-secret".into(),
                    key: "master".into(),
                },
            }),
        });
        launch
            .validate()
            .expect("a lawful workload launch validates");
        // Workload sessions use a longer deadline range than container smoke jobs.
        launch.deadline_seconds = Some(5_400);
        launch
            .validate()
            .expect("a 90-minute workload lifetime is inside the workload window");
        launch.deadline_seconds = Some(odin_registry::schema::MAX_WORKLOAD_DEADLINE_SECONDS + 1);
        let error = launch
            .validate()
            .expect_err("a workload lifetime beyond the window is rejected");
        assert!(error.contains("deadline"), "unexpected error: {error}");
        launch.deadline_seconds = Some(5_400);
        let serialized = serde_json::to_string(&launch).expect("launch serializes");
        let replayed: JobLaunch = serde_json::from_str(&serialized).expect("launch replays");
        assert_eq!(replayed, launch);
        assert!(
            replayed
                .workload
                .as_ref()
                .expect("plan survives")
                .agent
                .as_ref()
                .expect("agent plan")
                .display
                .stream
        );

        // The in-pod launcher needs the staged catalog because it has no built-in gateway provider.
        launch.models_config = None;
        let error = launch
            .validate()
            .expect_err("a workload launch without a models document is rejected");
        assert!(
            error.contains("models document"),
            "unexpected error: {error}"
        );

        launch.models_config = Some(crate::job::JobModelsConfigLaunch {
            config_artifact: ArtifactId::new("bound-test-unstaged").expect("artifact id"),
            config_digest: models.config_digest.clone(),
            credential_env: models.credential_env.clone(),
        });
        let error = launch
            .validate()
            .expect_err("an unstaged models document is rejected");
        assert!(
            error.contains("exactly one staging input"),
            "unexpected error: {error}"
        );

        launch.models_config = Some(models);
        launch.workload = Some(crate::workload::WorkloadPodPlan {
            profile: "profile-under-test".to_owned(),
            state_mount: "not-absolute".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            allow_hosts: vec![],
            agent: Some(crate::workload::WorkloadAgentPlan {
                launcher: "/odin/bin/omp-launch".to_owned(),
                gateway: crate::workload::WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 4000,
                },
                browser: "/odin/bin/chromium".to_owned(),
                supervisor: "/odin/bin/odind".to_owned(),
                playwright: "/odin/lib/playwright-core".to_owned(),
                browser_node: "/odin/bin/node".to_owned(),
                browser_engine: odin_registry::BrowserEngine::default(),
                display: crate::workload::WorkloadDisplayPlan {
                    xvfb: "/odin/bin/Xvfb".to_owned(),
                    screen: "1280x800x24".to_owned(),
                    stream: false,
                },
                home_dir: None,
                credential: crate::workload::WorkloadCredentialEnv {
                    env_name: "ODIN_GATEWAY_KEY".into(),
                    secret: "gateway-secret".into(),
                    key: "master".into(),
                },
            }),
        });
        let error = launch
            .validate()
            .expect_err("a malformed state mount is rejected");
        assert!(error.contains("workload binding rejected"));
    }
}
