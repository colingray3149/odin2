//! Typed Kubernetes read views and Odin-owned workload commands.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::{
    ArtifactId, AttemptId, CheckpointId, CommandId, Digest, DomainError, LaneId, NodeId, ProjectId,
    RunId, SeatId, TaskId,
};
use odin_types::{OperationId, WorkerId};

use super::artifact::ArtifactRef;

pub const KUBE_JOB_PROJECTION_SCHEMA: &str = "odin.kube.job-projection.v1";

macro_rules! opaque_kube_identity {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if value.is_empty() || value.len() > 512 || value.as_bytes().contains(&0) {
                    return Err(DomainError::InvalidId {
                        kind: $kind,
                        value,
                        reason: "must be 1..=512 bytes and contain no NUL",
                    });
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = DomainError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

opaque_kube_identity!(KubeUid, "Kubernetes UID");
opaque_kube_identity!(KubeResourceVersion, "Kubernetes resourceVersion");

/// API-server identity of one batch/v1 Job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeJobIdentity {
    pub uid: KubeUid,
    pub resource_version: KubeResourceVersion,
}

/// Exact Odin bindings projected into Job labels.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeJobLabels {
    pub task_id: TaskId,
    pub run_id: RunId,
    pub attempt_id: AttemptId,
    pub seat_id: SeatId,
    pub project_id: ProjectId,
    pub lane_id: LaneId,
    pub model: String,
    pub budget_policy_digest: Digest,
    pub container_identity: Digest,
}

/// Content identity used by staging and checkpoint projections. It contains no
/// host path, file descriptor, or transport authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeContentIdentity {
    pub artifact_id: ArtifactId,
    pub content_digest: Digest,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeStagingProjection {
    pub inputs: Vec<KubeContentIdentity>,
    pub resumed_from: Option<CheckpointId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeCheckpointProjection {
    pub checkpoint_id: CheckpointId,
    pub parent_checkpoint_id: Option<CheckpointId>,
    pub state: KubeContentIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeJobLifecycle {
    Pending,
    Staging,
    Running,
    Paused,
    Succeeded,
    Failed,
    Cancelling,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeWorkerBinding {
    pub worker_id: WorkerId,
    pub container_identity: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeOperationKind {
    Create,
    Pause,
    Resume,
    Restart,
    Cancel,
    Summarize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeOperationProjection {
    pub operation_id: OperationId,
    pub worker_id: WorkerId,
    pub kind: KubeOperationKind,
    pub expected_resource_version: KubeResourceVersion,
    pub idempotency_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KubeJobProjectionSchema {
    #[serde(rename = "odin.kube.job-projection.v1")]
    V1,
}

/// Shared data contract only. No Kubernetes client, target, credential,
/// executable path, argv, PID, or eval authority is represented here.
/// Deserialization enforces [`Self::validate`]; directly constructed values must be validated by callers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KubeJobProjection {
    pub schema: KubeJobProjectionSchema,
    pub identity: KubeJobIdentity,
    pub labels: KubeJobLabels,
    pub staging: KubeStagingProjection,
    pub checkpoint: Option<KubeCheckpointProjection>,
    pub lifecycle: KubeJobLifecycle,
    pub worker: KubeWorkerBinding,
    pub operation: Option<KubeOperationProjection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KubeJobProjectionWire {
    schema: KubeJobProjectionSchema,
    identity: KubeJobIdentity,
    labels: KubeJobLabels,
    staging: KubeStagingProjection,
    checkpoint: Option<KubeCheckpointProjection>,
    lifecycle: KubeJobLifecycle,
    worker: KubeWorkerBinding,
    operation: Option<KubeOperationProjection>,
}

impl<'de> Deserialize<'de> for KubeJobProjection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = KubeJobProjectionWire::deserialize(deserializer)?;
        let projection = Self {
            schema: wire.schema,
            identity: wire.identity,
            labels: wire.labels,
            staging: wire.staging,
            checkpoint: wire.checkpoint,
            lifecycle: wire.lifecycle,
            worker: wire.worker,
            operation: wire.operation,
        };
        projection.validate().map_err(serde::de::Error::custom)?;
        Ok(projection)
    }
}

impl KubeJobProjection {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.labels.model.trim().is_empty() {
            return Err(DomainError::InvalidEnvelope(
                "Kubernetes Job labels require a nonempty model binding".to_owned(),
            ));
        }
        if self.worker.container_identity != self.labels.container_identity {
            return Err(DomainError::InvalidEnvelope(
                "Kubernetes worker and Job labels disagree on container identity".to_owned(),
            ));
        }
        if let Some(operation) = &self.operation {
            if operation.worker_id != self.worker.worker_id {
                return Err(DomainError::InvalidEnvelope(
                    "Kubernetes operation addresses a different worker".to_owned(),
                ));
            }
            if operation.expected_resource_version != self.identity.resource_version {
                return Err(DomainError::InvalidEnvelope(
                    "Kubernetes operation resourceVersion is stale".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Stable Kubernetes object identity as observed from the API server.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeResourceRef {
    pub cluster: String,
    pub api_version: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub uid: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeResourceKind {
    Namespace,
    Node,
    Job,
    Pod,
    Container,
    Deployment,
    StatefulSet,
    DaemonSet,
    Service,
    ConfigMap,
    PersistentVolumeClaim,
    Other,
}

/// Odin ownership is explicit in every resource view. Foreign objects remain observable only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum KubeResourceOwnership {
    Odin {
        run_id: RunId,
        attempt_id: Option<AttemptId>,
        lane_id: LaneId,
        seat_id: SeatId,
    },
    Foreign,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeResources {
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub ephemeral_storage_bytes: u64,
    pub gpu_count: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeNodeState {
    Ready,
    NotReady,
    Unschedulable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeNodeView {
    pub node_id: NodeId,
    pub resource: KubeResourceRef,
    pub revision: u64,
    pub state: KubeNodeState,
    pub architecture: String,
    pub operating_system: String,
    pub capacity: KubeResources,
    pub allocatable: KubeResources,
    pub usage: KubeResources,
    /// Usage metrics were unobserved at `observed_at` (no metrics server):
    /// the zeros above are absence, never a measured zero. Independent of
    /// `stale`, which stays a departure marker.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub usage_stale: bool,
    pub observed_at: OffsetDateTime,
    /// Departure staleness only — never set for missing usage (that is
    /// `usage_stale`).
    pub stale: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeWorkloadState {
    Pending,
    Scheduling,
    Running,
    Succeeded,
    Failed,
    Suspended,
    Terminating,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeContainerView {
    pub name: String,
    pub image: String,
    pub image_digest: Option<Digest>,
    pub ready: bool,
    pub restart_count: u32,
    pub requested: KubeResources,
    pub limit: KubeResources,
    pub usage: KubeResources,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeWorkloadView {
    pub resource: KubeResourceRef,
    pub ownership: KubeResourceOwnership,
    /// Workload-profile label lets routines follow runs of a declared profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub revision: u64,
    pub state: KubeWorkloadState,
    pub node_id: Option<NodeId>,
    pub containers: Vec<KubeContainerView>,
    pub requested: KubeResources,
    pub limit: KubeResources,
    pub usage: KubeResources,
    /// Usage metrics were unobserved at `observed_at` (a Job object carries
    /// none): the zeros above are absence, never a measured zero. A Job
    /// stays visible in default listings — `stale` never marks usage.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub usage_stale: bool,
    pub started_at: Option<OffsetDateTime>,
    pub finished_at: Option<OffsetDateTime>,
    pub observed_at: OffsetDateTime,
    /// Departure staleness: true only once the object left the API server
    /// (the catalog's retirement tombstone); never for missing usage —
    /// that is `usage_stale`.
    pub stale: bool,
}

/// One node pressure condition exactly as the API server reports it
/// (`MemoryPressure`, `DiskPressure`, `PIDPressure`); status `True` means
/// the pressure is active. Part of the `kube.health.read` observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeNodePressure {
    pub kind: String,
    pub status: String,
}

/// `kube.health.read` node row: readiness state, pressure conditions, and
/// capacity observed live from the real cluster.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeNodeHealth {
    pub name: String,
    pub uid: String,
    pub state: KubeNodeState,
    pub architecture: String,
    pub operating_system: String,
    pub pressures: Vec<KubeNodePressure>,
    pub unschedulable: bool,
    pub capacity: KubeResources,
    pub allocatable: KubeResources,
}

/// One container of a problem pod: readiness, restarts, and the waiting
/// reason (`CrashLoopBackOff`, `ImagePullBackOff`, ...) when present.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeContainerIssue {
    pub name: String,
    pub image: String,
    pub ready: bool,
    pub restart_count: u32,
    pub waiting_reason: Option<String>,
}

/// One pod the health observation flags: phase outside `Running`/`Succeeded`,
/// or a running pod with a not-ready or waiting container. `Succeeded`
/// (completed Job pods) is never a problem row.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubePodProblem {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub node: Option<String>,
    pub phase: Option<String>,
    pub reason: Option<String>,
    pub containers: Vec<KubeContainerIssue>,
}

/// One warning event, most recent first, bounded by the read's scan limits.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeWarningEvent {
    pub namespace: Option<String>,
    pub involved_kind: String,
    pub involved_name: String,
    pub reason: String,
    pub message: String,
    pub count: u32,
    /// RFC 3339 timestamps exactly as the API server reported them.
    pub first_timestamp: Option<String>,
    pub last_timestamp: Option<String>,
}

/// The `kube.health.read` observation: one bounded, read-only live health
/// snapshot of the configured cluster. Empty arrays are real observations
/// (a reachable cluster with no problem pods), never absence of data.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeClusterHealth {
    pub cluster: String,
    /// RFC 3339 observation instant, formatted once at read time.
    pub observed_at: String,
    pub nodes: Vec<KubeNodeHealth>,
    /// Every pod the bounded scan observed, problem or not.
    pub pods_observed: u32,
    pub pod_problems: Vec<KubePodProblem>,
    pub warning_events: Vec<KubeWarningEvent>,
}

/// Generic resource view. Specs and status documents are content-addressed artifacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeResourceView {
    pub resource: KubeResourceRef,
    pub resource_kind: KubeResourceKind,
    pub ownership: KubeResourceOwnership,
    pub revision: u64,
    pub manifest: Option<ArtifactRef>,
    pub status: Option<ArtifactRef>,
    pub observed_at: OffsetDateTime,
    pub stale: bool,
}

/// A bounded log segment stored outside the read-model message.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeLogView {
    pub resource: KubeResourceRef,
    pub container: Option<String>,
    pub revision: u64,
    pub from: OffsetDateTime,
    pub through: OffsetDateTime,
    pub line_count: u64,
    pub content: ArtifactRef,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KubeEventType {
    Normal,
    Warning,
    Error,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KubeEventView {
    pub event_artifact_id: ArtifactId,
    pub resource: KubeResourceRef,
    pub revision: u64,
    pub event_type: KubeEventType,
    pub reason: String,
    pub message: String,
    pub first_observed_at: OffsetDateTime,
    pub last_observed_at: OffsetDateTime,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum KubeView {
    Node(KubeNodeView),
    Workload(KubeWorkloadView),
    Resource(KubeResourceView),
    Log(KubeLogView),
    Event(KubeEventView),
}

/// Kubernetes mutations address an Odin run, never an arbitrary Kubernetes resource reference.
/// The adapter resolves and verifies the run's owned object before applying the command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum KubeCommand {
    RetryWorkload {
        command_id: CommandId,
        run_id: RunId,
        expected_revision: u64,
        arguments_digest: Digest,
    },
    SuspendWorkload {
        command_id: CommandId,
        run_id: RunId,
        expected_revision: u64,
        arguments_digest: Digest,
    },
    ResumeWorkload {
        command_id: CommandId,
        run_id: RunId,
        expected_revision: u64,
        arguments_digest: Digest,
    },
    DeleteWorkload {
        command_id: CommandId,
        run_id: RunId,
        expected_revision: u64,
        arguments_digest: Digest,
    },
    RehomeWorkload {
        command_id: CommandId,
        run_id: RunId,
        expected_revision: u64,
        target_node: NodeId,
        arguments_digest: Digest,
    },
}

impl KubeCommand {
    pub fn command_id(&self) -> &CommandId {
        match self {
            Self::RetryWorkload { command_id, .. }
            | Self::SuspendWorkload { command_id, .. }
            | Self::ResumeWorkload { command_id, .. }
            | Self::DeleteWorkload { command_id, .. }
            | Self::RehomeWorkload { command_id, .. } => command_id,
        }
    }

    pub fn run_id(&self) -> &RunId {
        match self {
            Self::RetryWorkload { run_id, .. }
            | Self::SuspendWorkload { run_id, .. }
            | Self::ResumeWorkload { run_id, .. }
            | Self::DeleteWorkload { run_id, .. }
            | Self::RehomeWorkload { run_id, .. } => run_id,
        }
    }

    pub const fn expected_revision(&self) -> u64 {
        match self {
            Self::RetryWorkload {
                expected_revision, ..
            }
            | Self::SuspendWorkload {
                expected_revision, ..
            }
            | Self::ResumeWorkload {
                expected_revision, ..
            }
            | Self::DeleteWorkload {
                expected_revision, ..
            }
            | Self::RehomeWorkload {
                expected_revision, ..
            } => *expected_revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: &str) -> Digest {
        Digest::hash(value.as_bytes())
    }

    fn projection() -> KubeJobProjection {
        let worker_id = WorkerId::new("worker-1").unwrap();
        let resource_version = KubeResourceVersion::new("1042").unwrap();
        let container_identity = digest("container");
        KubeJobProjection {
            schema: KubeJobProjectionSchema::V1,
            identity: KubeJobIdentity {
                uid: KubeUid::new("4c60f59e-d150-4c5f-b72f-475c20eb2fd9").unwrap(),
                resource_version: resource_version.clone(),
            },
            labels: KubeJobLabels {
                task_id: TaskId::new("task-1").unwrap(),
                run_id: RunId::new("run-1").unwrap(),
                attempt_id: AttemptId::new("attempt-1").unwrap(),
                seat_id: SeatId::new("normal").unwrap(),
                project_id: ProjectId::new("odin").unwrap(),
                lane_id: LaneId::new("build").unwrap(),
                model: "fixture-model".to_owned(),
                budget_policy_digest: digest("budget-policy"),
                container_identity,
            },
            staging: KubeStagingProjection {
                inputs: vec![KubeContentIdentity {
                    artifact_id: ArtifactId::new("input-1").unwrap(),
                    content_digest: digest("input"),
                    byte_len: 5,
                }],
                resumed_from: None,
            },
            checkpoint: Some(KubeCheckpointProjection {
                checkpoint_id: CheckpointId::new("checkpoint-1").unwrap(),
                parent_checkpoint_id: None,
                state: KubeContentIdentity {
                    artifact_id: ArtifactId::new("checkpoint-state").unwrap(),
                    content_digest: digest("state"),
                    byte_len: 5,
                },
            }),
            lifecycle: KubeJobLifecycle::Running,
            worker: KubeWorkerBinding {
                worker_id: worker_id.clone(),
                container_identity,
            },
            operation: Some(KubeOperationProjection {
                operation_id: OperationId::new("operation-1").unwrap(),
                worker_id,
                kind: KubeOperationKind::Pause,
                expected_resource_version: resource_version,
                idempotency_digest: digest("idempotency"),
            }),
        }
    }

    #[test]
    fn kube_projection_codecs() {
        let projected = projection();
        projected.validate().unwrap();
        let encoded = serde_json::to_value(&projected).unwrap();
        assert_eq!(
            encoded.get("schema").and_then(serde_json::Value::as_str),
            Some(KUBE_JOB_PROJECTION_SCHEMA)
        );
        assert_eq!(
            encoded
                .pointer("/identity/resourceVersion")
                .and_then(serde_json::Value::as_str),
            Some("1042")
        );
        assert!(encoded.pointer("/labels/budgetPolicyDigest").is_some());
        assert!(encoded.get("path").is_none());
        assert!(encoded.get("argv").is_none());
        assert!(encoded.get("pid").is_none());
        assert!(encoded.get("eval").is_none());
        assert_eq!(
            serde_json::from_value::<KubeJobProjection>(encoded.clone()).unwrap(),
            projected
        );

        let mut unknown = encoded.clone();
        unknown["worker"]["pid"] = serde_json::json!(17);
        assert!(serde_json::from_value::<KubeJobProjection>(unknown).is_err());

        let mut stale = projection();
        stale
            .operation
            .as_mut()
            .expect("operation")
            .expected_resource_version = KubeResourceVersion::new("1043").unwrap();
        assert!(stale.validate().is_err());

        let mut wrong_worker = projection();
        wrong_worker
            .operation
            .as_mut()
            .expect("operation")
            .worker_id = WorkerId::new("worker-2").unwrap();
        assert!(wrong_worker.validate().is_err());
    }

    #[test]
    fn kube_projection_wire_rejects_invalid_state() {
        let expected = projection();
        let valid = serde_json::to_value(&expected).unwrap();
        assert_eq!(
            serde_json::from_value::<KubeJobProjection>(valid.clone()).unwrap(),
            expected
        );

        let mut unbound = valid.clone();
        unbound["labels"]["model"] = serde_json::json!("   ");
        assert!(serde_json::from_value::<KubeJobProjection>(unbound).is_err());

        let mut wrong_worker = valid.clone();
        wrong_worker["operation"]["workerId"] = serde_json::json!("worker-2");
        assert!(serde_json::from_value::<KubeJobProjection>(wrong_worker).is_err());

        let mut mismatched_identity = valid.clone();
        mismatched_identity["worker"]["containerIdentity"] =
            serde_json::to_value(digest("other-container")).unwrap();
        assert!(serde_json::from_value::<KubeJobProjection>(mismatched_identity).is_err());

        let mut stale_operation = valid;
        stale_operation["operation"]["expectedResourceVersion"] = serde_json::json!("1043");
        assert!(serde_json::from_value::<KubeJobProjection>(stale_operation).is_err());
    }

    #[test]
    fn kube_projection_wire_preserves_optional_fields_and_rejects_unknown_fields() {
        let mut expected = projection();
        expected.checkpoint = None;
        expected.operation = None;
        let explicit_nulls = serde_json::to_value(&expected).unwrap();
        let decoded: KubeJobProjection = serde_json::from_value(explicit_nulls.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), explicit_nulls);

        let mut omitted = explicit_nulls;
        omitted.as_object_mut().unwrap().remove("checkpoint");
        omitted.as_object_mut().unwrap().remove("operation");
        assert_eq!(
            serde_json::from_value::<KubeJobProjection>(omitted.clone()).unwrap(),
            expected
        );
        omitted["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<KubeJobProjection>(omitted).is_err());
    }

    #[test]
    fn kube_identity_scalars_are_opaque_and_bounded() {
        assert!(KubeUid::new("").is_err());
        assert!(KubeResourceVersion::new("bad\0version").is_err());
        let uid = KubeUid::new("opaque/uid:value").unwrap();
        assert_eq!(uid.as_str(), "opaque/uid:value");
        let value = serde_json::to_value(&uid).unwrap();
        assert_eq!(serde_json::from_value::<KubeUid>(value).unwrap(), uid);
    }
}
