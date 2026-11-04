#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Deterministic discovery, validation, and publication of Odin desired state.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod authoring;
pub mod cheatsheet;
pub mod container_identity;
pub mod discover;
pub mod listing;
pub mod relational;
pub mod schema;
pub mod snapshot;
pub mod toolsets;

pub use authoring::{
    compile_fill_documents, patch_container_source, stage_fill_batch, validate_fill_batch,
    AuthoringDestination, AuthoringErrors, AuthoringIssue, CompiledDocument, CompiledFill,
    ContainerPatch, FillDocumentSource, FillRequest, FillValues, SkeletonCatalog, SkeletonContract,
    SkeletonKind, SkeletonVariable, StagedChange, StagedDiffMetadata, StagedFill, StagedFillBatch,
    ValidatedFill, ValidatedFillBatch, AUTHORING_FILL_SCHEMA, SKELETON_PATCH_SCHEMA,
    SKELETON_VARIABLE_SCHEMA,
};
pub use container_identity::{
    validate_container_identity_fields, ContainerIdentity, ContainerIdentityError,
    CONTAINER_IDENTITY_ENCODING,
};
pub use discover::{walk, Discovery, RawObject};

/// Restrict declaration-changing capabilities to the owner-facing seat, never pod seats.
pub const CREATION_CAPABILITIES: &[&str] = &[
    "workload.draft",
    "workload.publish",
    "project.create",
    "seat.create",
    "seat.propose",
    "task.grant",
];
/// Reject root-equivalent capabilities in every governed seat and pod, even when disabled.
pub const ROOT_EQUIVALENT_CAPABILITIES: &[&str] = &[
    "shell.root",
    "root.policy.write",
    "kube.cluster.admin",
    "secret.read_raw",
];
pub use relational::{validate as validate_relations, AdmittedBinding, RelationContext};
pub use schema::{
    at_cap, bind_budget_policy, parse_objects, refuse_wall, resolve_provider_policy,
    resolve_recovery_policy, unix_millis, AccountingWindowToml, BudgetPolicyToml, CommitError,
    EmbeddingFramingToml, EmbeddingProtocolToml, GatewayProjectionManifest, GatewayProjectionRoute,
    LaneBudget, LaneBudgetKind, LaneBudgetRaise, LaneBudgetRefusal, LaneDirection, LaneLimitsToml,
    LaneToml, LaneTransferPolicy, LaneWallLease, ObjectConfig, PayloadKind, ProviderPolicyError,
    ProviderPolicyToml, ProviderRouteToml, RaisedLaneBudgets, RecoveryAttemptLimitsToml,
    RecoveryCooldownsToml, RecoveryPolicyError, RecoveryPolicyToml, RecoveryRungToml, RegistryKind,
    RegistryObject, ResolvedBudgetPolicy, ResolvedProviderPolicy, ResolvedProviderRoute,
    ResolvedRecoveryPolicy, SeatModelToml, SeatToml, BUILD_SLOTS_LIMIT_KEY,
    GATEWAY_PROJECTION_SCHEMA, LANE_BUDGET_FILE, LANE_WALL_FILE,
    MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS, MAX_TURN_SECONDS, PODS_LIMIT_KEY, WALL_LIMIT_KEY,
};
pub use schema::{
    compose_claude_code, ClaudeAccountPolicy, ClaudeCodeToml, ClaudeDriver, ClaudeMcpScope,
    ClaudeMcpToml, ClaudePlacement, ClaudePresetToml, ClaudePresetWorkspace, ClaudeResourcesToml,
    ClaudeReviewBudgetToml, ClaudeReviewToml, CLAUDE_CODE_HARNESS, CLAUDE_REVIEW_TOOLS,
    CLAUDE_WORKTREE,
};
pub use schema::{
    compose_workload_profile, compose_workload_profiles, pod_may_hold, storage_quantity_bytes,
    valid_id, BrowserEngine, ComposedWorkloadProfile, WorkloadAgentView, WorkloadBriefToml,
    WorkloadDisplayToml, WorkloadExportToml, WorkloadImageToml, WorkloadLifetimeToml,
    WorkloadMemoryToml, WorkloadMode, WorkloadMonitoringToml, WorkloadNetworkToml,
    WorkloadProfileLookupError, WorkloadProfileToml, WorkloadReportToml, WorkloadRuntimeToml,
    WorkloadScriptToml, WorkloadSeatToml, WorkloadSimulationToml, WorkloadStateToml,
    WorkloadTransport, MAX_WORKLOAD_DEADLINE_SECONDS, MIN_WORKLOAD_DEADLINE_SECONDS, OMP_HARNESS,
    PLATFORM_IMAGE, SCRIPT_HARNESS, WORKLOAD_BRIEF_MAX_BYTES,
};
pub use schema::{
    context_profiles, foreign_account_paths, valid_account_name, AccountKind, AccountLayout,
    ContextProfileToml, EnvironmentObservationToml, EnvironmentPodToml, EnvironmentPosture,
    EnvironmentSandboxToml, EnvironmentToml, EnvironmentTransport, EnvironmentWatchdogToml,
    HarnessGovernance, HarnessOutput, HarnessPrompt, HarnessProtocol, HarnessStopToml, HarnessToml,
    ObservationChannel, DEFAULT_ACCOUNT, GIT_MIRROR_PORT,
};
pub use schema::{
    ModelCardToml, ModelThinkingToml, ModelWindowToml, AGY_ROUTE, CHAT_CAPABILITY, CLAUDE_ROUTE,
    EMBEDDING_CAPABILITY, EVERYDAY_TIER, FAST_CHEAP_TIER, FRONTIER_TIER, GATEWAY_ROUTE,
    LOCAL_ACCOUNT, MODELS_AVAILABLE, MODEL_ROUTES, MODEL_TIERS,
};
pub use snapshot::{
    CompositionDigest, PublicationOutcome, PublicationReceipt, PublicationResult,
    RuntimeProjection, Snapshot, SnapshotError, SnapshotHandle, SnapshotStore, Tombstone,
    ValidatedSnapshotCandidate, PUBLICATION_RECEIPT_SCHEMA,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Flag,
    Fail,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "FLAG",
            Self::Fail => "FAIL",
        }
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryFinding {
    pub severity: FindingSeverity,
    pub code: String,
    pub path: PathBuf,
    pub message: String,
}

impl RegistryFinding {
    pub fn flag(
        code: impl Into<String>,
        path: impl Into<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(FindingSeverity::Flag, code, path, message)
    }

    pub fn fail(
        code: impl Into<String>,
        path: impl Into<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(FindingSeverity::Fail, code, path, message)
    }

    pub const fn is_failure(&self) -> bool {
        matches!(self.severity, FindingSeverity::Fail)
    }

    fn new(
        severity: FindingSeverity,
        code: impl Into<String>,
        path: impl Into<PathBuf>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            path: path.into(),
            message: message.into(),
        }
    }
}
