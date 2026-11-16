//! Typed registry declarations and validation.

mod account;
mod brain_role;
mod capability;
mod claude_code;
mod compute_provider;
mod compute_target;
mod compute_usage;
mod container;
mod context_profile;
mod environment;
mod feature;
mod harness;
mod lane_budget;
mod model;
mod node;
mod object;
mod pod_exec;
mod provider;
mod rental_approvals;
mod rental_leases;
mod rental_targets;
mod routine;
mod seat;
mod toolset;
mod toolsets;
mod validation;
mod workflow;
mod workload;
pub use toolsets::{expand_toolset_grants, expand_toolset_refs};

#[cfg(test)]
pub(crate) mod fixtures;

pub use account::{
    foreign_account_paths, valid_account_name, AccountKind, AccountLayout, DEFAULT_ACCOUNT,
};
pub use brain_role::{BrainRoleName, BrainRoleToml};
pub(crate) use capability::is_handler_shell_syntax;
pub use capability::{
    ApprovalCardToml, ApprovalDeciderToml, BatchLimitsToml, BuiltinHandlerToml,
    CapabilityApprovalToml, CapabilityExposureToml, CapabilityIdempotencyToml,
    CapabilitySeatOpToml, CapabilityToml, ExecHandlerToml, HandlerBindingToml, PreviewKindToml,
    RetryToml, SliceContextToml, SliceKnowledgeToml, SliceLiveToml, SliceRedirectsToml, SliceToml,
    SliceToolRedirectsToml, SliceToolsToml, SliceVariableToml, ADAPTER_OPERATION_HANDLER_ID,
    ADAPTER_RECEIPT_EVIDENCE_ID, DESKTOP_ACT_OUTPUT_SCHEMA, POD_EXEC_OUTPUT_SCHEMA,
    SEAT_ASK_EVIDENCE_EXTRACTOR_ID, SEAT_ASK_HANDLER_ID, SEAT_ASK_INPUT_SCHEMA,
    SEAT_ASK_OUTPUT_SCHEMA,
};
pub use claude_code::{
    compose_claude_code, ClaudeAccountPolicy, ClaudeCodeToml, ClaudeDriver, ClaudeMcpScope,
    ClaudeMcpToml, ClaudePlacement, ClaudePresetToml, ClaudePresetWorkspace, ClaudeResourcesToml,
    ClaudeReviewBudgetToml, ClaudeReviewToml, CLAUDE_CODE_HARNESS, CLAUDE_REVIEW_TOOLS,
    CLAUDE_WORKTREE,
};
pub use compute_provider::{
    ComputeOfferToml, ComputeProviderApi, ComputeProviderToml, LeaseJoin, LeaseTargetToml,
};
pub use compute_target::{ComputeExecutor, ComputeTargetCost, ComputeTargetToml, OffloadRuntime};
pub use compute_usage::{
    refuse_compute, ComputeCharge, ComputeUsage, MeteredPod, COMPUTE_BUDGET_REFUSED,
    COMPUTE_USAGE_FILE,
};
pub use container::{
    AlertCondition, AlertOp, ContainerAlertActionToml, ContainerAlertSeverityToml,
    ContainerAlertToml, ContainerContentsKindToml, ContainerContentsToml,
    ContainerMonitoringPolicyToml, ContainerMonitoringToml, ContainerSurfaceDefinitionToml,
    ContainerSurfaceKindToml, ContainerSurfaceToml, ContainerToml, ContainerTunableValue,
    ContainerWatchdogToml, SteerPatch,
};
pub use context_profile::{context_profiles, ContextProfileToml};
pub use environment::{
    EnvironmentObservationToml, EnvironmentPodToml, EnvironmentPosture, EnvironmentSandboxToml,
    EnvironmentToml, EnvironmentTransport, EnvironmentWatchdogToml, ObservationChannel,
    GIT_MIRROR_PORT,
};
pub use harness::{
    HarnessGovernance, HarnessOutput, HarnessPrompt, HarnessProtocol, HarnessStopToml, HarnessToml,
    HARNESS_MAX_ARGS,
};
pub use lane_budget::{
    at_cap, refuse_wall, unix_millis, CommitError, LaneBudget, LaneBudgetKind, LaneBudgetRaise,
    LaneBudgetRefusal, LaneWallLease, RaisedLaneBudgets, BUILD_SLOTS_LIMIT_KEY,
    COMPUTE_USD_LIMIT_KEY, CORE_HOURS_LIMIT_KEY, GPU_HOURS_LIMIT_KEY, LANE_BUDGET_FILE,
    LANE_WALL_FILE, PODS_LIMIT_KEY, WALL_LIMIT_KEY,
};
pub use model::{
    ModelCardToml, ModelThinkingToml, ModelTokenizer, ModelWindowToml, AGY_ROUTE, CHAT_CAPABILITY,
    CLAUDE_ROUTE, EMBEDDING_CAPABILITY, EVERYDAY_TIER, FAST_CHEAP_TIER, FRONTIER_TIER,
    GATEWAY_ROUTE, LOCAL_ACCOUNT, MODELS_AVAILABLE, MODEL_ROUTES, MODEL_TIERS,
};
pub use node::{
    node_gateway_address_class, HostToml, LaunchQueueToml, NodeCostToml, NodeGatewayEndpoint,
    NodeGatewayEndpointError, NodeGpuToml, NodeToml, NodeYieldToml, WorkloadWatchToml,
    DEFAULT_COMPUTE_METER_SECONDS, DEFAULT_YIELD_STALE_HOURS, EXTERNAL_TOLERATION,
    NODE_GPU_MODEL_LABEL, NODE_GPU_VRAM_LABEL, NODE_TAINT_PREFIX, NODE_TRUST_FLEET,
    NODE_TRUST_LABEL,
};
pub use object::{
    parse_object_toml, parse_objects, ObjectConfig, ParseResult, RegistryKind, RegistryObject,
    CAPABILITY_SCHEMA_DIR, REGISTRY_DIR, REGISTRY_SCHEMA,
};
pub use pod_exec::{
    PodExecRecon, PodExecStdin, PodExecToml, ReconKind, ReconOutput, POD_EXEC_HANDLER_ID,
    POD_EXEC_IMPLEMENTATION, POD_EXEC_RECEIPT_ID, RECON_MAX_DEPTH,
};
pub use provider::{
    resolve_provider_policy, resolve_recovery_policy, EmbeddingFramingToml, EmbeddingProtocolToml,
    GatewayProjectionManifest, GatewayProjectionRoute, ProviderPolicyError, ProviderPolicyToml,
    ProviderRouteToml, ProviderToml, RecoveryAttemptLimitsToml, RecoveryCooldownsToml,
    RecoveryPolicyError, RecoveryPolicyToml, RecoveryRungToml, ResolvedProviderPolicy,
    ResolvedProviderRoute, ResolvedRecoveryPolicy, GATEWAY_PROJECTION_SCHEMA,
    MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS,
};
pub use rental_approvals::{RentalApproval, RentalApprovals};
pub use rental_leases::{
    RentalEnrollment, RentalLease, RentalLeaseGuard, RentalLeaseState, RentalLeases,
};
pub use rental_targets::RentalTargets;
pub use routine::{
    dm_placeholders, fill_dm, ClockTime, DmFacts, RoutineActionKind, RoutineActionToml,
    RoutineEvent, RoutineSchedule, RoutineToml, RoutineTriggerToml, ROUTINE_TEXT_MAX_CHARS,
};

pub use feature::{FeatureToml, Probe, UnitManager};
pub use seat::{
    bind_budget_policy, utc_seconds, AccountingWindowToml, BudgetPolicyToml, HeartbeatWhen,
    LaneDirection, LaneLimitsToml, LaneToml, LaneTransferPolicy, ModelClass, PayloadKind,
    ProjectDeployToml, ProjectDeviceActionToml, ProjectDeviceParamKind, ProjectDeviceToml,
    ProjectSphereToml, ProjectToml, ResolvedBudgetPolicy, SeatContextToml, SeatConversationToml,
    SeatEphemeralToml, SeatKnowledgeToml, SeatLimitsToml, SeatLiveToml, SeatLoomToml,
    SeatModelToml, SeatRolloverToml, SeatSandboxNetwork, SeatSandboxToml, SeatToml,
    SeatToolRedirectsToml, SeatToolsToml, DEFAULT_INLINE_SECONDS, DEFAULT_MAX_BACKGROUND_JOBS,
    MAX_TURN_SECONDS, SANDBOX_PATH_ROLES,
};
pub use toolset::ToolsetToml;
pub use validation::check_pod_recovery;
pub use validation::odin_kube_bounds;
pub use validation::valid_id;
pub use validation::valid_memory_namespace;
pub use validation::{has_failures, validate_object};
pub(crate) use validation::{lookup_toml_path, valid_brain_scope, valid_media_type};
pub use workflow::{WORKFLOW_HANDLER_ID, WORKFLOW_IMPLEMENTATION, WORKFLOW_RECEIPT_ID};
pub use workload::{
    compose_workload_profile, compose_workload_profiles, paths_nest_or_collide, pod_may_hold,
    storage_quantity_bytes, valid_allow_host, valid_pod_path, valid_screen, BrowserEngine,
    ComposedWorkloadProfile, OnYield, WorkloadAgentView, WorkloadBriefToml, WorkloadControlToml,
    WorkloadDataToml, WorkloadDisplayToml, WorkloadExportToml, WorkloadGpuToml, WorkloadImageToml,
    WorkloadLifetimeToml, WorkloadLimitsToml, WorkloadMemoryToml, WorkloadMode,
    WorkloadMonitoringToml, WorkloadNetworkToml, WorkloadOffloadToml, WorkloadProfileLookupError,
    WorkloadProfileToml, WorkloadReportToml, WorkloadRuntimeToml, WorkloadScriptToml,
    WorkloadSeatToml, WorkloadSimulationToml, WorkloadStateToml, WorkloadTransport,
    CHECKPOINT_PERCENT_RANGE, CONTROL_MAP_LIMIT_BYTES, FORBIDDEN_DATA_HOST_ROOTS, MAX_FRAME_BYTES,
    MAX_ROLLOVERS_LIMIT, MAX_WORKLOAD_DEADLINE_SECONDS, MIN_WORKLOAD_DEADLINE_SECONDS,
    NODE_CAPABILITY_LABEL_PREFIX, OMP_HARNESS, PLATFORM_IMAGE, RESERVED_POD_PATHS, SCRIPT_HARNESS,
    WORKLOAD_BRIEF_MAX_BYTES,
};
