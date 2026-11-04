//! Typed registry declarations and validation.

mod account;
mod capability;
mod claude_code;
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
pub(crate) use capability::is_handler_shell_syntax;
pub use capability::{
    ApprovalDeciderToml, BatchLimitsToml, BuiltinHandlerToml, CapabilityApprovalToml,
    CapabilityExposureToml, CapabilityIdempotencyToml, CapabilitySeatOpToml, CapabilityToml,
    ExecHandlerToml, HandlerBindingToml, PreviewKindToml, RetryToml, SliceContextToml,
    SliceKnowledgeToml, SliceLiveToml, SliceRedirectsToml, SliceToml, SliceToolRedirectsToml,
    SliceToolsToml, SliceVariableToml, ADAPTER_OPERATION_HANDLER_ID, ADAPTER_RECEIPT_EVIDENCE_ID,
    DESKTOP_ACT_OUTPUT_SCHEMA, POD_EXEC_OUTPUT_SCHEMA, SEAT_ASK_EVIDENCE_EXTRACTOR_ID,
    SEAT_ASK_HANDLER_ID, SEAT_ASK_INPUT_SCHEMA, SEAT_ASK_OUTPUT_SCHEMA,
};
pub use claude_code::{
    compose_claude_code, ClaudeAccountPolicy, ClaudeCodeToml, ClaudeDriver, ClaudeMcpScope,
    ClaudeMcpToml, ClaudePlacement, ClaudePresetToml, ClaudePresetWorkspace, ClaudeResourcesToml,
    ClaudeReviewBudgetToml, ClaudeReviewToml, CLAUDE_CODE_HARNESS, CLAUDE_REVIEW_TOOLS,
    CLAUDE_WORKTREE,
};
pub use container::{
    AlertCondition, AlertOp, ContainerAlertActionToml, ContainerAlertSeverityToml,
    ContainerAlertToml, ContainerContentsKindToml, ContainerContentsToml,
    ContainerMonitoringPolicyToml, ContainerMonitoringToml, ContainerSurfaceDefinitionToml,
    ContainerSurfaceKindToml, ContainerSurfaceToml, ContainerToml, ContainerTunableValue,
    ContainerWatchdogToml,
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
    LaneBudgetRefusal, LaneWallLease, RaisedLaneBudgets, BUILD_SLOTS_LIMIT_KEY, LANE_BUDGET_FILE,
    LANE_WALL_FILE, PODS_LIMIT_KEY, WALL_LIMIT_KEY,
};
pub use model::{
    ModelCardToml, ModelThinkingToml, ModelWindowToml, AGY_ROUTE, CHAT_CAPABILITY, CLAUDE_ROUTE,
    EMBEDDING_CAPABILITY, EVERYDAY_TIER, FAST_CHEAP_TIER, FRONTIER_TIER, GATEWAY_ROUTE,
    LOCAL_ACCOUNT, MODELS_AVAILABLE, MODEL_ROUTES, MODEL_TIERS,
};
pub use node::{
    node_gateway_address_class, HostToml, NodeGatewayEndpoint, NodeGatewayEndpointError, NodeToml,
};
pub use object::{
    parse_object_toml, parse_objects, ObjectConfig, ParseResult, RegistryKind, RegistryObject,
    CAPABILITY_SCHEMA_DIR, REGISTRY_DIR, REGISTRY_SCHEMA,
};
pub use pod_exec::{
    PodExecStdin, PodExecToml, POD_EXEC_HANDLER_ID, POD_EXEC_IMPLEMENTATION, POD_EXEC_RECEIPT_ID,
};
pub use provider::{
    resolve_provider_policy, resolve_recovery_policy, EmbeddingFramingToml, EmbeddingProtocolToml,
    GatewayProjectionManifest, GatewayProjectionRoute, ProviderPolicyError, ProviderPolicyToml,
    ProviderRouteToml, ProviderToml, RecoveryAttemptLimitsToml, RecoveryCooldownsToml,
    RecoveryPolicyError, RecoveryPolicyToml, RecoveryRungToml, ResolvedProviderPolicy,
    ResolvedProviderRoute, ResolvedRecoveryPolicy, GATEWAY_PROJECTION_SCHEMA,
    MAX_EMBEDDING_PROTOCOL_TRUNCATE_TOKENS,
};
pub use routine::{
    dm_placeholders, fill_dm, ClockTime, DmFacts, RoutineActionKind, RoutineActionToml,
    RoutineEvent, RoutineSchedule, RoutineToml, RoutineTriggerToml, ROUTINE_TEXT_MAX_CHARS,
};

pub use feature::{FeatureToml, Probe, UnitManager};
pub use seat::{
    bind_budget_policy, utc_seconds, AccountingWindowToml, BudgetPolicyToml, LaneDirection,
    LaneLimitsToml, LaneToml, LaneTransferPolicy, ModelClass, PayloadKind, ProjectDeployToml,
    ProjectDeviceActionToml, ProjectDeviceParamKind, ProjectDeviceToml, ProjectSphereToml,
    ProjectToml, ResolvedBudgetPolicy, SeatContextToml, SeatConversationToml, SeatEphemeralToml,
    SeatKnowledgeToml, SeatLimitsToml, SeatLiveToml, SeatModelToml, SeatRolloverToml,
    SeatSandboxNetwork, SeatSandboxToml, SeatToml, SeatToolRedirectsToml, SeatToolsToml,
    DEFAULT_INLINE_SECONDS, DEFAULT_MAX_BACKGROUND_JOBS, MAX_TURN_SECONDS, SANDBOX_PATH_ROLES,
};
pub use toolset::ToolsetToml;
pub use validation::check_pod_recovery;
pub use validation::valid_id;
pub use validation::valid_memory_namespace;
pub use validation::{has_failures, validate_object};
pub(crate) use validation::{lookup_toml_path, valid_brain_scope, valid_media_type};
pub use workflow::{WORKFLOW_HANDLER_ID, WORKFLOW_IMPLEMENTATION, WORKFLOW_RECEIPT_ID};
pub use workload::{
    compose_workload_profile, compose_workload_profiles, paths_nest_or_collide, pod_may_hold,
    storage_quantity_bytes, valid_allow_host, valid_pod_path, valid_screen, BrowserEngine,
    ComposedWorkloadProfile, WorkloadAgentView, WorkloadBriefToml, WorkloadDisplayToml,
    WorkloadExportToml, WorkloadImageToml, WorkloadLifetimeToml, WorkloadMemoryToml, WorkloadMode,
    WorkloadMonitoringToml, WorkloadNetworkToml, WorkloadProfileLookupError, WorkloadProfileToml,
    WorkloadReportToml, WorkloadRuntimeToml, WorkloadScriptToml, WorkloadSeatToml,
    WorkloadSimulationToml, WorkloadStateToml, WorkloadTransport, MAX_WORKLOAD_DEADLINE_SECONDS,
    MIN_WORKLOAD_DEADLINE_SECONDS, NODE_CAPABILITY_LABEL_PREFIX, OMP_HARNESS, PLATFORM_IMAGE,
    SCRIPT_HARNESS, WORKLOAD_BRIEF_MAX_BYTES,
};
