//! Typed registry declarations and validation.

mod account;
mod capability;
mod claude_code;
mod container;
mod context_profile;
mod environment;
mod harness;
mod node;
mod object;
mod provider;
mod routine;
mod seat;
mod validation;
mod workload;

#[cfg(test)]
pub(crate) mod fixtures;

pub use account::{
    foreign_account_paths, valid_account_name, AccountKind, AccountLayout, DEFAULT_ACCOUNT,
};
pub(crate) use capability::is_handler_shell_syntax;
pub use capability::{
    ApprovalDeciderToml, BatchLimitsToml, BuiltinHandlerToml, CapabilityApprovalToml,
    CapabilityIdempotencyToml, CapabilityToml, ExecHandlerToml, HandlerBindingToml,
    PreviewKindToml, RetryToml, SliceAliasRedirectToml, SliceContextToml, SliceKnowledgeToml,
    SliceLiveToml, SliceRedirectsToml, SliceToml, SliceToolRedirectsToml, SliceToolsToml,
    SliceVariableToml, ADAPTER_OPERATION_HANDLER_ID, ADAPTER_RECEIPT_EVIDENCE_ID,
    SEAT_ASK_EVIDENCE_EXTRACTOR_ID, SEAT_ASK_HANDLER_ID, SEAT_ASK_INPUT_SCHEMA,
    SEAT_ASK_OUTPUT_SCHEMA,
};
pub use claude_code::{
    compose_claude_code, ClaudeAccountPolicy, ClaudeCodeToml, ClaudeDriver, ClaudeMcpScope,
    ClaudeMcpToml, ClaudePlacement, ClaudePresetToml, ClaudePresetWorkspace, ClaudeResourcesToml,
    CLAUDE_CODE_HARNESS, CLAUDE_WORKTREE,
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
pub use node::{
    node_gateway_address_class, HostToml, NodeGatewayEndpoint, NodeGatewayEndpointError, NodeToml,
};
pub use object::{
    parse_object_toml, parse_objects, ObjectConfig, ParseResult, RegistryKind, RegistryObject,
    REGISTRY_SCHEMA,
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
    ClockTime, RoutineActionKind, RoutineActionToml, RoutineEvent, RoutineSchedule, RoutineToml,
    RoutineTriggerToml, ROUTINE_TEXT_MAX_CHARS,
};
pub use seat::{
    always_covers, bind_budget_policy, utc_seconds, AccountingWindowToml, ApprovalDefaultToml,
    ApprovalDefaultsToml, BudgetPolicyToml, LaneDirection, LaneToml, LaneTransferPolicy,
    PayloadKind, ProjectToml, ResolvedBudgetPolicy, SeatContextToml, SeatConversationToml,
    SeatEphemeralToml, SeatKnowledgeToml, SeatLimitsToml, SeatLiveToml, SeatRolloverToml,
    SeatSandboxNetwork, SeatSandboxToml, SeatToml, SeatToolRedirectsToml, SeatToolsToml,
    MAX_TURN_SECONDS, SANDBOX_PATH_ROLES,
};
pub use validation::check_pod_recovery;
pub use validation::valid_id;
pub use validation::valid_memory_namespace;
pub use validation::{has_failures, validate_object};
pub(crate) use validation::{lookup_toml_path, valid_brain_scope, valid_media_type};
pub use workload::{
    compose_workload_profile, compose_workload_profiles, paths_nest_or_collide, pod_may_hold,
    storage_quantity_bytes, valid_allow_host, valid_pod_path, valid_screen, BrowserEngine,
    ComposedWorkloadProfile, WorkloadAgentView, WorkloadBriefToml, WorkloadDisplayToml,
    WorkloadExportToml, WorkloadImageToml, WorkloadLifetimeToml, WorkloadMemoryToml, WorkloadMode,
    WorkloadMonitoringToml, WorkloadNetworkToml, WorkloadProfileLookupError, WorkloadProfileToml,
    WorkloadRuntimeToml, WorkloadScriptToml, WorkloadSeatToml, WorkloadSimulationToml,
    WorkloadStateToml, MAX_WORKLOAD_DEADLINE_SECONDS, MIN_WORKLOAD_DEADLINE_SECONDS,
    NODE_CAPABILITY_LABEL_PREFIX, OMP_HARNESS, PLATFORM_IMAGE, SCRIPT_HARNESS,
    WORKLOAD_BRIEF_MAX_BYTES,
};
