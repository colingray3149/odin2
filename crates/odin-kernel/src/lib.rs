#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Capability authorization, approval, and recovery primitives for Odin.

pub mod approval;
pub mod authority_transition;
pub mod capability;
pub mod error;
pub mod operation;
pub mod policy;
pub mod provider;
pub mod recovery;
pub mod stop;
pub mod stop_transport;
pub mod token;
pub mod worker_broker;

pub use approval::{
    Approval, ApprovalCommand, ApprovalDecision, ApprovalGate, ApprovalRedirect, ApprovalScope,
    ConsumeOutcome, DecisionOutcome, DenialEvidence, ExpireOutcome, ExpirySweep, NewApproval,
};
pub use authority_transition::{
    AuthorityAuditKind, AuthorityAuditRecord, AuthorityDispatchReceipt, AuthorityDispatchRequest,
    AuthorityState, AuthorityTransitionController, AuthorityTransitionError,
    AuthorityTransitionPlan, AuthorityTransitionReceipt,
};
pub use capability::{
    list_capabilities, resolve_tool, AdapterHealth, ApprovalRequirement, AuthorizationRejection,
    AuthorizedInvocation, CapabilityContract, HandlerBinding, IdempotencyPolicy, InvocationTarget,
    RetryPolicy, SchemaCatalog, ToolInvocation,
};
pub use error::{KernelError, KernelResult};
pub use operation::{
    validate_input_arguments, AdmittedCapability, CapsuleOutcome, Clock, CloseMode, EffectOutcome,
    ExecutorFault, InvokeRequest, OperationAuthority, OperationCatalog, OperationDecision,
    OperationExecutor, OperationRejection, Payload, PreWorld, PreWorldRecord, PreparedBinding,
    PreparedEffect, ProcessIdentity, ReconcileOutcome, Reconciliation, RecordedBinding, StopHandle,
    StopIntentOutcome, StopOutcome, Target,
};
pub use policy::{
    arguments_digest, authorize, authorize_host_command, authorize_plan_management, effective,
    resource_is_exact, AuthorizationOutcome, PlanGate, PolicyContext,
};
pub use provider::{
    enabled_providers, provider_status_snapshot, ProviderCandidate, ProviderCandidateState,
    ProviderError, ProviderFault, ProviderFaultRecord, ProviderHealth, ProviderLaneStatus,
    ProviderLeaseCoordinator, ProviderLeaseStatus, ProviderQuotaSnapshot, ProviderResult,
    ProviderRotation, ProviderStatusSnapshot, RequestBinding, PROVIDER_STATUS_SCHEMA,
};
pub use recovery::{
    DurationSnapshot, ObservationDisposition, RecoveryAction, RecoveryDecision, RecoveryError,
    RecoveryObservation, RecoveryPhase, RecoveryPhaseSnapshot, RecoveryPolicy,
    RecoveryPolicySnapshot, RecoveryRung, RecoverySnapshot, RecoveryState, RecoveryUpdate,
    RungCooldowns, RungLimits, RECOVERY_SNAPSHOT_VERSION,
};
pub use stop::{
    recovery_worker_channel, JobReleaseEvidence, JobReleaseOutcome, JobStopEvidenceRecord,
    JobStopOutcome, JobWorkerBackend, JobWorkerBackendFault, JobWorkerIdentity,
    JobWorkerRegistration, JobWorkerRegistrationOutcome, StopAuthority, StopAuthorityError,
    StopEvidenceRecord, WorkerLaunch,
};
pub use stop_transport::StopAuthorityProcessTransport;
pub use token::{
    ExpectedBindings, FreshAuthority, LedgerRevocations, MemoryRevocations, MintRequest,
    RevocationStore, SeatAuthority, TokenError, TokenIssuer, TokenVerifier,
};
pub use worker_broker::{
    AllowedParentBindings, BrokerEnvironmentEntry, BrokerIdentity, BrokerLimits, BrokerNaming,
    BrokerRejectionCode, BrokerRequest, BrokerResponse, BrokerSpec, BrokerStopOutcome,
    BrokerStopRecord, ParentAuthorityClient, ParentAuthorityDescriptor, ParentAuthorityError,
    ParentBrokerServer, ParentBrokerShutdown, ParentExecutableBinding, ParentExecutableProfile,
    MAX_BROKER_NESTING_DEPTH, MAX_BROKER_STDIN_WRITE_TIMEOUT, MAX_BROKER_WAIT_TIMEOUT,
    MAX_FRAME_BYTES, PARENT_AUTHORITY_ENV, SCOPE_LEDGER_NAME,
};
