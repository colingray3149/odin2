#![forbid(unsafe_code)]
#![deny(dead_code)]

//! Core domain vocabulary and transport-neutral contracts for Odin.

pub mod bus;
pub mod envelope;
pub mod error;
pub mod extension_policy;
pub mod huginn;
pub mod ids;
pub mod image_identity;
pub mod job_report;
pub mod knowledge;
pub mod operation;
pub mod progress;
pub mod scope;
pub mod status;
pub mod stop;
pub mod token;
pub mod worker;

pub use bus::{SUBJECT_APPROVAL_CHANGED, SUBJECT_COMMAND_CHANGED, SUBJECT_RUN_CHANGED};
pub use envelope::{
    Actor, CommandCapability, CommandEnvelope, CommandTarget, Correlation, EventEnvelope, Producer,
    Redaction, COMMAND_SCHEMA, EVENT_SCHEMA,
};
pub use error::DomainError;
pub use ids::{
    ApprovalId, ArmId, ArtifactId, AttemptId, CapabilityId, CheckpointId, CommandId, ContainerId,
    Digest, EventId, HostId, IncidentId, LaneId, LeaseId, NodeId, PlanId, ProjectId, ProviderId,
    RunId, SeatId, SeatTokenId, SessionId, SliceId, TaskId, TodoId, TurnId,
};
pub use image_identity::{
    ImageConfigIdentity, ImageExtensionIdentity, ImageModuleRootIdentity, ImageModuleRootsIdentity,
    ImageToolsIdentity, WorkloadImageIdentity, WORKLOAD_IMAGE_IDENTITY_SCHEMA,
};
pub use operation::{
    can_transition, CapabilityClass, EffectState, Grant, LimitKind, Limits, OperationError,
    RequestCost, Usage,
};
pub use scope::Scope;
pub use status::{ApprovalStatus, AttemptStatus, EffectClass, LaneStatus, RunStatus};
pub use stop::{
    can_transition_stop, StopAudit, StopEvidence, StopEvidenceError, StopFaultProbe,
    StopFaultProbeKind, StopMissing, StopResidue, StopResidueProcess, StopState, StopTraceEvent,
    StopTraceRow, StopVerdict, StopVerdictTag, STOP_AUTHORITY_TRACE_SCHEMA,
    WORKER_STOP_EVIDENCE_SCHEMA,
};
pub use token::{SeatToken, SEAT_TOKEN_SCHEMA_VERSION};
pub use worker::{
    can_transition_worker, InvocationId, InvocationIdError, WorkerPhase, INVOCATION_ID_HEX_LEN,
};
