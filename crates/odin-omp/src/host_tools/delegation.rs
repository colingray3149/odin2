//! Governed task delegation: the host-side contract for R1 `task.create` and
//! R0 `task.read`.
//!
//! A root session with an accepted plan may delegate one bounded
//! implementation worker. The delegation is a real governed GLM coding
//! session — the same pinned OMP process, admitted session authority, and
//! durable ledger as its parent — never an HTTP chat substitute. The worker
//! model and provider are fixed by host configuration; a caller cannot
//! choose or elevate either, and the child project must be inside the
//! parent's approved configured scope. Worker depth is bounded: a delegated
//! worker can never create another worker.
//!
//! Persist the parent-child link before minting a token or opening the child,
//! so a crash cannot leave an unlinked usable child. Open idle, install the
//! task plan and parent acceptance, then prompt.
//!
//! Before each child effect, recheck the parent's token signature, expiry,
//! session bindings, revocations, and plan acceptance before checking the child.
//! Do not renew the parent token automatically; root tokens need no parent check.
//!
//! The runtime supplies [`ChildAuthorityProvisioner`] and [`ChildSessionControl`];
//! delegation limits and orchestration stay here rather than being reimplemented there.
//!
//! Internal layout: `contracts` holds the declaration-derived contracts
//! and runtime seams, `links` the durable link ledger (the task store),
//! `vocabulary` the request/report types, `owner` the seat-ask/task
//! orchestration of [`GovernedTaskOwner`],
//! `lifecycle` the child lifecycle reconciliation and bounded parent-stop
//! ownership, and `tools` the model-facing capability routing.

mod contracts;
mod lifecycle;
pub use lifecycle::{
    gateway_fallbacks_seen, lane_stall_rates, next_declared_lane, next_switchable_lane,
    FallbackSeen, LaneStallRate, LaneSwitch, RefusedOut, StallPass, StalledOut,
    FALLBACK_OBSERVE_WINDOW_MS, MAX_STALL_RETRIES,
};
mod links;
mod owner;
#[cfg(test)]
mod provider_failure_tests;
#[cfg(test)]
mod tests;
mod tools;
mod vocabulary;

pub(crate) use contracts::live_session_id;
pub use contracts::{
    child_title, holds_task_create, nested_child_depth, provider_fault_kind, provider_turn_fault,
    ChildAuthorityProvisioner, ChildLifecycleSnapshot, ChildOpen, ChildSessionControl, ChildStop,
    ChildStopCoordinator, ChildStopRecord, DeferredDelegation, DeliveryVerdict, ParentSessionLink,
    ProviderFaultKind, ProviderFaultOrigin, ProviderTurnFault, WorkloadRest,
    INDETERMINATE_DELIVERY, MAX_DELEGATION_DEPTH, TARGET_ENDED, TASK_CREATE_CAPABILITY,
    TASK_CREATE_EVIDENCE_ID, TASK_CREATE_HANDLER_ID, TASK_CREATE_TOOL, TASK_PAUSE_CAPABILITY,
    TASK_PAUSE_EVIDENCE_ID, TASK_PAUSE_HANDLER_ID, TASK_PAUSE_TOOL, TASK_READ_CAPABILITY,
    TASK_READ_EVIDENCE_ID, TASK_READ_HANDLER_ID, TASK_READ_TOOL, TASK_STEER_CAPABILITY,
    TASK_STEER_EVIDENCE_ID, TASK_STEER_HANDLER_ID, TASK_STEER_TOOL,
};
pub use links::{
    DelegationLink, DelegationLinkLedger, DelegationPhase, GatewayFallback, LaneRefusal,
    PendingReportDelivery, PersistedLink, WorkerLane, DELEGATION_LINK_SCHEMA,
};
pub use owner::{
    CompletionEventObserver, DelegationGovernance, GovernedTaskOwner, SettledChild, SettledPod,
    TaskCompletionFacts, TaskLearningCapture, TaskOwner, TaskOwnerSlot, FAILED_POD_GRACE_MS,
};
pub use tools::{
    TaskControlEvidenceTool, TaskControlKind, TaskControlTool, TaskCreateEvidenceTool,
    TaskCreateTool, TaskReadEvidenceTool, TaskReadTool,
};
pub use vocabulary::{
    TaskBranchReport, TaskControl, TaskControlReport, TaskControlRequest, TaskCreateReceipt,
    TaskCreateRequest, TaskReadReport, TaskReadRequest, TaskResultReport, TaskToolFailure,
};
