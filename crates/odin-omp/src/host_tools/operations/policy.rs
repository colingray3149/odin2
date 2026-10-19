//! Operation policy composition: the digests, identity projections, and
//! host-owned (seat, lane) policy material every dispatch re-verifies
//! against. This module constructs policy and invocation identities; it
//! never grants or settles authority.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::{ResourceConstraint, ToolName};
use odin_domain::{ApprovalStatus, CapabilityId, CommandId, Digest, DomainError, Scope, SessionId};
use odin_kernel::{
    arguments_digest, CapabilityContract, OperationRejection, PolicyContext, ToolInvocation,
};
use odin_ledger::Ledger;
use odin_types::{CapsuleId, CorrelationId};
use serde_json::Value;

use super::HostToolOperationError;

/// Shared by catalog admission, policy contexts, and provisioned tokens to keep their digests consistent.
pub fn admission_digest(
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    snapshot_revision: i64,
) -> Result<Digest, HostToolOperationError> {
    let material = serde_json::json!({
        "admission_revision": snapshot_revision,
        "contracts": contracts,
    });
    let canonical = odin_strict_json::canonicalize(&material).map_err(|error| {
        HostToolOperationError::Composition {
            detail: format!("admission material is not canonicalizable: {error}"),
        }
    })?;
    Ok(Digest::hash(&canonical))
}

pub fn context_policy_digest(
    seat_id: &str,
    slice_id: &str,
    lane_id: &str,
    seat_revision: Digest,
    slice_revision: Digest,
) -> Digest {
    let material = serde_json::json!({
        "seat_id": seat_id,
        "slice_id": slice_id,
        "lane_id": lane_id,
        "seat_revision": seat_revision,
        "slice_revision": slice_revision,
    });
    let canonical =
        serde_json::to_vec(&material).expect("context policy material serialization is total");
    Digest::hash(&canonical)
}

/// The host-issued capsule identity of one bridge session. Deterministic from
/// the host-owned session id, so a reclaimed session reopens the same capsule
/// and the extension's `ODIN_CAPSULE_ID` environment value matches it.
pub fn session_capsule_id(session: &SessionId) -> Result<CapsuleId, HostToolOperationError> {
    CapsuleId::new(&format!("capsule:{}", session.as_str())).map_err(|error| {
        HostToolOperationError::Composition {
            detail: format!("session id cannot carry a capsule identity: {error}"),
        }
    })
}

/// The untrusted idempotency input of one side-channel request: a
/// deterministic projection of the host-issued session identity and the
/// request identity. The kernel binds it into the full request digest, so a
/// same-correlation different-payload request is a durable conflict and an
/// identical one is a replay.
pub fn correlation_for(
    session: &SessionId,
    request_id: &str,
) -> Result<CorrelationId, HostToolOperationError> {
    let digest = Digest::hash(
        format!(
            "odin.omp.host-tool-correlation.v1\0{}\0{request_id}",
            session.as_str()
        )
        .as_bytes(),
    );
    let rendered = digest.to_string();
    let hex = rendered.strip_prefix("blake3:").unwrap_or(&rendered);
    let Some(prefix) = hex.get(..32) else {
        return Err(HostToolOperationError::Composition {
            detail: "correlation digest material is shorter than 32 hex characters".to_owned(),
        });
    };
    CorrelationId::new(prefix).map_err(|error| HostToolOperationError::Composition {
        detail: format!("correlation projection is not a valid correlation id: {error}"),
    })
}

/// Shared by dispatch and `ConsumedHostCommand` so approvals identify the journaled command.
pub(crate) fn host_tool_command_id(
    correlation_id: &CorrelationId,
) -> Result<CommandId, DomainError> {
    CommandId::new(format!("odin.omp.host_tool:{correlation_id}"))
}

/// Restores only this command's original approval decoration. Selecting it
/// grants nothing: fresh authorization still checks its recorded binding.
pub(super) fn restore_consumed_approval(
    ledger: &Ledger,
    invocation: &mut ToolInvocation,
    correlation: &CorrelationId,
    issuer: &str,
) -> Result<(), HostToolOperationError> {
    if invocation.approval_id.is_some() {
        return Ok(());
    }
    let Some(command) = ledger.command(&invocation.command_id)? else {
        return Ok(());
    };
    let Some(approval_id) = command.approval_id.as_ref() else {
        return Ok(());
    };
    let Some(approval) = ledger.approval(approval_id)? else {
        return Ok(());
    };
    if approval.status != ApprovalStatus::Consumed
        || approval.consumed_by_command_id.as_ref() != Some(&invocation.command_id)
    {
        return Ok(());
    }
    if let Some(arguments) = invocation.arguments.as_object_mut() {
        arguments.insert("approvalId".into(), Value::String(approval_id.to_string()));
    }
    let digest = arguments_digest(&invocation.arguments);
    if command.correlation_id != correlation.as_str()
        || command.issuer != issuer
        || command.capability_id != invocation.capability_id
        || command.capability_version != i64::from(invocation.capability_version)
        || command.target_kind != invocation.target.kind
        || command.target_id != invocation.target.id
        || command.arguments_hash != digest
        || command.arguments != invocation.arguments
    {
        return Err(HostToolOperationError::Authority(
            OperationRejection::DuplicateConflict {
                correlation_id: correlation.clone(),
            },
        ));
    }
    invocation.arguments_digest = digest;
    invocation.expected_revision = Some(approval.revision);
    invocation.approval_id = Some(approval.approval_id);
    Ok(())
}

/// Per-(seat, lane) host-owned policy material assembled from validated
/// registry state. The factory derives the per-session capsule identity when
/// binding a session to it.
#[derive(Clone)]
pub struct SeatOperationPolicy {
    pub policy: PolicyContext,
    /// Digest binding seat, slice, lane, and their revisions into the token.
    pub context_policy_digest: Digest,
}

/// Validated registry inputs of one (seat, lane) policy binding, in
/// [`seat_operation_policy`] parameter order.
pub struct SeatOperationPolicyInputs {
    pub seat_id: odin_domain::SeatId,
    pub slice_id: odin_domain::SliceId,
    pub lane_id: odin_domain::LaneId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub admission: Digest,
    pub seat_tool_refs: BTreeSet<CapabilityId>,
    pub slice_capabilities: BTreeSet<CapabilityId>,
    pub project_capabilities: BTreeSet<CapabilityId>,
    pub lane_capabilities: BTreeSet<CapabilityId>,
    pub denied_capabilities: BTreeSet<CapabilityId>,
    pub denied_tools: BTreeSet<ToolName>,
    pub resource_constraints: BTreeMap<CapabilityId, Vec<ResourceConstraint>>,
    pub seat_categories: BTreeSet<String>,
}

/// Assembles one (seat, lane) policy binding from validated registry parts.
/// The single construction site for [`SeatOperationPolicy`]: the admission
/// digest is the catalog's, so the policy context, the token binding, and
/// the catalog admissions cannot drift apart.
pub fn seat_operation_policy(inputs: SeatOperationPolicyInputs) -> SeatOperationPolicy {
    let SeatOperationPolicyInputs {
        seat_id,
        slice_id,
        lane_id,
        seat_revision,
        slice_revision,
        admission,
        seat_tool_refs,
        slice_capabilities,
        project_capabilities,
        lane_capabilities,
        denied_capabilities,
        denied_tools,
        resource_constraints,
        seat_categories,
    } = inputs;
    let context_policy_digest = context_policy_digest(
        seat_id.as_str(),
        slice_id.as_str(),
        lane_id.as_str(),
        seat_revision,
        slice_revision,
    );
    SeatOperationPolicy {
        policy: PolicyContext {
            seat_id,
            slice_id,
            lane_id,
            seat_revision,
            slice_revision,
            capability_policy_digest: admission,
            seat_tool_refs,
            slice_capabilities,
            project_capabilities,
            lane_capabilities,
            denied_capabilities,
            denied_tools,
            seat_categories,
            adapter_health: Default::default(),
            resource_constraints,
            seat_hints: BTreeMap::new(),
        },
        context_policy_digest,
    }
}

/// Per-session, host-owned operation binding: the exact policy context the
/// seat/slice/lane authorize under, the context-policy digest the token
/// carries, and the session's capsule identity. Assembled once from validated
/// registry state; every dispatch still re-verifies, re-lists, and
/// re-authorizes against it.
#[derive(Clone)]
pub struct SessionOperationBinding {
    pub policy: PolicyContext,
    /// Digest binding seat, slice, lane, and their revisions into the token.
    pub context_policy_digest: Digest,
    pub capsule_id: CapsuleId,
    /// Retained publication selected from the token and persisted session revision.
    /// Token renewal must preserve this revision; changing it requires reopening the session.
    pub served_revision: u64,
    /// The delegated child's exact parent link. `None` for every original
    /// root session; its presence routes every dispatch through parent-first
    /// re-verification with no renewal around revocation.
    pub parent: Option<Arc<crate::host_tools::delegation::ParentSessionLink>>,
}

/// Borrows the trusted session context without cloning it at each operation entry point.
pub struct SessionOperationContext<'a> {
    pub binding: &'a SessionOperationBinding,
    /// The host-owned session identity the token and capsule bind to.
    pub session: &'a SessionId,
    pub scope: &'a Scope,
    /// The trusted execution proof captured from the host's ACTUAL bridge
    /// binding at dispatch time — never inferred from current ledger
    /// state. The host digests it into the durable executor binding, so
    /// replay re-decodes it; `None` keeps ordinary tools unchanged and
    /// fails governed knowledge tools typed.
    pub execution: Option<&'a crate::uri::ExecutionBinding>,
}
