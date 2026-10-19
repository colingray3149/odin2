//! Capability listings expire with their verified seat token.

use std::collections::BTreeMap;

use odin_domain::huginn::ids::LiveSessionId;
use odin_domain::knowledge::context::{CapabilityListingInit, ToolCapabilityInit};
use odin_domain::knowledge::{CapabilityListing, ToolCapability};
use odin_domain::{CapabilityId, SessionId};
use time::OffsetDateTime;

use crate::capability::{CapabilityContract, SchemaCatalog};
use crate::error::{KernelError, KernelResult};
use crate::policy::{effective, PolicyContext};
use crate::token::SeatAuthority;

/// Filter unavailable contracts before schema resolution so they cannot enter the listing digest.
pub fn list_capabilities(
    authority: &SeatAuthority,
    policy: &PolicyContext,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    schemas: &dyn SchemaCatalog,
    now_ms: u64,
) -> KernelResult<CapabilityListing> {
    require_policy_binding(authority, policy)?;
    require_authority_lifetime(authority, now_ms)?;

    let effective = effective(policy, contracts);
    let mut tools = Vec::with_capacity(effective.len());
    for capability_id in effective {
        let contract = contracts
            .get(&capability_id)
            .ok_or_else(|| KernelError::NotFound {
                kind: "capability contract",
                id: capability_id.to_string(),
            })?;
        tools.push(resolve_tool(policy, contract, schemas)?);
    }

    let issued_at = timestamp(now_ms)?;
    let expires_at = timestamp(authority.expires_at_ms())?;
    CapabilityListing::new(CapabilityListingInit {
        seat_id: authority.seat().clone(),
        slice_id: authority.slice().clone(),
        session_id: live_session(authority.session())?,
        seat_token_id: authority.token_id().clone(),
        policy_digest: authority.capability_policy_digest(),
        issued_at,
        expires_at,
        tools,
    })
    .map_err(KernelError::from)
}
/// Share schema and resource resolution with host admission so the checks cannot drift.
pub fn resolve_tool(
    policy: &PolicyContext,
    contract: &CapabilityContract,
    schemas: &dyn SchemaCatalog,
) -> KernelResult<ToolCapability> {
    let input_schema = schemas.schema(&contract.input_schema_ref)?;
    schemas.schema(&contract.output_schema_ref)?;
    let schema_digest = input_schema.digest();
    let resources = policy
        .resource_constraints
        .get(&contract.id)
        .cloned()
        .unwrap_or_default();
    ToolCapability::new(ToolCapabilityInit {
        capability_id: contract.id.clone(),
        tool_name: contract.tool_name.clone(),
        description: contract.description.clone(),
        input_schema,
        schema_digest,
        resource_constraints: resources,
    })
    .map_err(KernelError::from)
}

pub(crate) fn require_policy_binding(
    authority: &SeatAuthority,
    policy: &PolicyContext,
) -> KernelResult<()> {
    if policy.is_bound_to(authority) {
        Ok(())
    } else {
        Err(KernelError::InvalidAuthority(
            "policy context does not match verified seat authority".to_owned(),
        ))
    }
}

pub(crate) fn require_authority_lifetime(
    authority: &SeatAuthority,
    now_ms: u64,
) -> KernelResult<()> {
    if now_ms < authority.issued_at_ms() {
        return Err(KernelError::InvalidAuthority(
            "seat authority is not yet valid".to_owned(),
        ));
    }
    if now_ms >= authority.expires_at_ms() {
        return Err(KernelError::InvalidAuthority(
            "seat authority has expired".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn live_session(session: &SessionId) -> KernelResult<LiveSessionId> {
    LiveSessionId::parse(session.as_str()).map_err(|_| {
        KernelError::InvalidAuthority(
            "seat authority session is not a canonical live-session identifier".to_owned(),
        )
    })
}

pub(crate) fn timestamp(timestamp_ms: u64) -> KernelResult<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(timestamp_ms) * 1_000_000).map_err(|_| {
        KernelError::InvalidAuthority("authority timestamp is out of range".to_owned())
    })
}
