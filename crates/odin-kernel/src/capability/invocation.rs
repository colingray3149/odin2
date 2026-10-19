//! Keep unchecked tool calls distinct from kernel-authorized invocations.

use odin_domain::knowledge::{CapabilityListingDigest, ResourceConstraint};
use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest, EffectClass, PlanId, SeatId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::token::SeatAuthority;

use super::contract::CapabilityContract;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationTarget {
    pub kind: String,
    pub id: String,
}

/// Untrusted tool call submitted to the kernel for authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInvocation {
    pub command_id: CommandId,
    pub capability_id: CapabilityId,
    pub capability_version: u16,
    pub listing_digest: CapabilityListingDigest,
    pub arguments: Value,
    pub arguments_digest: Digest,
    pub target: InvocationTarget,
    /// Preserve opaque execution context unchanged; only the executor interprets it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_binding: Option<Value>,
    pub expected_revision: Option<i64>,
    pub plan_id: Option<PlanId>,
    pub approval_id: Option<ApprovalId>,
    pub resource: Option<ResourceConstraint>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum AuthorizationRejection {
    NeedsPlan {
        capability_id: CapabilityId,
    },
    NeedsApproval {
        capability_id: CapabilityId,
        effect_class: EffectClass,
    },
    WrongSeat {
        capability_id: CapabilityId,
        hint: SeatId,
    },
    UnknownCapability {
        capability_id: CapabilityId,
    },
    Unavailable {
        capability_id: CapabilityId,
        reason: String,
    },
    VersionMismatch {
        requested: u16,
        available: u16,
    },
    StaleListing,
    ArgumentDigestMismatch,
    StaleRevision {
        expected: i64,
        actual: i64,
    },
    ResourceDenied {
        reason: String,
    },
    ForgedIdentity,
}

/// Private construction and move-only consumption prevent callers from forging or duplicating authorization.
#[derive(Debug, Eq, PartialEq)]
pub struct AuthorizedInvocation {
    authority: SeatAuthority,
    invocation: ToolInvocation,
    contract: CapabilityContract,
}

impl AuthorizedInvocation {
    pub(crate) fn new(
        authority: SeatAuthority,
        invocation: ToolInvocation,
        contract: CapabilityContract,
    ) -> Self {
        Self {
            authority,
            invocation,
            contract,
        }
    }

    #[must_use]
    pub const fn authority(&self) -> &SeatAuthority {
        &self.authority
    }

    #[must_use]
    pub const fn invocation(&self) -> &ToolInvocation {
        &self.invocation
    }

    #[must_use]
    pub const fn contract(&self) -> &CapabilityContract {
        &self.contract
    }
}
