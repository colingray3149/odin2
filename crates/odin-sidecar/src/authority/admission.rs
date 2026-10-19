//! Verify the token and current policy for each request so revocations take effect immediately.

use super::projection::projection_schemas;
use super::store::StoreRevocations;
use super::{authorization_code, strict_to_serde, Sidecar};
use crate::{SidecarError, TransportRejection};
use odin_domain::knowledge::ResourceConstraint;
use odin_domain::{CapabilityId, CommandId};
use odin_kernel::policy::{self, AuthorizationOutcome};
use odin_kernel::token::{FreshAuthority, SeatAuthority, TokenError};
use odin_kernel::{
    ApprovalGate, AuthorizedInvocation, InvocationTarget, OperationRejection, ToolInvocation,
};
use odin_types::{CapsuleId, CorrelationId};
use std::path::PathBuf;
use std::sync::Arc;

impl Sidecar {
    /// Do not cache verification across requests because expiry and revocations can change.
    pub(super) fn fresh_authority(
        &self,
        now_ms: u64,
    ) -> Result<FreshAuthority, OperationRejection> {
        FreshAuthority::verify(
            &self.token,
            self.projection.expected.bindings(),
            self.signing_key.clone(),
            StoreRevocations {
                ledger: Arc::clone(&self.ledger),
            },
            now_ms,
        )
        .map_err(|error| {
            // Log the cause because the typed refusal carries no diagnostic detail.
            tracing::error!(
                session = %self.token.session.as_str(),
                seat = %self.token.seat.as_str(),
                %error,
                "seat token refused"
            );
            match error {
                TokenError::Expired { .. } => OperationRejection::IdentityExpired {
                    expires_at_ms: self.token.expires_at_ms,
                },
                _ => OperationRejection::Unauthorized,
            }
        })
    }

    pub(super) fn authorized_invocation(
        &self,
        authority: &SeatAuthority,
        capability: &CapabilityId,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        arguments: &odin_strict_json::Value,
        now_ms: u64,
    ) -> Result<AuthorizedInvocation, TransportRejection> {
        if capsule_id.as_str() != self.executor.capsule.capsule_id.as_str() {
            return Err(TransportRejection::new(
                "authority.resource_denied",
                format!(
                    "requested capsule {:?} is not this host's authenticated capsule {:?}",
                    capsule_id.as_str(),
                    self.executor.capsule.capsule_id.as_str()
                ),
            ));
        }
        let contract = self
            .projection
            .contracts
            .get(capability)
            .cloned()
            .ok_or_else(|| {
                TransportRejection::new(
                    "authority.unknown_capability",
                    format!("capability {:?} is not admitted", capability.as_str()),
                )
            })?;
        let command_id =
            CommandId::new(format!("cmd-{}", correlation_id.as_str())).map_err(|error| {
                TransportRejection::new(
                    "sidecar.state",
                    format!("command id is not representable: {error}"),
                )
            })?;
        let arguments_json = strict_to_serde(arguments)?;
        let schemas = projection_schemas(&self.projection);
        let listing = odin_kernel::list_capabilities(
            authority,
            &self.projection.context,
            &self.projection.contracts,
            schemas.as_ref(),
            now_ms,
        )
        .map_err(|error| {
            TransportRejection::new(
                "authority.durable",
                format!("fresh capability listing failed: {error}"),
            )
        })?;
        let target = InvocationTarget {
            kind: "capsule".to_owned(),
            id: capsule_id.as_str().to_owned(),
        };
        let resource = self.authority_resource_claim(capability, &target);
        let tool_invocation = ToolInvocation {
            command_id,
            capability_id: contract.id.clone(),
            capability_version: contract.version,
            listing_digest: listing.digest,
            arguments: arguments_json.clone(),
            arguments_digest: policy::arguments_digest(&arguments_json),
            target,
            executor_binding: None,
            expected_revision: None,
            plan_id: self.projection.plan_id.clone(),
            approval_id: None,
            // Derive the resource from the authenticated target, never payload arguments.
            resource,
        };
        let mut ledger = self.ledger.lock().map_err(|_| SidecarError::poisoned())?;
        let mut approval_gate = ApprovalGate::new(&mut ledger);
        match policy::authorize(
            odin_kernel::policy::AuthorizationEnvironment {
                authority,
                policy: &self.projection.context,
                contracts: &self.projection.contracts,
                schemas: schemas.as_ref(),
                listing: &listing,
            },
            &tool_invocation,
            self.projection.plan_gate,
            &mut approval_gate,
            now_ms,
        ) {
            Ok(AuthorizationOutcome::Authorized(authorized)) => Ok(*authorized),
            Ok(AuthorizationOutcome::Rejected(reason)) => Err(TransportRejection::new(
                authorization_code(&reason),
                format!("{reason:?}"),
            )),
            Err(error) => Err(TransportRejection::new(
                "authority.durable",
                format!("authorization pipeline failed: {error}"),
            )),
        }
    }

    /// Only claim a capsule resource when the target and configured constraints both match.
    fn authority_resource_claim(
        &self,
        capability: &CapabilityId,
        target: &InvocationTarget,
    ) -> Option<ResourceConstraint> {
        if target.kind != "capsule"
            || target.id.as_str() != self.executor.capsule.capsule_id.as_str()
        {
            return None;
        }
        let listed = self
            .projection
            .context
            .resource_constraints
            .get(capability)?;
        for constraint in listed {
            let candidate = match constraint {
                ResourceConstraint::FilesystemBeneath { .. } => {
                    ResourceConstraint::FilesystemBeneath {
                        root: PathBuf::from(self.capsule_root()),
                    }
                }
                ResourceConstraint::Named { kind, .. } if kind == "capsule" => {
                    ResourceConstraint::Named {
                        kind: kind.clone(),
                        value: target.id.clone(),
                    }
                }
                _ => continue,
            };
            if listed.iter().any(|listed| listed == &candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn capsule_root(&self) -> String {
        // Only the configured capsule root can supply a filesystem resource claim.
        self.executor.capsule.root.clone()
    }
}
