//! Shared fresh, nonconsuming admission for dispatch.
//! Passing this prefix is not a permit; only dispatch enters consuming gates.

use std::sync::Arc;

use odin_domain::knowledge::ResourceConstraint;
use odin_kernel::{validate_input_arguments, OperationRejection};
use serde_json::Value;

use super::dispatch::{delegates_beyond_depth, normalize_capability_arguments};
use super::{HostToolOperationError, HostToolOperations, SessionOperationContext};

pub(super) struct CheckedDispatchPrefix {
    pub(super) material: Arc<super::RevisionMaterial>,
    pub(super) arguments: Value,
}

impl HostToolOperations {
    pub(super) fn check_dispatch_prefix(
        &self,
        context: &SessionOperationContext<'_>,
        tool_name: &str,
        resource: Option<&ResourceConstraint>,
        arguments: Value,
    ) -> Result<CheckedDispatchPrefix, HostToolOperationError> {
        // Resolve contracts from the session's publication, not the stack's startup set.
        let material = self.generation_material(context.binding)?;
        let Some(capability_id) = material.tool_index.get(tool_name) else {
            return Err(HostToolOperationError::UnknownTool {
                name: tool_name.to_owned(),
            });
        };
        let Some(contract) = material.contracts.get(capability_id) else {
            return Err(HostToolOperationError::Composition {
                detail: format!("tool {tool_name} indexes absent capability {capability_id}"),
            });
        };
        // A delegated worker cannot create another worker, even if its listing permits it.
        if let Some(parent) = &context.binding.parent {
            if delegates_beyond_depth(contract, &material.escalation_targets) {
                crate::host_tools::delegation::nested_child_depth(
                    parent.depth.saturating_add(1),
                    Some(&parent.binding.policy.seat_id),
                    &context.binding.policy.seat_id,
                )
                .map_err(|detail| HostToolOperationError::Delegation {
                    detail: detail.to_owned(),
                })?;
            }
        }
        let schema = self
            .schemas
            .schema(&contract.input_schema_ref)
            .map_err(|error| OperationRejection::NotAdmitted {
                capability: contract.id.to_string(),
                detail: format!("input schema unavailable: {error}"),
            })?;
        // A `null` for an optional property is how a strict tool-calling
        // model omits it (see `schema_compat`): drop it before anything
        // digests or validates the arguments.
        let arguments = crate::host_tools::schema_compat::drop_null_optionals(
            schema.canonical_json(),
            arguments,
        );
        let arguments = normalize_capability_arguments(contract, arguments)?;
        // Reject invalid arguments before journaling or creating or consuming an approval.
        validate_input_arguments(&schema, &arguments)?;
        // Enforce deployment constraints, such as the seat's project enum, after the canonical schema.
        if let Some(narrowing) = self.narrowing_schemas.get(tool_name) {
            validate_input_arguments(narrowing, &arguments)?;
        }
        // Authenticate before sensitive readiness probes; dispatch re-verifies after they finish.
        let now_ms = (self.clock)();
        let (_fresh, listing, policy) =
            self.fresh_listing(context.binding, context.session, now_ms)?;
        // Use the kernel's admission predicates before any readiness probe can observe sensitive state.
        if !policy.is_capability_effective(&contract.id, &material.contracts) {
            if let Some(hint) = policy.wrong_seat_hint(&contract.id) {
                return Err(HostToolOperationError::Rejected(
                    odin_kernel::AuthorizationRejection::WrongSeat {
                        capability_id: contract.id.clone(),
                        hint: hint.clone(),
                    },
                ));
            }
            return Err(HostToolOperationError::Rejected(
                odin_kernel::AuthorizationRejection::Unavailable {
                    capability_id: contract.id.clone(),
                    reason: "capability is outside the current effective policy".to_owned(),
                },
            ));
        }
        let expected_tool =
            odin_kernel::resolve_tool(&policy, contract, &*self.schemas).map_err(|error| {
                HostToolOperationError::Rejected(odin_kernel::AuthorizationRejection::Unavailable {
                    capability_id: contract.id.clone(),
                    reason: format!("effective tool projection failed: {error}"),
                })
            })?;
        if !listing.tools.iter().any(|listed| listed == &expected_tool) {
            return Err(HostToolOperationError::Rejected(
                odin_kernel::AuthorizationRejection::StaleListing,
            ));
        }
        if !odin_kernel::resource_is_exact(resource, &expected_tool.resource_constraints) {
            return Err(HostToolOperationError::Rejected(
                odin_kernel::AuthorizationRejection::ResourceDenied {
                    reason: "invocation resource is not an exact listed constraint".to_owned(),
                },
            ));
        }
        Ok(CheckedDispatchPrefix {
            material,
            arguments,
        })
    }
}
