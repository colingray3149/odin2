//! Sidecar capability execution and result reading.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_omp::host_tools::{
    CanonicalV2CapabilityBinding, CanonicalV2CapabilityOwner, HostInvocation, HostToolError,
};
use odin_sidecar::SidecarClient;
use odin_sidecar_protocol::{Arguments, Budget, OperationState, Response, U64Wire};
use odin_types::{CapsuleId, CorrelationId, ToolId};
use serde_json::Value;

/// Read-only durable receipt source paired with one authenticated sidecar.
/// Implementations must verify the receipt against the operation journal's
/// evidence digest; absence is not converted into an empty receipt.
pub trait CanonicalEffectReceiptReader: Send + Sync {
    fn effect_receipt(&self, correlation_id: &CorrelationId) -> Result<Option<Value>, String>;
}

/// Persistent receipt reader for an out-of-process sidecar. The sidecar API
/// opens its authority ledger read-only and verifies the receipt bytes,
/// operation identity, recomputed digest, and journal evidence digest.
pub struct PersistentEffectReceiptReader {
    state_root: PathBuf,
}

impl PersistentEffectReceiptReader {
    pub fn new(state_root: PathBuf) -> Result<Self, String> {
        if !state_root.is_absolute() {
            return Err("sidecar receipt state root must be absolute".to_owned());
        }
        Ok(Self { state_root })
    }
}

impl CanonicalEffectReceiptReader for PersistentEffectReceiptReader {
    fn effect_receipt(&self, correlation_id: &CorrelationId) -> Result<Option<Value>, String> {
        match odin_sidecar::effect_receipt_at(&self.state_root, correlation_id) {
            Ok(receipt) => serde_json::to_value(receipt)
                .map(Some)
                .map_err(|error| format!("effect receipt is not representable: {error}")),
            Err(error) if error.code() == odin_sidecar::SidecarErrorCode::UnknownOperation => {
                Ok(None)
            }
            Err(error) => Err(format!("effect receipt verification failed: {error}")),
        }
    }
}

/// Concrete OMP HostTool owner for the compiled canonical-v2 bindings.
/// The caller owns the sidecar worker lifecycle and must keep it alive for
/// at least as long as this owner; dropping the owner closes its sole client
/// connection and lets the sidecar retire.
pub struct CanonicalV2SidecarOwner {
    client: Mutex<SidecarClient>,
    receipts: Arc<dyn CanonicalEffectReceiptReader>,
}

impl CanonicalV2CapabilityOwner for CanonicalV2SidecarOwner {
    fn invoke_authority_binding(
        &self,
        binding: CanonicalV2CapabilityBinding,
        capsule_id: CapsuleId,
        correlation_id: CorrelationId,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let session = invocation
            .scope
            .session
            .as_ref()
            .ok_or(HostToolError::Scope {
                tool: "odin_canonical_v2",
                reason: "the prepared scope has no session identity",
            })?;
        let expected =
            odin_omp::host_tools::operations::session_capsule_id(session).map_err(|error| {
                HostToolError::Catalog {
                    detail: format!("prepared capsule identity rejected: {error}"),
                }
            })?;
        if expected != capsule_id {
            return Err(HostToolError::Catalog {
                detail: "prepared capsule identity contradicts the bound session".to_owned(),
            });
        }

        if binding.is_evidence_extractor() {
            let receipt = self
                .receipts
                .effect_receipt(&correlation_id)
                .map_err(|detail| HostToolError::Uncertain {
                    tool: "odin_canonical_v2",
                    detail,
                })?
                .ok_or_else(|| HostToolError::Uncertain {
                    tool: "odin_canonical_v2",
                    detail: format!(
                        "operation correlation {} has no durable effector receipt",
                        correlation_id
                    ),
                })?;
            return project_capability_receipt(binding, receipt);
        }

        let arguments = strict_arguments("odin_canonical_v2", &invocation.arguments)?;
        let capability =
            ToolId::new(binding.capability_id()).map_err(|error| HostToolError::Catalog {
                detail: format!("compiled capability id is malformed: {error}"),
            })?;
        let receipt_correlation = correlation_id.clone();
        let expected_capsule = capsule_id.clone();
        let response = self
            .client
            .lock()
            .map_err(|_| HostToolError::Storage {
                tool: "odin_canonical_v2",
                detail: "sidecar client lock is poisoned".to_owned(),
            })?
            .invoke_capability(
                capsule_id,
                correlation_id,
                capability,
                Budget {
                    requests: U64Wire::new(1),
                    stops: U64Wire::new(0),
                    spend: U64Wire::new(0),
                },
                arguments,
            )
            .map_err(|error| invoke_wire_fault(&error))?;
        match response {
            Response::CapabilityInvoked {
                capsule_id,
                correlation_id,
                operation_id,
                state: OperationState::Committed,
                ..
            } if capsule_id == expected_capsule && correlation_id == receipt_correlation => {
                let receipt = self
                    .receipts
                    .effect_receipt(&receipt_correlation)
                    .map_err(|detail| HostToolError::Uncertain {
                        tool: "odin_canonical_v2",
                        detail,
                    })?
                    .ok_or_else(|| HostToolError::Uncertain {
                        tool: "odin_canonical_v2",
                        detail: "committed sidecar operation has no durable receipt".to_owned(),
                    })?;
                if receipt.get("operation_id").and_then(Value::as_str)
                    != Some(operation_id.as_str())
                {
                    return Err(HostToolError::Uncertain {
                        tool: "odin_canonical_v2",
                        detail: "sidecar response and durable receipt operation ids differ"
                            .to_owned(),
                    });
                }
                project_capability_receipt(binding, receipt)
            }
            Response::CapabilityInvoked {
                state: OperationState::Aborted,
                ..
            } => Err(HostToolError::Arguments {
                tool: "odin_canonical_v2",
                detail: "compiled effector rejected the prepared operation".to_owned(),
            }),
            Response::CapabilityInvoked {
                capsule_id,
                correlation_id,
                operation_id,
                state: OperationState::InDoubt,
                ..
            } if capsule_id == expected_capsule && correlation_id == receipt_correlation => {
                Err(in_doubt_fault(operation_id.as_str()))
            }
            other => Err(HostToolError::Uncertain {
                tool: "odin_canonical_v2",
                detail: format!("sidecar returned nonterminal authority response {other:?}"),
            }),
        }
    }

    fn preflight_authority_binding(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        binding: CanonicalV2CapabilityBinding,
        scope: &odin_domain::Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Extractors read results produced by an earlier invocation.
        if binding.is_evidence_extractor() {
            return Ok(());
        }
        let tool = "odin_canonical_v2";
        let session = scope.session.as_ref().ok_or(HostToolError::Scope {
            tool,
            reason: "the prepared scope has no session identity",
        })?;
        odin_omp::host_tools::operations::session_capsule_id(session).map_err(|error| {
            HostToolError::Catalog {
                detail: format!("prepared capsule identity rejected: {error}"),
            }
        })?;
        strict_arguments(tool, arguments).map(|_| ())
    }
}

/// Shared strict wire validation keeps preflight and execution consistent.
pub(crate) fn strict_arguments(
    tool: &'static str,
    arguments: &Value,
) -> Result<Arguments, HostToolError> {
    let encoded = serde_json::to_vec(arguments).map_err(|error| HostToolError::Arguments {
        tool,
        detail: format!("arguments are not representable: {error}"),
    })?;
    let decoded =
        odin_strict_json::decode(&encoded, 262_144).map_err(|error| HostToolError::Arguments {
            tool,
            detail: format!("arguments are not strict JSON: {error}"),
        })?;
    Arguments::new(decoded).map_err(|error| HostToolError::Arguments {
        tool,
        detail: error.to_string(),
    })
}

fn in_doubt_fault(operation_id: &str) -> HostToolError {
    HostToolError::Uncertain {
        tool: "odin_canonical_v2",
        detail: format!("sidecar operation {operation_id} did not complete"),
    }
}

fn invoke_wire_fault(error: &odin_sidecar::SidecarError) -> HostToolError {
    let detail = format!("invoke sidecar capability failed: {error}");
    if error.code() == odin_sidecar::SidecarErrorCode::Remote
        && error.detail().starts_with("executor.uncertain:")
    {
        HostToolError::Uncertain {
            tool: "odin_canonical_v2",
            detail,
        }
    } else {
        HostToolError::Arguments {
            tool: "odin_canonical_v2",
            detail,
        }
    }
}

fn project_capability_receipt(
    binding: CanonicalV2CapabilityBinding,
    mut receipt: Value,
) -> Result<Value, HostToolError> {
    if matches!(
        binding,
        CanonicalV2CapabilityBinding::FileEdit | CanonicalV2CapabilityBinding::FileEditEvidence
    ) {
        let object = receipt
            .as_object_mut()
            .ok_or_else(|| HostToolError::Uncertain {
                tool: "odin_canonical_v2",
                detail: "durable file-edit receipt is not an object".to_owned(),
            })?;
        for identity in [
            "schema",
            "correlation_id",
            "operation_id",
            "capability",
            "capsule_id",
        ] {
            object.remove(identity);
        }
    }
    Ok(receipt)
}

#[cfg(test)]
#[path = "receipts_tests.rs"]
mod tests;

impl CanonicalV2SidecarOwner {
    /// Adopts an already-authenticated sidecar client. The caller keeps
    /// single-connection ownership of the sidecar.
    pub fn adopt(client: SidecarClient, receipts: Arc<dyn CanonicalEffectReceiptReader>) -> Self {
        Self {
            client: Mutex::new(client),
            receipts,
        }
    }
}
