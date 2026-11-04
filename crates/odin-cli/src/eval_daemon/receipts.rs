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

/// The wire name of the one tool this sidecar owner serves.
const TOOL: &str = "odin_canonical_v2";

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
    /// The host path of the capsule this sidecar serves; code.look reads its screenshots here.
    capsule_root: PathBuf,
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
                tool: TOOL,
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
                .map_err(|detail| HostToolError::Uncertain { tool: TOOL, detail })?
                .ok_or_else(|| HostToolError::Uncertain {
                    tool: TOOL,
                    detail: format!(
                        "operation correlation {} has no durable effector receipt",
                        correlation_id
                    ),
                })?;
            return self.project(binding, receipt, &invocation.arguments);
        }

        let arguments = strict_arguments(TOOL, &invocation.arguments)?;
        let capability =
            ToolId::new(binding.capability_id()).map_err(|error| HostToolError::Catalog {
                detail: format!("compiled capability id is malformed: {error}"),
            })?;
        let receipt_correlation = correlation_id.clone();
        let expected_capsule = capsule_id.clone();
        let response = self
            .client
            .lock()
            .map_err(|error| HostToolError::Storage {
                tool: TOOL,
                detail: format!("sidecar client lock: {error}"),
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
                    .map_err(|detail| HostToolError::Uncertain { tool: TOOL, detail })?
                    .ok_or_else(|| HostToolError::Uncertain {
                        tool: TOOL,
                        detail: "committed sidecar operation has no durable receipt".to_owned(),
                    })?;
                if receipt.get("operation_id").and_then(Value::as_str)
                    != Some(operation_id.as_str())
                {
                    return Err(HostToolError::Uncertain {
                        tool: TOOL,
                        detail: "sidecar response and durable receipt operation ids differ"
                            .to_owned(),
                    });
                }
                self.project(binding, receipt, &invocation.arguments)
            }
            Response::CapabilityInvoked {
                state: OperationState::Aborted,
                ..
            } => Err(HostToolError::Arguments {
                tool: TOOL,
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
                tool: TOOL,
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
        let tool = TOOL;
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
    let decoded = odin_strict_json::decode(&encoded, odin_sidecar_protocol::MAX_REQUEST_BYTES)
        .map_err(|error| HostToolError::Arguments {
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
        tool: TOOL,
        detail: format!("sidecar operation {operation_id} did not complete"),
    }
}

fn invoke_wire_fault(error: &odin_sidecar::SidecarError) -> HostToolError {
    let detail = format!("invoke sidecar capability failed: {error}");
    let landed_unknown = match error.code() {
        odin_sidecar::SidecarErrorCode::Unanswered => true,
        odin_sidecar::SidecarErrorCode::Remote => error.detail().starts_with("executor.uncertain:"),
        _ => false,
    };
    if landed_unknown {
        HostToolError::Uncertain { tool: TOOL, detail }
    } else {
        HostToolError::Arguments { tool: TOOL, detail }
    }
}

/// One Execute receipt's observations, decoded for a capability's projection.
pub(super) struct Captured {
    pub(super) exit_code: Option<i64>,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) stdout_truncated: bool,
    /// Absolute capsule paths that differ from the capsule's base after the effect.
    pub(super) changed: Vec<String>,
}

impl Captured {
    fn from_receipt(receipt: &Value) -> Result<Self, HostToolError> {
        let text = |key: &str| -> Result<String, HostToolError> {
            let hex = receipt[key].as_str().unwrap_or_default();
            odin_types::hash::hex_decode(hex)
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|error| HostToolError::Uncertain {
                    tool: TOOL,
                    detail: format!("durable receipt {key} is malformed: {error}"),
                })
        };
        Ok(Self {
            exit_code: receipt["exit_code"].as_i64(),
            stdout: text("stdout_hex")?,
            stderr: text("stderr_hex")?,
            stdout_truncated: receipt["stdout_truncated"].as_bool().unwrap_or(false),
            changed: receipt["filesystem_changes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|change| change["path"].as_str().map(str::to_owned))
                .collect(),
        })
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
                tool: TOOL,
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
    /// Adopts an already-authenticated sidecar client for the capsule at
    /// `capsule_root`. The caller keeps single-connection ownership of the sidecar.
    pub fn adopt(
        client: SidecarClient,
        receipts: Arc<dyn CanonicalEffectReceiptReader>,
        capsule_root: PathBuf,
    ) -> Self {
        Self {
            client: Mutex::new(client),
            receipts,
            capsule_root,
        }
    }

    /// The code capabilities answer in the seat's terms; the capsule ones return their receipt.
    fn project(
        &self,
        binding: CanonicalV2CapabilityBinding,
        receipt: Value,
        arguments: &Value,
    ) -> Result<Value, HostToolError> {
        match binding {
            CanonicalV2CapabilityBinding::Rewrite
            | CanonicalV2CapabilityBinding::RewriteEvidence => super::rewrite::project(
                &Captured::from_receipt(&receipt)?,
                arguments,
                &self.capsule_root,
            ),
            CanonicalV2CapabilityBinding::Look | CanonicalV2CapabilityBinding::LookEvidence => {
                super::look::project(&Captured::from_receipt(&receipt)?, &self.capsule_root)
            }
            _ => project_capability_receipt(binding, receipt),
        }
    }
}
