//! `task.note`: pins a note to an open task through the runtime's scoped brain service.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, Weak};

use odin_domain::{CapabilityId, Digest, Scope};
use odin_kernel::{CapabilityContract, PreparedEffect};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{
    ConsumedHostCommand, HostInvocation, HostTool, HostToolError, HostToolRegistry,
    InternalBindingKey, RpcHostToolDefinition, ToolLoadMode,
};
use crate::uri::ExecutionBinding;

pub const NOTE_HANDLER: &str = "odin_brain.note";
pub const NOTE_EVIDENCE: &str = "odin_brain.note_evidence";
pub const MAX_RESPONSE_BYTES: usize = 262_144;

/// One note pinned to an open task by the id live memory shows.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskNoteInput {
    pub task: String,
    pub note: String,
}

/// Runtime composition binds this slot once, after services and URI routing exist.
pub type BrainToolsSlot = Arc<OnceLock<Arc<dyn BrainToolsBackend>>>;

pub trait BrainToolsBackend: Send + Sync {
    fn preflight(&self, scope: &Scope) -> Result<(), HostToolError>;
    fn note(
        &self,
        scope: &Scope,
        execution: &ExecutionBinding,
        input: TaskNoteInput,
    ) -> Result<Value, HostToolError>;
}

/// The model-facing name of `task.note`, the one tool left on this backend.
const TOOL: &str = "task_note";

struct BrainTool {
    // Runtime owns the slot; services may own operation gates which own
    // this registry. A weak edge prevents retaining the runtime in a cycle.
    slot: Weak<OnceLock<Arc<dyn BrainToolsBackend>>>,
    definition: RpcHostToolDefinition,
}

impl BrainTool {
    fn backend(&self) -> Result<Arc<dyn BrainToolsBackend>, HostToolError> {
        self.slot
            .upgrade()
            .and_then(|slot| slot.get().cloned())
            .ok_or_else(|| HostToolError::Unavailable {
                tool: TOOL,
                reason: "brain runtime is not composed or has stopped".into(),
            })
    }

    fn input(&self, arguments: Value) -> Result<TaskNoteInput, HostToolError> {
        let invalid = |detail: String| HostToolError::Arguments { tool: TOOL, detail };
        let input: TaskNoteInput =
            serde_json::from_value(arguments).map_err(|error| invalid(error.to_string()))?;
        if input.task.trim().is_empty() || input.note.trim().is_empty() {
            return Err(invalid("task and note must hold text".into()));
        }
        Ok(input)
    }
}

impl HostTool for BrainTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.input(arguments.clone())?;
        self.backend()?.preflight(scope)
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Scope {
            tool: TOOL,
            reason: "brain tools require governed execution proof",
        })
    }

    fn invoke_execution(
        &self,
        _effect: &PreparedEffect,
        _consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
        execution: Option<&ExecutionBinding>,
    ) -> Result<Value, HostToolError> {
        let execution = execution.ok_or(HostToolError::Scope {
            tool: TOOL,
            reason: "the caller supplied no trusted execution proof",
        })?;
        let input = self.input(invocation.arguments)?;
        let output = self.backend()?.note(&invocation.scope, execution, input)?;
        let bytes = serde_json::to_vec(&output).map_err(|error| HostToolError::Response {
            tool: TOOL,
            detail: error.to_string(),
        })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(HostToolError::Unavailable {
                tool: TOOL,
                reason: "knowledge response exceeds the transport bound".into(),
            });
        }
        Ok(output)
    }

    fn requires_execution_proof(&self) -> bool {
        true
    }
}

struct BrainEvidence {
    definition: RpcHostToolDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceInput {
    output: Value,
}

impl HostTool for BrainEvidence {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }
    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Evidence exists only after the governed handler returns.
        Ok(())
    }
    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let input: EvidenceInput =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: "brain_evidence",
                    detail: error.to_string(),
                }
            })?;
        let bytes = odin_strict_json::canonicalize(&input.output).map_err(|error| {
            HostToolError::Response {
                tool: "brain_evidence",
                detail: error.to_string(),
            }
        })?;
        Ok(json!({"contentDigest": Digest::hash(&bytes), "byteCount": bytes.len()}))
    }
}

pub fn register(
    registry: &mut HostToolRegistry,
    slot: BrainToolsSlot,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
) -> Result<(), HostToolError> {
    for contract in contracts.values() {
        if contract.id.as_str() != "task.note" {
            continue;
        }
        let parameters = crate::capability_parameters!("task.note");
        let tool: Arc<dyn HostTool> = Arc::new(BrainTool {
            slot: Arc::downgrade(&slot),
            definition: RpcHostToolDefinition {
                name: contract.tool_name.as_str().to_owned().into(),
                label: contract.id.as_str().to_owned().into(),
                description: contract.description.clone().into(),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        });
        registry.register(Arc::clone(&tool))?;
        registry.register_internal(InternalBindingKey::Builtin(NOTE_HANDLER.into()), tool)?;
        registry.register_internal(InternalBindingKey::Builtin(NOTE_EVIDENCE.into()), Arc::new(BrainEvidence {
            definition: RpcHostToolDefinition {
                name: NOTE_EVIDENCE.into(), label: "Brain evidence".into(),
                description: "Internal content-free digest of a governed knowledge response.".into(),
                parameters: json!({"type":"object","additionalProperties":false,"properties":{"output":{"type":"object"}},"required":["output"]}),
                hidden: true, load_mode: ToolLoadMode::Essential,
            },
        }))?;
    }
    Ok(())
}
