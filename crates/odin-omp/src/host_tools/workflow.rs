//! Workflow capabilities: one handler serves every `implementation = "workflow"`
//! capability by handing (capability, scope, arguments) to the authority's
//! compiled workflow catalog. Each capability's model-visible tool comes from
//! its declared name, description and input schema.
//!
//! The executor reaches [`HostTool::invoke_consumed`] for every kernel
//! dispatch, so every run carries the journaled command id as its
//! idempotency key; the other entry points refuse.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::{CapabilityId, Scope};
use odin_kernel::{CapabilityContract, HandlerBinding, PreparedEffect, SchemaCatalog};
use odin_registry::schema::{WORKFLOW_HANDLER_ID, WORKFLOW_RECEIPT_ID};
use serde_json::{json, Value};

use super::{
    ConsumedHostCommand, HostInvocation, HostTool, HostToolError, HostToolRegistry,
    InternalBindingKey, RpcHostToolDefinition, ToolLoadMode,
};

/// The authority's compiled workflows, as the workflow handler reaches them.
pub trait WorkflowRunner: Send + Sync {
    /// Whether a compiled workflow serves this capability id.
    fn compiled(&self, capability: &CapabilityId) -> bool;
    /// Read-only readiness: declared executables, roots, secrets, endpoints, and arguments.
    fn preflight(
        &self,
        capability: &CapabilityId,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError>;
    /// Runs the workflow. `consumed` carries the command id used as the
    /// idempotency key and, for operator capabilities, the consumed approval.
    fn run(
        &self,
        capability: &CapabilityId,
        scope: &Scope,
        arguments: &Value,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError>;
    /// The exact plan an approval card shows. Read-only.
    fn plan(&self, capability: &CapabilityId, arguments: &Value) -> Result<String, String>;
}

/// What the workflow handler needs: the authority's runner.
#[derive(Clone)]
pub struct WorkflowBinding {
    /// `None` off the authority: every workflow capability refuses, naming why.
    pub runner: Option<Arc<dyn WorkflowRunner>>,
}

/// The handler every workflow capability binds.
struct WorkflowTool {
    binding: WorkflowBinding,
    definition: RpcHostToolDefinition,
}

impl WorkflowTool {
    fn runner(&self) -> Result<&dyn WorkflowRunner, HostToolError> {
        self.binding.runner.as_deref().ok_or_else(|| {
            HostToolError::unavailable(
                WORKFLOW_HANDLER_ID,
                "workflows run only on the authority; this host composes none",
            )
        })
    }

    /// The consumed dispatch: the capability the permit names, with its command.
    fn run_consumed(
        &self,
        capability: &CapabilityId,
        consumed: &ConsumedHostCommand,
        invocation: &HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.runner()?.run(
            capability,
            &invocation.scope,
            &invocation.arguments,
            consumed,
        )
    }

    fn refuse_unconsumed() -> HostToolError {
        HostToolError::Catalog {
            detail: format!("{WORKFLOW_HANDLER_ID} requires a kernel-minted prepared operation"),
        }
    }
}

impl HostTool for WorkflowTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(Self::refuse_unconsumed())
    }

    fn invoke_prepared(
        &self,
        _effect: &PreparedEffect,
        _invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        Err(Self::refuse_unconsumed())
    }

    fn invoke_consumed(
        &self,
        effect: &PreparedEffect,
        consumed: &ConsumedHostCommand,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        self.run_consumed(&effect.contract().id, consumed, &invocation)
    }

    fn preflight(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.runner()?.preflight(&contract.id, scope, arguments)
    }
}

/// The receipt of one workflow call: which capability and what it did.
struct WorkflowReceipt {
    definition: RpcHostToolDefinition,
}

impl HostTool for WorkflowReceipt {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let output = invocation.arguments.get("output");
        let field = |name: &str| output.and_then(|output| output.get(name)).cloned();
        let Some(done) = field("done") else {
            return Err(HostToolError::Arguments {
                tool: WORKFLOW_RECEIPT_ID,
                detail: "the workflow output carries no done line".to_owned(),
            });
        };
        Ok(json!({ "capability": field("capability"), "done": done }))
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }
}

/// The model-visible face of one workflow capability; calls reach the
/// handler through the operation authority, never this name.
struct DeclaredWorkflowTool {
    definition: RpcHostToolDefinition,
}

impl HostTool for DeclaredWorkflowTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} must be dispatched through the operation authority",
                self.definition.name
            ),
        })
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }
}

fn marker_definition(name: &'static str) -> RpcHostToolDefinition {
    RpcHostToolDefinition {
        name: Cow::Borrowed(name),
        label: Cow::Borrowed("Workflow"),
        description: Cow::Borrowed("Workflow marker binding; never listed."),
        parameters: json!({"type": "object"}),
        hidden: true,
        load_mode: ToolLoadMode::Essential,
    }
}

/// Registers the workflow handler and receipt, and each workflow
/// capability's model-visible tool from its declared name, description and
/// input schema. On the authority every workflow capability must have a
/// compiled function.
pub fn register(
    registry: &mut HostToolRegistry,
    binding: WorkflowBinding,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    schemas: &dyn SchemaCatalog,
) -> Result<(), HostToolError> {
    let marker = HandlerBinding::Builtin {
        name: WORKFLOW_HANDLER_ID.to_owned(),
    };
    for contract in contracts
        .values()
        .filter(|contract| contract.handler == marker)
    {
        if let Some(runner) = &binding.runner {
            if !runner.compiled(&contract.id) {
                return Err(HostToolError::Catalog {
                    detail: format!(
                        "workflow capability {} has no compiled workflow; add it to its \
                         family's WORKFLOWS table",
                        contract.id
                    ),
                });
            }
        }
        let schema = schemas
            .schema(&contract.input_schema_ref)
            .map_err(|error| HostToolError::Catalog {
                detail: format!(
                    "workflow capability {} input schema {}: {error}",
                    contract.id, contract.input_schema_ref
                ),
            })?;
        registry.register(Arc::new(DeclaredWorkflowTool {
            definition: RpcHostToolDefinition {
                name: Cow::Owned(contract.tool_name.as_str().to_owned()),
                label: Cow::Owned(contract.id.as_str().to_owned()),
                description: Cow::Owned(contract.description.clone()),
                parameters: schema.canonical_json().clone(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }))?;
    }
    registry.register_internal(
        InternalBindingKey::Builtin(WORKFLOW_HANDLER_ID.to_owned()),
        Arc::new(WorkflowTool {
            binding,
            definition: marker_definition(WORKFLOW_HANDLER_ID),
        }),
    )?;
    registry.register_internal(
        InternalBindingKey::Builtin(WORKFLOW_RECEIPT_ID.to_owned()),
        Arc::new(WorkflowReceipt {
            definition: marker_definition(WORKFLOW_RECEIPT_ID),
        }),
    )
}

#[cfg(test)]
#[path = "workflow_tests.rs"]
mod tests;
