//! Executes internal host tools using kernel permits and hashes the extractor output.
//!
//! Arbitrary effects cannot be observed without executing them, so uncertain
//! outcomes remain `in_doubt` rather than being settled from a predicted result.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use odin_adapter_core::dispatch::AdapterResultSink;
use odin_adapter_core::AdapterError;
use odin_domain::{Digest, Scope};
use odin_kernel::{
    CapabilityContract, EffectOutcome, ExecutorFault, HandlerBinding, OperationExecutor, Payload,
    PreWorld, PreparedEffect, Target,
};
use odin_types::CorrelationId;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::operations::host_tool_command_id;
use super::{
    ConsumedHostCommand, HostInvocation, HostToolError, HostToolRegistry, InternalBindingKey,
};

/// Limits results retained between settlement and the caller's pickup.
const RESULT_RELAY_CAP: usize = 1024;

/// Authorization belongs to the kernel; this executor adds no retries.
pub struct HostToolExecutor {
    registry: Arc<HostToolRegistry>,
    results: Mutex<BTreeMap<String, Value>>,
}

impl HostToolExecutor {
    pub fn new(registry: Arc<HostToolRegistry>) -> Self {
        Self {
            registry,
            results: Mutex::new(BTreeMap::new()),
        }
    }

    /// Removes a locally retained result; replayed or evicted results return `None`.
    pub fn take_result(&self, correlation_id: &CorrelationId) -> Option<Value> {
        self.lock_results().remove(correlation_id.as_str())
    }

    fn relay(&self, correlation_id: &CorrelationId, result: Value) {
        self.relay_str(correlation_id.as_str(), result);
    }

    /// Adapter and builtin outcomes share the same result pickup.
    fn relay_str(&self, correlation_id: &str, result: Value) {
        let mut results = self.lock_results();
        if results.len() >= RESULT_RELAY_CAP {
            if let Some(oldest) = results.keys().next().cloned() {
                results.remove(&oldest);
            }
        }
        results.insert(correlation_id.to_owned(), result);
    }

    fn lock_results(&self) -> MutexGuard<'_, BTreeMap<String, Value>> {
        self.results
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Crate-visible definitions of every registered listed tool. The
    /// authority projects model-visible definitions from these only for
    /// admitted names; registration alone never advertises anything.
    pub(crate) fn definitions(&self) -> Vec<crate::host_tools::RpcHostToolDefinition> {
        self.registry.definitions()
    }

    pub(crate) fn definition(
        &self,
        name: &str,
        execution_proof_supported: bool,
    ) -> Option<crate::host_tools::RpcHostToolDefinition> {
        self.registry.definition(name, execution_proof_supported)
    }

    /// Checks handler prerequisites without effects before requesting approval.
    pub(crate) fn preflight_contract(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.registry.preflight_internal(
            &internal_key_of(&contract.handler),
            contract,
            scope,
            arguments,
        )
    }
}

impl OperationExecutor for HostToolExecutor {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
    }

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        let Some(declared) = payload.arguments.get("preWorld") else {
            return Ok(None);
        };
        let raw = declared.as_str().ok_or_else(|| ExecutorFault::Rejected {
            detail: format!("payload of {} declares a non-string preWorld", contract.id),
        })?;
        let digest = Digest::parse(raw).map_err(|error| ExecutorFault::Rejected {
            detail: format!(
                "payload of {} declares an undecodable preWorld digest: {error}",
                contract.id
            ),
        })?;
        Ok(Some(PreWorld::Digest(digest)))
    }

    fn observe(
        &self,
        _contract: &CapabilityContract,
        _payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        // Arbitrary capability effects have no read-only observation.
        Ok(PreWorld::Absent)
    }

    fn expected_post_world(
        &self,
        _contract: &CapabilityContract,
        _payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        // Predicting a result would require executing the effect.
        Ok(None)
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        if effect.executor_id() != <Self as OperationExecutor>::id(self) {
            return Err(ExecutorFault::Rejected {
                detail: format!(
                    "permit names executor {:?}; this executor is {:?}",
                    effect.executor_id(),
                    <Self as OperationExecutor>::id(self)
                ),
            });
        }
        let correlation_id = effect.correlation_id().clone();
        let contract = effect.contract().clone();
        let (scope, execution) = scope_and_execution_from_binding(effect.executor_binding())?;
        validate_scope_target(effect.target(), &scope)?;
        let consumed = ConsumedHostCommand::of_permit(&effect)?;
        let handler_key = internal_key_of(&contract.handler);
        let result = self
            .registry
            .dispatch_internal(
                &effect,
                &consumed,
                &handler_key,
                HostInvocation {
                    scope: scope.clone(),
                    arguments: effect.payload().arguments.clone(),
                },
                execution.as_ref(),
            )
            .map_err(map_dispatch_error)?;
        let extractor_key = internal_key_of(&contract.evidence_extractor);
        let evidence = self
            .registry
            .dispatch_internal(
                &effect,
                &consumed,
                &extractor_key,
                HostInvocation {
                    scope,
                    arguments: serde_json::json!({ "output": result }),
                },
                execution.as_ref(),
            )
            .map_err(|error| ExecutorFault::Uncertain {
                detail: format!(
                    "handler for {} landed; the bound evidence extractor failed: {error}",
                    contract.id
                ),
            })?;
        let canonical = odin_strict_json::canonicalize(&evidence).map_err(|error| {
            ExecutorFault::Uncertain {
                detail: format!(
                    "handler for {} landed; extracted evidence is not canonicalizable: {error}",
                    contract.id
                ),
            }
        })?;
        self.relay(&correlation_id, result);
        Ok(EffectOutcome {
            post_world: None,
            evidence_digest: Digest::hash(&canonical),
            stop: None,
        })
    }
}

/// Adapter outcomes use the same result pickup as builtin outcomes.
impl AdapterResultSink for HostToolExecutor {
    fn relay_result(&self, correlation_id: &str, result: Value) -> Result<(), AdapterError> {
        self.relay_str(correlation_id, result);
        Ok(())
    }
}

impl ConsumedHostCommand {
    /// Only the executor constructs this from the permit it is consuming.
    pub(crate) fn of_permit(effect: &PreparedEffect) -> Result<Self, ExecutorFault> {
        let command_id = host_tool_command_id(effect.correlation_id()).map_err(|error| {
            ExecutorFault::Rejected {
                detail: format!(
                    "host-tool correlation {} cannot form the journaled command id: {error}",
                    effect.correlation_id()
                ),
            }
        })?;
        let contract = effect.contract();
        Ok(Self {
            command_id,
            operation_id: effect.operation_id().clone(),
            correlation_id: effect.correlation_id().clone(),
            capsule_id: effect.capsule_id().clone(),
            capability_id: contract.id.clone(),
            capability_version: contract.version,
            target: effect.target().clone(),
            arguments: effect.payload().arguments.clone(),
            arguments_digest: effect.payload().digest,
        })
    }
}

pub(crate) fn internal_key_of(binding: &HandlerBinding) -> InternalBindingKey {
    match binding {
        HandlerBinding::Builtin { name } => InternalBindingKey::Builtin(name.clone()),
        HandlerBinding::Exec { executable, argv } => InternalBindingKey::Exec {
            executable: executable.clone(),
            argv: argv.clone(),
        },
    }
}

/// Persists the scope and bridge execution binding so replay uses the original values.
/// Knowledge tools reject `None` even when other host callers permit it.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct DurableExecutorBinding {
    pub(crate) scope: Scope,
    pub(crate) execution: Option<crate::uri::ExecutionBinding>,
}

/// Requires the complete canonical binding shape stored in the permit.
fn scope_and_execution_from_binding(
    binding: Option<&Value>,
) -> Result<(Scope, Option<crate::uri::ExecutionBinding>), ExecutorFault> {
    let binding = binding.ok_or_else(|| ExecutorFault::Rejected {
        detail: "host-tool permit has no execution scope binding".to_owned(),
    })?;
    let envelope =
        DurableExecutorBinding::deserialize(binding).map_err(|error| ExecutorFault::Rejected {
            detail: format!("host-tool execution binding is not decodable: {error}"),
        })?;
    let canonical = serde_json::to_value(&envelope).map_err(|error| ExecutorFault::Rejected {
        detail: format!("host-tool execution binding is not serializable: {error}"),
    })?;
    if &canonical != binding {
        return Err(ExecutorFault::Rejected {
            detail: "host-tool execution binding is not the complete canonical shape".to_owned(),
        });
    }
    Ok((envelope.scope, envelope.execution))
}

/// The approval/journal target must name the same run carried by the complete
/// durable scope binding.
fn validate_scope_target(target: &Target, scope: &Scope) -> Result<(), ExecutorFault> {
    let Some(run) = scope.run.as_ref() else {
        return Err(ExecutorFault::Rejected {
            detail: "host-tool execution scope does not bind a run".to_owned(),
        });
    };
    if target.kind != "run" || target.id != run.as_str() {
        return Err(ExecutorFault::Rejected {
            detail: format!(
                "host-tool target {:?}:{:?} does not match bound run {:?}",
                target.kind,
                target.id,
                run.as_str()
            ),
        });
    }
    Ok(())
}

/// Failures after an effect starts must not be reported as pre-effect rejections.
fn map_dispatch_error(error: HostToolError) -> ExecutorFault {
    match error {
        HostToolError::Uncertain { tool, detail } => ExecutorFault::Uncertain {
            detail: format!("host tool `{tool}` cannot prove its effect state: {detail}"),
        },
        HostToolError::Response { tool, detail } => ExecutorFault::Uncertain {
            detail: format!(
                "host tool `{tool}` landed its effect but the result could not be projected: {detail}"
            ),
        },
        HostToolError::PostEffect {
            tool,
            detail,
            evidence_digest,
        } => ExecutorFault::PostEffectUncertain {
            detail: format!("host tool `{tool}` landed its effect; {detail}"),
            evidence_digest,
        },
        // A typed URI refusal is a pre-effect read rejection: the knowledge
        // surface resolved nothing and wrote nothing.
        HostToolError::KnowledgeUri(error) => ExecutorFault::Rejected {
            detail: error.to_string(),
        },
        other => ExecutorFault::Rejected {
            detail: other.to_string(),
        },
    }
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
