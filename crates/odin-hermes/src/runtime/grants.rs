//! One owner decision for an exact batch of consequential effects. Ordinary
//! declared work needs no grant; task prose never supplies enforceable limits.

use std::sync::Arc;

use jiff::Timestamp;
use odin_domain::{ApprovalId, Scope};
use odin_omp::host_tools::task_grants::{PlannedEffect, TaskGrant};
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;

impl HermesRuntime {
    fn grant_plan(&self, arguments: &Value) -> Result<(), HostToolError> {
        let invalid = |detail: String| HostToolError::Arguments {
            tool: "task_grant",
            detail,
        };
        parse_string(arguments, "task", 1_000)?;
        let effects: Vec<PlannedEffect> = serde_json::from_value(arguments["effects"].clone())
            .map_err(|error| invalid(error.to_string()))?;
        let limits = self.batch_limits().map_err(invalid)?;
        let max_effects = usize::from(limits.max_effects);
        if effects.is_empty() || effects.len() > max_effects {
            return Err(invalid(format!(
                "a batch names 1..={max_effects} exact effects"
            )));
        }
        let batchable = self
            .contracts
            .iter()
            .filter(|(_, contract)| contract.batchable)
            .map(|(id, _)| id.as_str().to_owned())
            .collect::<Vec<_>>();
        for effect in effects {
            let Some(contract) = self.contracts.get(&effect.capability) else {
                return Err(invalid(format!(
                    "{} is not a declared capability",
                    effect.capability
                )));
            };
            if !contract.batchable {
                return Err(invalid(format!(
                    "only declared batchable capabilities can be batched ({}); ordinary declared work runs directly",
                    batchable.join(", ")
                )));
            }
            if !effect.arguments.is_object() || effect.arguments.get("approvalId").is_some() {
                return Err(invalid(
                    "effect arguments must be an object without approvalId".to_owned(),
                ));
            }
            if contract.preview == Some(odin_registry::schema::PreviewKindToml::Email) {
                let (account, draft_id, draft_digest) =
                    super::adapters::resolve_send_arguments(&effect.arguments)?;
                let adapter = self
                    .email
                    .as_ref()
                    .ok_or_else(|| invalid("the email adapter is not configured".to_owned()))?;
                adapter
                    .approved_draft(&account, &draft_id, &draft_digest)
                    .map_err(|error| invalid(error.to_string()))?;
            }
        }
        let max_minutes = i64::from(limits.max_minutes);
        arguments
            .get("minutes")
            .and_then(Value::as_i64)
            .filter(|minutes| (1..=max_minutes).contains(minutes))
            .ok_or_else(|| invalid(format!("minutes must be 1..={max_minutes}")))?;
        let max_uses = u64::from(limits.max_uses);
        arguments
            .get("max_uses")
            .and_then(Value::as_u64)
            .and_then(|uses| u32::try_from(uses).ok())
            .filter(|uses| (1..=limits.max_uses).contains(uses))
            .ok_or_else(|| invalid(format!("max_uses must be 1..={max_uses}")))?;
        Ok(())
    }

    pub(super) fn batch_limits(&self) -> Result<odin_registry::schema::BatchLimitsToml, String> {
        odin_omp::host_tools::task_grants::admitted_batch_policy(&self.contracts)
            .map(|(limits, _)| limits)
    }
}

pub(super) fn grant_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let batchable: Vec<String> = runtime
        .contracts
        .iter()
        .filter(|(_, contract)| contract.batchable)
        .map(|(id, _)| id.as_str().to_owned())
        .collect();
    let limits = runtime.batch_limits().ok();
    let max_effects = limits.map(|limit| limit.max_effects).unwrap_or(0);
    let max_minutes = limits.map(|limit| limit.max_minutes).unwrap_or(0);
    let max_uses = limits.map(|limit| limit.max_uses).unwrap_or(0);
    let listed = if batchable.is_empty() {
        "no declared batchable capabilities".to_owned()
    } else {
        batchable.join(", ")
    };
    let gate_runtime = Arc::clone(runtime);
    let gate = move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
        gate_runtime
            .task_grants()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: "task_grant",
                reason: "no task grant ledger is composed".to_owned(),
            })?;
        scope.session.as_ref().ok_or(HostToolError::Scope {
            tool: "task_grant",
            reason: "a bound session is required",
        })?;
        gate_runtime.grant_plan(arguments).map(|_| ())
    };
    let runtime = Arc::clone(runtime);
    let consumed = move |_effect: &odin_kernel::operation::PreparedEffect,
                         command: &odin_omp::host_tools::ConsumedHostCommand,
                         scope: Scope,
                         arguments: Value| {
        let store = runtime
            .task_grants()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: "task_grant",
                reason: "no task grant ledger is composed".to_owned(),
            })?;
        let session = scope.session.clone().ok_or(HostToolError::Scope {
            tool: "task_grant",
            reason: "a bound session is required",
        })?;
        runtime.grant_plan(&arguments)?;
        let unavailable = |reason| HostToolError::Unavailable {
            tool: "task_grant",
            reason,
        };
        let id = ApprovalId::new(parse_string(&arguments, "approvalId", 256)?)
            .map_err(|error| unavailable(error.to_string()))?;
        let (limits, batchable) =
            odin_omp::host_tools::task_grants::admitted_batch_policy(&runtime.contracts)
                .map_err(unavailable)?;
        let grant = {
            let ledger = runtime.adapter_ledger.lock();
            let approval = ledger
                .approval(&id)
                .map_err(|error| unavailable(error.to_string()))?
                .ok_or_else(|| unavailable("missing owner approval".to_owned()))?;
            if approval.scope != command.approval_scope()
                || approval.consumed_by_command_id.as_ref() != Some(command.command_id())
            {
                return Err(unavailable(
                    "approval does not cover this consumed command".to_owned(),
                ));
            }
            TaskGrant::from_approval(&ledger, &id, session, limits, &batchable)
                .map_err(unavailable)?
                .ok_or_else(|| {
                    unavailable("the exact batch needs a genuine owner decision".to_owned())
                })?
        };
        let now_ms = u64::try_from(Timestamp::now().as_millisecond()).unwrap_or(0);
        if now_ms >= grant.expires_at_ms {
            return Err(unavailable("the owner-approved batch expired".to_owned()));
        }
        let grant = store.record(grant, now_ms).map_err(unavailable)?;
        Ok(json!({
            "status": "granted",
            "task": grant.task,
            "capabilities": grant.capabilities,
            "until": runtime.clock.render(i64::try_from(grant.expires_at_ms).unwrap_or(i64::MAX)),
            "maxUses": grant.max_uses,
        }))
    };
    tools.push(Arc::new(CapabilityTool::approved(
        RpcHostToolDefinition {
            name: "task_grant".into(),
            label: "Get Colin's go-ahead for a whole task".into(),
            description: format!(
                "Ask once for a batch of exact declared effects ({listed}). \
             Each effects entry names capability and complete arguments, without approvalId. \
             Each entry may execute once; repeat intentions need explicit duplicate entries. \
             minutes starts at the owner's decision; max_uses caps the entire batch. Changed \
             arguments require a new decision. Delegated children share the same batch. task is \
             descriptive, never an enforced scope. Ordinary declared work runs directly without a grant."
            )
            .into(),
            parameters: object_schema(
                "task_grant",
                json!({
                    "task": { "type": "string", "minLength": 1, "maxLength": 1000 },
                    "effects": {
                        "type": "array", "minItems": 1, "maxItems": max_effects,
                        "items": {
                            "type": "object", "additionalProperties": false,
                            "properties": {
                                "capability": { "type": "string", "enum": batchable },
                                "arguments": { "type": "object", "not": { "required": ["approvalId"] } }
                            },
                            "required": ["capability", "arguments"]
                        }
                    },
                    "minutes": { "type": "integer", "minimum": 1, "maximum": max_minutes },
                    "max_uses": { "type": "integer", "minimum": 1, "maximum": max_uses },
                    "approvalId": { "type": "string", "minLength": 1, "maxLength": 256 }
                }),
                &["task", "effects", "minutes", "max_uses"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        "task.grant",
        Box::new(consumed),
        Box::new(gate),
    )));
}
