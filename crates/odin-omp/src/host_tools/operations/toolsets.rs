//! Fixed model surface over canonical identities. Routing ends before admission.
use super::{HostToolOperationError, HostToolOperations};
use crate::host_tools::RpcHostToolDefinition;
use odin_domain::{EffectClass, Scope};
use odin_kernel::{CapabilityContract, OperationRejection, SchemaCatalog};
use odin_registry::schema::CapabilityExposureToml;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const REASON_CHARS_MAX: usize = 400;
pub enum PreparedToolCall {
    /// `ignored` names the fields a read dropped; the result carries them back (`with_ignored`).
    Call {
        name: String,
        arguments: Value,
        ignored: Vec<String>,
    },
    Help(Value),
}

fn composition(detail: String) -> HostToolOperationError {
    HostToolOperationError::Composition { detail }
}

pub(super) fn routes<'a>(
    contracts: impl Iterator<Item = &'a CapabilityContract>,
    schemas: &dyn SchemaCatalog,
) -> Result<BTreeMap<(String, String), String>, HostToolOperationError> {
    let mut result = BTreeMap::new();
    for contract in contracts {
        let Some(toolset) = &contract.toolset else {
            continue;
        };
        let schema = schemas.schema(&contract.input_schema_ref)?;
        let ops = odin_registry::toolsets::member_ops(
            contract.id.as_str(),
            contract.op.as_deref(),
            schema.canonical_json(),
        );
        for (group, ops) in std::iter::once((toolset.clone(), ops)).chain(
            contract
                .seat_ops
                .iter()
                .map(|(seat, view)| (format!("{seat}:{}", view.toolset), vec![view.op.clone()])),
        ) {
            for op in ops {
                if op == "help"
                    || [
                        "read", "bash", "edit", "task", "eval", "todo", "recall", "search",
                    ]
                    .contains(&group.as_str())
                {
                    return Err(composition(format!(
                        "reserved toolset operation {group}.{op}"
                    )));
                }
                if result
                    .insert((group.clone(), op.clone()), contract.tool_name.to_string())
                    .is_some()
                {
                    return Err(composition(format!(
                        "duplicate toolset operation {group}.{op}"
                    )));
                }
            }
        }
    }
    Ok(result)
}

pub(super) struct ProjectionIndex {
    contracts: std::sync::Arc<BTreeMap<odin_domain::CapabilityId, CapabilityContract>>,
    tool_index: std::sync::Arc<BTreeMap<String, odin_domain::CapabilityId>>,
    routes: std::sync::Arc<BTreeMap<(String, String), String>>,
}

impl HostToolOperations {
    /// A served publication derives its routing once, never from startup metadata.
    pub(crate) fn projection_view(
        &self,
        binding: &super::SessionOperationBinding,
    ) -> Result<Self, HostToolOperationError> {
        let material = self.generation_material(binding)?;
        let mut memo = self
            .projection_memo
            .lock()
            .map_err(|_| composition("projection memo poisoned".into()))?;
        let index = if let Some(index) = memo.get(&material.revision) {
            index.clone()
        } else {
            let index = std::sync::Arc::new(ProjectionIndex {
                contracts: material.contracts.clone(),
                tool_index: std::sync::Arc::new(material.tool_index.clone()),
                routes: std::sync::Arc::new(routes(
                    material.contracts.values(),
                    self.schemas.as_ref(),
                )?),
            });
            while memo.len() >= super::generation::GENERATION_MEMO_CAP {
                memo.pop_first();
            }
            memo.insert(material.revision, index.clone());
            index
        };
        let mut view = self.clone();
        view.contracts = index.contracts.clone();
        view.tool_index = index.tool_index.clone();
        view.toolset_routes = index.routes.clone();
        Ok(view)
    }

    fn route(&self, tool: &str, op: &str, scope: Option<&Scope>) -> Option<&String> {
        scope
            .and_then(|scope| scope.seat.as_ref())
            .and_then(|seat| {
                self.toolset_routes
                    .get(&(format!("{seat}:{tool}"), op.to_owned()))
            })
            .or_else(|| self.toolset_routes.get(&(tool.to_owned(), op.to_owned())))
    }

    /// The operations of a toolset the session may call.
    fn toolset_ops(
        &self,
        admitted: &BTreeSet<String>,
        tool: &str,
        scope: Option<&Scope>,
    ) -> Vec<String> {
        let seat_group = scope
            .and_then(|scope| scope.seat.as_ref())
            .map(|seat| format!("{seat}:{tool}"));
        let ops: BTreeSet<&String> = self
            .toolset_routes
            .iter()
            .filter(|((group, _), name)| {
                (group == tool || seat_group.as_ref() == Some(group)) && admitted.contains(*name)
            })
            .map(|((_, op), _)| op)
            .collect();
        ops.into_iter().cloned().collect()
    }

    /// A call that names its operation `operation` or `action` means `op`.
    fn spell_op(&self, tool: &str, scope: Option<&Scope>, arguments: &mut Value) {
        let Some(fields) = arguments.as_object_mut() else {
            return;
        };
        if fields
            .get("op")
            .and_then(Value::as_str)
            .is_some_and(|op| !op.is_empty())
        {
            return;
        }
        for key in ["operation", "action"] {
            let spelled = fields.get(key).and_then(Value::as_str).map(str::to_owned);
            if let Some(op) =
                spelled.filter(|op| op == "help" || self.route(tool, op, scope).is_some())
            {
                fields.remove(key);
                fields.insert("op".into(), Value::String(op));
                return;
            }
        }
    }

    /// Resolve once, before reservations, timeouts, normalization, ledger and admission.
    pub fn prepare_tool_call(
        &self,
        admitted: &BTreeSet<String>,
        tool: &str,
        mut arguments: Value,
        scope: Option<&Scope>,
    ) -> Result<PreparedToolCall, HostToolOperationError> {
        self.spell_op(tool, scope, &mut arguments);
        let op = arguments
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let help = op == "help";
        let target = if help {
            arguments
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        } else {
            op.clone()
        };
        let selected = target.as_str();
        if selected.is_empty() {
            let ops = self.toolset_ops(admitted, tool, scope);
            if let Some(first) = ops.first() {
                // No operation named: the toolset's operations are the answer.
                return Ok(PreparedToolCall::Help(json!({
                    "toolset": tool,
                    "ops": ops,
                    "example": {"op":"help","operation":first},
                })));
            }
        }
        let name = self.route(tool, selected, scope);
        let Some(name) = name else {
            // Ungrouped future declarations retain their exact direct surface.
            if admitted.contains(tool)
                && self
                    .capability_of(tool)
                    .and_then(|id| self.contracts.get(id))
                    .is_some_and(|contract| {
                        contract.toolset.is_none()
                            && contract.expose != Some(CapabilityExposureToml::Internal)
                            && !scope
                                .and_then(|scope| scope.seat.as_ref())
                                .is_some_and(|seat| contract.delegate_to.as_ref() == Some(seat))
                    })
            {
                return Ok(PreparedToolCall::Call {
                    name: tool.to_owned(),
                    arguments,
                    ignored: Vec::new(),
                });
            }
            return Err(HostToolOperationError::UnknownTool {
                name: format!("{tool}.{selected}"),
            });
        };
        if !admitted.contains(name) {
            return Err(HostToolOperationError::UnknownTool {
                name: format!("{tool}.{selected}"),
            });
        }
        let contract = &self.contracts[&self.tool_index[name]];
        if contract.expose == Some(CapabilityExposureToml::Internal)
            || scope
                .and_then(|scope| scope.seat.as_ref())
                .is_some_and(|seat| contract.delegate_to.as_ref() == Some(seat))
        {
            return Err(HostToolOperationError::UnknownTool {
                name: format!("{tool}.{selected}"),
            });
        }
        if let Some(override_view) = scope
            .and_then(|scope| scope.seat.as_ref())
            .and_then(|seat| contract.seat_ops.get(seat))
        {
            if override_view.toolset != tool || override_view.op != selected {
                return Err(HostToolOperationError::UnknownTool {
                    name: format!("{tool}.{selected}"),
                });
            }
        }
        let canonical = self.schemas.schema(&contract.input_schema_ref)?;
        let definition = self
            .executor
            .definition(name, true, scope)
            .ok_or_else(|| composition(format!("missing member definition {name}")))?;
        let narrowing = super::catalog::declared_narrowing_schema(name, definition.parameters)?;
        if help {
            let mut exact = canonical.canonical_json().clone();
            let object = exact
                .as_object_mut()
                .ok_or_else(|| composition(format!("member {name} schema must be an object")))?;
            let constraints = object
                .entry("allOf")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or_else(|| composition(format!("member {name} allOf must be an array")))?;
            constraints.push(narrowing.canonical_json().clone());
            if canonical
                .canonical_json()
                .pointer("/properties/op")
                .is_some()
            {
                exact["properties"]["op"]["const"] = json!(selected);
            }
            // The listing keeps each operation's first sentence; help has the rest.
            exact["description"] = json!(match exact.get("description").and_then(Value::as_str) {
                Some(detail) => format!("{} {detail}", contract.description),
                None => contract.description.clone(),
            });
            return Ok(PreparedToolCall::Help(exact));
        }
        let (mut arguments, ignored) = super::loose::payload(
            canonical.canonical_json(),
            contract.effect_class == EffectClass::R0,
            arguments,
        );
        let result = (|| {
            if contract.id.as_str() == crate::host_tools::task_grants::TASK_GRANT_CAPABILITY {
                self.normalize_grant_effects(admitted, &mut arguments, scope)?;
            }
            let arguments = crate::host_tools::schema_compat::drop_null_optionals(
                canonical.canonical_json(),
                arguments,
            );
            let arguments = super::dispatch::normalize_capability_arguments(
                contract,
                narrowing.canonical_json(),
                arguments,
            )?;
            odin_kernel::validate_input_arguments(&canonical, &arguments)?;
            odin_kernel::validate_input_arguments(&narrowing, &arguments)?;
            Ok(arguments)
        })();
        let arguments = result.map_err(|error: HostToolOperationError| {
            let reason = match error {
                HostToolOperationError::Arguments { detail } => detail,
                HostToolOperationError::Authority(OperationRejection::SchemaInvalid { detail }) => {
                    detail
                }
                other => other.to_string(),
            };
            // A validator names the offending value in full; the field is what the model needs.
            let reason: String = reason.chars().take(REASON_CHARS_MAX).collect();
            HostToolOperationError::Arguments {
                detail: format!(
                    "{tool}.{op}: {reason}. Example: {}",
                    super::loose::example(
                        tool,
                        selected,
                        canonical.canonical_json(),
                        contract.expose == Some(CapabilityExposureToml::OnDemand)
                    )
                ),
            }
        })?;
        Ok(PreparedToolCall::Call {
            name: name.clone(),
            arguments,
            ignored,
        })
    }

    pub(super) fn normalize_grant_effects(
        &self,
        admitted: &BTreeSet<String>,
        arguments: &mut Value,
        scope: Option<&Scope>,
    ) -> Result<(), HostToolOperationError> {
        let Some(effects) = arguments.get_mut("effects").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        for effect in effects {
            let Some(tool) = effect
                .get("tool")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            let fields = effect.as_object().unwrap();
            if fields
                .keys()
                .any(|field| !["tool", "op", "arguments"].contains(&field.as_str()))
            {
                return Err(HostToolOperationError::Arguments {
                    detail: "grant effect accepts only tool, op and arguments".into(),
                });
            }
            let op = effect
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "grant effect requires op".into(),
                })?
                .to_owned();
            let route = scope
                .and_then(|scope| scope.seat.as_ref())
                .and_then(|seat| {
                    self.toolset_routes
                        .get(&(format!("{seat}:{tool}"), op.clone()))
                })
                .or_else(|| self.toolset_routes.get(&(tool.clone(), op.clone())))
                .ok_or_else(|| HostToolOperationError::UnknownTool {
                    name: format!("{tool}.{op}"),
                })?;
            // Operator-owned capabilities have routes but no dispatchable tool.
            let target = self
                .tool_index
                .get(route)
                .and_then(|capability| self.contracts.get(capability))
                .ok_or_else(|| HostToolOperationError::UnknownTool {
                    name: format!("{tool}.{op}"),
                })?;
            if target.id.as_str() == crate::host_tools::task_grants::TASK_GRANT_CAPABILITY {
                return Err(HostToolOperationError::Arguments {
                    detail: "a grant cannot grant another grant".into(),
                });
            }
            let mut payload = effect
                .get_mut("arguments")
                .map(Value::take)
                .unwrap_or_else(|| json!({}));
            if target.expose == Some(CapabilityExposureToml::OnDemand) {
                payload = json!({"op":op,"args":payload});
            } else if let Some(fields) = payload.as_object_mut() {
                fields.insert("op".into(), json!(op));
            }
            match self.prepare_tool_call(admitted, &tool, payload, scope)? {
                PreparedToolCall::Call {
                    name, arguments, ..
                } => {
                    *effect = json!({"capability":self.tool_index[&name],"arguments":arguments});
                }
                PreparedToolCall::Help(_) => {
                    return Err(HostToolOperationError::Arguments {
                        detail: "help is not a grant effect".into(),
                    })
                }
            }
        }
        Ok(())
    }

    pub(super) fn project_definitions(
        &self,
        definitions: Vec<RpcHostToolDefinition>,
        scope: Option<&Scope>,
    ) -> Result<Vec<RpcHostToolDefinition>, HostToolOperationError> {
        let mut direct = Vec::new();
        let mut members = Vec::new();
        for definition in definitions {
            let contract = &self.contracts[&self.tool_index[definition.name.as_ref()]];
            if contract.expose == Some(CapabilityExposureToml::Internal)
                || scope
                    .and_then(|scope| scope.seat.as_ref())
                    .is_some_and(|seat| contract.delegate_to.as_ref() == Some(seat))
            {
                continue;
            }
            let view = scope
                .and_then(|scope| scope.seat.as_ref())
                .and_then(|seat| contract.seat_ops.get(seat));
            let group = view
                .map(|view| view.toolset.as_str())
                .or(contract.toolset.as_deref());
            if let Some(group) = group {
                members.push(odin_registry::toolsets::Member {
                    id: contract.id.to_string(),
                    toolset: group.to_owned(),
                    op: view
                        .map(|view| view.op.clone())
                        .or_else(|| contract.op.clone()),
                    description: contract.description.clone(),
                    on_demand: contract.expose == Some(CapabilityExposureToml::OnDemand),
                    definition: serde_json::to_value(definition)
                        .map_err(|error| composition(error.to_string()))?,
                });
            } else {
                direct.push(definition);
            }
        }
        let projected =
            odin_registry::toolsets::project(members, &self.toolsets).map_err(composition)?;
        for value in projected {
            direct.push(RpcHostToolDefinition {
                name: value["name"].as_str().unwrap().to_owned().into(),
                label: value["label"].as_str().unwrap().to_owned().into(),
                description: value["description"].as_str().unwrap().to_owned().into(),
                parameters: value["parameters"].clone(),
                hidden: false,
                load_mode: crate::host_tools::ToolLoadMode::Essential,
            });
        }
        direct.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(direct)
    }
}
