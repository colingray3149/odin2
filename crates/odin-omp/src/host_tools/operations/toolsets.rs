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
                    || odin_registry::toolsets::RESERVED_TOOLSETS.contains(&group.as_str())
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

    /// Whether another operation of the toolset the session may call declares `field`: a strict
    /// lane fills the union of its ops' fields, so a read sheds such a field instead of refusing.
    fn toolset_declares(
        &self,
        admitted: &BTreeSet<String>,
        tool: &str,
        scope: Option<&Scope>,
        field: &str,
    ) -> bool {
        self.toolset_ops(admitted, tool, scope)
            .iter()
            .filter_map(|op| self.route(tool, op, scope))
            .filter_map(|name| self.tool_index.get(name))
            .filter_map(|id| self.contracts.get(id))
            .filter_map(|contract| self.schemas.schema(&contract.input_schema_ref).ok())
            .any(|schema| {
                schema
                    .canonical_json()
                    .pointer("/properties")
                    .and_then(Value::as_object)
                    .is_some_and(|properties| properties.contains_key(field))
            })
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

    /// `ask` with `to: "<seat>"` is that seat's own ask op, so its grant and approval stay per seat.
    fn spell_ask(
        &self,
        admitted: &BTreeSet<String>,
        tool: &str,
        scope: Option<&Scope>,
        arguments: &mut Value,
    ) -> Result<(), HostToolOperationError> {
        let Some(fields) = arguments.as_object_mut() else {
            return Ok(());
        };
        if fields.get("op").and_then(Value::as_str) != Some(odin_registry::toolsets::ASK_OP)
            || self
                .route(tool, odin_registry::toolsets::ASK_OP, scope)
                .is_some()
        {
            return Ok(());
        }
        let seats: Vec<String> = self
            .toolset_ops(admitted, tool, scope)
            .into_iter()
            .filter_map(|op| op.strip_prefix("ask_").map(str::to_owned))
            .collect();
        let to = fields
            .get("to")
            .and_then(Value::as_str)
            .map(|seat| seat.trim().to_ascii_lowercase());
        match to {
            Some(seat) if seats.contains(&seat) => {
                fields.remove("to");
                fields.insert("op".into(), Value::String(format!("ask_{seat}")));
                Ok(())
            }
            _ => Err(HostToolOperationError::Arguments {
                detail: format!(
                    "{tool}.ask needs to: one of {}",
                    listed_ops(&seats).replace(" and ", " or ")
                ),
            }),
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
        if tool == odin_registry::toolsets::MORE_TOOL {
            // `more {tool, op, args}` is that toolset's own call.
            unpack_args(&mut arguments);
            let inner = arguments
                .as_object_mut()
                .and_then(|fields| fields.remove("tool"))
                .and_then(|inner| inner.as_str().map(str::to_owned))
                .filter(|inner| inner != odin_registry::toolsets::MORE_TOOL)
                .ok_or_else(|| HostToolOperationError::Arguments {
                    detail: "more needs tool: one of the toolsets its description lists".into(),
                })?;
            return self.prepare_tool_call(admitted, &inner, arguments, scope);
        }
        self.spell_op(tool, scope, &mut arguments);
        unpack_args(&mut arguments);
        self.spell_ask(admitted, tool, scope, &mut arguments)?;
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
            let ops = self.toolset_ops(admitted, tool, scope);
            if !ops.is_empty() {
                return Err(HostToolOperationError::Arguments {
                    detail: format!(
                        "{tool} has no op {selected:?}; its ops are {}. Each op's fields are in the {tool} description.",
                        listed_ops(&ops)
                    ),
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
        let read_only = contract.effect_class == EffectClass::R0;
        let (mut arguments, ignored) = super::loose::payload(
            canonical.canonical_json(),
            |field| read_only && self.toolset_declares(admitted, tool, scope, field),
            arguments,
        );
        let result = (|| {
            super::loose::unknown(canonical.canonical_json(), &arguments)
                .map_err(|detail| HostToolOperationError::Arguments { detail })?;
            if contract.id.as_str() == crate::host_tools::task_grants::TASK_GRANT_CAPABILITY {
                self.normalize_grant_effects(admitted, &mut arguments, scope)?;
            }
            let arguments = crate::host_tools::schema_compat::drop_null_optionals(
                canonical.canonical_json(),
                arguments,
            );
            let arguments = all_for_missing_choices(
                canonical.canonical_json(),
                narrowing.canonical_json(),
                arguments,
            );
            let arguments = super::dispatch::normalize_capability_arguments(
                contract,
                scope,
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
            let shown = match &contract.delegate_to {
                Some(_) => odin_registry::toolsets::ASK_OP,
                None => selected,
            };
            let mut example = super::loose::example(
                tool,
                shown,
                &super::loose::narrowed(canonical.canonical_json(), narrowing.canonical_json()),
            );
            if let Some(seat) = &contract.delegate_to {
                example = example.replacen("{", &format!("{{\"to\":\"{seat}\","), 1);
            }
            HostToolOperationError::Arguments {
                detail: format!("{tool}.{shown}: {reason}. A good call: {example}"),
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
                    on_demand: view.and_then(|view| view.expose).or(contract.expose)
                        == Some(CapabilityExposureToml::OnDemand),
                    delegate_to: contract.delegate_to.as_ref().map(|seat| seat.to_string()),
                    definition: serde_json::to_value(definition)
                        .map_err(|error| composition(error.to_string()))?,
                });
            } else {
                direct.push(definition);
            }
        }
        let deferred = scope
            .and_then(|scope| scope.seat.as_ref())
            .and_then(|seat| self.deferred.get(seat.as_str()))
            .cloned()
            .unwrap_or_default();
        let projected = odin_registry::toolsets::project(members, &self.toolsets, &deferred)
            .map_err(composition)?;
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

/// The fields a model put in `args`, object or JSON text, beside the envelope: one bag either way.
fn unpack_args(arguments: &mut Value) {
    let Some(fields) = arguments.as_object_mut() else {
        return;
    };
    let wrapped = match fields.get("args") {
        Some(Value::Object(wrapped)) => wrapped.clone(),
        Some(Value::String(text)) => match serde_json::from_str(text) {
            Ok(Value::Object(wrapped)) => wrapped,
            // Not an object: left for the validator to name.
            _ => return,
        },
        Some(Value::Null) => serde_json::Map::new(),
        _ => return,
    };
    fields.remove("args");
    for (field, value) in wrapped {
        // A strict lane sends every listed field, null where it has nothing to say.
        if fields.get(&field).is_none_or(Value::is_null) {
            fields.insert(field, value);
        }
    }
}

/// `a, b and c`, for an error naming a toolset's ops.
fn listed_ops(ops: &[String]) -> String {
    match ops {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A required field whose declared values are resolved at the seam (an account) and that the call
/// left out means "all": a field with one value takes it, and a reading call reads every one.
fn all_for_missing_choices(schema: &Value, narrowing: &Value, mut arguments: Value) -> Value {
    let Some(fields) = arguments.as_object_mut() else {
        return arguments;
    };
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for field in required {
        let Some(property) = narrowing.pointer(&format!("/properties/{field}")) else {
            continue;
        };
        let values = property
            .get("enum")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        // Several accounts with no "all" among them is the owner's choice: the error names them.
        let open = values.len() == 1 || values.contains(&Value::String("all".into()));
        if property.get(odin_registry::listing::RESOLVED_IDS) == Some(&Value::Bool(true))
            && open
            && fields.get(field).is_none_or(Value::is_null)
        {
            fields.insert(field.to_owned(), Value::String("all".into()));
        }
    }
    arguments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_left_out_account_means_all_only_where_there_is_nothing_to_choose() {
        let schema = json!({"required": ["account"]});
        let narrowing = |values: Value| json!({"properties": {"account": {"enum": values, "x-odin-resolve-ids": true}}});
        let one = all_for_missing_choices(&schema, &narrowing(json!(["gmail"])), json!({}));
        assert_eq!(one["account"], "all");
        let reading =
            all_for_missing_choices(&schema, &narrowing(json!(["a", "b", "all"])), json!({}));
        assert_eq!(reading["account"], "all");
        let choice = all_for_missing_choices(&schema, &narrowing(json!(["a", "b"])), json!({}));
        assert!(choice.get("account").is_none());
        let named = all_for_missing_choices(
            &schema,
            &narrowing(json!(["gmail"])),
            json!({"account": "x"}),
        );
        assert_eq!(named["account"], "x");
    }
}
