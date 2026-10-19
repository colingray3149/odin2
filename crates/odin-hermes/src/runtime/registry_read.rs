//! Reads the daemon's pinned registry: no arguments lists kinds, `kind` lists
//! objects with relational fields, and `kind` + `id` returns the full declaration.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_registry::{RegistryKind, SnapshotHandle};
use serde_json::{json, Map, Value};

use super::tools::{object_schema, CapabilityTool};
use super::HermesRuntime;

const TOOL: &str = "registry_read";

/// Declaration fields that relate an object to others or state what it is
/// for: a listing carries exactly these, whatever the kind.
const LISTED_FIELDS: &[&str] = &[
    "enabled",
    "categories",
    "project_scope",
    "read_project_scope",
    "models",
    "seat",
    "project",
    "lane",
    "default_seat",
    "seats_offered",
    "purpose",
    "host",
    "effect_class",
    "delegate_to",
    "allow_hosts",
    "gpu_count",
    "placement",
    "mode",
    "harness",
    "environment",
];

const DESCRIPTION_CHARS: usize = 200;

fn kind_named(name: &str) -> Option<RegistryKind> {
    RegistryKind::ALL
        .into_iter()
        .find(|kind| kind.as_str() == name)
}

/// The listing entry of one declaration: id, a bounded description, and the
/// relational fields it declares.
fn listed(id: &str, declaration: &Map<String, Value>) -> Value {
    let mut entry = Map::new();
    entry.insert("id".to_owned(), json!(id));
    if let Some(description) = declaration.get("description").and_then(Value::as_str) {
        let bounded: String = description.chars().take(DESCRIPTION_CHARS).collect();
        entry.insert("description".to_owned(), json!(bounded));
    }
    for field in LISTED_FIELDS {
        if let Some(value) = declaration.get(*field) {
            if !value.is_null() {
                entry.insert((*field).to_owned(), value.clone());
            }
        }
    }
    Value::Object(entry)
}

pub fn read(pin: &SnapshotHandle, kind: Option<&str>, id: Option<&str>) -> Result<Value, String> {
    let snapshot = pin.current();
    let Some(kind_name) = kind else {
        if id.is_some() {
            return Err("an id needs its kind".to_owned());
        }
        let counts: Map<String, Value> = RegistryKind::ALL
            .into_iter()
            .map(|kind| {
                let count = snapshot
                    .objects
                    .iter()
                    .filter(|object| object.kind() == kind)
                    .count();
                (kind.as_str().to_owned(), json!(count))
            })
            .collect();
        return Ok(json!({ "revision": snapshot.revision, "kinds": counts }));
    };
    let kind = kind_named(kind_name).ok_or_else(|| {
        let known: Vec<&str> = RegistryKind::ALL.iter().map(|kind| kind.as_str()).collect();
        format!("there is no registry kind {kind_name:?}; the kinds are {known:?}")
    })?;
    let declarations = snapshot
        .objects
        .iter()
        .filter(|object| object.kind() == kind)
        .map(|object| {
            let mut value = serde_json::to_value(&object.config).map_err(|error| {
                format!("the {kind_name} {} does not serialize: {error}", object.id)
            })?;
            let declaration = match value.get_mut("config").map(Value::take) {
                Some(Value::Object(declaration)) => declaration,
                _ => {
                    return Err(format!(
                        "the {kind_name} {} has no declaration body",
                        object.id
                    ))
                }
            };
            Ok((object.id.as_str(), declaration))
        })
        .collect::<Result<Vec<_>, String>>()?;
    match id {
        Some(id) => declarations
            .into_iter()
            .find(|(candidate, _)| *candidate == id)
            .map(|(id, declaration)| {
                json!({
                    "revision": snapshot.revision,
                    "kind": kind_name,
                    "id": id,
                    "declaration": declaration,
                })
            })
            .ok_or_else(|| format!("the published registry has no {kind_name} {id:?}")),
        None => Ok(json!({
            "revision": snapshot.revision,
            "kind": kind_name,
            "objects": declarations
                .iter()
                .map(|(id, declaration)| listed(id, declaration))
                .collect::<Vec<_>>(),
        })),
    }
}

/// Adds each routine's runtime status (when it last fired, a source it
/// cannot read) beside its declaration or listing entry.
fn with_routine_status(runtime: &HermesRuntime, read: &mut Value) -> Result<(), String> {
    let entries: Vec<&mut Map<String, Value>> = match read {
        Value::Object(single) if single.contains_key("declaration") => vec![single],
        Value::Object(listing) => match listing.get_mut("objects") {
            Some(Value::Array(objects)) => objects
                .iter_mut()
                .filter_map(Value::as_object_mut)
                .collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    if entries.is_empty() {
        return Ok(());
    }
    let status = runtime.routine_statuses()?;
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        entry.extend(status(&id));
    }
    Ok(())
}

pub(super) fn registry_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let handler = move |_scope: Scope, arguments: Value| {
        let text = |field: &str| -> Result<Option<String>, HostToolError> {
            match arguments.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(value)) if !value.is_empty() && value.len() <= 128 => {
                    Ok(Some(value.clone()))
                }
                Some(_) => Err(HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("{field} must be a non-empty string of at most 128 bytes"),
                }),
            }
        };
        let (kind, id) = (text("kind")?, text("id")?);
        let pin = runtime
            .registry_pin()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: TOOL,
                reason: "the published registry is not bound on this host".to_owned(),
            })?;
        let mut read = read(&pin, kind.as_deref(), id.as_deref())
            .map_err(|reason| HostToolError::Unavailable { tool: TOOL, reason })?;
        if kind.as_deref() == Some(RegistryKind::Routine.as_str()) {
            with_routine_status(&runtime, &mut read)
                .map_err(|reason| HostToolError::Unavailable { tool: TOOL, reason })?;
        }
        Ok(read)
    };
    let kinds: Vec<&str> = RegistryKind::ALL.iter().map(|kind| kind.as_str()).collect();
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Read the registry".into(),
            description: "Reads the published registry. No arguments: counts per kind. \
                          kind: objects and their relations. kind + id: the full declaration, \
                          including a seat's projects and tool access. Routines also show their last \
                          firing and unreadable sources."
                .into(),
            parameters: object_schema(
                TOOL,
                json!({
                    "kind": { "type": "string", "enum": kinds },
                    "id": { "type": "string", "minLength": 1, "maxLength": 128 },
                }),
                &[],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}
