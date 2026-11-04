//! Fixed, lean toolset definitions shared by registry admission and host listing.
use crate::schema::ToolsetToml;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_LISTING_BYTES: usize = 35_000;
const TOOLSET_EXAMPLES_MIN: usize = 2;
const TOOLSET_EXAMPLES_MAX: usize = 5;
const TOOLSET_DESCRIPTION_MAX_CHARS: usize = 110;
/// Names the host's own tools use; a toolset cannot take them.
pub const RESERVED_TOOLSETS: [&str; 8] = [
    "read", "bash", "edit", "task", "eval", "todo", "recall", "search",
];
/// How many `$ref` hops a field type follows before the reference is called a cycle.
const REF_DEPTH_MAX: usize = 16;

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn valid_toolset_name(name: &str) -> bool {
    is_name(name) && !RESERVED_TOOLSETS.contains(&name)
}

/// The model-facing tool name of a capability id.
pub fn tool_name(id: &str) -> String {
    id.replace(['.', ':'], "_")
}

pub(crate) fn undeclared_toolset(group: &str) -> String {
    format!("toolset {group} is not declared; add registry/toolsets/{group}/toolset.toml")
}

pub struct Member {
    pub id: String,
    pub toolset: String,
    pub op: Option<String>,
    pub description: String,
    pub on_demand: bool,
    pub definition: Value,
}

pub fn member_ops(id: &str, op: Option<&str>, schema: &Value) -> Vec<String> {
    if op.is_none() && schema.pointer("/properties/op/x-op-descriptions").is_some() {
        if let Some(values) = schema
            .pointer("/properties/op/enum")
            .and_then(Value::as_array)
        {
            return values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
        }
    }
    vec![op
        .unwrap_or_else(|| id.rsplit('.').next().unwrap())
        .to_owned()]
}

/// The op a declared example calls: the first whole `op:` key (`stop:` is not one), its value
/// `"?([a-z0-9_]+)`.
pub(crate) fn example_op(example: &str) -> Option<&str> {
    example.match_indices("op:").find_map(|(start, _)| {
        let whole_key = example[..start]
            .chars()
            .next_back()
            .is_none_or(|before| before == '{' || before == ',' || before.is_whitespace());
        if !whole_key {
            return None;
        }
        let rest = example[start + 3..].trim_start();
        let rest = rest.strip_prefix('"').unwrap_or(rest);
        let end = rest
            .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(rest.len());
        (end > 0).then(|| &rest[..end])
    })
}

/// The declared examples whose op the seat holds, else the generated help call.
fn examples_line(
    group: &str,
    ops: &BTreeSet<String>,
    declared: Option<&ToolsetToml>,
    fallback: Value,
) -> String {
    let held: Vec<&str> = declared
        .map(|toolset| toolset.examples.as_slice())
        .unwrap_or_default()
        .iter()
        .filter(|example| example_op(example).is_some_and(|op| ops.contains(op)))
        .map(String::as_str)
        .collect();
    if held.is_empty() {
        format!("Example: {group} {fallback}")
    } else {
        format!("Examples: {}", held.join("; "))
    }
}

/// Every declared toolset by name, as listing projection reads them.
pub fn declared_toolsets(
    objects: &[crate::schema::RegistryObject],
) -> BTreeMap<String, ToolsetToml> {
    objects
        .iter()
        .filter_map(|object| match &object.config {
            crate::schema::ObjectConfig::Toolset(toolset) => {
                Some((object.id.clone(), toolset.as_ref().clone()))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn first_sentence(text: &str) -> &str {
    text.split_inclusive(['.', '!', '?'])
        .next()
        .unwrap_or(text)
        .trim()
}

fn read_schema(root: &std::path::Path, reference: &str) -> Result<Value, String> {
    let relative = std::path::Path::new(reference);
    if relative
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!("invalid schema path {reference:?}"));
    }
    let cause = |error: &dyn std::fmt::Display| format!("schema {reference}: {error}");
    let schema_root = std::fs::canonicalize(root.join("schemas")).map_err(|error| cause(&error))?;
    let path = std::fs::canonicalize(root.join(relative)).map_err(|error| cause(&error))?;
    if !path.starts_with(schema_root) {
        return Err(format!("schema escapes schema root: {reference}"));
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|error| cause(&error))?)
        .map_err(|error| cause(&error))
}

fn cached_schema<'a>(
    cache: &'a mut BTreeMap<String, Value>,
    root: &std::path::Path,
    reference: &str,
) -> Result<&'a Value, String> {
    if !cache.contains_key(reference) {
        cache.insert(reference.to_owned(), read_schema(root, reference)?);
    }
    Ok(&cache[reference])
}

fn field_type(value: &Value, schema: &Value, depth: usize) -> Result<Value, String> {
    if depth > REF_DEPTH_MAX {
        return Err("schema references loop".into());
    }
    if let Some(kind) = value.get("type") {
        return Ok(kind.clone());
    }
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let target = reference
            .strip_prefix('#')
            .and_then(|pointer| schema.pointer(pointer))
            .ok_or_else(|| format!("unresolved local schema reference {reference}"))?;
        return field_type(target, schema, depth + 1);
    }
    if value.get("properties").is_some() {
        return Ok(json!("object"));
    }
    if let Some(values) = value.get("enum").and_then(Value::as_array) {
        let mut kinds = BTreeSet::new();
        for value in values {
            kinds.insert(match value {
                Value::String(_) => "string",
                Value::Number(_) => "number",
                Value::Bool(_) => "boolean",
                Value::Null => "null",
                _ => return Err("non-scalar enum".into()),
            });
        }
        return Ok(if kinds.len() == 1 {
            json!(kinds.first().unwrap())
        } else {
            json!(kinds)
        });
    }
    if let Some(variants) = value
        .get("anyOf")
        .or_else(|| value.get("oneOf"))
        .and_then(Value::as_array)
    {
        let mut kinds = BTreeSet::new();
        for variant in variants {
            let kind = field_type(variant, schema, depth + 1)?;
            if let Some(kind) = kind.as_str() {
                kinds.insert(kind.to_owned());
            } else if let Some(values) = kind.as_array() {
                kinds.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
        return Ok(json!(kinds));
    }
    Err("field has no resolvable type".into())
}

/// Exact constraints remain in the member schema. Only the union's field vocabulary is shown.
pub fn project(
    mut members: Vec<Member>,
    toolsets: &BTreeMap<String, ToolsetToml>,
) -> Result<Vec<Value>, String> {
    // The listing is the same bytes however the caller ordered the members: by toolset, then id.
    members.sort_by(|a, b| (&a.toolset, &a.id).cmp(&(&b.toolset, &b.id)));
    let mut groups: BTreeMap<String, Vec<Member>> = BTreeMap::new();
    for member in members {
        groups
            .entry(member.toolset.clone())
            .or_default()
            .push(member);
    }
    let mut result = Vec::new();
    for (group, members) in groups {
        if !valid_toolset_name(&group) {
            return Err(format!("invalid or reserved toolset name {group}"));
        }
        let mut properties: Map<String, Value> = Map::new();
        let mut field_ops: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut field_values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut ops = BTreeSet::from(["help".to_owned()]);
        let mut lines = Vec::new();
        let mut example = None;
        let mut on_demand = false;
        let mut template = members[0].definition.clone();
        for member in members {
            let schema = &member.definition["parameters"];
            let member_ops = member_ops(&member.id, member.op.as_deref(), schema);
            for op in &member_ops {
                if !ops.insert(op.clone()) {
                    return Err(format!("duplicate toolset operation {group}.{op}"));
                }
                let description = schema
                    .pointer("/properties/op/x-op-descriptions")
                    .and_then(|descriptions| descriptions.get(op))
                    .and_then(Value::as_str)
                    .unwrap_or(&member.description);
                lines.push(format!("{op}: {}", first_sentence(description)));
                if example.is_none() {
                    example = Some(json!({"op":"help","operation":op}));
                }
            }
            if member.on_demand {
                on_demand = true;
                continue;
            }
            if let Some(fields) = schema.get("properties").and_then(Value::as_object) {
                for (field, original) in fields {
                    if field == "op" || original.get("readOnly") == Some(&json!(true)) {
                        continue;
                    }
                    let kind = field_type(original, schema, 0)
                        .map_err(|error| format!("{group}.{field}: {error}"))?;
                    let mut shown = json!({"type":kind});
                    if original.get(crate::listing::RESOLVED_IDS) == Some(&json!(true)) {
                        if let Some(values) = original.get("enum").and_then(Value::as_array) {
                            field_values
                                .entry(field.clone())
                                .or_default()
                                .extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
                        }
                    } else if let Some(values) = original.get("enum") {
                        shown["enum"] = values.clone();
                    }
                    if let Some(existing) = properties.get_mut(field) {
                        if existing["type"] != shown["type"] {
                            return Err(format!(
                                "toolset {group} field {field}: conflicting types {} and {}",
                                existing["type"], shown["type"]
                            ));
                        }
                        match (existing.get("enum").cloned(), shown.get("enum")) {
                            (Some(Value::Array(mut left)), Some(Value::Array(right))) => {
                                for value in right {
                                    if !left.contains(value) {
                                        left.push(value.clone());
                                    }
                                }
                                existing["enum"] = json!(left);
                            }
                            _ => {
                                existing.as_object_mut().unwrap().remove("enum");
                            }
                        }
                    } else {
                        properties.insert(field.clone(), shown);
                    }
                    field_ops
                        .entry(field.clone())
                        .or_default()
                        .extend(member_ops.iter().cloned());
                }
            }
        }
        for (field, users) in field_ops {
            let value = properties.get_mut(&field).unwrap();
            if value.get("enum").is_some() && users.len() > 1 {
                value["description"] = json!(users.join(","));
            }
        }
        for (field, values) in field_values {
            let value = properties.get_mut(&field).unwrap();
            value["description"] = json!(format!(
                "Values: {}",
                values.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        properties.insert("op".into(), json!({"type":"string","enum":ops}));
        properties.insert(
            "operation".into(),
            json!({"type":"string","description":"help target"}),
        );
        if on_demand {
            // A string too: a strict-schema provider can only send an empty object for a property
            // that declares no fields, so on those models the arguments travel as JSON text.
            properties.insert("args".into(), json!({"anyOf":[{"type":"string"},{"type":"object"}],"description":"On-demand arguments: an object or its JSON text; help returns exact fields."}));
        }
        let example = example.ok_or_else(|| format!("toolset {group} lists no operations"))?;
        lines.push(examples_line(&group, &ops, toolsets.get(&group), example));
        template["name"] = json!(group);
        template["label"] = template["name"].clone();
        template["description"] = json!(lines.join("\n"));
        template["parameters"] = json!({"type":"object","properties":properties,"required":["op"],"additionalProperties":false});
        result.push(template);
    }
    Ok(result)
}

/// The seat's listing as its model is sent it: the exact enabled grant set (toolset macros
/// already expanded) through the same adaptation the bridge applies, so
/// [`crate::listing::listing_bytes`] of it is the number the daemon holds to
/// [`DEFAULT_LISTING_BYTES`].
pub fn seat_listing(
    objects: &[crate::schema::RegistryObject],
    seat_id: &str,
    root: &std::path::Path,
) -> Result<Vec<Value>, String> {
    seat_definitions(objects, seat_id, root, &mut BTreeMap::new())
        .map(crate::listing::model_listing)
}

/// One capability a seat holds as listed: internal and self-delegated grants are left out.
pub(crate) struct Grant<'a> {
    pub(crate) id: &'a str,
    pub(crate) capability: &'a crate::schema::CapabilityToml,
    pub(crate) view: Option<&'a crate::schema::CapabilitySeatOpToml>,
}

impl<'a> Grant<'a> {
    pub(crate) fn group(&self) -> Option<&'a str> {
        self.view
            .map(|view| view.toolset.as_str())
            .or(self.capability.toolset.as_deref())
    }
}

pub(crate) fn seat_grants<'a>(
    objects: &'a [crate::schema::RegistryObject],
    seat_id: &str,
) -> Result<Vec<Grant<'a>>, String> {
    use crate::schema::{CapabilityExposureToml, ObjectConfig};
    let seat = objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Seat(seat) if object.id == seat_id => Some(seat),
            _ => None,
        })
        .ok_or_else(|| format!("unknown seat {seat_id}"))?;
    let capabilities: BTreeMap<_, _> = objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Capability(capability) => Some((object.id.as_str(), capability.as_ref())),
            _ => None,
        })
        .collect();
    let mut grants = Vec::new();
    for id in &seat.tool_refs {
        let (&id, &capability) = capabilities
            .get_key_value(id.as_str())
            .ok_or_else(|| format!("seat {seat_id}: missing capability {id}"))?;
        if !capability.enabled {
            return Err(format!("seat {seat_id}: capability {id} is disabled"));
        }
        if capability.expose == Some(CapabilityExposureToml::Internal)
            || capability
                .delegate_to
                .as_ref()
                .is_some_and(|seat| seat.as_str() == seat_id)
        {
            continue;
        }
        let view = capability
            .seat_ops
            .iter()
            .find(|(seat, _)| seat.as_str() == seat_id)
            .map(|(_, view)| view);
        grants.push(Grant {
            id,
            capability,
            view,
        });
    }
    Ok(grants)
}

/// The seat's category index: one line per toolset it holds, in the order of its
/// first grant of each, then its direct tools.
pub fn seat_index(
    objects: &[crate::schema::RegistryObject],
    seat_id: &str,
) -> Result<String, String> {
    let toolsets = declared_toolsets(objects);
    let mut groups = Vec::new();
    let mut direct = Vec::new();
    for grant in seat_grants(objects, seat_id)? {
        match grant.group() {
            Some(group) if !groups.contains(&group) => groups.push(group),
            Some(_) => {}
            None => direct.push(format!(
                "- {}: {}",
                tool_name(grant.id),
                first_sentence(&grant.capability.description)
            )),
        }
    }
    let mut lines = Vec::new();
    for group in groups {
        let toolset = toolsets
            .get(group)
            .ok_or_else(|| undeclared_toolset(group))?;
        lines.push(format!("- {group}: {}", toolset.description));
    }
    lines.extend(direct);
    Ok(lines.join("\n"))
}

fn seat_definitions(
    objects: &[crate::schema::RegistryObject],
    seat_id: &str,
    root: &std::path::Path,
    schemas: &mut BTreeMap<String, Value>,
) -> Result<Vec<Value>, String> {
    use crate::schema::CapabilityExposureToml;
    let mut members = Vec::new();
    let mut direct = Vec::new();
    for grant in seat_grants(objects, seat_id)? {
        let (id, capability, view) = (grant.id, grant.capability, grant.view);
        let reference = capability
            .input_schema
            .as_deref()
            .ok_or_else(|| format!("capability {id} has no input schema"))?;
        let schema = cached_schema(schemas, root, reference)?;
        let name = tool_name(id);
        // The bridge lists a paired schema the way the model is shown it.
        let mut parameters = schema.clone();
        crate::listing::action_surface(&mut parameters);
        let definition = json!({"name":name,"label":name,"description":capability.description,"parameters":parameters,"hidden":false,"loadMode":"essential"});
        if let Some(group) = grant.group() {
            members.push(Member {
                id: id.to_owned(),
                toolset: group.to_owned(),
                op: view
                    .map(|view| view.op.clone())
                    .or_else(|| capability.op.clone()),
                description: capability.description.clone(),
                on_demand: capability.expose == Some(CapabilityExposureToml::OnDemand),
                definition,
            });
        } else {
            direct.push(definition);
        }
    }
    direct.extend(project(members, &declared_toolsets(objects))?);
    direct.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(direct)
}

fn validate_metadata(
    objects: &[crate::schema::RegistryObject],
    root: &std::path::Path,
    schemas: &mut BTreeMap<String, Value>,
) -> Vec<crate::RegistryFinding> {
    use crate::schema::ObjectConfig;
    let mut findings = Vec::new();
    // Presentation follows enabled seats only: a seat_ops entry naming an
    // absent or disabled seat presents nothing and invalidates nothing —
    // inert, never a registry failure.
    let seats: BTreeSet<_> = objects
        .iter()
        .filter(|object| matches!(&object.config, ObjectConfig::Seat(seat) if seat.enabled))
        .map(|object| object.id.as_str())
        .collect();
    let toolsets = declared_toolsets(objects);
    let mut held: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut routes = BTreeMap::new();
    for object in objects {
        let ObjectConfig::Capability(capability) = &object.config else {
            continue;
        };
        if !capability.enabled {
            continue;
        }
        let schema = capability
            .input_schema
            .as_ref()
            .and_then(|reference| cached_schema(schemas, root, reference).ok())
            .unwrap_or(&Value::Null);
        if capability.toolset.is_none()
            && (capability.op.is_some()
                || !capability.seat_ops.is_empty()
                || capability.expose == Some(crate::schema::CapabilityExposureToml::OnDemand))
        {
            findings.push(crate::RegistryFinding::fail(
                "toolset-projection",
                &object.relative_config,
                "op, seat_ops and on_demand require a toolset",
            ));
        }
        let default_ops = member_ops(&object.id, capability.op.as_deref(), schema);
        let mut views = Vec::new();
        if let Some(group) = &capability.toolset {
            views.push((None, group.as_str(), default_ops.clone()));
        }
        for seat in &seats {
            if let Some(view) = capability
                .seat_ops
                .iter()
                .find(|(id, _)| id.as_str() == *seat)
                .map(|(_, view)| view)
            {
                views.push((Some(*seat), view.toolset.as_str(), vec![view.op.clone()]));
            } else if let Some(group) = &capability.toolset {
                views.push((Some(*seat), group.as_str(), default_ops.clone()));
            }
        }
        for group in views
            .iter()
            .map(|(_, group, _)| *group)
            .collect::<BTreeSet<_>>()
        {
            let cause = match toolsets.get(group) {
                Some(toolset) if toolset.enabled => continue,
                Some(_) => format!(
                    "toolset {group} is disabled; enable registry/toolsets/{group}/toolset.toml"
                ),
                None => undeclared_toolset(group),
            };
            findings.push(crate::RegistryFinding::fail(
                "toolset-declaration",
                &object.relative_config,
                cause,
            ));
        }
        for (seat, group, ops) in views {
            held.entry(group).or_default().extend(ops.iter().cloned());
            if !valid_toolset_name(group) {
                findings.push(crate::RegistryFinding::fail(
                    "toolset-projection",
                    &object.relative_config,
                    format!("invalid or reserved toolset {group:?}"),
                ));
            }
            for op in ops {
                if op == "help" || !is_name(&op) {
                    findings.push(crate::RegistryFinding::fail(
                        "toolset-projection",
                        &object.relative_config,
                        format!("invalid or reserved operation {group}.{op}"),
                    ));
                }
                if let Some(previous) = routes.insert((seat, group, op.clone()), object.id.as_str())
                {
                    findings.push(crate::RegistryFinding::fail(
                        "toolset-projection",
                        &object.relative_config,
                        format!(
                            "duplicate operation {group}.{op}: {previous} and {}",
                            object.id
                        ),
                    ));
                }
            }
        }
    }
    for object in objects {
        let ObjectConfig::Toolset(toolset) = &object.config else {
            continue;
        };
        if !toolset.enabled {
            continue;
        }
        let group = object.id.as_str();
        let mut fail = |message: String| {
            findings.push(crate::RegistryFinding::fail(
                "toolset-declaration",
                &object.relative_config,
                message,
            ))
        };
        let Some(ops) = held.get(group) else {
            fail(format!("toolset {group} has no enabled capability"));
            continue;
        };
        if !(TOOLSET_EXAMPLES_MIN..=TOOLSET_EXAMPLES_MAX).contains(&toolset.examples.len()) {
            fail(format!(
                "toolset {group} declares {} examples; it takes {TOOLSET_EXAMPLES_MIN} to {TOOLSET_EXAMPLES_MAX}",
                toolset.examples.len()
            ));
        }
        let length = toolset.description.chars().count();
        if length > TOOLSET_DESCRIPTION_MAX_CHARS {
            fail(format!(
                "toolset {group} description is {length} chars, over {TOOLSET_DESCRIPTION_MAX_CHARS}"
            ));
        }
        for example in &toolset.examples {
            match example_op(example) {
                Some(op) if ops.contains(op) => {}
                Some(op) => fail(format!(
                    "toolset {group} example {example:?} calls op {op}, which no {group} capability provides"
                )),
                None => fail(format!("toolset {group} example {example:?} names no op")),
            }
        }
    }
    findings
}

/// `documents` are candidate schemas not yet on disk, read before the tree is.
pub(crate) fn validate(
    objects: &[crate::schema::RegistryObject],
    root: &std::path::Path,
    documents: &BTreeMap<std::path::PathBuf, Vec<u8>>,
) -> Vec<crate::RegistryFinding> {
    use crate::schema::ObjectConfig;
    let mut schemas: BTreeMap<String, Value> = documents
        .iter()
        .filter_map(|(path, bytes)| {
            Some((
                path.to_str()?.to_owned(),
                serde_json::from_slice(bytes).ok()?,
            ))
        })
        .collect();
    let mut findings = validate_metadata(objects, root, &mut schemas);
    // Structural fixtures without a schema tree are already checked by schema-catalog validation.
    if !root.join(crate::schema::CAPABILITY_SCHEMA_DIR).is_dir() {
        return findings;
    }
    for object in objects {
        let ObjectConfig::Seat(seat) = &object.config else {
            continue;
        };
        if !seat.enabled {
            continue;
        }
        let budget = seat
            .tools
            .as_ref()
            .and_then(|tools| tools.listing_bytes)
            .map_or(DEFAULT_LISTING_BYTES, |bytes| bytes.get() as usize);
        if budget > DEFAULT_LISTING_BYTES {
            findings.push(crate::RegistryFinding::fail(
                "tool-listing",
                &object.relative_config,
                format!("listing budget {budget} exceeds hard maximum {DEFAULT_LISTING_BYTES}"),
            ));
            continue;
        }
        let measured =
            seat_definitions(objects, &object.id, root, &mut schemas).map(|definitions| {
                crate::listing::listing_bytes(&crate::listing::model_listing(definitions))
            });
        let detail = match measured {
            Ok(bytes) if bytes + crate::listing::DEPLOYMENT_HEADROOM_BYTES <= budget => continue,
            Ok(bytes) => format!(
                "seat {} listing is {bytes} bytes as the model is sent it, plus {} the daemon adds for deployment values, exceeding declared budget {budget}",
                object.id,
                crate::listing::DEPLOYMENT_HEADROOM_BYTES
            ),
            Err(error) => format!("seat {} listing: {error}", object.id),
        };
        findings.push(crate::RegistryFinding::fail(
            "tool-listing",
            &object.relative_config,
            detail,
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ObjectConfig, RegistryObject};
    use std::path::{Path, PathBuf};

    /// Projection without declared toolsets: the generated example line.
    fn project(members: Vec<Member>) -> Result<Vec<Value>, String> {
        super::project(members, &BTreeMap::new())
    }
    fn member(id: &str, op: &str, schema: Value, on_demand: bool) -> Member {
        Member {
            id: id.into(),
            toolset: "sample".into(),
            op: Some(op.into()),
            description: "Does the declared work. More details remain private.".into(),
            on_demand,
            definition: json!({"name":id,"parameters":schema}),
        }
    }

    #[test]
    fn help_and_union_keep_only_declared_types_descriptions_and_merged_enums() {
        let listing=project(vec![member("one","read",json!({"properties":{"limit":{"type":"integer","minimum":1,"maximum":10},"kind":{"type":"string","enum":["a"]}}}),false),member("two","list",json!({"properties":{"limit":{"type":"integer","minimum":20,"maximum":30},"kind":{"type":"string","enum":["b"]}}}),false)]).unwrap();
        let fields = &listing[0]["parameters"]["properties"];
        assert!(fields["op"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("help")));
        assert!(fields["limit"].get("minimum").is_none());
        assert_eq!(fields["kind"]["enum"], json!(["a", "b"]));
        assert!(fields["kind"]["description"]
            .as_str()
            .unwrap()
            .contains("read,list"));
    }

    #[test]
    fn on_demand_members_contribute_only_args_and_ops() {
        let listing = project(vec![member(
            "one",
            "scene",
            json!({"properties":{"steps":{"type":"array"}}}),
            true,
        )])
        .unwrap();
        let fields = &listing[0]["parameters"]["properties"];
        assert_eq!(
            fields["args"]["anyOf"],
            json!([{"type":"string"},{"type":"object"}])
        );
        assert!(fields.get("steps").is_none());
        assert_eq!(fields["op"]["enum"], json!(["help", "scene"]));
    }

    #[test]
    fn references_and_unions_resolve_to_declared_types_and_a_loop_is_an_error() {
        let schema = json!({
            "properties": {
                "step": {"$ref": "#/$defs/step"},
                "either": {"oneOf": [{"type": "string"}, {"type": "integer"}]},
            },
            "$defs": {"step": {"type": "object"}}
        });
        let listing = project(vec![member("one", "read", schema, false)]).unwrap();
        let fields = &listing[0]["parameters"]["properties"];
        assert_eq!(fields["step"]["type"], "object");
        assert_eq!(fields["either"]["type"], json!(["integer", "string"]));

        let looped = json!({
            "properties": {"a": {"$ref": "#/$defs/a"}},
            "$defs": {"a": {"$ref": "#/$defs/a"}}
        });
        let error = project(vec![member("one", "read", looped, false)]).unwrap_err();
        assert!(
            error.contains("sample.a") && error.contains("loop"),
            "{error}"
        );
        let missing = json!({"properties": {"a": {"$ref": "#/$defs/gone"}}});
        let error = project(vec![member("one", "read", missing, false)]).unwrap_err();
        assert!(error.contains("#/$defs/gone"), "{error}");
    }

    #[test]
    fn conflicting_types_and_duplicate_operations_are_load_errors() {
        let result = project(vec![
            member(
                "one",
                "read",
                json!({"properties":{"value":{"type":"string"}}}),
                false,
            ),
            member(
                "two",
                "list",
                json!({"properties":{"value":{"type":"object"}}}),
                false,
            ),
        ]);
        assert!(result.unwrap_err().contains("conflicting types"));
        assert!(project(vec![
            member("one", "read", json!({}), false),
            member("two", "read", json!({}), false)
        ])
        .unwrap_err()
        .contains("duplicate"));
    }

    fn toolset_toml(examples: &[&str]) -> ToolsetToml {
        ToolsetToml {
            schema: "odin.registry.v1".into(),
            kind: crate::schema::RegistryKind::Toolset,
            enabled: true,
            description: "Fixture category.".into(),
            examples: examples
                .iter()
                .map(|example| (*example).to_owned())
                .collect(),
        }
    }

    fn capability_with(id: &str, toolset: &str, op: &str, extra: &str) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: PathBuf::from(format!("registry/capabilities/{id}/capability.toml")),
            config: ObjectConfig::Capability(Box::new(
                toml::from_str(&format!(
                    r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
version = 1
description = "Fixture capability."
toolset = "{toolset}"
op = "{op}"
input_schema = "schemas/capability/fixture.tool.input.json"
output_schema = "schemas/capability/fixture.tool.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = {{ max_attempts = 1 }}
approval_policy = "none"
{extra}
"#
                ))
                .expect("parse capability fixture"),
            )),
        }
    }

    fn capability(id: &str, toolset: &str, op: &str) -> RegistryObject {
        capability_with(id, toolset, op, "")
    }

    fn toolset(id: &str, examples: &[&str]) -> RegistryObject {
        RegistryObject {
            id: id.to_owned(),
            relative_config: PathBuf::from(format!("registry/toolsets/{id}/toolset.toml")),
            config: ObjectConfig::Toolset(Box::new(toolset_toml(examples))),
        }
    }

    fn seat(
        id: &str,
        enabled: bool,
        tool_refs: &[&str],
        listing_bytes: Option<usize>,
    ) -> RegistryObject {
        let tool_refs = serde_json::to_string(tool_refs).unwrap();
        let tools = listing_bytes
            .map(|bytes| {
                format!(
                    "[tools]\nlisting_bytes = {bytes}\ndeny = []\n[tools.redirects]\n\
                     max_http_hops = 2\nallow_cross_origin = false\ndisabled_aliases = []\n"
                )
            })
            .unwrap_or_default();
        RegistryObject {
            id: id.to_owned(),
            relative_config: PathBuf::from(format!("registry/seats/{id}/seat.toml")),
            config: ObjectConfig::Seat(Box::new(
                toml::from_str(&format!(
                    "schema = \"odin.registry.v1\"\nkind = \"seat\"\nenabled = {enabled}\n\
                     description = \"fixture\"\ncategories = []\ntool_refs = {tool_refs}\n\
                     project_scope = [\"fixture\"]\nbrain_scope = []\n\
                     limits = {{ max_parallel_runs = 1, max_sessions = 1 }}\n{tools}"
                ))
                .expect("parse seat fixture"),
            )),
        }
    }

    fn messages(objects: &[RegistryObject]) -> Vec<String> {
        validate_metadata(objects, Path::new("/nonexistent"), &mut BTreeMap::new())
            .into_iter()
            .map(|finding| finding.message)
            .collect()
    }

    /// A schema tree holding one capability input of `fields` string properties.
    fn schema_root(fields: usize) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let schemas = root.path().join("schemas/capability");
        std::fs::create_dir_all(&schemas).unwrap();
        let properties: serde_json::Map<String, Value> = (0..fields)
            .map(|n| (format!("field_{n}"), json!({"type": "string"})))
            .collect();
        std::fs::write(
            schemas.join("fixture.tool.input.json"),
            json!({"type": "object", "properties": properties}).to_string(),
        )
        .unwrap();
        root
    }

    fn listing_findings(objects: &[RegistryObject], root: &Path) -> Vec<crate::RegistryFinding> {
        validate(objects, root, &BTreeMap::new())
            .into_iter()
            .filter(|finding| finding.code == "tool-listing")
            .collect()
    }

    /// A seat_ops entry naming an absent seat (`ghost`) or a disabled one
    /// (`parked`) presents nothing and invalidates nothing, while the
    /// enabled seat's own presentation (`live`) still validates.
    #[test]
    fn seat_ops_for_absent_or_disabled_seats_are_inert() {
        let objects = vec![
            capability_with(
                "fixture.tool",
                "kube",
                "pods",
                r#"seat_ops = { ghost = { toolset = "kube", op = "pods" }, parked = { toolset = "kube", op = "pods" }, live = { toolset = "kube", op = "Help" } }"#,
            ),
            seat("parked", false, &[], None),
            seat("live", true, &[], None),
        ];
        let findings = messages(&objects);
        assert!(
            findings.iter().all(|message| !message.contains("seat")),
            "absent and disabled seat_ops entries are inert: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|message| message.contains("invalid or reserved operation kube.Help")),
            "the enabled seat's own presentation still validates: {findings:?}"
        );
    }

    #[test]
    fn undeclared_toolset_fails_naming_the_file_to_add() {
        let findings = messages(&[capability("fixture.read", "sample", "read")]);
        assert!(
            findings
                .iter()
                .any(|message| message.contains("registry/toolsets/sample/toolset.toml")),
            "{findings:?}"
        );
    }

    #[test]
    fn toolset_declarations_are_refused_for_the_cause_that_breaks_them() {
        let two = [r#"sample {op: "read"}"#, r#"sample {op: "list"}"#];
        let read = || capability("fixture.read", "sample", "read");
        let long = "x".repeat(TOOLSET_DESCRIPTION_MAX_CHARS + 1);
        let mut long_description = toolset("sample", &two);
        if let ObjectConfig::Toolset(declared) = &mut long_description.config {
            declared.description = long;
        }
        let mut disabled = toolset("sample", &two);
        if let ObjectConfig::Toolset(declared) = &mut disabled.config {
            declared.enabled = false;
        }
        for (objects, cause) in [
            (vec![toolset("sample", &two)], "no enabled capability"),
            (vec![read(), toolset("sample", &two[..1])], "1 examples"),
            (
                vec![
                    read(),
                    toolset("sample", &[two[0]; TOOLSET_EXAMPLES_MAX + 1]),
                ],
                "6 examples",
            ),
            (vec![read(), long_description], "chars, over"),
            (
                vec![read(), toolset("sample", &[two[0], "sample {id: 1}"])],
                "names no op",
            ),
            (
                vec![
                    read(),
                    toolset("sample", &[two[0], r#"sample {stop: "now", op: "write"}"#]),
                ],
                "calls op write",
            ),
            (vec![read(), disabled], "is disabled"),
        ] {
            let findings = messages(&objects);
            assert!(
                findings.iter().any(|message| message.contains(cause)),
                "{cause}: {findings:?}"
            );
        }
        let valid = [
            read(),
            toolset("sample", &[r#"sample {stop: "now", op: "read"}"#, two[1]]),
            capability("fixture.list", "sample", "list"),
        ];
        assert_eq!(messages(&valid), Vec::<String>::new());
    }

    /// A seat whose projected listing, with the deployment headroom, fits its
    /// budget exactly is accepted; one byte under is refused by name, and no
    /// seat may declare more than the hard maximum.
    #[test]
    fn a_seat_listing_over_its_budget_fails_the_registry_naming_the_seat_and_size() {
        let root = schema_root(40);
        let objects = |budget: usize| {
            [
                capability("fixture.read", "sample", "read"),
                seat("live", true, &["fixture.read"], Some(budget)),
            ]
        };
        let measured = crate::listing::listing_bytes(
            &seat_listing(&objects(DEFAULT_LISTING_BYTES), "live", root.path()).unwrap(),
        );
        let needed = measured + crate::listing::DEPLOYMENT_HEADROOM_BYTES;
        assert!(listing_findings(&objects(needed), root.path()).is_empty());
        let refused = listing_findings(&objects(needed - 1), root.path());
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].message.contains("live")
                && refused[0].message.contains(&measured.to_string())
        );
        assert!(refused[0].path.ends_with("registry/seats/live/seat.toml"));
        let refused = listing_findings(&objects(DEFAULT_LISTING_BYTES + 1), root.path());
        assert!(refused[0].message.contains("hard maximum"), "{refused:?}");
    }

    #[test]
    fn a_schema_reference_cannot_leave_the_schema_tree() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("schemas/capability")).unwrap();
        std::fs::write(root.path().join("secret.json"), "{}").unwrap();
        std::os::unix::fs::symlink(
            root.path().join("secret.json"),
            root.path().join("schemas/capability/link.json"),
        )
        .unwrap();
        let refusal = |reference: &str| read_schema(root.path(), reference).unwrap_err();
        assert!(refusal("../secret.json").contains("invalid schema path"));
        assert!(refusal("schemas/capability/link.json").contains("escapes schema root"));
        assert!(refusal("schemas/capability/gone.json").contains("gone.json"));
    }
}
