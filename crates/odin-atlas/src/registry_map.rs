//! Registry object summaries derived directly from committed TOML.

use crate::{
    load_text_sources, AtlasNode, AtlasParseError, ScannedClass, SourceClass, SourceInput,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy)]
struct RegistryKindSpec {
    kind: &'static str,
    directory: &'static str,
}

const REGISTRY_KINDS: [RegistryKindSpec; 11] = [
    RegistryKindSpec {
        kind: "seat",
        directory: "seats",
    },
    RegistryKindSpec {
        kind: "project",
        directory: "projects",
    },
    RegistryKindSpec {
        kind: "lane",
        directory: "lanes",
    },
    RegistryKindSpec {
        kind: "node",
        directory: "nodes",
    },
    RegistryKindSpec {
        kind: "provider",
        directory: "providers",
    },
    RegistryKindSpec {
        kind: "capability",
        directory: "capabilities",
    },
    RegistryKindSpec {
        kind: "slice",
        directory: "slices",
    },
    RegistryKindSpec {
        kind: "container",
        directory: "containers",
    },
    RegistryKindSpec {
        kind: "host",
        directory: "hosts",
    },
    RegistryKindSpec {
        kind: "workload",
        directory: "workloads",
    },
    RegistryKindSpec {
        kind: "routine",
        directory: "routines",
    },
];

#[derive(Default)]
struct KindAggregate {
    enabled: usize,
    sources: Vec<(String, String)>,
}

pub(crate) fn scan(root: &Path, source_root: &Path) -> ScannedClass {
    let (mut scan, inputs) = load_text_sources(root, source_root, SourceClass::Registry, &["toml"]);
    let mut occurrences = BTreeMap::<String, usize>::new();
    let mut aggregates = REGISTRY_KINDS
        .into_iter()
        .map(|spec| (spec.kind, KindAggregate::default()))
        .collect::<BTreeMap<_, _>>();
    for input in inputs {
        let (summary, errors) = parse_toml_summary(&input.text);
        for message in errors {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Registry,
                path: input.relative.clone(),
                message: format!("TOML summary parse failed: {message}"),
            });
        }
        let mut node = registry_node(&input, summary);
        let occurrence = occurrences.entry(node.id.clone()).or_insert(0);
        *occurrence += 1;
        if *occurrence > 1 {
            node.id = format!("{}#{}", node.id, *occurrence);
        }
        if let Some(aggregate) = aggregates.get_mut(node.kind.as_str()) {
            if node
                .properties
                .get("enabled")
                .and_then(Value::as_str)
                .is_some_and(|enabled| enabled == "true")
            {
                aggregate.enabled += 1;
            }
            aggregate
                .sources
                .push((input.relative.clone(), input.hash.clone()));
        } else {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Registry,
                path: input.relative.clone(),
                message: format!(
                    "registry kind {:?} is not one of the nine v1 kinds",
                    node.kind
                ),
            });
        }
        scan.nodes.push(node);
    }

    let registry_directory = source_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("registry");
    for spec in REGISTRY_KINDS {
        let aggregate = aggregates.remove(spec.kind).unwrap_or_default();
        scan.nodes
            .push(registry_kind_node(registry_directory, spec, aggregate));
    }
    scan
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TomlSummary {
    pub(crate) properties: BTreeMap<String, String>,
}

pub(crate) fn parse_toml_summary(source: &str) -> (TomlSummary, Vec<String>) {
    let mut summary = TomlSummary::default();
    let mut errors = Vec::new();
    let mut section = String::new();
    let mut array_counts = BTreeMap::<String, usize>::new();
    let mut pending = String::new();
    let mut pending_line = 0usize;

    for (line_index, source_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let (without_comment, string_error) = strip_toml_comment(source_line);
        if let Some(error) = string_error {
            errors.push(format!("line {line_number}: {error}"));
        }
        let trimmed = without_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if pending.is_empty() && trimmed.starts_with("[[") {
            if !trimmed.ends_with("]]") || trimmed.len() < 5 {
                errors.push(format!("line {line_number}: malformed array table header"));
                continue;
            }
            let name = trimmed[2..trimmed.len() - 2].trim();
            if !valid_dotted_key(name) {
                errors.push(format!("line {line_number}: invalid array table name"));
                continue;
            }
            let index = array_counts.entry(name.to_owned()).or_insert(0);
            section = format!("{name}[{index}]");
            *index += 1;
            continue;
        }
        if pending.is_empty() && trimmed.starts_with('[') {
            if !trimmed.ends_with(']') || trimmed.len() < 3 {
                errors.push(format!("line {line_number}: malformed table header"));
                continue;
            }
            let name = trimmed[1..trimmed.len() - 1].trim();
            if !valid_dotted_key(name) {
                errors.push(format!("line {line_number}: invalid table name"));
                continue;
            }
            section = name.to_owned();
            continue;
        }

        if pending.is_empty() {
            pending_line = line_number;
            pending.push_str(trimmed);
        } else {
            pending.push(' ');
            pending.push_str(trimmed);
        }
        match value_is_complete(&pending) {
            Ok(true) => {
                match split_assignment(&pending) {
                    Some((key, value)) if valid_dotted_key(key) && !value.is_empty() => {
                        let path = if section.is_empty() {
                            key.to_owned()
                        } else {
                            format!("{section}.{key}")
                        };
                        if summary
                            .properties
                            .insert(path.clone(), normalize_toml_value(value))
                            .is_some()
                        {
                            errors.push(format!("line {pending_line}: duplicate property {path}"));
                        }
                    }
                    Some(_) => errors.push(format!("line {pending_line}: invalid TOML assignment")),
                    None => errors.push(format!(
                        "line {pending_line}: expected a key/value assignment"
                    )),
                }
                pending.clear();
            }
            Ok(false) => {}
            Err(error) => {
                errors.push(format!("line {pending_line}: {error}"));
                pending.clear();
            }
        }
    }
    if !pending.is_empty() {
        errors.push(format!("line {pending_line}: unterminated TOML value"));
    }
    (summary, errors)
}

pub(crate) fn toml_string(value: &str) -> Option<String> {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        serde_json::from_str(value).ok()
    } else if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        Some(value[1..value.len() - 1].to_owned())
    } else {
        None
    }
}

fn registry_node(input: &SourceInput, summary: TomlSummary) -> AtlasNode {
    let object_id = input
        .relative
        .split('/')
        .rev()
        .nth(1)
        .unwrap_or("unknown")
        .to_owned();
    let kind = summary
        .properties
        .get("kind")
        .and_then(|value| toml_string(value))
        .unwrap_or_else(|| {
            input
                .relative
                .rsplit('/')
                .next()
                .and_then(|name| name.strip_suffix(".toml"))
                .unwrap_or("object")
                .to_owned()
        });
    let summary_text = summary
        .properties
        .get("description")
        .and_then(|value| toml_string(value));
    let relationships = registry_relationships(&kind, &summary.properties);
    let policy = policy_summary(&summary.properties);
    let scope_tags = registry_scope_tags(&summary.properties);
    let mut properties = summary
        .properties
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect::<BTreeMap<_, _>>();
    properties.insert(
        "parent".to_owned(),
        Value::String(format!("registry:{kind}")),
    );
    properties.insert("policy".to_owned(), Value::Object(policy));
    properties.insert(
        "relationship_count".to_owned(),
        Value::from(relationships.len()),
    );
    properties.insert("relationships".to_owned(), Value::Array(relationships));
    properties.insert(
        "scope_tags".to_owned(),
        Value::Array(scope_tags.into_iter().map(Value::String).collect()),
    );
    AtlasNode {
        id: format!("registry:{kind}:{object_id}"),
        source_class: SourceClass::Registry,
        path: input.relative.clone(),
        source_blake3: input.hash.clone(),
        name: object_id,
        kind,
        signature: None,
        summary: summary_text,
        properties,
    }
}

fn registry_kind_node(
    registry_directory: &str,
    spec: RegistryKindSpec,
    mut aggregate: KindAggregate,
) -> AtlasNode {
    aggregate.sources.sort();
    let mut hasher = blake3::Hasher::new();
    for (path, hash) in &aggregate.sources {
        hasher.update(path.as_bytes());
        hasher.update(&[0]);
        hasher.update(hash.as_bytes());
        hasher.update(&[0]);
    }
    AtlasNode {
        id: format!("registry:{}", spec.kind),
        source_class: SourceClass::Registry,
        path: format!("{registry_directory}/{}", spec.directory),
        source_blake3: hasher.finalize().to_hex().to_string(),
        name: spec.kind.to_owned(),
        kind: "registry_kind".to_owned(),
        signature: None,
        summary: None,
        properties: [
            (
                "directory".to_owned(),
                Value::String(spec.directory.to_owned()),
            ),
            ("enabled_count".to_owned(), Value::from(aggregate.enabled)),
            (
                "object_count".to_owned(),
                Value::from(aggregate.sources.len()),
            ),
            ("parent".to_owned(), Value::String("registry".to_owned())),
            ("scope_tags".to_owned(), Value::Array(Vec::new())),
        ]
        .into_iter()
        .collect(),
    }
}

fn registry_relationships(kind: &str, properties: &BTreeMap<String, String>) -> Vec<Value> {
    let mut relationships = Vec::new();
    for (field, value) in properties {
        let Some(target_kind) = relationship_target(kind, field) else {
            continue;
        };
        for target_id in toml_string_values(value) {
            if target_id.is_empty() {
                continue;
            }
            let target = if target_kind == "tool" {
                format!("tool:{target_id}")
            } else {
                format!("registry:{target_kind}:{target_id}")
            };
            relationships.push(Value::Object(
                [
                    ("field".to_owned(), Value::String(field.clone())),
                    ("target".to_owned(), Value::String(target)),
                    ("target_id".to_owned(), Value::String(target_id)),
                    (
                        "target_kind".to_owned(),
                        Value::String(target_kind.to_owned()),
                    ),
                ]
                .into_iter()
                .collect(),
            ));
        }
    }
    relationships
}

fn relationship_target(kind: &str, field: &str) -> Option<&'static str> {
    match (kind, field) {
        ("seat", "project_scope") | ("seat", "read_project_scope") => Some("project"),
        ("seat", "tool_refs") => Some("capability"),
        ("seat", "live.file_ingress_lane")
        | ("seat", "live.file_egress_lane")
        | ("seat", "live.render_ingress_lane")
        | ("seat", "live.render_egress_lane") => Some("lane"),
        ("seat", "tools.allow") | ("seat", "tools.deny") => Some("tool"),
        ("slice", "capabilities") => Some("capability"),
        ("slice", "tools.allow") | ("slice", "tools.deny") => Some("tool"),
        ("project", "default_seat") => Some("seat"),
        ("lane", "project") => Some("project"),
        ("lane", "default_seat") => Some("seat"),
        ("node", "capabilities") => Some("capability"),
        ("container", "seats_offered") => Some("seat"),
        ("container", "monitoring.slice") => Some("slice"),
        _ if matches!(kind, "seat" | "slice")
            && field.starts_with("tools.alias_redirect[")
            && matches!(
                field.rsplit_once('.').map(|(_, suffix)| suffix),
                Some("from" | "to")
            ) =>
        {
            Some("tool")
        }
        _ => None,
    }
}

fn policy_summary(properties: &BTreeMap<String, String>) -> serde_json::Map<String, Value> {
    properties
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "schema" | "kind" | "description"))
        .map(|(key, value)| (key.clone(), typed_toml_value(value)))
        .collect()
}

fn registry_scope_tags(properties: &BTreeMap<String, String>) -> Vec<String> {
    let mut tags = properties
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "categories" | "seat_tags" | "scope_tags"))
        .flat_map(|(_, value)| toml_string_values(value))
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    tags
}

fn typed_toml_value(value: &str) -> Value {
    if let Some(value) = toml_string(value) {
        return Value::String(value);
    }
    if value == "true" {
        return Value::Bool(true);
    }
    if value == "false" {
        return Value::Bool(false);
    }
    let integer = value.replace('_', "");
    if let Ok(value) = integer.parse::<i64>() {
        return Value::from(value);
    }
    if let Ok(value) = integer.parse::<u64>() {
        return Value::from(value);
    }
    if value.starts_with('[') && value.ends_with(']') {
        let values = toml_string_values(value);
        if !values.is_empty() || value[1..value.len() - 1].trim().is_empty() {
            return Value::Array(values.into_iter().map(Value::String).collect());
        }
    }
    Value::String(value.to_owned())
}

fn toml_string_values(value: &str) -> Vec<String> {
    if let Some(value) = toml_string(value) {
        return vec![value];
    }
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Vec::new();
    }
    split_toml_list(&value[1..value.len() - 1])
        .into_iter()
        .filter_map(|item| toml_string(item.trim()))
        .collect()
}

fn split_toml_list(value: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            continue;
        }
        if character == ',' && quote.is_none() {
            items.push(&value[start..index]);
            start = index + 1;
        }
    }
    if start < value.len() {
        items.push(&value[start..]);
    }
    items
}

pub(crate) fn strip_toml_comment(line: &str) -> (String, Option<String>) {
    let mut result = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            result.push(character);
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            result.push(character);
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            result.push(character);
            continue;
        }
        if character == '#' && quote.is_none() {
            break;
        }
        result.push(character);
    }
    let error = quote.map(|_| "unterminated string literal".to_owned());
    (result, error)
}

fn value_is_complete(statement: &str) -> Result<bool, String> {
    let Some((_, value)) = split_assignment(statement) else {
        return Ok(true);
    };
    let mut square = 0usize;
    let mut curly = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }
        match character {
            '[' => square += 1,
            ']' => {
                square = square
                    .checked_sub(1)
                    .ok_or_else(|| "unmatched closing bracket".to_owned())?;
            }
            '{' => curly += 1,
            '}' => {
                curly = curly
                    .checked_sub(1)
                    .ok_or_else(|| "unmatched closing brace".to_owned())?;
            }
            _ => {}
        }
    }
    Ok(square == 0 && curly == 0 && quote.is_none())
}

fn split_assignment(statement: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in statement.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            continue;
        }
        if character == '=' && quote.is_none() {
            return Some((statement[..index].trim(), statement[index + 1..].trim()));
        }
    }
    None
}

fn valid_dotted_key(key: &str) -> bool {
    !key.is_empty()
        && key.split('.').all(|part| {
            !part.is_empty()
                && part.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

fn normalize_toml_value(value: &str) -> String {
    let mut normalized = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut pending_space = false;
    for character in value.trim().chars() {
        if escaped {
            normalized.push(character);
            escaped = false;
            continue;
        }
        if quote == Some('"') && character == '\\' {
            normalized.push(character);
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if pending_space && !normalized.is_empty() {
                normalized.push(' ');
            }
            pending_space = false;
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            normalized.push(character);
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            pending_space = true;
            continue;
        }
        if pending_space && !normalized.is_empty() {
            normalized.push(' ');
        }
        pending_space = false;
        normalized.push(character);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn seat_relationships_and_policy_are_derived_from_contract_fields() {
        let (summary, errors) = parse_toml_summary(
            r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "builder"
categories = ["build"]
tool_refs = ["check.run"]
project_scope = ["odin"]

[approval_defaults]
r0 = "auto"
r1 = "plan"
r2 = "approval"
r3 = "deny"

[limits]
max_parallel_runs = 4
max_sessions = 2
budget = { usd_micros = 1000, window = { duration_seconds = 86400 } }
"#,
        );
        assert!(errors.is_empty());
        let node = registry_node(
            &SourceInput {
                relative: "registry/seats/builder/seat.toml".to_owned(),
                hash: "source-hash".to_owned(),
                text: String::new(),
            },
            summary,
        );
        assert_eq!(
            node.properties.get("scope_tags"),
            Some(&Value::Array(vec![Value::String("build".to_owned())]))
        );
        assert_eq!(
            node.properties
                .get("policy")
                .and_then(Value::as_object)
                .and_then(|policy| policy.get("limits.max_parallel_runs")),
            Some(&Value::from(4))
        );
        let targets = node
            .properties
            .get("relationships")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|relationship| relationship.get("target"))
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            targets,
            BTreeSet::from(["registry:capability:check.run", "registry:project:odin"])
        );
    }
}
