//! Authoring skeleton and typed-variable catalog discovery.

use crate::registry_map::{parse_toml_summary, strip_toml_comment, toml_string, TomlSummary};
use crate::{
    load_text_sources, AtlasNode, AtlasParseError, ScannedClass, SourceClass, SourceInput,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) fn scan(root: &Path, source_root: &Path) -> ScannedClass {
    let (mut scan, inputs) = load_text_sources(root, source_root, SourceClass::Skeleton, &["toml"]);
    let mut directories = BTreeMap::<String, BTreeMap<String, SourceInput>>::new();
    for input in inputs {
        let Some((directory, name)) = input.relative.rsplit_once('/') else {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Skeleton,
                path: input.relative,
                message: "skeleton source is not inside a catalog directory".to_owned(),
            });
            continue;
        };
        directories
            .entry(directory.to_owned())
            .or_default()
            .insert(name.to_owned(), input);
    }

    for (directory, mut files) in directories {
        let skeleton_name = directory.rsplit('/').next().unwrap_or("unknown").to_owned();
        let template = files.remove("TEMPLATE.toml");
        let variables = files.remove("variables.toml");
        for extra in files.into_values() {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Skeleton,
                path: extra.relative,
                message: "unexpected TOML file in skeleton catalog".to_owned(),
            });
        }
        let Some(variables) = variables else {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Skeleton,
                path: format!("{directory}/variables.toml"),
                message: "missing skeleton variable catalog".to_owned(),
            });
            continue;
        };
        let Some(template) = template else {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Skeleton,
                path: format!("{directory}/TEMPLATE.toml"),
                message: "missing skeleton template".to_owned(),
            });
            continue;
        };

        let (variable_summary, variable_errors) = parse_toml_summary(&variables.text);
        record_errors(
            &mut scan,
            &variables.relative,
            "variable catalog",
            variable_errors,
        );
        let (_, template_errors) = parse_toml_summary(&template.text);
        record_errors(&mut scan, &template.relative, "template", template_errors);
        let placeholder_occurrences = template_placeholder_occurrences(&template.text);
        let placeholders = placeholder_occurrences
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let variable_groups = grouped_variables(&variable_summary);
        let destination = variable_summary
            .properties
            .get("destination")
            .and_then(|value| toml_string(value));
        record_catalog_mismatches(
            &mut scan,
            &variables.relative,
            destination.as_deref(),
            &placeholders,
            &variable_groups,
        );
        scan.nodes.push(skeleton_node(
            &skeleton_name,
            &variables,
            &template,
            &variable_summary,
            &placeholder_occurrences,
            &variable_groups,
        ));
        let mut variable_occurrences = BTreeMap::<String, usize>::new();
        for (index, fields) in variable_groups {
            let mut node = variable_node(
                &skeleton_name,
                index,
                fields,
                &variables,
                destination.as_deref(),
                &placeholder_occurrences,
            );
            let occurrence = variable_occurrences.entry(node.id.clone()).or_insert(0);
            *occurrence += 1;
            if *occurrence > 1 {
                node.id = format!("{}#{}", node.id, *occurrence);
            }
            scan.nodes.push(node);
        }
    }
    scan
}

fn record_errors(scan: &mut ScannedClass, path: &str, source: &str, errors: Vec<String>) {
    for message in errors {
        scan.parse_errors.push(AtlasParseError {
            source_class: SourceClass::Skeleton,
            path: path.to_owned(),
            message: format!("{source} TOML summary parse failed: {message}"),
        });
    }
}

fn skeleton_node(
    skeleton_name: &str,
    variables: &SourceInput,
    template: &SourceInput,
    summary: &TomlSummary,
    placeholder_occurrences: &BTreeMap<String, usize>,
    variable_groups: &BTreeMap<usize, BTreeMap<String, String>>,
) -> AtlasNode {
    let mut properties = summary
        .properties
        .iter()
        .filter(|(key, _)| !key.starts_with("variable["))
        .map(|(key, value)| (key.clone(), catalog_value(value)))
        .collect::<BTreeMap<_, _>>();
    let placeholders = placeholder_occurrences
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let declared = declared_variable_names(variable_groups);
    let mut variable_mapping = serde_json::Map::new();
    for name in &declared {
        variable_mapping.insert(
            name.clone(),
            Value::String(format!("skeleton:{skeleton_name}:variable:{name}")),
        );
    }
    properties.insert(
        "bijection".to_owned(),
        Value::Bool(placeholders == declared && declared.len() == variable_groups.len()),
    );
    properties.insert(
        "placeholder_count".to_owned(),
        Value::from(placeholders.len()),
    );
    properties.insert(
        "placeholder_occurrence_count".to_owned(),
        Value::from(placeholder_occurrences.values().sum::<usize>()),
    );
    properties.insert(
        "placeholders".to_owned(),
        Value::Array(placeholders.iter().cloned().map(Value::String).collect()),
    );
    properties.insert("scope_tags".to_owned(), Value::Array(Vec::new()));
    properties.insert(
        "template_blake3".to_owned(),
        Value::String(template.hash.clone()),
    );
    properties.insert(
        "template_path".to_owned(),
        Value::String(template.relative.clone()),
    );
    properties.insert(
        "variable_count".to_owned(),
        Value::from(variable_groups.len()),
    );
    properties.insert(
        "variable_mapping".to_owned(),
        Value::Object(variable_mapping),
    );
    properties.insert("parent".to_owned(), Value::String("skeletons".to_owned()));
    let kind = summary
        .properties
        .get("kind")
        .and_then(|value| toml_string(value))
        .unwrap_or_else(|| skeleton_name.to_owned());
    AtlasNode {
        id: format!("skeleton:{skeleton_name}"),
        source_class: SourceClass::Skeleton,
        path: variables.relative.clone(),
        source_blake3: variables.hash.clone(),
        name: skeleton_name.to_owned(),
        kind: "skeleton".to_owned(),
        signature: None,
        summary: Some(kind),
        properties,
    }
}

fn variable_node(
    skeleton_name: &str,
    index: usize,
    fields: BTreeMap<String, String>,
    variables: &SourceInput,
    destination: Option<&str>,
    placeholder_occurrences: &BTreeMap<String, usize>,
) -> AtlasNode {
    let name = fields
        .get("name")
        .and_then(|value| toml_string(value))
        .unwrap_or_else(|| format!("variable-{index}"));
    let declared_type = fields
        .get("type")
        .and_then(|value| toml_string(value))
        .unwrap_or_else(|| "unknown".to_owned());
    let meaning = fields.get("meaning").and_then(|value| toml_string(value));
    let mut properties = fields
        .into_iter()
        .map(|(key, value)| (key, catalog_value(&value)))
        .collect::<BTreeMap<_, _>>();
    properties.insert(
        "destination".to_owned(),
        destination.map_or(Value::Null, |value| Value::String(value.to_owned())),
    );
    properties.insert(
        "parent".to_owned(),
        Value::String(format!("skeleton:{skeleton_name}")),
    );
    properties.insert(
        "placeholder".to_owned(),
        Value::String(format!("__{name}__")),
    );
    properties.insert(
        "placeholder_occurrences".to_owned(),
        Value::from(
            placeholder_occurrences
                .get(&name)
                .copied()
                .unwrap_or_default(),
        ),
    );
    properties.insert("scope_tags".to_owned(), Value::Array(Vec::new()));
    add_variable_type_contract(&mut properties, &declared_type);
    AtlasNode {
        id: format!("skeleton:{skeleton_name}:variable:{name}"),
        source_class: SourceClass::Skeleton,
        path: variables.relative.clone(),
        source_blake3: variables.hash.clone(),
        name: name.clone(),
        kind: "skeleton_variable".to_owned(),
        signature: Some(format!("__{name}__: {declared_type}")),
        summary: meaning,
        properties,
    }
}

fn catalog_value(value: &str) -> Value {
    if let Some(value) = toml_string(value) {
        Value::String(value)
    } else if value == "true" {
        Value::Bool(true)
    } else if value == "false" {
        Value::Bool(false)
    } else if let Ok(value) = value.parse::<i64>() {
        Value::from(value)
    } else {
        Value::String(value.to_owned())
    }
}

fn add_variable_type_contract(properties: &mut BTreeMap<String, Value>, declared_type: &str) {
    let mut parts = declared_type.split(':');
    let variable_type = parts.next().unwrap_or("unknown");
    properties.insert(
        "variable_type".to_owned(),
        Value::String(variable_type.to_owned()),
    );
    if variable_type == "int" {
        let bounds = parts
            .next()
            .and_then(|minimum| minimum.parse::<i64>().ok())
            .zip(parts.next().and_then(|maximum| maximum.parse::<i64>().ok()));
        if let Some((minimum, maximum)) = bounds {
            properties.insert("range_min".to_owned(), Value::from(minimum));
            properties.insert("range_max".to_owned(), Value::from(maximum));
            properties.insert(
                "range".to_owned(),
                Value::Object(
                    [
                        ("inclusive".to_owned(), Value::Bool(true)),
                        ("max".to_owned(), Value::from(maximum)),
                        ("min".to_owned(), Value::from(minimum)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            );
        }
    } else if variable_type == "enum" {
        properties.insert(
            "allowed_values".to_owned(),
            Value::Array(
                parts
                    .flat_map(|values| values.split('|'))
                    .map(|value| Value::String(value.to_owned()))
                    .collect(),
            ),
        );
    }
}

fn grouped_variables(summary: &TomlSummary) -> BTreeMap<usize, BTreeMap<String, String>> {
    let mut groups = BTreeMap::<usize, BTreeMap<String, String>>::new();
    for (key, value) in &summary.properties {
        let Some(rest) = key.strip_prefix("variable[") else {
            continue;
        };
        let Some((index, field)) = rest.split_once("].") else {
            continue;
        };
        let Ok(index) = index.parse::<usize>() else {
            continue;
        };
        groups
            .entry(index)
            .or_default()
            .insert(field.to_owned(), value.clone());
    }
    groups
}

fn record_catalog_mismatches(
    scan: &mut ScannedClass,
    path: &str,
    destination: Option<&str>,
    placeholders: &BTreeSet<String>,
    variable_groups: &BTreeMap<usize, BTreeMap<String, String>>,
) {
    if destination.is_none() {
        scan.parse_errors.push(AtlasParseError {
            source_class: SourceClass::Skeleton,
            path: path.to_owned(),
            message: "variable catalog has no string destination".to_owned(),
        });
    }
    let names = variable_groups
        .values()
        .filter_map(|fields| fields.get("name"))
        .filter_map(|value| toml_string(value))
        .collect::<Vec<_>>();
    let declared = names.iter().cloned().collect::<BTreeSet<_>>();
    let mut occurrences = BTreeMap::<String, usize>::new();
    for name in names {
        let occurrence = occurrences.entry(name.clone()).or_insert(0);
        *occurrence += 1;
        if *occurrence == 2 {
            scan.parse_errors.push(AtlasParseError {
                source_class: SourceClass::Skeleton,
                path: path.to_owned(),
                message: format!("duplicate variable declaration {name:?}"),
            });
        }
    }
    for (index, fields) in variable_groups {
        for required_field in ["name", "type", "meaning"] {
            if !fields
                .get(required_field)
                .and_then(|value| toml_string(value))
                .is_some_and(|value| !value.is_empty())
            {
                scan.parse_errors.push(AtlasParseError {
                    source_class: SourceClass::Skeleton,
                    path: path.to_owned(),
                    message: format!(
                        "variable declaration {index} has no non-empty string {required_field}"
                    ),
                });
            }
        }
    }
    for name in placeholders.difference(&declared) {
        scan.parse_errors.push(AtlasParseError {
            source_class: SourceClass::Skeleton,
            path: path.to_owned(),
            message: format!("template placeholder {name:?} has no variable declaration"),
        });
    }
    for name in declared.difference(placeholders) {
        scan.parse_errors.push(AtlasParseError {
            source_class: SourceClass::Skeleton,
            path: path.to_owned(),
            message: format!("variable {name:?} has no template placeholder"),
        });
    }
}

fn declared_variable_names(
    variable_groups: &BTreeMap<usize, BTreeMap<String, String>>,
) -> BTreeSet<String> {
    variable_groups
        .values()
        .filter_map(|fields| fields.get("name"))
        .filter_map(|value| toml_string(value))
        .collect()
}

fn template_placeholder_occurrences(template: &str) -> BTreeMap<String, usize> {
    let uncommented = template
        .lines()
        .map(|line| strip_toml_comment(line).0)
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = uncommented.as_bytes();
    let mut placeholders = BTreeMap::<String, usize>::new();
    let mut index = 0usize;
    while index + 3 < bytes.len() {
        if bytes[index] != b'_' || bytes[index + 1] != b'_' {
            index += 1;
            continue;
        }
        let name_start = index + 2;
        let mut cursor = name_start;
        while cursor + 1 < bytes.len() {
            if bytes[cursor] == b'_' && bytes[cursor + 1] == b'_' {
                let name = &uncommented[name_start..cursor];
                if !name.is_empty()
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                {
                    *placeholders.entry(name.to_owned()).or_default() += 1;
                }
                index = cursor + 2;
                break;
            }
            cursor += 1;
        }
        if cursor + 1 >= bytes.len() {
            break;
        }
    }
    placeholders
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_catalog_maps_every_placeholder_and_preserves_type_contract() {
        let variable_source = r#"
schema = "odin.skeleton.variables.v1"
kind = "new-example"
destination = "examples"

[[variable]]
name = "limit"
type = "int:1:64"
required = true
meaning = "Bounded limit."

[[variable]]
name = "mode"
type = "enum:fast|careful"
required = true
meaning = "Execution mode."
"#;
        let template_source = "limit = __limit__\nmode = \"__mode__\"\nlabel = \"__mode__\"\n";
        let (summary, errors) = parse_toml_summary(variable_source);
        assert!(errors.is_empty());
        let groups = grouped_variables(&summary);
        let placeholders = template_placeholder_occurrences(template_source);
        assert_eq!(groups.len(), 2);
        assert_eq!(placeholders.len(), 2);
        assert_eq!(placeholders.values().sum::<usize>(), 3);
        assert_eq!(
            declared_variable_names(&groups),
            placeholders.keys().cloned().collect()
        );

        let variables = SourceInput {
            relative: "skeletons/new-example/variables.toml".to_owned(),
            hash: "variables-hash".to_owned(),
            text: variable_source.to_owned(),
        };
        let template = SourceInput {
            relative: "skeletons/new-example/TEMPLATE.toml".to_owned(),
            hash: "template-hash".to_owned(),
            text: template_source.to_owned(),
        };
        let skeleton = skeleton_node(
            "new-example",
            &variables,
            &template,
            &summary,
            &placeholders,
            &groups,
        );
        assert_eq!(
            skeleton.properties.get("bijection"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            skeleton.properties.get("variable_count"),
            Some(&Value::from(2))
        );

        let limit = variable_node(
            "new-example",
            0,
            groups.get(&0).cloned().expect("first variable"),
            &variables,
            Some("examples"),
            &placeholders,
        );
        assert_eq!(
            limit.properties.get("destination"),
            Some(&Value::String("examples".to_owned()))
        );
        assert_eq!(
            limit.properties.get("variable_type"),
            Some(&Value::String("int".to_owned()))
        );
        assert_eq!(limit.properties.get("range_min"), Some(&Value::from(1)));
        assert_eq!(limit.properties.get("range_max"), Some(&Value::from(64)));
    }
}
