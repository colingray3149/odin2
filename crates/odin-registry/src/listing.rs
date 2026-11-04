//! The tool listing a model is shown, and the one measure of its size.
//!
//! The bridge that registers a seat's host tools and the registry check that
//! guards the listing budget both go through [`model_listing`] and
//! [`listing_bytes`], so the gate counts the bytes the daemon will count.

use serde_json::{Map, Value};

/// Marks a property whose declared values resolve at the dispatch seam
/// (exact, case-fold, unique prefix) instead of gating the client: the
/// model surface drops the `enum` and lists the values in its description.
/// Validators ignore the keyword; the narrowing schema keeps it.
pub const RESOLVED_IDS: &str = "x-odin-resolve-ids";

/// Root keywords no validator reads and the model does not need beside the
/// tool description. Property descriptions stay: some are a field's only hint.
const ROOT_ANNOTATIONS: [&str; 4] = ["$schema", "$id", "title", "description"];

/// The schema without its root annotations: what `tools/list` shows a harness.
pub fn without_root_annotations(schema: &Value) -> Value {
    let mut schema = schema.clone();
    if let Some(object) = schema.as_object_mut() {
        for key in ROOT_ANNOTATIONS {
            object.remove(key);
        }
    }
    schema
}

/// What an OMP seat's model is shown: the declared schema without root
/// annotations, with each [`RESOLVED_IDS`] property a free string whose
/// description lists its real values. Validation always runs against the
/// declared schema.
pub fn model_parameters(schema: &Value) -> Value {
    let mut schema = without_root_annotations(schema);
    unresolve_ids(&mut schema);
    schema
}

/// A schema that pairs each `action` with its `arguments` through a top-level `oneOf` (the browser's),
/// as a model is shown it. A strict provider refuses the `oneOf` and can only send `{}` for an open
/// `arguments` object, so the pairing is dropped and every field the actions' arguments take is
/// declared beside `action`, optional. The call normalizer (odin-omp `loose`) moves them back into
/// `arguments`; validation keeps the declared schema. False, with the schema untouched, when it
/// carries no such pairing.
pub fn action_surface(schema: &mut Value) -> bool {
    let Some(Value::Array(branches)) = schema.get("oneOf") else {
        return false;
    };
    if ["action", "arguments"]
        .iter()
        .any(|field| schema.pointer(&format!("/properties/{field}")).is_none())
    {
        return false;
    }
    let mut fields = Map::new();
    for branch in branches {
        let Some(arguments) = branch.pointer("/properties/arguments") else {
            continue;
        };
        let arguments = match arguments.get("$ref").and_then(Value::as_str) {
            Some(reference) => reference
                .strip_prefix('#')
                .and_then(|pointer| schema.pointer(pointer)),
            None => Some(arguments),
        };
        let declared = arguments
            .and_then(|arguments| arguments.get("properties"))
            .and_then(Value::as_object);
        for (name, property) in declared.into_iter().flatten() {
            fields
                .entry(name.clone())
                .or_insert_with(|| property.clone());
        }
    }
    let Some(Value::Object(properties)) = schema.get_mut("properties") else {
        return false;
    };
    for (name, property) in fields {
        properties.entry(name).or_insert(property);
    }
    if let Value::Object(schema) = schema {
        schema.remove("oneOf");
    }
    true
}

/// The listing a model is sent: each serialized definition with its
/// `parameters` as [`model_parameters`] shows them.
pub fn model_listing(definitions: impl IntoIterator<Item = Value>) -> Vec<Value> {
    definitions
        .into_iter()
        .map(|mut definition| {
            if let Some(parameters) = definition.get("parameters") {
                definition["parameters"] = model_parameters(parameters);
            }
            definition
        })
        .collect()
}

/// What the running daemon adds to a listing the registry projects: the
/// accounts, projects and folder roots a deployment lists on its own fields,
/// and what its compiled tools add to the declared schemas. The registry
/// cannot see them, so every check of a projected listing leaves this much
/// room.
pub const DEPLOYMENT_HEADROOM_BYTES: usize = 1_500;

/// The size of a [`model_listing`] on the wire: its compact JSON array. This
/// is the number the daemon holds to [`crate::toolsets::DEFAULT_LISTING_BYTES`].
pub fn listing_bytes(listing: &[Value]) -> usize {
    serde_json::to_string(listing).map_or(usize::MAX, |json| json.len())
}

/// Replaces every [`RESOLVED_IDS`] property's `enum` with a description
/// listing the values, so no client rejects a near-miss before the seam can
/// resolve it.
fn unresolve_ids(schema: &mut Value) {
    if let Some(items) = schema.get_mut("items") {
        unresolve_ids(items);
    }
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = object.get_mut(keyword) {
            for branch in branches {
                unresolve_ids(branch);
            }
        }
    }
    let Some(Value::Object(properties)) = object.get_mut("properties") else {
        return;
    };
    for property in properties.values_mut() {
        unresolve_ids(property);
        let Some(entry) = property.as_object_mut() else {
            continue;
        };
        if entry.remove(RESOLVED_IDS) != Some(Value::Bool(true)) {
            continue;
        }
        let values = entry
            .remove("enum")
            .and_then(|declared| {
                declared
                    .as_array()
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(str::to_owned))
                            .collect::<Vec<_>>()
                    })
                    .filter(|values| !values.is_empty())
            })
            .unwrap_or_default();
        if values.is_empty() {
            continue;
        }
        entry.insert("type".to_owned(), Value::String("string".to_owned()));
        let listed = format!(" One of: {}.", values.join(", "));
        match entry.get("description").and_then(Value::as_str) {
            Some(text) => {
                let mut text = text.to_owned();
                if !text.ends_with('.') {
                    text.push('.');
                }
                text.push_str(&listed);
                entry.insert("description".to_owned(), Value::String(text));
            }
            None => {
                entry.insert(
                    "description".to_owned(),
                    Value::String(listed.trim_start().to_owned()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn direct_definition() -> Value {
        json!({
            "name": "mail_search",
            "label": "mail_search",
            "description": "Searches the mailbox.",
            "parameters": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "title": "mail.search input",
                "type": "object",
                "properties": {
                    "account": {
                        "type": "string",
                        RESOLVED_IDS: true,
                        "enum": ["personal", "school"]
                    }
                }
            },
            "hidden": false,
            "loadMode": "essential"
        })
    }

    #[test]
    fn listing_bytes_counts_the_adapted_listing_not_the_declared_schemas() {
        assert_eq!(
            listing_bytes(&[json!({"name": "x", "description": "d"})]),
            r#"[{"description":"d","name":"x"}]"#.len()
        );
        let raw = vec![direct_definition()];
        assert_ne!(
            listing_bytes(&model_listing(raw.clone())),
            listing_bytes(&raw)
        );
    }
}
