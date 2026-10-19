//! Strict model schemas require nullable optional fields; canonical validation
//! runs after optional nulls are removed.

use serde_json::{Map, Value};

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

/// What an OMP seat's model is shown: optionals required-and-nullable, root
/// annotations dropped. Validation always runs against the declared schema.
pub fn model_parameters(schema: &Value) -> Value {
    without_root_annotations(&nullable_optionals(schema))
}

/// The model-visible form of a tool's argument schema: every optional object
/// property becomes required and nullable, recursively. Required properties
/// are unchanged.
pub fn nullable_optionals(schema: &Value) -> Value {
    let mut schema = schema.clone();
    rewrite(&mut schema);
    schema
}

fn rewrite(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(items) = object.get_mut("items") {
        rewrite(items);
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        // Presence-only mode alternatives describe normalized arguments, not
        // the model's object with every inactive property filled with null.
        // Other unions (including property type unions) keep their constraints.
        let presence_modes = keyword != "allOf"
            && object.contains_key("properties")
            && object
                .get(keyword)
                .and_then(Value::as_array)
                .is_some_and(|branches| {
                    !branches.is_empty() && branches.iter().all(is_presence_mode)
                });
        if presence_modes {
            object.remove(keyword);
        } else if let Some(Value::Array(branches)) = object.get_mut(keyword) {
            for branch in branches {
                rewrite(branch);
            }
        }
    }
    let Some(Value::Object(properties)) = object.get("properties").cloned() else {
        return;
    };
    let required: Vec<String> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut rewritten = Map::new();
    let mut all_required = required.clone();
    for (name, mut property) in properties {
        rewrite(&mut property);
        if !required.contains(&name) {
            property = nullable(property);
            all_required.push(name.clone());
        }
        rewritten.insert(name, property);
    }
    object.insert("properties".to_owned(), Value::Object(rewritten));
    object.insert(
        "required".to_owned(),
        Value::Array(all_required.into_iter().map(Value::String).collect()),
    );
}

fn nullable(mut property: Value) -> Value {
    let Some(object) = property.as_object_mut() else {
        return property;
    };
    if let Some(Value::Array(values)) = object.get_mut("enum") {
        if !values.contains(&Value::Null) {
            values.push(Value::Null);
        }
    }
    match object.get_mut("type") {
        Some(Value::String(single)) => {
            let single = single.clone();
            object.insert(
                "type".to_owned(),
                Value::Array(vec![
                    Value::String(single),
                    Value::String("null".to_owned()),
                ]),
            );
            property
        }
        Some(Value::Array(types)) => {
            if !types.contains(&Value::String("null".to_owned())) {
                types.push(Value::String("null".to_owned()));
            }
            property
        }
        _ => serde_json::json!({ "anyOf": [property, { "type": "null" }] }),
    }
}

// Presence-only expressions describe which keys survive normalization, not
// which nullable placeholders appear on the wire. Recognize their grammar
// recursively, including both `not: {required: ...}` and compound negations.
// Any value/type constraint keeps the entire combinator visible to the model.
fn is_presence_mode(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    !object.is_empty()
        && object.iter().all(|(key, value)| match key.as_str() {
            "required" => value
                .as_array()
                .is_some_and(|names| !names.is_empty() && names.iter().all(Value::is_string)),
            "not" => is_presence_mode(value),
            "allOf" | "anyOf" | "oneOf" => value.as_array().is_some_and(|branches| {
                !branches.is_empty() && branches.iter().all(is_presence_mode)
            }),
            _ => false,
        })
}

fn required_names(schema: &Value) -> impl Iterator<Item = &str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

// Preserve requirements of modes selected by explicit non-null fields.
fn applicable_schemas<'a>(
    schema: &'a Value,
    fields: &Map<String, Value>,
    out: &mut Vec<&'a Value>,
) {
    out.push(schema);
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            applicable_schemas(branch, fields, out);
        }
    }
    for keyword in ["oneOf", "anyOf"] {
        let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
            continue;
        };
        let compatible = |branch: &&Value| {
            branch
                .get("properties")
                .and_then(Value::as_object)
                .is_none_or(|properties| {
                    properties.iter().all(|(name, constraint)| {
                        fields.get(name).is_none_or(|value| {
                            constraint
                                .get("const")
                                .is_none_or(|expected| expected == value)
                                && constraint
                                    .get("enum")
                                    .and_then(Value::as_array)
                                    .is_none_or(|values| values.contains(value))
                        })
                    })
                })
        };
        let evidenced = |branch: &&Value| {
            required_names(branch).any(|name| {
                // Shared requirements are not mode discriminators.
                !branches
                    .iter()
                    .all(|other| required_names(other).any(|other| other == name))
                    && fields.get(name).is_some_and(|value| !value.is_null())
            })
        };
        let selected = branches
            .iter()
            .filter(compatible)
            .any(|branch| evidenced(&branch));
        for branch in branches.iter().filter(compatible) {
            if !selected || evidenced(&branch) {
                applicable_schemas(branch, fields, out);
            }
        }
    }
}

/// Remove optional nulls while retaining values required by the active schema.
pub fn drop_null_optionals(schema: &Value, arguments: Value) -> Value {
    drop_null_optionals_from(&[schema], arguments)
}

fn drop_null_optionals_from(schemas: &[&Value], arguments: Value) -> Value {
    match arguments {
        Value::Object(fields) => {
            let mut applicable = Vec::new();
            for schema in schemas {
                applicable_schemas(schema, &fields, &mut applicable);
            }
            Value::Object(
                fields
                    .into_iter()
                    .filter(|(name, value)| {
                        !value.is_null()
                            || applicable.iter().any(|schema| {
                                required_names(schema).any(|required| required == name.as_str())
                            })
                    })
                    .map(|(name, value)| {
                        let value = if value.is_object() || value.is_array() {
                            let nested: Vec<&Value> = applicable
                                .iter()
                                .filter_map(|schema| {
                                    schema
                                        .get("properties")
                                        .and_then(|properties| properties.get(&name))
                                })
                                .collect();
                            drop_null_optionals_from(&nested, value)
                        } else {
                            value
                        };
                        (name, value)
                    })
                    .collect(),
            )
        }
        Value::Array(items) => {
            let item_schemas: Vec<&Value> = schemas
                .iter()
                .filter_map(|schema| schema.get("items"))
                .collect();
            Value::Array(
                items
                    .into_iter()
                    .map(|item| drop_null_optionals_from(&item_schemas, item))
                    .collect(),
            )
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn workload_draft_schema() -> Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/capability/workload.draft.input.json"
        ))
        .expect("the declared workload.draft input schema parses")
    }

    fn valid(schema: &Value, arguments: &Value) -> bool {
        jsonschema::validator_for(schema)
            .expect("schema compiles")
            .is_valid(arguments)
    }

    fn edit_schema() -> Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/capability/capsule.file.edit.input.json"
        ))
        .expect("the declared edit schema parses")
    }

    fn forget_schema() -> Value {
        serde_json::from_str(include_str!(
            "../../../../schemas/capability/memory.forget.input.json"
        ))
        .expect("the declared forget schema parses")
    }

    #[test]
    fn forget_modes_accept_null_placeholders_before_canonical_validation() {
        let schema = forget_schema();
        let shown = model_parameters(&schema);
        let commit = "a".repeat(40);
        for (sent, expected) in [
            (
                json!({"contains":"obsolete phrase", "commit":null, "page":null, "label":null}),
                json!({"contains":"obsolete phrase"}),
            ),
            (
                json!({"contains":null, "commit":commit, "page":"topic", "label":"original entry"}),
                json!({"commit":commit, "page":"topic", "label":"original entry"}),
            ),
        ] {
            assert!(valid(&shown, &sent), "model schema accepts {sent}");
            let normalized = drop_null_optionals(&schema, sent);
            assert_eq!(normalized, expected);
            assert!(valid(&schema, &normalized));
        }
        for sent in [
            json!({"contains":"obsolete phrase", "commit":commit, "page":"topic", "label":"original entry"}),
            json!({"contains":null, "commit":commit, "page":null, "label":"original entry"}),
            json!({"contains":null, "commit":null, "page":null, "label":null}),
        ] {
            assert!(
                !valid(&schema, &drop_null_optionals(&schema, sent.clone())),
                "{sent}"
            );
        }
    }

    #[test]
    fn nested_presence_expressions_are_projected_but_value_constraints_remain() {
        let mut schema = json!({
            "type":"object",
            "properties":{"left":{"type":"string"}, "right":{"type":"integer"}},
            "oneOf":[
                {"allOf":[{"required":["left"]}, {"not":{"required":["right"]}}]},
                {"required":["right"], "not":{"anyOf":[{"required":["left"]}]}}
            ]
        });
        let shown = model_parameters(&schema);
        assert!(shown.get("oneOf").is_none());
        assert!(valid(&shown, &json!({"left":"value", "right":null})));
        assert!(valid(&shown, &json!({"left":null, "right":7})));
        assert!(!valid(&shown, &json!({"left":null, "right":"wrong type"})));
        schema["oneOf"][0]["allOf"][1]["not"] =
            json!({"properties":{"right":{"const":7}}, "required":["right"]});
        let constrained = model_parameters(&schema);
        assert!(constrained.get("oneOf").is_some());
        assert_eq!(
            constrained["oneOf"][0]["allOf"][1]["not"],
            schema["oneOf"][0]["allOf"][1]["not"]
        );
        assert!(!valid(&constrained, &json!({"left":"value", "right":7})));
    }

    #[test]
    fn edit_modes_preserve_required_null_and_empty_values() {
        let schema = edit_schema();
        let shown = model_parameters(&schema);
        for content in ["", "hello", "null"] {
            let sent = json!({"path":"a", "content":content, "preimage_sha256":null,
                "old_text":null, "new_text":null});
            assert!(valid(&shown, &sent));
            let normalized = drop_null_optionals(&schema, sent);
            assert_eq!(
                normalized,
                json!({"path":"a", "content":content, "preimage_sha256":null})
            );
            assert!(valid(&schema, &normalized));
        }
        let sent = json!({"path":"a", "old_text":"old", "new_text":"",
            "content":null, "preimage_sha256":null});
        assert!(valid(&shown, &sent));
        let normalized = drop_null_optionals(&schema, sent);
        assert_eq!(
            normalized,
            json!({"path":"a", "old_text":"old", "new_text":""})
        );
        assert!(valid(&schema, &normalized));
    }

    #[test]
    fn edit_modes_refuse_missing_required_and_mixed_arguments() {
        let schema = edit_schema();
        for sent in [
            json!({"path":"a", "content":""}),
            json!({"path":"a", "preimage_sha256":null}),
            json!({"path":"a", "old_text":"old"}),
            json!({"path":"a", "old_text":"", "new_text":""}),
            json!({"path":"a", "content":null, "preimage_sha256":null}),
        ] {
            assert!(
                !valid(&schema, &drop_null_optionals(&schema, sent.clone())),
                "{sent}"
            );
        }
        let sent = json!({"path":"a", "content":"replacement", "preimage_sha256":"a".repeat(64)});
        assert!(valid(&schema, &drop_null_optionals(&schema, sent)));
        let sent = json!({"path":"a", "content":"", "preimage_sha256":null, "old_text":"old", "new_text":""});
        let normalized = drop_null_optionals(&schema, sent.clone());
        assert_eq!(normalized, sent);
        assert!(!valid(&schema, &normalized));
    }

    #[test]
    fn empty_fields_are_not_guessed_to_be_absent() {
        let schema = |name: &str| -> Value {
            let path = format!(
                "{}/../../schemas/capability/{name}.input.json",
                env!("CARGO_MANIFEST_DIR")
            );
            serde_json::from_str(&std::fs::read_to_string(path).expect("schema")).expect("json")
        };
        let write = schema("artifact.write");
        let sent = json!({"path":"", "text":"report", "mediaType":"text/plain"});
        assert!(!valid(&write, &drop_null_optionals(&write, sent)));
        let forget = schema("memory.forget");
        let sent = json!({"contains":"acc-token", "commit":"", "label":"", "page":""});
        let normalized = drop_null_optionals(&forget, sent.clone());
        assert_eq!(normalized, sent);
        assert!(!valid(&forget, &normalized));
    }

    #[test]
    fn combinator_requirements_preserve_nullable_values_and_omit_approval() {
        for keyword in ["oneOf", "anyOf"] {
            let schema = json!({
                "type":"object",
                "properties": {"kind":{"type":"string"}, "payload":{"type":["string","null"]},
                    "other":{"type":"string"}, "approvalId":{"type":"string"}},
                "allOf":[{"required":["kind"]}],
                (keyword): [
                    {"properties":{"kind":{"const":"write"}}, "required":["kind","payload"]},
                    {"properties":{"kind":{"const":"other"}}, "required":["kind","other"]}
                ]
            });
            let sent = json!({"kind":"write", "payload":null, "other":null, "approvalId":null});
            let normalized = drop_null_optionals(&schema, sent);
            assert_eq!(normalized, json!({"kind":"write", "payload":null}));
            assert!(valid(&schema, &normalized));
            assert!(!valid(
                &schema,
                &drop_null_optionals(&schema, json!({"kind":"write"}))
            ));
            assert!(
                model_parameters(&schema).get(keyword).is_some(),
                "non-presence unions stay visible"
            );
        }
    }

    #[test]
    fn a_null_optional_is_omitted_before_the_schema_sees_it() {
        let schema = workload_draft_schema();
        let arguments = json!({
            "profileId": "astra-hello",
            "imageReference": null,
            "scriptCommand": null,
            "tools": null,
        });
        assert!(
            !valid(&schema, &arguments),
            "the raw nulls fail the declared schema"
        );
        let dropped = drop_null_optionals(&schema, arguments);
        assert_eq!(dropped, json!({ "profileId": "astra-hello" }));
        assert!(valid(&schema, &dropped));
    }

    #[test]
    fn a_null_required_property_is_kept_and_refused() {
        let schema = workload_draft_schema();
        let dropped = drop_null_optionals(&schema, json!({ "profileId": null }));
        assert_eq!(dropped, json!({ "profileId": null }));
        assert!(!valid(&schema, &dropped));
    }

    #[test]
    fn the_model_sees_optionals_as_required_and_nullable() {
        let shown = nullable_optionals(&workload_draft_schema());
        let required = shown["required"].as_array().expect("required");
        assert!(required.contains(&json!("imageReference")));
        assert!(required.contains(&json!("profileId")));
        assert_eq!(
            shown["properties"]["imageReference"]["type"],
            json!(["string", "null"])
        );
        assert_eq!(shown["properties"]["profileId"]["type"], json!("string"));
        let sent = json!({ "profileId": "astra-hello", "imageReference": null });
        assert!(valid(
            &workload_draft_schema(),
            &drop_null_optionals(&workload_draft_schema(), sent)
        ));
    }

    #[test]
    fn only_null_optionals_are_omitted() {
        let schema = json!({
            "type": "object",
            "properties": {"runId": {"type": "string"}, "name": {"type": "string"}},
            "required": ["name"]
        });
        assert_eq!(
            drop_null_optionals(&schema, json!({"runId":null, "name":"x"})),
            json!({"name":"x"})
        );
        for value in [json!(""), json!("null")] {
            let sent = json!({"runId":value, "name":"x"});
            assert_eq!(drop_null_optionals(&schema, sent.clone()), sent);
        }
        assert_eq!(
            drop_null_optionals(&schema, json!({"runId": "run:1", "name": ""})),
            json!({"runId": "run:1", "name": ""}),
            "a required field and a real value are kept"
        );
    }

    #[test]
    fn optional_patterns_and_lengths_reject_invalid_strings() {
        let declared: Value = serde_json::from_str(include_str!(
            "../../../../schemas/capability/kube.workload.summarize.input.json"
        ))
        .expect("the declared summarize input schema parses");
        let shown = nullable_optionals(&declared);
        let sent = json!({"runId":null});
        assert!(valid(&shown, &sent));
        assert!(valid(&declared, &drop_null_optionals(&declared, sent)));
        let empty = json!({"runId":""});
        assert!(!valid(&shown, &empty));
        assert!(!valid(&declared, &drop_null_optionals(&declared, empty)));
        let literal = json!({"runId":"null"});
        assert!(valid(&shown, &literal));
        assert_eq!(drop_null_optionals(&declared, literal.clone()), literal);
        let bounded = json!({"type":"object", "properties":{
            "name":{"type":"string", "minLength":1}
        }});
        assert!(!valid(&nullable_optionals(&bounded), &json!({"name":""})));
        assert!(valid(&nullable_optionals(&bounded), &json!({"name":null})));
        assert!(valid(&shown, &json!({ "runId": "run:live:efe4a728" })));
        assert!(!valid(&shown, &json!({ "runId": "-bad id" })));
        assert!(!valid(&declared, &json!({ "runId": "-bad id" })));
    }
}
