//! The model surface of a capability's arguments, and the loose-input
//! normalizations behind it.
//!
//! Omitted optionals stay omitted: every optional used to be shown as
//! required-and-nullable, so a strict client rejected a call that simply
//! left one out. A wire null that still arrives (a non-strict lane, or a
//! hand-written call) is dropped by [`drop_null_optionals`] before anything
//! digests or validates it. Id-like values (accounts, projects, profiles)
//! resolve at the dispatch seam: the model sees a free string whose
//! description lists the real values, never an enum a client would reject a
//! near-miss against.

use serde_json::{Map, Value};

// One definition of the model's schema surface, shared with the registry check that sizes the listing.
pub use odin_registry::listing::{model_parameters, without_root_annotations, RESOLVED_IDS};

/// Keywords that relate properties to each other. The kernel enforces them
/// against the declared schema; the model sees each property on its own.
const CROSS_FIELD: [&str; 10] = [
    "oneOf",
    "anyOf",
    "allOf",
    "not",
    "if",
    "then",
    "else",
    "dependentRequired",
    "minProperties",
    "maxProperties",
];

/// A capability tool's parameters, from its one declared input schema: no
/// root annotations, host-filled (`readOnly`) properties, or cross-field rules.
/// Deployment narrowing is validated alongside the canonical schema at dispatch.
pub fn declared_parameters(schema_json: &str) -> Value {
    let schema: Value = serde_json::from_str(schema_json)
        .unwrap_or_else(|error| panic!("compiled capability input schema is not JSON: {error}"));
    parameters_of(&schema)
}

/// [`declared_parameters`] of an already parsed input schema.
pub fn parameters_of(schema: &Value) -> Value {
    let mut parameters = without_root_annotations(schema);
    strip_for_model(&mut parameters);
    parameters
}

/// [`declared_parameters`] of `schemas/capability/<id>.input.json`, compiled in.
#[macro_export]
macro_rules! capability_parameters {
    ($id:literal) => {
        $crate::host_tools::schema_compat::declared_parameters(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/capability/",
            $id,
            ".input.json"
        )))
    };
}

/// Narrows the declared property at `pointer` (e.g. `/properties/account`)
/// for this deployment: sets `keyword` (`enum`, `maximum`, `maxItems`) to
/// `value`.
pub fn narrow(
    mut parameters: Value,
    pointer: &str,
    keyword: &str,
    value: impl serde::Serialize,
) -> Value {
    let value = serde_json::to_value(value)
        .unwrap_or_else(|error| panic!("{pointer} {keyword} is not JSON: {error}"));
    parameters
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("the capability input schema declares no {pointer}"))
        .insert(keyword.to_owned(), value);
    parameters
}

/// Narrows the declared property at `pointer` to this deployment's real
/// id-like `values` (accounts, projects, profiles): the narrowing schema
/// still admits only those values, while the model surface — see
/// [`model_parameters`] — shows a free string whose description lists them,
/// and [`resolve_id_argument`] resolves a near-miss at the dispatch seam.
pub fn resolve_ids(
    mut parameters: Value,
    pointer: &str,
    values: impl IntoIterator<Item: AsRef<str>>,
) -> Value {
    let values: Vec<String> = values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect();
    let property = parameters
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .unwrap_or_else(|| panic!("the capability input schema declares no {pointer}"));
    property.insert(RESOLVED_IDS.to_owned(), Value::Bool(true));
    if values.is_empty() {
        property.remove("enum");
        property.insert(
            "description".to_owned(),
            Value::String("No values are declared for this session.".to_owned()),
        );
        parameters
    } else {
        narrow(parameters, pointer, "enum", values)
    }
}

/// Resolves one id-like argument against the declared `values`: exact, then
/// case-fold, then a prefix unique under case-fold. `Err` carries the
/// correction, naming the values.
pub fn resolve_id_argument(field: &str, given: &str, values: &[String]) -> Result<String, String> {
    if given.is_empty() {
        return Err(format!(
            "{field} must name one of: {values:?}; an empty string is not an identifier"
        ));
    }
    if values.iter().any(|value| value == given) {
        return Ok(given.to_owned());
    }
    let mut folded = values
        .iter()
        .filter(|value| value.eq_ignore_ascii_case(given));
    if let (Some(exact), None) = (folded.next(), folded.next()) {
        return Ok(exact.clone());
    }
    let needle = given.to_ascii_lowercase();
    let mut prefixes = values
        .iter()
        .filter(|value| value.to_ascii_lowercase().starts_with(&needle));
    match (prefixes.next(), prefixes.next()) {
        (Some(unique), None) => Ok(unique.clone()),
        _ => Err(format!(
            "{field} must be one of: {}; {given:?} is not, and it is no unique prefix",
            values
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn strip_for_model(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(items) = object.get_mut("items") {
        strip_for_model(items);
    }
    let Some(Value::Object(properties)) = object.get_mut("properties") else {
        return;
    };
    let host_filled: Vec<String> = properties
        .iter()
        .filter(|(_, property)| property.get("readOnly") == Some(&Value::Bool(true)))
        .map(|(name, _)| name.clone())
        .collect();
    for name in &host_filled {
        properties.remove(name);
    }
    for property in properties.values_mut() {
        strip_for_model(property);
    }
    for keyword in CROSS_FIELD {
        object.remove(keyword);
    }
    if let Some(Value::Array(required)) = object.get_mut("required") {
        required.retain(|name| !host_filled.iter().any(|filled| name == filled.as_str()));
    }
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
    fn omitted_optionals_stay_omitted_and_wire_nulls_normalize() {
        let schema = forget_schema();
        let shown = model_parameters(&schema);
        let commit = "a".repeat(40);
        // The model may leave every optional out: no client-side refusal
        // for a pure omission.
        assert!(valid(&shown, &json!({"contains":"obsolete phrase"})));
        // A null that still arrives from a non-strict lane is dropped
        // before canonical validation.
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
    fn edit_modes_preserve_required_null_and_empty_values() {
        let schema = edit_schema();
        for content in ["", "hello", "null"] {
            let sent = json!({"path":"a", "content":content, "preimage_sha256":null,
                "old_text":null, "new_text":null});
            let normalized = drop_null_optionals(&schema, sent);
            assert_eq!(
                normalized,
                json!({"path":"a", "content":content, "preimage_sha256":null})
            );
            assert!(valid(&schema, &normalized));
        }
        let sent = json!({"path":"a", "old_text":"old", "new_text":"",
            "content":null, "preimage_sha256":null});
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
    fn report_view_accepts_rasterizer_page_widths_and_rejects_non_pages() {
        let declared: Value = serde_json::from_str(include_str!(
            "../../../../schemas/capability/report.view.input.json"
        ))
        .expect("report view schema");
        for path in [
            "/export/pages/page-1.png",
            "/export/pages/page-01.png",
            "/export/pages/page-1000.png",
        ] {
            assert!(valid(&declared, &json!({"path": path})), "{path}");
        }
        for path in [
            "/export/pages/page-.png",
            "/export/pages/page-10000.png",
            "/export/pages/page-1.pdf",
            "/tmp/pages/page-1.png",
        ] {
            assert!(!valid(&declared, &json!({"path": path})), "{path}");
        }
    }

    #[test]
    fn resolvable_ids_show_values_and_resolve_near_misses() {
        let declared = json!({"type":"object", "properties":{
            "account":{"type":"string", "description":"Which account to use"}
        }});
        let narrowed = resolve_ids(declared, "/properties/account", ["personal", "school"]);
        assert_eq!(
            narrowed["properties"]["account"]["enum"],
            json!(["personal", "school"])
        );
        let shown = model_parameters(&narrowed);
        assert!(shown["properties"]["account"].get("enum").is_none());
        assert!(shown["properties"]["account"].get(RESOLVED_IDS).is_none());
        assert_eq!(shown["properties"]["account"]["type"], json!("string"));
        let description = shown["properties"]["account"]["description"]
            .as_str()
            .expect("description lists the values");
        assert!(
            description.contains("One of: personal, school."),
            "{description}"
        );

        let values = vec!["personal".to_owned(), "school".to_owned()];
        assert_eq!(
            resolve_id_argument("account", "personal", &values),
            Ok("personal".to_owned())
        );
        assert_eq!(
            resolve_id_argument("account", "School", &values),
            Ok("school".to_owned())
        );
        assert_eq!(
            resolve_id_argument("account", "cal", &values),
            Ok("school".to_owned())
        );
        let ambiguous = vec!["school".to_owned(), "calendar".to_owned()];
        for given in ["cal", "missing", ""] {
            let error = resolve_id_argument("account", given, &ambiguous).unwrap_err();
            assert!(error.contains("\"school\", \"calendar\""), "{error}");
        }
        let colliding = vec!["Work".to_owned(), "work".to_owned()];
        assert_eq!(
            resolve_id_argument("account", "Work", &colliding),
            Ok("Work".to_owned())
        );
        assert!(resolve_id_argument("account", "WORK", &colliding).is_err());
    }
}
