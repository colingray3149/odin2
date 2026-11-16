//! Calls as models write them, read as the call they meant. A field in the wrong place, a synonym
//! for the schema's own name, an extra field on a read, a bare file name for a path the schema roots in
//! one directory, or a required field with one declared default is not worth a round trip. A wrong
//! value still is, and the error says which field and what a good call looks like.
use serde_json::{json, Map, Value};

use odin_registry::listing::SYNONYMS;

/// The result field naming the fields a read dropped, so the model learns the real shape.
pub const IGNORED_FIELDS: &str = "ignored_fields";

/// The member's payload from a call's arguments, and the fields dropped on the way. `op` and the help
/// target are envelope; `args` and top-level fields are one bag, so an on-demand call and an inline one
/// mean the same; a synonym takes the schema's spelling; a path the schema roots in a directory takes
/// it; a required field with a declared `default` is filled; and a field `shed` names (a read's
/// field that another op of its toolset declares) is dropped. Any other undeclared field stays, so
/// `unknown` refuses it by name and nothing runs on a guess, except where the schema pairs an
/// `action` with its `arguments` (the browser's): a field outside them is that action's argument.
pub(super) fn payload(
    schema: &Value,
    shed: impl Fn(&str) -> bool,
    arguments: Value,
) -> (Value, Vec<String>) {
    let Value::Object(mut fields) = arguments else {
        return (arguments, Vec::new());
    };
    let properties = schema.get("properties").and_then(Value::as_object);
    let declares = |field: &str| properties.is_some_and(|declared| declared.contains_key(field));
    for envelope in ["op", "operation"] {
        if !declares(envelope) {
            fields.remove(envelope);
        }
    }
    if !declares("args") {
        match fields.remove("args") {
            Some(Value::Object(wrapped)) => {
                for (field, value) in wrapped {
                    fields.entry(field).or_insert(value);
                }
            }
            Some(Value::Null) | None => {}
            // Arguments a strict-schema model wrote as JSON text.
            Some(Value::String(text)) if text.trim().is_empty() => {}
            Some(Value::String(text)) => match serde_json::from_str(&text) {
                Ok(Value::Object(wrapped)) => {
                    for (field, value) in wrapped {
                        fields.entry(field).or_insert(value);
                    }
                }
                _ => {
                    fields.insert("args".into(), Value::String(text));
                }
            },
            // Not an object: the validator names it.
            Some(other) => {
                fields.insert("args".into(), other);
            }
        }
    }
    let mut ignored = Vec::new();
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
    if let (Some(properties), true) = (properties, closed) {
        let acts = properties.contains_key("action")
            && properties
                .get("arguments")
                .and_then(|arguments| arguments.get("type"))
                == Some(&json!("object"));
        let stray: Vec<String> = fields
            .keys()
            .filter(|field| !properties.contains_key(*field))
            .cloned()
            .collect();
        for field in stray {
            if fields[&field].is_null() || (!acts && empty(&fields[&field])) {
                // A null, or the empty value a strict lane fills every field of the toolset's
                // union with ("", "null", 0, false, [], {}), names nothing; an action's own
                // arguments (a scroll's deltaX of 0) still mean what they say.
                fields.remove(&field);
            } else if let Some(spelling) = synonym(&field, properties, &fields) {
                if let Some(value) = fields.remove(&field) {
                    fields.insert(spelling.to_owned(), value);
                }
            } else if acts {
                if let Some(value) = fields.remove(&field) {
                    let arguments = fields.entry("arguments").or_insert(Value::Null);
                    if arguments.is_null() {
                        *arguments = json!({});
                    }
                    if let Some(arguments) = arguments.as_object_mut() {
                        arguments.entry(field).or_insert(value);
                    }
                }
            } else if shed(&field) {
                fields.remove(&field);
                ignored.push(field);
            }
        }
    }
    for (name, property) in properties.into_iter().flatten() {
        let (Some(root), Some(Value::String(path))) = (rooted(property), fields.get_mut(name))
        else {
            continue;
        };
        if !path.starts_with('/') {
            let bare = path.trim_start_matches("./");
            *path = format!("{root}{}", bare.strip_prefix(&root[1..]).unwrap_or(bare));
        }
    }
    for name in required(schema) {
        let default = properties
            .and_then(|declared| declared.get(name))
            .and_then(|property| property.get("default"));
        // A strict lane sends every field of the toolset's union, null where it has nothing to say.
        if let (true, Some(default)) = (fields.get(name).is_none_or(Value::is_null), default) {
            fields.insert(name.to_owned(), default.clone());
        }
    }
    (Value::Object(fields), ignored)
}

/// Refuses the fields a closed schema does not declare, naming them and the fields the model may
/// give; host-filled (`readOnly`) fields are declared, so a call may carry them, but are not listed.
pub(super) fn unknown(schema: &Value, arguments: &Value) -> Result<(), String> {
    let (Some(properties), Some(fields)) = (
        schema.get("properties").and_then(Value::as_object),
        arguments.as_object(),
    ) else {
        return Ok(());
    };
    if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Ok(());
    }
    let stray: Vec<&str> = fields
        .keys()
        .filter(|field| !properties.contains_key(*field))
        .map(String::as_str)
        .collect();
    if stray.is_empty() {
        return Ok(());
    }
    let allowed: Vec<&str> = properties
        .iter()
        .filter(|(_, property)| property.get("readOnly") != Some(&Value::Bool(true)))
        .map(|(name, _)| name.as_str())
        .collect();
    Err(format!(
        "unknown field {}; the fields are {}",
        stray.join(", "),
        allowed.join(", ")
    ))
}

/// A value that says nothing: what a model writes for a field it has nothing to put in.
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty() || text == "null",
        Value::Array(items) => items.is_empty(),
        Value::Object(fields) => fields.is_empty(),
    }
}

/// The directory a path property's pattern roots it in: `^/export/[A-Za-z0-9]...` is `/export/`.
fn rooted(property: &Value) -> Option<&str> {
    let pattern = property.get("pattern")?.as_str()?.strip_prefix('^')?;
    let root = &pattern[..pattern.find('[')?];
    (root.len() > 1 && root.starts_with('/') && root.ends_with('/')).then_some(root)
}

/// The schema's own spelling of `field`: a synonym it declares and the call has not filled.
fn synonym(
    field: &str,
    properties: &Map<String, Value>,
    fields: &Map<String, Value>,
) -> Option<&'static str> {
    SYNONYMS
        .iter()
        .filter(|group| group.contains(&field))
        .flat_map(|group| group.iter().copied())
        .find(|other| properties.contains_key(*other) && !fields.contains_key(*other))
}

fn required(schema: &Value) -> impl Iterator<Item = &str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// One call that satisfies the schema's required fields, for an error to show beside the bad field.
/// A good call for `op`: its required fields inside `args` as JSON text, the one form every provider
/// can send.
pub(super) fn example(tool: &str, op: &str, schema: &Value) -> String {
    let mut fields = Map::new();
    for name in required(schema).filter(|name| *name != "op") {
        let property = schema.pointer(&format!("/properties/{name}"));
        // Host-filled fields are not the model's to give.
        if property.and_then(|property| property.get("readOnly")) != Some(&Value::Bool(true)) {
            fields.insert(name.to_owned(), placeholder(name, property));
        }
    }
    let mut call = Map::from_iter([("op".to_owned(), json!(op))]);
    if !fields.is_empty() {
        call.insert("args".to_owned(), json!(Value::Object(fields).to_string()));
    }
    format!("{tool} {}", Value::Object(call))
}

/// The canonical schema with the narrowing's required fields added, so an example for a narrowed
/// call names what the narrowing requires too (a projected `project`, for one).
pub(super) fn narrowed(schema: &Value, narrowing: &Value) -> Value {
    let mut merged = schema.clone();
    let mut names: Vec<String> = required(schema).map(str::to_owned).collect();
    for name in required(narrowing) {
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }
    if let Some(object) = merged.as_object_mut() {
        object.insert("required".to_owned(), json!(names));
    }
    // A property only the narrowing declares keeps its shape for the placeholder.
    if let (Some(properties), Some(narrowed)) = (
        merged.get_mut("properties").and_then(Value::as_object_mut),
        narrowing.get("properties").and_then(Value::as_object),
    ) {
        for (name, property) in narrowed {
            properties
                .entry(name.clone())
                .or_insert_with(|| property.clone());
        }
    }
    merged
}

fn placeholder(name: &str, property: Option<&Value>) -> Value {
    let Some(property) = property else {
        return json!(format!("<{name}>"));
    };
    if let Some(first) = property.get("enum").and_then(|values| values.get(0)) {
        return first.clone();
    }
    let kind = match property.get("type") {
        Some(Value::String(kind)) => Some(kind.as_str()),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|k| *k != "null"),
        _ => None,
    };
    match kind {
        Some("integer" | "number") => property.get("minimum").cloned().unwrap_or(json!(1)),
        Some("boolean") => json!(false),
        Some("array") => json!([]),
        Some("object") => json!({}),
        _ => json!(format!("<{name}>")),
    }
}

/// A result with the dropped fields named beside it. A result that is not an object is wrapped.
pub fn with_ignored(mut result: Value, ignored: &[String]) -> Value {
    if ignored.is_empty() {
        return result;
    }
    match result.as_object_mut() {
        Some(object) => {
            object.insert(IGNORED_FIELDS.to_owned(), json!(ignored));
            result
        }
        None => json!({"result": result, IGNORED_FIELDS: ignored}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "0b7f3c2a-1d4e-4f6a-8b9c-0d1e2f3a4b5c";

    fn schema(capability: &str) -> Value {
        let path = format!(
            "{}/../../schemas/capability/{capability}.input.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("the capability schema"))
            .expect("the capability schema parses")
    }

    /// Real shapes models sent: (capability, read-only, what was sent, the payload it means, what a
    /// read dropped).
    #[test]
    fn the_shapes_models_send_mean_the_call_they_meant() {
        let id = format!("blake3:{}", "0".repeat(64));
        let table = [
            // files artifact: `artifact` for artifactId (22 times), and the reverse on send and view.
            (
                "artifact.read",
                true,
                json!({"op":"artifact","artifact":id}),
                json!({"artifactId":id}),
                vec![],
            ),
            // On-demand fields beside `op` (docs.preview pages, desktop.device steps).
            (
                "docs.preview",
                true,
                json!({"op":"preview","artifact":id,"pages":[1]}),
                json!({"artifact":id,"pages":[1]}),
                vec![],
            ),
            (
                "desktop.device",
                false,
                json!({"op":"device","steps":[{"do":"map"}],"device":"pc"}),
                json!({"steps":[{"do":"map"}],"device":"pc"}),
                vec![],
            ),
            // The documented wrapper and a stray field together mean one call.
            (
                "docs.preview",
                true,
                json!({"op":"preview","args":{"artifact":id},"pages":[2]}),
                json!({"artifact":id,"pages":[2]}),
                vec![],
            ),
            // status huginn without kind.
            (
                "huginn.read",
                true,
                json!({"op":"huginn"}),
                json!({"kind":"status"}),
                vec![],
            ),
            // Fields a read has no use for are dropped and named: files.list limit, status.jobs lines.
            (
                "files.list",
                true,
                json!({"op":"list","root":"downloads","limit":50}),
                json!({"root":"downloads"}),
                vec!["limit"],
            ),
            (
                "jobs.list",
                true,
                json!({"op":"jobs","lines":20}),
                json!({}),
                vec!["lines"],
            ),
            // A delegate's prompt instead of question.
            (
                "seat.ask",
                false,
                json!({"op":"ask_gungnir","prompt":"count the vendors","subject":"orders"}),
                json!({"question":"count the vendors","subject":"orders","urgency":"medium"}),
                vec![],
            ),
            // A strict lane's nulls for fields the member never had name nothing, on a write too.
            (
                "artifact.write",
                false,
                json!({"op":"keep","text":"hi","file_name":null}),
                json!({"text":"hi"}),
                vec![],
            ),
        ];
        for (capability, read_only, sent, meant, dropped) in table {
            let (payload, ignored) = payload(&schema(capability), |_| read_only, sent.clone());
            assert_eq!(payload, meant, "{capability} {sent}");
            assert_eq!(ignored, dropped, "{capability} {sent}");
        }
    }

    /// Calls research pods send that their schemas refuse: each means a call the capability accepts.
    #[test]
    fn research_pod_calls_run_as_meant() {
        let table = [
            // research.save with a bare file name, and the `export/` and `./` spellings of the same file.
            (
                "web.save",
                false,
                json!({"op":"save","url":"https://example.com/a","path":"acecare-product.html"}),
                json!({"url":"https://example.com/a","path":"/export/acecare-product.html"}),
                vec![],
            ),
            (
                "web.save",
                false,
                json!({"op":"save","url":"https://example.com/a","path":"export/a.pdf"}),
                json!({"url":"https://example.com/a","path":"/export/a.pdf"}),
                vec![],
            ),
            (
                "web.save",
                false,
                json!({"op":"save","url":"https://example.com/a","path":"./a.pdf"}),
                json!({"url":"https://example.com/a","path":"/export/a.pdf"}),
                vec![],
            ),
            // research.export with the observe op's maxBytes and no offset: the file is read from its
            // start, and maxBytes is named as dropped.
            (
                "export.read",
                true,
                json!({"op":"export","path":"report.md","maxBytes":16000}),
                json!({"path":"/export/report.md","offset":0}),
                vec!["maxBytes"],
            ),
            // The same call from a strict lane, which sends the union's other fields as null.
            (
                "export.read",
                true,
                json!({"op":"export","path":"/export/report.md","offset":null,"maxBytes":null,"url":null}),
                json!({"path":"/export/report.md","offset":0}),
                vec![],
            ),
            // research.interact: each action's fields beside `action`, as the strict surface lists them,
            // with `arguments` empty or null (navigate), or holding some of them (fill).
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"navigate","arguments":{},"url":"https://example.com"}),
                json!({"sessionId":SESSION,"action":"navigate","arguments":{"url":"https://example.com"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"navigate","arguments":null,"url":"https://example.com"}),
                json!({"sessionId":SESSION,"action":"navigate","arguments":{"url":"https://example.com"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"fill","arguments":{"selector":"#q"},"text":"aerogel"}),
                json!({"sessionId":SESSION,"action":"fill","arguments":{"selector":"#q","text":"aerogel"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"fill","arguments":{},"selector":"#q","text":"aerogel"}),
                json!({"sessionId":SESSION,"action":"fill","arguments":{"selector":"#q","text":"aerogel"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"activate","arguments":{},"selector":"a.next"}),
                json!({"sessionId":SESSION,"action":"activate","arguments":{"selector":"a.next"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"submitForm","arguments":{},"selector":"form#search"}),
                json!({"sessionId":SESSION,"action":"submitForm","arguments":{"selector":"form#search"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"pressKey","arguments":{},"key":"Enter"}),
                json!({"sessionId":SESSION,"action":"pressKey","arguments":{"key":"Enter"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":"scroll","arguments":{},"deltaX":0,"deltaY":600}),
                json!({"sessionId":SESSION,"action":"scroll","arguments":{"deltaX":0,"deltaY":600}}),
                vec![],
            ),
            // A strict lane sends every field of the research tool, null where the action has nothing to say.
            (
                "browser.interact",
                false,
                json!({"op":"interact","operation":null,"query":null,"sessionId":SESSION,"expectedRevision":null,"action":"fill","arguments":{},"argumentsDigest":null,"policyRevision":null,"policyDigest":null,"url":null,"selector":"#q","text":"aerogel","key":null,"deltaX":null,"deltaY":null}),
                json!({"sessionId":SESSION,"action":"fill","arguments":{"selector":"#q","text":"aerogel"}}),
                vec![],
            ),
            (
                "browser.interact",
                false,
                json!({"op":"interact","operation":null,"query":null,"sessionId":SESSION,"expectedRevision":null,"action":"pressKey","arguments":{},"argumentsDigest":null,"policyRevision":null,"policyDigest":null,"url":null,"selector":null,"text":null,"key":"Enter","deltaX":null,"deltaY":null}),
                json!({"sessionId":SESSION,"action":"pressKey","arguments":{"key":"Enter"}}),
                vec![],
            ),
        ];
        // The actions that take no arguments keep the empty object, and the other actions' nulls vanish.
        let bare = ["back", "forward", "reload", "screenshot", "close"].map(|action| {
            (
                "browser.interact",
                false,
                json!({"op":"interact","sessionId":SESSION,"action":action,"arguments":{},"url":null,"selector":null,"deltaY":null}),
                json!({"sessionId":SESSION,"action":action,"arguments":{}}),
                vec![],
            )
        });
        for (capability, read_only, sent, meant, dropped) in table.into_iter().chain(bare) {
            let schema = schema(capability);
            let (payload, ignored) = payload(&schema, |_| read_only, sent.clone());
            // A declared optional a strict lane left null goes the way `prepare_tool_call` takes it.
            let payload = crate::host_tools::schema_compat::drop_null_optionals(&schema, payload);
            assert_eq!(payload, meant, "{capability} {sent}");
            assert_eq!(ignored, dropped, "{capability} {sent}");
            let accepted =
                jsonschema::validator_for(&schema).expect("the capability schema compiles");
            assert!(accepted.is_valid(&payload), "{capability} {payload}");
        }
    }

    #[test]
    fn a_write_drops_the_empty_values_a_model_fills_other_operations_fields_with() {
        let schema = json!({"type": "object", "additionalProperties": false,
            "properties": {"runId": {"type": "string"}, "expectedResourceVersion": {"type": "string"}},
            "required": ["runId", "expectedResourceVersion"]});
        let call = json!({"op": "stop", "runId": "r1", "expectedResourceVersion": "7", "count": 0,
            "inputs": [], "limits": {}, "args": "null", "company": "null", "offset": 0});
        let (stopped, _) = payload(&schema, |_| false, call);
        assert_eq!(
            stopped,
            json!({"runId": "r1", "expectedResourceVersion": "7"})
        );
        // A value that says something still reaches the validator, which names it.
        let (kept, _) = payload(
            &schema,
            |_| false,
            json!({"runId": "r1", "expectedResourceVersion": "7", "count": 3}),
        );
        assert_eq!(kept["count"], 3);
    }

    /// knowledge.dig with `case_sensitive` (its field is `case`): no op of the toolset declares it,
    /// so the read keeps it and the refusal names it beside the fields the op takes.
    #[test]
    fn a_read_refuses_a_field_no_op_of_its_toolset_declares() {
        let schema = schema("knowledge.dig");
        let sent = json!({"op":"dig","query":"DoMINO","case_sensitive":true,"limit":0});
        let (kept, ignored) = payload(&schema, |field| field == "maxBytes", sent);
        assert!(ignored.is_empty());
        let refusal = unknown(&schema, &kept).expect_err("an undeclared field is refused");
        assert!(refusal.contains("case_sensitive"), "{refusal}");
        assert!(
            refusal.contains("case") && refusal.contains("query"),
            "{refusal}"
        );
        // A sibling op's field is shed, as before, and what is left passes.
        let (shed, ignored) = payload(
            &schema,
            |field| field == "maxBytes",
            json!({"op":"dig","query":"DoMINO","maxBytes":100}),
        );
        assert_eq!(ignored, vec!["maxBytes"]);
        assert_eq!(unknown(&schema, &shed), Ok(()));
    }

    #[test]
    fn on_demand_arguments_written_as_json_text_are_the_same_call() {
        let schema = schema("artifact.read");
        let (object, _) = super::payload(
            &schema,
            |_| true,
            json!({"op":"artifact","args":{"artifactId":"a1"}}),
        );
        let (text, _) = super::payload(
            &schema,
            |_| true,
            json!({"op":"artifact","args":r#"{"artifactId":"a1"}"#}),
        );
        assert_eq!(text, object);
        assert_eq!(text, json!({"artifactId":"a1"}));
    }

    #[test]
    fn a_missing_project_example_names_project() {
        let canonical = schema("seat.ask");
        assert!(!example("seat", "ask", &canonical).contains("project"));
        let projected = narrowed(&canonical, &json!({"required": ["project"]}));
        assert!(
            example("seat", "ask", &projected).contains(r#"\"project\":\"<project>\""#),
            "{}",
            example("seat", "ask", &projected)
        );
    }

    #[test]
    fn a_refusal_shows_the_ops_arguments_as_json_text() {
        assert_eq!(
            example("files", "artifact", &schema("artifact.read")),
            r#"files {"args":"{\"artifactId\":\"<artifactId>\"}","op":"artifact"}"#
        );
        assert_eq!(
            example("calendar", "now", &schema("time.get_current_time")),
            r#"calendar {"op":"now"}"#
        );
    }
}
