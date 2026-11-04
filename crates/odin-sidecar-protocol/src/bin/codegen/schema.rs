//! Emits the JSON Schema document and validates the emitted graph against the model.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::json::{json, json_file, JsonMap, JsonValue, ToJson};
use crate::model::{
    Direction, FieldSpec, FieldType, MessageSpec, Model, ARGUMENT_MAX_ARRAY_ITEMS,
    ARGUMENT_MAX_DEPTH, ARGUMENT_MAX_KEY_CODE_POINTS, ARGUMENT_MAX_OBJECT_PROPERTIES,
    ARGUMENT_MAX_STRING_CODE_POINTS, DETAIL_MAX_CODE_POINTS, JS_SAFE_INTEGER_MAX, MAX_FRAME_BYTES,
    MAX_REQUEST_BYTES, U64_MAX_DECIMAL,
};

pub(crate) fn render_schema(model: &Model) -> Result<String, String> {
    let mut definitions = JsonMap::new();
    let u64_pattern = u64_decimal_pattern();
    definitions.insert("u64".to_string(), json!({
        "type":"string",
        "minLength":1,
        "maxLength":20,
        "pattern":(u64_pattern),
        "description":"Canonical unsigned decimal in 0..=18446744073709551615; never a JSON number."
    }));
    definitions.insert(
        "safe_id_128".to_string(),
        json!({
            "type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+(?![\\s\\S])"
        }),
    );
    definitions.insert(
        "correlation_id".to_string(),
        json!({
            "type":"string","pattern":"^[0-9a-f]{32}(?![\\s\\S])"
        }),
    );
    definitions.insert(
        "digest".to_string(),
        json!({
            "type":"string","pattern":"^[0-9a-f]{64}(?![\\s\\S])"
        }),
    );
    definitions.insert(
        "unit_name".to_string(),
        json!({
            "type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_.:@-]+(?![\\s\\S])"
        }),
    );
    definitions.insert(
        "cgroup_path".to_string(),
        json!({
            "type":"string",
            "minLength":2,
            "maxLength":4096,
            "pattern":"^/[A-Za-z0-9_.:@-]+(?:/[A-Za-z0-9_.:@-]+)*(?![\\s\\S])",
            "not":{"pattern":"(?:^|/)\\.{1,2}(?:/|$)"}
        }),
    );
    definitions.insert(
        "rejection_code".to_string(),
        json!({
            "type":"string","minLength":1,"maxLength":128,"pattern":"^[a-z][a-z0-9._-]*(?![\\s\\S])"
        }),
    );
    definitions.insert(
        "detail".to_string(),
        json!({
            "type":"string","minLength":1,"maxLength":DETAIL_MAX_CODE_POINTS
        }),
    );
    for depth in 0..=ARGUMENT_MAX_DEPTH {
        definitions.insert(argument_definition_name(depth), argument_schema(depth));
    }
    for enumeration in &model.string_enums {
        let values = enumeration
            .variants
            .iter()
            .map(|(_, wire)| *wire)
            .collect::<Vec<_>>();
        definitions.insert(
            enumeration.rust_name.to_string(),
            json!({"type":"string","enum":(values)}),
        );
    }
    for structure in &model.structures {
        definitions.insert(
            structure.rust_name.to_string(),
            strict_object_schema(&structure.fields, None),
        );
    }
    let evidence_variants = model
        .evidence
        .variants
        .iter()
        .map(|variant| strict_object_schema(&variant.fields, Some(variant.kind)))
        .collect::<Vec<_>>();
    definitions.insert(
        model.evidence.rust_name.to_string(),
        json!({"oneOf":(evidence_variants)}),
    );
    for message in &model.messages {
        definitions.insert(message.rust_name.to_string(), message_schema(message));
    }
    for direction in [Direction::Request, Direction::Response] {
        let variants = model
            .messages
            .iter()
            .filter(|message| message.direction == direction)
            .map(|message| {
                let reference = format!("#/$defs/{}", message.rust_name);
                json!({"$ref":(reference)})
            })
            .collect::<Vec<_>>();
        definitions.insert(direction.as_str().to_string(), json!({"oneOf":(variants)}));
    }
    let schema = json!({
        "$schema":"https://json-schema.org/draft/2020-12/schema",
        "$id":"https://odin.local/schemas/authority/odin-authority-wire-v2.schema.json",
        "title":"Odin authority wire v2",
        "description":"A canonical strict-JSON message preceded by a bounded four-byte big-endian unsigned payload length. Zero, partial, over-ceiling, noncanonical, unknown, and v1 payloads are rejected.",
        "oneOf":[{"$ref":"#/$defs/request"},{"$ref":"#/$defs/response"}],
        "$defs":definitions,
        "x-odin-framing":{
            "length_bytes":4,
            "byte_order":"big_endian",
            "zero_length":"forbidden",
            "request_ceiling_bytes":MAX_REQUEST_BYTES,
            "frame_ceiling_bytes":MAX_FRAME_BYTES
        }
    });
    validate_schema_graph(model, &schema)?;
    json_file(&schema)
}

fn u64_decimal_pattern() -> String {
    let digits = U64_MAX_DECIMAL.as_bytes();
    let mut alternatives = vec!["0".to_string(), "[1-9][0-9]{0,18}".to_string()];
    for (index, digit) in digits.iter().enumerate() {
        let maximum_digit = digit - b'0';
        let minimum_digit = if index == 0 { 1 } else { 0 };
        if maximum_digit <= minimum_digit {
            continue;
        }
        let mut alternative = U64_MAX_DECIMAL[..index].to_string();
        let high = maximum_digit - 1;
        if minimum_digit == high {
            alternative.push(char::from(b'0' + minimum_digit));
        } else {
            write!(alternative, "[{minimum_digit}-{high}]").expect("String write cannot fail");
        }
        let remaining = digits.len() - index - 1;
        match remaining {
            0 => {}
            1 => alternative.push_str("[0-9]"),
            _ => write!(alternative, "[0-9]{{{remaining}}}").expect("String write cannot fail"),
        }
        alternatives.push(alternative);
    }
    alternatives.push(U64_MAX_DECIMAL.to_string());
    format!("^(?:{})(?![\\s\\S])", alternatives.join("|"))
}

fn argument_definition_name(depth: usize) -> String {
    if depth == 0 {
        "argument".to_string()
    } else {
        format!("argument_{depth}")
    }
}

fn argument_schema(depth: usize) -> JsonValue {
    let mut alternatives = vec![
        json!({"type":"null"}),
        json!({"type":"boolean"}),
        json!({"type":"string","maxLength":ARGUMENT_MAX_STRING_CODE_POINTS}),
        json!({"type":"integer","minimum":(-JS_SAFE_INTEGER_MAX),"maximum":JS_SAFE_INTEGER_MAX}),
    ];
    if depth < ARGUMENT_MAX_DEPTH {
        let next = format!("#/$defs/{}", argument_definition_name(depth + 1));
        alternatives.push(json!({
            "type":"array",
            "maxItems":ARGUMENT_MAX_ARRAY_ITEMS,
            "items":{"$ref":(next.clone())}
        }));
        alternatives.push(json!({
            "type":"object",
            "maxProperties":ARGUMENT_MAX_OBJECT_PROPERTIES,
            "propertyNames":{
                "type":"string",
                "minLength":1,
                "maxLength":ARGUMENT_MAX_KEY_CODE_POINTS
            },
            "additionalProperties":{"$ref":(next)}
        }));
    }
    let mut schema = JsonMap::new();
    schema.insert("oneOf".to_string(), JsonValue::Array(alternatives));
    if depth == 0 {
        schema.insert(
            "description".to_string(),
            JsonValue::String(
                "Opaque strict JSON capability arguments; maximum nesting depth 32, arrays at 1024 items, objects at 256 properties, keys at 256 Unicode code points, strings at 65536 Unicode code points, and integers in the JavaScript-safe range."
                    .to_string(),
            ),
        );
    }
    JsonValue::Object(schema)
}

fn validate_schema_graph(model: &Model, schema: &JsonValue) -> Result<(), String> {
    let root = schema
        .as_object()
        .ok_or_else(|| "authority-wire schema root is not an object".to_string())?;
    if schema_string_field(root, "$schema", "schema root")?
        != "https://json-schema.org/draft/2020-12/schema"
    {
        return Err("authority-wire schema draft is not 2020-12".to_string());
    }
    if schema_string_field(root, "$id", "schema root")?
        != "https://odin.local/schemas/authority/odin-authority-wire-v2.schema.json"
    {
        return Err("authority-wire schema ID drifted".to_string());
    }

    let definitions = schema_object_field(root, "$defs", "schema root")?;
    let mut expected_definitions = [
        "cgroup_path",
        "correlation_id",
        "detail",
        "digest",
        "rejection_code",
        "request",
        "response",
        "safe_id_128",
        "u64",
        "unit_name",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    for depth in 0..=ARGUMENT_MAX_DEPTH {
        let name = argument_definition_name(depth);
        if !expected_definitions.insert(name.clone()) {
            return Err(format!("schema definition name {name} collides"));
        }
    }
    for name in model
        .structures
        .iter()
        .map(|structure| structure.rust_name)
        .chain(std::iter::once(model.evidence.rust_name))
        .chain(
            model
                .string_enums
                .iter()
                .map(|enumeration| enumeration.rust_name),
        )
        .chain(model.messages.iter().map(|message| message.rust_name))
    {
        if !expected_definitions.insert(name.to_string()) {
            return Err(format!("schema definition name {name} collides"));
        }
    }
    let actual_definitions = definitions.keys().cloned().collect::<BTreeSet<_>>();
    if actual_definitions != expected_definitions {
        return Err(format!(
            "whole schema definition set differs: {actual_definitions:?} != {expected_definitions:?}"
        ));
    }

    let root_targets = schema_ref_union("schema root", schema)?;
    let expected_root_targets = BTreeSet::from(["request".to_string(), "response".to_string()]);
    if root_targets != expected_root_targets {
        return Err(format!(
            "schema root must select request or response: {root_targets:?}"
        ));
    }
    for direction in [Direction::Request, Direction::Response] {
        let union = schema_field(definitions, direction.as_str(), "$defs")?;
        let actual = schema_ref_union(direction.as_str(), union)?;
        let expected = model
            .messages
            .iter()
            .filter(|message| message.direction == direction)
            .map(|message| message.rust_name.to_string())
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(format!(
                "{} schema union differs: {actual:?} != {expected:?}",
                direction.as_str()
            ));
        }
    }

    for structure in &model.structures {
        validate_strict_schema_object(
            structure.rust_name,
            schema_field(definitions, structure.rust_name, "$defs")?,
            &structure.fields,
            None,
            false,
        )?;
    }
    for message in &model.messages {
        validate_strict_schema_object(
            message.rust_name,
            schema_field(definitions, message.rust_name, "$defs")?,
            &message.fields,
            Some(message.kind),
            true,
        )?;
    }

    let evidence_schema = schema_field(definitions, model.evidence.rust_name, "$defs")?;
    let evidence_object = evidence_schema
        .as_object()
        .ok_or_else(|| "Evidence schema is not an object".to_string())?;
    let evidence_variants = schema_array_field(evidence_object, "oneOf", "Evidence schema")?;
    if evidence_variants.len() != model.evidence.variants.len() {
        return Err("Evidence schema variant count differs from the model".to_string());
    }
    let mut evidence_kinds = BTreeSet::new();
    for variant_schema in evidence_variants {
        let variant_object = variant_schema
            .as_object()
            .ok_or_else(|| "Evidence variant schema is not an object".to_string())?;
        let properties = schema_object_field(variant_object, "properties", "Evidence variant")?;
        let kind_schema = schema_object_field(properties, "kind", "Evidence properties")?;
        let kind = schema_string_field(kind_schema, "const", "Evidence.kind")?;
        if !evidence_kinds.insert(kind) {
            return Err(format!("Evidence schema repeats kind {kind}"));
        }
        let variant = model
            .evidence
            .variants
            .iter()
            .find(|variant| variant.kind == kind)
            .ok_or_else(|| format!("Evidence schema has unknown kind {kind}"))?;
        validate_strict_schema_object(
            &format!("Evidence.{kind}"),
            variant_schema,
            &variant.fields,
            Some(kind),
            false,
        )?;
    }
    let expected_evidence = model
        .evidence
        .variants
        .iter()
        .map(|variant| variant.kind)
        .collect::<BTreeSet<_>>();
    if evidence_kinds != expected_evidence {
        return Err("Evidence schema does not cover every model variant".to_string());
    }

    for enumeration in &model.string_enums {
        let definition = schema_object_field(definitions, enumeration.rust_name, "$defs")?;
        if schema_string_field(definition, "type", enumeration.rust_name)? != "string" {
            return Err(format!(
                "{} schema is not a string enum",
                enumeration.rust_name
            ));
        }
        let values = schema_array_field(definition, "enum", enumeration.rust_name)?;
        let mut actual = BTreeSet::new();
        for value in values {
            let value = value
                .as_str()
                .ok_or_else(|| format!("{} enum contains non-string", enumeration.rust_name))?;
            if !actual.insert(value) {
                return Err(format!(
                    "{} schema repeats enum value {value}",
                    enumeration.rust_name
                ));
            }
        }
        let expected = enumeration
            .variants
            .iter()
            .map(|(_, wire)| *wire)
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(format!(
                "{} schema enum values differ from the model",
                enumeration.rust_name
            ));
        }
    }

    validate_u64_schema(definitions)?;
    validate_identifier_schemas(definitions)?;
    validate_text_limit_schemas(definitions)?;
    validate_argument_schema(definitions)?;
    validate_schema_metadata(root)?;

    let mut reachable = BTreeSet::new();
    let mut pending = root_targets.into_iter().collect::<Vec<_>>();
    while let Some(name) = pending.pop() {
        if !reachable.insert(name.clone()) {
            continue;
        }
        let definition = definitions
            .get(&name)
            .ok_or_else(|| format!("schema reference #/$defs/{name} is unresolved"))?;
        let mut references = BTreeSet::new();
        collect_schema_refs(&format!("#/$defs/{name}"), definition, &mut references)?;
        for reference in references {
            if !definitions.contains_key(&reference) {
                return Err(format!(
                    "schema reference #/$defs/{reference} is unresolved"
                ));
            }
            if !reachable.contains(&reference) {
                pending.push(reference);
            }
        }
    }
    if reachable != actual_definitions {
        return Err(format!(
            "whole schema has unreachable definitions: {:?}",
            actual_definitions
                .difference(&reachable)
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}

fn validate_strict_schema_object(
    owner: &str,
    schema: &JsonValue,
    fields: &[FieldSpec],
    kind: Option<&str>,
    message: bool,
) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{owner} schema is not an object"))?;
    if schema_string_field(object, "type", owner)? != "object" {
        return Err(format!("{owner} schema type is not object"));
    }
    if object.get("additionalProperties") != Some(&JsonValue::Bool(false)) {
        return Err(format!("{owner} schema does not deny unknown fields"));
    }
    let properties = schema_object_field(object, "properties", owner)?;
    let mut expected = fields
        .iter()
        .map(|field| field.name.to_string())
        .collect::<BTreeSet<_>>();
    if kind.is_some() {
        expected.insert("kind".to_string());
    }
    if message {
        expected.insert("wire".to_string());
    }
    let actual = properties.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{owner} schema properties differ: {actual:?} != {expected:?}"
        ));
    }

    let required_values = schema_array_field(object, "required", owner)?;
    let mut required = BTreeSet::new();
    for value in required_values {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{owner} required entry is not a string"))?;
        if !required.insert(value.to_string()) {
            return Err(format!("{owner} schema repeats required field {value}"));
        }
    }
    if required != expected {
        return Err(format!(
            "{owner} required fields differ: {required:?} != {expected:?}"
        ));
    }

    if let Some(kind) = kind {
        let kind_schema = schema_object_field(properties, "kind", owner)?;
        if schema_string_field(kind_schema, "const", owner)? != kind {
            return Err(format!("{owner} schema kind discriminator drifted"));
        }
    }
    if message {
        let wire_schema = schema_object_field(properties, "wire", owner)?;
        if schema_integer_field(wire_schema, "const", owner)? != 2 {
            return Err(format!(
                "{owner} schema wire discriminator is not integer 2"
            ));
        }
    }
    Ok(())
}

fn validate_u64_schema(definitions: &JsonMap) -> Result<(), String> {
    let schema = schema_object_field(definitions, "u64", "$defs")?;
    let expected_pattern = u64_decimal_pattern();
    if schema_string_field(schema, "type", "u64")? != "string"
        || schema_integer_field(schema, "minLength", "u64")? != 1
        || schema_integer_field(schema, "maxLength", "u64")? != 20
        || schema_string_field(schema, "pattern", "u64")? != expected_pattern.as_str()
    {
        return Err("u64 schema is not the complete bounded decimal-string contract".to_string());
    }
    Ok(())
}

fn validate_identifier_schemas(definitions: &JsonMap) -> Result<(), String> {
    let patterns: [(&str, &str, Option<i64>, Option<i64>); 6] = [
        (
            "safe_id_128",
            "^[A-Za-z0-9._:-]+(?![\\s\\S])",
            Some(1),
            Some(128),
        ),
        ("correlation_id", "^[0-9a-f]{32}(?![\\s\\S])", None, None),
        ("digest", "^[0-9a-f]{64}(?![\\s\\S])", None, None),
        (
            "unit_name",
            "^[A-Za-z0-9_.:@-]+(?![\\s\\S])",
            Some(1),
            Some(256),
        ),
        (
            "cgroup_path",
            "^/[A-Za-z0-9_.:@-]+(?:/[A-Za-z0-9_.:@-]+)*(?![\\s\\S])",
            Some(2),
            Some(4_096),
        ),
        (
            "rejection_code",
            "^[a-z][a-z0-9._-]*(?![\\s\\S])",
            Some(1),
            Some(128),
        ),
    ];
    for (name, pattern, minimum, maximum) in patterns {
        let schema = schema_object_field(definitions, name, "$defs")?;
        if schema_string_field(schema, "type", name)? != "string"
            || schema_string_field(schema, "pattern", name)? != pattern
        {
            return Err(format!("{name} schema pattern drifted"));
        }
        if let Some(minimum) = minimum {
            if schema_integer_field(schema, "minLength", name)? != minimum {
                return Err(format!("{name} schema minimum length drifted"));
            }
        }
        if let Some(maximum) = maximum {
            if schema_integer_field(schema, "maxLength", name)? != maximum {
                return Err(format!("{name} schema maximum length drifted"));
            }
        }
    }
    let cgroup = schema_object_field(definitions, "cgroup_path", "$defs")?;
    let cgroup_not = schema_object_field(cgroup, "not", "cgroup_path")?;
    if schema_string_field(cgroup_not, "pattern", "cgroup_path.not")? != "(?:^|/)\\.{1,2}(?:/|$)" {
        return Err("cgroup path dot-segment exclusion drifted".to_string());
    }
    Ok(())
}

fn validate_text_limit_schemas(definitions: &JsonMap) -> Result<(), String> {
    let detail = schema_object_field(definitions, "detail", "$defs")?;
    if schema_string_field(detail, "type", "detail")? != "string"
        || schema_integer_field(detail, "minLength", "detail")? != 1
        || schema_integer_field(detail, "maxLength", "detail")?
            != i64::try_from(DETAIL_MAX_CODE_POINTS).expect("detail ceiling fits i64")
        || detail.contains_key("x-odin-max-utf8-bytes")
    {
        return Err("detail schema Unicode code-point limits drifted".to_string());
    }
    Ok(())
}

fn validate_argument_schema(definitions: &JsonMap) -> Result<(), String> {
    let string_ceiling =
        i64::try_from(ARGUMENT_MAX_STRING_CODE_POINTS).expect("argument string ceiling fits i64");
    let key_ceiling =
        i64::try_from(ARGUMENT_MAX_KEY_CODE_POINTS).expect("argument key ceiling fits i64");
    let array_ceiling =
        i64::try_from(ARGUMENT_MAX_ARRAY_ITEMS).expect("argument array ceiling fits i64");
    let object_ceiling =
        i64::try_from(ARGUMENT_MAX_OBJECT_PROPERTIES).expect("argument object ceiling fits i64");

    for depth in 0..=ARGUMENT_MAX_DEPTH {
        let name = argument_definition_name(depth);
        let schema = schema_object_field(definitions, &name, "$defs")?;
        if schema.contains_key("x-odin-utf8-byte-limits") {
            return Err(format!(
                "{name} contains a non-enforceable UTF-8 byte annotation"
            ));
        }
        let alternatives = schema_array_field(schema, "oneOf", &name)?;
        let mut branches = BTreeMap::new();
        for alternative in alternatives {
            let object = alternative
                .as_object()
                .ok_or_else(|| format!("{name} alternative is not an object"))?;
            let kind = schema_string_field(object, "type", &name)?;
            if branches.insert(kind, object).is_some() {
                return Err(format!("{name} repeats type {kind}"));
            }
        }
        let mut expected = BTreeSet::from(["boolean", "integer", "null", "string"]);
        if depth < ARGUMENT_MAX_DEPTH {
            expected.insert("array");
            expected.insert("object");
        }
        if branches.keys().copied().collect::<BTreeSet<_>>() != expected {
            return Err(format!(
                "{name} schema does not encode the exact depth-{depth} JSON domain"
            ));
        }

        let string = branches
            .get("string")
            .ok_or_else(|| format!("{name} string branch is missing"))?;
        if schema_integer_field(string, "maxLength", &name)? != string_ceiling
            || string.contains_key("x-odin-max-utf8-bytes")
        {
            return Err(format!("{name} string code-point ceiling drifted"));
        }
        let integer = branches
            .get("integer")
            .ok_or_else(|| format!("{name} integer branch is missing"))?;
        if schema_integer_field(integer, "minimum", &name)? != -JS_SAFE_INTEGER_MAX
            || schema_integer_field(integer, "maximum", &name)? != JS_SAFE_INTEGER_MAX
        {
            return Err(format!("{name} integer range is not JavaScript-lossless"));
        }
        if depth == ARGUMENT_MAX_DEPTH {
            continue;
        }

        let next = argument_definition_name(depth + 1);
        let array = branches
            .get("array")
            .ok_or_else(|| format!("{name} array branch is missing"))?;
        if schema_integer_field(array, "maxItems", &name)? != array_ceiling
            || local_ref_target(
                &format!("{name} array items"),
                schema_field(array, "items", &name)?,
            )? != next.as_str()
        {
            return Err(format!(
                "{name} array bounds or next-depth reference drifted"
            ));
        }
        let object = branches
            .get("object")
            .ok_or_else(|| format!("{name} object branch is missing"))?;
        if schema_integer_field(object, "maxProperties", &name)? != object_ceiling
            || local_ref_target(
                &format!("{name} object values"),
                schema_field(object, "additionalProperties", &name)?,
            )? != next.as_str()
        {
            return Err(format!(
                "{name} object bounds or next-depth reference drifted"
            ));
        }
        let property_names = schema_object_field(object, "propertyNames", &name)?;
        if schema_string_field(property_names, "type", &name)? != "string"
            || schema_integer_field(property_names, "minLength", &name)? != 1
            || schema_integer_field(property_names, "maxLength", &name)? != key_ceiling
            || property_names.contains_key("x-odin-max-utf8-bytes")
        {
            return Err(format!("{name} property-name code-point bounds drifted"));
        }
    }
    Ok(())
}

fn validate_schema_metadata(root: &JsonMap) -> Result<(), String> {
    let framing = schema_object_field(root, "x-odin-framing", "schema root")?;
    if schema_integer_field(framing, "length_bytes", "framing")? != 4
        || schema_string_field(framing, "byte_order", "framing")? != "big_endian"
        || schema_string_field(framing, "zero_length", "framing")? != "forbidden"
        || schema_integer_field(framing, "request_ceiling_bytes", "framing")?
            != i64::try_from(MAX_REQUEST_BYTES).expect("request ceiling fits i64")
        || schema_integer_field(framing, "frame_ceiling_bytes", "framing")?
            != i64::try_from(MAX_FRAME_BYTES).expect("frame ceiling fits i64")
    {
        return Err("four-byte framing schema metadata drifted".to_string());
    }
    if root.contains_key("x-odin-utf8-byte-limits") {
        return Err(
            "schema advertises an unenforceable per-field UTF-8 byte vocabulary".to_string(),
        );
    }
    Ok(())
}

fn schema_ref_union(owner: &str, schema: &JsonValue) -> Result<BTreeSet<String>, String> {
    let object = schema
        .as_object()
        .ok_or_else(|| format!("{owner} union is not an object"))?;
    let alternatives = schema_array_field(object, "oneOf", owner)?;
    if alternatives.is_empty() {
        return Err(format!("{owner} union is empty"));
    }
    let mut targets = BTreeSet::new();
    for alternative in alternatives {
        let target = local_ref_target(owner, alternative)?;
        if !targets.insert(target.clone()) {
            return Err(format!("{owner} union repeats #/$defs/{target}"));
        }
    }
    Ok(targets)
}

fn collect_schema_refs(
    owner: &str,
    value: &JsonValue,
    targets: &mut BTreeSet<String>,
) -> Result<(), String> {
    match value {
        JsonValue::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_schema_refs(&format!("{owner}[{index}]"), value, targets)?;
            }
        }
        JsonValue::Object(object) => {
            if object.contains_key("$ref") {
                targets.insert(local_ref_target(owner, value)?);
                return Ok(());
            }
            for (name, value) in object {
                collect_schema_refs(&format!("{owner}.{name}"), value, targets)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn local_ref_target(owner: &str, value: &JsonValue) -> Result<String, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{owner} reference is not an object"))?;
    if object.len() != 1 {
        return Err(format!("{owner} reference has sibling keywords"));
    }
    let reference = schema_string_field(object, "$ref", owner)?;
    let target = reference
        .strip_prefix("#/$defs/")
        .filter(|target| !target.is_empty() && !target.contains('/'))
        .ok_or_else(|| format!("{owner} has non-local reference {reference}"))?;
    Ok(target.to_string())
}

fn schema_field<'a>(object: &'a JsonMap, name: &str, owner: &str) -> Result<&'a JsonValue, String> {
    object
        .get(name)
        .ok_or_else(|| format!("{owner} is missing {name}"))
}

fn schema_object_field<'a>(
    object: &'a JsonMap,
    name: &str,
    owner: &str,
) -> Result<&'a JsonMap, String> {
    schema_field(object, name, owner)?
        .as_object()
        .ok_or_else(|| format!("{owner}.{name} is not an object"))
}

fn schema_array_field<'a>(
    object: &'a JsonMap,
    name: &str,
    owner: &str,
) -> Result<&'a [JsonValue], String> {
    schema_field(object, name, owner)?
        .as_array()
        .ok_or_else(|| format!("{owner}.{name} is not an array"))
}

fn schema_string_field<'a>(
    object: &'a JsonMap,
    name: &str,
    owner: &str,
) -> Result<&'a str, String> {
    schema_field(object, name, owner)?
        .as_str()
        .ok_or_else(|| format!("{owner}.{name} is not a string"))
}

fn schema_integer_field(object: &JsonMap, name: &str, owner: &str) -> Result<i64, String> {
    schema_field(object, name, owner)?
        .as_i64()
        .ok_or_else(|| format!("{owner}.{name} is not an integer"))
}

fn strict_object_schema(fields: &[FieldSpec], kind: Option<&str>) -> JsonValue {
    let mut properties = JsonMap::new();
    let mut required = Vec::new();
    if let Some(kind) = kind {
        properties.insert("kind".to_string(), json!({"const":kind}));
        required.push(JsonValue::String("kind".to_string()));
    }
    for field in fields {
        properties.insert(field.name.to_string(), field_schema(&field.ty));
        required.push(JsonValue::String(field.name.to_string()));
    }
    json!({
        "type":"object",
        "additionalProperties":false,
        "properties":properties,
        "required":required
    })
}

fn message_schema(message: &MessageSpec) -> JsonValue {
    let mut properties = JsonMap::new();
    properties.insert("kind".to_string(), json!({"const":(message.kind)}));
    properties.insert("wire".to_string(), json!({"const":2}));
    let mut required = vec![
        JsonValue::String("kind".to_string()),
        JsonValue::String("wire".to_string()),
    ];
    for field in &message.fields {
        properties.insert(field.name.to_string(), field_schema(&field.ty));
        required.push(JsonValue::String(field.name.to_string()));
    }
    json!({
        "type":"object",
        "additionalProperties":false,
        "properties":properties,
        "required":required
    })
}

fn field_schema(field_type: &FieldType) -> JsonValue {
    let reference = |name: &str| {
        let value = format!("#/$defs/{name}");
        json!({"$ref":value})
    };
    match field_type {
        FieldType::Arguments => reference("argument"),
        FieldType::Bool => json!({"type":"boolean"}),
        FieldType::Budget => reference("Budget"),
        FieldType::CapsuleId | FieldType::OperationId | FieldType::ToolId => {
            reference("safe_id_128")
        }
        FieldType::CgroupPath => reference("cgroup_path"),
        FieldType::CloseMode => reference("CloseMode"),
        FieldType::CorrelationId => reference("correlation_id"),
        FieldType::Detail => reference("detail"),
        FieldType::Digest => reference("digest"),
        FieldType::Evidence => reference("Evidence"),
        FieldType::I32 => {
            let minimum = i32::MIN;
            let maximum = i32::MAX;
            json!({"type":"integer","minimum":minimum,"maximum":maximum})
        }
        FieldType::NullableOperationId => {
            let operation_id = reference("safe_id_128");
            json!({"oneOf":[(operation_id),{"type":"null"}]})
        }
        FieldType::OperationState => reference("OperationState"),
        FieldType::RejectionCode => reference("rejection_code"),
        FieldType::StopState => reference("StopState"),
        FieldType::U64 => reference("u64"),
        FieldType::UnitName => reference("unit_name"),
    }
}
