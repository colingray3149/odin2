//! Self-checks every model entry against the frozen wire contract before emission.

use std::collections::{BTreeMap, BTreeSet};

use crate::json::{json, JsonMap, JsonValue, ToJson};
use crate::model::{
    field, Direction, FieldSpec, FieldType, Model, ARGUMENT_MAX_ARRAY_ITEMS, ARGUMENT_MAX_DEPTH,
    ARGUMENT_MAX_KEY_CODE_POINTS, ARGUMENT_MAX_OBJECT_PROPERTIES, ARGUMENT_MAX_STRING_CODE_POINTS,
    DETAIL_MAX_CODE_POINTS, JS_SAFE_INTEGER_MAX, MAX_FRAME_BYTES, MAX_REQUEST_BYTES,
    U64_MAX_DECIMAL,
};

pub(crate) fn validate_model(model: &Model) -> Result<(), String> {
    let expected_requests = BTreeSet::from([
        "close_capsule",
        "invoke_capability",
        "reconcile_operation",
        "resume_operation",
        "stop_intent",
    ]);
    let expected_responses = BTreeSet::from([
        "capability_invoked",
        "capsule_closed",
        "operation_reconciled",
        "operation_resumed",
        "rejected",
        "stop_recorded",
    ]);
    let actual_requests = model
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Request)
        .map(|message| message.kind)
        .collect::<BTreeSet<_>>();
    let actual_responses = model
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Response)
        .map(|message| message.kind)
        .collect::<BTreeSet<_>>();
    if actual_requests != expected_requests {
        return Err(format!(
            "request kinds differ from the frozen WP-05 set: {actual_requests:?}"
        ));
    }
    if actual_responses != expected_responses {
        return Err(format!(
            "response kinds differ from the complete WP-05 set: {actual_responses:?}"
        ));
    }

    let mut kinds = BTreeSet::new();
    let mut rust_names = BTreeSet::new();
    for message in &model.messages {
        if !kinds.insert((message.direction, message.kind)) {
            return Err(format!(
                "duplicate {} kind {}",
                message.direction.as_str(),
                message.kind
            ));
        }
        if !rust_names.insert(message.rust_name) {
            return Err(format!("duplicate Rust message name {}", message.rust_name));
        }
        unique_fields(message.rust_name, &message.fields)?;
        if message
            .fields
            .iter()
            .any(|field| matches!(field.name, "kind" | "wire"))
        {
            return Err(format!(
                "{} uses a reserved discriminator field",
                message.rust_name
            ));
        }
    }

    let mut structure_names = BTreeSet::new();
    for structure in &model.structures {
        if !structure_names.insert(structure.rust_name) {
            return Err(format!(
                "duplicate Rust structure name {}",
                structure.rust_name
            ));
        }
        unique_fields(structure.rust_name, &structure.fields)?;
    }
    if structure_names != BTreeSet::from(["Budget"]) {
        return Err(format!(
            "supporting structures differ from the complete WP-05 set: {structure_names:?}"
        ));
    }

    if model.evidence.rust_name != "Evidence" {
        return Err(format!(
            "evidence enum must be named Evidence, not {}",
            model.evidence.rust_name
        ));
    }
    let expected_evidence = BTreeSet::from(["absent", "cgroup", "durable", "process", "unit"]);
    let mut actual_evidence = BTreeSet::new();
    let mut evidence_rust_names = BTreeSet::new();
    for variant in &model.evidence.variants {
        if !actual_evidence.insert(variant.kind) {
            return Err(format!("duplicate evidence kind {}", variant.kind));
        }
        if !evidence_rust_names.insert(variant.rust_name) {
            return Err(format!(
                "duplicate evidence Rust variant {}",
                variant.rust_name
            ));
        }
        unique_fields(variant.rust_name, &variant.fields)?;
        if variant.fields.iter().any(|field| field.name == "kind") {
            return Err(format!(
                "{} uses the reserved evidence discriminator",
                variant.rust_name
            ));
        }
    }
    if actual_evidence != expected_evidence {
        return Err(format!(
            "evidence kinds differ from the complete WP-05 set: {actual_evidence:?}"
        ));
    }

    let expected_enums = BTreeMap::from([
        ("CloseMode", BTreeSet::from(["abort", "drain"])),
        (
            "OperationState",
            BTreeSet::from([
                "aborted",
                "committed",
                "effect_started",
                "in_doubt",
                "prepared",
            ]),
        ),
        (
            "StopState",
            BTreeSet::from(["failed", "requested", "stopped"]),
        ),
    ]);
    let mut actual_enums = BTreeMap::new();
    for enumeration in &model.string_enums {
        let mut rust_variants = BTreeSet::new();
        let mut wire_variants = BTreeSet::new();
        for (rust_name, wire_name) in &enumeration.variants {
            if !rust_variants.insert(*rust_name) {
                return Err(format!(
                    "{} repeats Rust enum variant {rust_name}",
                    enumeration.rust_name
                ));
            }
            if !wire_variants.insert(*wire_name) {
                return Err(format!(
                    "{} repeats wire enum value {wire_name}",
                    enumeration.rust_name
                ));
            }
        }
        if actual_enums
            .insert(enumeration.rust_name, wire_variants)
            .is_some()
        {
            return Err(format!("duplicate string enum {}", enumeration.rust_name));
        }
    }
    if actual_enums != expected_enums {
        return Err(format!(
            "string enums differ from the complete WP-05 set: {actual_enums:?}"
        ));
    }

    let message_by_kind = model
        .messages
        .iter()
        .map(|message| ((message.direction, message.kind), message))
        .collect::<BTreeMap<_, _>>();
    let expected_echo_responses = BTreeSet::from([
        "capability_invoked",
        "capsule_closed",
        "operation_reconciled",
        "operation_resumed",
        "stop_recorded",
    ]);
    let actual_echo_responses = model
        .messages
        .iter()
        .filter(|message| message.echo_for.is_some())
        .map(|message| message.kind)
        .collect::<BTreeSet<_>>();
    if actual_echo_responses != expected_echo_responses {
        return Err(format!(
            "ID-echo response kinds differ from the complete WP-05 set: {actual_echo_responses:?}"
        ));
    }
    for response in model
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Response)
    {
        let Some((request_kind, echo_fields)) = &response.echo_for else {
            continue;
        };
        let request = message_by_kind
            .get(&(Direction::Request, *request_kind))
            .ok_or_else(|| {
                format!(
                    "{} echoes unknown request kind {request_kind}",
                    response.rust_name
                )
            })?;
        let expected_fields = request
            .fields
            .iter()
            .filter(|field| matches!(field.name, "capsule_id" | "correlation_id" | "operation_id"))
            .map(|field| field.name)
            .collect::<BTreeSet<_>>();
        let actual_fields = echo_fields.iter().copied().collect::<BTreeSet<_>>();
        if actual_fields != expected_fields || actual_fields.len() != echo_fields.len() {
            return Err(format!(
                "{} must echo every caller-supplied ID exactly once: {actual_fields:?} != {expected_fields:?}",
                response.rust_name
            ));
        }
        let response_fields = response
            .fields
            .iter()
            .map(|field| field.name)
            .collect::<BTreeSet<_>>();
        if !actual_fields.is_subset(&response_fields) {
            return Err(format!(
                "{} is missing an echoed response field",
                response.rust_name
            ));
        }
    }

    let mut vector_by_name = BTreeMap::new();
    let mut covered_kinds = BTreeSet::new();
    let mut covered_evidence = BTreeSet::new();
    let mut covered_u64 = BTreeSet::new();
    for vector in &model.vectors {
        if vector_by_name.insert(vector.name, vector).is_some() {
            return Err(format!("duplicate vector name {}", vector.name));
        }
        let object = vector
            .message
            .as_object()
            .ok_or_else(|| format!("vector {} is not an object", vector.name))?;
        if object.get("wire") != Some(&json!(2)) {
            return Err(format!(
                "vector {} does not carry integer wire=2",
                vector.name
            ));
        }
        let kind = object
            .get("kind")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| format!("vector {} has no string kind", vector.name))?;
        let spec = message_by_kind
            .get(&(vector.direction, kind))
            .ok_or_else(|| {
                format!(
                    "vector {} has unknown {} kind {kind}",
                    vector.name,
                    vector.direction.as_str()
                )
            })?;
        validate_object_fields(vector.name, object, &spec.fields, true)?;
        covered_kinds.insert((vector.direction, kind));
        collect_special_coverage(&vector.message, &mut covered_evidence, &mut covered_u64);
        let ceiling = if vector.direction == Direction::Request {
            MAX_REQUEST_BYTES
        } else {
            MAX_FRAME_BYTES
        };
        if vector.canonical.len() > ceiling {
            return Err(format!("vector {} exceeds its frame ceiling", vector.name));
        }
    }
    if covered_kinds != kinds {
        let missing = kinds.difference(&covered_kinds).collect::<Vec<_>>();
        return Err(format!(
            "message kinds missing canonical vectors: {missing:?}"
        ));
    }
    if covered_evidence != expected_evidence {
        let missing = expected_evidence
            .difference(&covered_evidence)
            .collect::<Vec<_>>();
        return Err(format!(
            "evidence kinds missing canonical vectors: {missing:?}"
        ));
    }
    for required in ["0", "9007199254740993", U64_MAX_DECIMAL] {
        if !covered_u64.contains(required) {
            return Err(format!(
                "u64 boundary {required} is missing from canonical vectors"
            ));
        }
    }

    let mut echo_pairs = BTreeSet::new();
    let mut covered_echo_responses = BTreeSet::new();
    for pair in &model.echo_pairs {
        if !echo_pairs.insert((pair.request, pair.response)) {
            return Err(format!(
                "duplicate echo pair {} -> {}",
                pair.request, pair.response
            ));
        }
        let request = vector_by_name
            .get(pair.request)
            .ok_or_else(|| format!("echo pair references missing request {}", pair.request))?;
        let response = vector_by_name
            .get(pair.response)
            .ok_or_else(|| format!("echo pair references missing response {}", pair.response))?;
        if request.direction != Direction::Request || response.direction != Direction::Response {
            return Err(format!(
                "echo pair {} -> {} has reversed directions",
                pair.request, pair.response
            ));
        }
        let request_kind = request.message["kind"]
            .as_str()
            .ok_or_else(|| format!("request vector {} has no kind", pair.request))?;
        let response_kind = response.message["kind"]
            .as_str()
            .ok_or_else(|| format!("response vector {} has no kind", pair.response))?;
        let response_spec = message_by_kind
            .get(&(Direction::Response, response_kind))
            .ok_or_else(|| format!("response vector {} has unknown kind", pair.response))?;
        let Some((expected_request_kind, echo_fields)) = &response_spec.echo_for else {
            return Err(format!("response {} cannot be an echo pair", pair.response));
        };
        if request_kind != *expected_request_kind {
            return Err(format!(
                "response {} expects {expected_request_kind}, not {request_kind}",
                pair.response
            ));
        }
        for name in echo_fields {
            if request.message[*name] != response.message[*name] {
                return Err(format!(
                    "echo pair {} -> {} changes {name}",
                    pair.request, pair.response
                ));
            }
        }
        covered_echo_responses.insert(response_kind);
    }
    if covered_echo_responses != expected_echo_responses {
        return Err(format!(
            "response kinds missing exact-ID echo pairs: {:?}",
            expected_echo_responses
                .difference(&covered_echo_responses)
                .collect::<Vec<_>>()
        ));
    }

    let expected_v1 = BTreeSet::from([
        "v1-bind-request",
        "v1-bound-response",
        "v1-decision-request",
        "v1-decision-response",
        "v1-prepare-request",
        "v1-prepared-response",
        "v1-rejected-response",
        "v1-settle-request",
        "v1-settled-response",
        "v1-stop-intent-request",
        "v1-stop-outcome-request",
        "v1-stop-recorded-response",
    ]);
    let mut actual_v1 = BTreeSet::new();
    for case in &model.v1_rejections {
        if !actual_v1.insert(case.name) {
            return Err(format!("duplicate v1 rejection {}", case.name));
        }
    }
    if actual_v1 != expected_v1 {
        return Err("v1 rejection set is incomplete".to_string());
    }

    let required_malformed = BTreeSet::from([
        "argument-depth",
        "argument-float",
        "argument-u64-max-number",
        "argument-unsafe-integer",
        "argument-unsafe-negative-integer",
        "bad-capsule-id",
        "bad-capsule-id-terminal-newline",
        "bad-cgroup-path",
        "bad-close-mode",
        "bad-correlation-id",
        "bad-correlation-id-terminal-newline",
        "cgroup-path-terminal-newline",
        "digest-terminal-newline",
        "duplicate-argument-field",
        "duplicate-message-field",
        "invalid-utf8",
        "invalid-utf8-sequence",
        "lone-high-surrogate",
        "lone-low-surrogate",
        "missing-wire",
        "rejection-code-terminal-newline",
        "response-bad-digest",
        "response-u64-as-number",
        "response-unknown-field",
        "reversed-surrogate-pair",
        "u64-as-number",
        "u64-empty",
        "u64-leading-zero",
        "u64-negative",
        "u64-overflow",
        "u64-plus",
        "u64-terminal-newline",
        "unit-name-terminal-newline",
        "unknown-budget-field",
        "unknown-evidence-field",
        "unknown-evidence-kind",
        "unknown-message-field",
        "unknown-request-kind",
        "wire-string",
        "wire-v1",
    ]);
    let mut actual_malformed = BTreeSet::new();
    for case in &model.malformed {
        if !actual_malformed.insert(case.name) {
            return Err(format!("duplicate malformed case {}", case.name));
        }
    }
    let missing = required_malformed
        .difference(&actual_malformed)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "required malformed authority-wire cases are missing: {missing:?}"
        ));
    }
    Ok(())
}

fn unique_fields(owner: &str, fields: &[FieldSpec]) -> Result<(), String> {
    let mut names = BTreeSet::new();
    for field in fields {
        if !names.insert(field.name) {
            return Err(format!("{owner} repeats field {}", field.name));
        }
    }
    Ok(())
}

fn validate_object_fields(
    owner: &str,
    object: &JsonMap,
    fields: &[FieldSpec],
    message: bool,
) -> Result<(), String> {
    let mut expected = fields
        .iter()
        .map(|field| field.name)
        .collect::<BTreeSet<_>>();
    if message {
        expected.insert("kind");
        expected.insert("wire");
    }
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{owner} fields {actual:?} differ from {expected:?}"
        ));
    }
    for field in fields {
        validate_field(owner, field, &object[field.name])?;
    }
    Ok(())
}

fn validate_field(owner: &str, spec: &FieldSpec, value: &JsonValue) -> Result<(), String> {
    let result = match spec.ty {
        FieldType::Arguments => validate_argument(value, 0),
        FieldType::Bool => value
            .is_boolean()
            .then_some(())
            .ok_or("must be boolean".to_string()),
        FieldType::Budget => {
            let object = value.as_object().ok_or("must be an object".to_string())?;
            validate_object_fields(
                owner,
                object,
                &[
                    field("requests", FieldType::U64),
                    field("stops", FieldType::U64),
                    field("spend", FieldType::U64),
                ],
                false,
            )
        }
        FieldType::CapsuleId | FieldType::OperationId | FieldType::ToolId => {
            validate_safe_id(value, 128).map_err(str::to_string)
        }
        FieldType::CorrelationId => {
            validate_pattern_string(value, 32, |byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                .map_err(str::to_string)
        }
        FieldType::U64 => validate_u64(value).map_err(str::to_string),
        FieldType::I32 => value
            .as_i64()
            .filter(|value| i32::try_from(*value).is_ok())
            .map(|_| ())
            .ok_or("must be i32".to_string()),
        FieldType::NullableOperationId => {
            if value.is_null() {
                Ok(())
            } else {
                validate_safe_id(value, 128).map_err(str::to_string)
            }
        }
        FieldType::CloseMode => validate_enum(value, &["drain", "abort"]).map_err(str::to_string),
        FieldType::OperationState => validate_enum(
            value,
            &[
                "prepared",
                "effect_started",
                "committed",
                "aborted",
                "in_doubt",
            ],
        )
        .map_err(str::to_string),
        FieldType::StopState => {
            validate_enum(value, &["requested", "stopped", "failed"]).map_err(str::to_string)
        }
        FieldType::Evidence => validate_evidence(value),
        FieldType::UnitName => validate_string(value, 1, 256, |byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        })
        .map_err(str::to_string),
        FieldType::CgroupPath => validate_cgroup_path(value).map_err(str::to_string),
        FieldType::Digest => {
            validate_pattern_string(value, 64, |byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                .map_err(str::to_string)
        }
        FieldType::RejectionCode => validate_string(value, 1, 128, |byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        .and_then(|()| {
            value
                .as_str()
                .and_then(|text| text.as_bytes().first())
                .filter(|byte| byte.is_ascii_lowercase())
                .map(|_| ())
                .ok_or("must start with lowercase ASCII")
        })
        .map_err(str::to_string),
        FieldType::Detail => value
            .as_str()
            .filter(|text| {
                let code_points = text.chars().count();
                (1..=DETAIL_MAX_CODE_POINTS).contains(&code_points)
            })
            .map(|_| ())
            .ok_or("must be 1..=4096 Unicode code points".to_string()),
    };
    result.map_err(|error| format!("{owner}.{} {error}", spec.name))
}

fn validate_evidence(value: &JsonValue) -> Result<(), String> {
    let object = value.as_object().ok_or("must be an object")?;
    let kind = object
        .get("kind")
        .and_then(JsonValue::as_str)
        .ok_or("kind must be a string")?;
    let fields = match kind {
        "process" => vec![
            field("pid", FieldType::I32),
            field("start_time_ticks", FieldType::U64),
            field("process_group", FieldType::I32),
        ],
        "unit" => vec![field("unit_name", FieldType::UnitName)],
        "cgroup" => vec![
            field("path", FieldType::CgroupPath),
            field("inode", FieldType::U64),
        ],
        "durable" => vec![field("digest", FieldType::Digest)],
        "absent" => vec![],
        _ => return Err(format!("unknown evidence kind {kind}")),
    };
    let mut expected = fields
        .iter()
        .map(|field| field.name)
        .collect::<BTreeSet<_>>();
    expected.insert("kind");
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("fields {actual:?} differ from {expected:?}"));
    }
    for field in &fields {
        validate_field("evidence", field, &object[field.name])?;
    }
    Ok(())
}

fn validate_argument(value: &JsonValue, depth: usize) -> Result<(), String> {
    if depth > ARGUMENT_MAX_DEPTH {
        return Err("exceeds depth 32".to_string());
    }
    match value {
        JsonValue::Null | JsonValue::Bool(_) => Ok(()),
        JsonValue::String(value) => (value.chars().count() <= ARGUMENT_MAX_STRING_CODE_POINTS)
            .then_some(())
            .ok_or("string exceeds 65536 Unicode code points".to_string()),
        JsonValue::I64(value) => (-JS_SAFE_INTEGER_MAX..=JS_SAFE_INTEGER_MAX)
            .contains(value)
            .then_some(())
            .ok_or("number must be a JavaScript-safe integer".to_string()),
        JsonValue::U64(value) => (*value <= JS_SAFE_INTEGER_MAX as u64)
            .then_some(())
            .ok_or("number must be a JavaScript-safe integer".to_string()),
        JsonValue::Array(values) => {
            if depth == ARGUMENT_MAX_DEPTH {
                return Err("exceeds depth 32".to_string());
            }
            if values.len() > ARGUMENT_MAX_ARRAY_ITEMS {
                return Err("array exceeds 1024 items".to_string());
            }
            for value in values {
                validate_argument(value, depth + 1)?;
            }
            Ok(())
        }
        JsonValue::Object(values) => {
            if depth == ARGUMENT_MAX_DEPTH {
                return Err("exceeds depth 32".to_string());
            }
            if values.len() > ARGUMENT_MAX_OBJECT_PROPERTIES {
                return Err("object exceeds 256 properties".to_string());
            }
            for (key, value) in values {
                let code_points = key.chars().count();
                if code_points == 0 || code_points > ARGUMENT_MAX_KEY_CODE_POINTS {
                    return Err("object key must be 1..=256 Unicode code points".to_string());
                }
                validate_argument(value, depth + 1)?;
            }
            Ok(())
        }
    }
}

fn validate_safe_id(value: &JsonValue, ceiling: usize) -> Result<(), &'static str> {
    validate_string(value, 1, ceiling, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
    })
}

fn validate_pattern_string(
    value: &JsonValue,
    length: usize,
    predicate: impl Fn(u8) -> bool,
) -> Result<(), &'static str> {
    let text = value.as_str().ok_or("must be a string")?;
    if text.len() != length || !text.bytes().all(predicate) {
        return Err("has invalid length or character class");
    }
    Ok(())
}

fn validate_string(
    value: &JsonValue,
    minimum: usize,
    maximum: usize,
    predicate: impl Fn(u8) -> bool,
) -> Result<(), &'static str> {
    let text = value.as_str().ok_or("must be a string")?;
    if !(minimum..=maximum).contains(&text.chars().count()) {
        return Err("has invalid Unicode code-point length");
    }
    if !text.bytes().all(predicate) {
        return Err("has invalid character class");
    }
    Ok(())
}

fn validate_cgroup_path(value: &JsonValue) -> Result<(), &'static str> {
    let text = value.as_str().ok_or("must be a string")?;
    if text.chars().count() > 4096 || !text.starts_with('/') {
        return Err("must be an absolute path of at most 4096 Unicode code points");
    }
    for segment in text[1..].split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("has an empty, dot, or dot-dot segment");
        }
        if !segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@')
        }) {
            return Err("has an invalid segment character");
        }
    }
    Ok(())
}

fn validate_u64(value: &JsonValue) -> Result<(), &'static str> {
    let text = value.as_str().ok_or("must be a decimal string")?;
    if text == "0" {
        return Ok(());
    }
    let bytes = text.as_bytes();
    if !matches!(bytes.first(), Some(b'1'..=b'9')) || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("must be canonical unsigned decimal");
    }
    text.parse::<u64>().map(|_| ()).map_err(|_| "exceeds u64")
}

fn validate_enum(value: &JsonValue, allowed: &[&str]) -> Result<(), &'static str> {
    value
        .as_str()
        .filter(|value| allowed.contains(value))
        .map(|_| ())
        .ok_or("is not an allowed enum value")
}

fn collect_special_coverage(
    value: &JsonValue,
    evidence: &mut BTreeSet<&'static str>,
    u64_values: &mut BTreeSet<String>,
) {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                collect_special_coverage(value, evidence, u64_values);
            }
        }
        JsonValue::Object(values) => {
            if let Some(kind) = values.get("kind").and_then(JsonValue::as_str) {
                if let Some(known) = ["process", "unit", "cgroup", "durable", "absent"]
                    .into_iter()
                    .find(|candidate| *candidate == kind)
                {
                    evidence.insert(known);
                }
            }
            for (name, value) in values {
                if matches!(
                    name.as_str(),
                    "requests" | "stops" | "spend" | "start_time_ticks" | "inode" | "drained"
                ) {
                    if let Some(text) = value.as_str() {
                        u64_values.insert(text.to_string());
                    }
                }
                collect_special_coverage(value, evidence, u64_values);
            }
        }
        _ => {}
    }
}
