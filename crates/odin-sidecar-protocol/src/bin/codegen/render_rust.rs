//! Generate the Rust codec modules from templates and model substitutions.

use std::fmt::Write as _;

use crate::model::{
    Direction, FieldSpec, FieldType, Model, FIXTURE_ID, MAX_FRAME_BYTES, MAX_REQUEST_BYTES,
};
use crate::{line, subst};

const RUST_FACADE: &str = include_str!("../../../templates/rust-facade.rs.tmpl");
const RUST_PRELUDE: &str = include_str!("../../../templates/rust-prelude.rs.tmpl");
const RUST_CONTRACT_CONSTANTS: &str =
    include_str!("../../../templates/rust-contract-constants.rs.tmpl");
const RUST_STRING_ENUM: &str = include_str!("../../../templates/rust-string-enum.rs.tmpl");
const RUST_STRUCT: &str = include_str!("../../../templates/rust-struct.rs.tmpl");
const RUST_EVIDENCE_ENUM: &str = include_str!("../../../templates/rust-evidence-enum.rs.tmpl");
const RUST_MESSAGE_ENUM: &str = include_str!("../../../templates/rust-message-enum.rs.tmpl");
const RUST_ACCESSORS_REQUEST: &str =
    include_str!("../../../templates/rust-accessors-request.rs.tmpl");
const RUST_ACCESSORS_RESPONSE: &str =
    include_str!("../../../templates/rust-accessors-response.rs.tmpl");
const RUST_ECHOES: &str = include_str!("../../../templates/rust-echoes.rs.tmpl");
const RUST_SIZE_PRELUDE: &str = include_str!("../../../templates/rust-size-prelude.rs.tmpl");
const RUST_SIZE_EVIDENCE: &str = include_str!("../../../templates/rust-size-evidence.rs.tmpl");
const RUST_SIZE_DECODER: &str = include_str!("../../../templates/rust-size-decoder.rs.tmpl");
const RUST_SIZE_FIELD_SIZES: &str =
    include_str!("../../../templates/rust-size-field-sizes.rs.tmpl");
const RUST_CODEC: &str = include_str!("../../../templates/rust-codec.rs.tmpl");
const RUST_TEST_PRELUDE: &str = include_str!("../../../templates/rust-test-prelude.rs.tmpl");
const RUST_TEST_VECTORS: &str = include_str!("../../../templates/rust-test-vectors.rs.tmpl");
const RUST_TEST_EPILOGUE: &str = include_str!("../../../templates/rust-test-epilogue.rs.tmpl");

/// Paths are relative to the crate's `src/` directory.
pub(crate) struct RustSource {
    pub path: &'static str,
    pub source: String,
}

pub(crate) fn render_rust(model: &Model) -> Vec<RustSource> {
    vec![
        RustSource {
            path: "generated.rs",
            source: RUST_FACADE.to_string(),
        },
        RustSource {
            path: "generated/types.rs",
            source: render_rust_types(model),
        },
        RustSource {
            path: "generated/messages.rs",
            source: render_rust_messages(model),
        },
        RustSource {
            path: "generated/size.rs",
            source: render_rust_size(model),
        },
        RustSource {
            path: "generated/codec.rs",
            source: render_rust_codec(),
        },
        RustSource {
            path: "generated/tests.rs",
            source: render_rust_tests(),
        },
        RustSource {
            path: "generated/tests/vectors.rs",
            source: render_rust_test_vectors(model),
        },
    ]
}

fn owner_module(area: &str) -> String {
    let mut out = String::new();
    line(
        &mut out,
        format_args!("//! Generated authority wire v2 {area}; do not edit."),
    );
    out.push_str("\nuse super::*;\n\n");
    out
}

fn render_rust_types(model: &Model) -> String {
    let mut out = owner_module("data types and strict argument validation");
    out.push_str(RUST_PRELUDE);
    render_rust_contract_constants(&mut out, model);

    for enumeration in &model.string_enums {
        let mut variants = String::new();
        for (rust_name, _) in &enumeration.variants {
            line(&mut variants, format_args!("    {rust_name},"));
        }
        out.push_str(&subst(
            RUST_STRING_ENUM,
            &[("$NAME", enumeration.rust_name), ("$VARIANTS", &variants)],
        ));
    }
    for structure in &model.structures {
        render_rust_struct(&mut out, structure.rust_name, &structure.fields);
    }
    let mut evidence_variants = String::new();
    for variant in &model.evidence.variants {
        render_rust_variant(
            &mut evidence_variants,
            variant.rust_name,
            &variant.fields,
            false,
        );
    }
    out.push_str(&subst(
        RUST_EVIDENCE_ENUM,
        &[
            ("$NAME", model.evidence.rust_name),
            ("$VARIANTS", &evidence_variants),
        ],
    ));
    render_rust_message_enum(&mut out, model, Direction::Request);
    render_rust_message_enum(&mut out, model, Direction::Response);
    out
}

fn render_rust_messages(model: &Model) -> String {
    let mut out = owner_module("message accessors and exact echo semantics");
    render_rust_accessors(&mut out, model, Direction::Request);
    render_rust_accessors(&mut out, model, Direction::Response);
    render_rust_echoes(&mut out, model);
    out
}

fn render_rust_size(model: &Model) -> String {
    let mut out = owner_module("canonical size preflight and field size accounting");
    render_rust_size_preflight(&mut out, model);
    out
}

fn render_rust_codec() -> String {
    let mut out = owner_module("bounded canonical JSON payload codec");
    out.push_str(RUST_CODEC);
    out
}

fn render_rust_contract_constants(out: &mut String, model: &Model) {
    let vector_names = model
        .vectors
        .iter()
        .map(|vector| format!("    {:?},\n", vector.name))
        .collect::<String>();
    let rejection_names = model
        .v1_rejections
        .iter()
        .map(|rejection| format!("    {:?},\n", rejection.name))
        .collect::<String>();
    let echo_pairs = model
        .echo_pairs
        .iter()
        .map(|pair| format!("    ({:?}, {:?}),\n", pair.request, pair.response))
        .collect::<String>();
    out.push_str(&subst(
        RUST_CONTRACT_CONSTANTS,
        &[
            ("$FIXTURE_ID", &format!("{FIXTURE_ID:?}")),
            ("$MAX_REQUEST_BYTES", &MAX_REQUEST_BYTES.to_string()),
            ("$MAX_FRAME_BYTES", &MAX_FRAME_BYTES.to_string()),
            ("$VECTOR_NAMES", &vector_names),
            ("$V1_REJECTION_NAMES", &rejection_names),
            ("$ECHO_PAIRS", &echo_pairs),
        ],
    ));
}

fn render_rust_struct(out: &mut String, name: &str, fields: &[FieldSpec]) {
    let mut body = String::new();
    for field in fields {
        line(
            &mut body,
            format_args!("    pub {}: {},", field.name, rust_field_type(&field.ty)),
        );
    }
    out.push_str(&subst(RUST_STRUCT, &[("$NAME", name), ("$FIELDS", &body)]));
}

fn render_rust_variant(
    out: &mut String,
    rust_name: &str,
    fields: &[FieldSpec],
    include_wire: bool,
) {
    if fields.is_empty() && !include_wire {
        line(out, format_args!("    {rust_name},"));
        return;
    }
    line(out, format_args!("    {rust_name} {{"));
    if include_wire {
        out.push_str("        wire: Version,\n");
    }
    for field in fields {
        line(
            out,
            format_args!("        {}: {},", field.name, rust_field_type(&field.ty)),
        );
    }
    out.push_str("    },\n");
}

fn render_rust_message_enum(out: &mut String, model: &Model, direction: Direction) {
    let name = if direction == Direction::Request {
        "Request"
    } else {
        "Response"
    };
    let mut variants = String::new();
    for message in model
        .messages
        .iter()
        .filter(|message| message.direction == direction)
    {
        render_rust_variant(&mut variants, message.rust_name, &message.fields, true);
    }
    out.push_str(&subst(
        RUST_MESSAGE_ENUM,
        &[("$NAME", name), ("$VARIANTS", &variants)],
    ));
}

fn direction_names(direction: Direction) -> (&'static str, &'static str) {
    match direction {
        Direction::Request => ("Request", "request"),
        Direction::Response => ("Response", "response"),
    }
}

fn render_rust_accessors(out: &mut String, model: &Model, direction: Direction) {
    let messages = model
        .messages
        .iter()
        .filter(|message| message.direction == direction)
        .collect::<Vec<_>>();
    if direction == Direction::Request {
        let capsule_id_arms = messages
            .iter()
            .map(|message| {
                format!(
                    "            Self::{} {{ capsule_id, .. }} => capsule_id,\n",
                    message.rust_name
                )
            })
            .collect::<String>();
        let correlation_id_arms = messages
            .iter()
            .map(|message| {
                format!(
                    "            Self::{} {{ correlation_id, .. }} => correlation_id,\n",
                    message.rust_name
                )
            })
            .collect::<String>();
        let mut operation_id_arms = String::new();
        for message in messages {
            let arm = match message.kind {
                "resume_operation" | "reconcile_operation" => {
                    format!(
                        "            Self::{} {{ operation_id, .. }} => Some(operation_id),",
                        message.rust_name
                    )
                }
                "stop_intent" => {
                    format!(
                        "            Self::{} {{ operation_id, .. }} => operation_id.as_ref(),",
                        message.rust_name
                    )
                }
                _ => format!("            Self::{} {{ .. }} => None,", message.rust_name),
            };
            line(&mut operation_id_arms, format_args!("{arm}"));
        }
        out.push_str(&subst(
            RUST_ACCESSORS_REQUEST,
            &[
                ("$CAPSULE_ID_ARMS", &capsule_id_arms),
                ("$CORRELATION_ID_ARMS", &correlation_id_arms),
                ("$OPERATION_ID_ARMS", &operation_id_arms),
            ],
        ));
    } else {
        let correlation_id_arms = messages
            .iter()
            .map(|message| {
                if message.kind == "rejected" {
                    format!(
                        "            Self::{} {{ .. }} => None,\n",
                        message.rust_name
                    )
                } else {
                    format!(
                        "            Self::{} {{ correlation_id, .. }} => Some(correlation_id),\n",
                        message.rust_name
                    )
                }
            })
            .collect::<String>();
        out.push_str(&subst(
            RUST_ACCESSORS_RESPONSE,
            &[("$ARMS", &correlation_id_arms)],
        ));
    }
}

fn render_rust_echoes(out: &mut String, model: &Model) {
    let mut arms = String::new();
    for response in model
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Response)
    {
        let Some((request_kind, fields)) = &response.echo_for else {
            continue;
        };
        let request = model
            .messages
            .iter()
            .find(|message| {
                message.direction == Direction::Request && message.kind == *request_kind
            })
            .expect("validated response echo target");
        arms.push_str("        (\n");
        line(
            &mut arms,
            format_args!("            Response::{} {{", response.rust_name),
        );
        for field in fields {
            line(
                &mut arms,
                format_args!("                {field}: response_{field},"),
            );
        }
        arms.push_str("                ..\n            },\n");
        line(
            &mut arms,
            format_args!("            Request::{} {{", request.rust_name),
        );
        for field in fields {
            line(
                &mut arms,
                format_args!("                {field}: request_{field},"),
            );
        }
        arms.push_str("                ..\n            },\n        ) => {\n");
        for (index, field) in fields.iter().enumerate() {
            let connector = if index == 0 {
                "            "
            } else {
                "                && "
            };
            line(
                &mut arms,
                format_args!("{connector}response_{field} == request_{field}"),
            );
        }
        arms.push_str("        }\n");
    }
    out.push_str(&subst(RUST_ECHOES, &[("$ARMS", &arms)]));
}

fn string_enum_size_expression(field: &str, ty: &FieldType, model: &Model) -> Option<String> {
    let type_name = rust_field_type(ty);
    model
        .string_enums
        .iter()
        .find(|enumeration| enumeration.rust_name == type_name)
        .map(|enumeration| {
            let arms = enumeration
                .variants
                .iter()
                .map(|(rust_name, wire)| format!("{type_name}::{rust_name} => {wire:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("canonical_size_quoted(match {field} {{ {arms} }})")
        })
}

fn rust_size_expression(field: &str, ty: &FieldType, model: &Model) -> Option<String> {
    let expression = match ty {
        FieldType::Arguments => return None,
        FieldType::Bool => format!("if *{field} {{ 4 }} else {{ 5 }}"),
        FieldType::Budget => format!("canonical_size_budget({field})?"),
        FieldType::CapsuleId
        | FieldType::CorrelationId
        | FieldType::Detail
        | FieldType::Digest
        | FieldType::CgroupPath
        | FieldType::OperationId
        | FieldType::RejectionCode
        | FieldType::ToolId
        | FieldType::UnitName => format!("canonical_size_quoted({field}.as_str())"),
        FieldType::Evidence => return None,
        FieldType::I32 => format!("canonical_size_i32(i64::from(*{field}))"),
        FieldType::NullableOperationId => format!(
            "match {field} {{ Some(operation_id) => canonical_size_quoted(operation_id.as_str()), None => 4 }}"
        ),
        FieldType::U64 => format!("canonical_size_u64_wire({field}.get())"),
        FieldType::CloseMode | FieldType::OperationState | FieldType::StopState => {
            string_enum_size_expression(field, ty, model)?
        }
    };
    Some(expression)
}

fn render_rust_size_preflight(out: &mut String, model: &Model) {
    out.push_str(RUST_SIZE_PRELUDE);

    let mut evidence_arms = String::new();
    for variant in &model.evidence.variants {
        if variant.fields.is_empty() {
            line(
                &mut evidence_arms,
                format_args!(
                    "        {}::{} => canonical_size_object_parts(&[\n            canonical_size_quoted(\"kind\"), 1, canonical_size_quoted({:?}),\n        ])?,",
                    model.evidence.rust_name, variant.rust_name, variant.kind
                ),
            );
            continue;
        }
        let bindings = variant
            .fields
            .iter()
            .map(|field| field.name)
            .collect::<Vec<_>>()
            .join(", ");
        line(
            &mut evidence_arms,
            format_args!(
                "        {}::{} {{ {} }} => canonical_size_object_parts(&[",
                model.evidence.rust_name, variant.rust_name, bindings
            ),
        );
        line(
            &mut evidence_arms,
            format_args!(
                "            canonical_size_quoted(\"kind\"), 1, canonical_size_quoted({:?}),",
                variant.kind
            ),
        );
        for field in &variant.fields {
            let expression =
                rust_size_expression(field.name, &field.ty, model).unwrap_or_else(|| {
                    panic!("evidence field {} requires preflight binding", field.name)
                });
            line(
                &mut evidence_arms,
                format_args!(
                    "            canonical_size_quoted({:?}), 1, {expression},",
                    field.name
                ),
            );
        }
        evidence_arms.push_str("        ])?,\n");
    }
    out.push_str(&subst(
        RUST_SIZE_EVIDENCE,
        &[
            ("$NAME", model.evidence.rust_name),
            ("$ARMS", &evidence_arms),
        ],
    ));

    for direction in [Direction::Request, Direction::Response] {
        let (enum_name, enum_name_lower) = direction_names(direction);
        let mut arms = String::new();
        for message in model
            .messages
            .iter()
            .filter(|message| message.direction == direction)
        {
            let bindings = std::iter::once("wire: _")
                .chain(message.fields.iter().map(|field| field.name))
                .collect::<Vec<_>>()
                .join(", ");
            line(
                &mut arms,
                format_args!(
                    "        {}::{} {{ {bindings} }} => {{",
                    enum_name, message.rust_name
                ),
            );
            for field in &message.fields {
                match field.ty {
                    FieldType::Arguments => line(
                        &mut arms,
                        format_args!(
                            "            let arguments_size = canonical_size_value(arguments.as_value(), 0)?;"
                        ),
                    ),
                    FieldType::Evidence => line(
                        &mut arms,
                        format_args!("            let evidence_size = canonical_size_evidence(evidence)?;"),
                    ),
                    _ => {}
                }
            }
            arms.push_str("            canonical_size_object_parts(&[\n");
            line(
                &mut arms,
                format_args!(
                    "                canonical_size_quoted(\"kind\"), 1, canonical_size_quoted({:?}),",
                    message.kind
                ),
            );
            line(
                &mut arms,
                format_args!(
                    "                canonical_size_quoted(\"wire\"), 1, canonical_size_u64(u64::from(PROTOCOL_VERSION)),"
                ),
            );
            for field in &message.fields {
                let expression = match &field.ty {
                    FieldType::Arguments => "arguments_size".to_string(),
                    FieldType::Evidence => "evidence_size".to_string(),
                    other => rust_size_expression(field.name, other, model).unwrap_or_else(|| {
                        panic!("message field {} requires preflight expression", field.name)
                    }),
                };
                line(
                    &mut arms,
                    format_args!(
                        "                canonical_size_quoted({:?}), 1, {expression},",
                        field.name
                    ),
                );
            }
            arms.push_str("            ])?\n        }\n");
        }
        out.push_str(&subst(
            RUST_SIZE_DECODER,
            &[
                ("$LOWER", enum_name_lower),
                ("$NAME", enum_name),
                ("$ARMS", &arms),
            ],
        ));
    }
    for direction in [Direction::Request, Direction::Response] {
        let (enum_name, enum_name_lower) = direction_names(direction);
        let mut arms = String::new();
        for message in model
            .messages
            .iter()
            .filter(|message| message.direction == direction)
        {
            let bindings = std::iter::once("wire: _")
                .chain(message.fields.iter().map(|field| field.name))
                .collect::<Vec<_>>()
                .join(", ");
            line(
                &mut arms,
                format_args!(
                    "        {}::{} {{ {bindings} }} => {{",
                    enum_name, message.rust_name
                ),
            );
            for field in &message.fields {
                match field.ty {
                    FieldType::Arguments => line(
                        &mut arms,
                        format_args!(
                            "            let arguments_size = canonical_size_value(arguments.as_value(), 0)?;"
                        ),
                    ),
                    FieldType::Evidence => line(
                        &mut arms,
                        format_args!("            let evidence_size = canonical_size_evidence(evidence)?;"),
                    ),
                    _ => {}
                }
            }
            arms.push_str("            vec![\n");
            line(
                &mut arms,
                format_args!(
                    "                (\"kind\", canonical_size_quoted({:?})),",
                    message.kind
                ),
            );
            line(
                &mut arms,
                format_args!(
                    "                (\"wire\", canonical_size_u64(u64::from(PROTOCOL_VERSION))),"
                ),
            );
            for field in &message.fields {
                let expression = match &field.ty {
                    FieldType::Arguments => "arguments_size".to_string(),
                    FieldType::Evidence => "evidence_size".to_string(),
                    other => rust_size_expression(field.name, other, model).unwrap_or_else(|| {
                        panic!("field size contribution {} requires expression", field.name)
                    }),
                };
                line(
                    &mut arms,
                    format_args!("                ({:?}, {expression}),", field.name),
                );
            }
            arms.push_str("            ]\n        }\n");
        }
        out.push_str(&subst(
            RUST_SIZE_FIELD_SIZES,
            &[
                ("$LOWER", enum_name_lower),
                ("$NAME", enum_name),
                ("$ARMS", &arms),
            ],
        ));
    }
}

fn render_rust_test_vectors(model: &Model) -> String {
    let vector_rows = model
        .vectors
        .iter()
        .map(|vector| {
            format!(
                "        ({:?}, {}, {}, {:?}),\n",
                vector.name,
                vector.direction.rust_name(),
                rust_byte_string(vector.canonical.as_bytes()),
                vector.frame_hex
            )
        })
        .collect::<String>();
    let rejection_rows = model
        .v1_rejections
        .iter()
        .map(|case| {
            format!(
                "        ({:?}, {}, {}),\n",
                case.name,
                case.direction.rust_name(),
                rust_byte_string(case.payload.as_bytes())
            )
        })
        .collect::<String>();
    let echo_rows = model
        .echo_pairs
        .iter()
        .map(|pair| format!("        ({:?}, {:?}),\n", pair.request, pair.response))
        .collect::<String>();
    let malformed_rows = model
        .malformed
        .iter()
        .map(|case| {
            format!(
                "        ({:?}, {}, {}),\n",
                case.name,
                case.direction.rust_name(),
                rust_byte_slice(&case.payload)
            )
        })
        .collect::<String>();
    subst(
        RUST_TEST_VECTORS,
        &[
            ("$VECTORS", &vector_rows),
            ("$V1_REJECTIONS", &rejection_rows),
            ("$ECHO_PAIRS", &echo_rows),
            ("$MALFORMED", &malformed_rows),
        ],
    )
}

fn render_rust_tests() -> String {
    let mut out = String::new();
    out.push_str(RUST_TEST_PRELUDE);
    out.push_str(RUST_TEST_EPILOGUE);
    out
}

fn rust_field_type(field_type: &FieldType) -> &'static str {
    match field_type {
        FieldType::Arguments => "Arguments",
        FieldType::Bool => "bool",
        FieldType::Budget => "Budget",
        FieldType::CapsuleId => "CapsuleId",
        FieldType::CgroupPath => "CgroupPath",
        FieldType::CloseMode => "CloseMode",
        FieldType::CorrelationId => "CorrelationId",
        FieldType::Detail => "Detail",
        FieldType::Digest => "PredecessorHash",
        FieldType::Evidence => "Evidence",
        FieldType::I32 => "i32",
        FieldType::NullableOperationId => "Option<OperationId>",
        FieldType::OperationId => "OperationId",
        FieldType::OperationState => "OperationState",
        FieldType::RejectionCode => "RejectionCode",
        FieldType::StopState => "StopState",
        FieldType::ToolId => "ToolId",
        FieldType::U64 => "U64Wire",
        FieldType::UnitName => "UnitName",
    }
}

fn rust_byte_string(bytes: &[u8]) -> String {
    let mut out = String::from("b\"");
    for byte in bytes {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b' '..=b'~' => out.push(char::from(*byte)),
            _ => write!(out, "\\x{byte:02x}").expect("String write cannot fail"),
        }
    }
    out.push('"');
    out
}

fn rust_byte_slice(bytes: &[u8]) -> String {
    if bytes.iter().all(u8::is_ascii) {
        return rust_byte_string(bytes);
    }
    let mut out = String::from("&[");
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write!(out, "0x{byte:02x}").expect("String write cannot fail");
    }
    out.push(']');
    out
}
