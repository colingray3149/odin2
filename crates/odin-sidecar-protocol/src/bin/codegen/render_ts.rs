//! Emits `extension/generated/odin-authority-wire-v2.ts` from template files plus
//! model substitution.

use std::fmt::Write as _;

use crate::model::{Direction, FieldSpec, FieldType, Model, StructSpec, TaggedEnumSpec};
use crate::{line, subst};

const TS_PRELUDE: &str = include_str!("../../../templates/ts-prelude.ts.tmpl");
const TS_INTERFACE: &str = include_str!("../../../templates/ts-interface.ts.tmpl");
const TS_UNION: &str = include_str!("../../../templates/ts-union.ts.tmpl");
const TS_VALIDATION_PRELUDE: &str =
    include_str!("../../../templates/ts-validation-prelude.ts.tmpl");
const TS_STRUCT_DECODER: &str = include_str!("../../../templates/ts-struct-decoder.ts.tmpl");
const TS_EVIDENCE_DECODER: &str = include_str!("../../../templates/ts-evidence-decoder.ts.tmpl");
const TS_MESSAGE_DECODER: &str = include_str!("../../../templates/ts-message-decoder.ts.tmpl");
const TS_ECHOES: &str = include_str!("../../../templates/ts-echoes.ts.tmpl");
const TS_CODEC_EPILOGUE: &str = include_str!("../../../templates/ts-codec-epilogue.ts.tmpl");

pub(crate) fn render_ts(model: &Model) -> String {
    let mut out = String::new();
    out.push_str(TS_PRELUDE);
    for enumeration in &model.string_enums {
        let values = enumeration
            .variants
            .iter()
            .map(|(_, wire)| format!("\"{wire}\""))
            .collect::<Vec<_>>()
            .join(" | ");
        line(
            &mut out,
            format_args!("export type {} = {values};", enumeration.rust_name),
        );
    }
    out.push('\n');
    for structure in &model.structures {
        let mut fields = String::new();
        for field in &structure.fields {
            line(
                &mut fields,
                format_args!("\t{}: {};", field.name, ts_field_type(&field.ty)),
            );
        }
        out.push_str(&subst(
            TS_INTERFACE,
            &[("$NAME", structure.rust_name), ("$FIELDS", &fields)],
        ));
    }
    let evidence_variants = model
        .evidence
        .variants
        .iter()
        .map(|variant| {
            format!(
                "\t| {{ kind: \"{}\"{} }}\n",
                variant.kind,
                ts_inline_fields(&variant.fields)
            )
        })
        .collect::<String>();
    out.push_str(&subst(
        TS_UNION,
        &[
            ("$NAME", model.evidence.rust_name),
            ("$VARIANTS", &evidence_variants),
        ],
    ));
    for message in &model.messages {
        let mut fields = String::new();
        line(&mut fields, format_args!("\tkind: \"{}\";", message.kind));
        fields.push_str("\twire: 2;\n");
        for field in &message.fields {
            line(
                &mut fields,
                format_args!("\t{}: {};", field.name, ts_field_type(&field.ty)),
            );
        }
        out.push_str(&subst(
            TS_INTERFACE,
            &[("$NAME", message.rust_name), ("$FIELDS", &fields)],
        ));
    }
    render_ts_union(&mut out, model, Direction::Request);
    render_ts_union(&mut out, model, Direction::Response);
    out.push_str(TS_VALIDATION_PRELUDE);
    render_ts_struct_decoder(&mut out, &model.structures[0]);
    render_ts_evidence_decoder(&mut out, &model.evidence);
    render_ts_message_decoder(&mut out, model, Direction::Request);
    render_ts_message_decoder(&mut out, model, Direction::Response);
    render_ts_echoes(&mut out, model);
    out.push_str(TS_CODEC_EPILOGUE);
    out
}

fn render_ts_union(out: &mut String, model: &Model, direction: Direction) {
    let name = if direction == Direction::Request {
        "Request"
    } else {
        "Response"
    };
    let variants = model
        .messages
        .iter()
        .filter(|message| message.direction == direction)
        .map(|message| format!("\t| {}\n", message.rust_name))
        .collect::<String>();
    out.push_str(&subst(
        TS_UNION,
        &[("$NAME", name), ("$VARIANTS", &variants)],
    ));
}

fn render_ts_struct_decoder(out: &mut String, structure: &StructSpec) {
    let keys = structure
        .fields
        .iter()
        .map(|field| format!("\"{}\"", field.name))
        .collect::<Vec<_>>()
        .join(", ");
    let mut fields = String::new();
    for field in &structure.fields {
        line(
            &mut fields,
            format_args!(
                "\t\t{}: {},",
                field.name,
                ts_decode_expression(
                    &format!("record.{}", field.name),
                    &field.ty,
                    &format!("${{path}}.{}", field.name)
                )
            ),
        );
    }
    out.push_str(&subst(
        TS_STRUCT_DECODER,
        &[
            ("$NAME", structure.rust_name),
            ("$KEYS", &keys),
            ("$FIELDS", &fields),
        ],
    ));
}

fn render_ts_evidence_decoder(out: &mut String, evidence: &TaggedEnumSpec) {
    let mut cases = String::new();
    for variant in &evidence.variants {
        line(
            &mut cases,
            format_args!("\t\tcase \"{}\": {{", variant.kind),
        );
        if variant.fields.is_empty() {
            cases
                .push_str("\t\t\texactRecord(record, path, [\"kind\"]);\n\t\t\treturn { kind };\n");
        } else {
            cases.push_str("\t\t\tconst exact = exactRecord(record, path, [\"kind\"");
            for field in &variant.fields {
                write!(cases, ", \"{}\"", field.name).expect("String write cannot fail");
            }
            cases.push_str("]);\n\t\t\treturn { kind,\n");
            for field in &variant.fields {
                line(
                    &mut cases,
                    format_args!(
                        "\t\t\t\t{}: {},",
                        field.name,
                        ts_decode_expression(
                            &format!("exact.{}", field.name),
                            &field.ty,
                            &format!("${{path}}.{}", field.name)
                        )
                    ),
                );
            }
            cases.push_str("\t\t\t};\n");
        }
        cases.push_str("\t\t}\n");
    }
    out.push_str(&subst(
        TS_EVIDENCE_DECODER,
        &[("$NAME", evidence.rust_name), ("$CASES", &cases)],
    ));
}

fn render_ts_message_decoder(out: &mut String, model: &Model, direction: Direction) {
    let name = if direction == Direction::Request {
        "Request"
    } else {
        "Response"
    };
    let mut cases = String::new();
    for message in model
        .messages
        .iter()
        .filter(|message| message.direction == direction)
    {
        line(
            &mut cases,
            format_args!("\t\tcase \"{}\": {{", message.kind),
        );
        cases.push_str("\t\t\tconst exact = exactRecord(record, kind, [\"kind\", \"wire\"");
        for field in &message.fields {
            write!(cases, ", \"{}\"", field.name).expect("String write cannot fail");
        }
        cases.push_str(
            "]);\n\t\t\tversion(exact.wire, `${kind}.wire`);\n\t\t\treturn { kind, wire: 2,\n",
        );
        for field in &message.fields {
            line(
                &mut cases,
                format_args!(
                    "\t\t\t\t{}: {},",
                    field.name,
                    ts_decode_expression(
                        &format!("exact.{}", field.name),
                        &field.ty,
                        &format!("${{kind}}.{}", field.name)
                    )
                ),
            );
        }
        cases.push_str("\t\t\t};\n\t\t}\n");
    }
    out.push_str(&subst(
        TS_MESSAGE_DECODER,
        &[
            ("$NAME", name),
            ("$DIRECTION", direction.as_str()),
            ("$CASES", &cases),
        ],
    ));
}

fn render_ts_echoes(out: &mut String, model: &Model) {
    let mut cases = String::new();
    for response in model
        .messages
        .iter()
        .filter(|message| message.direction == Direction::Response)
    {
        let Some((request_kind, fields)) = &response.echo_for else {
            continue;
        };
        line(&mut cases, format_args!("\t\tcase \"{}\":", response.kind));
        line(
            &mut cases,
            format_args!("\t\t\treturn request.kind === \"{request_kind}\""),
        );
        for field in fields {
            line(
                &mut cases,
                format_args!("\t\t\t\t&& response.{field} === request.{field}"),
            );
        }
        cases.push_str("\t\t\t;\n");
    }
    out.push_str(&subst(TS_ECHOES, &[("$CASES", &cases)]));
}

fn ts_inline_fields(fields: &[FieldSpec]) -> String {
    let mut out = String::new();
    for field in fields {
        write!(out, "; {}: {}", field.name, ts_field_type(&field.ty))
            .expect("String write cannot fail");
    }
    out
}

fn ts_field_type(field_type: &FieldType) -> &'static str {
    match field_type {
        FieldType::Arguments => "Arguments",
        FieldType::Bool => "boolean",
        FieldType::Budget => "Budget",
        FieldType::CapsuleId
        | FieldType::CgroupPath
        | FieldType::CorrelationId
        | FieldType::Detail
        | FieldType::Digest
        | FieldType::OperationId
        | FieldType::RejectionCode
        | FieldType::ToolId
        | FieldType::UnitName => "string",
        FieldType::CloseMode => "CloseMode",
        FieldType::Evidence => "Evidence",
        FieldType::I32 => "number",
        FieldType::NullableOperationId => "string | null",
        FieldType::OperationState => "OperationState",
        FieldType::StopState => "StopState",
        FieldType::U64 => "U64",
    }
}

fn ts_decode_expression(value: &str, field_type: &FieldType, path: &str) -> String {
    match field_type {
        FieldType::Arguments => format!("decodeArgument({value}, `{path}`, 0)"),
        FieldType::Bool => format!("booleanField({value}, `{path}`)"),
        FieldType::Budget => format!("decodeBudget({value}, `{path}`)"),
        FieldType::CapsuleId | FieldType::OperationId | FieldType::ToolId => {
            format!("safeId({value}, `{path}`, 128)")
        }
        FieldType::CorrelationId => format!("correlationId({value}, `{path}`)"),
        FieldType::U64 => format!("u64Field({value}, `{path}`)"),
        FieldType::I32 => format!("i32Field({value}, `{path}`)"),
        FieldType::NullableOperationId => format!("nullableOperationId({value}, `{path}`)"),
        FieldType::CloseMode => format!("enumField({value}, `{path}`, CLOSE_MODE)"),
        FieldType::OperationState => format!("enumField({value}, `{path}`, OPERATION_STATE)"),
        FieldType::StopState => format!("enumField({value}, `{path}`, STOP_STATE)"),
        FieldType::Evidence => format!("decodeEvidence({value}, `{path}`)"),
        FieldType::UnitName => format!("unitName({value}, `{path}`)"),
        FieldType::CgroupPath => format!("cgroupPath({value}, `{path}`)"),
        FieldType::Digest => format!("digest({value}, `{path}`)"),
        FieldType::RejectionCode => format!("rejectionCode({value}, `{path}`)"),
        FieldType::Detail => format!("detail({value}, `{path}`)"),
    }
}
