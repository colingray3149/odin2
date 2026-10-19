//! The frozen authority wire v2 model: message, evidence, enum, and vector data.

use crate::json::{json, JsonMap, JsonValue, ToJson};
use crate::validate::validate_model;

pub(crate) const FIXTURE_ID: &str = "odin-authority-wire-v2";
pub(crate) const MAX_REQUEST_BYTES: usize = 262_144;
pub(crate) const MAX_FRAME_BYTES: usize = 1_048_576;
pub(crate) const U64_MAX_DECIMAL: &str = "18446744073709551615";
pub(crate) const JS_SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;
pub(crate) const ARGUMENT_MAX_DEPTH: usize = 32;
pub(crate) const ARGUMENT_MAX_ARRAY_ITEMS: usize = 1_024;
pub(crate) const ARGUMENT_MAX_OBJECT_PROPERTIES: usize = 256;
pub(crate) const ARGUMENT_MAX_KEY_CODE_POINTS: usize = 256;
pub(crate) const ARGUMENT_MAX_STRING_CODE_POINTS: usize = 65_536;
pub(crate) const DETAIL_MAX_CODE_POINTS: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Direction {
    Request,
    Response,
}

impl Direction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }

    pub(crate) const fn rust_name(self) -> &'static str {
        match self {
            Self::Request => "Direction::Request",
            Self::Response => "Direction::Response",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum FieldType {
    Arguments,
    Bool,
    Budget,
    CapsuleId,
    CgroupPath,
    CloseMode,
    CorrelationId,
    Detail,
    Digest,
    Evidence,
    I32,
    NullableOperationId,
    OperationId,
    OperationState,
    RejectionCode,
    StopState,
    ToolId,
    U64,
    UnitName,
}

#[derive(Clone, Debug)]
pub(crate) struct FieldSpec {
    pub(crate) name: &'static str,
    pub(crate) ty: FieldType,
}

#[derive(Clone, Debug)]
pub(crate) struct MessageSpec {
    pub(crate) rust_name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) direction: Direction,
    pub(crate) fields: Vec<FieldSpec>,
    pub(crate) echo_for: Option<(&'static str, Vec<&'static str>)>,
}

#[derive(Clone, Debug)]
pub(crate) struct StructSpec {
    pub(crate) rust_name: &'static str,
    pub(crate) fields: Vec<FieldSpec>,
}

#[derive(Clone, Debug)]
pub(crate) struct TaggedVariantSpec {
    pub(crate) rust_name: &'static str,
    pub(crate) kind: &'static str,
    pub(crate) fields: Vec<FieldSpec>,
}

#[derive(Clone, Debug)]
pub(crate) struct TaggedEnumSpec {
    pub(crate) rust_name: &'static str,
    pub(crate) variants: Vec<TaggedVariantSpec>,
}

#[derive(Clone, Debug)]
pub(crate) struct StringEnumSpec {
    pub(crate) rust_name: &'static str,
    pub(crate) variants: Vec<(&'static str, &'static str)>,
}

#[derive(Clone, Debug)]
pub(crate) struct RawVector {
    pub(crate) name: &'static str,
    pub(crate) direction: Direction,
    pub(crate) message: JsonValue,
}

#[derive(Clone, Debug)]
pub(crate) struct VectorSpec {
    pub(crate) name: &'static str,
    pub(crate) direction: Direction,
    pub(crate) message: JsonValue,
    pub(crate) canonical: String,
    pub(crate) frame_hex: String,
}

#[derive(Clone, Debug)]
pub(crate) struct V1Rejection {
    pub(crate) name: &'static str,
    pub(crate) direction: Direction,
    pub(crate) payload: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct EchoPair {
    pub(crate) request: &'static str,
    pub(crate) response: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct MalformedCase {
    pub(crate) name: &'static str,
    pub(crate) direction: Direction,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Model {
    pub(crate) structures: Vec<StructSpec>,
    pub(crate) evidence: TaggedEnumSpec,
    pub(crate) string_enums: Vec<StringEnumSpec>,
    pub(crate) messages: Vec<MessageSpec>,
    pub(crate) vectors: Vec<VectorSpec>,
    pub(crate) v1_rejections: Vec<V1Rejection>,
    pub(crate) echo_pairs: Vec<EchoPair>,
    pub(crate) malformed: Vec<MalformedCase>,
}

pub(crate) fn field(name: &'static str, ty: FieldType) -> FieldSpec {
    FieldSpec { name, ty }
}

fn message(
    rust_name: &'static str,
    kind: &'static str,
    direction: Direction,
    fields: Vec<FieldSpec>,
    echo_for: Option<(&'static str, Vec<&'static str>)>,
) -> MessageSpec {
    MessageSpec {
        rust_name,
        kind,
        direction,
        fields,
        echo_for,
    }
}

pub(crate) fn model() -> Result<Model, String> {
    let structures = vec![StructSpec {
        rust_name: "Budget",
        fields: vec![
            field("requests", FieldType::U64),
            field("stops", FieldType::U64),
            field("spend", FieldType::U64),
        ],
    }];

    let evidence = TaggedEnumSpec {
        rust_name: "Evidence",
        variants: vec![
            TaggedVariantSpec {
                rust_name: "Process",
                kind: "process",
                fields: vec![
                    field("pid", FieldType::I32),
                    field("start_time_ticks", FieldType::U64),
                    field("process_group", FieldType::I32),
                ],
            },
            TaggedVariantSpec {
                rust_name: "Unit",
                kind: "unit",
                fields: vec![field("unit_name", FieldType::UnitName)],
            },
            TaggedVariantSpec {
                rust_name: "Cgroup",
                kind: "cgroup",
                fields: vec![
                    field("path", FieldType::CgroupPath),
                    field("inode", FieldType::U64),
                ],
            },
            TaggedVariantSpec {
                rust_name: "Durable",
                kind: "durable",
                fields: vec![field("digest", FieldType::Digest)],
            },
            TaggedVariantSpec {
                rust_name: "Absent",
                kind: "absent",
                fields: vec![],
            },
        ],
    };

    let string_enums = vec![
        StringEnumSpec {
            rust_name: "OperationState",
            variants: vec![
                ("Prepared", "prepared"),
                ("EffectStarted", "effect_started"),
                ("Committed", "committed"),
                ("Aborted", "aborted"),
                ("InDoubt", "in_doubt"),
            ],
        },
        StringEnumSpec {
            rust_name: "StopState",
            variants: vec![
                ("Requested", "requested"),
                ("Stopped", "stopped"),
                ("Failed", "failed"),
            ],
        },
        StringEnumSpec {
            rust_name: "CloseMode",
            variants: vec![("Drain", "drain"), ("Abort", "abort")],
        },
    ];

    let messages = vec![
        message(
            "InvokeCapability",
            "invoke_capability",
            Direction::Request,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("capability", FieldType::ToolId),
                field("budget", FieldType::Budget),
                field("arguments", FieldType::Arguments),
            ],
            None,
        ),
        message(
            "ResumeOperation",
            "resume_operation",
            Direction::Request,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::OperationId),
            ],
            None,
        ),
        message(
            "ReconcileOperation",
            "reconcile_operation",
            Direction::Request,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::OperationId),
            ],
            None,
        ),
        message(
            "CloseCapsule",
            "close_capsule",
            Direction::Request,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("mode", FieldType::CloseMode),
            ],
            None,
        ),
        message(
            "StopIntent",
            "stop_intent",
            Direction::Request,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::NullableOperationId),
            ],
            None,
        ),
        message(
            "CapabilityInvoked",
            "capability_invoked",
            Direction::Response,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::OperationId),
                field("state", FieldType::OperationState),
                field("replay", FieldType::Bool),
            ],
            Some(("invoke_capability", vec!["capsule_id", "correlation_id"])),
        ),
        message(
            "OperationResumed",
            "operation_resumed",
            Direction::Response,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::OperationId),
                field("state", FieldType::OperationState),
                field("replay", FieldType::Bool),
            ],
            Some((
                "resume_operation",
                vec!["capsule_id", "correlation_id", "operation_id"],
            )),
        ),
        message(
            "OperationReconciled",
            "operation_reconciled",
            Direction::Response,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::OperationId),
                field("state", FieldType::OperationState),
                field("replay", FieldType::Bool),
                field("evidence", FieldType::Evidence),
            ],
            Some((
                "reconcile_operation",
                vec!["capsule_id", "correlation_id", "operation_id"],
            )),
        ),
        message(
            "CapsuleClosed",
            "capsule_closed",
            Direction::Response,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("drained", FieldType::U64),
            ],
            Some(("close_capsule", vec!["capsule_id", "correlation_id"])),
        ),
        message(
            "StopRecorded",
            "stop_recorded",
            Direction::Response,
            vec![
                field("capsule_id", FieldType::CapsuleId),
                field("correlation_id", FieldType::CorrelationId),
                field("operation_id", FieldType::NullableOperationId),
                field("state", FieldType::StopState),
                field("evidence", FieldType::Evidence),
            ],
            Some((
                "stop_intent",
                vec!["capsule_id", "correlation_id", "operation_id"],
            )),
        ),
        message(
            "Rejected",
            "rejected",
            Direction::Response,
            vec![
                field("code", FieldType::RejectionCode),
                field("detail", FieldType::Detail),
            ],
            None,
        ),
    ];

    let vectors = raw_vectors()
        .into_iter()
        .map(complete_vector)
        .collect::<Result<Vec<_>, _>>()?;

    let v1_rejections = vec![
        V1Rejection {
            name: "v1-bind-request",
            direction: Direction::Request,
            payload: r#"{"kind":"bind","session_id":"seat-session-alpha"}"#,
        },
        V1Rejection {
            name: "v1-prepare-request",
            direction: Direction::Request,
            payload: r#"{"kind":"prepare","session_id":"seat-session-alpha","request":{"correlation_id":"00112233445566778899aabbccddeeff","operation_id":"caller-op","capability":"write","requested_grant":{"capabilities":["write"],"stop_budget":0,"spend_budget":1},"cost":{"requests":1,"stops":0,"spend":1}}}"#,
        },
        V1Rejection {
            name: "v1-decision-request",
            direction: Direction::Request,
            payload: r#"{"kind":"decision","session_id":"seat-session-alpha","correlation_id":"00112233445566778899aabbccddeeff","operation_id":"caller-op"}"#,
        },
        V1Rejection {
            name: "v1-settle-request",
            direction: Direction::Request,
            payload: r#"{"kind":"settle","session_id":"seat-session-alpha","correlation_id":"00112233445566778899aabbccddeeff","operation_id":"caller-op","settlement":"commit"}"#,
        },
        V1Rejection {
            name: "v1-stop-intent-request",
            direction: Direction::Request,
            payload: r#"{"kind":"stop_intent","session_id":"seat-session-alpha","correlation_id":"00112233445566778899aabbccddeeff","helper":{"pid":42,"start_time_ticks":18446744073709551615,"process_group":42}}"#,
        },
        V1Rejection {
            name: "v1-stop-outcome-request",
            direction: Direction::Request,
            payload: r#"{"kind":"stop_outcome","session_id":"seat-session-alpha","correlation_id":"00112233445566778899aabbccddeeff","stopped":false,"survivors":[{"pid":42,"start_time_ticks":18446744073709551615,"process_group":42}]}"#,
        },
        V1Rejection {
            name: "v1-bound-response",
            direction: Direction::Response,
            payload: r#"{"kind":"bound"}"#,
        },
        V1Rejection {
            name: "v1-prepared-response",
            direction: Direction::Response,
            payload: r#"{"kind":"prepared","correlation_id":"00112233445566778899aabbccddeeff","state":"prepared","replay":false}"#,
        },
        V1Rejection {
            name: "v1-decision-response",
            direction: Direction::Response,
            payload: r#"{"kind":"decision","correlation_id":"00112233445566778899aabbccddeeff","operation_id":"caller-op","state":"prepared","effect_permit":true}"#,
        },
        V1Rejection {
            name: "v1-settled-response",
            direction: Direction::Response,
            payload: r#"{"kind":"settled","correlation_id":"00112233445566778899aabbccddeeff","state":"committed","replay":false}"#,
        },
        V1Rejection {
            name: "v1-stop-recorded-response",
            direction: Direction::Response,
            payload: r#"{"kind":"stop_recorded","correlation_id":"00112233445566778899aabbccddeeff","state":"requested"}"#,
        },
        V1Rejection {
            name: "v1-rejected-response",
            direction: Direction::Response,
            payload: r#"{"kind":"rejected","code":"authority.denied","detail":"not listed"}"#,
        },
    ];

    let echo_pairs = vec![
        EchoPair {
            request: "invoke-basic",
            response: "invoked-basic",
        },
        EchoPair {
            request: "invoke-u64-max",
            response: "invoked-replay",
        },
        EchoPair {
            request: "resume-operation",
            response: "operation-resumed",
        },
        EchoPair {
            request: "reconcile-durable",
            response: "operation-reconciled-durable",
        },
        EchoPair {
            request: "reconcile-absent",
            response: "operation-reconciled-absent",
        },
        EchoPair {
            request: "close-drain",
            response: "capsule-closed-drain",
        },
        EchoPair {
            request: "close-abort",
            response: "capsule-closed-abort",
        },
        EchoPair {
            request: "stop-process",
            response: "stop-recorded-requested",
        },
        EchoPair {
            request: "stop-cgroup",
            response: "stop-recorded-stopped",
        },
        EchoPair {
            request: "stop-unit",
            response: "stop-recorded-failed",
        },
    ];

    let model = Model {
        structures,
        evidence,
        string_enums,
        messages,
        vectors,
        v1_rejections,
        echo_pairs,
        malformed: malformed_cases(),
    };
    validate_model(&model)?;
    Ok(model)
}

fn raw_vectors() -> Vec<RawVector> {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    vec![
        raw_vector(
            "invoke-basic",
            Direction::Request,
            json!({
                "wire": 2, "kind": "invoke_capability", "capsule_id": "capsule-alpha",
                "correlation_id": "00112233445566778899aabbccddeeff", "capability": "capsule.eval.run",
                "budget": {"requests": "1", "stops": "0", "spend": "9007199254740993"},
                "arguments": {"accent": "café", "content": "quote=\" slash=\\ emoji=😀\n", "count": 7, "enabled": true, "items": [null, "λ", false]}
            }),
        ),
        raw_vector(
            "invoke-u64-max",
            Direction::Request,
            json!({
                "wire": 2, "kind": "invoke_capability", "capsule_id": "capsule-alpha",
                "correlation_id": "102132435465768798a9bacbdcedfe0f", "capability": "artifact.render",
                "budget": {"requests": U64_MAX_DECIMAL, "stops": "0", "spend": "9007199254740992"},
                "arguments": {"max_safe_integer": JS_SAFE_INTEGER_MAX, "nested": {"array": [1, 2, 3]}}
            }),
        ),
        raw_vector(
            "resume-operation",
            Direction::Request,
            json!({
                "wire": 2, "kind": "resume_operation", "capsule_id": "capsule-alpha",
                "correlation_id": "ffeeddccbbaa99887766554433221100", "operation_id": "op-authority-0001"
            }),
        ),
        raw_vector(
            "reconcile-durable",
            Direction::Request,
            json!({
                "wire": 2, "kind": "reconcile_operation", "capsule_id": "capsule-alpha",
                "correlation_id": "0123456789abcdef0123456789abcdef", "operation_id": "op-authority-0001"
            }),
        ),
        raw_vector(
            "reconcile-absent",
            Direction::Request,
            json!({
                "wire": 2, "kind": "reconcile_operation", "capsule_id": "capsule-beta",
                "correlation_id": "abcdef0123456789abcdef0123456789", "operation_id": "op-authority-missing"
            }),
        ),
        raw_vector(
            "close-drain",
            Direction::Request,
            json!({
                "wire": 2, "kind": "close_capsule", "capsule_id": "capsule-alpha",
                "correlation_id": "11111111111111111111111111111111", "mode": "drain"
            }),
        ),
        raw_vector(
            "close-abort",
            Direction::Request,
            json!({
                "wire": 2, "kind": "close_capsule", "capsule_id": "capsule-beta",
                "correlation_id": "22222222222222222222222222222222", "mode": "abort"
            }),
        ),
        raw_vector(
            "stop-process",
            Direction::Request,
            json!({
                "wire": 2, "kind": "stop_intent", "capsule_id": "capsule-alpha",
                "correlation_id": "33333333333333333333333333333333", "operation_id": "op-authority-0001",
            }),
        ),
        raw_vector(
            "stop-cgroup",
            Direction::Request,
            json!({
                "wire": 2, "kind": "stop_intent", "capsule_id": "capsule-beta",
                "correlation_id": "44444444444444444444444444444444", "operation_id": null,
            }),
        ),
        raw_vector(
            "stop-unit",
            Direction::Request,
            json!({
                "wire": 2, "kind": "stop_intent", "capsule_id": "capsule-beta",
                "correlation_id": "55555555555555555555555555555555", "operation_id": "op-authority-0002",
            }),
        ),
        raw_vector(
            "invoked-basic",
            Direction::Response,
            json!({
                "wire": 2, "kind": "capability_invoked", "capsule_id": "capsule-alpha",
                "correlation_id": "00112233445566778899aabbccddeeff", "operation_id": "op-authority-0001",
                "state": "effect_started", "replay": false
            }),
        ),
        raw_vector(
            "invoked-replay",
            Direction::Response,
            json!({
                "wire": 2, "kind": "capability_invoked", "capsule_id": "capsule-alpha",
                "correlation_id": "102132435465768798a9bacbdcedfe0f", "operation_id": "op-authority-0002",
                "state": "committed", "replay": true
            }),
        ),
        raw_vector(
            "operation-resumed",
            Direction::Response,
            json!({
                "wire": 2, "kind": "operation_resumed", "capsule_id": "capsule-alpha",
                "correlation_id": "ffeeddccbbaa99887766554433221100", "operation_id": "op-authority-0001",
                "state": "effect_started", "replay": false
            }),
        ),
        raw_vector(
            "operation-reconciled-durable",
            Direction::Response,
            json!({
                "wire": 2, "kind": "operation_reconciled", "capsule_id": "capsule-alpha",
                "correlation_id": "0123456789abcdef0123456789abcdef", "operation_id": "op-authority-0001",
                "state": "committed", "replay": true, "evidence": {"kind": "durable", "digest": digest}
            }),
        ),
        raw_vector(
            "operation-reconciled-absent",
            Direction::Response,
            json!({
                "wire": 2, "kind": "operation_reconciled", "capsule_id": "capsule-beta",
                "correlation_id": "abcdef0123456789abcdef0123456789", "operation_id": "op-authority-missing",
                "state": "in_doubt", "replay": false, "evidence": {"kind": "absent"}
            }),
        ),
        raw_vector(
            "capsule-closed-drain",
            Direction::Response,
            json!({
                "wire": 2, "kind": "capsule_closed", "capsule_id": "capsule-alpha",
                "correlation_id": "11111111111111111111111111111111", "drained": "2"
            }),
        ),
        raw_vector(
            "capsule-closed-abort",
            Direction::Response,
            json!({
                "wire": 2, "kind": "capsule_closed", "capsule_id": "capsule-beta",
                "correlation_id": "22222222222222222222222222222222", "drained": U64_MAX_DECIMAL
            }),
        ),
        raw_vector(
            "stop-recorded-requested",
            Direction::Response,
            json!({
                "wire": 2, "kind": "stop_recorded", "capsule_id": "capsule-alpha",
                "correlation_id": "33333333333333333333333333333333", "operation_id": "op-authority-0001", "state": "requested",
                "evidence": {"kind": "process", "pid": 4242, "start_time_ticks": "9007199254740993", "process_group": 4242}
            }),
        ),
        raw_vector(
            "stop-recorded-stopped",
            Direction::Response,
            json!({
                "wire": 2, "kind": "stop_recorded", "capsule_id": "capsule-beta",
                "correlation_id": "44444444444444444444444444444444", "operation_id": null, "state": "stopped",
                "evidence": {"kind": "cgroup", "path": "/user.slice/user-1000.slice/odin.scope", "inode": U64_MAX_DECIMAL}
            }),
        ),
        raw_vector(
            "stop-recorded-failed",
            Direction::Response,
            json!({
                "wire": 2, "kind": "stop_recorded", "capsule_id": "capsule-beta",
                "correlation_id": "55555555555555555555555555555555", "operation_id": "op-authority-0002", "state": "failed",
                "evidence": {"kind": "unit", "unit_name": "odin-worker@capsule-beta.service"}
            }),
        ),
        raw_vector(
            "rejected",
            Direction::Response,
            json!({
                "wire": 2, "kind": "rejected", "code": "authority.denied", "detail": "capability not listed"
            }),
        ),
    ]
}

fn raw_vector(name: &'static str, direction: Direction, message: JsonValue) -> RawVector {
    RawVector {
        name,
        direction,
        message,
    }
}

fn malformed_cases() -> Vec<MalformedCase> {
    let mut deep = JsonValue::Null;
    for _ in 0..34 {
        deep = JsonValue::Array(vec![deep]);
    }
    let deep_message = json!({
        "wire": 2, "kind": "invoke_capability", "capsule_id": "capsule-alpha",
        "correlation_id": "00112233445566778899aabbccddeeff", "capability": "capsule.eval.run",
        "budget": {"requests": "1", "stops": "0", "spend": "1"}, "arguments": deep
    });
    let deep_payload = odin_strict_json::canonicalize(&deep_message)
        .expect("deep malformed test vector serializes");

    vec![
        malformed("unknown-request-kind", Direction::Request, br#"{"kind":"settle","wire":2}"#),
        malformed("missing-wire", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability"}"#),
        malformed("wire-v1", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":1}"#),
        malformed("wire-string", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":"2"}"#),
        malformed("unknown-message-field", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","unknown":true,"wire":2}"#),
        malformed("unknown-budget-field", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1","spend":"1","stops":"0","unknown":"1"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-as-number", Direction::Request, br#"{"arguments":{},"budget":{"requests":9007199254740993,"spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-empty", Direction::Request, br#"{"arguments":{},"budget":{"requests":"","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-leading-zero", Direction::Request, br#"{"arguments":{},"budget":{"requests":"01","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-negative", Direction::Request, br#"{"arguments":{},"budget":{"requests":"-1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-plus", Direction::Request, br#"{"arguments":{},"budget":{"requests":"+1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-terminal-newline", Direction::Request, br#"{"arguments":{},"budget":{"requests":"1\n","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("u64-overflow", Direction::Request, br#"{"arguments":{},"budget":{"requests":"18446744073709551616","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("bad-correlation-id", Direction::Request, br#"{"capsule_id":"capsule-alpha","correlation_id":"ABC","kind":"resume_operation","operation_id":"op-authority-0001","wire":2}"#),
        malformed("bad-correlation-id-terminal-newline", Direction::Request, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff\n","kind":"resume_operation","operation_id":"op-authority-0001","wire":2}"#),
        malformed("bad-capsule-id", Direction::Request, br#"{"capsule_id":"bad/capsule","correlation_id":"00112233445566778899aabbccddeeff","kind":"resume_operation","operation_id":"op-authority-0001","wire":2}"#),
        malformed("bad-capsule-id-terminal-newline", Direction::Request, br#"{"capsule_id":"capsule-alpha\n","correlation_id":"00112233445566778899aabbccddeeff","kind":"resume_operation","operation_id":"op-authority-0001","wire":2}"#),
        malformed("bad-close-mode", Direction::Request, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"close_capsule","mode":"force","wire":2}"#),
        malformed("cgroup-path-terminal-newline", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"inode":"1","kind":"cgroup","path":"/user.slice/odin.scope\n"},"kind":"stop_recorded","operation_id":null,"state":"requested","wire":2}"#),
        malformed("unit-name-terminal-newline", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"kind":"unit","unit_name":"odin.service\n"},"kind":"stop_recorded","operation_id":null,"state":"requested","wire":2}"#),
        malformed("unknown-evidence-kind", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"kind":"pid"},"kind":"stop_recorded","operation_id":null,"state":"requested","wire":2}"#),
        malformed("unknown-evidence-field", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"kind":"absent","pid":42},"kind":"stop_recorded","operation_id":null,"state":"requested","wire":2}"#),
        malformed("bad-cgroup-path", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"inode":"1","kind":"cgroup","path":"/user.slice/../escape"},"kind":"stop_recorded","operation_id":null,"state":"requested","wire":2}"#),
        malformed("argument-float", Direction::Request, br#"{"arguments":{"ratio":1.5},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("argument-unsafe-integer", Direction::Request, br#"{"arguments":{"unsafe":9007199254740992},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("argument-unsafe-negative-integer", Direction::Request, br#"{"arguments":{"unsafe":-9007199254740992},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("argument-u64-max-number", Direction::Request, br#"{"arguments":{"unsafe":18446744073709551615},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        MalformedCase {
            name: "argument-depth",
            direction: Direction::Request,
            payload: deep_payload,
        },
        malformed("duplicate-message-field", Direction::Request, br#"{"capsule_id":"capsule-alpha","capsule_id":"capsule-beta","correlation_id":"00112233445566778899aabbccddeeff","kind":"resume_operation","operation_id":"op-authority-0001","wire":2}"#),
        malformed("duplicate-argument-field", Direction::Request, br#"{"arguments":{"same":1,"same":2},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("lone-high-surrogate", Direction::Request, br#"{"arguments":{"text":"\ud800"},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("lone-low-surrogate", Direction::Request, br#"{"arguments":{"text":"\udc00"},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("reversed-surrogate-pair", Direction::Request, br#"{"arguments":{"text":"\udc00\ud800"},"budget":{"requests":"1","spend":"1","stops":"0"},"capability":"capsule.eval.run","capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","kind":"invoke_capability","wire":2}"#),
        malformed("response-unknown-field", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","drained":"0","extra":true,"kind":"capsule_closed","wire":2}"#),
        malformed("response-u64-as-number", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","drained":0,"kind":"capsule_closed","wire":2}"#),
        malformed("response-bad-digest", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"digest":"abc","kind":"durable"},"kind":"operation_reconciled","operation_id":"op-authority-0001","replay":false,"state":"committed","wire":2}"#),
        malformed("digest-terminal-newline", Direction::Response, br#"{"capsule_id":"capsule-alpha","correlation_id":"00112233445566778899aabbccddeeff","evidence":{"digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n","kind":"durable"},"kind":"operation_reconciled","operation_id":"op-authority-0001","replay":false,"state":"committed","wire":2}"#),
        malformed("rejection-code-terminal-newline", Direction::Response, br#"{"code":"authority.denied\n","detail":"not listed","kind":"rejected","wire":2}"#),
        malformed("invalid-utf8", Direction::Request, &[0xff]),
        malformed("invalid-utf8-sequence", Direction::Request, &[0xc3, 0x28]),
    ]
}

fn malformed(name: &'static str, direction: Direction, payload: &'static [u8]) -> MalformedCase {
    MalformedCase {
        name,
        direction,
        payload: payload.to_vec(),
    }
}

fn complete_vector(raw: RawVector) -> Result<VectorSpec, String> {
    let canonical_bytes = odin_strict_json::canonicalize(&raw.message)
        .map_err(|error| format!("{} failed canonicalization: {error}", raw.name))?;
    let canonical = String::from_utf8(canonical_bytes.clone())
        .map_err(|error| format!("{} canonical bytes are not UTF-8: {error}", raw.name))?;
    let length = u32::try_from(canonical_bytes.len())
        .map_err(|_| format!("{} payload exceeds four-byte framing", raw.name))?;
    let mut frame = Vec::with_capacity(4 + canonical_bytes.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&canonical_bytes);
    Ok(VectorSpec {
        name: raw.name,
        direction: raw.direction,
        message: raw.message,
        canonical,
        frame_hex: odin_types::hash::hex_encode(&frame),
    })
}
