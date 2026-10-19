//! JSON-RPC edge cases: exact string ids, the special `status` method, and single-frame encoding.

use odin_adapter_core::ids::OperationKind;
use odin_adapter_core::transport::{
    decode_frame, encode_frame, JsonRpcOutcome, JsonRpcRequest, ProtocolError, RpcMethod,
    StatusParams, MAX_FRAME_BYTES,
};
use serde_json::{json, Value};

fn success_wire(id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null })
}

fn error_wire(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32601, "message": "no such method" },
    })
}

#[test]
fn outcome_echoes_exact_string_id() {
    // The id is opaque: non-ASCII, spacing, everything echoes byte-for-byte.
    let id = "op-42 ⟨séance⟩";
    let outcome = JsonRpcOutcome::from_wire(&success_wire(json!(id)), id)
        .expect("a matching string id parses");
    assert_eq!(outcome.id(), id);
    assert!(matches!(outcome, JsonRpcOutcome::Success { ref result, .. } if result.is_null()));

    let error = JsonRpcOutcome::from_wire(&error_wire(json!(id)), id)
        .expect("the error arm echoes the same id");
    assert_eq!(error.id(), id);
    assert!(matches!(error, JsonRpcOutcome::Error { ref code, .. } if code.code() == -32601));

    // The wire form the codec itself produces re-parses against the same id.
    JsonRpcOutcome::from_wire(&error.to_wire(), id).expect("to_wire output round-trips");
}

#[test]
fn outcome_rejects_mismatched_id() {
    assert_eq!(
        JsonRpcOutcome::from_wire(&success_wire(json!("other")), "req-1"),
        Err(ProtocolError::IdMismatch {
            expected: "req-1".to_owned(),
            found: "other".to_owned(),
        }),
    );
}

#[test]
fn outcome_rejects_nonstring_id() {
    for id in [json!(42), json!(null), json!(["req-1"])] {
        assert_eq!(
            JsonRpcOutcome::from_wire(&success_wire(id), "req-1"),
            Err(ProtocolError::IdNotAString),
        );
    }
}

#[test]
fn status_probe_parses_outside_operation_grammar() {
    // `status` is in the closed method vocabulary though it carries no dot.
    assert_eq!(RpcMethod::parse("status"), Ok(RpcMethod::Status));
    let request: JsonRpcRequest = serde_json::from_value(json!({
        "jsonrpc": "2.0",
        "id": "s1",
        "method": "status",
        "params": {},
    }))
    .expect("status probe with empty params parses");
    assert_eq!(request.method, RpcMethod::Status);
    assert_eq!(request.id, "s1");
    assert_eq!(StatusParams::from_wire(&request.params), Ok(StatusParams));

    // The probe is exactly `status`; every other wire method must carry
    // the dotted operation-kind grammar, and undotted names are unknown.
    assert_eq!(
        RpcMethod::parse("status.health"),
        Ok(RpcMethod::Operation(
            OperationKind::new("status.health").expect("dotted kind parses")
        ))
    );
    assert_eq!(
        RpcMethod::parse("unknown"),
        Err(ProtocolError::UnknownMethod("unknown".to_owned()))
    );
    // Status params are exactly the empty object.
    assert_eq!(
        StatusParams::from_wire(&json!({ "detail": "x" })),
        Err(ProtocolError::StatusParamsNotEmpty),
    );
}

#[test]
fn framing_rejects_extra_frame_and_oversize() {
    // Two frames in one read carry an embedded newline: rejected.
    assert_eq!(
        decode_frame(b"{}\n{}\n"),
        Err(ProtocolError::EmbeddedNewline)
    );
    // Size rejection precedes JSON validation.
    let mut oversize = vec![b'a'; MAX_FRAME_BYTES];
    oversize.push(b'\n');
    assert_eq!(
        decode_frame(&oversize),
        Err(ProtocolError::FrameTooLarge {
            size: MAX_FRAME_BYTES + 1,
            max: MAX_FRAME_BYTES,
        }),
    );

    let frame = encode_frame(&json!({ "b": 2, "a": 1 })).expect("small frame encodes");
    assert_eq!(&frame[..frame.len() - 1], br#"{"a":1,"b":2}"#);
    assert_eq!(decode_frame(&frame), Ok(json!({ "a": 1, "b": 2 })));
}
