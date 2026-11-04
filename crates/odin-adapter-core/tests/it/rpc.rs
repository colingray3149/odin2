//! JSON-RPC edge cases: exact string ids, the special `status` method, and single-frame encoding.

use odin_adapter_core::transport::{
    decode_frame, encode_frame, JsonRpcOutcome, ProtocolError, MAX_FRAME_BYTES,
};
use serde_json::{json, Value};

fn success_wire(id: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": Value::Null })
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
