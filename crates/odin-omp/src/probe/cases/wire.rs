//! Wire-shape helpers the case modules share.

use serde_json::Value;

use crate::frames::DecodedRpcFrame;

/// Whether any string leaf of `value` contains `needle`.
pub(super) fn contains_text(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(values) => values.iter().any(|value| contains_text(value, needle)),
        Value::Object(values) => values.values().any(|value| contains_text(value, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// The text of a message: its string content, or its first text block.
pub(super) fn message_text(message: &Value) -> Option<&str> {
    let content = message.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text);
    }
    content.as_array()?.iter().find_map(|block| {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            block.get("text").and_then(Value::as_str)
        } else {
            None
        }
    })
}

/// Every physical line of `frames`, concatenated in arrival order.
pub(super) fn physical_bytes(frames: &[DecodedRpcFrame]) -> Vec<u8> {
    let capacity = frames
        .iter()
        .flat_map(|frame| frame.lines())
        .map(Vec::len)
        .sum();
    let mut bytes = Vec::with_capacity(capacity);
    for line in frames.iter().flat_map(|frame| frame.lines()) {
        bytes.extend_from_slice(line);
    }
    bytes
}
