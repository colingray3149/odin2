use super::*;

/// Per-token session updates are live-only. The finished message, tools,
/// and an unrecognized class with the same type string stay durable.
#[test]
fn per_token_session_updates_are_not_durable_observations() {
    let update = ObservedFrame::decoded(
        FrameClass::Session,
        decode(b"{\"type\":\"message_update\",\"delta\":\"x\"}\n"),
        None,
    );
    assert!(ephemeral_token_update(&update));
    let end = ObservedFrame::decoded(
        FrameClass::Session,
        decode(b"{\"type\":\"message_end\",\"message\":{\"role\":\"assistant\"}}\n"),
        None,
    );
    assert!(!ephemeral_token_update(&end));
    let tool = ObservedFrame::decoded(
        FrameClass::Session,
        decode(b"{\"type\":\"tool_execution_update\",\"toolName\":\"read\"}\n"),
        None,
    );
    assert!(!ephemeral_token_update(&tool));
    let unknown = ObservedFrame::decoded(
        FrameClass::Unknown,
        decode(b"{\"type\":\"message_update\",\"delta\":\"x\"}\n"),
        None,
    );
    assert!(
        !ephemeral_token_update(&unknown),
        "an unrecognized class is not a session token row"
    );
}

/// Streaming snapshots are omitted from journal payloads; persistence skips token rows entirely.
#[test]
fn streaming_updates_are_journaled_without_the_accumulated_message() {
    let snapshot = json!({ "role": "assistant", "content": [{ "type": "text", "text": "long answer so far" }] });
    let update = json!({
        "type": "message_update",
        "message": snapshot,
        "assistantMessageEvent": { "type": "text_delta", "contentIndex": 0, "delta": "far", "partial": snapshot },
    });
    assert_eq!(
        journaled_frame(FrameClass::Session, &update),
        json!({
            "type": "message_update",
            "assistantMessageEvent": { "type": "text_delta", "contentIndex": 0, "delta": "far" },
        })
    );
    let end = json!({ "type": "message_end", "message": snapshot });
    assert_eq!(journaled_frame(FrameClass::Session, &end), end);
    assert_eq!(journaled_frame(FrameClass::Unknown, &update), update);
}
