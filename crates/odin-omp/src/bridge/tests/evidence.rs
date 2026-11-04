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
