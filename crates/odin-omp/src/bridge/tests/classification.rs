use super::*;

#[test]
fn frames_classify_by_their_type() {
    for (frame, expected) in [
        (json!({"type": "response"}), FrameClass::Response),
        (
            json!({"type": "extension_ui_request"}),
            FrameClass::ExtensionUi,
        ),
        (json!({"type": "host_tool_call"}), FrameClass::HostTool),
        (json!({"type": "host_uri_cancel"}), FrameClass::HostUri),
        (json!({"type": "subagent_progress"}), FrameClass::Subagent),
        (json!({"type": "agent_end"}), FrameClass::Session),
        (json!({"type": "session_shutdown"}), FrameClass::Session),
        // A future frame keeps its fields but never masquerades as a session event.
        (
            json!({"type": "odin_future_frame", "sequence": 21}),
            FrameClass::Unknown,
        ),
        (json!({"type": "turn_planned"}), FrameClass::Unknown),
        (json!({"id": "x"}), FrameClass::Unknown),
        (json!({"type": 7}), FrameClass::Unknown),
    ] {
        assert_eq!(classify_frame(&frame), expected, "{frame}");
    }
}

#[test]
fn unknown_frame_retains_exact_bytes_through_observation() {
    // The case-21 fixture through the real decode boundary: the class is
    // Unknown while every raw byte and future field survives observation.
    const RAW: &str = r#"{"type":"odin_future_frame","sequence":21,"future_field":"retained-byte-exact","nested":{"glyph":"\u00b5","flags":[true,false,null]}}"#;
    let mut line = RAW.as_bytes().to_vec();
    line.push(b'\n');
    let frame = decode(&line);
    assert_eq!(classify_frame(frame.value()), FrameClass::Unknown);
    let observed = ObservedFrame::decoded(FrameClass::Unknown, frame, None);
    let raw = observed.raw();
    assert_eq!(raw, RAW.as_bytes(), "logical bytes are exact");
    let value = observed.value().expect("unknown frame keeps its value");
    assert_eq!(
        value,
        &json!({
            "type": "odin_future_frame",
            "sequence": 21,
            "future_field": "retained-byte-exact",
            "nested": { "glyph": "\u{00b5}", "flags": [true, false, null] },
        }),
        "every future field is retained"
    );
    let reparsed: Value = serde_json::from_slice(&raw).expect("raw bytes reparse");
    assert_eq!(&reparsed, value, "raw bytes reparse to the retained value");
}
