use super::*;

#[test]
fn pinned_discriminants_classify_exactly() {
    let cases: [(&str, FrameClass); 16] = [
        ("response", FrameClass::Response),
        ("ready", FrameClass::Ready),
        ("prompt_result", FrameClass::PromptResult),
        ("available_commands_update", FrameClass::AvailableCommands),
        ("session_info_update", FrameClass::SessionInfo),
        ("config_update", FrameClass::ConfigUpdate),
        ("command_output", FrameClass::CommandOutput),
        ("extension_ui_request", FrameClass::ExtensionUi),
        ("extension_error", FrameClass::ExtensionError),
        ("host_tool_call", FrameClass::HostTool),
        ("host_tool_cancel", FrameClass::HostTool),
        ("host_uri_request", FrameClass::HostUri),
        ("host_uri_cancel", FrameClass::HostUri),
        ("subagent_lifecycle", FrameClass::Subagent),
        ("subagent_progress", FrameClass::Subagent),
        ("subagent_event", FrameClass::Subagent),
    ];
    for (discriminant, expected) in cases {
        assert_eq!(
            classify_frame(&json!({ "type": discriminant })),
            expected,
            "{discriminant}"
        );
    }
}

#[test]
fn pinned_session_events_classify_as_session() {
    // The exact pinned session-event vocabulary (omp @ `eab72e8`):
    // agent/turn/message/tool lifecycles, compaction, retry and fallback,
    // and the session lifecycle notifications.
    let session_events: [&str; 26] = [
        "agent_start",
        "agent_end",
        "turn_start",
        "turn_end",
        "message_start",
        "message_update",
        "message_end",
        "tool_execution_start",
        "tool_execution_update",
        "tool_execution_end",
        "auto_compaction_start",
        "auto_compaction_end",
        "auto_retry_start",
        "auto_retry_end",
        "retry_fallback_applied",
        "retry_fallback_succeeded",
        "ttsr_triggered",
        "todo_reminder",
        "todo_auto_clear",
        "irc_message",
        "notice",
        "thinking_level_changed",
        "model_changed",
        "advisor_cost_changed",
        "goal_updated",
        "session_shutdown",
    ];
    for discriminant in session_events {
        assert_eq!(
            classify_frame(&json!({ "type": discriminant })),
            FrameClass::Session,
            "{discriminant}"
        );
    }
}

#[test]
fn unrecognized_and_typeless_frames_classify_as_unknown() {
    // Conformance case 21: a future frame keeps its fields but never
    // masquerades as a session event.
    assert_eq!(
        classify_frame(&json!({
            "type": "odin_future_frame",
            "sequence": 21,
            "future_field": "retained-byte-exact",
            "nested": { "glyph": "\u{00b5}", "flags": [true, false, null] },
        })),
        FrameClass::Unknown
    );
    // Plausible-but-not-pinned names are futures too.
    assert_eq!(
        classify_frame(&json!({ "type": "turn_planned" })),
        FrameClass::Unknown
    );
    assert_eq!(classify_frame(&json!({ "type": "" })), FrameClass::Unknown);
    // Missing and non-string discriminants are Unknown.
    assert_eq!(classify_frame(&json!({ "id": "x" })), FrameClass::Unknown);
    assert_eq!(classify_frame(&json!({ "type": 7 })), FrameClass::Unknown);
    assert_eq!(
        classify_frame(&json!({ "type": null })),
        FrameClass::Unknown
    );
    assert_eq!(
        classify_frame(&json!({ "type": ["ready"] })),
        FrameClass::Unknown
    );
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

#[test]
fn frame_class_names_are_stable_snake_case_and_unique() {
    let all = [
        FrameClass::Ready,
        FrameClass::Response,
        FrameClass::Session,
        FrameClass::Subagent,
        FrameClass::AvailableCommands,
        FrameClass::ExtensionUi,
        FrameClass::HostTool,
        FrameClass::HostUri,
        FrameClass::PromptResult,
        FrameClass::CommandOutput,
        FrameClass::SessionInfo,
        FrameClass::ConfigUpdate,
        FrameClass::ExtensionError,
        FrameClass::RpcFrameError,
        FrameClass::Unknown,
    ];
    let names: std::collections::BTreeSet<&'static str> =
        all.iter().map(|class| class.as_str()).collect();
    assert_eq!(names.len(), all.len(), "live-event kinds must be unique");
    for name in names {
        assert!(!name.is_empty());
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "live-event kind `{name}` must be snake_case"
        );
    }
}

#[test]
fn observed_frame_retains_exact_bytes_on_both_paths() {
    let frame = decode(b"{\"type\":\"ready\",\"protocols\":[1]}\n");
    let observed = ObservedFrame::decoded(FrameClass::Ready, frame, None);
    assert_eq!(
        observed.value(),
        Some(&json!({ "type": "ready", "protocols": [1] }))
    );
    let reparsed: Value = serde_json::from_slice(&observed.raw()).expect("raw bytes reparse");
    assert_eq!(&reparsed, observed.value().expect("decoded value retained"));

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    let rejection = decoder
        .push_physical_line(b"{\"type\":\"ready\"")
        .expect_err("unterminated line is rejected");
    assert_eq!(rejection.kind(), &RpcFrameErrorKind::MissingNewline);
    let rejected = ObservedFrame::rejected(rejection.clone());
    assert!(rejected.value().is_none());
    let joined: Vec<u8> = rejection.evidence().concat();
    assert_eq!(rejected.raw(), joined, "rejection evidence bytes are exact");
}
