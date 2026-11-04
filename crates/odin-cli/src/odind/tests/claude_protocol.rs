use super::*;

const LOCAL: &str = "c4a8befa-df86-4972-a31f-bc583557f174";

fn protocol(rc: bool) -> ClaudeProtocol {
    ClaudeProtocol::new(LOCAL, rc, ProtocolLimits::default()).unwrap()
}

// Envelope nesting follows Claude Code's `.claude-wrapped` writer, not this parser.
fn success(id: &str, payload: Value) -> Vec<u8> {
    encode(json!({"type":"control_response","response":{
        "subtype":"success","request_id":id,"response":payload}}))
    .unwrap()
}

fn bridge() -> Value {
    json!({"session_url":"https://claude.ai/code/bridge-42",
        "connect_url":"https://claude.ai/code/connect/env-1",
        "environment_id":"env-1","bridge_epoch":7,"bridge_session_id":"bridge-42"})
}

fn feed(peer: &mut ClaudeProtocol, bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        offset += peer.ingest(&bytes[offset..]).unwrap();
    }
}

fn ready(peer: &mut ClaudeProtocol, rc: bool) {
    let init: Value = serde_json::from_slice(&peer.initialize().unwrap()).unwrap();
    assert_eq!(init["request"]["subtype"], "initialize");
    feed(peer, &success("odin-init-1", json!({})));
    if rc {
        assert!(!peer.is_ready());
        let request: Value =
            serde_json::from_slice(&peer.enable_remote_control("test").unwrap()).unwrap();
        assert_eq!(request["request"]["subtype"], "remote_control");
        assert!(peer.remote_control().is_none());
        feed(peer, &success("odin-rc-1", bridge()));
    }
    assert!(peer.is_ready());
}

#[test]
fn single_loop_init_remote_control_prompt_and_transcript() {
    let mut peer = protocol(true);
    assert!(matches!(
        peer.prompt("too early"),
        Err(ProtocolError::InvalidState)
    ));
    ready(&mut peer, true);
    let metadata = peer.remote_control().unwrap();
    assert_eq!(metadata.local_session_id, LOCAL);
    assert_eq!(metadata.bridge_session_id, "bridge-42");
    assert_ne!(metadata.local_session_id, metadata.bridge_session_id);
    let args = peer.launch_args();
    assert!(args.windows(2).any(|pair| pair == ["--session-id", LOCAL]));
    assert!(!args
        .iter()
        .any(|arg| arg == "--resume" || arg == "--remote-control"));
    let prompt = peer.prompt("one\ntwo \"quoted\" \u{0005}").unwrap();
    assert_eq!(prompt.iter().filter(|byte| **byte == b'\n').count(), 1);
    let prompt: Value = serde_json::from_slice(&prompt).unwrap();
    assert_eq!(prompt["session_id"], "default");
    assert_eq!(prompt["message"]["content"], "one\ntwo \"quoted\" \u{0005}");
    for event in [
        json!({"type":"system","subtype":"init","session_id":LOCAL}),
        json!({"type":"system","subtype":"bridge_state","session_id":LOCAL,"state":"connected"}),
        json!({"type":"assistant","session_id":LOCAL,"message":{"content":[]}}),
        json!({"type":"result","session_id":LOCAL,"is_error":true,"result":"tool failed"}),
    ] {
        let bytes = encode(event).unwrap();
        for byte in &bytes {
            feed(&mut peer, &[*byte]);
        }
    }
    let mut cursor = 0;
    while let Some(event) = peer.pop_event() {
        cursor += 1;
        assert_eq!(event.cursor, cursor);
        if cursor == 6 {
            assert_eq!(event.event["is_error"], true);
        }
    }
    assert_eq!(cursor, 6);
    assert!(peer.prompt("same conversation again").is_ok());
}

#[test]
fn rejected_or_uncorrelated_controls_never_claim_remote_control() {
    for frame in [
        success("wrong-id", bridge()),
        encode(
            json!({"type":"control_response","response":{"subtype":"error",
            "request_id":"odin-rc-1","error":"unsupported"}}),
        )
        .unwrap(),
        success("odin-rc-1", json!({})),
        success("odin-rc-1", {
            let mut p = bridge();
            p["session_url"] = json!("http://bad.example");
            p
        }),
    ] {
        let mut peer = protocol(true);
        peer.initialize().unwrap();
        feed(&mut peer, &success("odin-init-1", json!({})));
        peer.enable_remote_control("test").unwrap();
        assert!(peer.ingest(&frame).is_err());
        assert!(!peer.is_ready());
        assert!(peer.remote_control().is_none());
        assert_eq!(peer.ingest(b"{}\n"), Err(ProtocolError::Failed));
    }
}

#[test]
fn bounds_backpressure_and_partial_frames_are_lossless() {
    let limits = ProtocolLimits {
        max_line_bytes: 128,
        max_queued_bytes: 128,
        max_queued_events: 1,
        max_prompt_bytes: 8,
    };
    let mut peer = ClaudeProtocol::new(LOCAL, false, limits).unwrap();
    peer.initialize().unwrap();
    let response = success("odin-init-1", json!({}));
    feed(&mut peer, &response[..5]);
    feed(&mut peer, &response[5..]);
    assert_eq!(
        peer.ingest(b"{\"type\":\"assistant\"}\n"),
        Err(ProtocolError::Backpressure)
    );
    assert_eq!(peer.pop_event().unwrap().cursor, 1);
    let two = b"{\"type\":\"assistant\"}\n{\"type\":\"result\"}\n";
    let count = peer.ingest(two).unwrap();
    assert!(count < two.len());
    assert_eq!(peer.pop_event().unwrap().cursor, 2);
    feed(&mut peer, &two[count..]);
    assert_eq!(peer.pop_event().unwrap().cursor, 3);
    assert_eq!(peer.prompt("123456789"), Err(ProtocolError::PromptTooLarge));
    assert_eq!(
        peer.ingest(&[b'x'; 129]),
        Err(ProtocolError::OutputTooLarge)
    );
}

#[test]
fn malformed_eof_and_wrong_session_are_typed_terminal_failures() {
    let mut peer = protocol(false);
    assert_eq!(peer.eof(), Err(ProtocolError::UnexpectedEof));
    let mut peer = protocol(false);
    feed(&mut peer, b"{\"type\":");
    assert_eq!(peer.eof(), Err(ProtocolError::PartialLine));
    let mut peer = protocol(false);
    assert!(matches!(
        peer.ingest(b"not json\n"),
        Err(ProtocolError::Malformed(_))
    ));
    let mut peer = protocol(false);
    assert!(matches!(
        peer.ingest(b"\xff\n"),
        Err(ProtocolError::Malformed(_))
    ));
    let mut peer = protocol(false);
    assert_eq!(
        peer.ingest(b"{\"type\":\"assistant\",\"session_id\":\"other\"}\n"),
        Err(ProtocolError::SessionMismatch)
    );
    let mut peer = protocol(false);
    assert_eq!(
        peer.ingest(b"{\"type\":\"control_request\"}\n"),
        Err(ProtocolError::UnsupportedControlRequest)
    );
}

#[test]
fn restart_replays_log_without_writing_to_live_conversation() {
    let mut original = protocol(true);
    ready(&mut original, true);
    feed(
        &mut original,
        &encode(json!({"type":"assistant","session_id":LOCAL})).unwrap(),
    );
    let mut journal = Vec::new();
    while let Some(event) = original.pop_event() {
        journal.extend(encode(event.event).unwrap());
    }
    let mut restored = protocol(true);
    let _unsent = restored.initialize().unwrap();
    let mut offset = 0;
    while offset < journal.len() {
        offset += restored.ingest(&journal[offset..]).unwrap();
        if restored.is_initialized() && !restored.is_ready() && restored.phase == Phase::Initialized
        {
            let _unsent = restored.enable_remote_control("test").unwrap();
        }
    }
    assert!(restored.is_ready());
    assert_eq!(
        restored.remote_control().unwrap().bridge_session_id,
        "bridge-42"
    );
    let events: Vec<_> = std::iter::from_fn(|| restored.pop_event()).collect();
    assert_eq!(events.last().unwrap().cursor, 3);
}
