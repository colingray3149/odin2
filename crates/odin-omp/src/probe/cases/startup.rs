//! Case module `startup` — cold-start handshake conformance.
//!
//! Owns case 1 of the frozen conformance suite: start with no session,
//! receive the exact `ready` frame,
//! negotiate protocol v2, and record the protocol versions and the
//! physical/reassembled frame limits. Auxiliary frames interleaved inside the
//! negotiation window are retained evidence: allowed only between the ready
//! and negotiation frames, bounded, and classified by the production frame
//! classifier.

mod case;
mod evidence;

use std::sync::Arc;

use crate::frames::MAX_FRAME_BYTES;
use crate::probe::{ConformanceCase, ConformanceCaseId};

use self::case::ReadyStartup;

/// Case 1 — start with no session and receive the ready frame; record
/// protocol versions and physical/reassembled frame limits.
pub const READY_STARTUP: ConformanceCaseId = ConformanceCaseId::new(1);

/// Case-local bound on retained startup auxiliary frames, mirroring the
/// production retention cap (`STARTUP_AUX_FRAME_CAP` in `process`): the case
/// bounds the negotiation window independently instead of trusting it.
const MAX_STARTUP_AUX_FRAMES: usize = 256;
/// Case-local bound on the logical bytes retained by startup auxiliary
/// frames, mirroring the production retention cap (`STARTUP_AUX_BYTE_CAP`).
const MAX_STARTUP_AUX_BYTES: usize = 4 * MAX_FRAME_BYTES;

/// The module's registration slot.
pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![Arc::new(ReadyStartup)]
}

#[cfg(test)]
mod tests {
    use super::evidence::{is_chunk_frame, validate_startup_transcript};
    use super::*;
    use crate::bridge::{classify_frame, FrameClass};
    use crate::frames::{
        DecodedRpcFrame, RpcFrameDecoder, RpcProtocolVersion, MAX_FRAME_BYTES,
        MAX_REASSEMBLED_BYTES,
    };
    use crate::process::NEGOTIATE_REQUEST_ID;
    use serde_json::json;

    /// Decodes one complete v1-framed line through the real decoder boundary.
    fn decode_line(line: &str) -> DecodedRpcFrame {
        let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
        decoder
            .push_physical_line(format!("{line}\n").as_bytes())
            .expect("fixture line decodes")
            .expect("fixture line completes a frame")
    }

    /// The exact pinned ready frame.
    fn ready_fixture() -> DecodedRpcFrame {
        decode_line(
            &json!({
                "type": "ready",
                "protocolVersion": 1,
                "supportedProtocolVersions": [1, 2],
                "maxFrameBytes": MAX_FRAME_BYTES,
                "maxReassembledFrameBytes": MAX_REASSEMBLED_BYTES,
            })
            .to_string(),
        )
    }

    /// The exact pinned v2 negotiation response.
    fn negotiation_fixture() -> DecodedRpcFrame {
        decode_line(
            &json!({
                "id": NEGOTIATE_REQUEST_ID,
                "type": "response",
                "command": "negotiate_protocol",
                "success": true,
                "data": {"protocolVersion": 2},
            })
            .to_string(),
        )
    }

    /// The real pinned startup auxiliaries observed inside the negotiation
    /// window: an `extension_ui_request` and a `session_info_update`.
    fn extension_ui_fixture() -> DecodedRpcFrame {
        decode_line(
            r#"{"type":"extension_ui_request","id":"ui-1","method":"setStatus","params":{"text":"loading"}}"#,
        )
    }

    fn session_info_fixture() -> DecodedRpcFrame {
        decode_line(r#"{"type":"session_info_update","info":{"cwd":"/pinned","model":"default"}}"#)
    }

    #[test]
    fn startup_transcript_accepts_real_pinned_auxiliary_frames() {
        let ready = ready_fixture();
        let extension_ui = extension_ui_fixture();
        let session_info = session_info_fixture();
        let negotiation = negotiation_fixture();
        let transcript = vec![
            ready.clone(),
            extension_ui.clone(),
            session_info.clone(),
            negotiation.clone(),
        ];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(
            failures.is_empty(),
            "real pinned startup auxiliaries conform: {failures:?}"
        );
        // All auxiliaries ride in one aggregate artifact with their exact
        // physical bytes, in arrival order.
        assert_eq!(evidence.len(), 1, "{evidence:?}");
        let artifact = &evidence[0];
        assert_eq!(artifact.kind, "startup_auxiliary");
        assert_eq!(artifact.label, "startup-aux.raw.jsonl");
        let mut expected = extension_ui.lines()[0].clone();
        expected.extend_from_slice(&session_info.lines()[0]);
        assert_eq!(artifact.bytes, expected);
    }

    #[test]
    fn startup_transcript_accepts_bare_v2_and_v1_handshakes() {
        let ready = ready_fixture();
        let negotiation = negotiation_fixture();

        // v2 with zero interleaved auxiliaries: ready, then negotiation.
        let transcript = vec![ready.clone(), negotiation.clone()];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(evidence.iter().all(|item| item.kind != "startup_auxiliary"));

        // v1 runs no negotiation: the transcript is exactly the ready frame.
        let transcript = vec![ready.clone()];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            None,
            &mut evidence,
            &mut failures,
        );
        assert!(failures.is_empty(), "{failures:?}");
        assert!(evidence.is_empty());
    }

    #[test]
    fn startup_transcript_rejects_negotiation_response_in_auxiliary_position() {
        let ready = ready_fixture();
        let negotiation = negotiation_fixture();
        let session_info = session_info_fixture();
        // The response closed the window before the auxiliary frame arrived.
        let transcript = vec![ready.clone(), negotiation.clone(), session_info];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_transcript"
                    && failure.detail.contains("last retained frame")),
            "wrong response position fails the ordering anchor: {failures:?}"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_auxiliary"
                    && failure.detail.contains("is a response")),
            "the misplaced response fails auxiliary classification: {failures:?}"
        );
    }

    #[test]
    fn startup_transcript_rejects_extra_frames_when_no_negotiation_ran() {
        let ready = ready_fixture();
        let session_info = session_info_fixture();
        let transcript = vec![ready.clone(), session_info];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            None,
            &mut evidence,
            &mut failures,
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].check, "startup_transcript");
        assert!(
            failures[0]
                .detail
                .contains("expected exactly the ready frame"),
            "{failures:?}"
        );
    }

    #[test]
    fn startup_auxiliary_rejects_ready_and_response_frames() {
        let ready = ready_fixture();
        let negotiation = negotiation_fixture();
        for (intruder, detail) in [
            (ready_fixture(), "is a second ready frame"),
            (negotiation_fixture(), "is a response"),
        ] {
            let transcript = vec![ready.clone(), intruder, negotiation.clone()];
            let mut evidence = Vec::new();
            let mut failures = Vec::new();
            validate_startup_transcript(
                &transcript,
                Some(&ready),
                Some(&negotiation),
                &mut evidence,
                &mut failures,
            );
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.check == "startup_auxiliary"
                        && failure.detail.contains(detail)),
                "expected {detail:?}: {failures:?}"
            );
        }
    }

    #[test]
    fn startup_auxiliary_rejects_frames_outside_the_production_vocabulary() {
        let ready = ready_fixture();
        let negotiation = negotiation_fixture();
        let future = decode_line(r#"{"type":"odin_future_frame","sequence":21}"#);
        let transcript = vec![ready.clone(), future, negotiation.clone()];
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_auxiliary"
                    && failure
                        .detail
                        .contains("not classified by the production frame classifier")),
            "{failures:?}"
        );
    }

    #[test]
    fn startup_auxiliary_chunk_guard_matches_the_chunk_discriminant() {
        // The production decoder never yields chunk frames (v1 rejects them,
        // v2 absorbs them into reassembly), so no `DecodedRpcFrame` fixture
        // can carry one; the guard is pinned at the value level, on the
        // discriminant the production classifier maps to Unknown.
        let chunk = json!({
            "type": "rpc_chunk",
            "chunkId": "c",
            "index": 0,
            "count": 2,
            "byteLength": 2 * MAX_FRAME_BYTES,
            "data": "AA==",
        });
        assert_eq!(classify_frame(&chunk), FrameClass::Unknown);
        assert!(is_chunk_frame(&chunk));
        assert!(!is_chunk_frame(&json!({"type": "session_info_update"})));
    }

    #[test]
    fn startup_auxiliary_count_and_bytes_are_bounded() {
        let ready = ready_fixture();
        let negotiation = negotiation_fixture();

        // One frame beyond the retained-window count cap.
        let mut transcript = vec![ready.clone()];
        transcript.extend((0..=MAX_STARTUP_AUX_FRAMES).map(|index| {
            decode_line(&format!(
                r#"{{"type":"extension_ui_request","id":"ui-{index}"}}"#
            ))
        }));
        transcript.push(negotiation.clone());
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_auxiliary"
                    && failure.detail.contains("at most 256")),
            "{failures:?}"
        );
        // Evidence stays bounded: one aggregate artifact retains the exact
        // physical bytes of the in-cap window, in arrival order.
        assert_eq!(evidence.len(), 1, "{evidence:?}");
        let artifact = &evidence[0];
        assert_eq!(artifact.kind, "startup_auxiliary");
        assert_eq!(artifact.label, "startup-aux.raw.jsonl");
        let mut expected = Vec::new();
        for frame in &transcript[1..=MAX_STARTUP_AUX_FRAMES] {
            for line in frame.lines() {
                expected.extend_from_slice(line);
            }
        }
        assert_eq!(artifact.bytes, expected);

        // Five frames just under the physical ceiling overflow the byte cap
        // without tripping the count cap.
        let mut transcript = vec![ready.clone()];
        transcript.extend((0..5).map(|index| {
            decode_line(&format!(
                r#"{{"type":"extension_ui_request","id":"ui-{index}","data":"{}"}}"#,
                "x".repeat(MAX_FRAME_BYTES - 512)
            ))
        }));
        transcript.push(negotiation.clone());
        let mut evidence = Vec::new();
        let mut failures = Vec::new();
        validate_startup_transcript(
            &transcript,
            Some(&ready),
            Some(&negotiation),
            &mut evidence,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_auxiliary"
                    && failure.detail.contains("logical bytes")),
            "{failures:?}"
        );
        assert!(
            !failures
                .iter()
                .any(|failure| failure.detail.contains("at most 256")),
            "{failures:?}"
        );
        // Overflow must be refused rather than persisted in the aggregate artifact.
        assert!(
            failures
                .iter()
                .any(|failure| failure.check == "startup_auxiliary"
                    && failure.detail.contains("bounded artifact allowance")),
            "{failures:?}"
        );
        assert!(evidence.is_empty(), "{evidence:?}");
    }
}
