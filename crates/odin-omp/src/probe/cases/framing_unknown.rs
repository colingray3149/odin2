//! Cases 2 and 21: protocol-v2 framing and unknown-frame retention.
//!
//! The pinned OMP child supplies the successful oversized response. The
//! transport fixture is reserved for byte sequences a conforming peer cannot
//! emit: corrupt chunk trains, over-ceiling lines, invalid reassembled UTF-8,
//! and an unknown future object.

mod protocol;
mod unknown;

use std::sync::Arc;

use serde_json::Value;

use crate::frames::{DecodedRpcFrame, CHUNK_PAYLOAD_BYTES, MAX_FRAME_BYTES};
use crate::probe::{
    CaseEvidence, CaseFailure, CaseOutcome, CleanupReceipt, ConformanceCase, ConformanceCaseId,
    RawRpcDriver, MAX_EVIDENCE_ARTIFACT_BYTES,
};

use self::protocol::ProtocolReassemblyCase;
use self::unknown::UnknownFrameEvidenceCase;

/// Case 2 — negotiate v2 and prove strict, bounded oversized-frame handling.
pub const PROTOCOL_REASSEMBLY: ConformanceCaseId = ConformanceCaseId::new(2);

/// Case 21 — retain one unknown future object byte- and field-exactly.
pub const UNKNOWN_FRAME_EVIDENCE: ConformanceCaseId = ConformanceCaseId::new(21);

const BIG_REPLY_BYTES: usize = MAX_FRAME_BYTES + CHUNK_PAYLOAD_BYTES;
/// Seed of the shared deterministic payload generator (the TS fixture's twin).
const PAYLOAD_SEED: u32 = 0x6d2b_79f5;
/// Output alphabet of the shared generator, indexed by `state % 62`.
const PAYLOAD_ALPHABET: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const MAX_PATTERN_NODES: usize = 4_096;

/// The module's two fixed registration slots.
pub fn cases() -> Vec<Arc<dyn ConformanceCase>> {
    vec![
        Arc::new(ProtocolReassemblyCase) as Arc<dyn ConformanceCase>,
        Arc::new(UnknownFrameEvidenceCase),
    ]
}

/// The exact deterministic payload the TS fixture emits for the
/// `odin-mock:big` directive: xorshift32 advanced once per byte from the
/// shared seed, rendered through [`PAYLOAD_ALPHABET`] at `state % 62`. u32
/// wrapping matches the TS bitwise semantics, output is pure ASCII (byte
/// length equals string length), and the sequence is deterministic and
/// prefix-stable: `payload_bytes(n)` always equals the first `n` bytes of
/// `payload_bytes(m)` for `n <= m`.
fn payload_bytes(length: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(length);
    let mut state = PAYLOAD_SEED;
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        payload.push(PAYLOAD_ALPHABET[(state % 62) as usize]);
    }
    payload
}

/// True when some string in `root` is byte-for-byte `payload` — full-content
/// equality, never a substring match. The walk stays bounded by
/// [`MAX_PATTERN_NODES`] visited nodes.
fn contains_big_payload(root: &Value, payload: &[u8]) -> bool {
    let mut stack = Vec::with_capacity(32);
    stack.push(root);
    let mut visited = 0usize;
    while let Some(value) = stack.pop() {
        visited += 1;
        if visited > MAX_PATTERN_NODES {
            return false;
        }
        match value {
            Value::String(text) => {
                if text.as_bytes() == payload {
                    return true;
                }
            }
            Value::Array(items) => {
                let remaining = MAX_PATTERN_NODES.saturating_sub(stack.len());
                stack.extend(items.iter().take(remaining));
            }
            Value::Object(fields) => {
                let remaining = MAX_PATTERN_NODES.saturating_sub(stack.len());
                stack.extend(fields.values().take(remaining));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    false
}

fn response_success(frame: &DecodedRpcFrame, request_id: &str, command: &str) -> bool {
    let value = frame.value();
    value.get("type").and_then(Value::as_str) == Some("response")
        && value.get("id").and_then(Value::as_str) == Some(request_id)
        && value.get("command").and_then(Value::as_str) == Some(command)
        && value.get("success").and_then(Value::as_bool) == Some(true)
}

fn response_failure_detail(frame: &DecodedRpcFrame, request_id: &str, command: &str) -> String {
    let value = frame.value();
    format!(
        "expected successful {command} response id {request_id}; observed type={:?}, id={:?}, command={:?}, success={:?}",
        value.get("type").and_then(Value::as_str),
        value.get("id").and_then(Value::as_str),
        value.get("command").and_then(Value::as_str),
        value.get("success").and_then(Value::as_bool),
    )
}

fn retain_raw(
    frame: &DecodedRpcFrame,
    kind: &'static str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    if frame.raw().len() > MAX_EVIDENCE_ARTIFACT_BYTES {
        fail(
            failures,
            "evidence_bound",
            format!(
                "{label} logical evidence was {} bytes, above the per-artifact bound",
                frame.raw().len()
            ),
        );
        return;
    }
    evidence.push(CaseEvidence {
        kind,
        label: label.to_owned(),
        bytes: frame.raw().to_vec(),
    });
}

fn retain_lines(
    lines: &[Vec<u8>],
    kind: &'static str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) {
    let mut total = 0usize;
    for line in lines {
        let Some(next) = total.checked_add(line.len()) else {
            fail(
                failures,
                "evidence_bound",
                format!("{label} physical evidence length overflowed usize"),
            );
            return;
        };
        if next > MAX_EVIDENCE_ARTIFACT_BYTES {
            fail(
                failures,
                "evidence_bound",
                format!("{label} physical evidence exceeded the per-artifact bound"),
            );
            return;
        }
        total = next;
    }
    let mut bytes = Vec::with_capacity(total);
    for line in lines {
        bytes.extend_from_slice(line);
    }
    evidence.push(CaseEvidence {
        kind,
        label: label.to_owned(),
        bytes,
    });
}

async fn cleanup_driver(
    driver: &mut RawRpcDriver,
    cleanup: &mut CleanupReceipt,
    subject: &str,
    failures: &mut Vec<CaseFailure>,
) {
    let before = cleanup.steps.len();
    if let Err(error) = driver.cleanup(cleanup, subject.to_owned()).await {
        fail(
            failures,
            "bounded_cleanup",
            format!("{subject} cleanup failed: {error}"),
        );
    }
    if cleanup.steps.len() != before + 1 {
        fail(
            failures,
            "cleanup_evidence",
            format!("{subject} cleanup did not produce exactly one receipt"),
        );
    }
}

fn finish_case(
    mut failures: Vec<CaseFailure>,
    evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
    started_children: usize,
    minimum_evidence: usize,
    pass_summary: &'static str,
    fail_summary: &'static str,
) -> CaseOutcome {
    if evidence.len() < minimum_evidence {
        fail(
            &mut failures,
            "required_evidence",
            format!(
                "retained {} evidence artifacts; at least {minimum_evidence} were required",
                evidence.len()
            ),
        );
    }
    if cleanup.steps.len() != started_children {
        fail(
            &mut failures,
            "cleanup_evidence",
            format!(
                "{} children started but {} cleanup receipts were retained",
                started_children,
                cleanup.steps.len()
            ),
        );
    }
    if !cleanup.is_clean() {
        fail(
            &mut failures,
            "bounded_cleanup",
            "one or more child processes left a failed cleanup receipt",
        );
    }

    let mut outcome = if failures.is_empty() {
        CaseOutcome::pass(pass_summary)
    } else {
        CaseOutcome::fail(fail_summary, failures)
    };
    outcome.evidence = evidence;
    outcome.cleanup = cleanup;
    outcome
}

fn fail(failures: &mut Vec<CaseFailure>, check: &'static str, detail: impl Into<String>) {
    failures.push(CaseFailure {
        check: check.to_owned(),
        detail: detail.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The TS fixture's pinned first 64 payload characters: the shared seed,
    /// shifts, and alphabet must reproduce them byte-for-byte.
    const TS_PAYLOAD_PREFIX_64: &[u8; 64] =
        b"JbQx4pMl6u5eeZbSQg12t6C1LLpRNLiuYtgRCJ0bFJ0zh2p2euzeq7MDOYbDi0NG";

    #[test]
    fn payload_first_64_bytes_match_ts_fixture() {
        assert_eq!(payload_bytes(64), TS_PAYLOAD_PREFIX_64.to_vec());
        assert_eq!(
            &payload_bytes(BIG_REPLY_BYTES)[..64],
            TS_PAYLOAD_PREFIX_64.as_slice()
        );
    }

    #[test]
    fn payload_generation_is_deterministic() {
        let payload = payload_bytes(BIG_REPLY_BYTES);
        assert_eq!(payload.len(), BIG_REPLY_BYTES);
        assert_eq!(payload, payload_bytes(BIG_REPLY_BYTES));
        // Pure ASCII over the shared alphabet: byte length equals string length.
        assert!(payload.iter().all(|byte| PAYLOAD_ALPHABET.contains(byte)));
    }

    #[test]
    fn payload_is_prefix_stable() {
        let full = payload_bytes(BIG_REPLY_BYTES);
        for length in [0, 1, 63, 64, 65, CHUNK_PAYLOAD_BYTES, BIG_REPLY_BYTES - 1] {
            assert_eq!(payload_bytes(length), &full[..length]);
        }
    }

    #[test]
    fn verifier_demands_exact_payload_bytes() {
        let payload = payload_bytes(BIG_REPLY_BYTES);
        let exact = Value::String(String::from_utf8(payload.clone()).expect("alphabet is ascii"));
        assert!(contains_big_payload(&exact, &payload));

        // One mutated byte is rejected: the match is byte-for-byte.
        let mut corrupted = payload.clone();
        corrupted[0] = b'#';
        let mutated = Value::String(String::from_utf8(corrupted).expect("mutation stays ascii"));
        assert!(!contains_big_payload(&mutated, &payload));

        // Length mismatches in either direction are rejected, never
        // substring-matched.
        let truncated = Value::String(
            String::from_utf8(payload[..BIG_REPLY_BYTES - 1].to_vec()).expect("alphabet is ascii"),
        );
        assert!(!contains_big_payload(&truncated, &payload));
        let mut extended = payload.clone();
        extended.push(b'x');
        let padded = Value::String(String::from_utf8(extended).expect("padding stays ascii"));
        assert!(!contains_big_payload(&padded, &payload));

        assert!(!contains_big_payload(&Value::Null, &payload));
    }
}
