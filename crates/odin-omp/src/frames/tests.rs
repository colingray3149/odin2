//! Physical and reassembled frame bounds, malformed input and protocol transitions.

use super::*;

/// JSON object prefix of [`multibyte_payload`], 23 bytes.
const OPENING: &[u8] = b"{\"type\":\"demo\",\"text\":\"";
const E_ACCENT: [u8; 2] = [0xC3, 0xA9]; // 'é' in UTF-8

/// One physical line: exact wire bytes including the required terminating newline.
fn physical(line: &str) -> Vec<u8> {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

fn chunk_line(chunk_id: &str, index: u64, count: u64, byte_length: u64, data: &str) -> Vec<u8> {
    physical(
        &serde_json::json!({
            "type": "rpc_chunk",
            "chunkId": chunk_id,
            "index": index,
            "count": count,
            "byteLength": byte_length,
            "data": data,
        })
        .to_string(),
    )
}

fn chunk_lines(chunk_id: &str, payload: &[u8]) -> Vec<Vec<u8>> {
    chunk_lines_declared(chunk_id, payload, payload.len() as u64)
}

fn chunk_lines_declared(chunk_id: &str, payload: &[u8], declared: u64) -> Vec<Vec<u8>> {
    let count = payload.len().div_ceil(CHUNK_PAYLOAD_BYTES) as u64;
    (0..count)
        .map(|index| {
            let start = index as usize * CHUNK_PAYLOAD_BYTES;
            let end = (start + CHUNK_PAYLOAD_BYTES).min(payload.len());
            chunk_line(
                chunk_id,
                index,
                count,
                declared,
                &BASE64_STANDARD.encode(&payload[start..end]),
            )
        })
        .collect()
}

/// A >= 1 MiB logical JSON whose `text` value places a two-byte character
/// across every 256 KiB chunk boundary: the first `é` occupies bytes
/// [262_143, 262_145), then one every 262_144 bytes.
fn multibyte_payload() -> Vec<u8> {
    let mut payload = OPENING.to_vec();
    for repetition in 0..5 {
        payload.resize(
            CHUNK_PAYLOAD_BYTES - 1 + repetition * CHUNK_PAYLOAD_BYTES,
            b'a',
        );
        payload.extend_from_slice(&E_ACCENT);
    }
    payload.extend_from_slice(b"\"}");
    payload
}

/// Valid JSON content padded with trailing spaces to exactly the physical
/// ceiling, forcing the chunked path with a declared length >= 1 MiB.
fn json_padded_to_min_logical_frame(core: &[u8]) -> Vec<u8> {
    let mut payload = core.to_vec();
    payload.resize(MAX_FRAME_BYTES, b' ');
    payload
}

fn push_all(
    decoder: &mut RpcFrameDecoder,
    lines: &[Vec<u8>],
) -> Result<Option<DecodedRpcFrame>, RpcFrameError> {
    let mut frame = None;
    for line in lines {
        frame = decoder.push_physical_line(line)?;
    }
    Ok(frame)
}

#[test]
fn single_unknown_frame_round_trips_byte_for_byte() {
    let mut decoder = RpcFrameDecoder::default();
    assert_eq!(decoder.protocol(), RpcProtocolVersion::V1);
    let line = r#"{"type":"hologram","v":{"n":1}}"#;
    let frame = decoder
        .push_physical_line(&physical(line))
        .expect("unknown frames succeed")
        .expect("complete");
    assert_eq!(frame.value()["type"], "hologram");
    assert_eq!(frame.raw(), line.as_bytes());
    assert_eq!(frame.lines(), [physical(line)]);
    assert_eq!(frame.lines()[0].last(), Some(&b'\n'));
    let bare = r#"{"note":1}"#;
    let frame = decoder
        .push_physical_line(&physical(bare))
        .expect("typeless objects succeed")
        .expect("complete");
    assert_eq!(frame.raw(), bare.as_bytes());
    assert!(decoder.finish().is_ok());
}

#[test]
fn an_owned_line_over_the_ceiling_is_rejected_with_its_bounded_prefix() {
    let mut decoder = RpcFrameDecoder::default();
    let mut over = b"a".repeat(MAX_FRAME_BYTES);
    over.push(b'\n');
    let error = decoder
        .push_owned_line(over.clone())
        .expect_err("oversize owned line");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::FrameTooLarge {
            size: MAX_FRAME_BYTES + 1
        }
    );
    assert_eq!(error.evidence(), [&over[..MAX_FRAME_BYTES]]);
}

#[test]
fn malformed_line_json_is_rejected_with_evidence() {
    let mut decoder = RpcFrameDecoder::default();
    let error = decoder
        .push_physical_line(&physical("{\"a\":"))
        .expect_err("truncated json");
    assert!(matches!(
        error.kind(),
        RpcFrameErrorKind::MalformedLine { .. }
    ));
    assert_eq!(error.evidence(), [physical("{\"a\":")]);
}

#[test]
fn chunk_sequence_reassembles_across_multibyte_boundaries() {
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let payload = multibyte_payload();
    let lines = chunk_lines("multibyte", &payload);
    assert!(lines.len() >= 6, "payload spans several chunks");
    for repetition in 0..5 {
        let start = CHUNK_PAYLOAD_BYTES - 1 + repetition * CHUNK_PAYLOAD_BYTES;
        assert_eq!(
            &payload[start..start + 2],
            &E_ACCENT,
            "two-byte char straddles chunk boundary {repetition}"
        );
    }
    for line in &lines {
        assert!(
            line.len() <= MAX_FRAME_BYTES,
            "chunk line stays within the physical limit"
        );
    }
    for line in &lines[..lines.len() - 1] {
        assert_eq!(
            decoder.push_physical_line(line).expect("chunk accepted"),
            None
        );
    }
    let frame = decoder
        .push_physical_line(lines.last().expect("final chunk"))
        .expect("sequence completes")
        .expect("complete frame");
    let text = String::from_utf8(payload[OPENING.len()..payload.len() - 2].to_vec())
        .expect("payload text is utf-8");
    assert_eq!(frame.value()["type"], "demo");
    assert_eq!(frame.value()["text"], Value::String(text));
    assert_eq!(frame.raw(), payload);
    assert_eq!(frame.lines(), &lines[..]);
    assert!(
        decoder.finish().is_ok(),
        "completed sequence leaves no pending state"
    );
    // The decoder remains usable for subsequent frames.
    let next = decoder
        .push_physical_line(&physical("{\"type\":\"ready\"}"))
        .expect("frame after sequence");
    assert!(next.is_some());
}

#[test]
fn chunk_start_and_ordering_are_strict() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("order", &payload);
    let count = lines.len() as u64;

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = decoder
        .push_physical_line(&lines[1])
        .expect_err("sequence must start at index 0");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::ChunkSequenceStart { index: 1 }
    );
    assert_eq!(error.evidence(), [&lines[1][..]]);

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let error = decoder
        .push_physical_line(&lines[2])
        .expect_err("index gap");
    assert_eq!(*error.kind(), RpcFrameErrorKind::ChunkSequenceMismatch);
    assert_eq!(error.evidence(), [&lines[0][..], &lines[2][..]]);

    let foreign = chunk_line(
        "other",
        count - 1,
        count,
        payload.len() as u64,
        &BASE64_STANDARD.encode([0; 8]),
    );
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let error = decoder
        .push_physical_line(&foreign)
        .expect_err("foreign chunk id");
    assert_eq!(*error.kind(), RpcFrameErrorKind::ChunkSequenceMismatch);
}

#[test]
fn declared_length_is_enforced() {
    // Declared byteLength is only valid metadata at or above the physical
    // ceiling, so pad past it with slack on both sides: the short
    // declaration survives metadata validation and overflows mid-sequence,
    // the long one reaches the final-total check. Trailing spaces keep the
    // reassembled bytes a valid JSON object.
    let mut payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    payload.resize(MAX_FRAME_BYTES + 20, b' ');
    let real = payload.len() as u64;

    let short = chunk_lines_declared("short", &payload, real - 10);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = push_all(&mut decoder, &short).expect_err("overflow beyond the declared length");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::ChunkSequenceOverflow {
            received: real,
            declared: real - 10
        }
    );
    assert_eq!(error.evidence().len(), short.len());

    let long = chunk_lines_declared("long", &payload, real + 10);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error =
        push_all(&mut decoder, &long).expect_err("final total must equal the declared length");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::ChunkSequenceLengthMismatch {
            received: real,
            declared: real + 10
        }
    );
}

#[test]
fn line_violation_mid_sequence_retains_all_evidence_and_resets() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("midstream", &payload);

    // A malformed line inside an active sequence retains the whole failing
    // frame and drops the broken sequence state.
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let malformed = physical("{\"a\":");
    let error = decoder
        .push_physical_line(&malformed)
        .expect_err("malformed mid-sequence");
    assert!(matches!(
        error.kind(),
        RpcFrameErrorKind::MalformedLine { .. }
    ));
    assert_eq!(error.evidence(), [&lines[0][..], &malformed[..]]);
    assert!(decoder.finish().is_ok(), "broken sequence state is dropped");
    let frame = push_all(&mut decoder, &lines)
        .expect("fresh sequence after reset")
        .expect("complete frame");
    assert_eq!(frame.raw(), payload);

    // Oversize and invalid-UTF-8 lines behave identically.
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let mut oversize = b"a".repeat(MAX_FRAME_BYTES);
    oversize.push(b'\n');
    let error = decoder
        .push_physical_line(&oversize)
        .expect_err("oversize mid-sequence");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::FrameTooLarge {
            size: MAX_FRAME_BYTES + 1
        }
    );
    assert_eq!(
        error.evidence(),
        [&lines[0][..], &oversize[..MAX_FRAME_BYTES]]
    );
    assert!(decoder.finish().is_ok());

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let invalid = b"{\"a\":\"\xff\"}\n".to_vec();
    let error = decoder
        .push_physical_line(&invalid)
        .expect_err("invalid utf-8 mid-sequence");
    assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidLineUtf8);
    assert_eq!(error.evidence(), [&lines[0][..], &invalid[..]]);
    assert!(decoder.finish().is_ok());
}
