//! Physical and reassembled frame bounds, malformed input and protocol transitions.

use super::*;

/// JSON object prefix of [`multibyte_payload`], 23 bytes.
const OPENING: &[u8] = b"{\"type\":\"demo\",\"text\":\"";
const E_ACCENT: [u8; 2] = [0xC3, 0xA9]; // 'é' in UTF-8

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for group in bytes.chunks(3) {
        let word = (u32::from(group[0]) << 16)
            | (u32::from(*group.get(1).unwrap_or(&0)) << 8)
            | u32::from(*group.get(2).unwrap_or(&0));
        out.push(ALPHABET[(word >> 18) as usize & 63] as char);
        out.push(ALPHABET[(word >> 12) as usize & 63] as char);
        out.push(if group.len() > 1 {
            ALPHABET[(word >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            ALPHABET[word as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

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
                &encode_base64(&payload[start..end]),
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

/// Measurement: clone identity, not a timer. A thousand clones of a 64 KiB
/// frame must share the parsed value and the physical line (same pointers).
/// A deep clone would allocate a fresh buffer per clone. The 500 ms bound
/// only catches a stalled clone loop; the pointer asserts are the pin.
#[test]
fn owned_line_matches_borrowed_line_and_clones_share_the_payload() {
    let mut bytes = br#"{"type":"message_update","delta":""#.to_vec();
    bytes.extend(std::iter::repeat_n(b'x', 64 * 1024));
    bytes.extend(br#""}"#);
    bytes.push(b'\n');
    let mut borrowed = RpcFrameDecoder::default();
    let from_borrow = borrowed
        .push_physical_line(&bytes)
        .expect("borrowed decode")
        .expect("borrowed frame");
    let mut owned = RpcFrameDecoder::default();
    let frame = owned
        .push_owned_line(bytes)
        .expect("owned decode")
        .expect("owned frame");
    assert_eq!(frame.raw(), from_borrow.raw());
    assert_eq!(frame.lines(), from_borrow.lines());
    assert_eq!(frame.value(), from_borrow.value());
    assert!(frame.lines()[0].ends_with(b"\n"));
    assert!(!frame.raw().ends_with(b"\n"));
    let started = std::time::Instant::now();
    let first = frame.clone();
    let mut n = first.raw().len();
    for _ in 0..999 {
        let clone = frame.clone();
        assert_eq!(clone.raw().as_ptr(), first.raw().as_ptr());
        assert_eq!(clone.lines()[0].as_ptr(), first.lines()[0].as_ptr());
        assert_eq!(clone.value() as *const Value, first.value() as *const Value);
        n = n.saturating_add(clone.raw().len());
    }
    std::hint::black_box(n);
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "shared frame clones took {:?}",
        started.elapsed()
    );
    assert_eq!(n, 1_000 * frame.raw().len());
}

#[test]
fn non_object_lines_are_rejected() {
    for line in ["[1,2,3]", "\"text\"", "42", "null"] {
        let mut decoder = RpcFrameDecoder::default();
        let error = decoder.push_physical_line(&physical(line)).expect_err(line);
        assert_eq!(*error.kind(), RpcFrameErrorKind::NotAnObject);
        assert_eq!(error.evidence(), [physical(line)]);
    }
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
fn invalid_physical_utf8_is_a_typed_error_carrying_bytes() {
    let mut decoder = RpcFrameDecoder::default();
    let line = b"{\"a\":\"\xff\xfe\"}\n".to_vec();
    let error = decoder
        .push_physical_line(&line)
        .expect_err("invalid utf-8 content bytes");
    assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidLineUtf8);
    assert_eq!(error.evidence(), [&line[..]]);

    let truncated = b"{\"a\":\"\xc3\"}\n".to_vec();
    let error = decoder
        .push_physical_line(&truncated)
        .expect_err("truncated multibyte sequence");
    assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidLineUtf8);
    assert_eq!(error.evidence(), [&truncated[..]]);
}

#[test]
fn missing_newline_is_rejected() {
    let mut decoder = RpcFrameDecoder::default();
    let unterminated = b"{\"type\":\"x\"}".to_vec();
    let error = decoder
        .push_physical_line(&unterminated)
        .expect_err("no newline");
    assert_eq!(*error.kind(), RpcFrameErrorKind::MissingNewline);
    assert_eq!(error.evidence(), [&unterminated[..]]);

    let error = decoder
        .push_physical_line(b"")
        .expect_err("empty input carries no newline");
    assert_eq!(*error.kind(), RpcFrameErrorKind::MissingNewline);
    assert_eq!(error.evidence(), [b"".to_vec()]);
}

#[test]
fn embedded_and_double_newlines_are_rejected() {
    let mut decoder = RpcFrameDecoder::default();
    let doubled = b"{\"type\":\"x\"}\n\n".to_vec();
    let error = decoder
        .push_physical_line(&doubled)
        .expect_err("double newline");
    assert_eq!(*error.kind(), RpcFrameErrorKind::EmbeddedNewline);
    assert_eq!(error.evidence(), [&doubled[..]]);

    let mut decoder = RpcFrameDecoder::default();
    let two_lines = b"{\"a\":1}\n{\"b\":2}\n".to_vec();
    let error = decoder
        .push_physical_line(&two_lines)
        .expect_err("two lines at once");
    assert_eq!(*error.kind(), RpcFrameErrorKind::EmbeddedNewline);
    assert_eq!(error.evidence(), [&two_lines[..]]);
}

#[test]
fn blank_lines_carry_no_frame() {
    let mut decoder = RpcFrameDecoder::default();
    assert_eq!(
        decoder.push_physical_line(b"\n").expect("blank is ignored"),
        None
    );
    assert_eq!(
        decoder
            .push_physical_line(b"   \n")
            .expect("blank is ignored"),
        None
    );
    assert!(decoder.finish().is_ok());
}

#[test]
fn physical_ceiling_includes_the_newline() {
    let mut decoder = RpcFrameDecoder::default();
    let mut exact = b"a".repeat(MAX_FRAME_BYTES - 1);
    exact.push(b'\n');
    // MAX_FRAME_BYTES bytes including the newline: passes the size gate, fails JSON.
    let error = decoder.push_physical_line(&exact).expect_err("not json");
    assert!(matches!(
        error.kind(),
        RpcFrameErrorKind::MalformedLine { .. }
    ));
    assert_eq!(error.evidence(), [&exact[..]]);
    let mut over = b"a".repeat(MAX_FRAME_BYTES);
    over.push(b'\n');
    let error = decoder
        .push_physical_line(&over)
        .expect_err("oversize line");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::FrameTooLarge {
            size: MAX_FRAME_BYTES + 1
        }
    );
    // Over-ceiling evidence is bounded: only the in-ceiling prefix is kept.
    assert_eq!(error.evidence(), [&over[..MAX_FRAME_BYTES]]);
}

#[test]
fn oversized_input_is_gated_before_newline_checks_with_bounded_evidence() {
    // Oversized and unterminated: the size gate outranks MissingNewline.
    let mut decoder = RpcFrameDecoder::default();
    let unterminated = vec![b'x'; 2 * MAX_FRAME_BYTES];
    let error = decoder
        .push_physical_line(&unterminated)
        .expect_err("oversized input is gated before the newline checks");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::FrameTooLarge {
            size: 2 * MAX_FRAME_BYTES
        }
    );
    assert_eq!(error.evidence(), [&unterminated[..MAX_FRAME_BYTES]]);

    // Oversized with an embedded newline: still the size gate, still bounded.
    let mut decoder = RpcFrameDecoder::default();
    let mut multiline = vec![b'x'; MAX_FRAME_BYTES + 2];
    multiline[7] = b'\n';
    let error = decoder
        .push_physical_line(&multiline)
        .expect_err("oversized input is gated before the embedded-newline check");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::FrameTooLarge {
            size: MAX_FRAME_BYTES + 2
        }
    );
    assert_eq!(error.evidence(), [&multiline[..MAX_FRAME_BYTES]]);
}

#[test]
fn physical_evidence_retains_the_exact_bytes_including_newline() {
    let mut decoder = RpcFrameDecoder::default();
    let line = r#"{"type":"v1"}"#;
    let frame = decoder
        .push_physical_line(&physical(line))
        .expect("object frame")
        .expect("complete");
    assert_eq!(frame.lines(), [physical(line)]);
    assert_eq!(frame.lines()[0].last(), Some(&b'\n'));
    assert_eq!(frame.raw(), line.as_bytes());
    assert!(
        !frame.raw().ends_with(b"\n"),
        "logical bytes exclude the transport newline"
    );

    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("evidence", &payload);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let frame = push_all(&mut decoder, &lines)
        .expect("sequence completes")
        .expect("complete frame");
    assert_eq!(frame.lines(), &lines[..]);
    for line in frame.lines() {
        assert_eq!(
            line.last(),
            Some(&b'\n'),
            "every retained line keeps its newline"
        );
    }
    assert_eq!(frame.raw(), payload);
    assert!(
        !frame.raw().contains(&b'\n'),
        "reassembled logical bytes exclude newlines"
    );
}

#[test]
fn v1_rejects_chunks_until_negotiation_upgrades_the_decoder() {
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V1);
    let lines = chunk_lines("negotiate", &multibyte_payload());
    let error = decoder
        .push_physical_line(&lines[0])
        .expect_err("chunk under v1");
    assert_eq!(*error.kind(), RpcFrameErrorKind::ChunkBeforeNegotiation);
    assert_eq!(error.evidence(), [&lines[0][..]]);
    decoder.set_protocol(RpcProtocolVersion::V2);
    assert_eq!(decoder.protocol(), RpcProtocolVersion::V2);
    let frame = push_all(&mut decoder, &lines)
        .expect("sequence completes under v2")
        .expect("complete frame");
    assert_eq!(frame.value()["type"], "demo");
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
        &encode_base64(&[0; 8]),
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
fn chunk_metadata_is_rejected() {
    let data = encode_base64(&[0; 16]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "count below two",
            chunk_line("m", 0, 1, 2 * MAX_FRAME_BYTES as u64, &data),
        ),
        (
            "count above max",
            chunk_line(
                "m",
                0,
                MAX_CHUNK_COUNT as u64 + 1,
                MAX_REASSEMBLED_BYTES as u64,
                &data,
            ),
        ),
        (
            "index at count",
            chunk_line("m", 2, 2, 2 * MAX_FRAME_BYTES as u64, &data),
        ),
        (
            "declared below physical limit",
            chunk_line("m", 0, 2, MAX_FRAME_BYTES as u64 - 1, &data),
        ),
        (
            "declared above reassembly limit",
            chunk_line("m", 0, 2, MAX_REASSEMBLED_BYTES as u64 + 1, &data),
        ),
        (
            "empty chunk id",
            chunk_line("", 0, 2, 2 * MAX_FRAME_BYTES as u64, &data),
        ),
        (
            "overlong chunk id",
            chunk_line(
                &"x".repeat(MAX_CHUNK_ID_CHARS + 1),
                0,
                2,
                2 * MAX_FRAME_BYTES as u64,
                &data,
            ),
        ),
        (
            "fractional byte length",
            physical(
                &serde_json::json!({
                    "type": "rpc_chunk", "chunkId": "m", "index": 0, "count": 2,
                    "byteLength": 2_097_152.5, "data": data,
                })
                .to_string(),
            ),
        ),
        (
            "string index",
            physical(
                &serde_json::json!({
                    "type": "rpc_chunk", "chunkId": "m", "index": "0", "count": 2,
                    "byteLength": 2_097_152, "data": data,
                })
                .to_string(),
            ),
        ),
        (
            "missing byte length",
            physical(
                &serde_json::json!({
                    "type": "rpc_chunk", "chunkId": "m", "index": 0, "count": 2, "data": data,
                })
                .to_string(),
            ),
        ),
    ];
    for (label, line) in cases {
        let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
        let error = decoder.push_physical_line(&line).expect_err(label);
        assert_eq!(
            *error.kind(),
            RpcFrameErrorKind::InvalidChunkMetadata,
            "{label}"
        );
        assert_eq!(error.evidence(), [&line[..]], "{label}");
    }
}

#[test]
fn chunk_id_length_is_measured_in_utf16_units() {
    let data = encode_base64(&[0; 16]);
    // 64 astral characters are 128 UTF-16 code units: exactly at the
    // pin's `chunkId.length <= 128` bound.
    let accepted = chunk_line(&"𐀀".repeat(64), 0, 2, 2 * MAX_FRAME_BYTES as u64, &data);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&accepted)
            .expect("id at the utf-16 bound"),
        None
    );

    // 65 astral characters are 130 UTF-16 code units: the pin's JS length
    // rejects it even though it is only 65 Unicode scalar values.
    let rejected = chunk_line(&"𐀀".repeat(65), 0, 2, 2 * MAX_FRAME_BYTES as u64, &data);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = decoder
        .push_physical_line(&rejected)
        .expect_err("id past the utf-16 bound");
    assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidChunkMetadata);
}

#[test]
fn chunk_data_must_be_canonical_base64() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("b64", &payload);
    let bad_lines = [
        chunk_line("b64", 1, lines.len() as u64, payload.len() as u64, ""),
        chunk_line("b64", 1, lines.len() as u64, payload.len() as u64, "AB=="),
        chunk_line("b64", 1, lines.len() as u64, payload.len() as u64, "AAB="),
        chunk_line("b64", 1, lines.len() as u64, payload.len() as u64, "abc"),
        chunk_line("b64", 1, lines.len() as u64, payload.len() as u64, "a c="),
    ];
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    for bad in &bad_lines {
        assert_eq!(
            decoder
                .push_physical_line(&lines[0])
                .expect("first chunk accepted"),
            None
        );
        let error = decoder
            .push_physical_line(bad)
            .expect_err("non-canonical data");
        assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidChunkData);
        assert_eq!(error.evidence(), [&lines[0][..], &bad[..]]);
    }

    // Canonicality, directly: nonzero discarded bits and stray shapes fail.
    assert_eq!(decode_canonical_base64(""), None);
    assert_eq!(decode_canonical_base64("A"), None);
    assert_eq!(decode_canonical_base64("AA"), None);
    assert_eq!(decode_canonical_base64("AAA"), None);
    assert_eq!(decode_canonical_base64("AB=="), None);
    assert_eq!(decode_canonical_base64("AAB="), None);
    assert_eq!(decode_canonical_base64("=AAA"), None);
    assert_eq!(decode_canonical_base64("-_-_"), None);
    assert_eq!(decode_canonical_base64("AA=="), Some(vec![0]));
    assert_eq!(decode_canonical_base64("AAA="), Some(vec![0, 0]));
    assert_eq!(decode_canonical_base64("AAAA"), Some(vec![0, 0, 0]));
    assert_eq!(decode_canonical_base64("aGVsbG8="), Some(b"hello".to_vec()));
}

#[test]
fn chunk_payload_ceiling_is_enforced() {
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let oversized: Vec<u8> = std::iter::repeat_n(0_u8, CHUNK_PAYLOAD_BYTES + 1).collect();
    let oversized_line = chunk_line(
        "ceiling",
        0,
        4,
        (MAX_FRAME_BYTES + 145) as u64,
        &encode_base64(&oversized),
    );
    let error = decoder
        .push_physical_line(&oversized_line)
        .expect_err("payload above the ceiling");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::ChunkPayloadTooLarge {
            size: CHUNK_PAYLOAD_BYTES + 1
        }
    );
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
fn reassembled_bytes_must_be_utf8() {
    let mut payload = vec![b'a'; MAX_FRAME_BYTES - 1];
    payload.push(0xFF);
    let lines = chunk_lines("utf8", &payload);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = push_all(&mut decoder, &lines).expect_err("invalid utf-8 payload");
    assert_eq!(*error.kind(), RpcFrameErrorKind::InvalidFrameUtf8);
    assert_eq!(error.evidence(), &lines[..]);
}

#[test]
fn reassembled_frame_must_be_json_object() {
    let array_payload = json_padded_to_min_logical_frame(b"[1, 2, 3]");
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = push_all(&mut decoder, &chunk_lines("array", &array_payload))
        .expect_err("arrays are not frames");
    assert_eq!(*error.kind(), RpcFrameErrorKind::NotAnObject);

    let junk_payload = json_padded_to_min_logical_frame(b"not json");
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    let error = push_all(&mut decoder, &chunk_lines("junk", &junk_payload))
        .expect_err("unparseable reassembly");
    assert!(matches!(
        error.kind(),
        RpcFrameErrorKind::MalformedFrame { .. }
    ));
}

#[test]
fn interleaved_frames_interrupt_the_sequence() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("interrupted", &payload);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let ready = physical("{\"type\":\"ready\"}");
    let error = decoder
        .push_physical_line(&ready)
        .expect_err("frame mid-sequence");
    assert_eq!(*error.kind(), RpcFrameErrorKind::ChunkSequenceInterrupted);
    assert_eq!(error.evidence(), [&lines[0][..], &ready[..]]);
    // The broken sequence is dropped: only the finish gate re-reports state.
    assert!(decoder.finish().is_ok());

    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let bare_array = physical("[1]");
    let error = decoder
        .push_physical_line(&bare_array)
        .expect_err("non-object mid-sequence");
    // Interruption outranks the object check, matching the pinned decoder.
    assert_eq!(*error.kind(), RpcFrameErrorKind::ChunkSequenceInterrupted);
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

#[test]
fn blank_lines_do_not_disturb_an_active_sequence() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("blankgap", &payload);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    assert_eq!(
        decoder.push_physical_line(b"\n").expect("blank ignored"),
        None
    );
    assert_eq!(
        decoder.push_physical_line(b"   \n").expect("blank ignored"),
        None
    );
    let frame = push_all(&mut decoder, &lines[1..])
        .expect("sequence completes across blank lines")
        .expect("complete frame");
    assert_eq!(frame.raw(), payload);
    assert!(decoder.finish().is_ok());
}

#[test]
fn finish_rejects_unfinished_sequences() {
    let payload = json_padded_to_min_logical_frame(b"{\"type\":\"demo\"}");
    let lines = chunk_lines("eof", &payload);
    let mut decoder = RpcFrameDecoder::new(RpcProtocolVersion::V2);
    assert!(decoder.finish().is_ok(), "clean stream ends cleanly");
    assert_eq!(
        decoder
            .push_physical_line(&lines[0])
            .expect("first chunk accepted"),
        None
    );
    let error = decoder.finish().expect_err("sequence still pending");
    assert_eq!(
        *error.kind(),
        RpcFrameErrorKind::UnfinishedChunkSequence {
            chunk_id: "eof".to_owned(),
            next_index: 1,
            count: lines.len() as u64,
            received: CHUNK_PAYLOAD_BYTES.min(payload.len()) as u64,
            declared: payload.len() as u64,
        }
    );
    assert_eq!(error.evidence(), [&lines[0][..]]);
}
