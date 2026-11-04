//! Generated authority wire v2 conformance checks; do not edit.

use self::vectors::{ECHO_PAIRS, MALFORMED, V1_REJECTIONS, VECTORS};
use super::*;
use std::io::Cursor;
#[derive(Clone, Copy, Debug)]
enum Direction {
    Request,
    Response,
}

mod vectors;

fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "hex must contain complete bytes"
    );
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).expect("hex high nibble");
            let low = (pair[1] as char).to_digit(16).expect("hex low nibble");
            ((high << 4) | low) as u8
        })
        .collect()
}
fn vector(name: &str) -> (Direction, &'static [u8]) {
    VECTORS
        .iter()
        .find(|(candidate, _, _, _)| *candidate == name)
        .map(|(_, direction, payload, _)| (*direction, *payload))
        .expect("named vector exists")
}
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn changed_id(original: &str, hexadecimal: bool) -> String {
    let (primary, alternate) = if hexadecimal { ('f', 'e') } else { ('z', 'y') };
    let replacement = primary.to_string().repeat(original.len());
    if replacement == original {
        alternate.to_string().repeat(original.len())
    } else {
        replacement
    }
}
fn response_with_changed_id(
    response_payload: &[u8],
    original: &str,
    hexadecimal: bool,
) -> Response {
    let replacement = changed_id(original, hexadecimal);
    let original_payload = std::str::from_utf8(response_payload).expect("UTF-8");
    let changed = original_payload.replacen(original, &replacement, 1);
    assert_ne!(changed, original_payload, "echoed ID occurs in response");
    decode_response_payload(changed.as_bytes(), 1_048_576)
        .expect("same-length valid-ID mutation remains canonical")
}
#[test]
fn wire_v2_conformance_every_canonical_vector_round_trips() {
    for (name, direction, canonical, frame_hex) in VECTORS {
        let frame = decode_hex(frame_hex);
        assert!(frame.len() >= 4, "{name}: frame has prefix");
        let declared =
            u32::from_be_bytes(frame[..4].try_into().expect("four-byte prefix")) as usize;
        assert_eq!(declared, canonical.len(), "{name}: declared payload length");
        assert_eq!(&frame[4..], *canonical, "{name}: framed canonical bytes");
        match direction {
            Direction::Request => {
                let decoded = decode_request_payload(canonical, 262_144)
                    .unwrap_or_else(|error| panic!("{name}: request decode failed: {error}"));
                assert_eq!(
                    encode_request_payload(&decoded, 262_144).expect("request re-encodes"),
                    *canonical,
                    "{name}: request bytes"
                );
            }
            Direction::Response => {
                let decoded = decode_response_payload(canonical, 1_048_576)
                    .unwrap_or_else(|error| panic!("{name}: response decode failed: {error}"));
                assert_eq!(
                    encode_response_payload(&decoded, 1_048_576).expect("response re-encodes"),
                    *canonical,
                    "{name}: response bytes"
                );
            }
        }
    }
}

#[test]
fn wire_v2_conformance_exact_id_echoes_are_enforced() {
    for (request_name, response_name) in ECHO_PAIRS {
        let (request_direction, request_payload) = vector(request_name);
        let (response_direction, response_payload) = vector(response_name);
        assert!(matches!(request_direction, Direction::Request));
        assert!(matches!(response_direction, Direction::Response));
        let request =
            decode_request_payload(request_payload, 262_144).expect("request vector decodes");
        let response =
            decode_response_payload(response_payload, 1_048_576).expect("response vector decodes");
        assert!(
            echoes(&response, &request),
            "{request_name} -> {response_name} must echo IDs"
        );

        let mut echoed_ids = vec![
            ("capsule_id", request.capsule_id().as_str(), false),
            ("correlation_id", request.correlation_id().as_str(), true),
        ];
        if let Some(operation_id) = request.operation_id() {
            echoed_ids.push(("operation_id", operation_id.as_str(), false));
        }
        for (field, original, hexadecimal) in echoed_ids {
            let changed = response_with_changed_id(response_payload, original, hexadecimal);
            assert!(
                !echoes(&changed, &request),
                "{response_name}: changing echoed {field} must fail"
            );
        }
        if let Request::StopIntent { operation_id, .. } = &request {
            if operation_id.is_none() {
                let original_payload = std::str::from_utf8(response_payload).expect("UTF-8");
                let changed =
                    original_payload.replacen("\"operation_id\":null", "\"operation_id\":\"z\"", 1);
                assert_ne!(
                    changed, original_payload,
                    "optional operation_id occurs in response"
                );
                let changed = decode_response_payload(changed.as_bytes(), 1_048_576)
                    .expect("optional-ID mutation remains canonical");
                assert!(
                    !echoes(&changed, &request),
                    "{response_name}: changing absent operation_id must fail"
                );
            }
        }
    }
}

#[test]
fn wire_v2_conformance_every_v1_payload_is_rejected() {
    for (name, direction, payload) in V1_REJECTIONS {
        let rejected = match direction {
            Direction::Request => decode_request_payload(payload, 262_144).is_err(),
            Direction::Response => decode_response_payload(payload, 1_048_576).is_err(),
        };
        assert!(rejected, "{name}: v1 payload reached v2 decoder");
    }
}

#[test]
fn malformed_frames_payload_shape_and_version_fail_closed() {
    let limits = WireLimits::new(262_144, 1_048_576).expect("valid limits");
    for (name, direction, payload) in MALFORMED {
        let direct_error = match direction {
            Direction::Request => {
                decode_request_payload(payload, limits.max_request_bytes()).expect_err(name)
            }
            Direction::Response => {
                decode_response_payload(payload, limits.max_frame_bytes()).expect_err(name)
            }
        };
        assert!(
            matches!(direct_error, ProtocolError::Decode(_)),
            "{name}: direct payload: {direct_error}"
        );

        let framed_error = match direction {
            Direction::Request => {
                read_request(&mut Cursor::new(frame(payload)), limits).expect_err(name)
            }
            Direction::Response => {
                read_response(&mut Cursor::new(frame(payload)), limits).expect_err(name)
            }
        };
        assert!(
            matches!(framed_error, ProtocolError::Decode(_)),
            "{name}: framed payload: {framed_error}"
        );
    }
}

#[test]
fn malformed_frames_prefix_empty_oversize_and_truncation_are_distinct() {
    let limits = WireLimits::new(512, 1024).expect("valid limits");
    assert_eq!(
        read_request(&mut Cursor::new(Vec::<u8>::new()), limits).expect("EOF"),
        None
    );
    for prefix in [vec![0], vec![0, 0], vec![0, 0, 0]] {
        assert!(matches!(
            read_request(&mut Cursor::new(prefix), limits),
            Err(ProtocolError::TruncatedFrame)
        ));
    }
    assert!(matches!(
        read_request(&mut Cursor::new([0, 0, 0, 0]), limits),
        Err(ProtocolError::EmptyFrame)
    ));
    assert!(matches!(
        read_request(&mut Cursor::new([0, 0, 2, 1]), limits),
        Err(ProtocolError::FrameTooLarge {
            declared: 513,
            ceiling: 512
        })
    ));
    let mut truncated = vec![0, 0, 0, 5];
    truncated.extend_from_slice(b"1234");
    assert!(matches!(
        read_request(&mut Cursor::new(truncated), limits),
        Err(ProtocolError::TruncatedFrame)
    ));
}

#[test]
fn wire_v2_conformance_field_contributions_match_encoding_for_every_vector() {
    for (name, direction, canonical, frame_hex) in VECTORS {
        let frame = decode_hex(frame_hex);
        let _ = frame;
        let contributions = match direction {
            Direction::Request => {
                let payload = decode_request_payload(canonical, 262_144)
                    .unwrap_or_else(|error| panic!("{name}: decode failed: {error}"));
                let sizes = canonical_size_request_field_sizes(&payload).expect("{name}: sizes");
                let encoded = encode_request_payload(&payload, 262_144)
                    .unwrap_or_else(|error| panic!("{name}: encode failed: {error}"));
                (sizes, encoded)
            }
            Direction::Response => {
                let payload = decode_response_payload(canonical, 1_048_576)
                    .unwrap_or_else(|error| panic!("{name}: decode failed: {error}"));
                let sizes = canonical_size_response_field_sizes(&payload).expect("{name}: sizes");
                let encoded = encode_response_payload(&payload, 1_048_576)
                    .unwrap_or_else(|error| panic!("{name}: encode failed: {error}"));
                (sizes, encoded)
            }
        };
        let (sizes, encoded) = contributions;
        assert!(!sizes.is_empty(), "{name}: field contributions are empty");
        let mut total = 2usize + sizes.len().saturating_sub(1);
        for (field, size) in &sizes {
            assert!(*size > 0, "{name}: field {field} contributed zero bytes");
            total += canonical_size_quoted(field) + 1 + size;
        }
        assert_eq!(
            total,
            encoded.len(),
            "{name}: per-field contributions must reconstruct canonical encoding"
        );
    }
}
