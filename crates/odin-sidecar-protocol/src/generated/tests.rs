//! Generated authority wire v2 conformance checks; do not edit.

use self::vectors::{ECHO_PAIRS, MALFORMED, V1_REJECTIONS, VECTORS};
use super::*;
use std::io::{self, Cursor, Write};
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
        .chunks_exact(2)
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
fn nested_argument(depth: usize) -> Value {
    (0..depth).fold(Value::Null, |value, _| Value::Array(vec![value]))
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
struct BrokenWriter;
impl Write for BrokenWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "injected"))
    }
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
fn wire_v2_conformance_branded_u64_boundaries_are_exact() {
    for decimal in [
        "0",
        "1",
        "9007199254740991",
        "9007199254740992",
        "9007199254740993",
        "9999999999999999999",
        "10000000000000000000",
        "18446744073709551615",
    ] {
        let canonical = format!("{{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"drained\":\"{decimal}\",\"kind\":\"capsule_closed\",\"wire\":2}}");
        let response = decode_response_payload(canonical.as_bytes(), 4096)
            .expect("canonical decimal-string u64 decodes");
        let Response::CapsuleClosed { drained, .. } = response else {
            panic!("capsule_closed decoded to wrong kind");
        };
        assert_eq!(drained.to_string(), decimal);
    }
    for decimal in ["", "00", "01", "-1", "+1", "1\\n", "18446744073709551616"] {
        let canonical = format!("{{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"drained\":\"{decimal}\",\"kind\":\"capsule_closed\",\"wire\":2}}");
        assert!(
            decode_response_payload(canonical.as_bytes(), 4096).is_err(),
            "invalid decimal-string u64 {decimal:?} was accepted"
        );
    }
}

#[test]
fn wire_v2_conformance_generic_integer_domain_is_lossless() {
    let canonical = b"{\"arguments\":{\"maximum\":9007199254740991,\"minimum\":-9007199254740991},\"budget\":{\"requests\":\"1\",\"spend\":\"1\",\"stops\":\"0\"},\"capability\":\"capsule.eval.run\",\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"invoke_capability\",\"wire\":2}";
    let request = decode_request_payload(canonical, 4096).expect("safe integer boundaries decode");
    assert_eq!(
        encode_request_payload(&request, 4096).expect("safe integer boundaries encode"),
        canonical
    );
    for unsafe_integer in [
        "9007199254740992",
        "-9007199254740992",
        "18446744073709551615",
    ] {
        let payload = format!("{{\"arguments\":{{\"unsafe\":{unsafe_integer}}},\"budget\":{{\"requests\":\"1\",\"spend\":\"1\",\"stops\":\"0\"}},\"capability\":\"capsule.eval.run\",\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"invoke_capability\",\"wire\":2}}");
        assert!(
            decode_request_payload(payload.as_bytes(), 4096).is_err(),
            "unsafe generic integer {unsafe_integer} was accepted"
        );
    }
}

#[test]
fn wire_v2_conformance_argument_collection_boundaries_are_exact() {
    let exact_array = Value::Array(vec![Value::Null; ARGUMENT_MAX_ARRAY_ITEMS]);
    assert!(Arguments::new(exact_array).is_ok());
    let oversized_array = Value::Array(vec![Value::Null; ARGUMENT_MAX_ARRAY_ITEMS + 1]);
    assert!(Arguments::new(oversized_array).is_err());

    let exact_object = (0..ARGUMENT_MAX_OBJECT_PROPERTIES)
        .map(|index| odin_strict_json::ObjectEntry {
            key: format!("key-{index}"),
            value: Value::Null,
        })
        .collect::<Vec<_>>();
    assert!(Arguments::new(Value::Object(exact_object.clone())).is_ok());
    let mut oversized_object = exact_object;
    oversized_object.push(odin_strict_json::ObjectEntry {
        key: "overflow".to_string(),
        value: Value::Null,
    });
    assert!(Arguments::new(Value::Object(oversized_object)).is_err());

    assert!(Arguments::new(nested_argument(ARGUMENT_MAX_DEPTH)).is_ok());
    assert!(Arguments::new(nested_argument(ARGUMENT_MAX_DEPTH + 1)).is_err());
}

#[test]
fn wire_v2_conformance_unicode_code_point_boundaries_are_exact() {
    let exact_string = "😀".repeat(ARGUMENT_MAX_STRING_CODE_POINTS);
    assert_eq!(
        exact_string.chars().count(),
        ARGUMENT_MAX_STRING_CODE_POINTS
    );
    let oversized_string = format!("{exact_string}a");
    let arguments = Arguments::new(Value::String(exact_string))
        .expect("exact non-ASCII string code-point ceiling is accepted");
    assert!(odin_strict_json::canonicalize(&arguments).is_ok());
    assert!(Arguments::new(Value::String(oversized_string)).is_err());

    let exact_key = "😀".repeat(ARGUMENT_MAX_KEY_CODE_POINTS);
    assert_eq!(exact_key.chars().count(), ARGUMENT_MAX_KEY_CODE_POINTS);
    let oversized_key = format!("{exact_key}a");
    let arguments = Arguments::new(Value::Object(vec![odin_strict_json::ObjectEntry {
        key: exact_key,
        value: Value::Null,
    }]))
    .expect("exact non-ASCII key code-point ceiling is accepted");
    assert!(odin_strict_json::canonicalize(&arguments).is_ok());
    assert!(
        Arguments::new(Value::Object(vec![odin_strict_json::ObjectEntry {
            key: oversized_key,
            value: Value::Null,
        },]))
        .is_err()
    );

    let exact_detail = "😀".repeat(4096);
    assert_eq!(exact_detail.chars().count(), 4096);
    let detail = Detail::new(&exact_detail).expect("exact non-ASCII detail ceiling is accepted");
    assert!(odin_strict_json::canonicalize(&detail).is_ok());
    assert!(Detail::new(&format!("{exact_detail}a")).is_err());
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
fn wire_v2_conformance_valid_four_byte_framing_is_sequential() {
    let limits = WireLimits::new(262_144, 1_048_576).expect("valid limits");
    let (_, first_payload) = vector("resume-operation");
    let (_, second_payload) = vector("close-drain");
    let first =
        decode_request_payload(first_payload, limits.max_request_bytes()).expect("first request");
    let second =
        decode_request_payload(second_payload, limits.max_request_bytes()).expect("second request");
    let mut stream = Vec::new();
    write_request(&mut stream, &first, limits).expect("first frame writes");
    write_request(&mut stream, &second, limits).expect("second frame writes");
    let mut cursor = Cursor::new(stream);
    assert_eq!(
        read_request(&mut cursor, limits).expect("first read"),
        Some(first)
    );
    assert_eq!(
        read_request(&mut cursor, limits).expect("second read"),
        Some(second)
    );
    assert_eq!(read_request(&mut cursor, limits).expect("clean EOF"), None);
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
fn malformed_frames_exact_ceiling_is_accepted_and_next_size_rejected() {
    let payload = b"{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"resume_operation\",\"operation_id\":\"op-authority-0001\",\"wire\":2}";
    let ceiling = payload.len();
    let limits = WireLimits::new(ceiling, ceiling).expect("exact limits");
    let request = decode_request_payload(payload, ceiling).expect("exact-ceiling payload");
    let mut encoded = Vec::new();
    write_request(&mut encoded, &request, limits).expect("exact-ceiling frame writes");
    assert_eq!(
        read_request(&mut Cursor::new(encoded), limits).expect("exact-ceiling reads"),
        Some(request.clone())
    );
    let small = WireLimits::new(ceiling - 1, ceiling - 1).expect("smaller limits");
    assert!(matches!(
        read_request(&mut Cursor::new(frame(payload)), small),
        Err(ProtocolError::FrameTooLarge { .. })
    ));
    let error = write_request(&mut Vec::new(), &request, small).expect_err("oversized write fails");
    assert!(matches!(
        error,
        ProtocolError::FrameTooLarge {
            declared,
            ceiling: rejected_ceiling
        } if declared == ceiling && rejected_ceiling == ceiling - 1
    ));
}

#[test]
fn malformed_frames_extra_bytes_begin_a_new_frame() {
    let payload = b"{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"resume_operation\",\"operation_id\":\"op-authority-0001\",\"wire\":2}";
    let request = decode_request_payload(payload, 4096).expect("request decodes");
    let limits = WireLimits::new(4096, 4096).expect("valid limits");
    let mut stream = frame(payload);
    stream.push(0);
    let mut cursor = Cursor::new(stream);
    assert_eq!(
        read_request(&mut cursor, limits).expect("complete first frame"),
        Some(request)
    );
    assert!(matches!(
        read_request(&mut cursor, limits),
        Err(ProtocolError::TruncatedFrame)
    ));
}

#[test]
fn malformed_frames_noncanonical_payload_is_rejected() {
    let canonical = b"{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"resume_operation\",\"operation_id\":\"op-authority-0001\",\"wire\":2}";
    let mut leading_space = vec![b' '];
    leading_space.extend_from_slice(canonical);
    let limits = WireLimits::new(4096, 4096).expect("valid limits");
    assert!(matches!(
        read_request(&mut Cursor::new(frame(&leading_space)), limits),
        Err(ProtocolError::Decode(_))
    ));
}

#[test]
fn malformed_frames_writer_io_failure_is_not_decode_failure() {
    let payload = b"{\"capsule_id\":\"capsule-alpha\",\"correlation_id\":\"00112233445566778899aabbccddeeff\",\"kind\":\"resume_operation\",\"operation_id\":\"op-authority-0001\",\"wire\":2}";
    let request = decode_request_payload(payload, 4096).expect("request decodes");
    let limits = WireLimits::new(4096, 4096).expect("valid limits");
    assert!(matches!(
        write_request(&mut BrokenWriter, &request, limits),
        Err(ProtocolError::Io(_))
    ));
}

#[test]
fn malformed_frames_canonical_size_preflight_rejects_before_serialization() {
    let (_, resume_payload) = vector("resume-operation");
    let declared = resume_payload.len();
    let request = decode_request_payload(resume_payload, 4096).expect("request decodes");
    let small = WireLimits::new(declared - 1, declared - 1).expect("valid limits");
    let error = write_request(&mut Vec::new(), &request, small)
        .expect_err("one byte over ceiling is rejected");
    assert!(matches!(
        error,
        ProtocolError::FrameTooLarge {
            declared: exact,
            ceiling: limit,
        } if exact == declared && limit == declared - 1
    ));

    let (_, invoke_payload) = vector("invoke-basic");
    let mut baseline_request =
        decode_request_payload(invoke_payload, 262_144).expect("invoke decodes");
    let Request::InvokeCapability { arguments, .. } = &mut baseline_request else {
        panic!("invoke vector decoded as invoke");
    };
    *arguments = Arguments::new(Value::String("a".to_string()))
        .expect("single-character arguments validate");
    let baseline =
        encode_request_payload(&baseline_request, MAX_REQUEST_BYTES).expect("baseline encodes");

    let mut explosive_request =
        decode_request_payload(invoke_payload, 262_144).expect("invoke decodes");
    let Request::InvokeCapability { arguments, .. } = &mut explosive_request else {
        panic!("invoke vector decoded as invoke");
    };
    *arguments = Arguments::new(Value::String(
        "\u{1}".repeat(ARGUMENT_MAX_STRING_CODE_POINTS),
    ))
    .expect("escape-explosive arguments validate");
    let expected = baseline.len() - 1 + 6 * ARGUMENT_MAX_STRING_CODE_POINTS;
    let error = encode_request_payload(&explosive_request, MAX_REQUEST_BYTES)
        .expect_err("escape-explosive payload is rejected before allocation");
    assert!(matches!(
        error,
        ProtocolError::FrameTooLarge {
            declared: exact,
            ceiling: limit,
        } if exact == expected && limit == MAX_REQUEST_BYTES
    ));

    let mut nested_request =
        decode_request_payload(invoke_payload, 262_144).expect("invoke decodes");
    let Request::InvokeCapability { arguments, .. } = &mut nested_request else {
        panic!("invoke vector decoded as invoke");
    };
    *arguments = Arguments::new(Value::Array(vec![Value::Array(vec![Value::String(
        "\u{1}".repeat(ARGUMENT_MAX_STRING_CODE_POINTS),
    )])]))
    .expect("nested explosive arguments validate");
    let expected = baseline.len() - 1 + 6 * ARGUMENT_MAX_STRING_CODE_POINTS + 4;
    let error = encode_request_payload(&nested_request, MAX_REQUEST_BYTES)
        .expect_err("nested explosive payload is rejected before allocation");
    assert!(matches!(
        error,
        ProtocolError::FrameTooLarge {
            declared: exact,
            ceiling: limit,
        } if exact == expected && limit == MAX_REQUEST_BYTES
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
