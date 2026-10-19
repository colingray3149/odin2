//! Verifies the generated authority-wire fixture through the real Rust codec.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use odin_sidecar_protocol::generated;
use odin_sidecar_protocol::WireLimits;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    fixture: String,
    version: u8,
    limits: FixtureLimits,
    vectors: Vec<Vector>,
    v1_rejections: Vec<V1Rejection>,
    echo_pairs: Vec<EchoPair>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureLimits {
    max_request_bytes: usize,
    max_frame_bytes: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Request,
    Response,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    name: String,
    direction: Direction,
    message: odin_strict_json::Value,
    canonical: String,
    frame_hex: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Rejection {
    name: String,
    direction: Direction,
    payload: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EchoPair {
    request: String,
    response: String,
}

enum Decoded {
    Request(generated::Request),
    Response(generated::Response),
}

#[derive(Debug)]
enum AppError {
    Usage(String),
    Verify(String),
}

impl AppError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Verify(_) => 1,
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Usage(detail) | Self::Verify(detail) => detail,
        }
    }
}

fn parse_path() -> Result<PathBuf, AppError> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [flag, path] if flag.as_os_str() == "--verify" => Ok(PathBuf::from(path)),
        _ => Err(AppError::Usage(
            "usage: authority-wire-vectors --verify <authority-wire-v2.json>".to_string(),
        )),
    }
}

fn verify(path: &Path) -> Result<(), AppError> {
    let bytes = fs::read(path)
        .map_err(|error| AppError::Verify(format!("cannot read {}: {error}", path.display())))?;
    let fixture: Fixture =
        odin_strict_json::decode(&bytes, bytes.len().max(1)).map_err(|error| {
            AppError::Verify(format!(
                "fixture {} is not strict deny-unknown JSON: {error}",
                path.display()
            ))
        })?;
    if fixture.fixture != generated::FIXTURE_ID || fixture.version != generated::PROTOCOL_VERSION {
        return Err(AppError::Verify(format!(
            "fixture identity/version mismatch: {:?}/{}",
            fixture.fixture, fixture.version
        )));
    }
    if fixture.limits.max_request_bytes != generated::MAX_REQUEST_BYTES
        || fixture.limits.max_frame_bytes != generated::MAX_FRAME_BYTES
    {
        return Err(AppError::Verify(format!(
            "fixture limits differ from generated authority: request={}, frame={}",
            fixture.limits.max_request_bytes, fixture.limits.max_frame_bytes
        )));
    }
    let limits = WireLimits::new(
        fixture.limits.max_request_bytes,
        fixture.limits.max_frame_bytes,
    )
    .map_err(|error| AppError::Verify(format!("fixture limits are invalid: {error}")))?;
    let actual_vector_names = fixture
        .vectors
        .iter()
        .map(|vector| vector.name.as_str())
        .collect::<Vec<_>>();
    if actual_vector_names.as_slice() != generated::CANONICAL_VECTOR_NAMES {
        return Err(AppError::Verify(format!(
            "fixture canonical vector identities/order differ: {actual_vector_names:?} != {:?}",
            generated::CANONICAL_VECTOR_NAMES
        )));
    }
    let actual_rejection_names = fixture
        .v1_rejections
        .iter()
        .map(|rejection| rejection.name.as_str())
        .collect::<Vec<_>>();
    if actual_rejection_names.as_slice() != generated::V1_REJECTION_NAMES {
        return Err(AppError::Verify(format!(
            "fixture v1 rejection identities/order differ: {actual_rejection_names:?} != {:?}",
            generated::V1_REJECTION_NAMES
        )));
    }
    let actual_echo_pairs = fixture
        .echo_pairs
        .iter()
        .map(|pair| (pair.request.as_str(), pair.response.as_str()))
        .collect::<Vec<_>>();
    if actual_echo_pairs.as_slice() != generated::EXACT_ECHO_PAIRS {
        return Err(AppError::Verify(format!(
            "fixture echo-pair identities/order differ: {actual_echo_pairs:?} != {:?}",
            generated::EXACT_ECHO_PAIRS
        )));
    }

    let mut decoded = BTreeMap::new();
    for vector in &fixture.vectors {
        let canonical_from_message =
            odin_strict_json::canonicalize(&vector.message).map_err(|error| {
                AppError::Verify(format!(
                    "{} message cannot canonicalize: {error}",
                    vector.name
                ))
            })?;
        if canonical_from_message != vector.canonical.as_bytes() {
            return Err(AppError::Verify(format!(
                "{} message and canonical bytes differ",
                vector.name
            )));
        }
        let frame = decode_hex(&vector.frame_hex)
            .map_err(|error| AppError::Verify(format!("{} frame_hex: {error}", vector.name)))?;
        verify_frame(&vector.name, &frame, vector.canonical.as_bytes())?;
        let message = match vector.direction {
            Direction::Request => {
                let request = generated::decode_request_payload(
                    vector.canonical.as_bytes(),
                    limits.max_request_bytes(),
                )
                .map_err(|error| {
                    AppError::Verify(format!("{} request decode failed: {error}", vector.name))
                })?;
                let encoded =
                    generated::encode_request_payload(&request, limits.max_request_bytes())
                        .map_err(|error| {
                            AppError::Verify(format!(
                                "{} request encode failed: {error}",
                                vector.name
                            ))
                        })?;
                if encoded != vector.canonical.as_bytes() {
                    return Err(AppError::Verify(format!(
                        "{} Rust request encoder changed canonical bytes",
                        vector.name
                    )));
                }
                Decoded::Request(request)
            }
            Direction::Response => {
                let response = generated::decode_response_payload(
                    vector.canonical.as_bytes(),
                    limits.max_frame_bytes(),
                )
                .map_err(|error| {
                    AppError::Verify(format!("{} response decode failed: {error}", vector.name))
                })?;
                let encoded =
                    generated::encode_response_payload(&response, limits.max_frame_bytes())
                        .map_err(|error| {
                            AppError::Verify(format!(
                                "{} response encode failed: {error}",
                                vector.name
                            ))
                        })?;
                if encoded != vector.canonical.as_bytes() {
                    return Err(AppError::Verify(format!(
                        "{} Rust response encoder changed canonical bytes",
                        vector.name
                    )));
                }
                Decoded::Response(response)
            }
        };
        if decoded.insert(vector.name.as_str(), message).is_some() {
            return Err(AppError::Verify(format!(
                "duplicate vector name {} escaped exact identity validation",
                vector.name
            )));
        }
    }

    for rejection in &fixture.v1_rejections {
        let accepted = match rejection.direction {
            Direction::Request => generated::decode_request_payload(
                rejection.payload.as_bytes(),
                limits.max_request_bytes(),
            )
            .is_ok(),
            Direction::Response => generated::decode_response_payload(
                rejection.payload.as_bytes(),
                limits.max_frame_bytes(),
            )
            .is_ok(),
        };
        if accepted {
            return Err(AppError::Verify(format!(
                "{} v1 payload was accepted by v2 decoder",
                rejection.name
            )));
        }
    }

    for pair in &fixture.echo_pairs {
        let request = match decoded.get(pair.request.as_str()) {
            Some(Decoded::Request(request)) => request,
            Some(Decoded::Response(_)) => {
                return Err(AppError::Verify(format!(
                    "{} is a response, not an echo-pair request",
                    pair.request
                )))
            }
            None => {
                return Err(AppError::Verify(format!(
                    "echo pair request {} is missing",
                    pair.request
                )))
            }
        };
        let response = match decoded.get(pair.response.as_str()) {
            Some(Decoded::Response(response)) => response,
            Some(Decoded::Request(_)) => {
                return Err(AppError::Verify(format!(
                    "{} is a request, not an echo-pair response",
                    pair.response
                )))
            }
            None => {
                return Err(AppError::Verify(format!(
                    "echo pair response {} is missing",
                    pair.response
                )))
            }
        };
        if !generated::echoes(response, request) {
            return Err(AppError::Verify(format!(
                "response {} does not exactly echo request {} IDs",
                pair.response, pair.request
            )));
        }
    }

    println!(
        "authority-wire-v2 vectors: {} canonical, {} v1 rejections, {} echo pairs — OK",
        fixture.vectors.len(),
        fixture.v1_rejections.len(),
        fixture.echo_pairs.len()
    );
    Ok(())
}

fn verify_frame(name: &str, frame: &[u8], canonical: &[u8]) -> Result<(), AppError> {
    if frame.len() < 4 {
        return Err(AppError::Verify(format!(
            "{name} frame lacks four-byte prefix"
        )));
    }
    let prefix: [u8; 4] = frame[..4]
        .try_into()
        .map_err(|_| AppError::Verify(format!("{name} frame prefix is malformed")))?;
    let declared = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| AppError::Verify(format!("{name} declared length cannot fit usize")))?;
    if declared == 0 || declared != canonical.len() || frame.len() != 4 + declared {
        return Err(AppError::Verify(format!(
            "{name} frame length is inconsistent: declared={declared} payload={} total={}",
            canonical.len(),
            frame.len()
        )));
    }
    if &frame[4..] != canonical {
        return Err(AppError::Verify(format!(
            "{name} frame payload differs from canonical bytes"
        )));
    }
    Ok(())
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("odd number of hexadecimal nibbles".to_string());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_nibble(pair[0])?;
            let low = decode_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn decode_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("non-lowercase-hex byte 0x{byte:02x}")),
    }
}

fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .compact()
        .with_writer(std::io::stderr)
        .init();
    let result = parse_path().and_then(|path| verify(&path));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(detail = %error.detail(), "authority-wire-vectors");
            ExitCode::from(error.exit_code())
        }
    }
}
