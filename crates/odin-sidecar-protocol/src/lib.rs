//! Canonical JSON with four-byte length framing for sidecar requests and effector exchanges.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

use odin_strict_json::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub mod generated;

pub use generated::*;

/// Select compiled behavior rather than allowing transport requests to name arbitrary operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectBehavior {
    Execute,
    Verify,
    Preimage,
    Read,
    Write,
    Diff,
    /// The sidecar derives the interpreter and scratch path; callers supply source, not argv.
    Eval,
}

pub const SOURCE_KIND_GIT_COMMIT: &str = "git-commit";
pub const SOURCE_KIND_KNOWLEDGE_ROOT: &str = "knowledge-root";

/// Capsule paths come from host configuration, not caller-selected access rights.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleBinding {
    /// Reject requests naming another capsule rather than lending them this root.
    pub capsule_id: String,
    pub root: String,
    pub source_commit: String,
    /// Knowledge-root path digests are not Git commits and cannot satisfy source-verified effects.
    #[serde(default = "default_source_kind")]
    pub source_kind: String,
    pub git_bin: String,
}

fn default_source_kind() -> String {
    SOURCE_KIND_GIT_COMMIT.to_owned()
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOp {
    Declare,
    Observe,
    Execute,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum EffectRequest {
    Declare {
        capsule: CapsuleBinding,
        behavior: EffectBehavior,
        arguments: Value,
    },
    Observe {
        capsule: CapsuleBinding,
        behavior: EffectBehavior,
        arguments: Value,
    },
    Execute {
        capsule: CapsuleBinding,
        behavior: EffectBehavior,
        arguments: Value,
    },
}

impl EffectRequest {
    pub const fn op(&self) -> EffectOp {
        match self {
            Self::Declare { .. } => EffectOp::Declare,
            Self::Observe { .. } => EffectOp::Observe,
            Self::Execute { .. } => EffectOp::Execute,
        }
    }

    pub const fn behavior(&self) -> EffectBehavior {
        match self {
            Self::Declare { behavior, .. }
            | Self::Observe { behavior, .. }
            | Self::Execute { behavior, .. } => *behavior,
        }
    }

    pub const fn capsule(&self) -> &CapsuleBinding {
        match self {
            Self::Declare { capsule, .. }
            | Self::Observe { capsule, .. }
            | Self::Execute { capsule, .. } => capsule,
        }
    }

    pub const fn arguments(&self) -> &Value {
        match self {
            Self::Declare { arguments, .. }
            | Self::Observe { arguments, .. }
            | Self::Execute { arguments, .. } => arguments,
        }
    }
}

/// Paths are capsule-rooted; operations are `create`, `write`, or `unlink`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFileChange {
    pub op: String,
    pub path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectIdentity {
    pub pid: i32,
    pub start_time_ticks: u64,
    pub process_group: i32,
}

/// Leave unobservable fields absent rather than inventing values.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectResponse {
    pub ok: bool,
    pub op: EffectOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_post: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<EffectIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub survivors: Vec<EffectIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_stopped: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler_entry_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler_exit_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filesystem_changes: Vec<EffectFileChange>,
}

pub const EFFECT_MAX_REQUEST_BYTES: usize = 262_144;
pub const EFFECT_MAX_RESPONSE_BYTES: usize = 4_194_304;

/// Inject sandbox paths from host configuration so request arguments cannot widen access.
pub const EFFECTOR_BWRAP_ENV: &str = "ODIN_EFFECTOR_BWRAP";
pub const EFFECTOR_CACHE_ROOT_ENV: &str = "ODIN_EFFECTOR_CACHE_ROOT";
pub const EFFECTOR_TOOL_PATH_ENV: &str = "ODIN_EFFECTOR_TOOL_PATH";
pub const EFFECTOR_CONTEXT_ROOT_ENV: &str = "ODIN_EFFECTOR_CONTEXT_ROOT";
pub const EFFECTOR_CARGO_REGISTRY_CACHE_ENV: &str = "ODIN_EFFECTOR_CARGO_REGISTRY_CACHE";
pub const EFFECTOR_CARGO_GIT_CACHE_ENV: &str = "ODIN_EFFECTOR_CARGO_GIT_CACHE";
pub const EFFECTOR_NIX_CONFIG_ROOT_ENV: &str = "ODIN_EFFECTOR_NIX_CONFIG_ROOT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireLimits {
    max_request_bytes: usize,
    max_frame_bytes: usize,
}

impl WireLimits {
    pub fn new(max_request_bytes: usize, max_frame_bytes: usize) -> Result<Self, ProtocolError> {
        if max_request_bytes == 0
            || max_frame_bytes == 0
            || max_request_bytes > max_frame_bytes
            || max_frame_bytes > u32::MAX as usize
        {
            return Err(ProtocolError::InvalidLimits);
        }
        Ok(Self {
            max_request_bytes,
            max_frame_bytes,
        })
    }

    pub const fn max_request_bytes(self) -> usize {
        self.max_request_bytes
    }

    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }
}

#[derive(Debug)]
pub enum ProtocolError {
    InvalidLimits,
    EmptyFrame,
    FrameTooLarge { declared: usize, ceiling: usize },
    TruncatedFrame,
    Io(io::Error),
    Decode(String),
    Encode(String),
}

impl ProtocolError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidLimits => "protocol.invalid_limits",
            Self::EmptyFrame => "protocol.empty_frame",
            Self::FrameTooLarge { .. } => "protocol.frame_too_large",
            Self::TruncatedFrame => "protocol.truncated_frame",
            Self::Io(_) => "protocol.io",
            Self::Decode(_) => "protocol.decode",
            Self::Encode(_) => "protocol.encode",
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter
                .write_str("wire limits must be nonzero, request <= frame, and frame <= u32::MAX"),
            Self::EmptyFrame => formatter.write_str("zero-length frames are forbidden"),
            Self::FrameTooLarge { declared, ceiling } => {
                write!(
                    formatter,
                    "frame length {declared} exceeds ceiling {ceiling}"
                )
            }
            Self::TruncatedFrame => formatter.write_str("frame ended before its declared length"),
            Self::Io(error) => write!(formatter, "frame I/O failed: {error}"),
            Self::Decode(detail) => write!(formatter, "frame payload was rejected: {detail}"),
            Self::Encode(detail) => {
                write!(formatter, "frame payload could not be encoded: {detail}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

pub fn read_payload(
    reader: &mut impl Read,
    ceiling: usize,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut first = [0_u8; 1];
    let read = reader.read(&mut first).map_err(ProtocolError::Io)?;
    if read == 0 {
        return Ok(None);
    }
    let mut rest = [0_u8; 3];
    reader.read_exact(&mut rest).map_err(map_frame_read_error)?;
    let [first] = first;
    let [second, third, fourth] = rest;
    let declared = u32::from_be_bytes([first, second, third, fourth]) as usize;
    if declared == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if declared > ceiling {
        return Err(ProtocolError::FrameTooLarge { declared, ceiling });
    }
    let mut payload = vec![0_u8; declared];
    reader
        .read_exact(&mut payload)
        .map_err(map_frame_read_error)?;
    Ok(Some(payload))
}

pub fn write_payload(
    writer: &mut impl Write,
    payload: &[u8],
    ceiling: usize,
) -> Result<(), ProtocolError> {
    if payload.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if payload.len() > ceiling {
        return Err(ProtocolError::FrameTooLarge {
            declared: payload.len(),
            ceiling,
        });
    }
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        declared: payload.len(),
        ceiling,
    })?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(ProtocolError::Io)
}

fn map_frame_read_error(error: io::Error) -> ProtocolError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        ProtocolError::TruncatedFrame
    } else {
        ProtocolError::Io(error)
    }
}

fn read_effect<T: DeserializeOwned>(
    reader: &mut impl Read,
    ceiling: usize,
) -> Result<Option<T>, ProtocolError> {
    let Some(payload) = read_payload(reader, ceiling)? else {
        return Ok(None);
    };
    odin_strict_json::decode(&payload, ceiling)
        .map(Some)
        .map_err(|error| ProtocolError::Decode(error.to_string()))
}

fn write_effect<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
    ceiling: usize,
) -> Result<(), ProtocolError> {
    let payload = odin_strict_json::canonicalize(value)
        .map_err(|error| ProtocolError::Encode(error.to_string()))?;
    write_payload(writer, &payload, ceiling)
}

/// `Ok(None)` denotes a closed channel, not a malformed request.
pub fn read_effect_request(
    reader: &mut impl Read,
    ceiling: usize,
) -> Result<Option<EffectRequest>, ProtocolError> {
    read_effect(reader, ceiling)
}

pub fn write_effect_request(
    writer: &mut impl Write,
    request: &EffectRequest,
    ceiling: usize,
) -> Result<(), ProtocolError> {
    write_effect(writer, request, ceiling)
}

/// `Ok(None)` denotes a closed channel, not a malformed response.
pub fn read_effect_response(
    reader: &mut impl Read,
    ceiling: usize,
) -> Result<Option<EffectResponse>, ProtocolError> {
    read_effect(reader, ceiling)
}

pub fn write_effect_response(
    writer: &mut impl Write,
    response: &EffectResponse,
    ceiling: usize,
) -> Result<(), ProtocolError> {
    write_effect(writer, response, ceiling)
}

#[cfg(test)]
mod effect_response_contract {
    use super::*;

    fn measured_response(stdout_hex: String) -> EffectResponse {
        EffectResponse {
            ok: true,
            op: EffectOp::Execute,
            observed: None,
            expected_post: None,
            outcome: Some("completed".to_owned()),
            detail: None,
            exit_code: Some(0),
            signal: None,
            cancelled: Some(false),
            identity: Some(EffectIdentity {
                pid: 42,
                start_time_ticks: 7,
                process_group: 42,
            }),
            survivors: Vec::new(),
            stdout_bytes: Some((stdout_hex.len() / 2) as u64),
            stdout_hex: Some(stdout_hex),
            stderr_hex: Some(String::new()),
            stderr_bytes: Some(0),
            stdout_truncated: Some(false),
            stderr_truncated: Some(false),
            handler_entry_ms: Some(100),
            handler_exit_ms: Some(125),
            worker_stopped: Some(true),
            filesystem_changes: vec![EffectFileChange {
                op: "write".to_owned(),
                path: "/capsule/result.txt".to_owned(),
            }],
        }
    }

    #[test]
    fn full_measured_response_round_trips_canonically() {
        let response = measured_response("6f64696e0a".to_owned());
        let mut framed = Vec::new();
        write_effect_response(&mut framed, &response, EFFECT_MAX_RESPONSE_BYTES)
            .expect("bounded response writes");
        let decoded = read_effect_response(&mut framed.as_slice(), EFFECT_MAX_RESPONSE_BYTES)
            .expect("response frame reads")
            .expect("one response");
        assert_eq!(decoded, response);
    }

    #[test]
    fn oversized_capture_and_unknown_response_fields_fail_closed() {
        let response = measured_response("00".repeat(128));
        let mut framed = Vec::new();
        assert!(matches!(
            write_effect_response(&mut framed, &response, 64),
            Err(ProtocolError::FrameTooLarge { .. })
        ));

        let payload = br#"{"filesystem_changes":[],"ok":true,"op":"execute","survivors":[],"unexpected":true}"#;
        let mut framed = Vec::new();
        write_payload(&mut framed, payload, 1_024).expect("raw fixture frame");
        assert!(matches!(
            read_effect_response(&mut framed.as_slice(), 1_024),
            Err(ProtocolError::Decode(_))
        ));
    }

    #[test]
    fn eval_is_a_closed_private_behavior_not_an_authority_verdict() {
        let value = odin_strict_json::Value::Object(Vec::new());
        let request = EffectRequest::Execute {
            capsule: CapsuleBinding {
                capsule_id: "capsule-protocol".to_owned(),
                root: "/capsule".to_owned(),
                source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                source_kind: "git-commit".to_owned(),
                git_bin: "/store/git".to_owned(),
            },
            behavior: EffectBehavior::Eval,
            arguments: value,
        };
        let mut framed = Vec::new();
        write_effect_request(&mut framed, &request, EFFECT_MAX_REQUEST_BYTES)
            .expect("eval request writes");
        let decoded = read_effect_request(&mut framed.as_slice(), EFFECT_MAX_REQUEST_BYTES)
            .expect("eval request reads")
            .expect("one request");
        assert_eq!(decoded, request);
    }
}
