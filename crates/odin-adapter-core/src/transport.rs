//! Share FramedExecTool framing so host and adapter agree on canonical JSON-RPC bytes.

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};

pub use odin_kernel::{CapabilityContract, HandlerBinding};

use crate::config::{MAX_MAX_RESULTS, MIN_MAX_RESULTS};
use crate::ids::{AdapterWireId, OperationKind};
use crate::operation::IdempotencyKey;

/// Includes the terminating newline to match FramedExecTool's frame limit.
pub const MAX_FRAME_BYTES: usize = 1_048_576;

pub const WEB_SEARCH_KIND: &str = "web.search";

/// Probes are outside the dotted operation grammar to avoid colliding with operation names.
pub const STATUS_KIND: &str = "status";

/// Like `status`, descriptor probes are outside the dotted operation grammar.
pub const DESCRIBE_KIND: &str = "describe";

pub const MAX_QUERY_CHARS: usize = 400;

/// Dotted operation names keep arbitrary declared operations distinct from transport probes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RpcMethod {
    Operation(OperationKind),
    Status,
    Describe,
}

impl RpcMethod {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Operation(kind) => kind.as_str(),
            Self::Status => STATUS_KIND,
            Self::Describe => DESCRIBE_KIND,
        }
    }

    /// Parsing checks grammar; the dispatcher checks whether an operation is declared.
    pub fn parse(value: &str) -> Result<Self, ProtocolError> {
        if value == STATUS_KIND {
            return Ok(Self::Status);
        }
        if value == DESCRIBE_KIND {
            return Ok(Self::Describe);
        }
        OperationKind::new(value)
            .map(Self::Operation)
            .map_err(|_| ProtocolError::UnknownMethod(value.to_owned()))
    }
}

impl std::fmt::Display for RpcMethod {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for RpcMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RpcMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// Rejects versions other than `"2.0"` during deserialization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonRpcV2;

impl Serialize for JsonRpcV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for JsonRpcV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value == "2.0" {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "jsonrpc version must be exactly \"2.0\"",
            ))
        }
    }
}

/// String IDs must round-trip unchanged so replies can be matched to requests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct JsonRpcRequest {
    pub jsonrpc: JsonRpcV2,
    pub id: String,
    pub method: RpcMethod,
    pub params: Value,
}

impl JsonRpcRequest {
    pub fn new(
        id: impl Into<String>,
        method: RpcMethod,
        params: Value,
    ) -> Result<Self, ProtocolError> {
        if !params.is_object() {
            return Err(ProtocolError::ParamsNotObject);
        }
        Ok(Self {
            jsonrpc: JsonRpcV2,
            id: id.into(),
            method,
            params,
        })
    }

    /// Deployment configuration stays in the backend, not in operation parameters.
    pub fn web_search(
        id: impl Into<String>,
        operation_id: AdapterWireId,
        idempotency_key: IdempotencyKey,
        input: WebSearchInput,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            jsonrpc: JsonRpcV2,
            id: id.into(),
            method: RpcMethod::Operation(
                OperationKind::new(WEB_SEARCH_KIND).expect("canonical kind is grammar-valid"),
            ),
            params: WebSearchParams::new(operation_id, idempotency_key, input)?.to_wire(),
        })
    }

    pub fn status(id: impl Into<String>) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            id: id.into(),
            method: RpcMethod::Status,
            params: StatusParams.to_wire(),
        }
    }

    pub fn describe(id: impl Into<String>) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            id: id.into(),
            method: RpcMethod::Describe,
            params: StatusParams.to_wire(),
        }
    }

    pub fn from_wire(wire: &Value) -> Result<Self, ProtocolError> {
        let request: Self = serde::Deserialize::deserialize(wire)
            .map_err(|error| ProtocolError::InvalidEnvelope(error.to_string()))?;
        if !request.params.is_object() {
            return Err(ProtocolError::ParamsNotObject);
        }
        Ok(request)
    }

    pub fn to_wire(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": self.method.as_str(),
            "params": self.params,
        })
    }
}
/// Only operation metadata and input travel on the wire; deployment facts stay in backend config.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WebSearchParams {
    pub operation_id: AdapterWireId,
    pub idempotency_key: IdempotencyKey,
    pub input: WebSearchInput,
}

impl WebSearchParams {
    pub fn new(
        operation_id: AdapterWireId,
        idempotency_key: IdempotencyKey,
        input: WebSearchInput,
    ) -> Result<Self, ProtocolError> {
        let params = Self {
            operation_id,
            idempotency_key,
            input,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn from_wire(wire: &Value) -> Result<Self, ProtocolError> {
        let params: Self = serde::Deserialize::deserialize(wire)
            .map_err(|error| ProtocolError::InvalidEnvelope(error.to_string()))?;
        params.validate()?;
        Ok(params)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.input.validate()
    }

    pub fn to_wire(&self) -> Value {
        json!({
            "operation_id": self.operation_id.as_str(),
            "idempotency_key": self.idempotency_key.as_str(),
            "input": self.input.to_wire(),
        })
    }

    pub fn operation_id(&self) -> &AdapterWireId {
        &self.operation_id
    }

    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    pub fn input(&self) -> &WebSearchInput {
        &self.input
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct WebSearchInput {
    query: String,
    count: u32,
}

impl WebSearchInput {
    pub fn new(query: impl Into<String>, count: u32) -> Result<Self, ProtocolError> {
        let input = Self {
            query: query.into(),
            count,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let length = self.query.chars().count();
        if length == 0 {
            return Err(ProtocolError::EmptyQuery);
        }
        if length > MAX_QUERY_CHARS {
            return Err(ProtocolError::QueryTooLong);
        }
        if !(MIN_MAX_RESULTS..=MAX_MAX_RESULTS).contains(&self.count) {
            return Err(ProtocolError::InvalidCount);
        }
        Ok(())
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn to_wire(&self) -> Value {
        json!({ "query": self.query, "count": self.count })
    }
}

/// Status probes use an empty object because status facts belong in the reply.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StatusParams;

impl StatusParams {
    pub fn new() -> Self {
        Self
    }

    pub fn from_wire(wire: &Value) -> Result<Self, ProtocolError> {
        let object = wire.as_object().ok_or(ProtocolError::ParamsNotObject)?;
        if !object.is_empty() {
            return Err(ProtocolError::StatusParamsNotEmpty);
        }
        Ok(Self)
    }

    pub fn to_wire(self) -> Value {
        json!({})
    }
}

/// Server-range codes distinguish backend unavailability from JSON-RPC protocol errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdapterErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    /// No upstream request was sent when credential access failed.
    CredentialsUnavailable,
    AccountUnavailable,
    Timeout,
}

impl AdapterErrorCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::CredentialsUnavailable => -32000,
            Self::AccountUnavailable => -32001,
            Self::Timeout => -32002,
        }
    }
}

impl TryFrom<i32> for AdapterErrorCode {
    type Error = ProtocolError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            -32700 => Ok(Self::ParseError),
            -32600 => Ok(Self::InvalidRequest),
            -32601 => Ok(Self::MethodNotFound),
            -32602 => Ok(Self::InvalidParams),
            -32603 => Ok(Self::InternalError),
            -32000 => Ok(Self::CredentialsUnavailable),
            -32001 => Ok(Self::AccountUnavailable),
            -32002 => Ok(Self::Timeout),
            other => Err(ProtocolError::UnknownErrorCode(other)),
        }
    }
}

impl Serialize for AdapterErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i32(self.code())
    }
}

impl<'de> Deserialize<'de> for AdapterErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i32::deserialize(deserializer)?;
        Self::try_from(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonRpcErrorObject {
    pub code: AdapterErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A `null` result is valid, but each response must contain exactly one of `result` or `error`.
#[derive(Clone, Debug, PartialEq)]
pub enum JsonRpcOutcome {
    Success {
        id: String,
        result: Value,
    },
    Error {
        id: String,
        code: AdapterErrorCode,
        message: String,
        data: Option<Value>,
    },
}

impl JsonRpcOutcome {
    pub fn id(&self) -> &str {
        match self {
            Self::Success { id, .. } | Self::Error { id, .. } => id,
        }
    }

    /// Require the echoed request ID to prevent accepting an unrelated reply.
    pub fn from_wire(wire: &Value, expected_id: &str) -> Result<Self, ProtocolError> {
        let object = wire.as_object().ok_or(ProtocolError::NotAnObject)?;
        match object.get("jsonrpc").and_then(Value::as_str) {
            Some("2.0") => {}
            _ => return Err(ProtocolError::BadVersion),
        }
        let id = object
            .get("id")
            .ok_or(ProtocolError::MissingField("id"))?
            .as_str()
            .ok_or(ProtocolError::IdNotAString)?;
        if id != expected_id {
            return Err(ProtocolError::IdMismatch {
                expected: expected_id.to_owned(),
                found: id.to_owned(),
            });
        }
        match (object.contains_key("result"), object.contains_key("error")) {
            (true, true) | (false, false) => Err(ProtocolError::ResultAndErrorExclusive),
            (true, false) => Ok(Self::Success {
                id: id.to_owned(),
                result: object["result"].clone(),
            }),
            (false, true) => {
                let error: JsonRpcErrorObject =
                    serde::Deserialize::deserialize(&object["error"])
                        .map_err(|e| ProtocolError::InvalidEnvelope(e.to_string()))?;
                if error.message.trim().is_empty() {
                    return Err(ProtocolError::EmptyErrorMessage);
                }
                Ok(Self::Error {
                    id: id.to_owned(),
                    code: error.code,
                    message: error.message,
                    data: error.data,
                })
            }
        }
    }

    pub fn to_wire(&self) -> Value {
        match self {
            Self::Success { id, result } => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result,
            }),
            Self::Error {
                id,
                code,
                message,
                data,
            } => {
                let mut error = serde_json::Map::new();
                error.insert("code".to_owned(), json!(code.code()));
                error.insert("message".to_owned(), json!(message));
                if let Some(data) = data {
                    error.insert("data".to_owned(), data.clone());
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": Value::Object(error),
                })
            }
        }
    }
}

/// Use `NotDispatched` only when the frame was not sent; all other uncertain outcomes stay unknown.
pub trait AdapterTransport: Send + Sync {
    fn call(
        &self,
        binding: &HandlerBinding,
        timeout: Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterTransportFault {
    /// The request frame was not sent.
    NotDispatched { detail: String },
    /// The request may have been sent, but its outcome is unknown.
    DispatchedUnknown { detail: String },
}

impl AdapterTransportFault {
    /// Only this fault class permits a definite unavailable response.
    pub const fn proved_not_dispatched(&self) -> bool {
        matches!(self, Self::NotDispatched { .. })
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::NotDispatched { detail } | Self::DispatchedUnknown { detail } => detail,
        }
    }
}

/// Canonical encoding must match FramedExecTool's stdin format byte-for-byte.
pub fn encode_frame(value: &Value) -> Result<Vec<u8>, ProtocolError> {
    let mut frame =
        odin_strict_json::canonicalize(value).map_err(|error| ProtocolError::Encode {
            detail: error.to_string(),
        })?;
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len() + 1,
            max: MAX_FRAME_BYTES,
        });
    }
    frame.push(b'\n');
    Ok(frame)
}

/// Duplicate keys and embedded newlines are rejected to keep framing and JSON interpretation unique.
pub fn decode_frame(bytes: &[u8]) -> Result<Value, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    let (newline, frame) = bytes.split_last().expect("checked nonempty");
    if *newline != b'\n' {
        return Err(ProtocolError::MissingNewline);
    }
    if frame.contains(&b'\n') {
        return Err(ProtocolError::EmbeddedNewline);
    }
    if frame.len() + 1 > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len() + 1,
            max: MAX_FRAME_BYTES,
        });
    }
    let strict = odin_strict_json::parse(
        frame,
        odin_strict_json::DecodeOptions {
            byte_ceiling: MAX_FRAME_BYTES,
            ..odin_strict_json::DecodeOptions::default()
        },
    )
    .map_err(|error| ProtocolError::InvalidJson {
        detail: error.to_string(),
    })?;
    let value = serde_json::to_value(&strict).map_err(|error| ProtocolError::InvalidJson {
        detail: error.to_string(),
    })?;
    if !value.is_object() {
        return Err(ProtocolError::NotAnObject);
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    #[error("frame of {size} bytes exceeds the {max}-byte bound")]
    FrameTooLarge { size: usize, max: usize },
    #[error("frame is empty")]
    EmptyFrame,
    #[error("frame does not end with a newline")]
    MissingNewline,
    #[error("frame contains an embedded newline")]
    EmbeddedNewline,
    #[error("frame is not valid strict JSON: {detail}")]
    InvalidJson { detail: String },
    #[error("frame is not a JSON object")]
    NotAnObject,
    #[error("canonical encode failed: {detail}")]
    Encode { detail: String },
    #[error("JSON-RPC version must be exactly \"2.0\"")]
    BadVersion,
    #[error("missing JSON-RPC field {0}")]
    MissingField(&'static str),
    #[error("response id {found:?} does not match expected {expected:?}")]
    IdMismatch { expected: String, found: String },
    #[error("request params must be a JSON object")]
    ParamsNotObject,
    #[error("JSON-RPC id must be a string")]
    IdNotAString,
    #[error("web.search query must not be empty")]
    EmptyQuery,
    #[error("web.search query exceeds {MAX_QUERY_CHARS} characters")]
    QueryTooLong,
    #[error("web.search count must be between {MIN_MAX_RESULTS} and {MAX_MAX_RESULTS}")]
    InvalidCount,
    #[error("unknown JSON-RPC method {0:?}")]
    UnknownMethod(String),
    #[error("status params must be exactly the empty object")]
    StatusParamsNotEmpty,
    #[error("response must carry exactly one of result or error")]
    ResultAndErrorExclusive,
    #[error("error message must not be empty")]
    EmptyErrorMessage,
    #[error("unknown JSON-RPC error code {0}")]
    UnknownErrorCode(i32),
    #[error("invalid JSON-RPC wire value: {0}")]
    InvalidEnvelope(String),
}
