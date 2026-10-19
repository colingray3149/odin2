//! Derive advertised capabilities from dispatcher constants so unsupported methods stay unadvertised.

use std::io;

use serde::de::DeserializeOwned;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use tokio::io::AsyncBufReadExt as _;

/// Match Huginn's frame limit so neither side accepts messages the other cannot handle.
pub(crate) const MAX_FRAME_BYTES: usize =
    odin_huginn::protocol::CodecLimits::conservative().max_frame_bytes;

pub(crate) const ACP_PROTOCOL_VERSION: u64 = 1;

/// Keep IDs as JSON values so client-chosen strings and numbers round-trip unchanged.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Message {
    pub id: Option<Value>,
    pub method: Option<String>,
    pub params: Option<Value>,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub(crate) const PARSE_ERROR: i64 = -32700;
    pub(crate) const INVALID_REQUEST: i64 = -32600;
    pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
    pub(crate) const INVALID_PARAMS: i64 = -32602;
    pub(crate) const INTERNAL_ERROR: i64 = -32603;
    /// Server-range errors distinguish backend refusals from JSON-RPC protocol errors.
    pub(crate) const GOVERNED_REFUSAL: i64 = -32000;

    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RpcError {}

pub(crate) fn framing_error(error: io::Error) -> RpcError {
    match error.into_inner() {
        Some(cause) => match cause.downcast::<RpcError>() {
            Ok(error) => *error,
            Err(cause) => RpcError::new(RpcError::PARSE_ERROR, cause.to_string()),
        },
        None => RpcError::new(RpcError::PARSE_ERROR, "invalid ACP frame"),
    }
}

impl Message {
    pub(crate) fn from_value(value: Value) -> Result<Self, String> {
        let object = value.as_object().ok_or("message is not a JSON object")?;
        match object.get("jsonrpc").and_then(Value::as_str) {
            Some("2.0") => {}
            _ => return Err("jsonrpc must be exactly \"2.0\"".to_owned()),
        }
        let id = object.get("id");
        if id.is_some_and(|id| !matches!(id, Value::Null | Value::String(_) | Value::Number(_))) {
            return Err("id must be a string, number, or null".to_owned());
        }
        let method = object.get("method");
        let has_result = object.contains_key("result");
        let has_error = object.contains_key("error");
        match method {
            Some(Value::String(_)) if !has_result && !has_error => {
                if object
                    .get("params")
                    .is_some_and(|params| !params.is_object() && !params.is_array())
                {
                    return Err("params must be an object or array".to_owned());
                }
            }
            None if id.is_some() && has_result != has_error => {}
            _ => {
                return Err(
                    "message must be exactly one request, notification, or response".to_owned(),
                )
            }
        }
        Ok(Self {
            id: id.cloned(),
            method: method.and_then(Value::as_str).map(str::to_owned),
            params: object.get("params").cloned(),
            result: object.get("result").cloned(),
            error: object
                .get("error")
                .map(|error| {
                    serde_json::from_value(error.clone()).map_err(|error| error.to_string())
                })
                .transpose()?,
        })
    }

    pub(crate) fn request(id: Value, method: &str, params: Value) -> Self {
        Self {
            id: Some(id),
            method: Some(method.to_owned()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    pub(crate) fn notification(method: &str, params: Value) -> Self {
        Self {
            id: None,
            method: Some(method.to_owned()),
            params: Some(params),
            result: None,
            error: None,
        }
    }

    pub(crate) fn success(id: Value, result: Value) -> Self {
        Self {
            id: Some(id),
            method: None,
            params: None,
            result: Some(result),
            error: None,
        }
    }

    /// Unparseable requests use `Value::Null` because their ID cannot be recovered.
    pub(crate) fn failure(id: Value, error: RpcError) -> Self {
        Self {
            id: Some(id),
            method: None,
            params: None,
            result: None,
            error: Some(error),
        }
    }

    pub(crate) fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let has_error = self.error.is_some();
        let fields = 2
            + self.method.as_ref().map_or(0, |_| 1)
            + self.params.as_ref().map_or(0, |_| 1)
            + if has_error {
                0
            } else {
                self.result.as_ref().map_or(0, |_| 1)
            };
        let mut state = serializer.serialize_struct("Message", fields)?;
        state.serialize_field("jsonrpc", "2.0")?;
        if let Some(id) = &self.id {
            state.serialize_field("id", id)?;
        }
        if let Some(method) = &self.method {
            state.serialize_field("method", method)?;
        }
        if let Some(params) = &self.params {
            state.serialize_field("params", params)?;
        }
        if let Some(error) = &self.error {
            state.serialize_field("error", error)?;
        } else if let Some(result) = &self.result {
            state.serialize_field("result", result)?;
        }
        state.end()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitializeParams {
    pub protocol_version: u64,
    /// Diagnostic only; the frontend does not invoke client filesystem or terminal methods.
    #[serde(default)]
    pub client_capabilities: Value,
    #[serde(default)]
    pub client_info: Option<Implementation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Implementation {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Every advertised capability requires a dispatcher implementation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AgentCapabilities {
    pub load_session: bool,
}

/// Seat and project identity is session-specific, not part of the generic agent name.
pub(crate) const AGENT_NAME: &str = "odin-acp";
pub(crate) const AGENT_TITLE: &str = "Odin governed session frontend";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InitializeResult {
    pub protocol_version: u64,
    pub agent_capabilities: AgentCapabilities,
    /// Authentication uses the enrolled device credential, not an ACP exchange.
    pub auth_methods: [Value; 0],
    pub agent_info: Implementation,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionSetupParams {
    pub cwd: String,
    #[serde(default)]
    pub mcp_servers: Vec<Value>,
    #[serde(default)]
    pub additional_directories: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoadSessionParams {
    #[serde(flatten)]
    pub setup: SessionSetupParams,
    pub session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PromptParams {
    pub session_id: String,
    pub prompt: Vec<Value>,
}

pub(crate) const STOP_END_TURN: &str = "end_turn";
pub(crate) const STOP_CANCELLED: &str = "cancelled";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PromptResult {
    pub stop_reason: &'static str,
}

/// Omit always-allow because each consequential action needs its own decision.
pub(crate) fn permission_options() -> Value {
    json!([
        { "optionId": "allow", "name": "Allow once", "kind": "allow_once" },
        { "optionId": "deny", "name": "Deny", "kind": "reject_once" }
    ])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecidedPermission {
    AllowOnce,
    Deny,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RequestPermissionResult {
    pub outcome: Value,
}

impl RequestPermissionResult {
    /// Cancellation is a refusal because the client gave no consent.
    pub(crate) fn decision(&self) -> Option<DecidedPermission> {
        let outcome = self.outcome.get("outcome").and_then(Value::as_str)?;
        match outcome {
            "cancelled" => Some(DecidedPermission::Deny),
            "selected" => match self.outcome.get("optionId").and_then(Value::as_str) {
                Some("allow") => Some(DecidedPermission::AllowOnce),
                _ => Some(DecidedPermission::Deny),
            },
            _ => None,
        }
    }
}

pub(crate) fn agent_message_chunk(session_id: &str, text: &str) -> Value {
    json!({
        "sessionId": session_id,
        "update": {
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": text }
        }
    })
}

pub(crate) fn user_message_chunk(session_id: &str, text: &str) -> Value {
    json!({
        "sessionId": session_id,
        "update": {
            "sessionUpdate": "user_message_chunk",
            "content": { "type": "text", "text": text }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn tool_call(
    session_id: &str,
    tool_call_id: &str,
    title: &str,
    kind: &str,
    status: &str,
    raw_input: Option<Value>,
    content: Option<Value>,
) -> Value {
    let mut update = json!({
        "sessionUpdate": "tool_call",
        "toolCallId": tool_call_id,
        "title": title,
        "kind": kind,
        "status": status,
    });
    if let Some(raw_input) = raw_input {
        update["rawInput"] = raw_input;
    }
    if let Some(content) = content {
        update["content"] = content;
    }
    json!({ "sessionId": session_id, "update": update })
}

pub(crate) fn tool_call_update(
    session_id: &str,
    tool_call_id: &str,
    status: &str,
    content: Option<Value>,
) -> Value {
    let mut update = json!({
        "sessionUpdate": "tool_call_update",
        "toolCallId": tool_call_id,
        "status": status,
    });
    if let Some(content) = content {
        update["content"] = content;
    }
    json!({ "sessionId": session_id, "update": update })
}

pub(crate) fn request_permission(
    session_id: &str,
    tool_call_id: &str,
    title: &str,
    kind: &str,
    raw_input: Option<Value>,
) -> Value {
    let mut tool_call = json!({
        "toolCallId": tool_call_id,
        "title": title,
        "kind": kind,
        "status": "pending",
    });
    if let Some(raw_input) = raw_input {
        tool_call["rawInput"] = raw_input;
    }
    json!({
        "sessionId": session_id,
        "toolCall": tool_call,
        "options": permission_options(),
    })
}

/// Display classification must not determine authorization.
pub(crate) fn tool_kind(capability_id: &str) -> &'static str {
    let id = capability_id.to_ascii_lowercase();
    if id.contains("read") || id.contains("list") || id.contains("view") {
        "read"
    } else if id.contains("write") || id.contains("edit") || id.contains("patch") {
        "edit"
    } else if id.contains("delete") || id.contains("remove") {
        "delete"
    } else if id.contains("move") || id.contains("rename") {
        "move"
    } else if id.contains("search") || id.contains("query") || id.contains("find") {
        "search"
    } else if id.contains("shell")
        || id.contains("exec")
        || id.contains("run")
        || id.contains("command")
    {
        "execute"
    } else if id.contains("fetch") || id.contains("http") {
        "fetch"
    } else {
        "other"
    }
}

/// Reject non-text blocks rather than silently dropping unsupported content.
pub(crate) fn text_of_content_block(block: &Value) -> Result<String, RpcError> {
    let block_type = block
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "content block has no type"))?;
    match block_type {
        "text" => {
            let text = block
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::new(RpcError::INVALID_PARAMS, "text block has no text"))?;
            Ok(text.to_owned())
        }
        "image" | "audio" => Err(RpcError::new(
            RpcError::GOVERNED_REFUSAL,
            format!("unsupported content block {block_type:?}: the governed session channel carries text only"),
        )),
        "resource_link" | "resource" => Err(RpcError::new(
            RpcError::GOVERNED_REFUSAL,
            "unsupported content block: embedded resources are not accepted by the governed session channel",
        )),
        other => Err(RpcError::new(
            RpcError::INVALID_PARAMS,
            format!("unknown content block type {other:?}"),
        )),
    }
}

pub(crate) fn prompt_blocks_to_text(blocks: &[Value]) -> Result<Vec<String>, RpcError> {
    blocks
        .iter()
        .map(text_of_content_block)
        .collect::<Result<Vec<_>, RpcError>>()
}

pub(crate) fn decode_params<P: DeserializeOwned>(
    params: Option<&Value>,
    method: &str,
) -> Result<P, RpcError> {
    let params = params.cloned().unwrap_or(Value::Null);
    serde_json::from_value(params).map_err(|error| {
        RpcError::new(
            RpcError::INVALID_PARAMS,
            format!("{method} params are invalid: {error}"),
        )
    })
}

#[derive(Debug)]
pub(crate) enum Framing {
    Message(Message),
    Eof,
}

/// Oversized lines abort the session because truncation would corrupt message framing.
pub(crate) async fn read_message(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
    line: &mut Vec<u8>,
    max_bytes: usize,
) -> io::Result<Framing> {
    // The caller retains partial bytes when select! cancels this future.
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            let message = finish_line(line);
            line.clear();
            return Ok(message?.map_or(Framing::Eof, Framing::Message));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let length = newline.unwrap_or(available.len());
        if line.len() > max_bytes || length > max_bytes - line.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACP frame exceeds the bounded frame size",
            ));
        }
        line.extend_from_slice(&available[..length]);
        reader.consume(length + usize::from(newline.is_some()));
        if newline.is_some() {
            let message = finish_line(line);
            line.clear();
            if let Some(message) = message? {
                return Ok(Framing::Message(message));
            }
        }
    }
}

fn finish_line(line: &[u8]) -> io::Result<Option<Message>> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Message::from_value(value).map(Some).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            RpcError::new(RpcError::INVALID_REQUEST, error),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn invalid_envelopes_are_not_reported_as_json_syntax_errors() {
        for (wire, code) in [
            (b"not-json\n".as_slice(), RpcError::PARSE_ERROR),
            (
                b"{\"jsonrpc\":\"2.0\",\"method\":false,\"id\":1}\n".as_slice(),
                RpcError::INVALID_REQUEST,
            ),
        ] {
            let mut input = tokio::io::BufReader::new(wire);
            let error = read_message(&mut input, &mut Vec::new(), MAX_FRAME_BYTES)
                .await
                .expect_err("invalid input");
            assert_eq!(framing_error(error).code, code);
        }
    }

    fn parse(raw: &str) -> Result<Message, String> {
        Message::from_value(serde_json::from_str(raw).expect("test json"))
    }

    #[test]
    fn parses_request_notification_and_response() {
        let request =
            parse(r#"{"jsonrpc":"2.0","id":7,"method":"session/new","params":{"cwd":"/x"}}"#)
                .expect("request parses");
        assert!(request.method.is_some() && request.id.is_some());
        assert_eq!(request.id, Some(json!(7)));
        assert_eq!(request.method.as_deref(), Some("session/new"));

        let notification =
            parse(r#"{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s"}}"#)
                .expect("notification parses");
        assert!(notification.is_notification());

        let response = parse(r#"{"jsonrpc":"2.0","id":"abc","result":{"stopReason":"end_turn"}}"#)
            .expect("response parses");
        assert_eq!(response.method, None);
        assert_eq!(response.id, Some(json!("abc")));

        let error =
            parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#)
                .expect("error response parses");
        assert_eq!(error.error.as_ref().expect("error").code, -32602);
    }

    #[test]
    fn rejects_non_jsonrpc_envelopes() {
        assert!(parse(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#).is_err());
        assert!(parse(r#"{"id":1,"method":"x"}"#).is_err());
        assert!(parse(r#"[]"#).is_err());
        assert!(
            parse(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"m"}}"#)
                .is_err()
        );
    }

    #[tokio::test]
    async fn frames_lines_with_bounds() {
        let payload = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string();
        let stream = format!("{payload}\n\n   \n{payload}\n");
        let mut reader = tokio::io::BufReader::new(stream.as_bytes());
        let mut line = Vec::new();
        for _ in 0..2 {
            match read_message(&mut reader, &mut line, MAX_FRAME_BYTES)
                .await
                .expect("frames")
            {
                Framing::Message(message) => {
                    assert_eq!(message.method.as_deref(), Some("initialize"));
                }
                Framing::Eof => panic!("unexpected eof"),
            }
        }
        // The blank and whitespace-only lines are skipped as framing noise.
        assert!(matches!(
            read_message(&mut reader, &mut line, MAX_FRAME_BYTES)
                .await
                .expect("frames"),
            Framing::Eof
        ));
    }

    #[tokio::test]
    async fn refuses_oversized_frames_instead_of_truncating() {
        let oversized = format!("{}\n", "x".repeat(256));
        let mut reader = tokio::io::BufReader::new(oversized.as_bytes());
        let error = read_message(&mut reader, &mut Vec::new(), 64)
            .await
            .expect_err("must refuse");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_cancelled_read_preserves_the_partial_request() {
        use tokio::io::AsyncWriteExt as _;
        let (mut input, output) = tokio::io::duplex(256);
        let mut reader = tokio::io::BufReader::new(output);
        let mut line = Vec::new();
        input
            .write_all(br#"{"jsonrpc":"2.0","id":7,"method":"#)
            .await
            .unwrap();
        {
            let read = read_message(&mut reader, &mut line, MAX_FRAME_BYTES);
            tokio::pin!(read);
            // Poll until the prefix is consumed and the read needs more bytes.
            assert!(futures_util::poll!(&mut read).is_pending());
        }
        input.write_all(b"\"initialize\"}\n").await.unwrap();
        // The next poll must parse the whole request, not only its suffix.
        let message = read_message(&mut reader, &mut line, MAX_FRAME_BYTES)
            .await
            .unwrap();
        let Framing::Message(message) = message else {
            panic!("missing request")
        };
        assert_eq!(message.id, Some(json!(7)));
        assert_eq!(message.method.as_deref(), Some("initialize"));
    }

    #[test]
    fn non_text_prompt_blocks_are_refused_explicitly() {
        let image = json!({"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"});
        let error = text_of_content_block(&image).expect_err("image is refused");
        assert_eq!(error.code, RpcError::GOVERNED_REFUSAL);
        assert!(error.message.contains("image"));

        let audio = json!({"type": "audio", "data": "aGVsbG8=", "mimeType": "audio/wav"});
        assert_eq!(
            text_of_content_block(&audio)
                .expect_err("audio is refused")
                .code,
            RpcError::GOVERNED_REFUSAL
        );

        let resource = json!({"type": "resource", "resource": {"uri": "file:///x", "text": "t"}});
        assert_eq!(
            text_of_content_block(&resource)
                .expect_err("embedded resource is refused")
                .code,
            RpcError::GOVERNED_REFUSAL
        );

        let link = json!({"type": "resource_link", "uri": "file:///x"});
        assert_eq!(
            text_of_content_block(&link)
                .expect_err("link is refused")
                .code,
            RpcError::GOVERNED_REFUSAL
        );

        assert_eq!(
            text_of_content_block(&json!({"type": "text", "text": "hi"})).expect("text accepted"),
            "hi"
        );
    }

    #[test]
    fn permission_outcome_mapping_is_allow_once_or_deny_only() {
        let allow = RequestPermissionResult {
            outcome: json!({"outcome": "selected", "optionId": "allow"}),
        };
        assert_eq!(allow.decision(), Some(DecidedPermission::AllowOnce));

        let deny = RequestPermissionResult {
            outcome: json!({"outcome": "selected", "optionId": "deny"}),
        };
        assert_eq!(deny.decision(), Some(DecidedPermission::Deny));

        // An unknown option id is a refusal, never a grant.
        let stray = RequestPermissionResult {
            outcome: json!({"outcome": "selected", "optionId": "allow_always"}),
        };
        assert_eq!(stray.decision(), Some(DecidedPermission::Deny));

        let cancelled = RequestPermissionResult {
            outcome: json!({"outcome": "cancelled"}),
        };
        assert_eq!(cancelled.decision(), Some(DecidedPermission::Deny));

        let malformed = RequestPermissionResult {
            outcome: json!("nonsense"),
        };
        assert_eq!(malformed.decision(), None);
    }

    #[test]
    fn permission_options_advertise_only_allow_once_and_reject_once() {
        let options = permission_options();
        let kinds: Vec<&str> = options
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|option| option.get("kind").and_then(Value::as_str))
            .collect();
        assert_eq!(kinds, vec!["allow_once", "reject_once"]);
    }
}
