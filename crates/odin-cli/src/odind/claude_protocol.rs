//! Claude Code 2.1.280: one long-lived stream-json conversation, initialized before
//! enabling Remote Control through its correlated SDK control request (not the
//! interactive-only CLI flag). This module owns no process, seat, or memory.
//!
//! The carrier retains the sole stdin, enforces control deadlines, and persists
//! each popped event before reading more output. `ingest` consumes at most one
//! line; retain the unconsumed suffix. Backpressure is retryable after draining.
//! All other stream errors are terminal: never resume a second concurrent writer.
use std::collections::VecDeque;

use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

const QUALIFIED_VERSION: &str = "2.1.280";

#[derive(Debug, Clone, Copy)]
pub struct ProtocolLimits {
    pub max_line_bytes: usize,
    pub max_queued_bytes: usize,
    pub max_queued_events: usize,
    pub max_prompt_bytes: usize,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1024 * 1024,
            max_queued_bytes: 4 * 1024 * 1024,
            max_queued_events: 256,
            max_prompt_bytes: 256 * 1024,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported Claude stream-json Remote Control version: {0}")]
    UnsupportedVersion(String),
    #[error("invalid local conversation UUID")]
    InvalidSessionId,
    #[error("invalid protocol bounds")]
    InvalidLimits,
    #[error("operation is not valid in the current protocol state")]
    InvalidState,
    #[error("Claude output queue is full; drain before retrying")]
    Backpressure,
    #[error("Claude output line exceeds the configured bound")]
    OutputTooLarge,
    #[error("prompt exceeds the configured bound")]
    PromptTooLarge,
    #[error("malformed Claude NDJSON: {0}")]
    Malformed(String),
    #[error("uncorrelated Claude control response")]
    UncorrelatedControl,
    #[error("Claude control request failed: {0}")]
    ControlRejected(String),
    #[error("Claude requested an unsupported control operation")]
    UnsupportedControlRequest,
    #[error("Remote Control success lacks valid bridge metadata")]
    InvalidBridgeMetadata,
    #[error("Claude output belongs to a different local conversation")]
    SessionMismatch,
    #[error("Claude output ended with a partial NDJSON line")]
    PartialLine,
    #[error("Claude output ended unexpectedly")]
    UnexpectedEof,
    #[error("Claude protocol has failed")]
    Failed,
    #[error("transcript cursor exhausted")]
    CursorExhausted,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteControlMetadata {
    pub local_session_id: String,
    pub session_url: String,
    pub connect_url: String,
    pub environment_id: String,
    pub bridge_epoch: u64,
    pub bridge_session_id: String,
}

#[derive(Debug, Serialize)]
pub struct TranscriptEvent {
    pub cursor: u64,
    pub event: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Initializing,
    Initialized,
    EnablingRemoteControl,
    Ready,
    Failed,
}

pub struct ClaudeProtocol {
    local_session_id: String,
    require_remote_control: bool,
    limits: ProtocolLimits,
    phase: Phase,
    line: Vec<u8>,
    events: VecDeque<(usize, TranscriptEvent)>,
    queued_bytes: usize,
    cursor: u64,
    remote_control: Option<RemoteControlMetadata>,
}

impl ClaudeProtocol {
    pub fn new(
        local_session_id: &str,
        observed_version: &str,
        require_remote_control: bool,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        // Deliberately exact, not a semver lower bound: this private SDK control
        // shape has source-backed evidence only for the installed 2.1.280 build.
        let version = observed_version.trim();
        if version != QUALIFIED_VERSION && version != "2.1.280 (Claude Code)" {
            return Err(ProtocolError::UnsupportedVersion(version.to_owned()));
        }
        let id = Uuid::parse_str(local_session_id).map_err(|_| ProtocolError::InvalidSessionId)?;
        if id.is_nil() || id.to_string() != local_session_id {
            return Err(ProtocolError::InvalidSessionId);
        }
        if limits.max_line_bytes == 0
            || limits.max_queued_bytes < limits.max_line_bytes
            || limits.max_queued_events == 0
            || limits.max_prompt_bytes == 0
        {
            return Err(ProtocolError::InvalidLimits);
        }
        Ok(Self {
            local_session_id: local_session_id.to_owned(),
            require_remote_control,
            limits,
            phase: Phase::New,
            line: Vec::new(),
            events: VecDeque::new(),
            queued_bytes: 0,
            cursor: 0,
            remote_control: None,
        })
    }

    pub fn launch_args(&self) -> Vec<String> {
        [
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--replay-user-messages",
            "--session-id",
            &self.local_session_id,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    pub fn initialize(&mut self) -> Result<Vec<u8>, ProtocolError> {
        if self.phase != Phase::New {
            return Err(ProtocolError::InvalidState);
        }
        self.phase = Phase::Initializing;
        encode(json!({"type":"control_request","request_id":"odin-init-1",
            "request":{"subtype":"initialize"}}))
    }

    pub fn enable_remote_control(&mut self, name: &str) -> Result<Vec<u8>, ProtocolError> {
        if self.phase != Phase::Initialized || name.is_empty() {
            return Err(ProtocolError::InvalidState);
        }
        if name.len() > self.limits.max_prompt_bytes {
            return Err(ProtocolError::PromptTooLarge);
        }
        self.phase = Phase::EnablingRemoteControl;
        encode(json!({"type":"control_request","request_id":"odin-rc-1",
            "request":{"subtype":"remote_control","enabled":true,"name":name}}))
    }

    pub fn prompt(&mut self, text: &str) -> Result<Vec<u8>, ProtocolError> {
        if !self.is_ready() {
            return Err(ProtocolError::InvalidState);
        }
        if text.len() > self.limits.max_prompt_bytes {
            return Err(ProtocolError::PromptTooLarge);
        }
        // "default" is the SDK input routing sentinel, not the local UUID nor
        // the bridge session ID. The process was launched with --session-id.
        encode(
            json!({"type":"user","message":{"role":"user","content":text},
            "parent_tool_use_id":null,"session_id":"default"}),
        )
    }

    pub fn is_initialized(&self) -> bool {
        matches!(
            self.phase,
            Phase::Initialized | Phase::EnablingRemoteControl | Phase::Ready
        )
    }

    pub fn is_ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    pub fn remote_control(&self) -> Option<&RemoteControlMetadata> {
        self.remote_control.as_ref()
    }

    /// Returns bytes consumed, stopping at the first newline. On Backpressure no
    /// bytes are consumed. Bounded reservation permits processing the full next
    /// line without discarding a frame when the durable sink falls behind.
    pub fn ingest(&mut self, bytes: &[u8]) -> Result<usize, ProtocolError> {
        if self.phase == Phase::Failed {
            return Err(ProtocolError::Failed);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.events.len() >= self.limits.max_queued_events
            || self.queued_bytes > self.limits.max_queued_bytes - self.limits.max_line_bytes
        {
            return Err(ProtocolError::Backpressure);
        }
        let result = self.ingest_line(bytes);
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn ingest_line(&mut self, bytes: &[u8]) -> Result<usize, ProtocolError> {
        let end = bytes.iter().position(|byte| *byte == b'\n');
        let content_len = end.unwrap_or(bytes.len());
        if content_len > self.limits.max_line_bytes.saturating_sub(self.line.len()) {
            return Err(ProtocolError::OutputTooLarge);
        }
        self.line.extend_from_slice(&bytes[..content_len]);
        let Some(end) = end else {
            return Ok(bytes.len());
        };
        let size = self.line.len();
        let event: Value = serde_json::from_slice(&self.line)
            .map_err(|error| ProtocolError::Malformed(error.to_string()))?;
        self.line.clear();
        self.accept_frame(&event)?;
        self.cursor = self
            .cursor
            .checked_add(1)
            .ok_or(ProtocolError::CursorExhausted)?;
        self.queued_bytes += size;
        self.events.push_back((
            size,
            TranscriptEvent {
                cursor: self.cursor,
                event,
            },
        ));
        Ok(end + 1)
    }

    fn accept_frame(&mut self, event: &Value) -> Result<(), ProtocolError> {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| ProtocolError::Malformed("frame lacks type".into()))?;
        if let Some(id) = event.get("session_id") {
            if id.as_str() != Some(self.local_session_id.as_str()) {
                return Err(ProtocolError::SessionMismatch);
            }
        }
        match kind {
            "control_response" => self.accept_control(event),
            "control_request" => Err(ProtocolError::UnsupportedControlRequest),
            // Preserve complete event payloads, including system/init,
            // system/bridge_state, stream_event deltas, and result failures.
            "system" | "assistant" | "user" | "result" | "stream_event" | "tool_progress"
            | "tool_use_summary" | "auth_status" | "rate_limit_event" => Ok(()),
            _ => Err(ProtocolError::Malformed(format!(
                "unsupported frame type {kind}"
            ))),
        }
    }

    fn accept_control(&mut self, event: &Value) -> Result<(), ProtocolError> {
        let response = event
            .get("response")
            .ok_or(ProtocolError::UncorrelatedControl)?;
        let expected = match self.phase {
            Phase::Initializing => "odin-init-1",
            Phase::EnablingRemoteControl => "odin-rc-1",
            _ => return Err(ProtocolError::UncorrelatedControl),
        };
        if response.get("request_id").and_then(Value::as_str) != Some(expected) {
            return Err(ProtocolError::UncorrelatedControl);
        }
        match response.get("subtype").and_then(Value::as_str) {
            Some("success") => {}
            Some("error") => {
                return Err(ProtocolError::ControlRejected(
                    response
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified error")
                        .to_owned(),
                ))
            }
            _ => {
                return Err(ProtocolError::Malformed(
                    "invalid control response subtype".into(),
                ))
            }
        }
        if self.phase == Phase::Initializing {
            self.phase = if self.require_remote_control {
                Phase::Initialized
            } else {
                Phase::Ready
            };
        } else {
            let payload = response
                .get("response")
                .ok_or(ProtocolError::InvalidBridgeMetadata)?;
            let field = |key: &str| -> Result<String, ProtocolError> {
                payload
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .ok_or(ProtocolError::InvalidBridgeMetadata)
            };
            let session_url = field("session_url")?;
            let connect_url = field("connect_url")?;
            for value in [&session_url, &connect_url] {
                let url =
                    url::Url::parse(value).map_err(|_| ProtocolError::InvalidBridgeMetadata)?;
                if url.scheme() != "https"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return Err(ProtocolError::InvalidBridgeMetadata);
                }
            }
            self.remote_control = Some(RemoteControlMetadata {
                local_session_id: self.local_session_id.clone(),
                session_url,
                connect_url,
                environment_id: field("environment_id")?,
                bridge_epoch: payload
                    .get("bridge_epoch")
                    .and_then(Value::as_u64)
                    .ok_or(ProtocolError::InvalidBridgeMetadata)?,
                bridge_session_id: field("bridge_session_id")?,
            });
            self.phase = Phase::Ready;
        }
        Ok(())
    }

    pub fn pop_event(&mut self) -> Option<TranscriptEvent> {
        let (size, event) = self.events.pop_front()?;
        self.queued_bytes -= size;
        Some(event)
    }

    pub fn eof(&mut self) -> Result<(), ProtocolError> {
        self.phase = Phase::Failed;
        Err(if self.line.is_empty() {
            ProtocolError::UnexpectedEof
        } else {
            ProtocolError::PartialLine
        })
    }
}

fn encode(value: Value) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes =
        serde_json::to_vec(&value).map_err(|error| ProtocolError::Malformed(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
#[path = "tests/claude_protocol.rs"]
mod tests;
