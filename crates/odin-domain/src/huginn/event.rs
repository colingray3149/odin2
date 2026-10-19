//! Durable semantic events and replay cursors for live sessions.

use std::num::NonZeroU16;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::artifact::ArtifactRef;
use super::control::{CommandOutcome, CommandReceipt, PermissionDecision};
use super::ids::{EventSeq, LiveSessionId, PermissionRequestId, SessionEpoch, TerminalSeq};
use super::render::RenderManifest;
use super::roster::LiveSessionState;
use super::session::SessionManifest;
use super::terminal::{TerminalDeltaRef, TerminalSnapshotRef};
use crate::{ArtifactId, CapabilityId, CommandId, Digest, EventId, TurnId};

/// One provider message represented as typed, display-independent content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveMessage {
    pub content: Vec<LiveContentBlock>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveMessageWire {
    content: Vec<LiveContentBlock>,
}

impl<'de> Deserialize<'de> for LiveMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveMessageWire::deserialize(deserializer)?;
        let message = Self {
            content: wire.content,
        };
        message.validate().map_err(serde::de::Error::custom)?;
        Ok(message)
    }
}

impl LiveMessage {
    pub fn new(content: Vec<LiveContentBlock>) -> Result<Self, LiveMessageError> {
        let message = Self { content };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<(), LiveMessageError> {
        if self.content.is_empty() {
            return Err(LiveMessageError::EmptyContent);
        }
        Ok(())
    }
}

/// A semantic message block; terminal bytes are deliberately not a message block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum LiveContentBlock {
    Text(String),
    File(ArtifactRef),
    Render(RenderManifest),
    ToolUse(ToolUseBlock),
    ToolResult(ToolResultBlock),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolUseBlock {
    pub tool_use_id: String,
    pub capability_id: CapabilityId,
    pub arguments: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolResultBlock {
    pub tool_use_id: String,
    pub content: Vec<LiveContentBlock>,
    pub is_error: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LiveMessageError {
    #[error("live message content must not be empty")]
    EmptyContent,
}

pub const LIVE_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveEvent {
    pub schema_version: u16,
    pub event_id: EventId,
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub sequence: EventSeq,
    pub occurred_at: OffsetDateTime,
    pub body: LiveEventBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveEventWire {
    schema_version: u16,
    event_id: EventId,
    session_id: LiveSessionId,
    epoch: SessionEpoch,
    sequence: EventSeq,
    occurred_at: OffsetDateTime,
    body: LiveEventBody,
}

impl<'de> Deserialize<'de> for LiveEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveEventWire::deserialize(deserializer)?;
        let event = Self {
            schema_version: wire.schema_version,
            event_id: wire.event_id,
            session_id: wire.session_id,
            epoch: wire.epoch,
            sequence: wire.sequence,
            occurred_at: wire.occurred_at,
            body: wire.body,
        };
        event.validate().map_err(serde::de::Error::custom)?;
        Ok(event)
    }
}

impl LiveEvent {
    pub fn new(
        schema_version: u16,
        event_id: EventId,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        sequence: EventSeq,
        occurred_at: OffsetDateTime,
        body: LiveEventBody,
    ) -> Result<Self, LiveEventValidationError> {
        let event = Self {
            schema_version,
            event_id,
            session_id,
            epoch,
            sequence,
            occurred_at,
            body,
        };
        event.validate()?;
        Ok(event)
    }

    /// Validates invariants intrinsic to the event, independent of ledger state.
    pub fn validate(&self) -> Result<(), LiveEventValidationError> {
        if self.schema_version != LIVE_SCHEMA_VERSION {
            return Err(LiveEventValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.sequence.get() == 0 {
            return Err(LiveEventValidationError::SequenceMustStartAtOne);
        }

        match &self.body {
            LiveEventBody::SessionOpened(opened) => {
                if opened.manifest.session_id != self.session_id {
                    return Err(LiveEventValidationError::SessionMismatch {
                        expected: self.session_id,
                        actual: opened.manifest.session_id,
                    });
                }
            }
            LiveEventBody::UserMessage(message) | LiveEventBody::AssistantMessage(message) => {
                message
                    .validate()
                    .map_err(LiveEventValidationError::InvalidMessage)?;
                self.validate_content_binding(&message.content)?;
            }
            LiveEventBody::ToolFinished(finished) => {
                self.validate_content_binding(&finished.result.content)?;
            }
            LiveEventBody::ArtifactPublished(artifact) => {
                self.validate_artifact_binding(artifact)?;
            }
            LiveEventBody::TerminalSnapshot(snapshot) => {
                self.validate_terminal_binding(snapshot.session_id, snapshot.epoch)?;
            }
            LiveEventBody::TerminalDelta(delta) => {
                self.validate_terminal_binding(delta.session_id, delta.epoch)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn validate_content_binding(
        &self,
        content: &[LiveContentBlock],
    ) -> Result<(), LiveEventValidationError> {
        for block in content {
            match block {
                LiveContentBlock::File(artifact) => {
                    self.validate_artifact_binding(artifact)?;
                }
                LiveContentBlock::ToolResult(result) => {
                    self.validate_content_binding(&result.content)?;
                }
                LiveContentBlock::Text(_)
                | LiveContentBlock::Render(_)
                | LiveContentBlock::ToolUse(_) => {}
            }
        }
        Ok(())
    }

    fn validate_artifact_binding(
        &self,
        artifact: &ArtifactRef,
    ) -> Result<(), LiveEventValidationError> {
        if artifact.session_id != self.session_id {
            return Err(LiveEventValidationError::ArtifactSessionMismatch {
                artifact_id: artifact.artifact_id.clone(),
                expected: self.session_id,
                actual: artifact.session_id,
            });
        }
        Ok(())
    }
    fn validate_terminal_binding(
        &self,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
    ) -> Result<(), LiveEventValidationError> {
        if session_id != self.session_id {
            return Err(LiveEventValidationError::SessionMismatch {
                expected: self.session_id,
                actual: session_id,
            });
        }
        if epoch != self.epoch {
            return Err(LiveEventValidationError::EpochMismatch {
                expected: self.epoch,
                actual: epoch,
            });
        }
        Ok(())
    }

    /// Validates that an event being appended belongs to the actor that owns the ledger epoch.
    pub fn validate_binding(
        &self,
        session_id: &LiveSessionId,
        epoch: &SessionEpoch,
    ) -> Result<(), LiveEventValidationError> {
        self.validate()?;
        if &self.session_id != session_id {
            return Err(LiveEventValidationError::SessionMismatch {
                expected: *session_id,
                actual: self.session_id,
            });
        }
        if &self.epoch != epoch {
            return Err(LiveEventValidationError::EpochMismatch {
                expected: *epoch,
                actual: self.epoch,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "payload",
    deny_unknown_fields
)]
pub enum LiveEventBody {
    SessionOpened(SessionOpened),
    SessionStateChanged(SessionStateChanged),
    UserMessage(LiveMessage),
    AssistantMessage(LiveMessage),
    AssistantDelta(TextDelta),
    ToolStarted(ToolStarted),
    ToolFinished(ToolFinished),
    PermissionRequested(PermissionRequest),
    PermissionResolved(PermissionResolution),
    ControlAccepted(CommandReceipt),
    ControlCompleted(CommandOutcome),
    ArtifactPublished(ArtifactRef),
    TerminalSnapshot(TerminalSnapshotRef),
    TerminalDelta(TerminalDeltaRef),
    Result(SessionResult),
    Error(SessionError),
    SessionClosed(SessionClosed),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionOpened {
    pub manifest: Box<SessionManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionStateChanged {
    pub previous: LiveSessionState,
    pub current: LiveSessionState,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextDelta {
    pub turn_id: TurnId,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolStarted {
    pub turn_id: TurnId,
    pub tool: ToolUseBlock,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolFinished {
    pub turn_id: TurnId,
    pub result: ToolResultBlock,
}

/// One permission card bound to an exact tool invocation and argument digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionRequest {
    pub request_id: PermissionRequestId,
    pub tool_use_id: String,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
    pub prompt: String,
    pub expires_at: OffsetDateTime,
}

/// A mechanism resolution linked to its durable control command. Caller
/// authentication belongs to the command transport; no device is invented
/// for controller- or conversation-originated decisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionResolution {
    pub request_id: PermissionRequestId,
    pub command_id: CommandId,
    pub decision: PermissionDecision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionResult {
    pub summary: Option<String>,
    pub artifacts: Vec<ArtifactId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    /// Provider HTTP status from the frame's `errorStatus`, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_status: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionClosed {
    pub reason: SessionCloseReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum SessionCloseReason {
    Completed,
    Aborted,
    Retired,
    Failed,
}

/// Bounded semantic-history query. `after == 0` denotes the cursor before event one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryQuery {
    pub session_id: LiveSessionId,
    pub after: EventSeq,
    pub limit: NonZeroU16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryPage {
    pub events: Vec<LiveEvent>,
    pub next_after: EventSeq,
    pub head: EventSeq,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionSubscription {
    pub session_id: LiveSessionId,
    pub event_after: EventSeq,
    pub terminal_after: Option<TerminalSeq>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubscribeRequest {
    pub subscriptions: Vec<SessionSubscription>,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LiveEventValidationError {
    #[error("live event sequence must start at one")]
    SequenceMustStartAtOne,
    #[error("live event schema version {0} is unsupported (supported: 1)")]
    UnsupportedSchemaVersion(u16),
    #[error("live event session mismatch: expected {expected}, got {actual}")]
    SessionMismatch {
        expected: LiveSessionId,
        actual: LiveSessionId,
    },
    #[error("artifact {artifact_id} belongs to session {actual}, but event belongs to {expected}")]
    ArtifactSessionMismatch {
        artifact_id: ArtifactId,
        expected: LiveSessionId,
        actual: LiveSessionId,
    },
    #[error("live event epoch mismatch: expected {expected}, got {actual}")]
    EpochMismatch {
        expected: SessionEpoch,
        actual: SessionEpoch,
    },
    #[error(transparent)]
    InvalidMessage(#[from] LiveMessageError),
}
