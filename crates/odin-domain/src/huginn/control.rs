//! Idempotent, epoch-bound controls for live sessions.

use serde::{Deserialize, Deserializer, Serialize};

use super::event::LiveMessage;
use super::ids::{
    EventSeq, LiveSessionId, ModelName, PermissionRequestId, ProviderName, SessionEpoch,
};
use super::roster::LiveSessionState;
use crate::{ApprovalId, CapabilityId, CommandId, NodeId};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveCommand {
    pub command_id: CommandId,
    pub session_id: LiveSessionId,
    pub expected_epoch: SessionEpoch,
    pub expected_event_head: Option<EventSeq>,
    pub body: LiveCommandBody,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveCommandWire {
    command_id: CommandId,
    session_id: LiveSessionId,
    expected_epoch: SessionEpoch,
    expected_event_head: Option<EventSeq>,
    body: LiveCommandBody,
}

impl<'de> Deserialize<'de> for LiveCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = LiveCommandWire::deserialize(deserializer)?;
        let command = Self {
            command_id: wire.command_id,
            session_id: wire.session_id,
            expected_epoch: wire.expected_epoch,
            expected_event_head: wire.expected_event_head,
            body: wire.body,
        };
        // Intrinsic, state-free command semantics hold at decode time; state
        // applicability stays with validate_for(target).
        command
            .body
            .validate_message()
            .map_err(|rejection| serde::de::Error::custom(rejection.to_string()))?;
        Ok(command)
    }
}

impl LiveCommand {
    /// Validates the immutable session, actor epoch, and optional optimistic head binding.
    pub fn validate_target(&self, target: &LiveCommandTarget) -> Result<(), CommandRejection> {
        if self.session_id != target.session_id {
            return Err(CommandRejection::TargetMismatch {
                command_session: self.session_id,
                actual_session: target.session_id,
            });
        }
        if self.expected_epoch != target.epoch {
            return Err(CommandRejection::EpochMismatch {
                expected: self.expected_epoch,
                actual: target.epoch,
            });
        }
        if let Some(expected) = self.expected_event_head {
            if expected != target.event_head {
                return Err(CommandRejection::EventHeadMismatch {
                    expected,
                    actual: target.event_head,
                });
            }
        }
        Ok(())
    }

    /// Validates all pure preconditions known from a current session snapshot.
    pub fn validate_for(&self, target: &LiveCommandTarget) -> Result<(), CommandRejection> {
        self.validate_target(target)?;
        self.body.validate_message()?;
        self.body.validate_applicability(&target.state)
    }
}

/// Current actor state against which a command is validated before journaling.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveCommandTarget {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub event_head: EventSeq,
    pub state: LiveSessionState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    content = "payload",
    deny_unknown_fields
)]
pub enum LiveCommandBody {
    Prompt {
        message: LiveMessage,
    },
    FollowUp {
        message: LiveMessage,
    },
    Steer {
        message: LiveMessage,
    },
    Pause,
    Resume,
    Checkpoint,
    Restart,
    Rehome {
        target_node: NodeId,
    },
    SetModel {
        provider: ProviderName,
        model: ModelName,
    },
    Abort {
        scope: AbortScope,
    },
    DecidePermission {
        request_id: PermissionRequestId,
        decision: PermissionDecision,
    },
    DecideApproval {
        approval_id: ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    },
}

impl LiveCommandBody {
    pub const fn kind(&self) -> LiveCommandKind {
        match self {
            Self::Prompt { .. } => LiveCommandKind::Prompt,
            Self::FollowUp { .. } => LiveCommandKind::FollowUp,
            Self::Steer { .. } => LiveCommandKind::Steer,
            Self::Pause => LiveCommandKind::Pause,
            Self::Resume => LiveCommandKind::Resume,
            Self::Checkpoint => LiveCommandKind::Checkpoint,
            Self::Restart => LiveCommandKind::Restart,
            Self::Rehome { .. } => LiveCommandKind::Rehome,
            Self::SetModel { .. } => LiveCommandKind::SetModel,
            Self::Abort {
                scope: AbortScope::CurrentTurn,
            } => LiveCommandKind::AbortCurrentTurn,
            Self::Abort {
                scope: AbortScope::Session,
            } => LiveCommandKind::AbortSession,
            Self::DecidePermission { .. } => LiveCommandKind::DecidePermission,
            Self::DecideApproval { .. } => LiveCommandKind::DecideApproval,
        }
    }

    /// Validates session-state applicability without performing any I/O or mutation.
    pub fn validate_applicability(&self, state: &LiveSessionState) -> Result<(), CommandRejection> {
        use LiveCommandBody as Body;
        use LiveSessionState as State;

        let applicable = match self {
            Body::Prompt { .. } => matches!(state, State::Idle),
            Body::FollowUp { .. } | Body::Steer { .. } => {
                matches!(state, State::Running | State::RequiresAction)
            }
            Body::Pause => matches!(state, State::Running | State::RequiresAction),
            Body::Resume => matches!(state, State::Detached),
            Body::Checkpoint => {
                matches!(state, State::Idle | State::Running | State::RequiresAction)
            }
            Body::Restart => matches!(state, State::Idle | State::Failed | State::Detached),
            Body::Rehome { .. } => matches!(state, State::Idle | State::Detached),
            // A host tool can switch its own session while its turn is
            // running. Stock OMP's set_model changes the selected model
            // without aborting that turn.
            Body::SetModel { .. } => matches!(
                state,
                State::Idle | State::Running | State::RequiresAction | State::Detached
            ),
            Body::Abort {
                scope: AbortScope::CurrentTurn,
            } => matches!(state, State::Running | State::RequiresAction),
            Body::Abort {
                scope: AbortScope::Session,
            } => !matches!(state, State::Ended),
            Body::DecidePermission { .. } => matches!(state, State::RequiresAction),
            Body::DecideApproval { .. } => {
                matches!(state, State::Idle | State::Running | State::RequiresAction)
            }
        };

        if applicable {
            Ok(())
        } else {
            Err(CommandRejection::InvalidState {
                command: self.kind(),
                state: *state,
            })
        }
    }

    pub fn validate_message(&self) -> Result<(), CommandRejection> {
        let message = match self {
            Self::Prompt { message } | Self::FollowUp { message } | Self::Steer { message } => {
                Some(message)
            }
            _ => None,
        };
        if let Some(message) = message {
            message
                .validate()
                .map_err(|_| CommandRejection::EmptyMessage)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AbortScope {
    CurrentTurn,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum PermissionDecision {
    AllowOnce,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum LiveCommandKind {
    Prompt,
    FollowUp,
    Steer,
    Pause,
    Resume,
    Checkpoint,
    Restart,
    Rehome,
    SetModel,
    AbortCurrentTurn,
    AbortSession,
    DecidePermission,
    DecideApproval,
}

/// Immediate durable disposition of a command ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status",
    deny_unknown_fields
)]
pub enum CommandReceipt {
    Accepted {
        command_id: CommandId,
    },
    Duplicate {
        command_id: CommandId,
        prior_outcome: Option<Box<CommandOutcome>>,
    },
    Rejected {
        command_id: CommandId,
        reason: CommandRejection,
    },
}

/// Host admission refusal, not a tool execution result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolDenialReceipt {
    pub request_id: CommandId,
    pub tool_name: String,
    pub denial: ToolDenial,
    pub error: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum ToolDenial {
    UnknownTool,
    PolicyUnavailable {
        capability_id: CapabilityId,
        reason: String,
    },
}

/// Durable completion state for an accepted command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "status",
    deny_unknown_fields
)]
pub enum CommandOutcome {
    Applied {
        command_id: CommandId,
    },
    Cancelled {
        command_id: CommandId,
        reason: String,
    },
    Failed {
        command_id: CommandId,
        error: CommandFailure,
    },
    ToolDenied {
        command_id: CommandId,
        receipt: ToolDenialReceipt,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

/// Typed pre-journal rejection; callers never infer rejection from a boolean.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum CommandRejection {
    #[error("command targets session {command_session}, but actor owns {actual_session}")]
    TargetMismatch {
        command_session: LiveSessionId,
        actual_session: LiveSessionId,
    },
    #[error("command expected epoch {expected}, current epoch is {actual}")]
    EpochMismatch {
        expected: SessionEpoch,
        actual: SessionEpoch,
    },
    #[error("command expected event head {expected}, current head is {actual}")]
    EventHeadMismatch {
        expected: EventSeq,
        actual: EventSeq,
    },
    #[error("{command:?} is not applicable while the session is {state:?}")]
    InvalidState {
        command: LiveCommandKind,
        state: LiveSessionState,
    },
    #[error("prompt, follow-up, and steer messages must contain at least one content block")]
    EmptyMessage,

    #[error("permission request {request_id} is not outstanding")]
    PermissionRequestNotOutstanding { request_id: PermissionRequestId },
    #[error("approval {approval_id} revision mismatch: expected {expected}, current revision is {actual}")]
    ApprovalRevisionMismatch {
        approval_id: ApprovalId,
        expected: u64,
        actual: u64,
    },
}
