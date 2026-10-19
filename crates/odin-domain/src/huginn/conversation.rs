//! The owner conversation over Huginn: one declared conversation (the
//! Discord-bound seat/project root) reachable from every paired surface.
//! A paired device reads where the conversation lives (its current vehicle
//! session, followed with the ordinary history/stream requests) and says
//! something into it; the daemon admits the text through the same owner
//! intake as a Discord DM, so every surface sees one thread.

use serde::{Deserialize, Serialize};

use crate::{CommandId, ProjectId, SeatId};

use super::ids::LiveSessionId;

/// Stops workers and pods through StopAuthority before the daemon and model gateway; Ack means stopping has started.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmergencyStopRequest {
    pub command_id: CommandId,
}

/// Upper bound on one owner line from a non-Discord surface (Discord's own
/// message ceiling).
pub const CONVERSATION_MESSAGE_MAX_CHARS: usize = 2000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationSayRequest {
    /// Client idempotency key: a retried say with the same id is admitted
    /// once.
    pub command_id: CommandId,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationView {
    pub conversation_id: String,
    pub seat_id: SeatId,
    pub project_id: ProjectId,
    /// The live session currently carrying the conversation; it changes on
    /// a vehicle rollover, so clients re-read this view when it ends.
    pub vehicle_session: Option<LiveSessionId>,
    /// Set on a say: the intake status of the admitted owner line
    /// (`admitted`, `decided`, `duplicate`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intake: Option<String>,
    /// Set on a thread read: the owner channel's messages, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thread: Vec<ConversationLine>,
}

/// A read of the owner channel itself: exactly what Discord shows.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationThreadRequest {
    /// Only messages after this one; absent: the newest window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// Read the committed reply for one already-admitted say. The daemon looks
/// up the mirror that say recorded; this is not a new identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationReplyRequest {
    pub command_id: CommandId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationLine {
    /// The channel's own message id (the next read's cursor).
    pub id: String,
    /// Colin wrote it; otherwise the seat did.
    pub from_owner: bool,
    pub text: String,
    /// Names of the files attached to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
}
