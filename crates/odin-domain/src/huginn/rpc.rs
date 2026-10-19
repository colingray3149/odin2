use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{ArtifactId, CommandId, NodeId, ProjectId, SeatId, SliceId};

use super::artifact::{
    ArtifactChunk, ArtifactRef, TransferCancelRequest, TransferChunkRequest, TransferCreditRequest,
    TransferStatus, UploadManifest,
};
use super::control::{CommandReceipt, LiveCommand};
use super::event::{HistoryPage, LiveEvent, LiveMessage, SessionSubscription};
use super::file::{
    ContentTicket, ContentTicketRequest, FileDelta, FileListPage, FileQuery, FileReadRequest,
    FileWatchRequest,
};
use super::ids::{
    EventSeq, LiveSessionId, ModelName, ProviderName, RequestId, RosterRevision, SessionEpoch,
    SessionListCursor, TransferId,
};
use super::read_model::Revision;
use super::render::{RenderRequest, RenderStatus, RenderStatusRequest, RenderWatchRequest};
use super::roster::{LiveSessionSummary, RosterDelta, SeatRoster, SessionListPage};
use super::stream::{BinaryChunk, StreamFrame};
use super::terminal::{
    TerminalAcquireRequest, TerminalControlStatus, TerminalReleaseRequest, TerminalResizeRequest,
    TerminalSnapshot, TerminalWriteRequest,
};

pub const LIVE_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum LiveClientRequest {
    GetRoster {
        request_id: RequestId,
        if_revision: Option<RosterRevision>,
    },
    ListSessions {
        request_id: RequestId,
        seat_id: Option<SeatId>,
        include_ended: bool,
        cursor: Option<SessionListCursor>,
        limit: NonZeroU16,
    },
    GetHistory {
        request_id: RequestId,
        session_id: LiveSessionId,
        after: EventSeq,
        limit: NonZeroU16,
    },
    Subscribe {
        request_id: RequestId,
        subscriptions: Vec<SessionSubscription>,
    },
    Unsubscribe {
        request_id: RequestId,
        session_ids: Vec<LiveSessionId>,
    },
    OpenSession {
        request_id: RequestId,
        command_id: CommandId,
        seat_id: SeatId,
        project_id: ProjectId,
        slice_id: SliceId,
        provider: ProviderName,
        model: ModelName,
        title: Option<String>,
        target_node: NodeId,
        open_tab: bool,
        initial_prompt: Option<LiveMessage>,
        /// The opener's ensured token generation; absent on legacy clients,
        /// in which case the daemon resolves from the token's signed claim.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        served_revision: Option<u64>,
    },
    Control {
        request_id: RequestId,
        command: LiveCommand,
    },
    BeginUpload {
        request_id: RequestId,
        manifest: UploadManifest,
    },
    UploadChunk {
        request: TransferChunkRequest,
    },
    CommitUpload {
        request_id: RequestId,
        transfer_id: TransferId,
    },
    CancelTransfer {
        request_id: RequestId,
        request: TransferCancelRequest,
    },
    FetchArtifact {
        request_id: RequestId,
        artifact_id: ArtifactId,
        first_chunk: u32,
    },
    GrantDownloadCredit {
        request: TransferCreditRequest,
    },
    BrowseFiles {
        request_id: RequestId,
        query: FileQuery,
    },
    ReadFile {
        request_id: RequestId,
        request: FileReadRequest,
    },
    WatchFiles {
        request_id: RequestId,
        request: FileWatchRequest,
    },
    RequestRender {
        request_id: RequestId,
        request: RenderRequest,
    },
    RenderStatus {
        request_id: RequestId,
        request: RenderStatusRequest,
    },
    WatchRender {
        request_id: RequestId,
        request: RenderWatchRequest,
    },
    IssueContentTicket {
        request_id: RequestId,
        request: ContentTicketRequest,
    },
    AcquireTerminalControl {
        request_id: RequestId,
        request: TerminalAcquireRequest,
    },
    WriteTerminal {
        request_id: RequestId,
        request: TerminalWriteRequest,
    },
    ResizeTerminal {
        request_id: RequestId,
        request: TerminalResizeRequest,
    },
    ReleaseTerminalControl {
        request_id: RequestId,
        request: TerminalReleaseRequest,
    },
    BindTerminalTarget {
        request_id: RequestId,
        zellij_session: String,
    },
    UnbindTerminalTarget {
        request_id: RequestId,
    },
    GetTerminalTarget {
        request_id: RequestId,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
pub enum LiveResponse {
    Roster(Option<SeatRoster>),
    Sessions(SessionListPage),
    History(HistoryPage),
    Subscribed,
    SessionOpened(LiveSessionSummary),
    Command(CommandReceipt),
    Transfer(TransferStatus),
    Artifact(ArtifactRef),
    Files(FileListPage),
    Render(RenderStatus),
    TerminalControl(TerminalControlStatus),
    TerminalTarget(TerminalTargetStatus),
    ContentTicket(ContentTicket),
    Ack,
}

/// Origin of an effective terminal tab target: a declared daemon
/// configuration selector or an explicit operator registration sent from
/// the interactive client.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalTargetSource {
    /// Declared selector rendered into daemon configuration.
    Declared,
    /// Explicit operator registration from the interactive client.
    ChatRegistration,
}

/// Shared wire status of the operator terminal tab target: the
/// field-for-field mirror of the supervisor's live target status. The
/// daemon converts its internal type into this one at the plane boundary,
/// so the client never sees daemon-internal types.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TerminalTargetStatus {
    pub bound: bool,
    pub zellij_session: Option<String>,
    pub source: Option<TerminalTargetSource>,
    pub registered_at: Option<OffsetDateTime>,
    /// True when this status follows a registration that replaced an
    /// earlier chat registration.
    pub replaced: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    content = "value"
)]
pub enum LiveServerMessage {
    Response {
        request_id: RequestId,
        result: LiveResponse,
    },
    RosterSnapshot(SeatRoster),
    RosterDelta(RosterDelta),
    ReplayBegin {
        session_id: LiveSessionId,
        requested_after: EventSeq,
        head: EventSeq,
    },
    Event(LiveEvent),
    ReplayComplete {
        session_id: LiveSessionId,
        head: EventSeq,
    },
    TerminalReset(TerminalSnapshot),
    ArtifactChunk(ArtifactChunk),
    BinaryChunk(BinaryChunk),
    TransferStatus(TransferStatus),
    FileDelta(FileDelta),
    RenderStatus(RenderStatus),
    StreamFrame(StreamFrame),
    TerminalControlStatus(TerminalControlStatus),
    DeviceRevoked,
    ProtocolError(LiveProtocolError),
}

/// Stable client-visible live-plane failures. Adapter implementation errors are mapped here.
#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum LiveProtocolError {
    #[error("live protocol version {received} is unsupported (supported: {supported})")]
    UnsupportedVersion { received: u16, supported: u16 },
    #[error("invalid live request {code}: {message}")]
    InvalidRequest { code: String, message: String },
    #[error("authentication is required")]
    Unauthenticated,
    #[error("the authenticated device is not authorized")]
    Unauthorized,
    #[error("the authenticated device has been revoked")]
    DeviceRevoked,
    #[error("{object_kind} {object_id} was not found")]
    NotFound {
        object_kind: String,
        object_id: String,
    },
    #[error("session epoch mismatch: expected {expected}, actual {actual}")]
    EpochMismatch {
        expected: SessionEpoch,
        actual: SessionEpoch,
    },
    #[error("revision mismatch: expected {expected}, actual {actual}")]
    RevisionMismatch {
        expected: Revision,
        actual: Revision,
    },
    #[error("request conflicts with current session state: {message}")]
    Conflict { code: String, message: String },
    #[error("requested replay cursor is no longer retained")]
    CursorExpired,
    #[error("subscription overflowed its bounded buffer")]
    SubscriptionOverflow,
    #[error("transfer failed: {code}")]
    Transfer { code: String, message: String },
    #[error("resource limit exceeded: {limit}")]
    ResourceLimit { limit: String },
    #[error("operation is unsupported: {operation}")]
    Unsupported { operation: String },
    #[error("live service unavailable: {code}")]
    Unavailable { code: String },
}

pub type LiveError = LiveProtocolError;
