use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{ApprovalId, CommandId, LaneId, NodeId, ProjectId, SeatId, SliceId};

use super::artifact::{
    ArtifactChunk, ArtifactRef, TransferCancelRequest, TransferChunkRequest, TransferCreditRequest,
    TransferManifest, TransferStatus,
};
use super::browser::{BrowserCommand, BrowserObservation, BrowserObserveRequest};
use super::control::{ApprovalDecision, CommandOutcome, CommandReceipt, LiveCommand};
use super::conversation::{
    ConversationReplyRequest, ConversationSayRequest, ConversationThreadRequest, ConversationView,
    EmergencyStopRequest,
};
use super::event::{LiveEvent, LiveMessage};
use super::file::{
    ContentTicket, ContentTicketRequest, FileDelta, FileListPage, FileListRequest, FileReadRequest,
    FileWatchRequest,
};
use super::ids::{
    ModelName, ProviderName, RequestId, Sequence, SessionListCursor, StreamId, TransferId,
};
use super::kube::KubeCommand;
use super::read_model::{
    DeltaPage, DeltaQuery, ObjectDelta, ObjectDeltaBatch, ObjectSnapshot, ObjectSubscription,
    Revision, SearchPage, SearchQuery, SnapshotPage, SnapshotQuery,
};
use super::render::{RenderRequest, RenderStatus, RenderStatusRequest, RenderWatchRequest};
use super::ring::RingGestureReport;
use super::roster::{LiveSessionSummary, SeatRoster};
use super::session::WorkloadSessionBinding;
use super::simulation::SimulationCommand;
use super::spend::{SpendRequest, SpendView};
use super::stream::{BinaryChunk, StreamStatus, SubscriptionSet};
use super::terminal::{
    TerminalAcquireRequest, TerminalControlStatus, TerminalReleaseRequest, TerminalResizeRequest,
    TerminalSnapshot, TerminalWriteRequest,
};

/// Common protocol version used by the CLI, generated clients, and native shells.
pub const HUGINN_PROTOCOL_VERSION: u16 = 1;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSessionRequest {
    pub command_id: CommandId,
    pub seat_id: SeatId,
    pub project_id: ProjectId,
    pub slice_id: SliceId,
    pub provider: ProviderName,
    pub model: ModelName,
    pub title: Option<String>,
    pub target_node: NodeId,
    pub open_tab: bool,
    pub initial_prompt: Option<LiveMessage>,
    /// Declared workload binding for kube-launched profile sessions. Only
    /// the workload launch port sets it; ordinary opens leave it `None`,
    /// and admission records it as durable manifest state verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadSessionBinding>,
    /// The published snapshot revision the opener's ensured token binds:
    /// the session's admitted authority generation, recorded as durable
    /// manifest state. Absent on legacy senders; the daemon then resolves
    /// the generation from the token's own signed claim — never from the
    /// current pinned revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionListQuery {
    pub seat_id: Option<SeatId>,
    pub include_ended: bool,
    pub cursor: Option<SessionListCursor>,
    pub limit: NonZeroU16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneCommand {
    pub command_id: CommandId,
    pub lane_id: LaneId,
    pub expected_revision: u64,
    pub body: LaneCommandBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum LaneCommandBody {
    Pause,
    Resume,
    Restart,
    Checkpoint,
    Abort,
    Rehome(NodeId),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalDecisionCommand {
    pub command_id: CommandId,
    pub approval_id: ApprovalId,
    pub expected_revision: u64,
    pub decision: ApprovalDecision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum CommandExecutionState {
    Accepted,
    Executing,
    Completed,
    Failed,
    Blocked,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandStatus {
    pub command_id: CommandId,
    pub state: CommandExecutionState,
    pub updated_at: OffsetDateTime,
    pub outcome: Option<CommandOutcome>,
}

/// Transport-neutral request surface. The CLI and every other client use this enum.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum HuginnRequest {
    Snapshot(SnapshotQuery),
    Search(SearchQuery),
    Subscribe(SubscriptionSet),
    /// One live object subscription on the socket the client already holds.
    /// Answers `Subscribed`; every `SubscribeObjects` is also the ack — its
    /// `after` is the last checkpoint the client adopted.
    SubscribeObjects(ObjectSubscription),
    OpenSession(OpenSessionRequest),
    SessionCommand(LiveCommand),
    LaneCommand(LaneCommand),
    KubeCommand(KubeCommand),
    ApprovalDecision(ApprovalDecisionCommand),
    ListFiles(FileListRequest),
    ReadFile(FileReadRequest),
    WatchFiles(FileWatchRequest),
    BeginTransfer(TransferManifest),
    TransferChunk(TransferChunkRequest),
    CommitTransfer(TransferId),
    CancelTransfer(TransferCancelRequest),
    GrantDownloadCredit(TransferCreditRequest),
    RequestRender(RenderRequest),
    RenderStatus(RenderStatusRequest),
    WatchRender(RenderWatchRequest),
    IssueContentTicket(ContentTicketRequest),
    BrowserCommand(BrowserCommand),
    BrowserObserve(BrowserObserveRequest),
    SimulationCommand(SimulationCommand),
    AcquireTerminalControl(TerminalAcquireRequest),
    WriteTerminal(TerminalWriteRequest),
    ResizeTerminal(TerminalResizeRequest),
    ReleaseTerminalControl(TerminalReleaseRequest),
    /// Where the owner conversation lives (its current vehicle session).
    ConversationStatus,
    /// One owner line into the conversation, admitted like a Discord DM.
    ConversationSay(ConversationSayRequest),
    /// The owner channel's messages as Discord shows them.
    ConversationThread(ConversationThreadRequest),
    /// The committed reply for one say, if delivery has sent it. An empty
    /// thread means not yet. Never resumes or resends delivery.
    ConversationReply(ConversationReplyRequest),
    /// Model-gateway spend per day, lane, and seat.
    Spend(SpendRequest),
    Deltas(DeltaQuery),
    /// A gesture from the ring's paired device triggers `ring_gesture` routines and answers `Ack`.
    RingGesture(RingGestureReport),
    /// Stops all agent work on the authority; answers `Ack`.
    EmergencyStop(EmergencyStopRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum HuginnResponse {
    Snapshot(SnapshotPage),
    NotModified { revision: Revision },
    Search(SearchPage),
    Subscribed,
    SessionOpened(LiveSessionSummary),
    Roster(SeatRoster),
    Files(FileListPage),
    Command(CommandReceipt),
    Transfer(TransferStatus),
    BrowserObservation(BrowserObservation),
    Artifact(ArtifactRef),
    Render(RenderStatus),
    TerminalControl(TerminalControlStatus),
    ContentTicket(ContentTicket),
    Conversation(ConversationView),
    Spend(SpendView),
    Deltas(DeltaPage),
    Ack,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum HuginnMessage {
    Response {
        request_id: RequestId,
        result: HuginnResponse,
    },
    ObjectSnapshot(ObjectSnapshot),
    ObjectDelta(ObjectDelta),
    ObjectDeltaBatch(ObjectDeltaBatch),
    ReplayBegin {
        stream: StreamId,
        requested_after: Sequence,
        head: Sequence,
    },
    Event(LiveEvent),
    ReplayComplete {
        stream: StreamId,
        head: Sequence,
    },
    TerminalReset(TerminalSnapshot),
    ArtifactChunk(ArtifactChunk),
    BinaryChunk(BinaryChunk),
    TransferStatus(TransferStatus),
    FileDelta(FileDelta),
    RenderStatus(RenderStatus),
    TerminalControlStatus(TerminalControlStatus),
    StreamStatus(StreamStatus),
    CommandStatus(CommandStatus),
    ProtocolError(HuginnProtocolError),
}

/// Public, serializable failures. No transport, filesystem, or provider error is exposed directly.
#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    deny_unknown_fields
)]
pub enum HuginnProtocolError {
    #[error("protocol version {received} is unsupported (supported: {supported})")]
    UnsupportedVersion { received: u16, supported: u16 },
    #[error("invalid request {code}: {message}")]
    InvalidRequest { code: String, message: String },
    #[error("authentication is required")]
    Unauthenticated,
    #[error("the authenticated device is not authorized")]
    Unauthorized,
    #[error("{object_kind} {object_id} was not found")]
    NotFound {
        object_kind: String,
        object_id: String,
    },
    #[error("revision mismatch: expected {expected}, actual {actual}")]
    RevisionMismatch {
        expected: Revision,
        actual: Revision,
    },
    #[error("request conflicts with current state: {message}")]
    Conflict { code: String, message: String },
    #[error("requested stream cursor is no longer retained")]
    CursorExpired,
    #[error("resource limit exceeded: {limit}")]
    ResourceLimit { limit: String },
    #[error("operation is unsupported: {operation}")]
    Unsupported { operation: String },
    #[error("service unavailable: {code}")]
    Unavailable { code: String },
}
