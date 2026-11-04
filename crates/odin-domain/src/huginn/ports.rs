use std::fmt;
use std::num::NonZeroU16;
use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

use crate::{ArtifactId, CommandId, DomainError};

use super::artifact::{ArtifactChunk, ArtifactRef, TransferChunk, TransferStatus, UploadManifest};
use super::control::{CommandReceipt, LiveCommand};
use super::event::{HistoryPage, HistoryQuery, LiveEvent, SubscribeRequest};
use super::file::{
    ContentTicket, ContentTicketRequest, FileDelta, FileListPage, FileListRequest, FileReadRequest,
    FileWatchRequest,
};
use super::ids::{DeviceId, LiveSessionId, RenderId, TerminalControlLeaseId, TransferId};
use super::protocol::{
    HuginnProtocolError, HuginnRequest, HuginnResponse, OpenSessionRequest, SessionListQuery,
};
use super::read_model::{
    DeltaPage, DeltaQuery, ObjectDeltaBatch, ObjectKind, QueryScope, Revision, SearchPage,
    SearchQuery, SnapshotPage, SnapshotQuery,
};
use super::render::{RenderRequest, RenderStatus};
use super::roster::{LiveSessionSummary, SeatRoster, SessionListPage};
use super::rpc::{LiveError, TerminalTargetStatus};
use super::stream::{BinaryChunk, SubscriptionSet};
use super::terminal::{
    TerminalControlRequest, TerminalControlStatus, TerminalInput, TerminalResize,
};

/// A heap-erased stream whose producer enforces the bound or credit carried by its request.
pub type BoundedStream<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send + 'static>>;

pub type HuginnMessageStream = BoundedStream<super::protocol::HuginnMessage, HuginnProtocolError>;
pub type LiveEventStream = BoundedStream<LiveEvent, LiveError>;
pub type ArtifactReadStream = BoundedStream<ArtifactChunk, LiveError>;
pub type FileReadStream = BoundedStream<BinaryChunk, HuginnProtocolError>;
pub type FileDeltaStream = BoundedStream<FileDelta, HuginnProtocolError>;
pub type RenderStatusStream = BoundedStream<RenderStatus, HuginnProtocolError>;

/// The longest id after `cred:` in a credential handle.
pub const MAX_CREDENTIAL_NAME_BYTES: usize = 191;

/// Opaque adapter credential reference. The referenced value never enters this
/// ABI and the handle carries no authority outside an admitted operation.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct OpaqueCredentialHandle(String);

impl OpaqueCredentialHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let Some(name) = value.strip_prefix("cred:") else {
            return Err(DomainError::InvalidEnvelope(
                "credential handle must use the cred:<id> form".to_owned(),
            ));
        };
        let valid = !name.is_empty()
            && name.len() <= MAX_CREDENTIAL_NAME_BYTES
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        if !valid {
            return Err(DomainError::InvalidEnvelope(
                "credential handle contains an invalid opaque ID".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OpaqueCredentialHandle {
    type Error = DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<OpaqueCredentialHandle> for String {
    fn from(value: OpaqueCredentialHandle) -> Self {
        value.0
    }
}

impl fmt::Debug for OpaqueCredentialHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueCredentialHandle([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactReadRequest {
    pub artifact_id: ArtifactId,
    pub first_chunk: u32,
    pub initial_credit: NonZeroU16,
}

#[async_trait]
pub trait HuginnReadModel: Send + Sync {
    async fn snapshot(&self, query: SnapshotQuery) -> Result<SnapshotPage, HuginnProtocolError>;

    async fn search(&self, query: SearchQuery) -> Result<SearchPage, HuginnProtocolError>;

    /// One page of deltas after the query's opaque cursor, whose encoded
    /// deltas stay within `max_bytes` (the caller's frame budget). The
    /// cursor binds the model that issued it: another model's fails typed
    /// at any revision, so no per-connection state is needed to resume.
    async fn deltas(
        &self,
        query: DeltaQuery,
        max_bytes: usize,
    ) -> Result<DeltaPage, HuginnProtocolError>;

    /// Resolves once the global model revision moves past `known` and
    /// returns it. Revisions may batch, so the caller re-reads pages after
    /// the wake instead of trusting one value as complete. The scalar head
    /// watch stays server-side.
    async fn object_head_after(&self, _known: Revision) -> Result<Revision, HuginnProtocolError> {
        Err(HuginnProtocolError::Unsupported {
            operation: "read-model head wake".to_owned(),
        })
    }

    /// One coalesced [`ObjectDeltaBatch`] for a live object subscription:
    /// every object matching `kinds` and `scope`, at most one delta per
    /// object resolved to its state inside the covered range, within
    /// `max_bytes` encoded and `limit` items. `after` is the global model
    /// revision; below the retained window fails `CursorExpired` (the client
    /// snapshots and resubscribes), past the head fails per the existing
    /// cursor mapping.
    async fn object_deltas_page(
        &self,
        _after: Revision,
        _kinds: &[ObjectKind],
        _scope: &QueryScope,
        _limit: usize,
        _max_bytes: usize,
    ) -> Result<ObjectDeltaBatch, HuginnProtocolError> {
        Err(HuginnProtocolError::Unsupported {
            operation: "object subscription".to_owned(),
        })
    }

    /// Whether any change past `after` is urgent (see
    /// [`urgent_object`](super::read_model::urgent_object)) and inside this
    /// subscription's `kinds` and `scope` — the flush-now signal for a
    /// coalescing push whose page stopped short of retained content,
    /// answered without building a second page.
    async fn has_urgent_objects_since(
        &self,
        _after: Revision,
        _kinds: &[ObjectKind],
        _scope: &QueryScope,
    ) -> Result<bool, HuginnProtocolError> {
        Err(HuginnProtocolError::Unsupported {
            operation: "object subscription urgency".to_owned(),
        })
    }
}

#[async_trait]
pub trait HuginnCommandPort: Send + Sync {
    async fn execute(&self, request: HuginnRequest) -> Result<HuginnResponse, HuginnProtocolError>;
}

#[async_trait]
pub trait HuginnStreamSource: Send + Sync {
    async fn subscribe(
        &self,
        subscriptions: SubscriptionSet,
    ) -> Result<HuginnMessageStream, HuginnProtocolError>;
}

#[async_trait]
pub trait FileGateway: Send + Sync {
    async fn list(&self, request: FileListRequest) -> Result<FileListPage, HuginnProtocolError>;

    async fn read(&self, request: FileReadRequest) -> Result<FileReadStream, HuginnProtocolError>;

    async fn watch(
        &self,
        request: FileWatchRequest,
    ) -> Result<FileDeltaStream, HuginnProtocolError>;
}

#[async_trait]
pub trait RenderGateway: Send + Sync {
    async fn request_render(
        &self,
        request: RenderRequest,
    ) -> Result<RenderStatus, HuginnProtocolError>;

    async fn render_status(&self, render_id: RenderId)
        -> Result<RenderStatus, HuginnProtocolError>;

    async fn watch_render(
        &self,
        render_id: RenderId,
    ) -> Result<RenderStatusStream, HuginnProtocolError>;
}

#[async_trait]
pub trait ContentTicketIssuer: Send + Sync {
    async fn issue(
        &self,
        device: DeviceId,
        request: ContentTicketRequest,
    ) -> Result<ContentTicket, HuginnProtocolError>;
}

#[async_trait]
pub trait OmpLivePlane: Send + Sync {
    async fn roster(&self) -> Result<SeatRoster, LiveError>;

    async fn terminal_snapshot(
        &self,
        session: LiveSessionId,
    ) -> Result<super::terminal::TerminalSnapshot, LiveError>;

    async fn sessions(&self, query: SessionListQuery) -> Result<SessionListPage, LiveError>;

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError>;

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError>;

    async fn open_session(
        &self,
        request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError>;

    /// Opens a session while retaining ownership of all launch work until it
    /// completes. The caller cancels by sending `true` and must still await
    /// this method; dropping its future is not a cancellation protocol.
    ///
    /// On cancellation the implementation cancels and joins the actual launch
    /// before returning. The boolean reports whether launch authority must be
    /// retained: either the session actor was committed to the plane (before
    /// any initial prompt), or cleanup could not be proven. It can therefore
    /// be true even when the result is an error, including a launcher join
    /// failure. Only false permits the caller to release launch authority.
    /// Planes without this ownership guarantee refuse without starting work.
    async fn open_session_owned(
        &self,
        _request: OpenSessionRequest,
        _cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> (Result<LiveSessionSummary, LiveError>, bool) {
        (
            Err(LiveError::Unsupported {
                operation: "open_session_owned".to_owned(),
            }),
            false,
        )
    }

    /// Rehydrates one conversation vehicle from durable state into the
    /// plane: stops any stale incarnation for it, advances the epoch, and
    /// launches a fresh authority-verified bridge with the session's
    /// durable transcript resumed — under the SAME session identity. A
    /// truthfully Ended session is refused (terminal stays terminal).
    /// Works whether or not the plane currently holds an actor for the
    /// session.
    async fn reclaim_session(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        let _ = session_id;
        Err(LiveError::unavailable(
            "reclaim_session_unsupported",
            "this plane cannot reclaim sessions",
        ))
    }

    async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError>;

    async fn begin_upload(&self, manifest: UploadManifest) -> Result<TransferStatus, LiveError>;

    async fn upload_chunk(
        &self,
        transfer: TransferId,
        chunk: TransferChunk,
    ) -> Result<(), LiveError>;

    async fn commit_upload(&self, transfer: TransferId) -> Result<ArtifactRef, LiveError>;

    async fn cancel_transfer(
        &self,
        command_id: CommandId,
        transfer: TransferId,
    ) -> Result<TransferStatus, LiveError>;

    async fn grant_download_credit(
        &self,
        command_id: CommandId,
        transfer: TransferId,
        chunks: NonZeroU16,
    ) -> Result<(), LiveError>;

    async fn read_artifact(
        &self,
        request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError>;

    async fn acquire_terminal_control(
        &self,
        command_id: CommandId,
        device: DeviceId,
        request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError>;

    async fn write_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        input: TerminalInput,
    ) -> Result<(), LiveError>;

    async fn resize_terminal(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        resize: TerminalResize,
    ) -> Result<(), LiveError>;

    async fn release_terminal_control(
        &self,
        command_id: CommandId,
        session: LiveSessionId,
        lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError>;

    /// Explicitly binds the operator terminal tab target after the admin
    /// verified the named Zellij session is currently live. Fail-closed
    /// default: a plane without a wired terminal target admin refuses
    /// typed, it never guesses a session.
    async fn bind_terminal_target(
        &self,
        _zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        Err(LiveError::unavailable(
            "terminal_target_admin_unwired",
            "this plane has no terminal target admin",
        ))
    }

    /// Drops the chat registration, restoring the declared selector (or an
    /// unbound state). Fail-closed default like [`OmpLivePlane::bind_terminal_target`].
    async fn unbind_terminal_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        Err(LiveError::unavailable(
            "terminal_target_admin_unwired",
            "this plane has no terminal target admin",
        ))
    }

    /// Current terminal target binding, without live verification.
    async fn terminal_target_status(&self) -> Result<TerminalTargetStatus, LiveError> {
        Err(LiveError::unavailable(
            "terminal_target_admin_unwired",
            "this plane has no terminal target admin",
        ))
    }
}

#[cfg(test)]
mod tests {}
