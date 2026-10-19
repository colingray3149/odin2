use std::fmt;
use std::num::NonZeroU16;
use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

use crate::knowledge::retrieval::KnowledgeLineage;
use crate::{
    ApprovalId, ApprovalStatus, ArmId, ArtifactId, CapabilityId, CommandId, Digest, DomainError,
    EffectClass, SeatId,
};
use odin_types::OperationId;

use super::artifact::{ArtifactChunk, ArtifactRef, TransferChunk, TransferStatus, UploadManifest};
use super::control::{CommandReceipt, LiveCommand};
use super::event::{HistoryPage, HistoryQuery, LiveEvent, SubscribeRequest};
use super::file::{
    ContentTicket, ContentTicketIdentity, ContentTicketRequest, FileDelta, FileListPage,
    FileListRequest, FileReadRequest, FileWatchRequest,
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
use super::rpc::{LiveError, LiveServerMessage, TerminalTargetStatus};
use super::stream::{BinaryChunk, StreamFrame, SubscriptionSet};
use super::terminal::{
    TerminalControlRequest, TerminalControlStatus, TerminalInput, TerminalResize,
};

/// A heap-erased stream whose producer enforces the bound or credit carried by its request.
pub type BoundedStream<T, E> = Pin<Box<dyn Stream<Item = Result<T, E>> + Send + 'static>>;

pub type HuginnMessageStream = BoundedStream<super::protocol::HuginnMessage, HuginnProtocolError>;
pub type LiveEventStream = BoundedStream<LiveEvent, LiveError>;
pub type LiveServerStream = BoundedStream<LiveServerMessage, LiveError>;
pub type ArtifactReadStream = BoundedStream<ArtifactChunk, LiveError>;
pub type FileReadStream = BoundedStream<BinaryChunk, HuginnProtocolError>;
pub type FileDeltaStream = BoundedStream<FileDelta, HuginnProtocolError>;
pub type RenderStatusStream = BoundedStream<RenderStatus, HuginnProtocolError>;
pub type StreamFrameStream = BoundedStream<StreamFrame, HuginnProtocolError>;

pub const NARROWED_ARM_PROJECTION_SCHEMA: &str = "odin.narrowed-arm.projection.v1";

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
            && name.len() <= 191
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AdapterIdentity {
    pub adapter_id: String,
    pub version: String,
    pub binding_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NarrowedArmRecipient {
    pub arm_id: ArmId,
    pub seat_id: SeatId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NarrowedArmEffect {
    pub capability_id: CapabilityId,
    pub effect_class: EffectClass,
    pub arguments_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NarrowedApprovalBinding {
    pub approval_id: ApprovalId,
    pub status: ApprovalStatus,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum NarrowedArmProjectionSchema {
    #[serde(rename = "odin.narrowed-arm.projection.v1")]
    V1,
}

/// Behavior-free narrowed-arm projection. It carries one exact recipient and effect,
/// canonical lineage, and opaque file/transfer identities; it cannot express a
/// broad grant, raw effect, credential value, target endpoint, or payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NarrowedArmProjection {
    pub schema: NarrowedArmProjectionSchema,
    pub operation_id: OperationId,
    pub recipient: NarrowedArmRecipient,
    pub effect: NarrowedArmEffect,
    pub adapter: AdapterIdentity,
    pub credential_handle: Option<OpaqueCredentialHandle>,
    pub lineage: Option<KnowledgeLineage>,
    pub approval: Option<NarrowedApprovalBinding>,
    pub file_identity: Option<ContentTicketIdentity>,
    pub transfer_id: Option<TransferId>,
    pub idempotency_digest: Digest,
}

impl NarrowedArmProjection {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.adapter.adapter_id.trim().is_empty()
            || self.adapter.version.trim().is_empty()
            || self.adapter.adapter_id.chars().any(char::is_control)
            || self.adapter.version.chars().any(char::is_control)
        {
            return Err(DomainError::InvalidEnvelope(
                "narrowed arm adapter identity is invalid".to_owned(),
            ));
        }
        if let Some(approval) = &self.approval {
            if approval.capability_id != self.effect.capability_id
                || approval.arguments_digest != self.effect.arguments_digest
            {
                return Err(DomainError::InvalidEnvelope(
                    "narrowed arm approval does not bind the exact effect".to_owned(),
                ));
            }
        }
        if let Some(file) = &self.file_identity {
            file.validate()?;
            if file.seat != self.recipient.seat_id
                || file.capability.as_str() != self.effect.capability_id.as_str()
                || file.scope.trim().is_empty()
                || file.byte_len > file.byte_ceiling.get()
            {
                return Err(DomainError::InvalidEnvelope(
                    "narrowed arm file identity is outside the exact recipient/effect".to_owned(),
                ));
            }
        }
        Ok(())
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

/// The one descriptor-pinned bounded streaming route for ticket content.
///
/// Implementations re-check every binding on the presented ticket (identity
/// echo, expiry, ceiling, content revision, admitting policy pin) and deny
/// stale or wrong-identity redemption before the underlying descriptor is
/// opened; the returned stream is chunked and never buffers the whole object.
#[async_trait]
pub trait ContentStreamGateway: Send + Sync {
    async fn open_pinned(
        &self,
        ticket: &ContentTicket,
    ) -> Result<FileReadStream, HuginnProtocolError>;
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
        Err(LiveError::Unavailable {
            code: "reclaim_session_unsupported".to_owned(),
        })
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
        Err(LiveError::Unavailable {
            code: "terminal_target_admin_unwired".to_owned(),
        })
    }

    /// Drops the chat registration, restoring the declared selector (or an
    /// unbound state). Fail-closed default like [`OmpLivePlane::bind_terminal_target`].
    async fn unbind_terminal_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        Err(LiveError::Unavailable {
            code: "terminal_target_admin_unwired".to_owned(),
        })
    }

    /// Current terminal target binding, without live verification.
    async fn terminal_target_status(&self) -> Result<TerminalTargetStatus, LiveError> {
        Err(LiveError::Unavailable {
            code: "terminal_target_admin_unwired".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrowed_arm_projection() {
        let digest = |value: &str| Digest::hash(value.as_bytes()).to_string();
        let value = serde_json::json!({
            "schema": NARROWED_ARM_PROJECTION_SCHEMA,
            "operation_id": "operation-1",
            "recipient": { "arm_id": "personal-email", "seat_id": "sinmara" },
            "effect": {
                "capability_id": "email.send",
                "effect_class": "R2",
                "arguments_digest": digest("arguments")
            },
            "adapter": {
                "adapter_id": "synthetic.email",
                "version": "1.0.0",
                "binding_digest": digest("binding")
            },
            "credential_handle": "cred:synthetic-email",
            "lineage": {
                "capsuleId": "sinmara",
                "parents": [{
                    "factId": "7fd72ee8-58c1-4aa9-bce8-3ce9151b13fb",
                    "capsuleId": "sinmara",
                    "factRevision": digest("fact-revision"),
                    "contentDigest": digest("fact-content")
                }],
                "completeness": "complete",
                "freshness": { "asOfRevision": digest("freshness") }
            },
            "approval": {
                "approval_id": "approval-1",
                "status": "approved",
                "capability_id": "email.send",
                "arguments_digest": digest("arguments")
            },
            "file_identity": {
                "contentDigest": digest("file"),
                "revision": null,
                "policyRevision": 7,
                "policyDigest": digest("policy"),
                "identityDigest": digest("device"),
                "seat": "sinmara",
                "scope": "synthetic-email",
                "capability": "email.send",
                "byteLen": 128,
                "byteCeiling": 1024
            },
            "transfer_id": "3c0ae956-553c-4a92-a869-b6101093a9b5",
            "idempotency_digest": digest("idempotency")
        });
        let projection: NarrowedArmProjection =
            serde_json::from_value(value.clone()).expect("decode narrowed arm");
        projection.validate().expect("validate narrowed arm");
        assert!(projection.lineage.is_some());
        assert!(projection.file_identity.is_some());
        assert!(projection.transfer_id.is_some());
        assert_eq!(serde_json::to_value(&projection).unwrap(), value);
        assert_eq!(
            format!("{:?}", projection.credential_handle.as_ref().unwrap()),
            "OpaqueCredentialHandle([REDACTED])"
        );

        let mut unknown = value;
        unknown["credential_value"] = serde_json::json!("secret");
        assert!(serde_json::from_value::<NarrowedArmProjection>(unknown).is_err());
        assert!(OpaqueCredentialHandle::new("secret").is_err());
    }
}
