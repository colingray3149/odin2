//! Artifact transfer manifests, chunks, references, and state.

use std::collections::BTreeSet;

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use crate::{ArtifactId, CommandId, Digest, DomainError, LaneId, SeatId};

use super::ids::{DeviceId, LiveSessionId, TransferId};
use super::render::RenderKind;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactKind {
    File,
    Render(RenderKind),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactDirection {
    DeviceToSession,
    SessionToDevice,
}

/// One declared lane transfer policy projected from the validated registry
/// snapshot. Before any byte of a transfer is opened or written, the resolved
/// lane must admit the manifest direction, payload kind, media type, and
/// byte length, and the admitting policy revision/digest must still be
/// current.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LaneTransferBinding {
    pub lane: LaneId,
    pub direction: ArtifactDirection,
    pub payload: ArtifactKind,
    pub allowed_media_types: BTreeSet<String>,
    pub max_bytes: NonZeroU64,
    pub policy_revision: u64,
    pub policy_digest: Digest,
}

impl LaneTransferBinding {
    /// Producer→consumer admission check. Fails before any byte is read.
    pub fn admits(
        &self,
        direction: ArtifactDirection,
        payload: &ArtifactKind,
        media_type: &str,
        byte_len: u64,
    ) -> Result<(), DomainError> {
        if self.direction != direction {
            return Err(invalid_lane(format!(
                "lane {} carries {direction:?} traffic, not {:?}",
                self.lane, self.direction
            )));
        }
        if !same_payload_class(&self.payload, payload) {
            return Err(invalid_lane(format!(
                "lane {} carries {} payloads, not {payload:?}",
                self.lane,
                match self.payload {
                    ArtifactKind::File => "file",
                    ArtifactKind::Render(_) => "render",
                }
            )));
        }
        if !self
            .allowed_media_types
            .iter()
            .any(|allowed| allowed == media_type)
        {
            return Err(invalid_lane(format!(
                "lane {} does not admit media type {media_type:?}",
                self.lane
            )));
        }
        if byte_len > self.max_bytes.get() {
            return Err(invalid_lane(format!(
                "lane {} byte ceiling {} is below the manifest length {byte_len}",
                self.lane,
                self.max_bytes.get()
            )));
        }
        Ok(())
    }
}

fn same_payload_class(declared: &ArtifactKind, manifest: &ArtifactKind) -> bool {
    matches!(
        (declared, manifest),
        (ArtifactKind::File, ArtifactKind::File)
            | (ArtifactKind::Render(_), ArtifactKind::Render(_))
    )
}

/// Seat-scoped transfer byte ceilings resolved from the validated snapshot.
/// The revision/digest pair pins the snapshot that granted them; a consumer
/// resolving against a different policy state must fail as stale.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeatTransferCeilings {
    pub seat: SeatId,
    pub file_bytes: NonZeroU64,
    pub render_bytes: NonZeroU64,
    pub policy_revision: u64,
    pub policy_digest: Digest,
}

impl SeatTransferCeilings {}

fn invalid_lane(message: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("lane transfer policy: {}", message.into()))
}

#[derive(Clone, Debug)]
pub struct TransferManifestInit {
    pub transfer_id: TransferId,
    pub session_id: LiveSessionId,
    pub kind: ArtifactKind,
    pub direction: ArtifactDirection,
    pub display_name: String,
    pub media_type: String,
    pub byte_len: u64,
    pub chunk_len: NonZeroU32,
    pub content_digest: Digest,
}

/// A complete declaration made before any transfer bytes are accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferManifest {
    pub transfer_id: TransferId,
    pub session_id: LiveSessionId,
    pub kind: ArtifactKind,
    pub direction: ArtifactDirection,
    pub display_name: String,
    pub media_type: String,
    pub byte_len: u64,
    pub chunk_len: NonZeroU32,
    pub content_digest: Digest,
}

impl TransferManifest {
    pub fn new(init: TransferManifestInit) -> Result<Self, DomainError> {
        let TransferManifestInit {
            transfer_id,
            session_id,
            kind,
            direction,
            display_name,
            media_type,
            byte_len,
            chunk_len,
            content_digest,
        } = init;
        validate_display_name(&display_name)?;
        validate_media_type(kind, &media_type)?;
        Ok(Self {
            transfer_id,
            session_id,
            kind,
            direction,
            display_name,
            media_type,
            byte_len,
            chunk_len,
            content_digest,
        })
    }

    pub fn chunk_count(&self) -> u64 {
        let chunk_len = u64::from(self.chunk_len.get());
        self.byte_len / chunk_len + u64::from(!self.byte_len.is_multiple_of(chunk_len))
    }

    /// Validates a received chunk's index, exact range length, and BLAKE3 digest.
    pub fn validate_chunk(&self, chunk: &TransferChunk) -> Result<(), DomainError> {
        let chunk_count = self.chunk_count();
        let index = u64::from(chunk.index);
        if index >= chunk_count {
            return Err(invalid_artifact(format!(
                "chunk index {} is outside declared chunk count {chunk_count}",
                chunk.index
            )));
        }

        let offset = index
            .checked_mul(u64::from(self.chunk_len.get()))
            .ok_or_else(|| invalid_artifact("chunk offset overflow"))?;
        let remaining = self
            .byte_len
            .checked_sub(offset)
            .ok_or_else(|| invalid_artifact("chunk begins beyond declared content length"))?;
        let expected_len = remaining.min(u64::from(self.chunk_len.get()));
        let actual_len = u64::try_from(chunk.bytes.len())
            .map_err(|_| invalid_artifact("chunk length does not fit u64"))?;
        if actual_len != expected_len {
            return Err(invalid_artifact(format!(
                "chunk {} has {actual_len} bytes but its declared range requires {expected_len}",
                chunk.index
            )));
        }
        if Digest::hash(&chunk.bytes) != chunk.digest {
            return Err(invalid_artifact(format!(
                "chunk {} BLAKE3 digest does not match its bytes",
                chunk.index
            )));
        }
        Ok(())
    }

    /// Validates the assembled object before it may be published.
    pub fn validate_final(&self, received_len: u64, digest: Digest) -> Result<(), DomainError> {
        if received_len != self.byte_len {
            return Err(invalid_artifact(format!(
                "received length {received_len} does not match declared length {}",
                self.byte_len
            )));
        }
        if digest != self.content_digest {
            return Err(invalid_artifact(
                "assembled BLAKE3 digest does not match declared content digest",
            ));
        }
        Ok(())
    }
}

/// An inbound manifest bound to the authenticated source device.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UploadManifest {
    pub manifest: TransferManifest,
    pub source_device: DeviceId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferChunk {
    pub index: u32,
    pub bytes: Vec<u8>,
    pub digest: Digest,
}

impl TransferChunk {
    pub fn new(index: u32, bytes: Vec<u8>, digest: Digest) -> Result<Self, DomainError> {
        if Digest::hash(&bytes) != digest {
            return Err(invalid_artifact(
                "transfer chunk BLAKE3 digest does not match its bytes",
            ));
        }
        Ok(Self {
            index,
            bytes,
            digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferChunkRequest {
    pub transfer_id: TransferId,
    pub chunk: TransferChunk,
}

/// Idempotent cancellation of one transfer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCancelRequest {
    pub command_id: CommandId,
    pub transfer_id: TransferId,
}

/// Additional bounded download credit. `command_id` prevents retry amplification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferCreditRequest {
    pub command_id: CommandId,
    pub transfer_id: TransferId,
    pub chunks: NonZeroU16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactChunk {
    pub transfer_id: TransferId,
    pub artifact_id: ArtifactId,
    pub index: u32,
    pub bytes: Vec<u8>,
    pub digest: Digest,
    pub final_chunk: bool,
}

impl ArtifactChunk {
    pub fn new(
        transfer_id: TransferId,
        artifact_id: ArtifactId,
        index: u32,
        bytes: Vec<u8>,
        digest: Digest,
        final_chunk: bool,
    ) -> Result<Self, DomainError> {
        if Digest::hash(&bytes) != digest {
            return Err(invalid_artifact(
                "artifact chunk BLAKE3 digest does not match its bytes",
            ));
        }
        Ok(Self {
            transfer_id,
            artifact_id,
            index,
            bytes,
            digest,
            final_chunk,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactRefInit {
    pub artifact_id: ArtifactId,
    pub session_id: LiveSessionId,
    pub lane_id: LaneId,
    pub kind: ArtifactKind,
    pub display_name: String,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
}

/// Published immutable content. This identity is intentionally distinct from a file-root path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRef {
    pub artifact_id: ArtifactId,
    pub session_id: LiveSessionId,
    pub lane_id: LaneId,
    pub kind: ArtifactKind,
    pub display_name: String,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
}

impl ArtifactRef {
    pub fn new(init: ArtifactRefInit) -> Result<Self, DomainError> {
        let ArtifactRefInit {
            artifact_id,
            session_id,
            lane_id,
            kind,
            display_name,
            media_type,
            byte_len,
            content_digest,
        } = init;
        validate_display_name(&display_name)?;
        validate_media_type(kind, &media_type)?;
        Ok(Self {
            artifact_id,
            session_id,
            lane_id,
            kind,
            display_name,
            media_type,
            byte_len,
            content_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferStatus {
    Declared,
    Receiving,
    Verified,
    Published,
    Rejected,
    Cancelled,
}

impl TransferStatus {
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Declared,
                Self::Receiving | Self::Rejected | Self::Cancelled
            ) | (
                Self::Receiving,
                Self::Verified | Self::Rejected | Self::Cancelled
            ) | (
                Self::Verified,
                Self::Published | Self::Rejected | Self::Cancelled
            )
        )
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Published | Self::Rejected | Self::Cancelled)
    }
}

fn validate_display_name(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(invalid_artifact("display name must not be empty"));
    }
    if value.as_bytes().contains(&0) {
        return Err(invalid_artifact("display name must not contain NUL"));
    }
    Ok(())
}

fn validate_media_type(kind: ArtifactKind, value: &str) -> Result<(), DomainError> {
    if value.is_empty()
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(byte, b';' | b',')
        })
        || value.split_once('/').is_none()
    {
        return Err(invalid_artifact("media type must be a bare MIME type"));
    }

    let valid = match kind {
        ArtifactKind::File => true,
        ArtifactKind::Render(RenderKind::RasterImage) => {
            matches!(
                value,
                "image/png" | "image/jpeg" | "image/webp" | "image/avif"
            )
        }
        ArtifactKind::Render(RenderKind::SanitizedSvg) => value == "image/svg+xml",
        ArtifactKind::Render(RenderKind::Pdf) => value == "application/pdf",
    };
    if !valid {
        return Err(invalid_artifact(
            "media type is not permitted for the declared artifact kind",
        ));
    }
    Ok(())
}

fn invalid_artifact(message: impl Into<String>) -> DomainError {
    DomainError::InvalidEnvelope(format!("invalid artifact transfer: {}", message.into()))
}
