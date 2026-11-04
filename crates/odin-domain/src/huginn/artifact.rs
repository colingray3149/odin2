//! Artifact transfer manifests, chunks, references, and state.

use std::num::{NonZeroU16, NonZeroU32};

use serde::{Deserialize, Serialize};

use crate::{ArtifactId, CommandId, Digest, DomainError, LaneId};

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
        let actual_len = u64::try_from(chunk.bytes.len()).map_err(|error| {
            invalid_artifact(format!(
                "chunk length {} does not fit u64: {error}",
                chunk.bytes.len()
            ))
        })?;
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
    #[serde(with = "super::bytes")]
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
    #[serde(with = "super::bytes")]
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
    if !super::is_bare_mime(value) {
        return Err(invalid_artifact("media type must be a bare MIME type"));
    }
    let valid = match kind {
        ArtifactKind::File => true,
        ArtifactKind::Render(render) => render.media_type_is_valid(value),
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
