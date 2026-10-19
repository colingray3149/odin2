//! k3s projection and control adapters over the common read-model contracts.

pub mod control;
pub mod view;

pub use control::*;
use std::collections::HashMap;
use std::num::NonZeroU64;
pub use view::*;

use odin_domain::huginn::{ArtifactKind, ArtifactRef, HuginnProtocolError, LiveSessionId};
use odin_domain::{ArtifactId, Digest, LaneId};

const BLOCKED_MEDIA_TYPES: [&str; 3] = ["text/html", "application/xhtml+xml", "image/svg+xml"];

/// Bounded content store shared by the kube, browser, and simulation adapters.
///
/// Every surface artifact (logs, frames, downloads, telemetry, checkpoints, judge reports) is
/// published through this store so a single place enforces media policy, per-object and total
/// byte ceilings, and BLAKE3 digest assignment. Active HTML and unsanitized SVG are rejected:
/// sanitization belongs to the render plane, never to raw surface storage.
pub struct SurfaceArtifacts {
    session: LiveSessionId,
    lane: LaneId,
    max_object_bytes: NonZeroU64,
    max_total_bytes: NonZeroU64,
    total_bytes: u64,
    entries: HashMap<ArtifactId, StoredArtifact>,
}

struct StoredArtifact {
    reference: ArtifactRef,
    bytes: Vec<u8>,
}

impl SurfaceArtifacts {
    pub fn new(
        session: LiveSessionId,
        lane: LaneId,
        max_object_bytes: NonZeroU64,
        max_total_bytes: NonZeroU64,
    ) -> Self {
        Self {
            session,
            lane,
            max_object_bytes,
            max_total_bytes,
            total_bytes: 0,
            entries: HashMap::new(),
        }
    }

    pub fn session(&self) -> &LiveSessionId {
        &self.session
    }

    pub fn lane(&self) -> &LaneId {
        &self.lane
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Publishes one bounded surface object and returns its immutable reference.
    pub fn publish(
        &mut self,
        artifact_id: ArtifactId,
        kind: ArtifactKind,
        display_name: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        if matches!(kind, ArtifactKind::File) && BLOCKED_MEDIA_TYPES.contains(&media_type) {
            return Err(HuginnProtocolError::Unsupported {
                operation: format!("surface media type {media_type} is rejected before publish"),
            });
        }
        if self.entries.contains_key(&artifact_id) {
            return Err(HuginnProtocolError::Conflict {
                code: "surfaceArtifactExists".to_string(),
                message: format!("artifact {artifact_id} is already published"),
            });
        }
        let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_len > self.max_object_bytes.get() {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "surfaceArtifactObjectBytes".to_string(),
            });
        }
        if self.total_bytes.saturating_add(byte_len) > self.max_total_bytes.get() {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "surfaceArtifactTotalBytes".to_string(),
            });
        }
        let reference = ArtifactRef::new(odin_domain::huginn::ArtifactRefInit {
            artifact_id: artifact_id.clone(),
            session_id: self.session,
            lane_id: self.lane.clone(),
            kind,
            display_name: display_name.to_string(),
            media_type: media_type.to_string(),
            byte_len,
            content_digest: Digest::hash(bytes),
        })
        .map_err(|error| HuginnProtocolError::InvalidRequest {
            code: "surfaceArtifact".to_string(),
            message: error.to_string(),
        })?;
        self.total_bytes += byte_len;
        self.entries.insert(
            artifact_id,
            StoredArtifact {
                reference: reference.clone(),
                bytes: bytes.to_vec(),
            },
        );
        Ok(reference)
    }

    pub fn reference(&self, artifact_id: &ArtifactId) -> Option<&ArtifactRef> {
        self.entries.get(artifact_id).map(|entry| &entry.reference)
    }

    pub fn bytes(&self, artifact_id: &ArtifactId) -> Option<&[u8]> {
        self.entries
            .get(artifact_id)
            .map(|entry| entry.bytes.as_slice())
    }

    /// Returns the removed artifact's bytes to the budget; reports whether it was stored.
    pub fn remove(&mut self, artifact_id: &ArtifactId) -> bool {
        match self.entries.remove(artifact_id) {
            Some(entry) => {
                self.total_bytes = self.total_bytes.saturating_sub(entry.reference.byte_len);
                true
            }
            None => false,
        }
    }

    /// Confirms stored bytes still hash to the published digest before delivery.
    pub fn verify(&self, artifact_id: &ArtifactId) -> bool {
        match self.entries.get(artifact_id) {
            Some(entry) => Digest::hash(&entry.bytes) == entry.reference.content_digest,
            None => false,
        }
    }
}
