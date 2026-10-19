//! Approval-scope material, bounded publication offers, and sanitized
//! navigation observations.

use serde::{Deserialize, Serialize};

use odin_domain::huginn::{ArtifactRef, BrowserSessionId};
use odin_domain::{CapabilityId, Digest};

use super::error::CapabilityError;
use super::url::{restore_sanitized_url, SanitizedUrl};
use super::MAX_FRAGMENT_BYTES;

/// The material the kernel needs to mint an exact approval scope
/// (field-for-field `odin_ledger::approval::ApprovalScope`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalScopeMaterial {
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub arguments_digest: Digest,
}

impl ApprovalScopeMaterial {
    pub fn new(
        session_id: &BrowserSessionId,
        capability_id: CapabilityId,
        arguments_digest: Digest,
    ) -> Self {
        Self {
            target_kind: "browserSession".to_owned(),
            target_id: session_id.to_string(),
            capability_id,
            arguments_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicationKind {
    Frame,
    Screenshot,
    Download,
    Timeline,
}

/// One bounded payload offered for durable publication. The digest is
/// computed here over the exact bytes so the publisher and every downstream
/// consumer verify against the same value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactPublication {
    pub session_id: BrowserSessionId,
    pub kind: PublicationKind,
    pub display_name: String,
    pub media_type: String,
    pub content_digest: Digest,
    pub bytes: Vec<u8>,
}

impl ArtifactPublication {
    pub fn new(
        session_id: BrowserSessionId,
        kind: PublicationKind,
        display_name: String,
        media_type: String,
        bytes: Vec<u8>,
    ) -> Result<Self, CapabilityError> {
        if display_name.is_empty() || display_name.len() > MAX_FRAGMENT_BYTES {
            return Err(CapabilityError::InvalidRequest {
                reason: "display_name must be 1..=MAX_FRAGMENT_BYTES bytes".to_owned(),
            });
        }
        let content_digest = Digest::hash(&bytes);
        Ok(Self {
            session_id,
            kind,
            display_name,
            media_type,
            content_digest,
            bytes,
        })
    }

    pub fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }
}

/// Public publisher trait. Implemented above the adapter (durable Huginn
/// storage); callers must validate the returned [`ArtifactRef`] against the
/// publication before constructing any view from it.
pub trait ArtifactPublisher: Send + Sync {
    fn publish(&self, publication: ArtifactPublication) -> Result<ArtifactRef, CapabilityError>;
}

/// Sanitized navigation facts observed after an applied action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "NavigationObservationParts")]
pub struct NavigationObservation {
    pub url: SanitizedUrl,
    pub origin: String,
    pub exact_url_digest: Digest,
    pub document_digest: Option<Digest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NavigationObservationParts {
    url: String,
    origin: String,
    exact_url_digest: Digest,
    document_digest: Option<Digest>,
}

impl TryFrom<NavigationObservationParts> for NavigationObservation {
    type Error = CapabilityError;

    fn try_from(parts: NavigationObservationParts) -> Result<Self, Self::Error> {
        Self::from_sanitized_parts(
            parts.url,
            parts.origin,
            parts.exact_url_digest,
            parts.document_digest,
        )
    }
}

impl NavigationObservation {
    /// Builds navigation evidence from a worker-sanitized display URL and
    /// digests derived from opaque worker fingerprint tokens.
    pub(crate) fn from_sanitized_parts(
        display_url: String,
        origin: String,
        exact_url_digest: Digest,
        document_digest: Option<Digest>,
    ) -> Result<Self, CapabilityError> {
        let url = restore_sanitized_url(display_url, exact_url_digest, "navigation url")?;
        if url.origin() != origin {
            return Err(CapabilityError::InvalidRequest {
                reason: "navigation origin does not match url".to_owned(),
            });
        }
        Ok(Self {
            url,
            origin,
            exact_url_digest,
            document_digest,
        })
    }
}
