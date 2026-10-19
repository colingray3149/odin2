//! Scoped `odin-artifact://` reads with size limits and BLAKE3 verification through a sealed root.

use std::io::Read;
use std::path::Path;

use odin_domain::{ArtifactId, Digest};
use odin_ledger::{artifact::ArtifactMetadata, Ledger};

use super::resolvers::{
    parse_resource_id, proves_scope, required_id, storage_error, unknown_resource,
};
use super::ScopedUriRouter;
use super::{UriBody, UriContext, UriError, UriRequest, UriResult};

impl ScopedUriRouter {
    pub(super) fn resolve_artifact(
        &self,
        ledger: &Ledger,
        context: &UriContext,
        request: UriRequest,
    ) -> Result<UriResult, UriError> {
        let url = &request.url;
        let id = required_id(&request)?;
        let artifact_id: ArtifactId = parse_resource_id(url, id)?;
        let Some(metadata) = ledger.artifact(&artifact_id).map_err(storage_error)? else {
            return Err(unknown_resource(url, "artifact", id));
        };
        let references = ledger
            .artifact_references(&artifact_id)
            .map_err(storage_error)?;
        let mut proven_reference: Option<String> = None;
        for reference in &references {
            if proves_scope(
                ledger,
                url,
                &context.scope,
                &reference.object_kind,
                &reference.object_id,
                1,
            )? {
                proven_reference =
                    Some(format!("{}:{}", reference.object_kind, reference.object_id));
                break;
            }
        }
        let Some(reference_note) = proven_reference else {
            return Err(UriError::ScopeDenied {
                url: url.to_owned(),
                reason: "no registered artifact reference proves the bound scope".to_owned(),
            });
        };
        let bytes = self.load_artifact_bytes(url, &metadata)?;
        Ok(UriResult {
            content_type: metadata.media_type.clone(),
            immutable: true,
            notes: vec![
                format!(
                    "artifact bytes BLAKE3-verified against registered metadata {}",
                    metadata.digest
                ),
                format!("scope proven by {reference_note} artifact reference"),
            ],
            request,
            body: UriBody::Bytes(bytes),
        })
    }

    /// Reads, bounds, and BLAKE3-verifies artifact bytes against the registered metadata.
    /// The sealed confined-fs capability opens the registered relative path descriptor by
    /// descriptor (openat2 RESOLVE_BENEATH | NO_SYMLINKS) with regular-file and identity
    /// rechecks, so no path re-resolution race exists; the digest binds the bytes regardless.
    /// Before any open, the declared root name is re-proven against the sealed descriptor,
    /// so a root replaced after construction refuses as storage instead of answering from
    /// the orphaned tree.
    fn load_artifact_bytes(
        &self,
        url: &str,
        metadata: &ArtifactMetadata,
    ) -> Result<Vec<u8>, UriError> {
        let mismatch = |detail: String| UriError::ArtifactMismatch {
            url: url.to_owned(),
            detail,
        };
        if metadata.size_bytes > self.max_artifact_bytes {
            return Err(mismatch(format!(
                "registered size {} bytes exceeds the {} byte read bound",
                metadata.size_bytes, self.max_artifact_bytes
            )));
        }
        self.artifact_root
            .verify_declared_root(self.artifact_root_path.as_path())
            .map_err(|error| {
                storage_error(format!(
                    "declared artifact root no longer proves the sealed capability: {error}"
                ))
            })?;
        let file = self
            .artifact_root
            .open_read(Path::new(&metadata.storage_path))
            .map_err(|error| storage_error(format!("artifact bytes are unreadable: {error}")))?;
        let mut bytes = Vec::new();
        file.take(self.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| storage_error(format!("artifact bytes are unreadable: {error}")))?;
        let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if byte_length > self.max_artifact_bytes {
            return Err(mismatch(format!(
                "artifact exceeds the {} byte read bound",
                self.max_artifact_bytes
            )));
        }
        if byte_length != metadata.size_bytes {
            return Err(mismatch(format!(
                "artifact is {} bytes but metadata registers {} bytes",
                byte_length, metadata.size_bytes
            )));
        }
        if Digest::hash(&bytes) != metadata.digest {
            return Err(mismatch(
                "artifact BLAKE3 digest deviates from registered metadata".to_owned(),
            ));
        }
        Ok(bytes)
    }
}
