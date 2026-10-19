use odin_domain::huginn::{ContentSource, FileEntryKind, FileMetadata, HuginnProtocolError};
use odin_domain::Digest;
use serde::{Deserialize, Serialize};

use super::roots::{file_conflict, invalid_file};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PreviewKind {
    ExistingRaster,
    ExistingPdf,
    RenderRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewPlan {
    pub source: ContentSource,
    pub kind: PreviewKind,
    pub media_type: String,
    pub byte_len: u64,
    pub source_revision: Digest,
}

#[derive(Clone, Default)]
pub struct PreviewService;

impl PreviewService {
    pub fn new() -> Self {
        Self
    }

    pub fn for_file(&self, metadata: &FileMetadata) -> Result<PreviewPlan, HuginnProtocolError> {
        if metadata.entry_kind != FileEntryKind::File {
            return Err(invalid_file("only regular files can be previewed"));
        }
        let revision = metadata.revision.ok_or_else(|| {
            file_conflict("fileRevision", "preview source has no stable revision")
        })?;
        let media_type = metadata
            .media_type
            .clone()
            .ok_or_else(|| invalid_file("file media type is not declared by its root"))?;
        let kind = match media_type.as_str() {
            "image/png" | "image/jpeg" | "image/webp" | "image/avif" => PreviewKind::ExistingRaster,
            "application/pdf" => PreviewKind::ExistingPdf,
            "image/svg+xml" => PreviewKind::RenderRequired,
            "text/html" | "application/xhtml+xml" => {
                return Err(invalid_file("active HTML cannot be previewed"));
            }
            _ => PreviewKind::RenderRequired,
        };
        Ok(PreviewPlan {
            source: ContentSource::File {
                root: metadata.root_id.clone(),
                relative: metadata.relative_path.clone(),
                expected_revision: Some(revision),
            },
            kind,
            media_type,
            byte_len: metadata.byte_len,
            source_revision: revision,
        })
    }
}
