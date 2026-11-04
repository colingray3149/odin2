//! Citations, trust, and source revisions recorded on items flow through
//! chunks and retrieval hits unchanged; sources never mint facts, approvals,
//! or identity.

pub mod archive;
pub mod atlas;
pub mod ops;
pub mod silverbullet;
pub mod state;

use odin_domain::knowledge::ids::{AtlasId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::{Digest, ProjectId};

use crate::error::{BrainError, BrainResult};
use crate::index::model::ItemProvenance;

/// One exact, digest-identified source projection ready for chunking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceItem {
    /// Stable knowledge source identity (e.g. `atlas:odin`, `vault:silverbullet`).
    pub source: AtlasId,
    /// Immutable revision digest of the pinned source the item was read from.
    pub source_revision: Digest,
    /// Stable item identity derived from the source and its natural key.
    pub item_id: KnowledgeItemId,
    /// Trust assigned by provenance, carried into chunks and hits.
    pub trust: TrustClass,
    /// Exact Atlas node provenance when the source has node identity.
    pub provenance: Option<ItemProvenance>,
    /// Recorded project ownership, checked again at every serving boundary.
    pub project: Option<ProjectId>,
    /// Exact item text; citations address byte ranges within it.
    pub text: String,
    /// The human summary page of generated knowledge this item renders into
    /// (a project, a UTC day). Records carry none: the brain serves them,
    /// the vault never shows them one page each.
    pub summary_page: Option<String>,
}

impl SourceItem {
    /// Item identity prefix binding derived IDs to this module.
    const ITEM_ID_PREFIX: &'static [u8] = b"odin-brain:item:v1\x00";

    /// Derives the item identity from the pinned source and its natural key
    /// (Atlas node ID or vault page name), then constructs the item.
    ///
    /// The natural key must already be a stable, source-unique identifier;
    /// callers confine it before calling (Atlas scopes and vault page-name
    /// validation both enforce this).
    pub fn new(
        source: AtlasId,
        source_revision: Digest,
        natural_key: &[u8],
        trust: TrustClass,
        text: impl Into<String>,
    ) -> BrainResult<Self> {
        let item_id = Self::identity(&source, natural_key)?;
        let text = text.into();
        if text.is_empty() {
            return Err(BrainError::InvalidRequest(
                "source item text must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            source,
            source_revision,
            item_id,
            trust,
            provenance: None,
            project: None,
            text,
            summary_page: None,
        })
    }

    /// Derives the stable item identity from the pinned source and its natural
    /// key (Atlas node ID, vault page name, or archive record key) without
    /// copying projected text.
    pub fn identity(source: &AtlasId, natural_key: &[u8]) -> BrainResult<KnowledgeItemId> {
        if natural_key.is_empty() {
            return Err(BrainError::InvalidRequest(
                "source item natural key must not be empty".to_owned(),
            ));
        }
        let mut identity = Vec::with_capacity(
            Self::ITEM_ID_PREFIX.len() + source.as_str().len() + natural_key.len() + 1,
        );
        identity.extend_from_slice(Self::ITEM_ID_PREFIX);
        identity.extend_from_slice(source.as_str().as_bytes());
        identity.push(0);
        identity.extend_from_slice(natural_key);
        Ok(KnowledgeItemId::new(Digest::hash(&identity)))
    }

    /// Binds a projection to its recorded project; absence never implies one.
    pub fn with_project(mut self, project: ProjectId) -> Self {
        self.project = Some(project);
        self
    }

    /// Marks the item as (part of) the named generated-knowledge summary page.
    pub fn with_summary_page(mut self, page: impl Into<String>) -> Self {
        self.summary_page = Some(page.into());
        self
    }

    /// Attaches Atlas node provenance for `brain://` scope enforcement.
    pub fn with_provenance(mut self, provenance: ItemProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }
}

/// Rejects an oversize item before chunking so indexing stays bounded.
pub(crate) fn ensure_item_size(text: &str, max_bytes: u64) -> BrainResult<()> {
    let len = text.len() as u64;
    if len > max_bytes {
        return Err(BrainError::InvalidRequest(format!(
            "source item exceeds the {max_bytes} byte indexing bound ({len} bytes)"
        )));
    }
    Ok(())
}
