//! `BrainService`: the end-to-end composition of pinned Atlas sources, index
//! generations, retrieval, and durable stores over the existing authorities.
//!
//! Ownership invariants enforced by this composition:
//! - Atlas is the immutable knowledge authority; index generations are exact,
//!   disposable, and rebuilt only from the pinned revision. A moved head is a
//!   typed [`crate::error::BrainError::StaleAuthority`], never silently served data.
//! - Every knowledge source the resolved policy authorizes is composed: one
//!   generation per source, and retrieval pools every current generation.
//!   A zero- or multi-source policy composes exactly what it authorizes;
//!   an absent knowledge policy composes no serving surface at all and the
//!   affected operations fail typed-unavailable. No invented restriction ever
//!   breaks unrelated operations.
//! - The kernel owns capabilities; tool schemas are formatted from an exact
//!   capability listing and never granted here.
//! - The ledger owns audit; every brain-relevant transition is recorded
//!   through [`crate::audit::BrainAudit`].

pub mod archive;
mod authority;
mod config;
mod core_memory;
mod open;
mod prefetch;
mod projection;
mod retrieval;
mod serving;

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::knowledge::AtlasId;

use crate::audit::BrainAudit;
use crate::config::EffectiveBrainPolicy;
use crate::index;
use authority::KnowledgeSource;

pub use crate::projection::KnowledgeProjectionSink;
pub use archive::{
    archive_declaration_digest, ArchiveBackfillOutcome, ArchiveCitation,
    ArchiveEmbeddingBackfillReport, ArchiveEmbeddingBackfillRequest, ArchiveEmbeddingView,
    ArchiveIngestAuthority, ArchiveIngestGate, ArchiveIngestPlan, ArchiveIngestReport,
    ArchiveIngestRequest, ArchiveJobView, ArchivePublicationView, ArchiveSourceStatus,
    EmbeddingBatchLane,
};
pub use config::{
    BrainServiceConfig, BrainSourceConfig, BrainStatus, KnowledgeItem, KnowledgeRecord,
};
pub use core_memory::{meter_tokens, render_core, CoreMemory, CoreSection};
pub use prefetch::{render_prefetch, PREFETCH_HITS};
pub use retrieval::{RetrievalPosture, RetrievalResponse};

/// The composed brain service. Construction pins the Atlas heads and opens
/// every durable store; no component is optional once opened.
pub struct BrainService {
    config: BrainServiceConfig,
    policy: EffectiveBrainPolicy,
    sources: BTreeMap<AtlasId, KnowledgeSource>,
    index: index::store::IndexStore,
    /// Durable normalized archive records, publications, and backfill
    /// staging; present exactly when at least one archive source is wired.
    archives: Option<crate::archive::ArchiveStore>,
    audit: BrainAudit,
    /// The once-set generated-knowledge projection sink. Absent,
    /// nothing renders; present, every eligible source emits its
    /// deterministic pages after generation under the publication lock.
    projection_sink: std::sync::OnceLock<Arc<dyn crate::projection::KnowledgeProjectionSink>>,
    /// Emission publication state, guarded by the non-reentrant publication
    /// lock; see [`self::projection`].
    projection: std::sync::Mutex<projection::PublicationState>,
    /// Compact vector indexes of immutable generations, built once per
    /// process (see [`crate::retrieval::compact`]).
    compact: std::sync::Mutex<
        BTreeMap<
            odin_domain::knowledge::ids::IndexGenerationId,
            (
                std::time::Instant,
                Arc<crate::retrieval::compact::CompactIndex>,
            ),
        >,
    >,
}
