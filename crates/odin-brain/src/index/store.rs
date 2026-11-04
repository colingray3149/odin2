//! Exact, disposable, generation-scoped index storage in the brain's
//! PostgreSQL store.
//!
//! The index is a cache over the immutable Atlas authority: every stored row
//! is pinned to the Atlas revision and manifest digest it was built from and
//! can be rebuilt at any time. The store therefore implements:
//! - **Immutability**: a stored generation can never be overwritten; storing
//!   identical content is an idempotent no-op, and divergent content under an
//!   existing generation ID is impossible by construction (the ID is the
//!   manifest hash) and rejected as corruption when observed.
//! - **Sealing**: a build streams into the store and is read back and hashed
//!   to its manifest before its header seals it (`seal`); only sealed
//!   generations serve.
//! - **Staleness**: `current` only returns a generation whose pinned Atlas
//!   revision equals the caller's pinned head; a moved head yields `None`
//!   (stale) rather than stale rows.
//! - **Retention**: `retire_older` keeps a source's served generation and
//!   newer ones; a generation's rows go with its last holder.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId,
};
use odin_domain::knowledge::retrieval::{Citation, IndexGeneration, IndexedChunk, TrustClass};
use odin_domain::Digest;

use crate::error::{BrainError, BrainResult, BRAIN_INDEX_STORE};
use crate::index::build::IndexBuild;
use crate::index::model::ItemProvenance;
use crate::index::postgres::BrainPostgres;

mod chunks;
mod seal;

/// Provenance fields reach PostgreSQL text columns, which cannot hold NUL.
fn ensure_nul_free(provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>) -> BrainResult<()> {
    let has_nul = provenance.values().any(|item| {
        item.node_id.contains('\0')
            || item.path.contains('\0')
            || item.scope_tags.iter().any(|tag| tag.contains('\0'))
    });
    if has_nul {
        return Err(BrainError::InvalidRequest(
            "provenance fields must not contain NUL bytes".to_owned(),
        ));
    }
    Ok(())
}

fn create_root(root: &Path) -> BrainResult<()> {
    std::fs::create_dir_all(root).map_err(|error| BrainError::Unavailable {
        component: BRAIN_INDEX_STORE,
        reason: format!("cannot create index root {}: {error}", root.display()),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    /// The generation and its chunks were newly persisted.
    Stored,
    /// The identical generation was already present (idempotent rebuild).
    AlreadyPresent,
}

/// One seat's view of the generation-scoped index in the PostgreSQL store.
pub struct IndexStore {
    /// The store's directory: its owner key in the PostgreSQL store.
    root: PathBuf,
    postgres: Arc<BrainPostgres>,
    /// Generations this store holds sealed in the PostgreSQL store, with
    /// their chunk counts. Sealed headers are insert-only; only this
    /// store's own retire drops its hold.
    sealed: Mutex<BTreeMap<IndexGenerationId, (IndexGeneration, u64)>>,
}

impl IndexStore {
    /// Persists one deterministic build. Insert-only: a stored generation is
    /// immutable; re-storing identical content is an idempotent no-op.
    pub fn store(&self, build: &IndexBuild, created_epoch: u64) -> BrainResult<StoreOutcome> {
        ensure_nul_free(&build.provenance)?;
        if self
            .sealed_generation(&build.generation.generation_id)?
            .is_some()
        {
            return Ok(StoreOutcome::AlreadyPresent);
        }
        let stamp = seal::Stamp {
            atlas_id: &build.generation.atlas_id,
            atlas_revision: build.generation.atlas_revision,
            embedding_model: &build.generation.embedding_model,
        };
        let (generation, outcome) = self.write_postgres(
            &stamp,
            created_epoch,
            &mut build.chunks.iter().cloned().map(Ok),
            &build.provenance,
        )?;
        if generation.generation_id != build.generation.generation_id {
            return Err(corrupt(
                "the stored generation's manifest differs from the build's",
            ));
        }
        Ok(outcome)
    }

    /// Loads one exact generation and verifies it is pinned to the expected
    /// source and revision. Used by archive serving paths, which pin the
    /// publication's exact generation rather than the newest generation for
    /// a (source, revision) pair — an unpublished restamp twin must never
    /// win by timestamp.
    pub fn load_pinned(
        &self,
        generation_id: &IndexGenerationId,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
    ) -> BrainResult<IndexGeneration> {
        let found = self
            .sealed_generation(generation_id)?
            .map(|(generation, _)| generation);
        let generation = found.ok_or_else(|| BrainError::NotFound {
            kind: "index generation",
            id: generation_id.to_string(),
        })?;
        if &generation.atlas_id != atlas_id || &generation.atlas_revision != atlas_revision {
            return Err(BrainError::StaleAuthority {
                authority: "index_generation",
                detail: format!(
                    "generation {} pins {} at {} but the publication pins {} at {}",
                    generation.generation_id,
                    generation.atlas_id.as_str(),
                    generation.atlas_revision,
                    atlas_id.as_str(),
                    atlas_revision
                ),
            });
        }
        Ok(generation)
    }

    /// Returns the generation pinned to exactly this Atlas head, if stored.
    /// A moved head yields `None` — the stored generation is stale.
    pub fn current(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
    ) -> BrainResult<Option<IndexGeneration>> {
        self.current_for_model(atlas_id, atlas_revision, None)
    }

    /// The model-aware live selection: the newest generation for the
    /// (source, revision) pair WHOSE embedding-model stamp equals the
    /// requested effective model when one is declared. A model identity
    /// change (for example a provider protocol suffix) is a different
    /// embedding space by construction: an old-stamp generation must never
    /// win the pin only to be refused later by the vector-pool authority
    /// gate — the caller builds a fresh generation under the declared model
    /// instead. `None` keeps the newest-by-timestamp selection.
    pub fn current_for_model(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        embedding_model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<IndexGeneration>> {
        self.sealed_current(atlas_id, atlas_revision, embedding_model)
    }

    /// The newest sealed generation this store holds of one source (stamped
    /// with `model` when given), regardless of revision.
    pub fn newest(
        &self,
        atlas_id: &AtlasId,
        model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<IndexGeneration>> {
        Ok(self
            .held_generations(Some(atlas_id), model)?
            .into_iter()
            .next())
    }

    /// Whether `generation_id` serves: once this store holds it sealed.
    pub fn servable(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        Ok(self.sealed_generation(generation_id)?.is_some())
    }

    /// Keeps `keep` and every newer generation of its source; retires the
    /// rest. Returns how many retired.
    pub fn retire_older(&self, atlas_id: &AtlasId, keep: &IndexGenerationId) -> BrainResult<usize> {
        let ids: Vec<IndexGenerationId> = self
            .held_generations(Some(atlas_id), None)?
            .into_iter()
            .map(|generation| generation.generation_id)
            .collect();
        let Some(position) = ids.iter().position(|id| id == keep) else {
            return Ok(0);
        };
        let mut retired = 0;
        for id in &ids[position + 1..] {
            if self.retire(id)? {
                retired += 1;
            }
        }
        Ok(retired)
    }

    /// Lists the sealed generations this store holds, newest first,
    /// optionally for one source.
    pub fn list(&self, atlas_id: Option<&AtlasId>) -> BrainResult<Vec<IndexGeneration>> {
        self.held_generations(atlas_id, None)
    }

    /// Releases this store's hold on one generation (its rows go with the
    /// last holder). Returns whether it held it.
    pub fn retire(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        let held = self.sealed_generation(generation_id)?.is_some();
        self.unseal(generation_id)?;
        Ok(held)
    }

    /// Returns the recorded Atlas node provenance for one item of one sealed
    /// generation without materializing the generation's chunks. `Ok(None)`
    /// means the item exists but was indexed from a source without Atlas
    /// node identity (e.g. a SilverBullet page); a missing generation or
    /// item is typed [`BrainError::NotFound`].
    pub fn provenance(
        &self,
        generation_id: &IndexGenerationId,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ItemProvenance>> {
        self.sealed_provenance(generation_id, item_id)
    }

    /// Streaming variant of [`Self::store`]: persists one generation while
    /// consuming chunks one at a time, so mbox-scale sources never
    /// materialize every chunk in RAM. Chunks are spooled to an internal
    /// stage table while the manifest digest is computed incrementally over
    /// the exact chunk stream, then copied into the immutable chunk table in
    /// one transaction with the generation header. Chunks must arrive in
    /// stored-ordinal order (per-item chunk order). Insert-only with the
    /// same immutability and idempotency contract as `store`: re-storing
    /// identical content is an idempotent no-op, divergent content under an
    /// existing generation ID is typed corruption.
    ///
    /// Every provenance entry must reference an item the stream actually
    /// produced; the membership check runs against the streamed item set.
    pub fn store_streaming(
        &self,
        atlas_id: AtlasId,
        atlas_revision: Digest,
        embedding_model: &EmbeddingModelId,
        created_epoch: u64,
        chunks: &mut dyn Iterator<Item = BrainResult<IndexedChunk>>,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        ensure_nul_free(provenance)?;
        let stamp = seal::Stamp {
            atlas_id: &atlas_id,
            atlas_revision,
            embedding_model,
        };
        self.write_postgres(&stamp, created_epoch, chunks, provenance)
    }

    /// Builds the model-stamped twin of one stored lexical generation: the
    /// same chunks under a generation stamped with `embedding_model`, which
    /// the batch embedding backfill fills with a vector pool. The manifest
    /// is recomputed incrementally over the stored chunk identities (never
    /// their texts), so the result is deterministic and idempotent —
    /// re-restamping one source under one model always yields the same
    /// generation ID. An existing twin is verified and returned WITHOUT
    /// touching chunk rows, so resumed or budgeted backfills never collide
    /// on primary keys. The source generation header is verified first;
    /// item provenance rows are carried into the twin so provenance-bearing
    /// sources stay loadable.
    pub fn restamp_generation(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        created_epoch: u64,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        self.restamp_postgres(generation_id, embedding_model, created_epoch)
    }

    /// The number of chunks of one sealed generation; `None` when this
    /// store does not hold it. Used by the archive backfill to measure
    /// staged progress against the full pool.
    pub fn chunk_count(&self, generation_id: &IndexGenerationId) -> BrainResult<Option<u64>> {
        Ok(self
            .sealed_generation(generation_id)?
            .map(|(_, chunks)| chunks))
    }
}

/// Single construction point for typed store corruption errors.
pub(crate) fn corrupt(reason: impl Into<String>) -> BrainError {
    BrainError::Corrupt {
        component: BRAIN_INDEX_STORE,
        reason: reason.into(),
    }
}

fn parse_trust(value: &str) -> Option<TrustClass> {
    match value {
        "control" => Some(TrustClass::Control),
        "curated" => Some(TrustClass::Curated),
        "observed" => Some(TrustClass::Observed),
        "untrusted" => Some(TrustClass::Untrusted),
        _ => None,
    }
}

/// Parses a stored Atlas source class token.
fn parse_source_class(value: &str) -> Option<odin_atlas::SourceClass> {
    match value {
        "rust" => Some(odin_atlas::SourceClass::Rust),
        "typescript" => Some(odin_atlas::SourceClass::TypeScript),
        "registry" => Some(odin_atlas::SourceClass::Registry),
        "skeleton" => Some(odin_atlas::SourceClass::Skeleton),
        _ => None,
    }
}

/// Reconstructs and verifies one chunk row against its recorded identity.
pub(super) struct ChunkRow<'a> {
    atlas_id: &'a AtlasId,
    atlas_revision: Digest,
    chunk_id: &'a str,
    item_id: &'a str,
    trust: &'a str,
    digest: &'a str,
    text: &'a str,
    byte_start: i64,
    byte_end: i64,
}

pub(super) fn chunk_from_row(row: ChunkRow<'_>) -> BrainResult<IndexedChunk> {
    let ChunkRow {
        atlas_id,
        atlas_revision,
        chunk_id,
        item_id,
        trust,
        digest,
        text,
        byte_start,
        byte_end,
    } = row;
    let chunk_id =
        KnowledgeChunkId::parse(chunk_id).map_err(|error| corrupt(format!("chunk id: {error}")))?;
    let item_id = KnowledgeItemId::parse(item_id)
        .map_err(|error| corrupt(format!("chunk item id: {error}")))?;
    let digest =
        Digest::parse(digest).map_err(|error| corrupt(format!("chunk digest: {error}")))?;
    let trust = parse_trust(trust).ok_or_else(|| corrupt("chunk trust is not a known class"))?;
    let span = byte_end
        .checked_sub(byte_start)
        .filter(|span| *span > 0)
        .ok_or_else(|| corrupt("chunk citation byte range is not ordered"))?;
    // The citation range is ITEM-relative: its LENGTH must equal the stored
    // chunk text's byte length, not its absolute end. Comparing the absolute
    // end against the chunk text is wrong for every chunk after the first.
    if span as usize != text.len() {
        return Err(corrupt(
            "chunk citation span does not match its stored text length",
        ));
    }
    if digest != Digest::hash(text.as_bytes()) {
        return Err(corrupt("chunk content digest does not match stored text"));
    }
    let citation = Citation::new(odin_domain::knowledge::retrieval::CitationInit {
        source: atlas_id.clone(),
        source_revision: atlas_revision,
        item_id,
        fact_id: None,
        fact_revision: None,
        fact_origin: None,
        lineage: None,
        byte_start: byte_start as u64,
        byte_end: byte_end as u64,
    })?;
    Ok(IndexedChunk {
        item_id,
        chunk_id,
        trust,
        text: text.to_owned(),
        digest,
        citation,
    })
}
