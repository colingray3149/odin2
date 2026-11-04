//! The index store's generations in the brain's PostgreSQL store. A build
//! streams there directly (staged until its manifest names it), then —
//! inside one transaction under the generation's advisory lock — is read
//! back, hashed to its manifest, and only then sealed with its header.
//! Sealed generations are read from there; a retire releases this store's
//! hold. While a build streams, it holds its stage's session lock, so a
//! store that opens mid-build sweeps only stages whose owner is gone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeItemId, TokenizerId,
};
use odin_domain::knowledge::retrieval::{IndexGeneration, IndexedChunk};
use odin_domain::Digest;

use super::{
    chunk_from_row, corrupt, create_root, parse_source_class, ChunkRow, IndexStore, StoreOutcome,
};
use crate::context::tokenizer::PinnedTokenizer;
use crate::error::{BrainError, BrainResult, BRAIN_INDEX_STORE};
use crate::index::build::{trust_bytes, ManifestHasher, CHUNKER_VERSION, INDEX_TOKENIZER};
use crate::index::model::ItemProvenance;
use crate::index::postgres::{
    BrainPostgres, CitedRow, HeaderRow, ProvenanceRow, SealProof, SealRejection, SealWait,
};

/// Chunk rows staged, and provenance rows copied, per round trip.
const COPY_BATCH: i64 = 500;

/// Staged chunks moved into a generation per transaction: each passes the
/// `brain_search` trigger and its indexes, so a million-chunk archive moves
/// in bounded steps.
const PROMOTE_BATCH: i64 = 20_000;

/// What a generation is built from: its source revision and the embedding
/// model it is stamped with.
pub(super) struct Stamp<'a> {
    pub(super) atlas_id: &'a AtlasId,
    pub(super) atlas_revision: Digest,
    pub(super) embedding_model: &'a EmbeddingModelId,
}

/// A finished stage: the manifest its chunks hash to, their citation
/// offsets' digest, and how many there are.
struct Staged {
    manifest: Digest,
    offsets: Digest,
    count: i64,
}

impl IndexStore {
    /// Opens the store under `root` over the PostgreSQL store, which holds
    /// its whole index. Stages whose owner is gone — the session that
    /// built them ended, so Postgres released their lock — are dropped; a
    /// live build's stage (another process still holds its lock) stays.
    pub fn open(root: &Path, postgres: Arc<BrainPostgres>) -> BrainResult<Self> {
        create_root(root)?;
        let store = Self {
            root: root.to_path_buf(),
            postgres,
            sealed: Mutex::new(BTreeMap::new()),
        };
        let stages = format!("{}#", store.owner());
        if let Err(error) = store.postgres.sweep_dead_stages(&stages) {
            tracing::warn!(store = %root.display(), %error, "brain stages of an earlier run stay");
        }
        Ok(store)
    }

    /// Deletes the store under `root` (a retired seat's), releasing every
    /// hold it has on generations in `postgres` and dropping its stages
    /// first: no store will open this root again to sweep them.
    pub fn remove(root: &Path, postgres: &BrainPostgres) -> BrainResult<()> {
        let owner = root.display().to_string();
        for generation in postgres.held_by(&owner)? {
            postgres.release(&owner, &generation)?;
        }
        let stages = format!("{owner}#");
        if let Err(error) = postgres.drop_stages_under(&stages) {
            tracing::warn!(store = %root.display(), %error, "brain stages of a removed store stay");
        }
        std::fs::remove_dir_all(root).map_err(|error| BrainError::Unavailable {
            component: BRAIN_INDEX_STORE,
            reason: format!("cannot remove retired store {}: {error}", root.display()),
        })
    }

    pub(crate) fn postgres(&self) -> &BrainPostgres {
        &self.postgres
    }

    /// This store's key in `brain_generation`: its directory.
    pub(super) fn owner(&self) -> String {
        self.root.display().to_string()
    }

    fn cache(&self, generation: IndexGeneration, chunks: u64) -> BrainResult<()> {
        self.sealed
            .lock()
            .map_err(|error| corrupt(format!("sealed generation cache mutex: {error}")))?
            .insert(generation.generation_id, (generation, chunks));
        Ok(())
    }

    fn cached(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, u64)>> {
        Ok(self
            .sealed
            .lock()
            .map_err(|error| corrupt(format!("sealed generation cache mutex: {error}")))?
            .get(generation_id)
            .cloned())
    }

    /// The sealed header and chunk count of one generation, held by this
    /// store from now on. `None` while the generation is unsealed, or while another transaction holds the
    /// generation's advisory lock (a seal in flight), so a cold read never
    /// queues behind it.
    pub(super) fn sealed_generation(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, u64)>> {
        if let Some(cached) = self.cached(generation_id)? {
            return Ok(Some(cached));
        }
        let Some(row) = self
            .postgres
            .hold(&self.owner(), &generation_id.to_string())?
        else {
            return Ok(None);
        };
        let sealed = sealed_from(&row)?;
        self.cache(sealed.0.clone(), sealed.1)?;
        Ok(Some(sealed))
    }

    /// Why a serving generation holds no rows for an item: `Ok` when this
    /// store holds the generation (the item is simply not in it),
    /// corruption when it does not.
    pub fn require_generation(&self, generation_id: &IndexGenerationId) -> BrainResult<()> {
        if self.sealed_generation(generation_id)?.is_some() {
            return Ok(());
        }
        Err(corrupt(format!(
            "generation {generation_id} is serving but no store holds it"
        )))
    }

    /// The newest sealed generation of one source revision, stamped with
    /// `model` when given.
    pub(super) fn sealed_current(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<IndexGeneration>> {
        let Some((id, _)) = self.postgres.sealed_current(
            atlas_id.as_str(),
            &atlas_revision.to_string(),
            model.map(EmbeddingModelId::as_str),
        )?
        else {
            return Ok(None);
        };
        let id = IndexGenerationId::parse(&id)
            .map_err(|error| corrupt(format!("sealed generation id: {error}")))?;
        Ok(self
            .sealed_generation(&id)?
            .map(|(generation, _)| generation))
    }

    /// The sealed generations this store holds, of `atlas_id` when given
    /// (stamped with `model` when given), newest first.
    pub(super) fn held_generations(
        &self,
        atlas_id: Option<&AtlasId>,
        model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Vec<IndexGeneration>> {
        self.postgres
            .held_headers(
                &self.owner(),
                atlas_id.map(AtlasId::as_str),
                model.map(EmbeddingModelId::as_str),
            )?
            .iter()
            .map(|row| {
                let (generation, chunks) = sealed_from(row)?;
                self.cache(generation.clone(), chunks)?;
                Ok(generation)
            })
            .collect()
    }

    /// Writes one generation straight into the PostgreSQL store and seals
    /// it: the chunks stream into a stage while the manifest is hashed,
    /// move under the id the finished manifest names, and publish once the
    /// stored rows read back to that manifest. Insert-only and idempotent:
    /// a generation already sealed is `AlreadyPresent`, and one a
    /// concurrent build of the same content is sealing is left to it.
    pub(super) fn write_postgres(
        &self,
        stamp: &Stamp<'_>,
        created_epoch: u64,
        chunks: &mut dyn Iterator<Item = BrainResult<IndexedChunk>>,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        let postgres = self.postgres();
        let stage = format!("{}#{}", self.owner(), stage_nonce());
        // Taken before the first row lands and held until the stage goes:
        // another store's sweep must see this build as a live owner.
        let guard = postgres.stage_guard(&stage)?;
        let written = self
            .stage(&stage, stamp, chunks, provenance)
            .and_then(|staged| {
                let generation = IndexGeneration {
                    generation_id: IndexGenerationId::new(Digest::hash(staged.manifest.as_bytes())),
                    atlas_id: stamp.atlas_id.clone(),
                    atlas_revision: stamp.atlas_revision,
                    chunker_version: CHUNKER_VERSION.to_owned(),
                    tokenizer: PinnedTokenizer::id()?,
                    embedding_model: stamp.embedding_model.clone(),
                    manifest_digest: staged.manifest,
                };
                let outcome =
                    self.publish(&stage, &generation, &staged, created_epoch, provenance)?;
                Ok((generation, outcome))
            });
        let dropped = postgres.drop_stage(&stage);
        let written = written?;
        dropped?;
        drop(guard);
        Ok(written)
    }

    /// [`Self::restamp_generation`] over the PostgreSQL store: the sealed
    /// source's rows stream back through [`Self::write_postgres`] under
    /// the new model's stamp.
    pub(super) fn restamp_postgres(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        created_epoch: u64,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        let Some((source, _)) = self.sealed_generation(generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        if source.chunker_version != CHUNKER_VERSION || source.tokenizer.as_str() != INDEX_TOKENIZER
        {
            return Err(BrainError::StaleAuthority {
                authority: "index_generation",
                detail: format!(
                    "generation {generation_id} was chunked by {} with {}; this build chunks by \
                     {CHUNKER_VERSION} with {INDEX_TOKENIZER}, so rebuild it instead",
                    source.chunker_version, source.tokenizer
                ),
            });
        }
        let postgres = self.postgres();
        let id = generation_id.to_string();
        let provenance = provenance_map(postgres.provenance_rows(&id, None)?)?;
        let mut after = -1_i64;
        let mut batch = std::collections::VecDeque::new();
        let mut chunks = std::iter::from_fn(|| {
            if batch.is_empty() {
                match postgres.cited_after(&id, after, COPY_BATCH) {
                    Ok(rows) => batch.extend(rows),
                    Err(error) => return Some(Err(error)),
                }
            }
            let row = batch.pop_front()?;
            after = row.ordinal;
            Some(cited_chunk(&source, &row))
        });
        let stamp = Stamp {
            atlas_id: &source.atlas_id,
            atlas_revision: source.atlas_revision,
            embedding_model,
        };
        self.write_postgres(&stamp, created_epoch, &mut chunks, &provenance)
    }

    /// Streams `chunks` into `stage` while hashing what they make.
    fn stage(
        &self,
        stage: &str,
        stamp: &Stamp<'_>,
        chunks: &mut dyn Iterator<Item = BrainResult<IndexedChunk>>,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<Staged> {
        let postgres = self.postgres();
        let atlas_id = stamp.atlas_id;
        let mut hasher = ManifestHasher::new(
            atlas_id,
            &stamp.atlas_revision,
            CHUNKER_VERSION,
            INDEX_TOKENIZER,
            stamp.embedding_model.as_str(),
        );
        let mut offsets = OffsetHasher::default();
        let mut seen_items = BTreeSet::new();
        let mut batch = Vec::with_capacity(COPY_BATCH as usize);
        let mut count = 0_i64;
        for chunk in chunks {
            let chunk = chunk?;
            if &chunk.citation.source != atlas_id {
                return Err(BrainError::InvalidRequest(format!(
                    "chunk {} belongs to source {} but the generation pins {}",
                    chunk.chunk_id, chunk.citation.source, atlas_id
                )));
            }
            if chunk.citation.source_revision != stamp.atlas_revision {
                return Err(BrainError::InvalidRequest(format!(
                    "chunk {} was read from revision {} but the generation pins {}",
                    chunk.chunk_id, chunk.citation.source_revision, stamp.atlas_revision
                )));
            }
            hasher.push_chunk(&chunk);
            let (byte_start, byte_end) = (
                chunk.citation.byte_start as i64,
                chunk.citation.byte_end as i64,
            );
            offsets.push(count, byte_start, byte_end);
            seen_items.insert(chunk.item_id);
            batch.push(CitedRow {
                ordinal: count,
                chunk_id: chunk.chunk_id.to_string(),
                item: chunk.item_id.to_string(),
                trust: trust_bytes(chunk.trust).to_owned(),
                digest: chunk.digest.to_string(),
                text: chunk.text,
                byte_start,
                byte_end,
            });
            count += 1;
            if batch.len() == COPY_BATCH as usize {
                postgres.stage_chunks(stage, std::mem::take(&mut batch))?;
            }
        }
        if !batch.is_empty() {
            postgres.stage_chunks(stage, batch)?;
        }
        for (item_id, item_provenance) in provenance {
            if !seen_items.contains(item_id) {
                return Err(BrainError::InvalidRequest(format!(
                    "item {item_id} carries provenance but no indexed chunks"
                )));
            }
            hasher.push_provenance(item_id, item_provenance);
        }
        Ok(Staged {
            manifest: hasher.finish(),
            offsets: offsets.finish(),
            count,
        })
    }

    /// Moves a finished stage under `generation` and seals it.
    fn publish(
        &self,
        stage: &str,
        generation: &IndexGeneration,
        staged: &Staged,
        created_epoch: u64,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<StoreOutcome> {
        if self.sealed_generation(&generation.generation_id)?.is_some() {
            return Ok(StoreOutcome::AlreadyPresent);
        }
        let postgres = self.postgres();
        let id = generation.generation_id.to_string();
        // Held before the first row lands: a concurrent release refcounts
        // the write in flight instead of dropping its rows.
        postgres.claim(&self.owner(), &id)?;
        let published = self.copy_and_seal(stage, generation, staged, created_epoch, provenance);
        if let Err(error) = &published {
            // A copy or seal that failed (a timeout included) leaves nothing
            // behind: the claim goes, and the rows with it unless another
            // store holds them.
            if let Err(cleanup) = postgres.release(&self.owner(), &id) {
                tracing::warn!(generation = %id, "brain-seal failed ({error}) and its rows stay until the stale-claim sweep: {cleanup}");
            }
        }
        published
    }

    /// [`Self::publish`]'s copy and seal, under the store's claim.
    fn copy_and_seal(
        &self,
        stage: &str,
        generation: &IndexGeneration,
        staged: &Staged,
        created_epoch: u64,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<StoreOutcome> {
        let postgres = self.postgres();
        let count = staged.count;
        let id = generation.generation_id.to_string();
        let model = generation.embedding_model.as_str();
        let started = std::time::Instant::now();
        let closed = || -> BrainResult<StoreOutcome> {
            if self.sealed_generation(&generation.generation_id)?.is_some() {
                return Ok(StoreOutcome::AlreadyPresent);
            }
            tracing::warn!(generation = %id, "brain-seal deferred: a concurrent build holds it");
            Ok(StoreOutcome::Stored)
        };
        let mut after = -1_i64;
        while after + 1 < count {
            // Every window must hold every row this build staged into it —
            // `ON CONFLICT DO NOTHING` keeps a retried window a no-op — or
            // the stage went missing under the build, which fails it here
            // instead of letting the seal's proof find a shortfall.
            let expected = PROMOTE_BATCH.min(count - 1 - after);
            match postgres.promote_stage(stage, &id, model, after, PROMOTE_BATCH)? {
                Some(found) if found == expected => {}
                None => return closed(),
                Some(found) => {
                    return Err(BrainError::StageLost {
                        component: BRAIN_INDEX_STORE,
                        reason: format!(
                            "stage {stage} holds {found} of {expected} chunks at ordinals \
                             ({after}, {}]: its rows went missing under the build, so it \
                             cannot seal; the next build restages them",
                            after + expected
                        ),
                    });
                }
            }
            after += PROMOTE_BATCH;
        }
        let rows: Vec<_> = provenance
            .iter()
            .map(|(item_id, item)| (*item_id, item.clone()))
            .collect();
        for batch in rows.chunks(COPY_BATCH as usize) {
            if !postgres.copy_provenance(&id, provenance_rows(batch))? {
                return closed();
            }
        }
        let header = HeaderRow {
            generation_id: id.clone(),
            atlas_id: generation.atlas_id.as_str().to_owned(),
            atlas_revision: generation.atlas_revision.to_string(),
            chunker_version: generation.chunker_version.clone(),
            tokenizer: generation.tokenizer.as_str().to_owned(),
            embedding_model: model.to_owned(),
            manifest_digest: generation.manifest_digest.to_string(),
            created_epoch: created_epoch as i64,
            chunk_count: count,
        };
        let proof = ProofState::new(&header, staged.offsets)?;
        match postgres.seal(&self.owner(), header, COPY_BATCH, proof, SealWait::Try)? {
            Ok(()) => {
                self.cache(generation.clone(), count as u64)?;
                tracing::info!(
                    generation = %id,
                    chunks = count,
                    ms = started.elapsed().as_millis(),
                    "brain-seal done"
                );
                Ok(StoreOutcome::Stored)
            }
            Err(SealRejection::Rejected(reason)) => {
                Err(corrupt(format!("generation {id} was not sealed: {reason}")))
            }
            Err(SealRejection::Busy) => closed(),
        }
    }

    /// Drops day-old claims on generations that never sealed, and their
    /// rows.
    pub fn sweep_stale_claims(&self) -> BrainResult<usize> {
        self.postgres.sweep_stale_claims()
    }

    /// Of `unwired`, the generations of sources this store no longer wires,
    /// those unwired for at least `grace`. The marks live with the store's
    /// holds in Postgres.
    pub fn unwired_for(
        &self,
        unwired: &[IndexGenerationId],
        grace: std::time::Duration,
    ) -> BrainResult<Vec<IndexGenerationId>> {
        let marked = self.postgres.mark_unwired(
            &self.owner(),
            unwired.iter().map(ToString::to_string).collect(),
        )?;
        Ok(unwired
            .iter()
            .filter(|generation| {
                let id = generation.to_string();
                marked
                    .iter()
                    .any(|(marked, unwired_for)| *marked == id && *unwired_for >= grace)
            })
            .copied()
            .collect())
    }

    /// Releases this store's hold on a retired generation.
    pub(super) fn unseal(&self, generation_id: &IndexGenerationId) -> BrainResult<()> {
        self.sealed
            .lock()
            .map_err(|error| corrupt(format!("sealed generation cache mutex: {error}")))?
            .remove(generation_id);
        self.postgres
            .release(&self.owner(), &generation_id.to_string())
    }

    /// The chunks of a sealed generation at `ordinals`, in the order
    /// given; repeated ordinals repeat.
    pub(super) fn sealed_chunks_at(
        &self,
        generation: &IndexGeneration,
        ordinals: &[i64],
    ) -> BrainResult<Vec<IndexedChunk>> {
        let id = generation.generation_id.to_string();
        let found: BTreeMap<i64, CitedRow> = self
            .postgres
            .cited_at(&id, ordinals.to_vec())?
            .into_iter()
            .map(|row| (row.ordinal, row))
            .collect();
        ordinals
            .iter()
            .map(|ordinal| {
                let row = found.get(ordinal).ok_or_else(|| {
                    corrupt(format!("generation {id} has no chunk at ordinal {ordinal}"))
                })?;
                cited_chunk(generation, row)
            })
            .collect()
    }

    pub(super) fn sealed_ordinals(
        &self,
        generation_id: &IndexGenerationId,
        items: &BTreeSet<KnowledgeItemId>,
    ) -> BrainResult<Vec<i64>> {
        self.postgres.item_ordinals(
            &generation_id.to_string(),
            items.iter().map(ToString::to_string).collect(),
        )
    }

    pub(super) fn sealed_provenance(
        &self,
        generation_id: &IndexGenerationId,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ItemProvenance>> {
        let postgres = self.postgres();
        let (id, item) = (generation_id.to_string(), item_id.to_string());
        if !postgres.has_item(&id, &item)? {
            return Err(BrainError::NotFound {
                kind: "knowledge item",
                id: item,
            });
        }
        let rows = postgres.provenance_rows(&id, Some(item))?;
        Ok(provenance_map(rows)?.remove(item_id))
    }
}

/// Validates contiguous ordinals, chunk text/digests/spans, citation
/// offsets, manifest identity/provenance, and copied row counts before publication.
struct ProofState {
    generation: IndexGeneration,
    expected: i64,
    hasher: ManifestHasher,
    /// The canonical citation-offsets digest of the staged rows: the
    /// read-back offsets must hash to it, so a copied citation
    /// shifted to another span is refused even though its text, digest,
    /// and chunk identity all still match.
    offsets: Digest,
    offset_hasher: OffsetHasher,
    next: i64,
}

impl ProofState {
    fn new(header: &HeaderRow, offsets: Digest) -> BrainResult<Self> {
        let (generation, chunks) = sealed_from(header)?;
        Ok(Self {
            hasher: ManifestHasher::new(
                &generation.atlas_id,
                &generation.atlas_revision,
                &generation.chunker_version,
                generation.tokenizer.as_str(),
                generation.embedding_model.as_str(),
            ),
            expected: i64::try_from(chunks)
                .map_err(|error| corrupt(format!("sealed chunk count is negative: {error}")))?,
            generation,
            offsets,
            offset_hasher: OffsetHasher::default(),
            next: 0,
        })
    }
}

impl SealProof for ProofState {
    fn feed_chunks(&mut self, rows: Vec<CitedRow>) -> Result<(), String> {
        for row in rows {
            if row.ordinal != self.next {
                return Err(format!("chunk {} is missing", self.next));
            }
            match cited_chunk(&self.generation, &row) {
                Ok(chunk) => self.hasher.push_chunk(&chunk),
                Err(BrainError::Corrupt { reason, .. }) => return Err(reason),
                Err(error) => return Err(error.to_string()),
            }
            self.offset_hasher
                .push(row.ordinal, row.byte_start, row.byte_end);
            self.next += 1;
        }
        Ok(())
    }

    fn feed_provenance(&mut self, rows: Vec<ProvenanceRow>) -> Result<(), String> {
        for row in rows {
            match provenance_item(row) {
                Ok((item_id, item)) => self.hasher.push_provenance(&item_id, &item),
                Err(BrainError::Corrupt { reason, .. }) => return Err(reason),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<(), String> {
        if self.next != self.expected {
            return Err(format!(
                "{} of {} chunks are stored",
                self.next, self.expected
            ));
        }
        if self.offset_hasher.finish() != self.offsets {
            return Err(
                "stored citation offsets do not match the generation's citation offsets".to_owned(),
            );
        }
        if self.hasher.finish() != self.generation.manifest_digest {
            return Err("stored rows do not hash to the manifest digest".to_owned());
        }
        Ok(())
    }
}

fn cited_chunk(generation: &IndexGeneration, row: &CitedRow) -> BrainResult<IndexedChunk> {
    chunk_from_row(ChunkRow {
        atlas_id: &generation.atlas_id,
        atlas_revision: generation.atlas_revision,
        chunk_id: &row.chunk_id,
        item_id: &row.item,
        trust: &row.trust,
        digest: &row.digest,
        text: &row.text,
        byte_start: row.byte_start,
        byte_end: row.byte_end,
    })
}

/// A stored header as a verified generation and its chunk count.
fn sealed_from(row: &HeaderRow) -> BrainResult<(IndexGeneration, u64)> {
    let generation_id = IndexGenerationId::parse(&row.generation_id)
        .map_err(|error| corrupt(format!("sealed generation id: {error}")))?;
    let manifest_digest = Digest::parse(&row.manifest_digest)
        .map_err(|error| corrupt(format!("sealed manifest digest: {error}")))?;
    if generation_id.as_digest() != &Digest::hash(manifest_digest.as_bytes()) {
        return Err(corrupt(
            "sealed generation id does not cover its manifest digest",
        ));
    }
    let generation = IndexGeneration {
        generation_id,
        atlas_id: AtlasId::new(row.atlas_id.clone())
            .map_err(|error| corrupt(format!("sealed atlas id: {error}")))?,
        atlas_revision: Digest::parse(&row.atlas_revision)
            .map_err(|error| corrupt(format!("sealed atlas revision: {error}")))?,
        chunker_version: row.chunker_version.clone(),
        tokenizer: TokenizerId::new(row.tokenizer.clone())
            .map_err(|error| corrupt(format!("sealed tokenizer id: {error}")))?,
        embedding_model: EmbeddingModelId::new(row.embedding_model.clone())
            .map_err(|error| corrupt(format!("sealed embedding model id: {error}")))?,
        manifest_digest,
    };
    let chunks = u64::try_from(row.chunk_count)
        .map_err(|error| corrupt(format!("sealed chunk count is negative: {error}")))?;
    Ok((generation, chunks))
}

fn provenance_rows(rows: &[(KnowledgeItemId, ItemProvenance)]) -> Vec<ProvenanceRow> {
    rows.iter()
        .map(|(item_id, item)| ProvenanceRow {
            item_id: item_id.to_string(),
            node_id: item.node_id.clone(),
            path: item.path.clone(),
            source_class: item.source_class.as_str().to_owned(),
            scope_tags: item.scope_tags.clone(),
        })
        .collect()
}

fn provenance_item(row: ProvenanceRow) -> BrainResult<(KnowledgeItemId, ItemProvenance)> {
    let item_id = KnowledgeItemId::parse(&row.item_id)
        .map_err(|error| corrupt(format!("provenance item id: {error}")))?;
    let source_class = parse_source_class(&row.source_class)
        .ok_or_else(|| corrupt("provenance source class is not a known class"))?;
    Ok((
        item_id,
        ItemProvenance {
            node_id: row.node_id,
            path: row.path,
            source_class,
            scope_tags: row.scope_tags,
        },
    ))
}

fn provenance_map(
    rows: Vec<ProvenanceRow>,
) -> BrainResult<BTreeMap<KnowledgeItemId, ItemProvenance>> {
    rows.into_iter().map(provenance_item).collect()
}

/// Hashes big-endian citation spans in ordinal order identically for staging
/// and read-back validation; this digest is not part of the manifest or generation ID.
#[derive(Default)]
struct OffsetHasher(blake3::Hasher);

impl OffsetHasher {
    fn push(&mut self, ordinal: i64, byte_start: i64, byte_end: i64) {
        self.0.update(&ordinal.to_be_bytes());
        self.0.update(&byte_start.to_be_bytes());
        self.0.update(&byte_end.to_be_bytes());
    }

    fn finish(self) -> Digest {
        Digest::from_bytes(*self.0.finalize().as_bytes())
    }
}

/// A stage name no other build of this store shares.
fn stage_nonce() -> String {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let next = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{at}-{next}", std::process::id())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use odin_domain::knowledge::retrieval::TrustClass;

    use super::*;
    use crate::index::build::{build_index, Chunker, IndexBuild};
    use crate::source::SourceItem;
    use crate::test_cluster::TestCluster;

    fn build(texts: &[&str]) -> IndexBuild {
        let (source, revision) = (AtlasId::new("atlas:seal").unwrap(), Digest::hash(b"r1"));
        let items: Vec<SourceItem> = texts
            .iter()
            .map(|text| {
                SourceItem::new(
                    source.clone(),
                    revision,
                    text.as_bytes(),
                    TrustClass::Curated,
                    *text,
                )
                .unwrap()
            })
            .collect();
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        build_index(source, revision, &items, &chunker).unwrap()
    }

    #[test]
    fn a_build_is_written_straight_to_postgres_and_serves_from_there() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = tempfile::tempdir().unwrap();
        let store = IndexStore::open(root.path(), Arc::clone(&postgres)).unwrap();
        let build = build(&["alpha beta gamma delta", "epsilon zeta eta theta"]);
        let generation = build.generation.clone();
        let id = generation.generation_id;

        assert_eq!(store.store(&build, 7).unwrap(), StoreOutcome::Stored);
        assert_eq!(
            cluster.sql("SELECT count(*) FROM brain_generation_header"),
            "1"
        );
        assert_eq!(cluster.sql("SELECT count(*) FROM brain_chunk_stage"), "0");
        let served = store.chunks_at(&id, &[2, 0]).unwrap();
        assert_eq!(
            served,
            vec![build.chunks[2].clone(), build.chunks[0].clone()]
        );
        assert_eq!(
            store
                .current(&generation.atlas_id, &generation.atlas_revision)
                .unwrap(),
            Some(generation.clone())
        );
        assert_eq!(
            store.newest(&generation.atlas_id, None).unwrap(),
            Some(generation.clone())
        );
        assert_eq!(
            store.chunk_count(&id).unwrap(),
            Some(build.chunks.len() as u64)
        );
        let item = build.chunks[0].item_id;
        assert!(store
            .ordinals_for_items(&id, &BTreeSet::from([item]))
            .unwrap()
            .contains(&0));
        assert_eq!(store.provenance(&id, &item).unwrap(), None);

        // A second store of the same content shares the sealed rows.
        let other_root = tempfile::tempdir().unwrap();
        let other = IndexStore::open(other_root.path(), Arc::clone(&postgres)).unwrap();
        assert_eq!(
            other.store(&build, 8).unwrap(),
            StoreOutcome::AlreadyPresent
        );
        assert!(other.retire(&id).unwrap());
        assert_eq!(
            store.chunks_at(&id, &[0]).unwrap(),
            vec![build.chunks[0].clone()]
        );
        assert!(store.retire(&id).unwrap());
        assert_eq!(cluster.sql("SELECT count(*) FROM brain_chunk"), "0");
    }

    /// The generation a finished stage names, as `write_postgres` builds it.
    fn generation_of(stamp: &Stamp<'_>, staged: &Staged) -> IndexGeneration {
        IndexGeneration {
            generation_id: IndexGenerationId::new(Digest::hash(staged.manifest.as_bytes())),
            atlas_id: stamp.atlas_id.clone(),
            atlas_revision: stamp.atlas_revision,
            chunker_version: CHUNKER_VERSION.to_owned(),
            tokenizer: PinnedTokenizer::id().unwrap(),
            embedding_model: stamp.embedding_model.clone(),
            manifest_digest: staged.manifest,
        }
    }

    #[test]
    fn a_live_builds_stage_survives_another_store_open_and_seals() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = tempfile::tempdir().unwrap();
        let store = IndexStore::open(root.path(), Arc::clone(&postgres)).unwrap();
        let build = build(&["alpha beta gamma delta", "epsilon zeta eta theta"]);
        let stamp = Stamp {
            atlas_id: &build.generation.atlas_id,
            atlas_revision: build.generation.atlas_revision,
            embedding_model: &build.generation.embedding_model,
        };
        let stage = format!("{}#{}", store.owner(), "live-build");
        let guard = postgres.stage_guard(&stage).unwrap();
        let staged = store
            .stage(
                &stage,
                &stamp,
                &mut build.chunks.iter().cloned().map(Ok),
                &build.provenance,
            )
            .unwrap();
        assert_eq!(staged.count, build.chunks.len() as i64);

        // Another process's open on the same root (an odind restart, an
        // archive subprocess) must leave a live build's stage alone: its
        // owner still holds the session lock.
        for _ in 0..3 {
            let opener = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
            IndexStore::open(root.path(), opener).unwrap();
            assert_eq!(
                cluster.sql("SELECT count(*) FROM brain_chunk_stage"),
                staged.count.to_string(),
                "a live build's stage must survive another store's open"
            );
        }

        // The build those opens left alone still seals from its stage.
        let generation = generation_of(&stamp, &staged);
        assert_eq!(
            store
                .publish(&stage, &generation, &staged, 7, &build.provenance)
                .unwrap(),
            StoreOutcome::Stored
        );

        // The owner gone, what it left behind is reclaimable: publish does
        // not drop the stage, a crash before that drop would not either.
        drop(guard);
        let opener = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        IndexStore::open(root.path(), opener).unwrap();
        assert_eq!(
            cluster.sql("SELECT count(*) FROM brain_chunk_stage"),
            "0",
            "a dead owner's stage is reclaimed by the next open"
        );
    }

    #[test]
    fn a_stage_whose_rows_were_altered_never_seals() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = tempfile::tempdir().unwrap();
        let store = IndexStore::open(root.path(), Arc::clone(&postgres)).unwrap();
        let build = build(&["alpha beta gamma delta", "epsilon zeta eta theta"]);
        let stamp = Stamp {
            atlas_id: &build.generation.atlas_id,
            atlas_revision: build.generation.atlas_revision,
            embedding_model: &build.generation.embedding_model,
        };
        let stage = format!("{}#{}", store.owner(), "altered");
        let staged = store
            .stage(
                &stage,
                &stamp,
                &mut build.chunks.iter().cloned().map(Ok),
                &build.provenance,
            )
            .unwrap();
        cluster.sql("UPDATE brain_chunk_stage SET byte_end = byte_end + 1 WHERE ordinal = 0");
        let refused = store.publish(
            &stage,
            &generation_of(&stamp, &staged),
            &staged,
            7,
            &build.provenance,
        );
        assert!(
            matches!(refused, Err(BrainError::Corrupt { .. })),
            "{refused:?}"
        );
        assert_eq!(
            cluster.sql("SELECT count(*) FROM brain_generation_header"),
            "0",
            "an altered build leaves no sealed header"
        );
    }
}
