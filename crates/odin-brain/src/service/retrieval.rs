//! Scoped retrieval over the newest sealed generation of every source in the
//! request's authorized serving scope, and the background warm round that
//! builds, seals, embeds and retires those generations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::ids::EmbeddingModelId;
use odin_domain::knowledge::{
    AtlasId, IndexGeneration, IndexedChunk, KnowledgeChunkId, KnowledgeItemId, RelevanceScore,
    RetrievalHit, RetrievalMode, RetrievalQuery,
};
use odin_domain::{Digest, ProjectId};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::archive::store::{ArchiveIdentity, MAX_IDENTITY_PAGES, MAX_IDENTITY_RECORDS};
use crate::error::{BrainError, BrainResult};
use crate::retrieval::compact::CompactIndex;
use crate::retrieval::embedding::EmbeddingVector;
use crate::retrieval::identity::identity_literals;
use crate::retrieval::query::validate_embedding_binding;
use crate::retrieval::{embed_one, QueryEmbedder, RetrievalPlan, Retriever};
use crate::source::archive::ArchiveRecordKind;

use super::authority::{pin_all, PinnedSource};
use super::BrainService;

mod postgres;

/// One published archive record a turn's exact identity constraints address.
/// A segmented record is ONE logical record carried by several part items, so
/// the addressed content is the union of their chunks.
#[derive(Clone, Debug)]
struct AddressedRecord {
    source: AtlasId,
    item_ids: BTreeSet<KnowledgeItemId>,
}

/// The logical record one identity row belongs to: a segmented part's key is
/// its record's key with the `:part:<n>` suffix removed, so every part of one
/// logical record groups together.
fn logical_key(identity: &ArchiveIdentity) -> &str {
    match identity.part_index {
        Some(_) => identity
            .natural_key
            .rsplit_once(":part:")
            .map(|(key, _)| key)
            .unwrap_or(identity.natural_key.as_str()),
        None => identity.natural_key.as_str(),
    }
}

/// How one turn's exact identity constraints resolved.
#[derive(Clone, Debug)]
enum AddressResolution {
    /// The query names no published record: the ordinary pool serves.
    None,
    /// The query names exactly one published record coherently.
    Addressed(AddressedRecord),
    /// The query names a record incoherently — several candidates, a
    /// contradicted conversation or instant, or a lookup too saturated to
    /// decide. Nothing may be served as if it were the record asked for.
    Unresolved,
}

/// Uncached chunks one retrieval may embed inline; larger new generations
/// serve their lexical leg while [`BrainService::warm_vectors`] finishes them
/// in the background.
const LAZY_EMBED_BUDGET: usize = 32;

/// Compact vector indexes kept per service.
const MAX_COMPACT_INDEXES: usize = 16;

/// Largest live generation whose vector pool a turn may complete inline.
const INLINE_POOL_CHUNKS: usize = 512;

/// Whether a turn may build a missing compact vector index inline: a small
/// generation always; a large one only when the turn has no lexical leg to
/// serve meanwhile (a non-hybrid policy).
fn inline_compact_allowed(chunks: usize, lexical_fallback: bool) -> bool {
    !lexical_fallback || chunks <= INLINE_POOL_CHUNKS
}

/// The provider name typed vector-leg failures carry.
const EMBEDDING_LEG: &str = "odin.retrieval.embedding";

/// The posture one retrieval actually served under. The lexical-only
/// promise is explicit: a typed lane unavailability degrades ONLY Hybrid
/// plans to their lexical leg, reported here — never silently, never for
/// Vector plans, and never for any other failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetrievalPosture {
    /// The plan ran complete: a lexical plan, or a hybrid/vector plan with
    /// a usable pool or lane.
    Full,
    /// The vector leg did not run: lexical candidates were served instead
    /// and the unserved chunks await embedding through the declared
    /// gateway lane (observable via `archive_status` for archive sources).
    /// Produced only for Hybrid plans under a typed
    /// [`BrainError::EmbeddingUnavailable`], or for a lexical-only archive
    /// generation; Vector plans and every other error stay
    /// typed-unavailable.
    LexicalOnly {
        /// Why the vector leg did not run.
        reason: String,
    },
}

/// The outcome of one posture-aware retrieval.
#[derive(Clone, Debug)]
pub struct RetrievalResponse {
    pub hits: Vec<RetrievalHit>,
    pub posture: RetrievalPosture,
}

impl BrainService {
    /// Runs retrieval for one query under the resolved knowledge policy. The
    /// candidate pool merges, for every requested source the bound project's
    /// serving scope authorizes, the generation of its current head when
    /// sealed, else the newest sealed one; a source with none serves nothing
    /// this turn. `embedder` is the caller's session-bound kernel executor;
    /// it is required only when the resolved plan executes embeddings.
    ///
    /// A query that exactly addresses one published archive record — quoting
    /// its message id, thread id, or natural key, with any conversation and
    /// timestamp it also quotes agreeing — serves that record's content
    /// (`resolve_addressed_record`); every other query serves the ordinary
    /// merged pool.
    ///
    /// The posture is never silent: a Hybrid plan under a typed
    /// [`BrainError::EmbeddingUnavailable`] (or a Hybrid plan over a
    /// lexical-only archive generation) serves its lexical leg as
    /// [`RetrievalPosture::LexicalOnly`] with the reason; Vector plans and
    /// every other failure stay typed-unavailable and propagate. Every
    /// consumer receives the posture — there is no posture-dropping
    /// variant.
    pub fn retrieve(
        &self,
        query: &RetrievalQuery,
        project: Option<&ProjectId>,
        embedder: Option<&Arc<QueryEmbedder>>,
    ) -> BrainResult<RetrievalResponse> {
        let (hits, posture) = self.retrieve_scoped(query, project, None, embedder, None)?;
        Ok(RetrievalResponse { hits, posture })
    }

    /// [`BrainService::retrieve`] with an explicit serving scope:
    /// `Some(sources)` restricts served chunks to that set; `None` falls
    /// back to the query's own source set. Either is intersected with the
    /// bound project's serving authority before anything is pinned.
    pub(crate) fn retrieve_scoped(
        &self,
        query: &RetrievalQuery,
        project: Option<&ProjectId>,
        scope: Option<&BTreeSet<AtlasId>>,
        embedder: Option<&Arc<QueryEmbedder>>,
        mode: Option<RetrievalMode>,
    ) -> BrainResult<(Vec<RetrievalHit>, RetrievalPosture)> {
        let knowledge = self
            .policy
            .knowledge
            .as_ref()
            .ok_or_else(|| BrainError::Unavailable {
                component: "retrieval",
                reason: "the resolved policy does not enable knowledge retrieval".to_owned(),
            })?;
        // The serving scope rules EVERY surface of this request, and it is
        // decided before any source is pinned or built: the request (or the
        // caller's explicit scope) intersected with the policy's serving
        // authority for the bound project. A project-bound session serves
        // only general knowledge plus exactly its declared project memory; a
        // projectless one never serves project memory; a query naming its
        // own sources serves at most those. A source outside the scope is
        // never pinned, so its outage cannot fail this request, while a
        // requested, authorized source that cannot be pinned still fails it
        // typed.
        let authorized = self.policy.project_serving_scope(project);
        let scoped: BTreeSet<AtlasId> = scope
            .unwrap_or(&query.sources)
            .intersection(&authorized)
            .cloned()
            .collect();
        let serving_scope: &BTreeSet<AtlasId> = &scoped;
        let pinned_sources = self.pin_scoped(serving_scope)?;
        let mut generations: Vec<(AtlasId, IndexGeneration)> =
            Vec::with_capacity(pinned_sources.len());
        let mut visible_items = BTreeSet::new();
        // Archive pins have no live items; track their published chunks by source instead.
        let mut archive_sources = BTreeSet::new();
        for pinned in &pinned_sources {
            if pinned.generation.is_some() {
                archive_sources.insert(pinned.id.clone());
            }
            visible_items.extend(
                pinned
                    .items
                    .iter()
                    .filter(|item| self.item_visible(item, project))
                    .map(|item| item.item_id),
            );
            // Archive sources pin the publication's exact generation.
            let generation = match &pinned.generation {
                Some(generation_id) => {
                    self.index
                        .load_pinned(generation_id, &pinned.id, &pinned.revision)?
                }
                None => match self.serving_generation(pinned)? {
                    Some(generation) => generation,
                    None => {
                        tracing::debug!(
                            source = pinned.id.as_str(),
                            "brain-retrieval source has no sealed generation yet"
                        );
                        continue;
                    }
                },
            };
            generations.push((pinned.id.clone(), generation));
        }
        // The retriever is constructed per request over request-local state:
        // the plan derives from the knowledge policy (retrieval mode plus the
        // policy-resolved query), while chunks and their generation-bound
        // vector pools come from the generations pinned to the live heads
        // resolved above. The index generations are disposable; nothing
        // retriever-shaped is stored across requests.
        let resolved = knowledge.retrieval_query(query.text.clone())?;
        let mode = mode.unwrap_or(knowledge.retrieval_mode);
        let plan = RetrievalPlan::new(resolved, mode);
        // Defense in depth: the open-time and replace-time rejections hold
        // here too, before any vector pool load or executor call. A partial
        // binding never reaches embedding execution, and a vector/hybrid
        // query can never resolve to an empty success or a hybrid downgrade
        // through it.
        validate_embedding_binding(
            Some(mode),
            embedder.is_some(),
            self.config.embedding_model.is_some(),
        )?;
        // A query can ADDRESS a record instead of describing content: the
        // identity it quotes matches no indexed body text (identity lives in
        // the record's own columns), so resolving it here is the only path
        // from such a question to the content it asks about.
        let addressed =
            match self.resolve_addressed_record(&query.text, &pinned_sources, serving_scope)? {
                AddressResolution::Addressed(record) => Some(record),
                AddressResolution::None => None,
                AddressResolution::Unresolved => {
                    // An explicitly named record that cannot be resolved
                    // coherently serves NOTHING: unrelated memory must never be
                    // served as if it were the record asked for. The renderer
                    // states the empty result.
                    return Ok((Vec::new(), RetrievalPosture::Full));
                }
            };
        // Sources pinned to an exact published generation are archives;
        // the lexical-only archive posture applies only to them. Every
        // other source keeps the existing vector contract untouched.
        let archive_sources: BTreeSet<AtlasId> = pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_some())
            .map(|pinned| pinned.id.clone())
            .collect();
        let mut turn = postgres::PostgresTurn {
            plan,
            generations: generations
                .into_iter()
                .map(|(_, generation)| generation)
                .collect(),
            pinned: &pinned_sources,
            project,
            visible_items: &visible_items,
            archive_sources: &archive_sources,
            serving_scope,
            addressed: addressed.as_ref(),
            embedder,
        };
        if self.index.postgres().is_some() {
            turn.generations
                .retain(|generation| serving_scope.contains(&generation.atlas_id));
            if let Some(record) = turn.addressed {
                turn.generations
                    .retain(|generation| generation.atlas_id == record.source);
            }
            return self.retrieve_postgres(&turn);
        }
        self.retrieve_sqlite_turn(&turn)
    }

    /// The generation a turn serves for one live source: the one built for
    /// its current head when sealed, else the newest sealed one the pumps
    /// built — a turn never builds for a moved head. Without a PostgreSQL
    /// store, where SQLite serves, the first turn builds a source that has
    /// no generation at all.
    pub(super) fn serving_generation(
        &self,
        pinned: &PinnedSource,
    ) -> BrainResult<Option<IndexGeneration>> {
        let model = self.config.embedding_model.as_ref();
        if let Some(generation) =
            self.index
                .current_for_model(&pinned.id, &pinned.revision, model)?
        {
            if self.index.servable(&generation.generation_id)? {
                return Ok(Some(generation));
            }
        }
        if let Some(generation) = self.index.newest(&pinned.id, model, true)? {
            return Ok(Some(generation));
        }
        if self.index.postgres().is_some() {
            return Ok(None);
        }
        Ok(self
            .build_generations(std::slice::from_ref(pinned))?
            .into_iter()
            .next())
    }

    /// Pins exactly the composed sources of `scope`, sorted by source
    /// identity. A source in scope that cannot be pinned (unreadable root,
    /// vault unreachable) fails the request typed; an id this service does
    /// not compose, or an archive with no approved publication, pins nothing.
    fn pin_scoped(&self, scope: &BTreeSet<AtlasId>) -> BrainResult<Vec<PinnedSource>> {
        let mut pinned = Vec::with_capacity(scope.len());
        for id in scope {
            let Some(source) = self.sources.get(id) else {
                continue;
            };
            if let Some(head) = source.pin(self.archives.as_ref())? {
                pinned.push(head);
            }
        }
        Ok(pinned)
    }

    /// The turn over the SQLite index pools, for a service without a
    /// PostgreSQL store: candidates are nominated per generation from its
    /// persistent lexical index and compact vector index, then fused and
    /// ranked.
    fn retrieve_sqlite_turn(
        &self,
        turn: &postgres::PostgresTurn<'_>,
    ) -> BrainResult<(Vec<RetrievalHit>, RetrievalPosture)> {
        let plan = turn.plan.clone();
        let mut posture = RetrievalPosture::Full;
        // The query is embedded once, and only when some generation has a
        // vector index to nominate from — a turn over lexical-only sources
        // never spends an embedding on it.
        let mut query_embedding: Option<EmbeddingVector> = None;
        let nominate = usize::from(plan.query().candidate_limit.get());
        let lexical_leg = matches!(plan.mode(), RetrievalMode::Lexical | RetrievalMode::Hybrid);
        let query_terms = if lexical_leg {
            Some(crate::index::lexical::query_terms(plan.query())?)
        } else {
            None
        };
        // BM25 statistics of the served union: scores stay comparable
        // across sources exactly as one pooled index would make them.
        let mut union_stats = crate::index::lexical::CorpusStats::default();
        let mut chunks: Vec<IndexedChunk> = Vec::new();
        let mut vectors: BTreeMap<KnowledgeChunkId, EmbeddingVector> = BTreeMap::new();
        let mut timing = PhaseTiming::default();
        let started = std::time::Instant::now();
        for generation in &turn.generations {
            let source_id = &generation.atlas_id;
            // An addressed turn serves one record: no other source is read.
            let addressed_here = match turn.addressed {
                Some(addressed) if addressed.source != *source_id => continue,
                Some(addressed) => Some(addressed),
                None => None,
            };
            if !turn.serving_scope.contains(source_id) {
                continue;
            }
            let archive = turn.archive_sources.contains(source_id);
            let generation_id = &generation.generation_id;
            // Candidates are nominated from the generation's own indexes —
            // its persistent BM25 table and its compact vector index — never
            // by loading the whole generation: a turn costs the same whether
            // the source holds a hundred chunks or Colin's entire history.
            let mut nominated: BTreeSet<i64> = BTreeSet::new();
            if let Some(addressed) = addressed_here {
                nominated.extend(
                    self.index
                        .ordinals_for_items(generation_id, &addressed.item_ids)?,
                );
            }
            timing.sources += 1;
            let mark = std::time::Instant::now();
            if let Some(query_terms) = query_terms.as_ref() {
                let candidates = addressed_here.is_none().then(|| (plan.query(), nominate));
                let read = || {
                    self.index.generation_lexical_read(
                        generation_id,
                        query_terms,
                        candidates,
                        |item| archive || turn.visible_items.contains(item),
                    )
                };
                // Not ready, or evicted by another build since it was: build
                // it and read again, once.
                let (stats, lexical) = match read()? {
                    Some(read) => read,
                    None => {
                        self.index.build_generation_lexical(generation_id)?;
                        read()?.ok_or_else(|| BrainError::StaleAuthority {
                            authority: "lexical_index",
                            detail: format!(
                                "generation {generation_id} lost its lexical index again \
                                 right after it was built"
                            ),
                        })?
                    }
                };
                union_stats.add(&stats);
                nominated.extend(lexical);
            }
            timing.lexical += mark.elapsed();
            let mark = std::time::Instant::now();
            let compact = match turn.embedder {
                Some(embed)
                    if plan.requires_embeddings()
                        && !matches!(posture, RetrievalPosture::LexicalOnly { .. }) =>
                {
                    match self.vector_index(
                        generation,
                        archive,
                        embed.as_ref(),
                        plan.mode() == RetrievalMode::Hybrid,
                    )? {
                        Ok(compact) => compact,
                        Err(reason) if plan.mode() == RetrievalMode::Hybrid => {
                            posture = RetrievalPosture::LexicalOnly { reason };
                            None
                        }
                        Err(reason) => {
                            return Err(BrainError::EmbeddingUnavailable {
                                provider: EMBEDDING_LEG.to_owned(),
                                reason,
                            })
                        }
                    }
                }
                _ => None,
            };
            timing.vector_load += mark.elapsed();
            let mark = std::time::Instant::now();
            if let (Some(embed), Some(_)) = (turn.embedder, compact.as_ref()) {
                if query_embedding.is_none() {
                    match embed_one(embed.as_ref(), &plan.query().text) {
                        Ok(vector) => query_embedding = Some(vector),
                        Err(BrainError::EmbeddingUnavailable { reason, .. })
                            if plan.mode() == RetrievalMode::Hybrid =>
                        {
                            posture = RetrievalPosture::LexicalOnly { reason };
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            timing.embed += mark.elapsed();
            let mark = std::time::Instant::now();
            if let (Some(query_vector), Some(compact), None) =
                (query_embedding.as_ref(), compact.as_ref(), addressed_here)
            {
                nominated.extend(compact.nearest(query_vector.dims(), nominate, |item| {
                    archive || turn.visible_items.contains(item)
                }));
            }
            timing.nearest += mark.elapsed();
            let mark = std::time::Instant::now();
            let ordinals: Vec<i64> = nominated.into_iter().collect();
            let mut kept: Vec<(i64, IndexedChunk)> = Vec::new();
            for (ordinal, chunk) in ordinals
                .iter()
                .copied()
                .zip(self.index.chunks_at(generation_id, &ordinals)?)
            {
                let visible = turn.archive_sources.contains(&chunk.citation.source)
                    || turn.visible_items.contains(&chunk.item_id);
                let in_record = addressed_here
                    .is_none_or(|addressed| addressed.item_ids.contains(&chunk.citation.item_id));
                if turn.serving_scope.contains(&chunk.citation.source) && visible && in_record {
                    kept.push((ordinal, chunk));
                }
            }
            if compact.is_some() {
                // The exact full-dimension vectors of the candidates only.
                let wanted: Vec<i64> = kept.iter().map(|(ordinal, _)| *ordinal).collect();
                let stored: BTreeMap<i64, EmbeddingVector> = self
                    .index
                    .vectors_at(generation_id, &wanted)?
                    .into_iter()
                    .collect();
                for (ordinal, chunk) in &kept {
                    if let Some(vector) = stored.get(ordinal) {
                        vectors.insert(chunk.chunk_id, vector.clone());
                    }
                }
            }
            timing.fetch += mark.elapsed();
            chunks.extend(kept.into_iter().map(|(_, chunk)| chunk));
        }
        timing.log(started.elapsed(), chunks.len());
        let mut lexical_scores: BTreeMap<KnowledgeChunkId, RelevanceScore> = BTreeMap::new();
        if let Some(query_terms) = query_terms.as_ref() {
            for chunk in &chunks {
                if let Some(score) =
                    crate::index::lexical::bm25(&union_stats, query_terms, &chunk.text)?
                {
                    lexical_scores.insert(chunk.chunk_id, score);
                }
            }
        }
        chunks.sort_by_key(|left| left.chunk_id);
        // A degraded posture serves the lexical leg explicitly: the plan is
        // rebuilt as lexical so the retriever ranks the candidates it
        // actually has. The reported posture carries the reason — this is
        // a declared partial result, never a silent downgrade.
        let plan = if matches!(posture, RetrievalPosture::LexicalOnly { .. }) {
            RetrievalPlan::new(plan.query().clone(), RetrievalMode::Lexical)
        } else {
            plan
        };
        let mut retriever = Retriever::new(plan, &chunks, &vectors, &lexical_scores);
        if let Some(executor) = turn.embedder {
            retriever = retriever.with_executor(Arc::clone(executor));
        }
        if let Some(query_vector) = query_embedding {
            retriever = retriever.with_query_embedding(query_vector);
        }
        let hits = retriever.retrieve()?;
        Ok((hits, posture))
    }

    /// Fills the vector pool of one generation from the content-keyed
    /// chunk-vector cache, embedding at most `budget` uncached chunks in one
    /// batch request. Embedded chunks are cached at once, so progress
    /// accumulates across calls; the pool is stored only when every chunk of
    /// the generation is covered. `include` narrows which chunks this caller
    /// needs; a narrowed call never stores the shared pool.
    fn fill_pool(
        &self,
        generation: &IndexGeneration,
        chunks: &[IndexedChunk],
        include: impl Fn(&IndexedChunk) -> bool,
        embed: &QueryEmbedder,
        model: &EmbeddingModelId,
        budget: usize,
    ) -> BrainResult<bool> {
        let mut covered: BTreeMap<KnowledgeChunkId, Vec<f32>> = BTreeMap::new();
        let mut missing: Vec<(KnowledgeChunkId, Digest, String)> = Vec::new();
        let mut uncovered = 0_usize;
        for chunk in chunks.iter().filter(|chunk| include(chunk)) {
            let text_digest = Digest::hash(chunk.text.as_bytes());
            if let Some(dims) = self.index.cached_chunk_vector(model, &text_digest)? {
                covered.insert(chunk.chunk_id, dims);
            } else if missing.len() < budget {
                missing.push((chunk.chunk_id, text_digest, chunk.text.clone()));
            } else {
                uncovered += 1;
            }
        }
        if !missing.is_empty() {
            let texts: Vec<String> = missing.iter().map(|(_, _, text)| text.clone()).collect();
            let vectors = match embed(&texts) {
                Ok(vectors) => vectors,
                Err(BrainError::EmbeddingUnavailable { .. }) => return Ok(false),
                Err(error) => return Err(error),
            };
            for ((chunk_id, text_digest, _), vector) in missing.iter().zip(vectors) {
                self.index
                    .cache_chunk_vector(model, text_digest, vector.dims())?;
                covered.insert(*chunk_id, vector.dims().to_vec());
            }
        }
        if uncovered > 0 {
            return Ok(false);
        }
        if !covered.is_empty() && covered.len() == chunks.len() {
            let pool: Vec<_> = chunks
                .iter()
                .filter_map(|chunk| {
                    covered
                        .remove(&chunk.chunk_id)
                        .map(|dims| (chunk.chunk_id, dims))
                })
                .collect();
            self.index
                .store_vectors(&generation.generation_id, model, &pool)?;
        }
        Ok(true)
    }

    /// The compact vector index of one generation whose stored vector pool
    /// is complete, built once per process and reused across turns. `None`
    /// while the generation has no complete pool (a live source still being
    /// embedded, a lexical-only archive).
    /// The compact vector index of `generation` when already built in this
    /// process; never builds.
    fn cached_compact_index(
        &self,
        generation: &IndexGeneration,
    ) -> BrainResult<Option<Arc<CompactIndex>>> {
        let mut cache = self.compact.lock().map_err(|_| {
            crate::index::store::corrupt("the compact vector cache mutex is poisoned")
        })?;
        Ok(cache.get_mut(&generation.generation_id).map(|found| {
            found.0 = std::time::Instant::now();
            Arc::clone(&found.1)
        }))
    }

    pub(crate) fn compact_index(
        &self,
        generation: &IndexGeneration,
    ) -> BrainResult<Option<Arc<CompactIndex>>> {
        if let Some(found) = self
            .compact
            .lock()
            .map_err(|_| {
                crate::index::store::corrupt("the compact vector cache mutex is poisoned")
            })?
            .get_mut(&generation.generation_id)
        {
            found.0 = std::time::Instant::now();
            return Ok(Some(Arc::clone(&found.1)));
        }
        let expected = self
            .index
            .chunk_count(&generation.generation_id)?
            .unwrap_or(0);
        if expected == 0 || self.index.vector_count(&generation.generation_id)? != expected {
            return Ok(None);
        }
        let mut compact = CompactIndex::with_capacity(expected as usize);
        self.index
            .for_each_vector(&generation.generation_id, |ordinal, item, dims| {
                compact.push(ordinal, item, dims)
            })?;
        let compact = Arc::new(compact);
        let mut cache = self.compact.lock().map_err(|_| {
            crate::index::store::corrupt("the compact vector cache mutex is poisoned")
        })?;
        // Generations are immutable and superseded ones are never pinned
        // again; the cache keeps the most recent few.
        if cache.len() >= MAX_COMPACT_INDEXES {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (used, _))| *used)
                .map(|(id, _)| *id)
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            generation.generation_id,
            (std::time::Instant::now(), Arc::clone(&compact)),
        );
        Ok(Some(compact))
    }

    /// The compact vector index a turn nominates from, or why the vector
    /// leg is unavailable for this generation this turn. A complete stored
    /// pool serves directly; a small live generation completes its pool
    /// inline from the content-keyed cache (embedding at most
    /// [`LAZY_EMBED_BUDGET`] chunks); a large one is completed by the
    /// background warm while its lexical leg serves; a lexical-only archive
    /// fills through its own backfill.
    fn vector_index(
        &self,
        generation: &IndexGeneration,
        archive: bool,
        embed: &QueryEmbedder,
        lexical_fallback: bool,
    ) -> BrainResult<Result<Option<Arc<CompactIndex>>, String>> {
        if let Some(compact) = self.cached_compact_index(generation)? {
            return Ok(Ok(Some(compact)));
        }
        // Large hybrid pools warm off the turn path; lexical retrieval serves meanwhile.
        let chunks = self
            .index
            .chunk_count(&generation.generation_id)?
            .unwrap_or(0) as usize;
        if !inline_compact_allowed(chunks, lexical_fallback) {
            return Ok(Err(format!(
                "source {} vector index is warming; serving its lexical leg meanwhile",
                generation.atlas_id.as_str()
            )));
        }
        if let Some(compact) = self.compact_index(generation)? {
            return Ok(Ok(Some(compact)));
        }
        if generation.embedding_model.as_str() == crate::index::build::NO_EMBEDDING_MODEL {
            return Ok(if archive {
                Err(
                    "archive generation is lexical-only; embeddings are pending through \
                     the declared gateway lane"
                        .to_owned(),
                )
            } else {
                Ok(None)
            });
        }
        let Some(model) = self.config.embedding_model.as_ref() else {
            return Ok(Ok(None));
        };
        let count = self
            .index
            .chunk_count(&generation.generation_id)?
            .unwrap_or(0);
        if count as usize <= INLINE_POOL_CHUNKS {
            if let Some((_, chunks)) = self.index.load(&generation.generation_id)? {
                if self.fill_pool(
                    generation,
                    &chunks,
                    |_| true,
                    embed,
                    model,
                    LAZY_EMBED_BUDGET,
                )? {
                    return Ok(Ok(self.compact_index(generation)?));
                }
            }
        }
        Ok(Err(format!(
            "source {} is still being embedded; serving its lexical leg meanwhile",
            generation.atlas_id.as_str()
        )))
    }

    /// One background warm round over one pin of every source: builds the
    /// moved heads of the sources the state pump does not own, seals and
    /// embeds (or, without a PostgreSQL store, indexes and embeds the SQLite
    /// pools), then retires old generations. Returns how many generations
    /// still await sealing or vectors.
    pub fn warm(&self, embedder: &QueryEmbedder, budget: usize) -> BrainResult<usize> {
        let pinned = pin_all(&self.sources, self.archives.as_ref())?;
        let unowned: Vec<PinnedSource> = pinned
            .iter()
            .filter(|pinned| {
                pinned.generation.is_none()
                    && self
                        .sources
                        .get(&pinned.id)
                        .is_some_and(|source| !source.is_state())
            })
            .cloned()
            .collect();
        self.build_generations(&unowned)?;
        let pending = match self.index.postgres() {
            Some(postgres) => self.warm_postgres(postgres, &pinned, embedder, budget)?,
            None => self.warm_sqlite(&pinned, embedder, budget)?,
        };
        self.retain(&pinned)?;
        Ok(pending)
    }

    /// Keeps, per live source, the newest servable generation, anything
    /// newer, and the one before it; retires the rest and frees their space.
    fn retain(&self, pinned_sources: &[PinnedSource]) -> BrainResult<()> {
        let model = self.config.embedding_model.as_ref();
        let mut retired = 0;
        for pinned in pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_none())
        {
            if let Some(serving) = self.index.newest(&pinned.id, model, true)? {
                retired += self
                    .index
                    .retire_older(&pinned.id, &serving.generation_id)?;
            }
        }
        if retired > 0 {
            self.index.reclaim()?;
            tracing::info!(retired, "brain retention retired old generations");
        }
        Ok(())
    }

    fn warm_sqlite(
        &self,
        pinned_sources: &[PinnedSource],
        embedder: &QueryEmbedder,
        budget: usize,
    ) -> BrainResult<usize> {
        self.warm_indexes_over(pinned_sources)?;
        self.warm_vectors_over(pinned_sources, embedder, budget)
    }

    fn warm_indexes_over(&self, pinned_sources: &[PinnedSource]) -> BrainResult<usize> {
        let mut built = 0;
        for pinned in pinned_sources {
            let generation = match &pinned.generation {
                Some(generation_id) => {
                    self.index
                        .load_pinned(generation_id, &pinned.id, &pinned.revision)?
                }
                None => match self.serving_generation(pinned)? {
                    Some(generation) => generation,
                    None => continue,
                },
            };
            if !self
                .index
                .generation_lexical_ready(&generation.generation_id)?
            {
                self.index
                    .build_generation_lexical(&generation.generation_id)?;
                built += 1;
            }
            self.compact_index(&generation)?;
        }
        Ok(built)
    }

    /// Background vector warm, off every turn path: for each live source's
    /// current generation without a stored pool, embeds up to `budget`
    /// uncached chunks and stores the pool once complete. Returns how many
    /// generations still await vectors. Archives fill through their own
    /// bounded backfill and are skipped.
    pub fn warm_vectors(&self, embedder: &QueryEmbedder, budget: usize) -> BrainResult<usize> {
        self.warm_vectors_over(
            &pin_all(&self.sources, self.archives.as_ref())?,
            embedder,
            budget,
        )
    }

    fn warm_vectors_over(
        &self,
        pinned_sources: &[PinnedSource],
        embedder: &QueryEmbedder,
        budget: usize,
    ) -> BrainResult<usize> {
        let Some(model) = self.config.embedding_model.as_ref() else {
            return Ok(0);
        };
        let mut pending = 0;
        for pinned in pinned_sources {
            if pinned.generation.is_some() {
                continue;
            }
            let Some(generation) = self.serving_generation(pinned)? else {
                continue;
            };
            if self.index.vector_count(&generation.generation_id)? > 0 {
                continue;
            }
            let Some((_, chunks)) = self.index.load(&generation.generation_id)? else {
                continue;
            };
            if !self.fill_pool(&generation, &chunks, |_| true, embedder, model, budget)? {
                pending += 1;
            }
        }
        Ok(pending)
    }

    /// One turn's exact identity constraints, resolved to the published
    /// logical record the turn addresses.
    ///
    /// The query's opaque literals ([`identity_literals`]) are compared
    /// exactly against the published records of the serving scope's pinned
    /// archive sources, one lookup per literal and source. Only a
    /// message-class match on the record's OWN identity (natural key, message
    /// id, or thread id) selects content; a conversation id only confirms.
    /// Resolution is coherent or explicitly unresolved:
    ///
    /// - different logical records (or sources) carrying the same literal, a
    ///   literal whose matches exhaust the page budget, or a segmented record
    ///   missing a part its own metadata declares, is
    ///   [`AddressResolution::Unresolved`];
    /// - a segmented record's part items are ONE logical record: every part
    ///   seen is served, never treated as ambiguity;
    /// - an instant literal must equal the selected record's own instant to
    ///   the precision the query carries, and a record without one cannot
    ///   satisfy it; another message sharing that instant is irrelevant;
    /// - a conversation the selected record does not belong to is
    ///   [`AddressResolution::Unresolved`];
    /// - no candidate at all is [`AddressResolution::None`]: most queries
    ///   address no record, and each of them costs no lookup.
    fn resolve_addressed_record(
        &self,
        text: &str,
        pinned_sources: &[PinnedSource],
        serving_scope: &BTreeSet<AtlasId>,
    ) -> BrainResult<AddressResolution> {
        let literals = identity_literals(text);
        if literals.is_empty() {
            return Ok(AddressResolution::None);
        }
        let Some(store) = self.archives.as_ref() else {
            return Ok(AddressResolution::None);
        };
        let archives: Vec<&PinnedSource> = pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_some() && serving_scope.contains(&pinned.id))
            .collect();
        let mut addressed: BTreeMap<(AtlasId, String), BTreeSet<KnowledgeItemId>> = BTreeMap::new();
        let mut own_rows: BTreeMap<(AtlasId, String), Vec<ArchiveIdentity>> = BTreeMap::new();
        let mut conversations: BTreeSet<(AtlasId, String)> = BTreeSet::new();
        let mut unresolved = false;
        for pinned in &archives {
            for literal in &literals {
                // A literal's matches are paged to exhaustion: uniqueness is
                // never concluded from a truncated page, and a page budget
                // that runs out is explicitly unresolvable instead of a
                // silently partial answer.
                let mut page = store.identity_records(
                    &pinned.id,
                    &pinned.revision,
                    literal,
                    ArchiveRecordKind::Message,
                )?;
                let mut pages = 1_usize;
                loop {
                    let full = page.len() >= MAX_IDENTITY_RECORDS;
                    let mut last_item = None;
                    for identity in page {
                        last_item = Some(identity.item_id);
                        let owns = literal == &identity.natural_key
                            || identity.message_id.as_deref() == Some(literal.as_str())
                            || identity.thread_id.as_deref() == Some(literal.as_str());
                        if !owns {
                            // Matched by the record's own conversation: a
                            // confirmation for the addressed record, never a
                            // selector.
                            conversations.insert((pinned.id.clone(), literal.clone()));
                            continue;
                        }
                        let key = (pinned.id.clone(), logical_key(&identity).to_owned());
                        addressed
                            .entry(key.clone())
                            .or_default()
                            .insert(identity.item_id);
                        own_rows.entry(key).or_default().push(identity);
                    }
                    if !full {
                        break;
                    }
                    let Some(last_item) = last_item else { break };
                    if pages >= MAX_IDENTITY_PAGES {
                        unresolved = true;
                        break;
                    }
                    page = store.identity_records_after(
                        &pinned.id,
                        &pinned.revision,
                        literal,
                        ArchiveRecordKind::Message,
                        &last_item,
                    )?;
                    pages += 1;
                }
            }
        }
        if unresolved || addressed.len() > 1 {
            return Ok(AddressResolution::Unresolved);
        }
        let Some((key, item_ids)) = addressed.into_iter().next() else {
            return Ok(AddressResolution::None);
        };
        let source = key.0.clone();
        let Some(rows) = own_rows.remove(&key) else {
            return Ok(AddressResolution::Unresolved);
        };
        // A segmented logical record is complete only when every part its own
        // metadata declares is present: an incomplete logical message is
        // never served as if it were the whole record.
        let declared = rows.iter().filter_map(|identity| identity.part_count).max();
        if let Some(declared) = declared {
            let mut seen: BTreeSet<u32> = rows
                .iter()
                .filter_map(|identity| identity.part_index)
                .collect();
            if seen.len() != declared as usize {
                return Ok(AddressResolution::Unresolved);
            }
            for expected in 1..=declared {
                if !seen.remove(&expected) {
                    return Ok(AddressResolution::Unresolved);
                }
            }
            if !seen.is_empty() {
                return Ok(AddressResolution::Unresolved);
            }
        }
        let Some(own) = rows.into_iter().next() else {
            return Ok(AddressResolution::Unresolved);
        };
        if conversations.iter().any(|(candidate, conversation)| {
            *candidate == source && own.conversation_id.as_deref() != Some(conversation.as_str())
        }) {
            return Ok(AddressResolution::Unresolved);
        }
        if let Some(created_at) = own.created_at {
            for literal in &literals {
                let Ok(instant) = OffsetDateTime::parse(literal, &Rfc3339) else {
                    continue;
                };
                if !instant_matches(literal, instant, created_at) {
                    return Ok(AddressResolution::Unresolved);
                }
            }
        } else if literals
            .iter()
            .any(|literal| OffsetDateTime::parse(literal, &Rfc3339).is_ok())
        {
            return Ok(AddressResolution::Unresolved);
        }
        Ok(AddressResolution::Addressed(AddressedRecord {
            source,
            item_ids,
        }))
    }
}

/// Whether one query instant matches a record's own instant at the precision
/// the query carries: a fractional query must match exactly, while a
/// whole-second query matches any instant inside that second.
fn instant_matches(literal: &str, instant: OffsetDateTime, created_at: OffsetDateTime) -> bool {
    if literal.contains('.') {
        instant.unix_timestamp_nanos() == created_at.unix_timestamp_nanos()
    } else {
        instant.unix_timestamp() == created_at.unix_timestamp()
    }
}

#[cfg(test)]
mod inline_compact_tests {
    /// Small generations and non-hybrid policies still build inline.
    #[test]
    fn a_hybrid_turn_never_builds_a_large_compact_index_inline() {
        let large = super::INLINE_POOL_CHUNKS + 1;
        assert!(!super::inline_compact_allowed(large, true));
        assert!(super::inline_compact_allowed(large, false));
        assert!(super::inline_compact_allowed(
            super::INLINE_POOL_CHUNKS,
            true
        ));
    }
}

/// Per-phase time of one memory read, summed over its sources.
#[derive(Default)]
struct PhaseTiming {
    sources: usize,
    lexical: std::time::Duration,
    vector_load: std::time::Duration,
    embed: std::time::Duration,
    nearest: std::time::Duration,
    fetch: std::time::Duration,
}

impl PhaseTiming {
    fn log(&self, total: std::time::Duration, chunks: usize) {
        tracing::debug!(
            sources = self.sources,
            chunks,
            total_ms = total.as_millis(),
            lexical_ms = self.lexical.as_millis(),
            vector_load_ms = self.vector_load.as_millis(),
            embed_ms = self.embed.as_millis(),
            nearest_ms = self.nearest.as_millis(),
            fetch_ms = self.fetch.as_millis(),
            "retrieval"
        );
    }
}
