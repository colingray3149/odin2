//! Retrieval and warming over the brain's PostgreSQL store: one hybrid
//! nomination query per turn over every served generation, fused by
//! reciprocal rank; the warm pump mirrors pinned generations and embeds
//! their unembedded chunks there.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::{
    AtlasId, IndexGeneration, KnowledgeItemId, RelevanceScore, RetrievalHit, RetrievalMode,
    RetrievalQuery,
};
use odin_domain::{Digest, ProjectId};

use super::{AddressedRecord, RetrievalPosture, EMBEDDING_LEG};
use crate::error::{BrainError, BrainResult};
use crate::index::build::NO_EMBEDDING_MODEL;
use crate::index::postgres::{keyword_terms, BrainPostgres, Nominated, Nomination, RRF_K};
use crate::retrieval::embedding::EmbeddingVector;
use crate::retrieval::{embed_one, rank, QueryEmbedder, RetrievalPlan, ScoredCandidate};
use crate::service::authority::PinnedSource;
use crate::service::BrainService;

/// Unembedded chunks read per warm round, as a multiple of the embed budget.
const UNEMBEDDED_PAGE_FACTOR: usize = 16;

/// One retrieval turn: the resolved plan, the generations it serves, and
/// the request's visibility.
pub(super) struct PostgresTurn<'a> {
    pub plan: RetrievalPlan,
    pub generations: Vec<IndexGeneration>,
    pub pinned: &'a [PinnedSource],
    pub project: Option<&'a ProjectId>,
    pub visible_items: &'a BTreeSet<KnowledgeItemId>,
    pub archive_sources: &'a BTreeSet<AtlasId>,
    pub serving_scope: &'a BTreeSet<AtlasId>,
    pub addressed: Option<&'a AddressedRecord>,
    pub embedder: Option<&'a Arc<QueryEmbedder>>,
}

impl BrainService {
    pub(super) fn retrieve_postgres(
        &self,
        turn: &PostgresTurn<'_>,
    ) -> BrainResult<(Vec<RetrievalHit>, RetrievalPosture)> {
        let postgres = self.index.postgres();
        let started = std::time::Instant::now();
        let plan = turn.plan.clone();
        let mode = plan.mode();
        let terms = match mode {
            RetrievalMode::Lexical | RetrievalMode::Hybrid => {
                let terms = keyword_terms(&plan.query().text);
                if terms.is_empty() {
                    return Err(BrainError::InvalidRequest(
                        "retrieval query text has no lexical terms".to_owned(),
                    ));
                }
                Some(terms)
            }
            RetrievalMode::Vector => None,
        };
        let mut posture = RetrievalPosture::Full;
        let lexical_only_archive = turn.generations.iter().any(|generation| {
            turn.archive_sources.contains(&generation.atlas_id)
                && generation.embedding_model.as_str() == NO_EMBEDDING_MODEL
        });
        if plan.requires_embeddings() && lexical_only_archive {
            let reason = "archive generation is lexical-only; embeddings are pending through \
                          the declared gateway lane"
                .to_owned();
            if mode != RetrievalMode::Hybrid {
                return Err(BrainError::EmbeddingUnavailable {
                    provider: EMBEDDING_LEG.to_owned(),
                    reason,
                });
            }
            posture = RetrievalPosture::LexicalOnly { reason };
        }
        let mut embedding = None;
        if plan.requires_embeddings() && posture == RetrievalPosture::Full {
            let (Some(embed), Some(model)) = (turn.embedder, self.config.embedding_model.as_ref())
            else {
                return Err(BrainError::EmbeddingUnavailable {
                    provider: EMBEDDING_LEG.to_owned(),
                    reason: "no embedding executor is resolved for this retriever; vector and \
                             hybrid retrieval refuse lexical downgrade"
                        .to_owned(),
                });
            };
            match embed_one(embed.as_ref(), &plan.query().text) {
                Ok(vector) => embedding = Some((vector.dims().to_vec(), model.as_str().to_owned())),
                Err(BrainError::EmbeddingUnavailable { reason, .. })
                    if mode == RetrievalMode::Hybrid =>
                {
                    posture = RetrievalPosture::LexicalOnly { reason };
                }
                Err(error) => return Err(error),
            }
        }
        let embed_ms = started.elapsed().as_millis();
        let legs = u32::from(terms.is_some()) + u32::from(embedding.is_some());
        let by_id: BTreeMap<String, &IndexGeneration> = turn
            .generations
            .iter()
            .map(|generation| (generation.generation_id.to_string(), generation))
            .collect();
        let nominated = match turn.addressed {
            Some(record) => {
                let Some(generation) = turn
                    .generations
                    .iter()
                    .find(|generation| generation.atlas_id == record.source)
                else {
                    return Ok((Vec::new(), posture));
                };
                let ordinals = self
                    .index
                    .ordinals_for_items(&generation.generation_id, &record.item_ids)?;
                postgres.rank_record(
                    &generation.generation_id.to_string(),
                    ordinals,
                    terms,
                    embedding,
                )?
            }
            None => postgres.nominate(Nomination {
                generations: by_id.keys().cloned().collect(),
                hidden_items: hidden_items(self, turn.pinned, turn.project),
                terms,
                embedding,
                limit: i64::from(plan.query().candidate_limit.get()),
            })?,
        };
        let query_ms = started.elapsed().as_millis() - embed_ms;
        let mut by_generation: BTreeMap<&str, Vec<&Nominated>> = BTreeMap::new();
        for row in &nominated {
            by_generation
                .entry(row.generation_id.as_str())
                .or_default()
                .push(row);
        }
        let best = f64::from(legs.max(1)) / (RRF_K + 1.0);
        let mut pooled: Vec<(String, ScoredCandidate)> = Vec::with_capacity(nominated.len());
        for (id, rows) in by_generation {
            let Some(generation) = by_id.get(id) else {
                continue;
            };
            let ordinals: Vec<i64> = rows.iter().map(|row| row.ordinal).collect();
            for (row, chunk) in rows
                .iter()
                .zip(self.index.chunks_at(&generation.generation_id, &ordinals)?)
            {
                let visible = turn.archive_sources.contains(&chunk.citation.source)
                    || turn.visible_items.contains(&chunk.item_id);
                let in_record = turn
                    .addressed
                    .is_none_or(|record| record.item_ids.contains(&chunk.citation.item_id));
                if !(turn.serving_scope.contains(&chunk.citation.source) && visible && in_record) {
                    continue;
                }
                let scale = f64::from(RelevanceScore::MAX);
                let score = ((row.rrf / best) * scale).round().clamp(0.0, scale);
                pooled.push((
                    generation.generation_id.to_string(),
                    ScoredCandidate {
                        chunk,
                        score: RelevanceScore::new(score as u32)?,
                    },
                ));
            }
        }
        let query = plan.query();
        if !pooled.is_empty() && !(query.required_tags.is_empty() && query.denied_tags.is_empty()) {
            filter_by_tags(postgres, query, &mut pooled)?;
        }
        let mut candidates: Vec<ScoredCandidate> =
            pooled.into_iter().map(|(_, candidate)| candidate).collect();
        let served = candidates.len();
        let (rerank_ms, rerank_skipped) =
            self.rerank(&plan.query().text, plan.query().min_score, &mut candidates);
        // A lexical-only posture already says less was served; a skipped rerank only
        // downgrades a full one.
        if let (RetrievalPosture::Full, Some(reason)) = (&posture, rerank_skipped) {
            posture = RetrievalPosture::FusedOnly { reason };
        }
        let plan = match posture {
            RetrievalPosture::LexicalOnly { .. } => {
                RetrievalPlan::new(plan.query().clone(), RetrievalMode::Lexical)
            }
            RetrievalPosture::Full | RetrievalPosture::FusedOnly { .. } => plan,
        };
        let hits = rank(&plan, candidates)?;
        tracing::debug!(
            sources = turn.generations.len(),
            chunks = served,
            total_ms = started.elapsed().as_millis(),
            embed_ms,
            query_ms,
            rerank_ms,
            "retrieval"
        );
        Ok((hits, posture))
    }

    /// Reorders the best `candidates` by the declared reranker, in place:
    /// only candidates at or above `min_score` take part, and the reranked
    /// ones take the fused scores the head held, best first and strictly
    /// falling, in the reranker's order, so `top_k` cuts as before and the
    /// order survives ranking. Without a reranker, or when it fails (named in
    /// the log), the fused order stands. Returns the milliseconds it took and why the
    /// rerank was skipped, when it failed.
    fn rerank(
        &self,
        query: &str,
        min_score: RelevanceScore,
        candidates: &mut Vec<ScoredCandidate>,
    ) -> (u128, Option<String>) {
        let Some(reranker) = &self.config.rerank else {
            return (0, None);
        };
        let started = std::time::Instant::now();
        // Ranking keeps one chunk per text; a later twin would otherwise
        // keep the score its text held before the reorder.
        candidates.retain(|candidate| candidate.score >= min_score);
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.score));
        let mut seen = BTreeSet::new();
        candidates.retain(|candidate| seen.insert(candidate.chunk.digest));
        let best = candidates.len().min(reranker.candidates);
        if best < 2 {
            return (0, None);
        }
        let texts: Vec<&str> = candidates[..best]
            .iter()
            .map(|candidate| candidate.chunk.text.as_str())
            .collect();
        let mut skipped = None;
        match reranker.order(query, &texts) {
            Ok(order) => {
                let chunks: Vec<_> = order
                    .iter()
                    .map(|&position| candidates[position].chunk.clone())
                    .collect();
                let mut ceiling = u32::MAX;
                for (candidate, chunk) in candidates.iter_mut().zip(chunks) {
                    let score = candidate.score.get().min(ceiling).max(min_score.get());
                    ceiling = score.saturating_sub(1);
                    candidate.chunk = chunk;
                    if let Ok(score) = RelevanceScore::new(score) {
                        candidate.score = score;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "brain-rerank skipped; the fused order serves");
                skipped = Some(error.to_string());
            }
        }
        (started.elapsed().as_millis(), skipped)
    }

    /// One warm round over the PostgreSQL store: embeds up to `budget`
    /// uncached chunks of every pinned live source's serving generation in
    /// one batch; chunks whose text was embedded before take the stored
    /// vector. Archives are left to the nightly backfill. Returns how many
    /// generations still await embeddings.
    pub(super) fn warm_postgres(
        &self,
        pinned_sources: &[PinnedSource],
        embedder: &QueryEmbedder,
        budget: usize,
    ) -> BrainResult<usize> {
        let model = self.config.embedding_model.as_ref();
        let mut embeddable = Vec::new();
        for pinned in pinned_sources
            .iter()
            .filter(|pinned| pinned.generation.is_none())
        {
            let generation =
                match self
                    .index
                    .current_for_model(&pinned.id, &pinned.revision, model)?
                {
                    Some(generation) => generation,
                    None => match self.index.newest(&pinned.id, model)? {
                        Some(generation) => generation,
                        None => continue,
                    },
                };
            if Some(&generation.embedding_model) == model {
                embeddable.push(generation.generation_id.to_string());
            }
        }
        let Some(model) = model else {
            return Ok(0);
        };
        if embeddable.is_empty() {
            return Ok(0);
        }
        let round = embed_round(
            self.index.postgres(),
            embeddable,
            model.as_str(),
            budget,
            &mut |texts| embedder(texts),
        )?;
        if let Some(reason) = &round.unavailable {
            tracing::debug!(%reason, "postgres warm embedding unavailable");
        }
        if round.embedded > 0 || round.cached > 0 {
            tracing::debug!(
                embedded = round.embedded,
                cached = round.cached,
                pending_generations = round.pending,
                "postgres warm"
            );
        }
        Ok(round.pending)
    }
}

/// What one embedding round stored.
pub(in crate::service) struct EmbedRound {
    /// Vectors the embedder made this round.
    pub embedded: usize,
    /// Chunks that took the stored vector of identical text.
    pub cached: usize,
    /// Generations that had unembedded chunks when the round began.
    pub pending: usize,
    /// Why the embedder was unavailable, when it was.
    pub unavailable: Option<String>,
}

/// Embeds, in place, up to `budget` distinct uncached texts among the
/// unembedded chunks of `generations`; chunks whose text any generation
/// already embedded under `model` take that vector.
pub(in crate::service) fn embed_round(
    postgres: &BrainPostgres,
    generations: Vec<String>,
    model: &str,
    budget: usize,
    embed: &mut dyn FnMut(&[String]) -> BrainResult<Vec<EmbeddingVector>>,
) -> BrainResult<EmbedRound> {
    // Cache hits cost nothing, so a page reads well past the embed budget.
    let page = budget.saturating_mul(UNEMBEDDED_PAGE_FACTOR) as i64;
    let (chunks, pending) = postgres.unembedded(generations, page)?;
    let mut embedded: BTreeMap<String, Vec<(i64, Vec<f32>)>> = BTreeMap::new();
    // One request per distinct uncached text; every chunk sharing it
    // takes the same vector.
    let mut missing: BTreeMap<Digest, (String, Vec<(String, i64)>)> = BTreeMap::new();
    let mut round = EmbedRound {
        embedded: 0,
        cached: 0,
        pending,
        unavailable: None,
    };
    let known = postgres.embeddings_by_digest(
        model,
        chunks
            .iter()
            .map(|chunk| Digest::hash(chunk.text.as_bytes()).to_string())
            .collect(),
    )?;
    for chunk in chunks {
        let text_digest = Digest::hash(chunk.text.as_bytes());
        if let Some(dims) = known.get(&text_digest.to_string()).cloned() {
            round.cached += 1;
            embedded
                .entry(chunk.generation_id)
                .or_default()
                .push((chunk.ordinal, dims));
        } else if let Some((_, rows)) = missing.get_mut(&text_digest) {
            rows.push((chunk.generation_id, chunk.ordinal));
        } else if missing.len() < budget {
            missing.insert(
                text_digest,
                (chunk.text, vec![(chunk.generation_id, chunk.ordinal)]),
            );
        }
    }
    if !missing.is_empty() {
        let texts: Vec<String> = missing.values().map(|(text, _)| text.clone()).collect();
        match embed(&texts) {
            Ok(vectors) if vectors.len() != texts.len() => {
                return Err(BrainError::InvalidRequest(format!(
                    "the embedder returned {} vectors for {} texts",
                    vectors.len(),
                    texts.len()
                )));
            }
            Ok(vectors) => {
                round.embedded = vectors.len();
                for ((_, (_, rows)), vector) in missing.into_iter().zip(vectors) {
                    for (generation, ordinal) in rows {
                        embedded
                            .entry(generation)
                            .or_default()
                            .push((ordinal, vector.dims().to_vec()));
                    }
                }
            }
            Err(BrainError::EmbeddingUnavailable { reason, .. }) => {
                round.unavailable = Some(reason);
            }
            Err(error) => return Err(error),
        }
    }
    for (generation, rows) in embedded {
        postgres.insert_embeddings(&generation, model, rows)?;
    }
    Ok(round)
}

/// Drops pooled candidates whose item's scope tags miss a required tag or
/// hold a denied one. One query reads the tags of every candidate item; an
/// item with no provenance row carries no tags.
fn filter_by_tags(
    postgres: &BrainPostgres,
    query: &RetrievalQuery,
    pooled: &mut Vec<(String, ScoredCandidate)>,
) -> BrainResult<()> {
    let generations: BTreeSet<String> = pooled.iter().map(|(id, _)| id.clone()).collect();
    let items: BTreeSet<String> = pooled
        .iter()
        .map(|(_, candidate)| candidate.chunk.item_id.to_string())
        .collect();
    let tags: BTreeMap<(String, String), Vec<String>> = postgres
        .provenance_tags(
            generations.into_iter().collect(),
            items.into_iter().collect(),
        )?
        .into_iter()
        .map(|(generation, item, tags)| ((generation, item), tags))
        .collect();
    pooled.retain(|(generation, candidate)| {
        let key = (generation.clone(), candidate.chunk.item_id.to_string());
        let item_tags = tags.get(&key).map_or(&[][..], Vec::as_slice);
        query
            .required_tags
            .iter()
            .all(|tag| item_tags.contains(tag))
            && !query.denied_tags.iter().any(|tag| item_tags.contains(tag))
    });
    Ok(())
}

/// Items of the turn's live sources it may not see (another project's
/// memory); archives carry no items.
fn hidden_items(
    service: &BrainService,
    pinned: &[PinnedSource],
    project: Option<&ProjectId>,
) -> Vec<String> {
    pinned
        .iter()
        .flat_map(|source| source.items.iter())
        .filter(|item| !service.item_visible(item, project))
        .map(|item| item.item_id.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

    use std::sync::{Arc, Mutex};

    use odin_domain::huginn::ids::ModelName;

    use odin_domain::knowledge::retrieval::{ModelDescriptor, TrustClass};
    use odin_domain::knowledge::EmbeddingBackend;
    use odin_domain::Digest;
    use odin_ledger::Ledger;
    use odin_registry::schema::{
        AccountingWindowToml, BudgetPolicyToml, RegistryKind, SeatKnowledgeToml, SeatLimitsToml,
        SeatToml, SliceKnowledgeToml, SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
    };

    use super::*;
    use crate::config::EffectiveBrainPolicy;
    use crate::context::PinnedTokenizer;
    use crate::index::build::{build_index, Chunker};

    use crate::index::store::IndexStore;

    use crate::service::BrainServiceConfig;
    use crate::source::SourceItem;
    use crate::test_cluster::TestCluster;

    /// A resolved policy for the gate and warm fixtures: `None` composes no
    /// knowledge authority (the gate reads only the index store and the
    /// operator config); `Some` authorizes exactly one source so the warm
    /// pump resolves its configured embedding model and retrieval query.
    fn policy_for(authorized: Option<&AtlasId>) -> EffectiveBrainPolicy {
        let knowledge = authorized.map(|source| {
            (
                SliceKnowledgeToml {
                    required: false,
                    atlas_sources: BTreeSet::from([source.clone()]),
                    retrieval_mode: RetrievalMode::Lexical,
                    candidate_limit: NonZeroU16::new(64).unwrap(),
                    top_k: NonZeroU16::new(8).unwrap(),
                    min_score_micros: 0,
                    chunk_tokens: NonZeroU32::new(512).unwrap(),
                    chunk_overlap_tokens: 64,
                    embedding_backend: EmbeddingBackend::Local,
                },
                SeatKnowledgeToml {
                    atlas_sources: BTreeSet::from([source.clone()]),
                    required_tags: BTreeSet::new(),
                    denied_tags: BTreeSet::new(),
                    top_k: NonZeroU16::new(8).unwrap(),
                },
            )
        });
        let (slice_knowledge, seat_knowledge) = match knowledge {
            Some((slice, seat)) => (Some(slice), Some(seat)),
            None => (None, None),
        };
        EffectiveBrainPolicy::resolve(
            74,
            &SliceToml {
                schema: REGISTRY_SCHEMA.to_owned(),
                inherit_seat_grants: false,
                kind: RegistryKind::Slice,
                enabled: true,
                description: "turn gate fixture slice".to_owned(),
                capabilities: BTreeSet::new(),
                variables: BTreeMap::new(),
                redirects: SliceRedirectsToml {
                    out_of_scope: "NeedsPlan".to_owned(),
                },
                knowledge: slice_knowledge,
                context: None,
                tools: None,
                live: None,
                budget: None,
            },
            &SeatToml {
                slice: None,
                schema: REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Seat,
                enabled: true,
                description: "turn gate fixture seat".to_owned(),
                categories: BTreeSet::new(),
                project_scope: BTreeSet::new(),
                read_project_scope: BTreeSet::new(),
                models: Vec::new(),
                tool_refs: BTreeSet::new(),
                brain_scope: authorized.into_iter().cloned().collect(),
                limits: SeatLimitsToml {
                    max_parallel_runs: 4,
                    max_sessions: 4,
                    max_background_jobs: 4,
                    max_batch_launches: 256,
                    max_batch_inputs: 16,
                    inline_seconds: 4,
                    budget: Some(BudgetPolicyToml {
                        usd_micros: 30_000_000,
                        window: AccountingWindowToml {
                            duration_seconds: NonZeroU64::new(2_592_000).unwrap(),
                        },
                    }),
                },
                live: None,
                guidance: None,
                conversation: None,
                profile_namespace: None,
                knowledge: seat_knowledge,
                context: None,
                tools: None,
                ephemeral: None,
                sandbox: odin_registry::schema::SeatSandboxToml::default(),
            },
            &BTreeMap::new(),
            &std::collections::BTreeMap::new(),
            &model_descriptor(),
        )
        .unwrap()
    }

    fn model_descriptor() -> ModelDescriptor {
        ModelDescriptor {
            name: ModelName::new("model.turn-gate").unwrap(),
            tokenizer: PinnedTokenizer::id().unwrap(),
            context_window_tokens: NonZeroU32::new(8192).unwrap(),
        }
    }

    /// An item of a generation another seat's store built serves to a store
    /// that never built it.
    #[test]
    fn an_item_serves_from_a_generation_another_store_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let directory = tempfile::tempdir().unwrap();
        let base = directory.path().to_path_buf();
        let source = AtlasId::new("atlas:foreign-seal").unwrap();
        let revision = Digest::hash(b"foreign-seal");
        let item = SourceItem::new(
            source.clone(),
            revision,
            b"foreign-seal-item",
            TrustClass::Curated,
            "alpha beta gamma delta ".repeat(20),
        )
        .unwrap();
        let item_id = item.item_id;
        let build = build_index(
            source.clone(),
            revision,
            std::slice::from_ref(&item),
            &Chunker::new(NonZeroU32::new(16).unwrap(), 0).unwrap(),
        )
        .unwrap();
        let builder = IndexStore::open(&base.join("builder"), Arc::clone(&postgres)).unwrap();
        builder.store(&build, 1).unwrap();

        let service = BrainService::open(
            BrainServiceConfig {
                store_root: base.join("reader"),
                sources: BTreeMap::new(),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: Arc::clone(&postgres),
                rerank: None,
            },
            policy_for(None),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap();
        let pinned = PinnedSource {
            id: source,
            revision,
            generation: None,
            items: vec![item],
        };
        let served = service
            .serve_item(&pinned, &item_id)
            .unwrap()
            .expect("the sealed generation contains the item");
        assert_eq!(
            served.generation.generation_id,
            build.generation.generation_id
        );
        assert_eq!(served.chunks.len(), build.chunks.len());
    }

    /// A denied tag never returns and a required tag excludes untagged items.
    /// Exercised through the BM25 leg only; the filter runs on the fused pool
    /// after both legs, so vector nominations are filtered too but not tested here.
    #[test]
    fn a_denied_tag_never_returns_and_a_required_tag_excludes_untagged() {
        use crate::index::ItemProvenance;
        use odin_domain::knowledge::RetrievalQueryInit;

        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = tempfile::tempdir().unwrap();
        let source = AtlasId::new("atlas:tag-filter").unwrap();
        let revision = Digest::hash(b"tag-filter");
        let provenance = |scope_tags: Vec<String>| ItemProvenance {
            node_id: "node:tag-filter".to_owned(),
            path: "crates/tag/src/lib.rs".to_owned(),
            source_class: odin_atlas::SourceClass::Rust,
            scope_tags,
        };
        let secret = SourceItem::new(
            source.clone(),
            revision,
            b"tag-filter-secret",
            TrustClass::Curated,
            "tagfilter secretmarker alpha",
        )
        .unwrap()
        .with_provenance(provenance(vec!["secret".to_owned()]));
        let open = SourceItem::new(
            source.clone(),
            revision,
            b"tag-filter-open",
            TrustClass::Curated,
            "tagfilter openmarker beta",
        )
        .unwrap()
        .with_provenance(provenance(Vec::new()));
        let items = [secret.clone(), open.clone()];
        let build = build_index(
            source.clone(),
            revision,
            &items,
            &Chunker::new(NonZeroU32::new(512).unwrap(), 0).unwrap(),
        )
        .unwrap();
        IndexStore::open(root.path(), Arc::clone(&postgres))
            .unwrap()
            .store(&build, 1)
            .unwrap();

        let service = BrainService::open(
            BrainServiceConfig {
                store_root: root.path().to_path_buf(),
                sources: BTreeMap::new(),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: Arc::clone(&postgres),
                rerank: None,
            },
            policy_for(None),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap();
        let pinned = [PinnedSource {
            id: source.clone(),
            revision,
            generation: None,
            items: items.to_vec(),
        }];
        let visible: BTreeSet<KnowledgeItemId> = items.iter().map(|item| item.item_id).collect();
        let sources = BTreeSet::from([source.clone()]);
        let archive_sources = BTreeSet::new();
        let serve = |required: &[&str], denied: &[&str]| {
            let query = RetrievalQuery::new(RetrievalQueryInit {
                text: "tagfilter".to_owned(),
                sources: sources.clone(),
                required_tags: required.iter().map(|tag| (*tag).to_owned()).collect(),
                denied_tags: denied.iter().map(|tag| (*tag).to_owned()).collect(),
                allowed_trust: BTreeSet::from([TrustClass::Curated]),
                candidate_limit: NonZeroU16::new(64).unwrap(),
                top_k: NonZeroU16::new(8).unwrap(),
                min_score: RelevanceScore::ZERO,
            })
            .unwrap();
            let turn = PostgresTurn {
                plan: RetrievalPlan::new(query, RetrievalMode::Lexical),
                generations: vec![build.generation.clone()],
                pinned: &pinned,
                project: None,
                visible_items: &visible,
                archive_sources: &archive_sources,
                serving_scope: &sources,
                addressed: None,
                embedder: None,
            };
            service.retrieve_postgres(&turn).unwrap().0
        };

        let all = serve(&[], &[]);
        assert!(
            all.iter().any(|hit| hit.content.contains("secretmarker"))
                && all.iter().any(|hit| hit.content.contains("openmarker")),
            "the untagged baseline serves both items: {all:?}"
        );
        let denied = serve(&[], &["secret"]);
        assert!(!denied.is_empty(), "the open item still serves");
        assert!(
            denied
                .iter()
                .all(|hit| !hit.content.contains("secretmarker")),
            "a denied tag never returns: {denied:?}"
        );
        let required = serve(&["secret"], &[]);
        assert!(!required.is_empty(), "the tagged item serves");
        assert!(
            required
                .iter()
                .all(|hit| hit.content.contains("secretmarker")),
            "a required tag returns only its items: {required:?}"
        );
    }
}
