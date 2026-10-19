//! Retrieval and warming over the brain's PostgreSQL store: one hybrid
//! nomination query per turn over every served generation, fused by
//! reciprocal rank; the warm pump mirrors pinned generations and embeds
//! their unembedded chunks there.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::{
    AtlasId, IndexGeneration, KnowledgeItemId, RelevanceScore, RetrievalHit, RetrievalMode,
};
use odin_domain::{Digest, ProjectId};

use super::{AddressedRecord, RetrievalPosture, EMBEDDING_LEG};
use crate::error::{BrainError, BrainResult};
use crate::index::build::NO_EMBEDDING_MODEL;
use crate::index::postgres::{tsquery_terms, BrainPostgres, Nominated, Nomination, RRF_K};
use crate::retrieval::{embed_one, fuse_and_rank, QueryEmbedder, RetrievalPlan, ScoredCandidate};
use crate::service::authority::PinnedSource;
use crate::service::BrainService;

/// Chunk batches one warm round copies into the PostgreSQL store per
/// generation, so a first mirror of a large archive spreads over rounds.
const MIRROR_BATCHES_PER_ROUND: usize = 40;

/// Unembedded chunks read per warm round, as a multiple of the embed budget.
const UNEMBEDDED_PAGE_FACTOR: usize = 16;

/// One retrieval turn: the resolved plan, the generations it serves, and
/// the request's visibility. It is served from the PostgreSQL store and,
/// while that store is unreachable, from the SQLite index pools.
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
        let postgres = self
            .index
            .postgres()
            .ok_or_else(|| BrainError::Unavailable {
                component: "brain-postgres",
                reason: "no PostgreSQL store is configured".to_owned(),
            })?;
        let started = std::time::Instant::now();
        let plan = turn.plan.clone();
        let mode = plan.mode();
        let terms = match mode {
            RetrievalMode::Lexical | RetrievalMode::Hybrid => Some(tsquery_terms(
                crate::index::lexical::query_terms(plan.query())?,
            )),
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
        let mut candidates = Vec::with_capacity(nominated.len());
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
                let score = ((row.rrf / best) * 1_000_000.0)
                    .round()
                    .clamp(0.0, 1_000_000.0);
                candidates.push(ScoredCandidate {
                    chunk,
                    score: RelevanceScore::new(score as u32)?,
                });
            }
        }
        let served = candidates.len();
        let plan = match posture {
            RetrievalPosture::LexicalOnly { .. } => {
                RetrievalPlan::new(plan.query().clone(), RetrievalMode::Lexical)
            }
            RetrievalPosture::Full => plan,
        };
        let hits = fuse_and_rank(&plan, candidates, Vec::new())?;
        tracing::debug!(
            sources = turn.generations.len(),
            chunks = served,
            total_ms = started.elapsed().as_millis(),
            embed_ms,
            query_ms,
            "retrieval store=postgres finalists=postgres"
        );
        Ok((hits, posture))
    }

    /// One warm round over the PostgreSQL store: seals the newest built
    /// generation of every pinned source (bounded per round), resumes the
    /// durable SQLite vector pool of the sealed ones, then embeds up to
    /// `budget` uncached chunks in one batch; chunks whose text was embedded
    /// before take the cached vector. Returns how many generations still
    /// await sealing, pool resume, or embeddings.
    pub(super) fn warm_postgres(
        &self,
        postgres: &BrainPostgres,
        pinned_sources: &[PinnedSource],
        embedder: &QueryEmbedder,
        budget: usize,
    ) -> BrainResult<usize> {
        let model = self.config.embedding_model.as_ref();
        let (mut embeddable, mut mirroring) = (Vec::new(), 0_usize);
        let mut transferred = 0_usize;
        for pinned in pinned_sources {
            let generation = match &pinned.generation {
                Some(generation_id) => {
                    self.index
                        .load_pinned(generation_id, &pinned.id, &pinned.revision)?
                }
                None => match self
                    .index
                    .current_for_model(&pinned.id, &pinned.revision, model)?
                {
                    Some(generation) => generation,
                    None => match self.index.newest(&pinned.id, model, false)? {
                        Some(generation) => generation,
                        None => continue,
                    },
                },
            };
            if !self
                .index
                .seal(&generation.generation_id, Some(MIRROR_BATCHES_PER_ROUND))?
            {
                mirroring += 1;
            } else if Some(&generation.embedding_model) == model {
                // Resume the durable pool first: a row mirrored before its
                // vector — the pre-pool text mirror, an outage-deferred
                // transfer — takes the canonical SQLite vector instead of
                // paying a re-embed, and an embedding Postgres already
                // holds stays canonical. A round that copied a batch
                // defers the generation's embedding leg to the next round:
                // rows the pool still covers take its vectors, never a
                // re-embed.
                let copied = self.index.transfer_missing_vectors(
                    &generation.generation_id,
                    &generation.embedding_model,
                )?;
                transferred += copied;
                if copied > 0 {
                    mirroring += 1;
                } else {
                    embeddable.push(generation.generation_id.to_string());
                }
            }
        }
        let Some(model) = model else {
            return Ok(mirroring);
        };
        if embeddable.is_empty() {
            return Ok(mirroring);
        }
        // Cache hits cost nothing, so a page reads well past the embed budget.
        let page = budget.saturating_mul(UNEMBEDDED_PAGE_FACTOR) as i64;
        let (chunks, pending) = postgres.unembedded(embeddable, page)?;
        let mut embedded: BTreeMap<String, Vec<(i64, Vec<f32>)>> = BTreeMap::new();
        // One request per distinct uncached text; every chunk sharing it
        // takes the same vector.
        let mut missing: BTreeMap<Digest, (String, Vec<(String, i64)>)> = BTreeMap::new();
        let mut cached = 0_usize;
        for chunk in chunks {
            let text_digest = Digest::hash(chunk.text.as_bytes());
            if let Some(dims) = self.index.cached_chunk_vector(model, &text_digest)? {
                cached += 1;
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
        let mut count = 0_usize;
        if !missing.is_empty() {
            let texts: Vec<String> = missing.values().map(|(text, _)| text.clone()).collect();
            match embedder(&texts) {
                Ok(vectors) => {
                    count = vectors.len();
                    for ((text_digest, (_, rows)), vector) in missing.into_iter().zip(vectors) {
                        self.index
                            .cache_chunk_vector(model, &text_digest, vector.dims())?;
                        for (generation, ordinal) in rows {
                            embedded
                                .entry(generation)
                                .or_default()
                                .push((ordinal, vector.dims().to_vec()));
                        }
                    }
                }
                Err(BrainError::EmbeddingUnavailable { reason, .. }) => {
                    tracing::debug!(%reason, "postgres warm embedding unavailable");
                }
                Err(error) => return Err(error),
            }
        }
        for (generation, rows) in embedded {
            postgres.insert_embeddings(&generation, model.as_str(), rows)?;
        }
        if count > 0 || cached > 0 || transferred > 0 {
            tracing::debug!(
                embedded = count,
                cached,
                pool_transferred = transferred,
                pending_generations = pending,
                "postgres warm"
            );
        }
        Ok(mirroring + pending)
    }
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
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use odin_domain::huginn::ids::ModelName;
    use odin_domain::knowledge::ids::{EmbeddingModelId, KnowledgeChunkId};
    use odin_domain::knowledge::retrieval::{ModelDescriptor, TrustClass};
    use odin_domain::knowledge::{EmbeddingBackend, PrivacyClass};
    use odin_domain::Digest;
    use odin_ledger::Ledger;
    use odin_registry::schema::{
        AccountingWindowToml, ApprovalDefaultToml, ApprovalDefaultsToml, BudgetPolicyToml,
        RegistryKind, SeatKnowledgeToml, SeatLimitsToml, SeatToml, SliceKnowledgeToml,
        SliceRedirectsToml, SliceToml, REGISTRY_SCHEMA,
    };

    use super::*;
    use crate::config::EffectiveBrainPolicy;
    use crate::context::PinnedTokenizer;
    use crate::index::build::{build_index, build_index_with_embedding_model, Chunker};
    use crate::index::postgres::EMBEDDING_DIMS;
    use crate::index::store::IndexStore;
    use crate::postgres_test_cluster::TestCluster;
    use crate::retrieval::embedding::EmbeddingVector;
    use crate::service::{BrainServiceConfig, BrainSourceConfig};
    use crate::source::SourceItem;

    fn psql(cluster: &TestCluster, sql: &str) -> String {
        let output = Command::new("psql")
            .args([&cluster.conninfo, "-tAc", sql])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

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
                schema: REGISTRY_SCHEMA.to_owned(),
                kind: RegistryKind::Seat,
                enabled: true,
                description: "turn gate fixture seat".to_owned(),
                categories: BTreeSet::new(),
                project_scope: BTreeSet::new(),
                read_project_scope: BTreeSet::new(),
                models: Vec::new(),
                tool_refs: BTreeSet::new(),
                approval_defaults: ApprovalDefaultsToml {
                    r0: ApprovalDefaultToml::Auto,
                    r1: ApprovalDefaultToml::Auto,
                    r2: ApprovalDefaultToml::Auto,
                    r3: ApprovalDefaultToml::Auto,
                },
                brain_scope: authorized.into_iter().cloned().collect(),
                limits: SeatLimitsToml {
                    max_parallel_runs: 4,
                    max_sessions: 4,
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

    /// Two generations carrying the same chunk texts cost one embedding per
    /// distinct text: the second takes the cached vectors.
    #[test]
    fn warm_embeds_each_distinct_chunk_text_once() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = std::env::temp_dir().join(format!("odin-warm-cache-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let source = AtlasId::new("atlas:warm-cache").unwrap();
        let model = EmbeddingModelId::new("embedding.warm-cache.v1").unwrap();
        let text = (0..200).map(|word| format!("w{word} ")).collect::<String>();
        let chunker = Chunker::new(NonZeroU32::new(16).unwrap(), 0).unwrap();
        let mut pinned = Vec::new();
        let mut chunks = 0;
        {
            let store = IndexStore::open(&root)
                .unwrap()
                .with_postgres(Some(Arc::clone(&postgres)));
            for (epoch, revision) in [(1, &b"r1"[..]), (2, b"r2")] {
                let revision = Digest::hash(revision);
                let item = SourceItem::new(
                    source.clone(),
                    revision,
                    b"warm-cache-item",
                    TrustClass::Curated,
                    text.clone(),
                )
                .unwrap();
                let build = build_index_with_embedding_model(
                    source.clone(),
                    revision,
                    &[item],
                    &chunker,
                    model.clone(),
                )
                .unwrap();
                chunks = build.chunks.len();
                store.store(&build, epoch).unwrap();
                assert!(store.seal(&build.generation.generation_id, None).unwrap());
                pinned.push(PinnedSource {
                    id: source.clone(),
                    revision,
                    generation: Some(build.generation.generation_id),
                    items: Vec::new(),
                });
            }
        }
        let service = BrainService::open(
            BrainServiceConfig {
                store_root: root,
                sources: BTreeMap::from([(
                    source.clone(),
                    BrainSourceConfig::Withheld {
                        class: PrivacyClass::AplRestricted,
                    },
                )]),
                embedding_available: true,
                embedding_model: Some(model),
                archive_ingest_gate: None,
                postgres: Some(Arc::clone(&postgres)),
            },
            policy_for(Some(&source)),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap();
        let embedded = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&embedded);
        let embedder: Arc<QueryEmbedder> = Arc::new(move |texts: &[String]| {
            counted.fetch_add(texts.len(), Ordering::SeqCst);
            Ok(texts
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let mut dims = vec![0.0; EMBEDDING_DIMS];
                    dims[index % EMBEDDING_DIMS] = 1.0;
                    EmbeddingVector::from_dims(dims).unwrap()
                })
                .collect())
        });
        for _ in 0..10 {
            if service
                .warm_postgres(&postgres, &pinned, embedder.as_ref(), 4_096)
                .unwrap()
                == 0
            {
                break;
            }
        }
        assert_eq!(embedded.load(Ordering::SeqCst), chunks);
    }

    /// MEDIUM at the warm-pump level: a >1000-chunk generation whose text
    /// rows were mirrored before the durable pool takes ONLY pool vectors
    /// across warm rounds — the embedder is never called, and a round that
    /// copied a batch defers the generation's embedding leg to the next.
    #[test]
    fn warm_rounds_transfer_a_large_pool_without_any_embedding_calls() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = std::env::temp_dir().join(format!("odin-warm-resume-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let source = AtlasId::new("atlas:warm-resume").unwrap();
        let revision = Digest::hash(b"warm-resume");
        let model = EmbeddingModelId::new("embedding.warm-resume.v1").unwrap();
        let text =
            "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ".repeat(800);
        let items = vec![SourceItem::new(
            source.clone(),
            revision,
            b"warm-resume-item",
            TrustClass::Curated,
            text,
        )
        .unwrap()];
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index_with_embedding_model(
            source.clone(),
            revision,
            &items,
            &chunker,
            model.clone(),
        )
        .unwrap();
        assert!(
            build.chunks.len() > 1_000,
            "the pool must span several bounded batches: {}",
            build.chunks.len()
        );
        let id = build.generation.generation_id;

        // The text mirror seals before the pool exists; the pool then lands
        // in SQLite only, exactly like an outage-deferred transfer.
        {
            let store = IndexStore::open(&root)
                .unwrap()
                .with_postgres(Some(Arc::clone(&postgres)));
            store.store(&build, 7).unwrap();
            assert!(store.seal(&id, None).unwrap());
        }
        {
            let staging = IndexStore::open(&root).unwrap();
            let (_, chunks) = staging.load(&id).unwrap().unwrap();
            let pool: Vec<(KnowledgeChunkId, Vec<f32>)> = chunks
                .iter()
                .enumerate()
                .map(|(ordinal, chunk)| {
                    let mut dims = vec![0.0; EMBEDDING_DIMS];
                    dims[ordinal % EMBEDDING_DIMS] = 1.0;
                    (chunk.chunk_id, dims)
                })
                .collect();
            staging.store_vectors(&id, &model, &pool).unwrap();
        }

        let service = BrainService::open(
            BrainServiceConfig {
                store_root: root,
                sources: BTreeMap::from([(
                    source.clone(),
                    BrainSourceConfig::Withheld {
                        class: PrivacyClass::AplRestricted,
                    },
                )]),
                embedding_available: true,
                embedding_model: Some(model),
                archive_ingest_gate: None,
                postgres: Some(Arc::clone(&postgres)),
            },
            policy_for(Some(&source)),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let embedder: Arc<QueryEmbedder> = Arc::new(move |_query| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(BrainError::EmbeddingUnavailable {
                provider: "fixture-gateway".to_owned(),
                reason: "the durable pool must cover every mirrored row".to_owned(),
            })
        });
        let pinned = [PinnedSource {
            id: source,
            revision,
            generation: Some(id),
            items: Vec::new(),
        }];

        let mut rounds = 0_usize;
        loop {
            let pending = service
                .warm_postgres(&postgres, &pinned, embedder.as_ref(), 4_096)
                .unwrap();
            if pending == 0 {
                break;
            }
            rounds += 1;
            assert!(rounds < 20, "the pool resume must converge");
        }
        assert!(
            rounds > 1,
            "a copied batch must defer the embedding leg to a later round"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "rows the durable pool covers must never be re-embedded"
        );
    }

    /// MEDIUM: selection is the newest stored generation across BOTH
    /// stores. For one atlas/revision/model (two chunker configurations
    /// keep the generations distinct), an older sealed generation must not
    /// shadow a newer SQLite-only generation whose seal a PostgreSQL
    /// outage deferred: selection returns the newer one before warming,
    /// the warm pump seals the generation it selected, selection still
    /// returns the newer one after warming, and during an outage the
    /// newer one serves from SQLite.
    #[test]
    fn an_older_sealed_generation_never_shadows_a_newer_outage_deferred_one() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = std::env::temp_dir().join(format!("odin-shadow-seal-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let source = AtlasId::new("atlas:shadow-seal").unwrap();
        let revision = Digest::hash(b"shadow-seal");
        let text = "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ".repeat(3);
        let items = vec![SourceItem::new(
            source.clone(),
            revision,
            b"shadow-seal-item",
            TrustClass::Curated,
            text,
        )
        .unwrap()];

        // The older generation (coarse chunker, epoch 10) is stored and
        // sealed; the newer one (finer chunker, same revision and model,
        // epoch 20) is stored while PostgreSQL is unreachable, so its seal
        // is deferred.
        let older = {
            let store = IndexStore::open(&root)
                .unwrap()
                .with_postgres(Some(Arc::clone(&postgres)));
            let build = build_index(
                source.clone(),
                revision,
                &items,
                &Chunker::new(NonZeroU32::new(32).unwrap(), 8).unwrap(),
            )
            .unwrap();
            store.store(&build, 10).unwrap();
            assert!(store.seal(&build.generation.generation_id, None).unwrap());
            build.generation
        };
        let newer = {
            let outage = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
            outage.close_for_test();
            let store = IndexStore::open(&root).unwrap().with_postgres(Some(outage));
            let build = build_index(
                source.clone(),
                revision,
                &items,
                &Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap(),
            )
            .unwrap();
            store.store(&build, 20).unwrap();
            build.generation
        };
        assert_ne!(
            older.generation_id, newer.generation_id,
            "two chunker configurations over one revision build distinct generations"
        );
        assert_eq!(older.atlas_id, newer.atlas_id);
        assert_eq!(older.atlas_revision, newer.atlas_revision);
        assert_eq!(older.embedding_model, newer.embedding_model);

        let service = BrainService::open(
            BrainServiceConfig {
                store_root: root.clone(),
                sources: BTreeMap::new(),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: Some(Arc::clone(&postgres)),
            },
            policy_for(None),
            Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        )
        .unwrap();
        let select_newest = {
            let (source, revision) = (source.clone(), revision);
            move |store: &IndexStore| {
                store
                    .current_for_model(&source, &revision, None)
                    .unwrap()
                    .expect("a generation is stored")
                    .generation_id
            }
        };

        // Before warming: the newer, still-unsealed generation is selected
        // even though an older sealed generation exists — through the live
        // service store and a freshly opened one alike.
        assert_eq!(select_newest(&service.index), newer.generation_id);
        let cold = IndexStore::open(&root)
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        assert_eq!(select_newest(&cold), newer.generation_id);
        assert_eq!(
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_generation_header \
                     WHERE generation_id = '{}'",
                    newer.generation_id
                )
            ),
            "0",
            "the newer generation is genuinely unsealed before warming"
        );

        // Warming resolves through the same selector and therefore seals
        // the generation it selected — the newer one, not the older
        // already-sealed one.
        let pinned = [PinnedSource {
            id: source.clone(),
            revision,
            generation: None,
            items: Vec::new(),
        }];
        let embedder: Arc<QueryEmbedder> =
            Arc::new(|_query| panic!("the lexical-only warm never embeds"));
        let mut rounds = 0_usize;
        loop {
            let pending = service
                .warm_postgres(&postgres, &pinned, embedder.as_ref(), 4_096)
                .unwrap();
            if pending == 0 {
                break;
            }
            rounds += 1;
            assert!(rounds < 20, "the warm rounds must converge");
        }
        assert_eq!(
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_generation_header \
                     WHERE generation_id = '{}'",
                    newer.generation_id
                )
            ),
            "1",
            "the warm pump sealed the generation selection chose"
        );

        // After warming the newer generation is still the one served.
        assert_eq!(select_newest(&service.index), newer.generation_id);
        let cold = IndexStore::open(&root)
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        assert_eq!(select_newest(&cold), newer.generation_id);

        // During a PostgreSQL outage the newer generation still serves:
        // through the dead pool, a cold store, and a store without any
        // PostgreSQL store at all.
        postgres.close_for_test();
        assert_eq!(select_newest(&service.index), newer.generation_id);
        let outage_store = IndexStore::open(&root)
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        assert_eq!(select_newest(&outage_store), newer.generation_id);
        let reference = IndexStore::open(&root).unwrap();
        assert_eq!(select_newest(&reference), newer.generation_id);

        std::fs::remove_dir_all(&root).ok();
    }

    /// An item of a generation another seat's store built and sealed serves
    /// from PostgreSQL to a store whose SQLite file never held its rows.
    #[test]
    fn an_item_serves_from_a_generation_another_store_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let base = std::env::temp_dir().join(format!("odin-foreign-seal-{}", std::process::id()));
        std::fs::remove_dir_all(&base).ok();
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
        let builder = IndexStore::open(&base.join("builder"))
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        builder.store(&build, 1).unwrap();
        assert!(builder.seal(&build.generation.generation_id, None).unwrap());

        let service = BrainService::open(
            BrainServiceConfig {
                store_root: base.join("reader"),
                sources: BTreeMap::new(),
                embedding_available: false,
                embedding_model: None,
                archive_ingest_gate: None,
                postgres: Some(Arc::clone(&postgres)),
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

        std::fs::remove_dir_all(&base).ok();
    }
}
