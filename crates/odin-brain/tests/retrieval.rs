//! Behavior tests for the generation-bound embedding vector pool and the
//! persistent lexical BM25 scores in the exact index store.
//!
//! Every vector here is a plain mathematical function of its chunk's
//! ordinal — there is no provider, no mocked embedding authority, and the
//! store itself never fabricates: the pool only ever contains what the test
//! explicitly stored, exactly as real kernel-authorized embeddings would
//! arrive from the lease-governed transport.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::path::PathBuf;

use odin_brain::error::{BrainError, BrainResult};
use odin_brain::index::build::{build_index_with_embedding_model, Chunker, IndexBuild};
use odin_brain::index::store::{IndexStore, StoreOutcome, StoredVectors};
use odin_brain::retrieval::embedding::EmbeddingVector;
use odin_brain::retrieval::{
    fuse_and_rank, score_vector, take_top, RetrievalPlan, Retriever, ScoredCandidate,
};
use odin_brain::source::SourceItem;
use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId, RelevanceScore,
};
use odin_domain::knowledge::retrieval::{
    Citation, IndexedChunk, RetrievalMode, RetrievalQuery, TrustClass,
};
use odin_domain::Digest;
use rusqlite::{params, Connection};

const SOURCE: &str = "atlas:vectortest";
const DIM: usize = 3;

/// Explicit declared embedding model for this fixture. The mathematical
/// vectors below exercise vector storage against a generation stamped with
/// this model — they are storage payloads, not a stand-in provider — so the
/// fixture generation is never falsely pinned to the lexical-only
/// `NO_EMBEDDING_MODEL` stamp.
const TEST_EMBEDDING_MODEL: &str = "test:math-vectors-v1";

/// Deterministic mathematical vector for a chunk ordinal: distinct first
/// dimension per chunk, constant dimension count, entirely finite. Cosine
/// similarity against `[1.0, 0.0, 0.0]` is strictly increasing in the
/// ordinal, so the expected ranking is computable by hand.
fn vector_for(ordinal: usize) -> Vec<f32> {
    let mut dims = vec![0.0_f32; DIM];
    dims[0] = (ordinal + 1) as f32;
    dims[1] = 1.0;
    dims
}

/// Expected cosine of `vector_for(ordinal)` against the unit query axis.
fn expected_cosine(ordinal: usize) -> f64 {
    let leading = (ordinal + 1) as f64;
    leading / (leading * leading + 1.0).sqrt()
}

/// One vector per stored chunk, keyed by exact chunk identity.
fn pool(chunks: &[IndexedChunk]) -> Vec<(KnowledgeChunkId, Vec<f32>)> {
    chunks
        .iter()
        .enumerate()
        .map(|(ordinal, chunk)| (chunk.chunk_id, vector_for(ordinal)))
        .collect()
}

/// Isolated store root with one stored generation built by the production
/// model-stamped path, pinned to `TEST_EMBEDDING_MODEL`.
fn stored_generation(name: &str) -> BrainResult<(IndexStore, IndexBuild, PathBuf)> {
    let root = temp_root(name);
    let store = IndexStore::open(&root)?;
    let chunker = Chunker::new(NonZeroU32::new(4).expect("nonzero"), 1)?;
    let atlas_id = AtlasId::new(SOURCE)?;
    let revision = Digest::hash(b"pinned-revision");
    let items = vec![
        SourceItem::new(
            atlas_id.clone(),
            revision,
            b"item:alpha",
            TrustClass::Curated,
            "alpha one two three four five six seven eight nine ten eleven twelve thirteen fourteen",
        )?,
        SourceItem::new(
            atlas_id.clone(),
            revision,
            b"item:beta",
            TrustClass::Observed,
            "beta one two three four five six seven eight nine ten eleven twelve thirteen fourteen",
        )?,
    ];
    let build = build_index_with_embedding_model(
        atlas_id,
        revision,
        &items,
        &chunker,
        EmbeddingModelId::new(TEST_EMBEDDING_MODEL)?,
    )?;
    store.store(&build, 1)?;
    Ok((store, build, root))
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "odin-brain-retrieval-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    root
}

/// A bare persistent index store at an isolated root: the exact store the
/// service scores lexical candidates through.
fn scoring_store(name: &str) -> BrainResult<IndexStore> {
    IndexStore::open(&temp_root(name))
}

/// Scores `chunks` exactly as a turn does: stored as one generation, its
/// persistent BM25 index built, the top matches mapped back to the chunks.
fn lexical_scores(
    store: &IndexStore,
    query: &RetrievalQuery,
    chunks: &[IndexedChunk],
) -> BrainResult<BTreeMap<KnowledgeChunkId, RelevanceScore>> {
    let mut stream = chunks
        .iter()
        .cloned()
        .map(|mut chunk| {
            chunk.digest = Digest::hash(chunk.text.as_bytes());
            Ok(chunk)
        })
        .collect::<Vec<_>>()
        .into_iter();
    let (generation, _) = store.store_streaming(
        AtlasId::new(SOURCE)?,
        Digest::hash(b"rank-revision"),
        &EmbeddingModelId::new(odin_brain::index::build::NO_EMBEDDING_MODEL)?,
        1,
        &mut stream,
        &BTreeMap::new(),
    )?;
    store.build_generation_lexical(&generation.generation_id)?;
    Ok(store
        .generation_lexical_top(&generation.generation_id, query, chunks.len().max(1))?
        .into_iter()
        .map(|(ordinal, score)| (chunks[ordinal as usize].chunk_id, score))
        .collect())
}

#[test]
fn vector_pool_round_trips_exact_and_scores_consistently() -> BrainResult<()> {
    let (store, build, _root) = stored_generation("round-trip")?;
    assert!(build.chunks.len() >= 2, "fixture must yield several chunks");
    let generation_id = build.generation.generation_id;

    // Nothing stored yet: None means embed-now, never an empty result set.
    assert!(store.load_vectors(&generation_id)?.is_none());

    let offered = pool(&build.chunks);
    assert_eq!(
        store.store_vectors(&generation_id, &build.generation.embedding_model, &offered)?,
        StoreOutcome::Stored
    );
    // Insert-only: identical re-store is an idempotent no-op.
    assert_eq!(
        store.store_vectors(&generation_id, &build.generation.embedding_model, &offered)?,
        StoreOutcome::AlreadyPresent
    );
    // Re-embedding need not reproduce floats; the first valid pool remains canonical.
    let reembedded: Vec<_> = offered
        .iter()
        .map(|(chunk, dims)| (*chunk, dims.iter().map(|value| value * 1.001).collect()))
        .collect();
    assert_eq!(
        store.store_vectors(
            &generation_id,
            &build.generation.embedding_model,
            &reembedded
        )?,
        StoreOutcome::AlreadyPresent
    );

    let StoredVectors {
        embedding_model,
        vectors,
    } = store
        .load_vectors(&generation_id)?
        .expect("pool was stored above");
    // The pool is bound to the generation's pinned, immutable model stamp.
    assert_eq!(embedding_model.as_str(), TEST_EMBEDDING_MODEL);
    assert_eq!(vectors.len(), build.chunks.len());
    // Exact ordinal alignment and exact mathematical values.
    for (ordinal, vector) in vectors.iter().enumerate() {
        assert_eq!(vector.dims().len(), DIM);
        assert_eq!(vector.dims(), vector_for(ordinal).as_slice());
    }

    // Retrieval candidate consistency: zipping load()'s chunk order with
    // the pool yields the hand-computable cosine ranking.
    let candidates: BTreeMap<KnowledgeChunkId, EmbeddingVector> = build
        .chunks
        .iter()
        .cloned()
        .zip(vectors.iter().cloned())
        .map(|(chunk, vector)| (chunk.chunk_id, vector))
        .collect();
    let query = EmbeddingVector::from_dims(vec![1.0, 0.0, 0.0])?;
    for (ordinal, chunk) in build.chunks.iter().enumerate() {
        let cosine = candidates[&chunk.chunk_id].cosine_similarity(&query)?;
        assert!(
            (cosine - expected_cosine(ordinal)).abs() < 1e-6,
            "cosine for ordinal {ordinal}: {cosine}"
        );
    }
    let scored = score_vector(&query, &candidates, &build.chunks)?;
    assert!(!scored.is_empty());
    // Cosine is strictly increasing in the leading dimension. Best-first
    // order is take_top's frozen contract (score descending, provenance
    // ascending): the last chunk must rank first, the second-to-last
    // second.
    let count = u16::try_from(scored.len()).expect("chunk count fits u16");
    let ranked = take_top(scored, NonZeroU16::new(count).expect("nonzero"));
    assert_eq!(
        ranked[0].chunk.chunk_id,
        build.chunks.last().expect("non-empty").chunk_id
    );
    assert_eq!(
        ranked[1].chunk.chunk_id,
        build.chunks[build.chunks.len() - 2].chunk_id
    );
    Ok(())
}

#[test]
fn vector_pool_rejects_every_inexact_binding() -> BrainResult<()> {
    let (store, build, _root) = stored_generation("reject")?;
    let generation_id = build.generation.generation_id;
    let model = &build.generation.embedding_model;
    let full = pool(&build.chunks);

    // An empty pool is never a storable outcome.
    assert!(matches!(
        store.store_vectors(&generation_id, model, &[]),
        Err(BrainError::InvalidRequest(_))
    ));

    // Unknown generation: nothing to bind to.
    let stray = IndexGenerationId::new(Digest::hash(b"stray-generation"));
    assert!(matches!(
        store.store_vectors(&stray, model, &full),
        Err(BrainError::NotFound {
            kind: "index generation",
            ..
        })
    ));

    // Model drift is refused as a stale authority, never absorbed.
    let other_model = EmbeddingModelId::new("test:other-model-v1")?;
    assert!(matches!(
        store.store_vectors(&generation_id, &other_model, &full),
        Err(BrainError::StaleAuthority {
            authority: "embedding_model",
            ..
        })
    ));

    // Missing one vector: a partial pool is refused outright.
    let partial: Vec<_> = full[..full.len() - 1].to_vec();
    assert!(matches!(
        store.store_vectors(&generation_id, model, &partial),
        Err(BrainError::InvalidRequest(_))
    ));

    // An extra vector that belongs to no stored chunk is refused.
    let mut extra = full.clone();
    extra.push((
        KnowledgeChunkId::new(Digest::hash(b"not-a-chunk")),
        vector_for(0),
    ));
    assert!(matches!(
        store.store_vectors(&generation_id, model, &extra),
        Err(BrainError::InvalidRequest(_))
    ));

    // A chunk offered twice is refused.
    let mut duplicated = full.clone();
    duplicated.push((full[0].0, vector_for(0)));
    assert!(matches!(
        store.store_vectors(&generation_id, model, &duplicated),
        Err(BrainError::InvalidRequest(_))
    ));

    // Ragged, empty, and non-finite dimensions are never embeddings.
    let mut ragged = full.clone();
    ragged[0].1 = vec![1.0];
    assert!(matches!(
        store.store_vectors(&generation_id, model, &ragged),
        Err(BrainError::InvalidRequest(_))
    ));
    let mut empty_dims = full.clone();
    empty_dims[0].1 = Vec::new();
    assert!(matches!(
        store.store_vectors(&generation_id, model, &empty_dims),
        Err(BrainError::InvalidRequest(_))
    ));
    let mut nonfinite = full.clone();
    nonfinite[0].1 = vec![f32::NAN, 1.0, 0.0];
    assert!(matches!(
        store.store_vectors(&generation_id, model, &nonfinite),
        Err(BrainError::InvalidRequest(_))
    ));

    // Every rejection was atomic: nothing was written, the path stays
    // embed-now — and the exact pool still stores cleanly afterwards.
    assert!(store.load_vectors(&generation_id)?.is_none());
    assert_eq!(
        store.store_vectors(&generation_id, model, &full)?,
        StoreOutcome::Stored
    );
    Ok(())
}

#[test]
fn vector_pool_detects_storage_corruption_and_retires_cleanly() -> BrainResult<()> {
    let (store, build, root) = stored_generation("corrupt")?;
    let generation_id = build.generation.generation_id;
    let model = build.generation.embedding_model.clone();
    let full = pool(&build.chunks);
    assert_eq!(
        store.store_vectors(&generation_id, &model, &full)?,
        StoreOutcome::Stored
    );

    let database = Connection::open(root.join("brain-index.sqlite3"))?;

    // Tamper one stored blob into a non-finite run: it is never served.
    database.execute(
        "UPDATE brain_index_vector SET dims = ?1 WHERE ordinal = 0",
        params![vec![0x00u8, 0x00, 0xC0, 0x7F]], // f32 NaN, little-endian
    )?;
    assert!(matches!(
        store.load_vectors(&generation_id),
        Err(BrainError::Corrupt { .. })
    ));
    // Immutable pool: re-storing the original vectors now diverges.
    assert!(matches!(
        store.store_vectors(&generation_id, &model, &full),
        Err(BrainError::Corrupt { .. })
    ));

    // A truncated blob is not a whole f32 run.
    database.execute(
        "UPDATE brain_index_vector SET dims = X'0000' WHERE ordinal = 0",
        [],
    )?;
    assert!(matches!(
        store.load_vectors(&generation_id),
        Err(BrainError::Corrupt { .. })
    ));

    // Tampering with pinned chunk content fails generation verification
    // before any vector is handed out.
    database.execute(
        "UPDATE brain_index_chunk SET text = text || ' tampered' WHERE ordinal = 0",
        [],
    )?;
    assert!(matches!(
        store.load_vectors(&generation_id),
        Err(BrainError::Corrupt { .. })
    ));

    // Learning rollback drops the pool together with its generation.
    assert!(store.retire(&generation_id)?);
    assert!(store.load(&generation_id)?.is_none());
    assert!(store.load_vectors(&generation_id)?.is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// Lexical scoring through the persistent index store, and frozen-order
// fusion: the scoring contracts.
// ---------------------------------------------------------------------------

/// Builds one deterministic chunk: distinct item/chunk/digest identity per
/// seed, explicit trust, and a plain lineage-free citation.
fn rank_chunk(seed: &str, trust: TrustClass, text: &str) -> IndexedChunk {
    let source = AtlasId::new(SOURCE).expect("valid atlas id");
    let item_id = KnowledgeItemId::new(Digest::hash(format!("{seed}:item").as_bytes()));
    let citation = Citation::new(
        source,
        Digest::hash(b"rank-revision"),
        item_id,
        None,
        None,
        None,
        None,
        0,
        text.len() as u64,
    )
    .expect("valid citation");
    IndexedChunk {
        item_id,
        chunk_id: KnowledgeChunkId::new(Digest::hash(format!("{seed}:chunk").as_bytes())),
        trust,
        text: text.to_owned(),
        digest: Digest::hash(format!("{seed}:digest").as_bytes()),
        citation,
    }
}

/// One manually scored candidate; the score is raw millionths.
fn scored(chunk: IndexedChunk, score: u32) -> ScoredCandidate {
    ScoredCandidate {
        chunk,
        score: RelevanceScore::new(score).expect("valid score"),
    }
}

/// A hybrid-mode plan over the shared fixture source with explicit score and
/// top-k budgets.
fn fusion_plan(min_score: u32, top_k: u16) -> RetrievalPlan {
    let mut sources = BTreeSet::new();
    sources.insert(AtlasId::new(SOURCE).expect("valid atlas id"));
    let mut allowed_trust = BTreeSet::new();
    allowed_trust.insert(TrustClass::Curated);
    allowed_trust.insert(TrustClass::Observed);
    let query = RetrievalQuery::new(
        "alpha gamma".to_owned(),
        sources,
        BTreeSet::new(),
        BTreeSet::new(),
        allowed_trust,
        NonZeroU16::new(8).expect("nonzero"),
        NonZeroU16::new(top_k).expect("nonzero"),
        RelevanceScore::new(min_score).expect("valid score"),
    )
    .expect("valid retrieval query");
    RetrievalPlan::new(query, RetrievalMode::Hybrid)
}

/// Lexical relevance is the persistent index's BM25 score: matches score
/// above zero and both-term matches outrank single-term matches, misses are
/// absent from the map, and term-less queries are a typed caller error.
#[test]
fn lexical_scores_rank_matches_above_misses_in_the_persistent_index() -> BrainResult<()> {
    let store = scoring_store("lexical-scores")?;
    let query = fusion_plan(0, 4).query().clone();
    // alpha and gamma each appear in exactly two of five documents, so
    // both terms carry strictly positive IDF.
    let chunks = [
        rank_chunk("alpha", TrustClass::Curated, "alpha one"),
        rank_chunk("gamma", TrustClass::Curated, "gamma one"),
        rank_chunk("both", TrustClass::Curated, "alpha gamma one"),
        rank_chunk("delta", TrustClass::Curated, "delta one"),
        rank_chunk("echo", TrustClass::Curated, "echo one"),
    ];

    let scores = lexical_scores(&store, &query, &chunks)?;

    // Exactly the matching chunks are scored; the misses are absent.
    assert_eq!(scores.len(), 3);
    assert!(!scores.contains_key(&chunks[3].chunk_id));
    assert!(!scores.contains_key(&chunks[4].chunk_id));
    let alpha = scores[&chunks[0].chunk_id].get();
    let gamma = scores[&chunks[1].chunk_id].get();
    let both = scores[&chunks[2].chunk_id].get();
    assert!(alpha > 0 && gamma > 0, "a matched chunk scores above zero");
    assert!(
        both > alpha && both > gamma,
        "matching both query terms outranks either single-term match"
    );

    // The retriever path at the floor quantum: zero-filled misses fall
    // under min_score and only genuine matches serve, each under the
    // citation of its own chunk.
    let vectors: BTreeMap<KnowledgeChunkId, EmbeddingVector> = BTreeMap::new();
    let plan = RetrievalPlan::new(fusion_plan(1, 4).query().clone(), RetrievalMode::Lexical);
    let hits = Retriever::new(plan, &chunks, &vectors, &scores).retrieve()?;
    assert_eq!(hits.len(), 3);
    let served: BTreeSet<KnowledgeItemId> = hits.iter().map(|hit| hit.item_id).collect();
    assert!(served.contains(&chunks[0].item_id));
    assert!(served.contains(&chunks[1].item_id));
    assert!(served.contains(&chunks[2].item_id));
    assert!(!served.contains(&chunks[3].item_id));
    assert!(!served.contains(&chunks[4].item_id));
    let both_hit = hits
        .iter()
        .find(|hit| hit.item_id == chunks[2].item_id)
        .expect("the both-term match serves");
    assert_eq!(both_hit.source, chunks[2].citation.source);
    assert_eq!(both_hit.citation.item_id, chunks[2].item_id);
    assert_eq!(both_hit.content, chunks[2].text);
    assert_eq!(both_hit.content_digest, chunks[2].digest);
    assert!(both_hit.score.get() >= 1);

    // All-unmatched: an empty score map serves nothing.
    let mut unmatched = fusion_plan(1, 4).query().clone();
    unmatched.text = "3f9c1a70-2222-4333-8444-555566667777".to_owned();
    let empty = lexical_scores(&store, &unmatched, &chunks)?;
    assert!(empty.is_empty());
    let plan = RetrievalPlan::new(unmatched, RetrievalMode::Lexical);
    assert!(Retriever::new(plan, &chunks, &vectors, &empty)
        .retrieve()?
        .is_empty());

    // A query whose text has no lexical terms is a caller bug, not an
    // empty result set: the store rejects it typed.
    let mut symbol_query = fusion_plan(0, 4).query().clone();
    symbol_query.text = "!!! --- !!!".to_owned();
    assert!(matches!(
        lexical_scores(&store, &symbol_query, &chunks),
        Err(BrainError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn take_top_truncates_and_breaks_score_ties_by_provenance() {
    let low = scored(rank_chunk("a", TrustClass::Curated, "alpha one"), 900_000);
    let tie_one = scored(rank_chunk("b", TrustClass::Curated, "gamma one"), 700_000);
    let tie_two = scored(rank_chunk("c", TrustClass::Curated, "delta one"), 700_000);
    // Identity is digest-backed and Copy: capture expectations before the
    // candidates move into take_top, with no needless clones.
    let low_id = low.chunk.chunk_id;
    let expected_tie_id = if tie_one.chunk.item_id < tie_two.chunk.item_id {
        tie_one.chunk.item_id
    } else {
        tie_two.chunk.item_id
    };
    let top = take_top(vec![tie_two, low, tie_one], NonZeroU16::new(2).unwrap());
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].chunk.chunk_id, low_id);
    // Equal scores fall back to ascending item identity.
    assert_eq!(top[1].chunk.item_id, expected_tie_id);
}

#[test]
fn fusion_applies_frozen_mean_min_dedup_and_top_k() -> BrainResult<()> {
    let plan = fusion_plan(500_000, 3);
    let lexical_only = rank_chunk("lex", TrustClass::Curated, "alpha one");
    let both = rank_chunk("mean", TrustClass::Curated, "alpha gamma one");
    let vector_only = rank_chunk("vec", TrustClass::Curated, "gamma one");
    let low = rank_chunk("low", TrustClass::Curated, "alpha one");
    let duplicate_one = rank_chunk("dup", TrustClass::Curated, "alpha gamma one");
    let mut duplicate_two = rank_chunk("dup", TrustClass::Curated, "alpha gamma one");
    // Same content digest, different chunk identity: exactly one survives.
    duplicate_two.chunk_id = KnowledgeChunkId::new(Digest::hash(b"dup:chunk-two"));

    let lexical = vec![
        scored(lexical_only.clone(), 900_000),
        scored(both.clone(), 800_000),
        scored(low.clone(), 100_000),
        scored(duplicate_one.clone(), 850_000),
        scored(duplicate_two, 850_000),
    ];
    let vector = vec![
        scored(both.clone(), 600_000),
        scored(vector_only.clone(), 600_000),
    ];

    let hits = fuse_and_rank(&plan, lexical, vector)?;

    // 900_000 > dup 850_000 (one copy) > dual-signal mean 700_000. The
    // 600_000 candidates fell below top_k = 3, the 100_000 candidate below
    // min_score, and the single-signal scores are not diluted.
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[0].item_id, lexical_only.item_id);
    assert_eq!(hits[0].score.get(), 900_000);
    assert_eq!(hits[1].content_digest, duplicate_one.digest);
    assert_eq!(hits[1].score.get(), 850_000);
    assert_eq!(hits[2].item_id, both.item_id);
    assert_eq!(hits[2].score.get(), 700_000);
    let surviving: BTreeSet<KnowledgeItemId> = hits.iter().map(|hit| hit.item_id).collect();
    assert!(!surviving.contains(&low.item_id));
    assert!(!surviving.contains(&vector_only.item_id));
    Ok(())
}

#[test]
fn fusion_orders_trust_below_score_and_revalidates_filters() -> BrainResult<()> {
    // Equal scores: the frozen ordering key ranks the more-trusted hit first.
    let plan = fusion_plan(0, 4);
    let curated = rank_chunk("curated", TrustClass::Curated, "alpha one");
    let observed = rank_chunk("observed", TrustClass::Observed, "alpha one");
    let hits = fuse_and_rank(
        &plan,
        vec![
            scored(observed.clone(), 700_000),
            scored(curated.clone(), 700_000),
        ],
        Vec::new(),
    )?;
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].trust, TrustClass::Curated);
    assert_eq!(hits[1].trust, TrustClass::Observed);

    // A hit outside the query's trust filter is a typed policy failure,
    // never a silently kept or silently dropped row.
    let mut curated_only = BTreeSet::new();
    curated_only.insert(TrustClass::Curated);
    let mut strict_query = fusion_plan(0, 4).query().clone();
    strict_query.allowed_trust = curated_only;
    let strict = RetrievalPlan::new(strict_query, RetrievalMode::Lexical);
    let observed_hit = rank_chunk("observed", TrustClass::Observed, "alpha one");
    assert!(matches!(
        fuse_and_rank(&strict, vec![scored(observed_hit, 900_000)], Vec::new()),
        Err(BrainError::Domain(_))
    ));
    Ok(())
}

/// Reuse keeps the first vector recorded for the same model and text.
#[test]
fn chunk_vector_cache_is_keyed_by_model_and_text() -> BrainResult<()> {
    let store = IndexStore::open(&temp_root("chunk-vector-cache"))?;
    let model = EmbeddingModelId::new(TEST_EMBEDDING_MODEL)?;
    let other = EmbeddingModelId::new("test:other-model-v1")?;
    let text = Digest::hash(b"session sinmara running");
    assert_eq!(store.cached_chunk_vector(&model, &text)?, None);
    store.cache_chunk_vector(&model, &text, &vector_for(1))?;
    assert_eq!(
        store.cached_chunk_vector(&model, &text)?,
        Some(vector_for(1))
    );
    assert_eq!(
        store.cached_chunk_vector(&other, &text)?,
        None,
        "a different embedding model never reuses the vector"
    );
    store.cache_chunk_vector(&model, &text, &vector_for(2))?;
    assert_eq!(
        store.cached_chunk_vector(&model, &text)?,
        Some(vector_for(1)),
        "insert-only: the first recorded vector for a text is kept"
    );
    assert!(store
        .cache_chunk_vector(&model, &Digest::hash(b"nan"), &[f32::NAN])
        .is_err());
    Ok(())
}

/// BM25 sums only over the terms a chunk actually matches: opaque identity
/// tokens that match no document leave every score untouched, and an
/// all-unmatched query yields an empty map, never a failure.
#[test]
fn unmatchable_query_terms_neither_suppress_nor_fail_a_match() -> BrainResult<()> {
    let store = scoring_store("unmatched-terms")?;
    let chunks = [
        rank_chunk("alpha", TrustClass::Curated, "alpha one"),
        rank_chunk("both", TrustClass::Curated, "alpha gamma one"),
    ];
    let plain = fusion_plan(0, 4).query().clone();
    let scores = |query: &RetrievalQuery| -> BrainResult<BTreeMap<KnowledgeChunkId, u32>> {
        Ok(lexical_scores(&store, query, &chunks)?
            .into_iter()
            .map(|(chunk_id, score)| (chunk_id, score.get()))
            .collect())
    };
    let baseline = scores(&plain)?;

    let mut constrained = plain.clone();
    constrained.text = "alpha gamma 3f9c1a70-2222-4333-8444-555566667777 \
                        2026-01-02T03:04:05.678901Z <FIXTURE-Ab3D@mail.example.test>"
        .to_owned();
    assert_eq!(
        scores(&constrained)?,
        baseline,
        "opaque constraint tokens that match no document must not move a match"
    );

    let mut unmatched = plain.clone();
    unmatched.text = "3f9c1a70-2222-4333-8444-555566667777".to_owned();
    assert!(
        scores(&unmatched)?.is_empty(),
        "a query nothing can match yields no scored candidates, never an error"
    );
    Ok(())
}

/// Small scopes and ubiquitous terms stay measured: floor-clamped scores
/// serve or fall under min_score like any other score — never inflated,
/// never special-cased.
#[test]
fn tiny_scopes_and_ubiquitous_terms_stay_measured_not_special_cased() -> BrainResult<()> {
    let store = scoring_store("tiny-scope")?;
    let vectors: BTreeMap<KnowledgeChunkId, EmbeddingVector> = BTreeMap::new();

    // One-record scope: the floor-clamped match still serves its record.
    let solo = rank_chunk("solo", TrustClass::Curated, "alpha one");
    let mut solo_query = fusion_plan(1, 4).query().clone();
    solo_query.text = "alpha".to_owned();
    let solo_scores = lexical_scores(&store, &solo_query, std::slice::from_ref(&solo))?;
    assert_eq!(solo_scores.len(), 1);
    let plan = RetrievalPlan::new(solo_query.clone(), RetrievalMode::Lexical);
    let hits =
        Retriever::new(plan, std::slice::from_ref(&solo), &vectors, &solo_scores).retrieve()?;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item_id, solo.item_id);
    assert_eq!(hits[0].content, solo.text);
    assert_eq!(hits[0].citation.source, solo.citation.source);
    assert!(hits[0].score.get() >= 1);

    // A ubiquitous term scores every candidate instead of being dropped.
    let chunks = [
        rank_chunk("short", TrustClass::Curated, "ubiq one"),
        rank_chunk("long", TrustClass::Curated, "ubiq one two three"),
    ];
    let mut ubiq_query = fusion_plan(0, 4).query().clone();
    ubiq_query.text = "ubiq".to_owned();
    let ubiq_scores = lexical_scores(&store, &ubiq_query, &chunks)?;
    assert_eq!(ubiq_scores.len(), chunks.len());
    assert!(ubiq_scores.values().all(|score| score.get() > 0));

    // All-unmatched: nothing serves.
    let mut unmatched = solo_query;
    unmatched.text = "3f9c1a70-2222-4333-8444-555566667777".to_owned();
    let empty = lexical_scores(&store, &unmatched, std::slice::from_ref(&solo))?;
    assert!(empty.is_empty());
    let plan = RetrievalPlan::new(unmatched, RetrievalMode::Lexical);
    assert!(Retriever::new(plan, &[solo], &vectors, &empty)
        .retrieve()?
        .is_empty());
    Ok(())
}

#[test]
fn model_aware_selection_never_pins_a_divergent_stamp_generation() -> BrainResult<()> {
    let (store, build, _root) = stored_generation("model-aware-selection")?;
    let atlas_id = build.generation.atlas_id.clone();
    let revision = build.generation.atlas_revision;

    // Unfiltered selection still returns the stored generation (history).
    assert!(store.current(&atlas_id, &revision)?.is_some());

    // A DIFFERENT declared effective model: the old-stamp generation must
    // NOT win — the caller builds a fresh generation under the declared
    // model instead of serving (and later refusing) stale authority.
    let new_model = EmbeddingModelId::new("wemm-embedding:wemm-im-user-v1")?;
    assert!(
        store
            .current_for_model(&atlas_id, &revision, Some(&new_model))?
            .is_none(),
        "a divergent-stamp generation must never win the model-aware pin"
    );

    // Build and store the new-stamp generation for the same (atlas,
    // revision): it now wins the model-aware pin, and the old one still
    // wins the unfiltered lookup.
    let chunker = Chunker::new(NonZeroU32::new(4).expect("nonzero"), 1)?;
    let twin = build_index_with_embedding_model(
        atlas_id.clone(),
        revision,
        &[
            SourceItem::new(
                atlas_id.clone(),
                revision,
                b"item:alpha",
                TrustClass::Curated,
                "alpha one two three four five six seven eight nine ten eleven twelve thirteen fourteen",
            )?,
            SourceItem::new(
                atlas_id.clone(),
                revision,
                b"item:beta",
                TrustClass::Observed,
                "beta one two three four five six seven eight nine ten eleven twelve thirteen fourteen",
            )?,
        ],
        &chunker,
        new_model.clone(),
    )?;
    store.store(&twin, 2)?;
    let selected = store
        .current_for_model(&atlas_id, &revision, Some(&new_model))?
        .expect("the matching-stamp generation wins");
    assert_eq!(selected.generation_id, twin.generation.generation_id);
    assert_eq!(selected.embedding_model.as_str(), new_model.as_str());
    // History remains loadable by its exact id; the unfiltered newest
    // lookup now returns the twin (created later), which is correct.
    let historic = store.load_pinned(&build.generation.generation_id, &atlas_id, &revision)?;
    assert_eq!(
        historic.embedding_model.as_str(),
        build.generation.embedding_model.as_str()
    );
    Ok(())
}
