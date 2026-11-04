//! The frozen hit order a turn's candidates rank by, and the model-aware
//! generation selection a turn pins.

use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::num::NonZeroU32;

use odin_brain::error::BrainResult;
use odin_brain::index::build::{build_index_with_embedding_model, Chunker, IndexBuild};
use odin_brain::index::store::IndexStore;
use odin_brain::retrieval::{rank, RetrievalPlan, ScoredCandidate};
use odin_brain::source::SourceItem;
use odin_brain::test_cluster::TestCluster;
use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, KnowledgeChunkId, KnowledgeItemId, RelevanceScore,
};
use odin_domain::knowledge::retrieval::{
    Citation, IndexedChunk, RetrievalMode, RetrievalQuery, TrustClass,
};
use odin_domain::Digest;

const SOURCE: &str = "atlas:vectortest";

/// The declared embedding model the fixture generation is stamped with.
const TEST_EMBEDDING_MODEL: &str = "test:math-vectors-v1";

/// The two items every generation of this suite indexes.
fn fixture_items(atlas_id: &AtlasId, revision: Digest) -> BrainResult<Vec<SourceItem>> {
    Ok(vec![
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
    ])
}

/// Isolated store root with one stored generation built by the production
/// model-stamped path, pinned to `TEST_EMBEDDING_MODEL`.
fn stored_generation(
    cluster: &TestCluster,
) -> BrainResult<(tempfile::TempDir, IndexStore, IndexBuild)> {
    let root = tempfile::tempdir().expect("temp root");
    let store = IndexStore::open(root.path(), cluster.store())?;
    let chunker = Chunker::new(NonZeroU32::new(4).expect("nonzero"), 1)?;
    let atlas_id = AtlasId::new(SOURCE)?;
    let revision = Digest::hash(b"pinned-revision");
    let items = fixture_items(&atlas_id, revision)?;
    let build = build_index_with_embedding_model(
        atlas_id,
        revision,
        &items,
        &chunker,
        EmbeddingModelId::new(TEST_EMBEDDING_MODEL)?,
    )?;
    store.store(&build, 1)?;
    Ok((root, store, build))
}

fn rank_chunk(seed: &str, trust: TrustClass, text: &str) -> IndexedChunk {
    let source = AtlasId::new(SOURCE).expect("valid atlas id");
    let item_id = KnowledgeItemId::new(Digest::hash(format!("{seed}:item").as_bytes()));
    let citation = Citation::new(odin_domain::knowledge::retrieval::CitationInit {
        source,
        source_revision: Digest::hash(b"rank-revision"),
        item_id,
        fact_id: None,
        fact_revision: None,
        fact_origin: None,
        lineage: None,
        byte_start: 0,
        byte_end: text.len() as u64,
    })
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
    let query = RetrievalQuery::new(odin_domain::knowledge::retrieval::RetrievalQueryInit {
        text: "alpha gamma".to_owned(),
        sources,
        required_tags: BTreeSet::new(),
        denied_tags: BTreeSet::new(),
        allowed_trust,
        candidate_limit: NonZeroU16::new(8).expect("nonzero"),
        top_k: NonZeroU16::new(top_k).expect("nonzero"),
        min_score: RelevanceScore::new(min_score).expect("valid score"),
    })
    .expect("valid retrieval query");
    RetrievalPlan::new(query, RetrievalMode::Hybrid)
}

#[test]
fn ranking_applies_min_score_dedup_and_top_k() -> BrainResult<()> {
    let plan = fusion_plan(500_000, 3);
    let first = rank_chunk("first", TrustClass::Curated, "alpha one");
    let both = rank_chunk("both", TrustClass::Curated, "alpha gamma one");
    let fourth = rank_chunk("fourth", TrustClass::Curated, "gamma one");
    let low = rank_chunk("low", TrustClass::Curated, "alpha one");
    let duplicate_one = rank_chunk("dup", TrustClass::Curated, "alpha gamma one");
    let mut duplicate_two = rank_chunk("dup", TrustClass::Curated, "alpha gamma one");
    // Same content digest, different chunk identity: exactly one survives.
    duplicate_two.chunk_id = KnowledgeChunkId::new(Digest::hash(b"dup:chunk-two"));

    let hits = rank(
        &plan,
        vec![
            scored(first.clone(), 900_000),
            scored(both.clone(), 700_000),
            scored(low.clone(), 100_000),
            scored(duplicate_one.clone(), 850_000),
            scored(duplicate_two, 850_000),
            scored(fourth.clone(), 600_000),
        ],
    )?;

    // 900_000 > dup 850_000 (one copy) > 700_000; the 600_000 candidate
    // fell below top_k = 3 and the 100_000 one below min_score.
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[0].item_id, first.item_id);
    assert_eq!(hits[1].content_digest, duplicate_one.digest);
    assert_eq!(hits[2].item_id, both.item_id);
    let surviving: BTreeSet<KnowledgeItemId> = hits.iter().map(|hit| hit.item_id).collect();
    assert!(!surviving.contains(&low.item_id));
    assert!(!surviving.contains(&fourth.item_id));
    Ok(())
}

#[test]
fn model_aware_selection_never_pins_a_divergent_stamp_generation() -> BrainResult<()> {
    let cluster = TestCluster::start();
    let (_root, store, build) = stored_generation(&cluster)?;
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
        &fixture_items(&atlas_id, revision)?,
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
