//! Deterministic candidate scoring and fusion under the frozen ranking.
//!
//! Lexical relevance is produced by the persistent FTS5 BM25 index through
//! [`crate::index::store::IndexStore::generation_lexical_top`]; ranking consumes the
//! store's normalized score map and never re-derives relevance itself. Vector
//! relevance is quantized cosine similarity. Fusion takes the mean of
//! the available signals per candidate, and every surviving hit is ordered by
//! the frozen [`FrozenRetrievalHitOrderingKey`] (score descending, trust descending,
//! then source, item, and content digest ascending), deduplicated by content
//! digest, truncated to `top_k`, and revalidated against its query.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;

use odin_domain::knowledge::ids::{KnowledgeChunkId, RelevanceScore};
use odin_domain::knowledge::retrieval::{Citation, IndexedChunk, RetrievalHit};

use super::embedding::EmbeddingVector;
use super::query::RetrievalPlan;
use crate::error::{BrainError, BrainResult};

/// Re-exported frozen ordering vocabulary kept stable for callers.
///
/// [`FrozenRetrievalHitOrderingKey`] is the authority for ranking order; the
/// [`RetrievalHit`] compare helpers consume it, and fusion must never sort by
/// anything else. [`FrozenTrustClass`] confinement is enforced by
/// [`RetrievalHit::validate_for_query`].
pub use odin_domain::knowledge::retrieval::{
    Citation as FrozenCitation, RetrievalHit as FrozenRetrievalHit,
    RetrievalHitOrderingKey as FrozenRetrievalHitOrderingKey, TrustClass as FrozenTrustClass,
};

/// One candidate chunk carrying its mode-specific relevance score.
#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub chunk: IndexedChunk,
    pub score: RelevanceScore,
}

/// Builds lexical candidates for the pinned pool from the index store's
/// BM25 score map.
///
/// Every passed chunk receives exactly one candidate: a chunk the lexical
/// index did not match scores zero instead of dropping out, so fusion keeps
/// its full mean denominator and `min_score` — not missing index coverage —
/// decides survival. The map carries only scores the persistent index
/// computed; this is a lookup, never a second scorer.
pub fn lexical_candidates(
    chunks: &[IndexedChunk],
    scores: &BTreeMap<KnowledgeChunkId, RelevanceScore>,
) -> Vec<ScoredCandidate> {
    chunks
        .iter()
        .map(|chunk| ScoredCandidate {
            chunk: chunk.clone(),
            score: scores
                .get(&chunk.chunk_id)
                .copied()
                .unwrap_or(RelevanceScore::ZERO),
        })
        .collect()
}

/// Scores every embedded chunk by cosine similarity to the query embedding.
///
/// Chunks without a stored vector are simply not vector candidates; producing
/// a lexical score for them here would be the forbidden silent downgrade.
pub fn score_vector(
    query_embedding: &EmbeddingVector,
    vectors: &BTreeMap<KnowledgeChunkId, EmbeddingVector>,
    chunks: &[IndexedChunk],
) -> BrainResult<Vec<ScoredCandidate>> {
    let mut scored = Vec::new();
    for chunk in chunks {
        let Some(vector) = vectors.get(&chunk.chunk_id) else {
            continue;
        };
        let similarity = query_embedding.cosine_similarity(vector)?;
        scored.push(ScoredCandidate {
            chunk: chunk.clone(),
            score: quantize_similarity(similarity)?,
        });
    }
    Ok(scored)
}

/// Keeps the best `limit` candidates in deterministic order.
///
/// Order: score descending, then source, item, digest, and chunk id ascending.
pub fn take_top(mut candidates: Vec<ScoredCandidate>, limit: NonZeroU16) -> Vec<ScoredCandidate> {
    candidates.sort_by(candidate_rank);
    candidates.truncate(usize::from(limit.get()));
    candidates
}

/// Fuses lexical and vector candidates, orders by the frozen contract, and
/// applies `min_score`, digest deduplication, `top_k`, and per-hit revalidation.
///
/// Fusion takes the mean of the available signals per candidate, so a chunk
/// found by only one mode is never penalized for the missing signal and a
/// vector-only run is not diluted by absent lexical scores.
pub fn fuse_and_rank(
    plan: &RetrievalPlan,
    lexical: Vec<ScoredCandidate>,
    vector: Vec<ScoredCandidate>,
) -> BrainResult<Vec<RetrievalHit>> {
    struct Fused {
        chunk: IndexedChunk,
        lexical: Option<RelevanceScore>,
        vector: Option<RelevanceScore>,
    }
    let mut fused: BTreeMap<KnowledgeChunkId, Fused> = BTreeMap::new();
    for candidate in lexical {
        let entry = fused
            .entry(candidate.chunk.chunk_id)
            .or_insert_with(|| Fused {
                chunk: candidate.chunk.clone(),
                lexical: None,
                vector: None,
            });
        entry.lexical = Some(candidate.score);
    }
    for candidate in vector {
        let entry = fused
            .entry(candidate.chunk.chunk_id)
            .or_insert_with(|| Fused {
                chunk: candidate.chunk.clone(),
                lexical: None,
                vector: None,
            });
        entry.vector = Some(candidate.score);
    }

    let mut candidates: Vec<ScoredCandidate> = Vec::with_capacity(fused.len());
    for candidate in fused.into_values() {
        let signals =
            u64::from(candidate.lexical.is_some()) + u64::from(candidate.vector.is_some());
        let sum = candidate
            .lexical
            .map(|score| u64::from(score.get()))
            .unwrap_or(0)
            + candidate
                .vector
                .map(|score| u64::from(score.get()))
                .unwrap_or(0);
        candidates.push(ScoredCandidate {
            chunk: candidate.chunk,
            score: RelevanceScore::new((sum / signals) as u32)?,
        });
    }

    candidates.retain(|candidate| candidate.score >= plan.query().min_score);
    candidates.sort_by(candidate_rank);

    let mut seen_digests = BTreeSet::new();
    let mut hits = Vec::new();
    for candidate in candidates {
        if !seen_digests.insert(candidate.chunk.digest) {
            continue;
        }
        hits.push(hit_from_chunk(&candidate.chunk, candidate.score)?);
    }

    hits.sort_by(RetrievalHit::compare_rank);
    hits.truncate(usize::from(plan.query().top_k.get()));
    for hit in &hits {
        hit.validate_for_query(plan.query())?;
    }
    Ok(hits)
}

/// Builds a hit whose provenance is copied verbatim from the chunk citation,
/// so hit and citation agreement holds by construction.
fn hit_from_chunk(chunk: &IndexedChunk, score: RelevanceScore) -> BrainResult<RetrievalHit> {
    let citation: Citation = chunk.citation.clone();
    Ok(RetrievalHit {
        item_id: chunk.item_id,
        source: citation.source.clone(),
        source_revision: citation.source_revision,
        fact_id: citation.fact_id,
        fact_revision: citation.fact_revision,
        fact_origin: citation.fact_origin,
        lineage: citation.lineage.clone(),
        trust: chunk.trust,
        content_digest: chunk.digest,
        content: chunk.text.clone(),
        score,
        citation,
    })
}

/// Deterministic candidate order: score descending, then provenance ascending.
fn candidate_rank(left: &ScoredCandidate, right: &ScoredCandidate) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.chunk.citation.source.cmp(&right.chunk.citation.source))
        .then_with(|| left.chunk.item_id.cmp(&right.chunk.item_id))
        .then_with(|| left.chunk.digest.cmp(&right.chunk.digest))
        .then_with(|| left.chunk.chunk_id.cmp(&right.chunk.chunk_id))
}

/// Lowercased ASCII alphanumeric runs: the single deterministic lexical
/// tokenizer, shared by the persistent index's FTS5 expression builder and
/// its pre-tokenized corpus.
pub(crate) fn terms(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
}

const STOP_WORDS: &[&str] = &[
    "a", "an", "as", "at", "be", "by", "if", "in", "is", "it", "no", "of", "on", "or", "to",
    "such", "the", "and", "for", "are", "but", "not", "you", "your", "all", "any", "can", "had",
    "her", "was", "one", "our", "out", "has", "him", "his", "how", "its", "may", "now", "who",
    "did", "get", "got", "let", "say", "she", "too", "use", "what", "when", "where", "which",
    "with", "this", "that", "have", "from", "they", "will", "would", "there", "their", "about",
    "could", "should", "into", "than", "then", "them", "these", "those", "some", "just", "like",
    "does", "please", "tell", "know", "want", "need", "make", "thanks", "okay", "yes",
];

/// A function word that says nothing about what a chunk is about.
pub(crate) fn is_stop_word(term: &str) -> bool {
    STOP_WORDS.contains(&term)
}

/// Maps cosine similarity in `[-1, 1]` onto `[0, 1_000_000]` millionths.
fn quantize_similarity(similarity: f64) -> BrainResult<RelevanceScore> {
    if !similarity.is_finite() {
        return Err(BrainError::InvalidRequest(
            "vector similarity is not finite".to_owned(),
        ));
    }
    let normalized = ((similarity + 1.0) / 2.0).clamp(0.0, 1.0);
    Ok(RelevanceScore::new(
        (normalized * 1_000_000.0).round() as u32
    )?)
}
