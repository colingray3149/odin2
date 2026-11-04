//! The frozen order of a turn's hits. The store nominates and scores
//! candidates (BM25 and vector legs fused by reciprocal rank, see
//! [`crate::index::postgres`]); [`rank`] applies `min_score`, orders by the
//! frozen [`odin_domain::knowledge::retrieval::RetrievalHitOrderingKey`]
//! (score descending, trust descending, then source, item and content digest
//! ascending), deduplicates by content digest, truncates to `top_k` and
//! revalidates every hit against its query.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use odin_domain::knowledge::ids::RelevanceScore;
use odin_domain::knowledge::retrieval::{Citation, IndexedChunk, RetrievalHit};

use super::query::RetrievalPlan;
use crate::error::BrainResult;

/// One candidate chunk carrying its fused relevance score.
#[derive(Clone, Debug)]
pub struct ScoredCandidate {
    pub chunk: IndexedChunk,
    pub score: RelevanceScore,
}

/// Orders `candidates` by the frozen contract and applies `min_score`,
/// digest deduplication, `top_k`, and per-hit revalidation.
pub fn rank(
    plan: &RetrievalPlan,
    mut candidates: Vec<ScoredCandidate>,
) -> BrainResult<Vec<RetrievalHit>> {
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

/// Lowercased alphabetic and numeric runs, matching the BM25 indexes'
/// `pdb.regex_pattern('\p{Alphabetic}+|\p{Number}+')` tokenizer. Separating
/// letters from numbers makes compact and spaced identifiers equivalent.
pub(crate) fn terms(mut text: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::from_fn(move || {
        let start = text.find(char::is_alphanumeric)?;
        let word = &text[start..];
        let alphabetic = word.chars().next()?.is_alphabetic();
        let end = word
            .find(|character: char| {
                if alphabetic {
                    !character.is_alphabetic()
                } else {
                    !character.is_numeric()
                }
            })
            .unwrap_or(word.len());
        text = &word[end..];
        Some(word[..end].to_lowercase())
    })
}

const STOP_WORDS: &[&str] = &[
    "a", "an", "as", "at", "be", "by", "if", "in", "is", "it", "no", "of", "on", "or", "to",
    "such", "the", "and", "for", "are", "but", "not", "you", "your", "all", "any", "can", "had",
    "her", "was", "one", "our", "out", "has", "him", "his", "how", "its", "now", "who", "did",
    "get", "got", "let", "say", "she", "too", "use", "what", "when", "where", "which", "with",
    "this", "that", "have", "from", "they", "would", "there", "their", "about", "could", "should",
    "into", "than", "then", "them", "these", "those", "some", "just", "like", "does", "please",
    "tell", "know", "want", "need", "make", "thanks", "okay", "yes",
];

/// A function word that says nothing about what a chunk is about.
pub(crate) fn is_stop_word(term: &str) -> bool {
    STOP_WORDS.contains(&term)
}
