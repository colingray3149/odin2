//! Retrieval root: frozen module composition for candidate production and
//! ranking.
//!
//! This module declares the frozen retrieval vocabulary and exposes one
//! concrete [`Retriever`] that composes the existing pieces end to end:
//! [`query::RetrievalPlan`] pins the explicit [`RetrievalMode`] and resolved
//! query, [`rank::lexical_candidates`] / [`rank::score_vector`] produce
//! mode-scoped candidates from the index store's BM25 score map and the
//! stored vectors, and [`rank::fuse_and_rank`] applies the frozen ordering,
//! `min_score`, digest deduplication, `top_k`, and per-hit revalidation.
//! [`identity::identity_literals`] extracts the opaque identity constraints a
//! query can carry, which the service resolves against the published archive
//! records (identity lives in the record's own columns, never in indexed body
//! text).
//!
//! The retriever adds no ordering or scoring policy of its own. Lexical mode
//! is independently usable with no embedding backend at all; vector and
//! hybrid modes require a resolved embedding executor and surface
//! [`BrainError::EmbeddingUnavailable`] when none is wired — never a silent
//! downgrade to lexical candidates and never synthetic vectors.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::knowledge::ids::{KnowledgeChunkId, RelevanceScore};
use odin_domain::knowledge::retrieval::{IndexedChunk, RetrievalHit, RetrievalMode};
use odin_domain::LaneId;

use crate::error::{BrainError, BrainResult};

pub mod compact;
pub mod embedding;
pub mod identity;
pub mod query;
pub mod rank;

pub use query::RetrievalPlan;
pub use rank::{
    fuse_and_rank, lexical_candidates, score_vector, take_top, FrozenCitation, FrozenRetrievalHit,
    FrozenRetrievalHitOrderingKey, FrozenTrustClass, ScoredCandidate,
};

use embedding::EmbeddingVector;

/// Provider label for the retriever's embedding dependency. Presence of a
/// real executor is kernel authority, never carried as a string; this label
/// only names the absent dependency in [`BrainError::EmbeddingUnavailable`].
const EMBEDDING_PROVIDER: &str = "odin.retrieval.embedding";

/// The embedding executor: one gateway request embeds a batch of texts and
/// returns one vector per text, in order, or a typed failure.
/// Implementations must never synthesize vectors.
pub type QueryEmbedder = dyn Fn(&[String]) -> BrainResult<Vec<EmbeddingVector>> + Send + Sync;

pub fn embed_one(embed: &QueryEmbedder, text: &str) -> BrainResult<EmbeddingVector> {
    embed(&[text.to_owned()])?
        .pop()
        .ok_or_else(|| BrainError::EmbeddingUnavailable {
            provider: EMBEDDING_PROVIDER.to_owned(),
            reason: "the embedding executor returned no vector".to_owned(),
        })
}

/// The lane-binding seam runtime composition wires once: given the runtime
/// session lane, it returns the kernel-authoritative [`QueryEmbedder`]
/// bound to that lane, or a typed failure before any embedding execution.
/// The returned embedder holds its lane state strongly, so an in-flight
/// binding is never evicted while it is alive.
pub trait LaneEmbeddingProvider: Send + Sync {
    /// Binds one query embedder to the runtime session lane. The owned
    /// factory Arc becomes the binding's owner, so no wrapper allocation
    /// stands between composition and the bound embedder.
    fn bind_lane(self: Arc<Self>, lane: &LaneId) -> BrainResult<Arc<QueryEmbedder>>;
}

/// Concrete retrieval over one pinned immutable Atlas pool.
///
/// The plan fixes the mode and the resolved query (`min_score`, `top_k`,
/// source revision); `chunks` is the immutable candidate pool, `vectors` the
/// stored chunk embeddings of the same revision, and `lexical_scores` the
/// persistent index's BM25 scores for exactly that pool. Everything is
/// borrowed, never copied: retrieval is a view over frozen Atlas state.
#[derive(Clone)]
pub struct Retriever<'pool> {
    plan: RetrievalPlan,
    chunks: &'pool [IndexedChunk],
    vectors: &'pool BTreeMap<KnowledgeChunkId, EmbeddingVector>,
    lexical_scores: &'pool BTreeMap<KnowledgeChunkId, RelevanceScore>,
    embed: Option<Arc<QueryEmbedder>>,
    /// The query's embedding when the caller already computed it (the
    /// candidate stage needs it first); never embedded twice.
    query_embedding: Option<EmbeddingVector>,
}

impl<'pool> Retriever<'pool> {
    pub fn new(
        plan: RetrievalPlan,
        chunks: &'pool [IndexedChunk],
        vectors: &'pool BTreeMap<KnowledgeChunkId, EmbeddingVector>,
        lexical_scores: &'pool BTreeMap<KnowledgeChunkId, RelevanceScore>,
    ) -> Self {
        Self {
            plan,
            chunks,
            vectors,
            lexical_scores,
            embed: None,
            query_embedding: None,
        }
    }

    /// Wires the kernel-authoritative embedding executor. Required for
    /// [`RetrievalMode::Vector`] and [`RetrievalMode::Hybrid`]; ignored by
    /// [`RetrievalMode::Lexical`], which never executes embeddings.
    pub fn with_executor(mut self, embed: Arc<QueryEmbedder>) -> Self {
        self.embed = Some(embed);
        self
    }

    pub fn with_query_embedding(mut self, embedding: EmbeddingVector) -> Self {
        self.query_embedding = Some(embedding);
        self
    }

    pub const fn plan(&self) -> &RetrievalPlan {
        &self.plan
    }

    /// Candidate production is mode-scoped: `lexical` ranks the pool by the
    /// store-computed lexical scores only (unmatched chunks zero-fill),
    /// `vector` scores cosine similarity only (lexical candidates would be
    /// the forbidden silent downgrade), and `hybrid` produces both. Fusion
    /// then applies the frozen ordering contract. Vector and hybrid modes
    /// without a wired executor fail with
    /// [`BrainError::EmbeddingUnavailable`].
    pub fn retrieve(&self) -> BrainResult<Vec<RetrievalHit>> {
        let lexical = if matches!(
            self.plan.mode(),
            RetrievalMode::Lexical | RetrievalMode::Hybrid
        ) {
            lexical_candidates(self.chunks, self.lexical_scores)
        } else {
            Vec::new()
        };

        let vector = if self.plan.requires_embeddings() {
            let embed = self
                .embed
                .as_ref()
                .ok_or_else(|| BrainError::EmbeddingUnavailable {
                    provider: EMBEDDING_PROVIDER.to_string(),
                    reason: "no embedding executor is resolved for this retriever; vector and \
                             hybrid retrieval refuse lexical downgrade"
                        .to_string(),
                })?;
            let query_embedding = match &self.query_embedding {
                Some(embedding) => embedding.clone(),
                None => embed_one(embed.as_ref(), &self.plan.query().text)?,
            };
            score_vector(&query_embedding, self.vectors, self.chunks)?
        } else {
            Vec::new()
        };

        fuse_and_rank(&self.plan, lexical, vector)
    }
}
