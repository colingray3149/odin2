//! Retrieval vocabulary: the resolved [`query::RetrievalPlan`], the frozen
//! hit order ([`rank::rank`]), the embedding executor a hybrid or vector
//! turn needs, and [`identity::identity_literals`], the opaque identity
//! constraints a query can carry, which the service resolves against the
//! published archive records (identity lives in the record's own columns,
//! never in indexed body text). Vector and hybrid modes require a resolved
//! embedding executor and surface [`BrainError::EmbeddingUnavailable`] when
//! none is wired — never synthetic vectors.

use std::sync::Arc;

use odin_domain::LaneId;

use crate::error::{BrainError, BrainResult};

pub mod embedding;
pub mod identity;
pub mod query;
pub mod rank;
pub mod rerank;

pub use query::RetrievalPlan;
pub use rank::{rank, ScoredCandidate};

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
