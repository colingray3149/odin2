//! Retrieval query planning under resolved knowledge policy.
//!
//! [`RetrievalPlan`] pins the explicit [`RetrievalMode`] and the resolved
//! [`RetrievalQuery`] derived from an `EffectiveKnowledgePolicy`. The mode
//! selects lexical, vector, or hybrid candidate production:
//!
//! - `lexical` needs no embedding backend and stays independently usable.
//! - `vector` and `hybrid` require a resolved executor; policy validation
//!   already rejects `EmbeddingBackend::Disabled` for them, and a missing
//!   executor at runtime surfaces as [`BrainError::EmbeddingUnavailable`] —
//!   never a silent downgrade to lexical candidates.

use odin_domain::knowledge::retrieval::{RetrievalMode, RetrievalQuery};

use crate::error::{BrainError, BrainResult};

/// A retrieval query paired with its explicit candidate-generation mode.
#[derive(Clone, Debug)]
pub struct RetrievalPlan {
    query: RetrievalQuery,
    mode: RetrievalMode,
}

impl RetrievalPlan {
    pub fn new(query: RetrievalQuery, mode: RetrievalMode) -> Self {
        Self { query, mode }
    }

    pub fn query(&self) -> &RetrievalQuery {
        &self.query
    }

    pub const fn mode(&self) -> RetrievalMode {
        self.mode
    }

    pub const fn requires_embeddings(&self) -> bool {
        matches!(self.mode, RetrievalMode::Vector | RetrievalMode::Hybrid)
    }
}

/// Vector and hybrid plans require both executor and model, or neither.
/// A fully absent pair fails at execution; lexical plans need neither.
pub fn validate_embedding_binding(
    mode: Option<RetrievalMode>,
    has_executor: bool,
    has_model: bool,
) -> BrainResult<()> {
    if !matches!(mode, Some(RetrievalMode::Vector | RetrievalMode::Hybrid))
        || has_executor == has_model
    {
        return Ok(());
    }
    Err(BrainError::InvalidPolicy(
        if has_executor {
            "vector/hybrid retrieval binds an embedding executor without the \
             declared model the executor executes under"
        } else {
            "vector/hybrid retrieval declares an embedding model without the \
             executor that serves it"
        }
        .to_owned(),
    ))
}
