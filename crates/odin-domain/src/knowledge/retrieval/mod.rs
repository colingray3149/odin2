//! Knowledge fact, retrieval, index, trust, and policy domain vocabulary.

mod fact;
mod index;
mod policy;
#[cfg(test)]
mod tests;

pub use fact::{
    Citation, CitationInit, KnowledgeFact, KnowledgeFactInit, KnowledgeFreshness, KnowledgeLineage,
    KnowledgeLineageCompleteness, KnowledgeLineageParent, KnowledgeOrigin, KnowledgeOriginKind,
    KnowledgeOriginPrecedence, KnowledgeResurrection, KnowledgeSourceRevision, KnowledgeTombstone,
    TrustClass,
};
pub use index::{EmbeddingBackend, IndexGeneration, IndexedChunk};
pub use policy::{
    EffectiveKnowledgePolicy, ModelDescriptor, RetrievalHit, RetrievalHitOrderingKey,
    RetrievalMode, RetrievalQuery, RetrievalQueryInit, SeatKnowledgePolicy, SliceKnowledgePolicy,
};
