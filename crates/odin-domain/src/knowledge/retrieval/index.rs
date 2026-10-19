//! Index, chunk, and embedding contracts for canonical knowledge.

use serde::{Deserialize, Serialize};

use super::fact::{Citation, TrustClass};
use crate::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId, TokenizerId,
};
use crate::Digest;

/// A deterministic chunk ready for lexical or vector indexing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedChunk {
    pub item_id: KnowledgeItemId,
    pub chunk_id: KnowledgeChunkId,
    pub trust: TrustClass,
    pub text: String,
    pub digest: Digest,
    pub citation: Citation,
}

/// Exact, disposable index generation derived from one Atlas revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexGeneration {
    pub generation_id: IndexGenerationId,
    pub atlas_id: AtlasId,
    pub atlas_revision: Digest,
    pub chunker_version: String,
    pub tokenizer: TokenizerId,
    pub embedding_model: EmbeddingModelId,
    pub manifest_digest: Digest,
}

/// Embedding execution authority requested by a slice.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EmbeddingBackend {
    Disabled,
    Local,
    Remote,
}
