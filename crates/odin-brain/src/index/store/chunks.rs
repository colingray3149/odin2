//! Turn reads of one generation's stored chunks: the rows at given ordinals,
//! and the ordinals of given items.

use std::collections::BTreeSet;

use odin_domain::knowledge::ids::{IndexGenerationId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::IndexedChunk;

use super::IndexStore;
use crate::error::{BrainError, BrainResult};

impl IndexStore {
    /// The chunks of one generation at exactly `ordinals` (missing ordinals
    /// are corruption), in the order given.
    pub fn chunks_at(
        &self,
        generation_id: &IndexGenerationId,
        ordinals: &[i64],
    ) -> BrainResult<Vec<IndexedChunk>> {
        match self.sealed_generation(generation_id)? {
            Some((generation, _)) => self.sealed_chunks_at(&generation, ordinals),
            None => Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            }),
        }
    }

    /// The ordinals of every chunk of `items` in one generation.
    pub fn ordinals_for_items(
        &self,
        generation_id: &IndexGenerationId,
        items: &BTreeSet<KnowledgeItemId>,
    ) -> BrainResult<Vec<i64>> {
        self.sealed_ordinals(generation_id, items)
    }
}
