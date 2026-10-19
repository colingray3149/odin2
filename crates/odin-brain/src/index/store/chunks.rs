//! Turn reads of one generation's stored chunks: the rows at given ordinals,
//! and the ordinals of given items.

use std::collections::{BTreeSet, HashMap};

use odin_domain::knowledge::ids::{IndexGenerationId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::IndexedChunk;
use rusqlite::params;

use super::{chunk_from_row, corrupt, IndexStore};
use crate::error::{BrainError, BrainResult};

impl IndexStore {
    /// The chunks of one generation at exactly `ordinals` (missing ordinals
    /// are corruption), in the order given. A sealed generation serves from
    /// the PostgreSQL store only.
    pub fn chunks_at(
        &self,
        generation_id: &IndexGenerationId,
        ordinals: &[i64],
    ) -> BrainResult<Vec<IndexedChunk>> {
        if let Some((generation, _)) = self.sealed_generation(generation_id)? {
            return self.sealed_chunks_at(&generation, ordinals);
        }
        self.stored_chunks_at(generation_id, ordinals)
    }

    fn stored_chunks_at(
        &self,
        generation_id: &IndexGenerationId,
        ordinals: &[i64],
    ) -> BrainResult<Vec<IndexedChunk>> {
        let connection = self.lock_connection()?;
        let Some(generation) = Self::load_header(&connection, generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        let id = generation_id.to_string();
        // One statement for the turn's ordinals, not one round trip each.
        // SQLite's variable limit is 32766; candidate_limit is a u16.
        const BATCH: usize = 500;
        let mut found = HashMap::with_capacity(ordinals.len());
        for batch in ordinals.chunks(BATCH) {
            let mut sql = String::with_capacity(180 + batch.len() * 4);
            sql.push_str(
                "SELECT ordinal, chunk_id, item_id, trust, digest, text, byte_start, byte_end \
                 FROM brain_index_chunk WHERE generation_id = ?1 AND ordinal IN (",
            );
            for index in 0..batch.len() {
                if index > 0 {
                    sql.push(',');
                }
                sql.push('?');
                sql.push_str(&(index + 2).to_string());
            }
            sql.push(')');
            let mut statement = connection.prepare(&sql)?;
            let mut bound: Vec<&dyn rusqlite::types::ToSql> = Vec::with_capacity(batch.len() + 1);
            bound.push(&id);
            for ordinal in batch {
                bound.push(ordinal);
            }
            let mut rows = statement.query(bound.as_slice())?;
            while let Some(row) = rows.next()? {
                let ordinal: i64 = row.get(0)?;
                let chunk_id: String = row.get(1)?;
                let item_id: String = row.get(2)?;
                let trust: String = row.get(3)?;
                let digest: String = row.get(4)?;
                let text: String = row.get(5)?;
                let byte_start: i64 = row.get(6)?;
                let byte_end: i64 = row.get(7)?;
                found.insert(
                    ordinal,
                    chunk_from_row(
                        &generation.atlas_id,
                        generation.atlas_revision,
                        &chunk_id,
                        &item_id,
                        &trust,
                        &digest,
                        &text,
                        byte_start,
                        byte_end,
                    )?,
                );
            }
        }
        let mut chunks = Vec::with_capacity(ordinals.len());
        for ordinal in ordinals {
            chunks.push(found.get(ordinal).cloned().ok_or_else(|| {
                corrupt(format!("generation {id} has no chunk at ordinal {ordinal}"))
            })?);
        }
        Ok(chunks)
    }

    /// The ordinals of every chunk of `items` in one generation, sealed
    /// generations from the PostgreSQL store only.
    pub fn ordinals_for_items(
        &self,
        generation_id: &IndexGenerationId,
        items: &BTreeSet<KnowledgeItemId>,
    ) -> BrainResult<Vec<i64>> {
        if self.sealed_generation(generation_id)?.is_some() {
            return self.sealed_ordinals(generation_id, items);
        }
        self.stored_ordinals_for_items(generation_id, items)
    }

    fn stored_ordinals_for_items(
        &self,
        generation_id: &IndexGenerationId,
        items: &BTreeSet<KnowledgeItemId>,
    ) -> BrainResult<Vec<i64>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare_cached(
            "SELECT ordinal FROM brain_index_chunk WHERE generation_id = ?1 AND item_id = ?2 \
             ORDER BY ordinal",
        )?;
        let id = generation_id.to_string();
        let mut ordinals = Vec::new();
        for item in items {
            let rows = statement.query_map(params![id, item.to_string()], |row| row.get(0))?;
            for ordinal in rows {
                ordinals.push(ordinal?);
            }
        }
        Ok(ordinals)
    }
}
