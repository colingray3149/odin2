//! The SQLite body of the index store's vector pools: persisting the
//! kernel-authorized vectors per stored chunk, serving them verified, and
//! streaming them for the warm pump. Sealed generations serve their pools
//! from PostgreSQL (seal.rs); these methods are the store's own rows.

use std::collections::HashMap;

use odin_domain::knowledge::ids::{
    EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId,
};
use odin_domain::Digest;
use rusqlite::{params, Connection, OptionalExtension};

use super::{corrupt, decode_dims, IndexStore, StoreOutcome, StoredVectors};
use crate::error::{BrainError, BrainResult};
use crate::retrieval::embedding::EmbeddingVector;

impl IndexStore {
    /// Stored vector count of one generation (0 = no pool).
    pub fn vector_count(&self, generation_id: &IndexGenerationId) -> BrainResult<u64> {
        let connection = self.lock_connection()?;
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM brain_index_vector WHERE generation_id = ?1",
            params![generation_id.to_string()],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Stored vectors at exactly `ordinals`, each bound to the generation's
    /// pinned model; a row under another model is corruption.
    pub fn vectors_at(
        &self,
        generation_id: &IndexGenerationId,
        ordinals: &[i64],
    ) -> BrainResult<Vec<(i64, EmbeddingVector)>> {
        let connection = self.lock_connection()?;
        let Some(generation) = Self::load_header(&connection, generation_id)? else {
            return Ok(Vec::new());
        };
        let id = generation_id.to_string();
        let mut statement = connection.prepare_cached(
            "SELECT chunk_id, embedding_model, dims FROM brain_index_vector \
             WHERE generation_id = ?1 AND ordinal = ?2",
        )?;
        let mut vectors = Vec::with_capacity(ordinals.len());
        for ordinal in ordinals {
            let Some((chunk_id, model, dims)) = statement
                .query_row(params![id, ordinal], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .optional()?
            else {
                continue;
            };
            if model != generation.embedding_model.as_str() {
                return Err(corrupt(
                    "stored vector rows are bound to a different embedding model than the generation pins",
                ));
            }
            let vector = EmbeddingVector::from_dims(decode_dims(&chunk_id, &dims)?)
                .map_err(|error| corrupt(format!("stored vector fails revalidation: {error}")))?;
            vectors.push((*ordinal, vector));
        }
        Ok(vectors)
    }

    /// Streams every stored vector of one generation to `sink` in ordinal
    /// order, in bounded batches with the store lock released in between.
    pub fn for_each_vector(
        &self,
        generation_id: &IndexGenerationId,
        mut sink: impl FnMut(i64, KnowledgeItemId, &[f32]) -> BrainResult<()>,
    ) -> BrainResult<u64> {
        const BATCH: i64 = 4_096;
        let id = generation_id.to_string();
        let (mut after, mut seen) = (-1_i64, 0_u64);
        loop {
            let rows: Vec<(i64, String, String, Vec<u8>)> = {
                let connection = self.lock_connection()?;
                let mut statement = connection.prepare_cached(
                    "SELECT v.ordinal, v.chunk_id, c.item_id, v.dims FROM brain_index_vector v \
                     JOIN brain_index_chunk c \
                       ON c.generation_id = v.generation_id AND c.ordinal = v.ordinal \
                     WHERE v.generation_id = ?1 AND v.ordinal > ?2 ORDER BY v.ordinal LIMIT ?3",
                )?;
                let rows = statement.query_map(params![id, after, BATCH], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?;
                let rows = rows.collect::<Result<_, _>>()?;
                drop(statement);
                // Hand the connection to any waiting turn before the next
                // batch: an unfair unlock let this loop re-take it first.
                parking_lot::MutexGuard::unlock_fair(connection);
                rows
            };
            if rows.is_empty() {
                return Ok(seen);
            }
            for (ordinal, chunk_id, item, dims) in rows {
                let item = KnowledgeItemId::parse(&item)
                    .map_err(|_| corrupt(format!("chunk {chunk_id} has an unparseable item id")))?;
                sink(ordinal, item, &decode_dims(&chunk_id, &dims)?)?;
                after = ordinal;
                seen += 1;
            }
        }
    }

    /// Persists the kernel-authorized embedding vectors for every chunk of
    /// one stored generation, exactly bound to that generation's pinned
    /// embedding model.
    ///
    /// The pool must be exact: one finite, non-empty, common-dimension
    /// vector per stored chunk, matched by chunk ID in any order. This store
    /// never synthesizes vectors and refuses partial pools, so vector
    /// retrieval can never silently serve fewer candidates than the
    /// generation has chunks. Insert-only like the index itself:
    /// re-storing byte-identical vectors is an idempotent no-op; divergent
    /// vectors under one generation ID are typed corruption.
    pub fn store_vectors(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        vectors: &[(KnowledgeChunkId, Vec<f32>)],
    ) -> BrainResult<StoreOutcome> {
        if vectors.is_empty() {
            return Err(BrainError::InvalidRequest(
                "an empty vector pool is not a storable outcome; embed the generation's chunks first"
                    .to_owned(),
            ));
        }
        let connection = self.lock_connection()?;
        let Some((generation, chunks)) = Self::load_in(&connection, generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        if generation.embedding_model != *embedding_model {
            return Err(BrainError::StaleAuthority {
                authority: "embedding_model",
                detail: format!(
                    "vectors are bound to model {} but generation {} pins {}",
                    embedding_model.as_str(),
                    generation.generation_id,
                    generation.embedding_model.as_str(),
                ),
            });
        }
        let dimensions = vectors[0].1.len();
        let mut offered: HashMap<String, &[f32]> = HashMap::with_capacity(vectors.len());
        for (chunk_id, dims) in vectors {
            if let Some(reason) = invalid_dims_reason(dims) {
                return Err(BrainError::InvalidRequest(format!(
                    "vector for chunk {chunk_id} is not a usable embedding: {reason}"
                )));
            }
            if dims.len() != dimensions {
                return Err(BrainError::InvalidRequest(format!(
                    "vector for chunk {chunk_id} has {} dimensions but the pool pins {dimensions}",
                    dims.len()
                )));
            }
            if offered
                .insert(chunk_id.to_string(), dims.as_slice())
                .is_some()
            {
                return Err(BrainError::InvalidRequest(format!(
                    "chunk {chunk_id} was offered more than one vector"
                )));
            }
        }
        for chunk in &chunks {
            if !offered.contains_key(&chunk.chunk_id.to_string()) {
                return Err(BrainError::InvalidRequest(format!(
                    "chunk {} has no vector; the pool must cover every stored chunk exactly",
                    chunk.chunk_id
                )));
            }
        }
        if offered.len() != chunks.len() {
            return Err(BrainError::InvalidRequest(format!(
                "generation {} pins {} chunks but {} vectors were offered",
                generation.generation_id,
                chunks.len(),
                vectors.len()
            )));
        }
        let tx = crate::sqlite::write_transaction(&connection)?;
        let existing = read_vector_rows(&tx, generation_id)?;
        if !existing.is_empty() {
            if existing.len() != chunks.len() {
                return Err(corrupt(format!(
                    "generation {} has a partial stored vector pool ({} of {} chunks)",
                    generation.generation_id,
                    existing.len(),
                    chunks.len()
                )));
            }
            for (ordinal, chunk) in chunks.iter().enumerate() {
                let row = &existing[ordinal];
                if row.ordinal != ordinal
                    || row.chunk_id != chunk.chunk_id.to_string()
                    || row.embedding_model != generation.embedding_model.as_str()
                {
                    return Err(corrupt(
                        "stored vector rows diverge from the generation's chunk membership or model binding",
                    ));
                }
                // Embeddings need not be bit-reproducible; retain the first valid complete pool.
                let stored = decode_dims(&row.chunk_id, &row.dims)?;
                if stored.len() != dimensions {
                    return Err(corrupt(format!(
                        "stored vector for chunk {} has {} dimensions but the pool pins \
                         {dimensions}",
                        row.chunk_id,
                        stored.len()
                    )));
                }
            }
            drop(tx);
            drop(connection);
            self.transfer_pool_to_postgres(generation_id, embedding_model)?;
            return Ok(StoreOutcome::AlreadyPresent);
        }
        for (ordinal, chunk) in chunks.iter().enumerate() {
            tx.execute(
                "INSERT INTO brain_index_vector
                    (generation_id, ordinal, chunk_id, embedding_model, dims)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    generation_id.to_string(),
                    ordinal as i64,
                    chunk.chunk_id.to_string(),
                    embedding_model.as_str(),
                    encode_dims(offered[&chunk.chunk_id.to_string()]),
                ],
            )?;
        }
        tx.commit()?;
        drop(connection);
        self.transfer_pool_to_postgres(generation_id, embedding_model)?;
        Ok(StoreOutcome::Stored)
    }

    /// Reuses vectors for identical text across generations; the effective model
    /// key includes the protocol so model or framing changes cannot reuse them.
    pub fn cached_chunk_vector(
        &self,
        embedding_model: &EmbeddingModelId,
        text_digest: &Digest,
    ) -> BrainResult<Option<Vec<f32>>> {
        let connection = self.lock_connection()?;
        let dims: Option<Vec<u8>> = connection
            .query_row(
                "SELECT dims FROM brain_chunk_vector_cache
                 WHERE embedding_model = ?1 AND text_digest = ?2",
                params![embedding_model.as_str(), text_digest.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        dims.map(|dims| decode_dims(&text_digest.to_string(), &dims))
            .transpose()
    }

    /// Records one embedded chunk text's vector for reuse. Insert-only: an
    /// existing entry for the same model and text is kept.
    pub fn cache_chunk_vector(
        &self,
        embedding_model: &EmbeddingModelId,
        text_digest: &Digest,
        dims: &[f32],
    ) -> BrainResult<()> {
        if let Some(reason) = invalid_dims_reason(dims) {
            return Err(BrainError::InvalidRequest(format!(
                "vector for text {text_digest} is not a usable embedding: {reason}"
            )));
        }
        let connection = self.lock_connection()?;
        connection.execute(
            "INSERT OR IGNORE INTO brain_chunk_vector_cache (embedding_model, text_digest, dims)
             VALUES (?1, ?2, ?3)",
            params![
                embedding_model.as_str(),
                text_digest.to_string(),
                encode_dims(dims)
            ],
        )?;
        Ok(())
    }

    /// Loads the stored vector pool for one generation, fully verified.
    ///
    /// The generation itself is re-verified first (manifest and chunk
    /// digests), then the pool: complete chunk membership in chunk-ordinal
    /// order, the generation's pinned embedding model, and finite
    /// dimensions. `vectors[i]` is exactly the vector for chunk `i` of
    /// `load`; zip the two for scoring. `Ok(None)` means vectors were never
    /// stored: callers embed via the kernel-authorized transport and
    /// `store_vectors` — an absent pool is never an empty result set.
    pub fn load_vectors(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<StoredVectors>> {
        let connection = self.lock_connection()?;
        let Some((generation, chunks)) = Self::load_in(&connection, generation_id)? else {
            return Ok(None);
        };
        let rows = read_vector_rows(&connection, generation_id)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != chunks.len() {
            return Err(corrupt(format!(
                "generation {} has a partial stored vector pool ({} of {} chunks)",
                generation.generation_id,
                rows.len(),
                chunks.len()
            )));
        }
        let mut vectors = Vec::with_capacity(rows.len());
        for (ordinal, chunk) in chunks.iter().enumerate() {
            let row = &rows[ordinal];
            if row.ordinal != ordinal || row.chunk_id != chunk.chunk_id.to_string() {
                return Err(corrupt(
                    "stored vector rows do not match the generation's chunk membership",
                ));
            }
            if row.embedding_model != generation.embedding_model.as_str() {
                return Err(corrupt(
                    "stored vector rows are bound to a different embedding model than the generation pins",
                ));
            }
            let dims = decode_dims(&row.chunk_id, &row.dims)?;
            let vector = EmbeddingVector::from_dims(dims)
                .map_err(|error| corrupt(format!("stored vector fails revalidation: {error}")))?;
            vectors.push(vector);
        }
        Ok(Some(StoredVectors {
            embedding_model: generation.embedding_model,
            vectors,
        }))
    }

    /// Streaming variant of [`Self::store_vectors`]: consumes one staged
    /// vector per chunk in chunk-ordinal order and persists the pool in one
    /// transaction. The exact contract of `store_vectors` holds — complete
    /// membership, pinned model binding, common non-empty finite
    /// dimensionality, ordinal/chunk-id match against the verified
    /// generation — so a partially staged iterator fails before any row is
    /// committed, never leaving a partial pool behind.
    pub fn store_vectors_stream(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        vectors: &mut dyn Iterator<Item = BrainResult<(u64, String, Vec<f32>)>>,
    ) -> BrainResult<StoreOutcome> {
        let connection = self.lock_connection()?;
        // Header-only: chunk text never loads here (unlike the one-shot
        // `store_vectors`, which re-verifies content digests over a full
        // `load_in`; chunk integrity is verified on every full load, and
        // chunk rows are immutable once stored).
        let Some(generation) = Self::load_header(&connection, generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        if generation.embedding_model != *embedding_model {
            return Err(BrainError::StaleAuthority {
                authority: "embedding_model",
                detail: format!(
                    "vectors are bound to model {} but generation {} pins {}",
                    embedding_model.as_str(),
                    generation.generation_id,
                    generation.embedding_model.as_str(),
                ),
            });
        }
        let chunk_total = connection.query_row(
            "SELECT COUNT(*) FROM brain_index_chunk WHERE generation_id = ?1",
            params![generation_id.to_string()],
            |row| row.get::<_, i64>(0),
        )? as usize;
        if chunk_total == 0 {
            return Err(BrainError::InvalidRequest(
                "a generation without chunks has no pool to store".to_owned(),
            ));
        }
        let existing_total = connection.query_row(
            "SELECT COUNT(*) FROM brain_index_vector WHERE generation_id = ?1",
            params![generation_id.to_string()],
            |row| row.get::<_, i64>(0),
        )? as usize;
        if existing_total > chunk_total {
            return Err(corrupt(
                "stored vector pool exceeds the generation's chunk count",
            ));
        }
        if existing_total > 0 && existing_total != chunk_total {
            return Err(corrupt(format!(
                "generation {} has a partial stored vector pool ({} of {} chunks)",
                generation.generation_id, existing_total, chunk_total
            )));
        }
        // Two lockstep cursors, no materialization: chunk membership rows
        // (ordinal + id only) on one side, staged vectors on the other.
        let mut membership = connection.prepare(
            "SELECT ordinal, chunk_id FROM brain_index_chunk
             WHERE generation_id = ?1 ORDER BY ordinal",
        )?;
        let mut membership_rows = membership.query(params![generation_id.to_string()])?;
        let mut stored_row = connection.prepare(
            "SELECT chunk_id, embedding_model, dims FROM brain_index_vector
             WHERE generation_id = ?1 AND ordinal = ?2",
        )?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        let verify_only = existing_total == chunk_total && chunk_total > 0;
        let mut dimensions: Option<usize> = None;
        let mut yielded = 0_usize;
        let staged = vectors;
        loop {
            let staged_vector = staged.next();
            // Rows::next yields Result<Option<&Row>>: propagate the error,
            // keep the optional row.
            let membership_row = membership_rows.next()?;
            match (staged_vector, membership_row) {
                (None, None) => break,
                (None, Some(_)) | (Some(_), None) => {
                    tx.rollback()?;
                    return Err(BrainError::InvalidRequest(
                        "a vector pool must cover every stored chunk exactly; the staged \
                         stream length does not match the generation's chunk membership"
                            .to_owned(),
                    ));
                }
                (Some(vector), Some(row)) => {
                    let member_ordinal = row.get::<_, i64>(0)?;
                    let member_chunk_id = row.get::<_, String>(1)?;
                    let (ordinal, chunk_id, dims) = vector?;
                    let expected_ordinal = yielded as u64;
                    if ordinal != expected_ordinal || member_ordinal as u64 != expected_ordinal {
                        tx.rollback()?;
                        return Err(BrainError::InvalidRequest(format!(
                            "staged vector ordinal {ordinal} does not match the chunk membership \
                             position {expected_ordinal}"
                        )));
                    }
                    if chunk_id != member_chunk_id {
                        tx.rollback()?;
                        return Err(BrainError::InvalidRequest(format!(
                            "staged vector chunk id {chunk_id} does not match the stored chunk {} \
                             at ordinal {expected_ordinal}",
                            member_chunk_id
                        )));
                    }
                    if let Some(reason) = invalid_dims_reason(&dims) {
                        tx.rollback()?;
                        return Err(BrainError::InvalidRequest(format!(
                            "vector for chunk {chunk_id} is not a usable embedding: {reason}"
                        )));
                    }
                    match dimensions {
                        None => dimensions = Some(dims.len()),
                        Some(pinned) if pinned != dims.len() => {
                            tx.rollback()?;
                            return Err(BrainError::InvalidRequest(format!(
                                "vector for chunk {chunk_id} has {} dimensions but the pool \
                                 pins {pinned}",
                                dims.len()
                            )));
                        }
                        Some(_) => {}
                    }
                    let encoded = encode_dims(&dims);
                    if verify_only {
                        let stored: Option<(String, String, Vec<u8>)> = stored_row
                            .query_row(
                                params![generation_id.to_string(), expected_ordinal as i64],
                                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                            )
                            .optional()?;
                        // Membership and model binding only: the stored
                        // floats stay canonical (see store_vectors — the
                        // embedder is not bit-reproducible).
                        let consistent = matches!(
                            stored.as_ref(),
                            Some((stored_chunk, stored_model, _))
                                if stored_chunk == &chunk_id
                                    && stored_model == embedding_model.as_str()
                        );
                        if !consistent {
                            tx.rollback()?;
                            return Err(corrupt(
                                "stored vector rows diverge from the restaged chunk membership \
                                 or model binding under one generation ID",
                            ));
                        }
                    } else {
                        tx.execute(
                            "INSERT INTO brain_index_vector
                                (generation_id, ordinal, chunk_id, embedding_model, dims)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            params![
                                generation_id.to_string(),
                                expected_ordinal as i64,
                                chunk_id,
                                embedding_model.as_str(),
                                encoded,
                            ],
                        )?;
                    }
                    yielded += 1;
                }
            }
        }
        drop(membership_rows);
        drop(membership);
        // Full membership is required on every path: a one-vector prefix
        // can never pass as an already-stored pool.
        if yielded != chunk_total {
            tx.rollback()?;
            return Err(BrainError::InvalidRequest(format!(
                "a vector pool must cover every stored chunk exactly: {yielded} of \
                 {chunk_total} vectors were staged"
            )));
        }
        tx.commit()?;
        drop(stored_row);
        drop(connection);
        self.transfer_pool_to_postgres(generation_id, embedding_model)?;
        if verify_only {
            return Ok(StoreOutcome::AlreadyPresent);
        }
        Ok(StoreOutcome::Stored)
    }
}

/// One raw vector row as stored, before revalidation.
struct StoredVectorRow {
    ordinal: usize,
    chunk_id: String,
    embedding_model: String,
    dims: Vec<u8>,
}

/// Reads raw vector rows for one generation, ordered by chunk ordinal.
fn read_vector_rows(
    connection: &Connection,
    generation_id: &IndexGenerationId,
) -> BrainResult<Vec<StoredVectorRow>> {
    let mut statement = connection.prepare(
        "SELECT ordinal, chunk_id, embedding_model, dims
         FROM brain_index_vector WHERE generation_id = ?1 ORDER BY ordinal",
    )?;
    let mut rows_out = Vec::new();
    for row in statement.query_map(params![generation_id.to_string()], |row| {
        Ok(StoredVectorRow {
            ordinal: row.get::<_, i64>(0)? as usize,
            chunk_id: row.get::<_, String>(1)?,
            embedding_model: row.get::<_, String>(2)?,
            dims: row.get::<_, Vec<u8>>(3)?,
        })
    })? {
        rows_out.push(row?);
    }
    Ok(rows_out)
}

/// Encodes dimensions as a little-endian `f32` run.
fn encode_dims(dims: &[f32]) -> Vec<u8> {
    dims.iter().copied().flat_map(f32::to_le_bytes).collect()
}

/// Returns the reason a caller-offered vector is unusable, if any: an empty
/// or non-finite run can never be a real embedding.
fn invalid_dims_reason(dims: &[f32]) -> Option<String> {
    if dims.is_empty() {
        return Some("vector has no dimensions".to_owned());
    }
    let nonfinite = dims.iter().position(|value| !value.is_finite())?;
    Some(format!("dimension {nonfinite} is not finite"))
}
