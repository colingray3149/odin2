//! Store-side transfer of one generation's durable SQLite vector pool into
//! the Postgres chunk embeddings.

use super::IndexStore;
use crate::error::BrainResult;
use odin_domain::knowledge::ids::{EmbeddingModelId, IndexGenerationId};

/// Rows per Postgres embedding write: the transfer batches at the same
/// 500-row bound as the chunk copy.
const EMBEDDING_BATCH: usize = 500;

impl IndexStore {
    /// Copies a durable pool; outages defer transfer without losing SQLite data.
    pub(super) fn transfer_pool_to_postgres(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
    ) -> BrainResult<()> {
        let Some(postgres) = self.postgres.as_ref() else {
            return Ok(());
        };
        let (generation, model) = (
            generation_id.to_string(),
            embedding_model.as_str().to_owned(),
        );
        let mut batch = Vec::with_capacity(EMBEDDING_BATCH);
        let transferred = self
            .for_each_vector(generation_id, |ordinal, _, dims| {
                batch.push((ordinal, dims.to_vec()));
                if batch.len() == EMBEDDING_BATCH {
                    let full = std::mem::replace(&mut batch, Vec::with_capacity(EMBEDDING_BATCH));
                    postgres.insert_embeddings(&generation, &model, full)?;
                }
                Ok(())
            })
            .and_then(|streamed| {
                let tail = batch.len();
                if tail > 0 {
                    postgres.insert_embeddings(&generation, &model, batch)?;
                }
                Ok(streamed)
            });
        match transferred {
            Ok(rows) if rows > 0 => tracing::info!(
                generation = %generation,
                model = %model,
                rows,
                "postgres vectors transferred"
            ),
            Ok(_) => {}
            Err(error) if error.is_postgres_outage() => tracing::warn!(
                generation = %generation,
                model = %model,
                error = %error,
                "postgres vector transfer deferred"
            ),
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Resumes the durable pool's transfer for at most EMBEDDING_BATCH rows
    /// whose Postgres chunk still lacks an embedding: one warm round
    /// nominates the missing rows in the store, copies exactly those
    /// vectors from SQLite, and never rewrites an embedding the store
    /// already holds. Returns how many vectors were copied.
    pub(crate) fn transfer_missing_vectors(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
    ) -> BrainResult<usize> {
        let Some(postgres) = self.postgres() else {
            return Ok(0);
        };
        if self.vector_count(generation_id)? == 0 {
            return Ok(0);
        }
        let (missing, _) =
            postgres.unembedded(vec![generation_id.to_string()], EMBEDDING_BATCH as i64)?;
        if missing.is_empty() {
            return Ok(0);
        }
        let ordinals: Vec<i64> = missing.iter().map(|row| row.ordinal).collect();
        let vectors = self.vectors_at(generation_id, &ordinals)?;
        if vectors.is_empty() {
            return Ok(0);
        }
        let copied = vectors.len();
        let rows = vectors
            .into_iter()
            .map(|(ordinal, vector)| (ordinal, vector.dims().to_vec()))
            .collect();
        postgres.insert_embeddings(&generation_id.to_string(), embedding_model.as_str(), rows)?;
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Arc;

    use odin_domain::knowledge::ids::{AtlasId, KnowledgeChunkId};
    use odin_domain::knowledge::retrieval::TrustClass;
    use odin_domain::Digest;

    use super::*;
    use crate::index::build::{build_index, Chunker};
    use crate::index::postgres::{BrainPostgres, EMBEDDING_DIMS};
    use crate::index::store::StoreOutcome;
    use crate::postgres_test_cluster::TestCluster;
    use crate::source::SourceItem;

    fn psql(cluster: &TestCluster, sql: &str) -> String {
        let output = std::process::Command::new("psql")
            .args([&cluster.conninfo, "-tAc", sql])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// One unit vector along `axis`: exact under the halfvec column.
    fn axis(axis: usize) -> Vec<f32> {
        let mut dims = vec![0.0; EMBEDDING_DIMS];
        dims[axis % EMBEDDING_DIMS] = 1.0;
        dims
    }

    fn halfvec_text(axis_index: usize) -> String {
        let dims: Vec<&str> = (0..EMBEDDING_DIMS)
            .map(|ordinal| {
                if ordinal == axis_index % EMBEDDING_DIMS {
                    "1"
                } else {
                    "0"
                }
            })
            .collect();
        format!("[{}]", dims.join(","))
    }

    fn embedding(cluster: &TestCluster, generation: &str, ordinal: i64) -> String {
        psql(
            cluster,
            &format!(
                "SELECT coalesce(embedding::text, 'null') FROM brain_chunk \
                 WHERE generation_id = '{generation}' AND ordinal = {ordinal}"
            ),
        )
    }

    #[test]
    fn a_pool_completed_after_seal_reaches_postgres_exactly_and_keeps_the_canonical_rows() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = std::env::temp_dir().join(format!("odin-late-pool-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let (source, revision) = (
            AtlasId::new("atlas:late-pool").unwrap(),
            Digest::hash(b"late-pool"),
        );
        // One long item: enough chunks to cross one transfer batch.
        let text =
            "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ".repeat(400);
        let items = vec![SourceItem::new(
            source.clone(),
            revision,
            b"late-pool-item",
            TrustClass::Curated,
            text,
        )
        .unwrap()];
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source, revision, &items, &chunker).unwrap();
        assert!(
            build.chunks.len() > 500,
            "the pool must cross one transfer batch: {}",
            build.chunks.len()
        );
        let (generation_id, model) = (
            build.generation.generation_id,
            build.generation.embedding_model.clone(),
        );
        let store = IndexStore::open(&root)
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        store.store(&build, 7).unwrap();
        assert!(store.seal(&generation_id, None).unwrap());
        let generation = generation_id.to_string();

        // Sealed before any pool existed: Postgres holds every chunk with a
        // null embedding.
        assert_eq!(
            psql(
                &cluster,
                &format!("SELECT chunk_count FROM brain_generation_header WHERE generation_id = '{generation}'")
            ),
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_chunk WHERE generation_id = '{generation}' \
                     AND embedding IS NULL"
                )
            ),
            "the seal predates the pool; Postgres holds the chunks unembedded"
        );

        // An earlier warm round won the race for ordinal 499: its embedding
        // is already canonical in Postgres.
        postgres
            .insert_embeddings(&generation, model.as_str(), vec![(499, axis(5))])
            .unwrap();

        let (_, chunks) = store.load(&generation_id).unwrap().unwrap();
        let pool: Vec<(KnowledgeChunkId, Vec<f32>)> = chunks
            .iter()
            .enumerate()
            .map(|(ordinal, chunk)| (chunk.chunk_id, axis(ordinal + 6)))
            .collect();
        assert_eq!(
            store.store_vectors(&generation_id, &model, &pool).unwrap(),
            StoreOutcome::Stored
        );

        // Every unembedded ordinal got the exact staged vector in its batch;
        // the canonical row was not rewritten.
        let last = chunks.len() as i64 - 1;
        for ordinal in [0, 499, 500, last] {
            let expected = if ordinal == 499 {
                5
            } else {
                ordinal as usize + 6
            };
            assert_eq!(
                embedding(&cluster, &generation, ordinal),
                halfvec_text(expected),
                "ordinal {ordinal} must hold the exact vector"
            );
        }
        assert_eq!(
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_chunk WHERE generation_id = '{generation}' \
                     AND embedding IS NULL"
                )
            ),
            "0"
        );

        // The SQLite pool stays canonical and byte-exact.
        let stored = store.load_vectors(&generation_id).unwrap().unwrap();
        assert_eq!(stored.embedding_model, model);
        for (ordinal, vector) in stored.vectors.iter().enumerate() {
            assert_eq!(vector.dims(), pool[ordinal].1);
        }

        // Re-staging the pool transfers nothing new and rewrites nothing.
        assert_eq!(
            store.store_vectors(&generation_id, &model, &pool).unwrap(),
            StoreOutcome::AlreadyPresent
        );
        assert_eq!(
            embedding(&cluster, &generation, 499),
            halfvec_text(5),
            "the canonical embedding is never rewritten"
        );
        assert_eq!(embedding(&cluster, &generation, 500), halfvec_text(506));
    }

    /// MEDIUM: rows mirrored before their vectors — the pre-pool seal's
    /// text mirror, an interrupted post-seal transfer — resume from the
    /// durable pool in bounded warm rounds, never rewrite an embedding
    /// Postgres already holds, and leave the SQLite pool canonical.
    #[test]
    fn warm_rounds_resume_the_durable_pool_over_existing_text_rows_in_bounds() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let root = std::env::temp_dir().join(format!("odin-pool-resume-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let (source, revision) = (
            AtlasId::new("atlas:pool-resume").unwrap(),
            Digest::hash(b"pool-resume"),
        );
        // One long item: enough chunks for several bounded rounds.
        let text =
            "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu ".repeat(800);
        let items = vec![SourceItem::new(
            source.clone(),
            revision,
            b"pool-resume-item",
            TrustClass::Curated,
            text,
        )
        .unwrap()];
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source, revision, &items, &chunker).unwrap();
        assert!(
            build.chunks.len() > 1_000,
            "the pool must span several bounded rounds: {}",
            build.chunks.len()
        );
        let (generation_id, model) = (
            build.generation.generation_id,
            build.generation.embedding_model.clone(),
        );
        let generation = generation_id.to_string();

        // Sealed before any pool existed: the copy loop mirrors text only,
        // so every Postgres row is an existing unembedded text row.
        {
            let store = IndexStore::open(&root)
                .unwrap()
                .with_postgres(Some(Arc::clone(&postgres)));
            store.store(&build, 7).unwrap();
            assert!(store.seal(&generation_id, None).unwrap());
        }
        assert_eq!(
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_chunk WHERE generation_id = '{generation}' \
                     AND embedding IS NOT NULL"
                )
            ),
            "0",
            "the seal predates the pool; every mirrored row is unembedded"
        );

        // The pool lands in SQLite only — the transfer was interrupted
        // before any batch, and one row already won a canonical embedding
        // the resume must never rewrite.
        {
            let staging = IndexStore::open(&root).unwrap();
            let (_, chunks) = staging.load(&generation_id).unwrap().unwrap();
            let pool: Vec<(KnowledgeChunkId, Vec<f32>)> = chunks
                .iter()
                .enumerate()
                .map(|(ordinal, chunk)| (chunk.chunk_id, axis(ordinal + 6)))
                .collect();
            assert_eq!(
                staging
                    .store_vectors(&generation_id, &model, &pool)
                    .unwrap(),
                StoreOutcome::Stored
            );
        }
        postgres
            .insert_embeddings(&generation, model.as_str(), vec![(700, axis(5))])
            .unwrap();

        // Warm rounds copy the pool back in bounded batches until the
        // canonical row is the only one they never touched.
        let warm = IndexStore::open(&root)
            .unwrap()
            .with_postgres(Some(Arc::clone(&postgres)));
        let total = psql(
            &cluster,
            &format!("SELECT count(*) FROM brain_chunk WHERE generation_id = '{generation}'"),
        )
        .parse::<usize>()
        .unwrap();
        // The canonical row is the only row a warm round skips, so the
        // resume converges in exactly this many bounded batches.
        let expected_rounds = (total - 1).div_ceil(EMBEDDING_BATCH);
        let mut rounds = 0_usize;
        loop {
            let copied = warm
                .transfer_missing_vectors(&generation_id, &model)
                .unwrap();
            if copied == 0 {
                break;
            }
            rounds += 1;
            assert!(
                copied <= EMBEDDING_BATCH,
                "a warm round copies at most one bounded batch: {copied}"
            );
            assert!(
                rounds <= expected_rounds,
                "the resume must converge in bounded rounds: {rounds} > {expected_rounds}"
            );
        }
        assert_eq!(
            rounds,
            (total - 1).div_ceil(EMBEDDING_BATCH),
            "every row but the canonical one was copied in bounded rounds"
        );
        assert_eq!(
            psql(
                &cluster,
                &format!(
                    "SELECT count(*) FROM brain_chunk WHERE generation_id = '{generation}' \
                     AND embedding IS NULL"
                )
            ),
            "0"
        );
        assert_eq!(
            embedding(&cluster, &generation, 700),
            halfvec_text(5),
            "the canonical embedding is never rewritten"
        );
        for ordinal in [0_usize, 499, 500, 699, 701] {
            assert_eq!(
                embedding(&cluster, &generation, ordinal as i64),
                halfvec_text(ordinal + 6),
                "ordinal {ordinal} must hold the exact staged vector"
            );
        }

        // The SQLite pool stays canonical and byte-exact.
        let stored = warm.load_vectors(&generation_id).unwrap().unwrap();
        assert_eq!(stored.embedding_model, model);
        for (ordinal, vector) in stored.vectors.iter().enumerate() {
            assert_eq!(vector.dims(), axis(ordinal + 6));
        }
    }
}
