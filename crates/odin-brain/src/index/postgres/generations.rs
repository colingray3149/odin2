//! PostgreSQL chunk citations, item provenance, and headers published after row validation.

use sqlx::Row;

use super::{BrainPostgres, ChunkRow};
use crate::error::BrainResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HeaderRow {
    pub generation_id: String,
    pub atlas_id: String,
    pub atlas_revision: String,
    pub chunker_version: String,
    pub tokenizer: String,
    pub embedding_model: String,
    pub manifest_digest: String,
    pub created_epoch: i64,
    pub chunk_count: i64,
}

/// One chunk with its citation identity, as copied and as served.
#[derive(Clone, Debug)]
pub(crate) struct CitedRow {
    pub ordinal: i64,
    pub chunk_id: String,
    pub item: String,
    pub trust: String,
    pub digest: String,
    pub text: String,
    pub byte_start: i64,
    pub byte_end: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct ProvenanceRow {
    pub item_id: String,
    pub node_id: String,
    pub path: String,
    pub source_class: String,
    pub scope_tags: Vec<String>,
}

/// Whether [`BrainPostgres::seal`] queues behind the generation's
/// advisory lock or refuses at once when another transaction holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SealWait {
    #[cfg(test)]
    /// Waits for serialized publication in tests.
    Wait,
    /// Never wait: a concurrent sealer or releaser wins the lock and the
    /// caller defers — a turn never queues behind a whole-generation seal.
    Try,
}

/// Why [`BrainPostgres::seal`] published nothing.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SealRejection {
    /// Validation failed; the caller drops the rows before another copy.
    Rejected(String),
    /// [`SealWait::Try`] found the generation's advisory lock held:
    /// nothing is published and the stored rows are untouched — the
    /// lock's holder, a concurrent sealer, owns them.
    Busy,
}

const HEADER_COLUMNS: &str = "generation_id, atlas_id, atlas_revision, chunker_version, \
                              tokenizer, embedding_model, manifest_digest, created_epoch, \
                              chunk_count";

const CITED: &str = "SELECT k.ordinal, k.chunk_id, c.item, k.trust, c.digest, c.text, \
                     k.byte_start, k.byte_end \
                     FROM brain_chunk_cite k JOIN brain_chunk c \
                       ON c.generation_id = k.generation_id AND c.ordinal = k.ordinal";

fn header(row: sqlx::postgres::PgRow) -> Result<HeaderRow, sqlx::Error> {
    Ok(HeaderRow {
        generation_id: row.try_get(0)?,
        atlas_id: row.try_get(1)?,
        atlas_revision: row.try_get(2)?,
        chunker_version: row.try_get(3)?,
        tokenizer: row.try_get(4)?,
        embedding_model: row.try_get(5)?,
        manifest_digest: row.try_get(6)?,
        created_epoch: row.try_get(7)?,
        chunk_count: row.try_get(8)?,
    })
}

fn cited(row: sqlx::postgres::PgRow) -> Result<CitedRow, sqlx::Error> {
    Ok(CitedRow {
        ordinal: row.try_get(0)?,
        chunk_id: row.try_get(1)?,
        item: row.try_get(2)?,
        trust: row.try_get(3)?,
        digest: row.try_get(4)?,
        text: row.try_get(5)?,
        byte_start: row.try_get(6)?,
        byte_end: row.try_get(7)?,
    })
}

impl BrainPostgres {
    /// The sealed headers among `generations` that `owner` holds.
    pub(crate) fn held(
        &self,
        owner: &str,
        generations: Vec<String>,
    ) -> BrainResult<Vec<HeaderRow>> {
        let owner = owner.to_owned();
        self.run(|pool| async move {
            let sql = format!(
                "SELECT {HEADER_COLUMNS} FROM brain_generation_header \
                 WHERE generation_id = ANY($2) AND generation_id IN \
                   (SELECT generation_id FROM brain_generation WHERE owner = $1)"
            );
            sqlx::query(&sql)
                .bind(owner)
                .bind(generations)
                .try_map(header)
                .fetch_all(&pool)
                .await
        })
    }

    /// The sealed header of `generation`, held for `owner` from now on so
    /// another store's release cannot drop rows this one serves. `None`
    /// also while another transaction holds the generation's advisory
    /// lock — a seal or a release in flight: the read gate never queues
    /// behind it, and the caller serves the intact SQLite rows instead.
    pub(crate) fn hold(&self, owner: &str, generation: &str) -> BrainResult<Option<HeaderRow>> {
        let (owner, generation) = (owner.to_owned(), generation.to_owned());
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            let acquired: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                    .bind(&generation)
                    .fetch_one(&mut *transaction)
                    .await?;
            if !acquired {
                transaction.rollback().await?;
                return Ok(None);
            }
            let sql = format!(
                "SELECT {HEADER_COLUMNS} FROM brain_generation_header WHERE generation_id = $1"
            );
            let found = sqlx::query(&sql)
                .bind(&generation)
                .try_map(header)
                .fetch_optional(&mut *transaction)
                .await?;
            if found.is_some() {
                sqlx::query(
                    "INSERT INTO brain_generation (owner, generation_id) VALUES ($1, $2) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&owner)
                .bind(&generation)
                .execute(&mut *transaction)
                .await?;
            }
            transaction.commit().await?;
            Ok(found)
        })
    }

    /// The id and `created_epoch` of the newest sealed generation of one
    /// source revision, stamped with `model` when one is given.
    pub(crate) fn sealed_current(
        &self,
        atlas_id: &str,
        atlas_revision: &str,
        model: Option<&str>,
    ) -> BrainResult<Option<(String, i64)>> {
        let (atlas_id, atlas_revision) = (atlas_id.to_owned(), atlas_revision.to_owned());
        let model = model.map(str::to_owned);
        self.run(|pool| async move {
            sqlx::query_as(
                "SELECT generation_id, created_epoch FROM brain_generation_header \
                 WHERE atlas_id = $1 AND atlas_revision = $2 \
                   AND ($3::text IS NULL OR embedding_model = $3) \
                 ORDER BY created_epoch DESC, generation_id DESC LIMIT 1",
            )
            .bind(atlas_id)
            .bind(atlas_revision)
            .bind(model)
            .fetch_optional(&pool)
            .await
        })
    }

    pub(crate) fn last_ordinal(&self, generation: &str) -> BrainResult<Option<i64>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            sqlx::query_scalar("SELECT max(ordinal) FROM brain_chunk WHERE generation_id = $1")
                .bind(generation)
                .fetch_one(&pool)
                .await
        })
    }

    /// The highest ordinal whose citation is stored: chunks are copied in
    /// ordinal order, so a resumed copy continues after it.
    pub(crate) fn cited_through(&self, generation: &str) -> BrainResult<Option<i64>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            sqlx::query_scalar("SELECT max(ordinal) FROM brain_chunk_cite WHERE generation_id = $1")
                .bind(generation)
                .fetch_one(&pool)
                .await
        })
    }

    /// Copies one batch of chunks with their citations; rows already
    /// present stay. Returns false when the write is deferred: another
    /// transaction holds the generation's advisory lock — a seal proving
    /// or publishing, which a row write must never race — or the
    /// generation is already sealed and its rows are immutable.
    pub(crate) fn copy_cited(
        &self,
        generation: &str,
        model: &str,
        rows: Vec<(CitedRow, Option<Vec<f32>>)>,
    ) -> BrainResult<bool> {
        let mut chunks = Vec::with_capacity(rows.len());
        let mut cites = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (row, embedding) in rows {
            cites.0.push(row.ordinal);
            cites.1.push(row.chunk_id);
            cites.2.push(row.trust);
            cites.3.push(row.byte_start);
            cites.4.push(row.byte_end);
            chunks.push(ChunkRow {
                ordinal: row.ordinal,
                item: row.item,
                digest: row.digest,
                text: row.text,
                embedding,
            });
        }
        if !self.insert_chunks(generation, model, chunks)? {
            return Ok(false);
        }
        let generation = generation.to_owned();
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            if !row_write_open(&mut transaction, &generation).await? {
                return Ok(false);
            }
            sqlx::query(
                "INSERT INTO brain_chunk_cite \
                     (generation_id, ordinal, chunk_id, trust, byte_start, byte_end) \
                 SELECT $1, * FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::bigint[], \
                                          $6::bigint[]) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(generation)
            .bind(cites.0)
            .bind(cites.1)
            .bind(cites.2)
            .bind(cites.3)
            .bind(cites.4)
            .execute(&mut *transaction)
            .await
            .map(drop)?;
            transaction.commit().await?;
            Ok(true)
        })
    }

    /// Copies one batch of item provenance; rows already present stay.
    /// One statement per batch: a sealed generation's provenance is part
    /// of its identity, so a conflict never rewrites an existing row.
    /// Returns false when the write is deferred, like [`Self::copy_cited`].
    pub(crate) fn copy_provenance(
        &self,
        generation: &str,
        rows: Vec<ProvenanceRow>,
    ) -> BrainResult<bool> {
        let rows: Vec<_> = rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "item_id": row.item_id,
                    "node_id": row.node_id,
                    "path": row.path,
                    "source_class": row.source_class,
                    "scope_tags": row.scope_tags,
                })
            })
            .collect();
        let rows = serde_json::to_string(&rows)?;
        let generation = generation.to_owned();
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            if !row_write_open(&mut transaction, &generation).await? {
                return Ok(false);
            }
            sqlx::query(
                "INSERT INTO brain_item_provenance \
                     (generation_id, item_id, node_id, path, source_class, scope_tags) \
                 SELECT $1, r.item_id, r.node_id, r.path, r.source_class, r.scope_tags \
                 FROM jsonb_to_recordset($2::text::jsonb) \
                   AS r(item_id text, node_id text, path text, source_class text, \
                        scope_tags text[]) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(generation)
            .bind(rows)
            .execute(&mut *transaction)
            .await
            .map(drop)?;
            transaction.commit().await?;
            Ok(true)
        })
    }

    /// Records `owner` as holding a generation whose rows are being
    /// copied, before the first batch lands: a concurrent release then
    /// refcounts the copy in flight instead of dropping its rows.
    pub(crate) fn claim(&self, owner: &str, generation: &str) -> BrainResult<()> {
        let (owner, generation) = (owner.to_owned(), generation.to_owned());
        self.run(|pool| async move {
            sqlx::query(
                "INSERT INTO brain_generation (owner, generation_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(owner)
            .bind(generation)
            .execute(&pool)
            .await
            .map(drop)
        })
    }

    /// The cited chunks of one generation at `ordinals`, in any order.
    pub(crate) fn cited_at(
        &self,
        generation: &str,
        ordinals: Vec<i64>,
    ) -> BrainResult<Vec<CitedRow>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            let sql = format!("{CITED} WHERE k.generation_id = $1 AND k.ordinal = ANY($2)");
            sqlx::query(&sql)
                .bind(generation)
                .bind(ordinals)
                .try_map(cited)
                .fetch_all(&pool)
                .await
        })
    }

    /// The ordinals of every chunk of `items` in one generation.
    pub(crate) fn item_ordinals(
        &self,
        generation: &str,
        items: Vec<String>,
    ) -> BrainResult<Vec<i64>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            sqlx::query_scalar(
                "SELECT ordinal FROM brain_lex WHERE generation_id = $1 AND item = ANY($2) \
                 ORDER BY ordinal",
            )
            .bind(generation)
            .bind(items)
            .fetch_all(&pool)
            .await
        })
    }

    /// The item provenance of one generation, `item` alone when given.
    pub(crate) fn provenance_rows(
        &self,
        generation: &str,
        item: Option<String>,
    ) -> BrainResult<Vec<ProvenanceRow>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            sqlx::query(
                "SELECT item_id, node_id, path, source_class, scope_tags \
                 FROM brain_item_provenance \
                 WHERE generation_id = $1 AND ($2::text IS NULL OR item_id = $2)",
            )
            .bind(generation)
            .bind(item)
            .try_map(|row: sqlx::postgres::PgRow| {
                Ok(ProvenanceRow {
                    item_id: row.try_get(0)?,
                    node_id: row.try_get(1)?,
                    path: row.try_get(2)?,
                    source_class: row.try_get(3)?,
                    scope_tags: row.try_get(4)?,
                })
            })
            .fetch_all(&pool)
            .await
        })
    }

    pub(crate) fn has_item(&self, generation: &str, item: &str) -> BrainResult<bool> {
        let (generation, item) = (generation.to_owned(), item.to_owned());
        self.run(|pool| async move {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM brain_lex WHERE generation_id = $1 AND item = $2)",
            )
            .bind(generation)
            .bind(item)
            .fetch_one(&pool)
            .await
        })
    }

    /// Validates rows and publishes the header under the same advisory lock
    /// used by all mutators. Chunk/citation membership is checked separately
    /// so inner joins cannot hide uncited chunks or orphan citations.
    /// `Try` returns `Busy` without waiting; rejection rolls back before
    /// returning so cleanup can acquire the lock immediately.
    pub(crate) fn seal(
        &self,
        owner: &str,
        header: HeaderRow,
        batch: i64,
        proof: impl SealProof,
        wait: SealWait,
    ) -> BrainResult<Result<(), SealRejection>> {
        let owner = owner.to_owned();
        self.run(move |pool| async move {
            let mut transaction = pool.begin().await?;
            let acquired: bool = match wait {
                #[cfg(test)]
                SealWait::Wait => {
                    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                        .bind(&header.generation_id)
                        .execute(&mut *transaction)
                        .await?;
                    true
                }
                SealWait::Try => {
                    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                        .bind(&header.generation_id)
                        .fetch_one(&mut *transaction)
                        .await?
                }
            };
            if !acquired {
                return Ok(Err(SealRejection::Busy));
            }
            if let Err(reason) =
                prove(&mut transaction, &header.generation_id, batch, proof).await?
            {
                transaction.rollback().await?;
                return Ok(Err(SealRejection::Rejected(reason)));
            }
            if let Err(reason) =
                prove_sets(&mut transaction, &header.generation_id, header.chunk_count).await?
            {
                transaction.rollback().await?;
                return Ok(Err(SealRejection::Rejected(reason)));
            }
            let sql = format!(
                "INSERT INTO brain_generation_header ({HEADER_COLUMNS}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING"
            );
            sqlx::query(&sql)
                .bind(&header.generation_id)
                .bind(header.atlas_id)
                .bind(header.atlas_revision)
                .bind(header.chunker_version)
                .bind(header.tokenizer)
                .bind(header.embedding_model)
                .bind(header.manifest_digest)
                .bind(header.created_epoch)
                .bind(header.chunk_count)
                .execute(&mut *transaction)
                .await?;
            sqlx::query(
                "INSERT INTO brain_generation (owner, generation_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&owner)
            .bind(&header.generation_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(Ok(()))
        })
    }

    /// Removes rejected unsealed rows without waiting for another transaction.
    /// Sealed rows are untouched; skipped cleanup retries on a later rejection.
    pub(crate) fn discard_unsealed(&self, generation: &str) -> BrainResult<()> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            let acquired: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                    .bind(&generation)
                    .fetch_one(&mut *transaction)
                    .await?;
            if !acquired {
                return Ok(());
            }
            for table in ["brain_chunk_cite", "brain_item_provenance", "brain_chunk"] {
                let sql = format!(
                    "DELETE FROM {table} WHERE generation_id = $1 AND NOT EXISTS \
                     (SELECT 1 FROM brain_generation_header WHERE generation_id = $1)"
                );
                sqlx::query(&sql)
                    .bind(&generation)
                    .execute(&mut *transaction)
                    .await?;
            }
            transaction.commit().await
        })
    }
}

/// Check counts and membership separately: read-back's inner join hides
/// uncited chunks and orphan citations.
async fn prove_sets(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
    expected: i64,
) -> Result<Result<(), String>, sqlx::Error> {
    let (stored, uncited, orphans): (i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT count(*) FROM brain_chunk WHERE generation_id = $1), \
           (SELECT count(*) FROM brain_chunk c WHERE c.generation_id = $1 \
              AND NOT EXISTS (SELECT 1 FROM brain_chunk_cite k \
                              WHERE k.generation_id = $1 AND k.ordinal = c.ordinal)), \
           (SELECT count(*) FROM brain_chunk_cite k WHERE k.generation_id = $1 \
              AND NOT EXISTS (SELECT 1 FROM brain_chunk c \
                              WHERE c.generation_id = $1 AND c.ordinal = k.ordinal))",
    )
    .bind(generation)
    .fetch_one(&mut *transaction)
    .await?;
    if stored != expected {
        return Ok(Err(format!("{stored} of {expected} chunk rows are stored")));
    }
    if uncited != 0 {
        return Ok(Err(format!("{uncited} stored chunks have no citation")));
    }
    if orphans != 0 {
        return Ok(Err(format!("{orphans} citations have no stored chunk")));
    }
    Ok(Ok(()))
}

/// Validates read-back batches inside the publication transaction;
/// `Err(reason)` rejects the seal.
pub(crate) trait SealProof: Send + 'static {
    /// Folds one read-back batch of cited chunks, in ordinal order.
    fn feed_chunks(&mut self, rows: Vec<CitedRow>) -> Result<(), String>;
    /// Folds one read-back batch of item provenance, in item order.
    fn feed_provenance(&mut self, rows: Vec<ProvenanceRow>) -> Result<(), String>;
    /// Verifies the read-back count and the recomputed manifest digest.
    fn finish(self) -> Result<(), String>;
}

/// Reads cited chunks in ordinal order after `after` within the transaction.
async fn cited_after_batch(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
    after: i64,
    limit: i64,
) -> Result<Vec<CitedRow>, sqlx::Error> {
    let sql = format!(
        "{CITED} WHERE k.generation_id = $1 AND k.ordinal > $2 ORDER BY k.ordinal LIMIT $3"
    );
    sqlx::query(&sql)
        .bind(generation)
        .bind(after)
        .bind(limit)
        .try_map(cited)
        .fetch_all(&mut *transaction)
        .await
}

async fn provenance_after_batch(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
    after: Option<&str>,
    limit: i64,
) -> Result<Vec<ProvenanceRow>, sqlx::Error> {
    sqlx::query(
        "SELECT item_id, node_id, path, source_class, scope_tags \
         FROM brain_item_provenance \
         WHERE generation_id = $1 AND ($2::text IS NULL OR item_id > $2) \
         ORDER BY item_id LIMIT $3",
    )
    .bind(generation)
    .bind(after)
    .bind(limit)
    .try_map(|row: sqlx::postgres::PgRow| {
        Ok(ProvenanceRow {
            item_id: row.try_get(0)?,
            node_id: row.try_get(1)?,
            path: row.try_get(2)?,
            source_class: row.try_get(3)?,
            scope_tags: row.try_get(4)?,
        })
    })
    .fetch_all(&mut *transaction)
    .await
}

async fn prove(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
    batch: i64,
    mut proof: impl SealProof,
) -> Result<Result<(), String>, sqlx::Error> {
    let mut after = -1_i64;
    loop {
        let rows = cited_after_batch(transaction, generation, after, batch).await?;
        let Some(last) = rows.last() else { break };
        after = last.ordinal;
        if let Err(reason) = proof.feed_chunks(rows) {
            return Ok(Err(reason));
        }
    }
    let mut after: Option<String> = None;
    loop {
        let rows = provenance_after_batch(transaction, generation, after.as_deref(), batch).await?;
        let Some(last) = rows.last() else { break };
        after = Some(last.item_id.clone());
        if let Err(reason) = proof.feed_provenance(rows) {
            return Ok(Err(reason));
        }
    }
    Ok(proof.finish())
}

/// Returns false for a held advisory lock or an already sealed generation.
/// Lock, header check, and writes share a transaction so rows cannot change
/// between validation and publication or after sealing.
pub(crate) async fn row_write_open(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
) -> Result<bool, sqlx::Error> {
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
        .bind(generation)
        .fetch_one(&mut *transaction)
        .await?;
    if !acquired {
        return Ok(false);
    }
    let sealed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM brain_generation_header WHERE generation_id = $1)",
    )
    .bind(generation)
    .fetch_one(&mut *transaction)
    .await?;
    Ok(!sealed)
}
