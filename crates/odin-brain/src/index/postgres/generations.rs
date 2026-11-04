//! PostgreSQL chunk citations, item provenance, and headers published after row validation.

use sqlx::{Connection, Row};

use super::{begin_warm, BrainPostgres, OPERATION_DEADLINE, WARM_DEADLINE};
use crate::error::{BrainError, BrainResult, POSTGRES_STORE};

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

/// Slowest read-back rate the seal's deadline allows for: half the slowest
/// measured on mini (950–4,300 rows/s, 2026-10-26), so a 2.4M-row archive
/// gets 80 minutes.
const SEAL_ROWS_PER_SECOND: u64 = 500;

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
    /// The sealed header of `generation`, held for `owner` from now on so
    /// another store's release cannot drop rows this one serves. `None`
    /// also while another transaction holds the generation's advisory
    /// lock — a seal or a release in flight: the read gate never queues
    /// behind it.
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
        self.run_warm(|pool| async move {
            let mut transaction = begin_warm(&pool).await?;
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

    /// Stages one batch of a streaming build's chunks under `stage`.
    pub(crate) fn stage_chunks(&self, stage: &str, rows: Vec<CitedRow>) -> BrainResult<()> {
        let mut columns = (
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
            Vec::with_capacity(rows.len()),
        );
        for row in rows {
            columns.0.push(row.ordinal);
            columns.1.push(row.chunk_id);
            columns.2.push(row.item);
            columns.3.push(row.trust);
            columns.4.push(row.digest);
            columns.5.push(row.text);
            columns.6.push(row.byte_start);
            columns.7.push(row.byte_end);
        }
        let stage = stage.to_owned();
        self.run_warm(|pool| async move {
            sqlx::query(
                "INSERT INTO brain_chunk_stage \
                     (stage, ordinal, chunk_id, item, trust, digest, text, byte_start, byte_end) \
                 SELECT $1, * FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::text[], \
                                          $6::text[], $7::text[], $8::bigint[], $9::bigint[])",
            )
            .bind(stage)
            .bind(columns.0)
            .bind(columns.1)
            .bind(columns.2)
            .bind(columns.3)
            .bind(columns.4)
            .bind(columns.5)
            .bind(columns.6)
            .bind(columns.7)
            .execute(&pool)
            .await
            .map(drop)
        })
    }

    /// Moves the staged chunks with ordinals in `(after, after + limit]`
    /// into `generation` with their citations; each takes the embedding of
    /// any stored chunk with the same text under `model`, so a new revision
    /// embeds only its new text. Returns how many staged rows the window
    /// held — the caller staged them all, so fewer means the stage went
    /// missing under the build — or `None` when the generation's rows are
    /// closed: sealed, or a seal holds its lock.
    pub(crate) fn promote_stage(
        &self,
        stage: &str,
        generation: &str,
        model: &str,
        after: i64,
        limit: i64,
    ) -> BrainResult<Option<i64>> {
        let (stage, generation, model) =
            (stage.to_owned(), generation.to_owned(), model.to_owned());
        self.run_warm(|pool| async move {
            let mut transaction = begin_warm(&pool).await?;
            if !row_write_open(&mut transaction, &generation).await? {
                return Ok(None);
            }
            let found: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM brain_chunk_stage \
                 WHERE stage = $1 AND ordinal > $2 AND ordinal <= $2 + $3",
            )
            .bind(&stage)
            .bind(after)
            .bind(limit)
            .fetch_one(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO brain_chunk (generation_id, ordinal, item, digest, text, model, embedding) \
                 SELECT $2, s.ordinal, s.item, s.digest, s.text, peer.model, peer.embedding \
                 FROM brain_chunk_stage s LEFT JOIN LATERAL ( \
                     SELECT model, embedding FROM brain_chunk \
                     WHERE model = $3 AND digest = s.digest AND embedding IS NOT NULL LIMIT 1 \
                 ) AS peer ON true \
                 WHERE s.stage = $1 AND s.ordinal > $4 AND s.ordinal <= $4 + $5 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&stage)
            .bind(&generation)
            .bind(&model)
            .bind(after)
            .bind(limit)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO brain_chunk_cite \
                     (generation_id, ordinal, chunk_id, trust, byte_start, byte_end) \
                 SELECT $2, ordinal, chunk_id, trust, byte_start, byte_end FROM brain_chunk_stage \
                 WHERE stage = $1 AND ordinal > $3 AND ordinal <= $3 + $4 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(&stage)
            .bind(&generation)
            .bind(after)
            .bind(limit)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(Some(found))
        })
    }

    /// Takes one build's stage lock: a session advisory lock on the
    /// stage's name, held on a dedicated connection the returned guard
    /// owns. A live owner is exactly a session holding that lock — no
    /// host or process id could say the same across a restart — so
    /// [`Self::sweep_dead_stages`] reclaims a stage only once no session
    /// holds it. Taken before the stage's first row lands.
    pub(crate) fn stage_guard(&self, stage: &str) -> BrainResult<StageGuard<'_>> {
        let (stage, locked_stage) = (stage.to_owned(), stage.to_owned());
        let connection: sqlx::postgres::PgConnection = self
            .run(move |pool| async move {
                let mut connection = pool.acquire().await?.detach();
                let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtext($1))")
                    .bind(&locked_stage)
                    .fetch_one(&mut connection)
                    .await?;
                if !locked {
                    return Ok(Err(format!(
                        "another session already holds the stage lock of {locked_stage}"
                    )));
                }
                Ok(Ok(connection))
            })?
            .map_err(|reason| BrainError::Unavailable {
                component: POSTGRES_STORE,
                reason,
            })?;
        Ok(StageGuard {
            postgres: self,
            stage,
            connection: Some(connection),
        })
    }

    /// Drops the staged rows of every stage that begins with `prefix`
    /// whose owner is gone: a stage whose session lock
    /// ([`Self::stage_guard`]) can be taken has no live owner, because
    /// Postgres released the lock with its session's end. A live build's
    /// stage is left exactly as it is. Returns how many stages went.
    pub(crate) fn sweep_dead_stages(&self, prefix: &str) -> BrainResult<usize> {
        let prefix = prefix.to_owned();
        self.run_warm(|pool| async move {
            let stages: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT stage FROM brain_chunk_stage WHERE starts_with(stage, $1)",
            )
            .bind(&prefix)
            .fetch_all(&pool)
            .await?;
            let mut swept = 0_usize;
            for stage in stages {
                let mut transaction = begin_warm(&pool).await?;
                let dead: bool =
                    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                        .bind(&stage)
                        .fetch_one(&mut *transaction)
                        .await?;
                if dead {
                    sqlx::query("DELETE FROM brain_chunk_stage WHERE stage = $1")
                        .bind(&stage)
                        .execute(&mut *transaction)
                        .await?;
                    swept += 1;
                }
                transaction.commit().await?;
            }
            Ok(swept)
        })
    }

    /// Drops the staged chunks of one stage (a finished build's own
    /// cleanup); the stages other processes left behind belong to
    /// [`Self::sweep_dead_stages`].
    pub(crate) fn drop_stage(&self, stage: &str) -> BrainResult<()> {
        let stage = stage.to_owned();
        self.run_warm(|pool| async move {
            sqlx::query("DELETE FROM brain_chunk_stage WHERE stage = $1")
                .bind(stage)
                .execute(&pool)
                .await
                .map(drop)
        })
    }

    /// Drops every stage that begins with `prefix`, live or not: the
    /// store is being removed, so no open will ever sweep its stages. A
    /// build still streaming under such a stage fails its next window and
    /// rebuilds into a store that still exists.
    pub(crate) fn drop_stages_under(&self, prefix: &str) -> BrainResult<()> {
        let prefix = prefix.to_owned();
        self.run_warm(|pool| async move {
            sqlx::query("DELETE FROM brain_chunk_stage WHERE starts_with(stage, $1)")
                .bind(prefix)
                .execute(&pool)
                .await
                .map(drop)
        })
    }

    /// The sealed headers `owner` holds, of `atlas_id` when given (and
    /// stamped with `model` when given), newest first.
    pub(crate) fn held_headers(
        &self,
        owner: &str,
        atlas_id: Option<&str>,
        model: Option<&str>,
    ) -> BrainResult<Vec<HeaderRow>> {
        let owner = owner.to_owned();
        let (atlas_id, model) = (atlas_id.map(str::to_owned), model.map(str::to_owned));
        self.run(|pool| async move {
            let sql = format!(
                "SELECT {HEADER_COLUMNS} FROM brain_generation_header \
                 WHERE ($2::text IS NULL OR atlas_id = $2) \
                   AND ($3::text IS NULL OR embedding_model = $3) \
                   AND generation_id IN \
                     (SELECT generation_id FROM brain_generation WHERE owner = $1) \
                 ORDER BY created_epoch DESC, generation_id DESC"
            );
            sqlx::query(&sql)
                .bind(owner)
                .bind(atlas_id)
                .bind(model)
                .try_map(header)
                .fetch_all(&pool)
                .await
        })
    }

    /// Up to `limit` cited chunks of one generation after ordinal `after`,
    /// in ordinal order.
    pub(crate) fn cited_after(
        &self,
        generation: &str,
        after: i64,
        limit: i64,
    ) -> BrainResult<Vec<CitedRow>> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            let mut connection = pool.acquire().await?;
            cited_after_batch(&mut connection, &generation, after, limit).await
        })
    }

    /// Records `owner` as holding a generation whose rows are being
    /// copied, before the first batch lands: a concurrent release then
    /// refcounts the copy in flight instead of dropping its rows. Each copy
    /// restarts the claim's day before the stale-claim sweep.
    pub(crate) fn claim(&self, owner: &str, generation: &str) -> BrainResult<()> {
        let (owner, generation) = (owner.to_owned(), generation.to_owned());
        self.run(|pool| async move {
            sqlx::query(
                "INSERT INTO brain_generation (owner, generation_id) VALUES ($1, $2) \
                 ON CONFLICT (owner, generation_id) DO UPDATE SET claimed_at = now()",
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
                "SELECT ordinal FROM brain_search WHERE generation_id = $1 AND item = ANY($2) \
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

    /// The scope tags of the `items` of the `generations` in one query, as
    /// `(generation, item, tags)`. Items without a provenance row are absent.
    pub(crate) fn provenance_tags(
        &self,
        generations: Vec<String>,
        items: Vec<String>,
    ) -> BrainResult<Vec<(String, String, Vec<String>)>> {
        self.run(|pool| async move {
            sqlx::query_as::<_, (String, String, Vec<String>)>(
                "SELECT generation_id, item_id, scope_tags FROM brain_item_provenance \
                 WHERE generation_id = ANY($1) AND item_id = ANY($2)",
            )
            .bind(generations)
            .bind(items)
            .fetch_all(&pool)
            .await
        })
    }

    pub(crate) fn has_item(&self, generation: &str, item: &str) -> BrainResult<bool> {
        let (generation, item) = (generation.to_owned(), item.to_owned());
        self.run(|pool| async move {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM brain_search WHERE generation_id = $1 AND item = $2)",
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
        // The proof reads every chunk back in one transaction; each page is
        // bounded by the statement timeout, so the deadline grows with the
        // generation (a floor of SEAL_ROWS_PER_SECOND) instead of cancelling
        // a million-chunk archive's publication every round.
        let proving =
            std::time::Duration::from_secs(header.chunk_count.max(0) as u64 / SEAL_ROWS_PER_SECOND);
        self.run_within(WARM_DEADLINE + proving, move |pool| async move {
            let mut transaction = begin_warm(&pool).await?;
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
}

/// One build's stage lock ([`BrainPostgres::stage_guard`]): the session
/// holding it is the stage's live owner. Dropping the guard unlocks on that
/// session and closes the connection — it is never pooled with a lock still
/// held — and a session that ends first (crash, restart, lost connection)
/// releases the lock server-side, which is what
/// [`BrainPostgres::sweep_dead_stages`] reads.
pub(crate) struct StageGuard<'a> {
    postgres: &'a BrainPostgres,
    stage: String,
    connection: Option<sqlx::postgres::PgConnection>,
}

impl Drop for StageGuard<'_> {
    fn drop(&mut self) {
        let (Some(runtime), Some(mut connection)) =
            (self.postgres.runtime.as_ref(), self.connection.take())
        else {
            return;
        };
        let stage = std::mem::take(&mut self.stage);
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        runtime.spawn(async move {
            let _ = tokio::time::timeout(OPERATION_DEADLINE, async move {
                let _ = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
                    .bind(&stage)
                    .execute(&mut connection)
                    .await;
                let _ = connection.close().await;
            })
            .await;
            let _ = sender.send(());
        });
        // Cancellation drops the detached connection; PostgreSQL releases
        // its session lock even when the explicit unlock could not finish.
        let _ = receiver.recv_timeout(OPERATION_DEADLINE);
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
