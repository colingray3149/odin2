//! The brain's PostgreSQL store retains chunks for held index generations.
//! A turn's nomination reads `brain_lex` (the
//! lexical tsvector and the 256-d embedding prefix, not the inlined 2048-d
//! vector) and fuses the two legs by reciprocal rank. The full embedding is
//! fetched only to rerank the prefix neighbours.
//!
//! Chunk rows are content-addressed by generation id, so stores (one per
//! seat) that index the same source revision share them; `brain_generation`
//! records which store holds which generation, and a generation's rows go
//! with its last holder. A header row seals a generation once its rows were
//! read back and hashed to its manifest (`generations`); only sealed
//! generations serve. The service is synchronous: queries run on the
//! store's own small runtime and the caller waits on a channel, which is
//! safe from any thread. Every operation is one future cancelled at a
//! deadline: a stalled server or an unreachable advisory lock surfaces as
//! the typed outage callers shed to SQLite on, never an unbounded wait.

use std::collections::BTreeSet;
use std::future::Future;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection, Executor};

use crate::error::{BrainError, BrainResult};

/// Dimensions of the declared embedding model (`brain_chunk.embedding`).
pub const EMBEDDING_DIMS: usize = 2048;

/// Leading dimensions the HNSW index nominates by (`brain_lex_prefix`).
pub const PREFIX_DIMS: usize = 256;

/// The vector leg reranks this many prefix neighbours per nominated row by
/// the full embedding.
const RERANK_FACTOR: i64 = 4;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// The lexical leg's query over `rank::terms` tokens (ASCII alphanumeric,
/// so nothing in them is tsquery syntax): any term matches. Stop words drop
/// unless nothing else is left: `ts_rank` weighs no term by rarity, so one
/// would rank every chunk that repeats it and match most of the corpus.
pub(crate) fn tsquery_terms(terms: BTreeSet<String>) -> String {
    let content: Vec<&str> = terms
        .iter()
        .map(String::as_str)
        .filter(|term| !crate::retrieval::rank::is_stop_word(term))
        .collect();
    if content.is_empty() {
        terms.into_iter().collect::<Vec<_>>().join(" | ")
    } else {
        content.join(" | ")
    }
}

/// Session settings of every pooled connection. The vector leg is a filtered
/// HNSW scan (`ef_search` 100): it keeps walking the graph until the turn's
/// generations fill the limit. A generic plan cannot see how selective
/// `generation_id = ANY($1)` is, so a plan cached for one turn's generations
/// mis-plans the next; custom plans read the array. Bitmap heap scans
/// prefetch (`effective_io_concurrency`; the server default is 1).
/// `work_mem` keeps a large generation's top-N in memory. The
/// `statement_timeout` and `lock_timeout` bound one statement — and any
/// advisory-lock wait inside it — server-side: a stalled backend is
/// cancelled — `57014` for the statement timeout, `55P03` for the lock —
/// and frees its pool slot, classified as the outage in
/// [`BrainError::postgres`]. A long transaction still makes
/// progress statement by statement (one batch each) under the client cap
/// in [`OPERATION_DEADLINE`].
const SESSION: &str = "SET hnsw.iterative_scan = relaxed_order; SET hnsw.ef_search = 100; \
                       SET plan_cache_mode = force_custom_plan; \
                       SET effective_io_concurrency = 32; \
                       SET work_mem = '64MB'; \
                       SET statement_timeout = '30s'; \
                       SET lock_timeout = '10s'";

/// The deadline one database operation may take before its future is
/// cancelled. Pool acquire, the statements and any advisory-lock wait are
/// one future dropped together when it passes, so a timed-out transaction
/// rolls back and the caller gets [`BrainError::Unavailable`] — the outage
/// retrieval and warming shed to SQLite on — instead of waiting forever.
/// A stalled statement is cancelled earlier by the connection's server
/// timeouts (`SESSION`), which free its pool slot without waiting for
/// this cap; legitimate work stays far under it (a mirror round reads 40
/// batches of 500 rows; a full seal copies in 500-row batches).
const OPERATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug)]
pub struct BrainPostgres {
    runtime: Option<tokio::runtime::Runtime>,
    pool: PgPool,
    /// `None` once the store's schema is current; the reason it cannot
    /// serve while a migration runs (or after it failed).
    pending: std::sync::Arc<std::sync::RwLock<Option<String>>>,

    /// Cancels stalled database operations; tests use shorter durations.
    deadline: std::time::Duration,
}

/// What connecting finds of the store's migrations.
#[derive(Debug, Eq, PartialEq)]
enum Migrations {
    /// None applied: a new, empty store migrates before it serves.
    Fresh,
    /// Every migration applied with the checksum this build carries.
    Current,
    /// An existing store is behind by these versions: it migrates in the
    /// background so a long rewrite never holds the daemon's start.
    Behind(Vec<i64>),
}

/// Compares the applied `(version, checksum)` rows with this build's
/// migrations; an applied migration whose bytes changed, or one this build
/// does not know, refuses.
fn migrations_state(applied: &[(i64, Vec<u8>)]) -> Result<Migrations, String> {
    if applied.is_empty() {
        return Ok(Migrations::Fresh);
    }
    for (version, checksum) in applied {
        match MIGRATOR
            .iter()
            .find(|migration| migration.version == *version)
        {
            Some(migration) if migration.checksum.as_ref() == checksum.as_slice() => {}
            Some(_) => {
                return Err(format!(
                    "applied migration {version} differs from this build's"
                ))
            }
            None => {
                return Err(format!(
                    "applied migration {version} is unknown to this build"
                ))
            }
        }
    }
    let behind: Vec<i64> = MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .filter(|version| !applied.iter().any(|(applied, _)| applied == version))
        .collect();
    Ok(if behind.is_empty() {
        Migrations::Current
    } else {
        Migrations::Behind(behind)
    })
}

#[derive(Clone, Debug)]
pub(crate) struct ChunkRow {
    pub ordinal: i64,
    pub item: String,
    pub digest: String,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
}

/// One turn's nomination over the generations it serves.
#[derive(Clone, Debug)]
pub(crate) struct Nomination {
    pub generations: Vec<String>,
    /// Items the turn may not see (another project's memory).
    pub hidden_items: Vec<String>,
    /// The query's unique lexical terms, OR-joined for `websearch_to_tsquery`.
    pub terms: Option<String>,
    /// The query embedding and the model it was produced under.
    pub embedding: Option<(Vec<f32>, String)>,
    pub limit: i64,
}

/// One chunk awaiting its embedding.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Unembedded {
    pub generation_id: String,
    pub ordinal: i64,
    pub text: String,
}

/// One nominated chunk and its fused reciprocal rank.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Nominated {
    pub generation_id: String,
    pub ordinal: i64,
    pub rrf: f64,
}

/// Reciprocal-rank-fusion constant: a hit at rank r scores 1/(RRF_K + r).
pub(crate) const RRF_K: f64 = 60.0;

impl BrainPostgres {
    /// Connects to `conninfo` (libpq keywords: `host`, `port`, `dbname`,
    /// `user`; a `host` starting with `/` is a socket directory). A new
    /// store migrates before it serves; an existing one that is behind
    /// migrates in the background and answers `Unavailable` until done.
    pub fn connect(conninfo: &str) -> BrainResult<Self> {
        let options = connect_options(conninfo)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("odin-brain-postgres")
            .enable_all()
            .build()
            .map_err(|error| unavailable(format!("cannot start the store runtime: {error}")))?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        runtime.spawn(async move {
            let connected = async {
                let pool = PgPoolOptions::new()
                    .max_connections(4)
                    .after_connect(|connection, _| {
                        Box::pin(async move { connection.execute(SESSION).await.map(drop) })
                    })
                    .connect_with(options)
                    .await
                    .map_err(|error| error.to_string())?;
                let state = migrations_state(&applied_migrations(&pool).await?)?;
                if state == Migrations::Fresh {
                    MIGRATOR
                        .run(&pool)
                        .await
                        .map_err(|error| format!("migration failed: {error}"))?;
                }
                Ok::<_, String>((pool, state))
            };
            let _ = sender.send(
                match tokio::time::timeout(OPERATION_DEADLINE, connected).await {
                    Ok(outcome) => outcome,
                    Err(_) => Err(format!(
                        "connecting to the store did not settle within {OPERATION_DEADLINE:?}"
                    )),
                },
            );
        });
        let (pool, state) = receiver
            .recv()
            .map_err(|_| unavailable("the store runtime stopped while connecting"))?
            .map_err(unavailable)?;
        let pending = std::sync::Arc::new(std::sync::RwLock::new(None));
        if let Migrations::Behind(versions) = state {
            *pending
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(format!("migrating to versions {versions:?}"));
            let (pool, pending) = (pool.clone(), std::sync::Arc::clone(&pending));
            runtime.spawn(async move {
                let started = std::time::Instant::now();
                tracing::info!(versions = ?versions, "brain-migration started");
                let outcome = async {
                    // A schema rewrite may run past the serving statement
                    // timeout, so the migration connection carries none and
                    // is closed, never returned to the pool with its
                    // settings.
                    let mut connection = pool.acquire().await?;
                    (&mut *connection)
                        .execute("SET statement_timeout = 0; SET lock_timeout = 0")
                        .await?;
                    let outcome = MIGRATOR.run_direct(&mut *connection).await;
                    let _ = connection.detach().close().await;
                    outcome
                }
                .await;
                let outcome = match outcome {
                    Ok(()) => Ok(()),
                    Err(error) => Err(format!("migration failed: {error}")),
                };
                let mut slot = pending
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match outcome {
                    Ok(()) => {
                        *slot = None;
                        tracing::info!(ms = started.elapsed().as_millis(), "brain-migration done");
                    }
                    Err(error) => {
                        tracing::error!(error = %error, "brain-migration failed");
                        *slot = Some(error);
                    }
                }
            });
        }
        Ok(Self {
            runtime: Some(runtime),
            pool,
            deadline: OPERATION_DEADLINE,
            pending,
        })
    }

    /// Runs one database operation on the store's runtime and waits for
    /// its result. The whole operation — pool acquire, the statements,
    /// any advisory-lock wait — is a single future cancelled at the
    /// store's deadline: dropping a timed-out future rolls its
    /// transaction back, and the caller gets the typed outage it sheds
    /// to SQLite on instead of waiting forever. A stalled statement is
    /// cancelled earlier by the connection's server timeouts and
    /// surfaces as the same outage.
    fn run<T, F>(&self, query: impl FnOnce(PgPool) -> F) -> BrainResult<T>
    where
        F: Future<Output = Result<T, sqlx::Error>> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| unavailable("the store runtime is shut down"))?;
        if let Some(reason) = self
            .pending
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            return Err(unavailable(reason.clone()));
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let future = query(self.pool.clone());
        let deadline = self.deadline;
        runtime.spawn(async move {
            let outcome = match tokio::time::timeout(deadline, future).await {
                Ok(outcome) => outcome.map_err(BrainError::postgres),
                Err(_) => Err(unavailable(format!(
                    "a database operation timed out after {deadline:?} and was cancelled"
                ))),
            };
            let _ = sender.send(outcome);
        });
        receiver
            .recv()
            .map_err(|_| unavailable("the store runtime dropped a query"))?
    }

    /// Closes the pool: every later query fails as an outage. Test-only so
    /// the SQLite fallback paths have a real closed pool without stopping
    /// a cluster.
    #[cfg(test)]
    pub(crate) fn close_for_test(&self) {
        self.run(|pool| async move {
            pool.close().await;
            Ok(())
        })
        .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn set_deadline_for_test(&mut self, deadline: std::time::Duration) {
        self.deadline = deadline;
    }

    #[cfg(test)]
    pub(crate) fn gate_next_release_for_test(
        &mut self,
        conninfo: &str,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let gate = std::sync::Arc::new(parking_lot::Mutex::new(
            None::<(
                std::sync::mpsc::Sender<()>,
                tokio::sync::oneshot::Receiver<()>,
            )>,
        ));
        let callback_gate = gate.clone();
        let runtime = self.runtime.as_ref().unwrap();
        let pool = runtime
            .block_on(
                PgPoolOptions::new()
                    .max_connections(4)
                    .after_release(move |_, _| {
                        let gate = callback_gate.lock().take();
                        Box::pin(async move {
                            if let Some((entered, released)) = gate {
                                let _ = entered.send(());
                                let _ = released.await;
                            }
                            Ok(true)
                        })
                    })
                    .connect_with(connect_options(conninfo).unwrap()),
            )
            .unwrap();
        runtime.block_on(self.pool.close());
        self.pool = pool;
        *gate.lock() = Some((entered, released));
        (observed, release)
    }

    /// Inserts chunk rows of one generation stamped with `model`; rows
    /// already present stay. A row without its own embedding takes the
    /// embedding of any stored chunk with the same text under that model.
    /// Returns false when the write is deferred — the generation's
    /// advisory lock is held by a seal, or the generation is already
    /// sealed and its rows are immutable (see [`row_write_open`]).
    pub(crate) fn insert_chunks(
        &self,
        generation: &str,
        model: &str,
        rows: Vec<ChunkRow>,
    ) -> BrainResult<bool> {
        let (generation, model) = (generation.to_owned(), model.to_owned());
        let mut columns = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let mut embeddings: Vec<f32> = Vec::new();
        for row in rows {
            columns.0.push(row.ordinal);
            columns.1.push(row.item);
            columns.2.push(row.digest);
            columns.3.push(row.text);
            match row.embedding {
                Some(dims) => {
                    check_dims(row.ordinal, &dims)?;
                    embeddings.extend_from_slice(&dims);
                    columns.4.push((embeddings.len() / EMBEDDING_DIMS) as i32);
                }
                None => columns.4.push(0),
            }
        }
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            if !row_write_open(&mut transaction, &generation).await? {
                return Ok(false);
            }
            sqlx::query!(
                "INSERT INTO brain_chunk (generation_id, ordinal, item, digest, text, model, embedding)
                 SELECT $1, row.ordinal, row.item, row.digest, row.text,
                        CASE WHEN row.vector > 0 THEN $7 ELSE peer.model END,
                        CASE WHEN row.vector > 0
                             THEN ($6::real[])[(row.vector - 1) * 2048 + 1 : row.vector * 2048]::halfvec
                             ELSE peer.embedding END
                 FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::text[], $8::int[])
                      AS row(ordinal, item, digest, text, vector)
                 LEFT JOIN LATERAL (
                     SELECT model, embedding FROM brain_chunk
                     WHERE model = $7 AND digest = row.digest AND embedding IS NOT NULL LIMIT 1
                 ) AS peer ON row.vector = 0
                 ON CONFLICT DO NOTHING",
                generation,
                &columns.0,
                &columns.1,
                &columns.2,
                &columns.3,
                &embeddings as &[f32],
                model,
                &columns.4,
            )
            .execute(&mut *transaction)
            .await
            .map(drop)?;
            transaction.commit().await?;
            Ok(true)
        })
    }

    /// Stores embeddings of one generation's chunks under `model`; a chunk
    /// that already has one keeps it.
    pub(crate) fn insert_embeddings(
        &self,
        generation: &str,
        model: &str,
        rows: Vec<(i64, Vec<f32>)>,
    ) -> BrainResult<()> {
        for (ordinal, dims) in &rows {
            check_dims(*ordinal, dims)?;
        }
        let (generation, model) = (generation.to_owned(), model.to_owned());
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            for (ordinal, dims) in rows {
                sqlx::query!(
                    "UPDATE brain_chunk SET model = $3, embedding = $4::real[]::halfvec
                     WHERE generation_id = $1 AND ordinal = $2 AND embedding IS NULL",
                    generation,
                    ordinal,
                    model,
                    &dims as &[f32],
                )
                .execute(&mut *transaction)
                .await?;
            }
            transaction.commit().await
        })
    }

    /// Every generation `owner` holds.
    pub(crate) fn held_by(&self, owner: &str) -> BrainResult<Vec<String>> {
        let owner = owner.to_owned();
        self.run(|pool| async move {
            sqlx::query_scalar::<_, String>(
                "SELECT generation_id FROM brain_generation WHERE owner = $1",
            )
            .bind(owner)
            .fetch_all(&pool)
            .await
        })
    }

    /// Drops `owner`'s hold on `generation`, and its rows with the last hold.
    pub(crate) fn release(&self, owner: &str, generation: &str) -> BrainResult<()> {
        let (owner, generation) = (owner.to_owned(), generation.to_owned());
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            sqlx::query!("SELECT pg_advisory_xact_lock(hashtext($1))", generation)
                .execute(&mut *transaction)
                .await?;
            sqlx::query!(
                "DELETE FROM brain_generation WHERE owner = $1 AND generation_id = $2",
                owner,
                generation,
            )
            .execute(&mut *transaction)
            .await?;
            for table in [
                "brain_generation_header",
                "brain_chunk_cite",
                "brain_item_provenance",
                "brain_chunk",
            ] {
                let sql = format!(
                    "DELETE FROM {table} WHERE generation_id = $1 AND NOT EXISTS \
                     (SELECT 1 FROM brain_generation WHERE generation_id = $1)"
                );
                sqlx::query(&sql)
                    .bind(&generation)
                    .execute(&mut *transaction)
                    .await?;
            }
            transaction.commit().await
        })
    }

    /// Up to `limit` unembedded chunks `(generation, ordinal, text)` of
    /// `generations`, and how many of the generations have any.
    pub(crate) fn unembedded(
        &self,
        generations: Vec<String>,
        limit: i64,
    ) -> BrainResult<(Vec<Unembedded>, usize)> {
        self.run(|pool| async move {
            let rows = sqlx::query!(
                "SELECT generation_id, ordinal, text FROM brain_chunk
                 WHERE generation_id = ANY($1) AND embedding IS NULL
                 ORDER BY generation_id, ordinal LIMIT $2",
                &generations,
                limit,
            )
            .fetch_all(&pool)
            .await?;
            let remaining = sqlx::query_scalar!(
                r#"SELECT count(DISTINCT generation_id) AS "pending!" FROM brain_chunk
                   WHERE generation_id = ANY($1) AND embedding IS NULL"#,
                &generations,
            )
            .fetch_one(&pool)
            .await?;
            Ok((
                rows.into_iter()
                    .map(|row| Unembedded {
                        generation_id: row.generation_id,
                        ordinal: row.ordinal,
                        text: row.text,
                    })
                    .collect(),
                remaining as usize,
            ))
        })
    }

    /// One turn's candidates: the lexical leg (`ts_rank` over `terms`, a
    /// `to_tsquery` disjunction of [`tsquery_terms`]) and the vector leg
    /// (HNSW over the 256-d prefix of the turn's generations, ties broken
    /// by generation id then ordinal, reranked by the full embedding) each
    /// nominate `limit` chunks of those generations, fused by reciprocal rank.
    pub(crate) fn nominate(&self, nomination: Nomination) -> BrainResult<Vec<Nominated>> {
        let Nomination {
            generations,
            hidden_items,
            terms,
            embedding,
            limit,
        } = nomination;
        let (full, prefix, model) = match embedding {
            Some((full, model)) => {
                check_dims(-1, &full)?;
                let prefix = full[..PREFIX_DIMS].to_vec();
                (Some(full), Some(prefix), Some(model))
            }
            None => (None, None, None),
        };
        self.run(|pool| async move {
            let rows = sqlx::query!(
                r#"WITH lexical AS (
                       SELECT generation_id, ordinal,
                              row_number() OVER (ORDER BY score DESC, generation_id, ordinal) AS rank
                       FROM (SELECT generation_id, ordinal, ts_rank(tsv, query) AS score
                            FROM brain_lex, to_tsquery('simple', $2) AS query
                            WHERE $2::text IS NOT NULL AND generation_id = ANY($1)
                              AND tsv @@ query AND NOT (item = ANY($3))
                            ORDER BY score DESC, generation_id, ordinal LIMIT $4) AS matched
                  ),
                  nearest AS (
                      SELECT generation_id, ordinal FROM brain_lex
                      WHERE $5::real[] IS NOT NULL AND generation_id = ANY($1) AND model = $7
                        AND prefix IS NOT NULL AND NOT (item = ANY($3))
                      ORDER BY prefix <=> $5::real[]::halfvec(256), generation_id, ordinal
                      LIMIT $4 * $8
                  ),
                  vector AS (
                      SELECT generation_id, ordinal,
                             row_number() OVER (ORDER BY distance, generation_id, ordinal) AS rank
                      FROM (SELECT nearest.generation_id, nearest.ordinal,
                                   brain_chunk.embedding <=> $6::real[]::halfvec(2048) AS distance
                            FROM nearest
                            JOIN brain_chunk
                              ON brain_chunk.generation_id = nearest.generation_id
                             AND brain_chunk.ordinal = nearest.ordinal
                            ORDER BY distance, nearest.generation_id, nearest.ordinal LIMIT $4) AS reranked
                   )
                   SELECT generation_id AS "generation_id!", ordinal AS "ordinal!",
                          (COALESCE(1.0 / ($9::float8 + lexical.rank), 0)
                           + COALESCE(1.0 / ($9::float8 + vector.rank), 0))::float8 AS "rrf!"
                   FROM lexical FULL OUTER JOIN vector USING (generation_id, ordinal)
                   ORDER BY 3 DESC, 1, 2 LIMIT $4"#,
                &generations,
                terms,
                &hidden_items,
                limit,
                prefix.as_deref() as Option<&[f32]>,
                full.as_deref() as Option<&[f32]>,
                model,
                RERANK_FACTOR,
                RRF_K,
            )
            .fetch_all(&pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|row| Nominated {
                    generation_id: row.generation_id,
                    ordinal: row.ordinal,
                    rrf: row.rrf,
                })
                .collect())
        })
    }

    /// The fused reciprocal ranks of exactly `ordinals` of one generation
    /// (a turn that addresses one record): every chunk is ranked by both
    /// legs without the indexes, and chunks neither leg matches drop.
    pub(crate) fn rank_record(
        &self,
        generation: &str,
        ordinals: Vec<i64>,
        terms: Option<String>,
        embedding: Option<(Vec<f32>, String)>,
    ) -> BrainResult<Vec<Nominated>> {
        let generation = generation.to_owned();
        let (full, model) = embedding.unzip();
        self.run(|pool| async move {
            let rows = sqlx::query!(
                r#"WITH record AS (
                       SELECT ordinal, tsv, model, embedding FROM brain_chunk
                       WHERE generation_id = $1 AND ordinal = ANY($2)
                   ),
                   lexical AS (
                       SELECT ordinal, row_number() OVER (ORDER BY ts_rank(tsv, query) DESC, ordinal) AS rank
                       FROM record, to_tsquery('simple', $3) AS query
                       WHERE $3::text IS NOT NULL AND tsv @@ query
                   ),
                   vector AS (
                       SELECT ordinal,
                              row_number() OVER (ORDER BY embedding <=> $4::real[]::halfvec(2048), ordinal) AS rank
                       FROM record WHERE $4::real[] IS NOT NULL AND model = $5
                   )
                   SELECT ordinal AS "ordinal!",
                          (COALESCE(1.0 / ($6::float8 + lexical.rank), 0)
                           + COALESCE(1.0 / ($6::float8 + vector.rank), 0))::float8 AS "rrf!"
                   FROM lexical FULL OUTER JOIN vector USING (ordinal)
                   ORDER BY 2 DESC, 1"#,
                generation,
                &ordinals,
                terms,
                full.as_deref() as Option<&[f32]>,
                model,
                RRF_K,
            )
            .fetch_all(&pool)
            .await?;
            Ok(rows
                .into_iter()
                .map(|row| Nominated {
                    generation_id: generation.clone(),
                    ordinal: row.ordinal,
                    rrf: row.rrf,
                })
                .collect())
        })
    }
}

impl Drop for BrainPostgres {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// libpq keyword/value connection settings (`host=/run/postgresql
/// dbname=odin_brain`); unset keys keep libpq's defaults and environment.
fn connect_options(conninfo: &str) -> BrainResult<PgConnectOptions> {
    let mut options = PgConnectOptions::new();
    for pair in conninfo.split_whitespace() {
        let invalid = || {
            BrainError::InvalidPolicy(format!(
                "[brain] postgres: {pair:?} is not one of host=, port=, dbname=, user="
            ))
        };
        let (key, value) = pair.split_once('=').ok_or_else(invalid)?;
        options = match key {
            "host" => options.host(value),
            "port" => options.port(u16::from_str(value).map_err(|_| invalid())?),
            "dbname" => options.database(value),
            "user" => options.username(value),
            _ => return Err(invalid()),
        };
    }
    Ok(options)
}

fn check_dims(ordinal: i64, dims: &[f32]) -> BrainResult<()> {
    if dims.len() == EMBEDDING_DIMS {
        return Ok(());
    }
    Err(BrainError::InvalidRequest(format!(
        "the embedding of chunk {ordinal} has {} dimensions; the brain store holds {EMBEDDING_DIMS}",
        dims.len()
    )))
}

/// `(version, checksum)` of every successfully applied migration; none
/// when the bookkeeping table does not exist yet.
async fn applied_migrations(pool: &PgPool) -> Result<Vec<(i64, Vec<u8>)>, String> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await
        .map_err(|error| error.to_string())?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations WHERE success ORDER BY version")
        .fetch_all(pool)
        .await
        .map_err(|error| error.to_string())
}

fn unavailable(reason: impl Into<String>) -> BrainError {
    BrainError::Unavailable {
        component: crate::error::POSTGRES_STORE,
        reason: reason.into(),
    }
}

mod generations;
mod records;

pub use records::{RecordFilters, RecordHits, RecordRead};

pub(crate) use generations::{
    row_write_open, CitedRow, HeaderRow, ProvenanceRow, SealProof, SealRejection, SealWait,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres_test_cluster::TestCluster;

    const MODEL: &str = "test:model";

    /// A unit embedding along `axis`, so cosine order is known by hand.
    fn axis(axis: usize) -> Vec<f32> {
        let mut dims = vec![0.0; EMBEDDING_DIMS];
        dims[axis] = 1.0;
        dims
    }

    fn row(ordinal: i64, item: &str, text: &str, embedding: Option<Vec<f32>>) -> ChunkRow {
        ChunkRow {
            ordinal,
            item: item.to_owned(),
            digest: format!("digest:{text}"),
            text: text.to_owned(),
            embedding,
        }
    }

    fn nominate(store: &BrainPostgres, terms: Option<&str>, query: Option<usize>) -> Vec<i64> {
        store
            .nominate(Nomination {
                generations: vec!["g1".to_owned()],
                hidden_items: vec!["hidden".to_owned()],
                terms: terms.map(str::to_owned),
                embedding: query.map(|dim| (axis(dim), MODEL.to_owned())),
                limit: 10,
            })
            .unwrap()
            .into_iter()
            .map(|nominated| nominated.ordinal)
            .collect()
    }

    #[test]
    fn only_a_new_store_migrates_before_it_serves() {
        let all: Vec<(i64, Vec<u8>)> = MIGRATOR
            .iter()
            .map(|migration| (migration.version, migration.checksum.to_vec()))
            .collect();
        assert_eq!(migrations_state(&[]).unwrap(), Migrations::Fresh);
        assert_eq!(migrations_state(&all).unwrap(), Migrations::Current);
        let (last, _) = all.last().cloned().unwrap();
        assert_eq!(
            migrations_state(&all[..all.len() - 1]).unwrap(),
            Migrations::Behind(vec![last])
        );
        let mut changed = all.clone();
        changed[0].1 = vec![0; 4];
        assert!(migrations_state(&changed).is_err());
        let mut unknown = all;
        unknown.push((i64::MAX, Vec::new()));
        assert!(migrations_state(&unknown).is_err());
    }

    /// Migration failure keeps queries unavailable without blocking connection startup.
    #[test]
    fn a_store_behind_connects_at_once_and_waits_to_serve() {
        let cluster = TestCluster::start();
        drop(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let last = MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap();
        {
            let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
            store
                .run(move |pool| async move {
                    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
                        .bind(last)
                        .execute(&pool)
                        .await
                        .map(drop)
                })
                .unwrap();
        }
        let behind = BrainPostgres::connect(&cluster.conninfo).expect("connects at once");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match behind.last_ordinal("g1") {
                Err(BrainError::Unavailable { reason, .. }) if reason.contains("failed") => break,
                Err(BrainError::Unavailable { .. }) => {}
                other => panic!("a store whose migration cannot finish must not serve: {other:?}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the migration never settled"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn conninfo_takes_libpq_keywords_and_refuses_others() {
        let authority = connect_options("host=/run/postgresql dbname=odin_brain").unwrap();
        assert_eq!(
            Some(authority.get_username()),
            std::env::var("USER").ok().as_deref(),
            "peer authentication connects as the process user"
        );
        assert!(
            connect_options("host=/run/postgresql-standby port=5433 dbname=odin_brain").is_ok()
        );
        assert!(matches!(
            connect_options("host=/run/postgresql sslmode=disable"),
            Err(BrainError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn one_query_fuses_the_lexical_and_vector_legs_by_reciprocal_rank() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        store
            .insert_chunks(
                "g1",
                MODEL,
                vec![
                    row(0, "a", "tea is my favourite", Some(axis(1))),
                    row(1, "b", "oolong tea and more oolong tea", Some(axis(0))),
                    row(2, "c", "kubernetes job counters", Some(axis(2))),
                    row(
                        3,
                        "hidden",
                        "oolong secret of another project",
                        Some(axis(0)),
                    ),
                ],
            )
            .unwrap();
        store
            .insert_chunks(
                "g2",
                MODEL,
                vec![row(0, "z", "oolong elsewhere", Some(axis(0)))],
            )
            .unwrap();

        let lexical = nominate(&store, Some("oolong | tea"), None);
        assert_eq!(
            lexical.len(),
            2,
            "only g1's visible lexical matches: {lexical:?}"
        );
        assert_eq!(nominate(&store, None, Some(0))[0], 1, "nearest by vector");
        let fused = store
            .nominate(Nomination {
                generations: vec!["g1".to_owned()],
                hidden_items: vec!["hidden".to_owned()],
                terms: Some("oolong | tea".to_owned()),
                embedding: Some((axis(0), MODEL.to_owned())),
                limit: 10,
            })
            .unwrap();
        assert_eq!(fused[0].ordinal, 1, "first in both legs: {fused:?}");
        assert!((fused[0].rrf - 2.0 / (RRF_K + 1.0)).abs() < 1e-9);
        assert_eq!(
            fused.len(),
            3,
            "the vector leg also nominates the unmatched chunk"
        );
    }

    /// More embedded chunks than the prefix window (`limit * RERANK_FACTOR`).
    /// Identical prefixes tie, so only `generation_id, ordinal` decides which
    /// rows the window keeps. The excluded row is the full-embedding winner;
    /// a second row is nearer on the full vector than the window but farther
    /// on the prefix. Neither may appear on the vector leg.
    #[test]
    fn the_vector_leg_nominates_the_stable_prefix_window() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        let limit = 2;
        let window = limit * RERANK_FACTOR;
        let tied_out = window;
        let farther_prefix = window + 1;
        let mut closer_full = axis(0);
        closer_full[300] = 1.0;
        // Insert the full-embedding winner first, so a scan that drops the
        // tie-break and keeps the first equals would nominate it.
        let mut rows = vec![row(
            tied_out,
            "a",
            "same prefix, closer full embedding, past the window",
            Some(closer_full),
        )];
        for ordinal in 0..window {
            rows.push(row(
                ordinal,
                "a",
                &format!("prefix neighbour {ordinal}"),
                Some(axis(0)),
            ));
        }
        let mut angled = vec![0.0; EMBEDDING_DIMS];
        angled[0] = 0.5;
        angled[1] = 0.5;
        angled[300] = 1.0;
        rows.push(row(
            farther_prefix,
            "a",
            "worse prefix, better full embedding than the window",
            Some(angled),
        ));
        assert!(
            rows.len() as i64 > window,
            "the fixture must exceed the prefix window"
        );
        store.insert_chunks("g1", MODEL, rows).unwrap();

        let mut query = axis(0);
        query[300] = 1.0;
        let nominated: Vec<i64> = store
            .nominate(Nomination {
                generations: vec!["g1".to_owned()],
                hidden_items: vec!["hidden".to_owned()],
                terms: None,
                embedding: Some((query, MODEL.to_owned())),
                limit,
            })
            .unwrap()
            .into_iter()
            .map(|row| row.ordinal)
            .collect();
        assert_eq!(
            nominated,
            vec![0, 1],
            "stable prefix window reranks to the lowest ordinals: {nominated:?}"
        );
        assert!(
            !nominated.contains(&tied_out),
            "ordinal {tied_out} ties the prefix and loses the tie-break"
        );
        assert!(
            !nominated.contains(&farther_prefix),
            "ordinal {farther_prefix} is outside the prefix window"
        );
    }

    /// These tests exercise header/claim lifecycle, not row validation.
    struct Accept;

    impl SealProof for Accept {
        fn feed_chunks(&mut self, _rows: Vec<CitedRow>) -> Result<(), String> {
            Ok(())
        }

        fn feed_provenance(&mut self, _rows: Vec<ProvenanceRow>) -> Result<(), String> {
            Ok(())
        }

        fn finish(self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_generation_stays_while_any_store_holds_it_and_shares_embeddings_by_text() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        // The complete set: the chunk and its citation, as the seal now
        // demands before it publishes any header.
        store
            .copy_cited(
                "g1",
                MODEL,
                vec![(
                    CitedRow {
                        ordinal: 0,
                        chunk_id: "k0".to_owned(),
                        trust: "curated".to_owned(),
                        byte_start: 0,
                        byte_end: "same text".len() as i64,
                        item: "a".to_owned(),
                        digest: "digest:same text".to_owned(),
                        text: "same text".to_owned(),
                    },
                    Some(axis(3)),
                )],
            )
            .unwrap();
        let header = HeaderRow {
            generation_id: "g1".to_owned(),
            atlas_id: "atlas:a".to_owned(),
            atlas_revision: "r".to_owned(),
            chunker_version: "c".to_owned(),
            tokenizer: "t".to_owned(),
            embedding_model: MODEL.to_owned(),
            manifest_digest: "m".to_owned(),
            created_epoch: 1,
            chunk_count: 1,
        };
        store
            .seal("sinmara", header.clone(), 500, Accept, SealWait::Wait)
            .unwrap()
            .unwrap();
        assert_eq!(store.hold("gungnir", "g1").unwrap(), Some(header));
        store
            .insert_chunks(
                "g2",
                MODEL,
                vec![
                    row(0, "a", "same text", None),
                    row(1, "b", "new text", None),
                ],
            )
            .unwrap();
        let (pending, generations) = store.unembedded(vec!["g2".to_owned()], 10).unwrap();
        assert_eq!(
            pending,
            vec![Unembedded {
                generation_id: "g2".to_owned(),
                ordinal: 1,
                text: "new text".to_owned(),
            }],
            "the same text reuses its embedding"
        );
        assert_eq!(generations, 1);

        store.release("sinmara", "g1").unwrap();
        assert_eq!(
            store.last_ordinal("g1").unwrap(),
            Some(0),
            "gungnir still holds g1"
        );
        store.release("gungnir", "g1").unwrap();
        assert_eq!(
            store.last_ordinal("g1").unwrap(),
            None,
            "the last hold drops the rows"
        );
        assert!(
            nominate(&store, Some("same"), None).is_empty(),
            "a released generation leaves the lexical leg"
        );
        assert_eq!(
            store.hold("gungnir", "g1").unwrap(),
            None,
            "the header went too"
        );
    }

    /// The english parser kept a path, a URL and an e-mail address whole and
    /// dropped "the": a term the SQLite index found matched nothing here.
    #[test]
    fn the_lexical_leg_matches_every_ascii_term_the_sqlite_index_does() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        store
            .insert_chunks(
                "g1",
                MODEL,
                vec![
                    row(
                        0,
                        "a",
                        "see /home/colin/valhalla/odin/docs/HANDOFF.md",
                        None,
                    ),
                    row(
                        1,
                        "b",
                        "mail colin@example.org about https://mini.lan/x",
                        None,
                    ),
                    row(2, "c", "The Odin_brain store", None),
                ],
            )
            .unwrap();
        for (term, ordinal) in [
            ("handoff", 0),
            ("valhalla", 0),
            ("example", 1),
            ("mini", 1),
            ("the", 2),
            ("odin", 0),
        ] {
            let terms = tsquery_terms(crate::retrieval::rank::terms(term).collect());
            assert!(
                nominate(&store, Some(&terms), None).contains(&ordinal),
                "{term} finds chunk {ordinal}"
            );
        }
        assert!(nominate(&store, Some("brain"), None).contains(&2));
    }

    #[test]
    fn stop_words_leave_the_lexical_query_unless_nothing_else_is_left() {
        let terms = |text: &str| tsquery_terms(crate::retrieval::rank::terms(text).collect());
        assert_eq!(terms("what is the oolong tea"), "oolong | tea");
        assert_eq!(
            terms("is it in the list of such teas"),
            "list | teas",
            "the english function words english tsv dropped stay out of a mixed query"
        );
        assert_eq!(terms("the what"), "the | what");
        assert_eq!(terms("is it"), "is | it");
    }

    #[test]
    fn an_embedding_of_another_width_is_refused() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        let refused = store.insert_embeddings("g1", MODEL, vec![(0, vec![1.0; 8])]);
        assert!(matches!(refused, Err(BrainError::InvalidRequest(_))));
    }

    #[test]
    fn a_later_embedding_joins_the_vector_leg() {
        let cluster = TestCluster::start();
        let store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        store
            .insert_chunks("g1", MODEL, vec![row(0, "a", "oolong tea", None)])
            .unwrap();
        assert!(
            nominate(&store, None, Some(0)).is_empty(),
            "an unembedded chunk is not a vector neighbour"
        );
        store
            .insert_embeddings("g1", MODEL, vec![(0, axis(0))])
            .unwrap();
        assert_eq!(
            nominate(&store, None, Some(0)),
            vec![0],
            "the embedding update joins the prefix leg"
        );
    }

    /// A query parked on the generation's advisory lock (held from an
    /// outside session, the way a concurrent seal holds it) is cancelled
    /// by the server at the connection's lock timeout — `SQLSTATE 55P03` —
    /// and surfaces as the typed outage: while the holder still lives, the
    /// waiting backend is gone and its pool slot is free again, and the
    /// same mutator runs to completion the moment the lock frees.
    #[test]
    fn a_blocked_query_is_cancelled_at_its_deadline_without_leaving_work() {
        let cluster = TestCluster::start();
        let mut store = BrainPostgres::connect(&cluster.conninfo).unwrap();
        assert!(
            store
                .insert_chunks("g1", MODEL, vec![row(0, "a", "oolong tea", None)])
                .unwrap(),
            "the unsealed, uncontended generation must accept its rows"
        );
        // Configure every pooled connection below the client deadline so the server cancels first.
        store
            .run(|pool| async move {
                let mut held = Vec::new();
                for _ in 0..4 {
                    let mut connection = pool.acquire().await?;
                    (&mut *connection)
                        .execute("SET lock_timeout = '1s'; SET statement_timeout = '2s'")
                        .await?;
                    held.push(connection);
                }
                drop(held);
                Ok::<_, sqlx::Error>(())
            })
            .unwrap();
        store.set_deadline_for_test(std::time::Duration::from_secs(10));

        let holder_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let holder = holder_runtime.block_on(async {
            let mut connection =
                sqlx::PgConnection::connect_with(&connect_options(&cluster.conninfo).unwrap())
                    .await
                    .unwrap();
            sqlx::query("SELECT pg_advisory_lock(hashtext('g1'))")
                .execute(&mut connection)
                .await
                .unwrap();
            connection
        });

        let started = std::time::Instant::now();
        let refused = store
            .release("sinmara", "g1")
            .expect_err("a lock-blocked release must fail, never sit forever");
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_secs(1)
                && waited < std::time::Duration::from_secs(5),
            "the server lock timeout must cancel the wait well under the client cap: {waited:?}"
        );
        assert!(
            refused.is_postgres_outage(),
            "a server-cancelled wait is the outage callers shed to SQLite on: {refused:?}"
        );
        let BrainError::Unavailable { reason, .. } = &refused else {
            panic!("expected the outage variant: {refused:?}")
        };
        assert!(
            reason.contains("lock timeout"),
            "the reason must name the server-side cancellation: {reason}"
        );

        // The holder still lives, yet no backend is waiting on the lock or
        // holding a transaction: the cancelled attempt is gone and its
        // pool slot is free again.
        let mut leaked = true;
        for _ in 0..100 {
            let (waiting, in_transaction, advisory): (i64, i64, i64) = store
                .run(|pool| async move {
                    sqlx::query_as(
                        "SELECT (SELECT count(*) FROM pg_stat_activity \
                              WHERE wait_event_type = 'Lock'), \
                            (SELECT count(*) FROM pg_stat_activity \
                              WHERE state LIKE 'idle in transaction%'), \
                            (SELECT count(*) FROM pg_locks \
                              WHERE locktype = 'advisory' AND granted)",
                    )
                    .fetch_one(&pool)
                    .await
                })
                .unwrap();
            if (waiting, in_transaction, advisory) == (0, 0, 1) {
                leaked = false;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            !leaked,
            "the cancelled attempt left a waiter, a transaction or a lock behind"
        );
        assert_eq!(
            store.last_ordinal("g9").unwrap(),
            None,
            "the store serves past the cancelled call"
        );

        // With the lock freed, the same mutator finishes at once: nothing
        // the cancelled attempt left behind can hold it.
        drop(holder);
        drop(holder_runtime);
        store.release("sinmara", "g1").unwrap();
        assert_eq!(
            store.last_ordinal("g1").unwrap(),
            None,
            "the generation goes whole with the release, not half deleted"
        );
    }
}
