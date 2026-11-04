//! The brain's PostgreSQL store retains chunks for held index generations.
//! A turn's nomination reads `brain_search` (the chunk text under a BM25
//! index and the 256-d embedding prefix, not the inlined 2048-d vector) and
//! fuses the keyword and vector legs by reciprocal rank. The full embedding
//! is fetched only to rerank the prefix neighbours.
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
//! a typed outage, never an unbounded wait.

use std::collections::BTreeSet;
use std::future::Future;
use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection, Executor};

use crate::error::{postgres_outage, BrainError, BrainResult};

/// Dimensions of the declared embedding model (`brain_chunk.embedding`).
pub const EMBEDDING_DIMS: usize = 2048;

/// Leading dimensions the HNSW index nominates by (`brain_search_prefix`).
pub const PREFIX_DIMS: usize = 256;

/// The vector leg reranks this many prefix neighbours per nominated row by
/// the full embedding.
const RERANK_FACTOR: i64 = 4;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Most terms one keyword query carries.
const MAX_TERMS: usize = 64;

/// The keyword leg's terms of `text`: its distinct `rank::terms` tokens in
/// query order, without stop words unless nothing else is left.
pub(crate) fn keyword_terms(text: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let all: Vec<String> = crate::retrieval::rank::terms(text)
        .filter(|term| seen.insert(term.clone()))
        .collect();
    let content: Vec<String> = all
        .iter()
        .filter(|term| !crate::retrieval::rank::is_stop_word(term))
        .cloned()
        .collect();
    let mut terms = if content.is_empty() { all } else { content };
    terms.truncate(MAX_TERMS);
    terms
}

/// The BM25 query over `column` for the `text[]` parameter `terms`: chunks
/// with any term, boosted when they hold every term and again when the terms
/// stand together in query order (slop 2). On mini's 4.3M chunks and a fixed
/// set of 195 queries (names, course codes, ids, phrases, questions) it put a
/// relevant chunk in the top 16 for 0.67 of them against ts_rank's 0.57, in
/// 15 ms p50 and 24 ms p90 against 129 ms and 840 ms (2026-10-26).
pub(crate) fn keyword_query(column: &str, terms: &str) -> String {
    format!(
        "CASE WHEN cardinality({terms}) > 1 THEN paradedb.boolean(should => ARRAY[ \
             paradedb.match_disjunction('{column}', {terms}), \
             paradedb.boost(2, paradedb.match('{column}', array_to_string({terms}, ' '), \
                                             conjunction_mode => true)), \
             paradedb.boost(2, paradedb.phrase('{column}', {terms}, slop => 2))]) \
         ELSE paradedb.match_disjunction('{column}', {terms}) END"
    )
}

/// One turn's nomination over its generations (`$1`), hidden items (`$2`),
/// keyword terms (`$3`), limit (`$4`), query embedding prefix and full
/// vector (`$5`, `$6`) under model `$7`, prefix window factor (`$8`) and the
/// fusion constant (`$9`). `cardinality($2) = 0 OR` keeps an empty hidden
/// set from pushing down into the BM25 index as a filter that matches
/// nothing (pg_search 0.24). The keyword leg cuts by score alone, so
/// pg_search's top-k scan serves it (a tie-broken sort read every match:
/// 69 ms against 18 ms); ties at the cut fall either way.
static NOMINATE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "WITH keyword AS ( \
             SELECT generation_id, ordinal, \
                    row_number() OVER (ORDER BY score DESC, generation_id, ordinal) AS rank \
             FROM (SELECT generation_id, ordinal, pdb.score(id) AS score FROM brain_search \
                   WHERE $3::text[] IS NOT NULL AND id @@@ ({query}) \
                     AND generation_id = ANY($1) \
                     AND (cardinality($2::text[]) = 0 OR item <> ALL($2)) \
                   ORDER BY score DESC LIMIT $4) AS matched), \
         nearest AS ( \
             SELECT generation_id, ordinal FROM brain_search \
             WHERE $5::real[] IS NOT NULL AND generation_id = ANY($1) AND model = $7 \
               AND prefix IS NOT NULL AND item <> ALL($2) \
             ORDER BY prefix <=> $5::real[]::halfvec(256), generation_id, ordinal \
             LIMIT $4 * $8), \
         vector AS ( \
             SELECT generation_id, ordinal, \
                    row_number() OVER (ORDER BY distance, generation_id, ordinal) AS rank \
             FROM (SELECT nearest.generation_id, nearest.ordinal, \
                          brain_chunk.embedding <=> $6::real[]::halfvec(2048) AS distance \
                   FROM nearest JOIN brain_chunk \
                     ON brain_chunk.generation_id = nearest.generation_id \
                    AND brain_chunk.ordinal = nearest.ordinal \
                   ORDER BY distance, nearest.generation_id, nearest.ordinal LIMIT $4) AS reranked) \
         SELECT generation_id, ordinal, \
                (COALESCE(1.0 / ($9::float8 + keyword.rank), 0) \
                 + COALESCE(1.0 / ($9::float8 + vector.rank), 0))::float8 AS rrf \
         FROM keyword FULL OUTER JOIN vector USING (generation_id, ordinal) \
         ORDER BY 3 DESC, 1, 2 LIMIT $4",
        query = keyword_query("text", "$3")
    )
});

/// The fused ranks of exactly the ordinals `$2` of generation `$1` (a turn
/// that addresses one record): keyword terms `$3`, query embedding `$4`
/// under model `$5`, fusion constant `$6`.
static RANK_RECORD: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "WITH keyword AS ( \
             SELECT ordinal, row_number() OVER (ORDER BY pdb.score(id) DESC, ordinal) AS rank \
             FROM brain_search \
             WHERE $3::text[] IS NOT NULL AND id @@@ ({query}) \
               AND generation_id = $1 AND ordinal = ANY($2)), \
         vector AS ( \
             SELECT ordinal, \
                    row_number() OVER (ORDER BY embedding <=> $4::real[]::halfvec(2048), ordinal) AS rank \
             FROM brain_chunk \
             WHERE $4::real[] IS NOT NULL AND generation_id = $1 AND ordinal = ANY($2) AND model = $5) \
         SELECT ordinal, \
                (COALESCE(1.0 / ($6::float8 + keyword.rank), 0) \
                 + COALESCE(1.0 / ($6::float8 + vector.rank), 0))::float8 AS rrf \
         FROM keyword FULL OUTER JOIN vector USING (ordinal) \
         ORDER BY 2 DESC, 1",
        query = keyword_query("text", "$3")
    )
});

/// Session settings of every pooled connection. The vector leg is a filtered
/// HNSW scan (`ef_search` 100): it keeps walking the graph until the turn's
/// generations fill the limit. A generic plan cannot see how selective
/// `generation_id = ANY($1)` is, so a plan cached for one turn's generations
/// incorrectly plans the next; custom plans read the array. Bitmap heap scans
/// prefetch (`effective_io_concurrency`; the server default is 1).
/// `work_mem` keeps a large generation's top-N in memory. The
/// `statement_timeout` and `lock_timeout` bound one statement — and any
/// advisory-lock wait inside it — server-side: a stalled backend is
/// cancelled — `57014` for the statement timeout, `55P03` for the lock —
/// and frees its pool slot, classified as the outage in
/// [`BrainError::postgres`]. The statement timeout is a turn's: a search
/// that has not answered by then fails as the outage. The warm round's writes
/// raise it for their own transaction ([`WARM`]).
static SESSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "SET hnsw.iterative_scan = relaxed_order; SET hnsw.ef_search = 100; \
         SET plan_cache_mode = force_custom_plan; \
         SET effective_io_concurrency = 32; \
         SET work_mem = '64MB'; \
         SET statement_timeout = '{ms}ms'; \
         SET lock_timeout = '{ms}ms'",
        ms = TURN_STATEMENT_BOUND.as_millis()
    )
});

/// The server-side bound of one turn's statement or lock wait.
const TURN_STATEMENT_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// The statement bound of one warm-round write transaction (mirroring,
/// embedding, sealing, releasing a generation). Its rows pass through the
/// `brain_search` triggers and its indexes, so dropping a million-chunk
/// generation or inserting a batch on a cold cache runs for minutes
/// (2026-10-22: a 1.65M-row release cancelled at the old 30 s, every round).
/// `SET LOCAL` ends with the transaction; the pooled session keeps the
/// turn's bound.
static WARM: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!(
        "SET LOCAL statement_timeout = '{}ms'",
        WARM_STATEMENT_BOUND.as_millis()
    )
});

const WARM_STATEMENT_BOUND: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The client cap on one warm-round write: above [`WARM`], so the server
/// cancels a stalled statement first.
const WARM_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// The deadline one database operation may take before its future is
/// cancelled. Pool acquire, the statements and any advisory-lock wait are
/// one future dropped together when it passes, so a timed-out transaction
/// rolls back and the caller gets [`BrainError::Unavailable`] instead of
/// waiting forever. A stalled statement is cancelled earlier by the connection's server
/// timeouts (`SESSION`), which free its pool slot without waiting for
/// this cap. Warm-round writes run under [`WARM_DEADLINE`] instead.
const OPERATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

// The server cancels a stalled statement before the client gives up on it.
const _: () = assert!(
    TURN_STATEMENT_BOUND.as_millis() < OPERATION_DEADLINE.as_millis()
        && WARM_STATEMENT_BOUND.as_millis() < WARM_DEADLINE.as_millis()
);

/// A claim on a generation that never sealed is stale after this long.
const STALE_CLAIM: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

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

/// A chunk row tests insert directly; builds stage theirs.
#[cfg(test)]
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
    /// The query's keyword terms ([`keyword_terms`]).
    pub terms: Option<Vec<String>>,
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
            .map_err(|error| postgres_outage(format!("cannot start the store runtime: {error}")))?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        runtime.spawn(async move {
            let connected = async {
                let pool = PgPoolOptions::new()
                    .max_connections(4)
                    .after_connect(|connection, _| {
                        Box::pin(
                            async move { connection.execute(SESSION.as_str()).await.map(drop) },
                        )
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
            .map_err(|error| {
                postgres_outage(format!(
                    "the store runtime stopped while connecting: {error}"
                ))
            })?
            .map_err(postgres_outage)?;
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

    /// Why the store cannot serve while its schema migration runs (or
    /// after it failed); `None` once the schema is current.
    pub fn pending_migration(&self) -> Option<String> {
        self.pending
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Runs one database operation on the store's runtime and waits for
    /// its result. The whole operation — pool acquire, the statements,
    /// any advisory-lock wait — is a single future cancelled at the
    /// store's deadline: dropping a timed-out future rolls its
    /// transaction back, and the caller gets the typed outage instead of
    /// waiting forever. A stalled statement is
    /// cancelled earlier by the connection's server timeouts and
    /// surfaces as the same outage.
    fn run<T, F>(&self, query: impl FnOnce(PgPool) -> F) -> BrainResult<T>
    where
        F: Future<Output = Result<T, sqlx::Error>> + Send + 'static,
        T: Send + 'static,
    {
        self.run_within(self.deadline, query)
    }

    /// [`Self::run`] for a warm-round write: its transaction comes from
    /// [`begin_warm`].
    fn run_warm<T, F>(&self, query: impl FnOnce(PgPool) -> F) -> BrainResult<T>
    where
        F: Future<Output = Result<T, sqlx::Error>> + Send + 'static,
        T: Send + 'static,
    {
        self.run_within(WARM_DEADLINE, query)
    }

    /// [`Self::run`] with a caller-chosen deadline, for the one operation
    /// whose work grows with the data: the seal's read-back proof.
    fn run_within<T, F>(
        &self,
        deadline: std::time::Duration,
        query: impl FnOnce(PgPool) -> F,
    ) -> BrainResult<T>
    where
        F: Future<Output = Result<T, sqlx::Error>> + Send + 'static,
        T: Send + 'static,
    {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| postgres_outage("the store runtime is shut down"))?;
        if let Some(reason) = self
            .pending
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            return Err(postgres_outage(reason.clone()));
        }
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let future = query(self.pool.clone());
        runtime.spawn(async move {
            let outcome = match tokio::time::timeout(deadline, future).await {
                Ok(outcome) => outcome.map_err(BrainError::postgres),
                Err(_) => Err(postgres_outage(format!(
                    "a database operation timed out after {deadline:?} and was cancelled"
                ))),
            };
            let _ = sender.send(outcome);
        });
        receiver.recv().map_err(|error| {
            postgres_outage(format!("the store runtime dropped a query: {error}"))
        })?
    }

    #[cfg(test)]
    pub(crate) fn set_deadline_for_test(&mut self, deadline: std::time::Duration) {
        self.deadline = deadline;
    }

    /// Inserts chunk rows of one generation stamped with `model`; rows
    /// already present stay. A row without its own embedding takes the
    /// embedding of any stored chunk with the same text under that model.
    /// Returns false when the write is deferred — the generation's
    /// advisory lock is held by a seal, or the generation is already
    /// sealed and its rows are immutable (see `generations::row_write_open`).
    #[cfg(test)]
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
                    check_dims(&format_args!("embedding of chunk {}", row.ordinal), &dims)?;
                    embeddings.extend_from_slice(&dims);
                    columns.4.push((embeddings.len() / EMBEDDING_DIMS) as i32);
                }
                None => columns.4.push(0),
            }
        }
        self.run_warm(|pool| async move {
            let mut transaction = begin_warm(&pool).await?;
            if !generations::row_write_open(&mut transaction, &generation).await? {
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
                     WHERE row.vector = 0 AND model = $7 AND digest = row.digest
                       AND embedding IS NOT NULL LIMIT 1
                 ) AS peer ON true
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

    /// The stored embedding under `model` of each chunk text digest any
    /// generation already holds, so an archive's new revision embeds only
    /// the text it does not share with earlier ones.
    pub(crate) fn embeddings_by_digest(
        &self,
        model: &str,
        digests: Vec<String>,
    ) -> BrainResult<std::collections::HashMap<String, Vec<f32>>> {
        let model = model.to_owned();
        self.run(|pool| async move {
            let rows: Vec<(String, Vec<f32>)> = sqlx::query_as(
                "SELECT DISTINCT ON (digest) digest, embedding::real[] FROM brain_chunk
                 WHERE model = $1 AND digest = ANY($2) AND embedding IS NOT NULL",
            )
            .bind(&model)
            .bind(&digests)
            .fetch_all(&pool)
            .await?;
            Ok(rows.into_iter().collect())
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
            check_dims(&format_args!("embedding of chunk {ordinal}"), dims)?;
        }
        let (generation, model) = (generation.to_owned(), model.to_owned());
        self.run_warm(|pool| async move {
            let mut transaction = begin_warm(&pool).await?;
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
        self.run_warm(|pool| async move {
            let mut transaction = begin_warm(&pool).await?;
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
            drop_unheld(&mut transaction, &generation).await?;
            transaction.commit().await
        })
    }

    /// Drops claims a day old on generations that never sealed (a copy or
    /// seal that died mid-way), and their rows with the last claim. A
    /// generation whose lock is held, a seal in flight, waits for the next
    /// pass. Returns how many generations lost their rows.
    pub(crate) fn sweep_stale_claims(&self) -> BrainResult<usize> {
        self.run_warm(|pool| async move {
            let stale: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT generation_id FROM brain_generation b \
                 WHERE claimed_at < now() - make_interval(secs => $1) AND NOT EXISTS \
                   (SELECT 1 FROM brain_generation_header h \
                    WHERE h.generation_id = b.generation_id)",
            )
            .bind(STALE_CLAIM.as_secs_f64())
            .fetch_all(&pool)
            .await?;
            let mut swept = 0;
            for generation in stale {
                let mut transaction = begin_warm(&pool).await?;
                let acquired: bool =
                    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtext($1))")
                        .bind(&generation)
                        .fetch_one(&mut *transaction)
                        .await?;
                if !acquired {
                    continue;
                }
                sqlx::query(
                    "DELETE FROM brain_generation WHERE generation_id = $1 \
                     AND claimed_at < now() - make_interval(secs => $2) AND NOT EXISTS \
                       (SELECT 1 FROM brain_generation_header WHERE generation_id = $1)",
                )
                .bind(&generation)
                .bind(STALE_CLAIM.as_secs_f64())
                .execute(&mut *transaction)
                .await?;
                if drop_unheld(&mut transaction, &generation).await? {
                    swept += 1;
                    tracing::info!(generation = %generation, "brain retention swept an unsealed copy");
                }
                transaction.commit().await?;
            }
            Ok(swept)
        })
    }

    /// Marks `owner`'s holds on `unwired` as unwired from now (a mark keeps
    /// its first time) and clears the mark on every other hold. Returns the
    /// marked generations with how long each has been unwired.
    pub(crate) fn mark_unwired(
        &self,
        owner: &str,
        unwired: Vec<String>,
    ) -> BrainResult<Vec<(String, std::time::Duration)>> {
        let owner = owner.to_owned();
        self.run(|pool| async move {
            let mut transaction = pool.begin().await?;
            sqlx::query(
                "UPDATE brain_generation SET unwired_since = NULL \
                 WHERE owner = $1 AND unwired_since IS NOT NULL \
                   AND NOT (generation_id = ANY($2))",
            )
            .bind(&owner)
            .bind(&unwired)
            .execute(&mut *transaction)
            .await?;
            let marked: Vec<(String, f64)> = sqlx::query_as(
                "UPDATE brain_generation SET unwired_since = coalesce(unwired_since, now()) \
                 WHERE owner = $1 AND generation_id = ANY($2) \
                 RETURNING generation_id, extract(epoch FROM now() - unwired_since)::float8",
            )
            .bind(&owner)
            .bind(&unwired)
            .fetch_all(&mut *transaction)
            .await?;
            transaction.commit().await?;
            Ok(marked
                .into_iter()
                .map(|(generation, seconds)| {
                    (
                        generation,
                        std::time::Duration::from_secs_f64(seconds.max(0.0)),
                    )
                })
                .collect())
        })
    }

    /// How many chunks of `generation` have no embedding yet.
    pub(crate) fn unembedded_count(&self, generation: &str) -> BrainResult<u64> {
        let generation = generation.to_owned();
        self.run(|pool| async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM brain_chunk WHERE generation_id = $1 AND embedding IS NULL",
            )
            .bind(generation)
            .fetch_one(&pool)
            .await
        })
        .map(|count| count as u64)
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

    /// One turn's candidates: the keyword leg (BM25 over `terms`, see
    /// [`keyword_query`]) and the vector leg (HNSW over the 256-d prefix of
    /// the turn's generations, ties broken by generation id then ordinal,
    /// reranked by the full embedding) each nominate `limit` chunks of those
    /// generations, fused by reciprocal rank.
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
                check_dims(&"query embedding", &full)?;
                let prefix = full[..PREFIX_DIMS].to_vec();
                (Some(full), Some(prefix), Some(model))
            }
            None => (None, None, None),
        };
        self.run(|pool| async move {
            let rows: Vec<(String, i64, f64)> = sqlx::query_as(&NOMINATE)
                .bind(&generations)
                .bind(&hidden_items)
                .bind(terms)
                .bind(limit)
                .bind(prefix)
                .bind(full)
                .bind(model)
                .bind(RERANK_FACTOR)
                .bind(RRF_K)
                .fetch_all(&pool)
                .await?;
            Ok(rows
                .into_iter()
                .map(|(generation_id, ordinal, rrf)| Nominated {
                    generation_id,
                    ordinal,
                    rrf,
                })
                .collect())
        })
    }

    /// The fused reciprocal ranks of exactly `ordinals` of one generation
    /// (a turn that addresses one record): every chunk is ranked by both
    /// legs without the turn-wide limits, and chunks neither leg matches
    /// drop.
    pub(crate) fn rank_record(
        &self,
        generation: &str,
        ordinals: Vec<i64>,
        terms: Option<Vec<String>>,
        embedding: Option<(Vec<f32>, String)>,
    ) -> BrainResult<Vec<Nominated>> {
        let generation = generation.to_owned();
        if let Some((full, _)) = &embedding {
            check_dims(&"query embedding", full)?;
        }
        let (full, model) = embedding.unzip();
        self.run(|pool| async move {
            let rows: Vec<(i64, f64)> = sqlx::query_as(&RANK_RECORD)
                .bind(&generation)
                .bind(&ordinals)
                .bind(terms)
                .bind(full)
                .bind(model)
                .bind(RRF_K)
                .fetch_all(&pool)
                .await?;
            Ok(rows
                .into_iter()
                .map(|(ordinal, rrf)| Nominated {
                    generation_id: generation.clone(),
                    ordinal,
                    rrf,
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

/// Begins a warm-round write transaction under the [`WARM`] statement bound.
async fn begin_warm(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, sqlx::Error> {
    let mut transaction = pool.begin().await?;
    (&mut *transaction).execute(WARM.as_str()).await?;
    Ok(transaction)
}

/// Deletes the header and rows of `generation` once no store holds it; the
/// caller holds its advisory lock. Returns whether anything went.
async fn drop_unheld(
    transaction: &mut sqlx::PgConnection,
    generation: &str,
) -> Result<bool, sqlx::Error> {
    let mut dropped = false;
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
        let deleted = sqlx::query(&sql)
            .bind(generation)
            .execute(&mut *transaction)
            .await?;
        dropped |= deleted.rows_affected() > 0;
    }
    Ok(dropped)
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
            "port" => options.port(u16::from_str(value).map_err(|error| {
                BrainError::InvalidPolicy(format!("[brain] postgres: {pair:?} port: {error}"))
            })?),
            "dbname" => options.database(value),
            "user" => options.username(value),
            _ => return Err(invalid()),
        };
    }
    Ok(options)
}

/// Refuses a vector of another width than the store holds; `what` names it.
pub(super) fn check_dims(what: &dyn std::fmt::Display, dims: &[f32]) -> BrainResult<()> {
    if dims.len() == EMBEDDING_DIMS {
        return Ok(());
    }
    Err(BrainError::InvalidRequest(format!(
        "the {what} has {} dimensions; the brain store holds {EMBEDDING_DIMS}",
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

mod generations;
mod records;

pub use records::{RecordFilters, RecordHits, RecordRead};

pub(crate) use generations::{
    CitedRow, HeaderRow, ProvenanceRow, SealProof, SealRejection, SealWait,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_cluster::TestCluster;

    const MODEL: &str = "test:model";

    fn last_ordinal(store: &BrainPostgres, generation: &str) -> BrainResult<Option<i64>> {
        let generation = generation.to_owned();
        store.run(|pool| async move {
            sqlx::query_scalar("SELECT max(ordinal) FROM brain_chunk WHERE generation_id = $1")
                .bind(generation)
                .fetch_one(&pool)
                .await
        })
    }

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
                terms: terms.map(keyword_terms),
                embedding: query.map(|dim| (axis(dim), MODEL.to_owned())),
                limit: 10,
            })
            .unwrap()
            .into_iter()
            .map(|nominated| nominated.ordinal)
            .collect()
    }

    /// A store behind by one migration connects at once, migrates in the
    /// background, and then serves.
    #[test]
    fn a_store_behind_migrates_in_the_background_and_then_serves() {
        let cluster = TestCluster::start();
        drop(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let last = MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap();
        cluster.sql(&format!(
            "DELETE FROM _sqlx_migrations WHERE version = {last}"
        ));
        let behind = BrainPostgres::connect(&cluster.conninfo).expect("connects at once");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while behind.pending_migration().is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "the migration never finished"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(last_ordinal(&behind, "g1").unwrap(), None);
    }

    /// A migration that fails keeps queries unavailable without blocking connection startup.
    #[test]
    fn a_failed_migration_never_serves() {
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
                    // A dirty migration must fail regardless of whether
                    // its SQL can be replayed. Deleting the row is not a
                    // failure fixture: index-rebuild migrations such as
                    // 0012 can legitimately succeed when replayed.
                    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = $1")
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
            match last_ordinal(&behind, "g1") {
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

        let lexical = nominate(&store, Some("oolong tea"), None);
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
                terms: Some(keyword_terms("oolong tea")),
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
            .stage_chunks(
                "s1",
                vec![CitedRow {
                    ordinal: 0,
                    chunk_id: "k0".to_owned(),
                    trust: "curated".to_owned(),
                    byte_start: 0,
                    byte_end: "same text".len() as i64,
                    item: "a".to_owned(),
                    digest: "digest:same text".to_owned(),
                    text: "same text".to_owned(),
                }],
            )
            .unwrap();
        assert_eq!(
            store.promote_stage("s1", "g1", MODEL, -1, 10).unwrap(),
            Some(1)
        );
        // A retried window is a no-op that still counts its staged rows.
        assert_eq!(
            store.promote_stage("s1", "g1", MODEL, -1, 10).unwrap(),
            Some(1)
        );
        store.drop_stage("s1").unwrap();
        store
            .insert_embeddings("g1", MODEL, vec![(0, axis(3))])
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
            last_ordinal(&store, "g1").unwrap(),
            Some(0),
            "gungnir still holds g1"
        );
        store.release("gungnir", "g1").unwrap();
        assert_eq!(
            last_ordinal(&store, "g1").unwrap(),
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

    /// A path, a URL, an e-mail address and a snake_case name split into
    /// their words in the index as in the query; stop words match only alone.
    #[test]
    fn the_keyword_leg_finds_every_word_as_the_query_splits_it() {
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
                        "see /home/owner/valhalla/odin/docs/HANDOFF.md",
                        None,
                    ),
                    row(
                        1,
                        "b",
                        "mail owner@example.org about https://mini.lan/x",
                        None,
                    ),
                    row(2, "c", "The Odin_brain store of Zoë", None),
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
            ("brain", 2),
            ("zoë", 2),
            ("CS 295 owner@example.org", 1),
        ] {
            assert!(
                nominate(&store, Some(term), None).contains(&ordinal),
                "{term} finds chunk {ordinal}"
            );
        }
    }

    #[test]
    fn a_vector_of_another_width_is_refused_naming_what_it_was() {
        let message = |what: &str| check_dims(&what, &[1.0; 8]).unwrap_err().to_string();
        assert!(message("query embedding").contains("the query embedding has 8 dimensions"));
        assert!(message("embedding of chunk 3").contains("embedding of chunk 3"));
        assert!(check_dims(&"query embedding", &vec![0.5; EMBEDDING_DIMS]).is_ok());
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
            "a server-cancelled wait is the store's outage: {refused:?}"
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
            last_ordinal(&store, "g9").unwrap(),
            None,
            "the store serves past the cancelled call"
        );

        // With the lock freed, the same mutator finishes at once: nothing
        // the cancelled attempt left behind can hold it.
        drop(holder);
        drop(holder_runtime);
        store.release("sinmara", "g1").unwrap();
        assert_eq!(
            last_ordinal(&store, "g1").unwrap(),
            None,
            "the generation goes whole with the release, not half deleted"
        );
    }
}
