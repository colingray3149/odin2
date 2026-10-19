//! Per-generation persistent BM25 indexes behind
//! [`IndexStore::generation_lexical_top`](crate::index::store::IndexStore::generation_lexical_top).
//!
//! A generation is immutable, so its FTS5 table is built once — in bounded
//! batches, by the background warm when it gets there first — and a query
//! reads only its best matches to nominate candidates. A change to one
//! source never rebuilds another source's index, and a turn never pays for
//! the whole corpus. Final lexical scores are FTS5's BM25 over the served
//! union's statistics (summed per-generation document counts, token totals
//! and term document frequencies), so scores stay comparable across sources
//! exactly as one pooled index would make them.
//!
//! The measured recipe: chunk text pre-tokenized with the one shared ASCII
//! tokenizer into a `tokenize='ascii'` table, BM25 (k1 = 1.2, b = 0.75),
//! raw score squashed `s/(1+s)` to millionths. Indexes are derived cache
//! state, never permission: callers filter every candidate through the
//! serving scope, and torn state is rebuilt, never served.

use std::collections::{BTreeMap, BTreeSet};

use odin_domain::knowledge::ids::RelevanceScore;
use odin_domain::knowledge::retrieval::RetrievalQuery;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{BrainError, BrainResult};
use crate::index::store::corrupt;
use crate::retrieval::rank::terms;

/// Most generation indexes kept; the least recently queried beyond this are
/// dropped (a later query or warm rebuilds them).
const MAX_GENERATION_INDEXES: usize = 48;

pub(crate) const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS brain_index_generation_fts (
        generation_id TEXT PRIMARY KEY,
        chunks        INTEGER NOT NULL,
        tokens        INTEGER NOT NULL,
        access        INTEGER NOT NULL
    );
";

/// Drops the retired union-pool cache (one table per authorized union of
/// every source's chunks); per-generation indexes replace it.
pub(crate) fn drop_retired_pools(connection: &Connection) -> BrainResult<()> {
    let present: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'brain_index_lexical_pool'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if present.is_none() {
        return Ok(());
    }
    let tables: Vec<String> = {
        let mut statement = connection.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name GLOB 'brain_index_lexical_[0-9a-f]*'",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for table in tables {
        if table.len() == "brain_index_lexical_".len() + 64 {
            connection.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
        }
    }
    connection.execute("DROP TABLE brain_index_lexical_pool", [])?;
    Ok(())
}

/// The FTS table of one generation: a hash of its id, never the id itself.
fn table(generation_id: &str) -> String {
    let hash = blake3::hash(format!("brain_index_generation_fts_v1:{generation_id}").as_bytes());
    format!("brain_index_gfts_{}", &hash.to_hex()[..32])
}

/// The generation's term-statistics view (`fts5vocab`, one row per term
/// with its document count and total occurrences).
fn vocab(table: &str) -> String {
    format!("{table}_vocab")
}

fn table_rows(connection: &Connection, table: &str) -> BrainResult<Option<i64>> {
    let present: Option<i64> = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )
        .optional()?;
    if present.is_none() {
        return Ok(None);
    }
    Ok(Some(connection.query_row(
        &format!("SELECT COUNT(*) FROM {table}"),
        [],
        |row| row.get(0),
    )?))
}

/// Whether one generation's index is complete: its marker present and its
/// table holding exactly the marker's row count.
pub(crate) fn ready(connection: &Connection, generation_id: &str) -> BrainResult<bool> {
    let marker: Option<i64> = connection
        .query_row(
            "SELECT chunks FROM brain_index_generation_fts WHERE generation_id = ?1",
            params![generation_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(marker) = marker else {
        return Ok(false);
    };
    // The marker must also equal the generation's own chunk count: an index
    // two concurrent builds filled holds chunks twice and its marker counts
    // the duplicates (before the one-build-per-generation lock), so it is
    // rebuilt once instead of served.
    let chunks: i64 = connection.query_row(
        "SELECT COUNT(*) FROM brain_index_chunk WHERE generation_id = ?1",
        params![generation_id],
        |row| row.get(0),
    )?;
    Ok(marker == chunks && table_rows(connection, &table(generation_id))? == Some(marker))
}

/// Drops one generation's index and its marker.
pub(crate) fn drop_index(connection: &Connection, generation_id: &str) -> BrainResult<()> {
    let table = table(generation_id);
    connection.execute(
        "DELETE FROM brain_index_generation_fts WHERE generation_id = ?1",
        params![generation_id],
    )?;
    connection.execute(&format!("DROP TABLE IF EXISTS {}", vocab(&table)), [])?;
    connection.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
    Ok(())
}

/// Starts (or restarts) one generation's index: a fresh empty table and no
/// marker, so a crash mid-build is simply an unbuilt index.
pub(crate) fn begin(connection: &Connection, generation_id: &str) -> BrainResult<()> {
    let table = table(generation_id);
    drop_index(connection, generation_id)?;
    connection.execute(
        &format!(
            "CREATE VIRTUAL TABLE {table} \
             USING fts5(text, ordinal UNINDEXED, tokenize='ascii')"
        ),
        [],
    )?;
    connection.execute(
        &format!(
            "CREATE VIRTUAL TABLE {} USING fts5vocab({table}, 'row')",
            vocab(&table)
        ),
        [],
    )?;
    Ok(())
}

/// Indexes the next `batch` chunks after ordinal `after` in one transaction;
/// returns the last ordinal indexed, or `None` when the generation is done.
pub(crate) fn fill(
    connection: &Connection,
    generation_id: &str,
    after: i64,
    batch: usize,
) -> BrainResult<Option<i64>> {
    let table = table(generation_id);
    let transaction = crate::sqlite::write_transaction(connection)?;
    let mut last = None;
    {
        let mut select = transaction.prepare(
            "SELECT ordinal, text FROM brain_index_chunk \
             WHERE generation_id = ?1 AND ordinal > ?2 ORDER BY ordinal LIMIT ?3",
        )?;
        let mut insert = transaction.prepare(&format!(
            "INSERT INTO {table} (text, ordinal) VALUES (?1, ?2)"
        ))?;
        let mut rows = select.query(params![generation_id, after, batch as i64])?;
        while let Some(row) = rows.next()? {
            let ordinal: i64 = row.get(0)?;
            let text: String = row.get(1)?;
            insert.execute(params![terms(&text).collect::<Vec<_>>().join(" "), ordinal])?;
            last = Some(ordinal);
        }
    }
    transaction.commit()?;
    Ok(last)
}

/// Marks the index complete with its row and token counts and drops the
/// least recently used indexes beyond the bound.
pub(crate) fn finish(connection: &Connection, generation_id: &str) -> BrainResult<()> {
    let built = table(generation_id);
    let rows = table_rows(connection, &built)?
        .ok_or_else(|| corrupt("a generation index vanished while it was built"))?;
    let tokens: i64 = connection.query_row(
        &format!("SELECT COALESCE(SUM(cnt), 0) FROM {}", vocab(&built)),
        [],
        |row| row.get(0),
    )?;
    let access = next_access(connection)?;
    connection.execute(
        "INSERT OR REPLACE INTO brain_index_generation_fts \
         (generation_id, chunks, tokens, access) VALUES (?1, ?2, ?3, ?4)",
        params![generation_id, rows, tokens, access],
    )?;
    let stale: Vec<String> = {
        let mut statement = connection.prepare(
            "SELECT generation_id FROM brain_index_generation_fts \
             ORDER BY access DESC LIMIT -1 OFFSET ?1",
        )?;
        let rows = statement.query_map(params![MAX_GENERATION_INDEXES as i64], |row| {
            row.get::<_, String>(0)
        })?;
        rows.collect::<Result<_, _>>()?
    };
    for evicted in stale {
        let evicted_table = table(&evicted);
        connection.execute(
            &format!("DROP TABLE IF EXISTS {}", vocab(&evicted_table)),
            [],
        )?;
        connection.execute(&format!("DROP TABLE IF EXISTS {evicted_table}"), [])?;
        connection.execute(
            "DELETE FROM brain_index_generation_fts WHERE generation_id = ?1",
            params![evicted],
        )?;
    }
    Ok(())
}

fn next_access(connection: &Connection) -> BrainResult<i64> {
    Ok(connection.query_row(
        "SELECT COALESCE(MAX(access), 0) + 1 FROM brain_index_generation_fts",
        [],
        |row| row.get(0),
    )?)
}

/// The `limit` best-matching chunk ordinals of a ready generation index,
/// best first, with their squashed per-generation scores (candidate
/// nomination; final scores come from [`bm25`] over the served union). A
/// query without lexical terms is a typed invalid request; unmatched terms
/// yield nothing.
pub(crate) fn top(
    connection: &Connection,
    generation_id: &str,
    query: &RetrievalQuery,
    limit: usize,
) -> BrainResult<Vec<(i64, RelevanceScore)>> {
    let expression = lexical_expression(query)?;
    let table = table(generation_id);
    let access = next_access(connection)?;
    connection.execute(
        "UPDATE brain_index_generation_fts SET access = ?1 WHERE generation_id = ?2",
        params![access, generation_id],
    )?;
    let mut statement = connection.prepare(&format!(
        "SELECT ordinal, bm25({table}) FROM {table} WHERE {table} MATCH ?1 \
         ORDER BY bm25({table}), ordinal LIMIT ?2"
    ))?;
    let mut rows = statement.query(params![expression, limit as i64])?;
    let mut scored = Vec::new();
    while let Some(row) = rows.next()? {
        let ordinal: i64 = row.get(0)?;
        let raw = -row.get::<_, f64>(1)?;
        scored.push((ordinal, RelevanceScore::new(squashed_millionths(raw)?)?));
    }
    Ok(scored)
}

/// Up to `limit` best-matching ordinals of a ready generation index whose
/// item `admit` accepts, best first — the serving scope applies before the
/// limit, so an out-of-scope item never crowds out an admitted one.
pub(crate) fn nominate(
    connection: &Connection,
    generation_id: &str,
    query: &RetrievalQuery,
    limit: usize,
    admit: &dyn Fn(&str) -> bool,
) -> BrainResult<Vec<i64>> {
    let expression = lexical_expression(query)?;
    let table = table(generation_id);
    let access = next_access(connection)?;
    connection.execute(
        "UPDATE brain_index_generation_fts SET access = ?1 WHERE generation_id = ?2",
        params![access, generation_id],
    )?;
    let mut statement = connection.prepare(&format!(
        "SELECT f.ordinal, c.item_id FROM {table} f \
         JOIN brain_index_chunk c ON c.generation_id = ?2 AND c.ordinal = f.ordinal \
         WHERE {table} MATCH ?1 ORDER BY bm25({table}), f.ordinal"
    ))?;
    let mut rows = statement.query(params![expression, generation_id])?;
    let mut nominated = Vec::new();
    while nominated.len() < limit {
        let Some(row) = rows.next()? else { break };
        let item: String = row.get(1)?;
        if admit(&item) {
            nominated.push(row.get(0)?);
        }
    }
    Ok(nominated)
}

/// Corpus statistics BM25 needs, summable across generations: the served
/// union's statistics are the sum of its generations'.
#[derive(Clone, Debug, Default)]
pub struct CorpusStats {
    pub docs: u64,
    pub tokens: u64,
    /// Documents containing each query term.
    pub df: BTreeMap<String, u64>,
}

impl CorpusStats {
    pub fn add(&mut self, other: &CorpusStats) {
        self.docs += other.docs;
        self.tokens += other.tokens;
        for (term, count) in &other.df {
            *self.df.entry(term.clone()).or_default() += count;
        }
    }
}

/// The unique lexical terms of a query (typed invalid when there are none).
pub(crate) fn query_terms(query: &RetrievalQuery) -> BrainResult<BTreeSet<String>> {
    let query_terms: BTreeSet<String> = terms(&query.text).collect();
    if query_terms.is_empty() {
        return Err(BrainError::InvalidRequest(
            "retrieval query text has no lexical terms".to_owned(),
        ));
    }
    Ok(query_terms)
}

/// One ready generation's statistics for `query_terms`.
pub(crate) fn stats(
    connection: &Connection,
    generation_id: &str,
    query_terms: &BTreeSet<String>,
) -> BrainResult<CorpusStats> {
    let (docs, tokens): (i64, i64) = connection.query_row(
        "SELECT chunks, tokens FROM brain_index_generation_fts WHERE generation_id = ?1",
        params![generation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut statement = connection.prepare(&format!(
        "SELECT doc FROM {} WHERE term = ?1",
        vocab(&table(generation_id))
    ))?;
    let mut df = BTreeMap::new();
    for term in query_terms {
        let count: Option<i64> = statement
            .query_row(params![term], |row| row.get(0))
            .optional()?;
        df.insert(term.clone(), count.unwrap_or(0) as u64);
    }
    Ok(CorpusStats {
        docs: docs as u64,
        tokens: tokens as u64,
        df,
    })
}

/// FTS5's BM25 (k1 = 1.2, b = 0.75, idf floored at 1e-6) of one chunk text
/// over `stats`, squashed to millionths — `None` when no query term occurs.
pub(crate) fn bm25(
    stats: &CorpusStats,
    query_terms: &BTreeSet<String>,
    text: &str,
) -> BrainResult<Option<RelevanceScore>> {
    const K1: f64 = 1.2;
    const B: f64 = 0.75;
    let tokens: Vec<String> = terms(text).collect();
    let length = tokens.len() as f64;
    let docs = stats.docs.max(1) as f64;
    let average = (stats.tokens as f64 / docs).max(1.0);
    let mut raw = 0.0;
    let mut matched = false;
    for term in query_terms {
        let tf = tokens.iter().filter(|token| *token == term).count() as f64;
        if tf == 0.0 {
            continue;
        }
        matched = true;
        let nt = stats.df.get(term).copied().unwrap_or(0) as f64;
        let idf = ((docs - nt + 0.5) / (nt + 0.5)).ln().max(1e-6);
        raw += idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * length / average));
    }
    if !matched {
        return Ok(None);
    }
    Ok(Some(RelevanceScore::new(squashed_millionths(raw)?)?))
}

/// Builds the measured query form: the unique lexical terms of the query
/// text — extracted by the one shared tokenizer used for the corpus — as
/// a quoted OR expression. Terms are ASCII alphanumeric by construction,
/// so quoting needs no escaping.
fn lexical_expression(query: &RetrievalQuery) -> BrainResult<String> {
    Ok(query_terms(query)?
        .iter()
        .map(|term| format!("\"{term}\""))
        .collect::<Vec<_>>()
        .join(" OR "))
}

/// Normalizes raw BM25 onto `[0, 1)` with the frozen `s/(1+s)` squash and
/// quantizes to millionths (round half away from zero). A non-finite or
/// negative raw score is engine-level corruption, typed at the seam.
fn squashed_millionths(raw: f64) -> BrainResult<u32> {
    if !raw.is_finite() || raw < 0.0 {
        return Err(corrupt("lexical index produced a non-physical BM25 score"));
    }
    let normalized = raw / (1.0 + raw);
    Ok((normalized * 1_000_000.0).round() as u32)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use odin_domain::knowledge::ids::{
        AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId,
    };
    use odin_domain::knowledge::retrieval::{Citation, IndexedChunk, TrustClass};
    use odin_domain::Digest;
    use tempfile::TempDir;

    use super::*;
    use crate::index::build::NO_EMBEDDING_MODEL;
    use crate::index::store::IndexStore;

    const SOURCE: &str = "atlas:lexical-index-test";

    fn chunk(seed: &str, text: &str, revision: &str) -> IndexedChunk {
        let item_id = KnowledgeItemId::new(Digest::hash(format!("{seed}:item").as_bytes()));
        let citation = Citation::new(
            AtlasId::new(SOURCE).expect("atlas id"),
            Digest::hash(revision.as_bytes()),
            item_id,
            None,
            None,
            None,
            None,
            0,
            text.len() as u64,
        )
        .expect("citation");
        IndexedChunk {
            item_id,
            chunk_id: KnowledgeChunkId::new(Digest::hash(format!("{seed}:chunk").as_bytes())),
            trust: TrustClass::Curated,
            text: text.to_owned(),
            digest: Digest::hash(text.as_bytes()),
            citation,
        }
    }

    fn query(text: &str) -> RetrievalQuery {
        let mut allowed_trust = BTreeSet::new();
        allowed_trust.insert(TrustClass::Curated);
        RetrievalQuery::new(
            text.to_owned(),
            [AtlasId::new(SOURCE).expect("atlas id")].into(),
            BTreeSet::new(),
            BTreeSet::new(),
            allowed_trust,
            NonZeroU16::new(64).expect("nonzero"),
            NonZeroU16::new(16).expect("nonzero"),
            RelevanceScore::new(0).expect("score"),
        )
        .expect("query")
    }

    fn store_generation(store: &IndexStore, revision: &str, texts: &[&str]) -> IndexGenerationId {
        let chunks: Vec<IndexedChunk> = texts
            .iter()
            .enumerate()
            .map(|(index, text)| chunk(&format!("{revision}:{index}"), text, revision))
            .collect();
        let mut stream = chunks.into_iter().map(Ok);
        let (generation, _) = store
            .store_streaming(
                AtlasId::new(SOURCE).expect("atlas id"),
                Digest::hash(revision.as_bytes()),
                &EmbeddingModelId::new(NO_EMBEDDING_MODEL).expect("model"),
                1,
                &mut stream,
                &BTreeMap::new(),
            )
            .expect("store generation");
        generation.generation_id
    }

    #[test]
    fn a_generation_index_ranks_best_first_within_the_limit() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path())?;
        let generation = store_generation(
            &store,
            "r1",
            &[
                "rankine cycle boiler turbine condenser pump rankine",
                "otto cycle spark ignition",
                "the rankine cycle in chemical engineering",
                "unrelated grocery list",
            ],
        );
        assert!(!store.generation_lexical_ready(&generation)?);
        store.build_generation_lexical(&generation)?;
        assert!(store.generation_lexical_ready(&generation)?);
        let hits = store.generation_lexical_top(&generation, &query("rankine cycle"), 2)?;
        assert_eq!(hits.len(), 2, "the limit bounds the matches");
        assert_eq!(hits[0].0, 0, "the densest match ranks first");
        assert!(hits.iter().all(|(_, score)| score.get() > 0));
        assert!(store
            .generation_lexical_top(&generation, &query("omega"), 5)?
            .is_empty());
        assert!(matches!(
            store.generation_lexical_top(&generation, &query("!!!"), 5),
            Err(BrainError::InvalidRequest(_))
        ));
        Ok(())
    }

    #[test]
    fn chunks_at_returns_the_asked_order_in_one_read() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path())?;
        let generation = store_generation(&store, "ord", &["zero", "one", "two", "three"]);
        let chunks = store.chunks_at(&generation, &[3, 1, 0])?;
        let texts: Vec<_> = chunks.iter().map(|chunk| chunk.text.as_str()).collect();
        assert_eq!(texts, ["three", "one", "zero"]);
        let missing = store.chunks_at(&generation, &[1, 9]);
        assert!(
            matches!(missing, Err(BrainError::Corrupt { .. })),
            "a missing ordinal stays corruption, not a hole"
        );
        Ok(())
    }

    #[test]
    fn union_statistics_reproduce_the_engine_score() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path())?;
        let texts = ["alpha one", "gamma one", "alpha gamma one", "delta one"];
        let generation = store_generation(&store, "s", &texts);
        store.build_generation_lexical(&generation)?;
        let query = query("alpha gamma");
        let terms = query_terms(&query)?;
        let stats = store.generation_lexical_stats(&generation, &terms)?;
        assert_eq!((stats.docs, stats.tokens), (4, 9));
        assert_eq!(stats.df["alpha"], 2);
        // Over one generation the Rust score equals the engine's own bm25.
        for (ordinal, engine) in store.generation_lexical_top(&generation, &query, 4)? {
            let ours = bm25(&stats, &terms, texts[ordinal as usize])?.expect("matched");
            assert!(
                ours.get().abs_diff(engine.get()) <= 1,
                "{ours:?} vs {engine:?}"
            );
        }
        assert_eq!(bm25(&stats, &terms, "delta one")?, None);
        // Statistics sum across generations.
        let mut union = stats.clone();
        union.add(&stats);
        assert_eq!((union.docs, union.df["alpha"]), (8, 4));
        Ok(())
    }

    #[test]
    fn concurrent_builds_of_one_generation_leave_it_ready() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = std::sync::Arc::new(IndexStore::open(dir.path())?);
        let texts: Vec<String> = (0..9_000)
            .map(|index| format!("chunk {index} rankine turbine condenser {}", index % 97))
            .collect();
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let generation = store_generation(&store, "concurrent", &texts);
        let builders: Vec<_> = (0..8)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                // What a turn does: build, then read the index it built.
                std::thread::spawn(move || {
                    store.build_generation_lexical(&generation)?;
                    store.generation_lexical_ready(&generation)
                })
            })
            .collect();
        for builder in builders {
            assert!(
                builder.join().expect("builder thread")?,
                "a builder's own index was not ready right after its build"
            );
        }
        // An interleaved rebuild leaves duplicate rows (the first builder
        // keeps filling from its cursor into the table the second reset),
        // which the marker then counts as complete.
        let connection = Connection::open(dir.path().join("brain-index.sqlite3"))?;
        assert_eq!(
            table_rows(&connection, &table(&generation.to_string()))?,
            Some(9_000),
            "the index holds each chunk exactly once"
        );
        Ok(())
    }

    /// An evicted index is not ready; reading its statistics separately is an error.
    #[test]
    fn an_evicted_index_reads_as_not_ready_never_as_a_storage_failure() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path())?;
        let generation = store_generation(&store, "evicted", &["advisor meeting thursday"]);
        store.build_generation_lexical(&generation)?;
        let terms: BTreeSet<String> = ["advisor".to_owned()].into();
        let advisor = query("advisor");
        assert!(store
            .generation_lexical_read(&generation, &terms, Some((&advisor, 4)), |_| true)?
            .is_some_and(|(_, nominated)| nominated == vec![0]));
        // What `finish` does to the least recently used index beyond the
        // bound, between one caller's steps.
        let connection = Connection::open(dir.path().join("brain-index.sqlite3"))?;
        connection.execute(
            "DELETE FROM brain_index_generation_fts WHERE generation_id = ?1",
            params![generation.to_string()],
        )?;
        assert!(
            store.generation_lexical_stats(&generation, &terms).is_err(),
            "the step-wise read fails on an evicted index"
        );
        assert!(store
            .generation_lexical_read(&generation, &terms, Some((&advisor, 4)), |_| true)?
            .is_none());
        store.build_generation_lexical(&generation)?;
        assert!(store
            .generation_lexical_read(&generation, &terms, None, |_| true)?
            .is_some());
        Ok(())
    }

    #[test]
    fn indexes_are_per_generation_and_torn_state_is_never_served() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path())?;
        let first = store_generation(&store, "a", &["alpha beta", "gamma"]);
        store.build_generation_lexical(&first)?;
        // A new generation of the same source leaves the first index as it
        // is — nothing is rebuilt.
        let second = store_generation(&store, "b", &["alpha alpha delta"]);
        assert!(store.generation_lexical_ready(&first)?);
        assert!(!store.generation_lexical_ready(&second)?);
        store.build_generation_lexical(&second)?;
        assert_eq!(
            store
                .generation_lexical_top(&second, &query("alpha"), 5)?
                .len(),
            1
        );
        // A table that lost rows no longer matches its marker: not ready.
        let connection = Connection::open(dir.path().join("brain-index.sqlite3"))?;
        connection.execute(
            &format!(
                "DELETE FROM {} WHERE ordinal = 1",
                table(&first.to_string())
            ),
            [],
        )?;
        assert!(!store.generation_lexical_ready(&first)?);
        store.build_generation_lexical(&first)?;
        assert!(store.generation_lexical_ready(&first)?);
        Ok(())
    }

    #[test]
    fn opening_a_store_drops_the_retired_union_pools() -> BrainResult<()> {
        let dir = TempDir::new().expect("temp dir");
        drop(IndexStore::open(dir.path())?);
        let pool = format!("brain_index_lexical_{}", "a".repeat(64));
        {
            let connection = Connection::open(dir.path().join("brain-index.sqlite3"))?;
            connection.execute_batch(&format!(
                "CREATE TABLE brain_index_lexical_pool (pool_key TEXT PRIMARY KEY, \
                 chunks INTEGER NOT NULL, access INTEGER NOT NULL);
                 CREATE VIRTUAL TABLE {pool} USING fts5(text, chunk_id UNINDEXED);"
            ))?;
        }
        drop(IndexStore::open(dir.path())?);
        let connection = Connection::open(dir.path().join("brain-index.sqlite3"))?;
        for name in ["brain_index_lexical_pool", pool.as_str()] {
            let present: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            assert!(present.is_none(), "{name} was dropped");
        }
        Ok(())
    }
}
