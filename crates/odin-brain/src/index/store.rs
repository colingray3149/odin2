//! Exact, disposable, generation-scoped index storage.
//!
//! The index is a cache over the immutable Atlas authority: every stored row
//! is pinned to the Atlas revision and manifest digest it was built from, is
//! verified on load, and can be rebuilt at any time. The store therefore
//! implements:
//! - **Immutability**: a stored generation can never be overwritten; storing
//!   identical content is an idempotent no-op, and divergent content under an
//!   existing generation ID is impossible by construction (the ID is the
//!   manifest hash) and rejected as corruption when observed.
//! - **Corruption detection**: loads verify the manifest digest and every
//!   chunk content digest, failing typed ([`BrainError::Corrupt`]). Selection
//!   and bounded lookups recompute the manifest over the stored rows in one
//!   bounded streaming pass the first time a process touches a generation,
//!   then trust that verification for the process's lifetime.
//! - **Staleness**: `current` only returns a generation whose pinned Atlas
//!   revision equals the caller's pinned head; a moved head yields `None`
//!   (stale) rather than stale rows.
//! - **Retention**: `retire_older` keeps a source's served generation, newer
//!   ones and one previous; `reclaim` returns the freed pages.
//! - **Vector pools**: one exact, model-bound embedding vector per stored
//!   chunk ([`IndexStore::store_vectors`]/[`IndexStore::load_vectors`]),
//!   verified against the generation's pinned membership and embedding
//!   model; partial or divergent pools are refused or typed as corruption,
//!   never served.
//! - **Lexical pools**: persistent, content-keyed FTS5 BM25 pools
//!   ([`IndexStore::generation_lexical_top`]) derived from the exact authorized
//!   candidate chunks the caller passes. Rebuildable cache state with
//!   strictly pool-scoped statistics — never a permission boundary, since
//!   only passed chunk ids can ever score.
//!
//! Storage is a single SQLite database (rusqlite, WAL), consistent with the
//! ledger's conventions.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId,
    RelevanceScore, TokenizerId,
};
use odin_domain::knowledge::retrieval::{
    Citation, IndexGeneration, IndexedChunk, RetrievalQuery, TrustClass,
};
use odin_domain::Digest;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::context::tokenizer::PinnedTokenizer;
use crate::error::{BrainError, BrainResult};
use crate::index::build::{
    manifest_digest as compute_manifest_digest, source_class_bytes, trust_bytes, IndexBuild,
    ManifestHasher, CHUNKER_VERSION, INDEX_TOKENIZER,
};
use crate::index::lexical;
use crate::index::model::ItemProvenance;
use crate::retrieval::embedding::EmbeddingVector;

mod chunks;
mod embeddings;
mod provenance;
#[cfg(test)]
mod restamp_seal_tests;
mod seal;
#[cfg(test)]
mod seal_serving_tests;
mod vectors;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOutcome {
    /// The generation and its chunks were newly persisted.
    Stored,
    /// The identical generation was already present (idempotent rebuild).
    AlreadyPresent,
}

/// A fully verified, generation-pinned vector pool: one [`EmbeddingVector`]
/// per stored chunk in chunk-ordinal order, all bound to one embedding
/// model. Callers must refuse a pool whose model differs from their
/// configured backend — the store never silently rebinds vectors.
#[derive(Clone, Debug)]
pub struct StoredVectors {
    /// The embedding model every vector in the pool was produced under.
    pub embedding_model: EmbeddingModelId,
    /// Vector for the i-th chunk of the generation's chunk order.
    pub vectors: Vec<EmbeddingVector>,
}

/// Generation-scoped persistent index store over one SQLite database.
pub struct IndexStore {
    /// Fair handoff lets waiting turns acquire the connection between warm-pump batches.
    connection: parking_lot::Mutex<Connection>,
    /// The store file, keying the process-wide lexical build lock.
    path: PathBuf,
    postgres: Option<Arc<crate::index::postgres::BrainPostgres>>,
    /// Generations this store holds sealed in the PostgreSQL store, with
    /// their chunk counts. Sealed headers are insert-only; only this
    /// store's own retire drops its hold.
    sealed: Mutex<BTreeMap<IndexGenerationId, (IndexGeneration, u64)>>,
    /// Generations whose stored rows this store has verified against their
    /// pinned manifest (one bounded streaming pass). Selection and bounded
    /// lookups trust it for the process's lifetime; a corruption error or a
    /// retired generation drops the entry, and a fresh store starts empty.
    verified: Mutex<BTreeSet<IndexGenerationId>>,
}

impl IndexStore {
    const SCHEMA: &'static str = "
        CREATE TABLE IF NOT EXISTS brain_index_generation (
            generation_id   TEXT PRIMARY KEY,
            atlas_id        TEXT NOT NULL,
            atlas_revision  TEXT NOT NULL,
            chunker_version TEXT NOT NULL,
            tokenizer       TEXT NOT NULL,
            embedding_model TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            created_epoch   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS brain_index_chunk (
            generation_id TEXT NOT NULL REFERENCES brain_index_generation(generation_id),
            ordinal       INTEGER NOT NULL,
            chunk_id      TEXT NOT NULL,
            item_id       TEXT NOT NULL,
            trust         TEXT NOT NULL,
            digest        TEXT NOT NULL,
            text          TEXT NOT NULL,
            byte_start    INTEGER NOT NULL,
            byte_end      INTEGER NOT NULL,
            PRIMARY KEY (generation_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS brain_index_vector (
            generation_id   TEXT NOT NULL REFERENCES brain_index_generation(generation_id),
            ordinal         INTEGER NOT NULL,
            chunk_id        TEXT NOT NULL,
            embedding_model TEXT NOT NULL,
            dims            BLOB NOT NULL,
            PRIMARY KEY (generation_id, ordinal)
        );
        CREATE TABLE IF NOT EXISTS brain_chunk_vector_cache (
            embedding_model TEXT NOT NULL,
            text_digest     TEXT NOT NULL,
            dims            BLOB NOT NULL,
            PRIMARY KEY (embedding_model, text_digest)
        );
        CREATE TABLE IF NOT EXISTS brain_index_item_provenance (
            generation_id TEXT NOT NULL REFERENCES brain_index_generation(generation_id),
            item_id       TEXT NOT NULL,
            node_id       TEXT NOT NULL,
            path          TEXT NOT NULL,
            source_class  TEXT NOT NULL,
            scope_tags    TEXT NOT NULL,
            PRIMARY KEY (generation_id, item_id)
        );
        -- Covering pin indexes: the newest-generation selection reads one
        -- entry per (source, revision[, model]) lookup, in index order.
        CREATE INDEX IF NOT EXISTS brain_index_generation_model_pin
            ON brain_index_generation
            (atlas_id, atlas_revision, embedding_model, created_epoch DESC, generation_id DESC);
        CREATE INDEX IF NOT EXISTS brain_index_generation_pin
            ON brain_index_generation
            (atlas_id, atlas_revision, created_epoch DESC, generation_id DESC);
    ";

    /// Opens (creating if needed) the index database at `<root>/brain-index.sqlite3`.
    pub fn open(root: &Path) -> BrainResult<Self> {
        std::fs::create_dir_all(root).map_err(|error| BrainError::Unavailable {
            component: "brain-index-store",
            reason: format!("cannot create index root {}: {error}", root.display()),
        })?;
        let connection = crate::sqlite::open(&root.join("brain-index.sqlite3"))?;
        // The index is exact and disposable (rebuilt from its sources), so
        // a commit need not fsync (WAL stays consistent; a power cut can only
        // lose the newest rebuilds), turn-path sorts stay in memory, and the
        // WAL file is truncated back after each checkpoint instead of
        // keeping its high-water size.
        connection.execute_batch(
            "PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY; \
             PRAGMA cache_size = -8192; PRAGMA journal_size_limit = 67108864;",
        )?;
        connection.execute_batch(Self::SCHEMA)?;
        connection.execute_batch(lexical::SCHEMA)?;
        lexical::drop_retired_pools(&connection)?;
        // Drop the persistent stage; chunk staging uses a per-connection TEMP table.
        connection.execute_batch("DROP TABLE IF EXISTS main.brain_index_chunk_stage")?;
        Ok(Self {
            connection: parking_lot::Mutex::new(connection),
            path: root.join("brain-index.sqlite3"),
            postgres: None,
            sealed: Mutex::new(BTreeMap::new()),
            verified: Mutex::new(BTreeSet::new()),
        })
    }

    /// Deletes the store under `root` (a retired seat's), releasing every
    /// hold it has on generations in `postgres` first.
    pub fn remove(
        root: &Path,
        postgres: Option<&crate::index::postgres::BrainPostgres>,
    ) -> BrainResult<()> {
        if let Some(postgres) = postgres {
            let owner = root.join("brain-index.sqlite3").display().to_string();
            for generation in postgres.held_by(&owner)? {
                postgres.release(&owner, &generation)?;
            }
        }
        std::fs::remove_dir_all(root).map_err(|error| BrainError::Unavailable {
            component: "brain-index-store",
            reason: format!("cannot remove retired store {}: {error}", root.display()),
        })
    }

    fn lock_connection(&self) -> BrainResult<parking_lot::MutexGuard<'_, Connection>> {
        Ok(self.connection.lock())
    }

    /// Opens a momentary read-only connection for one selection while the
    /// shared connection is held (the warm pump streaming a pool): WAL
    /// readers never block readers, and the zero busy timeout keeps the
    /// path wait-free — the indexed lookup stays correct and returns
    /// without queueing behind the held mutex.
    fn read_only_connection(&self) -> BrainResult<Connection> {
        let connection = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| BrainError::Unavailable {
                component: "brain-index-store",
                reason: format!("cannot open a read-only index view: {error}"),
            })?;
        connection.busy_timeout(Duration::ZERO)?;
        Ok(connection)
    }

    /// Persists one deterministic build. Insert-only: a stored generation is
    /// immutable; re-storing identical content is an idempotent no-op.
    pub fn store(&self, build: &IndexBuild, created_epoch: u64) -> BrainResult<StoreOutcome> {
        if let Some((stored, _)) = self.load(&build.generation.generation_id)? {
            if stored.manifest_digest != build.generation.manifest_digest {
                return Err(corrupt(
                    "stored generation content diverges from the offered build under one generation id",
                ));
            }
            return Ok(StoreOutcome::AlreadyPresent);
        }
        for (item_id, item_provenance) in &build.provenance {
            if !build.chunks.iter().any(|chunk| &chunk.item_id == item_id) {
                return Err(BrainError::InvalidRequest(format!(
                    "item {item_id} carries provenance but no indexed chunks"
                )));
            }
            let nul_free = [
                item_provenance.node_id.as_str(),
                item_provenance.path.as_str(),
            ]
            .iter()
            .all(|field| !field.contains('\0'))
                && item_provenance
                    .scope_tags
                    .iter()
                    .all(|tag| !tag.contains('\0'));
            if !nul_free {
                return Err(BrainError::InvalidRequest(
                    "provenance fields must not contain NUL bytes".to_owned(),
                ));
            }
        }
        let connection = self.lock_connection()?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        // Re-check under the connection lock: the state rebuild pump and a
        // retrieval-time build may store the same deterministic generation
        // concurrently; the loser is the same idempotent no-op, never a
        // primary-key failure.
        let raced: Option<String> = tx
            .query_row(
                "SELECT manifest_digest FROM brain_index_generation WHERE generation_id = ?1",
                params![build.generation.generation_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored_digest) = raced {
            if stored_digest != build.generation.manifest_digest.to_string() {
                return Err(corrupt(
                    "stored generation content diverges from the offered build under one generation id",
                ));
            }
            return Ok(StoreOutcome::AlreadyPresent);
        }
        tx.execute(
            "INSERT INTO brain_index_generation
                (generation_id, atlas_id, atlas_revision, chunker_version, tokenizer,
                 embedding_model, manifest_digest, created_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                build.generation.generation_id.to_string(),
                build.generation.atlas_id.as_str(),
                build.generation.atlas_revision.to_string(),
                build.generation.chunker_version,
                build.generation.tokenizer.as_str(),
                build.generation.embedding_model.as_str(),
                build.generation.manifest_digest.to_string(),
                created_epoch as i64,
            ],
        )?;
        for (ordinal, chunk) in build.chunks.iter().enumerate() {
            tx.execute(
                "INSERT INTO brain_index_chunk
                    (generation_id, ordinal, chunk_id, item_id, trust, digest, text,
                     byte_start, byte_end)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    build.generation.generation_id.to_string(),
                    ordinal as i64,
                    chunk.chunk_id.to_string(),
                    chunk.item_id.to_string(),
                    trust_bytes(chunk.trust),
                    chunk.digest.to_string(),
                    chunk.text,
                    chunk.citation.byte_start as i64,
                    chunk.citation.byte_end as i64,
                ],
            )?;
        }
        for (item_id, item_provenance) in &build.provenance {
            tx.execute(
                "INSERT INTO brain_index_item_provenance
                    (generation_id, item_id, node_id, path, source_class, scope_tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    build.generation.generation_id.to_string(),
                    item_id.to_string(),
                    item_provenance.node_id,
                    item_provenance.path,
                    source_class_bytes(item_provenance.source_class),
                    item_provenance.scope_tags.join("\0"),
                ],
            )?;
        }
        tx.commit()?;
        // The warm pump is the only sealer: one sealer per generation.
        Ok(StoreOutcome::Stored)
    }

    /// Loads and fully verifies one generation: the generation ID must equal
    /// the hash of its manifest digest, the manifest digest must equal the
    /// hash over the stored ordered chunk identities, and every chunk text
    /// must hash to its recorded digest. Any mismatch is typed corruption.
    pub fn load(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, Vec<IndexedChunk>)>> {
        let connection = self.lock_connection()?;
        match Self::load_in(&connection, generation_id) {
            Ok(Some(loaded)) => {
                self.mark_verified(generation_id);
                Ok(Some(loaded))
            }
            Ok(None) => Ok(None),
            // A failed full verification proved the stored rows diverge from
            // the pinned manifest: this process's verified record for the
            // generation is dropped, so bounded lookups re-verify (and fail).
            Err(error) => {
                if matches!(error, BrainError::Corrupt { .. }) {
                    self.unverify(generation_id);
                }
                Err(error)
            }
        }
    }

    /// Connection-taking core of [`Self::load`]; callers that already hold
    /// the connection lock use this directly and stay deadlock-free.
    fn load_in(
        connection: &Connection,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, Vec<IndexedChunk>)>> {
        let Some(generation) = Self::load_header(connection, generation_id)? else {
            return Ok(None);
        };
        let id = generation_id.to_string();
        let mut statement = connection.prepare(
            "SELECT chunk_id, item_id, trust, digest, text, byte_start, byte_end
             FROM brain_index_chunk WHERE generation_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement.query_map(params![id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        let atlas_id = generation.atlas_id.clone();
        let atlas_revision = generation.atlas_revision;
        let mut chunks = Vec::new();
        for row in rows {
            let (chunk_id, item_id, trust, digest, text, byte_start, byte_end) = row?;
            chunks.push(chunk_from_row(
                &atlas_id,
                atlas_revision,
                &chunk_id,
                &item_id,
                &trust,
                &digest,
                &text,
                byte_start,
                byte_end,
            )?);
        }
        drop(statement);
        let item_provenance = read_item_provenance(connection, generation_id)?;
        for provenance_item in item_provenance.keys() {
            if !chunks.iter().any(|chunk| &chunk.item_id == provenance_item) {
                return Err(corrupt(
                    "stored provenance references an item the generation does not contain",
                ));
            }
        }

        let manifest_digest_of_rows = compute_manifest_digest(
            &generation.atlas_id,
            &generation.atlas_revision,
            &chunks,
            &item_provenance,
            &generation.chunker_version,
            generation.tokenizer.as_str(),
            generation.embedding_model.as_str(),
        );
        if manifest_digest_of_rows != generation.manifest_digest {
            return Err(corrupt(
                "stored chunk rows do not hash to the manifest digest",
            ));
        }
        Ok(Some((generation, chunks)))
    }

    /// Checks header identity without loading chunk text. Selection and provenance
    /// also use [`Self::verify_selected`]; full [`Self::load`] verifies every call.
    fn load_header(
        connection: &Connection,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<IndexGeneration>> {
        let id = generation_id.to_string();
        let row = connection
            .query_row(
                "SELECT atlas_id, atlas_revision, chunker_version, tokenizer,
                        embedding_model, manifest_digest
                 FROM brain_index_generation WHERE generation_id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((atlas_id, atlas_revision, chunker_version, tokenizer, embedding_model, manifest)) =
            row
        else {
            return Ok(None);
        };
        let manifest_digest = Digest::parse(&manifest)
            .map_err(|_| corrupt("manifest digest is not a canonical digest"))?;
        if generation_id.as_digest() != &Digest::hash(manifest_digest.as_bytes()) {
            return Err(corrupt("generation id does not cover its manifest digest"));
        }
        let atlas_id = AtlasId::new(atlas_id).map_err(|_| corrupt("stored atlas id is invalid"))?;
        let atlas_revision = Digest::parse(&atlas_revision)
            .map_err(|_| corrupt("stored atlas revision is not a digest"))?;
        Ok(Some(IndexGeneration {
            generation_id: *generation_id,
            atlas_id,
            atlas_revision,
            chunker_version,
            tokenizer: TokenizerId::new(tokenizer)
                .map_err(|_| corrupt("stored tokenizer id is invalid"))?,
            embedding_model: EmbeddingModelId::new(embedding_model)
                .map_err(|_| corrupt("stored embedding model id is invalid"))?,
            manifest_digest,
        }))
    }

    fn verified_contains(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        Ok(self
            .verified
            .lock()
            .map_err(|_| corrupt("verified generation cache mutex is poisoned"))?
            .contains(generation_id))
    }

    fn mark_verified(&self, generation_id: &IndexGenerationId) {
        self.verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(*generation_id);
    }

    fn unverify(&self, generation_id: &IndexGenerationId) {
        self.verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(generation_id);
    }

    /// First-touch per-process verification behind selection and bounded
    /// lookups: recomputes the manifest over the stored rows in one bounded
    /// streaming pass (one chunk row's text in memory at a time) and
    /// compares it to the pinned header digest. A verified generation is
    /// never re-hashed; tampered rows poison the whole generation — typed
    /// corruption — for this process's every reader.
    fn verify_selected(
        &self,
        connection: &Connection,
        generation: &IndexGeneration,
    ) -> BrainResult<()> {
        if self.verified_contains(&generation.generation_id)? {
            return Ok(());
        }
        let mut hasher = ManifestHasher::new(
            &generation.atlas_id,
            &generation.atlas_revision,
            &generation.chunker_version,
            generation.tokenizer.as_str(),
            generation.embedding_model.as_str(),
        );
        hash_stored_manifest_rows(connection, &generation.generation_id, &mut [&mut hasher])?;
        if hasher.finish() != generation.manifest_digest {
            return Err(corrupt(
                "stored chunk rows do not hash to the manifest digest",
            ));
        }
        self.mark_verified(&generation.generation_id);
        Ok(())
    }

    /// Loads one exact generation and verifies it is pinned to the expected
    /// source and revision. Used by archive serving paths, which pin the
    /// publication's exact generation rather than the newest generation for
    /// a (source, revision) pair — an unpublished restamp twin must never
    /// win by timestamp.
    pub fn load_pinned(
        &self,
        generation_id: &IndexGenerationId,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
    ) -> BrainResult<IndexGeneration> {
        let generation =
            match self.sealed_generation(generation_id)? {
                Some((generation, _)) => generation,
                None => Self::load_header(&*self.lock_connection()?, generation_id)?.ok_or_else(
                    || BrainError::NotFound {
                        kind: "index generation",
                        id: generation_id.to_string(),
                    },
                )?,
            };
        if &generation.atlas_id != atlas_id || &generation.atlas_revision != atlas_revision {
            return Err(BrainError::StaleAuthority {
                authority: "index_generation",
                detail: format!(
                    "generation {} pins {} at {} but the publication pins {} at {}",
                    generation.generation_id,
                    generation.atlas_id.as_str(),
                    generation.atlas_revision,
                    atlas_id.as_str(),
                    atlas_revision
                ),
            });
        }
        Ok(generation)
    }

    /// Returns the generation pinned to exactly this Atlas head, if stored.
    /// A moved head yields `None` — the stored generation is stale.
    pub fn current(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
    ) -> BrainResult<Option<IndexGeneration>> {
        self.current_for_model(atlas_id, atlas_revision, None)
    }

    /// The model-aware live selection: the newest generation for the
    /// (source, revision) pair WHOSE embedding-model stamp equals the
    /// requested effective model when one is declared. The newest sealed
    /// PostgreSQL candidate and the newest SQLite candidate — whatever its
    /// seal state — compete under one shared `(created_epoch, generation_id)`
    /// ordering, and the newer one serves: an older sealed generation must
    /// never shadow a newer SQLite-only generation whose seal a PostgreSQL
    /// outage deferred, and the warm pump seals whichever generation this
    /// selector returns. A model identity change (for example a provider
    /// protocol suffix) is a different embedding space by construction: an
    /// old-stamp generation must never win the pin only to be refused
    /// later by the vector-pool authority gate — the caller builds a fresh
    /// generation under the declared model instead. `None` keeps the
    /// historical newest-by-timestamp selection.
    /// With a sealed candidate in play the SQLite side is read without
    /// queueing behind the shared connection: a free lock serves directly,
    /// and a lock held by the warm pump answers from a momentary read-only
    /// connection (zero busy timeout), so a turn neither waits on warming
    /// nor silently serves the old sealed head.
    pub fn current_for_model(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        embedding_model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<IndexGeneration>> {
        let mut sealed = self.sealed_current(atlas_id, atlas_revision, embedding_model)?;
        if sealed.is_some() {
            // A sealed candidate never serves before the SQLite newest is
            // compared under the shared ordering: a strictly newer
            // SQLite-only generation whose seal a PostgreSQL outage
            // deferred must win. A free connection serves directly; a
            // connection held by the warm pump is answered from a momentary
            // read-only view instead of blocking the turn behind it.
            if let Some(connection) = self.connection.try_lock() {
                return self.select_current(
                    &connection,
                    &mut sealed,
                    atlas_id,
                    atlas_revision,
                    embedding_model,
                );
            }
            let connection = self.read_only_connection()?;
            return self
                .select_current(
                    &connection,
                    &mut sealed,
                    atlas_id,
                    atlas_revision,
                    embedding_model,
                )
                .map_err(Self::selection_busy);
        }
        let connection = self.lock_connection()?;
        self.select_current(
            &connection,
            &mut sealed,
            atlas_id,
            atlas_revision,
            embedding_model,
        )
    }

    /// The newest-generation statements of [`Self::select_current`],
    /// model-aware and model-less.
    const NEWEST_FOR_MODEL_SQL: &'static str = "SELECT generation_id, created_epoch \
         FROM brain_index_generation \
         WHERE atlas_id = ?1 AND atlas_revision = ?2 AND embedding_model = ?3 \
         ORDER BY created_epoch DESC, generation_id DESC LIMIT 1";
    const NEWEST_SQL: &'static str = "SELECT generation_id, created_epoch \
         FROM brain_index_generation \
         WHERE atlas_id = ?1 AND atlas_revision = ?2 \
         ORDER BY created_epoch DESC, generation_id DESC LIMIT 1";

    /// The connection-taking core of [`Self::current_for_model`]: the
    /// SQLite newest for the (source, revision[, model]) pin competes with
    /// the sealed candidate under one `(created_epoch, generation_id)`
    /// ordering — ties keep the sealed fast path — and the winner is
    /// manifest-verified over this same connection before it serves.
    fn select_current(
        &self,
        connection: &Connection,
        sealed: &mut Option<(IndexGeneration, i64)>,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        embedding_model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<IndexGeneration>> {
        let newest = if let Some(model) = embedding_model {
            connection
                .query_row(
                    Self::NEWEST_FOR_MODEL_SQL,
                    params![
                        atlas_id.as_str(),
                        atlas_revision.to_string(),
                        model.as_str()
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
        } else {
            connection
                .query_row(
                    Self::NEWEST_SQL,
                    params![atlas_id.as_str(), atlas_revision.to_string()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .optional()?
        };
        let Some((id, created_epoch)) = newest else {
            return Ok(sealed.take().map(|(generation, _)| generation));
        };
        let generation_id = IndexGenerationId::parse(&id)
            .map_err(|_| corrupt("stored generation id is not a canonical digest"))?;
        // Under the shared ordering the sealed candidate serves whenever it
        // is not older than the SQLite newest (ties keep the sealed fast
        // path); a strictly newer SQLite generation serves instead, and
        // sealing it is the warm pump's job.
        if let Some((generation, sealed_epoch)) = sealed.as_ref() {
            if (*sealed_epoch, generation.generation_id) >= (created_epoch, generation_id) {
                return Ok(sealed.take().map(|(generation, _)| generation));
            }
        }
        let Some(generation) = Self::load_header(connection, &generation_id)? else {
            // The SQLite rows retired beneath the selection: the sealed
            // candidate, if any, is the newest stored generation again.
            return Ok(sealed.take().map(|(generation, _)| generation));
        };
        self.verify_selected(connection, &generation)?;
        Ok(Some(generation))
    }

    /// Types a wait-free selection's SQLite busy state as unavailability:
    /// under a held connection nothing authoritative was chosen, so the
    /// caller sheds to its retry or fallback exactly as for any store
    /// outage — never to a silently serving old sealed head.
    fn selection_busy(error: BrainError) -> BrainError {
        match error {
            BrainError::Storage(rusqlite::Error::SqliteFailure(failure, _))
                if matches!(
                    failure.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                BrainError::Unavailable {
                    component: "brain-index-store",
                    reason: format!("the wait-free selection could not read the index: {error}"),
                }
            }
            other => other,
        }
    }

    /// The newest generation of one source (stamped with `model` when given),
    /// regardless of revision. With `sealed_only` and a PostgreSQL store,
    /// only a generation this store holds sealed qualifies.
    pub fn newest(
        &self,
        atlas_id: &AtlasId,
        model: Option<&EmbeddingModelId>,
        sealed_only: bool,
    ) -> BrainResult<Option<IndexGeneration>> {
        const CANDIDATES: usize = 8;
        let read = |connection: &Connection| -> BrainResult<Vec<IndexGenerationId>> {
            let mut statement = connection.prepare(
                "SELECT generation_id FROM brain_index_generation
                 WHERE atlas_id = ?1 AND (?2 IS NULL OR embedding_model = ?2)
                 ORDER BY created_epoch DESC, generation_id DESC LIMIT ?3",
            )?;
            let rows = statement.query_map(
                params![
                    atlas_id.as_str(),
                    model.map(EmbeddingModelId::as_str),
                    CANDIDATES as i64
                ],
                |row| row.get::<_, String>(0),
            )?;
            rows.map(|row| {
                IndexGenerationId::parse(&row?)
                    .map_err(|_| corrupt("stored generation id is not a canonical digest"))
            })
            .collect()
        };
        // A turn never queues behind the warm pump holding the connection.
        let ids = match self.connection.try_lock() {
            Some(connection) => read(&connection)?,
            None => read(&self.read_only_connection()?).map_err(Self::selection_busy)?,
        };
        if sealed_only && self.postgres.is_some() {
            let held = self.held(&ids)?;
            for id in ids.iter().filter(|id| held.contains(id)) {
                if let Some((generation, _)) = self.sealed_generation(id)? {
                    return Ok(Some(generation));
                }
            }
            return Ok(None);
        }
        let Some(id) = ids.first() else {
            return Ok(None);
        };
        let connection = self.lock_connection()?;
        let Some(generation) = Self::load_header(&connection, id)? else {
            return Ok(None);
        };
        self.verify_selected(&connection, &generation)?;
        Ok(Some(generation))
    }

    /// Whether this store holds `generation_id` sealed in its PostgreSQL
    /// store; always true without one, where SQLite serves.
    pub fn servable(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        if self.postgres.is_none() {
            return Ok(true);
        }
        Ok(self
            .held(std::slice::from_ref(generation_id))?
            .contains(generation_id))
    }

    /// Keeps `keep`, every newer generation of its source, and the one just
    /// before it (citations served from it moments ago still resolve);
    /// retires the rest. Returns how many retired; [`Self::reclaim`] frees
    /// their space.
    pub fn retire_older(&self, atlas_id: &AtlasId, keep: &IndexGenerationId) -> BrainResult<usize> {
        let ids: Vec<String> = {
            let connection = self.lock_connection()?;
            let mut statement = connection.prepare(
                "SELECT generation_id FROM brain_index_generation WHERE atlas_id = ?1
                 ORDER BY created_epoch DESC, generation_id DESC",
            )?;
            let rows = statement.query_map(params![atlas_id.as_str()], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let keep = keep.to_string();
        let Some(position) = ids.iter().position(|id| *id == keep) else {
            return Ok(0);
        };
        let mut retired = 0;
        for id in &ids[(position + 2).min(ids.len())..] {
            let id = IndexGenerationId::parse(id)
                .map_err(|_| corrupt("stored generation id is not a canonical digest"))?;
            if self.retire(&id)? {
                retired += 1;
            }
        }
        Ok(retired)
    }

    /// Returns freed pages to the filesystem. A store created before
    /// incremental auto-vacuum is converted by one full VACUUM, which only
    /// copies the rows still live.
    pub fn reclaim(&self) -> BrainResult<()> {
        let connection = self.lock_connection()?;
        let mode: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        if mode == 2 {
            connection.execute_batch("PRAGMA incremental_vacuum;")?;
        } else {
            connection.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
            tracing::info!(store = %self.path.display(), "brain store vacuumed");
        }
        Ok(())
    }

    /// Lists stored generations, newest first, optionally for one source.
    pub fn list(&self, atlas_id: Option<&AtlasId>) -> BrainResult<Vec<IndexGeneration>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT generation_id FROM brain_index_generation
             WHERE (?1 IS NULL OR atlas_id = ?1)
             ORDER BY created_epoch DESC, generation_id DESC",
        )?;
        let ids = statement
            .query_map(params![atlas_id.map(AtlasId::as_str)], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut generations = Vec::with_capacity(ids.len());
        for id in ids {
            let generation_id = IndexGenerationId::parse(&id)
                .map_err(|_| corrupt("stored generation id is not a canonical digest"))?;
            if let Some((generation, _)) = Self::load_in(&connection, &generation_id)? {
                generations.push(generation);
            }
        }
        Ok(generations)
    }

    /// Drops one generation: its rows, lexical index and PostgreSQL hold.
    /// Returns whether it existed.
    pub fn retire(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        let id = generation_id.to_string();
        let connection = self.lock_connection()?;
        let tx = crate::sqlite::write_transaction(&connection)?;
        tx.execute(
            "DELETE FROM brain_index_vector WHERE generation_id = ?1",
            params![id],
        )?;
        tx.execute(
            "DELETE FROM brain_index_item_provenance WHERE generation_id = ?1",
            params![id],
        )?;
        lexical::drop_index(&tx, &id)?;
        tx.execute(
            "DELETE FROM brain_index_chunk WHERE generation_id = ?1",
            params![id],
        )?;
        let removed = tx.execute(
            "DELETE FROM brain_index_generation WHERE generation_id = ?1",
            params![id],
        )?;
        tx.commit()?;
        drop(connection);
        self.unseal(generation_id)?;
        // The rows are gone; this process's verified record is too.
        self.unverify(generation_id);
        Ok(removed > 0)
    }

    /// Whether one generation's persistent lexical index is complete.
    pub fn generation_lexical_ready(&self, generation_id: &IndexGenerationId) -> BrainResult<bool> {
        let connection = self.lock_connection()?;
        lexical::ready(&connection, &generation_id.to_string())
    }

    /// Builds one generation's persistent lexical index in bounded batches,
    /// releasing the store lock between batches so a large archive never
    /// holds up another reader. The generation is verified once, in full,
    /// before its rows are indexed.
    pub fn build_generation_lexical(&self, generation_id: &IndexGenerationId) -> BrainResult<()> {
        const BATCH: usize = 2_000;
        let id = generation_id.to_string();
        // Serialize builders across batches so neither recreates the other's table.
        let build = lexical_build_lock(&self.path, &id);
        let _building = build
            .lock()
            .map_err(|_| corrupt("lexical build lock is poisoned"))?;
        {
            let connection = self.lock_connection()?;
            if lexical::ready(&connection, &id)? {
                drop(connection);
                release_lexical_build_lock(&self.path, &id, &build);
                return Ok(());
            }
            if Self::load_in(&connection, generation_id)?.is_none() {
                return Err(BrainError::NotFound {
                    kind: "index generation",
                    id,
                });
            }
            lexical::begin(&connection, &id)?;
        }
        let mut after = -1;
        let built = loop {
            let connection = self.lock_connection()?;
            match lexical::fill(&connection, &id, after, BATCH) {
                Ok(Some(last)) => after = last,
                Ok(None) => break lexical::finish(&connection, &id),
                Err(error) => break Err(error),
            }
        };
        release_lexical_build_lock(&self.path, &id, &build);
        built
    }

    /// The `limit` best lexical matches of a ready generation index.
    pub fn generation_lexical_top(
        &self,
        generation_id: &IndexGenerationId,
        query: &RetrievalQuery,
        limit: usize,
    ) -> BrainResult<Vec<(i64, RelevanceScore)>> {
        let connection = self.lock_connection()?;
        lexical::top(&connection, &generation_id.to_string(), query, limit)
    }

    /// Reads readiness, BM25 statistics, and optional candidates under one lock
    /// to prevent eviction between steps. `None` means build and read again.
    pub fn generation_lexical_read(
        &self,
        generation_id: &IndexGenerationId,
        query_terms: &BTreeSet<String>,
        nominate: Option<(&RetrievalQuery, usize)>,
        admit: impl Fn(&KnowledgeItemId) -> bool,
    ) -> BrainResult<Option<(lexical::CorpusStats, Vec<i64>)>> {
        let connection = self.lock_connection()?;
        let id = generation_id.to_string();
        if !lexical::ready(&connection, &id)? {
            return Ok(None);
        }
        let stats = lexical::stats(&connection, &id, query_terms)?;
        let nominated = match nominate {
            Some((query, limit)) => {
                lexical::nominate(&connection, &id, query, limit, &|item: &str| {
                    KnowledgeItemId::parse(item)
                        .map(|item| admit(&item))
                        .unwrap_or(false)
                })?
            }
            None => Vec::new(),
        };
        Ok(Some((stats, nominated)))
    }

    pub fn generation_lexical_stats(
        &self,
        generation_id: &IndexGenerationId,
        query_terms: &BTreeSet<String>,
    ) -> BrainResult<lexical::CorpusStats> {
        let connection = self.lock_connection()?;
        lexical::stats(&connection, &generation_id.to_string(), query_terms)
    }

    /// Returns the recorded Atlas node provenance for one item of one stored
    /// generation without materializing the generation's chunks: the stored
    /// rows are verified against the manifest once per process (one bounded
    /// streaming pass, `Self::verify_selected`), the item's membership is
    /// one indexed lookup, and the item's one provenance row is read
    /// directly. `Ok(None)` means the item exists but was indexed from a
    /// source without Atlas node identity (e.g. a SilverBullet page); a
    /// missing generation or item is typed [`BrainError::NotFound`], and
    /// tampered rows poison the generation as corruption.
    /// A sealed generation sheds to the SQLite body while PostgreSQL is
    /// unreachable.
    pub fn provenance(
        &self,
        generation_id: &IndexGenerationId,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ItemProvenance>> {
        if self.sealed_generation(generation_id)?.is_some() {
            return match self.sealed_provenance(generation_id, item_id) {
                Ok(found) => Ok(found),
                Err(error) if error.is_postgres_outage() => {
                    tracing::warn!(
                        generation = %generation_id,
                        "provenance store=sqlite postgres_unavailable"
                    );
                    self.stored_provenance(generation_id, item_id)
                }
                Err(error) => Err(error),
            };
        }
        self.stored_provenance(generation_id, item_id)
    }

    /// The unsealed SQLite body of [`Self::provenance`], and its shed target
    /// when a sealed generation's PostgreSQL store is unreachable.
    fn stored_provenance(
        &self,
        generation_id: &IndexGenerationId,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ItemProvenance>> {
        let connection = self.lock_connection()?;
        let Some(generation) = Self::load_header(&connection, generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        self.verify_selected(&connection, &generation)?;
        let member = connection
            .query_row(
                "SELECT 1 FROM brain_index_chunk
                 WHERE generation_id = ?1 AND item_id = ?2 LIMIT 1",
                params![generation_id.to_string(), item_id.to_string()],
                |_| Ok(()),
            )
            .optional()?;
        if member.is_none() {
            return Err(BrainError::NotFound {
                kind: "knowledge item",
                id: item_id.to_string(),
            });
        }
        provenance::read_one_provenance(&connection, generation_id, item_id)
    }

    /// Streaming variant of [`Self::store`]: persists one generation while
    /// consuming chunks one at a time, so mbox-scale sources never
    /// materialize every chunk in RAM. Chunks are spooled to an internal
    /// stage table while the manifest digest is computed incrementally over
    /// the exact chunk stream, then copied into the immutable chunk table in
    /// one transaction with the generation header. Chunks must arrive in
    /// stored-ordinal order (per-item chunk order). Insert-only with the
    /// same immutability and idempotency contract as `store`: re-storing
    /// identical content is an idempotent no-op, divergent content under an
    /// existing generation ID is typed corruption.
    ///
    /// Every provenance entry must reference an item the stream actually
    /// produced; the membership check runs against the streamed item set.
    #[allow(clippy::too_many_arguments)]
    pub fn store_streaming(
        &self,
        atlas_id: AtlasId,
        atlas_revision: Digest,
        embedding_model: &EmbeddingModelId,
        created_epoch: u64,
        chunks: &mut dyn Iterator<Item = BrainResult<IndexedChunk>>,
        provenance: &BTreeMap<KnowledgeItemId, ItemProvenance>,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        for item_provenance in provenance.values() {
            let nul_free = [
                item_provenance.node_id.as_str(),
                item_provenance.path.as_str(),
            ]
            .iter()
            .all(|field| !field.contains('\0'))
                && item_provenance
                    .scope_tags
                    .iter()
                    .all(|tag| !tag.contains('\0'));
            if !nul_free {
                return Err(BrainError::InvalidRequest(
                    "provenance fields must not contain NUL bytes".to_owned(),
                ));
            }
        }
        let connection = self.lock_connection()?;
        // The stage holds this call's chunk rows until the manifest
        // (knowable only after the last chunk) is complete. It is a TEMP
        // table: private to this connection (another process streaming into
        // the same store can never clear or mix into it), outside the WAL
        // (no per-row fsync, no write lock held while streaming), and gone
        // with the connection, so a crash mid-stream leaves nothing behind.
        connection.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS brain_index_chunk_stage (
                ordinal    INTEGER NOT NULL,
                chunk_id   TEXT NOT NULL,
                item_id    TEXT NOT NULL,
                trust      TEXT NOT NULL,
                digest     TEXT NOT NULL,
                text       TEXT NOT NULL,
                byte_start INTEGER NOT NULL,
                byte_end   INTEGER NOT NULL
            )",
        )?;
        connection.execute("DELETE FROM brain_index_chunk_stage", [])?;
        let mut hasher = ManifestHasher::new(
            &atlas_id,
            &atlas_revision,
            CHUNKER_VERSION,
            INDEX_TOKENIZER,
            embedding_model.as_str(),
        );
        let mut seen_items = std::collections::BTreeSet::new();
        let stage = |tx: &Connection, ordinal: i64, chunk: &IndexedChunk| -> BrainResult<()> {
            tx.execute(
                "INSERT INTO brain_index_chunk_stage
                    (ordinal, chunk_id, item_id, trust, digest, text, byte_start, byte_end)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    ordinal,
                    chunk.chunk_id.to_string(),
                    chunk.item_id.to_string(),
                    trust_bytes(chunk.trust),
                    chunk.digest.to_string(),
                    chunk.text,
                    chunk.citation.byte_start as i64,
                    chunk.citation.byte_end as i64,
                ],
            )?;
            Ok(())
        };
        for (ordinal, chunk) in (0_i64..).zip(chunks) {
            let chunk = chunk?;
            if chunk.citation.source != atlas_id {
                let error = BrainError::InvalidRequest(format!(
                    "chunk {} belongs to source {} but the generation pins {}",
                    chunk.chunk_id, chunk.citation.source, atlas_id
                ));
                let _ = connection.execute("DELETE FROM brain_index_chunk_stage", []);
                return Err(error);
            }
            hasher.push_chunk(&chunk);
            seen_items.insert(chunk.item_id);
            stage(&connection, ordinal, &chunk)?;
        }
        for provenance_item in provenance.keys() {
            if !seen_items.contains(provenance_item) {
                let error = BrainError::InvalidRequest(format!(
                    "item {provenance_item} carries provenance but no indexed chunks"
                ));
                let _ = connection.execute("DELETE FROM brain_index_chunk_stage", []);
                return Err(error);
            }
        }
        for (item_id, item_provenance) in provenance {
            hasher.push_provenance(item_id, item_provenance);
        }
        let manifest_digest = hasher.finish();
        let generation_id = IndexGenerationId::new(Digest::hash(manifest_digest.as_bytes()));
        let generation = IndexGeneration {
            generation_id,
            atlas_id: atlas_id.clone(),
            atlas_revision,
            chunker_version: CHUNKER_VERSION.to_owned(),
            tokenizer: PinnedTokenizer::id()?,
            embedding_model: embedding_model.clone(),
            manifest_digest,
        };
        let tx = crate::sqlite::write_transaction(&connection)?;
        let header = tx
            .query_row(
                "SELECT manifest_digest FROM brain_index_generation WHERE generation_id = ?1",
                params![generation_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(stored_manifest) = header {
            tx.rollback()?;
            connection.execute("DELETE FROM brain_index_chunk_stage", [])?;
            if stored_manifest != manifest_digest.to_string() {
                return Err(corrupt(
                    "stored generation content diverges from the offered build under one generation id",
                ));
            }
            return Ok((generation, StoreOutcome::AlreadyPresent));
        }
        tx.execute(
            "INSERT INTO brain_index_generation
                (generation_id, atlas_id, atlas_revision, chunker_version, tokenizer,
                 embedding_model, manifest_digest, created_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                generation_id.to_string(),
                atlas_id.as_str(),
                atlas_revision.to_string(),
                CHUNKER_VERSION,
                PinnedTokenizer::id()?.as_str(),
                embedding_model.as_str(),
                manifest_digest.to_string(),
                created_epoch as i64,
            ],
        )?;
        tx.execute(
            "INSERT INTO brain_index_chunk
                (generation_id, ordinal, chunk_id, item_id, trust, digest, text,
                 byte_start, byte_end)
             SELECT ?1, ordinal, chunk_id, item_id, trust, digest, text, byte_start, byte_end
             FROM brain_index_chunk_stage ORDER BY ordinal",
            params![generation_id.to_string()],
        )?;
        for (item_id, item_provenance) in provenance {
            tx.execute(
                "INSERT INTO brain_index_item_provenance
                    (generation_id, item_id, node_id, path, source_class, scope_tags)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    generation_id.to_string(),
                    item_id.to_string(),
                    item_provenance.node_id,
                    item_provenance.path,
                    source_class_bytes(item_provenance.source_class),
                    item_provenance.scope_tags.join("\0"),
                ],
            )?;
        }
        tx.execute("DELETE FROM brain_index_chunk_stage", [])?;
        tx.commit()?;
        self.seal_after(connection, &generation_id)?;
        Ok((generation, StoreOutcome::Stored))
    }

    /// Builds the model-stamped twin of one stored lexical generation: the
    /// same chunks under a generation stamped with `embedding_model`, which
    /// the batch embedding backfill fills with a vector pool. The manifest
    /// is recomputed incrementally over the stored chunk identities (never
    /// their texts), so the result is deterministic and idempotent —
    /// re-restamping one source under one model always yields the same
    /// generation ID. An existing twin is verified and returned WITHOUT
    /// touching chunk rows, so resumed or budgeted backfills never collide
    /// on primary keys. The source generation header is verified first;
    /// item provenance rows are carried into the twin so provenance-bearing
    /// sources stay loadable. Both outcomes seal the pending twin after
    /// releasing the SQLite connection, deferring only on a PostgreSQL
    /// outage.
    pub fn restamp_generation(
        &self,
        generation_id: &IndexGenerationId,
        embedding_model: &EmbeddingModelId,
        created_epoch: u64,
    ) -> BrainResult<(IndexGeneration, StoreOutcome)> {
        let connection = self.lock_connection()?;
        let Some(generation) = Self::load_header(&connection, generation_id)? else {
            return Err(BrainError::NotFound {
                kind: "index generation",
                id: generation_id.to_string(),
            });
        };
        // Full source verification, bounded: one chunk row (text included)
        // is hashed and dropped at a time. The recomputed source manifest
        // must equal the generation's recorded manifest — a header-only
        // check would let modified or deleted membership launder into a
        // valid-looking twin. The same pass feeds the twin's manifest under
        // the new embedding model.
        let mut source_hasher = ManifestHasher::new(
            &generation.atlas_id,
            &generation.atlas_revision,
            &generation.chunker_version,
            generation.tokenizer.as_str(),
            generation.embedding_model.as_str(),
        );
        let mut hasher = ManifestHasher::new(
            &generation.atlas_id,
            &generation.atlas_revision,
            &generation.chunker_version,
            generation.tokenizer.as_str(),
            embedding_model.as_str(),
        );
        hash_stored_manifest_rows(
            &connection,
            generation_id,
            &mut [&mut source_hasher, &mut hasher],
        )?;
        if source_hasher.finish() != generation.manifest_digest {
            return Err(corrupt(
                "stored chunk rows do not hash to the source generation's manifest",
            ));
        }
        let manifest_digest = hasher.finish();
        let twin_id = IndexGenerationId::new(Digest::hash(manifest_digest.as_bytes()));
        let twin = IndexGeneration {
            generation_id: twin_id,
            atlas_id: generation.atlas_id.clone(),
            atlas_revision: generation.atlas_revision,
            chunker_version: generation.chunker_version.clone(),
            tokenizer: generation.tokenizer.clone(),
            embedding_model: embedding_model.clone(),
            manifest_digest,
        };
        // Idempotency before any write: an existing twin must match the
        // recomputed manifest and is then a pure no-op, so a resumed or
        // budgeted backfill can restamp on every run without PK collisions.
        if let Some(existing) = Self::load_header(&connection, &twin_id)? {
            if existing.manifest_digest != manifest_digest
                || existing.embedding_model != *embedding_model
            {
                return Err(corrupt(
                    "stored restamped generation diverges from the recomputed manifest",
                ));
            }
            // warm_postgres visits published and current pins, never a
            // publication's pending twin, so the seal (or its PostgreSQL-
            // outage deferral) runs here on both restamp outcomes, after
            // the SQLite connection is released.
            self.seal_after(connection, &twin_id)?;
            return Ok((twin, StoreOutcome::AlreadyPresent));
        }
        let tx = crate::sqlite::write_transaction(&connection)?;
        // Header before children: with foreign keys on and immediate
        // reference checking, chunk rows can only copy after their
        // generation row exists.
        tx.execute(
            "INSERT INTO brain_index_generation
                (generation_id, atlas_id, atlas_revision, chunker_version, tokenizer,
                 embedding_model, manifest_digest, created_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                twin_id.to_string(),
                generation.atlas_id.as_str(),
                generation.atlas_revision.to_string(),
                generation.chunker_version,
                generation.tokenizer.as_str(),
                embedding_model.as_str(),
                manifest_digest.to_string(),
                created_epoch as i64,
            ],
        )?;
        tx.execute(
            "INSERT INTO brain_index_chunk
                (generation_id, ordinal, chunk_id, item_id, trust, digest, text,
                 byte_start, byte_end)
             SELECT ?1, ordinal, chunk_id, item_id, trust, digest, text, byte_start, byte_end
             FROM brain_index_chunk WHERE generation_id = ?2",
            params![twin_id.to_string(), generation_id.to_string()],
        )?;
        tx.execute(
            "INSERT INTO brain_index_item_provenance
                (generation_id, item_id, node_id, path, source_class, scope_tags)
             SELECT ?1, item_id, node_id, path, source_class, scope_tags
             FROM brain_index_item_provenance WHERE generation_id = ?2",
            params![twin_id.to_string(), generation_id.to_string()],
        )?;
        tx.commit()?;
        self.seal_after(connection, &twin_id)?;
        Ok((twin, StoreOutcome::Stored))
    }

    /// The number of chunks stored for one generation; `None` when the
    /// generation does not exist. Used by the archive backfill to measure
    /// staged progress against the full pool.
    pub fn chunk_count(&self, generation_id: &IndexGenerationId) -> BrainResult<Option<u64>> {
        if let Some((_, chunks)) = self.sealed_generation(generation_id)? {
            return Ok(Some(chunks));
        }
        let connection = self.lock_connection()?;
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM brain_index_chunk WHERE generation_id = ?1",
                params![generation_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(count.map(|count| count as u64))
    }

    /// Chunk `(ordinal, chunk id, text)` rows for one half-open ordinal
    /// range, bounded by the caller's batch size: the embedding backfill
    /// embeds and stages one batch at a time, never the whole pool.
    pub fn chunk_texts_in_range(
        &self,
        generation_id: &IndexGenerationId,
        from: u64,
        to: u64,
    ) -> BrainResult<Vec<(u64, String, String)>> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT ordinal, chunk_id, text FROM brain_index_chunk
             WHERE generation_id = ?1 AND ordinal >= ?2 AND ordinal < ?3
             ORDER BY ordinal",
        )?;
        let rows = statement.query_map(
            params![generation_id.to_string(), from as i64, to as i64],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        let mut chunks = Vec::new();
        for row in rows {
            let (ordinal, chunk_id, text) = row?;
            chunks.push((ordinal as u64, chunk_id, text));
        }
        Ok(chunks)
    }
}

/// Single construction point for typed store corruption errors.
pub(crate) fn corrupt(reason: impl Into<String>) -> BrainError {
    BrainError::Corrupt {
        component: "brain-index-store",
        reason: reason.into(),
    }
}

fn parse_trust(value: &str) -> Option<TrustClass> {
    match value {
        "control" => Some(TrustClass::Control),
        "curated" => Some(TrustClass::Curated),
        "observed" => Some(TrustClass::Observed),
        "untrusted" => Some(TrustClass::Untrusted),
        _ => None,
    }
}

/// Parses a stored Atlas source class token.
fn parse_source_class(value: &str) -> Option<odin_atlas::SourceClass> {
    match value {
        "rust" => Some(odin_atlas::SourceClass::Rust),
        "typescript" => Some(odin_atlas::SourceClass::TypeScript),
        "registry" => Some(odin_atlas::SourceClass::Registry),
        "skeleton" => Some(odin_atlas::SourceClass::Skeleton),
        _ => None,
    }
}

/// Reads and parses one generation's stored item provenance, ordered by item.
fn read_item_provenance(
    connection: &Connection,
    generation_id: &IndexGenerationId,
) -> BrainResult<BTreeMap<KnowledgeItemId, ItemProvenance>> {
    let mut statement = connection.prepare(
        "SELECT item_id, node_id, path, source_class, scope_tags
         FROM brain_index_item_provenance WHERE generation_id = ?1 ORDER BY item_id",
    )?;
    let mut stored = BTreeMap::new();
    for row in statement.query_map(params![generation_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })? {
        let (item_id, node_id, path, source_class, scope_tags) = row?;
        let (item_id, item_provenance) =
            provenance::parse_provenance_row(item_id, node_id, path, source_class, scope_tags)?;
        stored.insert(item_id, item_provenance);
    }
    Ok(stored)
}

/// Streams one generation's stored chunk rows in ordinal order, feeding
/// every hasher the canonical chunk identities and item provenance while
/// checking each row's text against its recorded digest and the ordinals'
/// density. One row's text is in memory at a time; this is the bounded core
/// shared by restamping and the once-per-process verification behind
/// selection and provenance lookups.
fn hash_stored_manifest_rows(
    connection: &Connection,
    generation_id: &IndexGenerationId,
    hashers: &mut [&mut ManifestHasher],
) -> BrainResult<()> {
    let mut statement = connection.prepare(
        "SELECT ordinal, chunk_id, item_id, trust, digest, text
         FROM brain_index_chunk WHERE generation_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement.query_map(params![generation_id.to_string()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    for (expected_ordinal, row) in (0_i64..).zip(rows) {
        let (ordinal, chunk_id, item_id, trust, digest, text) = row?;
        if ordinal != expected_ordinal {
            return Err(corrupt("stored chunk ordinals are not a dense sequence"));
        }
        let chunk_id = Digest::parse(&chunk_id)
            .map_err(|_| corrupt("stored chunk id is not a canonical digest"))?;
        let item_id = Digest::parse(&item_id)
            .map_err(|_| corrupt("stored item id is not a canonical digest"))?;
        let trust = parse_trust(&trust)
            .ok_or_else(|| corrupt("stored trust token is not a known class"))?;
        let digest = Digest::parse(&digest)
            .map_err(|_| corrupt("stored chunk digest is not a canonical digest"))?;
        if Digest::hash(text.as_bytes()) != digest {
            return Err(corrupt(
                "stored chunk text does not hash to its recorded digest",
            ));
        }
        for hasher in hashers.iter_mut() {
            hasher.push_chunk_identity(&chunk_id, &item_id, trust, &digest);
        }
    }
    drop(statement);
    for (item_id, item_provenance) in read_item_provenance(connection, generation_id)? {
        for hasher in hashers.iter_mut() {
            hasher.push_provenance(&item_id, &item_provenance);
        }
    }
    Ok(())
}

/// Reconstructs and verifies one chunk row against its recorded identity.
#[allow(clippy::too_many_arguments)]
fn chunk_from_row(
    atlas_id: &AtlasId,
    atlas_revision: Digest,
    chunk_id: &str,
    item_id: &str,
    trust: &str,
    digest: &str,
    text: &str,
    byte_start: i64,
    byte_end: i64,
) -> BrainResult<IndexedChunk> {
    let parse_failure = |reason: &str| corrupt(reason);
    let chunk_id = KnowledgeChunkId::parse(chunk_id)
        .map_err(|_| parse_failure("chunk id is not a canonical digest"))?;
    let item_id = KnowledgeItemId::parse(item_id)
        .map_err(|_| parse_failure("chunk item id is not a canonical digest"))?;
    let digest = Digest::parse(digest)
        .map_err(|_| parse_failure("chunk digest is not a canonical digest"))?;
    let trust =
        parse_trust(trust).ok_or_else(|| parse_failure("chunk trust is not a known class"))?;
    let span = byte_end
        .checked_sub(byte_start)
        .filter(|span| *span > 0)
        .ok_or_else(|| parse_failure("chunk citation byte range is not ordered"))?;
    // The citation range is ITEM-relative: its LENGTH must equal the stored
    // chunk text's byte length, not its absolute end. Comparing the absolute
    // end against the chunk text is wrong for every chunk after the first.
    if span as usize != text.len() {
        return Err(parse_failure(
            "chunk citation span does not match its stored text length",
        ));
    }
    if digest != Digest::hash(text.as_bytes()) {
        return Err(corrupt("chunk content digest does not match stored text"));
    }
    let citation = Citation::new(
        atlas_id.clone(),
        atlas_revision,
        item_id,
        None,
        None,
        None,
        None,
        byte_start as u64,
        byte_end as u64,
    )?;
    Ok(IndexedChunk {
        item_id,
        chunk_id,
        trust,
        text: text.to_owned(),
        digest,
        citation,
    })
}

/// Decodes and validates one stored dimension run as finite `f32` values.
fn decode_dims(chunk_id: &str, dims: &[u8]) -> BrainResult<Vec<f32>> {
    if dims.is_empty() || !dims.len().is_multiple_of(std::mem::size_of::<f32>()) {
        return Err(corrupt(format!(
            "stored vector for chunk {chunk_id} is not a whole little-endian f32 run"
        )));
    }
    let dims = dims
        .chunks_exact(std::mem::size_of::<f32>())
        .map(|bytes| f32::from_le_bytes(bytes.try_into().expect("width checked above")))
        .collect::<Vec<_>>();
    if let Some(dimension) = dims.iter().position(|value| !value.is_finite()) {
        return Err(corrupt(format!(
            "stored vector for chunk {chunk_id} has a non-finite dimension {dimension}"
        )));
    }
    Ok(dims)
}

/// Per (store file, generation) build locks; an entry lives while a build of
/// it runs or waits.
type LexicalBuildLocks = Mutex<HashMap<(PathBuf, String), Arc<Mutex<()>>>>;
static LEXICAL_BUILDS: LazyLock<LexicalBuildLocks> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lexical_build_lock(path: &Path, generation: &str) -> Arc<Mutex<()>> {
    let mut builds = LEXICAL_BUILDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(
        builds
            .entry((path.to_path_buf(), generation.to_owned()))
            .or_default(),
    )
}

/// Drops the entry once no other builder holds or waits on it (the map and
/// the caller are the only two references).
fn release_lexical_build_lock(path: &Path, generation: &str, build: &Arc<Mutex<()>>) {
    let mut builds = LEXICAL_BUILDS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if Arc::strong_count(build) <= 2 {
        builds.remove(&(path.to_path_buf(), generation.to_owned()));
    }
}

#[cfg(test)]
mod pragma_tests {
    use super::IndexStore;

    /// The turn path shares this connection with the background warmer:
    /// per-commit fsyncs and disk-spilled sorts showed up as seconds of turn
    /// latency, so the disposable index opens without them.
    #[test]
    fn index_store_opens_with_disposable_index_pragmas() {
        let root = std::env::temp_dir().join(format!("odin-index-pragmas-{}", std::process::id()));
        let store = IndexStore::open(&root).unwrap();
        let connection = store.lock_connection().unwrap();
        let read = |pragma: &str| -> i64 {
            connection
                .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
                .unwrap()
        };
        assert_eq!(read("synchronous"), 1, "NORMAL");
        assert_eq!(read("temp_store"), 2, "MEMORY");
        assert_eq!(read("journal_size_limit"), 67_108_864);
        drop(connection);
        std::fs::remove_dir_all(&root).ok();
    }
}

#[cfg(test)]
mod bounded_read_tests {
    use std::num::NonZeroU32;

    use odin_atlas::SourceClass;
    use odin_domain::knowledge::retrieval::TrustClass;
    use odin_domain::Digest;
    use tempfile::TempDir;

    use super::*;
    use crate::index::build::{build_index, Chunker};
    use crate::source::SourceItem;

    fn provenance_item(source: &AtlasId, revision: Digest, key: &str) -> SourceItem {
        SourceItem::new(
            source.clone(),
            revision,
            key.as_bytes(),
            TrustClass::Curated,
            format!("text {key} alpha beta gamma delta"),
        )
        .unwrap()
        .with_provenance(ItemProvenance {
            node_id: format!("crate:store:node-{key}"),
            path: format!("crates/store/src/{key}.rs"),
            source_class: SourceClass::Rust,
            scope_tags: vec!["scope:store".to_owned()],
        })
    }

    fn plain_item(source: &AtlasId, revision: Digest, key: &str) -> SourceItem {
        SourceItem::new(
            source.clone(),
            revision,
            key.as_bytes(),
            TrustClass::Curated,
            format!("text {key} alpha beta gamma delta"),
        )
        .unwrap()
    }

    fn opened() -> (TempDir, IndexStore) {
        let dir = TempDir::new().expect("temp dir");
        let store = IndexStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn store_items(
        store: &IndexStore,
        source: &AtlasId,
        revision: Digest,
        items: &[SourceItem],
        created_epoch: u64,
    ) -> IndexGeneration {
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source.clone(), revision, items, &chunker).unwrap();
        store.store(&build, created_epoch).unwrap();
        build.generation
    }

    /// Selection verifies the stored rows against the manifest once per
    /// process: a fresh store's first selection streams the rows (bounded,
    /// one text at a time) and a forged body poisons it, while a store that
    /// already verified the generation never re-hashes it. The retention
    /// sweep still resolves generations from their headers alone, and a
    /// full load refuses forged rows.
    #[test]
    fn selection_verifies_rows_once_per_process_and_retention_stays_header_only() {
        let source = AtlasId::new("atlas:bounded").unwrap();
        let old_revision = Digest::hash(b"old");
        let new_revision = Digest::hash(b"new");
        let (dir, store) = opened();
        let old_generation = store_items(
            &store,
            &source,
            old_revision,
            &[provenance_item(&source, old_revision, "old-key")],
            7,
        );
        store_items(
            &store,
            &source,
            new_revision,
            &[provenance_item(&source, new_revision, "new-key")],
            8,
        );

        // The first selection after storing verifies the stored rows (the
        // process's first touch) and records that verification.
        assert_eq!(
            store.current(&source, &old_revision).unwrap(),
            Some(old_generation.clone()),
            "selection resolves the stored generation"
        );

        // Forge every old chunk's text under its stored digest.
        {
            let connection = store.lock_connection().unwrap();
            connection
                .execute(
                    "UPDATE brain_index_chunk SET text = 'forged' WHERE generation_id = ?1",
                    params![old_generation.generation_id.to_string()],
                )
                .unwrap();
        }

        // Already verified in this process: selection trusts that
        // verification instead of re-hashing the rows.
        assert_eq!(
            store.current(&source, &old_revision).unwrap(),
            Some(old_generation.clone()),
            "a verified generation is not re-hashed on every selection"
        );

        // A fresh store has verified nothing: its first selection streams
        // the stored rows, so the forged body is typed corruption.
        let reopened = IndexStore::open(dir.path()).unwrap();
        assert!(
            matches!(
                reopened.current(&source, &old_revision).unwrap_err(),
                BrainError::Corrupt { .. }
            ),
            "first-touch selection verifies the stored rows against the manifest"
        );
        assert!(
            matches!(
                reopened.load(&old_generation.generation_id).unwrap_err(),
                BrainError::Corrupt { .. }
            ),
            "full loads still verify every chunk row"
        );

        assert!(store.retire(&old_generation.generation_id).unwrap());
    }

    /// One item's provenance reads the header, one membership lookup, and
    /// one provenance row once the generation is verified — and the first
    /// unverified lookup streams the stored rows (bounded, one text at a
    /// time), so forged rows poison the generation instead of serving
    /// bounded-row answers over corrupted state.
    #[test]
    fn provenance_of_one_item_reads_bounded_rows_once_verified() {
        let source = AtlasId::new("atlas:bounded").unwrap();
        let revision = Digest::hash(b"prov");
        let (dir, store) = opened();
        let items = vec![
            provenance_item(&source, revision, "with-prov"),
            plain_item(&source, revision, "plain"),
        ];
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source.clone(), revision, &items, &chunker).unwrap();
        store.store(&build, 7).unwrap();
        let id = build.generation.generation_id;
        let with_id = *build.provenance.keys().next().unwrap();
        let expected = build.provenance.values().next().unwrap().clone();
        let plain_id = build
            .chunks
            .iter()
            .map(|chunk| chunk.item_id)
            .find(|item_id| *item_id != with_id)
            .unwrap();

        assert_eq!(
            store.provenance(&id, &with_id).unwrap(),
            Some(expected.clone()),
        );
        assert_eq!(
            store.provenance(&id, &plain_id).unwrap(),
            None,
            "a source without Atlas node identity reads as provenance-free"
        );
        let unknown_item = KnowledgeItemId::new(Digest::hash(b"unknown"));
        match store.provenance(&id, &unknown_item).unwrap_err() {
            BrainError::NotFound { kind, .. } => assert_eq!(kind, "knowledge item"),
            other => panic!("expected NotFound, got {other:?}"),
        }
        let missing = IndexGenerationId::new(Digest::hash(b"missing"));
        match store.provenance(&missing, &with_id).unwrap_err() {
            BrainError::NotFound { kind, .. } => assert_eq!(kind, "index generation"),
            other => panic!("expected NotFound, got {other:?}"),
        }

        // This process already verified the generation: the single-item
        // lookup serves bounded rows.
        assert_eq!(
            store.provenance(&id, &with_id).unwrap(),
            Some(expected),
            "a verified generation's provenance is read from bounded rows"
        );

        // Forge a chunk row: a fresh store's first lookup verifies the
        // whole manifest in one bounded streaming pass and refuses.
        {
            let connection = store.lock_connection().unwrap();
            connection
                .execute(
                    "UPDATE brain_index_chunk SET text = 'forged' WHERE generation_id = ?1",
                    params![id.to_string()],
                )
                .unwrap();
        }
        let reopened = IndexStore::open(dir.path()).unwrap();
        assert!(
            matches!(
                reopened.provenance(&id, &with_id).unwrap_err(),
                BrainError::Corrupt { .. }
            ),
            "provenance lookup verifies the generation; forged rows poison it"
        );
    }
}
