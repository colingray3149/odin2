//! The index store's generations in the brain's PostgreSQL store. Each one
//! is copied there whole (chunks with citations and any stored vectors,
//! item provenance), then — inside one transaction under the generation's
//! advisory lock — read back, hashed to its manifest, and only then sealed
//! with its header. Sealed generations are read from there; a retire
//! releases this store's hold.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeItemId, TokenizerId,
};
use odin_domain::knowledge::retrieval::{IndexGeneration, IndexedChunk};
use odin_domain::Digest;
use rusqlite::{params, Connection};

use super::{
    chunk_from_row, corrupt, decode_dims, parse_source_class, provenance::read_provenance_batch,
    IndexStore,
};
use crate::error::{BrainError, BrainResult};
use crate::index::build::{source_class_bytes, ManifestHasher};
use crate::index::model::ItemProvenance;
use crate::index::postgres::{
    BrainPostgres, CitedRow, HeaderRow, ProvenanceRow, SealProof, SealRejection, SealWait,
};

/// Chunk rows copied per round trip.
const COPY_BATCH: i64 = 500;

impl IndexStore {
    /// Serves this store's sealed generations from `postgres`.
    pub fn with_postgres(mut self, postgres: Option<Arc<BrainPostgres>>) -> Self {
        self.postgres = postgres;
        self
    }

    pub(crate) fn postgres(&self) -> Option<&BrainPostgres> {
        self.postgres.as_deref()
    }

    fn owner(&self) -> String {
        self.path.display().to_string()
    }

    fn cache(&self, generation: IndexGeneration, chunks: u64) -> BrainResult<()> {
        self.sealed
            .lock()
            .map_err(|_| corrupt("sealed generation cache mutex is poisoned"))?
            .insert(generation.generation_id, (generation, chunks));
        Ok(())
    }

    fn cached(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, u64)>> {
        Ok(self
            .sealed
            .lock()
            .map_err(|_| corrupt("sealed generation cache mutex is poisoned"))?
            .get(generation_id)
            .cloned())
    }

    /// The sealed header and chunk count of one generation, held by this
    /// store from now on. `None` without a PostgreSQL store, while the
    /// generation is unsealed, while the store is unreachable, or while
    /// another transaction holds the generation's advisory lock — a seal
    /// in flight — so a cold read never queues behind it (the SQLite rows
    /// still serve it).
    pub(super) fn sealed_generation(
        &self,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<Option<(IndexGeneration, u64)>> {
        let Some(postgres) = self.postgres() else {
            return Ok(None);
        };
        if let Some(cached) = self.cached(generation_id)? {
            return Ok(Some(cached));
        }
        match postgres.hold(&self.owner(), &generation_id.to_string()) {
            Ok(Some(row)) => {
                let sealed = sealed_from(&row)?;
                self.cache(sealed.0.clone(), sealed.1)?;
                Ok(Some(sealed))
            }
            Ok(None) | Err(BrainError::Unavailable { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The newest sealed generation of one source revision (stamped with
    /// `model` when given), with the `created_epoch` of its seal — the
    /// ordering key the SQLite selection is compared against.
    pub(super) fn sealed_current(
        &self,
        atlas_id: &AtlasId,
        atlas_revision: &Digest,
        model: Option<&EmbeddingModelId>,
    ) -> BrainResult<Option<(IndexGeneration, i64)>> {
        let Some(postgres) = self.postgres() else {
            return Ok(None);
        };
        let found = postgres.sealed_current(
            atlas_id.as_str(),
            &atlas_revision.to_string(),
            model.map(EmbeddingModelId::as_str),
        );
        let (id, created_epoch) = match found {
            Ok(Some(found)) => found,
            Ok(None) | Err(BrainError::Unavailable { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        let id = IndexGenerationId::parse(&id)
            .map_err(|_| corrupt("sealed generation id is not a canonical digest"))?;
        Ok(self
            .sealed_generation(&id)?
            .map(|(generation, _)| (generation, created_epoch)))
    }

    /// The generations among `generations` this store holds sealed (none
    /// without a PostgreSQL store).
    pub(crate) fn held(
        &self,
        generations: &[IndexGenerationId],
    ) -> BrainResult<BTreeSet<IndexGenerationId>> {
        let Some(postgres) = self.postgres() else {
            return Ok(BTreeSet::new());
        };
        let mut held = BTreeSet::new();
        let mut unknown = Vec::new();
        for id in generations {
            if self.cached(id)?.is_some() {
                held.insert(*id);
            } else {
                unknown.push(id.to_string());
            }
        }
        if unknown.is_empty() {
            return Ok(held);
        }
        for row in postgres.held(&self.owner(), unknown)? {
            let (generation, chunks) = sealed_from(&row)?;
            held.insert(generation.generation_id);
            self.cache(generation, chunks)?;
        }
        Ok(held)
    }

    /// Seals one stored generation unless this store already holds it
    /// sealed, copying at most `batches` batches of chunk rows when bounded
    /// (a later call resumes). Returns whether this store now holds it.
    /// Publication and row writes share a nonblocking advisory lock so copies
    /// cannot change rows during validation. Contention returns false and a
    /// later call resumes from cited_through.
    pub(crate) fn seal(
        &self,
        generation_id: &IndexGenerationId,
        batches: Option<usize>,
    ) -> BrainResult<bool> {
        let Some(postgres) = self.postgres() else {
            return Ok(false);
        };
        if self.sealed_generation(generation_id)?.is_some() {
            return Ok(true);
        }
        let id = generation_id.to_string();
        let started = std::time::Instant::now();
        let (generation, chunks, created_epoch) = {
            let connection = self.lock_connection()?;
            let Some(generation) = Self::load_header(&connection, generation_id)? else {
                return Ok(false);
            };
            let (chunks, created_epoch): (i64, i64) = connection.query_row(
                "SELECT (SELECT COUNT(*) FROM brain_index_chunk WHERE generation_id = ?1),
                        created_epoch
                 FROM brain_index_generation WHERE generation_id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            (generation, chunks, created_epoch)
        };
        // Refcount the copy in flight: a concurrent release must not drop
        // the rows already copied while later batches are under way.
        postgres.claim(&self.owner(), &id)?;
        let model = generation.embedding_model.as_str();
        let chunked = postgres.last_ordinal(&id)?.unwrap_or(-1);
        let mut after = postgres.cited_through(&id)?.unwrap_or(-1);
        let mut copied = 0_usize;
        while after + 1 < chunks {
            if batches.is_some_and(|limit| copied >= limit) {
                return Ok(false);
            }
            let rows = {
                let connection = self.lock_connection()?;
                cited_rows_after(&connection, &id, model, after, chunked)?
            };
            let Some((last, _)) = rows.last() else { break };
            after = last.ordinal;
            if !postgres.copy_cited(&id, model, rows)? {
                // A concurrent seal proving or publishing holds the
                // generation's advisory lock: the copied rows are that
                // seal's to prove, and the next round resumes from
                // cited_through.
                tracing::warn!(generation = %id, "brain-seal deferred rows=busy");
                return Ok(false);
            }
            copied += 1;
        }
        let mut after_item: Option<String> = None;
        loop {
            let rows = {
                let connection = self.lock_connection()?;
                let rows = read_provenance_batch(
                    &connection,
                    generation_id,
                    after_item.as_deref(),
                    COPY_BATCH as usize,
                )?;
                // Fair: a long provenance copy must not starve the turn
                // path that shares this connection.
                parking_lot::MutexGuard::unlock_fair(connection);
                rows
            };
            let Some(last) = rows.last() else { break };
            after_item = Some(last.0.to_string());
            if !postgres.copy_provenance(&id, provenance_rows(&rows))? {
                tracing::warn!(generation = %id, "brain-seal deferred provenance=busy");
                return Ok(false);
            }
        }
        // Compare copied offsets to SQLite; text and manifest hashes do not cover shifted spans.
        let offsets = sqlite_offsets_digest(self, &id)?;
        let header = HeaderRow {
            generation_id: id.clone(),
            atlas_id: generation.atlas_id.as_str().to_owned(),
            atlas_revision: generation.atlas_revision.to_string(),
            chunker_version: generation.chunker_version.clone(),
            tokenizer: generation.tokenizer.as_str().to_owned(),
            embedding_model: model.to_owned(),
            manifest_digest: generation.manifest_digest.to_string(),
            created_epoch,
            chunk_count: chunks,
        };
        let proof = ProofState::new(&header, offsets)?;
        match postgres.seal(&self.owner(), header, COPY_BATCH, proof, SealWait::Try)? {
            Ok(()) => {
                self.cache(generation, chunks as u64)?;
                tracing::info!(
                    generation = %id,
                    chunks,
                    ms = started.elapsed().as_millis(),
                    "brain-seal done"
                );
                Ok(true)
            }
            Err(SealRejection::Rejected(reason)) => {
                postgres.discard_unsealed(&id)?;
                tracing::error!(generation = %id, reason = %reason, "brain-seal rejected");
                Ok(false)
            }
            Err(SealRejection::Busy) => {
                // A concurrent sealer or releaser holds the generation's
                // advisory lock: its copied rows are that holder's to prove
                // or drop, and the next round resumes from cited_through.
                tracing::warn!(generation = %id, "brain-seal deferred lock=busy");
                Ok(false)
            }
        }
    }

    /// [`Self::seal`] once the caller's connection lock is released. The
    /// caller's SQLite commit already succeeded and SQLite stays the
    /// authority, so an unreachable store only defers the seal — a later
    /// round resumes from `cited_through` — and must not fail the write.
    /// The publication never queues either: a busy advisory lock defers
    /// the same way, so a new-build turn returns at once and the warm pump
    /// seals later.
    pub(super) fn seal_after(
        &self,
        connection: parking_lot::MutexGuard<'_, Connection>,
        generation_id: &IndexGenerationId,
    ) -> BrainResult<()> {
        drop(connection);
        match self.seal(generation_id, None) {
            Ok(_) => Ok(()),
            Err(error) if error.is_postgres_outage() => {
                tracing::warn!(generation = %generation_id, error = %error, "brain-seal deferred");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Releases this store's hold on a retired generation.
    pub(super) fn unseal(&self, generation_id: &IndexGenerationId) -> BrainResult<()> {
        self.sealed
            .lock()
            .map_err(|_| corrupt("sealed generation cache mutex is poisoned"))?
            .remove(generation_id);
        match self.postgres() {
            Some(postgres) => postgres.release(&self.owner(), &generation_id.to_string()),
            None => Ok(()),
        }
    }

    /// The chunks of a sealed generation at `ordinals`, in the order
    /// given; repeated ordinals repeat, as the SQLite path serves them.
    pub(super) fn sealed_chunks_at(
        &self,
        generation: &IndexGeneration,
        ordinals: &[i64],
    ) -> BrainResult<Vec<IndexedChunk>> {
        let postgres = self.postgres().ok_or_else(no_store)?;
        let id = generation.generation_id.to_string();
        let found: BTreeMap<i64, CitedRow> = postgres
            .cited_at(&id, ordinals.to_vec())?
            .into_iter()
            .map(|row| (row.ordinal, row))
            .collect();
        ordinals
            .iter()
            .map(|ordinal| {
                let row = found.get(ordinal).ok_or_else(|| {
                    corrupt(format!("generation {id} has no chunk at ordinal {ordinal}"))
                })?;
                cited_chunk(generation, row)
            })
            .collect()
    }

    pub(super) fn sealed_ordinals(
        &self,
        generation_id: &IndexGenerationId,
        items: &BTreeSet<KnowledgeItemId>,
    ) -> BrainResult<Vec<i64>> {
        self.postgres().ok_or_else(no_store)?.item_ordinals(
            &generation_id.to_string(),
            items.iter().map(ToString::to_string).collect(),
        )
    }

    pub(super) fn sealed_provenance(
        &self,
        generation_id: &IndexGenerationId,
        item_id: &KnowledgeItemId,
    ) -> BrainResult<Option<ItemProvenance>> {
        let postgres = self.postgres().ok_or_else(no_store)?;
        let (id, item) = (generation_id.to_string(), item_id.to_string());
        if !postgres.has_item(&id, &item)? {
            return Err(BrainError::NotFound {
                kind: "knowledge item",
                id: item,
            });
        }
        let rows = postgres.provenance_rows(&id, Some(item))?;
        Ok(provenance_map(rows)?.remove(item_id))
    }
}

/// Validates contiguous ordinals, chunk text/digests/spans, SQLite citation
/// offsets, manifest identity/provenance, and copied row counts before publication.
struct ProofState {
    generation: IndexGeneration,
    expected: i64,
    hasher: ManifestHasher,
    /// The canonical citation-offsets digest of the authoritative SQLite
    /// rows: the read-back offsets must hash to it, so a copied citation
    /// shifted to another span is refused even though its text, digest,
    /// and chunk identity all still match.
    offsets: Digest,
    offset_hasher: OffsetHasher,
    next: i64,
}

impl ProofState {
    fn new(header: &HeaderRow, offsets: Digest) -> BrainResult<Self> {
        let (generation, chunks) = sealed_from(header)?;
        Ok(Self {
            hasher: ManifestHasher::new(
                &generation.atlas_id,
                &generation.atlas_revision,
                &generation.chunker_version,
                generation.tokenizer.as_str(),
                generation.embedding_model.as_str(),
            ),
            expected: i64::try_from(chunks)
                .map_err(|_| corrupt("sealed chunk count is negative"))?,
            generation,
            offsets,
            offset_hasher: OffsetHasher::default(),
            next: 0,
        })
    }
}

impl SealProof for ProofState {
    fn feed_chunks(&mut self, rows: Vec<CitedRow>) -> Result<(), String> {
        for row in rows {
            if row.ordinal != self.next {
                return Err(format!("chunk {} is missing", self.next));
            }
            match cited_chunk(&self.generation, &row) {
                Ok(chunk) => self.hasher.push_chunk(&chunk),
                Err(BrainError::Corrupt { reason, .. }) => return Err(reason),
                Err(error) => return Err(error.to_string()),
            }
            self.offset_hasher
                .push(row.ordinal, row.byte_start, row.byte_end);
            self.next += 1;
        }
        Ok(())
    }

    fn feed_provenance(&mut self, rows: Vec<ProvenanceRow>) -> Result<(), String> {
        for row in rows {
            match provenance_item(row) {
                Ok((item_id, item)) => self.hasher.push_provenance(&item_id, &item),
                Err(BrainError::Corrupt { reason, .. }) => return Err(reason),
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<(), String> {
        if self.next != self.expected {
            return Err(format!(
                "{} of {} chunks are stored",
                self.next, self.expected
            ));
        }
        if self.offset_hasher.finish() != self.offsets {
            return Err(
                "stored citation offsets do not match the generation's citation offsets".to_owned(),
            );
        }
        if self.hasher.finish() != self.generation.manifest_digest {
            return Err("stored rows do not hash to the manifest digest".to_owned());
        }
        Ok(())
    }
}

fn no_store() -> BrainError {
    BrainError::Unavailable {
        component: "brain-postgres",
        reason: "no PostgreSQL store is configured".to_owned(),
    }
}

fn cited_chunk(generation: &IndexGeneration, row: &CitedRow) -> BrainResult<IndexedChunk> {
    chunk_from_row(
        &generation.atlas_id,
        generation.atlas_revision,
        &row.chunk_id,
        &row.item,
        &row.trust,
        &row.digest,
        &row.text,
        row.byte_start,
        row.byte_end,
    )
}

/// A stored header as a verified generation and its chunk count.
fn sealed_from(row: &HeaderRow) -> BrainResult<(IndexGeneration, u64)> {
    let generation_id = IndexGenerationId::parse(&row.generation_id)
        .map_err(|_| corrupt("sealed generation id is not a canonical digest"))?;
    let manifest_digest = Digest::parse(&row.manifest_digest)
        .map_err(|_| corrupt("sealed manifest digest is not a canonical digest"))?;
    if generation_id.as_digest() != &Digest::hash(manifest_digest.as_bytes()) {
        return Err(corrupt(
            "sealed generation id does not cover its manifest digest",
        ));
    }
    let generation = IndexGeneration {
        generation_id,
        atlas_id: AtlasId::new(row.atlas_id.clone())
            .map_err(|_| corrupt("sealed atlas id is invalid"))?,
        atlas_revision: Digest::parse(&row.atlas_revision)
            .map_err(|_| corrupt("sealed atlas revision is not a digest"))?,
        chunker_version: row.chunker_version.clone(),
        tokenizer: TokenizerId::new(row.tokenizer.clone())
            .map_err(|_| corrupt("sealed tokenizer id is invalid"))?,
        embedding_model: EmbeddingModelId::new(row.embedding_model.clone())
            .map_err(|_| corrupt("sealed embedding model id is invalid"))?,
        manifest_digest,
    };
    let chunks =
        u64::try_from(row.chunk_count).map_err(|_| corrupt("sealed chunk count is negative"))?;
    Ok((generation, chunks))
}

fn provenance_rows(rows: &[(KnowledgeItemId, ItemProvenance)]) -> Vec<ProvenanceRow> {
    rows.iter()
        .map(|(item_id, item)| ProvenanceRow {
            item_id: item_id.to_string(),
            node_id: item.node_id.clone(),
            path: item.path.clone(),
            source_class: source_class_bytes(item.source_class).to_owned(),
            scope_tags: item.scope_tags.clone(),
        })
        .collect()
}

fn provenance_item(row: ProvenanceRow) -> BrainResult<(KnowledgeItemId, ItemProvenance)> {
    let item_id = KnowledgeItemId::parse(&row.item_id)
        .map_err(|_| corrupt("provenance item id is not a canonical digest"))?;
    let source_class = parse_source_class(&row.source_class)
        .ok_or_else(|| corrupt("provenance source class is not a known class"))?;
    Ok((
        item_id,
        ItemProvenance {
            node_id: row.node_id,
            path: row.path,
            source_class,
            scope_tags: row.scope_tags,
        },
    ))
}

fn provenance_map(
    rows: Vec<ProvenanceRow>,
) -> BrainResult<BTreeMap<KnowledgeItemId, ItemProvenance>> {
    rows.into_iter().map(provenance_item).collect()
}

/// Hashes big-endian citation spans in ordinal order identically for SQLite
/// and read-back validation; this digest is not part of the manifest or generation ID.
#[derive(Default)]
struct OffsetHasher(blake3::Hasher);

impl OffsetHasher {
    fn push(&mut self, ordinal: i64, byte_start: i64, byte_end: i64) {
        self.0.update(&ordinal.to_be_bytes());
        self.0.update(&byte_start.to_be_bytes());
        self.0.update(&byte_end.to_be_bytes());
    }

    fn finish(self) -> Digest {
        Digest::from_bytes(*self.0.finalize().as_bytes())
    }
}

/// Reads SQLite's reference offsets in batches, releasing the connection between them.
fn sqlite_offsets_digest(store: &IndexStore, generation: &str) -> BrainResult<Digest> {
    let mut hasher = OffsetHasher::default();
    let mut after = -1_i64;
    loop {
        let spans = {
            let connection = store.lock_connection()?;
            let spans = offset_spans_after(&connection, generation, after)?;
            parking_lot::MutexGuard::unlock_fair(connection);
            spans
        };
        let Some(last) = spans.last() else { break };
        after = last.0;
        for (ordinal, byte_start, byte_end) in spans {
            hasher.push(ordinal, byte_start, byte_end);
        }
    }
    Ok(hasher.finish())
}

/// The next [`COPY_BATCH`] citation spans after `after`, in ordinal order.
fn offset_spans_after(
    connection: &Connection,
    generation: &str,
    after: i64,
) -> BrainResult<Vec<(i64, i64, i64)>> {
    let mut statement = connection.prepare_cached(
        "SELECT ordinal, byte_start, byte_end FROM brain_index_chunk \
         WHERE generation_id = ?1 AND ordinal > ?2 ORDER BY ordinal LIMIT ?3",
    )?;
    let rows = statement.query_map(params![generation, after, COPY_BATCH], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// The next [`COPY_BATCH`] chunk rows after `after` with their citations.
/// Rows past `chunked` (the PostgreSQL store's highest chunk row) carry
/// their stored vector; rows it already has are copied without one, and a
/// batch never spans both.
fn cited_rows_after(
    connection: &Connection,
    generation: &str,
    model: &str,
    after: i64,
    chunked: i64,
) -> BrainResult<Vec<(CitedRow, Option<Vec<f32>>)>> {
    let vectors = after >= chunked;
    let through = if vectors { i64::MAX } else { chunked };
    let mut statement = connection.prepare_cached(
        "SELECT c.ordinal, c.chunk_id, c.item_id, c.trust, c.digest, c.text,
                c.byte_start, c.byte_end,
                CASE WHEN ?5 THEN v.embedding_model END, CASE WHEN ?5 THEN v.dims END
         FROM brain_index_chunk c LEFT JOIN brain_index_vector v
           ON ?5 AND v.generation_id = c.generation_id AND v.ordinal = c.ordinal
         WHERE c.generation_id = ?1 AND c.ordinal > ?2 AND c.ordinal <= ?3
         ORDER BY c.ordinal LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![generation, after, through, COPY_BATCH, vectors],
        |row| {
            Ok((
                CitedRow {
                    ordinal: row.get(0)?,
                    chunk_id: row.get(1)?,
                    item: row.get(2)?,
                    trust: row.get(3)?,
                    digest: row.get(4)?,
                    text: row.get(5)?,
                    byte_start: row.get(6)?,
                    byte_end: row.get(7)?,
                },
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<Vec<u8>>>(9)?,
            ))
        },
    )?;
    let mut chunks = Vec::new();
    for row in rows {
        let (cited, vector_model, dims) = row?;
        let embedding = match (vector_model, dims) {
            (Some(vector_model), Some(dims)) if vector_model == model => {
                Some(decode_dims(&cited.chunk_id, &dims)?)
            }
            (Some(_), Some(_)) => {
                return Err(corrupt(
                    "stored vector rows are bound to a different embedding model than the generation pins",
                ))
            }
            _ => None,
        };
        chunks.push((cited, embedding));
    }
    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use odin_domain::knowledge::retrieval::TrustClass;

    use super::*;
    use crate::index::build::{build_index, Chunker};
    use crate::postgres_test_cluster::TestCluster;
    use crate::source::SourceItem;

    fn psql(cluster: &TestCluster, sql: &str) -> String {
        let output = std::process::Command::new("psql")
            .args([&cluster.conninfo, "-tAc", sql])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A `psql` session fed over stdin: a connection outside the store's
    /// pool, able to hold a lock the store's transaction waits on. Drop
    /// kills and reaps the child — on a failed assert's unwind too — so
    /// no session outlives the test.
    struct PsqlSession {
        child: std::process::Child,
        stdin: std::process::ChildStdin,
    }

    impl PsqlSession {
        fn start(conninfo: &str) -> Self {
            let mut child = std::process::Command::new("psql")
                .args([conninfo, "-v", "ON_ERROR_STOP=1"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            Self { child, stdin }
        }

        fn run(&mut self, sql: &str) {
            std::io::Write::write_all(&mut self.stdin, sql.as_bytes()).unwrap();
        }
    }

    impl Drop for PsqlSession {
        fn drop(&mut self) {
            // Kill and reap on every path, as `BatchBlobs` does: a
            // waiting `wait` alone could hold the test hostage on a
            // session still inside its transaction.
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn stored(name: &str, postgres: &Arc<BrainPostgres>) -> (IndexStore, IndexGeneration) {
        let root = std::env::temp_dir().join(format!("odin-seal-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let store = IndexStore::open(&root).unwrap();
        let (source, revision) = (AtlasId::new("atlas:seal").unwrap(), Digest::hash(b"r1"));
        let items: Vec<SourceItem> = ["alpha beta gamma delta", "epsilon zeta eta theta"]
            .iter()
            .map(|text| {
                SourceItem::new(
                    source.clone(),
                    revision,
                    text.as_bytes(),
                    TrustClass::Curated,
                    *text,
                )
                .unwrap()
            })
            .collect();
        let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
        let build = build_index(source, revision, &items, &chunker).unwrap();
        store.store(&build, 7).unwrap();
        (
            store.with_postgres(Some(Arc::clone(postgres))),
            build.generation,
        )
    }

    #[test]
    fn a_sealed_generation_serves_without_its_sqlite_rows() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("serve", &postgres);
        let id = generation.generation_id;
        let expected = store.chunks_at(&id, &[2, 0]).unwrap();
        assert!(store.held(&[id]).unwrap().is_empty(), "not sealed yet");

        assert!(store.seal(&id, None).unwrap());
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "1"
        );
        store
            .lock_connection()
            .unwrap()
            .execute_batch("DELETE FROM brain_index_chunk; DELETE FROM brain_index_generation;")
            .unwrap();
        assert_eq!(store.chunks_at(&id, &[2, 0]).unwrap(), expected);
        assert_eq!(
            store
                .load_pinned(&id, &generation.atlas_id, &generation.atlas_revision)
                .unwrap(),
            generation
        );
        assert_eq!(
            store
                .current(&generation.atlas_id, &generation.atlas_revision)
                .unwrap(),
            Some(generation.clone())
        );
        let item = expected[1].item_id;
        let ordinals = store
            .ordinals_for_items(&id, &BTreeSet::from([item]))
            .unwrap();
        assert!(ordinals.contains(&0), "{ordinals:?}");
        assert!(store.chunk_count(&id).unwrap().is_some());
        assert_eq!(store.provenance(&id, &item).unwrap(), None);
    }

    /// Invalid copied rows are removed so the next round can recopy from SQLite.
    #[test]
    fn a_copy_that_does_not_hash_to_the_manifest_is_never_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("forged", &postgres);
        let id = generation.generation_id;
        assert!(
            !store.seal(&id, Some(0)).unwrap(),
            "a zero-batch round copies nothing"
        );
        let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id.to_string(), "none", -1, -1).unwrap()
        };
        let forged = rows
            .into_iter()
            .map(|(mut row, _)| {
                if row.ordinal == 1 {
                    row.text = "forged".to_owned();
                }
                (row, None)
            })
            .collect();
        postgres
            .copy_cited(&id.to_string(), generation.embedding_model.as_str(), forged)
            .unwrap();
        let (header, proof) = header_proof(&store, &generation, chunks);
        assert_eq!(
            postgres
                .seal("forged", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap(),
            Err(SealRejection::Rejected(
                "chunk citation span does not match its stored text length".to_owned()
            ))
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert!(
            !store.seal(&id, None).unwrap(),
            "the forged copy is refused"
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_chunk"),
            "0",
            "dropped"
        );
        assert!(store.seal(&id, None).unwrap(), "a clean copy seals");
    }

    fn header_proof(
        store: &IndexStore,
        generation: &IndexGeneration,
        chunks: i64,
    ) -> (HeaderRow, ProofState) {
        let header = HeaderRow {
            generation_id: generation.generation_id.to_string(),
            atlas_id: generation.atlas_id.as_str().to_owned(),
            atlas_revision: generation.atlas_revision.to_string(),
            chunker_version: generation.chunker_version.clone(),
            tokenizer: generation.tokenizer.as_str().to_owned(),
            embedding_model: generation.embedding_model.as_str().to_owned(),
            manifest_digest: generation.manifest_digest.to_string(),
            created_epoch: 0,
            chunk_count: chunks,
        };
        let id = generation.generation_id.to_string();
        let offsets = sqlite_offsets_digest(store, &id).unwrap();
        let proof = ProofState::new(&header, offsets).unwrap();
        (header, proof)
    }

    /// Validation requires every ordinal; a later copy fills missing rows from SQLite.
    #[test]
    fn a_copy_missing_a_chunk_is_never_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("missing", &postgres);
        let id = generation.generation_id;
        let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
        let all: Vec<i64> = (0..chunks).collect();
        let sqlite = store.chunks_at(&id, &all).unwrap();
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id.to_string(), "none", -1, -1).unwrap()
        };
        let missing_one = rows
            .into_iter()
            .filter(|(row, _)| row.ordinal != 1)
            .map(|(row, _)| (row, None))
            .collect();
        postgres
            .copy_cited(
                &id.to_string(),
                generation.embedding_model.as_str(),
                missing_one,
            )
            .unwrap();
        let (header, proof) = header_proof(&store, &generation, chunks);
        assert_eq!(
            postgres
                .seal("missing", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap(),
            Err(SealRejection::Rejected("chunk 1 is missing".to_owned()))
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert!(!store.seal(&id, None).unwrap());
        assert_eq!(psql(&cluster, "SELECT count(*) FROM brain_chunk_cite"), "0");
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0",
            "the refused round publishes no header"
        );
        assert_eq!(
            store.chunks_at(&id, &all).unwrap(),
            sqlite,
            "the refused round leaves SQLite intact"
        );
        assert!(
            store.seal(&id, None).unwrap(),
            "the gap is healed and sealed"
        );
        assert_eq!(
            store.chunks_at(&id, &all).unwrap(),
            sqlite,
            "the sealed generation serves the complete generation"
        );
    }

    /// Deletion under the advisory lock must be visible to validation before publication.
    #[test]
    fn a_header_is_never_published_over_rows_deleted_under_the_lock() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("race", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();
        let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id_string, "none", -1, -1).unwrap()
        };
        let copied = rows
            .into_iter()
            .map(|(row, _)| (row, None))
            .collect::<Vec<_>>();
        postgres
            .copy_cited(&id_string, generation.embedding_model.as_str(), copied)
            .unwrap();
        let provenance = {
            let connection = store.lock_connection().unwrap();
            read_provenance_batch(&connection, &id, None, COPY_BATCH as usize).unwrap()
        };
        postgres
            .copy_provenance(&id_string, provenance_rows(&provenance))
            .unwrap();

        // Hold the generation's advisory lock outside the store.
        let mut session = PsqlSession::start(&cluster.conninfo);
        session.run(&format!(
            "BEGIN;\nSELECT pg_advisory_xact_lock(hashtext('{id_string}'));\n"
        ));

        let mut locked = false;
        for _ in 0..400 {
            if psql(
                &cluster,
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted",
            ) == "1"
            {
                locked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(locked, "the outside session did not acquire the lock");

        let (header, proof) = header_proof(&store, &generation, chunks);
        let sealed = std::thread::spawn(move || {
            postgres
                .seal("race", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap()
        });
        let mut blocked = false;
        for _ in 0..400 {
            if psql(
                &cluster,
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
            ) == "1"
            {
                blocked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(blocked, "the seal did not wait for the advisory lock");

        // Validation cannot read until this deletion commits and releases the lock.
        session.run(&format!(
            "DELETE FROM brain_chunk_cite WHERE generation_id = '{id_string}';\n\
             DELETE FROM brain_item_provenance WHERE generation_id = '{id_string}';\n\
             DELETE FROM brain_chunk WHERE generation_id = '{id_string}';\n\
             COMMIT;\n"
        ));
        assert!(
            sealed.join().unwrap().is_err(),
            "rows deleted under the lock cannot be sealed"
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert_eq!(
            psql(
                &cluster,
                &format!("SELECT count(*) FROM brain_chunk WHERE generation_id = '{id_string}'")
            ),
            "0",
            "the refused copy is dropped"
        );
    }

    /// Only the offsets digest catches a shifted span with unchanged text and length.
    #[test]
    fn a_shifted_citation_span_is_never_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("shifted", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();
        let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
        let served = store.chunks_at(&id, &[0, 1]).unwrap();
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id_string, "none", -1, -1).unwrap()
        };
        let shifted = rows
            .into_iter()
            .map(|(mut row, _)| {
                if row.ordinal == 1 {
                    row.byte_start += 100;
                    row.byte_end += 100;
                }
                (row, None)
            })
            .collect();
        postgres
            .copy_cited(&id_string, generation.embedding_model.as_str(), shifted)
            .unwrap();
        let (header, proof) = header_proof(&store, &generation, chunks);
        assert_eq!(
            postgres
                .seal("shifted", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap(),
            Err(SealRejection::Rejected(
                "stored citation offsets do not match the generation's citation offsets".to_owned()
            ))
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert!(
            !store.seal(&id, None).unwrap(),
            "the shifted copy is refused"
        );
        assert!(store.seal(&id, None).unwrap(), "a clean copy seals");
        assert_eq!(store.chunks_at(&id, &[0, 1]).unwrap(), served);
    }

    #[test]
    fn rejected_proofs_release_the_lock_before_the_connection_returns_to_the_pool() {
        for (name, shifted) in [("rollback-proof", true), ("rollback-sets", false)] {
            let cluster = TestCluster::start();
            let fixture = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
            let (store, generation) = stored(name, &fixture);
            let id = generation.generation_id;
            let id_string = id.to_string();
            let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
            let rows = {
                let connection = store.lock_connection().unwrap();
                cited_rows_after(&connection, &id_string, "none", -1, -1).unwrap()
            };
            let copied = rows
                .into_iter()
                .map(|(mut row, vector)| {
                    if shifted && row.ordinal == 1 {
                        row.byte_start += 100;
                        row.byte_end += 100;
                    }
                    (row, vector)
                })
                .collect();
            assert!(fixture
                .copy_cited(&id_string, generation.embedding_model.as_str(), copied)
                .unwrap());
            if !shifted {
                psql(
                    &cluster,
                    &format!(
                        "INSERT INTO brain_chunk (generation_id, ordinal, item, digest, text) \
                         SELECT '{id_string}', {chunks}, item, digest, text \
                         FROM brain_chunk WHERE generation_id = '{id_string}' AND ordinal = 0"
                    ),
                );
            }
            let (header, proof) = header_proof(&store, &generation, chunks);
            let mut postgres = BrainPostgres::connect(&cluster.conninfo).unwrap();
            let (parked, release) = postgres.gate_next_release_for_test(&cluster.conninfo);
            let rejected = postgres
                .seal(name, header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap();
            let reason = if shifted {
                "stored citation offsets do not match the generation's citation offsets".to_owned()
            } else {
                format!("{} of {chunks} chunk rows are stored", chunks + 1)
            };
            assert_eq!(rejected, Err(SealRejection::Rejected(reason)));
            parked
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("the sealing connection must reach the release gate");

            // after_release precedes SQLx's ping, which flushes a dropped
            // transaction's queued rollback. No SQL runs on that connection
            // until release is sent (or dropped during assertion unwind).
            assert_eq!(
                psql(
                    &cluster,
                    &format!("SELECT pg_try_advisory_xact_lock(hashtext('{id_string}'))")
                ),
                "t",
                "{name}: rejection must release its lock before pool return"
            );
            postgres.discard_unsealed(&id_string).unwrap();
            for table in ["brain_chunk", "brain_chunk_cite", "brain_item_provenance"] {
                assert_eq!(
                    psql(
                        &cluster,
                        &format!(
                            "SELECT count(*) FROM {table} WHERE generation_id = '{id_string}'"
                        )
                    ),
                    "0",
                    "{name}: {table} cleanup must not wait for pool return"
                );
            }
            release.send(()).unwrap();
        }
    }

    /// The read-back walks cited chunks through an inner join, so a stored
    /// chunk without a citation and a citation without a stored chunk are
    /// invisible to it. The sealing transaction demands the complete sets
    /// — the header's count, no uncited rows, no orphan citations — before
    /// it publishes the header.
    #[test]
    fn extra_uncited_and_orphan_rows_are_never_sealed() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("sets", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();
        let chunks = store.chunk_count(&id).unwrap().unwrap() as i64;
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id_string, "none", -1, -1).unwrap()
        };
        let copied = rows
            .into_iter()
            .map(|(row, _)| (row, None))
            .collect::<Vec<_>>();
        postgres
            .copy_cited(&id_string, generation.embedding_model.as_str(), copied)
            .unwrap();

        // An extra stored chunk with no citation: the count no longer
        // matches the header, and the inner-joined read-back never sees
        // the row.
        psql(
            &cluster,
            &format!(
                "INSERT INTO brain_chunk (generation_id, ordinal, item, digest, text) \
                 SELECT '{id_string}', (SELECT max(ordinal) + 1 FROM brain_chunk \
                                        WHERE generation_id = '{id_string}'), \
                        item, digest, text \
                 FROM brain_chunk WHERE generation_id = '{id_string}' AND ordinal = 0"
            ),
        );
        let (header, proof) = header_proof(&store, &generation, chunks);
        assert_eq!(
            postgres
                .seal("sets", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap(),
            Err(SealRejection::Rejected(format!(
                "{} of {chunks} chunk rows are stored",
                chunks + 1
            )))
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        psql(
            &cluster,
            &format!(
                "DELETE FROM brain_chunk WHERE generation_id = '{id_string}' \
                 AND ordinal = (SELECT max(ordinal) FROM brain_chunk \
                                WHERE generation_id = '{id_string}')"
            ),
        );

        // The mirror case: a citation whose stored chunk row is gone. The
        // inner join skips it, so every read-back batch looks complete.
        psql(
            &cluster,
            &format!(
                "INSERT INTO brain_chunk_cite \
                     (generation_id, ordinal, chunk_id, trust, byte_start, byte_end) \
                 SELECT '{id_string}', (SELECT max(ordinal) + 1 FROM brain_chunk_cite \
                                        WHERE generation_id = '{id_string}'), \
                        chunk_id, trust, byte_start, byte_end \
                 FROM brain_chunk_cite WHERE generation_id = '{id_string}' AND ordinal = 0"
            ),
        );
        let (header, proof) = header_proof(&store, &generation, chunks);
        assert_eq!(
            postgres
                .seal("sets", header, COPY_BATCH, proof, SealWait::Wait)
                .unwrap(),
            Err(SealRejection::Rejected(
                "1 citations have no stored chunk".to_owned()
            ))
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0"
        );
        assert!(
            !store.seal(&id, None).unwrap(),
            "the orphan citation is refused"
        );
        assert!(store.seal(&id, None).unwrap(), "a clean copy seals");
    }

    /// The read gate never queues: while another session holds the
    /// generation's advisory lock, a cold lookup of an unsealed generation
    /// serves its intact SQLite rows at once instead of waiting for the
    /// seal to finish.
    #[test]
    fn a_read_with_the_seal_lock_held_serves_sqlite_at_once() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("gate", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();
        let expected = store.chunks_at(&id, &[0]).unwrap();
        assert!(store.held(&[id]).unwrap().is_empty(), "not sealed yet");

        // Hold the generation's advisory lock outside the store, as a
        // seal in flight would.
        let mut session = PsqlSession::start(&cluster.conninfo);
        session.run(&format!(
            "BEGIN;\nSELECT pg_advisory_xact_lock(hashtext('{id_string}'));\n"
        ));
        let mut locked = false;
        for _ in 0..400 {
            if psql(
                &cluster,
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted",
            ) == "1"
            {
                locked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(locked, "the outside session did not acquire the lock");

        let started = std::time::Instant::now();
        let served = store.chunks_at(&id, &[0]).unwrap();
        assert_eq!(served, expected, "the SQLite rows serve the cold read");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the read waited {:?} on the generation's advisory lock",
            started.elapsed()
        );
    }

    /// Lock contention must defer copying and publication without changing rows.
    #[test]
    fn a_seal_defers_while_another_holds_the_publication_lock() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("busy", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();

        // Hold the generation's advisory lock outside the store, as a
        // concurrent sealer would.
        let mut session = PsqlSession::start(&cluster.conninfo);
        session.run(&format!(
            "BEGIN;\nSELECT pg_advisory_xact_lock(hashtext('{id_string}'));\n"
        ));
        let mut locked = false;
        for _ in 0..400 {
            if psql(
                &cluster,
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted",
            ) == "1"
            {
                locked = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(locked, "the outside session did not acquire the lock");

        let started = std::time::Instant::now();
        assert!(
            !store.seal(&id, None).unwrap(),
            "the seal defers instead of waiting for the lock"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the seal waited {:?} on the generation's advisory lock",
            started.elapsed()
        );
        assert_eq!(
            psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
            "0",
            "nothing is published over a lock the store does not hold"
        );
        let copied: i64 = psql(
            &cluster,
            &format!("SELECT count(*) FROM brain_chunk WHERE generation_id = '{id_string}'"),
        )
        .parse()
        .unwrap();
        assert_eq!(
            copied, 0,
            "the busy seal writes no rows behind the held lock: every \
             row write takes the same advisory lock, so nothing lands in \
             the window a concurrent proof-to-publish transaction owns"
        );

        // Once the lock frees, the next round copies from scratch and
        // seals.
        drop(session);
        assert!(
            store.seal(&id, None).unwrap(),
            "the next round seals once the lock frees"
        );
    }

    /// Sealed rows are immutable: once the header is published, every row
    /// write for the generation is refused — a corrupted store or a late
    /// copier cannot add an unproven row behind a sealed identity.
    #[test]
    fn a_sealed_generation_rejects_new_row_writes() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("immutable", &postgres);
        let id = generation.generation_id;
        let id_string = id.to_string();
        assert!(store.seal(&id, None).unwrap());
        let counts = |table: &str| {
            psql(
                &cluster,
                &format!("SELECT count(*) FROM {table} WHERE generation_id = '{id_string}'"),
            )
        };
        let expected = [
            counts("brain_chunk"),
            counts("brain_chunk_cite"),
            counts("brain_item_provenance"),
        ];

        // A late copy — here with one extra ordinal past the sealed set —
        // is refused whole, not partially applied.
        let rows = {
            let connection = store.lock_connection().unwrap();
            cited_rows_after(&connection, &id_string, "none", -1, -1).unwrap()
        };
        let mut extra = rows;
        let mut forged = extra[0].0.clone();
        forged.ordinal = 999;
        extra.push((forged, None));
        assert!(
            !postgres
                .copy_cited(&id_string, generation.embedding_model.as_str(), extra)
                .unwrap(),
            "a sealed generation refuses new chunk rows"
        );
        assert!(
            !postgres.copy_provenance(&id_string, Vec::new()).unwrap(),
            "a sealed generation refuses new provenance"
        );
        assert_eq!(counts("brain_chunk"), expected[0]);
        assert_eq!(counts("brain_chunk_cite"), expected[1]);
        assert_eq!(counts("brain_item_provenance"), expected[2]);
    }

    /// Sealed serving keeps the public contract for repeated and reordered
    /// ordinals: every requested ordinal is answered, in the order given,
    /// exactly as the unsealed SQLite path serves them.
    #[test]
    fn sealed_chunks_serve_duplicate_and_reordered_ordinals_like_sqlite() {
        let cluster = TestCluster::start();
        let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
        let (store, generation) = stored("parity", &postgres);
        let id = generation.generation_id;
        let ordinals = [2, 0, 2, 0];
        let from_sqlite = store.chunks_at(&id, &ordinals).unwrap();
        assert_eq!(from_sqlite.len(), 4, "SQLite repeats requested ordinals");

        assert!(store.seal(&id, None).unwrap());
        let sealed = store.chunks_at(&id, &ordinals).unwrap();
        assert_eq!(sealed, from_sqlite, "sealed serving matches SQLite");
        assert_eq!(sealed[0], sealed[2], "a repeated ordinal repeats its chunk");
    }
}
