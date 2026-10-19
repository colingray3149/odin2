//! Sealed generations serve from PostgreSQL without SQLite rows or cached
//! headers; matching row counts alone cannot validate altered content.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;

use odin_atlas::SourceClass;
use odin_domain::knowledge::ids::{
    AtlasId, EmbeddingModelId, IndexGenerationId, KnowledgeChunkId, KnowledgeItemId,
};
use odin_domain::knowledge::retrieval::{IndexGeneration, TrustClass};
use odin_domain::Digest;
use rusqlite::params;

use super::{IndexStore, StoreOutcome};
use crate::error::BrainError;
use crate::index::build::{source_class_bytes, trust_bytes, Chunker, NO_EMBEDDING_MODEL};
use crate::index::model::ItemProvenance;
use crate::index::postgres::{BrainPostgres, CitedRow, ProvenanceRow};
use crate::source::SourceItem;

use crate::postgres_test_cluster::TestCluster;

fn psql(cluster: &TestCluster, sql: &str) -> String {
    let output = std::process::Command::new("psql")
        .args([&cluster.conninfo, "-tAc", sql])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Two provenance-bearing source items over one source and revision.
fn items_with_provenance(
    source: &AtlasId,
    revision: Digest,
) -> (Vec<SourceItem>, BTreeMap<KnowledgeItemId, ItemProvenance>) {
    let items: Vec<SourceItem> = ["node-one", "node-two"]
        .iter()
        .enumerate()
        .map(|(index, key)| {
            SourceItem::new(
                source.clone(),
                revision,
                key.as_bytes(),
                TrustClass::Curated,
                format!("item {index} alpha beta gamma delta"),
            )
            .unwrap()
            .with_provenance(ItemProvenance {
                node_id: format!("crate:seal:node-{index}"),
                path: format!("crates/seal/src/node_{index}.rs"),
                source_class: SourceClass::Rust,
                scope_tags: vec!["scope:seal".to_owned()],
            })
        })
        .collect();
    let provenance: BTreeMap<KnowledgeItemId, ItemProvenance> = items
        .iter()
        .map(|item| (item.item_id, item.provenance.clone().unwrap()))
        .collect();
    (items, provenance)
}

/// Streams a small provenance-bearing generation into a fresh store. A
/// `postgres` bound before the stream seals the generation whole as part
/// of the stream's commit.
fn streamed(
    name: &str,
    postgres: Option<Arc<BrainPostgres>>,
) -> (
    PathBuf,
    IndexStore,
    IndexGeneration,
    usize,
    BTreeMap<KnowledgeItemId, ItemProvenance>,
) {
    let root =
        std::env::temp_dir().join(format!("odin-seal-consumer-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let store = IndexStore::open(&root).unwrap().with_postgres(postgres);
    let source = AtlasId::new("atlas:seal").unwrap();
    let revision = Digest::hash(b"stage1-seal");
    let (items, provenance) = items_with_provenance(&source, revision);
    let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
    let chunks = items
        .iter()
        .map(|item| chunker.chunk_item(item).unwrap().len())
        .sum();
    let mut stream = items
        .iter()
        .flat_map(|item| chunker.chunk_item(item).unwrap())
        .map(Ok);
    let (generation, outcome) = store
        .store_streaming(
            source,
            revision,
            &EmbeddingModelId::new(NO_EMBEDDING_MODEL).unwrap(),
            7,
            &mut stream,
            &provenance,
        )
        .unwrap();
    assert_eq!(outcome, StoreOutcome::Stored);
    (root, store, generation, chunks, provenance)
}

/// Reads one generation's SQLite chunk rows as copy batches (these builds
/// store no vectors).
fn cited_rows(store: &IndexStore, id: &IndexGenerationId) -> Vec<(CitedRow, Option<Vec<f32>>)> {
    let connection = store.lock_connection().unwrap();
    let mut statement = connection
        .prepare(
            "SELECT ordinal, chunk_id, item_id, trust, digest, text, byte_start, byte_end \
             FROM brain_index_chunk WHERE generation_id = ?1 ORDER BY ordinal",
        )
        .unwrap();
    statement
        .query_map(params![id.to_string()], |row| {
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
                None,
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Copies `rows` (and `provenance` when given) so the PostgreSQL row count
/// matches the generation exactly, and asserts the copy cannot seal: the
/// header stays absent, every unsealed row is dropped, and the unsealed
/// store keeps serving its SQLite rows.
#[allow(clippy::too_many_arguments)]
fn refused(
    cluster: &TestCluster,
    postgres: &BrainPostgres,
    store: &IndexStore,
    id: IndexGenerationId,
    model: &str,
    chunks: usize,
    rows: Vec<(CitedRow, Option<Vec<f32>>)>,
    provenance: Vec<ProvenanceRow>,
) {
    postgres.copy_cited(&id.to_string(), model, rows).unwrap();
    if !provenance.is_empty() {
        postgres
            .copy_provenance(&id.to_string(), provenance)
            .unwrap();
    }
    let id_string = id.to_string();
    let stored = psql(
        cluster,
        &format!("SELECT count(*) FROM brain_chunk WHERE generation_id = '{id_string}'"),
    );
    assert_eq!(
        stored,
        chunks.to_string(),
        "the copy reaches the exact stored count"
    );
    assert!(
        !store.seal(&id, None).unwrap(),
        "a matching count alone must not seal a forged copy"
    );
    assert_eq!(
        psql(cluster, "SELECT count(*) FROM brain_generation_header"),
        "0"
    );
    for table in ["brain_chunk", "brain_chunk_cite", "brain_item_provenance"] {
        assert_eq!(
            psql(
                cluster,
                &format!("SELECT count(*) FROM {table} WHERE generation_id = '{id_string}'")
            ),
            "0",
            "{table} rows of a refused copy are dropped"
        );
    }
    assert!(store.held(&[id]).unwrap().is_empty());
}

#[test]
fn a_reopened_store_serves_a_streamed_generation_from_postgres_alone() {
    let cluster = TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let (root, store, generation, chunks, provenance) =
        streamed("serve", Some(Arc::clone(&postgres)));
    let id = generation.generation_id;
    let model = generation.embedding_model.clone();

    // The stream sealed the generation whole in PostgreSQL.
    assert_eq!(store.held(&[id]).unwrap(), BTreeSet::from([id]));
    assert_eq!(
        psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
        "1"
    );

    let probe = [0_i64, 2, chunks as i64 - 1];
    let expected = store.chunks_at(&id, &probe).unwrap();

    // The SQLite generation is deleted under the sealed copy.
    {
        let connection = store.lock_connection().unwrap();
        connection
            .execute_batch(
                "DELETE FROM brain_index_chunk; \
                 DELETE FROM brain_index_item_provenance; \
                 DELETE FROM brain_index_generation;",
            )
            .unwrap();
        assert_eq!(
            connection
                .query_row("SELECT count(*) FROM brain_index_chunk", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    // A fresh store (no cached seal) serves it from PostgreSQL alone.
    let served = IndexStore::open(&root)
        .unwrap()
        .with_postgres(Some(postgres));
    assert_eq!(served.held(&[id]).unwrap(), BTreeSet::from([id]));
    assert_eq!(
        served
            .load_pinned(&id, &generation.atlas_id, &generation.atlas_revision)
            .unwrap(),
        generation
    );
    assert_eq!(
        served
            .current(&generation.atlas_id, &generation.atlas_revision)
            .unwrap(),
        Some(generation.clone())
    );
    assert_eq!(
        served
            .current_for_model(
                &generation.atlas_id,
                &generation.atlas_revision,
                Some(&model)
            )
            .unwrap(),
        Some(generation.clone())
    );
    assert_eq!(served.chunks_at(&id, &probe).unwrap(), expected);
    assert_eq!(served.chunk_count(&id).unwrap(), Some(chunks as u64));
    for (item_id, item_provenance) in &provenance {
        assert_eq!(
            served.provenance(&id, item_id).unwrap(),
            Some(item_provenance.clone())
        );
    }
    let ordinals = served
        .ordinals_for_items(&id, &provenance.keys().copied().collect::<BTreeSet<_>>())
        .unwrap();
    let mut seen = ordinals;
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        (0..chunks as i64).collect::<Vec<i64>>(),
        "every chunk is some item's ordinal"
    );

    // An item without a chunk stays typed NotFound, and a moved pin stays
    // typed StaleAuthority — the sealed header never mutes either gate.
    let stranger = SourceItem::identity(&generation.atlas_id, b"stranger-node").unwrap();
    assert!(matches!(
        served.provenance(&id, &stranger),
        Err(BrainError::NotFound {
            kind: "knowledge item",
            ..
        })
    ));
    assert!(matches!(
        served.load_pinned(&id, &generation.atlas_id, &Digest::hash(b"moved")),
        Err(BrainError::StaleAuthority { .. })
    ));
}

/// Matching counts do not validate content; incomplete provenance must be
/// copied before publication, while altered rows must be rejected and removed.
#[test]
fn a_matching_row_count_cannot_seal_forged_text_identity_or_provenance() {
    let cluster = TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let (_root, store, generation, chunks, provenance) = streamed("count", None);
    let id = generation.generation_id;
    let store = store.with_postgres(Some(Arc::clone(&postgres)));

    // Attached but unsealed, the store holds nothing and serves SQLite.
    assert!(store.held(&[id]).unwrap().is_empty());
    let baseline = store.chunks_at(&id, &[1]).unwrap();

    let model = generation.embedding_model.as_str();
    let rows = cited_rows(&store, &id);
    assert_eq!(rows.len(), chunks);
    assert!(rows.len() >= 2);

    let mut text = rows.clone();
    let original = text[1].0.text.clone();
    text[1].0.text = "x".repeat(original.len());
    refused(
        &cluster,
        &postgres,
        &store,
        id,
        model,
        chunks,
        text,
        Vec::new(),
    );

    let mut identity = rows.clone();
    identity[1].0.chunk_id =
        KnowledgeChunkId::new(Digest::hash(b"forged chunk identity")).to_string();
    refused(
        &cluster,
        &postgres,
        &store,
        id,
        model,
        chunks,
        identity,
        Vec::new(),
    );

    let mut trust = rows.clone();
    trust[1].0.trust = trust_bytes(TrustClass::Observed).to_owned();
    refused(
        &cluster,
        &postgres,
        &store,
        id,
        model,
        chunks,
        trust,
        Vec::new(),
    );

    let forged_provenance: Vec<ProvenanceRow> = provenance
        .keys()
        .map(|item_id| ProvenanceRow {
            item_id: item_id.to_string(),
            node_id: "crate:forged:node".to_owned(),
            path: "crates/forged/src/lib.rs".to_owned(),
            source_class: source_class_bytes(SourceClass::Rust).to_owned(),
            scope_tags: vec!["scope:forged".to_owned()],
        })
        .collect();
    refused(
        &cluster,
        &postgres,
        &store,
        id,
        model,
        chunks,
        rows,
        forged_provenance,
    );

    // A count-only copy of just the cited rows cannot end sealed short its
    // provenance: the seal completes the copy and proves it whole.
    postgres
        .copy_cited(&id.to_string(), model, cited_rows(&store, &id))
        .unwrap();
    assert!(store.seal(&id, None).unwrap());
    assert_eq!(
        psql(&cluster, "SELECT count(*) FROM brain_generation_header"),
        "1"
    );
    assert_eq!(store.held(&[id]).unwrap(), BTreeSet::from([id]));
    assert_eq!(store.chunks_at(&id, &[1]).unwrap(), baseline);
    for (item_id, item_provenance) in &provenance {
        assert_eq!(
            store.provenance(&id, item_id).unwrap(),
            Some(item_provenance.clone())
        );
    }
}
