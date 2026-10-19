//! The restamped pending twin is sealed like a stored generation: both
//! restamp outcomes seal the twin (or defer the seal on a PostgreSQL
//! outage) before returning, so an unpublished twin is never SQLite-only —
//! the warm pump never visits a publication's pending generation.

use std::num::NonZeroU32;
use std::sync::Arc;

use odin_domain::knowledge::ids::{AtlasId, EmbeddingModelId};
use odin_domain::knowledge::retrieval::{IndexGeneration, TrustClass};
use odin_domain::Digest;

use super::{IndexStore, StoreOutcome};
use crate::index::build::{build_index, Chunker};
use crate::index::postgres::BrainPostgres;
use crate::postgres_test_cluster::TestCluster;
use crate::source::SourceItem;

fn psql(cluster: &TestCluster, sql: &str) -> String {
    let output = std::process::Command::new("psql")
        .args([&cluster.conninfo, "-tAc", sql])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A lexical-only generation whose restamped twin must end sealed.
fn stored(store: &IndexStore) -> IndexGeneration {
    let source = AtlasId::new("atlas:restamp").unwrap();
    let revision = Digest::hash(b"restamp-seal");
    let item = SourceItem::new(
        source.clone(),
        revision,
        b"pending-twin",
        TrustClass::Curated,
        "restamp this source alpha beta gamma delta",
    )
    .unwrap();
    let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
    let build = build_index(source, revision, &[item], &chunker).unwrap();
    assert_eq!(store.store(&build, 7).unwrap(), StoreOutcome::Stored);
    build.generation
}

#[test]
fn a_restamped_pending_twin_is_sealed_on_both_outcomes() {
    let cluster = TestCluster::start();
    let postgres = Arc::new(BrainPostgres::connect(&cluster.conninfo).unwrap());
    let root = std::env::temp_dir().join(format!("odin-restamp-seal-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let store = IndexStore::open(&root)
        .unwrap()
        .with_postgres(Some(postgres.clone()));
    let base = stored(&store);
    let model = EmbeddingModelId::new("embedding:restamp-twin-v1").unwrap();

    let header_count = |generation: &IndexGeneration| -> String {
        psql(
            &cluster,
            &format!(
                "SELECT count(*) FROM brain_generation_header
                     WHERE generation_id = '{}'",
                generation.generation_id
            ),
        )
    };

    // First restamp: the twin is sealed before restamp returns.
    let (twin, outcome) = store
        .restamp_generation(&base.generation_id, &model, 9)
        .unwrap();
    assert_eq!(outcome, StoreOutcome::Stored);
    assert_ne!(twin.generation_id, base.generation_id);
    assert_eq!(
        header_count(&twin),
        "1",
        "the pending twin's header is published in the PostgreSQL store"
    );
    assert!(
        store
            .sealed_generation(&twin.generation_id)
            .unwrap()
            .is_some(),
        "this store holds the sealed twin"
    );
    assert!(
        store.load(&twin.generation_id).unwrap().is_some(),
        "the twin's SQLite rows are retained alongside the sealed copy"
    );

    // Make the resumed restamp real: drop the twin's published header and
    // reopen the store (empty sealed and verified caches) — exactly the
    // state after a seal that a PostgreSQL outage deferred.
    psql(
        &cluster,
        &format!(
            "DELETE FROM brain_generation_header WHERE generation_id = '{}'",
            twin.generation_id
        ),
    );
    assert_eq!(header_count(&twin), "0", "the twin is genuinely unsealed");
    let resumed = IndexStore::open(&root)
        .unwrap()
        .with_postgres(Some(postgres));

    // The AlreadyPresent outcome (the twin's rows and header already exist
    // in SQLite) must seal the unsealed twin before returning.
    let (again, outcome) = resumed
        .restamp_generation(&base.generation_id, &model, 10)
        .unwrap();
    assert_eq!(outcome, StoreOutcome::AlreadyPresent);
    assert_eq!(again.generation_id, twin.generation_id);
    assert_eq!(
        header_count(&again),
        "1",
        "the AlreadyPresent outcome re-seals an unsealed pending twin"
    );
    assert!(
        resumed
            .sealed_generation(&again.generation_id)
            .unwrap()
            .is_some(),
        "the resumed store holds the sealed twin"
    );

    std::fs::remove_dir_all(&root).ok();
}
