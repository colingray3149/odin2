//! Source-index behavioral tests: multibyte byte-budget chunk limits with
//! gapless coverage, and pinned-generation immutability/rebuild.

use std::num::NonZeroU32;

use odin_atlas::SourceClass;
use odin_brain::error::BrainError;
use odin_brain::index::{
    build_index, Chunker, IndexBuild, IndexStore, ItemProvenance, StoreOutcome,
};
use odin_brain::source::SourceItem;
use odin_domain::knowledge::ids::{AtlasId, KnowledgeItemId};
use odin_domain::knowledge::retrieval::TrustClass;
use odin_domain::Digest;

fn atlas() -> AtlasId {
    AtlasId::new("atlas:test").unwrap()
}

fn item(atlas: &AtlasId, revision: Digest, text: &str) -> SourceItem {
    SourceItem::new(
        atlas.clone(),
        revision,
        b"node:test",
        TrustClass::Curated,
        text,
    )
    .unwrap()
}

/// Asserts every chunk of `build` is an exact, valid byte slice of `text`
/// within the byte budget, self-consistent with its digest and citation, and
/// that the chunk ranges overlap or abut with strictly advancing starts.
fn assert_bounded_slices(build: &IndexBuild, text: &str, budget: usize) {
    assert!(!build.chunks.is_empty());
    let mut previous_start: Option<u64> = None;
    for chunk in &build.chunks {
        assert!(
            chunk.text.len() <= budget,
            "chunk of {} bytes exceeds the {budget}-byte budget: {:?}",
            chunk.text.len(),
            chunk.text
        );
        let start = chunk.citation.byte_start as usize;
        let end = chunk.citation.byte_end as usize;
        assert!(text.is_char_boundary(start));
        assert!(text.is_char_boundary(end));
        assert_eq!(&text[start..end], chunk.text);
        assert_eq!(end - start, chunk.text.len());
        assert_eq!(chunk.digest, Digest::hash(chunk.text.as_bytes()));
        assert!(
            previous_start.is_none_or(|previous| chunk.citation.byte_start > previous),
            "chunk starts must strictly advance"
        );
        previous_start = Some(chunk.citation.byte_start);
    }
}

/// Asserts the chunk ranges leave no gap (each start never passes the previous
/// end, first starts at 0, the last ends at the item's end) and that dropping
/// the overlap reconstructs the source text byte for byte.
fn assert_reconstructs_source(build: &IndexBuild, text: &str) {
    let mut rebuilt = String::new();
    let mut covered_to = 0_usize;
    for chunk in &build.chunks {
        let start = chunk.citation.byte_start as usize;
        let end = chunk.citation.byte_end as usize;
        assert!(
            start <= covered_to,
            "gap before chunk at byte {start}: previous coverage ends at {covered_to}"
        );
        if end > covered_to {
            rebuilt.push_str(&text[covered_to..end]);
            covered_to = end;
        }
    }
    assert_eq!(
        covered_to,
        text.len(),
        "chunks do not reach the end of the item"
    );
    assert_eq!(
        rebuilt, text,
        "overlap-dropped chunks do not reconstruct the item"
    );
}

#[test]
fn multibyte_chunks_never_exceed_the_byte_budget() {
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    // Mixed 1-, 2-, and 3-byte scalars with a window of 6 bytes: the old
    // forward end-snap emitted chunks over budget whenever a window edge
    // landed inside a scalar.
    let text = "naïve café — 東京タワー, déjà vu";
    let chunker = Chunker::new(NonZeroU32::new(6).unwrap(), 2).unwrap();
    let build = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, text)],
        &chunker,
    )
    .unwrap();
    assert!(build.chunks.len() > 1);
    assert_bounded_slices(&build, text, 6);
    assert_reconstructs_source(&build, text);

    // A window exactly one scalar wide stays at budget on every chunk.
    let cjk = "漢字漢字ab";
    let scalar_chunker = Chunker::new(NonZeroU32::new(3).unwrap(), 0).unwrap();
    let scalar_build = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, cjk)],
        &scalar_chunker,
    )
    .unwrap();
    assert_bounded_slices(&scalar_build, cjk, 3);
    assert_reconstructs_source(&scalar_build, cjk);
}

#[test]
fn mixed_utf8_reconstructs_the_source_with_zero_and_nonzero_overlap() {
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    // 1-, 2-, 3-, and 4-byte scalars; every window below must chunk it within
    // budget, without gaps, for both zero and nonzero overlap.
    let text = "a漢字bcé — déjà 東京タワー 🌍 z";
    for (window, overlap) in [
        (NonZeroU32::new(4).unwrap(), 0),
        (NonZeroU32::new(4).unwrap(), 1),
        (NonZeroU32::new(6).unwrap(), 2),
        (NonZeroU32::new(7).unwrap(), 3),
    ] {
        let chunker = Chunker::new(window, overlap).unwrap();
        let build = build_index(
            atlas.clone(),
            revision,
            &[item(&atlas, revision, text)],
            &chunker,
        )
        .unwrap();
        assert_bounded_slices(&build, text, window.get() as usize);
        assert_reconstructs_source(&build, text);
    }
}

#[test]
fn chunking_multibyte_text_is_deterministic() {
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let text = "漢字漢字漢字";
    let chunker = Chunker::new(NonZeroU32::new(3).unwrap(), 1).unwrap();
    let first = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, text)],
        &chunker,
    )
    .unwrap();
    let second = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, text)],
        &chunker,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_bounded_slices(&first, text, 3);
    assert_reconstructs_source(&first, text);
}

#[test]
fn window_smaller_than_one_scalar_fails_typed_never_over_budget() {
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let text = "漢字漢字";
    // A 2-byte window cannot hold a 3-byte scalar: typed policy failure
    // instead of an over-budget or empty chunk.
    let too_small = Chunker::new(NonZeroU32::new(2).unwrap(), 0).unwrap();
    let error = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, text)],
        &too_small,
    )
    .unwrap_err();
    assert!(matches!(error, BrainError::InvalidPolicy(_)));
    // The same budget is fine for text whose scalars fit: no spurious failure.
    let ascii = Chunker::new(NonZeroU32::new(1).unwrap(), 0).unwrap();
    let build = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, "abc")],
        &ascii,
    )
    .unwrap();
    assert_bounded_slices(&build, "abc", 1);
    assert_reconstructs_source(&build, "abc");
}

#[test]
fn rebuild_of_a_pinned_revision_is_identical_and_a_different_pin_is_a_new_generation() {
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let chunker = Chunker::new(NonZeroU32::new(8).unwrap(), 2).unwrap();
    let items = [item(&atlas, revision, "alpha beta gamma — 東京 delta")];
    let first = build_index(atlas.clone(), revision, &items, &chunker).unwrap();
    let rebuilt = build_index(atlas.clone(), revision, &items, &chunker).unwrap();
    assert_eq!(first, rebuilt);
    assert_eq!(
        first.generation.generation_id,
        rebuilt.generation.generation_id
    );
    assert_eq!(
        first.generation.manifest_digest,
        rebuilt.generation.manifest_digest
    );

    // Moving the pinned head (or pinning another source) is a new generation.
    let moved_revision = Digest::hash(b"r2");
    let moved = build_index(
        atlas.clone(),
        moved_revision,
        &[item(
            &atlas,
            moved_revision,
            "alpha beta gamma — 東京 delta",
        )],
        &chunker,
    )
    .unwrap();
    assert_ne!(
        first.generation.generation_id,
        moved.generation.generation_id
    );
    let other_atlas = AtlasId::new("atlas:else").unwrap();
    let other = build_index(
        other_atlas.clone(),
        revision,
        &[item(
            &other_atlas,
            revision,
            "alpha beta gamma — 東京 delta",
        )],
        &chunker,
    )
    .unwrap();
    assert_ne!(
        first.generation.generation_id,
        other.generation.generation_id
    );
}

#[test]
fn stored_generations_are_immutable_and_go_stale_when_the_head_moves() {
    let dir = tempfile::tempdir().unwrap();
    let store = IndexStore::open(dir.path()).unwrap();
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let chunker = Chunker::new(NonZeroU32::new(6).unwrap(), 2).unwrap();
    let build = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, "alpha beta 東京 gamma")],
        &chunker,
    )
    .unwrap();

    // Storing identical content again is an idempotent no-op, never an
    // overwrite or an error: the stored generation is immutable.
    store.store(&build, 1).unwrap();
    store.store(&build, 2).unwrap();

    // A rebuild round-trips through the store with verified content.
    let (loaded_generation, loaded_chunks) = store
        .load(&build.generation.generation_id)
        .unwrap()
        .expect("stored generation loads");
    assert_eq!(loaded_generation, build.generation);
    assert_eq!(loaded_chunks.len(), build.chunks.len());
    for (loaded, built) in loaded_chunks.iter().zip(&build.chunks) {
        assert_eq!(loaded.digest, built.digest);
        assert_eq!(loaded.text, built.text);
    }

    // The store serves the generation only under its pinned head revision.
    assert!(store.current(&atlas, &revision).unwrap().is_some());
    assert!(store
        .current(&atlas, &Digest::hash(b"r2"))
        .unwrap()
        .is_none());
}

/// Stores one build carrying Atlas node provenance and returns the store,
/// the build, and the indexed item's ID.
fn stored_provenance_build(root: &std::path::Path) -> (IndexStore, IndexBuild, KnowledgeItemId) {
    let store = IndexStore::open(root).unwrap();
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let chunker = Chunker::new(NonZeroU32::new(4).unwrap(), 0).unwrap();
    let item = item(&atlas, revision, "one two three four").with_provenance(ItemProvenance {
        node_id: "crate:demo:fn:add_one".to_owned(),
        path: "crates/demo/src/lib.rs".to_owned(),
        source_class: SourceClass::Rust,
        scope_tags: vec!["coding".to_owned()],
    });
    let build = build_index(atlas, revision, &[item], &chunker).unwrap();
    assert_eq!(store.store(&build, 0).unwrap(), StoreOutcome::Stored);
    let item_id = build.chunks[0].item_id;
    (store, build, item_id)
}

#[test]
fn provenance_is_persisted_round_trips_and_retires_with_the_generation() {
    let root = tempfile::tempdir().unwrap();
    let (store, build, item_id) = stored_provenance_build(root.path());
    assert_eq!(build.provenance.len(), 1);

    let provenance = store
        .provenance(&build.generation.generation_id, &item_id)
        .unwrap()
        .expect("an indexed Atlas item must carry its recorded provenance");
    assert_eq!(provenance.node_id, "crate:demo:fn:add_one");
    assert_eq!(provenance.path, "crates/demo/src/lib.rs");
    assert_eq!(provenance.source_class, SourceClass::Rust);
    assert_eq!(provenance.scope_tags, vec!["coding".to_owned()]);

    // An item the generation does not contain is typed NotFound, never a
    // fabricated answer, and the lookup verifies the generation first.
    let absent = KnowledgeItemId::new(Digest::hash(b"absent"));
    let error = store
        .provenance(&build.generation.generation_id, &absent)
        .unwrap_err();
    assert!(matches!(error, BrainError::NotFound { .. }));

    // Learning retirement drops the provenance together with the
    // generation; nothing is served from retired state.
    assert!(store.retire(&build.generation.generation_id).unwrap());
    assert!(store
        .provenance(&build.generation.generation_id, &item_id)
        .is_err());
}

#[test]
fn tampered_provenance_fails_verification_as_corruption() {
    let root = tempfile::tempdir().unwrap();
    let (store, build, item_id) = stored_provenance_build(root.path());

    // Rewrite one provenance field out-of-band: scope-enforcement data is
    // manifest-bound, so a tampered row must poison the whole generation
    // instead of serving forged brain:// scope evidence.
    let connection = rusqlite::Connection::open(root.path().join("brain-index.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE brain_index_item_provenance
             SET node_id = 'crate:evil:fn:escape'
             WHERE item_id = ?1",
            rusqlite::params![item_id.to_string()],
        )
        .unwrap();
    drop(connection);

    let error = store.load(&build.generation.generation_id).unwrap_err();
    assert!(
        matches!(error, BrainError::Corrupt { .. }),
        "tampered provenance must fail load as corruption, got {error:?}"
    );
    assert!(store
        .provenance(&build.generation.generation_id, &item_id)
        .is_err());
}

#[test]
fn a_write_while_another_process_holds_the_store_waits_instead_of_failing() {
    let dir = tempfile::tempdir().unwrap();
    let store = IndexStore::open(dir.path()).unwrap();
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    let chunker = Chunker::new(NonZeroU32::new(6).unwrap(), 2).unwrap();
    let build = build_index(
        atlas.clone(),
        revision,
        &[item(&atlas, revision, "alpha beta gamma delta")],
        &chunker,
    )
    .unwrap();
    let other = rusqlite::Connection::open(dir.path().join("brain-index.sqlite3")).unwrap();
    other.execute_batch("BEGIN IMMEDIATE").unwrap();
    let holder = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        other.execute_batch("COMMIT").unwrap();
    });
    assert_eq!(store.store(&build, 1).unwrap(), StoreOutcome::Stored);
    holder.join().unwrap();
}

/// Two processes streaming generations into one store each keep their own
/// chunk stage: one never clears or mixes into the other's rows.
#[test]
fn concurrent_streaming_stores_never_share_a_chunk_stage() {
    let dir = tempfile::tempdir().unwrap();
    let first = IndexStore::open(dir.path()).unwrap();
    let second = IndexStore::open(dir.path()).unwrap();
    let atlas = atlas();
    let chunker = Chunker::new(NonZeroU32::new(4).unwrap(), 0).unwrap();
    let build_for = |seed: &[u8], text: &str| {
        let revision = Digest::hash(seed);
        build_index(
            atlas.clone(),
            revision,
            &[item(&atlas, revision, text)],
            &chunker,
        )
        .unwrap()
    };
    let outer = build_for(b"outer", "one two three four five six seven eight nine ten");
    let inner = build_for(b"inner", "red green blue cyan magenta yellow black white");
    assert!(outer.chunks.len() > 2);
    let model = outer.generation.embedding_model.clone();
    let mut fed = 0;
    let mut stream = outer.chunks.iter().cloned().map(|chunk| {
        fed += 1;
        if fed == 2 {
            let mut inner_stream = inner.chunks.iter().cloned().map(Ok);
            second
                .store_streaming(
                    atlas.clone(),
                    inner.generation.atlas_revision,
                    &model,
                    1,
                    &mut inner_stream,
                    &Default::default(),
                )
                .unwrap();
        }
        Ok(chunk)
    });
    let (generation, _) = first
        .store_streaming(
            atlas.clone(),
            outer.generation.atlas_revision,
            &model,
            1,
            &mut stream,
            &Default::default(),
        )
        .unwrap();
    assert_eq!(
        first.chunk_count(&generation.generation_id).unwrap(),
        Some(outer.chunks.len() as u64)
    );
    let (_, loaded) = first
        .load(&generation.generation_id)
        .unwrap()
        .expect("outer loads");
    assert!(loaded
        .iter()
        .zip(&outer.chunks)
        .all(|(l, b)| l.digest == b.digest));
}

/// Generations are insert-only, so a selection re-hashing every chunk on
/// every turn and warm round was pure cost (seconds per turn on the large
/// seat stores): a process verifies a generation once, later selections
/// read its proven header, a full load still verifies, and a fresh process
/// verifies again.
#[test]
fn a_selected_generation_is_verified_once_per_process() {
    let root = tempfile::tempdir().unwrap();
    let (store, build, _) = stored_provenance_build(root.path());
    let atlas = atlas();
    let revision = Digest::hash(b"r1");
    assert!(store.current(&atlas, &revision).unwrap().is_some());

    let connection = rusqlite::Connection::open(root.path().join("brain-index.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE brain_index_chunk SET text = 'forged' WHERE generation_id = ?1",
            rusqlite::params![build.generation.generation_id.to_string()],
        )
        .unwrap();
    drop(connection);

    assert!(
        store.current(&atlas, &revision).unwrap().is_some(),
        "a verified generation must not be re-hashed on every selection"
    );
    assert!(matches!(
        store.load(&build.generation.generation_id).unwrap_err(),
        BrainError::Corrupt { .. }
    ));
    let reopened = IndexStore::open(root.path()).unwrap();
    assert!(matches!(
        reopened.current(&atlas, &revision).unwrap_err(),
        BrainError::Corrupt { .. }
    ));
}

/// Retention keeps the served generation, anything newer, and the one just
/// before it; older ones are retired and their space reclaimed.
#[test]
fn retention_keeps_the_served_generation_newer_ones_and_one_previous() {
    let root = tempfile::tempdir().unwrap();
    let store = IndexStore::open(root.path()).unwrap();
    let atlas = atlas();
    let chunker = Chunker::new(NonZeroU32::new(4).unwrap(), 0).unwrap();
    let mut ids = Vec::new();
    for (index, revision) in [&b"r1"[..], b"r2", b"r3", b"r4", b"r5"]
        .into_iter()
        .enumerate()
    {
        let revision = Digest::hash(revision);
        let build = build_index(
            atlas.clone(),
            revision,
            &[item(&atlas, revision, "one two three")],
            &chunker,
        )
        .unwrap();
        store.store(&build, 100 * (index as u64 + 1)).unwrap();
        ids.push(build.generation.generation_id);
    }
    assert_eq!(store.retire_older(&atlas, &ids[3]).unwrap(), 2);
    store.reclaim().unwrap();
    let left: Vec<_> = store
        .list(Some(&atlas))
        .unwrap()
        .into_iter()
        .map(|generation| generation.generation_id)
        .collect();
    assert_eq!(left, vec![ids[4], ids[3], ids[2]]);
    assert_eq!(
        store
            .newest(&atlas, None, true)
            .unwrap()
            .map(|generation| generation.generation_id),
        Some(ids[4])
    );
}
