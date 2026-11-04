//! Source-index behavioral tests: multibyte byte-budget chunk limits with
//! gapless coverage, and pinned-generation immutability/rebuild in the
//! PostgreSQL store.

use std::num::NonZeroU32;

use odin_brain::index::{build_index, Chunker, IndexBuild, IndexStore, StoreOutcome};
use odin_brain::source::SourceItem;
use odin_brain::test_cluster::TestCluster;
use odin_domain::knowledge::ids::AtlasId;
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

/// Every chunk of a stored generation, read back by ordinal.
fn stored_chunks(
    store: &IndexStore,
    build: &IndexBuild,
) -> Vec<odin_domain::knowledge::retrieval::IndexedChunk> {
    let ordinals: Vec<i64> = (0..build.chunks.len() as i64).collect();
    store
        .chunks_at(&build.generation.generation_id, &ordinals)
        .unwrap()
}

#[test]
fn stored_generations_are_immutable_and_current_only_under_their_pinned_head() {
    let cluster = TestCluster::start();
    let dir = tempfile::tempdir().unwrap();
    let store = IndexStore::open(dir.path(), cluster.store()).unwrap();
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
    assert_eq!(store.store(&build, 1).unwrap(), StoreOutcome::Stored);
    assert_eq!(
        store.store(&build, 2).unwrap(),
        StoreOutcome::AlreadyPresent
    );
    assert_eq!(stored_chunks(&store, &build), build.chunks);

    // The store serves the generation only under its pinned head revision.
    assert!(store.current(&atlas, &revision).unwrap().is_some());
    assert!(store
        .current(&atlas, &Digest::hash(b"r2"))
        .unwrap()
        .is_none());
}

/// Two stores streaming generations at once each keep their own chunk
/// stage: one never clears or mixes into the other's rows.
#[test]
fn interleaved_streaming_stores_never_share_a_chunk_stage() {
    let cluster = TestCluster::start();
    let postgres = cluster.store();
    let dir = tempfile::tempdir().unwrap();
    let first = IndexStore::open(&dir.path().join("first"), postgres.clone()).unwrap();
    let second = IndexStore::open(&dir.path().join("second"), postgres).unwrap();
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
    assert_eq!(generation.generation_id, outer.generation.generation_id);
    assert_eq!(stored_chunks(&first, &outer), outer.chunks);
    assert_eq!(stored_chunks(&second, &inner), inner.chunks);
}

/// Retention keeps the served generation and anything newer; older ones
/// are retired.
#[test]
fn retention_keeps_the_served_generation_and_newer_ones() {
    let cluster = TestCluster::start();
    let root = tempfile::tempdir().unwrap();
    let store = IndexStore::open(root.path(), cluster.store()).unwrap();
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
    assert_eq!(store.retire_older(&atlas, &ids[3]).unwrap(), 3);
    let left: Vec<_> = store
        .list(Some(&atlas))
        .unwrap()
        .into_iter()
        .map(|generation| generation.generation_id)
        .collect();
    assert_eq!(left, vec![ids[4], ids[3]]);
    assert_eq!(
        store
            .newest(&atlas, None)
            .unwrap()
            .map(|generation| generation.generation_id),
        Some(ids[4])
    );
}
