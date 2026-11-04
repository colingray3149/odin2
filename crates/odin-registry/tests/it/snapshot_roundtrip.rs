//! A snapshot of the shipped registry round-trips through the current types.

use std::path::Path;

use odin_registry::{parse_objects, walk, Snapshot};

#[test]
fn shipped_snapshot_round_trips() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let parsed = parse_objects(&walk(root.join("registry")).objects);
    assert!(!parsed.objects.is_empty(), "the shipped registry parses");

    let snapshot = Snapshot::build(1, parsed.objects.clone()).expect("snapshot builds");
    snapshot
        .verify()
        .expect("a fresh snapshot of the shipped registry verifies");
    let bytes = serde_json::to_vec(&snapshot).expect("snapshot serializes");
    let read_back: Snapshot = serde_json::from_slice(&bytes).expect("snapshot reads back");
    for (before, after) in snapshot.objects.iter().zip(&read_back.objects) {
        assert_eq!(
            serde_json::to_value(before).unwrap(),
            serde_json::to_value(after).unwrap(),
            "{} changed during its snapshot round trip",
            before.id
        );
    }
    read_back
        .verify()
        .expect("the serialized snapshot verifies after read-back");
}
