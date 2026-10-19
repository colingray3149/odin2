use std::fs;

use super::{CommittedFixture, TestDirectory};
use crate::snapshot::store::{revision_directory, versioned_receipt_path, versioned_snapshot_path};
use crate::snapshot::{
    PublicationOutcome, SnapshotBase, SnapshotError, SnapshotStore, PUBLICATION_RECEIPT_SCHEMA,
    SNAPSHOT_SCHEMA,
};

fn legacy_seat_snapshot(revision: u64) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "schema": SNAPSHOT_SCHEMA,
        "revision": revision,
        "hash": "a".repeat(blake3::OUT_LEN * 2),
        "objects": [{
            "id": "legacy-seat",
            "relative_config": "seats/legacy-seat/seat.toml",
            "config": {
                "object_type": "seat",
                "config": {
                    "schema": "odin.registry.v1",
                    "kind": "seat",
                    "enabled": true,
                    "legacy_aliases": ["old-tool"]
                }
            }
        }, {
            "id": "legacy-pod",
            "relative_config": "workloads/legacy-pod/profile.toml",
            "config": {
                "object_type": "workload",
                "config": {
                    "schema": "odin.registry.v1",
                    "kind": "workload",
                    "enabled": true,
                    "description": "current-shape workload object inside an old-shape base",
                    "image": { "reference": "registry.example.com/odin/demo:1@sha256:aaaa" },
                    "runtime": {
                        "launcher": "/odin/bin/omp",
                        "browser": "/odin/bin/chromium",
                        "supervisor": "/odin/bin/odind",
                        "playwright": "/odin/lib/playwright-core"
                    },
                    "seat": { "seat": "coordinator", "project": "demo", "gateway_lane": "demo-lane" },
                    "network": { "allow_hosts": ["example.com"] },
                    "display": { "xvfb": "/odin/bin/Xvfb", "screen": "1280x800x24", "stream": true },
                    "state": { "path": "/state/session", "storage": "2Gi" },
                    "export": { "pod_path": "/export", "host_folder": "/tmp/export" },
                    "brief": { "text": "legacy brief" },
                    "memory": { "namespace": "atlas.personal" },
                    "lifetime": { "deadline_seconds": 3600 }
                }
            }
        }, {
            "id": "legacy-routine",
            "relative_config": "routines/legacy-routine/routine.toml",
            "config": {
                "object_type": "routine",
                "config": { "schema": "odin.registry.v1", "kind": "routine", "enabled": true }
            }
        }]
    }))
    .unwrap()
}

/// Installs an incompatible active snapshot exactly the way a genuine older
/// publication leaves it: immutable revision file plus binding receipt, with
/// the active bytes identical to the immutable ones.
pub(super) fn install_proven_legacy_publication(store: &SnapshotStore, revision: u64) -> Vec<u8> {
    let legacy = legacy_seat_snapshot(revision);
    fs::create_dir_all(store.path().parent().unwrap()).unwrap();
    fs::write(store.path(), &legacy).unwrap();
    fs::create_dir_all(revision_directory(store.path())).unwrap();
    fs::write(versioned_snapshot_path(store.path(), revision), &legacy).unwrap();
    let receipt = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": PUBLICATION_RECEIPT_SCHEMA,
        "outcome": "published",
        "revision": revision,
        "previous_revision": revision.checked_sub(1),
        "commit": format!("{:040x}", revision),
        "tree": format!("{:040x}", revision + 1),
        "snapshot_hash": "a".repeat(blake3::OUT_LEN * 2),
    }))
    .unwrap();
    fs::write(versioned_receipt_path(store.path(), revision), receipt).unwrap();
    legacy
}

#[test]
fn incompatible_snapshot_is_archived_exactly_before_monotonic_migration() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let legacy = install_proven_legacy_publication(&fixture.store, 7);

    let archive_path = match fixture.store.base_for_update().unwrap() {
        SnapshotBase::Incompatible {
            revision,
            archive_path,
        } => {
            assert_eq!(revision, 7);
            archive_path
        }
        other => panic!("expected incompatible snapshot base, found {other:?}"),
    };
    let expected_digest = blake3::hash(&legacy).to_hex().to_string();
    assert_eq!(
        archive_path.file_name().unwrap(),
        format!("snapshot.json.{expected_digest}.archive").as_str()
    );

    let candidate = fixture.candidate(&commit);
    let result = fixture
        .store
        .publish_committed(&candidate, 8)
        .expect("migrate incompatible revision");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.revision, 8);
    assert_eq!(result.receipt.previous_revision, Some(7));
    assert_eq!(fs::read(&archive_path).unwrap(), legacy);
    let active = fixture.store.load_verified().expect("verified migration");
    assert_eq!(active.revision, 8);
    assert_eq!(active.objects, candidate.objects());
}

#[test]
fn failed_incompatible_publish_retains_active_and_does_not_clobber_archive() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let legacy = install_proven_legacy_publication(&fixture.store, 7);
    let SnapshotBase::Incompatible { archive_path, .. } = fixture.store.base_for_update().unwrap()
    else {
        panic!("expected incompatible snapshot base");
    };
    let candidate = fixture.candidate(&commit);

    assert!(matches!(
        fixture.store.publish_committed(&candidate, 7),
        Err(SnapshotError::Stale {
            expected: 7,
            active: Some(7)
        })
    ));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), legacy);
    assert!(!archive_path.exists());

    fs::write(&archive_path, b"occupied-by-different-bytes").unwrap();
    assert!(fixture.store.publish_committed(&candidate, 8).is_err());
    assert_eq!(fs::read(fixture.store.path()).unwrap(), legacy);
    assert_eq!(
        fs::read(&archive_path).unwrap(),
        b"occupied-by-different-bytes"
    );
}

#[test]
fn incompatible_migration_fails_closed_without_a_proven_prior_publication() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    fs::create_dir_all(fixture.store.path().parent().unwrap()).unwrap();
    let legacy = legacy_seat_snapshot(7);
    fs::write(fixture.store.path(), &legacy).unwrap();

    let candidate = fixture.candidate(&commit);
    assert!(matches!(
        fixture.store.publish_committed(&candidate, 8),
        Err(SnapshotError::Invalid(message))
            if message.contains("no immutable publication")
    ));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), legacy);
}

#[test]
fn incompatible_migration_fails_closed_when_active_diverges_from_its_immutable_revision() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let _legacy = install_proven_legacy_publication(&fixture.store, 7);
    let mut tampered: serde_json::Value = serde_json::from_slice(&legacy_seat_snapshot(7)).unwrap();
    tampered["hash"] = serde_json::Value::String("b".repeat(blake3::OUT_LEN * 2));
    let tampered_bytes = serde_json::to_vec_pretty(&tampered).unwrap();
    fs::write(fixture.store.path(), &tampered_bytes).unwrap();

    let candidate = fixture.candidate(&commit);
    assert!(matches!(
        fixture.store.publish_committed(&candidate, 8),
        Err(SnapshotError::Invalid(message))
            if message.contains("diverges from immutable revision 7")
    ));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), tampered_bytes);
}

#[test]
fn incompatible_migration_fails_closed_when_the_receipt_does_not_bind_the_base() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let legacy = install_proven_legacy_publication(&fixture.store, 7);
    let receipt_path = versioned_receipt_path(fixture.store.path(), 7);
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["snapshot_hash"] = serde_json::Value::String("c".repeat(blake3::OUT_LEN * 2));
    fs::write(&receipt_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();

    let candidate = fixture.candidate(&commit);
    assert!(matches!(
        fixture.store.publish_committed(&candidate, 8),
        Err(SnapshotError::Invalid(message))
            if message.contains("does not bind incompatible revision 7")
    ));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), legacy);
}

#[test]
fn corrupt_or_unknown_raw_snapshot_is_not_a_migration_base() {
    let directory = TestDirectory::new();
    let path = directory.0.join("snapshot.json");
    let store = SnapshotStore::new(&path);

    let mut unknown: serde_json::Value = serde_json::from_slice(&legacy_seat_snapshot(7)).unwrap();
    unknown["schema"] = serde_json::Value::String("unknown.snapshot.v1".to_owned());
    fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(store.base_for_update().is_err());

    unknown["schema"] = serde_json::Value::String(SNAPSHOT_SCHEMA.to_owned());
    unknown["objects"] = serde_json::json!([null]);
    fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(store.base_for_update().is_err());

    fs::write(&path, b"{not-json").unwrap();
    assert!(store.base_for_update().is_err());
}
