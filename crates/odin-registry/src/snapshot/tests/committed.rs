use std::collections::BTreeSet;
use std::fs;

use super::{commit_all, commit_empty, git, node_toml, CommittedFixture, TestDirectory};
use crate::relational::AdmittedBinding;
use crate::schema::RegistryKind;
use crate::snapshot::contract::{merge_tombstones, ObjectRecord};
use crate::snapshot::{
    PublicationOutcome, PublicationReceipt, Snapshot, SnapshotError, SnapshotStore, Tombstone,
    ValidatedSnapshotCandidate, PUBLICATION_RECEIPT_SCHEMA,
};

#[test]
fn invalid_candidate_retains_active_snapshot() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish valid active snapshot");
    let before = fs::read(fixture.store.path()).unwrap();

    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        "schema = \"odin.registry.v1\"\nkind = \"node\"\n",
    )
    .unwrap();
    let invalid_commit = commit_all(&fixture.worktree, "invalid candidate");
    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &invalid_commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("invalid candidate must be rejected before publication");

    assert!(matches!(error, SnapshotError::Invalid(_)));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), before);
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("active retained")
            .revision,
        1
    );
}

#[test]
fn removal_appends_typed_tombstone_without_erasing_history() {
    let history = vec![Tombstone {
        kind: RegistryKind::Seat,
        id: "old-seat".to_owned(),
        removed_at_revision: 2,
        object_hash: "1".repeat(blake3::OUT_LEN * 2),
    }];
    let previous = vec![ObjectRecord {
        kind: RegistryKind::Project,
        id: "removed-project".to_owned(),
        hash: "2".repeat(blake3::OUT_LEN * 2),
    }];

    let tombstones = merge_tombstones(&history, &previous, &BTreeSet::new(), 3);

    assert_eq!(tombstones.len(), 2);
    assert_eq!(tombstones[0], history[0]);
    assert_eq!(tombstones[1].kind, RegistryKind::Project);
    assert_eq!(tombstones[1].id, "removed-project");
    assert_eq!(tombstones[1].removed_at_revision, 3);
    assert_eq!(tombstones[1].object_hash, previous[0].hash);
}

#[test]
fn committed_publisher_installs_versioned_snapshot_and_receipt() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let candidate = fixture.candidate(&commit);
    assert_eq!(candidate.commit(), commit);
    assert!(!candidate.tree().is_empty());

    let result = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish revision 1");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.schema, PUBLICATION_RECEIPT_SCHEMA);
    assert_eq!(result.receipt.revision, 1);
    assert_eq!(result.receipt.previous_revision, None);
    assert_eq!(result.receipt.commit, commit);

    let active = fs::read(fixture.store.path()).unwrap();
    assert_eq!(active, fs::read(fixture.versioned_snapshot(1)).unwrap());
    let stored_receipt: PublicationReceipt =
        serde_json::from_slice(&fs::read(fixture.versioned_receipt(1)).unwrap()).unwrap();
    assert_eq!(stored_receipt, result.receipt);

    let loaded = fixture.store.load_verified().expect("verified load");
    assert_eq!(loaded.revision, 1);
    assert_eq!(loaded.hash, stored_receipt.snapshot_hash);
    assert_eq!(loaded.objects.len(), 4);
    assert!(loaded
        .objects
        .iter()
        .any(|object| object.id == "alpha" && object.kind() == RegistryKind::Node));
}

#[test]
fn committed_publisher_reports_unchanged_for_identical_content() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    let first = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish revision 1");
    let active_before = fs::read(fixture.store.path()).unwrap();
    let receipt_before = fs::read(fixture.versioned_receipt(1)).unwrap();

    // Republishing the active publication's own commit is idempotent: the
    // immutable receipt's original provenance is returned and no new files
    // appear.
    let result = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("republish identical content");

    assert_eq!(result.outcome, PublicationOutcome::Unchanged);
    assert_eq!(result.receipt.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt, first.receipt);
    assert_eq!(result.receipt.revision, 1);
    assert_eq!(result.receipt.previous_revision, None);
    assert_eq!(result.receipt.commit, commit);
    assert_eq!(fs::read(fixture.store.path()).unwrap(), active_before);
    assert_eq!(
        fs::read(fixture.versioned_receipt(1)).unwrap(),
        receipt_before
    );
    assert!(!fixture.versioned_snapshot(2).exists());
}

#[test]
fn committed_publisher_advances_anchor_on_identical_content_from_direct_child() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    let published = fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");
    let receipt_before = fs::read(fixture.versioned_receipt(1)).unwrap();
    let snapshot_before = fs::read(fixture.versioned_snapshot(1)).unwrap();

    // A direct-child commit carrying the identical registry tree lawfully
    // advances the publication anchor to the next revision.
    let second_commit = commit_empty(&fixture.worktree, "same registry tree");
    assert_ne!(second_commit, first_commit);
    let second = fixture.candidate(&second_commit);
    assert_eq!(second.objects(), first.objects());
    assert!(second.parents().contains(&first_commit));

    // Identical content is published against the active revision: a
    // mismatched expectation is still stale, but naming the active
    // revision lets a direct child advance the anchor.
    assert!(matches!(
        fixture.store.publish_committed(&second, 3),
        Err(SnapshotError::Stale {
            expected: 3,
            active: Some(1)
        })
    ));

    let result = fixture
        .store
        .publish_committed(&second, 1)
        .expect("advance on identical content");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.schema, PUBLICATION_RECEIPT_SCHEMA);
    assert_eq!(result.receipt.revision, 2);
    assert_eq!(result.receipt.previous_revision, Some(1));
    assert_eq!(result.receipt.commit, second_commit);
    assert_eq!(result.receipt.tree, second.tree());

    let active = fixture.store.load_verified().expect("verified advance");
    assert_eq!(active.revision, 2);
    assert_eq!(active.objects, first.objects());
    assert_eq!(result.receipt.snapshot_hash, active.hash);
    assert_eq!(
        fs::read(fixture.store.path()).unwrap(),
        fs::read(fixture.versioned_snapshot(2)).unwrap()
    );

    // The superseded publication is untouched and the lineage stays
    // contiguous across the advancement.
    assert_eq!(
        fs::read(fixture.versioned_receipt(1)).unwrap(),
        receipt_before
    );
    assert_eq!(
        fs::read(fixture.versioned_snapshot(1)).unwrap(),
        snapshot_before
    );
    assert_eq!(published.receipt.commit, first_commit);
    let history = fixture
        .store
        .publication_history()
        .expect("contiguous publication history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].1.commit, first_commit);
    assert_eq!(history[1].1.commit, second_commit);
}

#[test]
fn committed_publisher_rejects_nonchild_identical_content() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");
    let active_before = fs::read(fixture.store.path()).unwrap();
    let receipt_before = fs::read(fixture.versioned_receipt(1)).unwrap();

    // An unrelated root commit carrying the identical tree is not a child
    // of the active publication: denied, and the store stays untouched.
    git(
        &fixture.worktree,
        &["checkout", "--orphan", "unrelated-line"],
    );
    let orphan_commit = commit_all(&fixture.worktree, "unrelated root with identical tree");
    assert_ne!(orphan_commit, first_commit);
    let orphan = fixture.candidate(&orphan_commit);
    assert!(orphan.parents().is_empty());

    let error = fixture
        .store
        .publish_committed(&orphan, 1)
        .expect_err("non-child identical content must be denied");
    assert!(matches!(
        error,
        SnapshotError::NonChild { expected_parent, commit, .. }
            if expected_parent == first_commit && commit == orphan_commit
    ));
    assert_eq!(fs::read(fixture.store.path()).unwrap(), active_before);
    assert_eq!(
        fs::read(fixture.versioned_receipt(1)).unwrap(),
        receipt_before
    );
    assert!(!fixture.versioned_snapshot(2).exists());
    assert!(!fixture.versioned_receipt(2).exists());
}

#[test]
fn committed_publisher_repairs_canonical_unreceipted_active_snapshot() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    let snapshot = Snapshot::build(1, candidate.objects().to_vec()).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&snapshot).unwrap();
    bytes.push(b'\n');
    fs::create_dir_all(fixture.store.path().parent().unwrap()).unwrap();
    fs::write(fixture.store.path(), &bytes).unwrap();
    assert!(fixture.store.load_verified().is_err());

    let result = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("authorized identical publish repairs missing sidecars");

    assert_eq!(result.outcome, PublicationOutcome::Unchanged);
    assert_eq!(result.receipt.revision, 1);
    assert_eq!(result.receipt.previous_revision, None);
    assert_eq!(result.receipt.commit, commit);
    assert_eq!(
        fixture.store.load_verified().expect("repaired store"),
        snapshot
    );
}

#[test]
fn committed_publisher_advances_revision_with_tombstones_across_restart() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    fs::remove_file(fixture.worktree.join("registry/nodes/beta/node.toml")).unwrap();
    fs::remove_dir(fixture.worktree.join("registry/nodes/beta")).unwrap();
    let second_commit = commit_all(&fixture.worktree, "remove beta");
    let second = fixture.candidate(&second_commit);
    let result = fixture
        .store
        .publish_committed(&second, 2)
        .expect("publish revision 2");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.revision, 2);
    assert_eq!(result.receipt.previous_revision, Some(1));

    // Restart: a fresh store read pins the immutable revision 2.
    let reloaded = fixture.store.load_verified().expect("restart load");
    assert_eq!(reloaded.revision, 2);
    assert_eq!(reloaded.objects.len(), 3);
    assert!(reloaded
        .tombstones
        .iter()
        .any(|tombstone| tombstone.id == "beta"
            && tombstone.kind == RegistryKind::Node
            && tombstone.removed_at_revision == 2));
}

#[test]
fn committed_publisher_rejects_dirty_worktree() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("control", "worker"),
    )
    .unwrap();

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("dirty worktree must be rejected");
    assert!(matches!(error, SnapshotError::DirtyWorktree { .. }));
}

#[test]
fn committed_publisher_rejects_untracked_registry_object() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let directory = fixture.worktree.join("registry/nodes/gamma");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("node.toml"), node_toml("gamma", false)).unwrap();

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("untracked registry object must be rejected");
    assert!(matches!(error, SnapshotError::DirtyWorktree { .. }));
}

#[test]
fn committed_publisher_rejects_ignored_files_under_registry() {
    let (fixture, _commit) = CommittedFixture::new(&[("alpha", true)]);
    fs::write(
        fixture.worktree.join(".gitignore"),
        "registry/scratch.txt\n",
    )
    .unwrap();
    fs::write(fixture.worktree.join("registry/scratch.txt"), b"scratch\n").unwrap();
    commit_all(&fixture.worktree, "ignore scratch");
    let ignored_commit = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    fs::write(fixture.worktree.join("registry/scratch.txt"), b"scratch\n").unwrap();

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &ignored_commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("ignored file under registry must be rejected");
    assert!(
        matches!(&error, SnapshotError::DirtyWorktree { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn committed_publisher_rejects_head_mismatch() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let other = "0".repeat(40);
    assert_ne!(other, commit);
    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &other,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("HEAD mismatch must be rejected");
    assert!(matches!(
        error,
        SnapshotError::HeadMismatch { expected, actual } if expected == other && actual == commit
    ));
}

#[test]
fn committed_publisher_rejects_malformed_expected_commit() {
    let (fixture, _commit) = CommittedFixture::new(&[("alpha", true)]);
    for malformed in ["main", "abcdef1", &"A".repeat(40), &"g".repeat(40)] {
        let error = ValidatedSnapshotCandidate::from_committed_worktree(
            &fixture.worktree,
            malformed,
            Vec::<AdmittedBinding>::new(),
        )
        .expect_err("malformed commit must be rejected");
        assert!(matches!(error, SnapshotError::Invalid(_)));
    }
}

#[test]
fn committed_publisher_rejects_invalid_committed_registry() {
    let (fixture, _commit) = CommittedFixture::new(&[("alpha", true)]);
    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        "schema = \"odin.registry.v1\"\nkind = \"node\"\n",
    )
    .unwrap();
    let bad_commit = commit_all(&fixture.worktree, "break the node");

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &bad_commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("invalid committed registry must be rejected");
    assert!(matches!(error, SnapshotError::Invalid(_)));
}

#[test]
fn committed_publisher_rejects_missing_kind_directory() {
    let directory = TestDirectory::new();
    let worktree = directory.0.join("worktree");
    fs::create_dir_all(&worktree).unwrap();
    git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
    let registry = worktree.join("registry");
    for kind in RegistryKind::ALL {
        if kind == RegistryKind::Host {
            continue;
        }
        let kind_directory = registry.join(kind.directory());
        fs::create_dir_all(&kind_directory).unwrap();
        fs::write(kind_directory.join(".gitkeep"), b"").unwrap();
    }
    let node = registry.join("nodes/alpha");
    fs::create_dir_all(&node).unwrap();
    fs::write(node.join("node.toml"), node_toml("alpha", true)).unwrap();
    fs::create_dir_all(worktree.join("schemas")).unwrap();
    fs::write(worktree.join("schemas/.gitkeep"), b"").unwrap();
    let commit = commit_all(&worktree, "registry without hosts");

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("missing kind directory must be rejected");
    assert!(
        matches!(&error, SnapshotError::Invalid(message) if message.contains("registry-kind-missing")),
        "unexpected error: {error}"
    );
}

#[test]
fn committed_publisher_rejects_stale_expected_revision() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);

    let error = fixture
        .store
        .publish_committed(&first, 2)
        .expect_err("first publication at revision 2 is stale");
    assert!(matches!(
        error,
        SnapshotError::Stale {
            expected: 2,
            active: None
        }
    ));

    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    // Identical content must name the active revision, not the next one.
    let error = fixture
        .store
        .publish_committed(&first, 2)
        .expect_err("unchanged content cannot claim the next revision");
    assert!(matches!(
        error,
        SnapshotError::Stale {
            expected: 2,
            active: Some(1)
        }
    ));

    // Changed content must advance: naming the occupied revision is stale.
    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("committed publisher fixture", "changed fixture"),
    )
    .unwrap();
    let second_commit = commit_all(&fixture.worktree, "change alpha");
    let second = fixture.candidate(&second_commit);
    let error = fixture
        .store
        .publish_committed(&second, 1)
        .expect_err("changed content cannot reuse the active revision");
    assert!(matches!(
        error,
        SnapshotError::Stale {
            expected: 1,
            active: Some(1)
        }
    ));
    fixture
        .store
        .publish_committed(&second, 2)
        .expect("changed content advances to revision 2");
}

#[test]
fn committed_publisher_occupied_revision_rejects_different_content() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    // Simulate the crash window: the versioned revision 1 file survives
    // but the active snapshot is gone. Different content for the same
    // revision is a conflict, never an overwrite.
    fs::remove_file(fixture.store.path()).unwrap();
    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("publisher fixture", "publisher changed fixture"),
    )
    .unwrap();
    let second_commit = commit_all(&fixture.worktree, "conflicting change");
    let second = fixture.candidate(&second_commit);
    let error = fixture
        .store
        .publish_committed(&second, 1)
        .expect_err("occupied revision rejects different content");
    assert!(matches!(error, SnapshotError::Conflict { revision: 1 }));

    // Retrying with the original content completes the interrupted install.
    let retry = fixture
        .store
        .publish_committed(&first, 1)
        .expect("identical retry completes the install");
    assert_eq!(retry.outcome, PublicationOutcome::Published);
    assert_eq!(retry.receipt.revision, 1);
    let restored = fixture.store.load_verified().expect("restored store");
    assert_eq!(restored.revision, 1);
}

#[test]
fn committed_publisher_load_verified_rejects_raw_sources() {
    let directory = TestDirectory::new();

    let missing = SnapshotStore::new(directory.0.join("missing/snapshot.json"));
    assert!(matches!(
        missing.load_verified(),
        Err(SnapshotError::Invalid(_))
    ));

    let raw_directory = SnapshotStore::new(directory.0.join("raw-registry"));
    fs::create_dir_all(raw_directory.path()).unwrap();
    assert!(raw_directory.load_verified().is_err());

    // A hand-written snapshot without immutable revision files is a raw
    // source, not a publication.
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish revision 1");

    let active_bytes = fs::read(fixture.store.path()).unwrap();
    let hand_written = SnapshotStore::new(directory.0.join("hand-written/snapshot.json"));
    fs::create_dir_all(hand_written.path().parent().unwrap()).unwrap();
    fs::write(hand_written.path(), &active_bytes).unwrap();
    assert!(matches!(
        hand_written.load_verified(),
        Err(SnapshotError::Invalid(_))
    ));

    // A diverged active file is not the immutable revision.
    fs::remove_file(fixture.versioned_receipt(1)).unwrap();
    assert!(matches!(
        fixture.store.load_verified(),
        Err(SnapshotError::Invalid(_))
    ));
}

#[test]
fn identical_publish_refuses_a_contradictory_receipt() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&first_commit), 1)
        .expect("publish revision 1");
    let second_commit = commit_empty(&fixture.worktree, "unrelated change");
    let receipt = fixture.versioned_receipt(1);
    let mut contradictory: PublicationReceipt =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    contradictory.snapshot_hash = "0".repeat(blake3::OUT_LEN * 2);
    fs::write(&receipt, serde_json::to_vec_pretty(&contradictory).unwrap()).unwrap();
    let active_before = fs::read(fixture.store.path()).unwrap();
    let receipt_before = fs::read(&receipt).unwrap();

    let error = fixture
        .store
        .publish_committed(&fixture.candidate(&second_commit), 1)
        .expect_err("a receipt that does not bind the active revision must refuse");

    assert!(matches!(error, SnapshotError::Invalid(_)), "{error:?}");
    assert_eq!(fs::read(fixture.store.path()).unwrap(), active_before);
    assert_eq!(fs::read(&receipt).unwrap(), receipt_before);
    assert!(!fixture.versioned_snapshot(2).exists());
}

#[test]
fn a_symlinked_immutable_revision_never_verifies() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&commit), 1)
        .expect("publish revision 1");
    let versioned = fixture.versioned_snapshot(1);
    fs::remove_file(&versioned).unwrap();
    std::os::unix::fs::symlink(fixture.store.path(), &versioned).unwrap();

    assert!(fixture.store.load_verified().is_err());
    assert!(fixture.store.publication_at(1).is_err());
    assert!(fixture.store.validate_retained_publication(1).is_err());
    assert!(fixture
        .store
        .publish_committed(&fixture.candidate(&commit), 1)
        .is_err());
}

#[test]
fn relations_read_the_committed_schema_bytes_not_the_worktree() {
    let (fixture, _) = CommittedFixture::new(&[("alpha", true)]);
    let schema = fixture.worktree.join("schemas/capability/probe.input.json");
    fs::create_dir_all(schema.parent().unwrap()).unwrap();
    fs::write(&schema, b"{}\n").unwrap();
    let commit = commit_all(&fixture.worktree, "schema without a dialect");
    git(
        &fixture.worktree,
        &[
            "update-index",
            "--skip-worktree",
            "schemas/capability/probe.input.json",
        ],
    );
    fs::write(
        &schema,
        b"{\"$schema\": \"https://json-schema.org/draft/2020-12/schema\"}\n",
    )
    .unwrap();
    assert_eq!(
        git(&fixture.worktree, &["status", "--porcelain=v1"]),
        "",
        "skip-worktree hides the edit from status"
    );

    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("the committed schema has no dialect");

    assert!(
        matches!(&error, SnapshotError::Invalid(message) if message.contains("schema-dialect")),
        "{error:?}"
    );
}

#[test]
fn runtime_projection_isolates_pending_registry_and_retains_active_schemas() {
    let (fixture, _) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    fs::write(
        fixture.worktree.join("schemas/retained.json"),
        b"{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}\n",
    )
    .unwrap();
    let anchor = commit_all(&fixture.worktree, "active retained schema");
    let initial = fixture.candidate(&anchor);
    fixture.store.publish_committed(&initial, 1).unwrap();
    let base = fixture.unpublished_change();
    let mutation = fixture.runtime_change("runtime alpha");
    let full = fixture.candidate(&mutation);
    let isolated = fixture.runtime_candidate(&mutation);
    assert_eq!(isolated.commit(), mutation);
    assert_eq!(isolated.tree(), full.tree());
    assert_eq!(isolated.parents(), &[base]);
    for object in initial
        .objects()
        .iter()
        .filter(|object| object.id != "alpha")
    {
        assert!(isolated.objects().contains(object));
    }
    assert_ne!(isolated.objects(), initial.objects());
    assert_ne!(isolated.objects(), full.objects());

    let published = fixture.store.publish_committed(&isolated, 2).unwrap();
    let projection = published.receipt.runtime_projection.as_ref().unwrap();
    assert_eq!(published.receipt.commit, mutation);
    assert_eq!(published.receipt.tree, full.tree());
    assert_eq!(
        git(
            &fixture.worktree,
            &["rev-parse", &format!("{}:schemas", projection.tree)]
        ),
        git(
            &fixture.worktree,
            &["rev-parse", &format!("{anchor}:schemas")]
        ),
    );
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        isolated.objects()
    );
    let active_before = fs::read(fixture.store.path()).unwrap();
    let receipt_before = fs::read(fixture.versioned_receipt(2)).unwrap();
    let replay_candidate = fixture.runtime_candidate(&mutation);
    let replay = fixture
        .store
        .publish_committed(&replay_candidate, 2)
        .unwrap();
    assert_eq!(replay.outcome, PublicationOutcome::Unchanged);
    assert_eq!(replay.receipt, published.receipt);
    assert_eq!(fs::read(fixture.store.path()).unwrap(), active_before);
    assert_eq!(
        fs::read(fixture.versioned_receipt(2)).unwrap(),
        receipt_before
    );
    assert!(!fixture.versioned_receipt(3).exists());

    let completion = fixture.store.publish_committed(&full, 3).unwrap();
    assert_eq!(completion.outcome, PublicationOutcome::Published);
    assert_eq!(completion.receipt.previous_revision, Some(2));
    assert_eq!(completion.receipt.commit, mutation);
    assert!(completion.receipt.runtime_projection.is_none());
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        full.objects()
    );
    assert_eq!(
        fs::read(fixture.versioned_receipt(2)).unwrap(),
        receipt_before
    );
}

#[test]
fn full_same_commit_completes_projection_even_when_objects_are_equal() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let mutation = fixture.runtime_change("runtime only");
    let isolated = fixture.runtime_candidate(&mutation);
    let full = fixture.candidate(&mutation);
    assert_eq!(isolated.objects(), full.objects());
    fixture.store.publish_committed(&isolated, 2).unwrap();
    let projected_receipt = fs::read(fixture.versioned_receipt(2)).unwrap();
    let result = fixture.store.publish_committed(&full, 2).unwrap();
    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt.revision, 3);
    assert_eq!(result.receipt.previous_revision, Some(2));
    assert_eq!(result.receipt.commit, mutation);
    assert!(result.receipt.runtime_projection.is_none());
    assert_eq!(fixture.store.load_verified().unwrap().revision, 3);
    assert_eq!(
        fs::read(fixture.versioned_receipt(2)).unwrap(),
        projected_receipt
    );
    let replay = fixture.store.publish_committed(&full, 3).unwrap();
    assert_eq!(replay.outcome, PublicationOutcome::Unchanged);
    assert_eq!(replay.receipt, result.receipt);
}

#[test]
fn successive_runtime_projections_reconstruct_after_git_prunes_effective_trees() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let initial = fixture.candidate(&anchor);
    fixture.store.publish_committed(&initial, 1).unwrap();
    fixture.unpublished_change();
    let first_commit = fixture.runtime_change("first runtime change");
    let first = fixture.runtime_candidate(&first_commit);
    let published = fixture.store.publish_committed(&first, 2).unwrap();
    let effective_tree = &published.receipt.runtime_projection.as_ref().unwrap().tree;
    git(&fixture.worktree, &["prune", "--expire=now"]);
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&fixture.worktree)
        .args(["cat-file", "-e", effective_tree])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "effective tree must actually be pruned"
    );
    let second_commit = fixture.runtime_change("second runtime change");
    let restarted = SnapshotStore::new(fixture.store.path());
    let second = restarted
        .runtime_candidate(
            &fixture.worktree,
            &second_commit,
            Vec::<AdmittedBinding>::new(),
        )
        .unwrap();
    for object in initial
        .objects()
        .iter()
        .filter(|object| object.id != "alpha")
    {
        assert!(second.objects().contains(object));
    }
    let result = restarted.publish_committed(&second, 3).unwrap();
    assert_eq!(result.receipt.previous_revision, Some(2));
    assert_eq!(result.receipt.commit, second_commit);
    assert!(result.receipt.runtime_projection.is_some());
    assert_eq!(restarted.load_verified().unwrap().objects, second.objects());
    assert_ne!(second.objects(), first.objects());
}

#[test]
fn legacy_publication_receipt_bytes_omit_projection_marker() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let result = fixture
        .store
        .publish_committed(&fixture.candidate(&commit), 1)
        .unwrap();
    let bytes = fs::read(fixture.versioned_receipt(1)).unwrap();
    let expected = format!(
        "{{\n  \"schema\": \"odin.registry-publication-receipt.v1\",\n  \"outcome\": \"published\",\n  \"revision\": 1,\n  \"previous_revision\": null,\n  \"commit\": \"{}\",\n  \"tree\": \"{}\",\n  \"snapshot_hash\": \"{}\"\n}}\n",
        result.receipt.commit, result.receipt.tree, result.receipt.snapshot_hash,
    );
    assert_eq!(bytes, expected.as_bytes());
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("runtime_projection").is_none());
    assert!(result.receipt.runtime_projection.is_none());
    let legacy: PublicationReceipt = serde_json::from_slice(&bytes).unwrap();
    let mut encoded = serde_json::to_vec_pretty(&legacy).unwrap();
    encoded.push(b'\n');
    assert_eq!(encoded, bytes);
    let mut marked = value;
    marked["runtime_projection"] =
        serde_json::json!({"tree": result.receipt.tree, "unknown": true});
    assert!(serde_json::from_value::<PublicationReceipt>(marked).is_err());
}

#[test]
fn runtime_projection_conflict_fails_before_publication() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    fixture.runtime_change("pending alpha deployment");
    let mutation = fixture.runtime_change("runtime overwrites pending alpha");
    let before = fs::read(fixture.store.path()).unwrap();
    let receipt = fs::read(fixture.versioned_receipt(1)).unwrap();
    let error = fixture
        .store
        .runtime_candidate(&fixture.worktree, &mutation, Vec::<AdmittedBinding>::new())
        .expect_err("delta cannot overwrite an unpublished change on the active base");
    assert!(
        matches!(&error, SnapshotError::Git { operation, .. } if *operation == "apply runtime delta"),
        "{error:?}"
    );
    assert_eq!(fs::read(fixture.store.path()).unwrap(), before);
    assert_eq!(fs::read(fixture.versioned_receipt(1)).unwrap(), receipt);
    assert!(!fixture.versioned_snapshot(2).exists());
    assert_eq!(git(&fixture.worktree, &["rev-parse", "HEAD"]), mutation);
}

#[test]
fn runtime_projection_cannot_rebind_to_another_store_at_the_same_revision() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let mutation = fixture.runtime_change("bound runtime mutation");
    let isolated = fixture.runtime_candidate(&mutation);
    let other = SnapshotStore::new(fixture._directory.0.join("other/snapshot.json"));
    other
        .publish_committed(&fixture.candidate(&mutation), 1)
        .unwrap();
    let before = fs::read(other.path()).unwrap();
    let error = other
        .publish_committed(&isolated, 1)
        .expect_err("same revision is not the candidate's bound active publication");
    assert!(matches!(error, SnapshotError::Invalid(_)), "{error:?}");
    assert_eq!(fs::read(other.path()).unwrap(), before);
    assert_eq!(other.load_verified().unwrap().revision, 1);
}

#[test]
fn fixed_descendant_can_cross_an_invalid_full_projection_anchor() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let beta = fixture.worktree.join("registry/nodes/beta/node.toml");
    fs::write(&beta, b"invalid = [unterminated").unwrap();
    commit_all(&fixture.worktree, "invalid pending deployment");
    let mutation = fixture.runtime_change("runtime mutation");
    fixture
        .store
        .publish_committed(&fixture.runtime_candidate(&mutation), 2)
        .unwrap();
    assert!(ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &mutation,
        Vec::<AdmittedBinding>::new(),
    )
    .is_err());
    fs::write(
        &beta,
        node_toml("beta", false).replace("committed publisher fixture", "fixed deployment"),
    )
    .unwrap();
    let repaired = commit_all(&fixture.worktree, "fix full anchor");
    let candidate = fixture.candidate(&repaired);
    let result = fixture.store.publish_committed(&candidate, 3).unwrap();
    assert_eq!(result.receipt.commit, repaired);
    assert!(result.receipt.runtime_projection.is_none());
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        candidate.objects()
    );
}

#[test]
fn runtime_projection_does_not_typed_decode_incompatible_historical_snapshots() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let legacy = super::migration::install_proven_legacy_publication(&fixture.store, 1);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 2)
        .unwrap();
    assert!(fixture.store.publication_history().is_err());
    fixture.store.validate_retained_publication(1).unwrap();
    fixture.unpublished_change();
    let first_commit = fixture.runtime_change("first post-migration runtime mutation");
    let first = fixture.runtime_candidate(&first_commit);
    fixture.store.publish_committed(&first, 3).unwrap();
    git(&fixture.worktree, &["prune", "--expire=now"]);
    let second_commit = fixture.runtime_change("second post-migration runtime mutation");
    let second = fixture.runtime_candidate(&second_commit);
    let result = fixture.store.publish_committed(&second, 4).unwrap();
    assert_eq!(result.receipt.previous_revision, Some(3));
    assert_eq!(result.receipt.commit, second_commit);
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        second.objects()
    );
    assert_eq!(fs::read(fixture.versioned_snapshot(1)).unwrap(), legacy);
    assert!(fixture.store.publication_history().is_err());
}
