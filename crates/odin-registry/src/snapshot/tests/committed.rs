use std::collections::BTreeSet;
use std::fs;

use super::{commit_all, git, node_toml, CommittedFixture};
use crate::relational::AdmittedBinding;
use crate::schema::RegistryKind;
use crate::snapshot::contract::{merge_tombstones, ObjectRecord};
use crate::snapshot::{
    PublicationOutcome, PublicationReceipt, SnapshotError, Tombstone, ValidatedSnapshotCandidate,
    PUBLICATION_RECEIPT_SCHEMA,
};

#[test]
fn committed_discovery_allows_absent_compute_kinds_but_validates_present_entries() {
    let (fixture, _) = CommittedFixture::new(&[("alpha", true)]);
    for kind in [RegistryKind::ComputeProvider, RegistryKind::ComputeTarget] {
        fs::remove_dir_all(fixture.worktree.join("registry").join(kind.directory())).unwrap();
    }
    let commit = commit_all(&fixture.worktree, "omit optional compute kinds");
    fixture.candidate(&commit);

    fs::write(
        fixture.worktree.join("registry/compute-providers"),
        b"not a directory",
    )
    .unwrap();
    let invalid_commit = commit_all(&fixture.worktree, "invalid compute kind");
    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &invalid_commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("present optional kind must be a directory");
    assert!(
        matches!(&error, SnapshotError::Invalid(message) if message.contains("registry-kind-type")),
        "{error:?}"
    );

    fs::remove_file(fixture.worktree.join("registry/compute-providers")).unwrap();
    fs::remove_dir_all(fixture.worktree.join("registry/seats")).unwrap();
    let missing_commit = commit_all(&fixture.worktree, "omit required kind");
    let error = ValidatedSnapshotCandidate::from_committed_worktree(
        &fixture.worktree,
        &missing_commit,
        Vec::<AdmittedBinding>::new(),
    )
    .expect_err("required kind must remain required");
    assert!(
        matches!(&error, SnapshotError::Invalid(message) if message.contains("registry-kind-missing") && message.contains("seats")),
        "{error:?}"
    );
}

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
fn runtime_projection_accepts_change_already_present_in_active_tree() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let initial = fixture.candidate(&anchor);
    fixture.store.publish_committed(&initial, 1).unwrap();

    fixture.unpublished_change();
    fixture.runtime_change("unpublished alpha");
    let restored = fixture.runtime_change("committed publisher fixture");
    let candidate = fixture.runtime_candidate(&restored);
    assert_eq!(candidate.objects(), initial.objects());
    let published = fixture.store.publish_committed(&candidate, 1).unwrap();
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        initial.objects()
    );

    let replay = fixture.runtime_candidate(&restored);
    assert_eq!(
        fixture.store.publish_committed(&replay, 2).unwrap().receipt,
        published.receipt
    );
    let next = fixture.runtime_change("next runtime alpha");
    let next_candidate = fixture.runtime_candidate(&next);
    fixture.store.publish_committed(&next_candidate, 3).unwrap();
}

#[test]
fn runtime_projection_rejects_conflicting_unpublished_change() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    fixture.runtime_change("unpublished alpha");
    let mutation = fixture.runtime_change("different runtime alpha");
    let error = fixture
        .store
        .runtime_candidate(&fixture.worktree, &mutation, Vec::<AdmittedBinding>::new())
        .unwrap_err();
    assert!(error.to_string().contains("apply runtime delta"), "{error}");
}
