use std::fs;
use std::sync::mpsc;
use std::time::Duration;

use super::{commit_all, node_toml, CommittedFixture, TestDirectory};
use crate::snapshot::publication::PublicationLock;
use crate::snapshot::{PublicationOutcome, SnapshotError, SnapshotStore};

#[test]
fn publication_races_interrupted_staging_file_never_claims_final_revision() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    let versioned = fixture.versioned_snapshot(1);
    let revisions = versioned.parent().unwrap();
    fs::create_dir_all(revisions).unwrap();
    let stale = revisions.join(format!(
        ".{}.stage.{}.0",
        versioned.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    fs::write(&stale, b"interrupted-partial-bytes").unwrap();

    let result = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("complete publication around stale staging file");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(fs::read(&stale).unwrap(), b"interrupted-partial-bytes");
    assert_eq!(
        fs::read(fixture.store.path()).unwrap(),
        fs::read(versioned).unwrap()
    );
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("verified store")
            .revision,
        1
    );
}

#[test]
fn publication_races_stale_active_swap_temp_cannot_block_publication() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    let parent = fixture.store.path().parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    let stale = parent.join(format!(".snapshot.json.tmp.{}.0", std::process::id()));
    fs::write(&stale, b"interrupted-active-swap").unwrap();

    let result = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish around stale active swap temp");

    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(fs::read(&stale).unwrap(), b"interrupted-active-swap");
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("verified store")
            .revision,
        1
    );
}

#[test]
fn publication_races_lock_serializes_publishers_until_guard_drop() {
    let directory = TestDirectory::new();
    let store = SnapshotStore::new(directory.0.join("state/snapshot.json"));
    let first = PublicationLock::acquire(store.path()).expect("acquire first lock");
    let (attempting_tx, attempting_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel();

    std::thread::scope(|scope| {
        scope.spawn(|| {
            attempting_tx.send(()).unwrap();
            let _second = PublicationLock::acquire(store.path()).expect("acquire second lock");
            acquired_tx.send(()).unwrap();
        });
        attempting_rx.recv().unwrap();
        assert!(
            acquired_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "second publisher acquired while first guard was live"
        );
        drop(first);
        acquired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second publisher acquired after first guard dropped");
    });
}

#[test]
fn publication_races_concurrent_identical_content_installs_revision_once() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    let store = fixture.store.clone();

    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| store.publish_committed(&candidate, 1));
        let right = scope.spawn(|| store.publish_committed(&candidate, 1));
        [left.join().unwrap(), right.join().unwrap()]
    });

    let mut published = 0;
    let mut unchanged = 0;
    for result in results {
        let receipt = result.expect("identical concurrent publications succeed");
        assert_eq!(receipt.receipt.revision, 1);
        match receipt.outcome {
            PublicationOutcome::Published => published += 1,
            PublicationOutcome::Unchanged => unchanged += 1,
        }
    }
    assert_eq!(published, 1, "exactly one publisher installs");
    assert_eq!(unchanged, 1, "the serialized follower is unchanged");

    let active = fixture.store.load_verified().expect("verified load");
    assert_eq!(active.revision, 1);
    assert_eq!(
        fs::read(fixture.store.path()).unwrap(),
        fs::read(fixture.versioned_snapshot(1)).unwrap()
    );
}

#[test]
fn publication_races_conflicting_content_has_exactly_one_winner() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);

    let second_worktree = fixture.worktree.clone();
    fs::write(
        second_worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("publisher fixture", "publisher changed fixture"),
    )
    .unwrap();
    let second_commit = commit_all(&second_worktree, "conflicting content");
    let second = fixture.candidate(&second_commit);
    let store = fixture.store.clone();

    let results = std::thread::scope(|scope| {
        let left = scope.spawn(|| store.publish_committed(&first, 1));
        let right = scope.spawn(|| store.publish_committed(&second, 1));
        [left.join().unwrap(), right.join().unwrap()]
    });

    let mut winners = 0;
    let mut stale_losers = 0;
    for result in results {
        match result {
            Ok(receipt) => {
                assert_eq!(receipt.outcome, PublicationOutcome::Published);
                assert_eq!(receipt.receipt.revision, 1);
                winners += 1;
            }
            Err(SnapshotError::Stale {
                expected: 1,
                active: Some(1),
            }) => stale_losers += 1,
            Err(other) => panic!("unexpected race error: {other}"),
        }
    }
    assert_eq!(winners, 1, "exactly one publisher installs revision 1");
    assert_eq!(stale_losers, 1, "the loser observes the active revision");
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("verified load")
            .revision,
        1
    );
}

#[test]
fn publication_races_delayed_revision_two_cannot_regress_revision_three() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    let node = fixture.worktree.join("registry/nodes/alpha/node.toml");
    fs::write(
        &node,
        node_toml("alpha", true).replace("committed publisher fixture", "second revision"),
    )
    .unwrap();
    let second_commit = commit_all(&fixture.worktree, "second revision");
    let delayed_second = fixture.candidate(&second_commit);
    fixture
        .store
        .publish_committed(&delayed_second, 2)
        .expect("publish revision 2");

    fs::write(
        &node,
        node_toml("alpha", true).replace("committed publisher fixture", "third revision"),
    )
    .unwrap();
    let third_commit = commit_all(&fixture.worktree, "third revision");
    let third = fixture.candidate(&third_commit);
    fixture
        .store
        .publish_committed(&third, 3)
        .expect("publish revision 3");
    let active_revision_three = fs::read(fixture.store.path()).unwrap();

    let error = fixture
        .store
        .publish_committed(&delayed_second, 2)
        .expect_err("delayed revision 2 publisher must not regress revision 3");
    assert!(matches!(
        error,
        SnapshotError::Stale {
            expected: 2,
            active: Some(3)
        }
    ));
    assert_eq!(
        fs::read(fixture.store.path()).unwrap(),
        active_revision_three
    );
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("revision 3 retained")
            .revision,
        3
    );
}

#[test]
fn publication_races_interrupted_install_completes_from_immutable_revision() {
    let (fixture, commit) = CommittedFixture::new(&[("alpha", true)]);
    let candidate = fixture.candidate(&commit);
    fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("publish revision 1");
    let versioned = fs::read(fixture.versioned_snapshot(1)).unwrap();

    // Crash window: the versioned revision and receipt survive; the
    // active swap never happened.
    fs::remove_file(fixture.store.path()).unwrap();
    assert!(fixture.store.load().unwrap().is_none());

    let receipt = fixture
        .store
        .publish_committed(&candidate, 1)
        .expect("retry completes the interrupted install");
    assert_eq!(receipt.outcome, PublicationOutcome::Published);
    assert_eq!(receipt.receipt.revision, 1);
    assert_eq!(fs::read(fixture.store.path()).unwrap(), versioned);
    assert_eq!(
        fixture
            .store
            .load_verified()
            .expect("verified load")
            .revision,
        1
    );
}

#[test]
fn projected_publication_retry_completes_staged_receipt_after_active_swap_crash() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let before = fs::read(fixture.store.path()).unwrap();
    fixture.unpublished_change();
    let mutation = fixture.runtime_change("runtime mutation");
    let candidate = fixture.runtime_candidate(&mutation);
    let published = fixture.store.publish_committed(&candidate, 2).unwrap();
    let snapshot = fs::read(fixture.versioned_snapshot(2)).unwrap();
    let receipt = fs::read(fixture.versioned_receipt(2)).unwrap();
    fs::write(fixture.store.path(), before).unwrap();

    let retried = fixture.runtime_candidate(&mutation);
    let result = fixture.store.publish_committed(&retried, 2).unwrap();
    assert_eq!(result.outcome, PublicationOutcome::Published);
    assert_eq!(result.receipt, published.receipt);
    assert_eq!(fs::read(fixture.versioned_snapshot(2)).unwrap(), snapshot);
    assert_eq!(fs::read(fixture.versioned_receipt(2)).unwrap(), receipt);
    assert_eq!(fs::read(fixture.store.path()).unwrap(), snapshot);
    assert_eq!(
        fixture.store.load_verified().unwrap().objects,
        candidate.objects()
    );
}

#[test]
fn staged_projection_receipt_cannot_be_replaced_by_equal_object_full_publication() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let before = fs::read(fixture.store.path()).unwrap();
    let mutation = fixture.runtime_change("runtime mutation");
    let projected = fixture.runtime_candidate(&mutation);
    let full = fixture.candidate(&mutation);
    assert_eq!(projected.objects(), full.objects());
    fixture.store.publish_committed(&projected, 2).unwrap();
    let snapshot = fs::read(fixture.versioned_snapshot(2)).unwrap();
    let receipt = fs::read(fixture.versioned_receipt(2)).unwrap();
    fs::write(fixture.store.path(), &before).unwrap();

    let error = fixture
        .store
        .publish_committed(&full, 2)
        .expect_err("equal objects do not authorize replacing staged projection provenance");
    assert!(
        matches!(error, SnapshotError::Conflict { revision: 2 }),
        "{error:?}"
    );
    assert_eq!(fs::read(fixture.store.path()).unwrap(), before);
    assert_eq!(fs::read(fixture.versioned_snapshot(2)).unwrap(), snapshot);
    assert_eq!(fs::read(fixture.versioned_receipt(2)).unwrap(), receipt);
    fixture.store.publish_committed(&projected, 2).unwrap();
    let completion = fixture.store.publish_committed(&full, 2).unwrap();
    assert_eq!(completion.receipt.revision, 3);
    assert!(completion.receipt.runtime_projection.is_none());
    assert_eq!(fixture.store.load_verified().unwrap().revision, 3);
}

#[test]
fn projected_candidate_rejects_advanced_active_base_without_overwriting_it() {
    let (fixture, anchor) = CommittedFixture::new(&[("alpha", true)]);
    fixture
        .store
        .publish_committed(&fixture.candidate(&anchor), 1)
        .unwrap();
    let mutation = fixture.runtime_change("runtime mutation");
    let projected = fixture.runtime_candidate(&mutation);
    fixture
        .store
        .publish_committed(&fixture.candidate(&mutation), 2)
        .unwrap();
    let before = fs::read(fixture.store.path()).unwrap();
    let receipt = fs::read(fixture.versioned_receipt(2)).unwrap();
    let error = fixture
        .store
        .publish_committed(&projected, 2)
        .expect_err("a completed full publication cannot be replaced by a stale projection");
    assert!(matches!(error, SnapshotError::Invalid(_)), "{error:?}");
    assert_eq!(fs::read(fixture.store.path()).unwrap(), before);
    assert_eq!(fs::read(fixture.versioned_receipt(2)).unwrap(), receipt);
    assert!(!fixture.versioned_receipt(3).exists());
}
