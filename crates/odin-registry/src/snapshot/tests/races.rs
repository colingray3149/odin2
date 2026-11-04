use std::fs;

use super::{commit_all, node_toml, CommittedFixture, TestDirectory};
use crate::snapshot::publication::PublicationLock;
use crate::snapshot::{PublicationOutcome, SnapshotError, SnapshotStore};

#[test]
fn publication_lock_excludes_other_holders_until_the_guard_drops() {
    let directory = TestDirectory::new();
    let store = SnapshotStore::new(directory.0.join("state/snapshot.json"));
    let lock_path = directory.0.join("state/.snapshot.json.publish.lock");
    let try_other_holder = || {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("lock file exists")
            .try_lock()
    };
    let first = PublicationLock::acquire(store.path()).expect("acquire lock");
    assert!(matches!(
        try_other_holder(),
        Err(fs::TryLockError::WouldBlock)
    ));
    drop(first);
    assert!(try_other_holder().is_ok());
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
