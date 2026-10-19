use std::fs;

use super::{commit_all, node_toml, CommittedFixture};
use crate::snapshot::{SnapshotError, SnapshotHandle};

#[test]
fn committed_publisher_handle_restarts_and_pins_across_reload() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true), ("beta", false)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    let handle = SnapshotHandle::open(fixture.store.clone()).expect("open handle");
    let mut revisions = handle.subscribe();
    handle.reload().expect("unchanged publication");
    assert!(!revisions.has_changed().unwrap());
    let pinned = handle.current();
    assert_eq!(pinned.revision, 1);
    assert_eq!(pinned.objects.len(), 4);

    fs::remove_file(fixture.worktree.join("registry/nodes/beta/node.toml")).unwrap();
    fs::remove_dir(fixture.worktree.join("registry/nodes/beta")).unwrap();
    let second_commit = commit_all(&fixture.worktree, "remove beta");
    let second = fixture.candidate(&second_commit);
    fixture
        .store
        .publish_committed(&second, 2)
        .expect("publish revision 2");

    // The pinned revision survives the reload untouched.
    let reloaded = handle.reload().expect("reload to revision 2");
    assert_eq!(reloaded.revision, 2);
    assert_eq!(pinned.revision, 1);
    assert_eq!(pinned.objects.len(), 4);
    assert_eq!(handle.current().revision, 2);
    assert!(revisions.has_changed().unwrap());
    assert_eq!(*revisions.borrow_and_update(), 2);
    handle.reload().expect("same publication remains current");
    assert!(!revisions.has_changed().unwrap());

    // Restart: a fresh handle pins the new active revision.
    drop(handle);
    let restarted = SnapshotHandle::open(fixture.store.clone()).expect("reopen handle");
    assert_eq!(restarted.current().revision, 2);
}

#[test]
fn committed_publisher_handle_rejects_regressed_reload() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");
    let first_active = fs::read(fixture.store.path()).unwrap();

    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("committed publisher fixture", "regression fixture"),
    )
    .unwrap();
    let second_commit = commit_all(&fixture.worktree, "change alpha");
    let second = fixture.candidate(&second_commit);
    fixture
        .store
        .publish_committed(&second, 2)
        .expect("publish revision 2");

    let handle = SnapshotHandle::open(fixture.store.clone()).expect("open handle");
    assert_eq!(handle.current().revision, 2);
    let revisions = handle.subscribe();

    // Valid retained revision files do not permit the active revision to move backward.
    fs::write(fixture.store.path(), &first_active).unwrap();
    let error = handle.reload().expect_err("regressed revision is rejected");
    assert!(matches!(error, SnapshotError::Invalid(_)));
    assert_eq!(handle.current().revision, 2);
    assert!(!revisions.has_changed().unwrap());
}

#[test]
fn publication_races_reader_pin_survives_concurrent_publish() {
    let (fixture, first_commit) = CommittedFixture::new(&[("alpha", true)]);
    let first = fixture.candidate(&first_commit);
    fixture
        .store
        .publish_committed(&first, 1)
        .expect("publish revision 1");

    fs::write(
        fixture.worktree.join("registry/nodes/alpha/node.toml"),
        node_toml("alpha", true).replace("committed publisher fixture", "second fixture"),
    )
    .unwrap();
    let second_commit = commit_all(&fixture.worktree, "second revision");
    let second = fixture.candidate(&second_commit);

    let handle = SnapshotHandle::open(fixture.store.clone()).expect("open handle");
    let pinned = handle.current();
    assert_eq!(pinned.revision, 1);

    let store = fixture.store.clone();
    let handle_ref = &handle;
    let pinned_ref = &pinned;
    std::thread::scope(|scope| {
        let publisher = scope.spawn(|| store.publish_committed(&second, 2));
        let reader = scope.spawn(|| {
            // The request's pinned revision never changes under it.
            assert_eq!(pinned_ref.revision, 1);
            handle_ref.current().revision
        });
        publisher
            .join()
            .unwrap()
            .expect("concurrent publish of revision 2");
        let observed = reader.join().unwrap();
        assert!(observed == 1 || observed == 2);
    });

    assert_eq!(pinned.revision, 1);
    let reloaded = handle.reload().expect("reload after publish");
    assert_eq!(reloaded.revision, 2);
    assert_eq!(pinned.revision, 1);
}
