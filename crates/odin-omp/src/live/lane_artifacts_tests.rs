use super::*;
use futures_util::{FutureExt, StreamExt};
use odin_domain::huginn::{ArtifactKind, LiveSessionId, TransferId, TransferManifestInit};
use std::future::Future;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;

fn artifact(lane: &LaneId, id: u128) -> LaneArtifact {
    let session_id = LiveSessionId::parse("00000000-0000-4000-8000-000000000001").expect("session");
    let digest = odin_domain::Digest::hash(b"hello");
    let manifest = TransferManifest::new(TransferManifestInit {
        transfer_id: TransferId::parse(&Uuid::from_u128(id).to_string()).expect("transfer"),
        session_id,
        kind: ArtifactKind::File,
        direction: ArtifactDirection::SessionToDevice,
        display_name: "fixture.bin".to_owned(),
        media_type: "application/octet-stream".to_owned(),
        byte_len: 5,
        chunk_len: NonZeroU32::new(5).expect("nonzero"),
        content_digest: digest,
    })
    .expect("manifest");
    LaneArtifact {
        lane_id: lane.clone(),
        manifest,
        blob: BlobRef {
            session_id,
            epoch: odin_domain::huginn::SessionEpoch::new(1),
            kind: super::super::ledger::BlobKind::Transfer,
            digest,
            byte_len: 5,
        },
    }
}

fn fixture() -> (TempDir, FsLaneArtifactPort, LaneId, PathBuf) {
    let root = TempDir::new().expect("root");
    let port = FsLaneArtifactPort::open(root.path()).expect("port");
    let lane = LaneId::new("artifact-test").expect("lane");
    let directory = port.lane_dir(&lane, "egress");
    fs::create_dir_all(&directory).expect("egress");
    (root, port, lane, directory)
}

async fn next(stream: &mut LaneEgressStream) -> Result<LaneArtifact, LiveError> {
    tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("native notification")
        .expect("stream item")
}

#[tokio::test(start_paused = true)]
async fn idle_has_no_scans_or_worker_wakeups_and_delivery_resumes() {
    let (_root, _port, lane, directory) = fixture();
    let first = artifact(&lane, 1);
    persist_artifact(&directory, &first).expect("backlog");
    let (changed, receiver) = watch::channel(false);
    let (sender, mut output) = mpsc::channel(32);
    let scans = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&scans);
    let worker = deliver_artifacts(
        directory.clone(),
        lane.clone(),
        receiver,
        sender,
        move |directory, lane| {
            count.fetch_add(1, Ordering::SeqCst);
            scan_artifacts(directory, lane)
        },
    );
    let polls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&polls);
    let mut worker = Box::pin(worker);
    let task = tokio::spawn(std::future::poll_fn(move |cx| {
        count.fetch_add(1, Ordering::SeqCst);
        worker.as_mut().poll(cx)
    }));
    assert_eq!(
        output.recv().await.expect("backlog").expect("artifact"),
        first
    );
    tokio::task::yield_now().await;
    let idle_polls = polls.load(Ordering::SeqCst);
    for _ in 0..10 {
        tokio::time::advance(Duration::from_secs(360)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(scans.load(Ordering::SeqCst), 1);
    assert_eq!(polls.load(Ordering::SeqCst), idle_polls);
    let second = artifact(&lane, 2);
    persist_artifact(&directory, &second).expect("arrival after idle");
    changed.send_modify(|_| {});
    assert_eq!(
        output.recv().await.expect("arrival").expect("artifact"),
        second
    );
    assert_eq!(scans.load(Ordering::SeqCst), 2);
    drop(output);
    task.await.expect("worker exits on cancellation");
    assert!(changed.is_closed());
}

#[tokio::test]
async fn arrival_after_scan_snapshot_is_not_lost() {
    let (_root, _port, lane, directory) = fixture();
    let arrival = artifact(&lane, 1);
    let (changed, receiver) = watch::channel(false);
    let (sender, mut output) = mpsc::channel(32);
    let scans = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&scans);
    let published = arrival.clone();
    let task = tokio::spawn(deliver_artifacts(
        directory,
        lane,
        receiver,
        sender,
        move |directory, lane| {
            let snapshot = scan_artifacts(directory, lane)?;
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                persist_artifact(directory, &published)?;
                changed.send_modify(|_| {});
            }
            Ok(snapshot)
        },
    ));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), output.recv())
            .await
            .expect("second scan")
            .expect("item")
            .expect("artifact"),
        arrival
    );
    assert_eq!(scans.load(Ordering::SeqCst), 2);
    drop(output);
    task.await.expect("worker exits");
}

#[tokio::test]
async fn native_backlog_idle_atomic_rename_and_backpressured_burst() {
    let (_root, port, lane, directory) = fixture();
    let backlog = artifact(&lane, 1);
    persist_artifact(&directory, &backlog).expect("backlog");
    let mut stream = port.subscribe(&lane).await.expect("watch");
    assert_eq!(next(&mut stream).await.expect("backlog"), backlog);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err()
    );
    // More arrivals than the bounded output channel; the watcher cannot block on delivery.
    for id in 2..=70 {
        persist_artifact(&directory, &artifact(&lane, id)).expect("atomic arrival");
    }
    let mut delivered = BTreeSet::new();
    for _ in 2..=70 {
        let item = next(&mut stream).await.expect("burst artifact");
        assert!(
            delivered.insert(item.manifest.transfer_id.to_string()),
            "duplicate"
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn removal_is_observed_and_same_path_can_be_delivered_again() {
    let (_root, _port, lane, directory) = fixture();
    let item = artifact(&lane, 1);
    persist_artifact(&directory, &item).expect("backlog");
    let (changed, receiver) = watch::channel(false);
    let (sender, mut output) = mpsc::channel(32);
    let (scanned, mut scans) = mpsc::unbounded_channel();
    let task = tokio::spawn(deliver_artifacts(
        directory.clone(),
        lane,
        receiver,
        sender,
        move |directory, lane| {
            let result = scan_artifacts(directory, lane);
            scanned.send(()).expect("scan observer");
            result
        },
    ));
    output.recv().await.expect("first").expect("artifact");
    scans.recv().await.expect("first scan");
    fs::remove_file(directory.join(format!("{}.cbor", item.manifest.transfer_id))).expect("remove");
    changed.send_modify(|_| {});
    scans.recv().await.expect("removal scan");
    // The removal snapshot is already captured; even an immediate recreation is queued.
    persist_artifact(&directory, &item).expect("recreate");
    changed.send_modify(|_| {});
    assert_eq!(
        output.recv().await.expect("recreated").expect("artifact"),
        item
    );
    drop(output);
    task.await.expect("worker exits");
}

#[tokio::test]
async fn native_directory_removal_errors_and_resubscription_reads_recreated_backlog() {
    let (_root, port, lane, directory) = fixture();
    let item = artifact(&lane, 1);
    persist_artifact(&directory, &item).expect("backlog");
    let mut stream = port.subscribe(&lane).await.expect("watch");
    next(&mut stream).await.expect("backlog");
    fs::remove_dir_all(&directory).expect("remove directory");
    assert!(
        matches!(next(&mut stream).await, Err(LiveError::Unavailable { code })
        if code == "lane_artifact_filesystem" || code == "lane_artifact_watch")
    );
    assert!(stream.next().await.is_none());
    persist_artifact(&directory, &item).expect("recreated directory");
    let mut stream = port.subscribe(&lane).await.expect("new subscription");
    assert_eq!(next(&mut stream).await.expect("recreated backlog"), item);
}

#[tokio::test]
async fn coalesced_watcher_error_is_terminal_and_stream_drop_releases_watcher() {
    let (_root, _port, lane, directory) = fixture();
    let (changed, receiver) = watch::channel(false);
    observe_change(
        Err(notify::Error::generic("injected")),
        &directory,
        &changed,
    );
    observe_change(
        Ok(notify::Event::new(notify::EventKind::Any).add_path(directory.clone())),
        &directory,
        &changed,
    );
    let mut stream = artifact_stream(
        directory.clone(),
        lane.clone(),
        receiver,
        (),
        scan_artifacts,
    );
    assert!(
        matches!(next(&mut stream).await, Err(LiveError::Unavailable { code })
        if code == "lane_artifact_watch")
    );
    assert!(stream.next().await.is_none());

    struct WatcherDrop(Arc<AtomicUsize>);
    impl Drop for WatcherDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let (changed, receiver) = watch::channel(false);
    let stream = artifact_stream(
        directory,
        lane,
        receiver,
        WatcherDrop(Arc::clone(&drops)),
        scan_artifacts,
    );
    drop(stream);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(5), changed.closed())
        .await
        .expect("worker aborted");
}

#[test]
fn read_events_do_not_wake_the_scanner_but_rescan_requests_do() {
    let (changed, mut receiver) = watch::channel(false);
    let directory = Path::new("/lane/egress");
    observe_change(
        Ok(
            notify::Event::new(notify::EventKind::Access(notify::event::AccessKind::Any))
                .add_path(directory.to_path_buf()),
        ),
        directory,
        &changed,
    );
    assert!(!receiver.has_changed().expect("open"));
    observe_change(
        Ok(notify::Event::new(notify::EventKind::Any)
            .add_path(PathBuf::from("/lane/ingress/ignored.cbor"))),
        directory,
        &changed,
    );
    assert!(!receiver.has_changed().expect("unrelated ingress ignored"));
    let mut event = notify::Event::new(notify::EventKind::Other);
    event.attrs.set_flag(notify::event::Flag::Rescan);
    observe_change(Ok(event), directory, &changed);
    assert!(receiver
        .changed()
        .now_or_never()
        .expect("rescan wake")
        .is_ok());
}

#[test]
fn removed_lane_anchor_cannot_leave_a_silent_subscription() {
    let (changed, receiver) = watch::channel(false);
    observe_change(
        Ok(
            notify::Event::new(notify::EventKind::Remove(notify::event::RemoveKind::Folder))
                .add_path(PathBuf::from("/lane")),
        ),
        Path::new("/lane/egress"),
        &changed,
    );
    assert!(*receiver.borrow(), "removed watch anchor is terminal");
}

#[tokio::test]
async fn malformed_and_wrong_lane_records_still_fail_closed() {
    let (_root, port, lane, directory) = fixture();
    fs::write(directory.join("bad.cbor"), b"not cbor").expect("bad record");
    let mut stream = port.subscribe(&lane).await.expect("watch");
    assert!(
        matches!(next(&mut stream).await, Err(LiveError::Unavailable { code })
        if code == "lane_artifact_filesystem")
    );
    assert!(stream.next().await.is_none());
    fs::remove_file(directory.join("bad.cbor")).expect("remove bad record");
    persist_artifact(
        &directory,
        &artifact(&LaneId::new("other-lane").expect("lane"), 1),
    )
    .expect("wrong lane record");
    let mut stream = port.subscribe(&lane).await.expect("watch");
    assert!(
        matches!(next(&mut stream).await, Err(LiveError::Transfer { code, .. })
        if code == "lane_artifact_binding")
    );
}

#[tokio::test]
async fn burst_while_output_is_full_remains_pending_and_drop_cancels() {
    let (_root, _port, lane, directory) = fixture();
    persist_artifact(&directory, &artifact(&lane, 1)).expect("first");
    persist_artifact(&directory, &artifact(&lane, 2)).expect("second");
    let (changed, receiver) = watch::channel(false);
    let (sender, mut output) = mpsc::channel(1);
    let scans = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&scans);
    let task = tokio::spawn(deliver_artifacts(
        directory.clone(),
        lane.clone(),
        receiver,
        sender,
        move |directory, lane| {
            count.fetch_add(1, Ordering::SeqCst);
            scan_artifacts(directory, lane)
        },
    ));
    // The second send cannot finish until this receive; the first snapshot is fixed.
    output.recv().await.expect("first").expect("artifact");
    for id in 3..=40 {
        persist_artifact(&directory, &artifact(&lane, id)).expect("burst");
        changed.send_modify(|_| {});
    }
    for _ in 2..=40 {
        tokio::time::timeout(Duration::from_secs(5), output.recv())
            .await
            .expect("delivery")
            .expect("item")
            .expect("artifact");
    }
    assert_eq!(scans.load(Ordering::SeqCst), 2, "burst must coalesce");
    drop(output);
    task.await.expect("worker exits");

    let (changed, receiver) = watch::channel(false);
    let stream = artifact_stream(directory, lane, receiver, (), scan_artifacts);
    // Initial backlog is larger than channel capacity. Cancellation must not wait for drain.
    tokio::task::yield_now().await;
    drop(stream);
    tokio::time::timeout(Duration::from_secs(5), changed.closed())
        .await
        .expect("cancelled");
}

#[tokio::test]
async fn native_arrival_before_first_worker_poll_is_delivered() {
    let (_root, port, lane, directory) = fixture();
    let mut stream = port.subscribe(&lane).await.expect("armed subscription");
    let arrival = artifact(&lane, 1);
    persist_artifact(&directory, &arrival).expect("arrival before initial scan");
    assert_eq!(next(&mut stream).await.expect("artifact"), arrival);
}

#[tokio::test]
async fn native_replaced_directory_rearms_before_scanning_arrivals() {
    let (_root, port, lane, directory) = fixture();
    for id in 1..=40 {
        persist_artifact(&directory, &artifact(&lane, id)).expect("backlog");
    }
    let mut stream = port.subscribe(&lane).await.expect("watch");
    next(&mut stream).await.expect("initial snapshot");
    // The old snapshot exceeds channel capacity, so its scan cannot finish delivery
    // before replacement. Re-arm must cover both the replacement backlog and later writes.
    fs::remove_dir_all(&directory).expect("remove");
    let replacement = artifact(&lane, 100);
    persist_artifact(&directory, &replacement).expect("replacement backlog");
    for _ in 2..=40 {
        next(&mut stream).await.expect("old snapshot drains");
    }
    assert_eq!(next(&mut stream).await.expect("replacement"), replacement);
    let later = artifact(&lane, 101);
    persist_artifact(&directory, &later).expect("post-rearm arrival");
    assert_eq!(next(&mut stream).await.expect("later"), later);
}

async fn expect_anchor_failure(stream: &mut LaneEgressStream, replacement: &LaneArtifact) {
    tokio::time::timeout(Duration::from_secs(5), async {
        // A snapshot may win the race with the native callback, but the sticky
        // ancestor failure must still terminate rather than leave us pending.
        let terminal = match stream.next().await.expect("replacement or terminal error") {
            Ok(item) => {
                assert_eq!(&item, replacement);
                stream.next().await.expect("terminal error")
            }
            error => error,
        };
        assert!(matches!(
            terminal,
            Err(LiveError::Unavailable { code })
                if code == "lane_artifact_watch" || code == "lane_artifact_filesystem"
        ));
        assert!(stream.next().await.is_none(), "error must end subscription");
    })
    .await
    .expect("ancestor replacement cannot strand the stream");
}

#[tokio::test]
async fn native_root_and_higher_ancestor_rename_recreation_is_terminal() {
    // Cover root, its parent, and its grandparent both after a completed initial
    // snapshot and before the stream worker gets its first poll.
    for before_first_poll in [false, true] {
        for ancestor_depth in 0..=2 {
            let sandbox = TempDir::new().expect("sandbox");
            let port = FsLaneArtifactPort::open(sandbox.path().join("outer/state/artifacts"))
                .expect("port");
            let lane = LaneId::new("artifact-test").expect("lane");
            let directory = port.lane_dir(&lane, "egress");
            if !before_first_poll {
                persist_artifact(&directory, &artifact(&lane, 1)).expect("backlog");
            }
            let mut stream = port.subscribe(&lane).await.expect("watch");
            if !before_first_poll {
                assert_eq!(
                    next(&mut stream).await.expect("initial snapshot"),
                    artifact(&lane, 1)
                );
            }
            let anchor = port.root.ancestors().nth(ancestor_depth).expect("anchor");
            fs::rename(anchor, anchor.with_extension("old")).expect("rename anchor");
            let replacement = artifact(&lane, 2);
            persist_artifact(&directory, &replacement).expect("recreate and atomically publish");
            expect_anchor_failure(&mut stream, &replacement).await;
        }
    }
}

#[tokio::test]
async fn native_ancestor_replacement_during_watch_installation_is_terminal() {
    for ancestor_depth in 0..=2 {
        let sandbox = TempDir::new().expect("sandbox");
        let port =
            FsLaneArtifactPort::open(sandbox.path().join("outer/state/artifacts")).expect("port");
        let lane = LaneId::new("artifact-test").expect("lane");
        let directory = port.lane_dir(&lane, "egress");
        fs::create_dir_all(&directory).expect("egress");
        let anchor = port.root.ancestors().nth(ancestor_depth).expect("anchor");
        let replacement = artifact(&lane, 1);
        let (changed, receiver) = watch::channel(false);
        let observed = directory.clone();
        let mut watcher = notify::recommended_watcher(move |event| {
            observe_change(event, &observed, &changed);
        })
        .expect("native watcher");
        let mut replaced = false;
        watch_path_anchors(&directory, &mut |path| {
            watcher.watch(path, notify::RecursiveMode::NonRecursive)?;
            if Some(path) == anchor.parent() {
                // Move the subtree between installing its parent and its own
                // watch. Later registrations see only the replacement inodes.
                fs::rename(anchor, anchor.with_extension("old")).expect("rename during setup");
                persist_artifact(&directory, &replacement).expect("replacement publication");
                replaced = true;
            }
            Ok(())
        })
        .expect("watch anchors");
        assert!(replaced, "replacement must occur during watch installation");
        let mut stream = artifact_stream(directory, lane, receiver, watcher, scan_artifacts);
        expect_anchor_failure(&mut stream, &replacement).await;
    }
}

#[test]
fn anchor_watch_installation_is_root_first_and_fails_closed() {
    let (_root, _port, _lane, directory) = fixture();
    let mut expected = directory.ancestors().collect::<Vec<_>>();
    expected.reverse();
    let mut installed = Vec::new();
    watch_path_anchors(&directory, &mut |path| {
        installed.push(path.to_path_buf());
        Ok(())
    })
    .expect("all anchors");
    assert_eq!(installed, expected);
    for unavailable_anchor in expected {
        let mut attempted = Vec::new();
        assert!(watch_path_anchors(&directory, &mut |path| {
            attempted.push(path.to_path_buf());
            if path == unavailable_anchor {
                Err(notify::Error::generic("ancestor cannot be watched"))
            } else {
                Ok(())
            }
        })
        .is_err());
        assert_eq!(
            attempted.last().expect("attempted anchor"),
            unavailable_anchor
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_lane_or_egress_fails_explicitly() {
    for link_lane in [false, true] {
        let sandbox = TempDir::new().expect("sandbox");
        let port = FsLaneArtifactPort::open(sandbox.path().join("artifacts")).expect("port");
        let lane = LaneId::new("artifact-test").expect("lane");
        let target = sandbox.path().join("target");
        fs::create_dir_all(&target).expect("target");
        let directory = port.lane_dir(&lane, "egress");
        let link = if link_lane {
            directory.parent().expect("lane directory")
        } else {
            fs::create_dir_all(directory.parent().expect("lane directory")).expect("lane");
            directory.as_path()
        };
        std::os::unix::fs::symlink(&target, link).expect("symlink");
        let mut stream = port.subscribe(&lane).await.expect("native registration");
        assert!(matches!(
            next(&mut stream).await,
            Err(LiveError::Unavailable { code }) if code == "lane_artifact_watch"
        ));
        assert!(tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("terminal stream")
            .is_none());
    }
}
