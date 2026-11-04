use super::*;
use futures_util::StreamExt;
use odin_domain::huginn::{ArtifactKind, LiveSessionId, TransferId, TransferManifestInit};
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
async fn malformed_and_wrong_lane_records_still_fail_closed() {
    let (_root, port, lane, directory) = fixture();
    fs::write(directory.join("bad.cbor"), b"not cbor").expect("bad record");
    let mut stream = port.subscribe(&lane).await.expect("watch");
    assert!(
        matches!(next(&mut stream).await, Err(LiveError::Unavailable { code, .. })
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
            Err(LiveError::Unavailable { code, .. }) if code == "lane_artifact_watch"
        ));
        assert!(tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("terminal stream")
            .is_none());
    }
}
