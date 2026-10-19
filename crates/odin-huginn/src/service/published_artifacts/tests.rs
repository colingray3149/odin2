use std::fs;
use std::path::Path;

use odin_domain::huginn::{BrowserSessionId, HuginnProtocolError, LiveSessionId};
use odin_domain::{Digest, LaneId};

use super::publication::payload_name;
use super::{BrowserArtifactKind, FsPublishedArtifactStore};

fn render_session() -> LiveSessionId {
    LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9").expect("valid live session id")
}

fn browser_session() -> BrowserSessionId {
    BrowserSessionId::parse("00000000-0000-4000-8000-000000000008").expect("valid browser session")
}

fn open_store(root: &Path) -> FsPublishedArtifactStore {
    FsPublishedArtifactStore::open(
        root,
        render_session(),
        LaneId::new("lane:fixture-files").expect("valid file lane"),
        LaneId::new("lane:fixture-renders").expect("valid render lane"),
    )
    .expect("store opens")
}

fn fixture_bytes(seed: u8) -> Vec<u8> {
    vec![seed; 96]
}

fn dir_names(directory: &Path) -> Vec<String> {
    let mut names = fs::read_dir(directory)
        .expect("directory readable")
        .map(|entry| {
            entry
                .expect("entry readable")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn invalid_code(error: HuginnProtocolError) -> String {
    match error {
        HuginnProtocolError::InvalidRequest { code, .. } => code,
        other => panic!("expected invalid request error, got {other:?}"),
    }
}

#[test]
fn browser_artifacts_confine_files_to_the_store_root() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = open_store(root.path());
    let bytes = fixture_bytes(1);
    let digest = Digest::hash(&bytes);
    let display_name = "../payload-escape".to_owned();
    let first = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Download,
            display_name.clone(),
            "application/octet-stream".to_owned(),
            digest,
            bytes.clone(),
        )
        .expect("download publishes");
    let second = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Download,
            display_name,
            "application/octet-stream".to_owned(),
            digest,
            bytes,
        )
        .expect("republish is idempotent");
    assert_eq!(first.artifact_id, second.artifact_id);

    // Filesystem effects stay confined to digest- and identity-derived names.
    assert_eq!(
        dir_names(&root.path().join("payloads")),
        vec![payload_name(digest).expect("payload name")]
    );
    assert_eq!(
        dir_names(&root.path().join("records")),
        vec![format!("{}.cbor", first.artifact_id.as_str())]
    );
    assert!(dir_names(&root.path().join("browser-pointers")).is_empty());
    assert_eq!(
        dir_names(root.path()),
        vec!["browser-pointers", "payloads", "records"]
    );
    assert!(!root.path().join("payload-escape").exists());
}

#[test]
fn browser_publications_expose_nothing_before_success() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = open_store(root.path());

    let bytes = fixture_bytes(2);
    let error = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Frame,
            "frame.png".to_owned(),
            "image/png".to_owned(),
            Digest::hash(&fixture_bytes(3)),
            bytes.clone(),
        )
        .expect_err("digest mismatch must reject");
    assert_eq!(invalid_code(error), "publishedArtifactDigest");

    let error = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Timeline,
            "timeline.jsonl".to_owned(),
            "application/json".to_owned(),
            Digest::hash(&bytes),
            bytes,
        )
        .expect_err("timeline media guard must reject");
    assert_eq!(invalid_code(error), "publishedArtifactMedia");

    // Rejected publications never expose partial records, payloads, or pointers.
    assert!(dir_names(&root.path().join("payloads")).is_empty());
    assert!(dir_names(&root.path().join("records")).is_empty());
    assert!(dir_names(&root.path().join("browser-pointers")).is_empty());
}

#[test]
fn frame_retirement_defers_to_outbound_stream_leases() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = open_store(root.path());

    let first_bytes = fixture_bytes(4);
    let first = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Frame,
            "frame-first.png".to_owned(),
            "image/png".to_owned(),
            Digest::hash(&first_bytes),
            first_bytes.clone(),
        )
        .expect("first frame publishes");
    let lease = store
        .lease_browser_artifact(&first.artifact_id)
        .expect("current frame leases");

    let second_bytes = fixture_bytes(5);
    let second = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Frame,
            "frame-second.png".to_owned(),
            "image/png".to_owned(),
            Digest::hash(&second_bytes),
            second_bytes.clone(),
        )
        .expect("second frame publishes");
    assert_ne!(first.artifact_id, second.artifact_id);

    store
        .flush_browser_retirements()
        .expect("flush while leased");
    let retained = store
        .read(&first.artifact_id, u64::MAX)
        .expect("first frame read")
        .expect("replaced frame survives while leased");
    assert_eq!(retained.bytes, first_bytes);
    assert_eq!(retained.media_type, "image/png");
    assert!(root
        .path()
        .join("payloads")
        .join(payload_name(Digest::hash(&first_bytes)).expect("payload name"))
        .exists());

    let error = store
        .lease_browser_artifact(&first.artifact_id)
        .err()
        .expect("replaced frame must refuse new leases");
    assert_eq!(invalid_code(error), "browserArtifactLease");

    drop(lease);
    store
        .flush_browser_retirements()
        .expect("flush after lease release");
    assert!(store
        .read(&first.artifact_id, u64::MAX)
        .expect("first frame read")
        .is_none());
    assert!(!root
        .path()
        .join("payloads")
        .join(payload_name(Digest::hash(&first_bytes)).expect("payload name"))
        .exists());
    assert!(store
        .read(&second.artifact_id, u64::MAX)
        .expect("second frame read")
        .is_some());
}

#[test]
fn timeline_retirement_awaits_projection_acknowledgement() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = open_store(root.path());

    let first_bytes = b"{\"action\":\"navigate\"}\n".to_vec();
    let first_digest = Digest::hash(&first_bytes);
    let first = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Timeline,
            "browser-action-timeline.jsonl".to_owned(),
            "application/x-ndjson".to_owned(),
            first_digest,
            first_bytes,
        )
        .expect("first timeline publishes");
    let second_bytes = b"{\"action\":\"navigate\"}\n{\"action\":\"click\"}\n".to_vec();
    let second = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Timeline,
            "browser-action-timeline.jsonl".to_owned(),
            "application/x-ndjson".to_owned(),
            Digest::hash(&second_bytes),
            second_bytes,
        )
        .expect("second timeline publishes");
    assert_ne!(first.artifact_id, second.artifact_id);

    store
        .flush_browser_retirements()
        .expect("flush before acknowledgement defers");
    assert!(store
        .read(&first.artifact_id, u64::MAX)
        .expect("first timeline read")
        .is_some());

    store
        .acknowledge_browser_timeline(browser_session(), &second.artifact_id)
        .expect("acknowledgement accepts the current timeline");
    store
        .flush_browser_retirements()
        .expect("flush after acknowledgement retires");
    assert!(store
        .read(&first.artifact_id, u64::MAX)
        .expect("first timeline read")
        .is_none());
    assert!(!root
        .path()
        .join("payloads")
        .join(payload_name(first_digest).expect("payload name"))
        .exists());

    let error = store
        .acknowledge_browser_timeline(browser_session(), &first.artifact_id)
        .expect_err("stale timeline must not acknowledge");
    assert_eq!(invalid_code(error), "browserTimelineAcknowledgement");
}

#[test]
fn retirement_failures_surface_and_recover_truthfully() {
    let root = tempfile::tempdir().expect("temporary root");
    let store = open_store(root.path());

    let first_bytes = fixture_bytes(6);
    let first = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Frame,
            "frame-first.png".to_owned(),
            "image/png".to_owned(),
            Digest::hash(&first_bytes),
            first_bytes,
        )
        .expect("first frame publishes");

    // A damaged record makes the pending frame retirement fail on the worker.
    fs::write(
        root.path().join("records").join("damaged.cbor"),
        b"not-a-record",
    )
    .expect("damaged record planted");

    let second_bytes = fixture_bytes(7);
    let second = store
        .publish_browser_artifact(
            browser_session(),
            BrowserArtifactKind::Frame,
            "frame-second.png".to_owned(),
            "image/png".to_owned(),
            Digest::hash(&second_bytes),
            second_bytes.clone(),
        )
        .expect("second frame publishes despite the damaged record");

    let error = store
        .flush_browser_retirements()
        .expect_err("retirement failure must surface");
    assert!(matches!(error, HuginnProtocolError::Unavailable { .. }));
    assert_eq!(
        store
            .flush_browser_retirements()
            .expect_err("failure stays latched"),
        error
    );

    fs::remove_file(root.path().join("records").join("damaged.cbor"))
        .expect("damaged record removed");
    // The flush that observes recovery still reports the latched failure once.
    assert_eq!(
        store
            .flush_browser_retirements()
            .expect_err("recovery flush reports the latch"),
        error
    );
    store
        .flush_browser_retirements()
        .expect("flush after recovery succeeds");

    assert!(store
        .read(&first.artifact_id, u64::MAX)
        .expect("first frame read")
        .is_none());
    assert!(store
        .read(&second.artifact_id, u64::MAX)
        .expect("second frame read")
        .is_some());
    assert_eq!(
        dir_names(&root.path().join("payloads")),
        vec![payload_name(Digest::hash(&second_bytes)).expect("payload name")]
    );
}
