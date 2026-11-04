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
        vec![payload_name(digest)]
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
        .join(payload_name(Digest::hash(&first_bytes)))
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
        .join(payload_name(Digest::hash(&first_bytes)))
        .exists());
    assert!(store
        .read(&second.artifact_id, u64::MAX)
        .expect("second frame read")
        .is_some());
}

#[test]
fn a_shared_payload_outlives_each_record_but_the_last() {
    let root = tempfile::tempdir().expect("temporary root");
    let other_session = BrowserSessionId::parse("00000000-0000-4000-8000-000000000009")
        .expect("valid browser session");
    let bytes = fixture_bytes(7);
    let payload = root
        .path()
        .join("payloads")
        .join(payload_name(Digest::hash(&bytes)));
    let store = open_store(root.path());
    let publish = |session| {
        store
            .publish_browser_artifact(
                session,
                BrowserArtifactKind::Frame,
                "frame.png".to_owned(),
                "image/png".to_owned(),
                Digest::hash(&bytes),
                bytes.clone(),
            )
            .expect("frame publishes")
    };
    let (first, second) = (publish(browser_session()), publish(other_session));
    assert_ne!(first.artifact_id, second.artifact_id);

    store
        .retire_browser_session(browser_session())
        .expect("first session retires");
    store.flush_browser_retirements().expect("flush");
    assert!(store
        .read(&first.artifact_id, u64::MAX)
        .expect("read")
        .is_none());
    let kept = store
        .read(&second.artifact_id, u64::MAX)
        .expect("read")
        .expect("the other session's frame still resolves");
    assert_eq!(kept.bytes, bytes);

    // Reopening counts the records on disk; recovery then retires the last frame, and its payload with it.
    drop(store);
    let reopened = open_store(root.path());
    reopened.flush_browser_retirements().expect("flush");
    assert!(reopened
        .read(&second.artifact_id, u64::MAX)
        .expect("read")
        .is_none());
    assert!(!payload.exists());
}
