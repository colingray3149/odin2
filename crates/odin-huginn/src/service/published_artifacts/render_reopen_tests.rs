//! Published artifacts survive restart; render job history does not.
//! Fixtures share a temporary root and no work runs detached from the test.

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::io::Write as _;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use odin_domain::huginn::{
    ArtifactRef, ContentSource, FileMediaPolicy, FileRoot, FileRootAccess, FileRootId,
    FileRootInit, FileWatchPolicy, HuginnProtocolError, LiveSessionId, RelativePath, RenderGateway,
    RenderId, RenderKind, RenderLimits, RenderManifest, RenderRequest, RenderState, RenderStatus,
    RendererId,
};
use odin_domain::{ArtifactId, CommandId, Digest, LaneId, SeatId};
use serde_json::Value;

use super::publication::payload_name;
use super::FsPublishedArtifactStore;
use crate::config::{FileLimits, RenderLimits as ServiceRenderLimits};
use crate::files::{BrowseEngine, RootCatalog};
use crate::renders::{
    CopyRenderer, FileRenderSource, HuginnRenderService, RenderInput, RenderPublisher, Renderer,
    RendererDescriptor, RendererRegistry, VerifiedRender,
};

const FOREIGN_NOTE: &str = "foreign-note.txt";
const FOREIGN_DIR: &str = "foreign-dir";
const COPY_RENDERER: &str = "builtin-png";
const GATED_RENDERER: &str = "fixture-gated";
const GENEROUS_TIMEOUT_SECONDS: i64 = 120;
const SHORT_TIMEOUT_MILLISECONDS: i64 = 300;

fn png_bytes(seed: u8) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
    bytes.extend((0..192_u8).map(|offset| seed.wrapping_add(offset)));
    bytes
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

fn snapshot(paths: &[&Path]) -> BTreeMap<String, Vec<u8>> {
    fn collect(path: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let metadata = fs::symlink_metadata(path).expect("fixture path stats");
        if metadata.is_dir() {
            out.insert(format!("{}/", path.display()), Vec::new());
            for entry in fs::read_dir(path).expect("fixture directory reads") {
                collect(&entry.expect("fixture entry").path(), out);
            }
        } else {
            out.insert(
                path.display().to_string(),
                fs::read(path).expect("fixture file reads"),
            );
        }
    }
    let mut out = BTreeMap::new();
    for path in paths {
        collect(path, &mut out);
    }
    out
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future)
        .await
        .expect("bounded wait elapsed")
}

fn render_limits(timeout: time::Duration, max_concurrent_renders: usize) -> ServiceRenderLimits {
    ServiceRenderLimits {
        timeout,
        max_concurrent_renders: NonZeroUsize::new(max_concurrent_renders)
            .expect("nonzero concurrency"),
        ..ServiceRenderLimits::default()
    }
}

fn generous_limits(max_concurrent_renders: usize) -> ServiceRenderLimits {
    render_limits(
        time::Duration::seconds(GENEROUS_TIMEOUT_SECONDS),
        max_concurrent_renders,
    )
}

fn request(
    command: &str,
    renderer: &str,
    source: ContentSource,
    max_output_bytes: u64,
) -> RenderRequest {
    RenderRequest {
        command_id: CommandId::new(command).expect("command id"),
        source,
        renderer: RendererId::parse(renderer).expect("renderer id"),
        renderer_version: "1".to_owned(),
        parameters: serde_json::json!({}),
        limits: RenderLimits {
            max_output_bytes: NonZeroU64::new(max_output_bytes).expect("nonzero output bound"),
            max_width_pixels: NonZeroU32::new(64).expect("nonzero width"),
            max_height_pixels: NonZeroU32::new(64).expect("nonzero height"),
            max_frames: NonZeroU32::new(1).expect("nonzero frames"),
        },
    }
}

fn png_descriptor(renderer: &str) -> RendererDescriptor {
    RendererDescriptor {
        renderer: RendererId::parse(renderer).expect("renderer id"),
        version: "1".to_owned(),
        accepted_media_types: vec!["image/png".to_owned()],
        output_kind: RenderKind::RasterImage,
        output_media_type: "image/png".to_owned(),
    }
}

fn copy_registry() -> RendererRegistry {
    let registry = RendererRegistry::new();
    registry
        .register(png_descriptor(COPY_RENDERER), Arc::new(CopyRenderer))
        .expect("copy renderer registers");
    registry
}

fn gated_registry(script: &Arc<Scripted>) -> RendererRegistry {
    let registry = copy_registry();
    let executor: Arc<dyn Renderer> = script.clone();
    registry
        .register(png_descriptor(GATED_RENDERER), executor)
        .expect("gated renderer registers");
    registry
}

#[derive(Clone, Copy)]
enum Behavior {
    HoldUntilCancelled,
}

/// Writes a partial staged output, announces entry, then holds or fails. The
/// hold never completes on its own: only cancellation (service timeout or
/// runtime shutdown) ends it, and `live` proves the future was dropped.
struct Scripted {
    behavior: Behavior,
    entered: tokio::sync::Semaphore,
    live: AtomicUsize,
}

impl Scripted {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            behavior,
            entered: tokio::sync::Semaphore::new(0),
            live: AtomicUsize::new(0),
        })
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    async fn wait_entered(&self) {
        within(self.entered.acquire())
            .await
            .expect("entry semaphore stays open")
            .forget();
    }
}

struct LiveGuard<'a>(&'a AtomicUsize);

impl<'a> LiveGuard<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Renderer for Scripted {
    async fn render(
        &self,
        input: RenderInput,
        _parameters: Value,
        _limits: RenderLimits,
        output: &Path,
    ) -> Result<(), HuginnProtocolError> {
        let _live = LiveGuard::enter(&self.live);
        drop(input);
        let mut partial = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(output)
            .map_err(|error| HuginnProtocolError::unavailable("fixture-output", error))?;
        partial
            .write_all(b"partial")
            .and_then(|()| partial.sync_all())
            .map_err(|error| HuginnProtocolError::unavailable("fixture-output", error))?;
        drop(partial);
        self.entered.add_permits(1);
        match self.behavior {
            Behavior::HoldUntilCancelled => {
                std::future::pending::<Result<(), HuginnProtocolError>>().await
            }
        }
    }
}

#[derive(Clone, Copy)]
enum PublishFault {
    LoseAcknowledgement,
}

struct FaultyPublisher {
    inner: FsPublishedArtifactStore,
    fault: PublishFault,
}

#[async_trait]
impl RenderPublisher for FaultyPublisher {
    async fn publish_render(
        &self,
        render: VerifiedRender,
    ) -> Result<ArtifactRef, HuginnProtocolError> {
        match self.fault {
            PublishFault::LoseAcknowledgement => {
                let _published = self.inner.publish_render(render).await?;
                Err(HuginnProtocolError::unavailable(
                    "fixtureAcknowledgementLost",
                    "the fixture drops the acknowledgement",
                ))
            }
        }
    }
}

/// One temporary directory owns the declared file root, the render staging
/// root, the artifact store root and every foreign sentinel.
struct Env {
    _base: tempfile::TempDir,
    declared: PathBuf,
    renders: PathBuf,
    artifacts: PathBuf,
    root_id: FileRootId,
    source_bytes: Vec<u8>,
}

impl Env {
    fn new() -> Self {
        let base = tempfile::tempdir().expect("temporary base");
        let path = base.path().canonicalize().expect("canonical base");
        let declared = path.join("declared");
        let renders = path.join("renders");
        let artifacts = path.join("artifacts");
        for directory in [&declared, &renders, &artifacts] {
            fs::create_dir(directory).expect("fixture directory");
        }
        let source_bytes = png_bytes(1);
        fs::write(declared.join("source.png"), &source_bytes).expect("source fixture");
        fs::write(
            declared.join("unrelated.txt"),
            b"unrelated declared-root file",
        )
        .expect("declared-root sentinel");
        fs::write(renders.join(FOREIGN_NOTE), b"foreign staging-root file")
            .expect("staging-root file sentinel");
        fs::create_dir_all(renders.join(FOREIGN_DIR).join("empty"))
            .expect("staging-root directory sentinel");
        fs::write(renders.join(FOREIGN_DIR).join("keep.bin"), b"foreign bytes")
            .expect("staging-root directory content");
        fs::write(
            artifacts.join("foreign-store-note.txt"),
            b"foreign store file",
        )
        .expect("store-root sentinel");
        Self {
            _base: base,
            declared,
            renders,
            artifacts,
            root_id: FileRootId::parse("fixture-root").expect("root id"),
            source_bytes,
        }
    }

    fn guarded(&self) -> BTreeMap<String, Vec<u8>> {
        let foreign_note = self.renders.join(FOREIGN_NOTE);
        let foreign_dir = self.renders.join(FOREIGN_DIR);
        let store_note = self.artifacts.join("foreign-store-note.txt");
        let source = self.declared.join("source.png");
        let unrelated = self.declared.join("unrelated.txt");
        snapshot(&[
            &foreign_note,
            &foreign_dir,
            &store_note,
            &source,
            &unrelated,
        ])
    }

    fn browse(&self) -> BrowseEngine {
        let root = FileRoot::new(FileRootInit {
            root_id: self.root_id.clone(),
            display_name: "Fixture".to_owned(),
            canonical_path: self.declared.clone(),
            access: FileRootAccess::ReadOnly,
            media_policy: FileMediaPolicy {
                allowed_media_types: vec!["image/png".to_owned()],
            },
            max_object_bytes: NonZeroU64::new(1 << 20).expect("nonzero"),
            watch_policy: FileWatchPolicy::Disabled,
            allowed_seats: vec![SeatId::new("colin").expect("seat id")],
            host: None,
            save_default: None,
        })
        .expect("declared root");
        BrowseEngine::new(
            Arc::new(RootCatalog::new(vec![root]).expect("unique root")),
            FileLimits::default(),
        )
    }

    fn source(&self, name: &str) -> ContentSource {
        ContentSource::File {
            root: self.root_id.clone(),
            relative: RelativePath::new(name).expect("relative path"),
            expected_revision: None,
        }
    }

    fn open_store(&self) -> FsPublishedArtifactStore {
        FsPublishedArtifactStore::open(
            &self.artifacts,
            LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9").expect("live session id"),
            LaneId::new("lane:fixture-files").expect("file lane"),
            LaneId::new("lane:fixture-renders").expect("render lane"),
        )
        .expect("store opens")
    }

    fn service(
        &self,
        publisher: Arc<dyn RenderPublisher>,
        registry: RendererRegistry,
        limits: ServiceRenderLimits,
    ) -> HuginnRenderService {
        HuginnRenderService::new(
            &self.renders,
            limits,
            registry,
            Arc::new(FileRenderSource::new(self.browse())),
            publisher,
        )
        .expect("render service starts")
    }

    fn staging_entries(&self) -> Vec<String> {
        dir_names(&self.renders)
            .into_iter()
            .filter(|name| name != FOREIGN_NOTE && name != FOREIGN_DIR)
            .collect()
    }

    fn leftover_parts(&self) -> Vec<PathBuf> {
        self.staging_entries()
            .into_iter()
            .map(|name| self.renders.join(name).join("output.part"))
            .filter(|part| part.exists())
            .collect()
    }

    fn store_listing(&self) -> (Vec<String>, Vec<String>) {
        (
            dir_names(&self.artifacts.join("records")),
            dir_names(&self.artifacts.join("payloads")),
        )
    }
}

async fn terminal(service: &HuginnRenderService, render_id: RenderId) -> RenderStatus {
    let mut stream = service.watch_render(render_id).await.expect("watch opens");
    within(async {
        while let Some(item) = stream.next().await {
            let status = item.expect("status item");
            if status.state.is_terminal() {
                return status;
            }
        }
        panic!("status stream ended before a terminal state");
    })
    .await
}

async fn complete(service: &HuginnRenderService, request: RenderRequest) -> RenderManifest {
    let accepted = service
        .request_render(request)
        .await
        .expect("render request accepted");
    let status = terminal(service, accepted.render_id).await;
    assert_eq!(
        status.state,
        RenderState::Completed,
        "diagnostic: {:?}",
        status.diagnostic
    );
    status
        .manifest
        .expect("completed status carries a manifest")
}

fn assert_refused<T>(result: Result<T, HuginnProtocolError>, what: &str) {
    match result {
        Ok(_) => panic!("{what}: a vanished render job must be refused, not answered"),
        Err(HuginnProtocolError::NotFound { .. } | HuginnProtocolError::Unavailable { .. }) => {}
        Err(other) => {
            panic!("{what}: expected a typed NotFound/Unavailable refusal, got {other:?}")
        }
    }
}

fn remove_staged_dir(env: &Env, render_id: RenderId) {
    match fs::remove_dir_all(env.renders.join(render_id.to_string())) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("owned staging directory must be removable: {error}"),
    }
}

// Positive control: durable bytes outlive both the service and the store.
#[tokio::test]
async fn published_render_artifact_outlives_service_and_store_reconstruction() {
    let env = Env::new();
    let guarded = env.guarded();
    let expected = env.source_bytes.clone();

    let store = env.open_store();
    let service = env.service(Arc::new(store.clone()), copy_registry(), generous_limits(2));
    let first = complete(
        &service,
        request(
            "cmd-reopen-1",
            COPY_RENDERER,
            env.source("source.png"),
            1 << 20,
        ),
    )
    .await;
    assert_eq!(first.content_digest, Digest::hash(&expected));
    assert_eq!(
        first.byte_len,
        u64::try_from(expected.len()).expect("fixture length")
    );

    // The durable copy must not alias the staged file the job owned.
    remove_staged_dir(&env, first.render_id);
    drop(service);
    drop(store);

    let reopened = env.open_store();
    let content = reopened
        .read(&first.artifact_id, u64::MAX)
        .expect("durable read")
        .expect("artifact survives reopen");
    assert_eq!(content.bytes, expected);
    assert_eq!(content.digest, first.content_digest);
    assert_eq!(content.media_type, "image/png");

    let rebuilt = env.service(
        Arc::new(reopened.clone()),
        copy_registry(),
        generous_limits(2),
    );
    assert_refused(rebuilt.render_status(first.render_id).await, "status");
    assert_refused(rebuilt.watch_render(first.render_id).await, "watch");

    // The old command id is not replayed as the old Completed result.
    let replay = rebuilt
        .request_render(request(
            "cmd-reopen-1",
            COPY_RENDERER,
            env.source("source.png"),
            1 << 20,
        ))
        .await
        .expect("replayed command is accepted as a new job");
    assert_ne!(replay.render_id, first.render_id);
    assert!(replay.manifest.is_none());
    let second = terminal(&rebuilt, replay.render_id).await;
    assert_eq!(second.state, RenderState::Completed);
    let second = second.manifest.expect("manifest");

    // Both artifacts stay readable over one content-addressed payload.
    for artifact_id in [&first.artifact_id, &second.artifact_id] {
        let content = reopened
            .read(artifact_id, u64::MAX)
            .expect("durable read")
            .expect("artifact readable");
        assert_eq!(content.bytes, expected);
    }
    assert_eq!(
        dir_names(&env.artifacts.join("payloads")),
        vec![payload_name(first.content_digest)]
    );
    assert_eq!(env.guarded(), guarded);
}

// A restart is modeled by dropping the runtime that owns the in-flight job.
async fn hold_until_timeout(
    env: &Env,
    script: &Arc<Scripted>,
) -> (HuginnRenderService, RenderId, RenderStatus) {
    let store = env.open_store();
    let service = env.service(
        Arc::new(store),
        gated_registry(script),
        render_limits(time::Duration::milliseconds(SHORT_TIMEOUT_MILLISECONDS), 1),
    );
    let accepted = service
        .request_render(request(
            "cmd-timeout-hold",
            GATED_RENDERER,
            env.source("source.png"),
            1 << 20,
        ))
        .await
        .expect("render request accepted");
    script.wait_entered().await;
    let status = terminal(&service, accepted.render_id).await;
    (service, accepted.render_id, status)
}

// A real timeout fails the job, cancels the renderer, releases its staging, publishes nothing and
// frees the single concurrency slot.
#[tokio::test]
async fn timed_out_render_fails_cancels_the_renderer_and_frees_its_slot() {
    let env = Env::new();
    let guarded = env.guarded();
    let script = Scripted::new(Behavior::HoldUntilCancelled);

    let (service, held, status) = hold_until_timeout(&env, &script).await;
    assert_eq!(status.state, RenderState::Failed);
    assert!(status.manifest.is_none());
    assert!(status.diagnostic.is_some());
    assert_eq!(
        script.live(),
        0,
        "the timed-out renderer future was cancelled, not detached"
    );
    assert!(
        env.leftover_parts().is_empty() && !env.staging_entries().contains(&held.to_string()),
        "a timed-out job released its owned partial output and staging"
    );
    let (records, payloads) = env.store_listing();
    assert!(records.is_empty(), "a timed-out render publishes no record");
    assert!(
        payloads.is_empty(),
        "a timed-out render publishes no payload"
    );

    // With one permit, this can only run if the timed-out job released it.
    let manifest = complete(
        &service,
        request(
            "cmd-timeout-follow",
            COPY_RENDERER,
            env.source("source.png"),
            1 << 20,
        ),
    )
    .await;
    assert_eq!(manifest.content_digest, Digest::hash(&env.source_bytes));
    assert_eq!(env.guarded(), guarded);
}

// Positive control: errors the job observes itself clean the staging it created.
// Unknown publish outcome: the artifact may have been published, so its
// durable evidence and the payload shared with an earlier artifact must stay.
#[tokio::test]
async fn lost_publish_acknowledgement_preserves_evidence_and_shared_payload() {
    let env = Env::new();
    let guarded = env.guarded();
    let expected = env.source_bytes.clone();
    let store = env.open_store();

    let good = env.service(Arc::new(store.clone()), copy_registry(), generous_limits(2));
    let first = complete(
        &good,
        request(
            "cmd-shared-1",
            COPY_RENDERER,
            env.source("source.png"),
            1 << 20,
        ),
    )
    .await;

    let faulty = env.service(
        Arc::new(FaultyPublisher {
            inner: store.clone(),
            fault: PublishFault::LoseAcknowledgement,
        }),
        copy_registry(),
        generous_limits(2),
    );
    let accepted = faulty
        .request_render(request(
            "cmd-shared-2",
            COPY_RENDERER,
            env.source("source.png"),
            1 << 20,
        ))
        .await
        .expect("render request accepted");
    let lost = terminal(&faulty, accepted.render_id).await;
    assert_eq!(lost.state, RenderState::Failed);
    assert!(lost.manifest.is_none());

    let first_record = format!("{}.cbor", first.artifact_id.as_str());
    let (records, payloads) = env.store_listing();
    assert!(records.contains(&first_record));
    let evidence = records
        .iter()
        .filter(|name| **name != first_record)
        .collect::<Vec<_>>();
    assert_eq!(
        evidence.len(),
        1,
        "the possibly-published record must stay as evidence"
    );
    let evidence_id = ArtifactId::new(
        evidence[0]
            .strip_suffix(".cbor")
            .expect("record file suffix"),
    )
    .expect("artifact id from record name");
    assert_eq!(payloads, vec![payload_name(first.content_digest)]);

    drop(good);
    drop(faulty);
    drop(store);
    let reopened = env.open_store();
    for artifact_id in [&first.artifact_id, &evidence_id] {
        let content = reopened
            .read(artifact_id, u64::MAX)
            .expect("durable read")
            .expect("artifact readable after reopen");
        assert_eq!(content.bytes, expected);
        assert_eq!(content.digest, first.content_digest);
    }
    assert_eq!(env.guarded(), guarded);
}

// A staging directory the job owns but cannot remove is a real, observable
// outcome of the job, not something silently dropped.
