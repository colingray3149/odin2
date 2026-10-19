use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use super::ledger::{decode_cbor, encode_cbor, BlobRef};
use async_trait::async_trait;
use futures_core::Stream;
use notify::Watcher;
use odin_domain::huginn::{ArtifactDirection, LiveError, TransferManifest};
use odin_domain::LaneId;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

pub type LaneEgressStream =
    Pin<Box<dyn Stream<Item = Result<LaneArtifact, LiveError>> + Send + 'static>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneArtifact {
    pub lane_id: LaneId,
    pub manifest: TransferManifest,
    pub blob: BlobRef,
}

#[async_trait]
pub trait LaneArtifactPort: Send + Sync {
    async fn publish(&self, artifact: LaneArtifact) -> Result<(), LiveError>;
    async fn subscribe(&self, lane: &LaneId) -> Result<LaneEgressStream, LiveError>;
}

/// Durable lane records observed through native filesystem notifications.
/// Producers publish complete `.cbor` files by atomic rename. Subscriptions
/// scan once for backlog, then only on changes; filesystem/watch errors end
/// the stream rather than switching to polling. Dropping a stream disarms it.
/// Watches cover the canonical path from the filesystem root through `egress`,
/// installed root-first before the initial scan. Replacing any ancestor of
/// `egress` terminates the subscription; replacing `egress` itself is re-armed.
/// All ancestors must support native watches or subscription fails explicitly.
/// Symlinks in the supplied root are resolved once by `open`. Symlinks below
/// that canonical root are rejected so watch anchors cannot miss retargeting.
#[derive(Clone)]
pub struct FsLaneArtifactPort {
    root: Arc<PathBuf>,
    write_lock: Arc<Mutex<()>>,
}

impl FsLaneArtifactPort {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LiveError> {
        fs::create_dir_all(root.as_ref()).map_err(io_error)?;
        set_private_directory(root.as_ref())?;
        let root = root.as_ref().canonicalize().map_err(io_error)?;
        Ok(Self {
            root: Arc::new(root),
            write_lock: Arc::new(Mutex::new(())),
        })
    }

    fn lane_dir(&self, lane: &LaneId, direction: &str) -> PathBuf {
        self.root.join(lane.as_str()).join(direction)
    }
}

#[async_trait]
impl LaneArtifactPort for FsLaneArtifactPort {
    async fn publish(&self, artifact: LaneArtifact) -> Result<(), LiveError> {
        let _guard = self.write_lock.lock().await;
        let directory = self.lane_dir(&artifact.lane_id, "ingress");
        tokio::task::spawn_blocking(move || persist_artifact(&directory, &artifact))
            .await
            .map_err(|_| unavailable())?
    }

    async fn subscribe(&self, lane: &LaneId) -> Result<LaneEgressStream, LiveError> {
        if matches!(
            notify::RecommendedWatcher::kind(),
            notify::WatcherKind::PollWatcher | notify::WatcherKind::NullWatcher
        ) {
            return Err(watch_error(notify::Error::generic(
                "native watcher unavailable",
            )));
        }
        let directory = self.lane_dir(lane, "egress");
        fs::create_dir_all(&directory).map_err(io_error)?;
        set_private_directory(&directory)?;
        let (changed, receiver) = watch::channel(false);
        let observed = directory.clone();
        let mut watcher = notify::recommended_watcher(move |event| {
            observe_change(event, &observed, &changed);
        })
        .map_err(watch_error)?;
        watch_path_anchors(&directory, &mut |path| {
            watcher.watch(path, notify::RecursiveMode::NonRecursive)
        })
        .map_err(watch_error)?;
        let watcher = Arc::new(std::sync::Mutex::new(watcher));
        let scanner = Arc::downgrade(&watcher);
        Ok(artifact_stream(
            directory,
            lane.clone(),
            receiver,
            watcher,
            move |directory, lane| {
                // Re-arm BEFORE the snapshot. Native backends can lose a replaced
                // directory's watch; anything published before re-arm is in the scan.
                let watcher = scanner.upgrade().ok_or_else(watcher_unavailable)?;
                watcher
                    .lock()
                    .map_err(|_| watcher_unavailable())?
                    .watch(directory, notify::RecursiveMode::NonRecursive)
                    .map_err(watch_error)?;
                // Validate after arming: alias installation during setup/re-arm
                // must either be observed or rejected before taking a snapshot.
                if directory.canonicalize().map_err(io_error)? != directory {
                    return Err(watch_error(notify::Error::generic(
                        "lane watch path contains a symlink below the artifact root",
                    )));
                }
                drop(watcher);
                scan_artifacts(directory, lane)
            },
        ))
    }
}

fn watch_path_anchors(
    directory: &Path,
    watch: &mut impl FnMut(&Path) -> notify::Result<()>,
) -> notify::Result<()> {
    // Arm parents first: a move during installation is then either reported by
    // an already armed parent, or makes a later watch fail. Leaf-first leaves
    // a window where an entire watched subtree can move without any event.
    if let Some(parent) = directory.parent() {
        watch_path_anchors(parent, watch)?;
    }
    watch(directory)
}

fn observe_change(
    event: notify::Result<notify::Event>,
    directory: &Path,
    changed: &watch::Sender<bool>,
) {
    match event {
        Ok(event)
            if matches!(
                event.kind,
                notify::EventKind::Remove(_)
                    | notify::EventKind::Modify(notify::event::ModifyKind::Name(_))
            ) && event
                .paths
                .iter()
                .any(|path| path != directory && directory.starts_with(path)) =>
        {
            // An ancestor replacement can detach every watch below it. Fail
            // closed, even if the original path has already been recreated.
            let _ = watch_error(notify::Error::generic("lane watch anchor removed"));
            changed.send_modify(|failed| *failed = true);
        }
        Ok(event)
            if !event.kind.is_access()
                && (event.need_rescan()
                    || event.paths.iter().any(|path| {
                        path.starts_with(directory) || directory.starts_with(path)
                    })) =>
        {
            changed.send_modify(|_| {});
        }
        Ok(_) => {}
        Err(error) => {
            let _ = watch_error(error);
            // Sticky across coalesced successful events: errors must reach the stream.
            changed.send_modify(|failed| *failed = true);
        }
    }
}

struct ArtifactStream<W: Unpin> {
    receiver: ReceiverStream<Result<LaneArtifact, LiveError>>,
    worker: tokio::task::JoinHandle<()>,
    watcher: Option<W>,
}

impl<W: Unpin> Stream for ArtifactStream<W> {
    type Item = Result<LaneArtifact, LiveError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let next = Pin::new(&mut this.receiver).poll_next(cx);
        if matches!(next, Poll::Ready(None)) {
            this.watcher.take();
        }
        next
    }
}

impl<W: Unpin> Drop for ArtifactStream<W> {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn artifact_stream<W, F>(
    directory: PathBuf,
    lane: LaneId,
    changed: watch::Receiver<bool>,
    watcher: W,
    scan_artifacts: F,
) -> LaneEgressStream
where
    W: Send + Unpin + 'static,
    F: Fn(&Path, &LaneId) -> Result<Vec<(PathBuf, LaneArtifact)>, LiveError>
        + Clone
        + Send
        + 'static,
{
    let (sender, receiver) = mpsc::channel(32);
    let worker = tokio::spawn(deliver_artifacts(
        directory,
        lane,
        changed,
        sender,
        scan_artifacts,
    ));
    Box::pin(ArtifactStream {
        receiver: ReceiverStream::new(receiver),
        worker,
        watcher: Some(watcher),
    })
}

async fn deliver_artifacts<F>(
    directory: PathBuf,
    lane: LaneId,
    mut changed: watch::Receiver<bool>,
    sender: mpsc::Sender<Result<LaneArtifact, LiveError>>,
    scan_artifacts: F,
) where
    F: Fn(&Path, &LaneId) -> Result<Vec<(PathBuf, LaneArtifact)>, LiveError>
        + Clone
        + Send
        + 'static,
{
    let mut delivered = BTreeSet::new();
    loop {
        // Consume the notification before scanning, never after: a concurrent
        // publication must cause another pass even while delivery is backpressured.
        let failed = *changed.borrow_and_update();
        if failed {
            let _ = sender.send(Err(watcher_unavailable())).await;
            return;
        }
        let scan_root = directory.clone();
        let expected_lane = lane.clone();
        let scan_artifacts = scan_artifacts.clone();
        let scan =
            tokio::task::spawn_blocking(move || scan_artifacts(&scan_root, &expected_lane)).await;
        let artifacts = match scan {
            Ok(Ok(artifacts)) => artifacts,
            Ok(Err(error)) => {
                let _ = sender.send(Err(error)).await;
                return;
            }
            Err(_) => {
                let _ = sender.send(Err(unavailable())).await;
                return;
            }
        };
        let present = artifacts
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<BTreeSet<_>>();
        delivered.retain(|path| present.contains(path));
        for (path, artifact) in artifacts {
            if delivered.contains(&path) {
                continue;
            }
            if sender.send(Ok(artifact)).await.is_err() {
                return;
            }
            delivered.insert(path);
        }
        tokio::select! {
            _ = sender.closed() => return,
            result = changed.changed() => {
                if result.is_err() {
                    let _ = sender.send(Err(watcher_unavailable())).await;
                    return;
                }
            }
        }
    }
}

fn watch_error(error: notify::Error) -> LiveError {
    tracing::error!("odind: lane_artifact_watch_failed error={error}");
    watcher_unavailable()
}

fn watcher_unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "lane_artifact_watch".to_owned(),
    }
}

fn persist_artifact(directory: &Path, artifact: &LaneArtifact) -> Result<(), LiveError> {
    fs::create_dir_all(directory).map_err(io_error)?;
    set_private_directory(directory)?;
    let path = directory.join(format!("{}.cbor", artifact.manifest.transfer_id));
    let encoded = encode_cbor(artifact).map_err(|_| unavailable())?;
    if path.try_exists().map_err(io_error)? {
        let existing: LaneArtifact =
            decode_cbor(&fs::read(&path).map_err(io_error)?).map_err(|_| unavailable())?;
        return if existing == *artifact {
            Ok(())
        } else {
            Err(LiveError::Conflict {
                code: "lane_artifact_transfer_reuse".to_owned(),
                message: "transfer ID is already bound to another lane artifact".to_owned(),
            })
        };
    }
    let temporary = directory.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = private_file(&temporary)?;
    file.write_all(&encoded).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(&temporary, &path).map_err(io_error)?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn scan_artifacts(
    directory: &Path,
    expected_lane: &LaneId,
) -> Result<Vec<(PathBuf, LaneArtifact)>, LiveError> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        if entry.file_type().map_err(io_error)?.is_file()
            && entry.path().extension().and_then(|value| value.to_str()) == Some("cbor")
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let artifact: LaneArtifact =
                decode_cbor(&fs::read(&path).map_err(io_error)?).map_err(|_| unavailable())?;
            if &artifact.lane_id != expected_lane {
                return Err(LiveError::Transfer {
                    code: "lane_artifact_binding".to_owned(),
                    message: "egress record lane does not match its filesystem lane".to_owned(),
                });
            }
            Ok((path, artifact))
        })
        .collect()
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), LiveError> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), LiveError> {
    Ok(())
}

fn private_file(path: &Path) -> Result<File, LiveError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(io_error)
}

fn io_error(_: std::io::Error) -> LiveError {
    unavailable()
}

fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "lane_artifact_filesystem".to_owned(),
    }
}

pub struct LaneTransferBridge {
    port: Arc<dyn LaneArtifactPort>,
}

impl LaneTransferBridge {
    pub fn new(port: Arc<dyn LaneArtifactPort>) -> Self {
        Self { port }
    }

    pub async fn publish_ingress(
        &self,
        lane_id: LaneId,
        manifest: TransferManifest,
        blob: BlobRef,
    ) -> Result<(), LiveError> {
        if manifest.direction != ArtifactDirection::DeviceToSession
            || manifest.session_id != blob.session_id
            || manifest.content_digest != blob.digest
            || manifest.byte_len != blob.byte_len
        {
            return Err(LiveError::Transfer {
                code: "lane_binding".to_owned(),
                message: "transfer manifest does not match durable ingress blob".to_owned(),
            });
        }
        self.port
            .publish(LaneArtifact {
                lane_id,
                manifest,
                blob,
            })
            .await
    }

    pub async fn subscribe_egress(&self, lane: &LaneId) -> Result<LaneEgressStream, LiveError> {
        self.port.subscribe(lane).await
    }
}

#[cfg(test)]
#[path = "lane_artifacts_tests.rs"]
mod tests;
