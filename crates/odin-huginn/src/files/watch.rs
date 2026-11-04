use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use notify::event::AccessKind;
use notify::{EventKind, RecursiveMode, Watcher as _};

use odin_domain::huginn::{
    FileChangeKind, FileDelta, FileDeltaStream, FileEntryKind, FileMetadata, FileWatchRequest,
    HuginnProtocolError, RelativePath,
};
use odin_domain::Digest;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

use super::browse::{metadata_for, read_directory_rows, SCAN_CAP};
use super::roots::{
    directory_flags, file_conflict, file_limit, invalid_file, listing_revision, map_open,
    modified_at, open_beneath, RootCatalog,
};
use crate::config::FileLimits;

const WATCH_DEPTH_CAP: usize = 32;
/// How often a watch rescans when the kernel signalled a change (or always, without one).
pub(super) const WATCH_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone)]
pub struct WatchManager {
    catalog: Arc<RootCatalog>,
    limits: FileLimits,
    poll_interval: Duration,
    permits: Arc<Semaphore>,
}

impl WatchManager {
    pub fn new(catalog: Arc<RootCatalog>, limits: FileLimits, poll_interval: Duration) -> Self {
        Self {
            catalog,
            permits: Arc::new(Semaphore::new(limits.max_watch_streams.get())),
            limits,
            poll_interval,
        }
    }

    pub async fn watch(
        &self,
        request: FileWatchRequest,
    ) -> Result<FileDeltaStream, HuginnProtocolError> {
        let root = self.catalog.get(&request.root_id)?.clone();
        request
            .validate_policy(&root)
            .map_err(super::roots::map_domain)?;
        if let Some(relative) = &request.relative_path {
            if relative.as_str().len() > self.limits.max_path_bytes.get() {
                return Err(file_limit("file-path-bytes"));
            }
        }
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::NoPermits => file_limit("file-watch-streams"),
                tokio::sync::TryAcquireError::Closed => {
                    HuginnProtocolError::unavailable("file-watch-streams", error)
                }
            })?;
        // Armed before the first scan so a change during it is not lost.
        let signal = change_signal(&root, &request);
        let request_for_scan = request.clone();
        let root_for_scan = root.clone();
        let mut previous =
            tokio::task::spawn_blocking(move || scan(&root_for_scan, &request_for_scan))
                .await
                .map_err(|error| HuginnProtocolError::unavailable("file-watch-join", error))??;
        if let Some(expected) = request.expected_revision {
            if previous.revision != expected {
                return Err(file_conflict(
                    "staleWatch",
                    "watch source revision moved past the expected revision",
                ));
            }
        }
        let (tx, rx) = mpsc::channel(self.limits.watch_queue_depth.get());
        let poll_interval = self.poll_interval;
        tokio::spawn(async move {
            let _permit = permit;
            let mut ticker = tokio::time::interval(poll_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                // Without a kernel watcher every tick rescans.
                if signal
                    .as_ref()
                    .is_some_and(|signal| !signal.dirty.swap(false, Ordering::Relaxed))
                {
                    continue;
                }
                let root = root.clone();
                let request_for_scan = request.clone();
                let next = match tokio::task::spawn_blocking(move || scan(&root, &request_for_scan))
                    .await
                {
                    Ok(Ok(snapshot)) => snapshot,
                    Ok(Err(error)) => {
                        let _ = tx.send(Err(error)).await;
                        return;
                    }
                    Err(error) => {
                        let _ = tx
                            .send(Err(HuginnProtocolError::unavailable(
                                "file-watch-join",
                                error,
                            )))
                            .await;
                        return;
                    }
                };
                if next.revision == previous.revision {
                    continue;
                }
                let deltas = diff(&request, &previous.entries, &next.entries);
                for delta in deltas {
                    if tx.send(Ok(delta)).await.is_err() {
                        return;
                    }
                }
                previous = next;
            }
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}

/// Inotify over the watched directory (a watched file is covered by its
/// parent). It only decides when the next confined scan runs, never what
/// that scan reports.
struct ChangeSignal {
    _watcher: notify::RecommendedWatcher,
    dirty: Arc<AtomicBool>,
}

/// `None` when inotify cannot be armed; the watch then rescans every tick.
fn change_signal(
    root: &odin_domain::huginn::FileRoot,
    request: &FileWatchRequest,
) -> Option<ChangeSignal> {
    let joined = match request.relative_path.as_ref() {
        Some(relative) => root.canonical_path.join(relative.as_path()),
        None => root.canonical_path.clone(),
    };
    // A symlink is not followed: the confined scan rejects it anyway.
    let meta = std::fs::symlink_metadata(&joined).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    let (path, mode) = if meta.is_file() {
        (joined.parent()?.to_path_buf(), RecursiveMode::NonRecursive)
    } else if request.recursive {
        (joined, RecursiveMode::Recursive)
    } else {
        (joined, RecursiveMode::NonRecursive)
    };
    let dirty = Arc::new(AtomicBool::new(false));
    let flag = dirty.clone();
    let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        // The scan's own directory opens are not changes. An error (inotify
        // queue overflow) may hide one, so it counts.
        let scan_open =
            event.is_ok_and(|event| matches!(event.kind, EventKind::Access(AccessKind::Open(_))));
        if !scan_open {
            flag.store(true, Ordering::Relaxed);
        }
    });
    let armed = watcher.and_then(|mut watcher| watcher.watch(&path, mode).map(|()| watcher));
    match armed {
        Ok(watcher) => Some(ChangeSignal {
            _watcher: watcher,
            dirty,
        }),
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "inotify unavailable; file watch rescans every tick"
            );
            None
        }
    }
}

struct WatchSnapshot {
    revision: Digest,
    entries: BTreeMap<RelativePath, FileMetadata>,
}

fn scan(
    root: &odin_domain::huginn::FileRoot,
    request: &FileWatchRequest,
) -> Result<WatchSnapshot, HuginnProtocolError> {
    let root_dir = super::roots::open_root(root)?;
    if let Some(relative) = &request.relative_path {
        let opened = open_beneath(&root_dir, relative.as_path(), super::roots::read_flags())
            .map_err(|error| super::roots::map_open(&error, "fileWatch", relative.as_str()))?;
        let stat = opened
            .metadata()
            .map_err(|error| HuginnProtocolError::unavailable("file-stat", error))?;
        if stat.is_file() {
            let metadata = single_file_metadata(root, relative, &stat)?;
            let revision = metadata
                .revision
                .ok_or_else(|| invalid_file("watched file has no revision"))?;
            return Ok(WatchSnapshot {
                revision,
                entries: BTreeMap::from([(relative.clone(), metadata)]),
            });
        }
        if !stat.is_dir() {
            return Err(invalid_file("watch target is not a file or directory"));
        }
    }

    let start = match &request.relative_path {
        Some(relative) => open_beneath(&root_dir, relative.as_path(), directory_flags())
            .map_err(|error| super::roots::map_open(&error, "fileDirectory", relative.as_str()))?,
        None => root_dir,
    };
    let first_rows = read_directory_rows(&start, SCAN_CAP, "file-watch-scan")?;
    let revision = listing_revision(&first_rows);
    let mut entries = BTreeMap::new();
    collect_directory(
        root,
        start,
        request.relative_path.as_ref(),
        request.recursive,
        0,
        first_rows,
        &mut entries,
    )?;
    if request.recursive {
        Ok(WatchSnapshot {
            revision: tree_revision(&entries),
            entries,
        })
    } else {
        Ok(WatchSnapshot { revision, entries })
    }
}

fn collect_directory(
    root: &odin_domain::huginn::FileRoot,
    dir: std::fs::File,
    prefix: Option<&RelativePath>,
    recursive: bool,
    depth: usize,
    mut rows: Vec<(String, super::roots::EntryStat)>,
    entries: &mut BTreeMap<RelativePath, FileMetadata>,
) -> Result<(), HuginnProtocolError> {
    if depth > WATCH_DEPTH_CAP {
        return Err(file_limit("file-watch-depth"));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, stat) in rows {
        if entries.len() >= SCAN_CAP {
            return Err(file_limit("file-watch-scan"));
        }
        let metadata = metadata_for(root, prefix, &name, stat)?;
        let relative = metadata.relative_path.clone();
        entries.insert(relative.clone(), metadata);
        if recursive && stat.kind == FileEntryKind::Directory {
            let child = open_beneath(&dir, Path::new(&name), directory_flags())
                .map_err(|error| map_child_open(&error, relative.as_str()))?;
            let child_rows = read_directory_rows(&child, SCAN_CAP, "file-watch-scan")?;
            collect_directory(
                root,
                child,
                Some(&relative),
                true,
                depth + 1,
                child_rows,
                entries,
            )?;
        }
    }
    Ok(())
}

/// A child directory that cannot be opened: a symlink, mount or replacement
/// is a boundary; anything else (it vanished, no permission) says its own cause.
fn map_child_open(error: &std::io::Error, relative: &str) -> HuginnProtocolError {
    use rustix::io::Errno;
    match Errno::from_io_error(error) {
        Some(Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => file_conflict(
            "pathBoundary",
            format!("watch encountered a symlink, mount, or replacement boundary at {relative}: {error}"),
        ),
        _ => map_open(error, "fileDirectory", relative),
    }
}

fn single_file_metadata(
    root: &odin_domain::huginn::FileRoot,
    relative: &RelativePath,
    stat: &std::fs::Metadata,
) -> Result<FileMetadata, HuginnProtocolError> {
    let modified = modified_at(stat);
    Ok(FileMetadata {
        root_id: root.root_id.clone(),
        relative_path: relative.clone(),
        entry_kind: FileEntryKind::File,
        byte_len: stat.len(),
        media_type: odin_domain::huginn::media_type_for_name(relative.as_str())
            .filter(|media| root.media_policy.allows(media))
            .map(str::to_owned),
        revision: Some(super::roots::entry_revision(stat.len(), modified)),
        modified_at: modified,
    })
}

fn tree_revision(entries: &BTreeMap<RelativePath, FileMetadata>) -> Digest {
    let mut hasher = blake3::Hasher::new();
    for (path, metadata) in entries {
        hasher.update(path.as_str().as_bytes());
        hasher.update(&[0]);
        hasher.update(&metadata.byte_len.to_le_bytes());
        if let Some(revision) = metadata.revision {
            hasher.update(revision.to_string().as_bytes());
        }
    }
    Digest::new(hasher.finalize().into())
}

fn diff(
    request: &FileWatchRequest,
    previous: &BTreeMap<RelativePath, FileMetadata>,
    current: &BTreeMap<RelativePath, FileMetadata>,
) -> Vec<FileDelta> {
    let mut deltas = Vec::new();
    for (path, before) in previous {
        match current.get(path) {
            None => deltas.push(FileDelta {
                watch_id: request.watch_id,
                root_id: request.root_id.clone(),
                relative_path: path.clone(),
                change: FileChangeKind::Removed,
                previous_path: None,
                previous_revision: before.revision,
                metadata: None,
            }),
            Some(after) if after != before => deltas.push(FileDelta {
                watch_id: request.watch_id,
                root_id: request.root_id.clone(),
                relative_path: path.clone(),
                change: FileChangeKind::Modified,
                previous_path: None,
                previous_revision: before.revision,
                metadata: Some(after.clone()),
            }),
            Some(_) => {}
        }
    }
    for (path, metadata) in current {
        if !previous.contains_key(path) {
            deltas.push(FileDelta {
                watch_id: request.watch_id,
                root_id: request.root_id.clone(),
                relative_path: path.clone(),
                change: FileChangeKind::Created,
                previous_path: None,
                previous_revision: None,
                metadata: Some(metadata.clone()),
            });
        }
    }
    deltas
}

#[cfg(test)]
mod tests {

    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::StreamExt as _;
    use odin_domain::huginn::{
        FileChangeKind, FileDelta, FileDeltaStream, FileRoot, FileRootAccess, FileRootInit,
        FileWatchId, FileWatchPolicy, FileWatchRequest,
    };

    use super::WatchManager;
    use crate::config::FileLimits;
    use crate::files::{test_root_init, RootCatalog};

    fn manager(dir: &Path, limits: FileLimits) -> (WatchManager, FileWatchRequest) {
        let root = FileRoot::new(FileRootInit {
            watch_policy: FileWatchPolicy::Recursive,
            ..test_root_init("tree", dir, FileRootAccess::ReadOnly, "text/plain")
        })
        .unwrap();
        let request = FileWatchRequest {
            watch_id: FileWatchId::parse("00000000-0000-4000-8000-00000000000c").unwrap(),
            root_id: root.root_id.clone(),
            relative_path: None,
            recursive: true,
            expected_revision: None,
        };
        let catalog = Arc::new(RootCatalog::new(vec![root]).unwrap());
        (
            WatchManager::new(catalog, limits, Duration::from_millis(25)),
            request,
        )
    }

    /// The next delta for `path`: its directory's own change arrives too.
    async fn delta_for(stream: &mut FileDeltaStream, path: &str) -> FileDelta {
        let next = async {
            while let Some(delta) = stream.next().await {
                let delta = delta.unwrap();
                if delta.relative_path.as_str() == path {
                    return delta;
                }
            }
            panic!("the watch stream ended");
        };
        tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .unwrap_or_else(|_| panic!("no delta for {path} within 5 s"))
    }

    #[tokio::test]
    async fn a_watched_tree_reports_files_created_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("d1")).unwrap();
        let (manager, request) = manager(dir.path(), FileLimits::default());
        let mut stream = manager.watch(request).await.unwrap();
        let file = dir.path().join("d1/note.txt");

        std::fs::write(&file, b"one\n").unwrap();
        assert_eq!(
            delta_for(&mut stream, "d1/note.txt").await.change,
            FileChangeKind::Created
        );
        std::fs::write(&file, b"one and two\n").unwrap();
        assert_eq!(
            delta_for(&mut stream, "d1/note.txt").await.change,
            FileChangeKind::Modified
        );
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            delta_for(&mut stream, "d1/note.txt").await.change,
            FileChangeKind::Removed
        );
    }
}
