use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::{
    FileChangeKind, FileDelta, FileDeltaStream, FileEntryKind, FileMetadata, FileWatchRequest,
    HuginnProtocolError, RelativePath,
};
use odin_domain::Digest;
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;

use super::browse::{metadata_for, read_directory_rows};
use super::roots::{
    directory_flags, file_conflict, file_limit, file_unavailable, invalid_file, listing_revision,
    open_beneath, RootCatalog,
};
use crate::config::FileLimits;

const WATCH_SCAN_CAP: usize = 10_000;
const WATCH_DEPTH_CAP: usize = 32;

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
            poll_interval: poll_interval.max(Duration::from_millis(25)),
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
            .map_err(|_| file_limit("file-watch-streams"))?;
        let request_for_scan = request.clone();
        let root_for_scan = root.clone();
        let mut previous =
            tokio::task::spawn_blocking(move || scan(&root_for_scan, &request_for_scan))
                .await
                .map_err(|_| file_unavailable("file-watch-join"))??;
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
                    Err(_) => {
                        let _ = tx.send(Err(file_unavailable("file-watch-join"))).await;
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

struct WatchSnapshot {
    revision: Digest,
    entries: BTreeMap<RelativePath, FileMetadata>,
}

fn scan(
    root: &odin_domain::huginn::FileRoot,
    request: &FileWatchRequest,
) -> Result<WatchSnapshot, HuginnProtocolError> {
    let root_dir = super::roots::open_root_dir(&root.canonical_path)
        .map_err(|_| file_unavailable("file-root-open"))?;
    if let Some(relative) = &request.relative_path {
        let opened = open_beneath(&root_dir, relative.as_path(), super::roots::read_flags())
            .map_err(|error| super::roots::map_open(&error, "fileWatch", relative.as_str()))?;
        let stat = opened
            .metadata()
            .map_err(|_| file_unavailable("file-stat"))?;
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
    let first_rows = read_directory_rows(&start, WATCH_SCAN_CAP, "file-watch-scan")?;
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
        if entries.len() >= WATCH_SCAN_CAP {
            return Err(file_limit("file-watch-scan"));
        }
        let metadata = metadata_for(root, prefix, &name, stat)?;
        let relative = metadata.relative_path.clone();
        entries.insert(relative.clone(), metadata);
        if recursive && stat.kind == FileEntryKind::Directory {
            let child = open_beneath(&dir, Path::new(&name), directory_flags()).map_err(|_| {
                file_conflict(
                    "pathBoundary",
                    "watch encountered a symlink, mount, or replacement boundary",
                )
            })?;
            let child_rows = read_directory_rows(&child, WATCH_SCAN_CAP, "file-watch-scan")?;
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

fn single_file_metadata(
    root: &odin_domain::huginn::FileRoot,
    relative: &RelativePath,
    stat: &std::fs::Metadata,
) -> Result<FileMetadata, HuginnProtocolError> {
    use std::os::unix::fs::MetadataExt;

    let modified_at = time::OffsetDateTime::from_unix_timestamp(stat.mtime())
        .ok()
        .and_then(|base| {
            base.replace_nanosecond(stat.mtime_nsec().clamp(0, 999_999_999) as u32)
                .ok()
        });
    Ok(FileMetadata {
        root_id: root.root_id.clone(),
        relative_path: relative.clone(),
        entry_kind: FileEntryKind::File,
        byte_len: stat.len(),
        media_type: super::roots::media_type_for_name(relative.as_str())
            .filter(|media| root.media_policy.allows(media))
            .map(str::to_owned),
        revision: Some(super::roots::entry_revision(stat.len(), modified_at)),
        modified_at,
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
