//! Bounded list, search, stat, and read over declared roots.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU16;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use odin_domain::huginn::{
    BinaryChunk, FileEntryKind, FileListPage, FileListRequest, FileMetadata, FileReadRequest,
    FileReadStream, FileRoot, FileRootId, HuginnProtocolError, RelativePath, Sequence, StreamId,
};
use odin_domain::Digest;
use rustix::fs::Dir;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::roots::{
    directory_flags, entry_revision, file_conflict, file_limit, file_unavailable, invalid_file,
    listing_revision, map_domain, map_open, media_type_for_name, open_beneath, open_root_dir,
    read_flags, stat_entry, EntryStat, RootCatalog,
};
use crate::config::FileLimits;

const STREAM_CHANNEL_CAPACITY: usize = 4;
const LIST_SCAN_CAP: usize = 10_000;
const SEARCH_SCAN_CAP: usize = 8_192;
const SEARCH_DEPTH_CAP: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSearchQuery {
    pub root_id: FileRootId,
    pub directory: Option<RelativePath>,
    pub pattern: String,
    pub limit: NonZeroU16,
}

#[derive(Clone)]
pub struct BrowseEngine {
    catalog: Arc<RootCatalog>,
    limits: FileLimits,
}

impl BrowseEngine {
    pub fn new(catalog: Arc<RootCatalog>, limits: FileLimits) -> Self {
        Self { catalog, limits }
    }

    pub async fn list(
        &self,
        request: FileListRequest,
    ) -> Result<FileListPage, HuginnProtocolError> {
        let root = self.catalog.get(&request.root_id)?.clone();
        let limit = request.limit.get().min(self.limits.max_browse_page.get());
        let expected_revision = request.expected_revision;
        let page = tokio::task::spawn_blocking(move || {
            let dir = open_root_dir(&root.canonical_path)
                .map_err(|_| file_unavailable("file-root-open"))?;
            list_sync(
                &root,
                &dir,
                request.directory.as_ref(),
                request.after.as_ref(),
                limit,
            )
        })
        .await
        .map_err(|_| file_unavailable("file-browse-join"))??;
        if let Some(expected) = expected_revision {
            if page.revision != expected {
                return Err(file_conflict(
                    "staleDirectory",
                    "directory revision moved past the expected revision",
                ));
            }
        }
        Ok(page)
    }

    pub async fn stat(
        &self,
        root_id: &FileRootId,
        relative: &RelativePath,
    ) -> Result<FileMetadata, HuginnProtocolError> {
        self.check_path_len(relative.as_str())?;
        let root = self.catalog.get(root_id)?.clone();
        let relative = relative.clone();
        tokio::task::spawn_blocking(move || {
            let dir = open_root_dir(&root.canonical_path)
                .map_err(|_| file_unavailable("file-root-open"))?;
            stat_sync(&root, &dir, &relative)
        })
        .await
        .map_err(|_| file_unavailable("file-stat-join"))?
    }

    pub async fn search(
        &self,
        query: FileSearchQuery,
    ) -> Result<Vec<FileMetadata>, HuginnProtocolError> {
        if query.pattern.is_empty() {
            return Err(invalid_file("search pattern must not be empty"));
        }
        if let Some(directory) = &query.directory {
            self.check_path_len(directory.as_str())?;
        }
        let root = self.catalog.get(&query.root_id)?.clone();
        let limit = query.limit.get().min(self.limits.max_browse_page.get()) as usize;
        let pattern = query.pattern.to_lowercase();
        tokio::task::spawn_blocking(move || {
            let dir = open_root_dir(&root.canonical_path)
                .map_err(|_| file_unavailable("file-root-open"))?;
            search_sync(&root, &dir, query.directory.as_ref(), &pattern, limit)
        })
        .await
        .map_err(|_| file_unavailable("file-search-join"))?
    }

    pub fn read(&self, request: FileReadRequest) -> Result<FileReadStream, HuginnProtocolError> {
        self.check_path_len(request.relative_path.as_str())?;
        let root = self.catalog.get(&request.root_id)?.clone();
        let (file, metadata) = open_file_checked(&root, &request.relative_path)?;
        request.validate_metadata(&metadata).map_err(map_domain)?;
        if metadata.media_type.is_none() {
            return Err(invalid_file(
                "file media type is not declared by its root policy",
            ));
        }

        let stream_id = StreamId::new(Uuid::new_v4()).map_err(map_domain)?;
        let chunk_cap = self.limits.max_read_chunk_bytes.get() as usize;
        let start = request.range.map(|range| range.offset).unwrap_or(0);
        let end_exclusive = match request.range {
            Some(range) => range.end_exclusive().map_err(map_domain)?,
            None => metadata.byte_len,
        };
        let (tx, rx) =
            mpsc::channel::<Result<BinaryChunk, HuginnProtocolError>>(STREAM_CHANNEL_CAPACITY);
        tokio::task::spawn_blocking(move || {
            pump_read_chunks(tx, file, stream_id, start, end_exclusive, chunk_cap);
        });
        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    pub(crate) fn catalog(&self) -> &Arc<RootCatalog> {
        &self.catalog
    }

    pub(crate) fn open_for_render(
        &self,
        root_id: &FileRootId,
        relative: &RelativePath,
        expected_revision: Option<Digest>,
    ) -> Result<(std::fs::File, FileMetadata), HuginnProtocolError> {
        self.check_path_len(relative.as_str())?;
        let root = self.catalog.get(root_id)?.clone();
        let (file, metadata) = open_file_checked(&root, relative)?;
        if let Some(expected) = expected_revision {
            if metadata.revision != Some(expected) {
                return Err(file_conflict(
                    "staleFile",
                    "file revision moved past the expected revision",
                ));
            }
        }
        Ok((file, metadata))
    }

    fn check_path_len(&self, path: &str) -> Result<(), HuginnProtocolError> {
        if path.len() > self.limits.max_path_bytes.get() {
            return Err(file_limit("file-path-bytes"));
        }
        Ok(())
    }
}

fn list_sync(
    root: &FileRoot,
    root_dir: &std::fs::File,
    directory: Option<&RelativePath>,
    after: Option<&RelativePath>,
    limit: u16,
) -> Result<FileListPage, HuginnProtocolError> {
    let dir = match directory {
        Some(relative) => open_beneath(root_dir, relative.as_path(), directory_flags())
            .map_err(|error| map_open(&error, "fileDirectory", relative.as_str()))?,
        None => root_dir
            .try_clone()
            .map_err(|_| file_unavailable("file-open"))?,
    };

    let mut rows = read_directory_rows(&dir, LIST_SCAN_CAP, "file-listing")?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let revision = listing_revision(&rows);

    let mut candidates = Vec::new();
    for (name, stat) in rows {
        let metadata = metadata_for(root, directory, &name, stat)?;
        if after.is_some_and(|cursor| metadata.relative_path.as_str() <= cursor.as_str()) {
            continue;
        }
        candidates.push(metadata);
    }
    let has_more = candidates.len() > usize::from(limit);
    candidates.truncate(usize::from(limit));
    let next_after = has_more
        .then(|| candidates.last().map(|entry| entry.relative_path.clone()))
        .flatten();

    Ok(FileListPage {
        root_id: root.root_id.clone(),
        directory: directory.cloned(),
        revision,
        entries: candidates,
        next_after,
    })
}

fn stat_sync(
    root: &FileRoot,
    root_dir: &std::fs::File,
    relative: &RelativePath,
) -> Result<FileMetadata, HuginnProtocolError> {
    let path = relative.as_path();
    let leaf = path
        .file_name()
        .ok_or_else(|| invalid_file("file path has no leaf"))?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = match parent_path {
        Some(parent) => open_beneath(root_dir, parent, directory_flags())
            .map_err(|error| map_open(&error, "fileDirectory", relative.as_str()))?,
        None => root_dir
            .try_clone()
            .map_err(|_| file_unavailable("file-open"))?,
    };
    let stat =
        stat_entry(&parent, leaf).map_err(|error| map_open(&error, "file", relative.as_str()))?;
    let name = leaf
        .to_str()
        .ok_or_else(|| invalid_file("file name is not valid UTF-8"))?;
    let parent_relative = parent_path
        .map(|parent| RelativePath::new(parent.to_string_lossy().into_owned()).map_err(map_domain))
        .transpose()?;
    metadata_for(root, parent_relative.as_ref(), name, stat)
}

fn search_sync(
    root: &FileRoot,
    root_dir: &std::fs::File,
    directory: Option<&RelativePath>,
    pattern: &str,
    limit: usize,
) -> Result<Vec<FileMetadata>, HuginnProtocolError> {
    let start = match directory {
        Some(relative) => open_beneath(root_dir, relative.as_path(), directory_flags())
            .map_err(|error| map_open(&error, "fileDirectory", relative.as_str()))?,
        None => root_dir
            .try_clone()
            .map_err(|_| file_unavailable("file-open"))?,
    };
    let mut queue = VecDeque::from([(start, directory.cloned(), 0_usize)]);
    let mut scanned = 0_usize;
    let mut results = Vec::with_capacity(limit.min(64));

    while let Some((dir, prefix, depth)) = queue.pop_front() {
        let mut rows = read_directory_rows(&dir, SEARCH_SCAN_CAP, "file-search")?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, stat) in rows {
            scanned += 1;
            if scanned > SEARCH_SCAN_CAP {
                return Err(file_limit("file-search"));
            }
            let metadata = metadata_for(root, prefix.as_ref(), &name, stat)?;
            if stat.kind == FileEntryKind::File && name.to_lowercase().contains(pattern) {
                results.push(metadata.clone());
                if results.len() == limit {
                    return Ok(results);
                }
            }
            if stat.kind == FileEntryKind::Directory && depth < SEARCH_DEPTH_CAP {
                let child =
                    open_beneath(&dir, Path::new(&name), directory_flags()).map_err(|_| {
                        file_conflict(
                            "pathBoundary",
                            "search encountered a symlink, mount, or replacement boundary",
                        )
                    })?;
                queue.push_back((child, Some(metadata.relative_path), depth + 1));
            }
        }
    }
    Ok(results)
}

pub(crate) fn read_directory_rows(
    dir: &std::fs::File,
    cap: usize,
    limit_name: &'static str,
) -> Result<Vec<(String, EntryStat)>, HuginnProtocolError> {
    let mut rows = Vec::new();
    let stream = Dir::read_from(dir).map_err(|_| file_unavailable("file-readdir"))?;
    for entry in stream {
        let entry = entry.map_err(|_| file_unavailable("file-readdir"))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            continue;
        };
        let stat =
            stat_entry(dir, OsStr::from_bytes(bytes)).map_err(|_| file_unavailable("file-stat"))?;
        rows.push((name.to_owned(), stat));
        if rows.len() > cap {
            return Err(file_limit(limit_name));
        }
    }
    Ok(rows)
}

pub(crate) fn metadata_for(
    root: &FileRoot,
    parent: Option<&RelativePath>,
    name: &str,
    stat: EntryStat,
) -> Result<FileMetadata, HuginnProtocolError> {
    let joined = match parent {
        Some(directory) => format!("{directory}/{name}"),
        None => name.to_owned(),
    };
    let relative_path = RelativePath::new(joined).map_err(map_domain)?;
    let media_type = media_type_for_name(name)
        .filter(|media| root.media_policy.allows(media))
        .map(str::to_owned);
    let revision =
        (stat.kind == FileEntryKind::File).then(|| entry_revision(stat.byte_len, stat.modified_at));
    Ok(FileMetadata {
        root_id: root.root_id.clone(),
        relative_path,
        entry_kind: stat.kind,
        byte_len: stat.byte_len,
        media_type,
        revision,
        modified_at: stat.modified_at,
    })
}

fn open_file_checked(
    root: &FileRoot,
    relative: &RelativePath,
) -> Result<(std::fs::File, FileMetadata), HuginnProtocolError> {
    let dir =
        open_root_dir(&root.canonical_path).map_err(|_| file_unavailable("file-root-open"))?;
    let file = open_beneath(&dir, relative.as_path(), read_flags())
        .map_err(|error| map_open(&error, "file", relative.as_str()))?;
    let stat = file.metadata().map_err(|_| file_unavailable("file-stat"))?;
    if !stat.is_file() {
        return Err(invalid_file("read target is not a regular file"));
    }
    let modified_at = modified_from_std(&stat);
    Ok((
        file,
        FileMetadata {
            root_id: root.root_id.clone(),
            relative_path: relative.clone(),
            entry_kind: FileEntryKind::File,
            byte_len: stat.len(),
            media_type: media_type_for_name(relative.as_str())
                .filter(|media| root.media_policy.allows(media))
                .map(str::to_owned),
            revision: Some(entry_revision(stat.len(), modified_at)),
            modified_at,
        },
    ))
}

fn modified_from_std(stat: &std::fs::Metadata) -> Option<time::OffsetDateTime> {
    use std::os::unix::fs::MetadataExt;

    let base = time::OffsetDateTime::from_unix_timestamp(stat.mtime()).ok()?;
    base.replace_nanosecond(stat.mtime_nsec().clamp(0, 999_999_999) as u32)
        .ok()
}

fn pump_read_chunks(
    tx: mpsc::Sender<Result<BinaryChunk, HuginnProtocolError>>,
    mut file: std::fs::File,
    stream_id: StreamId,
    start: u64,
    end_exclusive: u64,
    chunk_cap: usize,
) {
    if file.seek(SeekFrom::Start(start)).is_err() {
        let _ = tx.blocking_send(Err(file_unavailable("file-seek")));
        return;
    }
    if start == end_exclusive {
        let bytes = Vec::new();
        let _ = tx.blocking_send(Ok(BinaryChunk {
            stream_id,
            sequence: Sequence::new(0),
            offset: start,
            digest: Digest::hash(&bytes),
            bytes,
            final_chunk: true,
        }));
        return;
    }

    let mut buffer = vec![0_u8; chunk_cap];
    let mut offset = start;
    let mut sequence = 0_u64;
    while offset < end_exclusive {
        let wanted = (end_exclusive - offset).min(chunk_cap as u64) as usize;
        let read = loop {
            match file.read(&mut buffer[..wanted]) {
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = tx.blocking_send(Err(file_unavailable("file-read")));
                    return;
                }
            }
        };
        if read == 0 {
            let _ = tx.blocking_send(Err(file_conflict(
                "fileTruncated",
                "file became shorter than its observed revision",
            )));
            return;
        }
        let bytes = buffer[..read].to_vec();
        let next_offset = offset + read as u64;
        let final_chunk = next_offset == end_exclusive;
        let chunk = BinaryChunk {
            stream_id,
            sequence: Sequence::new(sequence),
            offset,
            digest: Digest::hash(&bytes),
            bytes,
            final_chunk,
        };
        if tx.blocking_send(Ok(chunk)).is_err() {
            return;
        }
        offset = next_offset;
        sequence = sequence.saturating_add(1);
    }
}
