//! Bounded list, search, stat, and read over declared roots.

use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU16;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use odin_domain::huginn::{
    media_type_for_name, BinaryChunk, FileEntryKind, FileListPage, FileListRequest, FileMetadata,
    FileReadRequest, FileReadStream, FileRoot, FileRootId, HuginnProtocolError, RelativePath,
    Sequence, StreamId,
};
use odin_domain::Digest;
use rustix::fs::Dir;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use super::roots::{
    directory_flags, entry_revision, file_conflict, file_limit, invalid_file, listing_revision,
    map_domain, map_open, modified_at, open_beneath, open_root, read_flags, stat_entry, EntryStat,
    RootCatalog,
};
use crate::config::FileLimits;

const STREAM_CHANNEL_CAPACITY: usize = 4;
/// Entries read from one directory for a listing or a watch scan; a larger directory is refused by name.
pub(super) const SCAN_CAP: usize = 10_000;
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
            let dir = open_root(&root)?;
            list_sync(
                &root,
                &dir,
                request.directory.as_ref(),
                request.after.as_ref(),
                limit,
            )
        })
        .await
        .map_err(|error| HuginnProtocolError::unavailable("file-browse-join", error))??;
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
            let dir = open_root(&root)?;
            stat_sync(&root, &dir, &relative)
        })
        .await
        .map_err(|error| HuginnProtocolError::unavailable("file-stat-join", error))?
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
            let dir = open_root(&root)?;
            search_sync(&root, &dir, query.directory.as_ref(), &pattern, limit)
                .map(|found| found.entries)
        })
        .await
        .map_err(|error| HuginnProtocolError::unavailable("file-search-join", error))?
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

/// A listing or name search; `truncated` when more may exist than `entries` holds,
/// because the limit or the scan cap ended it.
#[derive(Debug)]
pub struct Found {
    pub entries: Vec<FileMetadata>,
    pub truncated: bool,
}

/// One declared root's listing (`find` absent) or name search (`find`
/// given), outside any catalog: the gateway's own confined code, for a
/// seat sharing a file on this host or `odin host-file` on another.
pub fn find_in_root(
    root: &FileRoot,
    directory: Option<&RelativePath>,
    find: Option<&str>,
    limit: u16,
) -> Result<Found, HuginnProtocolError> {
    let dir = open_root(root)?;
    match find {
        Some(pattern) if !pattern.is_empty() => search_sync(
            root,
            &dir,
            directory,
            &pattern.to_lowercase(),
            usize::from(limit),
        ),
        Some(_) => Err(invalid_file("search pattern must not be empty")),
        None => {
            let page = list_sync(root, &dir, directory, None, limit)?;
            Ok(Found {
                truncated: page.next_after.is_some(),
                entries: page.entries,
            })
        }
    }
}

/// Opens a confined, policy-checked original for bounded-memory streaming.
pub fn open_from_root(
    root: &FileRoot,
    relative: &RelativePath,
) -> Result<(FileMetadata, std::fs::File), HuginnProtocolError> {
    let (file, metadata) = open_file_checked(root, relative)?;
    if metadata.media_type.is_none() {
        return Err(invalid_file(
            "file media type is not declared by its root policy",
        ));
    }
    if metadata.byte_len > root.max_object_bytes.get() {
        return Err(file_limit("file-object-bytes"));
    }
    Ok((metadata, file))
}

/// Closes a movable source only after its destination has been verified.
/// A changed source is retained, not unlinked.
pub fn remove_verified_source(
    root: &FileRoot,
    relative: &RelativePath,
    expected: Digest,
) -> Result<(), HuginnProtocolError> {
    if root.access != odin_domain::huginn::FileRootAccess::ReadWrite {
        return Err(invalid_file(format!("{} is read-only", root.root_id)));
    }
    let (metadata, _) = open_from_root(root, relative)?;
    let root_dir = open_root(root)?;
    let parent = relative
        .as_path()
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    let name = relative
        .as_path()
        .file_name()
        .ok_or_else(|| invalid_file("source has no file name"))?;
    if stat_sync(root, &root_dir, relative)?.revision != metadata.revision {
        return Err(file_conflict(
            "fileChanged",
            "move source changed; retained the source",
        ));
    }
    let dir = match parent {
        Some(parent) => open_beneath(&root_dir, parent, directory_flags())
            .map_err(|error| HuginnProtocolError::unavailable("file-open", error))?,
        None => root_dir,
    };
    // Claim the name atomically, then verify the claimed object. Checking
    // before unlink alone can delete a replacement that arrived in between.
    let claimed = format!(".odin-move-{}", Uuid::new_v4());
    rustix::fs::renameat_with(
        &dir,
        name,
        &dir,
        claimed.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|error| HuginnProtocolError::unavailable("file-move-claim", error))?;
    let verified = (|| -> std::io::Result<bool> {
        let mut file = open_beneath(&dir, Path::new(&claimed), read_flags())?;
        let mut digest = blake3::Hasher::new();
        digest.update_reader(&mut file)?;
        Ok(digest.finalize().as_bytes() == expected.as_bytes())
    })();
    if !matches!(verified, Ok(true)) {
        rustix::fs::renameat_with(&dir, claimed.as_str(), &dir, name, rustix::fs::RenameFlags::NOREPLACE)
            .map_err(|error| HuginnProtocolError::unavailable("file-move-restore",
                format!("source retained as {claimed}; its old name is occupied or unavailable: {error}")))?;
        return match verified {
            Err(error) => Err(HuginnProtocolError::unavailable("file-move-verify", error)),
            _ => Err(file_conflict(
                "fileChanged",
                "move source changed; retained the source",
            )),
        };
    }
    rustix::fs::unlinkat(&dir, claimed.as_str(), rustix::fs::AtFlags::empty())
        .map_err(|error| HuginnProtocolError::unavailable("file-remove", error))?;
    dir.sync_all()
        .map_err(|error| HuginnProtocolError::unavailable("file-sync", error))
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
            .map_err(|error| HuginnProtocolError::unavailable("file-open", error))?,
    };

    let mut rows = read_directory_rows(&dir, SCAN_CAP, "file-listing")?;
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
            .map_err(|error| HuginnProtocolError::unavailable("file-open", error))?,
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

/// Files whose name holds `pattern`, at most `limit`. A walk that reaches the scan
/// cap (in one directory or across them) ends with the hits found so far.
fn search_sync(
    root: &FileRoot,
    root_dir: &std::fs::File,
    directory: Option<&RelativePath>,
    pattern: &str,
    limit: usize,
) -> Result<Found, HuginnProtocolError> {
    let start = match directory {
        Some(relative) => open_beneath(root_dir, relative.as_path(), directory_flags())
            .map_err(|error| map_open(&error, "fileDirectory", relative.as_str()))?,
        None => root_dir
            .try_clone()
            .map_err(|error| HuginnProtocolError::unavailable("file-open", error))?,
    };
    let frame = |dir: std::fs::File, prefix, depth| {
        let (mut rows, over_cap) = scan_directory(&dir, SEARCH_SCAN_CAP)?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        Ok::<_, HuginnProtocolError>(((dir, prefix, depth, rows.into_iter()), over_cap))
    };
    // Keep only the active ancestry open, at most SEARCH_DEPTH_CAP + 1 directories.
    let (first, mut truncated) = frame(start, directory.cloned(), 0_usize)?;
    let mut stack = vec![first];
    let mut scanned = 0_usize;
    let mut results = Vec::with_capacity(limit.min(64));

    while let Some((dir, prefix, depth, rows)) = stack.last_mut() {
        let Some((name, stat)) = rows.next() else {
            stack.pop();
            continue;
        };
        scanned += 1;
        if scanned > SEARCH_SCAN_CAP {
            truncated = true;
            break;
        }
        let metadata = metadata_for(root, prefix.as_ref(), &name, stat)?;
        if stat.kind == FileEntryKind::Directory && *depth < SEARCH_DEPTH_CAP {
            let child =
                open_beneath(dir, Path::new(&name), directory_flags()).map_err(|error| {
                    map_open(&error, "fileDirectory", metadata.relative_path.as_str())
                })?;
            let (child_frame, over_cap) = frame(child, Some(metadata.relative_path), *depth + 1)?;
            truncated |= over_cap;
            stack.push(child_frame);
        } else if stat.kind == FileEntryKind::File && name.to_lowercase().contains(pattern) {
            results.push(metadata);
            if results.len() == limit {
                truncated = true;
                break;
            }
        }
    }
    Ok(Found {
        entries: results,
        truncated,
    })
}

pub(crate) fn read_directory_rows(
    dir: &std::fs::File,
    cap: usize,
    limit_name: &'static str,
) -> Result<Vec<(String, EntryStat)>, HuginnProtocolError> {
    match scan_directory(dir, cap)? {
        (rows, false) => Ok(rows),
        (_, true) => Err(file_limit(limit_name)),
    }
}

/// A directory's first `cap` entries, and whether it held more.
fn scan_directory(
    dir: &std::fs::File,
    cap: usize,
) -> Result<(Vec<(String, EntryStat)>, bool), HuginnProtocolError> {
    let mut rows = Vec::new();
    let stream = Dir::read_from(dir)
        .map_err(|error| HuginnProtocolError::unavailable("file-readdir", error))?;
    for entry in stream {
        let entry =
            entry.map_err(|error| HuginnProtocolError::unavailable("file-readdir", error))?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            continue;
        };
        if rows.len() == cap {
            return Ok((rows, true));
        }
        let stat = stat_entry(dir, OsStr::from_bytes(bytes))
            .map_err(|error| HuginnProtocolError::unavailable("file-stat", error))?;
        rows.push((name.to_owned(), stat));
    }
    Ok((rows, false))
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
    let dir = open_root(root)?;
    let file = open_beneath(&dir, relative.as_path(), read_flags())
        .map_err(|error| map_open(&error, "file", relative.as_str()))?;
    let stat = file
        .metadata()
        .map_err(|error| HuginnProtocolError::unavailable("file-stat", error))?;
    if !stat.is_file() {
        return Err(invalid_file("read target is not a regular file"));
    }
    let modified = modified_at(&stat);
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
            revision: Some(entry_revision(stat.len(), modified)),
            modified_at: modified,
        },
    ))
}

fn pump_read_chunks(
    tx: mpsc::Sender<Result<BinaryChunk, HuginnProtocolError>>,
    mut file: std::fs::File,
    stream_id: StreamId,
    start: u64,
    end_exclusive: u64,
    chunk_cap: usize,
) {
    if let Err(error) = file.seek(SeekFrom::Start(start)) {
        let _ = tx.blocking_send(Err(HuginnProtocolError::unavailable("file-seek", error)));
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
                Err(error) => {
                    let _ =
                        tx.blocking_send(Err(HuginnProtocolError::unavailable("file-read", error)));
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

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use odin_domain::huginn::{
        FileMetadata, FileRoot, FileRootAccess, HuginnProtocolError, RelativePath,
    };

    use super::{find_in_root, open_from_root};
    use crate::files::test_root_init;

    fn root(dir: &std::path::Path) -> FileRoot {
        FileRoot::new(test_root_init(
            "pc-documents",
            dir,
            FileRootAccess::ReadOnly,
            "application/pdf",
        ))
        .unwrap()
    }

    fn read_from_root(
        root: &FileRoot,
        path: &RelativePath,
    ) -> Result<(FileMetadata, Vec<u8>), HuginnProtocolError> {
        let (metadata, mut file) = open_from_root(root, path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        Ok((metadata, bytes))
    }

    #[test]
    fn a_seat_finds_and_reads_declared_files_and_nothing_past_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("CS91")).unwrap();
        std::fs::write(dir.path().join("CS91/CS 91a Draft.pdf"), b"%PDF draft").unwrap();
        std::fs::write(dir.path().join("CS91/notes.bin"), b"x").unwrap();
        std::fs::write(dir.path().join("big.pdf"), vec![0; 2048]).unwrap();
        std::fs::write(outside.path().join("secret.pdf"), b"%PDF secret").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.pdf"),
            dir.path().join("link.pdf"),
        )
        .unwrap();
        let root = root(dir.path());
        let path = |path: &str| RelativePath::parse(path).unwrap();

        let found = find_in_root(&root, None, Some("draft"), 10).unwrap();
        assert_eq!(found.entries.len(), 1);
        assert!(!found.truncated);
        assert_eq!(
            found.entries[0].relative_path.as_str(),
            "CS91/CS 91a Draft.pdf"
        );
        let listed = find_in_root(&root, Some(&path("CS91")), None, 10).unwrap();
        assert_eq!(listed.entries.len(), 2);

        let (metadata, bytes) = read_from_root(&root, &path("CS91/CS 91a Draft.pdf")).unwrap();
        assert_eq!(bytes, b"%PDF draft");
        assert_eq!(metadata.media_type.as_deref(), Some("application/pdf"));
        assert!(
            read_from_root(&root, &path("link.pdf")).is_err(),
            "symlink out"
        );
        assert!(
            read_from_root(&root, &path("CS91/notes.bin")).is_err(),
            "undeclared type"
        );
        assert!(
            read_from_root(&root, &path("big.pdf")).is_err(),
            "over the root ceiling"
        );
        assert!(RelativePath::parse("../secret.pdf").is_err());
    }

    #[test]
    fn a_search_past_the_scan_cap_returns_the_hits_it_reached_marked_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..super::SEARCH_SCAN_CAP + 100 {
            std::fs::write(dir.path().join(format!("needle-{index:05}.pdf")), b"%PDF").unwrap();
        }
        let found = find_in_root(&root(dir.path()), None, Some("needle"), u16::MAX).unwrap();
        assert_eq!(found.entries.len(), super::SEARCH_SCAN_CAP);
        assert!(found.truncated);
    }
}
