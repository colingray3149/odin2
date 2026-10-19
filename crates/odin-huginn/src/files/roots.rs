//! Declared file roots and kernel-enforced confinement.
//!
//! Every resolution beneath a declared root goes through `openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
//! RESOLVE_NO_XDEV`: `..` escapes, symlink redirection, magic-link traversal,
//! and mount-boundary crossings are rejected by the kernel before any byte is
//! read. Clients hold root handles and relative paths only.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Component, Path};

use odin_domain::huginn::{
    FileEntryKind, FileMediaPolicy, FileRoot, FileRootAccess, FileRootId, FileWatchPolicy,
    HuginnProtocolError,
};
use odin_domain::{Digest, DomainError};
use rustix::fs::{openat2, statat, AtFlags, Mode, OFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

/// The walk from `/` to a declared root: every confinement flag except
/// `NO_XDEV`. The root path is operator-declared and may lie across mount
/// points (odind's own unit bind-mounts `/home` read-only and the
/// ReadWritePaths beneath it), so a mount crossing on the way TO the root is
/// expected; symlinks are still refused at every step, and everything
/// beneath the root keeps the full set.
const ROOT_WALK: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

const MODE_FORMAT_MASK: u32 = 0o170_000;

pub(crate) fn invalid_file(message: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::InvalidRequest {
        code: "file".to_owned(),
        message: message.into(),
    }
}

pub(crate) fn file_unavailable(code: &'static str) -> HuginnProtocolError {
    HuginnProtocolError::Unavailable {
        code: code.to_owned(),
    }
}

pub(crate) fn file_not_found(kind: &'static str, id: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::NotFound {
        object_kind: kind.to_owned(),
        object_id: id.into(),
    }
}

pub(crate) fn file_limit(limit: &'static str) -> HuginnProtocolError {
    HuginnProtocolError::ResourceLimit {
        limit: limit.to_owned(),
    }
}

pub(crate) fn file_conflict(code: &'static str, message: impl Into<String>) -> HuginnProtocolError {
    HuginnProtocolError::Conflict {
        code: code.to_owned(),
        message: message.into(),
    }
}

pub(crate) fn map_domain(error: DomainError) -> HuginnProtocolError {
    match error {
        DomainError::InvalidScope(message) => HuginnProtocolError::InvalidRequest {
            code: "invalidScope".to_owned(),
            message,
        },
        other => HuginnProtocolError::InvalidRequest {
            code: "invalidRequest".to_owned(),
            message: other.to_string(),
        },
    }
}

/// Maps a confined-open failure onto the public surface without leaking host
/// paths: absence is typed, everything else is an availability failure.
pub(crate) fn map_open(error: &io::Error, kind: &'static str, id: &str) -> HuginnProtocolError {
    match error.kind() {
        io::ErrorKind::NotFound => file_not_found(kind, id),
        io::ErrorKind::InvalidInput => invalid_file("path is not representable beneath the root"),
        _ => file_unavailable("file-open"),
    }
}

/// Allows mount crossings on the way to the declared root, but rejects symlinks at every step.
pub(crate) fn open_root_dir(path: &Path) -> io::Result<File> {
    let mut current = File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "root path contains a non-literal component",
                ));
            }
        };
        current = File::from(openat2(
            &current,
            name,
            DIRECTORY_FLAGS,
            Mode::empty(),
            ROOT_WALK,
        )?);
    }
    Ok(current)
}

#[cfg(test)]
mod root_walk_tests {
    use super::{map_domain, DomainError, HuginnProtocolError};

    #[test]
    fn a_scope_refusal_keeps_only_its_reason() {
        assert_eq!(
            map_domain(DomainError::InvalidScope(
                "this folder cannot be watched".to_owned()
            )),
            HuginnProtocolError::InvalidRequest {
                code: "invalidScope".to_owned(),
                message: "this folder cannot be watched".to_owned(),
            }
        );
    }

    #[test]
    fn a_root_across_a_mount_point_opens() {
        super::open_root_dir(std::path::Path::new("/proc"))
            .expect("a root behind a mount point opens");
    }

    #[test]
    fn a_symlink_on_the_way_to_a_root_is_still_refused() {
        let base = tempfile::tempdir().expect("tempdir");
        let real = base.path().join("real");
        std::fs::create_dir(&real).expect("real dir");
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let canonical = base.path().canonicalize().expect("canonical base");
        super::open_root_dir(&canonical.join("real")).expect("the real root opens");
        assert!(super::open_root_dir(&canonical.join("link")).is_err());
    }
}

/// Opens `relative` beneath an already-confined directory descriptor.
pub(crate) fn open_beneath(dir: &File, relative: &Path, flags: OFlags) -> io::Result<File> {
    Ok(File::from(openat2(
        dir,
        relative.as_os_str(),
        flags,
        Mode::empty(),
        RESOLVE,
    )?))
}

pub(crate) fn read_flags() -> OFlags {
    READ_FLAGS
}

pub(crate) fn directory_flags() -> OFlags {
    DIRECTORY_FLAGS
}

/// Filesystem facts captured per directory entry without following links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryStat {
    pub kind: FileEntryKind,
    pub byte_len: u64,
    pub modified_at: Option<OffsetDateTime>,
}

pub(crate) fn stat_entry(dir: &File, name: &std::ffi::OsStr) -> io::Result<EntryStat> {
    let stat = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)?;
    Ok(EntryStat {
        kind: entry_kind(stat.st_mode),
        byte_len: u64::try_from(stat.st_size).unwrap_or(0),
        modified_at: i64::try_from(stat.st_mtime_nsec)
            .ok()
            .and_then(|nanos| modified_from(stat.st_mtime, nanos)),
    })
}

pub(crate) fn entry_kind(mode: u32) -> FileEntryKind {
    match mode & MODE_FORMAT_MASK {
        0o004_0000 => FileEntryKind::Directory,
        0o010_0000 => FileEntryKind::File,
        0o012_0000 => FileEntryKind::Symlink,
        _ => FileEntryKind::Other,
    }
}

fn modified_from(secs: i64, nanos: i64) -> Option<OffsetDateTime> {
    let base = OffsetDateTime::from_unix_timestamp(secs).ok()?;
    base.replace_nanosecond(nanos.clamp(0, 999_999_999) as u32)
        .ok()
}

/// Deterministic state revision for one observed entry: length plus
/// modification nanoseconds. Content truth is re-established by per-chunk
/// BLAKE3 digests on every read; the revision makes stale reads rejectable.
pub(crate) fn entry_revision(byte_len: u64, modified_at: Option<OffsetDateTime>) -> Digest {
    let nanos = modified_at.map(time::OffsetDateTime::unix_timestamp_nanos);
    Digest::hash(format!("{byte_len}:{}", nanos.unwrap_or(-1)).as_bytes())
}

/// Deterministic digest over a whole ordered listing.
pub(crate) fn listing_revision(rows: &[(String, EntryStat)]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    for (name, stat) in rows {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(&[kind_byte(stat.kind)]);
        hasher.update(&stat.byte_len.to_le_bytes());
        let nanos = stat
            .modified_at
            .map(time::OffsetDateTime::unix_timestamp_nanos);
        hasher.update(&nanos.unwrap_or(-1).to_le_bytes());
    }
    Digest::new(hasher.finalize().into())
}

pub(crate) const fn kind_byte(kind: FileEntryKind) -> u8 {
    match kind {
        FileEntryKind::File => 0,
        FileEntryKind::Directory => 1,
        FileEntryKind::Symlink => 2,
        FileEntryKind::Other => 3,
    }
}

/// Media classification from the file-name extension. Classification is not
/// authorization: media policies are enforced against this value everywhere.
pub(crate) fn media_type_for_name(name: &str) -> Option<&'static str> {
    let extension = name.rsplit_once('.')?.1.to_ascii_lowercase();
    match extension.as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "svg" => Some("image/svg+xml"),
        "pdf" => Some("application/pdf"),
        "txt" => Some("text/plain"),
        "md" => Some("text/markdown"),
        "json" => Some("application/json"),
        "toml" => Some("application/toml"),
        "csv" => Some("text/csv"),
        "zip" => Some("application/zip"),
        "html" | "htm" => Some("text/html"),
        _ => None,
    }
}

/// The wire-safe projection of a declared root: handle identity and policy
/// only. The canonical host path never crosses the protocol.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootHandle {
    pub root_id: FileRootId,
    pub display_name: String,
    pub access: FileRootAccess,
    pub watch_policy: FileWatchPolicy,
    pub max_object_bytes: u64,
    pub media_policy: FileMediaPolicy,
}

/// The registry-declared root set. Construction is the only place host paths
/// enter this crate; every later operation resolves through [`RootCatalog::get`].
#[derive(Clone, Debug, Default)]
pub struct RootCatalog {
    roots: BTreeMap<FileRootId, FileRoot>,
}

impl RootCatalog {
    pub fn new(roots: Vec<FileRoot>) -> Result<Self, HuginnProtocolError> {
        let mut by_id = BTreeMap::new();
        for root in roots {
            if by_id.insert(root.root_id.clone(), root).is_some() {
                return Err(invalid_file("declared root id is not unique"));
            }
        }
        Ok(Self { roots: by_id })
    }

    pub fn handles(&self) -> Vec<RootHandle> {
        self.roots
            .values()
            .map(|root| RootHandle {
                root_id: root.root_id.clone(),
                display_name: root.display_name.clone(),
                access: root.access,
                watch_policy: root.watch_policy,
                max_object_bytes: root.max_object_bytes.get(),
                media_policy: root.media_policy.clone(),
            })
            .collect()
    }

    pub fn get(&self, root_id: &FileRootId) -> Result<&FileRoot, HuginnProtocolError> {
        self.roots
            .get(root_id)
            .ok_or_else(|| file_not_found("fileRoot", root_id.to_string()))
    }
}
