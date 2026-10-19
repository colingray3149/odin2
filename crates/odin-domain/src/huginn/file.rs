//! Declared file roots, confined relative paths, and bounded file operations.

use std::fmt;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::{ArtifactId, CommandId, Digest, DomainError, RunId, SeatId};

use super::ids::{BrowserSessionId, DownloadId, FileRootId, FileWatchId, SimulationOutputId};

const MAX_RELATIVE_PATH_BYTES: usize = 1_024;
const CONTENT_TICKET_TOKEN_BYTES: usize = 43;

/// A validated lexical path beneath a declared root.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativePath(String);

impl RelativePath {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_relative_path(&value)?;
        Ok(Self(value))
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::new(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Resolves lexically beneath a validated root; no filesystem access is performed.
    pub fn resolve_under(&self, root: &FileRoot) -> PathBuf {
        root.canonical_path.join(self.as_path())
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RelativePath {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RelativePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelativePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileRootAccess {
    ReadOnly,
    ReadWrite,
}

/// Media policy attached to a root. An empty allow-list permits no file media types.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMediaPolicy {
    pub allowed_media_types: Vec<String>,
}

impl FileMediaPolicy {
    pub fn allows(&self, media_type: &str) -> bool {
        self.allowed_media_types
            .iter()
            .any(|allowed| allowed == media_type)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileWatchPolicy {
    Disabled,
    NonRecursive,
    Recursive,
}

#[derive(Clone, Debug)]
pub struct FileRootInit {
    pub root_id: FileRootId,
    pub display_name: String,
    pub canonical_path: PathBuf,
    pub access: FileRootAccess,
    pub media_policy: FileMediaPolicy,
    pub max_object_bytes: NonZeroU64,
    pub watch_policy: FileWatchPolicy,
    pub allowed_seats: Vec<SeatId>,
}

/// A kernel/registry-authorized host filesystem root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileRoot {
    pub root_id: FileRootId,
    pub display_name: String,
    pub canonical_path: PathBuf,
    pub access: FileRootAccess,
    pub media_policy: FileMediaPolicy,
    pub max_object_bytes: NonZeroU64,
    pub watch_policy: FileWatchPolicy,
    pub allowed_seats: Vec<SeatId>,
}

impl FileRoot {
    pub fn new(init: FileRootInit) -> Result<Self, DomainError> {
        let FileRootInit {
            root_id,
            display_name,
            canonical_path,
            access,
            media_policy,
            max_object_bytes,
            watch_policy,
            allowed_seats,
        } = init;
        if display_name.is_empty() || display_name.as_bytes().contains(&0) {
            return Err(invalid_file(
                "root display name must be non-empty and contain no NUL",
            ));
        }
        validate_root_path(&canonical_path)?;
        for media_type in &media_policy.allowed_media_types {
            validate_media_type(media_type)?;
        }
        Ok(Self {
            root_id,
            display_name,
            canonical_path,
            access,
            media_policy,
            max_object_bytes,
            watch_policy,
            allowed_seats,
        })
    }

    pub fn resolve(&self, relative_path: &RelativePath) -> PathBuf {
        relative_path.resolve_under(self)
    }
}

/// Authority-bearing source for a file, render, or download operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    rename_all = "camelCase",
    tag = "kind",
    content = "value",
    deny_unknown_fields
)]
pub enum ContentSource {
    Artifact(ArtifactId),
    File {
        root: FileRootId,
        relative: RelativePath,
        expected_revision: Option<Digest>,
    },
    BrowserDownload {
        session: BrowserSessionId,
        item: DownloadId,
    },
    SimulationOutput {
        run: RunId,
        output: SimulationOutputId,
    },
}

/// Request for a short-lived bearer ticket bound to one content source and byte ceiling.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentTicketRequest {
    pub command_id: CommandId,
    pub source: ContentSource,
    pub max_bytes: NonZeroU64,
}

/// Short-lived content grant returned by the typed protocol.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentTicket {
    ticket: String,
    pub source: ContentSource,
    pub media_type: String,
    pub byte_len: u64,
    pub content_digest: Digest,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl ContentTicket {
    pub fn new(
        ticket: String,
        source: ContentSource,
        media_type: String,
        byte_len: u64,
        content_digest: Digest,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let grant = Self {
            ticket,
            source,
            media_type,
            byte_len,
            content_digest,
            issued_at,
            expires_at,
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn ticket(&self) -> &str {
        &self.ticket
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.ticket.len() != CONTENT_TICKET_TOKEN_BYTES
            || !self
                .ticket
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_file("content ticket token is malformed"));
        }
        validate_media_type(&self.media_type)?;
        if self.expires_at <= self.issued_at {
            return Err(invalid_file(
                "content ticket expiry must follow its issue time",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ContentTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentTicket")
            .field("ticket", &"[REDACTED]")
            .field("source", &self.source)
            .field("media_type", &self.media_type)
            .field("byte_len", &self.byte_len)
            .field("content_digest", &self.content_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Credential-free identity projection; carries no content authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentTicketIdentity {
    pub content_digest: Digest,
    pub revision: Option<Digest>,
    pub policy_revision: u64,
    pub policy_digest: Digest,
    pub identity_digest: Digest,
    pub seat: SeatId,
    pub scope: String,
    pub capability: String,
    pub byte_len: u64,
    pub byte_ceiling: NonZeroU64,
}

impl ContentTicketIdentity {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.policy_revision == 0 || self.byte_len > self.byte_ceiling.get() {
            return Err(invalid_file("projected ticket authority is invalid"));
        }
        validate_binding_string("scope", &self.scope)?;
        validate_binding_string("capability", &self.capability)
    }
}

fn validate_binding_string(field: &str, value: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(invalid_file(format!(
            "content ticket {field} binding is malformed"
        )));
    }
    Ok(())
}

/// Bounded directory listing request. `expected_revision` makes stale views rejectable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileListRequest {
    pub root_id: FileRootId,
    pub directory: Option<RelativePath>,
    pub expected_revision: Option<Digest>,
    pub after: Option<RelativePath>,
    pub limit: NonZeroU16,
}

pub type FileQuery = FileListRequest;

/// A checked byte interval within a file.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileByteRange {
    pub offset: u64,
    pub length: NonZeroU64,
}

impl FileByteRange {
    pub fn end_exclusive(self) -> Result<u64, DomainError> {
        self.offset
            .checked_add(self.length.get())
            .ok_or_else(|| invalid_file("byte range end overflows u64"))
    }

    pub fn validate_for_len(self, byte_len: u64) -> Result<(), DomainError> {
        let end = self.end_exclusive()?;
        if self.offset >= byte_len || end > byte_len {
            return Err(invalid_file("byte range lies outside the file"));
        }
        Ok(())
    }
}

/// Bounded file read request. The expected digest encodes stale-revision rejection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileReadRequest {
    pub root_id: FileRootId,
    pub relative_path: RelativePath,
    pub expected_revision: Option<Digest>,
    pub range: Option<FileByteRange>,
    pub max_bytes: NonZeroU64,
}

impl FileReadRequest {
    pub fn validate_metadata(&self, metadata: &FileMetadata) -> Result<(), DomainError> {
        if metadata.root_id != self.root_id || metadata.relative_path != self.relative_path {
            return Err(invalid_file(
                "metadata does not identify the requested file",
            ));
        }
        if let Some(expected) = self.expected_revision {
            if metadata.revision != Some(expected) {
                return Err(invalid_file("file revision is stale"));
            }
        }
        if let Some(range) = self.range {
            range.validate_for_len(metadata.byte_len)?;
            if range.length.get() > self.max_bytes.get() {
                return Err(invalid_file("requested range exceeds the read byte limit"));
            }
        } else if metadata.byte_len > self.max_bytes.get() {
            return Err(invalid_file("file exceeds the read byte limit"));
        }
        Ok(())
    }
}

/// Request for a resumable watch beneath one declared root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileWatchRequest {
    pub watch_id: FileWatchId,
    pub root_id: FileRootId,
    pub relative_path: Option<RelativePath>,
    pub recursive: bool,
    pub expected_revision: Option<Digest>,
}

impl FileWatchRequest {
    pub fn validate_policy(&self, root: &FileRoot) -> Result<(), DomainError> {
        if self.root_id != root.root_id {
            return Err(invalid_file("the watch names a different folder"));
        }
        match (root.watch_policy, self.recursive) {
            (FileWatchPolicy::Disabled, _) => Err(invalid_file("this folder cannot be watched")),
            (FileWatchPolicy::NonRecursive, true) => Err(invalid_file(
                "this folder can only be watched one level deep",
            )),
            (FileWatchPolicy::NonRecursive | FileWatchPolicy::Recursive, _) => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

/// Metadata returned without conflating a path with an immutable ArtifactId.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    pub root_id: FileRootId,
    pub relative_path: RelativePath,
    pub entry_kind: FileEntryKind,
    pub byte_len: u64,
    pub media_type: Option<String>,
    pub revision: Option<Digest>,
    pub modified_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileListPage {
    pub root_id: FileRootId,
    pub directory: Option<RelativePath>,
    pub revision: Digest,
    pub entries: Vec<FileMetadata>,
    pub next_after: Option<RelativePath>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FileChangeKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

/// One watch change with explicit before/after revisions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDelta {
    pub watch_id: FileWatchId,
    pub root_id: FileRootId,
    pub relative_path: RelativePath,
    pub change: FileChangeKind,
    pub previous_path: Option<RelativePath>,
    pub previous_revision: Option<Digest>,
    pub metadata: Option<FileMetadata>,
}

fn validate_relative_path(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(invalid_file("relative path must not be empty"));
    }
    if value.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(invalid_file("relative path exceeds 1024 UTF-8 bytes"));
    }
    if value.as_bytes().contains(&0) {
        return Err(invalid_file("relative path must not contain NUL"));
    }
    if value.contains('\\') {
        return Err(invalid_file("relative path must not contain backslashes"));
    }
    if value.starts_with('/') {
        return Err(invalid_file("absolute paths are not permitted"));
    }

    for component in value.split('/') {
        if component.is_empty() {
            return Err(invalid_file("relative path contains an empty component"));
        }
        if matches!(component, "." | "..") {
            return Err(invalid_file("relative path contains '.' or '..'"));
        }
    }
    Ok(())
}

fn validate_root_path(value: &Path) -> Result<(), DomainError> {
    if !value.is_absolute() {
        return Err(invalid_file("file root path must be absolute"));
    }
    if value.as_os_str().is_empty() {
        return Err(invalid_file("file root path must not be empty"));
    }
    if value
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(invalid_file("file root path must be lexically normalized"));
    }
    Ok(())
}

fn validate_media_type(value: &str) -> Result<(), DomainError> {
    if value.is_empty()
        || value.split_once('/').is_none()
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(byte, b';' | b',')
        })
    {
        return Err(invalid_file("invalid bare MIME type in root media policy"));
    }
    Ok(())
}

fn invalid_file(message: impl Into<String>) -> DomainError {
    DomainError::InvalidScope(message.into())
}
