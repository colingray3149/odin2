//! Durable session journals, content-addressed blobs, and replay joins.

pub mod fs;
pub mod replay;
pub mod segment;

use async_trait::async_trait;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

use odin_domain::huginn::{
    CommandOutcome, CommandReceipt, EventSeq, HistoryPage, HistoryQuery, LiveCommand, LiveError,
    LiveEvent, LiveEventBody, LiveEventValidationError, LiveSessionId, LiveSessionState,
    SessionEpoch, SessionManifest,
};
use odin_domain::{CommandId, Digest, EventId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

pub const LIVE_SCHEMA_VERSION: u16 = 1;
pub const MAX_BLOB_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_JOURNAL_COMMANDS: usize = 65_536;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("session {0} already exists with a different manifest")]
    SessionExists(LiveSessionId),
    #[error("live ledger is journal-degraded; reopen to reconcile")]
    JournalDegraded,
    #[error("change journal invariant violated: {0}")]
    JournalInvariant(String),
    #[error("session {0} is unknown")]
    SessionMissing(LiveSessionId),
    #[error("command {0} is unknown")]
    CommandMissing(CommandId),
    #[error("command {0} targets a different session")]
    CommandSessionMismatch(CommandId),
    #[error("command {0} already completed with a different outcome")]
    OutcomeConflict(CommandId),
    #[error("event {0} already exists")]
    DuplicateEvent(EventId),
    #[error(transparent)]
    InvalidEvent(#[from] LiveEventValidationError),
    #[error("epoch {actual} is not admissible for a session at epoch {current}")]
    StaleEpoch {
        current: SessionEpoch,
        actual: SessionEpoch,
    },
    #[error("event or terminal sequence is exhausted")]
    SequenceExhausted,
    #[error("session journal exceeded the {limit} command ceiling")]
    JournalFull { limit: usize },
    #[error("blob exceeds the {limit} byte ceiling")]
    BlobTooLarge { limit: u64 },
    #[error("blob {0} is unknown")]
    BlobMissing(String),
    #[error("blob content does not match its recorded digest")]
    BlobCorrupt,
    #[error("canonical CBOR codec: {0}")]
    Codec(String),
    #[error(transparent)]
    Segment(#[from] segment::SegmentError),
    #[error("ledger mutex is poisoned")]
    Poisoned,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Clone, Debug)]
pub struct NewLiveEvent {
    pub session_id: LiveSessionId,
    pub event_id: EventId,
    pub occurred_at: OffsetDateTime,
    pub body: LiveEventBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandJournalEntry {
    pub command: LiveCommand,
    pub receipt: CommandReceipt,
    pub recorded_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_identity: Option<u8>,
}

/// One durable change-journal entry: a session whose event head moved,
/// observed at the ledger's global arrival position.
#[derive(Clone, Debug)]
pub struct SessionChange {
    pub position: u64,
    pub session_id: LiveSessionId,
    pub head: EventSeq,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerSession {
    pub manifest: SessionManifest,
    pub epoch: SessionEpoch,
    pub head: EventSeq,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BlobKind {
    Terminal,
    Transfer,
}

#[derive(Clone, Debug)]
pub struct SessionBlob {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub kind: BlobKind,
    pub bytes: Vec<u8>,
}

/// Where blob bytes come from. `HashedFile` is an already-hashed file
/// positioned at byte 0: the store copies it and checks the length, and
/// does not hash the bytes again.
#[derive(Debug)]
pub enum BlobSource {
    Bytes(SessionBlob),
    File {
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        kind: BlobKind,
        source: PathBuf,
    },
    HashedFile {
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        kind: BlobKind,
        source: std::fs::File,
        byte_len: u64,
        digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobRef {
    pub session_id: LiveSessionId,
    pub epoch: SessionEpoch,
    pub kind: BlobKind,
    pub digest: Digest,
    pub byte_len: u64,
}

pub struct BlobStream {
    pub blob: BlobRef,
    file: std::fs::File,
    remaining: u64,
}

impl BlobStream {
    pub(crate) fn new(blob: BlobRef, file: std::fs::File) -> Self {
        let remaining = blob.byte_len;
        Self {
            blob,
            file,
            remaining,
        }
    }

    pub const fn remaining(&self) -> u64 {
        self.remaining
    }

    pub const fn byte_len(&self) -> u64 {
        self.blob.byte_len
    }

    pub fn reset(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.remaining = self.blob.byte_len;
        Ok(())
    }
}

impl Read for BlobStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let length = usize::try_from(self.remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "blob length overflow"))?;
        let read = self.file.read(&mut buffer[..length])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalCursorRecord {
    pub sequence: u64,
    pub snapshot_digest: Option<Digest>,
    pub columns: u16,
    pub rows: u16,
}

pub fn encode_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, LedgerError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map_err(|error| LedgerError::Codec(error.to_string()))?;
    Ok(bytes)
}

pub fn decode_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, LedgerError> {
    ciborium::from_reader(std::io::Cursor::new(bytes))
        .map_err(|error| LedgerError::Codec(error.to_string()))
}

pub fn digest_hex(digest: &Digest) -> String {
    let display = digest.to_string();
    display
        .strip_prefix("blake3:")
        .unwrap_or(&display)
        .to_owned()
}

pub fn event_blob_digest(body: &LiveEventBody) -> Option<Digest> {
    match body {
        LiveEventBody::ArtifactPublished(artifact) => Some(artifact.content_digest),
        LiveEventBody::TerminalSnapshot(reference) => Some(reference.content_digest),
        LiveEventBody::TerminalDelta(reference) => Some(reference.content_digest),
        _ => None,
    }
}

/// The session state after `body`: the one fold every journal replay uses.
pub fn state_after(state: LiveSessionState, body: &LiveEventBody) -> LiveSessionState {
    match body {
        LiveEventBody::SessionStateChanged(change) => change.current,
        LiveEventBody::SessionClosed(_) => LiveSessionState::Ended,
        LiveEventBody::Error(_) => LiveSessionState::Failed,
        _ => state,
    }
}

pub fn live_error(error: LedgerError) -> LiveError {
    match error {
        LedgerError::SessionMissing(session) => LiveError::NotFound {
            object_kind: "session".to_owned(),
            object_id: session.to_string(),
        },
        LedgerError::CommandMissing(command) => LiveError::NotFound {
            object_kind: "command".to_owned(),
            object_id: command.to_string(),
        },
        LedgerError::BlobMissing(blob) => LiveError::NotFound {
            object_kind: "blob".to_owned(),
            object_id: blob,
        },
        LedgerError::StaleEpoch { current, actual } => LiveError::EpochMismatch {
            expected: current,
            actual,
        },
        LedgerError::BlobTooLarge { limit } => LiveError::ResourceLimit {
            limit: format!("blob bytes {limit}"),
        },
        LedgerError::JournalFull { limit } => LiveError::ResourceLimit {
            limit: format!("command journal rows {limit}"),
        },
        LedgerError::InvalidEvent(error) => LiveError::InvalidRequest {
            code: "invalid_event".to_owned(),
            message: error.to_string(),
        },
        LedgerError::SessionExists(session) => LiveError::Conflict {
            code: "session_exists".to_owned(),
            message: session.to_string(),
        },
        LedgerError::DuplicateEvent(event) => LiveError::Conflict {
            code: "duplicate_event".to_owned(),
            message: event.to_string(),
        },
        LedgerError::CommandSessionMismatch(command) | LedgerError::OutcomeConflict(command) => {
            LiveError::Conflict {
                code: "command_conflict".to_owned(),
                message: command.to_string(),
            }
        }
        LedgerError::SequenceExhausted => LiveError::ResourceLimit {
            limit: "live sequence exhausted".to_owned(),
        },
        LedgerError::JournalDegraded => LiveError::Unavailable {
            code: "journal_degraded".to_owned(),
        },
        LedgerError::JournalInvariant(detail) => LiveError::Unavailable {
            code: format!("journal_invariant: {detail}"),
        },
        LedgerError::BlobCorrupt => LiveError::Unavailable {
            code: "blob_corrupt".to_owned(),
        },
        LedgerError::Codec(detail) => LiveError::Unavailable {
            code: format!("live_ledger codec: {detail}"),
        },
        LedgerError::Segment(error) => LiveError::Unavailable {
            code: format!("live_ledger segment: {error}"),
        },
        LedgerError::Poisoned => LiveError::Unavailable {
            code: "live_ledger poisoned".to_owned(),
        },
        LedgerError::Io(error) => LiveError::Unavailable {
            code: format!("live_ledger io: {error}"),
        },
    }
}

#[async_trait]
pub trait LiveLedger: Send + Sync {
    async fn create_session(&self, manifest: SessionManifest) -> Result<(), LedgerError>;

    async fn session(&self, session: LiveSessionId) -> Result<LedgerSession, LedgerError>;

    async fn sessions(&self) -> Result<Vec<LedgerSession>, LedgerError>;

    /// One BOUNDED page of durable session metadata, in deterministic
    /// session-id order, strictly after `after`. The bound is taken at
    /// the source — at most `limit` entries leave the ledger — so a
    /// consumer pages durable history with a cursor instead of collecting
    /// it in one unbounded map. Metadata only (manifest, epoch, event
    /// head): no journal replay happens here.
    async fn sessions_after(
        &self,
        after: Option<LiveSessionId>,
        limit: usize,
    ) -> Result<Vec<LedgerSession>, LedgerError>;

    /// One BOUNDED page of the durable change journal, in global arrival
    /// order, strictly after the durable ordinal `after` (0 = the journal
    /// beginning). Each entry is a session whose event head moved and the
    /// head observed at that arrival, tagged with its own durable ordinal —
    /// a consumer persists the last ordinal ONLY after publishing the
    /// entries' payload, so a crash before that redelivers the page
    /// idempotently and no change is ever skipped.
    async fn changes_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<SessionChange>, LedgerError>;

    async fn reclaim(&self, session: LiveSessionId) -> Result<SessionEpoch, LedgerError>;

    async fn append(
        &self,
        epoch: SessionEpoch,
        event: NewLiveEvent,
    ) -> Result<LiveEvent, LedgerError>;

    async fn command(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<CommandJournalEntry>, LedgerError>;

    async fn append_command(
        &self,
        command: &LiveCommand,
    ) -> Result<CommandJournalEntry, LedgerError>;

    async fn complete_command(
        &self,
        id: CommandId,
        outcome: CommandOutcome,
    ) -> Result<(), LedgerError>;

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LedgerError>;

    async fn head(&self, session: LiveSessionId) -> Result<EventSeq, LedgerError>;

    async fn store_blob(&self, source: BlobSource) -> Result<BlobRef, LedgerError>;

    async fn read_blob(&self, blob: &BlobRef) -> Result<BlobStream, LedgerError>;
}
