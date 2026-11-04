use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    CommandOutcome, CommandReceipt, EventSeq, HistoryPage, HistoryQuery, LiveCommand, LiveEvent,
    LiveSessionId, LiveSessionState, SessionEpoch, SessionManifest,
};
use odin_domain::{CommandId, Digest, EventId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::segment::{SegmentError, SegmentLayout, SegmentReader, SegmentWriter};
use super::{
    decode_cbor, encode_cbor, event_blob_digest, state_after, BlobRef, BlobSource, BlobStream,
    CommandJournalEntry, LedgerError, LedgerSession, LiveLedger, NewLiveEvent, SessionChange,
    DISPATCH_IDENTITY, MAX_BLOB_BYTES, MAX_JOURNAL_COMMANDS,
};

mod history;
use history::DiskCursor;

mod load;
use load::load_state;

mod journal;
pub use journal::journaled_state;

const MANIFEST_FILE: &str = "manifest.seg";
const STATE_FILE: &str = "state.seg";
const EVENTS_PREFIX: &str = "events";
const COMMANDS_PREFIX: &str = "commands";
const CHANGES_PREFIX: &str = "changes";
/// Ended or failed sessions whose last event is older than this are deleted when the ledger
/// opens, with the blobs no remaining session holds. Their pods and carriers are long released
/// and the brain's nightly history pass has read them.
pub const ENDED_SESSION_RETENTION: time::Duration = time::Duration::days(14);
/// Rotation ceiling for the change journal: any bounded page read scans at
/// most this many frames within one segment.
const CHANGE_SEGMENT_MAX_RECORDS: u64 = 8192;
/// Recent change segments that keep a frame-start index. Older pages scan.
/// The hot read is the tail, which always lives in this window.
pub(super) const CHANGE_INDEX_SEGMENTS: usize = 4;

/// Open writers kept per ledger (active sessions' event and command
/// segments, the change journal, state files); the least recent is closed.
const RESIDENT_WRITERS: usize = 64;

/// How much of the journal stays resident for the streaming observers: the recent `events` of each
/// of the most recently appended `sessions`. Pages inside a tail never touch the disk; older
/// pages and quieter sessions read the durable segments, and open reloads none, so the ledger's
/// resident events are bounded by these two numbers instead of growing with every session ever
/// journaled.
#[derive(Clone, Copy)]
struct ResidentLimits {
    events: usize,
    sessions: usize,
}

impl ResidentLimits {
    const LIVE: Self = Self {
        events: 512,
        sessions: 16,
    };
}

/// Identity of a resident segment writer. Copyable, so a hot append looks
/// the writer up without allocating a path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum WriterKey {
    Events(LiveSessionId),
    Commands(LiveSessionId),
    Changes,
    State(LiveSessionId),
}

/// Appends through the layout's resident writer. A failed write drops it,
/// so the next append resumes from disk and truncates any torn tail.
/// The hit path does not build a layout: the slot is a copyable id.
fn with_writer<T>(
    state: &mut FsState,
    key: WriterKey,
    layout: impl FnOnce() -> SegmentLayout,
    write: impl FnOnce(&mut SegmentWriter) -> Result<T, SegmentError>,
) -> Result<T, LedgerError> {
    let current = matches!(
        state.writers.get(&key),
        Some((_, writer)) if writer.is_current()
    );
    if current {
        match write(&mut state.writers.get_mut(&key).expect("resident writer").1) {
            Ok(value) => {
                state.writer_uses += 1;
                state.writers.get_mut(&key).expect("resident writer").0 = state.writer_uses;
                return Ok(value);
            }
            Err(error) => {
                state.writers.remove(&key);
                return Err(error.into());
            }
        }
    }
    state.writers.remove(&key);
    let mut writer = SegmentWriter::resume(layout())?;
    let value = write(&mut writer)?;
    if state.writers.len() >= RESIDENT_WRITERS {
        let least_recent = state
            .writers
            .iter()
            .min_by_key(|(_, (used, _))| *used)
            .map(|(key, _)| *key);
        if let Some(least_recent) = least_recent {
            state.writers.remove(&least_recent);
        }
    }
    state.writer_uses += 1;
    state.writers.insert(key, (state.writer_uses, writer));
    Ok(value)
}

pub struct FsLiveLedger {
    /// Shared so fsync and segment scans run on the blocking pool. The
    /// mutex is locked inside that task, never across `.await`.
    inner: Arc<LedgerInner>,
}

struct LedgerInner {
    root: PathBuf,
    state: Mutex<FsState>,
}

pub(super) struct FsState {
    sessions: BTreeMap<LiveSessionId, SessionState>,
    event_ids: HashSet<EventId>,
    commands: BTreeMap<CommandId, PersistedCommand>,
    /// Durable change-journal bookkeeping: total frames ever written and
    /// frames in the current (last) segment.
    change_count: u64,
    change_segment_records: u64,
    /// Open segment writers at their known tail: an append writes at the
    /// remembered offset instead of rescanning the segment.
    writers: BTreeMap<WriterKey, (u64, SegmentWriter)>,
    /// Use counter stamped on a writer at each append (least recent closes).
    writer_uses: u64,
    /// Fail-closed latch: set when a write's commit outcome is ambiguous or
    /// the change journal falls behind durable heads. EVERY source read and
    /// mutation refuses typed until reopen reconciles from durable truth.
    degraded: bool,
    /// Frame-start offsets for recent change segments, so a tail page seeks
    /// instead of hashing every preceding frame. A length mismatch drops
    /// the segment and the page falls back to a full scan.
    change_index: ChangeIndex,
    /// Where each session's next sequential disk page resumes (the frame
    /// position of the event past `after`), so a 0→head walk seeks each
    /// page to where the previous stopped instead of rescanning segments.
    disk_cursors: HashMap<LiveSessionId, DiskCursor>,
    /// Sessions holding a resident tail, least recently appended first;
    /// at most `resident.sessions`.
    resident_tails: VecDeque<LiveSessionId>,
    resident: ResidentLimits,
}

struct SessionState {
    manifest: SessionManifest,
    epoch: SessionEpoch,
    /// Durable event head. Event bodies live in the segments; only the tails [`ResidentLimits`]
    /// keeps stay resident.
    head: EventSeq,
    tail: VecDeque<LiveEvent>,
    command_count: usize,
}

#[derive(Clone)]
struct PersistedCommand {
    command: LiveCommand,
    recorded_at: OffsetDateTime,
    outcome: Option<CommandOutcome>,
    dispatch_identity: Option<u8>,
    fresh_handoff: Option<Vec<u8>>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum StateRecord {
    Epoch(SessionEpoch),
}

/// One durable change-journal frame: a session whose event head moved and
/// the head observed at that arrival.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeRecord {
    session_id: LiveSessionId,
    head: EventSeq,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "value")]
enum CommandRecord {
    Accepted {
        command: LiveCommand,
        recorded_at: OffsetDateTime,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dispatch_identity: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fresh_handoff: Option<Vec<u8>>,
    },
    Completed {
        command_id: CommandId,
        outcome: CommandOutcome,
        recorded_at: OffsetDateTime,
    },
}

impl FsLiveLedger {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LedgerError> {
        Self::open_at(root, OffsetDateTime::now_utc())
    }

    /// Opens the ledger as of `now`, the instant [`ENDED_SESSION_RETENTION`] counts from.
    pub fn open_at(root: impl AsRef<Path>, now: OffsetDateTime) -> Result<Self, LedgerError> {
        fs::create_dir_all(root.as_ref())?;
        let root = root.as_ref().canonicalize()?;
        fs::create_dir_all(root.join("sessions"))?;
        fs::create_dir_all(root.join("blobs"))?;
        let mut state = load_state(&root, now)?;
        // Derive contiguity, rotation, torn-tail recovery, and journal heads in one scan.
        let layout = SegmentLayout::Numbered {
            dir: root.join("changes"),
            prefix: CHANGES_PREFIX,
        };
        let segments = SegmentReader::numbered(&layout)?;
        if let Some((first, _)) = segments.first() {
            if *first != 0 {
                return Err(LedgerError::JournalInvariant(format!(
                    "change journal begins at segment {first}, not 0"
                )));
            }
        }
        let mut last_journaled: BTreeMap<LiveSessionId, u64> = BTreeMap::new();
        let segment_total = segments.len();
        for (position, (index, path)) in segments.iter().enumerate() {
            // Contiguous numbering: no gaps, no reordering surprises.
            if *index != position as u64 {
                return Err(LedgerError::JournalInvariant(format!(
                    "change journal segment {index} is out of sequence at position {position}"
                )));
            }
            let file_len = std::fs::metadata(path)
                .map_err(|error| {
                    LedgerError::JournalInvariant(format!(
                        "change journal segment {index} metadata unavailable: {error}"
                    ))
                })?
                .len();
            let mut frames = SegmentReader::frames(path)?;
            let mut count = 0u64;
            let mut starts = Vec::new();
            let keep_index = segment_total - position <= CHANGE_INDEX_SEGMENTS;
            loop {
                let start = frames.offset();
                let Some(record) = frames.next_frame()? else {
                    break;
                };
                let change: ChangeRecord = decode_cbor(record)?;
                let head = last_journaled.entry(change.session_id).or_insert(0);
                if change.head.get() > *head {
                    *head = change.head.get();
                }
                if keep_index {
                    starts.push(start);
                }
                count = count.checked_add(1).ok_or_else(|| {
                    LedgerError::Codec("change segment count overflow".to_owned())
                })?;
            }
            let valid_bytes = frames.valid_bytes();
            let torn_tail = file_len != valid_bytes;
            let is_last = position + 1 == segment_total;
            if !is_last {
                // Every non-last segment holds exactly the rotation ceiling
                // and is fully intact; a short or torn middle segment is
                // corruption, never a recoverable tail.
                if torn_tail || count != CHANGE_SEGMENT_MAX_RECORDS {
                    return Err(LedgerError::JournalInvariant(format!(
                        "change journal segment {index} holds {count} frames (torn: {torn_tail}), \
                         expected exactly {CHANGE_SEGMENT_MAX_RECORDS} before the final segment"
                    )));
                }
            } else if torn_tail && valid_bytes == 0 && file_len > 0 {
                return Err(LedgerError::JournalInvariant(format!(
                    "final change journal segment {index} has an unusable first frame"
                )));
            }
            // A torn final tail is recovered by truncating to the last
            // whole frame boundary; nothing after it is ever read.
            if torn_tail {
                let file = std::fs::OpenOptions::new().write(true).open(path)?;
                file.set_len(valid_bytes)?;
            }
            if keep_index {
                state.change_index.insert(*index, valid_bytes, starts);
            }
            state.change_count += count;
            state.change_segment_records = count;
        }
        // Reconcile-at-open: durable heads are the authority. A session
        // absent from the journal entirely gets a creation entry (its
        // durable head, even 0); a session whose durable head moved past
        // its last-journaled head (crash between the event and hint
        // commits) gets a synthesized entry. The transient map is dropped
        // after open: no retained historical extra map.
        {
            let mut pending: Vec<(LiveSessionId, EventSeq)> = Vec::new();
            for (session_id, session) in &state.sessions {
                let durable_head = session.head.get();
                match last_journaled.get(session_id) {
                    // Creation hint: the session exists durably but the
                    // change journal has never heard of it.
                    None => pending.push((*session_id, EventSeq::new(durable_head))),
                    Some(journaled) if *journaled < durable_head => {
                        pending.push((*session_id, EventSeq::new(durable_head)));
                    }
                    Some(_) => {}
                }
            }
            for (session_id, head) in pending {
                let mut writer = SegmentWriter::resume(SegmentLayout::Numbered {
                    dir: root.join("changes"),
                    prefix: CHANGES_PREFIX,
                })?;
                if state.change_segment_records >= CHANGE_SEGMENT_MAX_RECORDS {
                    writer.rotate()?;
                    state.change_segment_records = 0;
                }
                let start = writer.written();
                let segment = writer.index();
                writer.append(&encode_cbor(&ChangeRecord { session_id, head })?)?;
                let end = writer.written();
                writer.commit()?;
                state.change_index.note(segment, start, end);
                state.change_segment_records += 1;
                state.change_count += 1;
            }
        }
        Ok(Self {
            inner: Arc::new(LedgerInner {
                root,
                state: Mutex::new(state),
            }),
        })
    }

    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// A ledger keeping `resident` tails instead of the live ones, so a test reaches the paged
    /// reads without journaling hundreds of fsynced events.
    #[cfg(test)]
    fn with_resident(self, resident: ResidentLimits) -> Self {
        self.lock().expect("ledger state").resident = resident;
        self
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, FsState>, LedgerError> {
        self.inner
            .state
            .lock()
            .map_err(|error| LedgerError::Poisoned(error.to_string()))
    }

    fn share(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// The fail-closed gate: once a write's outcome is ambiguous or the
    /// change journal has fallen behind durable heads, EVERY source read and
    /// mutation refuses typed until reopen reconciles from durable truth.
    fn ensure_live(state: &FsState) -> Result<(), LedgerError> {
        if state.degraded {
            Err(LedgerError::JournalDegraded)
        } else {
            Ok(())
        }
    }

    fn session_dir(&self, session: LiveSessionId) -> PathBuf {
        self.inner.root.join("sessions").join(session.to_string())
    }

    fn changes_layout(&self) -> SegmentLayout {
        SegmentLayout::Numbered {
            dir: self.inner.root.join("changes"),
            prefix: CHANGES_PREFIX,
        }
    }

    /// Appends one durable change frame AFTER the event segment commit of
    /// the mutation it describes. Called only while the state lock is held;
    /// returns the entry's durable ordinal.
    fn journal_change(
        &self,
        state: &mut FsState,
        session: LiveSessionId,
        head: EventSeq,
    ) -> Result<(), LedgerError> {
        let rotate = state.change_segment_records >= CHANGE_SEGMENT_MAX_RECORDS;
        let bytes = encode_cbor(&ChangeRecord {
            session_id: session,
            head,
        })?;
        let (segment, start, end) = with_writer(
            state,
            WriterKey::Changes,
            || self.changes_layout(),
            |writer| {
                if rotate {
                    writer.rotate()?;
                }
                let segment = writer.index();
                let start = writer.written();
                writer.append(&bytes)?;
                let end = writer.written();
                writer.commit()?;
                Ok((segment, start, end))
            },
        )?;
        if rotate {
            state.change_segment_records = 0;
        }
        state.change_segment_records += 1;
        state.change_count += 1;
        state.change_index.note(segment, start, end);
        Ok(())
    }

    fn events_layout(&self, session: LiveSessionId) -> SegmentLayout {
        SegmentLayout::Numbered {
            dir: self.session_dir(session).join("events"),
            prefix: EVENTS_PREFIX,
        }
    }

    fn commands_layout(&self, session: LiveSessionId) -> SegmentLayout {
        SegmentLayout::Numbered {
            dir: self.session_dir(session).join("commands"),
            prefix: COMMANDS_PREFIX,
        }
    }

    fn blob_path(&self, digest: &Digest) -> PathBuf {
        blob_file(&self.inner.root, digest)
    }

    fn append_record<T: Serialize>(
        state: &mut FsState,
        key: WriterKey,
        layout: impl FnOnce() -> SegmentLayout,
        record: &T,
    ) -> Result<(), LedgerError> {
        let bytes = encode_cbor(record)?;
        let written = with_writer(state, key, layout, |writer| {
            writer.append(&bytes)?;
            writer.commit()
        });
        // Ambiguous: the frame may or may not have persisted. Fail closed
        // until reopen reconciles from the durable heads.
        if written.is_err() {
            state.degraded = true;
        }
        written
    }

    fn changes_after_blocking(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<SessionChange>, LedgerError> {
        let state = self.lock()?;
        Self::ensure_live(&state)?;
        let limit = limit.max(1).min(CHANGE_SEGMENT_MAX_RECORDS as usize);
        // The writer rotates BEFORE a segment would exceed
        // CHANGE_SEGMENT_MAX_RECORDS frames, so ordinal n lives in segment
        // n / CHANGE_SEGMENT_MAX_RECORDS at in-segment position
        // n % CHANGE_SEGMENT_MAX_RECORDS. The seek opens the start segment
        // DIRECTLY and reads forward only while the page needs more.
        let expected_total = state.change_count;
        if after >= expected_total {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        let mut ordinal = after;
        let mut segment = after / CHANGE_SEGMENT_MAX_RECORDS;
        let mut skip = (after % CHANGE_SEGMENT_MAX_RECORDS) as usize;
        let mut remaining = limit;
        loop {
            let path = self.changes_layout().nth_path(segment);
            if !path.exists() {
                // The state counter says ordinals remain, so a missing
                // segment is journal corruption, never a normal end.
                return Err(LedgerError::JournalInvariant(format!(
                    "change journal segment {segment} is missing while ordinals up to \
                     {expected_total} are unaccounted"
                )));
            }
            let records = change_frames(&state, &path, segment, skip, remaining)?;
            for record in records {
                let change: ChangeRecord = decode_cbor(&record)?;
                ordinal += 1;
                entries.push(SessionChange {
                    position: ordinal,
                    session_id: change.session_id,
                    head: change.head,
                });
                remaining -= 1;
                if remaining == 0 {
                    return Ok(entries);
                }
            }
            skip = 0;
            segment += 1;
            if ordinal >= expected_total {
                return Ok(entries);
            }
        }
    }
    fn append_blocking(
        &self,
        epoch: SessionEpoch,
        event: NewLiveEvent,
    ) -> Result<LiveEvent, LedgerError> {
        let mut state = self.lock()?;
        Self::ensure_live(&state)?;
        if state.event_ids.contains(&event.event_id) {
            return Err(LedgerError::DuplicateEvent(event.event_id));
        }
        let session = state
            .sessions
            .get(&event.session_id)
            .ok_or(LedgerError::SessionMissing(event.session_id))?;
        if epoch != session.epoch {
            return Err(LedgerError::StaleEpoch {
                current: session.epoch,
                actual: epoch,
            });
        }
        if let Some(digest) = event_blob_digest(&event.body) {
            if !self.blob_path(&digest).is_file() {
                return Err(LedgerError::BlobMissing(digest.to_string()));
            }
        }
        let sequence = if session.head.get() == 0 {
            EventSeq::new(1)
        } else {
            session
                .head
                .checked_increment()
                .ok_or(LedgerError::SequenceExhausted)?
        };
        let committed = LiveEvent::new(
            odin_domain::huginn::LIVE_SCHEMA_VERSION,
            event.event_id.clone(),
            event.session_id,
            epoch,
            sequence,
            event.occurred_at,
            event.body,
        )?;
        // Approved order: event frame commit -> authoritative memory ->
        // hint. Hint and event become visible to consumers under the same
        // lock, so a consumed hint always has its event readable. A hint
        // write failure latches journal-degraded (fail-closed until reopen
        // reconciles the missing hint from durable heads), as a failed frame
        // write does in `append_record`.
        Self::append_record(
            &mut state,
            WriterKey::Events(event.session_id),
            || self.events_layout(event.session_id),
            &committed,
        )?;
        state.event_ids.insert(event.event_id);
        let resident_events = state.resident.events;
        let session = state
            .sessions
            .get_mut(&event.session_id)
            .ok_or(LedgerError::SessionMissing(event.session_id))?;
        session.head = committed.sequence;
        session.tail.push_back(committed.clone());
        while session.tail.len() > resident_events {
            session.tail.pop_front();
        }
        Self::keep_tail_resident(&mut state, event.session_id);
        if let Err(error) = self.journal_change(&mut state, event.session_id, committed.sequence) {
            state.degraded = true;
            return Err(error);
        }
        Ok(committed)
    }

    /// Marks `session` the most recently appended and drops the tail of the
    /// least recent one past the resident session limit.
    fn keep_tail_resident(state: &mut FsState, session: LiveSessionId) {
        state.resident_tails.retain(|resident| *resident != session);
        state.resident_tails.push_back(session);
        if state.resident_tails.len() > state.resident.sessions {
            if let Some(quiet) = state.resident_tails.pop_front() {
                if let Some(quiet) = state.sessions.get_mut(&quiet) {
                    quiet.tail = VecDeque::new();
                }
            }
        }
    }
    fn store_blob_blocking(&self, source: BlobSource) -> Result<BlobRef, LedgerError> {
        let (session_id, epoch, kind) = match &source {
            BlobSource::Bytes(blob) => (blob.session_id, blob.epoch, blob.kind),
            BlobSource::HashedFile {
                session_id,
                epoch,
                kind,
                ..
            } => (*session_id, *epoch, *kind),
        };
        {
            let state = self.lock()?;
            Self::ensure_live(&state)?;
            let session = state
                .sessions
                .get(&session_id)
                .ok_or(LedgerError::SessionMissing(session_id))?;
            if epoch != session.epoch {
                return Err(LedgerError::StaleEpoch {
                    current: session.epoch,
                    actual: epoch,
                });
            }
        }

        let temp_dir = self.inner.root.join("blobs").join("incoming");
        fs::create_dir_all(&temp_dir)?;
        let temp_path = temp_dir.join(format!("{}.part", Uuid::new_v4()));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        let mut hasher = blake3::Hasher::new();
        let mut byte_len = 0u64;
        let mut preset = None;
        match source {
            BlobSource::Bytes(blob) => {
                byte_len = blob.bytes.len() as u64;
                if byte_len > MAX_BLOB_BYTES {
                    let _ = fs::remove_file(&temp_path);
                    return Err(LedgerError::BlobTooLarge {
                        limit: MAX_BLOB_BYTES,
                    });
                }
                hasher.update(&blob.bytes);
                output.write_all(&blob.bytes)?;
            }
            BlobSource::HashedFile {
                mut source,
                byte_len: expected_len,
                digest,
                ..
            } => {
                if expected_len > MAX_BLOB_BYTES {
                    let _ = fs::remove_file(&temp_path);
                    return Err(LedgerError::BlobTooLarge {
                        limit: MAX_BLOB_BYTES,
                    });
                }
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = source.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    byte_len =
                        byte_len
                            .checked_add(read as u64)
                            .ok_or(LedgerError::BlobTooLarge {
                                limit: MAX_BLOB_BYTES,
                            })?;
                    if byte_len > MAX_BLOB_BYTES {
                        let _ = fs::remove_file(&temp_path);
                        return Err(LedgerError::BlobTooLarge {
                            limit: MAX_BLOB_BYTES,
                        });
                    }
                    output.write_all(&buffer[..read])?;
                }
                if byte_len != expected_len {
                    let _ = fs::remove_file(&temp_path);
                    return Err(LedgerError::BlobCorrupt);
                }
                preset = Some(digest);
            }
        }
        output.flush()?;
        output.sync_all()?;
        let digest = preset.unwrap_or_else(|| Digest::new(*hasher.finalize().as_bytes()));
        let destination = self.blob_path(&digest);
        let parent = destination
            .parent()
            .ok_or_else(|| LedgerError::Codec("blob path has no parent".to_owned()))?;
        fs::create_dir_all(parent)?;
        if destination.exists() {
            fs::remove_file(&temp_path)?;
            validate_blob_file(&destination, byte_len, digest)?;
        } else {
            fs::rename(&temp_path, &destination)?;
            sync_dir(parent)?;
        }
        Ok(BlobRef {
            session_id,
            epoch,
            kind,
            digest,
            byte_len,
        })
    }
    async fn run_blocking<T, F>(&self, work: F) -> Result<T, LedgerError>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T, LedgerError> + Send + 'static,
    {
        let ledger = self.share();
        tokio::task::spawn_blocking(move || work(&ledger))
            .await
            .map_err(|error| LedgerError::Task(error.to_string()))?
    }

    fn create_session_blocking(&self, manifest: SessionManifest) -> Result<(), LedgerError> {
        let mut state = self.lock()?;
        Self::ensure_live(&state)?;
        if let Some(existing) = state.sessions.get(&manifest.session_id) {
            return if existing.manifest == manifest {
                Ok(())
            } else {
                Err(LedgerError::SessionExists(manifest.session_id))
            };
        }

        let session_dir = self.session_dir(manifest.session_id);
        fs::create_dir_all(&session_dir)?;
        let mut manifest_writer = SegmentWriter::create(SegmentLayout::Single {
            path: session_dir.join(MANIFEST_FILE),
        })?;
        manifest_writer.append(&encode_cbor(&manifest)?)?;
        manifest_writer.commit()?;
        let mut state_writer = SegmentWriter::create(SegmentLayout::Single {
            path: session_dir.join(STATE_FILE),
        })?;
        let epoch = SessionEpoch::new(1);
        state_writer.append(&encode_cbor(&StateRecord::Epoch(epoch))?)?;
        state_writer.commit()?;
        sync_dir(&session_dir)?;

        let created = manifest.session_id;
        state.sessions.insert(
            manifest.session_id,
            SessionState {
                manifest,
                epoch,
                head: EventSeq::new(0),
                tail: VecDeque::new(),
                command_count: 0,
            },
        );
        if let Err(error) = self.journal_change(&mut state, created, EventSeq::new(0)) {
            state.degraded = true;
            return Err(error);
        }
        Ok(())
    }

    fn reclaim_blocking(&self, session: LiveSessionId) -> Result<SessionEpoch, LedgerError> {
        let mut state = self.lock()?;
        Self::ensure_live(&state)?;
        let current = state
            .sessions
            .get(&session)
            .ok_or(LedgerError::SessionMissing(session))?
            .epoch;
        let next = current
            .checked_increment()
            .ok_or(LedgerError::SequenceExhausted)?;
        Self::append_record(
            &mut state,
            WriterKey::State(session),
            || SegmentLayout::Single {
                path: self.session_dir(session).join(STATE_FILE),
            },
            &StateRecord::Epoch(next),
        )?;
        state
            .sessions
            .get_mut(&session)
            .ok_or(LedgerError::SessionMissing(session))?
            .epoch = next;
        Ok(next)
    }

    fn append_command_blocking(
        &self,
        command: LiveCommand,
        fresh_handoff: Option<Vec<u8>>,
    ) -> Result<CommandJournalEntry, LedgerError> {
        let mut state = self.lock()?;
        Self::ensure_live(&state)?;
        if let Some(existing) = state.commands.get(&command.command_id) {
            if existing.command != command {
                return Err(LedgerError::CommandChanged(command.command_id.clone()));
            }
            if fresh_handoff.is_some() && existing.fresh_handoff != fresh_handoff {
                return Err(LedgerError::CommandChanged(command.command_id.clone()));
            }
            return Ok(CommandJournalEntry {
                command: command.clone(),
                receipt: CommandReceipt::Duplicate {
                    command_id: command.command_id.clone(),
                    prior_outcome: existing.outcome.clone().map(Box::new),
                },
                recorded_at: existing.recorded_at,
                dispatch_identity: existing.dispatch_identity,
            });
        }
        let session = state
            .sessions
            .get(&command.session_id)
            .ok_or(LedgerError::SessionMissing(command.session_id))?;
        if command.expected_epoch != session.epoch {
            return Err(LedgerError::StaleEpoch {
                current: session.epoch,
                actual: command.expected_epoch,
            });
        }
        if session.command_count >= MAX_JOURNAL_COMMANDS {
            return Err(LedgerError::JournalFull {
                limit: MAX_JOURNAL_COMMANDS,
            });
        }
        let recorded_at = OffsetDateTime::now_utc();
        Self::append_record(
            &mut state,
            WriterKey::Commands(command.session_id),
            || self.commands_layout(command.session_id),
            &CommandRecord::Accepted {
                command: command.clone(),
                recorded_at,
                dispatch_identity: Some(DISPATCH_IDENTITY),
                fresh_handoff: fresh_handoff.clone(),
            },
        )?;
        state.commands.insert(
            command.command_id.clone(),
            PersistedCommand {
                command: command.clone(),
                recorded_at,
                outcome: None,
                dispatch_identity: Some(DISPATCH_IDENTITY),
                fresh_handoff,
            },
        );
        state
            .sessions
            .get_mut(&command.session_id)
            .ok_or(LedgerError::SessionMissing(command.session_id))?
            .command_count += 1;
        Ok(CommandJournalEntry {
            command: command.clone(),
            receipt: CommandReceipt::Accepted {
                command_id: command.command_id.clone(),
            },
            recorded_at,
            dispatch_identity: Some(DISPATCH_IDENTITY),
        })
    }

    fn complete_command_blocking(
        &self,
        id: CommandId,
        outcome: CommandOutcome,
    ) -> Result<(), LedgerError> {
        let mut state = self.lock()?;
        Self::ensure_live(&state)?;
        let existing = state
            .commands
            .get(&id)
            .ok_or_else(|| LedgerError::CommandMissing(id.clone()))?;
        if let Some(prior) = &existing.outcome {
            return if *prior == outcome {
                Ok(())
            } else {
                Err(LedgerError::OutcomeConflict(id))
            };
        }
        let session_id = existing.command.session_id;
        Self::append_record(
            &mut state,
            WriterKey::Commands(session_id),
            || self.commands_layout(session_id),
            &CommandRecord::Completed {
                command_id: id.clone(),
                outcome: outcome.clone(),
                recorded_at: OffsetDateTime::now_utc(),
            },
        )?;
        state
            .commands
            .get_mut(&id)
            .ok_or(LedgerError::CommandMissing(id))?
            .outcome = Some(outcome);
        Ok(())
    }

    /// Hashes the blob once and returns that file sought to 0.
    fn read_blob_blocking(&self, blob: BlobRef) -> Result<BlobStream, LedgerError> {
        let path = self.blob_path(&blob.digest);
        if !path.is_file() {
            return Err(LedgerError::BlobMissing(blob.digest.to_string()));
        }
        let mut file = File::open(&path)?;
        hash_open_file(&mut file, blob.byte_len, blob.digest)?;
        Ok(BlobStream::new(blob, file))
    }
}

#[async_trait]
impl LiveLedger for FsLiveLedger {
    async fn create_session(&self, manifest: SessionManifest) -> Result<(), LedgerError> {
        self.run_blocking(move |ledger| ledger.create_session_blocking(manifest))
            .await
    }

    async fn session(&self, session: LiveSessionId) -> Result<LedgerSession, LedgerError> {
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            let session = state
                .sessions
                .get(&session)
                .ok_or(LedgerError::SessionMissing(session))?;
            Ok(to_ledger_session(session))
        })
        .await
    }

    async fn sessions(&self) -> Result<Vec<LedgerSession>, LedgerError> {
        self.run_blocking(|ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            Ok(state.sessions.values().map(to_ledger_session).collect())
        })
        .await
    }

    async fn sessions_after(
        &self,
        after: Option<LiveSessionId>,
        limit: usize,
    ) -> Result<Vec<LedgerSession>, LedgerError> {
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            // The bound is taken HERE, at the source: the ordered map yields
            // at most `limit` entries, strictly after the cursor.
            let matched: Vec<LedgerSession> = match &after {
                Some(after) => state
                    .sessions
                    .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                    .take(limit.max(1))
                    .map(|(_, session)| to_ledger_session(session))
                    .collect(),
                None => state
                    .sessions
                    .values()
                    .take(limit.max(1))
                    .map(to_ledger_session)
                    .collect(),
            };
            let mut entries = matched;
            entries.sort_by_key(|session| session.manifest.session_id);
            Ok(entries)
        })
        .await
    }

    async fn changes_after(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<Vec<SessionChange>, LedgerError> {
        self.run_blocking(move |ledger| ledger.changes_after_blocking(after, limit))
            .await
    }

    async fn reclaim(&self, session: LiveSessionId) -> Result<SessionEpoch, LedgerError> {
        self.run_blocking(move |ledger| ledger.reclaim_blocking(session))
            .await
    }

    async fn append(
        &self,
        epoch: SessionEpoch,
        event: NewLiveEvent,
    ) -> Result<LiveEvent, LedgerError> {
        self.run_blocking(move |ledger| ledger.append_blocking(epoch, event))
            .await
    }

    async fn command(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<CommandJournalEntry>, LedgerError> {
        let command = command.clone();
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            let Some(existing) = state.commands.get(&command.command_id) else {
                return Ok(None);
            };
            if existing.command != command {
                return Err(LedgerError::CommandChanged(command.command_id.clone()));
            }
            Ok(Some(CommandJournalEntry {
                command: command.clone(),
                receipt: CommandReceipt::Duplicate {
                    command_id: command.command_id.clone(),
                    prior_outcome: existing.outcome.clone().map(Box::new),
                },
                recorded_at: existing.recorded_at,
                dispatch_identity: existing.dispatch_identity,
            }))
        })
        .await
    }

    async fn command_by_id(
        &self,
        id: &CommandId,
    ) -> Result<Option<CommandJournalEntry>, LedgerError> {
        let id = id.clone();
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            Ok(state.commands.get(&id).map(|entry| CommandJournalEntry {
                command: entry.command.clone(),
                receipt: CommandReceipt::Duplicate {
                    command_id: id.clone(),
                    prior_outcome: entry.outcome.clone().map(Box::new),
                },
                recorded_at: entry.recorded_at,
                dispatch_identity: entry.dispatch_identity,
            }))
        })
        .await
    }

    async fn append_command(
        &self,
        command: &LiveCommand,
    ) -> Result<CommandJournalEntry, LedgerError> {
        let command = command.clone();
        self.run_blocking(move |ledger| ledger.append_command_blocking(command, None))
            .await
    }

    async fn append_fresh_command(
        &self,
        command: &LiveCommand,
        handoff: Vec<u8>,
    ) -> Result<CommandJournalEntry, LedgerError> {
        let command = command.clone();
        self.run_blocking(move |ledger| ledger.append_command_blocking(command, Some(handoff)))
            .await
    }

    async fn fresh_handoff(&self, command: &LiveCommand) -> Result<Option<Vec<u8>>, LedgerError> {
        let command = command.clone();
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            let Some(existing) = state.commands.get(&command.command_id) else {
                return Ok(None);
            };
            if existing.command != command {
                return Err(LedgerError::CommandChanged(command.command_id.clone()));
            }
            Ok(existing.fresh_handoff.clone())
        })
        .await
    }

    async fn pending_fresh_handoffs(&self) -> Result<Vec<(LiveCommand, Vec<u8>)>, LedgerError> {
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            Ok(state
                .commands
                .values()
                .filter_map(|entry| {
                    if entry.outcome.is_some() {
                        return None;
                    }
                    entry
                        .fresh_handoff
                        .as_ref()
                        .map(|handoff| (entry.command.clone(), handoff.clone()))
                })
                .collect())
        })
        .await
    }

    async fn has_pending_fresh(&self, session: LiveSessionId) -> Result<bool, LedgerError> {
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            Ok(state.commands.values().any(|entry| {
                entry.command.session_id == session
                    && entry.outcome.is_none()
                    && entry.fresh_handoff.is_some()
            }))
        })
        .await
    }

    async fn complete_command(
        &self,
        id: CommandId,
        outcome: CommandOutcome,
    ) -> Result<(), LedgerError> {
        self.run_blocking(move |ledger| ledger.complete_command_blocking(id, outcome))
            .await
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LedgerError> {
        self.run_blocking(move |ledger| {
            // The state lock covers the decision and any tail slice only;
            // the cold disk page reads without it so appends never queue
            // behind a reader's IO.
            let (head, resume) = {
                let state = ledger.lock()?;
                Self::ensure_live(&state)?;
                let session = state
                    .sessions
                    .get(&query.session_id)
                    .ok_or(LedgerError::SessionMissing(query.session_id))?;
                let head = session.head;
                if query.after.get() >= head.get() {
                    return Ok(HistoryPage {
                        events: Vec::new(),
                        next_after: EventSeq::new(query.after.get().min(head.get())),
                        head,
                    });
                }
                // Sequences are contiguous and ascending (load rejects a
                // gap; append assigns the next one). The resident tail
                // serves a page only when it reaches BACK to the cursor —
                // a reader lagged past its front pages the segments so no
                // event between the cursor and the tail is skipped.
                if session
                    .tail
                    .front()
                    .is_some_and(|first| first.sequence.get() <= query.after.get() + 1)
                {
                    let events = session
                        .tail
                        .iter()
                        .skip_while(|event| event.sequence.get() <= query.after.get())
                        .take(usize::from(query.limit.get()))
                        .cloned()
                        .collect::<Vec<_>>();
                    let next_after = events
                        .last()
                        .map_or(EventSeq::new(query.after.get().min(head.get())), |event| {
                            event.sequence
                        });
                    return Ok(HistoryPage {
                        events,
                        next_after,
                        head,
                    });
                }
                (head, state.disk_cursors.get(&query.session_id).copied())
            };
            let page = Self::page_events_on_disk(
                &ledger.events_layout(query.session_id),
                query.session_id,
                query.after.get(),
                query.limit.get(),
                head.get(),
                resume,
            )?;
            ledger
                .lock()?
                .disk_cursors
                .insert(query.session_id, page.resume);
            let next_after = page
                .events
                .last()
                .map_or(EventSeq::new(query.after.get().min(head.get())), |event| {
                    event.sequence
                });
            Ok(HistoryPage {
                events: page.events,
                next_after,
                head,
            })
        })
        .await
    }

    async fn head(&self, session: LiveSessionId) -> Result<EventSeq, LedgerError> {
        self.run_blocking(move |ledger| {
            let state = ledger.lock()?;
            Self::ensure_live(&state)?;
            let session = state
                .sessions
                .get(&session)
                .ok_or(LedgerError::SessionMissing(session))?;
            Ok(session.head)
        })
        .await
    }

    async fn store_blob(&self, source: BlobSource) -> Result<BlobRef, LedgerError> {
        self.run_blocking(move |ledger| ledger.store_blob_blocking(source))
            .await
    }

    async fn read_blob(&self, blob: &BlobRef) -> Result<BlobStream, LedgerError> {
        let blob = blob.clone();
        self.run_blocking(move |ledger| ledger.read_blob_blocking(blob))
            .await
    }
}

mod changes;
use changes::{change_frames, ChangeIndex};

fn to_ledger_session(session: &SessionState) -> LedgerSession {
    LedgerSession {
        manifest: session.manifest.clone(),
        epoch: session.epoch,
        head: session.head,
    }
}

/// Visits each valid frame without retaining the raw payloads. A torn tail
/// stops the visit at the last whole frame, matching `SegmentReader::scan`.
fn for_each_record(
    layout: &SegmentLayout,
    mut visit: impl FnMut(&[u8]) -> Result<(), LedgerError>,
) -> Result<(), LedgerError> {
    let paths = match layout {
        SegmentLayout::Numbered { .. } => SegmentReader::numbered(layout)?
            .into_iter()
            .map(|(_, path)| path)
            .collect::<Vec<_>>(),
        SegmentLayout::Single { path } if path.exists() => vec![path.clone()],
        SegmentLayout::Single { .. } => Vec::new(),
    };
    for path in paths {
        let mut frames = SegmentReader::frames(&path)?;
        while let Some(record) = frames.next_frame()? {
            visit(record)?;
        }
    }
    Ok(())
}

fn blob_file(root: &Path, digest: &Digest) -> PathBuf {
    let hex = digest.hex();
    root.join("blobs")
        .join(&hex[..2])
        .join(format!("{hex}.blob"))
}

fn validate_blob_file(path: &Path, expected_len: u64, expected: Digest) -> Result<(), LedgerError> {
    let mut file = File::open(path)?;
    hash_open_file(&mut file, expected_len, expected)
}

/// Hashes `file` and leaves it sought to 0 so the caller can read it back
/// without opening the path again.
fn hash_open_file(file: &mut File, expected_len: u64, expected: Digest) -> Result<(), LedgerError> {
    if file.metadata()?.len() != expected_len {
        return Err(LedgerError::BlobCorrupt);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if Digest::new(*hasher.finalize().as_bytes()) != expected {
        return Err(LedgerError::BlobCorrupt);
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), LedgerError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
