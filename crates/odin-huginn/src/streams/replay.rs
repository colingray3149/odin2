use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use odin_domain::huginn::{
    ArtifactRef, HuginnMessage, HuginnProtocolError, Sequence, StreamFrame, StreamId,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub trait StreamRetentionLease: Send + Sync {}

/// Frees the content a durable frame names once the replay store has dropped the frame: the replay
/// row is the only owner of a feed payload.
pub trait ReplayContentRetirement: Send + Sync {
    fn retire(&self, dropped: &[ArtifactRef]) -> Result<(), HuginnProtocolError>;
}

/// A stored item read for its frame only; the message is skipped, not decoded.
#[derive(Deserialize)]
struct StoredFrame {
    frame: StreamFrame,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct MultiplexedItem {
    pub frame: StreamFrame,
    pub message: HuginnMessage,
    #[serde(skip)]
    retention: Option<Arc<dyn StreamRetentionLease>>,
}

impl MultiplexedItem {
    pub fn new(frame: StreamFrame, message: HuginnMessage) -> Self {
        Self {
            frame,
            message,
            retention: None,
        }
    }

    pub fn with_retention(
        frame: StreamFrame,
        message: HuginnMessage,
        lease: Arc<dyn StreamRetentionLease>,
    ) -> Self {
        Self {
            frame,
            message,
            retention: Some(lease),
        }
    }

    pub(crate) fn into_message_and_retention(
        self,
    ) -> (HuginnMessage, Option<Arc<dyn StreamRetentionLease>>) {
        (self.message, self.retention)
    }
}

impl fmt::Debug for MultiplexedItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiplexedItem")
            .field("frame", &self.frame)
            .field("message", &self.message)
            .finish()
    }
}

impl PartialEq for MultiplexedItem {
    fn eq(&self, other: &Self) -> bool {
        self.frame == other.frame && self.message == other.message
    }
}

impl Eq for MultiplexedItem {}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayError {
    #[error("stream replay storage unavailable: {0}")]
    Storage(String),
    #[error("stream replay record is invalid: {0}")]
    InvalidRecord(String),
    #[error("stream {stream_id} sequence {received} does not follow head {head}")]
    SequenceGap {
        stream_id: String,
        head: u64,
        received: u64,
    },
    #[error("cursor {after} for stream {stream_id} is no longer retained")]
    CursorExpired { stream_id: String, after: u64 },
    #[error("stream replay item exceeds {limit} bytes")]
    ItemTooLarge { limit: u64 },
    #[error("stream replay request exceeds bounded batch {limit}")]
    BatchTooLarge { limit: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBatch {
    pub stream_id: StreamId,
    pub after: Sequence,
    pub head: Sequence,
    pub items: Vec<MultiplexedItem>,
}

#[derive(Clone)]
pub struct DurableReplayStore {
    connection: Arc<Mutex<Connection>>,
    max_events_per_stream: usize,
    max_item_bytes: u64,
    retirement: Option<Arc<dyn ReplayContentRetirement>>,
}

impl DurableReplayStore {
    pub fn open(
        path: impl AsRef<Path>,
        max_events_per_stream: usize,
        max_item_bytes: u64,
    ) -> Result<Self, ReplayError> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| {
                ReplayError::Storage(format!("creating {}: {error}", parent.display()))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(
                    |error| ReplayError::Storage(format!("securing {}: {error}", parent.display())),
                )?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .map_err(|error| {
                    ReplayError::Storage(format!("creating {}: {error}", path.display()))
                })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|error| {
                ReplayError::Storage(format!("securing {}: {error}", path.display()))
            })?;
        }
        let connection = Connection::open(path).map_err(|error| {
            ReplayError::Storage(format!("opening {}: {error}", path.display()))
        })?;
        connection
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; {STREAM_ITEMS_SCHEMA}"
            ))
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            max_events_per_stream: max_events_per_stream.max(1),
            max_item_bytes: max_item_bytes.max(1),
            retirement: None,
        })
    }

    pub fn in_memory(
        max_events_per_stream: usize,
        max_item_bytes: u64,
    ) -> Result<Self, ReplayError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        connection
            .execute_batch(STREAM_ITEMS_SCHEMA)
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            max_events_per_stream: max_events_per_stream.max(1),
            max_item_bytes: max_item_bytes.max(1),
            retirement: None,
        })
    }

    /// Hands each dropped frame's content to `retirement`, after the drop commits.
    pub fn with_content_retirement(mut self, retirement: Arc<dyn ReplayContentRetirement>) -> Self {
        self.retirement = Some(retirement);
        self
    }

    pub fn append(&self, item: &MultiplexedItem) -> Result<(), ReplayError> {
        if item.frame.content.byte_len > self.max_item_bytes {
            return Err(ReplayError::ItemTooLarge {
                limit: self.max_item_bytes,
            });
        }
        let sequence = as_sql_sequence(item.frame.sequence)?;
        let mut encoded = Vec::new();
        ciborium::into_writer(item, &mut encoded)
            .map_err(|error| ReplayError::InvalidRecord(format!("encoding the item: {error}")))?;
        let byte_len = i64::try_from(encoded.len()).map_err(|error| {
            ReplayError::InvalidRecord(format!("{} bytes do not fit i64: {error}", encoded.len()))
        })?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > self.max_item_bytes {
            return Err(ReplayError::ItemTooLarge {
                limit: self.max_item_bytes,
            });
        }
        let mut id_buf = [0u8; UUID_TEXT_LEN];
        let stream_id = bind_stream_id(&item.frame.stream_id, &mut id_buf);
        let mut connection = self
            .connection
            .lock()
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        let head = cached_aggregate(&transaction, SQL_MAX_SEQUENCE, stream_id)?;
        let expected = head
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| ReplayError::InvalidRecord(format!("head {head:?} has no successor")))?;
        if sequence != expected {
            return Err(ReplayError::SequenceGap {
                stream_id: stream_id.to_owned(),
                head: u64::try_from(head.unwrap_or(0)).unwrap_or(0),
                received: item.frame.sequence.get(),
            });
        }
        {
            let mut statement = transaction
                .prepare_cached(SQL_INSERT)
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            statement
                .execute(params![stream_id, sequence, encoded, byte_len])
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
        }
        let keep = i64::try_from(self.max_events_per_stream).map_err(|error| {
            ReplayError::Storage(format!(
                "retention {} does not fit i64: {error}",
                self.max_events_per_stream
            ))
        })?;
        // Sequences start at 1 and have no gaps, so `sequence <= keep` means
        // the retention predicate deletes nothing.
        let mut dropped = Vec::new();
        if sequence > keep {
            let mut statement = transaction
                .prepare_cached(SQL_DELETE_EXPIRED)
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            dropped = collect_blobs(statement.query(params![stream_id, keep]))?;
        }
        transaction
            .commit()
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        drop(connection);
        self.retire(stream_id, &dropped);
        Ok(())
    }

    /// Drops every frame but the head of each stream whose head is older than `cutoff`: a session that
    /// quiet is over or idle, its producer still resumes after the kept head, and the ledger keeps the
    /// full history. Returns how many streams and frames were dropped.
    pub fn expire_quiet_streams(
        &self,
        cutoff: OffsetDateTime,
    ) -> Result<(usize, usize), ReplayError> {
        let heads = {
            let connection = self
                .connection
                .lock()
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let mut statement = connection
                .prepare(SQL_STREAM_SPANS)
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let mut heads = Vec::new();
            for row in rows {
                let (stream_id, first, head) =
                    row.map_err(|error| ReplayError::Storage(error.to_string()))?;
                if first < head {
                    heads.push((stream_id, head));
                }
            }
            heads
        };
        let (mut streams, mut frames) = (0, 0);
        for (stream_id, head) in heads {
            let dropped = {
                let mut connection = self
                    .connection
                    .lock()
                    .map_err(|error| ReplayError::Storage(error.to_string()))?;
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(|error| ReplayError::Storage(error.to_string()))?;
                let encoded: Vec<u8> = transaction
                    .query_row(SQL_ITEM, params![stream_id, head], |row| row.get(0))
                    .map_err(|error| ReplayError::Storage(error.to_string()))?;
                if decode_frame(&encoded)?.produced_at >= cutoff {
                    continue;
                }
                let dropped = {
                    let mut statement = transaction
                        .prepare(SQL_DELETE_BELOW)
                        .map_err(|error| ReplayError::Storage(error.to_string()))?;
                    collect_blobs(statement.query(params![stream_id, head]))?
                };
                transaction
                    .commit()
                    .map_err(|error| ReplayError::Storage(error.to_string()))?;
                dropped
            };
            streams += 1;
            frames += dropped.len();
            self.retire(&stream_id, &dropped);
        }
        if streams > 0 {
            self.compact()?;
        }
        Ok((streams, frames))
    }

    /// Gives the file back once most of it is free pages (the first expiry on a store that never had
    /// one); otherwise SQLite reuses the free pages as it grows.
    fn compact(&self) -> Result<(), ReplayError> {
        let connection = self
            .connection
            .lock()
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        let pragma = |name: &str| -> Result<i64, ReplayError> {
            connection
                .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
                .map_err(|error| ReplayError::Storage(error.to_string()))
        };
        if pragma("freelist_count")? * 2 > pragma("page_count")? {
            connection
                .execute_batch("VACUUM")
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
        }
        Ok(())
    }

    fn retire(&self, stream_id: &str, dropped: &[Vec<u8>]) {
        let Some(retirement) = &self.retirement else {
            return;
        };
        if dropped.is_empty() {
            return;
        }
        let content = dropped
            .iter()
            .map(|encoded| decode_frame(encoded).map(|frame| frame.content))
            .collect::<Result<Vec<_>, _>>();
        let result = content
            .map_err(|error| error.to_string())
            .and_then(|content| {
                retirement
                    .retire(&content)
                    .map_err(|error| error.to_string())
            });
        // The frames are already gone; their content stays on disk until reclaimed by hand.
        if let Err(error) = result {
            tracing::warn!(
                stream = stream_id,
                frames = dropped.len(),
                %error,
                "replay store dropped frames whose published content could not be retired"
            );
        }
    }

    pub fn head(&self, stream_id: &StreamId) -> Result<Sequence, ReplayError> {
        let connection = self
            .connection
            .lock()
            .map_err(|error| ReplayError::Storage(error.to_string()))?;
        let mut id_buf = [0u8; UUID_TEXT_LEN];
        let stream_id = bind_stream_id(stream_id, &mut id_buf);
        let head = cached_aggregate(&connection, SQL_MAX_SEQUENCE, stream_id)?.unwrap_or(0);
        Ok(Sequence::new(u64::try_from(head).map_err(|error| {
            ReplayError::InvalidRecord(format!("head {head} is negative: {error}"))
        })?))
    }

    pub fn replay(
        &self,
        stream_id: &StreamId,
        after: Sequence,
        through: Sequence,
        batch_limit: usize,
    ) -> Result<ReplayBatch, ReplayError> {
        if through < after {
            return Err(ReplayError::InvalidRecord(format!(
                "replay through {through} is before {after}"
            )));
        }
        let requested = through.get().saturating_sub(after.get());
        let encoded_rows = {
            let connection = self
                .connection
                .lock()
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let mut id_buf = [0u8; UUID_TEXT_LEN];
            let bound_id = bind_stream_id(stream_id, &mut id_buf);
            let first = cached_aggregate(&connection, SQL_MIN_SEQUENCE, bound_id)?;
            if let Some(first) = first {
                let first = u64::try_from(first).map_err(|error| {
                    ReplayError::InvalidRecord(format!(
                        "first sequence {first} is negative: {error}"
                    ))
                })?;
                if after.get().saturating_add(1) < first && after < through {
                    return Err(ReplayError::CursorExpired {
                        stream_id: stream_id.to_string(),
                        after: after.get(),
                    });
                }
            } else if after < through {
                return Err(ReplayError::CursorExpired {
                    stream_id: stream_id.to_string(),
                    after: after.get(),
                });
            }
            if requested > u64::try_from(batch_limit).unwrap_or(u64::MAX) {
                return Err(ReplayError::BatchTooLarge { limit: batch_limit });
            }
            let mut statement = connection
                .prepare_cached(SQL_REPLAY)
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let rows = statement
                .query_map(
                    params![bound_id, as_sql_sequence(after)?, as_sql_sequence(through)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|error| ReplayError::Storage(error.to_string()))?;
            let mut encoded_rows =
                Vec::with_capacity(usize::try_from(requested).unwrap_or(batch_limit));
            for row in rows {
                encoded_rows.push(row.map_err(|error| ReplayError::Storage(error.to_string()))?);
            }
            encoded_rows
        };
        let mut items = Vec::with_capacity(encoded_rows.len());
        for encoded in encoded_rows {
            let item: MultiplexedItem =
                ciborium::from_reader(encoded.as_slice()).map_err(|error| {
                    ReplayError::InvalidRecord(format!("decoding an item: {error}"))
                })?;
            if item.frame.stream_id != *stream_id
                || item.frame.sequence <= after
                || item.frame.sequence > through
            {
                return Err(ReplayError::InvalidRecord(format!(
                    "stored frame {} sequence {} is outside {stream_id} ({after}, {through}]",
                    item.frame.stream_id, item.frame.sequence
                )));
            }
            items.push(item);
        }
        if u64::try_from(items.len()).unwrap_or(u64::MAX) != requested {
            return Err(ReplayError::CursorExpired {
                stream_id: stream_id.to_string(),
                after: after.get(),
            });
        }
        Ok(ReplayBatch {
            stream_id: *stream_id,
            after,
            head: through,
            items,
        })
    }
}

/// A hyphenated UUID's text length: the buffer a stream id is bound from.
const UUID_TEXT_LEN: usize = 36;
const STREAM_ITEMS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS stream_items (
        stream_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        encoded BLOB NOT NULL,
        byte_len INTEGER NOT NULL,
        PRIMARY KEY(stream_id, sequence)
    );";
const SQL_MAX_SEQUENCE: &str = "SELECT MAX(sequence) FROM stream_items WHERE stream_id = ?1";
const SQL_MIN_SEQUENCE: &str = "SELECT MIN(sequence) FROM stream_items WHERE stream_id = ?1";
const SQL_INSERT: &str =
    "INSERT INTO stream_items(stream_id, sequence, encoded, byte_len) VALUES (?1, ?2, ?3, ?4)";
const SQL_DELETE_EXPIRED: &str = "DELETE FROM stream_items
                 WHERE stream_id = ?1 AND sequence <= (
                    SELECT COALESCE(MAX(sequence), 0) - ?2 FROM stream_items WHERE stream_id = ?1
                 )
                 RETURNING encoded";
const SQL_STREAM_SPANS: &str =
    "SELECT stream_id, MIN(sequence), MAX(sequence) FROM stream_items GROUP BY stream_id";
const SQL_ITEM: &str = "SELECT encoded FROM stream_items WHERE stream_id = ?1 AND sequence = ?2";
const SQL_DELETE_BELOW: &str =
    "DELETE FROM stream_items WHERE stream_id = ?1 AND sequence < ?2 RETURNING encoded";
const SQL_REPLAY: &str = "SELECT encoded FROM stream_items
                 WHERE stream_id = ?1 AND sequence > ?2 AND sequence <= ?3
                 ORDER BY sequence ASC";

fn bind_stream_id<'a>(stream_id: &StreamId, buffer: &'a mut [u8; UUID_TEXT_LEN]) -> &'a str {
    stream_id.as_uuid().hyphenated().encode_lower(buffer)
}

fn cached_aggregate(
    connection: &Connection,
    sql: &str,
    stream_id: &str,
) -> Result<Option<i64>, ReplayError> {
    let mut statement = connection
        .prepare_cached(sql)
        .map_err(|error| ReplayError::Storage(error.to_string()))?;
    let value: Option<Option<i64>> = statement
        .query_row([stream_id], |row| row.get(0))
        .optional()
        .map_err(|error| ReplayError::Storage(error.to_string()))?;
    Ok(value.flatten())
}

fn collect_blobs(rows: rusqlite::Result<rusqlite::Rows<'_>>) -> Result<Vec<Vec<u8>>, ReplayError> {
    let mut rows = rows.map_err(|error| ReplayError::Storage(error.to_string()))?;
    let mut blobs = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| ReplayError::Storage(error.to_string()))?
    {
        blobs.push(
            row.get(0)
                .map_err(|error| ReplayError::Storage(error.to_string()))?,
        );
    }
    Ok(blobs)
}

fn decode_frame(encoded: &[u8]) -> Result<StreamFrame, ReplayError> {
    ciborium::from_reader::<StoredFrame, _>(encoded)
        .map(|stored| stored.frame)
        .map_err(|error| ReplayError::InvalidRecord(format!("decoding a frame: {error}")))
}

fn as_sql_sequence(sequence: Sequence) -> Result<i64, ReplayError> {
    i64::try_from(sequence.get()).map_err(|error| {
        ReplayError::InvalidRecord(format!("sequence {sequence} does not fit i64: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use odin_domain::huginn::{
        ArtifactKind, ArtifactRef, HuginnMessage, HuginnProtocolError, LiveSessionId,
        LiveStreamKind, Sequence, StreamFrame, StreamId,
    };
    use odin_domain::{ArtifactId, Digest, LaneId};
    use time::OffsetDateTime;

    use super::{DurableReplayStore, MultiplexedItem, ReplayError};

    #[test]
    fn a_store_in_a_new_nested_folder_is_private_and_replays_what_was_appended() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let parent_dir = root.path().join("nested").join("streams");
        let db_path = parent_dir.join("replay.sqlite3");
        let store =
            DurableReplayStore::open(&db_path, 100, 1024 * 1024).expect("open nested store");
        let mode =
            |path: &std::path::Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&parent_dir), 0o700);
        assert_eq!(mode(&db_path), 0o600);

        let stream_id = StreamId::parse("00000000-0000-4000-8000-000000000001").expect("stream id");
        let appended = item(stream_id, 1);
        store.append(&appended).expect("append item");
        let batch = store
            .replay(&stream_id, Sequence::new(0), Sequence::new(1), 10)
            .expect("replay");
        assert_eq!(batch.head, Sequence::new(1));
        assert_eq!(batch.items, vec![appended]);
    }

    #[test]
    fn retention_window_drops_the_oldest_sequence_and_expires_that_cursor() {
        let store = DurableReplayStore::in_memory(2, 1024).expect("memory store");
        let stream_id = StreamId::parse("00000000-0000-4000-8000-000000000009").expect("stream id");
        for sequence in 1..=3 {
            store
                .append(&item(stream_id, sequence))
                .expect("append within retention");
        }
        assert_eq!(store.head(&stream_id).expect("head"), Sequence::new(3));
        let expired = store
            .replay(&stream_id, Sequence::new(0), Sequence::new(2), 10)
            .expect_err("cursor before the retained window");
        assert!(
            matches!(expired, ReplayError::CursorExpired { after: 0, .. }),
            "{expired}"
        );
        let batch = store
            .replay(&stream_id, Sequence::new(1), Sequence::new(3), 10)
            .expect("replay retained suffix");
        assert_eq!(
            batch
                .items
                .iter()
                .map(|item| item.frame.sequence.get())
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    fn item(stream_id: StreamId, sequence: u64) -> MultiplexedItem {
        item_at(stream_id, sequence, OffsetDateTime::UNIX_EPOCH)
    }

    /// The content's `byte_len` carries the sequence, so retirement shows which frames went.
    fn item_at(stream_id: StreamId, sequence: u64, produced_at: OffsetDateTime) -> MultiplexedItem {
        MultiplexedItem::new(
            StreamFrame {
                stream_id,
                kind: LiveStreamKind::SimulationTelemetry,
                sequence: Sequence::new(sequence),
                control_revision: 1,
                produced_at,
                key_frame: true,
                content: ArtifactRef {
                    artifact_id: ArtifactId::parse("00000000-0000-4000-8000-000000000002")
                        .expect("artifact id"),
                    session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000003")
                        .expect("session id"),
                    lane_id: LaneId::new("lane-test").expect("lane id"),
                    kind: ArtifactKind::File,
                    display_name: "test.dat".to_owned(),
                    media_type: "application/octet-stream".to_owned(),
                    byte_len: sequence,
                    content_digest: Digest::new([1u8; 32]),
                },
            },
            HuginnMessage::ProtocolError(HuginnProtocolError::unavailable("test", "test frame")),
        )
    }
}
