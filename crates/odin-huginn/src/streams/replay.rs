use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use odin_domain::huginn::{HuginnMessage, Sequence, StreamFrame, StreamId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub trait StreamRetentionLease: Send + Sync {}

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
    #[error("stream replay storage unavailable")]
    Storage,
    #[error("stream replay record is invalid")]
    InvalidRecord,
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
            fs::create_dir_all(parent).map_err(|_| ReplayError::Storage)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                    .map_err(|_| ReplayError::Storage)?;
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
                .map_err(|_| ReplayError::Storage)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .map_err(|_| ReplayError::Storage)?;
        }
        let connection = Connection::open(path).map_err(|_| ReplayError::Storage)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS stream_items (
                    stream_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    encoded BLOB NOT NULL,
                    byte_len INTEGER NOT NULL,
                    PRIMARY KEY(stream_id, sequence)
                 );
                 DROP INDEX IF EXISTS stream_items_by_stream;",
            )
            .map_err(|_| ReplayError::Storage)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            max_events_per_stream: max_events_per_stream.max(1),
            max_item_bytes: max_item_bytes.max(1),
        })
    }

    pub fn in_memory(
        max_events_per_stream: usize,
        max_item_bytes: u64,
    ) -> Result<Self, ReplayError> {
        let connection = Connection::open_in_memory().map_err(|_| ReplayError::Storage)?;
        connection
            .execute_batch(
                "CREATE TABLE stream_items (
                    stream_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    encoded BLOB NOT NULL,
                    byte_len INTEGER NOT NULL,
                    PRIMARY KEY(stream_id, sequence)
                 );",
            )
            .map_err(|_| ReplayError::Storage)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            max_events_per_stream: max_events_per_stream.max(1),
            max_item_bytes: max_item_bytes.max(1),
        })
    }

    pub fn append(&self, item: &MultiplexedItem) -> Result<(), ReplayError> {
        if item.frame.content.byte_len > self.max_item_bytes {
            return Err(ReplayError::ItemTooLarge {
                limit: self.max_item_bytes,
            });
        }
        let sequence = as_sql_sequence(item.frame.sequence)?;
        let mut encoded = Vec::new();
        ciborium::into_writer(item, &mut encoded).map_err(|_| ReplayError::InvalidRecord)?;
        let byte_len = i64::try_from(encoded.len()).map_err(|_| ReplayError::InvalidRecord)?;
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > self.max_item_bytes {
            return Err(ReplayError::ItemTooLarge {
                limit: self.max_item_bytes,
            });
        }
        let mut id_buf = [0u8; 36];
        let stream_id = bind_stream_id(&item.frame.stream_id, &mut id_buf);
        let mut connection = self.connection.lock().map_err(|_| ReplayError::Storage)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ReplayError::Storage)?;
        let head = cached_aggregate(&transaction, SQL_MAX_SEQUENCE, stream_id)?;
        let expected = head
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(ReplayError::InvalidRecord)?;
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
                .map_err(|_| ReplayError::Storage)?;
            statement
                .execute(params![stream_id, sequence, encoded, byte_len])
                .map_err(|_| ReplayError::Storage)?;
        }
        let keep = i64::try_from(self.max_events_per_stream).map_err(|_| ReplayError::Storage)?;
        // Sequences start at 1 and have no gaps, so `sequence <= keep` means
        // the retention predicate deletes nothing.
        if sequence > keep {
            let mut statement = transaction
                .prepare_cached(SQL_DELETE_EXPIRED)
                .map_err(|_| ReplayError::Storage)?;
            statement
                .execute(params![stream_id, keep])
                .map_err(|_| ReplayError::Storage)?;
        }
        transaction.commit().map_err(|_| ReplayError::Storage)
    }

    pub fn head(&self, stream_id: &StreamId) -> Result<Sequence, ReplayError> {
        let connection = self.connection.lock().map_err(|_| ReplayError::Storage)?;
        let mut id_buf = [0u8; 36];
        let stream_id = bind_stream_id(stream_id, &mut id_buf);
        let head = cached_aggregate(&connection, SQL_MAX_SEQUENCE, stream_id)?;
        Ok(Sequence::new(
            u64::try_from(head.unwrap_or(0)).map_err(|_| ReplayError::InvalidRecord)?,
        ))
    }

    pub fn replay(
        &self,
        stream_id: &StreamId,
        after: Sequence,
        through: Sequence,
        batch_limit: usize,
    ) -> Result<ReplayBatch, ReplayError> {
        if through < after {
            return Err(ReplayError::InvalidRecord);
        }
        let requested = through.get().saturating_sub(after.get());
        let encoded_rows = {
            let connection = self.connection.lock().map_err(|_| ReplayError::Storage)?;
            let mut id_buf = [0u8; 36];
            let bound_id = bind_stream_id(stream_id, &mut id_buf);
            let first = cached_aggregate(&connection, SQL_MIN_SEQUENCE, bound_id)?;
            if let Some(first) = first {
                let first = u64::try_from(first).map_err(|_| ReplayError::InvalidRecord)?;
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
                .map_err(|_| ReplayError::Storage)?;
            let rows = statement
                .query_map(
                    params![bound_id, as_sql_sequence(after)?, as_sql_sequence(through)?],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|_| ReplayError::Storage)?;
            let mut encoded_rows =
                Vec::with_capacity(usize::try_from(requested).unwrap_or(batch_limit));
            for row in rows {
                encoded_rows.push(row.map_err(|_| ReplayError::Storage)?);
            }
            encoded_rows
        };
        let mut items = Vec::with_capacity(encoded_rows.len());
        for encoded in encoded_rows {
            let item: MultiplexedItem = ciborium::from_reader(encoded.as_slice())
                .map_err(|_| ReplayError::InvalidRecord)?;
            if item.frame.stream_id != *stream_id
                || item.frame.sequence <= after
                || item.frame.sequence > through
            {
                return Err(ReplayError::InvalidRecord);
            }
            items.push(item);
        }
        if items.len()
            != usize::try_from(requested)
                .map_err(|_| ReplayError::BatchTooLarge { limit: batch_limit })?
        {
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

const SQL_MAX_SEQUENCE: &str = "SELECT MAX(sequence) FROM stream_items WHERE stream_id = ?1";
const SQL_MIN_SEQUENCE: &str = "SELECT MIN(sequence) FROM stream_items WHERE stream_id = ?1";
const SQL_INSERT: &str =
    "INSERT INTO stream_items(stream_id, sequence, encoded, byte_len) VALUES (?1, ?2, ?3, ?4)";
const SQL_DELETE_EXPIRED: &str = "DELETE FROM stream_items
                 WHERE stream_id = ?1 AND sequence <= (
                    SELECT COALESCE(MAX(sequence), 0) - ?2 FROM stream_items WHERE stream_id = ?1
                 )";
const SQL_REPLAY: &str = "SELECT encoded FROM stream_items
                 WHERE stream_id = ?1 AND sequence > ?2 AND sequence <= ?3
                 ORDER BY sequence ASC";

fn bind_stream_id<'a>(stream_id: &StreamId, buffer: &'a mut [u8; 36]) -> &'a str {
    stream_id.as_uuid().hyphenated().encode_lower(buffer)
}

fn cached_aggregate(
    connection: &Connection,
    sql: &str,
    stream_id: &str,
) -> Result<Option<i64>, ReplayError> {
    let mut statement = connection
        .prepare_cached(sql)
        .map_err(|_| ReplayError::Storage)?;
    let value: Option<Option<i64>> = statement
        .query_row([stream_id], |row| row.get(0))
        .optional()
        .map_err(|_| ReplayError::Storage)?;
    Ok(value.flatten())
}

fn as_sql_sequence(sequence: Sequence) -> Result<i64, ReplayError> {
    i64::try_from(sequence.get()).map_err(|_| ReplayError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::SystemTime;

    use odin_domain::huginn::{
        ArtifactKind, ArtifactRef, HuginnMessage, HuginnProtocolError, LiveSessionId,
        LiveStreamKind, Sequence, StreamFrame, StreamId,
    };
    use odin_domain::{ArtifactId, Digest, LaneId};
    use time::OffsetDateTime;

    use super::{DurableReplayStore, MultiplexedItem, ReplayError};

    #[test]
    fn nested_path_opens_with_private_modes_and_supports_append_read() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "odin-huginn-replay-test-{}-{}",
            std::process::id(),
            nonce
        ));
        let parent_dir = root.join("nested").join("streams");
        let db_path = parent_dir.join("replay.sqlite3");

        let _ = fs::remove_dir_all(&root);

        let store =
            DurableReplayStore::open(&db_path, 100, 1024 * 1024).expect("open nested store");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let dir_meta = fs::metadata(&parent_dir).expect("parent directory metadata");
            assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
            let db_meta = fs::metadata(&db_path).expect("database file metadata");
            assert_eq!(db_meta.permissions().mode() & 0o777, 0o600);
        }

        let stream_id = StreamId::parse("00000000-0000-4000-8000-000000000001").expect("stream id");
        let item = MultiplexedItem::new(
            StreamFrame {
                stream_id,
                kind: LiveStreamKind::SimulationTelemetry,
                sequence: Sequence::new(1),
                control_revision: 1,
                produced_at: OffsetDateTime::now_utc(),
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
                    byte_len: 4,
                    content_digest: Digest::new([1u8; 32]),
                },
            },
            HuginnMessage::ProtocolError(HuginnProtocolError::Unavailable {
                code: "test".to_owned(),
            }),
        );

        store.append(&item).expect("append item");
        let head = store.head(&stream_id).expect("head");
        assert_eq!(head, Sequence::new(1));

        let batch = store
            .replay(&stream_id, Sequence::new(0), Sequence::new(1), 10)
            .expect("replay");
        assert_eq!(batch.stream_id, stream_id);
        assert_eq!(batch.after, Sequence::new(0));
        assert_eq!(batch.head, Sequence::new(1));
        assert_eq!(batch.items, vec![item]);

        let _ = fs::remove_dir_all(&root);
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
        MultiplexedItem::new(
            StreamFrame {
                stream_id,
                kind: LiveStreamKind::SimulationTelemetry,
                sequence: Sequence::new(sequence),
                control_revision: 1,
                produced_at: OffsetDateTime::UNIX_EPOCH,
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
                    byte_len: 4,
                    content_digest: Digest::new([1u8; 32]),
                },
            },
            HuginnMessage::ProtocolError(HuginnProtocolError::Unavailable {
                code: "test".to_owned(),
            }),
        )
    }
}
