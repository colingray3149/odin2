//! Revision-CAS delivery snapshots in the projection-independent extension table.
//! Hermes owns payload schema and immutable delivery binding validation.

use rusqlite::{params, Connection, OptionalExtension};
use serde::de::IgnoredAny;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

pub const CONVERSATION_DELIVERY_KIND: &str = "conversation_delivery";
pub const MAX_CONVERSATION_DELIVERY_STATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationDeliveryRow {
    pub object_id: String,
    pub revision: i64,
    pub state_json: String,
    pub updated_at: OffsetDateTime,
}

impl Ledger {
    pub fn conversation_delivery(
        &self,
        object_id: &str,
    ) -> LedgerResult<Option<ConversationDeliveryRow>> {
        validate_object_id(object_id)?;
        load(self.connection(), object_id)
    }

    /// Existing identity always wins; callers must validate its domain binding.
    pub fn open_conversation_delivery(
        &mut self,
        object_id: &str,
        initial_state_json: &str,
        at: OffsetDateTime,
    ) -> LedgerResult<ConversationDeliveryRow> {
        validate_object_id(object_id)?;
        validate_state_json(initial_state_json)?;
        let timestamp = encode_utc(at)?;
        self.with_tx(|transaction| {
            transaction.execute(
                "INSERT INTO materialized_status
                    (object_kind, object_id, revision, status_json, source_event_id, updated_at)
                 VALUES (?1, ?2, 1, ?3, ?4, ?5)
                 ON CONFLICT(object_kind, object_id) DO NOTHING",
                params![
                    CONVERSATION_DELIVERY_KIND,
                    object_id,
                    initial_state_json,
                    format!("conversation_delivery:{object_id}:init"),
                    timestamp,
                ],
            )?;
            load(transaction, object_id)?.ok_or_else(|| {
                LedgerError::invalid_data("conversation delivery disappeared after open".to_owned())
            })
        })
    }

    pub fn cas_conversation_delivery(
        &mut self,
        object_id: &str,
        expected_revision: i64,
        state_json: &str,
        at: OffsetDateTime,
    ) -> LedgerResult<ConversationDeliveryRow> {
        validate_object_id(object_id)?;
        validate_state_json(state_json)?;
        if expected_revision < 1 {
            return Err(LedgerError::invalid_data(
                "conversation delivery expected revision must be positive".to_owned(),
            ));
        }
        let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
            LedgerError::invalid_data("conversation delivery revision overflow".to_owned())
        })?;
        let timestamp = encode_utc(at)?;
        self.with_tx(|transaction| {
            let changed = transaction.execute(
                "UPDATE materialized_status
                 SET status_json = ?1, updated_at = ?2, source_event_id = ?3, revision = ?4
                 WHERE object_kind = ?5 AND object_id = ?6 AND revision = ?7",
                params![
                    state_json,
                    timestamp,
                    format!("conversation_delivery:{object_id}:revision:{next_revision}"),
                    next_revision,
                    CONVERSATION_DELIVERY_KIND,
                    object_id,
                    expected_revision,
                ],
            )?;
            if changed == 0 {
                return match load(transaction, object_id)? {
                    Some(row) => Err(LedgerError::StaleActor {
                        actor: format!("conversation_delivery:{object_id}"),
                        expected_revision,
                        actual_revision: row.revision,
                    }),
                    None => Err(LedgerError::NotFound {
                        kind: CONVERSATION_DELIVERY_KIND,
                        id: object_id.to_owned(),
                    }),
                };
            }
            load(transaction, object_id)?.ok_or_else(|| {
                LedgerError::invalid_data("conversation delivery disappeared after CAS".to_owned())
            })
        })
    }

    pub fn conversation_deliveries(&self) -> LedgerResult<Vec<ConversationDeliveryRow>> {
        let mut statement = self.connection().prepare(
            "SELECT object_id, revision, status_json, updated_at FROM materialized_status
             WHERE object_kind = ?1 ORDER BY object_id",
        )?;
        let mut rows = statement.query([CONVERSATION_DELIVERY_KIND])?;
        let mut deliveries = Vec::new();
        while let Some(row) = rows.next()? {
            deliveries.push(decode_row(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            )?);
        }
        Ok(deliveries)
    }
}

fn load(connection: &Connection, object_id: &str) -> LedgerResult<Option<ConversationDeliveryRow>> {
    let raw: Option<(i64, String, String)> = connection
        .query_row(
            "SELECT revision, status_json, updated_at FROM materialized_status
             WHERE object_kind = ?1 AND object_id = ?2",
            params![CONVERSATION_DELIVERY_KIND, object_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    raw.map(|(revision, state_json, updated_at)| {
        decode_row(object_id.to_owned(), revision, state_json, updated_at)
    })
    .transpose()
}

fn decode_row(
    object_id: String,
    revision: i64,
    state_json: String,
    updated_at: String,
) -> LedgerResult<ConversationDeliveryRow> {
    validate_object_id(&object_id)?;
    validate_state_json(&state_json)?;
    if revision < 1 {
        return Err(LedgerError::invalid_data(
            "conversation delivery stored revision must be positive".to_owned(),
        ));
    }
    Ok(ConversationDeliveryRow {
        object_id,
        revision,
        state_json,
        updated_at: decode_utc(&updated_at)?,
    })
}

fn validate_object_id(object_id: &str) -> LedgerResult<()> {
    if object_id.trim().is_empty() || object_id.len() > MAX_OBJECT_ID_BYTES {
        return Err(LedgerError::invalid_data(
            "conversation delivery object id is empty or over its byte bound".to_owned(),
        ));
    }
    Ok(())
}

fn validate_state_json(state_json: &str) -> LedgerResult<()> {
    if state_json.len() > MAX_CONVERSATION_DELIVERY_STATE_BYTES {
        return Err(LedgerError::invalid_data(
            "conversation delivery state json exceeds its byte bound".to_owned(),
        ));
    }
    if !state_json.trim_start().starts_with('{') {
        return Err(LedgerError::invalid_data(
            "conversation delivery state json must be an object".to_owned(),
        ));
    }
    serde_json::from_str::<IgnoredAny>(state_json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Barrier;

    const DELIVERY: &str = "conversation:original-turn:final";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct DatabaseDirectory(PathBuf);

    impl DatabaseDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "odin-delivery-{}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
            ));
            std::fs::create_dir(&path).expect("create fixture directory");
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.join("ledger.sqlite")
        }
    }

    impl Drop for DatabaseDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).expect("remove fixture directory");
        }
    }

    fn at(second: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_312_000 + second).expect("fixture timestamp")
    }

    #[test]
    fn concurrent_create_preserves_one_original_identity_across_reopen() {
        let directory = DatabaseDirectory::new();
        let mut first = Ledger::open(directory.path()).expect("first connection");
        let mut second = Ledger::open(directory.path()).expect("second connection");
        let barrier = Barrier::new(2);
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                first.open_conversation_delivery(DELIVERY, r#"{"binding":"first"}"#, at(0))
            });
            let right = scope.spawn(|| {
                barrier.wait();
                second.open_conversation_delivery(DELIVERY, r#"{"binding":"second"}"#, at(1))
            });
            (
                left.join().expect("first thread").expect("first open"),
                right.join().expect("second thread").expect("second open"),
            )
        });
        assert_eq!(left, right);
        assert_eq!(left.revision, 1);
        assert!(matches!(
            left.state_json.as_str(),
            r#"{"binding":"first"}"# | r#"{"binding":"second"}"#
        ));
        drop(first);
        drop(second);
        let mut reopened = Ledger::open(directory.path()).expect("reopen database");
        assert_eq!(
            reopened
                .open_conversation_delivery(DELIVERY, r#"{"binding":"replacement"}"#, at(2))
                .expect("replay"),
            left,
        );
        assert_eq!(
            reopened.conversation_delivery(DELIVERY).expect("get"),
            Some(left.clone())
        );
        assert_eq!(
            reopened.conversation_deliveries().expect("list"),
            vec![left]
        );
    }

    #[test]
    fn concurrent_cas_has_one_winner_and_reopen_fences_old_revision() {
        let directory = DatabaseDirectory::new();
        let mut first = Ledger::open(directory.path()).expect("first connection");
        first
            .open_conversation_delivery(DELIVERY, r#"{"phase":"open"}"#, at(0))
            .expect("create");
        let mut second = Ledger::open(directory.path()).expect("second connection");
        let barrier = Barrier::new(2);
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                barrier.wait();
                first.cas_conversation_delivery(DELIVERY, 1, r#"{"winner":"first"}"#, at(1))
            });
            let right = scope.spawn(|| {
                barrier.wait();
                second.cas_conversation_delivery(DELIVERY, 1, r#"{"winner":"second"}"#, at(2))
            });
            (
                left.join().expect("first thread"),
                right.join().expect("second thread"),
            )
        });
        let (winner, loser) = match (left, right) {
            (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
            other => panic!("exactly one writer must win: {other:?}"),
        };
        assert_eq!(winner.revision, 2);
        assert!(matches!(
            loser,
            LedgerError::StaleActor {
                expected_revision: 1,
                actual_revision: 2,
                ..
            }
        ));
        drop(first);
        drop(second);
        let mut reopened = Ledger::open(directory.path()).expect("reopen database");
        assert!(matches!(
            reopened.cas_conversation_delivery(DELIVERY, 1, r#"{"winner":"stale"}"#, at(3)),
            Err(LedgerError::StaleActor {
                expected_revision: 1,
                actual_revision: 2,
                ..
            })
        ));
        assert_eq!(
            reopened.conversation_delivery(DELIVERY).expect("get"),
            Some(winner.clone())
        );
        assert_eq!(
            reopened
                .open_conversation_delivery(DELIVERY, "{}", at(4))
                .expect("replay"),
            winner
        );
        let next = reopened
            .cas_conversation_delivery(DELIVERY, 2, r#"{"phase":"committed"}"#, at(5))
            .expect("fresh CAS");
        assert_eq!(next.revision, 3);
        assert_eq!(next.updated_at, at(5));
    }

    #[test]
    fn rejects_invalid_inputs_without_mutating_delivery() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        for id in [
            "".to_owned(),
            " ".to_owned(),
            "x".repeat(257),
            "é".repeat(129),
        ] {
            assert!(matches!(
                ledger.open_conversation_delivery(&id, "{}", at(0)),
                Err(LedgerError::InvalidData { .. })
            ));
            assert!(matches!(
                ledger.conversation_delivery(&id),
                Err(LedgerError::InvalidData { .. })
            ));
        }
        for json in ["[]", "null", "{", "{} trailing"] {
            assert!(ledger
                .open_conversation_delivery(DELIVERY, json, at(0))
                .is_err());
        }
        let oversized = format!(
            r#"{{"text":"{}"}}"#,
            "x".repeat(MAX_CONVERSATION_DELIVERY_STATE_BYTES)
        );
        assert!(matches!(
            ledger.open_conversation_delivery(DELIVERY, &oversized, at(0)),
            Err(LedgerError::InvalidData { .. })
        ));
        assert!(ledger
            .conversation_delivery(DELIVERY)
            .expect("absent")
            .is_none());
        assert!(matches!(
            ledger.cas_conversation_delivery(DELIVERY, 1, "{}", at(0)),
            Err(LedgerError::NotFound { .. })
        ));
        let original = ledger
            .open_conversation_delivery(DELIVERY, "{}", at(0))
            .expect("create");
        for revision in [0, -1, i64::MAX] {
            assert!(matches!(
                ledger.cas_conversation_delivery(DELIVERY, revision, "{}", at(1)),
                Err(LedgerError::InvalidData { .. })
            ));
        }
        assert!(ledger
            .cas_conversation_delivery(DELIVERY, 1, "[]", at(1))
            .is_err());
        assert_eq!(
            ledger.conversation_delivery(DELIVERY).expect("unchanged"),
            Some(original)
        );
    }

    #[test]
    fn accepts_full_payload_bound_and_lists_only_delivery_rows() {
        let mut ledger = Ledger::open_in_memory().expect("ledger");
        let payload = format!(
            r#"{{"text":"{}"}}"#,
            "x".repeat(MAX_CONVERSATION_DELIVERY_STATE_BYTES - 11)
        );
        assert_eq!(payload.len(), MAX_CONVERSATION_DELIVERY_STATE_BYTES);
        let id = "x".repeat(MAX_OBJECT_ID_BYTES);
        let row = ledger
            .open_conversation_delivery(&id, &payload, at(0))
            .expect("bounded payload");
        ledger
            .open_browser_control_state(&id, "{}", at(0))
            .expect("other extension");
        assert_eq!(ledger.conversation_deliveries().expect("list"), vec![row]);
    }
}
