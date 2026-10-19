use rusqlite::{params, Transaction};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

const MAX_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxClaim {
    Inserted,
    Duplicate,
}

pub fn claim(
    transaction: &Transaction<'_>,
    consumer_id: &str,
    message_id: &str,
    received_at: OffsetDateTime,
) -> LedgerResult<InboxClaim> {
    validate_stable_id("consumer", consumer_id)?;
    validate_stable_id("message", message_id)?;
    let received_at = encode_utc(received_at)?;
    let inserted = transaction.execute(
        "INSERT INTO inbox_dedup (consumer_id, message_id, received_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(consumer_id, message_id) DO NOTHING",
        params![consumer_id, message_id, received_at],
    )?;

    match inserted {
        1 => Ok(InboxClaim::Inserted),
        0 => Ok(InboxClaim::Duplicate),
        changed => Err(LedgerError::invalid_data(format!(
            "inbox claim changed {changed} rows"
        ))),
    }
}

fn validate_stable_id(kind: &str, value: &str) -> LedgerResult<()> {
    let mut bytes = value.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    let valid_rest =
        bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if value.len() > MAX_ID_BYTES || !valid_start || !valid_rest {
        return Err(LedgerError::invalid_data(format!(
            "{kind} ID must be 1..={MAX_ID_BYTES} bytes, start with an ASCII alphanumeric character, and contain only ASCII alphanumerics or '.', '_', ':', '-'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn duplicate_message_is_claimed_only_once_per_consumer() {
        let mut connection = Connection::open_in_memory().expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE inbox_dedup (
                   consumer_id TEXT NOT NULL,
                   message_id TEXT NOT NULL,
                   received_at TEXT NOT NULL,
                   processed_at TEXT,
                   result_hash TEXT,
                   PRIMARY KEY (consumer_id, message_id)
                 ) STRICT;",
            )
            .expect("create inbox schema");
        let transaction = connection.transaction().expect("begin transaction");
        let now = OffsetDateTime::UNIX_EPOCH;

        assert_eq!(
            claim(&transaction, "consumer:1", "event:1", now).expect("first claim"),
            InboxClaim::Inserted
        );
        assert_eq!(
            claim(&transaction, "consumer:1", "event:1", now).expect("duplicate claim"),
            InboxClaim::Duplicate
        );
        assert_eq!(
            claim(&transaction, "consumer:2", "event:1", now).expect("other consumer claim"),
            InboxClaim::Inserted
        );
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM inbox_dedup", [], |row| row.get(0))
            .expect("count claims");
        assert_eq!(count, 2);
    }

    #[test]
    fn unstable_ids_are_rejected_before_insert() {
        let mut connection = Connection::open_in_memory().expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE inbox_dedup (
                   consumer_id TEXT NOT NULL,
                   message_id TEXT NOT NULL,
                   received_at TEXT NOT NULL,
                   processed_at TEXT,
                   result_hash TEXT,
                   PRIMARY KEY (consumer_id, message_id)
                 ) STRICT;",
            )
            .expect("create inbox schema");
        let transaction = connection.transaction().expect("begin transaction");

        assert!(claim(&transaction, "", "event:1", OffsetDateTime::UNIX_EPOCH,).is_err());
        assert!(claim(
            &transaction,
            "consumer:1",
            "not stable",
            OffsetDateTime::UNIX_EPOCH,
        )
        .is_err());
    }
}
