use std::str::FromStr;

use odin_domain::CommandId;
use rusqlite::{params, OptionalExtension, Transaction};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

const MAX_KEY_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyClaim {
    Inserted,
    Existing { command_id: CommandId },
}

pub fn claim(
    transaction: &Transaction<'_>,
    key: &str,
    command_id: &CommandId,
    claimed_at: OffsetDateTime,
) -> LedgerResult<IdempotencyClaim> {
    validate_key(key)?;
    let claimed_at = encode_utc(claimed_at)?;
    let inserted = transaction.execute(
        "INSERT INTO idempotency_keys (key, command_id, claimed_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO NOTHING",
        params![key, command_id.to_string(), claimed_at],
    )?;

    if inserted == 1 {
        return Ok(IdempotencyClaim::Inserted);
    }
    if inserted != 0 {
        return Err(LedgerError::invalid_data(format!(
            "idempotency claim changed {inserted} rows"
        )));
    }

    let existing: Option<String> = transaction
        .query_row(
            "SELECT command_id FROM idempotency_keys WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()?;
    let existing = existing.ok_or_else(|| {
        LedgerError::invalid_data(format!(
            "idempotency key {key:?} conflicted but has no durable claim"
        ))
    })?;
    let command_id = CommandId::from_str(&existing).map_err(|error| {
        LedgerError::invalid_data_caused_by("invalid idempotency command id", error)
    })?;
    Ok(IdempotencyClaim::Existing { command_id })
}

fn validate_key(key: &str) -> LedgerResult<()> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(LedgerError::invalid_data(format!(
            "idempotency key must contain 1..={MAX_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use odin_domain::CommandId;
    use rusqlite::Connection;
    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn duplicate_claim_returns_the_original_command() {
        let mut connection = Connection::open_in_memory().expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE idempotency_keys (
                   key TEXT PRIMARY KEY,
                   command_id TEXT NOT NULL UNIQUE,
                   claimed_at TEXT NOT NULL
                 ) STRICT;",
            )
            .expect("create idempotency schema");
        let transaction = connection.transaction().expect("begin transaction");
        let first = CommandId::new("command:first").expect("valid command ID");
        let second = CommandId::new("command:second").expect("valid command ID");
        let now = OffsetDateTime::UNIX_EPOCH;

        assert_eq!(
            claim(&transaction, "request:1", &first, now).expect("first claim"),
            IdempotencyClaim::Inserted
        );
        assert_eq!(
            claim(&transaction, "request:1", &second, now).expect("duplicate claim"),
            IdempotencyClaim::Existing {
                command_id: first.clone()
            }
        );
        let count: i64 = transaction
            .query_row("SELECT COUNT(*) FROM idempotency_keys", [], |row| {
                row.get(0)
            })
            .expect("count claims");
        assert_eq!(count, 1);
    }

    #[test]
    fn command_id_cannot_claim_two_keys() {
        let mut connection = Connection::open_in_memory().expect("open database");
        connection
            .execute_batch(
                "CREATE TABLE idempotency_keys (
                   key TEXT PRIMARY KEY,
                   command_id TEXT NOT NULL UNIQUE,
                   claimed_at TEXT NOT NULL
                 ) STRICT;",
            )
            .expect("create idempotency schema");
        let transaction = connection.transaction().expect("begin transaction");
        let command_id = CommandId::new("command:1").expect("valid command ID");

        claim(
            &transaction,
            "request:1",
            &command_id,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("first claim");
        assert!(claim(
            &transaction,
            "request:2",
            &command_id,
            OffsetDateTime::UNIX_EPOCH,
        )
        .is_err());
    }
}
