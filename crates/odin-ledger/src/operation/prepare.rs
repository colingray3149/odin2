//! Exact request identity and idempotent admission: content-derived
//! operation identifiers, prepare replay/conflict admission, and the
//! journal reads built on the shared column decoder.

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use super::row::{
    read_row, NewOperation, OperationRow, PrepareOutcome, OPERATION_COLUMNS, STATE_EFFECT_STARTED,
    STATE_IN_DOUBT, STATE_PREPARED,
};
use crate::{encode_utc, LedgerError, LedgerResult};

/// Derives a stable operation ID from the request so prepare replays retain identity.
fn mint_operation_id(
    session_id: &str,
    capsule_id: &str,
    correlation_id: &str,
    request_digest: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"odin.operation_id.v1\0");
    hasher.update(session_id.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(capsule_id.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(correlation_id.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(request_digest.as_bytes());
    let hex = hasher.finalize().to_hex().to_string();
    format!("op-{}", &hex[..32])
}

pub(super) fn query_row(
    conn: &Connection,
    correlation_id: &str,
) -> LedgerResult<Option<OperationRow>> {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!("SELECT {OPERATION_COLUMNS} FROM operation_journal WHERE correlation_id = ?1")
    });
    conn.prepare_cached(SQL.as_str())?
        .query_row([correlation_id], read_row)
        .optional()
        .map_err(LedgerError::from)
}

/// Idempotently journals a fresh operation. A duplicate correlation id
/// replays the recorded row only when EVERY immutable authority binding, the
/// request digest, and the recorded binding match; any difference is a hard
/// conflict. The operation id is content-derived and minted only on a fresh
/// insert, so clock drift can never change a replayed identity.
#[doc(hidden)]
pub fn prepare_operation(
    tx: &Transaction<'_>,
    new: &NewOperation<'_>,
) -> LedgerResult<PrepareOutcome> {
    if new.correlation_id.is_empty() {
        return Err(LedgerError::invalid_data(
            "operation correlation id must not be empty".to_owned(),
        ));
    }
    let updated_at = encode_utc(new.now)?;
    let operation_id = mint_operation_id(
        new.session_id,
        new.capsule_id,
        new.correlation_id,
        new.request_digest,
    );
    let inserted: Option<String> = tx
        .prepare_cached(
            "INSERT INTO operation_journal (correlation_id, operation_id, capsule_id, seat_id, \
             token_id, session_id, policy_digest, listing_digest, capability, request_digest, \
             request_json, effect_state, reconciliation_json, evidence_digest, executor_id, \
             prepared_binding, binding_digest, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, ?14, ?15, ?16, ?17) \
             ON CONFLICT(correlation_id) DO NOTHING RETURNING operation_id",
        )?
        .query_row(
            params![
                new.correlation_id,
                &operation_id,
                new.capsule_id,
                new.seat_id,
                new.token_id,
                new.session_id,
                new.policy_digest,
                new.listing_digest,
                new.capability,
                new.request_digest,
                new.request_json,
                STATE_PREPARED,
                new.reconciliation_json,
                new.executor_id,
                new.prepared_binding,
                new.binding_digest,
                updated_at,
            ],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(operation_id) = inserted {
        return Ok(PrepareOutcome::Prepared { operation_id });
    }
    let row = query_row(tx, new.correlation_id)?.ok_or_else(|| {
        LedgerError::invalid_data("prepare reported no insert but the row is missing".to_owned())
    })?;
    let identical = row.capsule_id == new.capsule_id
        && row.seat_id == new.seat_id
        && row.token_id == new.token_id
        && row.session_id == new.session_id
        && row.policy_digest == new.policy_digest
        && row.listing_digest == new.listing_digest
        && row.capability == new.capability
        && row.request_digest == new.request_digest
        && row.request_json == new.request_json
        && row.reconciliation_json == new.reconciliation_json
        && row.executor_id == new.executor_id
        && row.prepared_binding == new.prepared_binding
        && row.binding_digest == new.binding_digest;
    if identical {
        Ok(PrepareOutcome::Replay { row: Box::new(row) })
    } else {
        Err(LedgerError::Conflict(format!(
            "correlation id {} already names a different operation",
            new.correlation_id
        )))
    }
}

pub fn operation_row(
    conn: &Connection,
    correlation_id: &str,
) -> LedgerResult<Option<OperationRow>> {
    query_row(conn, correlation_id)
}

/// Reads one operation row by its minted operation id: the binding a
/// targeted stop intent presents, whose correlation is the stop's own and
/// never names the operation journal.
pub fn operation_row_by_id(
    conn: &Connection,
    operation_id: &str,
) -> LedgerResult<Option<OperationRow>> {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!("SELECT {OPERATION_COLUMNS} FROM operation_journal WHERE operation_id = ?1")
    });
    conn.prepare_cached(SQL.as_str())?
        .query_row([operation_id], read_row)
        .optional()
        .map_err(LedgerError::from)
}

/// All operations for a capsule (or every capsule) in a nonterminal state.
pub fn nonterminal_rows(
    conn: &Connection,
    capsule_id: Option<&str>,
) -> LedgerResult<Vec<OperationRow>> {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "SELECT {OPERATION_COLUMNS} FROM operation_journal \
             WHERE effect_state IN ('{STATE_PREPARED}', '{STATE_EFFECT_STARTED}', '{STATE_IN_DOUBT}') \
             AND (?1 IS NULL OR capsule_id = ?1) ORDER BY correlation_id"
        )
    });
    let mut statement = conn.prepare_cached(SQL.as_str())?;
    let rows = statement
        .query_map(params![capsule_id], read_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Includes terminal rows so callers can detect any journaled effect, not only outstanding work.
pub fn rows_for_capsule(conn: &Connection, capsule_id: &str) -> LedgerResult<Vec<OperationRow>> {
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        format!(
            "SELECT {OPERATION_COLUMNS} FROM operation_journal \
                       WHERE capsule_id = ?1 ORDER BY correlation_id"
        )
    });
    let mut statement = conn.prepare_cached(SQL.as_str())?;
    let rows = statement
        .query_map(params![capsule_id], read_row)?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod returning_id {
    use super::super::row::{NewOperation, PrepareOutcome};
    use super::{operation_row, prepare_operation};
    use crate::migration;
    use rusqlite::Connection;
    use time::OffsetDateTime;

    #[test]
    fn inserted_id_matches_the_stored_row_and_a_replay_does_not_mint_another() {
        let mut connection = Connection::open_in_memory().unwrap();
        migration::migrate(&mut connection).unwrap();
        let tx = connection.transaction().unwrap();
        let new = NewOperation {
            capsule_id: "capsule-a",
            seat_id: "seat.one",
            token_id: "token.one",
            session_id: "session.one",
            policy_digest: "policy.one",
            listing_digest: "listing.one",
            executor_id: "odin.omp.host_tools",
            prepared_binding: "{\"binding\":true}",
            binding_digest: "binding-digest",
            correlation_id: "00112233445566778899aabbccddee01",
            capability: "tool.write",
            request_digest: "request-digest",
            request_json: "{}",
            reconciliation_json: "{}",
            now: OffsetDateTime::from_unix_timestamp(1_000).unwrap(),
        };
        let PrepareOutcome::Prepared { operation_id } = prepare_operation(&tx, &new).unwrap()
        else {
            panic!("fresh prepare must insert");
        };
        let stored = operation_row(&tx, new.correlation_id)
            .unwrap()
            .expect("row");
        assert_eq!(stored.operation_id, operation_id);
        assert!(matches!(
            prepare_operation(&tx, &new).unwrap(),
            PrepareOutcome::Replay { .. }
        ));
    }
}
