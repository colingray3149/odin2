//! Durable stop intents: idempotent recording under a verified authority,
//! per-operation observation, capsule-wide settlement gates, and terminal
//! settlement with evidence.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use time::OffsetDateTime;

use super::lease::LeaseAuthority;
use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopRow {
    pub correlation_id: String,
    pub operation_id: Option<String>,
    pub seat_id: String,
    pub token_id: String,
    pub session_id: String,
    pub policy_digest: String,
    pub listing_digest: String,
    pub capsule_id: String,
    pub state: String,
    pub evidence_json: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopRecordOutcome {
    Recorded,
    Existing { state: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopSettleOutcome {
    Settled,
    Replay,
}

/// Idempotently records a stop intent. A second intent for the same
/// correlation replays the recorded state.
#[doc(hidden)]
pub fn record_stop(
    tx: &Transaction<'_>,
    capsule_id: &str,
    authority: &LeaseAuthority<'_>,
    correlation_id: &str,
    operation_id: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<StopRecordOutcome> {
    let inserted = tx.execute(
        "INSERT INTO stop_intent (correlation_id, operation_id, seat_id, token_id, session_id, \
         policy_digest, listing_digest, capsule_id, state, evidence_json, requested_at, \
         settled_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'requested', NULL, ?9, NULL) \
         ON CONFLICT(correlation_id) DO NOTHING",
        params![
            correlation_id,
            operation_id,
            authority.seat_id,
            authority.token_id,
            authority.session_id,
            authority.policy_digest,
            authority.listing_digest,
            capsule_id,
            encode_utc(now)?,
        ],
    )?;
    if inserted == 1 {
        return Ok(StopRecordOutcome::Recorded);
    }
    let row = stop_row(tx, correlation_id)?.ok_or_else(|| {
        LedgerError::invalid_data("stop intent conflict reported no durable row".to_owned())
    })?;
    let same = row.seat_id == authority.seat_id
        && row.token_id == authority.token_id
        && row.session_id == authority.session_id
        && row.policy_digest == authority.policy_digest
        && row.listing_digest == authority.listing_digest
        && row.capsule_id == capsule_id;
    if !same {
        return Err(LedgerError::Conflict(format!(
            "stop intent {correlation_id} was recorded under a different authority"
        )));
    }
    Ok(StopRecordOutcome::Existing { state: row.state })
}

/// All stop intents that pertain to one operation: intents naming the
/// operation directly PLUS capsule-wide intents (NULL operation_id) recorded
/// against the capsule the operation runs in. Only `requested` rows return —
/// a terminal intent never re-settles.
#[doc(hidden)]
pub fn stop_intents_for_operation(
    conn: &Connection,
    operation_id: &str,
) -> LedgerResult<Vec<StopRow>> {
    let mut statement = conn.prepare(
        "SELECT correlation_id, operation_id, seat_id, token_id, session_id, policy_digest, \
         listing_digest, capsule_id, state, evidence_json \
         FROM stop_intent WHERE state = 'requested' AND \
         (operation_id = ?1 OR operation_id IS NULL AND capsule_id = \
           (SELECT capsule_id FROM operation_journal WHERE operation_id = ?1)) \
         ORDER BY correlation_id",
    )?;
    let rows = statement
        .query_map(params![operation_id], |row| {
            Ok(StopRow {
                correlation_id: row.get(0)?,
                operation_id: row.get(1)?,
                seat_id: row.get(2)?,
                token_id: row.get(3)?,
                session_id: row.get(4)?,
                policy_digest: row.get(5)?,
                listing_digest: row.get(6)?,
                capsule_id: row.get(7)?,
                state: row.get(8)?,
                evidence_json: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Capsule-wide settlement gate: a capsule-wide (NULL operation_id) stop
/// intent settles only when EVERY operation journal row in its capsule has
/// reached a terminal state — first-child success never fabricates the
/// capsule outcome.
#[doc(hidden)]
pub fn capsule_wide_stop_may_settle(conn: &Connection, capsule_id: &str) -> LedgerResult<bool> {
    let pending: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM operation_journal \
         WHERE capsule_id = ?1 AND effect_state IN \
         ('prepared', 'effect_started', 'in_doubt'))",
        [capsule_id],
        |row| row.get(0),
    )?;
    Ok(pending == 0)
}

/// Capsule-wide settlement gate EXCLUDING one correlation (the operation
/// currently aborting): used by the pre-start race guard so a first-child
/// abort cannot fabricate the capsule outcome while siblings are still
/// nonterminal.
#[doc(hidden)]
pub fn capsule_wide_stop_may_settle_excluding(
    conn: &Connection,
    capsule_id: &str,
    exclude_correlation_id: &str,
) -> LedgerResult<bool> {
    let pending: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM operation_journal \
         WHERE capsule_id = ?1 AND correlation_id != ?2 \
         AND effect_state IN \
         ('prepared', 'effect_started', 'in_doubt'))",
        params![capsule_id, exclude_correlation_id],
        |row| row.get(0),
    )?;
    Ok(pending == 0)
}

#[doc(hidden)]
pub fn settle_stop(
    tx: &Transaction<'_>,
    correlation_id: &str,
    state: &str,
    evidence_json: &str,
    now: OffsetDateTime,
) -> LedgerResult<StopSettleOutcome> {
    if state != "stopped" && state != "failed" {
        return Err(LedgerError::invalid_data(format!(
            "stop state {state:?} is not terminal"
        )));
    }
    let updated = tx.execute(
        "UPDATE stop_intent SET state = ?2, evidence_json = ?3, settled_at = ?4 \
         WHERE correlation_id = ?1 AND state = 'requested'",
        params![correlation_id, state, evidence_json, encode_utc(now)?],
    )?;
    if updated == 1 {
        return Ok(StopSettleOutcome::Settled);
    }
    Ok(StopSettleOutcome::Replay)
}

pub fn stop_row(conn: &Connection, correlation_id: &str) -> LedgerResult<Option<StopRow>> {
    conn.query_row(
        "SELECT correlation_id, operation_id, seat_id, token_id, session_id, policy_digest, \
         listing_digest, capsule_id, state, evidence_json \
         FROM stop_intent WHERE correlation_id = ?1",
        [correlation_id],
        |row| {
            Ok(StopRow {
                correlation_id: row.get(0)?,
                operation_id: row.get(1)?,
                seat_id: row.get(2)?,
                token_id: row.get(3)?,
                session_id: row.get(4)?,
                policy_digest: row.get(5)?,
                listing_digest: row.get(6)?,
                capsule_id: row.get(7)?,
                state: row.get(8)?,
                evidence_json: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(LedgerError::from)
}
