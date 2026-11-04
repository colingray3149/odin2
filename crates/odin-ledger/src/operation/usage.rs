//! Cumulative per-session usage counters: idempotent cost accumulation and
//! observation.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use time::OffsetDateTime;

use crate::{encode_utc, LedgerError, LedgerResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageRow {
    pub requests: u64,
    pub stops: u64,
    pub spend: u64,
}

#[doc(hidden)]
pub fn bump_usage(
    tx: &Transaction<'_>,
    session_id: &str,
    requests: u64,
    stops: u64,
    spend: u64,
    now: OffsetDateTime,
) -> LedgerResult<()> {
    tx.prepare_cached(
        "INSERT INTO operation_usage (session_id, requests, stops, spend, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT(session_id) DO UPDATE SET \
         requests = requests + ?2, stops = stops + ?3, spend = spend + ?4, \
         updated_at = ?5",
    )?
    .execute(params![
        session_id,
        requests,
        stops,
        spend,
        encode_utc(now)?,
    ])?;
    Ok(())
}

pub fn usage(conn: &Connection, session_id: &str) -> LedgerResult<UsageRow> {
    conn.prepare_cached("SELECT requests, stops, spend FROM operation_usage WHERE session_id = ?1")?
        .query_row([session_id], |row| {
            Ok(UsageRow {
                requests: row.get::<_, i64>(0)? as u64,
                stops: row.get::<_, i64>(1)? as u64,
                spend: row.get::<_, i64>(2)? as u64,
            })
        })
        .optional()
        .map(|row| row.unwrap_or_default())
        .map_err(LedgerError::from)
}
