//! Lean retention: covered streaming `message_update` rows drop as soon as a
//! later `message_end` in the same session and epoch exists, including a live
//! session. Unfinished updates stay, as do errors, tools, and full frames.
//! Sequences are not renumbered and `event_head` is not lowered.
//! `message_end` keeps each final message. Capsules are deleted when their
//! session ends (the live supervisor), not here.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::LiveSessionId;
use rusqlite::{Connection, OptionalExtension};

use crate::live::workload_watch::{route_finding, Finding};

pub(crate) const RETENTION_EVERY: Duration = Duration::from_secs(86_400);
/// How long the first retention pass waits after startup, and how long a pass waits on a busy ledger.
const RETENTION_FIRST_PASS: Duration = Duration::from_secs(600);
const LEDGER_BUSY_TIMEOUT: Duration = Duration::from_secs(30);
/// How often unanswered approvals are checked for expiry.
const EXPIRY_TICK: std::time::Duration = std::time::Duration::from_secs(60);

/// Sessions that still hold a token row a later `message_end` already covers.
/// Age does not matter: the row is useless once the finished message is stored.
pub(crate) fn sessions_with_covered_token_rows(ledger: &Path) -> Result<Vec<String>, String> {
    let connection = Connection::open(ledger).map_err(|error| error.to_string())?;
    connection
        .busy_timeout(LEDGER_BUSY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let mut statement = connection
        .prepare(
            "WITH ends AS ( \
               SELECT session_id, epoch, MAX(sequence) AS end_sequence \
                 FROM live_events \
                WHERE json_extract(body_json,'$.kind')='session' \
                  AND json_extract(body_json,'$.frame.type')='message_end' \
                GROUP BY session_id, epoch \
             ) \
             SELECT DISTINCT token.session_id FROM live_events AS token \
               JOIN ends ON ends.session_id=token.session_id AND ends.epoch=token.epoch \
              WHERE json_extract(token.body_json,'$.kind')='session' \
                AND json_extract(token.body_json,'$.frame.type')='message_update' \
                AND token.sequence < ends.end_sequence \
              ORDER BY token.session_id",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())
}

/// The ledger half of the pass: drop covered streaming rows of `sessions`.
/// A token row is covered only by a later `message_end` in the same session
/// and epoch. Unfinished updates, errors, tools, and full frames stay.
/// Live-event rows are immutable by trigger; the pass lifts the delete
/// guard only inside its own transaction and restores the exact declared
/// trigger before committing. Deleted rows leave sequence gaps; sequences
/// are not renumbered and `event_head` is not lowered.
pub(crate) fn retain_events(sessions: &[String], ledger: &Path) -> Result<usize, String> {
    if sessions.is_empty() {
        return Ok(0);
    }
    let mut connection = Connection::open(ledger).map_err(|error| error.to_string())?;
    connection
        .busy_timeout(LEDGER_BUSY_TIMEOUT)
        .map_err(|error| error.to_string())?;
    let sql = |error: rusqlite::Error| error.to_string();
    let transaction = connection.transaction().map_err(sql)?;
    let guard: Option<String> = transaction
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' \
             AND name='live_events_immutable_delete'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if guard.is_some() {
        transaction
            .execute_batch("DROP TRIGGER live_events_immutable_delete")
            .map_err(sql)?;
    }
    let placeholders = std::iter::repeat_n("?", sessions.len())
        .collect::<Vec<_>>()
        .join(",");
    let delete_sql = format!(
        "WITH ends AS ( \
           SELECT session_id, epoch, MAX(sequence) AS end_sequence \
             FROM live_events \
            WHERE session_id IN ({placeholders}) \
              AND json_extract(body_json,'$.kind')='session' \
              AND json_extract(body_json,'$.frame.type')='message_end' \
            GROUP BY session_id, epoch \
         ) \
         DELETE FROM live_events WHERE event_id IN ( \
           SELECT token.event_id FROM live_events AS token \
             JOIN ends ON ends.session_id=token.session_id AND ends.epoch=token.epoch \
            WHERE json_extract(token.body_json,'$.kind')='session' \
              AND json_extract(token.body_json,'$.frame.type')='message_update' \
              AND token.sequence < ends.end_sequence \
         )"
    );
    let events = transaction
        .execute(&delete_sql, rusqlite::params_from_iter(sessions.iter()))
        .map_err(sql)?;
    if let Some(guard) = guard {
        transaction.execute_batch(&guard).map_err(sql)?;
    }
    transaction.commit().map_err(sql)?;
    Ok(events)
}

/// The daily retention pump: first pass ten minutes after start, off
/// every turn path.
pub(crate) fn arm_retention_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    ledger: std::path::PathBuf,
) {
    pumps.spawn(async move {
        tokio::time::sleep(RETENTION_FIRST_PASS).await;
        loop {
            if let Err(error) = retention_pass(&ledger).await {
                tracing::error!("retention failed: {error}");
            }
            tokio::time::sleep(RETENTION_EVERY).await;
        }
    });
}

pub(crate) async fn retention_pass(ledger: &Path) -> Result<(), String> {
    let covered = sessions_with_covered_token_rows(ledger)?;
    let events = tokio::task::spawn_blocking({
        let ledger = ledger.to_path_buf();
        move || retain_events(&covered, &ledger)
    })
    .await
    .map_err(|error| format!("retention did not finish: {error}"))??;
    if events > 0 {
        tracing::debug!(
            "retention dropped {events} streaming events once a later message_end covered them"
        );
    }
    Ok(())
}

/// Expires due approvals once a minute. Replies held behind decided or
/// expired approvals are settled first, so the owner hears of a lapse; then the
/// issuer seat's ready live session, and no other, is told. An absent
/// session is only logged.
pub(crate) fn arm_approval_expiry_pump(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    ledger: std::path::PathBuf,
    owner: Option<Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>>,
    runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
) {
    pumps.spawn(async move {
        let mut ticker = tokio::time::interval(EXPIRY_TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let path = ledger.clone();
            let expired = tokio::task::spawn_blocking(move || expire_due(&path)).await;
            match expired {
                Ok(Ok(expired)) => {
                    if let Some(runtime) = &runtime {
                        if let Err(error) = runtime.settle_held_replies().await {
                            tracing::error!("held replies not settled: {error}");
                        }
                    }
                    for (id, capability, session) in expired {
                        tracing::info!("approval expired id={id} capability={capability}");
                        let (Some(owner), Some(runtime), Some(session)) =
                            (&owner, &runtime, session)
                        else {
                            continue;
                        };
                        if let Err(error) = route_finding(
                            owner,
                            runtime,
                            Finding {
                                key: format!("approval-expired:{id}"),
                                session: Some(session),
                                source: "approvals",
                                text: format!(
                                    "Approval for `{capability}` expired unanswered; the call did \
                                     not run. Ask again only if still needed."
                                ),
                            },
                        )
                        .await
                        {
                            tracing::error!("approval expiry finding not delivered: {error}");
                        }
                    }
                }
                Ok(Err(error)) => tracing::error!("approval expiry failed: {error}"),
                Err(error) => tracing::error!("approval expiry did not finish: {error}"),
            }
        }
    });
}

fn expire_due(path: &Path) -> Result<Vec<(String, String, Option<LiveSessionId>)>, String> {
    let mut ledger = odin_ledger::Ledger::open(path).map_err(|error| error.to_string())?;
    let expired = ledger
        .expire_due_approvals(time::OffsetDateTime::now_utc())
        .map_err(|error| error.to_string())?;
    expired
        .into_iter()
        .map(|approval| {
            let session = issuer_ready_session(&ledger, &approval.issuer)?;
            Ok((
                approval.approval_id.to_string(),
                approval.scope.capability_id.to_string(),
                session,
            ))
        })
        .collect()
}

/// The issuer seat's ready live session, newest first. Another seat's
/// session is never a substitute.
pub(crate) fn issuer_ready_session(
    ledger: &odin_ledger::Ledger,
    issuer: &str,
) -> Result<Option<LiveSessionId>, String> {
    let session_id: Option<String> = ledger
        .connection()
        .query_row(
            "SELECT session_id FROM live_sessions \
             WHERE seat_id = ?1 AND state = 'ready' \
             ORDER BY updated_at DESC LIMIT 1",
            [issuer],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    session_id
        .map(|session_id| {
            LiveSessionId::parse(&session_id).map_err(|error| {
                format!(
                    "issuer {issuer} ready session {session_id} is not a live session id: {error}"
                )
            })
        })
        .transpose()
}

#[cfg(test)]
#[path = "tests/retention.rs"]
mod tests;
