//! Start-time session settlement.
//!
//! Reconcile ready rows with terminal journals at startup. End sessions past
//! the park limit only if no conversation can resume them; remove settled captures.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_ledger::live::LiveSessionExit;
use odin_ledger::Ledger;
use odin_omp::live::supervisor::{LiveSupervisor, StartSettlement};
use time::OffsetDateTime;

/// Enable ended-capsule cleanup and sweep capsules left by earlier daemon runs.
pub(super) fn remove_ended_capsules(supervisor: &Arc<LiveSupervisor>, state_root: PathBuf) {
    supervisor.remove_capsules_under(state_root);
    let supervisor = Arc::clone(supervisor);
    tokio::spawn(async move {
        match supervisor.remove_ended_capsules().await {
            Ok(removed) => tracing::info!("capsule-sweep done removed={removed}"),
            Err(error) => tracing::error!("capsule-sweep stopped: {error}"),
        }
    });
}

/// Log settlement failures per session without blocking daemon startup.
pub(super) async fn settle_stale_sessions(
    supervisor: &LiveSupervisor,
    ledger: &Arc<Mutex<Ledger>>,
    conversation_state: Option<&Path>,
) {
    let owned: BTreeSet<String> = match conversation_state
        .map(odin_hermes::conversation::owned_conversation_sessions)
        .transpose()
    {
        Ok(owned) => owned.unwrap_or_default(),
        Err(error) => {
            // Missing ownership data cannot authorize ending any session.
            tracing::warn!("session-settle skipped: {error}");
            return;
        }
    };
    let rows = match ledger.lock().map(|ledger| ledger.ready_live_sessions()) {
        Ok(Ok(rows)) => rows,
        Ok(Err(error)) => {
            tracing::warn!("session-settle skipped: ready sessions unreadable: {error}");
            return;
        }
        Err(_) => {
            tracing::warn!("session-settle skipped: controller ledger lock poisoned");
            return;
        }
    };
    let now = OffsetDateTime::now_utc();
    let (mut settled, mut kept) = (0usize, 0usize);
    for row in rows {
        let session = row.session_id.to_string();
        let seat = row
            .manifest
            .get("seatId")
            .and_then(|value| value.as_str())
            .unwrap_or("?")
            .to_owned();
        let live_id = match session
            .parse::<uuid::Uuid>()
            .map_err(|error| error.to_string())
            .and_then(|uuid| {
                odin_domain::huginn::LiveSessionId::new(uuid).map_err(|error| error.to_string())
            }) {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(
                    "session-settle session={session} seat={seat} skipped: invalid id: {error}"
                );
                continue;
            }
        };
        let outcome = supervisor
            .settle_at_start(live_id, owned.contains(&session), now)
            .await;
        let exit = match &outcome {
            Ok(StartSettlement::Resumable) => {
                kept += 1;
                continue;
            }
            Ok(StartSettlement::Terminal(state))
                if *state == odin_domain::huginn::LiveSessionState::Failed =>
            {
                LiveSessionExit::Failed
            }
            Ok(StartSettlement::Terminal(_) | StartSettlement::Settled { .. }) => {
                LiveSessionExit::Ended
            }
            Err(error) => {
                tracing::error!("session-settle session={session} seat={seat} failed: {error}");
                continue;
            }
        };
        let finished = ledger
            .lock()
            .map_err(|_| "controller ledger lock poisoned".to_owned())
            .and_then(|mut ledger| {
                ledger
                    .finish_live_session(&row.session_id, row.epoch, exit, now)
                    .map_err(|error| error.to_string())
            });
        match (finished, outcome) {
            (Err(error), _) => {
                tracing::error!(
                    "session-settle session={session} seat={seat} row not retired: {error}"
                )
            }
            (
                Ok(_),
                Ok(StartSettlement::Settled {
                    previous,
                    idle_since,
                }),
            ) => {
                settled += 1;
                tracing::info!(
                    "session-settle session={session} seat={seat} outcome=ended \
                     previous={previous:?} idle_since={idle_since}"
                );
            }
            (Ok(_), Ok(StartSettlement::Terminal(state))) => {
                settled += 1;
                tracing::info!(
                    "session-settle session={session} seat={seat} outcome=row-follows-journal \
                     journal={state:?}"
                );
            }
            (Ok(_), _) => {}
        }
    }
    // A row finished without a journal close still lists as Idle and holds
    // every publication reload. Record the row's own terminal state. A ready
    // row is not in this list: a missing local terminal is not a finish.
    let terminal_rows = match ledger
        .lock()
        .map(|ledger| ledger.terminal_live_session_states())
    {
        Ok(Ok(rows)) => rows,
        Ok(Err(error)) => {
            tracing::warn!("session-settle skipped terminal rows: {error}");
            Vec::new()
        }
        Err(_) => {
            tracing::warn!("session-settle skipped terminal rows: controller ledger lock poisoned");
            Vec::new()
        }
    };
    let mut recorded = 0usize;
    for (session, epoch, state) in terminal_rows {
        let terminal = match state.as_str() {
            "ended" => odin_domain::huginn::LiveSessionState::Ended,
            "failed" => odin_domain::huginn::LiveSessionState::Failed,
            _ => continue,
        };
        let Ok(live_id) = odin_domain::huginn::LiveSessionId::parse(&session) else {
            tracing::warn!("session-settle session={session} skipped: invalid id");
            continue;
        };
        let Ok(epoch) = u64::try_from(epoch) else {
            tracing::warn!("session-settle session={session} skipped: invalid epoch");
            continue;
        };
        match supervisor
            .record_durable_terminal(
                live_id,
                odin_domain::huginn::SessionEpoch::new(epoch),
                terminal,
                now,
            )
            .await
        {
            Ok(true) => {
                recorded += 1;
                tracing::info!(
                    "session-settle session={session} outcome=journal-follows-row state={state}"
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!("session-settle session={session} journal not closed: {error}")
            }
        }
    }
    if recorded != 0 {
        tracing::info!("session-settle journaled terminal rows={recorded}");
    }
    tracing::info!("session-settle done settled={settled} resumable={kept}");
    match supervisor
        .settle_captures(|session| owned.contains(&session.to_string()), now)
        .await
    {
        Ok(removed) => tracing::info!("capture-settle done removed={}", removed.len()),
        Err(error) => tracing::error!("capture-settle failed: {error}"),
    }
}
