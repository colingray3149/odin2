//! Failed stops are logged; the worker ledger is reclaimed at the next start.

use std::sync::Arc;

use odin_hermes::conversation::ConversationRoot;

use crate::live_authority::SessionAuthorityPool;

use super::serving;

pub(super) async fn finalize(
    result: Result<(), String>,
    accounting: serving::ShutdownAccounting,
    vehicle_root: Option<Arc<ConversationRoot>>,
    session_capsule_authority: &SessionAuthorityPool,
) -> Result<(), String> {
    let (tracked, stragglers) = match accounting.outcome {
        serving::ShutdownOutcome::Drained { tracked } => (tracked, 0),
        serving::ShutdownOutcome::Stragglers {
            tracked,
            stragglers,
        } => (tracked, stragglers),
    };
    let (background_joined, background_aborted) = if let Some(root) = vehicle_root {
        let deadline = match accounting.outcome {
            serving::ShutdownOutcome::Drained { .. } => {
                tokio::time::Instant::from_std(accounting.deadline)
            }
            serving::ShutdownOutcome::Stragglers { .. } => tokio::time::Instant::now(),
        };
        root.join_background_until(deadline).await
    } else {
        (0, 0)
    };
    if background_aborted != 0 {
        tracing::error!(
            worker = "wake-continuations",
            remaining = background_aborted,
            cause = "shutdown deadline expired",
            "shutdown failed"
        );
    }
    for failure in &accounting.capsule_failures {
        tracing::error!(worker = "browser", cause = %failure, "shutdown failed");
    }
    let device_ok = accounting.device_stop.is_ok();
    if let Err(error) = &accounting.device_stop {
        tracing::error!(worker = "device", cause = %error, "shutdown failed");
    }
    let drained = matches!(accounting.outcome, serving::ShutdownOutcome::Drained { .. })
        && background_aborted == 0
        && device_ok
        && accounting.capsule_failures.is_empty();
    let retirement = if drained {
        tokio::task::block_in_place(|| session_capsule_authority.retire_all(accounting.deadline))
    } else {
        // Keep ledger rows for work that has not stopped.
        session_capsule_authority.abandon_all()
    };
    if drained {
        for gap in &retirement.incomplete {
            tracing::error!(
                worker = ?gap.capsule_id,
                cause = %gap.reason,
                "shutdown failed"
            );
        }
    }
    let authority = if !drained {
        "not-retired"
    } else if retirement.complete() {
        "retired"
    } else {
        "incomplete"
    };
    let retired = retirement.retired.len();
    let incomplete = retirement.incomplete.len();
    let device = if device_ok { "drained" } else { "incomplete" };
    let elapsed_ms = accounting.started.elapsed().as_millis();
    if result.is_ok() && drained && retirement.complete() {
        tracing::info!(
            "shutdown done tracked={tracked} stragglers={stragglers} device={device} authority={authority} retired={retired} incomplete={incomplete} background={background_joined}+{background_aborted}aborted ms={elapsed_ms}"
        );
    } else {
        tracing::debug!(
            "shutdown incomplete tracked={tracked} stragglers={stragglers} device={device} authority={authority} retired={retired} incomplete={incomplete} background={background_joined}+{background_aborted}aborted ms={elapsed_ms}"
        );
    }
    // Preserve serving errors; failed stops are already logged.
    result
}
