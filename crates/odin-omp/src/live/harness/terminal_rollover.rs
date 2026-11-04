//! Measured rollover for a terminal harness. The observation consumer feeds
//! terminal `agent_end` frames here. At the declared fraction of the selected
//! card window the session clears its context and reinjects a continuity
//! brief. The second successful boundary calls the fresh-session callback
//! instead of injecting into the running session. A failed clear or a failed
//! handoff does not advance the count.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde_json::Value;

use crate::live::rollover::{
    terminal_agent_end, RolloverPolicy, RolloverUsage, ROLLOVER_MIN_SETTLED_TURNS,
};

pub(super) type BoundCallback = std::sync::Arc<
    dyn Fn(u32) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync,
>;

/// The file under a session's store that holds its completed-rollover count.
const COUNT_FILE: &str = "count";

#[derive(Default)]
struct State {
    policy: Option<RolloverPolicy>,
    window: u64,
    ceiling: u64,
    completed: u32,
    /// The context watermark of the last measured turn.
    watermark: u64,
    /// Turns settled since the last rollover.
    settled: u32,
    /// A rollover is in flight: no second one starts until it commits or releases.
    busy: bool,
    callback: Option<BoundCallback>,
    store: Option<PathBuf>,
}

#[derive(Default)]
pub(super) struct TerminalRollover {
    state: Mutex<State>,
}

impl TerminalRollover {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The state is plain counters, so a poisoned lock holds nothing half-written.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn bind(
        &self,
        policy: RolloverPolicy,
        window: u64,
        ceiling: u64,
        completed: u32,
        store: Option<PathBuf>,
    ) {
        let mut state = self.state();
        state.policy = Some(policy);
        state.window = window;
        state.ceiling = ceiling;
        state.completed = completed;
        state.store = store;
    }

    pub(super) fn set_callback(&self, callback: BoundCallback) {
        self.state().callback = Some(callback);
    }

    pub(super) fn completed(&self) -> u32 {
        self.state().completed
    }

    pub(super) fn window(&self) -> Option<u64> {
        Some(self.state().window).filter(|window| *window > 0)
    }

    /// Records one terminal `agent_end`. `Some(next)` means this boundary
    /// should roll or hand off, and the caller must commit only after that
    /// action succeeds. `next` is the prospective completed count.
    pub(super) fn note(&self, frame: &Value) -> Option<u32> {
        if !terminal_agent_end(frame) {
            return None;
        }
        let mut state = self.state();
        let policy = state.policy.clone()?;
        let threshold = policy
            .threshold_for_window(state.window, state.ceiling)
            .or_else(|| {
                policy
                    .window_fraction
                    .is_none()
                    .then_some(policy.threshold_tokens)
            })?;
        state.settled = state.settled.saturating_add(1);
        if let Some(usage) = RolloverUsage::extract(frame) {
            state.watermark = usage.watermark();
        }
        if state.busy || state.watermark < threshold || state.settled < ROLLOVER_MIN_SETTLED_TURNS {
            return None;
        }
        state.busy = true;
        Some(state.completed.saturating_add(1))
    }

    pub(super) fn fresh_due(&self, prospective: u32) -> bool {
        self.state()
            .policy
            .as_ref()
            .is_some_and(|policy| policy.fresh_due(prospective))
    }

    pub(super) fn callback(&self) -> Option<BoundCallback> {
        self.state().callback.clone()
    }

    pub(super) fn commit(&self, completed: u32) {
        let mut state = self.state();
        state.completed = completed;
        state.settled = 0;
        state.watermark = 0;
        state.busy = false;
        if let Some(store) = &state.store {
            let written = std::fs::create_dir_all(store)
                .and_then(|()| std::fs::write(store.join(COUNT_FILE), completed.to_string()));
            if let Err(error) = written {
                tracing::warn!(
                    "odind: terminal rollover count not saved path={} error={error}",
                    store.display()
                );
            }
        }
    }

    pub(super) fn release(&self) {
        self.state().busy = false;
    }

    pub(super) fn restored(store: &Path) -> u32 {
        std::fs::read_to_string(store.join(COUNT_FILE))
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rollover(store: Option<PathBuf>) -> TerminalRollover {
        let rollover = TerminalRollover::new();
        let policy = RolloverPolicy {
            threshold_tokens: 1_000,
            ..RolloverPolicy::default()
        };
        rollover.bind(policy, 10_000, 10_000, 0, store);
        rollover
    }

    fn turn_end(tokens: u64) -> Value {
        json!({"type": "agent_end", "usage": {"input": tokens, "output": 0}})
    }

    /// The boundary arms once the watermark reaches the threshold and enough turns settled; one
    /// rollover is in flight at a time; a committed one saves its count and starts the next over,
    /// a released one leaves the count alone.
    #[test]
    fn a_rollover_arms_at_the_threshold_once_and_commits_its_count() {
        let store = tempfile::tempdir().unwrap();
        let rollover = rollover(Some(store.path().to_path_buf()));
        assert_eq!(
            rollover.note(&turn_end(5_000)),
            None,
            "the first settled turn is too few"
        );
        assert_eq!(rollover.note(&turn_end(500)), None, "below the threshold");
        assert_eq!(
            rollover.note(&json!({"type": "agent_start"})),
            None,
            "not a turn end"
        );
        assert_eq!(rollover.note(&turn_end(1_500)), Some(1));
        assert_eq!(
            rollover.note(&turn_end(1_500)),
            None,
            "one rollover at a time"
        );

        rollover.release();
        assert_eq!(
            rollover.completed(),
            0,
            "a failed rollover advances nothing"
        );
        assert_eq!(rollover.note(&turn_end(1_500)), Some(1));
        rollover.commit(1);
        assert_eq!(rollover.completed(), 1);
        assert_eq!(TerminalRollover::restored(store.path()), 1);
        assert_eq!(
            rollover.note(&turn_end(5_000)),
            None,
            "the count starts over after a rollover"
        );
        assert_eq!(rollover.note(&turn_end(5_000)), Some(2));
    }
}
