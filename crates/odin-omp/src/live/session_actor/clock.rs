use std::time::Duration;

use odin_domain::huginn::LiveSessionState;
use tokio::time::Instant;

/// Elapsed wall-clock budget of ONE model turn, declared by the seat's
/// `[live] max_turn_seconds`. Strictly per-turn and monotonic: armed when
/// the session enters `Running`, disarmed only on a settled terminal state
/// (`Idle`/`Failed`/`Ended`). One expiry cancels the turn exactly once
/// through the shared abort seam and journals an honest terminal.
pub(super) struct TurnBudgetClock {
    pub(super) budget: Duration,
    /// Monotonic deadline of the armed turn; `None` when no turn is armed.
    pub(super) deadline: Option<Instant>,
    /// Monotonic arming counter: identifies the armed turn episode.
    episode: u64,
    /// The give-up for the current episode already ran. A refused
    /// cancellation or a failed journal append leaves the summary Running;
    /// that same turn must never be re-armed — the once-per-turn expiry
    /// holds even when persistence fails. Cleared when the session settles
    /// (`Idle`/`Failed`/`Ended`), so the next turn arms a fresh episode.
    pub(super) given_up: bool,
}

/// Bounded grace for the budget give-up's cancellation: the declared budget
/// ends the turn, and the cancellation confirm must not wait on a child
/// that never answers. Measured abort confirms run ~1s; five seconds is
/// generous headroom that stays finite.
pub(super) const TURN_BUDGET_ABORT_GRACE: Duration = Duration::from_secs(5);

impl TurnBudgetClock {
    pub(super) fn new(budget: Duration) -> Self {
        Self {
            budget,
            deadline: None,
            episode: 0,
            given_up: false,
        }
    }

    /// Reacts to the session's current state; call after every state
    /// change. Entering `Running` freshly (from a settled state) arms a new
    /// episode; `RequiresAction`/`Detached` waits keep the deadline (the
    /// declaration is elapsed time, not generation time), and only the
    /// cancellation waits for `Running`. An episode whose give-up already
    /// ran never re-arms: a failed give-up leaves the session Running, and
    /// retrying the expiry would cancel the same turn twice.
    pub(super) fn observe(&mut self, state: LiveSessionState) {
        match state {
            LiveSessionState::Running => {
                if self.deadline.is_none() && !self.given_up {
                    self.episode = self.episode.saturating_add(1);
                    self.deadline = Some(Instant::now() + self.budget);
                }
            }
            LiveSessionState::Idle | LiveSessionState::Failed | LiveSessionState::Ended => {
                self.deadline = None;
                self.given_up = false;
            }
            _ => {}
        }
    }

    /// Disarms the episode for good: its give-up ran, so it never re-arms until the session settles.
    pub(super) fn give_up(&mut self) {
        self.deadline = None;
        self.given_up = true;
    }

    /// Time until the deadline; `Some(Duration::ZERO)` once passed, so the
    /// timer wake fires instead of the mailbox waiting forever. `None`
    /// while no turn is armed.
    pub(super) fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Arms a fresh episode when no turn is armed; keeps an already-armed
    /// deadline untouched — the declaration is elapsed time, so every wait
    /// of ONE turn (the initial dispatch included) shares the turn's single
    /// deadline, and a follow-up never re-arms it. Called when a
    /// starting-turn command is durably accepted, before its awaited
    /// dispatch, so the declared budget bounds the initial dispatch too.
    pub(super) fn arm(&mut self) {
        if self.deadline.is_none() && !self.given_up {
            self.episode = self.episode.saturating_add(1);
            self.deadline = Some(Instant::now() + self.budget);
        }
    }

    /// Whether the armed turn's budget has elapsed and the session can be
    /// cancelled now.
    pub(super) fn due(&self, state: LiveSessionState) -> bool {
        state == LiveSessionState::Running
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }
}
