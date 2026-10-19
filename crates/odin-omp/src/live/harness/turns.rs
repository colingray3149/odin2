//! Tracks process-harness turns through bounded shutdown.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::huginn::LiveError;
use tokio::sync::watch;

use super::TurnState;

/// How often a join looks again at a driver or an admission still running.
const JOIN_POLL: Duration = Duration::from_millis(5);

/// Tracks drivers and in-flight admissions without detaching them.
/// `stop` closes admission and signals turns synchronously; `join` counts
/// unfinished admissions, drivers, or teardowns as stragglers at the deadline.
pub struct HarnessTurns {
    state: Mutex<TurnsState>,
}

struct TurnsState {
    /// Set once by [`HarnessTurns::stop`]: admission is refused, and a turn
    /// that registers from here is signalled at once.
    stopped: bool,
    /// Opens and reserved prompts admitted but not yet ended or registered.
    admitted: usize,
    /// Append-only once stopped, so a join's position stays exact.
    turns: Vec<HeldTurn>,
}

struct HeldTurn {
    /// The session's turn state, through which the driver's stop is sent
    /// exactly once — a repeated stop never moves its teardown deadline.
    session: Arc<Mutex<TurnState>>,
    turn: u64,
    done: watch::Receiver<Option<Result<(), String>>>,
    driver: tokio::task::JoinHandle<()>,
}

impl HeldTurn {
    /// Sends the turn's stop if none was sent yet and the turn is still the
    /// session's running one.
    fn signal(&self) {
        let Ok(mut state) = self.session.lock() else {
            return;
        };
        if let Some(running) = state
            .running
            .as_mut()
            .filter(|running| running.turn == self.turn)
        {
            if let Some(stop) = running.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    fn proven(&self) -> bool {
        self.driver.is_finished() && matches!(*self.done.borrow(), Some(Ok(())))
    }

    /// The driver ended and the session no longer holds this turn. Keeping
    /// it would pile finished ssh failures up until the daemon restarts.
    fn released(&self) -> bool {
        if !self.driver.is_finished() {
            return false;
        }
        let Ok(state) = self.session.lock() else {
            return false;
        };
        state
            .running
            .as_ref()
            .is_none_or(|running| running.turn != self.turn)
    }
}

/// One open or reserved prompt admitted before [`HarnessTurns::stop`]: held
/// until it registers its driver or ends, so a join never misses it.
pub(super) struct Admission {
    turns: Arc<HarnessTurns>,
    live: bool,
}

impl Drop for Admission {
    fn drop(&mut self) {
        if self.live {
            let mut state = self.turns.lock();
            state.admitted = state.admitted.saturating_sub(1);
        }
    }
}

impl HarnessTurns {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(TurnsState {
                stopped: false,
                admitted: 0,
                turns: Vec::new(),
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TurnsState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn stopped(&self) -> bool {
        self.lock().stopped
    }

    /// Admits one open or prompt; refused typed once stopped.
    pub(super) fn admit(self: &Arc<Self>) -> Result<Admission, LiveError> {
        let mut state = self.lock();
        if state.stopped {
            return Err(LiveError::Unavailable {
                code: "harness_stopping".to_owned(),
            });
        }
        state.admitted += 1;
        Ok(Admission {
            turns: Arc::clone(self),
            live: true,
        })
    }

    /// Atomically replaces admission with a tracked driver; signals it if shutdown began.
    pub(super) fn register(
        &self,
        mut admission: Admission,
        session: Arc<Mutex<TurnState>>,
        turn: u64,
        done: watch::Receiver<Option<Result<(), String>>>,
        driver: tokio::task::JoinHandle<()>,
    ) {
        let held = HeldTurn {
            session,
            turn,
            done,
            driver,
        };
        let mut state = self.lock();
        admission.live = false;
        state.admitted = state.admitted.saturating_sub(1);
        if state.stopped {
            held.signal();
        } else {
            // Keep unresolved turns for shutdown to count; discard completed or released ones.
            state
                .turns
                .retain(|turn| !turn.proven() && !turn.released());
        }
        state.turns.push(held);
    }

    /// Closes admission and signals every held turn's stop. Synchronous and
    /// idempotent: the daemon's shutdown calls it before its first await.
    pub fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        for turn in &state.turns {
            turn.signal();
        }
    }

    /// Returns `(drained, stragglers)` at the shared deadline without aborting drivers.
    /// A driver counts as drained only after successful teardown and task completion.
    pub async fn join(&self, deadline: tokio::time::Instant) -> (usize, usize) {
        self.stop();
        let mut drained = 0;
        let mut stragglers = 0;
        let mut checked = 0;
        loop {
            let next = {
                let state = self.lock();
                match state.turns.get(checked) {
                    Some(turn) => Some(turn.done.clone()),
                    None if state.admitted == 0 => break,
                    None => None,
                }
            };
            let Some(mut done) = next else {
                // An open or prompt is still on its way to a driver.
                if tokio::time::Instant::now() >= deadline {
                    let admitted = self.lock().admitted;
                    stragglers += admitted;
                    tracing::warn!(
                        "odind: harness opens outlived the shutdown deadline; counted \
                         stragglers={admitted}"
                    );
                    break;
                }
                tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + JOIN_POLL))
                    .await;
                continue;
            };
            let verdict = tokio::time::timeout_at(deadline, done.wait_for(Option::is_some))
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|verdict| verdict.clone());
            if verdict == Some(Ok(())) && self.driver_ended(checked, deadline).await {
                drained += 1;
            } else {
                stragglers += 1;
                tracing::warn!(
                    "odind: harness turn custody unproven at the shutdown deadline; counted \
                     verdict={verdict:?}"
                );
            }
            checked += 1;
        }
        (drained, stragglers)
    }

    /// Checks completion without removing the tracked handle.
    async fn driver_ended(&self, index: usize, deadline: tokio::time::Instant) -> bool {
        loop {
            if self
                .lock()
                .turns
                .get(index)
                .is_some_and(|turn| turn.driver.is_finished())
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + JOIN_POLL)).await;
        }
    }
}
