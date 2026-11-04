//! Off-loop supervision of the browser capsule's retirement.
//!
//! Retire the capsule without stopping daemon services. Keep the terminal
//! future outside the serving select to avoid a busy loop after terminal
//! completion; the lazy local browser's own sessions end themselves.

use std::future::Future;

use odin_huginn::browser::BrowserProjectionError;

/// Retire exactly once on capsule termination or daemon shutdown.
pub(super) struct BrowserCapsuleSupervision {
    /// Dropping this sender also triggers retirement.
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<Vec<String>>,
}

impl Drop for BrowserCapsuleSupervision {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl BrowserCapsuleSupervision {
    /// Arms supervision over one terminal future and one retirement body.
    /// The retirement is built lazily so it can own the capsule's runtime
    /// pieces; it runs exactly once, after the terminal resolves or the
    /// stop side asks.
    pub(super) fn spawn<T, R, F>(terminal: T, retire: R) -> Self
    where
        T: Future<Output = Result<(), BrowserProjectionError>> + Send + 'static,
        R: FnOnce() -> F + Send + 'static,
        F: Future<Output = Vec<String>> + Send + 'static,
    {
        let (stop, waiter) = tokio::sync::oneshot::channel();
        let done = tokio::spawn(async move {
            let terminal = tokio::select! {
                terminal = terminal => Some(terminal),
                _ = waiter => None,
            };
            match &terminal {
                Some(Ok(())) => tracing::warn!(
                    "browser capsule closed cleanly; retiring the browser \
                     capsule while odind keeps serving"
                ),
                Some(Err(error)) => tracing::error!(
                    "browser capsule failed; retiring the browser capsule \
                     while odind keeps serving: {error}"
                ),
                None => {}
            }
            retire().await
        });
        Self {
            stop: Some(stop),
            done,
        }
    }

    /// Signals the one-time retirement without joining: the shutdown seam fires this the moment
    /// the daemon's stop begins, so the ladder runs concurrently with the rest of the drain and
    /// gets its whole browser budget. A no-op once retired or already signalled.
    pub(super) fn retire(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Joins the one-time retirement: wakes the supervisor (a no-op when the capsule already
    /// retired itself or `retire` already fired) and returns the graceful-ladder failures. Exactly
    /// one retirement runs. The CALLER bounds this join under the browser budget (BROWSER_STOP_GRACE)
    /// — the ladder is never aborted mid-flight, so past the budget it is the caller's straggler.
    pub(super) async fn retire_and_join(&mut self) -> Vec<String> {
        self.retire();
        // The owner carries a Drop that signals retirement, so the join
        // borrows the handle instead of moving it out.
        match (&mut self.done).await {
            Ok(failures) => failures,
            Err(error) => vec![format!("browser capsule supervision task failed: {error}")],
        }
    }
}
