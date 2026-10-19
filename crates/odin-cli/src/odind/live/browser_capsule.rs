//! Off-loop supervision of the live browser capsule's terminal.
//!
//! Retire the capsule without stopping daemon services. Keep the terminal
//! future outside the serving select to avoid fatal browser errors or a
//! busy loop after terminal completion.

use std::future::Future;

use odin_cli::browser_runtime::BrowserCommandCoordinator;
use odin_huginn::browser::{BrowserProjection, BrowserProjectionError};

type RetireFuture = std::pin::Pin<Box<dyn Future<Output = Vec<String>> + Send>>;

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

    /// The production capsule's supervision inputs: the real projection
    /// handle's terminal watch as the supervised future, and the owning
    /// graceful ladder as the retirement body. Command admission closes
    /// first (every later browser command is refused typed), pending
    /// approvals are cancelled with durable typed outcomes, and the
    /// projection shutdown joins the event pump that already retired the
    /// worker scope, frame stream, and artifacts. A retired capsule is
    /// never reopened: the operator's supported relaunch is a fresh daemon
    /// lifecycle composing a fresh capsule.
    pub(super) fn capsule_terminal_and_retirement(
        projection: BrowserProjection,
        coordinator: BrowserCommandCoordinator,
    ) -> (
        impl Future<Output = Result<(), BrowserProjectionError>> + Send + 'static,
        impl FnOnce() -> RetireFuture + Send + 'static,
    ) {
        let terminal_handle = projection.handle();
        (
            async move { terminal_handle.wait_terminal().await },
            move || {
                Box::pin(async move {
                    let mut failures = Vec::new();
                    if let Err(error) = coordinator.shutdown_pending().await {
                        failures.push(format!("browser pending shutdown failed: {error}"));
                    }
                    if let Err(error) = projection.shutdown().await {
                        failures.push(format!("browser runtime shutdown failed: {error}"));
                    }
                    failures
                })
            },
        )
    }

    /// Signals the one-time retirement without joining: the shutdown seam fires this the moment
    /// the daemon's stop begins, so the ladder runs concurrently with the rest of the drain and
    /// gets its full share of the one deadline. A no-op once retired or already signalled.
    pub(super) fn retire(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Joins the one-time retirement: wakes the supervisor (a no-op when the capsule already
    /// retired itself or `retire` already fired) and returns the graceful-ladder failures. Exactly
    /// one retirement runs. The CALLER bounds this join under the shutdown deadline — the ladder
    /// is never aborted mid-flight, so past the deadline it is the caller's honest straggler.
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
