//! Shared `#[cfg(test)]` wait helper for the Odin CLI test suites: poll a condition, never sleep a fixed time.

use std::time::Duration;

/// Polls `condition` every 10 ms until it holds; panics naming `what` after `timeout`.
pub(crate) async fn wait_until(what: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
