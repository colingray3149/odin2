//! Replay deferred delegation asks on the authority's existing pump set.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_hermes::runtime::HermesRuntime;
use odin_omp::host_tools::delegation::GovernedTaskOwner;

pub(super) fn arm_deferred_delegations(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    runtime: Arc<HermesRuntime>,
    owner: Arc<GovernedTaskOwner>,
    state_root: PathBuf,
) {
    pumps.spawn(async move {
        loop {
            let (runtime, owner, state_root) =
                (Arc::clone(&runtime), Arc::clone(&owner), state_root.clone());
            let replay = tokio::task::spawn_blocking(move || {
                crate::project_authoring::wake_deferred_delegations(&runtime, &owner, &state_root)
            })
            .await;
            handle_replay(replay).await;
            tokio::time::sleep(StdDuration::from_secs(5)).await;
        }
    });
}

/// A drained replay parks the pump for good: nothing is left to wake.
async fn handle_replay(replay: Result<Result<bool, String>, tokio::task::JoinError>) {
    match replay {
        Ok(Ok(true)) => std::future::pending::<()>().await,
        Ok(Ok(false)) => {}
        Ok(Err(error)) => tracing::warn!("deferred asks wait: {error}"),
        Err(error) => tracing::warn!("deferred ask replay failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt as _;

    use super::handle_replay;

    #[tokio::test]
    async fn only_a_drained_replay_parks_the_pump() {
        assert!(handle_replay(Ok(Ok(true))).now_or_never().is_none());
        assert!(handle_replay(Ok(Ok(false))).now_or_never().is_some());
        assert!(handle_replay(Ok(Err("not ready".to_owned())))
            .now_or_never()
            .is_some());
    }
}
