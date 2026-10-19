//! Tracks observe-only followers through bounded shutdown.

use std::future::Future;
use std::sync::Mutex;

use tokio::sync::watch;

/// Registers followers before they run, refuses new ones after stop, and joins
/// them with their SSH children under the shared shutdown deadline.
pub struct ObserverFollowers {
    state: Mutex<ObserverFollowersState>,
}

struct ObserverFollowersState {
    /// Set once shutdown stopped the tracker: registration is refused and
    /// every registered follower is already signaled.
    stopped: bool,
    followers: Vec<RegisteredFollower>,
}

struct RegisteredFollower {
    /// The follower's own stop signal: sending `true` ends its follow loop.
    stopped: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Default for ObserverFollowers {
    fn default() -> Self {
        Self::new()
    }
}

impl ObserverFollowers {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ObserverFollowersState {
                stopped: false,
                followers: Vec::new(),
            }),
        }
    }

    /// Whether shutdown stopped this tracker: the launcher refuses new
    /// observer admission when it answers yes.
    pub fn stopped(&self) -> bool {
        self.state.lock().expect("observer followers").stopped
    }

    /// Registers one spawned follower; refused once stopped, so no follower
    /// is ever born outside the tracker after shutdown began. Finished
    /// followers of closed sessions are reaped here.
    pub fn spawn(
        &self,
        stopped: watch::Sender<bool>,
        follower: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let mut state = self.state.lock().expect("observer followers");
        if state.stopped {
            return false;
        }
        state
            .followers
            .retain(|follower| !follower.task.is_finished());
        state.followers.push(RegisteredFollower {
            stopped,
            task: tokio::spawn(follower),
        });
        true
    }

    /// Stops: every registered follower is signaled to end (its ssh children
    /// are killed when the loop exits), and no new follower registers. Sync
    /// and idempotent: shutdown calls it before its first await.
    pub fn stop(&self) {
        let mut state = self.state.lock().expect("observer followers");
        state.stopped = true;
        for follower in &state.followers {
            let _ = follower.stopped.send_replace(true);
        }
    }

    /// Joins every registered follower under `deadline` (the shutdown's one
    /// shared instant): a follower that ended is drained; one that missed the
    /// deadline is aborted and counted — never claimed terminated. Returns
    /// `(drained, stragglers)`.
    pub async fn join(&self, deadline: tokio::time::Instant) -> (usize, usize) {
        let followers = {
            let mut state = self.state.lock().expect("observer followers");
            state.stopped = true;
            std::mem::take(&mut state.followers)
        };
        let mut drained = 0;
        let mut stragglers = 0;
        for mut follower in followers {
            let _ = follower.stopped.send_replace(true);
            match tokio::time::timeout_at(deadline, &mut follower.task).await {
                Ok(Ok(())) => drained += 1,
                Ok(Err(error)) => {
                    drained += 1;
                    tracing::error!("odind: observe follower ended abnormally: {error}");
                }
                Err(_elapsed) => {
                    follower.task.abort();
                    stragglers += 1;
                    tracing::error!(
                        "odind: observe follower outlived the shutdown deadline; aborted and \
                         counted"
                    );
                }
            }
        }
        (drained, stragglers)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use odin_domain::huginn::{HarnessBinding, LiveError, SessionEpoch, SessionManifest};
    use odin_domain::SeatId;

    use super::super::tests::{reginn_manifest, RunRecorder, TempWorkspace};
    use super::super::{HarnessLauncher, HarnessRoute, LiveSessionLauncher};

    /// The observed session's follower is born inside the launcher's
    /// tracker: a stopped tracker joins the follower bounded, and refuses
    /// any further observer admission — the shutdown owns the follower, it
    /// is never detached.
    #[tokio::test]
    async fn an_observed_follower_is_owned_and_a_stopped_tracker_refuses() {
        let mut route = HarnessRoute {
            harness_id: "observe".to_owned(),
            harness: super::super::tests::observe_fixture(),
            environment_id: "pc-claude-session".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/pc-claude-session/environment.toml"
            ))
            .expect("declared pc-claude-session environment parses"),
            account: None,
        };
        // The test host cannot reach the declared pc: the rescan ssh fails
        // at once and the follow loop idles until it is stopped.
        route.environment.host = Some("odin-observe-shutdown@invalid".to_owned());
        let launcher = HarnessLauncher::new(
            Arc::new(RunRecorder {
                runs: AtomicUsize::new(0),
                refuse: false,
            }),
            vec![route],
            Arc::new(TempWorkspace {
                prepared: AtomicUsize::new(0),
            }),
            None,
        );
        let manifest = SessionManifest {
            seat_id: SeatId::new("kubert").expect("seat id"),
            provider: odin_domain::huginn::ProviderName::new("observed").expect("provider"),
            model: odin_domain::huginn::ModelName::new("transcript").expect("model"),
            harness: Some(HarnessBinding {
                harness: "observe".to_owned(),
                environment: "pc-claude-session".to_owned(),
                account: None,
            }),
            ..reginn_manifest()
        };
        launcher
            .open(&manifest, SessionEpoch::new(1), false)
            .await
            .expect("the observed session opened");
        let followers = launcher
            .observer_followers()
            .expect("the launcher tracks its observed followers");
        assert!(!followers.stopped());
        followers.stop();
        let (drained, stragglers) = followers
            .join(tokio::time::Instant::now() + std::time::Duration::from_secs(5))
            .await;
        assert_eq!((drained, stragglers), (1, 0), "the follower drained");
        let refused = launcher
            .open(&manifest, SessionEpoch::new(2), false)
            .await
            .err()
            .expect("no observer admission after stop");
        assert!(
            matches!(refused, LiveError::Unavailable { .. }),
            "refused typed: {refused:?}"
        );
    }
}
