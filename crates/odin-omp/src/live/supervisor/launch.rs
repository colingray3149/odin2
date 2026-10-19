use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use odin_domain::huginn::{
    LiveError, LiveEventBody, LiveSessionState, SessionEpoch, SessionManifest, SessionStateChanged,
};
use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;

use super::admission::{restore_summary, unavailable};
use super::binding::{LaunchEffects, SessionRuntime};
use super::LiveSupervisor;
use crate::live::control::ControlExecutor;
use crate::live::ledger::live_error;
use crate::live::session_actor::{SessionActor, SessionActorHandle};

/// Retains launcher completion and pre-commit resources while `open_owned`
/// cancels its admission future. Cleanup is awaited, never spawned from Drop.
#[derive(Default)]
pub(super) struct LiveOpenOwnership {
    launcher: Mutex<Option<JoinHandle<Result<SessionRuntime, LiveError>>>>,
    committed: AtomicBool,
    join_failed: AtomicBool,
    effects: LaunchEffects,
    control: std::sync::Mutex<Option<Arc<dyn crate::live::control::LiveControlBackend>>>,
    actor: std::sync::Mutex<Option<SessionActorHandle>>,
}

impl LiveOpenOwnership {
    /// Whether this open inserted an actor, which may outlive initial-prompt
    /// delivery. Authority claims must survive request cancellation after this.
    pub fn committed(&self) -> bool {
        self.committed.load(Ordering::Acquire)
    }

    pub(super) fn commit(&self) {
        self.committed.store(true, Ordering::Release);
    }

    /// Cancel and witness termination of the actual launcher, not just its
    /// request wrapper. Call only after that wrapper has terminated.
    /// This wait is cancellation-safe: a timed-out wait retains the join handle.
    pub async fn cancel_and_join(
        &self,
        cancellation_joins_resources: bool,
    ) -> Result<(), LiveError> {
        if self.join_failed.load(Ordering::Acquire) {
            return Err(LiveError::Unavailable {
                code: "open_launcher_join_failed".to_owned(),
            });
        }
        let mut launcher = self.launcher.lock().await;
        if let Some(task) = launcher.as_mut() {
            task.abort();
            let result = task.await;
            launcher.take();
            match result {
                Ok(Ok(runtime)) => {
                    *self.control.lock().map_err(|_| unavailable())? = Some(runtime.control);
                }
                Ok(Err(_)) if self.effects.started() => {
                    return Err(LiveError::Unavailable {
                        code: "open_launcher_join_failed".to_owned(),
                    });
                }
                Err(error)
                    if !error.is_cancelled()
                        || (self.effects.started() && !cancellation_joins_resources) =>
                {
                    return Err(LiveError::Unavailable {
                        code: "open_launcher_join_failed".to_owned(),
                    });
                }
                _ => {}
            }
        }
        if self.committed() {
            return Ok(());
        }
        let actor = self.actor.lock().map_err(|_| unavailable())?.clone();
        let control = self.control.lock().map_err(|_| unavailable())?.clone();
        let stopped = if let Some(actor) = actor {
            actor.stop().await
        } else if let Some(control) = control {
            control.shutdown().await
        } else {
            Ok(())
        };
        stopped.map_err(|_| LiveError::Unavailable {
            code: "open_launcher_join_failed".to_owned(),
        })
    }
}

impl Drop for LiveOpenOwnership {
    fn drop(&mut self) {
        if let Some(task) = self.launcher.get_mut().as_ref() {
            task.abort();
        }
    }
}

impl LiveSupervisor {
    pub(super) async fn launch_actor(
        &self,
        manifest: SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionActorHandle, LiveError> {
        let ownership = LiveOpenOwnership::default();
        self.launch_actor_owned(manifest, epoch, reclaim, &ownership)
            .await
    }

    pub(super) async fn launch_actor_owned(
        &self,
        manifest: SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
        ownership: &LiveOpenOwnership,
    ) -> Result<SessionActorHandle, LiveError> {
        // The launch (and every task OmpBridge::start spawns inside it —
        // the sole-owner pump and the lease heartbeat) runs on the
        // supervisor's daemon runtime, never the caller's: a request-scoped
        // runtime that drops after the reply is delivered must not take the
        // pinned child with it.
        let mut launch = ownership.launcher.lock().await;
        let task = launch.insert(self.runtime.spawn({
            let launcher = Arc::clone(&self.launcher);
            let manifest = manifest.clone();
            let effects = ownership.effects.clone();
            // The durable epoch this launch was admitted at travels
            // with the launch: the factory binds the real bridge to
            // EXACTLY this epoch, so the launched binding can never
            // carry an epoch the admission journal does not know.
            async move {
                launcher
                    .open_owned(&manifest, epoch, reclaim, effects)
                    .await
            }
        }));
        let result = task.await;
        launch.take();
        drop(launch);
        let runtime = result
            .map_err(|_| {
                ownership.join_failed.store(true, Ordering::Release);
                LiveError::Unavailable {
                    code: "open_launcher_join_failed".to_owned(),
                }
            })?
            .inspect_err(|_| {
                if ownership.effects.started() {
                    ownership.join_failed.store(true, Ordering::Release);
                }
            })?;
        *ownership.control.lock().map_err(|_| unavailable())? = Some(Arc::clone(&runtime.control));
        let session = self
            .ledger
            .session(manifest.session_id)
            .await
            .map_err(live_error)?;
        let mut summary = restore_summary(&*self.ledger, &session).await?;
        let recovered_state = summary.state;
        summary.epoch = epoch;
        // A deliberate reclaim brings a FRESH bridge up under the same
        // session identity: even when the previous launch retired as
        // failed (the pinned child exits after every turn), the recovered
        // session rehydrates live — Idle, ready for the next prompt — with
        // its durable transcript resumed by the launcher. Only a truthfully
        // Ended session stays ended, and reclaim refuses it before launch.
        if summary.state != LiveSessionState::Ended
            && (reclaim || summary.state != LiveSessionState::Failed)
        {
            summary.state = LiveSessionState::Idle;
        }
        let actor = SessionActor::spawn(
            summary,
            Arc::clone(&self.ledger),
            ControlExecutor::new(runtime.control),
            runtime.terminal,
            self.runtime.clone(),
            self.completion_observer.clone(),
            self.bindings
                .read()
                .await
                .get(&manifest.seat_id)
                .and_then(|binding| binding.turn_budget),
        )?;
        *ownership.actor.lock().map_err(|_| unavailable())? = Some(actor.clone());
        // A reclaim advances the session's epoch in the durable manifest,
        // and that advance is itself a journal fact: it is always
        // published at the head — even when the state name is unchanged —
        // so a client replaying history to the head adopts the
        // authoritative current epoch instead of a stale pre-reclaim one.
        let current = actor.summary()?.state;
        if reclaim || recovered_state != current {
            actor
                .append(LiveEventBody::SessionStateChanged(SessionStateChanged {
                    previous: recovered_state,
                    current,
                    reason: Some(if reclaim {
                        format!("session ownership reclaimed (epoch {})", epoch.get())
                    } else {
                        "OMP runtime ready".to_owned()
                    }),
                }))
                .await?;
        }
        if let Some(mut observations) = runtime.observations {
            let target = actor.clone();
            let session = manifest.session_id;
            // The observation pump is the supervisor's task, never the
            // caller's: a request-scoped runtime that dies after this open
            // must not take the session's frame feed with it.
            self.runtime.spawn(async move {
                loop {
                    match observations.recv().await {
                        Ok(frame) => {
                            if target.ingest_omp(frame).await.is_err() {
                                return;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(frames)) => {
                            tracing::error!(
                                "odind: live observation lagged session={session} \
                                 frames_lost={frames}"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            });
        }
        if let Some(mut failures) = runtime.failed_notices {
            let target = actor.clone();
            // The shared live owner watches the bridge's typed failure
            // notices: a child death without any command durably transitions
            // the session to Failed, so ordinary observation surfaces and
            // the recovery route see the truth immediately.
            self.runtime.spawn(async move {
                loop {
                    let reason = failures.borrow_and_update().clone();
                    if let Some(reason) = reason {
                        if target.backend_failed(reason).await.is_err() {
                            return;
                        }
                    }
                    if failures.changed().await.is_err() {
                        return;
                    }
                }
            });
        }
        if let Some(terminal) = actor.terminal() {
            terminal.snapshot().await?;
        }
        Ok(actor)
    }
}
