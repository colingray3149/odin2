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
            return Err(LiveError::unavailable(
                "open_launcher_join_failed",
                "an earlier join of this launcher failed",
            ));
        }
        let mut launcher = self.launcher.lock().await;
        if let Some(task) = launcher.as_mut() {
            task.abort();
            let result = task.await;
            launcher.take();
            match result {
                Ok(Ok(runtime)) => {
                    *self.control.lock().map_err(unavailable)? = Some(runtime.control);
                }
                Ok(Err(error)) if self.effects.started() => {
                    return Err(LiveError::unavailable("open_launcher_join_failed", error));
                }
                Err(error)
                    if !error.is_cancelled()
                        || (self.effects.started() && !cancellation_joins_resources) =>
                {
                    return Err(LiveError::unavailable("open_launcher_join_failed", error));
                }
                _ => {}
            }
        }
        if self.committed() {
            return Ok(());
        }
        let actor = self.actor.lock().map_err(unavailable)?.clone();
        let control = self.control.lock().map_err(unavailable)?.clone();
        let stopped = if let Some(actor) = actor {
            actor.stop().await
        } else if let Some(control) = control {
            control.shutdown().await
        } else {
            Ok(())
        };
        stopped.map_err(|error| LiveError::unavailable("open_launcher_join_failed", error))
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
            .map_err(|error| {
                ownership.join_failed.store(true, Ordering::Release);
                LiveError::unavailable("open_launcher_join_failed", error)
            })?
            .inspect_err(|_| {
                if ownership.effects.started() {
                    ownership.join_failed.store(true, Ordering::Release);
                }
            })?;
        let control = Arc::clone(&runtime.control);
        *ownership.control.lock().map_err(unavailable)? = Some(Arc::clone(&control));
        let session = self
            .ledger
            .session(manifest.session_id)
            .await
            .map_err(live_error)?;
        let mut summary = restore_summary(&*self.ledger, &session).await?;
        if reclaim {
            summary.provider = manifest.provider.clone();
            summary.model = manifest.model.clone();
        }
        summary.quiet_seconds = self
            .bindings
            .read()
            .await
            .get(&manifest.seat_id)
            .map(|binding| binding.quiet_seconds)
            .unwrap_or(odin_domain::huginn::DEFAULT_QUIET_SECONDS);
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
        *ownership.actor.lock().map_err(unavailable)? = Some(actor.clone());
        if reclaim && manifest.workload.is_none() {
            actor
                .append(LiveEventBody::ModelReclaimed(
                    odin_domain::huginn::ModelReclaimed {
                        provider: manifest.provider.clone(),
                        model: manifest.model.clone(),
                    },
                ))
                .await?;
        }
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
        control.set_fresh_bound(boundary_callback(
            self.self_weak.clone(),
            manifest.session_id,
        ));
        if self.heartbeat_interval(&manifest.seat_id).is_some() {
            let owner = self.self_weak.clone();
            let session = manifest.session_id;
            let seat = manifest.seat_id.clone();
            let heartbeat_actor = actor.clone();
            self.runtime.spawn(async move {
                loop {
                    let Some(supervisor) = owner.upgrade() else {
                        return;
                    };
                    let Some(interval) = supervisor.heartbeat_interval(&seat) else {
                        return;
                    };
                    drop(supervisor);
                    tokio::time::sleep(interval).await;
                    let Some(supervisor) = owner.upgrade() else {
                        return;
                    };
                    if supervisor.heartbeat_due(session, Some(interval))
                        && supervisor.heartbeat_changed(&seat, session).await
                        && prompt_heartbeat(&heartbeat_actor, session).await.is_err()
                    {
                        supervisor.clear_heartbeat(session);
                    }
                }
            });
        }
        if let Some(mut observations) = runtime.observations {
            let target = actor.clone();
            let noted = Arc::clone(&control);
            let session = manifest.session_id;
            self.runtime.spawn(async move {
                loop {
                    match observations.recv().await {
                        Ok(frame) => {
                            let measured = frame.value().cloned();
                            if target.ingest_omp(frame).await.is_err() {
                                return;
                            }
                            if let Some(value) = measured {
                                if let Err(error) = noted.note_observed_turn(&value).await {
                                    tracing::error!(
                                        "odind: terminal rollover session={session} error={error}"
                                    );
                                }
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

async fn prompt_heartbeat(
    actor: &crate::live::session_actor::SessionActorHandle,
    session: odin_domain::huginn::LiveSessionId,
) -> Result<(), LiveError> {
    use odin_domain::huginn::{LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage};
    let summary = actor.summary()?;
    let message = LiveMessage::new(vec![LiveContentBlock::Text(
        "Declared heartbeat. Events already woke you if a lane moved; this is only the backstop. Read the lanes and steer what drifted.".to_owned(),
    )])
    .map_err(|error| LiveError::unavailable("heartbeat", error))?;
    let command_id =
        odin_domain::CommandId::new(format!("heartbeat:{session}:{}", summary.event_head))
            .map_err(|error| LiveError::unavailable("heartbeat", error))?;
    actor
        .command(LiveCommand {
            command_id,
            session_id: session,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body: LiveCommandBody::Prompt {
                message,
                owner_text: None,
                wake: false,
            },
        })
        .await
        .map(drop)
}

fn boundary_callback(
    owner: std::sync::Weak<LiveSupervisor>,
    session: odin_domain::huginn::LiveSessionId,
) -> crate::bridge::FreshBound {
    std::sync::Arc::new(move |completed| {
        let owner = owner.clone();
        let session = session;
        Box::pin(async move {
            let Some(owner) = owner.upgrade() else {
                return Err("the supervisor is gone".to_owned());
            };
            let Some(handoff) = owner.fresh_handoff() else {
                return Err("no fresh handoff is installed".to_owned());
            };
            handoff
                .handoff(&owner, session, completed, false, "")
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        })
    })
}
