use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    AbortScope, CommandFailure, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery,
    LiveCommand, LiveCommandBody, LiveCommandTarget, LiveError, LiveEvent, LiveEventBody,
    LiveEventStream, LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, ProviderName,
    SessionError, SessionStateChanged,
};
use odin_domain::EventId;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::bridge::ObservedFrame;

use super::control::ControlExecutor;
use super::ledger::replay::{ReplayJoin, ReplayTailItem};
use super::ledger::{live_error, LiveLedger, NewLiveEvent};
use super::normalize::{EventNormalizer, TerminalObservation};
use super::zellij::{TerminalEventSink, ZellijLiveAdapter};

const ACTOR_CAPACITY: usize = 256;
const SUBSCRIPTION_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct SessionActorHandle {
    sender: mpsc::Sender<ActorMessage>,
    summary: Arc<RwLock<LiveSessionSummary>>,
    terminal: Option<Arc<ZellijLiveAdapter>>,
    /// Raised before a stop is queued and never lowered (the stop ends the
    /// actor): every command wait, and every command still ahead of the
    /// stop in the mailbox, fails without waiting on the backend.
    stopping: Arc<tokio::sync::watch::Sender<bool>>,
}

impl SessionActorHandle {
    pub async fn command(&self, command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Command(command, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    /// Admit a replacement command without sending it to the retiring backend.
    pub(crate) async fn admit_fresh(
        &self,
        command: LiveCommand,
        handoff: Vec<u8>,
    ) -> Result<CommandReceipt, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::AdmitFresh(command, handoff, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    pub async fn subscribe(&self, after: EventSeq) -> Result<LiveEventStream, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Subscribe(after, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    pub async fn ingest_omp(&self, frame: ObservedFrame) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Omp(frame, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    pub async fn append(&self, body: LiveEventBody) -> Result<LiveEvent, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Event(body, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }
    /// Readiness does not imply child exit: a failed bridge may retain a live child.
    pub async fn bridge_ready(&self) -> bool {
        let (reply, receiver) = oneshot::channel();
        if self
            .sender
            .send(ActorMessage::BridgeReady(reply))
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    /// Whether child exit or teardown completed; a closed mailbox also counts.
    pub async fn process_exited(&self) -> bool {
        let (reply, receiver) = oneshot::channel();
        if self
            .sender
            .send(ActorMessage::ProcessExited(reply))
            .await
            .is_err()
        {
            return true;
        }
        receiver.await.unwrap_or(true)
    }
    /// Release authority requires an affirmative process-exit response, not a lost actor.
    pub async fn confirmed_process_exited(&self) -> bool {
        let (reply, receiver) = oneshot::channel();
        if self
            .sender
            .send(ActorMessage::ProcessExited(reply))
            .await
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    /// Stops the actor's processes and closes it, leaving the session
    /// durable and resumable (daemon shutdown, reaping an already-ended
    /// session): the backend teardown is the ordinary run stop, so the
    /// bridge's durable row keeps publishing `ready` for the next daemon
    /// to reclaim.
    pub async fn stop(&self) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.stopping.send_replace(true);
        self.sender
            .send(ActorMessage::Stop { end: false, reply })
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    /// Ends the durable session and actor so it cannot be reclaimed.
    pub async fn end(&self) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.stopping.send_replace(true);
        self.sender
            .send(ActorMessage::Stop { end: true, reply })
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }
    /// Recovers this session's bridge incarnation IN PLACE through the
    /// shared bridge recover (lease re-assert, published-row epoch
    /// advance, respawn with transcript resume). Never a final stop: child
    /// and tab resources are replaced while the session and its actor
    /// persist. Used by the supervisor's reclaim for a session that
    /// already holds a live actor.
    pub async fn recover(&self) -> Result<LiveSessionSummary, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Recover(reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)??;
        self.summary
            .read()
            .map_err(unavailable)
            .map(|value| value.clone())
    }

    /// Rolls this session's context-overflowed incarnation into a FRESH one
    /// through the typed context-refusal rollover: planned retirement,
    /// epoch advance, a NEW empty conversation, and ONE journaled
    /// continuity brief. Never a final stop; a parent stop already set
    /// refuses typed. Used by the governed delegation owner for a failed
    /// delegated child.
    pub async fn rollover_fresh(
        &self,
        refusal_event: u64,
    ) -> Result<LiveSessionSummary, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::RolloverFresh {
                refusal_event,
                reply,
            })
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)??;
        self.summary
            .read()
            .map_err(unavailable)
            .map(|value| value.clone())
    }

    pub fn summary(&self) -> Result<LiveSessionSummary, LiveError> {
        self.summary
            .read()
            .map_err(unavailable)
            .map(|value| value.clone())
    }

    /// Journals an unexpected backend failure; a later reclaim can recover in place.
    pub async fn backend_failed(&self, reason: String) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::BackendFailed(reason, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }

    /// Whether this actor's loop has exited (a stop always ends it, even
    /// a failed one): its handle can serve nothing any more.
    pub fn exited(&self) -> bool {
        self.sender.is_closed()
    }

    pub fn stopping(&self) -> bool {
        *self.stopping.borrow() || self.exited()
    }

    pub fn same_actor(&self, other: &Self) -> bool {
        self.sender.same_channel(&other.sender)
    }

    pub fn terminal(&self) -> Option<&Arc<ZellijLiveAdapter>> {
        self.terminal.as_ref()
    }
}

#[async_trait]
impl TerminalEventSink for SessionActorHandle {
    async fn persist(&self, observation: TerminalObservation) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Terminal(observation, reply))
            .await
            .map_err(unavailable)?;
        receive.await.map_err(unavailable)?
    }
}

pub struct SessionActor;

impl SessionActor {
    pub fn spawn(
        summary: LiveSessionSummary,
        ledger: Arc<dyn LiveLedger>,
        control: ControlExecutor,
        terminal: Option<Arc<ZellijLiveAdapter>>,
        runtime: tokio::runtime::Handle,
        // The durable completion-event observer, composed by the runtime:
        // invoked exactly when a typed `Result` event is durably appended
        // for this session. `None` serves sessions that are not delegated
        // children — no capture, no other behavior change.
        completion_observer: Option<
            std::sync::Arc<dyn crate::host_tools::delegation::CompletionEventObserver>,
        >,
        // The seat's declared elapsed budget of ONE model turn, from the
        // registry `[live] max_turn_seconds` declaration. `None` declares
        // no product budget: turns run until the child settles them.
        turn_budget: Option<Duration>,
    ) -> Result<SessionActorHandle, LiveError> {
        let (sender, receiver) = mpsc::channel(ACTOR_CAPACITY);
        let snapshot = summary.clone();
        // The launch identity this actor's incarnation was built from: the
        // manifest's provider/model at spawn time. Recovery compares the
        // session's recorded effective launch against it to decide whether
        // the fresh incarnation needs its model re-asserted.
        let launch = (snapshot.provider.clone(), snapshot.model.clone());
        let summary = Arc::new(RwLock::new(summary));
        let normalizer = Arc::new(EventNormalizer::new(
            snapshot.session_id,
            snapshot.epoch,
            snapshot.state,
            Arc::clone(&ledger),
        ));
        let handle = SessionActorHandle {
            sender,
            summary: Arc::clone(&summary),
            terminal: terminal.clone(),
            stopping: Arc::new(tokio::sync::watch::channel(false).0),
        };
        if let Some(adapter) = terminal {
            let sink: Arc<dyn TerminalEventSink> = Arc::new(handle.clone());
            adapter.bind_sink(sink)?;
        }
        // The caller's runtime can be request-scoped and die the moment
        // its reply is delivered; the supervisor's handle owns the actor
        // task so the conversation vehicle outlives every caller.
        runtime.spawn(run_actor(
            receiver,
            ActorContext {
                summary,
                ledger,
                control,
                normalizer,
                launch,
                terminal: handle.terminal.clone(),
                completion_observer,
                stopping: handle.stopping.subscribe(),
            },
            turn_budget,
        ));
        Ok(handle)
    }
}

mod command;
use command::{admit_fresh_command, append_body, apply_command, remove_capture_once, subscribe};
pub(super) enum ActorMessage {
    Command(
        LiveCommand,
        oneshot::Sender<Result<CommandReceipt, LiveError>>,
    ),
    AdmitFresh(
        LiveCommand,
        Vec<u8>,
        oneshot::Sender<Result<CommandReceipt, LiveError>>,
    ),
    Subscribe(
        EventSeq,
        oneshot::Sender<Result<LiveEventStream, LiveError>>,
    ),
    Omp(ObservedFrame, oneshot::Sender<Result<(), LiveError>>),
    Terminal(TerminalObservation, oneshot::Sender<Result<(), LiveError>>),
    Event(LiveEventBody, oneshot::Sender<Result<LiveEvent, LiveError>>),
    BridgeReady(oneshot::Sender<bool>),
    ProcessExited(oneshot::Sender<bool>),
    Recover(oneshot::Sender<Result<(), LiveError>>),
    RolloverFresh {
        refusal_event: u64,
        reply: oneshot::Sender<Result<(), LiveError>>,
    },
    BackendFailed(String, oneshot::Sender<Result<(), LiveError>>),
    /// `end`: the session is over, not merely this daemon's hold on it.
    Stop {
        end: bool,
        reply: oneshot::Sender<Result<(), LiveError>>,
    },
    /// Internal wake of the declared per-turn elapsed budget. No reply:
    /// the observation at the loop end decides whether the turn can be
    /// cancelled now (state `Running`) or the expiry stays due until it
    /// can.
    TurnBudgetElapsed,
}

/// Backend and pane teardown already performed for the session. An abort that
/// stopped the bridge must never stop it twice, and a completed teardown makes
/// a later supervisor stop an idempotent no-op.
#[derive(Default)]
pub(super) struct Teardown {
    bridge_stopped: bool,
    pane_terminated: bool,
    capture_removed: bool,
}
pub(super) struct CommandRuntime<'a> {
    terminal: Option<&'a Arc<ZellijLiveAdapter>>,
    subscribers: &'a mut Vec<mpsc::Sender<ReplayTailItem>>,
    teardown: &'a mut Teardown,
    stopping: &'a tokio::sync::watch::Receiver<bool>,
}

/// The immutable per-spawn world one session actor's run loop serves: the
/// actor's durable summary state, its ledger and control seams, the launch
/// identity reclaims compare against, the optional terminal adapter, and
/// the durable completion-event observer for delegated children.
pub(super) struct ActorContext {
    summary: Arc<RwLock<LiveSessionSummary>>,
    ledger: Arc<dyn LiveLedger>,
    control: ControlExecutor,
    normalizer: Arc<EventNormalizer>,
    launch: (ProviderName, ModelName),
    terminal: Option<Arc<ZellijLiveAdapter>>,
    completion_observer: Option<Arc<dyn crate::host_tools::delegation::CompletionEventObserver>>,
    stopping: tokio::sync::watch::Receiver<bool>,
}

mod clock;
use clock::{TurnBudgetClock, TURN_BUDGET_ABORT_GRACE};

/// Whether the session is reserved for a fresh replacement, read from the ledger once and
/// remembered. A ledger error is reported to the caller and read again on the next command;
/// it never stands in for a reservation.
async fn fresh_reservation(
    ledger: &Arc<dyn LiveLedger>,
    session_id: Option<LiveSessionId>,
    known: &mut Option<bool>,
) -> Result<bool, LiveError> {
    if let Some(reserved) = *known {
        return Ok(reserved);
    }
    let session_id = session_id.ok_or_else(|| unavailable("the session summary is unreadable"))?;
    let reserved = ledger
        .has_pending_fresh(session_id)
        .await
        .map_err(live_error)?;
    *known = Some(reserved);
    Ok(reserved)
}

async fn run_actor(
    mut receiver: mpsc::Receiver<ActorMessage>,
    context: ActorContext,
    turn_budget: Option<Duration>,
) {
    let ActorContext {
        summary,
        ledger,
        control,
        normalizer,
        launch,
        terminal,
        completion_observer,
        stopping,
    } = context;
    let mut subscribers: Vec<mpsc::Sender<ReplayTailItem>> = Vec::new();
    let mut teardown = Teardown::default();
    let mut clock = turn_budget.map(TurnBudgetClock::new);
    let session_id = summary.read().ok().map(|summary| summary.session_id);
    let mut fresh_reserved: Option<bool> = None;
    if let Some(clock) = clock.as_mut() {
        // A poisoned summary lock leaves the clock unarmed rather than
        // holding a non-Send poison error across the spawned task.
        if let Ok(state) = summary.read().map(|value| value.state) {
            clock.observe(state);
        }
    }
    loop {
        // The declared per-turn budget sleeps alongside the mailbox: an
        // expired budget is an internal wake, never a lost timer. A
        // deadline that already elapsed while the session waits OUTSIDE
        // `Running` (a permission/owner wait, a detached session) must
        // not spin: cancellation waits only for `Running`, so every wake
        // would observe `due == false` and rearm `sleep(0)` — a hot wake
        // loop until the owner acts. The overdue deadline STAYS ARMED
        // (the declaration is elapsed time) and the timer returns the
        // moment the state is `Running` again, cancelling exactly once.
        // An unreadable summary lock is treated as not-Running: no wake
        // storm, and every recovery route still arrives as a message.
        let running_now =
            summary.read().map(|value| value.state).ok() == Some(LiveSessionState::Running);
        // The budget wake folds into the mailbox's own message type: the
        // timer yields the synthetic `TurnBudgetElapsed` message directly,
        // so the hot path allocates nothing per delivered message. The
        // deadline passed while no mailbox traffic arrived; the
        // observation below decides the give-up.
        let message = match clock.as_ref().and_then(TurnBudgetClock::remaining) {
            Some(remaining) if running_now || remaining > Duration::ZERO => {
                let sleep = tokio::time::sleep(remaining);
                tokio::pin!(sleep);
                tokio::select! {
                    _ = &mut sleep => Some(ActorMessage::TurnBudgetElapsed),
                    message = receiver.recv() => message,
                }
            }
            _ => receiver.recv().await,
        };
        let Some(message) = message else {
            break;
        };
        match message {
            ActorMessage::Command(command, reply) => {
                let reserved =
                    match fresh_reservation(&ledger, session_id, &mut fresh_reserved).await {
                        Ok(reserved) => reserved,
                        Err(error) => {
                            let _ = reply.send(Err(error));
                            continue;
                        }
                    };
                if reserved {
                    let _ = reply.send(Err(LiveError::unavailable(
                        "fresh_handoff_pending",
                        "the session is reserved for a fresh replacement",
                    )));
                    continue;
                }
                let mut runtime = CommandRuntime {
                    terminal: terminal.as_ref(),
                    subscribers: &mut subscribers,
                    teardown: &mut teardown,
                    stopping: &stopping,
                };
                let result = apply_command(
                    command,
                    &summary,
                    &ledger,
                    &control,
                    &normalizer,
                    &mut runtime,
                    clock.as_mut(),
                )
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::AdmitFresh(command, handoff, reply) => {
                let reserved =
                    match fresh_reservation(&ledger, session_id, &mut fresh_reserved).await {
                        Ok(reserved) => reserved,
                        Err(error) => {
                            let _ = reply.send(Err(error));
                            continue;
                        }
                    };
                if reserved {
                    match ledger.fresh_handoff(&command).await {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            let _ = reply.send(Err(LiveError::unavailable(
                                "fresh_handoff_pending",
                                "another fresh replacement is already admitted",
                            )));
                            continue;
                        }
                        Err(error) => {
                            let _ = reply.send(Err(live_error(error)));
                            continue;
                        }
                    }
                }
                let result = admit_fresh_command(
                    command.clone(),
                    handoff,
                    &summary,
                    &ledger,
                    &mut subscribers,
                )
                .await;
                if matches!(
                    &result,
                    Ok(CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. })
                ) || (result.is_err()
                    && !matches!(ledger.fresh_handoff(&command).await, Ok(None)))
                {
                    fresh_reserved = Some(true);
                }
                let _ = reply.send(result);
            }
            ActorMessage::Subscribe(after, reply) => {
                let result = subscribe(&summary, &ledger, after, &mut subscribers).await;
                let _ = reply.send(result);
            }
            ActorMessage::Omp(frame, reply) => {
                let result = async {
                    for mut body in normalizer.normalize_omp(&frame)? {
                        if let LiveEventBody::Usage(usage) = &mut body {
                            usage.context_window =
                                control.context_window(&usage.provider, &usage.model);
                        }
                        let appended =
                            append_body(&summary, &ledger, body, &mut subscribers).await?;
                        // The durable completion-event hook: exactly when a
                        // typed `Result` event lands in the delegated child's
                        // durable history, the observer owns the ordered
                        // pending capture. Its link-row fsync and capture run
                        // on the blocking pool, never in this mailbox; its
                        // failures never fail the durable append.
                        if let LiveEventBody::Result(_) = &appended.body {
                            if let Some(observer) = &completion_observer {
                                let observer = Arc::clone(observer);
                                let (child, sequence) =
                                    (appended.session_id, appended.sequence.get());
                                tokio::task::spawn_blocking(move || {
                                    observer.result_persisted(child, sequence);
                                });
                            }
                        }
                    }
                    Ok(())
                }
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::Terminal(observation, reply) => {
                let result = async {
                    let body = normalizer.normalize_terminal(observation).await?;
                    append_body(&summary, &ledger, body, &mut subscribers).await?;
                    Ok(())
                }
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::Event(body, reply) => {
                let _ = reply.send(append_body(&summary, &ledger, body, &mut subscribers).await);
            }
            ActorMessage::Recover(reply) => {
                let result = async {
                    // The exact Restart semantics — the shared bridge
                    // recover (lease re-assert, published-row epoch
                    // advance, respawn with transcript resume), then the
                    // journal epoch advance and state settling — without
                    // journaling a client command: this is system
                    // recovery, never an operator instruction.
                    let snapshot = summary.read().map_err(unavailable)?.clone();
                    let effect = control
                        .apply(&LiveCommandBody::Restart, snapshot.state)
                        .await?;
                    // A recovered incarnation respawns from the launch
                    // manifest, so an operator model choice journaled after
                    // that manifest (recorded on this summary by an applied
                    // SetModel) is re-asserted against the fresh backend
                    // BEFORE anything else journals: the summary must never
                    // describe a model the incarnation does not run. One
                    // typed effect of system recovery — never a client
                    // command; a failed re-assert fails the whole recovery
                    // typed so the next recovery retries the exact Restart.
                    if snapshot.provider != launch.0 || snapshot.model != launch.1 {
                        control
                            .apply(
                                &LiveCommandBody::SetModel {
                                    provider: snapshot.provider.clone(),
                                    model: snapshot.model.clone(),
                                    route: None,
                                },
                                effect.state.unwrap_or(snapshot.state),
                            )
                            .await?;
                    }
                    if effect.reclaim_epoch {
                        let epoch = ledger
                            .reclaim(snapshot.session_id)
                            .await
                            .map_err(live_error)?;
                        normalizer.set_epoch(epoch)?;
                        let mut current = summary.write().map_err(unavailable)?;
                        current.epoch = epoch;
                        current.pending_permission_count = 0;
                    }
                    if let Some(next) = effect.state {
                        append_body(
                            &summary,
                            &ledger,
                            LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous: snapshot.state,
                                current: next,
                                reason: Some("incarnation recovered in place".to_owned()),
                            }),
                            &mut subscribers,
                        )
                        .await?;
                        normalizer.set_session_state(next)?;
                    }
                    // Keep the terminal adapter's epoch binding in lockstep
                    // with the advanced journal epoch, exactly like the
                    // journaled Restart path does — a stale binding would
                    // fail the next terminal snapshot.
                    if effect.reclaim_epoch {
                        if let Some(terminal) = &terminal {
                            let epoch = summary.read().map_err(unavailable)?.epoch;
                            terminal.set_epoch(epoch).await?;
                        }
                    }
                    Ok(())
                }
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::RolloverFresh {
                refusal_event,
                reply,
            } => {
                let result = async {
                    // A parent stop already set wins: the fresh incarnation
                    // would be torn down the moment after it started. The
                    // rollover call itself holds no turn-length await (the
                    // brief build, the bounded respawn, and the journaled
                    // dispatch admission only), so a Stop queued behind it
                    // waits seconds, never the reinjection turn.
                    if *stopping.borrow() {
                        return Err(LiveError::Conflict {
                            code: "session_stopping".to_owned(),
                            message: "a stopping session is never rolled over".to_owned(),
                        });
                    }
                    // The typed context-refusal rollover — the planned
                    // fresh-context respawn through the shared bridge
                    // rollover (bounded durable brief, epoch advance,
                    // respawn WITHOUT transcript resume, ONE journaled
                    // continuity brief) — is system recovery, never a
                    // client command.
                    let snapshot = summary.read().map_err(unavailable)?.clone();
                    // A journaled model choice rides INTO the rollover: the
                    // bridge re-asserts it after the respawn and BEFORE the
                    // reinjection turn, so the fresh incarnation's first
                    // turn runs the selected model and its context budget —
                    // never the launch pair with a correction only after
                    // the turn was already admitted. No post-turn SetModel
                    // competes with the reinjection.
                    let selected = (snapshot.provider != launch.0 || snapshot.model != launch.1)
                        .then_some((&snapshot.provider, &snapshot.model));
                    let effect = control
                        .apply_rollover_fresh(refusal_event, snapshot.state, selected)
                        .await?;
                    if effect.reclaim_epoch {
                        let epoch = ledger
                            .reclaim(snapshot.session_id)
                            .await
                            .map_err(live_error)?;
                        // The journal and the bridge row advance in lockstep
                        // from the same current epoch; the rollover names the
                        // epoch the bridge published, so a drift is a typed
                        // failure, never a summary that lies about the
                        // incarnation.
                        if let Some(bridge_epoch) = effect.epoch {
                            let journaled = i64::try_from(epoch.get()).map_err(|error| {
                                unavailable(format!(
                                    "epoch {} does not fit i64: {error}",
                                    epoch.get()
                                ))
                            })?;
                            if journaled != bridge_epoch {
                                return Err(LiveError::Conflict {
                                    code: "rollover_epoch_drift".to_owned(),
                                    message: format!(
                                        "the bridge published epoch {bridge_epoch} but the \
                                         journal advanced to {journaled}"
                                    ),
                                });
                            }
                        }
                        normalizer.set_epoch(epoch)?;
                        let mut current = summary.write().map_err(unavailable)?;
                        current.epoch = epoch;
                        current.pending_permission_count = 0;
                    }
                    if let Some(next) = effect.state {
                        append_body(
                            &summary,
                            &ledger,
                            LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous: snapshot.state,
                                current: next,
                                reason: Some(
                                    "context rollover: the fresh incarnation carries the \
                                     durable brief"
                                        .to_owned(),
                                ),
                            }),
                            &mut subscribers,
                        )
                        .await?;
                        normalizer.set_session_state(next)?;
                    }
                    // Keep the terminal adapter's epoch binding in lockstep
                    // with the advanced journal epoch, exactly like the
                    // recovered path does.
                    if effect.reclaim_epoch {
                        if let Some(terminal) = &terminal {
                            let epoch = summary.read().map_err(unavailable)?.epoch;
                            terminal.set_epoch(epoch).await?;
                        }
                    }
                    Ok(())
                }
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::BridgeReady(reply) => {
                let _ = reply.send(control.bridge_ready().await);
            }
            ActorMessage::ProcessExited(reply) => {
                let _ = reply.send(control.process_exited().await);
            }
            ActorMessage::BackendFailed(reason, reply) => {
                let result = async {
                    // Re-prove the failure under actor serialization against
                    // the CURRENT backend: a notice queued before a recovery
                    // must never mark a freshly recovered (ready) incarnation
                    // Failed. The typed readiness check — never the notice's
                    // text — decides.
                    if control.bridge_ready().await {
                        return Ok(());
                    }
                    let snapshot = summary.read().map_err(unavailable)?.clone();
                    // Already-truthful states stay untouched; a planned
                    // retirement never sends this notice.
                    if snapshot.state != LiveSessionState::Failed
                        && snapshot.state != LiveSessionState::Ended
                    {
                        append_body(
                            &summary,
                            &ledger,
                            LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous: snapshot.state,
                                current: LiveSessionState::Failed,
                                reason: Some(reason),
                            }),
                            &mut subscribers,
                        )
                        .await?;
                        summary.write().map_err(unavailable)?.state = LiveSessionState::Failed;
                        normalizer.set_session_state(LiveSessionState::Failed)?;
                    }
                    Ok(())
                }
                .await;
                let _ = reply.send(result);
            }
            ActorMessage::Stop { end, reply } => {
                let result = async {
                    let torn_down: Result<(), LiveError> = async {
                        if !teardown.bridge_stopped {
                            // The stop's SESSION disposition reaches the
                            // backend, not just this actor: an ordinary stop
                            // releases the daemon's hold — the run stops and
                            // the durable bridge row keeps the session
                            // resumable — while an end is terminal and
                            // retires the row the same way a whole-session
                            // abort does, so no later daemon reclaims a
                            // session its journal says ended.
                            if end {
                                control.end_session().await?;
                            } else {
                                control.shutdown().await?;
                            }
                            teardown.bridge_stopped = true;
                        }
                        if let Some(terminal) = &terminal {
                            if !teardown.pane_terminated {
                                terminal.terminate_pane().await?;
                                teardown.pane_terminated = true;
                            }
                        }
                        Ok(())
                    }
                    .await;
                    let snapshot = summary.read().map_err(unavailable)?.clone();
                    // End remains terminal even if teardown fails, because the actor exits.
                    if end && snapshot.state != LiveSessionState::Ended {
                        let reason = match &torn_down {
                            Ok(()) => "ended by its delegator".to_owned(),
                            Err(error) => format!(
                                "ended by its delegator; its teardown was not proven: {error}"
                            ),
                        };
                        append_body(
                            &summary,
                            &ledger,
                            LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous: snapshot.state,
                                current: LiveSessionState::Ended,
                                reason: Some(reason),
                            }),
                            &mut subscribers,
                        )
                        .await?;
                        summary.write().map_err(unavailable)?.state = LiveSessionState::Ended;
                        normalizer.set_session_state(LiveSessionState::Ended)?;
                    }
                    if end {
                        if let Some(terminal) = &terminal {
                            remove_capture_once(terminal, &mut teardown, &snapshot.session_id);
                        }
                    }
                    torn_down
                }
                .await;
                let _ = reply.send(result);
                for subscriber in subscribers.drain(..) {
                    let _ = subscriber.try_send(ReplayTailItem::Close);
                }
                break;
            }
            // The budget timer's synthetic message: the bookkeeping
            // happened in the select above and the observation below
            // decides the give-up.
            ActorMessage::TurnBudgetElapsed => {}
        }
        // Declared per-turn budget observation: runs after every handled
        // message so every state-change path (command effects, normalized
        // child frames, recovery, failure notices) keeps the clock honest.
        // The state is collapsed to an `Option` first so no lock guard (or
        // its poison error) stays alive across the give-up's await point.
        let state = summary.read().map(|value| value.state).ok();
        if let (Some(clock), Some(state)) = (clock.as_mut(), state) {
            clock.observe(state);
            if clock.due(state) {
                // The give-up disarms the clock itself and propagates
                // journal failures; a failure here never claims Idle.
                if let Err(error) = give_up_turn(
                    &summary,
                    &ledger,
                    &control,
                    &normalizer,
                    &mut subscribers,
                    clock,
                )
                .await
                {
                    let session = summary.read().map(|value| value.session_id.to_string());
                    tracing::error!(
                        "odind: turn-budget give-up-failed session={} state={state:?} \
                         reason={error}",
                        session.unwrap_or_else(|_| "unknown".to_owned())
                    );
                }
            }
        }
    }
}

/// Cancels the current turn through the shared abort seam within the abort grace; `Err` says
/// why the host cancellation is not confirmed.
async fn cancel_current_turn(
    control: &ControlExecutor,
    state: LiveSessionState,
) -> Result<(), String> {
    let cancellation = tokio::time::timeout(
        TURN_BUDGET_ABORT_GRACE,
        control.apply(
            &LiveCommandBody::Abort {
                scope: AbortScope::CurrentTurn,
            },
            state,
        ),
    )
    .await;
    match cancellation {
        Ok(Ok(_effect)) => Ok(()),
        Ok(Err(error)) => Err(format!("the host cancellation failed: {error}")),
        Err(_) => Err("the host cancellation did not confirm within the bounded grace".to_owned()),
    }
}

/// Deterministic give-up of one turn whose declared elapsed budget
/// expired. Disarms the clock first (exactly one give-up per arming), then
/// cancels the turn through the shared abort seam — the same
/// `Abort{CurrentTurn}` control path the operator uses — and journals the
/// expiry as an error. It is not a completed answer. Every journal failure
/// propagates: a turn whose cancellation or journaling failed is never
/// claimed settled, so the durable record can never lose a live operation.
async fn give_up_turn(
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    control: &ControlExecutor,
    normalizer: &EventNormalizer,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
    clock: &mut TurnBudgetClock,
) -> Result<(), LiveError> {
    clock.give_up();
    let snapshot = summary.read().map_err(unavailable)?.clone();
    if snapshot.state != LiveSessionState::Running {
        return Ok(());
    }
    let budget_seconds = clock.budget.as_secs();
    // The cancellation itself is bounded: a child that never answers its abort must not
    // park the give-up forever. A refused or unconfirmed cancellation journals the typed
    // failure, settles Failed (never Idle) and synchronizes the normalizer so late
    // original-turn frames cannot reopen the turn.
    if let Err(cause) = cancel_current_turn(control, snapshot.state).await {
        append_body(
            summary,
            ledger,
            LiveEventBody::Error(SessionError {
                code: "turn_budget_abort_failed".to_owned(),
                message: format!(
                    "the turn exceeded the declared turn budget of {budget_seconds}s and {cause}"
                ),
                retryable: true,
                error_status: None,
            }),
            subscribers,
        )
        .await?;
        normalizer.set_session_state(LiveSessionState::Failed)?;
        return Err(unavailable(format!("over-budget turn: {cause}")));
    }
    append_body(
        summary,
        ledger,
        LiveEventBody::Error(SessionError {
            code: "turn_budget_exceeded".to_owned(),
            message: format!(
                "the turn exceeded the declared turn budget of {budget_seconds}s and was \
                 ended before the answer completed; the host could not complete the \
                 answer within the declared budget"
            ),
            retryable: true,
            error_status: None,
        }),
        subscribers,
    )
    .await?;
    append_body(
        summary,
        ledger,
        LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous: LiveSessionState::Running,
            current: LiveSessionState::Failed,
            reason: Some("turn budget elapsed".to_owned()),
        }),
        subscribers,
    )
    .await?;
    normalizer.set_session_state(LiveSessionState::Failed)?;
    Ok(())
}

pub(super) fn publish(event: LiveEvent, subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>) {
    subscribers.retain(|sender| {
        match sender.try_send(ReplayTailItem::Event(Box::new(event.clone()))) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
            Err(mpsc::error::TrySendError::Full(_)) => {
                let sender = sender.clone();
                tokio::spawn(async move {
                    let _ = sender.send(ReplayTailItem::Overflow).await;
                });
                false
            }
        }
    });
}

pub(super) fn unavailable(cause: impl std::fmt::Display) -> LiveError {
    LiveError::unavailable("session_actor", cause)
}

#[cfg(test)]
pub(crate) mod tests;
