use std::num::NonZeroU16;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    AbortScope, CommandFailure, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery,
    LiveCommand, LiveCommandBody, LiveCommandTarget, LiveError, LiveEvent, LiveEventBody,
    LiveEventStream, LiveSessionState, LiveSessionSummary, ModelName, ProviderName, SessionError,
    SessionStateChanged,
};
use odin_domain::EventId;
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot};
// The turn-budget clock reads tokio's clock (the wall clock in production)
// so a paused test runtime drives it deterministically.
use tokio::time::Instant;
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
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub async fn subscribe(&self, after: EventSeq) -> Result<LiveEventStream, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Subscribe(after, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub async fn ingest_omp(&self, frame: ObservedFrame) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Omp(frame, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    pub async fn append(&self, body: LiveEventBody) -> Result<LiveEvent, LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::Event(body, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
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
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
    }

    /// Ends the durable session and actor so it cannot be reclaimed.
    pub async fn end(&self) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.stopping.send_replace(true);
        self.sender
            .send(ActorMessage::Stop { end: true, reply })
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
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
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())??;
        self.summary
            .read()
            .map_err(|_| unavailable())
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
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())??;
        self.summary
            .read()
            .map_err(|_| unavailable())
            .map(|value| value.clone())
    }

    pub fn summary(&self) -> Result<LiveSessionSummary, LiveError> {
        self.summary
            .read()
            .map_err(|_| unavailable())
            .map(|value| value.clone())
    }

    /// Journals an unexpected backend failure; a later reclaim can recover in place.
    pub async fn backend_failed(&self, reason: String) -> Result<(), LiveError> {
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(ActorMessage::BackendFailed(reason, reply))
            .await
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
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
            .map_err(|_| unavailable())?;
        receive.await.map_err(|_| unavailable())?
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

enum ActorMessage {
    Command(
        LiveCommand,
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
struct Teardown {
    bridge_stopped: bool,
    pane_terminated: bool,
    capture_removed: bool,
}

fn remove_capture_once(
    terminal: &ZellijLiveAdapter,
    teardown: &mut Teardown,
    session: &impl std::fmt::Display,
) {
    if teardown.capture_removed {
        return;
    }
    teardown.capture_removed = true;
    if let Err(error) = terminal.remove_capture() {
        tracing::error!("odind: terminal-capture remove-failed session={session} reason={error}");
    }
}

struct CommandRuntime<'a> {
    terminal: Option<&'a Arc<ZellijLiveAdapter>>,
    subscribers: &'a mut Vec<mpsc::Sender<ReplayTailItem>>,
    teardown: &'a mut Teardown,
    stopping: &'a tokio::sync::watch::Receiver<bool>,
}

/// The immutable per-spawn world one session actor's run loop serves: the
/// actor's durable summary state, its ledger and control seams, the launch
/// identity reclaims compare against, the optional terminal adapter, and
/// the durable completion-event observer for delegated children.
struct ActorContext {
    summary: Arc<RwLock<LiveSessionSummary>>,
    ledger: Arc<dyn LiveLedger>,
    control: ControlExecutor,
    normalizer: Arc<EventNormalizer>,
    launch: (ProviderName, ModelName),
    terminal: Option<Arc<ZellijLiveAdapter>>,
    completion_observer: Option<Arc<dyn crate::host_tools::delegation::CompletionEventObserver>>,
    stopping: tokio::sync::watch::Receiver<bool>,
}

/// Elapsed wall-clock budget of ONE model turn, declared by the seat's
/// `[live] max_turn_seconds`. Strictly per-turn and monotonic: armed when
/// the session enters `Running`, disarmed only on a settled terminal state
/// (`Idle`/`Failed`/`Ended`). One expiry cancels the turn exactly once
/// through the shared abort seam and journals an honest terminal.
struct TurnBudgetClock {
    budget: Duration,
    /// Monotonic deadline of the armed turn; `None` when no turn is armed.
    deadline: Option<Instant>,
    /// Monotonic arming counter: identifies the armed turn episode.
    episode: u64,
    /// The give-up for the current episode already ran. A refused
    /// cancellation or a failed journal append leaves the summary Running;
    /// that same turn must never be re-armed — the once-per-turn expiry
    /// holds even when persistence fails. Cleared when the session settles
    /// (`Idle`/`Failed`/`Ended`), so the next turn arms a fresh episode.
    given_up: bool,
}

/// Bounded grace for the budget give-up's cancellation: the declared budget
/// ends the turn, and the cancellation confirm must not wait on a child
/// that never answers. Measured abort confirms run ~1s; five seconds is
/// generous headroom that stays finite.
const TURN_BUDGET_ABORT_GRACE: Duration = Duration::from_secs(5);

impl TurnBudgetClock {
    fn new(budget: Duration) -> Self {
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
    fn observe(&mut self, state: LiveSessionState) {
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

    /// Time until the deadline; `Some(Duration::ZERO)` once passed, so the
    /// timer wake fires instead of the mailbox waiting forever. `None`
    /// while no turn is armed.
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Arms a fresh episode when no turn is armed; keeps an already-armed
    /// deadline untouched — the declaration is elapsed time, so every wait
    /// of ONE turn (the initial dispatch included) shares the turn's single
    /// deadline, and a follow-up never re-arms it. Called when a
    /// starting-turn command is durably accepted, before its awaited
    /// dispatch, so the declared budget bounds the initial dispatch too.
    fn arm(&mut self) {
        if self.deadline.is_none() && !self.given_up {
            self.episode = self.episode.saturating_add(1);
            self.deadline = Some(Instant::now() + self.budget);
        }
    }

    /// Whether the armed turn's budget has elapsed and the session can be
    /// cancelled now.
    fn due(&self, state: LiveSessionState) -> bool {
        state == LiveSessionState::Running
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }
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
            ActorMessage::Subscribe(after, reply) => {
                let result = subscribe(&summary, &ledger, after, &mut subscribers).await;
                let _ = reply.send(result);
            }
            ActorMessage::Omp(frame, reply) => {
                let result = async {
                    for body in normalizer.normalize_omp(&frame)? {
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
                    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
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
                        let mut current = summary.write().map_err(|_| unavailable())?;
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
                            let epoch = summary.read().map_err(|_| unavailable())?.epoch;
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
                    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
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
                            let journaled =
                                i64::try_from(epoch.get()).map_err(|_| unavailable())?;
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
                        let mut current = summary.write().map_err(|_| unavailable())?;
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
                            let epoch = summary.read().map_err(|_| unavailable())?.epoch;
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
                    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
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
                        summary.write().map_err(|_| unavailable())?.state =
                            LiveSessionState::Failed;
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
                    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
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
                        summary.write().map_err(|_| unavailable())?.state = LiveSessionState::Ended;
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
    clock.deadline = None;
    clock.given_up = true;
    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
    if snapshot.state != LiveSessionState::Running {
        return Ok(());
    }
    let budget_seconds = clock.budget.as_secs();
    // The declared budget ends the turn; the cancellation itself is bounded
    // too. A child that never answers its abort must not park the give-up
    // forever: past this grace the give-up journals the typed
    // cancellation-failure error and never claims Idle, exactly like a
    // refused cancellation.
    let cancellation = tokio::time::timeout(
        TURN_BUDGET_ABORT_GRACE,
        control.apply(
            &LiveCommandBody::Abort {
                scope: AbortScope::CurrentTurn,
            },
            snapshot.state,
        ),
    )
    .await;
    match cancellation {
        Ok(Ok(_effect)) => {}
        Ok(Err(error)) => {
            // The append is awaited and its failure propagated: the typed
            // cancellation failure IS the terminal. The summary settles
            // Failed (never Idle), and the normalizer follows immediately
            // so late original-turn frames cannot reopen the failure.
            append_body(
                summary,
                ledger,
                LiveEventBody::Error(SessionError {
                    code: "turn_budget_abort_failed".to_owned(),
                    message: format!(
                        "the turn exceeded the declared turn budget of {budget_seconds}s and \
                         the host cancellation failed: {error}"
                    ),
                    retryable: true,
                    error_status: None,
                }),
                subscribers,
            )
            .await?;
            normalizer.set_session_state(LiveSessionState::Failed)?;
            return Err(unavailable());
        }
        Err(_) => {
            // The grace expired with the cancellation confirm still
            // outstanding; the same honesty applies as for a refused
            // cancellation. (The abort frame may still reach the child —
            // the journaled Failed state and the synchronized normalizer
            // make a late successful agent_end a stale frame, never a
            // reopening Idle transition.)
            append_body(
                summary,
                ledger,
                LiveEventBody::Error(SessionError {
                    code: "turn_budget_abort_failed".to_owned(),
                    message: format!(
                        "the turn exceeded the declared turn budget of {budget_seconds}s and \
                         the host cancellation did not confirm within the bounded grace"
                    ),
                    retryable: true,
                    error_status: None,
                }),
                subscribers,
            )
            .await?;
            normalizer.set_session_state(LiveSessionState::Failed)?;
            return Err(unavailable());
        }
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

async fn apply_command(
    command: LiveCommand,
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    control: &ControlExecutor,
    normalizer: &EventNormalizer,
    runtime: &mut CommandRuntime<'_>,
    mut clock: Option<&mut TurnBudgetClock>,
) -> Result<CommandReceipt, LiveError> {
    let existing = ledger.command(&command).await.map_err(live_error)?;
    let recovering = existing.as_ref().is_some_and(|entry| {
        control.supports_identity_safe_dispatch()
            && entry.dispatch_identity == Some(1)
            && matches!(
                entry.receipt,
                CommandReceipt::Duplicate {
                    prior_outcome: None,
                    ..
                }
            )
            && matches!(
                command.body,
                LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
            )
    });
    if let Some(existing) = &existing {
        if !recovering {
            return Ok(existing.receipt.clone());
        }
    }
    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
    let target = LiveCommandTarget {
        session_id: snapshot.session_id,
        epoch: snapshot.epoch,
        event_head: snapshot.event_head,
        state: snapshot.state,
    };
    if let Err(reason) = command.validate_for(&target).or_else(|reason| {
        if recovering && snapshot.state != LiveSessionState::Ended {
            Ok(())
        } else {
            Err(reason)
        }
    }) {
        let receipt = CommandReceipt::Rejected {
            command_id: command.command_id.clone(),
            reason,
        };
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(receipt.clone()),
            runtime.subscribers,
        )
        .await?;
        return Ok(receipt);
    }
    let journal = if let Some(existing) = existing {
        existing
    } else {
        let journal = ledger.append_command(&command).await.map_err(live_error)?;
        if matches!(journal.receipt, CommandReceipt::Duplicate { .. }) {
            return Ok(journal.receipt);
        }
        append_body(
            summary,
            ledger,
            LiveEventBody::ControlAccepted(journal.receipt.clone()),
            runtime.subscribers,
        )
        .await?;
        journal
    };
    // A starting-turn command arms the declared budget at acceptance —
    // after preflight validation and durable journaling, before the awaited
    // dispatch — so the initial journaled dispatch and its correlated reply
    // are bounded by the deadline exactly like every later turn wait.
    // Rejected preflight commands and replayed duplicates return above
    // without touching the clock; an already-armed clock is never re-armed,
    // so follow-ups of one turn share the turn's single deadline.
    let starts_turn = matches!(
        command.body,
        LiveCommandBody::Prompt { .. } | LiveCommandBody::DecideApproval { .. }
    );
    if starts_turn {
        if let Some(clock) = clock.as_mut() {
            clock.arm();
        }
    }
    // The declared per-turn budget stays effective while a command awaits
    // its backend: a running-state command's correlated RPC reply
    // (Steer/Checkpoint/Abort answer only from a `Running` turn) and a
    // starting-turn command's initial dispatch alike. DecidePermission is
    // deliberately not bounded here: it resolves a `RequiresAction` wait,
    // and cancellation waits only for `Running`.
    // A queued stop ends the wait the same way: the stop's own teardown
    // then shuts the backend the command was dispatched to.
    let deadline_bounded = snapshot.state == LiveSessionState::Running || starts_turn;
    let remaining = clock
        .as_ref()
        .and_then(|clock| clock.remaining())
        .filter(|_| deadline_bounded);
    let expiry = async {
        match remaining {
            Some(remaining) => tokio::time::sleep(remaining).await,
            None => std::future::pending().await,
        }
    };
    let mut stopping = runtime.stopping.clone();
    let applied = tokio::select! {
        biased;
        Ok(_) = stopping.wait_for(|stopping| *stopping) => Err(LiveError::Unavailable {
            code: "session_stopping".to_owned(),
        }),
        () = expiry => Err(LiveError::Unavailable {
            code: "turn_budget_expired".to_owned(),
        }),
        applied = control.apply_identified(&command, snapshot.state) => applied,
    };
    let applied = match applied {
        Ok(Some(effect)) => Ok(effect),
        Ok(None) => {
            tracing::error!(
                "odind: live-command-unsettled session={} command={}",
                command.session_id,
                command.command_id
            );
            return Ok(CommandReceipt::Duplicate {
                command_id: command.command_id.clone(),
                prior_outcome: None,
            });
        }
        Err(error)
            if matches!(&error, LiveError::Unavailable { code } if code != "turn_budget_expired")
                && matches!(
                    command.body,
                    LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
                ) =>
        {
            tracing::error!(
                "odind: live-command-dispatch-unresolved session={} command={} error={error}",
                command.session_id,
                command.command_id
            );
            return Err(error);
        }
        Err(error) => Err(error),
    };
    // Expiry cancels the WAIT, never the dispatched command. For a
    // running-state command the observation below runs the budget's own
    // give-up through the shared abort seam; for a starting-turn command
    // that expired before the session entered Running, the dispatch
    // outcome is unknown and `expired_start` reconciles it below.
    let expired_start = starts_turn
        && snapshot.state != LiveSessionState::Running
        && matches!(
            &applied,
            Err(LiveError::Unavailable { code }) if code == "turn_budget_expired"
        );
    let outcome = match applied {
        Ok(mut effect) => {
            if effect.reclaim_epoch {
                let epoch = ledger
                    .reclaim(snapshot.session_id)
                    .await
                    .map_err(live_error)?;
                normalizer.set_epoch(epoch)?;
                if let Some(terminal) = runtime.terminal {
                    terminal.set_epoch(epoch).await?;
                }
                let mut current = summary.write().map_err(|_| unavailable())?;
                current.epoch = epoch;
                current.pending_permission_count = 0;
            }
            if let Some(provider) = effect.provider {
                summary.write().map_err(|_| unavailable())?.provider = provider;
            }
            if let Some(model) = effect.model {
                summary.write().map_err(|_| unavailable())?.model = model;
            }
            if let LiveCommandBody::DecidePermission {
                request_id,
                decision,
            } = &command.body
            {
                append_body(
                    summary,
                    ledger,
                    LiveEventBody::PermissionResolved(odin_domain::huginn::PermissionResolution {
                        request_id: request_id.clone(),
                        command_id: command.command_id.clone(),
                        decision: *decision,
                    }),
                    runtime.subscribers,
                )
                .await?;
                if summary
                    .read()
                    .map_err(|_| unavailable())?
                    .pending_permission_count
                    > 0
                {
                    effect.state = Some(LiveSessionState::RequiresAction);
                }
            }
            if let Some(next) = effect.state {
                let previous = summary.read().map_err(|_| unavailable())?.state;
                append_body(
                    summary,
                    ledger,
                    LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous,
                        current: next,
                        reason: Some(format!("control:{:?}", command.body.kind())),
                    }),
                    runtime.subscribers,
                )
                .await?;
                normalizer.set_session_state(next)?;
            }
            // A terminating control already stopped the backend bridge as part
            // of the command; finish the local teardown exactly once before
            // the outcome is journaled so a failed teardown never records
            // Applied.
            let mut teardown_error = None;
            if effect.terminate {
                runtime.teardown.bridge_stopped = true;
                if let Some(terminal) = runtime.terminal {
                    if !runtime.teardown.pane_terminated {
                        match terminal.terminate_pane().await {
                            Ok(()) => runtime.teardown.pane_terminated = true,
                            Err(error) => teardown_error = Some(error),
                        }
                    }
                    remove_capture_once(terminal, runtime.teardown, &command.session_id);
                }
            }
            if let Some(error) = teardown_error {
                CommandOutcome::Failed {
                    command_id: command.command_id.clone(),
                    error: CommandFailure {
                        code: "terminate_failed".to_owned(),
                        message: error.to_string(),
                        retryable: matches!(error, LiveError::Unavailable { .. }),
                    },
                }
            } else {
                CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                }
            }
        }
        Err(error) => CommandOutcome::Failed {
            command_id: command.command_id.clone(),
            error: CommandFailure {
                code: "control_failed".to_owned(),
                message: error.to_string(),
                retryable: matches!(error, LiveError::Unavailable { .. }),
            },
        },
    };
    ledger
        .complete_command(command.command_id.clone(), outcome.clone())
        .await
        .map_err(live_error)?;
    append_body(
        summary,
        ledger,
        LiveEventBody::ControlCompleted(outcome),
        runtime.subscribers,
    )
    .await?;
    if expired_start {
        // Reconciliation of the uncertain dispatch: the wire write may
        // already have been accepted, so the child can start the turn after
        // our timeout. Cancel bounded through the shared abort seam (a
        // child with no live turn answers promptly; the bound only fences
        // a child that never answers), disarm this episode for good, and
        // journal the typed failure terminal — Failed, never Idle — so a
        // late-started turn's frames can never reopen a live turn outside
        // the declared budget. The retryable command failure never
        // re-applies its effect on replay: the journaled command row is
        // complete, and recovery advances the epoch before new work.
        if let Some(clock) = clock.as_mut() {
            clock.deadline = None;
            clock.given_up = true;
        }
        let cancellation = tokio::time::timeout(
            TURN_BUDGET_ABORT_GRACE,
            control.apply(
                &LiveCommandBody::Abort {
                    scope: AbortScope::CurrentTurn,
                },
                snapshot.state,
            ),
        )
        .await;
        let cancellation_outcome = match &cancellation {
            Ok(Ok(_)) => "the host cancellation confirmed".to_owned(),
            Ok(Err(error)) => format!("the host cancellation failed: {error}"),
            Err(_) => "the host cancellation did not confirm within the bounded grace".to_owned(),
        };
        let budget_seconds = clock
            .as_ref()
            .map(|clock| clock.budget.as_secs())
            .unwrap_or_default();
        append_body(
            summary,
            ledger,
            LiveEventBody::Error(SessionError {
                code: "turn_budget_expired".to_owned(),
                message: format!(
                    "the turn exceeded the declared turn budget of {budget_seconds}s before \
                     its dispatch completed; the dispatch outcome is unknown and \
                     {cancellation_outcome}"
                ),
                retryable: true,
                error_status: None,
            }),
            runtime.subscribers,
        )
        .await?;
        normalizer.set_session_state(LiveSessionState::Failed)?;
    }
    if recovering {
        return Ok(ledger
            .command(&command)
            .await
            .map_err(live_error)?
            .expect("recovered command remains journaled")
            .receipt);
    }
    Ok(journal.receipt)
}

async fn subscribe(
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    after: EventSeq,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
) -> Result<LiveEventStream, LiveError> {
    let session_id = summary.read().map_err(|_| unavailable())?.session_id;
    let head = ledger.head(session_id).await.map_err(live_error)?;
    let (sender, receiver) = mpsc::channel(SUBSCRIPTION_CAPACITY);
    subscribers.push(sender);
    let limit = NonZeroU16::new(1024).ok_or_else(unavailable)?;
    let mut cursor = after;
    let mut events = Vec::new();
    while cursor < head {
        let page = ledger
            .history(HistoryQuery {
                session_id,
                after: cursor,
                limit,
            })
            .await
            .map_err(live_error)?;
        if page.events.is_empty() {
            break;
        }
        cursor = page.next_after;
        events.extend(
            page.events
                .into_iter()
                .filter(|event| event.sequence <= head),
        );
    }
    Ok(Box::pin(
        ReplayJoin::open(events, after, head, receiver).replay_then_tail(),
    ))
}

async fn append_body(
    summary: &Arc<RwLock<LiveSessionSummary>>,
    ledger: &Arc<dyn LiveLedger>,
    body: LiveEventBody,
    subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>,
) -> Result<LiveEvent, LiveError> {
    let snapshot = summary.read().map_err(|_| unavailable())?.clone();
    let event = ledger
        .append(
            snapshot.epoch,
            NewLiveEvent {
                session_id: snapshot.session_id,
                event_id: EventId::new(format!("event:{}", Uuid::new_v4()))
                    .map_err(|_| unavailable())?,
                occurred_at: OffsetDateTime::now_utc(),
                body: body.clone(),
            },
        )
        .await
        .map_err(live_error)?;
    {
        let mut summary = summary.write().map_err(|_| unavailable())?;
        summary.event_head = event.sequence;
        summary.updated_at = event.occurred_at;
        let previous = summary.state;
        match body {
            LiveEventBody::SessionStateChanged(change) => summary.state = change.current,
            LiveEventBody::PermissionRequested(_) => {
                summary.pending_permission_count =
                    summary.pending_permission_count.saturating_add(1)
            }
            LiveEventBody::PermissionResolved(_) => {
                summary.pending_permission_count =
                    summary.pending_permission_count.saturating_sub(1)
            }
            LiveEventBody::TerminalSnapshot(reference) => {
                summary.terminal_head = reference.sequence
            }
            LiveEventBody::TerminalDelta(reference) => summary.terminal_head = reference.sequence,
            LiveEventBody::SessionClosed(_) => summary.state = LiveSessionState::Ended,
            LiveEventBody::Error(_) => summary.state = LiveSessionState::Failed,
            _ => {}
        }
        if summary.state == LiveSessionState::Failed {
            if previous != LiveSessionState::Failed {
                summary.failed_at = Some(event.occurred_at);
            }
        } else {
            summary.failed_at = None;
        }
    }
    publish(event.clone(), subscribers);
    Ok(event)
}

fn publish(event: LiveEvent, subscribers: &mut Vec<mpsc::Sender<ReplayTailItem>>) {
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

fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "session_actor".to_owned(),
    }
}

#[cfg(test)]
pub(crate) mod tests;
