use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::sync::Arc;

use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveCommand, LiveError, LiveEventBody, LiveLaunchOption, LiveSessionId,
    LiveSessionState, LiveSessionSummary, ModelName, OpenSessionRequest, ProviderName,
    SessionManifest, SessionOpened, SessionStateChanged, TerminalSeq, WorkloadSessionBinding,
};
use odin_domain::{EventId, NodeId, SeatId, SliceId};
use time::OffsetDateTime;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use super::binding::LiveSessionLauncher;
use super::launch::LiveOpenOwnership;
use super::LiveSupervisor;
use crate::live::ledger::{
    live_error, state_after, LedgerError, LedgerSession, LiveLedger, NewLiveEvent,
};
use crate::live::session_actor::SessionActorHandle;

#[derive(Clone)]
pub struct LiveSeatBinding {
    pub seat_id: SeatId,
    pub slice_id: SliceId,
    pub display_name: String,
    pub launch_options: Vec<LiveLaunchOption>,
    pub allowed_nodes: Vec<NodeId>,
    pub max_sessions: usize,
    /// Declared elapsed wall-clock budget of ONE model turn for this
    /// seat's sessions, from the seat's `[live] max_turn_seconds`
    /// declaration. `None` declares no product turn budget: turns run
    /// until the child settles them.
    pub turn_budget: Option<std::time::Duration>,
}

impl LiveSeatBinding {
    /// Selected provider/model pairs must appear in the seat's declared launches.
    ///
    /// The command-side composition derivation and this supervisor's own
    /// session-open admission run EXACTLY this predicate, so authority can
    /// never be composed for a pair an open would refuse, and an open can
    /// never admit a pair no composition could name. Declaration order is
    /// never a selection: a seat that wants a shorter default must name it.
    pub fn declared_launch_option(
        &self,
        provider: &ProviderName,
        model: &ModelName,
    ) -> Option<&LiveLaunchOption> {
        self.launch_options
            .iter()
            .find(|option| option.provider == *provider && option.model == *model)
    }
}

impl LiveSupervisor {
    /// Constructs the supervisor from within the daemon runtime context:
    /// the current handle becomes the lifetime owner of every session
    /// actor this supervisor launches.
    pub fn new(
        ledger: Arc<dyn LiveLedger>,
        launcher: Arc<dyn LiveSessionLauncher>,
        max_sessions: usize,
        completion_observer: Option<
            std::sync::Arc<dyn crate::host_tools::delegation::CompletionEventObserver>,
        >,
    ) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            launcher,
            bindings: RwLock::new(BTreeMap::new()),
            actors: RwLock::new(BTreeMap::new()),
            inactive: RwLock::new(BTreeMap::new()),
            open_gate: Mutex::new(()),
            starting: std::sync::Mutex::new(BTreeMap::new()),
            max_sessions,
            runtime: tokio::runtime::Handle::current(),
            completion_observer,
            capsule_root: std::sync::OnceLock::new(),
        })
    }

    pub async fn discover(
        ledger: Arc<dyn LiveLedger>,
        launcher: Arc<dyn LiveSessionLauncher>,
        max_sessions: usize,
        completion_observer: Option<
            std::sync::Arc<dyn crate::host_tools::delegation::CompletionEventObserver>,
        >,
    ) -> Result<Arc<Self>, LiveError> {
        // Bounded working-set loading over the LEDGER'S PAGED API — never
        // an all-history map: durable metadata arrives in bounded chunks,
        // each session is classified by restoring its journal exactly
        // once, and only recoverable non-terminal sessions are parked —
        // and only while the declared capacity allows. Terminal sessions
        // and capacity-overflow sessions stay purely durable: open,
        // recovery, and the unified page read them back on demand.
        let supervisor = Self::new(ledger, launcher, max_sessions, completion_observer);
        let mut cursor: Option<LiveSessionId> = None;
        loop {
            let chunk = supervisor
                .ledger
                .sessions_after(cursor, 256)
                .await
                .map_err(live_error)?;
            let chunk_len = chunk.len();
            for session in &chunk {
                if supervisor.inactive.read().await.len() >= supervisor.max_sessions {
                    // Declared capacity is reached: later history pages
                    // could only classify overflow sessions that stay
                    // purely durable, so the scan stops here instead of
                    // paging the full history metadata.
                    return Ok(supervisor);
                }
                let summary = restore_summary(&*supervisor.ledger, session).await?;
                if !parks_on_discovery(&summary, OffsetDateTime::now_utc()) {
                    continue;
                }
                supervisor
                    .inactive
                    .write()
                    .await
                    .insert(summary.session_id, summary);
            }
            cursor = chunk.last().map(|session| session.manifest.session_id);
            if chunk_len < 256 {
                break;
            }
        }
        Ok(supervisor)
    }

    pub async fn bind(&self, binding: LiveSeatBinding) -> Result<(), LiveError> {
        if binding.max_sessions == 0 || binding.allowed_nodes.is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "invalid_seat_binding".to_owned(),
                message: "seat binding requires nodes and a nonzero session limit".to_owned(),
            });
        }
        let mut bindings = self.bindings.write().await;
        if bindings.insert(binding.seat_id.clone(), binding).is_some() {
            return Err(LiveError::Conflict {
                code: "seat_already_bound".to_owned(),
                message: "seat binding already exists".to_owned(),
            });
        }
        Ok(())
    }

    pub async fn bindings(&self) -> Vec<LiveSeatBinding> {
        self.bindings.read().await.values().cloned().collect()
    }

    pub async fn open(&self, request: OpenSessionRequest) -> Result<LiveSessionSummary, LiveError> {
        self.open_inner(request, None, &LiveOpenOwnership::default())
            .await
    }

    /// Cooperatively cancels an open and joins its actual daemon-runtime
    /// launcher before returning. The ownership bit reports actor insertion
    /// before initial-prompt delivery, or unproven cleanup requiring retention
    /// of the launch's authority. The caller must await cancellation completion.
    pub async fn open_owned(
        &self,
        request: OpenSessionRequest,
        mut cancellation: tokio::sync::watch::Receiver<bool>,
    ) -> (Result<LiveSessionSummary, LiveError>, bool) {
        let ownership = LiveOpenOwnership::default();
        let result = {
            let open = self.open_inner(request, None, &ownership);
            tokio::pin!(open);
            tokio::select! {
                biased;
                _ = async {
                    loop {
                        if *cancellation.borrow_and_update() {
                            break;
                        }
                        if cancellation.changed().await.is_err() {
                            break;
                        }
                    }
                } => Err(LiveError::Unavailable {
                    code: "open_cancelled".to_owned(),
                }),
                result = &mut open => result,
            }
        };
        let result = match ownership
            .cancel_and_join(self.launcher.cancellation_joins_resources())
            .await
        {
            Ok(()) => result,
            Err(error) => {
                ownership.commit();
                Err(error)
            }
        };
        if matches!(&result, Err(LiveError::Unavailable { code }) if code == "open_launcher_join_failed")
        {
            ownership.commit();
        }
        (result, ownership.committed())
    }

    /// Interactive sessions count until child exit or end; pod sessions are excluded.
    /// A failed bridge with a live child still occupies capacity.
    pub(super) async fn interactive_sessions_of(&self, seat: &SeatId) -> Vec<LiveSessionSummary> {
        let mut live = Vec::new();
        let actors: Vec<_> = self.actors.read().await.values().cloned().collect();
        for actor in actors {
            let summary = match actor.summary() {
                Ok(summary) => summary,
                Err(error) => {
                    tracing::warn!("odind: admission skipped an unreadable session actor: {error}");
                    continue;
                }
            };
            if &summary.seat_id != seat || summary.state == LiveSessionState::Ended {
                continue;
            }
            if actor.process_exited().await {
                continue;
            }
            match self.ledger.session(summary.session_id).await {
                Ok(durable) if durable.manifest.workload.is_some() => continue,
                Ok(_) => {}
                // Unreadable: it keeps its slot (fail closed on capacity).
                Err(error) => tracing::error!(
                    "odind: admission could not read session {} kind: {error}",
                    summary.session_id
                ),
            }
            live.push(summary);
        }
        live
    }

    /// Opens one kube-launched workload session with its exact declared
    /// binding: the only lawful producer is the workload launch port, whose
    /// operation id is the durable settlement key of the admitted carrier.
    pub async fn open_workload(
        &self,
        request: OpenSessionRequest,
        workload: WorkloadSessionBinding,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.open_inner(request, Some(workload), &LiveOpenOwnership::default())
            .await
    }

    async fn open_inner(
        &self,
        request: OpenSessionRequest,
        workload: Option<WorkloadSessionBinding>,
        ownership: &LiveOpenOwnership,
    ) -> Result<LiveSessionSummary, LiveError> {
        let gate = self.open_gate.lock().await;
        let binding = self
            .bindings
            .read()
            .await
            .get(&request.seat_id)
            .cloned()
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "seat".to_owned(),
                object_id: request.seat_id.to_string(),
            })?;
        if request.slice_id != binding.slice_id
            || !binding.allowed_nodes.contains(&request.target_node)
            || binding
                .declared_launch_option(&request.provider, &request.model)
                .is_none()
        {
            return Err(LiveError::Unauthorized);
        }
        let session_id = session_id_for(&request.command_id)?;
        let manifest = SessionManifest {
            session_id,
            seat_id: request.seat_id.clone(),
            slice_id: request.slice_id.clone(),
            project_id: request.project_id.clone(),
            provider: request.provider.clone(),
            model: request.model.clone(),
            title: request.title.clone(),
            target_node: request.target_node.clone(),
            open_tab: request.open_tab,
            workload,
            served_revision: request.served_revision,
            // The declared option's harness travels with the session: the
            // launcher runs it under that harness and environment.
            harness: binding
                .declared_launch_option(&request.provider, &request.model)
                .and_then(|option| option.harness.clone()),
        };
        self.refuse_starting(session_id)?;
        if let Some(actor) = self.actors.read().await.get(&session_id) {
            let existing = self.ledger.session(session_id).await.map_err(live_error)?;
            if existing.manifest != manifest {
                return Err(LiveError::Conflict {
                    code: "open_command_conflict".to_owned(),
                    message: "open command ID is already bound to another manifest".to_owned(),
                });
            }
            ownership.commit();
            return actor.summary();
        }
        if let Some(summary) = self.inactive.read().await.get(&session_id) {
            let existing = self.ledger.session(session_id).await.map_err(live_error)?;
            if existing.manifest != manifest {
                return Err(LiveError::Conflict {
                    code: "open_command_conflict".to_owned(),
                    message: "open command ID is already bound to another manifest".to_owned(),
                });
            }
            return Ok(summary.clone());
        }
        // Neither map holds it: consult the DURABLE journal before any
        // effect. A terminal session stays terminal — its exact durable
        // summary is returned without any launch — and a parked
        // non-terminal session is remembered through the bounded cache,
        // never silently respawned by a re-open (recovery is the explicit
        // Restart's job). Only a typed NotFound means "genuinely new":
        // ledger I/O or corruption propagates, it is never read as
        // absence.
        match self.ledger.session(session_id).await {
            Ok(durable_session) => {
                if durable_session.manifest != manifest {
                    return Err(LiveError::Conflict {
                        code: "open_command_conflict".to_owned(),
                        message: "open command ID is already bound to another manifest".to_owned(),
                    });
                }
                let durable = restore_summary(&*self.ledger, &durable_session).await?;
                if durable.state != LiveSessionState::Ended {
                    self.park(session_id, durable.clone()).await?;
                }
                return Ok(durable);
            }
            // The raw ledger call fails with the LEDGER's typed error:
            // only SessionMissing is "genuinely new", everything else is
            // mapped through live_error and propagated.
            Err(LedgerError::SessionMissing(_)) => {}
            Err(error) => return Err(live_error(error)),
        }
        // A session that settled Ended releases its seat here instead of
        // holding it for the daemon's lifetime: a terminal conversation is
        // never a live one, and reopening a chat must not require a daemon
        // restart. Its summary leaves the process entirely — history is
        // ledger-owned. Failed sessions keep their actor: a typed Restart
        // can still recover them within this daemon.
        self.retire_ended().await;
        // Release slots only after child exit or teardown, not merely bridge failure.
        let mut live_for_seat: Vec<String> = self
            .interactive_sessions_of(&request.seat_id)
            .await
            .iter()
            .map(|summary| summary.session_id.to_string())
            .collect();
        live_for_seat.extend(self.starting_interactive(&request.seat_id));
        // A pod's agent session runs its harness in the pod, bounded by the
        // pod itself (one session per admitted launch operation) and the
        // roster limit below: it neither takes nor waits for one of the
        // seat's interactive slots.
        if manifest.workload.is_none() && live_for_seat.len() >= binding.max_sessions {
            let live = live_for_seat.join(", ");
            return Err(LiveError::ResourceLimit {
                limit: format!(
                    "seat {} already holds its bounded maximum of {} live session(s): {live}; \
                     attach to an existing session instead of opening another",
                    request.seat_id, binding.max_sessions
                ),
            });
        }
        // The declared composition limit bounds the ENTIRE tracked roster
        // — live actors plus recoverable parked sessions — across ALL
        // seats: in-memory session state is a declared budget, never an
        // accident of per-seat arithmetic.
        let mut roster = self.roster_len(None).await?;
        if roster >= self.max_sessions
            && self.reclaim_idle_capacity(OffsetDateTime::now_utc()).await
        {
            roster = self.roster_len(None).await?;
        }
        if roster >= self.max_sessions {
            return Err(LiveError::ResourceLimit {
                limit: format!(
                    "declared limits.sessions.max_sessions is {}; {} session(s) are already \
                     tracked; attach to an existing session instead of opening another",
                    self.max_sessions, roster
                ),
            });
        }
        self.ledger
            .create_session(manifest.clone())
            .await
            .map_err(live_error)?;
        let session = self.ledger.session(session_id).await.map_err(live_error)?;
        if session.head.get() == 0 {
            self.ledger
                .append(
                    session.epoch,
                    NewLiveEvent {
                        session_id,
                        event_id: EventId::new(format!("opened:{session_id}"))
                            .map_err(|_| unavailable())?,
                        occurred_at: OffsetDateTime::now_utc(),
                        body: LiveEventBody::SessionOpened(SessionOpened {
                            manifest: Box::new(manifest.clone()),
                        }),
                    },
                )
                .await
                .map_err(live_error)?;
        }
        // The launch (a child process and its handshake) runs outside the
        // gate: this session holds its slot and roster place as starting,
        // so other opens and reclaims proceed meanwhile.
        let starting = StartingSlot::hold(self, session_id, &manifest);
        drop(gate);
        let launched = self
            .launch_actor_owned(manifest, session.epoch, false, ownership)
            .await;
        let gate = self.open_gate.lock().await;
        drop(starting);
        let actor = match launched {
            Ok(actor) => actor,
            Err(error) => {
                // A failed explicit launch is terminal. Otherwise its persisted
                // Starting record silently respawns on the next daemon start.
                self.ledger
                    .append(
                        session.epoch,
                        NewLiveEvent {
                            session_id,
                            event_id: EventId::new(format!("open-failed:{session_id}"))
                                .map_err(|_| unavailable())?,
                            occurred_at: OffsetDateTime::now_utc(),
                            body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous: LiveSessionState::Starting,
                                current: LiveSessionState::Failed,
                                reason: Some(error.to_string()),
                            }),
                        },
                    )
                    .await
                    .map_err(live_error)?;
                let durable = self.ledger.session(session_id).await.map_err(live_error)?;
                let failed = restore_summary(&*self.ledger, &durable).await?;
                self.park(session_id, failed).await?;
                return Err(error);
            }
        };
        let summary = actor.summary()?;
        self.actors.write().await.insert(session_id, actor.clone());
        ownership.commit();
        drop(gate);
        if let Some(message) = request.initial_prompt {
            let command = LiveCommand {
                command_id: request.command_id,
                session_id,
                expected_epoch: summary.epoch,
                expected_event_head: Some(summary.event_head),
                body: odin_domain::huginn::LiveCommandBody::Prompt { message },
            };
            let _ = actor.command(command).await?;
        }
        actor.summary()
    }

    /// A session whose actor is still launching refuses a second open or a
    /// reclaim until that launch settles.
    pub(super) fn refuse_starting(&self, session_id: LiveSessionId) -> Result<(), LiveError> {
        let starting = self.starting.lock().map_err(|_| unavailable())?;
        if starting.contains_key(&session_id) {
            return Err(LiveError::Unavailable {
                code: "session_starting".to_owned(),
            });
        }
        Ok(())
    }

    fn starting_interactive(&self, seat: &SeatId) -> Vec<String> {
        self.starting.lock().map_or_else(
            |_| Vec::new(),
            |starting| {
                starting
                    .iter()
                    .filter(|(_, (owner, workload))| owner == seat && !workload)
                    .map(|(session_id, _)| session_id.to_string())
                    .collect()
            },
        )
    }

    /// Reclaims actors whose sessions settled `Ended` and removes them
    /// from the roster entirely: the handle leaves the live map, its
    /// bounded teardown runs at most once (an Ended session's bridge
    /// already stopped, so the stop only closes subscribers), and NOTHING
    /// is parked — a terminal session is ledger history, never process
    /// memory. This is the eviction that keeps the roster equal to the
    /// actually-live sessions across any number of spawn/end cycles.
    /// Deliberately NOT public: eviction runs inside the supervisor's own
    /// synchronized paths (open/reclaim hold the gate; summaries is the
    /// read path), never as an unsynchronized external teardown.
    pub(super) async fn retire_ended(&self) {
        let ended: Vec<(LiveSessionId, SessionActorHandle)> = self
            .actors
            .read()
            .await
            .iter()
            .filter_map(|(session_id, actor)| {
                let summary = actor.summary().ok()?;
                (summary.state == LiveSessionState::Ended || actor.exited())
                    .then(|| (*session_id, actor.clone()))
            })
            .collect();
        if ended.is_empty() {
            return;
        }
        let mut retired = Vec::new();
        {
            // Every mutation of the actors map is serialized by the open
            // gate `open` holds and by the actor-map lock here, so each
            // scanned handle is still the map's current entry at removal
            // time.
            let mut actors = self.actors.write().await;
            for (session_id, actor) in ended {
                // Only the scanned incarnation leaves: a reclaim may have
                // replaced it meanwhile (the read path holds no gate).
                if actors
                    .get(&session_id)
                    .is_some_and(|current| current.same_actor(&actor))
                {
                    actors.remove(&session_id);
                    retired.push((session_id, actor));
                }
            }
        }
        for (session_id, actor) in retired {
            // An actor whose loop exited (a stop that failed closed) serves
            // nothing: its session leaves the live roster and is parked by
            // its last state, or dropped when terminal — it must never read
            // live behind a dead handle.
            if actor.exited() {
                if let Ok(summary) = actor.summary() {
                    tracing::info!(
                        "odind: session-retire exited-actor session={session_id} state={:?}",
                        summary.state
                    );
                    let _ = self.park(session_id, summary).await;
                }
                continue;
            }
            // Best-effort teardown: the session is already Ended, so a stop
            // failure must never block the seat it is releasing. The
            // durable journal already carries the terminal truth; a failed
            // stop cannot un-end it — but it may leave a child process.
            if let Err(error) = actor.stop().await {
                tracing::error!(
                    "odind: session-retire stop-failed session={session_id} reason={error}"
                );
            }
            self.remove_capsule(session_id);
        }
    }

    /// Deletes each ended session's capsule under `state_root` from now on.
    pub fn remove_capsules_under(&self, state_root: std::path::PathBuf) {
        if let Err(ignored) = self.capsule_root.set(state_root) {
            tracing::error!(
                "capsule root {} ignored: this supervisor already removes capsules elsewhere",
                ignored.display()
            );
        }
    }

    fn remove_capsule(&self, session_id: LiveSessionId) {
        if let Some(root) = self.capsule_root.get().cloned() {
            self.runtime
                .spawn_blocking(move || crate::live::capsules::remove_capsule(&root, session_id));
        }
    }

    /// Deletes the capsule of every session whose journal is Ended: the
    /// start-time pass for sessions that ended in an earlier daemon.
    pub async fn remove_ended_capsules(&self) -> Result<usize, String> {
        let Some(root) = self.capsule_root.get().cloned() else {
            return Ok(0);
        };
        let mut removed = 0;
        for session_id in crate::live::capsules::capsule_sessions(&root)? {
            let ended = self
                .terminal_summary(session_id)
                .await
                .map_err(|error| format!("session {session_id} journal unreadable: {error}"))?;
            if ended.is_some() {
                let root = root.clone();
                tokio::task::spawn_blocking(move || {
                    crate::live::capsules::remove_capsule(&root, session_id)
                })
                .await
                .map_err(|error| format!("capsule removal for {session_id} failed: {error}"))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Frees one roster slot for an open that would exceed the declared
    /// budget (see [`CAPACITY_RECLAIM_IDLE`]): a parked victim leaves the
    /// parked map, a live one has its processes stopped — both stay durable
    /// and resumable. Returns whether a slot was freed.
    async fn reclaim_idle_capacity(&self, now: OffsetDateTime) -> bool {
        let mut candidates = Vec::new();
        for (session_id, actor) in self.actors.read().await.iter() {
            if let Ok(summary) = actor.summary() {
                candidates.push((*session_id, summary, false));
            }
        }
        for (session_id, summary) in self.inactive.read().await.iter() {
            candidates.push((*session_id, summary.clone(), true));
        }
        let Some((victim, parked)) = capacity_victim(&candidates, now) else {
            tracing::error!("odind: session capacity full; no idle session to reclaim");
            return false;
        };
        if parked {
            self.inactive.write().await.remove(&victim);
        } else {
            let actor = {
                let mut actors = self.actors.write().await;
                actors.remove(&victim)
            };
            if let Some(actor) = actor {
                if let Err(error) = actor.stop().await {
                    tracing::error!(
                        "odind: session capacity-reclaim stop-failed session={victim} reason={error}"
                    );
                }
            }
        }
        tracing::info!(
            "odind: session capacity-reclaim session={victim} parked={parked} (durable, resumable)"
        );
        true
    }

    /// The launch operation of `session` when it is a workload (pod)
    /// environment session.
    pub async fn workload_operation(
        &self,
        session: LiveSessionId,
    ) -> Result<Option<String>, LiveError> {
        let session = self.ledger.session(session).await.map_err(live_error)?;
        Ok(session.manifest.workload.map(|binding| binding.operation))
    }

    /// Ends an absent workload actor under the admission gate, excluding concurrent launch.
    /// The durable marker frees its roster slot and queues carrier release across restarts.
    /// `Ok(true)` says THIS call wrote the transition — exactly one
    /// caller ever sees it; `Ok(false)` says the session was already
    /// terminal (including a concurrent settlement that wrote the
    /// identical transition first), or never existed — nothing written.
    pub async fn settle_absent_session(
        &self,
        session_id: LiveSessionId,
        reason: &str,
    ) -> Result<bool, LiveError> {
        let _gate = self.open_gate.lock().await;
        self.refuse_starting(session_id)?;
        // Under the gate no incarnation can register: an actor seen here
        // was live before the caller's NotFound, so its own end path owns
        // the transition.
        if self.actors.read().await.contains_key(&session_id) {
            return Err(LiveError::Conflict {
                code: "session_live".to_owned(),
                message: "the session holds a live actor; its own end path owns the \
                          transition"
                    .to_owned(),
            });
        }
        let session = match self.ledger.session(session_id).await {
            Ok(session) => session,
            Err(LedgerError::SessionMissing(_)) => return Ok(false),
            Err(error) => return Err(live_error(error)),
        };
        let summary = restore_summary(&*self.ledger, &session).await?;
        if summary.state == LiveSessionState::Ended {
            self.inactive.write().await.remove(&session_id);
            return Ok(false);
        }
        match self
            .ledger
            .append(
                session.epoch,
                NewLiveEvent {
                    session_id,
                    event_id: EventId::new(format!("settled-absent:{session_id}"))
                        .map_err(|_| unavailable())?,
                    occurred_at: OffsetDateTime::now_utc(),
                    body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: summary.state,
                        current: LiveSessionState::Ended,
                        reason: Some(reason.to_owned()),
                    }),
                },
            )
            .await
        {
            Ok(_) => {}
            // A concurrent settlement already journaled the identical
            // transition: adopt it — evict the roster slot and report
            // nothing written, so exactly one caller logs the settlement.
            Err(LedgerError::DuplicateEvent(_)) => {
                self.inactive.write().await.remove(&session_id);
                return Ok(false);
            }
            Err(error) => return Err(live_error(error)),
        }
        self.inactive.write().await.remove(&session_id);
        Ok(true)
    }

    /// Every ended workload (pod) session with the launch operation that
    /// created its pod, read from the durable ledger and journals. A pod's
    /// carrier release outlives its resting-scan visibility — the report
    /// pump ends the session before releasing, and an ended session is
    /// ledger history — so the release backlog is enumerated from durable
    /// truth, never from live actors, restarts included.
    pub async fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, LiveError> {
        let mut ended = Vec::new();
        for session in self.ledger.sessions().await.map_err(live_error)? {
            if session.manifest.workload.is_none() {
                continue;
            }
            let summary = restore_summary(&*self.ledger, &session).await?;
            if summary.state == LiveSessionState::Ended {
                if let Some(workload) = session.manifest.workload {
                    ended.push((session.manifest.session_id, workload.operation));
                }
            }
        }
        Ok(ended)
    }

    pub async fn actor(&self, session: LiveSessionId) -> Result<SessionActorHandle, LiveError> {
        let exited = self
            .actors
            .read()
            .await
            .get(&session)
            .is_some_and(SessionActorHandle::exited);
        if exited {
            self.retire_ended().await;
        }
        self.actors
            .read()
            .await
            .get(&session)
            .cloned()
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "active_session".to_owned(),
                object_id: session.to_string(),
            })
    }
    /// The durable summary of a session that currently has no live actor
    /// (parked by a load-only discovery, a failed launch, or a
    /// still-recoverable settled state). `None` for unknown and TERMINAL
    /// sessions: an ended session is not parked anywhere — it is read back
    /// from its durable journal through [`Self::terminal_summary`].
    pub async fn parked(
        &self,
        session_id: LiveSessionId,
    ) -> Result<Option<LiveSessionSummary>, LiveError> {
        if self.actors.read().await.contains_key(&session_id) {
            return Ok(None);
        }
        Ok(self.inactive.read().await.get(&session_id).cloned())
    }

    pub async fn summaries(&self) -> Result<Vec<LiveSessionSummary>, LiveError> {
        // Retire ended actors before projecting the roster; teardown is synchronized internally.
        self.retire_ended().await;
        let mut summaries = Vec::new();
        // Guard bound to the collection: the canonical refresh below takes
        // the write lock.
        let cached_ids: Vec<LiveSessionId> = self.inactive.read().await.keys().copied().collect();
        for session_id in cached_ids {
            if let Some(summary) = self.canonical_cached_summary(session_id).await? {
                summaries.push(without_process(summary));
            }
        }
        for actor in self.actors.read().await.values() {
            summaries.push(actor.summary()?);
        }
        summaries.sort_by_key(|summary| summary.session_id);
        Ok(summaries)
    }

    /// Counts live actors and recoverable parked sessions. Failed bridges retain
    /// slots until child exit or teardown; uncertain actor states still count.
    /// `exclude` prevents a recovering parked session from counting itself twice.
    pub(super) async fn roster_len(
        &self,
        exclude: Option<LiveSessionId>,
    ) -> Result<usize, LiveError> {
        // Drop the map guard before awaiting process-exit checks.
        let live_actors: Vec<_> = self.actors.read().await.values().cloned().collect();
        let mut actors = 0usize;
        for actor in live_actors {
            let counts = match actor.summary() {
                Ok(summary) => {
                    actor_occupies_slot(summary.state, actor.exited(), actor.process_exited().await)
                }
                Err(_) => true,
            };
            if counts {
                actors += 1;
            }
        }
        let mut parked = 0usize;
        // Bind the guard to the collection, not the loop: the canonical
        // refresh below takes the write lock.
        let cached_ids: Vec<LiveSessionId> = self.inactive.read().await.keys().copied().collect();
        for session_id in cached_ids {
            if Some(session_id) == exclude {
                continue;
            }
            if let Some(summary) = self.canonical_cached_summary(session_id).await? {
                if Self::counts_toward_capacity(summary.state) {
                    parked += 1;
                }
            }
        }
        let starting = self.starting.lock().map_or(0, |starting| starting.len());
        Ok(actors + parked + starting)
    }

    /// Parked failed rows use no capacity; live actors require [`actor_occupies_slot`].
    pub(super) fn counts_toward_capacity(state: LiveSessionState) -> bool {
        state.holds_capacity()
    }

    /// Refreshes cached summaries from the journal under a write lock, removing ended rows.
    /// Only still-cached entries are refreshed so concurrent reclaim cannot resurrect them.
    pub(super) async fn canonical_cached_summary(
        &self,
        session_id: LiveSessionId,
    ) -> Result<Option<LiveSessionSummary>, LiveError> {
        if !self.inactive.read().await.contains_key(&session_id) {
            return Ok(None);
        }
        let session = self.ledger.session(session_id).await.map_err(live_error)?;
        let canonical = restore_summary(&*self.ledger, &session).await?;
        let mut cache = self.inactive.write().await;
        match cache.get_mut(&session_id) {
            Some(entry) => {
                if canonical.state == LiveSessionState::Ended {
                    cache.remove(&session_id);
                    return Ok(None);
                }
                *entry = canonical.clone();
                Ok(Some(canonical))
            }
            None => Ok(None),
        }
    }

    /// Parks one summary in the bounded cache — WITHOUT any eviction
    /// policy: if the tracked roster is already at the declared limit the
    /// park is simply skipped. Nothing depends on the cache for
    /// correctness: an unparked session stays fully durable, and open,
    /// recovery, and exact lookup all read the journal directly.
    pub(super) async fn park(
        &self,
        session_id: LiveSessionId,
        summary: LiveSessionSummary,
    ) -> Result<(), LiveError> {
        // Terminal summaries are never cached: a closed or failed row is
        // ledger history, so any cached label for it is dropped and the
        // physically bounded cache holds only recoverable non-terminal
        // entries.
        if !Self::counts_toward_capacity(summary.state) {
            self.inactive.write().await.remove(&session_id);
            return Ok(());
        }
        let mut cache = self.inactive.write().await;
        // Physical bound of the cache itself, enforced under the same
        // write guard as the insertion: a new key is admitted only under
        // the declared bound (replacing an existing key is always
        // allowed), so the cache can never exceed it even though the
        // logical roster above excludes terminal entries.
        if cache.len() >= self.max_sessions && !cache.contains_key(&session_id) {
            return Ok(());
        }
        cache.insert(session_id, summary);
        Ok(())
    }

    /// Frees one cached slot for a stranded recovery: the cache is
    /// documented non-load-bearing, so the dropped session stays exactly
    /// as durable and recoverable as before. Selects and removes the
    /// deterministic oldest entry under one write lock.
    pub(super) async fn free_oldest_cached_slot(&self) {
        let mut cache = self.inactive.write().await;
        let victim = cache
            .values()
            .min_by_key(|summary| (summary.updated_at, summary.session_id))
            .map(|summary| summary.session_id);
        if let Some(session_id) = victim {
            cache.remove(&session_id);
        }
    }
    /// The durable summary of one terminal session, read from its journal.
    /// `None` for unknown and non-terminal sessions.
    pub async fn terminal_summary(
        &self,
        session_id: LiveSessionId,
    ) -> Result<Option<LiveSessionSummary>, LiveError> {
        Ok(self
            .durable_summary(session_id)
            .await?
            .filter(|summary| summary.state == LiveSessionState::Ended))
    }

    /// One session's summary read from its journal, whatever its state;
    /// `None` when the ledger has no such session.
    pub async fn durable_summary(
        &self,
        session_id: LiveSessionId,
    ) -> Result<Option<LiveSessionSummary>, LiveError> {
        let session = match self.ledger.session(session_id).await {
            Ok(session) => session,
            Err(LedgerError::SessionMissing(_)) => return Ok(None),
            Err(error) => return Err(live_error(error)),
        };
        restore_summary(&*self.ledger, &session).await.map(Some)
    }

    /// One BOUNDED unified durable page. Every actor session has a
    /// durable row, so there is exactly ONE pagination source: the
    /// ledger's source-bounded metadata page `sessions_after(cursor,
    /// limit + 1)` — the extra row is the lookahead that proves whether
    /// more durable sessions exist beyond this page. Each scanned row is
    /// overlaid with its exact in-memory summary (actor or parked) when
    /// one exists, otherwise restored from the durable journal; seat and
    /// `include_ended` filters then apply. The next cursor is the LAST
    /// SCANNED metadata id — even when filters empty the page — and is
    /// `None` exactly when the source is exhausted, so no row is skipped
    /// or duplicated across pages. Work is bounded: one metadata page
    /// call per request, at most `limit` rows returned, and restores only
    /// for rows without an in-memory overlay.
    pub async fn session_summaries_page(
        &self,
        seat: Option<&SeatId>,
        include_ended: bool,
        after: Option<LiveSessionId>,
        limit: usize,
    ) -> Result<(Vec<LiveSessionSummary>, Option<LiveSessionId>), LiveError> {
        self.retire_ended().await;
        let limit = limit.max(1);
        let scanned = self
            .ledger
            .sessions_after(after, limit + 1)
            .await
            .map_err(live_error)?;
        let has_more = scanned.len() > limit;
        // The (limit+1)th row is ONLY the has-more lookahead: processing
        // stops at exactly the first `limit` source rows, and the cursor
        // is the LAST PROCESSED row's id — the lookahead row itself is
        // left for the next page, so no row can be skipped or duplicated.
        let processed = scanned.iter().take(limit);
        let mut page: Vec<LiveSessionSummary> = Vec::new();
        let mut last_scanned = after;
        for candidate in processed {
            let session_id = candidate.manifest.session_id;
            last_scanned = Some(session_id);
            if seat.is_some_and(|bound| bound != &candidate.manifest.seat_id) {
                continue;
            }
            // The authoritative live overlay of THIS incarnation wins:
            // an actor's summary is always served verbatim. Only a cached
            // parked entry is canonicalized against its durable journal,
            // and a canonically ended entry serves the durable truth.
            let actor = self.actors.read().await.get(&session_id).cloned();
            let summary = match actor {
                Some(actor) => actor.summary()?,
                None => without_process(match self.canonical_cached_summary(session_id).await? {
                    Some(summary) => summary,
                    // Canonically ended (and evicted): the durable truth
                    // is served unchanged.
                    None => restore_summary(&*self.ledger, candidate).await?,
                }),
            };
            if !include_ended
                && matches!(
                    summary.state,
                    LiveSessionState::Ended | LiveSessionState::Failed
                )
            {
                continue;
            }
            // `processed` is already capped at `limit` rows, so the page
            // can never exceed the bound.
            page.push(summary);
        }
        Ok((page, has_more.then_some(last_scanned).flatten()))
    }

    /// The launcher's owned observe-only followers, when the launcher opens
    /// observe-only sessions: the daemon's shutdown stops and joins them
    /// under its one deadline. `None` when nothing tracks.
    pub fn observer_followers(
        &self,
    ) -> Option<std::sync::Arc<crate::live::harness::ObserverFollowers>> {
        self.launcher.observer_followers()
    }

    /// The composed launcher's owned process-harness turns, when it drives
    /// any: the daemon's shutdown stops their admission at its signal and
    /// joins them under its one deadline, after this supervisor's own stop.
    /// `None` when nothing tracks.
    pub fn harness_turns(&self) -> Option<std::sync::Arc<crate::live::harness::HarnessTurns>> {
        self.launcher.harness_turns()
    }

    /// Stops actors and their children while preserving resumable sessions.
    /// Run this before draining work that waits on session replies; failures report stragglers.
    pub async fn shutdown(&self) -> Result<usize, LiveError> {
        let actors = std::mem::take(&mut *self.actors.write().await);
        let stopped = actors.len();
        let mut failure = None;
        for actor in actors.into_values() {
            if let Err(error) = actor.stop().await {
                failure = Some(error);
            }
        }
        failure.map_or(Ok(stopped), Err)
    }
}

/// A session with no actor in this daemon has no process, so every reader
/// (terminal capture, reload hold, roster) sees Detached, never Idle or
/// Running; a command recovers it in place.
fn without_process(mut summary: LiveSessionSummary) -> LiveSessionSummary {
    if summary.state.holds_capacity() {
        summary.state = LiveSessionState::Detached;
    }
    summary
}

/// A session idle longer than this is not parked at discovery and is not
/// part of its seat's current state: it stays durable and recoverable on
/// demand, but never holds a slot of the declared session budget.
pub(crate) const PARK_IDLE_LIMIT: time::Duration = time::Duration::hours(24);

/// A session idle at least this long yields its roster slot to an open that
/// would exceed the declared budget. It stays durable and resumable on demand
/// (the reclaim path re-opens it).
pub(super) const CAPACITY_RECLAIM_IDLE: time::Duration = time::Duration::minutes(10);

/// Which tracked session yields its slot: the longest-idle one that is
/// `Idle` (or parked, any non-running state), idle past
/// [`CAPACITY_RECLAIM_IDLE`], with no pending permission. `None` when every
/// session is busy or recent.
pub(super) fn capacity_victim(
    candidates: &[(LiveSessionId, LiveSessionSummary, bool)],
    now: OffsetDateTime,
) -> Option<(LiveSessionId, bool)> {
    candidates
        .iter()
        .filter(|(_, summary, parked)| {
            summary.state.holds_capacity()
                && (*parked || summary.state == LiveSessionState::Idle)
                && summary.pending_permission_count == 0
                && now - summary.updated_at >= CAPACITY_RECLAIM_IDLE
        })
        .min_by_key(|(_, summary, _)| summary.updated_at)
        .map(|(session_id, _, parked)| (*session_id, *parked))
}

/// Whether discovery parks `summary`: never an ended one; any other only
/// when it was active within [`PARK_IDLE_LIMIT`] — a failed one for its
/// label (it holds no slot), but an old failure is history, not a label
/// that keeps its seat degraded across every restart.
pub(super) fn parks_on_discovery(summary: &LiveSessionSummary, now: OffsetDateTime) -> bool {
    summary.state != LiveSessionState::Ended && now - summary.updated_at <= PARK_IDLE_LIMIT
}

/// What the start-time settlement found for one durable session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartSettlement {
    /// The journal is already terminal (or was never written): the caller's
    /// session row follows it.
    Terminal(LiveSessionState),
    /// Idle past `PARK_IDLE_LIMIT` and named by no owner: journaled
    /// `Ended` now, with the reason.
    Settled {
        previous: LiveSessionState,
        idle_since: OffsetDateTime,
    },
    /// Live in this daemon, parked, owned, or recent: left resumable.
    Resumable,
}

impl LiveSupervisor {
    /// Settles one session a dead daemon left non-terminal.
    /// A session idle past the park limit that no owner names (`owned` is
    /// the caller's verdict, e.g. a conversation's recorded vehicle) can
    /// never be resumed by anyone, so it is journaled `Ended` with the
    /// reason instead of reading as live forever.
    /// A session that is not left resumable gives up its terminal capture.
    pub async fn settle_at_start(
        &self,
        session_id: LiveSessionId,
        owned: bool,
        now: OffsetDateTime,
    ) -> Result<StartSettlement, LiveError> {
        let settlement = self.settle_journal_at_start(session_id, owned, now).await?;
        if settlement != StartSettlement::Resumable {
            self.remove_capture(session_id).await;
        }
        Ok(settlement)
    }

    /// Settles every session holding a terminal capture through
    /// [`Self::settle_at_start`]: a harness session has no controller row,
    /// so the row-driven settlement never reaches it. `owned` names the
    /// sessions a conversation owns. Returns the captures removed.
    pub async fn settle_captures(
        &self,
        owned: impl Fn(LiveSessionId) -> bool,
        now: OffsetDateTime,
    ) -> Result<Vec<LiveSessionId>, LiveError> {
        let Some(admin) = self.launcher.terminal_target_admin() else {
            return Ok(Vec::new());
        };
        let mut removed = Vec::new();
        for session_id in admin.captured_sessions().await? {
            if self.refuse_starting(session_id).is_err() {
                continue;
            }
            if self
                .settle_at_start(session_id, owned(session_id), now)
                .await?
                != StartSettlement::Resumable
            {
                removed.push(session_id);
            }
        }
        Ok(removed)
    }

    async fn remove_capture(&self, session_id: LiveSessionId) {
        let Some(admin) = self.launcher.terminal_target_admin() else {
            return;
        };
        match admin.remove_session_capture(session_id).await {
            Ok(()) => tracing::info!("odind: terminal-capture removed session={session_id}"),
            Err(error) => tracing::error!(
                "odind: terminal-capture remove-failed session={session_id} reason={error}"
            ),
        }
    }

    async fn settle_journal_at_start(
        &self,
        session_id: LiveSessionId,
        owned: bool,
        now: OffsetDateTime,
    ) -> Result<StartSettlement, LiveError> {
        if self.actors.read().await.contains_key(&session_id)
            || self.inactive.read().await.contains_key(&session_id)
        {
            return Ok(StartSettlement::Resumable);
        }
        let session = match self.ledger.session(session_id).await {
            Ok(session) => session,
            Err(LedgerError::SessionMissing(_)) => {
                return Ok(StartSettlement::Terminal(LiveSessionState::Failed))
            }
            Err(error) => return Err(live_error(error)),
        };
        let summary = restore_summary(&*self.ledger, &session).await?;
        if !summary.state.holds_capacity() {
            return Ok(StartSettlement::Terminal(summary.state));
        }
        if owned || parks_on_discovery(&summary, now) {
            return Ok(StartSettlement::Resumable);
        }
        let reason = format!(
            "settled at odind start: idle since {} in an earlier daemon lifetime, and no \
             conversation or task owns it, so nothing can resume it",
            summary
                .updated_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| summary.updated_at.to_string()),
        );
        self.ledger
            .append(
                session.epoch,
                NewLiveEvent {
                    session_id,
                    event_id: EventId::new(format!("settled-at-start:{session_id}"))
                        .map_err(|_| unavailable())?,
                    occurred_at: now,
                    body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: summary.state,
                        current: LiveSessionState::Ended,
                        reason: Some(reason),
                    }),
                },
            )
            .await
            .map_err(live_error)?;
        Ok(StartSettlement::Settled {
            previous: summary.state,
            idle_since: summary.updated_at,
        })
    }

    /// Records a controller row's already-finished state into the file journal
    /// when that journal never closed. Does nothing for a live actor, a
    /// missing journal, or a journal that is already terminal. A `ready` row
    /// is not a caller's input: absence of a local terminal is not this finish.
    pub async fn record_durable_terminal(
        &self,
        session_id: LiveSessionId,
        expected_epoch: odin_domain::huginn::SessionEpoch,
        terminal: LiveSessionState,
        now: OffsetDateTime,
    ) -> Result<bool, LiveError> {
        if terminal.holds_capacity() {
            return Ok(false);
        }
        if self.actors.read().await.contains_key(&session_id) {
            return Ok(false);
        }
        let session = match self.ledger.session(session_id).await {
            Ok(session) => session,
            Err(LedgerError::SessionMissing(_)) => return Ok(false),
            Err(error) => return Err(live_error(error)),
        };
        if session.epoch != expected_epoch {
            return Ok(false);
        }
        let summary = restore_summary(&*self.ledger, &session).await?;
        if !summary.state.holds_capacity() {
            return Ok(false);
        }
        self.ledger
            .append(
                session.epoch,
                NewLiveEvent {
                    session_id,
                    event_id: EventId::new(format!(
                        "row-terminal:{session_id}:{}:{terminal:?}",
                        expected_epoch.get()
                    ))
                    .map_err(|_| unavailable())?,
                    occurred_at: now,
                    body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: summary.state,
                        current: terminal,
                        reason: Some(format!(
                            "controller row is already {terminal:?}; the journal never recorded that finish"
                        )),
                    }),
                },
            )
            .await
            .map_err(live_error)?;
        self.inactive.write().await.remove(&session_id);
        Ok(true)
    }
}

impl LiveSupervisor {
    /// odind opens one observer per declared remote session at start. Every
    /// observer an earlier daemon lifetime opened for the same seat and
    /// environment is superseded: it has no process here and must not read
    /// `Running` in the roster. Each is journaled `Ended` with the reason
    /// and leaves the roster. Returns the sessions it ended.
    pub async fn settle_superseded_observers(
        &self,
        seat: &SeatId,
        environment: &str,
        now: OffsetDateTime,
    ) -> Result<Vec<LiveSessionId>, LiveError> {
        let candidates: Vec<LiveSessionId> = self.inactive.read().await.keys().copied().collect();
        let mut ended = Vec::new();
        for session_id in candidates {
            if self.actors.read().await.contains_key(&session_id) {
                continue;
            }
            let session = self.ledger.session(session_id).await.map_err(live_error)?;
            let manifest = &session.manifest;
            let observes = manifest.seat_id == *seat
                && manifest
                    .harness
                    .as_ref()
                    .is_some_and(|binding| binding.environment == environment);
            if !observes {
                continue;
            }
            let summary = restore_summary(&*self.ledger, &session).await?;
            // Already over: nothing to end, but its capture still goes.
            if !summary.state.holds_capacity() {
                self.inactive.write().await.remove(&session_id);
                self.remove_capture(session_id).await;
                continue;
            }
            self.ledger
                .append(
                    session.epoch,
                    NewLiveEvent {
                        session_id,
                        event_id: EventId::new(format!("superseded-observer:{session_id}"))
                            .map_err(|_| unavailable())?,
                        occurred_at: now,
                        body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                            previous: summary.state,
                            current: LiveSessionState::Ended,
                            reason: Some(format!(
                                "superseded: this daemon watches {environment} with a new \
                                 observer; this one belonged to an earlier daemon lifetime"
                            )),
                        }),
                    },
                )
                .await
                .map_err(live_error)?;
            self.inactive.write().await.remove(&session_id);
            self.remove_capture(session_id).await;
            ended.push(session_id);
        }
        Ok(ended)
    }
}

pub(super) async fn restore_summary(
    ledger: &dyn LiveLedger,
    session: &LedgerSession,
) -> Result<LiveSessionSummary, LiveError> {
    let limit = NonZeroU16::new(1024).ok_or_else(unavailable)?;
    let mut cursor = EventSeq::new(0);
    let mut state = LiveSessionState::Starting;
    let mut started_at = OffsetDateTime::now_utc();
    let mut updated_at = started_at;
    let mut failed_at = None;
    let mut terminal_head = TerminalSeq::new(0);
    let mut pending = 0u16;
    let mut first = true;
    while cursor < session.head {
        let page = ledger
            .history(HistoryQuery {
                session_id: session.manifest.session_id,
                after: cursor,
                limit,
            })
            .await
            .map_err(live_error)?;
        if page.events.is_empty() {
            break;
        }
        for event in &page.events {
            if first {
                started_at = event.occurred_at;
                first = false;
            }
            updated_at = event.occurred_at;
            let next = state_after(state, &event.body);
            if next == LiveSessionState::Failed {
                if state != LiveSessionState::Failed {
                    failed_at = Some(event.occurred_at);
                }
            } else {
                failed_at = None;
            }
            state = next;
            match &event.body {
                LiveEventBody::PermissionRequested(_) if event.epoch == session.epoch => {
                    pending = pending.saturating_add(1);
                }
                LiveEventBody::PermissionResolved(_) if event.epoch == session.epoch => {
                    pending = pending.saturating_sub(1);
                }
                LiveEventBody::TerminalSnapshot(reference) => terminal_head = reference.sequence,
                LiveEventBody::TerminalDelta(reference) => terminal_head = reference.sequence,
                _ => {}
            }
        }
        cursor = page.next_after;
    }
    Ok(LiveSessionSummary {
        session_id: session.manifest.session_id,
        epoch: session.epoch,
        seat_id: session.manifest.seat_id.clone(),
        provider: session.manifest.provider.clone(),
        model: session.manifest.model.clone(),
        title: session.manifest.title.clone(),
        state,
        started_at,
        updated_at,
        failed_at,
        event_head: session.head,
        terminal_head,
        pending_permission_count: pending,
    })
}

/// The deterministic live session identity of one operator command: the sole
/// derivation shared by the supervisor and the operator-side provisioning
/// path, so a pre-minted token always binds the exact session that opens.
pub fn session_id_for(command_id: &odin_domain::CommandId) -> Result<LiveSessionId, LiveError> {
    let digest = blake3::hash(command_id.as_str().as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    LiveSessionId::new(Uuid::from_bytes(bytes)).map_err(|_| unavailable())
}

pub(super) fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "live_supervisor".to_owned(),
    }
}

/// Live actors hold slots until mailbox closure or child exit; bridge failure alone is insufficient.
/// Ended sessions never occupy capacity.
pub(super) fn actor_occupies_slot(
    state: LiveSessionState,
    exited: bool,
    process_exited: bool,
) -> bool {
    !exited && !process_exited && (state.holds_capacity() || state == LiveSessionState::Failed)
}

/// One session's place in the starting map, released however its launch
/// ends (a cancelled open included).
struct StartingSlot<'a> {
    supervisor: &'a LiveSupervisor,
    session_id: LiveSessionId,
}

impl<'a> StartingSlot<'a> {
    fn hold(
        supervisor: &'a LiveSupervisor,
        session_id: LiveSessionId,
        manifest: &SessionManifest,
    ) -> Self {
        if let Ok(mut starting) = supervisor.starting.lock() {
            starting.insert(
                session_id,
                (manifest.seat_id.clone(), manifest.workload.is_some()),
            );
        }
        Self {
            supervisor,
            session_id,
        }
    }
}

impl Drop for StartingSlot<'_> {
    fn drop(&mut self) {
        if let Ok(mut starting) = self.supervisor.starting.lock() {
            starting.remove(&self.session_id);
        }
    }
}
#[cfg(test)]
mod capacity_tests {
    use super::actor_occupies_slot;
    use odin_domain::huginn::LiveSessionState;
    #[test]
    fn a_live_failed_actor_holds_a_slot_until_its_process_is_gone() {
        assert!(actor_occupies_slot(LiveSessionState::Failed, false, false));
        assert!(actor_occupies_slot(LiveSessionState::Running, false, false));
        assert!(!actor_occupies_slot(LiveSessionState::Failed, false, true));
        assert!(!actor_occupies_slot(LiveSessionState::Failed, true, false));
        assert!(actor_occupies_slot(LiveSessionState::Running, false, false));
        assert!(!actor_occupies_slot(LiveSessionState::Running, true, false));
        assert!(!actor_occupies_slot(LiveSessionState::Ended, false, false));
    }
}
