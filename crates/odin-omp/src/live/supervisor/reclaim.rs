use odin_domain::huginn::{
    AbortScope, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveCommandTarget, LiveError, LiveEventBody, LiveSessionId, LiveSessionState,
    LiveSessionSummary, SessionStateChanged,
};
use odin_domain::EventId;
use std::num::NonZeroU16;
use time::OffsetDateTime;

use super::admission::{restore_summary, unavailable};
use super::LiveSupervisor;
use crate::live::ledger::{live_error, LedgerError, NewLiveEvent};

impl LiveSupervisor {
    /// Recovers one durable session in place under the SAME session
    /// identity: the previous bridge incarnation (if any) is stopped, the
    /// epoch advances, and a fresh bridge launches with the session's
    /// durable transcript resumed. The root session, its journal, and its
    /// capsule authority registration all persist — only the child
    /// incarnation changes. A truthfully Ended session is terminal and is
    /// refused before ANY effect: no stop, no epoch bump, no spawn. This
    /// is the shared recovery path for every client — the conversation
    /// route and ordinary operator surfaces alike.
    pub async fn reclaim(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        let _gate = self.open_gate.lock().await;
        self.refuse_starting(session_id)?;
        let started = std::time::Instant::now();
        let summary = self.reclaim_locked(session_id).await?;
        tracing::info!(
            "odind: session-runtime relaunched session={session_id} seat={} ms={}",
            summary.seat_id,
            started.elapsed().as_millis()
        );
        Ok(summary)
    }

    /// The admission and execution of a parked session's two lawful
    /// transitions, under ONE hold of the supervisor gate: Restart
    /// recovers in place (the only parked transition that composes fresh
    /// authority, so a moved capsule source commit refuses it typed), and
    /// a whole-session Abort settles the durable terminal transition
    /// without composing any authority. Exact-replay first, then
    /// terminality, full command validation, once-only journaling, and
    /// the single effect; a second id at a stale precondition refuses
    /// typed without launching anything.
    pub async fn recover_parked_command(
        &self,
        mut command: LiveCommand,
    ) -> Result<CommandReceipt, LiveError> {
        // A parked session has no turn: any Abort ends the whole session.
        if matches!(command.body, LiveCommandBody::Abort { .. }) {
            command.body = LiveCommandBody::Abort {
                scope: AbortScope::Session,
            };
        }
        self.recover_parked_command_inner(command, false).await
    }

    /// Recovers an owner's durable report intent that crashed before live
    /// admission. Only a missing command row permits this path; admitted
    /// commands retain their exact replay/dispatch reconciliation semantics.
    /// Recovery advances the epoch, so the ORIGINAL command is submitted
    /// unchanged and refused by admission. The owner must durably record a
    /// fresh attempt before delivering against the new epoch.
    pub async fn recover_parked_report_command(
        &self,
        command: LiveCommand,
    ) -> Result<CommandReceipt, LiveError> {
        if !matches!(
            &command.body,
            LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
        ) {
            return Err(LiveError::InvalidRequest {
                code: "report_command_required".to_owned(),
                message: "report recovery requires a Prompt or FollowUp command".to_owned(),
            });
        }
        self.recover_parked_command_inner(command, true).await
    }

    async fn recover_parked_command_inner(
        &self,
        command: LiveCommand,
        recover_absent_report: bool,
    ) -> Result<CommandReceipt, LiveError> {
        let _gate = self.open_gate.lock().await;
        self.refuse_starting(command.session_id)?;
        // A concurrent recovery may already have installed the actor while
        // this report waited for the gate. Never reclaim that actor again.
        if recover_absent_report {
            if let Some(actor) = self.actors.read().await.get(&command.session_id).cloned() {
                return actor.command(command).await;
            }
        }
        // Replayed ids keep their stored receipt — except an interrupted
        // terminal settlement, which reconciles from the journal without
        // re-executing its effect: an id with no outcome, and an id whose
        // Applied outcome was journaled but whose completion event or
        // roster eviction was then skipped.
        if let Some(existing) = self.ledger.command(&command).await.map_err(live_error)? {
            if existing.dispatch_identity == Some(1)
                && matches!(
                    existing.receipt,
                    CommandReceipt::Duplicate {
                        prior_outcome: None,
                        ..
                    }
                )
                && matches!(
                    command.body,
                    LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
                )
            {
                self.reclaim_locked(command.session_id).await?;
                let actor = self
                    .actors
                    .read()
                    .await
                    .get(&command.session_id)
                    .cloned()
                    .ok_or_else(unavailable)?;
                return actor.command(command).await;
            }
            let interrupted_settlement = match (&command.body, &existing.receipt) {
                (
                    LiveCommandBody::Abort {
                        scope: AbortScope::Session,
                    },
                    CommandReceipt::Duplicate { prior_outcome, .. },
                ) => matches!(
                    prior_outcome.as_deref(),
                    None | Some(CommandOutcome::Applied { .. })
                ),
                _ => false,
            };
            if interrupted_settlement {
                return self.reconcile_parked_abort(&command).await;
            }
            return Ok(existing.receipt);
        }
        // Another admitted transition may have changed the journal while
        // this request waited for the gate; validate against durable
        // truth.
        let session = self
            .ledger
            .session(command.session_id)
            .await
            .map_err(live_error)?;
        let parked = restore_summary(&*self.ledger, &session).await?;
        if parked.state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "the session is truthfully ended; a terminal session is never \
                          recovered"
                    .to_owned(),
            });
        }
        if recover_absent_report {
            // Absence was checked under the admission gate; preserve the original command.
            self.reclaim_locked(command.session_id).await?;
            let actor = self
                .actors
                .read()
                .await
                .get(&command.session_id)
                .cloned()
                .ok_or_else(unavailable)?;
            return actor.command(command).await;
        }
        // Restart composes fresh authority; session abort needs none because the actor stopped.
        // Other commands require a live incarnation.
        match command.body {
            LiveCommandBody::Restart => {}
            LiveCommandBody::Abort {
                scope: AbortScope::Session,
            } => {
                return self.settle_parked_abort(command, parked).await;
            }
            _ => {
                return Err(LiveError::Conflict {
                    code: "session_parked".to_owned(),
                    message: "the session is parked after a daemon restart; send the \
                              Restart command to recover it in place, or Abort to end it \
                              durably"
                        .to_owned(),
                });
            }
        }
        // Full admission validation against the EXACT durable target: the
        // FS journal's append_command checks the epoch but not the event
        // head or command applicability, so both are checked here against
        // current durable summary before anything is journaled.
        let target = LiveCommandTarget {
            session_id: command.session_id,
            epoch: parked.epoch,
            event_head: parked.event_head,
            state: parked.state,
        };
        command
            .validate_for(&target)
            .map_err(|rejection| LiveError::InvalidRequest {
                code: "command_not_admissible".to_owned(),
                message: rejection.to_string(),
            })?;
        // Once-only admission at the original durable precondition.
        let journal = self
            .ledger
            .append_command(&command)
            .await
            .map_err(live_error)?;
        if matches!(journal.receipt, CommandReceipt::Duplicate { .. }) {
            return Ok(journal.receipt);
        }
        self.ledger
            .append(
                parked.epoch,
                NewLiveEvent {
                    session_id: command.session_id,
                    event_id: EventId::new(format!(
                        "control:{}",
                        odin_domain::Digest::hash(command.command_id.as_str().as_bytes())
                    ))
                    .map_err(|_| unavailable())?,
                    occurred_at: journal.recorded_at,
                    body: LiveEventBody::ControlAccepted(journal.receipt.clone()),
                },
            )
            .await
            .map_err(live_error)?;
        // The single recovery effect — still inside this gate hold.
        let recovered = self.reclaim_locked(command.session_id).await?;
        let outcome = CommandOutcome::Applied {
            command_id: command.command_id.clone(),
        };
        self.ledger
            .complete_command(command.command_id.clone(), outcome.clone())
            .await
            .map_err(live_error)?;
        self.ledger
            .append(
                recovered.epoch,
                NewLiveEvent {
                    session_id: command.session_id,
                    event_id: EventId::new(format!(
                        "control-done:{}",
                        odin_domain::Digest::hash(command.command_id.as_str().as_bytes())
                    ))
                    .map_err(|_| unavailable())?,
                    occurred_at: OffsetDateTime::now_utc(),
                    body: LiveEventBody::ControlCompleted(outcome),
                },
            )
            .await
            .map_err(live_error)?;
        Ok(journal.receipt)
    }

    /// The durable half of a live whole-session abort, for a session with
    /// no incarnation: the bridge stop the live abort performs already
    /// holds — the child stopped with the parking daemon — so the
    /// settlement is journal work only. It writes exactly the transition
    /// the actor journals (accepted, state change to Ended under
    /// control:AbortSession, Applied completion) and then frees the
    /// bounded-roster slot. No authority is composed, nothing spawns, no
    /// epoch advances; a crash mid-settlement is reconcilable through
    /// [`Self::reconcile_parked_abort`].
    async fn settle_parked_abort(
        &self,
        command: LiveCommand,
        parked: LiveSessionSummary,
    ) -> Result<CommandReceipt, LiveError> {
        let target = LiveCommandTarget {
            session_id: command.session_id,
            epoch: parked.epoch,
            event_head: parked.event_head,
            state: parked.state,
        };
        command
            .validate_for(&target)
            .map_err(|rejection| LiveError::InvalidRequest {
                code: "command_not_admissible".to_owned(),
                message: rejection.to_string(),
            })?;
        let journal = self
            .ledger
            .append_command(&command)
            .await
            .map_err(live_error)?;
        self.ledger
            .append(
                parked.epoch,
                NewLiveEvent {
                    session_id: command.session_id,
                    event_id: control_event_id(&command, "control")?,
                    occurred_at: journal.recorded_at,
                    body: LiveEventBody::ControlAccepted(journal.receipt.clone()),
                },
            )
            .await
            .map_err(live_error)?;
        // The one settlement effect is this durable terminal transition:
        // once it lands, the outcome is Applied even across a crash.
        self.ledger
            .append(
                parked.epoch,
                NewLiveEvent {
                    session_id: command.session_id,
                    event_id: control_event_id(&command, "control-state")?,
                    occurred_at: OffsetDateTime::now_utc(),
                    body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                        previous: parked.state,
                        current: LiveSessionState::Ended,
                        reason: Some(format!("control:{:?}", command.body.kind())),
                    }),
                },
            )
            .await
            .map_err(live_error)?;
        let outcome = CommandOutcome::Applied {
            command_id: command.command_id.clone(),
        };
        self.ledger
            .complete_command(command.command_id.clone(), outcome.clone())
            .await
            .map_err(live_error)?;
        self.ledger
            .append(
                parked.epoch,
                NewLiveEvent {
                    session_id: command.session_id,
                    event_id: control_event_id(&command, "control-done")?,
                    occurred_at: OffsetDateTime::now_utc(),
                    body: LiveEventBody::ControlCompleted(outcome),
                },
            )
            .await
            .map_err(live_error)?;
        self.inactive.write().await.remove(&command.session_id);
        Ok(journal.receipt)
    }

    /// Reconciles only commands with deterministic parked markers, without re-execution.
    /// A terminal marker permits completing Applied settlement; admission alone or
    /// missing markers leave the stored receipt untouched, including live-path aborts.
    async fn reconcile_parked_abort(
        &self,
        command: &LiveCommand,
    ) -> Result<CommandReceipt, LiveError> {
        let journaled = self.ledger.command(command).await.map_err(live_error)?;
        if self.parked_marker(command).await? == ParkedMarker::Settled {
            let outcome = CommandOutcome::Applied {
                command_id: command.command_id.clone(),
            };
            // Idempotent for the identical outcome, so repeated
            // reconciliation can never conflict.
            self.ledger
                .complete_command(command.command_id.clone(), outcome.clone())
                .await
                .map_err(live_error)?;
            let session = self
                .ledger
                .session(command.session_id)
                .await
                .map_err(live_error)?;
            match self
                .ledger
                .append(
                    session.epoch,
                    NewLiveEvent {
                        session_id: command.session_id,
                        event_id: control_event_id(command, "control-done")?,
                        occurred_at: OffsetDateTime::now_utc(),
                        body: LiveEventBody::ControlCompleted(outcome),
                    },
                )
                .await
            {
                // A settle that crashed after completing already
                // journaled the identical completion event: adoption,
                // not duplication.
                Ok(_) | Err(LedgerError::DuplicateEvent(_)) => {}
                Err(error) => return Err(live_error(error)),
            }
            self.inactive.write().await.remove(&command.session_id);
            // The completion just landed in the journal: return the
            // durable receipt, not the cached pre-completion one.
            return Ok(self
                .ledger
                .command(command)
                .await
                .map_err(live_error)?
                .map(|entry| entry.receipt)
                .expect("a reconciled id is journaled"));
        }
        // Admitted-but-unsettled and unprovable ids keep their stored
        // receipt exactly as journaled — untouched, so the cached one.
        Ok(journaled
            .map(|entry| entry.receipt)
            .expect("a reconciled id is journaled"))
    }

    /// Which of THIS command's own deterministic parked markers the
    /// journal already carries. Bounded page scan; empty pages end it.
    async fn parked_marker(&self, command: &LiveCommand) -> Result<ParkedMarker, LiveError> {
        let admitted = control_event_id(command, "control")?;
        let settled = control_event_id(command, "control-state")?;
        let head = self
            .ledger
            .head(command.session_id)
            .await
            .map_err(live_error)?;
        let mut marker = ParkedMarker::Unproven;
        let mut cursor = EventSeq::new(0);
        while cursor < head {
            let page = self
                .ledger
                .history(HistoryQuery {
                    session_id: command.session_id,
                    after: cursor,
                    limit: NonZeroU16::new(1024).ok_or_else(unavailable)?,
                })
                .await
                .map_err(live_error)?;
            if page.events.is_empty() {
                break;
            }
            for event in &page.events {
                if event.event_id == settled {
                    return Ok(ParkedMarker::Settled);
                }
                if event.event_id == admitted {
                    marker = ParkedMarker::Admitted;
                }
            }
            cursor = page.next_after;
        }
        Ok(marker)
    }

    /// The reclaim body proper: the caller owns the supervisor gate.
    async fn reclaim_locked(
        &self,
        session_id: LiveSessionId,
    ) -> Result<LiveSessionSummary, LiveError> {
        // The durable journal — not any in-memory cache — decides
        // terminality, and it decides it BEFORE any effect: whether the
        // session currently holds an actor or sits parked, a truthfully
        // Ended session is never stopped, never epoch-bumped, and never
        // respawned.
        let session = self.ledger.session(session_id).await.map_err(live_error)?;
        let durable = restore_summary(&*self.ledger, &session).await?;
        if durable.state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: "the session is truthfully ended; a terminal session is never \
                          reopened"
                    .to_owned(),
            });
        }
        if let Some(actor) = self.actors.read().await.get(&session_id).cloned() {
            // A session that already holds a live actor recovers through
            // the shared incarnation recover: the bridge re-asserts its
            // lease, advances the published row epoch, and respawns with
            // transcript resume — child and tab resources are REPLACED,
            // never finalized, and the session is never marked Ended. The
            // actor object and its journal subscription persist.
            let recovered = actor.recover().await?;
            self.inactive.write().await.remove(&session_id);
            return Ok(recovered);
        }
        // Parked session (no actor): the launch factory composes and
        // verifies the fresh provisioned authority BEFORE any child
        // spawns, then brings up the fresh incarnation. Recovery is
        // capacity-gated like any open: the recovered session occupies its
        // seat's bounded slot, so it may never exceed max_sessions.
        // A pod's agent session is bounded by its pod, not the seat's
        // interactive slots (see `interactive_sessions_of`).
        let pod_session = session.manifest.workload.is_some();
        if let Some(binding) = self.bindings.read().await.get(&durable.seat_id).cloned() {
            let live_for_seat = self.interactive_sessions_of(&durable.seat_id).await.len();
            if !pod_session && live_for_seat >= binding.max_sessions {
                return Err(LiveError::ResourceLimit {
                    limit: format!(
                        "seat {} already holds its bounded maximum of {} live session(s); \
                         recover it by attaching once the seat frees or raise the declared limit",
                        durable.seat_id, binding.max_sessions
                    ),
                });
            }
        }
        // Read-path reclaim: retire anything that settled Ended before the
        // capacity decision, under this gate hold.
        self.retire_ended().await;
        // The declared composition limit bounds the ENTIRE tracked roster
        // across ALL seats. The session being recovered is parked inside
        // that roster, so it is excluded from the count — its recovery
        // converts a parked entry into a live one instead of adding a new
        // one, and must never refuse itself.
        //
        // A recovery target stranded beyond the discovery cutoff holds no
        // cached slot to exclude; the cache is documented non-load-bearing,
        // so at a full roster one cached slot is freed for it — pure cache
        // management with zero durable effect.
        let stranded = !self.inactive.read().await.contains_key(&session_id);
        let roster_full = stranded && self.roster_len(None).await? >= self.max_sessions;
        if roster_full {
            self.free_oldest_cached_slot().await;
        }
        let roster = self.roster_len(Some(session_id)).await?;
        if roster >= self.max_sessions {
            return Err(LiveError::ResourceLimit {
                limit: format!(
                    "declared limits.sessions.max_sessions is {}; {} session(s) are already \
                     tracked; attach to an existing session instead of opening another",
                    self.max_sessions, roster
                ),
            });
        }
        let epoch = self.ledger.reclaim(session_id).await.map_err(live_error)?;
        let session = self.ledger.session(session_id).await.map_err(live_error)?;
        let previous = durable.state;
        let actor = match self.launch_actor(session.manifest, epoch, true).await {
            Ok(actor) => actor,
            Err(error) => {
                self.ledger
                    .append(
                        epoch,
                        NewLiveEvent {
                            session_id,
                            event_id: EventId::new(format!(
                                "reclaim-failed:{session_id}:{}",
                                epoch.get()
                            ))
                            .map_err(|_| unavailable())?,
                            occurred_at: OffsetDateTime::now_utc(),
                            body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                                previous,
                                current: LiveSessionState::Failed,
                                reason: Some(error.to_string()),
                            }),
                        },
                    )
                    .await
                    .map_err(live_error)?;
                // The epoch advanced even though the launch failed: refresh
                // the parked summary from durable state so the advertised
                // epoch is the real one and a later Restart can admit.
                let durable = self.ledger.session(session_id).await.map_err(live_error)?;
                let refreshed = restore_summary(&*self.ledger, &durable).await?;
                self.park(session_id, refreshed).await?;
                return Err(error);
            }
        };
        let summary = actor.summary()?;
        self.inactive.write().await.remove(&session_id);
        self.actors.write().await.insert(session_id, actor);
        Ok(summary)
    }
}

/// The deterministic event id of one control step of `command`: the same
/// derivation on every attempt, so an interrupted settlement can never
/// double-append a step during reconciliation.
fn control_event_id(command: &LiveCommand, prefix: &str) -> Result<EventId, LiveError> {
    EventId::new(format!(
        "{prefix}:{}",
        odin_domain::Digest::hash(command.command_id.as_str().as_bytes())
    ))
    .map_err(|_| unavailable())
}

/// Durable parked-path markers used to distinguish interrupted settlements.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ParkedMarker {
    /// Neither marker exists.
    Unproven,
    /// The admission marker alone: admitted by the parked path, the
    /// terminal settlement never landed.
    Admitted,
    /// The terminal settlement marker: the settlement landed.
    Settled,
}
