//! Fresh session after a declared rollover bound, or when the opener has
//! new information. The running session is retired; its transcript stays
//! on the ledger. The successor starts from a short brief of host-read
//! knowledge — task notes, `memory.project.*`, and `state.repos` — plus
//! the exact owner text when new information is what retired the session.
//! That text is never injected into the retired session. The original
//! command and exact successor request are journaled together before
//! retirement. A retry resumes that handoff, and acknowledges the original
//! command only after the successor accepts and applies the brief.
//!
//! The decision is the seat's rollover policy. A caller identity is not an
//! input: new information is a flag the opener sets, and the rollover bound
//! is the declaration.

use odin_domain::huginn::{
    AbortScope, CommandOutcome, CommandReceipt, LiveCommand, LiveCommandBody, LiveContentBlock,
    LiveError, LiveEventBody, LiveMessage, LiveSessionId, LiveSessionState, LiveSessionSummary,
    OpenSessionRequest, SessionStateChanged,
};
use odin_domain::{CommandId, NodeId, ProjectId, SliceId};

use crate::live::ledger::live_error;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::admission::unavailable;
use super::LiveSupervisor;
use crate::live::rollover::{
    fresh_open_due, fresh_prompt, heartbeat_due as interval_due, render_fresh_brief,
    FreshBriefSources, FreshOpenReason, RolloverPolicy,
};

/// What the successor opened as, and why. The retired session id is the
/// record; its transcript is unchanged. `accepted` is the successor's
/// receipt for the brief that carries the owner text. It is `Some` only
/// after that prompt is accepted. `brief` is that prompt, exact owner text
/// included. A rollover-bound open with no owner text leaves `accepted`
/// as `None`.
#[derive(Clone, Debug)]
pub struct FreshSession {
    pub retired: LiveSessionId,
    pub opened: LiveSessionSummary,
    pub reason: FreshOpenReason,
    pub accepted: Option<CommandReceipt>,
    pub brief: String,
}

/// Where the retired session was placed. Copied onto the successor so the
/// fresh open does not invent a project, node, or revision.
#[derive(Clone, Debug)]
pub struct FreshPlacement {
    pub project_id: ProjectId,
    pub slice_id: SliceId,
    pub target_node: NodeId,
    pub open_tab: bool,
    pub served_revision: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct FreshHandoffRecord {
    request: OpenSessionRequest,
    brief: String,
    owner_present: bool,
}

impl LiveSupervisor {
    /// Retires `session` and opens a new one of the same seat, project, and
    /// model when the policy says so. `new_information` is the opener's
    /// declaration that the running session must not be injected into; it
    /// is not a seat name. The brief is rendered from `sources` inside the
    /// policy byte budget before anything is ended, so an owner text that
    /// cannot be carried exactly leaves the running session untouched. A
    /// policy that does not ask for a fresh open returns `Ok(None)` and
    /// changes nothing. The successor's acceptance of the brief is the
    /// acknowledgement; a rejected brief is not reported as accepted.
    pub async fn open_fresh(
        &self,
        session: LiveSessionId,
        policy: &RolloverPolicy,
        completed_rollovers: u32,
        new_information: bool,
        sources: FreshBriefSources,
        placed: FreshPlacement,
    ) -> Result<Option<FreshSession>, LiveError> {
        let Some(reason) = fresh_open_due(policy, completed_rollovers, new_information) else {
            return Ok(None);
        };
        let _gate = self.fresh_gate.lock().await;
        let trigger_id = CommandId::new(format!("fresh-trigger-{session}")).map_err(unavailable)?;
        if let Some(entry) = self
            .ledger
            .command_by_id(&trigger_id)
            .await
            .map_err(live_error)?
        {
            let command = entry.command;
            if command.session_id != session {
                return Err(LiveError::Conflict {
                    code: "fresh_command_conflict".to_owned(),
                    message: "fresh trigger belongs to another session".to_owned(),
                });
            }
            let bytes = self
                .ledger
                .fresh_handoff(&command)
                .await
                .map_err(live_error)?
                .ok_or_else(|| unavailable("fresh trigger has no handoff"))?;
            let record: FreshHandoffRecord = serde_json::from_slice(&bytes).map_err(unavailable)?;
            let opened = self.finish_fresh(&command, &record).await?;
            let accepted = record.owner_present.then(|| CommandReceipt::Accepted {
                command_id: record.request.command_id.clone(),
            });
            return Ok(Some(FreshSession {
                retired: session,
                opened,
                reason,
                accepted,
                brief: record.brief,
            }));
        }
        let actor = self.actor(session).await?;
        let current = actor.summary()?;
        let owner_present = !sources.owner_text.is_empty();
        let (request, brief) = Self::fresh_request(
            session,
            &current,
            policy,
            &reason,
            new_information,
            sources,
            placed,
        )?;
        let command = LiveCommand {
            command_id: trigger_id,
            session_id: session,
            expected_epoch: current.epoch,
            expected_event_head: Some(current.event_head),
            body: LiveCommandBody::Abort {
                scope: AbortScope::Session,
            },
        };
        let record = FreshHandoffRecord {
            request,
            brief,
            owner_present,
        };
        let bytes = serde_json::to_vec(&record).map_err(unavailable)?;
        let receipt = actor.admit_fresh(command.clone(), bytes).await?;
        if matches!(receipt, CommandReceipt::Rejected { .. }) {
            return Err(LiveError::unavailable(
                "fresh_supervisor_brief",
                format!("fresh handoff rejected: {receipt:?}"),
            ));
        }
        let opened = self.finish_fresh(&command, &record).await?;
        let accepted = record.owner_present.then(|| CommandReceipt::Accepted {
            command_id: record.request.command_id.clone(),
        });
        Ok(Some(FreshSession {
            retired: session,
            opened,
            reason,
            accepted,
            brief: record.brief,
        }))
    }

    fn fresh_request(
        session: LiveSessionId,
        current: &LiveSessionSummary,
        policy: &RolloverPolicy,
        reason: &FreshOpenReason,
        new_information: bool,
        mut sources: FreshBriefSources,
        placed: FreshPlacement,
    ) -> Result<(OpenSessionRequest, String), LiveError> {
        if current.state == LiveSessionState::Ended {
            return Err(LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: format!("live session {session} is already ended"),
            });
        }
        if sources.reason.is_empty() {
            sources.reason = reason.label();
        }
        if new_information && sources.owner_text.trim().is_empty() {
            return Err(LiveError::unavailable(
                "fresh_supervisor_brief",
                "new information requires exact owner text",
            ));
        }
        let (_, bytes) = render_fresh_brief(&sources, policy)
            .map_err(|detail| LiveError::unavailable("fresh_supervisor_brief", detail))?;
        let text = String::from_utf8(bytes).map_err(unavailable)?;
        let brief = fresh_prompt(&text);
        let message =
            LiveMessage::new(vec![LiveContentBlock::Text(brief.clone())]).map_err(unavailable)?;
        Ok((
            OpenSessionRequest {
                command_id: fresh_open_command_id(session, reason)?,
                seat_id: current.seat_id.clone(),
                project_id: placed.project_id,
                slice_id: placed.slice_id,
                provider: current.provider.clone(),
                model: current.model.clone(),
                title: current.title.clone(),
                target_node: placed.target_node,
                open_tab: placed.open_tab,
                initial_prompt: Some(message),
                workload: None,
                served_revision: placed.served_revision,
            },
            brief,
        ))
    }

    /// Traces the brief an opened successor was just handed, when this
    /// supervisor holds the authority's session roots.
    fn trace_fresh_brief(&self, successor: LiveSessionId, brief: &str) {
        let Some(roots) = self.capsule_root.get() else {
            return;
        };
        let block = crate::live::context_trace::Block::new("fresh brief", brief, Vec::new());
        if let Err(error) = crate::live::context_trace::record(
            &crate::live::context_trace::root(&roots.state_root),
            successor,
            crate::live::context_trace::Kind::Fresh,
            None,
            &[block],
        ) {
            tracing::warn!("odind: injected context not traced: {error}");
        }
    }

    /// Finish an admitted handoff using only the durable record. A failed
    /// launch leaves the original command pending and is retried explicitly.
    async fn finish_fresh(
        &self,
        command: &LiveCommand,
        record: &FreshHandoffRecord,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.carry_delegated_children(command.session_id, &record.request.command_id)?;
        let session = self
            .ledger
            .session(command.session_id)
            .await
            .map_err(live_error)?;
        let old = super::admission::restore_summary(&*self.ledger, &session).await?;
        if old.state != LiveSessionState::Ended {
            let actor = { self.actors.read().await.get(&command.session_id).cloned() };
            if let Some(actor) = actor {
                actor.end().await?;
            } else {
                let _gate = self.open_gate.lock().await;
                self.refuse_starting(command.session_id)?;
                if self.actors.read().await.contains_key(&command.session_id) {
                    return Err(LiveError::unavailable(
                        "fresh_handoff_race",
                        "the retiring actor was recovered concurrently; retry the handoff",
                    ));
                }
                let session = self
                    .ledger
                    .session(command.session_id)
                    .await
                    .map_err(live_error)?;
                let old = super::admission::restore_summary(&*self.ledger, &session).await?;
                if old.state != LiveSessionState::Ended {
                    self.ledger
                        .append(
                            session.epoch,
                            crate::live::ledger::NewLiveEvent {
                                session_id: command.session_id,
                                event_id: odin_domain::EventId::new(format!(
                                    "fresh-retired:{}",
                                    command.session_id
                                ))
                                .map_err(unavailable)?,
                                occurred_at: time::OffsetDateTime::now_utc(),
                                body: LiveEventBody::SessionStateChanged(SessionStateChanged {
                                    previous: old.state,
                                    current: LiveSessionState::Ended,
                                    reason: Some("fresh replacement".to_owned()),
                                }),
                            },
                        )
                        .await
                        .map_err(live_error)?;
                    self.inactive.write().await.remove(&command.session_id);
                }
            }
        }
        let mut opened = self.open(record.request.clone()).await?;
        let successor = opened.session_id;
        self.trace_fresh_brief(successor, &record.brief);
        let existing = self
            .ledger
            .command_by_id(&record.request.command_id)
            .await
            .map_err(live_error)?;
        if let Some(entry) = &existing {
            if entry.command.session_id != successor
                || !matches!(&entry.command.body, LiveCommandBody::Prompt { message, .. }
                    if Some(message) == record.request.initial_prompt.as_ref())
            {
                return Err(LiveError::Conflict {
                    code: "fresh_successor_conflict".to_owned(),
                    message: "successor command identity is bound to a different prompt".to_owned(),
                });
            }
        }
        let pending = existing.as_ref().is_some_and(|entry| {
            matches!(
                &entry.receipt,
                CommandReceipt::Duplicate {
                    prior_outcome: None,
                    ..
                }
            )
        });
        if existing.is_none() || pending {
            let actor = match self.actor(successor).await {
                Ok(actor) if actor.summary()?.state != LiveSessionState::Failed => actor,
                Ok(_) | Err(LiveError::NotFound { .. }) => {
                    self.reclaim(successor).await?;
                    self.actor(successor).await?
                }
                Err(error) => return Err(error),
            };
            let snapshot = actor.summary()?;
            let prompt = if let Some(entry) = existing {
                entry.command
            } else {
                LiveCommand {
                    command_id: record.request.command_id.clone(),
                    session_id: successor,
                    expected_epoch: snapshot.epoch,
                    expected_event_head: Some(snapshot.event_head),
                    body: LiveCommandBody::Prompt {
                        message: record
                            .request
                            .initial_prompt
                            .clone()
                            .ok_or_else(|| unavailable("fresh prompt missing"))?,
                        owner_text: None,
                    },
                }
            };
            match actor.command(prompt).await? {
                CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. } => {}
                rejected => {
                    return Err(LiveError::unavailable(
                        "fresh_supervisor_brief",
                        format!("successor refused the brief: {rejected:?}"),
                    ))
                }
            }
            opened = actor.summary()?;
        }
        let settled = self
            .ledger
            .command_by_id(&record.request.command_id)
            .await
            .map_err(live_error)?
            .ok_or_else(|| unavailable("successor prompt was not journaled"))?;
        if !matches!(settled.receipt, CommandReceipt::Duplicate {
            prior_outcome: Some(outcome), ..
        } if matches!(*outcome, CommandOutcome::Applied { .. }))
        {
            return Err(LiveError::unavailable(
                "fresh_supervisor_brief",
                "successor prompt delivery has not settled successfully",
            ));
        }
        self.ledger
            .complete_command(
                command.command_id.clone(),
                CommandOutcome::Applied {
                    command_id: command.command_id.clone(),
                },
            )
            .await
            .map_err(live_error)?;
        Ok(opened)
    }

    /// Resume an exact replay before routing it to any session actor.
    pub async fn resume_fresh_command(
        &self,
        command: &LiveCommand,
    ) -> Result<Option<CommandReceipt>, LiveError> {
        let _gate = self.fresh_gate.lock().await;
        let Some(bytes) = self
            .ledger
            .fresh_handoff(command)
            .await
            .map_err(live_error)?
        else {
            return Ok(None);
        };
        let entry = self
            .ledger
            .command(command)
            .await
            .map_err(live_error)?
            .ok_or_else(|| unavailable("fresh handoff has no command"))?;
        if matches!(
            &entry.receipt,
            CommandReceipt::Duplicate {
                prior_outcome: Some(_),
                ..
            }
        ) {
            return Ok(Some(entry.receipt));
        }
        let record: FreshHandoffRecord = serde_json::from_slice(&bytes).map_err(unavailable)?;
        self.finish_fresh(command, &record).await?;
        Ok(Some(
            self.ledger
                .command(command)
                .await
                .map_err(live_error)?
                .ok_or_else(|| unavailable("fresh handoff has no command"))?
                .receipt,
        ))
    }

    /// Carries a new-information prompt into a successor instead of
    /// injecting it. The original command and exact handoff are admitted
    /// durably before retirement. The returned receipt uses the original
    /// command ID; exact replays resume pending handoffs or return duplicates.
    /// Seats without the declaration accept the prompt on the running session.
    pub async fn refuse_injection_when_fresh(
        &self,
        session: LiveSessionId,
        policy: &RolloverPolicy,
        new_information: bool,
        command: LiveCommand,
        sources: FreshBriefSources,
        placed: FreshPlacement,
    ) -> Result<CommandReceipt, LiveError> {
        if let Some(receipt) = self.resume_fresh_command(&command).await? {
            return Ok(receipt);
        }
        if let Some(reason) = fresh_open_due(policy, 0, new_information) {
            if matches!(
                command.body,
                LiveCommandBody::Prompt { .. } | LiveCommandBody::FollowUp { .. }
            ) {
                let owner_text = match &command.body {
                    LiveCommandBody::Prompt { owner_text, .. }
                    | LiveCommandBody::FollowUp { owner_text, .. } => {
                        owner_text.as_deref().unwrap_or("")
                    }
                    _ => unreachable!(),
                };
                let mut sources = sources;
                if !sources.owner_text.is_empty() && sources.owner_text != owner_text {
                    return Err(LiveError::InvalidRequest {
                        code: "fresh_owner_text_mismatch".to_owned(),
                        message: "the fresh brief must carry the command's exact owner text"
                            .to_owned(),
                    });
                }
                sources.owner_text = owner_text.to_owned();
                let _gate = self.fresh_gate.lock().await;
                if let Some(bytes) = self
                    .ledger
                    .fresh_handoff(&command)
                    .await
                    .map_err(live_error)?
                {
                    let record: FreshHandoffRecord =
                        serde_json::from_slice(&bytes).map_err(unavailable)?;
                    self.finish_fresh(&command, &record).await?;
                    return Ok(self
                        .ledger
                        .command(&command)
                        .await
                        .map_err(live_error)?
                        .ok_or_else(|| unavailable("fresh handoff has no command"))?
                        .receipt);
                }
                let actor = self.actor(session).await?;
                let current = actor.summary()?;
                let (request, brief) =
                    Self::fresh_request(session, &current, policy, &reason, true, sources, placed)?;
                let record = FreshHandoffRecord {
                    request,
                    brief,
                    owner_present: true,
                };
                let bytes = serde_json::to_vec(&record).map_err(unavailable)?;
                let receipt = actor.admit_fresh(command.clone(), bytes).await?;
                if matches!(receipt, CommandReceipt::Rejected { .. }) {
                    return Ok(receipt);
                }
                self.finish_fresh(&command, &record).await?;
                return Ok(receipt);
            }
        }
        self.actor(session).await?.command(command).await
    }

    /// The seat's declared backstop interval, as set by `set_heartbeat_interval`. A seat that
    /// declared none has no heartbeat.
    pub fn heartbeat_interval(&self, seat: &odin_domain::SeatId) -> Option<Duration> {
        self.heartbeat_intervals
            .lock()
            .ok()
            .and_then(|slots| slots.get(seat).copied())
    }

    /// Whether the declared heartbeat is due for `session`. The first
    /// observation is due; later ones wait out the declared interval.
    /// `None` — the seat declared no heartbeat — is never due, so events
    /// remain the only wake. Checking more often than the interval does
    /// not fire more often.
    pub fn heartbeat_due(&self, session: LiveSessionId, interval: Option<Duration>) -> bool {
        let Some(interval) = interval else {
            return false;
        };
        let now = Instant::now();
        let mut clocks = self
            .heartbeat_clock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last = clocks.get(&session).copied();
        if !interval_due(interval, last, now) {
            return false;
        }
        clocks.insert(session, now);
        true
    }

    /// Drops the last fire so a prompt that did not land is due again.
    pub fn clear_heartbeat(&self, session: LiveSessionId) {
        if let Ok(mut clocks) = self.heartbeat_clock().lock() {
            clocks.remove(&session);
        }
    }

    fn heartbeat_clock(&self) -> &Mutex<HashMap<LiveSessionId, Instant>> {
        self.heartbeat_clocks
            .get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Installed by the daemon that holds the delegation ledger. Fixtures
    /// leave it unset; a fresh open then keeps children where they are.
    pub fn set_delegation_links(&self, links: crate::host_tools::delegation::DelegationLinkLedger) {
        if let Ok(mut slot) = self.delegation_links.lock() {
            *slot = Some(links);
        }
    }

    /// Arms the successor and moves live children onto it before the
    /// predecessor ends, so the stop barrier hands them off instead of
    /// stopping them. Wakes follow `link.parent`. Idempotent on retry.
    fn carry_delegated_children(
        &self,
        predecessor: LiveSessionId,
        successor_command: &CommandId,
    ) -> Result<(), LiveError> {
        let Some(links) = self
            .delegation_links
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
        else {
            return Ok(());
        };
        let successor = super::admission::session_id_for(successor_command)?;
        let from = odin_domain::SessionId::new(predecessor.to_string()).map_err(unavailable)?;
        let to = odin_domain::SessionId::new(successor.to_string()).map_err(unavailable)?;
        links.arm_successor(&from, &to).map_err(|error| {
            unavailable(format!(
                "could not arm delegated children from {from} to {to}: {error}"
            ))
        })?;
        links.repoint_children(&from, &to).map_err(|error| {
            unavailable(format!(
                "could not carry delegated children from {from} to {to}: {error}"
            ))
        })?;
        if let Some(mut row) = links.load(&predecessor).map_err(|error| {
            unavailable(format!(
                "could not read the predecessor delegation row: {error}"
            ))
        })? {
            if matches!(
                row.phase,
                crate::host_tools::delegation::DelegationPhase::Provisioning
                    | crate::host_tools::delegation::DelegationPhase::Running
            ) {
                let mut carried = row.clone();
                carried.child = successor;
                carried.command = successor_command.clone();
                carried.child_run = odin_domain::RunId::new(format!("run:live:{successor}"))
                    .map_err(unavailable)?;
                carried.phase = crate::host_tools::delegation::DelegationPhase::Running;
                links.persist(&carried).map_err(|error| {
                    unavailable(format!(
                        "could not carry the predecessor delegation row: {error}"
                    ))
                })?;
                row.phase = crate::host_tools::delegation::DelegationPhase::Ended;
                links.persist(&row).map_err(|error| {
                    unavailable(format!(
                        "could not retire the predecessor delegation row: {error}"
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Installs the handoff the observation pump calls when a rollover
    /// bound is reached. The daemon that holds the brain installs it.
    pub fn set_fresh_handoff(
        &self,
        handoff: std::sync::Arc<dyn crate::live::service::FreshHandoff>,
    ) {
        if let Ok(mut slot) = self.fresh_handoff.lock() {
            *slot = Some(handoff);
        }
    }

    pub fn set_heartbeat_interval(
        &self,
        seat: &odin_domain::SeatId,
        interval: Option<std::time::Duration>,
    ) {
        if let Ok(mut slots) = self.heartbeat_intervals.lock() {
            match interval {
                Some(interval) => {
                    slots.insert(seat.clone(), interval);
                }
                None => {
                    slots.remove(seat);
                }
            }
        }
    }

    pub(super) fn fresh_handoff(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::live::service::FreshHandoff>> {
        self.fresh_handoff.lock().ok().and_then(|slot| slot.clone())
    }

    /// Routes one coordinator update through the installed fresh-session
    /// policy. `Ok(None)` means the policy keeps the running session, and
    /// the caller dispatches the original command. Ordinary wakes do not
    /// call this.
    pub async fn handoff_coordinator(
        &self,
        command: LiveCommand,
        owner_text: &str,
    ) -> Result<Option<CommandReceipt>, LiveError> {
        let Some(handoff) = self.fresh_handoff() else {
            return Ok(None);
        };
        handoff.handoff_command(self, command, owner_text).await
    }

    /// Finishes every durable handoff that was admitted and not completed.
    /// Startup and recovery call this so a rollover-generated trigger does
    /// not wait for the original caller to resend it. A launch that fails
    /// leaves the record pending for the next call.
    pub async fn resume_pending_handoffs(&self) -> Result<usize, LiveError> {
        let _gate = self.fresh_gate.lock().await;
        let pending = self
            .ledger
            .pending_fresh_handoffs()
            .await
            .map_err(live_error)?;
        let mut finished = 0usize;
        for (command, bytes) in pending {
            let record: FreshHandoffRecord = serde_json::from_slice(&bytes).map_err(unavailable)?;
            self.finish_fresh(&command, &record).await?;
            finished += 1;
        }
        Ok(finished)
    }
}

/// Successor open id. The reason label is a sentence and must not be
/// inlined: command ids are at most 128 bytes. The kind is the policy,
/// never a seat or caller name.
fn fresh_open_command_id(
    session: LiveSessionId,
    reason: &FreshOpenReason,
) -> Result<CommandId, LiveError> {
    let kind = match reason {
        FreshOpenReason::NewInformation => "new-information",
        FreshOpenReason::RolloverBound { .. } => "rollover-bound",
    };
    CommandId::new(format!("fresh-{kind}-{session}")).map_err(unavailable)
}
