//! Successor admission waits until the daemon serves the published composition.

use super::identity::{bounded_command, now_unix_ms, successor_vehicle_command};
use super::{ConversationRecord, ConversationRoot, SuccessorTrouble};
use crate::runtime::IntentFailure;
use odin_domain::huginn::{LiveSessionId, LiveSessionState};
use odin_domain::CommandId;
use odin_omp::live::rollover::{
    render_brief, RolloverBriefInputs, RolloverChildState, RolloverPendingApproval, RolloverPolicy,
};
use odin_omp::live::supervisor::session_id_for;

/// Bound work per invocation without permanently exhausting a durable transition.
const MAX_SUCCESSOR_TRANSITIONS: usize = 8;
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VehicleRollover {
    pub(crate) predecessor_session: String,
    pub(crate) predecessor_command: String,
    pub(crate) successor_command: String,
    pub(crate) successor_session: String,
    /// The bounded continuity brief, persisted BEFORE the successor open
    /// and carried as the successor's first prompt.
    pub(crate) brief: Option<String>,
    /// The predecessor journal head the brief was rendered at.
    pub(crate) predecessor_event_head: u64,
    pub(crate) phase: SuccessorPhase,
    #[serde(default)]
    pub(crate) brief_command: Option<odin_domain::huginn::LiveCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ended: Option<EndedSuccessors>,
}

/// Successors of this transition that ended before they served (their
/// first open failed), counted under the daemon executable that tried
/// them: a new build starts the count over.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EndedSuccessors {
    pub(crate) count: u32,
    pub(crate) last_at_unix_ms: u64,
    pub(crate) executable: String,
    /// The cap stopped minting under this executable (reported once).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) exhausted: bool,
}

/// Successors that may end before serving under one daemon build; past it
/// none is minted until a new build runs.
pub const MAX_ENDED_SUCCESSORS: u32 = 6;

/// The wait before minting the successor after `count` ended ones: the
/// first is replaced at once, then 5 min doubling to an hourly ceiling.
pub(crate) fn ended_successor_backoff_ms(count: u32) -> u64 {
    const FIRST_MS: u64 = 5 * 60 * 1000;
    const CEILING_MS: u64 = 60 * 60 * 1000;
    match count {
        0 => 0,
        n => FIRST_MS
            .saturating_mul(1u64 << (n - 1).min(16))
            .min(CEILING_MS),
    }
}

fn daemon_executable() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SuccessorPhase {
    /// The record has switched to the successor, but its open has not completed.
    Pending,
    /// The successor open returned: the transition is complete.
    Open,
}

impl ConversationRoot {
    /// Selects delegated children by links from the predecessor, not by seat;
    /// newest states and answer excerpts give the successor continuity.
    async fn live_delegated_children(
        &self,
        predecessor_session: &LiveSessionId,
    ) -> Result<serde_json::Value, IntentFailure> {
        const MAX_CHILDREN: usize = 8;
        const ANSWER_EXCERPT: usize = 600;
        let Some(links) = &self.delegation_links else {
            return Ok(serde_json::Value::Array(Vec::new()));
        };
        let parent = odin_domain::SessionId::new(predecessor_session.to_string())
            .map_err(|error| IntentFailure::Other(format!("predecessor session: {error}")))?;
        let mut links = links.children_of(&parent).map_err(|error| {
            IntentFailure::Other(format!("delegated children listing failed: {error}"))
        })?;
        links.sort_by_key(|link| std::cmp::Reverse(link.created_at_ms));
        let truncated = links.len() > MAX_CHILDREN;
        let mut children = Vec::new();
        for link in links.into_iter().take(MAX_CHILDREN) {
            let summary = self.find_session(link.child, true).await.ok().flatten();
            let answer = self
                .last_answer(link.child)
                .await
                .map(|text| text.chars().take(ANSWER_EXCERPT).collect::<String>());
            children.push(serde_json::json!({
                "session": link.child.to_string(),
                "seat": summary.as_ref().map(|summary| summary.seat_id.to_string()),
                "title": summary.as_ref().and_then(|summary| summary.title.clone()),
                "state": summary
                    .as_ref()
                    .map_or_else(|| "Ended".to_owned(), |summary| format!("{:?}", summary.state)),
                "answer": answer,
            }));
        }
        if truncated {
            children.push(serde_json::json!({ "truncated": true }));
        }
        Ok(serde_json::Value::Array(children))
    }

    /// The last non-empty assistant text of `session`, from its durable
    /// history; `None` when it has not answered or its history is unreadable.
    async fn last_answer(&self, session: LiveSessionId) -> Option<String> {
        let mut after = odin_domain::huginn::EventSeq::new(0);
        let mut answer = None;
        loop {
            let page = self
                .plane
                .history(odin_domain::huginn::HistoryQuery {
                    session_id: session,
                    after,
                    limit: super::history::page_limit(),
                })
                .await
                .ok()?;
            if page.events.is_empty() {
                return answer;
            }
            for event in page.events {
                after = event.sequence;
                if let odin_domain::huginn::LiveEventBody::AssistantMessage(message) = event.body {
                    let text = message
                        .content
                        .iter()
                        .filter_map(|block| match block {
                            odin_domain::huginn::LiveContentBlock::Text(text) => {
                                Some(text.as_str())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !text.trim().is_empty() {
                        answer = Some(text);
                    }
                }
            }
        }
    }

    /// Moves stale prompts to fresh successor command ids in Prepared phase, retaining
    /// the decision cursor. Live continuations still observe their original session journal.
    async fn rebind_wakes_to_successor(
        &self,
        record: &mut ConversationRecord,
        successor_session: &str,
    ) -> Result<(), IntentFailure> {
        // The observe cursor and epoch pin to the successor's CURRENT
        // head: a stale predecessor cursor would scan the successor's own
        // brief events and misread them as the wake's answer.
        let (event_head, epoch) = match self
            .find_session(
                LiveSessionId::parse(successor_session).map_err(|error| {
                    IntentFailure::Other(format!("successor session invalid: {error}"))
                })?,
                true,
            )
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
        {
            Some(summary) => (summary.event_head.get(), summary.epoch.get()),
            None => return Ok(()),
        };
        for wake in record.wakes.iter_mut() {
            if wake.completion.is_some() {
                continue;
            }
            let stale = wake
                .prompt
                .as_ref()
                .is_some_and(|prompt| prompt.session_id != successor_session)
                || (wake.session_id != successor_session
                    && wake.kind == super::WakeKind::KernelRetry);
            if !stale {
                continue;
            }
            let derivation = wake
                .approval_id
                .clone()
                .unwrap_or_else(|| wake.label.clone());
            let fresh = bounded_command("conversation-wake", &[successor_session, &derivation])
                .map_err(IntentFailure::Other)?
                .to_string();
            tracing::info!(
                session = %successor_session,
                "odin-hermes: rebinding pending wake {} onto successor {} as {}",
                wake.command_id, successor_session, fresh
            );
            wake.session_id = successor_session.to_owned();
            if let Some(prompt) = wake.prompt.as_mut() {
                prompt.session_id = successor_session.to_owned();
                prompt.command_id = fresh.clone();
                prompt.idempotency_key = fresh.clone();
                prompt.phase = super::InFlightPhase::Prepared;
                prompt.expected_epoch = epoch;
                prompt.event_cursor = event_head;
            }
            if wake.reply.is_none() {
                wake.command_id = fresh;
            }
        }
        Ok(())
    }

    pub(super) async fn begin_successor(
        &self,
        record: &mut ConversationRecord,
        observed_epoch: Option<u64>,
        observed_head: Option<u64>,
    ) -> Result<LiveSessionId, IntentFailure> {
        let predecessor_session = record.session_id.clone().ok_or_else(|| {
            IntentFailure::Other("the conversation vehicle is not initialized".to_owned())
        })?;
        let predecessor_command = self
            .recorded_vehicle_command(record)
            .map_err(IntentFailure::Other)?;
        if record.conversation_id.is_empty() {
            record.conversation_id = self.conversation_id.clone();
        }
        let successor_command =
            successor_vehicle_command(&record.conversation_id, &predecessor_session)
                .map_err(IntentFailure::Other)?;
        let successor_session = session_id_for(&successor_command)
            .map_err(|error| {
                IntentFailure::Other(format!("successor session identity rejected: {error}"))
            })?
            .to_string();
        // The brief is rendered FIRST: nothing is armed until the
        // continuity carrier exists.
        let delegated_children = self
            .live_delegated_children(&LiveSessionId::parse(&predecessor_session).map_err(
                |error| IntentFailure::Other(format!("predecessor session invalid: {error}")),
            )?)
            .await;
        let brief =
            self.render_successor_brief(&predecessor_session, observed_epoch, delegated_children)?;
        // Persist the pending transition before touching the predecessor so restart
        // can resume retirement, confirmation, switching and opening.
        record.rollover = Some(VehicleRollover {
            predecessor_session: predecessor_session.clone(),
            predecessor_command: predecessor_command.to_string(),
            successor_command: successor_command.to_string(),
            successor_session: successor_session.clone(),
            brief,
            predecessor_event_head: observed_head.unwrap_or(0),
            phase: SuccessorPhase::Pending,
            brief_command: None,
            ended: None,
        });
        self.store_record(record).map_err(IntentFailure::Other)?;
        self.resume_successor(record).await
    }

    /// Validates both derived identities and confirms predecessor retirement before
    /// opening, whether the record still names the predecessor or the successor.
    pub(super) async fn resume_successor(
        &self,
        record: &mut ConversationRecord,
    ) -> Result<LiveSessionId, IntentFailure> {
        for _ in 0..MAX_SUCCESSOR_TRANSITIONS {
            if let Some(session) = self.resume_successor_step(record).await? {
                return Ok(session);
            }
        }
        Err(IntentFailure::Other(
            "publication advanced during successor admission; transition remains pending"
                .to_owned(),
        ))
    }

    async fn resume_successor_step(
        &self,
        record: &mut ConversationRecord,
    ) -> Result<Option<LiveSessionId>, IntentFailure> {
        if self.authority.rollover_deferred() {
            tracing::warn!(
                conversation = %self.conversation_id,
                "successor admission waits for publication reload; retry the request after reload"
            );
            return Err(IntentFailure::ConversationBusy);
        }
        let slot = record
            .rollover
            .clone()
            .ok_or_else(|| IntentFailure::Other("no successor transition is armed".to_owned()))?;
        let derived = successor_vehicle_command(&record.conversation_id, &slot.predecessor_session)
            .map_err(IntentFailure::Other)?;
        if derived.to_string() != slot.successor_command {
            return Err(IntentFailure::Other(
                "the armed successor identity does not match its derivation".to_owned(),
            ));
        }
        let derived_session = session_id_for(&derived)
            .map_err(|error| {
                IntentFailure::Other(format!("successor session identity rejected: {error}"))
            })?
            .to_string();
        if derived_session != slot.successor_session {
            return Err(IntentFailure::Other(
                "the armed successor session does not match its derivation".to_owned(),
            ));
        }
        // Re-render oversized persisted briefs under the current budget before opening a successor.
        {
            let budget = self.rollover.max_brief_bytes;
            if slot.brief.as_deref().map_or(0, str::len) > budget {
                let predecessor = slot.predecessor_session.clone();
                let children = self
                    .live_delegated_children(&LiveSessionId::parse(&predecessor).map_err(
                        |error| {
                            IntentFailure::Other(format!("predecessor session invalid: {error}"))
                        },
                    )?)
                    .await;
                let rendered = self.render_successor_brief(&predecessor, None, children)?;
                if rendered.is_some() {
                    if let Some(current) = record.rollover.as_mut() {
                        current.brief = rendered;
                    }
                    self.store_record(record).map_err(IntentFailure::Other)?;
                }
            }
        }
        let follows_predecessor = match record.session_id.as_deref() {
            Some(id) if id == slot.successor_session => false,
            Some(id) if id == slot.predecessor_session => {
                // Route old inputs before the record starts naming the successor.
                self.route_unsettled_inputs(
                    record,
                    &slot.predecessor_session,
                    &slot.successor_session,
                )
                .await?;
                true
            }
            _ => {
                return Err(IntentFailure::Other(
                    "the record names neither the predecessor nor the derived successor".to_owned(),
                ));
            }
        };
        self.carry_delegated_children(&slot.predecessor_session, &slot.successor_session)?;
        let retired = self
            .retire_predecessor(&slot.predecessor_session, None)
            .await?;
        if retired {
            if let Some(links) = &self.delegation_links {
                let predecessor = odin_domain::SessionId::new(slot.predecessor_session.clone())
                    .map_err(|error| {
                        IntentFailure::Other(format!("predecessor session: {error}"))
                    })?;
                links.clear_successor(&predecessor).map_err(|error| {
                    IntentFailure::Other(format!(
                        "could not clear the predecessor handoff arm: {error}"
                    ))
                })?;
            }
        }
        if follows_predecessor {
            record.vehicle_command_id = Some(slot.successor_command.clone());
            record.session_id = Some(slot.successor_session.clone());
            self.store_record(record).map_err(IntentFailure::Other)?;
        }
        self.open_successor(record).await
    }

    /// Ensures + opens the derived successor at the current generation,
    /// carrying the persisted brief as its first prompt. Marks the slot
    /// Open only once the open is durable.
    async fn open_successor(
        &self,
        record: &mut ConversationRecord,
    ) -> Result<Option<LiveSessionId>, IntentFailure> {
        let Some(slot) = record.rollover.clone() else {
            return Err(IntentFailure::Other(
                "the successor transition slot vanished".to_owned(),
            ));
        };
        let successor_session = LiveSessionId::parse(&slot.successor_session)
            .map_err(|error| IntentFailure::Other(format!("successor session invalid: {error}")))?;
        let successor_command = CommandId::new(&slot.successor_command)
            .map_err(|error| IntentFailure::Other(format!("successor command invalid: {error}")))?;
        let ensured = self
            .authority
            .ensure(&successor_command, successor_session)
            .await
            .map_err(IntentFailure::Other)?;
        if self
            .find_session(successor_session, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
            .is_some_and(|summary| summary.state == LiveSessionState::Ended)
        {
            // A pending successor that ended before it served (its first
            // open failed) can never be reopened: derive a fresh one.
            return self.supersede_ended_successor(record, &slot);
        }
        if ensured.lags() {
            // Replace stale-generation successors before opening, preserving the unused brief;
            // resume handles retirement, switching and opening under the new identity.
            self.supersede_pending_successor(record, &slot)?;
            return Ok(None);
        }
        let manifest_present = self
            .plane
            .session_manifest_present(successor_session)
            .await
            .map_err(|error| {
                IntentFailure::Other(format!("successor manifest lookup failed: {error}"))
            })?;
        if manifest_present {
            // The open already happened before the crash: converge on the
            // recovered successor, unless it ended.
            match self
                .recover_session(successor_session, None, "successor resume")
                .await
            {
                Err(IntentFailure::ConversationClosed) => {
                    return self.supersede_ended_successor(record, &slot);
                }
                outcome => {
                    outcome?;
                }
            }
        } else {
            self.open_vehicle(record, &successor_command, successor_session, ensured.bound)
                .await
                .map_err(|error| IntentFailure::Other(error.to_string()))?;
        }
        match self
            .deliver_successor_brief(record, successor_session, &successor_command)
            .await?
        {
            BriefDelivery::Applied => {}
            BriefDelivery::NeverApplied => {
                // The brief command was recorded by an earlier attempt
                // while the successor never came up (its accepting run is
                // gone), so it can never resolve to an applied outcome —
                // re-submitting the same id is a permanent Duplicate
                // loop. Retire that successor identity and derive a fresh
                // one (brief preserved verbatim, no journal record at the
                // new id); the idempotent resume owns the retry and the
                // transition bound caps it. Never a loop.
                self.supersede_pending_successor(record, &slot)?;
                return Ok(None);
            }
        }
        // Once the successor and brief settle, move wakes to fresh command ids;
        // a predecessor's prompt cannot be submitted to a different session.
        self.rebind_wakes_to_successor(record, &slot.successor_session)
            .await?;
        // Move approval scope to the successor so it can consume the predecessor's approved requests.
        if let (Ok(predecessor), Ok(successor)) = (
            LiveSessionId::parse(&slot.predecessor_session),
            LiveSessionId::parse(&slot.successor_session),
        ) {
            // The coding review lane's evidence follows through this same
            // transfer. A failed transfer leaves the slot pending: the
            // idempotent resume retries it instead of marking it Open.
            self.approvals
                .follow_vehicle(&predecessor, &successor)
                .await
                .map_err(IntentFailure::Other)?;
        }

        // The first owner message must not race the continuity turn.
        tokio::time::timeout(self.answer_bound, async {
            loop {
                let summary = self
                    .find_session(successor_session, true)
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?
                    .ok_or(IntentFailure::HistoryUnavailable)?;
                match summary.state {
                    LiveSessionState::Idle => return Ok(()),
                    LiveSessionState::Ended => return Err(IntentFailure::ConversationClosed),
                    LiveSessionState::Failed => return Err(IntentFailure::VehicleLost),
                    _ => self
                        .plane
                        .wait_for_history(successor_session, summary.event_head)
                        .await
                        .map_err(|_| IntentFailure::HistoryUnavailable)?,
                }
            }
        })
        .await
        .map_err(|_| IntentFailure::AnswerTimeout)??;
        let recovered = record
            .rollover
            .as_ref()
            .is_some_and(|slot| slot.ended.is_some());
        if let Some(slot) = record.rollover.as_mut() {
            slot.phase = super::rollover::SuccessorPhase::Open;
        }
        self.store_record(record).map_err(IntentFailure::Other)?;
        if recovered {
            self.authority
                .successor_trouble(&record.conversation_id, SuccessorTrouble::Recovered);
        }
        Ok(Some(successor_session))
    }
    async fn deliver_successor_brief(
        &self,
        record: &mut ConversationRecord,
        session: LiveSessionId,
        command_id: &CommandId,
    ) -> Result<BriefDelivery, IntentFailure> {
        use odin_domain::huginn::{
            CommandReceipt, LiveCommand, LiveCommandBody, LiveContentBlock, LiveMessage,
        };

        let slot = record
            .rollover
            .as_ref()
            .ok_or_else(|| IntentFailure::Other("the successor slot vanished".to_owned()))?;
        let Some(brief) = slot.brief.as_ref() else {
            return Err(IntentFailure::HistoryUnavailable);
        };
        let previous = slot.brief_command.clone();
        if let Some(command) = previous.as_ref() {
            if let Some(entry) = self
                .plane
                .command_entry(command)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
            {
                return classify_applied_brief(&entry.receipt);
            }
        }
        let summary = self
            .find_session(session, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
            .ok_or(IntentFailure::HistoryUnavailable)?;
        if summary.state == LiveSessionState::Ended {
            return Err(IntentFailure::ConversationClosed);
        }
        let command = LiveCommand {
            command_id: command_id.clone(),
            session_id: session,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body: LiveCommandBody::Prompt {
                message: LiveMessage::new(vec![LiveContentBlock::Text(brief.clone())])
                    .map_err(|error| IntentFailure::Other(error.to_string()))?,
            },
        };
        record
            .rollover
            .as_mut()
            .expect("slot was checked")
            .brief_command = Some(command.clone());
        self.store_record(record).map_err(IntentFailure::Other)?;
        match self
            .plane
            .command(command.clone())
            .await
            .map_err(|error| IntentFailure::Other(format!("continuity prompt failed: {error}")))?
        {
            CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. } => {
                let entry = self
                    .plane
                    .command_entry(&command)
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?
                    .ok_or(IntentFailure::HistoryUnavailable)?;
                classify_applied_brief(&entry.receipt)
            }
            CommandReceipt::Rejected { reason, .. } => Err(IntentFailure::Other(format!(
                "continuity prompt rejected: {reason:?}"
            ))),
        }
    }

    /// Replaces successors that ended before serving on a durable backoff, not every open retry.
    fn supersede_ended_successor(
        &self,
        record: &mut ConversationRecord,
        slot: &VehicleRollover,
    ) -> Result<Option<LiveSessionId>, IntentFailure> {
        let executable = daemon_executable();
        let now = now_unix_ms();
        let prior = slot
            .ended
            .as_ref()
            .filter(|ended| ended.executable == executable);
        let attempts = prior.map_or(0, |ended| ended.count);
        if attempts >= MAX_ENDED_SUCCESSORS {
            let newly = prior.is_some_and(|ended| !ended.exhausted);
            if newly {
                tracing::error!(
                    session = %slot.successor_session,
                    "odind: conversation successor exhausted conversation={} ended={attempts} \
                     successor={}; minting stops until a new build",
                    record.conversation_id, slot.successor_session
                );
                if let Some(ended) = record
                    .rollover
                    .as_mut()
                    .and_then(|slot| slot.ended.as_mut())
                {
                    ended.exhausted = true;
                }
                self.store_record(record).map_err(IntentFailure::Other)?;
            }
            self.authority.successor_trouble(
                &record.conversation_id,
                SuccessorTrouble::Exhausted { attempts, newly },
            );
            return Err(IntentFailure::SuccessorStartExhausted { attempts });
        }
        if let Some(prior) = prior {
            let retry_at_unix_ms = prior
                .last_at_unix_ms
                .saturating_add(ended_successor_backoff_ms(prior.count));
            if now < retry_at_unix_ms {
                self.authority.successor_trouble(
                    &record.conversation_id,
                    SuccessorTrouble::Backoff {
                        attempts,
                        retry_at_unix_ms,
                    },
                );
                return Err(IntentFailure::SuccessorStartBackoff {
                    attempts,
                    retry_at_unix_ms,
                });
            }
        }
        tracing::warn!(
            session = %slot.successor_session,
            "odind: conversation successor ended before serving successor={} ended={} \
             conversation={}; deriving a fresh successor",
            slot.successor_session,
            attempts + 1,
            record.conversation_id
        );
        if let Some(current) = record.rollover.as_mut() {
            current.ended = Some(EndedSuccessors {
                count: attempts + 1,
                last_at_unix_ms: now,
                executable,
                exhausted: false,
            });
        }
        self.supersede_pending_successor(record, slot)?;
        Ok(None)
    }

    /// Moves a pending transition one governed generation forward: the
    /// stale successor session becomes the slot's predecessor and the
    /// next derived identity becomes its successor. The brief and its
    /// rendered head are preserved verbatim, and the slot stays Pending.
    fn supersede_pending_successor(
        &self,
        record: &mut ConversationRecord,
        slot: &VehicleRollover,
    ) -> Result<(), IntentFailure> {
        let stale_session = slot.successor_session.clone();
        let stale_command = slot.successor_command.clone();
        let next_command = successor_vehicle_command(&record.conversation_id, &stale_session)
            .map_err(IntentFailure::Other)?;
        let next_session = session_id_for(&next_command)
            .map_err(|error| {
                IntentFailure::Other(format!("successor session identity rejected: {error}"))
            })?
            .to_string();
        let predecessor = slot.predecessor_session.clone();
        // Unopened B: children of B and of A must name C before the slot moves.
        self.carry_delegated_children(&stale_session, &next_session)?;
        self.carry_delegated_children(&predecessor, &next_session)?;
        let slot = record
            .rollover
            .as_mut()
            .ok_or_else(|| IntentFailure::Other("the successor slot vanished".to_owned()))?;
        slot.predecessor_session = stale_session;
        slot.predecessor_command = stale_command;
        slot.successor_command = next_command.to_string();
        slot.brief_command = None;
        slot.successor_session = next_session;
        self.store_record(record).map_err(IntentFailure::Other)
    }

    /// Arms late children before moving live children onto the next vehicle.
    fn carry_delegated_children(&self, from: &str, to: &str) -> Result<(), IntentFailure> {
        let Some(links) = &self.delegation_links else {
            return Ok(());
        };
        let from = odin_domain::SessionId::new(from)
            .map_err(|error| IntentFailure::Other(format!("delegation parent {from}: {error}")))?;
        let to = odin_domain::SessionId::new(to)
            .map_err(|error| IntentFailure::Other(format!("delegation successor {to}: {error}")))?;
        links.arm_successor(&from, &to).map_err(|error| {
            IntentFailure::Other(format!(
                "could not arm delegated children from {from} to {to}: {error}"
            ))
        })?;
        links.repoint_children(&from, &to).map_err(|error| {
            IntentFailure::Other(format!(
                "could not carry delegated children from {from} to {to}: {error}"
            ))
        })?;
        Ok(())
    }

    /// Retries need fresh command IDs because old IDs only replay their results.
    async fn retire_predecessor(
        &self,
        predecessor_session: &str,
        observed_epoch: Option<u64>,
    ) -> Result<bool, IntentFailure> {
        const ATTEMPTS: u32 = 3;
        const PROOF_POLLS: u32 = 8;
        const PROOF_SLICE: std::time::Duration = std::time::Duration::from_millis(100);
        let session_id = LiveSessionId::parse(predecessor_session)
            .map_err(|error| IntentFailure::Other(format!("session invalid: {error}")))?;
        let canonical = self.find_session(session_id, true).await.map_err(|error| {
            IntentFailure::Other(format!("predecessor listing failed: {error}"))
        })?;
        if let Some(summary) = canonical.as_ref() {
            if summary.state == LiveSessionState::Ended {
                return Ok(true);
            }
        }
        let Some(epoch) =
            observed_epoch.or_else(|| canonical.as_ref().map(|summary| summary.epoch.get()))
        else {
            if self
                .plane
                .session_manifest_present(session_id)
                .await
                .map_err(|error| {
                    IntentFailure::Other(format!("predecessor manifest lookup failed: {error}"))
                })?
            {
                self.log_left_running(predecessor_session, "manifest present, no readable row");
                return Ok(false);
            }
            return Ok(true);
        };
        let mut left = String::new();
        for attempt in 0..ATTEMPTS {
            if self.predecessor_ended(session_id).await? {
                return Ok(true);
            }
            let command = self
                .retirement_command(session_id, epoch, attempt)
                .map_err(IntentFailure::Other)?;
            // A prior attempt that already applied is not driven again.
            // A failed, rejected, or still-unfinished receipt is: the next
            // attempt index is a new command, so the stop actually re-runs.
            if let Some(entry) = self.plane.command_entry(&command).await.map_err(|error| {
                IntentFailure::Other(format!("retirement journal lookup failed: {error}"))
            })? {
                if retirement_applied(&entry.receipt) {
                    if self
                        .await_predecessor_ended(session_id, PROOF_POLLS, PROOF_SLICE)
                        .await?
                    {
                        return Ok(true);
                    }
                    left = format!(
                        "attempt {attempt} applied but session {} is still not Ended",
                        session_id
                    );
                } else {
                    left = format!(
                        "attempt {attempt} is already journaled and did not retire the session"
                    );
                }
                continue;
            }
            match self.plane.command(command).await {
                Ok(receipt) if retirement_applied(&receipt) => {
                    if self
                        .await_predecessor_ended(session_id, PROOF_POLLS, PROOF_SLICE)
                        .await?
                    {
                        return Ok(true);
                    }
                    left = format!(
                        "attempt {attempt} accepted but session {} did not reach Ended",
                        session_id
                    );
                }
                Ok(receipt) => {
                    left = format!("attempt {attempt} did not retire the session: {receipt:?}");
                }
                Err(error) => {
                    left = format!("attempt {attempt} retirement command failed: {error}");
                }
            }
        }
        let state = self
            .find_session(session_id, true)
            .await
            .ok()
            .flatten()
            .map(|summary| format!("{:?}", summary.state))
            .unwrap_or_else(|| "unlisted".to_owned());
        self.log_left_running(
            predecessor_session,
            &format!("state={state} epoch={epoch} {left}"),
        );
        Ok(false)
    }

    async fn predecessor_ended(&self, session_id: LiveSessionId) -> Result<bool, IntentFailure> {
        Ok(self
            .find_session(session_id, true)
            .await
            .map_err(|error| IntentFailure::Other(format!("retirement proof unreadable: {error}")))?
            .is_some_and(|summary| summary.state == LiveSessionState::Ended))
    }

    async fn await_predecessor_ended(
        &self,
        session_id: LiveSessionId,
        polls: u32,
        slice: std::time::Duration,
    ) -> Result<bool, IntentFailure> {
        for _ in 0..polls {
            if self.predecessor_ended(session_id).await? {
                return Ok(true);
            }
            tokio::time::sleep(slice).await;
        }
        self.predecessor_ended(session_id).await
    }

    fn log_left_running(&self, session: &str, detail: &str) {
        tracing::warn!(
            session = %session,
            "odin-hermes: predecessor {session} left running; successor opens anyway ({detail})"
        );
    }

    /// Bound continuity by delivered conversation turns, not worker events.
    /// A failed vehicle can have no messages even though the same logical
    /// conversation has durable replies from earlier vehicles.
    fn render_successor_brief(
        &self,
        predecessor_session: &str,
        observed_epoch: Option<u64>,
        delegated_children: Result<serde_json::Value, IntentFailure>,
    ) -> Result<Option<String>, IntentFailure> {
        let policy = self.rollover.clone();
        let history_error = |error: rusqlite::Error| {
            IntentFailure::Other(format!("durable conversation history unavailable: {error}"))
        };
        let connection = rusqlite::Connection::open_with_flags(
            &self.ledger_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(history_error)?;
        // Scope before LIMIT: another conversation's newer rows must neither
        // leak into this brief nor displace this owner's recent turns.
        let mut statement = connection
            .prepare(
                "SELECT substr(json_extract(arguments_json, '$.request'), 1, ?5),
                    substr(json_extract(terminal_result_json, '$.outcome.answer'), 1, ?5),
                    issued_at
             FROM commands
             WHERE issuer = ?7 AND target_kind = 'seat' AND target_id = ?1
               AND accepted_at IS NOT NULL
               AND terminal_status = 'completed' AND terminal_at IS NOT NULL
               AND json_extract(arguments_json, '$.author_id') = ?2
               AND json_extract(arguments_json, '$.channel_id') = ?3
               AND json_type(arguments_json, '$.guild_id') = 'null'
               AND json_type(arguments_json, '$.request') = 'text'
               AND json_extract(terminal_result_json, '$.status') = 'executed'
               AND json_extract(terminal_result_json, '$.outcome.seat') = ?1
               AND json_extract(terminal_result_json, '$.outcome.project') = ?4
               AND json_extract(terminal_result_json, '$.outcome.commandId') = command_id
               AND json_extract(terminal_result_json, '$.outcome.idempotencyKey') = idempotency_key
               AND json_type(terminal_result_json, '$.outcome.replySent') = 'true'
               AND json_type(terminal_result_json, '$.outcome.answer') = 'text'
               AND length(trim(json_extract(terminal_result_json, '$.outcome.answer'))) > 0
             ORDER BY terminal_at DESC, command_id DESC LIMIT ?6",
            )
            .map_err(history_error)?;
        let turns = statement
            .query_map(
                rusqlite::params![
                    self.binding.seat_id.as_str(),
                    self.owner.owner_user_id,
                    self.owner.channel_id,
                    self.project.as_str(),
                    odin_omp::live::rollover::ROLLOVER_TAIL_ENTRY_CHARS + 1,
                    policy.history_tail_events / 2,
                    crate::ingress::INTENT_ISSUER,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(history_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(history_error)?;
        let mut events = Vec::with_capacity(turns.len() * 2);
        for (request, answer, issued_at) in turns.into_iter().rev() {
            let request = stamped_request(self.clock.as_ref(), &issued_at, request);
            events.push(serde_json::json!({
                "kind": "command_issued",
                "command": "prompt",
                "frame": { "message": request },
            }));
            events.push(serde_json::json!({
                "kind": "session",
                "frame": { "type": "message_end", "role": "assistant", "content": answer },
            }));
        }
        let inputs = RolloverBriefInputs {
            session_id: predecessor_session.to_owned(),
            seat_id: self.binding.seat_id.as_str().to_owned(),
            project_id: self.project.as_str().to_owned(),
            lane_id: self.lane.as_str().to_owned(),
            provider: self.provider.as_str().to_owned(),
            model: self.model.as_str().to_owned(),
            title: None,
            epoch_before: observed_epoch.unwrap_or(0) as i64,
            observed_watermark: None,
            threshold_tokens: policy.threshold_tokens,
            plan: None,
            assignment: None,
            children: Vec::<RolloverChildState>::new(),
            pending_approvals: Vec::<RolloverPendingApproval>::new(),
            events,
        };
        // Delegated children carry honestly: the bounded live listing when
        // the plane answers, or the typed refusal — never a fabricated
        // empty list.
        let delegated_children = match delegated_children {
            Ok(children) => children,
            Err(error) => serde_json::json!(format!("listing unavailable: {error}")),
        };
        let notes = serde_json::json!({
            "conversation_tail": "delivered owner DM turns from the durable conversation ledger",
            "delegated_children": delegated_children,
            "task_plan": "re-verified by the successor plan gate",
            "observed_watermark": "not measured at the conversation boundary",
        });
        let notes_bytes = serde_json::to_vec(&notes).map_err(|error| {
            IntentFailure::Other(format!("brief notes serialize failed: {error}"))
        })?;
        let reserved = notes_bytes.len() + "\"continuity_notes\":".len() + 1;
        let render_policy = RolloverPolicy {
            max_brief_bytes: policy
                .max_brief_bytes
                .checked_sub(reserved)
                .ok_or_else(|| {
                    IntentFailure::Other("continuity metadata exceeds the brief budget".to_owned())
                })?,
            ..policy.clone()
        };
        let (mut brief, _) = render_brief(&inputs, &render_policy)
            .map_err(|error| IntentFailure::Other(format!("continuity brief failed: {error}")))?;
        brief["continuity_notes"] = notes;
        let bounded = serde_json::to_vec(&brief)
            .map_err(|error| IntentFailure::Other(format!("brief serialize failed: {error}")))?;
        if bounded.len() > policy.max_brief_bytes {
            return Err(IntentFailure::Other(format!(
                "the continuity brief exceeds its bounded budget: {} bytes",
                bounded.len()
            )));
        }
        // Use the shared rollover marker for the first-context carrier.
        let json = String::from_utf8(bounded)
            .map_err(|error| IntentFailure::Other(format!("brief is not UTF-8: {error}")))?;
        Ok(Some(odin_omp::live::rollover::continuity_prompt(
            &format!("{}]", odin_omp::live::rollover::ROLLOVER_PROMPT_MARKER),
            &json,
        )))
    }

    /// Checks journal admission, not local phase: admitted inputs retain their session,
    /// cursor and epoch; only unadmitted prompts move to the successor. Read errors refuse.
    async fn route_unsettled_inputs(
        &self,
        record: &mut ConversationRecord,
        predecessor_session: &str,
        successor_session: &str,
    ) -> Result<(), IntentFailure> {
        // Only PREDECESSOR-owned inputs route: a repeated resume after the
        // switch never re-queries the un-admitted new session as old — an
        // entry already carried to the successor stays exactly where it
        // is.
        if let Some(flight) = record.in_flight.as_mut() {
            // Only PREDECESSOR-owned inputs route: a repeated resume after
            // the switch never re-queries the un-admitted new session as
            // old — an entry already carried to the successor stays
            // exactly where it is.
            if flight.session_id == predecessor_session {
                let command = flight.command().map_err(IntentFailure::Other)?;
                let admitted = self
                    .plane
                    .command_entry(&command)
                    .await
                    .map_err(|error| {
                        IntentFailure::Other(format!(
                            "the admission journal is unreadable; the transition refuses: {error}"
                        ))
                    })?
                    .is_some();
                if !admitted {
                    flight.session_id = successor_session.to_owned();
                    flight.phase = super::InFlightPhase::Prepared;
                    flight.expected_epoch = 1;
                    flight.event_cursor = 0;
                }
            }
        }
        for wake in record.wakes.iter_mut() {
            if wake.completion.is_some() {
                continue;
            }
            let Some(prompt) = wake.prompt.as_mut() else {
                continue;
            };
            // The same predecessor-ownership filter for wakes.
            if prompt.session_id != predecessor_session {
                continue;
            }
            let command = prompt.command().map_err(IntentFailure::Other)?;
            let admitted = self
                .plane
                .command_entry(&command)
                .await
                .map_err(|error| {
                    IntentFailure::Other(format!(
                        "the admission journal is unreadable; the transition refuses: {error}"
                    ))
                })?
                .is_some();
            if !admitted {
                prompt.session_id = successor_session.to_owned();
                prompt.phase = super::InFlightPhase::Prepared;
                prompt.expected_epoch = 1;
                prompt.event_cursor = 0;
            }
        }
        Ok(())
    }
}

/// The classified outcome of the successor brief command's journal entry.
pub(super) enum BriefDelivery {
    /// The recorded command provably applied — continuity was consumed.
    Applied,
    /// The recorded command can NEVER apply: its accepting run is gone
    /// (the successor never came up) or it settled Failed/Cancelled, so
    /// re-submission is a permanent Duplicate replaying that outcome. The caller must retire this successor
    /// identity and derive a fresh one.
    NeverApplied,
}

fn classify_applied_brief(
    receipt: &odin_domain::huginn::CommandReceipt,
) -> Result<BriefDelivery, IntentFailure> {
    use odin_domain::huginn::{CommandOutcome, CommandReceipt};
    match receipt {
        CommandReceipt::Duplicate {
            prior_outcome: Some(outcome),
            ..
        } if matches!(outcome.as_ref(), CommandOutcome::Applied { .. }) => {
            Ok(BriefDelivery::Applied)
        }
        // Recorded but never applied, and nothing can apply it now: the
        // successor that admitted it never came up (no outcome), or its
        // continuity turn settled Failed/Cancelled — a durable outcome that
        // re-submitting the same id can only replay. Supersede, never loop.
        CommandReceipt::Duplicate { .. } => Ok(BriefDelivery::NeverApplied),
        other => Err(IntentFailure::Other(format!(
            "continuity command has no durable applied outcome: {other:?}"
        ))),
    }
}

/// An accepted abort, or a duplicate whose prior outcome applied. A
/// rejection, a failed outcome, or a duplicate with no outcome did not
/// retire the session and must be driven again under a new command id.
fn retirement_applied(receipt: &odin_domain::huginn::CommandReceipt) -> bool {
    use odin_domain::huginn::{CommandOutcome, CommandReceipt};
    match receipt {
        CommandReceipt::Accepted { .. } => true,
        CommandReceipt::Duplicate {
            prior_outcome: Some(outcome),
            ..
        } => matches!(outcome.as_ref(), CommandOutcome::Applied { .. }),
        CommandReceipt::Duplicate { .. } | CommandReceipt::Rejected { .. } => false,
    }
}

/// Carries the owner's original local timestamp so a successor does not infer message age.
fn stamped_request(
    clock: Option<&crate::schedule::OwnerClock>,
    issued_at: &str,
    request: String,
) -> String {
    match (clock, issued_at.parse::<jiff::Timestamp>()) {
        (Some(clock), Ok(at)) => format!("{} {request}", clock.line(at)),
        _ => request,
    }
}

#[cfg(test)]
mod stamp_tests {
    #[test]
    fn a_carried_turn_opens_with_the_owners_local_time_when_it_was_sent() {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(
            dir.path().join("clock.json"),
            r#"{"zone":"America/Los_Angeles"}"#,
        )
        .expect("zone");
        let clock = crate::schedule::OwnerClock::new(dir.path());
        assert_eq!(
            super::stamped_request(
                Some(&clock),
                "2026-09-30T08:25:04.100Z",
                "fyi I'm going to study at the Red Door cafe tonight".to_owned()
            ),
            "[Colin's local time: Wednesday 2026-09-30 01:25 PDT (America/Los_Angeles)] \
             fyi I'm going to study at the Red Door cafe tonight"
        );
        assert_eq!(
            super::stamped_request(None, "2026-09-30T08:25:04.100Z", "hi".to_owned()),
            "hi"
        );
    }
}
