//! Decisions require delivered open questions and persist their wake before deciding.
//! Wakes resume from durable history and are cleared only after completion.

use std::time::Duration as StdDuration;

use async_trait::async_trait;
use odin_domain::huginn::{
    CommandReceipt, EventSeq, HistoryQuery, LiveCommand, LiveCommandBody, LiveSessionId,
    LiveSessionState, PermissionDecision, PermissionRequestId,
};
use odin_domain::CommandId;

use crate::natural::{
    parse_leading_denial, parse_whole_message_decision, Designation, OwnerDecision,
};
use crate::runtime::{
    AuthenticatedOwnerMessage, DecisionRefusal, IntentFailure, OwnerDecisionRoute,
};

use super::history::page_limit;
use super::history::AnswerWait;
use super::identity::{bounded_command, now_unix_ms, now_utc};
use super::KernelDecisionOutcome;
use super::{
    ContinuationReply, ConversationRecord, ConversationRoot, DeliveredQuestion, InFlightKind,
    InFlightPhase, InFlightPrompt, PendingWake, WakeKind,
};

/// How long a late answer is awaited before its wake gives up.
pub(super) const LATE_ANSWER_BOUND: StdDuration = StdDuration::from_secs(45 * 60);
/// The queue's wake retries a failed pass after this, doubling to the max.
const QUEUE_RETRY_FIRST: StdDuration = StdDuration::from_secs(30);
const QUEUE_RETRY_MAX: StdDuration = StdDuration::from_secs(10 * 60);
/// How often any other failed wake is retried before it is settled.
const WAKE_RETRIES: u32 = 4;
/// How long an aborted, obsolete tracker of the same continuation may take
/// to unwind before an external decision refuses instead of deciding.
const WAKE_RETIRE_BOUND: StdDuration = StdDuration::from_secs(5);
/// How many wake tasks are listed before finished ones without a plan are
/// forgotten.
const FINISHED_WAKES_KEPT: usize = 64;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum WakeProgress {
    Complete,
    /// Removed durably under the lock that observed its terminal status.
    Retired,
    Pending,
}

enum NativeDecisionStatus {
    Unresolved,
    Resolved,
    Failed(String),
}

fn decision_word(approved: bool) -> &'static str {
    if approved {
        "approve"
    } else {
        "deny"
    }
}

fn decision_ack(approved: bool) -> &'static str {
    if approved {
        "Done \u{2014} I'm on it."
    } else {
        "Understood \u{2014} I won't do that."
    }
}

/// Renders one kernel decision refusal as one plain sentence. No ids, no
/// receipt hashes, no machinery.
fn kernel_refusal_sentence(refusal: &DecisionRefusal) -> String {
    match refusal {
        DecisionRefusal::NotAuthenticated => {
            "That decision could not be authenticated, so nothing was authorized.".to_owned()
        }
        DecisionRefusal::Undelivered(_) => {
            "That question never actually reached you, so nothing was authorized.".to_owned()
        }
        DecisionRefusal::Superseded { .. } => {
            "The question you answered has since changed, so nothing was authorized.".to_owned()
        }
        DecisionRefusal::NotOpen(_) => {
            "That question has already settled, so nothing was changed.".to_owned()
        }
        DecisionRefusal::Expired(_) => {
            "That question expired before your reply, so nothing was authorized.".to_owned()
        }
        DecisionRefusal::SessionRetired => {
            "The conversation that asked has since closed, so nothing was authorized.".to_owned()
        }
        DecisionRefusal::PredatesDelivery(_) => {
            "I can't safely match that reply to the question. Please answer it again.".to_owned()
        }
        DecisionRefusal::IntakeConsumed(_) => {
            "That reply already settled its question, so nothing new was changed.".to_owned()
        }
        DecisionRefusal::Evidence(_) | DecisionRefusal::Ledger(_) => {
            "The decision could not be recorded just now and nothing was authorized; say it \
             again in a moment."
                .to_owned()
        }
    }
}

const MULTIPLE_QUESTIONS_SENTENCE: &str =
    "More than one thing is waiting on you right now; tell me which one you mean in plain \
     words, or answer them one at a time.";

impl ConversationRoot {
    /// Spawns a durable wake plan as an OWNED continuation: tracked in
    /// the background registry (bounded join at shutdown), never
    /// detached. The plan was persisted before this spawn. `false` when the
    /// stopping root declined to own it.
    pub(super) async fn spawn_wake_task(&self, wake: PendingWake) -> bool {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let mut background = self.background.lock().await;
        self.spawn_wake_task_owned(wake, &mut background)
    }

    fn spawn_wake_task_owned(
        &self,
        wake: PendingWake,
        background: &mut std::collections::BTreeMap<String, tokio::task::JoinHandle<()>>,
    ) -> bool {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let Some(root) = self.self_weak.upgrade() else {
            return false;
        };
        // A finished task stays listed while its plan remains: the queue
        // reads it as "ran, now waiting on Colin", never as unspawned.
        if background.len() > FINISHED_WAKES_KEPT {
            let planned: std::collections::BTreeSet<String> = self
                .load_record()
                .map(|record| {
                    record
                        .wakes
                        .into_iter()
                        .map(|plan| plan.command_id)
                        .collect()
                })
                .unwrap_or_default();
            background.retain(|id, handle| !handle.is_finished() || planned.contains(id));
        }
        if background
            .get(&wake.command_id)
            .is_some_and(|handle| !handle.is_finished())
        {
            return true;
        }
        let key = wake.command_id.clone();
        let handle = self.handle.spawn(async move {
            let mut retry = QUEUE_RETRY_FIRST;
            let mut retries = 0;
            loop {
                match root.run_wake(&wake).await {
                    Ok(WakeProgress::Complete) => {
                        let _guard = root.lock.lock().await;
                        if let Err(error) = root.drop_wake(&wake) {
                            tracing::error!(error = %error, "conversation wake could not persist completion: {error}");
                        }
                    }
                    Ok(WakeProgress::Pending | WakeProgress::Retired) => {}
                    // Colin's queued messages never wait on a later message
                    // or a restart to be sent; a wake ahead of them retries
                    // a few times and is then settled, so the queue never
                    // waits on it forever.
                    Err(error) if wake.kind == WakeKind::QueuedAsks || retries < WAKE_RETRIES => {
                        retries += 1;
                        tracing::warn!(
                            error = %error,
                            "odind: conversation-wake retry kind={:?} in_s={} error={error}",
                            wake.kind,
                            retry.as_secs()
                        );
                        tokio::time::sleep(retry).await;
                        retry = (retry * 2).min(QUEUE_RETRY_MAX);
                        continue;
                    }
                    // Given up: its reply becomes the plain sentence, and the
                    // loop goes on until Colin has it.
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            "odind: conversation-wake abandoned kind={:?} error={error}",
                            wake.kind
                        );
                        root.abandon_wake(&wake).await;
                        retries = 0;
                        tokio::time::sleep(retry).await;
                        continue;
                    }
                }
                break;
            }
        });
        background.insert(key, handle);
        true
    }

    fn wake_notice(&self, wake: &PendingWake) -> String {
        if wake.approved {
            format!(
                "[host] The owner approved your request ({}). Re-issue the EXACT same call now \
                 with unchanged arguments \u{2014} the approval is consumed exactly once. When \
                 the result is back, report it to the owner in plain words.",
                wake.label
            )
        } else {
            let note = wake
                .owner_note
                .as_deref()
                .map(|note| {
                    format!(" With it he said: \u{201c}{note}\u{201d} \u{2014} act on that.")
                })
                .unwrap_or_default();
            format!(
                "[host] The owner DECLINED your request ({}). Do not retry it.{note} Briefly \
                 tell the owner how this affects the plan and continue naturally.",
                wake.label
            )
        }
    }

    /// Runs one durable wake plan. LiveContinuation is observe-ONLY: the
    /// child continues on its own after the decision, so injecting a
    /// prompt could duplicate an operation that already ran. KernelRetry
    /// may prompt — only when the durable history proves the approved
    /// operation has not produced any continuation since the decision.
    pub(super) async fn run_wake(&self, requested: &PendingWake) -> Result<WakeProgress, String> {
        // Durable completion is owed first, independent of current history.
        {
            let _guard = self.lock.lock().await;
            let mut record = self.load_record()?;
            if let Some(mut wake) = record
                .wakes
                .iter()
                .find(|wake| wake.command_id == requested.command_id)
                .cloned()
            {
                if let Some(progress) = self.replay_wake_completion(&wake) {
                    return Ok(progress);
                }
                if wake.reply.is_some() {
                    return self.deliver_wake_reply(&mut record, &mut wake, None);
                }
            }
        }
        match requested.kind {
            WakeKind::LateAnswer => return self.run_late_answer(requested).await,
            WakeKind::QueuedAsks => return self.run_queued(requested).await,
            WakeKind::LiveContinuation | WakeKind::KernelRetry => {}
        }
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        let Some(mut wake) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == requested.command_id)
            .cloned()
        else {
            return Ok(WakeProgress::Complete);
        };
        if wake.kind == WakeKind::LiveContinuation {
            match self.native_decision_status(&wake).await? {
                NativeDecisionStatus::Unresolved => return Ok(WakeProgress::Pending),
                NativeDecisionStatus::Failed(_) => return Ok(WakeProgress::Complete),
                NativeDecisionStatus::Resolved => {}
            }
        }
        if wake.reply.is_some() {
            return self.deliver_wake_reply(&mut record, &mut wake, None);
        }
        let session_id = LiveSessionId::parse(&wake.session_id)
            .map_err(|error| format!("wake session invalid: {error}"))?;
        let mut consumed = false;
        if wake.kind == WakeKind::KernelRetry {
            let approval_id = wake
                .approval_id
                .as_deref()
                .ok_or_else(|| "kernel continuation lacks its approval identity".to_owned())?;
            match self.approvals.approval_status(approval_id).await? {
                Some(odin_domain::ApprovalStatus::Approved) if wake.approved => {}
                Some(odin_domain::ApprovalStatus::Consumed) if wake.approved => consumed = true,
                Some(odin_domain::ApprovalStatus::Denied) if !wake.approved => {}
                _ => {
                    // Matching decisions hold this same lock through commit,
                    // refusal or cancellation. Requested owes no continuation;
                    // expired/missing or opposite decisions owe none either.
                    // Retire before releasing the lock: rollover must not
                    // rebind a completed plan beyond its old tracker's id.
                    record
                        .wakes
                        .retain(|stored| stored.command_id != wake.command_id);
                    self.store_record(&mut record)?;
                    return Ok(WakeProgress::Retired);
                }
            }
        }
        let mut summary = self
            .resolve_vehicle(&mut record)
            .await
            .map_err(|error| error.to_string())?;
        let (cursor, turn) = if wake.kind == WakeKind::KernelRetry {
            if wake.prompt.is_none() {
                // The original gate-error turn is not the approved continuation.
                // Wait for it to finish before admitting our distinct prompt.
                let deadline = tokio::time::Instant::now() + self.answer_bound;
                while summary.state != LiveSessionState::Idle {
                    if summary.state == LiveSessionState::Failed {
                        return Err(
                            "the conversation session failed; the continuation was not sent"
                                .to_owned(),
                        );
                    }
                    if summary.state == LiveSessionState::RequiresAction {
                        self.await_answer(session_id, EventSeq::new(wake.decision_cursor), None)
                            .await
                            .map_err(|error| error.to_string())?;
                        return Ok(WakeProgress::Pending);
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(IntentFailure::AnswerTimeout.to_string());
                    }
                    tokio::time::sleep(self.poll_interval).await;
                    let listed = self
                        .find_session(session_id, true)
                        .await
                        .map_err(|error| error.to_string())?;
                    if listed
                        .as_ref()
                        .is_some_and(|summary| summary.state == LiveSessionState::Failed)
                    {
                        return Err(
                            "the conversation session failed; the continuation was not sent"
                                .to_owned(),
                        );
                    }
                    summary = self
                        .resolve_vehicle(&mut record)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                let content = if consumed {
                    "[host] The approval has already been consumed. Do not repeat the action; \
                     check its recorded outcome and report what actually happened."
                        .to_owned()
                } else {
                    let mut notice = self.wake_notice(&wake);
                    // Successors need the exact journaled call rather than inferred arguments.
                    if wake.approved {
                        if let Some((tool, retry)) = match wake.approval_id.as_deref() {
                            Some(approval) => self.approvals.approved_call(approval).await,
                            None => None,
                        } {
                            notice.push_str(&format!(
                                " The approved call is exactly: {tool} {retry}"
                            ));
                        }
                    }
                    notice
                };
                wake.prompt = Some(InFlightPrompt {
                    idempotency_key: wake.command_id.clone(),
                    content,
                    command_id: wake.command_id.clone(),
                    session_id: wake.session_id.clone(),
                    kind: InFlightKind::Prompt,
                    expected_epoch: summary.epoch.get(),
                    event_cursor: summary.event_head.get(),
                    phase: InFlightPhase::Prepared,
                    clock: None,
                    asks: Vec::new(),
                });
                self.store_wake(&mut record, &wake)?;
            }
            let mut prompt = wake
                .prompt
                .clone()
                .ok_or_else(|| "missing durable wake prompt".to_owned())?;
            let cursor = self
                .submit_prompt(&mut record, &summary, &mut prompt)
                .await
                .map_err(|error| error.to_string())?;
            let turn = odin_domain::CommandId::new(&prompt.command_id)
                .map_err(|error| format!("wake command identity rejected: {error}"))?;
            wake.prompt = Some(prompt);
            (cursor, Some(turn))
        } else {
            (EventSeq::new(wake.decision_cursor), None)
        };
        match self
            .await_answer(session_id, cursor, turn.as_ref())
            .await
            .map_err(|error| error.to_string())?
        {
            AnswerWait::Answer(answer) => {
                // Polling may have persisted new questions; never overwrite them.
                record = self.load_record()?;
                self.deliver_wake_reply(&mut record, &mut wake, Some(answer))
            }
            AnswerWait::NeedsOwner => Ok(WakeProgress::Pending),
            // The continuation's own turn ended without a report: Colin
            // hears that plainly instead of the turn timing out.
            AnswerWait::Silent => {
                record = self.load_record()?;
                self.deliver_wake_reply(
                    &mut record,
                    &mut wake,
                    Some(crate::natural::natural_intent_failure(
                        &IntentFailure::SilentTurn,
                    )),
                )
            }
            AnswerWait::VehicleDown => Err(IntentFailure::VehicleLost.to_string()),
        }
    }

    /// Waits — WITHOUT the conversation lock, so Colin can keep talking —
    /// until the long turn stops running, then takes the lock to collect
    /// and deliver its answer through the durable reply path. Bounded by
    /// [`LATE_ANSWER_BOUND`]; a pending question is relayed by the normal
    /// answer wait and its decision path owns the continuation.
    async fn run_late_answer(&self, requested: &PendingWake) -> Result<WakeProgress, String> {
        let session_id = LiveSessionId::parse(&requested.session_id)
            .map_err(|error| format!("wake session invalid: {error}"))?;
        let deadline = tokio::time::Instant::now() + LATE_ANSWER_BOUND;
        loop {
            let summary = self
                .find_session(session_id, true)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "the late-answer session vanished".to_owned())?;
            match summary.state {
                LiveSessionState::Running | LiveSessionState::Starting
                    if tokio::time::Instant::now() < deadline =>
                {
                    let _ = tokio::time::timeout(
                        self.poll_interval.max(StdDuration::from_secs(5)),
                        self.plane.wait_for_history(session_id, summary.event_head),
                    )
                    .await;
                }
                LiveSessionState::Running | LiveSessionState::Starting => {
                    return Err("the turn is still running past the late-answer bound".to_owned())
                }
                LiveSessionState::Ended | LiveSessionState::Failed => {
                    // Colin was told it is coming: say it is not.
                    let _guard = self.lock.lock().await;
                    let mut record = self.load_record()?;
                    let Some(mut wake) = record
                        .wakes
                        .iter()
                        .find(|wake| wake.command_id == requested.command_id)
                        .cloned()
                    else {
                        return Ok(WakeProgress::Complete);
                    };
                    tracing::warn!(
                        session = %session_id,
                        "odin-hermes: late answer lost session={session_id} state={:?}",
                        summary.state
                    );
                    return self.deliver_wake_reply(
                        &mut record,
                        &mut wake,
                        Some(super::prompt::LATE_ANSWER_LOST.to_owned()),
                    );
                }
                _ => break,
            }
        }
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        let Some(mut wake) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == requested.command_id)
            .cloned()
        else {
            return Ok(WakeProgress::Complete);
        };
        if wake.reply.is_some() {
            return self.deliver_wake_reply(&mut record, &mut wake, None);
        }
        match self
            .await_answer(session_id, EventSeq::new(wake.decision_cursor), None)
            .await
            .map_err(|error| error.to_string())?
        {
            AnswerWait::Answer(answer) => {
                record = self.load_record()?;
                self.deliver_wake_reply(&mut record, &mut wake, Some(answer))
            }
            AnswerWait::NeedsOwner => Ok(WakeProgress::Complete),
            // Unbound waits never report Silent; named, not folded.
            AnswerWait::Silent => Err("the late turn ended without a reply".to_owned()),
            AnswerWait::VehicleDown => Err(IntentFailure::VehicleLost.to_string()),
        }
    }

    fn store_wake(
        &self,
        record: &mut ConversationRecord,
        wake: &PendingWake,
    ) -> Result<(), String> {
        let current = record
            .wakes
            .iter_mut()
            .find(|plan| plan.command_id == wake.command_id)
            .ok_or_else(|| "continuation has no durable owner".to_owned())?;
        *current = wake.clone();
        self.store_record(record)
    }

    /// A handoff receipt was persisted only after durable question delivery.
    /// Replaying it never re-checks decidability or sends another question.
    pub(super) fn replay_wake_completion(&self, wake: &PendingWake) -> Option<WakeProgress> {
        let outcome = match wake.completion? {
            super::WakeCompletion::NeedsOwner => "needs_owner",
        };
        if let Some(prompt) = &wake.prompt {
            for ask in &prompt.asks {
                tracing::info!(
                    "odind: conversation-turn key={} unprompted=false queued=true outcome={outcome}",
                    ask.idempotency_key,
                );
            }
        }
        Some(WakeProgress::Complete)
    }

    /// The lifecycle reply is a cache; only the durable delivery owns retry state.
    pub(super) fn deliver_wake_reply(
        &self,
        record: &mut ConversationRecord,
        wake: &mut PendingWake,
        answer: Option<String>,
    ) -> Result<WakeProgress, String> {
        if wake.kind == WakeKind::QueuedAsks && wake.owner_keys.is_empty() {
            if let Some(prompt) = &wake.prompt {
                wake.owner_keys = prompt
                    .asks
                    .iter()
                    .map(|ask| ask.idempotency_key.clone())
                    .collect();
                self.store_wake(record, wake)?;
            }
        }
        if wake.reply.is_none() {
            wake.reply = Some(ContinuationReply {
                answer: answer.ok_or_else(|| "continuation result is missing".to_owned())?,
                delivered: None,
                terminal_outcome: None,
            });
            self.store_wake(record, wake)?;
        }
        let reply = wake
            .reply
            .as_ref()
            .ok_or_else(|| "continuation result is missing".to_owned())?;
        let key = if wake.kind == WakeKind::LateAnswer {
            wake.owner_keys.first().unwrap_or(&wake.command_id).clone()
        } else {
            wake.command_id.clone()
        };
        let key = key.as_str();
        let direct = super::prompt::owes_direct_reply(wake);
        let mut projection = serde_json::json!({
            "conversationId": self.conversation_id,
            "seat": self.binding.seat_id.as_str(),
            "project": self.project.as_str(),
            "session": wake.session_id,
            "commandId": wake.command_id,
            "idempotencyKey": key,
            "answer": reply.answer,
            "waitingOnApproval": false,
            "replySent": false,
        });
        if wake.kind == WakeKind::QueuedAsks {
            projection["queued"] = serde_json::Value::Bool(true);
        }
        if let Err(error) = self
            .reply_delivery(key, Some(&reply.answer), Some(&projection))
            .and_then(|_| self.link_delivery_keys(key, &wake.owner_keys))
            .and_then(|_| self.deliver_final(key, &reply.answer, Some(&projection)))
        {
            tracing::warn!(key = %key, error = %error, "odind: conversation-wake delivery_blocked key={key} error={error}");
            // A direct reply in doubt grants no further attempts: its
            // reservation stays durable and visible, and only this owner
            // retires, undelivered, so nothing queued waits behind it.
            if direct
                && matches!(
                    self.reply_disposition(key),
                    Ok(super::delivery::ReplyDisposition::Unknown)
                )
            {
                tracing::warn!(
                    key = %key,
                    "odind: conversation-wake direct_reply_retired key={key} outcome=unknown"
                );
                return Ok(WakeProgress::Complete);
            }
            return Err(format!("continuation reply was not delivered: {error}"));
        }
        if let Some(reply) = wake.reply.as_mut() {
            reply.delivered = Some(true);
        }
        // The turn's cached result follows its canonical committed row.
        if direct && record.last_idempotency_key.as_deref() == Some(key) {
            if let Ok(Some(settled)) = self.replay_delivery(key) {
                record.last_projection = Some(settled);
            }
        }
        self.store_wake(record, wake)?;
        // Stored-reply retries bypass answer_queued; report completion here only
        // after delivery is durable, including receipt replay after a restart.
        if wake.kind == WakeKind::QueuedAsks {
            if let Some(prompt) = &wake.prompt {
                let outcome = wake
                    .reply
                    .as_ref()
                    .and_then(|reply| reply.terminal_outcome.as_deref())
                    .unwrap_or("unknown");
                for ask in &prompt.asks {
                    tracing::info!(
                        "odind: conversation-turn key={} unprompted=false queued=true outcome={outcome}",
                        ask.idempotency_key,
                    );
                }
            }
        }
        Ok(WakeProgress::Complete)
    }

    /// Refuses new wake continuations without waiting for the task registry.
    pub fn close_background(&self) {
        self.closing
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Joins the owned wake continuations under a bounded grace, aborting
    /// stragglers — shutdown never hangs on an approval wait.
    pub async fn join_background(&self, grace: StdDuration) {
        self.join_background_until(tokio::time::Instant::now() + grace)
            .await;
    }

    /// Joins the owned wake continuations under the CALLER's absolute
    /// deadline — the daemon's ONE shared shutdown deadline, not a private
    /// grace — aborting stragglers, and reports how many handles ended
    /// inside their remaining budget versus were aborted. The wait for each
    /// handle is bounded by that deadline's remainder; nothing here waits
    /// unboundedly.
    pub async fn join_background_until(&self, deadline: tokio::time::Instant) -> (usize, usize) {
        self.close_background();
        let Ok(mut background) = tokio::time::timeout_at(deadline, self.background.lock()).await
        else {
            // The registry owner may still be admitting an already-started wake.
            // Its unavailable handles cannot be claimed joined or cancelled.
            return (0, 1);
        };
        let handles = std::mem::take(&mut *background);
        drop(background);
        let mut joined = 0;
        let mut aborted = 0;
        for mut handle in handles.into_values() {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                handle.abort();
                aborted += 1;
                continue;
            }
            if tokio::time::timeout(remaining, &mut handle).await.is_err() {
                handle.abort();
                aborted += 1;
            } else {
                joined += 1;
            }
        }
        (joined, aborted)
    }

    /// Resumes the durable wake plans at startup. Each plan verifies its
    /// own durable decision before acting; a decision that never landed
    /// drops the plan and the question stays open and re-askable.
    pub(super) async fn resume_wakes(&self, record: &ConversationRecord) {
        for wake in record.wakes.clone() {
            self.spawn_wake_task(wake).await;
        }
    }

    /// Admission is not application. Only the exact durable native
    /// resolution proves that the child received this decision.
    async fn native_decision_status(
        &self,
        plan: &PendingWake,
    ) -> Result<NativeDecisionStatus, String> {
        let session_id =
            LiveSessionId::parse(&plan.session_id).map_err(|error| error.to_string())?;
        let mut cursor = EventSeq::new(plan.decision_cursor);
        let mut horizon = None;
        loop {
            let page = self
                .plane
                .history(HistoryQuery {
                    session_id,
                    after: cursor,
                    limit: page_limit(),
                })
                .await
                .map_err(|error| error.to_string())?;
            let head = *horizon.get_or_insert(page.head);
            let previous = cursor;
            for event in page.events {
                if event.sequence > head {
                    break;
                }
                cursor = event.sequence;
                match event.body {
                    odin_domain::huginn::LiveEventBody::PermissionResolved(resolution)
                        if resolution.command_id.as_str() == plan.command_id =>
                    {
                        if (resolution.decision == PermissionDecision::AllowOnce) != plan.approved {
                            return Err(
                                "native resolution disagrees with the recorded decision".to_owned()
                            );
                        }
                        return Ok(NativeDecisionStatus::Resolved);
                    }
                    odin_domain::huginn::LiveEventBody::ControlCompleted(
                        odin_domain::huginn::CommandOutcome::Failed { command_id, error },
                    ) if command_id.as_str() == plan.command_id => {
                        return Ok(NativeDecisionStatus::Failed(error.message));
                    }
                    _ => {}
                }
            }
            if cursor >= head {
                return Ok(NativeDecisionStatus::Unresolved);
            }
            if cursor <= previous {
                return Err(IntentFailure::HistoryUnavailable.to_string());
            }
        }
    }

    /// Settles a wake that cannot finish: its reply becomes one plain
    /// sentence that nothing more came of it, stored before it is sent, so
    /// the wake leaves only once Colin has it.
    async fn abandon_wake(&self, plan: &PendingWake) {
        let _guard = self.lock.lock().await;
        let Ok(mut record) = self.load_record() else {
            return;
        };
        let Some(mut wake) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == plan.command_id)
            .cloned()
        else {
            return;
        };
        if wake.reply.is_some() || wake.completion.is_some() {
            return;
        }
        let answer = match plan.kind {
            WakeKind::KernelRetry | WakeKind::LiveContinuation => format!(
                "I couldn't carry on after your answer about {}, so nothing more was done \
                 \u{2014} ask me again if you still want it.",
                plan.label
            ),
            WakeKind::LateAnswer | WakeKind::QueuedAsks => {
                super::prompt::LATE_ANSWER_LOST.to_owned()
            }
        };
        wake.reply = Some(ContinuationReply {
            answer,
            delivered: None,
            terminal_outcome: None,
        });
        if let Err(error) = self.store_wake(&mut record, &wake) {
            tracing::error!(error = %error, "odind: conversation-wake abandon_unpersisted error={error}");
        }
    }

    fn drop_wake(&self, plan: &PendingWake) -> Result<(), String> {
        let target = plan.command_id.clone();
        let mut record = self.load_record()?;
        record.wakes.retain(|wake| wake.command_id != target);
        for question in &mut record.questions {
            if question.decision_command_id.as_deref() == Some(target.as_str()) {
                question.decision_command_id = None;
            }
        }
        self.store_record(&mut record)
    }

    /// Decides one delivered live permission question on the EXACT
    /// session it was asked on. Freshness is re-proven against the
    /// durable history (a replaced or resolved request refuses), the
    /// decision-wake plan is persisted BEFORE the decision command, and
    /// the wake itself is observe-only.
    async fn decide_live_question(
        &self,
        record: &mut ConversationRecord,
        question: &DeliveredQuestion,
        decision: PermissionDecision,
        reply_id: &str,
    ) -> Result<Option<String>, String> {
        let session_id = LiveSessionId::parse(&question.session_id)
            .map_err(|error| format!("the delivered question's session is invalid: {error}"))?;
        let summary = self
            .resolve_vehicle(record)
            .await
            .map_err(|failure| match failure {
                IntentFailure::ConversationClosed => {
                    "The conversation that asked has since closed, so nothing was authorized."
                        .to_owned()
                }
                other => other.to_string(),
            })?;
        if question.session_epoch != Some(summary.epoch.get()) {
            return Ok(Some(
                "The session that asked was replaced; nothing was authorized.".to_owned(),
            ));
        }
        if summary.session_id != session_id {
            return Ok(Some(
                "The conversation that asked has since closed, so nothing was authorized."
                    .to_owned(),
            ));
        }
        let pending = self
            .session_pending_requests(session_id, summary.epoch)
            .await
            .map_err(|failure| failure.to_string())?;
        if !pending.contains(&question.request_id) {
            if let Some(stored) = record.questions.iter_mut().find(|stored| {
                stored.request_id == question.request_id
                    && stored.session_epoch == question.session_epoch
            }) {
                stored.settled = true;
            }
            self.store_record(record)?;
            return Ok(Some(
                "That question has already settled, so nothing was changed.".to_owned(),
            ));
        }
        let request_id = PermissionRequestId::parse(&question.request_id)
            .map_err(|error| format!("the delivered request identity is invalid: {error}"))?;
        let approved = decision == PermissionDecision::AllowOnce;
        let plan = if let Some(command_id) = question.decision_command_id.as_deref() {
            let previous = record
                .wakes
                .iter()
                .find(|wake| wake.command_id == command_id)
                .cloned()
                .ok_or_else(|| {
                    "the prior decision is missing its durable continuation".to_owned()
                })?;
            if previous.approved != approved {
                return Err("The previous decision still owns this question; its outcome must be resolved first.".to_owned());
            }
            previous
        } else {
            let command_id = bounded_command(
                "permission",
                &[
                    &question.session_id,
                    &summary.epoch.get().to_string(),
                    &question.request_id,
                    reply_id,
                ],
            )
            .map_err(|error| format!("permission command identity rejected: {error}"))?;
            PendingWake {
                command_id: command_id.to_string(),
                owner_keys: Vec::new(),
                kind: WakeKind::LiveContinuation,
                approved,
                label: question.prompt.clone(),
                session_id: session_id.to_string(),
                decision_cursor: summary.event_head.get(),
                approval_id: None,
                prompt: None,
                reply: None,
                completion: None,
                owner_note: None,
                rolled: false,
            }
        };
        let command_id = CommandId::new(plan.command_id.clone())
            .map_err(|error| format!("permission command identity rejected: {error}"))?;
        let stored = record
            .questions
            .iter_mut()
            .find(|stored| {
                stored.request_id == question.request_id
                    && stored.session_epoch == question.session_epoch
            })
            .ok_or_else(|| "the delivered question is no longer recorded".to_owned())?;
        stored.decision_command_id = Some(plan.command_id.clone());
        record
            .wakes
            .retain(|wake| wake.command_id != plan.command_id);
        record.wakes.push(plan.clone());
        self.store_record(record)?;
        let command = LiveCommand {
            command_id,
            session_id,
            expected_epoch: summary.epoch,
            expected_event_head: None,
            body: LiveCommandBody::DecidePermission {
                request_id,
                decision,
            },
        };
        match self.plane.command(command).await {
            Ok(CommandReceipt::Accepted { .. }) | Ok(CommandReceipt::Duplicate { .. }) => {
                match self.native_decision_status(&plan).await? {
                    NativeDecisionStatus::Resolved => {}
                    NativeDecisionStatus::Unresolved => {
                        self.resume_wakes(record).await;
                        return Err(
                            "The decision was admitted, but its resolution is not yet known."
                                .to_owned(),
                        );
                    }
                    NativeDecisionStatus::Failed(error) => {
                        self.drop_wake(&plan)?;
                        return Err(format!(
                            "The controller reported a failed permission decision: {error}"
                        ));
                    }
                }
                if let Some(stored) = record.questions.iter_mut().find(|stored| {
                    stored.request_id == question.request_id
                        && stored.session_epoch == question.session_epoch
                }) {
                    stored.settled = true;
                }
                self.store_record(record)?;
                self.resume_wakes(record).await;
                Ok(Some(decision_ack(approved).to_owned()))
            }
            Ok(CommandReceipt::Rejected { reason, .. }) => {
                self.drop_wake(&plan)?;
                Ok(Some(format!(
                    "That question is no longer open on the conversation, so nothing was \
                     changed. ({reason:?})"
                )))
            }
            Err(error) => {
                self.resume_wakes(record).await;
                Err(format!(
                    "the permission decision's delivery is uncertain: {error}"
                ))
            }
        }
    }
}

impl ConversationRoot {
    /// Persists and starts the question's wake before deciding, holding the conversation
    /// lock until `decide` finishes so the wake observes its durable outcome.
    /// Unrelated decisions run outside the lock once question membership is known;
    /// unreadable state refuses. Returns `decide` unchanged; it must not re-enter this root.
    pub async fn decide_external<T: Send>(
        &self,
        approval_id: &str,
        approved: bool,
        decide: impl std::future::Future<Output = T> + Send,
    ) -> Result<T, String> {
        let guard = self.lock.lock().await;
        let Some((mut record, plan)) = self.external_plan(approval_id, approved).await? else {
            drop(guard);
            return Ok(decide.await);
        };
        self.own_requested_wake(&mut record, &plan).await?;
        let decided = decide.await;
        drop(guard);
        Ok(decided)
    }

    /// Both paired-device and DM decisions enter with the conversation lock
    /// held and this approval still Requested. Retire a previous same-id
    /// observer before replacing its plan: it may be waiting to drop that
    /// id after observing Requested, not merely waiting to read the status.
    async fn own_requested_wake(
        &self,
        record: &mut ConversationRecord,
        plan: &PendingWake,
    ) -> Result<(), String> {
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("the conversation runtime is stopping".to_owned());
        }
        // Cancellation while waiting for the registry creates no new plan.
        let mut background = self.background.lock().await;
        let prior_wakes = record.wakes.len();
        record
            .wakes
            .retain(|wake| wake.command_id != plan.command_id);
        if record.wakes.len() != prior_wakes {
            // Persist retirement before its await so cancellation cannot
            // leave an aborted observer's plan without an owner.
            self.store_record(record)?;
        }
        Self::retire_wake_task(&mut background, &plan.command_id).await?;
        record.wakes.push(plan.clone());
        self.store_record(record)?;
        if !self.spawn_wake_task_owned(plan.clone(), &mut background) {
            self.drop_wake(plan)?;
            return Err("the conversation runtime is stopping".to_owned());
        }
        Ok(())
    }

    /// Retires the old tracker before replacement while holding the conversation lock
    /// and the approval is still requested. The tracker cannot be inside an effect;
    /// leaving it registered could skip the replacement or remove its fresh plan.
    async fn retire_wake_task(
        background: &mut std::collections::BTreeMap<String, tokio::task::JoinHandle<()>>,
        command_id: &str,
    ) -> Result<(), String> {
        // Retain the handle during join so caller cancellation cannot detach the tracker.
        let Some(tracker) = background.get_mut(command_id) else {
            return Ok(());
        };
        if !tracker.is_finished() {
            tracker.abort();
            if tokio::time::timeout(WAKE_RETIRE_BOUND, &mut *tracker)
                .await
                .is_err()
            {
                return Err(
                    "the previous continuation of this decision is still settling".to_owned(),
                );
            }
        }
        background.remove(command_id);
        Ok(())
    }

    /// The durable wake this conversation owes a decision on one of its
    /// delivered, still-open questions, with the record it joins; `None`
    /// when the approval is not one.
    async fn external_plan(
        &self,
        approval_id: &str,
        approved: bool,
    ) -> Result<Option<(ConversationRecord, PendingWake)>, String> {
        let record = self.load_record()?;
        let Some(session_raw) = record.session_id.clone() else {
            return Ok(None);
        };
        let session_id = LiveSessionId::parse(&session_raw)
            .map_err(|error| format!("conversation session is invalid: {error}"))?;
        let target = format!("run:live:{session_id}");
        let Some(approval) = self
            .approvals
            .delivered_pending(&self.owner.channel_id, &self.owner.owner_user_id, now_utc())
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|approval| {
                approval.session == target && approval.approval_id.as_str() == approval_id
            })
        else {
            return Ok(None);
        };
        let summary = self
            .find_session(session_id, true)
            .await
            .map_err(|error| format!("conversation decision cursor is unavailable: {error}"))?
            .ok_or_else(|| "conversation decision has no durable session".to_owned())?;
        if summary.state == LiveSessionState::Ended {
            return Ok(None);
        }
        let plan = PendingWake {
            command_id: bounded_command(
                "conversation-wake",
                &[&approval.approval_id.to_string(), decision_word(approved)],
            )
            .map_err(|error| format!("wake command identity rejected: {error}"))?
            .to_string(),
            owner_keys: Vec::new(),
            kind: WakeKind::KernelRetry,
            approved,
            label: approval.label.clone(),
            session_id: session_id.to_string(),
            decision_cursor: summary.event_head.get(),
            approval_id: Some(approval.approval_id.to_string()),
            prompt: None,
            reply: None,
            completion: None,
            owner_note: None,
            rolled: false,
        };
        Ok(Some((record, plan)))
    }
}

#[async_trait]
impl OwnerDecisionRoute for ConversationRoot {
    /// Interprets one authenticated paired-owner DM as a whole-message
    /// decision ([`crate::natural`] owns the language). Kernel approvals
    /// decide first through their delivery proofs; live permission
    /// receipts are freshness-validated against the durable history
    /// BEFORE cardinality; undelivered or superseded questions refuse
    /// with one plain sentence and authorize nothing. `Ok(None)` leaves
    /// the message an ordinary intent.
    async fn try_decision(
        &self,
        message: AuthenticatedOwnerMessage,
    ) -> Result<Option<String>, String> {
        if message.owner_user_id != self.owner.owner_user_id
            || message.channel_id != self.owner.channel_id
            || message.seat != self.binding.seat_id
            || message.project != self.project
        {
            return Ok(None);
        }
        let parsed_decision = parse_whole_message_decision(&message.content);
        let owner_note = parse_leading_denial(&message.content);
        if parsed_decision.is_none() && !crate::natural::opens_decisionish(&message.content) {
            return Ok(None);
        }
        // Decision-like new requests leave questions open; only a framed answer
        // such as "yes to the laptop" selects a pending question.
        let named_decision = crate::natural::parse_named_decision(&message.content);
        let framed = crate::natural::is_framed_decision(&message.content);
        if parsed_decision.is_none() && owner_note.is_none() && named_decision.is_some() && !framed
        {
            return Ok(None);
        }
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("the conversation runtime is stopping".to_owned());
        }
        let Some(session_raw) = record.session_id.as_deref() else {
            return Ok(None);
        };
        let session_id = LiveSessionId::parse(session_raw)
            .map_err(|error| format!("conversation session is invalid: {error}"))?;
        let session_key = session_id.to_string();
        let target = format!("run:live:{session_id}");
        let now = now_utc();
        // Kernel R3 approvals first — their durable delivery proofs are
        // the receipt; this is conversation-scoped, never a global scan.
        let mut kernel = self
            .approvals
            .delivered_pending(&self.owner.channel_id, &self.owner.owner_user_id, now)
            .await
            .map_err(|error| error.to_string())?;
        kernel.retain(|approval| approval.session == target);
        // Live candidates, freshness-validated against the durable
        // history BEFORE any cardinality rule: a stale receipt is marked
        // settled, never counted.
        let mut live: Vec<DeliveredQuestion> = record
            .questions
            .iter()
            .filter(|question| {
                question.session_id == session_key && self.is_decidable_receipt(question)
            })
            .cloned()
            .collect();
        if !live.is_empty() {
            let current = self
                .find_session(session_id, true)
                .await
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "the question's session no longer exists".to_owned())?;
            let pending = self
                .session_pending_requests(session_id, current.epoch)
                .await
                .map_err(|failure| failure.to_string())?;
            let mut changed = false;
            live.retain(|question| {
                let open = question.session_epoch == Some(current.epoch.get())
                    && pending.contains(&question.request_id);
                if !open {
                    if let Some(stored) = record.questions.iter_mut().find(|stored| {
                        stored.request_id == question.request_id
                            && stored.session_epoch == question.session_epoch
                    }) {
                        stored.settled = true;
                        changed = true;
                    }
                }
                open
            });
            if changed {
                self.store_record(&mut record)?;
            }
        }
        // Several open: a reply that names exactly one of them decides that
        // one ("no to the calendar one"); anything else asks which.
        let mut parsed_decision = parsed_decision;
        let mut owner_note = owner_note;
        if kernel.len() + live.len() > 1
            && live.is_empty()
            && crate::natural::denies_every_question(&message.content)
        {
            // "no to both": every open question is declined; his words are
            // not an instruction for any one of them.
            parsed_decision = Some(OwnerDecision::Deny);
            owner_note = None;
        } else if kernel.len() + live.len() > 1 || (framed && kernel.len() + live.len() == 1) {
            let Some((named, terms)) = named_decision else {
                return Ok(Some(MULTIPLE_QUESTIONS_SENTENCE.to_owned()));
            };
            // Only a whole-message designation decides: "yes to the laptop
            // sleeve" or "yes to the laptop, but only if under $100" names
            // the question AND says something it does not, so it stays open
            // and his words are an ordinary message.
            let kernel_texts: Vec<String> = kernel
                .iter()
                .map(|approval| {
                    format!(
                        "{} {}",
                        approval.label,
                        approval.detail.as_deref().unwrap_or_default()
                    )
                })
                .collect();
            let designations: Vec<Designation> = kernel_texts
                .iter()
                .map(String::as_str)
                .chain(live.iter().map(|question| question.prompt.as_str()))
                .map(|text| crate::natural::designation(&terms, text))
                .collect();
            let touched = designations
                .iter()
                .filter(|designation| **designation != Designation::Untouched)
                .count();
            if touched > 1 {
                return Ok(Some(MULTIPLE_QUESTIONS_SENTENCE.to_owned()));
            }
            let Some(chosen) = designations
                .iter()
                .position(|designation| *designation == Designation::Whole)
            else {
                return Ok(None);
            };
            // "yes to the laptop under $500" against "…under $1,500 with a
            // $500 deposit?", or "yes to one laptop" against "Buy two
            // laptops with one charger?": a quantity in a yes may set a new
            // limit that only happens to appear in the question. It decides
            // nothing; he is asked the plain yes/no again.
            if named == OwnerDecision::AllowOnce
                && crate::natural::states_a_quantity(&message.content)
            {
                tracing::warn!(
                    "odind: conversation-decision reasked reason=quantity conversation={}",
                    self.conversation_id
                );
                return Ok(Some(if chosen < kernel.len() {
                    crate::natural::approval_question(
                        &kernel[chosen].label,
                        kernel[chosen].detail.as_deref(),
                    )
                } else {
                    live[chosen - kernel.len()].prompt.clone()
                }));
            }
            if chosen < kernel.len() {
                kernel = vec![kernel.swap_remove(chosen)];
                live.clear();
            } else {
                live = vec![live.swap_remove(chosen - kernel.len())];
                kernel.clear();
            }
            parsed_decision = Some(named);
        }
        // A punctuated denial with an instruction decides a KERNEL approval
        // (its declined turn carries his words); a live question has no
        // declined turn to carry them, so it keeps asking.
        let parsed_decision = parsed_decision.or_else(|| {
            (owner_note.is_some() && !kernel.is_empty()).then_some(OwnerDecision::Deny)
        });
        let Some(natural_decision) = parsed_decision else {
            return Ok(kernel
                .first()
                .map(|approval| {
                    crate::natural::approval_question(&approval.label, approval.detail.as_deref())
                })
                .or_else(|| live.first().map(|question| question.prompt.clone())));
        };
        let decision = match natural_decision {
            OwnerDecision::AllowOnce => PermissionDecision::AllowOnce,
            OwnerDecision::Deny => PermissionDecision::Deny,
        };
        if !kernel.is_empty() {
            let approved = decision == PermissionDecision::AllowOnce;
            // The wake plan is durable BEFORE the decision: a crash after
            // decide replays it, keyed by approval plus decision.
            // The decision-time cursor: the vehicle's current head BEFORE
            // the decision is recorded, so the wake observes exactly the
            // continuation window of this decision — never cursor zero,
            // never a stale historical reply.
            let summary = self
                .find_session(session_id, true)
                .await
                .map_err(|error| format!("conversation decision cursor is unavailable: {error}"))?
                .ok_or_else(|| "conversation decision has no durable session".to_owned())?;
            if summary.state == LiveSessionState::Ended {
                return Ok(Some(
                    "That conversation has closed, so nothing was authorized.".to_owned(),
                ));
            }
            let decision_cursor = summary.event_head.get();
            // One question, or every one on "no to both": each gets its own
            // durable wake before its decision; the first that fails stops.
            for approval in &kernel {
                let plan = PendingWake {
                    command_id: bounded_command(
                        "conversation-wake",
                        &[&approval.approval_id.to_string(), decision_word(approved)],
                    )
                    .map_err(|error| format!("wake command identity rejected: {error}"))?
                    .to_string(),
                    owner_keys: Vec::new(),
                    kind: WakeKind::KernelRetry,
                    approved,
                    label: approval.label.clone(),
                    session_id: session_key.clone(),
                    decision_cursor,
                    approval_id: Some(approval.approval_id.to_string()),
                    prompt: None,
                    reply: None,
                    completion: None,
                    owner_note: owner_note.clone().filter(|_| !approved),
                    rolled: false,
                };
                self.own_requested_wake(&mut record, &plan).await?;
                let outcome = self
                    .approvals
                    .decide_delivered(&message, approval, natural_decision, now)
                    .await;
                match outcome {
                    Ok(Some(KernelDecisionOutcome::Approved))
                    | Ok(Some(KernelDecisionOutcome::Denied)) => {
                        self.resume_wakes(&record).await;
                    }
                    Ok(Some(KernelDecisionOutcome::NotSettled)) | Ok(None) => {
                        self.drop_wake(&plan)?;
                        return Ok(Some(
                            "That decision did not settle, so nothing was changed. Say it again \
                         and I'll pass it on."
                                .to_owned(),
                        ));
                    }
                    Err(refusal) => {
                        self.drop_wake(&plan)?;
                        return Ok(Some(kernel_refusal_sentence(&refusal)));
                    }
                }
                record = self.load_record()?;
            }
            return Ok(Some(decision_ack(approved).to_owned()));
        }
        if let Some(question) = live.first() {
            let follows = question
                .delivered_message_id
                .as_deref()
                .is_some_and(|sent| {
                    crate::discord::transport_message_order(&message.message_id, sent)
                        == Some(std::cmp::Ordering::Greater)
                });
            if !follows {
                return Ok(Some(
                    "Your reply cannot be proven to follow this question; nothing was authorized."
                        .to_owned(),
                ));
            }
            return self
                .decide_live_question(&mut record, question, decision, &message.message_id)
                .await;
        }
        // Missing delivery proof refuses; old stored text is not evidence
        // that this owner received a question in the current generation.
        let undelivered = record.questions.iter().any(|question| {
            question.delivered_message_id.is_none()
                && !question.settled
                && question.owner_user_id == self.owner.owner_user_id
                && question.channel_id == self.owner.channel_id
                && question.expires_at_unix_ms > now_unix_ms()
        });
        if undelivered {
            return Ok(Some(
                "I don't have a valid delivery receipt for that request, so nothing was \
                 authorized. It needs a fresh question."
                    .to_owned(),
            ));
        }
        if record.questions.iter().any(|question| {
            question.session_id == session_key
                && question.owner_user_id == self.owner.owner_user_id
                && question.channel_id == self.owner.channel_id
                && question.delivered_message_id.is_some()
                && question.settled
        }) {
            return Ok(Some(
                "That request is no longer open, so nothing was authorized.".to_owned(),
            ));
        }
        Ok(None)
    }
}
