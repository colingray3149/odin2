//! Decisions require delivered open questions and persist their wake before deciding.
//! Wakes resume from durable history and are cleared only after completion.

use std::time::Duration as StdDuration;

use async_trait::async_trait;
use odin_domain::huginn::{
    CommandReceipt, EventSeq, HistoryQuery, LiveCommand, LiveCommandBody, LiveSessionId,
    LiveSessionState, PermissionDecision, PermissionRequestId,
};
use odin_domain::CommandId;
use time::OffsetDateTime;

use crate::natural::{parse_owner_answer, OwnerAnswer, OwnerDecision};
use crate::runtime::{
    AuthenticatedOwnerMessage, DecisionRefusal, DeliveredApproval, IntentFailure,
    OwnerDecisionRoute,
};

use super::history::page_limit;
use super::history::AnswerWait;
use super::identity::{bounded_command, now_unix_ms};
use super::KernelDecisionOutcome;
use super::{
    ContinuationReply, ConversationRecord, ConversationRoot, DeliveredQuestion, InFlightKind,
    InFlightPhase, InFlightPrompt, PendingWake, WakeKind,
};

/// How long a late answer is awaited before its wake gives up.
pub(super) const LATE_ANSWER_BOUND: StdDuration = StdDuration::from_secs(45 * 60);
/// A wake retries a failed pass after this, doubling to the max.
const WAKE_RETRY_FIRST: StdDuration = StdDuration::from_secs(30);
const WAKE_RETRY_MAX: StdDuration = StdDuration::from_secs(10 * 60);
/// Why a continuation was dropped when its session failed.
pub(super) const CONTINUATION_SESSION_FAILED: &str =
    "the conversation session failed; the continuation was not sent";
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
        DecisionRefusal::PredatesDelivery(_) => {
            "I can't safely match that reply to the question. Please answer it again.".to_owned()
        }
        DecisionRefusal::NotOpen(_) => {
            "That question has already settled, so nothing was changed.".to_owned()
        }
        DecisionRefusal::Expired(_) => {
            "That question expired before your reply, so nothing was authorized.".to_owned()
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

/// A bare yes or no decides only when exactly one question is open; with several, the owner names
/// the one he means by its number ("yes 2"). Returns the open questions with the chosen one first
/// and the note his answer still carries, or the sentence that lists them.
fn choose_open(
    open: &[DeliveredApproval],
    live_count: usize,
    note: Option<String>,
) -> Result<(Vec<DeliveredApproval>, Option<String>), String> {
    if live_count > 0 && open.len() + live_count > 1 {
        return Err(
            "Several questions are waiting, so I did not decide any. Use the button on the question you mean."
                .to_owned(),
        );
    }
    if open.len() <= 1 {
        return Ok((open.to_vec(), note));
    }
    let picked = note
        .as_deref()
        .and_then(|note| note.trim().trim_start_matches('#').parse::<usize>().ok())
        .filter(|number| (1..=open.len()).contains(number));
    if let Some(number) = picked {
        let mut ordered = vec![open[number - 1].clone()];
        ordered.extend(
            open.iter()
                .enumerate()
                .filter(|(index, _)| *index != number - 1)
                .map(|(_, approval)| approval.clone()),
        );
        return Ok((ordered, None));
    }
    let mut sentence = format!(
        "{} questions are waiting, so I did not decide any. Say \u{201c}yes 1\u{201d} or \
         \u{201c}no 2\u{201d} for the one you mean:",
        open.len()
    );
    for (index, approval) in open.iter().enumerate() {
        sentence.push_str(&format!("\n{}. {}", index + 1, approval.label));
    }
    Err(sentence)
}

const HEDGED_YES_SENTENCE: &str =
    "I read that as more than a yes, so I did not approve anything. Say just \u{201c}yes\u{201d} \
     to approve it as asked, or \u{201c}no\u{201d}.";

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
        // reads it as "ran, now waiting on the owner", never as unspawned.
        if background.len() > FINISHED_WAKES_KEPT {
            // An unreadable record forgets nothing: its plans are unknown.
            if let Ok(record) = self.load_record() {
                let planned: std::collections::BTreeSet<String> = record
                    .wakes
                    .into_iter()
                    .map(|plan| plan.command_id)
                    .collect();
                background.retain(|id, handle| !handle.is_finished() || planned.contains(id));
            }
        }
        if background
            .get(&wake.command_id)
            .is_some_and(|handle| !handle.is_finished())
        {
            return true;
        }
        let key = wake.command_id.clone();
        let handle = self.handle.spawn(async move {
            let mut retry = WAKE_RETRY_FIRST;
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
                    // the owner's queued messages never wait on a later message
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
                        retry = (retry * 2).min(WAKE_RETRY_MAX);
                        continue;
                    }
                    // Given up: its reply becomes the plain sentence, and the
                    // loop goes on until the owner has it.
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
        let note = wake
            .owner_note
            .as_deref()
            .map(|note| format!(" With it he said: \u{201c}{note}\u{201d} \u{2014} act on that."))
            .unwrap_or_default();
        if wake.approved {
            format!(
                "[host] The owner approved your request ({}) and the host made the call for \
                 you: {}. Do not make it again.{note} Report the result to the owner in plain \
                 words.",
                wake.label,
                wake.outcome.as_deref().unwrap_or("it is running")
            )
        } else {
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
        if wake.kind == WakeKind::KernelRetry {
            let approval_id = wake
                .approval_id
                .as_deref()
                .ok_or_else(|| "kernel continuation lacks its approval identity".to_owned())?;
            match self.approvals.approval_status(approval_id).await? {
                // The host ran the approved call, so the row is Consumed (or Approved when
                // the call could not start); either way the seat is owed the outcome.
                Some(
                    odin_domain::ApprovalStatus::Approved | odin_domain::ApprovalStatus::Consumed,
                ) if wake.approved => {}
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
                        return Err(CONTINUATION_SESSION_FAILED.to_owned());
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
                        return Err(CONTINUATION_SESSION_FAILED.to_owned());
                    }
                    summary = self
                        .resolve_vehicle(&mut record)
                        .await
                        .map_err(|error| error.to_string())?;
                }
                let content = self.wake_notice(&wake);
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
                    brief: None,
                    owner: false,
                    unprompted: false,
                    asks: Vec::new(),
                    harness: Vec::new(),
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
        let waited = match self.await_answer(session_id, cursor, turn.as_ref()).await {
            Err(stalled @ IntentFailure::LaneStalled { .. }) => {
                return self.deliver_stalled_lane(&mut wake, &stalled);
            }
            other => other.map_err(|error| error.to_string())?,
        };
        match waited {
            AnswerWait::Answer(answer) => {
                // Polling may have persisted new questions; never overwrite them.
                record = self.load_record()?;
                self.deliver_wake_reply(&mut record, &mut wake, Some(answer))
            }
            // The continuation asked again: this wake still owns its reply.
            AnswerWait::NeedsOwner(asked) => {
                self.hold_reply(None, &asked)?;
                Ok(WakeProgress::Pending)
            }
            // The continuation's own turn ended without a report: the owner
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

    /// A wake's turn lost its quiet lane and is not sent again: the owner hears which lane went
    /// quiet and which took over, as the wake's reply.
    pub(super) fn deliver_stalled_lane(
        &self,
        wake: &mut PendingWake,
        stalled: &IntentFailure,
    ) -> Result<WakeProgress, String> {
        let mut record = self.load_record()?;
        self.deliver_wake_reply(
            &mut record,
            wake,
            Some(crate::natural::natural_intent_failure(stalled)),
        )
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
        let mut projection =
            self.settle_projection(&wake.session_id, &wake.command_id, key, &reply.answer);
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
                return Err(IntentFailure::history(format!(
                    "session {session_id} history did not advance past {} below head {}",
                    previous.get(),
                    head.get()
                ))
                .to_string());
            }
        }
    }

    /// Settles a wake that cannot finish: its reply becomes one plain
    /// sentence that nothing more came of it, stored before it is sent, so
    /// the wake leaves only once the owner has it.
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
                approved,
                label: question.prompt.clone(),
                ..PendingWake::new(
                    WakeKind::LiveContinuation,
                    command_id.to_string(),
                    session_id.to_string(),
                    summary.event_head.get(),
                )
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

/// The wake that tells a seat how the owner answered its approval and runs the call it held.
fn kernel_retry_wake(
    approval: &DeliveredApproval,
    approved: bool,
    session_id: &str,
    decision_cursor: u64,
) -> Result<PendingWake, String> {
    let command_id = bounded_command(
        "conversation-wake",
        &[&approval.approval_id.to_string(), decision_word(approved)],
    )
    .map_err(|error| format!("wake command identity rejected: {error}"))?;
    Ok(PendingWake {
        approved,
        label: approval.label.clone(),
        approval_id: Some(approval.approval_id.to_string()),
        ..PendingWake::new(
            WakeKind::KernelRetry,
            command_id.to_string(),
            session_id,
            decision_cursor,
        )
    })
}

impl ConversationRoot {
    /// The wake this conversation's seat is owed when the owner answers its own question, or `None`
    /// when its conversation has already closed.
    async fn kernel_wake(
        &self,
        session_id: LiveSessionId,
        session_key: &str,
        approval: &DeliveredApproval,
        approved: bool,
        owner_note: Option<String>,
    ) -> Result<Option<PendingWake>, String> {
        let summary = self
            .find_session(session_id, true)
            .await
            .map_err(|error| format!("conversation decision cursor is unavailable: {error}"))?
            .ok_or_else(|| "conversation decision has no durable session".to_owned())?;
        if summary.state == LiveSessionState::Ended {
            return Ok(None);
        }
        Ok(Some(PendingWake {
            owner_note,
            ..kernel_retry_wake(approval, approved, session_key, summary.event_head.get())?
        }))
    }

    /// Decides the newest open approval with the owner's answer and, on a yes, runs the call its
    /// seat was holding, once. Returns what the owner is told. The wake is durable BEFORE the
    /// decision and starts only once the conversation lock is released, so it always sees the
    /// decision and the run's outcome.
    async fn settle_kernel(
        &self,
        record: &mut ConversationRecord,
        message: &AuthenticatedOwnerMessage,
        open: &[DeliveredApproval],
        wake: Option<PendingWake>,
        approved: bool,
        now: OffsetDateTime,
    ) -> Result<String, String> {
        let approval = &open[0];
        let owner_decision = if approved {
            OwnerDecision::AllowOnce
        } else {
            OwnerDecision::Deny
        };
        if let Some(plan) = &wake {
            self.own_requested_wake(record, plan).await?;
        }
        let settled = self
            .approvals
            .decide_delivered(message, approval, owner_decision, now)
            .await;
        match settled {
            Ok(Some(KernelDecisionOutcome::Approved | KernelDecisionOutcome::Denied)) => {}
            Ok(Some(KernelDecisionOutcome::NotSettled) | None) => {
                if let Some(plan) = &wake {
                    self.drop_wake(plan)?;
                }
                return Ok(
                    "That decision did not settle, so nothing was changed. Say it again \
                           and I'll pass it on."
                        .to_owned(),
                );
            }
            Err(refusal) => {
                if approval.capability_id.as_str() == "plan.root-consent" {
                    if let Some(plan) = &wake {
                        self.drop_wake(plan)?;
                    }
                    return Ok("The reviewed plan could not be accepted; it may have changed. Nothing was authorized.".to_owned());
                }
                if let Some(plan) = &wake {
                    self.drop_wake(plan)?;
                }
                return Ok(kernel_refusal_sentence(&refusal));
            }
        }
        let mut ack = decision_ack(approved).to_owned();
        if approved && approval.capability_id.as_str() == "plan.root-consent" {
            ack = "The reviewed root plan is accepted.".to_owned();
        } else if approved {
            let ran = self.approvals.run_approved(&approval.approval_id).await;
            let outcome = match &ran {
                Ok(receipt) => format!("it ran, and its result was: {receipt}"),
                Err(cause) => format!("it did not run: {cause}"),
            };
            match (&ran, &wake) {
                (Err(cause), _) => ack = format!("You said yes, but it did not run: {cause}"),
                (Ok(_), None) => ack = "Done \u{2014} it ran.".to_owned(),
                (Ok(_), Some(_)) => {}
            }
            if let Some(plan) = &wake {
                let mut stored = self.load_record()?;
                if let Some(entry) = stored
                    .wakes
                    .iter_mut()
                    .find(|entry| entry.command_id == plan.command_id)
                {
                    entry.outcome = Some(outcome);
                    self.store_record(&mut stored)?;
                }
            }
        }
        if wake.is_some() {
            let stored = self.load_record()?;
            self.resume_wakes(&stored).await;
        }
        if open.len() > 1 {
            ack.push_str(&format!(
                " {} more question{} still waiting on you.",
                open.len() - 1,
                if open.len() == 2 { " is" } else { "s are" }
            ));
        }
        Ok(ack)
    }

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
            let decided = decide.await;
            if approved {
                self.run_other_seats_approval(approval_id).await;
            }
            return Ok(decided);
        };
        self.own_requested_wake(&mut record, &plan).await?;
        let decided = decide.await;
        // A paired device's yes runs the held call exactly as a DM yes does,
        // and the seat's notice carries what it came to.
        if approved && plan.kind == WakeKind::KernelRetry {
            self.run_external_approval(approval_id, &plan).await?;
        }
        drop(guard);
        Ok(decided)
    }

    /// Once the device decision is durably Approved, runs the held call and
    /// records its outcome on the wake, then resumes the wake to report it.
    async fn run_external_approval(
        &self,
        approval_id: &str,
        plan: &PendingWake,
    ) -> Result<(), String> {
        if self.approvals.approval_status(approval_id).await?
            != Some(odin_domain::ApprovalStatus::Approved)
        {
            return Ok(());
        }
        let id = odin_domain::ApprovalId::new(approval_id.to_owned())
            .map_err(|error| format!("approval id {approval_id}: {error}"))?;
        let outcome = match self.approvals.run_approved(&id).await {
            Ok(receipt) => format!("it ran, and its result was: {receipt}"),
            Err(cause) => format!("it did not run: {cause}"),
        };
        let mut stored = self.load_record()?;
        if let Some(entry) = stored
            .wakes
            .iter_mut()
            .find(|entry| entry.command_id == plan.command_id)
        {
            entry.outcome = Some(outcome);
            self.store_record(&mut stored)?;
        }
        let stored = self.load_record()?;
        self.resume_wakes(&stored).await;
        Ok(())
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
            .delivered_pending(
                &self.owner.channel_id,
                &self.owner.owner_user_id,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|approval| {
                approval.capability_id.as_str() != "plan.root-consent"
                    && approval.session == target
                    && approval.approval_id.as_str() == approval_id
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
        let plan = kernel_retry_wake(
            &approval,
            approved,
            &session_id.to_string(),
            summary.event_head.get(),
        )?;
        Ok(Some((record, plan)))
    }
}

#[async_trait]
impl OwnerDecisionRoute for ConversationRoot {
    async fn settle_held_replies(&self) -> Result<(), String> {
        self.settle_held().await
    }

    async fn clear(&self) -> Result<(), String> {
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        if record.session_id.is_none() {
            return Ok(());
        }
        // An armed fresh successor is the clear: it opens once the session
        // can take it (a publication reload, a settling turn).
        let armed_fresh = |record: &super::ConversationRecord| {
            record.rollover.as_ref().is_some_and(|slot| {
                slot.phase == super::rollover::SuccessorPhase::Pending
                    && slot
                        .brief
                        .as_deref()
                        .is_some_and(|brief| brief.starts_with(super::rollover::FRESH_BRIEF))
            })
        };
        if armed_fresh(&record) {
            return Ok(());
        }
        if record
            .rollover
            .as_ref()
            .is_some_and(|slot| slot.phase == super::rollover::SuccessorPhase::Pending)
        {
            return Err("a session change is already in progress".to_owned());
        }
        match self.begin_successor(&mut record, None, None, true).await {
            Ok(_) => Ok(()),
            Err(_) if armed_fresh(&self.load_record()?) => Ok(()),
            Err(failure) => Err(failure.to_string()),
        }
    }

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
        let Some(answer) = parse_owner_answer(&message.content) else {
            return Ok(None);
        };
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err("the conversation runtime is stopping".to_owned());
        }
        let now = OffsetDateTime::now_utc();
        let Some(session_raw) = record.session_id.as_deref() else {
            // No vehicle is open, so there is no seat to wake and no live question: his answer
            // still decides the newest open approval.
            let kernel = self
                .approvals
                .delivered_pending(&self.owner.channel_id, &self.owner.owner_user_id, now)
                .await
                .map_err(|error| error.to_string())?;
            let (approved, note) = match answer {
                OwnerAnswer::Yes(note) => (true, note),
                OwnerAnswer::No(note) => (false, note),
                OwnerAnswer::Hedged if !kernel.is_empty() => {
                    return Ok(Some(HEDGED_YES_SENTENCE.to_owned()))
                }
                OwnerAnswer::Hedged => (true, None),
            };
            if kernel.is_empty() {
                return self
                    .approvals
                    .lapsed(&self.owner.channel_id, &self.owner.owner_user_id, now)
                    .await;
            }
            let kernel = match choose_open(&kernel, 0, note) {
                Ok((kernel, _)) => kernel,
                Err(sentence) => return Ok(Some(sentence)),
            };
            return self
                .settle_kernel(&mut record, &message, &kernel, None, approved, now)
                .await
                .map(Some);
        };
        let session_id = LiveSessionId::parse(session_raw)
            .map_err(|error| format!("conversation session is invalid: {error}"))?;
        let session_key = session_id.to_string();
        let target = format!("run:live:{session_id}");
        // Every open kernel question the owner was asked, newest first.
        let kernel = self
            .approvals
            .delivered_pending(&self.owner.channel_id, &self.owner.owner_user_id, now)
            .await
            .map_err(|error| error.to_string())?;
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
        let open = !kernel.is_empty() || !live.is_empty();
        let (decision, owner_note) = match answer {
            OwnerAnswer::Yes(note) => (PermissionDecision::AllowOnce, note),
            OwnerAnswer::No(note) => (PermissionDecision::Deny, note),
            OwnerAnswer::Hedged if open => return Ok(Some(HEDGED_YES_SENTENCE.to_owned())),
            OwnerAnswer::Hedged => (PermissionDecision::AllowOnce, None),
        };
        let (kernel, owner_note) = match choose_open(&kernel, live.len(), owner_note) {
            Ok(chosen) => chosen,
            Err(sentence) => return Ok(Some(sentence)),
        };
        if let Some(approval) = kernel.first() {
            let approved = decision == PermissionDecision::AllowOnce;
            // Only this conversation's own seat is told the outcome; a worker's question is
            // answered and run all the same.
            let wake = if approval.capability_id.as_str() != "plan.root-consent"
                && approval.session == target
            {
                self.kernel_wake(session_id, &session_key, approval, approved, owner_note)
                    .await?
            } else {
                None
            };
            if wake.is_none()
                && approval.capability_id.as_str() != "plan.root-consent"
                && approval.session == target
            {
                return Ok(Some(
                    "That conversation has closed, so nothing was authorized.".to_owned(),
                ));
            }
            return self
                .settle_kernel(&mut record, &message, &kernel, wake, approved, now)
                .await
                .map(Some);
        }
        // Exactly one live question remains.
        if let Some(question) = live.last() {
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
        // A yes cannot count for a question that never reached him, so the question goes out
        // now and the yes is asked for again.
        let undelivered: Vec<usize> = record
            .questions
            .iter()
            .enumerate()
            .filter(|(_, question)| {
                question.delivered_message_id.is_none()
                    && !question.settled
                    && question.owner_user_id == self.owner.owner_user_id
                    && question.channel_id == self.owner.channel_id
                    && question.expires_at_unix_ms > now_unix_ms()
            })
            .map(|(index, _)| index)
            .collect();
        if !undelivered.is_empty() {
            for &index in &undelivered {
                self.relay_question(&mut record, index)
                    .map_err(|failure| failure.to_string())?;
            }
            let sent = undelivered
                .iter()
                .all(|&index| record.questions[index].delivered_message_id.is_some());
            return Ok(Some(
                if sent {
                    "That request had not reached you, so your yes could not count for it. I have \
                     sent it now; answer it there."
                } else {
                    "That request never reached you and I could not send it again, so nothing was \
                     authorized."
                }
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
        // A yes or no for a question that already lapsed or settled is told why nothing
        // happened, never read as chat.
        self.approvals
            .lapsed(&self.owner.channel_id, &self.owner.owner_user_id, now)
            .await
    }
}

#[cfg(test)]
mod choose_open_tests {
    use super::*;

    fn open(label: &str) -> DeliveredApproval {
        DeliveredApproval {
            approval_id: odin_domain::ApprovalId::new(format!(
                "approval:{}",
                label.replace(' ', "-")
            ))
            .unwrap(),
            revision: 1,
            capability_id: odin_domain::CapabilityId::new("registry.edit.grant").unwrap(),
            session: "run:live:x".to_owned(),
            label: label.to_owned(),
        }
    }

    #[test]
    fn a_bare_answer_decides_only_a_single_open_question() {
        let one = [open("edit scribe")];
        let (chosen, note) = choose_open(&one, 0, Some("thanks".to_owned())).unwrap();
        assert_eq!(chosen, one.to_vec());
        assert_eq!(note.as_deref(), Some("thanks"));

        let two = [open("edit scribe"), open("deploy odin")];
        let listed = choose_open(&two, 0, None).unwrap_err();
        assert!(
            listed.contains("1. edit scribe") && listed.contains("2. deploy odin"),
            "{listed}"
        );
        let (chosen, note) = choose_open(&two, 0, Some("2".to_owned())).unwrap();
        assert_eq!(chosen[0].label, "deploy odin");
        assert_eq!(chosen.len(), 2);
        assert_eq!(note, None);
        assert!(choose_open(&two, 0, Some("3".to_owned())).is_err());
        assert!(choose_open(&one, 1, None).is_err());
        assert!(choose_open(&[], 2, None).is_err());
        assert!(choose_open(&[], 1, None).is_ok());
    }
}
