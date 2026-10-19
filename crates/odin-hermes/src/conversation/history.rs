//! Bounded history observation and answer projection: the drained
//! durable-history answer wait, question relay receipts, and the
//! outstanding-request freshness walk.

use std::collections::BTreeSet;

use super::stream::AnswerStream;
use super::{ConversationRecord, ConversationRoot, DeliveredQuestion};
use odin_domain::huginn::{
    EventSeq, HistoryQuery, LiveContentBlock, LiveSessionId, LiveSessionState, SessionEpoch,
};
use odin_domain::CommandId;

use crate::runtime::IntentFailure;

use super::identity::{now_unix_ms, now_utc};

/// The authenticated context-fit refusal code the bridge types.
const CONTEXT_WINDOW_REFUSAL: &str = "context_refusal.window_exceeded";
/// The extension's typed refusal when its over-window structured fit cannot
/// locate the turn's registered retrieval block exactly once
/// (extension/odin.ts): it fires only for a request already over the
/// window, so the request does not fit either.
const CONTEXT_ENVELOPE_REFUSAL: &str = "context_refusal.envelope_invalid";
/// Every context-fit refusal shares this code prefix (bridge/contracts.rs).
const CONTEXT_REFUSAL_PREFIX: &str = "context_refusal.";
/// The journal's typed provider refusal of a turn (`turn_end` with
/// `stopReason: error`, odin-omp's normalizer).
const PROVIDER_TURN_ERROR: &str = "provider_turn_error";

pub(super) enum AnswerWait {
    Answer(String),
    /// A delivered open question ends the wait without consuming the answer timeout.
    NeedsOwner,
    /// The vehicle's child exited without a committed answer.
    VehicleDown,
    /// The turn settled idle without reply text or error, so no answer remains to wait for.
    Silent,
}

pub(super) fn page_limit() -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(128).expect("128 is non-zero")
}

impl ConversationRoot {
    /// Drains history after `cursor` before checking terminal state, preserving answers
    /// committed before exit. With `turn`, ignores earlier turns' text and idle events.
    /// Delivered open questions return [`AnswerWait::NeedsOwner`] without timing out.
    pub(super) async fn await_answer(
        &self,
        session_id: LiveSessionId,
        cursor: EventSeq,
        turn: Option<&CommandId>,
    ) -> Result<AnswerWait, IntentFailure> {
        self.await_answer_streaming(session_id, cursor, turn, None)
            .await
    }

    /// [`Self::await_answer`] ending with [`IntentFailure::AnswerTimeout`]
    /// at `deadline`: a caller holding the conversation lock waits in
    /// slices and lets other work in between.
    pub(super) async fn await_answer_until(
        &self,
        session_id: LiveSessionId,
        cursor: EventSeq,
        turn: Option<&CommandId>,
        deadline: tokio::time::Instant,
    ) -> Result<AnswerWait, IntentFailure> {
        self.answer_wait(session_id, cursor, turn, None, deadline)
            .await
    }

    /// [`Self::await_answer`] that shows the owner the reply as it is
    /// written through `stream`.
    pub(super) async fn await_answer_streaming(
        &self,
        session_id: LiveSessionId,
        cursor: EventSeq,
        turn: Option<&CommandId>,
        stream: Option<&mut AnswerStream>,
    ) -> Result<AnswerWait, IntentFailure> {
        let deadline = tokio::time::Instant::now() + self.answer_bound;
        self.answer_wait(session_id, cursor, turn, stream, deadline)
            .await
    }

    async fn answer_wait(
        &self,
        session_id: LiveSessionId,
        mut cursor: EventSeq,
        turn: Option<&CommandId>,
        mut stream: Option<&mut AnswerStream>,
        deadline: tokio::time::Instant,
    ) -> Result<AnswerWait, IntentFailure> {
        let session_key = session_id.to_string();
        let mut answer = None;
        let mut settled_idle = false;
        let mut in_turn = turn.is_none();
        // Follow-ups start at their own user message or run, not acceptance;
        // text before that still belongs to the preceding turn.
        let mut awaiting_prompt = false;
        let mut provider_error: Option<String> = None;
        let mut record = self.load_record().map_err(IntentFailure::Other)?;
        loop {
            let summary = self
                .find_session(session_id, true)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
                .ok_or(IntentFailure::VehicleLost)?;
            let horizon = summary.event_head;
            let mut changed = false;
            // The NEXT answer: the drain stops at the first turn that
            // settled idle with an answer, so a later turn (a wake, a new
            // DM) can never stand in for this one.
            let mut turn_settled = false;
            // Drain the entire observed journal window before interpreting a
            // terminal summary; an answer may be on a later page.
            while cursor < horizon && !turn_settled {
                let page = self
                    .plane
                    .history(HistoryQuery {
                        session_id,
                        after: cursor,
                        limit: page_limit(),
                    })
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?;
                let previous = cursor;
                for event in page.events {
                    if event.sequence > horizon || turn_settled {
                        break;
                    }
                    cursor = event.sequence;
                    match event.body {
                        odin_domain::huginn::LiveEventBody::ControlAccepted(receipt)
                            if accepts_turn(&receipt, turn) =>
                        {
                            in_turn = true;
                            awaiting_prompt = matches!(
                                receipt,
                                odin_domain::huginn::CommandReceipt::Accepted { .. }
                            );
                            answer = None;
                            settled_idle = false;
                        }
                        odin_domain::huginn::LiveEventBody::UserMessage(_)
                            if in_turn && awaiting_prompt =>
                        {
                            awaiting_prompt = false;
                        }
                        odin_domain::huginn::LiveEventBody::SessionStateChanged(change)
                            if in_turn && awaiting_prompt =>
                        {
                            awaiting_prompt = change.current != LiveSessionState::Running;
                        }
                        // A refused prompt cannot answer; return its error without waiting for timeout.
                        odin_domain::huginn::LiveEventBody::ControlCompleted(
                            odin_domain::huginn::CommandOutcome::Failed { command_id, error },
                        ) if turn == Some(&command_id) => {
                            return Err(IntentFailure::TurnRefused {
                                reason: error.message,
                            });
                        }
                        // Both over-window refusals require rollover; this request cannot fit as composed.
                        odin_domain::huginn::LiveEventBody::Error(error)
                            if in_turn
                                && (error.code == CONTEXT_WINDOW_REFUSAL
                                    || error.code == CONTEXT_ENVELOPE_REFUSAL) =>
                        {
                            return Err(IntentFailure::ContextExhausted);
                        }
                        // Any other context refusal: the request never
                        // reached the model and never will as composed.
                        odin_domain::huginn::LiveEventBody::Error(error)
                            if in_turn && error.code.starts_with(CONTEXT_REFUSAL_PREFIX) =>
                        {
                            return Err(IntentFailure::TurnRefused {
                                reason: format!("{}: {}", error.code, error.message),
                            });
                        }
                        // The provider refused this turn: remembered, and
                        // reported once the turn settles without an answer
                        // (a provider retry that answers clears it). The
                        // terminal error outranks any text the failed turn
                        // streamed before it: that text is partial.
                        odin_domain::huginn::LiveEventBody::Error(error)
                            if in_turn && !awaiting_prompt && error.code == PROVIDER_TURN_ERROR =>
                        {
                            answer = None;
                            provider_error = Some(error.message);
                        }
                        odin_domain::huginn::LiveEventBody::AssistantDelta(delta)
                            if in_turn && !awaiting_prompt =>
                        {
                            if let Some(stream) = stream.as_deref_mut() {
                                stream.delta(&delta.text);
                            }
                        }
                        odin_domain::huginn::LiveEventBody::AssistantMessage(message)
                            if in_turn && !awaiting_prompt =>
                        {
                            if let Some(stream) = stream.as_deref_mut() {
                                stream.message_finished();
                            }
                            let text = assistant_text(&message);
                            if !text.trim().is_empty() {
                                answer = Some(text);
                                provider_error = None;
                            }
                        }
                        odin_domain::huginn::LiveEventBody::SessionStateChanged(change)
                            if in_turn && !awaiting_prompt && event.epoch == summary.epoch =>
                        {
                            match change.current {
                                LiveSessionState::Idle | LiveSessionState::Failed
                                    if answer.is_none() && provider_error.is_some() =>
                                {
                                    return Err(IntentFailure::ModelUnavailable {
                                        reason: provider_error.take().unwrap_or_default(),
                                    });
                                }
                                LiveSessionState::Idle => {
                                    settled_idle = true;
                                    turn_settled = answer.is_some();
                                }
                                LiveSessionState::Running | LiveSessionState::RequiresAction => {
                                    settled_idle = false;
                                }
                                _ => {}
                            }
                        }
                        odin_domain::huginn::LiveEventBody::PermissionRequested(request)
                            if event.epoch == summary.epoch && request.expires_at > now_utc() =>
                        {
                            let request_id = request.request_id.to_string();
                            if !record.questions.iter().any(|question| {
                                question.request_id == request_id
                                    && question.session_epoch == Some(event.epoch.get())
                            }) {
                                record.questions.push(DeliveredQuestion {
                                    request_id,
                                    session_id: session_key.clone(),
                                    session_epoch: Some(event.epoch.get()),
                                    prompt: request.prompt,
                                    expires_at_unix_ms: u64::try_from(
                                        request.expires_at.unix_timestamp_nanos() / 1_000_000,
                                    )
                                    .unwrap_or(0),
                                    owner_user_id: self.owner.owner_user_id.clone(),
                                    channel_id: self.owner.channel_id.clone(),
                                    delivered_message_id: None,
                                    delivery_chunks: Vec::new(),
                                    delivery_pending: false,
                                    decision_command_id: None,
                                    delivery_error: None,
                                    settled: false,
                                });
                                changed = true;
                            }
                        }
                        odin_domain::huginn::LiveEventBody::PermissionResolved(resolution)
                            if event.epoch == summary.epoch =>
                        {
                            if let Some(question) = record.questions.iter_mut().find(|question| {
                                question.request_id == resolution.request_id.to_string()
                                    && question.session_epoch == Some(event.epoch.get())
                            }) {
                                question.settled = true;
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                }
                if cursor <= previous {
                    return Err(IntentFailure::HistoryUnavailable);
                }
            }
            if changed {
                self.store_record(&mut record)
                    .map_err(IntentFailure::Other)?;
            }
            let next_step = match stream.as_deref_mut() {
                Some(stream) if !turn_settled => {
                    stream.tick(self.egress.as_ref(), tokio::time::Instant::now())
                }
                _ => None,
            };
            if summary.state == LiveSessionState::Ended {
                return match answer.filter(|_| settled_idle) {
                    Some(answer) => Ok(AnswerWait::Answer(answer)),
                    None => Err(IntentFailure::ConversationClosed),
                };
            }
            if summary.state == LiveSessionState::Failed && !turn_settled {
                // The journal settles Failed on the typed provider error
                // itself: the turn is over and the provider said why, so
                // there is no vehicle to recover.
                if answer.is_none() {
                    if let Some(reason) = provider_error.take() {
                        return Err(IntentFailure::ModelUnavailable { reason });
                    }
                }
                // The caller recovers in place and re-reads the original
                // window; it must never start again at the recovery head.
                return Ok(AnswerWait::VehicleDown);
            }
            for index in 0..record.questions.len() {
                let question = &record.questions[index];
                if question.session_id == session_key
                    && !question.settled
                    && question.session_epoch == Some(summary.epoch.get())
                    && question.delivered_message_id.is_none()
                    && question.expires_at_unix_ms > now_unix_ms()
                {
                    self.relay_question(&mut record, index)?;
                }
            }
            // Delivery precedes accepting the model's "needs approval"
            // answer as final, even when the turn already went idle.
            let kernel = self
                .approvals
                .deliver_session_questions(
                    &session_id,
                    &self.owner.channel_id,
                    &self.owner.owner_user_id,
                    now_utc(),
                )
                .await
                .map_err(IntentFailure::Other)?;
            if !kernel.is_empty()
                || record.questions.iter().any(|question| {
                    question.session_id == session_key
                        && question.session_epoch == Some(summary.epoch.get())
                        && self.is_decidable_receipt(question)
                })
            {
                return Ok(AnswerWait::NeedsOwner);
            }
            if settled_idle {
                if let Some(answer) = answer {
                    return Ok(AnswerWait::Answer(answer));
                }
                // This command's own turn went Idle and said nothing: it
                // is over. An unbound wait cannot tell its turn's settle
                // from an earlier one and keeps waiting.
                if turn.is_some() && summary.state == LiveSessionState::Idle {
                    return Ok(AnswerWait::Silent);
                }
            }
            let wake = next_step.map_or(deadline, |due| due.min(deadline));
            let remaining = wake.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.plane.wait_for_history(session_id, cursor))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(IntentFailure::HistoryUnavailable),
                Err(_) if wake < deadline => {}
                Err(_) => return Err(IntentFailure::AnswerTimeout),
            }
        }
    }

    /// Only a committed durable delivery authorizes the question receipt.
    pub(super) fn relay_question(
        &self,
        record: &mut ConversationRecord,
        index: usize,
    ) -> Result<(), IntentFailure> {
        let question = &mut record.questions[index];
        let Some(epoch) = question.session_epoch else {
            return Ok(());
        };
        if question.settled
            || question.delivered_message_id.is_some()
            || question.owner_user_id != self.owner.owner_user_id
            || question.channel_id != self.owner.channel_id
            || question.expires_at_unix_ms <= now_unix_ms()
        {
            return Ok(());
        }
        let key = format!(
            "permission:{}:{epoch}:{}",
            question.session_id, question.request_id
        );
        if question.delivery_pending || !question.delivery_chunks.is_empty() {
            let mut refs = question.delivery_chunks.iter().map(|message_id| {
                crate::discord::DiscordMessageRef {
                    message_id: message_id.clone(),
                    channel_id: question.channel_id.clone(),
                }
            });
            let ownership = refs.next().map(|anchor| crate::egress::ReplyChunks {
                anchor,
                tails: refs.collect(),
            });
            if let Err(error) =
                self.import_legacy_delivery(&key, ownership.as_ref(), question.delivery_pending)
            {
                question.delivery_error = Some(error.to_string());
                return self.store_record(record).map_err(IntentFailure::Other);
            }
        }
        match self.deliver_final(&key, &question.prompt, None) {
            Ok(Some(delivery)) if delivery.anchor.channel_id == question.channel_id => {
                question.delivered_message_id = Some(delivery.anchor.message_id);
                question.delivery_error = None;
            }
            Ok(_) => {
                question.delivery_error =
                    Some("question delivery did not commit an owner-channel message".to_owned());
            }
            Err(error) => {
                question.delivery_error = Some(error.to_string());
            }
        }
        self.store_record(record).map_err(IntentFailure::Other)
    }

    /// One bounded full-history walk returning the still-outstanding
    /// request ids of the session: every PermissionRequested without a
    /// later PermissionResolved.
    pub(super) async fn session_pending_requests(
        &self,
        session_id: LiveSessionId,
        epoch: SessionEpoch,
    ) -> Result<BTreeSet<String>, IntentFailure> {
        let mut pending = BTreeSet::new();
        let mut cursor = EventSeq::new(0);
        loop {
            let page = self
                .plane
                .history(HistoryQuery {
                    session_id,
                    after: cursor,
                    limit: page_limit(),
                })
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?;
            let advanced = !page.events.is_empty();
            for event in page.events {
                cursor = event.sequence;
                if event.epoch != epoch {
                    continue;
                }
                match event.body {
                    odin_domain::huginn::LiveEventBody::PermissionRequested(request) => {
                        if request.expires_at > now_utc() {
                            pending.insert(request.request_id.to_string());
                        }
                    }
                    odin_domain::huginn::LiveEventBody::PermissionResolved(resolution) => {
                        pending.remove(resolution.request_id.to_string().as_str());
                    }
                    _ => {}
                }
            }
            if !advanced {
                return Ok(pending);
            }
        }
    }

    /// Observes history from `cursor` for one settled assistant answer:
    /// the newest answer when the turn settled idle, otherwise nothing.
    pub(super) async fn observe_since(
        &self,
        session_id: LiveSessionId,
        cursor: EventSeq,
        turn: Option<&CommandId>,
    ) -> Result<Option<String>, IntentFailure> {
        let mut cursor = cursor;
        let mut answer: Option<String> = None;
        let mut settled_idle = false;
        let mut in_turn = turn.is_none();
        let mut awaiting_prompt = false;
        loop {
            let page = self
                .plane
                .history(HistoryQuery {
                    session_id,
                    after: cursor,
                    limit: page_limit(),
                })
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?;
            let advanced = !page.events.is_empty();
            for event in page.events {
                cursor = event.sequence;
                match event.body {
                    odin_domain::huginn::LiveEventBody::ControlAccepted(receipt)
                        if accepts_turn(&receipt, turn) =>
                    {
                        in_turn = true;
                        awaiting_prompt = matches!(
                            receipt,
                            odin_domain::huginn::CommandReceipt::Accepted { .. }
                        );
                        answer = None;
                        settled_idle = false;
                    }
                    odin_domain::huginn::LiveEventBody::UserMessage(_)
                        if in_turn && awaiting_prompt =>
                    {
                        awaiting_prompt = false;
                    }
                    odin_domain::huginn::LiveEventBody::SessionStateChanged(change)
                        if in_turn && awaiting_prompt =>
                    {
                        awaiting_prompt = change.current != LiveSessionState::Running;
                    }
                    odin_domain::huginn::LiveEventBody::Error(error)
                        if in_turn && !awaiting_prompt && error.code == PROVIDER_TURN_ERROR =>
                    {
                        answer = None;
                    }
                    odin_domain::huginn::LiveEventBody::AssistantMessage(message)
                        if in_turn && !awaiting_prompt =>
                    {
                        let text = assistant_text(&message);
                        if !text.trim().is_empty() {
                            answer = Some(text);
                        }
                    }
                    odin_domain::huginn::LiveEventBody::SessionStateChanged(change)
                        if in_turn && !awaiting_prompt =>
                    {
                        match change.current {
                            LiveSessionState::Idle => settled_idle = true,
                            LiveSessionState::Running | LiveSessionState::RequiresAction => {
                                settled_idle = false
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            if !advanced {
                break;
            }
        }
        Ok(if settled_idle { answer } else { None })
    }

    /// A receipt is decidable when it was actually delivered to THIS
    /// owner/channel and is not marked settled.
    pub(super) fn is_decidable_receipt(&self, question: &DeliveredQuestion) -> bool {
        question.delivered_message_id.is_some()
            && question.session_epoch.is_some()
            && !question.settled
            && question.owner_user_id == self.owner.owner_user_id
            && question.channel_id == self.owner.channel_id
            && question.expires_at_unix_ms > now_unix_ms()
    }
}

/// True when `receipt` is the acceptance of exactly `turn`'s command.
fn accepts_turn(receipt: &odin_domain::huginn::CommandReceipt, turn: Option<&CommandId>) -> bool {
    use odin_domain::huginn::CommandReceipt;
    match (receipt, turn) {
        (
            CommandReceipt::Accepted { command_id } | CommandReceipt::Duplicate { command_id, .. },
            Some(turn),
        ) => command_id == turn,
        _ => false,
    }
}

/// The human-readable text of one assistant message: the text blocks,
/// joined. Non-text blocks carry no conversational answer.
pub(super) fn assistant_text(message: &odin_domain::huginn::LiveMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            LiveContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}
