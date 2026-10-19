//! Prompt admission and replay: the exact admitted prompt is persisted
//! before submission. The original turn's durable reply freezes its final
//! target before lifecycle settlement and takes precedence over the root cache.

use async_trait::async_trait;
use odin_domain::huginn::{
    CommandReceipt, CommandRejection, EventSeq, LiveCommand, LiveCommandBody, LiveContentBlock,
    LiveError, LiveMessage, LiveSessionId, LiveSessionState, LiveSessionSummary, SessionEpoch,
};
use odin_domain::CommandId;

use crate::runtime::{ApprovedIntentExecution, ApprovedIntentRoute, IntentFailure};

use super::delivery::ReplyDisposition;
use super::history::AnswerWait;
use super::identity::bounded_command;
use super::stream::AnswerStream;
use super::{
    ContinuationReply, ConversationRecord, ConversationRoot, InFlightKind, InFlightPhase,
    InFlightPrompt, PendingWake, WakeKind,
};

/// Supplies the owner's local time and live model so the seat need not infer them from memory.
pub(super) fn turn_context_line(clock: Option<String>, summary: &LiveSessionSummary) -> String {
    let model = format!(
        "[You are running on {}/{}]",
        summary.provider.as_str(),
        summary.model.as_str()
    );
    match clock {
        Some(clock) => format!("{clock} {model}"),
        None => model,
    }
}

impl InFlightPrompt {
    /// Reconstruct the immutable journal claim, including its original epoch.
    pub(super) fn command(&self) -> Result<LiveCommand, String> {
        let text = match &self.clock {
            Some(line) => format!("{line}\n{}", self.content),
            None => self.content.clone(),
        };
        let message = LiveMessage::new(vec![LiveContentBlock::Text(text)])
            .map_err(|error| format!("in-flight prompt message rejected: {error}"))?;
        Ok(LiveCommand {
            command_id: CommandId::new(&self.command_id)
                .map_err(|error| format!("in-flight command identity rejected: {error}"))?,
            session_id: LiveSessionId::parse(&self.session_id)
                .map_err(|error| format!("in-flight session identity rejected: {error}"))?,
            expected_epoch: SessionEpoch::new(self.expected_epoch),
            expected_event_head: None,
            body: match self.kind {
                InFlightKind::Prompt => LiveCommandBody::Prompt { message },
                InFlightKind::FollowUp => LiveCommandBody::FollowUp { message },
            },
        })
    }
}

/// The whole answer of an unprompted turn with nothing for Colin: code sends
/// nothing.
pub(crate) const QUIET_REPLY: &str = "[quiet]";

/// Removes the quiet control token and adjacent punctuation, leaving only owner-facing text.
pub(crate) fn without_quiet_token(answer: &str) -> &str {
    let mut text = answer.trim();
    if let Some(rest) = text.strip_prefix(QUIET_REPLY) {
        text = rest.trim_start_matches(|character: char| {
            character.is_whitespace()
                || matches!(character, '\u{2014}' | '\u{2013}' | '-' | ':' | ',' | '.')
        });
    }
    if let Some(rest) = text.strip_suffix(QUIET_REPLY) {
        text = rest.trim_end();
    }
    text
}

/// Sent when the answer wait times out while work continues.
pub(super) const LATE_ANSWER_HOLDING: &str =
    "Still working on that one \u{2014} I'll send it over as soon as it's ready.";

/// What Colin hears when a handed-off turn's session ends before it
/// answered: never only the holding line.
pub(super) const LATE_ANSWER_LOST: &str =
    "That one stopped before it finished, so I have no answer for it \u{2014} send it again if you still need it.";

/// A single follow-up for a turn that settled without reply text.
pub(super) const SILENT_TURN_REPROMPT: &str =
    "[host] Your last turn ended without a reply to Colin. Reply to him now, in plain words.";

/// Owner messages require a reply even when the model emits the quiet token.
pub(super) const QUIET_OWNER_REPROMPT: &str =
    "[host] Your last turn answered Colin's own message with [quiet], so he got nothing. \
     [quiet] is only for wakes and reports; his messages always get a reply. Reply to him \
     now, in plain words.";

/// Why an owner turn is reprompted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Unanswered {
    /// It settled with no reply text.
    Silent,
    /// It answered only the quiet token.
    Quiet,
}

impl Unanswered {
    fn reprompt(self) -> &'static str {
        match self {
            Self::Silent => SILENT_TURN_REPROMPT,
            Self::Quiet => QUIET_OWNER_REPROMPT,
        }
    }
}

/// Colin's own turn answered with nothing but the quiet token.
fn quiet_owner_answer(intent: &ApprovedIntentExecution, answer: &str) -> bool {
    !intent.unprompted && without_quiet_token(answer).is_empty()
}

/// The one continuation that owns a direct turn's undelivered final reply,
/// derived from its owner key so it is never armed twice.
fn direct_reply_command(key: &str) -> Result<String, String> {
    bounded_command("reply-owed", &[key]).map(|id| id.to_string())
}

/// Whether this late-answer plan is exactly a direct turn's reply owner.
pub(super) fn owes_direct_reply(wake: &PendingWake) -> bool {
    wake.kind == WakeKind::LateAnswer
        && matches!(wake.owner_keys.as_slice(), [key]
            if direct_reply_command(key).is_ok_and(|id| id == wake.command_id))
}

/// Maps a journal rejection to the typed failure seam without string
/// matching on formatted text.
fn rejection_failure(reason: &CommandRejection) -> IntentFailure {
    match reason {
        // The vehicle moved on between resolve and send; the next intent
        // follows it up.
        CommandRejection::InvalidState { .. } => IntentFailure::ConversationBusy,
        CommandRejection::EpochMismatch { .. }
        | CommandRejection::TargetMismatch { .. }
        | CommandRejection::EventHeadMismatch { .. } => IntentFailure::VehicleLost,
        CommandRejection::EmptyMessage
        | CommandRejection::PermissionRequestNotOutstanding { .. }
        | CommandRejection::ApprovalRevisionMismatch { .. } => {
            IntentFailure::Other("the conversation session rejected the prompt".to_owned())
        }
    }
}

/// Durable reply failures retain admission until the original reply can settle.
fn reply_state_failure(error: crate::egress::EgressError) -> IntentFailure {
    tracing::warn!(error = %error, "odin-hermes: durable reply state unavailable: {error}");
    IntentFailure::ReplyStateUnavailable
}

impl ConversationRoot {
    /// All prompts, including approval continuations, share exact journal
    /// lookup before epoch refresh and persist before submission.
    pub(super) async fn submit_prompt(
        &self,
        record: &mut ConversationRecord,
        summary: &LiveSessionSummary,
        flight: &mut InFlightPrompt,
    ) -> Result<EventSeq, IntentFailure> {
        let mut epoch = summary.epoch;
        for attempt in 0..2 {
            let command = flight.command().map_err(IntentFailure::Other)?;
            if command.session_id != summary.session_id {
                return Err(IntentFailure::Other(
                    "prompt belongs to a different conversation".to_owned(),
                ));
            }
            if self
                .plane
                .command_entry(&command)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
                .is_some()
            {
                self.record_admission(flight)?;
                flight.phase = InFlightPhase::Sent;
                self.persist_prompt(record, flight)?;
                return Ok(EventSeq::new(flight.event_cursor));
            }
            // The journal, not the cached phase, decides admission; resubmitting
            // an absent command is safe because the journal deduplicates its id.
            if flight.phase == InFlightPhase::Sent {
                flight.phase = InFlightPhase::Prepared;
                self.persist_prompt(record, flight)?;
            }
            if flight.expected_epoch != epoch.get() {
                flight.expected_epoch = epoch.get();
                self.persist_prompt(record, flight)?;
            }
            match self
                .plane
                .command(flight.command().map_err(IntentFailure::Other)?)
                .await
            {
                Ok(CommandReceipt::Accepted { .. } | CommandReceipt::Duplicate { .. }) => {
                    self.record_admission(flight)?;
                    flight.phase = InFlightPhase::Sent;
                    self.persist_prompt(record, flight)?;
                    return Ok(EventSeq::new(flight.event_cursor));
                }
                Ok(CommandReceipt::Rejected { reason, .. }) => {
                    return Err(rejection_failure(&reason))
                }
                Err(LiveError::Conflict { code, .. })
                    if code == "session_parked" && attempt == 0 =>
                {
                    let recovered = self
                        .recover_vehicle(record, Some(summary.epoch.get()))
                        .await?;
                    if recovered.session_id != summary.session_id {
                        return Err(IntentFailure::VehicleLost);
                    }
                    epoch = recovered.epoch;
                }
                Err(error) => {
                    return Err(IntentFailure::Other(format!(
                        "conversation prompt failed: {error}"
                    )))
                }
            }
        }
        Err(IntentFailure::VehicleLost)
    }

    /// The journal proved this prompt admitted: its logical reply owns it
    /// from here on, whether or not the turn ever answers.
    fn record_admission(&self, flight: &InFlightPrompt) -> Result<(), IntentFailure> {
        self.record_admitted_prompt(
            &flight.idempotency_key,
            &flight.session_id,
            &flight.command_id,
        )
        .map_err(reply_state_failure)
    }

    fn persist_prompt(
        &self,
        record: &mut ConversationRecord,
        flight: &InFlightPrompt,
    ) -> Result<(), IntentFailure> {
        if record
            .in_flight
            .as_ref()
            .is_some_and(|current| current.command_id == flight.command_id)
        {
            record.in_flight = Some(flight.clone());
        } else if let Some(wake) = record.wakes.iter_mut().find(|wake| {
            wake.command_id == flight.command_id
                || wake
                    .prompt
                    .as_ref()
                    .is_some_and(|prompt| prompt.command_id == flight.command_id)
        }) {
            wake.prompt = Some(flight.clone());
        } else {
            return Err(IntentFailure::Other(
                "prompt has no durable conversation owner".to_owned(),
            ));
        }
        self.store_record(record).map_err(IntentFailure::Other)
    }

    /// Persists the fresh in-flight prompt (exact bounded command
    /// identity, phase, epoch, and cursor) and submits it once.
    async fn prepare_and_send_prompt(
        &self,
        record: &mut ConversationRecord,
        summary: &LiveSessionSummary,
        intent: &ApprovedIntentExecution,
    ) -> Result<EventSeq, IntentFailure> {
        self.ensure_plan_accepted(summary, &intent.content)?;
        // Colin's queued messages go before any wake.
        if summary.state != LiveSessionState::Idle
            || (intent.unprompted && !record.queued.is_empty())
        {
            return Err(IntentFailure::ConversationBusy);
        }
        // One journal command per attempt: a failed attempt clears its
        // flight while the journal keeps its command, so a retry (fresh
        // clock line, possibly a successor session or epoch) must never
        // reuse that id. A crash mid-attempt replays the persisted flight.
        let attempt = jiff::Timestamp::now();
        let command_id = bounded_command(
            "intent",
            &[
                &intent.idempotency_key,
                &summary.session_id.to_string(),
                &summary.epoch.get().to_string(),
                &attempt.as_millisecond().to_string(),
            ],
        )
        .map_err(IntentFailure::Other)?;
        let mut flight = InFlightPrompt {
            idempotency_key: intent.idempotency_key.clone(),
            content: intent.content.clone(),
            command_id: command_id.to_string(),
            session_id: summary.session_id.to_string(),
            kind: InFlightKind::Prompt,
            expected_epoch: summary.epoch.get(),
            event_cursor: summary.event_head.get(),
            phase: InFlightPhase::Prepared,
            clock: Some(turn_context_line(
                self.clock.as_ref().map(|clock| clock.line(attempt)),
                summary,
            )),
            asks: Vec::new(),
        };
        record.in_flight = Some(flight.clone());
        self.store_record(record).map_err(IntentFailure::Other)?;
        self.submit_prompt(record, summary, &mut flight).await
    }

    /// Sends one settled answer to Colin and records the receipt. A turn
    /// that concludes nothing for him (a wake, a report, a late answer with
    /// nothing to add) answers exactly [`QUIET_REPLY`] and nothing is sent;
    /// the token itself is never sent. A frozen reply the row proves is
    /// known-unsent is owned by a durable late-answer plan, stored before
    /// its tracked task starts; one in doubt is never retried here.
    async fn deliver_answer(
        &self,
        intent: &ApprovedIntentExecution,
        projection: &mut serde_json::Value,
        answer: &str,
    ) -> Result<(), IntentFailure> {
        let spoken = without_quiet_token(answer);
        let delivered = self.deliver_final(&intent.idempotency_key, spoken, Some(projection));
        let mut owed = None;
        if spoken.is_empty() {
            // Quiet is control vocabulary and must not reach the owner, even on an owner turn.
            if !intent.unprompted {
                tracing::info!(
                    "odind: conversation-reply quiet_owner_turn key={} conversation={}",
                    intent.idempotency_key,
                    self.conversation_id
                );
            }
            projection["replySent"] = serde_json::Value::Bool(false);
            projection["quiet"] = serde_json::Value::Bool(true);
            if let Err(error) = delivered {
                projection["replyError"] = serde_json::Value::String(error.to_string());
            }
        } else {
            match delivered {
                Ok(_) => projection["replySent"] = serde_json::Value::Bool(true),
                Err(error) => {
                    projection["replySent"] = serde_json::Value::Bool(false);
                    let detail = match self.reply_disposition(&intent.idempotency_key) {
                        Ok(ReplyDisposition::Resumable) => {
                            owed = Some(PendingWake {
                                command_id: direct_reply_command(&intent.idempotency_key)
                                    .map_err(IntentFailure::Other)?,
                                owner_keys: vec![intent.idempotency_key.clone()],
                                kind: WakeKind::LateAnswer,
                                approved: true,
                                label: String::new(),
                                session_id: projection["session"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_owned(),
                                decision_cursor: 0,
                                approval_id: None,
                                prompt: None,
                                reply: Some(ContinuationReply {
                                    answer: spoken.to_owned(),
                                    delivered: None,
                                    terminal_outcome: None,
                                }),
                                completion: None,
                                owner_note: None,
                                rolled: false,
                            });
                            format!("{error}; the undelivered rest is saved and retried")
                        }
                        Ok(ReplyDisposition::Unknown) => {
                            format!("{error}; whether it arrived is unknown, so nothing is resent")
                        }
                        _ => error.to_string(),
                    };
                    projection["replyError"] = serde_json::Value::String(detail);
                }
            }
            if !intent.unprompted {
                self.egress.turn_answered(crate::runtime::review::Exchange {
                    seat: self.binding.seat_id.clone(),
                    session: projection["session"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                    parent_session: None,
                    project: Some(self.project.clone()),
                    trigger: "turn",
                    turn_keys: vec![intent.idempotency_key.clone()],
                    sequence: None,
                    asked: intent.content.clone(),
                    answered: spoken.to_owned(),
                });
            }
        }
        let Some(wake) = owed else {
            return self.update_projection(&intent.idempotency_key, projection.clone());
        };
        // One store carries the plan and the projection that names it: a
        // failed store surfaces and claims no owner; the frozen row stays.
        let mut fresh = self.load_record().map_err(IntentFailure::Other)?;
        if !fresh
            .wakes
            .iter()
            .any(|existing| existing.command_id == wake.command_id)
        {
            fresh.wakes.push(wake.clone());
        }
        if fresh.last_idempotency_key.as_deref() == Some(intent.idempotency_key.as_str()) {
            fresh.last_projection = Some(projection.clone());
        }
        self.store_record(&mut fresh)
            .map_err(IntentFailure::Other)?;
        self.spawn_wake_task(wake).await;
        Ok(())
    }

    /// Freezes the settled answer under its original key before retiring the
    /// flight. Replay resumes that delivery even after newer turns replace
    /// the lifecycle projection cache.
    async fn observe_and_settle(
        &self,
        record: &mut ConversationRecord,
        summary: &LiveSessionSummary,
        intent: &ApprovedIntentExecution,
        cursor: EventSeq,
    ) -> Result<serde_json::Value, IntentFailure> {
        // This intent's own turn: once the journal proves its command was
        // admitted, its reply is the answer after ITS acceptance, never an
        // earlier turn's (a successor's brief). A flight the journal does
        // not carry has no acceptance to bind and is observed unbound.
        let mut turn = None;
        if let Some(command) = record
            .in_flight
            .as_ref()
            .filter(|flight| flight.idempotency_key == intent.idempotency_key)
            .and_then(|flight| flight.command().ok())
        {
            if matches!(self.plane.command_entry(&command).await, Ok(Some(_))) {
                turn = Some(command.command_id);
            }
        }
        let mut stream = AnswerStream::new(
            self.reply_delivery(&intent.idempotency_key, None, None)
                .map_err(reply_state_failure)?,
        );
        match self
            .await_answer_streaming(
                summary.session_id,
                cursor,
                turn.as_ref(),
                (!intent.unprompted).then_some(&mut stream),
            )
            .await
        {
            Ok(AnswerWait::Answer(answer)) if quiet_owner_answer(intent, &answer) => {
                self.reprompt_unanswered(
                    record,
                    summary.session_id,
                    intent,
                    turn.as_ref(),
                    Unanswered::Quiet,
                )
                .await
            }
            Ok(AnswerWait::Answer(answer)) => {
                let mut projection = self.projection(
                    summary.session_id.to_string(),
                    intent,
                    &answer,
                    false,
                    false,
                    None,
                )?;
                self.reply_delivery(
                    &intent.idempotency_key,
                    Some(without_quiet_token(&answer)),
                    Some(&projection),
                )
                .map_err(reply_state_failure)?;
                self.settle(&intent.idempotency_key, projection.clone())?;
                self.deliver_answer(intent, &mut projection, &answer)
                    .await?;
                Ok(projection)
            }
            Ok(AnswerWait::NeedsOwner) => {
                let projection = self.projection(
                    summary.session_id.to_string(),
                    intent,
                    "",
                    true,
                    false,
                    None,
                )?;
                self.settle(&intent.idempotency_key, projection.clone())?;
                Ok(projection)
            }
            Ok(AnswerWait::Silent) => {
                self.reprompt_unanswered(
                    record,
                    summary.session_id,
                    intent,
                    turn.as_ref(),
                    Unanswered::Silent,
                )
                .await
            }
            Ok(AnswerWait::VehicleDown) => {
                if record.session_id.as_deref() != Some(summary.session_id.to_string().as_str()) {
                    return Err(IntentFailure::VehicleLost);
                }
                // The child exited WITHOUT a committed answer in the
                // drained window. Recover the SAME session once — the
                // durable transcript resumed — and keep the ORIGINAL
                // cursor: history written before the recovery stays
                // visible. Observe only; never a fabricated resend.
                // Nothing was observed here: no epoch is invented.
                let recovered = self.recover_vehicle(record, None).await?;
                if recovered.session_id != summary.session_id {
                    return Err(IntentFailure::VehicleLost);
                }
                match self
                    .await_answer_streaming(
                        recovered.session_id,
                        cursor,
                        turn.as_ref(),
                        (!intent.unprompted).then_some(&mut stream),
                    )
                    .await
                {
                    Ok(AnswerWait::Answer(answer)) if quiet_owner_answer(intent, &answer) => {
                        self.reprompt_unanswered(
                            record,
                            recovered.session_id,
                            intent,
                            turn.as_ref(),
                            Unanswered::Quiet,
                        )
                        .await
                    }
                    Ok(AnswerWait::Answer(answer)) => {
                        let mut projection = self.projection(
                            recovered.session_id.to_string(),
                            intent,
                            &answer,
                            false,
                            false,
                            None,
                        )?;
                        self.reply_delivery(
                            &intent.idempotency_key,
                            Some(without_quiet_token(&answer)),
                            Some(&projection),
                        )
                        .map_err(reply_state_failure)?;
                        self.settle(&intent.idempotency_key, projection.clone())?;
                        self.deliver_answer(intent, &mut projection, &answer)
                            .await?;
                        Ok(projection)
                    }
                    Ok(AnswerWait::NeedsOwner) => {
                        let projection = self.projection(
                            recovered.session_id.to_string(),
                            intent,
                            "",
                            true,
                            false,
                            None,
                        )?;
                        self.settle(&intent.idempotency_key, projection.clone())?;
                        Ok(projection)
                    }
                    Ok(AnswerWait::Silent) => {
                        self.reprompt_unanswered(
                            record,
                            recovered.session_id,
                            intent,
                            turn.as_ref(),
                            Unanswered::Silent,
                        )
                        .await
                    }
                    Ok(AnswerWait::VehicleDown) | Err(IntentFailure::VehicleLost) => {
                        Err(IntentFailure::VehicleLost)
                    }
                    // Resumed turns use the same late-answer handoff as other long turns.
                    Err(IntentFailure::AnswerTimeout) => {
                        self.hand_off_late_answer(&recovered, intent, cursor).await
                    }
                    Err(other) => Err(other),
                }
            }
            Err(IntentFailure::AnswerTimeout) => {
                self.hand_off_late_answer(summary, intent, cursor).await
            }
            Err(other) => Err(other),
        }
    }

    /// The owner's own turn settled Idle without a word for him, or with
    /// only the quiet token: one bounded reprompt on the SAME session asks
    /// for the reply, under a command id derived from the intent (a replay
    /// never sends a second one), and a second silence is the typed
    /// [`IntentFailure::SilentTurn`] at once.
    async fn reprompt_unanswered(
        &self,
        record: &mut ConversationRecord,
        session_id: LiveSessionId,
        intent: &ApprovedIntentExecution,
        silent_turn: Option<&CommandId>,
        why: Unanswered,
    ) -> Result<serde_json::Value, IntentFailure> {
        let command_id = bounded_command(
            "silent",
            &[&intent.idempotency_key, &session_id.to_string()],
        )
        .map_err(IntentFailure::Other)?;
        if silent_turn == Some(&command_id) {
            // The reprompt itself (observed on replay) ended silent.
            tracing::warn!(
                session = %session_id,
                "odin-hermes: turn ended silent after reprompt key={} session={session_id}",
                intent.idempotency_key
            );
            return Err(IntentFailure::SilentTurn);
        }
        let summary = self
            .find_session(session_id, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
            .ok_or(IntentFailure::VehicleLost)?;
        tracing::warn!(
            session = %session_id,
            "odin-hermes: turn ended unanswered; reprompted key={} session={session_id} why={why:?}",
            intent.idempotency_key
        );
        let mut flight = InFlightPrompt {
            idempotency_key: intent.idempotency_key.clone(),
            content: why.reprompt().to_owned(),
            command_id: command_id.to_string(),
            session_id: session_id.to_string(),
            kind: InFlightKind::Prompt,
            expected_epoch: summary.epoch.get(),
            event_cursor: summary.event_head.get(),
            phase: InFlightPhase::Prepared,
            clock: None,
            asks: Vec::new(),
        };
        // Reloaded: the answer wait persisted its own receipts.
        *record = self.load_record().map_err(IntentFailure::Other)?;
        record.in_flight = Some(flight.clone());
        self.store_record(record).map_err(IntentFailure::Other)?;
        let cursor = self.submit_prompt(record, &summary, &mut flight).await?;
        match self
            .await_answer(session_id, cursor, Some(&command_id))
            .await
        {
            Ok(AnswerWait::Answer(answer)) if quiet_owner_answer(intent, &answer) => {
                tracing::info!(
                    session = %session_id,
                    "odin-hermes: turn answered quiet after reprompt key={} session={session_id}",
                    intent.idempotency_key
                );
                Err(IntentFailure::SilentTurn)
            }
            Ok(AnswerWait::Answer(answer)) => {
                let mut projection =
                    self.projection(session_id.to_string(), intent, &answer, false, false, None)?;
                self.reply_delivery(
                    &intent.idempotency_key,
                    Some(without_quiet_token(&answer)),
                    Some(&projection),
                )
                .map_err(reply_state_failure)?;
                self.settle(&intent.idempotency_key, projection.clone())?;
                self.deliver_answer(intent, &mut projection, &answer)
                    .await?;
                Ok(projection)
            }
            Ok(AnswerWait::NeedsOwner) => {
                let projection =
                    self.projection(session_id.to_string(), intent, "", true, false, None)?;
                self.settle(&intent.idempotency_key, projection.clone())?;
                Ok(projection)
            }
            Ok(AnswerWait::Silent) => {
                tracing::warn!(
                    session = %session_id,
                    "odin-hermes: turn ended silent after reprompt key={} session={session_id}",
                    intent.idempotency_key
                );
                Err(IntentFailure::SilentTurn)
            }
            Ok(AnswerWait::VehicleDown) => Err(IntentFailure::VehicleLost),
            Err(IntentFailure::AnswerTimeout) => {
                self.hand_off_late_answer(&summary, intent, cursor).await
            }
            Err(other) => Err(other),
        }
    }

    /// A turn that outlives the answer bound keeps working: Colin hears one
    /// holding line now, the intent settles so he can keep talking, and a
    /// durable late-answer wake delivers the real answer when the turn
    /// settles — across restarts too.
    async fn hand_off_late_answer(
        &self,
        summary: &LiveSessionSummary,
        intent: &ApprovedIntentExecution,
        cursor: EventSeq,
    ) -> Result<serde_json::Value, IntentFailure> {
        // Only a turn that is still working (or coming back up) is handed
        // off; one blocked on a question it could not deliver stays an
        // honest timeout.
        let state = self
            .find_session(summary.session_id, true)
            .await
            .ok()
            .flatten()
            .map(|session| session.state);
        if !matches!(
            state,
            Some(LiveSessionState::Running | LiveSessionState::Starting)
        ) {
            tracing::warn!(
                session = %summary.session_id,
                "odin-hermes: turn not handed off late key={} session={} state={state:?}",
                intent.idempotency_key, summary.session_id
            );
            return Err(IntentFailure::AnswerTimeout);
        }
        let command_id =
            bounded_command("late", &[&intent.idempotency_key]).map_err(IntentFailure::Other)?;
        let wake = PendingWake {
            command_id: command_id.to_string(),
            owner_keys: vec![intent.idempotency_key.clone()],
            kind: WakeKind::LateAnswer,
            approved: true,
            label: String::new(),
            session_id: summary.session_id.to_string(),
            decision_cursor: cursor.get(),
            approval_id: None,
            prompt: None,
            reply: None,
            completion: None,
            owner_note: None,
            rolled: false,
        };
        let mut record = self.load_record().map_err(IntentFailure::Other)?;
        if !record
            .wakes
            .iter()
            .any(|existing| existing.command_id == wake.command_id)
        {
            record.wakes.push(wake.clone());
            self.store_record(&mut record)
                .map_err(IntentFailure::Other)?;
        }
        let mut projection = self.projection(
            summary.session_id.to_string(),
            intent,
            "",
            false,
            false,
            None,
        )?;
        projection["lateAnswer"] = serde_json::Value::Bool(true);
        self.settle(&intent.idempotency_key, projection.clone())?;
        let sent = self
            .egress
            .deliver(
                LATE_ANSWER_HOLDING,
                self.reply_delivery(&intent.idempotency_key, None, None)
                    .map_err(reply_state_failure)?,
            )
            .is_ok();
        projection["replySent"] = serde_json::Value::Bool(sent);
        self.update_projection(&intent.idempotency_key, projection.clone())?;
        self.spawn_wake_task(wake).await;
        Ok(projection)
    }

    #[allow(clippy::too_many_arguments)]
    fn projection(
        &self,
        session: String,
        intent: &ApprovedIntentExecution,
        answer: &str,
        waiting_on_approval: bool,
        reply_sent: bool,
        reply_error: Option<String>,
    ) -> Result<serde_json::Value, IntentFailure> {
        let mut projection = serde_json::json!({
            "conversationId": self.conversation_id,
            "session": session,
            "seat": self.binding.seat_id.as_str(),
            "project": self.project.as_str(),
            "commandId": intent.command_id,
            "idempotencyKey": intent.idempotency_key,
            "answer": answer,
            "waitingOnApproval": waiting_on_approval,
            "replySent": reply_sent,
        });
        if let Some(error) = reply_error {
            projection["replyError"] = serde_json::Value::String(error);
        }
        self.stamp_prompts(&intent.idempotency_key, &mut projection)
            .map_err(reply_state_failure)?;
        Ok(projection)
    }

    /// Persists the settled projection and retires the in-flight record.
    /// The record is RELOADED: the answer wait persists delivery receipts
    /// and resolutions in its own copy while polling, and this settle
    /// must not clobber them with the caller's older snapshot.
    fn settle(
        &self,
        idempotency_key: &str,
        projection: serde_json::Value,
    ) -> Result<(), IntentFailure> {
        let mut fresh = self.load_record().map_err(IntentFailure::Other)?;
        fresh.in_flight = None;
        fresh.last_idempotency_key = Some(idempotency_key.to_owned());
        fresh.last_projection = Some(projection);
        // Settled questions leave the record; undelivered ones stay so a
        // late reply still refuses instead of flowing through as chat.
        fresh.questions.retain(|question| !question.settled);
        self.store_record(&mut fresh).map_err(IntentFailure::Other)
    }

    fn update_projection(
        &self,
        idempotency_key: &str,
        projection: serde_json::Value,
    ) -> Result<(), IntentFailure> {
        let mut fresh = self.load_record().map_err(IntentFailure::Other)?;
        if fresh.last_idempotency_key.as_deref() == Some(idempotency_key) {
            fresh.last_projection = Some(projection);
            self.store_record(&mut fresh)
                .map_err(IntentFailure::Other)?;
        }
        Ok(())
    }

    /// Retires another intent's interrupted flight without resending it. Unadmitted
    /// commands return to their intent's recovery path; admitted commands with no
    /// observable answer notify the owner of uncertainty before new work proceeds.
    pub(super) async fn settle_interrupted_in_flight(
        &self,
        record: &mut ConversationRecord,
        flight: InFlightPrompt,
    ) -> Result<(), IntentFailure> {
        if let Some(projection) = self
            .replay_delivery(&flight.idempotency_key)
            .map_err(|error| IntentFailure::Other(error.to_string()))?
        {
            record.in_flight = None;
            record.last_idempotency_key = Some(flight.idempotency_key);
            record.last_projection = Some(projection);
            return self.store_record(record).map_err(IntentFailure::Other);
        }
        let session_id = LiveSessionId::parse(&flight.session_id)
            .map_err(|error| IntentFailure::Other(format!("in-flight session invalid: {error}")))?;
        let command = flight.command().map_err(IntentFailure::Other)?;
        let admitted = self
            .plane
            .command_entry(&command)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
            .is_some();
        if !admitted {
            // Never applied: the flight is durable bookkeeping only.
            record.in_flight = None;
            return self.store_record(record).map_err(IntentFailure::Other);
        }
        let answer = self
            .observe_since(
                session_id,
                EventSeq::new(flight.event_cursor),
                Some(&command.command_id),
            )
            .await?
            .filter(|answer| !answer.trim().is_empty());
        if let Some(answer) = answer {
            let mut settled = serde_json::json!({
                "conversationId": self.conversation_id,
                "session": flight.session_id,
                "seat": self.binding.seat_id.as_str(),
                "project": self.project.as_str(),
                "commandId": flight.command_id,
                "idempotencyKey": flight.idempotency_key,
                "answer": answer,
                "waitingOnApproval": false,
                "replySent": false,
            });
            self.stamp_prompts(&flight.idempotency_key, &mut settled)
                .map_err(reply_state_failure)?;
            record.in_flight = None;
            record.last_idempotency_key = Some(flight.idempotency_key.clone());
            record.last_projection = Some(settled);
            self.reply_delivery(
                &flight.idempotency_key,
                Some(without_quiet_token(&answer)),
                record.last_projection.as_ref(),
            )
            .map_err(|error| IntentFailure::Other(error.to_string()))?;
            self.store_record(record).map_err(IntentFailure::Other)?;
            let delivered = self.deliver_final(
                &flight.idempotency_key,
                without_quiet_token(&answer),
                record.last_projection.as_ref(),
            );
            if let Some(projection) = &mut record.last_projection {
                projection["replySent"] =
                    serde_json::Value::Bool(delivered.as_ref().is_ok_and(|reply| reply.is_some()));
                if let Err(error) = delivered {
                    projection["replyError"] = serde_json::Value::String(error.to_string());
                }
            }
            return self.store_record(record).map_err(IntentFailure::Other);
        }
        // Unknown fate: the accepting run is gone and the answer is not
        // provable. Retire the flight with one plain owner sentence and
        // clear the way for the new intent.
        let notice = unknown_fate_notice(&flight.content);
        let mut unknown = serde_json::json!({
            "conversationId": self.conversation_id,
            "session": flight.session_id,
            "seat": self.binding.seat_id.as_str(),
            "project": self.project.as_str(),
            "commandId": flight.command_id,
            "idempotencyKey": flight.idempotency_key,
            "answer": "",
            "unknownFate": true,
            "waitingOnApproval": false,
            "replySent": false,
        });
        self.stamp_prompts(&flight.idempotency_key, &mut unknown)
            .map_err(reply_state_failure)?;
        record.in_flight = None;
        record.last_idempotency_key = Some(flight.idempotency_key.clone());
        record.last_projection = Some(unknown);
        self.reply_delivery(
            &flight.idempotency_key,
            Some(&notice),
            record.last_projection.as_ref(),
        )
        .map_err(|error| IntentFailure::Other(error.to_string()))?;
        self.store_record(record).map_err(IntentFailure::Other)?;
        let delivered = self.deliver_final(
            &flight.idempotency_key,
            &notice,
            record.last_projection.as_ref(),
        );
        if let Some(projection) = &mut record.last_projection {
            projection["replySent"] = serde_json::Value::Bool(delivered.is_ok());
            if let Err(error) = delivered {
                projection["replyError"] = serde_json::Value::String(error.to_string());
            }
        }
        self.store_record(record).map_err(IntentFailure::Other)
    }

    /// Clears the record's in-flight prompt for one idempotency key when
    /// the route could not settle it (the answer did not settle within
    /// its bound, the session was lost, ...): the typed failure is
    /// delivered by the reconciler, and this clears the durable flight so
    /// the NEXT intent is never refused "still settling". The record is
    /// RELOADED first — delivery receipts written by the answer wait must
    /// not be clobbered.
    fn clear_in_flight(&self, idempotency_key: &str) -> Result<(), IntentFailure> {
        let mut fresh = self.load_record().map_err(IntentFailure::Other)?;
        if fresh
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.idempotency_key == idempotency_key)
        {
            fresh.in_flight = None;
            self.store_record(&mut fresh)
                .map_err(IntentFailure::Other)?;
        }
        Ok(())
    }
}

#[async_trait]
impl ApprovedIntentRoute for ConversationRoot {
    /// Reuses recorded results and observes admitted prompts without resending;
    /// unadmitted prompts may refresh their epoch while retaining id and body.
    async fn execute(
        &self,
        intent: ApprovedIntentExecution,
    ) -> Result<serde_json::Value, IntentFailure> {
        // Queue admission transfers terminal reporting to durable wake delivery.
        let started = tokio::time::Instant::now();
        let mut phases = TurnPhases::default();
        let result = self.execute_timed(&intent, &mut phases).await;
        if result
            .as_ref()
            .is_ok_and(|projection| projection["queued"] == true)
        {
            return result;
        }
        tracing::debug!(
            "odind: conversation-turn key={} unprompted={} lock_ms={} vehicle_ms={} send_ms={} \
             answer_ms={} total_ms={} outcome={}",
            intent.idempotency_key,
            intent.unprompted,
            phases.lock_ms,
            phases.vehicle_ms,
            phases.send_ms,
            phases.answer_ms,
            started.elapsed().as_millis(),
            match &result {
                Ok(_) => "settled".to_owned(),
                Err(failure) => format!("{failure:?}"),
            },
        );
        result
    }

    /// Queues waiting owner messages together so one prompt answers the batch.
    async fn execute_batch(
        &self,
        intents: Vec<ApprovedIntentExecution>,
    ) -> Vec<Result<serde_json::Value, IntentFailure>> {
        if intents.len() < 2 || intents.iter().any(|intent| intent.unprompted) {
            let mut outcomes = Vec::with_capacity(intents.len());
            for intent in intents {
                outcomes.push(self.execute(intent).await);
            }
            return outcomes;
        }
        let outcomes = match self.queue_batch(&intents).await {
            Ok(outcomes) => outcomes,
            Err(failure) => intents.iter().map(|_| Err(failure.clone())).collect(),
        };
        for (intent, outcome) in intents.iter().zip(&outcomes) {
            if let Err(failure) = outcome {
                tracing::error!(
                    "odind: conversation-turn key={} unprompted=false queued=true outcome={failure:?}",
                    intent.idempotency_key,
                );
            }
        }
        outcomes
    }
}

/// Where one conversation turn spent its time, in milliseconds.
#[derive(Default)]
struct TurnPhases {
    lock_ms: u128,
    vehicle_ms: u128,
    send_ms: u128,
    answer_ms: u128,
}

impl ConversationRoot {
    // A refused prompt has no effects, so its owner request can wait for reload.
    async fn roll_and_resend(
        &self,
        refused: &LiveSessionSummary,
        intent: &ApprovedIntentExecution,
    ) -> Result<serde_json::Value, IntentFailure> {
        tracing::warn!(
            session = %refused.session_id,
            "odin-hermes: vehicle {} refused a turn for its context window; rolling to a \
             successor and resending",
            refused.session_id
        );
        let mut record = self.load_record().map_err(IntentFailure::Other)?;
        record.in_flight = None;
        self.store_record(&mut record)
            .map_err(IntentFailure::Other)?;
        let observed = self
            .find_session(refused.session_id, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?;
        let successor = self
            .begin_successor(
                &mut record,
                observed.as_ref().map(|summary| summary.epoch.get()),
                observed.as_ref().map(|summary| summary.event_head.get()),
            )
            .await?;
        let summary = self
            .find_session(successor, false)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
            .ok_or(IntentFailure::HistoryUnavailable)?;
        let cursor = self
            .prepare_and_send_prompt(&mut record, &summary, intent)
            .await?;
        self.observe_and_settle(&mut record, &summary, intent, cursor)
            .await
    }

    async fn execute_timed(
        &self,
        intent: &ApprovedIntentExecution,
        phases: &mut TurnPhases,
    ) -> Result<serde_json::Value, IntentFailure> {
        let intent = intent.clone();
        let mark = tokio::time::Instant::now();
        let _guard = self.lock.lock().await;
        phases.lock_ms = mark.elapsed().as_millis();
        if let Some(projection) = self
            .replay_delivery(&intent.idempotency_key)
            .map_err(|error| IntentFailure::Other(error.to_string()))?
        {
            return Ok(projection);
        }
        let mut record = self.load_record().map_err(IntentFailure::Other)?;
        if record.last_idempotency_key.as_deref() == Some(intent.idempotency_key.as_str()) {
            if let Some(projection) = &record.last_projection {
                return Ok(projection.clone());
            }
        }
        // A replayed message the queue already owns is answered there.
        if record.covered.contains(&intent.idempotency_key) {
            return Ok(self.queued_projection(&intent));
        }
        // A stale in-flight prompt from ANOTHER intent (the process died
        // mid-turn): observe what actually happened, deliver its answer
        // if one settled, and retire it. Never a resend.
        if let Some(flight) = record.in_flight.clone() {
            if flight.idempotency_key != intent.idempotency_key {
                self.settle_interrupted_in_flight(&mut record, flight)
                    .await?;
            }
        }
        let mark = tokio::time::Instant::now();
        let vehicle = self.resolve_vehicle(&mut record).await;
        phases.vehicle_ms = mark.elapsed().as_millis();
        let mut summary = vehicle?;
        // Observe a flight from the preceding session once: use its settled answer,
        // report uncertainty, or send afresh only if it was never admitted.
        if let Some(flight) = record
            .in_flight
            .clone()
            .filter(|flight| flight.idempotency_key == intent.idempotency_key)
            .filter(|flight| flight.session_id != summary.session_id.to_string())
        {
            let session = LiveSessionId::parse(&flight.session_id).map_err(|error| {
                IntentFailure::Other(format!("in-flight session invalid: {error}"))
            })?;
            let ended = self
                .find_session(session, true)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
                .is_none_or(|old| old.state == LiveSessionState::Ended);
            if ended {
                self.settle_interrupted_in_flight(&mut record, flight)
                    .await?;
                if record.last_idempotency_key.as_deref() == Some(intent.idempotency_key.as_str()) {
                    return record.last_projection.clone().ok_or_else(|| {
                        IntentFailure::Other("the retired flight left no projection".to_owned())
                    });
                }
            }
        }
        if let Some(flight) = record.in_flight.as_ref() {
            let session = LiveSessionId::parse(&flight.session_id).map_err(|error| {
                IntentFailure::Other(format!("in-flight session invalid: {error}"))
            })?;
            if session != summary.session_id {
                summary = self
                    .find_session(session, true)
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?
                    .ok_or(IntentFailure::HistoryUnavailable)?;
            }
        }
        let own_flight = record
            .in_flight
            .as_ref()
            .is_some_and(|flight| flight.idempotency_key == intent.idempotency_key);
        // Never folded into a running turn, never ahead of messages already
        // waiting: it joins the queue.
        if !own_flight
            && !intent.unprompted
            && (super::queue::busy(summary.state) || !record.queued.is_empty())
        {
            return self
                .queue_asks(&mut record, &summary, std::slice::from_ref(&intent))
                .await
                .and_then(|mut outcomes| outcomes.remove(0));
        }
        let mark = tokio::time::Instant::now();
        let outcome = match record
            .in_flight
            .clone()
            .filter(|flight| flight.idempotency_key == intent.idempotency_key)
        {
            Some(flight) => match flight.phase {
                InFlightPhase::Prepared => {
                    let mut flight = flight;
                    self.submit_prompt(&mut record, &summary, &mut flight).await
                }
                InFlightPhase::Sent => Ok(EventSeq::new(flight.event_cursor)),
            },
            None => {
                self.prepare_and_send_prompt(&mut record, &summary, &intent)
                    .await
            }
        };
        phases.send_ms = mark.elapsed().as_millis();
        let mark = tokio::time::Instant::now();
        let settled = match outcome {
            Ok(cursor) => {
                self.observe_and_settle(&mut record, &summary, &intent, cursor)
                    .await
            }
            Err(failure) => Err(failure),
        };
        let settled = match settled {
            Err(IntentFailure::ContextExhausted) => self.roll_and_resend(&summary, &intent).await,
            other => other,
        };
        phases.answer_ms = mark.elapsed().as_millis();
        // A failed provenance write/read or final freeze cannot retire admission:
        // the prompt may already be admitted, so the flight stays and a retry
        // of this key re-proves the admission rather than sending again.
        // Any other intent settles it through `settle_interrupted_in_flight`.
        if settled
            .as_ref()
            .is_err_and(|failure| *failure != IntentFailure::ReplyStateUnavailable)
        {
            // The bound failure path must never leave the flight set: a
            // set flight refuses every later intent "still settling" and
            // wedges the vehicle. The typed failure is delivered by the
            // reconciler; this clears the durable bookkeeping. A clear
            // failure is logged, never masked.
            if let Err(error) = self.clear_in_flight(intent.idempotency_key.as_str()) {
                tracing::error!(error = %error, "odin-hermes could not clear the unsettled in-flight prompt: {error}");
            }
        }
        settled
    }
}

/// The ONE plain owner sentence for an unknown-fate prompt: bounded,
/// quotes a bounded prefix of the lost content, asks for a resend.
pub(crate) fn unknown_fate_notice(content: &str) -> String {
    const BOUND: usize = 80;
    let mut prefix: String = content.trim().chars().take(BOUND).collect();
    if content.trim().chars().count() > BOUND {
        prefix.push('…');
    }
    format!("I lost track of your message '{prefix}' — can you send it again?")
}

#[cfg(test)]
mod clock_tests {
    use super::*;

    #[test]
    fn a_prompt_carries_the_owner_clock_line_ahead_of_the_message() {
        let mut flight = InFlightPrompt {
            idempotency_key: "k".to_owned(),
            content: "remind me tomorrow before class".to_owned(),
            command_id: "command:intent:k".to_owned(),
            session_id: "00000000-0000-4000-8000-000000000001".to_owned(),
            kind: InFlightKind::Prompt,
            expected_epoch: 1,
            event_cursor: 0,
            phase: InFlightPhase::Prepared,
            clock: Some("[Colin's local time: Tuesday 2026-09-29 16:52 PDT]".to_owned()),
            asks: Vec::new(),
        };
        let text = |flight: &InFlightPrompt| match flight.command().expect("command").body {
            LiveCommandBody::Prompt { message } => serde_json::to_string(&message).expect("json"),
            _ => unreachable!("prompt body"),
        };
        let with_clock = text(&flight);
        assert!(with_clock.contains("Tuesday 2026-09-29 16:52 PDT"));
        assert!(with_clock.contains("remind me tomorrow before class"));
        flight.clock = None;
        assert!(!text(&flight).contains("local time"));
    }

    #[test]
    fn every_turn_names_the_model_the_session_is_running() {
        let summary = LiveSessionSummary {
            session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000001")
                .expect("session"),
            epoch: SessionEpoch::new(2),
            seat_id: odin_domain::SeatId::new("sinmara").expect("seat"),
            provider: odin_domain::huginn::ProviderName::new("gateway").expect("provider"),
            model: odin_domain::huginn::ModelName::new("zai-glm").expect("model"),
            title: None,
            state: LiveSessionState::Idle,
            started_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            failed_at: None,
            event_head: EventSeq::new(0),
            terminal_head: odin_domain::huginn::TerminalSeq::new(0),
            pending_permission_count: 0,
        };
        assert_eq!(
            super::turn_context_line(Some("[Colin's local time: now]".to_owned()), &summary),
            "[Colin's local time: now] [You are running on gateway/zai-glm]"
        );
        assert_eq!(
            super::turn_context_line(None, &summary),
            "[You are running on gateway/zai-glm]"
        );
    }
}
