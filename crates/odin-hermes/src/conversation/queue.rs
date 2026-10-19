//! Colin's messages that arrive while a turn runs: never folded into that
//! turn (OMP holds a follow-up until the running turn ends, and its answer
//! merges into that turn's reply), but kept in the durable queue and sent
//! together, in order, as the next turn's one prompt — rapid repeats once,
//! late ones marked late — and answered in one reply that quotes them.

use odin_domain::huginn::{LiveSessionId, LiveSessionState, LiveSessionSummary};

use crate::runtime::{ApprovedIntentExecution, IntentFailure};

use super::decisions::{WakeProgress, LATE_ANSWER_BOUND};
use super::history::AnswerWait;
use super::identity::{bounded_command, now_unix_ms};
use super::prompt::{turn_context_line, without_quiet_token};
use super::{
    ConversationRecord, ConversationRoot, InFlightKind, InFlightPhase, InFlightPrompt, PendingWake,
    QueuedAsk, WakeKind, COVERED_KEYS,
};

const MAX_QUEUED: usize = 32;

/// An ask older than this when its turn starts is marked late.
const STALE_AFTER_MS: u64 = 60_000;
const QUOTE_CHARS: usize = 100;

/// What Colin hears when his message waits behind a running turn.
pub(super) const QUEUED_BEHIND_TURN: &str =
    "Got it \u{2014} I'll answer that as soon as I've finished what I'm on.";

impl QueuedAsk {
    pub(super) fn of(intent: &ApprovedIntentExecution) -> Self {
        Self {
            idempotency_key: intent.idempotency_key.clone(),
            content: intent.content.clone(),
            at_unix_ms: now_unix_ms(),
        }
    }
}

/// The session is busy with a turn an owner message must not fold into.
pub(super) fn busy(state: LiveSessionState) -> bool {
    matches!(
        state,
        LiveSessionState::Running | LiveSessionState::Starting | LiveSessionState::RequiresAction
    )
}

fn normalized(content: &str) -> String {
    content
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The asks in order, identical ones once with how often they were sent.
fn distinct(asks: &[QueuedAsk]) -> Vec<(&QueuedAsk, usize)> {
    let mut distinct: Vec<(&QueuedAsk, usize)> = Vec::new();
    for ask in asks {
        match distinct
            .iter_mut()
            .find(|(seen, _)| normalized(&seen.content) == normalized(&ask.content))
        {
            Some((_, count)) => *count += 1,
            None => distinct.push((ask, 1)),
        }
    }
    distinct
}

fn local_time(at_unix_ms: u64, zone: Option<&jiff::tz::TimeZone>) -> String {
    let Ok(at) = jiff::Timestamp::from_millisecond(i64::try_from(at_unix_ms).unwrap_or(i64::MAX))
    else {
        return String::new();
    };
    match zone {
        Some(zone) => at.to_zoned(zone.clone()).strftime("%H:%M").to_string(),
        None => at.strftime("%H:%M UTC").to_string(),
    }
}

/// The one prompt a queue's asks go out as: a single fresh ask exactly as
/// typed, otherwise every distinct ask numbered in order with when it was
/// sent, how long it has waited, and how often it was repeated.
pub(super) fn compose(
    asks: &[QueuedAsk],
    now_unix_ms: u64,
    zone: Option<&jiff::tz::TimeZone>,
) -> String {
    let distinct = distinct(asks);
    let waited = |ask: &QueuedAsk| now_unix_ms.saturating_sub(ask.at_unix_ms);
    if let [(ask, 1)] = distinct.as_slice() {
        if waited(ask) < STALE_AFTER_MS {
            return ask.content.clone();
        }
    }
    let mut text = if distinct.len() == 1 {
        "[Colin sent this while you were busy; reply to it now.]".to_owned()
    } else {
        "[Colin sent these while you were busy; reply to each, in order, in one message.]"
            .to_owned()
    };
    for (number, (ask, count)) in distinct.iter().enumerate() {
        let mut when = local_time(ask.at_unix_ms, zone);
        let minutes = waited(ask) / 60_000;
        if waited(ask) >= STALE_AFTER_MS {
            when.push_str(&format!(", {minutes} min ago"));
        }
        if *count > 1 {
            when.push_str(&format!(", sent {count} times"));
        }
        text.push_str(&format!(
            "\n{}. [{when}] {}",
            number + 1,
            ask.content.trim()
        ));
    }
    text
}

/// The lines the reply opens with, quoting what it answers.
pub(super) fn heading(asks: &[QueuedAsk]) -> String {
    distinct(asks)
        .iter()
        .map(|(ask, _)| {
            let line = ask.content.trim().lines().next().unwrap_or_default();
            let mut quoted: String = line.chars().take(QUOTE_CHARS).collect();
            if line.chars().count() > QUOTE_CHARS || ask.content.trim().lines().nth(1).is_some() {
                quoted.push('\u{2026}');
            }
            format!("> {quoted}\n")
        })
        .collect()
}

impl ConversationRecord {
    /// Adds the asks the queue does not own yet, as many as it has room
    /// for, oldest first; answers the keys of those it had no room for.
    fn enqueue(&mut self, asks: &[QueuedAsk]) -> Vec<String> {
        let fresh: Vec<&QueuedAsk> = asks
            .iter()
            .filter(|ask| {
                !self.covered.contains(&ask.idempotency_key)
                    && !self
                        .queued
                        .iter()
                        .any(|queued| queued.idempotency_key == ask.idempotency_key)
            })
            .collect();
        let room = MAX_QUEUED.saturating_sub(self.queued.len());
        let overflow = fresh
            .iter()
            .skip(room)
            .map(|ask| ask.idempotency_key.clone())
            .collect();
        for ask in fresh.into_iter().take(room) {
            self.covered.push(ask.idempotency_key.clone());
            self.queued.push(ask.clone());
        }
        // A key leaves only once its message is neither waiting nor in a
        // prompt still owed an answer.
        while self.covered.len() > COVERED_KEYS {
            let Some(index) = self.covered.iter().position(|key| !self.owes(key)) else {
                break;
            };
            self.covered.remove(index);
        }
        overflow
    }

    fn owes(&self, key: &str) -> bool {
        self.queued
            .iter()
            .any(|queued| queued.idempotency_key == key)
            || self.wakes.iter().any(|wake| {
                wake.prompt
                    .as_ref()
                    .is_some_and(|prompt| prompt.asks.iter().any(|ask| ask.idempotency_key == key))
            })
    }

    /// The asks of an unsent prompt go back to the front of the queue.
    fn requeue(&mut self, wake_id: &str) {
        let Some(wake) = self
            .wakes
            .iter_mut()
            .find(|wake| wake.command_id == wake_id)
        else {
            return;
        };
        if let Some(prompt) = wake.prompt.take() {
            self.queued.splice(0..0, prompt.asks);
        }
    }

    fn queue_wake(&self) -> Option<&PendingWake> {
        self.wakes
            .iter()
            .find(|wake| wake.kind == WakeKind::QueuedAsks && wake.prompt.is_none())
    }
}

impl ConversationRoot {
    /// The settle projection of a message the queue answers.
    pub(super) fn queued_projection(&self, intent: &ApprovedIntentExecution) -> serde_json::Value {
        serde_json::json!({
            "conversationId": self.conversation_id,
            "seat": self.binding.seat_id.as_str(),
            "project": self.project.as_str(),
            "commandId": intent.command_id,
            "idempotencyKey": intent.idempotency_key,
            "answer": "",
            "queued": true,
            "waitingOnApproval": false,
            "replySent": false,
        })
    }

    /// Messages that waited together in the reconciler join the queue.
    pub(super) async fn queue_batch(
        &self,
        intents: &[ApprovedIntentExecution],
    ) -> Result<Vec<Result<serde_json::Value, IntentFailure>>, IntentFailure> {
        let _guard = self.lock.lock().await;
        let mut record = self.load_record().map_err(IntentFailure::Other)?;
        let summary = self.resolve_vehicle(&mut record).await?;
        self.queue_asks(&mut record, &summary, intents).await
    }

    /// Colin's messages join the durable queue together with the one wake
    /// that sends them, in the same store, before any of them is reported
    /// queued. Behind a running turn he hears once that they are coming —
    /// or, behind his own open question, that question again.
    pub(super) async fn queue_asks(
        &self,
        record: &mut ConversationRecord,
        summary: &LiveSessionSummary,
        intents: &[ApprovedIntentExecution],
    ) -> Result<Vec<Result<serde_json::Value, IntentFailure>>, IntentFailure> {
        let asks: Vec<QueuedAsk> = intents.iter().map(QueuedAsk::of).collect();
        let overflow = record.enqueue(&asks);
        if !overflow.is_empty() {
            tracing::error!(
                "odind: conversation-queue full refused={} depth={} conversation={}",
                overflow.len(),
                record.queued.len(),
                self.conversation_id
            );
        }
        if overflow.len() == intents.len() {
            return Err(IntentFailure::ConversationBusy);
        }
        let first = record.queue_wake().is_none();
        let wake = self
            .arm_queue_wake(
                record,
                &summary.session_id.to_string(),
                summary.event_head.get(),
                &asks[0].idempotency_key,
            )
            .map_err(IntentFailure::Other)?;
        self.store_record(record).map_err(IntentFailure::Other)?;
        tracing::info!(
            "odind: conversation-queue queued asks={} depth={} state={:?} conversation={}",
            asks.len(),
            record.queued.len(),
            summary.state,
            self.conversation_id
        );
        let mut projections: Vec<Result<serde_json::Value, IntentFailure>> = intents
            .iter()
            .map(|intent| {
                if overflow.contains(&intent.idempotency_key) {
                    Err(IntentFailure::ConversationBusy)
                } else {
                    Ok(self.queued_projection(intent))
                }
            })
            .collect();
        if first && busy(summary.state) {
            let session = summary.session_id.to_string();
            let open_question = record
                .questions
                .iter()
                .rev()
                .find(|question| {
                    question.session_id == session
                        && !question.settled
                        && question.delivered_message_id.is_some()
                })
                .map(|question| question.prompt.clone());
            let notice = match open_question {
                Some(question) if summary.state == LiveSessionState::RequiresAction => format!(
                    "Got it \u{2014} I'll answer that once you've said yes or no to this: \
                     {question}"
                ),
                _ => QUEUED_BEHIND_TURN.to_owned(),
            };
            let sent = match self.reply_delivery(&wake.command_id, None, None) {
                Ok(delivery) => self.egress.deliver(&notice, delivery),
                Err(error) => Err(error),
            };
            if let Err(error) = &sent {
                tracing::warn!(
                    "odind: conversation-queue notice_blocked key={} error={error}",
                    wake.command_id
                );
            }
            if let Some(Ok(last)) = projections.iter_mut().rev().find(|outcome| outcome.is_ok()) {
                last["replySent"] = serde_json::Value::Bool(sent.is_ok());
            }
        }
        self.spawn_wake_task(wake).await;
        Ok(projections)
    }

    /// The queue's unsent wake, armed on the record when there is none.
    pub(super) fn arm_queue_wake(
        &self,
        record: &mut ConversationRecord,
        session_id: &str,
        cursor: u64,
        first_key: &str,
    ) -> Result<PendingWake, String> {
        if let Some(wake) = record.queue_wake() {
            return Ok(wake.clone());
        }
        let wake = PendingWake {
            command_id: bounded_command("queued", &[&self.conversation_id, first_key])?.to_string(),
            owner_keys: Vec::new(),
            kind: WakeKind::QueuedAsks,
            approved: true,
            label: String::new(),
            session_id: session_id.to_owned(),
            decision_cursor: cursor,
            approval_id: None,
            prompt: None,
            reply: None,
            completion: None,
            owner_note: None,
            rolled: false,
        };
        record.wakes.push(wake.clone());
        Ok(wake)
    }

    /// Whether anything else still owes Colin a reply first: on `session`, a
    /// late answer or a decision's continuation (spawned or only planned);
    /// anywhere, an older queue wake whose prompt or reply is still owed. A
    /// stored reply not yet delivered is owed whatever its task is doing.
    /// Without one, a failing continuation keeps its task alive while it
    /// retries and stores its sentence when it gives up, so a finished task
    /// means it is waiting on Colin, not owed ahead.
    async fn delivery_ahead(&self, record: &ConversationRecord, own: &str, session: &str) -> bool {
        let background = self.background.lock().await;
        let own_index = record
            .wakes
            .iter()
            .position(|wake| wake.command_id == own)
            .unwrap_or(record.wakes.len());
        record.wakes.iter().enumerate().any(|(index, wake)| {
            let undelivered = wake.reply.as_ref().map(|_| true);
            if wake.command_id == own || wake.completion.is_some() {
                false
            } else if wake.kind == WakeKind::QueuedAsks {
                index < own_index && undelivered.unwrap_or(wake.prompt.is_some())
            } else {
                wake.session_id == session
                    && undelivered.unwrap_or_else(|| {
                        background
                            .get(&wake.command_id)
                            .is_none_or(|handle| !handle.is_finished())
                    })
            }
        })
    }

    /// The queue's wake: once the running turn has ended and nothing else
    /// owes Colin a reply first, every queued message goes as ONE prompt and
    /// its answer is delivered, quoting them.
    pub(super) async fn run_queued(&self, requested: &PendingWake) -> Result<WakeProgress, String> {
        let deadline = tokio::time::Instant::now() + LATE_ANSWER_BOUND;
        let pause = self.poll_interval.max(std::time::Duration::from_secs(1));
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err("the queued messages are still waiting".to_owned());
            }
            let record = self.load_record()?;
            let Some(wake) = record
                .wakes
                .iter()
                .find(|wake| wake.command_id == requested.command_id)
                .cloned()
            else {
                return Ok(WakeProgress::Complete);
            };
            if let Some(prompt) = &wake.prompt {
                if prompt.phase == InFlightPhase::Sent {
                    match self.answer_queued(&wake.command_id, deadline).await? {
                        Answered::Settled(progress) => return Ok(progress),
                        Answered::Rolled => continue,
                    }
                }
            } else {
                if record
                    .rollover
                    .as_ref()
                    .is_some_and(|slot| slot.phase == super::rollover::SuccessorPhase::Pending)
                {
                    let _guard = self.lock.lock().await;
                    let mut record = self.load_record()?;
                    self.resolve_vehicle(&mut record)
                        .await
                        .map_err(|error| error.to_string())?;
                    continue;
                }
                let observed = match record.session_id.as_deref().map(LiveSessionId::parse) {
                    Some(Ok(session)) => self.find_session(session, true).await.ok().flatten(),
                    _ => None,
                };
                if observed
                    .as_ref()
                    .is_some_and(|summary| summary.state == LiveSessionState::Failed)
                {
                    return self.settle_failed_queue(&wake).await;
                }
                let session = observed
                    .as_ref()
                    .map(|summary| summary.session_id.to_string())
                    .unwrap_or_default();
                let waiting = observed.as_ref().is_some_and(|summary| busy(summary.state))
                    || self
                        .delivery_ahead(&record, &wake.command_id, &session)
                        .await;
                if waiting {
                    let wait = pause.max(std::time::Duration::from_secs(5));
                    match &observed {
                        Some(summary) => {
                            let _ = tokio::time::timeout(
                                wait,
                                self.plane
                                    .wait_for_history(summary.session_id, summary.event_head),
                            )
                            .await;
                        }
                        None => tokio::time::sleep(wait).await,
                    }
                    continue;
                }
            }
            match self.send_queued(&requested.command_id).await? {
                Sent::Accepted => {}
                Sent::Busy => tokio::time::sleep(pause).await,
                Sent::Nothing => return Ok(WakeProgress::Complete),
            }
        }
    }

    /// A Failed session will not become Idle. The queued asks are taken
    /// with the failure receipt so recovery cannot send them, and their
    /// keys replay that receipt. It is stored before it is sent, so the
    /// spawned wake delivers it once and stops.
    async fn settle_failed_queue(&self, wake: &PendingWake) -> Result<WakeProgress, String> {
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        let Some(mut stored) = record
            .wakes
            .iter()
            .find(|stored| stored.command_id == wake.command_id)
            .cloned()
        else {
            return Ok(WakeProgress::Complete);
        };
        if stored.reply.is_none() {
            // Same store as the receipt: a crash before drop_wake must not
            // leave these asks runnable, and an empty production owner list
            // must still replay this failure.
            let asks = std::mem::take(&mut record.queued);
            if stored.owner_keys.is_empty() {
                stored.owner_keys = asks.iter().map(|ask| ask.idempotency_key.clone()).collect();
            }
            stored.reply = Some(super::ContinuationReply {
                answer: "The conversation session failed, so the messages waiting on it were not \
                     sent \u{2014} send them again if you still need them."
                    .to_owned(),
                delivered: None,
                terminal_outcome: Some("session failed".to_owned()),
            });
            self.store_wake_plan(&mut record, &stored)?;
        }
        self.deliver_wake_reply(&mut record, &mut stored, None)
    }

    /// Under the lock: moves every queued message into the wake's one
    /// prompt (or takes its unsent one) and submits it on the current
    /// vehicle. A prompt the journal never admitted gives its messages back
    /// to the queue.
    async fn send_queued(&self, command_id: &str) -> Result<Sent, String> {
        let _guard = self.lock.lock().await;
        let mut record = self.load_record()?;
        let Some(mut wake) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == command_id)
            .cloned()
        else {
            return Ok(Sent::Nothing);
        };
        let summary = self
            .resolve_vehicle(&mut record)
            .await
            .map_err(|error| error.to_string())?;
        if let Some(prompt) = &wake.prompt {
            let admitted = self
                .plane
                .command_entry(&prompt.command()?)
                .await
                .map_err(|error| error.to_string())?
                .is_some();
            if admitted {
                let mut prompt = prompt.clone();
                prompt.phase = InFlightPhase::Sent;
                wake.prompt = Some(prompt);
                self.store_wake_plan(&mut record, &wake)?;
                return Ok(Sent::Accepted);
            }
            record.requeue(command_id);
            self.store_record(&mut record)?;
            wake.prompt = None;
        }
        if record.queued.is_empty() {
            return Ok(Sent::Nothing);
        }
        // Under the lock no turn is executing: a flight left on the record
        // was interrupted, and is settled the way the next message would.
        if let Some(flight) = record.in_flight.clone() {
            self.settle_interrupted_in_flight(&mut record, flight)
                .await
                .map_err(|failure| failure.to_string())?;
        }
        if summary.state == LiveSessionState::Failed {
            return Ok(Sent::Nothing);
        }
        if summary.state != LiveSessionState::Idle {
            return Ok(Sent::Busy);
        }
        let asks = std::mem::take(&mut record.queued);
        let now = jiff::Timestamp::now();
        let zone = self.clock.as_ref().map(|clock| clock.zone());
        let mut prompt = InFlightPrompt {
            idempotency_key: wake.command_id.clone(),
            content: compose(
                &asks,
                u64::try_from(now.as_millisecond()).unwrap_or_default(),
                zone.as_ref(),
            ),
            // One journal command per attempt: an unsent attempt's id is
            // never reused for different content.
            command_id: bounded_command(
                "queued-turn",
                &[&wake.command_id, &now.as_millisecond().to_string()],
            )?
            .to_string(),
            session_id: summary.session_id.to_string(),
            kind: InFlightKind::Prompt,
            expected_epoch: summary.epoch.get(),
            event_cursor: summary.event_head.get(),
            phase: InFlightPhase::Prepared,
            clock: Some(turn_context_line(
                self.clock.as_ref().map(|clock| clock.line(now)),
                &summary,
            )),
            asks,
        };
        wake.session_id = summary.session_id.to_string();
        wake.owner_keys = prompt
            .asks
            .iter()
            .map(|ask| ask.idempotency_key.clone())
            .collect();
        wake.prompt = Some(prompt.clone());
        self.store_wake_plan(&mut record, &wake)?;
        match self.submit_prompt(&mut record, &summary, &mut prompt).await {
            Ok(_) => {
                tracing::info!(
                    session = %summary.session_id,
                    "odind: conversation-queue sent asks={} session={} conversation={}",
                    prompt.asks.len(),
                    summary.session_id,
                    self.conversation_id
                );
                Ok(Sent::Accepted)
            }
            Err(failure) => {
                // Only the journal's word that it never admitted the prompt
                // gives its messages back; an unreadable journal keeps the
                // exact prompt and id for the next pass to look up again.
                match self.plane.command_entry(&prompt.command()?).await {
                    Ok(None) => {
                        let mut record = self.load_record()?;
                        record.requeue(command_id);
                        self.store_record(&mut record)?;
                    }
                    Ok(Some(_)) => {}
                    Err(error) => tracing::warn!(
                        error = %error,
                        "odind: conversation-queue admission_unknown command={} error={error}",
                        prompt.command_id
                    ),
                }
                Err(format!("the queued prompt was not sent: {failure}"))
            }
        }
    }

    fn store_wake_plan(
        &self,
        record: &mut ConversationRecord,
        wake: &PendingWake,
    ) -> Result<(), String> {
        let stored = record
            .wakes
            .iter_mut()
            .find(|plan| plan.command_id == wake.command_id)
            .ok_or_else(|| "the queue's wake has no durable plan".to_owned())?;
        *stored = wake.clone();
        self.store_record(record)
    }

    /// The queued turn outgrew the vehicle's context window: the
    /// conversation rolls to a successor (as a single message does) and the
    /// same asks go back to the front of the queue to be sent there.
    async fn roll_queued(&self, wake: &PendingWake, refused: LiveSessionId) -> Result<(), String> {
        // The asks leave the refused prompt first, so the rollover has no
        // prompt of the queue's to carry over.
        let mut record = self.load_record()?;
        record.requeue(&wake.command_id);
        self.store_record(&mut record)?;
        let observed = self
            .find_session(refused, true)
            .await
            .map_err(|error| error.to_string())?;
        let successor = self
            .begin_successor(
                &mut record,
                observed.as_ref().map(|summary| summary.epoch.get()),
                observed.as_ref().map(|summary| summary.event_head.get()),
            )
            .await
            .map_err(|error| error.to_string())?;
        let mut record = self.load_record()?;
        if let Some(stored) = record
            .wakes
            .iter_mut()
            .find(|plan| plan.command_id == wake.command_id)
        {
            stored.rolled = true;
        }
        self.store_record(&mut record)?;
        tracing::info!(
            session = %successor,
            "odind: conversation-queue rolled from={refused} to={successor} conversation={}",
            self.conversation_id
        );
        Ok(())
    }

    /// Waits — without the lock — for the queued turn to stop running, then
    /// delivers its answer under a quote of the messages it answers. The
    /// answer is read under the lock in slices, so a question the turn
    /// raised and Colin cannot be told yet never holds his next message up.
    async fn answer_queued(
        &self,
        command_id: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Answered, String> {
        let record = self.load_record()?;
        let Some(prompt) = record
            .wakes
            .iter()
            .find(|wake| wake.command_id == command_id)
            .and_then(|wake| wake.prompt.clone())
        else {
            return Ok(Answered::Settled(WakeProgress::Complete));
        };
        let session_id = LiveSessionId::parse(&prompt.session_id)
            .map_err(|error| format!("queued session invalid: {error}"))?;
        let turn = odin_domain::CommandId::new(&prompt.command_id)
            .map_err(|error| format!("queued command identity rejected: {error}"))?;
        let lost = loop {
            match self
                .find_session(session_id, true)
                .await
                .map_err(|error| error.to_string())?
            {
                None => break true,
                Some(summary)
                    if matches!(
                        summary.state,
                        LiveSessionState::Running | LiveSessionState::Starting
                    ) =>
                {
                    if tokio::time::Instant::now() >= deadline {
                        return Err("the queued turn is still running".to_owned());
                    }
                    let _ = tokio::time::timeout(
                        self.poll_interval.max(std::time::Duration::from_secs(5)),
                        self.plane.wait_for_history(session_id, summary.event_head),
                    )
                    .await;
                }
                // A Failed turn is read like any other: its journal says
                // whether it was refused (and why) or simply went down.
                Some(summary) => break summary.state == LiveSessionState::Ended,
            }
        };
        let slice = self.poll_interval.max(std::time::Duration::from_secs(1));
        loop {
            let guard = self.lock.lock().await;
            let mut record = self.load_record()?;
            let Some(mut wake) = record
                .wakes
                .iter()
                .find(|wake| wake.command_id == command_id)
                .cloned()
            else {
                return Ok(Answered::Settled(WakeProgress::Complete));
            };
            if let Some(progress) = self.replay_wake_completion(&wake) {
                return Ok(Answered::Settled(progress));
            }
            if wake.reply.is_some() {
                return self
                    .deliver_wake_reply(&mut record, &mut wake, None)
                    .map(Answered::Settled);
            }
            let mut refused = false;
            let mut terminal_outcome = None;
            let answer = if lost {
                terminal_outcome = Some(format!("{:?}", IntentFailure::VehicleLost));
                super::prompt::LATE_ANSWER_LOST.to_owned()
            } else {
                let until = (tokio::time::Instant::now() + slice).min(deadline);
                match self
                    .await_answer_until(
                        session_id,
                        odin_domain::huginn::EventSeq::new(prompt.event_cursor),
                        Some(&turn),
                        until,
                    )
                    .await
                {
                    Err(IntentFailure::AnswerTimeout) if until < deadline => {
                        drop(guard);
                        tokio::time::sleep(slice).await;
                        continue;
                    }
                    Ok(AnswerWait::Answer(answer)) if !without_quiet_token(&answer).is_empty() => {
                        without_quiet_token(&answer).to_owned()
                    }
                    Ok(AnswerWait::NeedsOwner) => {
                        // Question delivery is already durable. Persist this wake's
                        // outcome separately before emitting any per-key terminal.
                        record = self.load_record()?;
                        wake.completion = Some(super::WakeCompletion::NeedsOwner);
                        self.store_wake_plan(&mut record, &wake)?;
                        return Ok(Answered::Settled(
                            self.replay_wake_completion(&wake)
                                .expect("stored handoff completion"),
                        ));
                    }
                    Ok(AnswerWait::Answer(_) | AnswerWait::Silent) => {
                        terminal_outcome = Some(format!("{:?}", IntentFailure::SilentTurn));
                        crate::natural::natural_intent_failure(&IntentFailure::SilentTurn)
                    }
                    Ok(AnswerWait::VehicleDown) | Err(IntentFailure::VehicleLost) => {
                        terminal_outcome = Some(format!("{:?}", IntentFailure::VehicleLost));
                        super::prompt::LATE_ANSWER_LOST.to_owned()
                    }
                    Err(IntentFailure::ContextExhausted) if !wake.rolled => {
                        self.roll_queued(&wake, session_id).await?;
                        return Ok(Answered::Rolled);
                    }
                    // Only a failure to read the journal is worth another
                    // look; anything the journal settled (a refusal, a
                    // provider that turned the turn down, a closed
                    // conversation) would read the same again. Colin hears
                    // it once.
                    Err(
                        failure @ (IntentFailure::HistoryUnavailable
                        | IntentFailure::AnswerTimeout
                        | IntentFailure::ConversationBusy
                        | IntentFailure::SuccessorStartBackoff { .. }
                        | IntentFailure::Other(_)),
                    ) => return Err(failure.to_string()),
                    Err(failure) => {
                        tracing::error!(
                            error = %failure,
                            "odind: conversation-queue refused asks={} error={failure} conversation={}",
                            prompt.asks.len(),
                            self.conversation_id
                        );
                        refused = true;
                        terminal_outcome = Some(format!("{failure:?}"));
                        crate::natural::natural_intent_failure(&failure)
                    }
                }
            };
            record = self.load_record()?;
            let keys: Vec<String> = prompt
                .asks
                .iter()
                .map(|ask| ask.idempotency_key.clone())
                .collect();
            record.remember_answer_for(&keys, &answer);
            if !lost && !refused {
                self.egress.turn_answered(crate::runtime::review::Exchange {
                    seat: self.binding.seat_id.clone(),
                    session: prompt.session_id.clone(),
                    parent_session: None,
                    project: Some(self.project.clone()),
                    trigger: "turn",
                    turn_keys: keys.clone(),
                    sequence: None,
                    asked: prompt.content.clone(),
                    answered: answer.clone(),
                });
            }
            tracing::info!(
                "odind: conversation-queue answered asks={} lost={lost} conversation={}",
                keys.len(),
                self.conversation_id
            );
            wake.reply = Some(super::ContinuationReply {
                answer: format!("{}{answer}", heading(&prompt.asks)),
                delivered: None,
                terminal_outcome: Some(terminal_outcome.unwrap_or_else(|| "settled".to_owned())),
            });
            self.store_wake_plan(&mut record, &wake)?;
            return self
                .deliver_wake_reply(&mut record, &mut wake, None)
                .map(Answered::Settled);
        }
    }
}

/// How the wait for a queued turn's answer ended.
enum Answered {
    Settled(WakeProgress),
    /// The vehicle rolled to a successor; the asks wait in the queue again.
    Rolled,
}

/// What one attempt to send the queue did.
enum Sent {
    /// The journal holds the queued prompt.
    Accepted,
    /// The vehicle is busy again.
    Busy,
    /// Nothing is left to send.
    Nothing,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(key: &str, content: &str, at: u64) -> QueuedAsk {
        QueuedAsk {
            idempotency_key: key.to_owned(),
            content: content.to_owned(),
            at_unix_ms: at,
        }
    }

    #[test]
    fn one_fresh_ask_goes_out_as_typed() {
        let asks = [ask("a", "what's 17 times 23?", 1_000)];
        assert_eq!(compose(&asks, 2_000, None), "what's 17 times 23?");
        assert_eq!(heading(&asks), "> what's 17 times 23?\n");
    }

    #[test]
    fn rapid_repeats_go_once_and_late_asks_are_marked_late() {
        let minute = 60_000;
        let asks = [
            ask("a", "what's 17 times 23?", 0),
            ask("b", "ping", 4 * minute),
            ask("c", "Ping ", 4 * minute + 1_000),
            ask("d", "ping", 4 * minute + 2_000),
            ask("e", "café 日本語", 4 * minute + 3_000),
        ];
        let text = compose(&asks, 4 * minute + 10_000, None);
        assert_eq!(
            text,
            "[Colin sent these while you were busy; reply to each, in order, in one message.]\n\
             1. [00:00 UTC, 4 min ago] what's 17 times 23?\n\
             2. [00:04 UTC, sent 3 times] ping\n\
             3. [00:04 UTC] café 日本語"
        );
        assert_eq!(
            heading(&asks),
            "> what's 17 times 23?\n> ping\n> café 日本語\n"
        );
    }

    #[test]
    fn one_ask_that_waited_is_marked_late() {
        let text = compose(&[ask("a", "ping", 0)], 3 * 60_000, None);
        assert_eq!(
            text,
            "[Colin sent this while you were busy; reply to it now.]\n1. [00:00 UTC, 3 min ago] ping"
        );
    }

    #[test]
    fn the_queue_owns_each_message_once() {
        let mut record: ConversationRecord = serde_json::from_value(serde_json::json!({
            "conversationId": "c", "seat": "s", "project": "p",
            "vehicleCommandId": null, "sessionId": null, "inFlight": null, "wakes": [],
            "lastIdempotencyKey": null, "lastProjection": null, "questions": [],
            "updatedAtUnixMs": 0
        }))
        .expect("record");
        record.enqueue(&[ask("a", "x", 0)]);
        record.enqueue(&[ask("a", "x", 0), ask("b", "y", 0)]);
        assert_eq!(record.queued.len(), 2);
        record.queued.clear();
        record.enqueue(&[ask("a", "x", 0)]);
        assert!(
            record.queued.is_empty(),
            "a sent message never queues again"
        );
        let many: Vec<QueuedAsk> = (0..=MAX_QUEUED)
            .map(|n| ask(&format!("k{n}"), "z", 0))
            .collect();
        assert_eq!(
            record.enqueue(&many),
            vec![format!("k{MAX_QUEUED}")],
            "only the overflow is refused"
        );
        assert_eq!(record.queued.len(), MAX_QUEUED);
    }

    /// A key stays remembered while its message still waits, however many
    /// keys came after it.
    #[test]
    fn a_waiting_message_is_never_forgotten() {
        let mut record: ConversationRecord = serde_json::from_value(serde_json::json!({
            "conversationId": "c", "seat": "s", "project": "p",
            "vehicleCommandId": null, "sessionId": null, "inFlight": null, "wakes": [],
            "lastIdempotencyKey": null, "lastProjection": null, "questions": [],
            "updatedAtUnixMs": 0
        }))
        .expect("record");
        record.enqueue(&[ask("waiting", "x", 0)]);
        for n in 0..COVERED_KEYS + 10 {
            record.enqueue(&[ask(&format!("k{n}"), "y", 0)]);
            record
                .queued
                .retain(|queued| queued.idempotency_key == "waiting");
        }
        assert!(record.covered.contains(&"waiting".to_owned()));
        assert!(record.covered.len() <= COVERED_KEYS);
        record.enqueue(&[ask("waiting", "x", 0)]);
        assert_eq!(record.queued.len(), 1, "a replay never queues it twice");
    }

    #[test]
    fn a_message_in_an_unanswered_prompt_is_never_forgotten() {
        let mut record: ConversationRecord = serde_json::from_value(serde_json::json!({
            "conversationId": "c", "seat": "s", "project": "p",
            "vehicleCommandId": null, "sessionId": null, "inFlight": null,
            "wakes": [{
                "commandId": "command:queued:x", "kind": "queuedAsks", "approved": true,
                "label": "", "sessionId": "s", "decisionCursor": 0, "approvalId": null,
                "prompt": {
                    "idempotencyKey": "command:queued:x", "content": "x",
                    "commandId": "command:queued-turn:x", "sessionId": "s", "kind": "prompt",
                    "expectedEpoch": 1, "eventCursor": 0, "phase": "sent",
                    "asks": [{"idempotencyKey": "sent", "content": "x", "atUnixMs": 0}]
                }
            }],
            "covered": ["sent"],
            "lastIdempotencyKey": null, "lastProjection": null, "questions": [],
            "updatedAtUnixMs": 0
        }))
        .expect("record");
        for n in 0..COVERED_KEYS + 10 {
            record.enqueue(&[ask(&format!("k{n}"), "y", 0)]);
            record.queued.clear();
        }
        assert!(record.covered.contains(&"sent".to_owned()));
        record.enqueue(&[ask("sent", "x", 0)]);
        assert!(record.queued.is_empty(), "a replay never queues it again");
    }

    #[test]
    fn an_answered_message_outlives_many_later_ones() {
        let mut record: ConversationRecord = serde_json::from_value(serde_json::json!({
            "conversationId": "c", "seat": "s", "project": "p",
            "vehicleCommandId": null, "sessionId": null, "inFlight": null, "wakes": [],
            "lastIdempotencyKey": null, "lastProjection": null, "questions": [],
            "updatedAtUnixMs": 0
        }))
        .expect("record");
        record.enqueue(&[ask("answered", "x", 0)]);
        record.queued.clear();
        for n in 0..200 {
            record.enqueue(&[ask(&format!("k{n}"), "y", 0)]);
            record.queued.clear();
        }
        record.enqueue(&[ask("answered", "x", 0)]);
        assert!(record.queued.is_empty(), "a replay never queues it again");
    }
}
