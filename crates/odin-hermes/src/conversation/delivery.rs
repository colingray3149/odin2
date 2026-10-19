//! Persists reply text and links it to the live journal's prompt and tool events.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_ledger::conversation_delivery::ConversationDeliveryRow;
use odin_ledger::Ledger;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::discord::{DiscordMessageRef, DiscordSendError, MAX_MESSAGE_CODEPOINTS};
use crate::egress::{
    split_reply, DeliveryCheckpoint, DeliveryOperation, DeliveryPlan, DeliveryReservation,
    EgressError, OutboundMessage, ReplyChunks,
};

use super::{identity::bounded_command, ConversationRoot};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Open,
    Finalizing,
    Committed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Chunk {
    reference: DiscordMessageRef,
    content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pending {
    sequence: u64,
    dispatcher_pid: u32,
    operation: DeliveryOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdmittedPrompt {
    session: String,
    command_id: String,
}

fn stamp_prompts(projection: &mut serde_json::Value, prompts: &[AdmittedPrompt]) {
    if let (false, Some(object)) = (prompts.is_empty(), projection.as_object_mut()) {
        object.insert(
            "promptCommands".to_owned(),
            serde_json::to_value(prompts).unwrap_or_default(),
        );
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct State {
    conversation: String,
    key: String,
    channel: String,
    phase: Phase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    prompts: Vec<AdmittedPrompt>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    legacy_unknown: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_answer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    projection: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    target: Vec<String>,
    #[serde(default)]
    final_rendered: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chunks: Vec<Chunk>,
    generation: u64,
    sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<Pending>,
}

fn failure(error: impl std::fmt::Display) -> EgressError {
    EgressError::DeliveryState(error.to_string())
}

fn decode(row: &ConversationDeliveryRow) -> Result<State, EgressError> {
    let state: State = serde_json::from_str(&row.state_json).map_err(failure)?;
    if delivery_id(&state.conversation, &state.key)? != row.object_id
        || state.channel.is_empty()
        || state.chunks.iter().any(|chunk| {
            chunk.reference.channel_id != state.channel || chunk.reference.message_id.is_empty()
        })
        || state.alias.as_deref() == Some(state.key.as_str())
    {
        return Err(failure("durable reply identity does not match its owner"));
    }
    Ok(state)
}

fn delivery_id(conversation: &str, key: &str) -> Result<String, EgressError> {
    bounded_command("conversation-delivery", &[conversation, key])
        .map(|id| id.to_string())
        .map_err(failure)
}

fn ownership(state: &State) -> Option<ReplyChunks> {
    let mut refs = state.chunks.iter().map(|chunk| chunk.reference.clone());
    Some(ReplyChunks {
        anchor: refs.next()?,
        tails: refs.collect(),
    })
}

fn operations(state: &State) -> Vec<DeliveryOperation> {
    let mut operations = Vec::new();
    for (index, content) in state.target.iter().enumerate() {
        match state.chunks.get(index) {
            Some(chunk) if chunk.content == *content => {}
            Some(chunk) => operations.push(DeliveryOperation::Patch {
                index,
                reference: chunk.reference.clone(),
                content: content.clone(),
            }),
            None => operations.push(DeliveryOperation::Post {
                index,
                content: content.clone(),
            }),
        }
    }
    operations.extend(state.chunks.iter().skip(state.target.len()).map(|chunk| {
        DeliveryOperation::Delete {
            reference: chunk.reference.clone(),
        }
    }));
    operations
}

fn next_operation_matches(state: &State, operation: &DeliveryOperation) -> bool {
    for (index, content) in state.target.iter().enumerate() {
        match state.chunks.get(index) {
            Some(chunk) if chunk.content == *content => continue,
            Some(chunk) => {
                return matches!(operation, DeliveryOperation::Patch { index: candidate, reference, content: body }
                if *candidate == index && *reference == chunk.reference && body == content)
            }
            None => {
                return matches!(operation, DeliveryOperation::Post { index: candidate, content: body }
                if *candidate == index && body == content)
            }
        }
    }
    state.chunks.get(state.target.len()).is_some_and(|chunk| {
        matches!(operation, DeliveryOperation::Delete { reference } if *reference == chunk.reference)
    })
}

/// What one durable reply still owes, from its row alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplyDisposition {
    /// Committed, never finalized, or owned by its primary key.
    NotOwed,
    /// A frozen final with known-unsent work and no reservation in doubt.
    Resumable,
    /// A reservation's outcome is unknown: only reconciliation may proceed.
    Unknown,
}

fn disposition(state: &State) -> ReplyDisposition {
    if state.alias.is_some() || state.phase != Phase::Finalizing {
        ReplyDisposition::NotOwed
    } else if state.pending.is_some() || state.legacy_unknown {
        ReplyDisposition::Unknown
    } else {
        ReplyDisposition::Resumable
    }
}

fn physical_complete(state: &State) -> bool {
    state.chunks.len() == state.target.len()
        && state
            .chunks
            .iter()
            .zip(&state.target)
            .all(|(chunk, target)| chunk.content == *target)
}

/// Projects a final reply after its caller has proved every physical operation.
fn commit_final(state: &mut State) {
    state.phase = Phase::Committed;
    if let Some(projection) = &mut state.projection {
        projection["replySent"] = serde_json::Value::Bool(true);
        if let Some(object) = projection.as_object_mut() {
            object.remove("replyError");
        }
    }
}

fn persist(
    ledger: &mut Ledger,
    row: &ConversationDeliveryRow,
    state: &State,
) -> Result<(), EgressError> {
    let json = serde_json::to_string(state).map_err(failure)?;
    ledger
        .cas_conversation_delivery(
            &row.object_id,
            row.revision,
            &json,
            OffsetDateTime::now_utc(),
        )
        .map_err(failure)?;
    Ok(())
}

/// The stored fate wins over fresh dispatch admission. Only a resumable
/// reply needs owned content and a new dispatch handle.
pub(crate) enum ScheduledReply {
    Resumable {
        checkpoint: Arc<ReplyDelivery>,
        content: String,
    },
    Delivered(ReplyChunks),
    Unknown,
}

/// What a stopped scheduled send already proved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScheduledSeal {
    /// Every physical chunk was acknowledged. The final commit may still be owed.
    Acknowledged,
    /// The send may exist. A later open must not resume it.
    Unknown,
}

/// Concurrent writes a seal re-reads before giving up.
const SEAL_ATTEMPTS: usize = 8;

/// A handle is bound to one rendered generation. Loading a reservation never
/// recreates permission to dispatch it.
pub struct ReplyDelivery {
    ledger_path: PathBuf,
    id: String,
    final_answer: Option<String>,
    generation: Mutex<Option<u64>>,
    /// Opened by [`Self::open_scheduled`]: an unknown outcome is never resent.
    scheduled: bool,
}

impl ReplyDelivery {
    fn ledger(&self) -> Result<Ledger, EgressError> {
        Ledger::open(&self.ledger_path).map_err(failure)
    }

    fn load(&self, ledger: &Ledger) -> Result<(ConversationDeliveryRow, State), EgressError> {
        let row = ledger
            .conversation_delivery(&self.id)
            .map_err(failure)?
            .ok_or_else(|| failure("durable reply is missing"))?;
        let state = decode(&row)?;
        Ok((row, state))
    }

    /// Opens (creating if absent) the durable row once and decodes it, with
    /// no answer bound to the handle yet.
    fn begin(
        ledger_path: &Path,
        conversation: &str,
        channel: &str,
        key: &str,
    ) -> Result<(Self, Ledger, ConversationDeliveryRow, State), EgressError> {
        let id = delivery_id(conversation, key)?;
        let handle = Self {
            ledger_path: ledger_path.to_owned(),
            id,
            final_answer: None,
            generation: Mutex::new(None),
            scheduled: false,
        };
        let initial = State {
            conversation: conversation.to_owned(),
            key: key.to_owned(),
            channel: channel.to_owned(),
            phase: Phase::Open,
            alias: None,
            prompts: Vec::new(),
            legacy_unknown: false,
            final_answer: None,
            projection: None,
            target: Vec::new(),
            final_rendered: false,
            chunks: Vec::new(),
            generation: 0,
            sequence: 0,
            pending: None,
        };
        let mut ledger = handle.ledger()?;
        let row = ledger
            .open_conversation_delivery(
                &handle.id,
                &serde_json::to_string(&initial).map_err(failure)?,
                OffsetDateTime::now_utc(),
            )
            .map_err(failure)?;
        let state = decode(&row)?;
        if state.channel != channel || state.alias.is_some() {
            return Err(failure("reply belongs to a different owner channel"));
        }
        Ok((handle, ledger, row, state))
    }

    /// Freezes `answer` as the reply's final answer, or accepts the one an
    /// earlier open already froze when it is identical.
    fn freeze(
        ledger: &mut Ledger,
        row: &ConversationDeliveryRow,
        state: &mut State,
        answer: &str,
        projection: Option<&serde_json::Value>,
    ) -> Result<(), EgressError> {
        match state.phase {
            Phase::Open => {
                state.phase = Phase::Finalizing;
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| failure("reply generation overflow"))?;
                state.final_answer = Some(answer.to_owned());
                let mut frozen = projection.cloned();
                if let Some(frozen) = &mut frozen {
                    stamp_prompts(frozen, &state.prompts);
                }
                state.projection = frozen;
                persist(ledger, row, state)
            }
            Phase::Finalizing | Phase::Committed
                if state.final_answer.as_deref() == Some(answer) =>
            {
                Ok(())
            }
            _ => Err(failure("a different final answer already owns this turn")),
        }
    }

    pub(crate) fn open(
        ledger_path: &Path,
        conversation: &str,
        channel: &str,
        key: &str,
        final_answer: Option<&str>,
        projection: Option<&serde_json::Value>,
    ) -> Result<Arc<Self>, EgressError> {
        let (mut handle, mut ledger, row, mut state) =
            Self::begin(ledger_path, conversation, channel, key)?;
        handle.final_answer = final_answer.map(str::to_owned);
        if let Some(answer) = final_answer {
            Self::freeze(&mut ledger, &row, &mut state, answer, projection)?;
        } else if state.phase != Phase::Open {
            return Err(failure("the reply is already finalizing"));
        }
        Ok(Arc::new(handle))
    }

    /// Opens a reply whose bytes are fixed by its first attempt and reports
    /// what the durable row already says, from one read of it. A row with no
    /// frozen answer is rendered by `render` and frozen; a frozen one keeps
    /// its bytes and `render` is never called. The reported fate is the
    /// stored one — a receipt or an unknown operation — whatever the caller's
    /// ability to dispatch now.
    pub(crate) fn open_scheduled(
        ledger_path: &Path,
        conversation: &str,
        channel: &str,
        key: &str,
        render: impl FnOnce() -> String,
    ) -> Result<ScheduledReply, EgressError> {
        let (mut handle, mut ledger, row, mut state) =
            Self::begin(ledger_path, conversation, channel, key)?;
        if state.phase != Phase::Open && state.final_answer.is_none() {
            return Err(failure("a frozen reply has no final answer"));
        }
        if state.pending.is_some() || state.legacy_unknown {
            return Ok(ScheduledReply::Unknown);
        }
        if state.phase == Phase::Finalizing && state.final_rendered && physical_complete(&state) {
            commit_final(&mut state);
            persist(&mut ledger, &row, &state)?;
        }
        if state.phase == Phase::Committed {
            return Ok(ownership(&state).map_or(ScheduledReply::Unknown, ScheduledReply::Delivered));
        }
        let content = if state.phase == Phase::Open {
            let content = render();
            Self::freeze(&mut ledger, &row, &mut state, &content, None)?;
            content
        } else {
            state
                .final_answer
                .as_ref()
                .expect("validated frozen answer")
                .clone()
        };
        handle.final_answer = state.final_answer.take();
        handle.scheduled = true;
        Ok(ScheduledReply::Resumable {
            checkpoint: Arc::new(handle),
            content,
        })
    }

    /// Records that a scheduled send stopped before its outcome was known.
    /// An already-acknowledged row stays resumable so its final commit can
    /// finish; anything less is sealed so a later open cannot post it again.
    pub(crate) fn seal_unobserved(
        ledger_path: &Path,
        conversation: &str,
        channel: &str,
        key: &str,
    ) -> Result<ScheduledSeal, EgressError> {
        let (handle, mut ledger, mut row, mut state) =
            Self::begin(ledger_path, conversation, channel, key)?;
        // The abandoned worker may still be writing this row; re-read when it moves.
        for _ in 0..SEAL_ATTEMPTS {
            if state.phase == Phase::Committed
                || (state.phase == Phase::Finalizing
                    && state.final_rendered
                    && state.pending.is_none()
                    && !state.legacy_unknown
                    && physical_complete(&state))
            {
                return Ok(ScheduledSeal::Acknowledged);
            }
            if state.pending.is_some() || state.legacy_unknown {
                return Ok(ScheduledSeal::Unknown);
            }
            state.legacy_unknown = true;
            let json = serde_json::to_string(&state).map_err(failure)?;
            match ledger.cas_conversation_delivery(
                &row.object_id,
                row.revision,
                &json,
                OffsetDateTime::now_utc(),
            ) {
                Ok(_) => return Ok(ScheduledSeal::Unknown),
                Err(odin_ledger::LedgerError::StaleActor { .. }) => {
                    (row, state) = handle.load(&ledger)?;
                }
                Err(error) => return Err(failure(error)),
            }
        }
        Err(failure(format!(
            "scheduled delivery {key} changed on every one of {SEAL_ATTEMPTS} seal attempts"
        )))
    }

    pub(super) fn result(&self) -> Result<Option<ReplyChunks>, EgressError> {
        let ledger = self.ledger()?;
        let (_, state) = self.load(&ledger)?;
        if state.phase != Phase::Committed {
            return Err(failure("reply delivery is not committed"));
        }
        Ok(ownership(&state))
    }

    pub(super) fn quiet(&self) -> Result<(), EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        if state.pending.is_some() || !state.chunks.is_empty() {
            return Err(failure("a visible reply cannot be committed as quiet"));
        }
        if state.phase == Phase::Committed {
            return Ok(());
        }
        if state.phase != Phase::Finalizing || state.final_answer.as_deref() != Some("") {
            return Err(failure("quiet reply was not selected"));
        }
        state.phase = Phase::Committed;
        if let Some(projection) = &mut state.projection {
            projection["replySent"] = serde_json::Value::Bool(false);
            projection["quiet"] = serde_json::Value::Bool(true);
        }
        persist(&mut ledger, &row, &state)
    }
}

impl DeliveryCheckpoint for ReplyDelivery {
    fn prepare(&self, message: &OutboundMessage) -> Result<DeliveryPlan, EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        if state.channel != message.channel_id {
            return Err(failure("reply dispatch channel changed"));
        }
        // A send whose daemon died before it settled (a restart mid-send)
        // is resent: a possible duplicate line beats a conversation that
        // never answers. Only this daemon's own send in flight refuses.
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.dispatcher_pid == std::process::id())
        {
            return Err(failure("a send of this reply is still in flight"));
        }
        // A scheduled send sealed unknown (its caller gave up on this worker) is never resent.
        if self.scheduled && (state.pending.is_some() || state.legacy_unknown) {
            return Err(failure(
                "a scheduled send with an unknown outcome is never resent",
            ));
        }
        if state.pending.is_some() || state.legacy_unknown {
            tracing::warn!(
                "odind: conversation-delivery key={} outcome unknown after a restart; resending",
                state.key
            );
            state.pending = None;
            state.legacy_unknown = false;
            persist(&mut ledger, &row, &state)?;
        }
        if state.phase != Phase::Open && state.final_answer != self.final_answer {
            return Err(failure(
                "stale streaming reply cannot replace the final answer",
            ));
        }
        let chunks = split_reply(&message.content, MAX_MESSAGE_CODEPOINTS);
        if state.phase == Phase::Committed || state.final_rendered {
            // The durable bytes win over a changed scrub vocabulary after restart.
        } else {
            if state.target != chunks {
                state.target = chunks;
                state.generation = state
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| failure("reply generation overflow"))?;
            }
            state.final_rendered = state.phase == Phase::Finalizing;
            persist(&mut ledger, &row, &state)?;
        }
        *self.generation.lock().map_err(failure)? = Some(state.generation);
        Ok(DeliveryPlan {
            chunks: state.target.clone(),
            ownership: ownership(&state),
            operations: operations(&state),
        })
    }

    fn reserve(&self, operation: &DeliveryOperation) -> Result<DeliveryReservation, EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        if state.phase == Phase::Committed
            || state.pending.is_some()
            || state.legacy_unknown
            || (state.phase != Phase::Open && state.final_answer != self.final_answer)
            || *self.generation.lock().map_err(failure)? != Some(state.generation)
            || !next_operation_matches(&state, operation)
        {
            return Err(failure("reply operation lost its reservation race"));
        }
        state.sequence = state
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure("reply operation sequence overflow"))?;
        state.pending = Some(Pending {
            sequence: state.sequence,
            dispatcher_pid: std::process::id(),
            operation: operation.clone(),
        });
        persist(&mut ledger, &row, &state)?;
        Ok(DeliveryReservation {
            sequence: state.sequence,
        })
    }

    fn acknowledge(
        &self,
        reservation: &DeliveryReservation,
        reference: Option<&DiscordMessageRef>,
    ) -> Result<(), EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        apply_ack(&mut state, reservation.sequence, reference)?;
        persist(&mut ledger, &row, &state)
    }

    fn failed(
        &self,
        reservation: &DeliveryReservation,
        error: &DiscordSendError,
    ) -> Result<(), EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        if state.pending.as_ref().map(|pending| pending.sequence) != Some(reservation.sequence) {
            return Err(failure("reply failure belongs to a stale operation"));
        }
        if matches!(
            error,
            DiscordSendError::CredentialsUnavailable
                | DiscordSendError::GatewayNotOwned
                | DiscordSendError::Unreachable
                | DiscordSendError::RateLimited { .. }
                | DiscordSendError::Rejected { .. }
        ) {
            state.pending = None;
            persist(&mut ledger, &row, &state)?;
        }
        Ok(())
    }

    fn complete(&self) -> Result<(), EgressError> {
        let mut ledger = self.ledger()?;
        let (row, mut state) = self.load(&ledger)?;
        if state.pending.is_some()
            || state.legacy_unknown
            || !physical_complete(&state)
            || *self.generation.lock().map_err(failure)? != Some(state.generation)
            || (state.phase == Phase::Finalizing
                && (!state.final_rendered || state.final_answer != self.final_answer))
        {
            return Err(failure("reply has unacknowledged physical operations"));
        }
        if state.phase == Phase::Finalizing {
            commit_final(&mut state);
            persist(&mut ledger, &row, &state)?;
        }
        Ok(())
    }
}

fn apply_ack(
    state: &mut State,
    sequence: u64,
    reference: Option<&DiscordMessageRef>,
) -> Result<(), EgressError> {
    let pending = state
        .pending
        .as_ref()
        .filter(|pending| pending.sequence == sequence)
        .ok_or_else(|| failure("reply acknowledgement belongs to a stale operation"))?;
    match &pending.operation {
        DeliveryOperation::Post { index, content } => {
            let reference = reference
                .filter(|reference| {
                    reference.channel_id == state.channel && !reference.message_id.is_empty()
                })
                .ok_or_else(|| failure("POST acknowledgement has no matching message identity"))?;
            if *index != state.chunks.len() {
                return Err(failure("POST acknowledgement is out of order"));
            }
            state.chunks.push(Chunk {
                reference: reference.clone(),
                content: content.clone(),
            });
        }
        DeliveryOperation::Patch {
            index,
            reference: expected,
            content,
        } => {
            if reference != Some(expected) {
                return Err(failure("PATCH acknowledgement changed message identity"));
            }
            let chunk = state
                .chunks
                .get_mut(*index)
                .filter(|chunk| chunk.reference == *expected)
                .ok_or_else(|| failure("PATCH no longer owns its chunk"))?;
            chunk.content.clone_from(content);
        }
        DeliveryOperation::Delete {
            reference: expected,
        } => {
            if reference.is_some() {
                return Err(failure(
                    "DELETE acknowledgement unexpectedly names a message",
                ));
            }
            let index = state
                .chunks
                .iter()
                .position(|chunk| chunk.reference == *expected)
                .ok_or_else(|| failure("DELETE no longer owns its chunk"))?;
            state.chunks.remove(index);
        }
    }
    state.pending = None;
    Ok(())
}

impl ConversationRoot {
    pub(super) fn reply_delivery(
        &self,
        key: &str,
        answer: Option<&str>,
        projection: Option<&serde_json::Value>,
    ) -> Result<Arc<ReplyDelivery>, EgressError> {
        ReplyDelivery::open(
            &self.ledger_path,
            &self.conversation_id,
            &self.owner.channel_id,
            key,
            answer,
            projection,
        )
    }

    pub(super) fn record_admitted_prompt(
        &self,
        key: &str,
        session: &str,
        command_id: &str,
    ) -> Result<(), EgressError> {
        let (_, mut ledger, row, mut state) = ReplyDelivery::begin(
            &self.ledger_path,
            &self.conversation_id,
            &self.owner.channel_id,
            key,
        )?;
        if state
            .prompts
            .iter()
            .any(|held| held.session == session && held.command_id == command_id)
        {
            return Ok(());
        }
        if state.phase != Phase::Open {
            return Err(failure(
                "a frozen reply cannot take a different admitted prompt",
            ));
        }
        state.prompts.push(AdmittedPrompt {
            session: session.to_owned(),
            command_id: command_id.to_owned(),
        });
        persist(&mut ledger, &row, &state)
    }

    pub(super) fn stamp_prompts(
        &self,
        key: &str,
        projection: &mut serde_json::Value,
    ) -> Result<(), EgressError> {
        let ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let id = delivery_id(&self.conversation_id, key)?;
        if let Some(row) = ledger.conversation_delivery(&id).map_err(failure)? {
            stamp_prompts(projection, &decode(&row)?.prompts);
        }
        Ok(())
    }

    /// The committed chunk texts of one logical reply, following an alias to
    /// its primary. Absent while the row is missing, still open, or marked
    /// sent-false: a finished task can still be queued. Never posts, edits,
    /// or resumes delivery.
    pub fn committed_reply(&self, key: &str) -> Result<Option<Vec<String>>, EgressError> {
        self.committed_reply_at(key, 0)
    }

    fn committed_reply_at(&self, key: &str, depth: u8) -> Result<Option<Vec<String>>, EgressError> {
        if depth > 8 {
            return Err(failure("reply alias chain is too deep"));
        }
        let ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let id = delivery_id(&self.conversation_id, key)?;
        let Some(row) = ledger.conversation_delivery(&id).map_err(failure)? else {
            return Ok(None);
        };
        let state = decode(&row)?;
        if let Some(primary) = state.alias.clone() {
            return self.committed_reply_at(&primary, depth + 1);
        }
        if state.phase != Phase::Committed {
            return Ok(None);
        }
        let sent = state
            .projection
            .as_ref()
            .and_then(|projection| projection.get("replySent"))
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if !sent {
            return Ok(None);
        }
        let chunks: Vec<String> = state
            .chunks
            .iter()
            .map(|chunk| chunk.content.clone())
            .filter(|text| !text.trim().is_empty())
            .collect();
        if !chunks.is_empty() {
            return Ok(Some(chunks));
        }
        Ok(state
            .final_answer
            .filter(|text| !text.trim().is_empty())
            .map(|text| vec![text]))
    }

    pub(super) fn deliver_final(
        &self,
        key: &str,
        answer: &str,
        projection: Option<&serde_json::Value>,
    ) -> Result<Option<ReplyChunks>, EgressError> {
        let delivery = self.reply_delivery(key, Some(answer), projection)?;
        if let Ok(committed) = delivery.result() {
            return Ok(committed);
        }
        if answer.is_empty() {
            delivery.quiet()?;
            return Ok(None);
        }
        self.egress.deliver(answer, delivery).map(Some)
    }

    pub(super) fn replay_delivery(
        &self,
        key: &str,
    ) -> Result<Option<serde_json::Value>, EgressError> {
        let ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let id = delivery_id(&self.conversation_id, key)?;
        let Some(row) = ledger.conversation_delivery(&id).map_err(failure)? else {
            return Ok(None);
        };
        let state = decode(&row)?;
        if let Some(primary) = &state.alias {
            let mut projection = self.replay_delivery(primary)?;
            if let Some(projection) = &mut projection {
                projection["idempotencyKey"] = serde_json::Value::String(key.to_owned());
            }
            return Ok(projection);
        }
        if state.phase == Phase::Open {
            return Ok(None);
        }
        let Some(mut projection) = state.projection else {
            return Ok(None);
        };
        let answer = state
            .final_answer
            .ok_or_else(|| failure("final reply has no selected answer"))?;
        let result = self.deliver_final(key, &answer, Some(&projection));
        projection["replySent"] =
            serde_json::Value::Bool(result.as_ref().is_ok_and(|reply| reply.is_some()));
        if let Err(error) = result {
            projection["replyError"] = serde_json::Value::String(error.to_string());
        }
        Ok(Some(projection))
    }

    /// The durable row's own answer to "may this reply be resumed?" — never
    /// a guess from a transport error.
    pub(super) fn reply_disposition(&self, key: &str) -> Result<ReplyDisposition, EgressError> {
        let ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let id = delivery_id(&self.conversation_id, key)?;
        let Some(row) = ledger.conversation_delivery(&id).map_err(failure)? else {
            return Ok(ReplyDisposition::NotOwed);
        };
        let state = decode(&row)?;
        if state.channel != self.owner.channel_id {
            return Err(failure("recovered reply channel changed"));
        }
        Ok(disposition(&state))
    }

    pub(super) fn link_delivery_keys(
        &self,
        primary: &str,
        keys: &[String],
    ) -> Result<(), EgressError> {
        let mut ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let primary_id = delivery_id(&self.conversation_id, primary)?;
        let row = ledger
            .conversation_delivery(&primary_id)
            .map_err(failure)?
            .ok_or_else(|| failure("primary reply is not durable"))?;
        let source = decode(&row)?;
        if source.alias.is_some() {
            return Err(failure("reply aliases cannot chain"));
        }
        for key in keys.iter().filter(|key| key.as_str() != primary) {
            let id = delivery_id(&self.conversation_id, key)?;
            let mut alias = source.clone();
            alias.key.clone_from(key);
            alias.alias = Some(primary.to_owned());
            alias.chunks.clear();
            alias.target.clear();
            alias.pending = None;
            alias.prompts.clear();
            alias.projection = None;
            alias.final_answer = None;
            let row = ledger
                .open_conversation_delivery(
                    &id,
                    &serde_json::to_string(&alias).map_err(failure)?,
                    OffsetDateTime::now_utc(),
                )
                .map_err(failure)?;
            // A key that already owns a reply (e.g. one opened before a
            // daemon restart) keeps it; the batch answer still delivers once
            // under the primary key, so nothing queued waits behind it.
            if decode(&row)?.alias.as_deref() != Some(primary) {
                tracing::warn!(
                    "odind: conversation-delivery key={key} already owns a reply; not aliased to {primary}"
                );
            }
        }
        Ok(())
    }

    pub(super) fn import_legacy_delivery(
        &self,
        key: &str,
        owned: Option<&ReplyChunks>,
        uncertain: bool,
    ) -> Result<(), EgressError> {
        let initial = State {
            conversation: self.conversation_id.clone(),
            key: key.to_owned(),
            channel: self.owner.channel_id.clone(),
            phase: Phase::Open,
            alias: None,
            prompts: Vec::new(),
            legacy_unknown: uncertain,
            final_answer: None,
            projection: None,
            target: Vec::new(),
            final_rendered: false,
            chunks: owned
                .into_iter()
                .flat_map(ReplyChunks::refs)
                .map(|reference| Chunk {
                    reference: reference.clone(),
                    content: String::new(),
                })
                .collect(),
            generation: 0,
            sequence: 0,
            pending: None,
        };
        let mut ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        ledger
            .open_conversation_delivery(
                &delivery_id(&self.conversation_id, key)?,
                &serde_json::to_string(&initial).map_err(failure)?,
                OffsetDateTime::now_utc(),
            )
            .map_err(failure)?;
        Ok(())
    }

    pub(super) fn resume_deliveries(&self) -> Result<(), EgressError> {
        let ledger = Ledger::open(&self.ledger_path).map_err(failure)?;
        let rows = ledger.conversation_deliveries().map_err(failure)?;
        drop(ledger);
        for row in rows {
            let state = decode(&row)?;
            if state.conversation != self.conversation_id
                || disposition(&state) != ReplyDisposition::Resumable
            {
                continue;
            }
            if state.channel != self.owner.channel_id {
                return Err(failure("recovered reply channel changed"));
            }
            let answer = state
                .final_answer
                .as_deref()
                .ok_or_else(|| failure("final reply has no selected answer"))?;
            self.deliver_final(&state.key, answer, state.projection.as_ref())?;
        }
        Ok(())
    }
}

/// Operator inspection deliberately omits reply bodies.
pub fn inspect(ledger_path: &Path) -> Result<serde_json::Value, String> {
    let ledger = Ledger::open(ledger_path).map_err(|error| error.to_string())?;
    let mut replies = Vec::new();
    for row in ledger
        .conversation_deliveries()
        .map_err(|error| error.to_string())?
    {
        let state = decode(&row).map_err(|error| error.to_string())?;
        replies.push(serde_json::json!({ "id": row.object_id, "revision": row.revision,
            "conversation": state.conversation, "key": state.key, "phase": state.phase,
            "channel": state.channel, "chunks": state.chunks.iter().map(|chunk| &chunk.reference).collect::<Vec<_>>(),
            "legacyOutcomeUnknown": state.legacy_unknown,
            "blockedReason": state.legacy_unknown.then_some("legacy reservation lacks physical operation and exact wire content; no automatic resend or invented reconciliation"),
            "pendingSequence": state.pending.as_ref().map(|pending| pending.sequence),
            "pendingKind": state.pending.as_ref().map(|pending| match &pending.operation {
                DeliveryOperation::Post { .. } => "post", DeliveryOperation::Patch { .. } => "patch", DeliveryOperation::Delete { .. } => "delete" }) }));
    }
    Ok(serde_json::Value::Array(replies))
}

/// Adopts a proven effect after the reserving process exits; never retries it.
pub async fn reconcile(
    ledger_path: &Path,
    id: &str,
    expected_revision: i64,
    sequence: u64,
    message_id: Option<&str>,
    transport: &crate::discord::DiscordRestTransport,
) -> Result<serde_json::Value, String> {
    let mut ledger = Ledger::open(ledger_path).map_err(|error| error.to_string())?;
    let row = ledger
        .conversation_delivery(id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "reply delivery does not exist".to_owned())?;
    if row.revision != expected_revision {
        return Err("reply revision changed".to_owned());
    }
    let mut state = decode(&row).map_err(|error| error.to_string())?;
    let pending = state
        .pending
        .as_ref()
        .filter(|pending| pending.sequence == sequence)
        .ok_or_else(|| "reply operation does not match the requested sequence".to_owned())?;
    // PID reuse refuses rather than guessing that an old dispatcher is dead.
    if Path::new("/proc")
        .join(pending.dispatcher_pid.to_string())
        .exists()
    {
        return Err("the reserving process still exists; stop it before reconciling".to_owned());
    }
    let supplied = message_id.ok_or_else(|| "an explicit message ID is required".to_owned())?;
    let bot = transport
        .delivery_bot_user_id()
        .await
        .map_err(|error| error.to_string())?;
    let actual = transport
        .fetch_delivery_message(&state.channel, supplied)
        .await
        .map_err(|error| error.to_string())?;
    let reference = match &pending.operation {
        DeliveryOperation::Post { content, .. } => {
            let actual = actual
                .filter(|actual| {
                    actual.id == supplied
                        && actual.channel_id == state.channel
                        && actual.author_id == bot
                        && actual.content == *content
                        && actual.guild_id.is_none()
                })
                .ok_or_else(|| {
                    "message does not prove the reserved POST's exact content and owner".to_owned()
                })?;
            if state
                .chunks
                .iter()
                .any(|chunk| chunk.reference.message_id == actual.id)
            {
                return Err("message is already owned by another chunk".to_owned());
            }
            Some(DiscordMessageRef {
                channel_id: actual.channel_id,
                message_id: actual.id,
            })
        }
        DeliveryOperation::Patch {
            reference, content, ..
        } => {
            if reference.message_id != supplied {
                return Err("message ID is not the PATCH target".to_owned());
            }
            if !actual.is_some_and(|actual| {
                actual.id == supplied
                    && actual.channel_id == state.channel
                    && actual.author_id == bot
                    && actual.content == *content
                    && actual.guild_id.is_none()
            }) {
                return Err(
                    "message does not prove the reserved PATCH's exact content and owner"
                        .to_owned(),
                );
            }
            Some(reference.clone())
        }
        DeliveryOperation::Delete { reference } => {
            if reference.message_id != supplied || actual.is_some() {
                return Err("the exact DELETE target has not been proven absent".to_owned());
            }
            None
        }
    };
    apply_ack(&mut state, sequence, reference.as_ref()).map_err(|error| error.to_string())?;
    if state.phase == Phase::Finalizing
        && state.final_rendered
        && !state.legacy_unknown
        && physical_complete(&state)
    {
        commit_final(&mut state);
    }
    persist(&mut ledger, &row, &state).map_err(|error| error.to_string())?;
    Ok(serde_json::json!({ "id": id, "sequence": sequence, "reconciled": true }))
}
