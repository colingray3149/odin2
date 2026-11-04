//! Outgoing owner DMs contain assistant replies and approval questions, not lifecycle receipts.
//!
//! Credential handles and configured tokens are scrubbed; long replies are chunked rather than truncated.
//! Approval questions require confirmed delivery: a database row alone does not mean the owner saw one.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::discord::{
    DiscordMessageRef, DiscordSendError, DiscordTransport, MAX_MESSAGE_CODEPOINTS,
};
use async_trait::async_trait;
use odin_domain::SUBJECT_APPROVAL_CHANGED;
use odin_domain::SUBJECT_COMMAND_CHANGED;
use odin_domain::SUBJECT_RUN_CHANGED;

/// The subjects the egress publisher subscribes to. Anything outside this set
/// is never rendered, whatever its payload claims.
pub const EGRESS_SUBJECTS: &[&str] = &[
    SUBJECT_COMMAND_CHANGED,
    SUBJECT_APPROVAL_CHANGED,
    SUBJECT_RUN_CHANGED,
];

/// One message bound for the Discord surface, already scrubbed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundMessage {
    pub channel_id: String,
    pub content: String,
}

/// Physical messages in reply order; the anchor remains stable across edits for ordering and deduplication.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplyChunks {
    pub anchor: DiscordMessageRef,
    /// The physical messages after the anchor, oldest first.
    pub tails: Vec<DiscordMessageRef>,
}

impl ReplyChunks {
    pub fn single(reference: DiscordMessageRef) -> Self {
        Self {
            anchor: reference,
            tails: Vec::new(),
        }
    }

    /// Every physical message of the reply, oldest first.
    pub fn refs(&self) -> impl Iterator<Item = &DiscordMessageRef> {
        std::iter::once(&self.anchor).chain(self.tails.iter())
    }

    pub fn len(&self) -> usize {
        self.tails.len() + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeliveryOperation {
    Post {
        index: usize,
        content: String,
    },
    Patch {
        index: usize,
        reference: DiscordMessageRef,
        content: String,
    },
    Delete {
        reference: DiscordMessageRef,
    },
}

#[derive(Clone, Debug)]
pub struct DeliveryPlan {
    pub chunks: Vec<String>,
    pub ownership: Option<ReplyChunks>,
    pub operations: Vec<DeliveryOperation>,
}

#[derive(Debug)]
pub struct DeliveryReservation {
    pub(crate) sequence: u64,
}

pub trait DeliveryCheckpoint: Send + Sync {
    fn prepare(&self, message: &OutboundMessage) -> Result<DeliveryPlan, EgressError>;
    fn reserve(&self, operation: &DeliveryOperation) -> Result<DeliveryReservation, EgressError>;
    fn acknowledge(
        &self,
        reservation: &DeliveryReservation,
        reference: Option<&DiscordMessageRef>,
    ) -> Result<(), EgressError>;
    fn failed(
        &self,
        reservation: &DeliveryReservation,
        error: &DiscordSendError,
    ) -> Result<(), EgressError>;
    fn complete(&self) -> Result<(), EgressError>;
}

/// Typed egress failures. None is a success; there is no silent-drop path.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EgressError {
    #[error("egress routing is not configured")]
    RoutingUnavailable,
    #[error("egress transport failed: {0}")]
    Transport(#[from] DiscordSendError),
    #[error("egress state invalid: {0}")]
    InvalidState(&'static str),
    #[error("durable delivery state failed: {0}")]
    DeliveryState(String),
    #[error("the notify worker dropped the send's reply")]
    ReplyLost,
    /// A split reply's operation failed after `applied` of `total` chunk
    /// operations landed. `ownership` is the acknowledged physical set —
    /// landed chunks merged with any old tails not yet deleted. An uncertain
    /// POST may have created an additional, unacknowledged message; its
    /// `post_outcome_unknown` flag forbids blindly retrying that append.
    /// A failure on the very first operation stays a plain [`EgressError::
    /// Transport`] with the caller's ownership untouched. The set is boxed:
    /// a failure carries it rarely, and the error type stays small on every
    /// return path.
    #[error("egress applied {applied} of {total} reply chunk operations before failing (POST outcome unknown: {post_outcome_unknown}): {source}")]
    Partial {
        ownership: Box<ReplyChunks>,
        applied: usize,
        total: usize,
        /// The failed operation was a POST whose outcome is unknown, not a
        /// PATCH/DELETE against an already acknowledged message identity.
        post_outcome_unknown: bool,
        #[source]
        source: DiscordSendError,
    },
}

impl EgressError {
    /// Whether any message may have landed, including acknowledged partial
    /// progress. This does not imply that a failed POST has an unknown outcome;
    /// use [`Self::post_outcome_unknown`] to distinguish that retry hazard.
    pub fn may_have_posted(&self) -> bool {
        match self {
            Self::RoutingUnavailable | Self::InvalidState(_) => false,
            Self::ReplyLost | Self::Partial { .. } | Self::DeliveryState(_) => true,
            Self::Transport(error) => transport_outcome_unknown(error),
        }
    }

    /// Whether an unacknowledged message may have been created by a failed POST.
    /// Partial failures carry the operation-specific answer. A plain transport
    /// error has no operation identity, so this conservatively assumes POST:
    /// callers performing an edit must exclude that case (the first failed
    /// operation is a PATCH). Lost replies/live errors cannot rule out a POST.
    pub fn post_outcome_unknown(&self) -> bool {
        match self {
            Self::Partial {
                post_outcome_unknown,
                ..
            } => *post_outcome_unknown,
            _ => self.may_have_posted(),
        }
    }
}

fn transport_outcome_unknown(error: &DiscordSendError) -> bool {
    !matches!(
        error,
        DiscordSendError::CredentialsUnavailable
            | DiscordSendError::GatewayNotOwned
            | DiscordSendError::Unreachable
            | DiscordSendError::RateLimited { .. }
            | DiscordSendError::Rejected { .. }
    )
}

/// The send port the publisher depends on, kept separate from
/// [`DiscordTransport`] so alternate sinks stay wireable by the runtime.
/// A logical reply longer than the per-message bound is posted as
/// consecutive bounded chunks; the successful result owns every physical
/// message — `anchor` first — and the same anchor identifies the reply
/// across edits. No reference is fabricated on failure.
#[async_trait]
pub trait OutgoingSink: Send + Sync {
    async fn deliver(
        &self,
        message: OutboundMessage,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError>;

    async fn send(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError>;

    async fn typing(&self, channel_id: &str) -> Result<(), EgressError>;

    /// Posts one message that does not notify the owner's phone.
    async fn send_silent(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
        self.send(message).await
    }

    /// Replaces the content of one message this bot posted, outside any
    /// reply's delivery record.
    async fn edit(&self, message: &DiscordMessageRef, content: &str) -> Result<(), EgressError> {
        let _ = (message, content);
        Err(EgressError::InvalidState("this sink cannot edit a message"))
    }

    /// Deletes one message this bot posted; one already gone counts as deleted.
    async fn delete(&self, message: &DiscordMessageRef) -> Result<(), EgressError> {
        let _ = message;
        Err(EgressError::InvalidState(
            "this sink cannot delete a message",
        ))
    }
}

/// Real sink over the Discord transport: splits content past the Discord
/// code point bound into consecutive chunk messages — never a truncation —
/// and reconciles the reply's whole physical set on every delivery.
pub struct DiscordEgressSink {
    transport: Arc<dyn DiscordTransport>,
}

impl DiscordEgressSink {
    pub fn new(transport: Arc<dyn DiscordTransport>) -> Self {
        Self { transport }
    }

    /// Deletes `message`; one that is already gone counts as deleted.
    async fn remove(&self, message: &DiscordMessageRef) -> Result<(), DiscordSendError> {
        match self
            .transport
            .delete_message(&message.channel_id, &message.message_id)
            .await
        {
            Err(DiscordSendError::Rejected { code, .. })
                if code == crate::discord::UNKNOWN_MESSAGE_CODE || code == 404 =>
            {
                Ok(())
            }
            outcome => outcome,
        }
    }

    /// Posts `chunks` in order. A failure past the first chunk reports the
    /// acknowledged ownership in the typed error; the first chunk's failure
    /// is a plain transport error — no message identity was acknowledged.
    async fn post_chunks(
        &self,
        channel_id: &str,
        chunks: &[String],
    ) -> Result<ReplyChunks, EgressError> {
        let mut posted: Vec<DiscordMessageRef> = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            match self.transport.send_message(channel_id, chunk).await {
                Ok(reference) => posted.push(reference),
                Err(error) => {
                    return Err(match posted.is_empty() {
                        true => error.into(),
                        false => EgressError::Partial {
                            ownership: Box::new(ownership_of(posted.clone())),
                            applied: posted.len(),
                            total: chunks.len(),
                            post_outcome_unknown: transport_outcome_unknown(&error),
                            source: error,
                        },
                    });
                }
            }
        }
        Ok(ownership_of(posted))
    }
}

#[async_trait]
impl OutgoingSink for DiscordEgressSink {
    async fn deliver(
        &self,
        message: OutboundMessage,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        let plan = checkpoint.prepare(&message)?;
        let mut held: Vec<DiscordMessageRef> = plan
            .ownership
            .as_ref()
            .map(|owned| owned.refs().cloned().collect())
            .unwrap_or_default();
        let total = plan.operations.len();
        for (applied, operation) in plan.operations.iter().enumerate() {
            let reservation = checkpoint.reserve(operation)?;
            let outcome = match operation {
                DeliveryOperation::Post { content, .. } => self
                    .transport
                    .send_message(&message.channel_id, content)
                    .await
                    .map(Some),
                DeliveryOperation::Patch {
                    reference, content, ..
                } => self
                    .transport
                    .edit_message(&reference.channel_id, &reference.message_id, content)
                    .await
                    .map(Some),
                DeliveryOperation::Delete { reference } => {
                    self.remove(reference).await.map(|()| None)
                }
            };
            match outcome {
                Ok(reference) => {
                    checkpoint.acknowledge(&reservation, reference.as_ref())?;
                    match operation {
                        DeliveryOperation::Post { .. } => {
                            held.push(reference.expect("POST reference"))
                        }
                        DeliveryOperation::Patch { index, .. } => {
                            held[*index] = reference.expect("PATCH reference");
                        }
                        DeliveryOperation::Delete { reference } => {
                            held.retain(|held| held != reference)
                        }
                    }
                }
                Err(error) => {
                    checkpoint.failed(&reservation, &error)?;
                    return Err(if applied == 0 || held.is_empty() {
                        error.into()
                    } else {
                        EgressError::Partial {
                            ownership: Box::new(ownership_of(held)),
                            applied,
                            total,
                            post_outcome_unknown: matches!(
                                operation,
                                DeliveryOperation::Post { .. }
                            ) && transport_outcome_unknown(&error),
                            source: error,
                        }
                    });
                }
            }
        }
        checkpoint.complete()?;
        if held.is_empty() {
            return Err(EgressError::DeliveryState(
                "delivery owns no acknowledged messages".into(),
            ));
        }
        Ok(ownership_of(held))
    }

    async fn send(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
        let chunks = split_reply(&message.content, MAX_MESSAGE_CODEPOINTS);
        self.post_chunks(&message.channel_id, &chunks).await
    }

    async fn send_silent(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
        let posted = self
            .transport
            .send_silent(&message.channel_id, &message.content)
            .await?;
        Ok(ReplyChunks::single(posted))
    }

    async fn typing(&self, channel_id: &str) -> Result<(), EgressError> {
        Ok(self.transport.trigger_typing(channel_id).await?)
    }

    async fn edit(&self, message: &DiscordMessageRef, content: &str) -> Result<(), EgressError> {
        self.transport
            .edit_message(&message.channel_id, &message.message_id, content)
            .await?;
        Ok(())
    }

    async fn delete(&self, message: &DiscordMessageRef) -> Result<(), EgressError> {
        Ok(self.remove(message).await?)
    }
}

/// The physical set `held` names: the anchor first, then the tails.
fn ownership_of(held: Vec<DiscordMessageRef>) -> ReplyChunks {
    let mut held = held.into_iter();
    let anchor = held.next().expect("a reply owns at least its anchor chunk");
    ReplyChunks {
        anchor,
        tails: held.collect(),
    }
}

/// Sentence-ending characters a chunk break prefers, including the CJK
/// stops.
const SENTENCE_ENDS: [char; 7] = ['.', '!', '?', '\n', '。', '！', '？'];

/// Splits one logical reply into consecutive chunks of at most `limit`
/// Unicode code points whose concatenation is exactly `text`: within each
/// window a paragraph boundary is preferred, then a sentence end, then any
/// whitespace, then a hard cut between characters — never a partial
/// character, never a lost tail.
pub fn split_reply(text: &str, limit: usize) -> Vec<String> {
    if text.chars().count() <= limit {
        return vec![text.to_owned()];
    }
    let mut chunks = Vec::new();
    let mut rest = text;
    while rest.chars().count() > limit {
        let cut = break_point(rest, limit);
        let (chunk, tail) = rest.split_at(cut);
        chunks.push(chunk.to_owned());
        rest = tail;
    }
    chunks.push(rest.to_owned());
    chunks
}

/// The byte offset of the best break at most `limit` code points into
/// `text`, always on a character boundary past at least one character.
fn break_point(text: &str, limit: usize) -> usize {
    let limit = limit.max(1);
    let byte_limit = text
        .char_indices()
        .nth(limit)
        .map_or(text.len(), |(offset, _)| offset);
    let prefix = &text[..byte_limit];
    if let Some(position) = prefix.rfind("\n\n") {
        if position > 0 {
            return position + "\n\n".len();
        }
    }
    let mut sentence = None;
    let mut space = None;
    for (index, character) in prefix.char_indices() {
        if index == 0 {
            continue;
        }
        if SENTENCE_ENDS.contains(&character) {
            sentence = Some(index + character.len_utf8());
        }
        if character.is_whitespace() {
            space = Some(index + character.len_utf8());
        }
    }
    sentence.or(space).unwrap_or(byte_limit)
}

/// Masks `cred:` credential handles and every configured token. Idempotent
/// and deterministic; used on every outgoing message.
pub fn scrub_sensitive(text: &str, tokens: &BTreeSet<String>) -> String {
    let mut scrubbed = mask_credential_handles(text);
    for token in tokens {
        if scrubbed.contains(token.as_str()) {
            scrubbed = scrubbed.replace(token.as_str(), "[masked]");
        }
    }
    scrubbed
}

fn mask_credential_handles(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("cred:") {
        let (before, tail) = rest.split_at(position);
        result.push_str(before);
        let handle_end = tail
            .bytes()
            .position(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
            })
            .unwrap_or(tail.len());
        result.push_str("cred:[masked]");
        rest = &tail[handle_end..];
    }
    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A report the size of the ChemNODE live scenario (8 930 code points,
    /// well past the 8 265 the owner asked about): its last line is the
    /// Limitations tail with the citation.
    fn chemnode_report() -> String {
        let finding = "ChemNODE couples a message-passing network to a thermodynamic \
            prior, and the ablation holds across all three solvents. ";
        let mut report = String::new();
        report.push_str("# ChemNODE (arXiv:2101.04749)\n\n");
        for section in 0..9 {
            report.push_str(&format!(
                "## Section {section}\n\n{}\n\n",
                finding.repeat(8)
            ));
        }
        report.push_str(
            "## Limitations\n\nThe training set covers 8 265 measured cells only; the \
             extrapolation beyond 400 K is unvalidated, and the citation trail ends at \
             the supplement (arXiv:2101.04749).",
        );
        report
    }

    #[test]
    fn an_oversized_report_splits_into_bounded_ordered_chunks() {
        let report = chemnode_report();
        assert!(report.chars().count() > 8_000);
        let chunks = split_reply(&report, MAX_MESSAGE_CODEPOINTS);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), report, "no tail is lost or duplicated");
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CODEPOINTS);
            assert!(!chunk.is_empty());
        }
        assert!(
            chunks[0].ends_with("\n\n"),
            "the first break lands on the paragraph boundary"
        );
        assert!(chunks[0].chars().count() > 1_500, "chunks fill greedily");
        assert!(chunks.last().unwrap().ends_with("(arXiv:2101.04749)."));
    }

    #[test]
    fn configured_tokens_and_credential_handles_are_masked_in_outgoing_text() {
        let tokens = BTreeSet::from(["bot-token-123".to_owned()]);
        let out = scrub_sensitive(
            "it said bot-token-123 and cred:mail-account twice: bot-token-123",
            &tokens,
        );
        assert!(
            !out.contains("bot-token-123") && !out.contains("cred:mail-account"),
            "{out}"
        );
        assert_eq!(out.matches("[masked]").count(), 3);
    }
}
