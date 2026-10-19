//! Outgoing owner DMs contain assistant replies and approval questions, not lifecycle receipts.
//!
//! Credential handles and configured tokens are scrubbed; long replies are chunked rather than truncated.
//! Approval questions require confirmed delivery: a database row alone does not mean the owner saw one.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::discord::{
    DiscordMessageRef, DiscordSendError, DiscordTransport, MAX_MESSAGE_CODEPOINTS,
    UNKNOWN_MESSAGE_CODE,
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

/// Egress deployment facts (owner DM channel, scrub vocabulary, subscription
/// bound) supplied by the runtime from dotfiles; no compiled defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressConfig {
    /// The owner-paired channel that receives status notifications.
    pub channel_id: String,
    /// Extra literal tokens masked in every outgoing message (for example
    /// account references the operator registered). Structural non-disclosure
    /// holds without any tokens; these are defense in depth.
    pub scrub_tokens: BTreeSet<String>,
    /// Bounded subscription buffer requested from the bus.
    pub capacity: usize,
}

impl EgressConfig {
    pub fn new(
        channel_id: impl Into<String>,
        scrub_tokens: impl IntoIterator<Item = String>,
        capacity: usize,
    ) -> Result<Self, EgressError> {
        let channel_id = channel_id.into();
        if channel_id.is_empty() || channel_id.len() > 32 {
            return Err(EgressError::RoutingUnavailable);
        }
        if capacity == 0 {
            return Err(EgressError::InvalidState(
                "egress subscription capacity must be positive",
            ));
        }
        let scrub_tokens: BTreeSet<String> = scrub_tokens
            .into_iter()
            .filter(|token| !token.is_empty())
            .collect();
        Ok(Self {
            channel_id,
            scrub_tokens,
            capacity,
        })
    }
}

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
    #[error("live event stream failed: {0}")]
    Live(#[from] odin_domain::huginn::rpc::LiveProtocolError),
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
            Self::ReplyLost | Self::Live(_) | Self::Partial { .. } | Self::DeliveryState(_) => true,
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

    /// Rewrites the logical reply `current` owns to read exactly `message`'s
    /// content: carried chunks are edited in place (the anchor keeps its
    /// id), missing chunks are posted, surplus chunks are deleted. An
    /// already-deleted surplus chunk counts as settled.
    async fn edit(
        &self,
        current: &ReplyChunks,
        message: OutboundMessage,
    ) -> Result<ReplyChunks, EgressError>;

    async fn typing(&self, channel_id: &str) -> Result<(), EgressError>;
}

/// Real sink over the Discord transport: splits content past the Discord
/// code point bound into consecutive chunk messages — never a truncation —
/// and reconciles the reply's whole physical set on every edit.
pub struct DiscordEgressSink {
    transport: Arc<dyn DiscordTransport>,
}

impl DiscordEgressSink {
    pub fn new(transport: Arc<dyn DiscordTransport>) -> Self {
        Self { transport }
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
                DeliveryOperation::Delete { reference } => match self
                    .transport
                    .delete_message(&reference.channel_id, &reference.message_id)
                    .await
                {
                    Ok(()) => Ok(None),
                    Err(DiscordSendError::Rejected { code, .. })
                        if code == UNKNOWN_MESSAGE_CODE || code == 404 =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(error),
                },
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

    async fn edit(
        &self,
        current: &ReplyChunks,
        message: OutboundMessage,
    ) -> Result<ReplyChunks, EgressError> {
        let chunks = split_reply(&message.content, MAX_MESSAGE_CODEPOINTS);
        let surplus: Vec<DiscordMessageRef> = current.refs().skip(chunks.len()).cloned().collect();
        let total = chunks.len() + surplus.len();
        let mut settled: Vec<DiscordMessageRef> = Vec::with_capacity(chunks.len());
        for (index, chunk) in chunks.iter().enumerate() {
            let outcome = match current.refs().nth(index) {
                Some(existing) => self
                    .transport
                    .edit_message(&existing.channel_id, &existing.message_id, chunk)
                    .await
                    .map(|_| existing.clone()),
                None => {
                    self.transport
                        .send_message(&message.channel_id, chunk)
                        .await
                }
            };
            match outcome {
                Ok(reference) => settled.push(reference),
                Err(error) => {
                    return Err(match settled.is_empty() && index == 0 {
                        true => error.into(),
                        false => {
                            let mut held = settled.clone();
                            held.extend(current.refs().skip(index).cloned());
                            EgressError::Partial {
                                ownership: Box::new(ownership_of(held)),
                                applied: settled.len(),
                                total,
                                post_outcome_unknown: index >= current.len()
                                    && transport_outcome_unknown(&error),
                                source: error,
                            }
                        }
                    });
                }
            }
        }
        let mut deleted = 0usize;
        for extra in &surplus {
            match self
                .transport
                .delete_message(&extra.channel_id, &extra.message_id)
                .await
            {
                Ok(()) => deleted += 1,
                Err(DiscordSendError::Rejected { code, .. })
                    if code == UNKNOWN_MESSAGE_CODE || code == 404 =>
                {
                    deleted += 1;
                }
                Err(error) => {
                    let mut held = settled.clone();
                    held.extend(current.refs().skip(chunks.len() + deleted).cloned());
                    return Err(EgressError::Partial {
                        ownership: Box::new(ownership_of(held)),
                        applied: chunks.len() + deleted,
                        total,
                        post_outcome_unknown: false,
                        source: error,
                    });
                }
            }
        }
        Ok(ownership_of(settled))
    }

    async fn typing(&self, channel_id: &str) -> Result<(), EgressError> {
        Ok(self.transport.trigger_typing(channel_id).await?)
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
    fn multibyte_text_never_splits_inside_a_character() {
        let text = "沸点测定。\u{1F52C}".repeat(900);
        assert!(text.chars().count() > MAX_MESSAGE_CODEPOINTS);
        let chunks = split_reply(&text, MAX_MESSAGE_CODEPOINTS);
        assert_eq!(chunks.concat(), text);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CODEPOINTS);
        }
    }

    #[test]
    fn breaks_fall_back_from_paragraphs_to_sentences_to_words() {
        let paragraph = format!("a\n\n{}", "x".repeat(MAX_MESSAGE_CODEPOINTS + 5));
        let chunks = split_reply(&paragraph, MAX_MESSAGE_CODEPOINTS);
        assert_eq!(chunks[0], "a\n\n");
        assert_eq!(chunks.last().unwrap(), "xxxxx");
        let sentences = format!("{} One.", "x".repeat(MAX_MESSAGE_CODEPOINTS - 2));
        let chunks = split_reply(&sentences, MAX_MESSAGE_CODEPOINTS);
        assert_eq!(
            chunks[0],
            format!("{} ", "x".repeat(MAX_MESSAGE_CODEPOINTS - 2))
        );
        assert_eq!(chunks[1], "One.");
        let words = format!("{} tail", "x".repeat(MAX_MESSAGE_CODEPOINTS - 1));
        let chunks = split_reply(&words, MAX_MESSAGE_CODEPOINTS);
        assert_eq!(chunks[1], "tail");
        let unbreakable: String = "日".repeat(MAX_MESSAGE_CODEPOINTS + 3);
        let chunks = split_reply(&unbreakable, MAX_MESSAGE_CODEPOINTS);
        assert_eq!(chunks[1], "日日日");
    }

    #[test]
    fn a_short_reply_is_one_chunk() {
        assert_eq!(split_reply("short", MAX_MESSAGE_CODEPOINTS), ["short"]);
        let exact = "x".repeat(MAX_MESSAGE_CODEPOINTS);
        assert_eq!(split_reply(&exact, MAX_MESSAGE_CODEPOINTS), [exact]);
    }

    #[test]
    fn partial_progress_is_distinct_from_an_unknown_post_outcome() {
        let ownership = ReplyChunks::single(DiscordMessageRef {
            message_id: "1".to_owned(),
            channel_id: "c".to_owned(),
        });
        let partial = EgressError::Partial {
            ownership: Box::new(ownership),
            applied: 1,
            total: 3,
            post_outcome_unknown: false,
            source: DiscordSendError::RateLimited { retry_after_ms: 10 },
        };
        assert!(partial.may_have_posted());
        assert!(!partial.post_outcome_unknown());
        assert!(
            !EgressError::Transport(DiscordSendError::RateLimited { retry_after_ms: 10 })
                .may_have_posted()
        );
        assert_eq!(
            partial.to_string(),
            "egress applied 1 of 3 reply chunk operations before failing (POST outcome unknown: false): discord rate \
             limited the request; retry after 10 ms"
        );
    }

    #[test]
    fn plain_transport_uncertainty_excludes_definite_non_delivery() {
        for source in [
            DiscordSendError::CredentialsUnavailable,
            DiscordSendError::GatewayNotOwned,
            DiscordSendError::Unreachable,
            DiscordSendError::RateLimited { retry_after_ms: 10 },
            DiscordSendError::Rejected {
                code: 400,
                message: "invalid message".to_owned(),
            },
        ] {
            assert!(!EgressError::Transport(source).post_outcome_unknown());
        }
        for source in [
            DiscordSendError::ServiceUnavailable,
            DiscordSendError::Encoding,
        ] {
            assert!(EgressError::Transport(source).post_outcome_unknown());
        }
        assert!(EgressError::ReplyLost.post_outcome_unknown());
        let checkpoint = EgressError::DeliveryState("acknowledgement lost".into());
        assert!(checkpoint.may_have_posted());
        assert!(checkpoint.post_outcome_unknown());
        assert!(!EgressError::RoutingUnavailable.post_outcome_unknown());
        assert!(!EgressError::InvalidState("not started").post_outcome_unknown());
    }

    #[test]
    fn partial_uncertainty_tracks_failed_post_not_patch_or_delete() {
        for post_outcome_unknown in [false, true] {
            let partial = EgressError::Partial {
                ownership: Box::new(ReplyChunks::single(DiscordMessageRef {
                    message_id: "1".to_owned(),
                    channel_id: "c".to_owned(),
                })),
                applied: 1,
                total: 2,
                post_outcome_unknown,
                source: DiscordSendError::ServiceUnavailable,
            };
            assert!(partial.may_have_posted());
            assert_eq!(partial.post_outcome_unknown(), post_outcome_unknown);
        }
    }
}
