//! What the owner sees of a turn while it runs: one status message that says
//! what she is doing, and a long answer streamed into the turn's durable
//! reply. Final settlement always goes through the root, even when text is
//! unchanged.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::prompt::{without_quiet_token, QUIET_REPLY};
use super::{BackgroundWork, ConversationEgress};
use crate::discord::DiscordMessageRef;
use crate::egress::DeliveryCheckpoint;

const EDIT_EVERY: Duration = Duration::from_secs(1);
/// The status message is edited at most this often: inside Discord's five
/// edits per five seconds on one channel, so the answer streaming into the
/// same channel keeps its room.
const STATUS_EVERY: Duration = Duration::from_secs(4);
/// Background work a status names; the rest is counted.
const STATUS_LISTED: usize = 4;
/// Characters of a step or a piece of background work a status keeps.
const STATUS_WHAT_CHARS: usize = 80;
/// A segment streams only once it is this long or spans lines: a short
/// message may still turn out to be one said between tool calls, which never
/// reaches the turn's reply.
const STREAM_FROM_CHARS: usize = 200;
/// Discord shows "typing…" for about ten seconds per trigger.
const TYPING_EVERY: Duration = Duration::from_secs(8);

pub(super) struct AnswerStream {
    segment: String,
    checkpoint: Arc<dyn DeliveryCheckpoint>,
    first_words: Option<Instant>,
    shown: Option<String>,
    last_edit: Option<Instant>,
    last_typing: Option<Instant>,
    /// The streamed reply reached the owner.
    pub(super) streamed: bool,
}

impl AnswerStream {
    pub(super) fn new(checkpoint: Arc<dyn DeliveryCheckpoint>) -> Self {
        Self {
            segment: String::new(),
            checkpoint,
            first_words: None,
            shown: None,
            last_edit: None,
            last_typing: None,
            streamed: false,
        }
    }

    pub(super) fn delta(&mut self, text: &str) {
        self.segment.push_str(text);
    }

    pub(super) fn message_finished(&mut self) {
        self.segment.clear();
    }

    pub(super) fn tick(
        &mut self,
        egress: &dyn ConversationEgress,
        now: Instant,
    ) -> Option<Instant> {
        let visible = visible(&self.segment);
        let long = visible.chars().count() >= STREAM_FROM_CHARS || visible.contains('\n');
        if !long {
            if self.shown.is_none() {
                if self
                    .last_typing
                    .is_none_or(|last| now.duration_since(last) >= TYPING_EVERY)
                {
                    if let Err(error) = egress.typing() {
                        tracing::warn!(error = %error, "odind: conversation-stream typing failed: {error}");
                    }
                    self.last_typing = Some(now);
                }
                return self.last_typing.map(|last| last + TYPING_EVERY);
            }
            return None;
        }
        let first = *self.first_words.get_or_insert(now);
        if now < first + EDIT_EVERY {
            return Some(first + EDIT_EVERY);
        }
        if self.shown.as_deref() == Some(visible) {
            return None;
        }
        if let Some(last) = self.last_edit {
            if now.duration_since(last) < EDIT_EVERY {
                return Some(last + EDIT_EVERY);
            }
        }
        match egress.deliver(visible, self.checkpoint.clone()) {
            Ok(_) => {
                self.shown = Some(visible.to_owned());
                // The streamed reply reached the owner: it counts as her own
                // words for the rest of the turn, so nothing later talks
                // over it (a holding line would).
                self.streamed = true;
            }
            Err(error) => {
                self.shown = None;
                tracing::error!(error = %error, "odind: conversation-stream delivery failed: {error}");
            }
        }
        self.last_edit = Some(now);
        None
    }
}

/// The one message that tells the owner what a turn is doing: the step it is on,
/// how long it has run, and what she has running in the background. It is
/// posted at the turn's first tool call and edited in place; her own words
/// between tool calls go nowhere else. It is deleted when the turn ends,
/// answered or quiet: a summary left behind would pile up above every reply,
/// and a deleted message can never go on claiming work that is over. It is
/// a display only, so a failed post, edit or delete is logged and never
/// stops the turn; the next tick tries again.
pub(super) struct TurnStatus {
    egress: Arc<dyn ConversationEgress>,
    started: Instant,
    /// The latest tool call's label; none until the first tool call.
    step: Option<String>,
    message: Option<DiscordMessageRef>,
    last_sent: Option<Instant>,
    /// A post may have gone through without a reference to delete it by:
    /// posting again could leave two, so the turn shows no more status.
    gave_up: bool,
}

impl TurnStatus {
    pub(super) fn new(egress: Arc<dyn ConversationEgress>, started: Instant) -> Self {
        Self {
            egress,
            started,
            step: None,
            message: None,
            last_sent: None,
            gave_up: false,
        }
    }

    /// A tool call started: the step is the call's own short label, or its
    /// tool when it gave none.
    pub(super) fn tool_started(&mut self, started: &odin_domain::huginn::ToolStarted) {
        let label = started
            .intent
            .as_deref()
            .unwrap_or_else(|| started.tool.capability_id.as_str());
        self.step = Some(short(label));
    }

    /// Whether the owner has a status message now.
    pub(super) fn posted(&self) -> bool {
        self.message.is_some()
    }

    /// Posts the status at the first tool call, then edits it once
    /// [`STATUS_EVERY`] has passed; `background` is read only when a send is
    /// due. Returns when the next send is due.
    pub(super) fn tick(
        &mut self,
        now: Instant,
        background: impl FnOnce() -> Vec<BackgroundWork>,
    ) -> Option<Instant> {
        let step = self.step.as_deref().filter(|_| !self.gave_up)?;
        if let Some(due) = self.last_sent.map(|last| last + STATUS_EVERY) {
            if now < due {
                return Some(due);
            }
        }
        let text = render(step, now.duration_since(self.started), &background());
        self.last_sent = Some(now);
        match &self.message {
            None => match self.egress.status_post(&text) {
                Ok(message) => self.message = Some(message),
                Err(error) => {
                    tracing::warn!(error = %error, "odind: conversation status not posted: {error}");
                    self.gave_up = error.may_have_posted;
                }
            },
            Some(message) => {
                if let Err(error) = self.egress.status_edit(message, &text) {
                    tracing::warn!(error = %error, "odind: conversation status not edited: {error}");
                }
            }
        }
        Some(now + STATUS_EVERY)
    }

    /// Deletes the message, once; the status posts nothing after this.
    pub(super) fn finish(&mut self) {
        self.step = None;
        if let Some(message) = self.message.take() {
            if let Err(error) = self.egress.status_delete(&message) {
                tracing::warn!(error = %error, "odind: conversation status not deleted: {error}");
            }
        }
    }
}

impl Drop for TurnStatus {
    fn drop(&mut self) {
        self.finish();
    }
}

fn render(step: &str, elapsed: Duration, background: &[BackgroundWork]) -> String {
    let mut text = format!("Working, {}: {step}", age(elapsed.as_secs()));
    if !background.is_empty() {
        text.push_str("\nIn the background: ");
        for (index, work) in background.iter().take(STATUS_LISTED).enumerate() {
            if index > 0 {
                text.push_str(", ");
            }
            let _ = write!(text, "{} ({})", short(&work.what), age(work.seconds));
        }
        if background.len() > STATUS_LISTED {
            let _ = write!(text, " and {} more", background.len() - STATUS_LISTED);
        }
    }
    text
}

/// `text` on one line, cut at [`STATUS_WHAT_CHARS`].
fn short(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(STATUS_WHAT_CHARS) {
        Some((end, _)) => format!("{}…", line[..end].trim_end()),
        None => line,
    }
}

fn age(seconds: u64) -> String {
    match seconds {
        0..60 => format!("{seconds} s"),
        60..3600 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, seconds % 3600 / 60),
    }
}

/// Opens a message in which the model wrote its tool calls as text instead
/// of calling them. Such a message is never for the owner.
const TOOL_CALL_MARKUP: &str = "<tool_call>";

/// Whether `text` is tool calls written as text rather than words.
pub(super) fn tool_call_markup(text: &str) -> bool {
    text.trim_start().starts_with(TOOL_CALL_MARKUP)
}

fn visible(segment: &str) -> &str {
    let trimmed = segment.trim();
    if QUIET_REPLY.starts_with(trimmed) || tool_call_markup(trimmed) {
        return "";
    }
    without_quiet_token(segment)
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::discord::{DiscordMessageRef, DiscordSendError};
    use crate::egress::{DeliveryOperation, EgressError, OutboundMessage, ReplyChunks};

    #[derive(Default)]
    struct Recorder {
        log: Mutex<Vec<String>>,
        fail: Mutex<bool>,
    }

    impl ConversationEgress for Recorder {
        fn deliver(
            &self,
            content: &str,
            checkpoint: Arc<dyn DeliveryCheckpoint>,
        ) -> Result<ReplyChunks, EgressError> {
            let plan = checkpoint.prepare(&OutboundMessage {
                channel_id: "chan-1".to_owned(),
                content: content.to_owned(),
            })?;
            let mut owned = plan.ownership;
            for operation in plan.operations {
                let reservation = checkpoint.reserve(&operation)?;
                let reference = match &operation {
                    DeliveryOperation::Post { index, content } => {
                        self.log.lock().push(format!("post {content}"));
                        Some(DiscordMessageRef {
                            channel_id: "chan-1".to_owned(),
                            message_id: format!("m{index}"),
                        })
                    }
                    DeliveryOperation::Patch {
                        reference, content, ..
                    } => {
                        self.log.lock().push(format!("edit {content}"));
                        Some(reference.clone())
                    }
                    DeliveryOperation::Delete { .. } => None,
                };
                if std::mem::take(&mut *self.fail.lock()) {
                    let error = DiscordSendError::ServiceUnavailable;
                    checkpoint.failed(&reservation, &error)?;
                    return Err(EgressError::Transport(error));
                }
                checkpoint.acknowledge(&reservation, reference.as_ref())?;
                if let Some(reference) = reference {
                    owned = Some(ReplyChunks::single(reference));
                }
            }
            checkpoint.complete()?;
            owned.ok_or(EgressError::InvalidState("test reply has no chunks"))
        }

        fn typing(&self) -> Result<(), String> {
            self.log.lock().push("typing".to_owned());
            Ok(())
        }
    }

    #[tokio::test]
    async fn visible_words_wait_and_updates_are_throttled() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let mut stream = AnswerStream::new(root.reply_delivery("stream", None, None).unwrap());
        let start = Instant::now();
        stream.delta("[qui");
        assert_eq!(
            stream.tick(egress.as_ref(), start),
            Some(start + TYPING_EVERY)
        );
        stream.message_finished();
        stream.delta("Tea:\nOolong");
        assert_eq!(
            stream.tick(egress.as_ref(), start),
            Some(start + EDIT_EVERY)
        );
        stream.tick(egress.as_ref(), start + EDIT_EVERY);
        stream.delta(" tea");
        assert_eq!(
            stream.tick(egress.as_ref(), start + Duration::from_millis(1500)),
            Some(start + EDIT_EVERY * 2)
        );
        stream.tick(egress.as_ref(), start + EDIT_EVERY * 2);
        root.deliver_final("stream", "Tea:\nOolong tea.", None)
            .unwrap();
        assert_eq!(
            *egress.log.lock(),
            [
                "typing",
                "post Tea:\nOolong",
                "edit Tea:\nOolong tea",
                "edit Tea:\nOolong tea."
            ]
        );
    }

    #[tokio::test]
    async fn a_long_streamed_reply_counts_as_shown() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let mut stream = AnswerStream::new(root.reply_delivery("late", None, None).unwrap());
        let start = Instant::now();
        stream.delta(
            "Your Rankine cycle summary is ready: I pulled the CS63a notes, the problem \
             set, and last year's model answers into one folder, re-checked the two \
             derivations you flagged, and marked where the reheat stage changes the \
             efficiency calculation.",
        );
        stream.tick(egress.as_ref(), start);
        stream.tick(egress.as_ref(), start + EDIT_EVERY);
        // The reply streamed to the owner, so it already counts as her words
        // for the rest of the turn: a holding line would talk over it.
        let long = "Your Rankine cycle summary is ready: I pulled the CS63a notes, the problem set, and last year's model answers into one folder, re-checked the two derivations you flagged, and marked where the reheat stage changes the efficiency calculation.";
        assert_eq!(*egress.log.lock(), [format!("post {long}")]);
        assert!(stream.streamed);
    }

    #[tokio::test]
    async fn short_reply_is_only_posted_at_final_settlement() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let mut stream = AnswerStream::new(root.reply_delivery("short", None, None).unwrap());
        let start = Instant::now();
        stream.delta("391");
        stream.tick(egress.as_ref(), start);
        stream.delta(".");
        stream.tick(egress.as_ref(), start + Duration::from_millis(300));
        assert_eq!(*egress.log.lock(), ["typing"]);
        root.deliver_final("short", "391.", None).unwrap();
        root.deliver_final("short", "391.", None).unwrap();
        assert_eq!(*egress.log.lock(), ["typing", "post 391."]);
    }

    #[tokio::test]
    async fn unknown_post_is_blocked_by_checkpoint_after_stream_reconstruction() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let start = Instant::now();
        let mut stream = AnswerStream::new(root.reply_delivery("unknown", None, None).unwrap());
        stream.delta("a\nreport");
        stream.tick(egress.as_ref(), start);
        *egress.fail.lock() = true;
        stream.tick(egress.as_ref(), start + EDIT_EVERY);
        drop(stream);
        let mut recovered = AnswerStream::new(root.reply_delivery("unknown", None, None).unwrap());
        recovered.delta("a\nreport");
        recovered.tick(egress.as_ref(), start + EDIT_EVERY * 2);
        recovered.tick(egress.as_ref(), start + EDIT_EVERY * 3);
        assert!(root.deliver_final("unknown", "a\nreport", None).is_err());
        assert_eq!(*egress.log.lock(), ["post a\nreport"]);
    }

    #[test]
    fn a_status_reads_step_age_and_background_work() {
        let work = |what: &str, seconds| BackgroundWork {
            what: what.to_owned(),
            seconds,
        };
        assert_eq!(
            render("Reading mail", Duration::from_secs(64), &[]),
            "Working, 1 min 4 s: Reading mail"
        );
        let five: Vec<_> = (1..=5).map(|n| work(&format!("job {n}"), n)).collect();
        assert_eq!(
            render("Waiting", Duration::from_secs(3), &five),
            "Working, 3 s: Waiting\nIn the background: job 1 (1 s), job 2 (2 s), job 3 (3 s), job 4 (4 s) and 1 more"
        );
    }

    #[test]
    fn long_steps_are_cut_on_one_line_and_ages_read_in_units() {
        assert_eq!(short("one\n two   three"), "one two three");
        let cut = short(&"word ".repeat(40));
        assert_eq!(cut.chars().count(), STATUS_WHAT_CHARS);
        assert!(cut.ends_with('…'));
        assert_eq!(age(59), "59 s");
        assert_eq!(age(3_725), "1 h 2 min");
    }
}
