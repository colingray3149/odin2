//! Throttled visible text updates on the original turn's durable reply.
//! Final settlement always goes through the root, even when text is unchanged.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::prompt::{without_quiet_token, QUIET_REPLY};
use super::ConversationEgress;
use crate::egress::DeliveryCheckpoint;

const EDIT_EVERY: Duration = Duration::from_secs(1);
/// Discord shows "typing…" for about ten seconds per trigger.
const TYPING_EVERY: Duration = Duration::from_secs(8);

pub(super) struct AnswerStream {
    segment: String,
    checkpoint: Arc<dyn DeliveryCheckpoint>,
    first_words: Option<Instant>,
    shown: Option<String>,
    last_edit: Option<Instant>,
    last_typing: Option<Instant>,
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
        if visible.is_empty() {
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
            Ok(_) => self.shown = Some(visible.to_owned()),
            Err(error) => {
                self.shown = None;
                tracing::error!(error = %error, "odind: conversation-stream delivery failed: {error}");
            }
        }
        self.last_edit = Some(now);
        None
    }
}

fn visible(segment: &str) -> &str {
    let trimmed = segment.trim();
    if QUIET_REPLY.starts_with(trimmed) {
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
        stream.delta("Oolong");
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
        root.deliver_final("stream", "Oolong tea.", None).unwrap();
        assert_eq!(
            *egress.log.lock(),
            [
                "typing",
                "post Oolong",
                "edit Oolong tea",
                "edit Oolong tea."
            ]
        );
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
        assert!(egress.log.lock().is_empty());
        root.deliver_final("short", "391.", None).unwrap();
        root.deliver_final("short", "391.", None).unwrap();
        assert_eq!(*egress.log.lock(), ["post 391."]);
    }

    #[tokio::test]
    async fn unchanged_final_still_commits_and_replays_original_key() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let mut stream = AnswerStream::new(root.reply_delivery("same", None, None).unwrap());
        let start = Instant::now();
        stream.delta("answer");
        stream.tick(egress.as_ref(), start);
        stream.tick(egress.as_ref(), start + EDIT_EVERY);
        let projection = serde_json::json!({ "answer": "answer", "idempotencyKey": "same" });
        root.deliver_final("same", "answer", Some(&projection))
            .unwrap();
        root.deliver_final("newer", "new answer", None).unwrap();
        let replay = root.replay_delivery("same").unwrap().unwrap();
        assert_eq!(replay["answer"], "answer");
        assert_eq!(replay["replySent"], true);
        assert_eq!(*egress.log.lock(), ["post answer", "post new answer"]);
    }

    #[tokio::test]
    async fn unknown_post_is_blocked_by_checkpoint_after_stream_reconstruction() {
        let egress = Arc::new(Recorder::default());
        let (_dir, root) = super::super::tests::delivery_test_root(egress.clone()).await;
        let start = Instant::now();
        let mut stream = AnswerStream::new(root.reply_delivery("unknown", None, None).unwrap());
        stream.delta("report");
        stream.tick(egress.as_ref(), start);
        *egress.fail.lock() = true;
        stream.tick(egress.as_ref(), start + EDIT_EVERY);
        drop(stream);
        let mut recovered = AnswerStream::new(root.reply_delivery("unknown", None, None).unwrap());
        recovered.delta("report");
        recovered.tick(egress.as_ref(), start + EDIT_EVERY * 2);
        recovered.tick(egress.as_ref(), start + EDIT_EVERY * 3);
        assert!(root.deliver_final("unknown", "report", None).is_err());
        assert_eq!(*egress.log.lock(), ["post report"]);
    }
}
