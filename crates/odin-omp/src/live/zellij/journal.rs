use async_trait::async_trait;
use futures_core::Stream;
use odin_domain::huginn::{LiveError, TerminalDelta, TerminalSeq, TerminalSnapshot};
use std::pin::Pin;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;

use super::{invalid_terminal, unavailable, ZellijLiveAdapter, TAIL_CAPACITY};
use crate::live::normalize::TerminalObservation;

#[async_trait]
pub trait TerminalEventSink: Send + Sync {
    async fn persist(&self, observation: TerminalObservation) -> Result<(), LiveError>;
}

#[derive(Clone, Debug)]
pub enum TerminalReplayItem {
    Reset(TerminalSnapshot),
    Delta(TerminalDelta),
}

pub type TerminalReadStream =
    Pin<Box<dyn Stream<Item = Result<TerminalReplayItem, LiveError>> + Send + 'static>>;

#[derive(Clone, Debug)]
pub struct TerminalReplay {
    pub snapshot: TerminalSnapshot,
    pub deltas: Vec<TerminalDelta>,
    pub head: TerminalSeq,
}

impl ZellijLiveAdapter {
    pub fn bind_sink(&self, sink: Arc<dyn TerminalEventSink>) -> Result<(), LiveError> {
        *self.sink.write().map_err(|_| unavailable())? = Some(sink);
        Ok(())
    }

    pub async fn snapshot(&self) -> Result<TerminalSnapshot, LiveError> {
        let captured_epoch = *self.epoch.read().await;
        let mut captured = self.pane.capture().await?;
        if captured.contents.contains('\0') {
            captured.contents = captured.contents.replace('\0', "�");
        }
        let mut state = self.state.lock().await;
        let epoch = *self.epoch.read().await;
        if epoch != captured_epoch {
            return Err(LiveError::Conflict {
                code: "terminal_capture_epoch_changed".to_owned(),
                message: "the session incarnation changed during terminal capture".to_owned(),
            });
        }
        if let Some(previous) = state.snapshots.back() {
            if previous.epoch == epoch
                && previous.columns == captured.columns
                && previous.rows == captured.rows
                && previous.cursor == captured.cursor
                && previous.contents == captured.contents
            {
                return Ok(previous.clone());
            }
        }
        let sequence = next_sequence(state.head)?;
        let snapshot = TerminalSnapshot {
            session_id: self.session_id,
            epoch,
            sequence,
            recorded_at: OffsetDateTime::now_utc(),
            columns: captured.columns,
            rows: captured.rows,
            contents: captured.contents,
            cursor: captured.cursor,
        };
        snapshot.validate().map_err(invalid_terminal)?;
        self.persist(TerminalObservation::Snapshot(snapshot.clone()))
            .await?;
        state.head = sequence;
        state.snapshots.push_back(snapshot.clone());
        while state.snapshots.len() > 2 {
            state.snapshots.pop_front();
        }
        let _ = self.tail.send(TerminalReplayItem::Reset(snapshot.clone()));
        Ok(snapshot)
    }

    pub async fn replay(&self, after: Option<TerminalSeq>) -> Result<TerminalReplay, LiveError> {
        let state = self.state.lock().await;
        let requested = after.unwrap_or(state.head);
        let snapshot = state
            .snapshots
            .iter()
            .rev()
            .find(|snapshot| snapshot.sequence <= requested)
            .or_else(|| state.snapshots.back())
            .cloned()
            .ok_or_else(|| LiveError::NotFound {
                object_kind: "terminal_snapshot".to_owned(),
                object_id: self.session_id.to_string(),
            })?;
        let deltas = state
            .deltas
            .iter()
            .filter(|delta| delta.sequence > requested.max(snapshot.sequence))
            .cloned()
            .collect();
        Ok(TerminalReplay {
            snapshot,
            deltas,
            head: state.head,
        })
    }

    pub async fn subscribe_read_only(
        &self,
        after: Option<TerminalSeq>,
    ) -> Result<TerminalReadStream, LiveError> {
        let mut tail = self.tail.subscribe();
        let replay = self.replay(after).await?;
        let (sender, receiver) = mpsc::channel(TAIL_CAPACITY);
        tokio::spawn(async move {
            if sender
                .send(Ok(TerminalReplayItem::Reset(replay.snapshot)))
                .await
                .is_err()
            {
                return;
            }
            for delta in replay.deltas {
                if sender
                    .send(Ok(TerminalReplayItem::Delta(delta)))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            loop {
                match tail.recv().await {
                    Ok(item) => {
                        if sender.send(Ok(item)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = sender.send(Err(LiveError::SubscriptionOverflow)).await;
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }

    pub async fn terminate_pane(&self) -> Result<(), LiveError> {
        self.pane.terminate().await
    }

    /// The pane this adapter drives, for tests that address it directly.
    #[cfg(test)]
    pub(crate) fn pane_for_test(&self) -> Arc<dyn super::ZellijPane> {
        Arc::clone(&self.pane)
    }

    async fn persist(&self, observation: TerminalObservation) -> Result<(), LiveError> {
        let sink = self
            .sink
            .read()
            .map_err(|_| unavailable())?
            .clone()
            .ok_or_else(unavailable)?;
        sink.persist(observation).await
    }
}

fn next_sequence(current: TerminalSeq) -> Result<TerminalSeq, LiveError> {
    current
        .checked_increment()
        .ok_or_else(|| LiveError::ResourceLimit {
            limit: "terminal sequence exhausted".to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::zellij::{CapturedTerminal, ZellijPane};
    use odin_domain::huginn::{LiveSessionId, SessionEpoch, TerminalCursor};
    use odin_domain::CommandId;
    use std::num::NonZeroU16;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Pane;
    #[async_trait]
    impl ZellijPane for Pane {
        async fn capture(&self) -> Result<CapturedTerminal, LiveError> {
            Ok(CapturedTerminal {
                columns: NonZeroU16::new(80).unwrap(),
                rows: NonZeroU16::new(24).unwrap(),
                contents: "actual pane output".to_owned(),
                cursor: TerminalCursor {
                    row: 0,
                    column: 0,
                    visible: true,
                },
            })
        }
        async fn write_input(&self, _: &CommandId, _: &[u8]) -> Result<(), LiveError> {
            Ok(())
        }
        async fn resize(
            &self,
            _: &CommandId,
            _: NonZeroU16,
            _: NonZeroU16,
        ) -> Result<(), LiveError> {
            Ok(())
        }
        async fn terminate(&self) -> Result<(), LiveError> {
            Ok(())
        }
    }

    struct Sink(AtomicUsize);
    #[async_trait]
    impl TerminalEventSink for Sink {
        async fn persist(&self, _: TerminalObservation) -> Result<(), LiveError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn unchanged_screen_preserves_sequence_but_new_epoch_resets() {
        let root = tempfile::tempdir().unwrap();
        let session = LiveSessionId::parse("11111111-2222-4333-8444-555555555555").unwrap();
        let adapter = ZellijLiveAdapter::open(
            root.path(),
            session,
            SessionEpoch::new(1),
            TerminalSeq::new(7),
            Arc::new(Pane),
        )
        .unwrap();
        let sink = Arc::new(Sink(AtomicUsize::new(0)));
        adapter.bind_sink(sink.clone()).unwrap();
        let first = adapter.snapshot().await.unwrap();
        let same = adapter.snapshot().await.unwrap();
        assert_eq!(first, same);
        assert_eq!(first.sequence.get(), 8);
        assert_eq!(sink.0.load(Ordering::SeqCst), 1);
        adapter.set_epoch(SessionEpoch::new(2)).await.unwrap();
        let reset = adapter.snapshot().await.unwrap();
        assert_eq!(reset.session_id, session);
        assert_eq!(reset.epoch.get(), 2);
        assert_eq!(reset.sequence.get(), 9);
        assert_eq!(sink.0.load(Ordering::SeqCst), 2);
    }
}
