//! Capture-head replay followed by a deduplicated buffered live tail.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use odin_domain::huginn::{EventSeq, LiveError, LiveEvent};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum ReplayTailItem {
    Event(Box<LiveEvent>),
    Overflow,
    Close,
}

pub struct ReplayJoin {
    snapshot: VecDeque<LiveEvent>,
    cursor: EventSeq,
    head: EventSeq,
    tail: mpsc::Receiver<ReplayTailItem>,
}

impl ReplayJoin {
    pub fn open(
        snapshot: Vec<LiveEvent>,
        cursor: EventSeq,
        head: EventSeq,
        tail: mpsc::Receiver<ReplayTailItem>,
    ) -> Self {
        Self {
            snapshot: snapshot.into(),
            cursor,
            head,
            tail,
        }
    }

    pub const fn cursor(&self) -> EventSeq {
        self.cursor
    }

    pub const fn head(&self) -> EventSeq {
        self.head
    }

    pub fn replay_then_tail(self) -> ReplayStream {
        ReplayStream {
            last_emitted: self.cursor.get(),
            join: self,
            state: ReplayState::Snapshot,
            terminal_error_emitted: false,
        }
    }
}

#[derive(Clone, Copy)]
enum ReplayState {
    Snapshot,
    Tail,
    Closed,
}

pub struct ReplayStream {
    join: ReplayJoin,
    state: ReplayState,
    last_emitted: u64,
    terminal_error_emitted: bool,
}

impl ReplayStream {
    pub const fn cursor(&self) -> EventSeq {
        self.join.cursor
    }

    pub const fn captured_head(&self) -> EventSeq {
        self.join.head
    }
}

impl Stream for ReplayStream {
    type Item = Result<LiveEvent, LiveError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match this.state {
                ReplayState::Snapshot => match this.join.snapshot.pop_front() {
                    Some(event) if event.sequence.get() > this.last_emitted => {
                        this.last_emitted = event.sequence.get();
                        return Poll::Ready(Some(Ok(event)));
                    }
                    Some(_) => continue,
                    None => this.state = ReplayState::Tail,
                },
                ReplayState::Tail => match Pin::new(&mut this.join.tail).poll_recv(context) {
                    Poll::Ready(Some(ReplayTailItem::Event(event)))
                        if event.sequence.get() > this.last_emitted =>
                    {
                        this.last_emitted = event.sequence.get();
                        return Poll::Ready(Some(Ok(*event)));
                    }
                    Poll::Ready(Some(ReplayTailItem::Event(_))) => continue,
                    Poll::Ready(Some(ReplayTailItem::Overflow)) => {
                        this.state = ReplayState::Closed;
                        if !this.terminal_error_emitted {
                            this.terminal_error_emitted = true;
                            return Poll::Ready(Some(Err(LiveError::SubscriptionOverflow)));
                        }
                    }
                    Poll::Ready(Some(ReplayTailItem::Close)) | Poll::Ready(None) => {
                        this.state = ReplayState::Closed;
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReplayState::Closed => return Poll::Ready(None),
            }
        }
    }
}
