use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_core::Stream;
use odin_domain::huginn::StreamId;
use odin_domain::huginn::{
    HuginnMessage, HuginnMessageStream, HuginnProtocolError, HuginnStreamSource, LiveStreamMode,
    Sequence, StreamCursor, StreamLifecycle, StreamStatus, StreamSubscription, SubscriptionSet,
};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use super::backpressure::{BackpressureError, BoundedQueue, CreditGrant, CreditWindow};
use super::replay::{DurableReplayStore, MultiplexedItem, ReplayError, StreamRetentionLease};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionEvent {
    ReplayBegin {
        stream_id: StreamId,
        requested_after: Sequence,
        head: Sequence,
    },
    Item(Arc<MultiplexedItem>),
    ReplayComplete {
        stream_id: StreamId,
        head: Sequence,
    },
    LatestFrameLoss(StreamStatus),
    Closed(StreamStatus),
    Failed {
        stream_id: StreamId,
        error: HuginnProtocolError,
    },
}

#[derive(Clone)]
pub struct BoundedMultiplexer {
    inner: Arc<Inner>,
}

struct Inner {
    replay: DurableReplayStore,
    subscriptions: Mutex<MultiplexerState>,
    next_subscription: AtomicU64,
    outbound_depth: usize,
    max_subscriptions: usize,
}

struct MultiplexerState {
    streams: HashMap<(u64, StreamId), SubscriptionState>,
    latest_heads: HashMap<StreamId, Sequence>,
    latest_items: HashMap<StreamId, Arc<MultiplexedItem>>,
}

struct SubscriptionState {
    stream_id: StreamId,
    kind: odin_domain::huginn::LiveStreamKind,
    mode: LiveStreamMode,
    lifecycle: StreamLifecycle,
    sender: mpsc::Sender<SubscriptionEvent>,
    credit: CreditWindow,
    pending: BoundedQueue<Arc<MultiplexedItem>>,
    replay_complete: Option<Sequence>,
    durable_head: Option<Sequence>,
    last_delivered: Option<Sequence>,
    control_revision: u64,
    dropped_items: u64,
    reported_drops: u64,
    updated_at: OffsetDateTime,
    failure: Option<String>,
    terminal_error: Option<HuginnProtocolError>,
    close_requested: bool,
    limits: odin_domain::huginn::StreamBackpressureLimits,
}

pub struct SubscriptionHandle {
    id: u64,
    inner: Arc<Inner>,
    receiver: ReceiverStream<SubscriptionEvent>,
    retention_depth: usize,
    poisoned: bool,
}

impl BoundedMultiplexer {
    /// Maximum delivered items whose retention leases may remain held by one
    /// protocol subscription, independent of its outbound channel depth.
    pub(crate) const MAX_DELIVERED_LEASE_WINDOW: usize = 32;

    pub fn new(
        replay: DurableReplayStore,
        outbound_depth: usize,
        max_subscriptions: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                replay,
                subscriptions: Mutex::new(MultiplexerState {
                    streams: HashMap::new(),
                    latest_heads: HashMap::new(),
                    latest_items: HashMap::new(),
                }),
                next_subscription: AtomicU64::new(1),
                outbound_depth: outbound_depth.max(1),
                max_subscriptions: max_subscriptions.max(1),
            }),
        }
    }

    /// The durable replay head of one stream — `0` when nothing was ever
    /// retained. A durable-stream producer resumes exactly after this
    /// sequence, so a restart can neither duplicate nor skip a frame.
    pub fn durable_head(&self, stream_id: &StreamId) -> Result<Sequence, HuginnProtocolError> {
        self.inner
            .replay
            .head(stream_id)
            .map_err(replay_protocol_error)
    }

    pub fn open(
        &self,
        subscriptions: SubscriptionSet,
        now: OffsetDateTime,
    ) -> Result<SubscriptionHandle, HuginnProtocolError> {
        if !subscriptions.is_valid() {
            return Err(HuginnProtocolError::InvalidRequest {
                code: "subscription-set".to_owned(),
                message: "subscription set is empty, duplicated, or has an invalid stream mode"
                    .to_owned(),
            });
        }
        if subscriptions.subscriptions.len() > self.inner.max_subscriptions {
            return Err(HuginnProtocolError::ResourceLimit {
                limit: "subscriptions-per-connection".to_owned(),
            });
        }
        let id = self.inner.next_subscription.fetch_add(1, Ordering::Relaxed);
        if id == u64::MAX {
            return Err(HuginnProtocolError::Unavailable {
                code: "subscription-id-exhausted".to_owned(),
            });
        }
        let stream_count = subscriptions.subscriptions.len();
        let marker_depth =
            stream_count
                .checked_mul(2)
                .ok_or_else(|| HuginnProtocolError::ResourceLimit {
                    limit: "subscription-channel".to_owned(),
                })?;
        let channel_depth = self
            .inner
            .outbound_depth
            .checked_mul(stream_count)
            .and_then(|depth| depth.checked_add(marker_depth))
            .ok_or_else(|| HuginnProtocolError::ResourceLimit {
                limit: "subscription-channel".to_owned(),
            })?;
        let channel_depth = channel_depth.max(1);
        let (sender, receiver) = mpsc::channel(channel_depth);
        let mut state = multiplexer_state(&self.inner)?;
        for subscription in subscriptions.subscriptions {
            if let Err(error) =
                self.insert_subscription(&mut state, id, sender.clone(), subscription, now)
            {
                state
                    .streams
                    .retain(|(subscription_id, _), _| *subscription_id != id);
                return Err(error);
            }
        }
        Ok(SubscriptionHandle {
            id,
            inner: Arc::clone(&self.inner),
            receiver: ReceiverStream::new(receiver),
            retention_depth: channel_depth.min(Self::MAX_DELIVERED_LEASE_WINDOW),
            poisoned: false,
        })
    }

    pub fn publish(
        &self,
        item: MultiplexedItem,
        now: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let mode = item.frame.kind.mode();
        let item = Arc::new(item);
        let mut state = multiplexer_state(&self.inner)?;
        if mode == LiveStreamMode::Durable {
            append_off_runtime(&self.inner.replay, &item).map_err(replay_protocol_error)?;
        }
        if mode == LiveStreamMode::LatestFrame {
            let prior = state.latest_heads.get(&item.frame.stream_id).copied();
            if prior.is_some_and(|head| item.frame.sequence <= head) {
                return Err(HuginnProtocolError::Conflict {
                    code: "stream-sequence".to_owned(),
                    message: "latest-frame sequence must increase".to_owned(),
                });
            }
            if !state.latest_items.contains_key(&item.frame.stream_id)
                && state.latest_items.len() >= self.inner.max_subscriptions
            {
                return Err(HuginnProtocolError::ResourceLimit {
                    limit: "latest-frame-streams".to_owned(),
                });
            }
            state
                .latest_heads
                .insert(item.frame.stream_id, item.frame.sequence);
            state
                .latest_items
                .insert(item.frame.stream_id, Arc::clone(&item));
        }
        for subscription in state.streams.values_mut().filter(|subscription| {
            subscription.stream_id == item.frame.stream_id
                && subscription.kind == item.frame.kind
                && subscription.lifecycle != StreamLifecycle::Closed
                && subscription.lifecycle != StreamLifecycle::Failed
                && !subscription.close_requested
        }) {
            subscription.updated_at = now;
            subscription.control_revision = item.frame.control_revision;
            if mode == LiveStreamMode::Durable {
                subscription.durable_head = Some(item.frame.sequence);
            }
            enqueue(subscription, Arc::clone(&item), now);
        }
        Ok(())
    }

    /// Gracefully closes a stream after draining already-buffered items and
    /// evicts its retained latest frame so reconnects cannot observe stale
    /// browser output.
    pub fn close_stream(
        &self,
        stream_id: &StreamId,
        now: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let mut state = multiplexer_state(&self.inner)?;
        state.latest_heads.remove(stream_id);
        state.latest_items.remove(stream_id);
        for subscription in state
            .streams
            .values_mut()
            .filter(|subscription| &subscription.stream_id == stream_id)
        {
            graceful_close_subscription(subscription, now);
        }
        Ok(())
    }

    fn insert_subscription(
        &self,
        state: &mut MultiplexerState,
        id: u64,
        sender: mpsc::Sender<SubscriptionEvent>,
        subscription: StreamSubscription,
        now: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError> {
        let stream_id = *subscription.cursor.stream_id();
        let mut entry = SubscriptionState {
            stream_id,
            kind: subscription.kind,
            mode: subscription.kind.mode(),
            lifecycle: StreamLifecycle::Opening,
            sender,
            credit: CreditWindow::new(subscription.credit, subscription.limits),
            pending: BoundedQueue::new(subscription.limits),
            replay_complete: None,
            durable_head: None,
            last_delivered: None,
            control_revision: 0,
            dropped_items: 0,
            reported_drops: 0,
            terminal_error: None,
            updated_at: now,
            failure: None,
            limits: subscription.limits,
            close_requested: false,
        };
        match subscription.cursor {
            StreamCursor::Durable { after, .. } => {
                let after = after.unwrap_or_else(|| Sequence::new(0));
                let head = self
                    .inner
                    .replay
                    .head(&stream_id)
                    .map_err(replay_protocol_error)?;
                entry.durable_head = Some(head);
                entry
                    .sender
                    .try_send(SubscriptionEvent::ReplayBegin {
                        stream_id,
                        requested_after: after,
                        head,
                    })
                    .map_err(|_| HuginnProtocolError::ResourceLimit {
                        limit: "subscription-channel".to_owned(),
                    })?;
                let replay = self
                    .inner
                    .replay
                    .replay(
                        &stream_id,
                        after,
                        head,
                        usize::try_from(subscription.limits.max_buffered_items.get())
                            .unwrap_or(usize::MAX),
                    )
                    .map_err(replay_protocol_error)?;
                // One stream id carries several kinds (a session's agent
                // events and its terminal); a subscription replays its own.
                for item in replay
                    .items
                    .into_iter()
                    .filter(|item| item.frame.kind == entry.kind)
                {
                    let bytes = item.frame.content.byte_len;
                    entry
                        .pending
                        .push(Arc::new(item), bytes)
                        .map_err(backpressure_protocol_error)?;
                }
                entry.replay_complete = Some(head);
                drain(&mut entry, now);
            }
            StreamCursor::LatestFrame { .. } => {
                entry.lifecycle = StreamLifecycle::Live;
                if let Some(item) = state.latest_items.get(&stream_id) {
                    if item.frame.kind != entry.kind {
                        return Err(HuginnProtocolError::Conflict {
                            code: "stream-kind".to_owned(),
                            message: "stream identity was reused for another stream kind"
                                .to_owned(),
                        });
                    }
                    enqueue(&mut entry, Arc::clone(item), now);
                }
            }
        }
        state.streams.insert((id, stream_id), entry);
        Ok(())
    }
}

impl SubscriptionHandle {
    pub const fn id(&self) -> u64 {
        self.id
    }

    pub async fn recv(&mut self) -> Result<Option<SubscriptionEvent>, HuginnProtocolError> {
        if self.poisoned {
            return Ok(None);
        }
        if let Err(error) = self.drain_terminal_streams(OffsetDateTime::now_utc()) {
            self.poisoned = true;
            return Err(error);
        }
        let event = self.receiver.next().await;
        if let Err(error) = self.drain_terminal_streams(OffsetDateTime::now_utc()) {
            self.poisoned = true;
            return Err(error);
        }
        match &event {
            Some(SubscriptionEvent::Item(item)) => {
                if let Err(error) = self.grant(
                    &item.frame.stream_id,
                    CreditGrant {
                        items: 1,
                        bytes: item.frame.content.byte_len,
                    },
                    item.frame.produced_at,
                ) {
                    self.poisoned = true;
                    return Err(error);
                }
            }
            Some(SubscriptionEvent::Closed(status)) => {
                if let Err(error) = self.remove_stream(&status.stream_id) {
                    self.poisoned = true;
                    return Err(error);
                }
            }
            Some(SubscriptionEvent::Failed {
                stream_id,
                error: _,
            }) => {
                if let Err(error) = self.remove_stream(stream_id) {
                    self.poisoned = true;
                    return Err(error);
                }
            }
            _ => {}
        }
        Ok(event)
    }

    pub fn grant(
        &self,
        stream_id: &StreamId,
        grant: CreditGrant,
        now: OffsetDateTime,
    ) -> Result<bool, HuginnProtocolError> {
        let mut state = multiplexer_state(&self.inner)?;
        let Some(subscription) = state.streams.get_mut(&(self.id, *stream_id)) else {
            return Ok(false);
        };
        subscription.credit.grant(grant);
        drain(subscription, now);
        Ok(true)
    }

    fn remove_stream(&self, stream_id: &StreamId) -> Result<(), HuginnProtocolError> {
        multiplexer_state(&self.inner)?
            .streams
            .remove(&(self.id, *stream_id));
        Ok(())
    }
    fn drain_terminal_streams(&self, now: OffsetDateTime) -> Result<(), HuginnProtocolError> {
        let mut state = multiplexer_state(&self.inner)?;
        for ((id, _), subscription) in &mut state.streams {
            let pending_failure = subscription.lifecycle == StreamLifecycle::Failed
                && subscription.terminal_error.is_some();
            if *id == self.id
                && (subscription.close_requested || pending_failure)
                && subscription.sender.capacity() > 0
            {
                drain(subscription, now);
            }
        }
        Ok(())
    }

    pub fn statuses(&self, now: OffsetDateTime) -> Result<Vec<StreamStatus>, HuginnProtocolError> {
        let state = multiplexer_state(&self.inner)?;
        let mut statuses: Vec<_> = state
            .streams
            .iter()
            .filter(|((id, _), _)| *id == self.id)
            .map(|(_, subscription)| subscription.status(now))
            .collect();
        statuses.sort_by_key(|status| status.stream_id);
        Ok(statuses)
    }

    fn into_protocol_stream(self) -> HuginnMessageStream {
        Box::pin(ProtocolSubscription {
            retention_depth: self.retention_depth,
            handle: self,
            delivered_retentions: VecDeque::new(),
        })
    }
}

impl Stream for SubscriptionHandle {
    type Item = Result<SubscriptionEvent, HuginnProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.poisoned {
            return Poll::Ready(None);
        }
        if let Err(error) = self.drain_terminal_streams(OffsetDateTime::now_utc()) {
            self.poisoned = true;
            return Poll::Ready(Some(Err(error)));
        }
        let event = Pin::new(&mut self.receiver).poll_next(context);
        if let Poll::Ready(Some(event)) = &event {
            if let Err(error) = self.drain_terminal_streams(OffsetDateTime::now_utc()) {
                self.poisoned = true;
                return Poll::Ready(Some(Err(error)));
            }
            let removal = match event {
                SubscriptionEvent::Closed(status) => self.remove_stream(&status.stream_id),
                SubscriptionEvent::Failed {
                    stream_id,
                    error: _,
                } => self.remove_stream(stream_id),
                _ => Ok(()),
            };
            if let Err(error) = removal {
                self.poisoned = true;
                return Poll::Ready(Some(Err(error)));
            }
        }
        event.map(|event| event.map(Ok))
    }
}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        // A destructor cannot return a protocol error: poisoned state is
        // cleaned up best-effort here. This destructor exception is not a
        // successful protocol operation; fallible paths report the poison
        // as `HuginnProtocolError::Unavailable`.
        multiplexer_state_best_effort(&self.inner)
            .streams
            .retain(|(id, _), _| *id != self.id);
    }
}

struct ProtocolSubscription {
    handle: SubscriptionHandle,
    delivered_retentions: VecDeque<(StreamId, Arc<dyn StreamRetentionLease>)>,
    retention_depth: usize,
}

impl ProtocolSubscription {
    fn retain_delivery(&mut self, stream_id: StreamId, lease: Arc<dyn StreamRetentionLease>) {
        if self.delivered_retentions.len() == self.retention_depth {
            self.delivered_retentions.pop_front();
        }
        self.delivered_retentions.push_back((stream_id, lease));
    }

    fn release_stream(&mut self, stream_id: &StreamId) {
        self.delivered_retentions
            .retain(|(retained_stream_id, _)| retained_stream_id != stream_id);
    }
}

impl Stream for ProtocolSubscription {
    type Item = Result<HuginnMessage, HuginnProtocolError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.handle).poll_next(context) {
            Poll::Ready(Some(Ok(SubscriptionEvent::ReplayBegin {
                stream_id,
                requested_after,
                head,
            }))) => Poll::Ready(Some(Ok(HuginnMessage::ReplayBegin {
                stream: stream_id,
                requested_after,
                head,
            }))),
            Poll::Ready(Some(Ok(SubscriptionEvent::Item(item)))) => {
                let stream_id = item.frame.stream_id;
                if let Err(error) = self.handle.grant(
                    &stream_id,
                    CreditGrant {
                        items: 1,
                        bytes: item.frame.content.byte_len,
                    },
                    item.frame.produced_at,
                ) {
                    self.handle.poisoned = true;
                    return Poll::Ready(Some(Err(error)));
                }
                let owned = Arc::try_unwrap(item).unwrap_or_else(|shared| (*shared).clone());
                let (message, retention) = owned.into_message_and_retention();
                if let Some(lease) = retention {
                    self.retain_delivery(stream_id, lease);
                }
                Poll::Ready(Some(Ok(message)))
            }
            Poll::Ready(Some(Ok(SubscriptionEvent::ReplayComplete { stream_id, head }))) => {
                Poll::Ready(Some(Ok(HuginnMessage::ReplayComplete {
                    stream: stream_id,
                    head,
                })))
            }
            Poll::Ready(Some(Ok(SubscriptionEvent::LatestFrameLoss(status)))) => {
                Poll::Ready(Some(Ok(HuginnMessage::StreamStatus(status))))
            }
            Poll::Ready(Some(Ok(SubscriptionEvent::Closed(status)))) => {
                self.release_stream(&status.stream_id);
                Poll::Ready(Some(Ok(HuginnMessage::StreamStatus(status))))
            }
            Poll::Ready(Some(Ok(SubscriptionEvent::Failed { stream_id, error }))) => {
                self.release_stream(&stream_id);
                Poll::Ready(Some(Err(error)))
            }
            // Poison reported by the handle: forward the single typed error;
            // the handle ends the stream on the next poll.
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => {
                self.delivered_retentions.clear();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[async_trait]
impl HuginnStreamSource for BoundedMultiplexer {
    async fn subscribe(
        &self,
        subscriptions: SubscriptionSet,
    ) -> Result<HuginnMessageStream, HuginnProtocolError> {
        self.open(subscriptions, OffsetDateTime::now_utc())
            .map(SubscriptionHandle::into_protocol_stream)
    }
}

impl SubscriptionState {
    fn status(&self, now: OffsetDateTime) -> StreamStatus {
        StreamStatus {
            stream_id: self.stream_id,
            kind: self.kind,
            mode: self.mode,
            lifecycle: self.lifecycle,
            durable_head: self.durable_head,
            last_delivered: self.last_delivered,
            control_revision: self.control_revision,
            buffered_items: u32::try_from(self.pending.len()).unwrap_or(u32::MAX),
            buffered_bytes: self.pending.bytes(),
            dropped_items: self.dropped_items,
            limits: self.limits,
            updated_at: now.max(self.updated_at),
            failure: self.failure.clone(),
        }
    }
}

fn enqueue(subscription: &mut SubscriptionState, item: Arc<MultiplexedItem>, now: OffsetDateTime) {
    let byte_len = item.frame.content.byte_len;
    let result = if subscription.mode == LiveStreamMode::LatestFrame
        && (!subscription.credit.can_send(byte_len) || subscription.sender.capacity() == 0)
    {
        subscription
            .pending
            .replace_latest(item, byte_len)
            .map(|replaced| {
                if replaced {
                    subscription.dropped_items = subscription.dropped_items.saturating_add(1);
                }
            })
    } else {
        subscription.pending.push(item, byte_len)
    };
    if let Err(error) = result {
        fail_subscription(subscription, backpressure_protocol_error(error), now);
        return;
    }
    drain(subscription, now);
}

fn drain(subscription: &mut SubscriptionState, now: OffsetDateTime) {
    if subscription.lifecycle == StreamLifecycle::Closed {
        return;
    }
    if subscription.lifecycle == StreamLifecycle::Failed {
        let Some(error) = subscription.terminal_error.clone() else {
            return;
        };
        if subscription.sender.capacity() > 0
            && subscription
                .sender
                .try_send(SubscriptionEvent::Failed {
                    stream_id: subscription.stream_id,
                    error,
                })
                .is_ok()
        {
            subscription.terminal_error = None;
            subscription.lifecycle = StreamLifecycle::Closed;
        }
        return;
    }
    if subscription.mode == LiveStreamMode::LatestFrame
        && subscription.dropped_items > subscription.reported_drops
        && subscription.sender.capacity() > 0
    {
        let status = subscription.status(now);
        if subscription
            .sender
            .try_send(SubscriptionEvent::LatestFrameLoss(status))
            .is_ok()
        {
            subscription.reported_drops = subscription.dropped_items;
        } else {
            subscription.lifecycle = StreamLifecycle::Closed;
            return;
        }
    }
    while let Some(bytes) = subscription.pending.front_bytes() {
        if !subscription.credit.can_send(bytes) || subscription.sender.capacity() == 0 {
            subscription.lifecycle = StreamLifecycle::Stalled;
            return;
        }
        if !subscription.credit.consume(bytes) {
            subscription.lifecycle = StreamLifecycle::Stalled;
            return;
        }
        let item = subscription.pending.pop().expect("front exists");
        subscription.last_delivered = Some(item.frame.sequence);
        subscription.control_revision = item.frame.control_revision;
        if subscription
            .sender
            .try_send(SubscriptionEvent::Item(item))
            .is_err()
        {
            subscription.lifecycle = StreamLifecycle::Closed;
            return;
        }
    }
    if let Some(head) = subscription.replay_complete.take() {
        if subscription.sender.capacity() == 0 {
            subscription.replay_complete = Some(head);
            subscription.lifecycle = StreamLifecycle::Stalled;
            return;
        }
        if subscription
            .sender
            .try_send(SubscriptionEvent::ReplayComplete {
                stream_id: subscription.stream_id,
                head,
            })
            .is_err()
        {
            subscription.lifecycle = StreamLifecycle::Closed;
            return;
        }
    }
    if subscription.close_requested {
        if subscription.sender.capacity() == 0 {
            subscription.lifecycle = StreamLifecycle::Stalled;
            return;
        }
        subscription.close_requested = false;
        subscription.lifecycle = StreamLifecycle::Closed;
        subscription.updated_at = now;
        let status = subscription.status(now);
        if subscription
            .sender
            .try_send(SubscriptionEvent::Closed(status))
            .is_err()
        {
            return;
        }
        return;
    }
    subscription.lifecycle = StreamLifecycle::Live;
    subscription.updated_at = now;
}

fn graceful_close_subscription(subscription: &mut SubscriptionState, now: OffsetDateTime) {
    if matches!(
        subscription.lifecycle,
        StreamLifecycle::Closed | StreamLifecycle::Failed
    ) {
        return;
    }
    subscription.close_requested = true;
    subscription.updated_at = now;
    if subscription.mode == LiveStreamMode::LatestFrame {
        while subscription.pending.pop().is_some() {
            subscription.dropped_items = subscription.dropped_items.saturating_add(1);
        }
    }
    drain(subscription, now);
}

fn fail_subscription(
    subscription: &mut SubscriptionState,
    error: HuginnProtocolError,
    now: OffsetDateTime,
) {
    subscription.lifecycle = StreamLifecycle::Failed;
    subscription.failure = Some(error.to_string());
    subscription.terminal_error = Some(error);
    subscription.updated_at = now;
    drain(subscription, now);
}

// A runtime worker must not run the sqlite append. Sync callers, and a
// current-thread runtime where `block_in_place` is illegal, keep the direct path.
fn append_off_runtime(
    replay: &DurableReplayStore,
    item: &MultiplexedItem,
) -> Result<(), ReplayError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(|| replay.append(item))
        }
        _ => replay.append(item),
    }
}

fn replay_protocol_error(error: ReplayError) -> HuginnProtocolError {
    match error {
        ReplayError::CursorExpired { .. } => HuginnProtocolError::CursorExpired,
        ReplayError::ItemTooLarge { .. } | ReplayError::BatchTooLarge { .. } => {
            HuginnProtocolError::ResourceLimit {
                limit: "stream-replay".to_owned(),
            }
        }
        ReplayError::SequenceGap {
            stream_id,
            head,
            received,
        } => HuginnProtocolError::Conflict {
            code: "stream-sequence".to_owned(),
            message: format!("stream {stream_id} sequence {received} does not follow head {head}"),
        },
        ReplayError::Storage | ReplayError::InvalidRecord => HuginnProtocolError::Unavailable {
            code: "stream-replay".to_owned(),
        },
    }
}

fn backpressure_protocol_error(error: BackpressureError) -> HuginnProtocolError {
    HuginnProtocolError::ResourceLimit {
        limit: match error {
            BackpressureError::ItemTooLarge { .. } => "stream-item".to_owned(),
            BackpressureError::Overflow => "subscription-buffer".to_owned(),
        },
    }
}

/// Lock the multiplexer state on paths that can return a protocol error.
/// A poisoned lock means prior-panic corruption of shared state: it is
/// reported as `HuginnProtocolError::Unavailable`, never recovered
/// silently and never retried globally.
fn multiplexer_state(
    inner: &Inner,
) -> Result<MutexGuard<'_, MultiplexerState>, HuginnProtocolError> {
    inner
        .subscriptions
        .lock()
        .map_err(|_| HuginnProtocolError::Unavailable {
            code: "multiplexer-lock-poisoned".to_owned(),
        })
}

/// Lock the multiplexer state for best-effort destruction in `Drop` only.
/// A poisoned lock is recovered with `PoisonError::into_inner` as explicit
/// best-effort cleanup of the subscriptions this handle owns; this is not a
/// successful protocol operation. Every normal operation goes through
/// `multiplexer_state`, which reports the poison as
/// `HuginnProtocolError::Unavailable`.
fn multiplexer_state_best_effort(inner: &Inner) -> MutexGuard<'_, MultiplexerState> {
    inner
        .subscriptions
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use odin_domain::huginn::{
        ArtifactKind, ArtifactRef, HuginnMessage, HuginnProtocolError, LiveSessionId,
        LiveStreamKind, Sequence, StreamFrame, StreamId,
    };
    use odin_domain::{ArtifactId, Digest, LaneId};
    use time::OffsetDateTime;

    use super::BoundedMultiplexer;
    use crate::streams::replay::{DurableReplayStore, MultiplexedItem};

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("timestamp")
    }

    fn stream(id: &str) -> StreamId {
        StreamId::parse(id).expect("stream id")
    }

    fn item(stream_id: StreamId, sequence: u64) -> MultiplexedItem {
        kind_item(stream_id, sequence, LiveStreamKind::AgentEvents)
    }

    fn kind_item(stream_id: StreamId, sequence: u64, kind: LiveStreamKind) -> MultiplexedItem {
        MultiplexedItem::new(
            StreamFrame {
                stream_id,
                kind,
                sequence: Sequence::new(sequence),
                control_revision: 1,
                produced_at: now(),
                key_frame: true,
                content: ArtifactRef {
                    artifact_id: ArtifactId::parse("00000000-0000-4000-8000-000000000002")
                        .expect("artifact id"),
                    session_id: LiveSessionId::parse("00000000-0000-4000-8000-000000000003")
                        .expect("session id"),
                    lane_id: LaneId::new("lane-test").expect("lane id"),
                    kind: ArtifactKind::File,
                    display_name: "test.dat".to_owned(),
                    media_type: "application/octet-stream".to_owned(),
                    byte_len: 4,
                    content_digest: Digest::new([1u8; 32]),
                },
            },
            HuginnMessage::ProtocolError(HuginnProtocolError::Unavailable {
                code: "test".to_owned(),
            }),
        )
    }

    fn multiplexer() -> (tempfile::TempDir, BoundedMultiplexer) {
        let dir = tempfile::tempdir().expect("replay dir");
        let replay =
            DurableReplayStore::open(dir.path().join("stream-items.sqlite3"), 64, 1024 * 1024)
                .expect("replay opens");
        (dir, BoundedMultiplexer::new(replay, 8, 8))
    }

    fn assert_multi_thread() {
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
    }

    /// Current-thread tests never enter the multi-thread durable append odind runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_thread_publish_appends_the_next_durable_frame() {
        assert_multi_thread();
        let (_dir, multiplexer) = multiplexer();
        let stream_id = stream("00000000-0000-4000-8000-000000000001");
        let now = now();
        multiplexer
            .publish(item(stream_id, 1), now)
            .expect("publish");
        multiplexer
            .publish(item(stream_id, 2), now)
            .expect("append after the retained prefix");
        assert_eq!(multiplexer.durable_head(&stream_id).expect("head").get(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_thread_concurrent_publishers_both_append() {
        assert_multi_thread();
        let (_dir, multiplexer) = multiplexer();
        let multiplexer = Arc::new(multiplexer);
        let left = Arc::clone(&multiplexer);
        let right = Arc::clone(&multiplexer);
        let now = now();
        let left_task = tokio::spawn(async move {
            left.publish(item(stream("00000000-0000-4000-8000-000000000011"), 1), now)
        });
        let right_task = tokio::spawn(async move {
            right.publish(item(stream("00000000-0000-4000-8000-000000000012"), 1), now)
        });
        left_task
            .await
            .expect("left publisher")
            .expect("left publish");
        right_task
            .await
            .expect("right publisher")
            .expect("right publish");
        assert_eq!(
            multiplexer
                .durable_head(&stream("00000000-0000-4000-8000-000000000011"))
                .expect("left head")
                .get(),
            1
        );
        assert_eq!(
            multiplexer
                .durable_head(&stream("00000000-0000-4000-8000-000000000012"))
                .expect("right head")
                .get(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_serves_only_the_subscribed_kind() {
        use futures_util::StreamExt as _;
        use odin_domain::huginn::{
            StreamBackpressureLimits, StreamCredit, StreamCursor, StreamSubscription,
            SubscriptionSet,
        };
        use std::num::{NonZeroU32, NonZeroU64};

        let (_dir, multiplexer) = multiplexer();
        let stream_id = stream("00000000-0000-4000-8000-000000000021");
        multiplexer
            .publish(kind_item(stream_id, 1, LiveStreamKind::AgentEvents), now())
            .expect("agent event");
        multiplexer
            .publish(kind_item(stream_id, 2, LiveStreamKind::Terminal), now())
            .expect("terminal frame");
        multiplexer
            .publish(kind_item(stream_id, 3, LiveStreamKind::AgentEvents), now())
            .expect("agent event");
        let mut handle = multiplexer
            .open(
                SubscriptionSet {
                    subscriptions: vec![StreamSubscription {
                        kind: LiveStreamKind::Terminal,
                        cursor: StreamCursor::Durable {
                            stream_id,
                            after: None,
                        },
                        credit: StreamCredit {
                            items: NonZeroU32::new(64).expect("items"),
                            bytes: NonZeroU64::new(1 << 20).expect("bytes"),
                        },
                        limits: StreamBackpressureLimits {
                            max_buffered_items: NonZeroU32::new(64).expect("items"),
                            max_buffered_bytes: NonZeroU64::new(1 << 20).expect("bytes"),
                            max_item_bytes: NonZeroU64::new(1 << 16).expect("item"),
                            max_items_per_second: NonZeroU32::new(256).expect("rate"),
                            max_in_flight_bytes: NonZeroU64::new(1 << 20).expect("flight"),
                        },
                    }],
                },
                now(),
            )
            .expect("subscribe");
        let mut replayed = Vec::new();
        while let Some(event) = handle.receiver.next().await {
            match event {
                super::SubscriptionEvent::Item(item) => {
                    replayed.push((item.frame.sequence.get(), item.frame.kind));
                }
                super::SubscriptionEvent::ReplayComplete { .. } => break,
                _ => {}
            }
        }
        assert_eq!(replayed, [(2, LiveStreamKind::Terminal)]);
    }
}
