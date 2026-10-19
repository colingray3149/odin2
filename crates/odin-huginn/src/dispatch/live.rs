//! Bounded general/live dispatch: the [`LiveDispatcher`] runtime, its
//! limits and posture gates, the per-connection serve loop, and stream
//! pumping over the framed transport.

use async_trait::async_trait;
use futures_util::StreamExt;
use odin_domain::huginn::{
    urgent_object, ArtifactReadStream, ContentTicketIssuer, DeviceId, EventSeq, FileDeltaStream,
    FileGateway, FileReadStream, HuginnMessage, HuginnMessageStream, HuginnProtocolError,
    HuginnReadModel, HuginnRequest, HuginnStreamSource, LiveEvent, LiveEventStream,
    LiveProtocolError, LiveServerMessage, LiveSessionId, ObjectKind, ObjectSubscription,
    OmpLivePlane, QueryScope, RenderGateway, RenderStatusStream, Revision, SnapshotPage,
    SnapshotQuery, VerifiedColinDevice,
};
use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

use crate::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};
use crate::read_model::canonical_kinds;
use crate::state::NodePosture;

use super::command::AuthenticatedCommandPort;
use super::outbound::{until_ended, Control, DeliveryReceipt, Ending, Outbound};
use super::registry::{
    ConnectionFrame, ConnectionRegistration, FrameReader, FrameWriter, ServerConnection,
};

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("connection transport failed: {0}")]
    Transport(String),
    #[error("response encoding failed: {0}")]
    Codec(#[from] crate::protocol::CodecError),
    #[error("over {limit} bytes queued for a peer that is not reading")]
    Overflow { limit: usize },
    #[error("a frame took over {seconds} s to reach the peer")]
    Stalled { seconds: u64 },
}

#[async_trait]
pub trait DispatchGuard: Send + Sync {
    async fn check_stop(&self) -> Result<(), HuginnProtocolError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveDispatcherLimits {
    pub codec_limits: CodecLimits,
    pub max_subscriptions: usize,
    pub initial_download_credit: NonZeroU16,
}

impl Default for LiveDispatcherLimits {
    fn default() -> Self {
        Self {
            codec_limits: CodecLimits::default(),
            max_subscriptions: 64,
            initial_download_credit: NonZeroU16::new(16).expect("nonzero"),
        }
    }
}

impl LiveDispatcherLimits {
    pub fn new(
        codec_limits: CodecLimits,
        max_subscriptions: usize,
        initial_download_credit: NonZeroU16,
    ) -> Self {
        Self {
            codec_limits,
            max_subscriptions,
            initial_download_credit,
        }
    }
}

#[derive(Clone, Default)]
pub struct LiveGateways {
    pub files: Option<Arc<dyn FileGateway>>,
    pub renders: Option<Arc<dyn RenderGateway>>,
}

impl LiveGateways {
    pub fn none() -> Self {
        Self::default()
    }

    pub fn new<F, V>(files: Arc<F>, renders: Arc<V>) -> Self
    where
        F: FileGateway + 'static,
        V: RenderGateway + 'static,
    {
        Self {
            files: Some(files),
            renders: Some(renders),
        }
    }
}

#[derive(Default)]
pub(super) struct ConnectionStreams {
    pub(super) general: Option<HuginnMessageStream>,
    pub(super) live: Option<LiveEventStream>,
    /// Replay framing of the live subscription: the live protocol promises
    /// `ReplayBegin` / `ReplayComplete` per subscribed session, and clients
    /// (odin-acp) gate session setup on `ReplayComplete`.
    pub(super) live_replay: LiveReplayFraming,
    pub(super) artifact: Option<ArtifactReadStream>,
    pub(super) file: Option<FileReadStream>,
    pub(super) file_watch: Option<FileDeltaStream>,
    pub(super) render: Option<RenderStatusStream>,
    pub(super) objects: Option<ObjectWatch>,
    pub(super) resume: ResumePoints,
}

/// Where a request may resume object state from on this connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Standing {
    /// This connection was handed the point and its frame completed.
    Handed,
    /// This connection was handed the point, but its frame is still on
    /// the way out: retry once it is on the wire.
    InFlight,
    /// Not handed here: the client takes a fresh snapshot.
    Unknown,
}

/// The object-subscription baselines one connection may resume from: only
/// snapshots it served itself. A model's revisions restart at zero with
/// every daemon lifetime, so a numeric revision handed out elsewhere —
/// perhaps by an earlier daemon — can equal this model's head while naming
/// unrelated objects. Revision zero is the one universal point: every
/// model is empty there. (Raw `Deltas` cursors carry their model and need
/// none of this.)
///
/// A baseline is a snapshot whose every page this connection served: a
/// first page (no cursor) starts the chain, each page continues it only at
/// the exact cursor this connection handed out, and the final page — once
/// its frame, and so every earlier page's, completed — is the baseline. A
/// final page reached by a cursor from another connection completes
/// nothing. Bounded: one chain in progress and one baseline; the
/// subscription's own checkpoints live on its [`ObjectWatch`].
#[derive(Default)]
pub(super) struct ResumePoints {
    baseline: Option<(SnapshotBaseline, DeliveryReceipt)>,
    chain: Option<SnapshotChain>,
    /// Handed out by the answer being queued, until its frame has a mark.
    staged: Option<Staged>,
}

/// The query identity a baseline answered: a baseline of one scope or kind
/// set never resumes another. Kinds are a canonical set.
#[derive(Clone, PartialEq)]
struct SnapshotIdentity {
    kinds: Vec<ObjectKind>,
    scope: QueryScope,
    include_stale: bool,
}

impl SnapshotIdentity {
    fn new(kinds: &[ObjectKind], scope: &QueryScope, include_stale: bool) -> Self {
        Self {
            kinds: canonical_kinds(kinds),
            scope: scope.clone(),
            include_stale,
        }
    }

    fn of(query: &SnapshotQuery) -> Self {
        Self::new(&query.kinds, &query.scope, query.include_stale)
    }
}

/// A complete snapshot this connection served, page by page.
struct SnapshotBaseline {
    identity: SnapshotIdentity,
    revision: Revision,
}

/// A paged snapshot this connection is serving: the cursor its next page
/// must arrive at.
struct SnapshotChain {
    identity: SnapshotIdentity,
    next_cursor: String,
}

enum Staged {
    Chain(SnapshotChain),
    Baseline(SnapshotBaseline),
}

impl ResumePoints {
    /// Stages what one served snapshot page adds: the start or next link of
    /// this connection's chain, or — on its final page — the baseline.
    pub(super) fn stage_snapshot(&mut self, query: &SnapshotQuery, page: &SnapshotPage) {
        let identity = SnapshotIdentity::of(query);
        let continues = match &query.cursor {
            None => true,
            Some(cursor) => self
                .chain
                .as_ref()
                .is_some_and(|chain| &chain.next_cursor == cursor && chain.identity == identity),
        };
        if !continues {
            return;
        }
        self.staged = Some(match &page.next_cursor {
            Some(next_cursor) => Staged::Chain(SnapshotChain {
                identity,
                next_cursor: next_cursor.clone(),
            }),
            None => Staged::Baseline(SnapshotBaseline {
                identity,
                revision: page.revision,
            }),
        });
    }

    /// Settles the staged point against its answer's frame: kept — the
    /// baseline with the frame's receipt — or dropped when the answer
    /// itself was not queued.
    pub(super) fn settle(&mut self, delivery: Option<DeliveryReceipt>) {
        match (self.staged.take(), delivery) {
            (Some(Staged::Chain(chain)), Some(_)) => self.chain = Some(chain),
            (Some(Staged::Baseline(baseline)), Some(delivery)) => {
                self.chain = None;
                self.baseline = Some((baseline, delivery));
            }
            _ => {}
        }
    }

    fn standing(&self, revision: Revision, identity: &SnapshotIdentity) -> Standing {
        match &self.baseline {
            Some((baseline, delivery))
                if baseline.revision == revision && &baseline.identity == identity =>
            {
                if delivery.delivered() {
                    Standing::Handed
                } else {
                    Standing::InFlight
                }
            }
            _ => Standing::Unknown,
        }
    }

    /// Whether a conditional snapshot may answer "unchanged": only against
    /// a delivered baseline of the same query.
    pub(super) fn honours_if_revision(&self, query: &SnapshotQuery) -> bool {
        query.if_revision.is_some_and(|revision| {
            self.standing(revision, &SnapshotIdentity::of(query)) == Standing::Handed
        })
    }

    /// A subscription resumes from its own checkpoints — the acked one or
    /// the outstanding page's, whose delivery the ack gate still checks —
    /// or from a complete snapshot of its kind set and scope with stale
    /// objects included.
    pub(super) fn subscription(
        &self,
        subscription: &ObjectSubscription,
        watch: Option<&ObjectWatch>,
    ) -> Standing {
        let after = subscription.after;
        if after == Revision::new(0) {
            return Standing::Handed;
        }
        let identity = SnapshotIdentity::new(&subscription.kinds, &subscription.scope, true);
        let own = watch.is_some_and(|watch| {
            canonical_kinds(&watch.kinds) == identity.kinds
                && watch.scope == subscription.scope
                && (watch.acked == after
                    || watch
                        .unacked
                        .as_ref()
                        .is_some_and(|page| page.checkpoint == after))
        });
        if own {
            return Standing::Handed;
        }
        self.standing(after, &identity)
    }
}

/// How long coalescible object changes wait for an urgent neighbour before
/// they flush anyway.
const OBJECT_COALESCE: Duration = Duration::from_secs(30);
/// Most objects one pushed object page carries; the frame budget may cut
/// it shorter.
const OBJECT_PAGE_ITEMS: usize = 256;

/// One connection's object subscription: the server side of the
/// `SubscribeObjects` contract. `acked` is the checkpoint the client last
/// adopted; `scanned` the head watermark the wake watches past. While a
/// page is outstanding (`unacked`) no second page is pulled and the
/// coalesce deadline is cleared: the batch in flight is the only object
/// state this connection owes until its ack frees it.
pub(super) struct ObjectWatch {
    kinds: Vec<ObjectKind>,
    scope: QueryScope,
    acked: Revision,
    scanned: Revision,
    unacked: Option<UnackedPage>,
    deadline: Option<Instant>,
}

/// The checkpoint can be acknowledged only after its exact frame completes,
/// including writes drained while a request is awaiting dispatch.
struct UnackedPage {
    checkpoint: Revision,
    delivery: DeliveryReceipt,
}

impl ObjectWatch {
    pub(super) fn new(subscription: &ObjectSubscription) -> Self {
        Self {
            kinds: subscription.kinds.clone(),
            scope: subscription.scope.clone(),
            acked: subscription.after,
            scanned: subscription.after,
            unacked: None,
            deadline: None,
        }
    }

    /// The wake arm runs, and a page may be pulled, only for a live
    /// subscription with nothing unacked: one page per connection.
    fn armed(&self) -> bool {
        self.unacked.is_none()
    }

    /// The checkpoint still waiting for transport completion.
    pub(super) fn unacked_checkpoint(&self) -> Option<Revision> {
        self.unacked
            .as_ref()
            .filter(|page| !page.delivery.delivered())
            .map(|page| page.checkpoint)
    }

    /// Drops the outstanding page: an ack at its checkpoint or a
    /// re-baseline supersedes it.
    pub(super) fn clear_unacked(&mut self) {
        self.unacked = None;
    }
}

/// Per-connection replay boundary bookkeeping for the live event stream.
///
/// A confirmed Subscribe records each session's durable head, read AFTER the
/// event stream was opened, so every event up to that head is guaranteed to
/// be delivered by the stream (replay, then tail). `ReplayBegin` frames are
/// queued behind the Subscribe response; a session's `ReplayComplete` goes
/// out right after its delivered cursor reaches the recorded head, or
/// immediately when there is nothing to replay.
#[derive(Debug, Default)]
pub(super) struct LiveReplayFraming {
    /// Frames due right after the current response, in order.
    pub(super) queued: VecDeque<LiveServerMessage>,
    /// Sessions still replaying, keyed to the head that completes them.
    replaying: BTreeMap<LiveSessionId, EventSeq>,
}

impl LiveReplayFraming {
    /// Replaces the framing for a new subscription set (the controller
    /// replaces the connection's whole live stream on every Subscribe).
    pub(super) fn begin(
        &mut self,
        sessions: impl IntoIterator<Item = (LiveSessionId, EventSeq, EventSeq)>,
    ) {
        self.queued.clear();
        self.replaying.clear();
        for (session_id, requested_after, head) in sessions {
            self.queued.push_back(LiveServerMessage::ReplayBegin {
                session_id,
                requested_after,
                head,
            });
            if head <= requested_after {
                self.queued
                    .push_back(LiveServerMessage::ReplayComplete { session_id, head });
            } else {
                self.replaying.insert(session_id, head);
            }
        }
    }

    /// Clears every boundary: the live stream is gone.
    pub(super) fn clear(&mut self) {
        self.queued.clear();
        self.replaying.clear();
    }

    /// The `ReplayComplete` due after delivering `event`, if it reached its
    /// session's recorded head.
    pub(super) fn after_event(&mut self, event: &LiveEvent) -> Option<LiveServerMessage> {
        let head = *self.replaying.get(&event.session_id)?;
        if event.sequence < head {
            return None;
        }
        self.replaying.remove(&event.session_id);
        Some(LiveServerMessage::ReplayComplete {
            session_id: event.session_id,
            head,
        })
    }
}

pub struct LiveDispatcher<R, C, S> {
    pub(super) read_model: Arc<R>,
    pub(super) commands: Arc<C>,
    pub(super) streams: Arc<S>,
    pub(super) guard: Arc<dyn DispatchGuard>,
    pub(super) posture: NodePosture,
    pub(super) tickets: Arc<dyn ContentTicketIssuer>,
    pub(super) files: Option<Arc<dyn FileGateway>>,
    pub(super) renders: Option<Arc<dyn RenderGateway>>,
    pub(super) codec_limits: CodecLimits,
    pub(super) max_subscriptions: usize,
    pub(super) initial_download_credit: NonZeroU16,
}

impl<R, C, S> Clone for LiveDispatcher<R, C, S> {
    fn clone(&self) -> Self {
        Self {
            read_model: self.read_model.clone(),
            commands: self.commands.clone(),
            streams: self.streams.clone(),
            guard: self.guard.clone(),
            tickets: self.tickets.clone(),
            files: self.files.clone(),
            renders: self.renders.clone(),
            codec_limits: self.codec_limits,
            max_subscriptions: self.max_subscriptions,
            initial_download_credit: self.initial_download_credit,
            posture: self.posture,
        }
    }
}

impl<R, C, S> LiveDispatcher<R, C, S> {
    pub fn new(
        read_model: Arc<R>,
        commands: Arc<C>,
        streams: Arc<S>,
        guard: Arc<dyn DispatchGuard>,
        tickets: Arc<dyn ContentTicketIssuer>,
    ) -> Self {
        Self::with_limits(
            read_model,
            commands,
            streams,
            guard,
            tickets,
            LiveDispatcherLimits::default(),
        )
    }

    pub fn with_limits(
        read_model: Arc<R>,
        commands: Arc<C>,
        streams: Arc<S>,
        guard: Arc<dyn DispatchGuard>,
        tickets: Arc<dyn ContentTicketIssuer>,
        limits: LiveDispatcherLimits,
    ) -> Self {
        Self::with_runtime_limits(
            read_model,
            commands,
            streams,
            guard,
            tickets,
            LiveGateways::none(),
            limits,
        )
    }

    pub fn with_runtime_limits(
        read_model: Arc<R>,
        commands: Arc<C>,
        streams: Arc<S>,
        guard: Arc<dyn DispatchGuard>,
        tickets: Arc<dyn ContentTicketIssuer>,
        gateways: LiveGateways,
        limits: LiveDispatcherLimits,
    ) -> Self {
        Self::with_posture_limits(
            read_model,
            commands,
            streams,
            guard,
            tickets,
            gateways,
            limits,
            NodePosture::Authoritative,
        )
    }

    /// Full constructor. The caller states the node's authority posture,
    /// derived once at startup from the kernel-verified published snapshot
    /// relation; the dispatcher never re-derives or re-reads it.
    // Keep independent composition ports explicit; a builder default must not infer authority.
    #[allow(clippy::too_many_arguments)]
    pub fn with_posture_limits(
        read_model: Arc<R>,
        commands: Arc<C>,
        streams: Arc<S>,
        guard: Arc<dyn DispatchGuard>,
        tickets: Arc<dyn ContentTicketIssuer>,
        gateways: LiveGateways,
        limits: LiveDispatcherLimits,
        posture: NodePosture,
    ) -> Self {
        Self {
            read_model,
            commands,
            streams,
            guard,
            posture,
            tickets,
            files: gateways.files,
            renders: gateways.renders,
            codec_limits: limits.codec_limits,
            max_subscriptions: limits.max_subscriptions.max(1),
            initial_download_credit: limits.initial_download_credit,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Channel {
    General,
    Live,
}

impl<R, C, S> LiveDispatcher<R, C, S>
where
    R: HuginnReadModel + 'static,
    C: AuthenticatedCommandPort + OmpLivePlane + 'static,
    S: HuginnStreamSource + 'static,
{
    pub async fn serve_connection<P>(
        &self,
        connection: P,
        device: VerifiedColinDevice,
        registration: ConnectionRegistration,
    ) -> Result<(), DispatchError>
    where
        P: ServerConnection,
    {
        let (mut reader, writer) = connection.split();
        let mut control = Control::new(&registration);
        let mut outbound =
            Outbound::new(writer, device.device_id, self.codec_limits.max_frame_bytes);
        let mut channel = None;
        let served = self
            .serve_frames(
                &mut reader,
                &mut outbound,
                &mut control,
                device.device_id,
                &mut channel,
            )
            .await;
        let told = tokio::time::Instant::now();
        let result = match served {
            Ok(Finish::PeerClosed) => Ok(()),
            Ok(Finish::Violation) => {
                outbound.close(told, true, None).await;
                Ok(())
            }
            Ok(Finish::Ended(ending)) => {
                let notice = match ending {
                    Ending::Revoked => Some(self.revoked_frame(channel)?),
                    Ending::Released | Ending::Stopping => None,
                };
                let discarded = outbound.close(told, false, notice).await;
                if ending != Ending::Stopping {
                    tracing::info!(
                        device = %device.device_id,
                        reason = ending.as_str(),
                        discarded_frames = discarded,
                        "huginn connection_ended"
                    );
                }
                Ok(())
            }
            Err(error @ DispatchError::Overflow { .. }) => {
                let discarded = outbound.close(told, false, None).await;
                tracing::warn!(
                    device = %device.device_id,
                    discarded_frames = discarded,
                    "huginn connection_ended reason=overflow"
                );
                Err(error)
            }
            Err(error) => Err(error),
        };
        drop(reader);
        drop(registration);
        result
    }

    async fn serve_frames<P, W>(
        &self,
        reader: &mut P,
        outbound: &mut Outbound<W>,
        control: &mut Control,
        device: DeviceId,
        channel: &mut Option<Channel>,
    ) -> Result<Finish, DispatchError>
    where
        P: FrameReader,
        W: FrameWriter,
    {
        let mut streams = ConnectionStreams::default();
        loop {
            tokio::select! {
                biased;
                ending = control.ended() => return Ok(Finish::Ended(ending)),
                sent = outbound.progress(), if outbound.busy() => {
                    sent?;
                }
                incoming = reader.receive() => {
                    let incoming = incoming.map_err(DispatchError::Transport)?;
                    let Some(incoming) = incoming else { return Ok(Finish::PeerClosed) };
                    match incoming {
                        ConnectionFrame::Close => return Ok(Finish::PeerClosed),
                        ConnectionFrame::Ping(bytes) => {
                            outbound.push(ConnectionFrame::Pong(bytes))?;
                        }
                        ConnectionFrame::Pong(_) => {}
                        ConnectionFrame::Text => {
                            self.queue_invalid_transport(outbound, *channel, "binaryFrameRequired")?;
                            return Ok(Finish::Violation);
                        }
                        ConnectionFrame::Binary(bytes) => {
                            let decoded = match decode_frame::<ClientFrame>(&bytes, &self.codec_limits) {
                                Ok(decoded) => decoded.value,
                                Err(error) => {
                                    let protocol = error.into_protocol_error();
                                    self.queue_general(outbound, HuginnMessage::ProtocolError(protocol))?;
                                    return Ok(Finish::Violation);
                                }
                            };
                            let received_channel = match &decoded {
                                ClientFrame::General(_) => Channel::General,
                                ClientFrame::Live(_) => Channel::Live,
                            };
                            if channel.is_some_and(|current| current != received_channel) {
                                self.queue_invalid_transport(outbound, *channel, "mixedProtocolChannels")?;
                                return Ok(Finish::Violation);
                            }
                            *channel = Some(received_channel);
                            match decoded {
                                ClientFrame::General(request) => {
                                    let object_subscription =
                                        matches!(request, HuginnRequest::SubscribeObjects(_));
                                    let dispatched =
                                        self.dispatch_general(request, device, &mut streams);
                                    match until_ended(dispatched, control, outbound).await? {
                                        Ok(Some(message)) => {
                                            let mark = self.queue_response(
                                                outbound,
                                                ServerFrame::General(message),
                                            )?;
                                            // A resume point this answer
                                            // hands out counts once its own
                                            // frame completes.
                                            streams
                                                .resume
                                                .settle(mark.map(|mark| outbound.receipt(mark)));
                                            // Subscribed precedes any pushed page.
                                            if object_subscription {
                                                self.pump_objects(&mut streams, outbound)
                                                    .await?;
                                            }
                                        }
                                        Ok(None) => streams.resume.settle(None),
                                        Err(ending) => return Ok(Finish::Ended(ending)),
                                    }
                                }
                                ClientFrame::Live(request) => {
                                    let dispatched = self.dispatch_live(request, device, &mut streams);
                                    match until_ended(dispatched, control, outbound).await? {
                                        Ok(Some(message)) => {
                                            self.queue_response(outbound, ServerFrame::Live(message))?;
                                        }
                                        Ok(None) => {}
                                        Err(ending) => return Ok(Finish::Ended(ending)),
                                    }
                                    // Replay boundaries follow the Subscribe
                                    // response, before any streamed event.
                                    while let Some(marker) = streams.live_replay.queued.pop_front() {
                                        self.queue_live(outbound, marker)?;
                                    }
                                }
                            }
                        }
                    }
                }
                _ = self.object_due(&mut streams.objects),
                    if streams.objects.as_ref().is_some_and(ObjectWatch::armed)
                        && outbound.has_room() =>
                {
                    self.pump_objects(&mut streams, outbound).await?;
                }
                message = next_general(&mut streams.general), if outbound.has_room() => {
                    match message {
                        Some(Ok(message)) => self.queue_general(outbound, message)?,
                        Some(Err(error)) => {
                            self.queue_general(outbound, HuginnMessage::ProtocolError(error))?;
                            streams.general = None;
                        }
                        None => streams.general = None,
                    }
                }
                event = next_live(&mut streams.live), if outbound.has_room() => {
                    match event {
                        Some(Ok(event)) => {
                            let complete = streams.live_replay.after_event(&event);
                            self.queue_live(outbound, LiveServerMessage::Event(event))?;
                            if let Some(complete) = complete {
                                self.queue_live(outbound, complete)?;
                            }
                        }
                        Some(Err(error)) => {
                            self.queue_live(outbound, LiveServerMessage::ProtocolError(error))?;
                            streams.live = None;
                            streams.live_replay.clear();
                        }
                        None => {
                            streams.live = None;
                            streams.live_replay.clear();
                        }
                    }
                }
                chunk = next_artifact(&mut streams.artifact), if outbound.has_room() => {
                    match chunk {
                        Some(Ok(chunk)) => self.queue_live(outbound, LiveServerMessage::ArtifactChunk(chunk))?,
                        Some(Err(error)) => {
                            self.queue_live(outbound, LiveServerMessage::ProtocolError(error))?;
                            streams.artifact = None;
                        }
                        None => streams.artifact = None,
                    }
                }
                chunk = next_file(&mut streams.file), if outbound.has_room() => {
                    match chunk {
                        Some(Ok(chunk)) => match *channel {
                            Some(Channel::Live) => self.queue_live(outbound, LiveServerMessage::BinaryChunk(chunk))?,
                            _ => self.queue_general(outbound, HuginnMessage::BinaryChunk(chunk))?,
                        },
                        Some(Err(error)) => {
                            self.queue_channel_error(outbound, *channel, error)?;
                            streams.file = None;
                        }
                        None => streams.file = None,
                    }
                }
                delta = next_file_delta(&mut streams.file_watch), if outbound.has_room() => {
                    match delta {
                        Some(Ok(delta)) => match *channel {
                            Some(Channel::Live) => self.queue_live(outbound, LiveServerMessage::FileDelta(delta))?,
                            _ => self.queue_general(outbound, HuginnMessage::FileDelta(delta))?,
                        },
                        Some(Err(error)) => {
                            self.queue_channel_error(outbound, *channel, error)?;
                            streams.file_watch = None;
                        }
                        None => streams.file_watch = None,
                    }
                }
                status = next_render(&mut streams.render), if outbound.has_room() => {
                    match status {
                        Some(Ok(status)) => match *channel {
                            Some(Channel::Live) => self.queue_live(outbound, LiveServerMessage::RenderStatus(status))?,
                            _ => self.queue_general(outbound, HuginnMessage::RenderStatus(status))?,
                        },
                        Some(Err(error)) => {
                            self.queue_channel_error(outbound, *channel, error)?;
                            streams.render = None;
                        }
                        None => streams.render = None,
                    }
                }
            }
        }
    }

    /// Queues one request's answer. An answer over the frame bound is never
    /// sent (an oversized frame would drop the connection without a close
    /// handshake): the client gets a typed `ResourceLimit` on the same
    /// channel instead and the connection stays up. Answers the outbox mark
    /// of the answer itself, `None` when it was refused.
    fn queue_response<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        frame: ServerFrame,
    ) -> Result<Option<u64>, DispatchError> {
        match encode_frame(&frame, &self.codec_limits) {
            Ok(encoded) => outbound
                .push(ConnectionFrame::Binary(encoded.into()))
                .map(Some),
            Err(crate::protocol::CodecError::LimitExceeded { limit }) => {
                let channel = match &frame {
                    ServerFrame::General(_) => "general",
                    ServerFrame::Live(_) => "live",
                };
                tracing::error!(
                    channel,
                    limit,
                    max_frame_bytes = self.codec_limits.max_frame_bytes,
                    "huginn response refused over frame bound"
                );
                let limit = "max_frame_bytes".to_owned();
                let refusal = match frame {
                    ServerFrame::General(_) => ServerFrame::General(HuginnMessage::ProtocolError(
                        HuginnProtocolError::ResourceLimit { limit },
                    )),
                    ServerFrame::Live(_) => ServerFrame::Live(LiveServerMessage::ProtocolError(
                        LiveProtocolError::ResourceLimit { limit },
                    )),
                };
                self.queue_frame(outbound, refusal).map(|_| None)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn queue_general<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        message: HuginnMessage,
    ) -> Result<(), DispatchError> {
        self.queue_frame(outbound, ServerFrame::General(message))
            .map(|_| ())
    }

    fn queue_live<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        message: LiveServerMessage,
    ) -> Result<(), DispatchError> {
        self.queue_frame(outbound, ServerFrame::Live(message))
            .map(|_| ())
    }

    fn queue_channel_error<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        channel: Option<Channel>,
        error: HuginnProtocolError,
    ) -> Result<(), DispatchError> {
        match channel {
            Some(Channel::Live) => self.queue_live(
                outbound,
                LiveServerMessage::ProtocolError(protocol_to_live(error)),
            ),
            _ => self.queue_general(outbound, HuginnMessage::ProtocolError(error)),
        }
    }

    /// Queues one encoded server frame and returns its outbox mark.
    fn queue_frame<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        frame: ServerFrame,
    ) -> Result<u64, DispatchError> {
        let encoded = encode_frame(&frame, &self.codec_limits)?;
        outbound.push(ConnectionFrame::Binary(encoded.into()))
    }

    fn queue_invalid_transport<W: FrameWriter>(
        &self,
        outbound: &mut Outbound<W>,
        channel: Option<Channel>,
        code: &'static str,
    ) -> Result<(), DispatchError> {
        match channel {
            Some(Channel::Live) => self.queue_live(
                outbound,
                LiveServerMessage::ProtocolError(LiveProtocolError::InvalidRequest {
                    code: code.to_owned(),
                    message: "connection protocol violation".to_owned(),
                }),
            ),
            _ => self.queue_general(
                outbound,
                HuginnMessage::ProtocolError(HuginnProtocolError::InvalidRequest {
                    code: code.to_owned(),
                    message: "connection protocol violation".to_owned(),
                }),
            ),
        }
    }

    fn revoked_frame(&self, channel: Option<Channel>) -> Result<ConnectionFrame, DispatchError> {
        let frame = match channel {
            Some(Channel::Live) => ServerFrame::Live(LiveServerMessage::DeviceRevoked),
            _ => ServerFrame::General(HuginnMessage::ProtocolError(
                HuginnProtocolError::Unauthorized,
            )),
        };
        Ok(ConnectionFrame::Binary(
            encode_frame(&frame, &self.codec_limits)?.into(),
        ))
    }
    /// Resolves when a pushed object page is due: the model head moved
    /// past the scanned watermark, or the coalesce deadline for deferred
    /// content arrived. Cancel-safe — every poll re-derives from the
    /// connection's own state, and the wake resolves only past the
    /// watermark, so an unhandled wake never becomes a spin.
    async fn object_due(&self, objects: &mut Option<ObjectWatch>) {
        let (scanned, deadline) = match objects.as_ref().filter(|state| state.armed()) {
            Some(state) => (state.scanned, state.deadline),
            None => {
                std::future::pending::<()>().await;
                unreachable!("pending never resolves")
            }
        };
        tokio::select! {
            // A failed wake means the read model is gone; the page read
            // reports that failure, the wake itself stays harmless.
            _ = self.read_model.object_head_after(scanned) => {}
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {}
        }
    }

    /// Whether a page must leave now instead of waiting out the coalesce
    /// window: it carries urgent content itself, or it stops short of a
    /// retained range that holds urgent content beyond it.
    async fn flush_now(
        &self,
        page: &odin_domain::huginn::ObjectDeltaBatch,
        state: &ObjectWatch,
    ) -> Result<bool, HuginnProtocolError> {
        if page
            .deltas
            .iter()
            .any(|delta| urgent_object(delta.object.kind, &delta.object.id))
        {
            return Ok(true);
        }
        if page.next_after.is_none() {
            // The page covers everything retained; nothing is hiding
            // past its end, and no extra model probe is owed.
            return Ok(false);
        }
        self.read_model
            .has_urgent_objects_since(page.to_revision, &state.kinds, &state.scope)
            .await
    }

    /// The byte budget one object page is built within: the connection's
    /// frame bound less the response-envelope headroom. Validation reads
    /// under it too, so a subscribe never clones more than it could send.
    pub(super) fn object_page_budget(&self) -> usize {
        self.codec_limits
            .max_frame_bytes
            .saturating_sub(super::routes::DELTA_FRAME_HEADROOM)
    }

    /// Attempts one pushed object page for the connection's subscription:
    /// nothing while a page is unacked, nothing when nothing selected is
    /// new, a deferral (deadline) for coalescible-only content, and one
    /// atomic cursor-bearing batch otherwise. Every read starts at the
    /// acked checkpoint, so an urgent flush covers earlier metric changes
    /// instead of skipping them.
    async fn pump_objects<W: FrameWriter>(
        &self,
        streams: &mut ConnectionStreams,
        outbound: &mut Outbound<W>,
    ) -> Result<(), DispatchError> {
        let Some(state) = streams.objects.as_mut().filter(|state| state.armed()) else {
            return Ok(());
        };
        let budget = self.object_page_budget();
        let page = match self
            .read_model
            .object_deltas_page(
                state.acked,
                &state.kinds,
                &state.scope,
                OBJECT_PAGE_ITEMS,
                budget,
            )
            .await
        {
            Ok(page) => page,
            Err(error) => {
                // A checkpoint the model no longer serves ends the
                // subscription typed: the client snapshots and resubscribes.
                self.queue_general(outbound, HuginnMessage::ProtocolError(error))?;
                streams.objects = None;
                return Ok(());
            }
        };
        state.scanned = state.scanned.max(page.to_revision);
        if page.deltas.is_empty() {
            state.deadline = None;
            return Ok(());
        }
        let flush = match self.flush_now(&page, state).await {
            Ok(flush) => flush,
            Err(error) => {
                self.queue_general(outbound, HuginnMessage::ProtocolError(error))?;
                streams.objects = None;
                return Ok(());
            }
        };
        // Coalescible content defers while no window is open yet or while
        // the opened window still lies ahead; the elapsed deadline is
        // itself the flush, and urgent content never waits.
        if !flush && state.deadline.is_none_or(|at| at > Instant::now()) {
            if page.next_after.is_some() {
                // The deferred range continues past this page: the wake
                // watermark moves to the head so the deadline alone
                // flushes it; the flush reads from the acked checkpoint
                // regardless.
                match self.read_model.object_head_after(page.to_revision).await {
                    Ok(head) => state.scanned = state.scanned.max(head),
                    Err(error) => {
                        self.queue_general(outbound, HuginnMessage::ProtocolError(error))?;
                        streams.objects = None;
                        return Ok(());
                    }
                }
            }
            if state.deadline.is_none() {
                state.deadline = Some(Instant::now() + OBJECT_COALESCE);
            }
            return Ok(());
        }
        state.deadline = None;
        let checkpoint = page.to_revision;
        let mark = self.queue_frame(
            outbound,
            ServerFrame::General(HuginnMessage::ObjectDeltaBatch(page)),
        )?;
        state.unacked = Some(UnackedPage {
            checkpoint,
            delivery: outbound.receipt(mark),
        });
        Ok(())
    }
}

/// How a connection's serve loop ended without a transport failure.
enum Finish {
    /// The peer closed or went away: nothing more is owed to it.
    PeerClosed,
    /// The peer broke the protocol: its error is queued, then a close.
    Violation,
    Ended(Ending),
}

pub(super) fn protocol_to_live(error: HuginnProtocolError) -> LiveProtocolError {
    match error {
        HuginnProtocolError::UnsupportedVersion {
            received,
            supported,
        } => LiveProtocolError::UnsupportedVersion {
            received,
            supported,
        },
        HuginnProtocolError::InvalidRequest { code, message } => {
            LiveProtocolError::InvalidRequest { code, message }
        }
        HuginnProtocolError::Unauthenticated => LiveProtocolError::Unauthenticated,
        HuginnProtocolError::Unauthorized => LiveProtocolError::Unauthorized,
        HuginnProtocolError::NotFound {
            object_kind,
            object_id,
        } => LiveProtocolError::NotFound {
            object_kind,
            object_id,
        },
        HuginnProtocolError::RevisionMismatch { expected, actual } => {
            LiveProtocolError::RevisionMismatch { expected, actual }
        }
        HuginnProtocolError::Conflict { code, message } => {
            LiveProtocolError::Conflict { code, message }
        }
        HuginnProtocolError::CursorExpired => LiveProtocolError::CursorExpired,
        HuginnProtocolError::ResourceLimit { limit } => LiveProtocolError::ResourceLimit { limit },
        HuginnProtocolError::Unsupported { operation } => {
            LiveProtocolError::Unsupported { operation }
        }
        HuginnProtocolError::Unavailable { code } => LiveProtocolError::Unavailable { code },
    }
}

async fn next_general(
    stream: &mut Option<HuginnMessageStream>,
) -> Option<Result<HuginnMessage, HuginnProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_live(
    stream: &mut Option<LiveEventStream>,
) -> Option<Result<odin_domain::huginn::LiveEvent, LiveProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_artifact(
    stream: &mut Option<ArtifactReadStream>,
) -> Option<Result<odin_domain::huginn::ArtifactChunk, LiveProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_file(
    stream: &mut Option<FileReadStream>,
) -> Option<Result<odin_domain::huginn::BinaryChunk, HuginnProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_file_delta(
    stream: &mut Option<FileDeltaStream>,
) -> Option<Result<odin_domain::huginn::FileDelta, HuginnProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}

async fn next_render(
    stream: &mut Option<RenderStatusStream>,
) -> Option<Result<odin_domain::huginn::RenderStatus, HuginnProtocolError>> {
    match stream {
        Some(stream) => stream.next().await,
        None => std::future::pending().await,
    }
}
