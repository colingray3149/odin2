//! Slow-reader tests exercise command handling, revocation, shutdown, and queue limits.

use std::num::{NonZeroU16, NonZeroUsize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use odin_domain::huginn::{
    ConnectionId, DeviceId, HuginnMessage, HuginnProtocolError, HuginnRequest, HuginnResponse,
    LiveClientRequest, LiveServerMessage, ObjectKind, ObjectSubscription, QueryScope, Revision,
    TailnetNodeId, TransferCreditRequest, TransferId, VerifiedColinDevice,
};
use odin_domain::CommandId;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::super::live::{DispatchError, DispatchGuard, LiveDispatcher, LiveDispatcherLimits};
use super::super::outbound::Outbound;
use super::super::registry::{
    ConnectionFrame, ConnectionRegistry, FrameReader, FrameWriter, ServerConnection,
};
use super::{
    request_id, session, subscription, test_time, upsert_object, PlaneFixture, Unsupported,
    SESSION_A,
};
use crate::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};
use crate::read_model::MaterializedReadModel;
use serde_json::json;

/// A peer whose reads the test meters: every written frame takes a permit.
struct Metered {
    incoming: mpsc::UnboundedReceiver<ConnectionFrame>,
    writer: MeteredWriter,
    read: Arc<AtomicUsize>,
}

struct MeteredReader {
    incoming: mpsc::UnboundedReceiver<ConnectionFrame>,
    /// Frames the serve loop has pulled: the request-observed handshake.
    read: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct MeteredWriter {
    permits: Arc<Semaphore>,
    written: Arc<Mutex<Vec<ConnectionFrame>>>,
    /// Writes begun but maybe not finished: the observable barrier for a
    /// frame parked on its meter.
    started: Arc<AtomicUsize>,
}

impl ServerConnection for Metered {
    type Reader = MeteredReader;
    type Writer = MeteredWriter;

    fn split(self) -> (MeteredReader, MeteredWriter) {
        (
            MeteredReader {
                incoming: self.incoming,
                read: self.read,
            },
            self.writer,
        )
    }
}

#[async_trait]
impl FrameReader for MeteredReader {
    async fn receive(&mut self) -> Result<Option<ConnectionFrame>, String> {
        let frame = self.incoming.recv().await;
        if frame.is_some() {
            self.read.fetch_add(1, Ordering::SeqCst);
        }
        Ok(frame)
    }
}

#[async_trait]
impl FrameWriter for MeteredWriter {
    async fn send(&mut self, frame: ConnectionFrame) -> Result<(), String> {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.permits
            .acquire()
            .await
            .map_err(|error| error.to_string())?
            .forget();
        self.written.lock().push(frame);
        Ok(())
    }
}

struct Peer {
    to_server: mpsc::UnboundedSender<ConnectionFrame>,
    writer: MeteredWriter,
    read: Arc<AtomicUsize>,
    registry: ConnectionRegistry,
    device: DeviceId,
    served: JoinHandle<Result<(), DispatchError>>,
    limits: CodecLimits,
}

impl Peer {
    /// Frames queued before the serve loop starts arrive as one burst.
    fn serve(
        plane: Arc<PlaneFixture>,
        limits: CodecLimits,
        reads: usize,
        burst: Vec<ConnectionFrame>,
    ) -> Self {
        Self::serve_model(
            plane,
            Arc::new(MaterializedReadModel::new(64, test_time())),
            limits,
            reads,
            burst,
        )
    }

    fn serve_model(
        plane: Arc<PlaneFixture>,
        model: Arc<MaterializedReadModel>,
        limits: CodecLimits,
        reads: usize,
        burst: Vec<ConnectionFrame>,
    ) -> Self {
        Self::serve_guard(plane, model, limits, reads, burst, Arc::new(Unsupported))
    }

    fn serve_guard(
        plane: Arc<PlaneFixture>,
        model: Arc<MaterializedReadModel>,
        limits: CodecLimits,
        reads: usize,
        burst: Vec<ConnectionFrame>,
        guard: Arc<dyn DispatchGuard>,
    ) -> Self {
        let dispatcher = LiveDispatcher::with_limits(
            model,
            plane,
            Arc::new(Unsupported),
            guard,
            Arc::new(Unsupported),
            LiveDispatcherLimits::new(limits, 64, NonZeroU16::new(16).unwrap()),
        );
        let device = VerifiedColinDevice {
            device_id: DeviceId::new(Uuid::new_v4()).unwrap(),
            tailnet_node_id: TailnetNodeId::parse("node.phone").unwrap(),
            connection_id: ConnectionId::new(Uuid::new_v4()).unwrap(),
        };
        let registry = ConnectionRegistry::new();
        let registration = registry.register(&device).unwrap();
        let (to_server, incoming) = mpsc::unbounded_channel();
        for frame in burst {
            to_server.send(frame).unwrap();
        }
        let read = Arc::new(AtomicUsize::new(0));
        let writer = MeteredWriter {
            permits: Arc::new(Semaphore::new(reads)),
            written: Arc::default(),
            started: Arc::new(AtomicUsize::new(0)),
        };
        let connection = Metered {
            incoming,
            writer: writer.clone(),
            read: Arc::clone(&read),
        };
        let device_id = device.device_id;
        let served = tokio::spawn(async move {
            dispatcher
                .serve_connection(connection, device, registration)
                .await
        });
        Self {
            to_server,
            writer,
            read,
            registry,
            device: device_id,
            served,
            limits,
        }
    }

    fn live(limits: &CodecLimits, request: LiveClientRequest) -> ConnectionFrame {
        ConnectionFrame::Binary(
            encode_frame(&ClientFrame::Live(request), limits)
                .unwrap()
                .into(),
        )
    }

    fn send(&self, request: LiveClientRequest) {
        self.to_server
            .send(Self::live(&self.limits, request))
            .unwrap();
    }

    fn send_general(&self, request: HuginnRequest) {
        let frame = ConnectionFrame::Binary(
            encode_frame(&ClientFrame::General(request), &self.limits)
                .unwrap()
                .into(),
        );
        self.to_server.send(frame).unwrap();
    }

    fn written(&self) -> Vec<ConnectionFrame> {
        self.writer.written.lock().clone()
    }

    /// Writes started but not completed: a frame parked on its meter.
    fn pending_writes(&self) -> usize {
        self.writer
            .started
            .load(Ordering::SeqCst)
            .saturating_sub(self.writer.written.lock().len())
    }

    /// Frames the serve loop has pulled from the peer. Once a request is
    /// observed, its answer is already queued: dispatch and the queueing
    /// of the response happen in one serve-loop poll.
    fn frames_read(&self) -> usize {
        self.read.load(Ordering::SeqCst)
    }

    fn decoded(&self, frame: &ConnectionFrame) -> Option<LiveServerMessage> {
        let ConnectionFrame::Binary(bytes) = frame else {
            return None;
        };
        match decode_frame::<ServerFrame>(bytes, &self.limits)
            .unwrap()
            .value
        {
            ServerFrame::Live(message) => Some(message),
            ServerFrame::General(_) => None,
        }
    }

    fn decoded_general(&self, frame: &ConnectionFrame) -> Option<HuginnMessage> {
        let ConnectionFrame::Binary(bytes) = frame else {
            return None;
        };
        match decode_frame::<ServerFrame>(bytes, &self.limits)
            .unwrap()
            .value
        {
            ServerFrame::General(message) => Some(message),
            ServerFrame::Live(_) => None,
        }
    }

    async fn ended_within(self, bound: Duration) -> Result<(), DispatchError> {
        tokio::time::timeout(bound, self.served)
            .await
            .expect("the connection ended within its bound")
            .unwrap()
    }
}

fn roster() -> LiveClientRequest {
    LiveClientRequest::GetRoster {
        request_id: request_id(),
        if_revision: None,
    }
}

fn listing() -> LiveClientRequest {
    LiveClientRequest::ListSessions {
        request_id: request_id(),
        seat_id: None,
        include_ended: false,
        cursor: None,
        limit: NonZeroU16::MIN,
    }
}

/// The REAL-TIME bound one polled wait may take. A paused runtime's
/// auto-advance can freeze virtual time while the peer stays wedged, so
/// the bound must not be virtual: a missed condition fails the test in
/// seconds instead of hanging the run.
const REAL_WAIT_BOUND: Duration = Duration::from_secs(5);

async fn until(mut done: impl FnMut() -> bool) {
    let bound = std::time::Instant::now() + REAL_WAIT_BOUND;
    while !done() {
        assert!(
            std::time::Instant::now() < bound,
            "the waited-for condition never held within {REAL_WAIT_BOUND:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One write permit every 500 ms: a peer reading, but slowly.
async fn trickle_task(permits: Arc<Semaphore>) {
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        permits.add_permits(1);
    }
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_stops_reading_keeps_its_commands_and_revocation() {
    let a = session(SESSION_A);
    let plane = Arc::new(PlaneFixture::with_history(&[(a, 2_000)]));
    let peer = Peer::serve(Arc::clone(&plane), CodecLimits::default(), 0, Vec::new());
    peer.send(LiveClientRequest::Subscribe {
        request_id: request_id(),
        subscriptions: vec![subscription(a, 0)],
    });
    peer.send(roster());
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.rosters.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the roster command was received while nothing was read");

    assert_eq!(peer.registry.close_device(peer.device).unwrap(), 1);
    let registry = peer.registry.clone();
    peer.ended_within(Duration::from_millis(2_100))
        .await
        .unwrap();
    assert_eq!(registry.served_connections(), 0);
}

/// A peer reading a frame every 500 ms is told it was revoked within the
/// close bound: the backlog queued ahead of the notice is discarded, so at
/// most the frame already in flight precedes it.
#[tokio::test(start_paused = true)]
async fn a_revoked_trickle_reader_hears_it_before_any_backlog() {
    let a = session(SESSION_A);
    let plane = Arc::new(PlaneFixture::with_history(&[(a, 2_000)]));
    let peer = Peer::serve(plane, CodecLimits::default(), 0, Vec::new());
    let permits = Arc::clone(&peer.writer.permits);
    tokio::spawn(trickle_task(permits));
    peer.send(LiveClientRequest::Subscribe {
        request_id: request_id(),
        subscriptions: vec![subscription(a, 0)],
    });
    until(|| peer.written().len() >= 3).await;

    let before = peer.written().len();
    peer.registry.close_device(peer.device).unwrap();
    let revoked_at = tokio::time::Instant::now();
    until(|| peer.written().last() == Some(&ConnectionFrame::Close)).await;
    assert!(revoked_at.elapsed() <= Duration::from_secs(2));
    let tail = peer.written()[before..].to_vec();
    assert!(
        tail.len() <= 3,
        "only the in-flight frame precedes the notice: {tail:?}"
    );
    assert!(matches!(
        peer.decoded(&tail[tail.len() - 2]),
        Some(LiveServerMessage::DeviceRevoked)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_stop_ends_an_outstanding_command_without_a_revocation() {
    let plane = Arc::new(PlaneFixture::default());
    let peer = Peer::serve(
        Arc::clone(&plane),
        CodecLimits::default(),
        1_000,
        Vec::new(),
    );
    peer.send(listing());
    until(|| plane.listings.load(Ordering::SeqCst) == 1).await;

    peer.registry.stop_all();
    let registry = peer.registry.clone();
    let written = Arc::clone(&peer.writer.written);
    peer.ended_within(Duration::from_millis(2_100))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(1), registry.drained())
        .await
        .expect("drained");
    assert_eq!(*written.lock(), vec![ConnectionFrame::Close]);
    let device = VerifiedColinDevice {
        device_id: DeviceId::new(Uuid::new_v4()).unwrap(),
        tailnet_node_id: TailnetNodeId::parse("node.phone").unwrap(),
        connection_id: ConnectionId::new(Uuid::new_v4()).unwrap(),
    };
    assert!(matches!(
        registry.register(&device),
        Err(super::super::registry::RegistryError::Stopping)
    ));
}

/// A valid request burst and maximum-size subscription must not be treated as overload.
#[tokio::test(start_paused = true)]
async fn a_ping_burst_and_a_full_subscription_are_answered() {
    let sessions: Vec<_> = (0..64u32)
        .map(|index| session(&format!("{index:08x}-2222-4333-8444-555555555555")))
        .collect();
    let history: Vec<_> = sessions.iter().map(|session| (*session, 1)).collect();
    let plane = Arc::new(PlaneFixture::with_history(&history));
    let limits = CodecLimits::default();
    let mut burst: Vec<_> = (0..32u8)
        .map(|ping| ConnectionFrame::Ping(vec![ping].into()))
        .collect();
    burst.push(Peer::live(
        &limits,
        LiveClientRequest::Subscribe {
            request_id: request_id(),
            subscriptions: sessions
                .iter()
                .map(|session| subscription(*session, 1))
                .collect(),
        },
    ));
    let peer = Peer::serve(plane, limits, usize::MAX >> 4, burst);
    until(|| peer.written().len() >= 32 + 1 + 128).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let written = peer.written();
    assert_eq!(written.len(), 32 + 1 + 128);
    for (ping, frame) in written[..32].iter().enumerate() {
        assert_eq!(*frame, ConnectionFrame::Pong(vec![ping as u8].into()));
    }
    let completes = written[33..]
        .iter()
        .filter(|frame| {
            matches!(
                peer.decoded(frame),
                Some(LiveServerMessage::ReplayComplete { .. })
            )
        })
        .count();
    assert_eq!(completes, 64);
    assert!(!peer.served.is_finished());
}

/// A peer that sends but never reads fills a bounded queue and is closed;
/// the serve loop never grows it without limit.
#[tokio::test(start_paused = true)]
async fn a_peer_that_never_reads_is_closed_at_the_queue_bound() {
    let limits = CodecLimits::from_max_frame_bytes(NonZeroUsize::new(4_096).unwrap());
    let burst = (0..400)
        .map(|_| ConnectionFrame::Ping(vec![0; 1_000].into()))
        .collect();
    let peer = Peer::serve(Arc::new(PlaneFixture::default()), limits, 0, burst);
    let ended = peer.ended_within(Duration::from_millis(2_100)).await;
    assert!(
        matches!(ended, Err(DispatchError::Overflow { .. })),
        "{ended:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_stop_ends_a_blocked_write_and_its_outstanding_command() {
    let plane = Arc::new(PlaneFixture::default());
    let peer = Peer::serve(Arc::clone(&plane), CodecLimits::default(), 0, Vec::new());
    peer.to_server
        .send(ConnectionFrame::Ping(vec![7].into()))
        .unwrap();
    peer.send(listing());
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.listings.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the listing was received while the write was blocked");

    peer.registry.stop_all();
    let registry = peer.registry.clone();
    let written = Arc::clone(&peer.writer.written);
    let ended = peer.ended_within(Duration::from_millis(2_100)).await;
    assert!(
        ended.is_ok(),
        "the stop ended the connection, not the send bound: {ended:?}"
    );
    tokio::time::timeout(Duration::from_millis(1), registry.drained())
        .await
        .expect("drained");
    assert!(written.lock().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_revocation_gives_up_a_command_the_plane_never_answers() {
    let plane = Arc::new(PlaneFixture::default());
    let peer = Peer::serve(
        Arc::clone(&plane),
        CodecLimits::default(),
        1_000,
        Vec::new(),
    );
    peer.send(listing());
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.listings.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the listing was received");

    peer.registry.close_device(peer.device).unwrap();
    let revoked_at = tokio::time::Instant::now();
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| peer.written().last() == Some(&ConnectionFrame::Close)),
    )
    .await
    .expect("the revocation closed the connection");
    assert!(revoked_at.elapsed() <= Duration::from_secs(2));
    let written = peer.written();
    assert_eq!(written.len(), 2, "{written:?}");
    assert!(matches!(
        peer.decoded(&written[0]),
        Some(LiveServerMessage::DeviceRevoked)
    ));
}

#[tokio::test(start_paused = true)]
async fn a_flood_of_tiny_frames_is_still_bounded() {
    let limits = CodecLimits::from_max_frame_bytes(NonZeroUsize::new(4_096).unwrap());
    let burst = (0..5_000)
        .map(|_| ConnectionFrame::Ping(vec![0].into()))
        .collect();
    let peer = Peer::serve(Arc::new(PlaneFixture::default()), limits, 0, burst);
    let ended = peer.ended_within(Duration::from_millis(2_100)).await;
    assert!(
        matches!(ended, Err(DispatchError::Overflow { .. })),
        "{ended:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_backlogged_stream_never_stops_a_new_command() {
    let a = session(SESSION_A);
    let plane = Arc::new(PlaneFixture::with_history(&[(a, 6_000)]));
    let limits = CodecLimits::from_max_frame_bytes(NonZeroUsize::new(4_096).unwrap());
    let burst = vec![
        Peer::live(
            &limits,
            LiveClientRequest::Subscribe {
                request_id: request_id(),
                subscriptions: vec![subscription(a, 0)],
            },
        ),
        Peer::live(&limits, roster()),
    ];
    let peer = Peer::serve(Arc::clone(&plane), limits, 0, burst);
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.rosters.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the roster was answered behind the whole unread replay");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!peer.served.is_finished());
}

#[tokio::test(start_paused = true)]
async fn a_trickling_peer_still_receives_credit_and_commands() {
    let a = session(SESSION_A);
    let plane = Arc::new(PlaneFixture::with_history(&[(a, 2_000)]));
    let peer = Peer::serve(Arc::clone(&plane), CodecLimits::default(), 0, Vec::new());
    let permits = Arc::clone(&peer.writer.permits);
    let trickle = tokio::spawn(trickle_task(Arc::clone(&permits)));
    peer.send(LiveClientRequest::Subscribe {
        request_id: request_id(),
        subscriptions: vec![subscription(a, 0)],
    });
    tokio::time::timeout(Duration::from_secs(5), until(|| peer.written().len() >= 3))
        .await
        .expect("frames trickled out while the backlog stayed queued");

    trickle.abort();
    let _ = trickle.await;
    let taken = peer.written().len();
    peer.send(LiveClientRequest::GrantDownloadCredit {
        request: TransferCreditRequest {
            command_id: CommandId::new("credit-cmd").unwrap(),
            transfer_id: TransferId::new(Uuid::new_v4()).unwrap(),
            chunks: NonZeroU16::MIN,
        },
    });
    peer.send(roster());
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.credits.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the credit reached the plane before the backlog cleared");
    tokio::time::timeout(
        Duration::from_secs(5),
        until(|| plane.rosters.load(Ordering::SeqCst) == 1),
    )
    .await
    .expect("the roster reached the plane before the backlog cleared");
    assert!(
        peer.written().len() <= taken + 1,
        "the backlog was still queued, not written: taken={taken} written={}",
        peer.written().len()
    );

    let drip = tokio::spawn(trickle_task(Arc::clone(&permits)));
    peer.registry.stop_all();
    let registry = peer.registry.clone();
    let ended = peer.ended_within(Duration::from_millis(2_100)).await;
    assert!(
        ended.is_ok(),
        "the stop ended the connection while trickling: {ended:?}"
    );
    tokio::time::timeout(Duration::from_millis(1), registry.drained())
        .await
        .expect("drained");
    drip.abort();
    let _ = drip.await;
}

/// A writer whose frame never completes: the peer stopped reading.
struct Stalled;

#[async_trait]
impl FrameWriter for Stalled {
    async fn send(&mut self, _frame: ConnectionFrame) -> Result<(), String> {
        std::future::pending().await
    }
}

// The byte budget includes the frame retained by a blocked write.
#[tokio::test(start_paused = true)]
async fn an_in_flight_write_counts_against_the_outbox_bound() {
    let max_frame = 4_096;
    let mut outbound = Outbound::new(Stalled, DeviceId::new(Uuid::new_v4()).unwrap(), max_frame);
    let bound = 256 * 1024 + 2 * max_frame;
    let in_flight = 64 + max_frame;
    let ping = 64 + 1;
    outbound
        .push(ConnectionFrame::Binary(vec![0; max_frame].into()))
        .unwrap();
    tokio::time::timeout(Duration::ZERO, outbound.progress())
        .await
        .ok();
    assert!(outbound.has_room());

    let mut admitted = 0;
    while outbound.push(ConnectionFrame::Ping(vec![0].into())).is_ok() {
        admitted += 1;
    }
    assert_eq!(admitted, (bound - in_flight) / ping);
    assert!(!outbound.has_room());
    assert!(matches!(
        outbound.push(ConnectionFrame::Ping(vec![0].into())),
        Err(DispatchError::Overflow { .. })
    ));
}

/// Ack backpressure over the actual serve loop: one unacked object batch
/// sits behind a stalled write, later urgent changes pull no second page,
/// and the stop still ends the connection inside the close bound with the
/// queued batch discarded.
#[tokio::test(start_paused = true)]
async fn a_stop_ends_a_connection_with_an_outstanding_object_batch() {
    let model = Arc::new(MaterializedReadModel::new(64, test_time()));
    let plane = Arc::new(PlaneFixture::default());
    let peer = Peer::serve_model(
        Arc::clone(&plane),
        model.clone(),
        CodecLimits::default(),
        1,
        Vec::new(),
    );
    peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds: vec![ObjectKind::Session],
        scope: QueryScope::All,
        after: model.revision().unwrap(),
    }));
    // The single permit carries the Subscribed answer out.
    until(|| peer.written().len() == 1).await;
    assert!(matches!(
        peer.decoded_general(&peer.written()[0]),
        Some(HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        })
    ));

    upsert_object(
        &model,
        ObjectKind::Session,
        "session-1",
        1,
        json!({"state": "open"}),
    );
    // The batch is queued behind the stalled write and nothing releases
    // it: the page is unacked, so even this urgent change pulls no second
    // page and receive/control stay live underneath.
    upsert_object(
        &model,
        ObjectKind::Session,
        "session-1",
        2,
        json!({"state": "prompt"}),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(peer.written().len(), 1, "the unacked page is the only one");

    peer.registry.stop_all();
    let registry = peer.registry.clone();
    let written = Arc::clone(&peer.writer.written);
    let ended = peer.ended_within(Duration::from_millis(2_100)).await;
    assert!(
        ended.is_ok(),
        "the stop ended the connection with the batch outstanding: {ended:?}"
    );
    tokio::time::timeout(Duration::from_millis(1), registry.drained())
        .await
        .expect("drained");
    assert_eq!(written.lock().len(), 1, "the queued batch was discarded");
}

/// A writer that always completes immediately.
struct EagerWriter;

#[async_trait]
impl FrameWriter for EagerWriter {
    async fn send(&mut self, _frame: ConnectionFrame) -> Result<(), String> {
        Ok(())
    }
}

/// A completed write marks only its own frame delivered: the next queued
/// frame stays undelivered until its own write completes. The ack gate's
/// exactness rests on this.
#[tokio::test(start_paused = true)]
async fn a_completed_frame_never_marks_the_next_one_delivered() {
    let mut outbound = Outbound::new(EagerWriter, DeviceId::new(Uuid::new_v4()).unwrap(), 4_096);
    let first = outbound
        .push(ConnectionFrame::Ping(vec![1].into()))
        .unwrap();
    let second = outbound
        .push(ConnectionFrame::Ping(vec![2].into()))
        .unwrap();
    assert_ne!(first, second, "marks are per-frame");
    let first = outbound.receipt(first);
    let second = outbound.receipt(second);
    assert!(!first.delivered());

    outbound.progress().await.unwrap();
    assert!(first.delivered());
    assert!(!second.delivered());

    outbound.progress().await.unwrap();
    assert!(second.delivered());
}

struct FailingWriter;

#[async_trait]
impl FrameWriter for FailingWriter {
    async fn send(&mut self, _frame: ConnectionFrame) -> Result<(), String> {
        Err("peer disconnected".to_owned())
    }
}

#[tokio::test]
async fn a_failed_write_never_delivers_its_receipt() {
    let mut outbound = Outbound::new(FailingWriter, DeviceId::new(Uuid::new_v4()).unwrap(), 4_096);
    let mark = outbound
        .push(ConnectionFrame::Ping(vec![1].into()))
        .unwrap();
    let receipt = outbound.receipt(mark);
    assert!(matches!(
        outbound.progress().await,
        Err(DispatchError::Transport(_))
    ));
    assert!(!receipt.delivered());
}

/// While an object batch is still in flight the server refuses every
/// SubscribeObjects typed and keeps the old page held: the ack at the
/// checkpoint works only once the batch is actually on the wire, and a
/// re-baseline cannot sneak a second page past the one-page bound.
#[tokio::test]
async fn an_undelivered_page_refuses_resubscribe_until_delivered() {
    let model = Arc::new(MaterializedReadModel::new(64, test_time()));
    let plane = Arc::new(PlaneFixture::default());
    let peer = Peer::serve_model(
        Arc::clone(&plane),
        model.clone(),
        CodecLimits::default(),
        1,
        Vec::new(),
    );
    peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds: vec![ObjectKind::Session],
        scope: QueryScope::All,
        after: model.revision().unwrap(),
    }));
    until(|| peer.written().len() == 1).await;

    upsert_object(
        &model,
        ObjectKind::Session,
        "session-1",
        1,
        json!({"state": "open"}),
    );
    // The urgent page is pumped ahead of the stalled write: wait until
    // the batch is the one frame in flight — the subscribed response
    // completed, the batch write started and parked, undelivered. Both
    // the premature ack at its checkpoint and a re-baseline are then
    // refused typed.
    until(|| peer.written().len() == 1 && peer.pending_writes() == 1).await;
    let checkpoint = model.revision().unwrap();
    peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds: vec![ObjectKind::Session],
        scope: QueryScope::All,
        after: checkpoint,
    }));
    peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds: vec![ObjectKind::Session],
        scope: QueryScope::All,
        after: Revision::new(0),
    }));
    // The serve loop answers each request in the one poll that pulls it,
    // so once the second resubscribe is observed both typed refusals are
    // queued behind the parked batch. Only then is the writer released.
    until(|| peer.frames_read() == 3).await;
    peer.writer.permits.add_permits(3);
    until(|| peer.written().len() == 4).await;
    let written = peer.written();
    assert!(matches!(
        peer.decoded_general(&written[1]),
        Some(HuginnMessage::ObjectDeltaBatch(_))
    ));
    for refusal in &written[2..4] {
        assert!(matches!(
            peer.decoded_general(refusal),
            Some(HuginnMessage::ProtocolError(
                HuginnProtocolError::Conflict { .. }
            ))
        ));
    }

    // The batch is on the wire now: the exact ack is accepted and pulls
    // no second page — one batch ever left this connection.
    peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds: vec![ObjectKind::Session],
        scope: QueryScope::All,
        after: checkpoint,
    }));
    peer.writer.permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), until(|| peer.written().len() == 5))
        .await
        .expect("the delivered checkpoint must accept resubscription promptly");
    assert!(matches!(
        peer.decoded_general(&peer.written()[4]),
        Some(HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        })
    ));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(peer.written().len(), 5);
    let batches = peer
        .written()
        .iter()
        .filter(|frame| {
            matches!(
                peer.decoded_general(frame),
                Some(HuginnMessage::ObjectDeltaBatch(_))
            )
        })
        .count();
    assert_eq!(batches, 1, "one page per wire, no matter the refusals");
    peer.to_server.send(ConnectionFrame::Close).unwrap();
    peer.ended_within(Duration::from_secs(1)).await.unwrap();
}

struct ResubscribeGuard {
    calls: AtomicUsize,
    release: Semaphore,
}

#[async_trait]
impl DispatchGuard for ResubscribeGuard {
    async fn check_stop(&self) -> Result<(), HuginnProtocolError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            self.release.acquire().await.unwrap().forget();
        }
        Ok(())
    }
}

#[tokio::test]
async fn a_page_delivered_during_resubscribe_dispatch_accepts_its_checkpoint() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let model = Arc::new(MaterializedReadModel::new(64, test_time()));
        let guard = Arc::new(ResubscribeGuard {
            calls: AtomicUsize::new(0),
            release: Semaphore::new(0),
        });
        let peer = Peer::serve_guard(
            Arc::new(PlaneFixture::default()),
            model.clone(),
            CodecLimits::default(),
            1,
            Vec::new(),
            guard.clone(),
        );
        peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
            kinds: vec![ObjectKind::Session],
            scope: QueryScope::All,
            after: model.revision().unwrap(),
        }));
        until(|| peer.written().len() == 1).await;
        upsert_object(
            &model,
            ObjectKind::Session,
            "session-1",
            1,
            json!({"state": "open"}),
        );
        until(|| peer.pending_writes() == 1).await;
        let checkpoint = model.revision().unwrap();
        peer.send_general(HuginnRequest::SubscribeObjects(ObjectSubscription {
            kinds: vec![ObjectKind::Session],
            scope: QueryScope::All,
            after: checkpoint,
        }));
        until(|| guard.calls.load(Ordering::SeqCst) == 2).await;
        peer.writer.permits.add_permits(1);
        until(|| peer.written().len() == 2).await;
        assert!(matches!(
            &peer.decoded_general(&peer.written()[1]),
            Some(HuginnMessage::ObjectDeltaBatch(page)) if page.to_revision == checkpoint
        ));
        guard.release.add_permits(1);
        peer.writer.permits.add_permits(1);
        until(|| peer.written().len() == 3).await;
        assert!(
            matches!(
                peer.decoded_general(&peer.written()[2]),
                Some(HuginnMessage::Response {
                    result: HuginnResponse::Subscribed,
                    ..
                })
            ),
            "completion during dispatch must not leave a stale objectAckPending gate"
        );
        upsert_object(
            &model,
            ObjectKind::Session,
            "session-1",
            2,
            json!({"state": "prompt"}),
        );
        peer.writer.permits.add_permits(1);
        until(|| peer.written().len() == 4).await;
        assert!(matches!(
            &peer.decoded_general(&peer.written()[3]),
            Some(HuginnMessage::ObjectDeltaBatch(page))
                if page.from_revision == checkpoint && page.to_revision == model.revision().unwrap()
        ));
        peer.to_server.send(ConnectionFrame::Close).unwrap();
        peer.ended_within(Duration::from_secs(1)).await.unwrap();
    })
    .await
    .expect("resubscription and subsequent urgent delivery must finish within five seconds");
}
