//! Dispatch tests using the serve loop, with history replay followed by live events.

use std::collections::BTreeMap;
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{self, StreamExt};
use odin_domain::huginn::HuginnCommandPort;
use odin_domain::huginn::{
    ArtifactReadRequest, ArtifactReadStream, ArtifactRef, CommandReceipt, ConnectionId,
    ContentTicket, ContentTicketIssuer, ContentTicketRequest, DeltaPage, DeltaQuery, DeviceId,
    EventSeq, Freshness, FreshnessState, HistoryPage, HistoryQuery, HuginnMessage,
    HuginnMessageStream, HuginnProtocolError, HuginnReadModel, HuginnRequest, HuginnResponse,
    HuginnStreamSource, LiveClientRequest, LiveCommand, LiveContentBlock, LiveError, LiveEvent,
    LiveEventBody, LiveEventStream, LiveMessage, LiveProtocolError, LiveResponse,
    LiveServerMessage, LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, ObjectKind,
    ObjectRef, ObjectSnapshot, ObjectSubscription, OmpLivePlane, OpenSessionRequest, ProviderName,
    QueryScope, RequestId, Revision, RevisionSource, SearchPage, SearchQuery, SeatRoster,
    SessionEpoch, SessionListPage, SessionListQuery, SessionSubscription, SnapshotPage,
    SnapshotQuery, SubscribeRequest, SubscriptionSet, TailnetNodeId, TerminalControlLeaseId,
    TerminalControlRequest, TerminalControlStatus, TerminalInput, TerminalResize, TerminalSeq,
    TransferChunk, TransferId, TransferStatus, UploadManifest, VerifiedOwnerDevice,
};
use odin_domain::{CommandId, Digest, EventId, NodeId, ProjectId, SeatId, SliceId};
use serde_json::json;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;

use super::command::AuthenticatedCommandPort;
use super::live::{
    DispatchGuard, LiveDispatcher, LiveDispatcherLimits, LiveDispatcherRuntime, LiveGateways,
};
use super::registry::{
    ConnectionFrame, ConnectionRegistry, FrameReader, FrameWriter, ServerConnection,
};
use crate::client::{
    memory_transport, ClientError, RemoteClient, DeviceCredential, MemoryCredentialStore,
    MemoryServerEnd, TransportFrame,
};
use crate::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};
use crate::read_model::{MaterializedReadModel, ProjectionMetadata};
use crate::state::NodePosture;

const SESSION_A: &str = "11111111-2222-4333-8444-555555555555";
const SESSION_B: &str = "66666666-7777-4888-9999-aaaaaaaaaaaa";

fn session(id: &str) -> LiveSessionId {
    LiveSessionId::parse(id).unwrap()
}

fn live_event(session: LiveSessionId, sequence: u64) -> LiveEvent {
    LiveEvent::new(
        1,
        EventId::new(format!("event:{session}-{sequence}")).unwrap(),
        session,
        SessionEpoch::new(1),
        EventSeq::new(sequence),
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        LiveEventBody::UserMessage(
            LiveMessage::new(vec![LiveContentBlock::Text(format!("frame {sequence}"))]).unwrap(),
        ),
    )
    .unwrap()
}

fn unsupported() -> LiveError {
    LiveError::unavailable("fixture", "the fixture plane does not serve this")
}

fn unsupported_general() -> HuginnProtocolError {
    HuginnProtocolError::Unsupported {
        operation: "fixture".to_owned(),
    }
}

/// Durable history per session plus tail senders, like the session actor.
#[derive(Default)]
struct PlaneFixture {
    history: Mutex<BTreeMap<LiveSessionId, Vec<LiveEvent>>>,
    tails: Mutex<Vec<mpsc::UnboundedSender<Result<LiveEvent, LiveError>>>>,
    /// Roster reads served: a command the connection received.
    rosters: std::sync::atomic::AtomicUsize,
    /// Session listings begun; each one never answers.
    listings: std::sync::atomic::AtomicUsize,
    /// Download-credit grants received: a control frame taken while
    /// writes stalled.
    credits: std::sync::atomic::AtomicUsize,
    /// Authenticated session opens: the (device, request) the
    /// authenticated port received, in order.
    authenticated_opens: Mutex<Vec<(DeviceId, OpenSessionRequest)>>,
    /// Device-less open attempts at the general port: must stay zero.
    unauthenticated_opens: std::sync::atomic::AtomicUsize,
    /// Device-less plane opens: must stay zero on every channel.
    plane_opens: std::sync::atomic::AtomicUsize,
    /// The page limit each `history` read asked the plane for.
    history_limits: Mutex<Vec<u16>>,
    /// The first Compute request is held until released, so a test can
    /// cover the cancellable watch around an in-flight sample.
    compute_hold: Mutex<Option<tokio::sync::watch::Receiver<bool>>>,
}
impl PlaneFixture {
    fn with_history(sessions: &[(LiveSessionId, u64)]) -> Self {
        let fixture = Self::default();
        {
            let mut history = fixture.history.lock().unwrap();
            for (session, head) in sessions {
                history.insert(
                    *session,
                    (1..=*head).map(|seq| live_event(*session, seq)).collect(),
                );
            }
        }
        fixture
    }

    /// Appends one durable event and publishes it to every live tail.
    fn append(&self, session: LiveSessionId) {
        let event = {
            let mut history = self.history.lock().unwrap();
            let events = history.entry(session).or_default();
            let event = live_event(session, events.len() as u64 + 1);
            events.push(event.clone());
            event
        };
        for tail in self.tails.lock().unwrap().iter() {
            let _ = tail.send(Ok(event.clone()));
        }
    }
}

#[async_trait]
impl HuginnCommandPort for PlaneFixture {
    async fn execute(&self, request: HuginnRequest) -> Result<HuginnResponse, HuginnProtocolError> {
        if matches!(request, HuginnRequest::OpenSession(_)) {
            self.unauthenticated_opens
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        Err(unsupported_general())
    }
}

#[async_trait]
impl AuthenticatedCommandPort for PlaneFixture {
    async fn execute_authenticated(
        &self,
        device: DeviceId,
        request: HuginnRequest,
    ) -> Result<HuginnResponse, HuginnProtocolError> {
        if let HuginnRequest::OpenSession(open) = request {
            self.authenticated_opens
                .lock()
                .unwrap()
                .push((device, open));
            return Ok(HuginnResponse::SessionOpened(opened_summary()));
        }
        // Compute needs a device, so the held sample lives on this port.
        let held = self
            .compute_hold
            .lock()
            .unwrap()
            .take_if(|_| matches!(request, HuginnRequest::Compute));
        if let Some(mut held) = held {
            let _ = held.changed().await;
        }
        Err(unsupported_general())
    }
}

#[async_trait]
impl OmpLivePlane for PlaneFixture {
    async fn terminal_snapshot(
        &self,
        _session: odin_domain::huginn::LiveSessionId,
    ) -> Result<odin_domain::huginn::TerminalSnapshot, LiveError> {
        Err(unsupported())
    }

    async fn roster(&self) -> Result<SeatRoster, LiveError> {
        self.rosters
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(unsupported())
    }

    async fn sessions(&self, _query: SessionListQuery) -> Result<SessionListPage, LiveError> {
        self.listings
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::pending().await
    }

    async fn history(&self, query: HistoryQuery) -> Result<HistoryPage, LiveError> {
        self.history_limits.lock().unwrap().push(query.limit.get());
        let history = self.history.lock().unwrap();
        let events = history.get(&query.session_id).ok_or(LiveError::NotFound {
            object_kind: "session".to_owned(),
            object_id: query.session_id.to_string(),
        })?;
        let head = events
            .last()
            .map_or(EventSeq::new(0), |event| event.sequence);
        let page: Vec<LiveEvent> = events
            .iter()
            .filter(|event| event.sequence > query.after)
            .take(usize::from(query.limit.get()))
            .cloned()
            .collect();
        let next_after = page.last().map_or(query.after, |event| event.sequence);
        Ok(HistoryPage {
            events: page,
            next_after,
            head,
        })
    }

    async fn subscribe(&self, request: SubscribeRequest) -> Result<LiveEventStream, LiveError> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let replay: Vec<Result<LiveEvent, LiveError>> = {
            let history = self.history.lock().unwrap();
            request
                .subscriptions
                .iter()
                .flat_map(|subscription| {
                    history
                        .get(&subscription.session_id)
                        .into_iter()
                        .flatten()
                        .filter(|event| event.sequence > subscription.event_after)
                        .cloned()
                        .map(Ok)
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        self.tails.lock().unwrap().push(sender);
        Ok(Box::pin(
            stream::iter(replay).chain(UnboundedReceiverStream::new(receiver)),
        ))
    }

    async fn open_session(
        &self,
        _request: OpenSessionRequest,
    ) -> Result<LiveSessionSummary, LiveError> {
        self.plane_opens
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(unsupported())
    }

    async fn command(&self, _command: LiveCommand) -> Result<CommandReceipt, LiveError> {
        Err(unsupported())
    }

    async fn begin_upload(&self, _manifest: UploadManifest) -> Result<TransferStatus, LiveError> {
        Err(unsupported())
    }

    async fn upload_chunk(
        &self,
        _transfer: TransferId,
        _chunk: TransferChunk,
    ) -> Result<(), LiveError> {
        Err(unsupported())
    }

    async fn commit_upload(&self, _transfer: TransferId) -> Result<ArtifactRef, LiveError> {
        Err(unsupported())
    }

    async fn cancel_transfer(
        &self,
        _command_id: CommandId,
        _transfer: TransferId,
    ) -> Result<TransferStatus, LiveError> {
        Err(unsupported())
    }

    async fn grant_download_credit(
        &self,
        _command_id: CommandId,
        _transfer: TransferId,
        _chunks: std::num::NonZeroU16,
    ) -> Result<(), LiveError> {
        self.credits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    async fn read_artifact(
        &self,
        _request: ArtifactReadRequest,
    ) -> Result<(ArtifactRef, ArtifactReadStream), LiveError> {
        Err(unsupported())
    }

    async fn acquire_terminal_control(
        &self,
        _command_id: CommandId,
        _device: DeviceId,
        _request: TerminalControlRequest,
    ) -> Result<TerminalControlStatus, LiveError> {
        Err(unsupported())
    }

    async fn write_terminal(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _input: TerminalInput,
    ) -> Result<(), LiveError> {
        Err(unsupported())
    }

    async fn resize_terminal(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _resize: TerminalResize,
    ) -> Result<(), LiveError> {
        Err(unsupported())
    }

    async fn release_terminal_control(
        &self,
        _command_id: CommandId,
        _session: LiveSessionId,
        _lease: TerminalControlLeaseId,
    ) -> Result<TerminalControlStatus, LiveError> {
        Err(unsupported())
    }
}

struct Unsupported;

#[async_trait]
impl HuginnReadModel for Unsupported {
    async fn snapshot(&self, _query: SnapshotQuery) -> Result<SnapshotPage, HuginnProtocolError> {
        Err(unsupported_general())
    }

    async fn search(&self, _query: SearchQuery) -> Result<SearchPage, HuginnProtocolError> {
        Err(unsupported_general())
    }

    async fn deltas(
        &self,
        _query: DeltaQuery,
        _max_bytes: usize,
    ) -> Result<DeltaPage, HuginnProtocolError> {
        Err(unsupported_general())
    }
}

#[async_trait]
impl HuginnStreamSource for Unsupported {
    async fn subscribe(
        &self,
        _subscriptions: SubscriptionSet,
    ) -> Result<HuginnMessageStream, HuginnProtocolError> {
        Err(unsupported_general())
    }
}

#[async_trait]
impl ContentTicketIssuer for Unsupported {
    async fn issue(
        &self,
        _device: DeviceId,
        _request: ContentTicketRequest,
    ) -> Result<ContentTicket, HuginnProtocolError> {
        Err(unsupported_general())
    }
}

#[async_trait]
impl DispatchGuard for Unsupported {
    async fn check_stop(&self) -> Result<(), HuginnProtocolError> {
        Ok(())
    }
}

/// An in-memory websocket: binary frames in, binary frames out.
struct MemoryConnection {
    incoming: mpsc::UnboundedReceiver<ConnectionFrame>,
    outgoing: mpsc::UnboundedSender<ConnectionFrame>,
}

struct MemoryReader(mpsc::UnboundedReceiver<ConnectionFrame>);
struct MemoryWriter(mpsc::UnboundedSender<ConnectionFrame>);

impl ServerConnection for MemoryConnection {
    type Reader = MemoryReader;
    type Writer = MemoryWriter;

    fn split(self) -> (MemoryReader, MemoryWriter) {
        (MemoryReader(self.incoming), MemoryWriter(self.outgoing))
    }
}

#[async_trait]
impl FrameReader for MemoryReader {
    async fn receive(&mut self) -> Result<Option<ConnectionFrame>, String> {
        Ok(self.0.recv().await)
    }
}

#[async_trait]
impl FrameWriter for MemoryWriter {
    async fn send(&mut self, frame: ConnectionFrame) -> Result<(), String> {
        self.0.send(frame).map_err(|error| error.to_string())
    }
}

struct Client {
    device: DeviceId,
    to_server: mpsc::UnboundedSender<ConnectionFrame>,
    from_server: mpsc::UnboundedReceiver<ConnectionFrame>,
    limits: CodecLimits,
}

impl Client {
    fn connect(plane: Arc<PlaneFixture>) -> Self {
        Self::connect_with_model(plane, Arc::new(MaterializedReadModel::new(64, test_time())))
    }

    fn connect_with_model(plane: Arc<PlaneFixture>, model: Arc<MaterializedReadModel>) -> Self {
        Self::connect_configured(
            plane,
            model,
            LiveDispatcherLimits::default(),
            NodePosture::Authoritative,
            Arc::new(Unsupported),
        )
    }

    fn connect_configured(
        plane: Arc<PlaneFixture>,
        model: Arc<MaterializedReadModel>,
        limits: LiveDispatcherLimits,
        posture: NodePosture,
        guard: Arc<dyn DispatchGuard>,
    ) -> Self {
        let dispatcher = LiveDispatcher::with_posture_limits(
            model,
            plane,
            Arc::new(Unsupported),
            guard,
            Arc::new(Unsupported),
            LiveDispatcherRuntime {
                gateways: LiveGateways::none(),
                limits,
                posture,
            },
        );
        let device = VerifiedOwnerDevice {
            device_id: DeviceId::new(Uuid::new_v4()).unwrap(),
            tailnet_node_id: TailnetNodeId::parse("node.pc").unwrap(),
            connection_id: ConnectionId::new(Uuid::new_v4()).unwrap(),
        };
        let device_id = device.device_id;
        let registration = ConnectionRegistry::new().register(&device).unwrap();
        let (to_server, incoming) = mpsc::unbounded_channel();
        let (outgoing, from_server) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = dispatcher
                .serve_connection(
                    MemoryConnection { incoming, outgoing },
                    device,
                    registration,
                )
                .await;
        });
        Self {
            device: device_id,
            to_server,
            from_server,
            limits: CodecLimits::default(),
        }
    }

    fn send(&self, request: LiveClientRequest) {
        let bytes = encode_frame(&ClientFrame::Live(request), &self.limits).unwrap();
        self.to_server
            .send(ConnectionFrame::Binary(bytes.into()))
            .unwrap();
    }

    fn send_general(&self, request: HuginnRequest) {
        let bytes = encode_frame(&ClientFrame::General(request), &self.limits).unwrap();
        self.to_server
            .send(ConnectionFrame::Binary(bytes.into()))
            .unwrap();
    }

    async fn next_raw(&mut self) -> ConnectionFrame {
        tokio::time::timeout(Duration::from_secs(5), self.from_server.recv())
            .await
            .expect("the server answered within 5 s")
            .expect("the connection stayed open")
    }

    async fn next_general(&mut self) -> HuginnMessage {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.from_server.recv())
            .await
            .expect("the server answered within 5 s")
            .expect("the connection stayed open");
        let ConnectionFrame::Binary(bytes) = frame else {
            panic!("expected a binary frame");
        };
        match decode_frame::<ServerFrame>(&bytes, &self.limits)
            .unwrap()
            .value
        {
            ServerFrame::General(message) => message,
            ServerFrame::Live(message) => panic!("unexpected live frame {message:?}"),
        }
    }

    async fn next(&mut self) -> LiveServerMessage {
        let frame = tokio::time::timeout(Duration::from_secs(5), self.from_server.recv())
            .await
            .expect("the server answered within 5 s")
            .expect("the connection stayed open");
        let ConnectionFrame::Binary(bytes) = frame else {
            panic!("expected a binary frame");
        };
        match decode_frame::<ServerFrame>(&bytes, &self.limits)
            .unwrap()
            .value
        {
            ServerFrame::Live(message) => message,
            ServerFrame::General(message) => panic!("unexpected general frame {message:?}"),
        }
    }

    async fn silent(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(200), self.from_server.recv())
                .await
                .is_err(),
            "no further frame was due"
        );
    }
}

fn request_id() -> RequestId {
    RequestId::parse(&Uuid::new_v4().to_string()).unwrap()
}

fn subscription(session: LiveSessionId, after: u64) -> SessionSubscription {
    SessionSubscription {
        session_id: session,
        event_after: EventSeq::new(after),
        terminal_after: None,
    }
}

fn event_seq(message: &LiveServerMessage) -> (LiveSessionId, u64) {
    match message {
        LiveServerMessage::Event(event) => (event.session_id, event.sequence.get()),
        other => panic!("expected an event, got {other:?}"),
    }
}

/// ACP waits for ReplayComplete before answering session/new; tail events need no replay markers.
#[tokio::test(start_paused = true)]
async fn live_subscribe_completes_each_session_at_its_own_head() {
    let a = session(SESSION_A);
    let b = session(SESSION_B);
    let plane = Arc::new(PlaneFixture::with_history(&[(a, 2), (b, 1)]));
    let mut client = Client::connect(Arc::clone(&plane));
    client.send(LiveClientRequest::Subscribe {
        request_id: request_id(),
        subscriptions: vec![subscription(a, 0), subscription(b, 1)],
    });

    assert!(matches!(
        client.next().await,
        LiveServerMessage::Response {
            result: LiveResponse::Subscribed,
            ..
        }
    ));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::ReplayBegin { session_id, head, .. } if session_id == a && head.get() == 2
    ));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::ReplayBegin { session_id, head, .. } if session_id == b && head.get() == 1
    ));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::ReplayComplete { session_id, head } if session_id == b && head.get() == 1
    ));
    assert_eq!(event_seq(&client.next().await), (a, 1));
    assert_eq!(event_seq(&client.next().await), (a, 2));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::ReplayComplete { session_id, head } if session_id == a && head.get() == 2
    ));

    plane.append(b);
    assert_eq!(event_seq(&client.next().await), (b, 2));
    client.silent().await;
}

/// The STOP guard closes dispatch for every request, and a follower refuses a write but still
/// answers a read.
#[tokio::test(start_paused = true)]
async fn a_stop_closes_dispatch_and_a_follower_refuses_writes() {
    struct Stopped;
    #[async_trait]
    impl DispatchGuard for Stopped {
        async fn check_stop(&self) -> Result<(), HuginnProtocolError> {
            Err(HuginnProtocolError::Conflict {
                code: "controllerStopped".to_owned(),
                message: "stopped".to_owned(),
            })
        }
    }
    let model = || Arc::new(MaterializedReadModel::new(64, test_time()));
    let connect = |posture, guard: Arc<dyn DispatchGuard>| {
        Client::connect_configured(
            Arc::new(PlaneFixture::default()),
            model(),
            LiveDispatcherLimits::default(),
            posture,
            guard,
        )
    };

    let mut stopped = connect(NodePosture::Authoritative, Arc::new(Stopped));
    stopped.send_general(HuginnRequest::Compute);
    assert!(matches!(
        stopped.next_general().await,
        HuginnMessage::ProtocolError(HuginnProtocolError::Conflict { code, .. }) if code == "controllerStopped"
    ));
    let mut stopped = connect(NodePosture::Authoritative, Arc::new(Stopped));
    stopped.send(LiveClientRequest::GetRoster {
        request_id: request_id(),
        if_revision: None,
    });
    assert!(matches!(
        stopped.next().await,
        LiveServerMessage::ProtocolError(LiveProtocolError::Conflict { code, .. }) if code == "controllerStopped"
    ));

    let mut follower = connect(NodePosture::Follower, Arc::new(Unsupported));
    follower.send_general(HuginnRequest::Compute);
    assert!(matches!(
        follower.next_general().await,
        HuginnMessage::ProtocolError(HuginnProtocolError::Unauthorized)
    ));
    follower.send_general(HuginnRequest::Snapshot(snapshot_query(vec![
        ObjectKind::Seat,
    ])));
    assert!(
        matches!(
            follower.next_general().await,
            HuginnMessage::Response {
                result: HuginnResponse::Snapshot(_),
                ..
            }
        ),
        "a read is still admitted"
    );
}

/// A peer that breaks the protocol gets the typed error and then a close; an answer over the frame
/// bound is replaced by a refusal and the connection stays up.
#[tokio::test(start_paused = true)]
async fn protocol_violations_close_and_an_oversize_answer_does_not() {
    let a = session(SESSION_A);
    let violate = |frame: ConnectionFrame| async move {
        let mut client = Client::connect(Arc::new(PlaneFixture::default()));
        client.to_server.send(frame).unwrap();
        let first = client.next_raw().await;
        let second = client.next_raw().await;
        (first, second)
    };

    let (first, second) = violate(ConnectionFrame::Text).await;
    assert!(matches!(first, ConnectionFrame::Binary(_)));
    assert!(matches!(second, ConnectionFrame::Close));
    let (first, second) = violate(ConnectionFrame::Binary(vec![0xff, 0x00].into())).await;
    assert!(matches!(first, ConnectionFrame::Binary(_)));
    assert!(matches!(second, ConnectionFrame::Close));

    let mut mixed = Client::connect(Arc::new(PlaneFixture::default()));
    mixed.send_general(HuginnRequest::Compute);
    mixed.next_general().await;
    mixed.send(LiveClientRequest::GetRoster {
        request_id: request_id(),
        if_revision: None,
    });
    assert!(matches!(mixed.next_raw().await, ConnectionFrame::Binary(_)));
    assert!(matches!(mixed.next_raw().await, ConnectionFrame::Close));

    let plane = Arc::new(PlaneFixture::with_history(&[(a, 40)]));
    let limits = LiveDispatcherLimits::new(
        CodecLimits::from_max_frame_bytes(std::num::NonZeroUsize::new(4096).unwrap()),
        64,
        NonZeroU16::new(16).unwrap(),
    );
    let mut client = Client::connect_configured(
        plane,
        Arc::new(MaterializedReadModel::new(64, test_time())),
        limits,
        NodePosture::Authoritative,
        Arc::new(Unsupported),
    );
    let history = |limit: u16| LiveClientRequest::GetHistory {
        request_id: request_id(),
        session_id: a,
        after: EventSeq::new(0),
        limit: NonZeroU16::new(limit).unwrap(),
    };
    client.send(history(40));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::ProtocolError(LiveProtocolError::ResourceLimit { limit }) if limit == "max_frame_bytes"
    ));
    client.send(history(1));
    assert!(matches!(
        client.next().await,
        LiveServerMessage::Response {
            result: LiveResponse::History(_),
            ..
        }
    ));
}

fn test_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn upsert_object(
    model: &MaterializedReadModel,
    kind: ObjectKind,
    id: &str,
    revision: u64,
    value: serde_json::Value,
) {
    upsert_object_scoped(
        model,
        kind,
        id,
        revision,
        value,
        &ProjectionMetadata::new("object", "dispatch test"),
    );
}

fn upsert_object_scoped(
    model: &MaterializedReadModel,
    kind: ObjectKind,
    id: &str,
    revision: u64,
    value: serde_json::Value,
    metadata: &ProjectionMetadata,
) {
    let snapshot = ObjectSnapshot {
        object: ObjectRef {
            kind,
            id: id.to_owned(),
        },
        revision: Revision::new(revision),
        revision_source: RevisionSource::Registry,
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: test_time(),
            source_updated_at: None,
            stale_after_seconds: None,
        },
        content_digest: Digest::hash(value.to_string().as_bytes()),
        value,
    };
    model.upsert_indexed(snapshot, metadata.clone()).unwrap();
}

fn subscribe_objects(kinds: Vec<ObjectKind>, after: Revision) -> HuginnRequest {
    HuginnRequest::SubscribeObjects(ObjectSubscription {
        kinds,
        scope: QueryScope::All,
        after,
    })
}

fn snapshot_query(kinds: Vec<ObjectKind>) -> SnapshotQuery {
    SnapshotQuery {
        scope: QueryScope::All,
        kinds,
        if_revision: None,
        cursor: None,
        limit: std::num::NonZeroU16::new(64).unwrap(),
        include_stale: true,
    }
}

/// The real baseline a subscription resumes from: a complete snapshot of
/// its kinds and scope, taken on the subscribing connection.
async fn baseline(client: &mut Client, query: SnapshotQuery) -> Revision {
    client.send_general(HuginnRequest::Snapshot(query));
    let page = next_snapshot(client).await;
    assert_eq!(page.next_cursor, None, "one complete page");
    page.revision
}

async fn next_snapshot(client: &mut Client) -> SnapshotPage {
    match client.next_general().await {
        HuginnMessage::Response {
            result: HuginnResponse::Snapshot(page),
            ..
        } => page,
        other => panic!("expected a snapshot, got {other:?}"),
    }
}

fn object_ids(page: &SnapshotPage) -> Vec<&str> {
    page.objects
        .iter()
        .map(|object| object.object.id.as_str())
        .collect()
}

/// The phone contract end to end: `Subscribed` answers first, then one
/// atomic batch carries every selected change with the global checkpoint
/// it covers — including changes filtered out by kinds — and the ack at
/// that checkpoint frees the next page.
#[tokio::test(start_paused = true)]
async fn subscribe_objects_delivers_batch_after_subscribed_and_acks_at_checkpoint() {
    let model = Arc::new(MaterializedReadModel::new(64, test_time()));
    let plane = Arc::new(PlaneFixture::default());
    let mut client = Client::connect_with_model(Arc::clone(&plane), Arc::clone(&model));
    upsert_object(
        &model,
        ObjectKind::Session,
        "session-1",
        1,
        json!({"state": "open"}),
    );
    let after = baseline(
        &mut client,
        snapshot_query(vec![ObjectKind::Session, ObjectKind::Approval]),
    )
    .await;
    assert_eq!(after, model.revision().unwrap());

    client.send_general(subscribe_objects(
        vec![ObjectKind::Session, ObjectKind::Approval],
        after,
    ));
    assert!(matches!(
        client.next_general().await,
        HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        }
    ));
    client.silent().await;

    upsert_object(
        &model,
        ObjectKind::Session,
        "session-1",
        2,
        json!({"state": "prompt"}),
    );
    upsert_object(
        &model,
        ObjectKind::Approval,
        "approval-1",
        1,
        json!({"pending": true}),
    );
    upsert_object(
        &model,
        ObjectKind::KubeResource,
        "kube-1",
        1,
        json!({"cpu": 1}),
    );
    let HuginnMessage::ObjectDeltaBatch(batch) = client.next_general().await else {
        panic!("expected an object batch");
    };
    assert_eq!(batch.from_revision, after);
    assert_eq!(batch.to_revision, model.revision().unwrap());
    assert_eq!(
        batch.deltas.len(),
        2,
        "the kube delta is filtered: {batch:?}"
    );
    assert!(batch.deltas.iter().all(|delta| matches!(
        delta.object.kind,
        ObjectKind::Session | ObjectKind::Approval
    )));
    assert_eq!(batch.next_after, None);

    client.send_general(subscribe_objects(
        vec![ObjectKind::Session, ObjectKind::Approval],
        batch.to_revision,
    ));
    assert!(matches!(
        client.next_general().await,
        HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        }
    ));
    client.silent().await;
}

/// Coalescible-only content waits out the 30-second window; the flush at
/// the deadline is one bounded batch, not ten ticks.
#[tokio::test(start_paused = true)]
async fn coalescible_changes_flush_at_the_thirty_second_deadline() {
    let model = Arc::new(MaterializedReadModel::new(64, test_time()));
    let plane = Arc::new(PlaneFixture::default());
    let mut client = Client::connect_with_model(Arc::clone(&plane), Arc::clone(&model));
    client.send_general(subscribe_objects(
        vec![ObjectKind::KubeResource],
        model.revision().unwrap(),
    ));
    assert!(matches!(
        client.next_general().await,
        HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        }
    ));

    for revision in 1..=10u64 {
        upsert_object(
            &model,
            ObjectKind::KubeResource,
            "kube-1",
            revision,
            json!({"cpu": revision}),
        );
    }
    client.silent().await;

    tokio::time::advance(Duration::from_secs(35)).await;
    let HuginnMessage::ObjectDeltaBatch(batch) = client.next_general().await else {
        panic!("expected the deadline flush");
    };
    assert_eq!(batch.deltas.len(), 1, "coalesced to the latest body");
    assert_eq!(batch.deltas[0].to_revision, Revision::new(10));
    assert_eq!(batch.to_revision, model.revision().unwrap());
    client.silent().await;
}

/// A cursor the deque no longer serves fails typed before any Subscribed,
/// and the recovery is a snapshot resubscribed at its revision — never a
/// resume that treats the gap as empty.
#[tokio::test(start_paused = true)]
async fn an_expired_cursor_fails_typed_and_never_resumes_the_gap() {
    let model = Arc::new(MaterializedReadModel::with_limits(64, 4, test_time()));
    let plane = Arc::new(PlaneFixture::default());
    let mut client = Client::connect_with_model(Arc::clone(&plane), Arc::clone(&model));
    for revision in 1..=6u64 {
        upsert_object(
            &model,
            ObjectKind::KubeResource,
            &format!("kube-{revision}"),
            1,
            json!({"cpu": revision}),
        );
    }

    client.send_general(subscribe_objects(
        vec![ObjectKind::KubeResource],
        Revision::new(0),
    ));
    assert!(
        matches!(
            client.next_general().await,
            HuginnMessage::ProtocolError(HuginnProtocolError::CursorExpired)
        ),
        "the expired cursor is a typed refusal"
    );

    let after = baseline(&mut client, snapshot_query(vec![ObjectKind::KubeResource])).await;
    client.send_general(subscribe_objects(vec![ObjectKind::KubeResource], after));
    assert!(matches!(
        client.next_general().await,
        HuginnMessage::Response {
            result: HuginnResponse::Subscribed,
            ..
        }
    ));
    client.silent().await;
}

/// Serves one connection of the real client's memory transport with the
/// real dispatcher over `model` and `gateways`: frames are piped unchanged
/// both ways.
async fn serve_client_end(
    model: Arc<MaterializedReadModel>,
    mut end: MemoryServerEnd,
    gateways: LiveGateways,
) {
    let dispatcher = LiveDispatcher::with_runtime_limits(
        model,
        Arc::new(PlaneFixture::default()),
        Arc::new(Unsupported),
        Arc::new(Unsupported),
        Arc::new(Unsupported),
        gateways,
        LiveDispatcherLimits::default(),
    );
    let device = VerifiedOwnerDevice {
        device_id: end.device_id(),
        tailnet_node_id: TailnetNodeId::parse("node.phone").unwrap(),
        connection_id: ConnectionId::new(Uuid::new_v4()).unwrap(),
    };
    let registration = ConnectionRegistry::new().register(&device).unwrap();
    let (to_server, incoming) = mpsc::unbounded_channel();
    let (outgoing, mut from_server) = mpsc::unbounded_channel();
    let served = tokio::spawn(async move {
        let _ = dispatcher
            .serve_connection(
                MemoryConnection { incoming, outgoing },
                device,
                registration,
            )
            .await;
    });
    loop {
        tokio::select! {
            frame = end.next_frame() => match frame {
                Ok(Some(bytes)) => {
                    if to_server.send(ConnectionFrame::Binary(bytes.into())).is_err() {
                        break;
                    }
                }
                _ => {
                    let _ = to_server.send(ConnectionFrame::Close);
                    break;
                }
            },
            frame = from_server.recv() => match frame {
                Some(ConnectionFrame::Binary(bytes)) => {
                    if end.send_frame(bytes.to_vec()).await.is_err() {
                        break;
                    }
                }
                Some(ConnectionFrame::Close) | None => break,
                Some(_) => {}
            },
        }
    }
    drop(to_server);
    let _ = served.await;
}

/// The real client across a daemon restart: its reconnect adopts nothing
/// the old daemon delivered, the new daemon refuses the old numeric
/// checkpoint although it equals the new head, and the client's own resync
/// — a fresh snapshot on the new connection, then a subscribe at its
/// revision — resumes delivery of the new daemon's updates.
#[tokio::test]
async fn a_reconnected_client_resyncs_instead_of_adopting_an_old_checkpoint() {
    let old_model = Arc::new(MaterializedReadModel::new(64, test_time()));
    for id in ["session-old-a", "session-old-b"] {
        upsert_object(
            &old_model,
            ObjectKind::Session,
            id,
            1,
            json!({"lifetime": "old"}),
        );
    }
    let new_model = Arc::new(MaterializedReadModel::new(64, test_time()));
    for id in ["session-new-c", "session-new-d"] {
        upsert_object(
            &new_model,
            ObjectKind::Session,
            id,
            1,
            json!({"lifetime": "new"}),
        );
    }
    let (transport, mut hub) = memory_transport(16);
    let lifetimes = [Arc::clone(&old_model), Arc::clone(&new_model)];
    let server = tokio::spawn(async move {
        for model in lifetimes {
            let end = hub.accept().await.expect("the client connects");
            tokio::spawn(serve_client_end(model, end, LiveGateways::none()));
        }
    });
    let credential = DeviceCredential::from_parts(Uuid::new_v4(), [7u8; 32]).unwrap();
    let client = RemoteClient::new(transport, MemoryCredentialStore::new(credential));
    let mut connection = client.connect().await.unwrap();

    let kinds = vec![ObjectKind::Session];
    let HuginnResponse::Snapshot(old_view) = connection
        .request(HuginnRequest::Snapshot(snapshot_query(kinds.clone())))
        .await
        .unwrap()
    else {
        panic!("expected the old daemon's snapshot");
    };
    assert_eq!(object_ids(&old_view), ["session-old-a", "session-old-b"]);
    connection
        .subscribe_objects(kinds.clone(), QueryScope::All, old_view.revision)
        .await
        .unwrap();
    let old_checkpoint = connection
        .object_checkpoint()
        .expect("adopted on the old daemon");

    // The daemon restarted: a reconnect that resumes the old checkpoint is
    // refused, and the client adopted nothing across it.
    let resumed = connection
        .reconnect_request(subscribe_objects(kinds.clone(), old_checkpoint))
        .await;
    assert!(
        matches!(
            resumed,
            Err(ClientError::Protocol(HuginnProtocolError::CursorExpired))
        ),
        "{resumed:?}"
    );
    assert_eq!(connection.object_checkpoint(), None);

    let (objects, revision) = connection.resync_objects().await.unwrap();
    let ids: Vec<&str> = objects
        .iter()
        .map(|object| object.object.id.as_str())
        .collect();
    assert_eq!(ids, ["session-new-c", "session-new-d"]);
    assert_eq!(
        revision, old_checkpoint,
        "the lifetimes collide numerically"
    );
    assert_eq!(connection.object_checkpoint(), Some(revision));

    upsert_object(
        &new_model,
        ObjectKind::Session,
        "session-new-c",
        2,
        json!({"lifetime": "new", "state": "prompt"}),
    );
    let delivered = tokio::time::timeout(Duration::from_secs(5), connection.next())
        .await
        .expect("the new daemon pushed the update")
        .expect("the connection stayed open")
        .unwrap();
    let HuginnMessage::ObjectDeltaBatch(batch) = delivered else {
        panic!("expected the new daemon's batch, got {delivered:?}");
    };
    assert_eq!(batch.from_revision, revision);
    assert_eq!(batch.deltas.len(), 1);
    assert_eq!(batch.deltas[0].object.id, "session-new-c");
    connection.ack_objects().await.unwrap();
    assert_eq!(connection.object_checkpoint(), Some(batch.to_revision));
    server.await.unwrap();
}

#[path = "serve_tests.rs"]
mod serve_tests;

/// The session summary the fixture answers a device-authenticated open
/// with, so both channels can assert the open actually reached the port.
fn opened_summary() -> LiveSessionSummary {
    LiveSessionSummary {
        session_id: session(SESSION_A),
        epoch: SessionEpoch::new(1),
        seat_id: SeatId::new("gungnir").unwrap(),
        provider: ProviderName::new("fixture").unwrap(),
        model: ModelName::new("fixture-model").unwrap(),
        title: None,
        state: LiveSessionState::Starting,
        started_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        updated_at: OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
        failed_at: None,
        event_head: EventSeq::new(0),
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
        quiet_seconds: 600,
    }
}

fn open_session_request() -> OpenSessionRequest {
    OpenSessionRequest {
        command_id: CommandId::new("open-session").unwrap(),
        seat_id: SeatId::new("gungnir").unwrap(),
        project_id: ProjectId::new("research").unwrap(),
        slice_id: SliceId::new("slice:research").unwrap(),
        provider: ProviderName::new("fixture").unwrap(),
        model: ModelName::new("fixture-model").unwrap(),
        title: None,
        target_node: NodeId::new("laptop").unwrap(),
        open_tab: false,
        initial_prompt: None,
        workload: None,
        served_revision: None,
    }
}

/// Both channels reach the plane's authenticated open with the caller's device, never the
/// device-less port or plane.
#[tokio::test]
async fn opening_a_session_rides_the_authenticated_port_on_both_channels() {
    for live in [false, true] {
        let plane = Arc::new(PlaneFixture::default());
        let mut client = Client::connect(Arc::clone(&plane));
        if live {
            let open = open_session_request();
            client.send(LiveClientRequest::OpenSession {
                request_id: request_id(),
                command_id: open.command_id,
                seat_id: open.seat_id,
                project_id: open.project_id,
                slice_id: open.slice_id,
                provider: open.provider,
                model: open.model,
                title: open.title,
                target_node: open.target_node,
                open_tab: open.open_tab,
                initial_prompt: open.initial_prompt,
                served_revision: open.served_revision,
            });
            assert!(matches!(
                client.next().await,
                LiveServerMessage::Response {
                    result: LiveResponse::SessionOpened(_),
                    ..
                }
            ));
        } else {
            client.send_general(HuginnRequest::OpenSession(open_session_request()));
            assert!(matches!(
                client.next_general().await,
                HuginnMessage::Response {
                    result: HuginnResponse::SessionOpened(_),
                    ..
                }
            ));
        }
        let opens = plane.authenticated_opens.lock().unwrap();
        assert_eq!(
            opens.len(),
            1,
            "exactly one authenticated open (live: {live})"
        );
        assert_eq!(opens[0].0, client.device, "the open carries the caller");
        drop(opens);
        let count = |counter: &std::sync::atomic::AtomicUsize| {
            counter.load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(
            count(&plane.unauthenticated_opens),
            0,
            "the device-less port saw the open"
        );
        assert_eq!(
            count(&plane.plane_opens),
            0,
            "the device-less plane open ran"
        );
    }
}

/// Downloads through the serving stack distinguish length/mtime revisions from content digests.
mod download_regression {
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
    use std::sync::Arc;

    use odin_domain::huginn::{
        ContentSource, FileGateway, FileListRequest, FileMediaPolicy, FileMetadata, FileRoot,
        FileRootAccess, FileRootId, FileRootInit, FileWatchPolicy, HuginnProtocolError,
        HuginnRequest, HuginnResponse,
    };
    use odin_domain::{Digest, SeatId};
    use uuid::Uuid;

    use crate::client::{
        memory_transport, ClientError, RemoteClient, DeviceCredential, MemoryCredentialStore,
        MemorySink, MemoryTransport,
    };
    use crate::config::FileLimits;
    use crate::dispatch::LiveGateways;
    use crate::files::{HuginnFileService, RootCatalog};
    use crate::read_model::MaterializedReadModel;

    use super::{serve_client_end, test_time};

    const FILE_NAME: &str = "notes.txt";

    fn file_bytes(len: u32, first: u8) -> Vec<u8> {
        (0..len).map(|i| first + (i % 26) as u8).collect()
    }

    /// Small chunks, so a 200-byte fixture streams as several BinaryChunks
    /// and the client's digest assembles across them.
    fn file_limits() -> FileLimits {
        FileLimits {
            max_read_chunk_bytes: NonZeroU32::new(64).expect("nonzero"),
            ..FileLimits::default()
        }
    }

    fn declared_root(dir: &tempfile::TempDir) -> FileRoot {
        FileRoot::new(FileRootInit {
            root_id: FileRootId::parse("regression-root").expect("root id"),
            display_name: "Regression".to_owned(),
            canonical_path: dir.path().to_path_buf(),
            access: FileRootAccess::ReadOnly,
            media_policy: FileMediaPolicy {
                allowed_media_types: vec!["text/plain".to_owned()],
            },
            max_object_bytes: NonZeroU64::new(1 << 20).expect("nonzero"),
            watch_policy: FileWatchPolicy::Disabled,
            allowed_seats: vec![SeatId::new("colin").expect("seat id")],
            host: None,
            save_default: None,
        })
        .expect("declared root")
    }

    fn text_service(dir: &tempfile::TempDir) -> (Arc<HuginnFileService>, FileRootId) {
        std::fs::write(dir.path().join(FILE_NAME), file_bytes(200, b'a'))
            .expect("the fixture file is written");
        let root = declared_root(dir);
        let root_id = root.root_id.clone();
        let service = Arc::new(HuginnFileService::new(
            RootCatalog::new(vec![root]).expect("root id is unique"),
            file_limits(),
        ));
        (service, root_id)
    }

    struct Rig {
        client: RemoteClient<MemoryTransport, MemoryCredentialStore>,
        root_id: FileRootId,
    }

    /// A real client over the real dispatcher and file gateway: the daemon
    /// task accepts each memory connection and serves it unchanged.
    fn rig(files: Arc<dyn FileGateway>, root_id: FileRootId) -> Rig {
        let (transport, mut hub) = memory_transport(16);
        let model = Arc::new(MaterializedReadModel::new(64, test_time()));
        tokio::spawn(async move {
            while let Some(end) = hub.accept().await {
                let gateways = LiveGateways {
                    files: Some(Arc::clone(&files)),
                    renders: None,
                };
                tokio::spawn(serve_client_end(Arc::clone(&model), end, gateways));
            }
        });
        Rig {
            client: RemoteClient::new(
                transport,
                MemoryCredentialStore::new(
                    DeviceCredential::from_parts(Uuid::new_v4(), [7u8; 32])
                        .expect("device credential"),
                ),
            ),
            root_id,
        }
    }

    async fn listed_entry(
        client: &RemoteClient<MemoryTransport, MemoryCredentialStore>,
        root_id: &FileRootId,
    ) -> FileMetadata {
        let HuginnResponse::Files(page) = client
            .request(HuginnRequest::ListFiles(FileListRequest {
                root_id: root_id.clone(),
                directory: None,
                expected_revision: None,
                after: None,
                limit: NonZeroU16::new(64).expect("nonzero"),
            }))
            .await
            .expect("the real dispatcher serves the listing")
        else {
            panic!("the listing answered with a files page");
        };
        assert_eq!(
            page.entries.len(),
            1,
            "the fixture root holds exactly the one file"
        );
        page.entries.into_iter().next().expect("one entry")
    }

    #[tokio::test]
    async fn a_listed_file_downloads_its_exact_bytes_at_the_listed_state_revision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (files, root_id) = text_service(&dir);
        let rig = rig(files, root_id);
        let entry = listed_entry(&rig.client, &rig.root_id).await;
        let listed_revision = entry
            .revision
            .expect("a file entry carries its length:mtime state revision");
        let content = file_bytes(200, b'a');
        assert_eq!(entry.byte_len, content.len() as u64);
        assert_eq!(entry.media_type.as_deref(), Some("text/plain"));
        assert_ne!(
            listed_revision,
            Digest::hash(&content),
            "the state revision is length:mtime material, not the content digest"
        );

        let mut sink = MemorySink::new(1 << 20);
        let downloaded = rig
            .client
            .download(
                ContentSource::File {
                    root: rig.root_id.clone(),
                    relative: entry.relative_path.clone(),
                    expected_revision: Some(listed_revision),
                },
                &mut sink,
            )
            .await
            .expect("a download at the listed state revision returns the exact bytes");
        assert_eq!(downloaded, Digest::hash(&content));
        assert_eq!(sink.digest(), Some(downloaded));
        assert_eq!(sink.into_bytes(), content);
    }

    /// Server-side revision admission: once the file moves past the listed
    /// revision, the stale download is refused before a byte streams.
    #[tokio::test]
    async fn a_file_changed_after_listing_refuses_the_stale_revision() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (files, root_id) = text_service(&dir);
        let rig = rig(files, root_id);
        let entry = listed_entry(&rig.client, &rig.root_id).await;
        let stale_revision = entry
            .revision
            .expect("a file entry carries its length:mtime state revision");
        std::fs::write(dir.path().join(FILE_NAME), file_bytes(260, b'A'))
            .expect("the file changes length and mtime");

        let mut sink = MemorySink::new(1 << 20);
        let refusal = rig
            .client
            .download(
                ContentSource::File {
                    root: rig.root_id.clone(),
                    relative: entry.relative_path.clone(),
                    expected_revision: Some(stale_revision),
                },
                &mut sink,
            )
            .await;
        assert!(matches!(
            refusal,
            Err(ClientError::Protocol(HuginnProtocolError::InvalidRequest { code, .. }))
                if code == "invalidScope"
        ));
        assert_eq!(sink.digest(), None);
        assert!(sink.into_bytes().is_empty());
    }
}
