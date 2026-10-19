use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::{SinkExt as _, StreamExt as _};
use odin_domain::huginn::stream::{
    LiveStreamKind, LiveStreamMode, StreamCursor, StreamLifecycle, SubscriptionSet,
};
use odin_domain::huginn::{
    BrowserObservation, BrowserObserveRequest, DeviceId, HuginnMessage, HuginnProtocolError,
    HuginnRequest, HuginnResponse, LiveClientRequest, LiveProtocolError, LiveResponse,
    LiveServerMessage, ObjectKind, ObjectSnapshot, ObjectSubscription, QueryScope, RequestId,
    Revision, Sequence, SnapshotQuery, StreamId,
};
use odin_domain::Digest;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

use crate::private_network::VerifiedTailnetPeer;
use crate::protocol::{decode_frame, encode_frame, ClientFrame, CodecLimits, ServerFrame};

use super::model::{BootstrapInfo, ClientError, DeviceCredential, DeviceCredentialStore};
use super::stream::HuginnStream;
use super::transfer::{DownloadSink, UploadSource, UploadTarget};

const MAX_PENDING_MESSAGES: usize = 1_024;
/// How long a replaced socket gets to be closed by the server.
const RELEASE_BOUND: std::time::Duration = std::time::Duration::from_secs(2);
/// How many frames a replaced socket is read out at most.
const RELEASE_FRAMES: usize = 256;

#[async_trait]
pub trait TransportFrame: Send {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), ClientError>;
    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError>;
    async fn close(&mut self) -> Result<(), ClientError>;
}

#[async_trait]
pub trait HuginnTransport: Clone + Send + Sync + 'static {
    type Socket: TransportFrame + Send + 'static;

    async fn bootstrap(&self, credential: &DeviceCredential) -> Result<BootstrapInfo, ClientError>;

    async fn connect(&self, credential: &DeviceCredential) -> Result<Self::Socket, ClientError>;
}

#[derive(Clone)]
pub struct EndpointTransport {
    endpoint: url::Url,
    http: reqwest::Client,
}

impl std::fmt::Debug for EndpointTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointTransport")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl EndpointTransport {
    pub fn new(endpoint: url::Url) -> Result<Self, ClientError> {
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ClientError::InvalidInput(
                "endpoint must not contain credentials, a query, or a fragment".to_owned(),
            ));
        }
        let loopback_host = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(&['[', ']'][..])
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        let local_http = endpoint.scheme() == "http" && loopback_host;
        if endpoint.scheme() != "https" && !local_http {
            return Err(ClientError::InvalidInput(
                "endpoint must be HTTPS or loopback HTTP".to_owned(),
            ));
        }
        let http = reqwest::Client::builder()
            .https_only(!local_http)
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        Ok(Self { endpoint, http })
    }

    fn url(&self, path: &str) -> Result<url::Url, ClientError> {
        self.endpoint
            .join(path)
            .map_err(|error| ClientError::InvalidInput(error.to_string()))
    }
}

pub type EndpointSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[async_trait]
impl TransportFrame for EndpointSocket {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), ClientError> {
        self.send(Message::Binary(frame.into()))
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))
    }

    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        loop {
            match self.next().await {
                Some(Ok(Message::Binary(frame))) => return Ok(Some(frame.to_vec())),
                Some(Ok(Message::Ping(payload))) => {
                    self.send(Message::Pong(payload))
                        .await
                        .map_err(|error| ClientError::Transport(error.to_string()))?;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Ok(None),
                Some(Ok(Message::Text(_))) => {
                    return Err(ClientError::Transport(
                        "server sent a text frame on the binary protocol".to_owned(),
                    ));
                }
                Some(Ok(Message::Frame(_))) => {}
                Some(Err(error)) => return Err(ClientError::Transport(error.to_string())),
            }
        }
    }

    async fn close(&mut self) -> Result<(), ClientError> {
        self.close(None)
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))
    }
}

#[async_trait]
impl HuginnTransport for EndpointTransport {
    type Socket = EndpointSocket;

    async fn bootstrap(&self, credential: &DeviceCredential) -> Result<BootstrapInfo, ClientError> {
        let response = self
            .http
            .get(self.url("/colinremote/v1/bootstrap")?)
            .bearer_auth(credential.bearer_token())
            .send()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(ClientError::DeviceRevoked);
        }
        let response = response
            .error_for_status()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let info = response
            .json::<BootstrapInfo>()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        info.validate()?;
        Ok(info)
    }

    async fn connect(&self, credential: &DeviceCredential) -> Result<Self::Socket, ClientError> {
        let mut url = self.url("/colinremote/v1/connect")?;
        url.set_scheme(if url.scheme() == "https" { "wss" } else { "ws" })
            .map_err(|_| ClientError::InvalidInput("invalid WebSocket endpoint".to_owned()))?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|error| ClientError::Transport(error.to_string()))?;
        let value = HeaderValue::from_str(&format!("Bearer {}", credential.bearer_token()))
            .map_err(|_| ClientError::InvalidInput("invalid device credential".to_owned()))?;
        request.headers_mut().insert(AUTHORIZATION, value);
        tokio_tungstenite::connect_async(request)
            .await
            .map(|(socket, _)| socket)
            .map_err(|error| match &error {
                tokio_tungstenite::tungstenite::Error::Http(response)
                    if matches!(response.status().as_u16(), 401 | 403) =>
                {
                    ClientError::DeviceRevoked
                }
                tokio_tungstenite::tungstenite::Error::Http(response) => {
                    let reason = response
                        .body()
                        .as_deref()
                        .map(String::from_utf8_lossy)
                        .unwrap_or_default();
                    ClientError::Transport(format!("{error}: {reason}"))
                }
                _ => ClientError::Transport(error.to_string()),
            })
    }
}

#[derive(Clone, Debug)]
pub struct MemoryTransport {
    pending: mpsc::Sender<MemoryServerEnd>,
    buffer: usize,
    peer: VerifiedTailnetPeer,
}

#[derive(Debug)]
pub struct MemoryServerHub {
    pending: mpsc::Receiver<MemoryServerEnd>,
}

#[derive(Debug)]
pub struct MemoryClientEnd {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: mpsc::Receiver<Vec<u8>>,
}

#[derive(Debug)]
pub struct MemoryServerEnd {
    outgoing: mpsc::Sender<Vec<u8>>,
    incoming: mpsc::Receiver<Vec<u8>>,
    device_id: DeviceId,
    peer: VerifiedTailnetPeer,
}

pub fn memory_transport(buffer: usize) -> (MemoryTransport, MemoryServerHub) {
    memory_transport_for_peer(
        buffer,
        VerifiedTailnetPeer::local(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
    )
}

pub fn memory_transport_for_peer(
    buffer: usize,
    peer: VerifiedTailnetPeer,
) -> (MemoryTransport, MemoryServerHub) {
    let buffer = buffer.max(1);
    let (pending, incoming) = mpsc::channel(buffer);
    (
        MemoryTransport {
            pending,
            buffer,
            peer,
        },
        MemoryServerHub { pending: incoming },
    )
}

impl MemoryServerHub {
    pub async fn accept(&mut self) -> Option<MemoryServerEnd> {
        self.pending.recv().await
    }
}

impl MemoryServerEnd {
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn peer(&self) -> &VerifiedTailnetPeer {
        &self.peer
    }
}

#[async_trait]
impl TransportFrame for MemoryClientEnd {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), ClientError> {
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        Ok(self.incoming.recv().await)
    }

    async fn close(&mut self) -> Result<(), ClientError> {
        self.incoming.close();
        Ok(())
    }
}

#[async_trait]
impl TransportFrame for MemoryServerEnd {
    async fn send_frame(&mut self, frame: Vec<u8>) -> Result<(), ClientError> {
        self.outgoing
            .send(frame)
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ClientError> {
        Ok(self.incoming.recv().await)
    }

    async fn close(&mut self) -> Result<(), ClientError> {
        self.incoming.close();
        Ok(())
    }
}

#[async_trait]
impl HuginnTransport for MemoryTransport {
    type Socket = MemoryClientEnd;

    async fn bootstrap(
        &self,
        _credential: &DeviceCredential,
    ) -> Result<BootstrapInfo, ClientError> {
        Ok(BootstrapInfo::local(CodecLimits::default().max_frame_bytes))
    }

    async fn connect(&self, credential: &DeviceCredential) -> Result<Self::Socket, ClientError> {
        let (client_outgoing, server_incoming) = mpsc::channel(self.buffer);
        let (server_outgoing, client_incoming) = mpsc::channel(self.buffer);
        self.pending
            .send(MemoryServerEnd {
                outgoing: server_outgoing,
                incoming: server_incoming,
                device_id: credential.device_id()?,
                peer: self.peer.clone(),
            })
            .await
            .map_err(|_| ClientError::ConnectionClosed)?;
        Ok(MemoryClientEnd {
            outgoing: client_outgoing,
            incoming: client_incoming,
        })
    }
}

pub struct ColinRemoteClient<T, K> {
    transport: T,
    credentials: Arc<K>,
    limits: CodecLimits,
}

impl<T, K> ColinRemoteClient<T, K>
where
    T: HuginnTransport,
    K: DeviceCredentialStore,
{
    pub fn new(transport: T, credentials: K) -> Self {
        Self::with_limits(transport, credentials, CodecLimits::default())
    }

    pub fn with_limits(transport: T, credentials: K, limits: CodecLimits) -> Self {
        Self {
            transport,
            credentials: Arc::new(credentials),
            limits,
        }
    }

    pub async fn bootstrap(&self) -> Result<BootstrapInfo, ClientError> {
        let credential = self.credential()?;
        let result = self.transport.bootstrap(&credential).await;
        self.handle_revocation(result)
    }

    pub async fn connect(&self) -> Result<LiveConnection<T::Socket, T>, ClientError> {
        let credential = self.credential()?;
        let bootstrap = self.handle_revocation(self.transport.bootstrap(&credential).await)?;
        bootstrap.validate()?;
        let socket = self.handle_revocation(self.transport.connect(&credential).await)?;
        let mut limits = self.limits;
        limits.max_frame_bytes = limits.max_frame_bytes.min(bootstrap.max_frame_bytes);
        let credential_store: Arc<dyn DeviceCredentialStore> = self.credentials.clone();
        Ok(LiveConnection::new(
            socket,
            self.transport.clone(),
            credential,
            credential_store,
            limits,
        ))
    }

    pub async fn request(&self, request: HuginnRequest) -> Result<HuginnResponse, ClientError> {
        let mut connection = self.connect().await?;
        let result = connection.request(request).await;
        let close_result = connection.close().await;
        let final_result = match result {
            Ok(response) => close_result.map(|()| response),
            Err(error) => Err(error),
        };
        self.handle_revocation(final_result)
    }

    /// Performs one bounded browser.observe call through the authenticated
    /// shared protocol and rebinds the typed payload to its canonical digest.
    pub async fn browser_observe(
        &self,
        request: BrowserObserveRequest,
    ) -> Result<BrowserObservation, ClientError> {
        request
            .validate()
            .map_err(|reason| ClientError::InvalidInput(reason.to_owned()))?;
        let expected_session = request.session_id;
        let expected_kind = request.kind;
        let response = self.request(HuginnRequest::BrowserObserve(request)).await?;
        let HuginnResponse::BrowserObservation(observation) = response else {
            return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "unexpectedResponse".to_owned(),
                message: "browser observe did not return BrowserObservation".to_owned(),
            }));
        };
        let payload = serde_json::to_vec(&observation.payload).map_err(|_| {
            ClientError::Protocol(HuginnProtocolError::Unavailable {
                code: "browserObservationEncoding".to_owned(),
            })
        })?;
        if observation.session_id != expected_session
            || observation.kind != expected_kind
            || observation.payload_digest != Digest::hash(&payload)
        {
            return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "browserObservationBinding".to_owned(),
                message: "browser observation identity or digest did not match".to_owned(),
            }));
        }
        Ok(observation)
    }

    pub async fn subscribe(
        &self,
        set: SubscriptionSet,
    ) -> Result<HuginnStream<T::Socket, T>, ClientError> {
        let mut connection = self.connect().await?;
        self.handle_revocation(connection.subscribe(set).await)?;
        Ok(HuginnStream::new(connection))
    }

    pub async fn request_stream(
        &self,
        request: HuginnRequest,
    ) -> Result<(HuginnResponse, HuginnStream<T::Socket, T>), ClientError> {
        if !matches!(
            &request,
            HuginnRequest::WatchFiles(_) | HuginnRequest::WatchRender(_)
        ) {
            return Err(ClientError::InvalidInput(
                "request does not start a dedicated protocol stream".to_owned(),
            ));
        }
        let reconnect_request = request.clone();
        let mut connection = self.connect().await?;
        let response = connection.request(request).await?;
        if !matches!(&response, HuginnResponse::Subscribed | HuginnResponse::Ack) {
            return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "unexpectedResponse".to_owned(),
                message: "stream request did not return Subscribed or Ack".to_owned(),
            }));
        }
        Ok((
            response,
            HuginnStream::new_request(connection, reconnect_request),
        ))
    }

    pub async fn upload(
        &self,
        source: UploadSource,
        target: UploadTarget,
    ) -> Result<odin_domain::huginn::ArtifactRef, ClientError> {
        let result = super::transfer::upload(self, source, target).await;
        self.handle_revocation(result)
    }

    pub async fn download(
        &self,
        source: odin_domain::huginn::ContentSource,
        sink: &mut dyn DownloadSink,
    ) -> Result<odin_domain::Digest, ClientError> {
        let result = super::transfer::download(self, source, sink).await;
        self.handle_revocation(result)
    }

    pub(crate) fn limits(&self) -> CodecLimits {
        self.limits
    }

    pub(crate) fn device_id(&self) -> Result<DeviceId, ClientError> {
        self.credential()?.device_id()
    }

    fn credential(&self) -> Result<DeviceCredential, ClientError> {
        self.credentials
            .load()?
            .ok_or(ClientError::CredentialUnavailable)
    }

    fn handle_revocation<R>(&self, result: Result<R, ClientError>) -> Result<R, ClientError> {
        match result {
            Err(ClientError::DeviceRevoked) => {
                self.credentials.clear()?;
                Err(ClientError::DeviceRevoked)
            }
            other => other,
        }
    }
}
/// How many snapshot pages one object resync walks before giving up:
/// a bounded recovery, not an unbounded mirror.
const RESYNC_PAGE_BOUND: usize = 256;

/// The client side of the object subscription: which kinds and scope were
/// subscribed, the checkpoint the server last confirmed (`adopted`), and
/// a delivered batch's checkpoint awaiting the consumer's explicit ack.
/// Arrival alone adopts nothing: `to_revision` becomes the resume point
/// only after the consumer applied the batch and acked it.
#[derive(Clone, Debug)]
struct ObjectTrack {
    kinds: Vec<ObjectKind>,
    scope: QueryScope,
    adopted: Option<Revision>,
    pending: Option<Revision>,
}

impl ObjectTrack {
    fn new(kinds: Vec<ObjectKind>, scope: QueryScope, after: Revision) -> Self {
        Self {
            kinds,
            scope,
            adopted: Some(after),
            pending: None,
        }
    }

    fn receive(&mut self, checkpoint: Revision) {
        self.pending = Some(checkpoint);
    }
}

pub struct LiveConnection<S, T>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    socket: S,
    transport: T,
    credential: DeviceCredential,
    credential_store: Arc<dyn DeviceCredentialStore>,
    limits: CodecLimits,
    subscriptions: Option<SubscriptionSet>,
    cursors: BTreeMap<StreamId, StreamCursor>,
    pending: VecDeque<HuginnMessage>,
    pending_live: VecDeque<LiveServerMessage>,
    objects: Option<ObjectTrack>,
}

impl<S, T> LiveConnection<S, T>
where
    S: TransportFrame,
    T: HuginnTransport<Socket = S>,
{
    fn new(
        socket: S,
        transport: T,
        credential: DeviceCredential,
        credential_store: Arc<dyn DeviceCredentialStore>,
        limits: CodecLimits,
    ) -> Self {
        Self {
            socket,
            transport,
            credential,
            credential_store,
            limits,
            subscriptions: None,
            cursors: BTreeMap::new(),
            pending: VecDeque::new(),
            pending_live: VecDeque::new(),
            objects: None,
        }
    }

    pub async fn close(&mut self) -> Result<(), ClientError> {
        self.socket.close().await
    }

    pub async fn next(&mut self) -> Option<Result<HuginnMessage, ClientError>> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                if self.prepare_delivery(&message) {
                    return Some(Ok(message));
                }
                continue;
            }
            let frame = match self.read_server().await {
                Ok(Some(frame)) => frame,
                Ok(None) => return None,
                Err(error) => return Some(Err(error)),
            };
            match frame {
                ServerFrame::General(message) => match self.general_message(message) {
                    Ok(Some(message)) if self.prepare_delivery(&message) => {
                        return Some(Ok(message));
                    }
                    Ok(_) => {}
                    Err(error) => return Some(Err(error)),
                },
                ServerFrame::Live(message) => {
                    if let Err(error) = self.check_live_error(&message) {
                        return Some(Err(error));
                    }
                    if let Err(error) = self.enqueue_live(message) {
                        return Some(Err(error));
                    }
                }
            }
        }
    }

    pub async fn request(&mut self, request: HuginnRequest) -> Result<HuginnResponse, ClientError> {
        let mut subscription = match &request {
            HuginnRequest::Subscribe(set) => Some(set.clone()),
            _ => None,
        };
        if let Some(set) = subscription.as_ref() {
            self.validate_subscription_set(set)?;
        }
        self.send_client(ClientFrame::General(request)).await?;
        loop {
            let Some(frame) = self.read_server().await? else {
                return Err(ClientError::ConnectionClosed);
            };
            match frame {
                ServerFrame::General(HuginnMessage::Response { result, .. }) => {
                    if matches!(result, HuginnResponse::Subscribed) {
                        if let Some(set) = subscription.take() {
                            self.install_subscriptions(set);
                        }
                    }
                    return Ok(result);
                }
                ServerFrame::General(message) => {
                    if let Some(message) = self.general_message(message)? {
                        self.enqueue_general(message)?;
                    }
                }
                ServerFrame::Live(message) => {
                    self.check_live_error(&message)?;
                    self.enqueue_live(message)?;
                }
            }
        }
    }

    pub async fn subscribe(&mut self, set: SubscriptionSet) -> Result<(), ClientError> {
        self.validate_subscription_set(&set)?;
        match self.request(HuginnRequest::Subscribe(set)).await? {
            HuginnResponse::Subscribed => Ok(()),
            _ => Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "unexpectedResponse".to_owned(),
                message: "subscribe did not return Subscribed".to_owned(),
            })),
        }
    }

    pub async fn reconnect(&mut self, cursors: Vec<StreamCursor>) -> Result<(), ClientError> {
        let mut set = self.subscriptions.clone().ok_or(ClientError::InvalidInput(
            "connection has no subscription to reconnect".to_owned(),
        ))?;
        if cursors.len() > set.subscriptions.len()
            || cursors.iter().enumerate().any(|(index, cursor)| {
                cursors[index + 1..]
                    .iter()
                    .any(|other| other.stream_id() == cursor.stream_id())
            })
        {
            return Err(ClientError::InvalidInput(
                "reconnect cursors are duplicated or exceed the subscription set".to_owned(),
            ));
        }
        for cursor in cursors {
            let subscription = set
                .subscriptions
                .iter_mut()
                .find(|subscription| subscription.cursor.stream_id() == cursor.stream_id())
                .ok_or_else(|| {
                    ClientError::InvalidInput(
                        "reconnect cursor is not part of the subscription set".to_owned(),
                    )
                })?;
            if subscription.cursor.mode() != cursor.mode() {
                return Err(ClientError::InvalidInput(
                    "reconnect cursor mode differs from its subscription".to_owned(),
                ));
            }
            subscription.cursor = cursor;
        }

        self.reopen().await?;
        self.subscribe(set).await
    }

    pub(crate) async fn reconnect_request(
        &mut self,
        request: HuginnRequest,
    ) -> Result<HuginnResponse, ClientError> {
        self.reopen().await?;
        self.request(request).await
    }

    async fn reopen(&mut self) -> Result<(), ClientError> {
        self.release_socket().await;
        let bootstrap = self
            .transport
            .bootstrap(&self.credential)
            .await
            .map_err(|error| self.revoke_if_needed(error))?;
        bootstrap.validate()?;
        let socket = self
            .transport
            .connect(&self.credential)
            .await
            .map_err(|error| self.revoke_if_needed(error))?;
        self.limits.max_frame_bytes = self.limits.max_frame_bytes.min(bootstrap.max_frame_bytes);
        self.socket = socket;
        self.pending.clear();
        self.pending_live.clear();
        // Object checkpoints resume only on the connection that handed
        // them out — the server behind the new one may be another daemon
        // whose revisions collide — so the subscription resyncs from a
        // fresh snapshot ([`Self::resync_objects`]).
        if let Some(track) = self.objects.as_mut() {
            track.adopted = None;
            track.pending = None;
        }
        Ok(())
    }

    /// Closes the abandoned socket and reads it out until the server ends
    /// it (bounded): under a connection cap its slot is the one the
    /// replacement needs.
    async fn release_socket(&mut self) {
        let socket = &mut self.socket;
        let _ = tokio::time::timeout(RELEASE_BOUND, async {
            if socket.close().await.is_err() {
                return;
            }
            for _ in 0..RELEASE_FRAMES {
                if !matches!(socket.next_frame().await, Ok(Some(_))) {
                    return;
                }
            }
        })
        .await;
    }

    pub fn cursors(&self) -> Vec<StreamCursor> {
        self.cursors.values().cloned().collect()
    }

    pub fn subscriptions(&self) -> Option<&SubscriptionSet> {
        self.subscriptions.as_ref()
    }

    /// The object subscription's adopted checkpoint on this connection:
    /// what a resubscribe resumes from, and what a resync replaces. `None`
    /// before the first subscribe and after a reconnect, whose new
    /// connection resumes nothing it did not hand out itself.
    pub fn object_checkpoint(&self) -> Option<Revision> {
        self.objects.as_ref().and_then(|track| track.adopted)
    }

    /// Subscribes (or re-subscribes) to object deltas of `kinds` in
    /// `scope`, resuming after `after`: the revision of a complete snapshot
    /// of this kind set and scope (stale objects included) whose every page
    /// this connection fetched, or a checkpoint this connection delivered.
    /// Batches arrive as `HuginnMessage::ObjectDeltaBatch`; any other point
    /// — one the server no longer retains, or one from an earlier
    /// connection or daemon — fails typed `Protocol(CursorExpired)`: take a
    /// fresh snapshot ([`Self::resync_objects`]) instead of resuming the
    /// gap. On `Subscribed`, batches still queued from the subscription it
    /// replaces are dropped: the server pushes the new one's pages only
    /// after its answer.
    pub async fn subscribe_objects(
        &mut self,
        kinds: Vec<ObjectKind>,
        scope: QueryScope,
        after: Revision,
    ) -> Result<(), ClientError> {
        match self
            .request(HuginnRequest::SubscribeObjects(ObjectSubscription {
                kinds: kinds.clone(),
                scope: scope.clone(),
                after,
            }))
            .await?
        {
            HuginnResponse::Subscribed => {
                self.pending
                    .retain(|message| !matches!(message, HuginnMessage::ObjectDeltaBatch(_)));
                self.objects = Some(ObjectTrack::new(kinds, scope, after));
                Ok(())
            }
            _ => Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "unexpectedResponse".to_owned(),
                message: "subscribe objects did not return Subscribed".to_owned(),
            })),
        }
    }

    /// Acknowledges the last delivered batch at its checkpoint — the
    /// credit that frees the server's one unacked page. The consumer
    /// applies the batch first: nothing is adopted on arrival. While the
    /// server has not finished writing the batch it refuses typed
    /// `objectAckPending` (the pending checkpoint is restored here); the
    /// retry succeeds once the batch is on the wire.
    pub async fn ack_objects(&mut self) -> Result<(), ClientError> {
        let Some(track) = self.objects.as_mut() else {
            return Err(ClientError::InvalidInput(
                "connection has no object subscription".to_owned(),
            ));
        };
        let Some(checkpoint) = track.pending.take() else {
            return Err(ClientError::InvalidInput(
                "no delivered object batch to acknowledge".to_owned(),
            ));
        };
        let request = HuginnRequest::SubscribeObjects(ObjectSubscription {
            kinds: track.kinds.clone(),
            scope: track.scope.clone(),
            after: checkpoint,
        });
        match self.request(request).await {
            Ok(HuginnResponse::Subscribed) => {
                self.objects
                    .as_mut()
                    .expect("track held at the top of this method")
                    .adopted = Some(checkpoint);
                Ok(())
            }
            Ok(_) => Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                code: "unexpectedResponse".to_owned(),
                message: "object ack did not return Subscribed".to_owned(),
            })),
            Err(error) => {
                self.objects
                    .as_mut()
                    .expect("track held at the top of this method")
                    .pending = Some(checkpoint);
                Err(error)
            }
        }
    }

    /// Re-establishes the object subscription after a cursor expiry or a
    /// reconnect: a fresh paged snapshot of the subscribed kinds and
    /// scope, every page on this connection — never a resume that treats
    /// the gap as empty — then a subscribe at that snapshot's revision.
    /// Returns the state to load and the revision it reflects; batches of
    /// the replaced subscription that arrived meanwhile are dropped, so
    /// none is ever applied on top of the fresh state.
    ///
    /// The server refuses the subscribe `objectAckPending` while a frame it
    /// depends on — the replaced subscription's outstanding batch, or this
    /// snapshot's last page — is still being written. That refusal is
    /// queued behind the frame, so its arrival proves the frame is on the
    /// wire. One repeat may then succeed; an active old subscription can
    /// still race it with a fresh batch, which remains a typed refusal.
    pub async fn resync_objects(&mut self) -> Result<(Vec<ObjectSnapshot>, Revision), ClientError> {
        let Some(track) = self.objects.clone() else {
            return Err(ClientError::InvalidInput(
                "connection has no object subscription to resync".to_owned(),
            ));
        };
        let mut cursor = None;
        let mut objects = Vec::new();
        let mut revision = Revision::new(0);
        for _ in 0..RESYNC_PAGE_BOUND {
            let page = match self
                .request(HuginnRequest::Snapshot(SnapshotQuery {
                    scope: track.scope.clone(),
                    kinds: track.kinds.clone(),
                    if_revision: None,
                    cursor: cursor.clone(),
                    limit: NonZeroU16::new(256).expect("nonzero"),
                    include_stale: true,
                }))
                .await?
            {
                HuginnResponse::Snapshot(page) => page,
                _ => {
                    return Err(ClientError::Protocol(HuginnProtocolError::Conflict {
                        code: "unexpectedResponse".to_owned(),
                        message: "snapshot did not return Snapshot".to_owned(),
                    }))
                }
            };
            revision = page.revision;
            cursor = page.next_cursor;
            let done = cursor.is_none();
            objects.extend(page.objects);
            if done {
                break;
            }
        }
        if cursor.is_some() {
            return Err(ClientError::Limit(
                "snapshot pages in one resync".to_owned(),
            ));
        }
        match self
            .subscribe_objects(track.kinds.clone(), track.scope.clone(), revision)
            .await
        {
            Err(ClientError::Protocol(HuginnProtocolError::Conflict { code, .. }))
                if code == "objectAckPending" =>
            {
                self.subscribe_objects(track.kinds.clone(), track.scope.clone(), revision)
                    .await?;
            }
            subscribed => subscribed?,
        }
        Ok((objects, revision))
    }

    pub async fn request_live(
        &mut self,
        request: LiveClientRequest,
    ) -> Result<LiveResponse, ClientError> {
        let request_id = live_request_id(&request).ok_or_else(|| {
            ClientError::InvalidInput("live request does not carry a request ID".to_owned())
        })?;
        self.send_client(ClientFrame::Live(request)).await?;
        loop {
            let Some(frame) = self.read_server().await? else {
                return Err(ClientError::ConnectionClosed);
            };
            match frame {
                ServerFrame::Live(LiveServerMessage::Response {
                    request_id: response_id,
                    result,
                }) if response_id == request_id => return Ok(result),
                ServerFrame::Live(message) => {
                    self.check_live_error(&message)?;
                    self.enqueue_live(message)?;
                }
                ServerFrame::General(message) => {
                    if let Some(message) = self.general_message(message)? {
                        self.enqueue_general(message)?;
                    }
                }
            }
        }
    }

    pub async fn send_live(&mut self, request: LiveClientRequest) -> Result<(), ClientError> {
        self.send_client(ClientFrame::Live(request)).await
    }

    pub async fn next_live(&mut self) -> Option<Result<LiveServerMessage, ClientError>> {
        loop {
            if let Some(message) = self.pending_live.pop_front() {
                return Some(self.check_live_error(&message).map(|()| message));
            }
            let frame = match self.read_server().await {
                Ok(Some(frame)) => frame,
                Ok(None) => return None,
                Err(error) => return Some(Err(error)),
            };
            match frame {
                ServerFrame::Live(message) => {
                    return Some(self.check_live_error(&message).map(|()| message));
                }
                ServerFrame::General(message) => match self.general_message(message) {
                    Ok(Some(message)) => {
                        if let Err(error) = self.enqueue_general(message) {
                            return Some(Err(error));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => return Some(Err(error)),
                },
            }
        }
    }

    async fn send_client(&mut self, frame: ClientFrame) -> Result<(), ClientError> {
        self.socket
            .send_frame(encode_frame(&frame, &self.limits)?)
            .await
    }

    async fn read_server(&mut self) -> Result<Option<ServerFrame>, ClientError> {
        let Some(frame) = self.socket.next_frame().await? else {
            return Ok(None);
        };
        Ok(Some(
            decode_frame::<ServerFrame>(&frame, &self.limits)?.value,
        ))
    }

    fn validate_subscription_set(&self, set: &SubscriptionSet) -> Result<(), ClientError> {
        if !set.is_valid() {
            return Err(ClientError::InvalidInput(
                "invalid subscription set".to_owned(),
            ));
        }
        if set.subscriptions.len() > self.limits.max_container_items {
            return Err(ClientError::Limit("subscription cursors".to_owned()));
        }
        Ok(())
    }

    fn install_subscriptions(&mut self, set: SubscriptionSet) {
        self.cursors.clear();
        for subscription in &set.subscriptions {
            self.cursors.insert(
                *subscription.cursor.stream_id(),
                subscription.cursor.clone(),
            );
        }
        self.subscriptions = Some(set);
    }

    fn general_message(
        &self,
        message: HuginnMessage,
    ) -> Result<Option<HuginnMessage>, ClientError> {
        // A general request refusal does not revoke the device or clear its credential.
        match message {
            HuginnMessage::ProtocolError(error) => Err(ClientError::Protocol(error)),
            message => Ok(Some(message)),
        }
    }

    fn check_live_error(&self, message: &LiveServerMessage) -> Result<(), ClientError> {
        match message {
            LiveServerMessage::DeviceRevoked
            | LiveServerMessage::ProtocolError(
                LiveProtocolError::Unauthenticated
                | LiveProtocolError::Unauthorized
                | LiveProtocolError::DeviceRevoked,
            ) => Err(self.revoked_error()),
            LiveServerMessage::ProtocolError(error) => {
                Err(ClientError::LiveProtocol(error.clone()))
            }
            _ => Ok(()),
        }
    }

    fn revoke_if_needed(&self, error: ClientError) -> ClientError {
        if error == ClientError::DeviceRevoked {
            self.revoked_error()
        } else {
            error
        }
    }

    fn revoked_error(&self) -> ClientError {
        match self.credential_store.clear() {
            Ok(()) => ClientError::DeviceRevoked,
            Err(error) => error,
        }
    }

    fn enqueue_general(&mut self, message: HuginnMessage) -> Result<(), ClientError> {
        if self.pending.len() >= self.pending_limit() {
            return Err(ClientError::Limit(
                "pending general-message queue".to_owned(),
            ));
        }
        self.pending.push_back(message);
        Ok(())
    }

    fn enqueue_live(&mut self, message: LiveServerMessage) -> Result<(), ClientError> {
        if self.pending_live.len() >= self.pending_limit() {
            return Err(ClientError::Limit("pending live-message queue".to_owned()));
        }
        self.pending_live.push_back(message);
        Ok(())
    }

    fn pending_limit(&self) -> usize {
        MAX_PENDING_MESSAGES.min(self.limits.max_container_items.max(1))
    }

    fn prepare_delivery(&mut self, message: &HuginnMessage) -> bool {
        match message {
            HuginnMessage::ReplayBegin { .. } => true,
            HuginnMessage::ReplayComplete { stream, head } => {
                self.advance_cursor(*stream, *head);
                true
            }
            HuginnMessage::Event(event) => self.advance_kind_cursor(
                LiveStreamKind::AgentEvents,
                Sequence::new(event.sequence.get()),
            ),
            HuginnMessage::TerminalReset(snapshot) => self.advance_kind_cursor(
                LiveStreamKind::Terminal,
                Sequence::new(snapshot.sequence.get()),
            ),
            HuginnMessage::BinaryChunk(chunk) => {
                self.advance_cursor(chunk.stream_id, chunk.sequence)
            }
            // A durable item carried as a live status (kube events): its
            // last_delivered is the item's sequence.
            HuginnMessage::StreamStatus(status)
                if status.mode == LiveStreamMode::Durable
                    && status.lifecycle == StreamLifecycle::Live =>
            {
                status
                    .last_delivered
                    .is_none_or(|sequence| self.advance_cursor(status.stream_id, sequence))
            }
            // A pushed batch is recorded, not adopted: the consumer acks
            // at its checkpoint after applying it.
            HuginnMessage::ObjectDeltaBatch(batch) => {
                if let Some(track) = self.objects.as_mut() {
                    track.receive(batch.to_revision);
                }
                true
            }
            _ => true,
        }
    }

    fn advance_kind_cursor(&mut self, kind: LiveStreamKind, sequence: Sequence) -> bool {
        let stream_id = self.subscriptions.as_ref().and_then(|set| {
            let mut matching = set
                .subscriptions
                .iter()
                .filter(|subscription| subscription.kind == kind)
                .map(|subscription| *subscription.cursor.stream_id());
            let first = matching.next()?;
            matching.next().is_none().then_some(first)
        });
        stream_id.is_none_or(|stream_id| self.advance_cursor(stream_id, sequence))
    }

    fn advance_cursor(&mut self, stream_id: StreamId, sequence: Sequence) -> bool {
        let Some(StreamCursor::Durable { after, .. }) = self.cursors.get_mut(&stream_id) else {
            return true;
        };
        if after.is_some_and(|delivered| sequence <= delivered) {
            return false;
        }
        *after = Some(sequence);
        true
    }
}

fn live_request_id(request: &LiveClientRequest) -> Option<RequestId> {
    match request {
        LiveClientRequest::GetRoster { request_id, .. }
        | LiveClientRequest::ListSessions { request_id, .. }
        | LiveClientRequest::GetHistory { request_id, .. }
        | LiveClientRequest::Subscribe { request_id, .. }
        | LiveClientRequest::Unsubscribe { request_id, .. }
        | LiveClientRequest::OpenSession { request_id, .. }
        | LiveClientRequest::Control { request_id, .. }
        | LiveClientRequest::BeginUpload { request_id, .. }
        | LiveClientRequest::CommitUpload { request_id, .. }
        | LiveClientRequest::CancelTransfer { request_id, .. }
        | LiveClientRequest::FetchArtifact { request_id, .. }
        | LiveClientRequest::BrowseFiles { request_id, .. }
        | LiveClientRequest::ReadFile { request_id, .. }
        | LiveClientRequest::WatchFiles { request_id, .. }
        | LiveClientRequest::RequestRender { request_id, .. }
        | LiveClientRequest::RenderStatus { request_id, .. }
        | LiveClientRequest::WatchRender { request_id, .. }
        | LiveClientRequest::IssueContentTicket { request_id, .. }
        | LiveClientRequest::AcquireTerminalControl { request_id, .. }
        | LiveClientRequest::WriteTerminal { request_id, .. }
        | LiveClientRequest::ResizeTerminal { request_id, .. }
        | LiveClientRequest::BindTerminalTarget { request_id, .. }
        | LiveClientRequest::UnbindTerminalTarget { request_id, .. }
        | LiveClientRequest::GetTerminalTarget { request_id, .. }
        | LiveClientRequest::ReleaseTerminalControl { request_id, .. } => Some(*request_id),
        LiveClientRequest::UploadChunk { .. } | LiveClientRequest::GrantDownloadCredit { .. } => {
            None
        }
    }
}

#[cfg(test)]
mod tests;
