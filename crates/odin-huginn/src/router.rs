use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{
    connect_info::ConnectInfo, ws::WebSocketUpgrade, DefaultBodyLimit, Path, Request, State,
};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE,
    PRAGMA, RANGE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use odin_domain::huginn::{
    DeviceId, FileGateway, HuginnReadModel, HuginnStreamSource, OmpLivePlane, RenderGateway,
    VerifiedOwnerDevice,
};
use odin_domain::Digest;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::{AuthError, SecretBytes, TailnetAuthenticator};
use crate::client::BootstrapInfo;
use crate::config::HuginnLimits;
use crate::devices::DeviceTrustStore;
use crate::dispatch::{
    AuthenticatedCommandPort, LiveDispatcher, LiveDispatcherLimits, LiveDispatcherRuntime,
    LiveGateways,
};
use crate::private_network::{is_tailnet_address, TailnetVerifier, VerifiedTailnetPeer};
use crate::state::HuginnLiveState;

const CONTENT_DIGEST: HeaderName = HeaderName::from_static("x-content-blake3");
const TAILSCALE_USER_LOGIN: HeaderName = HeaderName::from_static("tailscale-user-login");
const TAILSCALE_USER_NAME: HeaderName = HeaderName::from_static("tailscale-user-name");
const TAILSCALE_USER_PROFILE_PIC: HeaderName =
    HeaderName::from_static("tailscale-user-profile-pic");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const TAILSCALE_FUNNEL_REQUEST: HeaderName = HeaderName::from_static("tailscale-funnel-request");

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ContentTicketId(String);

impl ContentTicketId {
    pub fn parse(value: &str) -> Result<Self, ContentTicketError> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ContentTicketError::InvalidTicket);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContentTicketId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone)]
pub struct ContentTicketStore {
    inner: Arc<Mutex<TicketState>>,
    capacity: usize,
    max_bytes: u64,
    ttl: Duration,
}

#[derive(Default)]
struct TicketState {
    tickets: HashMap<ContentTicketId, ContentTicket>,
}

struct ContentTicket {
    device_id: DeviceId,
    media_type: String,
    digest: Digest,
    bytes: Bytes,
    expires_at: Instant,
}

#[derive(Debug, Error)]
pub enum ContentTicketError {
    #[error("content ticket is invalid")]
    InvalidTicket,
    #[error("content ticket was not found or expired")]
    NotFound,
    #[error("content ticket belongs to another device")]
    Unauthorized,
    #[error("content length exceeds the configured limit")]
    TooLarge,
    #[error("content media type is invalid")]
    InvalidMediaType,
    #[error("content ticket capacity is exhausted")]
    Capacity,
    #[error("content ticket store lock: {0}")]
    Poisoned(String),
}

#[derive(Clone)]
struct DownloadContent {
    media_type: String,
    digest: Digest,
    bytes: Bytes,
}

impl ContentTicketStore {
    pub fn new(capacity: usize, max_bytes: u64, ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TicketState::default())),
            capacity,
            max_bytes,
            ttl,
        }
    }

    pub fn issue_download(
        &self,
        device_id: DeviceId,
        media_type: impl Into<String>,
        bytes: impl Into<Bytes>,
    ) -> Result<ContentTicketId, ContentTicketError> {
        let media_type = valid_media_type(media_type.into())?;
        let bytes = bytes.into();
        if bytes.len() as u64 > self.max_bytes {
            return Err(ContentTicketError::TooLarge);
        }
        let digest = Digest::hash(&bytes);
        self.insert(ContentTicket {
            device_id,
            media_type,
            digest,
            bytes,
            expires_at: Instant::now() + self.ttl,
        })
    }

    fn insert(&self, ticket: ContentTicket) -> Result<ContentTicketId, ContentTicketError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|error| ContentTicketError::Poisoned(error.to_string()))?;
        purge_expired(&mut state);
        if state.tickets.len() >= self.capacity {
            return Err(ContentTicketError::Capacity);
        }
        loop {
            let mut random = [0_u8; 32];
            random[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            random[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            let id = ContentTicketId(URL_SAFE_NO_PAD.encode(random));
            random.fill(0);
            if !state.tickets.contains_key(&id) {
                state.tickets.insert(id.clone(), ticket);
                return Ok(id);
            }
        }
    }

    fn download(
        &self,
        ticket: &ContentTicketId,
        device_id: DeviceId,
    ) -> Result<DownloadContent, ContentTicketError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|error| ContentTicketError::Poisoned(error.to_string()))?;
        purge_expired(&mut state);
        match state.tickets.get(ticket) {
            Some(held) if held.device_id == device_id => Ok(DownloadContent {
                media_type: held.media_type.clone(),
                digest: held.digest,
                bytes: held.bytes.clone(),
            }),
            Some(_) => Err(ContentTicketError::Unauthorized),
            None => Err(ContentTicketError::NotFound),
        }
    }
}

fn purge_expired(state: &mut TicketState) {
    let now = Instant::now();
    state.tickets.retain(|_, ticket| ticket.expires_at > now);
}

fn valid_media_type(media_type: String) -> Result<String, ContentTicketError> {
    if media_type.is_empty()
        || media_type.len() > 128
        || media_type.chars().any(char::is_control)
        || HeaderValue::from_str(&media_type).is_err()
    {
        Err(ContentTicketError::InvalidMediaType)
    } else {
        Ok(media_type)
    }
}

struct RouterState<R, C, S, F, V, D, T> {
    live: Arc<HuginnLiveState<R, C, S, F, V, D, T>>,
    dispatcher: LiveDispatcher<R, C, S>,
    tickets: ContentTicketStore,
    max_frame_bytes: usize,
    max_connections: usize,
}

type SharedRouterState<R, C, S, F, V, D, T> = Arc<RouterState<R, C, S, F, V, D, T>>;

pub fn live_router_with_runtime<R, C, S, F, V, D, T>(
    state: HuginnLiveState<R, C, S, F, V, D, T>,
    limits: &HuginnLimits,
    tickets: ContentTicketStore,
) -> Router
where
    R: HuginnReadModel + Send + Sync + 'static,
    C: AuthenticatedCommandPort + OmpLivePlane + Send + Sync + 'static,
    S: HuginnStreamSource + Send + Sync + 'static,
    F: FileGateway + 'static,
    V: RenderGateway + 'static,
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    let posture = state.posture;
    let dispatcher = LiveDispatcher::with_posture_limits(
        state.read_model.clone(),
        state.commands.clone(),
        state.streams.clone(),
        state.guard.clone(),
        state.tickets.clone(),
        LiveDispatcherRuntime {
            gateways: LiveGateways::new(state.files.clone(), state.renders.clone()),
            limits: LiveDispatcherLimits::from_declared(limits),
            posture,
        },
    );
    let max_frame_bytes = limits.connections.max_frame_bytes.get();
    let max_body_bytes =
        usize::try_from(limits.transfers.max_transfer_bytes.get()).unwrap_or(usize::MAX);
    let state = Arc::new(RouterState {
        live: Arc::new(state),
        dispatcher,
        tickets,
        max_frame_bytes,
        max_connections: limits.connections.max_connections.get(),
    });
    Router::new()
        .route(
            "/colinremote/v1/bootstrap",
            get(bootstrap::<R, C, S, F, V, D, T>),
        )
        .route(
            "/colinremote/v1/connect",
            get(connect::<R, C, S, F, V, D, T>),
        )
        .route(
            "/colinremote/v1/content/{ticket}",
            get(get_content::<R, C, S, F, V, D, T>),
        )
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(private_headers))
        .with_state(state)
}

async fn bootstrap<R, C, S, F, V, D, T>(
    State(state): State<SharedRouterState<R, C, S, F, V, D, T>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response
where
    R: Send + Sync + 'static,
    C: Send + Sync + 'static,
    S: Send + Sync + 'static,
    F: Send + Sync + 'static,
    V: Send + Sync + 'static,
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    if let Err(response) = authenticate(&state, peer, &headers).await {
        return response;
    }
    Json(BootstrapInfo::local(state.max_frame_bytes)).into_response()
}

async fn connect<R, C, S, F, V, D, T>(
    State(state): State<SharedRouterState<R, C, S, F, V, D, T>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response
where
    R: HuginnReadModel + Send + Sync + 'static,
    C: AuthenticatedCommandPort + OmpLivePlane + Send + Sync + 'static,
    S: HuginnStreamSource + Send + Sync + 'static,
    F: Send + Sync + 'static,
    V: Send + Sync + 'static,
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    let device = match authenticate(&state, peer, &headers).await {
        Ok(device) => device,
        Err(response) => return response,
    };
    let registration = match state
        .live
        .devices
        .register_connection(&device, &state.live.connections, state.max_connections)
        .await
    {
        Ok(registration) => registration,
        Err(error) => {
            tracing::error!(
                device = %device.device_id,
                error = %error,
                "huginn connection_refused"
            );
            let status = match error {
                AuthError::DeviceRevoked | AuthError::DeviceRevocationPending => {
                    StatusCode::FORBIDDEN
                }
                AuthError::UnknownDevice(_) => StatusCode::UNAUTHORIZED,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            return (status, error.to_string()).into_response();
        }
    };
    let dispatcher = state.dispatcher.clone();
    upgrade
        .max_frame_size(state.max_frame_bytes)
        .max_message_size(state.max_frame_bytes)
        .on_upgrade(move |socket| async move {
            let _ = dispatcher
                .serve_connection(socket, device, registration)
                .await;
        })
}

async fn get_content<R, C, S, F, V, D, T>(
    State(state): State<SharedRouterState<R, C, S, F, V, D, T>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(ticket): Path<String>,
    headers: HeaderMap,
) -> Response
where
    R: Send + Sync + 'static,
    C: Send + Sync + 'static,
    S: Send + Sync + 'static,
    F: Send + Sync + 'static,
    V: Send + Sync + 'static,
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    let device = match authenticate(&state, peer, &headers).await {
        Ok(device) => device,
        Err(response) => return response,
    };
    let ticket = match ContentTicketId::parse(&ticket) {
        Ok(ticket) => ticket,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let content = match state.tickets.download(&ticket, device.device_id) {
        Ok(content) => content,
        Err(error) => return ticket_error(error),
    };
    download_response(content, headers.get(RANGE))
}

#[allow(clippy::result_large_err)] // Axum responses are returned directly; boxing adds no benefit.
async fn authenticate<R, C, S, F, V, D, T>(
    state: &SharedRouterState<R, C, S, F, V, D, T>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<VerifiedOwnerDevice, Response>
where
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    authenticate_peer(&state.live.tailnet, &state.live.devices, peer, headers).await
}

/// A request's paired device: the tailnet peer verified, the Serve identity
/// bound, and the bearer checked against the device trust store.
#[allow(clippy::result_large_err)] // Axum responses are returned directly; boxing adds no benefit.
pub(crate) async fn authenticate_peer<D, T>(
    tailnet: &Arc<T>,
    devices: &Arc<D>,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<VerifiedOwnerDevice, Response>
where
    D: DeviceTrustStore + 'static,
    T: TailnetVerifier + 'static,
{
    let peer = tailnet
        .verify_peer(peer)
        .await
        .map_err(|error| forbidden(&error))?;
    let peer = bind_serve_identity(peer, headers, tailnet.as_ref()).map_err(|error| *error)?;
    let presented = peer.tailnet_node_id().cloned();
    let credential =
        bearer_credential(headers).ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    TailnetAuthenticator::new(Arc::clone(devices))
        .authenticate(peer, credential)
        .await
        .map_err(|error| match error {
            AuthError::TailnetNodeMismatch => {
                if let Some(id) = presented {
                    tracing::error!(
                        node = %id,
                        "huginn device rejected; the credential is paired to a different node"
                    );
                }
                forbidden(&error)
            }
            AuthError::DeviceRevoked => forbidden(&error),
            AuthError::Store(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            _ => StatusCode::UNAUTHORIZED.into_response(),
        })
}

/// Serve connects from loopback and replaces `X-Forwarded-For` with one
/// original source address (`Header.Set` of `SrcAddr` in
/// `addProxyForwardedHeaders`). `Tailscale-User-*` is the user, not the node,
/// and tagged devices omit it (`addTailscaleIdentityHeaders` returns when
/// `node.IsTagged()`).
/// https://github.com/tailscale/tailscale/blob/v1.102.2/ipn/ipnlocal/serve.go
/// Those headers never select a node, and their absence is not a local client.
/// Only loopback proxy headers are trusted. A direct tailnet peer keeps the
/// socket binding; spoofed headers on that peer are ignored.
fn bind_serve_identity(
    peer: VerifiedTailnetPeer,
    headers: &HeaderMap,
    nodes: &impl TailnetVerifier,
) -> Result<VerifiedTailnetPeer, Box<Response>> {
    if !peer.is_loopback() {
        return Ok(peer);
    }
    let forwarded = one_header(headers, &X_FORWARDED_FOR)?;
    let login = one_header(headers, &TAILSCALE_USER_LOGIN)?;
    let name = one_header(headers, &TAILSCALE_USER_NAME)?;
    let profile = one_header(headers, &TAILSCALE_USER_PROFILE_PIC)?;
    let funnel = one_header(headers, &TAILSCALE_FUNNEL_REQUEST)?;
    if funnel.is_some() {
        tracing::error!("huginn rejected a tailscale funnel request");
        return Err(Box::new(forbidden("a tailscale funnel request is refused")));
    }
    if forwarded.is_none() && login.is_none() && name.is_none() && profile.is_none() {
        return Ok(peer);
    }
    let Some(raw) = forwarded else {
        tracing::error!("huginn rejected tailscale identity headers without X-Forwarded-For");
        return Err(Box::new(forbidden(
            "tailscale identity headers arrived without X-Forwarded-For",
        )));
    };
    let forwarded = raw.trim();
    let ip = if forwarded.is_empty()
        || forwarded.contains(',')
        || forwarded.split_whitespace().nth(1).is_some()
    {
        None
    } else {
        forwarded.parse::<IpAddr>().ok()
    };
    let Some(ip) = ip else {
        tracing::error!("huginn rejected a malformed X-Forwarded-For header");
        return Err(Box::new(forbidden(
            "the X-Forwarded-For header is malformed",
        )));
    };
    if !is_tailnet_address(ip) {
        tracing::error!(%ip, "huginn rejected forwarded source; it is not a tailscale address");
        return Err(Box::new(forbidden(format!(
            "forwarded source {ip} is not a tailscale address"
        ))));
    }
    let Some(node) = nodes.node_for_addr(ip) else {
        tracing::error!(
            %ip,
            "huginn rejected forwarded source; add that address to [tailnet_peers] with the paired node id"
        );
        return Err(Box::new(forbidden(format!(
            "forwarded source {ip} is not in the authority's [tailnet_peers]; a client on the authority host should use loopback"
        ))));
    };
    Ok(VerifiedTailnetPeer::tailnet(peer.addr(), Some(node)))
}

/// A 403 that names its cause in the body. Only `AuthError::DeviceRevoked` reads as revoked to a client (it deletes its
/// stored credential on that text alone); every other refusal here is placement or configuration, and the client keeps its
/// credential and reports the reason.
fn forbidden(reason: impl std::fmt::Display) -> Response {
    (StatusCode::FORBIDDEN, reason.to_string()).into_response()
}

fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, Box<Response>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        tracing::error!(%name, "huginn rejected duplicate header");
        return Err(Box::new(forbidden(format!("duplicate {name} header"))));
    }
    value.to_str().map(Some).map_err(|error| {
        tracing::error!(%name, %error, "huginn rejected non-text header");
        Box::new(forbidden(format!("non-text {name} header")))
    })
}

fn bearer_credential(headers: &HeaderMap) -> Option<SecretBytes> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || token.contains(' ') {
        return None;
    }
    Some(SecretBytes::new(token.as_bytes().to_vec()))
}

fn download_response(content: DownloadContent, range: Option<&HeaderValue>) -> Response {
    let total = content.bytes.len();
    let (status, start, end) = match range {
        Some(range) => match parse_range(range, total) {
            Some((start, end)) => (StatusCode::PARTIAL_CONTENT, start, end),
            None => {
                let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
                response.headers_mut().insert(
                    CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{total}")).expect("valid range"),
                );
                return response;
            }
        },
        None if total == 0 => (StatusCode::OK, 0, 0),
        None => (StatusCode::OK, 0, total - 1),
    };
    let body = if total == 0 {
        Bytes::new()
    } else {
        content.bytes.slice(start..=end)
    };
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(&content.media_type).expect("validated media type"),
    );
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&body.len().to_string()).expect("valid length"),
    );
    headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("attachment"));
    headers.insert(
        CONTENT_DIGEST,
        HeaderValue::from_str(&content.digest.to_string()).expect("valid digest"),
    );
    if status == StatusCode::PARTIAL_CONTENT {
        headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).expect("valid range"),
        );
    }
    response
}

fn parse_range(value: &HeaderValue, total: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }
    let value = value.to_str().ok()?.strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?;
        if suffix == 0 {
            return None;
        }
        return Some((total.saturating_sub(suffix.min(total)), total - 1));
    }
    let start = start.parse::<usize>().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.is_empty() {
        total - 1
    } else {
        end.parse::<usize>().ok()?.min(total - 1)
    };
    (start <= end).then_some((start, end))
}

fn ticket_error(error: ContentTicketError) -> Response {
    match error {
        ContentTicketError::Unauthorized => StatusCode::FORBIDDEN.into_response(),
        ContentTicketError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        error @ (ContentTicketError::Capacity | ContentTicketError::Poisoned(_)) => {
            (StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
        }
        ContentTicketError::InvalidMediaType | ContentTicketError::InvalidTicket => {
            StatusCode::BAD_REQUEST.into_response()
        }
        ContentTicketError::NotFound => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn private_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, max-age=0"),
    );
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::{HeaderMap, HeaderValue};
    use odin_domain::huginn::DeviceId;

    use uuid::Uuid;

    use super::{bind_serve_identity, forbidden, X_FORWARDED_FOR};
    use crate::auth::AuthError;
    use crate::private_network::{InterfaceTailnetVerifier, TailnetVerifier};

    fn header(name: &axum::http::HeaderName, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_str(value).expect("header"));
        headers
    }

    async fn refusal(response: axum::response::Response) -> (axum::http::StatusCode, String) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("body");
        (status, String::from_utf8(body.to_vec()).expect("text"))
    }

    /// The authority's own address is not a peer, so a client on the authority host that rides the tailnet route is
    /// refused 403 for its forwarded source. That refusal names the cause and is not the revoked text, which is all a
    /// client deletes its stored credential on.
    #[tokio::test]
    async fn a_refusal_for_placement_names_its_cause_and_only_a_revocation_reads_as_revoked() {
        let verifier = InterfaceTailnetVerifier::new(BTreeMap::new());
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18420);
        let peer = verifier.verify_peer(loopback).await.expect("loopback");
        let Err(response) =
            bind_serve_identity(peer, &header(&X_FORWARDED_FOR, "100.64.0.11"), &verifier)
        else {
            panic!("an unmapped forwarded source is refused");
        };
        let (status, body) = refusal(*response).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        assert!(
            body.contains("100.64.0.11") && body.contains("tailnet_peers"),
            "{body}"
        );
        assert_ne!(body, crate::client::DEVICE_REVOKED_REFUSAL);

        let (status, body) = refusal(forbidden(&AuthError::DeviceRevoked)).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(body, crate::client::DEVICE_REVOKED_REFUSAL);
        let (_, body) = refusal(forbidden(&AuthError::TailnetNodeMismatch)).await;
        assert_ne!(body, crate::client::DEVICE_REVOKED_REFUSAL);
    }

    #[test]
    fn a_ticket_downloads_only_for_its_device_and_the_store_is_bounded() {
        use super::{ContentTicketError, ContentTicketStore};

        let store = ContentTicketStore::new(1, 8, std::time::Duration::from_secs(60));
        let owner = DeviceId::new(Uuid::new_v4()).unwrap();
        let other = DeviceId::new(Uuid::new_v4()).unwrap();
        let ticket = store
            .issue_download(owner, "text/plain", b"hello".to_vec())
            .unwrap();
        assert_eq!(
            store.download(&ticket, owner).unwrap().bytes.as_ref(),
            b"hello"
        );
        assert!(matches!(
            store.download(&ticket, other),
            Err(ContentTicketError::Unauthorized)
        ));
        assert!(matches!(
            store.issue_download(owner, "text/plain", b"second".to_vec()),
            Err(ContentTicketError::Capacity)
        ));
        assert!(matches!(
            ContentTicketStore::new(4, 8, std::time::Duration::from_secs(60)).issue_download(
                owner,
                "text/plain",
                vec![0; 9]
            ),
            Err(ContentTicketError::TooLarge)
        ));
    }
}
