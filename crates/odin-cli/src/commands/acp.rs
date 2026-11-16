//! `odin acp`: Odin's live sessions over the Agent Client Protocol, so an
//! ACP client (Agmente on the phone, T3 Code, Zed) chats with the owner
//! conversation, watches and steers seat sessions and pods, and approves
//! what waits on the owner's yes.
//!
//! It is a Huginn client like `odin view`. `session/list` names the owner
//! conversation, every live seat session (lanes, Kubert, the supervisor) and
//! every Odin pod; a watcher tells the client when one starts or ends
//! (`session_info_update`, then `_odin/sessions_changed`). An opened session's
//! live events become `session/update`s. A prompt is said into the owner
//! conversation like a Discord DM (its photos staged like Discord photos),
//! sent to a seat session as a steer (or a prompt when it is idle), and
//! passed to the conversation for a pod; a tool result's images come back as
//! resource links. An approval waiting on the owner, whichever seat asked, becomes a
//! `session/request_permission` in its open session, else the owner
//! conversation, whose answer is the `ApprovalDecision`.
//! Over stdio by default; `--listen` serves the same over a WebSocket that
//! requires `Authorization: Bearer <token>`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Args;
use odin_cli::authority_provision;
use odin_domain::huginn as live;
use odin_huginn::client::{RemoteClient, EndpointTransport, FileCredentialStore};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch};

mod approvals;
mod sessions;

#[derive(Debug, Args)]
pub(crate) struct AcpArgs {
    /// Serve ACP over a WebSocket on this address instead of stdio.
    #[arg(long)]
    listen: Option<SocketAddr>,
    /// The bearer token a WebSocket client must send; created (0600) when missing.
    #[arg(long, requires = "listen")]
    token_file: Option<PathBuf>,
    /// Images a WebSocket client can still open by link (the newest are kept).
    #[arg(long, default_value_t = 32)]
    images_kept: usize,
    /// Huginn endpoint (HTTPS, or loopback HTTP on the authority).
    #[arg(long, env = "ODIN_HUGINN_ENDPOINT")]
    endpoint: Option<String>,
    /// Holds `huginn/device.credential`, this host's pairing.
    #[arg(long, env = "ODIN_HUGINN_STATE_ROOT", default_value = "state")]
    state_root: PathBuf,
}

pub(super) type Client = RemoteClient<EndpointTransport, FileCredentialStore>;

const PROTOCOL_VERSION: u64 = 1;
const REQUEST_BOUND: Duration = Duration::from_secs(20);
const RETRY_EVERY: Duration = Duration::from_secs(2);
/// The longest a prompt waits for its turn to end.
const TURN_BOUND: Duration = Duration::from_secs(15 * 60);
/// After an approval, how long the prompt waits for the turn its result starts.
const AFTER_APPROVAL: Duration = Duration::from_secs(180);
/// Events `session/load` replays.
const HISTORY: u64 = 200;
/// The longest tool result text shown in a tool call update.
const RESULT_CHARS: usize = 2000;

pub(crate) fn run(arguments: AcpArgs) -> Result<(), String> {
    let endpoint = arguments
        .endpoint
        .ok_or("odin acp: no Huginn endpoint (set ODIN_HUGINN_ENDPOINT or pass --endpoint)")?;
    let url = url::Url::parse(&endpoint)
        .map_err(|error| format!("odin acp: invalid Huginn endpoint {endpoint}: {error}"))?;
    let transport = EndpointTransport::new(url).map_err(|error| error.to_string())?;
    let credentials = FileCredentialStore::open(arguments.state_root.join("huginn"))
        .map_err(|error| format!("odin acp: this host is not paired with Huginn: {error}"))?;
    let client = Arc::new(RemoteClient::new(transport, credentials));
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("odin acp: could not start the runtime: {error}"))?;
    match arguments.listen {
        None => runtime.block_on(stdio(client)),
        Some(address) => {
            let token_file = arguments
                .token_file
                .ok_or("odin acp: --listen needs --token-file")?;
            let token = token(&token_file)?;
            let shelf = Arc::new(Shelf::new(arguments.images_kept));
            runtime.block_on(websocket(client, address, token, shelf))
        }
    }
}

/// The token in `path`, made (owner-only) the first time.
fn token(path: &std::path::Path) -> Result<String, String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Ok(text) = std::fs::read_to_string(path) {
        let text = text.trim().to_owned();
        if text.len() >= 32 {
            return Ok(text);
        }
        return Err(format!(
            "odin acp: {} holds no usable token (32+ characters)",
            path.display()
        ));
    }
    let made = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("odin acp: {}: {error}", parent.display()))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| writeln!(file, "{made}"))
        .map_err(|error| format!("odin acp: {}: {error}", path.display()))?;
    Ok(made)
}

async fn stdio(client: Arc<Client>) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let (incoming, inbox) = mpsc::unbounded_channel();
    let (outbox, mut outgoing) = mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(message) = outgoing.recv().await {
            let line = format!("{message}\n");
            if stdout.write_all(line.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
                break;
            }
        }
    });
    let reader = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(message) = parse(&line) {
                if incoming.send(message).is_err() {
                    break;
                }
            }
        }
    });
    serve(client, inbox, outbox, None).await;
    reader.abort();
    writer.abort();
    Ok(())
}

fn parse(text: &str) -> Option<Value> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    match serde_json::from_str(text) {
        Ok(message) => Some(message),
        Err(error) => {
            tracing::warn!("odin acp: a message is not JSON: {error}");
            None
        }
    }
}

/// The images a tool result returned, kept so the phone can open them: Agmente shows only a
/// message's text, so each image goes as a Markdown link to `/image/<token>` on this listener
/// (tailnet HTTPS in front of it). A token is 256 random bits; only the newest are kept.
pub(super) struct Shelf {
    kept: usize,
    images: Mutex<std::collections::VecDeque<(String, String, Vec<u8>)>>,
}

impl Shelf {
    fn new(kept: usize) -> Self {
        Self {
            kept: kept.max(1),
            images: Mutex::new(std::collections::VecDeque::new()),
        }
    }

    fn put(&self, mime: &str, bytes: Vec<u8>) -> String {
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let mut images = lock(&self.images);
        images.push_back((token.clone(), mime.to_owned(), bytes));
        while images.len() > self.kept {
            images.pop_front();
        }
        token
    }

    fn get(&self, token: &str) -> Option<(String, Vec<u8>)> {
        lock(&self.images)
            .iter()
            .find(|(kept, _, _)| kept == token)
            .map(|(_, mime, bytes)| (mime.clone(), bytes.clone()))
    }
}

/// Where a WebSocket client opens shelved images: the shelf, and this listener's public origin
/// as the client reached it (its Host header).
#[derive(Clone)]
pub(super) struct Links {
    shelf: Arc<Shelf>,
    origin: String,
}

async fn websocket(
    client: Arc<Client>,
    address: SocketAddr,
    token: String,
    shelf: Arc<Shelf>,
) -> Result<(), String> {
    use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
    use axum::http::{header, StatusCode};
    use axum::response::{IntoResponse, Response};
    use futures_util::{SinkExt as _, StreamExt as _};

    async fn connected(socket: WebSocket, client: Arc<Client>, links: Links) {
        let (mut sink, mut source) = socket.split();
        let (incoming, inbox) = mpsc::unbounded_channel();
        let (outbox, mut outgoing) = mpsc::unbounded_channel::<Value>();
        let writer = tokio::spawn(async move {
            while let Some(message) = outgoing.recv().await {
                if sink
                    .send(Message::Text(message.to_string().into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let reader = tokio::spawn(async move {
            while let Some(Ok(frame)) = source.next().await {
                let message = match frame {
                    Message::Text(text) => parse(text.as_str()),
                    Message::Close(_) => break,
                    _ => None,
                };
                if let Some(message) = message {
                    if incoming.send(message).is_err() {
                        break;
                    }
                }
            }
        });
        serve(client, inbox, outbox, Some(links)).await;
        reader.abort();
        writer.abort();
    }

    let expected = format!("Bearer {token}");
    let images = Arc::clone(&shelf);
    let app = axum::Router::new()
        .route(
            "/image/{token}",
            axum::routing::get(
                move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let found = images.get(&token);
                    async move {
                        match found {
                            Some((mime, bytes)) => {
                                ([(header::CONTENT_TYPE, mime)], bytes).into_response()
                            }
                            None => (StatusCode::NOT_FOUND, "this image is no longer kept\n")
                                .into_response(),
                        }
                    }
                },
            ),
        )
        .route(
            "/",
            axum::routing::get(
                move |headers: axum::http::HeaderMap, upgrade: WebSocketUpgrade| {
                    let client = Arc::clone(&client);
                    let links = Links {
                        shelf: Arc::clone(&shelf),
                        origin: headers
                            .get(header::HOST)
                            .and_then(|value| value.to_str().ok())
                            .map(|host| format!("https://{host}"))
                            .unwrap_or_default(),
                    };
                    let allowed = headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        == Some(expected.as_str());
                    async move {
                        if !allowed {
                            let refused: Response = (
                                StatusCode::UNAUTHORIZED,
                                "odin acp needs its bearer token\n",
                            )
                                .into_response();
                            return refused;
                        }
                        upgrade.on_upgrade(move |socket| connected(socket, client, links))
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| format!("odin acp: cannot listen on {address}: {error}"))?;
    tracing::info!("odin acp: serving ACP over WebSocket on {address}");
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("odin acp: {error}"))
}

/// One ACP connection, until its client goes.
pub(super) struct Peer {
    client: Arc<Client>,
    out: mpsc::UnboundedSender<Value>,
    /// Our requests to the client (permission asks), by JSON-RPC id.
    asked: Mutex<HashMap<u64, oneshot::Sender<Value>>>,
    next_id: AtomicU64,
    /// The owner conversation's ACP id, and the live session carrying it.
    conversation: Mutex<Option<String>>,
    vehicle: Mutex<Option<live::LiveSessionId>>,
    /// The sessions the client opened, each followed by its own task.
    followers: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    /// Per opened session: its turns, approvals and open permission cards.
    tracks: Mutex<HashMap<String, Arc<Track>>>,
    /// The listed sessions as last seen, to tell the client what changed.
    known: Mutex<BTreeMap<String, sessions::Entry>>,
    /// The session watcher, started with the first session request.
    watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// `session/cancel`, per session.
    cancelled: watch::Sender<u64>,
    /// A WebSocket client reconnects on its own and then lists the sessions
    /// again (Agmente does), so a started or ended session is shown by
    /// hanging up once nothing is in flight. A stdio client cannot.
    reconnects: bool,
    /// Where a WebSocket client opens the images a tool returned; a stdio client has none.
    links: Option<Links>,
    /// Sessions started or ended since the client last listed them.
    relist: AtomicBool,
    /// Prompts waiting for their turn to end.
    prompts: AtomicU64,
    hang_up: watch::Sender<bool>,
    /// The last prompt said in each session, so its echo is not shown back.
    said: Mutex<HashMap<String, String>>,
    /// Approvals already put to the client.
    approvals: Mutex<BTreeSet<String>>,
    /// Tool calls by id (title, arguments), and the call each approval
    /// came from, so a permission card names what it approves.
    calls: Mutex<HashMap<String, (String, Value)>>,
    asked_by: Mutex<HashMap<String, String>>,
}

/// One opened session's progress.
#[derive(Default)]
pub(super) struct Track {
    /// Turns that ended (the session went idle).
    turns: watch::Sender<u64>,
    /// Approvals the client granted for this session.
    approved: watch::Sender<u64>,
    /// Permission cards open on the client right now.
    asking: AtomicU64,
}

async fn serve(
    client: Arc<Client>,
    mut inbox: mpsc::UnboundedReceiver<Value>,
    out: mpsc::UnboundedSender<Value>,
    links: Option<Links>,
) {
    let peer = Arc::new(Peer {
        client,
        out,
        asked: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        conversation: Mutex::new(None),
        vehicle: Mutex::new(None),
        followers: Mutex::new(HashMap::new()),
        tracks: Mutex::new(HashMap::new()),
        known: Mutex::new(BTreeMap::new()),
        watcher: Mutex::new(None),
        cancelled: watch::channel(0).0,
        reconnects: links.is_some(),
        links,
        relist: AtomicBool::new(false),
        prompts: AtomicU64::new(0),
        hang_up: watch::channel(false).0,
        said: Mutex::new(HashMap::new()),
        approvals: Mutex::new(BTreeSet::new()),
        calls: Mutex::new(HashMap::new()),
        asked_by: Mutex::new(HashMap::new()),
    });
    let mut hang_up = peer.hang_up.subscribe();
    loop {
        let message = tokio::select! {
            message = inbox.recv() => message,
            _ = hang_up.changed() => None,
        };
        let Some(message) = message else {
            break;
        };
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id").cloned();
        match (method, id) {
            (Some(method), Some(id)) => {
                let peer = Arc::clone(&peer);
                let method = method.to_owned();
                let params = message.get("params").cloned().unwrap_or(Value::Null);
                tokio::spawn(async move {
                    let reply = match peer.handle(&method, &params).await {
                        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                        Err((code, text)) => json!({"jsonrpc": "2.0", "id": id,
                            "error": {"code": code, "message": text}}),
                    };
                    let _ = peer.out.send(reply);
                });
            }
            (Some("session/cancel"), None) => peer.cancelled.send_modify(|count| *count += 1),
            (Some(_), None) => {}
            (None, Some(id)) => {
                let waiting = id.as_u64().and_then(|id| lock(&peer.asked).remove(&id));
                if let Some(waiting) = waiting {
                    let _ = waiting.send(message);
                }
            }
            (None, None) => {}
        }
    }
    let tasks: Vec<_> = lock(&peer.followers)
        .drain()
        .map(|(_, task)| task)
        .collect();
    let watcher = lock(&peer.watcher).take();
    for task in tasks.into_iter().chain(watcher) {
        task.abort();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type Refusal = (i64, String);

const INVALID_PARAMS: i64 = -32602;
const NOT_FOUND: i64 = -32601;
const INTERNAL: i64 = -32603;

/// What an ACP session id names.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Target {
    /// The owner conversation, through whichever live session carries it.
    Conversation,
    /// One seat's live session (a lane, Kubert, the supervisor…).
    Live(live::LiveSessionId),
    /// One Odin pod, by its Job name: status only, steered through the conversation.
    Pod(String),
}

pub(super) const LIVE_PREFIX: &str = "live:";
pub(super) const POD_PREFIX: &str = "pod:";

impl Peer {
    async fn handle(self: &Arc<Self>, method: &str, params: &Value) -> Result<Value, Refusal> {
        match method {
            "initialize" => Ok(json!({
                "protocolVersion": PROTOCOL_VERSION,
                "agentCapabilities": {
                    "loadSession": true,
                    "promptCapabilities": {"image": true, "audio": false, "embeddedContext": false},
                    "sessionCapabilities": {"list": {}},
                },
                "authMethods": [],
                "agentInfo": {"name": "odin", "title": "Odin", "version": env!("CARGO_PKG_VERSION")},
            })),
            "session/list" => {
                self.watch();
                let cwd = params["cwd"].as_str().unwrap_or("/");
                let entries = self
                    .list()
                    .await
                    .map_err(|error| (INTERNAL, format!("the sessions are unreadable: {error}")))?;
                Ok(
                    json!({ "sessions": entries.iter().map(|entry| entry.info(cwd)).collect::<Vec<_>>() }),
                )
            }
            "session/new" => {
                self.watch();
                let conversation = self.conversation_id().await?;
                self.open(&conversation, 0).await?;
                Ok(json!({ "sessionId": conversation }))
            }
            "session/load" => {
                self.watch();
                let session = params["sessionId"]
                    .as_str()
                    .ok_or((INVALID_PARAMS, "session/load needs a sessionId".to_owned()))?
                    .to_owned();
                self.conversation_id().await?;
                self.open(&session, HISTORY).await?;
                Ok(Value::Null)
            }
            "session/prompt" => self.prompt(params).await,
            other => Err((NOT_FOUND, format!("odin acp does not serve {other}"))),
        }
    }

    pub(super) async fn request(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, String> {
        match tokio::time::timeout(REQUEST_BOUND, self.client.request(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err(format!("Huginn did not answer within {REQUEST_BOUND:?}")),
        }
    }

    /// The owner conversation's id (its ACP session id).
    async fn conversation_id(&self) -> Result<String, Refusal> {
        if let Some(known) = lock(&self.conversation).clone() {
            return Ok(known);
        }
        match self.request(live::HuginnRequest::ConversationStatus).await {
            Ok(live::HuginnResponse::Conversation(view)) => {
                *lock(&self.conversation) = Some(view.conversation_id.clone());
                Ok(view.conversation_id)
            }
            Ok(other) => Err((INTERNAL, format!("Huginn answered {other:?}"))),
            Err(error) => Err((
                INTERNAL,
                format!("the owner conversation is not reachable: {error}"),
            )),
        }
    }

    pub(super) fn target(&self, session: &str) -> Result<Target, Refusal> {
        if lock(&self.conversation).as_deref() == Some(session) {
            return Ok(Target::Conversation);
        }
        if let Some(id) = session.strip_prefix(LIVE_PREFIX) {
            return id.parse().map(Target::Live).map_err(|_| {
                (
                    INVALID_PARAMS,
                    format!("{session:?} is not a live session id"),
                )
            });
        }
        if let Some(name) = session.strip_prefix(POD_PREFIX) {
            return Ok(Target::Pod(name.to_owned()));
        }
        Err((
            INVALID_PARAMS,
            format!("{session:?} is not a session this agent lists"),
        ))
    }

    pub(super) fn track(&self, session: &str) -> Arc<Track> {
        Arc::clone(lock(&self.tracks).entry(session.to_owned()).or_default())
    }

    /// Opens (or reuses) the follow of one session, replaying `history`
    /// events; answers once the replay is sent.
    async fn open(self: &Arc<Self>, session: &str, history: u64) -> Result<(), Refusal> {
        let target = self.target(session)?;
        if lock(&self.followers)
            .get(session)
            .is_some_and(|task| !task.is_finished())
        {
            return Ok(());
        }
        self.track(session);
        let (replayed, done) = oneshot::channel();
        let peer = Arc::clone(self);
        let id = session.to_owned();
        let follower =
            tokio::spawn(async move { peer.follow(id, target, history, replayed).await });
        if let Some(previous) = lock(&self.followers).insert(session.to_owned(), follower) {
            previous.abort();
        }
        let _ = tokio::time::timeout(REQUEST_BOUND, done).await;
        Ok(())
    }

    pub(super) fn update(&self, session: &str, update: Value) {
        let _ = self
            .out
            .send(json!({"jsonrpc": "2.0", "method": "session/update",
            "params": {"sessionId": session, "update": update}}));
    }

    /// Shelves each image a tool returned and says a Markdown link to it in the session, so the
    /// phone opens it with a tap (an artifact is fetched from Huginn first).
    fn link_images(&self, session: &str, links: &Links, blocks: &[live::LiveContentBlock]) {
        let images: Vec<live::LiveContentBlock> = blocks
            .iter()
            .filter(|block| match block {
                live::LiveContentBlock::Image { .. } => true,
                live::LiveContentBlock::Render(render) => render.media_type.starts_with("image/"),
                live::LiveContentBlock::File(file) => file.media_type.starts_with("image/"),
                _ => false,
            })
            .cloned()
            .collect();
        if images.is_empty() {
            return;
        }
        let (client, out, links, session) = (
            Arc::clone(&self.client),
            self.out.clone(),
            links.clone(),
            session.to_owned(),
        );
        tokio::spawn(async move {
            for block in images {
                let line = match image_bytes(&client, &block).await {
                    Ok((name, mime, bytes)) => {
                        let token = links.shelf.put(&mime, bytes);
                        format!("\n[{name}]({}/image/{token})\n", links.origin)
                    }
                    Err(reason) => format!("\n(an image could not be fetched: {reason})\n"),
                };
                let _ = out.send(json!({"jsonrpc": "2.0", "method": "session/update",
                    "params": {"sessionId": session, "update": {"sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": line}}}}));
            }
        });
    }

    pub(super) fn say_in(&self, session: &str, text: &str) {
        self.update(
            session,
            json!({"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": text}}),
        );
    }

    /// The live session carrying `target` now, and its event head.
    async fn vehicle(&self, target: &Target) -> Result<(live::LiveSessionId, u64), String> {
        let session = match target {
            Target::Conversation => {
                match self
                    .request(live::HuginnRequest::ConversationStatus)
                    .await?
                {
                    live::HuginnResponse::Conversation(view) => view
                        .vehicle_session
                        .ok_or("the conversation has no live session right now")?,
                    other => return Err(format!("Huginn answered {other:?}")),
                }
            }
            Target::Live(session) => *session,
            Target::Pod(_) => return Err("a pod has no live session to follow".to_owned()),
        };
        let head = self
            .roster()
            .await?
            .into_iter()
            .flat_map(|entry| entry.active_sessions)
            .find(|summary| summary.session_id == session)
            .map(|summary| summary.event_head.get());
        match (target, head) {
            (Target::Live(_), None) => Err("the session has ended".to_owned()),
            (_, head) => Ok((session, head.unwrap_or(0))),
        }
    }

    /// Follows one session for as long as the connection lasts: a
    /// conversation across reconnects and vehicle rollovers, a seat
    /// session until it ends, a pod through its status reports.
    async fn follow(
        self: Arc<Self>,
        id: String,
        target: Target,
        history: u64,
        replayed: oneshot::Sender<()>,
    ) {
        let mut replayed = Some(replayed);
        if let Target::Pod(name) = &target {
            if let Some(entry) = lock(&self.known).get(&id) {
                self.say_in(&id, &entry.pod_line(name));
            }
            if let Some(replayed) = replayed.take() {
                let _ = replayed.send(());
            }
            return;
        }
        let mut position: Option<(live::LiveSessionId, u64)> = None;
        let mut turn = Turn::default();
        loop {
            let (session, head) = match self.vehicle(&target).await {
                Ok(found) => found,
                Err(error) => {
                    tracing::warn!("odin acp: {id}: {error}");
                    if let Some(replayed) = replayed.take() {
                        let _ = replayed.send(());
                    }
                    if matches!(target, Target::Live(_)) {
                        self.say_in(&id, &format!("\n({error})\n"));
                        return;
                    }
                    tokio::time::sleep(RETRY_EVERY).await;
                    continue;
                }
            };
            let after = match &position {
                Some((followed, after)) if *followed == session => *after,
                _ => head.saturating_sub(history),
            };
            let stream_id = odin_huginn::feed::agent_event_stream(session);
            let mut stream = match self.client.subscribe(subscription(stream_id, after)).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!("odin acp: following {session} failed: {error}");
                    tokio::time::sleep(RETRY_EVERY).await;
                    continue;
                }
            };
            position = Some((session, after));
            while let Some(message) = stream.next().await {
                match message {
                    Ok(live::HuginnMessage::Event(event)) => {
                        position = Some((session, event.sequence.get()));
                        self.event(&id, &event, &mut turn);
                    }
                    Ok(live::HuginnMessage::ReplayComplete { .. }) => {
                        if let Some(replayed) = replayed.take() {
                            let _ = replayed.send(());
                        }
                    }
                    Ok(live::HuginnMessage::StreamStatus(status))
                        if matches!(
                            status.lifecycle,
                            live::StreamLifecycle::Closed | live::StreamLifecycle::Failed
                        ) =>
                    {
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!("odin acp: {session} stream lost: {error}");
                        break;
                    }
                }
            }
            if let Some(replayed) = replayed.take() {
                let _ = replayed.send(());
            }
            tokio::time::sleep(RETRY_EVERY).await;
        }
    }

    fn event(&self, id: &str, event: &live::LiveEvent, turn: &mut Turn) {
        match &event.body {
            live::LiveEventBody::UserMessage(message) => {
                let text = owner_words(&message_text(message));
                let said = lock(&self.said).get(id).cloned().unwrap_or_default();
                // Odin's own notices ("[Harness event …]", job reports) are not
                // the owner's words: they show as the agent's background, not his lines.
                let kind = if text.starts_with('[') {
                    "agent_thought_chunk"
                } else {
                    "user_message_chunk"
                };
                if !text.is_empty() && (said.is_empty() || !text.contains(said.trim())) {
                    self.update(
                        id,
                        json!({"sessionUpdate": kind, "content": {"type": "text", "text": text}}),
                    );
                }
            }
            live::LiveEventBody::AssistantDelta(delta) => {
                turn.streamed = true;
                self.say_in(id, &delta.text);
            }
            live::LiveEventBody::AssistantMessage(message) => {
                let text = message_text(message);
                if !std::mem::take(&mut turn.streamed) && !text.trim().is_empty() {
                    self.say_in(id, &text);
                }
            }
            live::LiveEventBody::Thinking(thinking) => {
                self.update(
                    id,
                    json!({"sessionUpdate": "agent_thought_chunk",
                    "content": {"type": "text", "text": thinking.text}}),
                );
            }
            live::LiveEventBody::ToolStarted(started) => {
                let title = started
                    .intent
                    .clone()
                    .unwrap_or_else(|| started.tool.capability_id.to_string());
                lock(&self.calls).insert(
                    started.tool.tool_use_id.clone(),
                    (title.clone(), started.tool.arguments.clone()),
                );
                self.update(
                    id,
                    json!({"sessionUpdate": "tool_call",
                    "toolCallId": started.tool.tool_use_id, "title": title, "kind": "other",
                    "status": "in_progress", "rawInput": started.tool.arguments}),
                );
            }
            live::LiveEventBody::ToolFinished(finished) => {
                let text: String = finished
                    .result
                    .content
                    .iter()
                    .filter_map(|block| match block {
                        live::LiveContentBlock::Text(text) => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    .chars()
                    .take(RESULT_CHARS)
                    .collect();
                let content = tool_content(&text, &finished.result.content);
                // "approval required: … approval `approval:r3:…`": the call it waits on.
                if let Some(approval) = text.split('`').find(|part| part.starts_with("approval:")) {
                    lock(&self.asked_by)
                        .insert(approval.to_owned(), finished.result.tool_use_id.clone());
                }
                self.update(
                    id,
                    json!({"sessionUpdate": "tool_call_update",
                    "toolCallId": finished.result.tool_use_id,
                    "status": if finished.result.is_error { "failed" } else { "completed" },
                    "content": content}),
                );
                if let Some(links) = &self.links {
                    self.link_images(id, links, &finished.result.content);
                }
            }
            live::LiveEventBody::Error(error) => {
                self.say_in(id, &format!("\n(error: {})\n", error.message));
            }
            live::LiveEventBody::SessionStateChanged(change)
                if change.current == live::LiveSessionState::Idle
                    && change.previous != live::LiveSessionState::Idle =>
            {
                turn.streamed = false;
                self.track(id).turns.send_modify(|count| *count += 1);
            }
            _ => {}
        }
    }

    /// Delivers the prompt to its session and answers when that turn ends;
    /// an approval asked meanwhile keeps the turn open until it is answered
    /// and the work it allowed has reported.
    async fn prompt(self: &Arc<Self>, params: &Value) -> Result<Value, Refusal> {
        let text = prompt_text(params);
        let images = prompt_images(params)?;
        if text.trim().is_empty() && images.is_empty() {
            return Err((INVALID_PARAMS, "the prompt has no text or image".to_owned()));
        }
        let session = params["sessionId"]
            .as_str()
            .ok_or((
                INVALID_PARAMS,
                "session/prompt needs a sessionId".to_owned(),
            ))?
            .to_owned();
        let conversation = self.conversation_id().await?;
        let target = self.target(&session)?;
        self.open(&session, 0).await?;
        // A pod has no inbox of its own: the conversation is asked to steer it.
        let (waited, said) = match &target {
            Target::Pod(name) => {
                self.open(&conversation, 0).await?;
                let label = lock(&self.known)
                    .get(&session)
                    .map_or_else(|| name.clone(), |entry| entry.title.clone());
                self.say_in(
                    &session,
                    "Pods take messages through the conversation; passed on there.\n",
                );
                (
                    conversation.clone(),
                    format!("Steer the pod \"{label}\" (job {name}) with this: {text}"),
                )
            }
            _ => (session.clone(), text),
        };
        lock(&self.said).insert(waited.clone(), said.clone());
        self.prompts.fetch_add(1, Ordering::Relaxed);
        let answer = self.wait_turn(&target, &waited, &said, images).await;
        self.prompts.fetch_sub(1, Ordering::Relaxed);
        answer
    }

    /// Delivers `said` and waits for the turn in `waited` to end.
    async fn wait_turn(
        &self,
        target: &Target,
        waited: &str,
        said: &str,
        images: Vec<live::ConversationImage>,
    ) -> Result<Value, Refusal> {
        let track = self.track(waited);
        let mut turns = track.turns.subscribe();
        let mut approved = track.approved.subscribe();
        let mut cancelled = self.cancelled.subscribe();
        match target {
            Target::Live(live_session) => self.steer(*live_session, said, images).await?,
            _ => self.say(said, images).await?,
        }
        let mut deadline = tokio::time::Instant::now() + TURN_BOUND;
        loop {
            tokio::select! {
                changed = turns.changed() => {
                    if changed.is_err() || track.asking.load(Ordering::Relaxed) == 0 {
                        return Ok(json!({"stopReason": "end_turn"}));
                    }
                }
                _ = approved.changed() => {
                    deadline = tokio::time::Instant::now() + AFTER_APPROVAL;
                }
                _ = cancelled.changed() => return Ok(json!({"stopReason": "cancelled"})),
                () = tokio::time::sleep_until(deadline) => {
                    return Ok(json!({"stopReason": "end_turn"}));
                }
            }
        }
    }

    /// Says a line into the owner conversation, like a Discord DM.
    async fn say(&self, text: &str, images: Vec<live::ConversationImage>) -> Result<(), Refusal> {
        let command_id =
            authority_provision::random_command_uuid().map_err(|error| (INTERNAL, error))?;
        let say = live::HuginnRequest::ConversationSay(live::ConversationSayRequest {
            command_id,
            text: text.to_owned(),
            terminal: true,
            images,
        });
        match self.request(say).await {
            Ok(live::HuginnResponse::Conversation(_)) => Ok(()),
            Ok(other) => Err((INTERNAL, format!("Huginn answered the say with {other:?}"))),
            Err(error) => Err((INTERNAL, format!("not sent: {error}"))),
        }
    }

    /// A message into one seat's live session: a steer while it works, a
    /// new prompt when it is idle.
    async fn steer(
        &self,
        session: live::LiveSessionId,
        text: &str,
        images: Vec<live::ConversationImage>,
    ) -> Result<(), Refusal> {
        let summary = self
            .roster()
            .await
            .map_err(|error| (INTERNAL, error))?
            .into_iter()
            .flat_map(|entry| entry.active_sessions)
            .find(|summary| summary.session_id == session)
            .ok_or((INVALID_PARAMS, "that session has ended".to_owned()))?;
        let blocks = std::iter::once(live::LiveContentBlock::Text(text.to_owned()))
            .filter(|_| !text.trim().is_empty())
            .chain(
                images
                    .into_iter()
                    .map(|image| live::LiveContentBlock::Image {
                        mime_type: image.mime_type,
                        data: image.data,
                    }),
            )
            .collect();
        let message =
            live::LiveMessage::new(blocks).map_err(|error| (INVALID_PARAMS, error.to_string()))?;
        let body = if summary.state == live::LiveSessionState::Idle {
            live::LiveCommandBody::Prompt {
                message,
                owner_text: Some(text.to_owned()),
                wake: false,
            }
        } else {
            live::LiveCommandBody::Steer { message }
        };
        let command_id =
            authority_provision::random_command_uuid().map_err(|error| (INTERNAL, error))?;
        let command = live::HuginnRequest::SessionCommand(live::LiveCommand {
            command_id,
            session_id: session,
            expected_epoch: summary.epoch,
            expected_event_head: None,
            body,
        });
        match self.request(command).await {
            Ok(_) => Ok(()),
            Err(error) => Err((INTERNAL, format!("not delivered: {error}"))),
        }
    }
}

/// Per-turn state while following: whether this message streamed as deltas.
#[derive(Default)]
struct Turn {
    streamed: bool,
}

fn subscription(stream_id: live::StreamId, after: u64) -> live::SubscriptionSet {
    let positive32 = |value: u32| std::num::NonZeroU32::new(value).expect("positive");
    let positive64 = |value: u64| std::num::NonZeroU64::new(value).expect("positive");
    live::SubscriptionSet {
        subscriptions: vec![live::StreamSubscription {
            kind: live::LiveStreamKind::AgentEvents,
            cursor: live::StreamCursor::Durable {
                stream_id,
                after: Some(live::Sequence::new(after)),
            },
            credit: live::StreamCredit {
                items: positive32(64),
                bytes: positive64(1 << 20),
            },
            limits: live::StreamBackpressureLimits {
                max_buffered_items: positive32(512),
                max_buffered_bytes: positive64(8 << 20),
                max_item_bytes: positive64(2 << 20),
                max_items_per_second: positive32(60),
                max_in_flight_bytes: positive64(8 << 20),
            },
        }],
    }
}

fn message_text(message: &live::LiveMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|block| match block {
            live::LiveContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// What the owner wrote, without the bracketed lines the runtime prefixes.
fn owner_words(text: &str) -> String {
    let mut rest = text.trim_start();
    while rest.starts_with('[') {
        match rest.find("]\n") {
            Some(end) => rest = rest[end + 2..].trim_start(),
            None => break,
        }
    }
    rest.trim().to_owned()
}

/// The prompt's images as seat-sized JPEGs, shrunk the way a Discord photo
/// is; anything that is not an image is refused, naming what it is.
fn prompt_images(params: &Value) -> Result<Vec<live::ConversationImage>, Refusal> {
    use base64::Engine as _;
    use odin_hermes::runtime::images;
    let refused = |reason: String| (INVALID_PARAMS, format!("the prompt's image {reason}"));
    let blocks: Vec<&Value> = params["prompt"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|block| block["type"] == "image")
        .collect();
    if blocks.len() > images::MAX_TURN_IMAGES {
        return Err((
            INVALID_PARAMS,
            format!(
                "one prompt carries at most {} images",
                images::MAX_TURN_IMAGES
            ),
        ));
    }
    blocks
        .into_iter()
        .map(|block| {
            let mime = block["mimeType"].as_str().unwrap_or("no media type");
            if !mime.starts_with("image/") {
                return Err(refused(format!("is {mime}, not an image")));
            }
            let data = block["data"].as_str().ok_or_else(|| {
                refused("carries no data (a uri alone is not fetched)".to_owned())
            })?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|error| refused(format!("is not base64: {error}")))?;
            let limit = odin_hermes::account::MAX_ATTACHMENT_BYTES;
            if bytes.len() as u64 > limit {
                return Err(refused(format!(
                    "is {} bytes, over the {limit} byte limit",
                    bytes.len()
                )));
            }
            let jpeg = images::view_jpeg(&bytes, images::TURN_IMAGE_BASE64).map_err(refused)?;
            Ok(live::ConversationImage {
                mime_type: "image/jpeg".to_owned(),
                data: base64::engine::general_purpose::STANDARD.encode(jpeg),
            })
        })
        .collect()
}

/// A tool call's content: its text, then a `resource_link` per image it
/// returned: an artifact by its Odin id, an inline image as a `data:` URI.
/// Agmente renders only text (Agmente/SessionSupplementalViews.swift `MarkdownText`),
/// so a WebSocket client also gets each image as a tappable link ([`Peer::link_images`]).
fn tool_content(text: &str, blocks: &[live::LiveContentBlock]) -> Vec<Value> {
    let link = |uri: String, name: &str, mime: &str, size: Option<u64>| {
        json!({"type": "content", "content": {"type": "resource_link",
            "uri": uri, "name": name, "mimeType": mime, "size": size}})
    };
    let artifact = |id: &odin_domain::ArtifactId| format!("odin://artifact/{id}");
    std::iter::once(json!({"type": "content", "content": {"type": "text", "text": text}}))
        .chain(blocks.iter().filter_map(|block| match block {
            live::LiveContentBlock::Image { mime_type, data } => Some(link(
                format!("data:{mime_type};base64,{data}"),
                "image",
                mime_type,
                None,
            )),
            live::LiveContentBlock::Render(render) if render.media_type.starts_with("image/") => {
                Some(link(
                    artifact(&render.artifact_id),
                    &render.render_id.to_string(),
                    &render.media_type,
                    Some(render.byte_len),
                ))
            }
            live::LiveContentBlock::File(file) if file.media_type.starts_with("image/") => {
                Some(link(
                    artifact(&file.artifact_id),
                    &file.display_name,
                    &file.media_type,
                    Some(file.byte_len),
                ))
            }
            _ => None,
        }))
        .collect()
}

/// One image block's name, media type and bytes: inline data decoded, an artifact downloaded.
async fn image_bytes(
    client: &Client,
    block: &live::LiveContentBlock,
) -> Result<(String, String, Vec<u8>), String> {
    use base64::Engine as _;
    let (name, mime, artifact) = match block {
        live::LiveContentBlock::Image { mime_type, data } => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|error| format!("its data is not base64: {error}"))?;
            return Ok(("image".to_owned(), mime_type.clone(), bytes));
        }
        live::LiveContentBlock::Render(render) => (
            render.render_id.to_string(),
            render.media_type.clone(),
            render.artifact_id.clone(),
        ),
        live::LiveContentBlock::File(file) => (
            file.display_name.clone(),
            file.media_type.clone(),
            file.artifact_id.clone(),
        ),
        _ => return Err("it is not an image".to_owned()),
    };
    let mut sink = odin_huginn::client::MemorySink::new(odin_registry::schema::MAX_FRAME_BYTES);
    client
        .download(live::ContentSource::Artifact(artifact), &mut sink)
        .await
        .map_err(|error| error.to_string())?;
    Ok((name, mime, sink.into_bytes()))
}

/// The prompt's text blocks, with any linked resource named by its URI.
fn prompt_text(params: &Value) -> String {
    params["prompt"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|block| match block["type"].as_str() {
            Some("text") => block["text"].as_str().map(str::to_owned),
            Some("resource_link") => block["uri"].as_str().map(str::to_owned),
            Some("resource") => block["resource"]["text"].as_str().map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prompt_is_its_text_and_an_echo_loses_the_runtime_prefix() {
        let params = json!({"sessionId": "s", "prompt": [
            {"type": "text", "text": "weather tomorrow?"},
            {"type": "resource_link", "uri": "file:///tmp/a.pdf", "name": "a.pdf"},
        ]});
        assert_eq!(prompt_text(&params), "weather tomorrow?\nfile:///tmp/a.pdf");
        assert_eq!(
            owner_words(
                "[the owner's local time: Friday] [You are running on x]\nTurn off the monitors"
            ),
            "Turn off the monitors"
        );
        assert_eq!(owner_words("plain"), "plain");
    }

    /// A 1x1 PNG.
    const PNG: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    #[test]
    fn a_prompt_image_becomes_a_seat_sized_jpeg_and_a_pdf_is_refused() {
        use base64::Engine as _;
        let params = json!({"sessionId": "s", "prompt": [
            {"type": "text", "text": "what is this?"},
            {"type": "image", "mimeType": "image/png", "data": PNG},
        ]});
        let images = prompt_images(&params).unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].mime_type, "image/jpeg");
        let jpeg = base64::engine::general_purpose::STANDARD
            .decode(&images[0].data)
            .unwrap();
        assert_eq!(&jpeg[..2], &[0xff, 0xd8], "a JPEG");
        assert_eq!(prompt_text(&params), "what is this?");
        let pdf =
            json!({"prompt": [{"type": "image", "mimeType": "application/pdf", "data": PNG}]});
        let (code, reason) = prompt_images(&pdf).unwrap_err();
        assert_eq!(code, INVALID_PARAMS);
        assert!(reason.contains("application/pdf, not an image"), "{reason}");
    }

    #[test]
    fn a_shelved_image_opens_by_its_token_until_newer_ones_push_it_out() {
        let shelf = Shelf::new(2);
        let first = shelf.put("image/png", vec![1]);
        let second = shelf.put("image/png", vec![2]);
        assert_eq!(shelf.get(&second), Some(("image/png".to_owned(), vec![2])));
        assert!(shelf.get("not-a-token").is_none());
        shelf.put("image/png", vec![3]);
        assert!(shelf.get(&first).is_none(), "the oldest left the shelf");
        assert!(first.len() >= 64, "a token is unguessable");
    }

    #[test]
    fn a_render_result_streams_as_a_resource_link() {
        let render = live::RenderManifest::new(live::RenderManifestInit {
            render_id: live::RenderId::new(uuid::Uuid::new_v4()).unwrap(),
            command_id: odin_domain::CommandId::new("command:render-1").unwrap(),
            renderer: live::RendererId::parse("field").unwrap(),
            renderer_version: "1".to_owned(),
            kind: live::RenderKind::RasterImage,
            media_type: "image/png".to_owned(),
            byte_len: 3 << 20,
            content_digest: odin_domain::Digest::hash(b"frame"),
            artifact_id: odin_domain::ArtifactId::new("artifact:frame17").unwrap(),
            completed_at: time::OffsetDateTime::now_utc(),
        })
        .unwrap();
        let content = tool_content(
            "rendered",
            &[
                live::LiveContentBlock::Text("rendered".to_owned()),
                live::LiveContentBlock::Render(render),
                live::LiveContentBlock::Image {
                    mime_type: "image/png".to_owned(),
                    data: PNG.to_owned(),
                },
            ],
        );
        assert_eq!(content.len(), 3, "{content:?}");
        assert_eq!(
            content[0]["content"],
            json!({"type": "text", "text": "rendered"}),
            "Agmente shows the first text block"
        );
        let link = &content[1]["content"];
        assert_eq!(link["type"], "resource_link");
        assert_eq!(link["uri"], "odin://artifact/artifact:frame17");
        assert_eq!(link["mimeType"], "image/png");
        assert_eq!(link["size"], 3 << 20);
        let inline = &content[2]["content"];
        assert_eq!(inline["type"], "resource_link");
        assert_eq!(inline["uri"], format!("data:image/png;base64,{PNG}"));
    }

    #[test]
    fn a_token_file_is_made_owner_only_and_read_back() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acp/token");
        let made = token(&path).unwrap();
        assert_eq!(made.len(), 64);
        assert_eq!(token(&path).unwrap(), made);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::write(&path, "short").unwrap();
        assert!(token(&path).is_err());
    }
}
