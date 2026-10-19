//! Private loopback Discord for the scheduled-notification consumer tests:
//! a real HTTP server the production `DiscordRestTransport` talks to, so a
//! reminder takes the same path to the wire it takes in the daemon. Nothing
//! here reaches beyond 127.0.0.1 and no credential is real.
//!
//! The server runs on its own thread and runtime and stops on a fuse that
//! `Drop` pulls and joins, so a failing test can neither hang nor leak it.
//! The gated sink and the joined helper thread follow the same rule: every
//! wait has a hard cap, and the fuse is released before any join.

use async_trait::async_trait;
use odin_hermes::discord::{DiscordCredential, DiscordRestTransport, SecretToken};
use odin_hermes::egress::{
    DeliveryCheckpoint, DiscordEgressSink, EgressError, OutboundMessage, OutgoingSink, ReplyChunks,
};
use parking_lot::{Condvar, Mutex};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The hard cap on every fixture wait: long enough for a loaded machine,
/// short enough that a broken baseline fails instead of hanging the suite.
pub(crate) const FUSE_CAP: Duration = Duration::from_secs(30);

/// How the loopback answers one POST.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PostReply {
    /// The message is posted and the reply says so.
    Accept,
    /// The message IS posted, but the reply is a 500: the client cannot
    /// know whether it landed.
    LoseReply,
    /// A 400 before anything is posted: the client knows nothing landed.
    Refuse,
}

/// One POST the server saw, in arrival order, whatever its fate.
#[derive(Clone, Debug)]
pub(crate) struct PostAttempt {
    pub(crate) channel_id: String,
    pub(crate) content: String,
    pub(crate) reply: PostReply,
}

#[derive(Default)]
struct Wire {
    script: VecDeque<PostReply>,
    default_reply: Option<PostReply>,
    attempts: Vec<PostAttempt>,
    patches: Vec<(String, String)>,
    deletes: Vec<String>,
}

pub(crate) struct LoopbackDiscord {
    api_base: String,
    wire: Arc<Mutex<Wire>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LoopbackDiscord {
    pub(crate) fn start() -> Self {
        let wire = Arc::new(Mutex::new(Wire::default()));
        let next_id = Arc::new(AtomicU64::new(1_200_000_000_000_000_000));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<String>();
        let served = Arc::clone(&wire);
        let thread = std::thread::Builder::new()
            .name("loopback-discord".to_owned())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("loopback runtime");
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("loopback bind");
                    let address = listener.local_addr().expect("loopback address");
                    let app = router(served, next_id);
                    ready_tx
                        .send(format!("http://{address}"))
                        .expect("loopback ready");
                    tokio::select! {
                        _ = async { let _ = axum::serve(listener, app.into_make_service()).await; } => {}
                        _ = stopped => {}
                    }
                });
            })
            .expect("loopback thread");
        let api_base = ready_rx
            .recv_timeout(FUSE_CAP)
            .expect("loopback server did not start");
        Self {
            api_base,
            wire,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// The next POSTs answer in this order; once spent, [`Self::answer_all`]
    /// (default: accept) decides.
    pub(crate) fn script(&self, replies: &[PostReply]) {
        self.wire.lock().script.extend(replies.iter().copied());
    }

    pub(crate) fn answer_all(&self, reply: PostReply) {
        self.wire.lock().default_reply = Some(reply);
    }

    /// A fresh production sink over the production Discord transport,
    /// pointed at this server: what a reopened daemon rebinds.
    pub(crate) fn sink(&self) -> Arc<DiscordEgressSink> {
        let transport = DiscordRestTransport::with_api_base(
            DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                SecretToken::new("loopback-token").unwrap(),
            ),
            reqwest::Client::new(),
            self.api_base.clone(),
        )
        .unwrap();
        Arc::new(DiscordEgressSink::new(Arc::new(transport)))
    }

    /// Every POST the server saw, refused ones included.
    pub(crate) fn attempts(&self) -> Vec<PostAttempt> {
        self.wire.lock().attempts.clone()
    }

    /// The contents of the messages that physically exist in the channel:
    /// accepted and lost-reply POSTs, in order. A refused POST is not here.
    pub(crate) fn posted(&self) -> Vec<String> {
        self.wire
            .lock()
            .attempts
            .iter()
            .filter(|attempt| attempt.reply != PostReply::Refuse)
            .map(|attempt| attempt.content.clone())
            .collect()
    }

    /// Edits and deletes the server saw. A scheduled notification is posted
    /// once and never reworded, so both stay empty.
    pub(crate) fn rewrites(&self) -> (Vec<(String, String)>, Vec<String>) {
        let wire = self.wire.lock();
        (wire.patches.clone(), wire.deletes.clone())
    }
}

impl Drop for LoopbackDiscord {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn router(wire: Arc<Mutex<Wire>>, next_id: Arc<AtomicU64>) -> axum::Router {
    use axum::response::IntoResponse;
    let posts = {
        let wire = Arc::clone(&wire);
        axum::routing::post(
            move |axum::extract::Path(channel_id): axum::extract::Path<String>,
                  axum::Json(body): axum::Json<Value>| {
                let wire = Arc::clone(&wire);
                let next_id = Arc::clone(&next_id);
                async move {
                    let content = body["content"].as_str().unwrap_or_default().to_owned();
                    let reply = {
                        let mut wire = wire.lock();
                        let reply = wire
                            .script
                            .pop_front()
                            .or(wire.default_reply)
                            .unwrap_or(PostReply::Accept);
                        wire.attempts.push(PostAttempt {
                            channel_id: channel_id.clone(),
                            content,
                            reply,
                        });
                        reply
                    };
                    match reply {
                        PostReply::Accept => {
                            let id = next_id.fetch_add(1, Ordering::SeqCst).to_string();
                            axum::Json(json!({ "id": id, "channel_id": channel_id }))
                                .into_response()
                        }
                        PostReply::LoseReply => {
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
                        }
                        PostReply::Refuse => (
                            axum::http::StatusCode::BAD_REQUEST,
                            axum::Json(json!({ "code": 50035, "message": "Invalid Form Body" })),
                        )
                            .into_response(),
                    }
                }
            },
        )
    };
    let edits = {
        let wire = Arc::clone(&wire);
        axum::routing::patch(
            move |axum::extract::Path((channel_id, message_id)): axum::extract::Path<(
                String,
                String,
            )>,
                  axum::Json(body): axum::Json<Value>| {
                let wire = Arc::clone(&wire);
                async move {
                    wire.lock().patches.push((
                        message_id.clone(),
                        body["content"].as_str().unwrap_or_default().to_owned(),
                    ));
                    axum::Json(json!({ "id": message_id, "channel_id": channel_id }))
                }
            },
        )
    };
    let deletes = axum::routing::delete(
        move |axum::extract::Path((_, message_id)): axum::extract::Path<(String, String)>| {
            let wire = Arc::clone(&wire);
            async move {
                wire.lock().deletes.push(message_id);
                axum::http::StatusCode::NO_CONTENT
            }
        },
    );
    axum::Router::new()
        .route("/channels/{channel_id}/messages", posts)
        .route(
            "/channels/{channel_id}/messages/{message_id}",
            edits.merge(deletes),
        )
}

/// A one-way latch that releases every waiter and stays released.
#[derive(Clone, Default)]
pub(crate) struct Fuse {
    released: Arc<(Mutex<bool>, Condvar)>,
}

impl Fuse {
    pub(crate) fn release(&self) {
        *self.released.0.lock() = true;
        self.released.1.notify_all();
    }

    /// Blocks until released; false when the cap passed first.
    fn wait(&self, cap: Duration) -> bool {
        let deadline = Instant::now() + cap;
        let mut released = self.released.0.lock();
        while !*released {
            if self
                .released
                .1
                .wait_until(&mut released, deadline)
                .timed_out()
            {
                return *released;
            }
        }
        true
    }
}

/// The production Discord sink behind a gate: `deliver` announces it was
/// entered, waits for the fuse, and only then reaches the wire. While it
/// waits, the notify worker is busy inside the sink exactly as it is when
/// Discord stalls, and nothing has been sent.
pub(crate) struct GatedSink {
    inner: Arc<DiscordEgressSink>,
    fuse: Fuse,
    entered: Arc<(Mutex<usize>, Condvar)>,
}

impl GatedSink {
    pub(crate) fn new(inner: Arc<DiscordEgressSink>, fuse: &Fuse) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fuse: fuse.clone(),
            entered: Arc::new((Mutex::new(0), Condvar::new())),
        })
    }

    /// Blocks until `count` deliveries have entered the gate.
    pub(crate) fn wait_entered(&self, count: usize) -> bool {
        let deadline = Instant::now() + FUSE_CAP;
        let mut entered = self.entered.0.lock();
        while *entered < count {
            if self
                .entered
                .1
                .wait_until(&mut entered, deadline)
                .timed_out()
            {
                return *entered >= count;
            }
        }
        true
    }
}

#[async_trait]
impl OutgoingSink for GatedSink {
    async fn deliver(
        &self,
        message: OutboundMessage,
        checkpoint: Arc<dyn DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        *self.entered.0.lock() += 1;
        self.entered.1.notify_all();
        if !self.fuse.wait(FUSE_CAP) {
            return Err(EgressError::InvalidState("release fuse cap elapsed"));
        }
        self.inner.deliver(message, checkpoint).await
    }

    async fn send(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
        *self.entered.0.lock() += 1;
        self.entered.1.notify_all();
        if !self.fuse.wait(FUSE_CAP) {
            return Err(EgressError::InvalidState("release fuse cap elapsed"));
        }
        self.inner.send(message).await
    }

    async fn edit(
        &self,
        current: &ReplyChunks,
        message: OutboundMessage,
    ) -> Result<ReplyChunks, EgressError> {
        self.inner.edit(current, message).await
    }

    async fn typing(&self, channel_id: &str) -> Result<(), EgressError> {
        self.inner.typing(channel_id).await
    }
}

/// A test-owned helper thread. Dropping it, including on a panic, releases
/// the fuse first and then joins, so no helper is left blocked or detached.
pub(crate) struct Helper<T: Send + 'static> {
    fuse: Fuse,
    handle: Option<std::thread::JoinHandle<T>>,
}

impl<T: Send + 'static> Helper<T> {
    pub(crate) fn spawn(fuse: &Fuse, work: impl FnOnce() -> T + Send + 'static) -> Self {
        Self {
            fuse: fuse.clone(),
            handle: Some(std::thread::spawn(work)),
        }
    }

    /// Releases the fuse, then waits for the helper's result.
    pub(crate) fn finish(mut self) -> T {
        self.fuse.release();
        self.handle
            .take()
            .expect("helper joined once")
            .join()
            .expect("helper thread panicked")
    }
}

impl<T: Send + 'static> Drop for Helper<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.fuse.release();
            let _ = handle.join();
        }
    }
}
