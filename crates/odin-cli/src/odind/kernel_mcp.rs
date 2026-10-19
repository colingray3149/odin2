//! odind's kernel MCP listener: the one loopback
//! socket non-OMP harness sessions reach their seat's Odin functions on.
//! The protocol, the per-session bearer and the governed dispatch live in
//! `odin_omp::live::kernel_mcp`; this module only binds the socket and
//! moves bytes. It is deliberately NOT the Huginn listener: that one is
//! published to the tailnet by `tailscale serve`, this one never leaves the
//! host. A fixed port keeps a terminal session's config valid across an
//! odind restart (its agent read the URL once).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use odin_omp::live::kernel_mcp::{KernelMcpServer, McpReply};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub(crate) const KERNEL_MCP_ADDRESS: &str = "127.0.0.1:18430";
/// The kernel bridge's port on the node's pod-facing address.
pub(crate) const KERNEL_MCP_PORT: u16 = 18430;

pub(crate) fn base_url(address: SocketAddr) -> String {
    format!("http://{address}")
}

/// One daemon's ledger of in-flight governed dispatches: registered
/// before the blocking closure spawns, released only as that closure
/// exits — whatever the HTTP connection does. Admission, closing and
/// counting share one linearized state: once [`KernelDispatches::close`]
/// returns, nothing registers any more, and [`KernelDispatches::drained`]
/// speaks only for a closed, emptied ledger.
#[derive(Clone)]
pub(crate) struct KernelDispatches {
    inner: Arc<DispatchLedger>,
}

/// The ledger's whole state, watched as one: never read piecemeal.
#[derive(Clone, Copy)]
struct LedgerState {
    closing: bool,
    active: usize,
}

struct DispatchLedger {
    state: tokio::sync::watch::Sender<LedgerState>,
}

impl KernelDispatches {
    pub(crate) fn new() -> Self {
        let (state, _) = tokio::sync::watch::channel(LedgerState {
            closing: false,
            active: 0,
        });
        Self {
            inner: Arc::new(DispatchLedger { state }),
        }
    }

    /// Closes admission; the drain then only awaits the exits.
    pub(crate) fn close(&self) {
        self.inner.state.send_modify(|state| state.closing = true);
    }

    /// Resolves once the ledger is closed and every registered dispatch
    /// exited.
    pub(crate) async fn drained(&self) {
        // A dropped ledger is gone with its daemon: nothing can change.
        let _ = self
            .inner
            .state
            .subscribe()
            .wait_for(|state| state.closing && state.active == 0)
            .await;
    }

    /// Shutdown stragglers, including dispatches whose HTTP handlers have ended.
    pub(crate) fn active(&self) -> usize {
        self.inner.state.borrow().active
    }

    /// Registers one dispatch unless closing, in the same linearized step
    /// as the close itself; the guard moves into the blocking closure, so
    /// a dropped HTTP handler cannot release it.
    fn admit(&self) -> Option<KernelDispatch> {
        let mut admitted = false;
        self.inner.state.send_modify(|state| {
            if !state.closing {
                state.active += 1;
                admitted = true;
            }
        });
        admitted.then(|| KernelDispatch {
            dispatches: self.clone(),
        })
    }
}

/// One registered dispatch: dropping it is the closure's exit.
struct KernelDispatch {
    dispatches: KernelDispatches,
}

impl Drop for KernelDispatch {
    fn drop(&mut self) {
        self.dispatches
            .inner
            .state
            .send_modify(|state| state.active = state.active.saturating_sub(1));
    }
}

/// One daemon's kernel MCP bridge as the main seam owns it: the spawned
/// listeners for the bounded join, and the ledger to close and drain.
pub(crate) struct KernelMcpBridge {
    /// The loopback and node serve tasks, joined under the stop deadline.
    pub(crate) listeners: Vec<JoinHandle<()>>,
    /// The daemon's dispatch ledger: closed at the stop, drained before
    /// the authority retires.
    pub(crate) dispatches: KernelDispatches,
}

pub(crate) fn router(server: Arc<KernelMcpServer>, dispatches: KernelDispatches) -> Router {
    Router::new()
        .route(
            "/mcp/{session}",
            post(call).get(not_served).delete(not_served),
        )
        .fallback(unknown_path)
        .with_state((server, dispatches))
}

/// Binds the loopback listener and serves it until the owning daemon
/// resolves its stop token: accepting stops and the socket closes at the
/// token, the serve task ends once its connections drained, and the
/// handle is the owning shutdown's bounded join point. The governed
/// calls outlive this join on the daemon's dispatch ledger, whose drain
/// — not the join — is their evidence. A bind failure is returned typed;
/// harness sessions then run without the bridge.
pub(crate) async fn serve(
    address: SocketAddr,
    server: Arc<KernelMcpServer>,
    dispatches: KernelDispatches,
    stopping: watch::Receiver<bool>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the kernel MCP bridge binds loopback only, not {address}"),
        ));
    }
    listen(address, server, dispatches, stopping).await
}

/// The node-reachable listener terminal pods use:
/// a pod cannot reach the host's loopback, so the same bridge also binds
/// the node's declared pod-facing address (its gateway endpoint host, the
/// tailnet IP the node firewall admits the pod CIDR to). Every call still
/// needs its session's bearer; an unspecified address is refused. The
/// stop token, dispatch ledger and join handle are [`serve`]'s.
pub(crate) async fn serve_node(
    address: SocketAddr,
    server: Arc<KernelMcpServer>,
    dispatches: KernelDispatches,
    stopping: watch::Receiver<bool>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    if address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the kernel MCP bridge binds one declared node address, not {address}"),
        ));
    }
    listen(address, server, dispatches, stopping).await
}

/// Stop accepting immediately on cancellation, then drain connections.
/// Joining this task does not establish that blocking dispatches have ended;
/// those remain tracked independently in the ledger.
async fn listen(
    address: SocketAddr,
    server: Arc<KernelMcpServer>,
    dispatches: KernelDispatches,
    stopping: watch::Receiver<bool>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind(address).await?;
    let bound = listener.local_addr()?;
    tracing::info!("mcp listening address={bound}");
    let handle = tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router(server, dispatches))
            .with_graceful_shutdown(stopped(stopping))
            .await
        {
            tracing::error!("mcp listener stopped error=\"{error}\"");
        }
    });
    Ok((bound, handle))
}

/// Resolves when the daemon's stop token flips; a sender dropped before
/// any signal resolves it too, so a listener never outlives its daemon.
async fn stopped(mut stopping: watch::Receiver<bool>) {
    while !*stopping.borrow_and_update() {
        if stopping.changed().await.is_err() {
            break;
        }
    }
}

fn reply(reply: McpReply) -> Response {
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match reply.body {
        Some(body) => (status, Json(body)).into_response(),
        None => status.into_response(),
    }
}

/// Browsers are not clients: a request carrying a non-loopback Origin is a
/// page trying the loopback port (DNS rebinding), refused before auth.
fn foreign_origin(headers: &HeaderMap) -> Option<String> {
    let origin = headers.get(header::ORIGIN)?.to_str().unwrap_or("?");
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            origin == *prefix
                || origin
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with(':'))
        });
    (!loopback).then(|| origin.to_owned())
}

async fn call(
    State((server, dispatches)): State<(Arc<KernelMcpServer>, KernelDispatches)>,
    Path(session): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(origin) = foreign_origin(&headers) {
        tracing::error!("mcp refused session={session} reason=foreign_origin origin={origin}");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "foreign_origin"})),
        )
            .into_response();
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // A tool call runs the governed dispatch (ledger, kernel, adapters):
    // registered on the daemon's ledger before the blocking closure
    // spawns and released only as that closure exits, so a reset socket
    // drops the connection, never the daemon's drain evidence. A closed
    // ledger refuses fresh work outright.
    let Some(dispatch) = dispatches.admit() else {
        tracing::error!("mcp refused session={session} reason=closing");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "closing"})),
        )
            .into_response();
    };
    match tokio::task::spawn_blocking(move || {
        let _dispatch = dispatch; // lives to this closure's exit
        server.handle(&session, authorization.as_deref(), &body)
    })
    .await
    {
        Ok(answer) => reply(answer),
        Err(error) => {
            tracing::error!("mcp handler failed error=\"{error}\"");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// No server-initiated stream and no session to delete: the bridge answers
/// every POST with JSON.
async fn not_served(Path(session): Path<String>) -> Response {
    tracing::error!("mcp refused session={session} reason=method_not_allowed");
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

async fn unknown_path(uri: axum::http::Uri) -> Response {
    tracing::error!("mcp refused path={} reason=unknown_path", uri.path());
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "unknown_path"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::KernelDispatches;
    use odin_omp::live::kernel_mcp::{KernelMcpServer, KernelSession};
    use tokio::sync::{watch, Notify};
    use tokio::time::timeout;

    /// The generous real-socket bound a test grants its listener to end.
    const LISTENER_END: Duration = Duration::from_secs(5);

    /// Allow the listener to observe shutdown while a parked call prevents draining.
    const STOP_HOLD: Duration = Duration::from_millis(500);

    /// A lost release must unblock the thread rather than hang runtime shutdown.
    const PARKED_DISPATCH: Duration = Duration::from_secs(30);

    struct NoTools;

    impl KernelSession for NoTools {
        fn tools(
            &self,
        ) -> Result<
            Vec<odin_omp::host_tools::RpcHostToolDefinition>,
            odin_omp::host_tools::operations::HostToolOperationError,
        > {
            Ok(Vec::new())
        }

        fn call(
            &self,
            tool: &str,
            _arguments: serde_json::Value,
            _request_id: &str,
        ) -> Result<serde_json::Value, odin_omp::host_tools::operations::HostToolOperationError>
        {
            Err(
                odin_omp::host_tools::operations::HostToolOperationError::UnknownTool {
                    name: tool.to_owned(),
                },
            )
        }
    }

    /// A tool call that parks in the governed dispatch until the test
    /// releases it — by a send on the release channel, or by the sender's
    /// drop when the test panics: the in-flight work a graceful stop must
    /// outlive.
    struct Parked {
        entered: Notify,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl KernelSession for Parked {
        fn tools(
            &self,
        ) -> Result<
            Vec<odin_omp::host_tools::RpcHostToolDefinition>,
            odin_omp::host_tools::operations::HostToolOperationError,
        > {
            Ok(Vec::new())
        }

        fn call(
            &self,
            tool: &str,
            _arguments: serde_json::Value,
            _request_id: &str,
        ) -> Result<serde_json::Value, odin_omp::host_tools::operations::HostToolOperationError>
        {
            self.entered.notify_one();
            // The park is bounded: a lost release — or the panicking
            // test's dropped sender — unparks this blocking thread
            // instead of hanging the runtime's shutdown.
            let _ = self
                .release
                .lock()
                .expect("release lock")
                .recv_timeout(PARKED_DISPATCH);
            Err(
                odin_omp::host_tools::operations::HostToolOperationError::UnknownTool {
                    name: tool.to_owned(),
                },
            )
        }
    }

    /// Binds one daemon's loopback listener on its own stop token and
    /// dispatch ledger.
    async fn serve_daemon(
        server: Arc<KernelMcpServer>,
    ) -> (
        watch::Sender<bool>,
        KernelDispatches,
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
    ) {
        let (stop, stopping) = watch::channel(false);
        let dispatches = KernelDispatches::new();
        let serve = super::serve(
            "127.0.0.1:0".parse().expect("address"),
            server,
            dispatches.clone(),
            stopping,
        );
        let (bound, handle) = timeout(LISTENER_END, serve)
            .await
            .expect("the bind is bounded")
            .expect("bind");
        (stop, dispatches, bound, handle)
    }

    /// Resolves the token and waits for the listener to end: its socket is
    /// closed when this returns.
    async fn stop_daemon(stop: watch::Sender<bool>, handle: tokio::task::JoinHandle<()>) {
        stop.send(true).expect("the daemon's own token is alive");
        timeout(LISTENER_END, handle)
            .await
            .expect("the listener ends once its token resolves")
            .expect("the serve task never panics");
    }

    /// One client for every request: its timeout bounds each send and
    /// body read, so a listener that stops answering fails an assertion
    /// instead of hanging the test.
    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(LISTENER_END)
            .build()
            .expect("the test client builds")
    }

    /// A POST to an unregistered session proves a listener is still
    /// accepting: the bridge answers `404` (unknown_session) before any
    /// bearer is checked.
    async fn probe(listener: std::net::SocketAddr) -> reqwest::Response {
        client()
            .post(format!("http://{listener}/mcp/none"))
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
            .send()
            .await
            .expect("the listener is accepting")
    }

    /// A stopped listener refuses a fresh client outright: its socket is
    /// closed, nothing is accepted any more.
    async fn refuses(listener: std::net::SocketAddr) {
        let refused = client()
            .post(format!("http://{listener}/mcp/none"))
            .send()
            .await;
        assert!(refused.is_err(), "the listener at {listener} is closed");
    }

    /// The listener moves bytes to the protocol handler and back over a
    /// real loopback socket: auth, JSON answers, `202` notifications,
    /// refused methods, paths and foreign origins.
    #[tokio::test]
    async fn the_listener_serves_post_json_and_refuses_everything_else() {
        let server = KernelMcpServer::new("http://127.0.0.1:0");
        let registration = server.register("s1", "class", Arc::new(NoTools), None);
        let (stop, _dispatches, bound, handle) = serve_daemon(Arc::clone(&server)).await;
        let url = format!("http://{bound}/mcp/s1");
        let bearer = format!("Bearer {}", registration.endpoint.bearer);
        let client = client();
        let post = |body: &'static str, auth: Option<&str>, origin: Option<&str>| {
            let mut request = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body);
            if let Some(auth) = auth {
                request = request.header("authorization", auth.to_owned());
            }
            if let Some(origin) = origin {
                request = request.header("origin", origin.to_owned());
            }
            request.send()
        };
        let list = post(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            Some(&bearer),
            None,
        )
        .await
        .expect("list");
        assert_eq!(list.status(), 200);
        let body: serde_json::Value = list.json().await.expect("json");
        assert_eq!(body["result"]["tools"], serde_json::json!([]));
        let notified = post(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            Some(&bearer),
            None,
        )
        .await
        .expect("notify");
        assert_eq!(notified.status(), 202);
        let anonymous = post(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#, None, None)
            .await
            .expect("anonymous");
        assert_eq!(anonymous.status(), 401);
        let rebinding = post(
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
            Some(&bearer),
            Some("http://evil.example"),
        )
        .await
        .expect("origin");
        assert_eq!(rebinding.status(), 403);
        let local = post(
            r#"{"jsonrpc":"2.0","id":4,"method":"ping"}"#,
            Some(&bearer),
            Some("http://127.0.0.1:18430"),
        )
        .await
        .expect("local origin");
        assert_eq!(local.status(), 200);
        let stream = client.get(&url).send().await.expect("get");
        assert_eq!(stream.status(), 405);
        let elsewhere = client
            .post(format!("http://{bound}/other"))
            .send()
            .await
            .expect("other");
        assert_eq!(elsewhere.status(), 404);
        stop_daemon(stop, handle).await;
    }

    /// The owning stop drains the call parked in the governed dispatch
    /// before the listener ends, then refuses every later call.
    #[tokio::test]
    async fn the_owned_stop_drains_the_in_flight_call_then_refuses_new_ones() {
        let server = KernelMcpServer::new("http://127.0.0.1:0");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let parked = Arc::new(Parked {
            entered: Notify::new(),
            release: std::sync::Mutex::new(release_rx),
        });
        let registration = server.register("s1", "class", Arc::<Parked>::clone(&parked), None);
        let (stop, _dispatches, bound, handle) = serve_daemon(Arc::clone(&server)).await;
        let in_flight = tokio::spawn({
            let url = format!("http://{bound}/mcp/s1");
            let bearer = format!("Bearer {}", registration.endpoint.bearer);
            async move {
                client()
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("authorization", bearer)
                    .body(
                        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"parked","arguments":{}}}"#,
                    )
                    .send()
                    .await
                    .expect("the parked call is answered")
            }
        });
        // The call has entered the governed dispatch and parked there:
        // awaiting the signal parks this test task, so the runtime keeps
        // polling the spawned request on this current-thread test.
        timeout(LISTENER_END, parked.entered.notified())
            .await
            .expect("the parked call enters the governed dispatch in time");
        // The daemon resolves its own token while the call is parked.
        stop.send(true).expect("the daemon's own token is alive");
        // A parked call must keep the listener alive after it observes shutdown.
        let held = timeout(STOP_HOLD, async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            held.is_err(),
            "the serve task ends only after the parked call drained"
        );
        release_tx.send(()).expect("release the parked call");
        let answered = timeout(LISTENER_END, in_flight)
            .await
            .expect("the in-flight call survives the resolved token")
            .expect("in-flight response");
        assert_eq!(answered.status(), 200);
        let body: serde_json::Value = answered.json().await.expect("json");
        assert_eq!(body["error"]["code"], serde_json::json!(-32602));
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("parked")),
            "an unknown tool names itself: {body}"
        );
        // The listener ends once drained and closes its socket.
        timeout(LISTENER_END, handle)
            .await
            .expect("the listener ends once the in-flight call drained")
            .expect("the serve task never panics");
        refuses(bound).await;
    }

    /// A reset socket cannot deregister its dispatch: the listener joins
    /// while the disconnected client's governed call is still parked and
    /// registered, and only the closure's exit drains the ledger.
    #[tokio::test]
    async fn a_reset_socket_cannot_deregister_its_dispatch() {
        let server = KernelMcpServer::new("http://127.0.0.1:0");
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let parked = Arc::new(Parked {
            entered: Notify::new(),
            release: std::sync::Mutex::new(release_rx),
        });
        let registration = server.register("s1", "class", Arc::<Parked>::clone(&parked), None);
        let (stop, dispatches, bound, mut handle) = serve_daemon(Arc::clone(&server)).await;
        let in_flight = tokio::spawn({
            let url = format!("http://{bound}/mcp/s1");
            let bearer = format!("Bearer {}", registration.endpoint.bearer);
            async move {
                client()
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("authorization", bearer)
                    .body(
                        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"parked","arguments":{}}}"#,
                    )
                    .send()
                    .await
                    .expect("the parked call is answered")
            }
        });
        timeout(LISTENER_END, parked.entered.notified())
            .await
            .expect("the parked call enters the governed dispatch in time");
        assert_eq!(
            dispatches.active(),
            1,
            "the parked call is registered on the daemon's ledger"
        );
        // The daemon stops, and the client resets its socket: the HTTP
        // handler is dropped, the blocking dispatch is not.
        stop.send(true).expect("the daemon's own token is alive");
        dispatches.close();
        in_flight.abort();
        timeout(LISTENER_END, &mut handle)
            .await
            .expect("the reset socket does not keep the listener alive")
            .expect("the serve task never panics");
        assert_eq!(
            dispatches.active(),
            1,
            "the reset dispatch is still on the ledger"
        );
        // The listener is gone; the disconnected call is still owed: the
        // ledger does not drain until the release.
        let held = timeout(STOP_HOLD, dispatches.drained()).await;
        assert!(
            held.is_err(),
            "a dispatch outlives the socket that carried it"
        );
        release_tx.send(()).expect("release the parked call");
        timeout(LISTENER_END, dispatches.drained())
            .await
            .expect("the released dispatch drains in time");
        refuses(bound).await;
    }

    /// The drain only speaks for a ledger the daemon closed: an open one
    /// is never a drained one, and the closed empty one drains at once.
    #[tokio::test]
    async fn an_open_ledger_is_never_a_drained_one() {
        let dispatches = KernelDispatches::new();
        let held = timeout(STOP_HOLD, dispatches.drained()).await;
        assert!(held.is_err(), "the drain demands the daemon's close first");
        dispatches.close();
        timeout(STOP_HOLD, dispatches.drained())
            .await
            .expect("the closed empty ledger drains at once");
    }

    /// Admission and closing are one linearized ledger state: once the
    /// close returns, nothing registers any more, and the drain only
    /// speaks for a closed, emptied ledger.
    #[tokio::test]
    async fn a_closed_ledger_admits_nothing_beyond_the_race() {
        let dispatches = Arc::new(KernelDispatches::new());
        let workers: Vec<tokio::task::JoinHandle<usize>> = (0..8)
            .map(|_| {
                let dispatches = Arc::clone(&dispatches);
                tokio::spawn(async move {
                    // Held guards: the close races real, counted work.
                    let guards: Vec<_> = (0..64).filter_map(|_| dispatches.admit()).collect();
                    for _ in 0..8 {
                        tokio::task::yield_now().await;
                    }
                    guards.len()
                })
            })
            .collect();
        // Yield the race room, then close: from this return on, the
        // ledger refuses every admission, whatever a worker was doing.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        dispatches.close();
        assert!(
            dispatches.admit().is_none(),
            "a closed ledger refuses admission"
        );
        for worker in workers {
            timeout(LISTENER_END, worker)
                .await
                .expect("the racing worker joins in time")
                .expect("the racing worker never panics");
        }
        assert_eq!(
            dispatches.active(),
            0,
            "every admitted guard dropped with its worker"
        );
        timeout(STOP_HOLD, dispatches.drained())
            .await
            .expect("the closed emptied ledger drains");
        // And a closed ledger keeps refusing: the shutdown cannot be
        // reopened by traffic.
        let late: Vec<_> = (0..4)
            .map(|_| {
                let dispatches = Arc::clone(&dispatches);
                tokio::spawn(async move { dispatches.admit().is_none() })
            })
            .collect();
        for worker in late {
            assert!(
                timeout(LISTENER_END, worker)
                    .await
                    .expect("the late worker joins in time")
                    .expect("the late worker never panics"),
                "a closed ledger refuses late admission"
            );
        }
        assert_eq!(dispatches.active(), 0, "no late admission registered");
    }

    /// One daemon's one token ends every listener it owns — loopback and
    /// the node address — and closes both sockets.
    #[tokio::test]
    async fn the_owned_stop_ends_every_listener_of_its_daemon() {
        let server = KernelMcpServer::new("http://127.0.0.1:0");
        let (stop, stopping) = watch::channel(false);
        let dispatches = KernelDispatches::new();
        let loopback_serve = super::serve(
            "127.0.0.1:0".parse().expect("address"),
            Arc::clone(&server),
            dispatches.clone(),
            stopping.clone(),
        );
        let (loopback, loopback_handle) = timeout(LISTENER_END, loopback_serve)
            .await
            .expect("the loopback bind is bounded")
            .expect("loopback bind");
        let node_serve = super::serve_node(
            "127.0.0.1:0".parse().expect("address"),
            Arc::clone(&server),
            dispatches.clone(),
            stopping,
        );
        let (node, node_handle) = timeout(LISTENER_END, node_serve)
            .await
            .expect("the node bind is bounded")
            .expect("node bind");
        assert_eq!(probe(loopback).await.status(), 404);
        assert_eq!(probe(node).await.status(), 404);
        stop.send(true).expect("the daemon's own token is alive");
        for (listener, handle) in [("loopback", loopback_handle), ("node", node_handle)] {
            timeout(LISTENER_END, handle)
                .await
                .unwrap_or_else(|_| panic!("the {listener} listener ends once its token resolves"))
                .expect("the serve task never panics");
        }
        refuses(loopback).await;
        refuses(node).await;
    }

    /// The stop token is each daemon's own dependency, never a process
    /// global: stopping one daemon leaves an independent one serving.
    #[tokio::test]
    async fn a_daemons_stop_token_is_its_own_never_a_process_global() {
        let (first_stop, _first, first_bound, first_handle) =
            serve_daemon(KernelMcpServer::new("http://127.0.0.1:0")).await;
        let (second_stop, _second, second_bound, second_handle) =
            serve_daemon(KernelMcpServer::new("http://127.0.0.1:0")).await;
        assert_eq!(probe(first_bound).await.status(), 404);
        assert_eq!(probe(second_bound).await.status(), 404);
        stop_daemon(first_stop, first_handle).await;
        refuses(first_bound).await;
        // The independent daemon never noticed the other's stop.
        assert_eq!(probe(second_bound).await.status(), 404);
        stop_daemon(second_stop, second_handle).await;
        refuses(second_bound).await;
    }

    #[tokio::test]
    async fn the_bridge_never_binds_beyond_loopback() {
        let server = KernelMcpServer::new("http://0.0.0.0:1");
        let (_, stopping) = watch::channel(false);
        let error = super::serve(
            "0.0.0.0:0".parse().expect("address"),
            server,
            KernelDispatches::new(),
            stopping,
        )
        .await
        .expect_err("a non-loopback bind is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
