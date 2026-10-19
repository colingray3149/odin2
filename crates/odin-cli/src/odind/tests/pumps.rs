//! Fatal gateway closes alert once and park; recoverable closes redial without alerts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::{ObjectKind, ObjectSnapshot};
use odin_hermes::discord::{
    DiscordCredential, DiscordGateway, DiscordIngressSink, GatewayOwnership, SecretToken,
    DEFAULT_GATEWAY_INTENTS,
};
use odin_huginn::incidents::{IncidentSeverityView, IncidentView};
use odin_huginn::read_model::MaterializedReadModel;
use serde_json::{json, Value};
use time::OffsetDateTime;

struct NoIntake;

impl DiscordIngressSink for NoIntake {
    fn message(&self, _message: odin_hermes::discord::DiscordMessage) {}
}

fn hello(interval_ms: u64) -> Value {
    json!({"op": 10, "d": {"heartbeat_interval": interval_ms, "_trace": ["test"]}})
}

async fn read_gateway_frame(
    socket: &mut axum::extract::ws::WebSocket,
    timeout_ms: u64,
) -> Option<Value> {
    let received = tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv())
        .await
        .ok()?
        .and_then(|received| received.ok())?;
    match received {
        axum::extract::ws::Message::Text(text) => serde_json::from_str::<Value>(&text).ok(),
        _ => None,
    }
}

async fn send_gateway_frame(socket: &mut axum::extract::ws::WebSocket, frame: &Value) {
    let _ = socket
        .send(axum::extract::ws::Message::Text(frame.to_string().into()))
        .await;
}

fn discord_close(code: u16, reason: &'static str) -> axum::extract::ws::Message {
    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// Every connection gets HELLO, must IDENTIFY, and is closed with the
/// scripted code; the connection count is the retry observable.
async fn closing_gateway_server(
    listener: tokio::net::TcpListener,
    connections: Arc<AtomicU64>,
    close_code: u16,
    close_reason: &'static str,
) {
    let app = axum::Router::new().route(
        "/gateway",
        axum::routing::get(move |ws: axum::extract::ws::WebSocketUpgrade| {
            let connections = Arc::clone(&connections);
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    connections.fetch_add(1, Ordering::SeqCst);
                    send_gateway_frame(&mut socket, &hello(1_000)).await;
                    match read_gateway_frame(&mut socket, 2_000).await {
                        Some(identify) if identify["op"] == 2 => {}
                        other => {
                            panic!("expected IDENTIFY, got {other:?}");
                        }
                    }
                    let _ = socket.send(discord_close(close_code, close_reason)).await;
                    let _ = tokio::time::timeout(Duration::from_secs(2), socket.recv()).await;
                })
            }
        }),
    );
    let _ = axum::serve(listener, app.into_make_service()).await;
}

async fn spawn_pump(
    connections: Arc<AtomicU64>,
    close_code: u16,
    close_reason: &'static str,
) -> (
    tokio::task::JoinHandle<Result<(), String>>,
    tokio::task::JoinHandle<()>,
    Arc<MaterializedReadModel>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(closing_gateway_server(
        listener,
        connections,
        close_code,
        close_reason,
    ));

    let read_model = Arc::new(MaterializedReadModel::new(1024, OffsetDateTime::now_utc()));
    let gateway = Arc::new(
        DiscordGateway::with_gateway_url(
            GatewayOwnership::Odin,
            DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                SecretToken::new("gateway-fatal-pump-bot-token").unwrap(),
            ),
            DEFAULT_GATEWAY_INTENTS,
            format!("ws://{address}/gateway?v=10&encoding=json"),
        )
        .unwrap(),
    );
    // A minimal real runtime with no Discord surface: the pump's
    // catch-up pass is a typed no-op and the fatal-close park is what is
    // under test.
    let state = tempfile::tempdir().unwrap();
    let settings = odin_hermes::config::HermesSettings::new(
        state.path().to_path_buf(),
        None,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let ledgers = odin_hermes::runtime::HermesLedgers {
        conversation: odin_ledger::Ledger::open_in_memory().unwrap(),
        adapter: std::sync::Arc::new(parking_lot::Mutex::new(
            odin_ledger::Ledger::open_in_memory().unwrap(),
        )),
        purchase: std::sync::Arc::new(std::sync::Mutex::new(
            odin_ledger::Ledger::open_in_memory().unwrap(),
        )),
    };
    let runtime = odin_hermes::runtime::HermesRuntime::open(
        settings,
        ledgers,
        &std::collections::BTreeMap::new(),
        None,
        8,
        std::collections::BTreeMap::new(),
        None,
    )
    .unwrap();
    let parked = tokio::spawn(super::gateway_listener_pump(
        Arc::new(NoIntake),
        runtime,
        Arc::clone(&read_model),
        gateway,
    ));
    (parked, server, read_model)
}

/// Waits for the fatal-close incident as the EXACTLY ONE Status row.
async fn wait_for_incident(
    parked: &tokio::task::JoinHandle<Result<(), String>>,
    read_model: &MaterializedReadModel,
) -> ObjectSnapshot {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let statuses = read_model.objects_of_kind(ObjectKind::Status).unwrap();
        assert!(
            statuses.len() <= 1,
            "multiple fatal-close incidents published: {statuses:?}"
        );
        if let [only] = statuses.as_slice() {
            if let Some(snapshot) = read_model.get(only).unwrap() {
                return snapshot;
            }
        }
        assert!(
            !parked.is_finished(),
            "the pump finished instead of parking after the fatal close"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "the fatal-close incident never reached the read model"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fatal_close_through_the_pump_publishes_one_incident_and_parks() {
    let connections = Arc::new(AtomicU64::new(0));
    let (parked, server, read_model) =
        spawn_pump(Arc::clone(&connections), 4004, "Authentication failed.").await;

    let snapshot = wait_for_incident(&parked, &read_model).await;
    let view: IncidentView = serde_json::from_value(snapshot.value).unwrap();
    assert_eq!(view.severity, IncidentSeverityView::Critical);
    assert_eq!(view.observed_state["close"]["code"], json!(4004));
    assert_eq!(
        view.observed_state["close"]["reason"],
        json!("Authentication failed.")
    );
    assert_eq!(view.observed_state["reconnect"], json!(false));

    // The grace crosses a full 5 s ticker period: a pump that failed to
    // park (or lost the fatal branch) would have redialed and published
    // a second incident by now.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "a fatal close must stop the loop: no redial after the park"
    );
    assert_eq!(
        read_model
            .objects_of_kind(ObjectKind::Status)
            .unwrap()
            .len(),
        1,
        "exactly one incident per fatal close"
    );
    assert!(
        !parked.is_finished(),
        "the pump must park, not complete into the serving select"
    );

    parked.abort();
    let cancel = parked.await.unwrap_err();
    assert!(cancel.is_cancelled(), "the parked pump must cancel cleanly");
    server.abort();
    server.await.unwrap_err();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recoverable_close_through_the_pump_alerts_nothing_and_retries() {
    let connections = Arc::new(AtomicU64::new(0));
    let (parked, server, read_model) =
        spawn_pump(Arc::clone(&connections), 4000, "unknown error").await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while connections.load(Ordering::SeqCst) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the pump must retry a recoverable close"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert!(
        read_model
            .objects_of_kind(ObjectKind::Status)
            .unwrap()
            .is_empty(),
        "a recoverable close must never publish the fatal-close incident"
    );
    assert!(
        !parked.is_finished(),
        "a recoverable close keeps the pump in its retry loop"
    );
    parked.abort();
    assert!(parked.await.unwrap_err().is_cancelled());
    server.abort();
    server.await.unwrap_err();
}

/// A successful SSH response overrides a failed reachability probe.
#[test]
fn a_host_that_answered_over_ssh_is_online() {
    use odin_huginn::fleet::{Reachability, ZellijSessions};
    let mut probes = std::collections::BTreeMap::from([
        ("laptop".to_owned(), Reachability::Unreachable),
        ("arm".to_owned(), Reachability::Unreachable),
    ]);
    let zellij = std::collections::BTreeMap::from([
        (
            "laptop".to_owned(),
            ZellijSessions::Live(vec!["main".to_owned()]),
        ),
        ("arm".to_owned(), ZellijSessions::Unreachable),
    ]);
    super::answered_over_ssh(&mut probes, &zellij);
    assert_eq!(probes["laptop"], Reachability::Reachable);
    assert_eq!(probes["arm"], Reachability::Unreachable);
}

/// Poll at known lead times rather than waiting for the regular polling interval.
#[test]
fn a_calendar_lead_time_seen_ahead_is_polled_when_it_comes_due() {
    let polled = std::time::Instant::now();
    let lead_due = polled + Duration::from_secs(80);
    assert!(!super::routine_sources_due(
        Some(polled),
        Some(lead_due),
        polled + Duration::from_secs(79)
    ));
    assert!(super::routine_sources_due(
        Some(polled),
        Some(lead_due),
        polled + Duration::from_secs(81)
    ));
    assert!(super::routine_sources_due(
        Some(polled),
        None,
        polled + Duration::from_secs(300)
    ));
    assert!(!super::routine_sources_due(
        Some(polled),
        None,
        polled + Duration::from_secs(81)
    ));
}
