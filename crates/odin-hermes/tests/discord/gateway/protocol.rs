//! Loopback tests for HELLO deadlines, handshake cancellation, and exact loopback-host validation.

use super::{hello, read_gateway_frame, send_gateway_frame, NoSink};
use odin_hermes::discord::{
    DiscordCredential, DiscordGateway, DiscordSendError, GatewayOwnership, ReconnectPolicy,
    SecretToken, DEFAULT_GATEWAY_INTENTS,
};
use parking_lot::Mutex;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[tokio::test(start_paused = true)]
async fn gateway_missing_hello_deadline_expires_typed() {
    // A silent gateway: HELLO never arrives, so the bounded HELLO deadline
    // is the protocol boundary that must fire — typed. Paused time advances
    // the real deadline instead of cancelling the run early.
    let silent_app = move |ws: axum::extract::ws::WebSocketUpgrade| async move {
        ws.on_upgrade(move |mut socket| async move {
            let _ = socket.recv().await;
        })
    };
    let app = axum::Router::new().route("/gateway", axum::routing::get(silent_app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("gateway-hello-bot-token").unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway"),
    )
    .unwrap();
    let outcome = gateway
        .run(
            Arc::new(NoSink),
            ReconnectPolicy {
                max_attempts: 1,
                initial_backoff: std::time::Duration::from_millis(10),
                max_backoff: std::time::Duration::from_millis(20),
            },
        )
        .await;
    assert_eq!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayHelloMissing,
        "the HELLO deadline must expire typed, not hang or cancel silently"
    );
}

#[tokio::test]
async fn gateway_run_cancellation_ends_cleanly_without_spin() {
    let observed_cancellation = Arc::new(AtomicBool::new(false));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // A silent gateway hangs the handshake; the awaited run must stay
    // cancellable at any moment and drop its socket cleanly.
    let silent_app = {
        let observed_cancellation = observed_cancellation.clone();
        let violations = violations.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade| {
            let observed_cancellation = observed_cancellation.clone();
            let violations = violations.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(3), socket.recv())
                        .await
                    {
                        Err(_) => violations
                            .lock()
                            .push("the cancelled run never closed its socket".to_owned()),
                        Ok(None) | Ok(Some(Err(_))) => {
                            observed_cancellation.store(true, Ordering::SeqCst);
                        }
                        Ok(Some(Ok(axum::extract::ws::Message::Close(_)))) => {
                            observed_cancellation.store(true, Ordering::SeqCst);
                        }
                        Ok(Some(Ok(_))) => violations
                            .lock()
                            .push("the cancelled run sent an unexpected frame".to_owned()),
                    }
                })
            }
        }
    };
    let app = axum::Router::new().route("/gateway", axum::routing::get(silent_app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("gateway-cancel-bot-token").unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway"),
    )
    .unwrap();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        gateway.run(
            Arc::new(NoSink),
            ReconnectPolicy {
                max_attempts: 1,
                initial_backoff: std::time::Duration::from_millis(10),
                max_backoff: std::time::Duration::from_millis(20),
            },
        ),
    )
    .await;
    assert!(
        outcome.is_err(),
        "the hung handshake must stay cancellable, not spin or complete"
    );
    // Cancellation dropped the future and closed the socket; the server
    // observes it without any leaked heartbeat loop. The bounded wait only
    // yields to the server task; the close itself is immediate on loopback.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !observed_cancellation.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        observed_cancellation.load(Ordering::SeqCst),
        "the cancelled run must close its socket cleanly"
    );
    let violations = violations.lock();
    assert!(
        violations.is_empty(),
        "gateway protocol violations: {violations:?}"
    );
}

#[tokio::test]
async fn gateway_spoofed_loopback_resume_host_is_refused_without_dialing() {
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let base_connections = Arc::new(AtomicU64::new(0));

    // A domain beginning with a loopback name must be rejected before dialing.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let base_app = {
        let violations = violations.clone();
        let base_connections = base_connections.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade| {
            let violations = violations.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    base_connections.fetch_add(1, Ordering::SeqCst);
                    send_gateway_frame(&mut socket, &hello(1_000)).await;
                    let Some(identify) = read_gateway_frame(&mut socket, 2_000).await else {
                        violations.lock().push("no IDENTIFY arrived".to_owned());
                        return;
                    };
                    if identify["op"] != 2 {
                        violations
                            .lock()
                            .push(format!("expected IDENTIFY, got {identify}"));
                        return;
                    }
                    send_gateway_frame(
                        &mut socket,
                        &json!({
                            "op": 0, "s": 1, "t": "READY",
                            "d": {
                                "session_id": "sess-spoof",
                                "resume_gateway_url": "ws://localhost.attacker.example/resume",
                                "_trace": ["test"],
                            },
                        }),
                    )
                    .await;
                    // The refusal must be typed and local: the session ends
                    // here and no external host is ever dialed.
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
                        .await;
                })
            }
        }
    };
    let app = axum::Router::new().route("/gateway", axum::routing::get(base_app));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    assert!(
        DiscordGateway::with_gateway_url(
            GatewayOwnership::Odin,
            DiscordCredential::absent(),
            DEFAULT_GATEWAY_INTENTS,
            "ws://localhost.attacker.example",
        )
        .is_err(),
        "a lookalike loopback domain must be refused at construction"
    );

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("gateway-spoof-bot-token").unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway?v=10&encoding=json"),
    )
    .unwrap();
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gateway.run(
            Arc::new(NoSink),
            ReconnectPolicy {
                max_attempts: 1,
                initial_backoff: std::time::Duration::from_millis(10),
                max_backoff: std::time::Duration::from_millis(20),
            },
        ),
    )
    .await
    .expect("the refused run terminates");
    // The spoofed resume host is refused typed and synchronously: no
    // external dial is attempted, the run ends after the base session.
    let error = outcome.unwrap_err();
    assert!(
        matches!(error, DiscordSendError::GatewayProtocolViolation { .. }),
        "expected a typed protocol violation, got {error:?}"
    );
    assert!(
        format!("{error:?}").contains("transport"),
        "the refusal must name the transport law"
    );
    assert_eq!(
        base_connections.load(Ordering::SeqCst),
        1,
        "the spoofed resume host must be refused without any further dial"
    );
    let violations = violations.lock();
    assert!(
        violations.is_empty(),
        "gateway protocol violations: {violations:?}"
    );
}
