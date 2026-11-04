//! Gateway recovery transcripts: RESUME identity and sequence across
//! reconnects (op 7, zombie sockets, cancellations), invalid-session
//! decisions (op 9 resumable vs not), and fatal-close no-retry — each proven
//! against the loopback WebSocket stand-in.

use super::{
    discord_close, dispatch, hello, read_gateway_frame, send_gateway_frame, NoSink, RecordingSink,
};
use odin_hermes::discord::{
    DiscordCredential, DiscordGateway, DiscordSendError, GatewayOwnership, ReconnectPolicy,
    SecretToken, DEFAULT_GATEWAY_INTENTS,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn gateway_op7_resumes_session_identity_and_fatal_close_stops_retrying() {
    let secret = "gateway-resume-bot-token";
    let identifies: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let resumes: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let base_connections = Arc::new(AtomicU64::new(0));
    let resume_connections = Arc::new(AtomicU64::new(0));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    // The base session pins the session identity at READY and the sequence
    // at a dispatch, then requests a reconnect (op 7).
    let base_app = {
        let identifies = identifies.clone();
        let violations = violations.clone();
        let base_connections = base_connections.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade| {
            let identifies = identifies.clone();
            let violations = violations.clone();
            let base_connections = base_connections.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    base_connections.fetch_add(1, Ordering::SeqCst);
                    send_gateway_frame(&mut socket, &hello(1_000)).await;
                    let Some(identify) = read_gateway_frame(&mut socket, 2_000).await else {
                        violations.lock().push("no IDENTIFY arrived".to_owned());
                        return;
                    };
                    if identify["op"] != 2 || identify["d"]["token"] != json!(secret) {
                        violations
                            .lock()
                            .push(format!("expected IDENTIFY, got {identify}"));
                        return;
                    }
                    identifies.lock().push(identify);
                    send_gateway_frame(
                        &mut socket,
                        &json!({
                            "op": 0, "s": 3, "t": "READY",
                            "d": {
                                "session_id": "sess-op7",
                                "resume_gateway_url": format!("ws://{address}/resume"),
                                "_trace": ["test"],
                            },
                        }),
                    )
                    .await;
                    send_gateway_frame(
                        &mut socket,
                        &dispatch(4, "1000000000000000031", "before reconnect"),
                    )
                    .await;
                    send_gateway_frame(&mut socket, &json!({"op": 7, "d": {}})).await;
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
                        .await;
                })
            }
        }
    };

    // The resume endpoint observes the RESUME identity and sequence, then
    // closes fatally: the run must surface this once and stop dialing.
    let resume_app = {
        let resumes = resumes.clone();
        let violations = violations.clone();
        let resume_connections = resume_connections.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade, uri: axum::http::Uri| {
            let resumes = resumes.clone();
            let violations = violations.clone();
            let resume_connections = resume_connections.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    resume_connections.fetch_add(1, Ordering::SeqCst);
                    // The resume endpoint arrives bare at READY; the pinned
                    // connection query (version + encoding) must ride along.
                    if uri.query() != Some("v=10&encoding=json") {
                        violations.lock().push(format!(
                            "the resume dial dropped the pinned connection query: {uri}"
                        ));
                        return;
                    }
                    send_gateway_frame(&mut socket, &hello(1_000)).await;
                    let Some(resume) = read_gateway_frame(&mut socket, 2_000).await else {
                        violations.lock().push("no RESUME arrived".to_owned());
                        return;
                    };
                    if resume["op"] != 6
                        || resume["d"]["token"] != json!(secret)
                        || resume["d"]["session_id"] != json!("sess-op7")
                        || resume["d"]["seq"] != json!(4)
                    {
                        violations
                            .lock()
                            .push(format!("expected the pinned session RESUME, got {resume}"));
                        return;
                    }
                    resumes.lock().push(resume);
                    // Resume accepted: replay the missed dispatch, then the
                    // fatal close.
                    send_gateway_frame(
                        &mut socket,
                        &json!({"op": 0, "s": 5, "t": "RESUMED", "d": {"_trace": ["test"]}}),
                    )
                    .await;
                    send_gateway_frame(
                        &mut socket,
                        &dispatch(6, "1000000000000000032", "replayed after resume"),
                    )
                    .await;
                    let _ = socket
                        .send(discord_close(4004, "Authentication failed."))
                        .await;
                })
            }
        }
    };
    let app = axum::Router::new()
        .route("/gateway", axum::routing::get(base_app))
        .route("/resume", axum::routing::get(resume_app));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new(secret).unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway?v=10&encoding=json"),
    )
    .unwrap();
    let sink = Arc::new(RecordingSink::default());
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        gateway.run(
            sink.clone(),
            ReconnectPolicy {
                max_attempts: 3,
                initial_backoff: std::time::Duration::from_millis(10),
                max_backoff: std::time::Duration::from_millis(20),
            },
        ),
    )
    .await
    .expect("the gateway run terminates");
    assert_eq!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayFatalClose {
            code: 4004,
            reason: "Authentication failed.".to_owned(),
        }
    );
    // The reconnect resumed the pinned session and the fatal close stopped
    // the loop: exactly two dials, no third, and no re-identify.
    assert_eq!(base_connections.load(Ordering::SeqCst), 1);
    assert_eq!(resume_connections.load(Ordering::SeqCst), 1);
    assert_eq!(identifies.lock().len(), 1, "a resume must not re-identify");
    assert_eq!(resumes.lock().len(), 1);
    let violations = violations.lock();
    assert!(
        violations.is_empty(),
        "gateway protocol violations: {violations:?}"
    );
    drop(violations);
    let messages = sink.messages.lock();
    assert_eq!(
        messages.len(),
        2,
        "the replayed dispatch reaches the sink once"
    );
    assert_eq!(messages[0].content, "before reconnect");
    assert_eq!(messages[1].content, "replayed after resume");
}

#[tokio::test]
async fn gateway_zombie_heartbeat_is_typed_and_the_next_run_resumes() {
    let secret = "gateway-zombie-bot-token";
    let identifies: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let resumes: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let base_connections = Arc::new(AtomicU64::new(0));
    let resume_connections = Arc::new(AtomicU64::new(0));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    // The base session pins the session identity and sequence, then stops
    // acknowledging heartbeats: the client must detect the zombie itself,
    // and the next run must resume the observed session and sequence.
    let base_app = {
        let identifies = identifies.clone();
        let violations = violations.clone();
        let base_connections = base_connections.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade| {
            let identifies = identifies.clone();
            let violations = violations.clone();
            let base_connections = base_connections.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    base_connections.fetch_add(1, Ordering::SeqCst);
                    send_gateway_frame(&mut socket, &hello(40)).await;
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
                    identifies.lock().push(identify);
                    send_gateway_frame(
                        &mut socket,
                        &json!({
                            "op": 0, "s": 9, "t": "READY",
                            "d": {
                                "session_id": "sess-zombie",
                                "resume_gateway_url": format!("ws://{address}/resume"),
                                "_trace": ["test"],
                            },
                        }),
                    )
                    .await;
                    // The first heartbeat must echo the pinned sequence;
                    // from then on the server never acknowledges.
                    loop {
                        let Some(frame) = read_gateway_frame(&mut socket, 2_000).await else {
                            violations
                                .lock()
                                .push("no heartbeat echoed the session sequence".to_owned());
                            return;
                        };
                        if frame["op"] == 1 {
                            if frame["d"] != json!(9) {
                                violations.lock().push(format!(
                                    "the heartbeat did not echo the pinned sequence: {frame}"
                                ));
                                return;
                            }
                            break;
                        }
                    }
                    // The zombie session must be terminated by the client
                    // without any further acknowledged heartbeat.
                    match tokio::time::timeout(std::time::Duration::from_secs(2), socket.recv())
                        .await
                    {
                        Err(_) => violations.lock().push(
                            "the zombie session was never terminated by the client".to_owned(),
                        ),
                        Ok(None) | Ok(Some(Err(_))) => {}
                        Ok(Some(Ok(axum::extract::ws::Message::Close(_)))) => {}
                        Ok(Some(Ok(_))) => violations
                            .lock()
                            .push("frames kept flowing on the zombie socket".to_owned()),
                    }
                })
            }
        }
    };

    // The resume endpoint observes the retained session identity and last
    // sequence, then closes fatally to end the second run typed.
    let resume_app = {
        let resumes = resumes.clone();
        let violations = violations.clone();
        let resume_connections = resume_connections.clone();
        move |ws: axum::extract::ws::WebSocketUpgrade, uri: axum::http::Uri| {
            let resumes = resumes.clone();
            let violations = violations.clone();
            let resume_connections = resume_connections.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    resume_connections.fetch_add(1, Ordering::SeqCst);
                    // The resume endpoint arrives bare at READY; the pinned
                    // connection query (version + encoding) must ride along.
                    if uri.query() != Some("v=10&encoding=json") {
                        violations.lock().push(format!(
                            "the resume dial dropped the pinned connection query: {uri}"
                        ));
                        return;
                    }
                    send_gateway_frame(&mut socket, &hello(1_000)).await;
                    let Some(resume) = read_gateway_frame(&mut socket, 2_000).await else {
                        violations.lock().push("no RESUME arrived".to_owned());
                        return;
                    };
                    if resume["op"] != 6
                        || resume["d"]["token"] != json!(secret)
                        || resume["d"]["session_id"] != json!("sess-zombie")
                        || resume["d"]["seq"] != json!(9)
                    {
                        violations
                            .lock()
                            .push(format!("expected the pinned session RESUME, got {resume}"));
                        return;
                    }
                    resumes.lock().push(resume);
                    let _ = socket
                        .send(discord_close(4004, "Authentication failed."))
                        .await;
                })
            }
        }
    };
    let app = axum::Router::new()
        .route("/gateway", axum::routing::get(base_app))
        .route("/resume", axum::routing::get(resume_app));
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new(secret).unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway?v=10&encoding=json"),
    )
    .unwrap();
    let policy = ReconnectPolicy {
        max_attempts: 1,
        initial_backoff: std::time::Duration::from_millis(10),
        max_backoff: std::time::Duration::from_millis(20),
    };

    // Run one: the un-acknowledged heartbeat ends the session typed.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gateway.run(Arc::new(NoSink), policy),
    )
    .await
    .expect("the zombie run terminates");
    assert_eq!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayHeartbeatAckMissing
    );

    // Run two: the retained session identity and last sequence are resumed
    // instead of a fresh identify, and the fatal close ends typed.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        gateway.run(Arc::new(NoSink), policy),
    )
    .await
    .expect("the resume run terminates");
    assert_eq!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayFatalClose {
            code: 4004,
            reason: "Authentication failed.".to_owned(),
        }
    );
    assert_eq!(
        base_connections.load(Ordering::SeqCst),
        1,
        "the reconnect must dial the resume endpoint, not the base"
    );
    assert_eq!(resume_connections.load(Ordering::SeqCst), 1);
    assert_eq!(
        identifies.lock().len(),
        1,
        "a zombie reconnect must resume, not re-identify"
    );
    assert_eq!(resumes.lock().len(), 1);
    let violations = violations.lock();
    assert!(
        violations.is_empty(),
        "gateway protocol violations: {violations:?}"
    );
}
