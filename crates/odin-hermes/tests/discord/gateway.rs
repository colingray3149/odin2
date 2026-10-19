//! Gateway protocol: strict wire parsing, stable surface correlation, paired intents, session ownership, and heartbeat recovery.

use crate::fixtures::{DM_CHANNEL, OWNER};
use odin_domain::DomainError;
use odin_hermes::correlation::{surface_correlation, surface_session, DiscordSurface};
use odin_hermes::discord::{
    parse_message_create, DiscordCredential, DiscordGateway, DiscordIngressSink, DiscordMessage,
    DiscordSendError, GatewayOwnership, ReconnectPolicy, SecretToken, DEFAULT_GATEWAY_INTENTS,
    GATEWAY_INTENT_DIRECT_MESSAGES, GATEWAY_INTENT_MESSAGE_CONTENT,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[test]
fn gateway_message_create_wire_is_parsed_strictly() {
    let payload = json!({
        "id": "1000000000000000009",
        "channel_id": DM_CHANNEL,
        "author": {"id": OWNER, "username": "colin"},
        "content": "plan my week",
        "guild_id": Value::Null,
    });
    let parsed = parse_message_create(&payload).unwrap();
    assert_eq!(parsed.id, "1000000000000000009");
    assert_eq!(parsed.channel_id, DM_CHANNEL);
    assert_eq!(parsed.author_id, OWNER);
    assert_eq!(parsed.guild_id, None);
    assert_eq!(parsed.content, "plan my week");

    // Guild messages keep their guild id; garbage payloads are refused.
    let mut guilded = payload.clone();
    guilded["guild_id"] = json!("800000000000000001");
    assert_eq!(
        parse_message_create(&guilded).unwrap().guild_id,
        Some("800000000000000001".to_owned())
    );
    let mut broken = payload.clone();
    broken["id"] = json!(12_345);
    assert!(parse_message_create(&broken).is_none());
    let mut no_author = payload;
    no_author["author"] = json!({"username": "colin"});
    assert!(parse_message_create(&no_author).is_none());
}

#[test]
fn attachments_parse_and_only_discord_cdn_urls_survive() {
    let payload = json!({
        "id": "1000000000000000010",
        "channel_id": DM_CHANNEL,
        "author": {"id": OWNER},
        "content": "",
        "attachments": [
            {"id": "1100000000000000001", "filename": "ME11 syllabus.pdf", "size": 245_000,
             "url": "https://cdn.discordapp.com/attachments/1/2/ME11_syllabus.pdf?ex=1",
             "content_type": "application/pdf"},
            {"id": "1100000000000000002", "filename": "evil.pdf", "size": 10,
             "url": "https://attacker.example/evil.pdf"},
            {"id": "1100000000000000003", "filename": "plain.pdf", "size": 10,
             "url": "http://cdn.discordapp.com/plain.pdf"}
        ]
    });
    let parsed = parse_message_create(&payload).unwrap();
    assert_eq!(parsed.content, "");
    assert_eq!(parsed.attachments.len(), 1, "{:?}", parsed.attachments);
    let attachment = &parsed.attachments[0];
    assert_eq!(attachment.filename, "ME11 syllabus.pdf");
    assert_eq!(attachment.size, 245_000);
    assert_eq!(attachment.content_type.as_deref(), Some("application/pdf"));
}
#[test]
fn discord_surface_correlation_is_stable_and_bound() {
    let surface = DiscordSurface::new(DM_CHANNEL, "1000000000000000001").unwrap();
    let correlation = surface_correlation(&surface).unwrap();
    assert_eq!(
        correlation.idempotency_key,
        format!("discord:v1:{DM_CHANNEL}:1000000000000000001")
    );
    assert_eq!(
        surface_correlation(&surface).unwrap(),
        correlation,
        "the same surface must always produce the same key"
    );
    assert_eq!(
        surface_session(&surface).unwrap().as_str(),
        format!("discord-dm-{DM_CHANNEL}")
    );
    assert!(matches!(
        DiscordSurface::new(DM_CHANNEL, "not-a-snowflake"),
        Err(DomainError::InvalidId { .. })
    ));
    // The gateway carries no secret material in its Debug rendering.
    let gateway = DiscordGateway::new(
        GatewayOwnership::Odin,
        DiscordCredential::absent(),
        DEFAULT_GATEWAY_INTENTS,
    );
    assert!(!format!("{gateway:?}").contains("token"));
}
#[test]
fn gateway_intents_match_paired_dm_protocol() {
    assert_eq!(GATEWAY_INTENT_DIRECT_MESSAGES, 1 << 12);
    assert_eq!(GATEWAY_INTENT_MESSAGE_CONTENT, 1 << 15);
    // The default requests the minimal unprivileged DM intent only:
    // MESSAGE_CONTENT is privileged and fails IDENTIFY with 4014 unless the
    // portal toggle is enabled, while DM content arrives without it.
    assert_eq!(DEFAULT_GATEWAY_INTENTS, 4_096);
    // Neither the guild message bit (1 << 9) nor the privileged content bit
    // (1 << 15) is admitted by default.
    assert_eq!(DEFAULT_GATEWAY_INTENTS & (1 << 9), 0);
    assert_eq!(DEFAULT_GATEWAY_INTENTS & (1 << 15), 0);
}
#[tokio::test]
async fn non_owner_cannot_open_a_second_gateway_session() {
    // The pinned Hermes deployment owns the live gateway on the shared
    // token; a HermesPinned-composed listener refuses before any socket.
    let gateway = DiscordGateway::new(
        GatewayOwnership::HermesPinned,
        DiscordCredential::absent(),
        DEFAULT_GATEWAY_INTENTS,
    );
    let error = gateway
        .run(Arc::new(NoSink), ReconnectPolicy::bounded())
        .await
        .unwrap_err();
    assert_eq!(error, DiscordSendError::GatewayNotOwned);

    // The Odin-owned listener validates its reconnect bound before dialing
    // and reports absent credentials typed, never a faked session.
    let owned = DiscordGateway::new(
        GatewayOwnership::Odin,
        DiscordCredential::absent(),
        DEFAULT_GATEWAY_INTENTS,
    );
    let unbounded = ReconnectPolicy {
        max_attempts: 0,
        initial_backoff: std::time::Duration::from_secs(1),
        max_backoff: std::time::Duration::from_secs(30),
    };
    let error = owned.run(Arc::new(NoSink), unbounded).await.unwrap_err();
    assert!(matches!(error, DiscordSendError::Rejected { .. }));
    let error = owned
        .run(Arc::new(NoSink), ReconnectPolicy::bounded())
        .await
        .unwrap_err();
    assert_eq!(error, DiscordSendError::CredentialsUnavailable);
}
#[tokio::test]
async fn gateway_heartbeat_recovery_and_identify_through_the_real_protocol() {
    let secret = "gateway-test-bot-token";
    let identifies: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let violations: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let zombie_closed = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(AtomicU64::new(0));

    let server_identifies = identifies.clone();
    let server_violations = violations.clone();
    let server_zombie = zombie_closed.clone();
    let server_connections = connections.clone();
    let app = axum::Router::new().route(
        "/gateway",
        axum::routing::get(move |ws: axum::extract::ws::WebSocketUpgrade| {
            let identifies = server_identifies.clone();
            let violations = server_violations.clone();
            let zombie_closed = server_zombie.clone();
            let connections = server_connections.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    let stage = connections.fetch_add(1, Ordering::SeqCst);
                    let hello =
                        json!({"op": 10, "d": {"heartbeat_interval": 50, "_trace": ["test"]}});
                    if socket
                        .send(axum::extract::ws::Message::Text(hello.to_string().into()))
                        .await
                        .is_err()
                    {
                        violations
                            .lock()
                            .push("the HELLO could not be sent".to_owned());
                        return;
                    }
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
                    if identify["d"]["token"] != json!(secret) {
                        violations
                            .lock()
                            .push("the IDENTIFY did not carry the bearer token".to_owned());
                        return;
                    }
                    if identify["d"]["intents"] != json!(DEFAULT_GATEWAY_INTENTS) {
                        violations
                            .lock()
                            .push("the IDENTIFY did not carry the configured intents".to_owned());
                        return;
                    }
                    identifies.lock().push(identify);
                    match stage {
                        // Session one: dispatch, then a server-requested
                        // heartbeat answered with the dispatch sequence; the
                        // next un-acknowledged tick must kill the socket.
                        0 => {
                            let dispatch = json!({
                                "op": 0, "s": 7, "t": "MESSAGE_CREATE",
                                "d": {
                                    "id": "1000000000000000023",
                                    "channel_id": DM_CHANNEL,
                                    "author": {"id": OWNER, "username": "colin"},
                                    "content": "plan my week",
                                    "guild_id": Value::Null,
                                },
                            });
                            let _ = socket
                                .send(axum::extract::ws::Message::Text(
                                    dispatch.to_string().into(),
                                ))
                                .await;
                            let _ = socket
                                .send(axum::extract::ws::Message::Text(
                                    json!({"op": 1, "d": null}).to_string().into(),
                                ))
                                .await;
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_millis(500);
                            let mut echo_seen = false;
                            while std::time::Instant::now() < deadline {
                                let Some(frame) = read_gateway_frame(&mut socket, 100).await else {
                                    continue;
                                };
                                if frame["op"] != 1 {
                                    continue;
                                }
                                if frame["d"] == json!(7) {
                                    // The heartbeat echoed the dispatch
                                    // sequence; stop acknowledging so the
                                    // next unanswered tick must kill the
                                    // session.
                                    echo_seen = true;
                                    break;
                                }
                                // A pre-dispatch tick (no sequence yet):
                                // keep the session alive and keep waiting.
                                let _ = socket
                                    .send(axum::extract::ws::Message::Text(
                                        json!({"op": 11}).to_string().into(),
                                    ))
                                    .await;
                            }
                            if !echo_seen {
                                violations.lock().push(
                                    "the heartbeat did not echo the dispatch sequence".to_owned(),
                                );
                            }
                            // The session must be terminated from the
                            // client side: no ack means no liveness.
                            let end =
                                std::time::Instant::now() + std::time::Duration::from_millis(1_500);
                            loop {
                                let remaining =
                                    end.saturating_duration_since(std::time::Instant::now());
                                if remaining.is_zero() {
                                    break;
                                }
                                match tokio::time::timeout(remaining, socket.recv()).await {
                                    Err(_) => break,
                                    Ok(None) => {
                                        zombie_closed.store(true, Ordering::SeqCst);
                                        break;
                                    }
                                    Ok(Some(Err(_))) => {
                                        zombie_closed.store(true, Ordering::SeqCst);
                                        break;
                                    }
                                    Ok(Some(Ok(axum::extract::ws::Message::Close(_)))) => {
                                        zombie_closed.store(true, Ordering::SeqCst);
                                        break;
                                    }
                                    Ok(Some(Ok(_))) => continue,
                                }
                            }
                        }
                        // Session two: the server requests reconnect.
                        1 => {
                            let _ = socket
                                .send(axum::extract::ws::Message::Text(
                                    json!({"op": 7, "d": {}}).to_string().into(),
                                ))
                                .await;
                            let _ = read_gateway_frame(&mut socket, 1_500).await;
                        }
                        // Session three: invalid session — fresh identify is
                        // the only honest recovery.
                        _ => {
                            let _ = socket
                                .send(axum::extract::ws::Message::Text(
                                    json!({"op": 9, "d": false}).to_string().into(),
                                ))
                                .await;
                            let _ = read_gateway_frame(&mut socket, 1_500).await;
                        }
                    }
                })
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });

    // Non-loopback overrides are refused at construction.
    assert!(DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::absent(),
        DEFAULT_GATEWAY_INTENTS,
        "ws://example.internal",
    )
    .is_err());

    let gateway = DiscordGateway::with_gateway_url(
        GatewayOwnership::Odin,
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new(secret).unwrap(),
        ),
        DEFAULT_GATEWAY_INTENTS,
        format!("ws://{address}/gateway"),
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
    .expect("the bounded gateway loop terminates");
    // The loop ended on the gateway's non-resumable invalid-session: the
    // typed cause, not a flat unavailability.
    assert!(matches!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayInvalidSession { resumable: false }
    ));

    // Three fresh sessions, each with a full IDENTIFY carrying the token
    // and the pinned DM intents: no resume state, no second ownership.
    assert_eq!(connections.load(Ordering::SeqCst), 3);
    assert_eq!(
        identifies.lock().len(),
        3,
        "every reconnect must identify fresh"
    );
    {
        let violations = violations.lock();
        assert!(
            violations.is_empty(),
            "gateway protocol violations: {violations:?}"
        );
    }
    // The un-acknowledged heartbeat terminated the session from the
    // client side — the server never asked it to close. The server's task
    // sees that close on its next read, which can trail the client's last
    // reconnect under load (full gate 10-04).
    let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !zombie_closed.load(Ordering::SeqCst) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "a heartbeat left un-acknowledged must terminate the session"
    );

    // The dispatch was forwarded to the sink exactly once.
    let messages = sink.messages.lock();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].author_id, OWNER);
    assert_eq!(messages[0].content, "plan my week");
}
struct NoSink;
impl DiscordIngressSink for NoSink {
    fn message(&self, _message: DiscordMessage) {}
}
#[derive(Default)]
struct RecordingSink {
    messages: Mutex<Vec<DiscordMessage>>,
}
impl DiscordIngressSink for RecordingSink {
    fn message(&self, message: DiscordMessage) {
        self.messages.lock().push(message);
    }
}
/// Reads the next JSON gateway frame inside a deadline. `None` means the
/// deadline elapsed, the socket closed, or the frame was not JSON text.
async fn read_gateway_frame(
    socket: &mut axum::extract::ws::WebSocket,
    timeout_ms: u64,
) -> Option<Value> {
    let received =
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), socket.recv())
            .await
        {
            // Elapsed / closed socket / transport error are all "no frame".
            Ok(Some(Ok(message))) => message,
            _ => return None,
        };
    match received {
        axum::extract::ws::Message::Text(text) => serde_json::from_str::<Value>(&text).ok(),
        _ => None,
    }
}
/// Sends one JSON gateway frame, tolerating a closed socket.
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

/// A HELLO with the given heartbeat interval in milliseconds.
fn hello(interval_ms: u64) -> Value {
    json!({"op": 10, "d": {"heartbeat_interval": interval_ms, "_trace": ["test"]}})
}

/// A MESSAGE_CREATE dispatch from the paired owner on the DM surface.
fn dispatch(sequence: u64, id: &str, content: &str) -> Value {
    json!({
        "op": 0, "s": sequence, "t": "MESSAGE_CREATE",
        "d": {
            "id": id,
            "channel_id": DM_CHANNEL,
            "author": {"id": OWNER, "username": "colin"},
            "content": content,
            "guild_id": Value::Null,
        },
    })
}

#[path = "gateway/protocol.rs"]
mod protocol_failures;
#[path = "gateway/recovery.rs"]
mod recovery;
