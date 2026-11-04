//! Gateway protocol: strict wire parsing, stable surface correlation, paired intents, session ownership, and heartbeat recovery.

use crate::discord::fixtures::{DM_CHANNEL, OWNER};
use odin_hermes::discord::{
    parse_message_create, DiscordCredential, DiscordGateway, DiscordIngressSink, DiscordMessage,
    DiscordSendError, GatewayOwnership, ReconnectPolicy, SecretToken, DEFAULT_GATEWAY_INTENTS,
};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;

#[test]
fn attachments_parse_and_only_discord_cdn_urls_survive() {
    let payload = json!({
        "id": "1000000000000000010",
        "channel_id": DM_CHANNEL,
        "author": {"id": OWNER},
        "content": "",
        "attachments": [
            {"id": "1100000000000000001", "filename": "CS11 syllabus.pdf", "size": 245_000,
             "url": "https://cdn.discordapp.com/attachments/1/2/CS11_syllabus.pdf?ex=1",
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
    assert_eq!(attachment.filename, "CS11 syllabus.pdf");
    assert_eq!(attachment.size, 245_000);
    assert_eq!(attachment.content_type.as_deref(), Some("application/pdf"));
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
/// The session opens with an IDENTIFY carrying the bearer token and the configured
/// intents, and a MESSAGE_CREATE dispatch reaches the sink. (Resume, invalid
/// session, zombie heartbeat and cancellation are proven in `recovery`.)
#[tokio::test]
async fn gateway_identifies_with_its_token_and_intents_and_forwards_the_dispatch() {
    let secret = "gateway-test-bot-token";
    let identifies: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let server_identifies = identifies.clone();
    let app = axum::Router::new().route(
        "/gateway",
        axum::routing::get(move |ws: axum::extract::ws::WebSocketUpgrade| {
            let identifies = server_identifies.clone();
            async move {
                ws.on_upgrade(move |mut socket| async move {
                    let text =
                        |value: Value| axum::extract::ws::Message::Text(value.to_string().into());
                    let _ = socket.send(text(hello(50))).await;
                    let Some(identify) = read_gateway_frame(&mut socket, 2_000).await else {
                        return;
                    };
                    identifies.lock().push(identify);
                    let _ = socket
                        .send(text(dispatch(7, "1000000000000000023", "plan my week")))
                        .await;
                    // A non-resumable invalid session ends the bounded run.
                    let _ = socket.send(text(json!({"op": 9, "d": false}))).await;
                    let _ = read_gateway_frame(&mut socket, 1_500).await;
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
                max_attempts: 1,
                initial_backoff: std::time::Duration::from_millis(10),
                max_backoff: std::time::Duration::from_millis(20),
            },
        ),
    )
    .await
    .expect("the bounded gateway loop terminates");
    assert!(matches!(
        outcome.unwrap_err(),
        DiscordSendError::GatewayInvalidSession { resumable: false }
    ));

    let identifies = identifies.lock();
    assert_eq!(identifies.len(), 1);
    assert_eq!(identifies[0]["op"], 2);
    assert_eq!(identifies[0]["d"]["token"], secret);
    assert_eq!(
        identifies[0]["d"]["intents"],
        json!(DEFAULT_GATEWAY_INTENTS)
    );
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
