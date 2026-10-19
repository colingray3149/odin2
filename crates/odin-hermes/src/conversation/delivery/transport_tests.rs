use super::*;
use crate::discord::{DiscordCredential, DiscordRestTransport, SecretToken};
use crate::egress::{DiscordEgressSink, OutgoingSink};
use parking_lot::Mutex;
use serde_json::{json, Value};
const DM_CHANNEL: &str = "1000000000000000001";

/// Reads the complete POST before discarding its response, unlike a scripted
/// HTTP error that may have rejected the request before applying it.
async fn spawn_accepted_post_server(
    drop_attempt: usize,
    ledger_path: std::path::PathBuf,
) -> (
    String,
    Arc<Mutex<Vec<(Value, Value)>>>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let observed = accepted.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut bytes = [0; 4096];
                let count = socket.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0, "request headers must arrive completely");
                request.extend_from_slice(&bytes[..count]);
                if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            let mut request_line = headers.lines().next().unwrap().split_whitespace();
            let method = request_line.next().unwrap().to_owned();
            let target = request_line.next().unwrap().to_owned();
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + length {
                let mut bytes = [0; 4096];
                let count = socket.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0, "request body must arrive completely");
                request.extend_from_slice(&bytes[..count]);
            }
            let mut body: Value = if length == 0 {
                json!({})
            } else {
                serde_json::from_slice(&request[header_end..header_end + length]).unwrap()
            };
            body["_method"] = json!(method);
            body["_target"] = json!(target);
            // Independently open the real database at the physical boundary.
            let rows = Ledger::open(&ledger_path)
                .unwrap()
                .conversation_deliveries()
                .unwrap();
            assert_eq!(rows.len(), 1);
            let state: Value = serde_json::from_str(&rows[0].state_json).unwrap();
            let (attempt, id) = {
                let mut accepted = observed.lock();
                let attempt = accepted.len() + 1;
                let id = if method == "POST" {
                    format!("{}", 11_000_000_000_000_000_u64 + attempt as u64)
                } else {
                    target.rsplit('/').next().unwrap().to_owned()
                };
                body["_accepted_id"] = json!(id);
                accepted.push((body, state));
                (attempt, id)
            };
            if attempt == drop_attempt {
                drop(socket);
                continue;
            }
            let response = if method == "DELETE" {
                String::new()
            } else {
                json!({"id": id, "channel_id": DM_CHANNEL}).to_string()
            };
            let status = if method == "DELETE" {
                "204 No Content"
            } else {
                "200 OK"
            };
            socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).as_bytes()).await.unwrap();
        }
    });
    (format!("http://{address}"), accepted, task)
}

fn persisted_delivery(path: &std::path::Path) -> Value {
    let rows = Ledger::open(path)
        .unwrap()
        .conversation_deliveries()
        .unwrap();
    assert_eq!(rows.len(), 1);
    serde_json::from_str(&rows[0].state_json).unwrap()
}

fn transport(base: String) -> DiscordRestTransport {
    DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("bot-token").unwrap(),
        ),
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap(),
        base,
    )
    .unwrap()
}

fn checkpoint(path: &Path) -> Arc<ReplyDelivery> {
    ReplyDelivery::open(
        path,
        "physical-test",
        DM_CHANNEL,
        "original-turn",
        None,
        None,
    )
    .unwrap()
}

fn outbound(content: &str) -> OutboundMessage {
    OutboundMessage {
        channel_id: DM_CHANNEL.to_owned(),
        content: content.to_owned(),
    }
}

#[tokio::test]
async fn accepted_posts_with_lost_responses_remain_reserved_across_restart() {
    for lost in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.sqlite3");
        let delivery = checkpoint(&path);
        let (base, accepted, server) = spawn_accepted_post_server(lost, path.clone()).await;
        let sink = DiscordEgressSink::new(Arc::new(transport(base)));
        let text = "x".repeat(MAX_MESSAGE_CODEPOINTS * 3);
        let error = sink
            .deliver(outbound(&text), delivery.clone())
            .await
            .unwrap_err();
        assert!(error.may_have_posted());
        let state = persisted_delivery(&path);
        assert_eq!(state["pending"]["operation"]["Post"]["index"], lost - 1);
        assert_eq!(state["chunks"].as_array().map_or(0, Vec::len), lost - 1);
        assert_ne!(state["phase"], "committed");
        {
            let calls = accepted.lock();
            assert_eq!(calls.len(), lost);
            if lost == 2 {
                assert_eq!(
                    state["chunks"][0]["reference"]["message_id"],
                    calls[0].0["_accepted_id"]
                );
                assert_eq!(state["chunks"][0]["content"], calls[0].0["content"]);
            }
            for (index, (body, before_http)) in calls.iter().enumerate() {
                assert_eq!(
                    before_http["pending"]["operation"]["Post"]["content"],
                    body["content"]
                );
                assert_eq!(
                    before_http["chunks"].as_array().map_or(0, Vec::len),
                    index,
                    "every previous acknowledgement precedes the next HTTP request"
                );
            }
        }
        drop(delivery);
        for _ in 0..2 {
            let reopened = checkpoint(&path);
            assert!(sink.deliver(outbound(&text), reopened).await.is_err());
            assert_eq!(persisted_delivery(&path), state);
            assert_eq!(
                accepted.lock().len(),
                lost,
                "unknown operation must never resend"
            );
        }
        server.abort();
    }
}

/// The wrapper only injects an unavailable database at the real acknowledgement
/// write boundary; all state transitions remain the production implementation.
struct FailAcknowledgement {
    inner: Arc<ReplyDelivery>,
    path: std::path::PathBuf,
}

impl DeliveryCheckpoint for FailAcknowledgement {
    fn prepare(&self, message: &OutboundMessage) -> Result<DeliveryPlan, EgressError> {
        self.inner.prepare(message)
    }
    fn reserve(&self, operation: &DeliveryOperation) -> Result<DeliveryReservation, EgressError> {
        self.inner.reserve(operation)
    }
    fn acknowledge(
        &self,
        reservation: &DeliveryReservation,
        reference: Option<&DiscordMessageRef>,
    ) -> Result<(), EgressError> {
        let saved = self.path.with_extension("saved");
        std::fs::rename(&self.path, &saved).unwrap();
        std::fs::create_dir(&self.path).unwrap();
        let result = self.inner.acknowledge(reservation, reference);
        std::fs::remove_dir(&self.path).unwrap();
        std::fs::rename(saved, &self.path).unwrap();
        assert!(result.is_err(), "actual ledger acknowledgement must fail");
        result
    }
    fn failed(
        &self,
        reservation: &DeliveryReservation,
        error: &DiscordSendError,
    ) -> Result<(), EgressError> {
        self.inner.failed(reservation, error)
    }
    fn complete(&self) -> Result<(), EgressError> {
        self.inner.complete()
    }
}

#[tokio::test]
async fn acknowledgement_persistence_failure_stops_before_next_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery.sqlite3");
    let delivery = checkpoint(&path);
    let (base, accepted, server) = spawn_accepted_post_server(usize::MAX, path.clone()).await;
    let sink = DiscordEgressSink::new(Arc::new(transport(base)));
    let text = "x".repeat(MAX_MESSAGE_CODEPOINTS * 3);
    let checkpoint = Arc::new(FailAcknowledgement {
        inner: delivery,
        path: path.clone(),
    });
    assert!(sink.deliver(outbound(&text), checkpoint).await.is_err());
    assert_eq!(accepted.lock().len(), 1);
    let state = persisted_delivery(&path);
    assert!(state["pending"].is_object());
    assert_eq!(state["chunks"].as_array().map_or(0, Vec::len), 0);
    let reopened = ReplyDelivery::open(
        &path,
        "physical-test",
        DM_CHANNEL,
        "original-turn",
        None,
        None,
    )
    .unwrap();
    assert!(sink.deliver(outbound(&text), reopened).await.is_err());
    assert_eq!(accepted.lock().len(), 1);
    assert_eq!(persisted_delivery(&path), state);
    server.abort();
}

#[tokio::test]
async fn growth_and_shrink_keep_exact_references_across_reopened_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery.sqlite3");
    let initial = checkpoint(&path);
    let (base, accepted, server) = spawn_accepted_post_server(usize::MAX, path.clone()).await;
    let sink = DiscordEgressSink::new(Arc::new(transport(base)));
    let anchor = sink.deliver(outbound("short"), initial).await.unwrap();
    let grown = sink
        .deliver(
            outbound(&"x".repeat(MAX_MESSAGE_CODEPOINTS * 3)),
            checkpoint(&path),
        )
        .await
        .unwrap();
    assert_eq!(grown.anchor, anchor.anchor);
    assert_eq!(grown.tails.len(), 2);
    let shrunk = sink
        .deliver(outbound("short again"), checkpoint(&path))
        .await
        .unwrap();
    assert_eq!(shrunk.anchor, anchor.anchor);
    assert!(shrunk.tails.is_empty());
    let count = {
        let calls = accepted.lock();
        assert_eq!(
            calls
                .iter()
                .map(|(body, _)| body["_method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["POST", "PATCH", "POST", "POST", "PATCH", "DELETE", "DELETE"]
        );
        for (body, state) in calls.iter() {
            let operation = &state["pending"]["operation"];
            assert!(operation.is_object(), "reservation precedes every mutation");
            if body["_method"] == "DELETE" {
                assert!(body["_target"].as_str().unwrap().ends_with(
                    operation["Delete"]["reference"]["message_id"]
                        .as_str()
                        .unwrap()
                ));
            }
        }
        assert_eq!(
            calls[6].1["chunks"].as_array().unwrap().len(),
            2,
            "first delete acknowledgement persisted before second delete"
        );
        calls.len()
    };
    sink.deliver(outbound("short again"), checkpoint(&path))
        .await
        .unwrap();
    assert_eq!(
        accepted.lock().len(),
        count,
        "reopened completed target performs no HTTP"
    );
    server.abort();
}

#[tokio::test]
async fn unknown_patch_and_delete_block_restart_without_anchor_fallback() {
    for drop_attempt in [4, 5, 6] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("delivery.sqlite3");
        let initial = checkpoint(&path);
        let (base, accepted, server) = spawn_accepted_post_server(drop_attempt, path.clone()).await;
        let sink = DiscordEgressSink::new(Arc::new(transport(base)));
        let original = sink
            .deliver(outbound(&"x".repeat(MAX_MESSAGE_CODEPOINTS * 3)), initial)
            .await
            .unwrap();
        assert!(sink
            .deliver(outbound("short"), checkpoint(&path))
            .await
            .is_err());
        let state = persisted_delivery(&path);
        assert_eq!(
            state["chunks"][0]["reference"]["message_id"],
            original.anchor.message_id
        );
        assert_eq!(
            state["chunks"].as_array().unwrap().len(),
            if drop_attempt == 6 { 2 } else { 3 }
        );
        assert!(state["pending"].is_object());
        assert!(sink
            .deliver(outbound("short"), checkpoint(&path))
            .await
            .is_err());
        assert_eq!(accepted.lock().len(), drop_attempt);
        assert_eq!(persisted_delivery(&path), state);
        server.abort();
    }
}

#[tokio::test]
async fn reconciliation_requires_exact_channel_author_and_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("delivery.sqlite3");
    let delivery = ReplyDelivery::open(
        &path,
        "physical-test",
        DM_CHANNEL,
        "original-turn",
        Some("exact wire bytes"),
        Some(&json!({"replySent":false})),
    )
    .unwrap();
    let plan = delivery.prepare(&outbound("exact wire bytes")).unwrap();
    let _reservation = delivery.reserve(&plan.operations[0]).unwrap();
    drop(delivery);
    // Model an exited dispatcher, retaining the genuine reserved operation.
    // No test dispatch can be alive: reserve above never entered transport.
    let mut ledger = Ledger::open(&path).unwrap();
    let row = ledger.conversation_deliveries().unwrap().remove(0);
    let mut state: Value = serde_json::from_str(&row.state_json).unwrap();
    state["pending"]["dispatcher_pid"] = json!(u32::MAX);
    assert!(!Path::new("/proc").join(u32::MAX.to_string()).exists());
    let row = ledger
        .cas_conversation_delivery(
            &row.object_id,
            row.revision,
            &state.to_string(),
            OffsetDateTime::now_utc(),
        )
        .unwrap();
    drop(ledger);
    let exact = json!({"id":"11000000000000001", "channel_id":DM_CHANNEL,
        "author":{"id":"11000000000000002", "bot":true}, "content":"exact wire bytes"});
    let response = Arc::new(Mutex::new(exact.clone()));
    let message_response = response.clone();
    let app = axum::Router::new()
        .route(
            "/users/@me",
            axum::routing::get(|| async {
                axum::Json(json!({"id":"11000000000000002", "bot":true}))
            }),
        )
        .route(
            "/channels/{channel}/messages/{message}",
            axum::routing::get(move || {
                let response = message_response.lock().clone();
                async move { axum::Json(response) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rest = transport(format!("http://{}", listener.local_addr().unwrap()));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    for wrong in [
        json!({"channel_id":"other-channel"}),
        json!({"author":{"id":"another-bot", "bot":true}}),
        json!({"content":"similar, not exact wire bytes"}),
    ] {
        let mut candidate = exact.clone();
        for (key, value) in wrong.as_object().unwrap() {
            candidate[key] = value.clone();
        }
        *response.lock() = candidate;
        assert!(reconcile(
            &path,
            &row.object_id,
            row.revision,
            1,
            Some("11000000000000001"),
            &rest
        )
        .await
        .is_err());
        let unchanged = Ledger::open(&path)
            .unwrap()
            .conversation_delivery(&row.object_id)
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.revision, row.revision);
        assert_eq!(unchanged.state_json, row.state_json);
    }
    *response.lock() = exact;
    reconcile(
        &path,
        &row.object_id,
        row.revision,
        1,
        Some("11000000000000001"),
        &rest,
    )
    .await
    .unwrap();
    let reopened = ReplyDelivery::open(
        &path,
        "physical-test",
        DM_CHANNEL,
        "original-turn",
        Some("exact wire bytes"),
        None,
    )
    .unwrap();
    assert!(reopened
        .prepare(&outbound("exact wire bytes"))
        .unwrap()
        .operations
        .is_empty());
    let adopted = persisted_delivery(&path);
    assert!(adopted["pending"].is_null());
    assert_eq!(
        adopted["chunks"][0]["reference"]["message_id"],
        "11000000000000001"
    );
    assert_eq!(adopted["phase"], "committed");
    assert_eq!(adopted["projection"]["replySent"], true);
    server.abort();
}
