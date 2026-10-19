//! Gated delivery and envelope hygiene: kernel-gated R3 effects, typed credential absence, authenticated transport posts, split-replies that reach the transport whole, no token or account leakage.

use crate::fixtures::{
    allowing, ingress_config, message, now, pairing, store, CapturedRequest, DM_CHANNEL, OWNER,
};
use axum::response::IntoResponse;
use odin_domain::EffectClass;
use odin_hermes::discord::{
    DiscordCredential, DiscordRestTransport, DiscordSendError, DiscordTransport as _, SecretToken,
    MAX_MESSAGE_CODEPOINTS,
};
use odin_hermes::egress::OutgoingSink as _;
use odin_hermes::egress::{scrub_sensitive, DiscordEgressSink, EgressError, OutboundMessage};
use odin_hermes::ingress::{DiscordIngress, EffectGate, IntentOutcome};
use odin_kernel::{ApprovalDecision, DecisionOutcome};
use odin_ledger::command::CommandTerminalStatus;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn r3_effect_is_gated_denial_is_recorded_approval_executes() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R3),
    );

    // Denied leg: the effect stops at the kernel gate and the denial is
    // durably recorded with its evidence reference.
    let denied = ingress
        .admit(
            &message("1000000000000000005", OWNER, "buy more coffee"),
            now(),
        )
        .unwrap();
    let (denied_receipt, denied_approval) = match denied {
        IntentOutcome::EffectGated(receipt, approval) => (receipt, approval),
        _ => panic!("an R3 intent must be gated"),
    };
    let denial = ingress
        .decide_effect_approval(
            &denied_approval,
            ApprovalDecision::Deny {
                evidence_ref: "artifact:denial-1".to_owned(),
            },
            "colin",
            now(),
        )
        .unwrap();
    let observed_revision = match &denial {
        DecisionOutcome::Denied(evidence) => evidence.revision,
        other => panic!("expected the recorded denial, got {other:?}"),
    };
    let gate = ingress
        .gate_effect(
            &denied_receipt,
            &denied_approval.approval_id,
            observed_revision,
            now(),
        )
        .unwrap();
    match gate {
        EffectGate::Denied { evidence_ref } => {
            assert_eq!(evidence_ref, "artifact:denial-1");
        }
        _ => panic!("a denied effect must never carry an execution proof"),
    }
    let denied_task = ledger_store
        .task(&denied_receipt.command_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        denied_task.terminal_status,
        Some(CommandTerminalStatus::Rejected)
    );
    let result = denied_task.terminal_result.unwrap();
    assert_eq!(result["status"], "denied");
    assert_eq!(result["evidence_ref"], "artifact:denial-1");

    // Replaying the denied intent stays terminally non-executable: the
    // same durable task surfaces, the recorded denial is kept intact, and
    // no second task or idempotency claim is created.
    let replayed = ingress
        .admit(
            &message("1000000000000000005", OWNER, "buy more coffee"),
            now(),
        )
        .unwrap();
    let replayed_command_id = match replayed {
        IntentOutcome::GovernanceRejected { command_id } => command_id,
        _ => panic!("a denied intent must stay terminally non-executable on replay"),
    };
    assert_eq!(replayed_command_id, denied_receipt.command_id);
    let replayed_task = ledger_store
        .task(&denied_receipt.command_id)
        .unwrap()
        .expect("the denial record is kept");
    assert_eq!(
        replayed_task.terminal_status,
        Some(CommandTerminalStatus::Rejected)
    );
    assert_eq!(
        replayed_task.terminal_result.unwrap()["evidence_ref"],
        "artifact:denial-1"
    );
    assert_eq!(ledger_store.idempotency_claim_count().unwrap(), 1);

    // Approved leg: the kernel gate consumes the approval exactly once and
    // only then does the task settle as executed.
    let approved = ingress
        .admit(
            &message("1000000000000000006", OWNER, "book the dentist"),
            now(),
        )
        .unwrap();
    let (approved_receipt, approved_pending) = match approved {
        IntentOutcome::EffectGated(receipt, approval) => (receipt, approval),
        _ => panic!("an R3 intent must be gated"),
    };
    let decision = ingress
        .decide_effect_approval(
            &approved_pending,
            ApprovalDecision::Approve { evidence_ref: None },
            "colin",
            now(),
        )
        .unwrap();
    let observed_revision = match &decision {
        DecisionOutcome::Approved(approval) => approval.revision,
        other => panic!("expected the approval, got {other:?}"),
    };
    let gate = ingress
        .gate_effect(
            &approved_receipt,
            &approved_pending.approval_id,
            observed_revision,
            now(),
        )
        .unwrap();
    let EffectGate::Approved { accepted } = gate else {
        panic!("an approved effect must carry an execution proof");
    };
    ingress
        .settle_effect(&accepted, json!({"status": "executed"}), now())
        .unwrap();
    let approved_task = ledger_store
        .task(&approved_receipt.command_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        approved_task.terminal_status,
        Some(CommandTerminalStatus::Completed)
    );

    // An R1 configuration never gates: the task is admitted directly.
    let plain_store = store(Ledger::open_in_memory().unwrap());
    let plain = DiscordIngress::new(
        pairing(),
        plain_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    assert!(matches!(
        plain
            .admit(
                &message("1000000000000000007", OWNER, "note the idea"),
                now()
            )
            .unwrap(),
        IntentOutcome::Admitted(_)
    ));
}
#[tokio::test]
async fn absent_credentials_report_typed_unavailable_never_success() {
    let transport = DiscordRestTransport::new(DiscordCredential::absent());
    let error = transport
        .send_message(DM_CHANNEL, "status: task recorded")
        .await
        .unwrap_err();
    assert_eq!(error, DiscordSendError::CredentialsUnavailable);

    // The typed unavailability propagates through the egress sink.
    let sink = Arc::new(DiscordEgressSink::new(Arc::new(DiscordRestTransport::new(
        DiscordCredential::absent(),
    ))));
    let error = sink
        .send(OutboundMessage {
            channel_id: DM_CHANNEL.to_owned(),
            content: "status: task recorded".to_owned(),
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        EgressError::Transport(DiscordSendError::CredentialsUnavailable)
    ));
}
#[tokio::test]
async fn real_transport_posts_real_authenticated_request_without_token_leakage() {
    let (api_base, captured) = spawn_capture_server().await;
    let secret = "super-secret-bot-token-value";
    let transport = DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new(secret).unwrap(),
        ),
        reqwest::Client::new(),
        api_base,
    )
    .unwrap();

    let reference = transport
        .send_message(DM_CHANNEL, "task command:one: recorded")
        .await
        .unwrap();
    assert_eq!(reference.channel_id, DM_CHANNEL);

    let calls = captured.lock();
    assert_eq!(calls.len(), 1);
    let call = &calls[0];
    assert_eq!(call.channel_id, DM_CHANNEL);
    // The bearer value travels only in the Authorization header.
    assert_eq!(call.authorization, format!("Bot {secret}"));
    assert_eq!(call.body, json!({"content": "task command:one: recorded"}));
    let body_text = call.body.to_string();
    assert!(!body_text.contains(secret));
    drop(calls);

    // No debug rendering of the transport, credential, or errors exposes the
    // secret value.
    let debugged = format!("{transport:?}");
    assert!(!debugged.contains(secret));
    let error = DiscordSendError::CredentialsUnavailable;
    assert!(!format!("{error:?}").contains(secret));

    // Non-loopback plain http is refused at construction.
    assert!(DiscordRestTransport::with_api_base(
        DiscordCredential::absent(),
        reqwest::Client::new(),
        "http://example.internal".to_owned(),
    )
    .is_err());
}
#[tokio::test]
async fn fixture_account_number_never_reaches_an_outgoing_envelope() {
    let ledger_store = store(Ledger::open_in_memory().unwrap());
    let ingress = DiscordIngress::new(
        pairing(),
        ledger_store.clone(),
        allowing(),
        ingress_config(EffectClass::R1),
    );
    let content = format!("wire {FIXTURE_ACCOUNT} to savings tomorrow");
    let receipt = match ingress
        .admit(&message("1000000000000000008", OWNER, &content), now())
        .unwrap()
    {
        IntentOutcome::Admitted(receipt) => receipt,
        _other => panic!("expected a new durable task"),
    };

    // The receipt envelope carries identity and status only: neither the
    // message text nor the account number appears anywhere in it.
    let event_text = serde_json::to_string(&receipt.event).unwrap();
    assert!(!event_text.contains(FIXTURE_ACCOUNT));
    assert!(!event_text.contains("wire"));
    // The receipt payload is exactly the identity/status pair: there is
    // no content field it could hide text in.
    let payload = receipt.event.payload.as_object().expect("payload object");
    let payload_keys: BTreeSet<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(payload_keys, BTreeSet::from(["task", "status"]));

    // The content stayed durable inside the ledger for Sinmara processing —
    // non-exposure means envelopes, not data loss.
    let task = ledger_store.task(&receipt.command_id).unwrap().unwrap();
    assert_eq!(task.arguments["request"], content.as_str());
}
#[test]
fn scrub_sensitive_masks_credential_handles() {
    // Credential handles never survive scrubbing, even with no tokens
    // registered: the structural handle pattern is masked on its own.
    assert_eq!(
        scrub_sensitive("lease cred:discord.bot rotated", &BTreeSet::new()),
        "lease cred:[masked] rotated"
    );
}
const FIXTURE_ACCOUNT: &str = "4417229483";
async fn spawn_capture_server() -> (String, Arc<Mutex<Vec<CapturedRequest>>>) {
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let state = captured.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::post(
            move |axum::extract::Path(channel_id): axum::extract::Path<String>,
                  headers: axum::http::HeaderMap,
                  axum::Json(body): axum::Json<Value>| {
                let state = state.clone();
                async move {
                    state.lock().push(CapturedRequest {
                        channel_id: channel_id.clone(),
                        authorization: headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                        body,
                    });
                    axum::Json(json!({
                        "id": "1100000000000000001",
                        "channel_id": channel_id,
                    }))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (format!("http://{address}"), captured)
}

#[tokio::test]
async fn fetch_messages_after_requests_the_bounded_window_oldest_first() {
    // Loopback admission target serving Discord's real GET shape (the
    // newest-first window) for the reconnect catch-up.
    let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let state = captured.clone();
    let history = vec![
        json!({
            "id": "1000000000000000030",
            "channel_id": DM_CHANNEL,
            "author": { "id": "100000000000000001" },
            "content": "newest",
        }),
        json!({
            "id": "1000000000000000020",
            "channel_id": DM_CHANNEL,
            "author": { "id": "100000000000000001" },
            "content": "oldest",
        }),
    ];
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::get(
            move |axum::extract::Path(channel_id): axum::extract::Path<String>,
                  axum::extract::RawQuery(query): axum::extract::RawQuery,
                  headers: axum::http::HeaderMap| {
                let state = state.clone();
                async move {
                    state.lock().push((
                        channel_id.clone(),
                        headers
                            .get("authorization")
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or_default()
                            .to_owned(),
                    ));
                    let _ = query;
                    axum::Json(serde_json::Value::Array(history.clone()))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let secret = "super-secret-bot-token-value";
    let transport = DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new(secret).unwrap(),
        ),
        reqwest::Client::new(),
        format!("http://{address}"),
    )
    .unwrap();

    let messages = transport
        .fetch_messages_after(DM_CHANNEL, Some("1000000000000000010"), 50)
        .await
        .unwrap();
    // Discord returns newest first; intake order is oldest first.
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, "1000000000000000020");
    assert_eq!(messages[0].content, "oldest");
    assert_eq!(messages[1].id, "1000000000000000030");
    assert_eq!(messages[1].channel_id, DM_CHANNEL);
    // The bearer travelled only in the Authorization header, exactly once.
    {
        let calls = captured.lock();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, DM_CHANNEL);
        assert_eq!(calls[0].1, format!("Bot {secret}"));
    }
    // The bound is clamped to the catch-up window and a non-snowflake
    // cursor is refused before any request.
    assert!(transport
        .fetch_messages_after(DM_CHANNEL, Some("not-a-snowflake"), 50)
        .await
        .is_err());
    // A missing credential is typed unavailability, never a dial.
    let absent = DiscordRestTransport::with_api_base(
        DiscordCredential::absent(),
        reqwest::Client::new(),
        format!("http://{address}"),
    )
    .unwrap();
    assert!(absent
        .fetch_messages_after(DM_CHANNEL, None, 50)
        .await
        .is_err());
}

/// Case 27: a file reaches the DM as a real attachment — one multipart
/// message-create carrying the caption in `payload_json` and the exact bytes
/// in `files[0]` under the original name.
#[tokio::test]
async fn a_file_is_posted_as_one_multipart_attachment() {
    type Captured = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
    let captured: Captured = Arc::new(Mutex::new(Vec::new()));
    let state = captured.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::post(
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let state = state.clone();
                async move {
                    let kind = headers
                        .get("content-type")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    state.lock().push((kind, body.to_vec()));
                    axum::Json(json!({ "id": "1000000000000000777", "channel_id": DM_CHANNEL }))
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let transport = DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("test-token").unwrap(),
        ),
        reqwest::Client::new(),
        format!("http://{address}"),
    )
    .unwrap();
    let pdf = b"%PDF-1.7 schedule bytes".to_vec();
    let sent = transport
        .send_file(
            DM_CHANNEL,
            "Your fall class schedule.",
            "print-schedule.pdf",
            &pdf,
        )
        .await
        .unwrap();
    assert_eq!(sent.message_id, "1000000000000000777");
    let requests = captured.lock();
    assert_eq!(requests.len(), 1);
    let (kind, body) = &requests[0];
    assert!(kind.starts_with("multipart/form-data; boundary="), "{kind}");
    let text = String::from_utf8_lossy(body);
    assert!(text.contains("name=\"payload_json\""));
    assert!(text.contains("\"content\":\"Your fall class schedule.\""));
    assert!(text.contains("name=\"files[0]\"; filename=\"print-schedule.pdf\""));
    assert!(body
        .windows(pdf.len())
        .any(|window| window == pdf.as_slice()));
}

/// A loopback channel answering each POST with the next scripted response;
/// returns the base URL and the instant each POST arrived.
async fn spawn_scripted_server(
    script: Vec<axum::response::Response>,
) -> (String, Arc<Mutex<Vec<std::time::Instant>>>) {
    let arrivals: Arc<Mutex<Vec<std::time::Instant>>> = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(std::collections::VecDeque::from(script)));
    let seen = arrivals.clone();
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::post(move || {
            let (seen, script) = (seen.clone(), script.clone());
            async move {
                seen.lock().push(std::time::Instant::now());
                script.lock().pop_front().expect("a scripted response")
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
    (format!("http://{address}"), arrivals)
}

fn scripted(status: u16, headers: &[(&str, &str)], body: Value) -> axum::response::Response {
    let mut builder = axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

fn loopback_transport(api_base: String) -> DiscordRestTransport {
    DiscordRestTransport::with_api_base(
        DiscordCredential::token(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
            SecretToken::new("bot-token").unwrap(),
        ),
        reqwest::Client::new(),
        api_base,
    )
    .unwrap()
}

fn sent() -> Value {
    json!({"id": "1100000000000000002", "channel_id": DM_CHANNEL})
}

#[tokio::test]
async fn a_rate_limited_reply_is_retried_once_after_the_wait() {
    let (api_base, arrivals) = spawn_scripted_server(vec![
        scripted(429, &[], json!({"retry_after": 0.2, "global": false})),
        scripted(200, &[], sent()),
    ])
    .await;
    let transport = loopback_transport(api_base);
    let reference = transport
        .send_message(DM_CHANNEL, "the answer")
        .await
        .expect("the retry delivers");
    assert_eq!(reference.message_id, "1100000000000000002");
    let arrivals = arrivals.lock();
    assert_eq!(arrivals.len(), 2);
    assert!(arrivals[1] - arrivals[0] >= std::time::Duration::from_millis(200));
}

#[tokio::test]
async fn a_second_rate_limit_is_reported_not_retried_forever() {
    let (api_base, arrivals) = spawn_scripted_server(vec![
        scripted(429, &[("retry-after", "0")], json!({})),
        scripted(429, &[], json!({"retry_after": 3.5})),
    ])
    .await;
    let error = loopback_transport(api_base)
        .send_message(DM_CHANNEL, "the answer")
        .await
        .expect_err("two 429s stay rate limited");
    assert!(matches!(
        error,
        DiscordSendError::RateLimited {
            retry_after_ms: 3500
        }
    ));
    assert_eq!(
        arrivals.lock().len(),
        2,
        "a 429 naming no wait still waits, once"
    );
}

#[tokio::test]
async fn a_spent_bucket_waits_for_its_reset_before_the_next_send() {
    let (api_base, arrivals) = spawn_scripted_server(vec![
        scripted(
            200,
            &[
                ("x-ratelimit-remaining", "0"),
                ("x-ratelimit-reset-after", "0.3"),
            ],
            sent(),
        ),
        scripted(200, &[], sent()),
    ])
    .await;
    let transport = loopback_transport(api_base);
    transport.send_message(DM_CHANNEL, "one").await.unwrap();
    transport.send_message(DM_CHANNEL, "two").await.unwrap();
    let arrivals = arrivals.lock();
    assert!(arrivals[1] - arrivals[0] >= std::time::Duration::from_millis(300));
}

/// One captured Discord REST call of the split-reply suite: the method,
/// the path's message id (a POST mints one), and the JSON body. Failed
/// POSTs and PATCHes are not captures; DELETE attempts always are.
#[derive(Clone, Debug)]
struct ChunkCall {
    method: String,
    message_id: Option<String>,
    body: Value,
}

/// A loopback Discord API tracking channel contents after successful writes
/// and deletes, with scripted failures for each REST method.
struct ChunkServer {
    calls: Mutex<Vec<ChunkCall>>,
    messages: Mutex<BTreeMap<(String, String), String>>,
    posts: AtomicU64,
    post_attempts: AtomicU64,
    patch_attempts: AtomicU64,
    delete_attempts: AtomicU64,
    /// 1-based POST attempts that answer 500 instead of posting.
    posts_to_fail: Mutex<VecDeque<u64>>,
    /// 1-based PATCH attempts that answer 500 instead of editing.
    patches_to_fail: Mutex<VecDeque<u64>>,
    /// 1-based DELETE attempts that answer 500 instead of deleting.
    deletes_to_fail: Mutex<VecDeque<u64>>,
    /// 1-based DELETE attempts that answer Discord's unknown-message 404.
    deletes_already_gone: Mutex<VecDeque<u64>>,
}

impl ChunkServer {
    fn channel_contents(&self, channel_id: &str) -> Vec<String> {
        self.messages
            .lock()
            .iter()
            .filter(|((channel, _), _)| channel == channel_id)
            .map(|(_, content)| content.clone())
            .collect()
    }

    fn posted_ids(&self) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .filter(|call| call.method == "POST")
            .map(|call| call.message_id.clone().expect("posts mint ids"))
            .collect()
    }

    fn contents(&self, method: &str) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .filter(|call| call.method == method)
            .map(|call| {
                call.body
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    }

    fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .map(|call| call.method.clone())
            .collect()
    }

    fn deleted_ids(&self) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .filter(|call| call.method == "DELETE")
            .map(|call| call.message_id.clone().expect("deletes name the id"))
            .collect()
    }
}

fn scheduled_attempt(schedule: &Mutex<VecDeque<u64>>, attempt: u64) -> bool {
    let mut schedule = schedule.lock();
    if schedule.front() == Some(&attempt) {
        schedule.pop_front();
        true
    } else {
        false
    }
}

async fn spawn_chunk_server() -> (String, Arc<ChunkServer>) {
    let server = Arc::new(ChunkServer {
        calls: Mutex::new(Vec::new()),
        messages: Mutex::new(BTreeMap::new()),
        posts: AtomicU64::new(11_000_000_000_000_000),
        post_attempts: AtomicU64::new(0),
        patch_attempts: AtomicU64::new(0),
        delete_attempts: AtomicU64::new(0),
        posts_to_fail: Mutex::new(VecDeque::new()),
        patches_to_fail: Mutex::new(VecDeque::new()),
        deletes_to_fail: Mutex::new(VecDeque::new()),
        deletes_already_gone: Mutex::new(VecDeque::new()),
    });
    let state = server.clone();
    let posts = axum::routing::post(
        move |axum::extract::Path(channel_id): axum::extract::Path<String>,
              axum::Json(body): axum::Json<Value>| {
            let state = state.clone();
            async move {
                let attempt = state.post_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if scheduled_attempt(&state.posts_to_fail, attempt) {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let id = state.posts.fetch_add(1, Ordering::SeqCst).to_string();
                state.messages.lock().insert(
                    (channel_id.clone(), id.clone()),
                    body["content"]
                        .as_str()
                        .expect("message content")
                        .to_owned(),
                );
                state.calls.lock().push(ChunkCall {
                    method: "POST".to_owned(),
                    message_id: Some(id.clone()),
                    body,
                });
                axum::Json(json!({ "id": id, "channel_id": channel_id })).into_response()
            }
        },
    );
    let state = server.clone();
    let edits = axum::routing::patch(
        move |axum::extract::Path((channel_id, message_id)): axum::extract::Path<(
            String,
            String,
        )>,
              axum::Json(body): axum::Json<Value>| {
            let state = state.clone();
            async move {
                let attempt = state.patch_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if scheduled_attempt(&state.patches_to_fail, attempt) {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let mut messages = state.messages.lock();
                let content = messages
                    .get_mut(&(channel_id.clone(), message_id.clone()))
                    .expect("PATCH names an existing message");
                *content = body["content"]
                    .as_str()
                    .expect("message content")
                    .to_owned();
                drop(messages);
                state.calls.lock().push(ChunkCall {
                    method: "PATCH".to_owned(),
                    message_id: Some(message_id.clone()),
                    body,
                });
                axum::Json(json!({ "id": message_id, "channel_id": channel_id })).into_response()
            }
        },
    );
    let state = server.clone();
    let deletes = axum::routing::delete(
        move |axum::extract::Path((channel_id, message_id)): axum::extract::Path<(
            String,
            String,
        )>| {
            let state = state.clone();
            async move {
                let attempt = state.delete_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                state.calls.lock().push(ChunkCall {
                    method: "DELETE".to_owned(),
                    message_id: Some(message_id.clone()),
                    body: Value::Null,
                });
                if scheduled_attempt(&state.deletes_to_fail, attempt) {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                state.messages.lock().remove(&(channel_id, message_id));
                if scheduled_attempt(&state.deletes_already_gone, attempt) {
                    return (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(json!({
                            "code": 10008,
                            "message": "Unknown Message",
                        })),
                    )
                        .into_response();
                }
                axum::http::StatusCode::NO_CONTENT.into_response()
            }
        },
    );
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages/{message_id}",
        edits.merge(deletes),
    );
    let app = app.route("/channels/{channel_id}/messages", posts);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    (format!("http://{address}"), server)
}

fn chunk_sink(api_base: &str) -> DiscordEgressSink {
    DiscordEgressSink::new(Arc::new(loopback_transport(api_base.to_owned())))
}

fn message_to(channel: &str, content: String) -> OutboundMessage {
    OutboundMessage {
        channel_id: channel.to_owned(),
        content,
    }
}

/// Five sections below the per-message limit form an oversized report with a citation at its tail.
fn chemnode_report() -> String {
    let finding = "The fitted band widens past 400 K and the ablation holds. ".repeat(29);
    let mut report = String::from("# ChemNODE (arXiv:2101.04749)\n\n");
    for section in 0..5 {
        report.push_str(&format!("## Section {section}\n\n{finding}\n\n"));
    }
    report.push_str(
        "## Limitations\n\nThe training set covers 8 265 measured cells only; the \
         extrapolation beyond 400 K is unvalidated, and the citation trail ends at \
         the supplement (arXiv:2101.04749).",
    );
    report
}

#[tokio::test]
async fn an_oversized_report_reaches_the_transport_in_bounded_order() {
    let (api_base, server) = spawn_chunk_server().await;
    let payload = chemnode_report();
    assert!(
        payload.chars().count() >= 8_265,
        "the ChemNODE-sized payload"
    );
    let owned = chunk_sink(&api_base)
        .send(message_to(DM_CHANNEL, payload.clone()))
        .await
        .expect("the report posts");
    let posted = server.posted_ids();
    assert_eq!(posted.len(), 5, "four section chunks plus the tail chunk");
    assert_eq!(owned.anchor.message_id, posted[0], "the anchor is first");
    assert_eq!(
        owned
            .tails
            .iter()
            .map(|tail| tail.message_id.clone())
            .collect::<Vec<_>>(),
        posted[1..]
    );
    let contents = server.contents("POST");
    assert_eq!(contents.concat(), payload);
    for content in &contents {
        assert!(content.chars().count() <= MAX_MESSAGE_CODEPOINTS);
    }
    assert!(contents[0].ends_with("\n\n"), "breaks land on paragraphs");
    assert!(contents.last().unwrap().ends_with("(arXiv:2101.04749)."));
}

/// Multibyte text splits on code points, never inside a character.
#[tokio::test]
async fn a_multibyte_report_posts_whole_characters() {
    let (api_base, server) = spawn_chunk_server().await;
    let text = "定「比熱」を測った。🔬".repeat(700);
    assert!(text.chars().count() > MAX_MESSAGE_CODEPOINTS);
    let owned = chunk_sink(&api_base)
        .send(message_to(DM_CHANNEL, text.clone()))
        .await
        .expect("the multibyte report posts");
    let contents = server.contents("POST");
    assert!(contents.len() > 1);
    assert_eq!(contents.concat(), text, "no character lost or duplicated");
    assert_eq!(owned.anchor.message_id, server.posted_ids()[0]);
    for content in &contents {
        assert!(content.chars().count() <= MAX_MESSAGE_CODEPOINTS);
    }
}

/// A streamed answer that grows past the per-message bound gains tail
/// chunks in order; one that shrinks back has its surplus tails deleted,
/// the anchor id never changing.
#[tokio::test]
async fn an_edit_across_the_chunk_boundary_grows_and_shrinks() {
    let (api_base, server) = spawn_chunk_server().await;
    let sink = chunk_sink(&api_base);
    let owned = sink
        .send(message_to(DM_CHANNEL, "first words".to_owned()))
        .await
        .expect("the first words post");
    let anchor = owned.anchor.message_id.clone();
    assert_eq!(server.calls.lock().len(), 1);

    let grown = sink
        .edit(&owned, message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect("the grown reply reconciles");
    assert_eq!(grown.anchor.message_id, anchor, "the anchor never moves");
    assert_eq!(grown.tails.len(), 4, "four new tail chunks posted");
    assert_eq!(
        server.methods(),
        ["POST", "PATCH", "POST", "POST", "POST", "POST"],
        "the anchor is patched in place, the tails appended in order"
    );
    let contents = server.channel_contents(DM_CHANNEL);
    assert_eq!(contents.concat(), chemnode_report());
    assert!(contents
        .iter()
        .all(|content| content.chars().count() <= MAX_MESSAGE_CODEPOINTS));
    assert!(contents.last().unwrap().ends_with("(arXiv:2101.04749)."));

    let shrunk = sink
        .edit(&grown, message_to(DM_CHANNEL, "first words".to_owned()))
        .await
        .expect("the shrunk reply reconciles");
    assert_eq!(shrunk.anchor.message_id, anchor);
    assert!(shrunk.tails.is_empty());
    assert_eq!(server.channel_contents(DM_CHANNEL), ["first words"]);
    assert_eq!(
        server.deleted_ids(),
        grown
            .tails
            .iter()
            .map(|tail| tail.message_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        server.methods(),
        [
            "POST", "PATCH", "POST", "POST", "POST", "POST", "PATCH", "DELETE", "DELETE", "DELETE",
            "DELETE"
        ]
    );
}

/// A surplus tail Discord reports as already deleted counts as settled.
#[tokio::test]
async fn a_delete_of_an_already_gone_tail_is_settled() {
    let (api_base, server) = spawn_chunk_server().await;
    server.deletes_already_gone.lock().push_back(1);
    let sink = chunk_sink(&api_base);
    let owned = sink
        .send(message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect("the report posts");
    let shrunk = sink
        .edit(&owned, message_to(DM_CHANNEL, "short again".to_owned()))
        .await
        .expect("the unknown-message delete settles");
    assert!(shrunk.tails.is_empty());
    assert_eq!(server.deleted_ids().len(), 4);
}

/// A mid-split send failure is typed and honest: what landed is named, the
/// outcome is unknown-posted, and the very first chunk's failure stays a
/// plain transport error — whose unknown outcome the classifier reports.
#[tokio::test]
async fn a_mid_split_failure_reports_typed_partial_ownership() {
    let (api_base, server) = spawn_chunk_server().await;
    server.posts_to_fail.lock().push_back(2);
    let error = chunk_sink(&api_base)
        .send(message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect_err("the second chunk fails");
    let EgressError::Partial {
        ownership,
        applied,
        total,
        ..
    } = &error
    else {
        panic!("a mid-split failure is typed Partial: {error}");
    };
    assert_eq!((*applied, *total), (1, 5));
    assert_eq!(ownership.anchor.message_id, server.posted_ids()[0]);
    assert!(ownership.tails.is_empty());
    assert!(error.may_have_posted());
    assert!(error.post_outcome_unknown());
    assert!(error.to_string().contains("1 of 5"));

    let (quiet_base, quiet) = spawn_chunk_server().await;
    quiet.posts_to_fail.lock().push_back(1);
    let error = chunk_sink(&quiet_base)
        .send(message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect_err("the first chunk fails");
    assert!(
        matches!(
            error,
            EgressError::Transport(DiscordSendError::ServiceUnavailable)
        ),
        "a first-chunk failure stays a plain transport error: {error}"
    );
    assert!(
        error.may_have_posted(),
        "a 5xx answer means the request reached Discord with unknown outcome"
    );
    assert!(error.post_outcome_unknown());
}

/// A shrinking edit whose surplus delete fails keeps every still-standing
/// message in the error's ownership — the retry deletes the leftovers
/// instead of leaking the stale tail.
#[tokio::test]
async fn a_failed_shrink_delete_keeps_the_untouched_tail_owned() {
    let (api_base, server) = spawn_chunk_server().await;
    server.deletes_to_fail.lock().push_back(1);
    let sink = chunk_sink(&api_base);
    let owned = sink
        .send(message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect("the report posts");
    let ids: Vec<String> = owned
        .refs()
        .map(|reference| reference.message_id.clone())
        .collect();
    let error = sink
        .edit(&owned, message_to(DM_CHANNEL, "short again".to_owned()))
        .await
        .expect_err("the first delete fails");
    let EgressError::Partial {
        ownership,
        applied,
        total,
        ..
    } = &error
    else {
        panic!("a failed delete is typed Partial: {error}");
    };
    assert_eq!(
        (*applied, *total),
        (1, 5),
        "the write landed, the delete did not"
    );
    let held: Vec<String> = ownership
        .refs()
        .map(|reference| reference.message_id.clone())
        .collect();
    assert_eq!(held, ids, "the channel still holds all five messages");
    assert!(error.may_have_posted());
    assert!(!error.post_outcome_unknown());
}

#[tokio::test]
async fn a_failed_patch_keeps_partial_changes_owned_until_the_final_report_edit() {
    let (api_base, server) = spawn_chunk_server().await;
    server.patches_to_fail.lock().push_back(2);
    let sink = chunk_sink(&api_base);
    let report = chemnode_report();
    let draft = report
        .replace("fitted", "drafty")
        .replace("2101.04749", "0000.00000");
    let owned = sink
        .send(message_to(DM_CHANNEL, draft.clone()))
        .await
        .expect("the draft posts");
    let before = server.channel_contents(DM_CHANNEL);
    assert_eq!(before.concat(), draft);

    let error = sink
        .edit(&owned, message_to(DM_CHANNEL, report.clone()))
        .await
        .expect_err("the second PATCH fails after the anchor changes");
    let EgressError::Partial {
        ownership,
        applied,
        total,
        source,
        post_outcome_unknown,
    } = &error
    else {
        panic!("a mid-edit failure is typed Partial: {error}");
    };
    assert_eq!((*applied, *total), (1, 5));
    assert_eq!(*source, DiscordSendError::ServiceUnavailable);
    assert_eq!(ownership.as_ref(), &owned);
    assert!(error.may_have_posted());
    assert!(!post_outcome_unknown);
    assert!(!error.post_outcome_unknown());
    assert_eq!(server.patch_attempts.load(Ordering::SeqCst), 2);
    assert!(server.patches_to_fail.lock().is_empty());
    let partial = server.channel_contents(DM_CHANNEL);
    let mut expected_partial = before.clone();
    expected_partial[0] = before[0]
        .replace("drafty", "fitted")
        .replace("0000.00000", "2101.04749");
    assert_ne!(partial[0], before[0], "the first PATCH really landed");
    assert_eq!(partial, expected_partial);
    assert_eq!(partial.concat(), expected_partial.concat());
    assert_ne!(partial.concat(), report, "the failed edit is not complete");
    assert!(partial
        .iter()
        .all(|content| content.chars().count() <= MAX_MESSAGE_CODEPOINTS));

    let final_owned = sink
        .edit(ownership, message_to(DM_CHANNEL, report.clone()))
        .await
        .expect("the final edit restores every chunk, including the tail");
    assert_eq!(final_owned, owned, "the same five messages stay owned");
    assert_eq!(server.posted_ids().len(), 5, "no duplicate tail posts");
    assert!(server.deleted_ids().is_empty());
    assert_eq!(server.patch_attempts.load(Ordering::SeqCst), 7);
    let final_contents = server.channel_contents(DM_CHANNEL);
    assert_eq!(final_contents.concat(), report);
    assert!(final_contents
        .iter()
        .all(|content| content.chars().count() <= MAX_MESSAGE_CODEPOINTS));
    assert!(final_contents.last().unwrap().contains("## Limitations"));
    assert!(final_contents
        .last()
        .unwrap()
        .ends_with("(arXiv:2101.04749)."));
}

#[tokio::test]
async fn a_second_delete_failure_preserves_only_the_remaining_tail_for_retry() {
    let (api_base, server) = spawn_chunk_server().await;
    server.deletes_to_fail.lock().push_back(2);
    let sink = chunk_sink(&api_base);
    let owned = sink
        .send(message_to(DM_CHANNEL, chemnode_report()))
        .await
        .expect("the report posts");
    let before = server.channel_contents(DM_CHANNEL);
    let error = sink
        .edit(&owned, message_to(DM_CHANNEL, "short again".to_owned()))
        .await
        .expect_err("the second DELETE fails, not the first");
    let EgressError::Partial {
        ownership,
        applied,
        total,
        source,
        post_outcome_unknown,
    } = &error
    else {
        panic!("a failed delete is typed Partial: {error}");
    };
    assert_eq!((*applied, *total), (2, 5));
    assert_eq!(*source, DiscordSendError::ServiceUnavailable);
    assert_eq!(ownership.anchor, owned.anchor);
    assert_eq!(ownership.tails, owned.tails[1..]);
    assert!(error.may_have_posted());
    assert!(!post_outcome_unknown);
    assert!(!error.post_outcome_unknown());
    assert_eq!(server.delete_attempts.load(Ordering::SeqCst), 2);
    assert!(server.deletes_to_fail.lock().is_empty());
    assert_eq!(
        server.channel_contents(DM_CHANNEL).concat(),
        format!("short again{}", before[2..].concat())
    );
    let shrunk = sink
        .edit(ownership, message_to(DM_CHANNEL, "short again".to_owned()))
        .await
        .expect("the retry removes all remaining tails");
    assert_eq!(shrunk.anchor, owned.anchor);
    assert!(shrunk.tails.is_empty());
    assert_eq!(server.channel_contents(DM_CHANNEL), ["short again"]);
}

#[tokio::test]
async fn a_failed_appended_tail_post_reports_unknown_outcome_after_the_anchor_patch() {
    let (api_base, server) = spawn_chunk_server().await;
    server.posts_to_fail.lock().push_back(2);
    let sink = chunk_sink(&api_base);
    let owned = sink
        .send(message_to(DM_CHANNEL, "first words".to_owned()))
        .await
        .expect("the short anchor posts");
    let report = chemnode_report();
    let expected_chunks = odin_hermes::egress::split_reply(&report, MAX_MESSAGE_CODEPOINTS);
    let error = sink
        .edit(&owned, message_to(DM_CHANNEL, report))
        .await
        .expect_err("the first appended tail POST has an unknown outcome");
    let EgressError::Partial {
        ownership,
        applied,
        total,
        source,
        post_outcome_unknown,
    } = &error
    else {
        panic!("a failed append after the anchor edit is typed Partial: {error}");
    };
    assert_eq!((*applied, *total), (1, 5));
    assert_eq!(*source, DiscordSendError::ServiceUnavailable);
    assert_eq!(ownership.as_ref(), &owned);
    assert!(ownership.tails.is_empty());
    assert!(*post_outcome_unknown);
    assert!(error.post_outcome_unknown());
    assert!(error.may_have_posted());
    assert_eq!(server.post_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(server.patch_attempts.load(Ordering::SeqCst), 1);
    assert!(server.posts_to_fail.lock().is_empty());
    assert_eq!(
        server.posted_ids(),
        std::slice::from_ref(&owned.anchor.message_id)
    );
    assert_eq!(server.methods(), ["POST", "PATCH"]);
    let contents = server.channel_contents(DM_CHANNEL);
    assert_eq!(contents, expected_chunks[..1]);
    assert_eq!(contents.concat(), expected_chunks[0]);
    assert!(contents[0].chars().count() <= MAX_MESSAGE_CODEPOINTS);
}
