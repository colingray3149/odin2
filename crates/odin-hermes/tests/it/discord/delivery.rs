//! Gated delivery and envelope hygiene: kernel-gated R3 effects, typed credential absence, authenticated transport posts, split-replies that reach the transport whole, no token or account leakage.

use crate::discord::fixtures::{
    allowing, ingress_config, message, now, pairing, spawn_capture_server, store, DM_CHANNEL, OWNER,
};
use axum::response::IntoResponse;
use odin_domain::EffectClass;
use odin_hermes::discord::{
    DiscordCredential, DiscordRestTransport, DiscordSendError, DiscordTransport as _, SecretToken,
};
use odin_hermes::egress::OutgoingSink as _;
use odin_hermes::egress::{DiscordEgressSink, EgressError, OutboundMessage};
use odin_hermes::ingress::{DiscordIngress, EffectGate, IntentOutcome};
use odin_kernel::{ApprovalDecision, DecisionOutcome};
use odin_ledger::command::CommandTerminalStatus;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::VecDeque;
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
    let (api_base, captured) = spawn_capture_server(1_100_000_000_000_000_001).await;
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

    // No debug rendering of the transport exposes the secret value.
    let debugged = format!("{transport:?}");
    assert!(!debugged.contains(secret));

    // Non-loopback plain http is refused at construction.
    assert!(DiscordRestTransport::with_api_base(
        DiscordCredential::absent(),
        reqwest::Client::new(),
        "http://example.internal".to_owned(),
    )
    .is_err());
}

/// A file reaches the DM as a real attachment — one multipart
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

/// One captured Discord REST call of the split-reply suite: the method,
/// the message id the POST minted, and the JSON body. Failed POSTs are not
/// captures.
#[derive(Clone, Debug)]
struct ChunkCall {
    method: String,
    message_id: Option<String>,
}

/// A loopback Discord API taking posts, with scripted failures.
struct ChunkServer {
    calls: Mutex<Vec<ChunkCall>>,
    posts: AtomicU64,
    post_attempts: AtomicU64,
    /// 1-based POST attempts that answer 500 instead of posting.
    posts_to_fail: Mutex<VecDeque<u64>>,
}

impl ChunkServer {
    fn posted_ids(&self) -> Vec<String> {
        self.calls
            .lock()
            .iter()
            .filter(|call| call.method == "POST")
            .map(|call| call.message_id.clone().expect("posts mint ids"))
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
        posts: AtomicU64::new(11_000_000_000_000_000),
        post_attempts: AtomicU64::new(0),
        posts_to_fail: Mutex::new(VecDeque::new()),
    });
    let state = server.clone();
    let posts = axum::routing::post(
        move |axum::extract::Path(channel_id): axum::extract::Path<String>,
              axum::Json(_): axum::Json<Value>| {
            let state = state.clone();
            async move {
                let attempt = state.post_attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if scheduled_attempt(&state.posts_to_fail, attempt) {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let id = state.posts.fetch_add(1, Ordering::SeqCst).to_string();
                state.calls.lock().push(ChunkCall {
                    method: "POST".to_owned(),
                    message_id: Some(id.clone()),
                });
                axum::Json(json!({ "id": id, "channel_id": channel_id })).into_response()
            }
        },
    );
    let app = axum::Router::new().route("/channels/{channel_id}/messages", posts);
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
