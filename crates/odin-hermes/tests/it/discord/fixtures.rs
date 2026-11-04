//! Shared private fixtures for this suite; visible only to child modules here.

use odin_domain::{CapabilityId, EffectClass, SeatId};
use odin_hermes::correlation::ConversationTaskStore;
use odin_hermes::discord::DiscordMessage;
use odin_hermes::ingress::{
    GovernanceDecision, IngressConfig, IntakeGovernance, IntakeInvocation, OwnerPairing,
};
use odin_ledger::Ledger;
use serde_json::Value;
use std::sync::Arc;
use time::OffsetDateTime;

pub(crate) const OWNER: &str = "222222222222222222";

pub(crate) const DM_CHANNEL: &str = "900000000000000001";

/// The declared ask capability this fixture conversation binds: pure
/// configuration data, exactly as the daemon's strict wire section
/// supplies it.
pub(crate) const ASK_CAPABILITY: &str = "seat.ask.sinmara";

pub(crate) fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_789_000_000).unwrap()
}

pub(crate) fn pairing() -> OwnerPairing {
    OwnerPairing::new(OWNER).unwrap()
}

pub(crate) fn ingress_config(effect_class: EffectClass) -> IngressConfig {
    IngressConfig::new(
        SeatId::new("sinmara").unwrap(),
        CapabilityId::new(ASK_CAPABILITY).unwrap(),
        1,
        effect_class,
        900,
        Some(DM_CHANNEL.to_owned()),
    )
    .unwrap()
}

pub(crate) fn message(id: &str, author: &str, content: &str) -> DiscordMessage {
    DiscordMessage {
        id: id.to_owned(),
        channel_id: DM_CHANNEL.to_owned(),
        author_id: author.to_owned(),
        guild_id: None,
        content: content.to_owned(),
        attachments: Vec::new(),
    }
}

pub(crate) fn store(ledger: Ledger) -> Arc<ConversationTaskStore> {
    Arc::new(ConversationTaskStore::new(ledger))
}

struct AllowingGovernance;

impl IntakeGovernance for AllowingGovernance {
    fn authorize_intake(&self, _invocation: IntakeInvocation) -> GovernanceDecision {
        GovernanceDecision::Authorized {
            authorization_ref: "authz:test".to_owned(),
        }
    }
}

pub(crate) fn allowing() -> Arc<dyn IntakeGovernance> {
    Arc::new(AllowingGovernance)
}

pub(crate) struct CapturedRequest {
    pub(crate) channel_id: String,
    pub(crate) authorization: String,
    pub(crate) body: Value,
}

/// A loopback stand-in for Discord's message-create endpoint: it records every authenticated post
/// and answers with a strictly increasing posted-message id starting at `first_id`.
pub(crate) async fn spawn_capture_server(
    first_id: u64,
) -> (String, Arc<parking_lot::Mutex<Vec<CapturedRequest>>>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    let captured: Arc<parking_lot::Mutex<Vec<CapturedRequest>>> = Arc::default();
    let state = captured.clone();
    let next_id = Arc::new(AtomicU64::new(first_id));
    let app = axum::Router::new()
        .route(
            "/channels/{channel_id}/messages/{message_id}",
            axum::routing::delete(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"code": 10008, "message": "Unknown Message"})),
                )
            }),
        )
        .route(
            "/channels/{channel_id}/messages",
            axum::routing::post(
                move |axum::extract::Path(channel_id): axum::extract::Path<String>,
                      headers: axum::http::HeaderMap,
                      axum::Json(body): axum::Json<Value>| {
                    let state = state.clone();
                    let id = next_id.fetch_add(1, Ordering::SeqCst).to_string();
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
                        axum::Json(serde_json::json!({ "id": id, "channel_id": channel_id }))
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
