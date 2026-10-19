//! Shared private fixtures for this suite; visible only to child modules here.

use odin_domain::{CapabilityId, ProjectId, SeatId};
use odin_hermes::egress::{EgressError, OutboundMessage, ReplyChunks};
use odin_hermes::runtime::{ConversationOwnership, HermesRuntime};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(crate) fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

pub(crate) fn settings(dir: &std::path::Path) -> odin_hermes::config::HermesSettings {
    odin_hermes::config::HermesSettings::new(
        dir.join("state"),
        None,       // discord
        None,       // vault
        None,       // finance
        Vec::new(), // no life accounts
    )
    .unwrap()
}

/// The deployment fact the ask surfaces advertise: the projects the
/// configured lane bindings bind to each seat.
pub(crate) fn fixture_bound_projects() -> BTreeMap<SeatId, BTreeSet<ProjectId>> {
    [
        ("architect", &["colinremote", "dotfiles", "odin"][..]),
        ("gungnir", &["odin", "skuld"][..]),
        ("kubert", &["odin"][..]),
        ("sinmara", &["life"][..]),
    ]
    .into_iter()
    .map(|(seat, projects)| {
        (
            SeatId::new(seat).unwrap(),
            projects
                .iter()
                .map(|project| ProjectId::new(*project).unwrap())
                .collect::<BTreeSet<_>>(),
        )
    })
    .collect()
}

/// Four declared delegation targets share the generic handler and extractor.
pub(crate) fn delegation_contracts() -> BTreeMap<CapabilityId, CapabilityContract> {
    [
        ("seat.ask.sinmara", "sinmara", "seat_ask_sinmara"),
        ("seat.ask.kubert", "kubert", "seat_ask_kubert"),
        ("seat.ask.gungnir", "gungnir", "seat_ask_gungnir"),
        ("seat.ask.architect", "architect", "seat_ask_architect"),
    ]
    .into_iter()
    .map(|(id, target, tool)| {
        let contract = CapabilityContract {
            id: CapabilityId::new(id).unwrap(),
            delegate_to: Some(SeatId::new(target).unwrap()),
            version: 1,
            tool_name: odin_domain::knowledge::ToolName::new(tool).unwrap(),
            description: format!("Delegate one bounded task to the {target} seat."),
            handler: odin_kernel::HandlerBinding::Builtin {
                name: "seat_ask".to_owned(),
            },
            input_schema_ref: "schemas/capability/seat.ask.input.json".to_owned(),
            output_schema_ref: "schemas/capability/seat.ask.output.json".to_owned(),
            effect_class: odin_domain::EffectClass::R3,
            seat_tags: BTreeSet::from(["coordinator".to_owned()]),
            timeout_seconds: std::num::NonZeroU32::new(30).unwrap(),
            idempotency: odin_kernel::IdempotencyPolicy::Required,
            retry: odin_kernel::RetryPolicy { max_attempts: 1 },
            approval: odin_kernel::ApprovalRequirement::Operator,
            evidence_extractor: odin_kernel::HandlerBinding::Builtin {
                name: "odin_hermes_seat_ask_evidence".to_owned(),
            },
            adapter: None,
            preview: None,
            batchable: false,
            batch: None,
        };
        (contract.id.clone(), contract)
    })
    .collect()
}

/// A runtime whose admitted contracts publish the fixture delegation
/// declarations — the shape every model-facing ask surface is generated
/// from.
pub(crate) fn runtime_with_declarations(dir: &std::path::Path) -> Arc<HermesRuntime> {
    HermesRuntime::open(
        settings(dir),
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &delegation_contracts(),
        None,
        8_192,
        fixture_bound_projects(),
        None,
    )
    .unwrap()
}

/// The model-facing ask tool names come from the admitted declarations.
pub(crate) fn delegation_tool_names() -> Vec<&'static str> {
    vec![
        "seat_ask_sinmara",
        "seat_ask_kubert",
        "seat_ask_gungnir",
        "seat_ask_architect",
    ]
}

/// The declared ownership of the fixture conversation: seat `sinmara`,
/// project `life`, gated by an admitted ask contract that delegates to
/// exactly this seat.
pub(crate) fn conversation_ownership() -> ConversationOwnership {
    ConversationOwnership {
        seat: SeatId::new("sinmara").unwrap(),
        project: ProjectId::new("life").unwrap(),
        ask_capability: CapabilityId::new("seat.ask.sinmara").unwrap(),
    }
}

pub(crate) fn owner_ask_contract() -> CapabilityContract {
    delegation_contracts()
        .get(&CapabilityId::new("seat.ask.sinmara").unwrap())
        .unwrap()
        .clone()
}

pub(crate) const INTENT_OWNER: &str = "100000000000000001";

pub(crate) const INTENT_DM_CHANNEL: &str = "1000000000000000002";

pub(crate) fn discord_settings() -> odin_hermes::config::DiscordSettings {
    odin_hermes::config::DiscordSettings::new(
        "sinmara",
        "life",
        INTENT_OWNER,
        INTENT_DM_CHANNEL,
        "discord.intake",
        4,
        4096,
        "discord-bot-token",
        BTreeSet::new(),
        3600,
    )
    .unwrap()
}

pub(crate) fn intake_contract(effect_class: odin_domain::EffectClass) -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new("discord.intake").unwrap(),
        delegate_to: None,
        version: 1,
        tool_name: odin_domain::knowledge::ToolName::new("discord_intake").unwrap(),
        description: "Owner-paired Discord intake.".to_owned(),
        handler: odin_kernel::HandlerBinding::Builtin {
            name: "odin_hermes_discord_intake".to_owned(),
        },
        input_schema_ref: "schemas/capability/discord.intake.input.json".to_owned(),
        output_schema_ref: "schemas/capability/discord.intake.output.json".to_owned(),
        effect_class,
        seat_tags: BTreeSet::from(["*".to_owned()]),
        timeout_seconds: std::num::NonZeroU32::new(30).unwrap(),
        idempotency: odin_kernel::IdempotencyPolicy::Required,
        retry: odin_kernel::RetryPolicy { max_attempts: 1 },
        approval: odin_kernel::ApprovalRequirement::None,
        evidence_extractor: odin_kernel::HandlerBinding::Builtin {
            name: "odin_hermes_discord_intake_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

struct AllowingAuthority;

impl odin_hermes::runtime::IntakeAuthorityFacts for AllowingAuthority {
    fn seat_token_revoked(&self, _seat: &str) -> bool {
        false
    }

    fn stopped(&self, _identity: &str) -> bool {
        false
    }
}

pub(crate) fn discord_runtime(
    dir: &std::path::Path,
    sinmara: odin_ledger::Ledger,
    effect_class: odin_domain::EffectClass,
) -> Arc<HermesRuntime> {
    let settings = odin_hermes::config::HermesSettings::new(
        dir.join("state"),
        Some(discord_settings()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    discord_runtime_with(settings, sinmara, effect_class)
}

pub(crate) fn discord_runtime_with(
    settings: odin_hermes::config::HermesSettings,
    sinmara: odin_ledger::Ledger,
    effect_class: odin_domain::EffectClass,
) -> Arc<HermesRuntime> {
    let capability = CapabilityId::new("discord.intake").unwrap();
    let mut contracts = BTreeMap::from([(capability, intake_contract(effect_class))]);
    // The conversation surface is governed by an admitted ask contract
    // delegating to exactly the declared owner seat.
    contracts.insert(owner_ask_contract().id.clone(), owner_ask_contract());
    let runtime = HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: sinmara,
            adapter: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        None,
        8_192,
        fixture_bound_projects(),
        Some(conversation_ownership()),
    )
    .unwrap();
    runtime.set_intake_authority(Arc::new(AllowingAuthority));
    runtime
}

pub(crate) fn owner_dm(message_id: &str, content: &str) -> odin_hermes::discord::DiscordMessage {
    odin_hermes::discord::DiscordMessage {
        id: message_id.to_owned(),
        channel_id: INTENT_DM_CHANNEL.to_owned(),
        author_id: INTENT_OWNER.to_owned(),
        guild_id: None,
        content: content.to_owned(),
        attachments: Vec::new(),
    }
}

/// One Discord REST history entry in the gateway-shaped JSON the
/// transport parses.
pub(crate) fn history_message(id: &str, author_id: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "channel_id": INTENT_DM_CHANNEL,
        "author": { "id": author_id },
        "content": content,
    })
}

/// Discord returns the newest window without a cursor, or the oldest
/// window after a cursor; each response is ordered newest first.
pub(crate) async fn paginated_history(
    backlog: Vec<serde_json::Value>,
) -> Arc<odin_hermes::discord::DiscordRestTransport> {
    let backlog = Arc::new(backlog);
    let app = axum::Router::new().route(
        "/channels/{channel_id}/messages",
        axum::routing::get(
            move |axum::extract::RawQuery(query): axum::extract::RawQuery| {
                let backlog = Arc::clone(&backlog);
                async move {
                    let mut after: Option<u64> = None;
                    let mut limit: usize = 50;
                    for pair in query.as_deref().unwrap_or("").split('&') {
                        let Some((key, value)) = pair.split_once('=') else {
                            continue;
                        };
                        match key {
                            "after" => after = Some(value.parse().expect("numeric cursor")),
                            "limit" => limit = value.parse().expect("numeric limit"),
                            _ => {}
                        }
                    }
                    let id = |message: &&serde_json::Value| {
                        message["id"].as_str().unwrap().parse::<u64>().unwrap()
                    };
                    let mut window: Vec<_> = backlog
                        .iter()
                        .filter(|message| after.is_none_or(|cursor| id(message) > cursor))
                        .collect();
                    window.sort_by_key(id);
                    if after.is_none() {
                        window.reverse();
                    }
                    window.truncate(limit);
                    if after.is_some() {
                        window.reverse();
                    }
                    axum::response::IntoResponse::into_response(axum::Json(window))
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
    Arc::new(
        odin_hermes::discord::DiscordRestTransport::with_api_base(
            odin_hermes::discord::DiscordCredential::token(
                odin_domain::huginn::OpaqueCredentialHandle::new("cred:discord.bot").unwrap(),
                odin_hermes::discord::SecretToken::new("test-token").unwrap(),
            ),
            reqwest::Client::new(),
            format!("http://{address}"),
        )
        .unwrap(),
    )
}

pub(crate) struct FakeRoute {
    executions: Mutex<Vec<odin_hermes::runtime::ApprovedIntentExecution>>,
    failure: Option<odin_hermes::runtime::IntentFailure>,
}

impl FakeRoute {
    pub(super) fn answering() -> Arc<Self> {
        Arc::new(Self {
            executions: Mutex::new(Vec::new()),
            failure: None,
        })
    }

    pub(super) fn failing(detail: &str) -> Arc<Self> {
        Arc::new(Self {
            executions: Mutex::new(Vec::new()),
            failure: Some(odin_hermes::runtime::IntentFailure::Other(
                detail.to_owned(),
            )),
        })
    }

    pub(super) fn count(&self) -> usize {
        self.executions.lock().len()
    }

    pub(super) fn execution_contents(&self) -> Vec<String> {
        self.executions
            .lock()
            .iter()
            .map(|execution| execution.content.clone())
            .collect()
    }

    pub(super) fn sole_execution(&self) -> odin_hermes::runtime::ApprovedIntentExecution {
        self.executions.lock().first().cloned().unwrap()
    }
}

#[async_trait::async_trait]
impl odin_hermes::runtime::ApprovedIntentRoute for FakeRoute {
    async fn execute(
        &self,
        intent: odin_hermes::runtime::ApprovedIntentExecution,
    ) -> Result<serde_json::Value, odin_hermes::runtime::IntentFailure> {
        self.executions.lock().push(intent.clone());
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        Ok(serde_json::json!({
            "conversationId": "conversation:sinmara:life",
            "answer": "Hi — Sinmara here.",
            "replySent": true,
        }))
    }
}

pub(crate) fn intent_task_id(projection: &serde_json::Value) -> odin_domain::CommandId {
    odin_domain::CommandId::new(projection["task"].as_str().unwrap().to_owned()).unwrap()
}

/// Records every send, reporting success with a deterministic transport
/// message identity — the durable stand-in for a proven Discord delivery.
/// The scripted ids are ordered decimal strings exactly like real
/// snowflakes, so the decision path's causal ordering is exercised against
/// honest transport identities.
#[derive(Default)]
pub(crate) struct RecordingNotifySink {
    pub(super) calls: Mutex<Vec<String>>,
    fail: Mutex<Option<odin_hermes::discord::DiscordSendError>>,
    next_id: Mutex<u64>,
    pub(super) posted_channel: Mutex<Option<String>>,
}

impl RecordingNotifySink {
    /// The first identity a scripted send posts.
    pub(super) const FIRST_POSTED_ID: u64 = 1_000_000_000_000_000_001;

    pub(super) fn message_id(offset_ms: u64) -> String {
        (Self::FIRST_POSTED_ID + (offset_ms << 22)).to_string()
    }

    pub(super) fn fail_next(&self, error: odin_hermes::discord::DiscordSendError) {
        *self.fail.lock() = Some(error);
    }
}

#[async_trait::async_trait]
impl odin_hermes::egress::OutgoingSink for RecordingNotifySink {
    async fn deliver(
        &self,
        message: OutboundMessage,
        checkpoint: std::sync::Arc<dyn odin_hermes::egress::DeliveryCheckpoint>,
    ) -> Result<ReplyChunks, EgressError> {
        use odin_hermes::egress::DeliveryOperation;
        let plan = checkpoint.prepare(&message)?;
        let mut held: Vec<_> = plan
            .ownership
            .as_ref()
            .map(|owned| owned.refs().cloned().collect())
            .unwrap_or_default();
        for operation in &plan.operations {
            let reservation = checkpoint.reserve(operation)?;
            let result = match operation {
                DeliveryOperation::Post { content, .. } => self
                    .send(OutboundMessage {
                        channel_id: message.channel_id.clone(),
                        content: content.clone(),
                    })
                    .await
                    .map(|reply| Some(reply.anchor)),
                DeliveryOperation::Patch {
                    reference, content, ..
                } => self
                    .edit(
                        &ReplyChunks::single(reference.clone()),
                        OutboundMessage {
                            channel_id: message.channel_id.clone(),
                            content: content.clone(),
                        },
                    )
                    .await
                    .map(|reply| Some(reply.anchor)),
                DeliveryOperation::Delete { reference } => {
                    let index = reference
                        .message_id
                        .parse::<u64>()
                        .ok()
                        .and_then(|id| id.checked_sub(Self::FIRST_POSTED_ID))
                        .and_then(|offset| usize::try_from(offset >> 22).ok());
                    let mut calls = self.calls.lock();
                    match index.and_then(|index| calls.get_mut(index)) {
                        Some(slot) => {
                            slot.clear();
                            Ok(None)
                        }
                        None => Err(EgressError::InvalidState("no such posted message")),
                    }
                }
            };
            let reference = match result {
                Ok(reference) => reference,
                Err(error) => {
                    if let EgressError::Transport(source) = &error {
                        checkpoint.failed(&reservation, source)?;
                    }
                    return Err(error);
                }
            };
            checkpoint.acknowledge(&reservation, reference.as_ref())?;
            match operation {
                DeliveryOperation::Post { .. } => held.push(reference.expect("POST reference")),
                DeliveryOperation::Patch { index, .. } => {
                    held[*index] = reference.expect("PATCH reference")
                }
                DeliveryOperation::Delete { reference } => held.retain(|held| held != reference),
            }
        }
        checkpoint.complete()?;
        let mut held = held.into_iter();
        Ok(ReplyChunks {
            anchor: held
                .next()
                .ok_or(EgressError::InvalidState("no acknowledged messages"))?,
            tails: held.collect(),
        })
    }

    async fn send(&self, message: OutboundMessage) -> Result<ReplyChunks, EgressError> {
        if let Some(error) = self.fail.lock().take() {
            return Err(EgressError::Transport(error));
        }
        let mut next = self.next_id.lock();
        let id = Self::message_id(*next);
        *next += 1;
        self.calls.lock().push(message.content);
        Ok(ReplyChunks::single(
            odin_hermes::discord::DiscordMessageRef {
                message_id: id,
                channel_id: self
                    .posted_channel
                    .lock()
                    .clone()
                    .unwrap_or(message.channel_id),
            },
        ))
    }

    async fn edit(
        &self,
        current: &ReplyChunks,
        message: OutboundMessage,
    ) -> Result<ReplyChunks, EgressError> {
        let first = Self::FIRST_POSTED_ID;
        let index = current
            .anchor
            .message_id
            .parse::<u64>()
            .ok()
            .and_then(|id| usize::try_from((id - first) >> 22).ok());
        let mut calls = self.calls.lock();
        let slot = index
            .and_then(|index| calls.get_mut(index))
            .ok_or(EgressError::InvalidState("no such posted message"))?;
        *slot = message.content;
        Ok(ReplyChunks {
            anchor: odin_hermes::discord::DiscordMessageRef {
                message_id: current.anchor.message_id.clone(),
                channel_id: message.channel_id,
            },
            tails: current.tails.clone(),
        })
    }

    async fn typing(&self, _channel_id: &str) -> Result<(), EgressError> {
        Ok(())
    }
}

/// The admitted contract the delivery gate words the question from.
fn ask_contract() -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new("seat.ask.gungnir").unwrap(),
        delegate_to: None,
        version: 1,
        tool_name: odin_domain::knowledge::ToolName::new("seat_ask_gungnir").unwrap(),
        description: "Delegate one bounded coding task to the governed Gungnir \
         implementation seat. Rejections are typed and prove no child was \
         created."
            .to_owned(),
        handler: odin_kernel::HandlerBinding::Builtin {
            name: "seat_ask".to_owned(),
        },
        input_schema_ref: "schemas/capability/seat.ask.input.json".to_owned(),
        output_schema_ref: "schemas/capability/seat.ask.output.json".to_owned(),
        effect_class: odin_domain::EffectClass::R3,
        seat_tags: BTreeSet::from(["coordinator".to_owned()]),
        timeout_seconds: std::num::NonZeroU32::new(30).unwrap(),
        idempotency: odin_kernel::IdempotencyPolicy::Required,
        retry: odin_kernel::RetryPolicy { max_attempts: 0 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: odin_kernel::HandlerBinding::Builtin {
            name: "odin_hermes_seat_ask_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// Requests one R3-style approval row in `ledger` targeting a live-ish
pub(crate) fn request_gate_approval(
    ledger: &mut Ledger,
    name: &str,
    now: time::OffsetDateTime,
) -> (odin_domain::ApprovalId, i64) {
    let approval_id = odin_domain::ApprovalId::new(format!("approval:gate:{name}")).unwrap();
    // The journaled PREAPPROVAL dispatch body: the arguments the first gated
    // call carried, before the derived approvalId existed.
    let arguments = serde_json::json!({
        "project": "life",
        "subject": format!("subject {name}"),
        "question": format!("fix the {name} pipeline"),
        "urgency": "high",
    });
    // The approval scope digest covers the retry-form arguments: the body
    // plus the derived approvalId (the dispatch gate's own derivation).
    let mut retry = arguments.clone();
    retry["approvalId"] = serde_json::Value::String(approval_id.to_string());
    let scope_digest = odin_kernel::arguments_digest(&retry);
    // The preapproval command row, scoped exactly as the dispatch journals
    // it: same issuer, target, capability, and the ORIGINAL arguments.
    ledger
        .record_command(&odin_ledger::command::CommandSpec {
            id: odin_domain::CommandId::new(format!("command:gate:{name}")).unwrap(),
            idempotency_key: format!("command:gate:{name}"),
            correlation_id: format!("correlation:gate:{name}"),
            causation_id: None,
            issuer: "sinmara".to_owned(),
            approval_id: None,
            target_kind: "run".to_owned(),
            target_id: "run:live:test-vehicle".to_owned(),
            capability_id: CapabilityId::new("seat.ask.gungnir").unwrap(),
            capability_version: 1,
            arguments_hash: odin_kernel::arguments_digest(&arguments),
            arguments,
            expected_desired_revision: None,
            issued_at: now,
            expires_at: now + time::Duration::hours(1),
        })
        .unwrap();
    let approval = ledger
        .request_approval(odin_ledger::approval::NewApproval {
            approval_id: approval_id.clone(),
            issuer: "sinmara".to_owned(),
            scope: odin_ledger::approval::ApprovalScope {
                target_kind: "run".to_owned(),
                target_id: "run:live:test-vehicle".to_owned(),
                capability_id: CapabilityId::new("seat.ask.gungnir").unwrap(),
                arguments_digest: scope_digest,
            },
            requested_at: now,
            expires_at: now + time::Duration::hours(1),
        })
        .unwrap();
    (approval_id, approval.revision)
}

pub(crate) fn gate_runtime(dir: &std::path::Path) -> Arc<HermesRuntime> {
    gate_runtime_with_adapter(
        dir,
        Arc::new(Mutex::new(
            Ledger::open(dir.join("gate-adapter.db")).unwrap(),
        )),
    )
}

pub(crate) fn gate_runtime_with_adapter(
    dir: &std::path::Path,
    adapter: Arc<Mutex<Ledger>>,
) -> Arc<HermesRuntime> {
    let settings = odin_hermes::config::HermesSettings::new(
        dir.join("state"),
        Some(discord_settings()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let contract = intake_contract(odin_domain::EffectClass::R1);
    let mut contracts = BTreeMap::from([(contract.id.clone(), contract)]);
    contracts.insert(
        CapabilityId::new("seat.ask.gungnir").unwrap(),
        ask_contract(),
    );
    contracts.insert(owner_ask_contract().id.clone(), owner_ask_contract());
    let runtime = HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open(dir.join("gate-conversation.db")).unwrap(),
            adapter,
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        None,
        8_192,
        fixture_bound_projects(),
        Some(conversation_ownership()),
    )
    .unwrap();
    // Published intake governance re-proves the LIVE seat-authority facts
    // on every invocation and refuses closed while unbound. This surface
    // binds the same all-allowing facts the Discord fixtures bind, so a
    // legitimate owner DM queues instead of governance-rejecting — the
    // refusal paths under test here are the delivery and decision ones.
    runtime.set_intake_authority(Arc::new(AllowingAuthority));
    runtime
}
