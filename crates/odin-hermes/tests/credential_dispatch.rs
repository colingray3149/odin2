//! Credential preflight and approval consumption through the composed runtime and kernel dispatch.
//! Shared-ledger tests cover readiness refusal, single execution, and replay without redispatch.
//! Unreachable or silent provider endpoints distinguish readiness rejection from attempted exchange.

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::knowledge::ToolName;
use odin_domain::operation::Limits;
use odin_domain::{
    ApprovalId, CapabilityId, CommandId, Digest, EffectClass, LaneId, ProjectId, RunId, Scope,
    SeatId, SessionId, SliceId,
};
use odin_hermes::calendar::{CalendarEventDraft, CalendarMutation, CalendarProposal};
use odin_hermes::config::{HermesSettings, LifeAccountSettings, LifeProviderSettings};
use odin_hermes::google::GoogleTokenFile;
use odin_hermes::runtime::{
    hermes_capability_bindings, hermes_host_tools, HermesLedgers, HermesRuntime,
};
use odin_kernel::{
    ApprovalDecision, ApprovalGate, CapabilityContract, DecisionOutcome, HandlerBinding,
    IdempotencyPolicy, MintRequest, RetryPolicy, TokenIssuer,
};
use odin_ledger::lane_run::{create_lane, create_run, NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use odin_omp::host_tools::executor::HostToolExecutor;
use odin_omp::host_tools::operations::{
    admission_digest, correlation_for, seat_operation_policy, session_capsule_id,
    DeclaredOperationCatalog, FilesystemSchemaCatalog, HostToolOperationError, HostToolOperations,
    OperationStackInputs, ProvisionedFreshAuthorityProvider, RevisionMaterial,
    RevisionMaterialSource, SeatOperationPolicy, SeatOperationPolicyInputs,
    SessionOperationBinding, SessionOperationContext, SupervisedAdapterStatus,
    UnsupervisedAdapterStatus,
};
use odin_omp::host_tools::{HostToolRegistry, InternalBindingKey};
use serde_json::{json, Value};
use time::OffsetDateTime;

const ACCOUNT: &str = "sinmara";
const SECRET_VALUE: &str = "test-rendered-credential-material";
const KEY: &[u8] = b"credential-dispatch fixture signing key";
const SEAT: &str = "atlas";
const SLICE: &str = "slice.fixture";
const LANE: &str = "atlas-household";
const PROJECT: &str = "household";
const SESSION: &str = "00000000-0000-4000-8000-0000000000c1";
const RUN: &str = "run:live:00000000-0000-4000-8000-0000000000c0";
const WINDOW_START: &str = "2026-09-27T10:00:00Z";
const WINDOW_END: &str = "2026-09-27T11:00:00Z";
/// The declared-calendar stack's Google account, its credential handle and
/// private token file, its recorded Gmail draft, and its mail-only account.
const GOOGLE_ACCOUNT: &str = "personal";
const GOOGLE_HANDLE: &str = "cred:personal-google";
const GOOGLE_TOKEN: &str = "personal-google.token";
const GMAIL_DRAFT: &str = "gmail-draft-1";
const MAIL_ONLY_ACCOUNT: &str = "sinmara-mail";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("fixture capability id")
}

fn seat() -> SeatId {
    SeatId::new(SEAT).unwrap()
}

fn lane() -> LaneId {
    LaneId::new(LANE).unwrap()
}

fn project() -> ProjectId {
    ProjectId::new(PROJECT).unwrap()
}

fn run() -> RunId {
    RunId::new(RUN).unwrap()
}

fn session() -> SessionId {
    SessionId::new(SESSION).unwrap()
}

/// One faithful R3 contract per gated life capability: the real
/// capability ids, the real handler/evidence bindings, and the real
/// canonical schema references the repository filesystem serves.
fn contract(name: &str, tool: &str, evidence: &str) -> CapabilityContract {
    CapabilityContract {
        id: capability(name),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(tool).unwrap(),
        description: format!("fixture contract for the {name} dispatch regression"),
        handler: HandlerBinding::Builtin {
            name: tool.to_owned(),
        },
        input_schema_ref: format!("schemas/capability/{name}.input.json"),
        output_schema_ref: format!("schemas/capability/{name}.output.json"),
        effect_class: EffectClass::R3,
        seat_tags: BTreeSet::from(["*".to_owned()]),
        timeout_seconds: NonZeroU32::new(30).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 1 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: HandlerBinding::Builtin {
            name: evidence.to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// One contract exactly as the repository registry declares it, and
/// whether that declaration decides its own approval — derived exactly as
/// the published revision material derives it.
fn registry_contract(name: &str) -> (CapabilityContract, bool) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = format!("registry/capabilities/{name}/capability.toml");
    let source = std::fs::read_to_string(root.join(&path)).unwrap();
    let object = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Capability,
        name,
        &path,
        &source,
    )
    .unwrap();
    let odin_registry::ObjectConfig::Capability(declaration) = &object.config else {
        panic!("expected capability");
    };
    let admitted = odin_registry::relational::AdmittedBinding {
        version: declaration.version,
        input_schema: declaration.input_schema.clone().unwrap(),
        output_schema: declaration.output_schema.clone().unwrap(),
        handler: declaration.handler.clone().unwrap(),
        evidence_extractor: declaration.evidence_extractor.clone().unwrap(),
    };
    let decided =
        declaration.approval_decider == odin_registry::schema::ApprovalDeciderToml::Declaration;
    let contract = CapabilityContract::try_from_registry(&object, &admitted).unwrap();
    (contract, decided)
}

/// The deterministic identities the production handlers derive for
/// account-scoped send and calendar intents.
fn send_identity_key(draft_id: &str, draft_digest: &str) -> String {
    let material = format!("{ACCOUNT}\u{0}{draft_id}\u{0}{draft_digest}");
    let digest = Digest::hash(material.as_bytes());
    let mut key = String::from("email-send:");
    for byte in digest.as_bytes().iter().take(8) {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

fn propose_identity_key(account: &str, title: &str, start: &str, end: &str) -> String {
    let proposal = CalendarProposal {
        account: account.to_owned(),
        mutation: CalendarMutation::Create(CalendarEventDraft {
            title: title.to_owned(),
            start: start.to_owned(),
            end: end.to_owned(),
            location: Some("Longhouse".to_owned()),
            description: None,
        }),
    };
    let canonical = serde_json::to_vec(&proposal).expect("fixture proposal serializes");
    let digest = Digest::hash(&canonical);
    let mut key = String::from("calendar-propose:");
    for byte in digest.as_bytes().iter().take(8) {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

fn command_id(identity_key: &str) -> CommandId {
    CommandId::new(format!("command:{identity_key}")).expect("intent command id")
}

/// The revision material the fresh authority recomposes: revision 1 over
/// the fixture contracts, the (seat, lane) policy and the declaration-decided
/// capabilities, exactly as the provisioning path composes.
struct FixtureGeneration {
    material: RevisionMaterial,
}

impl FixtureGeneration {
    fn new(
        contracts: &BTreeMap<CapabilityId, CapabilityContract>,
        policy: &SeatOperationPolicy,
        declaration_decided: BTreeSet<CapabilityId>,
    ) -> Self {
        let admission = admission_digest(contracts, 1).expect("fixture admission digest");
        let mut tool_index = BTreeMap::new();
        for (id, contract) in contracts {
            tool_index.insert(contract.tool_name.as_ref().to_owned(), id.clone());
        }
        Self {
            material: RevisionMaterial {
                revision: 1,
                contracts: Arc::new(contracts.clone()),
                admission_digest: admission,
                seat_operation_bindings: BTreeMap::from([((seat(), lane()), policy.clone())]),
                session_lanes: BTreeMap::from([((seat(), project()), lane())]),
                tool_index,
                contract_adapters: BTreeSet::new(),
                declaration_decided,
                escalation_targets: Default::default(),
            },
        }
    }
}

impl RevisionMaterialSource for FixtureGeneration {
    fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String> {
        match revision {
            1 => Ok(self.material.clone()),
            other => Err(format!("fixture serves no publication revision {other}")),
        }
    }

    fn resolve_legacy(&self, _token: &odin_domain::SeatToken) -> Result<u64, String> {
        Err("fixture authority resolves no legacy generation".to_owned())
    }
}

/// Both kernel and adapter connections share one ledger file so settlement sees consumed approvals.
struct Stack {
    _root: tempfile::TempDir,
    secret_path: PathBuf,
    operations: HostToolOperations,
    ledger: Arc<Mutex<Ledger>>,
    binding: SessionOperationBinding,
    session: SessionId,
    draft_digest: String,
    /// The declared-calendar stack's recorded Gmail draft digest.
    google_draft_digest: Option<String>,
    runtime: Arc<HermesRuntime>,
    adapter: Arc<parking_lot::Mutex<Ledger>>,
}

/// The Gmail wire of the Google draft producer: it answers exactly the
/// draft creation, never anything a dispatch scenario sends.
struct GmailDraftWire;

impl odin_hermes::google::GoogleWire for GmailDraftWire {
    fn call(
        &self,
        request: odin_hermes::google::GoogleRequest,
    ) -> Result<odin_hermes::google::GoogleResponse, odin_hermes::account::TransportFault> {
        assert!(request.url.ends_with("/users/me/drafts"), "{}", request.url);
        Ok(odin_hermes::google::GoogleResponse {
            status: 200,
            body: json!({ "id": GMAIL_DRAFT }),
        })
    }
}

/// Produces the Google account's recorded draft through the real Google
/// provider and email adapter into the shared adapter ledger, under a
/// ready private token the scenarios later replace. Returns its digest.
fn produce_google_draft(
    root: &Path,
    ledger: &Arc<parking_lot::Mutex<Ledger>>,
    endpoint: &str,
) -> String {
    let token = root.join(GOOGLE_TOKEN);
    ready_token().write_private(&token).unwrap();
    let credential = odin_hermes::account::AccountSecretRef::new(
        odin_domain::huginn::OpaqueCredentialHandle::new(GOOGLE_HANDLE).unwrap(),
        token,
    )
    .unwrap();
    let provider = odin_hermes::google::GoogleProvider::new(
        odin_hermes::google::GoogleAccountConfig {
            account: GOOGLE_ACCOUNT.to_owned(),
            credential: credential.clone(),
            token_url: format!("{endpoint}/token"),
            gmail_api_url: format!("{endpoint}/gmail/v1"),
            calendar_api_url: format!("{endpoint}/calendar/v3"),
            calendar_id: "primary".to_owned(),
            request_timeout_ms: 1_000,
            max_response_bytes: 65_536,
        },
        Arc::new(GmailDraftWire),
    )
    .unwrap();
    let leases = Arc::new(odin_hermes::account::FileCredentialLeases::new(
        BTreeMap::from([(GOOGLE_ACCOUNT.to_owned(), credential)]),
    ));
    let producer = odin_hermes::email::EmailAdapter::new(
        Arc::clone(ledger),
        Arc::new(provider),
        leases,
        "fixture",
    );
    let receipt = producer
        .save_draft(
            &odin_hermes::account::EffectIdentity {
                idempotency_key: "google-draft".into(),
                correlation_id: "google-draft".into(),
            },
            &odin_hermes::email::EmailDraft {
                account: GOOGLE_ACCOUNT.into(),
                to: vec!["to@example.invalid".into()],
                subject: "Approved".into(),
                body_text: "Approved body".into(),
            },
            now(),
        )
        .unwrap();
    receipt.result["draftDigest"].as_str().unwrap().to_owned()
}

const OWNER: &str = "100000000000000001";
const CHANNEL: &str = "1000000000000000002";

/// Supplies ordered message ids beneath the production egress and delivery checkpoint paths.
#[derive(Default)]
struct ScriptedDiscord(parking_lot::Mutex<u64>);

#[async_trait::async_trait]
impl odin_hermes::discord::DiscordTransport for ScriptedDiscord {
    async fn send_message(
        &self,
        channel_id: &str,
        _content: &str,
    ) -> Result<odin_hermes::discord::DiscordMessageRef, odin_hermes::discord::DiscordSendError>
    {
        let mut next = self.0.lock();
        *next += 1;
        Ok(odin_hermes::discord::DiscordMessageRef {
            message_id: (1_000_000_000_000_000_000_u64 + (*next << 22)).to_string(),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        _content: &str,
    ) -> Result<odin_hermes::discord::DiscordMessageRef, odin_hermes::discord::DiscordSendError>
    {
        Ok(odin_hermes::discord::DiscordMessageRef {
            message_id: message_id.to_owned(),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn delete_message(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), odin_hermes::discord::DiscordSendError> {
        Ok(())
    }

    async fn trigger_typing(&self, _: &str) -> Result<(), odin_hermes::discord::DiscordSendError> {
        Ok(())
    }
}

impl Stack {
    fn open() -> Self {
        Self::with_intake_reader(false, false)
    }

    fn with_intake_reader(include_reader: bool, deny_reader: bool) -> Self {
        Self::compose(include_reader, deny_reader, false, None)
    }

    /// The stack whose runtime owns the paired owner conversation: owner
    /// questions are decided only on their complete delivered preview.
    fn with_owner() -> Self {
        Self::compose(false, false, true, None)
    }

    /// The stack composed from the CURRENT `calendar.propose` declaration
    /// beside a Google calendar account and a mail-only account, every
    /// provider endpoint of both naming the local `provider` listener.
    fn with_declared_calendar(provider: &TcpListener) -> Self {
        let port = provider.local_addr().unwrap().port();
        Self::compose(false, false, false, Some(port))
    }

    /// Delivers the complete question for `approval_id` to the paired owner
    /// and settles the owner's reply that follows it.
    fn owner_decides(&self, approval_id: &ApprovalId, revision: i64) -> i64 {
        let delivered = self
            .runtime
            .deliver_approval_question(&self.adapter, approval_id, CHANNEL, OWNER, now(), None)
            .expect("the complete exact question is delivered");
        let reply = delivered.sent_message_id.parse::<u64>().unwrap() + (1 << 22);
        let message = odin_hermes::runtime::AuthenticatedOwnerMessage {
            owner_user_id: OWNER.to_owned(),
            channel_id: CHANNEL.to_owned(),
            message_id: reply.to_string(),
            seat: seat(),
            project: project(),
            content: "yes".to_owned(),
        };
        match self.runtime.decide_delivered_approval(
            &self.adapter,
            &message,
            approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        ) {
            Ok(DecisionOutcome::Approved(approval)) => approval.revision,
            other => panic!("the owner's reply must approve, got {other:?}"),
        }
    }

    fn compose(
        include_reader: bool,
        deny_reader: bool,
        owner: bool,
        provider: Option<u16>,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("sinmara-email.secret");
        let ledger_path = root.path().join("dispatch-ledger.sqlite3");

        let mut contracts: BTreeMap<CapabilityId, CapabilityContract> = [
            contract(
                "email.send",
                "email_send",
                "odin_hermes_email_send_evidence",
            ),
            contract(
                "calendar.propose",
                "calendar_propose",
                "odin_hermes_calendar_propose_evidence",
            ),
            contract(
                "registry.author.grant",
                "registry_author_grant",
                "odin_hermes_registry_author_grant_evidence",
            ),
        ]
        .into_iter()
        .map(|contract| (contract.id.clone(), contract))
        .collect();
        if include_reader {
            for name in ["intake.read", "intake.file"] {
                let (contract, _) = registry_contract(name);
                if name == "intake.file" {
                    assert_eq!(contract.effect_class, EffectClass::R2);
                    assert_eq!(
                        contract.handler,
                        HandlerBinding::Builtin {
                            name: "intake_file".to_owned()
                        }
                    );
                } else {
                    assert_eq!(contract.effect_class, EffectClass::R1);
                    assert_eq!(contract.approval, odin_kernel::ApprovalRequirement::None);
                }
                contracts.insert(contract.id.clone(), contract);
            }
        }
        // The current declaration replaces the owner-gated fixture contract
        // and decides its own approval exactly as the published material does.
        let mut declaration_decided = BTreeSet::new();
        if provider.is_some() {
            let (contract, decided) = registry_contract("calendar.propose");
            if decided {
                declaration_decided.insert(contract.id.clone());
            }
            contracts.insert(contract.id.clone(), contract);
        }

        let mut accounts = vec![LifeAccountSettings {
            account: ACCOUNT.to_owned(),
            secret_handle: "cred:sinmara-email".to_owned(),
            secret_path: secret_path.clone(),
            provider: LifeProviderSettings::Jmap {
                session_url: provider.map_or_else(
                    || "https://jmap.example.invalid/session".to_owned(),
                    |port| format!("https://127.0.0.1:{port}/session"),
                ),
                identity_id: "identity-1".to_owned(),
                from_address: "sinmara@example.invalid".to_owned(),
                drafts_mailbox_id: "drafts".to_owned(),
                archive_mailbox_id: "archive".to_owned(),
                trash_mailbox_id: "trash".to_owned(),
                calendar_id: Some("calendar-1".to_owned()),
                request_timeout_ms: 1_000,
                max_response_bytes: 65_536,
            },
        }];
        let endpoint = provider.map(|port| format!("https://127.0.0.1:{port}"));
        if let Some(endpoint) = &endpoint {
            // The Google token is written ready by the draft producer below
            // and rewritten by each scenario; the mail-only account's
            // credential is present, so only its missing calendar refuses it.
            let mail_secret = root.path().join("sinmara-mail.secret");
            std::fs::write(&mail_secret, SECRET_VALUE).unwrap();
            accounts.extend([
                LifeAccountSettings {
                    account: GOOGLE_ACCOUNT.to_owned(),
                    secret_handle: GOOGLE_HANDLE.to_owned(),
                    secret_path: root.path().join(GOOGLE_TOKEN),
                    provider: LifeProviderSettings::Google {
                        token_url: format!("{endpoint}/token"),
                        gmail_api_url: format!("{endpoint}/gmail/v1"),
                        calendar_api_url: format!("{endpoint}/calendar/v3"),
                        calendar_id: "primary".to_owned(),
                        request_timeout_ms: 1_000,
                        max_response_bytes: 65_536,
                    },
                },
                LifeAccountSettings {
                    account: MAIL_ONLY_ACCOUNT.to_owned(),
                    secret_handle: "cred:sinmara-mail".to_owned(),
                    secret_path: mail_secret,
                    provider: LifeProviderSettings::Jmap {
                        session_url: format!("{endpoint}/session"),
                        identity_id: "identity-1".to_owned(),
                        from_address: "sinmara@example.invalid".to_owned(),
                        drafts_mailbox_id: "drafts".to_owned(),
                        archive_mailbox_id: "archive".to_owned(),
                        trash_mailbox_id: "trash".to_owned(),
                        calendar_id: None,
                        request_timeout_ms: 1_000,
                        max_response_bytes: 65_536,
                    },
                },
            ]);
        }
        let discord = owner.then(|| {
            odin_hermes::config::DiscordSettings::new(
                SEAT,
                PROJECT,
                OWNER,
                CHANNEL,
                "discord.intake",
                4,
                4096,
                "discord-bot-token",
                BTreeSet::new(),
                3600,
            )
            .unwrap()
        });
        let settings =
            HermesSettings::new(root.path().join("state"), discord, None, None, accounts).unwrap();
        // The owner conversation's admitted ask and intake declarations are
        // Hermes surface contracts; the dispatch stack serves only the rest.
        let mut hermes_contracts = contracts.clone();
        let (bound_projects, ownership) = if owner {
            let mut ask = contract(
                "seat.ask.atlas",
                "seat_ask",
                "odin_hermes_seat_ask_evidence",
            );
            ask.tool_name = ToolName::new("seat_ask_atlas").unwrap();
            ask.delegate_to = Some(seat());
            ask.input_schema_ref = "schemas/capability/seat.ask.input.json".to_owned();
            ask.output_schema_ref = "schemas/capability/seat.ask.output.json".to_owned();
            let mut intake = contract(
                "discord.intake",
                "discord_intake",
                "odin_hermes_discord_intake_evidence",
            );
            intake.effect_class = EffectClass::R1;
            intake.approval = odin_kernel::ApprovalRequirement::None;
            for extra in [ask, intake] {
                hermes_contracts.insert(extra.id.clone(), extra);
            }
            (
                BTreeMap::from([(seat(), BTreeSet::from([project()]))]),
                Some(odin_hermes::runtime::ConversationOwnership {
                    seat: seat(),
                    project: project(),
                    ask_capability: capability("seat.ask.atlas"),
                }),
            )
        } else {
            (BTreeMap::new(), None)
        };
        // The adapter ledger is a second connection to the SAME file the
        // kernel dispatch stack journals and consumes against.
        let adapter_ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&ledger_path).unwrap()));
        struct DraftExchange;
        impl odin_hermes::jmap::JmapExchange for DraftExchange {
            fn readiness(&self) -> Result<(), odin_hermes::account::TransportFault> {
                Ok(())
            }

            fn exchange(
                &self,
                request: &odin_hermes::jmap::JmapRequest,
                _lease: &odin_hermes::account::ScopedCredentialLease,
            ) -> Result<odin_hermes::jmap::JmapResponse, odin_hermes::account::TransportFault>
            {
                assert_eq!(request.method_calls[0].name, "Email/set");
                Ok(odin_hermes::jmap::JmapResponse {
                    responses: vec![odin_hermes::jmap::JmapResponseCall {
                        name: "Email/set".into(),
                        call_id: "s".into(),
                        arguments: json!({"created":{"draft":{"id":"draft-1"}}}),
                    }],
                })
            }
        }
        // Create the real bound draft before the scenarios begin, then restore
        // their initially absent credential. The runtime transport is unchanged.
        std::fs::write(&secret_path, SECRET_VALUE).unwrap();
        let secret = odin_hermes::account::AccountSecretRef::new(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
            secret_path.clone(),
        )
        .unwrap();
        let leases = Arc::new(odin_hermes::account::FileCredentialLeases::new(
            BTreeMap::from([(ACCOUNT.to_owned(), secret)]),
        ));
        let transport =
            odin_hermes::email::JmapEmailTransport::new(odin_hermes::email::JmapMailConfig {
                account_id: ACCOUNT.into(),
                identity_id: "identity-1".into(),
                from_address: "sinmara@example.invalid".into(),
                drafts_mailbox_id: "drafts".into(),
                archive_mailbox_id: "archive".into(),
                trash_mailbox_id: "trash".into(),
                exchange: Arc::new(DraftExchange),
            })
            .unwrap();
        let producer = odin_hermes::email::EmailAdapter::new(
            adapter_ledger.clone(),
            Arc::new(transport),
            leases,
            "fixture",
        );
        let receipt = producer
            .save_draft(
                &odin_hermes::account::EffectIdentity {
                    idempotency_key: "dispatch-draft".into(),
                    correlation_id: "dispatch-draft".into(),
                },
                &odin_hermes::email::EmailDraft {
                    account: ACCOUNT.into(),
                    to: vec!["to@example.invalid".into()],
                    subject: "Approved".into(),
                    body_text: "Approved body".into(),
                },
                now(),
            )
            .unwrap();
        let draft_digest = receipt.result["draftDigest"].as_str().unwrap().to_owned();
        std::fs::remove_file(&secret_path).unwrap();
        let google_draft_digest = endpoint
            .as_deref()
            .map(|endpoint| produce_google_draft(root.path(), &adapter_ledger, endpoint));
        let runtime = HermesRuntime::open(
            settings,
            HermesLedgers {
                conversation: Ledger::open_in_memory().unwrap(),
                adapter: Arc::clone(&adapter_ledger),
                purchase: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            },
            &hermes_contracts,
            None,
            8_192,
            bound_projects,
            ownership,
        )
        .unwrap();
        if owner {
            runtime
                .bind_notify_sink(Arc::new(odin_hermes::egress::DiscordEgressSink::new(
                    Arc::new(ScriptedDiscord::default()),
                )))
                .unwrap();
        }

        let registry = Arc::new({
            let mut registry = HostToolRegistry::new();
            // Exercise narrowing from the listed definition as well as the canonical schema.
            let author = hermes_host_tools(&runtime)
                .into_iter()
                .find(|tool| tool.definition().name == "registry_author_grant")
                .expect("the grant author tool is registered");
            registry.register(author).unwrap();
            for (id, tool) in hermes_capability_bindings(&runtime) {
                registry
                    .register_internal(InternalBindingKey::Builtin(id.to_owned()), tool)
                    .unwrap();
            }
            registry
        });

        let seat_revision = Digest::hash(b"seat");
        let slice_revision = Digest::hash(b"slice");
        let admission = admission_digest(&contracts, 1).unwrap();
        let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
        let policy = seat_operation_policy(SeatOperationPolicyInputs {
            seat_id: seat(),
            slice_id: SliceId::new(SLICE).unwrap(),
            lane_id: lane(),
            seat_revision,
            slice_revision,
            admission,
            seat_tool_refs: allowed.clone(),
            slice_capabilities: allowed.clone(),
            project_capabilities: allowed.clone(),
            lane_capabilities: allowed,
            denied_capabilities: if deny_reader {
                BTreeSet::from([capability("intake.read")])
            } else {
                BTreeSet::new()
            },
            denied_tools: BTreeSet::new(),
            resource_constraints: BTreeMap::new(),
            seat_categories: BTreeSet::from(["coordinator".to_owned()]),
        });

        let token_root = root.path().join("authority-tokens");
        std::fs::create_dir_all(&token_root).unwrap();
        let signing_key = {
            let mut key = KEY.to_vec();
            key.truncate(32);
            key
        };
        let session = session();
        let issued_at_ms = (odin_omp::host_tools::operations::wall_clock())();
        let token = TokenIssuer::new(signing_key.clone())
            .unwrap()
            .mint(MintRequest {
                seat: seat(),
                slice: SliceId::new(SLICE).unwrap(),
                lane: lane(),
                session: session.clone(),
                seat_revision,
                slice_revision,
                capability_policy_digest: admission,
                context_policy_digest: policy.context_policy_digest,
                issued_at_ms,
                expires_at_ms: issued_at_ms + 3_600_000,
                entropy: b"credential dispatch fixture token",
            })
            .unwrap();
        std::fs::write(
            token_root.join(format!("{}.json", session.as_str())),
            serde_json::to_vec(&token).unwrap(),
        )
        .unwrap();
        let authority_provider = Arc::new(
            ProvisionedFreshAuthorityProvider::open(token_root, signing_key)
                .expect("open provisioned authority provider"),
        );

        let catalog: Arc<dyn odin_kernel::OperationCatalog> = Arc::new(
            DeclaredOperationCatalog::from_contracts(
                &contracts,
                1,
                admission,
                Arc::clone(&registry),
                &BTreeSet::new(),
            )
            .expect("declared operation catalog"),
        );
        let executor = Arc::new(HostToolExecutor::new(Arc::clone(&registry)));
        let ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let operations = HostToolOperations::new(
            OperationStackInputs {
                workload_drafts: None,
                catalog,
                schemas: Arc::new(FilesystemSchemaCatalog::new(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
                )),
                adapter_executor: Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
                adapter_status: Arc::new(SupervisedAdapterStatus::new(
                    Arc::new(UnsupervisedAdapterStatus),
                    std::collections::BTreeSet::new(),
                    Duration::ZERO,
                )),
                executor,
                limits: Limits::new(100, 100, 100),
                clock: odin_omp::host_tools::operations::wall_clock(),
                ledger: Arc::clone(&ledger),
                revisions: Arc::new(FixtureGeneration::new(
                    &contracts,
                    &policy,
                    declaration_decided,
                )),
            },
            contracts.clone(),
            authority_provider,
        )
        .expect("operation stack");

        {
            let mut guard = ledger.lock().unwrap();
            create_lane(
                guard.connection(),
                &NewLane {
                    lane_id: lane(),
                    seat_id: seat(),
                    project_id: Some(project()),
                    template_id: "template:dispatch-fixture".to_owned(),
                    backend: "local_omp".to_owned(),
                    created_by: "operator:fixture".to_owned(),
                    created_at: OffsetDateTime::UNIX_EPOCH,
                    retained: false,
                },
            )
            .unwrap();
            if owner {
                // The live vehicle the owner conversation is bound to.
                guard
                    .create_live_session(&odin_ledger::live::NewLiveSession {
                        session_id: SessionId::new(&RUN["run:live:".len()..]).unwrap(),
                        seat_id: SEAT.to_owned(),
                        project_id: PROJECT.to_owned(),
                        slice_id: SLICE.to_owned(),
                        lane_id: LANE.to_owned(),
                        target_node_id: String::new(),
                        provider: "gateway".to_owned(),
                        model: "fixture".to_owned(),
                        title: None,
                        manifest: json!({}),
                        open_tab: false,
                        state: "ready".to_owned(),
                        created_at: OffsetDateTime::UNIX_EPOCH,
                    })
                    .unwrap();
            }
            create_run(
                guard.connection(),
                &NewRun {
                    run_id: run(),
                    lane_id: lane(),
                    attempt_number: 1,
                    workflow_id: Some("live:dispatch-fixture".to_owned()),
                    workflow_version: Some(1),
                    input_hash: "fixture".to_owned(),
                    accepted_capability_revision: None,
                    lease_id: None,
                    absolute_deadline: None,
                    retry_budget: 0,
                    created_at: OffsetDateTime::UNIX_EPOCH,
                },
            )
            .unwrap();
            let plan = guard
                .replace_plan(
                    &run(),
                    "Dispatch the governed life effect",
                    &[TodoSpec {
                        id: odin_domain::TodoId::new("todo:dispatch-fixture").unwrap(),
                        title: "Dispatch the governed life effect".to_owned(),
                        status: TodoStatus::Pending,
                    }],
                    0,
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap();
            guard
                .accept_plan(
                    &run(),
                    plan.revision,
                    "operator:fixture",
                    OffsetDateTime::UNIX_EPOCH,
                )
                .unwrap();
        }

        let binding = SessionOperationBinding {
            policy: policy.policy.clone(),
            context_policy_digest: policy.context_policy_digest,
            capsule_id: session_capsule_id(&session).unwrap(),
            served_revision: 1,
            parent: None,
        };

        Stack {
            _root: root,
            secret_path,
            operations,
            ledger,
            binding,
            session,
            draft_digest,
            google_draft_digest,
            runtime,
            adapter: adapter_ledger,
        }
    }

    fn scope(&self) -> Scope {
        Scope {
            seat: Some(seat()),
            project: Some(project()),
            lane: Some(lane()),
            run: Some(run()),
            session: Some(self.session.clone()),
            ..Scope::default()
        }
    }

    fn dispatch(
        &self,
        tool_name: &str,
        arguments: Value,
        request_id: &str,
    ) -> Result<Value, HostToolOperationError> {
        self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope(),
                execution: None,
            },
            tool_name,
            None,
            arguments,
            request_id,
        )
    }

    fn write_secret(&self) {
        std::fs::write(&self.secret_path, SECRET_VALUE).unwrap();
    }

    fn remove_secret(&self) {
        let _ = std::fs::remove_file(&self.secret_path);
    }

    fn approvals(&self) -> Vec<odin_ledger::approval::Approval> {
        self.ledger.lock().unwrap().approvals().unwrap()
    }

    fn approval(&self, approval_id: &ApprovalId) -> odin_ledger::approval::Approval {
        self.ledger
            .lock()
            .unwrap()
            .approval(approval_id)
            .unwrap()
            .expect("the approval row exists")
    }

    fn operation_row(&self, request_id: &str) -> Option<odin_ledger::operation::OperationRow> {
        let correlation =
            correlation_for(&self.session, request_id).expect("fixture correlation derives");
        odin_ledger::operation::operation_row(
            self.ledger.lock().unwrap().connection(),
            correlation.as_str(),
        )
        .unwrap()
    }

    fn command(&self, id: &CommandId) -> odin_ledger::command::Command {
        self.ledger
            .lock()
            .unwrap()
            .command(id)
            .unwrap()
            .expect("the command row exists")
    }

    /// The operator's decision through the real kernel approval gate.
    fn approve(&self, approval_id: &ApprovalId, revision: i64) -> i64 {
        let mut guard = self.ledger.lock().unwrap();
        match ApprovalGate::new(&mut guard)
            .decide(
                approval_id,
                revision,
                ApprovalDecision::Approve { evidence_ref: None },
                "operator:fixture",
                now(),
            )
            .unwrap()
        {
            DecisionOutcome::Approved(approval) => approval.revision,
            other => panic!("the operator approval must settle, got {other:?}"),
        }
    }
}

fn stage_csv(stack: &Stack, message: &str, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let root = stack._root.path().join("state/intake");
    let dir = root.join(message);
    std::fs::create_dir_all(&dir).unwrap();
    for path in [&root, &dir] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(dir.join("1.txt"), text).unwrap();
    std::fs::write(dir.join("1.json"), r#"{"filename":"life.csv"}"#).unwrap();
}

#[test]
fn intake_reader_dispatch_returns_exact_complete_csv_without_a_vault_or_class_writer() {
    let stack = Stack::with_intake_reader(true, false);
    // Nine data records; quoted delimiters and an embedded newline are bytes
    // to preserve, not a request for the reader to parse or count CSV rows.
    let csv = "name,value\nalpha,1\nbeta,2\n\"gamma,quoted\",3\n\"delta\ncontinued\",4\nepsilon,5\nzeta,6\neta,7\ntheta,8\niota,9\n";
    stage_csv(&stack, "1557195830124089344", csv);
    stage_csv(&stack, "1557195830124089345", "name,value\nother,99\n");
    for (message, expected, request) in [
        ("1557195830124089344", csv, "read-original"),
        (
            "1557195830124089345",
            "name,value\nother,99\n",
            "read-same-name",
        ),
    ] {
        let intake = format!("{message}/1");
        let result = stack
            .dispatch("intake_read", json!({"intake": intake}), request)
            .expect("R1 reading needs neither a class nor a vault writer");
        assert_eq!(
            result,
            json!({"intake": intake, "filename": "life.csv", "text": expected})
        );
    }
    assert!(stack.approvals().is_empty());
    assert!(!stack._root.path().join("vault").exists());
    assert!(
        stack
            .dispatch(
                "intake_file",
                json!({"intake": "1557195830124089344/1", "course": "ME 11", "title": "Data"}),
                "filing-still-unavailable",
            )
            .is_err(),
        "reader registration must not compose a class writer"
    );
}

#[test]
fn intake_reader_dispatch_denies_undeclared_and_explicitly_denied_authority() {
    for (include_reader, deny_reader) in [(false, false), (true, true)] {
        let stack = Stack::with_intake_reader(include_reader, deny_reader);
        stage_csv(&stack, "1557195830124089344", "private staged bytes");
        let error = stack
            .dispatch(
                "intake_read",
                json!({"intake": "1557195830124089344/1"}),
                "unauthorized-read",
            )
            .expect_err("unadmitted reader authority must not obtain bytes");
        assert!(!error.to_string().contains("private staged bytes"));
        assert!(stack.operation_row("unauthorized-read").is_none());
        assert!(stack.approvals().is_empty());
    }
}

#[test]
fn registry_author_model_calls_mint_and_consume_only_valid_normalized_scopes() {
    for skeleton in ["new-environment", "enable-capability", "remove-environment"] {
        {
            let absent = Value::Null;
            let stack = Stack::open();
            let first = json!({
                "skeleton": skeleton,
                "id": "fixture",
                "values": if skeleton == "remove-environment" {
                    absent.clone()
                } else {
                    json!("seat = \"sinmara\"")
                },
                "approvalId": absent,
            });
            let mut invalid = first.clone();
            invalid["unexpected"] = json!(true);
            assert!(stack
                .dispatch("registry_author_grant", invalid, "author-invalid")
                .is_err());
            assert!(stack.approvals().is_empty(), "invalid calls must not mint");
            assert!(stack.operation_row("author-invalid").is_none());

            let (approval_id, revision) = match stack
                .dispatch("registry_author_grant", first.clone(), "author-mint")
                .expect_err("a first call must ask for operator approval")
            {
                HostToolOperationError::ApprovalRequired {
                    approval_id,
                    revision,
                    ..
                } => (approval_id, revision),
                other => panic!("expected approval request for {skeleton}, got {other:?}"),
            };
            assert_eq!(stack.approvals().len(), 1);
            assert_eq!(
                stack.approval(&approval_id).status,
                odin_domain::ApprovalStatus::Requested
            );
            let approved_revision = stack.approve(&approval_id, revision);
            let mut retry = first;
            retry["approvalId"] = json!(approval_id.to_string());
            let mut invalid_retry = retry.clone();
            invalid_retry["id"] = json!("");
            assert!(stack
                .dispatch(
                    "registry_author_grant",
                    invalid_retry,
                    "author-invalid-retry"
                )
                .is_err());
            assert_eq!(
                stack.approval(&approval_id).status,
                odin_domain::ApprovalStatus::Approved
            );
            assert_eq!(stack.approval(&approval_id).revision, approved_revision);
            assert!(stack.operation_row("author-invalid-retry").is_none());

            let error = stack
                .dispatch("registry_author_grant", retry.clone(), "author-consume")
                .expect_err("the fixture deliberately has no authoring route");
            match error {
                HostToolOperationError::Authority(
                    odin_kernel::operation::OperationRejection::Executor(
                        odin_kernel::operation::ExecutorFault::Rejected { detail },
                    ),
                ) => assert!(
                    detail.contains("registry authoring is not composed on this host"),
                    "{detail}"
                ),
                other => panic!("expected the real author's unavailable route, got {other:?}"),
            }
            let consumed = stack.approval(&approval_id);
            assert_eq!(consumed.status, odin_domain::ApprovalStatus::Consumed);
            assert_eq!(consumed.revision, approved_revision + 1);
            let correlation = correlation_for(&stack.session, "author-consume").unwrap();
            let command = CommandId::new(format!("odin.omp.host_tool:{correlation}")).unwrap();
            assert_eq!(consumed.consumed_by_command_id.as_ref(), Some(&command));
            assert!(stack.operation_row("author-consume").is_some());
            assert!(stack
                .dispatch("registry_author_grant", retry, "author-consume")
                .is_err());
            assert_eq!(stack.approval(&approval_id).revision, consumed.revision);
            assert_eq!(stack.approvals().len(), 1, "replay must not remint");
        }
    }
}

#[test]
fn registry_author_refuses_invalid_approval_values_without_minting() {
    for approval in [json!(""), json!(42)] {
        let stack = Stack::open();
        let arguments = json!({
            "skeleton":"new-environment", "id":"fixture",
            "values":"seat = \"sinmara\"", "approvalId":approval,
        });
        assert!(stack
            .dispatch(
                "registry_author_grant",
                arguments,
                "author-invalid-approval"
            )
            .is_err());
        assert!(stack.approvals().is_empty());
        assert!(stack.operation_row("author-invalid-approval").is_none());
    }
}

fn send_phase_one(stack: &Stack) -> Value {
    json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest })
}

fn send_phase_two(stack: &Stack, approval_id: &ApprovalId) -> Value {
    json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest, "approvalId": approval_id.to_string() })
}

fn propose_phase_one() -> Value {
    json!({
        "account": ACCOUNT,
        "type": "create",
        "title": "Standup",
        "start": WINDOW_START,
        "end": WINDOW_END,
        "location": "Longhouse",
    })
}

fn propose_phase_two(approval_id: &ApprovalId) -> Value {
    let mut arguments = propose_phase_one();
    arguments["approvalId"] = json!(approval_id.to_string());
    arguments
}

#[test]
fn absent_credential_refuses_dispatch_before_any_mint_or_consume() {
    for tool_name in ["email_send", "calendar_propose"] {
        let stack = Stack::open();
        let (phase_one, phase_two_id) = if tool_name == "email_send" {
            (send_phase_one(&stack), "approval:r3:fixture-send")
        } else {
            (propose_phase_one(), "approval:r3:fixture-propose")
        };
        stack.remove_secret();

        // The first dispatch: the preflight refusal, not an approval
        // demand — and never a journaled or minted row.
        for (label, arguments, request_id) in [
            ("first dispatch", phase_one.clone(), "req-phase-one"),
            ("immediate retry", phase_one.clone(), "req-phase-one-again"),
            (
                "approved-retry shape",
                {
                    let mut retry = phase_one.clone();
                    retry["approvalId"] = json!(phase_two_id);
                    retry
                },
                "req-phase-two-shape",
            ),
        ] {
            let error = match stack.dispatch(tool_name, arguments, request_id) {
                Err(error) => error,
                Ok(value) => panic!("{tool_name} {label} must refuse, got {value}"),
            };
            let detail = match &error {
                HostToolOperationError::Arguments { detail } => detail,
                other => panic!(
                    "{tool_name} {label} must refuse at the declared preflight, got {other:?}"
                ),
            };
            assert!(
                detail.contains("credential"),
                "{tool_name} {label} refusal must name the credential prerequisite, got {detail}"
            );
            assert!(
                !format!("{error:?}").contains("ApprovalRequired"),
                "{tool_name} {label} must never demand an approval for a missing prerequisite"
            );
        }

        assert!(
            stack.approvals().is_empty(),
            "{tool_name}: the approval table must stay EMPTY, found {:?}",
            stack.approvals()
        );
        for request_id in [
            "req-phase-one",
            "req-phase-one-again",
            "req-phase-two-shape",
        ] {
            assert!(
                stack.operation_row(request_id).is_none(),
                "{tool_name}: no operation may journal for a refused dispatch ({request_id})"
            );
        }
    }
}

/// The d5-shaped race for credentials, end to end through the real
/// dispatch pipeline: the first dispatch mints exactly one durable
/// request; the operator approves it; the credential then VANISHES, and
/// the approved retry refuses at the preflight with the approved
/// decision untouched — still `Approved`, never consumed, no operation
/// journaled. Once the credential returns, the retry is consumed exactly
/// once and the handler runs exactly once; against the unreachable
/// example provider the dispatch settles its outcome honestly
/// in-doubt/aborted (never a faked success), and replaying the identical
/// dispatch routes to the typed redirect without re-consuming,
/// reminting, or re-executing. The provider-success twin of this cycle
/// is proven crate-internally over the deterministic scripted transport.
#[test]
fn approved_send_survives_readiness_refusal_then_consumes_and_executes_once() {
    let stack = Stack::with_owner();
    stack.write_secret();

    // Phase one: the gate admits the business request, the kernel gate
    // demands the approval, and the pipeline mints exactly one durable
    // request under the same ledger lock that journaled the intent.
    let (approval_id, requested_revision) = match stack
        .dispatch("email_send", send_phase_one(&stack), "req-send-1")
        .expect_err("the first R3 dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    {
        let approvals = stack.approvals();
        assert_eq!(approvals.len(), 1, "exactly one request is minted");
        assert_eq!(approvals[0].status, odin_domain::ApprovalStatus::Requested);
        assert_eq!(approvals[0].approval_id, approval_id);
    }

    // The owner decides the complete question delivered to the conversation.
    let approved_revision = stack.owner_decides(&approval_id, requested_revision);
    assert_eq!(
        stack.approval(&approval_id).status,
        odin_domain::ApprovalStatus::Approved
    );

    // The credential disappears before the approved retry. The preflight
    // refuses BEFORE the approval pin, the journal, or the gate — the
    // settled decision survives untouched, executable later.
    stack.remove_secret();
    let error = stack
        .dispatch(
            "email_send",
            send_phase_two(&stack, &approval_id),
            "req-send-2",
        )
        .expect_err("the dead credential must refuse the approved retry");
    match &error {
        HostToolOperationError::Arguments { detail } => assert!(
            detail.contains("credential"),
            "the refusal must name the credential prerequisite, got {detail}"
        ),
        other => panic!("expected the typed preflight refusal, got {other:?}"),
    }
    {
        let approval = stack.approval(&approval_id);
        assert_eq!(approval.status, odin_domain::ApprovalStatus::Approved,);
        assert_eq!(
            approval.revision, approved_revision,
            "no consumption happened"
        );
        assert_eq!(approval.consumed_by_command_id, None);
        assert!(
            stack.operation_row("req-send-2").is_none(),
            "a refused retry must never journal an operation"
        );
    }

    // The credential returns: the same approved decision is consumed
    // exactly once and the handler executes exactly once. The provider
    // is unreachable, so the handler reports the typed pre-dispatch
    // unavailability and the executor classifies it rejected (provably
    // pre-effect) — the approval consumption and the single execution
    // are the durable truths asserted here.
    stack.write_secret();
    let error = stack
        .dispatch(
            "email_send",
            send_phase_two(&stack, &approval_id),
            "req-send-3",
        )
        .expect_err("the unreachable example provider cannot settle a send");
    match &error {
        HostToolOperationError::Authority(
            odin_kernel::operation::OperationRejection::Executor(
                odin_kernel::operation::ExecutorFault::Rejected { detail },
            ),
        ) => assert!(
            detail.contains("unavailable"),
            "the pre-dispatch failure must stay typed, got {detail}"
        ),
        other => panic!("expected the executor's typed pre-dispatch rejection, got {other:?}"),
    }
    {
        let approval = stack.approval(&approval_id);
        assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
        assert_eq!(
            approval.revision,
            approved_revision + 1,
            "exactly one consumption"
        );
        let correlation = correlation_for(&stack.session, "req-send-3").unwrap();
        let host_command = CommandId::new(format!("odin.omp.host_tool:{correlation}"))
            .expect("the host command id");
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&host_command),
            "the consumption names the journaled dispatch command"
        );
        assert_eq!(stack.approvals().len(), 1);
        assert!(
            stack.operation_row("req-send-3").is_some(),
            "the consumed dispatch journals exactly one operation"
        );
    }

    // The handler ran exactly once: the intent it records from the
    // permit is durable, was accepted, and the provably-not-dispatched
    // transport failure settled it terminal `failed` with the
    // sanitized reason — never in-doubt, never success.
    let intent = stack.command(&command_id(&send_identity_key(
        "draft-1",
        &stack.draft_digest,
    )));
    assert_eq!(intent.arguments["account"], json!(ACCOUNT));
    assert_eq!(intent.arguments["draftId"], json!("draft-1"));
    assert!(
        intent.accepted_at.is_some(),
        "the single execution accepted the intent before dispatching"
    );
    assert_eq!(
        intent.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Failed),
        "the provably-not-dispatched failure settles terminal failed"
    );
    assert_eq!(
        intent
            .terminal_result
            .as_ref()
            .and_then(|result| result["reason"].as_str()),
        Some("service-unavailable"),
        "the terminal document carries the sanitized reason class only"
    );

    // The exact consumed retry recovers its existing aborted operation,
    // rather than asking for another approval or executing the handler again.
    let operation = stack.operation_row("req-send-3").unwrap();
    assert_eq!(
        operation.effect_state,
        odin_domain::operation::EffectState::Aborted
    );
    let replay = stack
        .dispatch(
            "email_send",
            send_phase_two(&stack, &approval_id),
            "req-send-3",
        )
        .expect_err("the original pre-effect failure remains aborted");
    assert!(matches!(replay, HostToolOperationError::Aborted));
    assert_eq!(stack.operation_row("req-send-3").as_ref(), Some(&operation));
    assert_eq!(stack.command(&intent.id), intent);
    {
        let approval = stack.approval(&approval_id);
        assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
        assert_eq!(
            approval.revision,
            approved_revision + 1,
            "the replay must not advance the row"
        );
        assert_eq!(
            stack.approvals().len(),
            1,
            "the consumed row must never be reminted under a fresh suffix"
        );
    }
}

/// Recorded intent must retain the complete approved proposal, including location.
#[test]
fn calendar_propose_mints_once_and_records_the_full_approved_proposal() {
    let stack = Stack::open();
    stack.write_secret();

    let (approval_id, requested_revision) = match stack
        .dispatch("calendar_propose", propose_phase_one(), "req-propose-1")
        .expect_err("the first R3 dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    assert_eq!(stack.approvals().len(), 1);
    let approved_revision = stack.approve(&approval_id, requested_revision);

    let error = stack
        .dispatch(
            "calendar_propose",
            propose_phase_two(&approval_id),
            "req-propose-2",
        )
        .expect_err("the unreachable example provider cannot settle a booking");
    match &error {
        HostToolOperationError::Authority(
            odin_kernel::operation::OperationRejection::Executor(
                odin_kernel::operation::ExecutorFault::Rejected { detail },
            ),
        ) => assert!(
            detail.contains("unavailable"),
            "the pre-dispatch failure must stay typed, got {detail}"
        ),
        other => panic!("expected the executor's typed pre-dispatch rejection, got {other:?}"),
    }
    {
        let approval = stack.approval(&approval_id);
        assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
        assert_eq!(approval.revision, approved_revision + 1);
        assert_eq!(stack.approvals().len(), 1);
    }

    // The recorded intent is the exact approved proposal: the optional
    // location the operator saw rides the durable record verbatim.
    let intent = stack.command(&command_id(&propose_identity_key(
        ACCOUNT,
        "Standup",
        WINDOW_START,
        WINDOW_END,
    )));
    assert_eq!(intent.arguments["account"], json!(ACCOUNT));
    assert_eq!(intent.arguments["mutation"]["type"], json!("create"));
    assert_eq!(intent.arguments["mutation"]["title"], json!("Standup"));
    assert_eq!(intent.arguments["mutation"]["start"], json!(WINDOW_START));
    assert_eq!(intent.arguments["mutation"]["end"], json!(WINDOW_END));
    assert_eq!(intent.arguments["mutation"]["location"], json!("Longhouse"));
    assert!(intent.accepted_at.is_some());

    // Recover the same terminal operation and exact provider intent, without
    // consuming again, reminting consent or re-running the provider handler.
    let operation = stack.operation_row("req-propose-2").unwrap();
    assert_eq!(
        operation.effect_state,
        odin_domain::operation::EffectState::Aborted
    );
    let replay = stack
        .dispatch(
            "calendar_propose",
            propose_phase_two(&approval_id),
            "req-propose-2",
        )
        .expect_err("the original pre-effect failure remains aborted");
    assert!(matches!(replay, HostToolOperationError::Aborted));
    assert_eq!(
        stack.operation_row("req-propose-2").as_ref(),
        Some(&operation)
    );
    assert_eq!(stack.command(&intent.id), intent);
    assert_eq!(stack.approval(&approval_id).revision, approved_revision + 1);
    assert_eq!(stack.approvals().len(), 1);
}

/// The silent local endpoint every provider URL of the declared-calendar
/// stack names. It never accepts; a nonblocking accept observes whether
/// any provider connection was attempted.
fn provider_listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

/// Whether a provider connection reached the listener since the last look.
fn provider_contacted(provider: &TcpListener) -> bool {
    match provider.accept() {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(error) => panic!("the provider listener failed: {error}"),
    }
}

/// A well-formed Google token whose access token is unexpired, so ready
/// credentials never need the token endpoint.
fn ready_token() -> GoogleTokenFile {
    GoogleTokenFile::new(
        "fixture-client",
        "fixture-client-secret",
        "fixture-refresh",
        "fixture-access",
        now() + time::Duration::hours(1),
    )
    .unwrap()
}

fn google_token() -> Vec<u8> {
    serde_json::to_vec(&ready_token()).unwrap()
}

fn write_google_token(stack: &Stack, bytes: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let path = stack._root.path().join(GOOGLE_TOKEN);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn propose_on(account: &str) -> Value {
    let mut arguments = propose_phase_one();
    arguments["account"] = json!(account);
    arguments
}

fn assert_refused_before_any_decision(stack: &Stack, tool: &str, label: &str, arguments: Value) {
    let request_id = format!("req-{tool}-{}", label.replace(' ', "-"));
    match stack.dispatch(tool, arguments, &request_id) {
        Err(HostToolOperationError::Arguments { .. }) => {}
        other => panic!("{label}: the declared preflight must refuse, got {other:?}"),
    }
    assert!(
        stack.approvals().is_empty(),
        "{label}: no approval may be minted or decided, found {:?}",
        stack.approvals()
    );
    assert!(
        stack.operation_row(&request_id).is_none(),
        "{label}: a refused dispatch must never journal or consume"
    );
}

/// Readiness parity, credential half: a Google token the provider itself
/// refuses at use — malformed, not private, unreadable — is refused by the
/// shared preflight before the CURRENT declaration decides, before anything
/// is consumed, and before any provider endpoint is contacted.
#[test]
fn unusable_google_token_refuses_calendar_before_any_decision_or_provider_request() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    let token = google_token();
    for (label, bytes, mode) in [
        ("malformed token", b"{\"provider\":".to_vec(), 0o600),
        ("wrong private mode", token.clone(), 0o644),
        ("unreadable token", token, 0o000),
    ] {
        write_google_token(&stack, &bytes, mode);
        let arguments = propose_on(GOOGLE_ACCOUNT);
        assert_refused_before_any_decision(&stack, "calendar_propose", label, arguments);
    }
    assert!(
        !provider_contacted(&provider),
        "no provider endpoint may be contacted"
    );
}

/// Readiness parity, routing half: an account declared for mail only is
/// refused a calendar mutation by the same preflight, although its
/// credential is present.
#[test]
fn mail_only_account_refuses_calendar_before_any_decision_or_provider_request() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    let arguments = propose_on(MAIL_ONLY_ACCOUNT);
    assert_refused_before_any_decision(&stack, "calendar_propose", "mail-only account", arguments);
    assert!(
        !provider_contacted(&provider),
        "no provider endpoint may be contacted"
    );
}

/// Readiness parity, proposal half: with ready credentials, a proposal the
/// existing validator refuses — an inverted or fractional span, or one
/// invalid member of a batch — is refused by the same preflight, not after
/// the declaration decided and its approval was consumed.
#[test]
fn invalid_calendar_proposal_refuses_before_any_decision_or_provider_request() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    write_google_token(&stack, &google_token(), 0o600);
    for (label, arguments) in [
        (
            "inverted span",
            json!({
                "account": GOOGLE_ACCOUNT,
                "type": "create",
                "title": "Standup",
                "start": WINDOW_END,
                "end": WINDOW_START,
            }),
        ),
        (
            "fractional span",
            json!({
                "account": GOOGLE_ACCOUNT,
                "type": "move",
                "eventId": "event-1",
                "start": "2026-09-27T10:00:00.5Z",
                "end": WINDOW_END,
            }),
        ),
        (
            "invalid batch member",
            json!({
                "account": GOOGLE_ACCOUNT,
                "type": "batchCreate",
                "drafts": [
                    { "title": "Standup", "start": WINDOW_START, "end": WINDOW_END },
                    { "title": "Retro", "start": WINDOW_START, "end": "2027-09-29T10:00:00Z" },
                ],
            }),
        ),
    ] {
        assert_refused_before_any_decision(&stack, "calendar_propose", label, arguments);
    }
    assert!(
        !provider_contacted(&provider),
        "no provider endpoint may be contacted"
    );
}

/// A ready account reaches the silent endpoint but cannot report a completed booking.
#[test]
fn declared_calendar_booking_asks_no_owner_question_and_reaches_the_provider() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    write_google_token(&stack, &google_token(), 0o600);
    stack
        .dispatch(
            "calendar_propose",
            propose_on(GOOGLE_ACCOUNT),
            "req-declared",
        )
        .expect_err("the silent endpoint cannot confirm a booking");
    let approvals = stack.approvals();
    assert_eq!(approvals.len(), 1, "{approvals:?}");
    assert_eq!(approvals[0].status, odin_domain::ApprovalStatus::Consumed);
    assert_eq!(
        approvals[0].decided_by.as_deref(),
        Some(format!("declaration:{SEAT}").as_str()),
        "the seat's declaration decides; the owner is never asked"
    );
    assert!(stack.operation_row("req-declared").is_some());
    assert!(
        provider_contacted(&provider),
        "the declared booking reaches the provider endpoint"
    );
}

/// Readiness parity, JMAP credential half: a bearer file the JMAP exchange
/// itself refuses at use — empty after trimming, or carrying a control
/// character — is present and readable, so only the shared preflight can
/// refuse it. Both gated JMAP capabilities refuse before the owner is asked
/// or the CURRENT declaration decides, with nothing journaled and no
/// provider endpoint contacted.
#[test]
fn malformed_jmap_bearer_refuses_email_send_and_calendar_before_any_decision() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    for (label, bytes) in [
        ("empty bearer", ""),
        ("control-character bearer", "rendered\u{7}credential"),
    ] {
        std::fs::write(&stack.secret_path, bytes).unwrap();
        assert_refused_before_any_decision(&stack, "email_send", label, send_phase_one(&stack));
        assert_refused_before_any_decision(&stack, "calendar_propose", label, propose_phase_one());
    }
    assert!(
        !provider_contacted(&provider),
        "no provider endpoint may be contacted"
    );
}

/// Readiness parity on the shared email port: a recorded Gmail draft whose
/// account token is malformed or not private is refused by the `email_send`
/// preflight before any owner question is minted, nothing is journaled,
/// and no provider endpoint is contacted. The same draft under a ready
/// token asks the owner exactly once, still without a provider request.
#[test]
fn unusable_google_token_refuses_email_send_before_any_owner_question() {
    let provider = provider_listener();
    let stack = Stack::with_declared_calendar(&provider);
    let send = json!({
        "account": GOOGLE_ACCOUNT,
        "draft_id": GMAIL_DRAFT,
        "draft_digest": stack.google_draft_digest.clone().unwrap(),
    });
    let token = google_token();
    for (label, bytes, mode) in [
        ("malformed token", b"{\"provider\":".to_vec(), 0o600),
        ("wrong private mode", token.clone(), 0o644),
    ] {
        write_google_token(&stack, &bytes, mode);
        assert_refused_before_any_decision(&stack, "email_send", label, send.clone());
    }
    assert!(
        !provider_contacted(&provider),
        "no provider endpoint may be contacted"
    );

    write_google_token(&stack, &token, 0o600);
    match stack.dispatch("email_send", send, "req-email-send-ready") {
        Err(HostToolOperationError::ApprovalRequired { .. }) => {}
        other => panic!("a ready send asks the owner once, got {other:?}"),
    }
    let approvals = stack.approvals();
    assert_eq!(approvals.len(), 1, "{approvals:?}");
    assert_eq!(approvals[0].status, odin_domain::ApprovalStatus::Requested);
    assert!(
        !provider_contacted(&provider),
        "asking the owner contacts no provider"
    );
}
