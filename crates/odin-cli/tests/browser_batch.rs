//! Exercises task grant approval, permit consumption, and browser coordination.
//! Only relay page mechanics and Discord message identities are scripted.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_browser::capability::{ActionArguments, ActionRequest, ElementRef};
use odin_browser::StructuralAction;
use odin_cli::browser_runtime::BrowserCommandCoordinator;
use odin_domain::knowledge::ToolName;
use odin_domain::operation::Limits;
use odin_domain::{
    ApprovalStatus, CapabilityId, Digest, EffectClass, LaneId, ProjectId, RunId, Scope, SeatId,
    SessionId, SliceId,
};
use odin_hermes::discord::{DiscordMessageRef, DiscordSendError, DiscordTransport};
use odin_hermes::runtime::{AuthenticatedOwnerMessage, ConversationOwnership, HermesRuntime};
use odin_huginn::browser::BrowserProjection;
use odin_huginn::read_model::MaterializedReadModel;
use odin_kernel::{
    ApprovalRequirement, CapabilityContract, HandlerBinding, IdempotencyPolicy, MintRequest,
    RetryPolicy, TokenIssuer,
};
use odin_ledger::Ledger;
use odin_omp::host_tools::operations::{
    admission_digest, seat_operation_policy, session_capsule_id, DeclaredOperationCatalog,
    FilesystemSchemaCatalog, HostToolOperationError, HostToolOperations, OperationStackInputs,
    ProvisionedFreshAuthorityProvider, RevisionMaterial, RevisionMaterialSource,
    SeatOperationPolicyInputs, SessionOperationBinding, SessionOperationContext,
    SupervisedAdapterStatus, UnsupervisedAdapterStatus,
};
use odin_omp::host_tools::task_grants::TaskGrantStore;
use odin_omp::host_tools::{BrowserCapabilityOwner, HostToolRegistry, InternalBindingKey};
use serde_json::{json, Value};
use time::OffsetDateTime;
#[path = "support/browser.rs"]
mod browser_fixture;
use browser_fixture::{open_browser, BROWSER};

const SEAT: &str = "sinmara";
const PROJECT: &str = "life";
const LANE: &str = "sinmara-life";
const VEHICLE: &str = "00000000-0000-4000-8000-0000000000b0";
const SESSION: &str = "00000000-0000-4000-8000-0000000000b1";
const OWNER: &str = "100000000000000001";
const CHANNEL: &str = "1000000000000000002";

fn seat() -> SeatId {
    SeatId::new(SEAT).unwrap()
}

fn project() -> ProjectId {
    ProjectId::new(PROJECT).unwrap()
}

fn lane() -> LaneId {
    LaneId::new(LANE).unwrap()
}

fn run() -> RunId {
    RunId::new(format!("run:live:{VEHICLE}")).unwrap()
}

/// Discord-shaped ordered snowflakes: `id >> 22` is the causal order the
/// decision route compares.
fn snowflake(sequence: u64) -> String {
    (1_000_000_000_000_000_000_u64 + (sequence << 22)).to_string()
}

fn contract(id: &str, tool: &str, handler: &str, evidence: &str) -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new(id).unwrap(),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(tool).unwrap(),
        description: "Approve this exact batch".to_owned(),
        handler: HandlerBinding::Builtin {
            name: handler.to_owned(),
        },
        input_schema_ref: format!("schemas/capability/{id}.input.json"),
        output_schema_ref: format!("schemas/capability/{id}.output.json"),
        effect_class: EffectClass::R3,
        seat_tags: BTreeSet::from(["*".to_owned()]),
        timeout_seconds: NonZeroU32::new(30).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 0 },
        approval: ApprovalRequirement::Operator,
        evidence_extractor: HandlerBinding::Builtin {
            name: evidence.to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

#[derive(Default)]
struct ScriptedDiscord(Mutex<u64>);

#[async_trait::async_trait]
impl DiscordTransport for ScriptedDiscord {
    async fn send_message(
        &self,
        channel_id: &str,
        _content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError> {
        let mut next = self.0.lock().unwrap();
        *next += 1;
        Ok(DiscordMessageRef {
            message_id: snowflake(*next),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        _content: &str,
    ) -> Result<DiscordMessageRef, DiscordSendError> {
        Ok(DiscordMessageRef {
            message_id: message_id.to_owned(),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn delete_message(&self, _: &str, _: &str) -> Result<(), DiscordSendError> {
        Ok(())
    }

    async fn trigger_typing(&self, _: &str) -> Result<(), DiscordSendError> {
        Ok(())
    }
}

/// One exact batch entry bound to the session's live revision and policy.
async fn submit_effect(projection: &BrowserProjection, selector: &str) -> Value {
    let handle = projection.handle();
    let policy = handle.browser().policy().await;
    let request = ActionRequest::new(
        StructuralAction::SubmitForm,
        ActionArguments::Selector {
            selector: ElementRef::new(selector.to_owned()).unwrap(),
        },
    )
    .unwrap();
    json!({
        "sessionId": BROWSER,
        "expectedRevision": handle.browser().control_revision().await,
        "action": "submitForm",
        "arguments": {"selector": selector},
        "argumentsDigest": request.canonical_arguments_digest().to_string(),
        "policyRevision": policy.revision(),
        "policyDigest": policy.digest().to_string(),
    })
}

struct Generation(RevisionMaterial);

impl RevisionMaterialSource for Generation {
    fn material_at(&self, revision: u64) -> Result<RevisionMaterial, String> {
        (revision == 1)
            .then(|| self.0.clone())
            .ok_or_else(|| format!("no publication revision {revision}"))
    }

    fn resolve_legacy(&self, _: &odin_domain::SeatToken) -> Result<u64, String> {
        Err("no legacy generation".to_owned())
    }
}

/// The real Hermes conversation surface (owner delivery and decision) and
/// the real OMP dispatch stack over the real grant handler and the real
/// browser capability owner.
fn compose(
    root: &Path,
    ledger_path: &Path,
    coordinator: &BrowserCommandCoordinator,
) -> (
    Arc<HermesRuntime>,
    HostToolOperations,
    SessionOperationBinding,
) {
    let mut grant = contract(
        "task.grant",
        "task_grant",
        "task_grant",
        "odin_hermes_task_grant_evidence",
    );
    grant.preview = Some(odin_registry::schema::PreviewKindToml::Batch);
    grant.batch = Some(odin_registry::schema::BatchLimitsToml {
        max_effects: 2,
        max_minutes: 10,
        max_uses: 2,
    });
    let mut browser = contract(
        "browser.consequential",
        "browser_consequential",
        "odin_browser.consequential",
        "odin_browser.consequential_evidence",
    );
    browser.preview = Some(odin_registry::schema::PreviewKindToml::Browser);
    browser.batchable = true;
    let contracts: BTreeMap<_, _> = [grant, browser]
        .into_iter()
        .map(|contract| (contract.id.clone(), contract))
        .collect();
    let mut hermes_contracts = contracts.clone();
    let mut ask = contract(
        "seat.ask.sinmara",
        "seat_ask_sinmara",
        "seat_ask",
        "odin_hermes_seat_ask_evidence",
    );
    ask.delegate_to = Some(seat());
    ask.input_schema_ref = "schemas/capability/seat.ask.input.json".to_owned();
    ask.output_schema_ref = "schemas/capability/seat.ask.output.json".to_owned();
    let mut intake = contract(
        "discord.intake",
        "discord_intake",
        "odin_hermes_discord_intake",
        "odin_hermes_discord_intake_evidence",
    );
    intake.effect_class = EffectClass::R1;
    intake.approval = ApprovalRequirement::None;
    for extra in [ask, intake] {
        hermes_contracts.insert(extra.id.clone(), extra);
    }
    let discord = odin_hermes::config::DiscordSettings::new(
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
    .unwrap();
    let runtime = HermesRuntime::open(
        odin_hermes::config::HermesSettings::new(
            root.join("hermes"),
            Some(discord),
            None,
            None,
            Vec::new(),
        )
        .unwrap(),
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(Ledger::open(ledger_path).unwrap())),
            purchase: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &hermes_contracts,
        None,
        8_192,
        BTreeMap::from([(seat(), BTreeSet::from([project()]))]),
        Some(ConversationOwnership {
            seat: seat(),
            project: project(),
            ask_capability: CapabilityId::new("seat.ask.sinmara").unwrap(),
        }),
    )
    .unwrap();
    runtime
        .bind_notify_sink(Arc::new(odin_hermes::egress::DiscordEgressSink::new(
            Arc::new(ScriptedDiscord::default()),
        )))
        .unwrap();
    let grants = Arc::new(TaskGrantStore::open(root.join("task-grants.json")));
    runtime.set_task_grants(Arc::clone(&grants));

    let mut registry = HostToolRegistry::new();
    for (id, tool) in odin_hermes::runtime::hermes_capability_bindings(&runtime) {
        registry
            .register_internal(InternalBindingKey::Builtin(id.to_owned()), tool)
            .unwrap();
    }
    registry
        .register_browser_capabilities(
            Arc::new(coordinator.clone()) as Arc<dyn BrowserCapabilityOwner>
        )
        .unwrap();
    let registry = Arc::new(registry);

    let slice = SliceId::new(LANE).unwrap();
    let session = SessionId::new(SESSION).unwrap();
    let (seat_revision, slice_revision) = (Digest::hash(b"seat"), Digest::hash(b"slice"));
    let admission = admission_digest(&contracts, 1).unwrap();
    let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
    let policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: seat(),
        slice_id: slice.clone(),
        lane_id: lane(),
        seat_revision,
        slice_revision,
        admission,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: BTreeMap::new(),
        seat_categories: BTreeSet::from(["coordinator".to_owned()]),
    });
    let key = b"browser batch fixture signing key".to_vec()[..32].to_vec();
    let issued_at_ms = (odin_omp::host_tools::operations::wall_clock())();
    let token = TokenIssuer::new(key.clone())
        .unwrap()
        .mint(MintRequest {
            seat: seat(),
            slice,
            lane: lane(),
            session: session.clone(),
            seat_revision,
            slice_revision,
            capability_policy_digest: admission,
            context_policy_digest: policy.context_policy_digest,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
            entropy: b"browser batch fixture token",
        })
        .unwrap();
    let tokens = root.join("authority-tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    std::fs::write(
        tokens.join(format!("{SESSION}.json")),
        serde_json::to_vec(&token).unwrap(),
    )
    .unwrap();
    let mut tool_index = BTreeMap::new();
    for (id, contract) in &contracts {
        tool_index.insert(contract.tool_name.as_ref().to_owned(), id.clone());
    }
    let generation = Generation(RevisionMaterial {
        revision: 1,
        contracts: Arc::new(contracts.clone()),
        admission_digest: admission,
        seat_operation_bindings: BTreeMap::from([((seat(), lane()), policy.clone())]),
        session_lanes: BTreeMap::from([((seat(), project()), lane())]),
        tool_index,
        contract_adapters: BTreeSet::new(),
        declaration_decided: BTreeSet::new(),
        escalation_targets: Default::default(),
    });
    let executor = Arc::new(odin_omp::host_tools::executor::HostToolExecutor::new(
        Arc::clone(&registry),
    ));
    let operations = HostToolOperations::new(
        OperationStackInputs {
            workload_drafts: None,
            catalog: Arc::new(
                DeclaredOperationCatalog::from_contracts(
                    &contracts,
                    1,
                    admission,
                    registry,
                    &BTreeSet::new(),
                )
                .unwrap(),
            ),
            schemas: Arc::new(FilesystemSchemaCatalog::new(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
            )),
            adapter_executor: Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
            adapter_status: Arc::new(SupervisedAdapterStatus::new(
                Arc::new(UnsupervisedAdapterStatus),
                BTreeSet::new(),
                Duration::ZERO,
            )),
            executor,
            limits: Limits::new(100, 100, 100),
            clock: odin_omp::host_tools::operations::wall_clock(),
            ledger: Arc::new(Mutex::new(Ledger::open(ledger_path).unwrap())),
            revisions: Arc::new(generation),
        },
        contracts,
        Arc::new(ProvisionedFreshAuthorityProvider::open(tokens, key).unwrap()),
    )
    .unwrap()
    .with_task_grants(grants);
    let binding = SessionOperationBinding {
        policy: policy.policy.clone(),
        context_policy_digest: policy.context_policy_digest,
        capsule_id: session_capsule_id(&session).unwrap(),
        served_revision: 1,
        parent: None,
    };
    (runtime, operations, binding)
}

/// The live vehicle the owner conversation is bound to, its run and the
/// accepted plan the side-effect gate requires.
fn seed_vehicle(ledger_path: &Path) {
    let now = OffsetDateTime::now_utc();
    let mut ledger = Ledger::open(ledger_path).unwrap();
    odin_ledger::lane_run::create_lane(
        ledger.connection(),
        &odin_ledger::lane_run::NewLane {
            lane_id: lane(),
            seat_id: seat(),
            project_id: Some(project()),
            template_id: "default".to_owned(),
            backend: "local_omp".to_owned(),
            created_by: "live-session".to_owned(),
            created_at: now,
            retained: false,
        },
    )
    .unwrap();
    ledger
        .create_live_session(&odin_ledger::live::NewLiveSession {
            session_id: SessionId::new(VEHICLE).unwrap(),
            seat_id: SEAT.to_owned(),
            project_id: PROJECT.to_owned(),
            slice_id: LANE.to_owned(),
            lane_id: LANE.to_owned(),
            target_node_id: String::new(),
            provider: "gateway".to_owned(),
            model: "fixture".to_owned(),
            title: None,
            manifest: json!({}),
            open_tab: false,
            state: "ready".to_owned(),
            created_at: now,
        })
        .unwrap();
    odin_ledger::lane_run::create_run(
        ledger.connection(),
        &odin_ledger::lane_run::NewRun {
            run_id: run(),
            lane_id: lane(),
            attempt_number: 1,
            workflow_id: Some("live:browser-batch".to_owned()),
            workflow_version: Some(1),
            input_hash: "browser-batch".to_owned(),
            accepted_capability_revision: None,
            lease_id: None,
            absolute_deadline: None,
            retry_budget: 0,
            created_at: now,
        },
    )
    .unwrap();
    let plan = ledger
        .replace_plan(
            &run(),
            "Submit the two approved forms",
            &[odin_ledger::plan::TodoSpec {
                id: odin_domain::TodoId::new("todo:browser-batch").unwrap(),
                title: "Submit the two approved forms".to_owned(),
                status: odin_ledger::plan::TodoStatus::Pending,
            }],
            0,
            now,
        )
        .unwrap();
    ledger
        .accept_plan(&run(), plan.revision, "operator:fixture", now)
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_decided_browser_batch_runs_each_entry_once_through_the_real_coordinator() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let ledger_path = root.join("authority.sqlite3");
    seed_vehicle(&ledger_path);
    let dispatched = Arc::new(Mutex::new(Vec::new()));
    let (projection, coordinator) = open_browser(
        &root,
        Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap())),
        Arc::clone(&dispatched),
        Arc::new(MaterializedReadModel::with_limits(
            4096,
            8192,
            OffsetDateTime::now_utc(),
        )),
    )
    .await;
    let first = submit_effect(&projection, "#approve-form").await;
    let second = submit_effect(&projection, "#send-form").await;
    let (runtime, operations, binding) = compose(&root, &ledger_path, &coordinator);
    let approvals = Ledger::open(&ledger_path).unwrap();
    let requested = move || {
        approvals
            .approvals()
            .unwrap()
            .into_iter()
            .filter(|approval| approval.status == ApprovalStatus::Requested)
            .count()
    };
    let recorded = Arc::clone(&dispatched);
    tokio::task::spawn_blocking(move || {
        let session = SessionId::new(SESSION).unwrap();
        let scope = Scope {
            seat: Some(seat()),
            project: Some(project()),
            lane: Some(lane()),
            run: Some(run()),
            session: Some(session.clone()),
            ..Scope::default()
        };
        let dispatch = |tool: &str, arguments: Value, request: &str| {
            operations.dispatch_tool(
                SessionOperationContext {
                    binding: &binding,
                    session: &session,
                    scope: &scope,
                    execution: None,
                },
                tool,
                None,
                arguments,
                request,
            )
        };
        let batch = json!({
            "task": "Submit the two approved forms", "minutes": 10, "max_uses": 2,
            "effects": [
                {"capability": "browser.consequential", "arguments": first},
                {"capability": "browser.consequential", "arguments": second},
            ],
        });
        let (id, revision) = match dispatch("task_grant", batch.clone(), "batch-request") {
            Err(HostToolOperationError::ApprovalRequired {
                approval_id,
                revision,
                ..
            }) => (approval_id, revision),
            other => panic!("the batch must ask its owner question: {other:?}"),
        };
        let adapter = Arc::new(parking_lot::Mutex::new(Ledger::open(&ledger_path).unwrap()));
        runtime
            .deliver_approval_question(
                &adapter,
                &id,
                CHANNEL,
                OWNER,
                OffsetDateTime::now_utc(),
                None,
            )
            .expect("the complete exact batch question is delivered");
        let decided = runtime
            .decide_delivered_approval(
                &adapter,
                &AuthenticatedOwnerMessage {
                    owner_user_id: OWNER.to_owned(),
                    channel_id: CHANNEL.to_owned(),
                    message_id: snowflake(1_000),
                    seat: seat(),
                    project: project(),
                    content: "yes".to_owned(),
                },
                &id,
                revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                OffsetDateTime::now_utc(),
            )
            .expect("the owner's reply follows the delivered question");
        assert!(matches!(decided, odin_kernel::DecisionOutcome::Approved(_)));
        let mut retry = batch;
        retry["approvalId"] = json!(id.to_string());
        dispatch("task_grant", retry, "batch-consume").expect("the owner-approved grant");
        assert!(recorded.lock().unwrap().is_empty());

        // One entry: the OMP-consumed grant permit reaches the real
        // coordinator, which executes the exact action once.
        dispatch("browser_consequential", first.clone(), "first-submit")
            .expect("the first planned entry executes without another owner question");
        assert_eq!(recorded.lock().unwrap().len(), 1);
        // Continuation: the second exact entry runs on the same decision.
        dispatch("browser_consequential", second, "second-submit")
            .expect("the second planned entry executes without another owner question");
        let actions = recorded.lock().unwrap().clone();
        assert_eq!(
            actions,
            [
                json!({"type": "submitForm", "selector": "#approve-form"}),
                json!({"type": "submitForm", "selector": "#send-form"}),
            ]
        );
        assert_eq!(requested(), 0, "no second owner question was asked");
        // A spent entry never runs again, under any request identity.
        for request in ["first-submit", "first-again"] {
            assert!(dispatch("browser_consequential", first.clone(), request).is_err());
        }
        assert_eq!(recorded.lock().unwrap().len(), 2);
    })
    .await
    .unwrap();
    projection
        .shutdown()
        .await
        .expect("the owned browser closes");
}
