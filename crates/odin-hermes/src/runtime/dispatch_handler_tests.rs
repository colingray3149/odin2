//! The real-handler governed-dispatch scenario, crate-internal: the
//! first dispatch mints exactly one durable request; the operator
//! approves it through the real kernel gate; the retry rides the REAL
//! `HostToolOperations::dispatch_tool` pipeline into the REAL registered
//! `email_send`/`calendar_propose` prepared handlers — with the composed
//! runtime's adapters rebound over the deterministic scripted
//! transports through `Arc::get_mut` on the sole-owner runtime (no
//! production seam, no new wiring) — so the provider dispatch SUCCEEDS
//! exactly once and the identical retry never duplicates it.
//!
//! The tests/credential_dispatch.rs integration file proves the same
//! laws against the production HTTPS composition (outcome honestly
//! uncertain); this module proves the happy path end to end.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::knowledge::ToolName;
use odin_domain::operation::Limits;
use odin_domain::{
    ApprovalId, CapabilityId, CommandId, Digest, EffectClass, LaneId, ProjectId, RunId, Scope,
    SeatId, SessionId, SliceId,
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

use super::model_set::{
    ModelCommandRoute, ModelLaunchDeclaration, ModelRouteError, ModelSetCommand, SeatSessionSurvey,
};
use super::{
    hermes_capability_bindings, AuthorityMovePlan, FleetDrainOutcome, FleetDrainPlanStep,
    FleetDrainResolution, FleetDrainResult, FleetDrainRoute, FleetRestoreOutcome, HermesLedgers,
    HermesRuntime, StandbyCandidate, WorkspaceConnectRoute, WorkspaceConnection,
    WorkspaceConnectionKind, RUNTIME_ISSUER,
};
use crate::account::{AccountSecretRef, CredentialLeases, FileCredentialLeases};
use crate::calendar::{CalendarAdapter, CalendarMutation, CalendarProposal, CalendarTransport};
use crate::config::{HermesSettings, LifeAccountSettings, LifeProviderSettings};
use crate::email::{EmailAdapter, EmailTransport};
use odin_domain::huginn::{
    CommandReceipt, EventSeq, LiveLaunchOption, LiveSessionId, LiveSessionState,
    LiveSessionSummary, SessionEpoch, TerminalSeq,
};

const ACCOUNT: &str = "sinmara";
const SECRET_VALUE: &str = "test-rendered-credential-material";
const KEY: &[u8] = b"dispatch-handler fixture signing key";
const SEAT: &str = "atlas";
const SLICE: &str = "slice.fixture";
const LANE: &str = "atlas-household";
const PROJECT: &str = "household";
const SESSION: &str = "00000000-0000-4000-8000-0000000000d1";
const RUN: &str = "run:live:00000000-0000-4000-8000-0000000000d0";
const WINDOW_START: &str = "2026-09-27T10:00:00Z";
const WINDOW_END: &str = "2026-09-27T11:00:00Z";

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

fn contract(name: &str, tool: &str, evidence: &str) -> CapabilityContract {
    CapabilityContract {
        id: capability(name),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(tool).unwrap(),
        description: format!("fixture contract for the {name} handler scenario"),
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

/// One contract exactly as the repository registry declares it, so the
/// dispatch follows the actual declared effect class and approval policy.
fn registry_contract(name: &str) -> CapabilityContract {
    let path = format!("registry/capabilities/{name}/capability.toml");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = std::fs::read_to_string(root.join(&path)).unwrap();
    let object = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Capability,
        name,
        &path,
        &source,
    )
    .unwrap();
    let odin_registry::ObjectConfig::Capability(declaration) = &object.config else {
        panic!("{name} is a capability");
    };
    CapabilityContract::try_from_registry(
        &object,
        &odin_registry::relational::AdmittedBinding {
            version: declaration.version,
            input_schema: declaration.input_schema.clone().unwrap(),
            output_schema: declaration.output_schema.clone().unwrap(),
            handler: declaration.handler.clone().unwrap(),
            evidence_extractor: declaration.evidence_extractor.clone().unwrap(),
        },
    )
    .unwrap()
}

/// The `workspace.connect` contract exactly as the registry declares it:
/// R2 (it opens a window), required idempotency, no retry,
/// coordinator-tagged, no approval, served by the
/// dotted hermes handler id and its evidence extractor.
fn workspace_contract() -> CapabilityContract {
    CapabilityContract {
        id: capability("workspace.connect"),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new("workspace_connect").unwrap(),
        description: "fixture contract for the workspace.connect handler scenario".to_owned(),
        handler: HandlerBinding::Builtin {
            name: "odin_hermes.workspace_connect".to_owned(),
        },
        input_schema_ref: "schemas/capability/workspace.connect.input.json".to_owned(),
        output_schema_ref: "schemas/capability/workspace.connect.output.json".to_owned(),
        effect_class: EffectClass::R2,
        seat_tags: BTreeSet::from(["coordinator".to_owned()]),
        timeout_seconds: NonZeroU32::new(15).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 0 },
        approval: odin_kernel::ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes.workspace_connect_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

fn desktop_contract() -> CapabilityContract {
    CapabilityContract {
        id: capability("desktop.input"),
        tool_name: ToolName::new("desktop_input").unwrap(),
        description: "fixture contract for the desktop.input handler scenario".to_owned(),
        handler: HandlerBinding::Builtin {
            name: "desktop_input".to_owned(),
        },
        input_schema_ref: "schemas/capability/desktop.input.input.json".to_owned(),
        output_schema_ref: "schemas/capability/desktop.input.output.json".to_owned(),
        timeout_seconds: NonZeroU32::new(30).unwrap(),
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes_desktop_input_evidence".to_owned(),
        },
        ..workspace_contract()
    }
}

/// The `fleet.drain` contract exactly as the registry declares it: R2,
/// required idempotency, operator approval, coordinator-tagged, 300s,
/// served by the dotted hermes handler id and its evidence extractor —
/// the first R2 capability whose approval the kernel consumes.
fn fleet_drain_contract() -> CapabilityContract {
    CapabilityContract {
        id: capability("fleet.drain"),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new("fleet_drain").unwrap(),
        description: "fixture contract for the fleet.drain handler scenario".to_owned(),
        handler: HandlerBinding::Builtin {
            name: "odin_hermes.fleet_drain".to_owned(),
        },
        input_schema_ref: "schemas/capability/fleet.drain.input.json".to_owned(),
        output_schema_ref: "schemas/capability/fleet.drain.output.json".to_owned(),
        effect_class: EffectClass::R2,
        seat_tags: BTreeSet::from(["coordinator".to_owned()]),
        timeout_seconds: NonZeroU32::new(300).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 0 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes.fleet_drain_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// The `fleet.restore` twin: R2, operator approval, 60s, restore handler
/// ids.
fn fleet_restore_contract() -> CapabilityContract {
    CapabilityContract {
        id: capability("fleet.restore"),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new("fleet_restore").unwrap(),
        description: "fixture contract for the fleet.restore handler scenario".to_owned(),
        handler: HandlerBinding::Builtin {
            name: "odin_hermes.fleet_restore".to_owned(),
        },
        input_schema_ref: "schemas/capability/fleet.restore.input.json".to_owned(),
        output_schema_ref: "schemas/capability/fleet.restore.output.json".to_owned(),
        effect_class: EffectClass::R2,
        seat_tags: BTreeSet::from(["coordinator".to_owned()]),
        timeout_seconds: NonZeroU32::new(60).unwrap(),
        idempotency: IdempotencyPolicy::Required,
        retry: RetryPolicy { max_attempts: 0 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes.fleet_restore_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

struct ScriptedWorkspace {
    outcome: Result<WorkspaceConnection, String>,
}

impl WorkspaceConnectRoute for ScriptedWorkspace {
    fn connect(&self, _host: Option<&str>, _target: &str) -> Result<WorkspaceConnection, String> {
        self.outcome.clone()
    }

    fn input(&self, device: &str, text: &str, enter: bool) -> Result<(), String> {
        self.outcome.clone().map(|_| ()).map_err(|reason| {
            format!("{reason} (asked to type {text:?} on {device}, enter={enter})")
        })
    }
}

/// Records cluster touches separately from requests to detect authority-host actuation.
struct ScriptedFleetDrain {
    resolution: Result<FleetDrainResolution, String>,
    drain_outcome: Result<FleetDrainOutcome, String>,
    restore_outcome: Result<FleetRestoreOutcome, String>,
    asks: parking_lot::Mutex<Vec<String>>,
    touches: parking_lot::Mutex<Vec<String>>,
}

impl ScriptedFleetDrain {
    /// Reports one pod removed and one remaining on a schedulable worker.
    fn worker() -> Arc<Self> {
        Arc::new(Self {
            resolution: Ok(FleetDrainResolution {
                host: "mini".to_owned(),
                nodes: vec!["mini-node".to_owned()],
                authority_node: None,
                kube_ready: true,
            }),
            drain_outcome: Ok(FleetDrainOutcome {
                host: "mini".to_owned(),
                node: "mini-node".to_owned(),
                result: FleetDrainResult::Drained,
                cordoned: true,
                evicted: vec!["batch-0".to_owned()],
                remained: vec!["stuck-pod".to_owned()],
                authority_holds: false,
                plan: None,
                workloads: Vec::new(),
            }),
            restore_outcome: Ok(FleetRestoreOutcome {
                host: "mini".to_owned(),
                node: "mini-node".to_owned(),
                uncordoned: true,
                schedulable: true,
                resumed: Vec::new(),
            }),
            asks: parking_lot::Mutex::new(Vec::new()),
            touches: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// The authority host: its resolution names the authoritative node,
    /// and its drain answer is the seven-step move plan with one declared
    /// standby candidate — the cluster is never touched.
    fn authority() -> Arc<Self> {
        Arc::new(Self {
            resolution: Ok(FleetDrainResolution {
                host: "mini".to_owned(),
                nodes: vec!["odin-core".to_owned()],
                authority_node: Some("odin-core".to_owned()),
                kube_ready: true,
            }),
            drain_outcome: Ok(FleetDrainOutcome {
                host: "mini".to_owned(),
                node: "odin-core".to_owned(),
                result: FleetDrainResult::AuthorityMovePlan,
                cordoned: false,
                evicted: Vec::new(),
                remained: Vec::new(),
                authority_holds: true,
                plan: Some(AuthorityMovePlan {
                    steps: (1..=7)
                        .map(|step| FleetDrainPlanStep {
                            step,
                            description: format!("step {step}"),
                            command: Some(format!("odind step-{step}")),
                            facts: None,
                        })
                        .collect(),
                    candidates: vec![StandbyCandidate {
                        node: "spare-node".to_owned(),
                        host: "spare".to_owned(),
                    }],
                    note: "the standby is the operator's choice".to_owned(),
                }),
                workloads: Vec::new(),
            }),
            restore_outcome: Ok(FleetRestoreOutcome {
                host: "mini".to_owned(),
                node: "odin-core".to_owned(),
                uncordoned: true,
                schedulable: true,
                resumed: Vec::new(),
            }),
            asks: parking_lot::Mutex::new(Vec::new()),
            touches: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// The offline host: the read-only resolution refuses typed before
    /// anything is journaled.
    fn offline() -> Arc<Self> {
        Arc::new(Self {
            resolution: Err("host mini is offline (last seen 2026-09-28T09:00:00Z)".to_owned()),
            ..Self::unpacked(Self::worker())
        })
    }

    fn unpacked(route: Arc<Self>) -> Self {
        Self {
            resolution: route.resolution.clone(),
            drain_outcome: route.drain_outcome.clone(),
            restore_outcome: route.restore_outcome.clone(),
            asks: parking_lot::Mutex::new(Vec::new()),
            touches: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

impl FleetDrainRoute for ScriptedFleetDrain {
    fn resolve(&self, _host: &str) -> Result<FleetDrainResolution, String> {
        self.resolution.clone()
    }

    fn drain(&self, host: &str) -> Result<FleetDrainOutcome, String> {
        self.asks.lock().push(format!("drain:{host}"));
        let authority = matches!(
            &self.resolution,
            Ok(resolution) if resolution.authority_node.is_some()
        );
        if !authority {
            self.touches.lock().push(format!("drain:{host}"));
        }
        self.drain_outcome.clone()
    }

    fn restore(&self, host: &str) -> Result<FleetRestoreOutcome, String> {
        self.asks.lock().push(format!("restore:{host}"));
        self.touches.lock().push(format!("restore:{host}"));
        self.restore_outcome.clone()
    }
}
/// Scripted send/draft provider with lease-scope observation and a private
/// provider-ordered draft mailbox. Management uses the production JMAP
/// transport against the local fixture mailbox.
#[derive(Default)]
struct ScriptedSend {
    lease_scopes: parking_lot::Mutex<Vec<(String, String)>>,
    mailbox: Arc<LocalMailbox>,
    drafts: parking_lot::Mutex<Vec<(String, crate::email::EmailDraft)>>,
    /// Runs once as the provider commits a draft, before its reply returns.
    after_save: ProviderHook,
}

/// A one-shot fixture action taken at the instant a provider call commits.
type ProviderHook = parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>;

fn run_provider_hook(hook: &ProviderHook) {
    let pending = hook.lock().take();
    if let Some(action) = pending {
        action();
    }
}

/// A local JMAP mailbox over the shared email fixture messages: it
/// applies the production transport's `Email/set` keyword JSON Pointer
/// patches and mailbox replacements to fixture state. Unknown ids answer
/// `notUpdated`; no message is ever destroyed.
struct LocalMailbox {
    messages: parking_lot::Mutex<BTreeMap<String, Value>>,
    sets: parking_lot::Mutex<usize>,
    /// Applies the update, then loses the reply: honestly unknowable.
    lose_reply: parking_lot::Mutex<bool>,
}

impl Default for LocalMailbox {
    fn default() -> Self {
        let fixtures =
            crate::fixtures::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
                .expect("life fixtures load");
        let messages = fixtures
            .email
            .messages
            .iter()
            .enumerate()
            .map(|(index, message)| {
                let keywords = if index == 0 {
                    json!({ "$seen": true })
                } else {
                    json!({})
                };
                let state = json!({ "mailboxIds": { "inbox": true }, "keywords": keywords });
                (message.id.clone(), state)
            })
            .collect();
        Self {
            messages: parking_lot::Mutex::new(messages),
            sets: parking_lot::Mutex::new(0),
            lose_reply: parking_lot::Mutex::new(false),
        }
    }
}

impl crate::jmap::JmapExchange for LocalMailbox {
    fn readiness(&self) -> Result<(), crate::account::TransportFault> {
        Ok(())
    }

    fn exchange(
        &self,
        request: &crate::jmap::JmapRequest,
        _lease: &crate::account::ScopedCredentialLease,
    ) -> Result<crate::jmap::JmapResponse, crate::account::TransportFault> {
        let [call] = request.method_calls.as_slice() else {
            panic!("management is one Email/set call");
        };
        assert_eq!(call.name, "Email/set");
        assert!(call.arguments.get("destroy").is_none(), "nothing destroys");
        *self.sets.lock() += 1;
        let mut messages = self.messages.lock();
        let mut updated = serde_json::Map::new();
        let mut not_updated = serde_json::Map::new();
        for (id, patch) in call.arguments["update"].as_object().expect("update map") {
            let Some(message) = messages.get_mut(id) else {
                not_updated.insert(id.clone(), json!({ "type": "notFound" }));
                continue;
            };
            for (path, value) in patch.as_object().expect("patch object") {
                let Some(token) = path.strip_prefix("keywords/") else {
                    message[path.as_str()] = value.clone();
                    continue;
                };
                let keyword = token.replace("~1", "/").replace("~0", "~");
                let keywords = message["keywords"].as_object_mut().expect("keywords");
                if value.is_null() {
                    keywords.remove(&keyword);
                } else {
                    keywords.insert(keyword, value.clone());
                }
            }
            updated.insert(id.clone(), Value::Null);
        }
        if *self.lose_reply.lock() {
            return Err(crate::account::TransportFault::Timeout);
        }
        Ok(crate::jmap::JmapResponse {
            responses: vec![crate::jmap::JmapResponseCall {
                name: "Email/set".to_owned(),
                arguments: json!({ "updated": updated, "notUpdated": not_updated }),
                call_id: call.call_id.clone(),
            }],
        })
    }
}

impl EmailTransport for ScriptedSend {
    fn readiness(&self, _account: &str) -> Result<(), crate::account::TransportFault> {
        Ok(())
    }

    fn search(
        &self,
        _lease: &crate::account::ScopedCredentialLease,
        _query: &crate::email::EmailSearchQuery,
        _now: OffsetDateTime,
    ) -> Result<Vec<crate::email::EmailSummary>, crate::account::TransportFault> {
        panic!("the handler scenario never searches")
    }

    fn read(
        &self,
        _lease: &crate::account::ScopedCredentialLease,
        _email_id: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<crate::email::EmailMessage>, crate::account::TransportFault> {
        panic!("the handler scenario never reads")
    }

    fn save_draft(
        &self,
        _lease: &crate::account::ScopedCredentialLease,
        draft: &crate::email::EmailDraft,
        _now: OffsetDateTime,
    ) -> Result<crate::email::EmailDraftReceipt, crate::account::TransportFault> {
        let mut drafts = self.drafts.lock();
        let draft_id = match draft.subject.as_str() {
            "Approved subject" => "draft-1".to_owned(),
            "Changed subject" => "draft-changed".to_owned(),
            _ => format!("mailbox-draft-{}", drafts.len() + 1),
        };
        drafts.push((draft_id.clone(), draft.clone()));
        drop(drafts);
        run_provider_hook(&self.after_save);
        Ok(crate::email::EmailDraftReceipt {
            draft_id,
            binding: crate::email::DraftContentBinding::Gmail {
                raw: serde_json::to_string(draft).unwrap(),
            },
        })
    }

    fn manage(
        &self,
        lease: &crate::account::ScopedCredentialLease,
        management: &crate::email::EmailManagement,
        now: OffsetDateTime,
    ) -> Result<crate::email::EmailManagementReceipt, crate::account::BatchFault> {
        self.lease_scopes.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        crate::email::JmapEmailTransport::new(crate::email::JmapMailConfig {
            account_id: "account-1".to_owned(),
            identity_id: "identity-1".to_owned(),
            from_address: "sinmara@example.invalid".to_owned(),
            drafts_mailbox_id: "drafts".to_owned(),
            archive_mailbox_id: "archive".to_owned(),
            trash_mailbox_id: "trash".to_owned(),
            exchange: self.mailbox.clone(),
        })?
        .manage(lease, management, now)
    }

    fn send_draft(
        &self,
        lease: &crate::account::ScopedCredentialLease,
        receipt: &crate::email::EmailDraftReceipt,
        _now: OffsetDateTime,
    ) -> Result<String, crate::account::TransportFault> {
        self.lease_scopes.lock().push((
            lease.capability().as_str().to_owned(),
            lease.account().to_owned(),
        ));
        assert_eq!(
            receipt.draft_id, "draft-1",
            "the intent's draft reference dispatches"
        );
        Ok("submission-1".to_owned())
    }
}

/// A deterministic scripted calendar provider: only the booking call
/// runs, records the proposal it was handed, and returns a fixed id. A
/// batch books member by member into the calendar's own state; the
/// second member applies but its reply is lost.
#[derive(Default)]
struct ScriptedBook {
    proposals: parking_lot::Mutex<Vec<CalendarProposal>>,
    booked: parking_lot::Mutex<Vec<String>>,
    /// Runs once as the provider commits a single booking, before its reply.
    after_apply: ProviderHook,
}

impl CalendarTransport for ScriptedBook {
    fn readiness(&self, _account: &str) -> Result<(), crate::account::TransportFault> {
        Ok(())
    }

    fn read_window(
        &self,
        _lease: &crate::account::ScopedCredentialLease,
        _window: &crate::calendar::CalendarWindow,
        _now: OffsetDateTime,
    ) -> Result<Vec<crate::calendar::CalendarEventSummary>, crate::account::TransportFault> {
        panic!("the handler scenario never reads the window")
    }

    fn apply(
        &self,
        _lease: &crate::account::ScopedCredentialLease,
        proposal: &CalendarProposal,
        _now: OffsetDateTime,
    ) -> Result<crate::calendar::CalendarMutationReceipt, crate::account::BatchFault> {
        self.proposals.lock().push(proposal.clone());
        let CalendarMutation::BatchCreate { drafts } = &proposal.mutation else {
            self.booked.lock().push("event-1".to_owned());
            run_provider_hook(&self.after_apply);
            return Ok(crate::calendar::CalendarMutationReceipt {
                event_ids: vec!["event-1".to_owned()],
            });
        };
        let mut known = Vec::new();
        for index in 1..=drafts.len() {
            let id = format!("event-{index}");
            self.booked.lock().push(id.clone());
            if index == 2 {
                return Err(crate::account::BatchFault::after(
                    known,
                    crate::account::TransportFault::Protocol("the booking reply was lost"),
                ));
            }
            known.push(id);
        }
        Ok(crate::calendar::CalendarMutationReceipt { event_ids: known })
    }
}

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

/// Uses production dispatch with scripted email/calendar transports sharing the same
/// ledger and credentials; adapters are replaced before the runtime `Arc` is shared.
struct Stack {
    _root: tempfile::TempDir,
    operations: HostToolOperations,
    ledger: Arc<Mutex<Ledger>>,
    binding: SessionOperationBinding,
    session: SessionId,
    send_transport: Arc<ScriptedSend>,
    book_transport: Arc<ScriptedBook>,
    draft_digest: String,
    changed_digest: String,
    runtime: Arc<HermesRuntime>,
    adapter: Arc<parking_lot::Mutex<Ledger>>,
    vault_root: Option<PathBuf>,
    /// The file-backed purchase ledger path, when this stack composes a
    /// purchase backend: the durable store the REAL purchase handler
    /// records its intent and terminal outcome against.
    purchase_ledger_path: Option<PathBuf>,
}

/// Optional life-receipt composition: a real private vault under the fixture
/// root, and `calendar.propose` decided by its declaration as in the registry.
#[derive(Clone, Copy, Default)]
struct Life {
    vault: bool,
    declare_calendar: bool,
}

const OWNER: &str = "100000000000000001";
const CHANNEL: &str = "1000000000000000002";

/// Supplies ordered message identities to the real egress and delivery tracking.
#[derive(Default)]
struct ScriptedDiscord(parking_lot::Mutex<u64>);

#[async_trait::async_trait]
impl crate::discord::DiscordTransport for ScriptedDiscord {
    async fn send_message(
        &self,
        channel_id: &str,
        _content: &str,
    ) -> Result<crate::discord::DiscordMessageRef, crate::discord::DiscordSendError> {
        let mut next = self.0.lock();
        *next += 1;
        Ok(crate::discord::DiscordMessageRef {
            message_id: (1_000_000_000_000_000_000_u64 + (*next << 22)).to_string(),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn edit_message(
        &self,
        channel_id: &str,
        message_id: &str,
        _content: &str,
    ) -> Result<crate::discord::DiscordMessageRef, crate::discord::DiscordSendError> {
        Ok(crate::discord::DiscordMessageRef {
            message_id: message_id.to_owned(),
            channel_id: channel_id.to_owned(),
        })
    }

    async fn delete_message(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), crate::discord::DiscordSendError> {
        Ok(())
    }

    async fn trigger_typing(&self, _: &str) -> Result<(), crate::discord::DiscordSendError> {
        Ok(())
    }
}

impl Stack {
    fn open() -> Self {
        Self::assemble(None, None, None)
    }

    /// The stack whose runtime owns the paired owner conversation: owner
    /// questions are decided only on their complete delivered preview.
    fn open_with_owner() -> Self {
        Self::assemble_with(None, None, None, true)
    }

    /// Delivers the complete question for `approval_id` to the paired owner
    /// and settles the owner's reply that follows it.
    fn owner_decides(&self, approval_id: &ApprovalId, revision: i64) -> i64 {
        let delivered = self
            .runtime
            .deliver_approval_question(&self.adapter, approval_id, CHANNEL, OWNER, now(), None)
            .expect("the complete exact question is delivered");
        let reply = delivered.sent_message_id.parse::<u64>().unwrap() + (1 << 22);
        let message = super::AuthenticatedOwnerMessage {
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
            crate::natural::OwnerDecision::AllowOnce,
            now(),
        ) {
            Ok(DecisionOutcome::Approved(approval)) => approval.revision,
            other => panic!("the owner's reply must approve, got {other:?}"),
        }
    }

    /// `None` admits the contract without a route to exercise unavailable dispatch.
    fn open_with_workspace(route: Option<Arc<ScriptedWorkspace>>) -> Self {
        Self::assemble(None, Some(route), None)
    }

    fn open_with_model(model: Option<Arc<ScriptedModel>>) -> Self {
        Self::assemble(model, None, None)
    }
    /// `Some(None)` admits both contracts without a route to exercise unavailable dispatch.
    fn open_with_fleet(route: Option<Option<Arc<ScriptedFleetDrain>>>) -> Self {
        Self::assemble(None, None, route)
    }

    fn assemble(
        model: Option<Arc<ScriptedModel>>,
        workspace: Option<Option<Arc<ScriptedWorkspace>>>,
        fleet: Option<Option<Arc<ScriptedFleetDrain>>>,
    ) -> Self {
        Self::assemble_with(model, workspace, fleet, false)
    }

    fn open_with_life(life: Life) -> Self {
        Self::build(None, None, None, false, life, None)
    }

    /// The purchase stack: the registry-declared `purchase.submit`
    /// capability admitted beside a descriptor-admitted backend double,
    /// over the file-backed purchase ledger, so the REAL kernel-dispatched
    /// purchase handler runs end to end against a deterministic
    /// canonical-frame provider.
    fn open_with_purchase(
        contract: crate::purchase::PurchaseAdapterContract,
        exchange: Arc<ScriptedCheckoutBackend>,
    ) -> Self {
        Self::build(
            None,
            None,
            None,
            false,
            Life::default(),
            Some((contract, exchange)),
        )
    }

    fn assemble_with(
        model: Option<Arc<ScriptedModel>>,
        workspace: Option<Option<Arc<ScriptedWorkspace>>>,
        fleet: Option<Option<Arc<ScriptedFleetDrain>>>,
        owner: bool,
    ) -> Self {
        Self::build(model, workspace, fleet, owner, Life::default(), None)
    }

    fn build(
        model: Option<Arc<ScriptedModel>>,
        workspace: Option<Option<Arc<ScriptedWorkspace>>>,
        fleet: Option<Option<Arc<ScriptedFleetDrain>>>,
        owner: bool,
        life: Life,
        purchase: Option<(
            crate::purchase::PurchaseAdapterContract,
            Arc<ScriptedCheckoutBackend>,
        )>,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let vault_root = life.vault.then(|| {
            let path = root.path().join("vault");
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        });
        let vault = vault_root.as_ref().map(|path| crate::vault::VaultConfig {
            vault_root: path.clone(),
            source_id: "atlas.personal".to_owned(),
            silverbullet: None,
            general_namespaces: vec!["knowledge".to_owned()],
            generated_namespace: "generated".to_owned(),
            excluded_namespaces: Vec::new(),
            max_pages: 100,
            max_page_bytes: 64 * 1024,
            timeout_ms: 1_000,
        });
        let mut declaration_decided = BTreeSet::from([capability("task.grant")]);
        if life.declare_calendar {
            declaration_decided.insert(capability("calendar.propose"));
        }
        let secret_path = root.path().join("sinmara-email.secret");
        std::fs::write(&secret_path, SECRET_VALUE).unwrap();
        let ledger_path = root.path().join("dispatch-ledger.sqlite3");
        let ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
        // Production passes the SAME authoritative ledger and mutex to
        // kernel dispatch and purchase follow-through, not a shadow database.
        let purchase_ledger_path = purchase.as_ref().map(|_| ledger_path.clone());

        let mut contracts: BTreeMap<CapabilityId, CapabilityContract> = [
            contract(
                "email.send",
                "email_send",
                "odin_hermes_email_send_evidence",
            ),
            contract(
                "task.grant",
                "task_grant",
                "odin_hermes_task_grant_evidence",
            ),
            contract(
                "calendar.propose",
                "calendar_propose",
                "odin_hermes_calendar_propose_evidence",
            ),
        ]
        .into_iter()
        .map(|contract| (contract.id.clone(), contract))
        .collect();
        // Grant composition reads the declared batch policy, not the generic
        // contract defaults. email.send stays the fixture handler; only its
        // declared preview and batchability are copied.
        let declared_grant = registry_contract("task.grant");
        let grant = contracts.get_mut(&declared_grant.id).unwrap();
        grant.preview = declared_grant.preview;
        grant.batchable = declared_grant.batchable;
        grant.batch = declared_grant.batch;
        let declared_send = registry_contract("email.send");
        let send = contracts.get_mut(&declared_send.id).unwrap();
        send.preview = declared_send.preview;
        send.batchable = declared_send.batchable;
        let manage = registry_contract("email.manage");
        contracts.insert(manage.id.clone(), manage);
        let draft = registry_contract("email.draft");
        contracts.insert(draft.id.clone(), draft);
        if life.vault {
            // The declared R2 generated-write surface a receipt repair rides.
            let writer = registry_contract("vault.write_generated");
            contracts.insert(writer.id.clone(), writer);
        }
        for operation in ["open", "prompt", "read", "stop"] {
            let mut declaration = contract(
                &format!("claude.{operation}"),
                &format!("claude_{operation}"),
                &format!("odin_hermes_claude_{operation}_evidence"),
            );
            declaration.effect_class = if operation == "read" {
                EffectClass::R0
            } else {
                EffectClass::R2
            };
            declaration.approval = odin_kernel::ApprovalRequirement::None;
            declaration.retry.max_attempts = 0;
            contracts.insert(declaration.id.clone(), declaration);
        }
        if model.is_some() {
            let mut declaration = contract(
                "seat.model.set",
                "seat_model_set",
                "odin_hermes_seat_model_set_evidence",
            );
            declaration.effect_class = EffectClass::R2;
            declaration.retry.max_attempts = 0;
            contracts.insert(declaration.id.clone(), declaration);
        }
        if workspace.is_some() {
            for declaration in [workspace_contract(), desktop_contract()] {
                contracts.insert(declaration.id.clone(), declaration);
            }
        }
        if fleet.is_some() {
            for declaration in [fleet_drain_contract(), fleet_restore_contract()] {
                contracts.insert(declaration.id.clone(), declaration);
            }
        }
        if purchase.is_some() {
            // The declared purchase.submit capability exactly as the
            // registry declares it — R3, operator approval, required
            // idempotency, no retry — so the scenario drives the real
            // governed dispatch route the production daemon serves.
            let submit = registry_contract("purchase.submit");
            contracts.insert(submit.id.clone(), submit);
        }

        let accounts = vec![LifeAccountSettings {
            account: ACCOUNT.to_owned(),
            secret_handle: "cred:sinmara-email".to_owned(),
            secret_path: secret_path.clone(),
            provider: LifeProviderSettings::Jmap {
                session_url: "https://jmap.example.invalid/session".to_owned(),
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
        let discord = owner.then(|| {
            crate::config::DiscordSettings::new(
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
            HermesSettings::new(root.path().join("state"), discord, vault, None, accounts).unwrap();
        // The owner conversation's admitted ask and intake declarations are
        // Hermes surface contracts; the dispatch stack serves only the rest.
        let mut hermes_contracts = contracts.clone();
        let (bound_projects, ownership) = if owner {
            let mut ask = contract(
                "seat.ask.atlas",
                "seat_ask_atlas",
                "odin_hermes_seat_ask_evidence",
            );
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
                Some(super::ConversationOwnership {
                    seat: seat(),
                    project: project(),
                    ask_capability: capability("seat.ask.atlas"),
                }),
            )
        } else {
            (BTreeMap::new(), None)
        };

        let send_transport = Arc::new(ScriptedSend::default());
        let book_transport = Arc::new(ScriptedBook::default());
        let adapter_ledger = Arc::new(parking_lot::Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let leases: Arc<dyn CredentialLeases> =
            Arc::new(FileCredentialLeases::new(BTreeMap::from([(
                ACCOUNT.to_owned(),
                AccountSecretRef::new(
                    odin_domain::huginn::OpaqueCredentialHandle::new("cred:sinmara-email").unwrap(),
                    secret_path.clone(),
                )
                .unwrap(),
            )])));

        let mut runtime = HermesRuntime::open(
            settings,
            HermesLedgers {
                conversation: if purchase.is_some() {
                    Ledger::open(&ledger_path).unwrap()
                } else {
                    Ledger::open_in_memory().unwrap()
                },
                adapter: Arc::clone(&adapter_ledger),
                purchase: if purchase.is_some() {
                    Arc::clone(&ledger)
                } else {
                    Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()))
                },
            },
            &hermes_contracts,
            None,
            8_192,
            bound_projects,
            ownership,
        )
        .unwrap();
        // Sole-owner rebind: swap the composed JMAP adapters for the
        // scripted-transport twins over the same ledger and leases. The
        // tools composed below capture this runtime and their handlers
        // read these adapters — the REAL handler path, deterministic
        // provider.
        {
            let runtime = Arc::get_mut(&mut runtime).expect("sole owner before tool composition");
            let send_dyn: Arc<dyn EmailTransport> = send_transport.clone();
            let book_dyn: Arc<dyn CalendarTransport> = book_transport.clone();
            runtime.email = Some(EmailAdapter::new(
                Arc::clone(&adapter_ledger),
                send_dyn,
                Arc::clone(&leases),
                RUNTIME_ISSUER,
            ));
            runtime.calendar = Some(CalendarAdapter::new(
                Arc::clone(&adapter_ledger),
                book_dyn,
                leases,
                RUNTIME_ISSUER,
            ));
        }
        if let Some((contract, exchange)) = &purchase {
            runtime
                .bind_purchase_backend(
                    contract.clone(),
                    Arc::clone(exchange) as Arc<dyn crate::purchase::PurchaseFrameExchange>,
                )
                .expect("the fixture purchase backend binds before tool composition");
        }
        if owner {
            runtime
                .bind_notify_sink(Arc::new(crate::egress::DiscordEgressSink::new(Arc::new(
                    ScriptedDiscord::default(),
                ))))
                .unwrap();
        }
        let produce = |subject: &str, key: &str| {
            runtime
                .email
                .as_ref()
                .unwrap()
                .save_draft(
                    &crate::account::EffectIdentity {
                        idempotency_key: key.into(),
                        correlation_id: key.into(),
                    },
                    &crate::email::EmailDraft {
                        account: ACCOUNT.into(),
                        to: vec!["owner@example.invalid".into()],
                        subject: subject.into(),
                        body_text: "Exact approved message".into(),
                    },
                    now(),
                )
                .unwrap()
                .result["draftDigest"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let draft_digest = produce("Approved subject", "fixture-draft");
        let changed_digest = produce("Changed subject", "fixture-changed-draft");
        if let Some(Some(workspace)) = workspace {
            runtime.set_workspace_connect_route(workspace);
        }
        if let Some(route) = model {
            runtime.set_model_launch_declaration(model_launches());
            runtime.set_model_command_route(route);
        }
        if let Some(Some(fleet)) = fleet {
            runtime.set_fleet_drain_route(fleet);
        }
        let task_grants = Arc::new(odin_omp::host_tools::task_grants::TaskGrantStore::open(
            root.path().join("task-grants.json"),
        ));
        runtime.set_task_grants(Arc::clone(&task_grants));

        let registry = Arc::new({
            let mut registry = HostToolRegistry::new();
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
            denied_capabilities: BTreeSet::new(),
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
                entropy: b"dispatch handler fixture token",
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
        .expect("operation stack")
        .with_task_grants(task_grants);

        {
            let mut guard = ledger.lock().unwrap();
            create_lane(
                guard.connection(),
                &NewLane {
                    lane_id: lane(),
                    seat_id: seat(),
                    project_id: Some(project()),
                    template_id: "template:handler-fixture".to_owned(),
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
                    workflow_id: Some("live:handler-fixture".to_owned()),
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
                        id: odin_domain::TodoId::new("todo:handler-fixture").unwrap(),
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
            operations,
            ledger,
            binding,
            session,
            send_transport,
            book_transport,
            draft_digest,
            changed_digest,
            runtime,
            adapter: adapter_ledger,
            vault_root,
            purchase_ledger_path,
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

fn send_identity_key(draft_id: &str, draft_digest: &str) -> String {
    let material = format!("{ACCOUNT}\u{0}{draft_id}\u{0}{draft_digest}");
    let digest = odin_domain::Digest::hash(material.as_bytes());
    let mut key = String::from("email-send:");
    for byte in digest.as_bytes().iter().take(8) {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

#[test]
fn invalid_email_bindings_refuse_before_any_owner_question() {
    let stack = Stack::open();
    for arguments in [
        json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.changed_digest}),
        json!({"account": "other-account", "draft_id": "draft-1", "draft_digest": stack.draft_digest}),
        json!({"account": ACCOUNT, "draft_id": "missing", "draft_digest": stack.draft_digest}),
    ] {
        assert!(stack
            .dispatch("email_send", arguments.clone(), "invalid-direct")
            .is_err());
        assert!(stack
            .dispatch(
                "task_grant",
                json!({
                    "task": "Invalid content scope", "minutes": 10, "max_uses": 1,
                    "effects": [{"capability": "email.send", "arguments": arguments}],
                }),
                "invalid-batch"
            )
            .is_err());
        assert!(
            stack.approvals().is_empty(),
            "preflight must refuse before asking the owner"
        );
        assert!(stack.send_transport.lease_scopes.lock().is_empty());
    }
}

#[test]
fn task_grant_creation_cannot_manufacture_owner_consent() {
    let stack = Stack::open();
    let grant = stack.dispatch(
        "task_grant",
        json!({
            "task": "Send the planned update",
            "effects": [{"capability": "email.send", "arguments": {"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}}],
            "minutes": 10,
            "max_uses": 1,
        }),
        "req-unapproved-plan",
    );
    let send = stack.dispatch(
        "email_send",
        json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}),
        "req-unapproved-plan-send",
    );
    assert!(stack.send_transport.lease_scopes.lock().is_empty());
    assert!(
        matches!(send, Err(HostToolOperationError::ApprovalRequired { .. })),
        "without an owner decision no grant may dispatch an effect: grant={grant:?}, send={send:?}"
    );
    assert!(
        matches!(grant, Err(HostToolOperationError::ApprovalRequired { .. })),
        "the consequential batch must await its real owner decision: {grant:?}"
    );
}

#[test]
fn task_grant_refuses_purchase_and_ordinary_work_without_an_owner_question() {
    let stack = Stack::open();
    for capability in ["purchase.submit", "calendar.propose", "task.grant"] {
        let result = stack.dispatch(
            "task_grant",
            json!({
                "task": "No blanket permission", "minutes": 10, "max_uses": 1,
                "effects": [{"capability": capability, "arguments": {}}]
            }),
            capability,
        );
        assert!(result.is_err());
        assert!(stack.approvals().is_empty());
        assert!(stack.send_transport.lease_scopes.lock().is_empty());
    }
}

/// Requests one exact batch through the real `task_grant` dispatch, settles
/// the owner's reply to its complete delivered question, consumes it
/// through the real retry, and reopens the durable grant store.
fn owner_batch(stack: &mut Stack, arguments: Value) {
    let (id, revision) = match stack
        .dispatch("task_grant", arguments.clone(), "batch-request")
        .unwrap_err()
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected batch owner request: {other:?}"),
    };
    assert!(stack.send_transport.lease_scopes.lock().is_empty());
    stack.owner_decides(&id, revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(id.to_string());
    stack
        .dispatch("task_grant", retry, "batch-consume")
        .expect("real owner-approved grant");
    stack.operations = stack.operations.clone().with_task_grants(Arc::new(
        odin_omp::host_tools::task_grants::TaskGrantStore::open(
            stack._root.path().join("task-grants.json"),
        ),
    ));
}

/// A refusal that provably never reached the provider (the plan gate is
/// Draft) must not spend the batch's only planned entry: once the plan is
/// accepted again a fresh request continues on the same owner decision,
/// without a second question, exactly once.
#[test]
fn known_no_effect_refusal_keeps_the_planned_entry_for_a_fresh_request() -> Result<(), &'static str>
{
    let mut stack = Stack::open_with_owner();
    let send =
        json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest});
    owner_batch(
        &mut stack,
        json!({
            "task": "Send the exact planned update", "minutes": 10, "max_uses": 1,
            "effects": [{"capability": "email.send", "arguments": send.clone()}]
        }),
    );
    let draft_revision = {
        let mut guard = stack
            .ledger
            .lock()
            .map_err(|_| "fixture authority ledger is poisoned")?;
        let current = guard.plan(&run()).unwrap().expect("fixture plan").revision;
        guard
            .replace_plan(
                &run(),
                "A changed plan awaiting acceptance",
                &[TodoSpec {
                    id: odin_domain::TodoId::new("todo:changed-plan").unwrap(),
                    title: "A changed plan awaiting acceptance".to_owned(),
                    status: TodoStatus::Pending,
                }],
                current,
                now(),
            )
            .unwrap()
            .revision
    };
    assert!(stack
        .dispatch("email_send", send.clone(), "draft-plan-send")
        .is_err());
    assert!(stack.send_transport.lease_scopes.lock().is_empty());
    stack
        .ledger
        .lock()
        .map_err(|_| "fixture authority ledger is poisoned")?
        .accept_plan(&run(), draft_revision, "operator:fixture", now())
        .unwrap();
    // A continuation that already covered this command before the refusal
    // must not consume its old approval after the entry becomes available.
    let stale = stack
        .approvals()
        .into_iter()
        .find(|approval| approval.scope.capability_id.as_str() == "email.send")
        .expect("the refused command's derived approval");
    let correlation = correlation_for(&stack.session, "draft-plan-send").unwrap();
    let stale_command = CommandId::new(format!("odin.omp.host_tool:{correlation}")).unwrap();
    let stale_use = {
        let mut ledger = stack
            .ledger
            .lock()
            .map_err(|_| "fixture authority ledger is poisoned")?;
        ApprovalGate::new(&mut ledger)
            .authorize_command(
                EffectClass::R3,
                odin_kernel::ApprovalCommand {
                    command_id: &stale_command,
                    approval_id: Some(&stale.approval_id),
                    scope: &stale.scope,
                    expected_revision: Some(stale.revision),
                    now: now(),
                },
            )
            .expect("the real gate checks the old approval")
    };
    assert!(
        matches!(stale_use, odin_kernel::ConsumeOutcome::Redirect(_)),
        "a released entry left a consumable old approval: {stale_use:?}"
    );
    assert!(
        stack
            .dispatch("email_send", send.clone(), "draft-plan-send")
            .is_err(),
        "the cancelled command cannot change its journaled approval identity"
    );
    stack
        .dispatch("email_send", send.clone(), "fresh-send")
        .expect("the unspent planned entry continues without a second owner question");
    assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
    assert!(
        stack
            .approvals()
            .iter()
            .all(|approval| approval.status != odin_domain::ApprovalStatus::Requested),
        "no second owner question"
    );
    // Same-command retries and a further request never spend it again.
    for request in ["fresh-send", "draft-plan-send", "extra-send"] {
        assert!(stack.dispatch("email_send", send.clone(), request).is_err());
    }
    assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
    Ok(())
}

#[test]
fn owner_decided_batch_continues_through_real_grant_and_delegated_dispatch() {
    for delegated in [false, true] {
        let mut stack = Stack::open_with_owner();
        let arguments = json!({
            "task": "Send the exact planned update", "minutes": 10, "max_uses": 1,
            "effects": [{"capability": "email.send", "arguments": {"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}}]
        });
        owner_batch(&mut stack, arguments);
        if delegated {
            let parent_session = stack.session.clone();
            let parent_binding = stack.binding.clone();
            stack.session = SessionId::new("00000000-0000-4000-8000-0000000000d2").unwrap();
            let mut key = KEY.to_vec();
            key.truncate(32);
            let issued = (odin_omp::host_tools::operations::wall_clock())();
            let token = TokenIssuer::new(key)
                .unwrap()
                .mint(MintRequest {
                    seat: seat(),
                    slice: SliceId::new(SLICE).unwrap(),
                    lane: lane(),
                    session: stack.session.clone(),
                    seat_revision: parent_binding.policy.seat_revision,
                    slice_revision: parent_binding.policy.slice_revision,
                    capability_policy_digest: parent_binding.policy.capability_policy_digest,
                    context_policy_digest: parent_binding.context_policy_digest,
                    issued_at_ms: issued,
                    expires_at_ms: issued + 3_600_000,
                    entropy: b"batch delegated child",
                })
                .unwrap();
            std::fs::write(
                stack
                    ._root
                    .path()
                    .join("authority-tokens")
                    .join(format!("{}.json", stack.session)),
                serde_json::to_vec(&token).unwrap(),
            )
            .unwrap();
            stack.binding.capsule_id = session_capsule_id(&stack.session).unwrap();
            stack.binding.parent = Some(Arc::new(
                odin_omp::host_tools::delegation::ParentSessionLink {
                    session: parent_session,
                    binding: parent_binding,
                    run: run(),
                    depth: 0,
                },
            ));
        }
        let changed = stack.dispatch("email_send", json!({"account": ACCOUNT, "draft_id": "draft-changed", "draft_digest": stack.changed_digest}), "changed-send");
        assert!(
            matches!(
                changed,
                Err(HostToolOperationError::ApprovalRequired { .. })
            ),
            "{changed:?}"
        );
        assert!(stack.send_transport.lease_scopes.lock().is_empty());
        stack.dispatch("email_send", json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}), "planned-send")
            .expect("the exact batch continues without a second owner decision");
        assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
        assert!(stack.dispatch("email_send", json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}), "planned-send").is_err());
        assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
        let exhausted = stack.dispatch(
            "email_send",
            json!({"account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest}),
            "extra-send",
        );
        assert!(
            matches!(
                exhausted,
                Err(HostToolOperationError::ApprovalRequired { .. })
            ),
            "{exhausted:?}"
        );
        assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
    }
}

/// The exact happy path through the REAL registered prepared handler:
/// mint -> approve -> consumed retry invokes the handler, the scripted
/// provider is called exactly once, the settle receipt is the handler's
/// real result, and the identical retry routes to the typed redirect
/// with no duplicate dispatch.
#[test]
fn email_send_happy_path_invokes_the_real_handler_and_dispatches_once() {
    let stack = Stack::open_with_owner();

    // First dispatch: mint exactly one durable request.
    let (approval_id, requested_revision) = match stack
        .dispatch(
            "email_send",
            json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest }),
            "req-handler-1",
        )
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

    // The owner decides the complete question delivered to the conversation.
    let approved_revision = stack.owner_decides(&approval_id, requested_revision);

    // The approved retry rides the real pipeline into the real
    // `email_send` handler: the provider dispatch SUCCEEDS, exactly once.
    let receipt = stack
        .dispatch(
            "email_send",
            json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest, "approvalId": approval_id.to_string() }),
            "req-handler-2",
        )
        .expect("the consumed retry must settle through the real handler");
    assert_eq!(receipt["result"]["sentId"], json!("submission-1"));
    assert_eq!(receipt["replayed"], json!(false));
    assert_eq!(
        stack.send_transport.lease_scopes.lock().len(),
        1,
        "exactly one provider dispatch"
    );
    assert_eq!(
        stack.send_transport.lease_scopes.lock()[0],
        ("email.send".to_owned(), ACCOUNT.to_owned()),
        "the dispatch rides the scoped lease for exactly this capability and account"
    );

    // One consumption, naming the journaled dispatch command.
    {
        let approval = stack.approval(&approval_id);
        assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
        assert_eq!(approval.revision, approved_revision + 1);
        let correlation = correlation_for(&stack.session, "req-handler-2").unwrap();
        let host_command = CommandId::new(format!("odin.omp.host_tool:{correlation}")).unwrap();
        assert_eq!(
            approval.consumed_by_command_id.as_ref(),
            Some(&host_command)
        );
        assert_eq!(stack.approvals().len(), 1);
    }

    // The durable intent the handler recorded completed terminally.
    let intent_id = CommandId::new(format!(
        "command:{}",
        send_identity_key("draft-1", &stack.draft_digest)
    ))
    .unwrap();
    let intent = stack
        .ledger
        .lock()
        .unwrap()
        .command(&intent_id)
        .unwrap()
        .expect("the handler recorded the intent");
    assert!(intent.accepted_at.is_some());
    assert_eq!(
        intent
            .terminal_result
            .as_ref()
            .and_then(|result| result["sentId"].as_str()),
        Some("submission-1"),
        "the durable intent completed with the provider's real receipt"
    );

    // The identical retry never repeats consumption or provider dispatch.
    stack
        .dispatch(
            "email_send",
            json!({ "account": ACCOUNT, "draft_id": "draft-1", "draft_digest": stack.draft_digest, "approvalId": approval_id.to_string() }),
            "req-handler-2",
        )
        .expect_err("a consumed approval must never authorize twice");
    assert_eq!(
        stack.send_transport.lease_scopes.lock().len(),
        1,
        "the replay must never re-dispatch"
    );
    assert_eq!(stack.approval(&approval_id).revision, approved_revision + 1);
    assert_eq!(stack.approvals().len(), 1);
}

/// The calendar twin of the happy path: the real `calendar_propose`
/// handler records the full approved proposal (location included) and
/// the scripted provider books exactly once.
#[test]
fn calendar_propose_happy_path_books_the_full_proposal_once() {
    let stack = Stack::open();
    let proposal = json!({
        "account": ACCOUNT,
        "type": "create",
        "title": "Standup",
        "start": WINDOW_START,
        "end": WINDOW_END,
        "location": "Longhouse",
    });

    let (approval_id, requested_revision) = match stack
        .dispatch("calendar_propose", proposal.clone(), "req-book-1")
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

    let mut retry = proposal;
    retry["approvalId"] = json!(approval_id.to_string());
    let receipt = stack
        .dispatch("calendar_propose", retry, "req-book-2")
        .expect("the consumed retry must settle through the real handler");
    assert_eq!(receipt["result"]["eventIds"], json!(["event-1"]));
    assert_eq!(receipt["replayed"], json!(false));
    assert_eq!(
        stack.book_transport.proposals.lock().len(),
        1,
        "exactly one booking"
    );
    let proposals = stack.book_transport.proposals.lock();
    match &proposals[0].mutation {
        CalendarMutation::Create(draft) => assert_eq!(
            draft.location.as_deref(),
            Some("Longhouse"),
            "the booked proposal is the full approved proposal, location included"
        ),
        mutation => panic!("expected create mutation, got {mutation:?}"),
    }
    drop(proposals);
    assert_eq!(
        stack.approval(&approval_id).revision,
        approved_revision + 1,
        "exactly one consumption"
    );

    // The identical retry never re-books.
    let mut retry_again = json!({
        "account": ACCOUNT,
        "type": "create",
        "title": "Standup",
        "start": WINDOW_START,
        "end": WINDOW_END,
        "location": "Longhouse",
    });
    retry_again["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("calendar_propose", retry_again, "req-book-2")
        .expect_err("a consumed approval must never authorize twice");
    assert_eq!(
        stack.book_transport.proposals.lock().len(),
        1,
        "the replay must never re-book"
    );
}

/// The real `email_draft` handler saves one mailbox draft per fresh owner
/// request, bound to its complete intent: a fresh request to another
/// recipient never conflicts, a fresh identical request is never
/// suppressed by an earlier draft, and the exact retry never saves twice.
#[test]
fn email_draft_saves_each_fresh_request_once_with_its_complete_intent() {
    let stack = Stack::open();
    let fixture_drafts = stack.send_transport.drafts.lock().len();
    let (to_a, to_b) = ("a@example.invalid", "b@example.invalid");
    let request = |to: &str| json!({ "account": ACCOUNT, "to": [to], "subject": "Lunch", "body_text": "Noon at the longhouse?" });

    let first = stack
        .dispatch("email_draft", request(to_a), "draft-a")
        .expect("the first request saves its draft");
    let other = stack
        .dispatch("email_draft", request(to_b), "draft-b")
        .expect("a fresh request to another recipient saves its own draft");
    let _ = stack.dispatch("email_draft", request(to_a), "draft-a");
    let again = stack
        .dispatch("email_draft", request(to_a), "draft-a-again")
        .expect("a fresh identical request saves another draft");

    // The private mailbox holds exactly one draft per fresh request, each
    // with the complete requested recipients and content.
    let saved = stack.send_transport.drafts.lock()[fixture_drafts..].to_vec();
    let recipients: Vec<Vec<String>> = saved.iter().map(|(_, draft)| draft.to.clone()).collect();
    assert_eq!(
        recipients,
        [
            vec![to_a.to_owned()],
            vec![to_b.to_owned()],
            vec![to_a.to_owned()]
        ]
    );
    for (_, draft) in &saved {
        assert_eq!(draft.account, ACCOUNT);
        assert_eq!(draft.subject, "Lunch");
        assert_eq!(draft.body_text, "Noon at the longhouse?");
    }

    // Each receipt names its own completed durable command and provider
    // draft, and email.send's frozen-content lookup resolves exactly the
    // saved recipients from it.
    let email = stack.runtime.email.as_ref().unwrap();
    let mut commands = BTreeSet::new();
    for (receipt, (draft_id, mailbox)) in [&first, &other, &again].into_iter().zip(&saved) {
        assert_eq!(receipt["replayed"], json!(false));
        assert_eq!(receipt["result"]["draftId"], json!(draft_id));
        let digest = receipt["result"]["draftDigest"].as_str().unwrap();
        let frozen = email
            .approved_draft(ACCOUNT, draft_id, digest)
            .expect("the receipt binds the saved draft");
        assert_eq!(frozen.to, mailbox.to);
        let command_id = receipt["command_id"].as_str().unwrap();
        let command = stack
            .adapter
            .lock()
            .command(&CommandId::new(command_id).unwrap())
            .unwrap()
            .expect("the durable draft command");
        assert!(matches!(
            command.terminal_status,
            Some(odin_ledger::command::CommandTerminalStatus::Completed)
        ));
        assert_eq!(command.arguments["to"], json!(mailbox.to));
        commands.insert(command_id.to_owned());
    }
    assert_eq!(
        commands.len(),
        3,
        "each fresh request settles its own command"
    );
}

#[test]
fn a_booking_with_failed_receipt_storage_remains_uncertain() -> Result<(), String> {
    let stack = Stack::open();
    let mut proposal = json!({
        "account": ACCOUNT, "type": "create", "title": "Stored once",
        "start": WINDOW_START, "end": WINDOW_END,
    });
    let (approval_id, revision) = match stack
        .dispatch("calendar_propose", proposal.clone(), "receipt-ask")
        .expect_err("the fixture contract requires a decision")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected the fixture question, got {other:?}"),
    };
    stack.approve(&approval_id, revision);
    proposal["approvalId"] = json!(approval_id.to_string());
    stack.adapter.lock().connection().execute_batch(
        "CREATE TEMP TRIGGER fixture_receipt_failure BEFORE UPDATE OF terminal_status ON commands
         WHEN OLD.capability_id = 'calendar.propose'
         BEGIN SELECT RAISE(ABORT, 'fixture receipt storage unavailable'); END;",
    ).unwrap();
    stack
        .dispatch("calendar_propose", proposal.clone(), "receipt-book")
        .expect_err("the provider applied but its receipt could not settle");
    assert_eq!(*stack.book_transport.booked.lock(), ["event-1"]);
    let correlation = correlation_for(&stack.session, "receipt-book").unwrap();
    let row = odin_ledger::operation::operation_row(
        stack
            .ledger
            .lock()
            .map_err(|_| "kernel ledger poisoned".to_owned())?
            .connection(),
        correlation.as_str(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        row.effect_state,
        odin_domain::operation::EffectState::InDoubt,
        "post-effect storage failure never proves an effect-free abort"
    );
    {
        let adapter = stack.adapter.lock();
        let command = adapter
            .commands()
            .unwrap()
            .into_iter()
            .find(|command| command.capability_id.as_str() == "calendar.propose")
            .unwrap();
        assert!(command.accepted_at.is_some() && command.terminal_status.is_none());
        adapter
            .connection()
            .execute_batch("DROP TRIGGER temp.fixture_receipt_failure")
            .unwrap();
    }
    stack
        .dispatch("calendar_propose", proposal, "receipt-book")
        .expect_err("the exact retry must not book again");
    assert_eq!(*stack.book_transport.booked.lock(), ["event-1"]);
    Ok(())
}

/// Loosens the vault root's mode, which the private vault writer refuses
/// (it requires a 0700 directory): a real filesystem fault independent of
/// the account ledger and of the user running the tests.
fn loosen_vault_root(root: &Path) {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
        .expect("the fixture vault root loosens");
}

/// Restores the vault root's private mode when a test ends or fails.
struct PrivateVaultRoot(PathBuf);

impl Drop for PrivateVaultRoot {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// Arms the vault fault for the instant the provider commits its draft: the
/// vault is healthy through admission and the provider call, and unwritable
/// only afterwards, when the handler derives the receipt page.
fn fail_vault_when_draft_commits(stack: &Stack) -> PrivateVaultRoot {
    let root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let hook_root = root.clone();
    *stack.send_transport.after_save.lock() = Some(Box::new(move || loosen_vault_root(&hook_root)));
    PrivateVaultRoot(root)
}

fn fail_vault_when_booking_commits(stack: &Stack) -> PrivateVaultRoot {
    let root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let hook_root = root.clone();
    *stack.book_transport.after_apply.lock() =
        Some(Box::new(move || loosen_vault_root(&hook_root)));
    PrivateVaultRoot(root)
}

/// Every file beneath the vault root, relative to it, sorted.
fn vault_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, root: &Path, found: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, found);
            } else {
                found.push(path.strip_prefix(root).unwrap().to_owned());
            }
        }
    }
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found.sort();
    found
}

fn publication_status(receipt: &Value) -> Option<&str> {
    receipt["receiptPublication"]["status"].as_str()
}

fn operation_state(stack: &Stack, request_id: &str) -> odin_domain::operation::EffectState {
    let correlation = correlation_for(&stack.session, request_id).unwrap();
    let row = odin_ledger::operation::operation_row(
        stack.ledger.lock().unwrap().connection(),
        correlation.as_str(),
    )
    .unwrap()
    .expect("the dispatched operation row");
    row.effect_state
}

fn draft_request() -> Value {
    json!({
        "account": ACCOUNT, "to": ["receipt@example.invalid"],
        "subject": "Receipt probe", "body_text": "Noon at the longhouse?",
    })
}

fn booking_request() -> Value {
    json!({
        "account": ACCOUNT, "type": "create", "title": "Receipt probe",
        "start": WINDOW_START, "end": WINDOW_END,
    })
}

/// The provider saved exactly one new draft and the result and durable
/// account command carry exactly that committed draft.
fn assert_one_committed_draft(stack: &Stack, receipt: &Value, drafts_before: usize) {
    let saved = stack.send_transport.drafts.lock()[drafts_before..].to_vec();
    assert_eq!(saved.len(), 1, "exactly one provider draft call");
    assert_eq!(
        receipt["result"]["draftId"],
        json!(saved[0].0),
        "the result keeps the provider's committed draft id"
    );
    assert_eq!(receipt["replayed"], json!(false));
    let command = stack
        .adapter
        .lock()
        .command(&CommandId::new(receipt["command_id"].as_str().unwrap()).unwrap())
        .unwrap()
        .expect("the durable draft command");
    assert!(matches!(
        command.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    ));
}

/// The provider applied exactly one booking and the result and durable
/// account command carry exactly that committed event.
fn assert_one_committed_booking(stack: &Stack, receipt: &Value) {
    assert_eq!(*stack.book_transport.booked.lock(), ["event-1"]);
    assert_eq!(
        stack.book_transport.proposals.lock().len(),
        1,
        "exactly one provider booking call"
    );
    assert_eq!(
        receipt["result"]["eventIds"],
        json!(["event-1"]),
        "the result keeps the provider's committed event id"
    );
    assert_eq!(receipt["replayed"], json!(false));
    let command = stack
        .adapter
        .lock()
        .command(&CommandId::new(receipt["command_id"].as_str().unwrap()).unwrap())
        .unwrap()
        .expect("the durable booking command");
    assert!(matches!(
        command.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    ));
}

/// A committed draft whose derived page cannot be written stays a committed
/// draft, and its result says the receipt page failed. A settled request is
/// never re-run, so no retry under the same request can save another draft.
#[test]
fn email_draft_reports_a_failed_receipt_publication_beside_its_committed_draft() {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: false,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let owner_note = vault_root.join("owner-note.md");
    std::fs::write(&owner_note, b"pending owner edits\n").unwrap();
    let _private = fail_vault_when_draft_commits(&stack);
    let drafts_before = stack.send_transport.drafts.lock().len();

    let receipt = stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect("the committed draft remains the dispatch result");

    assert_one_committed_draft(&stack, &receipt, drafts_before);
    assert_eq!(
        operation_state(&stack, "receipt-draft"),
        odin_domain::operation::EffectState::Committed,
        "a page failure never turns a committed draft into an abort or doubt"
    );
    assert!(
        stack.approvals().is_empty(),
        "a failed page never asks the owner anything"
    );
    assert_eq!(vault_files(&vault_root), [PathBuf::from("owner-note.md")]);

    stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect_err("a settled request is never re-executed");
    assert_eq!(
        stack.send_transport.drafts.lock().len(),
        drafts_before + 1,
        "the same request never saves another draft"
    );
    assert_eq!(vault_files(&vault_root), [PathBuf::from("owner-note.md")]);
    assert_eq!(
        std::fs::read(&owner_note).unwrap(),
        b"pending owner edits\n"
    );

    assert_eq!(
        publication_status(&receipt),
        Some("failed"),
        "the draft result must report its receipt publication as failed"
    );
}

/// A committed booking whose receipt and appointment pages cannot be written
/// stays a committed booking decided by its declaration, and its result says
/// the receipt publication failed.
#[test]
fn calendar_propose_reports_a_failed_receipt_publication_beside_its_committed_booking() {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: true,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let owner_note = vault_root.join("owner-note.md");
    std::fs::write(&owner_note, b"pending owner edits\n").unwrap();
    let _private = fail_vault_when_booking_commits(&stack);

    let receipt = stack
        .dispatch("calendar_propose", booking_request(), "receipt-book")
        .expect("the committed booking remains the dispatch result");

    assert_one_committed_booking(&stack, &receipt);
    assert_eq!(
        operation_state(&stack, "receipt-book"),
        odin_domain::operation::EffectState::Committed,
        "a page failure never turns a committed booking into an abort or doubt"
    );
    let approvals = stack.approvals();
    let decider = format!("declaration:{SEAT}");
    assert_eq!(approvals.len(), 1, "no owner question was minted");
    assert_eq!(approvals[0].status, odin_domain::ApprovalStatus::Consumed);
    assert_eq!(approvals[0].decided_by.as_deref(), Some(decider.as_str()));
    assert_eq!(vault_files(&vault_root), [PathBuf::from("owner-note.md")]);

    stack
        .dispatch("calendar_propose", booking_request(), "receipt-book")
        .expect_err("a settled request is never re-executed");
    assert_eq!(
        *stack.book_transport.booked.lock(),
        ["event-1"],
        "the same request never rebooks"
    );
    assert_eq!(stack.book_transport.proposals.lock().len(), 1);
    assert_eq!(vault_files(&vault_root), [PathBuf::from("owner-note.md")]);
    assert_eq!(
        std::fs::read(&owner_note).unwrap(),
        b"pending owner edits\n"
    );

    assert_eq!(
        publication_status(&receipt),
        Some("failed"),
        "the booking result must report its receipt publication as failed"
    );
}

/// The healthy private vault is the control: the same dispatches publish
/// their real pages and say so, so a failed result is distinguishable.
#[test]
fn life_receipts_report_published_when_the_private_vault_accepts_the_pages() {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: true,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let drafts_before = stack.send_transport.drafts.lock().len();

    let draft = stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect("the draft commits");
    assert_one_committed_draft(&stack, &draft, drafts_before);
    let pages = vault_files(&vault_root);
    assert_eq!(pages.len(), 1, "one draft page");
    assert!(pages[0].starts_with("generated/drafts"));

    let booking = stack
        .dispatch("calendar_propose", booking_request(), "receipt-book")
        .expect("the booking commits");
    assert_one_committed_booking(&stack, &booking);
    let parents: Vec<PathBuf> = vault_files(&vault_root)
        .iter()
        .map(|page| page.parent().unwrap().to_owned())
        .collect();
    assert_eq!(
        parents,
        [
            PathBuf::from("generated/appointments"),
            PathBuf::from("generated/calendar"),
            PathBuf::from("generated/drafts"),
        ]
    );

    assert_eq!(
        publication_status(&draft),
        Some("published"),
        "a written draft page is reported published"
    );
    assert_eq!(
        publication_status(&booking),
        Some("published"),
        "written receipt and appointment pages are reported published"
    );
}

/// With no vault composed nothing can be published, and the results say so
/// instead of omitting the page or reporting it published.
#[test]
fn life_receipts_report_unavailable_when_no_vault_is_composed() {
    let stack = Stack::open_with_life(Life {
        vault: false,
        declare_calendar: true,
    });
    let drafts_before = stack.send_transport.drafts.lock().len();

    let draft = stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect("the draft commits");
    assert_one_committed_draft(&stack, &draft, drafts_before);
    let booking = stack
        .dispatch("calendar_propose", booking_request(), "receipt-book")
        .expect("the booking commits");
    assert_one_committed_booking(&stack, &booking);

    assert_eq!(publication_status(&draft), Some("unavailable"));
    assert_eq!(publication_status(&booking), Some("unavailable"));
}

/// Republishes the receipt of one original operation under a new R2 host
/// request on the existing generated-write surface.
fn repair_receipt(
    stack: &Stack,
    correlation_id: &str,
    request_id: &str,
) -> Result<Value, HostToolOperationError> {
    stack.dispatch(
        "vault_write_generated",
        json!({ "receipt_correlation_id": correlation_id }),
        request_id,
    )
}

/// Each reported receipt page with its outcome, in publication order.
fn page_outcomes(receipt: &Value) -> Vec<(String, String)> {
    receipt["receiptPublication"]["pages"]
        .as_array()
        .expect("the publication lists its pages")
        .iter()
        .map(|page| {
            (
                page["pageName"].as_str().unwrap().to_owned(),
                page["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn page(name: &str, outcome: &str) -> (String, String) {
    (name.to_owned(), outcome.to_owned())
}

fn account_command(stack: &Stack, receipt: &Value) -> odin_ledger::command::Command {
    stack
        .adapter
        .lock()
        .command(&CommandId::new(receipt["command_id"].as_str().unwrap()).unwrap())
        .unwrap()
        .expect("the durable account command")
}

/// A draft page that failed beside its committed draft is repaired from the
/// committed draft's own record once the vault is private again: model page
/// text is still refused, the original correlation writes exactly the
/// derived page, an identical retry writes nothing, an owner's edit is never
/// overwritten, and the provider never saves another draft.
#[test]
fn email_draft_receipt_repair_republishes_only_the_committed_draft_page() {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: false,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let owner_note = vault_root.join("owner-note.md");
    std::fs::write(&owner_note, b"pending owner edits\n").unwrap();
    let private = fail_vault_when_draft_commits(&stack);
    let drafts_before = stack.send_transport.drafts.lock().len();
    let receipt = stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect("the committed draft remains the dispatch result");
    assert_one_committed_draft(&stack, &receipt, drafts_before);
    let committed = account_command(&stack, &receipt);
    let correlation = correlation_for(&stack.session, "receipt-draft").unwrap();
    assert_eq!(
        receipt["receiptPublication"]["correlationId"],
        json!(correlation.as_str()),
        "the failed publication names its original operation"
    );
    let failed = page_outcomes(&receipt);
    assert_eq!(failed.len(), 1);
    let draft_page = failed[0].0.clone();
    assert_eq!(failed, [page(&draft_page, "failed")]);

    drop(private);
    let forged = json!({ "page_name": draft_page, "content": "# Draft forged\n" });
    stack
        .dispatch("vault_write_generated", forged, "receipt-forged")
        .expect_err("model page text is still gated by the project-memory write gate");
    let mixed = json!({
        "receipt_correlation_id": correlation.as_str(),
        "page_name": draft_page,
        "content": "# Draft forged\n",
    });
    stack
        .dispatch("vault_write_generated", mixed, "receipt-mixed")
        .expect_err("a receipt repair never takes caller page text");
    assert_eq!(vault_files(&vault_root), [PathBuf::from("owner-note.md")]);

    let repaired = repair_receipt(&stack, correlation.as_str(), "receipt-repair")
        .expect("the committed draft's page is republished");
    assert_eq!(publication_status(&repaired), Some("published"));
    assert_eq!(
        repaired["receiptPublication"]["correlationId"],
        json!(correlation.as_str())
    );
    assert_eq!(page_outcomes(&repaired), [page(&draft_page, "written")]);
    let expected = format!(
        "# Draft {}\n\nSubject: Receipt probe\n\nNoon at the longhouse?\n",
        receipt["command_id"].as_str().unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(vault_root.join(&draft_page)).unwrap(),
        expected,
        "the page is derived from the committed draft's durable record"
    );
    assert_eq!(
        repaired["receiptPublication"]["pages"][0]["contentDigest"],
        json!(Digest::hash(expected.as_bytes()).to_string())
    );
    assert_eq!(
        operation_state(&stack, "receipt-repair"),
        odin_domain::operation::EffectState::Committed
    );
    assert_eq!(
        vault_files(&vault_root),
        [PathBuf::from(&draft_page), PathBuf::from("owner-note.md")]
    );

    let again = repair_receipt(&stack, correlation.as_str(), "receipt-repair-again")
        .expect("an identical page is an idempotent success");
    assert_eq!(publication_status(&again), Some("published"));
    assert_eq!(page_outcomes(&again), [page(&draft_page, "identical")]);
    assert_eq!(
        std::fs::read_to_string(vault_root.join(&draft_page)).unwrap(),
        expected
    );

    let edited = b"# Draft notes\n\nOwner: send after lunch\n";
    std::fs::write(vault_root.join(&draft_page), edited).unwrap();
    repair_receipt(&stack, correlation.as_str(), "receipt-repair-edited")
        .expect_err("an owner-edited page is a conflict, never overwritten");
    assert_eq!(std::fs::read(vault_root.join(&draft_page)).unwrap(), edited);

    assert_eq!(
        stack.send_transport.drafts.lock().len(),
        drafts_before + 1,
        "no repair ever saves another draft"
    );
    assert_eq!(
        account_command(&stack, &receipt),
        committed,
        "the completed draft command and its provider draft id are untouched"
    );
    assert!(stack.approvals().is_empty(), "no repair asks the owner");
    assert_eq!(
        std::fs::read(&owner_note).unwrap(),
        b"pending owner edits\n"
    );
}

/// A booking whose two receipt pages failed is repaired page by page from
/// its committed record: with the owner's edit standing on the appointment
/// page, only the missing calendar page is written and the publication stays
/// failed; a retry that could write nothing refuses; once the edit is gone
/// the exact appointment page is written beside the identical calendar page.
/// The provider is never contacted again and no owner decision is minted.
#[test]
fn calendar_receipt_repair_writes_only_missing_pages_and_never_rebooks() {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: true,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let private = fail_vault_when_booking_commits(&stack);
    let receipt = stack
        .dispatch("calendar_propose", booking_request(), "receipt-book")
        .expect("the committed booking remains the dispatch result");
    assert_one_committed_booking(&stack, &receipt);
    let committed = account_command(&stack, &receipt);
    let correlation = correlation_for(&stack.session, "receipt-book").unwrap();
    let failed = page_outcomes(&receipt);
    assert_eq!(
        failed.len(),
        2,
        "the receipt and appointment pages were promised"
    );
    let (calendar_page, appointment_page) = (failed[0].0.clone(), failed[1].0.clone());
    assert_eq!(
        failed,
        [
            page(&calendar_page, "failed"),
            page(&appointment_page, "failed")
        ]
    );
    assert!(calendar_page.starts_with("generated/calendar/"));
    assert!(appointment_page.starts_with("generated/appointments/"));

    drop(private);
    let appointment_path = vault_root.join(&appointment_page);
    std::fs::create_dir_all(appointment_path.parent().unwrap()).unwrap();
    let edited = b"# Appointment Receipt probe\n\nOwner: bring the agenda\n";
    std::fs::write(&appointment_path, edited).unwrap();

    let partial = repair_receipt(&stack, correlation.as_str(), "receipt-repair")
        .expect("the missing receipt page is written");
    assert_eq!(
        publication_status(&partial),
        Some("failed"),
        "one promised page still is not the receipt"
    );
    assert_eq!(
        page_outcomes(&partial),
        [
            page(&calendar_page, "written"),
            page(&appointment_page, "conflict")
        ]
    );
    let calendar_receipt = format!(
        "# Calendar mutation receipt\n\ncreate Receipt probe ({WINDOW_START}..{WINDOW_END})\
         \n\nEvent ids: event-1\n"
    );
    assert_eq!(
        std::fs::read_to_string(vault_root.join(&calendar_page)).unwrap(),
        calendar_receipt
    );
    assert_eq!(std::fs::read(&appointment_path).unwrap(), edited);

    repair_receipt(&stack, correlation.as_str(), "receipt-repair-blocked")
        .expect_err("a repair that can write nothing is refused");
    assert_eq!(std::fs::read(&appointment_path).unwrap(), edited);

    std::fs::remove_file(&appointment_path).unwrap();
    let complete = repair_receipt(&stack, correlation.as_str(), "receipt-repair-complete")
        .expect("the missing appointment page is written");
    assert_eq!(publication_status(&complete), Some("published"));
    assert_eq!(
        page_outcomes(&complete),
        [
            page(&calendar_page, "identical"),
            page(&appointment_page, "written")
        ]
    );
    assert_eq!(
        std::fs::read_to_string(&appointment_path).unwrap(),
        format!("# Appointment Receipt probe\n\nStart: {WINDOW_START}\nEnd: {WINDOW_END}\n")
    );
    assert_eq!(
        std::fs::read_to_string(vault_root.join(&calendar_page)).unwrap(),
        calendar_receipt
    );

    assert_eq!(*stack.book_transport.booked.lock(), ["event-1"]);
    assert_eq!(
        stack.book_transport.proposals.lock().len(),
        1,
        "no repair ever reaches the provider"
    );
    assert_eq!(
        account_command(&stack, &receipt),
        committed,
        "the completed booking and its event id are untouched"
    );
    assert_eq!(
        stack.approvals().len(),
        1,
        "only the original declaration decision exists"
    );
}

/// A receipt repair is bound to its genuine original effect: the same
/// committed draft refuses while its journal row names another seat or
/// session, an in-doubt partial booking and an unrelated committed operation
/// refuse, and an unknown correlation refuses — each without a page or a
/// provider call. The restored row is then repaired, so the refusals were
/// the identity binding and not an unusable fixture.
#[test]
fn receipt_repair_refuses_foreign_unsettled_and_unrelated_identities() -> Result<(), String> {
    let stack = Stack::open_with_life(Life {
        vault: true,
        declare_calendar: false,
    });
    let vault_root = stack
        .vault_root
        .clone()
        .expect("the stack composes a vault");
    let private = fail_vault_when_draft_commits(&stack);
    let drafts_before = stack.send_transport.drafts.lock().len();
    let receipt = stack
        .dispatch("email_draft", draft_request(), "receipt-draft")
        .expect("the committed draft remains the dispatch result");
    assert_eq!(publication_status(&receipt), Some("failed"));
    drop(private);
    let correlation = correlation_for(&stack.session, "receipt-draft").unwrap();
    let journal = |column: &str, value: &str| {
        stack
            .adapter
            .lock()
            .connection()
            .execute(
                &format!("UPDATE operation_journal SET {column} = ?1 WHERE correlation_id = ?2"),
                [value, correlation.as_str()],
            )
            .unwrap();
    };

    journal("seat_id", "another-seat");
    repair_receipt(&stack, correlation.as_str(), "repair-foreign-seat")
        .expect_err("another seat's draft is never repaired here");
    journal("seat_id", SEAT);
    journal("session_id", "00000000-0000-4000-8000-0000000000e1");
    repair_receipt(&stack, correlation.as_str(), "repair-foreign-session")
        .expect_err("another session's draft is never repaired here");
    journal("session_id", SESSION);

    let draft = |title: &str| json!({ "title": title, "start": WINDOW_START, "end": WINDOW_END });
    let mut batch = json!({
        "account": ACCOUNT,
        "type": "batchCreate",
        "drafts": [draft("Standup"), draft("Retro")],
    });
    let (approval_id, revision) = match stack
        .dispatch("calendar_propose", batch.clone(), "repair-batch-ask")
        .expect_err("the fixture contract requires a decision")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected the fixture question, got {other:?}"),
    };
    stack.approve(&approval_id, revision);
    batch["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("calendar_propose", batch, "repair-batch")
        .expect_err("a partially applied batch is never a booking");
    assert_eq!(
        operation_state(&stack, "repair-batch"),
        odin_domain::operation::EffectState::InDoubt
    );
    let in_doubt = correlation_for(&stack.session, "repair-batch").unwrap();
    repair_receipt(&stack, in_doubt.as_str(), "repair-in-doubt")
        .expect_err("an unsettled booking is reconciled, never given a receipt");

    stack
        .dispatch("email_manage", manage_arguments(), "repair-manage")
        .expect("reversible organization commits");
    let unrelated = correlation_for(&stack.session, "repair-manage").unwrap();
    repair_receipt(&stack, unrelated.as_str(), "repair-unrelated")
        .expect_err("an operation without a life receipt is refused");
    repair_receipt(&stack, "0123456789abcdef0123456789abcdef", "repair-unknown")
        .expect_err("an unknown correlation names nothing");

    assert!(
        vault_files(&vault_root).is_empty(),
        "no refusal wrote a page"
    );
    assert_eq!(stack.book_transport.proposals.lock().len(), 1);
    assert_eq!(*stack.book_transport.booked.lock(), ["event-1", "event-2"]);
    let in_doubt_command = stack
        .adapter
        .lock()
        .commands()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|command| command.capability_id.as_str() == "calendar.propose")
        .ok_or("the recorded booking intent")?;
    assert_eq!(
        in_doubt_command.terminal_status, None,
        "a refused repair never settles the in-doubt booking"
    );

    let repaired = repair_receipt(&stack, correlation.as_str(), "repair-restored")
        .expect("the restored original identity is repaired");
    assert_eq!(publication_status(&repaired), Some("published"));
    assert_eq!(vault_files(&vault_root).len(), 1);
    assert_eq!(
        stack.send_transport.drafts.lock().len(),
        drafts_before + 1,
        "no repair or refusal ever saves another draft"
    );
    Ok(())
}

/// A batch booking whose provider applied the first member and lost the
/// reply to the second reaches the kernel as uncertainty through the real
/// `calendar_propose` handler: the outer operation is in-doubt, never
/// aborted without effect; the account command stays unsettled beside the
/// durable known id; and the exact retry never reaches the provider.
#[test]
fn calendar_propose_partial_batch_stays_in_doubt_and_never_rebooks() -> Result<(), String> {
    let stack = Stack::open();
    let draft = |title: &str| json!({ "title": title, "start": WINDOW_START, "end": WINDOW_END });
    let mut proposal = json!({
        "account": ACCOUNT,
        "type": "batchCreate",
        "drafts": [draft("Standup"), draft("Retro")],
    });
    let (approval_id, requested_revision) = match stack
        .dispatch("calendar_propose", proposal.clone(), "req-batch-1")
        .expect_err("the first R3 dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    stack.approve(&approval_id, requested_revision);
    proposal["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("calendar_propose", proposal.clone(), "req-batch-2")
        .expect_err("a partially applied batch is never a booking");
    assert_eq!(
        *stack.book_transport.booked.lock(),
        ["event-1", "event-2"],
        "the provider applied both members; only the first reply arrived"
    );

    let correlation = correlation_for(&stack.session, "req-batch-2").unwrap();
    let row = odin_ledger::operation::operation_row(
        stack
            .ledger
            .lock()
            .map_err(|_| "kernel ledger poisoned".to_owned())?
            .connection(),
        correlation.as_str(),
    )
    .unwrap()
    .expect("the dispatched operation row");
    assert_eq!(
        row.effect_state,
        odin_domain::operation::EffectState::InDoubt,
        "the kernel never records an effect-free abort"
    );
    {
        let adapter = stack.adapter.lock();
        let command = adapter
            .commands()
            .unwrap()
            .into_iter()
            .find(|command| command.capability_id.as_str() == "calendar.propose")
            .expect("the recorded booking intent");
        assert!(command.accepted_at.is_some());
        assert_eq!(
            command.terminal_status, None,
            "an incomplete batch is never terminal"
        );
        let evidence = adapter
            .audit_events_after(0, 1_000)
            .unwrap()
            .into_iter()
            .find(|event| event.kind == crate::account::PARTIAL_EFFECT_AUDIT_KIND)
            .expect("the partial truth is durable");
        assert_eq!(
            evidence.evidence,
            [odin_ledger::audit::AuditEvidence::Command(command.id)]
        );
        assert_eq!(evidence.payload["knownIds"], json!(["event-1"]));
    }

    stack
        .dispatch("calendar_propose", proposal, "req-batch-2")
        .expect_err("an in-doubt operation never re-runs");
    assert_eq!(
        stack.book_transport.proposals.lock().len(),
        1,
        "the exact retry never reaches the provider"
    );
    assert_eq!(stack.book_transport.booked.lock().len(), 2);
    Ok(())
}

const MODEL_TARGET: &str = "another-assistant";

#[derive(Default)]
struct ScriptedModel {
    survey: parking_lot::Mutex<SeatSessionSurvey>,
    commands: parking_lot::Mutex<Vec<ModelSetCommand>>,
    persisted: parking_lot::Mutex<Vec<(String, String)>>,
}

impl ModelCommandRoute for ScriptedModel {
    fn survey_seat(&self, _seat: &SeatId) -> Result<SeatSessionSurvey, ModelRouteError> {
        Ok(self.survey.lock().clone())
    }

    fn command_set_model(
        &self,
        command: ModelSetCommand,
    ) -> Result<CommandReceipt, ModelRouteError> {
        let receipt = CommandReceipt::Accepted {
            command_id: command.command_id.clone(),
        };
        self.commands.lock().push(command);
        Ok(receipt)
    }

    fn persist_choice(
        &self,
        _seat: &SeatId,
        provider: &odin_domain::huginn::ProviderName,
        model: &odin_domain::huginn::ModelName,
    ) -> Result<(), ModelRouteError> {
        self.persisted
            .lock()
            .push((provider.as_str().to_owned(), model.as_str().to_owned()));
        Ok(())
    }
}

fn model_launches() -> ModelLaunchDeclaration {
    ModelLaunchDeclaration::from_bindings(&[odin_omp::live::supervisor::LiveSeatBinding {
        seat_id: SeatId::new(MODEL_TARGET).unwrap(),
        slice_id: SliceId::new(SLICE).unwrap(),
        display_name: "Another assistant".to_owned(),
        launch_options: [("provider-a", "model-a"), ("provider-b", "model-b")]
            .into_iter()
            .map(|(provider, model)| LiveLaunchOption {
                provider: odin_domain::huginn::ProviderName::new(provider).unwrap(),
                model: odin_domain::huginn::ModelName::new(model).unwrap(),
                skeleton_ref: "fixture".to_owned(),
                container_id: odin_domain::ContainerId::new("fixture").unwrap(),
                harness: None,
            })
            .collect(),
        allowed_nodes: vec![],
        max_sessions: 2,
        turn_budget: None,
    }])
}

fn model_session(id: u32) -> LiveSessionSummary {
    LiveSessionSummary {
        session_id: LiveSessionId::parse(&format!("{id:08x}-0000-4000-8000-000000000001")).unwrap(),
        epoch: SessionEpoch::new(3),
        seat_id: SeatId::new(MODEL_TARGET).unwrap(),
        provider: odin_domain::huginn::ProviderName::new("provider-a").unwrap(),
        model: odin_domain::huginn::ModelName::new("model-a").unwrap(),
        title: None,
        state: LiveSessionState::Idle,
        started_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        failed_at: None,
        event_head: EventSeq::new(0),
        terminal_head: TerminalSeq::new(0),
        pending_permission_count: 0,
    }
}

fn model_arguments() -> Value {
    json!({"seat": MODEL_TARGET, "provider": "provider-b", "model": "model-b"})
}

#[test]
fn model_switch_approved_cross_seat_dispatches_once_and_replay_cannot_switch_again() {
    let route = Arc::new(ScriptedModel::default());
    route.survey.lock().live_sessions = vec![model_session(1)];
    let stack = Stack::open_with_model(Some(route.clone()));
    let arguments = model_arguments();
    let first = stack
        .dispatch("seat_model_set", arguments.clone(), "model-first")
        .unwrap_err();
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        effect_class,
        ..
    } = first
    else {
        panic!("expected actionable operator approval, got {first:?}");
    };
    assert_eq!(effect_class, EffectClass::R2);
    assert!(route.commands.lock().is_empty());
    assert_eq!(stack.approvals().len(), 1);
    stack.approve(&approval_id, revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let result = stack
        .dispatch("seat_model_set", retry.clone(), "model-approved")
        .unwrap();
    assert_eq!(result["seat"], MODEL_TARGET);
    assert_eq!(result["receipt"]["status"], "accepted");
    assert_eq!(result["sessionId"], model_session(1).session_id.to_string());
    let commands = route.commands.lock();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].provider.as_str(), "provider-b");
    assert_eq!(commands[0].model.as_str(), "model-b");
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
    assert_eq!(
        approval.consumed_by_command_id.as_ref(),
        Some(&commands[0].command_id)
    );
    drop(commands);
    stack
        .dispatch("seat_model_set", retry, "model-approved")
        .expect_err("the completed command cannot switch the model again");
    assert_eq!(route.commands.lock().len(), 1);
}

#[test]
fn model_switch_preflight_refuses_undeclared_pairs_and_keeps_choices_without_a_live_session() {
    let route = Arc::new(ScriptedModel::default());
    route.survey.lock().live_sessions = vec![model_session(1)];
    let stack = Stack::open_with_model(Some(route.clone()));
    let mut wrong_pair = model_arguments();
    wrong_pair["provider"] = json!("provider-a");
    let error = stack
        .dispatch("seat_model_set", wrong_pair, "model-wrong-pair")
        .unwrap_err();
    assert!(matches!(error, HostToolOperationError::Arguments { .. }));
    assert!(stack.approvals().is_empty());
    assert!(route.commands.lock().is_empty());

    let mut starting = model_session(1);
    starting.state = LiveSessionState::Starting;
    let mut aborting = model_session(1);
    aborting.state = LiveSessionState::Aborting;
    // Without a switchable session, approval persists the choice without issuing a live command.
    for (index, sessions) in [
        vec![],
        vec![starting],
        vec![aborting],
        vec![model_session(1), model_session(2)],
    ]
    .into_iter()
    .enumerate()
    {
        route.survey.lock().live_sessions = sessions;
        let command = format!("model-unresolved-{index}");
        let HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } = stack
            .dispatch("seat_model_set", model_arguments(), &command)
            .unwrap_err()
        else {
            panic!("a seat without a live session is still switchable");
        };
        stack.approve(&approval_id, revision);
        let mut arguments = model_arguments();
        arguments["approvalId"] = json!(approval_id.to_string());
        let result = stack
            .dispatch("seat_model_set", arguments, &format!("{command}-approved"))
            .unwrap();
        assert_eq!(result["persisted"], true);
        assert!(route.commands.lock().is_empty());
    }
    assert_eq!(route.persisted.lock().len(), 4);

    // The declared vehicle, not order or recency, resolves the ambiguity.
    route.survey.lock().declared_vehicle = Some(model_session(2).session_id);
    let first = stack
        .dispatch("seat_model_set", model_arguments(), "model-vehicle")
        .unwrap_err();
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        ..
    } = first
    else {
        panic!("expected vehicle-specific approved request, got {first:?}");
    };
    stack.approve(&approval_id, revision);
    let mut arguments = model_arguments();
    arguments["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("seat_model_set", arguments, "model-vehicle-approved")
        .unwrap();
    assert_eq!(
        route.commands.lock()[0].session_id,
        model_session(2).session_id
    );
}

#[test]
fn workspace_connect_dispatch_serves_the_declared_session_command() {
    let stack = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Ok(WorkspaceConnection {
            command: "zr mini odin".to_owned(),
            kind: WorkspaceConnectionKind::Zellij,
            host: "mini".to_owned(),
            target: "odin".to_owned(),
        }),
    })));
    let receipt = stack
        .dispatch(
            "workspace_connect",
            json!({ "target": "odin" }),
            "req-workspace-1",
        )
        .expect("the R1 pure dispatch must settle through the real handler");
    assert_eq!(receipt["command"], json!("zr mini odin"));
    assert_eq!(receipt["kind"], json!("zellij"));
    assert_eq!(receipt["host"], json!("mini"));
    assert_eq!(receipt["target"], json!("odin"));
    assert!(
        stack.approvals().is_empty(),
        "an R1 contract with approval_policy none must never mint an approval row"
    );
}

/// The project twin: a declared project id resolves to the zed-over-ssh
/// command for the host that runs it.
#[test]
fn workspace_connect_dispatch_serves_the_declared_project_command() {
    let stack = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Ok(WorkspaceConnection {
            command: "zed ssh://mini/home/colin/odin-deslop".to_owned(),
            kind: WorkspaceConnectionKind::Zed,
            host: "mini".to_owned(),
            target: "odin".to_owned(),
        }),
    })));
    let receipt = stack
        .dispatch(
            "workspace_connect",
            json!({ "target": "odin", "host": "mini" }),
            "req-workspace-2",
        )
        .expect("the project dispatch must settle through the real handler");
    assert_eq!(
        receipt["command"],
        json!("zed ssh://mini/home/colin/odin-deslop")
    );
    assert_eq!(receipt["kind"], json!("zed"));
}

/// An offline host is a typed refusal at the declared-admissibility gate:
/// the exact sentence travels in the dispatch error and nothing is
/// journaled toward an effect.
#[test]
fn workspace_connect_dispatch_refuses_an_offline_host_typed() {
    let stack = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Err("host mini is offline (last seen 2026-09-28T09:00:00Z)".to_owned()),
    })));
    let error = stack
        .dispatch(
            "workspace_connect",
            json!({ "target": "odin" }),
            "req-workspace-3",
        )
        .expect_err("an offline host must refuse typed");
    let HostToolOperationError::Arguments { detail } = &error else {
        panic!("expected the preflight typed refusal, got {error:?}");
    };
    assert!(
        detail.contains("host mini is offline (last seen 2026-09-28T09:00:00Z)"),
        "the typed offline sentence must travel: {detail}"
    );
    assert!(
        stack.approvals().is_empty(),
        "a refused dispatch must never mint an approval row"
    );
}

/// An unknown target is a typed refusal in the LiveError vocabulary.
#[test]
fn workspace_connect_dispatch_refuses_an_unknown_target_typed() {
    let stack = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Err(
            "zellij session or project nowhere was not found in the fleet placements or the \
             declared projects"
                .to_owned(),
        ),
    })));
    let error = stack
        .dispatch(
            "workspace_connect",
            json!({ "target": "nowhere" }),
            "req-workspace-4",
        )
        .expect_err("an unknown target must refuse typed");
    let HostToolOperationError::Arguments { detail } = &error else {
        panic!("expected the preflight typed refusal, got {error:?}");
    };
    assert!(
        detail.contains("nowhere was not found"),
        "the typed not-found sentence must travel: {detail}"
    );
}

/// The route is a daemon seam the runtime composes unbound: an unbound
/// seam fails closed with a typed unavailability.
#[test]
fn workspace_connect_dispatch_fails_closed_when_the_route_is_unbound() {
    let stack = Stack::open_with_workspace(None);
    let error = stack
        .dispatch(
            "workspace_connect",
            json!({ "target": "odin" }),
            "req-workspace-5",
        )
        .expect_err("an unbound route must refuse typed");
    let HostToolOperationError::Arguments { detail } = &error else {
        panic!("expected the unbound typed refusal, got {error:?}");
    };
    assert!(
        detail.contains("the workspace connect route is not bound"),
        "the typed unbound sentence must travel: {detail}"
    );
}

#[test]
fn fleet_drain_non_authority_host_needs_exactly_one_approval_then_settles_once() {
    let route = ScriptedFleetDrain::worker();
    let stack = Stack::open_with_fleet(Some(Some(route.clone())));
    let arguments = json!({ "host": "mini" });
    let first = stack
        .dispatch("fleet_drain", arguments.clone(), "fleet-first")
        .unwrap_err();
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        effect_class,
        ..
    } = first
    else {
        panic!("expected the R2 operator approval gate, got {first:?}");
    };
    assert_eq!(effect_class, EffectClass::R2);
    assert!(
        route.asks.lock().is_empty(),
        "a gated dispatch must never reach the route before the approval is consumed"
    );
    assert_eq!(stack.approvals().len(), 1, "exactly ONE approval row");
    stack.approve(&approval_id, revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let result = stack
        .dispatch("fleet_drain", retry.clone(), "fleet-approved")
        .expect("the approved retry must settle through the real handler");
    assert_eq!(result["host"], json!("mini"));
    assert_eq!(result["node"], json!("mini-node"));
    assert_eq!(result["result"], json!("drained"));
    assert_eq!(result["cordoned"], json!(true));
    assert_eq!(result["evicted"], json!(["batch-0"]));
    assert_eq!(result["remained"], json!(["stuck-pod"]));
    assert_eq!(result["authorityHolds"], json!(false));
    let asks = route.asks.lock();
    assert_eq!(asks.len(), 1, "the route drained exactly once");
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
    assert!(approval.consumed_by_command_id.is_some());
    drop(asks);
    assert!(matches!(
        stack.dispatch("fleet_drain", retry, "fleet-replay"),
        Err(HostToolOperationError::Rejected(
            odin_kernel::AuthorizationRejection::NeedsApproval { .. }
        ))
    ));
    assert_eq!(route.asks.lock().len(), 1, "the replay never re-drains");
}

/// The authority host twin: the drain answer is the authority-move plan,
/// the seven steps arrive in order, the standby candidates come from the
/// declarations, and the route was NEVER asked to touch the cluster.
#[test]
fn fleet_drain_authority_host_returns_the_move_plan_without_touching_the_cluster() {
    let route = ScriptedFleetDrain::authority();
    let stack = Stack::open_with_fleet(Some(Some(route.clone())));
    let arguments = json!({ "host": "mini" });
    let first = stack
        .dispatch("fleet_drain", arguments.clone(), "authority-first")
        .unwrap_err();
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        effect_class,
        ..
    } = first
    else {
        panic!("expected the R2 operator approval gate, got {first:?}");
    };
    assert_eq!(effect_class, EffectClass::R2);
    stack.approve(&approval_id, revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let result = stack
        .dispatch("fleet_drain", retry, "authority-approved")
        .expect("the approved retry must settle with the plan");
    assert_eq!(result["result"], json!("authority-move-plan"));
    assert_eq!(result["authorityHolds"], json!(true));
    assert_eq!(result["cordoned"], json!(false));
    assert_eq!(result["node"], json!("odin-core"));
    let steps = result["plan"]["steps"]
        .as_array()
        .expect("the plan carries its ordered steps");
    assert_eq!(steps.len(), 7, "the runbook is seven ordered steps");
    for (index, step) in steps.iter().enumerate() {
        assert_eq!(step["step"], json!((index + 1) as u64), "ordered steps");
    }
    let candidates = result["plan"]["candidates"]
        .as_array()
        .expect("the plan lists the declared standby candidates");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["node"], json!("spare-node"));
    assert_eq!(candidates[0]["host"], json!("spare"));
    assert!(
        route.touches.lock().is_empty(),
        "an authority host is never actuated: no cluster touch may be recorded"
    );
}

/// An offline host refuses typed at the declared-admissibility gate: the
/// exact sentence travels and nothing is journaled toward an effect.
#[test]
fn fleet_drain_refuses_an_offline_host_typed() {
    let route = ScriptedFleetDrain::offline();
    let stack = Stack::open_with_fleet(Some(Some(route.clone())));
    let error = stack
        .dispatch("fleet_drain", json!({ "host": "mini" }), "fleet-offline")
        .expect_err("an offline host must refuse typed");
    let HostToolOperationError::Arguments { detail } = &error else {
        panic!("expected the preflight typed refusal, got {error:?}");
    };
    assert!(
        detail.contains("host mini is offline (last seen 2026-09-28T09:00:00Z)"),
        "the typed offline sentence must travel: {detail}"
    );
    assert!(
        stack.approvals().is_empty(),
        "a refused dispatch must never mint an approval row"
    );
    assert!(route.asks.lock().is_empty());
}

/// An unbound fleet route fails closed for BOTH tools with a typed
/// unavailability.
#[test]
fn fleet_drain_and_restore_fail_closed_when_the_route_is_unbound() {
    let stack = Stack::open_with_fleet(Some(None));
    for (tool, request) in [
        ("fleet_drain", "req-fleet-unbound-1"),
        ("fleet_restore", "req-fleet-unbound-2"),
    ] {
        let error = stack
            .dispatch(tool, json!({ "host": "mini" }), request)
            .expect_err("an unbound route must refuse typed");
        let HostToolOperationError::Arguments { detail } = &error else {
            panic!("expected the unbound typed refusal for {tool}, got {error:?}");
        };
        assert!(
            detail.contains("the fleet drain route is not bound"),
            "the typed unbound sentence must travel for {tool}: {detail}"
        );
    }
}

/// The restore twin: one R2 approval, then the real handler reports the
/// uncordoned, schedulable node; the replay is refused.
#[test]
fn fleet_restore_needs_exactly_one_approval_then_reports_schedulable() {
    let route = ScriptedFleetDrain::worker();
    let stack = Stack::open_with_fleet(Some(Some(route.clone())));
    let arguments = json!({ "host": "mini" });
    let first = stack
        .dispatch("fleet_restore", arguments.clone(), "restore-first")
        .unwrap_err();
    let HostToolOperationError::ApprovalRequired {
        approval_id,
        revision,
        effect_class,
        ..
    } = first
    else {
        panic!("expected the R2 operator approval gate, got {first:?}");
    };
    assert_eq!(effect_class, EffectClass::R2);
    assert_eq!(stack.approvals().len(), 1);
    stack.approve(&approval_id, revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let result = stack
        .dispatch("fleet_restore", retry.clone(), "restore-approved")
        .expect("the approved retry must settle through the real handler");
    assert_eq!(result["host"], json!("mini"));
    assert_eq!(result["node"], json!("mini-node"));
    assert_eq!(result["uncordoned"], json!(true));
    assert_eq!(result["schedulable"], json!(true));
    assert_eq!(route.asks.lock().len(), 1);
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
    assert!(matches!(
        stack.dispatch("fleet_restore", retry, "restore-replay"),
        Err(HostToolOperationError::Rejected(
            odin_kernel::AuthorizationRejection::NeedsApproval { .. }
        ))
    ));
    assert_eq!(route.asks.lock().len(), 1);
}

#[test]
fn desktop_input_types_through_the_desktop_route() {
    let connected = WorkspaceConnection {
        command: "zr mini odin".to_owned(),
        kind: WorkspaceConnectionKind::Zellij,
        host: "mini".to_owned(),
        target: "odin".to_owned(),
    };
    let stack = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Ok(connected),
    })));
    let receipt = stack
        .dispatch(
            "desktop_input",
            json!({ "device": "laptop", "text": "hello", "enter": true }),
            "req-desktop-1",
        )
        .expect("the dispatch settles through the real handler");
    assert_eq!(receipt["status"], json!("typed"));
    assert_eq!(receipt["device"], json!("laptop"));
    assert_eq!(receipt["typed"], json!("hello ⏎"));
    let locked = Stack::open_with_workspace(Some(Arc::new(ScriptedWorkspace {
        outcome: Err("the laptop's screen is locked, so nothing was typed".to_owned()),
    })));
    let error = locked
        .dispatch(
            "desktop_input",
            json!({ "device": "laptop", "text": "hello" }),
            "req-desktop-2",
        )
        .expect_err("a locked screen refuses");
    assert!(error.to_string().contains("screen is locked"), "{error}");
}

#[test]
fn claude_capabilities_refuse_unbound_before_approval_or_effect() {
    let stack = Stack::open();
    for (tool, arguments) in [
        (
            "claude_open",
            json!({"account":"default","project":"household"}),
        ),
        ("claude_prompt", json!({"session":"owned","text":"hello"})),
        ("claude_read", json!({"session":"owned"})),
        ("claude_stop", json!({"session":"owned"})),
    ] {
        let error = stack
            .dispatch(tool, arguments, &format!("req-{tool}-unbound"))
            .expect_err("unbound Claude routes must refuse before effects");
        let HostToolOperationError::Arguments { detail } = error else {
            panic!("expected typed Claude preflight refusal, got {error:?}");
        };
        assert!(
            detail.contains("Claude session route is not bound"),
            "{detail}"
        );
    }
}

/// One reversible batch over the fixture mailbox on the explicit account:
/// a keyword patch, an archive, and a trash move.
fn manage_arguments() -> Value {
    json!({
        "account": ACCOUNT,
        "actions": [
            {"action": "label", "emailId": "email-001", "addLabels": ["$flagged"], "removeLabels": ["$seen"]},
            {"action": "archive", "emailId": "email-002"},
            {"action": "trash", "emailId": "email-003"}
        ]
    })
}

#[test]
fn email_manage_applies_the_reversible_batch_without_an_owner_question() {
    let stack = Stack::open();
    let receipt = stack
        .dispatch("email_manage", manage_arguments(), "manage-first")
        .expect("reversible organization runs without an owner question");
    assert!(stack.approvals().is_empty(), "no owner question");
    assert_eq!(
        receipt["result"]["emailIds"],
        json!(["email-001", "email-002", "email-003"])
    );
    assert_eq!(receipt["replayed"], json!(false));
    let mailbox = |id: &str| stack.send_transport.mailbox.messages.lock()[id].clone();
    assert_eq!(
        mailbox("email-001"),
        json!({ "mailboxIds": { "inbox": true }, "keywords": { "$flagged": true } })
    );
    assert_eq!(
        mailbox("email-002")["mailboxIds"],
        json!({ "archive": true })
    );
    assert_eq!(mailbox("email-003")["mailboxIds"], json!({ "trash": true }));
    assert_eq!(
        *stack.send_transport.lease_scopes.lock(),
        vec![("email.manage".to_owned(), ACCOUNT.to_owned())]
    );
    let intent = stack
        .adapter
        .lock()
        .command(&CommandId::new(receipt["command_id"].as_str().unwrap()).unwrap())
        .unwrap()
        .expect("the durable account intent");
    assert_eq!(intent.capability_id.as_str(), "email.manage");
    assert_eq!(
        intent.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );

    let settled = stack.send_transport.mailbox.messages.lock().clone();
    let retry = stack.dispatch("email_manage", manage_arguments(), "manage-first");
    assert!(
        !matches!(retry, Err(HostToolOperationError::ApprovalRequired { .. })),
        "{retry:?}"
    );
    assert_eq!(*stack.send_transport.mailbox.sets.lock(), 1);
    assert_eq!(*stack.send_transport.mailbox.messages.lock(), settled);
    assert_eq!(stack.send_transport.lease_scopes.lock().len(), 1);
    assert!(stack.approvals().is_empty());
}

/// A fresh request is a fresh explicit action, never a lifetime replay:
/// label, remove the label, then the same label again each really change
/// the mailbox under their own request.
#[test]
fn email_manage_fresh_request_reapplies_after_its_inverse() {
    fn label(add: &[&str], remove: &[&str]) -> Value {
        json!({ "account": ACCOUNT, "actions": [
            {"action": "label", "emailId": "email-002", "addLabels": add, "removeLabels": remove}
        ] })
    }
    let stack = Stack::open();
    for (request, arguments, keywords) in [
        (
            "manage-label",
            label(&["$flagged"], &[]),
            json!({ "$flagged": true }),
        ),
        ("manage-unlabel", label(&[], &["$flagged"]), json!({})),
        (
            "manage-relabel",
            label(&["$flagged"], &[]),
            json!({ "$flagged": true }),
        ),
    ] {
        let receipt = stack
            .dispatch("email_manage", arguments, request)
            .expect("each fresh request applies");
        assert_eq!(receipt["replayed"], json!(false), "{request}");
        let state = stack.send_transport.mailbox.messages.lock()["email-002"].clone();
        assert_eq!(state["keywords"], keywords, "{request}");
    }
    assert_eq!(*stack.send_transport.mailbox.sets.lock(), 3);
    assert!(stack.approvals().is_empty());
}

/// Unbound or irreversible management never reaches the mailbox and never
/// asks the owner: an undeclared account, a permanent delete, a legacy
/// approval selector, and a missing credential all refuse before effect.
#[test]
fn email_manage_refuses_unbound_or_irreversible_work_without_mutation() {
    let stack = Stack::open();
    let before = stack.send_transport.mailbox.messages.lock().clone();
    let mut other_account = manage_arguments();
    other_account["account"] = json!("other-account");
    let mut delete = manage_arguments();
    delete["actions"] = json!([{"action": "delete", "emailId": "email-001"}]);
    let mut legacy = manage_arguments();
    legacy["approvalId"] = json!("approval:legacy");
    for (request, arguments) in [
        ("manage-other-account", other_account),
        ("manage-delete", delete),
        ("manage-legacy-approval", legacy),
    ] {
        let refused = stack.dispatch("email_manage", arguments, request);
        assert!(refused.is_err(), "{request} must refuse: {refused:?}");
    }
    std::fs::remove_file(stack._root.path().join("sinmara-email.secret")).unwrap();
    let missing = stack.dispatch("email_manage", manage_arguments(), "manage-missing-secret");
    assert!(missing.is_err(), "{missing:?}");
    assert!(stack.approvals().is_empty(), "no owner question");
    assert_eq!(*stack.send_transport.mailbox.sets.lock(), 0);
    assert_eq!(*stack.send_transport.mailbox.messages.lock(), before);
    assert!(stack.send_transport.lease_scopes.lock().is_empty());
}

/// A lost provider reply after the patch shipped is honestly in doubt:
/// never a receipt, never an owner question, and the exact retry never
/// patches the mailbox again.
#[test]
fn email_manage_lost_reply_stays_in_doubt_and_never_reapplies() {
    let stack = Stack::open();
    *stack.send_transport.mailbox.lose_reply.lock() = true;
    let first = stack.dispatch("email_manage", manage_arguments(), "manage-lost-reply");
    assert!(
        first.is_err(),
        "an unknowable outcome is no receipt: {first:?}"
    );
    assert!(stack.approvals().is_empty(), "no owner question");
    assert_eq!(*stack.send_transport.mailbox.sets.lock(), 1);
    let intent = stack
        .adapter
        .lock()
        .commands()
        .unwrap()
        .into_iter()
        .find(|command| command.capability_id.as_str() == "email.manage")
        .expect("the durable account intent");
    assert!(intent.accepted_at.is_some() && intent.terminal_status.is_none());

    *stack.send_transport.mailbox.lose_reply.lock() = false;
    let retry = stack.dispatch("email_manage", manage_arguments(), "manage-lost-reply");
    assert!(retry.is_err(), "{retry:?}");
    assert_eq!(*stack.send_transport.mailbox.sets.lock(), 1);
    assert!(stack.approvals().is_empty());
}

// -- purchase.submit: the REAL kernel-dispatched purchase handler ------

/// How the scripted checkout vendor settles an order it actually saw.
#[derive(Clone, Copy)]
enum CheckoutVerdict {
    /// The order was placed; the confirmation page carries this reference.
    Placed(&'static str),
    /// The vendor refused BEFORE the place-order control was touched:
    /// typed pre-effect refusal, nothing was bought.
    Refused,
    /// The place-order step may have landed: honestly unknowable.
    InDoubt,
}

/// Uses production frame decoding and reply helpers, retaining each exchanged frame.
struct ScriptedCheckoutBackend {
    governed_browser: bool,
    verdict: CheckoutVerdict,
    frames: parking_lot::Mutex<Vec<String>>,
    /// When armed with the purchase-ledger path, the instant an order is
    /// answered a second SQLite connection takes the database's real
    /// write lock and holds it, so the handler's terminal record fails
    /// for a genuine persistence reason after the witnessed outcome.
    terminal_fault: parking_lot::Mutex<Option<PathBuf>>,
    write_lock: parking_lot::Mutex<Option<Ledger>>,
}

impl ScriptedCheckoutBackend {
    fn governed_browser(verdict: CheckoutVerdict) -> Arc<Self> {
        Arc::new(Self {
            governed_browser: true,
            verdict,
            frames: parking_lot::Mutex::new(Vec::new()),
            terminal_fault: parking_lot::Mutex::new(None),
            write_lock: parking_lot::Mutex::new(None),
        })
    }

    fn vendor_api(verdict: CheckoutVerdict) -> Arc<Self> {
        Arc::new(Self {
            governed_browser: false,
            verdict,
            frames: parking_lot::Mutex::new(Vec::new()),
            terminal_fault: parking_lot::Mutex::new(None),
            write_lock: parking_lot::Mutex::new(None),
        })
    }

    /// Frames sent to the provider.
    fn exchanged(&self) -> usize {
        self.frames.lock().len()
    }
}

impl crate::purchase::PurchaseFrameExchange for ScriptedCheckoutBackend {
    fn exchange(&self, request_line: String) -> Result<String, crate::purchase::PurchaseFault> {
        self.frames.lock().push(request_line.clone());
        let reply = if self.governed_browser {
            match crate::purchase::CheckoutOrder::from_frame(&request_line) {
                Ok(order) => match self.verdict {
                    CheckoutVerdict::Placed(reference) => {
                        crate::purchase::checkout_reply_placed(&order.request_id, reference)
                    }
                    CheckoutVerdict::Refused => crate::purchase::checkout_reply_refused(
                        Some(&order.request_id),
                        "the checkout page did not show the approved amount",
                    ),
                    CheckoutVerdict::InDoubt => crate::purchase::checkout_reply_uncertain(
                        Some(&order.request_id),
                        "the place-order step may have landed",
                    ),
                },
                Err((id, refusal)) => {
                    crate::purchase::checkout_reply_refused(id.as_deref(), &refusal.to_string())
                }
            }
        } else {
            // A vendor-API backend takes the approved operation as-is.
            let id = serde_json::from_str::<Value>(&request_line)
                .ok()
                .and_then(|frame| frame.get("id").and_then(Value::as_str).map(str::to_owned));
            match (id, self.verdict) {
                (Some(id), CheckoutVerdict::Placed(reference)) => {
                    crate::purchase::checkout_reply_placed(&id, reference)
                }
                _ => crate::purchase::checkout_reply_uncertain(None, "the vendor reply was lost"),
            }
        };
        if let Some(path) = self.terminal_fault.lock().take() {
            let ledger = Ledger::open(&path).expect("the terminal store reopens");
            ledger
                .connection()
                .execute_batch("BEGIN EXCLUSIVE")
                .expect("the terminal-store write lock is taken");
            *self.write_lock.lock() = Some(ledger);
        }
        Ok(reply)
    }
}

/// Vendor-API backends do not require browser checkout plans.
fn vendor_api_purchase_contract() -> crate::purchase::PurchaseAdapterContract {
    let handle = "cred:fixture-vendor-api";
    let wire = json!({
        "schema": "odin.adapter.descriptor.v1",
        "adapter": {
            "adapter_id": crate::purchase::PURCHASE_BACKEND_ADAPTER_ID,
            "version": "1.0.0",
            "binding_digest": odin_domain::Digest::hash(
                b"odin.purchase.fixture-vendor-api.v1"
            ).to_string(),
        },
        "protocol_version": 1,
        "operations": [{
            "kind": crate::purchase::PURCHASE_OPERATION_WIRE_ID,
            "input_schema": "schemas/capability/purchase.submit.input.json",
            "output_schema": "schemas/capability/purchase.submit.output.json",
            "effect_class": "R3",
            "idempotency": "required",
            "evidence": [{
                "kind": "purchase.submit.evidence",
                "schema": "schemas/capability/purchase.submit.output.json",
                "required": true,
            }],
            "credential_handle": handle,
            "taint_after": "credential_tainted",
        }],
        "credential_handles": [handle],
        "initial_taint": "credential_tainted",
    });
    let descriptor = odin_adapter_core::descriptor::AdapterDescriptor::from_wire(&wire)
        .expect("the fixture vendor-api purchase descriptor parses");
    crate::purchase::PurchaseAdapterContract::admit(descriptor)
        .expect("the fixture vendor-api purchase contract admits")
}

/// The model-facing `purchase_submit` arguments for one governed-browser
/// checkout of a USB-C cable, with or without the checkout plan.
fn purchase_arguments(checkout: bool) -> Value {
    let mut arguments = json!({
        "vendor": "Shop",
        "item_description": "USB-C cable",
        "amount": { "currency": "USD", "minor_units": 799 },
    });
    if checkout {
        arguments["checkout"] = json!({
            "product_url": "https://www.shop.example/dp/B0CHEAP",
            "add_to_cart": "#add-to-cart-button",
            "checkout_url": "https://www.shop.example/checkout",
            "place_order": "#place-order",
        });
    }
    arguments
}

/// The durable purchase intent row's id: keyed to the OUTER dispatch
/// command the kernel gate consumed the operator approval into.
fn purchase_intent_id(stack: &Stack, run_request: &str) -> CommandId {
    let correlation = correlation_for(&stack.session, run_request).unwrap();
    CommandId::new(format!("odin.omp.host_tool:{correlation}")).unwrap()
}

/// Reads the durable purchase intent row from the runtime's private
/// purchase ledger.
fn purchase_intent(stack: &Stack, run_request: &str) -> odin_ledger::command::Command {
    let id = purchase_intent_id(stack, run_request);
    stack
        .runtime
        .purchase_ledger
        .lock()
        .unwrap()
        .command(&id)
        .unwrap()
        .unwrap_or_else(|| panic!("the durable purchase intent row for {run_request} exists"))
}

#[test]
fn approved_checkout_purchase_settles_once_through_the_real_handler() {
    let backend =
        ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Placed("fixture-order-799"));
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let arguments = purchase_arguments(true);

    // First dispatch: exactly one owner question, zero provider contact.
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-control-ask")
        .expect_err("the first R3 purchase dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    assert_eq!(stack.approvals().len(), 1);
    assert_eq!(
        backend.exchanged(),
        0,
        "no frame may precede the consumed approval"
    );
    let approved_revision = stack.approve(&approval_id, requested_revision);

    // The approved retry settles through the real handler.
    let mut retry = arguments.clone();
    retry["approvalId"] = json!(approval_id.to_string());
    let receipt = stack
        .dispatch("purchase_submit", retry, "purchase-control-run")
        .expect("the consumed retry must settle through the real purchase handler");
    assert_eq!(receipt["status"], json!("submitted"));
    assert_eq!(receipt["provider_ref"], json!("fixture-order-799"));
    assert_eq!(backend.exchanged(), 1, "exactly one provider frame");

    // The one canonical frame bound the consumed command, the prepared
    // idempotency key, and the approved checkout exactly.
    let frame = backend.frames.lock()[0].clone();
    let order = crate::purchase::CheckoutOrder::from_frame(&frame).expect("the frame is canonical");
    let intent_id = purchase_intent_id(&stack, "purchase-control-run");
    assert_eq!(order.request_id, intent_id.as_str());

    // One consumption, naming the journaled dispatch command.
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
    assert_eq!(approval.consumed_by_command_id.as_ref(), Some(&intent_id));
    assert_eq!(approval.revision, approved_revision + 1);
    assert_eq!(stack.approvals().len(), 1);

    // The durable intent the handler recorded completed terminally with
    // the provider's real receipt.
    let intent = purchase_intent(&stack, "purchase-control-run");
    assert_eq!(
        intent.approval_id.as_ref(),
        Some(&approval_id),
        "the durable effect must name the operator approval actually consumed"
    );
    assert_eq!(intent.capability_id.as_str(), "purchase.submit");
    assert!(intent.accepted_at.is_some());
    assert_eq!(
        intent.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );
    assert_eq!(
        intent
            .terminal_result
            .as_ref()
            .and_then(|result| result["providerRef"].as_str()),
        Some("fixture-order-799"),
        "the durable intent completed with the provider's real receipt"
    );

    // The identical retry never re-exchanges.
    let mut replay = arguments;
    replay["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("purchase_submit", replay, "purchase-control-run")
        .expect_err("a consumed approval must never authorize twice");
    assert_eq!(backend.exchanged(), 1, "the replay must never re-exchange");
}

#[test]
fn governed_browser_purchase_without_a_plan_never_costs_an_owner_question() {
    let backend =
        ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Placed("never-reached"));
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let refused = stack.dispatch(
        "purchase_submit",
        purchase_arguments(false),
        "purchase-noplan-ask",
    );
    assert!(
        refused.is_err(),
        "a plan-less governed-browser purchase must refuse: {refused:?}"
    );
    assert!(
        !matches!(
            refused,
            Err(HostToolOperationError::ApprovalRequired { .. })
        ),
        "the refusal must not be an owner question: {refused:?}"
    );
    assert!(
        stack.approvals().is_empty(),
        "the refusal must precede any owner approval row"
    );
    assert!(
        stack
            .ledger
            .lock()
            .unwrap()
            .commands()
            .unwrap()
            .iter()
            .all(|command| command.capability_id.as_str() != "purchase.submit"),
        "the refusal must precede any journaled purchase intent"
    );
    assert_eq!(
        backend.exchanged(),
        0,
        "the refusal must precede any provider frame"
    );
}

#[test]
fn vendor_api_purchase_without_a_plan_completes_the_real_route() {
    let backend =
        ScriptedCheckoutBackend::vendor_api(CheckoutVerdict::Placed("fixture-vendor-order-1"));
    let stack = Stack::open_with_purchase(vendor_api_purchase_contract(), backend.clone());
    let arguments = purchase_arguments(false);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-vendor-ask")
        .expect_err("a plan-less vendor-API purchase still demands the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    assert_eq!(stack.approvals().len(), 1);
    assert_eq!(backend.exchanged(), 0);
    stack.approve(&approval_id, requested_revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let receipt = stack
        .dispatch("purchase_submit", retry, "purchase-vendor-run")
        .expect("the vendor-API purchase settles through the real handler");
    assert_eq!(receipt["provider_ref"], json!("fixture-vendor-order-1"));
    assert_eq!(backend.exchanged(), 1);
    let intent = purchase_intent(&stack, "purchase-vendor-run");
    assert_eq!(
        intent.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Completed)
    );
    assert!(
        intent.arguments.get("checkout").is_none(),
        "the plan-less request stays plan-less end to end"
    );
}

#[test]
fn an_uncertain_purchase_settlement_stays_reconcilable_and_never_reexchanges() {
    let backend = ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::InDoubt);
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let arguments = purchase_arguments(true);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-doubt-ask")
        .expect_err("the first dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    stack.approve(&approval_id, requested_revision);
    let mut retry = arguments.clone();
    retry["approvalId"] = json!(approval_id.to_string());
    let in_doubt = stack.dispatch("purchase_submit", retry.clone(), "purchase-doubt-run");
    assert!(
        in_doubt.is_err(),
        "an unknowable outcome is no receipt: {in_doubt:?}"
    );
    assert_eq!(
        backend.exchanged(),
        1,
        "exactly one provider frame was witnessed"
    );

    // The durable intent stays accepted and unsettled — reconcilable,
    // never terminally Failed.
    let intent = purchase_intent(&stack, "purchase-doubt-run");
    assert!(
        intent.accepted_at.is_some(),
        "execution durably began before the doubt"
    );
    assert_eq!(
        intent.terminal_status, None,
        "an uncertain purchase must never settle terminally: {intent:?}"
    );

    // The identical replay cannot blindly exchange again.
    let replay = stack.dispatch("purchase_submit", retry, "purchase-doubt-run");
    assert!(
        replay.is_err(),
        "the consumed approval must never authorize a second exchange: {replay:?}"
    );
    assert_eq!(backend.exchanged(), 1, "the replay must never re-exchange");
}

/// A SQLite write lock prevents settlement after a confirmed order, leaving the result uncertain.
#[test]
fn a_terminal_record_fault_after_a_witnessed_order_surfaces_uncertainty() {
    let backend = ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Placed(
        "fixture-order-witnessed",
    ));
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let ledger_path = stack
        .purchase_ledger_path
        .clone()
        .expect("the purchase stack backs its ledger with a real file");
    *backend.terminal_fault.lock() = Some(ledger_path);
    let arguments = purchase_arguments(true);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-fault-ask")
        .expect_err("the first dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    stack.approve(&approval_id, requested_revision);
    let mut retry = arguments.clone();
    retry["approvalId"] = json!(approval_id.to_string());
    let uncertain = stack.dispatch("purchase_submit", retry.clone(), "purchase-fault-run");
    assert!(
        uncertain.is_err(),
        "a witnessed order without its durable terminal record is no success: {uncertain:?}"
    );
    assert_eq!(
        backend.exchanged(),
        1,
        "the order really was witnessed by the backend"
    );

    // Release the real write lock: the durable state is exactly the
    // witnessed-but-unsettled intent, never a terminal record.
    drop(backend.write_lock.lock().take());
    let intent = purchase_intent(&stack, "purchase-fault-run");
    assert_eq!(
        intent.terminal_status, None,
        "no terminal record may exist for a faulted settlement: {intent:?}"
    );

    // The identical replay cannot blindly exchange again either.
    let replay = stack.dispatch("purchase_submit", retry, "purchase-fault-run");
    assert!(
        replay.is_err(),
        "the consumed approval must never authorize a second exchange: {replay:?}"
    );
    assert_eq!(backend.exchanged(), 1, "the replay must never re-exchange");
}

#[test]
fn a_denied_purchase_never_reaches_the_backend_or_records_an_intent() {
    let backend =
        ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Placed("never-reached"));
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let arguments = purchase_arguments(true);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-denied-ask")
        .expect_err("the first dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    // The owner denies with durable evidence.
    let evidence_ref = "ledger://approvals/fixture-denial-evidence";
    {
        let mut guard = stack.ledger.lock().unwrap();
        match ApprovalGate::new(&mut guard)
            .decide(
                &approval_id,
                requested_revision,
                ApprovalDecision::Deny {
                    evidence_ref: evidence_ref.to_owned(),
                },
                "operator:fixture",
                now(),
            )
            .expect("the denial records")
        {
            DecisionOutcome::Denied(evidence) => assert_eq!(evidence.evidence_ref, evidence_ref),
            outcome => panic!("expected a recorded denial, got {outcome:?}"),
        }
    }
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    let refused = stack.dispatch("purchase_submit", retry, "purchase-denied-run");
    assert!(
        refused.is_err(),
        "a denied approval must never authorize a purchase: {refused:?}"
    );
    assert_eq!(
        backend.exchanged(),
        0,
        "a denied purchase never reaches a provider"
    );
    // The authorization-request row may remain, but must not be accepted or settled.
    assert!(
        stack
            .runtime
            .purchase_ledger
            .lock()
            .unwrap()
            .command(&purchase_intent_id(&stack, "purchase-denied-run"))
            .unwrap()
            .map(|row| row.accepted_at.is_none() && row.terminal_status.is_none())
            .unwrap_or(true),
        "a denied purchase never accepts or settles a durable intent"
    );
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Denied);
    assert_eq!(
        approval.consumed_by_command_id, None,
        "a denied approval is never consumed"
    );
    assert_eq!(
        approval.decision_evidence_ref.as_deref(),
        Some(evidence_ref),
        "the durable denial evidence survives the refused retry"
    );
}

/// A pre-effect backend refusal completes the accepted command as Failed without a second exchange.
#[test]
fn a_typed_backend_refusal_after_consumption_stays_exactly_once() {
    let backend = ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Refused);
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let arguments = purchase_arguments(true);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-refused-ask")
        .expect_err("the first dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    stack.approve(&approval_id, requested_revision);
    let mut retry = arguments.clone();
    retry["approvalId"] = json!(approval_id.to_string());
    let refused = stack.dispatch("purchase_submit", retry.clone(), "purchase-refused-run");
    assert!(
        refused.is_err(),
        "a typed pre-effect refusal is never a success: {refused:?}"
    );
    assert_eq!(
        backend.exchanged(),
        1,
        "exactly one frame; the refusal is the typed pre-effect answer"
    );
    // The effect is provably absent: the accepted intent settles Failed
    // with the typed reason (an accepted command completes, never
    // rejects).
    let intent = purchase_intent(&stack, "purchase-refused-run");
    assert_eq!(
        intent.terminal_status,
        Some(odin_ledger::command::CommandTerminalStatus::Failed)
    );
    // The approval was consumed by the refused attempt; the durable row
    // is the evidence — exactly once holds even under refusal.
    let approval = stack.approval(&approval_id);
    assert_eq!(approval.status, odin_domain::ApprovalStatus::Consumed);
    assert_eq!(
        approval.consumed_by_command_id.as_ref(),
        Some(&purchase_intent_id(&stack, "purchase-refused-run"))
    );
    // The identical replay never re-exchanges.
    let replay = stack.dispatch("purchase_submit", retry, "purchase-refused-run");
    assert!(
        replay.is_err(),
        "the consumed approval must never authorize a second exchange: {replay:?}"
    );
    assert_eq!(backend.exchanged(), 1, "the replay must never re-exchange");
}

#[test]
fn a_changed_purchase_never_reuses_a_consumed_approval() {
    let backend =
        ScriptedCheckoutBackend::governed_browser(CheckoutVerdict::Placed("fixture-order-799"));
    let stack = Stack::open_with_purchase(
        crate::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
        backend.clone(),
    );
    let arguments = purchase_arguments(true);
    let (approval_id, requested_revision) = match stack
        .dispatch("purchase_submit", arguments.clone(), "purchase-changed-ask")
        .expect_err("the first dispatch must demand the operator approval")
    {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id, revision),
        other => panic!("expected ApprovalRequired, got {other:?}"),
    };
    stack.approve(&approval_id, requested_revision);
    let mut retry = arguments;
    retry["approvalId"] = json!(approval_id.to_string());
    stack
        .dispatch("purchase_submit", retry, "purchase-changed-run")
        .expect("the original request settles through the real handler");
    assert_eq!(backend.exchanged(), 1);

    // A different amount is a different request: the consumed approval
    // cannot authorize it — the changed dispatch refuses with zero new
    // exchanges and no reminted decision.
    let mut changed = purchase_arguments(true);
    changed["amount"]["minor_units"] = json!(1299);
    changed["approvalId"] = json!(approval_id.to_string());
    let refused = stack.dispatch("purchase_submit", changed, "purchase-changed-other");
    assert!(
        refused.is_err(),
        "a changed request is a new approval scope, never the consumed one: {refused:?}"
    );
    assert_eq!(
        backend.exchanged(),
        1,
        "the changed request must never re-exchange"
    );
    assert_eq!(
        stack.approvals().len(),
        1,
        "the refused changed scope mints no new owner question"
    );
}
