//! Seat delegation through kernel authorization, approval, and GovernedTaskOwner with durable state.
//! Child process control and authority provisioning are scripted; these tests launch no provider.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
// These ledger mutexes are required by the kernel/GovernedTaskOwner APIs;
// fixture-local coordination below uses parking_lot.

use odin_domain::huginn::LiveSessionId;
use odin_domain::knowledge::ToolSchema;
use odin_domain::operation::{EffectState, Limits, RequestCost};
use odin_domain::{
    CommandId, Correlation, Digest, EffectClass, LaneId, PlanId, ProjectId, RunId, SeatId,
    SessionId, SliceId,
};
use odin_hermes::runtime::{hermes_capability_bindings, HermesRuntime};
use odin_kernel::capability::{list_capabilities, InvocationTarget, ToolInvocation};
use odin_kernel::operation::{
    AdmittedCapability, InvokeRequest, OperationAuthority, OperationCatalog,
};
use odin_kernel::policy::{
    arguments_digest, authorize, AuthorizationEnvironment, AuthorizationOutcome, PlanGate,
    PolicyContext,
};
use odin_kernel::token::{
    ExpectedBindings, FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer,
};
use odin_kernel::{
    ApprovalDecision, ApprovalGate, ApprovalScope, CapabilityContract, DecisionOutcome,
    HandlerBinding, NewApproval, SchemaCatalog,
};
use odin_ledger::lane_run::{create_lane, create_run, read_run, NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use odin_omp::host_tools::delegation::{
    ChildAuthorityProvisioner, ChildLifecycleSnapshot, ChildOpen, ChildSessionControl, ChildStop,
    DelegationGovernance, DelegationLinkLedger, GovernedTaskOwner,
};
use odin_omp::host_tools::executor::HostToolExecutor;
use odin_omp::host_tools::{HostToolRegistry, InternalBindingKey};
use odin_omp::live::supervisor::session_id_for;
use odin_types::CapsuleId;
use time::OffsetDateTime;

/// Arbitrary declared seats: NO production seat name appears anywhere in
/// this fixture, proving the shared path is identity-free.
const OWNER_SEAT: &str = "atlas";
const SMITH_SEAT: &str = "hephaestus";
const SKALD_SEAT: &str = "skald";
const OWNER_CONTRACT: &str = "seat.ask.atlas";
const SMITH_CONTRACT: &str = "seat.ask.hephaestus";
const KEY: &[u8] = b"governed-dispatch fixture signing key";
const SLICE: &str = "slice.fixture";

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn seat(seat: &str) -> SeatId {
    SeatId::new(seat).unwrap()
}

fn delegation_contract(id: &str, target: &str) -> CapabilityContract {
    CapabilityContract {
        id: odin_domain::CapabilityId::new(id).unwrap(),
        delegate_to: Some(seat(target)),
        version: 1,
        // One model-visible name per declared contract: two admitted
        // contracts exposing the same tool name would collide on the
        // model surface, so the name derives from the declared target.
        tool_name: odin_domain::knowledge::ToolName::new(format!("declared_ask_{target}")).unwrap(),
        description: format!("Delegate one bounded task to the {target} seat."),
        handler: HandlerBinding::Builtin {
            name: "seat_ask".to_owned(),
        },
        input_schema_ref: "schemas/capability/seat.ask.input.json".to_owned(),
        output_schema_ref: "schemas/capability/seat.ask.output.json".to_owned(),
        effect_class: EffectClass::R3,
        seat_tags: BTreeSet::from(["*".to_owned()]),
        timeout_seconds: NonZeroU32::new(30).unwrap(),
        idempotency: odin_kernel::IdempotencyPolicy::Required,
        retry: odin_kernel::RetryPolicy { max_attempts: 1 },
        approval: odin_kernel::ApprovalRequirement::Operator,
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes_seat_ask_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// The canonical generic input schema the pinned snapshot serves: the
/// host-only reserved target argument is required by the CANONICAL schema —
/// the dispatch layer injects it before the approval hash — while the
/// model-facing projection never declares it.
fn input_schema() -> ToolSchema {
    ToolSchema::from_value(serde_json::json!({
        "type": "object",
        "properties": {
            "_delegate_to": {"type": "string"},
            "project": {"type": "string"},
            "subject": {"type": "string"},
            "question": {"type": "string"},
            "urgency": {"type": "string"},
            "options": {"type": "array"},
            "wait_seconds": {"type": "integer"}
        },
        "required": ["_delegate_to", "project", "subject", "question", "urgency"],
        "additionalProperties": false
    }))
    .unwrap()
}

struct Catalog(BTreeMap<String, AdmittedCapability>);

impl OperationCatalog for Catalog {
    fn admitted(&self, capability: &odin_domain::CapabilityId) -> Option<AdmittedCapability> {
        self.0.get(capability.as_str()).cloned()
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        matches!(
            binding,
            HandlerBinding::Builtin { name } if name == "seat_ask" || name == "odin_hermes_seat_ask_evidence"
        )
    }
}

struct Schemas(ToolSchema);

impl SchemaCatalog for Schemas {
    fn schema(&self, _reference: &str) -> odin_kernel::KernelResult<ToolSchema> {
        Ok(self.0.clone())
    }
}

/// The scripted child control: the supervisor-facing lifecycle seam exactly
/// as production implements it, recorded for assertions.
#[derive(Default)]
struct FixtureControl {
    live: parking_lot::Mutex<BTreeMap<String, bool>>,
    prompts: parking_lot::Mutex<Vec<(String, String)>>,
    fail_prompt: parking_lot::Mutex<bool>,
}

impl FixtureControl {
    fn set_live(&self, child: &LiveSessionId, active: bool) {
        self.live.lock().insert(child.to_string(), active);
    }
}

impl ChildSessionControl for FixtureControl {
    fn snapshot(&self, child: LiveSessionId) -> Result<ChildLifecycleSnapshot, String> {
        let active = self
            .live
            .lock()
            .get(&child.to_string())
            .copied()
            .unwrap_or(false);
        Ok(ChildLifecycleSnapshot {
            active,
            state: None,
            epoch: None,
            settled_since_ms: None,
            quiet_since_ms: None,
            provider_fault: None,
        })
    }

    fn prompt(&self, child: LiveSessionId, message: &str) -> Result<(), String> {
        if std::mem::take(&mut *self.fail_prompt.lock()) {
            return Err("the opened child's prompt channel failed".to_owned());
        }
        self.prompts
            .lock()
            .push((child.to_string(), message.to_owned()));
        Ok(())
    }

    fn stop_child(&self, child: LiveSessionId) -> Result<ChildStop, String> {
        self.set_live(&child, false);
        Ok(ChildStop::Ended)
    }

    fn await_stop(
        &self,
        child: LiveSessionId,
        _budget: std::time::Duration,
    ) -> Result<bool, String> {
        Ok(!self.snapshot(child)?.active)
    }

    fn retire_capsule_on_stop(
        &self,
        _session: LiveSessionId,
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        if std::time::Instant::now() >= deadline {
            return Err("capsule retirement deadline elapsed".to_owned());
        }
        Ok(())
    }

    fn last_answer(
        &self,
        _child: LiveSessionId,
        _epoch: Option<i64>,
    ) -> Result<Option<String>, String> {
        // The fixture keeps no durable child history; honest absence.
        Ok(None)
    }

    fn last_result(
        &self,
        _child: LiveSessionId,
    ) -> Result<Option<odin_omp::host_tools::delegation::TaskResultReport>, String> {
        // The fixture keeps no durable child history; honest typed absence.
        Ok(None)
    }

    fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String> {
        // The fixture keeps no durable ledger; no ended pod sessions.
        Ok(Vec::new())
    }
}

/// The scripted provisioning callback: records every consultation (the
/// exact target seat included) and mirrors the supervisor's durable
/// child-run creation against the shared ledger before returning.
struct FixtureProvisioner {
    cross_seat_targets: parking_lot::Mutex<Vec<String>>,
    same_seat_calls: parking_lot::Mutex<Vec<String>>,
    /// The configured declared-readiness verdict, settable mid-test so the
    /// disappear-after-approval race reproduces: the surface is ready when
    /// the approval is requested and dead when the retry is preflighted.
    readiness: parking_lot::Mutex<Result<(), String>>,
    readiness_observations: parking_lot::Mutex<Vec<String>>,
    ledger: Arc<Mutex<Ledger>>,
    control: Arc<FixtureControl>,
    profiles: BTreeMap<String, (String, String)>,
}

impl FixtureProvisioner {
    fn create_child_run(
        &self,
        parent_lane: &LaneId,
        child: &LiveSessionId,
        child_command: &CommandId,
    ) -> Result<(), String> {
        let child_run = GovernedTaskOwner::child_run_for(child).map_err(|e| e.to_string())?;
        let guard = self
            .ledger
            .lock()
            .map_err(|_| "test ledger poisoned".to_owned())?;
        let attempt: i64 = guard
            .connection()
            .query_row(
                "SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM runs WHERE lane_id = ?1",
                [parent_lane.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        create_run(
            guard.connection(),
            &NewRun {
                run_id: child_run,
                lane_id: parent_lane.clone(),
                attempt_number: attempt,
                workflow_id: Some(format!("live:delegated:{child}")),
                workflow_version: Some(1),
                input_hash: Digest::hash(child_command.as_str().as_bytes()).to_string(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: now(),
            },
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl ChildAuthorityProvisioner for FixtureProvisioner {
    fn provision_child(
        &self,
        _parent_seat: &SeatId,
        parent_lane: &LaneId,
        _parent_session: &SessionId,
        child: ChildOpen<'_>,
    ) -> Result<LiveSessionId, String> {
        let child_command = child.command;
        self.same_seat_calls.lock().push(child_command.to_string());
        let child = session_id_for(child_command).map_err(|e| e.to_string())?;
        self.create_child_run(parent_lane, &child, child_command)?;
        self.control.set_live(&child, true);
        Ok(child)
    }

    fn provision_child_for_seat(
        &self,
        _parent_seat: &SeatId,
        parent_lane: &LaneId,
        _parent_session: &SessionId,
        child: ChildOpen<'_>,
        target_seat: &SeatId,
    ) -> Result<LiveSessionId, String> {
        let child_command = child.command;
        self.cross_seat_targets
            .lock()
            .push(target_seat.as_str().to_owned());
        let child = session_id_for(child_command).map_err(|e| e.to_string())?;
        self.create_child_run(parent_lane, &child, child_command)?;
        self.control.set_live(&child, true);
        Ok(child)
    }

    fn seat_worker_profile(
        &self,
        target_seat: &SeatId,
        requested: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(String, String), String> {
        if let Some(lane) = requested {
            return Ok((lane.provider.clone(), lane.model.clone()));
        }
        self.profiles
            .get(target_seat.as_str())
            .cloned()
            .ok_or_else(|| format!("seat {target_seat} serves no declared launch"))
    }

    /// The scripted readiness observation: records the consultation (the
    /// route's exact target included) and reports the configured verdict.
    /// Touches nothing else — no run row, no control state — mirroring the
    /// read-only contract of the real provisioner.
    fn preflight_child(
        &self,
        _parent_seat: &SeatId,
        _parent_lane: &LaneId,
        _parent_session: &SessionId,
        child_project: &ProjectId,
        target_seat: Option<&SeatId>,
        _launch: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(), String> {
        self.readiness_observations.lock().push(format!(
            "{child_project}|{}",
            target_seat
                .map(|seat| seat.as_str().to_owned())
                .unwrap_or_else(|| "same-seat".to_owned())
        ));
        self.readiness.lock().clone()
    }
}

/// The assembled real stack under test.
struct Stack {
    _root: tempfile::TempDir,
    authority: OperationAuthority,
    executor: Arc<HostToolExecutor>,
    runtime: Arc<HermesRuntime>,
    contracts: BTreeMap<odin_domain::CapabilityId, CapabilityContract>,
    context: PolicyContext,
    schemas: Arc<Schemas>,
    ledger: Arc<Mutex<Ledger>>,
    links: DelegationLinkLedger,
    provisioner: Arc<FixtureProvisioner>,
    fresh: FreshAuthority,
    caller_session: SessionId,
    parent_run: RunId,
}

fn fresh_authority(expected: &ExpectedBindings<'_>) -> FreshAuthority {
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: expected.seat.clone(),
            slice: expected.slice.clone(),
            lane: expected.lane.clone(),
            session: expected.session.clone(),
            seat_revision: expected.seat_revision,
            slice_revision: expected.slice_revision,
            capability_policy_digest: expected.capability_policy_digest,
            context_policy_digest: expected.context_policy_digest,
            issued_at_ms: 0,
            expires_at_ms: 1_000_000,
            entropy: b"governed-dispatch",
        })
        .unwrap();
    FreshAuthority::verify(
        &token,
        ExpectedBindings {
            seat: expected.seat,
            slice: expected.slice,
            lane: expected.lane,
            session: expected.session,
            seat_revision: expected.seat_revision,
            slice_revision: expected.slice_revision,
            capability_policy_digest: expected.capability_policy_digest,
            context_policy_digest: expected.context_policy_digest,
        },
        KEY.to_vec(),
        MemoryRevocations::new(),
        1_000,
    )
    .unwrap()
}

/// Assembles the complete real stack over ONE shared ledger: operation
/// journal, approvals, delegation governance, and child runs.
fn stack() -> Stack {
    let root = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    let links = DelegationLinkLedger::open(root.path().join("links")).unwrap();

    // The parent run exists because the parent bridge created it; the
    // fixture reproduces that durable state through the same public APIs.
    let caller_session = SessionId::new("00000000-0000-4000-8000-0000000000a1").unwrap();
    let parent_run = RunId::new("run:live:00000000-0000-4000-8000-0000000000a0").unwrap();
    let caller_lane = LaneId::new("atlas-household").unwrap();
    {
        let mut guard = ledger.lock().unwrap();
        create_lane(
            guard.connection(),
            &NewLane {
                lane_id: caller_lane.clone(),
                seat_id: seat(OWNER_SEAT),
                project_id: Some(ProjectId::new("household").unwrap()),
                template_id: "template:dev".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator".to_owned(),
                created_at: now(),
                retained: false,
            },
        )
        .unwrap();
        create_run(
            guard.connection(),
            &NewRun {
                run_id: parent_run.clone(),
                lane_id: caller_lane.clone(),
                attempt_number: 1,
                workflow_id: Some("live:fixture".to_owned()),
                workflow_version: Some(1),
                input_hash: "fixture".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: now(),
            },
        )
        .unwrap();
        let plan = guard
            .replace_plan(
                &parent_run,
                "Parent objective",
                &[TodoSpec {
                    id: odin_domain::TodoId::new("todo:parent").unwrap(),
                    title: "Parent todo".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                now(),
            )
            .unwrap();
        guard
            .accept_plan(&parent_run, plan.revision, "operator:fixture", now())
            .unwrap();
    }

    let control = Arc::new(FixtureControl::default());
    let provisioner = Arc::new(FixtureProvisioner {
        cross_seat_targets: parking_lot::Mutex::new(Vec::new()),
        same_seat_calls: parking_lot::Mutex::new(Vec::new()),
        readiness: parking_lot::Mutex::new(Ok(())),
        readiness_observations: parking_lot::Mutex::new(Vec::new()),
        ledger: Arc::clone(&ledger),
        control: Arc::clone(&control),
        profiles: BTreeMap::from([(
            SMITH_SEAT.to_owned(),
            ("gateway".to_owned(), "hephaestus-mini".to_owned()),
        )]),
    });
    let policy_digest = Digest::hash(b"policy");
    let context_digest = Digest::hash(b"context");
    let governance = DelegationGovernance {
        provider: "gateway".to_owned(),
        model: "same-seat-mini".to_owned(),
        max_children_per_session: 2,
        max_prompt_bytes: 8_192,
        approved_projects: BTreeMap::from([
            (
                ProjectId::new("household").unwrap(),
                root.path().join("household"),
            ),
            (ProjectId::new("forge").unwrap(), root.path().join("forge")),
        ]),
        operation_bindings: BTreeMap::from([(
            (seat(OWNER_SEAT), caller_lane.clone()),
            odin_omp::host_tools::operations::SeatOperationPolicy {
                policy: PolicyContext {
                    seat_id: seat(OWNER_SEAT),
                    slice_id: SliceId::new(SLICE).unwrap(),
                    lane_id: caller_lane.clone(),
                    seat_revision: Digest::hash(b"seat"),
                    slice_revision: Digest::hash(b"slice"),
                    capability_policy_digest: policy_digest,
                    seat_tool_refs: BTreeSet::new(),
                    slice_capabilities: BTreeSet::new(),
                    project_capabilities: BTreeSet::new(),
                    lane_capabilities: BTreeSet::new(),
                    denied_capabilities: BTreeSet::new(),
                    denied_tools: BTreeSet::new(),
                    seat_categories: BTreeSet::from(["coordinator".to_owned()]),
                    adapter_health: Default::default(),
                    resource_constraints: BTreeMap::new(),
                    seat_hints: BTreeMap::new(),
                },
                context_policy_digest: context_digest,
            },
        )]),
    };
    let owner = GovernedTaskOwner::new(
        Arc::clone(&provisioner) as Arc<dyn ChildAuthorityProvisioner>,
        Arc::clone(&control) as Arc<dyn ChildSessionControl>,
        links.clone(),
        Arc::clone(&ledger),
        governance,
    );

    // The Hermes runtime composes the REAL governed owner as its sole
    // delegation authority, with the arbitrary declared contracts as data.
    let contracts: BTreeMap<odin_domain::CapabilityId, CapabilityContract> = [
        delegation_contract(OWNER_CONTRACT, OWNER_SEAT),
        delegation_contract(SMITH_CONTRACT, SMITH_SEAT),
    ]
    .into_iter()
    .map(|contract| (contract.id.clone(), contract))
    .collect();
    let settings = odin_hermes::config::HermesSettings::new(
        root.path().join("state"),
        None,
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let runtime = HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::new(parking_lot::Mutex::new(Ledger::open_in_memory().unwrap())),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        Some(Arc::new(owner)),
        8_192,
        BTreeMap::from([
            (
                seat(OWNER_SEAT),
                BTreeSet::from([ProjectId::new("household").unwrap()]),
            ),
            (
                seat(SMITH_SEAT),
                BTreeSet::from([
                    ProjectId::new("forge").unwrap(),
                    ProjectId::new("odin").unwrap(),
                ]),
            ),
        ]),
        None,
    )
    .unwrap();

    // The kernel operation stack: real catalog, real schemas, and the real
    // host executor over the runtime's registered generic bindings.
    let admitted = contracts
        .iter()
        .map(|(id, contract)| {
            (
                id.as_str().to_owned(),
                AdmittedCapability {
                    contract: contract.clone(),
                    snapshot_revision: 1,
                    snapshot_digest: policy_digest,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let catalog = Arc::new(Catalog(admitted));
    let schemas: Arc<Schemas> = Arc::new(Schemas(input_schema()));
    let registry = Arc::new({
        let mut registry = HostToolRegistry::new();
        for (id, tool) in hermes_capability_bindings(&runtime) {
            registry
                .register_internal(InternalBindingKey::Builtin(id.to_owned()), tool)
                .unwrap();
        }
        registry
    });
    let executor = Arc::new(HostToolExecutor::new(Arc::clone(&registry)));
    let clock_ms = Arc::new(std::sync::atomic::AtomicU64::new(1_000));
    let clock_clone = Arc::clone(&clock_ms);
    let authority = OperationAuthority::new(
        catalog,
        Arc::clone(&schemas) as Arc<dyn SchemaCatalog + Send + Sync>,
        Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
        Limits::new(10, 10, 10_000),
        Arc::new(move || clock_clone.load(std::sync::atomic::Ordering::SeqCst)),
        Arc::clone(&ledger),
    );

    let allowed: BTreeSet<odin_domain::CapabilityId> = contracts.keys().cloned().collect();
    let context = PolicyContext {
        seat_id: seat(OWNER_SEAT),
        slice_id: SliceId::new(SLICE).unwrap(),
        lane_id: caller_lane.clone(),
        seat_revision: Digest::hash(b"seat"),
        slice_revision: Digest::hash(b"slice"),
        capability_policy_digest: policy_digest,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        seat_categories: BTreeSet::from(["coordinator".to_owned()]),
        adapter_health: odin_kernel::AdapterHealth::default(),
        resource_constraints: BTreeMap::new(),
        seat_hints: BTreeMap::new(),
    };
    let bindings = ExpectedBindings {
        seat: &context.seat_id,
        slice: &context.slice_id,
        lane: &context.lane_id,
        session: &caller_session,
        seat_revision: context.seat_revision,
        slice_revision: context.slice_revision,
        capability_policy_digest: context.capability_policy_digest,
        context_policy_digest: context_digest,
    };
    let fresh = fresh_authority(&bindings);

    Stack {
        _root: root,
        authority,
        executor,
        runtime,
        schemas,
        ledger,
        links,
        contracts,
        context,
        provisioner,
        fresh,
        caller_session,
        parent_run,
    }
}

/// The journaled arguments exactly as the governed preparation produces
/// them: the host-injected reserved target argument present.
fn journaled_arguments(contract: &CapabilityContract, project: &str) -> serde_json::Value {
    let mut arguments = serde_json::json!({
        "project": project,
        "subject": "Read-only check",
        "question": "Inspect and report; do not modify anything.",
        "urgency": "medium",
    });
    arguments[CapabilityContract::DELEGATION_TARGET_ARGUMENT] = serde_json::json!(contract
        .delegate_to
        .as_ref()
        .map(|target| target.as_str())
        .unwrap_or_default());
    arguments
}

fn scope_binding(stack: &Stack) -> serde_json::Value {
    let scope = odin_domain::Scope {
        seat: Some(seat(OWNER_SEAT)),
        lane: Some(LaneId::new("atlas-household").unwrap()),
        run: Some(stack.parent_run.clone()),
        session: Some(stack.caller_session.clone()),
        ..odin_domain::Scope::default()
    };
    serde_json::json!({"scope": scope, "execution": null})
}

/// Runs the REAL authorization + approval + consumed-dispatch cycle for one
/// correlation: first dispatch refuses with NeedsApproval and consumes
/// nothing; the operator's decision through the REAL kernel gate is what
/// the retry consumes; the settled result is the handler's real receipt.
fn authorize_approve_dispatch(
    stack: &Stack,
    capability: &str,
    arguments: &serde_json::Value,
    correlation_tag: &str,
) -> Result<serde_json::Value, odin_kernel::operation::OperationRejection> {
    let now_ms = 1_000u64;
    let contract = &stack.contracts[&odin_domain::CapabilityId::new(capability).unwrap()];
    let listing = list_capabilities(
        stack.fresh.get(),
        &stack.context,
        &stack.contracts,
        stack.schemas.as_ref(),
        now_ms,
    )
    .unwrap();
    let scope = ApprovalScope {
        target_kind: "run".to_owned(),
        target_id: stack.parent_run.as_str().to_owned(),
        capability_id: contract.id.clone(),
        arguments_digest: arguments_digest(arguments),
    };

    // The first dispatch carries no approval: the gate redirects and the
    // real authorization pass consumes nothing and records nothing.
    let first = ToolInvocation {
        command_id: CommandId::new(format!("command:{correlation_tag}")).unwrap(),
        capability_id: contract.id.clone(),
        capability_version: contract.version,
        listing_digest: listing.digest,
        arguments: arguments.clone(),
        arguments_digest: arguments_digest(arguments),
        target: InvocationTarget {
            kind: "run".to_owned(),
            id: stack.parent_run.as_str().to_owned(),
        },
        executor_binding: Some(scope_binding(stack)),
        expected_revision: None,
        plan_id: Some(PlanId::new("plan:fixture").unwrap()),
        approval_id: None,
        resource: None,
    };
    let rejection = {
        let mut guard = stack.ledger.lock().unwrap();
        let outcome = authorize(
            AuthorizationEnvironment {
                authority: stack.fresh.get(),
                policy: &stack.context,
                contracts: &stack.contracts,
                schemas: stack.schemas.as_ref(),
                listing: &listing,
            },
            &first,
            PlanGate::Accepted,
            &mut ApprovalGate::new(&mut guard),
            now_ms,
        )
        .unwrap();
        match outcome {
            AuthorizationOutcome::Authorized(_) => {
                panic!("an R3 dispatch without an approval must never authorize")
            }
            AuthorizationOutcome::Rejected(rejection) => rejection,
        }
    };
    assert!(
        format!("{rejection:?}").contains("NeedsApproval"),
        "the first dispatch must demand the operator approval, got {rejection:?}"
    );

    // Decide through the kernel gate before retrying the request.
    let (approval_id, requested_revision) = {
        let mut guard = stack.ledger.lock().unwrap();
        let requested = guard
            .request_approval(NewApproval {
                approval_id: odin_domain::ApprovalId::new(format!("approval:{correlation_tag}"))
                    .unwrap(),
                issuer: "operator:fixture".to_owned(),
                scope,
                requested_at: now(),
                expires_at: now() + time::Duration::hours(1),
            })
            .unwrap();
        (requested.approval_id, requested.revision)
    };
    let approved = {
        let mut guard = stack.ledger.lock().unwrap();
        match ApprovalGate::new(&mut guard)
            .decide(
                &approval_id,
                requested_revision,
                ApprovalDecision::Approve { evidence_ref: None },
                "operator:fixture",
                now(),
            )
            .unwrap()
        {
            DecisionOutcome::Approved(approval) => approval,
            other => panic!("the operator approval must settle, got {other:?}"),
        }
    };

    let retry = ToolInvocation {
        approval_id: Some(approved.approval_id.clone()),
        expected_revision: Some(approved.revision),
        command_id: CommandId::new(format!("command:{correlation_tag}:retry")).unwrap(),
        capability_id: contract.id.clone(),
        capability_version: contract.version,
        listing_digest: listing.digest,
        arguments: arguments.clone(),
        arguments_digest: arguments_digest(arguments),
        target: InvocationTarget {
            kind: "run".to_owned(),
            id: stack.parent_run.as_str().to_owned(),
        },
        executor_binding: Some(scope_binding(stack)),
        plan_id: Some(PlanId::new("plan:fixture").unwrap()),
        resource: None,
    };
    let authorized = {
        let mut guard = stack.ledger.lock().unwrap();
        // Approval consumption references the same durable command journal
        // that the production host-operation path writes before authorization.
        guard
            .record_command(&odin_ledger::command::CommandSpec {
                id: retry.command_id.clone(),
                idempotency_key: retry.command_id.to_string(),
                correlation_id: correlation_tag.to_owned(),
                causation_id: None,
                issuer: stack.fresh.get().seat().as_str().to_owned(),
                approval_id: retry.approval_id.clone(),
                target_kind: retry.target.kind.clone(),
                target_id: retry.target.id.clone(),
                capability_id: retry.capability_id.clone(),
                capability_version: i64::from(retry.capability_version),
                arguments_hash: retry.arguments_digest,
                arguments: retry.arguments.clone(),
                expected_desired_revision: retry.expected_revision,
                issued_at: time::OffsetDateTime::from_unix_timestamp_nanos(
                    i128::from(now_ms) * 1_000_000,
                )
                .unwrap(),
                expires_at: time::OffsetDateTime::from_unix_timestamp_nanos(
                    i128::from(stack.fresh.get().expires_at_ms()) * 1_000_000,
                )
                .unwrap(),
            })
            .unwrap();
        match authorize(
            AuthorizationEnvironment {
                authority: stack.fresh.get(),
                policy: &stack.context,
                contracts: &stack.contracts,
                schemas: stack.schemas.as_ref(),
                listing: &listing,
            },
            &retry,
            PlanGate::Accepted,
            &mut ApprovalGate::new(&mut guard),
            now_ms,
        )
        .unwrap()
        {
            AuthorizationOutcome::Authorized(authorized) => *authorized,
            AuthorizationOutcome::Rejected(rejection) => {
                panic!("the approved dispatch must authorize, got {rejection:?}")
            }
        }
    };
    let correlation = Correlation::new(format!("dispatch:{correlation_tag}"))
        .unwrap()
        .idempotency_key;
    let correlation_id = odin_types::CorrelationId::new(&hex_correlation(&correlation)).unwrap();
    let decision = stack.authority.invoke_authorized(
        authorized,
        &InvokeRequest {
            capsule_id: CapsuleId::new("capsule:fixture").unwrap(),
            correlation_id: correlation_id.clone(),
            requested_ceiling: RequestCost {
                requests: 1,
                stops: 0,
                spend: 0,
            },
        },
    )?;
    assert_eq!(
        decision.state,
        EffectState::Committed,
        "the consumed dispatch must commit"
    );
    Ok(stack
        .executor
        .take_result(&correlation_id)
        .expect("the handler's real receipt is relayed"))
}

/// Derives a 32-lowercase-hex correlation identity from the idempotency key.
fn hex_correlation(key: &str) -> String {
    let hex = Digest::hash(key.as_bytes()).to_string();
    hex[7..39].to_owned()
}

#[test]
fn arbitrary_declared_targets_reach_the_governed_owner_through_real_dispatch() {
    let stack = stack();

    // A cross-seat ask from the owner seat to the arbitrary smith seat.
    let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
    let receipt = authorize_approve_dispatch(
        &stack,
        SMITH_CONTRACT,
        &journaled_arguments(contract, "forge"),
        "smith-ask",
    )
    .unwrap();
    assert_eq!(receipt["status"], "recorded", "receipt: {receipt}");
    assert_eq!(receipt["target_seat"], SMITH_SEAT);
    assert_eq!(receipt["model"], "hephaestus-mini");
    assert_eq!(receipt["plan_accepted"], true);

    let children = stack.links.children_of(&stack.caller_session).unwrap();
    assert_eq!(children.len(), 1, "exactly one durable delegation link");
    let link = &children[0];
    assert_eq!(link.parent, stack.caller_session);
    assert_eq!(link.depth, 1);
    assert_eq!(link.project.as_str(), "forge");
    assert_eq!(link.model, "hephaestus-mini");
    let child_run = link.child_run.clone();
    {
        let guard = stack.ledger.lock().unwrap();
        assert!(
            read_run(guard.connection(), &child_run).unwrap().is_some(),
            "the child bridge run must be durable"
        );
        assert!(
            guard.plan_is_accepted(&child_run).unwrap(),
            "the child plan must be durably inherited-accepted"
        );
    }

    // The declared OWNER seat's own ask rides the SAME path on the
    // same-seat route: the governed owner's own provider/model, no
    // cross-seat consultation.
    let owner_contract = &stack.contracts[&odin_domain::CapabilityId::new(OWNER_CONTRACT).unwrap()];
    let receipt = authorize_approve_dispatch(
        &stack,
        OWNER_CONTRACT,
        &journaled_arguments(owner_contract, "household"),
        "owner-ask",
    )
    .unwrap();
    assert_eq!(receipt["target_seat"], OWNER_SEAT);
    assert_eq!(receipt["model"], "same-seat-mini");
    assert_eq!(
        stack
            .links
            .children_of(&stack.caller_session)
            .unwrap()
            .len(),
        2
    );
}

/// The mismatch wall: journaled arguments naming a DIFFERENT target than
/// the admitted contract's declared delegate_to refuse at the REAL kernel
/// authorization — before any approval is requested or consumed — so no
/// delegation link, child run, or provisioning call can exist.
#[test]
fn mismatched_target_never_reaches_the_governed_owner() {
    let stack = stack();
    let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
    let listing = list_capabilities(
        stack.fresh.get(),
        &stack.context,
        &stack.contracts,
        stack.schemas.as_ref(),
        1_000,
    )
    .unwrap();
    let mut drifted = journaled_arguments(contract, "forge");
    drifted[CapabilityContract::DELEGATION_TARGET_ARGUMENT] = serde_json::json!(SKALD_SEAT);
    let invocation = ToolInvocation {
        command_id: CommandId::new("command:drift").unwrap(),
        capability_id: contract.id.clone(),
        capability_version: contract.version,
        listing_digest: listing.digest,
        arguments: drifted.clone(),
        arguments_digest: arguments_digest(&drifted),
        target: InvocationTarget {
            kind: "run".to_owned(),
            id: stack.parent_run.as_str().to_owned(),
        },
        executor_binding: Some(scope_binding(&stack)),
        expected_revision: None,
        plan_id: Some(PlanId::new("plan:fixture").unwrap()),
        approval_id: None,
        resource: None,
    };
    let outcome = {
        let mut guard = stack.ledger.lock().unwrap();
        authorize(
            AuthorizationEnvironment {
                authority: stack.fresh.get(),
                policy: &stack.context,
                contracts: &stack.contracts,
                schemas: stack.schemas.as_ref(),
                listing: &listing,
            },
            &invocation,
            PlanGate::Accepted,
            &mut ApprovalGate::new(&mut guard),
            1_000,
        )
        .unwrap()
    };
    assert!(matches!(
        outcome,
        AuthorizationOutcome::Rejected(odin_kernel::AuthorizationRejection::ResourceDenied { .. })
    ));
    assert!(
        stack.ledger.lock().unwrap().approvals().unwrap().is_empty(),
        "the drifted dispatch consumed no approval"
    );
    assert!(
        stack
            .links
            .children_of(&stack.caller_session)
            .unwrap()
            .is_empty(),
        "a drifted target must create no child link"
    );
    assert!(
        stack.provisioner.cross_seat_targets.lock().is_empty(),
        "a drifted target must never reach provisioning"
    );
}

#[test]
fn post_open_prompt_failure_remains_a_durable_uncertain_effect() {
    let stack = stack();
    *stack.provisioner.control.fail_prompt.lock() = true;
    let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
    let outcome = authorize_approve_dispatch(
        &stack,
        SMITH_CONTRACT,
        &journaled_arguments(contract, "forge"),
        "prompt-failure",
    );
    assert!(matches!(
        outcome,
        Err(odin_kernel::operation::OperationRejection::Executor(
            odin_kernel::operation::ExecutorFault::Uncertain { .. }
        ))
    ));
    let correlation = Correlation::new("dispatch:prompt-failure")
        .unwrap()
        .idempotency_key;
    let correlation_id = hex_correlation(&correlation);
    let guard = stack.ledger.lock().unwrap();
    let row = odin_ledger::operation::operation_row(guard.connection(), &correlation_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.effect_state, EffectState::InDoubt);
    assert_eq!(
        stack
            .links
            .children_of(&stack.caller_session)
            .unwrap()
            .len(),
        1
    );
}

/// Missing declared surfaces must fail preflight before approval or provisioning, including on retry.
#[cfg(test)]
mod readiness_preflight {
    use super::*;
    use odin_domain::Scope;
    use odin_hermes::runtime::hermes_host_tools;
    use odin_omp::host_tools::HostTool;

    fn seat_ask_binding(runtime: &Arc<HermesRuntime>) -> Arc<dyn HostTool> {
        hermes_capability_bindings(runtime)
            .into_iter()
            .find(|(id, _)| *id == "seat_ask")
            .map(|(_, tool)| tool)
            .expect("the generic seat_ask binding is registered")
    }

    fn scope(stack: &Stack) -> Scope {
        Scope {
            seat: Some(stack.context.seat_id.clone()),
            project: None,
            lane: Some(stack.context.lane_id.clone()),
            run: Some(stack.parent_run.clone()),
            attempt: None,
            session: Some(stack.caller_session.clone()),
            node: None,
        }
    }

    /// Incident class (d5): the runtime's readiness observation refuses
    /// with the exact missing-surface detail; the gate is pre-effect — no
    /// link row, no provision consultation, no child.
    #[test]
    fn seat_ask_preflight_refuses_missing_surface_before_any_effect() {
        let stack = stack();
        *stack.provisioner.readiness.lock() =
            Err("zellij_session brain-m6b was not found".to_owned());
        let binding = seat_ask_binding(&stack.runtime);
        let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
        let error = binding
            .preflight(
                contract,
                &scope(&stack),
                &journaled_arguments(contract, "forge"),
            )
            .expect_err("a dead declared surface refuses at preflight");
        match error {
            odin_omp::host_tools::HostToolError::Delegation { detail, .. } => assert!(
                detail.contains("surface_unavailable"),
                "the gate surfaces the typed readiness refusal: {detail}"
            ),
            other => panic!("expected the typed delegation refusal, got {other:?}"),
        }
        assert!(
            stack
                .links
                .children_of(&stack.caller_session)
                .unwrap()
                .is_empty(),
            "no delegation link exists off a refused preflight"
        );
        assert!(
            stack.provisioner.same_seat_calls.lock().is_empty()
                && stack.provisioner.cross_seat_targets.lock().is_empty(),
            "no provisioning consultation ran"
        );
        assert!(
            !stack.provisioner.readiness_observations.lock().is_empty(),
            "the readiness observation ran, naming the declared route"
        );
    }

    /// The race the incident exposed: ready at request time, dead at the
    /// approved retry — the rerun gate refuses read-only, so the approved
    /// row would remain unspent and no child or effect exists.
    #[test]
    fn seat_ask_preflight_rerun_refuses_when_the_surface_disappears() {
        let stack = stack();
        let binding = seat_ask_binding(&stack.runtime);
        let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
        let arguments = journaled_arguments(contract, "forge");
        binding
            .preflight(contract, &scope(&stack), &arguments)
            .expect("the surface is ready when the approval is requested");
        *stack.provisioner.readiness.lock() =
            Err("zellij_session brain-m6b was not found".to_owned());
        let error = binding
            .preflight(contract, &scope(&stack), &arguments)
            .expect_err("the approved retry's preflight refuses on the dead surface");
        assert!(
            format!("{error:?}").contains("surface_unavailable"),
            "unexpected refusal: {error:?}"
        );
        assert!(
            stack
                .links
                .children_of(&stack.caller_session)
                .unwrap()
                .is_empty(),
            "no link row exists for the refused retry"
        );
        assert!(
            stack.provisioner.same_seat_calls.lock().is_empty()
                && stack.provisioner.cross_seat_targets.lock().is_empty(),
            "no provisioning act consumed the retry"
        );
    }

    /// The contract supplies the target, and preflight performs no child creation.
    #[test]
    fn model_surface_preflight_binds_the_contract_target_and_executes_once() {
        let stack = stack();
        let model_tool = hermes_host_tools(&stack.runtime)
            .into_iter()
            .find(|tool| {
                tool.definition().name.as_ref()
                    == stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()]
                        .tool_name
                        .as_str()
            })
            .expect("the per-contract model tool is listed");
        let contract = &stack.contracts[&odin_domain::CapabilityId::new(SMITH_CONTRACT).unwrap()];
        // Model arguments carry NO host-injected target.
        let model_arguments = serde_json::json!({
            "project": "forge",
            "subject": "Hammer the hinge",
            "question": "Reply with pong",
            "urgency": "low",
        });
        model_tool
            .preflight(contract, &scope(&stack), &model_arguments)
            .expect("the declared target's ready surface passes");
        assert!(
            stack
                .links
                .children_of(&stack.caller_session)
                .unwrap()
                .is_empty(),
            "a passing preflight still creates nothing"
        );
        let receipt = authorize_approve_dispatch(
            &stack,
            SMITH_CONTRACT,
            &journaled_arguments(contract, "forge"),
            "smith-ask-preflight",
        )
        .unwrap();
        assert_eq!(receipt["status"], "recorded");
        assert_eq!(
            stack
                .links
                .children_of(&stack.caller_session)
                .unwrap()
                .len(),
            1,
            "the ready target follows the normal single-consume execution"
        );
    }
}
