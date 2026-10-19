//! Shared operation fixtures use the authorization pipeline, an in-memory executor,
//! reentrant retries, and a mutable clock.

use super::model::{charged_invocation, utc};
use super::*;

use crate::approval::ApprovalGate;
use crate::capability::{
    list_capabilities, AuthorizedInvocation, CapabilityContract, HandlerBinding, InvocationTarget,
    SchemaCatalog,
};
use crate::token::{FreshAuthority, MemoryRevocations, MintRequest, RevocationStore, TokenIssuer};

use odin_domain::knowledge::ToolSchema;
use odin_domain::operation::{EffectState, RequestCost};
use odin_domain::{
    CapabilityId, CommandId, Digest, EffectClass, LaneId, PlanId, SeatId, SessionId, SliceId,
};
use odin_ledger::operation as store;
use odin_ledger::LedgerError;
use odin_types::{CapsuleId, CorrelationId, OperationId};

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

mod child;
mod close;
mod invoke;
mod lease;
mod lifecycle;
mod midflight;
mod stop;
mod uncertainty;

const CAPABILITY: &str = "tool.write";
const CAPSULE: &str = "capsule-test";
const KEY: &[u8] = b"test signing key";

fn contract() -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new(CAPABILITY).unwrap(),
        delegate_to: None,
        version: 3,
        tool_name: odin_domain::knowledge::ToolName::new("tool_write").unwrap(),
        description: "write".to_owned(),
        handler: HandlerBinding::Builtin {
            name: "write".to_owned(),
        },
        input_schema_ref: "schemas/capability/t.in.json".to_owned(),
        output_schema_ref: "schemas/capability/t.out.json".to_owned(),
        effect_class: EffectClass::R1,
        seat_tags: BTreeSet::from(["builder".to_owned()]),
        timeout_seconds: NonZeroU32::new(5).unwrap(),
        idempotency: crate::capability::IdempotencyPolicy::Required,
        retry: crate::capability::RetryPolicy { max_attempts: 1 },
        approval: crate::capability::ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: "write_evidence".to_owned(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// Keep captured evidence distinct from the predicted post-world hash.
fn receipt_digest(content: &str) -> Digest {
    Digest::hash(format!("receipt:{content}").as_bytes())
}

#[derive(Default)]
struct World {
    files: Mutex<BTreeMap<String, String>>,
    executions: AtomicU64,
    uncertain: AtomicBool,
    // Simulate uncertainty after writing output and capturing its evidence.
    post_effect_uncertain: AtomicBool,
}

struct Executor(Arc<World>);

impl OperationExecutor for Executor {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
    }
    fn declared_pre_world(
        &self,
        _contract: &CapabilityContract,
        _payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        Ok(Some(PreWorld::Absent))
    }

    fn observe(
        &self,
        _contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        let path = payload
            .arguments
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or_default();
        Ok(self
            .0
            .files
            .lock()
            .unwrap()
            .get(path)
            .map(|content| PreWorld::Digest(Digest::hash(content.as_bytes())))
            .unwrap_or(PreWorld::Absent))
    }

    fn expected_post_world(
        &self,
        _contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        let content = payload
            .arguments
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        Ok(Some(Digest::hash(content.as_bytes())))
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        self.0.executions.fetch_add(1, Ordering::SeqCst);
        if self.0.uncertain.load(Ordering::SeqCst) {
            return Err(ExecutorFault::Uncertain {
                detail: "executor died".to_owned(),
            });
        }
        let path = effect
            .payload()
            .arguments
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or_default()
            .to_owned();
        let content = effect
            .payload()
            .arguments
            .get("content")
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_owned();
        let captured = receipt_digest(&content);
        self.0.files.lock().unwrap().insert(path.clone(), content);
        if self.0.post_effect_uncertain.load(Ordering::SeqCst) {
            // Preserve the captured evidence when reporting failure after the effect.
            return Err(ExecutorFault::PostEffectUncertain {
                detail: "response interrupted after the effect landed".to_owned(),
                evidence_digest: captured,
            });
        }
        let post = self
            .0
            .files
            .lock()
            .unwrap()
            .get(&path)
            .map(|content| Digest::hash(content.as_bytes()));
        Ok(EffectOutcome {
            post_world: post,
            evidence_digest: captured,
            stop: None,
        })
    }
}

/// Mutations injected while observation runs without the ledger lock.
enum Race {
    /// Concurrently settle every in-flight row: the exact CAS another
    /// authority's dispatch or reconcile would apply.
    SettleAborted,
    /// Concurrently move every effect-started row to in-doubt, the
    /// exact CAS `recover()` applies after a restart.
    MarkInDoubt,
}

/// Use try_lock to detect a held ledger lock without hanging;
/// Race injects a mutation during observation.
struct ReenteringExecutor {
    inner: Executor,
    ledger: Arc<Mutex<Ledger>>,
    reentries: AtomicU64,
    blocked: AtomicU64,
    race: Mutex<Option<Race>>,
}

impl ReenteringExecutor {
    fn new(world: Arc<World>, ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            inner: Executor(world),
            ledger,
            reentries: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            race: Mutex::new(None),
        }
    }

    fn observe_probe(&self) {
        match self.ledger.try_lock() {
            Ok(mut ledger) => {
                let in_flight = store::nonterminal_rows(ledger.connection(), None)
                    .expect("reentrant ledger read succeeds");
                self.reentries.fetch_add(1, Ordering::SeqCst);
                if let Some(race) = self
                    .race
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take()
                {
                    let now = utc(20).unwrap();
                    for row in &in_flight {
                        let to = match race {
                            Race::SettleAborted => EffectState::Aborted,
                            Race::MarkInDoubt => EffectState::InDoubt,
                        };
                        ledger
                            .with_tx(|tx| {
                                store::transition_operation(
                                    tx,
                                    &row.correlation_id,
                                    row.effect_state,
                                    to,
                                    None,
                                    now,
                                )
                            })
                            .expect("concurrent mutation applies");
                    }
                }
            }
            Err(_) => {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

impl OperationExecutor for ReenteringExecutor {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
    }

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        self.inner.declared_pre_world(contract, payload)
    }

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        self.observe_probe();
        self.inner.observe(contract, payload)
    }

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        self.inner.expected_post_world(contract, payload)
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        self.inner.execute(effect)
    }
}

/// Replay during dispatch; a weak authority reference avoids an executor-reference cycle.
struct MidflightRetryExecutor {
    inner: Executor,
    authority: Mutex<Option<Weak<OperationAuthority>>>,
    retry: Mutex<Option<RetryInputs>>,
    retry_verdict: Mutex<Option<Result<OperationDecision, String>>>,
    before_start: std::sync::OnceLock<(Arc<Mutex<Ledger>>, CorrelationId)>,
}

impl MidflightRetryExecutor {
    fn new(world: Arc<World>) -> Self {
        Self {
            inner: Executor(world),
            authority: Mutex::new(None),
            retry: Mutex::new(None),
            retry_verdict: Mutex::new(None),
            before_start: std::sync::OnceLock::new(),
        }
    }

    fn arm(
        &self,
        authority: &Arc<OperationAuthority>,
        fixture: &Fixture,
        arguments: &serde_json::Value,
    ) {
        let mut armed = self
            .authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *armed = Some(Arc::downgrade(authority));
        drop(armed);
        *self
            .retry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(RetryInputs {
            arguments: arguments.clone(),
            contracts: fixture.contracts.clone(),
            context: fixture.context.clone(),
            schemas: Arc::clone(&fixture.schemas),
        });
    }

    fn take_retry_verdict(&self) -> Option<Result<OperationDecision, String>> {
        self.retry_verdict
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
    fn retry_prepared(&self) -> Result<(), String> {
        let Some((ledger, correlation)) = self.before_start.get() else {
            return Ok(());
        };
        let prepared = match ledger.try_lock() {
            Ok(ledger) => store::operation_row(ledger.connection(), correlation.as_str())
                .map_err(|error| error.to_string())?
                .is_some_and(|row| row.effect_state == EffectState::Prepared),
            Err(std::sync::TryLockError::WouldBlock) => false,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("the private retry ledger is poisoned".into());
            }
        };
        if prepared {
            self.retry_once(correlation);
        }
        Ok(())
    }

    fn retry_once(&self, correlation: &CorrelationId) {
        let authority = self
            .authority
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(authority) = authority {
            let inputs = self
                .retry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(inputs) = inputs {
                let verdict = authority.invoke_authorized(
                    authorize_invocation(
                        fresh_proof(30),
                        &inputs.arguments,
                        30,
                        "command.one",
                        &inputs.contracts,
                        &inputs.context,
                        inputs.schemas.as_ref(),
                    ),
                    &invoke_request(correlation, 1),
                );
                *self
                    .retry_verdict
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    Some(verdict.map_err(|rejection| format!("{rejection:?}")));
            }
        }
    }
}

impl OperationExecutor for MidflightRetryExecutor {
    fn id(&self) -> &'static str {
        self.retry_prepared().expect("private prepared retry");
        PreparedEffect::OMP_HOST_EXECUTOR
    }

    fn declared_pre_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        self.inner.declared_pre_world(contract, payload)
    }

    fn observe(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<PreWorld, ExecutorFault> {
        self.inner.observe(contract, payload)
    }

    fn expected_post_world(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        self.inner.expected_post_world(contract, payload)
    }

    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        self.retry_once(effect.correlation_id());
        self.inner.execute(effect)
    }
}

struct Catalog(BTreeMap<String, AdmittedCapability>);

impl OperationCatalog for Catalog {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability> {
        self.0.get(capability.as_str()).cloned()
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        matches!(binding, HandlerBinding::Builtin { name } if name == "write" || name == "write_evidence")
    }
}

struct Schemas(ToolSchema);

impl SchemaCatalog for Schemas {
    fn schema(&self, _reference: &str) -> crate::error::KernelResult<ToolSchema> {
        Ok(self.0.clone())
    }
}

/// Retries use the same authorization pipeline as the original invocation.
fn authorize_invocation(
    fresh: FreshAuthority,
    arguments: &serde_json::Value,
    now_ms: u64,
    command_id: &str,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    context: &crate::policy::PolicyContext,
    schemas: &dyn SchemaCatalog,
) -> AuthorizedInvocation {
    let listing = list_capabilities(fresh.get(), context, contracts, schemas, now_ms).unwrap();
    let invocation = crate::capability::ToolInvocation {
        command_id: CommandId::new(command_id).unwrap(),
        capability_id: CapabilityId::new(CAPABILITY).unwrap(),
        capability_version: 3,
        listing_digest: listing.digest,
        arguments: arguments.clone(),
        arguments_digest: crate::policy::arguments_digest(arguments),
        target: InvocationTarget {
            kind: "capsule".to_owned(),
            id: CAPSULE.to_owned(),
        },
        executor_binding: None,
        expected_revision: None,
        plan_id: Some(PlanId::new("plan.one").unwrap()),
        approval_id: None,
        resource: None,
    };
    let mut ledger = Ledger::open_in_memory().unwrap();
    let mut gate = ApprovalGate::new(&mut ledger);
    match crate::policy::authorize(
        crate::policy::AuthorizationEnvironment {
            authority: fresh.get(),
            policy: context,
            contracts,
            schemas,
            listing: &listing,
        },
        &invocation,
        crate::policy::PlanGate::Accepted,
        &mut gate,
        now_ms,
    )
    .unwrap()
    {
        crate::policy::AuthorizationOutcome::Authorized(authorized) => *authorized,
        crate::policy::AuthorizationOutcome::Rejected(reason) => {
            panic!("fixture authorization rejected: {reason:?}")
        }
    }
}

/// Policy inputs retained for reauthorization during the original dispatch.
#[derive(Clone)]
struct RetryInputs {
    arguments: serde_json::Value,
    contracts: BTreeMap<CapabilityId, CapabilityContract>,
    context: crate::policy::PolicyContext,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
}

struct Fixture {
    authority: Arc<OperationAuthority>,
    world: Arc<World>,
    contracts: BTreeMap<CapabilityId, CapabilityContract>,
    context: crate::policy::PolicyContext,
    schemas: Arc<dyn SchemaCatalog + Send + Sync>,
    clock_ms: Arc<AtomicU64>,
}

fn bindings() -> crate::token::ExpectedBindings<'static> {
    crate::token::ExpectedBindings {
        seat: Box::leak(Box::new(SeatId::new("seat.one").unwrap())) as &'static SeatId,
        slice: Box::leak(Box::new(SliceId::new("slice.one").unwrap())),
        lane: Box::leak(Box::new(LaneId::new("lane.one").unwrap())),
        session: Box::leak(Box::new(
            SessionId::new("00000000-0000-4000-8000-000000000001").unwrap(),
        )),
        seat_revision: Digest::hash(b"seat"),
        slice_revision: Digest::hash(b"slice"),
        capability_policy_digest: Digest::hash(b"policy"),
        context_policy_digest: Digest::hash(b"context"),
    }
}

fn fresh_proof(now_ms: u64) -> FreshAuthority {
    let bindings = bindings();
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: bindings.seat.clone(),
            slice: bindings.slice.clone(),
            lane: bindings.lane.clone(),
            session: bindings.session.clone(),
            seat_revision: bindings.seat_revision,
            slice_revision: bindings.slice_revision,
            capability_policy_digest: bindings.capability_policy_digest,
            context_policy_digest: bindings.context_policy_digest,
            issued_at_ms: 0,
            // Finite fixture lifetime: the spoofed-clock test crosses
            // this expiry while every other scenario stays inside it.
            expires_at_ms: 1_000,
            entropy: b"entropy",
        })
        .unwrap();
    FreshAuthority::verify(
        &token,
        bindings,
        KEY.to_vec(),
        MemoryRevocations::new(),
        now_ms,
    )
    .unwrap()
}

fn fixture() -> Fixture {
    let world = Arc::new(World::default());
    let executor_world = Arc::clone(&world);
    let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
    fixture_with(world, Arc::new(Executor(executor_world)), ledger)
}

/// The standard fixture, on the original policy generation.
fn fixture_with(
    world: Arc<World>,
    executor: Arc<dyn OperationExecutor>,
    ledger: Arc<Mutex<Ledger>>,
) -> Fixture {
    fixture_with_policy(world, executor, ledger, b"policy")
}

/// A fixture whose admitted catalog snapshot and policy context carry an
/// explicit capability-policy digest, so a renewal test can roll the policy
/// the way a registry publication does.
fn fixture_with_policy(
    world: Arc<World>,
    executor: Arc<dyn OperationExecutor>,
    ledger: Arc<Mutex<Ledger>>,
    policy: &'static [u8],
) -> Fixture {
    fixture_with_contract(world, executor, ledger, policy, contract())
}

fn fixture_with_contract(
    world: Arc<World>,
    executor: Arc<dyn OperationExecutor>,
    ledger: Arc<Mutex<Ledger>>,
    policy: &'static [u8],
    contract: CapabilityContract,
) -> Fixture {
    let contracts = BTreeMap::from([(contract.id.clone(), contract.clone())]);
    let admitted = AdmittedCapability {
        contract: contract.clone(),
        snapshot_revision: 1,
        snapshot_digest: Digest::hash(policy),
    };
    let catalog = Arc::new(Catalog(BTreeMap::from([(CAPABILITY.to_owned(), admitted)])));
    let schemas: Arc<dyn SchemaCatalog + Send + Sync> = Arc::new(Schemas(
        ToolSchema::from_value(serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
            "additionalProperties": false
        }))
        .unwrap(),
    ));
    let clock_ms = Arc::new(AtomicU64::new(20));
    let clock_clone = Arc::clone(&clock_ms);
    let authority = Arc::new(OperationAuthority::new(
        catalog,
        Arc::clone(&schemas),
        executor,
        Limits::new(10, 10, 10_000),
        Arc::new(move || clock_clone.load(Ordering::SeqCst)),
        ledger,
    ));
    let allowed = BTreeSet::from([contract.id.clone()]);
    let bindings = bindings();
    let context = crate::policy::PolicyContext {
        seat_id: bindings.seat.clone(),
        slice_id: bindings.slice.clone(),
        lane_id: bindings.lane.clone(),
        seat_revision: bindings.seat_revision,
        slice_revision: bindings.slice_revision,
        capability_policy_digest: Digest::hash(policy),
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        seat_categories: BTreeSet::from(["builder".to_owned()]),
        adapter_health: crate::capability::AdapterHealth::default(),
        resource_constraints: BTreeMap::new(),
        seat_hints: BTreeMap::new(),
    };
    Fixture {
        authority,
        world,
        contracts,
        context,
        schemas,
        clock_ms,
    }
}

impl Fixture {
    fn authorize(&self, arguments: &serde_json::Value, now_ms: u64) -> AuthorizedInvocation {
        self.authorize_with(fresh_proof(now_ms), arguments, now_ms)
    }

    /// Renewal tests supply a different token generation from `fresh_proof`.
    fn authorize_with(
        &self,
        fresh: FreshAuthority,
        arguments: &serde_json::Value,
        now_ms: u64,
    ) -> AuthorizedInvocation {
        self.authorize_command(fresh, arguments, now_ms, "command.one")
    }

    /// Allow replay tests to change the command without changing the correlation.
    fn authorize_command(
        &self,
        fresh: FreshAuthority,
        arguments: &serde_json::Value,
        now_ms: u64,
        command_id: &str,
    ) -> AuthorizedInvocation {
        authorize_invocation(
            fresh,
            arguments,
            now_ms,
            command_id,
            &self.contracts,
            &self.context,
            self.schemas.as_ref(),
        )
    }

    fn operation_id(&self, correlation_id: &str) -> OperationId {
        let ledger = self.authority.store.lock().unwrap();
        OperationId::new(
            &odin_ledger::operation::operation_row(ledger.connection(), correlation_id)
                .unwrap()
                .unwrap()
                .operation_id,
        )
        .unwrap()
    }

    fn row_state(&self, correlation_id: &str) -> EffectState {
        let ledger = self.authority.store.lock().unwrap();
        odin_ledger::operation::operation_row(ledger.connection(), correlation_id)
            .unwrap()
            .unwrap()
            .effect_state
    }

    fn row_evidence(&self, correlation_id: &str) -> Option<String> {
        let ledger = self.authority.store.lock().unwrap();
        odin_ledger::operation::operation_row(ledger.connection(), correlation_id)
            .unwrap()
            .unwrap()
            .evidence_digest
    }

    fn lease_state(&self, capsule_id: &str) -> String {
        let ledger = self
            .authority
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store::lease_row(ledger.connection(), capsule_id)
            .unwrap()
            .expect("lease exists")
            .state
    }

    /// Open a lease before recording capsule-wide stops, using the invocation authority.
    fn open_test_lease(&self, authorized: &AuthorizedInvocation, capsule_id: &str, now_ms: u64) {
        let authority = authorized.authority();
        let invocation = authorized.invocation();
        let mut ledger = self.authority.store.lock().unwrap();
        let lease_id = format!("lease-{}", capsule_id);
        let now = utc(now_ms).unwrap();
        ledger
            .with_tx(|tx| {
                store::open_lease(
                    tx,
                    capsule_id,
                    &store::LeaseAuthority {
                        seat_id: authority.seat().as_str(),
                        token_id: authority.token_id().as_str(),
                        session_id: authority.session().as_str(),
                        policy_digest: &authority.capability_policy_digest().to_string(),
                        listing_digest: &invocation.listing_digest.to_string(),
                        token_issued_at_ms: authority.issued_at_ms(),
                    },
                    &lease_id,
                    now,
                )
            })
            .unwrap();
    }

    /// Seed a Prepared sibling so capsule-wide settlement must wait for it.
    fn seed_in_flight_operation(
        &self,
        correlation_id: &CorrelationId,
        capsule_id: &CapsuleId,
        authorized: &AuthorizedInvocation,
    ) -> OperationId {
        let authority = authorized.authority();
        let invocation = authorized.invocation();
        let contract = authorized.contract();
        let admitted = self
            .authority
            .catalog
            .admitted(&contract.id)
            .expect("seeded sibling capability is admitted");
        let request = InvokeRequest {
            capsule_id: capsule_id.clone(),
            correlation_id: correlation_id.clone(),
            requested_ceiling: RequestCost {
                requests: 1,
                stops: 0,
                spend: 0,
            },
        };
        let charged = charged_invocation();
        let payload = Payload::from_arguments(&invocation.arguments);
        let request_digest = self.authority.request_digest(
            &request,
            charged,
            payload.digest,
            invocation.executor_binding.as_ref(),
            authority,
        );
        let request_json =
            self.authority
                .request_json(invocation, &payload, request.requested_ceiling);
        let now_ms = self.clock_ms.load(Ordering::SeqCst);
        let now = utc(now_ms).unwrap();
        let reconciliation = self
            .authority
            .reconciliation_for(contract, &payload)
            .expect("seeded sibling reconciliation binds");
        let binding = PreparedBinding {
            contract: contract.clone(),
            executor_id: PreparedEffect::OMP_HOST_EXECUTOR.to_owned(),
            handler_key: contract.handler.canonical_key(),
            extractor_key: contract.evidence_extractor.canonical_key(),
            target: Target {
                kind: invocation.target.kind.clone(),
                id: invocation.target.id.clone(),
            },
            executor_binding: invocation.executor_binding.clone(),
            pre_world: PreWorldRecord {
                absent: reconciliation.pre_world == PreWorld::Absent,
                digest: reconciliation.pre_world.encode(),
            },
            expected_post_world: reconciliation
                .expected_post_world
                .map(|digest| digest.to_string()),
            lease: None,
            expires_at_ms: now_ms.saturating_add(u64::from(contract.timeout_seconds.get()) * 1_000),
            snapshot_revision: admitted.snapshot_revision,
            snapshot_digest: admitted.snapshot_digest.to_string(),
        };
        let binding_json = serde_json::to_string(&binding).unwrap();
        let binding_digest = Digest::hash(binding_json.as_bytes()).to_string();
        let new = store::NewOperation {
            capsule_id: capsule_id.as_str(),
            seat_id: authority.seat().as_str(),
            token_id: authority.token_id().as_str(),
            session_id: authority.session().as_str(),
            policy_digest: &authority.capability_policy_digest().to_string(),
            listing_digest: &invocation.listing_digest.to_string(),
            executor_id: PreparedEffect::OMP_HOST_EXECUTOR,
            prepared_binding: &binding_json,
            binding_digest: &binding_digest,
            correlation_id: correlation_id.as_str(),
            capability: contract.id.as_str(),
            request_digest: &request_digest.to_string(),
            request_json: &request_json,
            reconciliation_json: &reconciliation.encode(),
            now,
        };
        let mut ledger = self.authority.store.lock().unwrap();
        let prepared = ledger
            .with_tx(|tx| {
                let prepared = store::prepare_operation(tx, &new)?;
                store::bump_usage(
                    tx,
                    authority.session().as_str(),
                    charged.requests,
                    charged.stops,
                    charged.spend,
                    now,
                )?;
                Ok(prepared)
            })
            .unwrap();
        let store::PrepareOutcome::Prepared { operation_id } = prepared else {
            panic!("seeded sibling correlation must be fresh");
        };
        OperationId::new(&operation_id).unwrap()
    }
}

fn correlation(tag: &str) -> CorrelationId {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in tag.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let half = format!("{hash:016x}");
    CorrelationId::new(&format!("{half}{half}")).unwrap()
}

fn invoke_request(correlation_id: &CorrelationId, ceiling: u64) -> InvokeRequest {
    InvokeRequest {
        capsule_id: CapsuleId::new(CAPSULE).unwrap(),
        correlation_id: correlation_id.clone(),
        requested_ceiling: RequestCost {
            requests: ceiling,
            stops: 0,
            spend: 0,
        },
    }
}

fn write_arguments(content: &str) -> serde_json::Value {
    serde_json::json!({"path": "docs/note.md", "content": content})
}

/// Identical inputs mint the same token so tests can replay an issuance generation.
fn proof_with(
    seat: &str,
    session: &str,
    policy: &'static [u8],
    issued_at_ms: u64,
    now_ms: u64,
) -> FreshAuthority {
    let base = bindings();
    let seat_id = SeatId::new(seat).unwrap();
    let session_id = SessionId::new(session).unwrap();
    let bindings = crate::token::ExpectedBindings {
        seat: &seat_id,
        slice: base.slice,
        lane: base.lane,
        session: &session_id,
        seat_revision: base.seat_revision,
        slice_revision: base.slice_revision,
        capability_policy_digest: Digest::hash(policy),
        context_policy_digest: base.context_policy_digest,
    };
    let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
    let token = issuer
        .mint(MintRequest {
            seat: bindings.seat.clone(),
            slice: bindings.slice.clone(),
            lane: bindings.lane.clone(),
            session: bindings.session.clone(),
            seat_revision: bindings.seat_revision,
            slice_revision: bindings.slice_revision,
            capability_policy_digest: bindings.capability_policy_digest,
            context_policy_digest: bindings.context_policy_digest,
            issued_at_ms,
            expires_at_ms: 1_000,
            entropy: b"entropy",
        })
        .unwrap();
    FreshAuthority::verify(
        &token,
        bindings,
        KEY.to_vec(),
        MemoryRevocations::new(),
        now_ms,
    )
    .unwrap()
}

/// Use distinct paths so successive invocations observe an absent pre-image.
fn arguments_at(path: &str, content: &str) -> serde_json::Value {
    serde_json::json!({"path": path, "content": content})
}

fn lease_ledger_path(tag: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "odin-kernel-lease-rebind-{}-{tag}.sqlite3",
        std::process::id()
    ));
    discard_ledger(&path);
    path
}

fn discard_ledger(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut candidate = path.as_os_str().to_owned();
        candidate.push(suffix);
        let _ = std::fs::remove_file(candidate);
    }
}

fn rebind_events(ledger: &Ledger) -> usize {
    ledger
        .audit_events_in_scope(&odin_domain::Scope::default(), 0, 100)
        .unwrap()
        .iter()
        .filter(|event| event.kind == "capsule.lease.rebound")
        .count()
}

fn lease_snapshot(authority: &OperationAuthority) -> store::CapsuleLeaseRow {
    let ledger = authority.lock_store().expect("ledger lock");
    store::lease_row(ledger.connection(), CAPSULE)
        .unwrap()
        .expect("lease exists")
}
