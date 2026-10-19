//! Adapter dispatch tests using kernel authorization and an in-memory receipt ledger.
//! Only the adapter transport is simulated.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use odin_adapter_core::descriptor::AdapterDescriptor;
use odin_adapter_core::dispatch::{
    AdapterBackends, AdapterExecutor, AdapterResultSink, AdapterUnavailable,
};
use odin_adapter_core::evidence::{EffectReceiptSink, LedgerEffectReceiptSink};
use odin_adapter_core::transport::{
    AdapterErrorCode, AdapterTransport, AdapterTransportFault, JsonRpcOutcome, JsonRpcRequest,
};
use odin_adapter_core::{ADAPTER_OPERATION_HANDLER, ADAPTER_RECEIPT_EVIDENCE};
use odin_domain::knowledge::{ToolName, ToolSchema};
use odin_domain::{
    CapabilityId, CommandId, Digest, EffectClass, EffectState, LaneId, Limits, PlanId, RequestCost,
    SeatId, SessionId, SliceId,
};
use odin_kernel::capability::{
    list_capabilities, AdapterHealth, ApprovalRequirement, AuthorizedInvocation,
    CapabilityContract, HandlerBinding, IdempotencyPolicy, InvocationTarget, RetryPolicy,
    SchemaCatalog, ToolInvocation,
};
use odin_kernel::error::KernelError;
use odin_kernel::policy::{
    arguments_digest, authorize, AuthorizationEnvironment, AuthorizationOutcome, PlanGate,
    PolicyContext,
};
use odin_kernel::token::{
    ExpectedBindings, FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer,
};
use odin_kernel::{
    AdmittedCapability, ApprovalGate, ExecutorFault, InvokeRequest, OperationAuthority,
    OperationCatalog, OperationDecision, OperationRejection,
};
use odin_ledger::Ledger;
use odin_types::{CapsuleId, CorrelationId};
use serde_json::{json, Value};

const CAPABILITY: &str = "web.search";
const CAPSULE: &str = "capsule-test";
const KEY: &[u8] = b"adapter authority fixture signing key";
const NOW_MS: u64 = 20;
const DIGEST: &str = "blake3:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const CRED: &str = "cred:web-search-primary";
/// The declared adapter id the capability routes to (registry
/// `implementation = "web-search"`), distinct from the operation kind.
const ADAPTER: &str = "web-search";
const RECEIPT_SCHEMA: &str = "schemas/control/adapter-receipt-evidence.schema.json";

fn arguments() -> Value {
    json!({"query": "odin kernel adapter dispatch", "count": 3})
}

fn search_result() -> Value {
    json!({
        "results": [{
            "title": "Odin",
            "url": "https://odin.local/adapter",
            "description": "one pure search result",
        }],
        "resultCount": 1,
    })
}

fn exact_handler() -> HandlerBinding {
    HandlerBinding::Builtin {
        name: ADAPTER_OPERATION_HANDLER.to_owned(),
    }
}

fn exact_extractor() -> HandlerBinding {
    HandlerBinding::Builtin {
        name: ADAPTER_RECEIPT_EVIDENCE.to_owned(),
    }
}
fn corr(hex: &str) -> CorrelationId {
    CorrelationId::new(hex).unwrap()
}

const CORR_SUCCESS: &str = "e0000000000000000000000000000001";
const CORR_WRONG_EXTRACTOR: &str = "e0000000000000000000000000000002";
const CORR_EXEC_HANDLER: &str = "e0000000000000000000000000000003";
const CORR_UNDECLARED_KIND: &str = "e0000000000000000000000000000004";
const CORR_OUTPUT_MISMATCH: &str = "e0000000000000000000000000000005";
const CORR_REPLAY: &str = "e0000000000000000000000000000006";
const CORR_RELAY_DOWN: &str = "e0000000000000000000000000000007";
const CORR_DEAD_SINK: &str = "e0000000000000000000000000000008";
const CORR_NOT_DISPATCHED: &str = "e0000000000000000000000000000009";
const CORR_DISPATCHED_UNKNOWN: &str = "e000000000000000000000000000000a";
const CORR_UNCONFIGURED: &str = "e000000000000000000000000000000b";
const CORR_TYPED_ERROR: &str = "e000000000000000000000000000000d";

fn descriptor() -> AdapterDescriptor {
    let operation = json!({
        "kind": CAPABILITY,
        "input_schema": "schemas/capability/web.search.input.json",
        "output_schema": "schemas/capability/web.search.output.json",
        "effect_class": "R0",
        "idempotency": "pure",
        "evidence": [{
            "kind": "adapter.receipt",
            "schema": RECEIPT_SCHEMA,
            "required": true,
        }],
        "credential_handle": CRED,
        "taint_after": "credential_tainted",
    });
    let wire = json!({
        "schema": "odin.adapter.descriptor.v1",
        "adapter": {
            "adapter_id": "web-search",
            "version": "1.4.2",
            "binding_digest": DIGEST,
        },
        "protocol_version": 1,
        "operations": [operation],
        "credential_handles": [CRED],
        "initial_taint": "credential_tainted",
    });
    AdapterDescriptor::from_wire(&wire).expect("admitted descriptor parses")
}

fn adapter_contract(
    id: &str,
    tool: &str,
    handler: HandlerBinding,
    extractor: HandlerBinding,
    adapter: &str,
) -> CapabilityContract {
    CapabilityContract {
        id: CapabilityId::new(id).unwrap(),
        delegate_to: None,
        version: 1,
        tool_name: ToolName::new(tool).unwrap(),
        description: "one pure web search through the admitted adapter".to_owned(),
        handler,
        input_schema_ref: "schemas/capability/web.search.input.json".to_owned(),
        output_schema_ref: "schemas/capability/web.search.output.json".to_owned(),
        effect_class: EffectClass::R0,
        seat_tags: BTreeSet::from(["builder".to_owned()]),
        timeout_seconds: NonZeroU32::new(5).unwrap(),
        idempotency: IdempotencyPolicy::Pure,
        retry: RetryPolicy { max_attempts: 1 },
        approval: ApprovalRequirement::None,
        evidence_extractor: extractor,
        adapter: Some(adapter.to_owned()),
        preview: None,
        batchable: false,
        batch: None,
    }
}

/// The standard web.search contract: the capability id IS the operation
/// kind the dispatcher binds against; the adapter is the declared backend.
fn search_contract(handler: HandlerBinding, extractor: HandlerBinding) -> CapabilityContract {
    adapter_contract(CAPABILITY, "web_search", handler, extractor, ADAPTER)
}

/// Admits mismatched bindings so dispatch, rather than catalog admission, rejects them.
struct Catalog {
    admitted: BTreeMap<String, AdmittedCapability>,
    resolvable: Vec<HandlerBinding>,
}

impl OperationCatalog for Catalog {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability> {
        self.admitted.get(capability.as_str()).cloned()
    }

    fn resolves(&self, binding: &HandlerBinding) -> bool {
        self.resolvable.contains(binding)
    }
}

/// Schema catalog over the REAL canonical capability schemas: the kernel
/// validates payloads against the actual input schema and the dispatcher
/// validates results against the actual output schema.
struct Schemas(BTreeMap<String, ToolSchema>);

impl Schemas {
    fn new() -> Self {
        let input: Value = serde_json::from_str(include_str!(
            "../../../schemas/capability/web.search.input.json"
        ))
        .unwrap();
        let output: Value = serde_json::from_str(include_str!(
            "../../../schemas/capability/web.search.output.json"
        ))
        .unwrap();
        Self(BTreeMap::from([
            (
                "schemas/capability/web.search.input.json".to_owned(),
                ToolSchema::from_value(input).unwrap(),
            ),
            (
                "schemas/capability/web.search.output.json".to_owned(),
                ToolSchema::from_value(output).unwrap(),
            ),
            (
                RECEIPT_SCHEMA.to_owned(),
                ToolSchema::from_value(
                    serde_json::from_str(include_str!(
                        "../../../schemas/control/adapter-receipt-evidence.schema.json"
                    ))
                    .unwrap(),
                )
                .unwrap(),
            ),
        ]))
    }
}

impl SchemaCatalog for Schemas {
    fn schema(&self, reference: &str) -> odin_kernel::error::KernelResult<ToolSchema> {
        self.0
            .get(reference)
            .cloned()
            .ok_or_else(|| KernelError::NotFound {
                kind: "schema",
                id: reference.to_owned(),
            })
    }
}

/// What the fixture transport answers. Single scripted call per fixture;
/// a second call can only ever observe the unknown-outcome script.
const SCRIPT_SUCCESS: u64 = 1;
const SCRIPT_TYPED_ERROR: u64 = 2;
const SCRIPT_NOT_DISPATCHED: u64 = 3;
const SCRIPT_DISPATCHED_UNKNOWN: u64 = 4;

struct FixtureTransport {
    script: AtomicU64,
    payload: OnceLock<Value>,
    calls: AtomicU64,
    last_request: OnceLock<Value>,
}

impl FixtureTransport {
    fn scripted(kind: u64, payload: Value) -> Self {
        let transport = Self {
            script: AtomicU64::new(kind),
            payload: OnceLock::new(),
            calls: AtomicU64::new(0),
            last_request: OnceLock::new(),
        };
        transport.payload.set(payload).ok();
        transport
    }

    fn success(result: Value) -> Self {
        Self::scripted(SCRIPT_SUCCESS, result)
    }

    fn typed_error(code: AdapterErrorCode, message: &'static str) -> Self {
        Self::scripted(
            SCRIPT_TYPED_ERROR,
            json!({"code": code.code(), "message": message}),
        )
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> Value {
        self.last_request
            .get()
            .cloned()
            .expect("the transport was called")
    }
}

impl AdapterTransport for FixtureTransport {
    fn call(
        &self,
        _binding: &HandlerBinding,
        _timeout: std::time::Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.last_request.set(request.to_wire()).ok();
        let id = request.id.clone();
        let kind = self
            .script
            .swap(SCRIPT_DISPATCHED_UNKNOWN, Ordering::SeqCst);
        match kind {
            SCRIPT_SUCCESS => {
                let result = self.payload.get().cloned().expect("scripted result");
                let wire = json!({"jsonrpc": "2.0", "id": id, "result": result});
                Ok(JsonRpcOutcome::from_wire(&wire, &id).expect("fixture success frame parses"))
            }
            SCRIPT_TYPED_ERROR => {
                let payload = self.payload.get().cloned().expect("scripted error");
                let wire = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": payload["code"],
                        "message": payload["message"],
                    },
                });
                Ok(JsonRpcOutcome::from_wire(&wire, &id).expect("fixture error frame parses"))
            }
            SCRIPT_NOT_DISPATCHED => Err(AdapterTransportFault::NotDispatched {
                detail: "fixture: the exec child never started".to_owned(),
            }),
            _ => Err(AdapterTransportFault::DispatchedUnknown {
                detail: "fixture: the deadline expired with no reply frame".to_owned(),
            }),
        }
    }
}

struct RelaySink {
    fail: AtomicBool,
    relayed: OnceLock<Value>,
}

impl RelaySink {
    fn new(fail: bool) -> Self {
        Self {
            fail: AtomicBool::new(fail),
            relayed: OnceLock::new(),
        }
    }

    fn relayed(&self) -> Vec<Value> {
        self.relayed.get().cloned().into_iter().collect()
    }
}

impl AdapterResultSink for RelaySink {
    fn relay_result(
        &self,
        _correlation_id: &str,
        result: Value,
    ) -> Result<(), odin_adapter_core::AdapterError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(odin_adapter_core::AdapterError::Receipt {
                detail: "fixture: the caller-visible relay is down".to_owned(),
            });
        }
        self.relayed.set(result).ok();
        Ok(())
    }
}

/// Simulates a receipt store that cannot persist.
struct DeadSink;

impl EffectReceiptSink for DeadSink {
    fn persist_receipt(
        &self,
        _correlation_id: &str,
        _receipt: &odin_adapter_core::operation::AdapterOperationRecord,
        _evidence: Option<&Value>,
    ) -> Result<odin_adapter_core::Digest, odin_adapter_core::AdapterError> {
        Err(odin_adapter_core::AdapterError::Receipt {
            detail: "fixture: the receipt store is unavailable".to_owned(),
        })
    }
}

/// The declared backends the dispatcher serves: the fixture transport
/// behind the one configured adapter, or nothing configured at all.
struct FixtureBackends {
    transport: Arc<FixtureTransport>,
    configured: bool,
}

impl AdapterBackends for FixtureBackends {
    fn descriptor(&self, adapter: &str) -> Result<AdapterDescriptor, AdapterUnavailable> {
        if self.configured && adapter == ADAPTER {
            return Ok(descriptor());
        }
        Err(AdapterUnavailable {
            adapter: adapter.to_owned(),
            detail: "no backend is declared for it on this host".to_owned(),
        })
    }

    fn call(
        &self,
        adapter: &str,
        timeout: std::time::Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        assert_eq!(adapter, ADAPTER, "only the configured adapter is called");
        self.transport.call(&exact_handler(), timeout, request)
    }
}

/// The fallback must never see an adapter permit in these scenarios.
struct AbortFallback;

impl odin_kernel::OperationExecutor for AbortFallback {
    fn id(&self) -> &'static str {
        odin_kernel::PreparedEffect::OMP_HOST_EXECUTOR
    }

    fn declared_pre_world(
        &self,
        _contract: &CapabilityContract,
        _payload: &odin_kernel::Payload,
    ) -> Result<Option<odin_kernel::PreWorld>, ExecutorFault> {
        Ok(None)
    }

    fn observe(
        &self,
        _contract: &CapabilityContract,
        _payload: &odin_kernel::Payload,
    ) -> Result<odin_kernel::PreWorld, ExecutorFault> {
        Ok(odin_kernel::PreWorld::Absent)
    }

    fn expected_post_world(
        &self,
        _contract: &CapabilityContract,
        _payload: &odin_kernel::Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        Ok(None)
    }

    fn execute(
        &self,
        _effect: odin_kernel::PreparedEffect,
    ) -> Result<odin_kernel::EffectOutcome, ExecutorFault> {
        panic!("the fallback executor must never receive an adapter permit")
    }
}

struct Fixture {
    authority: OperationAuthority,
    ledger: Arc<std::sync::Mutex<Ledger>>,
    transport: Arc<FixtureTransport>,
    relay: Arc<RelaySink>,
    context: PolicyContext,
    contracts: BTreeMap<CapabilityId, CapabilityContract>,
    schemas: Arc<Schemas>,
}

impl Fixture {
    /// Builds the full authority stack: one shared in-memory ledger behind
    /// BOTH the operation journal and the real receipt sink, a real token
    /// pipeline, and the dispatcher under test as the sole executor.
    fn new(
        contract: CapabilityContract,
        transport: FixtureTransport,
        configured: bool,
        relay_fail: bool,
        dead_receipts: bool,
    ) -> Self {
        let ledger = Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap()));
        let transport = Arc::new(transport);
        let relay = Arc::new(RelaySink::new(relay_fail));
        let schemas = Arc::new(Schemas::new());
        let receipts: Arc<dyn EffectReceiptSink> = if dead_receipts {
            Arc::new(DeadSink)
        } else {
            Arc::new(LedgerEffectReceiptSink::new(
                Arc::clone(&ledger),
                Arc::new(|| {
                    time::OffsetDateTime::from_unix_timestamp(
                        i64::try_from(NOW_MS).expect("fixture timestamp fits i64"),
                    )
                    .unwrap()
                }),
            ))
        };
        let executor = AdapterExecutor::new(
            Arc::new(FixtureBackends {
                transport: Arc::clone(&transport),
                configured,
            }) as Arc<dyn AdapterBackends>,
            Arc::new(AbortFallback),
            Arc::clone(&schemas) as Arc<dyn SchemaCatalog + Send + Sync>,
            receipts,
            Arc::clone(&relay) as Arc<dyn AdapterResultSink>,
            Arc::new(|| {
                time::OffsetDateTime::from_unix_timestamp(
                    i64::try_from(NOW_MS).expect("fixture timestamp fits i64"),
                )
                .unwrap()
            }),
        );
        let capability_id = CapabilityId::new(CAPABILITY).unwrap();
        let admitted = AdmittedCapability {
            contract: contract.clone(),
            snapshot_revision: 1,
            snapshot_digest: Digest::hash(b"policy"),
        };
        let catalog = Catalog {
            admitted: BTreeMap::from([(CAPABILITY.to_owned(), admitted)]),
            resolvable: vec![
                contract.handler.clone(),
                contract.evidence_extractor.clone(),
            ],
        };
        let clock_ms = Arc::new(AtomicU64::new(NOW_MS));
        let clock_clone = Arc::clone(&clock_ms);
        let authority = OperationAuthority::new(
            Arc::new(catalog),
            Arc::clone(&schemas) as Arc<dyn SchemaCatalog + Send + Sync>,
            Arc::new(executor),
            Limits::new(10, 10, 10_000),
            Arc::new(move || clock_clone.load(Ordering::SeqCst)),
            Arc::clone(&ledger),
        );
        let allowed = BTreeSet::from([capability_id.clone()]);
        let context = PolicyContext {
            seat_id: SeatId::new("seat.one").unwrap(),
            slice_id: SliceId::new("slice.one").unwrap(),
            lane_id: LaneId::new("lane.one").unwrap(),
            seat_revision: Digest::hash(b"seat"),
            slice_revision: Digest::hash(b"slice"),
            capability_policy_digest: Digest::hash(b"policy"),
            seat_tool_refs: allowed.clone(),
            slice_capabilities: allowed.clone(),
            project_capabilities: allowed.clone(),
            lane_capabilities: allowed,
            denied_capabilities: BTreeSet::new(),
            denied_tools: BTreeSet::new(),
            seat_categories: BTreeSet::from(["builder".to_owned()]),
            // The health key is the CONTRACT's adapter: the declared
            // backend id every capability of it routes to.
            adapter_health: AdapterHealth::new(BTreeMap::from([(ADAPTER.to_owned(), true)])),
            resource_constraints: BTreeMap::new(),
            seat_hints: BTreeMap::new(),
        };
        Self {
            authority,
            ledger,
            transport,
            relay,
            context,
            contracts: BTreeMap::from([(capability_id, contract)]),
            schemas,
        }
    }

    fn exact() -> Self {
        Self::new(
            search_contract(exact_handler(), exact_extractor()),
            FixtureTransport::success(search_result()),
            true,
            false,
            false,
        )
    }

    /// Mints an `AuthorizedInvocation` through the real pipeline: fresh
    /// token, fresh listing, full `authorize` pass.
    fn authorized_invocation(&self, capability_arguments: &Value) -> AuthorizedInvocation {
        let seat = SeatId::new("seat.one").unwrap();
        let slice = SliceId::new("slice.one").unwrap();
        let lane = LaneId::new("lane.one").unwrap();
        let session = SessionId::new("00000000-0000-4000-8000-000000000001").unwrap();
        let expected = ExpectedBindings {
            seat: &seat,
            slice: &slice,
            lane: &lane,
            session: &session,
            seat_revision: Digest::hash(b"seat"),
            slice_revision: Digest::hash(b"slice"),
            capability_policy_digest: Digest::hash(b"policy"),
            context_policy_digest: Digest::hash(b"context"),
        };
        let issuer = TokenIssuer::new(KEY.to_vec()).unwrap();
        let token = issuer
            .mint(MintRequest {
                seat: seat.clone(),
                slice: slice.clone(),
                lane: lane.clone(),
                session: session.clone(),
                seat_revision: expected.seat_revision,
                slice_revision: expected.slice_revision,
                capability_policy_digest: expected.capability_policy_digest,
                context_policy_digest: expected.context_policy_digest,
                issued_at_ms: 0,
                expires_at_ms: 1_000,
                entropy: b"entropy",
            })
            .unwrap();
        let fresh = FreshAuthority::verify(
            &token,
            expected,
            KEY.to_vec(),
            MemoryRevocations::new(),
            NOW_MS,
        )
        .unwrap();
        let authority = fresh.get();
        let mut context = self.context.clone();
        context.seat_id = authority.seat().clone();
        context.slice_id = authority.slice().clone();
        context.lane_id = authority.lane().clone();
        let listing = list_capabilities(
            authority,
            &context,
            &self.contracts,
            self.schemas.as_ref(),
            NOW_MS,
        )
        .unwrap();
        let invocation = ToolInvocation {
            command_id: CommandId::new("command.one").unwrap(),
            capability_id: CapabilityId::new(CAPABILITY).unwrap(),
            capability_version: 1,
            listing_digest: listing.digest,
            arguments_digest: arguments_digest(capability_arguments),
            arguments: capability_arguments.clone(),
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
        let mut approvals_ledger = Ledger::open_in_memory().unwrap();
        let mut approvals = ApprovalGate::new(&mut approvals_ledger);
        match authorize(
            AuthorizationEnvironment {
                authority,
                policy: &context,
                contracts: &self.contracts,
                schemas: self.schemas.as_ref(),
                listing: &listing,
            },
            &invocation,
            PlanGate::Accepted,
            &mut approvals,
            NOW_MS,
        )
        .unwrap()
        {
            AuthorizationOutcome::Authorized(authorized) => *authorized,
            AuthorizationOutcome::Rejected(reason) => {
                panic!("fixture authorization rejected: {reason:?}")
            }
        }
    }

    fn invoke(
        &self,
        id: &CorrelationId,
        capability_arguments: &Value,
    ) -> Result<OperationDecision, OperationRejection> {
        let authorized = self.authorized_invocation(capability_arguments);
        self.authority.invoke_authorized(
            authorized,
            &InvokeRequest {
                capsule_id: CapsuleId::new(CAPSULE).unwrap(),
                // THE caller's exact correlation: the journal row, the
                // JSON-RPC echo id, and this handle are one identity.
                correlation_id: id.clone(),
                requested_ceiling: RequestCost {
                    requests: 1,
                    stops: 0,
                    spend: 0,
                },
            },
        )
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The journal row for this exact correlation, or a precise failure:
    /// a missing row means the authority never journaled the invoke.
    fn journal_row(&self, id: &CorrelationId) -> odin_ledger::operation::OperationRow {
        let ledger = self.ledger();
        odin_ledger::operation::operation_row(ledger.connection(), id.as_str())
            .expect("operation journal read succeeds")
            .unwrap_or_else(|| {
                panic!(
                    "the authority journaled no operation for correlation {}",
                    id.as_str()
                )
            })
    }

    fn row_state(&self, id: &CorrelationId) -> EffectState {
        self.journal_row(id).effect_state
    }

    fn row_evidence(&self, id: &CorrelationId) -> Option<String> {
        self.journal_row(id).evidence_digest
    }

    /// The correlation → operation-id semantics of the real journal: the
    /// minted authority operation identity for this exact correlation.
    fn journal_operation_id(&self, id: &CorrelationId) -> String {
        self.journal_row(id).operation_id
    }

    /// Whether the authority journaled ANY operation for this exact
    /// correlation.
    fn journaled(&self, id: &CorrelationId) -> bool {
        let ledger = self.ledger();
        odin_ledger::operation::operation_row(ledger.connection(), id.as_str())
            .expect("operation journal read succeeds")
            .is_some()
    }

    fn receipt_count(&self) -> i64 {
        let ledger = self.ledger();
        ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM effect_receipts", [], |row| row.get(0))
            .unwrap()
    }

    /// The evidence document inside the persisted canonical receipt.
    fn receipt_evidence(&self, id: &CorrelationId) -> Option<Value> {
        let ledger = self.ledger();
        let json: String = ledger
            .connection()
            .query_row(
                "SELECT receipt_json FROM effect_receipts WHERE correlation_id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .ok()?;
        serde_json::from_str::<Value>(&json)
            .ok()?
            .get("evidence")
            .cloned()
    }

    fn receipt_digest(&self, id: &CorrelationId) -> Option<String> {
        let ledger = self.ledger();
        let connection = ledger.connection();
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM effect_receipts WHERE correlation_id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        if present == 0 {
            return None;
        }
        Some(
            connection
                .query_row(
                    "SELECT receipt_digest FROM effect_receipts WHERE correlation_id = ?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .unwrap(),
        )
    }
}

#[test]
fn dispatch_success_settles_committed_with_persisted_receipt() {
    let fixture = Fixture::exact();
    let id = corr(CORR_SUCCESS);
    let decision = fixture
        .invoke(&id, &arguments())
        .expect("the effect settles");
    assert_eq!(decision.state, EffectState::Committed);

    // Exactly one frame left the host, and it carried ONLY the
    // host-derived closed ABI: no endpoint, credential, or bounds.
    assert_eq!(fixture.transport.call_count(), 1);
    let request = fixture.transport.last_request();
    assert_eq!(request["jsonrpc"], "2.0");
    assert_eq!(request["method"], CAPABILITY);
    assert_eq!(request["id"], id.as_str());
    let params = request["params"].as_object().unwrap();
    assert_eq!(
        params.keys().collect::<Vec<_>>(),
        vec!["idempotency_key", "input", "operation_id"]
    );
    // The authority-minted operation identity — the OUTCOME id the
    // decision carries, not any adapter key — travels as operation_id
    // and idempotency_key; the correlation stays the JSON-RPC echo id.
    assert_eq!(params["operation_id"], decision.operation_id.as_str());
    assert_eq!(params["idempotency_key"], decision.operation_id.as_str());
    assert_eq!(params["input"]["query"], arguments()["query"]);
    assert_eq!(params["input"]["count"], arguments()["count"]);
    // The authority relationship: the decision's operation id IS the
    // journal's minted id for this exact correlation — not an adapter key.
    assert_eq!(
        decision.operation_id.as_str(),
        fixture.journal_operation_id(&id)
    );
    // Settlement must reference a receipt persisted before the outcome.
    let evidence = fixture
        .row_evidence(&id)
        .expect("the committed row binds evidence");
    assert_eq!(Some(evidence), fixture.receipt_digest(&id));
    assert_eq!(fixture.receipt_count(), 1);

    assert_eq!(fixture.relay.relayed(), vec![search_result()]);
}

#[test]
fn declaration_binding_mismatch_is_rejected_before_any_frame() {
    // Authorization succeeds; dispatch must reject the mismatched binding before sending.
    let binding_scenarios: Vec<(&str, &str, CapabilityContract)> = vec![
        (
            "wrong-extractor-binding",
            CORR_WRONG_EXTRACTOR,
            search_contract(
                exact_handler(),
                HandlerBinding::Builtin {
                    name: "write_evidence".to_owned(),
                },
            ),
        ),
        (
            "handler-not-the-adapter-marker",
            CORR_EXEC_HANDLER,
            search_contract(
                HandlerBinding::Exec {
                    executable: "/nix/store/0000bin-tool/bin/tool".to_owned(),
                    argv: vec![],
                },
                exact_extractor(),
            ),
        ),
    ];
    for (scenario, corr_hex, contract) in binding_scenarios {
        let fixture = Fixture::new(
            contract,
            FixtureTransport::success(search_result()),
            true,
            false,
            false,
        );
        let id = corr(corr_hex);
        let outcome = fixture
            .invoke(&id, &arguments())
            .expect_err("a mis-declared binding is refused before dispatch");
        let OperationRejection::Executor(ExecutorFault::Rejected { detail }) = outcome else {
            panic!("{scenario}: expected a pre-dispatch rejection, got {outcome:?}");
        };
        assert!(
            detail.contains("refused"),
            "{scenario}: the refusal names the binding law: {detail}"
        );
        assert_eq!(fixture.transport.call_count(), 0, "{scenario}");
        assert_eq!(fixture.receipt_count(), 0, "{scenario}");
        assert!(fixture.relay.relayed().is_empty(), "{scenario}");
        assert_eq!(fixture.row_state(&id), EffectState::Aborted, "{scenario}");
        assert_eq!(fixture.row_evidence(&id), None, "{scenario}");
    }

    // An undeclared capability kind is kernel ADMISSION, not an executor
    // binding mismatch: the authority refuses it before the executor ever
    // runs, and before prepare there is no journal row at all.
    let undeclared = Fixture::new(
        adapter_contract(
            "web.archive",
            "web_archive",
            exact_handler(),
            exact_extractor(),
            ADAPTER,
        ),
        FixtureTransport::success(search_result()),
        true,
        false,
        false,
    );
    let id = corr(CORR_UNDECLARED_KIND);
    let outcome = undeclared
        .invoke(&id, &arguments())
        .expect_err("an undeclared capability kind never reaches the executor");
    assert!(
        matches!(outcome, OperationRejection::UnknownCapability { .. }),
        "the authority refuses the unknown capability before the executor: {outcome:?}"
    );
    assert_eq!(undeclared.transport.call_count(), 0);
    assert!(
        !undeclared.journaled(&id),
        "prepare never happened, so no journal row exists"
    );
    assert_eq!(undeclared.receipt_count(), 0);
    assert!(undeclared.relay.relayed().is_empty());
}

#[test]
fn output_schema_mismatch_is_uncertain_and_persists_no_receipt() {
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::success(json!({
        "results": [{"url": "ftp://not-https"}],
        "resultCount": 1,
        })),
        true,
        false,
        false,
    );
    let id = corr(CORR_OUTPUT_MISMATCH);
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("a malformed output can never settle as success");
    assert!(matches!(
        outcome,
        OperationRejection::Executor(ExecutorFault::Uncertain { .. })
    ));
    // The effect landed, so the row is in doubt — but nothing was settled
    // and no receipt exists.
    assert_eq!(fixture.transport.call_count(), 1);
    assert_eq!(fixture.row_state(&id), EffectState::InDoubt);
    assert_eq!(fixture.row_evidence(&id), None);
    assert_eq!(fixture.receipt_count(), 0);
    assert!(fixture.relay.relayed().is_empty());
}

#[test]
fn idempotent_replay_dispatches_once_and_conflict_rejects() {
    let fixture = Fixture::exact();
    let id = corr(CORR_REPLAY);
    let first = fixture.invoke(&id, &arguments()).expect("first dispatch");
    assert_eq!(first.state, EffectState::Committed);
    assert!(!first.replay);

    // The identical request replays the recorded decision: the adapter is
    // NOT called again and no second receipt appears.
    let replay = fixture.invoke(&id, &arguments()).expect("replay");
    assert_eq!(replay.state, EffectState::Committed);
    assert!(replay.replay);
    assert_eq!(replay.operation_id.as_str(), first.operation_id.as_str());
    assert_eq!(fixture.transport.call_count(), 1);
    assert_eq!(fixture.receipt_count(), 1);

    // The same correlation with a DIFFERENT request is a conflict, never
    // a second effect.
    let conflicting = json!({"query": "a different query", "count": 3});
    let outcome = fixture.invoke(&id, &conflicting).expect_err("conflict");
    assert!(matches!(
        outcome,
        OperationRejection::DuplicateConflict { .. }
    ));
    assert_eq!(fixture.transport.call_count(), 1);
    assert_eq!(fixture.row_state(&id), EffectState::Committed);
}

#[test]
fn post_effect_uncertain_binds_only_genuinely_persisted_evidence() {
    // Relay down AFTER a settled receipt: PostEffectUncertain carries the
    // persisted digest, and the journal binds exactly that evidence.
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::success(search_result()),
        true,
        true,
        false,
    );
    let id = corr(CORR_RELAY_DOWN);
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("a relay failure is in-doubt, never a silent success");
    let OperationRejection::Executor(ExecutorFault::PostEffectUncertain {
        evidence_digest, ..
    }) = outcome
    else {
        panic!("expected PostEffectUncertain, got {outcome:?}");
    };
    assert_eq!(fixture.row_state(&id), EffectState::InDoubt);
    assert_eq!(
        fixture.row_evidence(&id),
        Some(evidence_digest.to_string()),
        "the same CAS that records in-doubt binds the captured evidence"
    );
    // The receipt must exist under the digest recorded by settlement.
    assert_eq!(
        fixture.receipt_digest(&id),
        Some(evidence_digest.to_string())
    );

    // Without a persisted receipt, dispatch must return Uncertain, not PostEffectUncertain.
    let dead = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::success(search_result()),
        true,
        false,
        true,
    );
    let dead_id = corr(CORR_DEAD_SINK);
    let outcome = dead
        .invoke(&dead_id, &arguments())
        .expect_err("an unpersistable receipt is in-doubt");
    assert!(matches!(
        outcome,
        OperationRejection::Executor(ExecutorFault::Uncertain { .. })
    ));
    assert_eq!(dead.row_state(&dead_id), EffectState::InDoubt);
    assert_eq!(dead.row_evidence(&dead_id), None);
    assert!(dead.relay.relayed().is_empty());
}

#[test]
fn transport_faults_follow_the_proved_law() {
    // A fault that PROVES the frame never left is a pre-dispatch
    // rejection: abort, no receipt, no relay.
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::scripted(SCRIPT_NOT_DISPATCHED, Value::Null),
        true,
        false,
        false,
    );
    let id = corr(CORR_NOT_DISPATCHED);
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("a proved non-dispatch is a rejection");
    assert!(matches!(
        outcome,
        OperationRejection::Executor(ExecutorFault::Rejected { .. })
    ));
    assert_eq!(fixture.row_state(&id), EffectState::Aborted);
    assert_eq!(fixture.receipt_count(), 0);
    assert!(fixture.relay.relayed().is_empty());

    // An unknown-outcome fault proves nothing: in doubt, unbound.
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::scripted(SCRIPT_DISPATCHED_UNKNOWN, Value::Null),
        true,
        false,
        false,
    );
    let id = corr(CORR_DISPATCHED_UNKNOWN);
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("an unknown upstream state is in-doubt");
    assert!(matches!(
        outcome,
        OperationRejection::Executor(ExecutorFault::Uncertain { .. })
    ));
    assert_eq!(fixture.row_state(&id), EffectState::InDoubt);
    assert_eq!(fixture.row_evidence(&id), None);
    assert_eq!(fixture.receipt_count(), 0);
}

#[test]
fn an_adapter_with_no_declared_backend_is_refused_before_any_frame() {
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::success(search_result()),
        false,
        false,
        false,
    );
    let id = corr(CORR_UNCONFIGURED);
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("an undeclared backend is a typed pre-dispatch refusal");
    let OperationRejection::Executor(ExecutorFault::Rejected { detail }) = outcome else {
        panic!("expected a pre-dispatch rejection, got {outcome:?}");
    };
    assert!(
        detail.contains(ADAPTER),
        "the refusal names the adapter: {detail}"
    );
    assert_eq!(fixture.transport.call_count(), 0);
    assert_eq!(fixture.row_state(&id), EffectState::Aborted);
    assert_eq!(fixture.receipt_count(), 0);
}

#[test]
fn the_receipt_evidence_names_the_answering_adapter_and_digests_the_response() {
    let fixture = Fixture::exact();
    let id = corr(CORR_SUCCESS);
    fixture
        .invoke(&id, &arguments())
        .expect("the effect settles");
    let evidence = fixture
        .receipt_evidence(&id)
        .expect("receipt evidence persisted");
    assert_eq!(evidence["adapter_identity"]["adapter_id"], ADAPTER);
    assert_eq!(evidence["kind"], CAPABILITY);
    assert_eq!(evidence["taint"], "credential_tainted");
    assert!(evidence["response_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("blake3:")));
}

#[test]
fn typed_backend_error_is_truthful_persisted_failure_evidence() {
    let fixture = Fixture::new(
        search_contract(exact_handler(), exact_extractor()),
        FixtureTransport::typed_error(
            AdapterErrorCode::CredentialsUnavailable,
            "credential file missing",
        ),
        true,
        false,
        false,
    );
    let id = corr(CORR_TYPED_ERROR);
    // A typed backend failure is NEVER a settled success: the dispatched
    // exchange landed upstream, the failed-effect receipt is the genuine
    // captured evidence, and the executor hands the authority a bounded
    // PostEffectUncertain instead of an outcome. The typed reason is
    // relayed verbatim and never retried locally.
    let outcome = fixture
        .invoke(&id, &arguments())
        .expect_err("a typed backend failure is in-doubt, never success");
    let OperationRejection::Executor(ExecutorFault::PostEffectUncertain {
        evidence_digest, ..
    }) = outcome
    else {
        panic!("expected PostEffectUncertain for a typed backend failure, got {outcome:?}");
    };
    assert_eq!(fixture.row_state(&id), EffectState::InDoubt);
    assert_eq!(
        fixture.row_evidence(&id),
        Some(evidence_digest.to_string()),
        "the in-doubt row binds exactly the persisted failure receipt"
    );
    assert_eq!(
        fixture.receipt_digest(&id),
        Some(evidence_digest.to_string()),
        "the evidence is genuine: a durable failed-effect receipt"
    );
    // The caller observes the typed unavailable code verbatim.
    let relayed = fixture.relay.relayed();
    assert_eq!(relayed.len(), 1);
    assert_eq!(relayed[0]["code"], -32000);
    assert_eq!(relayed[0]["message"], "credential file missing");
    assert_eq!(fixture.transport.call_count(), 1);
}
