//! Real token authorization and registered session composition for scoped tests.

use super::DaemonCodingRoute;
use odin_domain::knowledge::ToolSchema;
use odin_domain::{Digest, Scope};
use odin_hermes::runtime::coding::{CodingRoute, TestSelection};
use odin_kernel::capability::{CapabilityContract, HandlerBinding, SchemaCatalog};
use odin_kernel::operation::*;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::authority_fixture as config_fixture;

pub(super) fn now() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap()
}

struct Catalog(CapabilityContract);
impl OperationCatalog for Catalog {
    fn admitted(&self, capability: &odin_domain::CapabilityId) -> Option<AdmittedCapability> {
        (capability == &self.0.id).then(|| AdmittedCapability {
            contract: self.0.clone(),
            snapshot_revision: 1,
            snapshot_digest: Digest::hash(b"policy"),
        })
    }
    fn resolves(&self, binding: &HandlerBinding) -> bool {
        binding == &self.0.handler || binding == &self.0.evidence_extractor
    }
}

type Work = Box<dyn Fn(&PreparedEffect) -> bool + Send + Sync>;

struct Execute {
    work: Work,
    stop: Option<std::sync::mpsc::Sender<Arc<StopHandle>>>,
}
impl OperationExecutor for Execute {
    fn id(&self) -> &'static str {
        PreparedEffect::OMP_HOST_EXECUTOR
    }
    fn declared_pre_world(
        &self,
        _: &CapabilityContract,
        _: &Payload,
    ) -> Result<Option<PreWorld>, ExecutorFault> {
        Ok(Some(PreWorld::Absent))
    }
    fn observe(&self, _: &CapabilityContract, _: &Payload) -> Result<PreWorld, ExecutorFault> {
        Ok(PreWorld::Absent)
    }
    fn expected_post_world(
        &self,
        _: &CapabilityContract,
        _: &Payload,
    ) -> Result<Option<Digest>, ExecutorFault> {
        Ok(None)
    }
    fn execute(&self, effect: PreparedEffect) -> Result<EffectOutcome, ExecutorFault> {
        if let Some(sender) = &self.stop {
            sender.send(effect.stop_handle()).unwrap();
        }
        if !(self.work)(&effect) {
            return Err(ExecutorFault::Uncertain {
                detail: "scoped execution did not complete".into(),
            });
        }
        Ok(EffectOutcome {
            post_world: None,
            evidence_digest: Digest::hash(b"scoped result"),
            stop: None,
        })
    }
}

pub(super) fn policy(
    scope: &Scope,
    contract: &CapabilityContract,
) -> odin_kernel::policy::PolicyContext {
    let allowed = BTreeSet::from([contract.id.clone()]);
    odin_kernel::policy::PolicyContext {
        seat_id: scope.seat.clone().unwrap(),
        slice_id: "slice.test".parse().unwrap(),
        lane_id: "lane.test".parse().unwrap(),
        seat_revision: Digest::hash(b"seat"),
        slice_revision: Digest::hash(b"slice"),
        capability_policy_digest: Digest::hash(b"policy"),
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        seat_categories: BTreeSet::from(["builder".into()]),
        adapter_health: Default::default(),
        resource_constraints: BTreeMap::new(),
        seat_hints: BTreeMap::new(),
    }
}
fn contract() -> CapabilityContract {
    CapabilityContract {
        id: "test.run".parse().unwrap(),
        delegate_to: None,
        version: 1,
        tool_name: "test_run".parse().unwrap(),
        description: "scoped tests".into(),
        handler: HandlerBinding::Builtin {
            name: "test_run".into(),
        },
        input_schema_ref: "scoped.input".into(),
        output_schema_ref: "scoped.output".into(),
        effect_class: odin_domain::EffectClass::R1,
        seat_tags: BTreeSet::from(["builder".into()]),
        timeout_seconds: std::num::NonZeroU32::new(1260).unwrap(),
        idempotency: odin_kernel::capability::IdempotencyPolicy::Required,
        retry: odin_kernel::capability::RetryPolicy { max_attempts: 0 },
        approval: odin_kernel::capability::ApprovalRequirement::None,
        evidence_extractor: HandlerBinding::Builtin {
            name: "odin_hermes_test_run_evidence".into(),
        },
        adapter: None,
        preview: None,
        batchable: false,
        batch: None,
    }
}

pub(super) fn dispatch(
    route: Arc<DaemonCodingRoute>,
    scope: Scope,
    selection: TestSelection,
    stop: Option<std::sync::mpsc::Sender<Arc<StopHandle>>>,
) -> Result<serde_json::Value, String> {
    let arguments = match &selection {
        TestSelection::Paths(paths) => serde_json::json!({ "paths": paths }),
        TestSelection::Attr(attr) => serde_json::json!({ "attr": attr }),
    };
    let admitted = scope.clone();
    dispatch_with(scope, arguments, stop, move |effect| {
        route.run_tests(effect, &admitted, selection.clone())
    })
}

/// Hand off the authorized permit's stop handle before executing `work`.
pub(super) fn dispatch_with<V: Send + 'static, E: Send + 'static>(
    scope: Scope,
    arguments: serde_json::Value,
    stop: Option<std::sync::mpsc::Sender<Arc<StopHandle>>>,
    work: impl Fn(&PreparedEffect) -> Result<V, E> + Send + Sync + 'static,
) -> Result<V, E> {
    use odin_kernel::token::{FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer};
    let contract = contract();
    let policy = policy(&scope, &contract);
    let session = scope.session.as_ref().unwrap();
    let key = vec![42; 32];
    let token = TokenIssuer::new(key.clone())
        .unwrap()
        .mint(MintRequest {
            seat: policy.seat_id.clone(),
            slice: policy.slice_id.clone(),
            lane: policy.lane_id.clone(),
            session: session.clone(),
            seat_revision: policy.seat_revision,
            slice_revision: policy.slice_revision,
            capability_policy_digest: policy.capability_policy_digest,
            context_policy_digest: Digest::hash(b"context"),
            issued_at_ms: now(),
            expires_at_ms: now() + 1_300_000,
            entropy: b"scoped-tests",
        })
        .unwrap();
    let fresh = FreshAuthority::verify(
        &token,
        odin_kernel::ExpectedBindings {
            seat: &policy.seat_id,
            slice: &policy.slice_id,
            lane: &policy.lane_id,
            session,
            seat_revision: policy.seat_revision,
            slice_revision: policy.slice_revision,
            capability_policy_digest: policy.capability_policy_digest,
            context_policy_digest: Digest::hash(b"context"),
        },
        key,
        MemoryRevocations::new(),
        now(),
    )
    .unwrap();
    let contracts = BTreeMap::from([(contract.id.clone(), contract.clone())]);
    let schema = ToolSchema::from_value(serde_json::json!({"type":"object"})).unwrap();
    let schemas: Arc<dyn SchemaCatalog + Send + Sync> = Arc::new(
        odin_omp::host_tools::operations::StaticSchemaCatalog::new([
            (contract.input_schema_ref.clone(), schema.clone()),
            (contract.output_schema_ref.clone(), schema),
        ])
        .unwrap(),
    );
    let listing = odin_kernel::capability::list_capabilities(
        fresh.get(),
        &policy,
        &contracts,
        schemas.as_ref(),
        now(),
    )
    .unwrap();
    let capsule = odin_omp::host_tools::operations::session_capsule_id(session).unwrap();
    let invocation = odin_kernel::capability::ToolInvocation {
        command_id: config_fixture::command("command.scoped"),
        capability_id: contract.id.clone(),
        capability_version: contract.version,
        listing_digest: listing.digest,
        arguments: arguments.clone(),
        arguments_digest: odin_kernel::policy::arguments_digest(&arguments),
        target: odin_kernel::capability::InvocationTarget {
            kind: "capsule".into(),
            id: capsule.to_string(),
        },
        executor_binding: None,
        expected_revision: None,
        plan_id: Some("plan.scoped".parse().unwrap()),
        approval_id: None,
        resource: None,
    };
    let mut ledger = odin_ledger::Ledger::open_in_memory().unwrap();
    let authorized = match odin_kernel::policy::authorize(
        odin_kernel::policy::AuthorizationEnvironment {
            authority: fresh.get(),
            policy: &policy,
            contracts: &contracts,
            schemas: schemas.as_ref(),
            listing: &listing,
        },
        &invocation,
        odin_kernel::policy::PlanGate::Accepted,
        &mut odin_kernel::approval::ApprovalGate::new(&mut ledger),
        now(),
    )
    .unwrap()
    {
        odin_kernel::policy::AuthorizationOutcome::Authorized(value) => *value,
        other => panic!("scoped authorization refused: {other:?}"),
    };
    let result = Arc::new(Mutex::new(None));
    let kept = Arc::clone(&result);
    let executor = Arc::new(Execute {
        work: Box::new(move |effect| {
            let outcome = work(effect);
            let success = outcome.is_ok();
            *kept.lock() = Some(outcome);
            success
        }),
        stop,
    });
    let authority = OperationAuthority::new(
        Arc::new(Catalog(contract)),
        schemas,
        executor,
        odin_domain::operation::Limits::new(10, 10, 10_000),
        Arc::new(now),
        Arc::new(std::sync::Mutex::new(ledger)),
    );
    let _ = authority.invoke_authorized(
        authorized,
        &InvokeRequest {
            capsule_id: capsule,
            correlation_id: odin_types::CorrelationId::new("0123456789abcdef0123456789abcdef")
                .unwrap(),
            requested_ceiling: odin_domain::operation::RequestCost {
                requests: 10,
                stops: 0,
                spend: 10_000,
            },
        },
    );
    let result = result.lock().take();
    result.expect("admitted executor must run")
}

#[test]
fn worker_bootstrap_fixture_entry() {
    odin_process::test_support::run_bootstrap_if_active();
}

pub(super) fn find(name: &str) -> std::path::PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|dir| dir.join(name))
        .find(|path| path.is_absolute() && path.is_file())
        .unwrap()
}

fn binding(path: std::path::PathBuf) -> odin_huginn::PathDigestRef {
    odin_huginn::PathDigestRef {
        digest: format!(
            "blake3:{}",
            blake3::hash(&std::fs::read(&path).unwrap()).to_hex()
        ),
        path,
    }
}

pub(super) fn open(route: &DaemonCodingRoute, scope: &Scope, source: &std::path::Path) {
    use odin_omp::live::runtime::SessionCapsuleAuthority;
    let session = scope.session.as_ref().unwrap();
    let binding = odin_omp::host_tools::operations::SessionOperationBinding {
        policy: policy(scope, &contract()),
        context_policy_digest: Digest::hash(b"context"),
        capsule_id: odin_omp::host_tools::operations::session_capsule_id(session).unwrap(),
        served_revision: 1,
        parent: None,
    };
    route
        .session_pool
        .as_ref()
        .unwrap()
        .open_session(session, &binding, source)
        .unwrap();
}

/// A session pool holding only the pinned git its registrations run, with
/// `scope`'s session registered: the review lane without a test worker.
pub(super) fn register(
    route: &mut DaemonCodingRoute,
    scope: &Scope,
    source: &std::path::Path,
) -> config_fixture::Fixture {
    let fixture = config_fixture::fixture();
    let manifest = odin_huginn::RuntimeManifest {
        schema: "odin.runtime-manifest.v1".into(),
        executables: BTreeMap::from([("git".into(), binding(find("git")))]),
        odind_config: binding(find("true")),
    };
    let mut config = fixture.config.clone();
    config.paths.state_root = route.state_root.clone();
    route.session_pool = Some(
        odin_cli::live_authority::SessionAuthorityPool::open(&config, &manifest, vec![42; 32])
            .unwrap(),
    );
    open(route, scope, source);
    fixture
}

pub(super) fn compose(
    route: &mut DaemonCodingRoute,
    scope: &Scope,
    source: &std::path::Path,
) -> (
    config_fixture::Fixture,
    odin_process::test_support::RegisteredWorkerFixture,
) {
    compose_with_worker(
        route,
        scope,
        source,
        odin_process::test_support::RegisteredWorkerFixture::new_delegated().unwrap(),
    )
}

pub(super) fn compose_with_worker(
    route: &mut DaemonCodingRoute,
    scope: &Scope,
    source: &std::path::Path,
    worker: odin_process::test_support::RegisteredWorkerFixture,
) -> (
    config_fixture::Fixture,
    odin_process::test_support::RegisteredWorkerFixture,
) {
    let fixture = config_fixture::fixture();
    let channel = worker
        .channel_for_harness(
            &std::env::current_exe().unwrap(),
            "coding_route::tests::scoped_test_fixture::worker_bootstrap_fixture_entry",
            &find("unshare"),
        )
        .unwrap();
    let manifest = odin_huginn::RuntimeManifest {
        schema: "odin.runtime-manifest.v1".into(),
        executables: BTreeMap::from([
            ("git".into(), binding(find("git"))),
            ("nix".into(), binding(find("nix"))),
            ("bwrap".into(), binding(find("bwrap"))),
            ("bash".into(), binding(find("bash"))),
            ("cp".into(), binding(find("cp"))),
            ("mkdir".into(), binding(find("mkdir"))),
            ("chmod".into(), binding(find("chmod"))),
            (
                "worker_bootstrap".into(),
                binding(channel.bootstrap().to_path_buf()),
            ),
            ("unshare".into(), binding(channel.unshare().to_path_buf())),
        ]),
        odind_config: binding(find("true")),
    };
    let mut config = fixture.config.clone();
    config.worker_bus = channel.bus().to_string();
    config.paths.state_root = route.state_root.clone();
    let pool = odin_cli::live_authority::SessionAuthorityPool::open_with_worker_channel(
        &config,
        &manifest,
        vec![42; 32],
        channel,
    )
    .unwrap();
    route.session_pool = Some(pool);
    open(route, scope, source);
    (fixture, worker)
}
