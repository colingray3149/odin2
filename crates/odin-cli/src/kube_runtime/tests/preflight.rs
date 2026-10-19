//! Invalid workload declarations must fail before approval, without a cluster.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::kube::CellInputs;
use crate::kube_runtime::KubeCommandCoordinator;
use crate::live::workload::{LaunchPort, WorkloadComposition, WorkloadModelPolicy};
use crate::test_fixture::{fixture_config_text, odind_host_toml};
use crate::test_support::{commit_all, git};
use crate::KubeRuntimeCell;
use odin_domain::knowledge::ResourceConstraint;
use odin_domain::operation::Limits;
use odin_domain::{
    AttemptId, Digest, LaneId, NodeId, ProjectId, RunId, Scope, SeatId, SessionId, SliceId,
};
use odin_huginn::PathDigestRef;
use odin_kernel::{MintRequest, TokenIssuer};
use odin_kube::KubeConfig;
use odin_ledger::lane_run::{NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use odin_omp::host_tools::executor::HostToolExecutor;
use odin_omp::host_tools::operations::{
    admission_digest, seat_operation_policy, session_capsule_id, DeclaredOperationCatalog,
    FilesystemSchemaCatalog, HostToolOperationError, HostToolOperations, OperationStackInputs,
    ProvisionedFreshAuthorityProvider, RevisionMaterial, RevisionMaterialSource,
    SeatOperationPolicyInputs, SessionOperationBinding, SessionOperationContext,
    SupervisedAdapterStatus, UnsupervisedAdapterStatus,
};
use odin_omp::host_tools::{HostToolRegistry, KubeCapabilityOwner};
use odin_registry::{
    GatewayProjectionManifest, GatewayProjectionRoute, SnapshotHandle, SnapshotStore,
    ValidatedSnapshotCandidate,
};
use serde_json::json;
use tempfile::TempDir;
use time::OffsetDateTime;

const PROFILE: &str = "preflight-proof";
/// The declared serving lane. The projection under test deliberately does
/// NOT carry a route for this exact (lane, model) pair.
const LANE: &str = "kubert-odin";
const MODEL: &str = "glm-flash";
const SEAT: &str = "operator";
const PROJECT: &str = "life";
const SLICE: &str = "coordinator";
const SESSION: &str = "00000000-0000-4000-8000-00000000c0de";
const RUN: &str = "run.preflight-no-approval-proof";
/// The run a create of PROFILE under RUN owns (`pod_launch_scope`).
const POD_RUN: &str = "run.preflight-no-approval-proof:pod:preflight-proof";

/// The isolated deployment: a committed registry worktree with one enabled
/// provider route for the lane, the REAL `kube.workload.create` capability
/// declaration and its REAL canonical schemas, one enabled workload profile
/// bound to (operator, life, kubert-odin); a published revision-1 snapshot;
/// and a digest-pinned gateway projection file that carries a route ONLY for
/// a different (lane, model) pair.
struct Proof {
    _dir: TempDir,
    root: PathBuf,
    pin: Arc<SnapshotHandle>,
    schema_root: PathBuf,
    store: PathBuf,
}

// A nonstandard endpoint port exercises declaration-driven routing.
const GATEWAY_ENDPOINT: &str = "http://node-gateway.internal:14000/v1";

fn fixture() -> Proof {
    fixture_with_nodes(&[(
        "preflight",
        preflight_node_toml("preflight", true, Some(GATEWAY_ENDPOINT)),
    )])
}

/// The fixture node declaration: an enabled node on its own fixture host,
/// declaring the node-local gateway endpoint the resolver consumes. The
/// endpoint host is deliberately not the profile's `allow_hosts` entry, and
/// `gateway_endpoint` is omitted for the case that models a snapshot
/// published before the declaration (or a node that never admitted
/// workloads).
fn preflight_node_toml(id: &str, allow_workloads: bool, gateway_endpoint: Option<&str>) -> String {
    let mut node = format!(
        "schema = \"odin.registry.v1\"\n\
         kind = \"node\"\n\
         enabled = true\n\
         description = \"preflight fixture node\"\n\
         host = \"{id}-host\"\n\
         role = \"control\"\n\
         capabilities = []\n\
         allow_workloads = {allow_workloads}\n\
         authoritative_state = true\n"
    );
    if let Some(endpoint) = gateway_endpoint {
        node.push_str(&format!("gateway_endpoint = \"{endpoint}\"\n"));
    }
    node
}

fn fixture_with_nodes(nodes: &[(&str, String)]) -> Proof {
    let dir = TempDir::new().expect("fixture root");
    let seed = dir.path().join("seed");
    std::fs::create_dir(&seed).expect("seed");
    git(&seed, &["-c", "init.defaultBranch=main", "init"]);
    git(
        &seed,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "seed",
        ],
    );
    git(
        &seed,
        &[
            "worktree",
            "add",
            "-b",
            "preflight",
            dir.path().join("authoring").to_str().expect("utf8 path"),
            "main",
        ],
    );
    let worktree = dir.path().join("authoring");

    for kind in odin_registry::RegistryKind::ALL {
        let directory = worktree.join("registry").join(kind.directory());
        std::fs::create_dir_all(&directory).expect("kind directory");
        std::fs::write(directory.join(".gitkeep"), b"").expect("kind placeholder");
    }
    std::fs::create_dir_all(worktree.join("schemas/capability")).expect("schemas root");

    // The workload's gateway lane must resolve to an enabled provider route.
    let provider = worktree.join("registry/providers/gateway");
    std::fs::create_dir_all(&provider).expect("provider directory");
    std::fs::write(
        provider.join("provider.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"provider\"\n",
            "enabled = true\n",
            "description = \"preflight fixture gateway\"\n",
            "adapter = \"litellm-gateway\"\n",
            "\n[policy]\n",
            "routes = [{ gateway_lane_id = \"kubert-odin\", gateway_model_id = \"openai/glm-5.3-flash\" }]\n",
            "\n[budget]\n",
            "usd_micros = 30000000\n",
            "\n[budget.window]\n",
            "duration_seconds = 2592000\n",
            "\n[recovery]\n",
            "allowed_rungs = [\"escalate\"]\n",
            "blocked_missing_decision = \"fixture\"\n",
            "\n[recovery.max_attempts]\n",
            "retry = 0\nrestart_worker = 0\ncheckpoint = 0\nrehome = 0\nescalate = 1\n",
            "\n[recovery.cooldown_seconds]\n",
            "retry = 0\nrestart_worker = 0\ncheckpoint = 0\nrehome = 0\nescalate = 0\n",
        ),
    )
    .expect("provider");

    let project = worktree.join("registry/projects/life");
    std::fs::create_dir_all(&project).expect("project directory");
    std::fs::write(
        project.join("project.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"project\"\n",
            "enabled = true\n",
            "description = \"preflight fixture project\"\n",
            "source_root = \"\"\n",
            "default_seat = \"operator\"\n",
            "memory_namespaces = [\"atlas.personal\"]\n",
            "artifact_policy = \"standard\"\n",
        ),
    )
    .expect("project");

    let seat = worktree.join("registry/seats/operator");
    std::fs::create_dir_all(&seat).expect("seat directory");
    std::fs::write(
        seat.join("seat.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"seat\"\n",
            "enabled = true\n",
            "description = \"preflight fixture seat\"\n",
            "categories = [\"operator\"]\n",
            "tool_refs = []\n",
            "project_scope = [\"life\"]\n",
            "approval_defaults = { r0 = \"auto\", r1 = \"auto\", r2 = \"auto\", r3 = \"approval\" }\n",
            "brain_scope = [\"atlas.personal\"]\n",
            "limits = { max_parallel_runs = 4, max_sessions = 2, budget = { usd_micros = 30000000, window = { duration_seconds = 2592000 } } }\n",
        ),
    )
    .expect("seat");

    for (id, node_toml) in nodes {
        let node_directory = worktree.join("registry/nodes").join(id);
        std::fs::create_dir_all(&node_directory).expect("node directory");
        std::fs::write(node_directory.join("node.toml"), node_toml).expect("node");
        let host_directory = worktree.join("registry/hosts").join(format!("{id}-host"));
        std::fs::create_dir_all(&host_directory).expect("host directory");
        std::fs::write(host_directory.join("host.toml"), odind_host_toml(id)).expect("host");
    }

    // The REAL governed capability declaration and its REAL canonical
    // schemas: the dispatch stack derives its contract from the committed
    // object through the production derivation against the compiled
    // admitted tuple, exactly as the daemon does.
    let capability = worktree.join("registry/capabilities/kube.workload.create");
    std::fs::create_dir_all(&capability).expect("capability directory");
    std::fs::write(
        capability.join("capability.toml"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../registry/capabilities/kube.workload.create/capability.toml"
        )),
    )
    .expect("capability");
    for schema in [
        "kube.workload.create.input.json",
        "kube.workload.create.output.json",
    ] {
        let declared = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/capability")
                .join(schema),
        )
        .unwrap_or_else(|error| panic!("schema {schema} is missing: {error}"));
        std::fs::write(worktree.join("schemas/capability").join(schema), declared).expect("schema");
    }
    let harness = worktree.join("registry/harnesses/omp");
    std::fs::create_dir_all(&harness).expect("harness directory");
    std::fs::write(
        harness.join("harness.toml"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../registry/harnesses/omp/harness.toml"
        )),
    )
    .expect("harness");

    // One enabled workload profile bound to (operator, life, kubert-odin):
    // exactly the launch surface the resolver consults.
    let workload = worktree.join("registry/workloads").join(PROFILE);
    std::fs::create_dir_all(&workload).expect("workload directory");
    std::fs::write(
        workload.join("profile.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"workload\"\n",
            "enabled = true\n",
            "description = \"preflight regression profile\"\n",
            "\n[image]\n",
            "reference = \"localhost/odin-fixture@sha256:1111111111111111111111111111111111111111111111111111111111111111\"\n",
            "\n[runtime]\n",
            "launcher = \"/odin/bin/omp\"\n",
            "browser = \"/odin/bin/chromium\"\n",
            "supervisor = \"/odin/bin/odind\"\n",
            "playwright = \"/odin/lib/playwright-core\"\n",
            "\n[seat]\n",
            "seat = \"operator\"\n",
            "project = \"life\"\n",
            "gateway_lane = \"kubert-odin\"\n",
            "\n[network]\n",
            "allow_hosts = [\"gateway.internal\"]\n",
            "\n[display]\n",
            "xvfb = \"/odin/bin/Xvfb\"\n",
            "screen = \"1280x800x24\"\n",
            "stream = true\n",
            "\n[state]\n",
            "path = \"/state\"\n",
            "storage = \"2Gi\"\n",
            "\n[export]\n",
            "pod_path = \"/export\"\n",
            "host_folder = \"/srv/odin/preflight\"\n",
            "\n[brief]\n",
            "text = \"preflight regression brief\"\n",
            "\n[memory]\n",
            "namespace = \"atlas.personal\"\n",
            "\n[lifetime]\n",
            "deadline_seconds = 3600\n",
        ),
    )
    .expect("workload profile");

    commit_all(&worktree, "preflight fixture registry");
    std::fs::create_dir_all(dir.path().join("state")).expect("fixture state root");
    let store = dir.path().join("state/registry/snapshot.json");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &git(&worktree, &["rev-parse", "HEAD"]),
        odin_omp::host_tools::production_bindings()
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("fixture candidate");
    SnapshotStore::new(&store)
        .publish_committed(&candidate, 1)
        .expect("fixture publication");
    let pin = Arc::new(SnapshotHandle::open(SnapshotStore::new(&store)).expect("fixture pin"));
    Proof {
        root: dir.path().to_path_buf(),
        _dir: dir,
        pin,
        schema_root: worktree,
        store,
    }
}

fn missing_route_projection(root: &Path) -> (PathBuf, String) {
    let manifest = GatewayProjectionManifest::build(vec![GatewayProjectionRoute {
        gateway_lane_id: "elsewhere".to_owned(),
        gateway_model_id: "other/model".to_owned(),
        account_handle: "fixture-account".to_owned(),
        endpoint: "https://gateway.internal:4000/v1".to_owned(),
        credential_handle: "fixture-credential".to_owned(),
        role: "serve".to_owned(),
        affinity_key: "fixture".to_owned(),
        eligible: true,
    }])
    .expect("projection builds");
    let bytes = serde_json::to_vec(&manifest).expect("serialize projection");
    let path = root.join("gateway-projection.json");
    std::fs::write(&path, &bytes).expect("write projection");
    (path, Digest::hash(&bytes).to_string())
}

/// The revision material the fresh authority recomposes: revision 1 over
/// the fixture contracts and the (seat, lane) policy, exactly as the
/// provisioning path composes.
struct FixtureGeneration {
    material: RevisionMaterial,
}

impl FixtureGeneration {
    fn new(
        contracts: &BTreeMap<odin_domain::CapabilityId, odin_kernel::CapabilityContract>,
        policy: &odin_omp::host_tools::operations::SeatOperationPolicy,
        seat: SeatId,
        lane: LaneId,
        project: ProjectId,
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
                seat_operation_bindings: BTreeMap::from([(
                    (seat.clone(), lane.clone()),
                    policy.clone(),
                )]),
                session_lanes: BTreeMap::from([((seat, project), lane)]),
                tool_index,
                contract_adapters: BTreeSet::new(),
                declaration_decided: BTreeSet::new(),
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

#[tokio::test]
async fn missing_gateway_route_refuses_preflight_and_mints_no_approval_row() {
    let proof = fixture();
    let (projection_path, projection_digest) = missing_route_projection(&proof.root);

    // The strict daemon configuration with the projection pin: the exact
    // material `load_gateway_projection` re-reads per admission.
    let mut config =
        odin_huginn::OdindConfig::parse(&fixture_config_text(&proof.root, &proof.store))
            .expect("fixture config parses");
    config.catalogs.gateway_projection = PathDigestRef {
        path: projection_path,
        digest: projection_digest,
    };

    let (error, approvals, effects) =
        dispatch_create_to_verdict(&proof, config, "preflight-proof-1").await;
    // The typed preflight refusal — never an approval demand. The refusal
    // must name the exact unserved (lane, model) pair the resolver missed;
    // its wording is the resolver's, not a snapshot asserted here.
    let refusal = match &error {
        HostToolOperationError::Arguments { detail } => detail,
        other => panic!("expected the typed preflight refusal, got {other:?}"),
    };
    assert!(
        refusal.contains(LANE) && refusal.contains(MODEL),
        "the refusal must name the unserved (lane, model) pair: {refusal}"
    );
    assert_eq!(
        approvals, 0,
        "a missing gateway route must mint ZERO approval rows"
    );
    assert_eq!(
        effects, 0,
        "a missing gateway route must journal ZERO effect rows"
    );
}

#[tokio::test]
async fn explicit_target_runtime_validation_rejects_malformed_names_before_authority() {
    let coordinator = KubeCommandCoordinator::new(None);
    for target in ["", "Preflight", "-preflight", "preflight-", "preflight\n"] {
        let error = coordinator
            .require_create_target("kube_workload_create", Some(target), None)
            .expect_err("malformed target must refuse before missing runtime authority");
        assert!(
            error.to_string().contains("is not a node name"),
            "runtime target syntax must be strict for {target:?}: {error}"
        );
    }
}

/// Exercise the production replay guard over a real journal and lazy client.
/// A settled rejection is a replay marker: matching placement must replay it,
/// while changed placement must refuse before reading that settlement.
fn assert_initial_target_checked_before_settled_replay(mut launch: odin_kube::JobLaunch) {
    use std::num::{NonZeroU64, NonZeroUsize};

    let dir = TempDir::new().expect("replay fixture");
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("replay.sqlite3")).expect("replay ledger"),
    ));
    launch.initial_target_node = Some("mini".to_owned());
    let run = &launch.labels.run_id;
    let operation = &launch.operation_id;
    {
        let guard = ledger.lock().expect("ledger lock");
        guard
            .connection()
            .execute(
                "INSERT INTO kube_job_runs(run_id,cluster,namespace,launch_json,created_at) \
             VALUES(?1,'unit-cluster','unit-namespace',?2,'2026-01-01T00:00:00Z')",
                rusqlite::params![
                    run.as_str(),
                    serde_json::to_string(&launch).expect("launch json")
                ],
            )
            .expect("seed declared placement");
        guard.connection().execute(
            "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
             idempotency_digest,fingerprint,request_json,state,failure_kind,failure_reason,created_at,updated_at) \
             VALUES(?1,?2,'unit-cluster','unit-namespace','create',?3,'fixture',?4,\
             'rejected','rejected','settled replay marker','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')",
            rusqlite::params![operation.as_str(), run.as_str(), launch.idempotency_digest.to_string(),
                serde_json::to_string(&launch).expect("request json")],
        ).expect("seed settled operation");
    }
    let client = odin_kube::KubeClient {
        client: kube::Client::try_from(kube::Config::new(
            "http://127.0.0.1:9".parse().expect("cluster uri"),
        ))
        .expect("lazy kube client"),
        config: KubeConfig {
            kubeconfig: dir.path().join("kubeconfig"),
            cluster: "unit-cluster".to_owned(),
            namespace: "unit-namespace".to_owned(),
            allowed_nodes: BTreeSet::from(["mini".to_owned(), "pc".to_owned()]),
            request_timeout: Duration::from_secs(2),
            teardown_timeout: Duration::from_secs(2),
        },
    };
    let bus = odin_process::BusAddress::unix_socket(dir.path().join("stop-bus.sock"))
        .expect("bus address");
    let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
    let stops = Arc::new(odin_kernel::stop::StopAuthority::new(
        Arc::clone(&ledger),
        channel,
    ));
    let artifacts = dir.path().join("artifacts");
    std::fs::create_dir_all(&artifacts).expect("artifacts root");
    let reconciler = odin_kube::JobReconciler::new(
        client.clone(),
        Arc::clone(&ledger),
        stops,
        Arc::default(),
        artifacts,
    )
    .expect("reconciler");
    let catalog = odin_huginn::kube::KubeCatalog::new(
        odin_huginn::kube::SurfaceArtifacts::new(
            odin_domain::huginn::LiveSessionId::parse(crate::kube::KUBE_SURFACE_SESSION)
                .expect("surface session"),
            LaneId::new(crate::kube::KUBE_SURFACE_LANE).expect("surface lane"),
            NonZeroU64::new(65_536).expect("nonzero"),
            NonZeroU64::new(1_048_576).expect("nonzero"),
        ),
        NonZeroUsize::new(256).expect("nonzero"),
        NonZeroU64::new(16_384).expect("nonzero"),
        NonZeroU64::new(128).expect("nonzero"),
    );
    let control =
        odin_huginn::kube::KubeControl::new(catalog, Arc::new(reconciler), ledger, client);
    for (target, expected) in [
        (Some("mini"), "settled replay marker"),
        (
            None,
            "initial target differs from the run's admitted declaration",
        ),
        (
            Some("pc"),
            "initial target differs from the run's admitted declaration",
        ),
    ] {
        let error =
            super::create_replay_or_fresh("kube_workload_create", &control, run, operation, target)
                .expect_err("settled refusal or placement mismatch");
        assert!(
            error.to_string().contains(expected),
            "unexpected replay verdict: {error}"
        );
    }
}

/// Explicit placement is checked against the real pinned runtime authority
/// before gateway resolution or launch material can ask for approval.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_target_refusals_precede_gateway_and_mint_no_approval_rows() {
    let cases: &[(&str, Option<&[&str]>, &str)] = &[
        ("Preflight", None, "targetNode"),
        ("-preflight", None, "targetNode"),
        ("preflight-", None, "targetNode"),
        ("preflight\n", None, "targetNode"),
        (
            "preflight",
            None,
            "initial placement requires pinned kube placement authority",
        ),
        (
            "preflight",
            Some(&["other"]),
            "outside admitted placement authority",
        ),
        (
            "other",
            Some(&["preflight", "other"]),
            "disagrees with the agent's bound serving node",
        ),
    ];
    for (target, allowed_nodes, expected) in cases {
        let proof = fixture_with_nodes(&[
            (
                "preflight",
                preflight_node_toml("preflight", true, Some(UNRESOLVABLE_GATEWAY_ENDPOINT)),
            ),
            (
                "other",
                preflight_node_toml("other", true, Some(UNRESOLVABLE_GATEWAY_ENDPOINT))
                    .replace("authoritative_state = true", "authoritative_state = false"),
            ),
        ]);
        // Binding resolves the served route before placement; the selected
        // endpoint remains unreachable so placement must refuse before probing it.
        let config = serving_config(&proof.root, &proof.store);
        let (error, approvals, effects) = dispatch_create_with_target_to_verdict(
            &proof,
            config,
            "preflight-explicit-target",
            Some(target),
            *allowed_nodes,
        )
        .await;
        // Canonical schema syntax rejection precedes handler preflight;
        // runtime placement failures retain the handler's typed detail.
        let detail = match &error {
            HostToolOperationError::Arguments { detail } => detail.clone(),
            HostToolOperationError::Authority(_) if *expected == "targetNode" => error.to_string(),
            other => {
                panic!("expected typed placement preflight refusal for {target:?}, got {other:?}")
            }
        };
        assert!(
            detail.contains(expected),
            "placement must refuse before probing the unreachable gateway: {detail}"
        );
        assert_eq!(
            approvals, 0,
            "placement refusal must mint ZERO approval rows"
        );
        assert_eq!(
            effects, 0,
            "placement refusal must journal ZERO operation rows"
        );
    }
}

/// A missing route still refuses before placement, even when the explicit
/// target equals the serving node and the pinned cell admits that node.
#[tokio::test]
async fn missing_route_precedes_admitted_explicit_serving_node_without_approval() {
    let proof = fixture();
    let (path, digest) = missing_route_projection(&proof.root);
    let mut config =
        odin_huginn::OdindConfig::parse(&fixture_config_text(&proof.root, &proof.store))
            .expect("fixture config parses");
    config.catalogs.gateway_projection = PathDigestRef { path, digest };
    let (error, approvals, effects) = dispatch_create_with_target_to_verdict(
        &proof,
        config,
        "preflight-admitted-explicit-target",
        Some("preflight"),
        Some(&["preflight"]),
    )
    .await;
    let detail = match &error {
        HostToolOperationError::Arguments { detail } => detail,
        other => panic!("expected typed gateway preflight refusal, got {other:?}"),
    };
    assert!(
        detail.contains(LANE) && detail.contains(MODEL),
        "admitted placement must reach the missing gateway route: {detail}"
    );
    assert_eq!(approvals, 0, "missing route must mint ZERO approval rows");
    assert_eq!(effects, 0, "missing route must journal ZERO operation rows");
}

/// Runs one REAL governed `kube.workload.create` dispatch over the whole
/// production chain (contracts, seat policy, signed token, catalogue,
/// coordinator/LaunchPort/gate/ledger) and returns the dispatch verdict
/// plus the durable approval-row and operation-journal-row counts (ALL
/// rows for the capsule, terminal included — a refused pre-mint dispatch
/// must leave the journal EMPTY). Shared by every refusal case below so
/// the pre-mint ordering is proven once, not re-mocked per case.
async fn dispatch_create_to_verdict(
    proof: &Proof,
    config: odin_huginn::OdindConfig,
    correlation: &str,
) -> (HostToolOperationError, usize, usize) {
    dispatch_create_with_target_to_verdict(proof, config, correlation, None, None).await
}

async fn dispatch_create_with_target_to_verdict(
    proof: &Proof,
    config: odin_huginn::OdindConfig,
    correlation: &str,
    target_node: Option<&str>,
    allowed_nodes: Option<&[&str]>,
) -> (HostToolOperationError, usize, usize) {
    // The REAL coordinator over the REAL launch port, composed exactly as
    // `odind` composes it (un-armed supervisor; no cluster surface is
    // needed because the refusal is declared configuration).
    let cell = allowed_nodes.map(|nodes| {
        let ledger = Arc::new(Mutex::new(
            Ledger::open(proof.root.join("dispatch-ledger.sqlite3")).expect("runtime ledger"),
        ));
        let bus = odin_process::BusAddress::unix_socket(proof.root.join("stop-bus.sock"))
            .expect("bus address");
        let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
        let stops = Arc::new(odin_kernel::stop::StopAuthority::new(
            Arc::clone(&ledger),
            channel,
        ));
        KubeRuntimeCell::new(CellInputs {
            config: KubeConfig {
                kubeconfig: proof.root.join("kubeconfig"),
                cluster: "unit-cluster".to_owned(),
                namespace: "unit-namespace".to_owned(),
                allowed_nodes: nodes.iter().map(|node| (*node).to_owned()).collect(),
                request_timeout: Duration::from_secs(5),
                teardown_timeout: Duration::from_secs(5),
            },
            ledger,
            stops,
            artifact_root: proof.root.join("artifacts"),
            snapshot: proof.pin.current(),
            config_revision: 1,
            launch_binding: None,
            workload_identity: crate::kube::WorkloadExtensionIdentity {
                artifact: odin_domain::ArtifactId::new(
                    Digest::hash(b"preflight-placement-identity").to_string(),
                )
                .expect("artifact id"),
                deployment: Default::default(),
            },
        })
    });
    let coordinator = Arc::new(KubeCommandCoordinator::new(cell));
    coordinator
        .arm_workload_port(Arc::new(LaunchPort {
            snapshot: Arc::clone(&proof.pin),
            composition: WorkloadComposition {
                laws: BTreeMap::new(),
                models: BTreeMap::from([(
                    PROFILE.to_owned(),
                    WorkloadModelPolicy::Exact {
                        provider: "gateway".to_owned(),
                        model: MODEL.to_owned(),
                    },
                )]),
                bindings: BTreeMap::from([(
                    PROFILE.to_owned(),
                    (
                        SliceId::new(SLICE).expect("slice id"),
                        LaneId::new(LANE).expect("lane id"),
                        NodeId::new("preflight").expect("node id"),
                    ),
                )]),
                skipped: Default::default(),
            },
            supervisor: Arc::new(OnceLock::new()),
            config,
            deployment: None,
            session_lanes: BTreeMap::new(),
        }))
        .expect("arm the workload launch port");

    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(Arc::clone(&coordinator) as Arc<dyn KubeCapabilityOwner>)
        .expect("register the real kube surface");
    let registry = Arc::new(registry);

    // The governed dispatch stack over the REAL derived contracts.
    let snapshot = proof.pin.current();
    let contracts = odin_cli::runtime_bindings::operation_contracts(&snapshot.objects)
        .expect("the fixture registry derives the real capability contract");
    assert!(
        contracts.contains_key(
            &odin_domain::CapabilityId::new("kube.workload.create").expect("capability id")
        ),
        "the fixture must admit kube.workload.create"
    );

    let seat = SeatId::new(SEAT).expect("seat id");
    let slice = SliceId::new(SLICE).expect("slice id");
    let lane = LaneId::new(LANE).expect("lane id");
    let project = ProjectId::new(PROJECT).expect("project id");
    let run = RunId::new(RUN).expect("run id");
    let session = SessionId::new(SESSION).expect("session id");
    let seat_revision = snapshot
        .objects
        .iter()
        .find(|object| object.kind() == odin_registry::RegistryKind::Seat && object.id == SEAT)
        .expect("fixture seat object")
        .canonical_bytes()
        .map(|bytes| Digest::hash(&bytes))
        .expect("seat canonical bytes");
    let slice_revision = Digest::hash(b"preflight fixture slice");
    let admission = admission_digest(&contracts, 1).expect("admission digest");
    let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
    let resource = ResourceConstraint::Named {
        kind: "workspace".to_owned(),
        value: "preflight".to_owned(),
    };
    let policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: seat.clone(),
        slice_id: slice.clone(),
        lane_id: lane.clone(),
        seat_revision,
        slice_revision,
        admission,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: contracts
            .keys()
            .map(|id| (id.clone(), vec![resource.clone()]))
            .collect::<BTreeMap<_, _>>(),
        seat_categories: BTreeSet::from([SEAT.to_owned()]),
    });

    // A genuine signed token file the provider re-verifies on every
    // dispatch, issued now and valid one hour, exactly like production.
    let issued_at_ms = (odin_omp::host_tools::operations::wall_clock())();
    let token_root = proof.root.join("authority-tokens");
    std::fs::create_dir_all(&token_root).expect("token root");
    let signing_key = {
        let mut key = b"preflight no-approval fixture signing key".to_vec();
        key.truncate(32);
        key
    };
    let token = TokenIssuer::new(signing_key.clone())
        .expect("token issuer")
        .mint(MintRequest {
            seat: seat.clone(),
            slice: slice.clone(),
            lane: lane.clone(),
            session: session.clone(),
            seat_revision,
            slice_revision,
            capability_policy_digest: admission,
            context_policy_digest: policy.context_policy_digest,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
            entropy: b"preflight no-approval fixture token",
        })
        .expect("mint fixture session token");
    std::fs::write(
        token_root.join(format!("{}.json", session.as_str())),
        serde_json::to_vec(&token).expect("encode token"),
    )
    .expect("write provisioned token");
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
    let ledger = Arc::new(Mutex::new(
        Ledger::open(proof.root.join("dispatch-ledger.sqlite3")).expect("dispatch ledger"),
    ));
    let operations = HostToolOperations::new(
        OperationStackInputs {
            workload_drafts: None,
            catalog,
            schemas: Arc::new(FilesystemSchemaCatalog::new(&proof.schema_root)),
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
                seat.clone(),
                lane.clone(),
                project.clone(),
            )),
        },
        contracts.clone(),
        authority_provider,
    )
    .expect("operation stack");

    // The bridge lane/run and the accepted plan the R3 plan gate proves —
    // every OTHER gate is satisfied, so the ONLY thing standing between the
    // dispatch and a minted approval is the declared preflight.
    {
        let mut ledger = ledger.lock().expect("ledger lock");
        odin_ledger::lane_run::create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: lane.clone(),
                seat_id: seat.clone(),
                project_id: Some(project.clone()),
                template_id: "template:preflight".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator:fixture".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .expect("fixture bridge lane");
        odin_ledger::lane_run::create_run(
            ledger.connection(),
            &NewRun {
                run_id: run.clone(),
                lane_id: lane.clone(),
                attempt_number: 1,
                workflow_id: Some("live:preflight".to_owned()),
                workflow_version: Some(1),
                input_hash: "preflight".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .expect("fixture bridge run");
        let plan = ledger
            .replace_plan(
                &run,
                "Launch the declared workload profile",
                &[TodoSpec {
                    id: odin_domain::TodoId::new("todo:preflight-proof").expect("todo id"),
                    title: "Launch the declared workload profile".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        ledger
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan acceptance");
    }

    // The canonical create input optionally carries explicit placement. The
    // preflight must refuse before anything is journaled, minted, or consumed.
    let mut arguments = json!({ "profile": PROFILE });
    if let Some(target) = target_node {
        arguments["targetNode"] = json!(target);
    }
    let capsule = session_capsule_id(&session).expect("capsule id");
    let error = operations
        .dispatch_tool(
            SessionOperationContext {
                binding: &SessionOperationBinding {
                    policy: policy.policy,
                    context_policy_digest: policy.context_policy_digest,
                    capsule_id: capsule.clone(),
                    served_revision: 1,
                    parent: None,
                },
                session: &session,
                scope: &Scope {
                    seat: Some(seat),
                    project: Some(project),
                    lane: Some(lane),
                    run: Some(run),
                    session: Some(session.clone()),
                    ..Scope::default()
                },
                execution: None,
            },
            "kube_workload_create",
            Some(resource),
            arguments,
            correlation,
        )
        .expect_err("the governed dispatch must refuse this create");

    let approvals = ledger
        .lock()
        .expect("ledger lock")
        .approvals()
        .expect("approval rows readable");
    // NOTHING may be journaled for this capsule — every operation row,
    // terminal committed effects included: a mistakenly committed effect
    // must fail here, not only a nonterminal one.
    let effects = odin_ledger::operation::rows_for_capsule(
        ledger.lock().expect("ledger lock").connection(),
        capsule.as_str(),
    )
    .expect("operation rows readable");
    (error, approvals.len(), effects.len())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_attempt_mismatch_refuses_preflight_and_mints_no_approval_row() {
    let proof = fixture();
    let root = proof.root.clone();

    // A SERVING projection: the profile's exact (lane, model) pair is
    // eligible, so the resolver binds and the Launch path is reached.
    let manifest = GatewayProjectionManifest::build(vec![GatewayProjectionRoute {
        gateway_lane_id: LANE.to_owned(),
        gateway_model_id: MODEL.to_owned(),
        account_handle: "fixture-account".to_owned(),
        endpoint: "https://gateway.internal:4000/v1".to_owned(),
        credential_handle: "fixture-credential".to_owned(),
        role: "serve".to_owned(),
        affinity_key: "fixture".to_owned(),
        eligible: true,
    }])
    .expect("projection builds");
    let bytes = serde_json::to_vec(&manifest).expect("serialize projection");
    let projection_path = root.join("gateway-projection-serving.json");
    std::fs::write(&projection_path, &bytes).expect("write projection");

    // Declare credentials so admission reaches the attempt mismatch check.
    let mut config_text = fixture_config_text(&root, &proof.store);
    config_text.push_str(&format!(
        "\n[kube]\n\
         kubeconfig = '{0}/kubeconfig'\n\
         cluster = 'unit-cluster'\n\
         namespace = 'unit-namespace'\n\
         request_timeout_seconds = 5\n\
         teardown_timeout_seconds = 5\n\
         image_identity = '{0}/workload-identity.json'\n\
         [kube.gateway_credentials.fixture-credential]\n\
         secret = 'fixture-gateway-secret'\n\
         key = 'master'\n",
        root.display()
    ));
    let mut config = odin_huginn::OdindConfig::parse(&config_text).expect("fixture config parses");
    config.catalogs.gateway_projection = PathDigestRef {
        path: projection_path,
        digest: Digest::hash(&bytes).to_string(),
    };
    // One durable ledger for the whole fabric: the dispatch/approval store
    // AND the admission journal whose kube_job_runs row declares the run's
    // admitted launch — attempt "workload-attempt-admitted".
    let ledger = Arc::new(Mutex::new(
        Ledger::open(root.join("dispatch-ledger.sqlite3")).expect("dispatch ledger"),
    ));
    let declared_attempt = "workload-attempt-admitted";
    // The run's durably declared launch, built with the REAL typed
    // constructor — every field complete, identities valid — then
    // serialized exactly as save_launch persists it.
    let declared_launch = odin_kube::JobLaunch {
        labels: odin_domain::huginn::KubeJobLabels {
            task_id: odin_domain::TaskId::new("workload-task-preflight-attempt").expect("task id"),
            run_id: RunId::new(POD_RUN).expect("run id"),
            attempt_id: AttemptId::new(declared_attempt).expect("attempt id"),
            seat_id: SeatId::new(SEAT).expect("seat id"),
            project_id: ProjectId::new(PROJECT).expect("project id"),
            lane_id: LaneId::new(LANE).expect("lane id"),
            model: MODEL.to_owned(),
            budget_policy_digest: Digest::hash(b"preflight-attempt-budget"),
            container_identity: Digest::hash(b"preflight-attempt-image"),
        },
        worker_id: odin_kernel::stop::mint_worker_id().expect("minted worker id"),
        extension: None,
        models_config: None,
        staging: Default::default(),
        checkpoint: None,
        image: "localhost/odin-workload:preflight".to_owned(),
        command: vec!["/bin/sh".to_owned(), "-c".to_owned()],
        args: vec!["exec true".to_owned()],
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: None,
        service: false,
        workload: None,
        operation_id: odin_types::OperationId::new("op-000000000000000000000000deadbeef")
            .expect("operation id"),
        idempotency_digest: Digest::hash(b"preflight-attempt-idempotency"),
    };
    assert_initial_target_checked_before_settled_replay(declared_launch.clone());
    {
        let guard = ledger.lock().expect("ledger lock");
        guard
            .connection()
            .execute(
                "INSERT INTO kube_job_runs(run_id,cluster,namespace,launch_json,created_at) \
                 VALUES(?1,?2,?3,?4,?5)",
                rusqlite::params![
                    POD_RUN,
                    "unit-cluster",
                    "unit-namespace",
                    serde_json::to_string(&declared_launch).expect("serialize launch"),
                    "2026-01-01T00:00:00Z",
                ],
            )
            .expect("seed the declared launch");
    }

    // The REAL runtime cell over that ledger: the preflight reads the
    // declared attempt from the durable journal, cluster-free. The stop
    // authority and channel are construction-only; nothing connects.
    let bus =
        odin_process::BusAddress::unix_socket(root.join("stop-bus.sock")).expect("bus address");
    let channel = odin_process::WorkerChannel::for_recovery(bus).expect("worker channel");
    let stops = Arc::new(odin_kernel::stop::StopAuthority::new(
        Arc::clone(&ledger),
        channel,
    ));
    let cell = KubeRuntimeCell::new(CellInputs {
        config: KubeConfig {
            kubeconfig: root.join("kubeconfig"),
            cluster: "unit-cluster".to_owned(),
            namespace: "unit-namespace".to_owned(),
            allowed_nodes: BTreeSet::new(),
            request_timeout: Duration::from_secs(5),
            teardown_timeout: Duration::from_secs(5),
        },
        ledger: Arc::clone(&ledger),
        stops,
        artifact_root: root.join("artifacts"),
        snapshot: proof.pin.current(),
        config_revision: 1,
        launch_binding: None,
        workload_identity: crate::kube::WorkloadExtensionIdentity {
            artifact: odin_domain::ArtifactId::new(
                Digest::hash(b"preflight-attempt-identity").to_string(),
            )
            .expect("artifact id"),
            deployment: Default::default(),
        },
    });

    let coordinator = Arc::new(KubeCommandCoordinator::new(Some(cell)));
    coordinator
        .arm_workload_port(Arc::new(LaunchPort {
            snapshot: Arc::clone(&proof.pin),
            composition: WorkloadComposition {
                laws: BTreeMap::new(),
                models: BTreeMap::from([(
                    PROFILE.to_owned(),
                    WorkloadModelPolicy::Exact {
                        provider: "gateway".to_owned(),
                        model: MODEL.to_owned(),
                    },
                )]),
                bindings: BTreeMap::from([(
                    PROFILE.to_owned(),
                    (
                        SliceId::new(SLICE).expect("slice id"),
                        LaneId::new(LANE).expect("lane id"),
                        NodeId::new("preflight").expect("node id"),
                    ),
                )]),
                skipped: Default::default(),
            },
            supervisor: Arc::new(OnceLock::new()),
            config,
            deployment: None,
            session_lanes: BTreeMap::new(),
        }))
        .expect("arm the workload launch port");

    let mut registry = HostToolRegistry::new();
    registry
        .register_kube_capabilities(Arc::clone(&coordinator) as Arc<dyn KubeCapabilityOwner>)
        .expect("register the real kube surface");
    let registry = Arc::new(registry);

    let snapshot = proof.pin.current();
    let contracts = odin_cli::runtime_bindings::operation_contracts(&snapshot.objects)
        .expect("the fixture registry derives the real capability contract");
    let seat = SeatId::new(SEAT).expect("seat id");
    let slice = SliceId::new(SLICE).expect("slice id");
    let lane = LaneId::new(LANE).expect("lane id");
    let project = ProjectId::new(PROJECT).expect("project id");
    let run = RunId::new(RUN).expect("run id");
    let session = SessionId::new(SESSION).expect("session id");
    let seat_revision = snapshot
        .objects
        .iter()
        .find(|object| object.kind() == odin_registry::RegistryKind::Seat && object.id == SEAT)
        .expect("fixture seat object")
        .canonical_bytes()
        .map(|bytes| Digest::hash(&bytes))
        .expect("seat canonical bytes");
    let slice_revision = Digest::hash(b"preflight fixture slice");
    let admission = admission_digest(&contracts, 1).expect("admission digest");
    let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
    let resource = ResourceConstraint::Named {
        kind: "workspace".to_owned(),
        value: "preflight".to_owned(),
    };
    let policy = seat_operation_policy(SeatOperationPolicyInputs {
        seat_id: seat.clone(),
        slice_id: slice.clone(),
        lane_id: lane.clone(),
        seat_revision,
        slice_revision,
        admission,
        seat_tool_refs: allowed.clone(),
        slice_capabilities: allowed.clone(),
        project_capabilities: allowed.clone(),
        lane_capabilities: allowed,
        denied_capabilities: BTreeSet::new(),
        denied_tools: BTreeSet::new(),
        resource_constraints: contracts
            .keys()
            .map(|id| (id.clone(), vec![resource.clone()]))
            .collect::<BTreeMap<_, _>>(),
        seat_categories: BTreeSet::from([SEAT.to_owned()]),
    });

    let issued_at_ms = (odin_omp::host_tools::operations::wall_clock())();
    let token_root = root.join("authority-tokens");
    std::fs::create_dir_all(&token_root).expect("token root");
    let signing_key = {
        let mut key = b"preflight attempt mismatch fixture signing key".to_vec();
        key.truncate(32);
        key
    };
    let token = TokenIssuer::new(signing_key.clone())
        .expect("token issuer")
        .mint(MintRequest {
            seat: seat.clone(),
            slice: slice.clone(),
            lane: lane.clone(),
            session: session.clone(),
            seat_revision,
            slice_revision,
            capability_policy_digest: admission,
            context_policy_digest: policy.context_policy_digest,
            issued_at_ms,
            expires_at_ms: issued_at_ms + 3_600_000,
            entropy: b"preflight attempt mismatch fixture token",
        })
        .expect("mint fixture session token");
    std::fs::write(
        token_root.join(format!("{}.json", session.as_str())),
        serde_json::to_vec(&token).expect("encode token"),
    )
    .expect("write provisioned token");
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
            schemas: Arc::new(FilesystemSchemaCatalog::new(&proof.schema_root)),
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
                seat.clone(),
                lane.clone(),
                project.clone(),
            )),
        },
        contracts.clone(),
        authority_provider,
    )
    .expect("operation stack");

    // Seed the bridge lane/run/plan alongside the declared workload launch.
    {
        let mut guard = ledger.lock().expect("ledger lock");
        odin_ledger::lane_run::create_lane(
            guard.connection(),
            &NewLane {
                lane_id: lane.clone(),
                seat_id: seat.clone(),
                project_id: Some(project.clone()),
                template_id: "template:preflight".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "operator:fixture".to_owned(),
                created_at: OffsetDateTime::UNIX_EPOCH,
                retained: false,
            },
        )
        .expect("fixture bridge lane");
        odin_ledger::lane_run::create_run(
            guard.connection(),
            &NewRun {
                run_id: run.clone(),
                lane_id: lane.clone(),
                attempt_number: 1,
                workflow_id: Some("live:preflight".to_owned()),
                workflow_version: Some(1),
                input_hash: "preflight".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
        )
        .expect("fixture bridge run");
        let plan = guard
            .replace_plan(
                &run,
                "Launch the declared workload profile",
                &[TodoSpec {
                    id: odin_domain::TodoId::new("todo:preflight-attempt").expect("todo id"),
                    title: "Launch the declared workload profile".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan");
        guard
            .accept_plan(
                &run,
                plan.revision,
                "operator:fixture",
                OffsetDateTime::UNIX_EPOCH,
            )
            .expect("fixture plan acceptance");
    }

    // The dispatch declares an explicit attempt that DIFFERS from the
    // run's durably declared one. Every other gate is satisfied, so the
    // ONLY possible verdict is the preflight attempt refusal — before any
    // approval is minted or any admission material is registered.
    let minted = AttemptId::new("workload-attempt-dispatched").expect("attempt id");
    let error = operations
        .dispatch_tool(
            SessionOperationContext {
                binding: &SessionOperationBinding {
                    policy: policy.policy,
                    context_policy_digest: policy.context_policy_digest,
                    capsule_id: session_capsule_id(&session).expect("capsule id"),
                    served_revision: 1,
                    parent: None,
                },
                session: &session,
                scope: &Scope {
                    seat: Some(seat),
                    project: Some(project),
                    lane: Some(lane),
                    run: Some(run),
                    session: Some(session.clone()),
                    attempt: Some(minted),
                    ..Scope::default()
                },
                execution: None,
            },
            "kube_workload_create",
            Some(resource),
            json!({ "profile": PROFILE }),
            "preflight-attempt-mismatch-1",
        )
        .expect_err("an explicit attempt mismatch must refuse the dispatch");
    let refusal = match &error {
        HostToolOperationError::Arguments { detail } => detail,
        other => panic!("expected the typed attempt-law refusal, got {other:?}"),
    };
    assert!(
        refusal.contains(declared_attempt) && refusal.contains("workload-attempt-dispatched"),
        "the refusal must name both the declared and the mismatched attempt: {refusal}"
    );

    let approvals = ledger
        .lock()
        .expect("ledger lock")
        .approvals()
        .expect("approval rows readable");
    assert!(
        approvals.is_empty(),
        "an attempt mismatch must mint ZERO approval rows, found {approvals:?}"
    );
}

// Node-local gateway endpoint preflight checks.

/// A declared node-local gateway endpoint that cannot resolve: the
/// reserved `.invalid` TLD never answers, so the bounded probe always
/// refuses without depending on any machine-local listener.
const UNRESOLVABLE_GATEWAY_ENDPOINT: &str = "http://node-gateway.invalid:14000/v1";

// Valid routing and credentials isolate endpoint validation.
fn serving_config(root: &Path, store: &Path) -> odin_huginn::OdindConfig {
    let manifest = GatewayProjectionManifest::build(vec![GatewayProjectionRoute {
        gateway_lane_id: LANE.to_owned(),
        gateway_model_id: MODEL.to_owned(),
        account_handle: "fixture-account".to_owned(),
        endpoint: "https://gateway.internal:4000/v1".to_owned(),
        credential_handle: "fixture-credential".to_owned(),
        role: "serve".to_owned(),
        affinity_key: "fixture".to_owned(),
        eligible: true,
    }])
    .expect("projection builds");
    let bytes = serde_json::to_vec(&manifest).expect("serialize projection");
    let projection_path = root.join("gateway-projection-endpoint.json");
    std::fs::write(&projection_path, &bytes).expect("write projection");

    let mut config_text = fixture_config_text(root, store);
    config_text.push_str(&format!(
        "\n[kube]\n\
         kubeconfig = '{0}/kubeconfig'\n\
         cluster = 'unit-cluster'\n\
         namespace = 'unit-namespace'\n\
         request_timeout_seconds = 5\n\
         teardown_timeout_seconds = 5\n\
         image_identity = '{0}/workload-identity.json'\n\
         [kube.gateway_credentials.fixture-credential]\n\
         secret = 'fixture-gateway-secret'\n\
         key = 'master'\n",
        root.display()
    ));
    let mut config = odin_huginn::OdindConfig::parse(&config_text).expect("fixture config parses");
    config.catalogs.gateway_projection = PathDigestRef {
        path: projection_path,
        digest: Digest::hash(&bytes).to_string(),
    };
    config
}

/// The real workload launch port over the fixture snapshot, with the profile
/// explicitly bound to `target_node`.
fn launch_port(
    pin: Arc<SnapshotHandle>,
    config: odin_huginn::OdindConfig,
    target_node: &str,
) -> Arc<LaunchPort> {
    Arc::new(LaunchPort {
        snapshot: pin,
        composition: WorkloadComposition {
            laws: BTreeMap::new(),
            models: BTreeMap::from([(
                PROFILE.to_owned(),
                WorkloadModelPolicy::Exact {
                    provider: "gateway".to_owned(),
                    model: MODEL.to_owned(),
                },
            )]),
            bindings: BTreeMap::from([(
                PROFILE.to_owned(),
                (
                    SliceId::new(SLICE).expect("slice id"),
                    LaneId::new(LANE).expect("lane id"),
                    NodeId::new(target_node).expect("node id"),
                ),
            )]),
            skipped: Default::default(),
        },
        supervisor: Arc::new(OnceLock::new()),
        config,
        deployment: None,
        session_lanes: BTreeMap::new(),
    })
}

/// Runs the production pre-mint preflight for the fixture profile bound to
/// `target_node`, exactly as the dispatch calls it.
fn preflight_create(
    pin: Arc<SnapshotHandle>,
    config: odin_huginn::OdindConfig,
    target_node: &str,
) -> Result<(), odin_omp::host_tools::HostToolError> {
    let coordinator = KubeCommandCoordinator::new(None);
    coordinator
        .arm_workload_port(launch_port(pin, config, target_node))
        .expect("arm the workload launch port");
    coordinator.preflight_create(
        &Scope {
            seat: Some(SeatId::new(SEAT).expect("seat id")),
            project: Some(ProjectId::new(PROJECT).expect("project id")),
            lane: Some(LaneId::new(LANE).expect("lane id")),
            run: Some(RunId::new(RUN).expect("run id")),
            ..Scope::default()
        },
        &json!({ "profile": PROFILE }),
    )
}

// Input admission reaches launch; this fixture then refuses because it has no cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_pod_create_accepts_declared_input_artifacts() {
    let proof = fixture_with_nodes(&[(
        "preflight",
        preflight_node_toml("preflight", true, Some(GATEWAY_ENDPOINT)),
    )]);
    let coordinator = KubeCommandCoordinator::new(None);
    coordinator
        .arm_workload_port(launch_port(
            Arc::clone(&proof.pin),
            serving_config(&proof.root, &proof.store),
            "preflight",
        ))
        .expect("arm the workload launch port");
    let error = coordinator
        .create(
            "kube_workload_create",
            60,
            odin_types::OperationId::new("op-agent-pod-inputs").expect("operation id"),
            odin_omp::host_tools::HostInvocation {
                scope: Scope {
                    seat: Some(SeatId::new(SEAT).expect("seat id")),
                    project: Some(ProjectId::new(PROJECT).expect("project id")),
                    lane: Some(LaneId::new(LANE).expect("lane id")),
                    run: Some(RunId::new(RUN).expect("run id")),
                    ..Scope::default()
                },
                arguments: json!({ "profile": PROFILE, "inputs": ["blake3:surtr-readme"] }),
            },
        )
        .await
        .expect_err("the fixture has no cluster to launch on");
    assert!(
        !error.to_string().contains("takes no inputs"),
        "an agent pod must accept declared inputs: {error}"
    );
    assert!(
        matches!(
            error,
            odin_omp::host_tools::HostToolError::Unavailable { .. }
        ),
        "the create proceeds to the launch path: {error:?}"
    );
}

/// A selected target node that declares NO node-local gateway endpoint
/// refuses the pre-mint preflight typed: the owning node-declaration seam's
/// reason names the node, and nothing is minted. A snapshot published before
/// the endpoint declaration existed (or a node that never admitted
/// workloads) is exactly this shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_node_gateway_endpoint_refuses_the_pre_mint_preflight() {
    let proof = fixture_with_nodes(&[("preflight", preflight_node_toml("preflight", false, None))]);
    let error = preflight_create(
        Arc::clone(&proof.pin),
        serving_config(&proof.root, &proof.store),
        "preflight",
    )
    .expect_err("a node without a declared gateway endpoint must refuse");
    let detail = error.to_string();
    assert!(
        matches!(error, odin_omp::host_tools::HostToolError::Arguments { .. }),
        "the declaration refusal is argument-class: {error:?}"
    );
    assert!(
        detail.contains("\"preflight\"") && detail.contains("gateway endpoint"),
        "the refusal must name the selected node and the missing declaration: {detail}"
    );
}

/// A selected target node whose declared endpoint cannot be reached refuses
/// the pre-mint preflight as the typed pre-effect `unavailable`, naming the
/// declared endpoint and the probe's exact boundary — no pod-namespace or
/// provider-health claim, and no approval minted for a gateway that does not
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_node_gateway_endpoint_refuses_the_pre_mint_preflight() {
    let proof = fixture_with_nodes(&[(
        "preflight",
        preflight_node_toml("preflight", true, Some(UNRESOLVABLE_GATEWAY_ENDPOINT)),
    )]);
    let error = preflight_create(
        Arc::clone(&proof.pin),
        serving_config(&proof.root, &proof.store),
        "preflight",
    )
    .expect_err("an unreachable declared gateway endpoint must refuse");
    let reason = match &error {
        odin_omp::host_tools::HostToolError::Unavailable { reason, .. } => reason,
        other => panic!("expected the typed pre-flight unavailability, got {other:?}"),
    };
    assert!(
        reason.contains("node-gateway.invalid:14000")
            && reason.contains("does not resolve")
            && reason.contains("measured boundary"),
        "the refusal must name the declared endpoint and its measured boundary: {reason}"
    );
}

// Select the second node to catch accidental use of the first node's endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_node_binds_its_own_endpoint_into_models_config_and_egress_pin() {
    let proof = fixture_with_nodes(&[
        (
            // The non-selected neighbor is deliberately NOT the authority: the
            // registry admits exactly one enabled authoritative node.
            "aaa-other",
            preflight_node_toml("aaa-other", true, Some("http://aaa-other.invalid:4000/v1"))
                .replace("authoritative_state = true", "authoritative_state = false"),
        ),
        (
            "zzz-selected",
            preflight_node_toml(
                "zzz-selected",
                true,
                Some("http://zzz-selected.invalid:15001/v1"),
            ),
        ),
    ]);
    let port = launch_port(
        Arc::clone(&proof.pin),
        serving_config(&proof.root, &proof.store),
        "zzz-selected",
    );
    let inputs = match crate::kube_runtime::WorkloadLaunchPort::resolve_launch(&*port, PROFILE) {
        crate::kube_runtime::WorkloadResolve::Launch(inputs) => inputs,
        crate::kube_runtime::WorkloadResolve::Refused(reason) => {
            panic!("the selected node's declared endpoint must resolve: {reason}")
        }
        crate::kube_runtime::WorkloadResolve::NotWorkload
        | crate::kube_runtime::WorkloadResolve::Script(_) => {
            panic!("the fixture profile is an agent workload profile")
        }
    };
    assert_eq!(inputs.target_node.as_str(), "zzz-selected");
    assert_eq!(
        inputs.gateway.as_str(),
        "http://zzz-selected.invalid:15001/v1"
    );
    assert_eq!(inputs.gateway.host(), "zzz-selected.invalid");
    assert_eq!(inputs.gateway.port(), 15001);

    let document = crate::kube_runtime::models_config::compose_models_document(
        "kube.workload.create",
        inputs.provider.as_str(),
        inputs.model.as_str(),
        &inputs.gateway,
    )
    .expect("the selected endpoint composes the models document");
    let text = String::from_utf8(document.bytes).expect("the document is utf8");
    assert!(
        text.contains("\"baseUrl\":\"http://zzz-selected.invalid:15001/v1\""),
        "the models config carries the selected node's endpoint: {text}"
    );
    // 10-04: pod sessions sent no spend tags, so the gateway accounted
    // none of their requests per seat or session.
    assert!(
        text.contains("\"headers\":{\"x-litellm-tags\":\"ODIN_SPEND_TAG\"}"),
        "the pod's requests carry the session's spend tags: {text}"
    );

    let rendered = serde_json::to_value(odin_kube::workload::egress_rules(
        &odin_kube::workload::ResolvedEgress {
            sites: BTreeMap::new(),
            pinned: vec![(
                odin_kube::workload::WorkloadGatewayTarget {
                    host: inputs.gateway.host().to_owned(),
                    port: inputs.gateway.port(),
                },
                BTreeSet::from(["10.42.0.9".parse::<std::net::IpAddr>().expect("ip")]),
            )],
        },
    ))
    .expect("the egress rules serialize");
    assert_eq!(
        rendered[1]["to"][0]["ipBlock"]["cidr"],
        json!("10.42.0.9/32")
    );
    let ports = rendered[1]["ports"]
        .as_array()
        .expect("the gateway pin declares ports")
        .iter()
        .map(|port| port["port"].as_i64().expect("an integer TCP port"))
        .collect::<Vec<_>>();
    assert_eq!(
        ports,
        vec![15001],
        "the gateway pin carries the selected endpoint's own port"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreachable_endpoint_refuses_the_governed_dispatch_and_mints_no_approval_row() {
    let proof = fixture_with_nodes(&[(
        "preflight",
        preflight_node_toml("preflight", true, Some(UNRESOLVABLE_GATEWAY_ENDPOINT)),
    )]);
    let config = serving_config(&proof.root, &proof.store);
    let (error, approvals, effects) =
        dispatch_create_to_verdict(&proof, config, "preflight-endpoint-unreachable-1").await;
    let detail = match &error {
        HostToolOperationError::Arguments { detail } => detail,
        other => panic!("expected the typed preflight refusal, got {other:?}"),
    };
    assert!(
        detail.contains("node-gateway.invalid:14000") && detail.contains("unavailable"),
        "the dispatch must refuse the unreachable declared gateway typed: {detail}"
    );
    assert_eq!(
        approvals, 0,
        "an unreachable declared gateway must mint ZERO approval rows"
    );
    assert_eq!(
        effects, 0,
        "an unreachable declared gateway must journal ZERO operation rows — no effect of any \
         state, terminal committed effects included"
    );
}

/// Kubert restarted the failed arXiv pod run after a
/// deploy; the restart cloned the admitted launch's image, which the deploy
/// had replaced and pruned, so the pod sat in ImagePullBackOff (and the old
/// image lacked the fix the deploy carried). Such a restart is refused with
/// the reason; a container-profile launch or the current image restarts.
#[test]
fn a_restart_onto_a_replaced_workload_image_is_refused() {
    let old = "localhost/odin-workload@sha256:f45e";
    let deployed = "localhost/odin-workload@sha256:0b7c";
    let mut launch = odin_kube::JobLaunch {
        labels: odin_domain::huginn::KubeJobLabels {
            task_id: odin_domain::TaskId::new("workload-task-restart").expect("task id"),
            run_id: RunId::new(RUN).expect("run id"),
            attempt_id: AttemptId::new("workload-attempt-restart").expect("attempt id"),
            seat_id: SeatId::new(SEAT).expect("seat id"),
            project_id: ProjectId::new(PROJECT).expect("project id"),
            lane_id: LaneId::new(LANE).expect("lane id"),
            model: MODEL.to_owned(),
            budget_policy_digest: Digest::hash(b"restart-budget"),
            container_identity: Digest::hash(b"restart-image"),
        },
        worker_id: odin_kernel::stop::mint_worker_id().expect("minted worker id"),
        extension: Some(odin_kube::job::JobExtensionLaunch {
            verifier: "/odin/bin/odind".to_owned(),
            trusted_extension: "/odin/lib/odin.ts".to_owned(),
            policy_artifact: odin_domain::ArtifactId::new(
                Digest::hash(b"restart-policy").to_string(),
            )
            .expect("artifact id"),
            policy_digest: Digest::hash(b"restart-policy").to_string(),
        }),
        models_config: None,
        staging: Default::default(),
        checkpoint: None,
        image: old.to_owned(),
        command: Vec::new(),
        args: Vec::new(),
        node_selector: BTreeMap::new(),
        initial_target_node: None,
        gpu_count: 0,
        deadline_seconds: None,
        service: false,
        workload: None,
        operation_id: odin_types::OperationId::new("op-000000000000000000000000deadbeef")
            .expect("operation id"),
        idempotency_digest: Digest::hash(b"restart-idempotency"),
    };
    let refusal = super::replaced_image_refusal(&launch, deployed).expect("refused");
    assert!(
        refusal.contains(old) && refusal.contains(deployed),
        "{refusal}"
    );
    assert!(refusal.contains("kube_workload_create"), "{refusal}");
    launch.image = deployed.to_owned();
    assert_eq!(super::replaced_image_refusal(&launch, deployed), None);
    launch.image = old.to_owned();
    launch.extension = None;
    assert_eq!(super::replaced_image_refusal(&launch, deployed), None);
}
