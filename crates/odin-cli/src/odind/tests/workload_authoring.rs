//! Workload authoring recovery and races through isolated Git and snapshot stores.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ResourceConstraint;
use odin_domain::operation::Limits;
use odin_domain::{Digest, LaneId, ProjectId, RunId, Scope, SeatId, SessionId, SliceId};
use odin_kernel::{MintRequest, TokenIssuer};
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
use odin_omp::host_tools::{HostToolRegistry, InternalBindingKey};
use odin_registry::{SnapshotHandle, SnapshotStore, ValidatedSnapshotCandidate};
use serde_json::json;
use tempfile::TempDir;
use time::OffsetDateTime;

use super::DaemonWorkloadAuthoring;
use crate::test_fixture::{git_bytes, odind_host_toml, odind_node_toml};
use crate::test_support::{commit_all, git};
use odin_hermes::runtime::{
    WorkloadAuthoringFailure, WorkloadAuthoringRoute, WorkloadDraftAnswers, WorkloadDraftRequest,
    WorkloadPublishRequest,
};

/// Builds an isolated authoring deployment: a committed Git worktree with
/// the real skeleton catalog, one provider, one project, one seat, and the
/// real `workload.draft`/`workload.publish` capability declarations; a
/// published revision-1 store over it; and the route bound to the same
/// active pin a launch seam would read.
struct Fixture {
    _dir: TempDir,
    worktree: PathBuf,
    store: PathBuf,
    route: Arc<DaemonWorkloadAuthoring>,
    pin: Arc<SnapshotHandle>,
    ledger_path: PathBuf,
    /// The Odin repository root the production schema catalog loads the
    /// canonical capability schemas from.
    repo_root: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("fixture root");
    // A real LINKED Git worktree over a seed repository: the author stage
    // refuses a plain `git init` checkout, exactly as production refuses
    // authoring outside an isolated worktree of the Odin repository.
    let seed = dir.path().join("seed");
    std::fs::create_dir(&seed).expect("seed");
    git(&seed, &["-c", "init.defaultBranch=main", "init"]);
    // Persist repo-local identity for the plain `git commit` the production
    // publish stage runs; the linked worktree shares this seed config.
    git(&seed, &["config", "user.name", "Odin Test"]);
    git(
        &seed,
        &["config", "user.email", "odin-test@example.invalid"],
    );
    git(&seed, &["config", "commit.gpgsign", "false"]);
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
            "authoring",
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
    std::fs::create_dir_all(worktree.join("schemas")).expect("schemas root");
    std::fs::write(worktree.join("schemas/.gitkeep"), b"").expect("schemas placeholder");

    // The REAL skeleton catalog: the draft path under test must compile
    // against the exact declared contract, never a test-shaped copy, and
    // the catalog validates every fixed skeleton folder, so the fixture
    // mirrors the repository's skeletons/ tree verbatim.
    let repo_skeletons = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skeletons");
    for entry in std::fs::read_dir(&repo_skeletons).expect("repository skeleton catalog") {
        let entry = entry.expect("skeleton entry");
        if !entry.file_type().expect("skeleton entry type").is_dir() {
            continue;
        }
        for file in ["TEMPLATE.toml", "variables.toml"] {
            let declared =
                std::fs::read_to_string(entry.path().join(file)).unwrap_or_else(|error| {
                    panic!(
                        "skeleton {} is missing {file}: {error}",
                        entry.file_name().to_string_lossy()
                    )
                });
            let destination = worktree.join("skeletons").join(entry.file_name());
            std::fs::create_dir_all(&destination).expect("skeleton directory");
            std::fs::write(destination.join(file), declared).expect("skeleton file");
        }
    }

    let provider = worktree.join("registry/providers/gateway");
    std::fs::create_dir_all(&provider).expect("provider directory");
    std::fs::write(
        provider.join("provider.toml"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../registry/providers/gateway/provider.toml"
        )),
    )
    .expect("provider");

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

    let project = worktree.join("registry/projects/home");
    std::fs::create_dir_all(&project).expect("project directory");
    std::fs::write(
        project.join("project.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"project\"\n",
            "enabled = true\n",
            "description = \"fixture project\"\n",
            "source_root = \"\"\n",
            "default_seat = \"coordinator\"\n",
            "memory_namespaces = [\"atlas.personal\"]\n",
            "artifact_policy = \"standard\"\n",
        ),
    )
    .expect("project");

    let seat = worktree.join("registry/seats/coordinator");
    std::fs::create_dir_all(&seat).expect("seat directory");
    std::fs::write(
        seat.join("seat.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\n",
            "kind = \"seat\"\n",
            "enabled = true\n",
            "description = \"fixture conversation seat\"\n",
            "categories = [\"coordinator\"]\n",
            "tool_refs = []\n",
            "project_scope = [\"home\"]\n",
            "brain_scope = [\"atlas.personal\"]\n",
            "limits = { max_parallel_runs = 8, max_sessions = 4, budget = { usd_micros = 30000000, window = { duration_seconds = 2592000 } } }\n",
        ),
    )
    .expect("seat");
    let node_directory = worktree.join("registry/nodes/authoring");
    std::fs::create_dir_all(&node_directory).expect("node directory");
    std::fs::write(
        node_directory.join("node.toml"),
        odind_node_toml("authoring", true),
    )
    .expect("node");
    let host_directory = worktree.join("registry/hosts/authoring-host");
    std::fs::create_dir_all(&host_directory).expect("host directory");
    std::fs::write(
        host_directory.join("host.toml"),
        odind_host_toml("authoring"),
    )
    .expect("host");
    // The REAL governed authoring capability declarations: the dispatch
    // stack under test derives its contracts from these committed objects
    // through the production `operation_contracts` derivation, exactly as
    // the daemon derives them from a published snapshot.
    for (capability, declared) in [
        (
            "workload.draft",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../registry/capabilities/workload.draft/capability.toml"
            )),
        ),
        (
            "workload.publish",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../registry/capabilities/workload.publish/capability.toml"
            )),
        ),
    ] {
        let directory = worktree.join("registry/capabilities").join(capability);
        std::fs::create_dir_all(&directory).expect("capability directory");
        std::fs::write(directory.join("capability.toml"), declared).expect("capability");
    }
    // Their toolset, declared with examples of the two ops this registry holds.
    let toolset = worktree.join("registry/toolsets/odin");
    std::fs::create_dir_all(&toolset).expect("toolset directory");
    std::fs::write(
        toolset.join("toolset.toml"),
        concat!(
            "schema = \"odin.registry.v1\"\nkind = \"toolset\"\nenabled = true\n",
            "description = \"Fixture pod authoring.\"\n",
            "examples = ['odin {op: \"draft\"}', 'odin {op: \"publish\"}']\n",
        ),
    )
    .expect("toolset");
    // The REAL canonical schemas the capability declarations reference:
    // relation validation resolves input/output schema references against
    // the committed worktree, exactly as production publication does.
    for schema in [
        "workload.draft.input.json",
        "workload.draft.output.json",
        "workload.publish.input.json",
        "workload.publish.output.json",
    ] {
        let declared = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/capability")
                .join(schema),
        )
        .unwrap_or_else(|error| panic!("schema {schema} is missing: {error}"));
        let destination = worktree.join("schemas/capability");
        std::fs::create_dir_all(&destination).expect("schema directory");
        std::fs::write(destination.join(schema), declared).expect("schema file");
    }

    // The two lanes the fixture seats run, plus every card their fallbacks reach (publication refuses a dangling fallback).
    let mut lanes = vec!["zai-glm".to_owned(), "glm-flash".to_owned()];
    let mut next = 0;
    while let Some(lane) = lanes.get(next).cloned() {
        next += 1;
        let card = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../registry/models")
                .join(&lane)
                .join("model.toml"),
        )
        .expect("model card");
        let fallbacks = toml::from_str::<toml::Value>(&card)
            .expect("model card toml")
            .get("fallbacks")
            .and_then(toml::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for fallback in fallbacks.iter().filter_map(toml::Value::as_str) {
            if !lanes.iter().any(|known| known == fallback) {
                lanes.push(fallback.to_owned());
            }
        }
        let directory = worktree.join("registry/models").join(&lane);
        std::fs::create_dir_all(&directory).expect("model card directory");
        std::fs::write(directory.join("model.toml"), card).expect("write model card");
    }

    commit_all(&worktree, "fixture registry base");
    let store = dir.path().join("state/registry/snapshot.json");
    let candidate = ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &git(&worktree, &["rev-parse", "HEAD"]),
        odin_omp::host_tools::production_bindings()
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("fixture base candidate");
    SnapshotStore::new(&store)
        .publish_committed(&candidate, 1)
        .expect("fixture base publication");
    let pin = Arc::new(SnapshotHandle::open(SnapshotStore::new(&store)).expect("fixture pin"));
    let ledger_path = dir.path().join("state/ledger.sqlite3");
    std::fs::create_dir_all(dir.path().join("state")).expect("fixture state root");
    let route = DaemonWorkloadAuthoring::new(
        Arc::clone(&pin),
        worktree.clone(),
        store.clone(),
        dir.path().join("state/ledger.sqlite3"),
        dir.path().join("state"),
        Some(fixture_deployment()),
        None,
    )
    .expect("the fixture route seals its draft store")
    .with_gateway(Some(fixture_gateway()));
    let route = Arc::new(route);
    Fixture {
        _dir: dir,
        worktree,
        store,
        route,
        pin,
        ledger_path,
        repo_root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
    }
}

impl Fixture {
    fn pin_handle(&self) -> Arc<SnapshotHandle> {
        Arc::clone(&self.pin)
    }

    fn ledger_path(&self) -> PathBuf {
        self.ledger_path.clone()
    }

    fn state_root(&self) -> PathBuf {
        self.ledger_path
            .parent()
            .expect("the ledger lives in the state root")
            .to_path_buf()
    }
}

const IMAGE: &str = concat!(
    "localhost/odin-site-agent@sha256:",
    "2222222222222222222222222222222222222222222222222222222222222222"
);

/// The chat lanes the fixture's drafts may use, as a pinned gateway projection.
fn fixture_gateway() -> odin_registry::GatewayProjectionManifest {
    let route = |lane: &str, model: &str| odin_registry::GatewayProjectionRoute {
        gateway_lane_id: lane.to_owned(),
        gateway_model_id: model.to_owned(),
        account_handle: "litellm-loopback".to_owned(),
        endpoint: "http://127.0.0.1:4000/v1".to_owned(),
        credential_handle: "litellm-master-key".to_owned(),
        role: "coding".to_owned(),
        affinity_key: lane.to_owned(),
        eligible: true,
    };
    odin_registry::GatewayProjectionManifest::build(vec![
        route("glm-flash", "openai/glm-5.3-flash"),
        route("kimi-k31", "openai/kimi-for-coding"),
        route("zai-glm", "openai/glm-5.3"),
    ])
    .expect("fixture gateway projection")
}

fn fixture_deployment() -> crate::kube::WorkloadDeploymentFacts {
    crate::kube::WorkloadDeploymentFacts {
        image_reference: IMAGE.to_owned(),
        launcher: "/odin/bin/omp".to_owned(),
        browser: "/odin/bin/chromium".to_owned(),
        supervisor: "/odin/bin/odin-browser-supervisor".to_owned(),
        playwright: "/odin/lib/playwright-core".to_owned(),
        xvfb: "/odin/bin/Xvfb".to_owned(),
        state_path: Some("/state".to_owned()),
        export_pod_path: Some("/export".to_owned()),
        export_host_folder: Some("/tmp/export".to_owned()),
        agent_lane: None,
    }
}

fn complete_answers() -> WorkloadDraftAnswers {
    WorkloadDraftAnswers {
        description: Some("confined browser agent".to_owned()),
        enabled: Some(true),
        seat: Some("coordinator".to_owned()),
        project: Some("home".to_owned()),
        gateway_lane: Some("zai-glm".to_owned()),
        allow_hosts: Some(vec!["example.com".to_owned()]),
        screen: Some("1280x720x24".to_owned()),
        stream: Some(true),
        state_path: Some("/state".to_owned()),
        state_storage: Some("2Gi".to_owned()),
        export_pod_path: Some("/export".to_owned()),
        export_host_folder: Some("/tmp/export".to_owned()),
        brief_text: Some("Take one screenshot of the allowlisted site.".to_owned()),
        memory_namespace: Some("atlas.personal".to_owned()),
        deadline_seconds: Some(3600),
        ..WorkloadDraftAnswers::default()
    }
}

fn draft_request(profile_id: &str, answers: WorkloadDraftAnswers) -> WorkloadDraftRequest {
    WorkloadDraftRequest {
        profile_id: profile_id.to_owned(),
        answers,
        expected_registry_revision: None,
    }
}

fn publish_request(
    profile_id: &str,
    digest: &str,
    expected_revision: u64,
) -> WorkloadPublishRequest {
    WorkloadPublishRequest {
        profile_id: profile_id.to_owned(),
        declaration_digest: digest.to_owned(),
        expected_registry_revision: expected_revision,
    }
}

fn store_revision(store: &Path) -> u64 {
    SnapshotStore::new(store)
        .load_verified()
        .expect("active publication")
        .revision
}

// Dispatch through the production operation stack and compare published bytes with Git objects.

const DISPATCH_SEAT: &str = "coordinator";
const DISPATCH_SLICE: &str = "coordinator";
const DISPATCH_LANE: &str = "authoring";
const DISPATCH_PROJECT: &str = "home";
const DISPATCH_RUN: &str = "run.authoring-publish-proof";
const DISPATCH_SESSION: &str = "00000000-0000-4000-8000-00000000c0de";

struct GovernedDispatch {
    operations: HostToolOperations,
    binding: SessionOperationBinding,
    ledger: Arc<Mutex<Ledger>>,
    session: SessionId,
    scope: Scope,
    resource: ResourceConstraint,
}

impl GovernedDispatch {
    fn compose(fixture: &Fixture) -> Self {
        let state_root = fixture.state_root();
        let installed = SnapshotStore::new(&fixture.store)
            .load_verified()
            .expect("fixture installed snapshot");
        let contracts = odin_cli::runtime_bindings::operation_contracts(&installed.objects)
            .expect("the fixture registry derives the real capability contracts");

        // Share the conversation ledger as `hermes_routes::bind` does.
        let settings = odin_hermes::config::HermesSettings::new(
            state_root.join("hermes"),
            None,
            None,
            Vec::new(),
        )
        .expect("hermes settings");
        let runtime = odin_hermes::runtime::HermesRuntime::open(
            settings,
            odin_hermes::runtime::HermesLedgers {
                conversation: Ledger::open(&fixture.ledger_path).expect("hermes ledger"),
                adapter: Arc::new(parking_lot::Mutex::new(
                    Ledger::open(&fixture.ledger_path).expect("adapter ledger"),
                )),
                purchase: Arc::new(Mutex::new(
                    Ledger::open(&fixture.ledger_path).expect("purchase ledger"),
                )),
            },
            &contracts,
            None,
            0,
            BTreeMap::new(),
            None,
        )
        .expect("hermes runtime");
        runtime.set_workload_authoring_route(
            Arc::clone(&fixture.route) as Arc<dyn WorkloadAuthoringRoute>
        );

        // The real tool registry: every listed hermes surface plus the exact
        // internal handler/extractor bindings the kernel executor resolves.
        let mut registry = HostToolRegistry::new();
        for tool in odin_hermes::runtime::hermes_host_tools(&runtime) {
            registry.register(tool).expect("listed hermes tool");
        }
        for (id, tool) in odin_hermes::runtime::hermes_capability_bindings(&runtime) {
            registry
                .register_internal(InternalBindingKey::Builtin(id.to_owned()), tool)
                .expect("hermes capability binding");
        }
        let registry = Arc::new(registry);

        let seat = SeatId::new(DISPATCH_SEAT).expect("seat id");
        let slice = SliceId::new(DISPATCH_SLICE).expect("slice id");
        let lane = LaneId::new(DISPATCH_LANE).expect("lane id");
        let project = ProjectId::new(DISPATCH_PROJECT).expect("project id");
        let run = RunId::new(DISPATCH_RUN).expect("run id");
        let session = SessionId::new(DISPATCH_SESSION).expect("session id");
        let seat_revision = installed
            .objects
            .iter()
            .find(|object| {
                object.kind() == odin_registry::RegistryKind::Seat && object.id == DISPATCH_SEAT
            })
            .expect("fixture seat object")
            .canonical_bytes()
            .map(|bytes| Digest::hash(&bytes))
            .expect("seat canonical bytes");
        // The fixture declares no slice object: the token, the policy, and
        // the provider all bind the same fixture slice revision.
        let slice_revision = Digest::hash(b"authoring fixture slice");
        let admission = admission_digest(&contracts, 1).expect("admission digest");
        let allowed = contracts.keys().cloned().collect::<BTreeSet<_>>();
        let resource = ResourceConstraint::Named {
            kind: "workspace".to_owned(),
            value: "authoring".to_owned(),
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
            seat_categories: BTreeSet::from([DISPATCH_SEAT.to_owned()]),
        });

        // The provisioned session authority: a genuine signed token file the
        // provider re-verifies on every dispatch, against the REAL clock —
        // issued now, valid one hour, exactly like a provisioned session.
        let issued_at_ms = (odin_omp::host_tools::operations::wall_clock())();
        let token_root = state_root.join("authority-tokens");
        std::fs::create_dir_all(&token_root).expect("token root");
        let signing_key = {
            let mut key = b"authoring dispatch fixture signing key bytes".to_vec();
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
                entropy: b"authoring dispatch fixture token",
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
            Ledger::open(&fixture.ledger_path).expect("bridge ledger"),
        ));
        let operations = HostToolOperations::new(
            OperationStackInputs {
                workload_drafts: Some(Arc::new(
                    odin_omp::host_tools::WorkloadDraftStore::seal(&state_root)
                        .expect("seal the retained-draft store"),
                )),
                catalog,
                schemas: Arc::new(FilesystemSchemaCatalog::new(&fixture.repo_root)),
                adapter_executor: Arc::clone(&executor) as Arc<dyn odin_kernel::OperationExecutor>,
                adapter_status: Arc::new(SupervisedAdapterStatus::new(
                    Arc::new(UnsupervisedAdapterStatus),
                    std::collections::BTreeSet::new(),
                    std::time::Duration::ZERO,
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

        {
            let mut ledger = ledger.lock().expect("ledger lock");
            odin_ledger::lane_run::create_lane(
                ledger.connection(),
                &NewLane {
                    lane_id: lane.clone(),
                    seat_id: seat.clone(),
                    project_id: Some(project.clone()),
                    template_id: "template:authoring".to_owned(),
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
                    workflow_id: Some("live:authoring".to_owned()),
                    workflow_version: Some(1),
                    input_hash: "authoring".to_owned(),
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
                    "Publish the approved workload profile",
                    &[TodoSpec {
                        id: odin_domain::TodoId::new("todo:authoring-publish-proof")
                            .expect("todo id"),
                        title: "Publish the approved workload profile".to_owned(),
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

        Self {
            operations,
            binding: SessionOperationBinding {
                policy: policy.policy,
                context_policy_digest: policy.context_policy_digest,
                capsule_id: session_capsule_id(&session).expect("capsule id"),
                served_revision: 1,
                parent: None,
            },
            ledger,
            session: session.clone(),
            scope: Scope {
                seat: Some(seat),
                project: Some(project),
                lane: Some(lane),
                run: Some(run),
                session: Some(session.clone()),
                ..Scope::default()
            },
            resource,
        }
    }

    fn dispatch(
        &self,
        tool: &str,
        arguments: serde_json::Value,
        request_id: &str,
    ) -> Result<serde_json::Value, HostToolOperationError> {
        self.operations.dispatch_tool(
            SessionOperationContext {
                binding: &self.binding,
                session: &self.session,
                scope: &self.scope,
                execution: None,
            },
            tool,
            Some(self.resource.clone()),
            arguments,
            request_id,
        )
    }

    fn draft(
        &self,
        profile_id: &str,
        answers: &WorkloadDraftAnswers,
        request_id: &str,
    ) -> serde_json::Value {
        self.dispatch(
            "workload_draft",
            draft_arguments(profile_id, answers),
            request_id,
        )
        .expect("the draft dispatch compiles")
    }

    fn publish(
        &self,
        profile_id: &str,
        digest: &str,
        expected_registry_revision: u64,
        request_id: &str,
    ) -> Result<serde_json::Value, HostToolOperationError> {
        self.dispatch(
            "workload_publish",
            json!({
                "profileId": profile_id,
                "declarationDigest": digest,
                "expectedRegistryRevision": expected_registry_revision,
            }),
            request_id,
        )
    }

    /// The ledger's total approval-row count: a publish asks no one.
    fn approval_count(&self) -> usize {
        self.ledger
            .lock()
            .expect("ledger lock")
            .approvals()
            .expect("approvals readable")
            .len()
    }
}

/// The fixture's retained-publication source: revision 1 composed from the
/// fixture registry's own derived contracts and the (seat, lane) policy the
/// token binds — the same pure composition the provisioning path runs. Every
/// other revision refuses; legacy resolution refuses.
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

/// The exact draft dispatch arguments for one answer set: the canonical
/// camelCase wire form the strict input schema admits.
fn draft_arguments(profile_id: &str, answers: &WorkloadDraftAnswers) -> serde_json::Value {
    let mut arguments = json!({ "profileId": profile_id });
    let object = arguments.as_object_mut().expect("draft arguments object");
    let strings: &[(&str, Option<&String>)] = &[
        ("description", answers.description.as_ref()),
        ("seat", answers.seat.as_ref()),
        ("project", answers.project.as_ref()),
        ("gatewayLane", answers.gateway_lane.as_ref()),
        ("screen", answers.screen.as_ref()),
        ("statePath", answers.state_path.as_ref()),
        ("stateStorage", answers.state_storage.as_ref()),
        ("exportPodPath", answers.export_pod_path.as_ref()),
        ("exportHostFolder", answers.export_host_folder.as_ref()),
        ("briefText", answers.brief_text.as_ref()),
        ("memoryNamespace", answers.memory_namespace.as_ref()),
    ];
    for (name, value) in strings {
        if let Some(value) = value {
            object.insert((*name).to_owned(), json!(value));
        }
    }
    if let Some(enabled) = answers.enabled {
        object.insert("enabled".to_owned(), json!(enabled));
    }
    if let Some(stream) = answers.stream {
        object.insert("stream".to_owned(), json!(stream));
    }
    if let Some(hosts) = answers.allow_hosts.as_ref() {
        object.insert("allowHosts".to_owned(), json!(hosts));
    }
    if let Some(deadline) = answers.deadline_seconds {
        object.insert("deadlineSeconds".to_owned(), json!(deadline));
    }
    arguments
}

#[test]
fn incomplete_draft_lists_declared_clarifications_not_refusals() {
    let fixture = fixture();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", WorkloadDraftAnswers::default()))
        .expect("a draft with no answers still drafts");
    assert!(
        draft.declaration.is_none(),
        "no declaration without answers"
    );
    assert_eq!(
        draft.memory_namespaces, None,
        "no seat and project answered: no namespace facts"
    );
    let missing: Vec<&str> = draft
        .missing
        .iter()
        .map(|item| item.variable.as_str())
        .collect();
    for required in [
        "seat",
        "project",
        "gateway_lane",
        "allow_hosts",
        "brief_text",
        "memory_namespace",
        "deadline_seconds",
    ] {
        assert!(
            missing.contains(&required),
            "missing list must name {required}: {missing:?}"
        );
    }
    // Deployment facts are never a question; an agent pod runs "platform".
    for deployed in [
        "image_reference",
        "launcher",
        "browser",
        "supervisor",
        "playwright",
        "xvfb",
    ] {
        assert!(
            !missing.contains(&deployed),
            "{deployed} is a deployment fact: {missing:?}"
        );
    }
    let hosts = draft
        .missing
        .iter()
        .find(|item| item.variable == "allow_hosts")
        .expect("allowlist clarification");
    assert!(
        !hosts.meaning.is_empty(),
        "the clarification carries the skeleton's declared meaning"
    );
}

#[test]
fn complete_draft_returns_the_exact_declaration_digest_and_lane_facts() {
    let fixture = fixture();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", complete_answers()))
        .expect("a complete draft compiles");
    let declaration = draft.declaration.as_ref().expect("complete declaration");
    assert_eq!(
        declaration.destination, "registry/workloads/site-agent/profile.toml",
        "the canonical workload destination"
    );
    assert_eq!(
        declaration.declaration_digest,
        odin_domain::Digest::hash(declaration.rendered_toml.as_bytes()).to_string(),
        "the digest identifies the rendered declaration"
    );
    let rendered: toml::Table = toml::from_str(&declaration.rendered_toml).expect("a profile");
    assert_eq!(
        rendered["lifetime"]["deadline_seconds"].as_integer(),
        Some(3600),
        "the declared run lifetime is part of the declaration"
    );
    // Pods select gateway routes, not session lanes.
    let lane = draft.lane.as_ref().expect("lane facts");
    assert_eq!(lane.lane, "zai-glm");
    assert!(lane.available, "a declared chat route is available");
    assert_eq!(lane.provider.as_deref(), Some("gateway"));
    let snapshot = fixture.pin.current();
    let session_lanes: Vec<&str> = snapshot
        .objects
        .iter()
        .filter(|object| object.kind() == odin_registry::RegistryKind::Lane)
        .map(|object| object.id.as_str())
        .collect();
    assert!(!lane.declared_alternatives.is_empty());
    for alternative in &lane.declared_alternatives {
        assert!(
            !session_lanes.contains(&alternative.as_str()),
            "{alternative} is a session lane, not a gateway route"
        );
    }
    let limits = draft.seat_limits.as_ref().expect("seat facts");
    assert_eq!(limits.max_sessions, 4);
    assert_eq!(limits.max_parallel_runs, 8);
    assert_eq!(
        draft.memory_namespaces,
        Some(vec!["atlas.personal".to_owned()]),
        "the pair's admissible memory namespaces ride the draft"
    );
}

#[test]
fn the_declared_export_root_is_the_only_export_folder() {
    let fixture = fixture();
    let mut answers = complete_answers();
    answers.export_host_folder = None;
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("the declared root completes the draft");
    let rendered = &draft.declaration.as_ref().expect("complete").rendered_toml;
    assert!(
        rendered.contains("host_folder = \"/tmp/export\""),
        "the declared export root is supplied: {rendered}"
    );
    answers.export_host_folder = Some("/home/owner/exports/site-agent".to_owned());
    let refusal = fixture
        .route
        .draft(draft_request("site-agent", answers))
        .expect_err("a folder other than the declared root is refused");
    let detail = format!("{refusal:?}");
    assert!(
        detail.contains("/tmp/export") && detail.contains("export root"),
        "the refusal names the declared root: {detail}"
    );
}

#[test]
fn draft_refuses_unknown_references_and_stale_contexts() {
    let fixture = fixture();
    let mut answers = complete_answers();
    answers.gateway_lane = Some("not-a-declared-lane".to_owned());
    let failure = fixture
        .route
        .draft(draft_request("site-agent", answers))
        .expect_err("an unknown gateway lane must refuse");
    assert!(
        matches!(failure, WorkloadAuthoringFailure::InvalidDeclaration { .. }),
        "unexpected failure: {failure:?}"
    );

    let failure = fixture
        .route
        .draft(WorkloadDraftRequest {
            profile_id: "site-agent".to_owned(),
            answers: WorkloadDraftAnswers::default(),
            expected_registry_revision: Some(99),
        })
        .expect_err("a stale draft context must refuse");
    assert!(
        matches!(
            failure,
            WorkloadAuthoringFailure::StaleRevision { bound: 99, next: 1 }
        ),
        "unexpected failure: {failure:?}"
    );
}

#[test]
fn a_repeated_publication_returns_unchanged_not_stale() {
    let fixture = fixture();
    let answers = complete_answers();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft");
    let digest = draft
        .declaration
        .as_ref()
        .expect("declaration")
        .declaration_digest
        .clone();
    let target = draft.publish_revision;
    let first = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect("first publication");
    assert_eq!(first.outcome, "published");
    assert_eq!(first.published_revision, target);
    assert!(crate::project_authoring::reload_requested());
    assert_eq!(
        first.pinned_revision, target,
        "adoption is part of the receipt"
    );
    let head_after_first = git(&fixture.worktree, &["rev-parse", "HEAD"]);

    // The crash window: the operator approval is replayed (an identical
    // journaled operation) but the first attempt "died" before its receipt
    // arrived. The retry must return the EXISTING work — never a second
    // commit, never a second store effect, never a stale refusal.
    let retry = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect("the retry completes the already-landed publication");
    assert_eq!(retry.outcome, "unchanged");
    assert_eq!(retry.published_revision, target);
    assert_eq!(retry.pinned_revision, target);
    assert_eq!(retry.declaration_digest, digest);
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_after_first,
        "the retry must not create another commit"
    );
    assert_eq!(
        store_revision(&fixture.store),
        target,
        "no second store effect"
    );
}

#[test]
fn publish_crash_between_install_and_commit_resumes_the_same_declaration() {
    let fixture = fixture();
    let answers = complete_answers();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft");
    let declaration = draft.declaration.expect("declaration");
    // Simulate the crash window: the canonical declaration is installed in
    // the worktree but never committed.
    let destination = fixture.worktree.join(&declaration.destination);
    std::fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("destination directory");
    std::fs::write(&destination, &declaration.rendered_toml).expect("installed declaration");

    let publication = fixture
        .route
        .publish(publish_request(
            "site-agent",
            &declaration.declaration_digest,
            2,
        ))
        .expect("the resume path commits exactly the installed declaration");
    assert_eq!(publication.outcome, "published");
    assert_eq!(publication.published_revision, 2);
    let status = git(&fixture.worktree, &["status", "--porcelain"]);
    assert!(status.is_empty(), "the resume leaves a clean worktree");
    assert_eq!(store_revision(&fixture.store), 2);
}

#[test]
fn foreign_staged_work_is_refused_never_swept_into_the_commit() {
    let fixture = fixture();
    let answers = complete_answers();
    let digest = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft")
        .declaration
        .expect("declaration")
        .declaration_digest;
    // Concurrent external work: an unrelated file staged in the worktree.
    std::fs::write(fixture.worktree.join("notes.txt"), b"unrelated\n").expect("foreign file");
    git(&fixture.worktree, &["add", "notes.txt"]);

    let failure = fixture
        .route
        .publish(publish_request("site-agent", &digest, 2))
        .expect_err("foreign staged work must refuse the whole transaction");
    assert!(
        matches!(failure, WorkloadAuthoringFailure::PublicationRefused { .. }),
        "unexpected failure: {failure:?}"
    );
    assert_eq!(store_revision(&fixture.store), 1, "nothing published");
    assert!(
        fixture.worktree.join("notes.txt").exists(),
        "foreign content is never touched"
    );
}

#[test]
fn publish_consumes_the_draft_target_revision_and_installs_the_exact_digest() {
    let fixture = fixture();
    let answers = complete_answers();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft");
    let digest = draft
        .declaration
        .as_ref()
        .expect("declaration")
        .declaration_digest
        .clone();
    let base = draft.base_revision;
    let target = draft.publish_revision;
    assert_eq!(target, base + 1, "the publication target is base + 1");

    // Presenting the stale BASE is refused with the real target named.
    let stale = fixture
        .route
        .publish(publish_request("site-agent", &digest, base))
        .expect_err("the base revision is not a publication target");
    assert!(
        matches!(&stale, WorkloadAuthoringFailure::UnknownDraft { digest: refused, bound_registry_revision }
            if *refused == digest && *bound_registry_revision == base),
        "the stale-base refusal is UnknownDraft naming the presented bound: {stale:?}"
    );

    // Presenting the draft's publishRevision installs that exact revision
    // and the installed workload object digests to the approved declaration.
    let publication = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect("the draft-target publication installs");
    assert_eq!(publication.outcome, "published");
    assert_eq!(publication.published_revision, target);

    let installed = SnapshotStore::new(&fixture.store)
        .load_verified()
        .expect("installed snapshot");
    assert_eq!(installed.revision, target);
    let object = installed
        .objects
        .iter()
        .find(|object| {
            object.kind() == odin_registry::RegistryKind::Workload && object.id == "site-agent"
        })
        .expect("the published workload object");
    let odin_registry::ObjectConfig::Workload(profile) = &object.config else {
        panic!("the installed object is a workload profile");
    };
    let installed_digest = odin_domain::Digest::hash(
        toml::to_string(profile.as_ref())
            .expect("canonical serialization")
            .as_bytes(),
    )
    .to_string();
    assert_eq!(
        installed_digest, digest,
        "the installed profile is byte-identically the approved declaration"
    );
}

/// Reject symlinks even when their targets contain the approved bytes.
#[test]
fn symlinked_destination_is_never_written_through() {
    let fixture = fixture();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", complete_answers()))
        .expect("draft");
    let declaration = draft.declaration.as_ref().expect("complete declaration");
    let digest = declaration.declaration_digest.clone();
    let rendered = declaration.rendered_toml.clone();
    let target = draft.publish_revision;

    let relative = "registry/workloads/site-agent/profile.toml";
    let destination = fixture.worktree.join(relative);
    std::fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("destination directory");
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);

    // Sharpest attack: the link reads through to the EXACT approved bytes,
    // so a digest probe alone would bless the destination and a naive
    // commit would sweep the link into the registry.
    let victim = fixture.worktree.join("registry/.victim");
    std::fs::write(&victim, rendered.as_bytes()).expect("plant victim bytes");
    std::os::unix::fs::symlink(&victim, &destination).expect("plant resume-shaped symlink");

    let resumed = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect_err("the resume-shaped symlink must refuse");
    assert!(
        matches!(resumed, WorkloadAuthoringFailure::PublicationRefused { .. }),
        "the untracked link is foreign worktree state, never resumed over: {resumed:?}"
    );
    assert_eq!(
        std::fs::read(&victim).expect("victim readable"),
        rendered.as_bytes(),
        "the link target keeps its exact bytes"
    );
    assert!(
        std::fs::symlink_metadata(&destination)
            .expect("destination probe")
            .file_type()
            .is_symlink(),
        "the destination stayed a symlink"
    );
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the refusal committed nothing"
    );

    std::fs::remove_file(&destination).expect("drop the first link");
    std::fs::write(&victim, b"foreign bytes").expect("replant victim bytes");
    std::os::unix::fs::symlink(&victim, &destination).expect("plant conflict symlink");
    let conflicted = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect_err("the conflict symlink must refuse");
    assert!(
        matches!(conflicted, WorkloadAuthoringFailure::DigestMismatch { .. }),
        "foreign bytes behind the link are a digest mismatch: {conflicted:?}"
    );
    assert_eq!(
        std::fs::read(&victim).expect("victim readable"),
        b"foreign bytes",
        "the conflict link target is never written through either"
    );

    // Once the planted link is gone, the retained declaration publishes
    // through the shared staged transaction and commits byte-exactly.
    std::fs::remove_file(&destination).expect("drop the conflict link");
    std::fs::remove_file(&victim).expect("drop the victim");
    let publication = fixture
        .route
        .publish(publish_request("site-agent", &digest, target))
        .expect("the clean destination publishes through the shared install");
    assert_eq!(publication.outcome, "published");
    assert_eq!(publication.published_revision, target);
    assert_eq!(
        git_bytes(
            &fixture.worktree,
            &["show", &format!("{}:{relative}", publication.commit)]
        ),
        rendered.as_bytes(),
        "the staged install commits exactly the approved declaration"
    );
}

// ---------------------------------------------------------------------------
// Readiness-before-mint through the REAL dispatch: an unpublishable scope
// refuses with the owning typed failure before any approval is consumed —
// the row survives exactly as approved; a valid preparation publishes
// nothing and the valid path executes once.
// ---------------------------------------------------------------------------

#[test]
fn occupied_destination_refuses_before_initial_mint_and_recovers() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    assert_eq!(dispatch.approval_count(), 0, "no approval exists yet");

    let relative = "registry/workloads/site-agent/profile.toml";
    let destination = fixture.worktree.join(relative);
    std::fs::create_dir_all(destination.parent().expect("destination parent"))
        .expect("destination directory");
    std::fs::write(&destination, b"not the approved declaration")
        .expect("occupy the destination with a different declaration");

    // The owner's seam names the typed dead scope before any demand.
    let typed = fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect_err("the occupied destination refuses at the owner's typed seam");
    assert!(
        matches!(typed, WorkloadAuthoringFailure::DigestMismatch { .. }),
        "expected a typed digest-mismatch refusal, got {typed:?}"
    );

    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        "publish-occupied-destination",
    );
    let error = refused.expect_err("the occupied destination must refuse");
    assert!(
        matches!(error, HostToolOperationError::Arguments { .. }),
        "the refusal is the owning typed argument refusal, not a demand: {error:?}"
    );
    assert_eq!(
        dispatch.approval_count(),
        0,
        "the readiness refusal minted nothing"
    );

    // Clearing the plant restores the lawful path end to end.
    std::fs::remove_file(&destination).expect("clear the occupied destination");
    fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect("the cleared destination prepares clean at the owner's seam");
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "publish-cleared-destination-approved",
        )
        .expect("the cleared approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
}

/// Publish from a private linked worktree and land the commit on main before updating the store.
#[test]
fn a_deployed_authority_publishes_its_runtime_commit_onto_odin_main() {
    let fixture = fixture();
    let root = fixture._dir.path();
    let seed = root.join("seed");
    let origin = root.join("origin.git");
    git(
        root,
        &[
            "init",
            "--quiet",
            "--bare",
            "-b",
            "main",
            origin.to_str().expect("utf8"),
        ],
    );
    git(
        &seed,
        &["remote", "add", "origin", origin.to_str().expect("utf8")],
    );
    let anchor = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    git(
        &fixture.worktree,
        &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
    );
    std::fs::create_dir_all(fixture.worktree.join("docs")).expect("docs dir");
    std::fs::write(fixture.worktree.join("docs/NOTE.md"), "note\n").expect("docs note");
    commit_all(&fixture.worktree, "docs note");
    let docs = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    git(
        &fixture.worktree,
        &["push", "--quiet", "origin", "HEAD:refs/heads/main"],
    );
    let hook = origin.join("hooks/pre-receive");
    std::fs::write(&hook, "#!/bin/sh\necho push >> runtime-pushes\n").expect("hook");
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("hook mode");

    let route = DaemonWorkloadAuthoring::new(
        fixture.pin_handle(),
        root.join("runtime-authoring/odin"),
        fixture.store.clone(),
        fixture.ledger_path(),
        fixture.state_root(),
        Some(fixture_deployment()),
        Some(super::AuthoringSync {
            repository: seed.clone(),
        }),
    )
    .expect("route")
    .with_gateway(Some(fixture_gateway()));
    let declaration = route
        .draft(draft_request("site-agent", complete_answers()))
        .expect("draft")
        .declaration
        .expect("declaration");
    let publication = route
        .publish(publish_request(
            "site-agent",
            &declaration.declaration_digest,
            2,
        ))
        .expect("the runtime publication succeeds");

    let main = git(&origin, &["rev-parse", "main"]);
    assert_eq!(
        publication.commit, main,
        "the published commit is odin main"
    );
    let parents = git(&origin, &["rev-list", "--parents", "-n", "1", "main"]);
    assert_eq!(
        parents.split_whitespace().skip(1).collect::<Vec<_>>(),
        vec![docs.as_str()],
        "a plain child of main's tip, published on the anchor"
    );
    git(&origin, &["merge-base", "--is-ancestor", &anchor, "main"]);
    assert_eq!(store_revision(&fixture.store), 2);
    assert_eq!(publication.published_revision, 2);
    assert_eq!(
        git(
            &origin,
            &["rev-list", "--count", &format!("{docs}..{main}")]
        ),
        "1",
        "the actual workload transaction creates exactly one reachable commit"
    );
    assert_eq!(
        std::fs::read_to_string(origin.join("runtime-pushes")).expect("push log"),
        "push\n",
        "one runtime push"
    );
    let replay = route
        .publish(publish_request(
            "site-agent",
            &declaration.declaration_digest,
            2,
        ))
        .expect("exact replay");
    assert_eq!(replay.outcome, "unchanged");
    assert_eq!(replay.commit, publication.commit);
    assert_eq!(replay.published_revision, 2);
    assert_eq!(store_revision(&fixture.store), 2);
    assert_eq!(git(&origin, &["rev-parse", "main"]), main);
    assert_eq!(
        std::fs::read_to_string(origin.join("runtime-pushes")).expect("push log"),
        "push\n",
        "exact replay never pushes a second mutation"
    );
}

#[test]
fn a_draft_refuses_a_lane_its_seat_does_not_run() {
    let fixture = fixture();
    let seat = complete_answers().seat.expect("fixture seat");
    let route = DaemonWorkloadAuthoring::new(
        fixture.pin_handle(),
        fixture.worktree.clone(),
        fixture.store.clone(),
        fixture.ledger_path(),
        fixture.state_root(),
        Some(fixture_deployment()),
        None,
    )
    .expect("route")
    .with_gateway(Some(fixture_gateway()))
    .with_seat_lanes([(seat.clone(), vec!["glm-flash".to_owned()])].into());
    let error = route
        .draft(draft_request("site-agent", complete_answers()))
        .expect_err("the seat does not run zai-glm")
        .to_string();
    assert!(
        error.contains("runs only on gateway lane(s) glm-flash"),
        "{error}"
    );
    let mut answers = complete_answers();
    answers.gateway_lane = Some("glm-flash".to_owned());
    let draft = route
        .draft(draft_request("site-agent", answers))
        .expect("the seat's own lane drafts");
    let lane = draft.lane.expect("lane facts");
    assert_eq!(lane.lane, "glm-flash");
    assert!(
        lane.declared_alternatives.is_empty(),
        "the seat runs no other lane to offer: {:?}",
        lane.declared_alternatives
    );
}
