//! Workload authoring recovery and races through isolated Git and snapshot stores.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ResourceConstraint;
use odin_domain::operation::Limits;
use odin_domain::{CommandId, Digest, LaneId, ProjectId, RunId, Scope, SeatId, SessionId, SliceId};
use odin_kernel::{ApprovalDecision, ApprovalGate, DecisionOutcome, MintRequest, TokenIssuer};
use odin_ledger::approval::Approval;
use odin_ledger::lane_run::{NewLane, NewRun};
use odin_ledger::plan::{TodoSpec, TodoStatus};
use odin_ledger::Ledger;
use odin_omp::host_tools::executor::HostToolExecutor;
use odin_omp::host_tools::operations::{
    admission_digest, correlation_for, seat_operation_policy, session_capsule_id,
    DeclaredOperationCatalog, FilesystemSchemaCatalog, HostToolOperationError, HostToolOperations,
    OperationStackInputs, ProvisionedFreshAuthorityProvider, RevisionMaterial,
    RevisionMaterialSource, SeatOperationPolicyInputs, SessionOperationBinding,
    SessionOperationContext, SupervisedAdapterStatus, UnsupervisedAdapterStatus,
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

    let project = worktree.join("registry/projects/life");
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
            "project_scope = [\"life\"]\n",
            "approval_defaults = { r0 = \"auto\", r1 = \"auto\", r2 = \"auto\", r3 = \"approval\" }\n",
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
    .expect("the fixture route seals its draft store");
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
        project: Some("life".to_owned()),
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
const DISPATCH_PROJECT: &str = "life";
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
        approval_id: &str,
        request_id: &str,
    ) -> Result<serde_json::Value, HostToolOperationError> {
        self.dispatch(
            "workload_publish",
            json!({
                "profileId": profile_id,
                "declarationDigest": digest,
                "expectedRegistryRevision": expected_registry_revision,
                "approvalId": approval_id,
            }),
            request_id,
        )
    }

    /// The operator decision over one durable approval row: the exact
    /// ledger-decided approval the governed flow's owner step records.
    fn decide(&self, approval_id: &odin_domain::ApprovalId, revision: i64) {
        let mut ledger = self.ledger.lock().expect("ledger lock");
        let mut gate = ApprovalGate::new(&mut ledger);
        match gate
            .decide(
                approval_id,
                revision,
                ApprovalDecision::Approve {
                    evidence_ref: Some("operator:authoring-fixture".to_owned()),
                },
                "operator:fixture",
                OffsetDateTime::now_utc(),
            )
            .expect("owner decision recorded")
        {
            DecisionOutcome::Approved(_) => {}
            other => panic!("unexpected approval outcome: {other:?}"),
        }
    }

    /// Every durable approval row minted for the publish capability.
    fn publish_approval_rows(&self) -> Vec<Approval> {
        self.ledger
            .lock()
            .expect("ledger lock")
            .approvals()
            .expect("approval rows")
            .into_iter()
            .filter(|approval| approval.scope.capability_id.as_str() == "workload.publish")
            .collect()
    }

    fn approval_row(&self, approval_id: &odin_domain::ApprovalId) -> Option<Approval> {
        self.ledger
            .lock()
            .expect("ledger lock")
            .approval(approval_id)
            .expect("approval readable")
    }

    /// The ledger's total approval-row count: minting is observable.
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

fn minted_demand(refusal: &HostToolOperationError) -> (odin_domain::ApprovalId, i64) {
    match refusal {
        HostToolOperationError::ApprovalRequired {
            approval_id,
            revision,
            ..
        } => (approval_id.clone(), *revision),
        other => panic!("expected the minted ApprovalRequired demand: {other:?}"),
    }
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

/// Multiline briefs are user input; image facts come only from the deployment.
#[test]
fn a_paragraphed_brief_drafts_on_the_deployed_image() {
    let fixture = fixture();
    let mut answers = complete_answers();
    answers.brief_text = Some("Fetch the feed.\n\n1) Rank the top 5.\n2)\tReport them.".to_owned());
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers))
        .expect("a multi-line brief drafts");
    let rendered = &draft
        .declaration
        .as_ref()
        .expect("complete declaration")
        .rendered_toml;
    let profile: toml::Table = toml::from_str(rendered).expect("rendered TOML parses");
    assert_eq!(
        profile["brief"]["text"].as_str(),
        Some("Fetch the feed.\n\n1) Rank the top 5.\n2)\tReport them.")
    );
    assert_eq!(
        profile["image"]["reference"].as_str(),
        Some(odin_registry::PLATFORM_IMAGE)
    );
    let schema: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas/capability/workload.draft.input.json"),
        )
        .expect("draft input schema"),
    )
    .expect("schema JSON");
    for platform_owned in ["launcher", "browser", "supervisor", "playwright", "xvfb"] {
        assert!(
            schema["properties"].get(platform_owned).is_none(),
            "{platform_owned} is a deployment fact, not a draft answer"
        );
    }
    // An agent pod runs the platform image: naming another is refused.
    let mut named = complete_answers();
    named.image_reference = Some(format!("docker.io/library/python:3.12@{}", digest_of('a')));
    let refused = fixture
        .route
        .draft(draft_request("site-agent", named))
        .expect_err("an agent pod never names its image");
    assert!(
        format!("{refused:?}").contains("platform's own image"),
        "{refused:?}"
    );
}

fn digest_of(fill: char) -> String {
    format!("sha256:{}", fill.to_string().repeat(64))
}

/// a script pod drafts from a DM — its own digest-pinned
/// image, its command, GPUs and service mode — and compiles with no agent
/// sections (runtime, display, memory, lifetime) and no model lane.
#[test]
fn a_script_service_pod_drafts_without_agent_sections() {
    let fixture = fixture();
    let answers = WorkloadDraftAnswers {
        description: Some("residual monitor service".to_owned()),
        enabled: Some(true),
        seat: Some("coordinator".to_owned()),
        project: Some("life".to_owned()),
        allow_hosts: Some(vec!["example.com".to_owned()]),
        state_storage: Some("1Gi".to_owned()),
        brief_text: Some("Serve the residual counter.".to_owned()),
        harness: Some("script".to_owned()),
        image_reference: Some(format!("docker.io/library/python:3.12@{}", digest_of('b'))),
        script_command: Some(vec![
            "python3".to_owned(),
            "-c".to_owned(),
            "print(1)".to_owned(),
        ]),
        gpu_count: Some(1),
        mode: Some("service".to_owned()),
        ..WorkloadDraftAnswers::default()
    };
    let draft = fixture
        .route
        .draft(draft_request("residual-service", answers))
        .expect("a script service drafts");
    let rendered = &draft
        .declaration
        .as_ref()
        .expect("complete declaration")
        .rendered_toml;
    let profile: odin_registry::WorkloadProfileToml = toml::from_str(rendered).expect("parses");
    assert_eq!(profile.harness(), "script");
    assert_eq!(profile.mode, odin_registry::WorkloadMode::Service);
    assert_eq!(profile.gpu_count, 1);
    assert_eq!(
        profile.script.expect("script").command,
        ["python3", "-c", "print(1)"]
    );
    assert!(profile
        .image
        .reference
        .starts_with("docker.io/library/python:3.12@"));
    assert!(
        profile.runtime.is_none()
            && profile.display.is_none()
            && profile.memory.is_none()
            && profile.lifetime.is_none()
            && profile.seat.gateway_lane.is_none(),
        "{rendered}"
    );
}

/// Monitoring configuration does not require a watchdog.
#[test]
fn an_anti_stuck_pod_drafts_its_progress_counter_and_ladder() {
    let fixture = fixture();
    let rungs = serde_json::json!({
        "retry": 0, "restart_worker": 1, "checkpoint": 0, "rehome": 0, "escalate": 1
    });
    let answers = WorkloadDraftAnswers {
        description: Some("counter that gets stuck".to_owned()),
        enabled: Some(true),
        seat: Some("coordinator".to_owned()),
        project: Some("life".to_owned()),
        allow_hosts: Some(Vec::new()),
        state_storage: Some("1Gi".to_owned()),
        brief_text: Some("Count, then stall.".to_owned()),
        harness: Some("script".to_owned()),
        image_reference: Some(format!("docker.io/library/python:3.12@{}", digest_of('b'))),
        script_command: Some(vec![
            "python3".to_owned(),
            "-c".to_owned(),
            "print(1)".to_owned(),
        ]),
        deadline_seconds: Some(900),
        monitoring_cadence_seconds: Some(15),
        progress: Some("step".to_owned()),
        stall_seconds: Some(60),
        recovery: Some(serde_json::json!({
            "max_attempts": rungs,
            "cooldown_seconds": {
                "retry": 0, "restart_worker": 30, "checkpoint": 0, "rehome": 0, "escalate": 0
            },
            "allowed_rungs": ["restart_worker", "escalate"],
            "blocked_missing_decision": "Colin decides whether to fix or drop the pod",
        })),
        ..WorkloadDraftAnswers::default()
    };
    let draft = fixture
        .route
        .draft(draft_request("stuck-counter", answers))
        .expect("an anti-stuck pod drafts");
    let rendered = &draft
        .declaration
        .as_ref()
        .unwrap_or_else(|| panic!("incomplete: {draft:?}"))
        .rendered_toml;
    let profile: odin_registry::WorkloadProfileToml = toml::from_str(rendered).expect("parses");
    let monitoring = profile.monitoring.expect("monitoring");
    assert_eq!(monitoring.progress.as_deref(), Some("step"));
    assert_eq!(monitoring.stall_seconds.map(|stall| stall.get()), Some(60));
    assert!(monitoring.watchdogs.is_empty());
    assert!(
        odin_registry::schema::check_pod_recovery(&monitoring).is_ok(),
        "{rendered}"
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
    assert!(
        declaration.declaration_digest.starts_with("blake3:"),
        "the digest is the blake3 identity of the declaration"
    );
    assert!(
        declaration.rendered_toml.contains("supervisor")
            && declaration.rendered_toml.contains("storage"),
        "the rendered TOML is the profile declaration"
    );
    assert!(
        declaration
            .rendered_toml
            .contains("[lifetime]\ndeadline_seconds = 3600"),
        "the declared run lifetime is part of the declaration: {}",
        declaration.rendered_toml
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
    answers.export_host_folder = Some("/home/colin/exports/site-agent".to_owned());
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
fn publish_crash_after_store_install_retries_as_unchanged_not_stale() {
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
fn conflicting_declaration_for_a_published_id_invalidates_the_old_scope() {
    let fixture = fixture();
    let answers = complete_answers();
    let digest = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft")
        .declaration
        .expect("declaration")
        .declaration_digest;
    fixture
        .route
        .publish(publish_request("site-agent", &digest, 2))
        .expect("first publication");

    let mut conflicting_answers = complete_answers();
    conflicting_answers.description = Some("a different pod".to_owned());
    let refused = fixture
        .route
        .draft(draft_request("site-agent", conflicting_answers.clone()))
        .expect_err("a different declaration under a published id is refused at draft")
        .to_string();
    assert!(
        refused.contains("already published with different content"),
        "{refused}"
    );
    // An identical redraft still drafts (replay of the published declaration).
    fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("the identical declaration redrafts");
    let conflicting = fixture
        .route
        .draft(draft_request("site-agent-v2", conflicting_answers))
        .expect("a new id drafts")
        .declaration
        .expect("complete conflicting declaration");
    assert_ne!(
        conflicting.declaration_digest, digest,
        "a redraft yields a distinct digest: the approval is per digest"
    );
    // The approved scope is untouched: the pin still names it.
    let pinned = SnapshotStore::new(&fixture.store)
        .load_verified()
        .expect("active snapshot");
    assert_eq!(pinned.revision, 2);
}

#[test]
fn concurrent_bound_scopes_publish_distinct_content_and_replay_identical() {
    let fixture = fixture();
    let first_answers = complete_answers();
    let first_digest = fixture
        .route
        .draft(draft_request("site-agent", first_answers.clone()))
        .expect("draft")
        .declaration
        .expect("declaration")
        .declaration_digest;
    fixture
        .route
        .publish(publish_request("site-agent", &first_digest, 2))
        .expect("the first scope publishes revision 2");

    let mut second_answers = complete_answers();
    second_answers.description = Some("the other agent's distinct declared purpose".to_owned());
    let second = fixture
        .route
        .draft(draft_request("other-agent", second_answers.clone()))
        .expect("draft");
    let second_digest = second
        .declaration
        .as_ref()
        .expect("declaration")
        .declaration_digest
        .clone();
    let second_target = second.publish_revision;
    let second_publication = fixture
        .route
        .publish(publish_request(
            "other-agent",
            &second_digest,
            second_target,
        ))
        .expect("the second scope publishes its bound revision");
    assert_eq!(second_publication.profile_id, "other-agent");
    assert_eq!(second_publication.published_revision, second_target);
    assert_eq!(second_publication.pinned_revision, second_target);
    assert_ne!(
        second_digest, first_digest,
        "distinct scopes have distinct digests"
    );
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
fn publish_receipt_commit_binds_the_exact_approved_bytes() {
    let fixture = fixture();
    let answers = complete_answers();
    let draft = fixture
        .route
        .draft(draft_request("site-agent", answers.clone()))
        .expect("draft");
    let declaration = draft.declaration.expect("declaration");
    let publication = fixture
        .route
        .publish(publish_request(
            "site-agent",
            &declaration.declaration_digest,
            2,
        ))
        .expect("publication");
    // The receipt commit is the real HEAD sha, and the committed blob is
    // the exact approved declaration bytes (byte-exact, newline included).
    let head = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    assert_eq!(publication.commit, head, "receipt commit is the real sha");
    assert_eq!(head.len(), 40, "full lowercase hex sha");
    let committed = git_bytes(
        &fixture.worktree,
        &["show", &format!("HEAD:{}", declaration.destination)],
    );
    assert_eq!(
        odin_domain::Digest::hash(&committed).to_string(),
        declaration.declaration_digest,
        "the committed blob is the approved declaration, byte-exact"
    );
}

#[test]
fn worktree_transaction_lock_is_exclusive_and_releases() {
    let fixture = fixture();
    let git_dir = fixture.worktree.join(".git");
    let held =
        super::WorktreeLock::acquire(&fixture.worktree, std::time::Duration::from_millis(50))
            .expect("first acquire");
    let failure =
        super::WorktreeLock::acquire(&fixture.worktree, std::time::Duration::from_millis(120))
            .expect_err("a held transaction lock must bound the second acquirer");
    assert!(
        matches!(failure, WorkloadAuthoringFailure::BridgeTimeout { .. }),
        "unexpected failure: {failure:?}"
    );
    drop(held);
    super::WorktreeLock::acquire(&fixture.worktree, std::time::Duration::from_millis(120))
        .expect("the released lock is acquirable again");
    let _ = git_dir;
}

#[test]
fn plain_thread_caller_completes_drafts_via_the_dedicated_thread_bridge() {
    // A caller that is NOT a multi-thread runtime worker (this test thread;
    // try_current fails here) must take the dedicated-thread bridge: the
    // path that would panic under block_in_place cannot be reached. The
    // draft still completes and this thread blocks by contract, exactly as
    // the seam documents.
    let fixture = fixture();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime (proves try_current is not relied on)");
    let _guard = runtime.enter();
    let route = DaemonWorkloadAuthoring::new(
        fixture.pin_handle(),
        fixture.worktree.clone(),
        fixture.store.clone(),
        fixture.ledger_path(),
        fixture.state_root(),
        Some(fixture_deployment()),
        None,
    )
    .expect("the fixture route seals its draft store");
    let draft = route
        .draft(draft_request("site-agent", complete_answers()))
        .expect("the dedicated-thread bridge completes the draft");
    assert!(draft.declaration.is_some(), "complete answers compile");
    // The route and bridge must read the same draft identity from the canonical store.
    let declaration = draft
        .declaration
        .as_ref()
        .expect("complete answers compile a declaration");
    let canonical = odin_omp::host_tools::WorkloadDraftStore::seal(&fixture.state_root())
        .expect("the bridge's canonical draft store");
    let retained = canonical
        .require_retained(
            &draft.profile_id,
            &declaration.declaration_digest,
            draft.publish_revision,
        )
        .expect("the retained draft is the draft the publish pre-gate consumes");
    assert_eq!(retained.profile_id, draft.profile_id);
    assert_eq!(retained.declaration_digest, declaration.declaration_digest);
    assert_eq!(retained.bound_registry_revision, draft.publish_revision);
}

#[test]
fn multithread_worker_caller_offloads_through_the_blocking_pool() {
    // The production caller context: the sync handler runs ON a multi-thread
    // runtime worker, so the bridge must take the block_in_place +
    // spawn_blocking path. The draft completes on that path.
    let fixture = fixture();
    let runtime = tokio::runtime::Runtime::new().expect("multi-thread runtime");
    let draft = runtime.block_on(async {
        let route = DaemonWorkloadAuthoring::new(
            fixture.pin_handle(),
            fixture.worktree.clone(),
            fixture.store.clone(),
            fixture.ledger_path(),
            fixture.state_root(),
            Some(fixture_deployment()),
            None,
        )
        .expect("the fixture route seals its draft store");
        route
            .draft(draft_request("site-agent", complete_answers()))
            .expect("the blocking-pool bridge completes the draft")
    });
    assert!(draft.declaration.is_some(), "complete answers compile");
}

/// The base-vs-target contract, end to end over the REAL chain: the draft
/// names the exact NEW revision its publication installs; presenting the
/// stale BASE instead is a typed StaleRevision naming the real target;
/// presenting the draft's publishRevision installs that exact revision with
/// the exact approved declaration digest.
#[test]
fn model_redraft_never_disturbs_the_retained_approved_draft() {
    let fixture = fixture();
    let first_answers = complete_answers();
    let first = fixture
        .route
        .draft(draft_request("site-agent", first_answers.clone()))
        .expect("draft");
    let first_digest = first
        .declaration
        .as_ref()
        .expect("declaration")
        .declaration_digest
        .clone();
    let target = first.publish_revision;
    let first_publication = fixture
        .route
        .publish(publish_request("site-agent", &first_digest, target))
        .expect("publish D1");
    assert_eq!(first_publication.outcome, "published");

    let mut second_answers = complete_answers();
    second_answers.description = Some("a re-drafted pod".to_owned());
    let refused = fixture
        .route
        .draft(draft_request("site-agent", second_answers))
        .expect_err("a conflicting redraft of a published id is refused at draft");
    assert!(
        matches!(refused, WorkloadAuthoringFailure::InvalidDeclaration { .. }),
        "unexpected failure: {refused:?}"
    );

    let republished = fixture
        .route
        .publish(publish_request("site-agent", &first_digest, target))
        .expect("republish D1 unchanged");
    assert_eq!(republished.outcome, "unchanged");
    assert_eq!(republished.published_revision, target);
    let pinned = SnapshotStore::new(&fixture.store)
        .load_verified()
        .expect("installed snapshot");
    let pinned_profile = pinned
        .objects
        .iter()
        .find(|object| {
            object.kind() == odin_registry::RegistryKind::Workload && object.id == "site-agent"
        })
        .expect("the pinned workload object");
    let odin_registry::ObjectConfig::Workload(profile) = &pinned_profile.config else {
        panic!("the pinned object is a workload profile");
    };
    assert_eq!(
        odin_domain::Digest::hash(toml::to_string(profile.as_ref()).expect("toml").as_bytes())
            .to_string(),
        first_digest,
        "the pinned profile is byte-exactly the FIRST approved draft"
    );
}

#[test]
fn publish_without_a_retained_draft_fails_unknown_draft() {
    let fixture = fixture();
    let unknown = "blake3:1111111111111111111111111111111111111111111111111111111111111111";
    let failure = fixture
        .route
        .publish(publish_request("site-agent", unknown, 2))
        .expect_err("an unknown retained draft must refuse");
    assert!(
        matches!(failure, WorkloadAuthoringFailure::UnknownDraft { .. }),
        "unexpected failure: {failure:?}"
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
        matches!(&stale, WorkloadAuthoringFailure::UnknownDraft { digest, bound_registry_revision }
            if *digest == *digest.as_str() && *bound_registry_revision == base),
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

/// The mandated approval loop end to end over the REAL governed chain: the
/// draft dispatch retains the compiled declaration; the first publish
/// dispatch mints the durable ApprovalRequired request through the real
/// kernel gate; the operator decides it in the ledger; a redraft retains a
/// distinct scope; and the approved retry — the SAME original digest and
/// bound revision under the ACTUAL minted approval id — commits the EXACT
/// retained D1 TOML to the authoring worktree and the snapshot store and
/// consumes the approval exactly once. Every replay is refused or unchanged:
/// no duplicate effect ever exists.
#[test]
fn approved_dispatch_commits_the_exact_retained_bytes_and_consumes_once() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    // D1: the real draft dispatch compiles and retains the declaration.
    let first = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let d1_digest = first["declaration"]["declarationDigest"]
        .as_str()
        .expect("the D1 declaration digest")
        .to_owned();
    let d1_toml = first["declaration"]["renderedToml"]
        .as_str()
        .expect("the D1 rendered declaration")
        .to_owned();
    let target = first["publishRevision"].as_u64().expect("publish revision");
    assert_eq!(target, 2, "the draft binds base revision 1 plus one");

    // The first publish dispatch can only carry the placeholder: the REAL
    // gate mints the durable exact-scope request and names it.
    let demand = dispatch
        .publish(
            "site-agent",
            &d1_digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    {
        let requested = dispatch.approval_row(&minted).expect("the minted row");
        assert_eq!(requested.status, odin_domain::ApprovalStatus::Requested);
    }
    dispatch.decide(&minted, minted_revision);

    // D2 redraft: a distinct retained scope at the same bound target — the
    // registry never moved, so the approval on D1 is not disturbed.
    let mut second_answers = complete_answers();
    second_answers.description = Some("a re-drafted pod".to_owned());
    let second = dispatch.draft("site-agent", &second_answers, "draft-d2");
    let d2_digest = second["declaration"]["declarationDigest"]
        .as_str()
        .expect("the D2 declaration digest");
    assert_ne!(
        d2_digest, d1_digest,
        "the redraft compiles a new declaration"
    );
    assert_eq!(
        second["publishRevision"].as_u64(),
        Some(target),
        "the redraft binds the same still-unpublished target"
    );

    // The approved retry: the SAME original digest and bound revision, the
    // ACTUAL minted approval id. The kernel consumes the approval and the
    // route installs the retained bytes.
    let publication = dispatch
        .publish(
            "site-agent",
            &d1_digest,
            target,
            minted.as_str(),
            "publish-d1",
        )
        .expect("the approved D1 publish dispatches");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
    assert_eq!(publication["declarationDigest"], d1_digest);
    assert_eq!(publication["profileId"], "site-agent");
    let commit = publication["commit"].as_str().expect("the commit sha");

    // The COMMITTED bytes are the exact retained D1 declaration — read from
    // the git object database and the worktree, never from the retained
    // draft store.
    let relative = "registry/workloads/site-agent/profile.toml";
    assert_eq!(
        git_bytes(
            &fixture.worktree,
            &["show", &format!("{commit}:{relative}")]
        ),
        d1_toml.as_bytes(),
        "the commit blob is byte-exactly the approved D1 declaration"
    );
    assert_eq!(
        std::fs::read(fixture.worktree.join(relative)).expect("installed destination"),
        d1_toml.as_bytes(),
        "the installed worktree file is byte-exactly the approved declaration"
    );

    // The published snapshot carries the same declaration at revision 2.
    let installed = SnapshotStore::new(&fixture.store)
        .load_verified()
        .expect("the installed snapshot");
    assert_eq!(installed.revision, target);
    let object = installed
        .objects
        .iter()
        .find(|object| {
            object.kind() == odin_registry::RegistryKind::Workload && object.id == "site-agent"
        })
        .expect("the published workload object");
    let odin_registry::ObjectConfig::Workload(profile) = &object.config else {
        panic!("the published object is a workload profile");
    };
    assert_eq!(
        odin_domain::Digest::hash(
            toml::to_string(profile.as_ref())
                .expect("canonical serialization")
                .as_bytes()
        )
        .to_string(),
        d1_digest,
        "the published snapshot object is the approved declaration"
    );

    // Approval lifecycle: exactly one publish approval exists, consumed
    // exactly once by exactly the retry command; the redraft never minted
    // one and the placeholder was never a second approval.
    let rows = dispatch.publish_approval_rows();
    assert_eq!(rows.len(), 1, "exactly one publish approval: {rows:?}");
    assert_eq!(rows[0].status, odin_domain::ApprovalStatus::Consumed);
    let correlation = correlation_for(&dispatch.session, "publish-d1").expect("correlation");
    let consumed_by =
        CommandId::new(format!("odin.omp.host_tool:{correlation}")).expect("command id");
    assert_eq!(rows[0].consumed_by_command_id.as_ref(), Some(&consumed_by));

    // A fresh dispatch under the consumed approval can never re-consume:
    // typed refusal, registry untouched, no new approval row.
    let replay = dispatch.publish(
        "site-agent",
        &d1_digest,
        target,
        minted.as_str(),
        "publish-d1-replay",
    );
    assert!(
        replay.is_err(),
        "the consumed approval never authorizes a second effect: {replay:?}"
    );
    assert_eq!(
        SnapshotStore::new(&fixture.store)
            .load_verified()
            .expect("the installed snapshot")
            .revision,
        target,
        "the replay published nothing"
    );
    let rows = dispatch.publish_approval_rows();
    assert_eq!(rows.len(), 1, "the replay minted nothing");
    assert_eq!(rows[0].status, odin_domain::ApprovalStatus::Consumed);

    // The route-level replay completes unchanged against the SAME bound
    // revision receipt: no second commit, no second consumption.
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    let route_replay = fixture
        .route
        .publish(publish_request("site-agent", &d1_digest, target))
        .expect("the identical route-level replay");
    assert_eq!(route_replay.outcome, "unchanged");
    assert_eq!(route_replay.published_revision, target);
    assert_eq!(route_replay.commit, commit);
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the replay committed nothing"
    );
    let rows = dispatch.publish_approval_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, odin_domain::ApprovalStatus::Consumed);
}

#[test]
fn corrupt_retained_record_refuses_before_consume_and_the_approval_survives() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    // D1 drafted; the real gate minted the demand; the owner approved.
    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    dispatch.decide(&minted, minted_revision);
    let approved_before = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        approved_before.status,
        odin_domain::ApprovalStatus::Approved
    );

    // Corrupt the retained record's CONTENT while keeping it parseable: the
    // sharpest corruption — existence, name, and shape all pass, but the
    // bytes no longer hash to the approved digest.
    let leaf = retained_leaf(&fixture, &digest);
    let intact = std::fs::read(&leaf).expect("the retained leaf is readable");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
            .expect("unlock the retained leaf");
    }
    let mut corrupted =
        serde_json::from_slice::<serde_json::Value>(&intact).expect("the retained record parses");
    corrupted["rendered_toml"] = serde_json::Value::String("tampered declaration".to_owned());
    std::fs::write(
        &leaf,
        serde_json::to_vec_pretty(&corrupted).expect("encode"),
    )
    .expect("tamper the retained leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
            .expect("reseal the retained leaf");
    }

    // The approved dispatch refuses BEFORE the gate consumes anything: the
    // approved row is exactly as the operator left it.
    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        minted.as_str(),
        "publish-corrupted",
    );
    assert!(
        refused.is_err(),
        "the corrupt retained record must refuse the approved dispatch: {refused:?}"
    );
    let after = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        after.status,
        odin_domain::ApprovalStatus::Approved,
        "the approval is not spent on a corrupt record: {after:?}"
    );
    assert_eq!(
        after.revision, approved_before.revision,
        "the row never moved"
    );
    assert_eq!(
        after.consumed_by_command_id, None,
        "nothing consumed the approval"
    );
    assert_eq!(
        SnapshotStore::new(&fixture.store)
            .load_verified()
            .expect("the installed snapshot")
            .revision,
        1,
        "nothing published"
    );

    // Restoring the exact retained bytes lets the SAME approved dispatch
    // publish: the corrupt attempt spent nothing.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
            .expect("unlock the retained leaf");
    }
    std::fs::write(&leaf, &intact).expect("restore the retained leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
            .expect("reseal the retained leaf");
    }
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-d1-restored",
        )
        .expect("the restored approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
    let rows = dispatch.publish_approval_rows();
    assert!(
        rows[0].consumed_by_command_id.is_some(),
        "the restored dispatch is the one consumer"
    );
}

/// Locate by digest rather than depending on the store's filename format.
fn retained_leaf(fixture: &Fixture, digest: &str) -> PathBuf {
    let body = digest
        .strip_prefix("blake3:")
        .expect("the blake3 digest body");
    let directory = fixture.state_root().join("workload-drafts");
    std::fs::read_dir(&directory)
        .expect("the retained-draft directory")
        .filter_map(|entry| entry.expect("draft entry").file_name().into_string().ok())
        .find(|name| name.contains(body))
        .map(|name| directory.join(name))
        .expect("the retained draft leaf exists")
}

/// Matching bytes do not authorize a different destination.
#[test]
fn redirected_retained_record_refuses_before_consume_and_never_installs() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    // D1 drafted for site-agent; the real gate minted; the owner approved.
    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    dispatch.decide(&minted, minted_revision);

    // Redirect the retained record: the declaration bytes stay exactly the
    // approved ones, but the recorded profile id names another destination —
    // the one tamper content-identity alone cannot see.
    let leaf = retained_leaf(&fixture, &digest);
    let intact = std::fs::read(&leaf).expect("the retained leaf is readable");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
            .expect("unlock the retained leaf");
    }
    let mut redirected =
        serde_json::from_slice::<serde_json::Value>(&intact).expect("the retained record parses");
    redirected["profile_id"] = serde_json::Value::String("shadow-destination".to_owned());
    std::fs::write(
        &leaf,
        serde_json::to_vec_pretty(&redirected).expect("encode"),
    )
    .expect("tamper the retained identity");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
            .expect("reseal the retained leaf");
    }

    // The approved dispatch refuses BEFORE consuming: the row stays exactly
    // Approved, nothing was published anywhere.
    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        minted.as_str(),
        "publish-redirected",
    );
    assert!(
        refused.is_err(),
        "the redirected retained record must refuse the approved dispatch: {refused:?}"
    );
    let after = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        after.status,
        odin_domain::ApprovalStatus::Approved,
        "the approval is not spent on a redirected record: {after:?}"
    );
    assert_eq!(after.consumed_by_command_id, None);
    let installed = SnapshotStore::new(&fixture.store)
        .load_verified()
        .expect("the installed snapshot");
    assert_eq!(installed.revision, 1, "nothing published");
    assert!(
        !fixture
            .worktree
            .join("registry/workloads/shadow-destination")
            .try_exists()
            .expect("shadow destination probe"),
        "the redirected destination never materializes"
    );

    // Restoring the exact retained identity lets the SAME approved dispatch
    // publish the approved bytes at the approved destination, once.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o644))
            .expect("unlock the retained leaf");
    }
    std::fs::write(&leaf, &intact).expect("restore the retained leaf");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o444))
            .expect("reseal the retained leaf");
    }
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-d1-restored",
        )
        .expect("the restored approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["profileId"], "site-agent");
    let commit = publication["commit"].as_str().expect("the commit sha");
    assert_eq!(
        git_bytes(
            &fixture.worktree,
            &[
                "show",
                &format!("{}:registry/workloads/site-agent/profile.toml", commit)
            ]
        ),
        draft["declaration"]["renderedToml"]
            .as_str()
            .expect("the approved declaration")
            .as_bytes(),
        "the approved destination carries exactly the approved bytes"
    );
    assert!(
        !fixture
            .worktree
            .join("registry/workloads/shadow-destination")
            .try_exists()
            .expect("shadow destination probe"),
        "the shadow destination still never materializes"
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
fn stale_target_revision_refuses_before_consume_and_the_approval_survives() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    dispatch.decide(&minted, minted_revision);
    let approved_before = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        approved_before.status,
        odin_domain::ApprovalStatus::Approved
    );

    // Advance the registry PAST the approved target with unrelated, fully
    // valid publications through the owner route itself.
    for (profile, description) in [
        ("other-agent", "the first unrelated profile"),
        ("third-agent", "the second unrelated profile"),
    ] {
        let mut answers = complete_answers();
        answers.description = Some(description.to_owned());
        let unrelated = fixture
            .route
            .draft(draft_request(profile, answers))
            .expect("the unrelated draft compiles");
        let declaration = unrelated
            .declaration
            .as_ref()
            .expect("complete declaration");
        fixture
            .route
            .publish(publish_request(
                profile,
                &declaration.declaration_digest,
                unrelated.publish_revision,
            ))
            .expect("the unrelated publication installs");
    }
    assert_eq!(
        store_revision(&fixture.store),
        3,
        "the registry advanced past the approved bound revision"
    );
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);

    // The owner's own seam refuses with the exact typed stale scope.
    let typed = fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect_err("the stale scope refuses at the owner's typed seam");
    match typed {
        WorkloadAuthoringFailure::StaleRevision { bound, .. } => assert_eq!(
            bound, target,
            "the typed refusal names the approved bound revision"
        ),
        other => panic!("expected a typed stale-revision refusal, got {other:?}"),
    }

    // The approved dispatch refuses BEFORE the gate consumes anything: the
    // stale scope dies at the readiness seam, not after the spend.
    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        minted.as_str(),
        "publish-stale-target",
    );
    let error = refused.expect_err("the stale target must refuse");
    assert!(
        matches!(error, HostToolOperationError::Arguments { .. }),
        "the refusal is the owning typed argument refusal, not a demand: {error:?}"
    );
    let after = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        after.status,
        odin_domain::ApprovalStatus::Approved,
        "the approval is not spent on a stale scope: {after:?}"
    );
    assert_eq!(
        after.revision, approved_before.revision,
        "the row never moved"
    );
    assert_eq!(
        after.consumed_by_command_id, None,
        "nothing consumed the approval"
    );
    assert_eq!(
        store_revision(&fixture.store),
        3,
        "the refusal published nothing"
    );
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the refusal committed nothing"
    );

    // The stack stays lawful: a fresh draft against the CURRENT registry
    // publishes through the same dispatch path.
    let fresh = dispatch.draft("site-agent", &complete_answers(), "draft-d1-fresh");
    let fresh_digest = fresh["declaration"]["declarationDigest"]
        .as_str()
        .expect("the fresh digest")
        .to_owned();
    let fresh_target = fresh["publishRevision"].as_u64().expect("fresh target");
    assert_eq!(
        fresh_target, 4,
        "the fresh draft binds the current registry"
    );
    let fresh_demand = dispatch
        .publish(
            "site-agent",
            &fresh_digest,
            fresh_target,
            "pending",
            "publish-d1-fresh-demand",
        )
        .expect_err("the fresh publish demands its own approval");
    let (fresh_minted, fresh_revision) = minted_demand(&fresh_demand);
    dispatch.decide(&fresh_minted, fresh_revision);
    let publication = dispatch
        .publish(
            "site-agent",
            &fresh_digest,
            fresh_target,
            fresh_minted.as_str(),
            "publish-d1-fresh",
        )
        .expect("the fresh approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], fresh_target);
}

/// Read-only preparation must not take the authoring lock or consume approval.
#[test]
fn missing_worktree_git_marker_refuses_before_consume_and_the_approval_survives() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    dispatch.decide(&minted, minted_revision);

    let marker = fixture.worktree.join(".git");
    let intact = std::fs::read_to_string(&marker).expect("the .git gitfile");
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    std::fs::remove_file(&marker).expect("remove the .git marker");

    // The owner's own seam refuses with the exact typed worktree failure.
    let typed = fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect_err("the unusable worktree refuses at the owner's typed seam");
    assert!(
        matches!(typed, WorkloadAuthoringFailure::WorktreeInvalid { .. }),
        "expected a typed worktree refusal, got {typed:?}"
    );

    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        minted.as_str(),
        "publish-no-git-marker",
    );
    let error = refused.expect_err("the missing marker must refuse");
    assert!(
        matches!(error, HostToolOperationError::Arguments { .. }),
        "the refusal is the owning typed argument refusal, not a demand: {error:?}"
    );
    let after = dispatch.approval_row(&minted).expect("the approved row");
    assert_eq!(
        after.status,
        odin_domain::ApprovalStatus::Approved,
        "the approval is not spent on an unusable worktree: {after:?}"
    );
    assert_eq!(
        after.consumed_by_command_id, None,
        "nothing consumed the approval"
    );
    assert_eq!(
        store_revision(&fixture.store),
        1,
        "the refusal published nothing"
    );

    // Restoring the exact marker lets the SAME approved dispatch publish:
    // the refusal spent nothing and the preparation mutated nothing.
    std::fs::write(&marker, intact).expect("restore the .git marker");
    fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect("the restored worktree prepares clean at the owner's seam");
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-marker-restored",
        )
        .expect("the restored approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
    assert_ne!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the restored dispatch is the one committer"
    );
}

/// Preparing an exact replay must preserve the store, receipt, and worktree unchanged.
#[test]
fn exact_replay_prepares_clean_publishes_nothing_and_executes_once_as_unchanged() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-demand",
        )
        .expect_err("the first publish dispatch demands approval");
    let (minted, minted_revision) = minted_demand(&demand);
    dispatch.decide(&minted, minted_revision);
    let publication = dispatch
        .publish("site-agent", &digest, target, minted.as_str(), "publish-d1")
        .expect("the approved publish dispatches");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
    let receipt_commit = SnapshotStore::new(&fixture.store)
        .publication_at(target)
        .expect("the durable receipt at the bound revision")
        .1
        .commit;
    let receipt_before = serde_json::to_value(
        SnapshotStore::new(&fixture.store)
            .publication_at(target)
            .expect("receipt")
            .1,
    )
    .expect("receipt JSON");
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);

    // The owner's read-only preparation proves replay eligibility against
    // the durable receipt — and by contract publishes nothing: the store
    // revision, the receipt's commit, and the worktree HEAD are untouched.
    fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect("the exact replay is eligible at the readiness seam");
    assert_eq!(
        store_revision(&fixture.store),
        target,
        "preparation publishes nothing"
    );
    assert_eq!(
        SnapshotStore::new(&fixture.store)
            .publication_at(target)
            .expect("the durable receipt survives preparation")
            .1
            .commit,
        receipt_commit,
        "the durable receipt is immutable under preparation"
    );
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "preparation commits nothing"
    );

    // A fresh demand over the identical operation: execution completes it
    // exactly once as `unchanged` at the SAME receipt, consuming only its
    // own approval — the consumed first approval stays terminal.
    let replay_demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-d1-replay-demand",
        )
        .expect_err("the replay demands its own approval");
    let (replay_minted, replay_revision) = minted_demand(&replay_demand);
    dispatch.decide(&replay_minted, replay_revision);
    let replayed = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            replay_minted.as_str(),
            "publish-d1-replay",
        )
        .expect("the approved replay dispatches");
    assert_eq!(replayed["outcome"], "unchanged");
    assert_eq!(replayed["publishedRevision"], target);
    assert_eq!(
        replayed["commit"].as_str(),
        Some(receipt_commit.as_str()),
        "the replay is addressed at the same immutable receipt"
    );
    assert_eq!(
        store_revision(&fixture.store),
        target,
        "the replay created no new revision"
    );
    assert_eq!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the replay committed nothing"
    );
    assert_eq!(
        serde_json::to_value(
            SnapshotStore::new(&fixture.store)
                .publication_at(target)
                .expect("replay receipt")
                .1,
        )
        .expect("receipt JSON"),
        receipt_before,
        "approval replay preserves the entire immutable receipt"
    );
    let replay_row = dispatch
        .approval_row(&replay_minted)
        .expect("the replay approval row");
    assert!(
        replay_row.consumed_by_command_id.is_some(),
        "the replay dispatch is the one consumer of its own approval"
    );
    let first_row = dispatch
        .approval_row(&minted)
        .expect("the first approval row");
    assert_eq!(
        first_row.status,
        odin_domain::ApprovalStatus::Consumed,
        "the first approval stays terminal, never re-consumed"
    );
}

#[test]
fn corrupt_active_store_refuses_before_initial_mint_and_recovers() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    assert_eq!(dispatch.approval_count(), 0, "no approval exists yet");

    // The owner's seam names the typed store fault before any demand.
    let intact = std::fs::read(&fixture.store).expect("the active store bytes");
    std::fs::write(&fixture.store, b"corrupt: not a snapshot").expect("corrupt the active store");
    let typed = fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect_err("the corrupt store refuses at the owner's typed seam");
    assert!(
        matches!(typed, WorkloadAuthoringFailure::PublicationRefused { .. }),
        "expected a typed store refusal, got {typed:?}"
    );

    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        "pending",
        "publish-corrupt-store",
    );
    let error = refused.expect_err("the corrupt active store must refuse");
    assert!(
        matches!(error, HostToolOperationError::Arguments { .. }),
        "the refusal is the owning typed argument refusal, not a demand: {error:?}"
    );
    assert_eq!(
        dispatch.approval_count(),
        0,
        "the readiness refusal minted nothing"
    );

    // The restored store demands its own approval and publishes through
    // the same dispatch stack.
    std::fs::write(&fixture.store, intact).expect("restore the active store");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-restored-store",
        )
        .expect_err("the restored stack demands its own approval");
    let (minted, minted_revision) = minted_demand(&demand);
    assert_eq!(dispatch.approval_count(), 1, "exactly one row was minted");
    dispatch.decide(&minted, minted_revision);
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-restored-store-approved",
        )
        .expect("the restored approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
}

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
        "pending",
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
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-cleared-destination",
        )
        .expect_err("the cleared stack demands its own approval");
    let (minted, minted_revision) = minted_demand(&demand);
    assert_eq!(dispatch.approval_count(), 1, "exactly one row was minted");
    dispatch.decide(&minted, minted_revision);
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-cleared-destination-approved",
        )
        .expect("the cleared approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
}

#[test]
fn missing_worktree_git_marker_refuses_before_initial_mint_and_recovers() {
    let fixture = fixture();
    let dispatch = GovernedDispatch::compose(&fixture);

    let draft = dispatch.draft("site-agent", &complete_answers(), "draft-d1");
    let digest = draft["declaration"]["declarationDigest"]
        .as_str()
        .expect("the declaration digest")
        .to_owned();
    let target = draft["publishRevision"].as_u64().expect("publish revision");
    assert_eq!(dispatch.approval_count(), 0, "no approval exists yet");

    let marker = fixture.worktree.join(".git");
    let intact = std::fs::read_to_string(&marker).expect("the .git gitfile");
    let head_before = git(&fixture.worktree, &["rev-parse", "HEAD"]);
    std::fs::remove_file(&marker).expect("remove the .git marker");

    // The owner's seam names the typed worktree failure before any demand.
    let typed = fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect_err("the unusable worktree refuses at the owner's typed seam");
    assert!(
        matches!(typed, WorkloadAuthoringFailure::WorktreeInvalid { .. }),
        "expected a typed worktree refusal, got {typed:?}"
    );

    let refused = dispatch.publish(
        "site-agent",
        &digest,
        target,
        "pending",
        "publish-no-git-marker-premint",
    );
    let error = refused.expect_err("the missing marker must refuse");
    assert!(
        matches!(error, HostToolOperationError::Arguments { .. }),
        "the refusal is the owning typed argument refusal, not a demand: {error:?}"
    );
    assert_eq!(
        dispatch.approval_count(),
        0,
        "the readiness refusal minted nothing"
    );

    // Restoring the exact marker lets the same stack publish end to end.
    std::fs::write(&marker, intact).expect("restore the .git marker");
    fixture
        .route
        .prepare_publish(&publish_request("site-agent", &digest, target))
        .expect("the restored worktree prepares clean at the owner's seam");
    let demand = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            "pending",
            "publish-marker-restored-premint",
        )
        .expect_err("the restored stack demands its own approval");
    let (minted, minted_revision) = minted_demand(&demand);
    assert_eq!(dispatch.approval_count(), 1, "exactly one row was minted");
    dispatch.decide(&minted, minted_revision);
    let publication = dispatch
        .publish(
            "site-agent",
            &digest,
            target,
            minted.as_str(),
            "publish-marker-restored-premint-approved",
        )
        .expect("the restored approved dispatch publishes");
    assert_eq!(publication["outcome"], "published");
    assert_eq!(publication["publishedRevision"], target);
    assert_ne!(
        git(&fixture.worktree, &["rev-parse", "HEAD"]),
        head_before,
        "the approved dispatch is the one committer"
    );
}

#[test]
fn a_draft_completes_deployment_facts_from_the_pinned_image() {
    let fixture = fixture();
    let stated = fixture
        .route
        .draft(draft_request("site-agent", complete_answers()))
        .expect("stated draft");
    let mut roles_only = complete_answers();
    roles_only.state_path = None;
    roles_only.export_pod_path = None;
    let completed = fixture
        .route
        .draft(draft_request("site-agent", roles_only))
        .expect("role-only draft");
    assert!(completed.missing.is_empty(), "{:?}", completed.missing);
    assert_eq!(
        completed
            .declaration
            .expect("declaration")
            .declaration_digest,
        stated.declaration.expect("declaration").declaration_digest
    );
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
    .expect("route");
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
fn an_undeclared_gateway_lane_is_refused_with_the_declared_routes() {
    let fixture = fixture();
    let mut answers = complete_answers();
    answers.gateway_lane = Some("kimi-k28".to_owned());
    let error = fixture
        .route
        .draft(draft_request("site-agent", answers))
        .expect_err("an undeclared lane is refused");
    let error = error.to_string();
    assert!(
        error.contains("declared routes:") && error.contains("zai-glm"),
        "{error}"
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
    assert!(lane
        .declared_alternatives
        .iter()
        .all(|candidate| candidate == "glm-flash"));
}

/// The default agent lane must still be supported by the selected seat.
#[test]
fn an_agent_draft_naming_no_lane_runs_the_declared_agent_lane() {
    let fixture = fixture();
    let seat = complete_answers().seat.expect("fixture seat");
    let route = |seat_lane: &str| {
        DaemonWorkloadAuthoring::new(
            fixture.pin_handle(),
            fixture.worktree.clone(),
            fixture.store.clone(),
            fixture.ledger_path(),
            fixture.state_root(),
            Some(crate::kube::WorkloadDeploymentFacts {
                agent_lane: Some("zai-glm".to_owned()),
                ..fixture_deployment()
            }),
            None,
        )
        .expect("route")
        .with_seat_lanes([(seat.clone(), vec![seat_lane.to_owned()])].into())
    };
    let mut answers = complete_answers();
    answers.gateway_lane = None;
    let draft = route("zai-glm")
        .draft(draft_request("site-agent", answers.clone()))
        .expect("the declared agent lane fills the draft");
    let declaration = draft.declaration.expect("complete declaration");
    assert!(
        declaration
            .rendered_toml
            .contains("gateway_lane = \"zai-glm\""),
        "{}",
        declaration.rendered_toml
    );
    let error = route("glm-flash")
        .draft(draft_request("site-agent", answers))
        .expect_err("a seat that does not run the agent lane refuses it")
        .to_string();
    assert!(
        error.contains("runs only on gateway lane(s) glm-flash"),
        "{error}"
    );
}
