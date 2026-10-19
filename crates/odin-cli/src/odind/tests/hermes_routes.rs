//! Missing Discord credentials must disable route startup; a closed vehicle
//! must fail its open request without stopping the daemon.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use odin_domain::huginn::{
    LiveError, LiveEventBody, LiveLaunchOption, LiveSessionId, LiveSessionState, ModelName,
    ProviderName, SessionCloseReason, SessionClosed, SessionEpoch, SessionManifest,
};
use odin_domain::{
    CapabilityId, CommandId, ContainerId, EventId, LaneId, NodeId, ProjectId, SeatId, SliceId,
};
use odin_hermes::config::{DiscordSettings, HermesSettings};
use odin_hermes::runtime::{ConversationOwnership, HermesLedgers, HermesRuntime};
use odin_huginn::incidents::{IncidentSeverityView, IncidentStatusView};
use odin_huginn::read_model::MaterializedReadModel;
use odin_omp::live::lane_artifacts::{FsLaneArtifactPort, LaneTransferBridge};
use odin_omp::live::ledger::fs::FsLiveLedger;
use odin_omp::live::ledger::{LiveLedger, NewLiveEvent};
use odin_omp::live::service::OmpLiveService;
use odin_omp::live::supervisor::{
    session_id_for, LiveSeatBinding, LiveSessionLauncher, LiveSupervisor, SessionRuntime,
};
use odin_omp::live::transfer::{RegistryTransferLaneResolver, TransferManager};
use odin_registry::schema::SeatConversationToml;
use odin_registry::{ObjectConfig, RegistryKind, SnapshotHandle, SnapshotStore};
use tempfile::TempDir;
use time::OffsetDateTime;

use super::*;
use crate::live::vehicle_open::tests::published_incidents;
use crate::live::vehicle_open::{arm_vehicle_open_lane, VehicleRetrySchedule};
use crate::test_fixture::fixture_config_text;
use crate::test_support::{commit_all, git};

/// Subprocesses isolate credential presence from the parent test environment.
const GATE_MODE_VAR: &str = "ODIN_HERMES_ROUTE_GATE_MODE";
const GATE_TEST_PATH: &str = "live::hermes_routes::tests::declared_absent_credential_composes_no_route_and_armed_stays_fail_closed";

/// Published declarations exercise the same authority composition as startup.
const GATE_SEAT_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "route gate fixture coordinator seat"
categories = ["coordinator", "builder"]
tool_refs = []
project_scope = ["research"]
approval_defaults = { r0 = "auto", r1 = "auto", r2 = "auto", r3 = "approval" }
brain_scope = ["atlas.code"]
limits = { max_parallel_runs = 2, max_sessions = 2, budget = { usd_micros = 1000000, window = { duration_seconds = 2592000 } } }
live = { max_sessions = 2, file_ingress_lane = "file.in", file_egress_lane = "file.out", render_ingress_lane = "render.in", render_egress_lane = "render.out" }
knowledge = { atlas_sources = ["atlas.code"], required_tags = [], denied_tags = [], top_k = 16 }
context = { max_bundle_tokens = 24576, profile = "fixture" }
tools = { deny = [], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] } }
"#;

const GATE_SLICE_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = true
description = "route gate fixture coordinator slice"
capabilities = ["task.read"]
variables = {}
redirects = { out_of_scope = "NeedsPlan" }
budget = { usd_micros = 500000, window = { duration_seconds = 86400 } }
live = { max_sessions_per_seat = 8, max_prompt_bytes = 262144, transfer_chunk_bytes = 1048576, max_file_bytes = 268435456, max_render_bytes = 67108864, allowed_file_media_types = ["text/plain"], allowed_render_media_types = ["image/png"] }
knowledge = { required = false, atlas_sources = ["atlas.code"], retrieval_mode = "hybrid", candidate_limit = 128, top_k = 24, min_score_micros = 100000, chunk_tokens = 512, chunk_overlap_tokens = 64, embedding_backend = "local" }
context = { max_bundle_tokens = 32768, reserve_output_tokens = 4096, control_tokens = 4096, history_tokens = 12288, core_tokens = 2048, prefetch_tokens = 6144, tool_result_tokens = 4096, tool_schema_tokens = 4096, max_item_tokens = 2048 }
tools = { allow = [], deny = [], redirects = { max_http_hops = 2, allow_cross_origin = false, allow_https_downgrade = false }, alias_redirect = [] }
"#;

const GATE_CONTAINER_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "route gate fixture coordinator container"
purpose = "coordinator"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = []
identity_fields = ["purpose", "base", "contents.kind"]
tunables = { cycles = 8 }
surface = ["status"]
contents = { kind = "scripts" }
monitoring = "none"
"#;

/// The real `task.read` capability contract, mirrored verbatim from the
/// validated repository registry: its binding tuple is compiled into
/// `odin_omp::host_tools::PRE_ADMITTED_BINDINGS`, so the fixture publishes
/// through the production admission catalog, never a mock validator.
const GATE_CAPABILITY_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Read the nonblocking lifecycle truth of one delegated worker: the durable delegation row, supervisor liveness, and the fixed configuration. Only the delegating parent may read a row, and a worker that cannot be proven finished is never reported completed."
handler = { id = "odin_task.read" }
input_schema = "schemas/capability/task.read.input.json"
output_schema = "schemas/capability/task.read.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 5
idempotency = "pure"
retry = { max_attempts = 0 }
approval_policy = "none"
evidence_extractor = { id = "odin_task.read_evidence" }
"#;

fn gate_session_lane_toml() -> String {
    r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "route gate fixture coordinator research session lane"
project = "research"
family = "engine"
default_seat = "coordinator"
queue = "interactive"
requires_independent_review = false
"#
    .to_owned()
}

fn gate_transfer_lane_toml(name: &str, direction: &str, payload: &str) -> String {
    format!(
        r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "route gate fixture transfer lane {name}"
project = "research"
family = "transfer"
default_seat = "coordinator"
queue = "interactive"
requires_independent_review = false
direction = "{direction}"
payload_kind = "{payload}"
"#
    )
}

fn gate_project_toml() -> String {
    r#"
schema = "odin.registry.v1"
kind = "project"
enabled = true
description = "route gate fixture research project"
source_root = ""
default_seat = "coordinator"
memory_namespaces = ["atlas.code"]
artifact_policy = "standard"
"#
    .to_owned()
}

fn gate_provider_toml() -> String {
    r#"
schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "route gate fixture gateway"
adapter = "litellm-gateway"

[policy]
routes = [{ gateway_lane_id = "zai-glm", gateway_model_id = "openai/glm-5.3" }]

[budget]
usd_micros = 30000000

[budget.window]
duration_seconds = 2592000

[recovery]
allowed_rungs = ["retry", "restart_worker", "checkpoint", "rehome", "escalate"]
blocked_missing_decision = "operator decision required"

[recovery.max_attempts]
retry = 2
restart_worker = 1
checkpoint = 1
rehome = 1
escalate = 1

[recovery.cooldown_seconds]
retry = 30
restart_worker = 30
checkpoint = 60
rehome = 60
escalate = 0
"#
    .to_owned()
}

struct GateLauncherStub;

#[async_trait::async_trait]
impl LiveSessionLauncher for GateLauncherStub {
    fn harness_turns(&self) -> Option<std::sync::Arc<odin_omp::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _manifest: &SessionManifest,
        _epoch: SessionEpoch,
        _reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Err(LiveError::Unsupported {
            operation: "route gate regression stub".to_owned(),
        })
    }
}

pub(crate) struct GateFixture {
    pub(crate) _root: TempDir,
    pub(crate) config: OdindConfig,
    pub(crate) manifest: odin_huginn::RuntimeManifest,
    pub(crate) operation_store: Arc<std::sync::Mutex<Ledger>>,
    pub(crate) operation_clock: odin_kernel::operation::Clock,
    pub(crate) session_pool: Arc<odin_cli::live_authority::SessionAuthorityPool>,
    pub(crate) pin: Arc<SnapshotHandle>,
    pub(crate) omp: Arc<OmpLiveService>,
    pub(crate) supervisor: Arc<LiveSupervisor>,
    pub(crate) ledger: Arc<dyn LiveLedger>,
    pub(crate) runtime: Arc<HermesRuntime>,
    seat: SeatId,
    slice: SliceId,
    project: ProjectId,
    lane: LaneId,
    ask_id: CapabilityId,
    launch: LiveLaunchOption,
    pub(crate) read_model: Arc<MaterializedReadModel>,
    pub(crate) ledger_path: PathBuf,
    pub(crate) record_path: PathBuf,
    record_bytes: Vec<u8>,
    session: LiveSessionId,
}

impl GateFixture {
    /// The exact declared binding production composes: declaration plus
    /// the served vehicle (seat binding + lane) under the exact ownership.
    pub(crate) fn binding(&self) -> DeclaredConversationBinding {
        DeclaredConversationBinding {
            ownership: ConversationOwnership {
                seat: self.seat.clone(),
                project: self.project.clone(),
                ask_capability: self.ask_id.clone(),
            },
            declaration: SeatConversationToml {
                project: self.project.clone(),
                ask_capability: self.ask_id.clone(),
                guidance: "Use plain language.".to_owned(),
                answer_timeout_seconds: NonZeroU64::new(240).expect("answer bound"),
            },
            vehicle: Some((
                LiveSeatBinding {
                    seat_id: self.seat.clone(),
                    slice_id: self.slice.clone(),
                    display_name: "Coordinator".to_owned(),
                    launch_options: vec![self.launch.clone()],
                    allowed_nodes: vec![NodeId::new("laptop").expect("node id")],
                    max_sessions: 1,
                    turn_budget: None,
                },
                self.lane.clone(),
            )),
        }
    }

    pub(crate) fn hermes_runtime_arg(&self) -> Option<Arc<HermesRuntime>> {
        Some(Arc::clone(&self.runtime))
    }
}

/// Compose published declarations with a retained, terminal vehicle and a launcher that refuses opens.
pub(crate) async fn gate_fixture() -> GateFixture {
    gate_fixture_with(256, Arc::new(GateLauncherStub), true).await
}

pub(crate) async fn gate_fixture_with(
    supervisor_max_sessions: usize,
    launcher: Arc<dyn LiveSessionLauncher>,
    stage_terminal_vehicle: bool,
) -> GateFixture {
    let root = TempDir::new().expect("gate fixture root");
    let worktree = root.path().join("authoring");
    std::fs::create_dir(&worktree).expect("create authoring worktree");
    git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
    for kind in RegistryKind::ALL {
        let directory = worktree.join("registry").join(kind.directory());
        std::fs::create_dir_all(&directory).expect("create kind directory");
        std::fs::write(directory.join(".gitkeep"), b"").expect("kind placeholder");
    }
    let write_object = |kind: &str, id: &str, file: &str, body: &str| {
        let directory = worktree.join("registry").join(kind).join(id);
        std::fs::create_dir_all(&directory).expect("create object directory");
        std::fs::write(directory.join(file), body).expect("write object config");
    };
    write_object(
        "nodes",
        "laptop",
        "node.toml",
        &crate::test_fixture::odind_node_toml("laptop", true),
    );
    write_object(
        "hosts",
        "laptop-host",
        "host.toml",
        &crate::test_fixture::odind_host_toml("laptop"),
    );
    write_object("seats", "coordinator", "seat.toml", GATE_SEAT_TOML);
    write_object(
        "context-profiles",
        "fixture",
        "context-profile.toml",
        "schema = \"odin.registry.v1\"\nkind = \"context-profile\"\nenabled = true\ndescription = \"Fixture context profile.\"\ncore_tokens = 2048\ninject_tokens = 6144\ninject_k = 8\n",
    );
    write_object("slices", "coordinator-work", "slice.toml", GATE_SLICE_TOML);
    write_object(
        "containers",
        "coordinator-native",
        "container.toml",
        GATE_CONTAINER_TOML,
    );
    write_object(
        "capabilities",
        "task.read",
        "capability.toml",
        GATE_CAPABILITY_TOML,
    );
    write_object(
        "providers",
        "gateway",
        "provider.toml",
        &gate_provider_toml(),
    );
    write_object(
        "providers",
        "observed",
        "provider.toml",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../registry/providers/observed/provider.toml"
        )),
    );
    write_object("projects", "research", "project.toml", &gate_project_toml());
    write_object(
        "lanes",
        "coordinator-research",
        "lane.toml",
        &gate_session_lane_toml(),
    );
    write_object(
        "lanes",
        "file.in",
        "lane.toml",
        &gate_transfer_lane_toml("file.in", "ingress", "file"),
    );
    write_object(
        "lanes",
        "file.out",
        "lane.toml",
        &gate_transfer_lane_toml("file.out", "egress", "file"),
    );
    write_object(
        "lanes",
        "render.in",
        "lane.toml",
        &gate_transfer_lane_toml("render.in", "ingress", "render"),
    );
    write_object(
        "lanes",
        "render.out",
        "lane.toml",
        &gate_transfer_lane_toml("render.out", "egress", "render"),
    );
    write_object(
        "lanes",
        "lane-file",
        "lane.toml",
        &gate_transfer_lane_toml("lane-file", "egress", "file"),
    );
    write_object(
        "lanes",
        "lane-render",
        "lane.toml",
        &gate_transfer_lane_toml("lane-render", "egress", "render"),
    );
    std::fs::create_dir_all(worktree.join("schemas/capability")).expect("capability schema root");
    std::fs::write(worktree.join("schemas/.gitkeep"), b"").expect("schemas placeholder");
    std::fs::write(
        worktree.join("schemas/capability/task.read.input.json"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/capability/task.read.input.json"
        )),
    )
    .expect("task.read input schema");
    std::fs::write(
        worktree.join("schemas/capability/task.read.output.json"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/capability/task.read.output.json"
        )),
    )
    .expect("task.read output schema");
    std::fs::create_dir_all(root.path().join("projects/research")).expect("project root");
    std::fs::create_dir_all(root.path().join("state")).expect("state root");
    let commit = commit_all(&worktree, "route gate fixture registry");
    let snapshot_path = root.path().join("state/registry/snapshot.json");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("committed route gate fixture candidate");
    SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, 1)
        .expect("publish route gate fixture snapshot");
    // Startup authority composition requires a UUID render session.
    let config_text = fixture_config_text(root.path(), &snapshot_path)
        .replacen(
            "render_session = 'live-1'",
            "render_session = '00000000-0000-4000-8000-0000000000aa'",
            1,
        )
        + &format!(
            "[projects.research]\nroot = '{0}/projects/research'\n\
             [[lane_bindings]]\nseat = 'coordinator'\nproject = 'research'\nlane = 'coordinator-research'\n\
             [[seats]]\nseat = 'coordinator'\nslice = 'coordinator-work'\ndisplay_name = 'Coordinator'\nmax_sessions = 2\nlaunch_options = [{{ provider = 'gateway', model = 'zai-glm', skeletonRef = 'coordinator-research', containerId = 'coordinator-native' }}]\nallowed_nodes = ['laptop']\n",
            root.path().display()
        );
    assert!(
        config_text.contains("render_session = '00000000-0000-4000-8000-0000000000aa'"),
        "the shared fixture config no longer exposes the expected render_session line"
    );
    let config = OdindConfig::parse(&config_text).expect("fixture config parses");
    // Startup eagerly validates the registered ssh binding — the Claude host
    // transport stats the executable at compose time — so unlike the pure
    // identities below the ssh path must name a real file. These vehicle
    // tests still never dispatch it.
    let ssh = root.path().join("ssh");
    std::fs::write(&ssh, b"#!/bin/sh\nexit 0\n").expect("write fixture ssh executable");
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755))
        .expect("protect fixture ssh executable");
    let mut manifest = crate::test_fixture::manifest_identity_fixture("ssh", &ssh);
    for key in ["worker_bootstrap", "unshare"] {
        manifest.executables.extend(
            crate::test_fixture::manifest_identity_fixture(key, &root.path().join(key)).executables,
        );
    }
    let pin =
        Arc::new(SnapshotHandle::open(SnapshotStore::new(&snapshot_path)).expect("fixture pin"));

    // The authority minting secret: a real 64-byte key at the configured
    // path (mode 0600), so the armed startup's ensure mints its token the
    // way `odin authority init` provisions production.
    let key_path = config.paths.authority_verification_key_file.clone();
    std::fs::create_dir_all(key_path.parent().expect("authority key parent"))
        .expect("authority key root");
    std::fs::write(&key_path, vec![b'k'; 64]).expect("provision authority key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("protect authority key");

    let seat = SeatId::new("coordinator").expect("seat id");
    let slice = SliceId::new("coordinator-work").expect("slice id");
    let project = ProjectId::new("research").expect("project id");
    let lane = LaneId::new("coordinator-research").expect("lane id");
    let ask_id = CapabilityId::new("coord.assist").expect("ask capability id");
    let intake_id = CapabilityId::new("coord.discord.intake").expect("intake capability id");
    let launch = LiveLaunchOption {
        provider: ProviderName::new("gateway").expect("provider name"),
        model: ModelName::new("zai-glm").expect("model name"),
        skeleton_ref: "coordinator-research".to_owned(),
        container_id: ContainerId::new("coordinator-native").expect("container id"),
        harness: None,
    };

    // The deterministic vehicle identity and its TERMINAL retained state.
    let vehicle_command =
        CommandId::new("command:conversation-open:route-gate-fixture").expect("vehicle command");
    let session = session_id_for(&vehicle_command).expect("deterministic vehicle session");
    let ledger: Arc<dyn LiveLedger> =
        Arc::new(FsLiveLedger::open(root.path().join("live-ledger")).expect("live ledger"));
    if stage_terminal_vehicle {
        ledger
            .create_session(SessionManifest {
                session_id: session,
                seat_id: seat.clone(),
                slice_id: slice.clone(),
                project_id: project.clone(),
                provider: ProviderName::new("fixture").expect("provider name"),
                model: ModelName::new("fixture-model").expect("model name"),
                title: None,
                target_node: NodeId::new("laptop").expect("node id"),
                open_tab: false,
                workload: None,
                served_revision: None,
                harness: None,
            })
            .await
            .expect("staged vehicle session");
        ledger
            .append(
                SessionEpoch::new(1),
                NewLiveEvent {
                    session_id: session,
                    event_id: EventId::new(format!("route-gate-closed:{session}"))
                        .expect("event id"),
                    occurred_at: OffsetDateTime::now_utc(),
                    body: LiveEventBody::SessionClosed(SessionClosed {
                        reason: SessionCloseReason::Completed,
                    }),
                },
            )
            .await
            .expect("staged terminal closure");
    }

    // The real live plane production binds: service over supervisor and
    // durable transfers, exactly as the follower fixture composes them.
    let resolver = Arc::new(RegistryTransferLaneResolver::read_only(Arc::clone(&ledger)));
    let lane_port = Arc::new(
        FsLaneArtifactPort::open(root.path().join("lane-artifacts")).expect("lane artifact port"),
    );
    let bridge = Arc::new(LaneTransferBridge::new(lane_port));
    let transfers = Arc::new(
        TransferManager::open(
            root.path().join("live-transfers"),
            Arc::clone(&ledger),
            resolver,
            bridge,
        )
        .expect("transfer manager"),
    );
    let supervisor =
        LiveSupervisor::new(Arc::clone(&ledger), launcher, supervisor_max_sessions, None);
    let omp = Arc::new(OmpLiveService::new(
        Arc::clone(&ledger),
        Arc::clone(&supervisor),
        transfers,
    ));

    // The admitted contracts the runtime re-proves: the ask capability
    // delegating exactly to the owner seat, and the configured intake
    // capability — both derived from the real committed declarations.
    let ask_contract = {
        let mut ask_object = odin_registry::schema::parse_object_toml(
            RegistryKind::Capability,
            ask_id.as_str(),
            "capabilities/coord.assist/capability.toml",
            include_str!("../../../../../registry/capabilities/seat.ask.sinmara/capability.toml"),
        )
        .expect("ask declaration");
        let ObjectConfig::Capability(ask) = &mut ask_object.config else {
            panic!("ask declaration");
        };
        ask.delegate_to = Some(seat.clone());
        let admitted = odin_registry::relational::declared_admitted_binding(ask)
            .expect("declared native binding");
        odin_kernel::CapabilityContract::try_from_registry(&ask_object, &admitted)
            .expect("admitted ask contract")
    };
    let intake_contract = {
        let intake_object = odin_registry::schema::parse_object_toml(
            RegistryKind::Capability,
            intake_id.as_str(),
            "capabilities/coord.discord.intake/capability.toml",
            include_str!("../../../../../registry/capabilities/discord.intake/capability.toml"),
        )
        .expect("intake declaration");
        let admitted = match &intake_object.config {
            ObjectConfig::Capability(intake) => {
                odin_registry::relational::declared_admitted_binding(intake)
                    .expect("declared intake binding")
            }
            _ => panic!("intake declaration"),
        };
        odin_kernel::CapabilityContract::try_from_registry(&intake_object, &admitted)
            .expect("admitted intake contract")
    };
    let contracts = BTreeMap::from([
        (ask_id.clone(), ask_contract),
        (intake_id.clone(), intake_contract),
    ]);

    let discord = DiscordSettings {
        seat: seat.clone(),
        project: project.clone(),
        owner_user_id: "1000000000000000001".to_owned(),
        notify_channel_id: "1000000000000000002".to_owned(),
        capability: intake_id,
        egress_capacity: 8,
        gateway_intents: 4096,
        bot_token_handle: "cred:discord.bot".to_owned(),
        scrub_tokens: BTreeSet::new(),
        ttl_seconds: 300,
    };
    let settings = HermesSettings::new(
        root.path().join("state/hermes"),
        Some(discord),
        None,
        None,
        Vec::new(),
    )
    .expect("hermes settings");
    let ledger_path = root.path().join("state/ledger.sqlite3");
    let runtime = HermesRuntime::open(
        settings,
        HermesLedgers {
            conversation: Ledger::open(&ledger_path).expect("conversation ledger"),
            adapter: Arc::new(parking_lot::Mutex::new(
                Ledger::open(&ledger_path).expect("adapter ledger"),
            )),
            purchase: Arc::new(std::sync::Mutex::new(
                Ledger::open(&ledger_path).expect("purchase ledger"),
            )),
        },
        &contracts,
        None,
        0,
        BTreeMap::new(),
        Some(ConversationOwnership {
            seat: seat.clone(),
            project: project.clone(),
            ask_capability: ask_id.clone(),
        }),
    )
    .expect("hermes runtime");
    let operation_store = Arc::new(std::sync::Mutex::new(
        Ledger::open(&ledger_path).expect("operation ledger"),
    ));
    let operation_clock = odin_omp::host_tools::operations::wall_clock();

    // The retained record AFTER runtime composition (the runtime creates
    // the conversation state directory): it names the terminal vehicle.
    let record_path = root
        .path()
        .join("state/hermes/conversations")
        .join(seat.as_str())
        .join("root.json");
    let record = serde_json::json!({
        "conversationId": "",
        "seat": seat.as_str(),
        "project": project.as_str(),
        "vehicleCommandId": vehicle_command.as_str(),
        "sessionId": session.to_string(),
        "inFlight": serde_json::Value::Null,
        "wakes": [],
        "lastIdempotencyKey": serde_json::Value::Null,
        "lastProjection": serde_json::Value::Null,
        "questions": [],
        "updatedAtUnixMs": 0,
    });
    let record_bytes = serde_json::to_vec_pretty(&record).expect("record bytes");
    if stage_terminal_vehicle {
        std::fs::write(&record_path, &record_bytes).expect("stage retained record");
    }
    // Production startup seals the one durable draft store before the hermes
    // runtime composes (the bridge runtime's publish pre-gate, from the state
    // root); the fixture mirrors that EXACT seal — same call, same root — so
    // the authoring route's confined bind finds the daemon's own store.
    odin_omp::host_tools::WorkloadDraftStore::seal(&config.paths.state_root)
        .expect("the fixture seals the daemon's draft store");
    let session_pool =
        odin_cli::live_authority::SessionAuthorityPool::open(&config, &manifest, vec![b'k'; 64])
            .expect("fixture session authority");

    GateFixture {
        _root: root,
        config,
        manifest,
        operation_store,
        operation_clock,
        session_pool,
        pin,
        omp,
        supervisor,
        ledger,
        runtime,
        seat,
        slice,
        project,
        lane,
        ask_id,
        launch,
        read_model: Arc::new(MaterializedReadModel::with_limits(
            4096,
            8192,
            OffsetDateTime::now_utc(),
        )),
        ledger_path,
        record_path,
        record_bytes,
        session,
    }
}

/// Declared absence (credential variable absent): bind composes NOTHING —
/// no route, no initialization, no reopen. The terminal retained vehicle
/// is untouched (record byte-identical; the live ledger still holds
/// exactly the staged Ended session), and the read seams plus the authoring
/// route still bind (every other surface keeps serving).
async fn disarmed_case() {
    let fixture = gate_fixture().await;
    let gateway = fixture
        .runtime
        .gateway()
        .as_ref()
        .expect("the declared surface composes a gateway");
    assert!(
        gateway.credential_absent(),
        "this case requires the declared-absent credential state"
    );

    let hermes_runtime = fixture.hermes_runtime_arg();
    let outcome = bind(
        &hermes_runtime,
        Some(fixture.binding()),
        &fixture.omp,
        &fixture.supervisor,
        &fixture.config,
        &fixture.manifest,
        &fixture.ledger_path,
        &fixture.pin,
        &fixture.read_model,
        &None,
        &Default::default(),
        &fixture_delegation_links(),
        None,
        Arc::clone(&fixture.operation_store),
        Arc::clone(&fixture.operation_clock),
        &fixture.session_pool,
    )
    .await;
    let conversation_root = outcome.expect("a disarmed surface must not fail the daemon's startup");
    assert!(
        conversation_root.is_none(),
        "the disarmed surface must compose no conversation route"
    );

    let written = std::fs::read(&fixture.record_path).expect("retained record");
    assert_eq!(
        written, fixture.record_bytes,
        "the disarmed startup must not touch the terminal retained vehicle record"
    );
    let sessions = fixture.ledger.sessions().await.expect("durable sessions");
    assert_eq!(
        sessions.len(),
        1,
        "no vehicle session may be opened or reopened on the disarmed surface"
    );
    assert_eq!(sessions[0].manifest.session_id, fixture.session);
    let (page, _) = fixture
        .supervisor
        .session_summaries_page(Some(&fixture.seat), true, None, 16)
        .await
        .expect("durable summaries");
    assert_eq!(page.len(), 1, "exactly the staged session exists");
    assert_eq!(page[0].state, LiveSessionState::Ended);
}

/// Opening a terminal vehicle must fail once without failing startup or reopening its identity.
async fn armed_case() {
    let fixture = gate_fixture().await;
    let gateway = fixture
        .runtime
        .gateway()
        .as_ref()
        .expect("the declared surface composes a gateway");
    assert!(
        !gateway.credential_absent(),
        "this case requires the armed (credential-present) state"
    );

    let hermes_runtime = fixture.hermes_runtime_arg();
    let outcome = bind(
        &hermes_runtime,
        Some(fixture.binding()),
        &fixture.omp,
        &fixture.supervisor,
        &fixture.config,
        &fixture.manifest,
        &fixture.ledger_path,
        &fixture.pin,
        &fixture.read_model,
        &None,
        &Default::default(),
        &fixture_delegation_links(),
        None,
        Arc::clone(&fixture.operation_store),
        Arc::clone(&fixture.operation_clock),
        &fixture.session_pool,
    )
    .await;
    let bound = match outcome {
        Ok(Some(bound)) => bound,
        Ok(None) => panic!(
            "an armed surface composes the conversation route: a healthy-looking \
             None would fake availability"
        ),
        Err(error) => panic!("a vehicle-open failure must not exit the daemon's startup: {error}"),
    };

    // The lane owns the initialize: arm it with a tight bounded schedule
    // and let its first attempt reach the terminal refusal.
    let read_model = Arc::new(MaterializedReadModel::with_limits(
        4096,
        8192,
        OffsetDateTime::now_utc(),
    ));
    let mut pumps = tokio::task::JoinSet::new();
    arm_vehicle_open_lane(
        &mut pumps,
        Some(bound),
        Arc::clone(&read_model),
        VehicleRetrySchedule::new(
            5,
            StdDuration::from_millis(20),
            StdDuration::from_millis(40),
        ),
    );
    let mut card = None;
    for _ in 0..100 {
        let cards = published_incidents(&read_model).await;
        if let Some(published) = cards.first() {
            card = Some(published.clone());
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(50)).await;
    }
    let card = card.expect("the lane never published the terminal-closure card");
    assert_eq!(
        card.failure_signature,
        "odind.conversation.vehicle.terminal-closed"
    );
    assert_eq!(card.severity, IncidentSeverityView::Critical);
    assert_eq!(card.status, IncidentStatusView::Open);
    assert_eq!(card.revision, 1, "one publish: the lane never retries");
    assert!(
        card.deviation.contains(&fixture.session.to_string()),
        "the card names the terminally closed vehicle session: {card:?}"
    );

    // Terminal means terminal: no reopen, no replacement, no journal
    // growth — the launcher stub would fail loudly on any open attempt,
    // and the record is untouched.
    let written = std::fs::read(&fixture.record_path).expect("retained record");
    assert_eq!(
        written, fixture.record_bytes,
        "the refused startup must not touch the terminal retained vehicle record"
    );
    tokio::time::sleep(StdDuration::from_millis(250)).await;
    let sessions = fixture.ledger.sessions().await.expect("durable sessions");
    assert_eq!(
        sessions.len(),
        1,
        "no vehicle session may be opened or reopened past the terminal refusal"
    );
    assert_eq!(sessions[0].manifest.session_id, fixture.session);

    // The owning shutdown cancels the parked lane.
    pumps.abort_all();
    let cancel = pumps
        .join_next()
        .await
        .expect("the lane task exists")
        .expect_err("an aborted task joins with a cancel error");
    assert!(cancel.is_cancelled(), "shutdown cancels the parked lane");
}

#[tokio::test]
async fn declared_absent_credential_composes_no_route_and_armed_stays_fail_closed() {
    match std::env::var(GATE_MODE_VAR).as_deref() {
        Ok("disarmed") => disarmed_case().await,
        Ok("armed") => armed_case().await,
        _ => {
            // Orchestrator: both children drive the REAL bind path under
            // subprocess env isolation. This process never touches the
            // credential variable, so concurrent tests are unaffected.
            let harness = std::env::current_exe().expect("test harness path");
            let run = |mode: &str, token: Option<&str>| {
                let mut command = Command::new(&harness);
                command
                    .args([
                        "--exact",
                        GATE_TEST_PATH,
                        "--test-threads",
                        "1",
                        "--nocapture",
                    ])
                    .env(GATE_MODE_VAR, mode)
                    .env_remove(odin_hermes::runtime::DISCORD_TOKEN_ENV);
                if let Some(token) = token {
                    command.env(odin_hermes::runtime::DISCORD_TOKEN_ENV, token);
                }
                command.output().expect("gate child harness")
            };
            let disarmed = run("disarmed", None);
            assert!(
                disarmed.status.success(),
                "the declared-absent child must compose no route: {}{}",
                String::from_utf8_lossy(&disarmed.stdout),
                String::from_utf8_lossy(&disarmed.stderr),
            );
            let armed = run("armed", Some("fixture-gateway-token"));
            assert!(
                armed.status.success(),
                "the armed child must refuse the closed vehicle through the lane without \
                 failing startup: {}{}",
                String::from_utf8_lossy(&armed.stdout),
                String::from_utf8_lossy(&armed.stderr),
            );
        }
    }
}

/// A private, empty delegation-link ledger for one composition fixture.
fn fixture_delegation_links() -> odin_omp::host_tools::delegation::DelegationLinkLedger {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "odind-fixture-links-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    odin_omp::host_tools::delegation::DelegationLinkLedger::open(root).expect("fixture link ledger")
}
