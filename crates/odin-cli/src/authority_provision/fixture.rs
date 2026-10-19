//! Shared registry and configuration fixture for the authority
//! provisioning invariant tests.

use std::fs;
use std::path::Path;

use odin_domain::CommandId;
use odin_huginn::OdindConfig;
use odin_registry::SnapshotStore;
use tempfile::TempDir;

use crate::test_support::{commit_all, git};

const NODE_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "authority fixture node"
host = "laptop-host"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true
"#;

const HOST_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "authority fixture host"
hardware = "fixture"
role = "control"
tailscale = "laptop-host"
enrolled = true
"#;

pub(crate) const SEAT_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "Architect authority fixture seat"
categories = ["builder", "coordinator"]
tool_refs = []
project_scope = ["odin", "dotfiles"]
approval_defaults = { r0 = "auto", r1 = "auto", r2 = "auto", r3 = "approval" }
brain_scope = ["atlas.code"]
limits = { max_parallel_runs = 2, max_sessions = 2, budget = { usd_micros = 1000000, window = { duration_seconds = 2592000 } } }
live = { max_sessions = 2, file_ingress_lane = "file.in", file_egress_lane = "file.out", render_ingress_lane = "render.in", render_egress_lane = "render.out" }
knowledge = { atlas_sources = ["atlas.code"], required_tags = [], denied_tags = [], top_k = 16 }
context = { max_bundle_tokens = 24576, profile = "fixture" }
tools = { deny = [], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] } }
"#;

const SLICE_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "slice"
enabled = true
description = "Architect authority fixture slice"
capabilities = ["task.read"]
variables = {}
redirects = { out_of_scope = "NeedsPlan" }
budget = { usd_micros = 500000, window = { duration_seconds = 86400 } }
live = { max_sessions_per_seat = 8, max_prompt_bytes = 262144, transfer_chunk_bytes = 1048576, max_file_bytes = 268435456, max_render_bytes = 67108864, allowed_file_media_types = ["text/plain"], allowed_render_media_types = ["image/png"] }
knowledge = { required = false, atlas_sources = ["atlas.code"], retrieval_mode = "hybrid", candidate_limit = 128, top_k = 24, min_score_micros = 100000, chunk_tokens = 512, chunk_overlap_tokens = 64, embedding_backend = "local" }
context = { max_bundle_tokens = 32768, reserve_output_tokens = 4096, control_tokens = 4096, history_tokens = 12288, core_tokens = 2048, prefetch_tokens = 512, tool_result_tokens = 4096, tool_schema_tokens = 4096, max_item_tokens = 2048 }
tools = { allow = [], deny = [], redirects = { max_http_hops = 2, allow_cross_origin = false, allow_https_downgrade = false }, alias_redirect = [] }
"#;

const CONTAINER_TOML: &str = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Architect authority fixture container"
purpose = "architect"
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
/// validated repository registry (`registry/capabilities/task.read`). Its
/// declared binding tuple is compiled into
/// `odin_omp::host_tools::PRE_ADMITTED_BINDINGS`, so the fixture exercises
/// the production admission catalog instead of a mock validator.
const CAPABILITY_TOML: &str = r#"
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

fn session_lane_toml(project: &str) -> String {
    format!(
        r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "architect fixture lane for {project}"
project = "{project}"
family = "engine"
default_seat = "architect"
queue = "interactive"
requires_independent_review = false
"#
    )
}

fn transfer_lane_toml(name: &str, direction: &str, payload: &str) -> String {
    format!(
        r#"
schema = "odin.registry.v1"
kind = "lane"
enabled = true
description = "fixture transfer lane {name}"
project = "odin"
family = "transfer"
default_seat = "architect"
queue = "interactive"
requires_independent_review = false
direction = "{direction}"
payload_kind = "{payload}"
"#
    )
}

fn project_toml(description: &str) -> String {
    format!(
        r#"
schema = "odin.registry.v1"
kind = "project"
enabled = true
description = "{description}"
source_root = ""
default_seat = "architect"
memory_namespaces = ["atlas.code"]
artifact_policy = "standard"
"#
    )
}

fn provider_toml() -> String {
    r#"
schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "authority fixture gateway"
adapter = "litellm-gateway"

[policy]
routes = [
  { gateway_lane_id = "zai-glm", gateway_model_id = "openai/glm-5.3" },
  { gateway_lane_id = "glm-flash", gateway_model_id = "openai/glm-5.3-flash" },
]

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

pub(crate) struct Fixture {
    pub(crate) _temporary: TempDir,
    pub(crate) config: OdindConfig,
}

pub(crate) fn write_object(worktree: &Path, kind: &str, id: &str, file: &str, body: &str) {
    let directory = worktree.join("registry").join(kind).join(id);
    fs::create_dir_all(&directory).expect("create object directory");
    fs::write(directory.join(file), body).expect("write object config");
}

pub(crate) fn fixture() -> Fixture {
    let temporary = TempDir::new().expect("fixture root");
    let root = temporary.path();
    let worktree = root.join("authoring");
    fs::create_dir(&worktree).expect("create authoring worktree");
    git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
    for kind in odin_registry::RegistryKind::ALL {
        let directory = worktree.join("registry").join(kind.directory());
        fs::create_dir_all(&directory).expect("create kind directory");
        fs::write(directory.join(".gitkeep"), b"").expect("kind placeholder");
    }
    write_object(&worktree, "nodes", "laptop", "node.toml", NODE_TOML);
    write_object(&worktree, "hosts", "laptop-host", "host.toml", HOST_TOML);
    write_object(&worktree, "seats", "architect", "seat.toml", SEAT_TOML);
    write_object(
        &worktree,
        "context-profiles",
        "fixture",
        "context-profile.toml",
        "schema = \"odin.registry.v1\"\nkind = \"context-profile\"\nenabled = true\ndescription = \"Fixture context profile.\"\ncore_tokens = 2048\ninject_tokens = 512\ninject_k = 8\n",
    );
    write_object(
        &worktree,
        "slices",
        "architect-core",
        "slice.toml",
        SLICE_TOML,
    );
    write_object(
        &worktree,
        "containers",
        "architect-native",
        "container.toml",
        CONTAINER_TOML,
    );
    write_object(
        &worktree,
        "capabilities",
        "task.read",
        "capability.toml",
        CAPABILITY_TOML,
    );
    write_object(
        &worktree,
        "providers",
        "gateway",
        "provider.toml",
        &provider_toml(),
    );
    write_object(
        &worktree,
        "projects",
        "odin",
        "project.toml",
        &project_toml("Odin fixture project"),
    );
    write_object(
        &worktree,
        "projects",
        "dotfiles",
        "project.toml",
        &project_toml("Dotfiles fixture project"),
    );
    write_object(
        &worktree,
        "lanes",
        "architect-odin",
        "lane.toml",
        &session_lane_toml("odin"),
    );
    write_object(
        &worktree,
        "lanes",
        "architect-dotfiles",
        "lane.toml",
        &session_lane_toml("dotfiles"),
    );
    write_object(
        &worktree,
        "lanes",
        "file.in",
        "lane.toml",
        &transfer_lane_toml("file.in", "ingress", "file"),
    );
    write_object(
        &worktree,
        "lanes",
        "file.out",
        "lane.toml",
        &transfer_lane_toml("file.out", "egress", "file"),
    );
    write_object(
        &worktree,
        "lanes",
        "render.in",
        "lane.toml",
        &transfer_lane_toml("render.in", "ingress", "render"),
    );
    write_object(
        &worktree,
        "lanes",
        "render.out",
        "lane.toml",
        &transfer_lane_toml("render.out", "egress", "render"),
    );
    fs::create_dir_all(worktree.join("schemas/capability")).expect("capability schema root");
    fs::write(worktree.join("schemas/.gitkeep"), b"").expect("schemas placeholder");
    fs::write(
        worktree.join("schemas/capability/task.read.input.json"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/capability/task.read.input.json"
        )),
    )
    .expect("task.read input schema");
    fs::write(
        worktree.join("schemas/capability/task.read.output.json"),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/capability/task.read.output.json"
        )),
    )
    .expect("task.read output schema");
    let commit = commit_all(&worktree, "authority fixture registry");
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &worktree,
        &commit,
        odin_omp::host_tools::PRE_ADMITTED_BINDINGS
            .iter()
            .map(|binding| binding.to_admitted_binding()),
    )
    .expect("committed authority fixture candidate");
    let snapshot_path = root.join("state/registry/snapshot.json");
    SnapshotStore::new(&snapshot_path)
        .publish_committed(&candidate, 1)
        .expect("publish authority fixture snapshot");

    let config_path = root.join("odind.toml");
    fs::write(&config_path, config_text(root, &snapshot_path)).expect("write fixture config");
    let config = OdindConfig::load(&config_path).expect("fixture config loads");
    fs::create_dir_all(root.join("projects/odin")).expect("project root");
    fs::create_dir_all(root.join("projects/dotfiles")).expect("project root");
    Fixture {
        _temporary: temporary,
        config,
    }
}

fn config_text(root: &Path, snapshot: &Path) -> String {
    format!(
        "schema = 'odin.odind-config.v1'\n\
         revision = 1\n\
         worker_bus = 'unix:path={0}/worker-bus.sock'\n\
         [identity]\nnode = 'laptop'\n\
         [paths]\n\
         registry_root = '{0}/registry'\n\
         state_root = '{0}/state'\n\
         registry_snapshot = '{1}'\n\
         authority_token_root = '{0}/state/authority/tokens'\n\
         authority_verification_key_file = '{0}/authority/verification.key'\n\
         [listener]\naddress = '127.0.0.1:18421'\n\
         [executables]\nomp_bin = '{0}/omp'\nomp_revision = '{2}'\nextension = '{0}/index.ts'\nzellij_bin = '{0}/zellij'\nzellij_session = 'odin'\n\
         [catalogs.gateway_projection]\npath = '{0}/projection.json'\ndigest = 'blake3:{3}'\n\
         [publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'file.out'\nrender_lane = 'render.out'\n\
         [projects.odin]\nroot = '{0}/projects/odin'\n\
         [projects.dotfiles]\nroot = '{0}/projects/dotfiles'\n\
         [[lane_bindings]]\nseat = 'architect'\nproject = 'odin'\nlane = 'architect-odin'\n\
         [[lane_bindings]]\nseat = 'architect'\nproject = 'dotfiles'\nlane = 'architect-dotfiles'\n\
         [[seats]]\nseat = 'architect'\nslice = 'architect-core'\ndisplay_name = 'Architect'\nmax_sessions = 2\nlaunch_options = [{{ provider = 'gateway', model = 'zai-glm', skeletonRef = 'architect-odin', containerId = 'architect-native' }}, {{ provider = 'gateway', model = 'glm-flash', skeletonRef = 'architect-odin', containerId = 'architect-native' }}]\nallowed_nodes = ['laptop']\n\
         [capacity]\n",
        root.display(),
        snapshot.display(),
        "a".repeat(40),
        "c".repeat(64)
    )
}

pub(crate) fn command(raw: &str) -> CommandId {
    CommandId::new(raw).expect("fixture command id")
}
