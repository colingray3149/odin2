use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

fn fixture_config() -> OdindConfig {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8420);
    OdindConfig {
        schema: ODIND_CONFIG_SCHEMA.to_owned(),
        revision: 4,
        identity: OdindIdentityConfig {
            node: "laptop".to_owned(),
        },
        paths: OdindPathsConfig {
            registry_root: PathBuf::from("/run/odin/registry"),
            state_root: PathBuf::from("/var/lib/odin"),
            registry_snapshot: PathBuf::from("/run/odin/registry/snapshot.json"),
            authority_token_root: PathBuf::from("/var/lib/odin/authority/tokens"),
            authority_verification_key_file: PathBuf::from("/run/odin/authority/verification.key"),
            operator_context_root: None,
            cargo_registry_cache: None,
            cargo_git_cache: None,
            nix_daemon_socket: None,
            nix_config_root: None,
            authoring_repository: None,
            authoring_worktree: None,
        },
        listener: OdindListenerConfig {
            address,
            tls_cert: None,
            tls_key: None,
        },
        executables: OdindExecutablesConfig {
            omp_bin: PathBuf::from("/nix/store/omp/bin/omp"),
            omp_revision: "a".repeat(40),
            extension: PathBuf::from("/nix/store/extension/index.ts"),
            zellij_bin: PathBuf::from("/nix/store/zellij/bin/zellij"),
            zellij_hub: "hub.test".to_owned(),
            attach_command: Vec::new(),
            browser: Some(OdindBrowserConfig {
                chromium: PathBuf::from("/nix/store/chromium/bin/chromium"),
                profile_root: PathBuf::from("/var/lib/odin/browser"),
                policy: PathBuf::from("/nix/store/policy.json"),
                protected_values: PathBuf::from("/nix/store/values.json"),
                scanner: PathBuf::from("/nix/store/scanner/bin/scanner"),
                scanner_args: Vec::new(),
                stream: "0f0e0d0c-0b0a-4948-8765-432109876543".to_owned(),
                display: OdindDisplayConfig {
                    source: BrowserDisplaySource::Xvfb,
                    xvfb_binary: Some(PathBuf::from("/nix/store/xvfb/bin/Xvfb")),
                    display: None,
                },
                idle_seconds: None,
            }),
            web_save: None,
            recon: None,
        },
        catalogs: OdindCatalogsConfig {
            gateway_projection: PathDigestRef {
                path: PathBuf::from("/nix/store/gateway/projection.json"),
                digest: format!("blake3:{}", "a".repeat(64)),
            },
        },
        projects: BTreeMap::from([(
            "atlas".to_owned(),
            OdindProjectConfig {
                root: PathBuf::from("/srv/atlas"),
                runtime: false,
            },
        )]),
        lane_bindings: vec![OdindLaneBinding {
            seat: odin_domain::SeatId::new("colin").expect("seat id"),
            project: odin_domain::ProjectId::new("atlas").expect("project id"),
            lane: odin_domain::LaneId::new("lane-main").expect("lane id"),
            runtime: false,
        }],
        seats: Vec::new(),
        file_roots: Vec::new(),
        tailnet_peers: BTreeMap::new(),
        publish: OdindPublishConfig {
            render_session: "live-0f0e0d0c-0b0a-4948-8765-432109876543".to_owned(),
            file_lane: "lane-file".to_owned(),
            render_lane: "lane-render".to_owned(),
        },
        worker_bus: "unix:path=/run/odin/worker-bus.sock".to_owned(),
        capacity: HuginnLimits::default(),
        delegation: None,
        kube: None,
        adapter_backends: BTreeMap::new(),
        research: None,
        gateway_host_credentials: BTreeMap::new(),
        brain: None,
        hermes: None,
        alerts: None,
        models: Default::default(),
    }
}

/// The shipped schema, compiled once for every test that checks a config against it.
fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: std::sync::OnceLock<jsonschema::Validator> = std::sync::OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../schemas/control/odind-config.schema.json"
        ))
        .expect("odind-config schema parses as JSON");
        jsonschema::validator_for(&schema).expect("odind-config schema compiles")
    })
}

fn fixture_hermes_config(state_dir: PathBuf) -> OdindHermesConfig {
    OdindHermesConfig {
        consult: None,
        state_dir,
        discord: Some(OdindHermesDiscordConfig {
            seat: "coordinator".to_owned(),
            project: "research".to_owned(),
            owner_user_id: "owner".to_owned(),
            owner_name: "the owner".to_owned(),
            notify_channel_id: "paired-channel".to_owned(),
            capability: "discord.intake".to_owned(),
            egress_capacity: 8,
            gateway_intents: 1,
            bot_token_handle: "cred:discord.bot".to_owned(),
            scrub_tokens: BTreeSet::new(),
            ttl_seconds: 300,
        }),
        vault: None,
        finance: None,
        accounts: Vec::new(),
        model_gateway: None,
        brain_raw_root: None,
    }
}

/// Points every declared mutable state path of the fixture inside `root`
/// so individual tests can move one field out and observe the refusal.
fn confine_fixture_state(config: &mut OdindConfig, state_root: &Path) {
    config.paths.state_root = state_root.to_path_buf();
    config.paths.authority_token_root = state_root.join("authority/tokens");
    if let Some(browser) = config.executables.browser.as_mut() {
        browser.profile_root = state_root.join("browser/profiles");
    }
}

#[test]
fn declared_state_paths_outside_the_state_root_are_refused_by_name() {
    let mut config = fixture_config();
    config.hermes = Some(fixture_hermes_config(PathBuf::from("/var/lib/odin-hermes")));
    let error = config
        .validate()
        .expect_err("a sibling-root hermes state dir must refuse");
    match &error {
        ConfigError::StatePathOutsideStateRoot { key, path, root } => {
            assert_eq!(key, "hermes.state_dir");
            assert_eq!(path, &PathBuf::from("/var/lib/odin-hermes"));
            assert_eq!(root, &PathBuf::from("/var/lib/odin"));
        }
        other => panic!("typed state-path refusal expected, got {other:?}"),
    }
    let message = error.to_string();
    assert!(message.contains("hermes.state_dir"), "key named: {message}");
    assert!(message.contains("/var/lib/odin"), "root named: {message}");

    let mut config = fixture_config();
    config.paths.authority_token_root = PathBuf::from("/run/odin/authority/tokens");
    let error = config
        .validate()
        .expect_err("a sibling-root token root must refuse");
    assert!(matches!(
        &error,
        ConfigError::StatePathOutsideStateRoot { key, .. } if key == "paths.authority_token_root"
    ));

    let mut config = fixture_config();
    if let Some(browser) = config.executables.browser.as_mut() {
        browser.profile_root = PathBuf::from("/var/lib/odin-browser/profiles");
    }
    let error = config
        .validate()
        .expect_err("a sibling-root browser profile must refuse");
    assert!(matches!(
        &error,
        ConfigError::StatePathOutsideStateRoot { key, .. }
            if key == "executables.browser.profile_root"
    ));
}

#[test]
fn absent_parent_and_dangling_symlink_escapes_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let state_root = root.path().join("state");
    fs::create_dir_all(&state_root).unwrap();
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside).unwrap();

    // The exploit shape: an absent in-root segment, a `..` that lexically
    // normalizes back onto the root, and an existing symlink to outside
    // sitting behind it. The parent ban refuses the declared shape before
    // resolution, so no lexical normalization can hide the link.
    std::os::unix::fs::symlink(&outside, state_root.join("escape-link")).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(
        state_root.join("new/../escape-link/child"),
    ));
    match config.validate() {
        Err(ConfigError::Invalid(message)) => {
            assert!(message.contains("hermes.state_dir"), "key named: {message}");
            assert!(message.contains(".."), "parent ban named: {message}");
        }
        other => panic!("parent-ban refusal expected, got {other:?}"),
    }

    // A dangling symlink pointing outside resolves to where it WOULD land:
    // outside the root, refused — even though nothing along the walk exists.
    std::os::unix::fs::symlink(outside.join("deep/target"), state_root.join("dangle-out")).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(
        state_root.join("dangle-out/conversations"),
    ));
    assert!(matches!(
        config.validate(),
        Err(ConfigError::StatePathOutsideStateRoot { key, .. }) if key == "hermes.state_dir"
    ));

    // A dangling symlink to nowhere at all fails the same way.
    std::os::unix::fs::symlink("/nowhere/at/all", state_root.join("dangle-void")).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.paths.authority_token_root = state_root.join("dangle-void/tokens");
    assert!(matches!(
        config.validate(),
        Err(ConfigError::StatePathOutsideStateRoot { key, .. })
            if key == "paths.authority_token_root"
    ));

    // Dangling links are allowed when their resolved target stays inside the root.
    std::os::unix::fs::symlink(
        state_root.join("authority/tokens"),
        state_root.join("dangle-in"),
    )
    .unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.paths.authority_token_root = state_root.join("dangle-in");
    config
        .validate()
        .expect("a dangling in-root target resolves inside");
    assert!(!state_root.join("authority").exists());

    // A link cycle cannot walk forever: expansion shares one hop counter,
    // so the 40-hop bound is refused by name no matter how the chain nests.
    std::os::unix::fs::symlink("loop-b", state_root.join("loop-a")).unwrap();
    std::os::unix::fs::symlink("loop-a", state_root.join("loop-b")).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(state_root.join("loop-a/child")));
    match config.validate() {
        Err(ConfigError::Invalid(message)) => {
            assert!(message.contains("hermes.state_dir"), "key named: {message}");
            assert!(message.contains("cycle"), "cycle bound named: {message}");
        }
        other => panic!("cycle-bound refusal expected, got {other:?}"),
    }
}

#[test]
fn manifest_bound_configuration_rejects_valid_but_replaced_bytes() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("odind.toml");
    let mut config = fixture_config();
    let text = config.to_toml().unwrap();
    fs::write(&path, &text).unwrap();
    let mut manifest = RuntimeManifest {
        schema: RUNTIME_MANIFEST_SCHEMA.to_owned(),
        executables: BTreeMap::new(),
        odind_config: PathDigestRef {
            path: path.clone(),
            digest: odin_domain::Digest::hash(text.as_bytes()).to_string(),
        },
    };
    assert_eq!(manifest.load_config().unwrap(), config);
    config.identity.node = "another-node".to_owned();
    let replacement = config.to_toml().unwrap();
    fs::write(&path, &replacement).unwrap();
    assert!(matches!(
        manifest.load_config(),
        Err(ConfigError::Invalid(_))
    ));
    manifest.odind_config.digest = odin_domain::Digest::hash(replacement.as_bytes()).to_string();
    assert_eq!(manifest.load_config().unwrap(), config);
}

/// Both loaders adopt registry additions while preserving rendered lane bindings.
#[test]
fn manifest_bound_load_adopts_the_published_registry_like_the_direct_load() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let projects = root.join("projects");
    let snapshot = root.join("state/registry/snapshot.json");
    publish_adoption_registry(root, &projects, &snapshot);

    let path = root.join("odind.toml");
    let text = adoption_config_text(root, &projects, &snapshot);
    fs::write(&path, &text).unwrap();
    let manifest = RuntimeManifest {
        schema: RUNTIME_MANIFEST_SCHEMA.to_owned(),
        executables: BTreeMap::new(),
        odind_config: PathDigestRef {
            path: path.clone(),
            digest: odin_domain::Digest::hash(text.as_bytes()).to_string(),
        },
    };

    let direct = OdindConfig::load(&path).expect("the direct load accepts the document");
    let bound = manifest
        .load_config()
        .expect("the manifest-bound load accepts the same bytes");

    let expected: AdmittedIdentity = (
        BTreeMap::from([
            ("odin".to_owned(), (projects.join("odin"), false)),
            ("rig".to_owned(), (projects.join("rig"), true)),
        ]),
        vec![
            (
                "gungnir".to_owned(),
                "odin".to_owned(),
                "gungnir-odin".to_owned(),
                false,
            ),
            (
                "gungnir".to_owned(),
                "rig".to_owned(),
                "gungnir-rig".to_owned(),
                true,
            ),
        ],
        vec![("gungnir".to_owned(), false)],
    );
    assert_eq!(admitted_identity(&direct), expected, "direct load");
    assert_eq!(
        admitted_identity(&bound),
        admitted_identity(&direct),
        "the manifest-bound load must admit the direct load's projects, lanes, and seats"
    );
}

/// Projects by id (root, adopted), lane bindings in order (seat, project,
/// lane, adopted), and seats (id, adopted): what a composition consumes.
type AdmittedIdentity = (
    BTreeMap<String, (PathBuf, bool)>,
    Vec<(String, String, String, bool)>,
    Vec<(String, bool)>,
);

fn admitted_identity(config: &OdindConfig) -> AdmittedIdentity {
    let mut lanes: Vec<_> = config
        .lane_bindings
        .iter()
        .map(|binding| {
            (
                binding.seat.as_str().to_owned(),
                binding.project.as_str().to_owned(),
                binding.lane.as_str().to_owned(),
                binding.runtime,
            )
        })
        .collect();
    lanes.sort();
    let mut seats: Vec<_> = config
        .seats
        .iter()
        .map(|binding| (binding.seat.as_str().to_owned(), binding.runtime))
        .collect();
    seats.sort();
    (
        config
            .projects
            .iter()
            .map(|(id, project)| (id.clone(), (project.root.clone(), project.runtime)))
            .collect(),
        lanes,
        seats,
    )
}

/// Commits and publishes, through the committed publisher, a registry where
/// the configured seat `gungnir` scopes the rendered project `odin` and the
/// runtime-created project `rig` (rooted in the projects directory), with
/// one enabled lane for `rig` and two for `odin`.
fn publish_adoption_registry(root: &Path, projects: &Path, snapshot: &Path) {
    let worktree = root.join("authoring");
    fs::create_dir_all(&worktree).unwrap();
    fs::create_dir_all(projects.join("odin")).unwrap();
    fs::create_dir_all(projects.join("rig")).unwrap();
    fixture_git(&worktree, &["-c", "init.defaultBranch=main", "init", "-q"]);
    for kind in odin_registry::RegistryKind::ALL {
        let directory = worktree.join("registry").join(kind.directory());
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(".gitkeep"), b"").unwrap();
    }
    fs::create_dir_all(worktree.join("schemas")).unwrap();
    fs::write(worktree.join("schemas/.gitkeep"), b"").unwrap();
    let write = |kind: &str, id: &str, file: &str, body: String| {
        let directory = worktree.join("registry").join(kind).join(id);
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join(file), body).unwrap();
    };
    write(
        "context-profiles",
        "fixture",
        "context-profile.toml",
        r#"schema = "odin.registry.v1"
kind = "context-profile"
enabled = true
description = "Fixture context profile."
core_tokens = 2048
inject_tokens = 512
inject_k = 8
"#
        .to_owned(),
    );
    write(
        "nodes",
        "laptop",
        "node.toml",
        r#"schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "adoption fixture authority"
host = "laptop-host"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true
"#
        .to_owned(),
    );
    write(
        "hosts",
        "laptop-host",
        "host.toml",
        r#"schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "adoption fixture host"
hardware = "fixture"
role = "control"
tailscale = "laptop-host"
enrolled = true
"#
        .to_owned(),
    );
    write(
        "providers",
        "gateway",
        "provider.toml",
        r#"schema = "odin.registry.v1"
kind = "provider"
enabled = true
description = "adoption fixture provider"
adapter = "litellm-gateway"
policy = { routes = [] }
budget = { usd_micros = 1000000, window = { duration_seconds = 86400 } }
recovery = { allowed_rungs = ["retry", "restart_worker", "checkpoint", "rehome", "escalate"], blocked_missing_decision = "operator decision required", max_attempts = { retry = 2, restart_worker = 1, checkpoint = 1, rehome = 1, escalate = 1 }, cooldown_seconds = { retry = 30, restart_worker = 30, checkpoint = 60, rehome = 60, escalate = 0 } }
"#
        .to_owned(),
    );
    write(
        "seats",
        "gungnir",
        "seat.toml",
        "schema = \"odin.registry.v1\"\n\
         kind = \"seat\"\n\
         enabled = true\n\
         description = \"adoption fixture seat\"\n\
         categories = []\n\
         tool_refs = []\n\
         project_scope = [\"odin\", \"rig\"]\n\
         brain_scope = []\n\
         limits = { max_parallel_runs = 2, max_sessions = 2, budget = { usd_micros = 1000000, window = { duration_seconds = 2592000 } } }\n\
         knowledge = { atlas_sources = [], required_tags = [], denied_tags = [], top_k = 16 }\n\
         context = { max_bundle_tokens = 24576, profile = \"fixture\" }\n\
         tools = { deny = [], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [] } }\n"
            .to_owned(),
    );
    let project = |source_root: &str| {
        format!(
            "schema = \"odin.registry.v1\"\n\
             kind = \"project\"\n\
             enabled = true\n\
             description = \"adoption fixture project\"\n\
             source_root = \"{source_root}\"\n\
             default_seat = \"gungnir\"\n\
             memory_namespaces = []\n"
        )
    };
    write("projects", "odin", "project.toml", project(""));
    write(
        "projects",
        "rig",
        "project.toml",
        project(&projects.join("rig").display().to_string()),
    );
    let lane = |project: &str| {
        format!(
            "schema = \"odin.registry.v1\"\n\
             kind = \"lane\"\n\
             enabled = true\n\
             description = \"adoption fixture lane for {project}\"\n\
             project = \"{project}\"\n\
             default_seat = \"gungnir\"\n\
             requires_independent_review = false\n"
        )
    };
    write("lanes", "gungnir-odin", "lane.toml", lane("odin"));
    write("lanes", "gungnir-odin-review", "lane.toml", lane("odin"));
    write("lanes", "gungnir-rig", "lane.toml", lane("rig"));
    fixture_git(&worktree, &["add", "-A"]);
    fixture_git(
        &worktree,
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "adoption fixture registry",
        ],
    );
    let commit = fixture_git(&worktree, &["rev-parse", "HEAD"]);
    let candidate =
        odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(&worktree, &commit, [])
            .expect("committed adoption candidate");
    odin_registry::SnapshotStore::new(snapshot)
        .publish_committed(&candidate, 1)
        .expect("publish the adoption registry");
}

fn fixture_git(worktree: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim_end()
        .to_owned()
}

/// A rendered document declaring the authoring repository (so the projects
/// directory is its parent), the seat `gungnir`, the project `odin`, and
/// one explicit `(gungnir, odin)` lane binding — and nothing about `rig`.
fn adoption_config_text(root: &Path, projects: &Path, snapshot: &Path) -> String {
    format!(
        "schema = 'odin.odind-config.v1'\n\
         revision = 1\n\
         worker_bus = 'unix:path={root}/worker-bus.sock'\n\
         [identity]\nnode = 'laptop'\n\
         [paths]\n\
         registry_root = '{root}/registry'\n\
         state_root = '{root}/state'\n\
         registry_snapshot = '{snapshot}'\n\
         authority_token_root = '{root}/state/authority/tokens'\n\
         authority_verification_key_file = '{root}/authority/verification.key'\n\
         authoring_repository = '{projects}/odin'\n\
         authoring_worktree = '{root}/state/authoring/odin'\n\
         [listener]\naddress = '127.0.0.1:18421'\n\
         [executables]\nomp_bin = '{root}/omp'\nomp_revision = '{omp}'\nextension = '{root}/index.ts'\nzellij_bin = '{root}/zellij'\nzellij_hub = 'hub.test'\n\
         [catalogs.gateway_projection]\npath = '{root}/projection.json'\ndigest = 'blake3:{projection}'\n\
         [publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'file.out'\nrender_lane = 'render.out'\n\
         [projects.odin]\nroot = '{projects}/odin'\n\
         [[lane_bindings]]\nseat = 'gungnir'\nproject = 'odin'\nlane = 'gungnir-odin'\n\
         [[seats]]\nseat = 'gungnir'\nslice = 'gungnir-build'\ndisplay_name = 'Gungnir'\nmax_sessions = 2\nlaunch_options = [{{ provider = 'gateway', model = 'glm-flash', skeletonRef = 'gungnir-native', containerId = 'gungnir-native' }}]\nallowed_nodes = ['laptop']\n\
         [capacity]\n",
        root = root.display(),
        projects = projects.display(),
        snapshot = snapshot.display(),
        omp = "a".repeat(40),
        projection = "c".repeat(64)
    )
}

#[test]
fn strict_config_rejects_unknown_keys_and_wrong_schema() {
    let text = fixture_config().to_toml().expect("serializes");
    let polluted = format!("{text}\nextra_key = true\n");
    assert!(OdindConfig::parse(&polluted).is_err());
    let wrong_schema = text.replace("odin.odind-config.v1", "odin.odind-config.v2");
    let parsed = OdindConfig::parse(&wrong_schema).expect("parses structurally");
    assert!(matches!(parsed.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn strict_config_validate_enforces_listener_and_revision() {
    let listen = |ip: IpAddr| {
        let mut config = fixture_config();
        config.listener.address = SocketAddr::new(ip, 8420);
        config.validate()
    };
    for accepted in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254)),
        "::1".parse().unwrap(),
        "fd7a:115c:a1e0::7".parse().unwrap(),
    ] {
        listen(accepted).unwrap_or_else(|error| panic!("{accepted}: {error}"));
    }
    for refused in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)),
        IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
        "::".parse().unwrap(),
        "fe80::1".parse().unwrap(),
    ] {
        assert!(
            matches!(
                listen(refused),
                Err(ConfigError::UnsupportedListenAddress { .. })
            ),
            "{refused}"
        );
    }
    let mut config = fixture_config();
    config.listener.address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::EphemeralListenPort { .. })
    ));
    let mut config = fixture_config();
    config.revision = 0;
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

fn fixture_adapter_backend() -> OdindAdapterBackend {
    OdindAdapterBackend {
        argv: vec!["--adapter".to_owned(), "mcp-time".to_owned()],
    }
}

/// Every optional section the daemon accepts, populated: the fixture whose JSON the schema checks
/// and whose TOML must read back unchanged.
fn populated_config() -> OdindConfig {
    let mut config = fixture_config();
    config.adapter_backends = BTreeMap::from([("mcp-time".to_owned(), fixture_adapter_backend())]);
    config.research = Some(OdindResearchConfig {
        exit_socket: PathBuf::from("/run/odin-research/exit.sock"),
        state: PathBuf::from("/var/lib/odin/research"),
        adapters: vec!["mcp-time".to_owned()],
        pool: Vec::new(),
    });
    config.hermes = Some(OdindHermesConfig {
        consult: None,
        state_dir: PathBuf::from("/var/lib/odin/hermes"),
        discord: Some(OdindHermesDiscordConfig {
            seat: "coordinator".to_owned(),
            project: "research".to_owned(),
            owner_user_id: "owner".to_owned(),
            owner_name: "the owner".to_owned(),
            notify_channel_id: "paired-channel".to_owned(),
            capability: "discord.intake".to_owned(),
            egress_capacity: 8,
            gateway_intents: 1,
            bot_token_handle: "cred:discord.bot".to_owned(),
            scrub_tokens: BTreeSet::new(),
            ttl_seconds: 300,
        }),
        vault: None,
        finance: None,
        accounts: vec![
            OdindHermesAccountConfig {
                account: "sinmara".to_owned(),
                secret_handle: "cred:sinmara-email".to_owned(),
                secret_path: PathBuf::from("/var/lib/odin/secrets/sinmara-email"),
                provider: OdindHermesProviderConfig::Jmap {
                    session_url: "https://jmap.example.invalid/session".to_owned(),
                    identity_id: "identity-1".to_owned(),
                    from_address: "sinmara@example.invalid".to_owned(),
                    drafts_mailbox_id: "drafts".to_owned(),
                    archive_mailbox_id: "archive".to_owned(),
                    trash_mailbox_id: "trash".to_owned(),
                    calendar_id: Some("calendar-1".to_owned()),
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
                reconnect: None,
            },
            OdindHermesAccountConfig {
                account: "work".to_owned(),
                secret_handle: "cred:work-google".to_owned(),
                secret_path: PathBuf::from("/var/lib/odin/secrets/work-google"),
                provider: OdindHermesProviderConfig::Google {
                    token_url: "https://oauth2.example.invalid/token".to_owned(),
                    gmail_api_url: "https://gmail.example.invalid/".to_owned(),
                    calendar_api_url: "https://calendar.example.invalid/".to_owned(),
                    calendar_id: "work-calendar".to_owned(),
                    drive_api_url: None,
                    drive_upload_url: None,
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
                reconnect: None,
            },
            OdindHermesAccountConfig {
                account: "personal".to_owned(),
                secret_handle: "cred:personal-mail".to_owned(),
                secret_path: PathBuf::from("/var/lib/odin/secrets/personal-mail"),
                provider: OdindHermesProviderConfig::Generic {
                    from_address: "personal@example.invalid".to_owned(),
                    imap_host: "imap.example.invalid".to_owned(),
                    imap_port: 993,
                    imap_tls: OdindHermesMailTls::ImplicitTls,
                    smtp_host: "smtp.example.invalid".to_owned(),
                    smtp_port: 587,
                    smtp_tls: OdindHermesMailTls::StartTls,
                    helo_name: "odin.example.invalid".to_owned(),
                    inbox_mailbox_id: "inbox".to_owned(),
                    drafts_mailbox_id: "drafts".to_owned(),
                    archive_mailbox_id: "archive".to_owned(),
                    trash_mailbox_id: "trash".to_owned(),
                    caldav_base_url: Some("https://caldav.example.invalid/".to_owned()),
                    caldav_calendar_url: Some(
                        "https://caldav.example.invalid/personal/".to_owned(),
                    ),
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
                reconnect: None,
            },
        ],
        model_gateway: None,
        brain_raw_root: None,
    });
    config.file_roots = vec![odin_domain::huginn::FileRoot {
        root_id: odin_domain::huginn::FileRootId::parse("atlas-root").expect("root id"),
        display_name: "Atlas".to_owned(),
        canonical_path: PathBuf::from("/srv/atlas"),
        access: odin_domain::huginn::FileRootAccess::ReadWrite,
        media_policy: odin_domain::huginn::FileMediaPolicy {
            allowed_media_types: vec!["application/json".to_owned()],
        },
        max_object_bytes: NonZeroU64::new(1024).expect("nonzero"),
        watch_policy: odin_domain::huginn::FileWatchPolicy::Disabled,
        allowed_seats: vec![odin_domain::SeatId::new("colin").expect("seat id")],
        host: Some("atlas".to_owned()),
        save_default: Some("inbox".to_owned()),
    }];
    config
}

#[test]
fn generated_config_json_matches_odind_config_schema() {
    let config = populated_config();
    let validator = schema_validator();
    let instance = serde_json::to_value(&config).expect("fixture serializes");
    let errors = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "realistic OdindConfig JSON must satisfy odind-config.schema.json: {errors:?}\n{instance}"
    );
    let mut missing_project = instance.clone();
    missing_project["hermes"]["discord"]
        .as_object_mut()
        .expect("Discord object")
        .remove("project");
    assert!(!validator.is_valid(&missing_project));
    assert!(serde_json::from_value::<OdindConfig>(missing_project).is_err());

    let mut unknown_binding = instance.clone();
    unknown_binding["hermes"]["discord"]["default_project"] = serde_json::json!("research");
    assert!(!validator.is_valid(&unknown_binding));
    assert!(serde_json::from_value::<OdindConfig>(unknown_binding).is_err());

    let mut unknown_provider = instance.clone();
    unknown_provider["hermes"]["accounts"][0]["provider"]["kind"] = serde_json::json!("exchange");
    assert!(!validator.is_valid(&unknown_provider));
    assert!(serde_json::from_value::<OdindConfig>(unknown_provider).is_err());

    let mut unknown = instance.clone();
    unknown
        .as_object_mut()
        .expect("object")
        .insert("extra_key".to_owned(), serde_json::Value::Bool(true));
    assert!(
        validator.iter_errors(&unknown).next().is_some(),
        "unknown top-level field must fail the schema"
    );

    let mut empty_connections = instance;
    empty_connections["capacity"]["connections"] = serde_json::json!({});
    assert!(
        validator.iter_errors(&empty_connections).next().is_some(),
        "empty capacity.connections object must fail the schema"
    );
}



#[test]
fn a_seat_listing_a_non_seat_lane_is_refused_by_name() {
    let mut config = fixture_config();
    let seat = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Seat,
        "gungnir",
        "registry/seats/gungnir/seat.toml",
        include_str!("../../../../registry/seats/gungnir/seat.toml"),
    )
    .unwrap();
    let odin_registry::ObjectConfig::Seat(declared) = &seat.config else {
        panic!("gungnir is a seat")
    };
    let lane = declared.models[0].model.as_str().to_owned();
    config.models.lanes.insert(
        lane.clone(),
        OdindModelLaneConfig {
            seats: false,
            strengths: "A lane seats may not run.".to_owned(),
            tier: None,
            display_name: "Grok".to_owned(),
            context_window: 500_000,
            cost: OdindModelCost {
                input: "2".to_owned(),
                output: "6".to_owned(),
            },
            billing: "subscription".to_owned(),
        },
    );
    config.seats.push(OdindSeatBinding {
        seat: "gungnir".parse().unwrap(),
        slice: "gungnir-build".parse().unwrap(),
        display_name: "Gungnir".to_owned(),
        max_sessions: 2,
        launch_options: vec![odin_domain::huginn::LiveLaunchOption {
            provider: "gateway".parse().unwrap(),
            model: lane.parse().unwrap(),
            skeleton_ref: "gungnir-native".to_owned(),
            container_id: "gungnir-native".parse().unwrap(),
            harness: None,
        }],
        allowed_nodes: vec!["laptop".parse().unwrap()],
        runtime: false,
    });
    let error = config
        .adopt_projects_from(Path::new("/nonexistent"), std::slice::from_ref(&seat))
        .expect_err("a non-seat lane is refused");
    let text = error.to_string();
    assert!(
        text.contains(&format!("gateway/{lane}")),
        "the refusal names the lane: {text}"
    );
}

#[test]
fn the_agent_lane_must_be_a_declared_model_lane() {
    let mut config = fixture_config();
    config.models.lanes.insert(
        "zai-glm".to_owned(),
        OdindModelLaneConfig {
            seats: true,
            strengths: "Agent work.".to_owned(),
            tier: None,
            display_name: "GLM".to_owned(),
            context_window: 200_000,
            cost: OdindModelCost {
                input: "1".to_owned(),
                output: "2".to_owned(),
            },
            billing: "api".to_owned(),
        },
    );
    let error = config.check_agent_lane("ghost").unwrap_err().to_string();
    assert!(
        error.contains("\"ghost\" is not a declared model lane"),
        "{error}"
    );
    let error = config.check_agent_lane("zai-glm").unwrap_err().to_string();
    assert!(error.contains("not a gateway launch option"), "{error}");
}

#[test]
fn a_registry_snapshot_that_cannot_be_verified_is_named_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = fixture_config();
    config.paths.authoring_repository = Some(dir.path().join("odin"));
    config.paths.authoring_worktree = Some(dir.path().join("odin-worktree"));
    config.paths.registry_snapshot = dir.path().join("snapshot.json");
    let text = config.to_toml().unwrap();

    OdindConfig::parse_loaded(&text).expect("no published snapshot yet adds nothing");
    fs::write(&config.paths.registry_snapshot, "not a snapshot").unwrap();
    let error = OdindConfig::parse_loaded(&text).unwrap_err().to_string();
    assert!(error.contains("snapshot.json"), "{error}");
}

#[test]
fn a_staged_load_moves_declared_state_under_scratch_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (live, scratch) = (dir.path().join("live"), dir.path().join("scratch"));
    fs::create_dir_all(&scratch).unwrap();
    let mut config = fixture_config();
    config.paths.state_root = live.clone();
    config.paths.authority_token_root = live.join("authority/tokens");
    config.executables.browser.as_mut().unwrap().profile_root = live.join("browser");
    let config_path = dir.path().join("odind.toml");
    fs::write(&config_path, config.to_toml().unwrap()).unwrap();
    let staged_snapshot = dir.path().join("staged-snapshot.json");

    let staged = OdindConfig::load_staged(&config_path, &staged_snapshot, &scratch).unwrap();
    assert_eq!(staged.paths.state_root, scratch);
    assert_eq!(
        staged.paths.authority_token_root,
        scratch.join("authority/tokens")
    );
    assert_eq!(
        staged.executables.browser.unwrap().profile_root,
        scratch.join("browser")
    );
    assert_eq!(staged.paths.registry_snapshot, staged_snapshot);
    assert!(!live.exists(), "the live state root is never touched");
    assert_eq!(fs::read_dir(&scratch).unwrap().count(), 0);
}
