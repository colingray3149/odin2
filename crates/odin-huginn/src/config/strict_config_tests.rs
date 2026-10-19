use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::num::{NonZeroU32, NonZeroU64};
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
            zellij_session: "odin".to_owned(),
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
            }),
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
        gateway_host_credentials: BTreeMap::new(),
        brain: None,
        hermes: None,
        alerts: None,
    }
}

fn fixture_hermes_config(state_dir: PathBuf) -> OdindHermesConfig {
    OdindHermesConfig {
        state_dir,
        discord: Some(OdindHermesDiscordConfig {
            seat: "coordinator".to_owned(),
            project: "research".to_owned(),
            owner_user_id: "owner".to_owned(),
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
        review_gateway: None,
        immich: None,
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
fn declared_state_traversal_and_symlink_escapes_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let state_root = root.path().join("state");
    fs::create_dir_all(&state_root).unwrap();

    // Parent traversal is refused by name outright: `..` interacts with
    // symlinked earlier segments in ways lexical normalization cannot see.
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(state_root.join("../outside/hermes")));
    match config.validate() {
        Err(ConfigError::Invalid(message)) => {
            assert!(message.contains("hermes.state_dir"), "key named: {message}");
            assert!(message.contains(".."), "parent ban named: {message}");
        }
        other => panic!("parent-ban refusal expected, got {other:?}"),
    }

    // A symlink inside the root that resolves outside is refused through
    // the kernel-resolved prefix, not a text comparison.
    let outside = root.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, state_root.join("escape-link")).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(
        state_root.join("escape-link/conversations"),
    ));
    assert!(matches!(
        config.validate(),
        Err(ConfigError::StatePathOutsideStateRoot { .. })
    ));
}

#[test]
fn absent_in_root_state_leaves_validate_without_writing() {
    let root = tempfile::tempdir().unwrap();
    let state_root = root.path().join("state");
    fs::create_dir_all(&state_root).unwrap();
    let mut config = fixture_config();
    confine_fixture_state(&mut config, &state_root);
    config.hermes = Some(fixture_hermes_config(state_root.join("hermes")));
    config
        .validate()
        .expect("a not-yet-existing in-root leaf validates");
    assert!(!state_root.join("hermes").exists());
    assert!(!state_root.join("authority").exists());
    assert!(!state_root.join("browser").exists());
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
fn config_load_refuses_sibling_state_before_any_consumer_runs() {
    let root = tempfile::tempdir().unwrap();
    let mut config = fixture_config();
    config.hermes = Some(fixture_hermes_config(PathBuf::from("/var/lib/odin-hermes")));
    let path = root.path().join("odind.toml");
    fs::write(&path, config.to_toml().unwrap()).unwrap();
    let error = OdindConfig::load(&path)
        .expect_err("load must refuse a sibling-root state path before any consumer runs");
    assert!(matches!(
        error,
        ConfigError::StatePathOutsideStateRoot { .. }
    ));
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
            ("surtr".to_owned(), (projects.join("surtr"), true)),
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
                "surtr".to_owned(),
                "gungnir-surtr".to_owned(),
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
/// runtime-created project `surtr` (rooted in the projects directory), with
/// one enabled lane for `surtr` and two for `odin`.
fn publish_adoption_registry(root: &Path, projects: &Path, snapshot: &Path) {
    let worktree = root.join("authoring");
    fs::create_dir_all(&worktree).unwrap();
    fs::create_dir_all(projects.join("odin")).unwrap();
    fs::create_dir_all(projects.join("surtr")).unwrap();
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
policy = { routes = [{ gateway_lane_id = "glm-flash", gateway_model_id = "openai/glm-5.3-flash" }] }
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
         project_scope = [\"odin\", \"surtr\"]\n\
         approval_defaults = { r0 = \"auto\", r1 = \"auto\", r2 = \"auto\", r3 = \"approval\" }\n\
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
             memory_namespaces = []\n\
             artifact_policy = \"standard\"\n"
        )
    };
    write("projects", "odin", "project.toml", project(""));
    write(
        "projects",
        "surtr",
        "project.toml",
        project(&projects.join("surtr").display().to_string()),
    );
    let lane = |project: &str| {
        format!(
            "schema = \"odin.registry.v1\"\n\
             kind = \"lane\"\n\
             enabled = true\n\
             description = \"adoption fixture lane for {project}\"\n\
             project = \"{project}\"\n\
             family = \"engine\"\n\
             default_seat = \"gungnir\"\n\
             queue = \"interactive\"\n\
             requires_independent_review = false\n"
        )
    };
    write("lanes", "gungnir-odin", "lane.toml", lane("odin"));
    write("lanes", "gungnir-odin-review", "lane.toml", lane("odin"));
    write("lanes", "gungnir-surtr", "lane.toml", lane("surtr"));
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
/// one explicit `(gungnir, odin)` lane binding — and nothing about `surtr`.
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
         [executables]\nomp_bin = '{root}/omp'\nomp_revision = '{omp}'\nextension = '{root}/index.ts'\nzellij_bin = '{root}/zellij'\nzellij_session = 'odin'\n\
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
fn runtime_manifest_requires_the_claude_host_ssh_binding() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("odind.toml");
    let text = fixture_config().to_toml().unwrap();
    fs::write(&path, &text).unwrap();
    let binding = |key: &str| {
        (
            key.to_owned(),
            PathDigestRef {
                path: PathBuf::from("/nix/store/odin-fixture").join(key),
                digest: format!("blake3:{}", "a".repeat(64)),
            },
        )
    };
    let mut manifest = RuntimeManifest {
        schema: RUNTIME_MANIFEST_SCHEMA.to_owned(),
        executables: REQUIRED_RUNTIME_MANIFEST_KEYS
            .iter()
            .filter(|key| **key != "ssh")
            .map(|key| binding(key))
            .collect(),
        odind_config: PathDigestRef {
            path: path.clone(),
            digest: odin_domain::Digest::hash(text.as_bytes()).to_string(),
        },
    };
    match manifest.validate() {
        Err(ConfigError::Invalid(message)) => {
            assert!(message.contains("\"ssh\""), "missing key named: {message}");
        }
        other => panic!("a manifest without the ssh binding must fail closed, got {other:?}"),
    }
    let (ssh_key, ssh_entry) = binding("ssh");
    manifest.executables.insert(ssh_key, ssh_entry);
    manifest
        .validate()
        .expect("a manifest binding every required executable validates");
}

#[test]
fn strict_config_roundtrip_preserves_every_field() {
    let config = fixture_config();
    let text = config.to_toml().expect("serializes");
    let parsed = OdindConfig::parse(&text).expect("reparses");
    assert_eq!(parsed, config);
    parsed.validate().expect("validates");
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
fn strict_config_rejects_missing_required_fields() {
    let text = fixture_config().to_toml().expect("serializes");
    let missing = text
        .lines()
        .filter(|line| !line.contains("registry_snapshot"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(OdindConfig::parse(&missing).is_err());
}

#[test]
fn gateway_host_credentials_keep_opaque_handles_and_validate_environment_names() {
    let mut config = fixture_config();
    config.gateway_host_credentials.insert(
        "gateway/key".to_owned(),
        OdindGatewayHostCredential::new("FIXTURE_EMBEDDING_KEY").expect("valid environment name"),
    );
    let parsed = OdindConfig::parse(&config.to_toml().expect("serializes"))
        .expect("a valid custody entry round-trips");
    assert_eq!(
        parsed
            .gateway_host_credentials
            .get("gateway/key")
            .map(OdindGatewayHostCredential::environment),
        Some("FIXTURE_EMBEDDING_KEY"),
        "an opaque, nonblank handle such as `gateway/key` is a lawful custody key"
    );
    let bad = config
        .to_toml()
        .expect("serializes")
        .replace("FIXTURE_EMBEDDING_KEY", "9INVALID-NAME");
    assert!(
        OdindConfig::parse(&bad).is_err(),
        "an invalid environment variable name must refuse at parse"
    );
}

#[test]
fn strict_config_validate_enforces_listener_and_revision() {
    let mut config = fixture_config();
    config.listener.address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 7)), 8420);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::UnsupportedListenAddress { .. })
    ));
    config.listener.address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::EphemeralListenPort { .. })
    ));
    let mut config = fixture_config();
    config.revision = 0;
    assert!(matches!(config.validate(), Err(ConfigError::Invalid(_))));
}

#[test]
fn strict_config_fixture_derivation_substitutes_only_allowed_roots() {
    let config = fixture_config();
    let overrides = OdindFixtureOverrides {
        state_root: Some(PathBuf::from("/tmp/tx/state")),
        registry_root: Some(PathBuf::from("/tmp/tx/registry")),
        registry_snapshot: Some(PathBuf::from("/tmp/tx/registry/snapshot.json")),
        authority_token_root: Some(PathBuf::from("/tmp/tx/state/authority/tokens")),
        browser_profile_root: Some(PathBuf::from("/tmp/tx/state/browser/profiles")),
        listener_address: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19120)),
        project_roots: BTreeMap::from([("atlas".to_owned(), PathBuf::from("/tmp/tx/atlas"))]),
        gateway_projection: Some(PathDigestRef {
            path: PathBuf::from("/nix/store/fixture/projection.json"),
            digest: format!("blake3:{}", "b".repeat(64)),
        }),
        display: Some(OdindFixtureDisplay::Existing {
            display: ":7".to_owned(),
        }),
        ..Default::default()
    };
    let derived = config.derive_fixture(&overrides).expect("derives");
    assert_eq!(
        &derived.paths.state_root,
        overrides.state_root.as_ref().expect("state")
    );
    assert_eq!(
        derived.listener.address,
        overrides.listener_address.expect("listener")
    );
    assert_eq!(
        &derived.catalogs.gateway_projection,
        overrides.gateway_projection.as_ref().expect("gateway")
    );
    assert_eq!(
        derived.projects["atlas"].root,
        PathBuf::from("/tmp/tx/atlas")
    );
    assert_eq!(derived.executables.omp_bin, config.executables.omp_bin);
    assert_eq!(derived.executables.extension, config.executables.extension);
    assert_eq!(derived.capacity, config.capacity);
    assert_eq!(derived.seats, config.seats);
    match &derived
        .executables
        .browser
        .as_ref()
        .expect("browser")
        .display
    {
        OdindDisplayConfig {
            source: BrowserDisplaySource::Existing,
            display: Some(name),
            xvfb_binary: None,
        } => assert_eq!(name, ":7"),
        other => panic!("unexpected derived display {other:?}"),
    }
    let text = derived.to_toml().expect("derived serializes");
    assert!(!text.contains("xauthority"));
    // Non-loopback listener substitutions fail closed.
    let mut tailnet = overrides.clone();
    tailnet.listener_address = Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
        19120,
    ));
    assert!(config.derive_fixture(&tailnet).is_err());
    // Overrides may not introduce undeclared projects.
    let mut unknown = overrides.clone();
    unknown
        .project_roots
        .insert("ghost".to_owned(), PathBuf::from("/tmp/tx/ghost"));
    assert!(config.derive_fixture(&unknown).is_err());
    // An override set without a display preserves the packaged browser
    // configuration exactly except the sanctioned profile-root relocation.
    let mut quiet = overrides.clone();
    quiet.display = None;
    let preserved = config.derive_fixture(&quiet).expect("derives");
    let preserved_browser = preserved.executables.browser.as_ref().expect("browser");
    let packaged_browser = config.executables.browser.as_ref().expect("browser");
    assert_eq!(
        preserved_browser.profile_root,
        PathBuf::from("/tmp/tx/state/browser/profiles")
    );
    assert_eq!(preserved_browser.chromium, packaged_browser.chromium);
    assert_eq!(preserved_browser.policy, packaged_browser.policy);
    assert_eq!(
        preserved_browser.protected_values,
        packaged_browser.protected_values
    );
    assert_eq!(preserved_browser.scanner, packaged_browser.scanner);
    assert_eq!(preserved_browser.stream, packaged_browser.stream);
    assert_eq!(preserved_browser.display, packaged_browser.display);
}

fn fixture_adapter_backend() -> OdindAdapterBackend {
    OdindAdapterBackend {
        argv: vec!["--adapter".to_owned(), "mcp-time".to_owned()],
    }
}

#[test]
fn adapter_backends_validate_canonical_ids_and_argv() {
    let mut config = fixture_config();
    config.adapter_backends =
        BTreeMap::from([("_web-search".to_owned(), fixture_adapter_backend())]);
    let error = config
        .validate()
        .expect_err("leading punctuation must fail the canonical adapter ID grammar");
    assert!(
        error
            .to_string()
            .contains("must start with an ASCII alphanumeric"),
        "unexpected error: {error}"
    );

    config.adapter_backends = BTreeMap::from([(
        "mcp-time".to_owned(),
        OdindAdapterBackend {
            argv: vec![String::new()],
        },
    )]);
    assert!(
        config.validate().is_err(),
        "an empty argv argument is refused"
    );

    config.adapter_backends = BTreeMap::from([("mcp-time".to_owned(), fixture_adapter_backend())]);
    config
        .validate()
        .expect("a canonical adapter key with a static argv validates");
}

#[test]
fn generated_config_json_matches_odind_config_schema() {
    let mut config = fixture_config();
    config.adapter_backends = BTreeMap::from([("mcp-time".to_owned(), fixture_adapter_backend())]);
    config.hermes = Some(OdindHermesConfig {
        state_dir: PathBuf::from("/var/lib/odin/hermes"),
        discord: Some(OdindHermesDiscordConfig {
            seat: "coordinator".to_owned(),
            project: "research".to_owned(),
            owner_user_id: "owner".to_owned(),
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
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
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
            },
        ],
        review_gateway: None,
        immich: None,
        brain_raw_root: None,
    });
    config.file_roots = vec![odin_domain::huginn::FileRoot {
        root_id: odin_domain::huginn::FileRootId::parse("atlas-root").expect("root id"),
        display_name: "Atlas".to_owned(),
        canonical_path: PathBuf::from("/srv/atlas"),
        access: odin_domain::huginn::FileRootAccess::ReadOnly,
        media_policy: odin_domain::huginn::FileMediaPolicy {
            allowed_media_types: vec!["application/json".to_owned()],
        },
        max_object_bytes: NonZeroU64::new(1024).expect("nonzero"),
        watch_policy: odin_domain::huginn::FileWatchPolicy::Disabled,
        allowed_seats: vec![odin_domain::SeatId::new("colin").expect("seat id")],
    }];
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/control/odind-config.schema.json"
    ))
    .expect("odind-config schema parses as JSON");
    let validator = jsonschema::validator_for(&schema).expect("odind-config schema compiles");
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
fn generated_brain_sources_json_matches_odind_config_schema() {
    use odin_domain::knowledge::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    };
    let mut config = fixture_config();
    config.brain = Some(OdindBrainConfig {
        lane_windows: Default::default(),
        serving_model: OdindServingModelConfig {
            name: "openai/glm-5.3".to_owned(),
            context_window_tokens: NonZeroU32::new(131_072).expect("nonzero"),
            tokenizer: Some("odin.tokenizer.qwen3.v1".to_owned()),
        },
        sources: BTreeMap::from([
            (
                "atlas:odin".to_owned(),
                OdindBrainSourceConfig {
                    kind: "atlas".to_owned(),
                    privacy: None,
                    root: Some(PathBuf::from("/srv/atlas/odin")),
                    port: None,
                    expected_space_root: None,
                    general_namespaces: Vec::new(),
                    generated_namespace: None,
                    excluded_namespaces: Vec::new(),
                    max_pages: None,
                    format: None,
                    export_path: None,
                    memory_namespace: None,
                    privacy_class: None,
                    dedupe_key: None,
                    selection: None,
                },
            ),
            (
                "vault:silverbullet".to_owned(),
                OdindBrainSourceConfig {
                    kind: "silverbullet".to_owned(),
                    privacy: None,
                    root: None,
                    port: Some(8080),
                    expected_space_root: None,
                    general_namespaces: vec!["personal".to_owned()],
                    generated_namespace: Some("generated".to_owned()),
                    excluded_namespaces: Vec::new(),
                    max_pages: Some(1_000),
                    format: None,
                    export_path: None,
                    memory_namespace: None,
                    privacy_class: None,
                    dedupe_key: None,
                    selection: None,
                },
            ),
            (
                "archive:gmail".to_owned(),
                OdindBrainSourceConfig {
                    kind: "archive".to_owned(),
                    privacy: None,
                    root: None,
                    port: None,
                    expected_space_root: None,
                    general_namespaces: Vec::new(),
                    generated_namespace: None,
                    excluded_namespaces: Vec::new(),
                    max_pages: None,
                    format: Some(ArchiveFormat::Mbox),
                    export_path: Some(PathBuf::from("/srv/exports/mail.mbox")),
                    memory_namespace: Some("archive.gmail".to_owned()),
                    privacy_class: Some(ArchivePrivacyClass::Private),
                    dedupe_key: Some(ArchiveDedupeKey::ContentDigest),
                    selection: Some(ArchiveSelectionPolicy {
                        since: None,
                        exclude_labels: vec!["Spam".to_owned()],
                        exclude_if_header: vec!["List-Unsubscribe".to_owned()],
                        keep_if_participant: true,
                        participant_emails: vec!["colin@example.com".to_owned()],
                        suspicious_rules: Vec::new(),
                        exclude_do_not_remember: None,
                    }),
                },
            ),
        ]),
        embedding: Some(OdindBrainEmbeddingConfig {
            provider: "gateway".to_owned(),
            endpoint: "http://127.0.0.1:8400".to_owned(),
        }),
        postgres: None,
    });
    config
        .validate()
        .expect("brain fixture validates semantically");
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/control/odind-config.schema.json"
    ))
    .expect("odind-config schema parses as JSON");
    let validator = jsonschema::validator_for(&schema).expect("odind-config schema compiles");
    let instance = serde_json::to_value(&config).expect("fixture serializes");
    let errors = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "brain sources JSON must satisfy odind-config.schema.json: {errors:?}\n{instance}"
    );

    let mut cross_kind = instance.clone();
    cross_kind["brain"]["sources"]["atlas:odin"]["format"] = serde_json::json!("mbox");
    assert!(
        !validator.is_valid(&cross_kind),
        "an atlas source must not carry an archive format"
    );

    let mut missing_selection = instance.clone();
    missing_selection["brain"]["sources"]["archive:gmail"]
        .as_object_mut()
        .expect("archive source object")
        .remove("selection");
    assert!(
        !validator.is_valid(&missing_selection),
        "an archive source requires its declared selection policy"
    );

    let mut bad_kind = instance.clone();
    bad_kind["brain"]["sources"]["archive:gmail"]["kind"] = serde_json::json!("chatgpt-export");
    assert!(
        !validator.is_valid(&bad_kind),
        "unsupported source kinds must fail the schema"
    );

    let mut unknown_tokenizer = instance.clone();
    unknown_tokenizer["brain"]["serving_model"]["tokenizer"] =
        serde_json::json!("other.vendor.model");
    assert!(
        !validator.is_valid(&unknown_tokenizer),
        "an unsupported declared tokenizer identity must fail the schema"
    );

    let mut absent_tokenizer = instance;
    absent_tokenizer["brain"]["serving_model"]
        .as_object_mut()
        .expect("serving model object")
        .remove("tokenizer");
    assert!(
        validator.is_valid(&absent_tokenizer),
        "an absent tokenizer keeps the conservative byte-count default and stays schema-valid"
    );
}

#[test]
fn archive_declaration_validates_through_the_config_pipeline() {
    use odin_domain::knowledge::{
        ArchiveDedupeKey, ArchiveFormat, ArchivePrivacyClass, ArchiveSelectionPolicy,
    };

    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../schemas/control/odind-config.schema.json"
    ))
    .expect("odind-config schema parses as JSON");
    let validator = jsonschema::validator_for(&schema).expect("odind-config schema compiles");

    let chatgpt_source = |selection: ArchiveSelectionPolicy| -> OdindConfig {
        let mut config = fixture_config();
        config.brain = Some(OdindBrainConfig {
            lane_windows: Default::default(),
            serving_model: OdindServingModelConfig {
                name: "openai/glm-5.3".to_owned(),
                context_window_tokens: NonZeroU32::new(131_072).expect("nonzero"),
                tokenizer: None,
            },
            sources: BTreeMap::from([(
                "archive:chatgpt".to_owned(),
                OdindBrainSourceConfig {
                    kind: "archive".to_owned(),
                    privacy: None,
                    root: None,
                    port: None,
                    expected_space_root: None,
                    general_namespaces: Vec::new(),
                    generated_namespace: None,
                    excluded_namespaces: Vec::new(),
                    max_pages: None,
                    format: Some(ArchiveFormat::ChatGptExport),
                    export_path: Some(PathBuf::from("/srv/exports/chatgpt.zip")),
                    memory_namespace: Some("archive.chatgpt".to_owned()),
                    privacy_class: Some(ArchivePrivacyClass::Private),
                    dedupe_key: Some(ArchiveDedupeKey::ContentDigest),
                    selection: Some(selection),
                },
            )]),
            embedding: None,
            postgres: None,
        });
        config
    };

    let bare = ArchiveSelectionPolicy {
        since: None,
        exclude_labels: Vec::new(),
        exclude_if_header: Vec::new(),
        keep_if_participant: false,
        participant_emails: Vec::new(),
        suspicious_rules: Vec::new(),
        exclude_do_not_remember: None,
    };

    // A valid chatgpt-export declaration — carrying the forget-flag knob —
    // satisfies the schema and validates through the real controller route.
    let valid = chatgpt_source(ArchiveSelectionPolicy {
        exclude_do_not_remember: Some(true),
        ..bare.clone()
    });
    let instance = serde_json::to_value(&valid).expect("config serializes");
    assert!(
        validator.is_valid(&instance),
        "a chatgpt-export declaration must satisfy odind-config.schema.json"
    );
    valid
        .validate()
        .expect("a chatgpt-export declaration validates semantically");

    // The knob belongs to the chatgpt-export format: structurally it is
    // just a boolean, but the semantic route refuses it on any other
    // format through the shared declaration validation.
    let mut config = fixture_config();
    config.brain = Some(OdindBrainConfig {
        lane_windows: Default::default(),
        serving_model: OdindServingModelConfig {
            name: "openai/glm-5.3".to_owned(),
            context_window_tokens: NonZeroU32::new(131_072).expect("nonzero"),
            tokenizer: None,
        },
        sources: BTreeMap::from([(
            "archive:gmail".to_owned(),
            OdindBrainSourceConfig {
                kind: "archive".to_owned(),
                privacy: None,
                root: None,
                port: None,
                expected_space_root: None,
                general_namespaces: Vec::new(),
                generated_namespace: None,
                excluded_namespaces: Vec::new(),
                max_pages: None,
                format: Some(ArchiveFormat::Mbox),
                export_path: Some(PathBuf::from("/srv/exports/mail.mbox")),
                memory_namespace: Some("archive.gmail".to_owned()),
                privacy_class: Some(ArchivePrivacyClass::Private),
                dedupe_key: Some(ArchiveDedupeKey::ContentDigest),
                selection: Some(ArchiveSelectionPolicy {
                    since: None,
                    exclude_labels: vec!["Spam".to_owned()],
                    exclude_if_header: vec!["List-Unsubscribe".to_owned()],
                    keep_if_participant: true,
                    participant_emails: vec!["colin@example.com".to_owned()],
                    suspicious_rules: Vec::new(),
                    exclude_do_not_remember: Some(true),
                }),
            },
        )]),
        embedding: None,
        postgres: None,
    });
    let instance = serde_json::to_value(&config).expect("config serializes");
    assert!(
        validator.is_valid(&instance),
        "the knob is structurally a boolean on any archive source"
    );
    let error = config
        .validate()
        .expect_err("the knob applies only to the chatgpt-export format");
    let error = error.to_string();
    assert!(
        error.contains("exclude_do_not_remember"),
        "the semantic refusal names the knob: {error}"
    );

    // An unknown format name fails the schema enum.
    let mut unknown_format =
        serde_json::to_value(chatgpt_source(bare.clone())).expect("config serializes");
    unknown_format["brain"]["sources"]["archive:chatgpt"]["format"] =
        serde_json::json!("not-a-format");
    assert!(
        !validator.is_valid(&unknown_format),
        "an undeclared archive format must fail the schema"
    );

    // The knob is boolean-typed on the wire.
    let mut non_boolean = serde_json::to_value(chatgpt_source(ArchiveSelectionPolicy {
        exclude_do_not_remember: Some(true),
        ..bare
    }))
    .expect("config serializes");
    non_boolean["brain"]["sources"]["archive:chatgpt"]["selection"]["exclude_do_not_remember"] =
        serde_json::json!("true");
    assert!(
        !validator.is_valid(&non_boolean),
        "a non-boolean knob must fail the schema"
    );
    assert!(serde_json::from_value::<OdindConfig>(non_boolean).is_err());
}

#[test]
fn absent_declared_session_and_attach_command_round_trip_as_unbound() {
    let mut config = fixture_config();
    config.executables.zellij_session = String::new();
    config.executables.attach_command = Vec::new();
    config
        .validate()
        .expect("unbound terminal targeting is a valid declaration");
    let text = config.to_toml().expect("serializes");
    assert!(
        !text.contains("zellij_session"),
        "empty declared selector is skipped on the wire"
    );
    assert!(
        !text.contains("attach_command"),
        "absent attach command is skipped on the wire"
    );
    let reparsed = OdindConfig::parse(&text).expect("reparse");
    assert!(reparsed.executables.zellij_session.is_empty());
    assert!(reparsed.executables.attach_command.is_empty());
}

#[test]
fn declared_zellij_session_name_law() {
    let mut config = fixture_config();
    config.executables.zellij_session = "bad\nname".to_owned();
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid(_))),
        "control characters must fail the declared session name law"
    );
    config.executables.zellij_session = "x".repeat(129);
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid(_))),
        "names beyond 128 bytes must fail the declared session name law"
    );
    config.executables.zellij_session = String::new();
    config
        .validate()
        .expect("empty declared selector is the typed unbound state");
}

#[test]
fn attach_command_declaration_law_mirrors_the_compiled_factory() {
    let mut config = fixture_config();
    config.executables.attach_command = vec![
        "/run/current-system/sw/bin/odin".to_owned(),
        "session".to_owned(),
        "--interactive".to_owned(),
        "--attach".to_owned(),
        "{session_id}".to_owned(),
    ];
    config
        .validate()
        .expect("the governed attach template validates");

    config.executables.attach_command[1] = "session-{bogus}".to_owned();
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid(_))),
        "unknown placeholders must fail the attach declaration law"
    );

    config.executables.attach_command = vec!["arg".to_owned(); 65];
    assert!(
        matches!(config.validate(), Err(ConfigError::Invalid(_))),
        "templates beyond 64 arguments must fail the attach declaration law"
    );
}

#[test]
fn serving_model_tokenizer_declares_strictly_and_stays_absent_until_declared() {
    let brain = |tokenizer: Option<&str>| OdindBrainConfig {
        lane_windows: Default::default(),
        serving_model: OdindServingModelConfig {
            name: "openai/glm-5.3".to_owned(),
            context_window_tokens: NonZeroU32::new(131_072).expect("nonzero"),
            tokenizer: tokenizer.map(str::to_owned),
        },
        sources: BTreeMap::new(),
        embedding: None,
        postgres: None,
    };

    let mut config = fixture_config();
    config.brain = Some(brain(Some("odin.tokenizer.qwen3.v1")));
    let text = config.to_toml().expect("declared tokenizer serializes");
    let reparsed = OdindConfig::parse(&text).expect("declared tokenizer parses");
    assert_eq!(
        reparsed
            .brain
            .expect("brain")
            .serving_model
            .tokenizer
            .as_deref(),
        Some("odin.tokenizer.qwen3.v1")
    );

    let mut config = fixture_config();
    config.brain = Some(brain(None));
    let text = config.to_toml().expect("absent tokenizer serializes");
    assert!(
        !text.contains("tokenizer"),
        "an undeclared tokenizer is never serialized"
    );
    let reparsed = OdindConfig::parse(&text).expect("absent tokenizer parses");
    assert_eq!(reparsed.brain.expect("brain").serving_model.tokenizer, None);

    let mutated = text.replacen(
        "[brain.serving_model]",
        "[brain.serving_model]\nextra_key = true",
        1,
    );
    assert!(
        OdindConfig::parse(&mutated).is_err(),
        "unknown serving_model keys stay denied"
    );
}

#[test]
fn hermes_accounts_demand_unique_selectors() {
    let account = |selector: &str| OdindHermesAccountConfig {
        account: selector.to_owned(),
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
    };

    let mut config = fixture_config();
    config.hermes = Some(OdindHermesConfig {
        accounts: vec![
            account("sinmara"),
            OdindHermesAccountConfig {
                provider: OdindHermesProviderConfig::Google {
                    token_url: "https://oauth2.example.invalid/token".to_owned(),
                    gmail_api_url: "https://gmail.example.invalid/".to_owned(),
                    calendar_api_url: "https://calendar.example.invalid/".to_owned(),
                    calendar_id: "work-calendar".to_owned(),
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
                ..account("work")
            },
            OdindHermesAccountConfig {
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
                    caldav_base_url: Some("http://127.0.0.1:8008/".to_owned()),
                    caldav_calendar_url: Some("http://127.0.0.1:8008/personal/".to_owned()),
                    request_timeout_ms: 30_000,
                    max_response_bytes: 1_048_576,
                },
                ..account("personal")
            },
        ],
        ..fixture_hermes_config(PathBuf::from("/var/lib/odin/hermes"))
    });
    config
        .validate()
        .expect("one declaration per provider kind with unique selectors validates");

    if let Some(hermes) = config.hermes.as_mut() {
        hermes.accounts.push(account("sinmara"));
    }
    match config.validate() {
        Err(ConfigError::Invalid(message)) => {
            assert!(
                message.contains("sinmara"),
                "duplicate selector named: {message}"
            );
            assert!(message.contains("unique"), "selector law named: {message}");
        }
        other => panic!("duplicate selector refusal expected, got {other:?}"),
    }
}

#[test]
fn hermes_account_provider_laws_mirror_the_composition() {
    fn configured(account: OdindHermesAccountConfig) -> OdindConfig {
        let mut config = fixture_config();
        let mut hermes = fixture_hermes_config(PathBuf::from("/var/lib/odin/hermes"));
        hermes.accounts = vec![account];
        config.hermes = Some(hermes);
        config
    }

    fn refused(config: OdindConfig, needle: &str) {
        let error = config
            .validate()
            .expect_err("invalid provider deployment must be refused");
        assert!(
            error.to_string().contains(needle),
            "refusal must name {needle:?}: {error}"
        );
    }

    let jmap = OdindHermesProviderConfig::Jmap {
        session_url: "https://jmap.example.invalid/session".to_owned(),
        identity_id: "identity-1".to_owned(),
        from_address: "sinmara@example.invalid".to_owned(),
        drafts_mailbox_id: "drafts".to_owned(),
        archive_mailbox_id: "archive".to_owned(),
        trash_mailbox_id: "trash".to_owned(),
        calendar_id: Some("calendar-1".to_owned()),
        request_timeout_ms: 30_000,
        max_response_bytes: 1_048_576,
    };
    let account = |provider| OdindHermesAccountConfig {
        account: "sinmara".to_owned(),
        secret_handle: "cred:sinmara-email".to_owned(),
        secret_path: PathBuf::from("/var/lib/odin/secrets/sinmara-email"),
        provider,
    };

    configured(account(jmap.clone()))
        .validate()
        .expect("a bounded jmap account validates");

    let mut relative_secret = account(jmap.clone());
    relative_secret.secret_path = PathBuf::from("secrets/sinmara-email");
    refused(configured(relative_secret), "secret_path");

    let mut plaintext_session = account(jmap.clone());
    if let OdindHermesProviderConfig::Jmap { session_url, .. } = &mut plaintext_session.provider {
        *session_url = "http://jmap.example.invalid/session".to_owned();
    }
    refused(configured(plaintext_session), "session_url");

    refused(
        configured(account(OdindHermesProviderConfig::Google {
            token_url: "http://oauth2.example.invalid/token".to_owned(),
            gmail_api_url: "https://gmail.example.invalid/".to_owned(),
            calendar_api_url: "https://calendar.example.invalid/".to_owned(),
            calendar_id: "work-calendar".to_owned(),
            request_timeout_ms: 30_000,
            max_response_bytes: 1_048_576,
        })),
        "token_url",
    );

    let mut unbounded = account(jmap.clone());
    if let OdindHermesProviderConfig::Jmap {
        request_timeout_ms, ..
    } = &mut unbounded.provider
    {
        *request_timeout_ms = 999;
    }
    refused(configured(unbounded), "request_timeout_ms");

    let generic = OdindHermesProviderConfig::Generic {
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
        caldav_calendar_url: Some("https://caldav.example.invalid/personal/".to_owned()),
        request_timeout_ms: 30_000,
        max_response_bytes: 1_048_576,
    };
    configured(account(generic.clone()))
        .validate()
        .expect("a bounded generic account validates");

    // Plain HTTP CalDAV is loopback-only: a bridged local endpoint is the
    // one licensed plaintext deployment.
    let mut remote_http_caldav = account(generic.clone());
    if let OdindHermesProviderConfig::Generic {
        caldav_base_url, ..
    } = &mut remote_http_caldav.provider
    {
        *caldav_base_url = Some("http://caldav.example.invalid/".to_owned());
    }
    refused(configured(remote_http_caldav), "caldav_base_url");

    // The calendar collection URL cannot exist without the base it hangs
    // under.
    let mut orphan_calendar = account(generic);
    if let OdindHermesProviderConfig::Generic {
        caldav_base_url, ..
    } = &mut orphan_calendar.provider
    {
        *caldav_base_url = None;
    }
    refused(configured(orphan_calendar), "caldav_calendar_url");
}

/// Tokenizer-specific windows must not be interpreted as byte counts.
#[test]
fn lane_windows_declare_a_bare_count_or_a_count_with_its_tokenizer() {
    let brain: crate::OdindBrainConfig = toml::from_str(
        r#"
        lane_windows = { glm = 262144, kubert-mini = { context_window_tokens = 32768, tokenizer = "odin.tokenizer.qwen3.v1" } }
        [serving_model]
        name = "zai-glm"
        context_window_tokens = 200000
        "#,
    )
    .expect("both lane window forms parse");
    let glm = &brain.lane_windows["glm"];
    assert_eq!((glm.window().get(), glm.tokenizer()), (262_144, None));
    let kubert = &brain.lane_windows["kubert-mini"];
    assert_eq!(
        (kubert.window().get(), kubert.tokenizer()),
        (32_768, Some("odin.tokenizer.qwen3.v1"))
    );
    assert!(toml::from_str::<crate::OdindBrainConfig>(
        r#"
        lane_windows = { kubert-mini = { window = 32768 } }
        [serving_model]
        name = "zai-glm"
        context_window_tokens = 200000
        "#,
    )
    .is_err());
}

#[test]
fn a_seats_declared_models_become_its_launch_options() {
    let option =
        |provider: &str, model: &str, container: &str| odin_domain::huginn::LiveLaunchOption {
            provider: provider.parse().unwrap(),
            model: model.parse().unwrap(),
            skeleton_ref: container.to_owned(),
            container_id: container.parse().unwrap(),
            harness: None,
        };
    let mut config = fixture_config();
    config.seats.push(OdindSeatBinding {
        seat: "gungnir".parse().unwrap(),
        slice: "gungnir-build".parse().unwrap(),
        display_name: "Gungnir".to_owned(),
        max_sessions: 2,
        launch_options: vec![
            option("gateway", "undeclared", "gungnir-native"),
            option("gateway", "glm-flash", "gungnir-pod"),
        ],
        allowed_nodes: vec!["laptop".parse().unwrap()],
        runtime: false,
    });
    let seat = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Seat,
        "gungnir",
        "registry/seats/gungnir/seat.toml",
        include_str!("../../../../registry/seats/gungnir/seat.toml"),
    )
    .unwrap();
    let odin_registry::ObjectConfig::Seat(declared) = &seat.config else {
        unreachable!("parsed as a seat");
    };
    config.adopt_projects_from(Path::new("/nonexistent"), std::slice::from_ref(&seat));
    let launches = &config.seats.last().unwrap().launch_options;
    let pairs: Vec<String> = launches
        .iter()
        .map(|option| format!("{}/{}", option.provider, option.model))
        .collect();
    let expected: Vec<String> = declared.models.iter().map(ToString::to_string).collect();
    assert_eq!(pairs, expected);
    for option in launches {
        let container = if option.model.as_str() == "glm-flash" {
            "gungnir-pod"
        } else {
            "gungnir-native"
        };
        assert_eq!(option.container_id.as_str(), container);
    }
}
