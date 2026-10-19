use super::{confined_root, with_item_in_array};

#[test]
fn a_declaration_list_gains_one_item_in_place() {
    let seat = "schema = \"odin.registry.v1\"\nproject_scope = [\"skuld\", \"odin\"]\nother = 1\n";
    let edited = with_item_in_array(seat, None, "project_scope", "hekla").unwrap();
    assert!(edited.contains("project_scope = [\"skuld\", \"odin\", \"hekla\"]"));
    assert_eq!(
        with_item_in_array(&edited, None, "project_scope", "hekla").unwrap(),
        edited
    );
    let multiline =
        "tool_refs = [\n  \"a.b\",\n  \"c.d\",\n]\n[tools]\nallow = [\"a_b\"]\ndeny = []\n";
    let edited = with_item_in_array(multiline, None, "tool_refs", "seat.ask.x").unwrap();
    assert!(edited.contains("  \"c.d\", \"seat.ask.x\",\n]"), "{edited}");
    let edited = with_item_in_array(&edited, Some("tools"), "allow", "seat_ask_x").unwrap();
    assert!(
        edited.contains("allow = [\"a_b\", \"seat_ask_x\"]"),
        "{edited}"
    );
    assert!(edited.contains("deny = []"));
    assert!(with_item_in_array(multiline, None, "missing", "x").is_err());
}

/// A project root is confined to the projects directory: a new root only
/// directly inside it, an existing one anywhere inside it, never the
/// directory itself, a parent escape, or a symlink.
#[test]
fn project_roots_are_confined_to_the_projects_directory() {
    let dir = tempfile::tempdir().unwrap();
    let projects = dir.path().canonicalize().unwrap();
    std::fs::create_dir(projects.join("skuld")).unwrap();
    std::os::unix::fs::symlink("/etc", projects.join("sneaky")).unwrap();

    assert_eq!(
        confined_root(&projects, None, "hekla").unwrap(),
        (projects.join("hekla"), true)
    );
    let skuld = projects.join("skuld");
    assert_eq!(
        confined_root(&projects, Some(skuld.to_str().unwrap()), "skuld").unwrap(),
        (skuld, false)
    );
    for refused in [
        projects.to_str().unwrap().to_owned(),
        format!("{}/../etc", projects.display()),
        projects.join("sneaky").display().to_string(),
        "/tmp/elsewhere-new".to_owned(),
        "relative/path".to_owned(),
        projects.join("a/b/new").display().to_string(),
    ] {
        assert!(
            confined_root(&projects, Some(&refused), "x").is_err(),
            "{refused} must be refused"
        );
    }
}

struct RealRegistry {
    _dir: tempfile::TempDir,
    projects: std::path::PathBuf,
    repository: std::path::PathBuf,
    origin: std::path::PathBuf,
    store: std::path::PathBuf,
    route: super::DaemonProjectRoute,
}

/// Publish the repository's registry and skeletons in a scratch repo with a bare origin.
fn real_registry() -> RealRegistry {
    real_registry_with_lender(false)
}

fn real_registry_with_lender(narrow_lender: bool) -> RealRegistry {
    use crate::test_support::{commit_all, git};
    let dir = tempfile::tempdir().unwrap();
    let projects = dir.path().canonicalize().unwrap().join("valhalla");
    let repository = projects.join("odin");
    std::fs::create_dir_all(&repository).unwrap();
    git(
        &repository,
        &["-c", "init.defaultBranch=main", "init", "--quiet"],
    );
    for (key, value) in [
        ("user.name", "Odin Test"),
        ("user.email", "odin-test@example.invalid"),
        ("commit.gpgsign", "false"),
    ] {
        git(&repository, &["config", key, value]);
    }
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for tree in ["registry", "schemas", "skeletons"] {
        let status = std::process::Command::new("cp")
            .args([
                "-r",
                source.join(tree).to_str().unwrap(),
                repository.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
    let mut admission_config = helper_admission_config();
    admission_config.paths.authoring_repository = Some(repository.clone());
    if narrow_lender {
        let mut slice: toml::Table = toml::from_str(
            &std::fs::read_to_string(repository.join("registry/slices/gungnir-build/slice.toml"))
                .unwrap(),
        )
        .unwrap();
        let lender: toml::Table = toml::from_str(
            &std::fs::read_to_string(repository.join("registry/seats/forseti/seat.toml")).unwrap(),
        )
        .unwrap();
        // Keep the actual lender's own policy valid while narrowing what the
        // broader requested template can pass to its helper.
        slice["knowledge"]["atlas_sources"] = lender["knowledge"]["atlas_sources"].clone();
        let slice_root = repository.join("registry/slices/helper-review");
        std::fs::create_dir(&slice_root).unwrap();
        std::fs::write(
            slice_root.join("slice.toml"),
            toml::to_string(&slice).unwrap(),
        )
        .unwrap();
        let worker = admission_config.seats[0].clone();
        let mut lender = worker.clone();
        lender.seat = "forseti".parse().unwrap();
        lender.slice = "helper-review".parse().unwrap();
        lender.display_name = "Forseti".to_owned();
        admission_config.seats.insert(0, lender);
        // The narrowed lender lends to every seat its container offers:
        // the other workers stay configured on the slice they serve.
        for (seat, display) in [("reginn", "Reginn"), ("scribe", "Scribe")] {
            let mut binding = worker.clone();
            binding.seat = seat.parse().unwrap();
            binding.display_name = display.to_owned();
            admission_config.seats.push(binding);
        }
    }
    commit_all(&repository, "real registry");
    let origin = dir.path().join("origin.git");
    git(
        dir.path(),
        &[
            "init",
            "--quiet",
            "--bare",
            "-b",
            "main",
            origin.to_str().unwrap(),
        ],
    );
    git(
        &repository,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );
    git(&repository, &["push", "--quiet", "origin", "main"]);
    let store = dir.path().join("state/registry/snapshot.json");
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &repository,
        &head,
        odin_cli::runtime_bindings::admitted_registry_bindings(),
    )
    .expect("the real registry validates");
    odin_registry::SnapshotStore::new(&store)
        .publish_committed(&candidate, 1)
        .expect("base publication");
    let pin = std::sync::Arc::new(
        odin_registry::SnapshotHandle::open(odin_registry::SnapshotStore::new(&store)).unwrap(),
    );
    let route = super::DaemonProjectRoute {
        pin,
        admission_config,
        caller_slices: [("sinmara".to_owned(), "sinmara-life".to_owned())].into(),
        harness_environments: std::collections::BTreeMap::new(),
        snapshot_store: store.clone(),
        worktree: dir.path().join("odin-authoring/odin"),
        sync: crate::workload_authoring::AuthoringSync {
            repository: repository.clone(),
        },
    };
    RealRegistry {
        _dir: dir,
        projects,
        repository,
        origin,
        store,
        route,
    }
}

fn request(project: &str, seats: &[&str]) -> odin_hermes::runtime::projects::ProjectCreateRequest {
    odin_hermes::runtime::projects::ProjectCreateRequest {
        project: project.to_owned(),
        description: "Surtr, a personal project".to_owned(),
        kind: "code".to_owned(),
        seats: seats.iter().map(|seat| (*seat).to_owned()).collect(),
        root: None,
        repository: None,
    }
}

#[test]
fn the_coordinator_creates_a_project_on_odin_main() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::ProjectRoute;
    let real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let created = real
        .route
        .create(&sinmara, request("hekla", &["gungnir"]))
        .expect("the project is created");
    assert_eq!(created.lanes, vec!["gungnir-hekla".to_owned()]);
    assert_eq!(created.published_revision, 2);
    assert!(
        real.projects.join("hekla/.git").exists(),
        "a new repository"
    );
    // The new repository has a HEAD (state.repos refuses an unborn one).
    git(&real.projects.join("hekla"), &["rev-parse", "HEAD"]);
    let main = git(&real.origin, &["rev-parse", "main"]);
    assert_eq!(created.commit, main, "the declaration is on odin main");
    let scope = git(
        &real.origin,
        &["show", "main:registry/seats/gungnir/seat.toml"],
    );
    assert!(scope.contains("\"hekla\"]"), "{scope}");
    // Claude driver admission must not make new Gungnir projects fail the
    // bindable capability ceiling or lose the new seat's lifecycle tools.
    for capability in ["claude.open", "claude.prompt", "claude.read", "claude.stop"] {
        assert!(scope.contains(&format!("\"{capability}\"")), "{scope}");
    }
    let project = git(
        &real.origin,
        &["show", "main:registry/projects/hekla/project.toml"],
    );
    assert!(project.contains(&format!(
        "source_root = \"{}\"",
        real.projects.join("hekla").display()
    )));
    let active = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .unwrap();
    assert!(active
        .objects
        .iter()
        .any(|object| object.id == "gungnir-hekla"));
    let _ = &real.repository;

    // Start-time composition adopts exactly the runtime-created project and
    // its lane onto the configured seat; declared projects are untouched.
    let mut config = minimal_config_with_gungnir();
    config.adopt_projects_from(&real.projects, &active.objects);
    assert_eq!(
        config
            .projects
            .get("hekla")
            .map(|project| project.root.clone()),
        Some(real.projects.join("hekla"))
    );
    assert_eq!(config.projects.len(), 1, "only the runtime-created project");
    assert!(config.projects["hekla"].runtime, "adopted, not rendered");
    // Code projects use the served code corpus.
    assert!(
        project.contains("memory_namespaces = [\"atlas.code\"]"),
        "{project}"
    );
    // A session pinned before project creation must still recompose without that project.
    let before = odin_registry::SnapshotStore::new(&real.store)
        .publication_at(1)
        .unwrap()
        .0;
    if let Err(error) = odin_cli::runtime_bindings::RuntimeInputs::parse(&config, &before.objects) {
        assert!(
            !error.contains("hekla"),
            "the old generation must not refuse the runtime project: {error}"
        );
    }
    assert!(config
        .lane_bindings
        .iter()
        .any(|binding| binding.lane.as_str() == "gungnir-hekla"
            && binding.seat.as_str() == "gungnir"
            && binding.project.as_str() == "hekla"));
}

fn minimal_config_with_gungnir() -> odin_huginn::OdindConfig {
    let mut text = String::from(
        "schema = 'odin.odind-config.v1'\nrevision = 1\nworker_bus = 'unix:/tmp/bus.sock'\n[identity]\nnode = 'mini'\n[paths]\nregistry_root = '/'\nstate_root = '/'\nregistry_snapshot = '/'\nauthority_token_root = '/'\nauthority_verification_key_file = '/'\n[listener]\naddress = '127.0.0.1:18420'\n[executables]\nomp_bin = '/omp'\nomp_revision = '",
    );
    text.push_str(&"a".repeat(40));
    text.push_str(
        "'\nextension = '/ext.ts'\nzellij_bin = '/zellij'\nzellij_session = 'odin'\n[catalogs.gateway_projection]\npath = '/p.json'\ndigest = 'blake3:",
    );
    text.push_str(&"c".repeat(64));
    text.push_str(
        "'\n[publish]\nrender_session = '00000000-0000-4000-8000-0000000000aa'\nfile_lane = 'f'\nrender_lane = 'r'\n[[seats]]\nseat = 'gungnir'\nslice = 'gungnir-build'\ndisplay_name = 'Gungnir'\nmax_sessions = 4\nallowed_nodes = ['mini']\n[[seats.launch_options]]\nprovider = 'gateway'\nmodel = 'glm-flash'\ncontainerId = 'gungnir-native'\nskeletonRef = 'gungnir-native'\n[capacity]\n",
    );
    odin_huginn::OdindConfig::parse(&text).expect("minimal config parses")
}

fn helper_admission_config() -> odin_huginn::OdindConfig {
    let mut config = minimal_config_with_gungnir();
    config.brain = Some(odin_huginn::OdindBrainConfig {
        serving_model: odin_huginn::OdindServingModelConfig {
            name: "test-model".to_owned(),
            context_window_tokens: std::num::NonZeroU32::new(1_000_000).unwrap(),
            tokenizer: None,
        },
        sources: Default::default(),
        lane_windows: Default::default(),
        embedding: None,
        postgres: None,
    });
    config
}

fn resolved_helper_policy(
    real: &RealRegistry,
    id: &str,
) -> odin_brain::config::EffectiveBrainPolicy {
    use odin_registry::ObjectConfig;
    let snapshot = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .unwrap();
    let mut config = real.route.admission_config.clone();
    config.adopt_projects_from(&real.projects, &snapshot.objects);
    let slice_id = &config
        .seats
        .iter()
        .find(|binding| binding.seat.as_str() == id)
        .unwrap()
        .slice;
    let seat = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Seat(seat) if object.id == id => Some(seat.as_ref()),
            _ => None,
        })
        .unwrap();
    let slice = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Slice(slice) if object.id == slice_id.as_str() => Some(slice.as_ref()),
            _ => None,
        })
        .unwrap();
    let projects = snapshot
        .objects
        .iter()
        .filter_map(|object| match &object.config {
            ObjectConfig::Project(project) => Some((object.id.as_str(), project.as_ref())),
            _ => None,
        })
        .collect();
    let model = odin_domain::knowledge::retrieval::ModelDescriptor {
        name: "test-model".parse().unwrap(),
        tokenizer: "odin.tokenizer.utf8-bytes.v1".parse().unwrap(),
        context_window_tokens: std::num::NonZeroU32::new(1_000_000).unwrap(),
    };
    odin_brain::config::EffectiveBrainPolicy::resolve(
        snapshot.revision,
        slice,
        seat,
        &projects,
        &odin_registry::context_profiles(&snapshot.objects),
        &model,
    )
    .expect("published helper composes through the runtime policy resolver")
}

/// The ceiling, in code: no other seat creates, and a project never binds a
/// seat beyond the bindable capabilities (kubert reaches the cluster).
#[test]
fn creation_is_refused_beyond_the_ceiling() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::ProjectRoute;
    let real = real_registry();
    let before = git(&real.origin, &["rev-parse", "main"]);
    let gungnir: odin_domain::SeatId = "gungnir".parse().unwrap();
    real.route
        .create(&gungnir, request("hekla", &["gungnir"]))
        .expect_err("a worker must not create projects");
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    real.route
        .create(&sinmara, request("hekla", &["kubert"]))
        .expect_err("cluster authority is outside the creation ceiling");
    real.route
        .create(&sinmara, request("odin", &["gungnir"]))
        .expect_err("an existing binding must not be recreated");
    assert_eq!(git(&real.origin, &["rev-parse", "main"]), before);
    assert!(!real.projects.join("hekla").exists(), "nothing was created");
}

#[test]
fn a_restart_that_kills_its_client_was_accepted() {
    use std::os::unix::process::ExitStatusExt;
    assert!(super::restart_accepted(std::process::ExitStatus::from_raw(
        0
    )));
    assert!(super::restart_accepted(std::process::ExitStatus::from_raw(
        15
    )));
    assert!(!super::restart_accepted(
        std::process::ExitStatus::from_raw(1 << 8)
    ));
}

/// Refuse unavailable remotes rather than creating an empty duplicate repository.
#[test]
fn a_project_clones_colins_existing_repository() {
    use crate::test_support::{commit_all, git};
    use odin_hermes::runtime::projects::ProjectRoute;
    let real = real_registry();
    let owner = real.origin.parent().unwrap().to_path_buf();
    let work = owner.join("brokkr-work");
    std::fs::create_dir(&work).unwrap();
    git(&work, &["-c", "init.defaultBranch=main", "init", "--quiet"]);
    std::fs::write(work.join("engine.py"), "print('brokkr')\n").unwrap();
    let real_head = commit_all(&work, "brokkr: real work");
    git(
        &owner,
        &[
            "clone",
            "--quiet",
            "--bare",
            work.to_str().unwrap(),
            "brokkr.git",
        ],
    );
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();

    let created = real
        .route
        .create(&sinmara, request("brokkr", &["gungnir"]))
        .expect("the project is created");
    let root = real.projects.join("brokkr");
    assert_eq!(created.root, root.display().to_string());
    assert_eq!(
        git(&root, &["rev-parse", "HEAD"]),
        real_head,
        "the root is a clone of the existing repository, not an empty one"
    );
    assert!(root.join("engine.py").exists());

    let mut missing = request("hekla", &["gungnir"]);
    missing.repository = Some("no-such-repo".to_owned());
    let error = real.route.create(&sinmara, missing).unwrap_err();
    assert!(error.contains("there is no repository"), "{error}");
    assert!(!real.projects.join("hekla").exists());

    git(
        &real.repository,
        &[
            "remote",
            "set-url",
            "origin",
            "ssh://odin.invalid/owner/odin.git",
        ],
    );
    let error = real
        .route
        .create(&sinmara, request("eitri", &["gungnir"]))
        .unwrap_err();
    assert!(error.contains("could not check"), "{error}");
    assert!(
        !real.projects.join("eitri").exists(),
        "an unreachable GitHub never yields an empty duplicate"
    );
}

#[test]
fn the_coordinator_creates_a_seat_bounded_by_its_template() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::{ProjectRoute, SeatCreateRequest};
    let real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let ask = |seat: &str, template: &str, projects: &[&str]| SeatCreateRequest {
        seat: seat.to_owned(),
        purpose: "Writes CAD scripts and checks parts.".to_owned(),
        template: template.to_owned(),
        projects: projects.iter().map(|p| (*p).to_owned()).collect(),
    };
    for (caller, request, refusal) in [
        (
            "gungnir",
            ask("forge", "gungnir", &["odin"]),
            "only the owner-facing",
        ),
        (
            "sinmara",
            ask("forge", "kubert", &["odin"]),
            "beyond what a created seat",
        ),
        (
            "sinmara",
            ask("forge", "sinmara", &["odin"]),
            "cannot be copied",
        ),
        (
            "sinmara",
            ask("gungnir", "gungnir", &["odin"]),
            "already exists",
        ),
        (
            "sinmara",
            ask("forge", "gungnir", &["nowhere"]),
            "there is no project",
        ),
    ] {
        let caller: odin_domain::SeatId = caller.parse().unwrap();
        let error = real.route.create_seat(&caller, request).unwrap_err();
        assert!(error.contains(refusal), "{refusal}: {error}");
    }

    let created = real
        .route
        .create_seat(&sinmara, ask("forge", "gungnir", &["odin", "surtr"]))
        .expect("the seat is created");
    assert_eq!(created.lanes, ["forge-odin", "forge-surtr"]);
    assert_eq!(created.ask_tool, "seat_ask_forge");
    assert_eq!(created.published_revision, 2);
    let show = |path: &str| git(&real.origin, &["show", &format!("main:{path}")]);
    let seat: toml::Table = toml::from_str(&show("registry/seats/forge/seat.toml")).unwrap();
    let template: toml::Table = toml::from_str(&show("registry/seats/gungnir/seat.toml")).unwrap();
    assert_eq!(
        seat["tool_refs"], template["tool_refs"],
        "exactly the template's grants"
    );
    assert_eq!(
        seat["project_scope"],
        toml::Value::from(vec!["odin", "surtr"])
    );
    let policy = resolved_helper_policy(&real, "forge");
    assert_eq!(
        policy
            .project_memory
            .keys()
            .map(|id| id.as_str())
            .collect::<Vec<_>>(),
        ["odin", "surtr"]
    );
    assert!(policy.knowledge.is_some());
    assert!(show("registry/capabilities/seat.ask.forge/capability.toml")
        .contains("delegate_to = \"forge\""));
    assert!(show("registry/seats/sinmara/seat.toml").contains("\"seat.ask.forge\""));
    let slice = show("registry/slices/sinmara-life/slice.toml");
    assert!(slice.contains("\"seat.ask.forge\"") && slice.contains("\"seat_ask_forge\""));
    assert!(show("registry/containers/gungnir-native/container.toml").contains("\"forge\""));

    // The daemon adopts the seat on gungnir's binding, with its lanes on
    // declared projects; the generation before it still recomposes.
    let active = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .unwrap();
    let mut config = minimal_config_with_gungnir();
    config.projects.insert(
        "odin".to_owned(),
        odin_huginn::OdindProjectConfig {
            root: real.repository.clone(),
            runtime: false,
        },
    );
    config.adopt_projects_from(&real.projects, &active.objects);
    let forge = config
        .seats
        .iter()
        .find(|binding| binding.seat.as_str() == "forge")
        .expect("the created seat is adopted");
    assert!(forge.runtime);
    assert_eq!(forge.slice.as_str(), "gungnir-build");
    assert_eq!(forge.display_name, "Forge");
    assert!(config
        .lane_bindings
        .iter()
        .any(|binding| binding.lane.as_str() == "forge-odin"));
    let before = odin_registry::SnapshotStore::new(&real.store)
        .publication_at(1)
        .unwrap()
        .0;
    if let Err(error) = odin_cli::runtime_bindings::RuntimeInputs::parse(&config, &before.objects) {
        assert!(
            !error.contains("forge"),
            "the old generation must skip the seat: {error}"
        );
    }
}

#[test]
fn an_existing_project_gains_a_worker_seat() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::ProjectRoute;
    let real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let before = git(
        &real.origin,
        &["show", "main:registry/projects/dotfiles/project.toml"],
    );
    let created = real
        .route
        .create(&sinmara, request("dotfiles", &["gungnir"]))
        .expect("gungnir joins dotfiles");
    assert_eq!(created.lanes, ["gungnir-dotfiles"]);
    let show = |path: &str| git(&real.origin, &["show", &format!("main:{path}")]);
    assert_eq!(show("registry/projects/dotfiles/project.toml"), before);
    assert!(show("registry/seats/gungnir/seat.toml").contains("\"dotfiles\""));
    assert!(git(&real.origin, &["log", "-1", "--format=%s", "main"])
        .starts_with("project: add seats to 'dotfiles'"));
    let joined = real
        .route
        .create(&sinmara, request("dotfiles", &["gungnir", "reginn"]))
        .expect("reginn joins dotfiles");
    assert_eq!(
        joined.lanes,
        ["reginn-dotfiles"],
        "gungnir already works on it"
    );
    let error = real
        .route
        .create(&sinmara, request("dotfiles", &["gungnir"]))
        .unwrap_err();
    assert!(error.contains("already work on dotfiles"), "{error}");

    let active = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .unwrap();
    let mut config = minimal_config_with_gungnir();
    config.projects.insert(
        "dotfiles".to_owned(),
        odin_huginn::OdindProjectConfig {
            root: real.projects.join("dotfiles"),
            runtime: false,
        },
    );
    config.adopt_projects_from(&real.projects, &active.objects);
    let binding = config
        .lane_bindings
        .iter()
        .find(|binding| binding.lane.as_str() == "gungnir-dotfiles")
        .expect("the registry lane is bound");
    assert!(binding.runtime);
    let first = odin_registry::SnapshotStore::new(&real.store)
        .publication_at(1)
        .unwrap()
        .0;
    if let Err(error) = odin_cli::runtime_bindings::RuntimeInputs::parse(&config, &first.objects) {
        assert!(!error.contains("gungnir-dotfiles"), "{error}");
    }
}

/// An open delegated child holds the reload; the conversation alone, idle,
/// does not.
#[test]
fn an_open_delegated_child_holds_the_idle_reload() {
    use odin_domain::huginn::{LiveSessionState, LiveSessionSummary};
    let session = |seat: &str, state| LiveSessionSummary {
        session_id: odin_domain::huginn::LiveSessionId::parse(
            "00000000-0000-4000-8000-000000000001",
        )
        .unwrap(),
        epoch: odin_domain::huginn::SessionEpoch::new(1),
        seat_id: seat.parse().unwrap(),
        provider: odin_domain::huginn::ProviderName::new("gateway").unwrap(),
        model: odin_domain::huginn::ModelName::new("kimi-k28").unwrap(),
        title: None,
        state,
        started_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
        failed_at: None,
        event_head: odin_domain::huginn::EventSeq::new(0),
        terminal_head: odin_domain::huginn::TerminalSeq::new(0),
        pending_permission_count: 0,
    };
    let conversation: std::collections::BTreeSet<odin_domain::SeatId> =
        ["sinmara".parse().unwrap()].into();
    assert!(super::reload_blocked(
        &[session("sinmara", LiveSessionState::Idle)],
        &conversation,
        &Default::default(),
    )
    .is_none());
    assert!(super::reload_blocked(
        &[session("sinmara", LiveSessionState::Running)],
        &conversation,
        &Default::default(),
    )
    .is_some());
    assert!(super::reload_blocked(
        &[
            session("sinmara", LiveSessionState::Idle),
            session("kubert", LiveSessionState::Idle)
        ],
        &conversation,
        &Default::default(),
    )
    .is_some());
    // A child without a process never holds it.
    assert!(super::reload_blocked(
        &[
            session("sinmara", LiveSessionState::Idle),
            session("kubert", LiveSessionState::Detached)
        ],
        &conversation,
        &Default::default(),
    )
    .is_none());
    // An idle child of other work with a process still holds the reload.
    assert!(super::reload_blocked(
        &[
            session("sinmara", LiveSessionState::Idle),
            session("architect", LiveSessionState::Idle)
        ],
        &conversation,
        &Default::default(),
    )
    .is_some());
    // Observers never hold it.
    let mut observer = session("kubert", LiveSessionState::Running);
    observer.title = Some("watch-pc-claude-session".to_owned());
    let observers: std::collections::BTreeSet<String> =
        ["watch-pc-claude-session".to_owned()].into();
    assert!(super::reload_blocked(
        &[session("sinmara", LiveSessionState::Idle), observer.clone()],
        &conversation,
        &observers,
    )
    .is_none());
    assert!(super::reload_blocked(&[observer], &conversation, &Default::default()).is_some());
}

#[test]
fn a_pod_must_bind_a_seat_that_can_launch_it() {
    let real = real_registry();
    let objects = &real.route.pin.current().objects;
    let refusal = crate::workload_authoring::pod_launch_refusal(objects, "gungnir")
        .expect("gungnir cannot launch pods");
    assert!(refusal.contains("kubert"), "{refusal}");
    assert!(crate::workload_authoring::pod_launch_refusal(objects, "kubert").is_none());
}

#[test]
fn the_coordinator_authors_a_lane_a_pod_watchdog_and_an_environment() {
    use crate::test_support::git;
    use odin_hermes::runtime::registry_author::{AuthorRequest, RegistryAuthorRoute};
    let real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let author = |skeleton: &str, id: &str, values: &str| {
        real.route.author(
            &sinmara,
            AuthorRequest {
                skeleton: skeleton.to_owned(),
                id: id.to_owned(),
                values: values.to_owned(),
            },
        )
    };

    let skeleton = real.route.skeleton("new-environment").unwrap();
    assert!(skeleton["variables"]
        .as_array()
        .unwrap()
        .iter()
        .any(|variable| variable["name"] == "transport"));

    let lane = author(
        "new-lane",
        "surtr-authoring-fixture",
        "enabled = true\ndescription = \"reginn work on surtr\"\nproject = \"surtr\"\n\
         family = \"engine\"\ndefault_seat = \"reginn\"\nqueue = \"interactive\"\n\
         independent_review = false\n",
    )
    .expect("the lane is authored");
    assert_eq!(
        lane.path,
        "registry/lanes/surtr-authoring-fixture/lane.toml"
    );
    assert_eq!(lane.published_revision, 2);
    assert_eq!(lane.commit, git(&real.origin, &["rev-parse", "main"]));

    let watchdog = author(
        "new-alert",
        "residual-authoring-fixture",
        "workload = \"residual-watch\"\ncondition = \"residual > 5e-3\"\n\
         consecutive_hits = 4\ncooldown_seconds = 600\nseverity = \"warning\"\n\
         slice = \"kubert-ops\"\n",
    )
    .expect("the pod watchdog is authored");
    assert_eq!(
        watchdog.path,
        "registry/workloads/residual-watch/profile.toml"
    );
    let profile = git(
        &real.origin,
        &[
            "show",
            "main:registry/workloads/residual-watch/profile.toml",
        ],
    );
    assert!(
        profile.contains("id = \"residual-high\""),
        "kept: {profile}"
    );
    assert!(
        profile.contains("id = \"residual-authoring-fixture\""),
        "added: {profile}"
    );

    let environment = author(
        "new-environment",
        "pc-ssh-authoring-fixture",
        "enabled = true\ndescription = \"Colin's pc over ssh\"\ntransport = \"ssh-host\"\n\
         host = \"colin@pc\"\nseats = [\"gungnir\"]\nobservation = { channel = \"events\" }\n",
    )
    .expect("the environment is authored");
    assert_eq!(environment.published_revision, 4);
    let active = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .unwrap();
    for id in ["surtr-authoring-fixture", "pc-ssh-authoring-fixture"] {
        assert!(active.objects.iter().any(|object| object.id == id), "{id}");
    }

    let duplicate = author(
        "new-environment",
        "pc-ssh-authoring-fixture",
        "enabled = true\ndescription = \"again\"\ntransport = \"ssh-host\"\n\
         host = \"colin@pc\"\nseats = [\"gungnir\"]\nobservation = { channel = \"events\" }\n",
    )
    .unwrap_err();
    assert!(duplicate.contains("already exists"), "{duplicate}");
    let unknown_project = author(
        "new-lane",
        "reginn-nowhere",
        "enabled = true\ndescription = \"x\"\nproject = \"nowhere\"\nfamily = \"engine\"\n\
         default_seat = \"reginn\"\nqueue = \"interactive\"\nindependent_review = false\n",
    )
    .unwrap_err();
    assert!(unknown_project.contains("nowhere"), "{unknown_project}");
    let untyped = author(
        "new-lane",
        "reginn-x",
        "enabled = \"yes\"\ndescription = \"x\"\nproject = \"surtr\"\nfamily = \"engine\"\n\
         default_seat = \"reginn\"\nqueue = \"interactive\"\nindependent_review = false\n",
    )
    .unwrap_err();
    assert!(untyped.contains("enabled"), "{untyped}");
    assert_eq!(
        git(&real.origin, &["rev-parse", "main"]),
        environment.commit,
        "no refused fill reached main"
    );
}

#[test]
fn an_environment_removal_is_one_validated_tombstoned_commit() {
    use crate::test_support::git;
    use odin_hermes::runtime::registry_author::{AuthorRequest, RegistryAuthorRoute};
    let mut real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let author = |route: &super::DaemonProjectRoute, skeleton: &str, id: &str, values: &str| {
        route.author(
            &sinmara,
            AuthorRequest {
                skeleton: skeleton.to_owned(),
                id: id.to_owned(),
                values: values.to_owned(),
            },
        )
    };
    let environment = author(
        &real.route,
        "new-environment",
        "pc-ssh-authoring-fixture",
        "enabled = true\ndescription = \"Colin's pc over ssh\"\ntransport = \"ssh-host\"\n\
         host = \"colin@pc\"\nseats = [\"gungnir\"]\nobservation = { channel = \"events\" }\n",
    )
    .expect("the environment is authored");
    let store = odin_registry::SnapshotStore::new(&real.store);
    assert!(
        store
            .load_verified()
            .unwrap()
            .objects
            .iter()
            .any(|object| object.id == "pc-ssh-authoring-fixture"),
        "the environment is published"
    );

    let wrong_kind = author(&real.route, "remove-environment", "surtr", "").unwrap_err();
    assert!(wrong_kind.contains("not an environment"), "{wrong_kind}");
    let unknown = author(&real.route, "remove-environment", "no-such-env", "").unwrap_err();
    assert!(unknown.contains("no environment"), "{unknown}");
    let with_values = author(
        &real.route,
        "remove-environment",
        "pc-ssh-authoring-fixture",
        "reason = \"cleanup\"\n",
    )
    .unwrap_err();
    assert!(with_values.contains("takes no values"), "{with_values}");
    real.route.harness_environments.insert(
        "pc-ssh-authoring-fixture".to_owned(),
        ["sinmara".to_owned()].into(),
    );
    let bound = author(
        &real.route,
        "remove-environment",
        "pc-ssh-authoring-fixture",
        "",
    )
    .unwrap_err();
    assert!(
        bound.contains("bound by a configured seat launch"),
        "{bound}"
    );
    assert_eq!(
        git(&real.origin, &["rev-parse", "main"]),
        environment.commit,
        "no refused removal reached main"
    );
    real.route.harness_environments.clear();

    let removal = author(
        &real.route,
        "remove-environment",
        "pc-ssh-authoring-fixture",
        "",
    )
    .expect("the environment is removed");
    assert_eq!(removal.skeleton, "remove-environment");
    assert_eq!(
        removal.path,
        "registry/environments/pc-ssh-authoring-fixture/environment.toml"
    );
    assert_eq!(
        removal.published_revision,
        environment.published_revision + 1
    );
    let after = store.load_verified().unwrap();
    assert!(
        !after
            .objects
            .iter()
            .any(|object| object.id == "pc-ssh-authoring-fixture"),
        "the environment is gone from the published snapshot"
    );
    let tombstone = after
        .tombstones
        .iter()
        .find(|tombstone| {
            tombstone.kind == odin_registry::RegistryKind::Environment
                && tombstone.id == "pc-ssh-authoring-fixture"
        })
        .expect("the removal is recorded as a tombstone");
    assert_eq!(tombstone.removed_at_revision, removal.published_revision);
    let twice = author(
        &real.route,
        "remove-environment",
        "pc-ssh-authoring-fixture",
        "",
    )
    .unwrap_err();
    assert!(twice.contains("no environment"), "{twice}");
}

#[test]
fn a_proposed_seat_is_a_narrowed_copy_and_its_retirement_is_the_exact_inverse() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::{ProjectRoute, SeatCreateRequest, SeatProposeRequest};
    let real = real_registry();
    let sinmara: odin_domain::SeatId = "sinmara".parse().unwrap();
    let propose = |tools: &[&str]| SeatProposeRequest {
        seat: SeatCreateRequest {
            seat: "fixer".to_owned(),
            purpose: "Fixes one failing test in surtr.".to_owned(),
            template: "gungnir".to_owned(),
            projects: vec!["surtr".to_owned()],
        },
        ttl_hours: 2,
        tools: tools.iter().map(|tool| (*tool).to_owned()).collect(),
    };
    let before = git(&real.origin, &["rev-parse", "main:registry"]);
    let denied_head = git(&real.origin, &["rev-parse", "main"]);
    real.route
        .propose_seat(&sinmara, propose(&["build.run", "kube.workload.create"]))
        .expect_err("a temporary seat must not widen its template");
    assert_eq!(git(&real.origin, &["rev-parse", "main"]), denied_head);

    let proposed = real
        .route
        .propose_seat(&sinmara, propose(&["build.run"]))
        .expect("the temporary seat is proposed");
    assert_eq!(proposed.tools, ["build.run"]);
    assert_eq!(proposed.created.ask_tool, "seat_ask_fixer");
    let show = |path: &str| git(&real.origin, &["show", &format!("main:{path}")]);
    let seat: toml::Table = toml::from_str(&show("registry/seats/fixer/seat.toml")).unwrap();
    assert_eq!(seat["tool_refs"], toml::Value::from(vec!["build.run"]));
    assert_eq!(seat["ephemeral"]["proposed_by"].as_str(), Some("sinmara"));
    assert_eq!(
        seat["ephemeral"]["expires_at"].as_str(),
        Some(proposed.expires_at.as_str())
    );
    assert!(odin_registry::schema::utc_seconds(&proposed.expires_at).is_some());
    assert_eq!(seat["project_scope"], toml::Value::from(vec!["surtr"]));
    let expires = odin_registry::schema::utc_seconds(&proposed.expires_at).unwrap();
    let started =
        odin_registry::schema::utc_seconds(seat["ephemeral"]["proposed_at"].as_str().unwrap())
            .unwrap();
    assert_eq!(expires - started, 2 * 60 * 60);
    let policy = resolved_helper_policy(&real, "fixer");
    assert_eq!(
        policy
            .project_memory
            .keys()
            .map(|id| id.as_str())
            .collect::<Vec<_>>(),
        ["surtr"]
    );
    assert!(policy.knowledge.is_some());
    let template: toml::Table = toml::from_str(&show("registry/seats/gungnir/seat.toml")).unwrap();
    for key in ["context", "tools", "limits", "live", "approval_defaults"] {
        assert_eq!(
            seat[key], template[key],
            "{key} is not widened or discarded"
        );
    }
    assert_eq!(
        policy.registry_revision,
        proposed.created.published_revision
    );
    // The retire pass reads the published revision.
    real.route.pin.reload().unwrap();
    assert!(real
        .route
        .ephemeral_seats()
        .iter()
        .any(|(seat, _)| seat == "fixer"));
    let (revision, _commit) = real
        .route
        .retire_seat("fixer", "ttl")
        .expect("the seat retires");
    assert_eq!(revision, proposed.created.published_revision + 1);
    let after = git(&real.origin, &["rev-parse", "main:registry"]);
    assert_eq!(
        before, after,
        "the retirement is the exact inverse of the proposal"
    );
}

/// Reused seat names must not inherit completion from sessions predating the proposal.
#[test]
fn an_earlier_helpers_ended_session_is_not_this_proposals_work() {
    use super::{retire_reason, since_proposal};
    let session = |started: i64| odin_domain::huginn::LiveSessionSummary {
        session_id: odin_domain::huginn::LiveSessionId::parse(
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap(),
        epoch: odin_domain::huginn::SessionEpoch::new(1),
        seat_id: "surtr-readme-temp".parse().unwrap(),
        provider: odin_domain::huginn::ProviderName::new("gateway").unwrap(),
        model: odin_domain::huginn::ModelName::new("glm-flash").unwrap(),
        title: None,
        state: odin_domain::huginn::LiveSessionState::Ended,
        started_at: time::OffsetDateTime::from_unix_timestamp(started).unwrap(),
        updated_at: time::OffsetDateTime::from_unix_timestamp(started).unwrap(),
        failed_at: None,
        event_head: odin_domain::huginn::EventSeq::new(1),
        terminal_head: odin_domain::huginn::TerminalSeq::new(0),
        pending_permission_count: 0,
    };
    let earlier = vec![session(1_000)];
    assert!(since_proposal(earlier.clone(), Some(2_000)).is_empty());
    assert_eq!(
        retire_reason(2_100, 9_000, 0, 0),
        None,
        "nothing delegated yet"
    );
    assert_eq!(
        since_proposal(earlier, None).len(),
        1,
        "older seats keep the old count"
    );
    assert_eq!(since_proposal(vec![session(2_050)], Some(2_000)).len(), 1);
}

#[test]
fn a_temporary_seat_retires_at_its_expiry_or_when_its_work_is_done() {
    use super::retire_reason;
    assert_eq!(retire_reason(100, 100, 0, 1), Some("ttl"));
    assert_eq!(retire_reason(50, 100, 1, 0), Some("completed"));
    assert_eq!(retire_reason(50, 100, 1, 1), None, "work still open");
    assert_eq!(retire_reason(50, 100, 0, 0), None, "nothing delegated yet");
}

/// Retirement waits for an idle tick or pending reload, but proceeds an hour past expiry.
#[test]
fn a_retirement_waits_for_a_moment_the_reload_holds_no_one() {
    use super::retire_now;
    let expires = 10_000;
    assert!(
        !retire_now(false, true, expires + 60, expires),
        "a turn runs"
    );
    assert!(retire_now(false, false, expires + 60, expires), "idle");
    assert!(
        retire_now(true, true, expires + 60, expires),
        "joins the reload already pending"
    );
    assert!(
        retire_now(false, true, expires + 3_600, expires),
        "an hour past expiry it goes ahead"
    );
}

/// Worker reload holds expire; the conversation's own turn always holds the reload.
#[test]
fn a_worker_turn_holds_the_reload_only_up_to_the_limit() {
    use odin_domain::huginn::{LiveSessionState, LiveSessionSummary};
    let session = |seat: &str| LiveSessionSummary {
        session_id: odin_domain::huginn::LiveSessionId::parse(
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap(),
        epoch: odin_domain::huginn::SessionEpoch::new(1),
        seat_id: seat.parse().unwrap(),
        provider: odin_domain::huginn::ProviderName::new("gateway").unwrap(),
        model: odin_domain::huginn::ModelName::new("glm-flash").unwrap(),
        title: None,
        state: LiveSessionState::Running,
        started_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
        failed_at: None,
        event_head: odin_domain::huginn::EventSeq::new(0),
        terminal_head: odin_domain::huginn::TerminalSeq::new(0),
        pending_permission_count: 0,
    };
    let conversation: std::collections::BTreeSet<odin_domain::SeatId> =
        ["sinmara".parse().unwrap()].into();
    let limit = super::RELOAD_HOLD_LIMIT_SECONDS;
    assert!(!super::reload_forced(
        &session("gungnir"),
        &conversation,
        limit - 5
    ));
    assert!(super::reload_forced(
        &session("gungnir"),
        &conversation,
        limit
    ));
    assert!(!super::reload_forced(
        &session("sinmara"),
        &conversation,
        limit * 10
    ));
    let idle = LiveSessionSummary {
        state: LiveSessionState::Idle,
        ..session("gungnir")
    };
    assert!(super::reload_forced(&idle, &conversation, limit));
}

#[test]
fn only_a_composition_change_requests_the_reload() {
    use crate::project_authoring::{reload_decision, ReloadDecision};
    use odin_registry::schema::{parse_object_toml, RegistryKind};
    use odin_registry::Snapshot;
    const SEAT: &str = include_str!("../../../../../registry/seats/kubert/seat.toml");
    const ROUTINE: &str =
        include_str!("../../../../../registry/routines/weekly-review/routine.toml");
    let seat = |source: &str| {
        parse_object_toml(
            RegistryKind::Seat,
            "kubert",
            "registry/seats/kubert/seat.toml",
            source,
        )
        .expect("seat parses")
    };
    let routine = parse_object_toml(
        RegistryKind::Routine,
        "weekly-review",
        "registry/routines/weekly-review/routine.toml",
        ROUTINE,
    )
    .expect("routine parses");
    let before = Snapshot::build(4, vec![seat(SEAT)]).expect("before");
    let with_routine = Snapshot::build(5, vec![seat(SEAT), routine]).expect("routine");
    assert!(matches!(
        reload_decision(&before, &with_routine),
        ReloadDecision::CompositionUnchanged(_)
    ));
    let changed = SEAT.replacen("description = \"", "description = \"Changed. ", 1);
    let seat_change = Snapshot::build(5, vec![seat(&changed)]).expect("seat change");
    assert_eq!(
        reload_decision(&before, &seat_change),
        ReloadDecision::Recompose
    );
}

/// A reload forced past the hold limit stays forced until it fires: four
/// quiet ticks after the limit, never held again by the same turn.
#[test]
fn a_forced_reload_fires_after_four_ticks() {
    let limit = u32::try_from(super::RELOAD_HOLD_LIMIT_SECONDS / 5).expect("ticks");
    let (mut held, mut quiet, mut fired) = (0, 0, false);
    for tick in 0..limit + 10 {
        // the same worker turn blocks throughout; forced once held past the limit
        let forced = u64::from(held) * 5 >= super::RELOAD_HOLD_LIMIT_SECONDS;
        let _ = tick;
        (held, quiet, fired) = super::reload_step(held, quiet, true, !forced);
        if fired {
            break;
        }
    }
    assert!(fired, "the forced reload fired");
    let (_, _, early) = super::reload_step(3, 3, true, true);
    assert!(!early, "a busy tick never fires");
}
/// Runtime publication adds only its own change to the active snapshot, not undeployed edits on main.
#[test]
fn a_publication_carries_only_its_own_change_when_main_is_ahead() {
    use crate::test_support::{commit_all, git};
    let real = real_registry();
    let base = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .expect("base publication");
    // Another worker pushes a registry edit; no deploy publishes it.
    let capability = real
        .repository
        .join("registry/capabilities/brain.search/capability.toml");
    let text = std::fs::read_to_string(&capability).expect("capability");
    let edited = text.replacen("description = \"", "description = \"Unreleased. ", 1);
    assert_ne!(edited, text, "the fixture edit applies");
    std::fs::write(&capability, edited).expect("edit");
    commit_all(&real.repository, "brain.search (unreleased)");
    git(&real.repository, &["push", "--quiet", "origin", "main"]);
    let before = git(&real.origin, &["rev-parse", "main"]);
    let hook = real.origin.join("hooks/pre-receive");
    std::fs::write(&hook, "#!/bin/sh\necho push >> runtime-pushes\n").expect("hook");
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("hook mode");

    let routine = std::fs::read_to_string(
        real.repository
            .join("registry/routines/weekly-review/routine.toml"),
    )
    .expect("routine");
    let (revision, commit) = real
        .route
        .transact(
            "routine: declared 'noop-test' (runtime, by seat sinmara)",
            vec![(
                "registry/routines/noop-test/routine.toml".to_owned(),
                routine.replace("sun 18:00", "sun 03:33"),
            )],
            Vec::new(),
            &[],
        )
        .expect("the routine publishes");
    assert_eq!(revision, 2);
    assert_eq!(
        std::fs::read_to_string(real.origin.join("runtime-pushes")).expect("push log"),
        "push\n",
        "one push for the declaration"
    );
    let receipt = odin_registry::SnapshotStore::new(&real.store)
        .publication_at(revision)
        .expect("declaration receipt")
        .1;
    assert_eq!(receipt.commit, commit);
    assert_eq!(
        receipt.tree,
        git(&real.origin, &["rev-parse", &format!("{commit}^{{tree}}")]),
        "the receipt binds the actual main commit tree"
    );

    let published = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .expect("published");
    assert!(published
        .objects
        .iter()
        .any(|object| object.id == "noop-test"));
    assert_eq!(
        published.composition_digest().expect("digest"),
        base.composition_digest().expect("digest"),
        "the routine publication composes nothing new; main's unreleased edit is not in it"
    );
    assert_eq!(
        serde_json::to_value(
            published
                .objects
                .iter()
                .filter(|object| object.id != "noop-test")
                .collect::<Vec<_>>()
        )
        .expect("published objects"),
        serde_json::to_value(&base.objects).expect("base objects"),
        "active retains every unrelated object's exact bytes"
    );
    assert!(
        matches!(
            super::reload_decision(&base, &published),
            super::ReloadDecision::CompositionUnchanged(_)
        ),
        "no idle reload for it"
    );
    // Main holds both changes and the published commit.
    let main = git(&real.origin, &["rev-parse", "main"]);
    assert_eq!(commit, main, "the publication is main's actual tip");
    assert_eq!(
        git(&real.origin, &["rev-list", "--parents", "-n", "1", &main]),
        format!("{main} {before}"),
        "the declaration is a single-parent child of the previous main"
    );
    assert_eq!(
        git(
            &real.origin,
            &["rev-list", "--count", &format!("{before}..{main}")]
        ),
        "1",
        "exactly one reachable commit for the declaration"
    );
    let on_main = git(
        &real.origin,
        &[
            "show",
            &format!("{main}:registry/capabilities/brain.search/capability.toml"),
        ],
    );
    assert!(on_main.contains("Unreleased."), "main keeps the other edit");
    assert_eq!(
        on_main,
        git(
            &real.origin,
            &[
                "show",
                &format!("{before}:registry/capabilities/brain.search/capability.toml")
            ]
        ),
        "main retains the exact unpublished capability bytes"
    );
    git(
        &real.origin,
        &[
            "cat-file",
            "-e",
            &format!("{main}:registry/routines/noop-test/routine.toml"),
        ],
    );

    // Removal is another ordinary child, still excluding the unpublished edit.
    let (next, removal) = real
        .route
        .transact(
            "routine: removed 'noop-test'",
            Vec::new(),
            Vec::new(),
            &["registry/routines/noop-test".to_owned()],
        )
        .expect("the removal publishes");
    assert_eq!(next, 3);
    let removed_main = git(&real.origin, &["rev-parse", "main"]);
    assert_eq!(removal, removed_main);
    assert_eq!(
        git(
            &real.origin,
            &["rev-list", "--parents", "-n", "1", &removed_main]
        ),
        format!("{removed_main} {main}"),
        "the removal is a single-parent child of the declaration"
    );
    assert_eq!(
        git(
            &real.origin,
            &["rev-list", "--count", &format!("{main}..{removed_main}")]
        ),
        "1",
        "exactly one reachable commit for the removal"
    );
    assert_eq!(
        std::fs::read_to_string(real.origin.join("runtime-pushes")).expect("push log"),
        "push\npush\n",
        "one push per mutation"
    );
    assert_eq!(
        git(
            &real.origin,
            &[
                "show",
                &format!("{removed_main}:registry/capabilities/brain.search/capability.toml")
            ]
        ),
        on_main,
        "removal preserves the unpublished bytes on main"
    );
    assert_eq!(
        git(
            &real.origin,
            &[
                "ls-tree",
                "-r",
                "--name-only",
                &removed_main,
                "registry/routines/noop-test"
            ]
        ),
        "",
        "the routine is removed from main"
    );
    let receipt = odin_registry::SnapshotStore::new(&real.store)
        .publication_at(next)
        .expect("removal receipt")
        .1;
    assert_eq!(receipt.commit, removal);
    assert_eq!(
        receipt.tree,
        git(&real.origin, &["rev-parse", &format!("{removal}^{{tree}}")])
    );
    let removed = odin_registry::SnapshotStore::new(&real.store)
        .load_verified()
        .expect("published");
    assert_eq!(
        removed.composition_digest().expect("digest"),
        base.composition_digest().expect("digest")
    );
    assert_eq!(
        serde_json::to_value(&removed.objects).expect("removed objects"),
        serde_json::to_value(&base.objects).expect("base objects"),
        "active returns to exactly its original objects, not the unpublished registry"
    );
}

#[test]
fn a_runtime_change_lands_once_on_main_when_main_is_ahead_with_code() {
    use crate::test_support::{commit_all, git};
    let real = real_registry();
    std::fs::create_dir_all(real.repository.join("docs")).expect("docs");
    std::fs::write(real.repository.join("docs/NOTE.md"), "undeployed\n").expect("note");
    commit_all(&real.repository, "docs: undeployed note");
    git(&real.repository, &["push", "--quiet", "origin", "main"]);

    let routine = std::fs::read_to_string(
        real.repository
            .join("registry/routines/weekly-review/routine.toml"),
    )
    .expect("routine");
    let mut tip = git(&real.origin, &["rev-parse", "main"]);
    for (revision, message, files, removals) in [
        (
            2,
            "routine: declared 'noop-test' (runtime, by seat sinmara)",
            vec![(
                "registry/routines/noop-test/routine.toml".to_owned(),
                routine.replace("sun 18:00", "sun 03:33"),
            )],
            Vec::new(),
        ),
        (
            3,
            "routine: remove 'noop-test' (runtime, by seat sinmara)",
            Vec::new(),
            vec!["registry/routines/noop-test".to_owned()],
        ),
    ] {
        let (published, commit) = real
            .route
            .transact(message, files, Vec::new(), &removals)
            .expect("the routine change publishes");
        assert_eq!(published, revision);
        let main = git(&real.origin, &["rev-parse", "main"]);
        assert_eq!(commit, main, "the published commit is main's tip");
        assert_eq!(
            git(&real.origin, &["rev-list", "--parents", "-n", "1", &main]),
            format!("{main} {tip}"),
            "one plain child of the previous tip, no merge"
        );
        assert_eq!(
            git(
                &real.origin,
                &["log", "--format=%s", &format!("{tip}..{main}")]
            ),
            message
        );
        tip = main;
    }
}

/// A commit that lands on `main` while a runtime change is being pushed is
/// kept, and the change is staged again on top of it instead of failing.
#[test]
fn a_runtime_change_is_restaged_when_main_moves_under_its_push() {
    use crate::test_support::{commit_all, git};
    let real = real_registry();
    let before = git(&real.origin, &["rev-parse", "main"]);
    std::fs::create_dir_all(real.repository.join("docs")).expect("docs");
    std::fs::write(real.repository.join("docs/NOTE.md"), "concurrent\n").expect("note");
    commit_all(&real.repository, "docs: lands concurrently");
    git(
        &real.repository,
        &["push", "--quiet", "origin", "HEAD:refs/heads/incoming"],
    );
    let concurrent = git(&real.repository, &["rev-parse", "HEAD"]);
    // The first push is refused after `main` moves to the concurrent commit.
    let hook = real.origin.join("hooks/pre-receive");
    std::fs::write(
        &hook,
        "#!/bin/sh\nif [ ! -e moved ]; then touch moved; \
         env -u GIT_QUARANTINE_PATH git update-ref refs/heads/main refs/heads/incoming; exit 1; fi\n",
    )
    .expect("hook");
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("hook mode");

    let routine = std::fs::read_to_string(
        real.repository
            .join("registry/routines/weekly-review/routine.toml"),
    )
    .expect("routine");
    let message = "routine: declared 'noop-test' (runtime, by seat sinmara)";
    let (revision, commit) = real
        .route
        .transact(
            message,
            vec![(
                "registry/routines/noop-test/routine.toml".to_owned(),
                routine.replace("sun 18:00", "sun 03:33"),
            )],
            Vec::new(),
            &[],
        )
        .expect("the routine publishes on the moved main");
    assert_eq!(revision, 2);
    assert!(
        real.origin.join("moved").exists(),
        "the first push was refused"
    );
    let main = git(&real.origin, &["rev-parse", "main"]);
    assert_eq!(commit, main);
    assert_eq!(
        git(&real.origin, &["rev-list", "--parents", "-n", "1", &main]),
        format!("{main} {concurrent}"),
        "the change sits on the concurrent commit"
    );
    assert_eq!(
        git(
            &real.origin,
            &["log", "--format=%s", &format!("{before}..{main}")]
        ),
        format!("{message}\ndocs: lands concurrently")
    );
}

/// A refused push never advances active or leaves a reachable mutation on main.
#[test]
fn a_refused_runtime_push_leaves_main_and_active_unchanged() {
    use crate::test_support::git;
    let real = real_registry();
    let before = git(&real.origin, &["rev-parse", "main"]);
    let store = odin_registry::SnapshotStore::new(&real.store);
    let base = store.load_verified().expect("base");
    let receipt = store.publication_at(1).expect("base receipt").1;
    let hook = real.origin.join("hooks/pre-receive");
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").expect("hook");
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("hook mode");
    let routine = std::fs::read_to_string(
        real.repository
            .join("registry/routines/weekly-review/routine.toml"),
    )
    .expect("routine");
    assert!(
        real.route
            .transact(
                "routine: declared 'noop-test' (runtime, by seat sinmara)",
                vec![(
                    "registry/routines/noop-test/routine.toml".to_owned(),
                    routine
                )],
                Vec::new(),
                &[],
            )
            .is_err(),
        "the actual transaction refuses the rejected push"
    );
    assert_eq!(git(&real.origin, &["rev-parse", "main"]), before);
    assert_eq!(
        serde_json::to_value(store.load_verified().expect("active")).expect("active JSON"),
        serde_json::to_value(base).expect("base JSON"),
        "a rejected push publishes nothing"
    );
    assert_eq!(
        serde_json::to_value(store.publication_at(1).expect("receipt").1).expect("receipt JSON"),
        serde_json::to_value(receipt).expect("base receipt JSON")
    );
    assert!(
        store.publication_at(2).is_err(),
        "no second revision exists"
    );
}

/// A store failure after the push leaves one commit for the next deploy to publish.
#[test]
fn a_pushed_runtime_change_survives_store_failure_and_the_next_deploy() {
    use crate::test_support::git;
    let real = real_registry();
    let store = odin_registry::SnapshotStore::new(&real.store);
    let base = store.load_verified().expect("base");
    let before = git(&real.origin, &["rev-parse", "main"]);
    let hook = real.origin.join("hooks/pre-receive");
    std::fs::write(&hook, "#!/bin/sh\necho push >> runtime-pushes\n").expect("hook");
    std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("hook mode");
    // Occupy only the future immutable snapshot, not any active state that
    // transaction preparation must read. The real store write will refuse it.
    let obstruction = real
        .store
        .parent()
        .expect("store parent")
        .join("revisions/00000000000000000002.snapshot.json");
    std::fs::create_dir(&obstruction).expect("future snapshot obstruction");
    let routine = std::fs::read_to_string(
        real.repository
            .join("registry/routines/weekly-review/routine.toml"),
    )
    .expect("routine");
    assert!(
        real.route
            .transact(
                "routine: declared 'noop-test' (runtime, by seat sinmara)",
                vec![(
                    "registry/routines/noop-test/routine.toml".to_owned(),
                    routine
                )],
                Vec::new(),
                &[],
            )
            .is_err(),
        "the actual transaction reports its failed store write"
    );
    let main = git(&real.origin, &["rev-parse", "main"]);
    assert_ne!(
        main, before,
        "the push succeeded before the store write failed"
    );
    assert_eq!(
        git(&real.origin, &["rev-list", "--parents", "-n", "1", &main]),
        format!("{main} {before}")
    );
    assert_eq!(
        git(
            &real.origin,
            &["rev-list", "--count", &format!("{before}..{main}")]
        ),
        "1"
    );
    assert_eq!(store.load_verified().expect("active after failure"), base);
    assert!(store.publication_at(2).is_err());
    std::fs::remove_dir(&obstruction).expect("remove only the fixture obstruction");

    // The next deploy's ordinary committed-candidate path consumes the
    // already-pushed main commit; it must not author or push a replacement.
    let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
        &real.route.worktree,
        &main,
        odin_cli::runtime_bindings::admitted_registry_bindings(),
    )
    .expect("the pushed commit validates for deploy");
    store
        .publish_committed(&candidate, 2)
        .expect("next deploy publishes the pushed commit");
    let active = store.load_verified().expect("recovered active");
    assert!(active.objects.iter().any(|object| object.id == "noop-test"));
    let receipt = store.publication_at(2).expect("recovered receipt").1;
    assert_eq!(receipt.commit, main);
    assert_eq!(
        receipt.tree,
        git(&real.origin, &["rev-parse", &format!("{main}^{{tree}}")])
    );
    assert_eq!(git(&real.origin, &["rev-parse", "main"]), main);
    assert_eq!(
        std::fs::read_to_string(real.origin.join("runtime-pushes")).expect("push log"),
        "push\n",
        "failure plus deploy recovery pushes exactly once"
    );
}

#[test]
fn an_invalid_final_helper_policy_cannot_publish_or_advance_the_pin() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::{ProjectRoute, SeatCreateRequest, SeatProposeRequest};
    for change_slice in [false, true] {
        let real = real_registry();
        real.route
            .propose_seat(
                &"sinmara".parse().unwrap(),
                SeatProposeRequest {
                    seat: SeatCreateRequest {
                        seat: "fixer".to_owned(),
                        purpose: "Fixes surtr tests".to_owned(),
                        template: "gungnir".to_owned(),
                        projects: vec!["surtr".to_owned()],
                    },
                    ttl_hours: 2,
                    tools: vec!["build.run".to_owned()],
                },
            )
            .unwrap();
        resolved_helper_policy(&real, "fixer");
        let before_main = git(&real.origin, &["rev-parse", "main"]);
        let before_store = std::fs::read(&real.store).unwrap();
        let before_pin = real.route.pin.current();
        let path = if change_slice {
            "registry/slices/gungnir-build/slice.toml"
        } else {
            "registry/seats/fixer/seat.toml"
        };
        real.route
            .transact(
                "seat: reject invalid final helper policy",
                Vec::new(),
                vec![crate::project_authoring::Edit::new(
                    path.to_owned(),
                    path.to_owned(),
                    move |text| {
                        let mut declaration: toml::Table = toml::from_str(text).unwrap();
                        if change_slice {
                            // The synced slice drops a source the gungnir-native
                            // seats still declare, so no final policy resolves.
                            declaration["knowledge"]["atlas_sources"]
                                .as_array_mut()
                                .unwrap()
                                .retain(|source| source.as_str() != Some("atlas.code"));
                        } else {
                            // Registry-valid, but outside the helper's bound slice authority.
                            declaration["knowledge"]["atlas_sources"]
                                .as_array_mut()
                                .unwrap()
                                .push(toml::Value::from("memory.unserved-fixture"));
                            declaration["brain_scope"]
                                .as_array_mut()
                                .unwrap()
                                .push(toml::Value::from("memory.unserved-fixture"));
                        }
                        Ok(toml::to_string(&declaration).unwrap())
                    },
                )],
                &[],
            )
            .expect_err("an invalid final helper policy must not publish");
        assert_eq!(git(&real.origin, &["rev-parse", "main"]), before_main);
        assert_eq!(std::fs::read(&real.store).unwrap(), before_store);
        let after_pin = real.route.pin.current();
        assert!(std::sync::Arc::ptr_eq(&before_pin, &after_pin));
        assert!(matches!(
            crate::project_authoring::reload_decision(&before_pin, &after_pin),
            crate::project_authoring::ReloadDecision::CompositionUnchanged(_)
        ));
        resolved_helper_policy(&real, "fixer");
    }
}

#[test]
fn helpers_narrow_to_the_actual_cooffered_lender_not_the_requested_template() {
    use crate::test_support::git;
    use odin_hermes::runtime::projects::{ProjectRoute, SeatCreateRequest, SeatProposeRequest};
    for temporary in [false, true] {
        let real = real_registry_with_lender(true);
        let before = git(&real.origin, &["rev-parse", "main:registry"]);
        resolved_helper_policy(&real, "gungnir");
        let request = SeatCreateRequest {
            seat: "fixer".to_owned(),
            purpose: "Fixes surtr tests with review-slice knowledge".to_owned(),
            template: "gungnir".to_owned(),
            projects: vec!["surtr".to_owned()],
        };
        let caller = "sinmara".parse().unwrap();
        if temporary {
            let proposed = real
                .route
                .propose_seat(
                    &caller,
                    SeatProposeRequest {
                        seat: request,
                        ttl_hours: 2,
                        tools: vec!["build.run".to_owned()],
                    },
                )
                .expect("temporary helper narrows to the actual lender");
            assert_eq!(proposed.tools, ["build.run"]);
        } else {
            real.route
                .create_seat(&caller, request)
                .expect("permanent helper uses the same narrowed derivation");
        }
        let snapshot = real.route.pin.current();
        let mut config = real.route.admission_config.clone();
        config.adopt_projects_from(&real.projects, &snapshot.objects);
        let binding = config
            .seats
            .iter()
            .find(|binding| binding.seat.as_str() == "fixer")
            .unwrap();
        assert_eq!(binding.slice.as_str(), "helper-review");
        let policy = resolved_helper_policy(&real, "fixer");
        assert_eq!(
            policy
                .project_memory
                .keys()
                .map(|id| id.as_str())
                .collect::<Vec<_>>(),
            ["surtr"]
        );
        assert!(policy
            .project_memory
            .values()
            .all(|sources| sources.is_empty()));
        assert_eq!(
            policy
                .seat_global_sources
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>(),
            ["state.repos"]
        );
        let show = |seat| {
            git(
                &real.origin,
                &["show", &format!("main:registry/seats/{seat}/seat.toml")],
            )
        };
        let helper: toml::Table = toml::from_str(&show("fixer")).unwrap();
        let template: toml::Table = toml::from_str(&show("gungnir")).unwrap();
        assert!(template["brain_scope"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source.as_str() == Some("memory.colin")));
        assert_eq!(
            helper["brain_scope"],
            toml::Value::from(vec!["state.repos"])
        );
        assert_eq!(
            helper["knowledge"]["atlas_sources"],
            toml::Value::from(vec!["state.repos"])
        );
        assert_eq!(helper["project_scope"], toml::Value::from(vec!["surtr"]));
        if temporary {
            assert_eq!(helper["tool_refs"], toml::Value::from(vec!["build.run"]));
            real.route.retire_seat("fixer", "ttl").unwrap();
            assert_eq!(git(&real.origin, &["rev-parse", "main:registry"]), before);
        } else {
            assert_eq!(helper["tool_refs"], template["tool_refs"]);
            assert!(!helper.contains_key("ephemeral"));
        }
    }
}

#[test]
fn synced_authority_changes_cannot_publish_a_helpers_stale_plan() {
    use crate::test_support::git;
    for (path, refusal) in [
        (
            "registry/seats/gungnir/seat.toml",
            "template changed while planning helper authority",
        ),
        (
            "registry/slices/helper-review/slice.toml",
            "slice changed while planning helper authority",
        ),
        (
            "registry/slices/gungnir-build/slice.toml",
            "slice changed while planning helper authority",
        ),
        (
            "registry/containers/gungnir-native/container.toml",
            "container changed while planning helper binding",
        ),
        (
            "registry/projects/surtr/project.toml",
            "project changed while planning helper authority",
        ),
    ] {
        let real = real_registry_with_lender(true);
        let request = odin_hermes::runtime::projects::SeatCreateRequest {
            seat: "fixer".to_owned(),
            purpose: "Fixes surtr tests".to_owned(),
            template: "gungnir".to_owned(),
            projects: vec!["surtr".to_owned()],
        };
        let plan = real
            .route
            .seat_plan(&"sinmara".parse().unwrap(), &request, None)
            .expect("the pinned template admits the helper plan");
        let before_main = git(&real.origin, &["rev-parse", "main"]);
        let before_store = std::fs::read(&real.store).unwrap();
        let before_pin = real.route.pin.current();
        let mut edits = vec![crate::project_authoring::Edit::new(
            path.to_owned(),
            path.to_owned(),
            move |text| {
                let mut declaration: toml::Table = toml::from_str(text).unwrap();
                if path.contains("/containers/") {
                    declaration["seats_offered"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|seat| seat.as_str() != Some("forseti"));
                } else if path.contains("/projects/") {
                    declaration["memory_namespaces"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|namespace| namespace.as_str() != Some("memory.project.surtr"));
                } else {
                    declaration["knowledge"]["atlas_sources"]
                        .as_array_mut()
                        .unwrap()
                        .retain(|source| source.as_str() != Some("atlas.code"));
                    if let Some(scope) = declaration.get_mut("brain_scope") {
                        scope
                            .as_array_mut()
                            .unwrap()
                            .retain(|source| source.as_str() != Some("atlas.code"));
                    }
                }
                Ok(toml::to_string(&declaration).unwrap())
            },
        )];
        edits.extend(plan.edits);
        let error = real
            .route
            .transact(
                "seat: reject stale template authority",
                plan.files,
                edits,
                &[],
            )
            .unwrap_err();
        assert!(error.contains(refusal), "{refusal}: {error}");
        assert_eq!(git(&real.origin, &["rev-parse", "main"]), before_main);
        assert_eq!(std::fs::read(&real.store).unwrap(), before_store);
        let after_pin = real.route.pin.current();
        assert!(std::sync::Arc::ptr_eq(&before_pin, &after_pin));
        assert!(matches!(
            crate::project_authoring::reload_decision(&before_pin, &after_pin),
            crate::project_authoring::ReloadDecision::CompositionUnchanged(_)
        ));
    }
}

#[test]
fn a_final_lender_change_cannot_publish_even_when_the_policy_still_composes() {
    use crate::test_support::git;
    let real = real_registry_with_lender(true);
    let request = odin_hermes::runtime::projects::SeatCreateRequest {
        seat: "fixer".to_owned(),
        purpose: "Fixes surtr tests".to_owned(),
        template: "gungnir".to_owned(),
        projects: vec!["surtr".to_owned()],
    };
    let plan = real
        .route
        .seat_plan(&"sinmara".parse().unwrap(), &request, None)
        .unwrap();
    assert_eq!(plan.slice.as_str(), "helper-review");
    let before_main = git(&real.origin, &["rev-parse", "main"]);
    let before_store = std::fs::read(&real.store).unwrap();
    let before_pin = real.route.pin.current();
    let path = "registry/containers/gungnir-native/container.toml";
    let mut edits = plan.edits;
    edits.push(crate::project_authoring::Edit::new(
        path.to_owned(),
        path.to_owned(),
        |text| {
            let mut container: toml::Table = toml::from_str(text).unwrap();
            container["seats_offered"]
                .as_array_mut()
                .unwrap()
                .retain(|seat| seat.as_str() != Some("forseti"));
            Ok(toml::to_string(&container).unwrap())
        },
    ));
    let expected_slice = plan.slice;
    let final_policy_composed = std::cell::Cell::new(false);
    real.route
        .transact_with_admission(
            "seat: reject changed final helper lender",
            plan.files,
            edits,
            &[],
            |objects| {
                crate::projection::admit_brain_policies(
                    &real.route.admission_config,
                    before_pin.revision + 1,
                    objects,
                    &before_pin.objects,
                )
                .expect("the narrowed policy still composes on the broader replacement lender");
                final_policy_composed.set(true);
                real.route
                    .admit_planned_seat(objects, "fixer", &expected_slice)
            },
        )
        .expect_err("a changed final lender must not publish a stale helper plan");
    assert!(final_policy_composed.get());
    assert_eq!(git(&real.origin, &["rev-parse", "main"]), before_main);
    assert_eq!(std::fs::read(&real.store).unwrap(), before_store);
    let after_pin = real.route.pin.current();
    assert!(std::sync::Arc::ptr_eq(&before_pin, &after_pin));
    assert!(matches!(
        crate::project_authoring::reload_decision(&before_pin, &after_pin),
        crate::project_authoring::ReloadDecision::CompositionUnchanged(_)
    ));
}
