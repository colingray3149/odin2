//! Workload schema validation: strict fields, pinned images, confined paths and hosts, and typed lookup.

use std::path::PathBuf;

use super::{ObjectConfig, RegistryObject, WorkloadProfileToml, WORKLOAD_BRIEF_MAX_BYTES};
use odin_domain::huginn::WorkloadLimits;

const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

const VALID_PROFILE: &str = r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Strict workload shape."

[image]
reference = "localhost/odin-fixture@sha256:1111111111111111111111111111111111111111111111111111111111111111"

[runtime]
launcher = "/odin/bin/omp"
browser = "/odin/bin/chromium"
supervisor = "/odin/bin/odind"
playwright = "/odin/lib/playwright-core"

[seat]
seat = "coordinator"
project = "home"
gateway_lane = "fixture.gateway"

[network]
allow_hosts = ["example.com"]

[display]
xvfb = "/odin/bin/Xvfb"
screen = "1280x800x24"
stream = true

[state]
path = "/state"
storage = "2Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/fixture"

[brief]
text = "fixture brief"

[memory]
namespace = "atlas.code"

[lifetime]
deadline_seconds = 5400
"#;
fn object(id: &str, enabled: bool, source: &str) -> RegistryObject {
    let mut object = RegistryObject {
        id: id.to_owned(),
        relative_config: PathBuf::from(format!("registry/workloads/{id}/profile.toml")),
        config: ObjectConfig::Workload(Box::new(
            toml::from_str::<WorkloadProfileToml>(source).expect("parse workload fixture"),
        )),
    };
    if let ObjectConfig::Workload(profile) = &mut object.config {
        profile.enabled = enabled;
    }
    object
}

fn enabled_object(source: &str) -> RegistryObject {
    object("shape-fixture", true, source)
}

fn codes(source: &str) -> Vec<String> {
    crate::schema::validate_object(&enabled_object(source))
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

#[test]
fn campaign_approval_policy_defaults_off_and_round_trips() {
    let default: WorkloadProfileToml = toml::from_str(VALID_PROFILE).unwrap();
    assert!(!default.require_campaign_approval);
    assert!(!toml::to_string(&default)
        .unwrap()
        .contains("require_campaign_approval"));

    let source = VALID_PROFILE.replace(
        "description = \"Strict workload shape.\"",
        "description = \"Strict workload shape.\"\nrequire_campaign_approval = true",
    );
    let required: WorkloadProfileToml = toml::from_str(&source).unwrap();
    assert!(required.require_campaign_approval);
    let serialized = toml::to_string(&required).unwrap();
    let round_trip: WorkloadProfileToml = toml::from_str(&serialized).unwrap();
    assert!(round_trip.require_campaign_approval);

    let invalid = source.replace(
        "require_campaign_approval = true",
        "require_campaign_approval = \"yes\"",
    );
    assert!(toml::from_str::<WorkloadProfileToml>(&invalid).is_err());
}

#[test]
fn stage_run_limit_is_optional_nonzero_and_round_trips() {
    let default: WorkloadProfileToml = toml::from_str(VALID_PROFILE).unwrap();
    assert_eq!(default.stage_run_max_bytes, None);
    assert!(!toml::to_string(&default)
        .unwrap()
        .contains("stage_run_max_bytes"));

    let source = |value: &str| {
        VALID_PROFILE.replace(
            "description = \"Strict workload shape.\"",
            &format!("description = \"Strict workload shape.\"\nstage_run_max_bytes = {value}"),
        )
    };
    let profile: WorkloadProfileToml = toml::from_str(&source("2097152")).unwrap();
    assert_eq!(profile.stage_run_max_bytes.unwrap().get(), 2_097_152);
    let round_trip: WorkloadProfileToml =
        toml::from_str(&toml::to_string(&profile).unwrap()).unwrap();
    assert_eq!(round_trip.stage_run_max_bytes, profile.stage_run_max_bytes);
    for invalid in ["0", "-1", "\"large\""] {
        assert!(toml::from_str::<WorkloadProfileToml>(&source(invalid)).is_err());
    }
}

/// Workload memory accepts the same atlas.* and memory.* namespaces as projects.
#[test]
fn project_memory_namespaces_bind_workloads() {
    for (namespace, lawful) in [
        ("atlas.code", true),
        ("memory.project.odin", true),
        ("memory.kubert", true),
        ("memory.", false),
        ("atlas.", false),
        ("notes.odin", false),
    ] {
        let source = VALID_PROFILE.replace(
            "namespace = \"atlas.code\"",
            &format!("namespace = \"{namespace}\""),
        );
        let refused = codes(&source)
            .iter()
            .any(|code| code == "workload-memory-namespace");
        assert_eq!(refused, !lawful, "namespace {namespace}");
    }
}

#[test]
fn image_identity_requires_a_manifest_digest_pin() {
    let valid = codes(VALID_PROFILE);
    assert!(
        !valid.iter().any(|code| code == "workload-image-reference"),
        "the digest-pinned fixture must satisfy identity law: {valid:?}"
    );
    let platform = VALID_PROFILE.replacen(
        &format!("reference = \"localhost/odin-fixture@{DIGEST}\""),
        "reference = \"platform\"",
        1,
    );
    assert_ne!(platform, VALID_PROFILE, "replacement must hit the line");
    assert!(
        !codes(&platform)
            .iter()
            .any(|code| code == "workload-image-reference"),
        "\"platform\" names the deployed workload image"
    );
    for reference in [
        "Platform",
        "localhost/odin-fixture:20260921",
        "odin-fixture@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "localhost/odin-fixture@sha256:nothex",
        "localhost/odin-fixture:latest@sha256:1111111111111111111111111111",
    ] {
        let attempt = VALID_PROFILE.replacen(
            &format!("reference = \"localhost/odin-fixture@{DIGEST}\""),
            &format!("reference = \"{reference}\""),
            1,
        );
        assert_ne!(attempt, VALID_PROFILE, "replacement must hit the line");
        let codes = codes(&attempt);
        assert!(
            codes.iter().any(|code| code == "workload-image-reference"),
            "reference without a valid manifest digest pin must fail: {reference:?}"
        );
    }
}

#[test]
fn confined_paths_screens_namespaces_and_briefs_are_enforced() {
    let cases: [(&str, &str, &str); 9] = [
        ("runtime.launcher", "relative/omp", "workload-runtime-path"),
        (
            "runtime.supervisor",
            "relative/odind",
            "workload-runtime-path",
        ),
        ("runtime.playwright", "relative/pw", "workload-runtime-path"),
        ("state.path", "../escape", "workload-state-path"),
        ("state.storage", "2TiB", "workload-state-storage"),
        ("state.storage", "0Gi", "workload-state-storage"),
        ("display.screen", "1280x800", "workload-display-screen"),
        (
            "memory.namespace",
            "secrets/code",
            "workload-memory-namespace",
        ),
        ("brief.text", "", "workload-brief-empty"),
    ];
    for (field, replacement, expected_code) in cases {
        let source = match field {
            "runtime.launcher" => VALID_PROFILE.replacen("/odin/bin/omp", replacement, 1),
            "runtime.supervisor" => VALID_PROFILE.replacen("/odin/bin/odind", replacement, 1),
            "runtime.playwright" => {
                VALID_PROFILE.replacen("/odin/lib/playwright-core", replacement, 1)
            }
            "state.path" => {
                VALID_PROFILE.replacen("path = \"/state\"", &format!("path = \"{replacement}\""), 1)
            }
            "state.storage" => VALID_PROFILE.replacen(
                "storage = \"2Gi\"",
                &format!("storage = \"{replacement}\""),
                1,
            ),
            "display.screen" => VALID_PROFILE.replacen("1280x800x24", replacement, 1),
            "memory.namespace" => VALID_PROFILE.replacen("atlas.code", replacement, 1),
            "brief.text" => VALID_PROFILE.replacen("fixture brief", replacement, 1),
            _ => unreachable!(),
        };
        let codes = codes(&source);
        assert!(
            codes.iter().any(|code| code == expected_code),
            "{field} law must reject {replacement:?}: {codes:?}"
        );
    }
    let long_brief = VALID_PROFILE.replacen(
        "text = \"fixture brief\"",
        &format!("text = \"{}\"", "x".repeat(WORKLOAD_BRIEF_MAX_BYTES + 1)),
        1,
    );
    let codes = codes(&long_brief);
    assert!(
        codes.iter().any(|code| code == "workload-brief-bound"),
        "an oversized brief must fail the declared bound: {codes:?}"
    );
}

#[test]
fn open_public_egress_cannot_also_pin_hosts() {
    let open = VALID_PROFILE.replacen("[network]\n", "[network]\nopen = true\n", 1);
    let open_codes = codes(&open);
    assert!(
        open_codes
            .iter()
            .any(|code| code == "workload-network-open"),
        "open egress with host pins must fail: {open_codes:?}"
    );
    let public_only = open.replacen("allow_hosts = [\"example.com\"]", "allow_hosts = []", 1);
    let public_codes = codes(&public_only);
    assert!(
        !public_codes
            .iter()
            .any(|code| code.starts_with("workload-network")),
        "open egress with an empty allowlist is lawful: {public_codes:?}"
    );
}

#[test]
fn every_checked_in_workload_profile_parses_and_validates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry/workloads");
    let mut seen = 0;
    for entry in std::fs::read_dir(&root).expect("registry/workloads") {
        let dir = entry.expect("entry").path();
        let path = dir.join("profile.toml");
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let id = dir.file_name().unwrap().to_string_lossy().into_owned();
        crate::schema::parse_object_toml(
            crate::RegistryKind::Workload,
            &id,
            format!("registry/workloads/{id}/profile.toml"),
            &source,
        )
        .unwrap_or_else(|error| panic!("{id}: {error:?}"));
        seen += 1;
    }
    assert!(seen > 0);
}

#[test]
fn a_declared_browser_engine_must_match_the_pods_tools_and_display() {
    let engine = |engine: &str, tools: &str| {
        VALID_PROFILE.replacen(
            "description = \"Strict workload shape.\"",
            &format!(
                "description = \"Strict workload shape.\"\nbrowser_engine = \"{engine}\"\ntools = [{tools}]"
            ),
            1,
        )
    };
    let conflict = |source: &str| {
        toml::from_str::<WorkloadProfileToml>(source)
            .unwrap()
            .browser_engine_conflict()
            .is_some()
    };
    assert!(!conflict(&engine(
        "obscura",
        "\"web.search\", \"web.read\""
    )));
    assert!(conflict(&engine("obscura", "\"web.search\"")));
    assert!(conflict(&engine(
        "obscura",
        "\"web.read\", \"browser.observe\""
    )));
    assert!(!conflict(&engine("chromium-headed", "")));
    assert!(conflict(&engine("chromium-headless", "")));
    assert!(!conflict(VALID_PROFILE));

    let parsed = |source: &str| toml::from_str::<WorkloadProfileToml>(source).unwrap();
    assert_eq!(
        parsed(&engine("obscura", "\"web.read\"")).browser_engine(),
        super::BrowserEngine::Obscura
    );
    assert_eq!(
        parsed(VALID_PROFILE).browser_engine(),
        super::BrowserEngine::ChromiumHeaded
    );
    assert_eq!(
        parsed(&VALID_PROFILE.replacen("stream = true", "stream = false", 1)).browser_engine(),
        super::BrowserEngine::ChromiumHeadless
    );
}

#[test]
fn a_launch_may_only_lower_the_declared_run_limits() {
    let declared = VALID_PROFILE.replacen(
        "[lifetime]",
        "[limits]\noutput_reserve_tokens = 65536\ncheckpoint_percent = 70\nmax_rollovers = 4\n\n[lifetime]",
        1,
    );
    let profile = toml::from_str::<WorkloadProfileToml>(&declared).unwrap();
    let launch = |limits: WorkloadLimits| profile.resolve_limits(&limits);
    let plain = launch(Default::default()).expect("no overrides");
    assert_eq!(plain.deadline_seconds, Some(5400));
    assert_eq!(plain.output_reserve_tokens, Some(65536));
    let lowered = launch(WorkloadLimits {
        deadline_seconds: Some(3600),
        max_rollovers: Some(0),
        ..Default::default()
    })
    .expect("lowered");
    assert_eq!(
        (lowered.deadline_seconds, lowered.max_rollovers),
        (Some(3600), Some(0))
    );
    let above = launch(WorkloadLimits {
        output_reserve_tokens: Some(70_000),
        ..Default::default()
    })
    .expect_err("above the declared value");
    assert!(
        above.contains(
            "limits.outputReserveTokens 70000 is above the profile's declared value 65536"
        ),
        "{above}"
    );
    let undeclared = launch(WorkloadLimits {
        tool_result_bytes: Some(1024),
        ..Default::default()
    })
    .expect_err("undeclared");
    assert!(
        undeclared.contains("limits.toolResultBytes is not declared"),
        "{undeclared}"
    );
}

#[test]
fn a_declared_run_limit_stays_within_its_bounds() {
    let limits = |body: &str| {
        codes(&VALID_PROFILE.replacen("[lifetime]", &format!("[limits]\n{body}\n\n[lifetime]"), 1))
    };
    assert!(!limits("checkpoint_percent = 100").is_empty());
    assert!(!limits("max_rollovers = 17").is_empty());
    assert!(!limits("tool_result_bytes = 0").is_empty());
    assert!(limits("checkpoint_percent = 70\nmax_rollovers = 16").is_empty());
}

/// Values (deadline, cpu, memory, limits) are tunables Sinmara edits live; only relations are
/// checked: browser tools exactly when the engine is a browser.
#[test]
fn research_profiles_keep_engine_and_tool_invariants() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry/workloads");
    let mut checked = 0;
    for entry in std::fs::read_dir(&root).expect("workloads") {
        let path = entry.expect("entry").path();
        let id = path.file_name().unwrap().to_string_lossy().into_owned();
        if !id.starts_with("research") {
            continue;
        }
        let source = std::fs::read_to_string(path.join("profile.toml")).expect(&id);
        let profile = toml::from_str::<WorkloadProfileToml>(&source).expect(&id);
        let browser_tools = profile
            .tools
            .iter()
            .any(|tool| tool.as_str().starts_with("browser."));
        assert_eq!(
            browser_tools,
            profile.browser_engine() != super::BrowserEngine::Obscura,
            "{id}"
        );
        checked += 1;
    }
    assert!(checked > 0, "the registry declares research profiles");
}

#[test]
fn shm_must_be_a_quantity_below_memory() {
    let with = |shm: &str| {
        codes(&format!(
            "{VALID_PROFILE}\n[resources]\ncpu = 2\nmemory = \"4Gi\"\nshm = \"{shm}\"\n"
        ))
    };
    assert!(!with("1Gi")
        .iter()
        .any(|code| code == "workload-resources-shm"));
    assert!(with("4Gi")
        .iter()
        .any(|code| code == "workload-resources-shm"));
    assert!(with("lots")
        .iter()
        .any(|code| code == "workload-resources-shm"));
}

#[test]
fn stop_grace_must_be_positive_and_below_the_deadline() {
    let with = |grace: u32| {
        codes(&VALID_PROFILE.replacen(
            "description = \"Strict workload shape.\"\n",
            &format!("description = \"Strict workload shape.\"\nstop_grace_seconds = {grace}\n"),
            1,
        ))
    };
    assert!(!with(180).iter().any(|code| code == "workload-stop-grace"));
    assert!(with(0).iter().any(|code| code == "workload-stop-grace"));
    assert!(with(5400).iter().any(|code| code == "workload-stop-grace"));
}

#[test]
fn data_pod_path_cannot_shadow_state_or_staging() {
    let with = |host: &str, pod: &str| {
        codes(&format!(
            "{VALID_PROFILE}\n[[data]]\nname = \"stage\"\nhost_path = \"{host}\"\npod_path = \"{pod}\"\n"
        ))
    };
    assert!(with("/srv/example/stage", "/stage")
        .iter()
        .all(|code| !code.starts_with("workload-data")));
    for pod in [
        "/state",
        "/state/cases",
        "/var/run/odin/staging",
        "/dev/shm",
        "/export",
    ] {
        assert!(
            with("/srv/example/stage", pod)
                .iter()
                .any(|code| code == "workload-data-pod-path"),
            "{pod} must be refused"
        );
    }
    for host in [
        "/home/owner",
        "/nix/store",
        "/srv/odin/export/x",
        "relative",
    ] {
        assert!(
            with(host, "/stage")
                .iter()
                .any(|code| code == "workload-data-host-path"),
            "{host} must be refused"
        );
    }
}

#[test]
fn a_steer_patch_must_match_the_control_schema() {
    let with = |patch: &str| {
        codes(&format!(
            "{VALID_PROFILE}
[control]
max_bytes = 512
[control.schema]
type = \"object\"
additionalProperties = false
properties.maxCo = {{ type = \"number\", maximum = 2 }}

[monitoring]
cadence_seconds = 30
[[monitoring.watchdogs]]
id = \"courant\"
condition = \"courant_max > 1.0\"
consecutive_hits = 4
cooldown_seconds = 600
severity = \"warning\"
slice = \"kubert-ops\"
action = \"steer\"
{patch}
"
        ))
    };
    assert!(!with("patch = { maxCo = 0.5 }")
        .iter()
        .any(|code| code.contains("steer")));
    assert!(with("patch = { maxCo = 9 }")
        .iter()
        .any(|code| code == "workload-monitoring-steer"));
    assert!(with("patch = { writeNow = true }")
        .iter()
        .any(|code| code == "workload-monitoring-steer"));
    assert!(with("")
        .iter()
        .any(|code| code == "container-watchdog-steer"));
}

#[test]
fn a_gpu_profile_must_place_on_cuda_nodes() {
    let with = |fields: &str| {
        VALID_PROFILE.replacen(
            "description = \"Strict workload shape.\"",
            &format!("description = \"Strict workload shape.\"\n{fields}"),
            1,
        )
    };
    let refused = |source: &str, code: &str| codes(source).iter().any(|found| found == code);
    assert!(refused(&with("gpu_count = 1"), "workload-gpu-placement"));
    assert!(refused(
        &with("gpu_count = 1\nplacement = [\"gpu\", \"cfd\"]"),
        "workload-gpu-placement"
    ));
    assert!(!refused(
        &with("gpu_count = 1\nplacement = [\"cuda\"]"),
        "workload-gpu-placement"
    ));
    assert!(!refused(VALID_PROFILE, "workload-gpu-placement"));

    let memory =
        with("gpu_count = 1\nplacement = [\"cuda\"]\n[gpu]\nmin_vram_gib = 8\nvram_gib = 12");
    assert!(!refused(&memory, "workload-gpu-memory"));
    let profile = toml::from_str::<WorkloadProfileToml>(&memory).unwrap();
    assert_eq!(
        profile.min_vram_gib(),
        Some(12),
        "the need raises the floor"
    );
    assert!(refused(&with("[gpu]\nvram_gib = 4"), "workload-gpu-memory"));
    assert!(refused(
        &with("gpu_count = 1\nplacement = [\"cuda\"]\n[gpu]\nvram_gib = 0"),
        "workload-gpu-memory"
    ));
}

#[test]
fn an_external_profile_cannot_hold_a_gateway_lane_or_tools() {
    let external = |fields: &str, image: &str| {
        VALID_PROFILE
            .replacen(
                "description = \"Strict workload shape.\"",
                &format!(
                    "description = \"Strict workload shape.\"\ntolerate = [\"external\"]\n{fields}"
                ),
                1,
            )
            .replacen(
                &format!("reference = \"localhost/odin-fixture@{DIGEST}\""),
                &format!("reference = \"{image}\""),
                1,
            )
    };
    let pullable = format!("registry.example.test:5050/example-openfoam@{DIGEST}");
    let refused = |source: &str, code: &str| codes(source).iter().any(|found| found == code);
    // The fixture is an agent pod with a gateway lane: never external.
    assert!(refused(&external("", &pullable), "workload-external-scope"));
    assert!(!refused(
        &external("", &pullable),
        "workload-external-image"
    ));
    assert!(refused(
        &external("", &format!("localhost/odin-fixture@{DIGEST}")),
        "workload-external-image"
    ));
    assert!(refused(
        &external("", "platform"),
        "workload-external-image"
    ));
    assert!(refused(
        &VALID_PROFILE.replacen(
            "description = \"Strict workload shape.\"",
            "description = \"Strict workload shape.\"\ntolerate = [\"gpu\"]",
            1
        ),
        "workload-tolerate"
    ));
    assert!(!refused(VALID_PROFILE, "workload-external-scope"));
    let script = format!(
        r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "External case."
harness = "script"
tolerate = ["external"]

[image]
reference = "{pullable}"

[script]
command = ["case-run"]

[seat]
seat = "worker"
project = "example"

[network]
allow_hosts = []

[state]
path = "/state"
storage = "1Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/export"

[brief]
text = "Case."

[lifetime]
deadline_seconds = 600
"#
    );
    assert!(
        !refused(&script, "workload-external-scope"),
        "{:?}",
        codes(&script)
    );
    assert!(!refused(&script, "workload-external-image"));
    assert!(refused(
        &script.replacen("[image]", "tools = [\"web.read\"]\n\n[image]", 1),
        "workload-external-scope"
    ));
}

#[test]
fn an_offload_profile_is_a_finite_script_run_naming_its_targets() {
    let offload = |fields: &str| {
        VALID_PROFILE.replacen(
            "description = \"Strict workload shape.\"",
            &format!("description = \"Strict workload shape.\"\n{fields}"),
            1,
        )
    };
    let refused = |source: &str, code: &str| codes(source).iter().any(|found| found == code);
    // The fixture is an agent pod with a gateway lane: never offloaded.
    assert!(refused(
        &offload("[offload]\ntargets = [\"hpc\"]"),
        "workload-offload-scope"
    ));
    assert!(refused(
        &offload("[offload]\ntargets = []"),
        "workload-offload-targets"
    ));
    assert!(!refused(VALID_PROFILE, "workload-offload-scope"));
}

#[test]
fn a_compute_target_refuses_only_nonsense() {
    let target = |extra: &str| {
        format!(
            r#"
schema = "odin.registry.v1"
kind = "compute-target"
enabled = true
description = "Lab box."
executor = "ssh"
ssh_host = "lab-box"
known_host = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStub"
remote_root = "/scratch/odin"
runtime = "podman"
max_concurrent = 2
poll_seconds = 60
stop_grace_seconds = 120
allowed_projects = ["example"]
{extra}"#
        )
    };
    let codes = |source: &str| {
        let object = RegistryObject {
            id: "lab".to_owned(),
            relative_config: PathBuf::from("registry/compute-targets/lab/compute-target.toml"),
            config: ObjectConfig::ComputeTarget(Box::new(
                toml::from_str(source).expect("parse compute target"),
            )),
        };
        crate::schema::validate_object(&object)
            .into_iter()
            .map(|finding| finding.code)
            .collect::<Vec<_>>()
    };
    assert!(
        codes(&target(""))
            .iter()
            .all(|code| !code.starts_with("compute-target")),
        "{:?}",
        codes(&target(""))
    );
    assert!(
        codes(&target("partition = \"gpu\"")).contains(&"compute-target-slurm-fields".to_owned())
    );
    assert!(codes(&target("control_master = \"relative/sock\""))
        .contains(&"compute-target-control-master".to_owned()));
    assert!(
        codes(&target("[cost]\nusd_per_hour = -1.0")).contains(&"compute-target-cost".to_owned())
    );
    assert!(toml::from_str::<crate::schema::ComputeTargetToml>(
        &target("").replace("max_concurrent = 2", "max_concurrent = 0")
    )
    .is_err());
    let relative = target("").replace("/scratch/odin", "scratch/odin");
    assert!(codes(&relative).contains(&"compute-target-remote-root".to_owned()));
}
