//! Workload schema validation: strict fields, pinned images, confined paths and hosts, and typed lookup.

use std::path::PathBuf;

use super::{
    compose_workload_profile, compose_workload_profiles, valid_allow_host, valid_pod_path,
    valid_screen, ObjectConfig, RegistryObject, WorkloadProfileLookupError, WorkloadProfileToml,
    MAX_WORKLOAD_DEADLINE_SECONDS, MIN_WORKLOAD_DEADLINE_SECONDS, WORKLOAD_BRIEF_MAX_BYTES,
};

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
fn unknown_fields_are_rejected_in_every_table() {
    for source in [
        "unknown = true",
        "[image]\nbogus = 1",
        "[runtime]\nbogus = 1",
        "[seat]\nbogus = 1",
        "[network]\nbogus = 1",
        "[display]\nbogus = 1",
        "[state]\nbogus = 1",
        "[export]\nbogus = 1",
        "[brief]\nbogus = 1",
        "[memory]\nbogus = 1",
        "[lifetime]\nbogus = 1",
    ] {
        let attempt = format!("{VALID_PROFILE}\n{source}\n");
        assert!(
            toml::from_str::<WorkloadProfileToml>(&attempt).is_err(),
            "workload profile accepted an unknown field: {source}"
        );
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

/// A job never runs unbounded by omission: it declares a lifetime inside the
/// workload launch window. A service runs until stopped and declares none.
#[test]
fn the_run_lifetime_is_required_and_bounded() {
    let without = VALID_PROFILE.replace("[lifetime]\ndeadline_seconds = 5400\n", "");
    assert!(
        codes(&without)
            .iter()
            .any(|code| code == "workload-lifetime-deadline"),
        "a job without a lifetime is refused"
    );
    let service = without.replacen("description =", "mode = \"service\"\ndescription =", 1);
    assert!(
        !codes(&service)
            .iter()
            .any(|code| code == "workload-lifetime-deadline"),
        "a service declares no lifetime: {:?}",
        codes(&service)
    );
    let bounded_service =
        VALID_PROFILE.replacen("description =", "mode = \"service\"\ndescription =", 1);
    assert!(codes(&bounded_service)
        .iter()
        .any(|code| code == "workload-lifetime-deadline"));
    for (deadline, lawful) in [
        (MIN_WORKLOAD_DEADLINE_SECONDS - 1, false),
        (MIN_WORKLOAD_DEADLINE_SECONDS, true),
        (5400, true),
        (MAX_WORKLOAD_DEADLINE_SECONDS, true),
        (MAX_WORKLOAD_DEADLINE_SECONDS + 1, false),
    ] {
        let source = VALID_PROFILE.replace(
            "deadline_seconds = 5400",
            &format!("deadline_seconds = {deadline}"),
        );
        let refused = codes(&source)
            .iter()
            .any(|code| code == "workload-lifetime-deadline");
        assert_eq!(refused, !lawful, "deadline {deadline}s");
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
fn allow_hosts_must_be_unique_bare_hostnames() {
    let duplicated = VALID_PROFILE.replacen(
        "allow_hosts = [\"example.com\"]",
        "allow_hosts = [\"example.com\", \"example.com\"]",
        1,
    );
    let duplicated_codes = codes(&duplicated);
    assert!(
        duplicated_codes
            .iter()
            .any(|code| code == "registry-duplicate-value"),
        "duplicate allow hosts must fail: {duplicated_codes:?}"
    );
    let empty = VALID_PROFILE.replacen("allow_hosts = [\"example.com\"]", "allow_hosts = []", 1);
    // Empty site egress permits DNS only.
    let empty_codes = codes(&empty);
    assert!(
        !empty_codes
            .iter()
            .any(|code| code.starts_with("workload-network")),
        "an empty allowlist is lawful: {empty_codes:?}"
    );
    assert!(valid_allow_host("allowed.example.org"));
    assert!(!valid_allow_host("*.wild.example"));
    assert!(!valid_allow_host("example.com:443"));
}

#[test]
fn state_and_export_mount_points_must_be_distinct() {
    let colliding = VALID_PROFILE.replacen("pod_path = \"/export\"", "pod_path = \"/state\"", 1);
    let colliding_codes = codes(&colliding);
    assert!(
        colliding_codes
            .iter()
            .any(|code| code == "workload-volume-collision"),
        "state and export must not share a mount point: {colliding_codes:?}"
    );
    let nesting =
        VALID_PROFILE.replacen("pod_path = \"/export\"", "pod_path = \"/state/screens\"", 1);
    let nesting_codes = codes(&nesting);
    assert!(
        nesting_codes
            .iter()
            .any(|code| code == "workload-volume-collision"),
        "an export nested inside the state volume must fail: {nesting_codes:?}"
    );
}

#[test]
fn composed_lookup_resolves_enabled_profiles_and_types_the_rest() {
    let objects = [
        enabled_object(VALID_PROFILE),
        object("sleeping", false, VALID_PROFILE),
    ];
    let composed = compose_workload_profiles(&objects);
    assert_eq!(composed.len(), 1, "disabled profiles never compose");
    assert_eq!(composed[0].id, "shape-fixture");
    // A declared-but-disabled profile is a typed refusal, never a silent
    // skip: the runtime can never mistake it for a runnable pod.
    assert_eq!(
        compose_workload_profile(&objects, "sleeping"),
        Err(WorkloadProfileLookupError::Disabled {
            id: "sleeping".to_owned()
        })
    );
    assert_eq!(
        compose_workload_profile(&objects, "ghost"),
        Err(WorkloadProfileLookupError::Unknown {
            id: "ghost".to_owned()
        })
    );
}

#[test]
fn gateway_lane_must_be_a_stable_id() {
    let malformed = VALID_PROFILE.replacen(
        "gateway_lane = \"fixture.gateway\"",
        "gateway_lane = \"zai glm\"",
        1,
    );
    let codes = codes(&malformed);
    assert!(
        codes.iter().any(|code| code == "workload-gateway-lane"),
        "a malformed gateway lane must fail the stable-id law: {codes:?}"
    );
}

#[test]
fn pod_path_predicate_rejects_escapes_and_relative_forms() {
    assert!(valid_pod_path("/state"));
    assert!(valid_pod_path("/odin/bin/omp"));
    assert!(!valid_pod_path("state"));
    assert!(!valid_pod_path("/"));
    assert!(!valid_pod_path("/a/../b"));
    assert!(!valid_pod_path("/a//b"));
    assert!(valid_screen("1280x800x24"));
    assert!(valid_screen("8192x8192x32"));
    assert!(!valid_screen("1280x800"));
    assert!(!valid_screen("0x0x0"));
    assert!(!valid_screen("8193x800x24"));
    assert!(!valid_screen("1280x800x33"));
    assert!(!valid_screen("99999999999999x800x24"));
}

#[test]
fn a_script_pod_declares_its_command_and_no_agent_sections() {
    let script = format!(
        r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "GPU smoke"
harness = "script"
gpu_count = 1
placement = ["cuda"]

[image]
reference = "nvcr.io/nvidia/k8s/cuda-sample:vectoradd@{DIGEST}"

[script]
command = ["/cuda-samples/vectorAdd"]

[seat]
seat = "kubert"
project = "odin"

[network]
allow_hosts = ["example.com"]

[state]
path = "/state"
storage = "1Gi"

[export]
pod_path = "/export"
host_folder = "/srv/odin/export"

[brief]
text = "Run the CUDA sample."

[lifetime]
deadline_seconds = 600
"#
    );
    assert_eq!(codes(&script), Vec::<String>::new());
    let no_command = script.replace("[script]\ncommand = [\"/cuda-samples/vectorAdd\"]\n", "");
    assert!(codes(&no_command)
        .iter()
        .any(|code| code == "workload-script-command"));
    let bad_placement = script.replace(r#"placement = ["cuda"]"#, r#"placement = ["CUDA box"]"#);
    assert!(codes(&bad_placement)
        .iter()
        .any(|code| code == "workload-placement"));
    // The agent default still requires its agent half.
    let agent = script.replace("harness = \"script\"\n", "");
    let refused = codes(&agent);
    for code in [
        "workload-script-command",
        "workload-gateway-lane",
        "workload-runtime-path",
        "workload-memory-namespace",
    ] {
        assert!(
            refused.iter().any(|found| found == code),
            "{code}: {refused:?}"
        );
    }
}

/// Simulation settings validate renderer IDs and unknown fields; omission preserves canonical bytes.
#[test]
fn a_simulation_section_marks_a_mission_and_defaults_away() {
    let plain: WorkloadProfileToml = toml::from_str(VALID_PROFILE).expect("plain profile");
    assert!(plain.simulation.is_none());
    let canonical = serde_json::to_string(&plain).expect("canonical");
    assert!(!canonical.contains("simulation"), "{canonical}");

    let declared = format!("{VALID_PROFILE}\n[simulation]\nrenderers = [\"field_svg-v1\"]\n");
    let profile: WorkloadProfileToml = toml::from_str(&declared).expect("simulation profile");
    let simulation = profile.simulation.expect("the section parses");
    assert_eq!(simulation.renderers[0].as_str(), "field_svg-v1");
    let bare: WorkloadProfileToml =
        toml::from_str(&format!("{VALID_PROFILE}\n[simulation]\n")).expect("empty section");
    assert_eq!(bare.simulation, Some(Default::default()));

    for bad in [
        "[simulation]\nbogus = 1\n",
        "[simulation]\nrenderers = [\"has space\"]\n",
    ] {
        assert!(
            toml::from_str::<WorkloadProfileToml>(&format!("{VALID_PROFILE}\n{bad}")).is_err(),
            "accepted {bad}"
        );
    }
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
