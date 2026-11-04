//! Workload schema validation: strict fields, pinned images, confined paths and hosts, and typed lookup.

use std::path::PathBuf;

use super::{ObjectConfig, RegistryObject, WorkloadProfileToml, WORKLOAD_BRIEF_MAX_BYTES};

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
