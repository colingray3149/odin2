use std::collections::BTreeSet;
use std::num::NonZeroU16;
use std::path::PathBuf;

use odin_domain::SliceId;

use crate::schema::{
    parse_object_toml, validate_object, AlertCondition, ContainerAlertActionToml,
    ContainerAlertSeverityToml, ContainerAlertToml, ContainerSurfaceDefinitionToml,
    ContainerSurfaceKindToml, ContainerSurfaceToml, ContainerToml, ContainerWatchdogToml,
    ObjectConfig, RegistryKind, RegistryObject,
};

#[test]
fn tunables_reject_floats_and_nested_values() {
    let base = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Container shape."
purpose = "worker"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = []
identity_fields = ["purpose", "base", "contents.kind"]
surface = ["status"]
contents = { kind = "scripts" }
monitoring = "none"
"#;
    for tunables in ["tunables = { cycles = 1.5 }", "tunables = { cycles = [1] }"] {
        assert!(toml::from_str::<ContainerToml>(&format!("{base}{tunables}\n")).is_err());
    }
}

fn container_with(field: &str, element: &str) -> RegistryObject {
    let (watchdogs, surface) = match field {
        "watchdogs" => (element, ""),
        "surface" => ("", element),
        other => panic!("unsupported container field {other}"),
    };
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Container shape fixture."
purpose = "worker"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = [{watchdogs}]
identity_fields = ["purpose"]
tunables = {{}}
surface = [{surface}]
contents = {{ kind = "scripts" }}
monitoring = "none"
"#
    );
    RegistryObject {
        id: "shape-fixture".to_owned(),
        relative_config: PathBuf::from("registry/containers/shape-fixture/container.toml"),
        config: ObjectConfig::Container(Box::new(
            toml::from_str(&source).expect("parse container shape fixture"),
        )),
    }
}

#[test]
fn legacy_string_watchdog_and_surface_elements_remain_accepted() {
    let source = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Old wire form."
purpose = "worker"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = ["scripts/watch.sh"]
identity_fields = ["purpose"]
tunables = {}
surface = ["stdout"]
contents = { kind = "scripts" }
monitoring = "none"
"#;
    let container: ContainerToml = toml::from_str(source).expect("parse legacy container wire");
    assert_eq!(
        container.watchdogs,
        BTreeSet::from([ContainerWatchdogToml::Script("scripts/watch.sh".to_owned())])
    );
    assert_eq!(
        container.surface,
        BTreeSet::from([ContainerSurfaceToml::Id("stdout".to_owned())])
    );
    let serialized = toml::to_string(&container).expect("serialize legacy container wire");
    let reparsed: ContainerToml =
        toml::from_str(&serialized).expect("reparse legacy container wire");
    assert_eq!(reparsed, container);

    let object = parse_object_toml(
        RegistryKind::Container,
        "legacy-wire",
        PathBuf::from("registry/containers/legacy-wire/container.toml"),
        source,
    )
    .expect("source parser accepts legacy container wire");
    assert_eq!(object.config, ObjectConfig::Container(Box::new(container)));
    assert!(validate_object(&object).is_empty());
}

#[test]
fn image_executable_paths_requires_versioned_qualified_image_base() {
    fn container(base: &str, contents_kind: &str) -> ContainerToml {
        toml::from_str(&format!(
            r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "fixture"
purpose = "worker"
base = "{base}"
seats_offered = []
scripts = ["bin/true"]
watchdogs = []
identity_fields = ["purpose"]
tunables = {{}}
surface = []
contents = {{ kind = "{contents_kind}" }}
monitoring = "none"
"#
        ))
        .expect("parse container fixture")
    }
    let digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // The committed publisher profiles classify as image execution.
    assert!(container("docker.io/library/alpine:3.22", "scripts").image_executable_paths());
    assert!(
        container("registry.example.com:5000/team/sub/repo:1.2.3", "scripts")
            .image_executable_paths()
    );
    assert!(container("localhost/sweep:nightly", "scripts").image_executable_paths());
    // A digest alone pins the version; tag plus digest stays image execution.
    assert!(container(&format!("ghcr.io/odin/sweep@{digest}"), "scripts").image_executable_paths());
    assert!(container(
        &format!("docker.io/library/alpine:3.22@{digest}"),
        "scripts"
    )
    .image_executable_paths());

    // Process bases, unversioned and malformed references stay local.
    for base in [
        "local-process",
        "native-process",
        "alpine",
        "docker.io/library/alpine",
        "library/alpine:3.22",
        "/usr/bin/env",
        "../alpine:3.22",
        "docker.io/../etc:3.22",
        "docker.io/library/alpine:3.2$",
        "docker.io/library/alpine :3.22",
        "docker.io/library/alpine@sha256:012345",
    ] {
        assert!(
            !container(base, "scripts").image_executable_paths(),
            "base {base:?} must not classify as image execution"
        );
    }

    // The contents kind gates the classification: an image base with
    // non-scripts contents is not a set of image executables.
    assert!(!container("docker.io/library/alpine:3.22", "odin_env").image_executable_paths());
    assert!(!container("docker.io/library/alpine:3.22", "adapter").image_executable_paths());
}

#[test]
fn structured_alert_and_surface_definitions_are_lossless_and_valid() {
    let container: ContainerToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Structured elements."
purpose = "worker"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = [
    "scripts/watch.sh",
    { id = "cpu-hot", condition = "load > 8", consecutive_hits = 3, cooldown_seconds = 300, severity = "warning", slice = "example-watch" },
]
identity_fields = ["purpose"]
tunables = {}
surface = [
    "stdout",
    { id = "events", kind = "file", source = "handle:events", media_type = "application/json", refresh_seconds = 60 },
    { id = "metrics", kind = "metric", source = "handle:metrics", media_type = "application/json", refresh_seconds = 0, renderer = "grafana" },
]
contents = { kind = "scripts" }
monitoring = "none"
"#,
        )
        .expect("parse structured container wire");
    assert!(container
        .watchdogs
        .contains(&ContainerWatchdogToml::Alert(ContainerAlertToml {
            id: "cpu-hot".to_owned(),
            condition: "load > 8".to_owned(),
            consecutive_hits: NonZeroU16::new(3).expect("nonzero fixture"),
            cooldown_seconds: 300,
            severity: ContainerAlertSeverityToml::Warning,
            slice: SliceId::new("example-watch").expect("valid slice fixture"),
            action: ContainerAlertActionToml::Notify,
        })));
    assert!(container
        .surface
        .contains(&ContainerSurfaceToml::Definition(
            ContainerSurfaceDefinitionToml {
                id: "events".to_owned(),
                kind: ContainerSurfaceKindToml::File,
                source: "handle:events".to_owned(),
                media_type: "application/json".to_owned(),
                refresh_seconds: 60,
                renderer: None,
            }
        )));
    assert!(container
        .surface
        .contains(&ContainerSurfaceToml::Definition(
            ContainerSurfaceDefinitionToml {
                id: "metrics".to_owned(),
                kind: ContainerSurfaceKindToml::Metric,
                source: "handle:metrics".to_owned(),
                media_type: "application/json".to_owned(),
                refresh_seconds: 0,
                renderer: Some("grafana".to_owned()),
            }
        )));
    let serialized =
        toml::Value::try_from(&container).expect("serialize structured container into TOML value");
    let reparsed: ContainerToml = serialized
        .try_into()
        .expect("reparse structured container from TOML value");
    assert_eq!(reparsed, container);

    let object = RegistryObject {
        id: "structured-wire".to_owned(),
        relative_config: PathBuf::from("registry/containers/structured-wire/container.toml"),
        config: ObjectConfig::Container(Box::new(container)),
    };
    assert!(validate_object(&object).is_empty());
}

#[test]
fn structured_elements_enforce_shape_constraints() {
    let cases = [
        (
            "watchdogs",
            r#"{ id = "CPU HOT", condition = "load > 8", consecutive_hits = 1, cooldown_seconds = 0, severity = "info", slice = "example-watch" }"#,
            "container-watchdog-id",
        ),
        (
            "watchdogs",
            r#"{ id = "cpu-hot", condition = "load > 8", consecutive_hits = 1001, cooldown_seconds = 0, severity = "info", slice = "example-watch" }"#,
            "container-watchdog-range",
        ),
        (
            "watchdogs",
            r#"{ id = "cpu-hot", condition = "load > 8", consecutive_hits = 1, cooldown_seconds = 86401, severity = "info", slice = "example-watch" }"#,
            "container-watchdog-range",
        ),
        (
            "surface",
            r#"{ id = "metrics", kind = "metric", source = "handle:metrics", media_type = "not-a-media-type", refresh_seconds = 0 }"#,
            "container-surface-media-type",
        ),
        (
            "surface",
            r#"{ id = "metrics", kind = "metric", source = "handle:metrics", media_type = "application/json", refresh_seconds = 86401 }"#,
            "container-surface-range",
        ),
        (
            "surface",
            r#"{ id = "metrics", kind = "metric", source = "handle:metrics", media_type = "application/json", refresh_seconds = 0, renderer = "_bad" }"#,
            "container-surface-renderer",
        ),
        ("surface", r#""bad id""#, "container-surface-id"),
    ];
    for (field, element, expected_code) in cases {
        let object = container_with(field, element);
        assert!(
            validate_object(&object)
                .iter()
                .any(|finding| finding.code == expected_code),
            "missing {expected_code} for {field} = {element}"
        );
    }
}

#[test]
fn duplicate_identity_fields_are_rejected_before_set_loss() {
    let source = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Duplicate identity declaration."
purpose = "worker"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = []
identity_fields = ["purpose", "base", "purpose"]
tunables = {}
surface = []
contents = { kind = "scripts" }
monitoring = "none"
"#;
    assert!(
        toml::from_str::<ContainerToml>(source).is_ok(),
        "typed set should demonstrate why a raw precheck is required"
    );
    let finding = parse_object_toml(
        RegistryKind::Container,
        "duplicate-identity",
        PathBuf::from("registry/containers/duplicate-identity/container.toml"),
        source,
    )
    .expect_err("raw duplicate identity path must be rejected");
    assert_eq!(finding.code, "container-identity-duplicate");
    assert!(finding.message.contains("\"purpose\""));

    let invalid_source = source
        .replace(
            "identity_fields = [\"purpose\", \"base\", \"purpose\"]",
            "identity_fields = [\"tunables.cycles\", \"missing\"]",
        )
        .replace("tunables = {}", "tunables = { cycles = 1 }");
    let object = parse_object_toml(
        RegistryKind::Container,
        "invalid-identity",
        PathBuf::from("registry/containers/invalid-identity/container.toml"),
        &invalid_source,
    )
    .expect("parse non-duplicate invalid identity fixture");
    let findings = validate_object(&object);
    assert!(findings
        .iter()
        .any(|finding| finding.code == "container-identity-tunable"));
    assert!(findings
        .iter()
        .any(|finding| finding.code == "container-identity-path"));
}

#[test]
fn container_gpu_and_deadline_declarations_carry_their_bounds() {
    let base = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Bounded GPU smoke fixture."
purpose = "gpu-smoke-fixture"
base = "nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda12.5.0-ubuntu22.04"
seats_offered = ["kubert"]
scripts = ["cuda-samples/sample"]
watchdogs = []
identity_fields = ["base", "gpu_count", "deadline_seconds", "purpose", "scripts"]
tunables = {}
surface = []
gpu_count = {gpu}
deadline_seconds = {deadline}
contents = { kind = "scripts" }
monitoring = "none"
"#;

    let admitted = base.replace("{gpu}", "1").replace("{deadline}", "300");
    let object = parse_object_toml(
        RegistryKind::Container,
        "gpu-smoke-fixture",
        PathBuf::from("registry/containers/gpu-smoke-fixture/container.toml"),
        &admitted,
    )
    .expect("a bounded GPU profile parses");
    let findings = validate_object(&object);
    assert!(
        findings.is_empty(),
        "one GPU for 300s is inside the declared bounds: {findings:?}"
    );

    for (gpu, deadline, code) in [
        ("9", "300", "container-gpu-count"),
        ("1", "5", "container-deadline-seconds"),
        ("1", "7200", "container-deadline-seconds"),
    ] {
        let rejected = base.replace("{gpu}", gpu).replace("{deadline}", deadline);
        let object = parse_object_toml(
            RegistryKind::Container,
            "gpu-smoke-fixture",
            PathBuf::from("registry/containers/gpu-smoke-fixture/container.toml"),
            &rejected,
        )
        .expect("out-of-bounds declarations still parse; validation decides");
        let findings = validate_object(&object);
        assert!(
            findings.iter().any(|finding| finding.code == code),
            "gpu={gpu} deadline={deadline} must fail {code}: {findings:?}"
        );
    }
}

#[test]
fn gpu_free_profiles_serialize_byte_identically_to_the_pre_gpu_publication() {
    let source = r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "Historical GPU-free profile."
purpose = "kubert-job"
base = "docker.io/library/alpine:3.22"
seats_offered = ["kubert"]
scripts = ["bin/true"]
watchdogs = []
identity_fields = ["base", "contents.kind", "monitoring.slice", "purpose", "scripts"]
tunables = {}
surface = ["stdout"]
contents = { kind = "scripts" }
monitoring = { slice = "architect-engine", cadence_seconds = 30 }
"#;
    let container: ContainerToml = toml::from_str(source).expect("historical profile parses");
    let serialized = toml::to_string(&container).expect("serialize");
    assert!(
        !serialized.contains("gpu_count"),
        "a GPU-free profile must not grow new keys: {serialized}"
    );
    assert!(
        !serialized.contains("deadline_seconds"),
        "an undeclared deadline must stay absent: {serialized}"
    );
    // The hash the snapshot chain pins is computed over this exact
    // serialization: a reparsed GPU-free profile must be a fixed point.
    let reparsed: ContainerToml = toml::from_str(&serialized).expect("round trip");
    assert_eq!(
        toml::to_string(&reparsed).expect("re-serialize"),
        serialized
    );
}

/// The monitoring kernel's condition grammar is strict at publish time:
/// `<counter> <op> <number>` over reported counters, nothing else.
#[test]
fn alert_conditions_parse_strictly_and_evaluate_in_code() {
    let dislikes = AlertCondition::parse("dislikes >= 100").expect("grammar");
    assert!(dislikes.holds(100.0) && !dislikes.holds(99.0));
    assert!(AlertCondition::parse("likes == 0").unwrap().holds(0.0));
    assert!(AlertCondition::parse("errors > 3").unwrap().holds(4.0));
    for bad in [
        "load>8",
        "Load > 8",
        "load ~ 8",
        "load > eight",
        "load > inf",
        "rm -rf /",
    ] {
        assert!(AlertCondition::parse(bad).is_err(), "{bad} must be refused");
    }
}
