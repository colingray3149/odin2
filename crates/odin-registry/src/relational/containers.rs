use std::collections::BTreeSet;
use std::path::Path;

use crate::schema::{
    is_handler_shell_syntax, ContainerMonitoringToml, ContainerSurfaceToml, ContainerToml,
    ContainerWatchdogToml, RegistryKind, RegistryObject,
};
use crate::RegistryFinding;

use super::context::RelationContext;
use super::paths::{normalize_relative, relation_failure, validate_regular_file};
use super::refs::{validate_ref, validate_refs, Indices};

pub(super) fn validate_container_relations(
    object: &RegistryObject,
    value: &ContainerToml,
    context: &RelationContext,
    indices: &Indices,
    findings: &mut Vec<RegistryFinding>,
) {
    validate_refs(
        object,
        "seats_offered",
        value.seats_offered.iter().map(|id| id.as_str()),
        RegistryKind::Seat,
        indices,
        findings,
    );
    if let ContainerMonitoringToml::Policy(policy) = &value.monitoring {
        validate_ref(
            object,
            "monitoring.slice",
            policy.slice.as_str(),
            RegistryKind::Slice,
            indices,
            findings,
        );
    }
    let image_scripts = value.image_executable_paths();
    for script in &value.scripts {
        if image_scripts {
            validate_image_executable_path(object, "scripts", script, findings);
        } else {
            validate_object_relative_path(object, "scripts", script, context, findings);
        }
    }
    let mut alert_ids = BTreeSet::new();
    for watchdog in &value.watchdogs {
        match watchdog {
            ContainerWatchdogToml::Script(script) => {
                if !script.is_empty() {
                    if image_scripts {
                        validate_image_executable_path(object, "watchdogs", script, findings);
                    } else {
                        validate_object_relative_path(
                            object,
                            "watchdogs",
                            script,
                            context,
                            findings,
                        );
                    }
                }
            }
            ContainerWatchdogToml::Alert(alert) => {
                if !alert_ids.insert(alert.id.as_str()) {
                    findings.push(relation_failure(
                        object,
                        format!("duplicate watchdog alert id {:?}", alert.id),
                    ));
                }
                validate_ref(
                    object,
                    "watchdogs.slice",
                    alert.slice.as_str(),
                    RegistryKind::Slice,
                    indices,
                    findings,
                );
            }
        }
    }
    let mut surface_ids = BTreeSet::new();
    for surface in &value.surface {
        let id = match surface {
            ContainerSurfaceToml::Id(id) => id,
            ContainerSurfaceToml::Definition(definition) => &definition.id,
        };
        if !surface_ids.insert(id.as_str()) {
            findings.push(relation_failure(
                object,
                format!("duplicate surface id {id:?}"),
            ));
        }
    }
}

pub(super) fn validate_alias_redirect(
    object: &RegistryObject,
    from: &str,
    to: &str,
    from_is_canonical: bool,
    to_is_canonical: bool,
    findings: &mut Vec<RegistryFinding>,
) {
    if from_is_canonical {
        findings.push(relation_failure(
            object,
            format!("tools.alias_redirect.from {from:?} shadows a canonical tools.allow entry"),
        ));
    }
    if !to_is_canonical {
        findings.push(relation_failure(
            object,
            format!("tools.alias_redirect.to {to:?} is not a canonical tools.allow entry"),
        ));
    }
}

fn validate_object_relative_path(
    object: &RegistryObject,
    field: &str,
    reference: &str,
    context: &RelationContext,
    findings: &mut Vec<RegistryFinding>,
) {
    let normalized = match normalize_relative(reference) {
        Ok(path) if !path.as_os_str().is_empty() => path,
        Ok(_) => {
            findings.push(relation_failure(
                object,
                format!("{field} contains an empty relative path"),
            ));
            return;
        }
        Err(message) => {
            findings.push(relation_failure(
                object,
                format!("{field} path {reference:?} is invalid: {message}"),
            ));
            return;
        }
    };
    let config_dir = object
        .relative_config
        .parent()
        .unwrap_or(Path::new("registry"));
    let repo_relative = config_dir.join(normalized);
    let absolute = context.odin_root.join(&repo_relative);
    validate_regular_file(object, field, &repo_relative, &absolute, context, findings);
}

/// Validate image-relative executable paths without probing files on the publishing host.
fn validate_image_executable_path(
    object: &RegistryObject,
    field: &str,
    reference: &str,
    findings: &mut Vec<RegistryFinding>,
) {
    if reference.chars().any(char::is_whitespace) {
        findings.push(relation_failure(
            object,
            format!("{field} entry {reference:?} is not a safe image executable path: whitespace would split the argv token"),
        ));
        return;
    }
    if reference.chars().any(is_handler_shell_syntax) {
        findings.push(relation_failure(
            object,
            format!("{field} entry {reference:?} is not a safe image executable path: shell syntax is never executable argv"),
        ));
        return;
    }
    match normalize_relative(reference) {
        Ok(path) if !path.as_os_str().is_empty() => {}
        Ok(_) => findings.push(relation_failure(
            object,
            format!("{field} contains an empty image executable path"),
        )),
        Err(message) => findings.push(relation_failure(
            object,
            format!("{field} entry {reference:?} is not a safe image executable path: {message}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::relational::fixtures::slice_object;
    use crate::relational::validate;
    use crate::schema::{ContainerToml, HostToml, NodeToml, ObjectConfig, RegistryObject};

    use super::*;

    #[test]
    fn alias_redirects_require_a_distinct_canonical_allow_target() {
        let object = slice_object(true);
        let mut findings = Vec::new();
        validate_alias_redirect(
            &object,
            "canonical.tool",
            "stale.tool",
            true,
            false,
            &mut findings,
        );
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(RegistryFinding::is_failure));
    }

    #[test]
    fn structured_watchdog_and_surface_relations_are_enforced() {
        let container: ContainerToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "fixture"
purpose = "test"
base = "local-process"
seats_offered = []
scripts = []
watchdogs = [
    "scripts/relative.sh",
    { id = "cpu-hot", condition = "load > 8", consecutive_hits = 3, cooldown_seconds = 300, severity = "warning", slice = "missing.slice" },
    { id = "cpu-hot", condition = "load > 9", consecutive_hits = 2, cooldown_seconds = 60, severity = "error", slice = "fixture" },
]
identity_fields = ["purpose"]
tunables = {}
surface = ["stdout", { id = "stdout", kind = "log", source = "handle:logs", media_type = "text/plain", refresh_seconds = 0 }]
monitoring = "none"
[contents]
kind = "scripts"
"#,
        )
        .expect("parse container fixture");
        let container_object = RegistryObject {
            id: "fixture-container".to_owned(),
            relative_config: PathBuf::from("registry/containers/fixture-container/container.toml"),
            config: ObjectConfig::Container(Box::new(container)),
        };
        let findings = validate(
            &[container_object, slice_object(true)],
            &RelationContext::new("/nonexistent/odin-relation-fixture"),
        );
        for expected in [
            "duplicate watchdog alert id \"cpu-hot\"",
            "duplicate surface id \"stdout\"",
            "watchdogs.slice references missing slice \"missing.slice\"",
        ] {
            assert!(
                findings.iter().any(|finding| finding.message == expected),
                "missing finding: {expected}"
            );
        }
        assert!(!findings.iter().any(|finding| {
            finding.message == "watchdogs.slice references missing slice \"fixture\""
        }));
        assert!(findings.iter().any(|finding| {
            finding.message.starts_with(
                "watchdogs reference registry/containers/fixture-container/scripts/relative.sh cannot be resolved:",
            )
        }));
    }

    #[test]
    fn image_scripts_are_image_paths_and_local_scripts_stay_local() {
        fn container_object(base: &str, scripts: &str, watchdogs: &str) -> RegistryObject {
            let container: ContainerToml = toml::from_str(&format!(
                r#"
schema = "odin.registry.v1"
kind = "container"
enabled = true
description = "fixture"
purpose = "test"
base = "{base}"
seats_offered = []
scripts = [{scripts}]
watchdogs = [{watchdogs}]
identity_fields = ["purpose"]
tunables = {{}}
surface = []
monitoring = "none"
[contents]
kind = "scripts"
"#
            ))
            .expect("parse container fixture");
            RegistryObject {
                id: "fixture-container".to_owned(),
                relative_config: PathBuf::from(
                    "registry/containers/fixture-container/container.toml",
                ),
                config: ObjectConfig::Container(Box::new(container)),
            }
        }
        // Full `validate` enforces registry-wide invariants (schema catalog,
        // node authority) before any per-object relation, so the fixture root
        // is a real tempdir carrying the schemas directory plus exactly one
        // enabled authority node on an enabled, enrolled host.
        fn fixture_registry(container: RegistryObject) -> Vec<RegistryObject> {
            let host: HostToml = toml::from_str(
                r#"
schema = "odin.registry.v1"
kind = "host"
enabled = true
description = "fixture"
hardware = "fixture"
role = "control"
tailscale = "fixture-host"
enrolled = true
"#,
            )
            .expect("parse host fixture");
            let node: NodeToml = toml::from_str(
                r#"
schema = "odin.registry.v1"
kind = "node"
enabled = true
description = "fixture"
host = "fixture-host"
role = "control"
capabilities = []
allow_workloads = false
authoritative_state = true
"#,
            )
            .expect("parse node fixture");
            vec![
                RegistryObject {
                    id: "fixture-host".to_owned(),
                    relative_config: PathBuf::from("registry/hosts/fixture-host/host.toml"),
                    config: ObjectConfig::Host(Box::new(host)),
                },
                RegistryObject {
                    id: "fixture-node".to_owned(),
                    relative_config: PathBuf::from("registry/nodes/fixture-node/node.toml"),
                    config: ObjectConfig::Node(Box::new(node)),
                },
                container,
            ]
        }
        /// Typed rejection check: counts `registry-broken-relation` failures
        /// located at the container's own config, one per invalid reference.
        fn broken_relation_failures(findings: &[RegistryFinding]) -> usize {
            findings
                .iter()
                .filter(|finding| {
                    finding.code == "registry-broken-relation"
                        && finding.path
                            == Path::new("registry/containers/fixture-container/container.toml")
                        && finding.is_failure()
                })
                .count()
        }
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "odin-registry-image-script-fixture-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("schemas")).unwrap();
        let context = RelationContext::new(&root);

        // Image execution: no host file exists at the referenced paths, and
        // none may be required — the paths live inside the declared image.
        let image = container_object(
            "docker.io/library/alpine:3.22",
            "\"bin/true\"",
            "\"scripts/relative.sh\"",
        );
        let findings = validate(&fixture_registry(image), &context);
        assert!(
            findings.is_empty(),
            "image profile must validate without host files: {findings:?}"
        );

        // The identical declaration on a process base keeps local authority:
        // both entries fail closed as missing registry files.
        let local = container_object("local-process", "\"bin/true\"", "\"scripts/relative.sh\"");
        let findings = validate(&fixture_registry(local), &context);
        assert_eq!(
            broken_relation_failures(&findings),
            2,
            "scripts and watchdogs entries must fail closed: {findings:?}"
        );

        // A valid image base never whitewashes malformed executable paths.
        for script in [
            "\"\"",
            "\"../escape\"",
            "\"/abs/true\"",
            "\"bin/$true\"",
            "\"bin/a;b\"",
            "\"bin/a b\"",
        ] {
            let evasion = container_object("docker.io/library/alpine:3.22", script, "\"\"");
            let findings = validate(&fixture_registry(evasion), &context);
            assert_eq!(
                broken_relation_failures(&findings),
                1,
                "script {script} must fail image path validation: {findings:?}"
            );
        }

        // A malformed base never evades local validation: the scripts fall
        // back to the strict local file check and fail closed.
        for base in [
            "alpine",
            "docker.io/library/alpine",
            "native-process",
            "/usr/bin/env",
        ] {
            let evasion = container_object(base, "\"bin/true\"", "\"\"");
            let findings = validate(&fixture_registry(evasion), &context);
            assert_eq!(
                broken_relation_failures(&findings),
                1,
                "base {base} must fail closed: {findings:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
