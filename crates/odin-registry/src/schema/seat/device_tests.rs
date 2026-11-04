//! Device action executable and endpoint boundaries.

use std::path::PathBuf;

use super::super::{ObjectConfig, RegistryObject};
use crate::schema::{has_failures, validate_object};

fn project(source: &str) -> RegistryObject {
    RegistryObject {
        id: "fixture".to_owned(),
        relative_config: PathBuf::from("projects/fixture/project.toml"),
        config: ObjectConfig::Project(Box::new(toml::from_str(source).expect("project fixture"))),
    }
}

const PROJECT: &str = r#"
schema = "odin.registry.v1"
kind = "project"
enabled = true
description = "Device action fixture"
source_root = "/work"
default_seat = "builder"
memory_namespaces = []
artifact_policy = "standard"
[sphere]
scratch = "/scratch/project"
[[sphere.devices]]
name = "serial"
node = "/dev/serial/by-id/fixture"
[[sphere.devices.actions]]
name = "flash"
argv = ["{runtime.flipper}", "{node}", "{image}"]
[sphere.devices.actions.params]
image = "path"
"#;

#[test]
fn runtime_executable_binding_must_be_a_whole_valid_first_token() {
    for replacement in [
        "{runtime.}",
        "{runtime../flipper}",
        "{runtime.flipper}/extra",
    ] {
        let source = PROJECT.replace("{runtime.flipper}", replacement);
        assert!(
            has_failures(&validate_object(&project(&source))),
            "{replacement}"
        );
    }
    let source = PROJECT.replace("\"{node}\"", "\"{runtime.flipper}\"");
    assert!(has_failures(&validate_object(&project(&source))));
}

#[test]
fn a_serial_node_and_an_api_together_are_rejected() {
    let source = PROJECT.replace(
        "node = \"/dev/serial/by-id/fixture\"",
        "node = \"/dev/serial/by-id/fixture\"\napi = \"http://127.0.0.1:9\"",
    );
    assert!(has_failures(&validate_object(&project(&source))));
}
