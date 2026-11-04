use std::path::PathBuf;

use crate::schema::{validate_object, CapabilityToml, ObjectConfig, RegistryObject};

#[test]
fn enabled_unimplemented_capability_never_enters_a_listing() {
    let capability = toml::from_str::<CapabilityToml>(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "unimplemented"
version = 1
description = "Invalid enabled reservation."
effect_class = "R3"
seat_tags = []
timeout_seconds = 1
idempotency = "required"
retry = { max_attempts = 0 }
approval_policy = "operator"
"#,
    )
    .unwrap();
    let object = RegistryObject {
        id: "reserved".to_owned(),
        relative_config: PathBuf::from("capabilities/reserved/capability.toml"),
        config: ObjectConfig::Capability(Box::new(capability)),
    };
    assert!(!object.enters_listing());
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "capability-enabled-unimplemented"));
}

#[test]
fn plan_preview_requires_a_workflow() {
    let declared = |implementation: &str| {
        let capability = toml::from_str::<CapabilityToml>(&format!(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "{implementation}"
version = 1
description = "Submit one file."
handler = {{ id = "odin_workflow.run" }}
input_schema = "schemas/capability/fixture.input.json"
output_schema = "schemas/capability/fixture.output.json"
effect_class = "R3"
seat_tags = ["coordinator"]
timeout_seconds = 60
idempotency = "required"
retry = {{ max_attempts = 0 }}
approval_policy = "operator"
preview = "plan"
evidence_extractor = {{ id = "odin_workflow.receipt" }}
"#
        ))
        .expect("plan-preview capability");
        validate_object(&RegistryObject {
            id: "fixture.submit".to_owned(),
            relative_config: PathBuf::from("capabilities/fixture.submit/capability.toml"),
            config: ObjectConfig::Capability(Box::new(capability)),
        })
    };
    assert!(!declared("workflow")
        .iter()
        .any(|finding| finding.code == "capability-plan-preview"));
    assert!(declared("builtin")
        .iter()
        .any(|finding| finding.code == "capability-plan-preview"));
}

#[test]
fn an_untested_capability_is_flagged_and_a_malformed_or_repeated_test_is_refused() {
    const DECLARATION: &str = r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "A tool."
handler = { id = "example.handle" }
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { id = "example.extract" }
"#;
    let findings = |extra: &str| {
        let capability: CapabilityToml =
            toml::from_str(&format!("{DECLARATION}{extra}")).expect("capability parses");
        validate_object(&RegistryObject {
            id: "example".to_owned(),
            relative_config: PathBuf::from("registry/capabilities/example/capability.toml"),
            config: ObjectConfig::Capability(Box::new(capability)),
        })
    };
    let untested = findings("");
    assert_eq!(untested.len(), 1, "{untested:?}");
    assert_eq!(untested[0].code, "capability-untested");
    assert!(
        !untested[0].is_failure(),
        "an untested capability is flagged, not refused"
    );

    assert!(findings("tests = [\"odin-cli odind::features::tests::a_test\"]").is_empty());
    for refused in [
        "tests = [\"odin-cli\"]",
        "tests = [\"odin-cli a::b extra\"]",
        "tests = [\"odin-cli a::b\", \"odin-cli a::b\"]",
        "tests = [\"odin-cli a::b\"]\nprobes = [\"decl:capability/x\"]",
    ] {
        assert!(
            findings(refused).iter().any(|finding| finding.is_failure()),
            "{refused}"
        );
    }
}
