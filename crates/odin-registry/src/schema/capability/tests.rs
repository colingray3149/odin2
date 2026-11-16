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

/// A card that names its title and fields as JSON pointers on an owner card approval.
fn card_findings(preview: &str, approval_card: &str) -> Vec<String> {
    let capability = toml::from_str::<CapabilityToml>(&format!(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "fixture"
version = 1
description = "Approve one thing."
handler = {{ id = "odin_adapter.operation" }}
input_schema = "schemas/capability/fixture.approve.input.json"
output_schema = "schemas/capability/fixture.approve.output.json"
effect_class = "R1"
seat_tags = ["coordinator"]
timeout_seconds = 30
idempotency = "required"
retry = {{ max_attempts = 0 }}
approval_policy = "operator"
{preview}
approval_card = {approval_card}
evidence_extractor = {{ id = "odin_adapter.receipt" }}
"#
    ))
    .expect("approval-card capability");
    validate_object(&RegistryObject {
        id: "fixture.approve".to_owned(),
        relative_config: PathBuf::from("capabilities/fixture.approve/capability.toml"),
        config: ObjectConfig::Capability(Box::new(capability)),
    })
    .into_iter()
    .filter(|finding| finding.code == "capability-approval-card")
    .map(|finding| finding.message)
    .collect()
}

#[test]
fn an_approval_card_needs_the_card_preview_and_pointers() {
    let lawful = r#"{ title = "Run {/campaign}", fields = ["/box", "/nodes/0"] }"#;
    assert!(card_findings(r#"preview = "card""#, lawful).is_empty());
    assert_eq!(card_findings("", lawful).len(), 1);
    let nonsense = card_findings(
        r#"preview = "card""#,
        r#"{ title = "Run {campaign}", fields = ["box", "/rung"] }"#,
    );
    assert_eq!(nonsense.len(), 2, "{nonsense:?}");
    assert!(nonsense
        .iter()
        .any(|message| message.contains("\"campaign\"")));
    assert!(nonsense.iter().any(|message| message.contains("\"box\"")));
}

/// Every checked-in capability that declares an approval card validates.
#[test]
fn every_checked_in_approval_card_validates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry/capabilities");
    let mut cards = 0;
    for entry in std::fs::read_dir(&root).expect("registry/capabilities") {
        let dir = entry.expect("entry").path();
        let id = dir.file_name().unwrap().to_string_lossy().into_owned();
        let Ok(source) = std::fs::read_to_string(dir.join("capability.toml")) else {
            continue;
        };
        let object = crate::schema::parse_object_toml(
            crate::RegistryKind::Capability,
            &id,
            format!("registry/capabilities/{id}/capability.toml"),
            &source,
        )
        .unwrap_or_else(|error| panic!("{id}: {error:?}"));
        let ObjectConfig::Capability(capability) = &object.config else {
            continue;
        };
        if capability.approval_card.is_none() {
            continue;
        }
        let failing: Vec<_> = validate_object(&object)
            .into_iter()
            .filter(|finding| finding.severity == crate::FindingSeverity::Fail)
            .collect();
        assert!(failing.is_empty(), "{id}: {failing:?}");
        cards += 1;
    }
    assert!(
        cards > 0,
        "no checked-in capability declares an approval card"
    );
}
