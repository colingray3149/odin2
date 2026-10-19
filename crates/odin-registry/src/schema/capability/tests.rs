use std::path::PathBuf;

use crate::schema::{
    validate_object, BuiltinHandlerToml, CapabilityToml, ExecHandlerToml, HandlerBindingToml,
    ObjectConfig, RegistryObject,
};

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
fn structured_handlers_round_trip_exact_keys_and_argv() {
    let builtin: CapabilityToml = toml::from_str(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Structured builtin binding."
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
"#,
    )
    .expect("parse structured builtin capability");
    assert_eq!(
        builtin.handler,
        Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "example.handle".to_owned(),
        }))
    );
    assert_eq!(
        builtin.evidence_extractor,
        Some(HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "example.extract".to_owned(),
        }))
    );

    let exec: CapabilityToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Structured exec binding."
handler = { id = "example.handle" }
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { executable = "/nix/store/q0000000000000000000000000000000-odin-example/bin/odin-example-extract", argv = ["--framed", "--json"] }
"#,
        )
        .expect("parse structured exec capability");
    assert_eq!(
        exec.evidence_extractor,
        Some(HandlerBindingToml::Exec(ExecHandlerToml {
            executable:
                "/nix/store/q0000000000000000000000000000000-odin-example/bin/odin-example-extract"
                    .to_owned(),
            argv: vec!["--framed".to_owned(), "--json".to_owned()],
        }))
    );

    for capability in [builtin, exec] {
        let serialized = toml::Value::try_from(&capability)
            .expect("serialize structured capability into TOML value");
        let reparsed: CapabilityToml = serialized
            .try_into()
            .expect("reparse structured capability");
        assert_eq!(reparsed, capability);
        let object = RegistryObject {
            id: "example".to_owned(),
            relative_config: PathBuf::from("registry/capabilities/example/capability.toml"),
            config: ObjectConfig::Capability(Box::new(capability)),
        };
        assert!(validate_object(&object).is_empty());
    }
}

#[test]
fn structured_handlers_reject_legacy_scalars_unknown_keys_and_bad_shapes() {
    let scalar_cases = [
        r#"handler = "example.handle""#,
        r#"handler = "builtin:example.handle""#,
        r#"handler = "exec:/nix/store/x-tool/bin/tool --json""#,
    ];
    for scalar in scalar_cases {
        let source = format!(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Legacy scalar rejection."
{scalar}
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = {{ max_attempts = 1 }}
approval_policy = "none"
evidence_extractor = {{ id = "example.extract" }}
"#
        );
        assert!(
            toml::from_str::<CapabilityToml>(&source).is_err(),
            "legacy scalar parsed: {scalar}"
        );
    }

    let scalar_extractor = r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Legacy scalar extractor rejection."
handler = { id = "example.handle" }
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = "example.extract"
"#;
    assert!(
        toml::from_str::<CapabilityToml>(scalar_extractor).is_err(),
        "legacy scalar evidence extractor parsed"
    );

    let table_cases = [
        r#"handler = { id = "example.handle", shell = true }"#,
        r#"handler = { name = "example.handle" }"#,
        r#"handler = { executable = "/nix/store/x-tool/bin/tool" }"#,
        r#"handler = { executable = "/nix/store/x-tool/bin/tool", argv = ["--json"], extra = 1 }"#,
        r#"handler = { executable = "/nix/store/q0000000000000000000000000000000-odin/bin/tool", argv = [], env = { PATH = "/tmp" } }"#,
        r#"handler = { executable = "/nix/store/q0000000000000000000000000000000-odin/bin/tool", argv = [], cwd = "/tmp" }"#,
    ];
    for handler_table in table_cases {
        let source = format!(
            r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Exact key rejection."
{handler_table}
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = {{ max_attempts = 1 }}
approval_policy = "none"
evidence_extractor = {{ id = "example.extract" }}
"#
        );
        assert!(
            toml::from_str::<CapabilityToml>(&source).is_err(),
            "handler table parsed: {handler_table}"
        );
    }

    let malformed: &[(&str, HandlerBindingToml)] = &[
        (
            "empty builtin id",
            HandlerBindingToml::Builtin(BuiltinHandlerToml { id: String::new() }),
        ),
        (
            "builtin id with slash",
            HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "example/handle".to_owned(),
            }),
        ),
        (
            "builtin id with whitespace",
            HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "example handle".to_owned(),
            }),
        ),
        (
            "builtin id with shell syntax",
            HandlerBindingToml::Builtin(BuiltinHandlerToml {
                id: "example;handle".to_owned(),
            }),
        ),
        (
            "absolute non-store executable",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nonexistent-store/absent/bin/tool".to_owned(),
                argv: Vec::new(),
            }),
        ),
        (
            "relative exec executable",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "bin/tool".to_owned(),
                argv: vec!["--json".to_owned()],
            }),
        ),
        (
            "exec executable traversal",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/../tool".to_owned(),
                argv: vec!["--json".to_owned()],
            }),
        ),
        (
            "exec executable with shell syntax",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/x/bin/too<".to_owned(),
                argv: vec!["--json".to_owned()],
            }),
        ),
        (
            "store executable with shell syntax in tail",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/too<".to_owned(),
                argv: vec!["--json".to_owned()],
            }),
        ),
        (
            "whitespace exec argv element",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
                argv: vec!["--json extra".to_owned()],
            }),
        ),
        (
            "shell syntax exec argv element",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
                argv: vec!["--json;rm".to_owned()],
            }),
        ),
        (
            "empty exec argv element",
            HandlerBindingToml::Exec(ExecHandlerToml {
                executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
                argv: vec![String::new()],
            }),
        ),
    ];
    for (label, binding) in malformed {
        let message = binding.validate().expect_err(label);
        assert!(!message.is_empty(), "{label} rejected without a reason");
    }
    assert!(HandlerBindingToml::Exec(ExecHandlerToml {
        executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
        argv: vec!["--json".to_owned()],
    })
    .validate()
    .is_ok());
    assert!(HandlerBindingToml::Exec(ExecHandlerToml {
        executable: "/nix/store/q0000000000000000000000000000000-odin/bin/tool".to_owned(),
        argv: Vec::new(),
    })
    .validate()
    .is_ok());

    let capability: CapabilityToml = toml::from_str(
        r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "Shape finding codes."
handler = { id = "bad handle" }
input_schema = "schemas/capability/example.input.json"
output_schema = "schemas/capability/example.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { executable = "relative/tool", argv = ["--json"] }
"#,
    )
    .expect("parse shape-negative capability");
    let object = RegistryObject {
        id: "example".to_owned(),
        relative_config: PathBuf::from("registry/capabilities/example/capability.toml"),
        config: ObjectConfig::Capability(Box::new(capability)),
    };
    let findings = validate_object(&object);
    assert!(findings
        .iter()
        .any(|finding| finding.code == "capability-handler-binding"));
    assert!(findings
        .iter()
        .any(|finding| finding.code == "capability-evidence-extractor-binding"));
}

/// `delegate_to` is optional declaration data: absence must stay invisible
/// in canonical serialization, so the declaration hashes pinned by the
/// published snapshot chain never churn for capabilities that name no
/// target, and presence must round-trip as a typed seat id.
#[test]
fn capability_delegate_to_never_churns_canonical_serialization_when_absent() {
    let plain = r#"
schema = "odin.registry.v1"
kind = "capability"
enabled = true
implementation = "builtin"
version = 1
description = "fixture"
handler = { id = "fixture.handle" }
input_schema = "schemas/capability/fixture.tool.input.json"
output_schema = "schemas/capability/fixture.tool.output.json"
effect_class = "R0"
seat_tags = ["builder"]
timeout_seconds = 1
idempotency = "pure"
retry = { max_attempts = 1 }
approval_policy = "none"
evidence_extractor = { id = "fixture.evidence" }
"#;
    let capability: CapabilityToml = toml::from_str(plain).expect("parse plain capability");
    assert!(capability.delegate_to.is_none());
    let serialized = toml::to_string(&capability).expect("serialize plain capability");
    assert!(
        !serialized.contains("delegate_to"),
        "absent delegate_to must not appear in canonical serialization: {serialized}"
    );
    let reparsed: CapabilityToml = toml::from_str(&serialized).expect("reparse canonical bytes");
    assert_eq!(
        reparsed, capability,
        "canonical serialization must be a fixed point"
    );

    let delegating = plain.replace(
        "handler = { id = \"fixture.handle\" }",
        "handler = { id = \"seat_ask\" }\ndelegate_to = \"someseat\"",
    );
    let capability: CapabilityToml =
        toml::from_str(&delegating).expect("parse delegating capability");
    assert_eq!(
        capability
            .delegate_to
            .as_ref()
            .expect("delegate_to")
            .as_str(),
        "someseat"
    );
    let serialized = toml::to_string(&capability).expect("serialize delegating capability");
    assert!(
        serialized.contains("delegate_to = \"someseat\""),
        "the target must round-trip: {serialized}"
    );
    let reparsed: CapabilityToml = toml::from_str(&serialized).expect("reparse delegating bytes");
    assert_eq!(reparsed, capability);
}
