use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use crate::schema::fixtures::{COMPLETE_SEAT, COMPLETE_SLICE};
use crate::schema::{
    validate_object, BuiltinHandlerToml, CapabilityToml, ContainerToml, HandlerBindingToml,
    HostToml, LaneToml, NodeToml, ObjectConfig, ProjectToml, ProviderToml, RegistryKind,
    RegistryObject, SeatToml, SliceToml,
};

#[test]
fn complete_v1_seat_and_slice_shapes_parse_and_validate() {
    let seat = toml::from_str::<SeatToml>(COMPLETE_SEAT).unwrap();
    let slice = toml::from_str::<SliceToml>(COMPLETE_SLICE).unwrap();
    let objects = [
        RegistryObject {
            id: "builder".to_owned(),
            relative_config: PathBuf::from("seats/builder/seat.toml"),
            config: ObjectConfig::Seat(Box::new(seat)),
        },
        RegistryObject {
            id: "default".to_owned(),
            relative_config: PathBuf::from("slices/default/slice.toml"),
            config: ObjectConfig::Slice(Box::new(slice)),
        },
    ];
    for object in objects {
        assert!(validate_object(&object).is_empty());
        assert!(!object.canonical_bytes().unwrap().is_empty());
    }
}

#[test]
fn all_nine_kind_structs_deny_unknown_fields() {
    let cases = [
        (
            RegistryKind::Project,
            r#"schema="odin.registry.v1"
kind="project"
enabled=false
description="x"
source_root="."
default_seat="builder"
memory_namespaces=[]
artifact_policy="standard"
unknown=true"#,
        ),
        (
            RegistryKind::Lane,
            r#"schema="odin.registry.v1"
kind="lane"
enabled=false
description="x"
project="odin"
family="default"
default_seat="builder"
queue="default"
requires_independent_review=false
unknown=true"#,
        ),
        (
            RegistryKind::Node,
            r#"schema="odin.registry.v1"
kind="node"
enabled=false
description="x"
role="worker"
host=""
capabilities=[]
allow_workloads=false
authoritative_state=false
unknown=true"#,
        ),
        (
            RegistryKind::Provider,
            r#"schema="odin.registry.v1"
kind="provider"
enabled=false
description="x"
adapter="gateway"
policy = { routes = [{ gateway_lane_id = "zai-glm", gateway_model_id = "openai/glm-5.3" }] }
recovery = { allowed_rungs = ["escalate"], blocked_missing_decision = "x", max_attempts = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 1 }, cooldown_seconds = { retry = 0, restart_worker = 0, checkpoint = 0, rehome = 0, escalate = 0 } }
unknown=true"#,
        ),
        (
            RegistryKind::Host,
            r#"schema="odin.registry.v1"
kind="host"
enabled=false
description="x"
hardware="x86_64"
role="worker"
tailscale=""
enrolled=false
unknown=true"#,
        ),
    ];
    for (kind, source) in cases {
        let rejected = match kind {
            RegistryKind::Project => toml::from_str::<ProjectToml>(source).is_err(),
            RegistryKind::Lane => toml::from_str::<LaneToml>(source).is_err(),
            RegistryKind::Node => toml::from_str::<NodeToml>(source).is_err(),
            RegistryKind::Provider => toml::from_str::<ProviderToml>(source).is_err(),
            RegistryKind::Host => toml::from_str::<HostToml>(source).is_err(),
            _ => unreachable!(),
        };
        assert!(rejected, "{kind} accepted an unknown field");
    }
    assert!(toml::from_str::<SeatToml>(&format!("{COMPLETE_SEAT}\nunknown=true")).is_err());
    assert!(toml::from_str::<SliceToml>(&format!("{COMPLETE_SLICE}\nunknown=true")).is_err());
    assert!(toml::from_str::<CapabilityToml>(
        r#"schema="odin.registry.v1"
kind="capability"
enabled=false
implementation="unimplemented"
version=1
description="x"
effect_class="R0"
seat_tags=[]
timeout_seconds=1
idempotency="pure"
retry={max_attempts=0}
approval_policy="none"
unknown=true"#,
    )
    .is_err());
    assert!(toml::from_str::<ContainerToml>(
        r#"schema="odin.registry.v1"
kind="container"
enabled=false
description="x"
purpose="worker"
base="local-process"
seats_offered=[]
scripts=[]
watchdogs=[]
identity_fields=["purpose"]
tunables={}
surface=[]
contents={kind="scripts"}
monitoring="none"
unknown=true"#,
    )
    .is_err());
}

#[derive(Deserialize)]
struct SkeletonVariables {
    variable: Vec<SkeletonVariable>,
}

#[derive(Deserialize)]
struct SkeletonVariable {
    name: String,
    #[serde(rename = "type")]
    variable_type: String,
    required: bool,
}

#[test]
fn environment_and_harness_skeletons_compile_to_valid_objects() {
    let skeletons = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skeletons");
    let catalog = crate::SkeletonCatalog::load(&skeletons).expect("load skeleton catalog");
    assert_eq!(
        catalog.contracts().len(),
        14,
        "every skeleton kind has a contract"
    );
    assert!(catalog.anomalies().is_empty(), "{:?}", catalog.anomalies());

    let environment = toml::from_str::<toml::Table>(
        r#"
enabled = true
description = "Colin's pc over ssh for heavy builds."
transport = "ssh-host"
host = "colin@pc"
seats = ["gungnir"]
observation = { channel = "events" }
watchdog = [{ name = "force-push", match = "push --force" }]
"#,
    )
    .expect("typed environment fill");
    let compiled = catalog
        .compile(crate::FillRequest {
            skeleton: crate::SkeletonKind::NewEnvironment,
            destination_id: "pc-ssh".to_owned(),
            values: environment.into(),
        })
        .expect("compile environment fill");
    assert_eq!(
        compiled.destination.relative_config(),
        std::path::Path::new("registry/environments/pc-ssh/environment.toml")
    );
    let crate::CompiledDocument::Registry(config) = compiled.document else {
        panic!("environment fill must compile a registry object");
    };
    let ObjectConfig::Environment(declared) = &config else {
        panic!("environment fill must retain its registry kind");
    };
    assert_eq!(declared.host.as_deref(), Some("colin@pc"));
    assert!(
        declared.credential.is_none(),
        "an omitted optional stays absent"
    );
    assert_eq!(declared.watchdogs.len(), 1);
    let object = RegistryObject {
        id: "pc-ssh".to_owned(),
        relative_config: PathBuf::from("registry/environments/pc-ssh/environment.toml"),
        config,
    };
    let failures: Vec<_> = validate_object(&object)
        .into_iter()
        .filter(crate::RegistryFinding::is_failure)
        .collect();
    assert!(failures.is_empty(), "{failures:?}");

    let harness = toml::from_str::<toml::Table>(
        r#"
enabled = true
description = "Gemini CLI, one process per prompt; Odin watches and stops it."
protocol = "process"
governance = "observed"
command = ["gemini", "-p"]
prompt = "argv"
output = "text"
model_arg = "--model"
stop_signal = "SIGINT"
stop_grace_seconds = 10
"#,
    )
    .expect("typed harness fill");
    let compiled = catalog
        .compile(crate::FillRequest {
            skeleton: crate::SkeletonKind::NewHarness,
            destination_id: "gemini".to_owned(),
            values: harness.into(),
        })
        .expect("compile harness fill");
    let crate::CompiledDocument::Registry(ObjectConfig::Harness(declared)) = compiled.document
    else {
        panic!("harness fill must compile a harness");
    };
    assert_eq!(declared.stop.grace_seconds, 10);
    assert!(declared.check().is_empty(), "{:?}", declared.check());
}

#[test]
fn authoring_skeleton_destination_shapes_match_registry_contracts() {
    let skeletons = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skeletons");

    let catalog = crate::SkeletonCatalog::load(&skeletons).expect("load skeleton catalog");
    let binding = crate::AdmittedBinding {
        version: 4,
        input_schema: "schemas/capability/example.input.json".to_owned(),
        output_schema: "schemas/capability/example.output.json".to_owned(),
        handler: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "example.handle".to_owned(),
        }),
        evidence_extractor: HandlerBindingToml::Builtin(BuiltinHandlerToml {
            id: "example.extract".to_owned(),
        }),
    };
    let values = toml::from_str::<toml::Table>(
        r#"
enabled = true
description = "Filled skeleton capability."
binding_id = "example.handle"
effect_class = "R1"
seat_tags = ["builder"]
timeout_seconds = 60
idempotency = "pure"
max_attempts = 3
approval_policy = "none"
"#,
    )
    .expect("typed capability fill");
    let compiled = catalog
        .compile_with_bindings(
            crate::FillRequest {
                skeleton: crate::SkeletonKind::NewCapability,
                destination_id: "example.filled".to_owned(),
                values: values.into(),
            },
            std::slice::from_ref(&binding),
        )
        .expect("compile admitted capability fill");
    let crate::CompiledDocument::Registry(config) = compiled.document else {
        panic!("capability fill must compile a registry object");
    };
    let capability_object = RegistryObject {
        id: "example.filled".to_owned(),
        relative_config: PathBuf::from("registry/capabilities/example.filled/capability.toml"),
        config,
    };
    assert!(validate_object(&capability_object).is_empty());
    let ObjectConfig::Capability(capability) = &capability_object.config else {
        panic!("capability fill must retain its registry kind");
    };
    assert_eq!(capability.version, binding.version);
    assert_eq!(capability.handler.as_ref(), Some(&binding.handler));
    assert_eq!(
        capability.evidence_extractor.as_ref(),
        Some(&binding.evidence_extractor)
    );

    let seat_variables = fs::read_to_string(skeletons.join("new-seat/variables.toml"))
        .expect("read new-seat variables");
    let seat_variables: SkeletonVariables =
        toml::from_str(&seat_variables).expect("parse new-seat variables");
    let live_policy = seat_variables
        .variable
        .iter()
        .find(|variable| variable.name == "live")
        .expect("live policy variable");
    assert_eq!(live_policy.variable_type, "optional<table>");
    assert!(!live_policy.required);

    let lane_values = toml::from_str::<toml::Table>(
        r#"
enabled = true
description = "Engine lane without transfer policy."
project = "home"
family = "engine"
default_seat = "architect"
queue = "interactive"
independent_review = false
"#,
    )
    .expect("typed engine lane fill");
    let compiled_lane = catalog
        .compile(crate::FillRequest {
            skeleton: crate::SkeletonKind::NewLane,
            destination_id: "home-engine".to_owned(),
            values: lane_values.into(),
        })
        .expect("compile engine lane without transfer policy");
    let crate::CompiledDocument::Registry(config) = compiled_lane.document else {
        panic!("new-lane fill must compile a registry object");
    };
    let ObjectConfig::Lane(lane) = &config else {
        panic!("new-lane fill must retain its registry kind");
    };
    assert!(lane.transfer_policy().is_none());
    let lane_object = RegistryObject {
        id: "home-engine".to_owned(),
        relative_config: PathBuf::from("registry/lanes/home-engine/lane.toml"),
        config,
    };
    assert!(validate_object(&lane_object).is_empty());

    for (value, valid) in [(64, true), (65, false)] {
        let source = COMPLETE_SEAT.replace(
            "live = { max_sessions = 4,",
            &format!("live = {{ max_sessions = {value},"),
        );
        let seat =
            toml::from_str::<SeatToml>(&source).expect("parse seat live_max_sessions boundary");
        let object = RegistryObject {
            id: format!("seat-{value}"),
            relative_config: PathBuf::from(format!("registry/seats/seat-{value}/seat.toml")),
            config: ObjectConfig::Seat(Box::new(seat)),
        };
        let has_range_failure = validate_object(&object)
            .iter()
            .any(|finding| finding.code == "seat-live-range");
        assert_eq!(has_range_failure, !valid);
    }
}

/// MCP flags belong only to driving process/terminal transports and remain
/// absent from serialization when undeclared.
#[test]
fn generic_harness_mcp_flags_stay_optional() {
    let source = r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "Generic transport fixture"
protocol = "process"
governance = "observed"
command = ["fixture-agent"]
prompt = "argv"
output = "text"
[stop]
signal = "SIGTERM"
grace_seconds = 10
"#;
    let base = toml::from_str::<crate::schema::HarnessToml>(source).expect("fixture");
    for protocol in [
        crate::schema::HarnessProtocol::Process,
        crate::schema::HarnessProtocol::Terminal,
        crate::schema::HarnessProtocol::Acp,
    ] {
        let mut harness = base.clone();
        harness.protocol = protocol;
        match protocol {
            crate::schema::HarnessProtocol::Terminal => {
                harness.prompt = crate::schema::HarnessPrompt::Keys;
                harness.transcripts = Some("{home}/transcripts".to_owned());
            }
            crate::schema::HarnessProtocol::Acp => {
                harness.prompt = crate::schema::HarnessPrompt::Rpc;
                harness.output = crate::schema::HarnessOutput::Acp;
            }
            _ => {}
        }
        assert!(harness.check().is_empty());
        assert!(serde_json::to_value(&harness)
            .unwrap()
            .get("mcp_config_arg")
            .is_none());
        harness.mcp_config_arg = Some("--mcp-config".to_owned());
        assert_eq!(
            harness.check().is_empty(),
            protocol != crate::schema::HarnessProtocol::Acp
        );
    }
}

#[test]
fn observe_harness_has_no_driving_configuration() {
    use crate::schema::{HarnessOutput, HarnessPrompt, HarnessProtocol, HarnessToml};
    let harness: HarnessToml = toml::from_str(include_str!(
        "../../../../../registry/harnesses/observe/harness.toml"
    ))
    .unwrap();
    assert!(harness.check().is_empty());
    assert_eq!(harness.protocol, HarnessProtocol::Observe);
    assert_eq!(harness.prompt, HarnessPrompt::None);
    assert_eq!(harness.output, HarnessOutput::Environment);
    for field in [
        "command",
        "model",
        "account",
        "resume",
        "state",
        "brief",
        "mcp",
        "transcripts",
    ] {
        let mut invalid = harness.clone();
        match field {
            "command" => invalid.command = vec!["agent".into()],
            "model" => invalid.model_arg = Some("--model".into()),
            "account" => invalid.account = Some(crate::schema::AccountKind::ClaudeCode),
            "resume" => invalid.resume_args = vec!["{agent_session}".into()],
            "state" => invalid.state_paths = vec![".state".into()],
            "brief" => invalid.brief = Some("Drive the agent".into()),
            "mcp" => invalid.mcp_config_arg = Some("--mcp-config".into()),
            "transcripts" => invalid.transcripts = Some("{home}/transcripts".into()),
            _ => unreachable!(),
        }
        assert!(!invalid.check().is_empty(), "{field}");
    }
}

/// Claude Code is driver-only: no harness protocol — process, terminal or
/// acp — signs a Claude Code account in. The `claude.*` workload driver owns
/// Claude accounts; the refusal routes the declarer there, while the same
/// shape under the codex kind stays admittable.
#[test]
fn a_harness_cannot_sign_claude_code_in() {
    use crate::schema::{AccountKind, HarnessOutput, HarnessPrompt, HarnessProtocol, HarnessToml};
    let mut harness: HarnessToml = toml::from_str(
        r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "Generic transport fixture"
protocol = "process"
governance = "observed"
command = ["fixture-agent"]
prompt = "argv"
output = "text"
account = "claude-code"
[stop]
signal = "SIGTERM"
grace_seconds = 10
"#,
    )
    .expect("fixture");
    for protocol in [
        HarnessProtocol::Process,
        HarnessProtocol::Terminal,
        HarnessProtocol::Acp,
    ] {
        harness.protocol = protocol;
        match protocol {
            HarnessProtocol::Terminal => {
                harness.prompt = HarnessPrompt::Keys;
                harness.transcripts = Some("{account}/projects/{workspace_slug}".to_owned());
            }
            HarnessProtocol::Acp => {
                harness.prompt = HarnessPrompt::Rpc;
                harness.output = HarnessOutput::Acp;
                harness.transcripts = None;
            }
            HarnessProtocol::Process => {
                harness.prompt = HarnessPrompt::Argv;
                harness.transcripts = None;
            }
            _ => unreachable!(),
        }
        let refusal = harness.check().join(" | ");
        assert!(
            refusal.contains("claude.* workload driver"),
            "{protocol:?}: {refusal}"
        );
        harness.account = Some(AccountKind::Codex);
        assert!(
            harness.check().is_empty(),
            "{protocol:?}: {:?}",
            harness.check()
        );
        harness.account = Some(AccountKind::ClaudeCode);
    }
}

fn claude_workload_source() -> String {
    format!(
        r#"schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "Claude driver without seat authority."
harness = "claude-code"
account_kind = "claude-code"
accounts = "discovered"
image = {{ reference = "registry.example/claude:1@sha256:{}" }}
resources = {{ cpu_request = "1", cpu_limit = "2", memory_request = "1Gi", memory_limit = "2Gi", storage_limit = "4Gi" }}
"#,
        "a".repeat(64)
    )
}

#[test]
fn claude_workload_dispatch_preserves_identity_without_seat_composition() {
    let object = super::parse_object_toml(
        RegistryKind::Workload,
        "claude",
        "workloads/claude/profile.toml",
        &claude_workload_source(),
    )
    .expect("parse Claude driver workload");
    assert!(matches!(&object.config, ObjectConfig::ClaudeCode(_)));
    assert_eq!(object.kind(), RegistryKind::Workload);
    assert!(object.enabled());
    assert!(validate_object(&object).is_empty());
    let encoded = object.canonical_bytes().expect("canonical workload");
    assert!(!encoded.is_empty());
    let config: ObjectConfig =
        serde_json::from_slice(&object.config.canonical_bytes().expect("canonical config"))
            .expect("roundtrip tagged config");
    assert_eq!(config, object.config);
    let objects = [object];
    assert!(crate::compose_workload_profiles(&objects).is_empty());
    assert!(matches!(
        crate::compose_workload_profile(&objects, "claude"),
        Err(crate::WorkloadProfileLookupError::Unknown { .. })
    ));
}

#[test]
fn claude_workload_parser_rejects_seat_fields_and_unknown_harness() {
    for source in [
        format!(
            "{}\nseat = {{ id = \"builder\" }}",
            claude_workload_source()
        ),
        claude_workload_source().replace("harness = \"claude-code\"", "harness = \"unknown\""),
    ] {
        assert!(super::parse_object_toml(
            RegistryKind::Workload,
            "claude",
            "workloads/claude/profile.toml",
            &source,
        )
        .is_err());
    }
}

#[test]
fn claude_workload_relations_run_driver_validation() {
    let object = super::parse_object_toml(
        RegistryKind::Workload,
        "claude",
        "workloads/claude/profile.toml",
        &format!("{}\nprojects = [\"undeclared\"]", claude_workload_source()),
    )
    .expect("parse structurally valid driver");
    assert!(validate_object(&object).is_empty());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let findings = crate::validate_relations(&[object], &crate::RelationContext::new(root));
    assert!(findings.iter().any(|finding| {
        finding.code == "registry-broken-relation"
            && finding
                .message
                .contains("projects must contain distinct enabled declared project IDs")
    }));
}
