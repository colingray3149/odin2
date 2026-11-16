use std::path::PathBuf;

use crate::schema::fixtures::COMPLETE_SEAT;
use crate::schema::{validate_object, ObjectConfig, RegistryKind, RegistryObject, SeatToml};



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
description = "the owner's pc over ssh for heavy builds."
transport = "ssh-host"
host = "owner@pc"
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
    assert_eq!(declared.host.as_deref(), Some("owner@pc"));
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
fn a_harness_cannot_sign_claude_code_in() {
    use crate::schema::{AccountKind, HarnessPrompt, HarnessProtocol, HarnessToml};
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
    for protocol in [HarnessProtocol::Process, HarnessProtocol::Terminal] {
        harness.protocol = protocol;
        match protocol {
            HarnessProtocol::Terminal => {
                harness.prompt = HarnessPrompt::Keys;
                harness.transcripts = Some("{account}/projects/{workspace_slug}".to_owned());
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
