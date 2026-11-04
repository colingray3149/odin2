//! Workload relations require referenced declarations to be enabled.

use std::collections::BTreeSet;

use odin_domain::knowledge::AtlasId;
use odin_domain::ProjectId;

use crate::relational::context::RelationContext;
use crate::relational::fixtures::{
    project_object, provider_object, seat_object_named, workload_object,
};
use crate::relational::validate;
use crate::schema::{ObjectConfig, RegistryObject};
fn relation_messages(objects: &[RegistryObject]) -> Vec<String> {
    let mut objects = objects.to_vec();
    objects.push(model_card("fixture.gateway", true));
    objects.push(pod_harness("omp", true));
    let odin_root = tempfile::tempdir().expect("fixture odin root");
    std::fs::create_dir(odin_root.path().join("schemas")).expect("fixture schema root");
    let context = RelationContext::new(odin_root.path());
    validate(&objects, &context)
        .into_iter()
        .filter(|finding| finding.path.ends_with("profile.toml"))
        .map(|finding| finding.message)
        .collect()
}
fn model_card(id: &str, enabled: bool) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "model"
enabled = {enabled}
description = "fixture model card"
id = "gateway/{id}"
served = "fixture/model"
tier = "everyday"
account = "fixture-account"
strengths = "Fixture reasoning"
seats = true
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: std::path::PathBuf::from(format!("registry/models/{id}/model.toml")),
        config: ObjectConfig::Model(Box::new(
            toml::from_str(&source).expect("parse model card fixture"),
        )),
    }
}
fn pod_harness(id: &str, pod: bool) -> RegistryObject {
    let source = format!(
        r#"
schema = "odin.registry.v1"
kind = "harness"
enabled = true
description = "fixture harness"
protocol = "omp"
governance = "governed"
prompt = "rpc"
output = "omp-rpc"
pod = {pod}

[stop]
signal = "SIGTERM"
grace_seconds = 1
"#
    );
    RegistryObject {
        id: id.to_owned(),
        relative_config: std::path::PathBuf::from(format!("registry/harnesses/{id}/harness.toml")),
        config: ObjectConfig::Harness(Box::new(
            toml::from_str(&source).expect("parse harness fixture"),
        )),
    }
}
/// Enables the workload memory namespace in both seat scopes before varying a constraint.
fn bound_seat() -> RegistryObject {
    let mut seat = seat_object_named("fixture", "", false);
    if let ObjectConfig::Seat(seat_toml) = &mut seat.config {
        let atlas = AtlasId::new("atlas.code").expect("atlas id");
        seat_toml.brain_scope = BTreeSet::from([atlas.clone()]);
        if let Some(knowledge) = seat_toml.knowledge.as_mut() {
            knowledge.atlas_sources = BTreeSet::from([atlas]);
        }
    }
    seat
}

#[test]
fn fully_bound_workload_profile_validates_clean() {
    let profile = workload_object("fixture", "fixture", "fixture", "fixture.gateway", true);
    let messages = relation_messages(&[
        profile,
        bound_seat(),
        project_object(true),
        provider_object(true),
    ]);
    assert!(
        messages.is_empty(),
        "a fully bound workload profile must validate clean: {messages:?}"
    );
}

#[test]
fn workload_rejects_project_outside_the_seat_scope_and_foreign_namespace() {
    let mut profile = workload_object("fixture", "fixture", "fixture", "fixture.gateway", true);
    if let ObjectConfig::Workload(workload) = &mut profile.config {
        workload.seat.project = ProjectId::new("elsewhere").expect("project id");
        workload.memory.as_mut().expect("agent memory").namespace = "atlas.unrelated".to_owned();
    }
    let messages = relation_messages(&[
        profile,
        bound_seat(),
        project_object(true),
        provider_object(true),
    ]);
    assert!(
        messages
            .iter()
            .any(|message| message.contains("outside the bound seat's project_scope")),
        "an out-of-scope project must be a broken relation: {messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("outside the bound seat's brain_scope")),
        "a foreign namespace must be a broken relation: {messages:?}"
    );
}

/// Pod tools are a subset of seat tools and cannot launch, delegate, or create.
#[test]
fn a_pod_holds_only_seat_tools_that_cannot_create() {
    let mut profile = workload_object("fixture", "fixture", "fixture", "fixture.gateway", true);
    if let ObjectConfig::Workload(workload) = &mut profile.config {
        workload.tools = vec![
            odin_domain::CapabilityId::new("kube.workload.create").expect("id"),
            odin_domain::CapabilityId::new("memory.remember").expect("id"),
        ];
    }
    let messages = relation_messages(&[
        profile,
        bound_seat(),
        project_object(true),
        provider_object(true),
    ]);
    assert!(
        messages
            .iter()
            .any(|message| message
                .contains("\"kube.workload.create\" launches, delegates or creates")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("\"memory.remember\" is not a tool of seat")),
        "the fixture seat does not hold memory.remember: {messages:?}"
    );
}

fn with_harness(harness: &str) -> RegistryObject {
    let mut profile = workload_object("fixture", "fixture", "fixture", "fixture.gateway", true);
    if let ObjectConfig::Workload(workload) = &mut profile.config {
        workload.harness = Some(harness.to_owned());
    }
    profile
}

#[test]
fn a_harness_without_pod_is_refused() {
    let messages = relation_messages(&[
        with_harness("codex"),
        bound_seat(),
        project_object(true),
        provider_object(true),
        pod_harness("codex", false),
    ]);
    assert!(
        messages
            .iter()
            .any(|message| message.contains("does not declare pod support")),
        "{messages:?}"
    );
}

#[test]
fn offered_launch_seats_must_exist_and_be_enabled() {
    for (offered, enabled, expected) in [
        ("sinmara", true, None),
        ("sinmara", false, Some("disabled seat")),
        ("missing", true, Some("missing seat")),
    ] {
        let mut profile = workload_object("fixture", "fixture", "fixture", "fixture.gateway", true);
        if let ObjectConfig::Workload(workload) = &mut profile.config {
            workload
                .seats_offered
                .insert(offered.parse().expect("seat id"));
        }
        let mut caller = seat_object_named("sinmara", "", false);
        if let ObjectConfig::Seat(seat) = &mut caller.config {
            seat.enabled = enabled;
            seat.tool_refs
                .insert("workload.publish".parse().expect("capability"));
        }
        let messages = relation_messages(&[
            profile,
            bound_seat(),
            caller,
            project_object(true),
            provider_object(true),
        ]);
        let offered_messages: Vec<_> = messages
            .iter()
            .filter(|message| message.contains("seats_offered"))
            .collect();
        match expected {
            None => assert!(offered_messages.is_empty(), "{messages:?}"),
            Some(reason) => assert!(
                offered_messages
                    .iter()
                    .any(|message| message.contains(reason)),
                "{messages:?}"
            ),
        }
        assert!(
            !messages
                .iter()
                .any(|message| message.contains("holds creation capabilities")),
            "the caller may create; only the pod's bound seat is restricted: {messages:?}"
        );
    }
}
