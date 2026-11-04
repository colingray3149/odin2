use std::path::PathBuf;

use super::SeatModelToml;
use crate::schema::fixtures::COMPLETE_SEAT;
use crate::schema::{validate_object, ObjectConfig, RegistryObject, SeatSandboxNetwork, SeatToml};

#[test]
fn supervisor_grants_steering_and_delegation_without_build_or_merge() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../registry");
    let supervisor: SeatToml =
        toml::from_str(&std::fs::read_to_string(root.join("seats/supervisor/seat.toml")).unwrap())
            .unwrap();
    for id in [
        "task.read",
        "task.steer",
        "task.note",
        "task.pause",
        "seat.ask.sinmara",
        "seat.ask.gungnir",
        "seat.ask.kubert",
        "kube.workload.summarize",
        "kube.health.read",
        "artifact.read",
        "export.read",
        "model.consult",
    ] {
        assert!(
            supervisor.tool_refs.iter().any(|tool| tool.as_str() == id),
            "{id}"
        );
    }
    for id in [
        "build.run",
        "test.run",
        "git.branch.merge",
        "git.patch.propose",
    ] {
        assert!(
            !supervisor.tool_refs.iter().any(|tool| tool.as_str() == id),
            "{id}"
        );
    }
    for seat in ["sinmara", "gungnir"] {
        let source = std::fs::read_to_string(root.join(format!("seats/{seat}/seat.toml"))).unwrap();
        let seat: SeatToml = toml::from_str(&source).unwrap();
        assert!(seat
            .tool_refs
            .iter()
            .any(|tool| tool.as_str() == "seat.ask.supervisor"));
    }
}

#[test]
fn seat_conversation_requires_scope_membership_live_plane_and_guidance() {
    // COMPLETE_SEAT carries no conversation line, so append one whose
    // project sits outside the seat's declared scope.
    let out_of_scope = format!(
        "{COMPLETE_SEAT}\nconversation = {{ project = \"life\", ask_capability = \"seat.ask.builder\", guidance = \"g\", answer_timeout_seconds = 240 }}\n"
    );
    let seat = toml::from_str::<SeatToml>(&out_of_scope).expect("parse out-of-scope conversation");
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "seat-conversation-scope"));

    let without_live = COMPLETE_SEAT.replace(
        "live = { max_sessions = 4, file_ingress_lane = \"file.in\", file_egress_lane = \"file.out\", render_ingress_lane = \"render.in\", render_egress_lane = \"render.out\" }\n",
        "",
    );
    let without_live = format!(
        "{without_live}conversation = {{ project = \"odin\", ask_capability = \"seat.ask.builder\", guidance = \"g\", answer_timeout_seconds = 240 }}\n"
    );
    let seat = toml::from_str::<SeatToml>(&without_live).expect("parse conversation without live");
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "seat-conversation-live"));

    let empty_guidance = format!(
        "{COMPLETE_SEAT}\nconversation = {{ project = \"odin\", ask_capability = \"seat.ask.builder\", guidance = \" \", answer_timeout_seconds = 240 }}\n"
    );
    let seat = toml::from_str::<SeatToml>(&empty_guidance).expect("parse blank guidance");
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "registry-required-value"));
}

#[test]
fn a_seat_consults_only_one_of_its_own_models() {
    let declared = COMPLETE_SEAT.replace(
        "profile = \"fixture\" }",
        "profile = \"fixture\", consult = { lane = \"astra\", effort = \"high\" } }",
    );
    let mut seat = toml::from_str::<SeatToml>(&declared).unwrap();
    let consult = seat.context.as_ref().unwrap().consult.clone().unwrap();
    assert_eq!(
        (consult.lane.as_str(), consult.effort.as_str()),
        ("astra", "high")
    );
    seat.models = ["gateway/grok", "gateway/astra"]
        .map(|model| SeatModelToml::try_from(model.to_owned()).unwrap())
        .into();
    let mut object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object).is_empty());
    let ObjectConfig::Seat(seat) = &mut object.config else {
        unreachable!()
    };
    seat.models.pop();
    let findings = validate_object(&object);
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == "seat-consult-lane"
                && finding
                    .message
                    .contains("astra is not one of this seat's models")),
        "{findings:?}"
    );
}

#[test]
fn a_shell_seat_cannot_deny_bash() {
    let mut seat = toml::from_str::<SeatToml>(COMPLETE_SEAT).unwrap();
    seat.sandbox.shell = true;
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    let messages: Vec<_> = validate_object(&object)
        .into_iter()
        .filter(|finding| finding.code == "seat-sandbox")
        .map(|finding| finding.message)
        .collect();
    assert!(
        messages.iter().any(|message| {
            message == "shell = true passes the bash tool; remove Bash from tools.deny"
        }),
        "{messages:?}"
    );
}

fn sandbox_messages(mut seat: SeatToml) -> Vec<String> {
    if let Some(tools) = seat.tools.as_mut() {
        tools.deny.retain(|name| name.as_str() != "Bash");
    }
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    validate_object(&object)
        .into_iter()
        .filter(|finding| finding.code == "seat-sandbox")
        .map(|finding| finding.message)
        .collect()
}

#[test]
fn seat_sandbox_network_host_requires_a_shell() {
    let mut seat = toml::from_str::<SeatToml>(COMPLETE_SEAT).unwrap();
    seat.sandbox.shell = true;
    seat.sandbox.network = SeatSandboxNetwork::Host;
    assert!(
        sandbox_messages(seat.clone()).is_empty(),
        "{:?}",
        sandbox_messages(seat.clone())
    );

    seat.sandbox.shell = false;
    let messages = sandbox_messages(seat);
    assert!(
        messages
            .iter()
            .any(|message| message == "network = host requires shell = true"),
        "{messages:?}"
    );
}

#[test]
fn sandbox_mounts_reject_root_home_and_parent_paths() {
    let mut seat = toml::from_str::<SeatToml>(COMPLETE_SEAT).unwrap();
    seat.sandbox.shell = false;
    seat.sandbox.writable = vec!["/".to_owned(), "/home/owner".to_owned()];
    seat.sandbox.readonly = vec!["/tmp/../etc".to_owned(), "/var/tmp".to_owned()];
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    let messages: Vec<_> = validate_object(&object)
        .into_iter()
        .filter(|finding| finding.code == "seat-sandbox")
        .map(|finding| finding.message)
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("\"/\"") && message.contains("must not be /")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("\"/home/owner\"")
                && message.contains("must not be a path under /home")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("\"/tmp/../etc\"")
                && message.contains("must not contain ..")),
        "{messages:?}"
    );
    assert!(
        messages
            .iter()
            .all(|message| !message.contains("\"/var/tmp\"")),
        "{messages:?}"
    );
}

#[test]
fn a_half_window_rollover_parses_and_an_out_of_range_fraction_is_refused() {
    let source = r#"
schema = "odin.registry.v1"
kind = "seat"
enabled = true
description = "Strict seat shape."
categories = ["builder"]
tool_refs = ["artifact.read"]
project_scope = ["odin"]
brain_scope = ["atlas.code"]
[limits]
max_parallel_runs = 2
max_sessions = 2
[live]
max_sessions = 2
file_ingress_lane = "file.in"
file_egress_lane = "file.out"
render_ingress_lane = "render.in"
render_egress_lane = "render.out"
[live.rollover]
threshold_tokens = 180000
max_brief_bytes = 8000
history_tail_events = 64
window_fraction = 50
fresh_after_rollovers = 2
heartbeat_minutes = 30
"#;
    let seat: SeatToml = toml::from_str(source).expect("half-window rollover parses");
    let rollover = seat
        .live
        .as_ref()
        .expect("live")
        .rollover
        .as_ref()
        .expect("rollover");
    assert_eq!(rollover.window_fraction, Some(50));
    assert_eq!(rollover.fresh_after_rollovers, Some(2));
    assert_eq!(rollover.heartbeat_minutes, Some(30));
    let object = RegistryObject {
        id: "watcher".to_owned(),
        relative_config: PathBuf::from("seats/watcher/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(
        validate_object(&object)
            .iter()
            .all(|finding| finding.code != "seat-live-rollover-range"),
        "a 50% window, two rollovers, and a 30-minute heartbeat are in range"
    );

    let refused = source.replace("window_fraction = 50", "window_fraction = 100");
    let seat: SeatToml = toml::from_str(&refused).expect("struct still parses");
    let object = RegistryObject {
        id: "watcher".to_owned(),
        relative_config: PathBuf::from("seats/watcher/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object).iter().any(|finding| {
        finding.code == "seat-live-rollover-range" && finding.message.contains("window_fraction")
    }));
}

