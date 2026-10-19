use std::path::PathBuf;

use crate::schema::fixtures::COMPLETE_SEAT;
use crate::schema::{validate_object, ObjectConfig, RegistryObject, SeatSandboxNetwork, SeatToml};

#[test]
fn state_sources_are_admitted_but_unknown_state_kinds_are_not() {
    let mut seat = toml::from_str::<SeatToml>(COMPLETE_SEAT).unwrap();
    seat.brain_scope = ["state.registry", "state.live", "state.tasks"]
        .into_iter()
        .map(|id| odin_domain::knowledge::AtlasId::new(id).unwrap())
        .collect();
    let mut object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object).is_empty());
    let ObjectConfig::Seat(seat) = &mut object.config else {
        unreachable!()
    };
    seat.brain_scope
        .insert(odin_domain::knowledge::AtlasId::new("state.secrets").unwrap());
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "seat-brain-scope"));
}

#[test]
fn every_removed_seat_key_is_rejected_without_aliases() {
    for old_key in [
        "role = \"builder\"",
        "model_policy = \"gateway/default\"",
        "default_model_policy = \"default\"",
        "projects = [\"odin\"]",
        "memory_namespaces = [\"atlas.code\"]",
        "capabilities = [\"artifact.read\"]",
        "denied_capabilities = [\"shell.root\"]",
        "require_human_for_risk = [\"R3\"]",
    ] {
        let source = format!("{COMPLETE_SEAT}\n{old_key}\n");
        assert!(
            toml::from_str::<SeatToml>(&source).is_err(),
            "legacy key parsed: {old_key}"
        );
    }
    let legacy_top_level_tools = COMPLETE_SEAT.replace(
            "tools = { deny = [\"Bash\"], redirects = { max_http_hops = 0, allow_cross_origin = false, disabled_aliases = [\"FileReadTool\"] } }",
            "tools = [\"artifact.read\"]",
        );
    assert!(toml::from_str::<SeatToml>(&legacy_top_level_tools).is_err());
}

#[test]
fn seat_conversation_declares_a_strict_vehicle() {
    let source = format!(
        "{COMPLETE_SEAT}\nconversation = {{ project = \"odin\", ask_capability = \"seat.ask.builder\", guidance = \"Speak plainly.\", answer_timeout_seconds = 240 }}\n"
    );
    let seat = toml::from_str::<SeatToml>(&source).expect("parse seat with conversation");
    assert_eq!(
        seat.conversation
            .as_ref()
            .expect("conversation")
            .project
            .as_str(),
        "odin"
    );
    assert_eq!(
        seat.conversation
            .as_ref()
            .expect("conversation")
            .ask_capability
            .as_str(),
        "seat.ask.builder"
    );
    assert_eq!(
        seat.conversation
            .as_ref()
            .expect("conversation")
            .answer_timeout_seconds
            .get(),
        240
    );
    let object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object).is_empty());
}

#[test]
fn seat_conversation_rejects_unknown_missing_and_zero_fields() {
    let invalid = [
        "conversation = { project = \"odin\", ask_capability = \"seat.ask.builder\", guidance = \"g\", answer_timeout_seconds = 240, seat = \"sinmara\" }",
        "conversation = { guidance = \"g\", answer_timeout_seconds = 240 }",
        "conversation = { project = \"odin\", answer_timeout_seconds = 240 }",
        "conversation = { project = \"odin\", guidance = \"g\" }",
        "conversation = { project = \"odin\", guidance = \"g\", answer_timeout_seconds = 240 }",
        "conversation = { project = \"odin\", guidance = \"g\", answer_timeout_seconds = 0 }",
    ];
    for conversation in invalid {
        let source = format!("{COMPLETE_SEAT}\n{conversation}\n");
        assert!(
            toml::from_str::<SeatToml>(&source).is_err(),
            "invalid conversation parsed: {conversation}"
        );
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
fn a_seat_declares_its_brain_review_lane() {
    let declared = COMPLETE_SEAT.replace(
        "profile = \"fixture\" }",
        "profile = \"fixture\", review_lane = \"zai-glm\" }",
    );
    assert_ne!(
        declared, COMPLETE_SEAT,
        "the fixture carries a seat context"
    );
    let seat = toml::from_str::<SeatToml>(&declared).unwrap();
    assert_eq!(
        seat.context.as_ref().unwrap().review_lane.as_deref(),
        Some("zai-glm")
    );
    let mut object = RegistryObject {
        id: "builder".to_owned(),
        relative_config: PathBuf::from("seats/builder/seat.toml"),
        config: ObjectConfig::Seat(Box::new(seat)),
    };
    assert!(validate_object(&object).is_empty());
    let ObjectConfig::Seat(seat) = &mut object.config else {
        unreachable!()
    };
    seat.context.as_mut().unwrap().review_lane = Some("two words".to_owned());
    assert!(validate_object(&object)
        .iter()
        .any(|finding| finding.code == "seat-review-lane"));
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

#[test]
fn seat_sandbox_network_host_parses() {
    let source = COMPLETE_SEAT.replace(
        "tools = {",
        "sandbox = { shell = true, network = \"host\" }\ntools = {",
    );
    let seat = toml::from_str::<SeatToml>(&source).expect("host");
    assert_eq!(seat.sandbox.network, SeatSandboxNetwork::Host);
    assert!(seat.sandbox.shell);
}

#[test]
fn seat_sandbox_network_gateway_and_hosts_do_not_parse() {
    for network in ["gateway", "hosts"] {
        let source = COMPLETE_SEAT.replace(
            "tools = {",
            &format!("sandbox = {{ shell = true, network = \"{network}\" }}\ntools = {{"),
        );
        assert!(
            toml::from_str::<SeatToml>(&source).is_err(),
            "{network} must not parse"
        );
    }
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
    seat.sandbox.writable = vec!["/".to_owned(), "/home/colin".to_owned()];
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
            .any(|message| message.contains("\"/home/colin\"")
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
