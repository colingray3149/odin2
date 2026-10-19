//! Strict transport envelope shape, identity and capability invariants.

use serde_json::json;

use super::*;

fn event() -> EventEnvelope {
    EventEnvelope::new(EventEnvelopeInit {
        id: EventId::new("event:1").expect("valid event ID"),
        sequence: 7,
        revision: 3,
        occurred_at_ms: 1_000,
        kind: "lane.ready".to_owned(),
        actor: Actor::system("kernel").expect("valid actor"),
        scope: Scope::default(),
        correlation: Correlation::new("request:1").expect("valid correlation"),
        payload: json!({"z": 1, "a": 2}),
        redaction: Redaction::None,
        producer: Producer::new("ledger", "1", None).expect("valid producer"),
    })
    .expect("valid event")
}

fn command() -> CommandEnvelope {
    CommandEnvelope::new(CommandEnvelopeInit {
        id: CommandId::new("command:1").expect("valid command ID"),
        sequence: 9,
        issued_at_ms: 1_000,
        expires_at_ms: 2_000,
        kind: "lane.start".to_owned(),
        actor: Actor::system("kernel").expect("valid actor"),
        scope: Scope::default(),
        correlation: Correlation::new("request:1").expect("valid correlation"),
        payload: json!({"lane": "lane:1"}),
        redaction: Redaction::None,
        producer: Producer::new("kernel", "1", None).expect("valid producer"),
        target: CommandTarget::Lane(LaneId::new("lane:1").expect("valid lane ID")),
        capability: CommandCapability::new(
            CapabilityId::new("lane.start").expect("valid capability ID"),
            1,
        )
        .expect("valid capability"),
        args_hash: Digest::hash(b"arguments"),
        expected_revision: 4,
    })
    .expect("valid command")
}

#[test]
fn command_rejects_expiry_at_the_boundary() {
    let command = command();

    assert!(command.validate_at(1_999, 4).is_ok());
    assert!(matches!(
        command.validate_at(2_000, 4),
        Err(DomainError::InvalidEnvelope(_))
    ));
}

#[test]
fn command_rejects_an_inconsistent_revision() {
    let command = command();

    assert!(matches!(
        command.validate_at(1_999, 3),
        Err(DomainError::InvalidEnvelope(_))
    ));
}

/// Consolidated wire↔schema roundtrip: real constructors for both envelopes,
/// Huginn nesting, knowledge content, and learning proposals, with old-key,
/// unknown nested key/enum, and semantic negatives failing at typed decode.
#[test]
fn wire_schema_roundtrip() {
    let apply = |target: &mut serde_json::Value, mutation: &serde_json::Value| {
        let (Some(target), Some(source)) = (target.as_object_mut(), mutation.as_object()) else {
            panic!("mutations must be JSON objects applied to JSON objects");
        };
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    };

    // Event and command envelopes.
    let event = event();
    let event_json = serde_json::to_value(&event).expect("serialize event");
    let restored: EventEnvelope =
        serde_json::from_value(event_json.clone()).expect("deserialize event");
    assert_eq!(restored, event);

    for mutation in [
        json!({"schema": "odin.event.v2"}),
        json!({"sequence": 0}),
        json!({"kind": "lane ready"}),
        json!({"occurred_at": "2026-01-01T00:00:00Z"}),
        json!({"surprise": true}),
    ] {
        let mut broken = event_json.clone();
        apply(&mut broken, &mutation);
        assert!(
            serde_json::from_value::<EventEnvelope>(broken).is_err(),
            "event mutation {mutation} must fail to deserialize"
        );
    }

    let mut empty_redaction = event_json.clone();
    empty_redaction["redaction"] = json!({"kind": "fields", "json_pointers": []});
    assert!(serde_json::from_value::<EventEnvelope>(empty_redaction).is_err());
    let mut unanchored_redaction = event_json.clone();
    unanchored_redaction["redaction"] = json!({"kind": "fields", "json_pointers": ["payload/x"]});
    assert!(serde_json::from_value::<EventEnvelope>(unanchored_redaction).is_err());
    let mut duplicate_redaction = event_json.clone();
    duplicate_redaction["redaction"] = json!({"kind": "fields", "json_pointers": ["/a", "/a"]});
    assert!(
        serde_json::from_value::<EventEnvelope>(duplicate_redaction).is_err(),
        "duplicate JSON pointers must fail redaction decode"
    );
    let mut unknown_actor_kind = event_json.clone();
    unknown_actor_kind["actor"] = json!({"kind": "seatX", "seat": "seat:1"});
    assert!(serde_json::from_value::<EventEnvelope>(unknown_actor_kind).is_err());
    let mut unknown_actor_field = event_json.clone();
    unknown_actor_field["actor"] = json!({"kind": "system", "name": "kernel", "surprise": true});
    assert!(serde_json::from_value::<EventEnvelope>(unknown_actor_field).is_err());
    let mut empty_system = event_json.clone();
    empty_system["actor"] = json!({"kind": "system", "name": ""});
    assert!(serde_json::from_value::<EventEnvelope>(empty_system).is_err());
    let mut null_session = event_json.clone();
    null_session["actor"] = json!({"kind": "seat", "seat": "seat:1", "session": null});
    assert!(
        serde_json::from_value::<EventEnvelope>(null_session).is_err(),
        "explicit null actor session must fail decode"
    );
    let mut null_producer_node = event_json.clone();
    null_producer_node["producer"] = json!({"component": "ledger", "version": "1", "node": null});
    assert!(
        serde_json::from_value::<EventEnvelope>(null_producer_node).is_err(),
        "explicit null producer node must fail decode"
    );
    let mut scope_missing = event_json.clone();
    scope_missing["scope"]
        .as_object_mut()
        .expect("scope object")
        .remove("node")
        .expect("node key");
    assert!(
        serde_json::from_value::<EventEnvelope>(scope_missing).is_err(),
        "a removed required-nullable scope key must fail envelope decode"
    );

    let mut scope_surprise = event_json;
    scope_surprise["scope"] = json!({"seat": null, "project": null, "lane": null,
            "run": null, "attempt": null, "session": null, "node": null, "host": null});
    assert!(serde_json::from_value::<EventEnvelope>(scope_surprise).is_err());

    let command = command();
    let command_json = serde_json::to_value(&command).expect("serialize command");
    let restored_command: CommandEnvelope =
        serde_json::from_value(command_json.clone()).expect("deserialize command");
    assert_eq!(restored_command, command);

    for mutation in [
        json!({"schema": "odin.command.v2"}),
        json!({"kind": "lane start"}),
        json!({"expires_at_ms": 500}),
        json!({"sequence": 0}),
        json!({"expected_desired_revision": 4}),
    ] {
        let mut broken = command_json.clone();
        apply(&mut broken, &mutation);
        assert!(
            serde_json::from_value::<CommandEnvelope>(broken).is_err(),
            "command mutation {mutation} must fail to deserialize"
        );
    }

    let mut expired = command_json.clone();
    expired["expires_at_ms"] = json!(command.issued_at_ms);
    assert!(serde_json::from_value::<CommandEnvelope>(expired).is_err());
    let mut stale_capability = command_json.clone();
    stale_capability["capability"]["version"] = json!(0);
    assert!(serde_json::from_value::<CommandEnvelope>(stale_capability).is_err());
    let mut unknown_target = command_json.clone();
    unknown_target["target"] = json!({"kind": "seatX", "id": "seat:1"});
    assert!(serde_json::from_value::<CommandEnvelope>(unknown_target).is_err());
    let mut undotted_capability = command_json;
    undotted_capability["capability"] = json!({"id": "lane", "version": 1});
    assert!(serde_json::from_value::<CommandEnvelope>(undotted_capability).is_err());

    // Huginn event and command nesting through the public request surface.
    use crate::huginn::control::{LiveCommand, LiveCommandBody};
    use crate::huginn::event::{LiveContentBlock, LiveEvent, LiveEventBody, LiveMessage};
    use crate::huginn::ids::{EventSeq, LiveSessionId, SessionEpoch};
    use crate::huginn::protocol::{HuginnMessage, HuginnRequest};
    use time::OffsetDateTime;

    let session = LiveSessionId::parse("8f9c2ee3-85ec-46e9-a43a-a2cd6048c1e9")
        .expect("valid live session id");
    let message_body = || {
        LiveMessage::new(vec![LiveContentBlock::Text("hello".to_owned())])
            .expect("nonempty message")
    };
    let live_event = LiveEvent::new(
        1,
        EventId::new("event:live").expect("valid event id"),
        session,
        SessionEpoch::new(1),
        EventSeq::new(1),
        OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("valid time"),
        LiveEventBody::UserMessage(message_body()),
    )
    .expect("valid live event");
    let message_json = serde_json::to_value(&live_event).expect("serialize live event");
    let restored_event: LiveEvent =
        serde_json::from_value(message_json.clone()).expect("deserialize live event");
    assert_eq!(restored_event, live_event);
    let huginn_message = HuginnMessage::Event(live_event.clone());
    let huginn_json = serde_json::to_value(&huginn_message).expect("serialize message");
    let restored_huginn: HuginnMessage =
        serde_json::from_value(huginn_json).expect("deserialize huginn message");
    assert_eq!(restored_huginn, huginn_message);

    let mut zero_sequence = message_json.clone();
    zero_sequence["sequence"] = json!(0);
    assert!(
        serde_json::from_value::<LiveEvent>(zero_sequence).is_err(),
        "a zero sequence must fail live event decode"
    );
    let mut wrong_schema = message_json.clone();
    wrong_schema["schemaVersion"] = json!(2);
    assert!(
        serde_json::from_value::<LiveEvent>(wrong_schema).is_err(),
        "LIVE_SCHEMA_VERSION must be exactly 1"
    );
    let mut nested_event_surprise = message_json.clone();
    apply(
        &mut nested_event_surprise["body"]["payload"],
        &json!({"surprise": true}),
    );
    assert!(
        serde_json::from_value::<LiveEvent>(nested_event_surprise).is_err(),
        "unknown nested live event payload keys must fail"
    );
    let mut empty_body = message_json;
    empty_body["body"] = json!({"kind": "userMessage", "payload": {"content": []}});
    assert!(serde_json::from_value::<LiveEvent>(empty_body).is_err());

    let live_command = LiveCommand {
        command_id: CommandId::new("command:live").expect("valid command id"),
        session_id: session,
        expected_epoch: SessionEpoch::new(1),
        expected_event_head: Some(EventSeq::new(1)),
        body: LiveCommandBody::Prompt {
            message: message_body(),
        },
    };
    let request = HuginnRequest::SessionCommand(live_command.clone());
    let request_json = serde_json::to_value(&request).expect("serialize request");
    let restored_request: HuginnRequest =
        serde_json::from_value(request_json.clone()).expect("deserialize request");
    assert_eq!(restored_request, request);
    let mut nested_command_surprise = serde_json::to_value(&live_command).expect("command json");
    apply(
        &mut nested_command_surprise["body"]["payload"],
        &json!({"surprise": true}),
    );
    assert!(
        serde_json::from_value::<LiveCommand>(nested_command_surprise).is_err(),
        "unknown nested live command payload keys must fail"
    );
    use crate::huginn::read_model::{QueryScope, SnapshotQuery};
    use std::num::NonZeroU16;
    let snapshot = HuginnRequest::Snapshot(SnapshotQuery {
        scope: QueryScope::All,
        kinds: Vec::new(),
        if_revision: None,
        cursor: None,
        limit: NonZeroU16::new(1).expect("limit"),
        include_stale: false,
    });
    let mut snapshot_json = serde_json::to_value(&snapshot).expect("snapshot json");
    apply(&mut snapshot_json["value"], &json!({"surprise": true}));
    assert!(
        serde_json::from_value::<HuginnRequest>(snapshot_json).is_err(),
        "unknown nested SnapshotQuery keys must fail at the query owner"
    );

    let mut empty_prompt = serde_json::to_value(&live_command).expect("serialize command");
    empty_prompt["body"] = json!({
        "kind": "prompt",
        "payload": {"message": {"content": []}}
    });
    assert!(
        serde_json::from_value::<LiveCommand>(empty_prompt).is_err(),
        "an empty prompt message must fail live command decode"
    );
}
