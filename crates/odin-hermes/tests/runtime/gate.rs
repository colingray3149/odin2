//! The delivery authorization seam: only a delivered, exactly-matched, unreplayed decision can authorize a request.

use crate::fixtures::{
    gate_runtime, gate_runtime_with_adapter, now, request_gate_approval, RecordingNotifySink,
    INTENT_DM_CHANNEL, INTENT_OWNER,
};
use odin_domain::{ProjectId, SeatId};
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::sync::Arc;

#[test]
fn model_switch_question_uses_admitted_registry_description() {
    use crate::fixtures::{
        conversation_ownership, discord_settings, fixture_bound_projects, intake_contract,
        owner_ask_contract,
    };
    use odin_domain::{ApprovalId, CapabilityId, EffectClass};
    use odin_hermes::runtime::{HermesLedgers, HermesRuntime};
    use std::collections::BTreeMap;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = "registry/capabilities/seat.model.set/capability.toml";
    let source = std::fs::read_to_string(root.join(path)).unwrap();
    let object = odin_registry::schema::parse_object_toml(
        odin_registry::RegistryKind::Capability,
        "seat.model.set".to_owned(),
        path,
        &source,
    )
    .unwrap();
    let odin_registry::ObjectConfig::Capability(declaration) = &object.config else {
        panic!("expected a capability");
    };
    let admitted = odin_registry::relational::AdmittedBinding {
        version: declaration.version,
        input_schema: declaration.input_schema.clone().unwrap(),
        output_schema: declaration.output_schema.clone().unwrap(),
        handler: declaration.handler.clone().unwrap(),
        evidence_extractor: declaration.evidence_extractor.clone().unwrap(),
    };
    let declared = odin_kernel::CapabilityContract::try_from_registry(&object, &admitted).unwrap();
    assert_eq!(declared.effect_class, EffectClass::R2);
    assert_eq!(
        declared.approval,
        odin_kernel::ApprovalRequirement::Operator
    );

    // A changed admitted description must change the delivered action too:
    // the transport cannot substitute a hard-coded phrase for this capability.
    for description in [
        declared.description.clone(),
        "Use the requested declared model for the selected assistant".to_owned(),
        "Use cred:private-model-handle for the requested model".to_owned(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut contract = declared.clone();
        contract.description = description.clone();
        let contracts = BTreeMap::from([
            (contract.id.clone(), contract),
            (
                CapabilityId::new("discord.intake").unwrap(),
                intake_contract(EffectClass::R1),
            ),
            (owner_ask_contract().id.clone(), owner_ask_contract()),
        ]);
        let settings = odin_hermes::config::HermesSettings::new(
            dir.path().join("state"),
            Some(discord_settings()),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let ledger = Arc::new(Mutex::new(
            Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
        ));
        let runtime = HermesRuntime::open(
            settings,
            HermesLedgers {
                conversation: Ledger::open_in_memory().unwrap(),
                adapter: Arc::clone(&ledger),
                purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
            },
            &contracts,
            None,
            8_192,
            fixture_bound_projects(),
            Some(conversation_ownership()),
        )
        .unwrap();
        let sink = Arc::new(RecordingNotifySink::default());
        runtime.bind_notify_sink(sink.clone()).unwrap();
        create_vehicle(&mut ledger.lock(), "test-vehicle", now());
        let approval_id = ApprovalId::new("approval:model-switch-question").unwrap();
        ledger
            .lock()
            .request_approval(odin_ledger::approval::NewApproval {
                approval_id: approval_id.clone(),
                issuer: "sinmara".to_owned(),
                scope: odin_ledger::approval::ApprovalScope {
                    target_kind: "run".to_owned(),
                    target_id: "run:live:test-vehicle".to_owned(),
                    capability_id: declared.id.clone(),
                    arguments_digest: odin_kernel::arguments_digest(&serde_json::json!({
                        "seat": "sinmara", "provider": "declared", "model": "requested",
                    })),
                },
                requested_at: now(),
                expires_at: now() + time::Duration::hours(1),
            })
            .unwrap();
        runtime
            .deliver_approval_question(
                &ledger,
                &approval_id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None,
            )
            .unwrap();
        let calls = sink.calls.lock();
        assert!(!calls.is_empty());
        let wire = calls.concat();
        let expected = odin_hermes::egress::scrub_sensitive(
            &odin_hermes::natural::approval_question(&description, None),
            &std::collections::BTreeSet::new(),
        );
        assert_eq!(
            wire, expected,
            "all physical chunks reproduce the admitted description's rendered question"
        );
        let rows = ledger.lock().conversation_deliveries().unwrap();
        assert_eq!(rows.len(), 1);
        let durable: serde_json::Value = serde_json::from_str(&rows[0].state_json).unwrap();
        assert_eq!(durable["phase"], "committed");
        assert_eq!(durable["target"], serde_json::json!(&*calls));
        let durable_contents: Vec<_> = durable["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|chunk| chunk["content"].as_str().unwrap())
            .collect();
        assert_eq!(
            durable_contents,
            calls.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert!(!durable["target"]
            .to_string()
            .contains("cred:private-model-handle"));
        for internal in [
            "seat.model.set",
            "seat_model_set",
            "test-vehicle",
            approval_id.as_str(),
        ] {
            assert!(
                !wire.contains(internal),
                "internal identity leaked: {}",
                wire
            );
        }
    }
}

/// A requested approval without successful delivery must not authorize a later reply.
#[test]
fn failed_delivery_records_nothing_and_cannot_authorize() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "one", now());

    sink.fail_next(odin_hermes::discord::DiscordSendError::ServiceUnavailable);
    let error = runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .expect_err("a failed send must not record a delivery");
    assert!(
        matches!(error, odin_hermes::runtime::DeliveryError::SendFailed(_)),
        "the failure must be the typed send failure, got {error:?}"
    );
    let before = ledger.lock().conversation_deliveries().unwrap();
    assert_eq!(before.len(), 1);
    let state: serde_json::Value = serde_json::from_str(&before[0].state_json).unwrap();
    assert!(state["pending"].is_object());
    let reopened = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    assert!(
        runtime
            .deliver_approval_question(
                &reopened,
                &approval_id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None,
            )
            .is_err(),
        "unknown delivery must not retry even after reopening the ledger"
    );
    assert!(
        sink.calls.lock().is_empty(),
        "cleared fake transport failure must not permit a resend"
    );
    let after = reopened.lock().conversation_deliveries().unwrap();
    assert_eq!(after[0].revision, before[0].revision);
    assert_eq!(after[0].state_json, before[0].state_json);

    // The owner's later yes is refused: nothing was delivered.
    let outcome = runtime.decide_delivered_approval(
        &ledger,
        &auth_message(&RecordingNotifySink::message_id(100)),
        &approval_id,
        revision,
        odin_hermes::natural::OwnerDecision::AllowOnce,
        now(),
    );
    match outcome {
        Err(odin_hermes::runtime::DecisionRefusal::Undelivered(_)) => {}
        other => panic!("an undelivered question can never authorize, got {other:?}"),
    }
    let row = ledger.lock().approval(&approval_id).unwrap().unwrap();
    assert_eq!(row.status, odin_domain::ApprovalStatus::Requested,);
}
#[test]
fn delivery_to_another_channel_never_enables_the_paired_owner() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    *sink.posted_channel.lock() = Some("other-channel".to_owned());
    runtime.bind_notify_sink(sink).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "misrouted", now());
    assert!(matches!(
        runtime.deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        ),
        Err(odin_hermes::runtime::DeliveryError::SendFailed(_))
    ));
    assert!(matches!(
        runtime.decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(100)),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        ),
        Err(odin_hermes::runtime::DecisionRefusal::Undelivered(_))
    ));
    assert_eq!(
        ledger
            .lock()
            .approval(&approval_id)
            .unwrap()
            .unwrap()
            .status,
        odin_domain::ApprovalStatus::Requested,
    );
}
/// A delivered question identifies the exact request, revision, session, and conversation for decisions.
#[test]
fn delivered_question_binds_the_decision_to_the_exact_request() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "two", now());

    let delivery = runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .expect("the successful send IS the delivery");
    assert_eq!(delivery.revision, revision);
    assert_eq!(delivery.session, "run:live:test-vehicle");
    assert_eq!(delivery.seat.as_str(), "sinmara");
    assert_eq!(delivery.project.as_str(), "life");
    assert_eq!(sink.calls.lock().len(), 1);
    let question = sink.calls.lock()[0].clone();
    assert!(!question.contains(&approval_id.to_string()), "{question}");
    assert!(!question.contains("blake3"));

    // The delivered pending listing names exactly this conversation's ask.
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].approval_id, approval_id);

    // A reply bound to a DIFFERENT revision than the shown one refuses —
    // a replacement or replayed request cannot inherit the shown yes.
    let mismatch = runtime.decide_delivered_approval(
        &ledger,
        &auth_message(&RecordingNotifySink::message_id(101)),
        &approval_id,
        revision + 7,
        odin_hermes::natural::OwnerDecision::AllowOnce,
        now(),
    );
    assert!(matches!(
        mismatch,
        Err(odin_hermes::runtime::DecisionRefusal::Superseded { .. })
    ));

    // The real reply settles at the delivered revision.
    let outcome = runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(102)),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the exact delivered request authorizes");
    let approved = match outcome {
        odin_kernel::DecisionOutcome::Approved(approval) => approval,
        other => panic!("expected the durable approval, got {other:?}"),
    };
    assert_eq!(approved.approval_id, approval_id);
    let evidence = approved.decision_evidence_ref.expect("delivery evidence");
    assert!(
        evidence.starts_with("delivery:event:hermes-delivery:"),
        "the evidence must name the durable delivery proof: {evidence}"
    );
}
/// A queued `yes` written BEFORE the question was delivered can never
/// approve it, and can never approve a newer question either: the decision
/// orders the reply against the transport's own posted-question identity.
#[test]
fn queued_yes_written_before_delivery_authorizes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "queued", now());

    runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .expect("the question is delivered");
    // A reply composed BEFORE the posted question's identity: queued while
    // the surface was away, processed only after the question arrived.
    let queued = (RecordingNotifySink::FIRST_POSTED_ID - (1 << 22)).to_string();

    let outcome = runtime.decide_delivered_approval(
        &ledger,
        &auth_message(&queued),
        &approval_id,
        revision,
        odin_hermes::natural::OwnerDecision::AllowOnce,
        now(),
    );
    match outcome {
        Err(odin_hermes::runtime::DecisionRefusal::PredatesDelivery(_)) => {}
        other => panic!("a queued yes can never authorize, got {other:?}"),
    }
    let row = ledger.lock().approval(&approval_id).unwrap().unwrap();
    assert_eq!(row.status, odin_domain::ApprovalStatus::Requested);
    assert_eq!(row.revision, revision);
}
/// One authenticated reply message settles exactly ONE approval: after it
/// has durably settled one request, replaying the same message identity
/// against a different still-requested approval consumes nothing new.
#[test]
fn replayed_decision_message_cannot_settle_a_second_request() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (first_id, first_revision) = request_gate_approval(&mut ledger.lock(), "first", now());
    let (second_id, second_revision) = request_gate_approval(&mut ledger.lock(), "second", now());

    // Both questions reach the conversation; the reply postdates both.
    runtime
        .deliver_approval_question(
            &ledger,
            &first_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();
    runtime
        .deliver_approval_question(
            &ledger,
            &second_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();
    let reply = RecordingNotifySink::FIRST_POSTED_ID + (2 << 22);

    // The reply settles the first request.
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&reply.to_string()),
            &first_id,
            first_revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the reply settles the request it answers");

    // The SAME message replayed against the second (still requested)
    // approval passes ordering and state checks but is refused on its
    // durably consumed identity: one message, one settlement, forever.
    let replay = runtime.decide_delivered_approval(
        &ledger,
        &auth_message(&reply.to_string()),
        &second_id,
        second_revision,
        odin_hermes::natural::OwnerDecision::AllowOnce,
        now(),
    );
    match replay {
        Err(odin_hermes::runtime::DecisionRefusal::IntakeConsumed(_)) => {}
        other => panic!("a consumed decision message must never authorize again, got {other:?}"),
    }
    let first = ledger.lock().approval(&first_id).unwrap().unwrap();
    assert_eq!(first.status, odin_domain::ApprovalStatus::Approved);
    let second = ledger.lock().approval(&second_id).unwrap().unwrap();
    assert_eq!(second.status, odin_domain::ApprovalStatus::Requested);
    assert_eq!(second.revision, second_revision);
}
/// The settlement and its inbound-message consumption survive a ledger
/// reopen: the redelivered reply stays refused after a crash between the
/// decision and the next turn, and a legitimate later reply still settles
/// another already-delivered request.
#[test]
fn decision_intake_consumption_survives_reopen_and_later_yes_still_works() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("state")).unwrap();
    let ledger_path = dir.path().join("state").join("approval-causality.sqlite3");
    let (first_id, second_id, second_revision, reply_id) = {
        let ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let runtime = gate_runtime_with_adapter(dir.path(), ledger.clone());
        let sink = Arc::new(RecordingNotifySink::default());
        runtime.bind_notify_sink(sink.clone()).unwrap();
        create_vehicle(&mut ledger.lock(), "test-vehicle", now());
        let (first_id, first_revision) = request_gate_approval(&mut ledger.lock(), "reopen", now());
        runtime
            .deliver_approval_question(
                &ledger,
                &first_id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None,
            )
            .unwrap();
        let (second_id, second_revision) =
            request_gate_approval(&mut ledger.lock(), "replacement", now());
        runtime
            .deliver_approval_question(
                &ledger,
                &second_id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None,
            )
            .unwrap();
        let reply = RecordingNotifySink::FIRST_POSTED_ID + (10 << 22);
        runtime
            .decide_delivered_approval(
                &ledger,
                &auth_message(&reply.to_string()),
                &first_id,
                first_revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                now(),
            )
            .expect("the fresh reply settles");
        (first_id, second_id, second_revision, reply)
    };

    // "Crash": every handle drops; the durable ledger reopens.
    {
        let ledger = Arc::new(Mutex::new(Ledger::open(&ledger_path).unwrap()));
        let runtime = gate_runtime_with_adapter(dir.path(), ledger.clone());
        // The live vehicle row is durable: the reopened block reuses it
        // instead of creating a second row for the same session.
        // The redelivered OLD reply: its identity was consumed before the
        // crash, durably — it authorizes nothing, however it is bound.
        let replay = runtime.decide_delivered_approval(
            &ledger,
            &auth_message(&reply_id.to_string()),
            &second_id,
            second_revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        );
        match replay {
            Err(odin_hermes::runtime::DecisionRefusal::IntakeConsumed(_)) => {}
            other => panic!("the consumed intake must stay consumed across reopen, got {other:?}"),
        }
        // A new reply can still settle the other delivered question.
        let fresh = RecordingNotifySink::FIRST_POSTED_ID + (11 << 22);
        runtime
            .decide_delivered_approval(
                &ledger,
                &auth_message(&fresh.to_string()),
                &second_id,
                second_revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                now(),
            )
            .expect("a legitimate later reply settles the replacement");
    };
    let reopened = Ledger::open(&ledger_path).unwrap();
    let first = reopened.approval(&first_id).unwrap().unwrap();
    assert_eq!(first.status, odin_domain::ApprovalStatus::Approved);
    let second = reopened.approval(&second_id).unwrap().unwrap();
    assert_eq!(second.status, odin_domain::ApprovalStatus::Approved);
    assert_eq!(second.revision, second_revision + 1);
}
/// Filter by conversation before limiting the scan so unrelated traffic cannot hide a delivered question.
#[test]
fn unrelated_traffic_cannot_hide_a_delivered_question() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "noise", now());
    let delivery = runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();

    // Add more unrelated audit events than the scan limit, including other conversations' deliveries.
    for index in 0..300i64 {
        ledger
            .lock()
            .append_audit_event(odin_ledger::audit::NewAuditEvent {
                event_id: odin_domain::EventId::new(format!(
                    "event:noise:{}:{index}",
                    delivery.evidence_event_id
                ))
                .unwrap(),
                kind: odin_hermes::runtime::APPROVAL_DELIVERY_AUDIT_KIND.to_owned(),
                actor: odin_domain::Actor::System {
                    name: "fixture".to_owned(),
                },
                scope: odin_domain::Scope::default(),
                evidence: Vec::new(),
                payload: odin_ledger::audit::RedactedPayload::new(
                    serde_json::json!({
                        "approvalId": format!("approval:other:{index}"),
                        "revision": 1,
                        "channelId": "channel-elsewhere",
                        "ownerUserId": "owner-elsewhere",
                    }),
                    odin_domain::Redaction::None,
                )
                .unwrap(),
                occurred_at: now(),
            })
            .unwrap();
    }

    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    assert_eq!(
        pending.len(),
        1,
        "other conversations' traffic must not bury this proof"
    );
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&(RecordingNotifySink::FIRST_POSTED_ID + (1 << 22)).to_string()),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the delivered question still settles under heavy traffic");
}
/// Requests sharing id prefixes and delivery timestamps must retain distinct decidable delivery records.
#[test]
fn prefix_sharing_deliveries_never_collide() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (first_id, first_revision) =
        request_gate_approval(&mut ledger.lock(), "collision-one", now());
    let (second_id, second_revision) =
        request_gate_approval(&mut ledger.lock(), "collision-two", now());
    let shared = first_id.as_str();
    let other = second_id.as_str();
    assert_eq!(
        shared[..24.min(shared.len())],
        other[..24.min(other.len())],
        "fixture: the two ids must share their first characters"
    );

    // The SAME caller instant for both: the old prefix-truncated evidence
    // identity collided exactly here.
    let same_instant = now();
    let first = runtime
        .deliver_approval_question(
            &ledger,
            &first_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            same_instant,
            None,
        )
        .expect("the first delivery records its proof");
    let second = runtime
        .deliver_approval_question(
            &ledger,
            &second_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            same_instant,
            None,
        )
        .expect("the second delivery records its own proof");
    assert_ne!(
        first.evidence_event_id, second.evidence_event_id,
        "two deliveries may never share one evidence identity"
    );
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&(RecordingNotifySink::FIRST_POSTED_ID + (2 << 22)).to_string()),
            &first_id,
            first_revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the first request settles");
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&(RecordingNotifySink::FIRST_POSTED_ID + (3 << 22)).to_string()),
            &second_id,
            second_revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the second request settles too");
}
#[test]
fn repeated_question_in_one_clock_tick_remains_one_decidable_request() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "repeated", now());
    let instant = now();
    let mut proofs = Vec::new();
    for _ in 0..2 {
        let proof = runtime
            .deliver_approval_question(
                &ledger,
                &approval_id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                instant,
                None,
            )
            .unwrap();
        proofs.push(proof);
    }
    assert_eq!(proofs[0].evidence_event_id, proofs[1].evidence_event_id);
    assert_eq!(proofs[0].delivered_at, proofs[1].delivered_at);
    assert_eq!(proofs[0].sent_message_id, proofs[1].sent_message_id);
    assert_eq!(
        sink.calls.lock().len(),
        1,
        "same approval revision reuses durable receipt"
    );
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, instant)
        .unwrap();
    assert_eq!(pending.len(), 1, "re-asking must not manufacture ambiguity");
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(100)),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            instant,
        )
        .unwrap();
    assert_eq!(
        ledger
            .lock()
            .approval(&approval_id)
            .unwrap()
            .unwrap()
            .status,
        odin_domain::ApprovalStatus::Approved,
    );
}
#[test]
fn same_millisecond_worker_bits_cannot_authorize_a_reply() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    runtime
        .bind_notify_sink(Arc::new(RecordingNotifySink::default()))
        .unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let (approval_id, revision) = request_gate_approval(&mut ledger.lock(), "same-tick", now());
    runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();
    let same_tick = (RecordingNotifySink::FIRST_POSTED_ID | ((1 << 22) - 1)).to_string();
    assert!(matches!(
        runtime.decide_delivered_approval(
            &ledger,
            &auth_message(&same_tick),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        ),
        Err(odin_hermes::runtime::DecisionRefusal::PredatesDelivery(_))
    ));
    assert_eq!(
        ledger
            .lock()
            .approval(&approval_id)
            .unwrap()
            .unwrap()
            .status,
        odin_domain::ApprovalStatus::Requested,
    );
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(1)),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .unwrap();
    assert_eq!(
        ledger
            .lock()
            .approval(&approval_id)
            .unwrap()
            .unwrap()
            .status,
        odin_domain::ApprovalStatus::Approved,
    );
}
/// Creates the durable live vehicle the conversation approvals target:
/// bound to exactly the surface's declared seat and project.
fn create_vehicle(ledger: &mut Ledger, session: &str, now: time::OffsetDateTime) {
    // The live row's lane is a real parent row: `live_sessions.lane_id`
    // durably references `lanes`, so the fixture composes the lane first
    // through the same public ledger API production's live bridge uses —
    // exact seat and project, no raw SQL, no disabled integrity.
    odin_ledger::lane_run::create_lane(
        ledger.connection(),
        &odin_ledger::lane_run::NewLane {
            lane_id: odin_domain::LaneId::new("sinmara-life").unwrap(),
            seat_id: SeatId::new("sinmara").unwrap(),
            project_id: Some(ProjectId::new("life").unwrap()),
            template_id: "default".to_owned(),
            backend: "local_omp".to_owned(),
            created_by: "live-session".to_owned(),
            created_at: now,
            retained: false,
        },
    )
    .unwrap();
    ledger
        .create_live_session(&odin_ledger::live::NewLiveSession {
            session_id: odin_domain::SessionId::new(session).unwrap(),
            seat_id: "sinmara".to_owned(),
            project_id: "life".to_owned(),
            slice_id: "sinmara-life".to_owned(),
            lane_id: "sinmara-life".to_owned(),
            target_node_id: String::new(),
            provider: "gateway".to_owned(),
            model: "gungnir-mini".to_owned(),
            title: None,
            manifest: serde_json::json!({}),
            open_tab: false,
            state: "ready".to_owned(),
            created_at: now,
        })
        .unwrap();
}
fn auth_message(message_id: &str) -> odin_hermes::runtime::AuthenticatedOwnerMessage {
    odin_hermes::runtime::AuthenticatedOwnerMessage {
        owner_user_id: INTENT_OWNER.to_owned(),
        channel_id: INTENT_DM_CHANNEL.to_owned(),
        message_id: message_id.to_owned(),
        seat: SeatId::new("sinmara").unwrap(),
        project: ProjectId::new("life").unwrap(),
        content: "yes".to_owned(),
    }
}

#[test]
fn an_approval_question_carries_the_journaled_request_detail() {
    use crate::fixtures::{
        conversation_ownership, discord_settings, fixture_bound_projects, intake_contract,
        owner_ask_contract,
    };
    use odin_domain::{ApprovalId, CapabilityId, CommandId, EffectClass};
    use odin_hermes::runtime::{HermesLedgers, HermesRuntime};
    use std::collections::BTreeMap;

    let dir = tempfile::tempdir().unwrap();
    let ask = owner_ask_contract();
    let contracts = BTreeMap::from([
        (
            CapabilityId::new("discord.intake").unwrap(),
            intake_contract(EffectClass::R1),
        ),
        (ask.id.clone(), ask.clone()),
    ]);
    let settings = odin_hermes::config::HermesSettings::new(
        dir.path().join("state"),
        Some(discord_settings()),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let runtime = HermesRuntime::open(
        settings,
        HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: Arc::clone(&ledger),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        None,
        8_192,
        fixture_bound_projects(),
        Some(conversation_ownership()),
    )
    .unwrap();
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let arguments = serde_json::json!({
        "task": "Open a Hinge-only browser pod for 15 minutes and send at most 10 likes",
        "minutes": 15,
    });
    let approval_id = ApprovalId::new("approval:plan-question").unwrap();
    let mut approved = arguments.clone();
    approved["approvalId"] = serde_json::json!(approval_id.as_str());
    ledger
        .lock()
        .record_command(&odin_ledger::command::CommandSpec {
            id: CommandId::new("command:plan-request").unwrap(),
            idempotency_key: "plan-request".to_owned(),
            correlation_id: "plan-request".to_owned(),
            causation_id: None,
            issuer: "sinmara".to_owned(),
            approval_id: None,
            target_kind: "run".to_owned(),
            target_id: "run:live:test-vehicle".to_owned(),
            capability_id: ask.id.clone(),
            capability_version: 1,
            arguments_hash: odin_kernel::arguments_digest(&arguments),
            arguments: arguments.clone(),
            expected_desired_revision: None,
            issued_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap();
    ledger
        .lock()
        .request_approval(odin_ledger::approval::NewApproval {
            approval_id: approval_id.clone(),
            issuer: "sinmara".to_owned(),
            scope: odin_ledger::approval::ApprovalScope {
                target_kind: "run".to_owned(),
                target_id: "run:live:test-vehicle".to_owned(),
                capability_id: ask.id.clone(),
                arguments_digest: odin_kernel::arguments_digest(&approved),
            },
            requested_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap();
    runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();
    let calls = sink.calls.lock();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0].contains("Hinge-only browser pod for 15 minutes"),
        "the plan must be in the question: {}",
        calls[0]
    );
}

/// A worker's question requires its conversation vehicle for delivery and decision.
#[test]
fn a_delegated_workers_approval_is_delivered_and_decided_through_the_vehicle() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = gate_runtime(dir.path());
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("approvals.sqlite3")).unwrap(),
    ));
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    {
        let mut guard = ledger.lock();
        odin_ledger::lane_run::create_lane(
            guard.connection(),
            &odin_ledger::lane_run::NewLane {
                lane_id: odin_domain::LaneId::new("kubert-odin").unwrap(),
                seat_id: SeatId::new("kubert").unwrap(),
                project_id: Some(ProjectId::new("odin").unwrap()),
                template_id: "default".to_owned(),
                backend: "local_omp".to_owned(),
                created_by: "live-session".to_owned(),
                created_at: now(),
                retained: false,
            },
        )
        .unwrap();
        guard
            .create_live_session(&odin_ledger::live::NewLiveSession {
                session_id: odin_domain::SessionId::new("test-child").unwrap(),
                seat_id: "kubert".to_owned(),
                project_id: "odin".to_owned(),
                slice_id: "kubert-ops".to_owned(),
                lane_id: "kubert-odin".to_owned(),
                target_node_id: String::new(),
                provider: "gateway".to_owned(),
                model: "kubert-mini".to_owned(),
                title: None,
                manifest: serde_json::json!({}),
                open_tab: false,
                state: "ready".to_owned(),
                created_at: now(),
            })
            .unwrap();
    }
    let approval_id = odin_domain::ApprovalId::new("approval:gate:child").unwrap();
    let revision = ledger
        .lock()
        .request_approval(odin_ledger::approval::NewApproval {
            approval_id: approval_id.clone(),
            issuer: "kubert".to_owned(),
            scope: odin_ledger::approval::ApprovalScope {
                target_kind: "run".to_owned(),
                target_id: "run:live:test-child".to_owned(),
                capability_id: odin_domain::CapabilityId::new("seat.ask.gungnir").unwrap(),
                arguments_digest: odin_kernel::arguments_digest(&serde_json::json!({"x": 1})),
            },
            requested_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap()
        .revision;

    assert!(matches!(
        runtime.deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        ),
        Err(odin_hermes::runtime::DeliveryError::TargetUnbound)
    ));
    runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            Some("run:live:test-vehicle"),
        )
        .expect("the worker's question is delivered through the vehicle");
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    assert_eq!(pending.len(), 1);
    let outcome = runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(102)),
            &approval_id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now(),
        )
        .expect("the owner decides the worker's question");
    assert!(matches!(outcome, odin_kernel::DecisionOutcome::Approved(_)));
}

/// Only local JMAP method replies are scripted; draft receipts are produced
/// through the real adapter and resolved by the runtime's composed adapter.
struct BatchDraftExchange;

impl odin_hermes::jmap::JmapExchange for BatchDraftExchange {
    fn readiness(&self) -> Result<(), odin_hermes::account::TransportFault> {
        Ok(())
    }

    fn exchange(
        &self,
        request: &odin_hermes::jmap::JmapRequest,
        _lease: &odin_hermes::account::ScopedCredentialLease,
    ) -> Result<odin_hermes::jmap::JmapResponse, odin_hermes::account::TransportFault> {
        assert_eq!(request.method_calls.len(), 1);
        Ok(odin_hermes::jmap::JmapResponse {
            responses: vec![odin_hermes::jmap::JmapResponseCall {
                name: "Email/set".into(),
                arguments: serde_json::json!({"created":{"draft":{"id":"immutable-draft"}}}),
                call_id: "s".into(),
            }],
        })
    }
}

fn batch_preview_runtime(
    dir: &std::path::Path,
    ledger: Arc<Mutex<Ledger>>,
) -> (
    Arc<odin_hermes::runtime::HermesRuntime>,
    serde_json::Value,
    odin_hermes::email::EmailDraft,
) {
    use crate::fixtures::{
        conversation_ownership, discord_settings, fixture_bound_projects, intake_contract,
        owner_ask_contract,
    };
    use odin_hermes::config::{HermesSettings, LifeAccountSettings, LifeProviderSettings};
    use std::collections::BTreeMap;
    let secret_path = dir.join("mail.secret");
    std::fs::write(&secret_path, "fixture-secret").unwrap();
    let mut contracts = BTreeMap::new();
    for contract in [
        owner_ask_contract(),
        intake_contract(odin_domain::EffectClass::R1),
    ] {
        contracts.insert(contract.id.clone(), contract);
    }
    for (name, description) in [
        ("task.grant", "Approve this exact batch"),
        ("email.send", "Send this email"),
        ("browser.consequential", "Perform this browser action"),
    ] {
        let mut contract = owner_ask_contract();
        contract.id = odin_domain::CapabilityId::new(name).unwrap();
        contract.delegate_to = None;
        contract.description = description.into();
        match name {
            "task.grant" => {
                contract.preview = Some(odin_registry::schema::PreviewKindToml::Batch);
                contract.batch = Some(odin_registry::schema::BatchLimitsToml {
                    max_effects: 16,
                    max_minutes: 1440,
                    max_uses: 500,
                });
            }
            "email.send" => {
                contract.preview = Some(odin_registry::schema::PreviewKindToml::Email);
                contract.batchable = true;
            }
            "browser.consequential" => {
                contract.preview = Some(odin_registry::schema::PreviewKindToml::Browser);
                contract.batchable = true;
            }
            _ => {}
        }
        contracts.insert(contract.id.clone(), contract);
    }
    let settings = HermesSettings::new(
        dir.join("state"),
        Some(discord_settings()),
        None,
        None,
        vec![LifeAccountSettings {
            account: "personal".into(),
            secret_handle: "cred:batch-mail".into(),
            secret_path: secret_path.clone(),
            provider: LifeProviderSettings::Jmap {
                session_url: "https://mail.invalid/session".into(),
                identity_id: "identity".into(),
                from_address: "owner@example.test".into(),
                drafts_mailbox_id: "drafts".into(),
                archive_mailbox_id: "archive".into(),
                trash_mailbox_id: "trash".into(),
                calendar_id: None,
                request_timeout_ms: 1000,
                max_response_bytes: 65536,
            },
        }],
    )
    .unwrap();
    let runtime = odin_hermes::runtime::HermesRuntime::open(
        settings,
        odin_hermes::runtime::HermesLedgers {
            conversation: Ledger::open_in_memory().unwrap(),
            adapter: ledger.clone(),
            purchase: Arc::new(std::sync::Mutex::new(Ledger::open_in_memory().unwrap())),
        },
        &contracts,
        None,
        8192,
        fixture_bound_projects(),
        Some(conversation_ownership()),
    )
    .unwrap();
    let leases = odin_hermes::account::FileCredentialLeases::new(BTreeMap::from([(
        "personal".into(),
        odin_hermes::account::AccountSecretRef::new(
            odin_domain::huginn::OpaqueCredentialHandle::new("cred:batch-mail").unwrap(),
            secret_path,
        )
        .unwrap(),
    )]));
    let transport =
        odin_hermes::email::JmapEmailTransport::new(odin_hermes::email::JmapMailConfig {
            account_id: "personal".into(),
            identity_id: "identity".into(),
            from_address: "owner@example.test".into(),
            drafts_mailbox_id: "drafts".into(),
            archive_mailbox_id: "archive".into(),
            trash_mailbox_id: "trash".into(),
            exchange: Arc::new(BatchDraftExchange),
        })
        .unwrap();
    let adapter = odin_hermes::email::EmailAdapter::new(
        ledger,
        Arc::new(transport),
        Arc::new(leases),
        odin_hermes::runtime::RUNTIME_ISSUER,
    );
    let draft = odin_hermes::email::EmailDraft {
        account: "personal".into(),
        to: vec!["first@example.test".into(), "last@example.test".into()],
        subject: "Exact content beyond the old clipping boundary".into(),
        body_text: format!(
            "{}\nFinal approved paragraph.\n",
            "A complete approved paragraph. ".repeat(150)
        ),
    };
    let receipt = adapter
        .save_draft(
            &odin_hermes::account::EffectIdentity {
                idempotency_key: "batch-draft".into(),
                correlation_id: "batch-draft".into(),
            },
            &draft,
            now(),
        )
        .unwrap();
    let arguments = serde_json::json!({"account":"personal", "draft_id":receipt.result["draftId"], "draft_digest":receipt.result["draftDigest"]});
    (runtime, arguments, draft)
}

fn request_exact_batch(
    ledger: &mut Ledger,
    name: &str,
    arguments: serde_json::Value,
) -> (odin_domain::ApprovalId, i64, serde_json::Value) {
    let approval_id = odin_domain::ApprovalId::new(format!("approval:batch:{name}")).unwrap();
    ledger
        .record_command(&odin_ledger::command::CommandSpec {
            id: odin_domain::CommandId::new(format!("command:batch:{name}")).unwrap(),
            idempotency_key: name.into(),
            correlation_id: name.into(),
            causation_id: None,
            issuer: "sinmara".into(),
            approval_id: None,
            target_kind: "run".into(),
            target_id: "run:live:test-vehicle".into(),
            capability_id: odin_domain::CapabilityId::new("task.grant").unwrap(),
            capability_version: 1,
            arguments_hash: odin_kernel::arguments_digest(&arguments),
            arguments: arguments.clone(),
            expected_desired_revision: None,
            issued_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap();
    let mut retry = arguments;
    retry["approvalId"] = serde_json::json!(approval_id.as_str());
    let approval = ledger
        .request_approval(odin_ledger::approval::NewApproval {
            approval_id: approval_id.clone(),
            issuer: "sinmara".into(),
            scope: odin_ledger::approval::ApprovalScope {
                target_kind: "run".into(),
                target_id: "run:live:test-vehicle".into(),
                capability_id: odin_domain::CapabilityId::new("task.grant").unwrap(),
                arguments_digest: odin_kernel::arguments_digest(&retry),
            },
            requested_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap();
    (approval_id, approval.revision, retry)
}

#[test]
fn exact_batch_delivers_every_byte_before_owner_decision_and_mints_witnessed_grant() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    let (runtime, email, draft) = batch_preview_runtime(dir.path(), ledger.clone());
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let browser = serde_json::json!({
        "sessionId":"00000000-0000-4000-8000-0000000000b1", "expectedRevision":19,
        "action":"submitForm", "arguments":{"selector":"#approved-form"},
        "argumentsDigest":odin_domain::Digest::hash(b"typed-action").to_string(),
        "policyRevision":7, "policyDigest":odin_domain::Digest::hash(b"bound-policy").to_string(),
    });
    let (approval_id, revision, retry) = request_exact_batch(
        &mut ledger.lock(),
        "complete",
        serde_json::json!({
            "task":"This prose must not replace the exact effects", "minutes":17, "max_uses":2,
            "effects":[{"capability":"email.send","arguments":email}, {"capability":"email.send","arguments":email}, {"capability":"browser.consequential","arguments":browser}],
        }),
    );
    let delivered = runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
            None,
        )
        .unwrap();
    let calls = sink.calls.lock().clone();
    assert!(calls.len() > 2);
    let wire = calls.concat();
    let snapshot = serde_json::to_string_pretty(&draft).unwrap();
    assert_eq!(
        wire.matches(&snapshot).count(),
        2,
        "both complete exact snapshots must reach the owner"
    );
    assert!(!wire.contains("This prose must not replace"));
    let pending = runtime
        .delivered_pending_approvals(&ledger, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    assert_eq!(pending.len(), 1);
    let detail = pending[0].detail.as_deref().unwrap();
    assert_eq!(
        wire,
        odin_hermes::natural::approval_question("Approve this exact batch", Some(detail))
    );
    assert!(detail.contains("17 minutes"));
    assert!(detail.contains("2 total uses"));
    assert!(detail.rfind(&snapshot).unwrap() > 240);
    assert!(detail.contains(&serde_json::to_string(&draft.body_text).unwrap()));
    assert!(wire.ends_with(&format!(
        "{}?",
        serde_json::to_string_pretty(&browser).unwrap()
    )));
    let stored = ledger.lock().conversation_deliveries().unwrap();
    let checkpoint: serde_json::Value = serde_json::from_str(&stored[0].state_json).unwrap();
    assert_eq!(checkpoint["target"], serde_json::json!(calls));
    assert_eq!(checkpoint["phase"], "committed");
    assert_eq!(
        delivered.sent_message_id,
        RecordingNotifySink::message_id(calls.len() as u64 - 1)
    );
    for offset in [0, 1, calls.len() as u64 - 1] {
        assert!(matches!(
            runtime.decide_delivered_approval(
                &ledger,
                &auth_message(&RecordingNotifySink::message_id(offset)),
                &approval_id,
                revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                now()
            ),
            Err(odin_hermes::runtime::DecisionRefusal::PredatesDelivery(_))
        ));
    }
    assert!(matches!(
        runtime
            .decide_delivered_approval(
                &ledger,
                &auth_message(&RecordingNotifySink::message_id(calls.len() as u64)),
                &approval_id,
                revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                now()
            )
            .unwrap(),
        odin_kernel::DecisionOutcome::Approved(_)
    ));
    let mut guard = ledger.lock();
    let approved = guard.approval(&approval_id).unwrap().unwrap();
    assert!(guard.approval_has_owner_decision(&approved, true).unwrap());
    let command_id = odin_domain::CommandId::new("command:batch:consume").unwrap();
    guard
        .record_command(&odin_ledger::command::CommandSpec {
            id: command_id.clone(),
            idempotency_key: "batch-consume".into(),
            correlation_id: "batch-consume".into(),
            causation_id: None,
            issuer: "sinmara".into(),
            approval_id: Some(approval_id.clone()),
            target_kind: approved.scope.target_kind.clone(),
            target_id: approved.scope.target_id.clone(),
            capability_id: approved.scope.capability_id.clone(),
            capability_version: 1,
            arguments_hash: odin_kernel::arguments_digest(&retry),
            arguments: retry.clone(),
            expected_desired_revision: None,
            issued_at: now(),
            expires_at: now() + time::Duration::hours(1),
        })
        .unwrap();
    odin_kernel::ApprovalGate::new(&mut guard)
        .authorize_command(
            odin_domain::EffectClass::R3,
            odin_kernel::ApprovalCommand {
                command_id: &command_id,
                approval_id: Some(&approval_id),
                scope: &approved.scope,
                expected_revision: Some(approved.revision),
                now: now(),
            },
        )
        .unwrap();
    let limits = odin_registry::schema::BatchLimitsToml {
        max_effects: 16,
        max_minutes: 1440,
        max_uses: 500,
    };
    let batchable = std::collections::BTreeSet::from([
        odin_domain::CapabilityId::new("email.send").unwrap(),
        odin_domain::CapabilityId::new("browser.consequential").unwrap(),
    ]);
    let grant = odin_omp::host_tools::task_grants::TaskGrant::from_approval(
        &guard,
        &approval_id,
        odin_domain::SessionId::new("test-vehicle").unwrap(),
        limits,
        &batchable,
    )
    .unwrap()
    .unwrap();
    assert_eq!(grant.request, Some(retry));
    assert_eq!(grant.max_uses, 2);
    assert_eq!(grant.reservations.len(), 3);
    assert_eq!(
        grant.expires_at_ms,
        u64::try_from(approved.decided_at.unwrap().unix_timestamp_nanos() / 1_000_000).unwrap()
            + 17 * 60_000
    );
}

#[test]
fn exact_batch_refuses_unbound_account_digest_and_incomplete_snapshot_before_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    let (runtime, email, _) = batch_preview_runtime(dir.path(), ledger.clone());
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    for (index, key, value) in [
        (0, "account", serde_json::json!("other")),
        (
            1,
            "draft_digest",
            serde_json::json!(odin_domain::Digest::hash(b"wrong").to_string()),
        ),
        (2, "draft_digest", serde_json::Value::Null),
    ] {
        let mut invalid = email.clone();
        invalid[key] = value;
        let (id, revision, _) = request_exact_batch(
            &mut ledger.lock(),
            &index.to_string(),
            serde_json::json!({
                "task":"Do not fall back to this prose", "minutes":17, "max_uses":2,
                "effects":[{"capability":"email.send","arguments":email}, {"capability":"email.send","arguments":invalid}],
            }),
        );
        assert!(matches!(
            runtime.deliver_approval_question(
                &ledger,
                &id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None
            ),
            Err(odin_hermes::runtime::DeliveryError::SnapshotUnavailable(_))
        ));
        assert!(matches!(
            runtime.decide_delivered_approval(
                &ledger,
                &auth_message(&RecordingNotifySink::message_id(100)),
                &id,
                revision,
                odin_hermes::natural::OwnerDecision::AllowOnce,
                now()
            ),
            Err(odin_hermes::runtime::DecisionRefusal::Undelivered(_))
        ));
    }
    assert!(sink.calls.lock().is_empty());
    assert!(ledger.lock().conversation_deliveries().unwrap().is_empty());
}

/// Injects an unknown outcome at the second physical reservation, after
/// the first chunk has landed through the ordinary checkpointed sink.
struct InterruptedBatchSink(Arc<RecordingNotifySink>);

struct InterruptAfterFirst {
    inner: Arc<dyn odin_hermes::egress::DeliveryCheckpoint>,
    reservations: std::sync::atomic::AtomicUsize,
}

impl odin_hermes::egress::DeliveryCheckpoint for InterruptAfterFirst {
    fn prepare(
        &self,
        message: &odin_hermes::egress::OutboundMessage,
    ) -> Result<odin_hermes::egress::DeliveryPlan, odin_hermes::egress::EgressError> {
        self.inner.prepare(message)
    }
    fn reserve(
        &self,
        operation: &odin_hermes::egress::DeliveryOperation,
    ) -> Result<odin_hermes::egress::DeliveryReservation, odin_hermes::egress::EgressError> {
        let reservation = self.inner.reserve(operation)?;
        if self
            .reservations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            let error = odin_hermes::discord::DiscordSendError::ServiceUnavailable;
            self.inner.failed(&reservation, &error)?;
            return Err(odin_hermes::egress::EgressError::Transport(error));
        }
        Ok(reservation)
    }
    fn acknowledge(
        &self,
        reservation: &odin_hermes::egress::DeliveryReservation,
        reference: Option<&odin_hermes::discord::DiscordMessageRef>,
    ) -> Result<(), odin_hermes::egress::EgressError> {
        self.inner.acknowledge(reservation, reference)
    }
    fn failed(
        &self,
        reservation: &odin_hermes::egress::DeliveryReservation,
        error: &odin_hermes::discord::DiscordSendError,
    ) -> Result<(), odin_hermes::egress::EgressError> {
        self.inner.failed(reservation, error)
    }
    fn complete(&self) -> Result<(), odin_hermes::egress::EgressError> {
        self.inner.complete()
    }
}

#[async_trait::async_trait]
impl odin_hermes::egress::OutgoingSink for InterruptedBatchSink {
    async fn deliver(
        &self,
        message: odin_hermes::egress::OutboundMessage,
        checkpoint: Arc<dyn odin_hermes::egress::DeliveryCheckpoint>,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        self.0
            .deliver(
                message,
                Arc::new(InterruptAfterFirst {
                    inner: checkpoint,
                    reservations: std::sync::atomic::AtomicUsize::new(0),
                }),
            )
            .await
    }
    async fn send(
        &self,
        message: odin_hermes::egress::OutboundMessage,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        self.0.send(message).await
    }
    async fn edit(
        &self,
        current: &odin_hermes::egress::ReplyChunks,
        message: odin_hermes::egress::OutboundMessage,
    ) -> Result<odin_hermes::egress::ReplyChunks, odin_hermes::egress::EgressError> {
        self.0.edit(current, message).await
    }
    async fn typing(&self, channel: &str) -> Result<(), odin_hermes::egress::EgressError> {
        self.0.typing(channel).await
    }
}

#[test]
fn partial_exact_batch_never_records_consent_or_resends_unknown_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    let (runtime, email, _) = batch_preview_runtime(dir.path(), ledger.clone());
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime
        .bind_notify_sink(Arc::new(InterruptedBatchSink(sink.clone())))
        .unwrap();
    let (id, revision, _) = request_exact_batch(
        &mut ledger.lock(),
        "partial",
        serde_json::json!({
            "task":"batch", "minutes":17, "max_uses":2,
            "effects":[{"capability":"email.send","arguments":email}, {"capability":"email.send","arguments":email}],
        }),
    );
    assert!(runtime
        .deliver_approval_question(&ledger, &id, INTENT_DM_CHANNEL, INTENT_OWNER, now(), None)
        .is_err());
    assert_eq!(sink.calls.lock().len(), 1);
    assert!(matches!(
        runtime.decide_delivered_approval(
            &ledger,
            &auth_message(&RecordingNotifySink::message_id(100)),
            &id,
            revision,
            odin_hermes::natural::OwnerDecision::AllowOnce,
            now()
        ),
        Err(odin_hermes::runtime::DecisionRefusal::Undelivered(_))
    ));
    let reopened = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    assert!(runtime
        .deliver_approval_question(&reopened, &id, INTENT_DM_CHANNEL, INTENT_OWNER, now(), None)
        .is_err());
    assert_eq!(sink.calls.lock().len(), 1);
    let guard = ledger.lock();
    assert!(!guard
        .approval_has_owner_decision(&guard.approval(&id).unwrap().unwrap(), true)
        .unwrap());
}

#[test]
fn task_prose_without_exact_effects_never_becomes_an_approval_question() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    let (runtime, _, _) = batch_preview_runtime(dir.path(), ledger.clone());
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    for (index, request) in [
        serde_json::json!({"task":"Send all drafts", "minutes":17, "max_uses":2}),
        serde_json::json!({"task":"Send all drafts", "minutes":17, "max_uses":2, "effects":[]}),
        serde_json::json!({"task":"Click submit", "minutes":17, "max_uses":1, "effects":[{"capability":"browser.consequential", "arguments":{"action":"submitForm", "arguments":{"selector":"#send"}}}]}),
    ].into_iter().enumerate() {
        let (id, _, _) = request_exact_batch(&mut ledger.lock(), &format!("missing-{index}"), request);
        assert!(matches!(runtime.deliver_approval_question(&ledger, &id, INTENT_DM_CHANNEL, INTENT_OWNER, now(), None), Err(odin_hermes::runtime::DeliveryError::SnapshotUnavailable(_))));
    }
    assert!(sink.calls.lock().is_empty());
}

#[test]
fn exact_browser_preview_refuses_missing_bindings_invalid_pairings_and_scrubbed_content() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Arc::new(Mutex::new(
        Ledger::open(dir.path().join("batch.sqlite3")).unwrap(),
    ));
    let (runtime, _, _) = batch_preview_runtime(dir.path(), ledger.clone());
    create_vehicle(&mut ledger.lock(), "test-vehicle", now());
    let sink = Arc::new(RecordingNotifySink::default());
    runtime.bind_notify_sink(sink.clone()).unwrap();
    let browser = serde_json::json!({
        "sessionId":"00000000-0000-4000-8000-0000000000b1", "expectedRevision":19,
        "action":"submitForm", "arguments":{"selector":"#approved-form"},
        "argumentsDigest":odin_domain::Digest::hash(b"typed-action").to_string(),
        "policyRevision":7, "policyDigest":odin_domain::Digest::hash(b"bound-policy").to_string(),
    });
    for (index, key, value) in [
        (0, "policyDigest", serde_json::Value::Null),
        (
            1,
            "arguments",
            serde_json::json!({"url":"https://example.test"}),
        ),
        (
            2,
            "arguments",
            serde_json::json!({"selector":"cred:protected-material"}),
        ),
    ] {
        let mut invalid = browser.clone();
        invalid[key] = value;
        let (id, _, _) = request_exact_batch(
            &mut ledger.lock(),
            &format!("browser-{index}"),
            serde_json::json!({
                "task":"Act", "minutes":17, "max_uses":1,
                "effects":[{"capability":"browser.consequential", "arguments":invalid}],
            }),
        );
        assert!(matches!(
            runtime.deliver_approval_question(
                &ledger,
                &id,
                INTENT_DM_CHANNEL,
                INTENT_OWNER,
                now(),
                None
            ),
            Err(odin_hermes::runtime::DeliveryError::SnapshotUnavailable(_))
        ));
    }
    assert!(sink.calls.lock().is_empty());
    assert!(ledger.lock().conversation_deliveries().unwrap().is_empty());
}
