//! The delivery authorization seam: only a delivered, exactly-matched, unreplayed decision can authorize a request.

use crate::runtime::fixtures::{
    gate_runtime, now, request_gate_approval, RecordingNotifySink, INTENT_DM_CHANNEL, INTENT_OWNER,
};
use odin_domain::{ProjectId, SeatId};
use odin_ledger::Ledger;
use parking_lot::Mutex;
use std::sync::Arc;

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
        )
        .expect("the successful send IS the delivery");
    assert_eq!(delivery.revision, revision);
    assert_eq!(delivery.session, "run:live:test-vehicle");
    assert_eq!(delivery.seat.as_str(), "sinmara");
    assert_eq!(delivery.project.as_str(), "home");
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
        Ok(odin_kernel::DecisionOutcome::Redirect(
            odin_kernel::ApprovalRedirect::StaleRevision { .. }
        ))
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
        .deliver_approval_question(&ledger, &first_id, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    runtime
        .deliver_approval_question(&ledger, &second_id, INTENT_DM_CHANNEL, INTENT_OWNER, now())
        .unwrap();
    let reply = RecordingNotifySink::message_id(2);

    // The reply settles the first request.
    runtime
        .decide_delivered_approval(
            &ledger,
            &auth_message(&reply),
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
        &auth_message(&reply),
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
/// Creates the durable live vehicle the conversation approvals target:
/// bound to exactly the surface's declared seat and project.
pub(crate) fn create_vehicle(ledger: &mut Ledger, session: &str, now: time::OffsetDateTime) {
    // The live row's lane is a real parent row: `live_sessions.lane_id`
    // durably references `lanes`, so the fixture composes the lane first
    // through the same public ledger API production's live bridge uses —
    // exact seat and project, no raw SQL, no disabled integrity.
    odin_ledger::lane_run::create_lane(
        ledger.connection(),
        &odin_ledger::lane_run::NewLane {
            lane_id: odin_domain::LaneId::new("sinmara-life").unwrap(),
            seat_id: SeatId::new("sinmara").unwrap(),
            project_id: Some(ProjectId::new("home").unwrap()),
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
            project_id: "home".to_owned(),
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
        project: ProjectId::new("home").unwrap(),
        content: "yes".to_owned(),
    }
}

/// A worker's question is delivered to the owner and decided like any other.
#[test]
fn a_delegated_workers_approval_is_delivered_and_decided() {
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

    runtime
        .deliver_approval_question(
            &ledger,
            &approval_id,
            INTENT_DM_CHANNEL,
            INTENT_OWNER,
            now(),
        )
        .expect("the worker's question is delivered");
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

