//! Device decisions on delivered root-plan questions.
use super::*;
use odin_domain::{RunId, SessionId};

#[tokio::test]
async fn delivered_root_plan_button_accepts_once_and_replays_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite3");
    let ledger = Arc::new(Mutex::new(Ledger::open(&path).unwrap()));
    let now = OffsetDateTime::now_utc();
    let run = RunId::new("run:live:button-test").unwrap();
    let id = {
        let mut guard = ledger.lock().unwrap();
        guard.connection().execute_batch("INSERT INTO lanes(lane_id, seat_id, template_id, backend, status, created_by, created_at, updated_at) VALUES ('lane:button', 'seat:test', 'template:test', 'local_omp', 'desired', 'test', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z'); INSERT INTO runs(run_id, lane_id, attempt_number, status, input_hash, created_at, updated_at) VALUES ('run:live:button-test', 'lane:button', 1, 'pending', 'hash', '1970-01-01T00:00:00Z', '1970-01-01T00:00:00Z');").unwrap();
        let plan = guard
            .replace_plan(&run, "Review the incident", &[], 0, now)
            .unwrap();
        guard
            .request_root_plan_consent(
                &run,
                &SessionId::new("button-test").unwrap(),
                "sinmara",
                plan.revision,
                &plan.objective,
                now,
            )
            .unwrap()
    };
    let replay = odin_huginn::streams::DurableReplayStore::open(
        dir.path().join("replay.sqlite3"),
        256,
        1 << 20,
    )
    .unwrap();
    let port = RuntimeCommandPort::new(
        ledger.clone(),
        Arc::new(odin_huginn::read_model::MaterializedReadModel::with_limits(
            1024, 2048, now,
        )),
        None,
        Arc::new(odin_huginn::streams::BoundedMultiplexer::new(
            replay, 64, 64,
        )),
        None,
        live::StreamBackpressureLimits {
            max_buffered_items: std::num::NonZeroU32::new(64).unwrap(),
            max_buffered_bytes: NonZeroU64::new(64 << 20).unwrap(),
            max_item_bytes: NonZeroU64::new(1 << 20).unwrap(),
            max_items_per_second: std::num::NonZeroU32::new(256).unwrap(),
            max_in_flight_bytes: NonZeroU64::new(64 << 20).unwrap(),
        },
    );
    let approval = ledger.lock().unwrap().approval(&id).unwrap().unwrap();
    let device = live::DeviceId::parse("00000000-0000-4000-8000-0000000000a1").unwrap();
    let command = live::HuginnRequest::ApprovalDecision(live::ApprovalDecisionCommand {
        command_id: odin_domain::CommandId::new("button-root-plan").unwrap(),
        approval_id: id.clone(),
        expected_revision: approval.revision as u64,
        decision: live::ApprovalDecision::Approve,
    });
    assert!(
        port.execute_authenticated(device, command.clone())
            .await
            .is_err(),
        "button cannot bypass delivery"
    );
    let payload = serde_json::json!({"approvalId": id.as_str(), "revision": approval.revision,
        "capabilityId": "plan.root-consent", "session": approval.scope.target_id,
        "argumentsDigest": approval.scope.arguments_digest.to_string(), "completeSnapshot": true});
    ledger
        .lock()
        .unwrap()
        .append_audit_event(odin_ledger::audit::NewAuditEvent {
            event_id: odin_domain::EventId::new("event:root-button-delivery").unwrap(),
            kind: odin_ledger::approval::OWNER_PREVIEW_DELIVERY_KIND.to_owned(),
            actor: odin_domain::Actor::System {
                name: "odin-hermes.runtime".to_owned(),
            },
            scope: odin_domain::Scope::default(),
            evidence: Vec::new(),
            payload: odin_ledger::audit::RedactedPayload::new(
                payload,
                odin_domain::Redaction::None,
            )
            .unwrap(),
            occurred_at: now,
        })
        .unwrap();
    port.execute_authenticated(device, command.clone())
        .await
        .unwrap();
    assert!(ledger.lock().unwrap().plan_is_accepted(&run).unwrap());
    assert!(matches!(
        port.execute_authenticated(device, command).await.unwrap(),
        live::HuginnResponse::Command(live::CommandReceipt::Duplicate { .. })
    ));
    drop(port);
    drop(ledger);
    let reopened = Ledger::open(&path).unwrap();
    assert!(reopened.plan_is_accepted(&run).unwrap());
    assert!(reopened.root_plan_consent(&id).unwrap().unwrap().applied);
}
