//! Durable lane and run lifecycle and approval linkage invariants.

use super::*;
use crate::approval::{ApprovalDecision, ApprovalScope, ApprovalWire, DecideApproval, NewApproval};
use crate::incident::{
    ConfidenceMicros, EvidenceRefs, IncidentCardWire, IncidentObservation, IncidentSeverity,
    IncidentStatus, TransitionIncident,
};
use crate::plan::{PlanWire, TodoSpec, TodoStatus};
use crate::revision::transition_lane_at;
use crate::Ledger;
use odin_domain::{ApprovalId, CapabilityId, Digest, IncidentId, TodoId};
use serde_json::{json, Value};
use time::Duration;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_767_312_000).expect("valid timestamp")
}

fn db() -> Connection {
    let connection = Connection::open_in_memory().expect("open");
    connection.execute_batch(
            "CREATE TABLE runs(run_id TEXT PRIMARY KEY,status TEXT,revision INTEGER,started_at TEXT,ended_at TEXT,updated_at TEXT);
             CREATE TABLE attempts(attempt_id TEXT PRIMARY KEY,status TEXT,revision INTEGER,started_at TEXT,ended_at TEXT,updated_at TEXT);
             INSERT INTO runs VALUES('run:one','pending',1,NULL,NULL,'x');
             INSERT INTO attempts VALUES('attempt:one','orphaned',7,NULL,NULL,'x');"
        ).expect("schema");
    connection
}

#[test]
fn legal_transitions() {
    let connection = db();
    let run = RunId::parse("run:one").expect("run id");
    assert_eq!(
        transition_run(&connection, &run, RunStatus::Planning, 1, now()).expect("run"),
        2
    );
    let attempt = AttemptId::parse("attempt:one").expect("attempt id");
    assert_eq!(
        transition_attempt(&connection, &attempt, AttemptStatus::Recovering, 7, now())
            .expect("attempt"),
        8
    );
}

fn roundtrip_apply(target: &mut Value, mutation: &Value) {
    let (Some(target), Some(source)) = (target.as_object_mut(), mutation.as_object()) else {
        panic!("mutations must be JSON objects applied to JSON objects");
    };
    for (key, value) in source {
        target.insert(key.clone(), value.clone());
    }
}

fn roundtrip_rename_key(value: &mut Value, from: &str, to: &str) {
    let object = value
        .as_object_mut()
        .expect("renamed value must be an object");
    let moved = object.remove(from).expect("renamed key must exist");
    object.insert(to.to_owned(), moved);
}

fn seed_roundtrip_fixture(ledger: &mut Ledger) -> (LaneId, RunId, ApprovalId, IncidentId) {
    let lane_id = LaneId::new("lane:roundtrip").unwrap();
    let run_id = RunId::new("run:roundtrip").unwrap();
    let approval_id = ApprovalId::new("approval:roundtrip").unwrap();
    let incident_id = IncidentId::new("incident:roundtrip").unwrap();

    create_lane(
        ledger.connection(),
        &NewLane {
            lane_id: lane_id.clone(),
            seat_id: SeatId::new("seat:roundtrip").unwrap(),
            project_id: None,
            template_id: "template:roundtrip".to_owned(),
            backend: "local_omp".to_owned(),
            created_by: "operator".to_owned(),
            created_at: now(),
            retained: false,
        },
    )
    .unwrap();
    for (status, revision) in [
        (LaneStatus::Provisioning, 1),
        (LaneStatus::Ready, 2),
        (LaneStatus::Running, 3),
    ] {
        transition_lane_at(ledger.connection(), &lane_id, status, revision, now()).unwrap();
    }

    create_run(
        ledger.connection(),
        &NewRun {
            run_id: run_id.clone(),
            lane_id: lane_id.clone(),
            attempt_number: 1,
            workflow_id: None,
            workflow_version: None,
            input_hash: "input:roundtrip".to_owned(),
            accepted_capability_revision: None,
            lease_id: None,
            absolute_deadline: None,
            retry_budget: 3,
            created_at: now(),
        },
    )
    .unwrap();

    ledger
        .replace_plan(
            &run_id,
            "roundtrip the control plane through its owners",
            &[
                TodoSpec {
                    id: TodoId::new("todo:one").unwrap(),
                    title: "first".to_owned(),
                    status: TodoStatus::Completed,
                },
                TodoSpec {
                    id: TodoId::new("todo:two").unwrap(),
                    title: "second".to_owned(),
                    status: TodoStatus::Pending,
                },
            ],
            0,
            now(),
        )
        .unwrap();

    ledger
        .request_approval(NewApproval {
            approval_id: approval_id.clone(),
            issuer: "seat:roundtrip".to_owned(),
            scope: ApprovalScope {
                target_kind: "lane".to_owned(),
                target_id: lane_id.to_string(),
                capability_id: CapabilityId::new("cap:write").unwrap(),
                arguments_digest: Digest::hash(b"roundtrip"),
            },
            requested_at: now(),
            expires_at: now() + Duration::minutes(5),
        })
        .unwrap();
    let decided = ledger
        .decide_approval(
            &approval_id,
            ApprovalDecision::Approve {
                evidence_ref: Some("artifact:approved".to_owned()),
            },
            "human:one",
            now() + Duration::seconds(1),
            1,
        )
        .unwrap();
    assert!(matches!(decided, DecideApproval::Decided(_)));

    ledger
        .upsert_incident(
            IncidentObservation {
                incident_id: incident_id.clone(),
                run_id: Some(run_id.clone()),
                severity: IncidentSeverity::Error,
                confidence: ConfidenceMicros::new(900_000).unwrap(),
                deviation: "worker stopped making useful progress".to_owned(),
                failure_signature: "stalled:roundtrip:v1".to_owned(),
                expected_state: json!({"progress": true}),
                observed_state: json!({"progress": false}),
                affected_objects: vec!["lane:roundtrip".to_owned()],
                evidence_refs: EvidenceRefs::new(vec![
                    "event:one".to_owned(),
                    "event:two".to_owned(),
                ])
                .unwrap(),
                allowed_capabilities: vec![CapabilityId::new("cap:write").unwrap()],
                attempt_ids: Vec::new(),
                recommended_next_action: "restart the worker once".to_owned(),
                escalation_target: "seat:roundtrip".to_owned(),
                observed_at: now(),
                last_useful_progress_at: Some(now() - Duration::minutes(1)),
            },
            0,
        )
        .unwrap();
    let transitioned = ledger
        .transition_incident_status(&incident_id, IncidentStatus::Recovering, 1)
        .unwrap();
    assert!(matches!(transitioned, TransitionIncident::Transitioned(_)));

    (lane_id, run_id, approval_id, incident_id)
}

/// Persisted wire types round-trip and reject invalid shapes.
#[test]
fn stored_control_schema_roundtrip() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let (lane_id, run_id, approval_id, incident_id) = seed_roundtrip_fixture(&mut ledger);

    let lane = read_lane(ledger.connection(), &lane_id)
        .unwrap()
        .expect("lane exists");
    let lane_wire = LaneRecordWire::try_from(&lane).unwrap();
    assert_eq!(lane_wire.status, LaneStatus::Running);
    let lane_json = serde_json::to_value(&lane_wire).unwrap();
    assert_eq!(lane_json["status"], json!("running"));
    assert_eq!(lane_json["revision"], json!(4));
    assert!(lane_json.get("state").is_none());
    let restored = serde_json::from_value::<LaneRecordWire>(lane_json.clone())
        .unwrap()
        .into_record()
        .unwrap();
    assert_eq!(restored, lane);

    let plan = ledger.plan(&run_id).unwrap().expect("plan exists");
    let plan_json = serde_json::to_value(PlanWire::try_from(&plan).unwrap()).unwrap();
    assert_eq!(plan_json["todos"][0]["id"], json!("todo:one"));
    assert!(plan_json.get("items").is_none());
    let restored_plan = serde_json::from_value::<PlanWire>(plan_json.clone())
        .unwrap()
        .into_plan()
        .unwrap();
    assert_eq!(restored_plan, plan);

    let approval = ledger
        .approval(&approval_id)
        .unwrap()
        .expect("approval exists");
    let approval_json = serde_json::to_value(ApprovalWire::try_from(&approval).unwrap()).unwrap();
    assert_eq!(approval_json["scope"]["targetId"], json!("lane:roundtrip"));
    assert_eq!(approval_json["status"], json!("approved"));
    let restored_approval = serde_json::from_value::<ApprovalWire>(approval_json.clone())
        .unwrap()
        .into_approval()
        .unwrap();
    assert_eq!(restored_approval, approval);

    let incident = ledger
        .incident(&incident_id)
        .unwrap()
        .expect("incident exists");
    let incident_json =
        serde_json::to_value(IncidentCardWire::try_from(&incident).unwrap()).unwrap();
    assert_eq!(incident_json["status"], json!("recovering"));
    assert_eq!(incident_json["severity"], json!("error"));
    assert_eq!(incident_json["revision"], json!(2));
    let restored_incident = serde_json::from_value::<IncidentCardWire>(incident_json.clone())
        .unwrap()
        .into_card()
        .unwrap();
    assert_eq!(restored_incident, incident);

    // Reject legacy keys, unknown enum values, and unknown nested fields.
    let mut legacy_state = lane_json.clone();
    roundtrip_rename_key(&mut legacy_state, "status", "state");
    assert!(serde_json::from_value::<LaneRecordWire>(legacy_state).is_err());
    let mut legacy_completed = lane_json.clone();
    legacy_completed["status"] = json!("completed");
    assert!(serde_json::from_value::<LaneRecordWire>(legacy_completed).is_err());
    let mut unknown_backend = lane_json.clone();
    unknown_backend["backend"] = json!("mainframe");
    assert!(serde_json::from_value::<LaneRecordWire>(unknown_backend).is_err());
    let mut lane_missing_nullable = lane_json.clone();
    lane_missing_nullable
        .as_object_mut()
        .expect("lane object")
        .remove("projectId")
        .expect("projectId key");
    assert!(
        serde_json::from_value::<LaneRecordWire>(lane_missing_nullable).is_err(),
        "a removed required-nullable lane key must fail decode"
    );

    let mut lane_surprise = lane_json;
    roundtrip_apply(&mut lane_surprise, &json!({"surprise": true}));
    assert!(serde_json::from_value::<LaneRecordWire>(lane_surprise).is_err());

    let mut legacy_items = plan_json.clone();
    roundtrip_rename_key(&mut legacy_items, "todos", "items");
    assert!(serde_json::from_value::<PlanWire>(legacy_items).is_err());
    let mut legacy_item_id = plan_json.clone();
    roundtrip_rename_key(&mut legacy_item_id["todos"][0], "id", "item_id");
    assert!(serde_json::from_value::<PlanWire>(legacy_item_id).is_err());
    let mut zero_revision = plan_json.clone();
    zero_revision["revision"] = json!(0);
    assert!(serde_json::from_value::<PlanWire>(zero_revision).is_err());
    let mut todo_surprise = plan_json;
    roundtrip_apply(&mut todo_surprise["todos"][0], &json!({"priority": 1}));
    assert!(serde_json::from_value::<PlanWire>(todo_surprise).is_err());

    let mut legacy_flattened = approval_json.clone();
    let scope = legacy_flattened["scope"].clone();
    legacy_flattened
        .as_object_mut()
        .unwrap()
        .remove("scope")
        .unwrap();
    roundtrip_apply(&mut legacy_flattened, &scope);
    roundtrip_rename_key(&mut legacy_flattened, "argumentsDigest", "arguments_hash");
    assert!(serde_json::from_value::<ApprovalWire>(legacy_flattened).is_err());
    let mut undecidable = approval_json.clone();
    undecidable["decidedAt"] = Value::Null;
    assert!(serde_json::from_value::<ApprovalWire>(undecidable).is_err());
    let mut approval_missing_nullable = approval_json.clone();
    approval_missing_nullable
        .as_object_mut()
        .expect("approval object")
        .remove("decidedAt")
        .expect("decidedAt key");
    assert!(
        serde_json::from_value::<ApprovalWire>(approval_missing_nullable).is_err(),
        "a removed required-nullable approval key must fail decode"
    );

    let mut unknown_status = approval_json.clone();
    unknown_status["status"] = json!("maybe");
    assert!(serde_json::from_value::<ApprovalWire>(unknown_status).is_err());
    let mut empty_issuer = approval_json.clone();
    empty_issuer["issuer"] = json!("");
    assert!(
        serde_json::from_value::<ApprovalWire>(empty_issuer).is_err(),
        "an empty issuer must fail the schema id pattern"
    );
    let mut invalid_issuer = approval_json.clone();
    invalid_issuer["issuer"] = json!("-leading-hyphen");
    assert!(serde_json::from_value::<ApprovalWire>(invalid_issuer).is_err());
    let mut overlong_issuer = approval_json.clone();
    overlong_issuer["issuer"] = json!("a".repeat(129));
    assert!(serde_json::from_value::<ApprovalWire>(overlong_issuer).is_err());
    let mut invalid_decided_by = approval_json.clone();
    invalid_decided_by["decidedBy"] = json!("!!!");
    assert!(serde_json::from_value::<ApprovalWire>(invalid_decided_by).is_err());
    let mut empty_decided_by = approval_json.clone();
    empty_decided_by["decidedBy"] = json!(" ");
    assert!(serde_json::from_value::<ApprovalWire>(empty_decided_by).is_err());
    let mut empty_evidence = approval_json;
    empty_evidence["decisionEvidenceRef"] = json!("");
    assert!(serde_json::from_value::<ApprovalWire>(empty_evidence).is_err());

    let mut incomplete_incident = incident_json.clone();
    incomplete_incident
        .as_object_mut()
        .unwrap()
        .remove("status");
    assert!(serde_json::from_value::<IncidentCardWire>(incomplete_incident).is_err());
    let mut unknown_severity = incident_json.clone();
    unknown_severity["severity"] = json!("fatal");
    assert!(serde_json::from_value::<IncidentCardWire>(unknown_severity).is_err());
    let mut invalid_escalation = incident_json.clone();
    invalid_escalation["escalationTarget"] = json!("!!");
    assert!(
        serde_json::from_value::<IncidentCardWire>(invalid_escalation).is_err(),
        "escalationTarget must satisfy the schema id pattern"
    );
    let mut incident_missing_nullable = incident_json.clone();
    {
        let object = incident_missing_nullable
            .as_object_mut()
            .expect("incident object");
        object.remove("runId").expect("runId key");
        object
            .remove("lastUsefulProgressAt")
            .expect("lastUsefulProgressAt key");
    }
    assert!(
        serde_json::from_value::<IncidentCardWire>(incident_missing_nullable).is_err(),
        "removed required-nullable incident keys must fail decode"
    );

    let mut unbounded_evidence = incident_json.clone();
    unbounded_evidence["evidenceRefs"] =
        json!(["event:a", "event:b", "event:c", "event:d", "event:e", "event:f"]);
    assert!(serde_json::from_value::<IncidentCardWire>(unbounded_evidence).is_err());
    let mut duplicate_evidence = incident_json.clone();
    duplicate_evidence["evidenceRefs"] = json!(["event:a", "event:b", "event:a"]);
    assert!(
        serde_json::from_value::<IncidentCardWire>(duplicate_evidence).is_err(),
        "duplicate evidence refs must be rejected, not deduplicated"
    );
    let mut empty_evidence = incident_json;
    empty_evidence["evidenceRefs"] = json!([""]);
    assert!(serde_json::from_value::<IncidentCardWire>(empty_evidence).is_err());
}

#[test]
fn lane_header_rejects_non_schema_ids() {
    let ledger = Ledger::open_in_memory().unwrap();
    let lane_id = LaneId::new("lane:header").unwrap();
    let overlong_template = "a".repeat(129);
    for (template_id, created_by) in [
        ("", "operator"),
        ("-leading", "operator"),
        (overlong_template.as_str(), "operator"),
        ("template:header", ""),
        ("template:header", "-leading"),
    ] {
        let error = create_lane(
            ledger.connection(),
            &NewLane {
                lane_id: lane_id.clone(),
                seat_id: SeatId::new("seat:header").unwrap(),
                project_id: None,
                template_id: template_id.to_owned(),
                backend: "local_omp".to_owned(),
                created_by: created_by.to_owned(),
                created_at: now(),
                retained: false,
            },
        )
        .unwrap_err();
        assert!(matches!(error, LedgerError::InvalidData { .. }));
    }
}

#[test]
fn stale_cannot_overwrite() {
    let connection = db();
    let id = AttemptId::parse("attempt:one").expect("attempt id");
    assert!(matches!(
        transition_attempt(&connection, &id, AttemptStatus::Recovering, 6, now()),
        Err(LedgerError::StaleActor { .. })
    ));
    let status: String = connection
        .query_row("SELECT status FROM attempts", [], |row| row.get(0))
        .expect("read");
    assert_eq!(status, "orphaned");
}

/// Live-session runs are filtered by lane and returned oldest first.
#[test]
fn live_runs_for_lane_lists_only_that_lanes_live_sessions() {
    let ledger = Ledger::open_in_memory().unwrap();
    let new_lane = |id: &str| NewLane {
        lane_id: LaneId::new(id).unwrap(),
        seat_id: SeatId::new("gungnir").unwrap(),
        project_id: None,
        template_id: "template".to_owned(),
        backend: "local_omp".to_owned(),
        created_by: "operator".to_owned(),
        created_at: now(),
        retained: false,
    };
    create_lane(ledger.connection(), &new_lane("gungnir-surtr")).unwrap();
    create_lane(ledger.connection(), &new_lane("gungnir-odin")).unwrap();
    for (run, lane, attempt, minutes) in [
        ("run:live:b", "gungnir-surtr", 1, 2),
        ("run:live:a", "gungnir-surtr", 2, 1),
        ("run:workflow", "gungnir-surtr", 3, 0),
        ("run:live:other", "gungnir-odin", 1, 0),
    ] {
        create_run(
            ledger.connection(),
            &NewRun {
                run_id: RunId::new(run).unwrap(),
                lane_id: LaneId::new(lane).unwrap(),
                attempt_number: attempt,
                workflow_id: None,
                workflow_version: None,
                input_hash: "input".to_owned(),
                accepted_capability_revision: None,
                lease_id: None,
                absolute_deadline: None,
                retry_budget: 0,
                created_at: now() + Duration::minutes(minutes),
            },
        )
        .unwrap();
    }
    let runs =
        live_runs_for_lane(ledger.connection(), &LaneId::new("gungnir-surtr").unwrap()).unwrap();
    let ids: Vec<String> = runs.iter().map(ToString::to_string).collect();
    assert_eq!(ids, ["run:live:a", "run:live:b"]);
}
