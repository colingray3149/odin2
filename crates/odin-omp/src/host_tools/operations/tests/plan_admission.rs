//! Plan management can write without an accepted plan; other non-R0 effects require acceptance.

use serde_json::json;

use super::fixture::{Fixture, INCIDENT_TOOL, PLAN_TOOL, SIDE_EFFECT_TOOL};

#[test]
fn plan_writer_stores_a_plan_with_none_accepted() {
    let fixture = Fixture::for_plan_writer();
    fixture.seed_bridge_run();

    fixture
        .dispatch_named(
            PLAN_TOOL,
            Some(fixture.resource.clone()),
            json!({
                "objective": "write the missing plan",
                "todos": [{
                    "id": "todo:plan-writer",
                    "title": "write the missing plan",
                    "status": "pending"
                }],
                "expectedRevision": 0,
            }),
            "plan-writer-missing-plan",
        )
        .expect("plan writer authorizes with no accepted plan");

    let run = fixture.scope.run.clone().expect("bound run");
    let stored = fixture
        .ledger
        .lock()
        .expect("ledger lock")
        .plan(&run)
        .expect("plan query");
    let stored = stored.expect("plan writer persisted a plan row");
    assert_eq!(stored.objective, "write the missing plan");
    assert_eq!(stored.todos.len(), 1);
    assert_eq!(stored.todos[0].title, "write the missing plan");
}

#[test]
fn a_seat_with_no_accepted_plan_can_still_raise_an_incident() {
    let fixture = Fixture::for_plan_writer();
    fixture.seed_bridge_run();
    let refused = fixture.dispatch_named(
        SIDE_EFFECT_TOOL,
        Some(fixture.resource.clone()),
        json!({"value": "blocked"}),
        "plan-admission-side-effect",
    );
    assert!(
        refused.is_err(),
        "an ordinary side effect needs an accepted plan"
    );
    fixture
        .dispatch_named(
            INCIDENT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "blocked: no accepted plan"}),
            "plan-admission-incident",
        )
        .expect("incident.raise needs no accepted plan");
}

#[test]
fn a_root_plan_refuses_an_objective_that_would_void_its_acceptance() {
    let fixture = Fixture::for_plan_writer();
    fixture.accept_plan("answer the owner");
    let error = fixture
        .dispatch_named(
            PLAN_TOOL,
            Some(fixture.resource.clone()),
            json!({"objective": "something else", "todos": []}),
            "plan-admission-new-objective",
        )
        .expect_err("a new objective would void the owner's acceptance");
    assert!(error.to_string().contains("omit objective"), "{error}");
    let kept = fixture
        .dispatch_named(
            PLAN_TOOL,
            Some(fixture.resource.clone()),
            json!({"todos": [{"id": "todo:next", "title": "look it up", "status": "active"}]}),
            "plan-admission-keep-objective",
        )
        .expect("to-dos under the accepted objective");
    assert_eq!(kept["accepted"], true);
    assert_eq!(kept["acceptedBy"], "operator:fixture");
}
