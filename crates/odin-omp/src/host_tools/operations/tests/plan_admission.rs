//! Plan management can write without an accepted plan; other non-R0 effects require acceptance.

use serde_json::json;

use super::fixture::{Fixture, PLAN_TOOL};

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
                "timestampMs": 0
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
