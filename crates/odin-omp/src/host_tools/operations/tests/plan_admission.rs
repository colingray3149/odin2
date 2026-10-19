//! Plan management can write without an accepted plan; other non-R0 effects require acceptance.

use std::sync::atomic::Ordering;

use serde_json::json;

use crate::host_tools::operations::HostToolOperationError;

use super::fixture::{Fixture, PLAN_TOOL, SIDE_EFFECT_TOOL};

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
    assert!(stored.is_some(), "plan writer persisted a plan row");
}

#[test]
fn ordinary_side_effect_without_a_plan_is_needs_plan() {
    let fixture = Fixture::for_plan_writer();
    fixture.seed_bridge_run();

    let refused = fixture
        .dispatch_named(
            SIDE_EFFECT_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "side"}),
            "side-effect-missing-plan",
        )
        .expect_err("ordinary side effect without a plan is refused");
    assert!(
        matches!(
            refused,
            HostToolOperationError::Rejected(odin_kernel::AuthorizationRejection::NeedsPlan { .. })
        ),
        "missing plan refuses the side effect: {refused:?}"
    );
    assert_eq!(fixture.world.effects.load(Ordering::SeqCst), 0);
    assert!(fixture.world.calls().is_empty());
}
