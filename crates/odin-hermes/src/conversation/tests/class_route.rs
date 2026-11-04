//! Class routing through the real root: the journaled SetModel and the plane's model after it.

use super::*;
use crate::runtime::models::Reading;
use odin_domain::huginn::{ToolFinished, ToolResultBlock, ToolStarted, ToolUseBlock};
use odin_domain::TurnId;
use serde_json::json;

/// Two lanes, one per rung: `fast` runs on the launch model, `standard` and `strong` on the next.
fn reading() -> Arc<Reading> {
    let account = json!({"id": "test", "provider": "Test", "billing": "subscription",
        "monthly_usd": null, "renews": null, "secret": null, "keyed": true, "windows": []});
    let lane = |name: &str| {
        json!({"model_name": name, "model_info": {"odin": {"account": account,
            "vision": false, "context_window": 100000}}})
    };
    let class = |name: &str, lane: &str| {
        json!({"model_name": name, "model_info": {"odin": {"account": account,
            "vision": false, "context_window": 100000,
            "class": {"name": name, "order": [lane]}}}})
    };
    Arc::new(Reading::test_reading(&json!({"data": [
        lane("model"),
        lane(NEXT_MODEL),
        class("fast", "model"),
        class("standard", NEXT_MODEL),
        class("strong", NEXT_MODEL),
    ]})))
}

async fn failed_tool_call(plane: &FakePlane, session: &LiveSessionId, call: &str) {
    let turn = TurnId::new("turn:test").expect("turn id");
    plane
        .push_event(
            session,
            LiveEventBody::ToolStarted(ToolStarted {
                turn_id: turn.clone(),
                tool: ToolUseBlock {
                    tool_use_id: call.to_owned(),
                    capability_id: CapabilityId::new("test.run").expect("capability id"),
                    arguments: json!({}),
                },
                intent: None,
            }),
        )
        .await;
    plane
        .push_event(
            session,
            LiveEventBody::ToolFinished(ToolFinished {
                turn_id: turn,
                result: ToolResultBlock {
                    tool_use_id: call.to_owned(),
                    is_error: true,
                    content: Vec::new(),
                    details: Some(json!({"details": {"errorKind": "schema"}})),
                },
            }),
        )
        .await;
}

/// A turn that ends with the same typed tool failure twice moves the seat up one class: the
/// next turn runs on that class's lane, and one failure alone moves nothing.
#[tokio::test(start_paused = true)]
async fn repeated_typed_tool_failures_move_the_next_turn_up_a_class() {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    let mut config = root_config(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        Arc::new(FakeEgress::new()),
        Arc::new(FakeApprovals::empty()),
        fake_authority(1, 1),
        Default::default(),
        None,
    );
    config.class_route = Some(ClassRoute {
        class: "fast",
        gateway: "unused".to_owned(),
    });
    let root = ConversationRoot::open(config).expect("root composes");
    root.initialize().await.expect("initialize");
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let listed = || async { root.find_session(session, false).await.unwrap().unwrap() };

    failed_tool_call(&plane, &session, "one").await;
    assert!(
        root.route_with_reading(&listed().await, "next", None, Ok(reading()))
            .await
            .is_none(),
        "one failure is not a pattern"
    );
    assert_eq!(plane.model_of(&session), "model");

    failed_tool_call(&plane, &session, "two").await;
    let moved = root
        .route_with_reading(&listed().await, "next", None, Ok(reading()))
        .await
        .expect("the second failure moves the turn");
    assert_eq!(moved.model.as_str(), NEXT_MODEL);
    assert_eq!(plane.model_of(&session), NEXT_MODEL);
}
