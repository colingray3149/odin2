//! A lane that goes silent never strands the owner: its turn moves to the seat's next declared lane.

use super::user_messages;
use super::*;
use crate::runtime::ApprovedIntentRoute as _;
use odin_domain::huginn::{ToolStarted, ToolUseBlock};
use odin_domain::TurnId;

/// Under [`ANSWER_BOUND`], so a quiet lane is left before its turn would be handed off late.
const STALL: StdDuration = StdDuration::from_secs(10);

/// A root whose seat declares `stall`, over a plane whose first lane hangs on every prompt.
async fn first_lane_hangs(
    stall: StdDuration,
) -> (
    TempDir,
    Arc<FakePlane>,
    Arc<FakeEgress>,
    Arc<ConversationRoot>,
) {
    let dir = scratch_dir();
    let plane = Arc::new(FakePlane::new(dir.path()).await);
    plane.stalled_models.lock().insert("model".to_owned());
    let egress = Arc::new(FakeEgress::new());
    let mut config = root_config(
        dir.path(),
        Arc::clone(&plane) as Arc<dyn ConversationPlane>,
        egress.clone(),
        Arc::new(FakeApprovals::empty()),
        fake_authority(1, 1),
        Default::default(),
        None,
    );
    config.stall_bound = Some(stall);
    let root = ConversationRoot::open(config).expect("root composes");
    root.initialize().await.expect("initialize");
    (dir, plane, egress, root)
}

#[tokio::test(start_paused = true)]
async fn a_lane_that_goes_quiet_hands_the_turn_to_the_next_declared_lane() {
    let (_dir, plane, egress, root) = first_lane_hangs(STALL).await;
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    // A wake arriving while the lane is quiet waits for the turn instead of joining it.
    let mut wake = intent("wake");
    wake.unprompted = true;
    let waiting = tokio::spawn({
        let root = Arc::clone(&root);
        async move {
            tokio::time::sleep(StdDuration::from_secs(1)).await;
            root.execute(wake).await
        }
    });
    let started = tokio::time::Instant::now();
    let projection = root.execute(intent("ask")).await.expect("answered");
    assert_eq!(projection["answer"], "A plain answer.");
    assert!(
        started.elapsed() < ANSWER_BOUND,
        "left before a late hand-off"
    );
    waiting
        .await
        .unwrap()
        .expect("the wake runs as its own turn");

    let sends = egress.sends();
    assert_eq!(sends.len(), 3, "{sends:?}");
    assert!(
        sends[0].starts_with("model ") && sends[0].contains(NEXT_MODEL),
        "one line naming both lanes: {:?}",
        sends[0]
    );
    assert_eq!(plane.model_of(&session), NEXT_MODEL);
    let prompts = user_messages(&plane, session).await;
    assert_eq!(prompts.len(), 3, "{prompts:?}");
    assert!(prompts[0].starts_with("[You are running on prov/model]"));
    assert!(
        prompts[1].starts_with(&format!("[You are running on prov/{NEXT_MODEL}]"))
            && prompts[1].contains("intent ask"),
        "the resend names the lane now serving: {:?}",
        prompts[1]
    );
    assert!(prompts[2].contains("intent wake"));
}

#[tokio::test(start_paused = true)]
async fn a_second_quiet_lane_is_told_to_colin_not_tried_again() {
    let (_dir, plane, egress, root) = first_lane_hangs(STALL).await;
    plane.stalled_models.lock().insert(NEXT_MODEL.to_owned());
    let failure = root
        .execute(intent("ask"))
        .await
        .expect_err("both lanes quiet");
    assert!(
        matches!(&failure, IntentFailure::LaneStalled { from, .. } if from == NEXT_MODEL),
        "{failure:?}"
    );
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    assert_eq!(
        plane.prompt_count("command:intent:"),
        2,
        "sent once more, not again"
    );
    assert_eq!(
        plane.state_of(&session),
        Some(LiveSessionState::Idle),
        "the stuck turn is cancelled, so the next message is not queued behind it"
    );
    assert_eq!(egress.sends().len(), 1, "the one line for the first move");
}

/// A running tool is the tool's wait: cancelling it would send its effect twice.
#[tokio::test(start_paused = true)]
async fn a_tool_still_running_does_not_count_as_a_quiet_lane() {
    let (_dir, plane, _egress, root) = first_lane_hangs(STALL).await;
    let session = root.current_vehicle_session().await.unwrap().unwrap();
    let turn = tokio::spawn({
        let root = Arc::clone(&root);
        async move { root.execute(intent("render")).await }
    });
    tokio::time::sleep(StdDuration::from_secs(1)).await;
    plane
        .push_event(
            &session,
            LiveEventBody::ToolStarted(ToolStarted {
                turn_id: TurnId::new("turn:render").unwrap(),
                tool: ToolUseBlock {
                    tool_use_id: "call-1".to_owned(),
                    capability_id: CapabilityId::new("docs.render").unwrap(),
                    arguments: serde_json::json!({}),
                },
                intent: None,
            }),
        )
        .await;
    let handed_off = turn.await.unwrap().expect("handed off as late, not moved");
    assert_eq!(handed_off["lateAnswer"], true);
    assert_eq!(plane.model_of(&session), "model");
    assert!(plane.command_entries("command:lane-stall:").is_empty());
}
