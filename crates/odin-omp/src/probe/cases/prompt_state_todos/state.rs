//! Case 4 owner: state queries before, during, and after a turn.

use super::shared::*;
use super::*;

pub(super) struct StateAcrossTurnCase;

#[async_trait]
impl ConformanceCase for StateAcrossTurnCase {
    fn id(&self) -> ConformanceCaseId {
        STATE_ACROSS_TURN
    }

    fn name(&self) -> &'static str {
        "state_across_turn"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_state_across_turn(context).await
    }
}

async fn run_state_across_turn(context: &CaseContext) -> CaseOutcome {
    let mut driver = match spawn_driver(context).await {
        Ok(driver) => driver,
        Err(failure) => {
            return CaseOutcome::fail("state observation could not start", vec![failure])
        }
    };
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    if let Err(failure) = state_across_turn(&mut driver, &mut failures, &mut evidence).await {
        failures.push(failure);
    }
    finish_case(
        driver,
        "state_across_turn",
        "state snapshots proved the idle, streaming, and settled turn states",
        "state-across-turn contract failed",
        failures,
        evidence,
    )
    .await
}

async fn state_across_turn(
    driver: &mut RawRpcDriver,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
) -> Result<(), CaseFailure> {
    let before_id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| rpc_error("state_before_send", error))?;
    let before_frame = driver
        .wait_for_response(&before_id, "get_state", deadline())
        .await
        .map_err(|error| rpc_error("state_before_response", error))?;
    let before = parse_state(&before_frame, &before_id, "before turn", failures);

    let turn_start = driver.transcript().len();
    let prompt_id = driver
        .send(
            "prompt",
            json!({ "message": format!("odin-mock:delay {STATE_DELAY_MS} state-after-delay") }),
        )
        .await
        .map_err(|error| rpc_error("delayed_prompt_send", error))?;
    let prompt_response = driver
        .wait_for_response(&prompt_id, "prompt", deadline())
        .await
        .map_err(|error| rpc_error("delayed_prompt_response", error))?;
    check_response(
        &prompt_response,
        &prompt_id,
        "prompt",
        "delayed prompt",
        failures,
    );
    collect_if_missing(driver, turn_start, "delayed_prompt_start", |value| {
        is_type(value, "message_end") && message_role(value, "user")
    })
    .await?;

    let during_id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| rpc_error("state_during_send", error))?;
    let during_frame = driver
        .wait_for_response(&during_id, "get_state", deadline())
        .await
        .map_err(|error| rpc_error("state_during_response", error))?;
    let during = parse_state(&during_frame, &during_id, "during turn", failures);

    collect_if_missing(
        driver,
        turn_start,
        "delayed_prompt_completion",
        is_terminal_agent_end,
    )
    .await?;
    let after_id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| rpc_error("state_after_send", error))?;
    let after_frame = driver
        .wait_for_response(&after_id, "get_state", deadline())
        .await
        .map_err(|error| rpc_error("state_after_response", error))?;
    let after = parse_state(&after_frame, &after_id, "after turn", failures);

    if let Some(snapshot) = before.as_ref() {
        require(
            !snapshot.streaming && snapshot.queued == 0,
            "state_before",
            "before-turn state was streaming or queued",
            failures,
        );
    }
    if let Some(snapshot) = during.as_ref() {
        require(
            snapshot.streaming && snapshot.queued == 0,
            "state_during",
            "during-turn state was not actively streaming with an empty queue",
            failures,
        );
    }
    if let Some(snapshot) = after.as_ref() {
        require(
            !snapshot.streaming && snapshot.queued == 0,
            "state_after",
            "after-turn state remained streaming or queued",
            failures,
        );
    }
    if let (Some(before), Some(during), Some(after)) =
        (before.as_ref(), during.as_ref(), after.as_ref())
    {
        require(
            before.session == during.session && during.session == after.session,
            "state_session",
            "before/during/after snapshots mixed session ids",
            failures,
        );
        require(
            during.messages == before.messages.saturating_add(1),
            "state_during_messages",
            format!(
                "during messageCount={}, expected {}",
                during.messages,
                before.messages.saturating_add(1)
            ),
            failures,
        );
        require(
            after.messages == before.messages.saturating_add(2),
            "state_after_messages",
            format!(
                "after messageCount={}, expected {}",
                after.messages,
                before.messages.saturating_add(2)
            ),
            failures,
        );
    }

    let frames = driver.transcript();
    let before_index = find_required(
        frames,
        0,
        frames.len(),
        "state_before_order",
        "before-turn state response",
        failures,
        |value| response_matches(value, &before_id, "get_state"),
    );
    let prompt_index = find_after(
        frames,
        before_index,
        frames.len(),
        "state_prompt_order",
        "delayed prompt response",
        failures,
        |value| response_matches(value, &prompt_id, "prompt"),
    );
    let user_index = find_after(
        frames,
        prompt_index,
        frames.len(),
        "state_user_order",
        "delayed turn user message_end",
        failures,
        |value| is_type(value, "message_end") && message_role(value, "user"),
    );
    let during_index = find_after(
        frames,
        user_index,
        frames.len(),
        "state_during_order",
        "during-turn state response",
        failures,
        |value| response_matches(value, &during_id, "get_state"),
    );
    let terminal_index = find_after(
        frames,
        during_index,
        frames.len(),
        "state_terminal_order",
        "terminal agent_end",
        failures,
        is_terminal_agent_end,
    );
    let after_index = find_after(
        frames,
        terminal_index,
        frames.len(),
        "state_after_order",
        "after-turn state response",
        failures,
        |value| response_matches(value, &after_id, "get_state"),
    );
    require(
        after_index.is_some(),
        "state_snapshot_order",
        "before/during/after response ordering was incomplete",
        failures,
    );
    require(
        frames[turn_start..]
            .iter()
            .any(|frame| contains_string(frame.value(), "state-after-delay")),
        "state_delayed_effect",
        "delayed assistant result was absent",
        failures,
    );

    push_json_evidence(
        evidence,
        failures,
        "state_snapshots",
        "before-during-after.json",
        &json!({
            "before": before_frame.value().get("data").cloned().unwrap_or(Value::Null),
            "during": during_frame.value().get("data").cloned().unwrap_or(Value::Null),
            "after": after_frame.value().get("data").cloned().unwrap_or(Value::Null),
        }),
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct StateSnapshot {
    session: String,
    streaming: bool,
    queued: u64,
    messages: u64,
}

fn parse_state(
    frame: &DecodedRpcFrame,
    id: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> Option<StateSnapshot> {
    let data = response_data(frame, id, "get_state", label, failures)?;
    let session = required_str(data, "sessionId", label, failures)?;
    let streaming = required_bool(data, "isStreaming", label, failures)?;
    let queued = required_u64(data, "queuedMessageCount", label, failures)?;
    let messages = required_u64(data, "messageCount", label, failures)?;
    Some(StateSnapshot {
        session,
        streaming,
        queued,
        messages,
    })
}
