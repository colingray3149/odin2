//! Case 3 owner: prompt correlation across the immediate response,
//! `prompt_result`, local `command_output`, and streamed lifecycle events.

use super::shared::*;
use super::*;

pub(super) struct PromptCorrelationCase;

#[async_trait]
impl ConformanceCase for PromptCorrelationCase {
    fn id(&self) -> ConformanceCaseId {
        PROMPT_CORRELATION
    }

    fn name(&self) -> &'static str {
        "prompt_correlation"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_prompt_correlation(context).await
    }
}

async fn run_prompt_correlation(context: &CaseContext) -> CaseOutcome {
    let mut driver = match spawn_driver(context).await {
        Ok(driver) => driver,
        Err(failure) => {
            return CaseOutcome::fail("prompt correlation could not start", vec![failure])
        }
    };
    let mut failures = Vec::new();
    if let Err(failure) = prompt_correlation(&mut driver, &mut failures).await {
        failures.push(failure);
    }
    finish_case(
        driver,
        "prompt_correlation",
        "prompt acceptance, auxiliary frames, and lifecycle ordering matched",
        "prompt correlation contract failed",
        failures,
        Vec::new(),
    )
    .await
}

async fn prompt_correlation(
    driver: &mut RawRpcDriver,
    failures: &mut Vec<CaseFailure>,
) -> Result<(), CaseFailure> {
    let model_start = driver.transcript().len();
    let model_id = driver
        .send("prompt", json!({ "message": "odin-mock:read" }))
        .await
        .map_err(|error| rpc_error("prompt_send", error))?;
    let response = driver
        .wait_for_response(&model_id, "prompt", deadline())
        .await
        .map_err(|error| rpc_error("prompt_response", error))?;
    check_response(&response, &model_id, "prompt", "model prompt", failures);
    collect_if_missing(
        driver,
        model_start,
        "prompt_completion",
        is_terminal_agent_end,
    )
    .await?;
    assert_model_lifecycle(driver.transcript(), model_start, &model_id, failures);

    let command_start = driver.transcript().len();
    let command_id = driver
        .send("prompt", json!({ "message": "/model" }))
        .await
        .map_err(|error| rpc_error("command_output_send", error))?;
    let command_response = driver
        .wait_for_response(&command_id, "prompt", deadline())
        .await
        .map_err(|error| rpc_error("command_output_response", error))?;
    let command_end = driver.transcript().len();
    if let Some(data) = response_data(
        &command_response,
        &command_id,
        "prompt",
        "local /model",
        failures,
    ) {
        require(
            data.get("agentInvoked").and_then(Value::as_bool) == Some(false),
            "command_output_acceptance",
            "local /model did not report agentInvoked=false",
            failures,
        );
    }
    let output_index = find_required(
        driver.transcript(),
        command_start,
        command_end,
        "command_output",
        "effective-model command_output",
        failures,
        |value| {
            is_type(value, "command_output")
                && value
                    .get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.contains("Current model: odin-mock/mock-a"))
        },
    );
    let response_index = find_required(
        driver.transcript(),
        command_start,
        command_end,
        "command_output_response",
        "correlated /model response",
        failures,
        |value| response_matches(value, &command_id, "prompt"),
    );
    require_order(
        output_index,
        response_index,
        "command_output_order",
        "command_output did not precede its response",
        failures,
    );
    forbid_agent_events(
        driver.transcript(),
        command_start,
        command_end,
        "local /model",
        failures,
    );

    let auxiliary_start = driver.transcript().len();
    let auxiliary_id = driver
        .send("prompt", json!({ "message": "/odin-fixture auxiliary" }))
        .await
        .map_err(|error| rpc_error("auxiliary_send", error))?;
    let auxiliary_response = driver
        .wait_for_response(&auxiliary_id, "prompt", deadline())
        .await
        .map_err(|error| rpc_error("auxiliary_response", error))?;
    check_response(
        &auxiliary_response,
        &auxiliary_id,
        "prompt",
        "local extension prompt",
        failures,
    );
    if !driver
        .transcript()
        .iter()
        .skip(auxiliary_start)
        .any(|frame| prompt_result_matches(frame.value(), &auxiliary_id))
    {
        driver
            .collect_until(deadline(), |frame| {
                prompt_result_matches(frame.value(), &auxiliary_id)
            })
            .await
            .map_err(|error| rpc_error("auxiliary_prompt_result", error))?;
    }
    let auxiliary_end = driver.transcript().len();
    let accepted = find_required(
        driver.transcript(),
        auxiliary_start,
        auxiliary_end,
        "auxiliary_response",
        "extension prompt response",
        failures,
        |value| response_matches(value, &auxiliary_id, "prompt"),
    );
    let notify = find_required(
        driver.transcript(),
        auxiliary_start,
        auxiliary_end,
        "auxiliary_notify",
        "fixture notify frame",
        failures,
        |value| {
            is_type(value, "extension_ui_request")
                && value.get("method").and_then(Value::as_str) == Some("notify")
                && value.get("message").and_then(Value::as_str) == Some("odin-fixture:auxiliary")
        },
    );
    let result = find_required(
        driver.transcript(),
        auxiliary_start,
        auxiliary_end,
        "prompt_result",
        "correlated local-only prompt_result",
        failures,
        |value| prompt_result_matches(value, &auxiliary_id),
    );
    if let Some(index) = result {
        require(
            driver.transcript()[index]
                .value()
                .get("agentInvoked")
                .and_then(Value::as_bool)
                == Some(false),
            "prompt_result_status",
            "local prompt_result did not report agentInvoked=false",
            failures,
        );
    }
    require_order(
        accepted,
        result,
        "prompt_result_order",
        "prompt_result did not follow prompt acceptance",
        failures,
    );
    require_order(
        notify,
        result,
        "auxiliary_order",
        "extension notify did not precede prompt_result",
        failures,
    );
    forbid_agent_events(
        driver.transcript(),
        auxiliary_start,
        auxiliary_end,
        "local extension prompt",
        failures,
    );
    Ok(())
}

fn assert_model_lifecycle(
    frames: &[DecodedRpcFrame],
    start: usize,
    prompt_id: &str,
    failures: &mut Vec<CaseFailure>,
) {
    let end = frames.len();
    let response = find_required(
        frames,
        start,
        end,
        "prompt_acceptance",
        "immediate correlated prompt response",
        failures,
        |value| response_matches(value, prompt_id, "prompt"),
    );
    let agent_start = find_after(
        frames,
        response,
        end,
        "agent_start",
        "agent_start after prompt response",
        failures,
        |value| is_type(value, "agent_start"),
    );
    let turn_one = find_after(
        frames,
        agent_start,
        end,
        "first_turn_start",
        "first turn_start",
        failures,
        |value| is_type(value, "turn_start"),
    );
    let assistant_start = find_after(
        frames,
        turn_one,
        end,
        "assistant_start",
        "assistant message_start",
        failures,
        |value| is_type(value, "message_start") && message_role(value, "assistant"),
    );
    let assistant_end = find_after(
        frames,
        assistant_start,
        end,
        "assistant_tool_call",
        "assistant message_end carrying the read call",
        failures,
        |value| {
            is_type(value, "message_end")
                && message_role(value, "assistant")
                && message_has_tool_call(value, "read")
        },
    );
    if let (Some(start), Some(end)) = (assistant_start, assistant_end) {
        let _ = find_required(
            frames,
            start.saturating_add(1),
            end,
            "assistant_stream",
            "assistant message_update before message_end",
            failures,
            |value| is_type(value, "message_update") && message_role(value, "assistant"),
        );
    }
    let tool_start = find_after(
        frames,
        assistant_end,
        end,
        "tool_start",
        "read tool_execution_start",
        failures,
        |value| {
            is_type(value, "tool_execution_start")
                && value.get("toolName").and_then(Value::as_str) == Some("read")
        },
    );
    let tool_end = find_after(
        frames,
        tool_start,
        end,
        "tool_end",
        "read tool_execution_end",
        failures,
        |value| {
            is_type(value, "tool_execution_end")
                && value.get("toolName").and_then(Value::as_str) == Some("read")
        },
    );
    if let Some(index) = tool_end {
        require(
            frames[index]
                .value()
                .get("isError")
                .and_then(Value::as_bool)
                != Some(true),
            "tool_status",
            "deterministic read tool ended with isError=true",
            failures,
        );
    }
    let tool_result = find_after(
        frames,
        tool_end,
        end,
        "tool_result",
        "toolResult message_end",
        failures,
        |value| is_type(value, "message_end") && message_role(value, "toolResult"),
    );
    let turn_one_end = find_after(
        frames,
        tool_result,
        end,
        "first_turn_end",
        "turn_end after the tool result",
        failures,
        |value| is_type(value, "turn_end"),
    );
    let turn_two = find_after(
        frames,
        turn_one_end,
        end,
        "final_turn_start",
        "continuation turn_start",
        failures,
        |value| is_type(value, "turn_start"),
    );
    let final_message = find_after(
        frames,
        turn_two,
        end,
        "final_assistant",
        "final assistant message_end with the tool completion",
        failures,
        |value| {
            is_type(value, "message_end")
                && message_role(value, "assistant")
                && contains_string(value, "mock-tool-done:read:ok")
        },
    );
    let turn_two_end = find_after(
        frames,
        final_message,
        end,
        "final_turn_end",
        "final turn_end",
        failures,
        |value| is_type(value, "turn_end"),
    );
    let agent_end = find_after(
        frames,
        turn_two_end,
        end,
        "agent_end",
        "terminal agent_end",
        failures,
        is_terminal_agent_end,
    );
    if let Some(index) = agent_end {
        require(
            index.saturating_add(1) == end,
            "final_event_order",
            "terminal agent_end was not the final collected model-turn frame",
            failures,
        );
    }
}
