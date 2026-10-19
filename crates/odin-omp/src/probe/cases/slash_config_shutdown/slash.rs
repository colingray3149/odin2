//! Case 18 owner: pinned command-API discovery plus local slash-command
//! result visibility and completion semantics.

use super::shared::*;
use super::*;

pub(super) struct SlashCommandCase;

#[async_trait::async_trait]
impl ConformanceCase for SlashCommandCase {
    fn id(&self) -> ConformanceCaseId {
        SLASH_COMMAND_RESULT
    }

    fn name(&self) -> &'static str {
        "slash_command_result"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_slash_command(context).await
    }
}

async fn run_slash_command(context: &CaseContext) -> CaseOutcome {
    let spec = match isolated_process_spec(
        context,
        context.work_dir(),
        &context.work_dir().join("slash-isolation"),
        vec![NO_SESSION_ARG.to_owned()],
    ) {
        Ok(spec) => spec,
        Err(error) => return setup_failure("slash command", "fixture_setup", error),
    };
    let mut driver = match {
        let worker = context.worker_for(&spec);
        RawRpcDriver::spawn(spec, worker)
    }
    .await
    {
        Ok(driver) => driver,
        Err(error) => return setup_failure("slash command", "child_start", error),
    };

    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    let mut cleanup = CleanupReceipt::default();
    // Evidence only: the pinned child pushes a complete
    // `available_commands_update` at startup and on later metadata changes;
    // the latest push is recorded here while discovery authority rests on the
    // correlated `get_available_commands` response checked in the exercise.
    if let Some(update) = driver
        .transcript()
        .iter()
        .rev()
        .find(|frame| available_fixture_command(frame.value()))
        .map(|frame| frame.value().clone())
    {
        evidence.push(json_evidence(
            "available_commands_update",
            "slash-command startup advertisement",
            &update,
        ));
    }

    let exercise: Result<(), CaseFailure> = async {
        // Authoritative discovery: correlated `get_available_commands`
        // request after startup/extension registration.
        let discovery_id = driver
            .send("get_available_commands", json!({}))
            .await
            .map_err(|error| failure("command_discovery_send", error))?;
        let discovery_response = driver
            .wait_for_response(&discovery_id, "get_available_commands", rpc_deadline())
            .await
            .map_err(|error| failure("command_discovery_response", error))?;
        expect_success(&discovery_response, "command_discovery_response")?;
        let discovered = discovery_response
            .value()
            .pointer("/data/commands")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                failure(
                    "command_discovery_data",
                    "get_available_commands response omitted data.commands",
                )
            })?;
        require(
            discovered.iter().any(|command| {
                command.get("name").and_then(Value::as_str) == Some(FIXTURE_COMMAND)
            }),
            "slash_visibility",
            "`odin-fixture` was absent from the correlated get_available_commands response",
        )?;

        let slash_start = driver.transcript().len();
        let slash_id = driver
            .send("prompt", json!({ "message": "/odin-fixture visible" }))
            .await
            .map_err(|error| failure("slash_send", error))?;
        driver
            .collect_until(rpc_deadline(), |frame| {
                frame.value().get("type").and_then(Value::as_str) == Some("prompt_result")
                    && frame.value().get("id").and_then(Value::as_str) == Some(slash_id.as_str())
            })
            .await
            .map_err(|error| failure("slash_completion", error))?;
        let slash_response = driver
            .wait_for_response(&slash_id, "prompt", rpc_deadline())
            .await
            .map_err(|error| failure("slash_response", error))?;
        expect_success(&slash_response, "slash_response")?;

        let slash_frames = frame_values(&driver.transcript()[slash_start..]);
        require(
            slash_frames.iter().any(|value| {
                value.get("type").and_then(Value::as_str) == Some("extension_ui_request")
                    && value.get("method").and_then(Value::as_str) == Some("notify")
                    && value.get("message").and_then(Value::as_str) == Some("odin-fixture:visible")
                    && value.get("notifyType").and_then(Value::as_str) == Some("info")
            }),
            "slash_ui",
            "the fixture notify UI frame was not observed",
        )?;
        require(
            slash_frames.iter().any(|value| {
                value.get("type").and_then(Value::as_str) == Some("prompt_result")
                    && value.get("id").and_then(Value::as_str) == Some(slash_id.as_str())
                    && value.get("agentInvoked").and_then(Value::as_bool) == Some(false)
            }),
            "slash_prompt_result",
            "local extension completion did not report agentInvoked=false",
        )?;
        require(
            !slash_frames.iter().any(is_agent_work_frame),
            "slash_local_only",
            "the local fixture command unexpectedly started agent work",
        )?;

        let output_start = driver.transcript().len();
        let output_id = driver
            .send("prompt", json!({ "message": "/model" }))
            .await
            .map_err(|error| failure("command_output_send", error))?;
        let output_response = driver
            .wait_for_response(&output_id, "prompt", rpc_deadline())
            .await
            .map_err(|error| failure("command_output_response", error))?;
        expect_success(&output_response, "command_output_response")?;
        require(
            output_response
                .value()
                .pointer("/data/agentInvoked")
                .and_then(Value::as_bool)
                == Some(false),
            "command_output_completion",
            "the local builtin response did not complete with agentInvoked=false",
        )?;
        let output_frames = frame_values(&driver.transcript()[output_start..]);
        require(
            output_frames.iter().any(|value| {
                value.get("type").and_then(Value::as_str) == Some("command_output")
                    && value
                        .get("text")
                        .and_then(Value::as_str)
                        .is_some_and(|text| text.contains("odin-mock/mock-a"))
            }),
            "command_output",
            "the local builtin's visible command_output was not observed",
        )?;

        let state = request_state(&mut driver, "slash_state").await?;
        expect_bool(&state, "isStreaming", false, "slash_local_state")?;
        expect_u64(&state, "messageCount", 0, "slash_local_state")?;
        expect_u64(&state, "queuedMessageCount", 0, "slash_local_state")?;
        Ok(())
    }
    .await;
    if let Err(error) = exercise {
        failures.push(error);
    }

    cleanup_driver(
        &mut driver,
        "slash-command child",
        true,
        &mut failures,
        &mut evidence,
        &mut cleanup,
    )
    .await;
    push_transcript(&driver, "slash-command", &mut evidence);
    finish_case(
        "local slash discovery, output, UI, and completion semantics conformed",
        "local slash-command conformance failed",
        failures,
        evidence,
        cleanup,
        1,
    )
}
