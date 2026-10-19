//! Case 12 owner: harmless read-tool execution and tool event records.

use super::shared::*;
use super::*;

pub(super) struct ReadToolEventsCase;

#[async_trait]
impl ConformanceCase for ReadToolEventsCase {
    fn id(&self) -> ConformanceCaseId {
        READ_TOOL_EVENTS
    }

    fn name(&self) -> &'static str {
        "read_tool_events"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_read_tool_events(context).await
    }
}

async fn run_read_tool_events(context: &CaseContext) -> CaseOutcome {
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    let mut cleanup = CleanupReceipt::default();
    let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
    let mut driver = match {
        let worker = context.worker_for(&spec);
        RawRpcDriver::spawn(spec, worker)
    }
    .await
    {
        Ok(driver) => driver,
        Err(error) => {
            failures.push(failure("child_start", error));
            return finish_outcome(
                "harmless read tool events and source result passed",
                "harmless read tool events or source result failed",
                failures,
                evidence,
                cleanup,
            );
        }
    };

    if let Err(error) = exercise_read_tool(context, &mut driver).await {
        failures.push(failure("read_tool", error));
    }
    match driver
        .cleanup(&mut cleanup, "case-12 pinned OMP child")
        .await
    {
        Ok(exit) if !exit.success() => failures.push(failure("process_exit", exit)),
        Ok(_) => {}
        Err(error) => failures.push(failure("cleanup", error)),
    }
    push_raw_transcript(
        &mut failures,
        &mut evidence,
        "read-tool-rpc.jsonl",
        driver.transcript(),
    );

    finish_outcome(
        "harmless read tool events and source result passed",
        "harmless read tool events or source result failed",
        failures,
        evidence,
        cleanup,
    )
}

async fn exercise_read_tool(
    context: &CaseContext,
    driver: &mut RawRpcDriver,
) -> Result<(), String> {
    let source = context
        .config()
        .provider_fixture_path()
        .to_string_lossy()
        .into_owned();
    let prompt_id = driver
        .send(
            "prompt",
            json!({ "message": format!("odin-mock:read {source}") }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let prompt = driver
        .wait_for_response(&prompt_id, "prompt", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    ensure_directive_accepted(&prompt, "prompt")?;
    if !driver.transcript().iter().any(is_agent_end) {
        driver
            .collect_until(operation_deadline(), is_agent_end)
            .await
            .map_err(|error| error.to_string())?;
    }

    let (start_at, start) = driver
        .transcript()
        .iter()
        .enumerate()
        .find(|(_, frame)| {
            frame.value().get("type").and_then(Value::as_str) == Some("tool_execution_start")
                && frame.value().get("toolName").and_then(Value::as_str) == Some("read")
        })
        .ok_or_else(|| "read tool emitted no tool_execution_start".to_owned())?;
    if start.value().pointer("/args/path").and_then(Value::as_str) != Some(source.as_str()) {
        return Err("read start event did not name the fixture source path".to_owned());
    }
    let tool_call_id = start
        .value()
        .get("toolCallId")
        .and_then(Value::as_str)
        .ok_or_else(|| "read start event omitted toolCallId".to_owned())?
        .to_owned();
    let (end_at, end) = driver
        .transcript()
        .iter()
        .enumerate()
        .find(|(_, frame)| {
            frame.value().get("type").and_then(Value::as_str) == Some("tool_execution_end")
                && frame.value().get("toolName").and_then(Value::as_str) == Some("read")
                && frame.value().get("toolCallId").and_then(Value::as_str)
                    == Some(tool_call_id.as_str())
        })
        .ok_or_else(|| "read tool emitted no correlated tool_execution_end".to_owned())?;
    if end_at <= start_at {
        return Err("read tool end event preceded its start".to_owned());
    }
    if end.value().get("isError").and_then(Value::as_bool) != Some(false) {
        return Err("harmless fixture read ended as an error".to_owned());
    }
    // The read tool renders the resolved source in the `[<exact path>#<tag>]`
    // hashline header opening the result's first text content block.
    let text = end
        .value()
        .pointer("/result/content")
        .and_then(Value::as_array)
        .and_then(|blocks| {
            blocks.iter().find_map(|block| {
                let text = block.get("text").and_then(Value::as_str);
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => text,
                    _ => None,
                }
            })
        })
        .ok_or_else(|| "read end event omitted its text content block".to_owned())?;
    let (resolved_path, tag) = text
        .strip_prefix('[')
        .and_then(|header| header.split_once(']'))
        .and_then(|(header, _)| header.rsplit_once('#'))
        .ok_or_else(|| "read result text omitted its [path#tag] hashline header".to_owned())?;
    if resolved_path != source {
        return Err("read result hashline header did not name the exact resolved path".to_owned());
    }
    if tag.is_empty() {
        return Err("read result hashline header omitted its content tag".to_owned());
    }
    // The read tool must return the fixture's real bytes: derive the expected
    // marker from the file on disk instead of pinning a source-text constant,
    // so the check survives fixture edits and cannot pass on stale content.
    let fixture_marker = std::fs::read_to_string(&source)
        .map_err(|error| format!("read fixture bytes for comparison: {error}"))?
        .lines()
        .find(|line| line.contains("FIXTURE_COMMAND ="))
        .ok_or_else(|| "fixture source lost its command registration line".to_owned())?
        .trim()
        .to_owned();
    if !text.contains(&fixture_marker) {
        return Err("read result did not contain the fixture source bytes".to_owned());
    }
    if !driver
        .transcript()
        .iter()
        .skip(end_at + 1)
        .any(|frame| frame.value().to_string().contains("mock-tool-done:read:ok"))
    {
        return Err("provider never continued after the correlated read tool result".to_owned());
    }
    Ok(())
}

fn is_agent_end(frame: &DecodedRpcFrame) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some("agent_end")
}
