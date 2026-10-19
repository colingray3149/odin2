//! Case 11 owner: subagent subscription, start, message paging, and
//! roster/state observation.

use super::shared::*;
use super::*;

pub(super) struct SubagentSubscriptionCase;

#[async_trait]
impl ConformanceCase for SubagentSubscriptionCase {
    fn id(&self) -> ConformanceCaseId {
        SUBAGENT_SUBSCRIPTION
    }

    fn name(&self) -> &'static str {
        "subagent_subscription"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_subagent_subscription(context).await
    }
}

async fn run_subagent_subscription(context: &CaseContext) -> CaseOutcome {
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
                "subagent lifecycle, roster, and byte paging passed",
                "subagent lifecycle, roster, or byte paging failed",
                failures,
                evidence,
                cleanup,
            );
        }
    };

    if let Err(error) = exercise_subagent_subscription(&mut driver).await {
        failures.push(failure("subagent_protocol", error));
    }
    match driver
        .cleanup(&mut cleanup, "case-11 pinned OMP child")
        .await
    {
        Ok(exit) if !exit.success() => failures.push(failure("process_exit", exit)),
        Ok(_) => {}
        Err(error) => failures.push(failure("cleanup", error)),
    }
    push_raw_transcript(
        &mut failures,
        &mut evidence,
        "subagent-rpc.jsonl",
        driver.transcript(),
    );

    finish_outcome(
        "subagent lifecycle, roster, and byte paging passed",
        "subagent lifecycle, roster, or byte paging failed",
        failures,
        evidence,
        cleanup,
    )
}

async fn exercise_subagent_subscription(driver: &mut RawRpcDriver) -> Result<(), String> {
    let subscription_id = driver
        .send("set_subagent_subscription", json!({ "level": "events" }))
        .await
        .map_err(|error| error.to_string())?;
    let subscription = driver
        .wait_for_response(
            &subscription_id,
            "set_subagent_subscription",
            operation_deadline(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let subscription_data = response_data(&subscription, "set_subagent_subscription")?;
    if subscription_data.get("level").and_then(Value::as_str) != Some("events") {
        return Err("subscription response did not confirm the `events` level".to_owned());
    }

    let prompt_id = driver
        .send(
            "prompt",
            json!({
                "message": "odin-mock:subagent odin-mock:delay 1500 subagent-terminal"
            }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let prompt = driver
        .wait_for_response(&prompt_id, "prompt", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    ensure_directive_accepted(&prompt, "prompt")?;

    if !driver.transcript().iter().any(is_subagent_started) {
        driver
            .collect_until(operation_deadline(), is_subagent_started)
            .await
            .map_err(|error| error.to_string())?;
    }
    let subagent_id = driver
        .transcript()
        .iter()
        .find(|frame| is_subagent_started(frame))
        .and_then(|frame| frame.value().pointer("/payload/id"))
        .and_then(Value::as_str)
        .ok_or_else(|| "started lifecycle frame omitted its subagent id".to_owned())?
        .to_owned();

    let roster_id = driver
        .send("get_subagents", json!({}))
        .await
        .map_err(|error| error.to_string())?;
    let roster = driver
        .wait_for_response(&roster_id, "get_subagents", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    let active = response_data(&roster, "get_subagents")?
        .get("subagents")
        .and_then(Value::as_array)
        .and_then(|subagents| {
            subagents
                .iter()
                .find(|entry| entry.get("id").and_then(Value::as_str) == Some(subagent_id.as_str()))
        })
        .ok_or_else(|| "active roster omitted the started subagent".to_owned())?;
    if active.get("status").and_then(Value::as_str) != Some("running") {
        return Err(format!(
            "active roster reported unexpected status {:?}",
            active.get("status")
        ));
    }

    if !driver
        .transcript()
        .iter()
        .any(|frame| is_subagent_terminal(frame, &subagent_id))
    {
        let expected = subagent_id.clone();
        driver
            .collect_until(operation_deadline(), move |frame| {
                is_subagent_terminal(frame, &expected)
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    let terminal = driver
        .transcript()
        .iter()
        .find(|frame| is_subagent_terminal(frame, &subagent_id))
        .ok_or_else(|| "subagent never emitted a terminal lifecycle frame".to_owned())?;
    if terminal
        .value()
        .pointer("/payload/status")
        .and_then(Value::as_str)
        != Some("completed")
    {
        return Err(format!(
            "subagent terminated without completion: {:?}",
            terminal.value().pointer("/payload/status")
        ));
    }

    let progress_seen = driver.transcript().iter().any(|frame| {
        frame.value().get("type").and_then(Value::as_str) == Some("subagent_progress")
            && frame
                .value()
                .pointer("/payload/progress/id")
                .and_then(Value::as_str)
                == Some(subagent_id.as_str())
    });
    if !progress_seen {
        return Err("events subscription emitted no subagent progress".to_owned());
    }
    let event_seen = driver.transcript().iter().any(|frame| {
        frame.value().get("type").and_then(Value::as_str) == Some("subagent_event")
            && frame.value().pointer("/payload/id").and_then(Value::as_str)
                == Some(subagent_id.as_str())
    });
    if !event_seen {
        return Err("events subscription emitted no raw subagent event".to_owned());
    }

    let first_page_id = driver
        .send(
            "get_subagent_messages",
            json!({ "subagentId": subagent_id, "fromByte": 0 }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let first_page = driver
        .wait_for_response(
            &first_page_id,
            "get_subagent_messages",
            operation_deadline(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let first_data = response_data(&first_page, "get_subagent_messages")?;
    if first_data.get("fromByte").and_then(Value::as_u64) != Some(0)
        || first_data.get("reset").and_then(Value::as_bool) != Some(false)
    {
        return Err("first transcript page did not preserve byte cursor zero".to_owned());
    }
    let next_byte = first_data
        .get("nextByte")
        .and_then(Value::as_u64)
        .filter(|next| *next > 0)
        .ok_or_else(|| "first transcript page did not advance its byte cursor".to_owned())?;
    if !first_data
        .get("entries")
        .and_then(Value::as_array)
        .is_some_and(|entries| !entries.is_empty())
        || !first_data
            .get("messages")
            .and_then(Value::as_array)
            .is_some_and(|messages| !messages.is_empty())
    {
        return Err("first transcript page contained no durable messages".to_owned());
    }

    let second_page_id = driver
        .send(
            "get_subagent_messages",
            json!({ "subagentId": subagent_id, "fromByte": next_byte }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let second_page = driver
        .wait_for_response(
            &second_page_id,
            "get_subagent_messages",
            operation_deadline(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let second_data = response_data(&second_page, "get_subagent_messages")?;
    if second_data.get("fromByte").and_then(Value::as_u64) != Some(next_byte)
        || second_data
            .get("nextByte")
            .and_then(Value::as_u64)
            .is_none_or(|next| next < next_byte)
        || second_data.get("reset").and_then(Value::as_bool) != Some(false)
    {
        return Err("second transcript page violated byte-cursor continuity".to_owned());
    }

    let terminal_roster_id = driver
        .send("get_subagents", json!({}))
        .await
        .map_err(|error| error.to_string())?;
    let terminal_roster = driver
        .wait_for_response(&terminal_roster_id, "get_subagents", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    if response_data(&terminal_roster, "get_subagents")?
        .get("subagents")
        .and_then(Value::as_array)
        .is_none_or(|subagents| {
            subagents
                .iter()
                .any(|entry| entry.get("id").and_then(Value::as_str) == Some(subagent_id.as_str()))
        })
    {
        return Err("terminal subagent remained in the active roster".to_owned());
    }

    let started_at = driver
        .transcript()
        .iter()
        .position(is_subagent_started)
        .ok_or_else(|| "started lifecycle position disappeared".to_owned())?;
    let terminal_at = driver
        .transcript()
        .iter()
        .position(|frame| is_subagent_terminal(frame, &subagent_id))
        .ok_or_else(|| "terminal lifecycle position disappeared".to_owned())?;
    if terminal_at <= started_at {
        return Err("terminal lifecycle preceded its matching start".to_owned());
    }
    Ok(())
}

fn is_subagent_started(frame: &DecodedRpcFrame) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some("subagent_lifecycle")
        && frame
            .value()
            .pointer("/payload/status")
            .and_then(Value::as_str)
            == Some("started")
}

fn is_subagent_terminal(frame: &DecodedRpcFrame, subagent_id: &str) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some("subagent_lifecycle")
        && frame.value().pointer("/payload/id").and_then(Value::as_str) == Some(subagent_id)
        && matches!(
            frame
                .value()
                .pointer("/payload/status")
                .and_then(Value::as_str),
            Some("completed" | "failed" | "aborted")
        )
}
