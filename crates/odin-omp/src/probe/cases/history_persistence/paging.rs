//! Case 14 machinery: bounded paging of the long mock-provider history,
//! echo-pair verification, and the busy/stale-cursor error windows.

use std::time::Instant;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::probe::{
    CaseContext, CaseEvidence, CaseOutcome, CleanupReceipt, ConformanceCase, ConformanceCaseId,
    RawRpcDriver, DEFAULT_MODEL_SELECTOR,
};

use super::*;

const HISTORY_TURNS: usize = 10;

const HISTORY_EVIDENCE: &[&str] = &[
    "paging_trace",
    "history_snapshot",
    "paging_errors",
    "turn_state",
    "rpc_transcript",
];

pub(super) struct HistoryPagingCase;

#[async_trait]
impl ConformanceCase for HistoryPagingCase {
    fn id(&self) -> ConformanceCaseId {
        HISTORY_PAGING
    }

    fn name(&self) -> &'static str {
        "history_paging"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let mut evidence = Vec::new();
        let mut cleanup = CleanupReceipt::default();
        let result = run_history_paging(context, &mut evidence, &mut cleanup).await;
        finish_case(
            "long history paging retained one stable snapshot and rejected busy/stale reads",
            "history paging conformance failed",
            result,
            evidence,
            cleanup,
            HISTORY_EVIDENCE,
            1,
        )
    }
}

async fn run_history_paging(
    context: &CaseContext,
    evidence: &mut Vec<CaseEvidence>,
    cleanup: &mut CleanupReceipt,
) -> CheckResult<()> {
    let session_dir = context.work_dir().join("history-sessions");
    let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, session_dir_args(&session_dir));
    let mut driver = {
        let worker = context.worker_for(&spec);
        RawRpcDriver::spawn(spec, worker)
    }
    .await
    .map_err(|error| CaseCheck::new("spawn", error.to_string()))?;
    let subject = child_subject(&driver, "case-14-history");

    let body = exercise_history_paging(&mut driver, evidence).await;
    let stop = driver.cleanup(cleanup, subject).await;
    let transcript = push_transcript_evidence(evidence, "history-paging", driver.transcript());

    body?;
    let exit = stop.map_err(|error| CaseCheck::new("cleanup", error.to_string()))?;
    transcript?;
    if !exit.success() {
        return Err(CaseCheck::new(
            "cleanup",
            format!("history child did not exit successfully: {exit}"),
        ));
    }
    Ok(())
}

async fn exercise_history_paging(
    driver: &mut RawRpcDriver,
    evidence: &mut Vec<CaseEvidence>,
) -> CheckResult<()> {
    let initial_state = get_state(driver, "initial_state").await?;
    let baseline_count = state_message_count(&initial_state, "initial_state")?;
    let mut expected_count = baseline_count;

    for turn in 0..HISTORY_TURNS {
        expected_count += 2;
        let state = prompt_and_wait(
            driver,
            &format!("odin-mock:echo case-14-history-{turn:02}"),
            expected_count,
            "history_effect",
        )
        .await?;
        let observed = state_message_count(&state, "history_effect")?;
        if observed != expected_count {
            return Err(CaseCheck::new(
                "history_effect",
                format!(
                    "turn {turn} did not add exactly one user/assistant pair: \
                     expected {expected_count} messages after the turn, observed {observed}"
                ),
            ));
        }
    }

    let base = page_all(driver, "base_paging").await?;
    if base.total != expected_count || base.messages.len() != expected_count {
        return Err(CaseCheck::new(
            "history_effect",
            format!(
                "long history expected {expected_count} messages, paging returned {}/{}",
                base.messages.len(),
                base.total
            ),
        ));
    }
    verify_echo_turn_pairs(&base.messages, baseline_count, "history_effect")?;
    if base.responses.len() < 2 {
        return Err(CaseCheck::new(
            "bounded_paging",
            "long history fit in one page; paging was not exercised",
        ));
    }

    let replay = request(
        driver,
        "get_messages_page",
        page_fields(None),
        "stable_cursor",
    )
    .await?;
    expect_success(&replay, "get_messages_page", "stable_cursor")?;
    let replay_data = response_data(&replay, "stable_cursor")?;
    let first_data = base.responses[0]
        .get("data")
        .ok_or_else(|| CaseCheck::new("stable_cursor", "first page omitted data"))?;
    if replay_data != first_data {
        return Err(CaseCheck::new(
            "stable_cursor",
            "replaying the first page changed its total, messages, or next cursor",
        ));
    }

    let stale_cursor = base.first_next_cursor.clone().ok_or_else(|| {
        CaseCheck::new(
            "stale_cursor",
            "long-history first page did not issue a continuation cursor",
        )
    })?;
    let prompt_id = driver
        .send(
            "prompt",
            json!({"message": "odin-mock:delay 1500 case-14-busy", "images": []}),
        )
        .await
        .map_err(|error| CaseCheck::new("busy_cursor", error.to_string()))?;
    let prompt_ack = driver
        .wait_for_response(&prompt_id, "prompt", Instant::now() + RESPONSE_DEADLINE)
        .await
        .map_err(|error| CaseCheck::new("busy_cursor", error.to_string()))?;
    expect_success(&prompt_ack, "prompt", "busy_cursor")?;

    let busy_state = get_state(driver, "busy_cursor").await?;
    if busy_state.get("isStreaming").and_then(Value::as_bool) != Some(true) {
        return Err(CaseCheck::new(
            "busy_cursor",
            "delayed fixture turn was not streaming before the paging request",
        ));
    }
    let busy_response = request(
        driver,
        "get_messages_page",
        page_fields(None),
        "busy_cursor",
    )
    .await?;
    expect_page_error(&busy_response, "session_busy", "busy_cursor")?;

    let idle_state = wait_for_idle(driver, base.total + 2, "busy_cursor").await?;
    let stale_response = request(
        driver,
        "get_messages_page",
        page_fields(Some(&stale_cursor)),
        "stale_cursor",
    )
    .await?;
    expect_page_error(&stale_response, "stale_cursor", "stale_cursor")?;

    let fresh = page_all(driver, "fresh_paging").await?;
    if fresh.total != base.total + 2 || fresh.messages.len() != fresh.total {
        return Err(CaseCheck::new(
            "snapshot_restart",
            format!(
                "fresh snapshot expected {} messages, returned {}/{}",
                base.total + 2,
                fresh.messages.len(),
                fresh.total
            ),
        ));
    }
    if fresh.messages.get(..base.total) != Some(base.messages.as_slice()) {
        return Err(CaseCheck::new(
            "snapshot_restart",
            "fresh paging did not preserve the complete pre-mutation snapshot as an exact prefix",
        ));
    }
    let marker_count = fresh
        .messages
        .iter()
        .filter(|message| value_contains(message, "case-14-busy"))
        .count();
    if marker_count != 2 {
        return Err(CaseCheck::new(
            "snapshot_restart",
            format!("busy turn marker appeared in {marker_count} messages instead of exactly two"),
        ));
    }
    if state_message_count(&idle_state, "snapshot_restart")? != fresh.total {
        return Err(CaseCheck::new(
            "snapshot_restart",
            "idle state total did not match the complete fresh page drain",
        ));
    }

    let base_history = Value::Array(base.messages.clone());
    let fresh_history = Value::Array(fresh.messages.clone());
    push_json_evidence(
        evidence,
        "paging_trace",
        "stable-and-fresh-pages",
        &json!({
            "base_pages": &base.responses,
            "replayed_first_page": replay.value(),
            "fresh_pages": &fresh.responses,
        }),
        "history_evidence",
    )?;
    push_json_evidence(
        evidence,
        "history_snapshot",
        "before-and-after-mutation",
        &json!({
            "base_total": base.total,
            "baseline_total": baseline_count,
            "base_digest": digest_value(&base_history, "history_evidence")?,
            "base_messages": base_history,
            "fresh_total": fresh.total,
            "fresh_digest": digest_value(&fresh_history, "history_evidence")?,
            "fresh_messages": fresh_history,
        }),
        "history_evidence",
    )?;
    push_json_evidence(
        evidence,
        "paging_errors",
        "busy-and-stale-no-partial-data",
        &json!({
            "busy": busy_response.value(),
            "stale": stale_response.value(),
        }),
        "history_evidence",
    )?;
    push_json_evidence(
        evidence,
        "turn_state",
        "busy-to-idle",
        &json!({"busy": busy_state, "idle": idle_state}),
        "history_evidence",
    )?;
    Ok(())
}

/// Require the case's own history region to be the exact ordered echo pairs:
/// each turn contributes one user message carrying the directive text and one
/// assistant message carrying only the echoed marker, with no third message
/// and no duplicate marker anywhere in the drain.
fn verify_echo_turn_pairs(
    messages: &[Value],
    baseline_count: usize,
    check: &'static str,
) -> CheckResult<()> {
    for turn in 0..HISTORY_TURNS {
        let marker = format!("case-14-history-{turn:02}");
        let user_index = baseline_count + turn * 2;
        let user = messages.get(user_index).ok_or_else(|| {
            CaseCheck::new(
                check,
                format!("turn {turn} user message missing from the drain"),
            )
        })?;
        let assistant = messages.get(user_index + 1).ok_or_else(|| {
            CaseCheck::new(
                check,
                format!("turn {turn} assistant message missing from the drain"),
            )
        })?;
        let directive = format!("odin-mock:echo {marker}");
        if user.get("role").and_then(Value::as_str) != Some("user")
            || message_text(user) != Some(directive.as_str())
        {
            return Err(CaseCheck::new(
                check,
                format!("turn {turn} did not open with the exact user directive message"),
            ));
        }
        if assistant.get("role").and_then(Value::as_str) != Some("assistant")
            || message_text(assistant) != Some(marker.as_str())
        {
            return Err(CaseCheck::new(
                check,
                format!("turn {turn} did not close with the exact echoed assistant message"),
            ));
        }
        let marker_count = messages
            .iter()
            .filter(|message| value_contains(message, &marker))
            .count();
        if marker_count != 2 {
            return Err(CaseCheck::new(
                check,
                format!(
                    "turn {turn} marker appeared in {marker_count} drain messages \
                     instead of its exact pair"
                ),
            ));
        }
    }
    Ok(())
}

/// Text of a paged message: plain string content, or its first `text` block.
fn message_text(message: &Value) -> Option<&str> {
    let content = message.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text);
    }
    content.as_array()?.iter().find_map(|block| {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            block.get("text").and_then(Value::as_str)
        } else {
            None
        }
    })
}
