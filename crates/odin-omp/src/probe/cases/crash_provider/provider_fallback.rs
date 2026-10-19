//! Case 17 machinery: unavailable provider and model selections, then the
//! configured bounded retry/fallback run with its request-boundary, terminal,
//! and history checks.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::time::sleep;

use crate::frames::DecodedRpcFrame;
use crate::probe::{
    CaseContext, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    ConformanceCase, ConformanceCaseId, RawRpcDriver, DEFAULT_MODEL_SELECTOR, FIXTURE_MODEL_A,
    FIXTURE_MODEL_B, FIXTURE_PROVIDER,
};

use super::*;

const RPC_STEP_DEADLINE: Duration = Duration::from_secs(20);
const FALLBACK_MODEL_SELECTOR: &str = "odin-mock/mock-b";

pub(super) struct ProviderUnavailableFallback;

#[async_trait]
impl ConformanceCase for ProviderUnavailableFallback {
    fn id(&self) -> ConformanceCaseId {
        PROVIDER_UNAVAILABLE_FALLBACK
    }

    fn name(&self) -> &'static str {
        "provider_unavailable_fallback"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_provider_unavailable_fallback(context).await
    }
}

struct ProviderRunEvidence {
    policy: Value,
    journal: Value,
    history: Value,
    raw_frames: Vec<u8>,
    failures: Vec<CaseFailure>,
}

async fn run_provider_unavailable_fallback(context: &CaseContext) -> CaseOutcome {
    let mut cleanup = CleanupReceipt::default();
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    let config = json!({
        "retry":{
            "enabled":true,"maxRetries":1,"baseDelayMs":1,"maxDelayMs":100,
            "modelFallback":true,
            "fallbackChains":{"odin-mock/mock-a":[FALLBACK_MODEL_SELECTOR]},
            "fallbackRevertPolicy":"never",
        },
    });
    let config_bytes = serde_json::to_vec_pretty(&config).expect("JSON values always serialize");
    let config_path = context.work_dir().join(".omp").join("config.yml");
    let config_write = config_path
        .parent()
        .ok_or_else(|| std::io::Error::other("config path has no parent"))
        .and_then(std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&config_path, &config_bytes));
    if let Err(error) = config_write {
        failures.push(CaseFailure {
            check: ("fallback_config").to_owned(),
            detail: format!("could not write isolated project config: {error}"),
        });
        cleanup.push(
            "case_cleanup",
            context.ids().session.to_string(),
            CleanupOutcome::Failed {
                reason: "provider child was never started".to_owned(),
            },
        );
        return finish_outcome(
            "unavailable provider/model exercised configured bounded fallback",
            failures,
            evidence,
            cleanup,
        );
    }

    let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
    let worker = context.worker_for(&spec);
    let mut driver = match RawRpcDriver::spawn(spec, worker).await {
        Ok(driver) => driver,
        Err(error) => {
            failures.push(CaseFailure {
                check: ("provider_start").to_owned(),
                detail: error.to_string(),
            });
            cleanup.push(
                "child_start",
                context.ids().session.to_string(),
                CleanupOutcome::Failed {
                    reason: error.to_string(),
                },
            );
            return finish_outcome(
                "unavailable provider/model exercised configured bounded fallback",
                failures,
                evidence,
                cleanup,
            );
        }
    };
    let run = exercise_provider_fallback(&mut driver, config).await;
    let retained_before_cleanup = driver.transcript().len();
    if let Err(error) = driver
        .cleanup(
            &mut cleanup,
            format!("provider-fallback:{}", context.ids().session),
        )
        .await
    {
        failures.push(CaseFailure {
            check: ("provider_cleanup").to_owned(),
            detail: error.to_string(),
        });
    }
    match run {
        Ok(mut record) => {
            failures.extend(record.failures);
            evidence.push(CaseEvidence {
                kind: "provider_policy",
                label: "configured-fallback.json".to_owned(),
                bytes: config_bytes,
            });
            evidence.push(json_evidence(
                "provider_policy",
                "unavailable-and-fallback.json",
                &record.policy,
            ));
            evidence.push(json_evidence(
                "journal",
                "provider-event-journal.json",
                &record.journal,
            ));
            evidence.push(json_evidence(
                "history",
                "provider-history.json",
                &record.history,
            ));
            for frame in &driver.transcript()[retained_before_cleanup..] {
                append_raw(&mut record.raw_frames, frame.raw());
            }
            evidence.push(CaseEvidence {
                kind: "provider_frames",
                label: "retry-fallback.jsonl".to_owned(),
                bytes: record.raw_frames,
            });
        }
        Err(detail) => failures.push(CaseFailure {
            check: "provider_fallback".to_owned(),
            detail,
        }),
    }
    finish_outcome(
        "unavailable provider/model exercised configured bounded fallback",
        failures,
        evidence,
        cleanup,
    )
}

async fn exercise_provider_fallback(
    driver: &mut RawRpcDriver,
    config: Value,
) -> Result<ProviderRunEvidence, String> {
    require_success(
        &rpc_command(driver, "set_auto_retry", json!({"enabled":true})).await?,
        "set_auto_retry",
    )?;
    let initial_state =
        ensure_model_settled(driver, FIXTURE_PROVIDER, FIXTURE_MODEL_A, "initial state").await?;

    let unavailable_provider = "odin-unavailable-provider";
    let unavailable_model = "odin-unavailable-model";
    let missing_provider_response = rpc_command(
        driver,
        "set_model",
        json!({"provider":unavailable_provider,"modelId":unavailable_model}),
    )
    .await?;
    require_unavailable_response(
        &missing_provider_response,
        &format!("{unavailable_provider}/{unavailable_model}"),
    )?;
    let missing_model_response = rpc_command(
        driver,
        "set_model",
        json!({"provider":FIXTURE_PROVIDER,"modelId":unavailable_model}),
    )
    .await?;
    require_unavailable_response(
        &missing_model_response,
        &format!("{FIXTURE_PROVIDER}/{unavailable_model}"),
    )?;
    let unchanged_state = rpc_command(driver, "get_state", json!({})).await?;
    require_model(
        &unchanged_state,
        FIXTURE_PROVIDER,
        FIXTURE_MODEL_A,
        "state after unavailable selections",
    )?;
    let mut failures = Vec::new();

    let failure_marker = "case17-provider-unavailable";
    let fallback_start = driver.transcript().len();
    let prompt_response = rpc_command(
        driver,
        "prompt",
        json!({"message":format!("odin-mock:throw {failure_marker}")}),
    )
    .await?;
    require_success(&prompt_response, "prompt")?;
    ensure_exhausted_terminal(driver, fallback_start).await?;
    let fallback_end = driver.transcript().len();
    let boundary = inspect_fallback_boundary(
        &driver.transcript()[fallback_start..fallback_end],
        failure_marker,
        &mut failures,
    );

    let success_marker = "case17-fallback-succeeded";
    let success_start = driver.transcript().len();
    let success_response = rpc_command(
        driver,
        "prompt",
        json!({"message":format!("odin-mock:echo {success_marker}")}),
    )
    .await?;
    require_success(&success_response, "prompt")?;
    ensure_fallback_success_terminal(driver, success_start).await?;
    let success_end = driver.transcript().len();
    inspect_fallback_success(
        &driver.transcript()[success_start..success_end],
        success_marker,
        &mut failures,
    );

    let final_state = rpc_command(driver, "get_state", json!({})).await?;
    require_model(
        &final_state,
        FIXTURE_PROVIDER,
        FIXTURE_MODEL_B,
        "fallback state",
    )?;
    let history = rpc_command(driver, "get_messages", json!({})).await?;
    require_success(&history, "get_messages")?;
    require_history_error_then_fallback_success(
        &history,
        failure_marker,
        success_marker,
        &mut failures,
    );
    let event_journal = driver
        .transcript()
        .iter()
        .enumerate()
        .map(|(sequence, frame)| json!({"sequence":sequence,"frame":frame.value()}))
        .collect::<Vec<_>>();
    let raw_frames = raw_transcript(driver.transcript());
    let policy = json!({
        "schema":"odin.omp.probe.provider-fallback.v1","configured":config,
        "unavailable_provider_response":missing_provider_response,
        "unavailable_model_response":missing_model_response,
        "initial_state":initial_state,"state_after_unavailable":unchanged_state,
        "final_state":final_state,"boundary":boundary,
        "terminal_exhaustion_marker":failure_marker,"fallback_success_marker":success_marker,
    });
    Ok(ProviderRunEvidence {
        policy,
        journal: json!({
            "schema":"odin.omp.probe.provider-event-journal.v1","frames":event_journal,
        }),
        history,
        raw_frames,
        failures,
    })
}

async fn rpc_command(
    driver: &mut RawRpcDriver,
    command: &str,
    fields: Value,
) -> Result<Value, String> {
    let id = driver
        .send(command, fields)
        .await
        .map_err(|error| format!("{command} send failed: {error}"))?;
    let frame = driver
        .wait_for_response(&id, command, Instant::now() + RPC_STEP_DEADLINE)
        .await
        .map_err(|error| format!("{command} response failed: {error}"))?;
    Ok(frame.value().clone())
}

/// The pinned 18.1.18 child resolves `--model` deferred, after extensions
/// load, and a cold-start resolution that observes a partial catalog falls
/// back to the stock default selection until the extension catalog
/// populates. Polls the real state until it observes the declared fixture
/// model within the bounded step deadline — the current catalog contract,
/// observed honestly instead of assumed from the first response.
async fn ensure_model_settled(
    driver: &mut RawRpcDriver,
    provider: &str,
    model: &str,
    phase: &str,
) -> Result<Value, String> {
    let deadline = Instant::now() + RPC_STEP_DEADLINE;
    loop {
        let state = rpc_command(driver, "get_state", json!({})).await?;
        match require_model(&state, provider, model, phase) {
            Ok(()) => return Ok(state),
            Err(detail) if Instant::now() >= deadline => return Err(detail),
            Err(_) => sleep(Duration::from_millis(100)).await,
        }
    }
}

async fn ensure_exhausted_terminal(driver: &mut RawRpcDriver, from: usize) -> Result<(), String> {
    let existing = &driver.transcript()[from..];
    let mut exhausted = existing.iter().any(is_exhaustion);
    if event_precedes_terminal(existing, is_exhaustion) {
        return Ok(());
    }
    if existing.iter().any(is_terminal_agent_end) {
        return Err("terminal agent_end preceded required auto_retry_end".to_owned());
    }
    driver
        .collect_until(Instant::now() + RPC_STEP_DEADLINE, |frame| {
            if is_exhaustion(frame) {
                exhausted = true;
            }
            exhausted && is_terminal_agent_end(frame)
        })
        .await
        .map_err(|error| format!("fallback exhaustion lifecycle did not settle: {error}"))?;
    Ok(())
}

async fn ensure_fallback_success_terminal(
    driver: &mut RawRpcDriver,
    from: usize,
) -> Result<(), String> {
    let existing = &driver.transcript()[from..];
    let mut succeeded = existing.iter().any(is_fallback_succeeded);
    if event_precedes_terminal(existing, is_fallback_succeeded) {
        return Ok(());
    }
    if existing.iter().any(is_terminal_agent_end) {
        return Err("terminal agent_end preceded required retry_fallback_succeeded".to_owned());
    }
    driver
        .collect_until(Instant::now() + RPC_STEP_DEADLINE, |frame| {
            if is_fallback_succeeded(frame) {
                succeeded = true;
            }
            succeeded && is_terminal_agent_end(frame)
        })
        .await
        .map_err(|error| format!("fallback success lifecycle did not settle: {error}"))?;
    Ok(())
}

fn inspect_fallback_boundary(
    frames: &[DecodedRpcFrame],
    failure_marker: &str,
    failures: &mut Vec<CaseFailure>,
) -> Value {
    let error_turn = frames.iter().position(|frame| {
        frame_type(frame) == Some("turn_end")
            && frame
                .value()
                .pointer("/message/stopReason")
                .and_then(Value::as_str)
                == Some("error")
            && value_contains_text(frame.value(), failure_marker)
    });
    let model_change = next_frame_index(frames, error_turn, "model_changed");
    let fallback_applied = next_frame_index(frames, model_change, "retry_fallback_applied");
    let next_turn = next_frame_index(frames, fallback_applied, "turn_start");
    let fallback_error_turn = next_turn.and_then(|index| {
        frames
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, frame)| {
                frame_type(frame) == Some("turn_end")
                    && frame
                        .value()
                        .pointer("/message/stopReason")
                        .and_then(Value::as_str)
                        == Some("error")
                    && frame
                        .value()
                        .pointer("/message/provider")
                        .and_then(Value::as_str)
                        == Some(FIXTURE_PROVIDER)
                    && frame
                        .value()
                        .pointer("/message/model")
                        .and_then(Value::as_str)
                        == Some(FIXTURE_MODEL_B)
            })
            .map(|(index, _)| index)
    });
    let boundary_ok = matches!(
        (error_turn, model_change, fallback_applied, next_turn, fallback_error_turn),
        (Some(error), Some(change), Some(applied), Some(turn), Some(fallback_error))
            if error < change && change < applied && applied < turn && turn < fallback_error
    );
    if !boundary_ok {
        failures.push(CaseFailure { check: ("request_boundary_switch").to_owned(), detail: format!(
            "fallback was not wholly between provider turns or mock-b did not serve: error={error_turn:?}, model_change={model_change:?}, applied={fallback_applied:?}, next_turn={next_turn:?}, fallback_error={fallback_error_turn:?}"
        ) });
    }
    let applied_count = frames
        .iter()
        .filter(|frame| frame_type(frame) == Some("retry_fallback_applied"))
        .count();
    if applied_count != 1 {
        failures.push(CaseFailure {
            check: ("fallback_applied").to_owned(),
            detail: format!("expected one configured fallback event, observed {applied_count}"),
        });
    } else {
        let value = frames
            .iter()
            .find(|frame| frame_type(frame) == Some("retry_fallback_applied"))
            .expect("count proved one fallback event")
            .value();
        let from = value
            .get("from")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let to = value.get("to").and_then(Value::as_str).unwrap_or_default();
        let role = value
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !from.starts_with(DEFAULT_MODEL_SELECTOR)
            || to != FALLBACK_MODEL_SELECTOR
            || role != DEFAULT_MODEL_SELECTOR
        {
            failures.push(CaseFailure {
                check: ("fallback_applied").to_owned(),
                detail: format!("unexpected configured fallback: {from} -> {to}, role={role}"),
            });
        }
    }
    let retry_starts = frames
        .iter()
        .filter(|frame| frame_type(frame) == Some("auto_retry_start"))
        .count();
    if retry_starts != 1 {
        failures.push(CaseFailure {
            check: ("auto_retry_start").to_owned(),
            detail: format!("expected one bounded retry start, observed {retry_starts}"),
        });
    } else {
        let start = frames
            .iter()
            .find(|frame| frame_type(frame) == Some("auto_retry_start"))
            .expect("count proved one retry start")
            .value();
        if start.get("attempt").and_then(Value::as_u64) != Some(1)
            || start.get("maxAttempts").and_then(Value::as_u64) != Some(1)
        {
            failures.push(CaseFailure {
                check: ("auto_retry_start").to_owned(),
                detail: format!("retry start did not expose the configured 1/1 bound: {start}"),
            });
        }
    }
    let exhausted_count = frames.iter().filter(|frame| is_exhaustion(frame)).count();
    if exhausted_count != 1 {
        failures.push(CaseFailure {
            check: ("fallback_exhaustion").to_owned(),
            detail: format!("expected one surfaced retry exhaustion, observed {exhausted_count}"),
        });
    } else {
        let exhausted = frames
            .iter()
            .find(|frame| is_exhaustion(frame))
            .expect("count proved one exhaustion event")
            .value();
        if exhausted.get("attempt").and_then(Value::as_u64) != Some(1)
            || exhausted
                .get("finalError")
                .and_then(Value::as_str)
                .is_none_or(|error| !error.contains(failure_marker))
        {
            failures.push(CaseFailure { check: ("fallback_exhaustion").to_owned(), detail: format!(
                "retry exhaustion omitted its 1-attempt bound or terminal provider error: {exhausted}"
            ) });
        }
    }
    json!({
        "error_turn_end":error_turn,"model_changed":model_change,
        "fallback_applied":fallback_applied,"retry_turn_start":next_turn,
        "fallback_error_turn_end":fallback_error_turn,
        "switch_between_requests":boundary_ok,"auto_retry_start_count":retry_starts,
        "auto_retry_exhaustion_count":exhausted_count,
    })
}

fn next_frame_index(frames: &[DecodedRpcFrame], after: Option<usize>, kind: &str) -> Option<usize> {
    let after = after?;
    frames
        .iter()
        .enumerate()
        .skip(after + 1)
        .find(|(_, frame)| frame_type(frame) == Some(kind))
        .map(|(index, _)| index)
}

fn event_precedes_terminal(
    frames: &[DecodedRpcFrame],
    event: impl Fn(&DecodedRpcFrame) -> bool,
) -> bool {
    let mut observed = false;
    frames.iter().any(|frame| {
        observed |= event(frame);
        observed && is_terminal_agent_end(frame)
    })
}

fn inspect_fallback_success(
    frames: &[DecodedRpcFrame],
    success_marker: &str,
    failures: &mut Vec<CaseFailure>,
) {
    let succeeded_count = frames
        .iter()
        .filter(|frame| is_fallback_succeeded(frame))
        .count();
    if succeeded_count != 1 {
        failures.push(CaseFailure {
            check: ("fallback_succeeded").to_owned(),
            detail: format!(
            "expected one fallback-succeeded event on the next request, observed {succeeded_count}"
        ),
        });
    } else {
        let value = frames
            .iter()
            .find(|frame| is_fallback_succeeded(frame))
            .expect("count proved one fallback success event")
            .value();
        let model = value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let role = value
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !model.starts_with(FALLBACK_MODEL_SELECTOR) || role != DEFAULT_MODEL_SELECTOR {
            failures.push(CaseFailure {
                check: ("fallback_succeeded").to_owned(),
                detail: format!(
                    "fallback success had unexpected attribution: model={model}, role={role}"
                ),
            });
        }
    }
    let successful_turn = frames.iter().any(|frame| {
        frame_type(frame) == Some("turn_end")
            && frame
                .value()
                .pointer("/message/stopReason")
                .and_then(Value::as_str)
                == Some("stop")
            && frame
                .value()
                .pointer("/message/provider")
                .and_then(Value::as_str)
                == Some(FIXTURE_PROVIDER)
            && frame
                .value()
                .pointer("/message/model")
                .and_then(Value::as_str)
                == Some(FIXTURE_MODEL_B)
            && value_contains_text(frame.value(), success_marker)
    });
    if !successful_turn {
        failures.push(CaseFailure {
            check: ("fallback_effect").to_owned(),
            detail: "mock-b did not produce the deterministic successful effect".to_owned(),
        });
    }
}

fn require_history_error_then_fallback_success(
    history: &Value,
    failure_marker: &str,
    success_marker: &str,
    failures: &mut Vec<CaseFailure>,
) {
    let check = "provider_history";
    let Some(messages) = history.pointer("/data/messages").and_then(Value::as_array) else {
        failures.push(CaseFailure {
            check: check.to_owned(),
            detail: "get_messages response omitted data.messages".to_owned(),
        });
        return;
    };
    let error_index = messages.iter().position(|message| {
        message.get("role").and_then(Value::as_str) == Some("assistant")
            && message.get("stopReason").and_then(Value::as_str) == Some("error")
            && message
                .get("errorMessage")
                .and_then(Value::as_str)
                .is_some_and(|error| error.contains(failure_marker))
    });
    let Some(error_index) = error_index else {
        failures.push(CaseFailure {
            check: check.to_owned(),
            detail: format!("history omitted the assistant error turn for {failure_marker}"),
        });
        return;
    };
    let success_index = messages.iter().position(|message| {
        message.get("role").and_then(Value::as_str) == Some("assistant")
            && message.get("stopReason").and_then(Value::as_str) == Some("stop")
            && message.get("model").and_then(Value::as_str) == Some(FIXTURE_MODEL_B)
            && message
                .get("content")
                .is_some_and(|content| value_contains_text(content, success_marker))
    });
    match success_index {
        Some(success_index) if success_index > error_index => {}
        Some(success_index) => failures.push(CaseFailure { check: check.to_owned(), detail: format!(
            "mock-b success turn preceded the assistant error turn ({success_index} <= {error_index})"
        ) }),
        None => failures.push(CaseFailure { check: check.to_owned(), detail: format!("history omitted the mock-b success turn for {success_marker}") }),
    }
}

fn require_success(response: &Value, command: &str) -> Result<(), String> {
    if response.get("type").and_then(Value::as_str) == Some("response")
        && response.get("command").and_then(Value::as_str) == Some(command)
        && response.get("success").and_then(Value::as_bool) == Some(true)
    {
        Ok(())
    } else {
        Err(format!(
            "{command} returned a non-success response: {response}"
        ))
    }
}

fn require_unavailable_response(response: &Value, selector: &str) -> Result<(), String> {
    if response.get("type").and_then(Value::as_str) != Some("response")
        || response.get("command").and_then(Value::as_str) != Some("set_model")
        || response.get("success").and_then(Value::as_bool) != Some(false)
    {
        return Err(format!(
            "unavailable selector {selector} was not rejected: {response}"
        ));
    }
    let error = response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !error.contains("Model not found") || !error.contains(selector) {
        return Err(format!(
            "unavailable selector {selector} returned non-specific evidence: {error}"
        ));
    }
    Ok(())
}

fn require_model(
    state_response: &Value,
    provider: &str,
    model: &str,
    phase: &str,
) -> Result<(), String> {
    require_success(state_response, "get_state")?;
    let actual_provider = state_response
        .pointer("/data/model/provider")
        .and_then(Value::as_str);
    let actual_model = state_response
        .pointer("/data/model/id")
        .and_then(Value::as_str);
    if actual_provider != Some(provider) || actual_model != Some(model) {
        return Err(format!(
            "{phase} selected {actual_provider:?}/{actual_model:?}, expected {provider}/{model}"
        ));
    }
    Ok(())
}

fn is_exhaustion(frame: &DecodedRpcFrame) -> bool {
    frame_type(frame) == Some("auto_retry_end")
        && frame.value().get("success").and_then(Value::as_bool) == Some(false)
}

fn is_fallback_succeeded(frame: &DecodedRpcFrame) -> bool {
    frame_type(frame) == Some("retry_fallback_succeeded")
}

fn is_terminal_agent_end(frame: &DecodedRpcFrame) -> bool {
    frame_type(frame) == Some("agent_end")
        && frame.value().get("isTerminal").and_then(Value::as_bool) != Some(false)
}

fn frame_type(frame: &DecodedRpcFrame) -> Option<&str> {
    frame.value().get("type").and_then(Value::as_str)
}

fn value_contains_text(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_text(value, needle)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_text(value, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn raw_transcript(frames: &[DecodedRpcFrame]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for frame in frames {
        append_raw(&mut bytes, frame.raw());
    }
    bytes
}
