//! Case 8 owner: aborting a normal provider call and observing the pinned
//! abort signal settle the turn.

use super::shared::*;
use super::*;

pub(super) struct AbortProviderCall;

const ABORT_TURN_DELAY_MS: u64 = 30_000;

#[async_trait]
impl ConformanceCase for AbortProviderCall {
    fn id(&self) -> ConformanceCaseId {
        ABORT_PROVIDER_CALL
    }

    fn name(&self) -> &'static str {
        "abort_provider_call"
    }

    fn deadline(&self) -> Duration {
        STANDARD_CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
        let driver = match {
            let worker = context.worker_for(&spec);
            RawRpcDriver::spawn(spec, worker)
        }
        .await
        {
            Ok(driver) => driver,
            Err(error) => return startup_failure(self.name(), error),
        };
        let mut run = ControlRun::new(self.name(), driver);
        let result = run_abort_provider_call(&mut run, context).await;
        run.finish(
            "provider abort completed inside its bound and left the session idle",
            "provider abort conformance failed",
            result,
        )
        .await
    }
}

async fn run_abort_provider_call(
    run: &mut ControlRun,
    _context: &CaseContext,
) -> Result<Vec<CaseFailure>, CaseFailure> {
    let forbidden = "provider-call-must-not-complete";
    let prompt = format!("odin-mock:delay {ABORT_TURN_DELAY_MS} {forbidden}");
    let (prompt_id, prompt_start) = run
        .send("prompt", json!({ "message": prompt }), "abort_prompt")
        .await?;
    run.response(
        &prompt_id,
        "prompt",
        RESPONSE_BOUND,
        "abort_prompt_response",
    )
    .await?;
    run.wait_frame(prompt_start, TURN_BOUND, "abort_turn_start", |frame| {
        frame_type(frame, "turn_start")
    })
    .await?;
    let active_state = run.state("abort_active_state").await?;

    let (abort_id, abort_start) = run.send("abort", json!({}), "provider_abort").await?;
    let abort_sent = Instant::now();
    let abort_response = run
        .response_until(
            &abort_id,
            "abort",
            abort_sent + ABORT_BOUND,
            "provider_abort_response",
        )
        .await?;
    let abort_elapsed = abort_sent.elapsed();
    let aborted_message = run
        .wait_frame(
            prompt_start,
            RESPONSE_BOUND,
            "provider_aborted_message",
            is_aborted_assistant,
        )
        .await?;
    let aborted_index = frame_index(run.driver.transcript(), prompt_start, |frame| {
        frame == &aborted_message
    })
    .ok_or_else(|| {
        failure(
            "provider_abort_order",
            "aborted assistant frame was absent from transcript",
        )
    })?;
    run.wait_frame(
        aborted_index,
        RESPONSE_BOUND,
        "provider_abort_agent_end",
        |frame| frame_type(frame, "agent_end"),
    )
    .await?;
    let idle_state = run.state("abort_idle_state").await?;

    let abort_response_index = frame_index(run.driver.transcript(), abort_start, |frame| {
        frame == &abort_response
    });
    // Only assistant message traffic after the abort can prove a delayed
    // completion: the user directive itself quotes the forbidden marker, so
    // user echoes and aggregate agent frames must never be scanned.
    let forbidden_seen = run
        .driver
        .transcript()
        .iter()
        .skip(abort_start)
        .filter_map(|frame| {
            let event = frame.value().get("type").and_then(Value::as_str)?;
            if event == "message_end" || event == "message_update" {
                frame.value().get("message")
            } else {
                None
            }
        })
        .any(|message| {
            message.get("role").and_then(Value::as_str) == Some("assistant")
                && message_text(message).is_some_and(|text| text.contains(forbidden))
        });
    let mut failures = Vec::new();
    require(
        &mut failures,
        active_state.get("isStreaming").and_then(Value::as_bool) == Some(true),
        "provider_abort_active_state",
        format!("provider call was not active before abort: {active_state}"),
    );
    require(
        &mut failures,
        abort_elapsed <= ABORT_BOUND,
        "provider_abort_bound",
        format!(
            "abort took {} ms; bound is {} ms",
            abort_elapsed.as_millis(),
            ABORT_BOUND.as_millis()
        ),
    );
    require(
        &mut failures,
        !forbidden_seen,
        "provider_abort_effect",
        "the delayed provider completion appeared after abort",
    );
    require(
        &mut failures,
        idle_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
            && idle_state.get("queuedMessageCount").and_then(Value::as_u64) == Some(0),
        "provider_abort_idle_state",
        format!("abort did not return the session to idle: {idle_state}"),
    );
    let active_session = active_state.get("sessionId").and_then(Value::as_str);
    require(
        &mut failures,
        active_session.is_some_and(|session| !session.is_empty())
            && idle_state.get("sessionId").and_then(Value::as_str) == active_session,
        "provider_abort_session_stable",
        format!("abort did not remain on one OMP session: {active_state} / {idle_state}"),
    );
    require_order(
        &mut failures,
        Some(aborted_index),
        abort_response_index,
        "provider_abort_completion_order",
        "aborted assistant",
        "abort response",
    );

    run.record_json(
        "effect",
        "bounded-provider-abort",
        &json!({
            "prompt_request_id": prompt_id,
            "abort_request_id": abort_id,
            "abort_elapsed_ms": u64::try_from(abort_elapsed.as_millis()).unwrap_or(u64::MAX),
            "active_state": active_state,
            "aborted_message": aborted_message.value(),
            "abort_response": abort_response.value(),
            "idle_state": idle_state,
        }),
    )?;
    Ok(failures)
}
fn is_aborted_assistant(frame: &DecodedRpcFrame) -> bool {
    event_message(frame, "message_end").is_some_and(|message| {
        message.get("role").and_then(Value::as_str) == Some("assistant")
            && message.get("stopReason").and_then(Value::as_str) == Some("aborted")
    })
}
