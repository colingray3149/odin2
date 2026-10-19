//! Case 10 owner: switching models and observing the effective model.

use super::shared::*;
use super::*;

pub(super) struct SetModelObservation;

#[async_trait]
impl ConformanceCase for SetModelObservation {
    fn id(&self) -> ConformanceCaseId {
        SET_MODEL_OBSERVATION
    }

    fn name(&self) -> &'static str {
        "set_model_observation"
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
        let result = run_set_model_observation(&mut run, context).await;
        run.finish(
            "mock-a changed to mock-b in the response, state, event stream, and served turn",
            "model-change observation conformance failed",
            result,
        )
        .await
    }
}

async fn run_set_model_observation(
    run: &mut ControlRun,
    _context: &CaseContext,
) -> Result<Vec<CaseFailure>, CaseFailure> {
    let before_state = run.state("model_before_state").await?;
    let (set_model_id, set_model_start) = run
        .send(
            "set_model",
            json!({ "provider": FIXTURE_PROVIDER, "modelId": FIXTURE_MODEL_B }),
            "set_model_command",
        )
        .await?;
    let set_model_response = run
        .response(
            &set_model_id,
            "set_model",
            RESPONSE_BOUND,
            "set_model_response",
        )
        .await?;
    let model_changed = run
        .wait_frame(
            set_model_start,
            RESPONSE_BOUND,
            "model_changed_event",
            |frame| frame_type(frame, "model_changed"),
        )
        .await?;
    let after_state = run.state("model_after_state").await?;

    let served_prompt = "odin-mock:echo mock-b-served";
    let (prompt_id, prompt_start) = run
        .send(
            "prompt",
            json!({ "message": served_prompt }),
            "model_b_prompt",
        )
        .await?;
    run.response(
        &prompt_id,
        "prompt",
        RESPONSE_BOUND,
        "model_b_prompt_response",
    )
    .await?;
    let served_reply = run
        .wait_frame(prompt_start, TURN_BOUND, "model_b_served_reply", |frame| {
            assistant_text_is(frame, "mock-b-served")
        })
        .await?;
    let served_reply_index = frame_index(run.driver.transcript(), prompt_start, |frame| {
        frame == &served_reply
    })
    .ok_or_else(|| {
        failure(
            "model_b_served_order",
            "mock-b reply was absent from transcript",
        )
    })?;
    run.wait_frame(
        served_reply_index,
        RESPONSE_BOUND,
        "model_b_agent_end",
        |frame| frame_type(frame, "agent_end"),
    )
    .await?;
    let final_state = run.state("model_final_state").await?;

    let model_changed_index = frame_index(run.driver.transcript(), set_model_start, |frame| {
        frame == &model_changed
    });
    let set_model_response_index = frame_index(run.driver.transcript(), set_model_start, |frame| {
        frame == &set_model_response
    });
    let model_changed_count = set_model_response_index.map_or(0, |end| {
        run.driver.transcript()[set_model_start..=end]
            .iter()
            .filter(|frame| frame_type(frame, "model_changed"))
            .count()
    });
    let mut failures = Vec::new();
    require(
        &mut failures,
        model_is(&before_state, FIXTURE_PROVIDER, FIXTURE_MODEL_A),
        "model_before",
        format!(
            "initial effective model was not {FIXTURE_PROVIDER}/{FIXTURE_MODEL_A}: {before_state}"
        ),
    );
    require(
        &mut failures,
        model_is(
            set_model_response
                .value()
                .get("data")
                .unwrap_or(&Value::Null),
            FIXTURE_PROVIDER,
            FIXTURE_MODEL_B,
        ),
        "set_model_response",
        format!(
            "set_model response did not return {FIXTURE_PROVIDER}/{FIXTURE_MODEL_B}: {}",
            set_model_response.value()
        ),
    );
    require(
        &mut failures,
        model_is(&after_state, FIXTURE_PROVIDER, FIXTURE_MODEL_B),
        "model_after_state",
        format!("state did not change to {FIXTURE_PROVIDER}/{FIXTURE_MODEL_B}: {after_state}"),
    );
    require_order(
        &mut failures,
        model_changed_index,
        set_model_response_index,
        "model_changed_order",
        "model_changed event",
        "set_model response",
    );
    require(
        &mut failures,
        model_changed_count == 1,
        "model_changed_cardinality",
        format!("expected one model_changed event before set_model response, observed {model_changed_count}"),
    );
    let served_message = event_message(&served_reply, "message_end");
    require(
        &mut failures,
        served_message
            .and_then(|message| message.get("provider"))
            .and_then(Value::as_str)
            == Some(FIXTURE_PROVIDER)
            && served_message
                .and_then(|message| message.get("model"))
                .and_then(Value::as_str)
                == Some(FIXTURE_MODEL_B),
        "model_b_served_attribution",
        format!(
            "served reply was not attributed to mock-b: {}",
            served_reply.value()
        ),
    );
    let before_session = before_state.get("sessionId").and_then(Value::as_str);
    require(
        &mut failures,
        before_session.is_some_and(|session| !session.is_empty())
            && after_state.get("sessionId").and_then(Value::as_str) == before_session
            && final_state.get("sessionId").and_then(Value::as_str) == before_session
            && final_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
            && model_is(&final_state, FIXTURE_PROVIDER, FIXTURE_MODEL_B),
        "model_final_state",
        format!("model switch did not remain idle on one OMP session: {before_state} / {after_state} / {final_state}"),
    );

    run.record_json(
        "model",
        "mock-a-to-mock-b",
        &json!({
            "set_model_request_id": set_model_id,
            "prompt_request_id": prompt_id,
            "before_state": before_state,
            "model_changed": model_changed.value(),
            "model_changed_count": model_changed_count,
            "set_model_response": set_model_response.value(),
            "after_state": after_state,
            "served_reply": served_reply.value(),
            "final_state": final_state,
            "frame_order": {
                "model_changed": model_changed_index,
                "set_model_response": set_model_response_index,
                "served_reply": served_reply_index,
            },
        }),
    )?;
    Ok(failures)
}
fn model_is(value: &Value, provider: &str, model: &str) -> bool {
    let model_value = value.get("model").unwrap_or(value);
    model_value.get("provider").and_then(Value::as_str) == Some(provider)
        && model_value.get("id").and_then(Value::as_str) == Some(model)
}
