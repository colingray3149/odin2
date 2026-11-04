//! Case 6 owner: steering the model mid-turn through a pinned delay window.

use super::shared::*;
use super::*;

pub(super) struct SteerDuringTurn;

#[async_trait]
impl ConformanceCase for SteerDuringTurn {
    fn id(&self) -> ConformanceCaseId {
        STEER_DURING_TURN
    }

    fn name(&self) -> &'static str {
        "steer_during_turn"
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
        let result = run_steer_during_turn(&mut run, context).await;
        run.finish(
            "steer was injected into the observed active turn and served on the bound session",
            "active-turn steer conformance failed",
            result,
        )
        .await
    }
}

async fn run_steer_during_turn(
    run: &mut ControlRun,
    _context: &CaseContext,
) -> Result<Vec<CaseFailure>, CaseFailure> {
    let original = format!("odin-mock:delay {ACTIVE_TURN_DELAY_MS} steer-original");
    let steered = "odin-mock:echo steer-active-result";
    let (prompt_id, prompt_start) = run
        .send("prompt", json!({ "message": original }), "steer_prompt")
        .await?;
    run.response(
        &prompt_id,
        "prompt",
        RESPONSE_BOUND,
        "steer_prompt_response",
    )
    .await?;
    run.wait_frame(prompt_start, TURN_BOUND, "steer_turn_start", |frame| {
        frame_type(frame, "turn_start")
    })
    .await?;

    let active_state = run.state("steer_active_state").await?;
    let (steer_id, steer_start) = run
        .send("steer", json!({ "message": steered }), "steer_command")
        .await?;
    run.response(&steer_id, "steer", RESPONSE_BOUND, "steer_response")
        .await?;
    let served = run
        .wait_frame(steer_start, TURN_BOUND, "steer_served_reply", |frame| {
            assistant_text_is(frame, "steer-active-result")
        })
        .await?;
    let served_index = frame_index(run.driver.transcript(), steer_start, |frame| {
        frame == &served
    })
    .ok_or_else(|| {
        failure(
            "steer_order",
            "served steer reply was absent from retained transcript",
        )
    })?;
    run.wait_frame(served_index, RESPONSE_BOUND, "steer_agent_end", |frame| {
        frame_type(frame, "agent_end")
    })
    .await?;
    let idle_state = run.state("steer_idle_state").await?;

    let (turn_start, steer_response, steer_message, served_reply) = {
        let frames = run.driver.transcript();
        (
            frame_index(frames, prompt_start, |frame| {
                frame_type(frame, "turn_start")
            }),
            frame_index(frames, steer_start, |frame| {
                response_is(frame, &steer_id, "steer")
            }),
            frame_index(frames, steer_start, |frame| user_text_is(frame, steered)),
            frame_index(frames, steer_start, |frame| {
                assistant_text_is(frame, "steer-active-result")
            }),
        )
    };

    let mut failures = Vec::new();
    require(
        &mut failures,
        active_state.get("isStreaming").and_then(Value::as_bool) == Some(true),
        "steer_active_state",
        format!("state at steer boundary was not streaming: {active_state}"),
    );
    let active_session = active_state.get("sessionId").and_then(Value::as_str);
    require(
        &mut failures,
        active_session.is_some_and(|session| !session.is_empty())
            && idle_state.get("sessionId").and_then(Value::as_str) == active_session,
        "steer_session_stable",
        format!("steer did not remain on one non-empty OMP session: {active_state} / {idle_state}"),
    );
    require(
        &mut failures,
        idle_state.get("isStreaming").and_then(Value::as_bool) == Some(false),
        "steer_idle_state",
        format!("session did not become idle after served steer: {idle_state}"),
    );
    require(
        &mut failures,
        idle_state.get("queuedMessageCount").and_then(Value::as_u64) == Some(0),
        "steer_queue_drained",
        format!("steer queue was not empty after the turn: {idle_state}"),
    );
    require_order(
        &mut failures,
        turn_start,
        steer_response,
        "steer_response_order",
        "turn_start",
        "steer response",
    );
    require_order(
        &mut failures,
        turn_start,
        steer_message,
        "steer_injection_order",
        "turn_start",
        "steer message",
    );
    require_order(
        &mut failures,
        steer_message,
        served_reply,
        "steer_served_order",
        "steer message",
        "steered assistant reply",
    );

    run.record_json(
        "effect",
        "steer-active-turn",
        &json!({
            "prompt_request_id": prompt_id,
            "steer_request_id": steer_id,
            "active_state": active_state,
            "idle_state": idle_state,
            "frame_order": {
                "turn_start": turn_start,
                "steer_response": steer_response,
                "steer_message": steer_message,
                "served_reply": served_reply,
            },
        }),
    )?;
    Ok(failures)
}
