//! Case 7 owner: queueing a follow-up while a turn is in flight.

use super::shared::*;
use super::*;

pub(super) struct FollowUpQueue;

#[async_trait]
impl ConformanceCase for FollowUpQueue {
    fn id(&self) -> ConformanceCaseId {
        FOLLOW_UP_QUEUE
    }

    fn name(&self) -> &'static str {
        "follow_up_queue"
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
        let result = run_follow_up_queue(&mut run, context).await;
        run.finish(
            "follow-up remained queued until the delayed turn completed and then ran in order",
            "follow-up queue conformance failed",
            result,
        )
        .await
    }
}

async fn run_follow_up_queue(
    run: &mut ControlRun,
    _context: &CaseContext,
) -> Result<Vec<CaseFailure>, CaseFailure> {
    let original = format!("odin-mock:delay {ACTIVE_TURN_DELAY_MS} follow-up-first");
    let follow_up = "odin-mock:echo follow-up-second";
    let (prompt_id, prompt_start) = run
        .send("prompt", json!({ "message": original }), "follow_up_prompt")
        .await?;
    run.response(
        &prompt_id,
        "prompt",
        RESPONSE_BOUND,
        "follow_up_prompt_response",
    )
    .await?;
    run.wait_frame(prompt_start, TURN_BOUND, "follow_up_turn_start", |frame| {
        frame_type(frame, "turn_start")
    })
    .await?;
    let active_state = run.state("follow_up_active_state").await?;

    let (follow_id, follow_start) = run
        .send(
            "follow_up",
            json!({ "message": follow_up }),
            "follow_up_command",
        )
        .await?;
    run.response(
        &follow_id,
        "follow_up",
        RESPONSE_BOUND,
        "follow_up_response",
    )
    .await?;
    let queued_state = run.state("follow_up_queued_state").await?;
    let served = run
        .wait_frame(
            follow_start,
            TURN_BOUND,
            "follow_up_served_reply",
            |frame| assistant_text_is(frame, "follow-up-second"),
        )
        .await?;
    let served_index = frame_index(run.driver.transcript(), follow_start, |frame| {
        frame == &served
    })
    .ok_or_else(|| {
        failure(
            "follow_up_order",
            "served follow-up reply was absent from retained transcript",
        )
    })?;
    run.wait_frame(
        served_index,
        RESPONSE_BOUND,
        "follow_up_agent_end",
        |frame| frame_type(frame, "agent_end"),
    )
    .await?;
    let idle_state = run.state("follow_up_idle_state").await?;

    let (follow_response, first_reply, follow_message, second_reply) = {
        let frames = run.driver.transcript();
        (
            frame_index(frames, follow_start, |frame| {
                response_is(frame, &follow_id, "follow_up")
            }),
            frame_index(frames, prompt_start, |frame| {
                assistant_text_is(frame, "follow-up-first")
            }),
            frame_index(frames, follow_start, |frame| user_text_is(frame, follow_up)),
            frame_index(frames, follow_start, |frame| {
                assistant_text_is(frame, "follow-up-second")
            }),
        )
    };

    let mut failures = Vec::new();
    require(
        &mut failures,
        active_state.get("isStreaming").and_then(Value::as_bool) == Some(true),
        "follow_up_active_state",
        format!("state before queueing was not streaming: {active_state}"),
    );
    require(
        &mut failures,
        queued_state.get("isStreaming").and_then(Value::as_bool) == Some(true)
            && queued_state
                .get("queuedMessageCount")
                .and_then(Value::as_u64)
                == Some(1),
        "follow_up_queue_state",
        format!("follow-up was not observably queued during the active turn: {queued_state}"),
    );
    let active_session = active_state.get("sessionId").and_then(Value::as_str);
    require(
        &mut failures,
        active_session.is_some_and(|session| !session.is_empty())
            && queued_state.get("sessionId").and_then(Value::as_str) == active_session
            && idle_state.get("sessionId").and_then(Value::as_str) == active_session,
        "follow_up_session_stable",
        format!("follow-up did not remain on one OMP session: {active_state} / {queued_state} / {idle_state}"),
    );
    require(
        &mut failures,
        idle_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
            && idle_state.get("queuedMessageCount").and_then(Value::as_u64) == Some(0),
        "follow_up_idle_state",
        format!("session or queue did not settle after follow-up: {idle_state}"),
    );
    require_order(
        &mut failures,
        follow_response,
        first_reply,
        "follow_up_queued_before_completion",
        "follow-up response",
        "first assistant reply",
    );
    require_order(
        &mut failures,
        first_reply,
        follow_message,
        "follow_up_after_first_turn",
        "first assistant reply",
        "follow-up message",
    );
    require_order(
        &mut failures,
        follow_message,
        second_reply,
        "follow_up_served_order",
        "follow-up message",
        "second assistant reply",
    );

    run.record_json(
        "effect",
        "follow-up-queue-order",
        &json!({
            "prompt_request_id": prompt_id,
            "follow_up_request_id": follow_id,
            "active_state": active_state,
            "queued_state": queued_state,
            "idle_state": idle_state,
            "frame_order": {
                "follow_up_response": follow_response,
                "first_reply": first_reply,
                "follow_up_message": follow_message,
                "second_reply": second_reply,
            },
        }),
    )?;
    Ok(failures)
}
