//! Case 9 owner: abort/recover during compaction plus the background local
//! command lifecycle, including orphan cleanup and artifact evidence.

use super::shared::*;
use super::*;

pub(super) struct AbortCompactionAndBash;

const COMPACTION_REPLY_BYTES: usize = 32 * 1024;
const BASH_START_BOUND: Duration = Duration::from_secs(5);
const BASH_ORPHAN_DELAY: Duration = Duration::from_secs(2);
const BASH_ORPHAN_GRACE: Duration = Duration::from_millis(500);
const COMPACTION_CASE_DEADLINE: Duration = Duration::from_secs(60);
const FILE_POLL_INTERVAL: Duration = Duration::from_millis(10);

const COMPACTION_CONFIG: &str = "compaction:\n  enabled: true\n  methodOrder:\n    - soft\n  thresholdTokens: 4000\n  keepRecentTokens: 256\n  asyncEnabled: false\n  autoContinue: false\n";

#[async_trait]
impl ConformanceCase for AbortCompactionAndBash {
    fn id(&self) -> ConformanceCaseId {
        ABORT_COMPACTION_AND_BASH
    }

    fn name(&self) -> &'static str {
        "abort_compaction_and_bash"
    }

    fn deadline(&self) -> Duration {
        COMPACTION_CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        if let Err(error) = std::fs::create_dir_all(context.work_dir()) {
            return setup_failure(self.name(), "compaction_config", error);
        }
        let config_path = context.work_dir().join("case-09-compaction.yml");
        if let Err(error) = std::fs::write(&config_path, COMPACTION_CONFIG.as_bytes()) {
            return setup_failure(self.name(), "compaction_config", error);
        }
        let spec = context.process_spec(
            DEFAULT_MODEL_SELECTOR,
            vec![
                "--config".to_owned(),
                config_path.to_string_lossy().into_owned(),
            ],
        );
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
        run.record_bytes(
            "fixture_config",
            "soft-compaction-overlay",
            COMPACTION_CONFIG.as_bytes().to_vec(),
        );
        let result = run_abort_compaction_and_bash(&mut run, context).await;
        run.finish(
            "automatic compaction and background bash aborted cleanly; state and command execution recovered",
            "compaction and background-bash recovery conformance failed",
            result,
        )
        .await
    }
}

async fn run_abort_compaction_and_bash(
    run: &mut ControlRun,
    context: &CaseContext,
) -> Result<Vec<CaseFailure>, CaseFailure> {
    let baseline_state = run.state("compaction_baseline_state").await?;
    let (enable_id, _) = run
        .send(
            "set_auto_compaction",
            json!({ "enabled": true }),
            "enable_auto_compaction",
        )
        .await?;
    run.response(
        &enable_id,
        "set_auto_compaction",
        RESPONSE_BOUND,
        "enable_auto_compaction_response",
    )
    .await?;

    let mut seed_request_ids = Vec::with_capacity(2);
    for (message, reply, label) in [
        (
            "odin-mock:echo compaction-seed-a",
            "compaction-seed-a",
            "compaction_seed_a",
        ),
        (
            "odin-mock:echo compaction-seed-b",
            "compaction-seed-b",
            "compaction_seed_b",
        ),
    ] {
        let (seed_id, seed_start) = run
            .send("prompt", json!({ "message": message }), label)
            .await?;
        run.response(&seed_id, "prompt", RESPONSE_BOUND, label)
            .await?;
        let seed_reply = run
            .wait_frame(seed_start, RESPONSE_BOUND, label, |frame| {
                assistant_text_is(frame, reply)
            })
            .await?;
        let seed_reply_index = frame_index(run.driver.transcript(), seed_start, |frame| {
            frame == &seed_reply
        })
        .ok_or_else(|| failure(label, "seed reply was absent from retained transcript"))?;
        run.wait_frame(seed_reply_index, RESPONSE_BOUND, label, |frame| {
            frame_type(frame, "agent_end")
        })
        .await?;
        seed_request_ids.push(seed_id);
    }

    let big_prompt = format!("odin-mock:big {COMPACTION_REPLY_BYTES}");
    let (prompt_id, prompt_start) = run
        .send(
            "prompt",
            json!({ "message": big_prompt }),
            "compaction_trigger_prompt",
        )
        .await?;
    run.response(
        &prompt_id,
        "prompt",
        RESPONSE_BOUND,
        "compaction_trigger_response",
    )
    .await?;
    let compaction_start = run
        .wait_frame(prompt_start, TURN_BOUND, "auto_compaction_start", |frame| {
            frame_type(frame, "auto_compaction_start")
        })
        .await?;
    let compaction_start_index = frame_index(run.driver.transcript(), prompt_start, |frame| {
        frame == &compaction_start
    })
    .ok_or_else(|| {
        failure(
            "auto_compaction_order",
            "start frame was absent from transcript",
        )
    })?;
    let compacting_state = run.state("compacting_state").await?;

    // The threshold-triggering user directive and its exact-size assistant
    // reply are the compaction input/effect that must not be lost. Capture
    // both typed `message_end`s from the live wire before aborting so the
    // retained raw transcript carries authoritative pre-event evidence even
    // when the compaction window later replaces either side by design.
    let big_prompt_end = run
        .wait_frame(
            prompt_start,
            TURN_BOUND,
            "compaction_big_prompt_end",
            |frame| is_big_prompt_end(frame, &big_prompt),
        )
        .await?;
    let big_reply_end = run
        .wait_frame(
            prompt_start,
            TURN_BOUND,
            "compaction_big_reply_end",
            is_big_assistant_reply_end,
        )
        .await?;
    let (abort_id, abort_start) = run.send("abort", json!({}), "compaction_abort").await?;
    let abort_sent = Instant::now();
    let abort_response = run
        .response_until(
            &abort_id,
            "abort",
            abort_sent + ABORT_BOUND,
            "compaction_abort_response",
        )
        .await?;
    let abort_elapsed = abort_sent.elapsed();
    let compaction_end = run
        .wait_frame(
            compaction_start_index,
            RESPONSE_BOUND,
            "auto_compaction_end",
            |frame| frame_type(frame, "auto_compaction_end"),
        )
        .await?;
    let compaction_end_index =
        frame_index(run.driver.transcript(), compaction_start_index, |frame| {
            frame == &compaction_end
        })
        .ok_or_else(|| {
            failure(
                "auto_compaction_order",
                "end frame was absent from transcript",
            )
        })?;
    let post_abort_state = run.state("post_compaction_abort_state").await?;

    let preserved_messages = run.messages("post_compaction_abort_messages").await?;
    let (disable_id, _) = run
        .send(
            "set_auto_compaction",
            json!({ "enabled": false }),
            "disable_auto_compaction",
        )
        .await?;
    run.response(
        &disable_id,
        "set_auto_compaction",
        RESPONSE_BOUND,
        "disable_auto_compaction_response",
    )
    .await?;

    let recovery_prompt = "odin-mock:echo compaction-recovered";
    let (recovery_id, recovery_start) = run
        .send(
            "prompt",
            json!({ "message": recovery_prompt }),
            "compaction_recovery_prompt",
        )
        .await?;
    run.response(
        &recovery_id,
        "prompt",
        RESPONSE_BOUND,
        "compaction_recovery_response",
    )
    .await?;
    let recovery_reply = run
        .wait_frame(
            recovery_start,
            TURN_BOUND,
            "compaction_recovery_reply",
            |frame| assistant_text_is(frame, "compaction-recovered"),
        )
        .await?;
    let recovery_reply_index = frame_index(run.driver.transcript(), recovery_start, |frame| {
        frame == &recovery_reply
    })
    .ok_or_else(|| {
        failure(
            "compaction_recovery_order",
            "recovery reply was absent from transcript",
        )
    })?;
    run.wait_frame(
        recovery_reply_index,
        RESPONSE_BOUND,
        "compaction_recovery_agent_end",
        |frame| frame_type(frame, "agent_end"),
    )
    .await?;
    let recovered_state = run.state("compaction_recovered_state").await?;
    // The pinned auto compaction settles either by honoring the abort
    // (`aborted`) or by emitting a typed skipped/completed end; both branches
    // are a clean recovery once the window closed, the post-abort state
    // settled, and the recovery prompt finished on an idle session.
    let compaction_end_settled = compaction_end_is_settled(&compaction_end);
    let compaction_recovered_clean = compaction_end_settled
        && post_abort_state
            .get("isCompacting")
            .and_then(Value::as_bool)
            == Some(false)
        && recovered_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
        && recovered_state.get("isCompacting").and_then(Value::as_bool) == Some(false);
    run.cleanup.push(
        "compaction_abort",
        "automatic-compaction",
        if compaction_recovered_clean {
            CleanupOutcome::Clean
        } else {
            CleanupOutcome::Failed {
                reason:
                    "compaction end did not settle (aborted/skipped/result) into a recovered prompt"
                        .to_owned(),
            }
        },
    );

    let marker_dir = reserve_marker_dir(context.work_dir())?;
    let bash_started_path = marker_dir.join("child-started");
    let bash_orphan_path = marker_dir.join("orphan-write");
    run.register_marker_fixture(
        marker_dir.clone(),
        bash_started_path.clone(),
        bash_orphan_path.clone(),
    );
    let bash_command = format!(
        "(printf 'child-started\\n' > {}; sleep {}; printf 'orphan\\n' > {}) & wait",
        shell_quote(&bash_started_path),
        BASH_ORPHAN_DELAY.as_secs(),
        shell_quote(&bash_orphan_path),
    );
    let (bash_id, bash_start) = run
        .send(
            "bash",
            json!({ "command": bash_command }),
            "background_bash",
        )
        .await?;
    let bash_started_at = wait_for_file(&bash_started_path, BASH_START_BOUND).await?;
    run.mark(
        "background_bash.child_started",
        json!({ "path": bash_started_path, "request_id": bash_id }),
    );

    let (abort_bash_id, abort_bash_start) = run
        .send("abort_bash", json!({}), "abort_background_bash")
        .await?;
    let abort_bash_response = run
        .response(
            &abort_bash_id,
            "abort_bash",
            RESPONSE_BOUND,
            "abort_background_bash_response",
        )
        .await?;
    let bash_response = run
        .response(&bash_id, "bash", RESPONSE_BOUND, "cancelled_bash_response")
        .await?;

    let orphan_observation_end = bash_started_at + BASH_ORPHAN_DELAY + BASH_ORPHAN_GRACE;
    if Instant::now() < orphan_observation_end {
        time::sleep_until(time::Instant::from_std(orphan_observation_end)).await;
    }
    let orphan_exists = path_exists(&bash_orphan_path)?;
    run.mark(
        "background_bash.orphan_window_complete",
        json!({
            "observation_ms": (BASH_ORPHAN_DELAY + BASH_ORPHAN_GRACE).as_millis(),
            "orphan_marker_exists": orphan_exists,
        }),
    );
    let bash_cancelled = bash_response
        .value()
        .pointer("/data/cancelled")
        .and_then(Value::as_bool)
        == Some(true);
    run.cleanup.push(
        "background_bash_abort",
        bash_id.clone(),
        if bash_cancelled && !orphan_exists {
            CleanupOutcome::Clean
        } else {
            CleanupOutcome::Failed {
                reason: format!("cancelled={bash_cancelled}, orphan_marker_exists={orphan_exists}"),
            }
        },
    );
    run.cleanup_registered_marker(true);

    let recovery_command = "printf 'odin-bash-recovered\\n'";
    let (bash_recovery_id, _) = run
        .send(
            "bash",
            json!({ "command": recovery_command }),
            "bash_recovery",
        )
        .await?;
    let bash_recovery_response = run
        .response(
            &bash_recovery_id,
            "bash",
            RESPONSE_BOUND,
            "bash_recovery_response",
        )
        .await?;
    let final_messages = run.messages("compaction_bash_final_messages").await?;
    let final_state = run.state("compaction_bash_final_state").await?;

    let (big_reply_seen, original_prompt_seen) =
        message_set_contains_compaction_input(&preserved_messages, &big_prompt);
    let big_reply_end_index = frame_index(run.driver.transcript(), prompt_start, |frame| {
        is_big_assistant_reply_end(frame)
    });
    let big_reply_pre_event = big_reply_end_index.is_some();
    let big_reply_branch = match (big_reply_pre_event, big_reply_seen) {
        (true, true) => "pre_event_message_end+post_history",
        (true, false) => "pre_event_message_end",
        (false, true) => "post_history",
        (false, false) => "none",
    };
    let big_prompt_end_index = frame_index(run.driver.transcript(), prompt_start, |frame| {
        is_big_prompt_end(frame, &big_prompt)
    });
    let big_prompt_pre_event = big_prompt_end_index.is_some();
    let big_prompt_branch = match (big_prompt_pre_event, original_prompt_seen) {
        (true, true) => "pre_event_message_end+post_history",
        (true, false) => "pre_event_message_end",
        (false, true) => "post_history",
        (false, false) => "none",
    };
    // A committed compaction summary is `{role: "compactionSummary",
    // summary: "...", shortSummary?: "..."}`: the payload lives in top-level
    // string fields, not message content blocks, and an empty or malformed
    // summary proves nothing about the compaction commit.
    let compaction_summary = preserved_messages.as_array().and_then(|items| {
        items.iter().find_map(|message| {
            let summary = message.get("summary").and_then(Value::as_str)?;
            (message.get("role").and_then(Value::as_str) == Some("compactionSummary")
                && !summary.trim().is_empty()
                && message
                    .get("shortSummary")
                    .map(|short| short.as_str().is_some_and(|text| !text.trim().is_empty()))
                    .unwrap_or(true))
            .then_some(summary)
        })
    });
    let compaction_summary_retained = compaction_summary.is_some();
    let messages = final_messages.as_array();
    let cancelled_bash_message = messages.and_then(|items| {
        items.iter().find(|message| {
            message.get("role").and_then(Value::as_str) == Some("bashExecution")
                && message.get("command").and_then(Value::as_str) == Some(bash_command.as_str())
        })
    });
    let recovered_bash_message = messages.and_then(|items| {
        items.iter().find(|message| {
            message.get("role").and_then(Value::as_str) == Some("bashExecution")
                && message.get("command").and_then(Value::as_str) == Some(recovery_command)
        })
    });
    let abort_response_index = frame_index(run.driver.transcript(), abort_start, |frame| {
        frame == &abort_response
    });
    let abort_bash_response_index =
        frame_index(run.driver.transcript(), abort_bash_start, |frame| {
            frame == &abort_bash_response
        });
    let bash_response_index = frame_index(run.driver.transcript(), bash_start, |frame| {
        frame == &bash_response
    });

    let mut failures = Vec::new();
    require(
        &mut failures,
        baseline_state
            .get("autoCompactionEnabled")
            .and_then(Value::as_bool)
            == Some(true),
        "auto_compaction_enabled",
        format!("overlay did not start with automatic compaction enabled: {baseline_state}"),
    );
    require(
        &mut failures,
        compaction_start
            .value()
            .get("reason")
            .and_then(Value::as_str)
            == Some("threshold"),
        "auto_compaction_reason",
        format!(
            "automatic compaction did not report threshold reason: {}",
            compaction_start.value()
        ),
    );
    require(
        &mut failures,
        compacting_state
            .get("isCompacting")
            .and_then(Value::as_bool)
            == Some(true)
            || frame_index(
                run.driver.transcript(),
                compaction_start_index,
                |frame| frame_type(frame, "auto_compaction_end"),
            )
            .is_some(),
        "auto_compaction_active_state",
        format!(
            "state did not expose active automatic compaction or a settled window: {compacting_state}"
        ),
    );
    require(
        &mut failures,
        compaction_recovered_clean,
        "auto_compaction_abort_effect",
        format!(
            "compaction end/state did not prove a clean abort or recovery: {} / {post_abort_state}",
            compaction_end.value()
        ),
    );
    require_order(
        &mut failures,
        Some(compaction_start_index),
        Some(compaction_end_index),
        "auto_compaction_event_order",
        "auto_compaction_start",
        "auto_compaction_end",
    );
    require_order(
        &mut failures,
        Some(compaction_end_index),
        abort_response_index,
        "auto_compaction_abort_response_order",
        "auto_compaction_end",
        "abort response",
    );
    require_order(
        &mut failures,
        big_reply_end_index,
        abort_response_index,
        "compaction_reply_pre_event_order",
        "exact-size reply message_end",
        "abort response",
    );
    require_order(
        &mut failures,
        big_prompt_end_index,
        abort_response_index,
        "compaction_prompt_pre_event_order",
        "exact user directive message_end",
        "abort response",
    );
    let compaction_end_result = compaction_end
        .value()
        .get("result")
        .is_some_and(|result| !result.is_null());
    let recovery_state_clean = recovered_state.get("isStreaming").and_then(Value::as_bool)
        == Some(false)
        && recovered_state.get("isCompacting").and_then(Value::as_bool) == Some(false);
    require(
        &mut failures,
        original_prompt_seen || big_prompt_pre_event,
        "auto_compaction_prompt_evidence",
        format!(
            "the threshold-triggering user directive was neither proven from the pre-compaction typed message_end nor retained in post-compaction history: {big_prompt_branch}"
        ),
    );
    if !original_prompt_seen {
        // Compaction legitimately drops the compacted-away source directive,
        // so no silent loss is proven by the immutable raw-transcript
        // message_end plus a committed compaction summary (typed end result
        // or the retained summary entry) and a successfully recovered state.
        require(
            &mut failures,
            big_prompt_pre_event
                && (compaction_end_result || compaction_summary_retained)
                && post_abort_state.get("isCompacting").and_then(Value::as_bool) == Some(false)
                && recovery_state_clean,
            "auto_compaction_prompt_compaction_result",
            "the threshold-triggering user directive left post-compaction history without a pre-event message_end, a committed compaction summary, and a recovered prompt/state",
        );
    }
    require(
        &mut failures,
        big_reply_pre_event || big_reply_seen,
        "auto_compaction_reply_evidence",
        format!(
            "the exact-size assistant reply was neither proven from the pre-abort typed message_end nor retained in post-abort history: {big_reply_branch}"
        ),
    );
    if !big_reply_seen {
        require(
            &mut failures,
            big_reply_pre_event
                && compaction_end_result
                && post_abort_state.get("isCompacting").and_then(Value::as_bool) == Some(false)
                && recovery_state_clean,
            "auto_compaction_reply_compaction_result",
            "the exact-size assistant reply left post-compaction history without a pre-event message_end, a compaction end result, and a recovered prompt/state",
        );
    }
    require(
        &mut failures,
        recovered_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
            && recovered_state.get("isCompacting").and_then(Value::as_bool) == Some(false),
        "auto_compaction_recovery",
        format!("session did not recover after compaction abort: {recovered_state}"),
    );
    require(
        &mut failures,
        bash_cancelled,
        "background_bash_cancelled",
        format!(
            "background bash response was not cancelled: {}",
            bash_response.value()
        ),
    );
    require(
        &mut failures,
        !orphan_exists,
        "background_bash_no_orphan",
        format!(
            "cancelled background child wrote orphan marker at {}",
            bash_orphan_path.display()
        ),
    );
    require_order(
        &mut failures,
        abort_bash_response_index,
        bash_response_index,
        "background_bash_response_order",
        "abort_bash response",
        "cancelled bash response",
    );
    require(
        &mut failures,
        bash_recovery_response
            .value()
            .pointer("/data/cancelled")
            .and_then(Value::as_bool)
            == Some(false)
            && bash_recovery_response
                .value()
                .pointer("/data/exitCode")
                .and_then(Value::as_i64)
                == Some(0)
            && bash_recovery_response
                .value()
                .pointer("/data/output")
                .and_then(Value::as_str)
                .is_some_and(|output| output.contains("odin-bash-recovered")),
        "background_bash_recovery",
        format!(
            "post-abort bash command did not succeed: {}",
            bash_recovery_response.value()
        ),
    );
    require(
        &mut failures,
        cancelled_bash_message
            .and_then(|message| message.get("cancelled"))
            .and_then(Value::as_bool)
            == Some(true),
        "background_bash_cancelled_persisted",
        "cancelled bash result was not persisted on the owning session",
    );
    require(
        &mut failures,
        recovered_bash_message
            .and_then(|message| message.get("output"))
            .and_then(Value::as_str)
            .is_some_and(|output| output.contains("odin-bash-recovered")),
        "background_bash_recovery_persisted",
        "recovery bash result was not persisted on the owning session",
    );
    let baseline_session = baseline_state.get("sessionId").and_then(Value::as_str);
    require(
        &mut failures,
        baseline_session.is_some_and(|session| !session.is_empty())
            && post_abort_state.get("sessionId").and_then(Value::as_str) == baseline_session
            && recovered_state.get("sessionId").and_then(Value::as_str) == baseline_session
            && final_state.get("sessionId").and_then(Value::as_str) == baseline_session
            && final_state.get("isStreaming").and_then(Value::as_bool) == Some(false)
            && final_state.get("isCompacting").and_then(Value::as_bool) == Some(false),
        "compaction_bash_final_state",
        format!("compaction/bash recovery did not remain idle on one OMP session: {baseline_state} / {final_state}"),
    );

    run.record_json(
        "effect",
        "compaction-bash-abort-recovery",
        &json!({
            "enable_request_id": enable_id,
            "seed_request_ids": seed_request_ids,
            "trigger_prompt_request_id": prompt_id,
            "compaction_abort_request_id": abort_id,
            "compaction_abort_elapsed_ms": u64::try_from(abort_elapsed.as_millis()).unwrap_or(u64::MAX),
            "compaction_start": compaction_start.value(),
            "compacting_state": compacting_state,
            "compaction_end": compaction_end.value(),
            "compaction_end_settled": compaction_end_settled,
            "compaction_summary_retained": compaction_summary_retained,
            "compaction_summary_text": compaction_summary,
            "compaction_summary_digest": compaction_summary
                .map(|summary| blake3::hash(summary.as_bytes()).to_hex().to_string()),
            "big_reply_evidence_branch": big_reply_branch,
            "big_reply_message_end": big_reply_end.value(),
            "big_prompt_evidence_branch": big_prompt_branch,
            "big_prompt_message_end": big_prompt_end.value(),
            "post_abort_state": post_abort_state,
            "recovery_prompt_request_id": recovery_id,
            "recovered_state": recovered_state,
            "bash_request_id": bash_id,
            "abort_bash_request_id": abort_bash_id,
            "bash_response": bash_response.value(),
            "orphan_observation_ms": (BASH_ORPHAN_DELAY + BASH_ORPHAN_GRACE).as_millis(),
            "orphan_marker_exists": orphan_exists,
            "bash_recovery_request_id": bash_recovery_id,
            "bash_recovery_response": bash_recovery_response.value(),
            "final_state": final_state,
        }),
    )?;
    Ok(failures)
}

fn setup_failure(
    name: &'static str,
    check: &'static str,
    error: impl std::fmt::Display,
) -> CaseOutcome {
    let detail = format!("could not prepare {name}: {error}");
    let mut outcome = CaseOutcome::fail(
        "case fixture setup failed",
        vec![failure(check, detail.clone())],
    );
    outcome.evidence.push(CaseEvidence {
        kind: "setup_error",
        label: format!("{name}-setup-error"),
        bytes: detail.into_bytes(),
    });
    outcome
}

/// The exact deterministic `odin-mock:big` assistant reply: a typed
/// `message_end` whose assistant text is exactly [`COMPACTION_REPLY_BYTES`]
/// bytes long.
fn is_big_assistant_reply_end(frame: &DecodedRpcFrame) -> bool {
    event_message(frame, "message_end").is_some_and(|message| {
        message.get("role").and_then(Value::as_str) == Some("assistant")
            && message_text(message).is_some_and(|text| text.len() == COMPACTION_REPLY_BYTES)
    })
}

/// The exact threshold-triggering user directive: a typed `message_end`
/// whose user text is exactly `prompt`.
fn is_big_prompt_end(frame: &DecodedRpcFrame, prompt: &str) -> bool {
    event_message(frame, "message_end").is_some_and(|message| {
        message.get("role").and_then(Value::as_str) == Some("user")
            && message_text(message) == Some(prompt)
    })
}

/// A typed `auto_compaction_end` settles the compaction window when the abort
/// landed (`aborted`), compaction was skipped for a benign reason (`skipped`),
/// or it completed with a typed compaction result (`result`).
fn compaction_end_is_settled(frame: &DecodedRpcFrame) -> bool {
    if !frame_type(frame, "auto_compaction_end") {
        return false;
    }
    let value = frame.value();
    value.get("aborted").and_then(Value::as_bool) == Some(true)
        || value.get("skipped").and_then(Value::as_bool) == Some(true)
        || value.get("result").is_some_and(|result| !result.is_null())
}

fn message_set_contains_compaction_input(messages: &Value, prompt: &str) -> (bool, bool) {
    let Some(messages) = messages.as_array() else {
        return (false, false);
    };
    let mut big_reply = false;
    let mut original_prompt = false;
    for message in messages {
        match message.get("role").and_then(Value::as_str) {
            Some("user") if message_text(message) == Some(prompt) => original_prompt = true,
            Some("assistant") => {
                big_reply |=
                    message_text(message).is_some_and(|text| text.len() == COMPACTION_REPLY_BYTES);
            }
            _ => {}
        }
    }
    (big_reply, original_prompt)
}

fn reserve_marker_dir(work_dir: &Path) -> Result<PathBuf, CaseFailure> {
    for sequence in 0..32u8 {
        let path = work_dir.join(format!("bash-abort-{sequence:02}"));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(failure(
                    "background_bash_marker",
                    format!(
                        "could not reserve marker directory {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
    }
    Err(failure(
        "background_bash_marker",
        "all 32 retained marker directories already exist",
    ))
}

async fn wait_for_file(path: &Path, bound: Duration) -> Result<Instant, CaseFailure> {
    let deadline = Instant::now() + bound;
    loop {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => return Ok(Instant::now()),
            Ok(_) => {
                return Err(failure(
                    "background_bash_started",
                    format!("bash start marker is not a file: {}", path.display()),
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(failure(
                    "background_bash_started",
                    format!(
                        "could not inspect bash start marker {}: {error}",
                        path.display()
                    ),
                ));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure(
                "background_bash_started",
                format!(
                    "bash child did not create {} within {} ms",
                    path.display(),
                    bound.as_millis()
                ),
            ));
        }
        time::sleep(FILE_POLL_INTERVAL.min(remaining)).await;
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}
