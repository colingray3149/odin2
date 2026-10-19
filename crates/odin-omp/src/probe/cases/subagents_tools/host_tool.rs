//! Case 13 owner: host-tool and scoped-URI round trip, including lane
//! binding, cross-scope rejection, and the raw host cancel path.

use super::bridge::{
    exercise_bridge, journal_snapshot, side_channel_bytes, validate_bridge_side_channels,
    validate_journal,
};
use super::shared::*;
use super::*;

pub(super) struct HostToolAndUriCase;

#[async_trait]
impl ConformanceCase for HostToolAndUriCase {
    fn id(&self) -> ConformanceCaseId {
        HOST_TOOL_AND_URI
    }

    fn name(&self) -> &'static str {
        "host_tool_and_uri"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_host_tool_and_uri(context).await
    }
}

async fn run_host_tool_and_uri(context: &CaseContext) -> CaseOutcome {
    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    let mut cleanup = CleanupReceipt::default();

    if let Err(error) = seed_bound_lane(context) {
        failures.push(failure("fixture_seed", error));
        return finish_outcome(
            "bridge host tool, scoped URI, correlation, and cancellation passed",
            "bridge host tool, scoped URI, correlation, or cancellation failed",
            failures,
            evidence,
            cleanup,
        );
    }
    let config = match context.bridge_config(context.session_descriptor()) {
        Ok(config) => config,
        Err(error) => {
            failures.push(failure("bridge_config", error));
            return finish_outcome(
                "bridge host tool, scoped URI, correlation, and cancellation passed",
                "bridge host tool, scoped URI, correlation, or cancellation failed",
                failures,
                evidence,
                cleanup,
            );
        }
    };
    let uri_router = config.uri_router.clone();

    match prove_cross_scope_rejection(context, &config) {
        Ok(bytes) => evidence.push(CaseEvidence {
            kind: "scope_rejection",
            label: "foreign-lane-pre-storage.txt".to_owned(),
            bytes,
        }),
        Err(error) => failures.push(failure("cross_scope_rejection", error)),
    }
    let admitted_definitions = match config
        .operations
        .admitted_definitions(&config.admitted_host_tools, true)
    {
        Ok(definitions) => definitions,
        Err(error) => {
            failures.push(failure("tool_definitions", error.to_string()));
            Vec::new()
        }
    };
    let tool_definitions = match serde_json::to_value(&admitted_definitions) {
        Ok(definitions) => definitions,
        Err(error) => {
            failures.push(failure("tool_definitions", error));
            Value::Array(Vec::new())
        }
    };

    let bridge = match OmpBridge::start(config).await {
        Ok(bridge) => bridge,
        Err(error) => {
            failures.push(failure("bridge_start", error));
            run_raw_host_cancel(
                context,
                &tool_definitions,
                &mut failures,
                &mut evidence,
                &mut cleanup,
            )
            .await;
            return finish_outcome(
                "bridge host tool, scoped URI, correlation, and cancellation passed",
                "bridge host tool, scoped URI, correlation, or cancellation failed",
                failures,
                evidence,
                cleanup,
            );
        }
    };
    let mut receiver = bridge.subscribe();
    let command_ids = match exercise_bridge(context, &bridge, &mut receiver).await {
        Ok(command_ids) => Some(command_ids),
        Err(error) => {
            failures.push(failure("bridge_round_trip", error));
            None
        }
    };
    let mut observations = Vec::new();
    let dropped_observations = 0_u64;
    while let Ok(frame) = receiver.try_recv() {
        observations.push(frame);
    }
    let (side_channels, dropped_side_channels) = match bridge.side_channel_evidence() {
        Ok((side_channels, dropped_side_channels)) => (side_channels, dropped_side_channels),
        Err(error) => {
            failures.push(failure("side_channel_evidence", error));
            (Vec::new(), 0)
        }
    };
    let correlation = match validate_bridge_side_channels(
        context,
        &uri_router,
        &observations,
        dropped_observations,
        &side_channels,
        dropped_side_channels,
    ) {
        Ok(correlation) => Some(correlation),
        Err(error) => {
            failures.push(failure("side_channel_correlation", error));
            None
        }
    };
    match side_channel_bytes(&side_channels, dropped_side_channels) {
        Ok(bytes) => evidence.push(CaseEvidence {
            kind: "side_channel",
            label: "bridge-side-channel.json".to_owned(),
            bytes,
        }),
        Err(error) => failures.push(failure("side_channel_evidence", error)),
    }

    match bridge.stop().await {
        Ok(report) => {
            observations.extend(report.drained.iter().cloned());
            let child_outcome = match &report.exit {
                Some(exit) if exit.success() => CleanupOutcome::Clean,
                Some(exit) => CleanupOutcome::Failed {
                    reason: format!("bridge child did not exit successfully: {exit}"),
                },
                None => CleanupOutcome::Failed {
                    reason: "bridge produced no child exit evidence".to_owned(),
                },
            };
            cleanup.push("child_stop", "case-13 bridge child", child_outcome);
            cleanup.push(
                "lease_release",
                context.ids().session.to_string(),
                if report.lease_released {
                    CleanupOutcome::Clean
                } else {
                    CleanupOutcome::Failed {
                        reason: "bridge did not durably release its session lease".to_owned(),
                    }
                },
            );
            if !report.incomplete.is_empty() {
                failures.push(failure(
                    "journal_residue",
                    format!(
                        "bridge stop left incomplete commands: {}",
                        report
                            .incomplete
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        }
        Err(error) => {
            cleanup.push(
                "bridge_stop",
                "case-13 bridge child and lease",
                CleanupOutcome::Failed {
                    reason: error.to_string(),
                },
            );
            failures.push(failure("bridge_stop", error));
        }
    }
    push_observed_evidence(
        &mut failures,
        &mut evidence,
        "bridge-observations.jsonl",
        &observations,
    );

    match journal_snapshot(context) {
        Ok((journal, bytes)) => {
            if let (Some(commands), Some(correlation)) = (&command_ids, &correlation) {
                if let Err(error) = validate_journal(&journal, commands, correlation) {
                    failures.push(failure("journal_correlation", error));
                }
            } else {
                failures.push(failure(
                    "journal_correlation",
                    "round-trip correlation data was unavailable",
                ));
            }
            evidence.push(CaseEvidence {
                kind: "journal",
                label: "bridge-live-events.json".to_owned(),
                bytes,
            });
        }
        Err(error) => failures.push(failure("journal_evidence", error)),
    }

    run_raw_host_cancel(
        context,
        &tool_definitions,
        &mut failures,
        &mut evidence,
        &mut cleanup,
    )
    .await;

    finish_outcome(
        "bridge host tool, scoped URI, correlation, and cancellation passed",
        "bridge host tool, scoped URI, correlation, or cancellation failed",
        failures,
        evidence,
        cleanup,
    )
}

/// Binds the context-seeded lane and run for the bridge round trip. The
/// [`CaseContext`] ledger already carries this case's canonical rows
/// (deterministic ids, `Desired`/`Pending` at revision 1), so creating them
/// again would violate `lanes.lane_id`; case 13 reads the seeded rows, proves
/// the canonical owner and scope columns, then advances and binds only what
/// the host-tool and scoped-URI assertions need: lane
/// Provisioning→Ready→Running, run Planning→Running, and the lane's
/// current-run/session references.
fn seed_bound_lane(context: &CaseContext) -> Result<(), String> {
    let now = OffsetDateTime::from_unix_timestamp(13_000).map_err(|error| error.to_string())?;
    let shared = context.ledger();
    let ledger = shared
        .lock()
        .map_err(|_| "case ledger mutex was poisoned".to_owned())?;
    let ids = context.ids();
    let lane = lane_run::read_lane(ledger.connection(), &ids.lane)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "context did not seed the bound lane".to_owned())?;
    if lane.seat_id != ids.seat
        || lane.project_id.as_ref() != Some(&ids.project)
        || lane.backend != "local_omp"
        || lane.created_by != ids.owner
        || !lane.retained
    {
        return Err(format!(
            "seeded lane {} is not the canonical context row: {lane:?}",
            ids.lane
        ));
    }
    if lane.status != LaneStatus::Desired || lane.revision != 1 {
        return Err(format!(
            "seeded lane {} is not a fresh context row (status {:?}, revision {})",
            ids.lane, lane.status, lane.revision
        ));
    }
    let run = lane_run::read_run(ledger.connection(), &ids.run)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "context did not seed the bound run".to_owned())?;
    if run.lane_id != ids.lane || run.attempt_number != 1 {
        return Err(format!(
            "seeded run {} is not bound to lane {}: {run:?}",
            ids.run, ids.lane
        ));
    }
    if run.status != RunStatus::Pending || run.revision != 1 {
        return Err(format!(
            "seeded run {} is not a fresh context row (status {:?}, revision {})",
            ids.run, run.status, run.revision
        ));
    }
    revision::transition_lane_at(
        ledger.connection(),
        &ids.lane,
        LaneStatus::Provisioning,
        1,
        now,
    )
    .map_err(|error| error.to_string())?;
    revision::transition_lane_at(ledger.connection(), &ids.lane, LaneStatus::Ready, 2, now)
        .map_err(|error| error.to_string())?;
    lane_run::transition_run(ledger.connection(), &ids.run, RunStatus::Planning, 1, now)
        .map_err(|error| error.to_string())?;
    lane_run::transition_run(ledger.connection(), &ids.run, RunStatus::Running, 2, now)
        .map_err(|error| error.to_string())?;
    let run_id = ids.run.to_string();
    let session = ids.session.to_string();
    let lane_id = ids.lane.to_string();
    let updated = ledger
        .connection()
        .execute(
            "UPDATE lanes SET current_run_id=?1, session_ref=?2 WHERE lane_id=?3",
            [run_id.as_str(), session.as_str(), lane_id.as_str()],
        )
        .map_err(|error| error.to_string())?;
    if updated != 1 {
        return Err(format!("bound lane update touched {updated} rows"));
    }
    revision::transition_lane_at(ledger.connection(), &ids.lane, LaneStatus::Running, 3, now)
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn prove_cross_scope_rejection(
    context: &CaseContext,
    config: &OmpBridgeConfig,
) -> Result<Vec<u8>, String> {
    let before = read_bound_lane(context)?;
    let foreign =
        LaneId::from_parts("lane", 13, "odin-probe-foreign").map_err(|error| error.to_string())?;
    // Reject foreign lanes during read-only preflight, before journal writes or disclosure.
    let execution = crate::uri::ExecutionBinding::from_binding(&config.binding);
    let rejected = config.operations.dispatch_tool(
        SessionOperationContext {
            binding: &config.operation_binding,
            session: &config.binding.session_id,
            scope: &context.scope(),
            execution: Some(&execution),
        },
        LaneStatusTool::NAME,
        None,
        json!({ "laneId": foreign }),
        "probe-cross-scope-rejection",
    );
    let error = match rejected {
        Err(error) => error,
        Ok(value) => {
            return Err(format!(
                "foreign lane was disclosed instead of rejected: {value}"
            ))
        }
    };
    if !matches!(
        &error,
        HostToolOperationError::Arguments { detail }
            if detail.contains("outside the bound lane scope")
    ) {
        return Err(format!(
            "foreign lane reached the wrong rejection boundary: {error}"
        ));
    }
    let after = read_bound_lane(context)?;
    if before != after {
        return Err("foreign-lane rejection changed durable lane storage".to_owned());
    }
    Ok(error.to_string().into_bytes())
}

fn read_bound_lane(context: &CaseContext) -> Result<lane_run::LaneRecord, String> {
    let shared = context.ledger();
    let ledger = shared
        .lock()
        .map_err(|_| "case ledger mutex was poisoned".to_owned())?;
    lane_run::read_lane(ledger.connection(), &context.ids().lane)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "bound lane disappeared from the fixture ledger".to_owned())
}

async fn run_raw_host_cancel(
    context: &CaseContext,
    tool_definitions: &Value,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
    cleanup: &mut CleanupReceipt,
) {
    let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
    let mut driver = match {
        let worker = context.worker_for(&spec);
        RawRpcDriver::spawn(spec, worker)
    }
    .await
    {
        Ok(driver) => driver,
        Err(error) => {
            failures.push(failure("cancel_child_start", error));
            return;
        }
    };
    if let Err(error) = exercise_raw_host_cancel(context, tool_definitions, &mut driver).await {
        failures.push(failure("host_cancel", error));
    }
    match driver
        .cleanup(cleanup, "case-13 host-cancel pinned OMP child")
        .await
    {
        Ok(exit) if !exit.success() => failures.push(failure("cancel_process_exit", exit)),
        Ok(_) => {}
        Err(error) => failures.push(failure("cancel_cleanup", error)),
    }
    push_raw_transcript(
        failures,
        evidence,
        "host-cancel-rpc.jsonl",
        driver.transcript(),
    );
}

async fn exercise_raw_host_cancel(
    context: &CaseContext,
    tool_definitions: &Value,
    driver: &mut RawRpcDriver,
) -> Result<(), String> {
    let registration_id = driver
        .send(
            "set_host_tools",
            json!({ "tools": tool_definitions.clone() }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let registration = driver
        .wait_for_response(&registration_id, "set_host_tools", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    let names = response_data(&registration, "set_host_tools")?
        .get("toolNames")
        .and_then(Value::as_array)
        .ok_or_else(|| "host-tool registration omitted toolNames".to_owned())?;
    if !names
        .iter()
        .any(|name| name.as_str() == Some(LaneStatusTool::NAME))
    {
        return Err("raw cancellation child did not register odin_lane_status".to_owned());
    }

    let prompt_id = driver
        .send(
            "prompt",
            json!({
                "message": format!("odin-mock:host-tool {}", context.ids().lane)
            }),
        )
        .await
        .map_err(|error| error.to_string())?;
    let prompt = driver
        .wait_for_response(&prompt_id, "prompt", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    ensure_directive_accepted(&prompt, "prompt")?;
    if !driver.transcript().iter().any(is_lane_status_call) {
        driver
            .collect_until(operation_deadline(), is_lane_status_call)
            .await
            .map_err(|error| error.to_string())?;
    }
    let request = driver
        .transcript()
        .iter()
        .find(|frame| is_lane_status_call(frame))
        .and_then(|frame| frame.value().get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| "host tool call omitted its request id".to_owned())?
        .to_owned();

    let abort_id = driver
        .send("abort", json!({}))
        .await
        .map_err(|error| error.to_string())?;
    let abort = driver
        .wait_for_response(&abort_id, "abort", operation_deadline())
        .await
        .map_err(|error| error.to_string())?;
    ensure_response_success(&abort, "abort")?;
    if !driver
        .transcript()
        .iter()
        .any(|frame| is_cancel_for(frame, &request))
    {
        let target = request.clone();
        driver
            .collect_until(operation_deadline(), move |frame| {
                is_cancel_for(frame, &target)
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    if !driver
        .transcript()
        .iter()
        .any(|frame| is_cancel_for(frame, &request))
    {
        return Err("host_tool_cancel did not target the pending request".to_owned());
    }
    Ok(())
}

fn is_lane_status_call(frame: &DecodedRpcFrame) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some("host_tool_call")
        && frame.value().get("toolName").and_then(Value::as_str) == Some(LaneStatusTool::NAME)
}

fn is_cancel_for(frame: &DecodedRpcFrame, request_id: &str) -> bool {
    frame.value().get("type").and_then(Value::as_str) == Some("host_tool_cancel")
        && frame.value().get("targetId").and_then(Value::as_str) == Some(request_id)
}
