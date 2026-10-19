//! Case 20 owner: bounded stdin-EOF drain, request cancellation, session
//! disposal, and exit status.

use super::shared::*;
use super::*;

pub(super) struct StdinCloseShutdownCase;

#[async_trait::async_trait]
impl ConformanceCase for StdinCloseShutdownCase {
    fn id(&self) -> ConformanceCaseId {
        STDIN_CLOSE_SHUTDOWN
    }

    fn name(&self) -> &'static str {
        "stdin_close_shutdown"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_stdin_close_shutdown(context).await
    }
}

async fn run_stdin_close_shutdown(context: &CaseContext) -> CaseOutcome {
    const SHUTDOWN_EXTENSION: &str = r#"export default function shutdownProbe(pi: any): void {
	pi.on("session_shutdown", (_event: unknown, ctx: any) => {
		ctx.ui.notify("odin-probe-session-disposed", "info");
	});
}
"#;
    let extension_path = context.work_dir().join("shutdown-probe.ts");
    if let Err(error) = write_fixture(&extension_path, SHUTDOWN_EXTENSION) {
        return setup_failure("stdin close shutdown", "fixture_setup", error);
    }
    let spec = match isolated_process_spec(
        context,
        context.work_dir(),
        &context.work_dir().join("shutdown-isolation"),
        vec![
            "--extension".to_owned(),
            extension_path.to_string_lossy().into_owned(),
            NO_SESSION_ARG.to_owned(),
        ],
    ) {
        Ok(spec) => spec,
        Err(error) => return setup_failure("stdin close shutdown", "fixture_setup", error),
    };
    let close_bound = spec.drain_timeout.saturating_add(Duration::from_secs(1));
    let mut driver = match {
        let worker = context.worker_for(&spec);
        RawRpcDriver::spawn(spec, worker)
    }
    .await
    {
        Ok(driver) => driver,
        Err(error) => return setup_failure("stdin close shutdown", "child_start", error),
    };

    let mut failures = Vec::new();
    let mut evidence = vec![text_evidence(
        "fixture",
        "shutdown-extension",
        SHUTDOWN_EXTENSION,
    )];
    let mut cleanup = CleanupReceipt::default();
    let exercise: Result<(), CaseFailure> = async {
        let tools_id = driver
            .send(
                "set_host_tools",
                json!({
                    "tools": [{
                        "name": "odin_lane_status",
                        "description": "Odin shutdown conformance host tool",
                        "parameters": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": false
                        }
                    }]
                }),
            )
            .await
            .map_err(|error| failure("shutdown_host_tool_register", error))?;
        let tools_response = driver
            .wait_for_response(&tools_id, "set_host_tools", rpc_deadline())
            .await
            .map_err(|error| failure("shutdown_host_tool_register", error))?;
        expect_success(&tools_response, "shutdown_host_tool_register")?;

        let prompt_id = driver
            .send("prompt", json!({ "message": "odin-mock:host-tool" }))
            .await
            .map_err(|error| failure("shutdown_host_prompt", error))?;
        let prompt_response = driver
            .wait_for_response(&prompt_id, "prompt", rpc_deadline())
            .await
            .map_err(|error| failure("shutdown_host_prompt", error))?;
        expect_success(&prompt_response, "shutdown_host_prompt")?;
        driver
            .collect_until(rpc_deadline(), |frame| {
                frame.value().get("type").and_then(Value::as_str) == Some("host_tool_call")
                    && frame.value().get("toolName").and_then(Value::as_str) == Some("odin_lane_status")
            })
            .await
            .map_err(|error| failure("shutdown_host_pending", error))?;

        let bash_id = driver
            .send(
                "bash",
                json!({
                    "command": "sleep 0.5 & child=$!; printf 'odin-background-child:%s' \"$child\"; wait \"$child\"; printf :drained"
                }),
            )
            .await
            .map_err(|error| failure("shutdown_background_send", error))?;
        let state_id = driver
            .send("get_state", json!({}))
            .await
            .map_err(|error| failure("shutdown_serial_state_send", error))?;
        let messages_id = driver
            .send("get_messages", json!({}))
            .await
            .map_err(|error| failure("shutdown_serial_messages_send", error))?;

        let close_started = Instant::now();
        let shutdown = driver
            .close()
            .await
            .map_err(|error| failure("shutdown_drain", error))?;
        require(
            close_started.elapsed() <= close_bound,
            "shutdown_bound",
            "stdin EOF exceeded the configured graceful-drain bound",
        )?;
        require(
            shutdown.exit().success() && shutdown.exit().code() == Some(0),
            "shutdown_exit_status",
            format!("expected exit code 0, observed {}", shutdown.exit()),
        )?;
        require(
            matches!(driver.process().state(), OmpLifecycleState::Exited),
            "shutdown_reaped",
            "the OMP child did not reach the exited lifecycle state",
        )?;

        let frames = frame_values(shutdown.frames());
        let bash_response = find_response(&frames, &bash_id, "bash")
            .ok_or_else(|| failure("shutdown_background_drain", "the background bash response was not drained"))?;
        let bash_output = bash_response.pointer("/data/output").and_then(Value::as_str);
        require(
            bash_response.get("success").and_then(Value::as_bool) == Some(true)
                && bash_response.pointer("/data/exitCode").and_then(Value::as_i64) == Some(0)
                && bash_response.pointer("/data/cancelled").and_then(Value::as_bool) == Some(false)
                && bash_output.is_some_and(|output| {
                    output.contains("odin-background-child:") && output.contains(":drained")
                }),
            "shutdown_background_drain",
            "the background bash and its child did not complete and drain before exit",
        )?;
        require(
            bash_output.is_some_and(|output| output.contains(":drained")),
            "shutdown_no_orphan",
            "the background child was not reaped before the bash response and OMP exit",
        )?;
        for (id, command, check) in [
            (&state_id, "get_state", "shutdown_serial_state_drain"),
            (&messages_id, "get_messages", "shutdown_serial_messages_drain"),
        ] {
            let response = find_response(&frames, id, command)
                .ok_or_else(|| failure(check, format!("missing drained {command} response")))?;
            require(
                response.get("success").and_then(Value::as_bool) == Some(true),
                check,
                format!("{command} completed with a failure response"),
            )?;
        }
        require(
            frames.iter().any(|value| {
                value.get("type").and_then(Value::as_str) == Some("tool_execution_end")
                    && value.get("toolName").and_then(Value::as_str) == Some("odin_lane_status")
                    && value.get("isError").and_then(Value::as_bool) == Some(true)
            }),
            "shutdown_host_cancellation",
            "stdin EOF did not cancel the pending host-tool execution with an error result",
        )?;
        require(
            frames
                .iter()
                .filter(|value| {
                    value.get("type").and_then(Value::as_str) == Some("extension_ui_request")
                        && value.get("method").and_then(Value::as_str) == Some("notify")
                        && value.get("message").and_then(Value::as_str)
                            == Some("odin-probe-session-disposed")
                })
                .count()
                == 1,
            "shutdown_session_disposal",
            "session_shutdown disposal did not run exactly once before process exit",
        )?;
        Ok(())
    }
    .await;
    if let Err(error) = exercise {
        failures.push(error);
    }

    cleanup_driver(
        &mut driver,
        "stdin-close child",
        true,
        &mut failures,
        &mut evidence,
        &mut cleanup,
    )
    .await;
    push_transcript(&driver, "stdin-close-shutdown", &mut evidence);
    finish_case(
        "stdin EOF cancelled host work, drained serial/background work, disposed, and exited cleanly",
        "stdin-close shutdown conformance failed",
        failures,
        evidence,
        cleanup,
        1,
    )
}
