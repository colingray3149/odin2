//! Case 19 owner: RPC configuration against isolated user/project/extra
//! config, including defaults, resets, and ignored keys.

use super::shared::*;
use super::*;

pub(super) struct RpcConfigurationCase;

#[async_trait::async_trait]
impl ConformanceCase for RpcConfigurationCase {
    fn id(&self) -> ConformanceCaseId {
        RPC_CONFIGURATION
    }

    fn name(&self) -> &'static str {
        "rpc_configuration"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        run_rpc_configuration(context).await
    }
}

async fn run_rpc_configuration(context: &CaseContext) -> CaseOutcome {
    const USER_CONFIG: &str = "steeringMode: one-at-a-time\nfollowUpMode: all\ninterruptMode: wait\ncompaction:\n  enabled: false\n";
    const PROJECT_CONFIG: &str =
        "steeringMode: all\nfollowUpMode: one-at-a-time\ncompaction: ignored-shadow\nodinProbeUnknown: must-not-surface\n";
    const EXTRA_CONFIG: &str = "steeringMode: one-at-a-time\n";

    let root = context.work_dir().join("configuration");
    let default_cwd = root.join("default-project");
    let default_isolation = root.join("default-isolation");
    let layered_cwd = root.join("layered-project");
    let layered_isolation = root.join("layered-isolation");
    let user_config = layered_isolation.join("agent").join("config.yml");
    let project_config = layered_cwd.join(".omp").join("config.yml");
    let extra_config = root.join("extra.yml");
    for (path, contents) in [
        (&user_config, USER_CONFIG),
        (&project_config, PROJECT_CONFIG),
        (&extra_config, EXTRA_CONFIG),
    ] {
        if let Err(error) = write_fixture(path, contents) {
            return setup_failure("RPC configuration", "fixture_setup", error);
        }
    }

    let default_spec = match isolated_process_spec(
        context,
        &default_cwd,
        &default_isolation,
        vec![NO_SESSION_ARG.to_owned()],
    ) {
        Ok(spec) => spec,
        Err(error) => return setup_failure("RPC configuration", "fixture_setup", error),
    };
    let layered_spec = match isolated_process_spec(
        context,
        &layered_cwd,
        &layered_isolation,
        vec![
            NO_SESSION_ARG.to_owned(),
            "--config".to_owned(),
            extra_config.to_string_lossy().into_owned(),
        ],
    ) {
        Ok(spec) => spec,
        Err(error) => return setup_failure("RPC configuration", "fixture_setup", error),
    };

    let mut failures = Vec::new();
    let mut evidence = Vec::new();
    let mut cleanup = CleanupReceipt::default();
    let mut expected_cleanup = 0;
    let mut default_snapshot = None;
    let mut layered_snapshot = None;
    let mut reset_snapshot = None;

    match {
        let worker = context.worker_for(&default_spec);
        RawRpcDriver::spawn(default_spec, worker)
    }
    .await
    {
        Ok(mut driver) => {
            expected_cleanup += 1;
            let exercise: Result<(), CaseFailure> = async {
                let state = request_state(&mut driver, "configuration_defaults").await?;
                expect_str(
                    &state,
                    "steeringMode",
                    "one-at-a-time",
                    "configuration_defaults",
                )?;
                expect_str(
                    &state,
                    "followUpMode",
                    "one-at-a-time",
                    "configuration_defaults",
                )?;
                expect_str(
                    &state,
                    "interruptMode",
                    "immediate",
                    "configuration_defaults",
                )?;
                expect_bool(
                    &state,
                    "autoCompactionEnabled",
                    true,
                    "configuration_defaults",
                )?;
                expect_bool(&state, "fastModeEnabled", false, "configuration_defaults")?;
                default_snapshot = Some(configuration_state(&state));
                Ok(())
            }
            .await;
            if let Err(error) = exercise {
                failures.push(error);
            }
            cleanup_driver(
                &mut driver,
                "configuration-defaults child",
                true,
                &mut failures,
                &mut evidence,
                &mut cleanup,
            )
            .await;
            push_transcript(&driver, "configuration-defaults", &mut evidence);
        }
        Err(error) => {
            failures.push(failure("configuration_defaults_start", &error));
            evidence.push(text_evidence(
                "case_error",
                "configuration-defaults-start",
                error.to_string(),
            ));
        }
    }

    match {
        let worker = context.worker_for(&layered_spec);
        RawRpcDriver::spawn(layered_spec, worker)
    }
    .await
    {
        Ok(mut driver) => {
            expected_cleanup += 1;
            let exercise: Result<(), CaseFailure> = async {
                let initial = request_state(&mut driver, "configuration_precedence").await?;
                expect_str(
                    &initial,
                    "steeringMode",
                    "one-at-a-time",
                    "extra_config_precedence",
                )?;
                expect_str(
                    &initial,
                    "followUpMode",
                    "one-at-a-time",
                    "project_config_precedence",
                )?;
                expect_str(&initial, "interruptMode", "wait", "user_config_precedence")?;
                expect_bool(
                    &initial,
                    "autoCompactionEnabled",
                    false,
                    "ignored_project_group",
                )?;
                require(
                    initial.get("odinProbeUnknown").is_none(),
                    "ignored_unknown_key",
                    "an unknown project key leaked into RPC state",
                )?;
                layered_snapshot = Some(configuration_state(&initial));

                send_success(
                    &mut driver,
                    "set_steering_mode",
                    json!({ "mode": "all" }),
                    "configuration_runtime_mutation",
                )
                .await?;
                send_success(
                    &mut driver,
                    "set_follow_up_mode",
                    json!({ "mode": "all" }),
                    "configuration_runtime_mutation",
                )
                .await?;
                let modified = request_state(&mut driver, "configuration_runtime_mutation").await?;
                expect_str(
                    &modified,
                    "steeringMode",
                    "all",
                    "configuration_runtime_mutation",
                )?;
                expect_str(
                    &modified,
                    "followUpMode",
                    "all",
                    "configuration_runtime_mutation",
                )?;
                expect_str(
                    &modified,
                    "interruptMode",
                    "wait",
                    "configuration_runtime_mutation",
                )?;
                expect_bool(
                    &modified,
                    "autoCompactionEnabled",
                    false,
                    "configuration_runtime_mutation",
                )?;

                for (command, fields) in [
                    ("set_steering_mode", json!({ "mode": "one-at-a-time" })),
                    ("set_follow_up_mode", json!({ "mode": "one-at-a-time" })),
                    ("set_interrupt_mode", json!({ "mode": "immediate" })),
                    ("set_auto_compaction", json!({ "enabled": true })),
                ] {
                    send_success(&mut driver, command, fields, "configuration_default_reset")
                        .await?;
                }

                let config_start = driver.transcript().len();
                for model in ["mock-b", "mock-a"] {
                    let selector = format!("odin-mock/{model}");
                    let id = driver
                        .send("prompt", json!({ "message": format!("/model {selector}") }))
                        .await
                        .map_err(|error| failure("configuration_model_reset", error))?;
                    let response = driver
                        .wait_for_response(&id, "prompt", rpc_deadline())
                        .await
                        .map_err(|error| failure("configuration_model_reset", error))?;
                    expect_success(&response, "configuration_model_reset")?;
                    require(
                        response
                            .value()
                            .pointer("/data/agentInvoked")
                            .and_then(Value::as_bool)
                            == Some(false),
                        "configuration_model_reset",
                        format!("/model odin-mock/{model} did not complete locally"),
                    )?;
                }
                let config_frames = frame_values(&driver.transcript()[config_start..]);
                for model in ["mock-b", "mock-a"] {
                    let selector = format!("odin-mock/{model}");
                    require(
                        config_frames.iter().any(|value| {
                            value.get("type").and_then(Value::as_str) == Some("config_update")
                                && value.pointer("/model/provider").and_then(Value::as_str)
                                    == Some("odin-mock")
                                && value.pointer("/model/id").and_then(Value::as_str) == Some(model)
                        }),
                        "configuration_update_event",
                        format!("the {model} selection did not emit config_update"),
                    )?;
                    require(
                        config_frames.iter().any(|value| {
                            value.get("type").and_then(Value::as_str) == Some("command_output")
                                && value
                                    .get("text")
                                    .and_then(Value::as_str)
                                    .is_some_and(|text| text.contains(&selector))
                        }),
                        "configuration_update_output",
                        format!("the {model} selection did not emit visible command_output"),
                    )?;
                }

                let reset = request_state(&mut driver, "configuration_reset_state").await?;
                expect_str(
                    &reset,
                    "steeringMode",
                    "one-at-a-time",
                    "configuration_default_reset",
                )?;
                expect_str(
                    &reset,
                    "followUpMode",
                    "one-at-a-time",
                    "configuration_default_reset",
                )?;
                expect_str(
                    &reset,
                    "interruptMode",
                    "immediate",
                    "configuration_default_reset",
                )?;
                expect_bool(
                    &reset,
                    "autoCompactionEnabled",
                    true,
                    "configuration_default_reset",
                )?;
                expect_str(
                    reset.get("model").unwrap_or(&Value::Null),
                    "id",
                    "mock-a",
                    "configuration_model_reset",
                )?;
                reset_snapshot = Some(configuration_state(&reset));
                Ok(())
            }
            .await;
            if let Err(error) = exercise {
                failures.push(error);
            }
            cleanup_driver(
                &mut driver,
                "configuration-layered child",
                true,
                &mut failures,
                &mut evidence,
                &mut cleanup,
            )
            .await;
            push_transcript(&driver, "configuration-layered", &mut evidence);
        }
        Err(error) => {
            failures.push(failure("configuration_layered_start", &error));
            evidence.push(text_evidence(
                "case_error",
                "configuration-layered-start",
                error.to_string(),
            ));
        }
    }

    evidence.push(json_evidence(
        "configuration",
        "isolated-layer-precedence",
        &json!({
            "fixtures": {
                "user": USER_CONFIG,
                "project": PROJECT_CONFIG,
                "extra": EXTRA_CONFIG,
            },
            "states": {
                "defaults": default_snapshot,
                "layered": layered_snapshot,
                "reset": reset_snapshot,
            },
        }),
    ));
    finish_case(
        "isolated RPC configuration defaults, precedence, reset, and ignored keys conformed",
        "RPC configuration conformance failed",
        failures,
        evidence,
        cleanup,
        expected_cleanup,
    )
}
