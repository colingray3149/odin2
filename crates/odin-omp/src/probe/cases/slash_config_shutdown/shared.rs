//! The shared case harness: process isolation, RPC step helpers, assertion
//! and evidence plumbing, and bounded completion for cases 18-20.

use super::*;

pub(super) const CASE_DEADLINE: Duration = Duration::from_secs(120);
pub(super) const RPC_STEP_TIMEOUT: Duration = Duration::from_secs(20);
pub(super) const NO_SESSION_ARG: &str = "--no-session";

pub(super) fn isolated_process_spec(
    context: &CaseContext,
    cwd: &Path,
    isolation_root: &Path,
    extra_args: Vec<String>,
) -> Result<OmpProcessSpec, std::io::Error> {
    let home = isolation_root.join("home");
    let agent_dir = isolation_root.join("agent");
    let xdg = isolation_root.join("xdg");
    fs::create_dir_all(cwd)?;
    fs::create_dir_all(&home)?;
    fs::create_dir_all(&agent_dir)?;
    fs::create_dir_all(&xdg)?;

    let mut spec = context.process_spec(DEFAULT_MODEL_SELECTOR, extra_args);
    spec.cwd = cwd.to_path_buf();
    spec.explicit_env.retain(|(name, _)| {
        !matches!(
            name.as_str(),
            "HOME"
                | "XDG_CONFIG_HOME"
                | "XDG_DATA_HOME"
                | "XDG_STATE_HOME"
                | "XDG_CACHE_HOME"
                | "PI_CODING_AGENT_DIR"
                | "PI_CONFIG_DIR"
                | "PI_CONFIG_FILES"
                | "OMP_PROFILE"
                | "PI_PROFILE"
        )
    });
    for (name, value) in [
        ("HOME", home),
        ("XDG_CONFIG_HOME", xdg.join("config")),
        ("XDG_DATA_HOME", xdg.join("data")),
        ("XDG_STATE_HOME", xdg.join("state")),
        ("XDG_CACHE_HOME", xdg.join("cache")),
        ("PI_CODING_AGENT_DIR", agent_dir),
    ] {
        spec.explicit_env
            .push((name.to_owned(), value.to_string_lossy().into_owned()));
    }
    spec.explicit_env
        .push(("PI_CONFIG_DIR".to_owned(), ".omp".to_owned()));
    Ok(spec)
}

pub(super) fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

pub(super) async fn request_state(
    driver: &mut RawRpcDriver,
    check: &'static str,
) -> Result<Value, CaseFailure> {
    let id = driver
        .send("get_state", json!({}))
        .await
        .map_err(|error| failure(check, error))?;
    let response = driver
        .wait_for_response(&id, "get_state", rpc_deadline())
        .await
        .map_err(|error| failure(check, error))?;
    expect_success(&response, check)?;
    response
        .value()
        .get("data")
        .cloned()
        .ok_or_else(|| failure(check, "get_state response omitted data"))
}

pub(super) async fn send_success(
    driver: &mut RawRpcDriver,
    command: &str,
    fields: Value,
    check: &'static str,
) -> Result<(), CaseFailure> {
    let id = driver
        .send(command, fields)
        .await
        .map_err(|error| failure(check, error))?;
    let response = driver
        .wait_for_response(&id, command, rpc_deadline())
        .await
        .map_err(|error| failure(check, error))?;
    expect_success(&response, check)
}

pub(super) async fn cleanup_driver(
    driver: &mut RawRpcDriver,
    subject: &'static str,
    require_success: bool,
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
    cleanup: &mut CleanupReceipt,
) {
    match driver.cleanup(cleanup, subject).await {
        Ok(exit) => {
            if require_success && !exit.success() {
                failures.push(failure(
                    "cleanup_exit_status",
                    format!("{subject} did not exit successfully: {exit}"),
                ));
            }
            evidence.push(exit_evidence(subject, &exit));
        }
        Err(error) => {
            failures.push(failure("cleanup", format!("{subject}: {error}")));
            evidence.push(text_evidence(
                "case_error",
                format!("{subject}-cleanup"),
                error.to_string(),
            ));
        }
    }
}

pub(super) fn expect_success(
    frame: &DecodedRpcFrame,
    check: &'static str,
) -> Result<(), CaseFailure> {
    require(
        frame.value().get("success").and_then(Value::as_bool) == Some(true),
        check,
        format!("RPC response was not successful: {}", frame.value()),
    )
}

pub(super) fn expect_str(
    state: &Value,
    key: &str,
    expected: &str,
    check: &'static str,
) -> Result<(), CaseFailure> {
    require(
        state.get(key).and_then(Value::as_str) == Some(expected),
        check,
        format!(
            "expected {key}={expected:?}, observed {}",
            state.get(key).unwrap_or(&Value::Null)
        ),
    )
}

pub(super) fn expect_bool(
    state: &Value,
    key: &str,
    expected: bool,
    check: &'static str,
) -> Result<(), CaseFailure> {
    require(
        state.get(key).and_then(Value::as_bool) == Some(expected),
        check,
        format!(
            "expected {key}={expected}, observed {}",
            state.get(key).unwrap_or(&Value::Null)
        ),
    )
}

pub(super) fn expect_u64(
    state: &Value,
    key: &str,
    expected: u64,
    check: &'static str,
) -> Result<(), CaseFailure> {
    require(
        state.get(key).and_then(Value::as_u64) == Some(expected),
        check,
        format!(
            "expected {key}={expected}, observed {}",
            state.get(key).unwrap_or(&Value::Null)
        ),
    )
}

pub(super) fn require(
    condition: bool,
    check: &'static str,
    detail: impl Into<String>,
) -> Result<(), CaseFailure> {
    if condition {
        Ok(())
    } else {
        Err(CaseFailure {
            check: check.to_owned(),
            detail: detail.into(),
        })
    }
}

pub(super) fn failure(check: &'static str, detail: impl std::fmt::Display) -> CaseFailure {
    CaseFailure {
        check: check.to_owned(),
        detail: detail.to_string(),
    }
}

pub(super) fn available_fixture_command(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("available_commands_update")
        && value
            .get("commands")
            .and_then(Value::as_array)
            .is_some_and(|commands| {
                commands.iter().any(|command| {
                    command.get("name").and_then(Value::as_str) == Some("odin-fixture")
                })
            })
}

pub(super) fn is_agent_work_frame(value: &Value) -> bool {
    matches!(
        value.get("type").and_then(Value::as_str),
        Some("agent_start" | "turn_start" | "message_start" | "tool_execution_start")
    )
}

pub(super) fn find_response<'a>(frames: &'a [Value], id: &str, command: &str) -> Option<&'a Value> {
    frames.iter().find(|value| {
        value.get("type").and_then(Value::as_str) == Some("response")
            && value.get("id").and_then(Value::as_str) == Some(id)
            && value.get("command").and_then(Value::as_str) == Some(command)
    })
}

pub(super) fn frame_values(frames: &[DecodedRpcFrame]) -> Vec<Value> {
    frames.iter().map(DecodedRpcFrame::value).cloned().collect()
}

pub(super) fn configuration_state(state: &Value) -> Value {
    json!({
        "steeringMode": state.get("steeringMode"),
        "followUpMode": state.get("followUpMode"),
        "interruptMode": state.get("interruptMode"),
        "autoCompactionEnabled": state.get("autoCompactionEnabled"),
        "fastModeEnabled": state.get("fastModeEnabled"),
        "modelProvider": state.pointer("/model/provider"),
        "modelId": state.pointer("/model/id"),
    })
}

pub(super) fn push_transcript(
    driver: &RawRpcDriver,
    label: &str,
    evidence: &mut Vec<CaseEvidence>,
) {
    let mut bytes = Vec::new();
    let mut part = 1_usize;
    let mut emit = |bytes: &mut Vec<u8>| {
        evidence.push(CaseEvidence {
            kind: "rpc_transcript",
            label: format!("{label}-part-{part:03}"),
            bytes: std::mem::take(bytes),
        });
        part += 1;
    };
    for frame in driver.transcript() {
        if bytes.len() == MAX_EVIDENCE_ARTIFACT_BYTES {
            emit(&mut bytes);
        }
        let raw = frame.raw();
        let mut offset = 0;
        while offset < raw.len() {
            let room = MAX_EVIDENCE_ARTIFACT_BYTES - bytes.len();
            let take = room.min(raw.len() - offset);
            bytes.extend_from_slice(&raw[offset..offset + take]);
            offset += take;
            if bytes.len() == MAX_EVIDENCE_ARTIFACT_BYTES {
                emit(&mut bytes);
            }
        }
        bytes.push(b'\n');
    }
    emit(&mut bytes);
}

pub(super) fn exit_evidence(label: &str, exit: &OmpExitRecord) -> CaseEvidence {
    json_evidence(
        "process_exit",
        label,
        &json!({
            "success": exit.success(),
            "code": exit.code(),
            "stderrTail": exit.stderr_tail_lossy(),
            "unfinishedFrame": exit.unfinished_sequence().map(|error| error.kind().to_string()),
        }),
    )
}

pub(super) fn json_evidence(
    kind: &'static str,
    label: impl Into<String>,
    value: &Value,
) -> CaseEvidence {
    CaseEvidence {
        kind,
        label: label.into(),
        bytes: serde_json::to_vec_pretty(value).expect("JSON values are serializable"),
    }
}

pub(super) fn text_evidence(
    kind: &'static str,
    label: impl Into<String>,
    text: impl AsRef<[u8]>,
) -> CaseEvidence {
    CaseEvidence {
        kind,
        label: label.into(),
        bytes: text.as_ref().to_vec(),
    }
}

pub(super) fn setup_failure(
    case_name: &'static str,
    check: &'static str,
    error: impl std::fmt::Display,
) -> CaseOutcome {
    let detail = error.to_string();
    let mut outcome = CaseOutcome::fail(
        format!("{case_name} setup failed"),
        vec![CaseFailure {
            check: check.to_owned(),
            detail: detail.clone(),
        }],
    );
    outcome
        .evidence
        .push(text_evidence("case_error", check, detail));
    outcome
}

pub(super) fn finish_case(
    pass_summary: &'static str,
    fail_summary: &'static str,
    mut failures: Vec<CaseFailure>,
    evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
    expected_cleanup: usize,
) -> CaseOutcome {
    if evidence.is_empty() {
        failures.push(failure("evidence", "the case returned no evidence"));
    }
    if cleanup.steps.len() != expected_cleanup {
        failures.push(failure(
            "cleanup_receipt",
            format!(
                "expected {expected_cleanup} child cleanup step(s), observed {}",
                cleanup.steps.len()
            ),
        ));
    }
    if !cleanup.is_clean() {
        failures.push(failure(
            "cleanup_residue",
            "one or more cleanup steps failed",
        ));
    }
    let mut outcome = if failures.is_empty() {
        CaseOutcome::pass(pass_summary)
    } else {
        CaseOutcome::fail(fail_summary, failures)
    };
    outcome.evidence = evidence;
    outcome.cleanup = cleanup;
    outcome
}

pub(super) fn rpc_deadline() -> Instant {
    Instant::now() + RPC_STEP_TIMEOUT
}
