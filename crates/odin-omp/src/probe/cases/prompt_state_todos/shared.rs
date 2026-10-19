//! The shared case harness: driver spawn, RPC response/ordering checks, and
//! evidence plumbing for cases 3-5.

use super::*;

pub(super) const CASE_DEADLINE: Duration = Duration::from_secs(60);
pub(super) const RPC_WAIT: Duration = Duration::from_secs(20);
pub(super) const STATE_DELAY_MS: u64 = 3_000;

pub(super) async fn spawn_driver(context: &CaseContext) -> Result<RawRpcDriver, CaseFailure> {
    let spec = context.process_spec(DEFAULT_MODEL_SELECTOR, Vec::new());
    let worker = context.worker_for(&spec);
    RawRpcDriver::spawn(spec, worker)
        .await
        .map_err(|error| rpc_error("child_spawn", error))
}

pub(super) async fn collect_if_missing<F>(
    driver: &mut RawRpcDriver,
    start: usize,
    check: &'static str,
    mut predicate: F,
) -> Result<(), CaseFailure>
where
    F: FnMut(&Value) -> bool,
{
    if driver
        .transcript()
        .iter()
        .skip(start)
        .any(|frame| predicate(frame.value()))
    {
        return Ok(());
    }
    driver
        .collect_until(deadline(), |frame| predicate(frame.value()))
        .await
        .map(|_| ())
        .map_err(|error| rpc_error(check, error))
}

pub(super) fn check_response(
    frame: &DecodedRpcFrame,
    id: &str,
    command: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> bool {
    let value = frame.value();
    let correlated = response_matches(value, id, command);
    require(
        correlated,
        "response_correlation",
        format!("{label} did not match id={id} command={command}"),
        failures,
    );
    let successful = value.get("success").and_then(Value::as_bool) == Some(true);
    require(
        successful,
        "response_success",
        format!(
            "{label} failed{}",
            value
                .get("error")
                .and_then(Value::as_str)
                .map_or_else(String::new, |error| format!(": {error}"))
        ),
        failures,
    );
    correlated && successful
}

pub(super) fn response_data<'a>(
    frame: &'a DecodedRpcFrame,
    id: &str,
    command: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> Option<&'a Value> {
    if !check_response(frame, id, command, label, failures) {
        return None;
    }
    match frame.value().get("data") {
        Some(data) => Some(data),
        None => {
            failures.push(failure("response_data", format!("{label} omitted data")));
            None
        }
    }
}

pub(super) fn response_matches(value: &Value, id: &str, command: &str) -> bool {
    is_type(value, "response")
        && value.get("id").and_then(Value::as_str) == Some(id)
        && value.get("command").and_then(Value::as_str) == Some(command)
}

pub(super) fn prompt_result_matches(value: &Value, id: &str) -> bool {
    is_type(value, "prompt_result") && value.get("id").and_then(Value::as_str) == Some(id)
}

pub(super) fn is_type(value: &Value, expected: &str) -> bool {
    value.get("type").and_then(Value::as_str) == Some(expected)
}

pub(super) fn message_role(value: &Value, expected: &str) -> bool {
    value
        .get("message")
        .and_then(|message| message.get("role"))
        .and_then(Value::as_str)
        == Some(expected)
}

pub(super) fn message_has_tool_call(value: &Value, tool_name: &str) -> bool {
    value
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_array)
        .is_some_and(|content| {
            content.iter().any(|block| {
                block.get("type").and_then(Value::as_str) == Some("toolCall")
                    && block.get("name").and_then(Value::as_str) == Some(tool_name)
            })
        })
}

pub(super) fn is_terminal_agent_end(value: &Value) -> bool {
    is_type(value, "agent_end") && value.get("isTerminal").and_then(Value::as_bool) != Some(false)
}

pub(super) fn contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(text) => text.contains(expected),
        Value::Array(values) => values.iter().any(|value| contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| contains_string(value, expected)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

pub(super) fn find_after<F>(
    frames: &[DecodedRpcFrame],
    previous: Option<usize>,
    end: usize,
    check: &'static str,
    description: &str,
    failures: &mut Vec<CaseFailure>,
    predicate: F,
) -> Option<usize>
where
    F: FnMut(&Value) -> bool,
{
    find_required(
        frames,
        previous.map_or(0, |index| index.saturating_add(1)),
        end,
        check,
        description,
        failures,
        predicate,
    )
}

pub(super) fn find_required<F>(
    frames: &[DecodedRpcFrame],
    start: usize,
    end: usize,
    check: &'static str,
    description: &str,
    failures: &mut Vec<CaseFailure>,
    mut predicate: F,
) -> Option<usize>
where
    F: FnMut(&Value) -> bool,
{
    let found = frames
        .iter()
        .enumerate()
        .skip(start)
        .take(end.saturating_sub(start))
        .find_map(|(index, frame)| predicate(frame.value()).then_some(index));
    if found.is_none() {
        failures.push(failure(check, format!("missing {description}")));
    }
    found
}

pub(super) fn require_order(
    before: Option<usize>,
    after: Option<usize>,
    check: &'static str,
    detail: &str,
    failures: &mut Vec<CaseFailure>,
) {
    if let (Some(before), Some(after)) = (before, after) {
        require(before < after, check, detail, failures);
    }
}

pub(super) fn forbid_agent_events(
    frames: &[DecodedRpcFrame],
    start: usize,
    end: usize,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) {
    const TYPES: [&str; 9] = [
        "agent_start",
        "agent_end",
        "turn_start",
        "turn_end",
        "message_start",
        "message_update",
        "message_end",
        "tool_execution_start",
        "tool_execution_end",
    ];
    if let Some(kind) = frames[start..end].iter().find_map(|frame| {
        frame
            .value()
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| TYPES.contains(kind))
    }) {
        failures.push(failure(
            "unexpected_agent_event",
            format!("{label} emitted unexpected {kind}"),
        ));
    }
}

pub(super) fn required_str(
    value: &Value,
    field: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> Option<String> {
    match value.get(field).and_then(Value::as_str) {
        Some(value) => Some(value.to_owned()),
        None => {
            failures.push(failure(
                "state_shape",
                format!("{label} omitted string {field}"),
            ));
            None
        }
    }
}

pub(super) fn required_bool(
    value: &Value,
    field: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> Option<bool> {
    match value.get(field).and_then(Value::as_bool) {
        Some(value) => Some(value),
        None => {
            failures.push(failure(
                "state_shape",
                format!("{label} omitted boolean {field}"),
            ));
            None
        }
    }
}

pub(super) fn required_u64(
    value: &Value,
    field: &str,
    label: &str,
    failures: &mut Vec<CaseFailure>,
) -> Option<u64> {
    match value.get(field).and_then(Value::as_u64) {
        Some(value) => Some(value),
        None => {
            failures.push(failure(
                "state_shape",
                format!("{label} omitted integer {field}"),
            ));
            None
        }
    }
}

pub(super) fn require(
    condition: bool,
    check: &'static str,
    detail: impl Into<String>,
    failures: &mut Vec<CaseFailure>,
) {
    if !condition {
        failures.push(failure(check, detail));
    }
}

pub(super) fn failure(check: &'static str, detail: impl Into<String>) -> CaseFailure {
    CaseFailure {
        check: check.to_owned(),
        detail: detail.into(),
    }
}

pub(super) fn rpc_error(check: &'static str, error: impl std::fmt::Display) -> CaseFailure {
    failure(check, error.to_string())
}

pub(super) fn deadline() -> Instant {
    Instant::now() + RPC_WAIT
}

pub(super) fn push_json_evidence(
    evidence: &mut Vec<CaseEvidence>,
    failures: &mut Vec<CaseFailure>,
    kind: &'static str,
    label: &str,
    value: &Value,
) {
    match serde_json::to_vec_pretty(value) {
        Ok(bytes) => evidence.push(CaseEvidence {
            kind,
            label: label.to_owned(),
            bytes,
        }),
        Err(error) => failures.push(rpc_error("evidence_encode", error)),
    }
}

pub(super) async fn finish_case(
    mut driver: RawRpcDriver,
    name: &'static str,
    pass_summary: &'static str,
    fail_summary: &'static str,
    mut failures: Vec<CaseFailure>,
    mut evidence: Vec<CaseEvidence>,
) -> CaseOutcome {
    let mut cleanup = CleanupReceipt::default();
    match driver
        .cleanup(&mut cleanup, format!("{name}_rpc_child"))
        .await
    {
        Ok(exit) => require(
            exit.success(),
            "cleanup_exit",
            format!("graceful child cleanup ended with {exit}"),
            &mut failures,
        ),
        Err(error) => failures.push(rpc_error("cleanup", error)),
    }
    require(
        cleanup.steps.len() == 1,
        "cleanup_receipt",
        format!(
            "expected one cleanup step, observed {}",
            cleanup.steps.len()
        ),
        &mut failures,
    );
    if !cleanup.is_clean() && !failures.iter().any(|failure| failure.check == "cleanup") {
        failures.push(failure("cleanup", "child cleanup receipt was not clean"));
    }

    let transcript = driver.transcript();
    if transcript.is_empty() {
        failures.push(failure("raw_evidence", "RPC transcript was empty"));
    } else if transcript.iter().any(|frame| frame.lines().is_empty()) {
        failures.push(failure(
            "raw_evidence",
            "a decoded frame lacked exact physical-line evidence",
        ));
    } else {
        evidence.insert(
            0,
            CaseEvidence {
                kind: "rpc_transcript",
                label: format!("{name}.jsonl"),
                bytes: raw_transcript(transcript),
            },
        );
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

pub(super) fn raw_transcript(frames: &[DecodedRpcFrame]) -> Vec<u8> {
    let capacity = frames
        .iter()
        .flat_map(|frame| frame.lines())
        .map(Vec::len)
        .sum();
    let mut bytes = Vec::with_capacity(capacity);
    for line in frames.iter().flat_map(|frame| frame.lines()) {
        bytes.extend_from_slice(line);
    }
    bytes
}
