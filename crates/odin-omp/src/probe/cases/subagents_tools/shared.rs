//! The shared case harness: response/directive contract checks, evidence
//! plumbing, and deadline bounds for cases 11-13.

use super::*;

pub(super) const CASE_DEADLINE: Duration = Duration::from_secs(90);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn request_id(observed: &ObservedFrame) -> Result<String, String> {
    observed
        .value()
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "side-channel request omitted its correlation id".to_owned())
}

pub(super) fn response_data<'a>(
    frame: &'a DecodedRpcFrame,
    command: &str,
) -> Result<&'a Value, String> {
    ensure_response_success(frame, command)?;
    frame
        .value()
        .get("data")
        .ok_or_else(|| format!("{command} response omitted data"))
}

pub(super) fn ensure_response_success(
    frame: &DecodedRpcFrame,
    command: &str,
) -> Result<(), String> {
    let value = frame.value();
    if value.get("type").and_then(Value::as_str) != Some("response")
        || value.get("command").and_then(Value::as_str) != Some(command)
        || value.get("success").and_then(Value::as_bool) != Some(true)
    {
        return Err(format!(
            "{command} returned a non-success response: {value}"
        ));
    }
    Ok(())
}

/// Whether one response payload explicitly contradicts a pinned
/// model-visible directive. Success with an absent `data` payload — or an
/// absent flag — accepts the directive; only a literal `agentInvoked: false`
/// rejects it. Each case proves real invocation through its required agent,
/// tool, or side-channel lifecycle frames instead of this metadata.
pub(super) fn directive_rejected(data: &Value) -> bool {
    data.get("agentInvoked").and_then(Value::as_bool) == Some(false)
}

/// Accepts any successful pinned directive response; only an explicit
/// `agentInvoked: false` rejects it.
pub(super) fn ensure_directive_accepted(
    frame: &DecodedRpcFrame,
    command: &str,
) -> Result<(), String> {
    ensure_response_success(frame, command)?;
    if directive_rejected(frame.value().get("data").unwrap_or(&Value::Null)) {
        return Err(format!(
            "{command} response rejected the model-visible directive: agentInvoked=false"
        ));
    }
    Ok(())
}

pub(super) fn push_raw_transcript(
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
    label: &str,
    frames: &[DecodedRpcFrame],
) {
    let bytes = frames
        .iter()
        .flat_map(|frame| frame.lines().iter())
        .flat_map(|line| line.iter().copied())
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        failures.push(failure(
            "raw_evidence",
            format!("{label} contained no physical RPC frame bytes"),
        ));
    } else {
        evidence.push(CaseEvidence {
            kind: "raw_rpc",
            label: label.to_owned(),
            bytes,
        });
    }
}

pub(super) fn push_observed_evidence(
    failures: &mut Vec<CaseFailure>,
    evidence: &mut Vec<CaseEvidence>,
    label: &str,
    frames: &[ObservedFrame],
) {
    let mut bytes = Vec::new();
    for frame in frames {
        if let Some(decoded) = &frame.decoded {
            for line in decoded.lines() {
                bytes.extend_from_slice(line);
            }
        } else if let Some(rejection) = &frame.rejection {
            for line in rejection.evidence() {
                bytes.extend_from_slice(line);
            }
        }
    }
    if bytes.is_empty() {
        failures.push(failure(
            "raw_evidence",
            format!("{label} contained no bridge frame bytes"),
        ));
    } else {
        evidence.push(CaseEvidence {
            kind: "raw_rpc",
            label: label.to_owned(),
            bytes,
        });
    }
}

pub(super) fn failure(check: &'static str, detail: impl ToString) -> CaseFailure {
    CaseFailure {
        check: check.to_owned(),
        detail: detail.to_string(),
    }
}

pub(super) fn finish_outcome(
    pass_summary: &'static str,
    fail_summary: &'static str,
    mut failures: Vec<CaseFailure>,
    evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
) -> CaseOutcome {
    if evidence.is_empty() {
        failures.push(failure(
            "missing_evidence",
            "case produced no retained evidence artifacts",
        ));
    }
    if !cleanup.is_clean() {
        failures.push(failure(
            "cleanup",
            "one or more explicit cleanup steps failed",
        ));
    }
    if failures.is_empty() && cleanup.steps.is_empty() {
        failures.push(failure(
            "missing_cleanup",
            "case performed effects without a cleanup receipt",
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

pub(super) fn operation_deadline() -> Instant {
    Instant::now() + OPERATION_TIMEOUT
}
