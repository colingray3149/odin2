//! Validation and retained-evidence helpers backing the startup case:
//! launch/identity checks, transcript and auxiliary-window validation, and
//! the bounded evidence artifacts the case retains.

use std::fs;

use serde_json::{json, Value};

use crate::bridge::{classify_frame, FrameClass};
use crate::frames::{DecodedRpcFrame, MAX_FRAME_BYTES, MAX_REASSEMBLED_BYTES};
use crate::probe::{
    pinned_omp_version, CaseEvidence, CaseFailure, CaseOutcome, CleanupOutcome, CleanupReceipt,
    RawRpcError, MAX_EVIDENCE_ARTIFACT_BYTES, PINNED_OMP_SOURCE_REVISION,
};
use crate::process::{OmpExecutableIdentity, OmpProcessError, NEGOTIATE_REQUEST_ID};

use super::*;

pub(super) fn selects_existing_session(argument: &str) -> bool {
    matches!(
        argument,
        "--continue"
            | "-c"
            | "--resume"
            | "-r"
            | "--session"
            | "--fork"
            | "--from-claude"
            | "--from-codex"
    ) || argument.starts_with("--resume=")
        || argument.starts_with("--session=")
        || argument.starts_with("--fork=")
        || argument.starts_with("--no-session=")
}

pub(super) fn validate_identity(
    configured_executable: &std::path::Path,
    identity: &OmpExecutableIdentity,
    failures: &mut Vec<CaseFailure>,
) {
    match fs::canonicalize(configured_executable) {
        Ok(expected) if identity.canonical_path() == expected => {}
        Ok(expected) => push_failure(
            failures,
            "executable_path",
            format!(
                "configured executable resolved to {}, identity reported {}",
                expected.display(),
                identity.canonical_path().display()
            ),
        ),
        Err(error) => push_failure(
            failures,
            "executable_path",
            format!("configured executable stopped resolving after identity probe: {error}"),
        ),
    }
    if identity.source_revision() != PINNED_OMP_SOURCE_REVISION {
        push_failure(
            failures,
            "source_revision",
            format!(
                "expected {PINNED_OMP_SOURCE_REVISION}, observed {}",
                identity.source_revision()
            ),
        );
    }
    let pinned_version = match pinned_omp_version() {
        Ok(version) => version,
        Err(error) => {
            push_failure(failures, "executable_version", error.to_string());
            return;
        }
    };
    let pinned = parse_semantic_version(&pinned_version);
    match (parse_semantic_version(identity.version()), pinned) {
        (Some(observed), Some((major, minor, patch))) if observed == (major, minor, patch) => {}
        (Some(observed), Some((major, minor, patch))) => push_failure(
            failures,
            "executable_version",
            format!(
                "expected semantic version {major}.{minor}.{patch} from the pinned package \
                 {pinned_version}, observed {observed:?} in exact text {:?}",
                identity.version()
            ),
        ),
        (Some(_), None) => push_failure(
            failures,
            "executable_version",
            format!(
                "pinned package version {pinned_version:?} is not exactly one semantic version"
            ),
        ),
        (None, _) => push_failure(
            failures,
            "executable_version",
            format!(
                "expected exactly one semantic version in --version text, observed {:?}",
                identity.version()
            ),
        ),
    }
}

pub(super) fn retain_identity(identity: &OmpExecutableIdentity, evidence: &mut Vec<CaseEvidence>) {
    evidence.push(CaseEvidence {
        kind: "executable_identity",
        label: "identity.json".to_owned(),
        bytes: json!({
            "canonicalPath": identity.canonical_path().to_string_lossy(),
            "sourceRevision": identity.source_revision(),
            "pinnedVersion": pinned_omp_version().ok(),
            "versionText": identity.version(),
            "parsedSemanticVersion": parse_semantic_version(identity.version()).map(
                |(major, minor, patch)| format!("{major}.{minor}.{patch}")
            ),
        })
        .to_string()
        .into_bytes(),
    });
    evidence.push(CaseEvidence {
        kind: "version_output",
        label: "omp-version.stdout".to_owned(),
        bytes: identity.version().as_bytes().to_vec(),
    });
}

fn parse_semantic_version(text: &str) -> Option<(u64, u64, u64)> {
    let mut candidates = text
        .split(|character: char| !character.is_ascii_digit() && character != '.')
        .filter_map(parse_semantic_version_token);
    let version = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    Some(version)
}

fn parse_semantic_version_token(token: &str) -> Option<(u64, u64, u64)> {
    let mut components = token.split('.');
    let major = components.next()?.parse().ok()?;
    let minor = components.next()?.parse().ok()?;
    let patch = components.next()?.parse().ok()?;
    if components.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

pub(super) fn validate_ready(frame: &DecodedRpcFrame, failures: &mut Vec<CaseFailure>) {
    let expected = json!({
        "type": "ready",
        "protocolVersion": 1,
        "supportedProtocolVersions": [1, 2],
        "maxFrameBytes": MAX_FRAME_BYTES,
        "maxReassembledFrameBytes": MAX_REASSEMBLED_BYTES,
    });
    if frame.value() != &expected {
        push_failure(
            failures,
            "ready_frame",
            format!("expected exact {expected}, observed {}", frame.value()),
        );
    }
}

pub(super) fn validate_negotiation(frame: &DecodedRpcFrame, failures: &mut Vec<CaseFailure>) {
    let expected = json!({
        "id": NEGOTIATE_REQUEST_ID,
        "type": "response",
        "command": "negotiate_protocol",
        "success": true,
        "data": {"protocolVersion": 2},
    });
    if frame.value() != &expected {
        push_failure(
            failures,
            "negotiated_protocol",
            format!("expected exact {expected}, observed {}", frame.value()),
        );
    }
}

/// Validates the exact retained startup transcript against the
/// `startup_frames` contract: the ready frame at index 0 and, when protocol
/// v2 negotiation ran, the exact negotiation response at the last index, with
/// only bounded auxiliary frames between them. A v1 startup runs no
/// negotiation, so its transcript is exactly the ready frame — auxiliary
/// frames cannot exist outside the negotiation window. Every validated
/// auxiliary's exact physical lines aggregate into one bounded evidence
/// artifact in arrival order.
pub(super) fn validate_startup_transcript(
    transcript: &[DecodedRpcFrame],
    ready: Option<&DecodedRpcFrame>,
    negotiation: Option<&DecodedRpcFrame>,
    evidence: &mut Vec<CaseEvidence>,
    failures: &mut Vec<CaseFailure>,
) {
    if ready != transcript.first() {
        push_failure(
            failures,
            "startup_transcript",
            "first retained frame is not the exact ready evidence",
        );
    }
    let Some(negotiation) = negotiation else {
        // No negotiation ran: a v1 startup retains exactly the ready frame.
        if transcript.len() != 1 {
            push_failure(
                failures,
                "startup_transcript",
                format!(
                    "startup retained {} frame(s) without a negotiation response; expected exactly the ready frame",
                    transcript.len()
                ),
            );
        }
        return;
    };
    if Some(negotiation) != transcript.last() {
        push_failure(
            failures,
            "startup_transcript",
            "last retained frame is not the exact negotiation evidence",
        );
    }
    let auxiliaries: &[DecodedRpcFrame] = match transcript.len() {
        0 | 1 => &[],
        length => &transcript[1..length - 1],
    };
    if auxiliaries.len() > MAX_STARTUP_AUX_FRAMES {
        push_failure(
            failures,
            "startup_auxiliary",
            format!(
                "expected at most {MAX_STARTUP_AUX_FRAMES} retained startup auxiliary frames, observed {}",
                auxiliaries.len()
            ),
        );
    }
    let auxiliary_bytes = auxiliaries.iter().fold(0_usize, |total, frame| {
        total.saturating_add(frame.raw().len())
    });
    if auxiliary_bytes > MAX_STARTUP_AUX_BYTES {
        push_failure(
            failures,
            "startup_auxiliary",
            format!(
                "startup auxiliary frames retained {auxiliary_bytes} logical bytes, exceeding the {MAX_STARTUP_AUX_BYTES}-byte bound"
            ),
        );
    }
    // Validation and evidence stay bounded even when the window itself
    // overflows: only the in-cap prefix is validated and retained.
    let in_cap = &auxiliaries[..auxiliaries.len().min(MAX_STARTUP_AUX_FRAMES)];
    for (index, frame) in in_cap.iter().enumerate() {
        validate_startup_auxiliary(index + 1, frame, failures);
    }
    if let Some(artifact) = startup_auxiliary_evidence(in_cap, failures) {
        evidence.push(artifact);
    }
}

/// Validates one retained startup auxiliary frame: inside the v1-framed
/// negotiation window it must classify under the production vocabulary, must
/// not be a ready, response, or chunk frame, and its logical raw bytes must
/// be the exact physical frame payload.
fn validate_startup_auxiliary(
    position: usize,
    frame: &DecodedRpcFrame,
    failures: &mut Vec<CaseFailure>,
) {
    match classify_frame(frame.value()) {
        FrameClass::Ready => push_failure(
            failures,
            "startup_auxiliary",
            format!("auxiliary frame at startup position {position} is a second ready frame"),
        ),
        FrameClass::Response => push_failure(
            failures,
            "startup_auxiliary",
            format!(
                "auxiliary frame at startup position {position} is a response; only the exact negotiation response may close startup"
            ),
        ),
        FrameClass::Unknown if is_chunk_frame(frame.value()) => push_failure(
            failures,
            "startup_auxiliary",
            format!("auxiliary frame at startup position {position} is a chunk frame"),
        ),
        FrameClass::Unknown => push_failure(
            failures,
            "startup_auxiliary",
            format!(
                "auxiliary frame at startup position {position} is not classified by the production frame classifier: {}",
                frame.value()
            ),
        ),
        _ => {}
    }
    match frame.lines() {
        [line] => {
            if line.last() != Some(&b'\n') {
                push_failure(
                    failures,
                    "startup_auxiliary_raw",
                    format!(
                        "auxiliary frame at startup position {position} is not newline terminated"
                    ),
                );
            } else if line.get(..line.len() - 1) != Some(frame.raw()) {
                push_failure(
                    failures,
                    "startup_auxiliary_raw",
                    format!(
                        "auxiliary frame at startup position {position} logical raw bytes differ from the exact physical frame payload"
                    ),
                );
            }
        }
        lines => push_failure(
            failures,
            "startup_auxiliary_raw",
            format!(
                "auxiliary frame at startup position {position} expected one physical line, observed {}",
                lines.len()
            ),
        ),
    }
}

/// Aggregates every validated startup auxiliary frame's exact physical lines
/// into one bounded transcript artifact, in arrival order; the physical
/// newline boundaries keep frames separable byte-for-byte.
fn startup_auxiliary_evidence(
    auxiliaries: &[DecodedRpcFrame],
    failures: &mut Vec<CaseFailure>,
) -> Option<CaseEvidence> {
    if auxiliaries.is_empty() {
        return None;
    }
    // The 4 MiB logical window plus one terminating newline per frame: every
    // production-legal window fits exactly.
    const MAX_STARTUP_AUX_ARTIFACT_BYTES: usize = MAX_STARTUP_AUX_BYTES + MAX_STARTUP_AUX_FRAMES;
    let total = auxiliaries
        .iter()
        .flat_map(|frame| frame.lines())
        .try_fold(0_usize, |total, line| total.checked_add(line.len()));
    let Some(total) = total.filter(|total| *total <= MAX_STARTUP_AUX_ARTIFACT_BYTES) else {
        push_failure(
            failures,
            "startup_auxiliary",
            "auxiliary transcript evidence exceeded the bounded artifact allowance",
        );
        return None;
    };
    let mut bytes = Vec::with_capacity(total);
    for frame in auxiliaries {
        for line in frame.lines() {
            bytes.extend_from_slice(line);
        }
    }
    Some(CaseEvidence {
        kind: "startup_auxiliary",
        label: "startup-aux.raw.jsonl".to_owned(),
        bytes,
    })
}

/// Chunk frames must never appear in the decoded startup transcript.
pub(super) fn is_chunk_frame(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("rpc_chunk")
}

pub(super) fn frame_evidence(
    kind: &'static str,
    label: &str,
    check: &'static str,
    frame: &DecodedRpcFrame,
    failures: &mut Vec<CaseFailure>,
) -> CaseEvidence {
    let bytes = match frame.lines() {
        [line] => {
            if line.last() != Some(&b'\n') {
                push_failure(failures, check, "physical frame is not newline terminated");
            } else if line.get(..line.len() - 1) != Some(frame.raw()) {
                push_failure(
                    failures,
                    check,
                    "logical raw bytes differ from the exact physical frame payload",
                );
            }
            line.clone()
        }
        lines => {
            push_failure(
                failures,
                check,
                format!("expected one physical line, observed {}", lines.len()),
            );
            concatenate_lines(lines).unwrap_or_else(|| frame.raw().to_vec())
        }
    };
    CaseEvidence {
        kind,
        label: label.to_owned(),
        bytes,
    }
}

pub(super) fn shutdown_evidence(
    frames: &[DecodedRpcFrame],
    failures: &mut Vec<CaseFailure>,
) -> Option<CaseEvidence> {
    if frames.is_empty() {
        return None;
    }
    let total = frames
        .iter()
        .flat_map(|frame| frame.lines())
        .try_fold(0_usize, |total, line| total.checked_add(line.len()));
    let Some(total) = total.filter(|total| *total <= MAX_EVIDENCE_ARTIFACT_BYTES) else {
        push_failure(
            failures,
            "shutdown_evidence",
            "drain-frame evidence exceeded the bounded artifact allowance",
        );
        return None;
    };
    let mut bytes = Vec::with_capacity(total);
    for frame in frames {
        for line in frame.lines() {
            bytes.extend_from_slice(line);
        }
    }
    Some(CaseEvidence {
        kind: "shutdown_frames",
        label: "stdin-close.raw.jsonl".to_owned(),
        bytes,
    })
}

pub(super) fn validate_cleanup(cleanup: &CleanupReceipt, failures: &mut Vec<CaseFailure>) {
    let graceful = cleanup.steps.len() == 1
        && cleanup.steps[0].kind == "child_stop"
        && matches!(&cleanup.steps[0].outcome, CleanupOutcome::Clean);
    if !graceful {
        push_failure(
            failures,
            "cleanup_receipt",
            format!(
                "expected one clean child_stop receipt from bounded graceful exit, observed {:?}",
                cleanup.steps
            ),
        );
    }
    if !cleanup.is_clean() {
        push_failure(
            failures,
            "cleanup_receipt",
            "cleanup receipt contains failed residue",
        );
    }
}

pub(super) fn enforce_success_evidence(evidence: &[CaseEvidence], failures: &mut Vec<CaseFailure>) {
    for required in [
        "launch_contract",
        "executable_identity",
        "version_output",
        "ready_frame",
        "protocol_negotiation",
        "process_exit",
    ] {
        if !evidence
            .iter()
            .any(|item| item.kind == required && !item.bytes.is_empty())
        {
            push_failure(
                failures,
                "required_evidence",
                format!("missing non-empty {required} evidence"),
            );
        }
    }
}

pub(super) fn retain_raw_driver_error(error: &RawRpcError, evidence: &mut Vec<CaseEvidence>) {
    match error {
        RawRpcError::Process(error) => retain_process_error(error, evidence),
        _ => evidence.push(error_evidence("raw-rpc-error.txt", error)),
    }
}

pub(super) fn retain_process_error(error: &OmpProcessError, evidence: &mut Vec<CaseEvidence>) {
    evidence.push(error_evidence("process-error.txt", error));
    if let Some(lines) = startup_error_lines(error).and_then(concatenate_lines) {
        evidence.push(CaseEvidence {
            kind: "startup_error_frame",
            label: "startup-error.raw.jsonl".to_owned(),
            bytes: lines,
        });
    }
    if let Some(stderr) = process_error_stderr(error).filter(|stderr| !stderr.is_empty()) {
        evidence.push(CaseEvidence {
            kind: "process_stderr",
            label: "startup-error.stderr".to_owned(),
            bytes: stderr.to_vec(),
        });
    }
}

fn startup_error_lines(error: &OmpProcessError) -> Option<&[Vec<u8>]> {
    match error {
        OmpProcessError::StartupFailed { inner, .. } => startup_error_lines(inner),
        OmpProcessError::InvalidReadyFrame { lines, .. }
        | OmpProcessError::UnexpectedStartupFrame { lines, .. }
        | OmpProcessError::NegotiationMismatch { lines, .. } => Some(lines),
        OmpProcessError::FrameRejected(error) => Some(error.evidence()),
        _ => None,
    }
}

fn process_error_stderr(error: &OmpProcessError) -> Option<&[u8]> {
    match error {
        OmpProcessError::VersionProbe { stderr_tail, .. }
        | OmpProcessError::StartupFailed { stderr_tail, .. } => Some(stderr_tail),
        OmpProcessError::StdoutClosed { exit } => Some(exit.stderr_tail()),
        _ => None,
    }
}

fn concatenate_lines(lines: &[Vec<u8>]) -> Option<Vec<u8>> {
    let total = lines
        .iter()
        .try_fold(0_usize, |total, line| total.checked_add(line.len()))?;
    if total > MAX_EVIDENCE_ARTIFACT_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(total);
    for line in lines {
        bytes.extend_from_slice(line);
    }
    Some(bytes)
}

pub(super) fn error_evidence(label: &str, error: &dyn std::fmt::Display) -> CaseEvidence {
    CaseEvidence {
        kind: "case_error",
        label: label.to_owned(),
        bytes: error.to_string().into_bytes(),
    }
}

pub(super) fn push_failure(
    failures: &mut Vec<CaseFailure>,
    check: &'static str,
    detail: impl Into<String>,
) {
    failures.push(CaseFailure {
        check: check.to_owned(),
        detail: detail.into(),
    });
}

pub(super) fn finish(
    failures: Vec<CaseFailure>,
    evidence: Vec<CaseEvidence>,
    cleanup: CleanupReceipt,
) -> CaseOutcome {
    let mut outcome = if failures.is_empty() {
        CaseOutcome::pass(
            "pinned OMP started without a session, negotiated protocol v2, and exited cleanly",
        )
    } else {
        CaseOutcome::fail("pinned OMP fresh-start conformance failed", failures)
    };
    outcome.evidence = evidence;
    outcome.cleanup = cleanup;
    outcome
}
