//! Case 15 machinery: the pinned before-stop snapshot, the exact-pin
//! identity checks across both launches, and the resumed-session continuity
//! comparison on the canonical durable state and history projections.

use std::path::Path;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::probe::{
    CaseContext, CaseEvidence, CaseOutcome, CleanupReceipt, ConformanceCase, ConformanceCaseId,
    RawRpcDriver, DEFAULT_MODEL_SELECTOR, PINNED_OMP_SOURCE_REVISION,
};
use crate::process::{OmpProcessError, OmpProcessSpec};

use super::*;

const PERSISTENCE_EVIDENCE: &[&str] = &[
    "pin_identity",
    "state_history",
    "resume_comparison",
    "continuity",
    "stop",
    "rpc_transcript",
];

/// The `get_state` fields that survive a stop/resume cycle byte-for-byte: the
/// durable semantic projection case 15 compares across the cold restart. Every
/// other `RpcSessionState` field — the `isStreaming`/`isCompacting` activity
/// flags, `tokensPerSecond`, `fastModeActive`, `systemPrompt`, `dumpTools`, and
/// `contextUsage` — is derived from the live process and legitimately differs
/// after a restart, so it is excluded here.
const DURABLE_STATE_FIELDS: &[&str] = &[
    "model",
    "thinkingLevel",
    "steeringMode",
    "followUpMode",
    "interruptMode",
    "sessionId",
    "sessionFile",
    "sessionName",
    "autoCompactionEnabled",
    "fastModeEnabled",
    "messageCount",
    "queuedMessageCount",
    "todoPhases",
];

/// The optional [`DURABLE_STATE_FIELDS`] members whose absence on the wire is
/// semantically `Optional::None`, not a missing durable value. The durable
/// projection rewrites each of their disabled encodings onto one canonical
/// form ([`canonical_optional_encoding`]) so an encoding-only difference
/// across the restart does not fail case 15: `thinkingLevel` follows the
/// optional `ThinkingLevel` contract — absent, null, and `"off"` are one
/// disabled state, canonically `"off"` — while `sessionName` keeps absent
/// and null as explicit null. Concrete non-disabled values are never
/// rewritten, so real configured drift still fails.
const OPTIONAL_STATE_FIELDS: &[&str] = &["thinkingLevel", "sessionName"];

/// Canonical durable encoding of the disabled `thinkingLevel` state.
const THINKING_LEVEL_OFF: &str = "off";

pub(super) struct SessionStopResumeCase;

/// The pinned before-stop snapshot case 15 compares the resumed session
/// against: the final live `get_state` next to its durable projection, the
/// semantic projection of the paged history, and the pinned session
/// identity. Raw page responses stay in evidence; only the projection is
/// pinned for comparison.
struct PersistedSnapshot {
    state: Value,
    durable_projection: Value,
    /// [`semantic_history_projection`] of the paged history: the compared
    /// form; raw pages remain evidence only.
    semantic_messages: Vec<Value>,
    /// blake3 digest of the semantic projection.
    history_digest: String,
    session_id: String,
    session_file: String,
}

#[async_trait]
impl ConformanceCase for SessionStopResumeCase {
    fn id(&self) -> ConformanceCaseId {
        SESSION_STOP_RESUME
    }

    fn name(&self) -> &'static str {
        "session_stop_resume"
    }

    fn deadline(&self) -> Duration {
        CASE_DEADLINE
    }

    async fn run(&self, context: &CaseContext) -> CaseOutcome {
        let mut evidence = Vec::new();
        let mut cleanup = CleanupReceipt::default();
        let result = run_session_stop_resume(context, &mut evidence, &mut cleanup).await;
        finish_case(
            "the exact pinned OMP resumed one persisted session without state or history drift",
            "session stop/resume conformance failed",
            result,
            evidence,
            cleanup,
            PERSISTENCE_EVIDENCE,
            2,
        )
    }
}

async fn run_session_stop_resume(
    context: &CaseContext,
    evidence: &mut Vec<CaseEvidence>,
    cleanup: &mut CleanupReceipt,
) -> CheckResult<()> {
    let session_dir = context.work_dir().join("persistence-sessions");
    let first_spec = context.process_spec(DEFAULT_MODEL_SELECTOR, session_dir_args(&session_dir));
    let first_identity = first_spec
        .establish_identity(&context.worker_for(&first_spec))
        .await
        .map_err(|error| exact_pin_probe_failure(&first_spec, error))?;
    validate_pin(
        first_identity.source_revision(),
        first_identity.canonical_path(),
        "first launch",
    )?;

    let mut first = {
        let worker = context.worker_for(&first_spec);
        RawRpcDriver::spawn(first_spec, worker)
    }
    .await
    .map_err(|error| CaseCheck::new("first_spawn", error.to_string()))?;
    let first_subject = child_subject(&first, "case-15-before-stop");
    let before = capture_persisted_snapshot(&mut first, evidence).await;
    let first_stop = first.cleanup(cleanup, first_subject).await;
    let first_transcript = push_transcript_evidence(evidence, "before-stop", first.transcript());

    let before = before?;
    let first_exit = first_stop.map_err(|error| CaseCheck::new("first_stop", error.to_string()))?;
    first_transcript?;
    push_stop_evidence(evidence, "first-stop", &first_exit)?;
    if !first_exit.success() {
        return Err(CaseCheck::new(
            "first_stop",
            format!("first child did not stop successfully: {first_exit}"),
        ));
    }

    let metadata = std::fs::metadata(&before.session_file)
        .map_err(|error| CaseCheck::new("session_persisted", error.to_string()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(CaseCheck::new(
            "session_persisted",
            format!(
                "session file `{}` is not a non-empty regular file",
                before.session_file
            ),
        ));
    }

    let mut resume_args = session_dir_args(&session_dir);
    resume_args.push("--session".to_owned());
    resume_args.push(before.session_file.clone());
    let second_spec = context.process_spec(DEFAULT_MODEL_SELECTOR, resume_args);
    let second_identity = second_spec
        .establish_identity(&context.worker_for(&second_spec))
        .await
        .map_err(|error| exact_pin_probe_failure(&second_spec, error))?;
    validate_pin(
        second_identity.source_revision(),
        second_identity.canonical_path(),
        "resume launch",
    )?;
    if first_identity.canonical_path() != second_identity.canonical_path()
        || first_identity.source_revision() != second_identity.source_revision()
        || first_identity.version() != second_identity.version()
    {
        return Err(CaseCheck::new(
            "exact_pin",
            "stop/resume launches did not use one identical executable identity",
        ));
    }
    push_json_evidence(
        evidence,
        "pin_identity",
        "both-launches",
        &json!({
            "expected_source_revision": PINNED_OMP_SOURCE_REVISION,
            "first": {
                "path": first_identity.canonical_path().to_string_lossy(),
                "source_revision": first_identity.source_revision(),
                "version": first_identity.version(),
            },
            "second": {
                "path": second_identity.canonical_path().to_string_lossy(),
                "source_revision": second_identity.source_revision(),
                "version": second_identity.version(),
            },
            "session_file": before.session_file,
            "session_file_bytes": metadata.len(),
        }),
        "pin_evidence",
    )?;

    let mut second = {
        let worker = context.worker_for(&second_spec);
        RawRpcDriver::spawn(second_spec, worker)
    }
    .await
    .map_err(|error| CaseCheck::new("resume_spawn", error.to_string()))?;
    let second_subject = child_subject(&second, "case-15-after-resume");
    let resumed = exercise_resumed_session(&mut second, &before, evidence).await;
    let second_stop = second.cleanup(cleanup, second_subject).await;
    let second_transcript = push_transcript_evidence(evidence, "after-resume", second.transcript());

    resumed?;
    let second_exit =
        second_stop.map_err(|error| CaseCheck::new("second_stop", error.to_string()))?;
    second_transcript?;
    push_stop_evidence(evidence, "second-stop", &second_exit)?;
    if !second_exit.success() {
        return Err(CaseCheck::new(
            "second_stop",
            format!("resumed child did not stop successfully: {second_exit}"),
        ));
    }
    Ok(())
}

async fn capture_persisted_snapshot(
    driver: &mut RawRpcDriver,
    evidence: &mut Vec<CaseEvidence>,
) -> CheckResult<PersistedSnapshot> {
    let initial = get_state(driver, "persistence_initial_state").await?;
    let mut expected_count = state_message_count(&initial, "persistence_initial_state")?;
    if expected_count != 0 {
        return Err(CaseCheck::new(
            "persistence_initial_state",
            format!("fresh persistence session began with {expected_count} messages"),
        ));
    }

    for turn in 0..4 {
        let message = if turn == 1 {
            "odin-mock:big 65536".to_owned()
        } else {
            format!("odin-mock:echo case-15-before-stop-{turn}")
        };
        expected_count += 2;
        let state = prompt_and_wait(driver, &message, expected_count, "persist_effect").await?;
        if state_message_count(&state, "persist_effect")? != expected_count {
            return Err(CaseCheck::new(
                "persist_effect",
                format!("turn {turn} did not append exactly one user/assistant pair"),
            ));
        }
    }

    let state = get_state(driver, "pre_stop_state").await?;
    assert_idle_state(&state, "pre_stop_state")?;
    let history = page_all(driver, "pre_stop_history").await?;
    if history.total != expected_count
        || history.messages.len() != expected_count
        || state_message_count(&state, "pre_stop_state")? != expected_count
    {
        return Err(CaseCheck::new(
            "pre_stop_history",
            format!(
                "state/history totals diverged: expected {expected_count}, state {}, history {}/{}",
                state_message_count(&state, "pre_stop_state")?,
                history.messages.len(),
                history.total
            ),
        ));
    }

    let session_id = required_state_string(&state, "sessionId", "pre_stop_state")?;
    let session_file = required_state_string(&state, "sessionFile", "pre_stop_state")?;
    let durable_projection = durable_state_projection(&state, "pre_stop_state")?;
    let semantic_messages = semantic_history_projection(&history.messages);
    let history_value = Value::Array(semantic_messages.clone());
    let history_digest = digest_value(&history_value, "pre_stop_history")?;
    push_json_evidence(
        evidence,
        "state_history",
        "before-stop",
        &json!({
            "state": state,
            "durable_state_digest": digest_value(&durable_projection, "pre_stop_state")?,
            "history_digest": history_digest,
            "messages": history_value,
            "pages": history.responses,
        }),
        "pre_stop_evidence",
    )?;

    Ok(PersistedSnapshot {
        state,
        durable_projection,
        semantic_messages,
        history_digest,
        session_id,
        session_file,
    })
}

async fn exercise_resumed_session(
    driver: &mut RawRpcDriver,
    before: &PersistedSnapshot,
    evidence: &mut Vec<CaseEvidence>,
) -> CheckResult<()> {
    let state = get_state(driver, "resumed_state").await?;
    assert_idle_state(&state, "resumed_state")?;
    let history = page_all(driver, "resumed_history").await?;
    let projection = durable_state_projection(&state, "resumed_state")?;
    let semantic_messages = semantic_history_projection(&history.messages);
    let history_value = Value::Array(semantic_messages.clone());
    let history_digest = digest_value(&history_value, "resumed_history")?;
    let state_digest = digest_value(&projection, "resumed_state")?;
    let before_digest = digest_value(&before.durable_projection, "resumed_state")?;
    let session_id = required_state_string(&state, "sessionId", "resumed_state")?;
    let session_file = required_state_string(&state, "sessionFile", "resumed_state")?;
    // Both resume decisions run on the normalized projections: the durable
    // state folds disabled optional encodings onto one canonical form and
    // the history folds the assistant no-error `errorId` encodings onto the
    // absent form, so only real durable or history drift blocks continuity.
    let durable_matches = projection == before.durable_projection;
    let history_matches =
        semantic_messages == before.semantic_messages && history_digest == before.history_digest;
    let totals_match = history.total == before.semantic_messages.len()
        && state_message_count(&state, "resumed_state")? == before.semantic_messages.len();
    let changed_keys = changed_projection_keys(&before.durable_projection, &projection);
    let changed_messages = changed_history_messages(&before.semantic_messages, &semantic_messages);

    // Emitted before any mismatch return so every failed resume comparison
    // carries the full before/after states, both raw histories, the changed
    // durable keys, the changed-message detail, and all projection digests.
    push_json_evidence(
        evidence,
        "resume_comparison",
        "exact-state-and-history",
        &json!({
            "before_state": before.state,
            "after_state": state,
            "durable_projection": projection,
            "changed_durable_keys": changed_keys.clone(),
            "before_durable_state_digest": before_digest,
            "durable_state_digest": state_digest,
            "durable_state_matches": durable_matches,
            "before_history_digest": before.history_digest,
            "history_digest": history_digest,
            "history_matches": history_matches,
            "changed_messages": changed_messages.clone(),
            "before_messages": Value::Array(before.semantic_messages.clone()),
            "messages": history_value,
            "pages": history.responses,
        }),
        "resume_evidence",
    )?;

    if session_id != before.session_id {
        return Err(CaseCheck::new(
            "same_session",
            "resumed OMP session id changed",
        ));
    }
    if session_file != before.session_file {
        return Err(CaseCheck::new(
            "same_session",
            "resumed OMP session file changed",
        ));
    }
    if !durable_matches {
        return Err(CaseCheck::new(
            "state_digest",
            format!(
                "durable state changed across restart: before {before_digest}, \
                 after {state_digest}, changed keys [{}]",
                changed_keys.join(", ")
            ),
        ));
    }
    if !history_matches {
        return Err(CaseCheck::new(
            "history_digest",
            format!(
                "history changed across restart: before {}, after {history_digest}, \
                 changed messages [{}]",
                before.history_digest,
                changed_messages
                    .iter()
                    .map(|message| message.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if !totals_match {
        return Err(CaseCheck::new(
            "history_digest",
            "resumed state/history totals did not equal the persisted snapshot",
        ));
    }

    let continued_count = before.semantic_messages.len() + 2;
    let continued_state = prompt_and_wait(
        driver,
        "odin-mock:echo case-15-after-resume",
        continued_count,
        "resume_effect",
    )
    .await?;
    let continued = page_all(driver, "continued_history").await?;
    if continued.total != continued_count || continued.messages.len() != continued_count {
        return Err(CaseCheck::new(
            "resume_effect",
            format!(
                "continued session expected {continued_count} messages, returned {}/{}",
                continued.messages.len(),
                continued.total
            ),
        ));
    }
    let continued_semantic = semantic_history_projection(&continued.messages);
    if continued_semantic.get(..before.semantic_messages.len())
        != Some(before.semantic_messages.as_slice())
    {
        return Err(CaseCheck::new(
            "resume_effect",
            "continued history did not retain the pre-stop history as an exact semantic prefix",
        ));
    }
    let marker_count = continued
        .messages
        .iter()
        .filter(|message| value_contains(message, "case-15-after-resume"))
        .count();
    if marker_count != 2 {
        return Err(CaseCheck::new(
            "resume_effect",
            format!("continued turn marker appeared in {marker_count} messages instead of two"),
        ));
    }
    if state_message_count(&continued_state, "resume_effect")? != continued_count {
        return Err(CaseCheck::new(
            "resume_effect",
            "continued state total did not match the complete history",
        ));
    }

    let continued_value = Value::Array(continued_semantic.clone());
    push_json_evidence(
        evidence,
        "continuity",
        "one-turn-after-resume",
        &json!({
            "state": continued_state,
            "history_digest": digest_value(&continued_value, "continuity_evidence")?,
            "messages": continued_value,
            "pages": continued.responses,
        }),
        "continuity_evidence",
    )?;
    Ok(())
}

fn required_state_string(
    state: &Value,
    field: &'static str,
    check: &'static str,
) -> CheckResult<String> {
    state
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| CaseCheck::new(check, format!("state omitted non-empty `{field}`")))
}

fn assert_idle_state(state: &Value, check: &'static str) -> CheckResult<()> {
    if state.get("isStreaming").and_then(Value::as_bool) != Some(false)
        || state.get("isCompacting").and_then(Value::as_bool) != Some(false)
    {
        return Err(CaseCheck::new(check, "state was not idle"));
    }
    Ok(())
}

/// Build the explicit durable semantic projection of a `get_state` object:
/// exactly the [`DURABLE_STATE_FIELDS`] the pinned OMP host persists in the
/// session file and restores on resume. Compared byte-for-byte across the
/// cold restart. Optional fields (`thinkingLevel`, `sessionName`) project
/// their disabled encodings onto one canonical form — for `thinkingLevel`
/// the optional `ThinkingLevel` contract folds absent, null, and `"off"`
/// into canonical `"off"`, while `sessionName` keeps absent and null as
/// explicit null — so an encoding-only difference across the restart does
/// not fail case 15. Concrete non-disabled values keep their exact wire
/// encoding, so real configured drift still fails.
pub(super) fn durable_state_projection(state: &Value, check: &'static str) -> CheckResult<Value> {
    let object = state
        .as_object()
        .ok_or_else(|| CaseCheck::new(check, "state was not an object"))?;
    let mut projection = serde_json::Map::new();
    for field in DURABLE_STATE_FIELDS {
        let value = match object.get(*field) {
            Some(value) => value.clone(),
            None if OPTIONAL_STATE_FIELDS.contains(field) => Value::Null,
            None => continue,
        };
        projection.insert(
            (*field).to_owned(),
            canonical_optional_encoding(field, value),
        );
    }
    Ok(Value::Object(projection))
}

/// Project an optional field's wire value onto its canonical form. Under the
/// optional `ThinkingLevel` contract, absent, null, and the `"off"` level
/// are one disabled state: all three project to canonical
/// [`THINKING_LEVEL_OFF`]. Any concrete non-off level passes through
/// byte-for-byte, so configured thinking drift still fails. Every other
/// field's value is already canonical (absence was rewritten to null above).
fn canonical_optional_encoding(field: &str, value: Value) -> Value {
    if field == "thinkingLevel" && (value.is_null() || value.as_str() == Some(THINKING_LEVEL_OFF)) {
        return Value::String(THINKING_LEVEL_OFF.to_owned());
    }
    value
}

/// Keys whose durable projection values differ across the restart, sorted for
/// stable evidence and failure detail; computed on the normalized projection,
/// so only genuine value changes — including an absent optional field against
/// a concrete one — appear here.
pub(super) fn changed_projection_keys(before: &Value, after: &Value) -> Vec<String> {
    let empty = serde_json::Map::new();
    let before = before.as_object().unwrap_or(&empty);
    let after = after.as_object().unwrap_or(&empty);
    let mut keys: Vec<String> = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(key.as_str()) != after.get(key.as_str()))
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Build the explicit semantic projection of a paged history — the history
/// twin of [`durable_state_projection`] — used for every case-15 before/
/// after history equality, digest, total, and digest-bearing `messages`
/// evidence field; raw page responses preserve the wire evidence. Messages
/// are cloned in order,
/// and assistant `errorId` encodings of the one "no error" state are folded
/// onto the canonical absent form: the live mock provider serializes
/// assistant messages with `errorId: 0`, while the session-file reload
/// reports the same no-error state as an explicit null or an absent key.
/// Concrete nonzero error IDs and every other field of every message pass
/// through byte-exact — real history loss, reordering, or drift still
/// fails — and ordering and length are preserved.
pub(super) fn semantic_history_projection(messages: &[Value]) -> Vec<Value> {
    messages
        .iter()
        .map(|message| {
            let mut message = message.clone();
            if message.get("role").and_then(Value::as_str) == Some("assistant") {
                if let Some(object) = message.as_object_mut() {
                    let no_error = match object.get("errorId") {
                        Some(Value::Null) => true,
                        // Numeric zero — integer or float — is the same
                        // no-error state as the absent key the reload uses.
                        Some(Value::Number(number)) => number.as_f64() == Some(0.0),
                        _ => false,
                    };
                    if no_error {
                        object.remove("errorId");
                    }
                }
            }
            message
        })
        .collect()
}

/// Indices and changed keys where two semantic history projections differ,
/// ordered by index for stable evidence and failure detail; computed on the
/// normalized projections, so only genuine message drift — a dropped or
/// added entry, a changed role/content field, or a nonzero errorId
/// difference — appears here.
pub(super) fn changed_history_messages(before: &[Value], after: &[Value]) -> Vec<Value> {
    let mut changed = Vec::new();
    for index in 0..before.len().max(after.len()) {
        match (before.get(index), after.get(index)) {
            (Some(before_message), Some(after_message)) if before_message == after_message => {}
            (Some(before_message), Some(after_message)) => changed.push(json!({
                "index": index,
                "changed_keys": changed_projection_keys(before_message, after_message),
            })),
            (Some(_), None) => changed.push(json!({ "index": index, "only_in": "before" })),
            (None, Some(_)) => changed.push(json!({ "index": index, "only_in": "after" })),
            (None, None) => {}
        }
    }
    changed
}

fn validate_pin(source_revision: &str, executable: &Path, launch: &str) -> CheckResult<()> {
    if source_revision != PINNED_OMP_SOURCE_REVISION {
        return Err(CaseCheck::new(
            "exact_pin",
            format!("{launch} used source revision `{source_revision}`"),
        ));
    }
    if !executable.is_absolute() {
        return Err(CaseCheck::new(
            "exact_pin",
            format!(
                "{launch} executable was not canonical and absolute: `{}`",
                executable.display()
            ),
        ));
    }
    Ok(())
}

/// Detail for a failed exact-pin identity probe, telling a missing or
/// unusable executable apart from a missing launch working directory — both
/// surface as the same spawn ENOENT.
fn exact_pin_probe_failure(spec: &OmpProcessSpec, error: OmpProcessError) -> CaseCheck {
    CaseCheck::new(
        "exact_pin",
        format!(
            "identity probe failed: {error}; executable {}, cwd {}",
            describe_path(&spec.executable),
            describe_path(&spec.cwd),
        ),
    )
}

/// One-line existence/kind report for a launch path.
fn describe_path(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => format!("`{}` is a file", path.display()),
        Ok(metadata) if metadata.is_dir() => format!("`{}` is a directory", path.display()),
        Ok(_) => format!("`{}` is neither file nor directory", path.display()),
        Err(cause) => format!("`{}` is unusable: {cause}", path.display()),
    }
}

fn push_stop_evidence(
    evidence: &mut Vec<CaseEvidence>,
    label: &str,
    exit: &crate::process::OmpExitRecord,
) -> CheckResult<()> {
    push_json_evidence(
        evidence,
        "stop",
        label,
        &json!({
            "success": exit.success(),
            "code": exit.code(),
            "stderr_bytes": exit.stderr_tail().len(),
            "unfinished_frame": exit.unfinished_sequence().map(ToString::to_string),
        }),
        "stop_evidence",
    )
}
