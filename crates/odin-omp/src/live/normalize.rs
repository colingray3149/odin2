use std::sync::{Arc, Mutex};

use odin_domain::huginn::{
    LiveContentBlock, LiveError, LiveEventBody, LiveMessage, LiveSessionId, LiveSessionState,
    PermissionRequest, PermissionRequestId, SessionCloseReason, SessionClosed, SessionEpoch,
    SessionError, SessionResult, SessionStateChanged, TerminalDelta, TerminalDeltaRef,
    TerminalSnapshot, TerminalSnapshotRef, TextDelta, ToolFinished, ToolResultBlock, ToolStarted,
    ToolUseBlock,
};
use odin_domain::{ArtifactId, CapabilityId, Digest, TurnId};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::bridge::ObservedFrame;

use super::ledger::{live_error, BlobKind, BlobSource, LiveLedger, SessionBlob};

pub enum ProviderObservation {
    UserMessage(LiveMessage),
    AssistantMessage(LiveMessage),
    AssistantDelta { turn_id: TurnId, text: String },
    Result(SessionResult),
    Error(SessionError),
}

pub enum TerminalObservation {
    Snapshot(TerminalSnapshot),
    Delta(TerminalDelta),
}

struct NormalizerState {
    epoch: SessionEpoch,
    session_state: LiveSessionState,
    turn_result: TurnResult,
    stream: DeltaStream,
}

/// What one agent turn may still journal as its typed `Result`: an OMP
/// `prompt_result` and the terminal `agent_end` of the same turn never
/// yield two, and a failed provider turn yields none.
enum TurnResult {
    /// Nothing journaled yet.
    Open,
    /// The latest provider round (`turn_end`) stopped with `error`; this is
    /// the provider's own diagnostic and, when the frame carried one, its
    /// HTTP status. A round is not the turn: the loop may retry it in place,
    /// so the diagnostic stays private until the terminal `agent_end` types
    /// it, and a round that then ends otherwise reopens the turn. Text
    /// meanwhile is partial, never a result.
    ProviderError(ProviderRoundFault),
    /// The harness itself reported the turn stopped (a top-level `length`
    /// or `error`); its own report — a generic harness's `prompt_result`,
    /// carrying the failure and where the work was handed back — still
    /// journals once behind the failure.
    FailureReport,
    /// Journaled, or a failed provider turn.
    Closed,
}

/// One failed provider round, kept until the terminal frame types it.
struct ProviderRoundFault {
    message: String,
    error_status: Option<u16>,
}

/// The assistant's streamed text, journaled at most once per
/// [`DELTA_EVERY`] (each event is a journal append): a message's first
/// token at once, the rest coalesced, and the untold tail right before the
/// message itself, so a reader that skips the message after deltas loses
/// nothing.
#[derive(Default)]
struct DeltaStream {
    pending: String,
    last: Option<std::time::Instant>,
}

const DELTA_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

impl DeltaStream {
    fn push(&mut self, text: &str) -> Option<String> {
        self.pending.push_str(text);
        let now = std::time::Instant::now();
        if self
            .last
            .is_some_and(|last| now.duration_since(last) < DELTA_EVERY)
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.pending))
    }

    fn finish(&mut self) -> Option<String> {
        self.last = None;
        Some(std::mem::take(&mut self.pending)).filter(|tail| !tail.is_empty())
    }
}

impl NormalizerState {
    /// Failed, ended and paused sessions are settled: no late frame of the
    /// turn they settled reopens, re-types or answers them.
    fn settled(&self) -> bool {
        matches!(
            self.session_state,
            LiveSessionState::Failed | LiveSessionState::Ended | LiveSessionState::Detached
        )
    }

    /// OMP lifecycle observations are state-aware: a turn may only start from
    /// an active pre-turn state and only complete from an in-turn state, so a
    /// late `agent_end` after operator pause never drags the session back to
    /// `Idle`. Stale events are dropped without emitting a transition.
    fn lifecycle(
        &mut self,
        target: LiveSessionState,
        reason: Option<String>,
    ) -> Option<LiveEventBody> {
        let admitted = match target {
            LiveSessionState::Running => matches!(
                self.session_state,
                LiveSessionState::Starting | LiveSessionState::Idle
            ),
            LiveSessionState::Idle => matches!(
                self.session_state,
                LiveSessionState::Running | LiveSessionState::RequiresAction
            ),
            LiveSessionState::RequiresAction => matches!(
                self.session_state,
                LiveSessionState::Idle | LiveSessionState::Running
            ),
            _ => false,
        };
        if !admitted {
            return None;
        }
        let previous = self.session_state;
        self.session_state = target;
        Some(LiveEventBody::SessionStateChanged(SessionStateChanged {
            previous,
            current: target,
            reason,
        }))
    }
}

pub struct EventNormalizer {
    session_id: LiveSessionId,
    ledger: Arc<dyn LiveLedger>,
    state: Mutex<NormalizerState>,
}

impl EventNormalizer {
    pub fn new(
        session_id: LiveSessionId,
        epoch: SessionEpoch,
        state: LiveSessionState,
        ledger: Arc<dyn LiveLedger>,
    ) -> Self {
        Self {
            session_id,
            ledger,
            state: Mutex::new(NormalizerState {
                epoch,
                session_state: state,
                turn_result: TurnResult::Open,
                stream: DeltaStream::default(),
            }),
        }
    }

    /// A fresh incarnation (restart, recovery, rollover) has no turn in
    /// flight: nothing the previous one remembered decides its results.
    pub fn set_epoch(&self, epoch: SessionEpoch) -> Result<(), LiveError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        state.epoch = epoch;
        state.turn_result = TurnResult::Open;
        state.stream = DeltaStream::default();
        Ok(())
    }

    pub fn set_session_state(&self, session_state: LiveSessionState) -> Result<(), LiveError> {
        self.state.lock().map_err(|_| unavailable())?.session_state = session_state;
        Ok(())
    }

    pub fn normalize_omp(&self, frame: &ObservedFrame) -> Result<Vec<LiveEventBody>, LiveError> {
        let Some(value) = frame.value() else {
            return Ok(Vec::new());
        };
        let Some(kind) = value.get("type").and_then(Value::as_str) else {
            return Ok(Vec::new());
        };
        let body = match kind {
            // A provider/tool round is not the end of the agent loop.
            "agent_start" => {
                let mut state = self.state.lock().map_err(|_| unavailable())?;
                state.turn_result = TurnResult::Open;
                state.stream = DeltaStream::default();
                drop(state);
                self.transition(LiveSessionState::Running, None)?
            }
            // A terminal agent_end is only a successful settle when the
            // child says so: a failed provider round it ended on, or an
            // explicit unsuccessful stop reason (provider length limit,
            // error), means the turn ended WITHOUT a usable answer, and
            // journaling a plain Idle transition would be a misleading
            // idle success. The honest terminal is a typed error, then the
            // explicit Failed transition. A mid-loop frame (willContinue, or
            // isTerminal false) is not the end of the turn: settling Idle
            // there drops a turn the pinned harness is still running.
            "agent_end" => {
                if !crate::live::rollover::terminal_agent_end(value) {
                    None
                } else if let Some(failed) = self.failed_turn(value)? {
                    return Ok(failed);
                } else {
                    // The turn's typed completion result is its final
                    // answer (the delegated-task completion seam reads
                    // it): journaled before the settle, once per turn.
                    // A stale settle (after an operator pause) stays
                    // dropped, result included.
                    let Some(idle) = self.transition(LiveSessionState::Idle, None)? else {
                        return Ok(Vec::new());
                    };
                    let mut bodies = Vec::with_capacity(2);
                    bodies.extend(self.first_turn_result(final_answer(value))?);
                    bodies.push(idle);
                    return Ok(bodies);
                }
            }
            "message_update" => {
                let Some(delta) = text_delta(value) else {
                    return Ok(Vec::new());
                };
                let told = self
                    .state
                    .lock()
                    .map_err(|_| unavailable())?
                    .stream
                    .push(delta);
                match told {
                    Some(text) => Some(LiveEventBody::AssistantDelta(TextDelta {
                        turn_id: turn_id(value)?,
                        text,
                    })),
                    None => None,
                }
            }
            "message_end" => {
                let tail = self
                    .state
                    .lock()
                    .map_err(|_| unavailable())?
                    .stream
                    .finish();
                let Some((role, message)) = extract_message(value) else {
                    return Ok(Vec::new());
                };
                if role == "user" {
                    Some(LiveEventBody::UserMessage(message))
                } else {
                    let mut bodies = Vec::with_capacity(2);
                    if let Some(text) = tail {
                        bodies.push(LiveEventBody::AssistantDelta(TextDelta {
                            turn_id: turn_id(value)?,
                            text,
                        }));
                    }
                    bodies.push(LiveEventBody::AssistantMessage(message));
                    return Ok(bodies);
                }
            }
            // Classify only on the typed stopReason discriminant. The
            // round's outcome is remembered privately, not journaled: a
            // retried round may still answer, and the terminal agent_end
            // types the failure (even when message_end had no text).
            "turn_end" => {
                let failed =
                    value.pointer("/message/stopReason").and_then(Value::as_str) == Some("error");
                let message = value.get("message");
                let mut state = self.state.lock().map_err(|_| unavailable())?;
                let pending = matches!(state.turn_result, TurnResult::ProviderError(_));
                let open = pending || matches!(state.turn_result, TurnResult::Open);
                if !state.settled() {
                    if failed && open {
                        state.turn_result = TurnResult::ProviderError(ProviderRoundFault {
                            message: provider_diagnostic(message),
                            error_status: http_status(message),
                        });
                    } else if pending {
                        state.turn_result = TurnResult::Open;
                    }
                }
                None
            }
            "tool_execution_start" => Some(LiveEventBody::ToolStarted(ToolStarted {
                turn_id: turn_id(value)?,
                tool: ToolUseBlock {
                    tool_use_id: match string_field(value, &["toolCallId", "toolUseId", "id"]) {
                        Some(id) => id,
                        None => stable_label("tool-use", value)?,
                    },
                    capability_id: capability_id(value)?,
                    arguments: value
                        .get("args")
                        .or_else(|| value.get("arguments"))
                        .cloned()
                        .unwrap_or(Value::Null),
                },
            })),
            "tool_execution_end" => {
                let result = value
                    .get("result")
                    .or_else(|| value.get("content"))
                    .cloned()
                    .unwrap_or(Value::Null);
                Some(LiveEventBody::ToolFinished(ToolFinished {
                    turn_id: turn_id(value)?,
                    result: ToolResultBlock {
                        tool_use_id: match string_field(value, &["toolCallId", "toolUseId", "id"]) {
                            Some(id) => id,
                            None => stable_label("tool-use", value)?,
                        },
                        content: vec![LiveContentBlock::Text(value_text(&result)?)],
                        is_error: value
                            .get("isError")
                            .or_else(|| value.get("is_error"))
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    },
                }))
            }
            "extension_ui_request" => {
                let Some(body) = extension_ui_bodies(value)? else {
                    return Ok(Vec::new());
                };
                let asks_owner = matches!(body, LiveEventBody::PermissionRequested(_));
                let mut bodies = Vec::with_capacity(2);
                bodies.push(body);
                if asks_owner {
                    if let Some(waiting) =
                        self.transition(LiveSessionState::RequiresAction, None)?
                    {
                        bodies.push(waiting);
                    }
                }
                return Ok(bodies);
            }
            "prompt_result" => {
                let mut bodies = Vec::with_capacity(2);
                let summary = string_field(value, &["text", "summary", "result"]);
                // Pinned RPC reports local-only prompts without agent_end:
                // no agent turn can have journaled their result. A settled
                // session is not answered by a late one either.
                if value.get("agentInvoked").and_then(Value::as_bool) == Some(false) {
                    if self.state.lock().map_err(|_| unavailable())?.settled() {
                        return Ok(Vec::new());
                    }
                    bodies.push(LiveEventBody::Result(SessionResult {
                        summary,
                        artifacts: Vec::new(),
                    }));
                    if let Some(idle) = self.transition(LiveSessionState::Idle, None)? {
                        bodies.push(idle);
                    }
                } else if let Some(result) = self.first_turn_result(summary)? {
                    bodies.push(result);
                }
                return Ok(bodies);
            }
            "extension_error" => match &frame.journal_failure {
                Some(failure) => {
                    // The authenticated window_exceeded refusal names its retry
                    // path (compact or restart, then retry); every other typed
                    // failure repeats identically until reconfigured.
                    self.authenticated_failure(
                        failure,
                        failure.code == "context_refusal.window_exceeded",
                    )?
                }
                // Unauthenticated extension errors — any plugin, a
                // spoofed path, the wrong event, an unknown marker
                // code, or a malformed tail — stay generic: an honest
                // Uncertain, never a successful terminal and never a
                // typed refusal the bridge did not authenticate. The
                // journal settles Failed via this error; the state
                // follows so late frames cannot reopen it.
                None => {
                    self.set_session_state(LiveSessionState::Failed)?;
                    Some(LiveEventBody::Error(SessionError {
                        code: string_field(value, &["code"])
                            .unwrap_or_else(|| "omp_extension".to_owned()),
                        message: string_field(value, &["message", "error"])
                            .unwrap_or_else(|| "OMP extension error".to_owned()),
                        retryable: value
                            .get("retryable")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        error_status: None,
                    }))
                }
            },
            // The live control path dispatches prompts open-loop: the
            // correlated response arrives as a frame instead of an awaited
            // return value, so a rejection must surface here or it would be
            // silently lost to the session journal. The BRIDGE annotates a
            // response at the dispatch boundary — and only there — when
            // the rejection is correlated with a command of the current
            // binding whose waiter cannot receive it (the open-loop
            // prompt's dropped receiver, or a correlated mismatch); the
            // annotation carries the binding epoch. Those failures have no
            // other path and always journal typed here.
            //
            // An UNMATCHED response (no pending command — a stale or
            // duplicated frame, or a rejection from another incarnation)
            // carries no annotation and types NOTHING: no journal error,
            // no state change — however prompt-shaped its payload looks.
            // Raw payload matching must never substitute for the bridge's
            // correlation, or a stale rejection could fail a live session.
            // Successful responses (and rejections of still-awaited
            // commands, whose callers turn them into typed command
            // failures) stay out of the journal.
            "response" => {
                if let Some(failure) = &frame.journal_failure {
                    self.authenticated_failure(failure, true)?
                } else {
                    None
                }
            }
            "session_shutdown" => Some(LiveEventBody::SessionClosed(SessionClosed {
                reason: SessionCloseReason::Completed,
            })),
            _ => None,
        };
        Ok(body.into_iter().collect())
    }

    /// A bridge-authenticated failure. A stale-epoch annotation belongs to a
    /// previous incarnation: its durable observation stands, but it must not
    /// type this session's terminal. The journal settles Failed via this error;
    /// the normalizer's own state follows, so a late successful `agent_end`
    /// (the generic USER_INTERRUPT settle the pinned harness emits right after
    /// an aborted context refusal) can never reopen the failure with an Idle
    /// transition. `None` is a stale epoch: nothing is typed.
    fn authenticated_failure(
        &self,
        failure: &crate::bridge::TypedFrameFailure,
        retryable: bool,
    ) -> Result<Option<LiveEventBody>, LiveError> {
        let current = self.state.lock().map_err(|_| unavailable())?.epoch;
        if failure.epoch.is_some_and(|epoch| epoch != current) {
            return Ok(None);
        }
        self.set_session_state(LiveSessionState::Failed)?;
        Ok(Some(LiveEventBody::Error(SessionError {
            code: failure.code.clone(),
            message: failure.detail.clone(),
            retryable,
            error_status: None,
        })))
    }

    pub async fn normalize_terminal(
        &self,
        observation: TerminalObservation,
    ) -> Result<LiveEventBody, LiveError> {
        let epoch = self.state.lock().map_err(|_| unavailable())?.epoch;
        match observation {
            TerminalObservation::Snapshot(snapshot) => {
                snapshot.validate().map_err(invalid_domain)?;
                if snapshot.session_id != self.session_id || snapshot.epoch != epoch {
                    return Err(invalid("terminal_snapshot_binding"));
                }
                let bytes = super::ledger::encode_cbor(&snapshot).map_err(live_error)?;
                let blob = self
                    .ledger
                    .store_blob(BlobSource::Bytes(SessionBlob {
                        session_id: self.session_id,
                        epoch,
                        kind: BlobKind::Terminal,
                        bytes,
                    }))
                    .await
                    .map_err(live_error)?;
                let artifact_id = terminal_artifact_id("snapshot", &blob.digest)?;
                Ok(LiveEventBody::TerminalSnapshot(TerminalSnapshotRef {
                    session_id: self.session_id,
                    epoch,
                    sequence: snapshot.sequence,
                    columns: snapshot.columns,
                    rows: snapshot.rows,
                    artifact_id,
                    byte_len: blob.byte_len,
                    content_digest: blob.digest,
                }))
            }
            TerminalObservation::Delta(delta) => {
                delta.validate().map_err(invalid_domain)?;
                if delta.session_id != self.session_id || delta.epoch != epoch {
                    return Err(invalid("terminal_delta_binding"));
                }
                let bytes = super::ledger::encode_cbor(&delta).map_err(live_error)?;
                let blob = self
                    .ledger
                    .store_blob(BlobSource::Bytes(SessionBlob {
                        session_id: self.session_id,
                        epoch,
                        kind: BlobKind::Terminal,
                        bytes,
                    }))
                    .await
                    .map_err(live_error)?;
                let artifact_id = terminal_artifact_id("delta", &blob.digest)?;
                Ok(LiveEventBody::TerminalDelta(TerminalDeltaRef {
                    session_id: self.session_id,
                    epoch,
                    after: delta.after,
                    sequence: delta.sequence,
                    artifact_id,
                    byte_len: blob.byte_len,
                    content_digest: blob.digest,
                }))
            }
        }
    }

    fn transition(
        &self,
        current: LiveSessionState,
        reason: Option<String>,
    ) -> Result<Option<LiveEventBody>, LiveError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        Ok(state.lifecycle(current, reason))
    }
}

impl EventNormalizer {
    /// The failure of one terminal `agent_end`, or `None` when the turn did
    /// not fail. A turn that ended on a failed provider round (its pending
    /// `turn_end`, or the frame's own last assistant message) is the
    /// provider's `provider_turn_error` with the provider's diagnostic,
    /// which repeats as is; a turn the harness itself reports stopped is
    /// `turn_stopped_<reason>` with its `errorMessage`, and its own report
    /// still follows. Either is typed once, then the explicit `Failed`
    /// transition. Only an active turn fails: a late settle of a paused,
    /// ended, failed or already-settled turn types nothing — an intentional
    /// abort settles Idle before its aborted turn's frames arrive.
    fn failed_turn(&self, value: &Value) -> Result<Option<Vec<LiveEventBody>>, LiveError> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let nested = last_assistant(value)
            .filter(|message| message.get("stopReason").and_then(Value::as_str) == Some("error"));
        let provider =
            nested.is_some() || matches!(state.turn_result, TurnResult::ProviderError(_));
        let reason = unsuccessful_stop_reason(value);
        if !provider && reason.is_none() {
            return Ok(None);
        }
        if !matches!(
            state.session_state,
            LiveSessionState::Running | LiveSessionState::RequiresAction
        ) {
            return Ok(Some(Vec::new()));
        }
        let error = match reason.filter(|_| !provider) {
            None => {
                let (message, error_status) =
                    match std::mem::replace(&mut state.turn_result, TurnResult::Closed) {
                        TurnResult::ProviderError(fault) => (fault.message, fault.error_status),
                        _ => (provider_diagnostic(nested), http_status(nested)),
                    };
                SessionError {
                    code: "provider_turn_error".to_owned(),
                    message,
                    retryable: false,
                    error_status,
                }
            }
            Some(reason) => {
                state.turn_result = TurnResult::FailureReport;
                SessionError {
                    code: format!("turn_stopped_{reason}"),
                    message: string_field(value, &["errorMessage"]).unwrap_or_else(|| {
                        format!(
                            "the model turn stopped with reason '{reason}' without a usable \
                             final answer"
                        )
                    }),
                    retryable: true,
                    error_status: None,
                }
            }
        };
        let previous = state.session_state;
        state.session_state = LiveSessionState::Failed;
        Ok(Some(vec![
            LiveEventBody::Error(error),
            LiveEventBody::SessionStateChanged(SessionStateChanged {
                previous,
                current: LiveSessionState::Failed,
                reason: None,
            }),
        ]))
    }

    /// The turn's typed `Result` carrying `summary`, unless this turn
    /// already journaled one, its latest provider round failed (any text is
    /// partial), the session settled, or there is nothing to carry. A
    /// harness-reported failure's own report is the one result a failed
    /// session still takes.
    fn first_turn_result(
        &self,
        summary: Option<String>,
    ) -> Result<Option<LiveEventBody>, LiveError> {
        let Some(summary) = summary.filter(|text| !text.trim().is_empty()) else {
            return Ok(None);
        };
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        let admitted = match state.turn_result {
            TurnResult::Open => !state.settled(),
            TurnResult::FailureReport => state.session_state == LiveSessionState::Failed,
            TurnResult::ProviderError(_) | TurnResult::Closed => false,
        };
        if !admitted {
            return Ok(None);
        }
        state.turn_result = TurnResult::Closed;
        Ok(Some(LiveEventBody::Result(SessionResult {
            summary: Some(summary),
            artifacts: Vec::new(),
        })))
    }
}

/// The final answer of one terminal `agent_end`: the text of the last
/// assistant message the frame carries (thinking blocks are not words).
fn final_answer(value: &Value) -> Option<String> {
    let text = match last_assistant(value)?.get("content")? {
        Value::String(text) => text.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => return None,
    };
    Some(text)
}

/// The last assistant message one terminal `agent_end` carries.
fn last_assistant(value: &Value) -> Option<&Value> {
    value
        .get("messages")?
        .as_array()?
        .iter()
        .rev()
        .find(|message| message.get("role").and_then(Value::as_str) == Some("assistant"))
}

fn extract_message(value: &Value) -> Option<(&str, LiveMessage)> {
    let message = value.get("message").unwrap_or(value);
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("assistant");
    // tool_execution_end already records the tool result. It is not a
    // second assistant message when OMP also ends its toolResult message.
    if matches!(role, "tool" | "toolResult") {
        return None;
    }
    let content = message.get("content")?;
    let mut blocks = Vec::new();
    match content {
        Value::String(text) if !text.is_empty() => {
            blocks.push(LiveContentBlock::Text(text.clone()))
        }
        Value::Array(values) => {
            for block in values {
                if let Some(text) = block
                    .get("text")
                    .or_else(|| block.get("content"))
                    .and_then(Value::as_str)
                {
                    if !text.is_empty() {
                        blocks.push(LiveContentBlock::Text(text.to_owned()));
                    }
                }
            }
        }
        _ => {}
    }
    if blocks.is_empty() {
        None
    } else {
        Some((role, LiveMessage { content: blocks }))
    }
}

/// The text token of one OMP `message_update`
/// (`assistantMessageEvent: {type: "text_delta", delta}`); thinking and
/// tool-call deltas are not words to the owner.
fn text_delta(value: &Value) -> Option<&str> {
    let event = value.get("assistantMessageEvent")?;
    (event.get("type").and_then(Value::as_str) == Some("text_delta"))
        .then(|| event.get("delta").and_then(Value::as_str))
        .flatten()
        .filter(|delta| !delta.is_empty())
}

/// The explicit top-level stop reason of one terminal `agent_end` frame
/// when — and only when — it names an UNSUCCESSFUL stop: `length` (the
/// provider's own context limit cut the generation off) or `error`. Absent
/// and every other reason stay `None`: they are either historical
/// success-shaped frames or vocabulary this normalizer does not judge, and
/// both keep exactly the transition behavior they have always had. (A
/// failed last assistant message is the provider's failure, judged by
/// `failed_turn` exactly as `turn_end` classifies a provider round.)
fn unsuccessful_stop_reason(value: &Value) -> Option<&str> {
    value
        .get("stopReason")
        .or_else(|| value.get("stop_reason"))
        .or_else(|| value.get("finishReason"))
        .or_else(|| value.get("finish_reason"))
        .and_then(Value::as_str)
        .filter(|reason| matches!(*reason, "length" | "error"))
}

/// The provider's own diagnostic on one failed round's assistant message.
fn provider_diagnostic(message: Option<&Value>) -> String {
    message
        .and_then(|message| string_field(message, &["errorMessage"]))
        .unwrap_or_else(|| {
            "provider turn ended with stopReason error but no errorMessage".to_owned()
        })
}

/// The provider frame's typed `errorStatus`. A string that is the field
/// itself counts; digits inside the diagnostic text do not.
fn http_status(message: Option<&Value>) -> Option<u16> {
    let status = message?.get("errorStatus")?;
    status
        .as_u64()
        .and_then(|status| u16::try_from(status).ok())
        .or_else(|| status.as_str().and_then(|text| text.parse().ok()))
}

fn turn_id(value: &Value) -> Result<TurnId, LiveError> {
    if let Some(raw) = string_field(value, &["turnId", "turn_id"]) {
        if let Ok(id) = TurnId::new(raw) {
            return Ok(id);
        }
    }
    TurnId::new(stable_label("turn", value)?).map_err(invalid_domain)
}

fn capability_id(value: &Value) -> Result<CapabilityId, LiveError> {
    if let Some(raw) = string_field(value, &["capabilityId", "toolName", "tool", "method"]) {
        if let Ok(id) = CapabilityId::new(raw) {
            return Ok(id);
        }
    }
    CapabilityId::new(stable_label("capability", value)?).map_err(invalid_domain)
}

fn terminal_artifact_id(kind: &str, digest: &Digest) -> Result<ArtifactId, LiveError> {
    let hex = digest.to_string();
    ArtifactId::new(format!(
        "terminal:{kind}:{}",
        hex.strip_prefix("blake3:").unwrap_or(&hex)
    ))
    .map_err(invalid_domain)
}

fn stable_label(prefix: &str, value: &Value) -> Result<String, LiveError> {
    let bytes = serde_json::to_vec(value).map_err(invalid_domain)?;
    let digest = blake3::hash(&bytes).to_hex().to_string();
    Ok(format!("{prefix}:{}", &digest[..24]))
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| value.get(*name).and_then(Value::as_str))
        .map(str::to_owned)
}

fn value_text(value: &Value) -> Result<String, LiveError> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_owned());
    }
    serde_json::to_string(value).map_err(invalid_domain)
}

fn invalid(code: &str) -> LiveError {
    LiveError::InvalidRequest {
        code: code.to_owned(),
        message: "live observation is invalid".to_owned(),
    }
}

fn invalid_domain(error: impl std::fmt::Display) -> LiveError {
    LiveError::InvalidRequest {
        code: "invalid_observation".to_owned(),
        message: error.to_string(),
    }
}

fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "event_normalizer".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_results_are_not_repeated_as_assistant_messages() {
        let mut frame = serde_json::json!({"message":{"role":"toolResult","content":[{"type":"text","text":"tool output"}]}});
        assert!(extract_message(&frame).is_none());
        frame["message"]["role"] = serde_json::json!("assistant");
        assert!(extract_message(&frame).is_some());
    }

    fn state(session_state: LiveSessionState) -> NormalizerState {
        NormalizerState {
            stream: DeltaStream::default(),
            turn_result: TurnResult::Open,
            epoch: SessionEpoch::new(1),
            session_state,
        }
    }

    fn start(session: &mut NormalizerState) -> Option<SessionStateChanged> {
        match session.lifecycle(LiveSessionState::Running, None) {
            Some(LiveEventBody::SessionStateChanged(event)) => Some(event),
            Some(body) => panic!("start emitted unexpected body {body:?}"),
            None => None,
        }
    }

    fn end(session: &mut NormalizerState) -> Option<SessionStateChanged> {
        match session.lifecycle(LiveSessionState::Idle, None) {
            Some(LiveEventBody::SessionStateChanged(event)) => Some(event),
            Some(body) => panic!("end emitted unexpected body {body:?}"),
            None => None,
        }
    }

    mod stop_reason_terminal_honesty {
        use super::*;
        use crate::live::ledger::fs::FsLiveLedger;

        /// The tempdir stays bound in the caller for the normalizer's
        /// lifetime; agent_end normalization never reads the ledger, but
        /// the handle must not lose its directory underneath it.
        fn normalizer(session_state: LiveSessionState) -> (EventNormalizer, tempfile::TempDir) {
            let root = tempfile::tempdir().expect("tempdir");
            let ledger = FsLiveLedger::open(root.path()).expect("ledger opens");
            (
                EventNormalizer::new(
                    LiveSessionId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
                    SessionEpoch::new(1),
                    session_state,
                    std::sync::Arc::new(ledger),
                ),
                root,
            )
        }

        fn frame(raw: &str) -> crate::bridge::ObservedFrame {
            let line = format!("{raw}\n");
            let decoded = crate::frames::RpcFrameDecoder::default()
                .push_physical_line(line.as_bytes())
                .unwrap()
                .unwrap();
            crate::bridge::ObservedFrame {
                class: crate::bridge::classify_frame(decoded.value()),
                decoded: Some(decoded),
                rejection: None,
                active_command: None,
                journal_failure: None,
            }
        }

        /// The bounded-turn defect: a terminal agent_end that names the
        /// provider's own context limit is NOT a successful settle.
        /// Journaling Idle would be a misleading idle success — the honest
        /// terminal is a typed error, then the explicit Failed transition.
        #[test]
        fn terminal_agent_end_with_length_stop_is_a_typed_error_not_idle() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let bodies = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"length"}"#))
                .expect("agent_end normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error), LiveEventBody::SessionStateChanged(failed)] => {
                    assert_eq!(error.code, "turn_stopped_length");
                    assert!(error.retryable, "a length-stopped turn can be retried");
                    assert_eq!(failed.current, LiveSessionState::Failed);
                }
                other => panic!("a length-stopped turn must not settle successfully: {other:?}"),
            }
            // A late successful agent_end can never reopen the failure:
            // the normalizer state followed the error to Failed.
            let late = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("late agent_end normalizes");
            assert!(
                late.is_empty(),
                "a terminal state is never reopened by a late settle: {late:?}"
            );
        }

        /// Terminal messages include thinking and answer blocks without a preceding `prompt_result`.
        const RECORDED_AGENT_END: &str = r#"{"type":"agent_end","isTerminal":true,"messages":[{"attribution":"user","content":[{"type":"text","text":"Start exactly one heat-sim pod."}],"role":"user","timestamp":1791145586104},{"content":[{"type":"text","text":"{\"kind\":\"routine\"}"}],"isError":false,"role":"toolResult","timestamp":1791145630333,"toolCallId":"wwywUnnU6lZCCeGWebndSJMXCgwk0Y5Q","toolName":"registry_read"},{"api":"openai-completions","content":[{"thinking":"Let me report the result concisely.","thinkingSignature":"reasoning_content","type":"thinking"},{"text":"heat-sim launched and completed successfully.","type":"text"}],"model":"kubert-mini","provider":"gateway","role":"assistant","stopReason":"stop","timestamp":1791145630356}]}"#;

        #[test]
        fn a_recorded_agent_end_journals_the_final_answer_as_the_turn_result() {
            let (normalizer, _root) = normalizer(LiveSessionState::Idle);
            normalizer
                .normalize_omp(&frame(r#"{"type":"agent_start"}"#))
                .expect("agent_start normalizes");
            let bodies = normalizer
                .normalize_omp(&frame(RECORDED_AGENT_END))
                .expect("agent_end normalizes");
            match &bodies[..] {
                [LiveEventBody::Result(result), LiveEventBody::SessionStateChanged(idle)] => {
                    assert_eq!(
                        result.summary.as_deref(),
                        Some("heat-sim launched and completed successfully."),
                        "the answer, without the thinking block"
                    );
                    assert_eq!(idle.current, LiveSessionState::Idle);
                }
                other => panic!("the final answer, then the settle: {other:?}"),
            }
            // A prompt_result of the same turn arriving late adds nothing.
            let late = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"prompt_result","text":"heat-sim launched and completed successfully."}"#,
                ))
                .expect("prompt_result normalizes");
            assert!(late.is_empty(), "one Result per turn: {late:?}");

            // The other order: prompt_result first, then agent_end.
            normalizer
                .normalize_omp(&frame(r#"{"type":"agent_start"}"#))
                .expect("agent_start normalizes");
            let first = normalizer
                .normalize_omp(&frame(r#"{"type":"prompt_result","text":"second answer"}"#))
                .expect("prompt_result normalizes");
            assert!(
                matches!(&first[..], [LiveEventBody::Result(result)]
                    if result.summary.as_deref() == Some("second answer")),
                "{first:?}"
            );
            let settled = normalizer
                .normalize_omp(&frame(RECORDED_AGENT_END))
                .expect("agent_end normalizes");
            assert!(
                matches!(&settled[..], [LiveEventBody::SessionStateChanged(idle)]
                    if idle.current == LiveSessionState::Idle),
                "no second Result: {settled:?}"
            );

            // A local-only prompt (no agent turn) still reports its result.
            let local = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"prompt_result","agentInvoked":false,"text":"local"}"#,
                ))
                .expect("prompt_result normalizes");
            assert!(
                matches!(&local[..], [LiveEventBody::Result(result)]
                    if result.summary.as_deref() == Some("local")),
                "{local:?}"
            );
        }

        #[test]
        fn terminal_agent_end_with_error_stop_is_a_typed_error_not_idle() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let bodies = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stop_reason":"error"}"#))
                .expect("agent_end normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error), LiveEventBody::SessionStateChanged(failed)] => {
                    assert_eq!(error.code, "turn_stopped_error");
                    assert_eq!(failed.current, LiveSessionState::Failed);
                }
                other => panic!("an error-stopped turn must journal a typed error: {other:?}"),
            }
        }

        /// The recorded failed provider turn's terminal (sanitized): no
        /// top-level reason; its last assistant message carries
        /// `stopReason: error` and partial text.
        const FAILED_AGENT_END: &str = r#"{"type":"agent_end","isTerminal":true,"yielded":true,"messages":[{"role":"user","content":[{"type":"text","text":"Perform one bounded task."}]},{"role":"assistant","stopReason":"error","errorStatus":500,"errorMessage":"upstream API connection failed","content":[{"type":"text","text":"Partial answer from a failed request."}]}]}"#;

        /// A failed terminal after an operator pause is stale like any
        /// other late settle: the paused state is kept, nothing is typed.
        #[test]
        fn failed_terminal_after_pause_types_nothing() {
            let (normalizer, _root) = normalizer(LiveSessionState::Detached);
            let bodies = normalizer
                .normalize_omp(&frame(FAILED_AGENT_END))
                .expect("agent_end normalizes");
            assert!(bodies.is_empty(), "{bodies:?}");
        }

        /// Absent and successful stop reasons keep exactly the historical
        /// behavior: a plain Idle transition.
        #[test]
        fn terminal_agent_end_without_unsuccessful_stop_settles_idle() {
            for raw in [
                r#"{"type":"agent_end"}"#,
                r#"{"type":"agent_end","stopReason":"stop"}"#,
            ] {
                let (normalizer, _root) = normalizer(LiveSessionState::Running);
                let bodies = normalizer
                    .normalize_omp(&frame(raw))
                    .expect("agent_end normalizes");
                assert!(
                    matches!(
                        &bodies[..],
                        [LiveEventBody::SessionStateChanged(change)]
                            if change.current == LiveSessionState::Idle
                    ),
                    "a successful settle keeps the Idle transition: {bodies:?}"
                );
            }
        }

        /// An UNMATCHED rejected prompt response — no bridge annotation,
        /// no correlation — types NOTHING: the bridge alone decides, at
        /// the dispatch boundary, which rejections type a terminal. Raw
        /// payload matching would let a stale or duplicated rejection
        /// fail a live session.
        #[test]
        fn unannotated_rejected_prompt_response_types_nothing() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let bodies = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"response","id":"wire-1","command":"prompt","success":false,"code":"over_budget","error":"provider refused the turn"}"#,
                ))
                .expect("response normalizes");
            assert!(
                bodies.is_empty(),
                "an unannotated rejection is evidence only: {bodies:?}"
            );
            // The state was untouched: the turn's own lifecycle continues.
            let settle = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("agent_end normalizes");
            assert!(
                matches!(
                    &settle[..],
                    [LiveEventBody::SessionStateChanged(change)]
                        if change.current == LiveSessionState::Idle
                ),
                "an unannotated rejection never poisons the turn lifecycle: {settle:?}"
            );
        }

        /// The bridge-annotated open-loop prompt rejection (the dispatch
        /// boundary's correlated Observed rejection, carrying the binding
        /// epoch) journals the typed error — never silently lost with the
        /// dropped waiter — and settles Failed against a late reopen.
        #[test]
        fn bridge_annotated_prompt_rejection_is_a_typed_error_not_silence() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let diagnostic = "correlated provider refusal: declared lane usage limit";
            let mut observed = frame(
                r#"{"type":"response","id":"wire-1","command":"prompt","success":false,"code":"over_budget","error":"provider refused the turn"}"#,
            );
            observed.journal_failure = Some(crate::bridge::TypedFrameFailure {
                code: "prompt_rejected".to_owned(),
                detail: diagnostic.to_owned(),
                epoch: Some(SessionEpoch::new(1)),
            });
            let bodies = normalizer
                .normalize_omp(&observed)
                .expect("annotated rejection normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error)] => {
                    assert_eq!(error.code, "prompt_rejected");
                    assert_eq!(
                        error.message, diagnostic,
                        "correlated detail wins over raw payload"
                    );
                    assert!(error.retryable, "a rejected prompt can be retried");
                }
                other => panic!("an annotated rejection must journal a typed error: {other:?}"),
            }
            // The failure settles the session Failed; the normalizer's
            // own state followed, so a late successful agent_end of the
            // original turn can never reopen the failure with an Idle
            // transition.
            let late = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("late agent_end normalizes");
            assert!(
                late.is_empty(),
                "a correlated rejection is never reopened by a late settle: {late:?}"
            );
        }

        /// A correlated response mismatch whose waiter was dropped at the
        /// open-loop dispatch is annotated by the bridge; the normalizer
        /// must journal the typed failure — without the annotation it is
        /// silently lost to the session journal.
        #[test]
        fn orphaned_correlated_mismatch_is_a_typed_error_not_silence() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let diagnostic = "response/command mismatch: expected `prompt`, got `steer`";
            let mut observed = frame(
                r#"{"type":"response","id":"wire-1","command":"steer","success":true,"data":{}}"#,
            );
            observed.journal_failure = Some(crate::bridge::TypedFrameFailure {
                code: "response_mismatch".to_owned(),
                detail: diagnostic.to_owned(),
                epoch: Some(SessionEpoch::new(1)),
            });
            let bodies = normalizer
                .normalize_omp(&observed)
                .expect("annotated response normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error)] => {
                    assert_eq!(error.code, "response_mismatch");
                    assert_eq!(error.message, diagnostic);
                    assert!(error.retryable, "a mismatched response can be retried");
                }
                other => panic!("an orphaned mismatch must journal a typed error: {other:?}"),
            }
            // The failure settles Failed and stays settled: late original
            // turn frames cannot reopen it.
            let late = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("late agent_end normalizes");
            assert!(
                late.is_empty(),
                "an orphaned mismatch failure is never reopened by a late settle: {late:?}"
            );
        }

        /// The bridge-authenticated context refusal (the strict marker
        /// schema, trusted extension identity, pinned event, and a live
        /// turn anchor verified host-side at the bridge) journals the
        /// typed terminal and settles Failed, so the USER_INTERRUPT
        /// agent_end the pinned harness emits right after the abort
        /// cannot reopen the failure.
        #[test]
        fn authenticated_context_refusal_is_a_typed_terminal_not_silence() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let diagnostic = "measured 9000 + input 2500 + reserve 500 = 12000 exceeds the declared window 10000";
            let mut observed = frame(
                r#"{"type":"extension_error","extensionPath":"/nix/store/trusted-odin-extension/index.ts","event":"before_provider_request","error":"odin.context_refusal.v1|{...}"}"#,
            );
            observed.journal_failure = Some(crate::bridge::TypedFrameFailure {
                code: "context_refusal.window_exceeded".to_owned(),
                detail: diagnostic.to_owned(),
                epoch: Some(SessionEpoch::new(1)),
            });
            let bodies = normalizer
                .normalize_omp(&observed)
                .expect("authenticated refusal normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error)] => {
                    assert_eq!(error.code, "context_refusal.window_exceeded");
                    assert_eq!(
                        error.message, diagnostic,
                        "authenticated detail wins over marker text"
                    );
                    assert!(error.retryable, "window_exceeded names its retry path");
                }
                other => panic!("a typed refusal must journal a typed error: {other:?}"),
            }
            // The aborted turn's generic USER_INTERRUPT settle arrives
            // late and must not reopen the failure.
            let late = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("late agent_end normalizes");
            assert!(
                late.is_empty(),
                "a refusal terminal is never reopened by the abort's late settle: {late:?}"
            );
        }

        /// A marker-looking extension_error WITHOUT the bridge's
        /// authentication — wrong path, wrong event, unknown code,
        /// malformed tail, or no live turn anchor — is an unauthenticated
        /// frame: the generic honest Uncertain, preserving the raw error
        /// string verbatim, never a typed refusal and never a successful
        /// terminal. Other authenticated refusal codes are not retryable.
        #[test]
        fn unauthenticated_marker_stays_generic_and_config_refusals_fail_closed() {
            let (first, _first_root) = normalizer(LiveSessionState::Running);
            let raw = concat!(
                r#"{"type":"extension_error","extensionPath":"/ext/odin.ts","#,
                r#""event":"before_provider_request","error":"odin.context_refusal.v1|"#,
                r#"{\"code\":\"window_exceeded\",\"reason\":\"spoofed\"}"}"#,
            );
            let untrusted: serde_json::Value = serde_json::from_str(raw).expect("wire frame");
            let bodies = first
                .normalize_omp(&frame(raw))
                .expect("unauthenticated frame normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error)] => {
                    assert_eq!(
                        error.code, "omp_extension",
                        "no annotation, no typed refusal: {error:?}"
                    );
                    assert_eq!(
                        error.message,
                        untrusted["error"].as_str().expect("raw diagnostic")
                    );
                }
                other => panic!("an unauthenticated marker stays a generic error: {other:?}"),
            }
            // The generic failure settles Failed too; late frames cannot
            // reopen it.
            let late = first
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("late agent_end normalizes");
            assert!(
                late.is_empty(),
                "a generic extension failure is never reopened by a late settle: {late:?}"
            );

            let (guard, _guard_root) = normalizer(LiveSessionState::Running);
            let mut observed = frame(
                r#"{"type":"extension_error","extensionPath":"/nix/store/trusted-odin-extension/index.ts","event":"before_provider_request","error":"odin.context_refusal.v1|{...}"}"#,
            );
            observed.journal_failure = Some(crate::bridge::TypedFrameFailure {
                code: "context_refusal.model_identity_mismatch".to_owned(),
                detail: "seat declares serving model a but this session admits b".to_owned(),
                epoch: Some(SessionEpoch::new(1)),
            });
            let bodies = guard
                .normalize_omp(&observed)
                .expect("authenticated refusal normalizes");
            match &bodies[..] {
                [LiveEventBody::Error(error)] => {
                    assert_eq!(error.code, "context_refusal.model_identity_mismatch");
                    assert!(
                        !error.retryable,
                        "a declaration failure repeats identically until reconfigured"
                    );
                }
                other => panic!("a config refusal must journal a typed error: {other:?}"),
            }
        }

        /// A stale-epoch annotation belongs to a previous incarnation:
        /// the durable observation stands, but it types NOTHING in this
        /// session — no error body, and the normalizer's state stays
        /// untouched, so the turn's own lifecycle continues normally.
        #[test]
        fn stale_epoch_refusal_types_nothing_and_leaves_state_untouched() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let mut observed = frame(
                r#"{"type":"extension_error","extensionPath":"/nix/store/trusted-odin-extension/index.ts","event":"before_provider_request","error":"odin.context_refusal.v1|{...}"}"#,
            );
            observed.journal_failure = Some(crate::bridge::TypedFrameFailure {
                code: "context_refusal.window_exceeded".to_owned(),
                detail: "stale incarnation's refusal".to_owned(),
                epoch: Some(SessionEpoch::new(2)),
            });
            let bodies = normalizer
                .normalize_omp(&observed)
                .expect("stale refusal normalizes");
            assert!(
                bodies.is_empty(),
                "a stale-epoch annotation types nothing: {bodies:?}"
            );
            // The state was untouched: the turn settles normally.
            let settle = normalizer
                .normalize_omp(&frame(r#"{"type":"agent_end","stopReason":"stop"}"#))
                .expect("agent_end normalizes");
            assert!(
                matches!(
                    &settle[..],
                    [LiveEventBody::SessionStateChanged(change)]
                        if change.current == LiveSessionState::Idle
                ),
                "an un-typed stale refusal never poisons the turn lifecycle: {settle:?}"
            );
        }

        /// Successful prompt responses, unannotated rejected prompt
        /// responses (unmatched or stale — the bridge never annotated
        /// them), and rejections of commands whose callers still await
        /// the response stay out of the session journal (they surface
        /// through their own paths, or type nothing at all).
        #[test]
        fn successful_or_awaited_responses_stay_out_of_the_journal() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            for raw in [
                r#"{"type":"response","id":"wire-1","command":"prompt","success":true,"data":{}}"#,
                r#"{"type":"response","id":"wire-2","command":"steer","success":false,"error":"not steering"}"#,
                r#"{"type":"response","id":"wire-3","command":"prompt","success":false,"error":"stale rejection"}"#,
            ] {
                let bodies = normalizer
                    .normalize_omp(&frame(raw))
                    .expect("response normalizes");
                assert!(
                    bodies.is_empty(),
                    "non-rejected prompt responses and awaited-command rejections stay silent: {bodies:?}"
                );
            }
        }

        /// Emit the first delta immediately and flush coalesced tails before the message.
        #[test]
        fn omp_text_deltas_stream_coalesced_and_spell_the_whole_message() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let update = |kind: &str, delta: &str| {
                frame(&format!(
                    r#"{{"type":"message_update","message":{{"role":"assistant","content":[]}},"assistantMessageEvent":{{"type":"{kind}","contentIndex":0,"delta":"{delta}"}}}}"#
                ))
            };
            let mut told = String::new();
            let mut events = 0;
            for (kind, delta) in [
                ("thinking_delta", "hmm"),
                ("text_delta", "Oolong "),
                ("text_delta", "is "),
                ("text_delta", "a "),
                ("text_delta", "tea."),
            ] {
                for body in normalizer.normalize_omp(&update(kind, delta)).unwrap() {
                    let LiveEventBody::AssistantDelta(delta) = body else {
                        panic!("a token is only ever a delta: {body:?}");
                    };
                    told.push_str(&delta.text);
                    events += 1;
                }
            }
            assert_eq!(
                (told.as_str(), events),
                ("Oolong ", 1),
                "first token at once"
            );
            let end = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"message_end","message":{"role":"assistant","content":[{"type":"text","text":"Oolong is a tea."}]}}"#,
                ))
                .unwrap();
            match &end[..] {
                [LiveEventBody::AssistantDelta(tail), LiveEventBody::AssistantMessage(_)] => {
                    told.push_str(&tail.text);
                }
                other => panic!("the tail precedes the message: {other:?}"),
            }
            assert_eq!(told, "Oolong is a tea.");
            let next = normalizer
                .normalize_omp(&update("text_delta", "Next"))
                .unwrap();
            assert!(
                matches!(&next[..], [LiveEventBody::AssistantDelta(delta)] if delta.text == "Next"),
                "the next message's first token goes at once: {next:?}"
            );
        }

        #[test]
        fn a_mid_loop_agent_end_does_not_settle_and_the_true_end_still_does() {
            let (normalizer, _root) = normalizer(LiveSessionState::Running);
            let continued = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"agent_end","isTerminal":false,"willContinue":true,"stopReason":"length"}"#,
                ))
                .expect("agent_end normalizes");
            assert!(
                continued.is_empty(),
                "a continuation is not the end of the turn: {continued:?}"
            );
            let settled = normalizer
                .normalize_omp(&frame(
                    r#"{"type":"agent_end","isTerminal":true,"stopReason":"stop"}"#,
                ))
                .expect("the true end normalizes");
            assert!(
                matches!(
                    &settled[..],
                    [LiveEventBody::SessionStateChanged(change)]
                        if change.current == LiveSessionState::Idle
                ),
                "only the true end settles: {settled:?}"
            );
        }
    }

    #[test]
    fn start_enters_running_from_active_pre_turn_states() {
        for pre_turn in [LiveSessionState::Starting, LiveSessionState::Idle] {
            let mut session = state(pre_turn);
            let event = start(&mut session).expect("start must transition");
            assert_eq!(event.previous, pre_turn);
            assert_eq!(event.current, LiveSessionState::Running);
            assert_eq!(session.session_state, LiveSessionState::Running);
        }
    }

    #[test]
    fn running_to_idle_completion_emits_transition() {
        let mut session = state(LiveSessionState::Running);
        let event = end(&mut session).expect("end must transition");
        assert_eq!(event.previous, LiveSessionState::Running);
        assert_eq!(event.current, LiveSessionState::Idle);
        assert_eq!(session.session_state, LiveSessionState::Idle);
    }

    #[test]
    fn late_end_after_pause_leaves_session_detached() {
        let mut session = state(LiveSessionState::Idle);
        start(&mut session).expect("turn must start");
        session.session_state = LiveSessionState::Detached;
        assert!(end(&mut session).is_none());
        assert!(start(&mut session).is_none());
        assert_eq!(session.session_state, LiveSessionState::Detached);
    }

    #[test]
    fn lifecycle_matrix_admits_only_valid_sources() {
        let states = [
            LiveSessionState::Starting,
            LiveSessionState::Idle,
            LiveSessionState::Running,
            LiveSessionState::RequiresAction,
            LiveSessionState::Aborting,
            LiveSessionState::Ended,
            LiveSessionState::Failed,
            LiveSessionState::Detached,
        ];
        for current in states {
            let start_admitted =
                matches!(current, LiveSessionState::Starting | LiveSessionState::Idle);
            let end_admitted = matches!(
                current,
                LiveSessionState::Running | LiveSessionState::RequiresAction
            );

            let mut session = state(current);
            assert_eq!(
                start(&mut session).is_some(),
                start_admitted,
                "start admission from {current:?}"
            );
            let after_start = if start_admitted {
                LiveSessionState::Running
            } else {
                current
            };
            assert_eq!(session.session_state, after_start);

            let mut session = state(current);
            assert_eq!(
                end(&mut session).is_some(),
                end_admitted,
                "end admission from {current:?}"
            );
            let after_end = if end_admitted {
                LiveSessionState::Idle
            } else {
                current
            };
            assert_eq!(session.session_state, after_end);
        }
    }
}

/// Boolean confirmations have an exact answer in the live control protocol.
/// Text/choice dialogs are cancelled by the bridge and reported as unsupported,
/// rather than pretending that allow-once supplies a text value. Notifications
/// never become permission requests.
fn extension_ui_bodies(value: &Value) -> Result<Option<LiveEventBody>, LiveError> {
    let method = string_field(value, &["method"]).unwrap_or_default();
    if !matches!(method.as_str(), "select" | "confirm" | "input" | "editor") {
        return Ok(None);
    }
    let request_id = PermissionRequestId::new(
        string_field(value, &["id"]).ok_or_else(|| invalid("permission_request_id"))?,
    )
    .map_err(invalid_domain)?;
    if method != "confirm" {
        return Ok(Some(LiveEventBody::Error(SessionError {
            code: "unsupported_extension_dialog".to_owned(),
            message: format!(
                "The {method} dialog requires a text or choice response and was cancelled."
            ),
            retryable: false,
            error_status: None,
        })));
    }
    let bytes = serde_json::to_vec(value).map_err(|_| invalid("permission_args"))?;
    Ok(Some(LiveEventBody::PermissionRequested(
        PermissionRequest {
            request_id,
            tool_use_id: match string_field(value, &["toolCallId", "id"]) {
                Some(id) => id,
                None => stable_label("tool-use", value)?,
            },
            capability_id: capability_id(value)?,
            arguments_digest: Digest::hash(&bytes),
            prompt: string_field(value, &["title", "message", "method"])
                .unwrap_or_else(|| "Operator decision required".to_owned()),
            expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        },
    )))
}

#[cfg(test)]
mod extension_ui_tests {
    use super::*;

    #[test]
    fn fire_and_forget_extension_ui_is_never_a_permission_request() {
        // The live incident: the autoresearch dashboard's widget update
        // reached the owner as an unanswerable "Approval needed" prompt.
        for method in [
            "setWidget",
            "setStatus",
            "notify",
            "setTitle",
            "set_editor_text",
            "open_url",
        ] {
            let frame = serde_json::json!({
                "type": "extension_ui_request",
                "id": "1582482492c8d907",
                "method": method,
                "widgetKey": "autoresearch",
            });
            assert!(
                extension_ui_bodies(&frame)
                    .expect("triage succeeds")
                    .is_none(),
                "{method} must not become a permission request"
            );
        }
    }

    #[test]
    fn only_boolean_dialogs_offer_allow_once() {
        let confirmation = serde_json::json!({
            "type": "extension_ui_request", "id": "ui-dialog-1",
            "method": "confirm", "title": "confirm action",
        });
        assert!(matches!(
            extension_ui_bodies(&confirmation).unwrap(),
            Some(LiveEventBody::PermissionRequested(_))
        ));
        for method in ["select", "input", "editor"] {
            let mut unsupported = confirmation.clone();
            unsupported["method"] = serde_json::json!(method);
            assert!(matches!(
                extension_ui_bodies(&unsupported).unwrap(),
                Some(LiveEventBody::Error(_))
            ));
        }
    }

    #[test]
    fn malformed_decision_dialog_fails_typed() {
        let frame = serde_json::json!({
            "type": "extension_ui_request",
            "id": "",
            "method": "input",
        });
        assert!(extension_ui_bodies(&frame).is_err());
    }
}
