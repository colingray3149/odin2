//! The single frame-observation vocabulary: classification of every
//! child frame and the exact-bytes evidence object built from it.

use super::*;

/// Classification of one observed child frame.
///
/// The split is structural and stable: the pinned protocol discriminants are
/// named explicitly, the exact pinned session-event vocabulary is
/// [`FrameClass::Session`] (it grows only with the pinned harness, which owns its
/// normalization), and every other frame — an unrecognized string `type`, a
/// missing `type`, or a non-string `type` — is [`FrameClass::Unknown`], so a
/// future frame can never masquerade as a session event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameClass {
    /// The startup `ready` frame (consumed by the process boundary; retained
    /// here for evidence consumers).
    Ready,
    /// A command response, correlated by id and verified against the expected
    /// command name.
    Response,
    /// A frame carrying one of the exact pinned session-event discriminants
    /// (omp @ `eab72e8`): the agent/turn/message/tool lifecycles, compaction,
    /// retry and fallback, and the ttsr/todo/irc/notice/thinking/model/
    /// advisor/goal/session-shutdown notifications.
    Session,
    /// `subagent_lifecycle`, `subagent_progress`, or `subagent_event`.
    Subagent,
    /// `available_commands_update`.
    AvailableCommands,
    /// `extension_ui_request`.
    ExtensionUi,
    /// `host_tool_call` or `host_tool_cancel`.
    HostTool,
    /// `host_uri_request` or `host_uri_cancel`.
    HostUri,
    /// `prompt_result`.
    PromptResult,
    /// `command_output`.
    CommandOutput,
    /// `session_info_update`.
    SessionInfo,
    /// `config_update`.
    ConfigUpdate,
    /// `extension_error`.
    ExtensionError,
    /// A physical frame that never decoded; the observation carries the exact
    /// rejection evidence instead of a decoded value.
    RpcFrameError,
    /// A decodable object whose string `type` discriminant is outside the
    /// pinned vocabulary, or without a usable string `type` at all.
    Unknown,
}

impl FrameClass {
    /// Stable snake-case name used as the live-event `kind`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Response => "response",
            Self::Session => "session",
            Self::Subagent => "subagent",
            Self::AvailableCommands => "available_commands",
            Self::ExtensionUi => "extension_ui",
            Self::HostTool => "host_tool",
            Self::HostUri => "host_uri",
            Self::PromptResult => "prompt_result",
            Self::CommandOutput => "command_output",
            Self::SessionInfo => "session_info",
            Self::ConfigUpdate => "config_update",
            Self::ExtensionError => "extension_error",
            Self::RpcFrameError => "rpc_frame_error",
            Self::Unknown => "unknown",
        }
    }
}

/// Classifies one decoded frame value. The single vocabulary shared with the
/// conformance harness and any raw-fixture evidence tooling.
pub fn classify_frame(value: &Value) -> FrameClass {
    match value.get("type").and_then(Value::as_str) {
        Some("response") => FrameClass::Response,
        Some("ready") => FrameClass::Ready,
        Some("prompt_result") => FrameClass::PromptResult,
        Some("available_commands_update") => FrameClass::AvailableCommands,
        Some("session_info_update") => FrameClass::SessionInfo,
        Some("config_update") => FrameClass::ConfigUpdate,
        Some("command_output") => FrameClass::CommandOutput,
        Some("extension_ui_request") => FrameClass::ExtensionUi,
        Some("extension_error") => FrameClass::ExtensionError,
        Some("host_tool_call" | "host_tool_cancel") => FrameClass::HostTool,
        Some("host_uri_request" | "host_uri_cancel") => FrameClass::HostUri,
        Some("subagent_lifecycle" | "subagent_progress" | "subagent_event") => FrameClass::Subagent,
        // The exact pinned session-event vocabulary (omp @ `eab72e8`):
        // `AgentEvent` lifecycles plus every `AgentSessionEvent` extension.
        // Anything else — a future discriminant, a missing `type`, or a
        // non-string `type` — is Unknown, never a silent session event.
        Some(
            "agent_start"
            | "agent_end"
            | "turn_start"
            | "turn_end"
            | "message_start"
            | "message_update"
            | "message_end"
            | "tool_execution_start"
            | "tool_execution_update"
            | "tool_execution_end"
            | "auto_compaction_start"
            | "auto_compaction_end"
            | "auto_retry_start"
            | "auto_retry_end"
            | "retry_fallback_applied"
            | "retry_fallback_succeeded"
            | "ttsr_triggered"
            | "todo_reminder"
            | "todo_auto_clear"
            | "irc_message"
            | "notice"
            | "thinking_level_changed"
            | "model_changed"
            | "advisor_cost_changed"
            | "goal_updated"
            | "session_shutdown",
        ) => FrameClass::Session,
        Some(_) | None => FrameClass::Unknown,
    }
}

/// The journaled form of one decoded frame. A streaming `message_update`
/// repeats the whole partial message on every token. Those token rows are
/// not durable — [`ephemeral_token_update`] — and `message_end` journals
/// the finished message once. This compact form remains for any caller that
/// still journals an update: the accumulated snapshot is dropped and only
/// the incremental event is kept. Every other frame is journaled exactly
/// as observed.
pub(super) fn journaled_frame(class: FrameClass, value: &Value) -> Value {
    let streaming = class == FrameClass::Session
        && value.get("type").and_then(Value::as_str) == Some("message_update");
    let Some(object) = value.as_object().filter(|_| streaming) else {
        return value.clone();
    };
    let mut compact = serde_json::Map::with_capacity(object.len());
    for (key, field) in object {
        match key.as_str() {
            "message" => {}
            "assistantMessageEvent" => {
                let event = field
                    .as_object()
                    .map(|event| {
                        event
                            .iter()
                            .filter(|(name, _)| name.as_str() != "partial")
                            .map(|(name, value)| (name.clone(), value.clone()))
                            .collect::<serde_json::Map<_, _>>()
                    })
                    .map_or_else(|| field.clone(), Value::Object);
                compact.insert(key.clone(), event);
            }
            _ => {
                compact.insert(key.clone(), field.clone());
            }
        }
    }
    Value::Object(compact)
}

/// A per-token session `message_update` is live-only. Subscribers still
/// receive the original frame; the ledger keeps the later `message_end`,
/// not each token. An unrecognized class with the same type string is not
/// a session event and stays durable.
pub(super) fn ephemeral_token_update(observed: &ObservedFrame) -> bool {
    observed.class == FrameClass::Session
        && observed
            .value()
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            == Some("message_update")
}

/// A bridge-authenticated typed failure carried on an observed frame for
/// the session journal. Set ONLY by the bridge after full host-side
/// authentication — never from a frame's self-reported data alone, so a
/// spoofed or foreign extension_error can never type a session terminal.
/// The epoch records the binding the failure was authenticated under; the
/// normalizer rejects stale-epoch annotations, so a previous
/// incarnation's failure can never type this one's terminal.
#[derive(Clone, Debug)]
pub struct TypedFrameFailure {
    pub code: String,
    /// The failure detail: authenticated typed data (verbatim reason), or
    /// the expected-versus-answered command pair.
    pub detail: String,
    /// The binding epoch the failure was authenticated under.
    pub epoch: Option<odin_domain::huginn::SessionEpoch>,
}

/// One observed frame with its classification, ready for evidence consumers.
///
/// The exact original bytes and parsed value are always retained: either in
/// `decoded` ([`DecodedRpcFrame`] keeps the logical bytes, every physical
/// line, and the parsed value) or — exactly when `class` is
/// [`FrameClass::RpcFrameError`] — in `rejection`, which keeps the physical
/// inputs that were rejected.
#[derive(Clone, Debug)]
pub struct ObservedFrame {
    /// Structural classification applied by the bridge.
    pub class: FrameClass,
    /// The decoded logical frame; `None` exactly for `RpcFrameError`.
    pub decoded: Option<DecodedRpcFrame>,
    /// Exact rejection evidence; `Some` exactly for `RpcFrameError`.
    pub rejection: Option<RpcFrameError>,
    /// The journaled command this frame is associated with, when one is
    /// determinate: responses correlate by their echoed id; `prompt_result`
    /// correlates by its id; other lifecycle frames attach the most recent
    /// mutating command still in flight.
    pub active_command: Option<CommandId>,
    /// A bridge-authenticated typed failure for the session journal (the
    /// dropped-waiter correlated mismatch, or the authenticated context
    /// refusal). Set by the bridge only after host-side authentication;
    /// the normalizer consumes it — stale-epoch annotations are dropped,
    /// so a past incarnation's failure never types this terminal.
    pub journal_failure: Option<TypedFrameFailure>,
}

impl ObservedFrame {
    pub(super) fn decoded(
        class: FrameClass,
        frame: DecodedRpcFrame,
        active_command: Option<CommandId>,
    ) -> Self {
        Self {
            class,
            decoded: Some(frame),
            rejection: None,
            active_command,
            journal_failure: None,
        }
    }

    /// A canonical session-event frame composed from a non-OMP harness's
    /// own output: the same normalizer, journal and completion path as an
    /// OMP frame.
    pub fn harness_event(value: Value) -> Self {
        Self::decoded(
            FrameClass::Session,
            crate::frames::DecodedRpcFrame::synthesized(value),
            None,
        )
    }

    pub(super) fn rejected(rejection: RpcFrameError) -> Self {
        Self {
            class: FrameClass::RpcFrameError,
            decoded: None,
            rejection: Some(rejection),
            active_command: None,
            journal_failure: None,
        }
    }

    /// The parsed value, `None` exactly for rejected frames.
    pub fn value(&self) -> Option<&Value> {
        self.decoded.as_ref().map(DecodedRpcFrame::value)
    }

    /// The exact logical bytes of the decoded frame, or the joined physical
    /// evidence bytes of a rejection.
    pub fn raw(&self) -> Vec<u8> {
        match &self.decoded {
            Some(frame) => frame.raw().to_vec(),
            None => {
                let mut joined = Vec::new();
                if let Some(rejection) = &self.rejection {
                    for line in rejection.evidence() {
                        joined.extend_from_slice(line);
                    }
                }
                joined
            }
        }
    }

    /// Exact retained-byte count without allocating the joined public
    /// snapshot returned by [`Self::raw`].
    pub(super) fn raw_len(&self) -> usize {
        match &self.decoded {
            Some(frame) => frame.raw().len(),
            None => self
                .rejection
                .as_ref()
                .map(|rejection| {
                    rejection
                        .evidence()
                        .iter()
                        .fold(0usize, |total, line| total.saturating_add(line.len()))
                })
                .unwrap_or(0),
        }
    }
}
