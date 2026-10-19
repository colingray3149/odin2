//! Bridge contracts: typed failures, journaled receipts and reports,
//! lifecycle status, the observer extension point, side-channel outcome
//! types, and the small time/digest/serialization utilities.

use super::*;

/// Broadcast capacity of the observation fan-out. A slow consumer receives a
/// typed lag error naming the missed count; nothing is silently dropped.
pub const OBSERVATION_CHANNEL_CAP: usize = 1024;

pub(super) fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub(super) fn unix_ms(at: OffsetDateTime) -> u64 {
    let millis = at.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(millis.max(0)).unwrap_or(0)
}

pub(super) fn digest_hex(digest: &Digest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn json_bytes(value: &Value) -> Result<Vec<u8>, BridgeError> {
    serde_json::to_vec(value).map_err(|error| BridgeError::Config {
        detail: format!("value rejected serialization: {error}"),
    })
}

/// The declared context-refusal wire contract of the trusted extension
/// guard (`REFUSAL_MARKER` in extension/odin.ts, proven against the pinned
/// harness): an `extension_error` frame whose `error` string is exactly
/// `<marker>|<json>` carries the typed refusal. The marker prefix is the
/// contract; the JSON tail is parsed as a STRICT schema — never ad-hoc
/// matched out of formatted error text, and an unknown/malformed tail
/// fails closed to the generic extension-error path, never a successful
/// honest terminal.
pub(super) const CONTEXT_REFUSAL_MARKER: &str = "odin.context_refusal.v1";

/// The closed refusal code set of the marker contract. A frame carrying
/// any other code — including a future code this build does not know —
/// is not a context refusal.
const CONTEXT_REFUSAL_CODES: [&str; 10] = [
    "window_exceeded",
    "model_identity_mismatch",
    "declaration_unusable",
    "api_unresolved",
    "payload_not_json",
    "payload_uncountable",
    "media_uncountable",
    "output_unboundable",
    "output_uncappable",
    "envelope_invalid",
];

/// The numeric detail fields the refusal schema allows; each, when
/// present, must be a JSON number — a wrong type fails the schema closed.
/// `input_tokens` is the declared counter's own count of the dispatched
/// request text; `request_bytes` its serialized UTF-8 byte length. Both
/// ride every window_exceeded refusal so the two accounting units are
/// always separable, never conflated.
const CONTEXT_REFUSAL_NUMERIC_FIELDS: [&str; 5] = [
    "request_bytes",
    "requested_output",
    "reserve",
    "window",
    "input_tokens",
];

/// The string detail field the final structured fit adds on exhaustion,
/// with its one closed value: `fit` is present only when the fitter ran to
/// exhaustion (lower-ranked dropped, top prefix at its mandatory floor) and
/// still could not fit. Any other value is a malformed frame, not a
/// terminal.
const CONTEXT_REFUSAL_FIT_FIELD: &str = "fit";
const CONTEXT_REFUSAL_FIT_EXHAUSTED: &str = "final_fit_exhausted";

/// One parsed context refusal of the marker contract.
pub(super) struct ContextRefusal {
    pub(super) code: String,
    pub(super) reason: String,
}

/// Parses the marker contract out of one `extension_error` frame value.
/// `None` for every other shape: no marker prefix, a non-object tail,
/// malformed JSON, an unknown code, a missing/empty reason, or a
/// mistyped numeric field. The parse is data, not string matching — an
/// arbitrary provider or plugin error can never satisfy this schema.
pub(super) fn parse_context_refusal(value: &Value) -> Option<ContextRefusal> {
    let error = value.get("error").and_then(Value::as_str)?;
    let tail = error
        .strip_prefix(CONTEXT_REFUSAL_MARKER)?
        .strip_prefix('|')?;
    let parsed: Value = serde_json::from_str(tail).ok()?;
    let object = parsed.as_object()?;
    let code = object.get("code").and_then(Value::as_str)?;
    if !CONTEXT_REFUSAL_CODES.contains(&code) {
        return None;
    }
    let reason = object.get("reason").and_then(Value::as_str)?;
    if reason.is_empty() {
        return None;
    }
    for field in CONTEXT_REFUSAL_NUMERIC_FIELDS {
        if let Some(detail) = object.get(field) {
            if !detail.is_number() {
                return None;
            }
        }
    }
    match object.get(CONTEXT_REFUSAL_FIT_FIELD) {
        Some(Value::String(value)) if value == CONTEXT_REFUSAL_FIT_EXHAUSTED => {}
        Some(_) => return None,
        None => {}
    }
    Some(ContextRefusal {
        code: code.to_owned(),
        reason: reason.to_owned(),
    })
}

/// Requires exactly one trusted-extension argv selection. Authenticate frame paths
/// against this exact path, never a suffix or the frame's self-reported identity alone.
pub(super) fn trusted_extension_from_args(args: &[String]) -> Option<String> {
    let mut found: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let value = if arg == "--trusted-extension" {
            iter.next()?.as_str()
        } else if let Some(value) = arg.strip_prefix("--trusted-extension=") {
            value
        } else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(value.to_owned());
    }
    found
}

#[derive(Debug, Error)]
pub enum BridgeError {
    /// Host configuration or input validation rejected the call.
    #[error("bridge configuration rejected: {detail}")]
    Config { detail: String },
    /// The trusted process boundary failed.
    #[error(transparent)]
    Process(#[from] OmpProcessError),
    /// The durable ledger rejected an operation.
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    /// A URI side-channel resolution was rejected by the router.
    #[error(transparent)]
    Uri(#[from] UriError),
    /// A capability-bound operation failed inside the sole authority path.
    #[error(transparent)]
    Operation(#[from] HostToolOperationError),
    /// Another owner holds the exclusive session lease.
    #[error("session lease is held by another owner: {detail}")]
    LeaseConflict { detail: String },
    /// The declared binding's scope dimensions are inconsistent.
    #[error("bridge scope binding is invalid: {detail}")]
    ScopeBinding { detail: String },
    /// A launch carrying a requested durable admission epoch found the
    /// durable binding row AHEAD of that epoch: a stale incarnation asked
    /// to rewind a published epoch. Fail closed typed — never adopt, never
    /// clobber, never fake success.
    #[error("stale binding epoch: requested {requested}, live binding is at {actual}")]
    StaleBinding {
        /// The supervisor's requested admission epoch.
        requested: i64,
        /// The durable binding row's published epoch.
        actual: i64,
    },
    /// The bridge is not in a state that accepts the operation.
    #[error("bridge is not ready (state: {state})")]
    NotReady { state: String },
    /// Ambiguous journaled commands exist; mutating work is refused rather
    /// than replayed.
    #[error("ambiguous incomplete commands block execution: {commands:?}")]
    BlockedIncomplete { commands: Vec<CommandId> },
    /// The child answered a different command than the pending request.
    #[error("response/command mismatch: expected `{expected}`, got `{got}`")]
    ResponseMismatch { expected: String, got: String },
    /// The child completed the command with a typed failure response.
    #[error("OMP command `{command}` failed: {error}")]
    CommandFailed {
        command: String,
        error: String,
        /// The child's machine-readable code, when present.
        code: Option<String>,
    },
    /// The supervised child can no longer carry commands.
    #[error("OMP process is unavailable: {detail}")]
    ProcessDown { detail: String },
    /// The admitted remote harness carrier refused the exec attach: the
    /// typed transport reason is carried verbatim (gone, not running,
    /// foreign, attach failed, empty command) and nothing was launched.
    #[error("remote harness attach failed: {detail}")]
    RemoteAttach { detail: String },
    /// A startup failure whose durable settlement also failed: `primary` is the
    /// typed launch rejection, preserved verbatim, and `cleanup` is the failed
    /// settlement step (row retirement or lease release). Neither fact is
    /// swallowed, so a caller never believes durable state was repaired when it
    /// was not.
    #[error("{primary}; durable settlement failed: {cleanup}")]
    StartupSettlement {
        /// The typed launch/recovery rejection that failed the attempt.
        primary: Box<BridgeError>,
        /// The failed settlement step: row retirement or lease release.
        cleanup: Box<BridgeError>,
    },
    /// An observation consumer lagged the bounded channel by this many frames.
    #[error("observation consumer lagged; {0} frame(s) elided from the channel window")]
    ObservationLagged(u64),
    /// The bridge is stopped; no further operations are accepted.
    #[error("bridge is stopped")]
    Stopped,
    /// The pump task is gone; the bridge cannot carry traffic.
    #[error("bridge pump channel is closed")]
    ChannelClosed,
    /// Filesystem I/O behind an artifact write failed.
    #[error("bridge artifact I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A serialized payload rejected conversion.
    #[error("bridge serialization failed: {detail}")]
    Serialization {
        /// The conversion failure.
        detail: String,
    },
    /// Side-channel cleanup did not reach a fully joined, empty state. The
    /// bridge keeps admission closed and retains its lease and current epoch.
    #[error("side-channel authority remains active: {detail}")]
    SideChannelDrain {
        /// Timeout, task failure, or retained-state evidence.
        detail: String,
    },
    /// The parent's delegated children could not be awaited to a stop within
    /// the bounded budget. Stop fails closed; the lease and epoch remain.
    #[error("delegated child stop failed: {detail}")]
    ChildStop {
        /// Which child did not stop, and the observed evidence.
        detail: String,
    },
}

/// Streaming behavior of a prompt, in pinned wire form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamingBehavior {
    /// Steer the running turn.
    Steer,
    /// Queue as a follow-up turn.
    FollowUp,
}

impl StreamingBehavior {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Steer => "steer",
            Self::FollowUp => "followUp",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Prompt {
    pub message: String,
    /// Optional pinned `ImageContent` objects, host-constructed.
    pub images: Vec<Value>,
    pub streaming_behavior: Option<StreamingBehavior>,
}

impl Prompt {
    /// A plain-text prompt with default streaming behavior.
    pub fn text(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            images: Vec::new(),
            streaming_behavior: None,
        }
    }
}

/// Durable receipt of one journaled command.
#[derive(Clone, Debug)]
pub struct CommandReceipt {
    /// The journaled command id; identical to the wire request id.
    pub command_id: CommandId,
    /// The child's `data` payload on success.
    pub data: Value,
}

/// Result of one checkpoint: the committed ledger checkpoint, the
/// content-addressed artifact metadata, and the state digest they share.
#[derive(Clone, Debug)]
pub struct CheckpointRecord {
    pub checkpoint: Checkpoint,
    /// The content-addressed artifact holding the exact checkpoint bytes.
    pub artifact: ArtifactMetadata,
    /// BLAKE3 digest of the canonical checkpoint bytes; equals the artifact
    /// digest and the checkpoint's `state_digest`.
    pub state_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct RecoveryReport {
    /// The ownership epoch after reclaim.
    pub epoch: i64,
    /// Commands completed from durable response/checkpoint evidence (or
    /// superseded re-registration) without any resend.
    pub reconciled: Vec<CommandId>,
    /// Commands whose effect is ambiguous; they block mutating work.
    pub blocked: Vec<CommandId>,
}

/// Residue report of a bounded stop.
#[derive(Clone, Debug)]
pub struct StopReport {
    /// Frames drained during the bounded stop, classified like live traffic.
    pub drained: Vec<ObservedFrame>,
    /// The exact, observed exit record of the child; `None` only when no live
    /// child remained at stop. An unobserved root/group reap fails the stop
    /// instead of fabricating terminal evidence.
    pub exit: Option<OmpExitRecord>,
    /// Whether the session lease was released durably.
    pub lease_released: bool,
    /// Visible journaled commands left without a durable outcome.
    pub incomplete: Vec<CommandId>,
    /// Per-child outcomes of the bounded await of every active delegated
    /// child. Empty when the session delegated no workers or no stop
    /// coordinator was composed.
    pub children: Vec<crate::host_tools::delegation::ChildStopRecord>,
}

/// Typed observer extension point reserved for the future observation plane
/// and harness integration.
///
/// Observers are invoked synchronously from the pump, after the observation
/// is durably journaled and before the broadcast fan-out. Implementations
/// must be cheap and non-blocking; streaming consumers use
/// [`OmpBridge::subscribe`] instead.
pub trait BridgeObserver: Send + Sync + 'static {
    /// Receives one durably journaled observation.
    fn on_observation(&self, observed: &ObservedFrame);
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ObserverToken(pub(super) u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeStatus {
    /// Constructed but registration has not completed.
    Starting,
    /// Carrying traffic.
    Ready,
    /// Ambiguous journaled commands block mutating work.
    Blocked { commands: Vec<CommandId> },
    /// The child can no longer carry traffic; recover to resume.
    Failed { reason: String },
    /// Stopped durably; the bridge is spent.
    Stopped,
}

/// One completed host-tool or URI side-channel interaction, retained as
/// evidence whether or not its result reached the child.
#[derive(Clone, Debug)]
pub struct SideChannelOutcome {
    pub request_id: String,
    pub kind: SideChannelKind,
    /// Tool name, or the requested URL.
    pub name: String,
    pub status: SideChannelStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SideChannelKind {
    Tool,
    Uri,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SideChannelStatus {
    /// The tool or resolver produced a result; `sent` says whether it reached
    /// the child before any cancellation or shutdown.
    Completed {
        result: Value,
        /// Whether the result frame was written to the child.
        sent: bool,
    },
    /// A cancel arrived first; the computed result is retained as evidence
    /// and never sent late.
    Cancelled {
        /// The computed result, when the worker finished despite the cancel.
        result: Option<Value>,
    },
    /// The interaction failed before a result existed.
    Failed { error: String },
}
