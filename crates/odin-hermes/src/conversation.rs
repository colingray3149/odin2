//! One durable conversation per declared (seat, project). Canonical tuple hashes
//! keep root and command ids deterministic, restart-stable and within wire limits.
//!
//! Persist vehicle identity before opening or prompting. Replays observe admitted
//! commands; unadmitted prompts may refresh their epoch without changing id or body.
//! Replies reserve transport operations before sending and retain acknowledged chunks.
//! Decisions require a question delivered to this owner/channel and session, and
//! persist their continuation before deciding.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_domain::huginn::{ModelName, ProviderName};
use odin_domain::{LaneId, NodeId, ProjectId};
use odin_omp::live::supervisor::LiveSeatBinding;

mod class_route;
mod decisions;
pub mod delivery;
mod held;
mod history;
mod identity;
mod late;
pub(crate) mod prompt;
mod queue;
mod rollover;
mod seams;
mod stall;
mod stream;
mod vehicle;

pub use prompt::QUIET_REPLY;
pub use rollover::MAX_ENDED_SUCCESSORS;
pub use seams::{
    BackgroundWork, ClassRoute, CompositionPair, ConversationAuthority, ConversationEgress,
    ConversationPlane, ConversationRootConfig, DaemonKernelApprovals, EnsuredGeneration,
    KernelApprovals, KernelDecisionOutcome, OwnerSurface, Provenance, StatusPostError,
    SuccessorTrouble,
};
pub use vehicle::InitializeError;

pub const VEHICLE_TITLE_PREFIX: &str = "conversation ";

#[cfg(test)]
mod tests;

/// The durable root: one conversation per declared (seat, project).
pub struct ConversationRoot {
    binding: LiveSeatBinding,
    project: ProjectId,
    lane: LaneId,
    provider: ProviderName,
    model: ModelName,
    target_node: NodeId,
    owner: OwnerSurface,
    answer_bound: StdDuration,
    stall_bound: Option<StdDuration>,
    poll_interval: StdDuration,
    plane: Arc<dyn ConversationPlane>,
    authority: Arc<dyn ConversationAuthority>,
    egress: Arc<dyn ConversationEgress>,
    approvals: Arc<dyn KernelApprovals>,
    ledger_path: PathBuf,
    state_path: PathBuf,
    rollover: odin_omp::live::rollover::RolloverPolicy,
    clock: Option<crate::schedule::OwnerClock>,
    delegation_links: Option<odin_omp::host_tools::delegation::DelegationLinkLedger>,
    class_route: Option<ClassRoute>,
    /// The lane the class route last put the vehicle on; a vehicle on any other lane was put
    /// there at launch or by the owner.
    routed: parking_lot::Mutex<Option<ModelName>>,
    conversation_id: String,
    /// Serializes execute / decisions / initialize / wakes: record
    /// read-modify-write and prompt phases never interleave.
    lock: Arc<tokio::sync::Mutex<()>>,
    /// Tracks wake tasks so shutdown can join them instead of detaching them.
    background: tokio::sync::Mutex<std::collections::BTreeMap<String, tokio::task::JoinHandle<()>>>,
    closing: std::sync::atomic::AtomicBool,
    handle: tokio::runtime::Handle,
    self_weak: std::sync::Weak<ConversationRoot>,
}

/// Excludes recorded vehicles and in-progress rollover sessions from startup settlement.
pub fn owned_conversation_sessions(
    state_dir: &std::path::Path,
) -> Result<std::collections::BTreeSet<String>, String> {
    let root = state_dir.join("conversations");
    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(error) => return Err(format!("could not list {}: {error}", root.display())),
    };
    let mut owned = std::collections::BTreeSet::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("could not list {}: {error}", root.display()))?
            .path()
            .join("root.json");
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("could not read {}: {error}", path.display())),
        };
        let record: ConversationRecord = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "the conversation record {} is unreadable: {error}",
                path.display()
            )
        })?;
        owned.extend(record.session_id);
        if let Some(rollover) = record.rollover {
            owned.insert(rollover.predecessor_session);
            owned.insert(rollover.successor_session);
        }
    }
    Ok(owned)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConversationRecord {
    conversation_id: String,
    seat: String,
    project: String,
    /// The deterministic vehicle-open command id; every authority
    /// re-ensure composes through it and every retry re-derives the SAME
    /// session id from it.
    vehicle_command_id: Option<String>,
    session_id: Option<String>,
    /// The prompt retained for replay after restart.
    in_flight: Option<InFlightPrompt>,
    /// Durable decision-wake plans, persisted BEFORE the decision.
    wakes: Vec<PendingWake>,
    last_idempotency_key: Option<String>,
    last_projection: Option<serde_json::Value>,
    /// The answers of the last [`RECENT_ANSWERS`] settled turns, each under
    /// its own idempotency key: child reports and incident wakes settle
    /// between owner turns, so `last_projection` alone cannot say what was
    /// answered to one particular message.
    #[serde(default)]
    recent_answers: Vec<RecentAnswer>,
    /// The questions this root relayed, with their durable delivery
    /// receipts. A decision only ever binds to a `delivered` receipt.
    questions: Vec<DeliveredQuestion>,
    /// the owner's messages that arrived while a turn was running, oldest
    /// first: they go out together as the next turn's one prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    queued: Vec<QueuedAsk>,
    /// The newest [`COVERED_KEYS`] idempotency keys the queue took over:
    /// a replayed intent among them is already answered by its turn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    covered: Vec<String>,
    /// The one bounded pending successor transition of the governed
    /// fresh-generation rollover, when armed. Preserved until the
    /// successor open is durable.
    #[serde(default)]
    rollover: Option<rollover::VehicleRollover>,
    /// Consecutive in-place recoveries of the current vehicle that failed;
    /// at [`vehicle::WEDGE_ESCAPE_AFTER`] it rolls to a successor instead.
    #[serde(default)]
    recovery_failures: u32,
    /// Replies held behind the owner's yes/no, one per approval ([`held`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    held: Vec<HeldReply>,
    /// When the owner last cleared the conversation (RFC 3339). No later
    /// rollover brief replays a turn issued before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cleared_at: Option<String>,
    updated_at_unix_ms: u64,
}

/// A turn's reply held behind one approval card that stands in for it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeldReply {
    /// The held reply's delivery key; none when there is none to close.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply: Option<String>,
    approval_id: String,
    /// What the card asked, for the line that says it lapsed.
    asked: String,
}

const RECENT_ANSWERS: usize = 16;

/// How many queued keys the record remembers once answered. A replay comes
/// from an intent row the reconciler has not settled, and it re-presents
/// that row before any later intent executes; this bound only has to cover
/// what one reconcile pass can enqueue around it.
const COVERED_KEYS: usize = 512;

/// One owner message waiting for the running turn to end.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueuedAsk {
    idempotency_key: String,
    content: String,
    at_unix_ms: u64,
    /// Harness events that waited behind this message, riding its turn.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    harness: Vec<String>,
}

/// One settled turn's answer, as delivered to the owner.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecentAnswer {
    idempotency_key: String,
    answer: String,
}

impl ConversationRecord {
    /// Files `last_projection`'s answer under its key (replacing an earlier
    /// copy, as a late answer re-settles its key), keeping the newest
    /// [`RECENT_ANSWERS`].
    fn remember_answer(&mut self) {
        let Some(projection) = &self.last_projection else {
            return;
        };
        let (Some(key), Some(answer)) = (
            projection["idempotencyKey"].as_str(),
            projection["answer"].as_str(),
        ) else {
            return;
        };
        if answer.is_empty() {
            return;
        }
        let (key, answer) = (key.to_owned(), answer.to_owned());
        self.remember_answer_for(&[key], &answer);
    }

    /// Files one answer under every key it answered.
    fn remember_answer_for(&mut self, keys: &[String], answer: &str) {
        for key in keys {
            self.recent_answers
                .retain(|recent| &recent.idempotency_key != key);
            self.recent_answers.push(RecentAnswer {
                idempotency_key: key.clone(),
                answer: answer.to_owned(),
            });
        }
        let excess = self.recent_answers.len().saturating_sub(RECENT_ANSWERS);
        self.recent_answers.drain(..excess);
    }
}

/// The exact admitted prompt persisted before the send.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct InFlightPrompt {
    idempotency_key: String,
    content: String,
    command_id: String,
    session_id: String,
    /// Prompt vs FollowUp, chosen once from the observed session state.
    kind: InFlightKind,
    expected_epoch: u64,
    /// The event cursor the answer wait resumes from.
    event_cursor: u64,
    phase: InFlightPhase,
    /// The turn's context line at prepare time — the owner's clock and the
    /// model actually serving the session; part of the exact body, so a
    /// resend is byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    clock: Option<String>,
    /// The successor's continuity brief, riding the first turn sent to the
    /// fresh session instead of costing a turn of its own; part of the
    /// exact body like the clock line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    brief: Option<String>,
    /// The content is the owner's authenticated words — his ask, or a
    /// queued message of his — and not a daemon-authored wake or reprompt:
    /// the command carries it separately, so memory queries his text and
    /// never the rendered turn.
    #[serde(default)]
    owner: bool,
    /// The harness began this turn (a wake, routine, event or report), not
    /// the owner; false for his own turns and for nudges inside a turn already
    /// open.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unprompted: bool,
    /// The queued messages this one prompt carries, its own last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    asks: Vec<QueuedAsk>,
    /// Harness events that waited behind the owner's message, one line each:
    /// they follow his words in the same turn, part of the exact body like
    /// the clock line, and are never his text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    harness: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum InFlightKind {
    Prompt,
    /// Replay-only; its stored body must remain byte-identical.
    FollowUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum InFlightPhase {
    /// Persisted before the send; admission decides replay semantics.
    Prepared,
    /// The journal admitted the command; replay observes only.
    Sent,
}

/// A durable decision-wake plan, persisted BEFORE the decision.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingWake {
    command_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owner_keys: Vec<String>,
    kind: WakeKind,
    approved: bool,
    label: String,
    session_id: String,
    /// The event head captured BEFORE the decision: the wake observes
    /// exactly the continuation window of this decision.
    decision_cursor: u64,
    approval_id: Option<String>,
    #[serde(default)]
    prompt: Option<InFlightPrompt>,
    #[serde(default)]
    reply: Option<ContinuationReply>,
    /// A completed handoff needs no reply; replay its terminal even after
    /// the delivered question is decided or expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completion: Option<WakeCompletion>,
    /// What the owner said with a declining decision ("no — drop X…"),
    /// handed to the declined turn to act on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_note: Option<String>,
    /// What the host's run of the approved call came to, for the seat to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<String>,
    /// The queued asks were sent again once, on a successor after the turn outgrew its
    /// vehicle's context window or on the next lane after its own went quiet; a second
    /// trouble is told, never retried.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rolled: bool,
}

impl PendingWake {
    /// An approved wake of `kind` on `session`, watching events from `decision_cursor`; the
    /// caller sets whatever else it carries.
    fn new(
        kind: WakeKind,
        command_id: impl Into<String>,
        session_id: impl Into<String>,
        decision_cursor: u64,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            owner_keys: Vec::new(),
            kind,
            approved: true,
            label: String::new(),
            session_id: session_id.into(),
            decision_cursor,
            approval_id: None,
            prompt: None,
            reply: None,
            completion: None,
            owner_note: None,
            outcome: None,
            rolled: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum WakeCompletion {
    NeedsOwner,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContinuationReply {
    answer: String,
    delivered: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    terminal_outcome: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum WakeKind {
    /// A live permission decision: the child continues on its own, the
    /// wake observes and delivers — it NEVER injects a prompt.
    LiveContinuation,
    /// A kernel-ledger decision: the turn may have settled, so the host
    /// may need to ask the model to re-issue the exact gated call — only
    /// after the durable history proves it did not already continue.
    KernelRetry,
    /// Observes and delivers a turn that outlived the answer timeout.
    LateAnswer,
    /// the owner's queued messages: sent as one prompt once the running turn
    /// ends, its answer delivered like any other.
    QueuedAsks,
}

/// One relayed question and its delivery receipt.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeliveredQuestion {
    request_id: String,
    session_id: String,
    /// A question without its session generation cannot authorize a decision.
    #[serde(default)]
    session_epoch: Option<u64>,
    prompt: String,
    expires_at_unix_ms: u64,
    owner_user_id: String,
    channel_id: String,
    /// The actual transport message, never inferred from a stored question.
    #[serde(default)]
    delivered_message_id: Option<String>,
    /// The exact admitted or uncertain decision; a new reply cannot fork it.
    #[serde(default)]
    decision_command_id: Option<String>,
    delivery_error: Option<String>,
    /// The gate settled — by decision, timeout, or replacement — so the
    /// receipt can no longer be decided.
    settled: bool,
}
