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

mod decisions;
pub mod delivery;
mod history;
mod identity;
pub(crate) mod prompt;
mod queue;
mod rollover;
mod seams;
mod stream;
mod vehicle;

pub use rollover::MAX_ENDED_SUCCESSORS;
pub use seams::{
    CompositionPair, ConversationAuthority, ConversationEgress, ConversationPlane,
    ConversationRootConfig, DaemonKernelApprovals, EnsuredGeneration, KernelApprovals,
    KernelDecisionOutcome, OwnerSurface, SuccessorTrouble,
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
    /// Colin's messages that arrived while a turn was running, oldest
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
    updated_at_unix_ms: u64,
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
        self.recent_answers
            .retain(|recent| recent.idempotency_key != key);
        self.recent_answers.push(RecentAnswer {
            idempotency_key: key.to_owned(),
            answer: answer.to_owned(),
        });
        let excess = self.recent_answers.len().saturating_sub(RECENT_ANSWERS);
        self.recent_answers.drain(..excess);
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
    /// The queued messages this one prompt carries, its own last.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    asks: Vec<QueuedAsk>,
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
    /// The queued turn outgrew its vehicle's context window once and went
    /// to a successor; a second refusal is told, never rolled again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rolled: bool,
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
    /// Colin's queued messages: sent as one prompt once the running turn
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
    /// Acknowledged chunks of an incomplete delivery, in transport order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    delivery_chunks: Vec<String>,
    /// Reserved before transport; remains set when a POST outcome is unknown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    delivery_pending: bool,
    /// The exact admitted or uncertain decision; a new reply cannot fork it.
    #[serde(default)]
    decision_command_id: Option<String>,
    delivery_error: Option<String>,
    /// The gate settled — by decision, timeout, or replacement — so the
    /// receipt can no longer be decided.
    settled: bool,
}
