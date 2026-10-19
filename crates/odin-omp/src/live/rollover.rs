//! Bounded turn-boundary rollover: measured context-watermark trigger,
//! durable bounded brief, identity-checked respawn, single reinjection.
//!
//! The policy surface is declarative and bounded: a composition declares a
//! provider-token [`RolloverPolicy`] (threshold at most
//! [`ROLLOVER_THRESHOLD_TOKENS_MAX`]). The trigger a session actually runs
//! with is always narrowed to the bound lane's declared context ceiling by
//! [`lane_rollover_config`]; a seat that declares no policy runs no
//! rollover — undeclared means none, never an invented default. Oversize
//! requests on small lanes are refused honestly by the complete-request
//! context guard before they reach the provider, so no lane depends on an
//! implicit rollover to survive its own size. The bridge pump measures
//! the watermark ONLY from provider-reported usage on terminal `agent_end`
//! frames
//! ([`RolloverUsage::extract`] returns `None` when the payload carries no
//! numeric fields — nothing is ever estimated). The brief is assembled from
//! durable rows only (task plan/acceptance, the session's own delegated
//! assignment when it is a delegated child, delegation links joined with
//! live-ledger child state, pending approvals, journaled isError finishes,
//! and a bounded conversation tail) — a full-history replay is structurally
//! impossible: the walk, entry counts, and byte budget are all capped, and an
//! over-budget brief trims older conversation entries before failing typed.

use std::time::Duration;

use async_trait::async_trait;
use odin_domain::SessionId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const ROLLOVER_MEDIA_TYPE_BRIEF: &str = "application/vnd.odin.rollover-brief.v1";
pub const ROLLOVER_MEDIA_TYPE_USAGE: &str = "application/vnd.odin.rollover-usage.v1";
/// Hard ceiling of the declared token threshold.
pub const ROLLOVER_THRESHOLD_TOKENS_MAX: u64 = 250_000;
pub const ROLLOVER_THRESHOLD_TOKENS_DEFAULT: u64 = 180_000;
/// Hard ceiling of the rendered brief byte budget.
pub const ROLLOVER_BRIEF_BYTES_MAX: usize = 32_768;
/// Default brief byte budget of [`RolloverPolicy`] for seats that declare
/// none. The brief is the successor's mandatory first input, so it must fit
/// the destination slice's `max_item_tokens` (8_192 on the smallest slice;
/// composition refuses a declared budget that cannot fit its bound slice).
pub const ROLLOVER_BRIEF_BYTES_DEFAULT: usize = 8_000;
/// Inclusive lower bound of the conversation-tail event count.
pub const ROLLOVER_HISTORY_TAIL_MIN: usize = 8;
/// Inclusive upper bound of the conversation-tail event count.
pub const ROLLOVER_HISTORY_TAIL_MAX: usize = 1024;
pub const ROLLOVER_HISTORY_TAIL_DEFAULT: usize = 128;
/// Hard ceiling of journaled events one brief build may walk.
pub const ROLLOVER_HISTORY_WALK_CAP: usize = 8_192;
/// Maximum delegated-child entries one brief carries.
pub const ROLLOVER_CHILDREN_CAP: usize = 8;
/// Maximum pending-approval entries one brief carries.
pub const ROLLOVER_APPROVALS_CAP: usize = 8;
/// Maximum recent tool-failure entries one brief carries.
pub const ROLLOVER_FAILURES_CAP: usize = 8;
/// Characters retained per conversation-tail entry.
pub const ROLLOVER_TAIL_ENTRY_CHARS: usize = 4_096;
/// Characters retained per tool-failure detail.
pub const ROLLOVER_FAILURE_DETAIL_CHARS: usize = 1_024;
/// Marker every reinjection prompt starts with.
pub const ROLLOVER_PROMPT_MARKER: &str = "[ODIN ROLLOVER";

/// The continuity turn of a session that is nobody's delegated worker is
/// context, never a task: an agentic turn here held every restart's
/// vehicle open for minutes of tool calls before the owner could be
/// answered, so the successor absorbs and waits for its next request.
pub const ROLLOVER_ABSORB_INSTRUCTION: &str = "Continuity context from your previous session, \
    not a request: absorb it, call no tools, and reply with exactly one word: ready.";

/// The reinjection turn of a delegated worker: the brief carries the
/// original delegated assignment beside the bounded progress summary,
/// and the turn IS the work order — the fresh incarnation is the same
/// worker resuming the interrupted unit, never a context sink left idle
/// after an absorption acknowledgement.
pub const ROLLOVER_CONTINUE_INSTRUCTION: &str = "Continuity context from your previous session: \
    the brief below carries your original delegated assignment and your progress so far. This \
    is your next work order: continue the assigned unit from where you were, do not redo \
    finished work.";

/// The reinjection prompt: one header line — the marker plus its
/// attributes, closed with `]` — then the instruction and the bounded
/// brief on the following line.
fn instructed_prompt(header: &str, instruction: &str, brief: &str) -> String {
    format!("{header} {instruction}\n{brief}")
}

/// The absorb-only reinjection: a conversation successor's first context,
/// answered with one word while the successor awaits its next request.
pub fn continuity_prompt(header: &str, brief: &str) -> String {
    instructed_prompt(header, ROLLOVER_ABSORB_INSTRUCTION, brief)
}

/// The delegated worker's reinjection: the continuity brief and the order
/// to continue the interrupted unit in ONE canonical turn.
pub fn continuation_prompt(header: &str, brief: &str) -> String {
    instructed_prompt(header, ROLLOVER_CONTINUE_INSTRUCTION, brief)
}

/// Bounded wait for the reinjection turn to settle before the usage record.
pub const ROLLOVER_REINJECTION_SETTLE_BUDGET: Duration = Duration::from_secs(300);
/// Settled terminal turns required after a rollover before the next trigger.
pub const ROLLOVER_MIN_SETTLED_TURNS: u32 = 2;

/// Declared, bounded rollover policy. Every field has a compiled default;
/// [`RolloverPolicy::validate`] enforces the ceilings independently of any
/// config parser so a mis-mapped composition still fails closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloverPolicy {
    /// Provider-token watermark that arms the trigger; at most
    /// [`ROLLOVER_THRESHOLD_TOKENS_MAX`].
    pub threshold_tokens: u64,
    /// Byte budget of the rendered brief; at most [`ROLLOVER_BRIEF_BYTES_MAX`].
    pub max_brief_bytes: usize,
    /// Conversation-tail event count; within
    /// [`ROLLOVER_HISTORY_TAIL_MIN`]..=[`ROLLOVER_HISTORY_TAIL_MAX`].
    pub history_tail_events: usize,
}

impl Default for RolloverPolicy {
    fn default() -> Self {
        Self {
            threshold_tokens: ROLLOVER_THRESHOLD_TOKENS_DEFAULT,
            max_brief_bytes: ROLLOVER_BRIEF_BYTES_DEFAULT,
            history_tail_events: ROLLOVER_HISTORY_TAIL_DEFAULT,
        }
    }
}

impl RolloverPolicy {
    /// Validates the declared bounds; the error names the offending field.
    pub fn validate(&self) -> Result<(), String> {
        if self.threshold_tokens == 0 || self.threshold_tokens > ROLLOVER_THRESHOLD_TOKENS_MAX {
            return Err(format!(
                "rollover threshold_tokens {} must be in 1..={ROLLOVER_THRESHOLD_TOKENS_MAX}",
                self.threshold_tokens
            ));
        }
        if self.max_brief_bytes == 0 || self.max_brief_bytes > ROLLOVER_BRIEF_BYTES_MAX {
            return Err(format!(
                "rollover max_brief_bytes {} must be in 1..={ROLLOVER_BRIEF_BYTES_MAX}",
                self.max_brief_bytes
            ));
        }
        if !(ROLLOVER_HISTORY_TAIL_MIN..=ROLLOVER_HISTORY_TAIL_MAX)
            .contains(&self.history_tail_events)
        {
            return Err(format!(
                "rollover history_tail_events {} must be in \
                 {ROLLOVER_HISTORY_TAIL_MIN}..={ROLLOVER_HISTORY_TAIL_MAX}",
                self.history_tail_events
            ));
        }
        Ok(())
    }
}

/// Composed rollover configuration carried by
/// [`crate::bridge::OmpBridgeConfig`] and
/// [`crate::live::runtime::ProductionBridgeRuntimeConfig`]. Constructed
/// only through [`Self::new`], which validates the policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloverRuntimeConfig {
    policy: RolloverPolicy,
}

impl RolloverRuntimeConfig {
    /// Validates and assembles one configuration.
    pub fn new(policy: RolloverPolicy) -> Result<Self, String> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn policy(&self) -> RolloverPolicy {
        self.policy.clone()
    }

    /// Re-validates; used by composition-time guards.
    pub fn validate(&self) -> Result<(), String> {
        self.policy.validate()
    }
}

/// The rollover map every seat's sessions actually run with. One
/// composition pass, no fallback re-insert: a seat whose evaluation yields
/// `None` — no declaration, or a degenerate lane — composes NO rollover,
/// and a raw declaration is never re-added behind the narrowing's back.
///
/// * Seat with a declared context policy: the declaration (when present)
///   narrowed to the lane ceiling; a degenerate ceiling drops even an
///   explicit declaration (the trigger can never fire; the complete-request
///   context guard refuses oversize requests typed instead).
/// * Seat without a context policy: no lane ceiling exists to narrow
///   against, so a declared rollover stands exactly as declared.
pub fn compose_seat_rollovers(
    lanes: &[(odin_domain::SeatId, Option<(u32, u32)>)],
    declared: &std::collections::BTreeMap<odin_domain::SeatId, RolloverRuntimeConfig>,
) -> Result<std::collections::BTreeMap<odin_domain::SeatId, RolloverRuntimeConfig>, String> {
    let mut effective = std::collections::BTreeMap::new();
    for (seat, lane) in lanes {
        let Some((window, reserve)) = lane else {
            continue;
        };
        if let Some(config) = lane_rollover_config(declared.get(seat), *window, *reserve)? {
            effective.insert(seat.clone(), config);
        }
    }
    for (seat, config) in declared {
        if !lanes
            .iter()
            .any(|(lane_seat, lane)| lane_seat == seat && lane.is_some())
        {
            effective
                .entry(seat.clone())
                .or_insert_with(|| config.clone());
        }
    }
    Ok(effective)
}

/// The rollover configuration ONE session actually runs with, resolved
/// from the seat's declared policy against the bound lane's declared
/// context ceiling — the served model's declared context window minus the
/// declared reserved output tokens. The lane ceiling is a hard physical
/// bound: any threshold above it can never fire before the provider's own
/// length limit, so it is always narrowed to the ceiling.
///
/// * An explicit seat declaration is kept and its trigger narrowed to the
///   ceiling (`min(declared, window - reserve)`), even when the declared
///   threshold exceeds the lane window. A degenerate lane whose window does
///   not exceed its reserve (`ceiling == 0`) carries no rollover: nothing
///   can fit — the complete-request context guard refuses oversized
///   requests typed before they reach the provider — so an unfireable
///   declared trigger is dropped rather than retained.
/// * A seat without a declaration receives no rollover. Declarative
///   no-policy semantics: the host never invents a default policy, and the
///   complete-request guard plus native compaction cover the small-lane
///   case the retired lane-derived default used to paper over.
///
/// Every value comes from declarations (the serving model window, the
/// reserved output, the rollover fields); no model, seat, or lane is
/// hardcoded.
pub fn lane_rollover_config(
    declared: Option<&RolloverRuntimeConfig>,
    context_window_tokens: u32,
    reserve_output_tokens: u32,
) -> Result<Option<RolloverRuntimeConfig>, String> {
    let ceiling = u64::from(context_window_tokens).saturating_sub(u64::from(reserve_output_tokens));
    let Some(config) = declared else {
        return Ok(None);
    };
    if ceiling == 0 {
        return Ok(None);
    }
    let mut policy = config.policy();
    policy.threshold_tokens = policy.threshold_tokens.min(ceiling);
    Ok(Some(RolloverRuntimeConfig::new(policy)?))
}

/// Provider-reported usage of one settled model turn. Every count is the
/// provider's own number; absent fields stay `None`/zero rather than being
/// inferred.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloverUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cache_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub cost_usd: Option<f64>,
}

impl RolloverUsage {
    /// Extracts the provider-reported usage from one terminal `agent_end`
    /// payload. `Some` exactly when at least one numeric token count exists;
    /// anything else is no-accounting, never an estimate.
    pub fn extract(agent_end: &Value) -> Option<Self> {
        let candidates = [
            agent_end.get("usage"),
            agent_end
                .get("message")
                .and_then(|message| message.get("usage")),
            agent_end.get("cost"),
            // The settled assistant message inside a terminal `agent_end`
            // carries this omp shape's own turn accounting (`messages[n]`
            // with a `usage` object of input/output/cacheRead/cacheWrite/
            // totalTokens). The last message reporting one is the turn's;
            // user turns never carry usage.
            agent_end.get("messages").and_then(|messages| {
                messages.as_array().and_then(|frames| {
                    frames
                        .iter()
                        .rev()
                        .find_map(|frame| frame.get("usage").filter(|usage| usage.is_object()))
                })
            }),
            Some(agent_end),
        ];
        for candidate in candidates.into_iter().flatten() {
            let Some(object) = candidate.as_object() else {
                continue;
            };
            let usage = Self {
                input_tokens: count(object, &["input", "inputTokens", "input_tokens"]),
                output_tokens: count(object, &["output", "outputTokens", "output_tokens"]),
                cache_read_tokens: count(
                    object,
                    &[
                        "cacheRead",
                        "cacheReadTokens",
                        "cache_read_tokens",
                        "cachedTokens",
                    ],
                ),
                cache_write_tokens: count(
                    object,
                    &[
                        "cacheWrite",
                        "cacheWriteTokens",
                        "cache_write_tokens",
                        "cacheCreationInputTokens",
                    ],
                ),
                total_tokens: count(object, &["totalTokens", "total_tokens", "total"]),
                cost_usd: cost(
                    object,
                    &["cost", "costUsd", "totalCostUsd", "total_cost_usd"],
                ),
            };
            if usage
                .input_tokens
                .or(usage.output_tokens)
                .or(usage.cache_read_tokens)
                .or(usage.cache_write_tokens)
                .or(usage.total_tokens)
                .is_some()
            {
                return Some(usage);
            }
        }
        None
    }

    /// The context watermark of the turn: input + cacheRead + cacheWrite +
    /// output, saturating.
    pub fn watermark(&self) -> u64 {
        self.input_tokens
            .unwrap_or(0)
            .saturating_add(self.cache_read_tokens.unwrap_or(0))
            .saturating_add(self.cache_write_tokens.unwrap_or(0))
            .saturating_add(self.output_tokens.unwrap_or(0))
    }
}

/// Reads the first integer count under any of `keys`.
fn count(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    for key in keys {
        if let Some(value) = object.get(*key) {
            if let Some(integer) = value.as_u64() {
                return Some(integer);
            }
            if let Some(number) = value.as_f64() {
                if number.is_finite() && number >= 0.0 {
                    return Some(number.round() as u64);
                }
            }
        }
    }
    None
}

/// Reads the first finite float cost under any of `keys`.
fn cost(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    for key in keys {
        if let Some(number) = object.get(*key).and_then(Value::as_f64) {
            if number.is_finite() && number >= 0.0 {
                return Some(number);
            }
        }
    }
    None
}

/// True exactly for a terminal `agent_end` frame: mid-loop frames
/// (`isTerminal: false`, `willContinue: true`) never settle a turn.
pub fn terminal_agent_end(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("agent_end")
        && value.get("isTerminal").and_then(Value::as_bool) != Some(false)
        && value.get("willContinue").and_then(Value::as_bool) != Some(true)
}

/// Bounded durable state of one delegated child: the delegation-link row
/// joined with the live ledger's current session projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloverChildState {
    pub child_session: String,
    pub phase: String,
    pub project: String,
    pub provider: String,
    pub model: String,
    pub depth: u8,
    pub prompt_digest: String,
    pub created_at_ms: u64,
    /// Live-ledger epoch projection, when the child row is still served.
    pub epoch: Option<String>,
    /// Live-ledger event head projection, when the child row is still served.
    pub event_head: Option<String>,
}

/// Host-owned source of delegated-child durable state for the rollover
/// brief. The production factory implements it over the delegation-link
/// ledger and the live ledger; the bridge consumes it read-only.
#[async_trait]
pub trait RolloverChildrenSource: Send + Sync + 'static {
    /// Children of `parent`, bounded by `cap`, newest last.
    async fn children(
        &self,
        parent: &SessionId,
        cap: usize,
    ) -> Result<Vec<RolloverChildState>, String>;
    /// The canonical delegated assignment of `session` itself, when this
    /// session is a delegated child: the exact prompt text persisted at
    /// delegation admission, durable beyond every evictable conversation
    /// tail. `Ok(None)`: this session is nobody's delegated child. A
    /// delegated child whose row predates the field fails `Err` — the
    /// rollover refuses typed rather than absorbing without the
    /// requirements.
    async fn assignment(&self, session: &SessionId) -> Result<Option<String>, String>;
}

/// The durable task record section of the brief.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloverPlanRecord {
    pub revision: i64,
    pub objective: String,
    pub todos: Vec<Value>,
    pub accepted: bool,
}

/// One pending approval of the brief.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloverPendingApproval {
    pub approval_id: String,
    pub capability_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub issuer: String,
    pub requested_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Everything the durable brief is rendered from. Every field is host-read
/// durable state; nothing here is model input.
#[derive(Clone, Debug)]
pub struct RolloverBriefInputs {
    pub session_id: String,
    pub seat_id: String,
    pub project_id: String,
    pub lane_id: String,
    pub provider: String,
    pub model: String,
    pub title: Option<String>,
    pub epoch_before: i64,
    pub observed_watermark: Option<u64>,
    pub threshold_tokens: u64,
    pub plan: Option<RolloverPlanRecord>,
    /// The canonical delegated assignment when this session is a
    /// delegated child: rendered verbatim beside the task record, never
    /// trimmed by the byte budget — the conversation tail absorbs the
    /// budget, and a brief the tail cannot reconcile fails typed instead
    /// of silently cutting the assignment.
    pub assignment: Option<String>,
    pub children: Vec<RolloverChildState>,
    pub pending_approvals: Vec<RolloverPendingApproval>,
    /// Journaled event bodies (newest last), already walk-capped by the
    /// caller at [`ROLLOVER_HISTORY_WALK_CAP`].
    pub events: Vec<Value>,
}

/// Render within the byte budget, retaining the newest conversation entries.
/// If even the newest pair and required metadata cannot fit, fail rather than
/// silently presenting an empty conversation.
pub fn render_brief(
    inputs: &RolloverBriefInputs,
    policy: &RolloverPolicy,
) -> Result<(Value, Vec<u8>), String> {
    let mut rendered = assemble(inputs, policy)?;
    let bytes = serialize(&rendered)?;
    if bytes.len() <= policy.max_brief_bytes {
        return Ok((rendered, bytes));
    }
    let tail = rendered["conversation_tail"]
        .as_array_mut()
        .expect("assemble produces a conversation array");
    let mut excess = bytes.len() - policy.max_brief_bytes;
    let mut remove = 0;
    for entry in tail.iter().take(tail.len().saturating_sub(2)) {
        if excess == 0 {
            break;
        }
        // Removing a prefix entry also removes its following comma.
        excess = excess.saturating_sub(serialize(entry)?.len() + 1);
        remove += 1;
    }
    tail.drain(..remove);
    let trimmed_bytes = serialize(&rendered)?;
    if trimmed_bytes.len() <= policy.max_brief_bytes {
        return Ok((rendered, trimmed_bytes));
    }
    Err(format!(
        "rollover brief still {} bytes after trimming older conversation entries; \
         budget is {}",
        trimmed_bytes.len(),
        policy.max_brief_bytes
    ))
}

fn assemble(inputs: &RolloverBriefInputs, policy: &RolloverPolicy) -> Result<Value, String> {
    let mut conversation_tail = Vec::new();
    let mut failures = Vec::new();
    let start = inputs
        .events
        .len()
        .saturating_sub(ROLLOVER_HISTORY_WALK_CAP);
    for body in &inputs.events[start..] {
        let frame = match body.get("frame") {
            Some(frame) => frame,
            None => continue,
        };
        match body.get("kind").and_then(Value::as_str) {
            Some("command_issued") => {
                if body.get("command").and_then(Value::as_str) == Some("prompt") {
                    if let Some(text) = frame.get("message").and_then(Value::as_str) {
                        conversation_tail.push(json!({
                            "role": "user",
                            "text": truncate_chars(text, ROLLOVER_TAIL_ENTRY_CHARS),
                        }));
                    }
                }
            }
            Some("session") => {
                let frame_type = frame.get("type").and_then(Value::as_str);
                if frame_type == Some("message_end") && role_of(frame) == Some("assistant") {
                    if let Some(text) = message_text(frame) {
                        conversation_tail.push(json!({
                            "role": "assistant",
                            "text": truncate_chars(&text, ROLLOVER_TAIL_ENTRY_CHARS),
                        }));
                    }
                } else if frame_type == Some("tool_execution_end")
                    && frame.get("isError").and_then(Value::as_bool) == Some(true)
                {
                    failures.push(json!({
                        "tool": frame
                            .get("toolName")
                            .or_else(|| frame.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        "detail": truncate_chars(
                            &message_text(frame).unwrap_or_default(),
                            ROLLOVER_FAILURE_DETAIL_CHARS
                        ),
                    }));
                }
            }
            _ => {}
        }
    }
    let keep = policy.history_tail_events.min(conversation_tail.len());
    let tail_start = conversation_tail.len() - keep;
    let conversation_tail = conversation_tail.split_off(tail_start);
    if failures.len() > ROLLOVER_FAILURES_CAP {
        let drop = failures.len() - ROLLOVER_FAILURES_CAP;
        failures.drain(..drop);
    }
    let children = inputs
        .children
        .iter()
        .rev()
        .take(ROLLOVER_CHILDREN_CAP)
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    let mut approvals = inputs.pending_approvals.clone();
    if approvals.len() > ROLLOVER_APPROVALS_CAP {
        let drop = approvals.len() - ROLLOVER_APPROVALS_CAP;
        approvals.drain(..drop);
    }
    let mut brief = json!({
        "schema": "odin.rollover-brief.v1",
        "session": {
            "id": inputs.session_id,
            "seat": inputs.seat_id,
            "project": inputs.project_id,
            "lane": inputs.lane_id,
            "provider": inputs.provider,
            "model": inputs.model,
            "title": inputs.title,
            "epoch_before": inputs.epoch_before,
            "observed_watermark_tokens": inputs.observed_watermark,
            "threshold_tokens": inputs.threshold_tokens,
        },
        "task": inputs.plan,
        "delegated_children": children,
        "pending_approvals": approvals,
        "recent_tool_failures": failures,
        "conversation_tail": conversation_tail,
    });
    if let Some(assignment) = &inputs.assignment {
        brief["delegated_assignment"] = json!(assignment);
    }
    Ok(brief)
}

fn serialize(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|error| format!("rollover brief render failed: {error}"))
}

/// The role of one message-shaped session frame, tolerating both the
/// top-level and nested `message` placements.
fn role_of(frame: &Value) -> Option<&str> {
    frame.get("role").and_then(Value::as_str).or_else(|| {
        frame
            .get("message")
            .and_then(|m| m.get("role"))
            .and_then(Value::as_str)
    })
}

/// The text of one message-shaped session frame: a plain string content or
/// the joined text blocks.
fn message_text(frame: &Value) -> Option<String> {
    let content = frame
        .get("content")
        .or_else(|| frame.get("message").and_then(|m| m.get("content")))?;
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => {
            let mut joined = String::new();
            for block in blocks {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    joined.push_str(text);
                }
            }
            Some(joined)
        }
        _ => None,
    }
}

/// Character-bounded copy with an honest elision marker.
fn truncate_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut truncated: String = text.chars().take(limit).collect();
    truncated.push_str("…[truncated]");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn brief_keeps_recent_turns_when_older_history_exceeds_byte_budget() {
        let policy = RolloverPolicy {
            max_brief_bytes: 1024,
            ..RolloverPolicy::default()
        };
        let inputs = RolloverBriefInputs {
            session_id: "retired-vehicle".to_owned(),
            seat_id: "coordinator".to_owned(),
            project_id: "research".to_owned(),
            lane_id: "conversation".to_owned(),
            provider: "gateway".to_owned(),
            model: "model".to_owned(),
            title: None,
            epoch_before: 1,
            observed_watermark: None,
            threshold_tokens: policy.threshold_tokens,
            plan: None,
            assignment: None,
            children: Vec::new(),
            pending_approvals: Vec::new(),
            events: vec![
                json!({"kind":"command_issued","command":"prompt","frame":{"message":"old".repeat(1024)}}),
                json!({"kind":"session","frame":{"type":"message_end","role":"assistant","content":"old".repeat(1024)}}),
                json!({"kind":"command_issued","command":"prompt","frame":{"message":"recent request"}}),
                json!({"kind":"session","frame":{"type":"message_end","role":"assistant","content":"recent answer"}}),
            ],
        };
        let (brief, bytes) = render_brief(&inputs, &policy).expect("bounded brief");
        assert!(bytes.len() <= policy.max_brief_bytes);
        assert_eq!(
            brief["conversation_tail"],
            json!([
                {"role":"user","text":"recent request"},
                {"role":"assistant","text":"recent answer"},
            ]),
        );
    }

    /// The delegated assignment is durable beyond the bounded history
    /// tail: a long-running worker whose original prompt fell outside the
    /// retained conversation still rolls into a brief that carries its
    /// concrete requirements verbatim, and the continue reinjection
    /// orders the work resumed — the generic child plan alone never
    /// stands in for the assignment.
    #[test]
    fn the_delegated_assignment_rides_the_brief_beyond_the_evicted_tail() {
        let policy = RolloverPolicy {
            history_tail_events: 8,
            ..RolloverPolicy::default()
        };
        let assignment = "Implement the governed worker lifecycle end to end, \
            including the typed rollover bound and its regression tests."
            .to_owned();
        let mut events = vec![json!({
            "kind": "command_issued",
            "command": "prompt",
            "frame": {"message": assignment.clone()},
        })];
        for index in 0..24 {
            events.push(json!({
                "kind": "command_issued",
                "command": "prompt",
                "frame": {"message": format!("later turn {index}")},
            }));
            events.push(json!({
                "kind": "session",
                "frame": {"type": "message_end", "role": "assistant",
                          "content": format!("later answer {index}")},
            }));
        }
        let inputs = RolloverBriefInputs {
            session_id: "rolled-worker".to_owned(),
            seat_id: "worker".to_owned(),
            project_id: "odin".to_owned(),
            lane_id: "lane.odin".to_owned(),
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
            title: None,
            epoch_before: 3,
            observed_watermark: None,
            threshold_tokens: policy.threshold_tokens,
            plan: None,
            assignment: Some(assignment.clone()),
            children: Vec::new(),
            pending_approvals: Vec::new(),
            events,
        };
        let (brief, bytes) = render_brief(&inputs, &policy).expect("bounded brief");
        assert!(bytes.len() <= policy.max_brief_bytes);
        assert_eq!(brief["delegated_assignment"], json!(assignment));
        assert!(
            !brief["conversation_tail"]
                .to_string()
                .contains("governed worker lifecycle"),
            "the original prompt is evicted from the tail; the durable \
             assignment section alone carries it"
        );
        let prompt = continuation_prompt(
            "[ODIN ROLLOVER session=s epoch=3->4]",
            &String::from_utf8_lossy(&bytes),
        );
        assert!(prompt.contains(ROLLOVER_CONTINUE_INSTRUCTION));
        assert!(prompt.contains(&assignment));
        assert!(!prompt.contains(ROLLOVER_ABSORB_INSTRUCTION));
    }

    /// The assignment is never silently cut to fit the byte budget: the
    /// conversation tail absorbs the budget, and a brief the tail cannot
    /// reconcile fails typed instead of truncating the requirements.
    #[test]
    fn an_over_budget_assignment_fails_typed_rather_than_being_cut() {
        let policy = RolloverPolicy {
            max_brief_bytes: 512,
            ..RolloverPolicy::default()
        };
        let assignment = "x".repeat(700);
        let inputs = RolloverBriefInputs {
            session_id: "rolled-worker".to_owned(),
            seat_id: "worker".to_owned(),
            project_id: "odin".to_owned(),
            lane_id: "lane.odin".to_owned(),
            provider: "gateway".to_owned(),
            model: "glm-flash".to_owned(),
            title: None,
            epoch_before: 1,
            observed_watermark: None,
            threshold_tokens: policy.threshold_tokens,
            plan: None,
            assignment: Some(assignment),
            children: Vec::new(),
            pending_approvals: Vec::new(),
            events: vec![
                json!({"kind":"command_issued","command":"prompt","frame":{"message":"first"}}),
                json!({"kind":"session","frame":{"type":"message_end","role":"assistant","content":"second"}}),
            ],
        };
        let rendered = render_brief(&inputs, &policy)
            .expect_err("an assignment the budget cannot carry fails typed");
        assert!(
            rendered.contains("budget"),
            "the failure names the budget: {rendered}"
        );
    }

    /// Usage belongs to the settled assistant message, not the `agent_end` frame.
    #[test]
    fn usage_reads_the_settled_assistant_message_of_a_terminal_agent_end() {
        let frame = json!({
            "type": "agent_end",
            "isTerminal": true,
            "messages": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Reply with the single word: acknowledged."}],
                    "timestamp": 1789507331551i64
                },
                {
                    "role": "assistant",
                    "api": "openai-codex-responses",
                    "content": [{"type": "text", "text": "Noted."}],
                    "usage": {
                        "cacheRead": 0,
                        "cacheWrite": 0,
                        "cost": {
                            "cacheRead": 0.00486,
                            "cacheWrite": 0,
                            "input": 0.00192,
                            "output": 0.00035,
                            "total": 0.00713
                        },
                        "input": 4860,
                        "output": 48,
                        "reasoningTokens": 32,
                        "totalTokens": 4908
                    }
                }
            ]
        });
        let usage =
            RolloverUsage::extract(&frame).expect("assistant-message usage must be measured");
        assert_eq!(usage.input_tokens, Some(4860));
        assert_eq!(usage.output_tokens, Some(48));
        assert_eq!(usage.cache_read_tokens, Some(0));
        assert_eq!(usage.cache_write_tokens, Some(0));
        assert_eq!(usage.total_tokens, Some(4908));
        assert_eq!(usage.watermark(), 4908);
    }

    /// No numeric count anywhere stays no-accounting: the trigger must never
    /// estimate from message text or frame shape alone.
    #[test]
    fn usage_without_any_token_count_is_none() {
        let frame = json!({
            "type": "agent_end",
            "isTerminal": true,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "hello"}]}
            ]
        });
        assert_eq!(RolloverUsage::extract(&frame), None);
    }
}

#[cfg(test)]
mod compose_seat_rollovers_tests {
    use std::collections::BTreeMap;

    use odin_domain::SeatId;

    use super::{compose_seat_rollovers, RolloverPolicy, RolloverRuntimeConfig};

    fn declared(threshold: u64) -> RolloverRuntimeConfig {
        RolloverRuntimeConfig::new(RolloverPolicy {
            threshold_tokens: threshold,
            ..RolloverPolicy::default()
        })
        .expect("declared policy is valid")
    }

    fn seat(id: &str) -> SeatId {
        SeatId::new(id).expect("seat id")
    }

    /// Main-line guarantee: a seat whose lane evaluation drops the policy
    /// (degenerate ceiling) must NOT get the raw declaration back through
    /// a fallback re-insert — the drop is the composed answer.
    #[test]
    fn a_dropped_declaration_is_never_reinserted_raw() {
        let seats = [(seat("s"), Some((4_096u32, 4_096u32)))];
        let mut declared_map = BTreeMap::new();
        declared_map.insert(seat("s"), declared(12_000));
        let composed = compose_seat_rollovers(&seats, &declared_map).expect("composition");
        assert!(
            composed.is_empty(),
            "the degenerate-lane drop must not be bypassed by a raw re-insert"
        );
    }

    /// A healthy declared policy is narrowed once, by the lane ceiling.
    #[test]
    fn a_healthy_declaration_is_narrowed_once() {
        let seats = [(seat("s"), Some((16_384u32, 4_096u32)))];
        let mut declared_map = BTreeMap::new();
        declared_map.insert(seat("s"), declared(180_000));
        let composed = compose_seat_rollovers(&seats, &declared_map).expect("composition");
        assert_eq!(
            composed
                .get(&seat("s"))
                .expect("policy present")
                .policy()
                .threshold_tokens,
            12_288
        );
    }

    /// A declared rollover on a seat without a context policy stands
    /// exactly: no lane ceiling exists to narrow against.
    #[test]
    fn a_declaration_without_a_context_lane_stands_exactly() {
        let seats = [(seat("s"), None)];
        let mut declared_map = BTreeMap::new();
        declared_map.insert(seat("s"), declared(180_000));
        let composed = compose_seat_rollovers(&seats, &declared_map).expect("composition");
        assert_eq!(
            composed
                .get(&seat("s"))
                .expect("policy present")
                .policy()
                .threshold_tokens,
            180_000
        );
    }

    /// An undeclared seat composes nothing, with or without a lane.
    #[test]
    fn an_undeclared_seat_composes_nothing() {
        let seats = [(seat("s"), Some((16_384u32, 4_096u32))), (seat("t"), None)];
        let composed = compose_seat_rollovers(&seats, &BTreeMap::new()).expect("composition");
        assert!(composed.is_empty());
    }
}

#[cfg(test)]
mod lane_rollover_config_tests {
    use super::{lane_rollover_config, RolloverPolicy, RolloverRuntimeConfig};

    fn declared(threshold: u64) -> RolloverRuntimeConfig {
        RolloverRuntimeConfig::new(RolloverPolicy {
            threshold_tokens: threshold,
            ..RolloverPolicy::default()
        })
        .expect("declared policy is valid")
    }

    /// The context-window defect: an explicit rollover threshold above the
    /// lane's usable window can never fire before the provider's own
    /// length limit. The lane-derived ceiling always narrows it.
    #[test]
    fn an_explicit_threshold_above_the_lane_window_is_narrowed_to_the_ceiling() {
        let explicit = declared(180_000);
        let effective = lane_rollover_config(Some(&explicit), 16_384, 4_096)
            .expect("composition succeeds")
            .expect("a declared policy stays configured");
        assert_eq!(
            effective.policy().threshold_tokens,
            12_288,
            "min(declared, window - reserve)"
        );
    }

    /// Declarative no-policy semantics: a seat that declares no rollover
    /// runs no rollover on ANY lane. The retired lane-derived default used
    /// to invent a policy for small undeclared lanes; the complete-request
    /// context guard now refuses oversize requests honestly before the
    /// provider, so no lane needs an implicit policy to survive its size.
    #[test]
    fn an_undeclared_seat_runs_no_rollover_on_any_lane() {
        assert!(
            lane_rollover_config(None, 16_384, 4_096)
                .expect("composition succeeds")
                .is_none(),
            "a small undeclared lane must not grow an implicit rollover"
        );
        assert!(
            lane_rollover_config(None, 1_048_576, 65_536)
                .expect("composition succeeds")
                .is_none(),
            "a large undeclared lane keeps the no-rollover behavior"
        );
        assert!(lane_rollover_config(None, u32::MAX, 1)
            .expect("composition succeeds")
            .is_none());
    }

    /// An explicit declaration below the ceiling is kept exactly — the
    /// lane narrowing never widens a deliberate operator choice.
    #[test]
    fn an_explicit_threshold_below_the_ceiling_is_kept_exactly() {
        let explicit = declared(50_000);
        let effective = lane_rollover_config(Some(&explicit), 1_048_576, 65_536)
            .expect("composition succeeds")
            .expect("a declared policy stays configured");
        assert_eq!(effective.policy().threshold_tokens, 50_000);
    }

    /// An explicit declaration exactly at the ceiling is kept exactly —
    /// the narrowing is `min`, not a strict shrink.
    #[test]
    fn an_explicit_threshold_at_the_ceiling_is_kept_exactly() {
        let explicit = declared(12_288);
        let effective = lane_rollover_config(Some(&explicit), 16_384, 4_096)
            .expect("composition succeeds")
            .expect("a declared policy stays configured");
        assert_eq!(effective.policy().threshold_tokens, 12_288);
    }

    /// A degenerate lane whose window does not exceed its reserve carries
    /// no rollover — not even an explicit declaration: nothing can fit,
    /// the complete-request context guard refuses oversized requests typed
    /// before they reach the provider, and an unfireable trigger is
    /// dropped rather than retained.
    #[test]
    fn a_degenerate_zero_ceiling_lane_carries_no_rollover() {
        assert!(lane_rollover_config(None, 4_096, 4_096)
            .expect("composition succeeds")
            .is_none());
        let explicit = declared(12_000);
        assert!(
            lane_rollover_config(Some(&explicit), 4_096, 4_096)
                .expect("composition succeeds")
                .is_none(),
            "an unfireable declared trigger on a degenerate lane is dropped"
        );
    }
}

#[cfg(test)]
mod brief_budget_tests {
    use super::*;

    /// Continuity briefs must fit the declared item ceiling with control/schema headroom.
    #[test]
    fn default_brief_budget_fits_the_smallest_declared_item_ceiling() {
        // Read declarations so reduced item ceilings cannot silently invalidate the budget.
        let registry = concat!(env!("CARGO_MANIFEST_DIR"), "/../../registry/slices");
        let mut smallest = usize::MAX;
        for entry in std::fs::read_dir(registry).expect("registry slices readable") {
            let text = std::fs::read_to_string(entry.expect("entry").path().join("slice.toml"))
                .expect("slice toml");
            for line in text.lines() {
                if let Some(value) = line.trim().strip_prefix("max_item_tokens = ") {
                    let ceiling: usize = value.trim().parse().expect("max_item_tokens");
                    smallest = smallest.min(ceiling);
                }
            }
        }
        assert!(
            ROLLOVER_BRIEF_BYTES_DEFAULT < smallest,
            "the default brief budget {} must fit the smallest declared item ceiling {}",
            ROLLOVER_BRIEF_BYTES_DEFAULT,
            smallest
        );
        // And the renderer actually honors it under a huge tail: the
        // bounded newest-first trim produces a brief inside the budget.
        let mut turns = Vec::new();
        for index in 0..200 {
            turns.push(format!("turn {index}: {}", "continuity detail ".repeat(40)));
        }
        let rendered = render_tail_bounded(&turns, &RolloverPolicy::default());
        assert!(rendered.len() <= ROLLOVER_BRIEF_BYTES_DEFAULT);
    }

    /// Renders the newest-first bounded tail the way the brief does: each
    /// turn one line, oldest dropped first, hard byte cap.
    fn render_tail_bounded(turns: &[String], policy: &RolloverPolicy) -> String {
        let mut kept: Vec<&str> = Vec::new();
        let mut bytes = 0_usize;
        for turn in turns.iter().rev() {
            let cost = turn.len() + 1;
            if bytes + cost > policy.max_brief_bytes {
                break;
            }
            bytes += cost;
            kept.push(turn);
        }
        kept.reverse();
        kept.join("\n")
    }
}
