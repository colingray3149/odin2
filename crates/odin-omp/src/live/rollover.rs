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
/// Absolute-mode ceiling. A declared window fraction is not subject to
/// it: half of a 1_000_000-token card is 500_000, and the stored policy
/// must be able to hold that resolved watermark.
pub const ROLLOVER_THRESHOLD_TOKENS_MAX: u64 = 2_000_000;
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
/// context. An agentic turn here held every restart's vehicle open for
/// minutes of tool calls before the owner could be answered, so the
/// successor absorbs and waits for its next request.
pub const ROLLOVER_ABSORB_INSTRUCTION: &str = "Continuity context from your previous session. \
    The owner's next request follows it. This turn closes on a one-word reply: ready.";

/// The continuity brief a conversation successor's first real turn carries
/// ahead of its own message: context, not a request, and no turn of its own.
pub const ROLLOVER_CARRY_INSTRUCTION: &str = "Continuity context from your previous session. \
    This turn's own message follows it.";

/// The reinjection turn of a delegated worker: the brief carries the
/// original delegated assignment beside the bounded progress summary,
/// and the turn is the work order. The fresh incarnation is the same
/// worker resuming the interrupted unit.
pub const ROLLOVER_CONTINUE_INSTRUCTION: &str = "Continuity context from your previous session: \
    the brief below carries your original delegated assignment and your progress so far. This \
    turn resumes the assigned unit where it stopped. Finished work stays done.";

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

/// The brief a conversation successor's first turn carries: the marker
/// header, the carry instruction and the bounded brief, which the turn's own
/// text follows.
pub fn carried_prompt(header: &str, brief: &str) -> String {
    instructed_prompt(header, ROLLOVER_CARRY_INSTRUCTION, brief)
}

/// The delegated worker's reinjection: the continuity brief and the order
/// to continue the interrupted unit in ONE canonical turn.
pub fn continuation_prompt(header: &str, brief: &str) -> String {
    instructed_prompt(header, ROLLOVER_CONTINUE_INSTRUCTION, brief)
}

/// The notes file a pod writes at its checkpoint and reads after a rollover.
pub const POD_NOTES_PATH: &str = "/export/notes.md";
/// The report a pod writes on its last allowed rollover, then finishes.
pub const POD_REPORT_PATH: &str = "/export/report.md";

/// The mid-turn checkpoint steer of a pod: its context crossed the declared
/// checkpoint while the turn runs on, so it writes its notes now and keeps working.
pub fn pod_checkpoint_prompt(percent: u64) -> String {
    format!(
        "Your context is at {percent}% of its window. Write your working notes now to \
         {POD_NOTES_PATH}: findings with their sources, and which brief items are done and which \
         are still open. Keep working after that; when the window fills you continue in a fresh \
         context that starts from those notes."
    )
}

/// A pod's reinjection after a rollover: the notes and the launch inputs to read first.
/// On the last allowed rollover it orders the report instead.
pub fn pod_continuation_prompt(header: &str, brief: &str, inputs: &[String], last: bool) -> String {
    let launch = match inputs.is_empty() {
        true => String::new(),
        false => format!(" and the launch input is at {}", inputs.join(", ")),
    };
    let instruction = match last {
        true => format!(
            "Continuity context from your previous session. This is your last context: your \
             notes are in {POD_NOTES_PATH}{launch}; read them, then write {POD_REPORT_PATH} now \
             from them and finish. Report unfinished items as unmet."
        ),
        false => format!(
            "Continuity context from your previous session. Your notes are in \
             {POD_NOTES_PATH}{launch}; read them first, then continue the open items. Finished \
             work stays done."
        ),
    };
    instructed_prompt(header, &instruction, brief)
}

/// Bounded wait for the reinjection turn to settle before the usage record.
pub const ROLLOVER_REINJECTION_SETTLE_BUDGET: Duration = Duration::from_secs(300);
/// Settled terminal turns required after a rollover before the next trigger.
pub const ROLLOVER_MIN_SETTLED_TURNS: u32 = 2;
/// Inclusive bounds of a declared window fraction (percent of the selected
/// model card's context window).
pub const ROLLOVER_WINDOW_FRACTION_MIN: u8 = 1;
pub const ROLLOVER_WINDOW_FRACTION_MAX: u8 = 99;
/// The generic half-window trigger: 50% of the selected card.
pub const ROLLOVER_WINDOW_FRACTION_HALF: u8 = 50;
/// Inclusive bounds of how many same-session rollovers a seat may take
/// before the next one retires it and opens a fresh session.
pub const ROLLOVER_FRESH_AFTER_MIN: u8 = 1;
pub const ROLLOVER_FRESH_AFTER_MAX: u8 = 16;
/// Slow heartbeat bounds, in minutes. Five minutes is the routine floor;
/// a day is the ceiling. Thirty minutes is the declared backstop.
pub const ROLLOVER_HEARTBEAT_MINUTES_MIN: u16 = 5;
pub const ROLLOVER_HEARTBEAT_MINUTES_MAX: u16 = 1_440;
pub const ROLLOVER_HEARTBEAT_MINUTES_DEFAULT: u16 = 30;

/// Declared, bounded rollover policy. Every field has a compiled default;
/// [`RolloverPolicy::validate`] enforces the ceilings independently of any
/// config parser so an incorrectly mapped composition still fails closed.
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
    /// Trigger at this percent of the selected model card's context window.
    /// Absent keeps the absolute [`Self::threshold_tokens`] watermark, which
    /// remains the cap a fraction may not exceed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_fraction: Option<u8>,
    /// After this many same-session rollovers, the next trigger retires the
    /// session and opens a fresh one. Absent keeps same-session rollover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh_after_rollovers: Option<u8>,
    /// Slow backstop heartbeat in minutes. Absent means events alone wake
    /// the seat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_minutes: Option<u16>,
    /// `changed` skips a heartbeat when nothing the seat watches moved.
    #[serde(default, skip_serializing_if = "HeartbeatWhen::is_always")]
    pub heartbeat_when: HeartbeatWhen,
    /// A prompt is new information: retire and open fresh instead of
    /// injecting into the running session. Absent keeps injection.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fresh_on_new_information: bool,
}

/// When a declared heartbeat fires: every interval, or only when what the
/// seat watches moved since the last one.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatWhen {
    #[default]
    Always,
    Changed,
}

impl HeartbeatWhen {
    pub fn is_always(&self) -> bool {
        *self == Self::Always
    }
}

impl Default for RolloverPolicy {
    fn default() -> Self {
        Self {
            threshold_tokens: ROLLOVER_THRESHOLD_TOKENS_DEFAULT,
            max_brief_bytes: ROLLOVER_BRIEF_BYTES_DEFAULT,
            history_tail_events: ROLLOVER_HISTORY_TAIL_DEFAULT,
            window_fraction: None,
            fresh_after_rollovers: None,
            heartbeat_minutes: None,
            heartbeat_when: HeartbeatWhen::Always,
            fresh_on_new_information: false,
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
        if self.window_fraction.is_some_and(|fraction| {
            !(ROLLOVER_WINDOW_FRACTION_MIN..=ROLLOVER_WINDOW_FRACTION_MAX).contains(&fraction)
        }) {
            return Err(format!(
                "rollover window_fraction {:?} must be in \
                 {ROLLOVER_WINDOW_FRACTION_MIN}..={ROLLOVER_WINDOW_FRACTION_MAX}",
                self.window_fraction
            ));
        }
        if self.fresh_after_rollovers.is_some_and(|count| {
            !(ROLLOVER_FRESH_AFTER_MIN..=ROLLOVER_FRESH_AFTER_MAX).contains(&count)
        }) {
            return Err(format!(
                "rollover fresh_after_rollovers {:?} must be in \
                 {ROLLOVER_FRESH_AFTER_MIN}..={ROLLOVER_FRESH_AFTER_MAX}",
                self.fresh_after_rollovers
            ));
        }
        if self.heartbeat_minutes.is_some_and(|minutes| {
            !(ROLLOVER_HEARTBEAT_MINUTES_MIN..=ROLLOVER_HEARTBEAT_MINUTES_MAX).contains(&minutes)
        }) {
            return Err(format!(
                "rollover heartbeat_minutes {:?} must be in \
                 {ROLLOVER_HEARTBEAT_MINUTES_MIN}..={ROLLOVER_HEARTBEAT_MINUTES_MAX}",
                self.heartbeat_minutes
            ));
        }
        Ok(())
    }

    /// The provider-token watermark this policy fires at for one selected
    /// model card. A declared fraction is exactly that percent of the card
    /// window: a 1_000_000-token card at 50% fires at 500_000, and neither
    /// `threshold_tokens` nor the absolute cap applies. No fraction
    /// keeps the absolute watermark, narrowed to the lane ceiling. A zero
    /// window cannot fire. `ceiling` is the lane bound used only by the
    /// absolute mode; fractional mode ignores it.
    pub fn threshold_for_window(&self, context_window_tokens: u64, ceiling: u64) -> Option<u64> {
        if let Some(fraction) = self.window_fraction {
            if context_window_tokens == 0 {
                return None;
            }
            let tokens = context_window_tokens.saturating_mul(u64::from(fraction)) / 100;
            return (tokens > 0).then_some(tokens);
        }
        if ceiling == 0 {
            return None;
        }
        Some(self.threshold_tokens.min(ceiling).max(1))
    }

    /// Whether the next trigger, after `completed` same-session rollovers,
    /// retires this session and opens a fresh one. A seat that declares no
    /// fresh bound never retires for rollover count.
    pub fn fresh_due(&self, completed: u32) -> bool {
        fresh_open_due(self, completed, false).is_some()
    }

    /// The declared backstop, or none. A seat that declares no heartbeat
    /// is woken only by events.
    pub fn heartbeat(&self) -> Option<std::time::Duration> {
        self.heartbeat_minutes
            .map(|minutes| std::time::Duration::from_secs(u64::from(minutes).saturating_mul(60)))
    }
}

/// A workload pod's rollover contract. Its checkpoint is the policy's window
/// fraction; this carries the rollover budget and the launch inputs the
/// continuation names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodRollover {
    /// Rollovers the run may begin before it stops; `None` is unbounded.
    pub max_rollovers: Option<u8>,
    /// The staged launch input paths, named to every continuation.
    pub launch_inputs: Vec<String>,
}

impl PodRollover {
    /// Admits one more rollover after `begun` have begun. `Ok(true)` names the
    /// last one the budget allows; `Err` names a spent budget.
    pub fn admit(&self, begun: u32) -> Result<bool, String> {
        let Some(max) = self.max_rollovers.map(u32::from) else {
            return Ok(false);
        };
        if begun < max {
            return Ok(begun + 1 == max);
        }
        Err(format!(
            "pod rollover budget spent: {begun} of {max} rollovers begun; the run settles \
             with the report it has"
        ))
    }
}

/// Composed rollover configuration carried by
/// [`crate::bridge::OmpBridgeConfig`] and
/// [`crate::live::runtime::ProductionBridgeRuntimeConfig`]. Constructed
/// only through [`Self::new`] or [`Self::for_pod`], which validate the policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloverRuntimeConfig {
    policy: RolloverPolicy,
    pod: Option<PodRollover>,
}

impl RolloverRuntimeConfig {
    /// Validates and assembles one configuration.
    pub fn new(policy: RolloverPolicy) -> Result<Self, String> {
        policy.validate()?;
        Ok(Self { policy, pod: None })
    }

    /// Validates and assembles one workload pod's configuration.
    pub fn for_pod(policy: RolloverPolicy, pod: PodRollover) -> Result<Self, String> {
        policy.validate()?;
        Ok(Self {
            policy,
            pod: Some(pod),
        })
    }

    pub fn policy(&self) -> RolloverPolicy {
        self.policy.clone()
    }

    /// The pod contract, or `None` for a seat session.
    pub fn pod(&self) -> Option<&PodRollover> {
        self.pod.as_ref()
    }

    /// Whether a settled turn past the threshold rolls the session. A pod's
    /// settled turn is its answer, which its report settles; it rolls only when
    /// its window refuses a request, from the notes its checkpoint asked for.
    pub fn rolls_at_settled_turns(&self) -> bool {
        self.pod.is_none()
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
///   complete-request guard plus native compaction cover the small-lane case.
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
    // A declared fraction is resolved later against the selected card's
    // full window. Narrowing the absolute field here would cap a 50%
    // trigger at the 250_000 ceiling, so fractional mode leaves it alone.
    if policy.window_fraction.is_none() {
        policy.threshold_tokens = policy.threshold_tokens.min(ceiling);
    }
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
                        "cache_read_input_tokens",
                        "cachedTokens",
                    ],
                ),
                cache_write_tokens: count(
                    object,
                    &[
                        "cacheWrite",
                        "cacheWriteTokens",
                        "cache_write_tokens",
                        "cache_creation_input_tokens",
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

/// Reads the first integer count under any of `keys`; a fractional number is a dollar
/// figure, not a token count.
fn count(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
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

/// The durable rows every context restart carries: the run's task plan
/// with its acceptance, and the approvals still pending on the session or its run.
/// OMP's rollover brief and loom's summary both read them here.
pub fn durable_rows(
    ledger: &odin_ledger::Ledger,
    session_id: &SessionId,
    run_id: &odin_domain::RunId,
) -> Result<(Option<RolloverPlanRecord>, Vec<RolloverPendingApproval>), odin_ledger::LedgerError> {
    use odin_ledger::LedgerError;
    let plan = match ledger
        .plan(run_id)
        .map_err(|error| LedgerError::invalid_data_caused_by("plan load failed", error))?
    {
        Some(plan) => {
            let accepted = ledger.plan_is_accepted(run_id).map_err(|error| {
                LedgerError::invalid_data_caused_by("plan acceptance load failed", error)
            })?;
            Some(RolloverPlanRecord {
                revision: plan.revision,
                objective: plan.objective.clone(),
                todos: plan
                    .todos
                    .iter()
                    .map(|todo| {
                        json!({
                            "id": todo.id,
                            "ordinal": todo.ordinal,
                            "title": todo.title,
                            "status": todo.status,
                        })
                    })
                    .collect(),
                accepted,
            })
        }
        None => None,
    };
    let unix_ms = |at: time::OffsetDateTime| (at.unix_timestamp_nanos() / 1_000_000).max(0) as i64;
    let pending_approvals = ledger
        .approvals()
        .map_err(|error| LedgerError::invalid_data_caused_by("approval load failed", error))?
        .into_iter()
        .filter(|approval| {
            // Gated calls target the session's run; other requests the session itself.
            matches!(approval.status, odin_domain::ApprovalStatus::Requested)
                && match approval.scope.target_kind.as_str() {
                    "session" => approval.scope.target_id == session_id.as_str(),
                    "run" => approval.scope.target_id == run_id.as_str(),
                    _ => false,
                }
        })
        .map(|approval| RolloverPendingApproval {
            approval_id: approval.approval_id.to_string(),
            capability_id: approval.scope.capability_id.to_string(),
            target_kind: approval.scope.target_kind.clone(),
            target_id: approval.scope.target_id.clone(),
            issuer: approval.issuer.clone(),
            requested_at_ms: unix_ms(approval.requested_at),
            expires_at_ms: unix_ms(approval.expires_at),
        })
        .collect();
    Ok((plan, pending_approvals))
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
    let trimmed_bytes = trim_oldest(
        &mut rendered,
        "conversation_tail",
        2,
        bytes.len() - policy.max_brief_bytes,
    )?;
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

/// Drops the oldest entries of the brief's `key` array, keeping at least the newest `keep`,
/// until `excess` bytes are covered, and returns the re-serialized brief.
fn trim_oldest(
    rendered: &mut Value,
    key: &str,
    keep: usize,
    excess: usize,
) -> Result<Vec<u8>, String> {
    let entries = rendered[key]
        .as_array_mut()
        .expect("the brief carries its array");
    let mut excess = excess;
    let mut remove = 0;
    for entry in entries.iter().take(entries.len().saturating_sub(keep)) {
        if excess == 0 {
            break;
        }
        // Removing a prefix entry also removes its following comma.
        excess = excess.saturating_sub(serialize(entry)?.len() + 1);
        remove += 1;
    }
    entries.drain(..remove);
    serialize(rendered)
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

/// One lane note the fresh brief may carry. Host-read durable text; the
/// caller names the task the note was pinned to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshBriefNote {
    pub task: String,
    pub seat: String,
    pub noted_at: String,
    pub note: String,
}

/// One project memory entry the fresh brief may carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshBriefMemory {
    pub source: String,
    pub text: String,
}

/// One repository observation the fresh brief may carry: git status and
/// branch, already rendered by `state.repos`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshBriefRepo {
    pub project: String,
    pub summary: String,
}

/// The knowledge a fresh session starts from. Notes, project memory, and
/// repository state are host-read durable text. `owner_text` is the opener's
/// exact words when new information retires the running session; it is not a
/// caller or target identity, and it is never shortened to fit the budget.
#[derive(Clone, Debug, Default)]
pub struct FreshBriefSources {
    pub notes: Vec<FreshBriefNote>,
    pub project_memory: Vec<FreshBriefMemory>,
    pub repos: Vec<FreshBriefRepo>,
    /// Why this session is fresh: the rollover bound, or new information.
    /// The reason names the policy, not who asked.
    pub reason: String,
    /// Exact owner text that caused a new-information replacement. Empty
    /// when the fresh open has no owner prompt (a rollover bound). Never
    /// truncated: a brief that cannot carry it whole is refused.
    pub owner_text: String,
}

/// How many notes, memory entries, and repo summaries one fresh brief keeps.
pub const FRESH_BRIEF_NOTES_CAP: usize = 16;
pub const FRESH_BRIEF_MEMORY_CAP: usize = 8;
pub const FRESH_BRIEF_REPOS_CAP: usize = 8;
pub const FRESH_BRIEF_ENTRY_CHARS: usize = 600;

/// Renders the fresh-session brief inside the policy byte budget. Older
/// notes drop first; required metadata never drops. Owner text, when
/// present, is copied exactly and is never one of the dropped fields. An
/// empty source set still renders the reason, so a fresh open is never a
/// blank prompt. A brief that cannot carry the exact owner text inside the
/// budget is refused rather than shortened.
pub fn render_fresh_brief(
    sources: &FreshBriefSources,
    policy: &RolloverPolicy,
) -> Result<(Value, Vec<u8>), String> {
    let notes: Vec<Value> = sources
        .notes
        .iter()
        .rev()
        .take(FRESH_BRIEF_NOTES_CAP)
        .rev()
        .map(|note| {
            json!({
                "task": note.task,
                "seat": note.seat,
                "noted_at": note.noted_at,
                "note": truncate_chars(&note.note, FRESH_BRIEF_ENTRY_CHARS),
            })
        })
        .collect();
    let memory: Vec<Value> = sources
        .project_memory
        .iter()
        .take(FRESH_BRIEF_MEMORY_CAP)
        .map(|entry| {
            json!({
                "source": entry.source,
                "text": truncate_chars(&entry.text, FRESH_BRIEF_ENTRY_CHARS),
            })
        })
        .collect();
    let repos: Vec<Value> = sources
        .repos
        .iter()
        .take(FRESH_BRIEF_REPOS_CAP)
        .map(|repo| {
            json!({
                "project": repo.project,
                "summary": truncate_chars(&repo.summary, FRESH_BRIEF_ENTRY_CHARS),
            })
        })
        .collect();
    let mut rendered = json!({
        "schema": "odin.fresh-supervisor-brief.v1",
        "reason": truncate_chars(&sources.reason, FRESH_BRIEF_ENTRY_CHARS),
        "task_notes": notes,
        "project_memory": memory,
        "repos": repos,
    });
    if !sources.owner_text.is_empty() {
        rendered["owner_text"] = Value::String(sources.owner_text.clone());
    }
    let bytes = serialize(&rendered)?;
    if bytes.len() <= policy.max_brief_bytes {
        return Ok((rendered, bytes));
    }
    let trimmed = trim_oldest(
        &mut rendered,
        "task_notes",
        0,
        bytes.len() - policy.max_brief_bytes,
    )?;
    if trimmed.len() <= policy.max_brief_bytes {
        return Ok((rendered, trimmed));
    }
    Err(format!(
        "fresh brief still {} bytes after dropping older task notes; budget is {}; owner text is carried exactly and is not trimmed",
        trimmed.len(),
        policy.max_brief_bytes
    ))
}

/// The prompt a fresh session starts on: the shared rollover marker, the
/// absorb instruction, and the bounded knowledge brief. The old transcript
/// is not inlined; it stays readable on the retired session.
pub fn fresh_prompt(brief: &str) -> String {
    continuity_prompt(&format!("{ROLLOVER_PROMPT_MARKER}]"), brief)
}

/// Whether a seat's declared heartbeat fires now: a heartbeat that has never fired is due on
/// the first observation, and the interval is the declaration, so a caller that checks more
/// often still fires at most once per interval. A zero interval never fires.
pub fn heartbeat_due(
    interval: std::time::Duration,
    last: Option<std::time::Instant>,
    now: std::time::Instant,
) -> bool {
    if interval.is_zero() {
        return false;
    }
    last.is_none_or(|at| now.saturating_duration_since(at) >= interval)
}

/// Why a session opens fresh instead of receiving another injection.
/// The reason is the declaration: the rollover bound, or new information
/// the opener supplied. It never names a caller or a target seat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshOpenReason {
    /// `completed` same-session rollovers have reached the declared bound.
    RolloverBound { completed: u32, bound: u8 },
    /// The opener has new information; injecting it into the running
    /// session is refused by the declaration.
    NewInformation,
}

impl FreshOpenReason {
    pub fn label(self) -> String {
        match self {
            Self::RolloverBound { completed, bound } => {
                format!("rollover bound reached after {completed} rollovers (declared {bound})")
            }
            Self::NewInformation => {
                "new information; a fresh session replaces injection".to_owned()
            }
        }
    }
}

/// Whether the next trigger retires this session. `completed` is the count
/// of same-session rollovers already finished; the bound comes only from
/// the policy. A policy with no fresh bound never retires.
pub fn fresh_open_due(
    policy: &RolloverPolicy,
    completed: u32,
    new_information: bool,
) -> Option<FreshOpenReason> {
    if new_information && policy.fresh_on_new_information {
        return Some(FreshOpenReason::NewInformation);
    }
    policy.fresh_after_rollovers.and_then(|bound| {
        (completed >= u32::from(bound))
            .then_some(FreshOpenReason::RolloverBound { completed, bound })
    })
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
}

#[test]
fn a_window_fraction_follows_the_card_and_an_absolute_threshold_holds() {
    let fresh_after = 3;
    let policy = RolloverPolicy {
        window_fraction: Some(ROLLOVER_WINDOW_FRACTION_HALF),
        fresh_after_rollovers: Some(fresh_after),
        ..RolloverPolicy::default()
    };
    policy.validate().expect("half-window policy");
    // The declared share of the selected card; the absolute field and the
    // lane ceiling do not apply in fractional mode.
    let half = u64::from(ROLLOVER_WINDOW_FRACTION_HALF);
    for (window, ceiling) in [(200_000, 180_000), (1_000_000, 40_000)] {
        assert_eq!(
            policy.threshold_for_window(window, ceiling),
            Some(window * half / 100)
        );
    }
    assert!(policy.threshold_for_window(0, 100).is_none());
    assert!(!policy.fresh_due(u32::from(fresh_after) - 1));
    assert!(policy.fresh_due(u32::from(fresh_after)));
    let absolute = RolloverPolicy {
        window_fraction: None,
        fresh_after_rollovers: None,
        ..RolloverPolicy::default()
    };
    assert!(!absolute.fresh_due(99));
    assert_eq!(
        absolute.threshold_for_window(500_000, 400_000),
        Some(absolute.threshold_tokens.min(400_000))
    );
}

#[test]
fn a_fresh_brief_keeps_task_notes_project_memory_and_repo_state() {
    let policy = RolloverPolicy {
        max_brief_bytes: 8_000,
        ..RolloverPolicy::default()
    };
    let sources = FreshBriefSources {
        notes: vec![FreshBriefNote {
            task: "lane-7".into(),
            seat: "builder".into(),
            noted_at: "2026-10-27T00:00:00Z".into(),
            note: "the sim stalled after the second restart".into(),
        }],
        project_memory: vec![FreshBriefMemory {
            source: "memory.project.odin".into(),
            text: "prefer the declared capsule over a host shell".into(),
        }],
        repos: vec![FreshBriefRepo {
            project: "odin".into(),
            summary: "branch seat/builder/sim\nworking tree tracked changes: clean".into(),
        }],
        reason: "rollover bound reached".into(),
        owner_text: String::new(),
    };
    let (brief, bytes) = render_fresh_brief(&sources, &policy).expect("brief");
    assert!(bytes.len() <= policy.max_brief_bytes);
    assert_eq!(brief["task_notes"][0]["task"], "lane-7");
    assert_eq!(brief["project_memory"][0]["source"], "memory.project.odin");
    assert_eq!(brief["repos"][0]["project"], "odin");
    assert!(
        brief.get("seat").is_none(),
        "the brief names sources, not a caller"
    );
    let prompt = fresh_prompt(&String::from_utf8(bytes.clone()).unwrap());
    assert!(prompt.starts_with(ROLLOVER_PROMPT_MARKER));
    assert!(prompt.contains("lane-7"));
}

#[test]
fn a_fresh_brief_carries_owner_text_exactly_and_refuses_to_trim_it() {
    let owner = "  keep this exact: \"lane-7\"\nnot a summary  ";
    let policy = RolloverPolicy {
        max_brief_bytes: 8_000,
        ..RolloverPolicy::default()
    };
    let sources = FreshBriefSources {
        reason: "new information".into(),
        owner_text: owner.to_owned(),
        ..FreshBriefSources::default()
    };
    let (brief, bytes) = render_fresh_brief(&sources, &policy).expect("brief");
    assert_eq!(brief["owner_text"], owner);
    let prompt = fresh_prompt(&String::from_utf8(bytes).unwrap());
    let carried: Value =
        serde_json::from_str(prompt.lines().last().expect("brief json")).expect("prompt brief");
    assert_eq!(carried["owner_text"], owner);

    let over_budget = RolloverPolicy {
        max_brief_bytes: 64,
        ..RolloverPolicy::default()
    };
    let refused = render_fresh_brief(
        &FreshBriefSources {
            reason: "new information".into(),
            owner_text: "x".repeat(200),
            ..FreshBriefSources::default()
        },
        &over_budget,
    );
    assert!(refused.is_err(), "owner text is not trimmed to fit");
}

#[cfg(test)]
fn declared(threshold: u64) -> RolloverRuntimeConfig {
    RolloverRuntimeConfig::new(RolloverPolicy {
        threshold_tokens: threshold,
        ..RolloverPolicy::default()
    })
    .expect("declared policy is valid")
}

#[cfg(test)]
mod lane_rollover_config_tests {
    use super::{declared, lane_rollover_config};

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

    /// Declarative no-policy semantics: a seat that declares no rollover runs no rollover on
    /// any lane; the complete-request context guard refuses oversize requests before the
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
}
