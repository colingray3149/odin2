//! Seat, project, lane, and spend declarations.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use odin_domain::huginn::{ModelName, ProviderName};
use odin_domain::knowledge::{AtlasId, ToolName};
use odin_domain::{CapabilityId, Digest, LaneId, ProjectId, SeatId};
use serde::{Deserialize, Serialize};

use super::object::RegistryKind;
use super::validation::{valid_id, validate_budget_policy_fields};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub categories: BTreeSet<String>,
    pub tool_refs: BTreeSet<CapabilityId>,
    pub project_scope: BTreeSet<ProjectId>,
    /// Projects whose checkouts the seat may read (code.navigate) without any write or session authority.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub read_project_scope: BTreeSet<ProjectId>,
    pub approval_defaults: ApprovalDefaultsToml,
    pub brain_scope: BTreeSet<AtlasId>,
    pub limits: SeatLimitsToml,
    pub live: Option<SeatLiveToml>,
    pub knowledge: Option<SeatKnowledgeToml>,
    pub context: Option<SeatContextToml>,
    pub tools: Option<SeatToolsToml>,
    /// System guidance for a seat without a conversation (a conversation seat uses conversation.guidance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
    /// Absent disables standing conversation transport; present requires one enabled in-scope project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<SeatConversationToml>,
    /// Retire the proposed seat at expiry or when its delegated work finishes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<SeatEphemeralToml>,
    /// Writing this memory namespace requires both its declaration and a matching grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_namespace: Option<AtlasId>,
    /// Provider/model pairs the seat may run on, the first by default; they replace the composed launch choices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<SeatModelToml>,
    /// Shell defaults off; omit undeclared sandbox settings to preserve canonical snapshot hashes.
    #[serde(default, skip_serializing_if = "SeatSandboxToml::is_undeclared")]
    pub sandbox: SeatSandboxToml,
}

/// One `provider/model` launch choice, e.g. `gateway/grok`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct SeatModelToml {
    pub provider: ProviderName,
    pub model: ModelName,
}

impl TryFrom<String> for SeatModelToml {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (provider, model) = value
            .split_once('/')
            .ok_or_else(|| format!("model {value:?} must be provider/model"))?;
        Ok(Self {
            provider: ProviderName::new(provider)
                .map_err(|error| format!("model {value:?} provider: {error}"))?,
            model: ModelName::new(model)
                .map_err(|error| format!("model {value:?} model: {error}"))?,
        })
    }
}

impl From<SeatModelToml> for String {
    fn from(value: SeatModelToml) -> Self {
        value.to_string()
    }
}

impl std::fmt::Display for SeatModelToml {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.provider, self.model)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatEphemeralToml {
    /// UTC expiry, `YYYY-MM-DDTHH:MM:SSZ`.
    pub expires_at: String,
    pub proposed_by: SeatId,
    /// Count only sessions started since this UTC timestamp, excluding earlier uses of the seat name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_at: Option<String>,
}

impl SeatEphemeralToml {
    pub fn expires_at_unix(&self) -> Option<i64> {
        utc_seconds(&self.expires_at)
    }

    pub fn proposed_at_unix(&self) -> Option<i64> {
        self.proposed_at.as_deref().and_then(utc_seconds)
    }
}

pub fn utc_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| text.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDefaultToml {
    Auto,
    Plan,
    Approval,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalDefaultsToml {
    pub r0: ApprovalDefaultToml,
    pub r1: ApprovalDefaultToml,
    pub r2: ApprovalDefaultToml,
    pub r3: ApprovalDefaultToml,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatLimitsToml {
    pub max_parallel_runs: u16,
    pub max_sessions: u16,
    /// Optional per-seat cap enforced by the model gateway, not Odin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetPolicyToml>,
}

/// Use integer micros to represent USD exactly: 1 USD = 1,000,000 micros.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetPolicyToml {
    pub usd_micros: u64,
    pub window: AccountingWindowToml,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountingWindowToml {
    pub duration_seconds: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedBudgetPolicy {
    pub registry_revision: u64,
    pub policy_digest: Digest,
    pub scope: String,
    pub policy: BudgetPolicyToml,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatLiveToml {
    pub max_sessions: NonZeroU16,
    pub file_ingress_lane: LaneId,
    pub file_egress_lane: LaneId,
    pub render_ingress_lane: LaneId,
    pub render_egress_lane: LaneId,
    /// Absent disables rollover; composition caps its trigger at the served lane's context limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover: Option<SeatRolloverToml>,
    /// Optional turn deadline in seconds (1..=86400); expiry cancels the turn without claiming an answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_turn_seconds: Option<NonZeroU64>,
}

/// Share the turn limit between authored and runtime validation.
pub const MAX_TURN_SECONDS: u64 = 86_400;

/// Runtime validation rechecks these limits so incorrect composition cannot bypass them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SeatRolloverToml {
    /// Token watermark: default 180000, maximum 250000.
    pub threshold_tokens: u64,
    /// Rollover brief bytes: default 16384, range 1024..=32768.
    pub max_brief_bytes: usize,
    /// Conversation-tail event count (default 128, within 8..=1024).
    pub history_tail_events: usize,
}

impl Default for SeatRolloverToml {
    fn default() -> Self {
        Self {
            threshold_tokens: 180_000,
            max_brief_bytes: 16_384,
            history_tail_events: 128,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatKnowledgeToml {
    pub atlas_sources: BTreeSet<AtlasId>,
    pub required_tags: BTreeSet<String>,
    pub denied_tags: BTreeSet<String>,
    pub top_k: NonZeroU16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatContextToml {
    pub max_bundle_tokens: NonZeroU32,
    pub profile: String,
    /// Absent disables background brain review for the seat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_lane: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatToolsToml {
    pub deny: BTreeSet<ToolName>,
    pub redirects: SeatToolRedirectsToml,
    /// Initially listed capability IDs or dotted prefixes; empty lists all grants, others remain searchable.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub always: BTreeSet<String>,
}

pub fn always_covers(entry: &str, capability: &str) -> bool {
    capability == entry
        || capability
            .strip_prefix(entry)
            .is_some_and(|rest| rest.starts_with('.'))
}

/// Use declared project and presentation guidance rather than inferring conversation configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatConversationToml {
    /// Must be enabled and present in project_scope.
    pub project: ProjectId,
    /// Must name an enabled implemented ask capability whose delegate_to matches this seat.
    pub ask_capability: CapabilityId,
    pub guidance: String,
    pub answer_timeout_seconds: NonZeroU64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatToolRedirectsToml {
    pub max_http_hops: u8,
    pub allow_cross_origin: bool,
    pub disabled_aliases: BTreeSet<ToolName>,
}

/// Declare project-private memory explicitly; undeclared atlas sources remain seat-general knowledge.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub source_root: String,
    pub default_seat: SeatId,
    pub memory_namespaces: BTreeSet<AtlasId>,
    pub artifact_policy: String,
    /// Privacy floor for declared memory; apl_restricted and secret exclude it from model payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<odin_domain::knowledge::PrivacyClass>,
    /// Per-agent account; launch options override it, and undeclared kinds use default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accounts: BTreeMap<super::AccountKind, String>,
    /// Required reviewer capability unless the lane overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_verdict: Option<CapabilityId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LaneDirection {
    Internal,
    Ingress,
    Egress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Command,
    Event,
    File,
    Render,
    Scientific,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneTransferPolicy {
    pub direction: LaneDirection,
    pub payload_kind: PayloadKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub project: ProjectId,
    pub family: String,
    pub default_seat: SeatId,
    pub queue: String,
    pub requires_independent_review: bool,
    /// Overrides the project reviewer capability when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_verdict: Option<CapabilityId>,
    pub direction: Option<LaneDirection>,
    pub payload_kind: Option<PayloadKind>,
}

impl LaneToml {
    pub const fn transfer_policy(&self) -> Option<LaneTransferPolicy> {
        match (self.direction, self.payload_kind) {
            (Some(direction), Some(payload_kind)) => Some(LaneTransferPolicy {
                direction,
                payload_kind,
            }),
            _ => None,
        }
    }
}
/// Network none creates a namespace; host shares it. Neither is a packet allowlist.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SeatSandboxNetwork {
    #[default]
    None,
    Host,
}

pub const SANDBOX_PATH_ROLES: [&str; 3] = ["capsule", "scratch", "checkout"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SeatSandboxToml {
    /// Pass the bash tool. False omits it.
    pub shell: bool,
    /// Shell-tool network. `none` or `host`.
    #[serde(default)]
    pub network: SeatSandboxNetwork,
    /// Writable mounts. Empty on a shell seat means capsule plus scratch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writable: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readonly: Vec<String>,
}
impl SeatSandboxToml {
    fn is_undeclared(&self) -> bool {
        *self == Self::default()
    }
}

impl Default for SeatSandboxToml {
    fn default() -> Self {
        Self {
            shell: false,
            network: SeatSandboxNetwork::None,
            writable: Vec::new(),
            readonly: Vec::new(),
        }
    }
}

impl SeatSandboxToml {
    pub fn writable_entries(&self) -> Vec<String> {
        if self.writable.is_empty() && self.shell {
            vec!["capsule".to_owned(), "scratch".to_owned()]
        } else {
            self.writable.clone()
        }
    }
}

pub fn bind_budget_policy(
    registry_revision: u64,
    scope: impl Into<String>,
    policy: &BudgetPolicyToml,
) -> Result<ResolvedBudgetPolicy, String> {
    validate_budget_policy_fields(policy)?;
    let scope = scope.into();
    if !valid_id(&scope) {
        return Err("budget scope must be a stable ID".to_owned());
    }
    #[derive(Serialize)]
    struct BudgetPayload<'a> {
        registry_revision: u64,
        scope: &'a str,
        policy: &'a BudgetPolicyToml,
    }
    let canonical = serde_json::to_vec(&BudgetPayload {
        registry_revision,
        scope: &scope,
        policy,
    })
    .map_err(|error| format!("budget policy canonicalization failed: {error}"))?;
    Ok(ResolvedBudgetPolicy {
        registry_revision,
        policy_digest: Digest::hash(&canonical),
        scope,
        policy: policy.clone(),
    })
}

#[cfg(test)]
mod tests;
