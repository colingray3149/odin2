//! Structured capability declarations avoid interpreting handler strings as commands.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use odin_domain::knowledge::{AtlasId, EmbeddingBackend, RetrievalMode, ToolName};
use odin_domain::{CapabilityId, EffectClass, SeatId};
use serde::{Deserialize, Serialize};

use super::object::RegistryKind;
use super::seat::BudgetPolicyToml;
use super::validation::valid_id;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityIdempotencyToml {
    Pure,
    Required,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityApprovalToml {
    None,
    Operator,
}

/// Owner consent is required for consequential effects; declaration approval records the calling seat as decider.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalDeciderToml {
    #[default]
    Owner,
    Declaration,
}

impl ApprovalDeciderToml {
    pub fn is_owner(&self) -> bool {
        *self == Self::Owner
    }
}

/// Select the effect preview renderer; absence does not require complete preview delivery.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PreviewKindToml {
    Browser,
    Batch,
    /// A deploy: the project, the commit and its subject, and the hosts it switches.
    Deploy,
    /// A workflow's own read-only plan of the exact effect.
    Plan,
    /// The host's approval card: the object and each bound value, old and new.
    Card,
}

/// A declared approval card: `title` with each `{/pointer}` replaced by that bound argument, then one
/// `field: value` row per JSON pointer in `fields`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCardToml {
    pub title: String,
    pub fields: Vec<String>,
}

impl ApprovalCardToml {
    /// The `{...}` placeholders of the title, in order.
    pub fn title_pointers(&self) -> impl Iterator<Item = &str> {
        self.title
            .split('{')
            .skip(1)
            .filter_map(|part| part.split_once('}').map(|(inner, _)| inner))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchLimitsToml {
    pub max_effects: u16,
    pub max_minutes: u32,
    pub max_uses: u32,
}

/// Exact-key tables reject scalar command strings and ambiguous argv splitting.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum HandlerBindingToml {
    Builtin(BuiltinHandlerToml),
    Exec(ExecHandlerToml),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltinHandlerToml {
    pub id: String,
}

/// Use a store executable and static argv with sanitized environment and framed input/output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecHandlerToml {
    pub executable: String,
    pub argv: Vec<String>,
}

impl HandlerBindingToml {
    /// Validate syntax without filesystem lookup, ambient environment, or shell interpretation.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            HandlerBindingToml::Builtin(builtin) => validate_builtin_handler_id(&builtin.id),
            HandlerBindingToml::Exec(exec) => {
                validate_exec_handler_executable(&exec.executable)?;
                validate_exec_handler_argv(&exec.argv)
            }
        }
    }
}

fn validate_builtin_handler_id(id: &str) -> Result<(), String> {
    if !valid_id(id) {
        return Err(format!(
            "builtin handler id {id:?} must match the registry id grammar"
        ));
    }
    Ok(())
}

fn validate_exec_handler_executable(executable: &str) -> Result<(), String> {
    if executable.chars().any(char::is_whitespace) {
        return Err(format!(
            "exec executable {executable:?} must not contain whitespace"
        ));
    }
    if executable.chars().any(is_handler_shell_syntax) {
        return Err(format!(
            "exec executable {executable:?} contains shell syntax"
        ));
    }
    let Some(rest) = executable.strip_prefix("/nix/store/") else {
        return Err(format!(
            "exec executable {executable:?} must be a /nix/store/<hash>-<name> path, never a caller-relative or PATH-resolved form"
        ));
    };
    let (store_component, tail) = rest.split_once('/').ok_or_else(|| {
        format!("exec executable {executable:?} must name a file beneath its /nix/store component")
    })?;
    let (hash, name) = store_component.split_once('-').ok_or_else(|| {
        format!("exec executable {executable:?} has a malformed /nix/store component")
    })?;
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|byte| NIX_STORE_HASH_ALPHABET.as_bytes().contains(&byte))
    {
        return Err(format!(
            "exec executable {executable:?} has a malformed /nix/store hash"
        ));
    }
    if name.is_empty() {
        return Err(format!(
            "exec executable {executable:?} has an empty /nix/store package name"
        ));
    }
    if tail
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "exec executable {executable:?} is not a normalized /nix/store path"
        ));
    }
    Ok(())
}

/// The 32-character Nix base32 alphabet; `e`, `o`, `u`, and `t` are absent.
const NIX_STORE_HASH_ALPHABET: &str = "0123456789abcdfghijklmnpqrsvwxyz";

fn validate_exec_handler_argv(argv: &[String]) -> Result<(), String> {
    for element in argv {
        if element.is_empty() {
            return Err("exec argv elements must not be empty".to_owned());
        }
        if element.chars().any(char::is_whitespace) {
            return Err(format!(
                "exec argv element {element:?} must be one static token without whitespace"
            ));
        }
        if element.chars().any(is_handler_shell_syntax) {
            return Err(format!(
                "exec argv element {element:?} contains shell syntax"
            ));
        }
    }
    Ok(())
}

pub(crate) fn is_handler_shell_syntax(character: char) -> bool {
    matches!(
        character,
        '$' | '`' | ';' | '&' | '|' | '\n' | '\r' | '>' | '<'
    )
}

/// Identify cross-seat asks by the handler ID, never a capability or seat name.
pub const SEAT_ASK_HANDLER_ID: &str = "seat_ask";

pub const SEAT_ASK_EVIDENCE_EXTRACTOR_ID: &str = "odin_hermes_seat_ask_evidence";

pub const SEAT_ASK_INPUT_SCHEMA: &str = "schemas/capability/seat.ask.input.json";

/// Adapter capabilities use this handler marker rather than an in-process tool tuple.
pub const ADAPTER_OPERATION_HANDLER_ID: &str = "odin_adapter.operation";

pub const ADAPTER_RECEIPT_EVIDENCE_ID: &str = "odin_adapter.receipt";

/// `implementation` values that name an in-process owner, not an adapter.
const NON_ADAPTER_IMPLEMENTATIONS: [&str; 5] = [
    "builtin",
    "operator",
    "unimplemented",
    super::pod_exec::POD_EXEC_IMPLEMENTATION,
    super::workflow::WORKFLOW_IMPLEMENTATION,
];

pub const SEAT_ASK_OUTPUT_SCHEMA: &str = "schemas/capability/seat.ask.output.json";

/// Output schemas that several enabled capabilities share: every pod-exec capability and every desktop.act view.
pub const POD_EXEC_OUTPUT_SCHEMA: &str = "schemas/capability/pod-exec.output.json";

pub const DESKTOP_ACT_OUTPUT_SCHEMA: &str = "schemas/capability/desktop.act.output.json";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub implementation: Option<String>,
    pub version: u16,
    pub description: String,
    /// Model-facing grouping only; capability identity and authority remain unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<CapabilityExposureToml>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub seat_ops: BTreeMap<SeatId, CapabilitySeatOpToml>,
    pub handler: Option<HandlerBindingToml>,
    /// The generic ask handler uses this declared target; omission preserves canonical hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_to: Option<SeatId>,
    pub input_schema: Option<String>,
    pub output_schema: Option<String>,
    pub effect_class: EffectClass,
    pub seat_tags: BTreeSet<String>,
    pub timeout_seconds: NonZeroU32,
    pub idempotency: CapabilityIdempotencyToml,
    pub retry: RetryToml,
    pub approval_policy: CapabilityApprovalToml,
    /// Omit the default decider to preserve canonical declaration hashes.
    #[serde(default, skip_serializing_if = "ApprovalDeciderToml::is_owner")]
    pub approval_decider: ApprovalDeciderToml,
    /// Exact-effect preview the owner must see before consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<PreviewKindToml>,
    /// The values the owner reads on a `preview = "card"` approval, declared here so a new card or field
    /// is a registry edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_card: Option<ApprovalCardToml>,
    /// A grant batch may name this capability.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub batchable: bool,
    /// Bounds of one grant batch. Present only on the grant capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchLimitsToml>,
    pub evidence_extractor: Option<HandlerBindingToml>,
    /// The in-image tool a pod-exec capability runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec: Option<super::pod_exec::PodExecToml>,
    /// The nextest tests that prove this capability, each `<binary-id> <test-name>` as the gate's JUnit report
    /// names it. The gate fails when one is absent or red; none leaves the capability untested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<String>,
    /// Live checks (`unit:`, `http:`, `file:`, `models:`) shown beside the tests. They show the capability is
    /// up, never that it works, so they cannot make an untested capability green.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySeatOpToml {
    pub toolset: String,
    pub op: String,
    /// This seat's own listing of the op: `on_demand` keeps its fields behind `args` for this seat
    /// only, so a seat that rarely calls it does not carry its schema every turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose: Option<CapabilityExposureToml>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityExposureToml {
    OnDemand,
    Internal,
}

impl CapabilityToml {
    pub fn is_implemented(&self) -> bool {
        self.implementation
            .as_deref()
            .is_some_and(|implementation| {
                !implementation.is_empty() && implementation != "unimplemented"
            })
            && self.handler.is_some()
            && self
                .input_schema
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self
                .output_schema
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            && self.evidence_extractor.is_some()
            && !self.seat_tags.is_empty()
    }

    /// Implementations other than builtin, operator, and unimplemented name out-of-process adapters.
    pub fn adapter_implementation(&self) -> Option<&str> {
        self.implementation
            .as_deref()
            .filter(|implementation| !NON_ADAPTER_IMPLEMENTATIONS.contains(implementation))
    }

    pub fn binds_adapter_markers(&self) -> bool {
        matches!(
            &self.handler,
            Some(HandlerBindingToml::Builtin(builtin)) if builtin.id == ADAPTER_OPERATION_HANDLER_ID
        ) && matches!(
            &self.evidence_extractor,
            Some(HandlerBindingToml::Builtin(builtin)) if builtin.id == ADAPTER_RECEIPT_EVIDENCE_ID
        )
    }

    pub fn is_pod_exec(&self) -> bool {
        self.implementation.as_deref() == Some(super::pod_exec::POD_EXEC_IMPLEMENTATION)
    }

    pub fn binds_pod_exec_markers(&self) -> bool {
        matches!(
            &self.handler,
            Some(HandlerBindingToml::Builtin(builtin))
                if builtin.id == super::pod_exec::POD_EXEC_HANDLER_ID
        ) && matches!(
            &self.evidence_extractor,
            Some(HandlerBindingToml::Builtin(builtin))
                if builtin.id == super::pod_exec::POD_EXEC_RECEIPT_ID
        )
    }

    pub fn is_workflow(&self) -> bool {
        self.implementation.as_deref() == Some(super::workflow::WORKFLOW_IMPLEMENTATION)
    }

    pub fn binds_workflow_markers(&self) -> bool {
        matches!(
            &self.handler,
            Some(HandlerBindingToml::Builtin(builtin))
                if builtin.id == super::workflow::WORKFLOW_HANDLER_ID
        ) && matches!(
            &self.evidence_extractor,
            Some(HandlerBindingToml::Builtin(builtin))
                if builtin.id == super::workflow::WORKFLOW_RECEIPT_ID
        )
    }

    /// Recognize cross-seat asks by handler ID, never logical capability or seat names.
    pub fn is_seat_ask_primitive(&self) -> bool {
        matches!(
            &self.handler,
            Some(HandlerBindingToml::Builtin(builtin)) if builtin.id == SEAT_ASK_HANDLER_ID
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetryToml {
    pub max_attempts: u8,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub capabilities: BTreeSet<CapabilityId>,
    /// Explicitly use the seat grant source; omitted legacy ceilings retain their meaning.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub inherit_seat_grants: bool,
    pub variables: BTreeMap<String, SliceVariableToml>,
    pub redirects: SliceRedirectsToml,
    pub knowledge: Option<SliceKnowledgeToml>,
    pub context: Option<SliceContextToml>,
    pub tools: Option<SliceToolsToml>,
    pub live: Option<SliceLiveToml>,
    pub budget: Option<BudgetPolicyToml>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceVariableToml {
    #[serde(rename = "type")]
    pub variable_type: String,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub meaning: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceRedirectsToml {
    pub out_of_scope: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceKnowledgeToml {
    pub required: bool,
    pub atlas_sources: BTreeSet<AtlasId>,
    pub retrieval_mode: RetrievalMode,
    pub candidate_limit: NonZeroU16,
    pub top_k: NonZeroU16,
    pub min_score_micros: u32,
    pub chunk_tokens: NonZeroU32,
    pub chunk_overlap_tokens: u32,
    pub embedding_backend: EmbeddingBackend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceContextToml {
    pub max_bundle_tokens: NonZeroU32,
    pub reserve_output_tokens: NonZeroU32,
    pub control_tokens: NonZeroU32,
    pub history_tokens: NonZeroU32,
    pub core_tokens: NonZeroU32,
    pub prefetch_tokens: NonZeroU32,
    pub tool_result_tokens: NonZeroU32,
    pub tool_schema_tokens: NonZeroU32,
    pub max_item_tokens: NonZeroU32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceToolsToml {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allow: BTreeSet<ToolName>,
    pub deny: BTreeSet<ToolName>,
    pub redirects: SliceToolRedirectsToml,
    /// Reserved empty declaration retained for untouched external project slices.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    #[serde(deserialize_with = "reserved_empty_redirects")]
    pub alias_redirect: BTreeSet<()>,
}

fn reserved_empty_redirects<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<()>, D::Error> {
    let entries = Vec::<serde::de::IgnoredAny>::deserialize(deserializer)?;
    if !entries.is_empty() {
        return Err(serde::de::Error::custom(
            "alias_redirect is reserved and must be empty",
        ));
    }
    Ok(BTreeSet::new())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceToolRedirectsToml {
    pub max_http_hops: u8,
    pub allow_cross_origin: bool,
    pub allow_https_downgrade: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SliceLiveToml {
    pub max_sessions_per_seat: NonZeroU16,
    pub max_prompt_bytes: NonZeroU64,
    pub transfer_chunk_bytes: NonZeroU64,
    pub max_file_bytes: NonZeroU64,
    pub max_render_bytes: NonZeroU64,
    pub allowed_file_media_types: BTreeSet<String>,
    pub allowed_render_media_types: BTreeSet<String>,
}

#[cfg(test)]
mod tests;
