//! Model cards: one card per servable model, the single declaration the
//! gateway projection, the catalog, and every seat, class, consult, pod and
//! fallback reference. Capability facts absent from the card fall back to
//! AVAILABLE (`registry/models.available.json`); cost and display name always
//! come from AVAILABLE, never the card.

use odin_domain::huginn::GATEWAY_PROVIDER;
use serde::{Deserialize, Serialize};

use super::object::RegistryKind;
use std::num::NonZeroU32;
/// The card is a gateway lane served through the deployed LiteLLM loopback.
pub const GATEWAY_ROUTE: &str = GATEWAY_PROVIDER;
/// The card is served by the Claude Code official client.
pub const CLAUDE_ROUTE: &str = "claude-code";
/// The card is served by the agy (Antigravity) official client.
pub const AGY_ROUTE: &str = "agy";

/// The committed model catalog AVAILABLE, a data file beside the cards that
/// is never a registry object.
pub const MODELS_AVAILABLE: &str = "models.available.json";

/// Every declared serving route.
pub const MODEL_ROUTES: [&str; 3] = [GATEWAY_ROUTE, CLAUDE_ROUTE, AGY_ROUTE];

/// The strong tier: the consult frontier and the strong class.
pub const FRONTIER_TIER: &str = "frontier";
/// The standard tier.
pub const EVERYDAY_TIER: &str = "everyday";
/// The cheap tier: the fast class.
pub const FAST_CHEAP_TIER: &str = "fast-cheap";

/// Every declared chat tier.
pub const MODEL_TIERS: [&str; 3] = [FRONTIER_TIER, EVERYDAY_TIER, FAST_CHEAP_TIER];

/// A chat model card; chat cards declare a tier.
pub const CHAT_CAPABILITY: &str = "chat";
/// An embedding model card; embedding cards never declare a tier.
pub const EMBEDDING_CAPABILITY: &str = "embedding";

/// The account key whose cards are served by this fleet's own hardware and
/// are exempt from the AVAILABLE check.
pub const LOCAL_ACCOUNT: &str = "local";

fn default_route() -> String {
    GATEWAY_ROUTE.to_owned()
}

fn default_capability() -> String {
    CHAT_CAPABILITY.to_owned()
}

fn default_replay_reasoning() -> bool {
    true
}

fn is_default_reasoning_effort(value: &bool) -> bool {
    *value
}

fn is_default_route(route: &str) -> bool {
    route == GATEWAY_ROUTE
}

fn is_default_capability(capability: &str) -> bool {
    capability == CHAT_CAPABILITY
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCardToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    /// The card id, `provider/model`: the card's identity only. Everything
    /// that names a lane (classes, consult, review, pods, fallbacks, odind's
    /// `[models]`, the gateway's model name) uses the bare lane, `lane()`;
    /// seats list the `gateway/<lane>` provider/model pair.
    pub id: String,
    /// Upstream provider/model exactly as AVAILABLE lists it; optional only
    /// for local-account cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served: Option<String>,
    /// How the card is served: a gateway lane, or the Claude Code / agy
    /// official client.
    #[serde(default = "default_route", skip_serializing_if = "is_default_route")]
    pub route: String,
    /// Chat or embedding; embedding cards declare no tier.
    #[serde(
        default = "default_capability",
        skip_serializing_if = "is_default_capability"
    )]
    pub capability: String,
    /// frontier, everyday or fast-cheap; required exactly for chat cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Position in the class try order; only classed gateway chat cards
    /// carry it, and the class projection sorts by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<NonZeroU32>,
    /// The account pin holding this card's credentials; absent for
    /// official-client cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// One line naming when this card is the right pick.
    pub strengths: String,
    /// Fallback lanes (bare), in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<String>,
    /// True names a lane seats may run; the gateway refuses seat turns on
    /// every other card.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub seats: bool,
    /// A local family: every chat or vision model on the local model list
    /// is a member lane `local/<id>`, sharing this card's facts. Local
    /// accounts only.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub family: bool,
    /// Supply the brain's default serving identity and context window.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub brain_serving: bool,
    /// Provide a brain review lane required by the fleet configuration.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub brain_review: bool,
    /// models.yml compat.replayReasoningContent; false where the upstream
    /// cannot replay reasoning content.
    #[serde(
        default = "default_replay_reasoning",
        skip_serializing_if = "is_default_reasoning_effort"
    )]
    pub replay_reasoning: bool,
    /// Whether the upstream accepts `reasoning_effort` on the wire; false
    /// where the route rejects it (glm-flash).
    #[serde(
        default = "default_replay_reasoning",
        skip_serializing_if = "is_default_reasoning_effort"
    )]
    pub reasoning_effort: bool,
    /// Declared window; absent fields fall back to AVAILABLE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<ModelWindowToml>,
    /// Declared thinking effort; absent fields fall back to AVAILABLE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ModelThinkingToml>,
    /// Whether the model takes image input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<bool>,
    /// The wire API the upstream speaks (responses, chat-completions, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<String>,
    /// Strict tool-call validation; a catalog/provider fact, never a
    /// lane-name branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
    /// The context counter the card's window is guarded with; absent counts
    /// exact UTF-8 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<ModelTokenizer>,
}

/// A card's declared context counter. `qwen3` is the pinned native family;
/// `estimate` is one token per four bytes, calibrated per lane from provider
/// usage. Absent counts exact bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelTokenizer {
    Qwen3,
    Estimate,
}

impl ModelCardToml {
    /// The lane name a gateway card carries after its `gateway/` prefix.
    pub fn lane(&self) -> Option<&str> {
        self.id
            .strip_prefix(GATEWAY_PROVIDER)
            .and_then(|rest| rest.strip_prefix('/'))
    }
}

/// Declared window facts; each field the card omits comes from AVAILABLE.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelWindowToml {
    /// Context window in tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u64>,
    /// Maximum output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
}

/// Declared thinking facts; each field the card omits comes from AVAILABLE.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelThinkingToml {
    /// The default reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// The effort levels the model accepts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub levels: Vec<String>,
    /// Sampling temperature; lands as the gateway's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::{ModelCardToml, ModelTokenizer};

    #[test]
    fn a_card_declares_its_context_counter_and_no_other() {
        let card = |tokenizer: &str| {
            format!(
                "schema = \"odin.registry.v1\"\nkind = \"model\"\nenabled = true\n\
                 description = \"A hosted card.\"\nid = \"gateway/hosted\"\n\
                 strengths = \"Everything.\"\n{tokenizer}"
            )
        };
        let declared: ModelCardToml =
            toml::from_str(&card("tokenizer = \"estimate\"\n")).expect("estimate card parses");
        assert_eq!(declared.tokenizer, Some(ModelTokenizer::Estimate));
        let absent: ModelCardToml =
            toml::from_str(&card("")).expect("card without a counter parses");
        assert_eq!(absent.tokenizer, None);
        assert!(toml::from_str::<ModelCardToml>(&card("tokenizer = \"glm5\"\n")).is_err());
    }
}
