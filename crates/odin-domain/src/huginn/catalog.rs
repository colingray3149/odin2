//! One model catalog over Huginn: every model the operator's sign-ins and
//! keys expose (the authority's `omp models --json`), joined against the
//! dotfiles lane allowlist, so `/model` can show what seats may run and
//! what they may not, with the reason.

use serde::{Deserialize, Serialize};

/// Provider id of a gateway lane (`gateway/grok`). Seat `models` and the
/// OMP catalog both use it; the allowlist is keyed by the lane id alone.
pub const GATEWAY_PROVIDER: &str = "gateway";

/// One model the catalog shows. `seat_allowed` is the lane's `seats` flag;
/// a row a particular seat may not switch to still carries that flag, and
/// the view says why it is not selectable there.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelCatalogRow {
    /// `provider/model`, the same form a seat's `models` list uses.
    pub selector: String,
    pub name: String,
    /// One line from the lane declaration; empty when no lane declares it.
    pub strengths: String,
    /// The lane's tier tag (frontier, everyday, fast-cheap); empty when the
    /// projection declares none.
    pub tier: String,
    pub seat_allowed: bool,
    /// Why no seat may run it. Empty when `seat_allowed`.
    pub reason: String,
    pub context_window: u64,
    /// Declared USD per million tokens, as rendered. Empty when unknown.
    pub input_per_million: String,
    pub output_per_million: String,
    pub billing: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelCatalogView {
    /// Why the live list is missing (the first line of `omp`'s failure).
    /// Declared seat lanes still appear.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    pub rows: Vec<ModelCatalogRow>,
}
