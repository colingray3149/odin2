//! Model-gateway spend exposed over Huginn. The authority reads its LiteLLM gateway's own
//! daily aggregates — per day, per lane, per seat and per pod workload
//! (every session's requests carry `seat:<seat>`, a pod's also
//! `workload:<profile>`) — and any paired surface shows them.
//! Dollars are each lane's declared list price applied to its tokens;
//! subscription lanes cost no extra money.

use serde::{Deserialize, Serialize};

pub const SPEND_MAX_DAYS: u8 = 31;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendRequest {
    /// The last `days` days, today included (1..=31).
    pub days: u8,
}

/// One row: a day, a lane, a seat or the total.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendLine {
    pub label: String,
    pub usd_cents: u64,
    pub tokens: u64,
    pub requests: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendView {
    pub from: String,
    pub to: String,
    pub total: SpendLine,
    pub days: Vec<SpendLine>,
    /// Busiest first.
    pub lanes: Vec<SpendLine>,
    /// Busiest first; empty when the per-seat view is unavailable.
    pub seats: Vec<SpendLine>,
    /// Agent pod workloads by profile, busiest first: part of their seats'
    /// spend, not added to it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workloads: Vec<SpendLine>,
    /// Spend no seat tag accounts for (embeddings, untagged callers).
    pub untagged_usd_cents: u64,
    pub note: String,
}
