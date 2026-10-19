//! Typed fleet read views: per-host liveness and where-it-runs placement.
//!
//! The fleet producer ([`crate::huginn`] consumers: `odin_huginn::fleet`)
//! projects one [`FleetHostView`] per enabled+enrolled declared host and one
//! [`FleetPlacementView`] per placed thing (odind authority, node gateways,
//! pods per node, the authority host's live sessions). Views are pure
//! projections of the registry declarations, the bounded tailnet probe, and
//! the shared k3s read model — they carry no control authority and no secret
//! material.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::kube::KubeNodeState;

/// Tailnet liveness of one declared host as observed by the bounded probe.
/// `Unknown` is declared absence (no probe or no endpoint declared), never a
/// timeout: a bounded probe that fails resolves `Unreachable`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum FleetTailnetState {
    Reachable,
    Unreachable,
    Unknown,
}

/// One declared fleet host: registry declaration facts plus the live
/// liveness observation. `online` is the disjunction of the three
/// independent authorities — the tailnet endpoint probe, the k3s node
/// Ready condition, and the per-host zellij (ssh) session probe.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FleetHostView {
    /// The declared host id (the `hosts/<id>/host.toml` identity).
    pub host: String,
    /// The declared tailscale name; mandatory for enrolled hosts.
    pub tailscale: String,
    pub hardware: String,
    pub role: String,
    /// The union of the declared node capabilities hosted on this host.
    pub capabilities: Vec<String>,
    pub allow_workloads: bool,
    pub authoritative_state: bool,
    /// The declared node-local gateway endpoint, when a hosted node
    /// declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_endpoint: Option<String>,
    pub tailnet: FleetTailnetState,
    /// The k3s node Ready state of this host's declared node, or `None`
    /// when the host declares no k3s node (or the cluster reports none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k3s_node_state: Option<KubeNodeState>,
    /// Zellij SSH probe result: true means reachable, false unreachable,
    /// and None means no probe ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zellij_live: Option<bool>,
    pub online: bool,
    /// The most recent instant the host was observed reachable or k3s
    /// Ready. Preserved across offline passes: an offline host keeps its
    /// last-seen stamp instead of losing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<OffsetDateTime>,
    pub pods_scheduled: u32,
}

/// One placed thing in the fleet: where it runs and how much of it runs
/// there. The placements (authority, per-node gateway, per-node pods, the
/// authority host's live sessions, per-host zellij sessions) share one
/// view shape; fields outside a placement's shape stay absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FleetPlacementView {
    /// The placed thing's role: `odind-authority`, `gateway`, `pods`,
    /// `seat-sessions`, or `zellij-sessions`.
    pub thing: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The declared gateway endpoint, for the `gateway` placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Workload count, for the `pods` placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// Bounded, sorted workload names, for the `pods` placement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    /// Live session count holding capacity, for the `seat-sessions` placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_count: Option<u32>,
    /// Liveness of the observed thing, for the `zellij-sessions` placement:
    /// `false` records a host whose zellij session listing could not be
    /// reached within the probe bound. Absent for every placement that
    /// carries no live observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<bool>,
}
