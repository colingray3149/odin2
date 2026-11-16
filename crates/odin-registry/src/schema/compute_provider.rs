//! A cloud account Odin rents machines from (Hetzner, RunPod, Lambda). The card names the
//! secret holding the API key, never its value, and every cap and price is a value here: a
//! changed one applies to the next lease and the next reaper round, with no restart.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::RegistryKind;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeProviderToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub api: ComputeProviderApi,
    /// Name of the declared tools secret (a sops key) holding the API key.
    pub key: String,
    /// The API's base URL; absent uses the provider's public endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Bound on one provider API request; absent uses 30 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_seconds: Option<NonZeroU32>,
    /// Runpod SSH public-key enrollment and independently verified proxy identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runpod_ssh: Option<RunpodSshToml>,
    /// A lease priced above this is refused.
    pub max_hourly_usd: f64,
    /// Cumulative account spending cap in USD over `account_window_days`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_max_usd: Option<f64>,
    /// Rolling accounting window for the account cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_window_days: Option<NonZeroU32>,
    /// The longest TTL a lease may ask for.
    pub max_lease_hours: NonZeroU32,
    pub max_concurrent_leases: NonZeroU32,
    /// A live lease with no work on it this long is destroyed.
    pub idle_destroy_minutes: NonZeroU32,
    /// Seconds between reaper rounds (TTL, idle, lane spend, orphans).
    pub reap_seconds: NonZeroU32,
    /// Short-lived rentals use SSH offload; manually joined external nodes are separate.
    pub join: LeaseJoin,
    /// Projects whose lanes may lease here; empty admits none.
    pub allowed_projects: BTreeSet<String>,
    /// The machines this account offers, by name.
    pub offers: BTreeMap<String, ComputeOfferToml>,
    /// The offload target every lease becomes, with connection identity supplied per lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<LeaseTargetToml>,
}

/// Owner-verified Runpod proxy identity and the public key enrolled in each Pod.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunpodSshToml {
    pub account_id: String,
    /// SSH host key in `<type> <base64>` form, verified independently by the owner.
    pub known_host: String,
    /// Public key only; the corresponding private key remains local.
    pub public_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComputeProviderApi {
    Hetzner,
    Runpod,
    Lambda,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LeaseJoin {
    SshTarget,
}

/// One machine type: what the provider calls it, where, and its declared price.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOfferToml {
    /// The provider's machine type (Hetzner server type, RunPod GPU type, Lambda instance type).
    pub machine: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// The OS image (VMs) or container image (RunPod).
    pub image: String,
    pub usd_per_hour: f64,
    pub cores: NonZeroU32,
    #[serde(default)]
    pub gpus: u32,
}

/// The offload target fields a leased container shares.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTargetToml {
    pub user: String,
    pub remote_root: String,
    pub runtime: super::OffloadRuntime,
    pub max_concurrent: NonZeroU32,
    pub poll_seconds: NonZeroU32,
    pub stop_grace_seconds: NonZeroU32,
}
