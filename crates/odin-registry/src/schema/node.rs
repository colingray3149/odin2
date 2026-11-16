//! Node placement and gateway endpoints reachable by workloads.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::object::RegistryKind;
use super::workload::valid_allow_host;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub host: String,
    pub role: String,
    pub capabilities: BTreeSet<String>,
    pub allow_workloads: bool,
    pub authoritative_state: bool,
    /// Workload nodes require a non-loopback HTTP(S) endpoint because pods cannot reach host loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_endpoint: Option<String>,
    /// What an hour of this node costs; owned nodes omit it and cost nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<NodeCostToml>,
    /// On the authority node: how often odind meters running pods into lane compute budgets;
    /// absent means 60 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_meter_seconds: Option<std::num::NonZeroU32>,
    /// Offload pump retry cadence when no target is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offload_empty_poll_seconds: Option<std::num::NonZeroU32>,
    /// Maximum time to drain an external node, read when leaving it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_drain_timeout_seconds: Option<std::num::NonZeroU32>,
    /// On the authority node: seconds between simulation board passes; absent means 10.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation_pump_seconds: Option<std::num::NonZeroU32>,
    /// On the authority node: seconds between open Missions view polls; absent means 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missions_view_seconds: Option<std::num::NonZeroU32>,
    /// Unused managed images must be observed at least this long before pruning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prune_min_age_seconds: Option<std::num::NonZeroU64>,
    /// Managed image cache budget; pruning only starts above this size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prune_max_bytes: Option<std::num::NonZeroU64>,
    /// Seconds between managed image pruning rounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prune_cadence_seconds: Option<std::num::NonZeroU64>,
    /// Maximum duration of a CRI image query or removal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_prune_cri_timeout_seconds: Option<std::num::NonZeroU64>,
    /// On the authority node: maximum side in pixels for SVG mission previews; absent means 2048.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missions_preview_max_side: Option<std::num::NonZeroU32>,
    /// Seconds between root-plan continuation attempts on the authority node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_plan_wake_seconds: Option<std::num::NonZeroU32>,
    /// Host directories under which workload `[[data]]` mounts may read on this node.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub data_roots: BTreeSet<String>,
    /// The launch queue's pacing, read on the authority node; absent keys keep the defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_queue: Option<LaunchQueueToml>,
    /// Workload watch pacing and bounds, read from the authoritative node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_watch: Option<WorkloadWatchToml>,
    /// Host modes (`local-models mode`) during which Odin's pods leave this node.
    #[serde(default, rename = "yield", skip_serializing_if = "Option::is_none")]
    pub yield_to: Option<NodeYieldToml>,
    /// The node's one GPU model; labelled `odin.gpu/vram-gib` and `odin.gpu/model` for placement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu: Option<NodeGpuToml>,
    /// A rented or lab box outside the fleet: it joins tainted `odin.dev/external`, carries no
    /// trust label, and takes only launches whose profile tolerates `external`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub external: bool,
}

/// How the authority's launch queue pump paces itself.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchQueueToml {
    /// Held launches one pass looks at, oldest first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<std::num::NonZeroU32>,
    /// Seconds after which a pass retries even though no Odin Job ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backstop_seconds: Option<std::num::NonZeroU32>,
}

/// Workload watch bounds; omitted fields preserve the daemon defaults.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadWatchToml {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_seconds: Option<std::num::NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crash_loop_restarts: Option<std::num::NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_window_seconds: Option<std::num::NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<std::num::NonZeroU32>,
}

/// The owner's modes that take the node back: cordon it, and pause, move or keep each pod.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeYieldToml {
    pub modes: BTreeSet<String>,
    /// A yield mode older than this raises one incident asking whether it still holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_hours: Option<u32>,
    /// How often the authority checks for an overdue yield mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_check_seconds: Option<std::num::NonZeroU32>,
}

/// Used when a card declares no `stale_hours`.
pub const DEFAULT_YIELD_STALE_HOURS: u32 = 24;

impl NodeYieldToml {
    pub fn stale_hours(&self) -> u32 {
        self.stale_hours.unwrap_or(DEFAULT_YIELD_STALE_HOURS)
    }

    pub fn stale_check_seconds(&self) -> u32 {
        self.stale_check_seconds
            .map_or(900, std::num::NonZeroU32::get)
    }
}

impl NodeToml {
    /// Whether every host path lies under one of this node's declared data roots.
    pub fn covers_data<'a>(&self, host_paths: impl IntoIterator<Item = &'a str>) -> bool {
        host_paths.into_iter().all(|path| {
            self.data_roots
                .iter()
                .any(|root| std::path::Path::new(path).starts_with(root))
        })
    }
}

/// A node's hourly price, charged to lanes by each pod's share of the node's CPUs.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCostToml {
    pub usd_per_hour: f64,
}

// Validation refuses non-finite prices, so equality by value is total.
impl Eq for NodeCostToml {}

/// The meter cadence when the authority node declares none.
pub const DEFAULT_COMPUTE_METER_SECONDS: u32 = 60;

/// One GPU model per node: mixed cards on one host would need device-plugin resource renaming.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeGpuToml {
    /// Label-safe model slug, e.g. `rtx-3070`.
    pub model: String,
    pub vram_gib: u32,
    pub count: u32,
    /// GPU memory a desktop keeps for itself; a run declaring its need waits until that much
    /// plus its need is free. Absent reserves nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop_reserve_mib: Option<u32>,
}

/// The taint key prefix of node taints a profile's `tolerate` names, e.g. `odin.dev/external`.
pub const NODE_TAINT_PREFIX: &str = "odin.dev/";

/// The toleration name that admits external nodes.
pub const EXTERNAL_TOLERATION: &str = "external";

/// The label the k3s server sets on fleet nodes only; a kubelet cannot set this prefix itself.
pub const NODE_TRUST_LABEL: &str = "node-restriction.kubernetes.io/odin-trust";

pub const NODE_TRUST_FLEET: &str = "fleet";

/// The node label carrying a declared GPU's memory in whole GiB.
pub const NODE_GPU_VRAM_LABEL: &str = "odin.gpu/vram-gib";

/// The node label carrying a declared GPU's model slug.
pub const NODE_GPU_MODEL_LABEL: &str = "odin.gpu/model";

/// Preserve the declared URI while exposing its effective host and port for egress rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeGatewayEndpoint {
    endpoint: String,
    host: String,
    port: u16,
}

/// Do not echo malformed endpoint input because it may contain credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NodeGatewayEndpointError {
    #[error("the declared node gateway endpoint is empty")]
    Empty,
    #[error("the declared node gateway endpoint is not an absolute URL: {0}")]
    NotAbsolute(url::ParseError),
    #[error("the declared node gateway endpoint must be an http(s) URL, found scheme {scheme:?}")]
    Scheme { scheme: String },
    #[error(
        "the declared node gateway endpoint must not carry embedded credentials; the credential \
         belongs in the declared Secret binding"
    )]
    Credentials,
    #[error("the declared node gateway endpoint names no host authority")]
    HostMissing,
    #[error("the declared node gateway host {host:?} is not a declared host name or IP literal")]
    HostInvalid { host: String },
    #[error(
        "the declared node gateway endpoint binds {host:?} ({class}), an authority no pod on the \
         node can reach"
    )]
    UnreachableAuthority { host: String, class: &'static str },
    #[error("the declared node gateway endpoint has no usable effective TCP port")]
    Port,
}

impl NodeGatewayEndpoint {
    pub fn parse(endpoint: &str) -> Result<Self, NodeGatewayEndpointError> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return Err(NodeGatewayEndpointError::Empty);
        }
        let url = url::Url::parse(endpoint).map_err(NodeGatewayEndpointError::NotAbsolute)?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(NodeGatewayEndpointError::Scheme {
                scheme: url.scheme().to_owned(),
            });
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(NodeGatewayEndpointError::Credentials);
        }
        let (host, inadmissible) = match url.host().ok_or(NodeGatewayEndpointError::HostMissing)? {
            // Use normalized hosts so endpoint resolution and egress rules agree.
            url::Host::Domain(domain) => {
                if !valid_allow_host(domain) {
                    return Err(NodeGatewayEndpointError::HostInvalid {
                        host: domain.to_owned(),
                    });
                }
                let refusal = domain
                    .eq_ignore_ascii_case("localhost")
                    .then_some("loopback");
                (domain.to_owned(), refusal)
            }
            url::Host::Ipv4(address) => (
                address.to_string(),
                node_gateway_address_class(&IpAddr::V4(address)),
            ),
            url::Host::Ipv6(address) => (
                address.to_string(),
                node_gateway_address_class(&IpAddr::V6(address)),
            ),
        };
        if let Some(class) = inadmissible {
            return Err(NodeGatewayEndpointError::UnreachableAuthority { host, class });
        }
        let port = url
            .port_or_known_default()
            .filter(|port| *port != 0)
            .ok_or(NodeGatewayEndpointError::Port)?;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            host,
            port,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.endpoint
    }

    /// IPv6 hosts omit brackets so egress rules receive a canonical address.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Use the scheme default when no explicit port is declared.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Share address rejection with egress resolution, including IPv4-mapped IPv6 addresses.
pub fn node_gateway_address_class(address: &IpAddr) -> Option<&'static str> {
    if let Some(v4) = match address {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    } {
        if v4.is_loopback() {
            return Some("loopback");
        }
        if v4.is_unspecified() {
            return Some("unspecified");
        }
        if v4.is_broadcast() {
            return Some("broadcast");
        }
        if v4.is_multicast() {
            return Some("multicast");
        }
        return None;
    }
    let IpAddr::V6(v6) = address else {
        return None;
    };
    if v6.is_loopback() {
        return Some("loopback");
    }
    if v6.is_unspecified() {
        return Some("unspecified");
    }
    if v6.is_multicast() {
        return Some("multicast");
    }
    None
}

impl std::fmt::Display for NodeGatewayEndpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.endpoint)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub hardware: String,
    pub role: String,
    pub tailscale: String,
    pub enrolled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Invalid endpoints are rejected without echoing input that may contain credentials.
    #[test]
    fn parse_refuses_unreachable_credentialed_and_malformed_declarations() {
        for (declared, expected) in [
            (
                "http://localhost:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "localhost".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://127.0.0.1:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "127.0.0.1".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://[::ffff:127.0.0.1]:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "::ffff:127.0.0.1".to_owned(),
                    class: "loopback",
                },
            ),
            (
                "http://0.0.0.0:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "0.0.0.0".to_owned(),
                    class: "unspecified",
                },
            ),
            (
                "http://[::]:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "::".to_owned(),
                    class: "unspecified",
                },
            ),
            (
                "http://224.0.0.1:14000/v1",
                NodeGatewayEndpointError::UnreachableAuthority {
                    host: "224.0.0.1".to_owned(),
                    class: "multicast",
                },
            ),
            (
                "http://user:secret@mini:14000/v1",
                NodeGatewayEndpointError::Credentials,
            ),
            (
                "ftp://mini:14000/v1",
                NodeGatewayEndpointError::Scheme {
                    scheme: "ftp".to_owned(),
                },
            ),
            (
                "//user:secret@mini/v1",
                NodeGatewayEndpointError::NotAbsolute(url::ParseError::RelativeUrlWithoutBase),
            ),
        ] {
            assert_eq!(
                NodeGatewayEndpoint::parse(declared),
                Err(expected),
                "{declared:?} must refuse typed"
            );
        }
        // A malformed declaration can carry credentials: the refusal must not
        // echo any part of it.
        assert!(
            !NodeGatewayEndpointError::NotAbsolute(url::ParseError::RelativeUrlWithoutBase)
                .to_string()
                .contains("secret"),
            "the not-absolute refusal must never echo the declaration"
        );
    }
}
