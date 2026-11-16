//! Host-composed connection settings; no ambient kubeconfig or in-cluster discovery.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Resolved packet transport a `vpn-required` workload joins. Absent means
/// those launches refuse; direct workloads ignore it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnTransportBinding {
    pub endpoint: IpAddr,
    pub port: u16,
    /// The nameserver protected pods use, inside the tunnel.
    pub dns: IpAddr,
    /// Absolute in-image launcher path.
    pub launcher: PathBuf,
    /// Host executable that resolves a protected hostname to IPv4 addresses.
    /// Absent refuses hostname pins; it never falls back to host DNS.
    pub resolver: Option<PathBuf>,
    /// The address the authority forwards the endpoint to, which a local pod's egress admits too.
    pub forwarded: Option<IpAddr>,
}

impl VpnTransportBinding {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("vpn transport port 0 is not a UDP port".to_owned());
        }
        if !odin_registry::schema::valid_pod_path(&self.launcher.display().to_string()) {
            return Err(format!(
                "vpn transport launcher {:?} is not an absolute in-image path",
                self.launcher
            ));
        }
        if let Some(resolver) = &self.resolver {
            if !resolver.is_absolute() {
                return Err(format!(
                    "vpn transport resolver {:?} is not an absolute path",
                    resolver
                ));
            }
        }
        if !self.endpoint.is_ipv4()
            || self.endpoint.is_unspecified()
            || self.endpoint.is_multicast()
        {
            return Err(format!(
                "vpn transport endpoint {} must be a reachable IPv4 address",
                self.endpoint
            ));
        }
        Ok(())
    }

    pub fn launcher(&self) -> &Path {
        &self.launcher
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeConfig {
    /// Path to the admin kubeconfig (host declares it; e.g.
    /// `/etc/rancher/k3s/k3s.yaml`, mode 0640, group `k3s`).
    pub kubeconfig: PathBuf,
    /// Odin's logical cluster identity, independent of kubeconfig context names.
    pub cluster: String,
    /// Namespace all Job/Pod APIs are scoped to.
    pub namespace: String,
    /// Exact published node identities admitting new workload placement.
    /// Empty denies new placement without disabling observation or teardown.
    pub allowed_nodes: std::collections::BTreeSet<String>,
    /// Each node's declared data roots; a launch with data mounts places only where they cover it.
    pub node_data_roots: std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    /// Per-request timeout, including the connect probe.
    pub request_timeout: Duration,
    /// Timeout for Job stop and suspend settlement.
    pub teardown_timeout: Duration,
    /// Packet transport for protected workloads. `None` refuses `vpn-required` launches.
    pub vpn_transport: Option<VpnTransportBinding>,
}
