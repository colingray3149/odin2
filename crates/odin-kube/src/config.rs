//! Host-composed connection settings; no ambient kubeconfig or in-cluster discovery.

use std::path::PathBuf;
use std::time::Duration;

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
    /// Per-request timeout, including the connect probe.
    pub request_timeout: Duration,
    /// Timeout for Job stop and suspend settlement.
    pub teardown_timeout: Duration,
}
