//! Workload plans carry declared state, export paths, and network access.
//!
//! State claims are per-run and reused on restart; rehome checks volume affinity.
//! Exports use a per-run subfolder of an existing host directory.
//! Egress policies pin resolved IPs, not hostnames: shared IPs and DNS rebinding
//! are outside their protection. DNS rotation may refresh pins without changing
//! the declared hosts or gateway port. `network_open` instead admits public
//! TCP 80/443 for that run and still excludes private, loopback, link-local,
//! metadata, CGNAT, tailnet, and cluster ranges. The pinned gateway stays a
//! separate exception.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use k8s_openapi::api::core::v1::{
    EmptyDirVolumeSource, EnvVar, EnvVarSource, HostPathVolumeSource, PersistentVolume,
    PersistentVolumeClaim, PersistentVolumeClaimVolumeSource, Pod, SecretKeySelector, Volume,
    VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{ListParams, Patch, PatchParams, PostParams};
use odin_domain::{Digest, RunId};
use odin_registry::BrowserEngine;
use serde::{Deserialize, Serialize};

use odin_registry::schema::{
    paths_nest_or_collide, storage_quantity_bytes, valid_allow_host, valid_id, valid_pod_path,
    valid_screen,
};
use thiserror::Error;

use crate::client::{KubeClient, KubeError};
use crate::job::{bounded_label_value, JOB_API_VERSION, JOB_KIND, JOB_LABEL_RUN_ID};
mod egress;
pub(crate) use egress::desired_egress_policy;
use egress::{annotated_scope, declared_scope, inadmissible_gateway_addresses};
pub use egress::{egress_rules, resolve_declared_hosts, resolve_hosts, ResolvedEgress};

mod continuation;
mod placement;
pub use continuation::*;
pub use placement::*;

/// Shared by the staged provider config and the pod's SecretKeyRef environment entry.
pub const WORKLOAD_CREDENTIAL_ENV: &str = "ODIN_GATEWAY_KEY";

/// References a Kubernetes Secret key without storing its value in the launch plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadCredentialEnv {
    /// The container env name the staged models config names as the
    /// provider `apiKey` reference.
    pub env_name: String,
    pub secret: String,
    pub key: String,
}

impl WorkloadCredentialEnv {
    pub fn validate(&self) -> Result<(), String> {
        let valid_env = !self.env_name.is_empty()
            && self
                .env_name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && !self
                .env_name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit());
        if !valid_env {
            return Err(format!(
                "workload credential env name {:?} is not a valid env name",
                self.env_name
            ));
        }
        if self.secret.trim().is_empty() || self.key.trim().is_empty() {
            return Err(
                "workload credential binding requires a nonempty Secret name and key".to_owned(),
            );
        }
        if self.secret.contains('/') || self.key.contains('/') {
            return Err(
                "workload credential Secret name and key must not carry path separators".to_owned(),
            );
        }
        Ok(())
    }
}

/// Attributes workload Jobs and pods to their declared profile.
pub const WORKLOAD_LABEL: &str = "odin.dev/workload";

pub const WORKLOAD_STATE_VOLUME: &str = "odin-workload-state";
pub const WORKLOAD_EXPORT_VOLUME: &str = "odin-workload-export";
/// Only this container accepts browser relay execs and mounts the private socket directory.
pub const BROWSER_CONTAINER: &str = "browser";
/// Browser-only emptyDir mount for the relay socket.
pub const BROWSER_SOCKET_DIR: &str = "/run/odin-browser";
/// Never mount this socket volume in the worker or another container.
pub const BROWSER_SOCKET_VOLUME: &str = "odin-browser-socket";
pub const BROWSER_SOCKET: &str = "/run/odin-browser/relay.sock";

pub const MAX_ALLOW_HOSTS: usize = 64;

/// Stores comma-separated site hosts and gateway `host:port`, not resolved IPs,
/// so DNS rotation can refresh pins without allowing a scope change.
pub const DECLARED_HOSTS_ANNOTATION: &str = "odin.dev/declared-hosts";

/// Site ports only; gateway targets use their own declared TCP port.
const EGRESS_TCP_PORTS: [i32; 2] = [80, 443];
const EGRESS_UDP_PORTS: [i32; 1] = [443];

/// Bounds each daemon-host name lookup, and the gateway TCP probe (not a pod-network or
/// provider-readiness check).
pub(crate) const HOST_LOOKUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Gateway traffic uses this port rather than the site's standard HTTP/TLS ports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadGatewayTarget {
    pub host: String,
    pub port: u16,
}

impl WorkloadGatewayTarget {
    fn validate(&self) -> Result<(), String> {
        if !valid_allow_host(&self.host) && self.host.parse::<IpAddr>().is_err() {
            return Err(format!(
                "workload gateway host {:?} is not a declared host name or IP literal",
                self.host
            ));
        }
        if self.port == 0 {
            return Err("workload gateway port 0 is not a declared TCP port".to_owned());
        }
        Ok(())
    }
}
/// Resolved packet transport copied onto a protected launch. Replay keeps this
/// binding; it is not re-read from daemon config.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadVpnTransportPlan {
    pub endpoint: IpAddr,
    pub port: u16,
    /// The nameserver the pod's resolver uses, inside the tunnel.
    pub dns: IpAddr,
    /// Absolute in-image TUN launcher.
    pub launcher: String,
    /// Absolute host lookup used for hostname pins. Absent with a hostname pin refuses launch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolver: Option<String>,
    /// The address the authority forwards the endpoint to: a pod on the authority meets the
    /// cluster's policy engine already forwarded, so its egress admits this address as well.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded: Option<IpAddr>,
}

impl WorkloadVpnTransportPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("vpn transport port 0 is not a UDP port".to_owned());
        }
        if !valid_pod_path(&self.launcher) {
            return Err(format!(
                "vpn transport launcher {:?} is not a valid absolute in-image path",
                self.launcher
            ));
        }
        if let Some(resolver) = &self.resolver {
            if !resolver.starts_with('/') || resolver.contains('\0') {
                return Err(format!(
                    "vpn transport resolver {resolver:?} is not an absolute path"
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

    /// Launcher argv. The script owns packet setup; these are its inputs.
    /// Gateway and site pins are resolved IPv4 addresses. `--open` replaces pins.
    pub fn command(
        &self,
        gateway: &[IpAddr],
        gateway_port: u16,
        allow: &[IpAddr],
        open: bool,
    ) -> Vec<String> {
        let mut argv = vec![
            self.launcher.clone(),
            "--endpoint".to_owned(),
            self.endpoint.to_string(),
            "--port".to_owned(),
            self.port.to_string(),
        ];
        for address in gateway {
            argv.push("--gateway".to_owned());
            argv.push(address.to_string());
        }
        if !gateway.is_empty() {
            argv.push("--gateway-port".to_owned());
            argv.push(gateway_port.to_string());
        }
        if open {
            argv.push("--open".to_owned());
        } else if allow.is_empty() {
            argv.push("--closed".to_owned());
        } else {
            for address in allow {
                argv.push("--allow".to_owned());
                argv.push(address.to_string());
            }
        }
        argv
    }
}

/// Probe failures describe the daemon host's DNS/TCP path, not pod reachability
/// or provider readiness; a forwarded socket may accept TCP with its backend down.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GatewayProbeError {
    #[error(
        "the declared gateway endpoint {host}:{port} does not resolve within the {budget_ms}ms \
         probe budget: {detail}; measured boundary: this daemon host's DNS path only"
    )]
    Unresolved {
        host: String,
        port: u16,
        budget_ms: u128,
        detail: String,
    },
    #[error(
        "the declared gateway endpoint {host}:{port} accepted no TCP connection from this daemon \
         host within the {budget_ms}ms probe budget: {detail}; measured boundary: this daemon \
         host's TCP path only"
    )]
    Unreachable {
        host: String,
        port: u16,
        budget_ms: u128,
        detail: String,
    },
    #[error(
        "the declared gateway endpoint {host}:{port} resolves to an address no pod on the node \
         can reach ({detail}); measured boundary: this daemon host's DNS path only"
    )]
    Inadmissible {
        host: String,
        port: u16,
        detail: String,
    },
}

/// DNS and TCP share one deadline. Success means only that this daemon host
/// completed a TCP handshake, not that pods or the provider are ready.
pub async fn probe_gateway_target(target: &WorkloadGatewayTarget) -> Result<(), GatewayProbeError> {
    let budget = HOST_LOOKUP_BUDGET;
    let refusal = |detail: String| GatewayProbeError::Unresolved {
        host: target.host.clone(),
        port: target.port,
        budget_ms: budget.as_millis(),
        detail,
    };
    // Share the deadline so DNS and successive connects cannot each consume a full budget.
    let deadline = tokio::time::Instant::now() + budget;
    let resolved = tokio::time::timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        tokio::net::lookup_host((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|error| {
        refusal(format!(
            "host resolution exceeded the probe budget: {error}"
        ))
    })?
    .map_err(|error| refusal(error.to_string()))?
    .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(refusal("the host resolved to no address".to_owned()));
    }
    // Reject any inadmissible address before connecting, using the same check as egress.
    let inadmissible = inadmissible_gateway_addresses(
        &resolved
            .iter()
            .map(|address| address.ip())
            .collect::<Vec<_>>(),
    );
    if !inadmissible.is_empty() {
        return Err(GatewayProbeError::Inadmissible {
            host: target.host.clone(),
            port: target.port,
            detail: inadmissible.join(", "),
        });
    }
    let mut detail = String::new();
    for address in resolved {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            detail = format!("{address}: probe budget exhausted");
            break;
        }
        match tokio::time::timeout(remaining, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(_connected)) => return Ok(()),
            Ok(Err(error)) => detail = format!("{address}: {error}"),
            Err(_) => {
                detail = format!("{address}: connect exceeded the probe budget");
                break;
            }
        }
    }
    Err(GatewayProbeError::Unreachable {
        host: target.host.clone(),
        port: target.port,
        budget_ms: budget.as_millis(),
        detail,
    })
}

/// The supervisor launches the display from these profile settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadDisplayPlan {
    pub xvfb: String,
    /// Virtual display geometry `<width>x<height>x<depth>`.
    pub screen: String,
    /// Disables owner-frame publication when false; controls and screenshots remain available.
    pub stream: bool,
}

impl WorkloadDisplayPlan {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_pod_path(&self.xvfb) {
            return Err(format!(
                "workload display xvfb {:?} is not a valid absolute in-image path",
                self.xvfb
            ));
        }
        if !valid_screen(&self.screen) {
            return Err(format!(
                "workload display screen {:?} is not `<width>x<height>x<depth>` within the \
                 browser mechanism bound",
                self.screen
            ));
        }
        Ok(())
    }
}

/// Profile data persisted with the launch and revalidated by the reconciler on replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadPodPlan {
    pub profile: String,
    /// Absolute in-pod mount path.
    pub state_mount: String,
    /// Absolute in-pod mount path.
    pub export_mount: String,
    /// Existing host directory containing per-run export subfolders.
    pub export_host_folder: String,
    /// Kubernetes storage quantity, such as `2Gi`.
    pub state_storage: String,
    /// `None` uses the cluster default, which need not support cross-node access.
    #[serde(default)]
    pub state_storage_class: Option<String>,
    /// `false` when the profile declares `state.carry = false`: the state never leaves its node.
    #[serde(
        default = "carries_state",
        skip_serializing_if = "carries_state_is_default"
    )]
    pub state_carry: bool,
    /// Site hosts allowed on HTTP/TLS/QUIC ports; excludes the gateway's separate port.
    /// A protected plan keeps these as tunnel pins and does not resolve them on the host.
    pub allow_hosts: Vec<String>,
    /// Public-only TCP 80/443 for this run, excluding non-public ranges. Host pins still apply.
    /// Inside a tunnel the same pins are handed to the launcher rather than the cluster policy.
    #[serde(default)]
    pub network_open: bool,
    /// `direct` keeps ordinary routing. `vpn-required` launches only with `vpn`.
    #[serde(
        default,
        skip_serializing_if = "odin_registry::WorkloadTransport::is_direct"
    )]
    pub transport: odin_registry::WorkloadTransport,
    /// Resolved at admission from daemon config. Replay uses this copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<WorkloadVpnTransportPlan>,
    /// The profile's report contract: this run ends with exactly one PDF
    /// beside its markdown, completed by the authority when the pod itself
    /// rendered none.
    #[serde(default)]
    pub report_pdf: bool,
    /// Declared files.save root, retained on replay; never inferred from a seat default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_downloads_root: Option<String>,
    /// Declared files.save root that receives this run's export folder, retained on replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_deliver_root: Option<String>,
    /// The company folder for this report, already one directory segment.
    /// Absent when the launch named no company. Never parsed from prompt prose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// The worker container's declared reservation. Absent keeps the platform worker defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<WorkloadResources>,
    /// Pod termination grace for every stop path; absent keeps the cluster default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_grace_seconds: Option<u32>,
    /// Read-only node-local directories; placement narrows to nodes declaring their roots.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<WorkloadDataMount>,
    /// How long the finished run is kept before reaping; absent keeps the platform default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_finished_seconds: Option<u32>,
    /// What the run does when its node yields to its owner.
    #[serde(default, skip_serializing_if = "odin_registry::OnYield::is_rehome")]
    pub on_yield: odin_registry::OnYield,
    /// The profile's control declaration as admitted: steers check against this copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<odin_registry::WorkloadControlToml>,
    /// A script pod's declared gateway lane. Absent unless `seat.gateway_lane` is set.
    /// Named apart from the flattened agent plan's `gateway`, which shares the JSON keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_gateway: Option<WorkloadScriptGateway>,
    /// `None` for a script pod.
    #[serde(flatten)]
    pub agent: Option<WorkloadAgentPlan>,
}

fn carries_state() -> bool {
    true
}

fn carries_state_is_default(carry: &bool) -> bool {
    *carry
}

/// The worker's declared CPU (whole cores) and memory (bytes) reservation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadResources {
    pub cpu: u32,
    pub memory_bytes: u64,
    /// Memory-backed `/dev/shm` size, charged inside `memory_bytes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_bytes: Option<u64>,
}

/// One declared read-only host directory and where the worker sees it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadDataMount {
    pub name: String,
    pub host_path: String,
    pub pod_path: String,
}

/// A script pod's gateway: the same node gateway target and SecretKeyRef an
/// agent pod receives, plus the node's base URL, the declared lane and the
/// project's `[agents]` roles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadScriptGateway {
    /// The profile's `seat.gateway_lane`; absent when only the project's roles brought the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lane: Option<String>,
    /// The project's `[agents]` role → lane pairs, exposed as `ODIN_GATEWAY_ROLES`
    /// (`role=lane` joined by commas); the credential is then the project's own key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<String, String>,
    /// The node's declared OpenAI-compatible base URL, exposed as `ODIN_GATEWAY_URL`.
    pub url: String,
    pub gateway: WorkloadGatewayTarget,
    /// Required SecretKeyRef for gateway authentication; never a literal credential.
    pub credential: WorkloadCredentialEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadAgentPlan {
    /// Absolute in-image launcher path saved at creation, not re-read during attach.
    pub launcher: String,
    pub gateway: WorkloadGatewayTarget,
    /// Absolute in-image browser executable path.
    pub browser: String,
    /// Absolute in-image browser supervisor path.
    pub supervisor: String,
    /// Absolute in-image Playwright module root.
    pub playwright: String,
    pub display: WorkloadDisplayPlan,
    /// In-image Node executable resolved from `tools.node.in_image` at admission.
    pub browser_node: String,
    /// Obscura runs on the authority rather than in a pod browser container.
    #[serde(default, skip_serializing_if = "BrowserEngine::is_default")]
    pub browser_engine: BrowserEngine,
    /// `None` uses the state mount so the agent's home survives restart and rehome.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// Required SecretKeyRef for gateway authentication; never a literal credential.
    pub credential: WorkloadCredentialEnv,
}

impl WorkloadPodPlan {
    /// The gateway the pod's container reaches: an agent's, else a script gateway lane's.
    fn gateway_target(&self) -> Option<&WorkloadGatewayTarget> {
        self.agent
            .as_ref()
            .map(|agent| &agent.gateway)
            .or(self.script_gateway.as_ref().map(|script| &script.gateway))
    }

    /// The container env a gateway-bearing pod receives. Agent pods get the key only;
    /// script pods also get `ODIN_GATEWAY_URL`, and `ODIN_GATEWAY_LANE` and
    /// `ODIN_GATEWAY_ROLES` when declared.
    pub fn gateway_env(&self) -> Vec<EnvVar> {
        let credential = self.agent.as_ref().map(|agent| &agent.credential).or(self
            .script_gateway
            .as_ref()
            .map(|script| &script.credential));
        let plain = |name: &str, value: &str| EnvVar {
            name: name.to_owned(),
            value: Some(value.to_owned()),
            value_from: None,
        };
        let mut env = Vec::new();
        if let Some(credential) = credential {
            env.push(EnvVar {
                name: credential.env_name.clone(),
                value: None,
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: credential.secret.clone(),
                        key: credential.key.clone(),
                        optional: Some(false),
                    }),
                    ..Default::default()
                }),
            });
        }
        if let Some(script) = &self.script_gateway {
            env.push(plain("ODIN_GATEWAY_URL", &script.url));
            if let Some(lane) = &script.lane {
                env.push(plain("ODIN_GATEWAY_LANE", lane));
            }
            if !script.roles.is_empty() {
                let roles = script
                    .roles
                    .iter()
                    .map(|(role, lane)| format!("{role}={lane}"))
                    .collect::<Vec<_>>()
                    .join(",");
                env.push(plain("ODIN_GATEWAY_ROLES", &roles));
            }
        }
        env
    }

    /// Defaults to the state mount when no separate home directory is declared.
    pub fn home(&self) -> &str {
        self.agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_deref())
            .unwrap_or(&self.state_mount)
    }

    /// `None` for script and Obscura pods, which run no browser container.
    pub fn browser_command(&self) -> Option<Vec<String>> {
        let agent = self.agent.as_ref()?;
        (agent.browser_engine != BrowserEngine::Obscura).then_some(())?;
        Some(vec![
            agent.supervisor.clone(),
            "browser-serve".to_owned(),
            "--node".to_owned(),
            agent.browser_node.clone(),
            "--xvfb".to_owned(),
            agent.display.xvfb.clone(),
            "--screen".to_owned(),
            agent.display.screen.clone(),
            "--state-dir".to_owned(),
            format!("{}/browser", self.state_mount),
            "--socket".to_owned(),
            BROWSER_SOCKET.to_owned(),
        ])
    }

    /// State is shared with the worker; the relay socket is browser-only.
    pub fn browser_volume_mounts(&self) -> Vec<VolumeMount> {
        vec![
            VolumeMount {
                name: WORKLOAD_STATE_VOLUME.to_owned(),
                mount_path: self.state_mount.clone(),
                read_only: Some(false),
                ..Default::default()
            },
            VolumeMount {
                name: BROWSER_SOCKET_VOLUME.to_owned(),
                mount_path: BROWSER_SOCKET_DIR.to_owned(),
                read_only: Some(false),
                ..Default::default()
            },
        ]
    }

    pub fn browser_socket_volume() -> Volume {
        Volume {
            name: BROWSER_SOCKET_VOLUME.to_owned(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        }
    }
    /// Validate both at launch composition and journal replay; deserialization is not validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.profile.trim().is_empty() {
            return Err("workload plan requires a nonempty profile id".to_owned());
        }
        if let Some(company) = &self.company {
            company_directory(company)?;
        }
        match self.report_downloads_root.as_deref() {
            None if self.report_pdf => {
                return Err("report PDF delivery requires a declared files.save root".to_owned());
            }
            Some(root) if !valid_id(root) => {
                return Err(format!(
                    "report downloads root {root:?} is not a files.save root id"
                ));
            }
            _ => {}
        }
        if let Some(root) = self
            .export_deliver_root
            .as_deref()
            .filter(|root| !valid_id(root))
        {
            return Err(format!(
                "export delivery root {root:?} is not a files.save root id"
            ));
        }
        if let Some(class) = &self.state_storage_class {
            if !valid_allow_host(class) {
                return Err(format!(
                    "workload storage class {class:?} is not a declared DNS name"
                ));
            }
        }
        let mounts = [
            ("state mount", self.state_mount.as_str()),
            ("export mount", self.export_mount.as_str()),
        ];
        for (what, mount) in mounts {
            if !valid_pod_path(mount) {
                return Err(format!(
                    "workload {what} {mount:?} is not a valid absolute in-pod path"
                ));
            }
        }
        if paths_nest_or_collide(&self.state_mount, &self.export_mount) {
            return Err(format!(
                "workload state mount {:?} and export mount {:?} collide or nest",
                self.state_mount, self.export_mount
            ));
        }
        let home = self
            .agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_deref());
        if let Some(home) = home {
            if !valid_pod_path(home) {
                return Err(format!(
                    "workload home dir {home:?} is not a valid absolute in-pod path"
                ));
            }
            for (what, mount) in mounts {
                if paths_nest_or_collide(mount, home) {
                    return Err(format!(
                        "workload home dir {home:?} collides or nests with the {what} {mount:?}"
                    ));
                }
            }
        }
        // Overlapping mounts could shadow or expose the private relay socket.
        for (what, path) in mounts
            .into_iter()
            .chain(home.map(|home| ("home dir", home)))
        {
            if paths_nest_or_collide(BROWSER_SOCKET_DIR, path) {
                return Err(format!(
                    "the relay socket directory {BROWSER_SOCKET_DIR:?} collides or nests with \
                     the workload {what} {path:?}"
                ));
            }
        }
        if !valid_pod_path(&self.export_host_folder) {
            return Err(format!(
                "workload export host folder {:?} is not a valid absolute host path",
                self.export_host_folder
            ));
        }
        if let Some(agent) = &self.agent {
            for (what, path) in [
                ("launcher", &agent.launcher),
                ("browser executable", &agent.browser),
                ("browser supervisor", &agent.supervisor),
                ("playwright module root", &agent.playwright),
                ("browser node", &agent.browser_node),
            ] {
                if !valid_pod_path(path) {
                    return Err(format!(
                        "workload {what} {path:?} is not a valid absolute in-image path"
                    ));
                }
            }
            agent.display.validate()?;
        }
        storage_quantity_bytes(&self.state_storage)?;
        let egress_hosts = self.allow_hosts.len()
            + usize::from(self.agent.is_some())
            + usize::from(self.script_gateway.is_some());
        if egress_hosts > MAX_ALLOW_HOSTS {
            return Err(format!(
                "workload plan declares {egress_hosts} egress hosts: beyond the mechanical \
                 bound of {MAX_ALLOW_HOSTS}"
            ));
        }
        let mut seen = BTreeSet::new();
        for host in &self.allow_hosts {
            if !valid_allow_host(host) {
                return Err(format!(
                    "workload egress host {host:?} is not a declared host name"
                ));
            }
            if !seen.insert(host.as_str()) {
                return Err(format!("workload egress host {host:?} is declared twice"));
            }
        }
        match self.transport {
            odin_registry::WorkloadTransport::Direct => {
                if self.vpn.is_some() {
                    return Err("a direct workload carries no vpn transport binding".to_owned());
                }
            }
            odin_registry::WorkloadTransport::VpnRequired => {
                let Some(vpn) = &self.vpn else {
                    return Err(
                        "vpn-required workload has no resolved transport binding; refusing \
                         direct fallback"
                            .to_owned(),
                    );
                };
                vpn.validate()?;
            }
        }
        if let Some(resources) = self.resources {
            if resources.cpu == 0 || resources.memory_bytes == 0 {
                return Err(format!(
                    "workload resources need at least one CPU and nonzero memory, found {} CPU \
                     and {} bytes",
                    resources.cpu, resources.memory_bytes
                ));
            }
            if resources
                .shm_bytes
                .is_some_and(|shm| shm == 0 || shm >= resources.memory_bytes)
            {
                return Err(
                    "workload shared memory must be nonzero and below its memory".to_owned(),
                );
            }
        }
        if self.termination_grace_seconds == Some(0) {
            return Err("workload stop grace must be at least one second".to_owned());
        }
        self.validate_data()?;
        if let Some(script) = &self.script_gateway {
            if self.agent.is_some() {
                return Err(
                    "an agent pod takes its gateway from its agent plan, not a script \
                            gateway lane"
                        .to_owned(),
                );
            }
            if script
                .lane
                .as_deref()
                .is_some_and(|lane| lane.trim().is_empty())
            {
                return Err("workload script gateway lane is empty".to_owned());
            }
            if script.lane.is_none() && script.roles.is_empty() {
                return Err("workload script gateway names neither a lane nor roles".to_owned());
            }
            script.gateway.validate()?;
            script.credential.validate()?;
            if seen.contains(script.gateway.host.as_str()) {
                return Err(format!(
                    "workload gateway host {:?} is also declared in the site allowlist",
                    script.gateway.host
                ));
            }
        }
        let Some(agent) = &self.agent else {
            return Ok(());
        };
        agent.gateway.validate()?;
        if seen.contains(agent.gateway.host.as_str()) {
            return Err(format!(
                "workload gateway host {:?} is also declared in the site allowlist",
                agent.gateway.host
            ));
        }
        agent.credential.validate()
    }
}

impl WorkloadPodPlan {
    // The same bounds the registry publishes, re-checked on replay.
    fn validate_data(&self) -> Result<(), String> {
        let mut taken = vec![self.state_mount.as_str(), self.export_mount.as_str()];
        taken.extend(odin_registry::RESERVED_POD_PATHS);
        taken.extend(
            self.agent
                .as_ref()
                .and_then(|agent| agent.home_dir.as_deref()),
        );
        for (index, data) in self.data.iter().enumerate() {
            if data.name.trim().is_empty() {
                return Err("workload data mount requires a name".to_owned());
            }
            if !valid_pod_path(&data.host_path)
                || odin_registry::FORBIDDEN_DATA_HOST_ROOTS
                    .iter()
                    .any(|root| std::path::Path::new(&data.host_path).starts_with(root))
            {
                return Err(format!(
                    "workload data {:?} host path {:?} is not an allowed absolute host path",
                    data.name, data.host_path
                ));
            }
            if !valid_pod_path(&data.pod_path) {
                return Err(format!(
                    "workload data {:?} pod path {:?} is not a valid absolute in-pod path",
                    data.name, data.pod_path
                ));
            }
            let earlier = self.data[..index]
                .iter()
                .map(|other| other.pod_path.as_str());
            if let Some(other) = taken
                .iter()
                .copied()
                .chain(earlier)
                .find(|other| paths_nest_or_collide(&data.pod_path, other))
            {
                return Err(format!(
                    "workload data {:?} pod path {:?} collides or nests with {other:?}",
                    data.name, data.pod_path
                ));
            }
        }
        // State, export and home may not sit in the memory-backed shared memory mount.
        for path in [self.state_mount.as_str(), self.export_mount.as_str()]
            .into_iter()
            .chain(
                self.agent
                    .as_ref()
                    .and_then(|agent| agent.home_dir.as_deref()),
            )
        {
            if paths_nest_or_collide(SHM_MOUNT, path) {
                return Err(format!(
                    "workload mount {path:?} collides or nests with {SHM_MOUNT:?}"
                ));
            }
        }
        Ok(())
    }
}

/// Where a declared `shm` is mounted on the worker.
pub const SHM_MOUNT: &str = "/dev/shm";
const SHM_VOLUME: &str = "odin-shm";

const COMPANY_MAX_CHARS: usize = 80;

/// One directory segment for a report company folder. Slashes and dot segments
/// are refused; the caller supplies the name, and prompt prose is not parsed.
pub fn company_directory(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value == "."
        || value == ".."
        || value.chars().any(|character| character.is_control())
    {
        return Err("company must be one directory segment".to_owned());
    }
    if value.chars().count() > COMPANY_MAX_CHARS {
        return Err(format!("company is over {COMPANY_MAX_CHARS} characters"));
    }
    Ok(value.to_owned())
}

fn run_material(run_id: &RunId) -> String {
    let digest = Digest::hash(format!("odin-kube/workload/v1/{}", run_id.as_str()).as_bytes());
    let bytes = digest.as_bytes();
    let mut name = String::with_capacity(32);
    for byte in &bytes[..16] {
        name.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        name.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    name
}

/// Stable across restart and rehome, including when state is moved to a new volume.
pub fn state_claim_name(run_id: &RunId) -> String {
    format!("odin-state-{}", run_material(run_id))
}

pub fn egress_policy_name(run_id: &RunId) -> String {
    format!("odin-egress-{}", run_material(run_id))
}

/// Check the run label as well as the deterministic object name before reuse.
fn run_claim_labels(run_id: &RunId) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(
        JOB_LABEL_RUN_ID.to_owned(),
        bounded_label_value(run_id.as_str()),
    );
    labels
}

pub fn inject_pod_volumes(
    plan: &WorkloadPodPlan,
    run_id: &RunId,
    volumes: &mut Vec<Volume>,
    mounts: &mut Vec<VolumeMount>,
) {
    volumes.push(Volume {
        name: WORKLOAD_STATE_VOLUME.to_owned(),
        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
            claim_name: state_claim_name(run_id),
            read_only: Some(false),
        }),
        ..Default::default()
    });
    volumes.push(Volume {
        name: WORKLOAD_EXPORT_VOLUME.to_owned(),
        host_path: Some(HostPathVolumeSource {
            path: plan.export_host_folder.clone(),
            type_: Some("Directory".to_owned()),
        }),
        ..Default::default()
    });
    mounts.push(VolumeMount {
        name: WORKLOAD_STATE_VOLUME.to_owned(),
        mount_path: plan.state_mount.clone(),
        read_only: Some(false),
        ..Default::default()
    });
    mounts.push(VolumeMount {
        name: WORKLOAD_EXPORT_VOLUME.to_owned(),
        mount_path: plan.export_mount.clone(),
        read_only: Some(false),
        // Isolate each run's files so its exports can be captured independently.
        sub_path: Some(export_subfolder(run_id)),
        ..Default::default()
    });
    if let Some(shm) = plan.resources.and_then(|resources| resources.shm_bytes) {
        volumes.push(Volume {
            name: SHM_VOLUME.to_owned(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_owned()),
                size_limit: Some(k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                    shm.to_string(),
                )),
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: SHM_VOLUME.to_owned(),
            mount_path: SHM_MOUNT.to_owned(),
            ..Default::default()
        });
    }
    for data in &plan.data {
        let name = format!("odin-data-{}", data.name);
        volumes.push(Volume {
            name: name.clone(),
            host_path: Some(HostPathVolumeSource {
                path: data.host_path.clone(),
                type_: Some("Directory".to_owned()),
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name,
            mount_path: data.pod_path.clone(),
            read_only: Some(true),
            recursive_read_only: Some("IfPossible".to_owned()),
            ..Default::default()
        });
    }
}

/// The run's own folder under the declared export host folder: the run's
/// Job name, stable across restart and rehome.
pub fn export_subfolder(run_id: &RunId) -> String {
    crate::job::job_name(run_id)
}

/// Reuse requires matching run labels, storage request, and any explicit storage class.
pub async fn ensure_state_claim(
    client: &KubeClient,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
) -> Result<PersistentVolumeClaim, KubeError> {
    let claims = client.persistent_volume_claims();
    let name = state_claim_name(run_id);
    let existing = tokio::time::timeout(client.request_timeout(), claims.get_opt(&name))
        .await
        .map_err(|error| KubeError::unavailable(format!("state claim query timed out: {error}")))?
        .map_err(KubeError::from)?;
    if let Some(existing) = existing {
        verify_claim(&existing, run_id, plan)?;
        return Ok(existing);
    }
    let claim = PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(name),
            labels: Some(run_claim_labels(run_id)),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::core::v1::PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_owned()]),
            resources: Some(k8s_openapi::api::core::v1::VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_owned(),
                    k8s_openapi::apimachinery::pkg::api::resource::Quantity(
                        plan.state_storage.clone(),
                    ),
                )])),
                limits: None,
            }),
            // The cluster default need not support cross-node access.
            storage_class_name: plan.state_storage_class.clone(),
            volume_mode: Some("Filesystem".to_owned()),
            ..Default::default()
        }),
        status: None,
    };
    tokio::time::timeout(
        client.request_timeout(),
        claims.create(&PostParams::default(), &claim),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("state claim create timed out: {error}")))?
    .map_err(Into::into)
}

/// Compare only an explicitly declared storage class; the API server supplies its default otherwise.
fn verify_claim(
    claim: &PersistentVolumeClaim,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
) -> Result<(), KubeError> {
    let labels = claim
        .metadata
        .labels
        .as_ref()
        .ok_or_else(|| KubeError::rejected("state claim carries no binding labels"))?;
    if labels.get(JOB_LABEL_RUN_ID).map(String::as_str)
        != Some(bounded_label_value(run_id.as_str()).as_str())
    {
        return Err(KubeError::rejected(
            "state claim under this run's deterministic name belongs to a different run",
        ));
    }
    let spec = claim
        .spec
        .as_ref()
        .ok_or_else(|| KubeError::rejected("state claim carries no spec"))?;
    // The API server canonicalizes quantities (1024Mi is stored as 1Gi), so compare sizes, not text.
    let request = spec
        .resources
        .as_ref()
        .and_then(|resources| resources.requests.as_ref())
        .and_then(|requests| requests.get("storage"))
        .map(|quantity| quantity.0.as_str());
    let declared = storage_quantity_bytes(&plan.state_storage).map_err(KubeError::rejected)?;
    if request.and_then(|request| storage_quantity_bytes(request).ok()) != Some(declared) {
        return Err(KubeError::rejected(format!(
            "state claim storage request is {request:?}, the declared request is {:?}",
            plan.state_storage
        )));
    }
    if plan.state_storage_class.is_some()
        && spec.storage_class_name.as_deref() != plan.state_storage_class.as_deref()
    {
        return Err(KubeError::rejected(
            "state claim storage class differs from the declared class; refusing to move state storage topology in place",
        ));
    }
    Ok(())
}

/// Require matching labels and storage settings, not just an existing claim name.
pub async fn require_state_claim(
    client: &KubeClient,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
) -> Result<PersistentVolumeClaim, KubeError> {
    let claims = client.persistent_volume_claims();
    let name = state_claim_name(run_id);
    let claim = tokio::time::timeout(client.request_timeout(), claims.get_opt(&name))
        .await
        .map_err(|error| KubeError::unavailable(format!("state claim query timed out: {error}")))?
        .map_err(KubeError::from)?
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "state claim {name} does not exist; the run's state claim cannot be confirmed"
            ))
        })?;
    verify_claim(&claim, run_id, plan)?;
    Ok(claim)
}

/// Require the existing policy's run label and declared hosts to match before reuse.
fn verify_policy(
    existing: &NetworkPolicy,
    run_id: &RunId,
    resolved: &ResolvedEgress,
) -> Result<(), KubeError> {
    // A deterministic name alone does not establish which run created the policy.
    let labels = existing.metadata.labels.as_ref().ok_or_else(|| {
        KubeError::rejected(
            "egress policy under this run's deterministic name carries no binding labels",
        )
    })?;
    if labels.get(JOB_LABEL_RUN_ID).map(String::as_str)
        != Some(bounded_label_value(run_id.as_str()).as_str())
    {
        return Err(KubeError::rejected(
            "egress policy under this run's deterministic name belongs to a different run",
        ));
    }
    let declared = existing
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(DECLARED_HOSTS_ANNOTATION))
        .ok_or_else(|| {
            KubeError::rejected(
                "egress policy carries no declared host set; refusing to guess its scope",
            )
        })?;
    let expected = declared_scope(resolved);
    if annotated_scope(declared) != expected.iter().map(String::as_str).collect() {
        return Err(KubeError::rejected(
            "egress policy under this run's deterministic name differs from the declared scope; refusing to change network scope in place",
        ));
    }
    Ok(())
}

/// Check existing policy scope before stopping a workload; launch creates an absent policy.
pub async fn verify_egress_scope(
    client: &KubeClient,
    run_id: &RunId,
    plan: &WorkloadPodPlan,
) -> Result<(), KubeError> {
    let resolved = resolve_declared_hosts(plan).await?;
    let name = egress_policy_name(run_id);
    let existing = tokio::time::timeout(
        client.request_timeout(),
        client.network_policies().get_opt(&name),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("egress policy query timed out: {error}")))?
    .map_err(KubeError::from)?;
    match existing {
        Some(existing) => verify_policy(&existing, run_id, &resolved),
        None => Ok(()),
    }
}

pub async fn ensure_resolved_egress_policy(
    client: &KubeClient,
    run_id: &RunId,
    resolved: &ResolvedEgress,
) -> Result<(), KubeError> {
    let desired = desired_egress_policy(run_id, resolved);
    let policies = client.network_policies();
    let name = egress_policy_name(run_id);
    let existing = tokio::time::timeout(client.request_timeout(), policies.get_opt(&name))
        .await
        .map_err(|error| KubeError::unavailable(format!("egress policy query timed out: {error}")))?
        .map_err(KubeError::from)?;
    let Some(existing) = existing else {
        tokio::time::timeout(
            client.request_timeout(),
            policies.create(&PostParams::default(), &desired),
        )
        .await
        .map_err(|error| {
            KubeError::unavailable(format!("egress policy create timed out: {error}"))
        })?
        .map_err(KubeError::from)?;
        return Ok(());
    };
    verify_policy(&existing, run_id, resolved)?;
    // Refresh resolved addresses without changing the declared host set.
    let same = match (&existing.spec, &desired.spec) {
        (Some(existing_spec), Some(desired_spec)) => serde_json::to_value(existing_spec)
            .ok()
            .zip(serde_json::to_value(desired_spec).ok())
            .is_some_and(|(existing, desired)| existing == desired),
        _ => false,
    };
    if same {
        return Ok(());
    }
    tokio::time::timeout(
        client.request_timeout(),
        policies.replace(&name, &PostParams::default(), &desired),
    )
    .await
    .map_err(|error| KubeError::unavailable(format!("egress policy update timed out: {error}")))?
    .map_err(KubeError::from)?;
    Ok(())
}

/// Makes the run's egress policy a dependent of its Job, so Kubernetes
/// removes the policy with the Job. The Job's foreground deletion waits for
/// it, so a recreated Job never inherits a policy that is about to vanish.
pub async fn own_egress_policy(
    client: &KubeClient,
    run_id: &RunId,
    job: &k8s_openapi::api::batch::v1::Job,
) -> Result<(), KubeError> {
    let (Some(job_name), Some(job_uid)) = (&job.metadata.name, &job.metadata.uid) else {
        return Err(KubeError::rejected(
            "the created Job carries no name or UID",
        ));
    };
    let policies = client.network_policies();
    let name = egress_policy_name(run_id);
    let existing = tokio::time::timeout(client.request_timeout(), policies.get_opt(&name))
        .await
        .map_err(|_| KubeError::unavailable("egress policy query timed out"))?
        .map_err(KubeError::from)?;
    let Some(existing) = existing else {
        return Ok(());
    };
    let owned = existing
        .metadata
        .owner_references
        .iter()
        .flatten()
        .any(|owner| &owner.uid == job_uid);
    if owned {
        return Ok(());
    }
    let owner = OwnerReference {
        api_version: JOB_API_VERSION.to_owned(),
        kind: JOB_KIND.to_owned(),
        name: job_name.clone(),
        uid: job_uid.clone(),
        block_owner_deletion: Some(true),
        controller: None,
    };
    let patch = serde_json::json!({ "metadata": { "ownerReferences": [owner] } });
    tokio::time::timeout(
        client.request_timeout(),
        policies.patch(&name, &PatchParams::default(), &Patch::Merge(&patch)),
    )
    .await
    .map_err(|_| KubeError::unavailable("egress policy owner patch timed out"))?
    .map_err(KubeError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::egress::{network_policy_port, resolve_gateway_host};
    use super::*;

    fn declared_credential() -> WorkloadCredentialEnv {
        WorkloadCredentialEnv {
            env_name: WORKLOAD_CREDENTIAL_ENV.to_owned(),
            secret: "gateway-secret".to_owned(),
            key: "master".to_owned(),
        }
    }

    #[test]
    fn a_stored_plan_without_the_new_fields_replays_unchanged() {
        let plan = declared_plan();
        let mut stored = serde_json::to_value(&plan).expect("plan json");
        for key in ["termination_grace_seconds", "data"] {
            assert!(stored.get(key).is_none(), "{key} is omitted when unset");
        }
        stored["resources"] = serde_json::json!({"cpu": 1, "memory_bytes": 1024});
        let replayed: WorkloadPodPlan = serde_json::from_value(stored).expect("replay");
        assert_eq!(replayed.resources.and_then(|r| r.shm_bytes), None);
        assert_eq!(replayed.termination_grace_seconds, None);
        assert!(replayed.data.is_empty());
    }

    fn declared_plan() -> WorkloadPodPlan {
        let plan = WorkloadPodPlan {
            resources: None,
            termination_grace_seconds: None,
            data: Vec::new(),
            control: None,
            keep_finished_seconds: None,
            on_yield: Default::default(),
            script_gateway: None,
            profile: "continuity-fixture".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            state_carry: true,
            allow_hosts: vec!["example.com".to_owned()],
            network_open: false,
            transport: odin_registry::WorkloadTransport::Direct,
            vpn: None,
            report_pdf: false,
            report_downloads_root: None,
            export_deliver_root: None,
            company: None,
            agent: Some(crate::workload::WorkloadAgentPlan {
                launcher: "/odin/bin/omp-launch".to_owned(),
                gateway: WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 14000,
                },
                browser: "/odin/bin/chromium".to_owned(),
                supervisor: "/odin/bin/odind".to_owned(),
                playwright: "/odin/lib/playwright-core".to_owned(),
                browser_node: "/odin/bin/node".to_owned(),
                browser_engine: odin_registry::BrowserEngine::default(),
                display: WorkloadDisplayPlan {
                    xvfb: "/odin/bin/Xvfb".to_owned(),
                    screen: "1280x800x24".to_owned(),
                    stream: true,
                },
                home_dir: None,
                credential: declared_credential(),
            }),
        };
        plan.validate().expect("declared plan");
        plan
    }

    fn refused_with(change: impl FnOnce(&mut WorkloadPodPlan)) -> Option<String> {
        let mut plan = declared_plan();
        change(&mut plan);
        plan.validate().err()
    }

    fn agent_of(plan: &mut WorkloadPodPlan) -> &mut WorkloadAgentPlan {
        plan.agent.as_mut().expect("agent plan")
    }

    #[test]
    fn plan_law_refuses_unsafe_mounts_paths_and_storage() {
        assert!(refused_with(|plan| plan.state_mount = "state".to_owned()).is_some());
        assert!(refused_with(|plan| plan.export_mount = "/state/inner".to_owned()).is_some());
        assert!(refused_with(|plan| plan.export_mount = "/state".to_owned()).is_some());
        assert!(
            refused_with(|plan| plan.export_host_folder = "/srv/../escape".to_owned()).is_some()
        );
        assert!(refused_with(|plan| plan.state_storage = "2GiB".to_owned()).is_some());
        assert!(
            refused_with(|plan| plan.state_storage_class = Some("Bad_Class".to_owned())).is_some()
        );
        for home in [
            "/state/home",
            "/export",
            "/export/home",
            BROWSER_SOCKET_DIR,
            "/dev/shm",
            "/dev/shm/agent",
        ] {
            assert!(
                refused_with(|plan| agent_of(plan).home_dir = Some(home.to_owned())).is_some(),
                "home {home} collides with a mount"
            );
        }
        let mut plan = declared_plan();
        agent_of(&mut plan).home_dir = Some("/home/agent".to_owned());
        plan.state_storage_class = Some("fast-class".to_owned());
        plan.validate()
            .expect("a disjoint home dir and a DNS-name class are lawful");
    }

    #[test]
    fn plan_law_refuses_widened_or_duplicated_egress_scope() {
        for host in ["example.com:443", "*.example.com", "Example.com"] {
            assert!(
                refused_with(|plan| plan.allow_hosts = vec![host.to_owned()]).is_some(),
                "{host} is not a declared host name"
            );
        }
        let twice = refused_with(|plan| {
            plan.allow_hosts = vec!["example.com".to_owned(), "example.com".to_owned()];
        })
        .expect("a host declared twice");
        assert!(twice.contains("declared twice"), "{twice}");
        assert!(
            refused_with(|plan| agent_of(plan).gateway.host = "example.com".to_owned()).is_some(),
            "the gateway host may not also be a site host"
        );
        let hosts = |count: usize| -> Vec<String> {
            (0..count)
                .map(|index| format!("host{index}.example.net"))
                .collect()
        };
        assert!(refused_with(|plan| plan.allow_hosts = hosts(MAX_ALLOW_HOSTS)).is_some());
        let mut plan = declared_plan();
        plan.allow_hosts = hosts(MAX_ALLOW_HOSTS - 1);
        plan.validate()
            .expect("site hosts plus the gateway target fit the bound");
    }

    fn resolved_egress() -> ResolvedEgress {
        ResolvedEgress {
            deny_ingress: false,
            sites: BTreeMap::from([(
                "example.com".to_owned(),
                BTreeSet::from(["93.184.216.34".parse::<IpAddr>().expect("ip")]),
            )]),
            unresolved: BTreeMap::new(),
            pinned: vec![(
                WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 14000,
                },
                BTreeSet::from(["100.64.0.12".parse::<IpAddr>().expect("ip")]),
            )],
            open: false,
            protected: None,
        }
    }

    #[test]
    fn every_pinned_target_keeps_its_own_port_and_scope() {
        let mut resolved = resolved_egress();
        resolved.pinned.push((
            WorkloadGatewayTarget {
                host: "10.0.0.11".to_owned(),
                port: 9418,
            },
            BTreeSet::from(["10.0.0.11".parse::<IpAddr>().expect("ip")]),
        ));
        let rules = egress_rules(&resolved);
        let ports_to = |cidr: &str| {
            rules
                .iter()
                .find(|rule| {
                    rule.to.as_ref().is_some_and(|peers| {
                        peers[0]
                            .ip_block
                            .as_ref()
                            .is_some_and(|block| block.cidr == cidr)
                    })
                })
                .unwrap_or_else(|| panic!("no rule pins {cidr}"))
                .ports
                .clone()
                .expect("ports")
        };
        assert_eq!(
            ports_to("93.184.216.34/32"),
            [
                network_policy_port("TCP", 80),
                network_policy_port("TCP", 443),
                network_policy_port("UDP", 443),
            ],
            "a site pin keeps the HTTP/TLS/QUIC ports"
        );
        assert_eq!(
            ports_to("100.64.0.12/32"),
            [network_policy_port("TCP", 14000)]
        );
        assert_eq!(
            ports_to("10.0.0.11/32"),
            [network_policy_port("TCP", 9418)]
        );
        assert_eq!(
            declared_scope(&resolved),
            [
                "example.com",
                "gateway.example.net:14000",
                "10.0.0.11:9418"
            ]
        );
    }

    #[test]
    fn egress_policy_is_default_deny_and_selects_only_this_run() {
        let run = RunId::new("egress-scope-law").expect("run id");
        let resolved = resolved_egress();
        let policy = desired_egress_policy(&run, &resolved);
        let spec = policy.spec.as_ref().expect("spec");
        assert_eq!(spec.policy_types.as_ref().expect("types"), &["Egress"]);
        assert_eq!(
            spec.pod_selector
                .as_ref()
                .expect("selector")
                .match_labels
                .as_ref()
                .expect("labels")
                .get(JOB_LABEL_RUN_ID),
            Some(&bounded_label_value(run.as_str()))
        );
        assert_eq!(
            spec.egress.as_ref().expect("egress").len(),
            3,
            "DNS rule plus the site pin plus the gateway pin"
        );
        assert_eq!(
            policy
                .metadata
                .annotations
                .as_ref()
                .expect("annotations")
                .get(DECLARED_HOSTS_ANNOTATION),
            Some(&"example.com,gateway.example.net:14000".to_owned())
        );
    }

    fn pv_with_required_terms(
        terms: Vec<k8s_openapi::api::core::v1::NodeSelectorTerm>,
    ) -> PersistentVolume {
        PersistentVolume {
            spec: Some(k8s_openapi::api::core::v1::PersistentVolumeSpec {
                node_affinity: Some(k8s_openapi::api::core::v1::VolumeNodeAffinity {
                    required: Some(k8s_openapi::api::core::v1::NodeSelector {
                        node_selector_terms: terms,
                    }),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn hostname_in_term(values: &[&str]) -> k8s_openapi::api::core::v1::NodeSelectorTerm {
        k8s_openapi::api::core::v1::NodeSelectorTerm {
            match_expressions: Some(vec![k8s_openapi::api::core::v1::NodeSelectorRequirement {
                key: "kubernetes.io/hostname".to_owned(),
                operator: "In".to_owned(),
                values: Some(values.iter().map(|value| value.to_string()).collect()),
            }]),
            ..Default::default()
        }
    }

    fn pv_with_hostname_affinity(values: &[&str]) -> PersistentVolume {
        pv_with_required_terms(vec![hostname_in_term(values)])
    }

    #[test]
    fn rehome_admission_evaluates_real_selector_semantics() {
        let pv = pv_with_hostname_affinity(&["laptop", "mini"]);
        let labels = |hostname: &str| {
            BTreeMap::from([("kubernetes.io/hostname".to_owned(), hostname.to_owned())])
        };
        assert!(pv_admits_node_labels(&pv, "laptop", &labels("laptop")).is_ok());
        assert!(pv_admits_node_labels(&pv, "pc", &labels("pc")).is_err());
        // Disjunction of terms: a second term admitting another node holds.
        let two_terms = pv_with_required_terms(vec![
            hostname_in_term(&["laptop"]),
            k8s_openapi::api::core::v1::NodeSelectorTerm {
                match_fields: Some(vec![k8s_openapi::api::core::v1::NodeSelectorRequirement {
                    key: "metadata.name".to_owned(),
                    operator: "In".to_owned(),
                    values: Some(vec!["pc".to_owned()]),
                }]),
                ..Default::default()
            },
        ]);
        // The first term matches the hostname label; the second matches by
        // name even with no labels at all.
        assert!(pv_admits_node_labels(&two_terms, "laptop", &labels("laptop")).is_ok());
        assert!(pv_admits_node_labels(&two_terms, "pc", &BTreeMap::new()).is_ok());
        assert!(pv_admits_node_labels(&two_terms, "mini", &BTreeMap::new()).is_err());
        // No affinity is unrestricted; an unsupported constraint is not.
        assert!(
            pv_admits_node_labels(&PersistentVolume::default(), "mini", &BTreeMap::new()).is_ok()
        );
        // A required label missing from the target prevents admission.
        let exotic = pv_with_required_terms(vec![k8s_openapi::api::core::v1::NodeSelectorTerm {
            match_expressions: Some(vec![k8s_openapi::api::core::v1::NodeSelectorRequirement {
                key: "node.kubernetes.io/instance-type".to_owned(),
                operator: "Exists".to_owned(),
                values: None,
            }]),
            ..Default::default()
        }]);
        assert!(pv_admitted_nodes(&exotic).is_empty(), "report stays honest");
        assert!(pv_admits_node_labels(&exotic, "laptop", &BTreeMap::new()).is_err());
    }

    #[tokio::test]
    async fn probe_and_egress_refuse_the_same_inadmissible_authority_classes() {
        let inadmissible = [
            ("127.0.0.1", "loopback"),
            ("0.0.0.0", "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("224.0.0.1", "multicast"),
            ("::1", "loopback"),
            ("::ffff:127.0.0.1", "loopback"),
        ];
        for (host, class) in inadmissible {
            let parsed = host.parse::<IpAddr>().expect("IP literal");
            assert_eq!(
                odin_registry::schema::node_gateway_address_class(&parsed),
                Some(class),
                "{host} must classify as {class}"
            );
            let target = WorkloadGatewayTarget {
                host: host.to_owned(),
                port: 14000,
            };
            match probe_gateway_target(&target).await {
                Err(GatewayProbeError::Inadmissible { detail, .. }) => {
                    assert!(
                        detail.contains(class) && detail.contains(host),
                        "probe refusal for {host} must name its class: {detail}"
                    );
                }
                other => {
                    panic!("the probe must refuse {host} ({class}) before connecting: {other:?}")
                }
            }
            match resolve_gateway_host(host).await {
                Err(error) => {
                    let message = error.to_string();
                    assert!(
                        message.contains(class) && message.contains(host),
                        "egress refusal for {host} must name its class: {message}"
                    );
                }
                Ok(_) => panic!("egress resolution must refuse {host} ({class})"),
            }
        }
    }
}
