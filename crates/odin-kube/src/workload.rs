//! Workload plans carry declared state, export paths, and network access.
//!
//! State claims are per-run and reused on restart; rehome checks volume affinity.
//! Exports use a per-run subfolder of an existing host directory.
//! Egress policies pin resolved IPs, not hostnames: shared IPs and DNS rebinding
//! are outside their protection. DNS rotation may refresh pins without changing
//! the declared hosts or gateway port.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use k8s_openapi::api::core::v1::{
    EmptyDirVolumeSource, HostPathVolumeSource, PersistentVolume, PersistentVolumeClaim,
    PersistentVolumeClaimVolumeSource, Pod, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    IPBlock, NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{ListParams, PostParams};
use odin_domain::{Digest, RunId};
use odin_registry::BrowserEngine;
use serde::{Deserialize, Serialize};

use odin_registry::schema::{
    paths_nest_or_collide, storage_quantity_bytes, valid_allow_host, valid_pod_path, valid_screen,
};
use thiserror::Error;

use crate::client::{KubeClient, KubeError};
use crate::job::{bounded_label_value, JOB_LABEL_RUN_ID};
mod egress;
pub(crate) use egress::desired_egress_policy;
use egress::{annotated_scope, declared_scope};
pub use egress::{egress_rules, resolve_declared_hosts, resolve_hosts, ResolvedEgress};

mod placement;
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
                "workload credential custody requires a nonempty Secret name and key".to_owned(),
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
const DECLARED_HOSTS_ANNOTATION: &str = "odin.dev/declared-hosts";

/// Site ports only; gateway targets use their own declared TCP port.
const EGRESS_TCP_PORTS: [i32; 2] = [80, 443];
const EGRESS_UDP_PORTS: [i32; 1] = [443];

/// Limits the daemon-host TCP probe, not a pod-network or provider-readiness check.
const GATEWAY_PROBE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

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
    let budget = GATEWAY_PROBE_BUDGET;
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
    .map_err(|_| refusal("host resolution exceeded the probe budget".to_owned()))?
    .map_err(|error| refusal(error.to_string()))?
    .collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(refusal("the host resolved to no address".to_owned()));
    }
    // Reject any inadmissible address before connecting, using the same check as egress.
    let inadmissible = resolved
        .iter()
        .filter_map(|address| {
            odin_registry::schema::node_gateway_address_class(&address.ip())
                .map(|class| format!("{address} ({class})"))
        })
        .collect::<Vec<_>>();
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
    /// Site hosts allowed on HTTP/TLS/QUIC ports; excludes the gateway's separate port.
    pub allow_hosts: Vec<String>,
    /// `None` for a script pod.
    #[serde(flatten)]
    pub agent: Option<WorkloadAgentPlan>,
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
        if let Some(class) = &self.state_storage_class {
            if !valid_allow_host(class) {
                return Err(format!(
                    "workload storage class {class:?} is not a declared DNS name"
                ));
            }
        }
        if !valid_pod_path(&self.state_mount) {
            return Err(format!(
                "workload state mount {:?} is not a valid absolute in-pod path",
                self.state_mount
            ));
        }
        if !valid_pod_path(&self.export_mount) {
            return Err(format!(
                "workload export mount {:?} is not a valid absolute in-pod path",
                self.export_mount
            ));
        }
        if let Some(home) = self
            .agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_ref())
        {
            if !valid_pod_path(home) {
                return Err(format!(
                    "workload home dir {home:?} is not a valid absolute in-pod path"
                ));
            }
        }
        if paths_nest_or_collide(&self.state_mount, &self.export_mount) {
            return Err(format!(
                "workload state mount {:?} and export mount {:?} collide or nest",
                self.state_mount, self.export_mount
            ));
        }
        if let Some(home) = self
            .agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_ref())
        {
            if paths_nest_or_collide(&self.state_mount, home) {
                return Err(format!(
                    "workload home dir {home:?} collides or nests with the state mount {:?}",
                    self.state_mount
                ));
            }
        }
        if let Some(home) = self
            .agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_ref())
        {
            if paths_nest_or_collide(&self.export_mount, home) {
                return Err(format!(
                    "workload home dir {home:?} collides or nests with the export mount {:?}",
                    self.export_mount
                ));
            }
        }
        // Overlapping mounts could shadow or expose the private relay socket.
        for (what, mount) in [
            ("state mount", &self.state_mount),
            ("export mount", &self.export_mount),
        ] {
            if paths_nest_or_collide(BROWSER_SOCKET_DIR, mount) {
                return Err(format!(
                    "the relay socket directory {BROWSER_SOCKET_DIR:?} collides or nests with                      the workload {what} {mount:?}"
                ));
            }
        }
        if let Some(home) = self
            .agent
            .as_ref()
            .and_then(|agent| agent.home_dir.as_ref())
        {
            if paths_nest_or_collide(BROWSER_SOCKET_DIR, home) {
                return Err(format!(
                    "the relay socket directory {BROWSER_SOCKET_DIR:?} collides or nests with                      the workload home dir {home:?}"
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
        let egress_hosts = self.allow_hosts.len() + usize::from(self.agent.is_some());
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
        .map_err(|_| KubeError::unavailable("state claim query timed out"))?
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
    .map_err(|_| KubeError::unavailable("state claim create timed out"))?
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
    let request = spec
        .resources
        .as_ref()
        .and_then(|resources| resources.requests.as_ref())
        .and_then(|requests| requests.get("storage"))
        .map(|quantity| quantity.0.clone());
    if request.as_deref() != Some(plan.state_storage.as_str()) {
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
        .map_err(|_| KubeError::unavailable("state claim query timed out"))?
        .map_err(KubeError::from)?
        .ok_or_else(|| {
            KubeError::rejected(format!(
                "state claim {name} does not exist; state custody cannot be proven for this run"
            ))
        })?;
    verify_claim(&claim, run_id, plan)?;
    Ok(claim)
}

/// Require the existing policy's run label and declared hosts to match before reuse.
fn policy_custody(
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
    .map_err(|_| KubeError::unavailable("egress policy query timed out"))?
    .map_err(KubeError::from)?;
    match existing {
        Some(existing) => policy_custody(&existing, run_id, &resolved),
        None => Ok(()),
    }
}

pub async fn ensure_resolved_egress_policy(
    client: &KubeClient,
    run_id: &RunId,
    resolved: &ResolvedEgress,
) -> Result<(), KubeError> {
    let resolved = resolved.clone();
    let desired = desired_egress_policy(run_id, &resolved);
    let policies = client.network_policies();
    let name = egress_policy_name(run_id);
    let existing = tokio::time::timeout(client.request_timeout(), policies.get_opt(&name))
        .await
        .map_err(|_| KubeError::unavailable("egress policy query timed out"))?
        .map_err(KubeError::from)?;
    let Some(existing) = existing else {
        tokio::time::timeout(
            client.request_timeout(),
            policies.create(&PostParams::default(), &desired),
        )
        .await
        .map_err(|_| KubeError::unavailable("egress policy create timed out"))?
        .map_err(KubeError::from)?;
        return Ok(());
    };
    policy_custody(&existing, run_id, &resolved)?;
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
    .map_err(|_| KubeError::unavailable("egress policy update timed out"))?
    .map_err(KubeError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn an_empty_declared_host_annotation_is_the_empty_scope() {
        assert!(super::annotated_scope("").is_empty());
        assert_eq!(
            super::annotated_scope("arxiv.org,export.arxiv.org"),
            ["arxiv.org", "export.arxiv.org"].into_iter().collect()
        );
    }
    use super::egress::{network_policy_port, resolve_gateway_host};
    use super::*;

    fn declared_credential() -> WorkloadCredentialEnv {
        WorkloadCredentialEnv {
            env_name: "ODIN_GATEWAY_KEY".to_owned(),
            secret: "gateway-secret".to_owned(),
            key: "master".to_owned(),
        }
    }

    fn declared_plan() -> WorkloadPodPlan {
        let plan = WorkloadPodPlan {
            profile: "continuity-fixture".to_owned(),
            state_mount: "/state".to_owned(),
            export_mount: "/export".to_owned(),
            export_host_folder: "/srv/odin/export".to_owned(),
            state_storage: "2Gi".to_owned(),
            state_storage_class: None,
            allow_hosts: vec!["example.com".to_owned()],
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

    #[test]
    fn plan_law_rejects_a_relative_browser_node() {
        let mut plan = declared_plan();
        plan.agent.as_mut().expect("agent plan").browser_node = "bin/node".to_owned();
        assert!(
            plan.validate().is_err(),
            "the resolved browser node must be an absolute in-image path"
        );
    }

    #[test]
    fn an_obscura_pod_runs_no_browser_container() {
        let mut plan = declared_plan();
        assert!(plan.browser_command().is_some());
        plan.agent.as_mut().expect("agent plan").browser_engine = BrowserEngine::Obscura;
        assert_eq!(plan.browser_command(), None);
    }

    #[test]
    fn plan_law_rejects_unsafe_paths_folders_and_storage() {
        let mut plan = declared_plan();
        plan.state_mount = "state".to_owned();
        assert!(plan.validate().is_err());
        plan.state_mount = "/state".to_owned();
        plan.export_mount = "/state/inner".to_owned();
        assert!(plan.validate().is_err(), "nested mounts collide");
        plan.export_mount = "/state".to_owned();
        assert!(plan.validate().is_err(), "equal mounts collide");
        plan.export_mount = "/export".to_owned();
        plan.export_host_folder = "srv/relative".to_owned();
        assert!(plan.validate().is_err());
        plan.export_host_folder = "/srv/../escape".to_owned();
        assert!(plan.validate().is_err());
        plan.export_host_folder = "/srv/odin/export".to_owned();
        plan.state_storage = "twoGi".to_owned();
        assert!(plan.validate().is_err());
        plan.state_storage = "2GiB".to_owned();
        assert!(plan.validate().is_err());
        plan.state_storage = "2Gi".to_owned();
        plan.agent.as_mut().expect("agent plan").home_dir = Some("/state/home".to_owned());
        assert!(plan.validate().is_err(), "home nests in the state mount");
        plan.agent.as_mut().expect("agent plan").home_dir = Some("/export".to_owned());
        assert!(
            plan.validate().is_err(),
            "home equal to the export mount collides"
        );
        plan.agent.as_mut().expect("agent plan").home_dir = Some("/export/home".to_owned());
        assert!(plan.validate().is_err(), "home nests in the export mount");
        plan.agent.as_mut().expect("agent plan").home_dir = Some("/home/agent".to_owned());
        plan.validate()
            .expect("a home dir disjoint from both mounts is lawful");
        plan.state_storage_class = Some("Bad_Class".to_owned());
        assert!(plan.validate().is_err(), "a storage class is a DNS name");
        plan.agent.as_mut().expect("agent plan").home_dir = None;
        plan.state_storage_class = Some("fast-class".to_owned());
        plan.validate().expect("an explicit class is lawful");
    }

    #[test]
    fn plan_law_rejects_unsafe_browser_surface() {
        let mut plan = declared_plan();
        plan.agent.as_mut().expect("agent plan").browser = "chromium".to_owned();
        assert!(
            plan.validate().is_err(),
            "a relative browser executable is refused"
        );
        plan.agent.as_mut().expect("agent plan").browser = "/odin/bin/chromium".to_owned();
        plan.agent.as_mut().expect("agent plan").supervisor = "/odin//odind".to_owned();
        assert!(
            plan.validate().is_err(),
            "an empty path component is refused by the shared pod-path grammar"
        );
        plan.agent.as_mut().expect("agent plan").supervisor = "/odin/bin/odind/".to_owned();
        assert!(
            plan.validate().is_err(),
            "a trailing slash is refused by the shared pod-path grammar"
        );
        plan.agent.as_mut().expect("agent plan").supervisor = "/odin/bin/odind".to_owned();
        plan.agent.as_mut().expect("agent plan").playwright =
            "/odin/lib/../lib/playwright-core".to_owned();
        assert!(
            plan.validate().is_err(),
            "`..` escapes are refused inside in-image paths"
        );
        plan.agent.as_mut().expect("agent plan").playwright =
            "/odin/lib/playwright-core".to_owned();
        plan.agent.as_mut().expect("agent plan").display.screen = "1280x800".to_owned();
        assert!(
            plan.validate().is_err(),
            "the display screen is the full WxHxD grammar"
        );
        plan.agent.as_mut().expect("agent plan").display.screen = "0x800x24".to_owned();
        assert!(plan.validate().is_err(), "a zero dimension is refused");
        plan.agent.as_mut().expect("agent plan").display.screen = "1280x800x24".to_owned();
        plan.agent.as_mut().expect("agent plan").display.xvfb = "Xvfb".to_owned();
        assert!(plan.validate().is_err(), "a relative Xvfb path is refused");
        plan.agent.as_mut().expect("agent plan").display.xvfb = "/odin/bin/Xvfb".to_owned();
        plan.validate()
            .expect("the restored declared surface is lawful");
    }

    #[test]
    fn plan_law_rejects_widened_or_duplicated_egress_scope() {
        let mut plan = declared_plan();
        plan.allow_hosts = vec!["example.com:443".to_owned()];
        assert!(plan.validate().is_err(), "ports are not hosts");
        plan.allow_hosts = vec!["*.example.com".to_owned()];
        assert!(plan.validate().is_err(), "wildcards are not hosts");
        plan.allow_hosts = vec!["Example.com".to_owned()];
        assert!(plan.validate().is_err(), "hosts are lowercase");
        plan.allow_hosts = vec!["example.com".to_owned()];
        plan.agent.as_mut().expect("agent plan").gateway.host = "example.com".to_owned();
        assert!(
            plan.validate().is_err(),
            "the gateway host is also a site host"
        );
        plan.agent.as_mut().expect("agent plan").gateway.host = "gateway.example.net".to_owned();
        plan.allow_hosts = (0..MAX_ALLOW_HOSTS)
            .map(|index| format!("host{index}.example.net"))
            .collect();
        assert!(plan.validate().is_err(), "the declared-host bound is hard");
        plan.allow_hosts = (0..MAX_ALLOW_HOSTS - 1)
            .map(|index| format!("host{index}.example.net"))
            .collect();
        plan.validate()
            .expect("site hosts plus the one gateway target stay inside the bound");
    }

    #[test]
    fn storage_quantity_law_is_the_registry_grammar() {
        // Use the registry's binary-unit grammar, not Kubernetes' broader quantity syntax.
        for lawful in ["2Gi", "500Mi", "1Ei"] {
            assert!(storage_quantity_bytes(lawful).is_ok(), "{lawful} is lawful");
        }
        for refused in [
            "", "Gi", "2GiB", "twoGi", "1.2.3Gi", "1e9", "1", "1.5G", "10T",
        ] {
            assert!(
                storage_quantity_bytes(refused).is_err(),
                "{refused} is refused"
            );
        }
        let mut plan = declared_plan();
        plan.state_storage = "10T".to_owned();
        assert!(
            plan.validate().is_err(),
            "validate refuses what the registry grammar refuses"
        );
    }

    #[test]
    fn pod_volumes_mount_exactly_the_declared_paths() {
        let plan = declared_plan();
        let run = RunId::new("volume-mount-law").expect("run id");
        let mut volumes = Vec::new();
        let mut mounts = Vec::new();
        inject_pod_volumes(&plan, &run, &mut volumes, &mut mounts);
        assert_eq!(volumes.len(), 2);
        assert_eq!(mounts.len(), 2);
        let claim = volumes[0].persistent_volume_claim.as_ref().expect("pvc");
        assert_eq!(claim.claim_name, state_claim_name(&run));
        let host_path = volumes[1].host_path.as_ref().expect("hostPath");
        assert_eq!(host_path.path, "/srv/odin/export");
        assert_eq!(host_path.type_.as_deref(), Some("Directory"));
        assert_eq!(mounts[0].mount_path, "/state");
        assert_eq!(mounts[1].mount_path, "/export");
        assert_eq!(
            mounts[1].sub_path.as_deref(),
            Some(crate::job::job_name(&run).as_str()),
            "each run exports into its own folder under the declared host folder"
        );
    }

    fn resolved_egress() -> ResolvedEgress {
        ResolvedEgress {
            sites: BTreeMap::from([(
                "example.com".to_owned(),
                BTreeSet::from(["93.184.216.34".parse::<IpAddr>().expect("ip")]),
            )]),
            pinned: vec![(
                WorkloadGatewayTarget {
                    host: "gateway.example.net".to_owned(),
                    port: 14000,
                },
                BTreeSet::from(["100.64.0.12".parse::<IpAddr>().expect("ip")]),
            )],
        }
    }

    #[test]
    fn every_pinned_target_keeps_its_own_port_and_scope() {
        let mut resolved = resolved_egress();
        resolved.pinned.push((
            WorkloadGatewayTarget {
                host: "10.77.0.11".to_owned(),
                port: 9418,
            },
            BTreeSet::from(["10.77.0.11".parse::<IpAddr>().expect("ip")]),
        ));
        let mirror = egress_rules(&resolved)
            .into_iter()
            .find(|rule| {
                rule.to.as_ref().is_some_and(|peers| {
                    peers[0]
                        .ip_block
                        .as_ref()
                        .is_some_and(|block| block.cidr == "10.77.0.11/32")
                })
            })
            .expect("the mirror is pinned");
        assert_eq!(
            mirror.ports.expect("ports"),
            [network_policy_port("TCP", 9418)]
        );
        assert_eq!(
            declared_scope(&resolved),
            [
                "example.com",
                "gateway.example.net:14000",
                "10.77.0.11:9418"
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

    #[test]
    fn gateway_pin_carries_the_declared_port_apart_from_site_ports() {
        let rules = egress_rules(&resolved_egress());
        let ports_of = |rule: &NetworkPolicyEgressRule| {
            rule.ports
                .as_ref()
                .expect("ports")
                .iter()
                .map(|port| match port.port.as_ref().expect("port") {
                    IntOrString::Int(value) => (port.protocol.clone().expect("protocol"), *value),
                    other => panic!("unexpected port {other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ports_of(&rules[1]),
            vec![
                ("TCP".to_owned(), 80),
                ("TCP".to_owned(), 443),
                ("UDP".to_owned(), 443),
            ],
            "the site pin keeps the declared HTTP/TLS/QUIC ports"
        );
        assert_eq!(
            ports_of(&rules[2]),
            vec![("TCP".to_owned(), 14000)],
            "the gateway pin carries the endpoint's effective port"
        );
        let block = rules[2].to.as_ref().expect("peers")[0]
            .ip_block
            .as_ref()
            .expect("ipBlock");
        assert_eq!(block.cidr, "100.64.0.12/32");
        assert_eq!(
            rules[1].to.as_ref().expect("peers")[0]
                .ip_block
                .as_ref()
                .expect("ipBlock")
                .cidr,
            "93.184.216.34/32"
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

    /// A live loopback listener must still fail the pod-address check.
    #[tokio::test]
    async fn async_gateway_probe_decides_admissibility_before_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let live_loopback = WorkloadGatewayTarget {
            host: "127.0.0.1".to_owned(),
            port,
        };
        match probe_gateway_target(&live_loopback).await {
            Err(GatewayProbeError::Inadmissible { detail, .. }) => {
                assert!(detail.contains("loopback"), "{detail}");
            }
            other => panic!("a live loopback listener must never be readiness: {other:?}"),
        }
        drop(listener);

        let unspecified = WorkloadGatewayTarget {
            host: "0.0.0.0".to_owned(),
            port: 14000,
        };
        match probe_gateway_target(&unspecified).await {
            Err(GatewayProbeError::Inadmissible { detail, .. }) => {
                assert!(detail.contains("unspecified"), "{detail}");
            }
            other => panic!("an unspecified authority must never be readiness: {other:?}"),
        }

        let unresolvable = WorkloadGatewayTarget {
            host: "node-gateway.invalid".to_owned(),
            port: 14000,
        };
        match probe_gateway_target(&unresolvable).await {
            Err(GatewayProbeError::Unresolved { .. }) => {}
            other => panic!("expected the typed unresolved refusal, got {other:?}"),
        }

        let blackhole = WorkloadGatewayTarget {
            host: "192.0.2.1".to_owned(),
            port: 14000,
        };
        let started = std::time::Instant::now();
        match probe_gateway_target(&blackhole).await {
            Err(GatewayProbeError::Unreachable { budget_ms, .. }) => {
                assert_eq!(budget_ms, GATEWAY_PROBE_BUDGET.as_millis());
            }
            other => panic!("expected the bounded unreachable refusal, got {other:?}"),
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(8),
            "the probe must not outlive its budget: {:?}",
            started.elapsed()
        );
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
