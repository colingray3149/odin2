//! Declare pod execution and resources explicitly; runtime consumes the validated profile without inferred defaults.

use std::path::{Path, PathBuf};

use odin_domain::{ProjectId, SeatId};
use serde::{Deserialize, Serialize};

use super::container::{valid_fully_qualified_oci_base, valid_registry_hostname_label};
use super::object::{ObjectConfig, RegistryKind, RegistryObject};

/// Limit briefs because they are injected on every turn.
pub const WORKLOAD_BRIEF_MAX_BYTES: usize = 16_384;

/// Match odin-browser's maximum viewport dimension.
const MAX_SCREEN_DIMENSION: u32 = 8192;
const MAX_SCREEN_DEPTH: u32 = 32;

/// Omit default fields to preserve canonical profile hashes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadProfileToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    /// Seats allowed to launch this profile under its own execution binding.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub seats_offered: std::collections::BTreeSet<SeatId>,
    pub image: WorkloadImageToml,
    /// Script runs the declared command; agent harnesses default to omp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<WorkloadScriptToml>,
    /// Required for agent harnesses; a script pod declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<WorkloadRuntimeToml>,
    pub seat: WorkloadSeatToml,
    pub network: WorkloadNetworkToml,
    /// Required for agent harnesses; a script pod declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<WorkloadDisplayToml>,
    pub state: WorkloadStateToml,
    pub export: WorkloadExportToml,
    pub brief: WorkloadBriefToml,
    /// Required for agent harnesses; a script pod declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<WorkloadMemoryToml>,
    /// Required for `mode = "job"`; a service runs until stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<WorkloadLifetimeToml>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub gpu_count: u32,
    /// The worker container's CPU and memory reservation; absent keeps the platform defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<WorkloadResourcesToml>,
    /// Require these odin.capability node labels; empty permits any node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub placement: Vec<String>,
    #[serde(default, skip_serializing_if = "WorkloadMode::is_job")]
    pub mode: WorkloadMode,
    /// Counter watchdogs and optional independent daemon-owned review sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring: Option<WorkloadMonitoringToml>,
    /// Narrow seat tools; empty grants none, and pods cannot launch, delegate, or create.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<odin_domain::CapabilityId>,
    /// Optional simulation mission; Job state, ODIN-STATUS, and ODIN-CHECKPOINT drive its display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub simulation: Option<WorkloadSimulationToml>,
    /// The report contract this profile's runs owe; omitted runs owe their answer alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<WorkloadReportToml>,
    /// Defaults to Chromium, headed only when the display streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_engine: Option<BrowserEngine>,
}

/// The deliverable a run of this profile owes beside its markdown answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadReportToml {
    /// Every run ends with exactly one polished PDF beside its markdown:
    /// the pod renders it, and the authority completes it from the settled
    /// answer when the pod itself rendered none.
    pub pdf: bool,
    /// Declared files.save root for report copies; required when PDF delivery is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub downloads_root: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserEngine {
    /// Read through web.read on the authority without an in-pod browser.
    Obscura,
    #[default]
    ChromiumHeadless,
    /// Stream Chromium so the owner can take over, including for login.
    ChromiumHeaded,
}

impl BrowserEngine {
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::ChromiumHeadless)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSimulationToml {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renderers: Vec<odin_domain::huginn::RendererId>,
}

/// Pods cannot receive launch, delegation, or creation capabilities.
pub fn pod_may_hold(capability: &str) -> bool {
    !(capability.starts_with("kube.workload.")
        || capability.starts_with("seat.ask.")
        || capability == "task.create"
        || crate::CREATION_CAPABILITIES.contains(&capability))
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

pub const SCRIPT_HARNESS: &str = "script";
/// Resolve the platform image at launch to the deployed digest pin.
pub const PLATFORM_IMAGE: &str = "platform";
pub const OMP_HARNESS: &str = "omp";

impl WorkloadProfileToml {
    pub fn harness(&self) -> &str {
        self.harness.as_deref().unwrap_or(OMP_HARNESS)
    }

    pub fn runs_agent(&self) -> bool {
        self.harness() != SCRIPT_HARNESS
    }

    /// Obscura has no in-pod browser tools; headed Chromium requires a streamed display.
    pub fn browser_engine_conflict(&self) -> Option<&'static str> {
        let holds = |tool: &str| self.tools.iter().any(|held| held.as_str() == tool);
        let stream = self.display.as_ref().is_some_and(|display| display.stream);
        match self.browser_engine? {
            BrowserEngine::Obscura if !holds("web.read") => {
                Some("browser_engine = \"obscura\" reads through web.read; add it to tools")
            }
            BrowserEngine::Obscura
                if self.tools.iter().any(|tool| tool.as_str().starts_with("browser.")) =>
            {
                Some("browser_engine = \"obscura\" runs no pod browser; drop the browser.* tools")
            }
            BrowserEngine::ChromiumHeaded if !stream => {
                Some("browser_engine = \"chromium-headed\" streams its display; set display.stream = true")
            }
            BrowserEngine::ChromiumHeadless if stream => {
                Some("browser_engine = \"chromium-headless\" is not streamed; set display.stream = false")
            }
            _ => None,
        }
    }

    pub fn browser_engine(&self) -> BrowserEngine {
        self.browser_engine.unwrap_or(
            match self.display.as_ref().is_some_and(|display| display.stream) {
                true => BrowserEngine::ChromiumHeaded,
                false => BrowserEngine::ChromiumHeadless,
            },
        )
    }

    pub fn deadline_seconds(&self) -> Option<u32> {
        match self.mode {
            WorkloadMode::Job => self
                .lifetime
                .as_ref()
                .map(|lifetime| lifetime.deadline_seconds),
            WorkloadMode::Service => None,
        }
    }

    /// Whether every run of this profile owes exactly one PDF beside its
    /// markdown answer.
    pub fn report_pdf(&self) -> bool {
        self.report.as_ref().is_some_and(|report| report.pdf)
    }

    /// Agent fields are required for validated agent pods and absent for script pods.
    pub fn agent(&self) -> Option<WorkloadAgentView<'_>> {
        if !self.runs_agent() {
            return None;
        }
        Some(WorkloadAgentView {
            runtime: self.runtime.as_ref()?,
            display: self.display.as_ref()?,
            memory: self.memory.as_ref()?,
            gateway_lane: self.seat.gateway_lane.as_deref()?,
        })
    }

    pub fn placement_labels(&self) -> std::collections::BTreeMap<String, String> {
        self.placement
            .iter()
            .map(|capability| {
                (
                    format!("{NODE_CAPABILITY_LABEL_PREFIX}{capability}"),
                    "true".to_owned(),
                )
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WorkloadAgentView<'a> {
    pub runtime: &'a WorkloadRuntimeToml,
    pub display: &'a WorkloadDisplayToml,
    pub memory: &'a WorkloadMemoryToml,
    pub gateway_lane: &'a str,
}

pub const NODE_CAPABILITY_LABEL_PREFIX: &str = "odin.capability/";

/// Execute script argv as the image's non-root user.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadScriptToml {
    pub command: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadMode {
    /// Finite: ends with its command (or agent) or at its declared deadline.
    #[default]
    Job,
    /// Long-lived: restarted on failure, ended only by a stop command.
    Service,
}

impl WorkloadMode {
    pub fn is_job(&self) -> bool {
        *self == Self::Job
    }
}

/// Declared monitoring cadence; progress growth, not heartbeats, prevents stall recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadMonitoringToml {
    pub cadence_seconds: std::num::NonZeroU32,
    /// Independent daemon-owned review session; cadence is shared with counter monitoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<WorkloadReviewerToml>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watchdogs: Vec<super::container::ContainerAlertToml>,
    /// Only increasing values count as progress; heartbeats and repeated values do not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<String>,
    /// With `progress` and `recovery`: how long the counter may stand still. Alone: how long a
    /// running pod's session may journal no event before it is resumed once, then restarted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stall_seconds: Option<std::num::NonZeroU32>,
    /// Supported rungs: restart_worker via the seat, then terminal escalate to the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<super::provider::RecoveryPolicyToml>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadReviewerToml {
    pub seat: SeatId,
    pub provider: String,
    pub model: String,
}

pub const POD_RECOVERY_RUNGS: [super::provider::RecoveryRungToml; 2] = [
    super::provider::RecoveryRungToml::RestartWorker,
    super::provider::RecoveryRungToml::Escalate,
];

/// Require an OCI manifest digest so runtime pulls the declared image rather than a mutable tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadImageToml {
    pub reference: String,
}

impl WorkloadImageToml {
    pub fn is_platform(&self) -> bool {
        self.reference == PLATFORM_IMAGE
    }
}

/// Runtime paths refer only to the image, never host paths or credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRuntimeToml {
    pub launcher: String,
    pub browser: String,
    /// In-image supervisor starts Xvfb and serves the browser worker over the execution channel.
    pub supervisor: String,
    pub playwright: String,
}

/// Require explicit seat, in-scope project, and provider lane; never infer model or credential defaults.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSeatToml {
    pub seat: SeatId,
    pub project: ProjectId,
    /// Reject unavailable gateway lanes rather than silently selecting another model policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_lane: Option<String>,
}

/// How a workload reaches destinations outside the cluster.
/// `direct` keeps the existing host and pod routing. `vpn-required` refuses
/// launch unless the daemon resolved a VPN transport binding.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkloadTransport {
    #[default]
    Direct,
    VpnRequired,
}

impl WorkloadTransport {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::VpnRequired => "vpn-required",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadNetworkToml {
    pub allow_hosts: Vec<String>,
    /// Public-only TCP 80/443 for this run. Host pins still apply. Absent means closed.
    /// A `vpn-required` profile keeps the pins and applies them inside the tunnel.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    /// Absent means `direct`. `vpn-required` launches only with a resolved daemon binding.
    #[serde(default, skip_serializing_if = "WorkloadTransport::is_direct")]
    pub transport: WorkloadTransport,
}

/// Stream the declared virtual display through the browser takeover path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDisplayToml {
    pub xvfb: String,
    /// Virtual display geometry `<width>x<height>x<depth>`.
    pub screen: String,
    pub stream: bool,
}

/// Declared worker reservation: whole CPUs and a binary-suffixed memory quantity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadResourcesToml {
    pub cpu: u32,
    /// Memory quantity such as `4Gi`, parsed by the storage quantity grammar.
    pub memory: String,
}

impl WorkloadResourcesToml {
    pub fn memory_bytes(&self) -> Result<u64, String> {
        storage_quantity_bytes(&self.memory)
    }
}

/// Require explicit persistent storage and share its parser with workload planning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadStateToml {
    pub path: String,
    pub storage: String,
}

/// Require nonzero integer storage with a binary SI suffix to avoid ambiguous byte quantities.
pub fn storage_quantity_bytes(value: &str) -> Result<u64, String> {
    const UNITS: [(&str, u64); 6] = [
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1 << 40),
        ("Pi", 1 << 50),
        ("Ei", 1 << 60),
    ];
    let invalid =
        || format!("storage quantity {value:?} must be <count><Ki|Mi|Gi|Ti|Pi|Ei>, nonzero");
    // Slice at the first non-digit so the complete multi-character suffix is retained.
    let Some(index) = value.find(|c: char| !c.is_ascii_digit()) else {
        return Err(invalid());
    };
    let (digits, suffix) = (&value[..index], &value[index..]);
    if digits.is_empty() {
        return Err(invalid());
    }
    let count: u64 = digits
        .parse()
        .map_err(|error| format!("{}: {error}", invalid()))?;
    if count == 0 {
        return Err(invalid());
    }
    let multiplier = UNITS
        .iter()
        .find(|(name, _)| suffix == *name)
        .map(|(_, factor)| factor)
        .ok_or_else(invalid)?;
    count.checked_mul(*multiplier).ok_or_else(invalid)
}

/// Export artifacts only through the declared in-pod and host path mapping.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadExportToml {
    pub pod_path: String,
    pub host_folder: String,
    /// Declared files.save root that receives each finished run's export as `<run>-<label or profile>/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliver_root: Option<String>,
}

/// Inject declared guidance every turn; do not store runtime state in it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBriefToml {
    pub text: String,
}

/// Retrieved memory remains untrusted and must stay within the seat's brain scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadMemoryToml {
    /// Must be declared by the project and included in the seat's brain scope.
    pub namespace: String,
    /// Defaults to the seat's context profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Set activeDeadlineSeconds so job lifetime does not depend on agent cooperation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadLifetimeToml {
    pub deadline_seconds: u32,
}

/// Match workload launch limits; working sessions may last up to one day.
pub const MIN_WORKLOAD_DEADLINE_SECONDS: u32 = 60;
pub const MAX_WORKLOAD_DEADLINE_SECONDS: u32 = 86_400;

/// Tags are mutable, so require a manifest digest in addition to the shared OCI grammar.
pub(crate) fn valid_digest_pinned_oci_reference(reference: &str) -> bool {
    let Some((_, digest)) = reference.rsplit_once('@') else {
        return false;
    };
    super::container::valid_oci_sha256_digest(digest) && valid_fully_qualified_oci_base(reference)
}

/// Share normalized absolute-path validation with pod execution to prevent path escapes.
pub fn valid_pod_path(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('/') else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && !component.bytes().any(|byte| byte == b'\\' || byte == 0)
    })
}

/// Match browser geometry limits: dimensions 1..=8192 and Xvfb depth 1..=32.
pub fn valid_screen(value: &str) -> bool {
    let mut seen = 0usize;
    for part in value.split('x') {
        seen += 1;
        if seen > 3 {
            return false;
        }
        let bound = if seen == 3 {
            MAX_SCREEN_DEPTH
        } else {
            MAX_SCREEN_DIMENSION
        };
        match part.parse::<u32>() {
            Ok(number) if number != 0 && number <= bound => {}
            _ => return false,
        }
    }
    seen == 3
}

/// A bare hostname, or one dotted IPv4 address. Ports and wildcards are not hosts.
pub fn valid_allow_host(value: &str) -> bool {
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return address.is_ipv4();
    }
    if value.is_empty() || value.len() > 253 || value.ends_with('.') {
        return false;
    }
    value
        .split('.')
        .all(|label| !label.is_empty() && label.len() <= 63 && valid_registry_hostname_label(label))
}

/// Reject equal or nested mount paths because one volume would shadow the other.
pub fn paths_nest_or_collide(state: &str, export: &str) -> bool {
    // Path::starts_with compares complete components, including equality.
    let (state, export) = (Path::new(state), Path::new(export));
    state.starts_with(export) || export.starts_with(state)
}

/// Runtime resolves this validated profile rather than raw TOML or inferred defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComposedWorkloadProfile {
    pub id: String,
    pub relative_config: PathBuf,
    pub profile: WorkloadProfileToml,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkloadProfileLookupError {
    Unknown { id: String },
    Disabled { id: String },
}

impl std::fmt::Display for WorkloadProfileLookupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { id } => {
                write!(formatter, "workload profile {id:?} is not in the registry")
            }
            Self::Disabled { id } => {
                write!(
                    formatter,
                    "workload profile {id:?} is declared but disabled"
                )
            }
        }
    }
}

impl std::error::Error for WorkloadProfileLookupError {}

pub fn compose_workload_profiles(objects: &[RegistryObject]) -> Vec<ComposedWorkloadProfile> {
    let mut composed: Vec<ComposedWorkloadProfile> = objects
        .iter()
        .filter(|object| object.kind() == RegistryKind::Workload && object.enabled())
        .filter_map(|object| match &object.config {
            ObjectConfig::Workload(profile) => Some(ComposedWorkloadProfile {
                id: object.id.clone(),
                relative_config: object.relative_config.clone(),
                profile: profile.as_ref().clone(),
            }),
            _ => None,
        })
        .collect();
    composed.sort_by(|left, right| left.id.cmp(&right.id));
    composed
}

/// Disabled declarations return Disabled rather than disappearing from lookup.
pub fn compose_workload_profile(
    objects: &[RegistryObject],
    id: &str,
) -> Result<ComposedWorkloadProfile, WorkloadProfileLookupError> {
    let object = objects
        .iter()
        .find(|object| object.kind() == RegistryKind::Workload && object.id == id)
        .ok_or_else(|| WorkloadProfileLookupError::Unknown { id: id.to_owned() })?;
    let ObjectConfig::Workload(profile) = &object.config else {
        return Err(WorkloadProfileLookupError::Unknown { id: id.to_owned() });
    };
    if !object.enabled() {
        return Err(WorkloadProfileLookupError::Disabled { id: id.to_owned() });
    }
    Ok(ComposedWorkloadProfile {
        id: object.id.clone(),
        relative_config: object.relative_config.clone(),
        profile: profile.as_ref().clone(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod reviewer_contract {}
