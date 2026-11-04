//! Container profiles and conservative OCI reference parsing.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU16, NonZeroU32};

use odin_domain::{SeatId, SliceId};
use serde::{Deserialize, Serialize};

use super::capability::is_handler_shell_syntax;
use super::object::RegistryKind;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ContainerTunableValue {
    Integer(i64),
    Boolean(bool),
    String(String),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum ContainerWatchdogToml {
    Script(String),
    Alert(ContainerAlertToml),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerAlertToml {
    pub id: String,
    pub condition: String,
    pub consecutive_hits: NonZeroU16,
    pub cooldown_seconds: u32,
    pub severity: ContainerAlertSeverityToml,
    pub slice: SliceId,
    #[serde(default, skip_serializing_if = "ContainerAlertActionToml::is_notify")]
    pub action: ContainerAlertActionToml,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerAlertActionToml {
    /// Wake the seat that launched the workload with the finding.
    #[default]
    Notify,
    /// Cancel the workload, then tell the launching seat.
    Stop,
}

impl ContainerAlertActionToml {
    fn is_notify(&self) -> bool {
        *self == Self::Notify
    }
}

/// Parse conditions over counters emitted on ODIN-STATUS stdout lines.
#[derive(Clone, Debug, PartialEq)]
pub struct AlertCondition {
    pub counter: String,
    pub op: AlertOp,
    pub threshold: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertOp {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

impl AlertCondition {
    pub fn parse(text: &str) -> Result<Self, String> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        let [counter, op, threshold] = parts.as_slice() else {
            return Err(format!(
                "condition {text:?} is not `<counter> <op> <number>`"
            ));
        };
        let snake = counter.starts_with(|c: char| c.is_ascii_lowercase())
            && counter
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !snake || counter.len() > 64 {
            return Err(format!(
                "counter {counter:?} must be lower_snake_case (≤64 bytes)"
            ));
        }
        let op = match *op {
            ">" => AlertOp::Gt,
            ">=" => AlertOp::Ge,
            "<" => AlertOp::Lt,
            "<=" => AlertOp::Le,
            "==" => AlertOp::Eq,
            "!=" => AlertOp::Ne,
            other => return Err(format!("operator {other:?} is not one of > >= < <= == !=")),
        };
        let threshold = threshold
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .ok_or_else(|| format!("threshold {threshold:?} is not a finite number"))?;
        Ok(Self {
            counter: (*counter).to_owned(),
            op,
            threshold,
        })
    }

    pub fn holds(&self, value: f64) -> bool {
        match self.op {
            AlertOp::Gt => value > self.threshold,
            AlertOp::Ge => value >= self.threshold,
            AlertOp::Lt => value < self.threshold,
            AlertOp::Le => value <= self.threshold,
            AlertOp::Eq => (value - self.threshold).abs() < f64::EPSILON,
            AlertOp::Ne => (value - self.threshold).abs() >= f64::EPSILON,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerAlertSeverityToml {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum ContainerSurfaceToml {
    Id(String),
    Definition(ContainerSurfaceDefinitionToml),
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSurfaceDefinitionToml {
    pub id: String,
    pub kind: ContainerSurfaceKindToml,
    pub source: String,
    pub media_type: String,
    pub refresh_seconds: u32,
    pub renderer: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerSurfaceKindToml {
    Log,
    Metric,
    File,
    Render,
    Browser,
    Simulation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub purpose: String,
    pub base: String,
    /// Optional GPU reservation; requests and limits are equal for scheduler allocation.
    #[serde(default, skip_serializing_if = "is_zero_gpu_count")]
    pub gpu_count: u32,
    /// Optional job wall-clock limit mapped to spec.activeDeadlineSeconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_seconds: Option<u32>,
    /// Optional MemoryMax in bytes for native seat processes this container offers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<u64>,
    pub seats_offered: BTreeSet<SeatId>,
    pub scripts: BTreeSet<String>,
    pub watchdogs: BTreeSet<ContainerWatchdogToml>,
    pub identity_fields: BTreeSet<String>,
    pub tunables: BTreeMap<String, ContainerTunableValue>,
    pub surface: BTreeSet<ContainerSurfaceToml>,
    pub contents: ContainerContentsToml,
    pub monitoring: ContainerMonitoringToml,
}

impl ContainerToml {
    /// Treat scripts as image paths only for fully qualified, versioned OCI bases; otherwise validate local files.
    pub fn image_executable_paths(&self) -> bool {
        self.contents.kind == ContainerContentsKindToml::Scripts
            && valid_fully_qualified_oci_base(&self.base)
    }
}

/// Omit zero GPU reservations to preserve canonical snapshot hashes.
fn is_zero_gpu_count(gpu_count: &u32) -> bool {
    *gpu_count == 0
}

/// Require an explicit registry and a tag or digest so bare or unversioned references cannot select an image.
pub(crate) fn valid_fully_qualified_oci_base(base: &str) -> bool {
    if base.is_empty()
        || base.chars().any(char::is_whitespace)
        || base.chars().any(is_handler_shell_syntax)
        || base.contains('\\')
    {
        return false;
    }
    let (reference, digest) = match base.split_once('@') {
        Some((reference, digest)) => (reference, Some(digest)),
        None => (base, None),
    };
    if let Some(digest) = digest {
        if !valid_oci_sha256_digest(digest) {
            return false;
        }
    }
    let Some((host, repository)) = reference.split_once('/') else {
        return false;
    };
    if !valid_registry_host(host) {
        return false;
    }
    // After the host, the only allowed colon separates the repository from its tag.
    let (repository, tag) = match repository.rsplit_once(':') {
        Some((repository, tag)) => (repository, Some(tag)),
        None => (repository, None),
    };
    if repository.is_empty()
        || !repository
            .split('/')
            .all(valid_registry_repository_component)
    {
        return false;
    }
    match tag {
        // Unpinned references are ambiguous; require a tag, a digest, or both.
        Some(tag) => valid_oci_tag(tag),
        None => digest.is_some(),
    }
}

/// `host[:port]` where the host is `localhost` or a dotted lowercase name.
fn valid_registry_host(host: &str) -> bool {
    match host.rsplit_once(':') {
        Some((hostname, port)) => port.parse::<u16>().is_ok() && valid_registry_hostname(hostname),
        None => valid_registry_hostname(host),
    }
}

fn valid_registry_hostname(hostname: &str) -> bool {
    hostname == "localhost"
        || (hostname.contains('.') && hostname.split('.').all(valid_registry_hostname_label))
}

/// Share DNS label validation with workload network allowlists.
pub(crate) fn valid_registry_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    match (bytes.first(), bytes.last()) {
        (Some(&first), Some(&last)) => {
            alnum(first) && alnum(last) && bytes.iter().all(|&byte| alnum(byte) || byte == b'-')
        }
        _ => false,
    }
}

/// One OCI distribution-spec repository path component:
/// `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn valid_registry_repository_component(component: &str) -> bool {
    let mut characters = component.chars().peekable();
    // True only directly after an alphanumeric run.
    let mut separator_allowed = false;
    while let Some(character) = characters.next() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            separator_allowed = true;
            continue;
        }
        if !separator_allowed {
            return false;
        }
        match character {
            '.' => {}
            '_' => {
                if characters.peek() == Some(&'_') {
                    characters.next();
                }
            }
            '-' => {
                while characters.peek() == Some(&'-') {
                    characters.next();
                }
            }
            _ => return false,
        }
        separator_allowed = false;
    }
    separator_allowed
}

/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
fn valid_oci_tag(tag: &str) -> bool {
    let mut characters = tag.chars();
    match characters.next() {
        Some(first) if first.is_ascii_alphanumeric() || first == '_' => {}
        _ => return false,
    }
    characters.count() <= 127
        && tag.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

/// Share lowercase SHA-256 pin validation with workload image identity.
pub(crate) fn valid_oci_sha256_digest(digest: &str) -> bool {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerContentsKindToml {
    OdinEnv,
    Scripts,
    Adapter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerContentsToml {
    pub kind: ContainerContentsKindToml,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum ContainerMonitoringToml {
    Policy(ContainerMonitoringPolicyToml),
    None(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerMonitoringPolicyToml {
    pub slice: SliceId,
    pub cadence_seconds: NonZeroU32,
}

#[cfg(test)]
mod tests;
