//! Parse registry declarations strictly before relational validation.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::capability::{CapabilityToml, SliceToml};
use super::claude_code::{ClaudeCodeToml, CLAUDE_CODE_HARNESS};
use super::container::ContainerToml;
use super::context_profile::ContextProfileToml;
use super::environment::EnvironmentToml;
use super::harness::HarnessToml;
use super::node::{HostToml, NodeToml};
use super::provider::ProviderToml;
use super::routine::RoutineToml;
use super::seat::{LaneToml, ProjectToml, SeatToml};
use super::validation::validate_object;
use super::workload::WorkloadProfileToml;
use crate::container_identity::{validate_container_identity_fields, ContainerIdentityError};
use crate::discover::RawObject;
use crate::RegistryFinding;

pub const REGISTRY_SCHEMA: &str = "odin.registry.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryKind {
    Seat,
    Project,
    Lane,
    Node,
    Provider,
    Capability,
    Slice,
    Container,
    Host,
    Workload,
    Routine,
    Harness,
    Environment,
    #[serde(rename = "context-profile")]
    ContextProfile,
}

impl RegistryKind {
    pub const ALL: [Self; 14] = [
        Self::Seat,
        Self::Project,
        Self::Lane,
        Self::Node,
        Self::Provider,
        Self::Capability,
        Self::Slice,
        Self::Container,
        Self::Host,
        Self::Workload,
        Self::Routine,
        Self::Harness,
        Self::Environment,
        Self::ContextProfile,
    ];

    /// Dynamically read objects do not affect composition, so routine-only changes need no restart.
    pub const fn is_read_live(self) -> bool {
        matches!(self, Self::Routine)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Seat => "seat",
            Self::Project => "project",
            Self::Lane => "lane",
            Self::Node => "node",
            Self::Provider => "provider",
            Self::Capability => "capability",
            Self::Slice => "slice",
            Self::Container => "container",
            Self::Host => "host",
            Self::Workload => "workload",
            Self::Routine => "routine",
            Self::Harness => "harness",
            Self::Environment => "environment",
            Self::ContextProfile => "context-profile",
        }
    }

    pub const fn directory(self) -> &'static str {
        match self {
            Self::Seat => "seats",
            Self::Project => "projects",
            Self::Lane => "lanes",
            Self::Node => "nodes",
            Self::Provider => "providers",
            Self::Capability => "capabilities",
            Self::Slice => "slices",
            Self::Container => "containers",
            Self::Host => "hosts",
            Self::Workload => "workloads",
            Self::Routine => "routines",
            Self::Harness => "harnesses",
            Self::Environment => "environments",
            Self::ContextProfile => "context-profiles",
        }
    }

    pub fn config_name(self) -> String {
        match self {
            Self::Workload => "profile.toml".to_owned(),
            _ => format!("{}.toml", self.as_str()),
        }
    }

    pub fn from_directory(directory: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.directory() == directory)
    }
}

impl fmt::Display for RegistryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "object_type", content = "config", rename_all = "lowercase")]
pub enum ObjectConfig {
    Seat(Box<SeatToml>),
    Project(Box<ProjectToml>),
    Lane(Box<LaneToml>),
    Node(Box<NodeToml>),
    Provider(Box<ProviderToml>),
    Capability(Box<CapabilityToml>),
    Slice(Box<SliceToml>),
    Container(Box<ContainerToml>),
    Host(Box<HostToml>),
    Workload(Box<WorkloadProfileToml>),
    ClaudeCode(Box<ClaudeCodeToml>),
    Routine(Box<RoutineToml>),
    Harness(Box<HarnessToml>),
    Environment(Box<EnvironmentToml>),
    #[serde(rename = "context-profile")]
    ContextProfile(Box<ContextProfileToml>),
}

impl ObjectConfig {
    pub const fn kind(&self) -> RegistryKind {
        match self {
            Self::Seat(_) => RegistryKind::Seat,
            Self::Project(_) => RegistryKind::Project,
            Self::Lane(_) => RegistryKind::Lane,
            Self::Node(_) => RegistryKind::Node,
            Self::Provider(_) => RegistryKind::Provider,
            Self::Capability(_) => RegistryKind::Capability,
            Self::Slice(_) => RegistryKind::Slice,
            Self::Container(_) => RegistryKind::Container,
            Self::Host(_) => RegistryKind::Host,
            Self::Workload(_) => RegistryKind::Workload,
            Self::ClaudeCode(_) => RegistryKind::Workload,
            Self::Routine(_) => RegistryKind::Routine,
            Self::Harness(_) => RegistryKind::Harness,
            Self::Environment(_) => RegistryKind::Environment,
            Self::ContextProfile(_) => RegistryKind::ContextProfile,
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            Self::Seat(value) => value.enabled,
            Self::Project(value) => value.enabled,
            Self::Lane(value) => value.enabled,
            Self::Node(value) => value.enabled,
            Self::Provider(value) => value.enabled,
            Self::Capability(value) => value.enabled,
            Self::Slice(value) => value.enabled,
            Self::Container(value) => value.enabled,
            Self::Host(value) => value.enabled,
            Self::Workload(value) => value.enabled,
            Self::ClaudeCode(value) => value.enabled,
            Self::Routine(value) => value.enabled,
            Self::Harness(value) => value.enabled,
            Self::Environment(value) => value.enabled,
            Self::ContextProfile(value) => value.enabled,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryObject {
    pub id: String,
    pub relative_config: PathBuf,
    pub config: ObjectConfig,
}

impl RegistryObject {
    pub fn kind(&self) -> RegistryKind {
        self.config.kind()
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled()
    }

    pub fn enters_listing(&self) -> bool {
        match &self.config {
            ObjectConfig::Capability(value) => value.enabled && value.is_implemented(),
            _ => self.config.enabled(),
        }
    }

    /// Exclude source paths so identical declarations retain the same identity after relocation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        #[derive(Serialize)]
        struct CanonicalObject<'a> {
            id: &'a str,
            kind: RegistryKind,
            config: &'a ObjectConfig,
        }

        serde_json::to_vec(&CanonicalObject {
            id: &self.id,
            kind: self.kind(),
            config: &self.config,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct ParseResult {
    pub objects: Vec<RegistryObject>,
    pub findings: Vec<RegistryFinding>,
}

pub fn parse_objects(raw_objects: &[RawObject]) -> ParseResult {
    let mut result = ParseResult::default();
    for raw in raw_objects {
        match parse_object(raw) {
            Ok(object) => {
                result.findings.extend(validate_object(&object));
                result.objects.push(object);
            }
            Err(finding) => result.findings.push(finding),
        }
    }
    result.objects.sort_by(|left, right| {
        (left.kind(), left.id.as_str()).cmp(&(right.kind(), right.id.as_str()))
    });
    result.findings.sort();
    result
}

fn parse_object(raw: &RawObject) -> Result<RegistryObject, RegistryFinding> {
    let source = fs::read_to_string(&raw.absolute_config).map_err(|error| {
        RegistryFinding::fail(
            "registry-config-read",
            &raw.relative_config,
            format!("could not read config: {error}"),
        )
    })?;
    parse_object_toml(
        raw.kind,
        raw.id.clone(),
        raw.relative_config.clone(),
        &source,
    )
}

/// Reject duplicate container identity fields before BTreeSet deserialization erases them.
pub fn parse_object_toml(
    kind: RegistryKind,
    id: impl Into<String>,
    relative_config: impl Into<PathBuf>,
    source: &str,
) -> Result<RegistryObject, RegistryFinding> {
    let relative_config = relative_config.into();
    let parse_error = |error: toml::de::Error| {
        RegistryFinding::fail(
            "registry-config-shape",
            &relative_config,
            format!("strict TOML shape rejected: {error}"),
        )
    };
    let config = match kind {
        RegistryKind::Seat => {
            ObjectConfig::Seat(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Project => {
            ObjectConfig::Project(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Lane => {
            ObjectConfig::Lane(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Node => {
            ObjectConfig::Node(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Provider => {
            ObjectConfig::Provider(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Capability => {
            ObjectConfig::Capability(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Slice => {
            ObjectConfig::Slice(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Container => {
            let document: toml::Value = toml::from_str(source).map_err(parse_error)?;
            if let Some(finding) = duplicate_identity_finding(&document, &relative_config) {
                return Err(finding);
            }
            ObjectConfig::Container(Box::new(document.try_into().map_err(parse_error)?))
        }
        RegistryKind::Host => {
            ObjectConfig::Host(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Workload => {
            let document: toml::Value = toml::from_str(source).map_err(parse_error)?;
            if document.get("harness").and_then(toml::Value::as_str) == Some(CLAUDE_CODE_HARNESS) {
                ObjectConfig::ClaudeCode(Box::new(document.try_into().map_err(parse_error)?))
            } else {
                ObjectConfig::Workload(Box::new(document.try_into().map_err(parse_error)?))
            }
        }
        RegistryKind::Routine => {
            ObjectConfig::Routine(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Harness => {
            ObjectConfig::Harness(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::Environment => {
            ObjectConfig::Environment(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
        RegistryKind::ContextProfile => {
            ObjectConfig::ContextProfile(Box::new(toml::from_str(source).map_err(parse_error)?))
        }
    };
    Ok(RegistryObject {
        id: id.into(),
        relative_config,
        config,
    })
}

fn duplicate_identity_finding(
    document: &toml::Value,
    relative_config: &Path,
) -> Option<RegistryFinding> {
    let fields = document.get("identity_fields")?.as_array()?;
    let fields: Vec<String> = fields
        .iter()
        .map(|field| field.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    match validate_container_identity_fields(&fields) {
        Err(ContainerIdentityError::DuplicatePath { path }) => Some(RegistryFinding::fail(
            "container-identity-duplicate",
            relative_config,
            format!("identity_fields declares duplicate path {path:?}"),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
