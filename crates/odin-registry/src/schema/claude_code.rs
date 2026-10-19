//! Launch requests select declared workloads, never arbitrary commands or host mounts.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use super::{
    account::{valid_account_name, AccountKind, AccountLayout},
    environment::EnvironmentTransport,
    object::{ObjectConfig, RegistryKind, RegistryObject},
    workload::{storage_quantity_bytes, valid_allow_host, valid_pod_path, WorkloadImageToml},
};
use serde::{Deserialize, Serialize};

pub const CLAUDE_CODE_HARNESS: &str = "claude-code";
pub const CLAUDE_WORKTREE: &str = "/workspace/repo";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudePlacement {
    #[default]
    Pod,
    HostTab,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClaudeDriver {
    Sinmara,
    Colin,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudeAccountPolicy {
    Discovered,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudePresetWorkspace {
    NormalCheckout,
}

/// Fixed break-glass semantics, not arbitrary launch options.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudePresetToml {
    pub placement: ClaudePlacement,
    pub driver: ClaudeDriver,
    pub skip_permissions: bool,
    pub remote_control: bool,
    pub workspace: ClaudePresetWorkspace,
    pub default_account: String,
    pub default_host: String,
    pub default_dir: String,
    pub unsandboxed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeResourcesToml {
    pub cpu_request: String,
    pub cpu_limit: String,
    pub memory_request: String,
    pub memory_limit: String,
    pub storage_limit: String,
}

/// Expand worktree only to the session clone; reject launch-time command, environment, and egress overrides.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeMcpToml {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    pub scope: ClaudeMcpScope,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudeMcpScope {
    Worktree,
    Browser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCodeToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub harness: String,
    pub account_kind: AccountKind,
    pub accounts: ClaudeAccountPolicy,
    /// Optional narrowing of caller-admitted declared projects; empty adds no narrowing.
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub placement: ClaudePlacement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<ClaudeDriver>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default = "remote_control_default")]
    pub remote_control: bool,
    /// Per-open overrides are resolved and recorded before any launch effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_permissions: Option<bool>,
    pub image: WorkloadImageToml,
    pub resources: ClaudeResourcesToml,
    #[serde(default)]
    pub mcp: Vec<String>,
    #[serde(default)]
    pub mcp_servers: BTreeMap<String, ClaudeMcpToml>,
    #[serde(default)]
    pub presets: BTreeMap<String, ClaudePresetToml>,
    /// Host-tab opens must use this host's declared checkout.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub checkouts: BTreeMap<String, String>,
}
fn remote_control_default() -> bool {
    true
}

impl ClaudeCodeToml {
    pub fn skip_permissions(&self) -> bool {
        self.skip_permissions
            .unwrap_or(self.placement == ClaudePlacement::Pod)
    }
    pub fn driver(&self) -> ClaudeDriver {
        self.driver.unwrap_or(match self.placement {
            ClaudePlacement::Pod => ClaudeDriver::Sinmara,
            ClaudePlacement::HostTab => ClaudeDriver::Colin,
        })
    }
    /// Missing environment is an error, not permission to use host defaults.
    pub fn environment(&self) -> Result<&str, String> {
        self.environment
            .as_deref()
            .ok_or_else(|| "Claude workload must declare its environment".to_owned())
    }
    /// Check sign-in at admission on the execution host; publication validation does not inspect filesystems.
    pub fn validate(&self, objects: &[RegistryObject]) -> Vec<String> {
        let mut errors = Vec::new();
        if self.schema != super::object::REGISTRY_SCHEMA
            || self.kind != RegistryKind::Workload
            || self.harness != CLAUDE_CODE_HARNESS
        {
            errors.push(
                "Claude driver requires odin.registry.v1, kind=workload, harness=claude-code"
                    .into(),
            );
        }
        if self.account_kind != AccountKind::ClaudeCode {
            errors.push("Claude driver account_kind must be claude-code".into());
        }
        let mut projects = BTreeSet::new();
        if self.projects.iter().any(|project| {
            !projects.insert(project) || !objects.iter().any(|object| {
                &object.id == project
                    && matches!(&object.config, ObjectConfig::Project(declared) if declared.enabled)
            })
        }) {
            errors.push("projects must contain distinct enabled declared project IDs".into());
        }
        for (name, preset) in &self.presets {
            if preset.default_account.is_empty()
                || preset.default_host.is_empty()
                || preset.default_dir.is_empty()
            {
                errors.push(format!(
                    "Claude preset {name} needs a default account, host and directory"
                ));
            }
            if !objects.iter().any(|object| {
                object.id == preset.default_host
                    && matches!(&object.config, ObjectConfig::Host(host) if host.enabled && host.enrolled)
            }) {
                errors.push(format!(
                    "Claude preset {name} default host {} must be an enabled enrolled host",
                    preset.default_host
                ));
            }
            if self.enabled
                && objects.iter().filter(|object| {
                    matches!(&object.config, ObjectConfig::ClaudeCode(profile) if profile.enabled && profile.presets.contains_key(name))
                }).count()
                    > 1
            {
                errors.push(format!(
                    "Claude preset {name} is declared by multiple enabled workloads"
                ));
            }
        }
        for (project, path) in &self.checkouts {
            if !self.projects.iter().any(|declared| declared == project) || !path.starts_with('/') {
                errors.push(format!(
                    "checkout {project} must name a project of this workload and an absolute path"
                ));
            }
        }
        match self.placement {
            ClaudePlacement::Pod => {
                if self.host.is_some() {
                    errors.push("pod declares no host-tab host".into());
                }
            }
            ClaudePlacement::HostTab => {
                if !self.host.as_ref().is_some_and(|host| {
                    objects.iter().any(|object| {
                        &object.id == host
                            && matches!(&object.config, ObjectConfig::Host(declared) if declared.enabled)
                    })
                }) {
                    errors.push("host-tab requires an enabled declared host".into());
                }
            }
        }
        let environment_id = match self.environment() {
            Ok(id) => id,
            Err(error) => {
                errors.push(error);
                return errors;
            }
        };
        let environment = objects.iter().find_map(|object| match &object.config {
            ObjectConfig::Environment(declared)
                if object.id == environment_id && declared.enabled =>
            {
                Some(declared)
            }
            _ => None,
        });
        match environment {
            None => errors.push("environment must name an enabled declaration".into()),
            Some(e) => match self.placement {
                ClaudePlacement::Pod
                    if e.transport != EnvironmentTransport::K3sPod
                        || !e
                            .pod
                            .as_ref()
                            .is_some_and(|p| p.accounts.contains(&AccountKind::ClaudeCode)) =>
                {
                    errors.push("pod environment must admit claude-code accounts".into())
                }
                ClaudePlacement::HostTab
                    if e.transport != EnvironmentTransport::FleetHost || e.host != self.host =>
                {
                    errors.push("host-tab environment must name the selected fleet host".into())
                }
                _ => {}
            },
        }
        if self.image.reference != super::workload::PLATFORM_IMAGE
            && !super::workload::valid_digest_pinned_oci_reference(&self.image.reference)
        {
            errors
                .push("image must be platform or an immutable digest-pinned OCI reference".into());
        }
        let cpu = |s: &str| -> Option<u64> {
            let (n, scale) = s.strip_suffix('m').map_or((s, 1000), |n| (n, 1));
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            n.parse::<u64>().ok()?.checked_mul(scale).filter(|n| *n > 0)
        };
        if !matches!((cpu(&self.resources.cpu_request), cpu(&self.resources.cpu_limit)), (Some(a), Some(b)) if a <= b)
        {
            errors.push(
                "CPU request/limit must be positive cores or millicores with request <= limit"
                    .into(),
            );
        }
        if !matches!((storage_quantity_bytes(&self.resources.memory_request), storage_quantity_bytes(&self.resources.memory_limit)), (Ok(a), Ok(b)) if a <= b)
            || storage_quantity_bytes(&self.resources.storage_limit).is_err()
        {
            errors.push(
                "memory/storage must be positive binary quantities with memory request <= limit"
                    .into(),
            );
        }
        let mut seen = BTreeSet::new();
        for id in &self.mcp {
            if !seen.insert(id) || !self.mcp_servers.contains_key(id) {
                errors.push(format!("MCP {id} is repeated or undeclared"));
            }
        }
        for (id, server) in &self.mcp_servers {
            if !valid_account_name(id) || !valid_pod_path(&server.command) {
                errors.push(format!(
                    "MCP {id} needs a valid ID and absolute in-image command"
                ));
            }
            if server
                .args
                .iter()
                .chain(server.env.values())
                .any(|s| s.contains('\0'))
            {
                errors.push(format!("MCP {id} contains NUL"));
            }
            if server.scope == ClaudeMcpScope::Worktree {
                let command = match self.placement {
                    ClaudePlacement::Pod => "/odin/bin/mcp-server-filesystem",
                    ClaudePlacement::HostTab => {
                        "/etc/profiles/per-user/colin/bin/mcp-server-filesystem"
                    }
                };
                if server.command != command
                    || !server.env.is_empty()
                    || server.args.len() != 1
                    || server.args[0] != "{worktree}"
                    || !server.allow_hosts.is_empty()
                {
                    errors.push(format!("MCP {id} worktree scope requires the official placement-specific filesystem server, only a {{worktree}} argument, and no environment overrides or network egress"));
                }
            }
            if server.env.keys().any(|key| {
                key.is_empty()
                    || !key.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit())
                    })
                    || matches!(
                        key.as_str(),
                        "HOME" | "CLAUDE_CONFIG_DIR" | "PATH" | "LD_PRELOAD" | "LD_LIBRARY_PATH"
                    )
            }) {
                errors.push(format!(
                    "MCP {id} has an invalid or authority-bearing environment variable"
                ));
            }
            if server.allow_hosts.iter().any(|host| {
                !valid_allow_host(host)
                    || (self.placement == ClaudePlacement::Pod
                        && !environment
                            .and_then(|e| e.pod.as_ref())
                            .is_some_and(|p| p.allow_hosts.contains(host)))
            }) {
                errors.push(format!(
                    "MCP {id} egress must be admitted by the pod environment"
                ));
            }
        }
        errors
    }
    pub fn admit_account(&self, home: &Path, account: &str) -> Result<AccountLayout, String> {
        if self.account_kind != AccountKind::ClaudeCode
            || !AccountKind::ClaudeCode.signed_in(home, account)
        {
            return Err(format!(
                "Claude account {account} is not signed in on the selected host"
            ));
        }
        Ok(AccountKind::ClaudeCode.layout(account))
    }
    /// Caller project-scope authorization remains mandatory in the kernel.
    pub fn admits_project(&self, objects: &[RegistryObject], project: &str) -> bool {
        (self.projects.is_empty() || self.projects.iter().any(|id| id == project))
            && objects.iter().any(|o| {
                o.id == project && matches!(&o.config, ObjectConfig::Project(p) if p.enabled)
            })
    }
    /// Strict MCP config disables ambient auto-discovered servers at launch.
    pub fn mcp_config(
        &self,
        selected: &[String],
        worktree: &str,
    ) -> Result<serde_json::Value, String> {
        if !valid_pod_path(worktree) {
            return Err("MCP worktree must be an absolute owned path".into());
        }
        let mut servers = serde_json::Map::new();
        for id in selected {
            let server = self
                .mcp_servers
                .get(id)
                .filter(|_| self.mcp.contains(id))
                .ok_or_else(|| format!("MCP {id} is not admitted by this workload"))?;
            if servers.contains_key(id) {
                return Err(format!("MCP {id} selected twice"));
            }
            let expand = |value: &str| value.replace("{worktree}", worktree);
            servers.insert(id.clone(), serde_json::json!({"type":"stdio", "command": server.command, "args": server.args.iter().map(|v| expand(v)).collect::<Vec<_>>(), "env": server.env.iter().map(|(k,v)| (k.clone(), expand(v))).collect::<BTreeMap<_,_>>()}));
        }
        Ok(serde_json::json!({"mcpServers": servers}))
    }
}

pub fn compose_claude_code<'a>(
    objects: &'a [RegistryObject],
    id: &str,
) -> Result<&'a ClaudeCodeToml, String> {
    let profile = objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::ClaudeCode(profile) if object.id == id => Some(profile.as_ref()),
            _ => None,
        })
        .ok_or_else(|| format!("Claude workload {id} is not declared"))?;
    if !profile.enabled {
        return Err(format!("Claude workload {id} is disabled"));
    }
    let errors = profile.validate(objects);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(profile)
}

#[cfg(test)]
mod tests;
