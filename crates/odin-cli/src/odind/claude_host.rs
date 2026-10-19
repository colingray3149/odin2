//! Human host tabs accept neither driver prompts nor transcript scraping; automated host tabs are refused.
use crate::claude_host_transport::ClaudeHostTransport;
use crate::claude_sessions::{ClaudeBackendOutcome, ClaudeSessionBackend};
use odin_hermes::runtime::claude::{ClaudeOpenRequest, ClaudeSessionRecord};
use odin_omp::host_tools::HostToolError;
use odin_registry::{AccountKind, SnapshotHandle};
use serde_json::{json, Value};
use std::sync::Arc;

const TARGET: &str = include_str!("claude_host_target.py");

pub(crate) struct ClaudeHostBackend {
    pin: Arc<SnapshotHandle>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    transport: ClaudeHostTransport,
}

fn unavailable(reason: impl Into<String>) -> HostToolError {
    HostToolError::Unavailable {
        tool: "claude_open",
        reason: reason.into(),
    }
}
pub(crate) const HOST_TAB_UNPROMPTABLE: &str =
    "host_tab_unpromptable: Sinmara host-tab has no agent prompt path";
pub(crate) const COLIN_ONLY: &str = "colin_only: host-tab is never agent-driven";

pub(crate) fn declared_preset(
    registry: &odin_registry::Snapshot,
    id: &str,
) -> Result<odin_registry::ClaudePresetToml, String> {
    let mut found = None;
    for object in registry.listed_objects(odin_registry::RegistryKind::Workload) {
        let odin_registry::ObjectConfig::ClaudeCode(profile) = &object.config else {
            continue;
        };
        if !profile.enabled {
            continue;
        }
        if let Some(preset) = profile.presets.get(id) {
            if found.is_some() {
                return Err(format!("preset_ambiguous: {id}"));
            }
            found = Some(preset.clone());
        }
    }
    found.ok_or_else(|| format!("preset_undeclared: {id}"))
}

pub(crate) fn launch_placement(
    placement: odin_registry::ClaudePlacement,
) -> odin_hermes::runtime::claude::ClaudePlacement {
    match placement {
        odin_registry::ClaudePlacement::Pod => odin_hermes::runtime::claude::ClaudePlacement::Pod,
        odin_registry::ClaudePlacement::HostTab => {
            odin_hermes::runtime::claude::ClaudePlacement::HostTab
        }
    }
}

pub(crate) fn admitted_driver(
    registry: &odin_registry::Snapshot,
    request: &ClaudeOpenRequest,
) -> Result<odin_registry::ClaudeDriver, String> {
    if let Some(id) = request.preset.as_deref() {
        return Ok(declared_preset(registry, id)?.driver);
    }
    let host_id = request
        .host
        .as_deref()
        .ok_or_else(|| "host_not_declared: name the host".to_owned())?;
    let mut found = None;
    for object in registry.listed_objects(odin_registry::RegistryKind::Workload) {
        let odin_registry::ObjectConfig::ClaudeCode(profile) = &object.config else {
            continue;
        };
        if profile.enabled
            && profile.placement == odin_registry::ClaudePlacement::HostTab
            && profile.harness == odin_registry::CLAUDE_CODE_HARNESS
            && profile.host.as_deref() == Some(host_id)
            && (request.project.is_empty()
                || profile.projects.is_empty()
                || profile.projects.contains(&request.project))
        {
            if found.is_some() {
                return Err(
                    "host_workload_ambiguous: exactly one declared host-tab workload must match"
                        .into(),
                );
            }
            found = Some(profile.driver());
        }
    }
    found.ok_or_else(|| {
        "host_workload_ambiguous: exactly one declared host-tab workload must match".into()
    })
}

pub(crate) fn host_tab_prompt_refusal(driver: odin_registry::ClaudeDriver) -> &'static str {
    match driver {
        odin_registry::ClaudeDriver::Sinmara => HOST_TAB_UNPROMPTABLE,
        odin_registry::ClaudeDriver::Colin => COLIN_ONLY,
    }
}

pub(crate) fn declared_checkout(
    profile: &odin_registry::ClaudeCodeToml,
    project: &str,
) -> Result<String, String> {
    profile
        .checkouts
        .get(project)
        .filter(|path| path.starts_with('/'))
        .cloned()
        .ok_or_else(|| format!("project_checkout_undeclared: {project} has no absolute checkout"))
}

impl ClaudeHostBackend {
    pub(crate) fn new(
        pin: Arc<SnapshotHandle>,
        read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
        transport: ClaudeHostTransport,
    ) -> Self {
        Self {
            pin,
            read_model,
            transport,
        }
    }

    fn target(
        &self,
        request: &ClaudeOpenRequest,
    ) -> Result<(String, Option<String>), HostToolError> {
        let host_id = request
            .host
            .as_deref()
            .ok_or_else(|| unavailable("host_not_declared: name the host"))?;
        let registry = self.pin.current();
        let host = registry
            .listed_objects(odin_registry::RegistryKind::Host)
            .into_iter()
            .find_map(|object| match &object.config {
                odin_registry::ObjectConfig::Host(host)
                    if object.id == host_id && host.enabled && host.enrolled =>
                {
                    Some(host.tailscale.clone())
                }
                _ => None,
            })
            .filter(|name| !name.is_empty() && !name.starts_with('-'))
            .ok_or_else(|| unavailable("host_not_declared: host must be enabled and enrolled"))?;
        let capture = self
            .read_model
            .capture()
            .map_err(|_| unavailable("host_observation_unavailable"))?;
        if capture.objects.iter().any(|object| {
            object.object.id == host_id
                && object.object.kind == odin_domain::huginn::ObjectKind::FleetHost
                && object.value.get("online") == Some(&Value::Bool(false))
        }) {
            return Err(unavailable("host_offline"));
        }
        if request.preset.is_some() {
            if let Some(dir) = &request.dir {
                if !dir.starts_with('/') && dir != "~" && !dir.starts_with("~/") {
                    return Err(unavailable(
                        "preset_dir_invalid: use an absolute path or ~/path",
                    ));
                }
                return Ok((host, Some(dir.clone())));
            }
            if request.project.is_empty() {
                return Ok((host, None));
            }
        }
        let declared = registry
            .listed_objects(odin_registry::RegistryKind::Project)
            .into_iter()
            .any(|object| {
                matches!(&object.config, odin_registry::ObjectConfig::Project(project)
                if object.id == request.project && project.enabled)
            });
        if !declared {
            return Err(unavailable("project_not_declared"));
        }
        let profile = self.profile(request)?;
        let root = declared_checkout(&profile, &request.project).map_err(unavailable)?;
        Ok((host, Some(root)))
    }

    fn profile(
        &self,
        request: &ClaudeOpenRequest,
    ) -> Result<Box<odin_registry::ClaudeCodeToml>, HostToolError> {
        let host_id = request
            .host
            .as_deref()
            .ok_or_else(|| unavailable("host_not_declared: name the host"))?;
        let registry = self.pin.current();
        let profiles: Vec<_> = registry
            .listed_objects(odin_registry::RegistryKind::Workload)
            .filter_map(|object| match &object.config {
                odin_registry::ObjectConfig::ClaudeCode(profile)
                    if profile.enabled
                        && profile.placement == odin_registry::ClaudePlacement::HostTab
                        && profile.harness == odin_registry::CLAUDE_CODE_HARNESS
                        && profile.host.as_deref() == Some(host_id)
                        && (request.project.is_empty() && request.preset.is_some()
                            || profile.projects.is_empty()
                            || profile.projects.contains(&request.project)) =>
                {
                    Some(profile.clone())
                }
                _ => None,
            })
            .collect();
        if profiles.len() != 1 {
            return Err(unavailable(
                "host_workload_ambiguous: exactly one declared host-tab workload must match",
            ));
        }
        Ok(profiles.into_iter().next().expect("one matching profile"))
    }

    fn invoke(
        &self,
        request: &ClaudeOpenRequest,
        session: &str,
        op: &str,
        discard: bool,
    ) -> Result<Value, HostToolError> {
        if !odin_registry::valid_account_name(&request.account) {
            return Err(HostToolError::Arguments {
                tool: "claude_open",
                detail: "invalid_account_handle".into(),
            });
        }
        let profile = self.profile(request)?;
        let (host, root) = self.target(request)?;
        let payload = if op == "stop" {
            json!({"op": op, "session": session, "root": root, "discard_unpushed": discard})
        } else {
            let (remote_control, owns_worktree, unsandboxed) =
                if let Some(id) = request.preset.as_deref() {
                    let preset = declared_preset(&self.pin.current(), id).map_err(unavailable)?;
                    (
                        preset.remote_control,
                        !preset.unsandboxed,
                        preset.unsandboxed,
                    )
                } else {
                    (profile.remote_control, true, false)
                };
            let skip = request
                .skip_permissions
                .unwrap_or_else(|| profile.skip_permissions());
            let mcp = profile
                .mcp_config(&request.mcp, "/ODIN_OWNED_WORKTREE")
                .map_err(unavailable)?;
            let name = request.name.as_deref().unwrap_or(session);
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            {
                return Err(HostToolError::Arguments {
                    tool: "claude_open",
                    detail: "invalid_name: use lowercase letters, digits and dashes".into(),
                });
            }
            let account = AccountKind::ClaudeCode;
            let layout = account.layout(&request.account);
            json!({"op":op,"session":session,"root":root,"name":name,
                "account":request.account,"sign_in":layout.sign_in,
                "login_hint":format!("On {host}: {}", account.sign_in_hint(&request.account)),
                "config_dir":layout.env.map(|_| layout.dir),"discard_unpushed":discard,
                "remote_control": remote_control, "skip_permissions": skip, "mcp": mcp,
                "owns_worktree": owns_worktree, "unsandboxed": unsandboxed})
        };
        let failed = |detail: String| {
            if op == "preflight" {
                unavailable(detail)
            } else {
                HostToolError::Uncertain {
                    tool: if op == "stop" {
                        "claude_stop"
                    } else {
                        "claude_open"
                    },
                    detail,
                }
            }
        };
        let bytes = self
            .transport
            .run(&host, TARGET, &payload)
            .map_err(&failed)?;
        let reply: Value =
            serde_json::from_slice(&bytes).map_err(|_| failed("target_reply_invalid".into()))?;
        if let Some(error) = reply.get("error") {
            return Err(failed(error.to_string()));
        }
        reply
            .get("ok")
            .cloned()
            .ok_or_else(|| failed("target_reply_missing".into()))
    }
}

impl ClaudeSessionBackend for ClaudeHostBackend {
    fn resolve(&self, request: &ClaudeOpenRequest) -> Result<ClaudeOpenRequest, HostToolError> {
        let mut resolved = request.clone();
        if let Some(id) = request.preset.as_deref() {
            let preset = declared_preset(&self.pin.current(), id).map_err(unavailable)?;
            if preset.placement != odin_registry::ClaudePlacement::HostTab {
                return Err(unavailable(format!(
                    "preset_placement: {id} is not host-tab"
                )));
            }
            if preset.driver == odin_registry::ClaudeDriver::Sinmara {
                return Err(unavailable(HOST_TAB_UNPROMPTABLE));
            }
            if resolved.account.is_empty() {
                resolved.account = preset.default_account.clone();
            }
            if resolved.host.is_none() {
                resolved.host = Some(preset.default_host.clone());
            }
            if resolved.dir.is_none() && resolved.project.is_empty() {
                resolved.dir = Some(preset.default_dir.clone());
            }
            resolved.skip_permissions = Some(preset.skip_permissions);
            resolved.placement = Some(odin_hermes::runtime::claude::ClaudePlacement::HostTab);
        }
        let profile = self.profile(&resolved)?;
        if request.preset.is_none() && profile.driver() == odin_registry::ClaudeDriver::Sinmara {
            return Err(unavailable(HOST_TAB_UNPROMPTABLE));
        }
        if resolved.placement.is_none() {
            resolved.placement = Some(odin_hermes::runtime::claude::ClaudePlacement::HostTab);
        }
        if resolved.host.is_none() {
            resolved.host = profile.host.clone();
        }
        if resolved.host.is_none() {
            return Err(unavailable("host_not_declared: name the host"));
        }
        resolved.skip_permissions = Some(
            resolved
                .skip_permissions
                .unwrap_or_else(|| profile.skip_permissions()),
        );
        Ok(resolved)
    }
    fn preflight(&self, request: &ClaudeOpenRequest) -> Result<(), HostToolError> {
        let resolved = self.resolve(request)?;
        self.invoke(
            &resolved,
            "00000000-0000-0000-0000-000000000000",
            "preflight",
            false,
        )
        .map(|_| ())
    }
    fn open(
        &self,
        _: &odin_kernel::PreparedEffect,
        record: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let resource = self.invoke(&record.request, &record.session, "open", false)?;
        let driver = if let Some(id) = record.request.preset.as_deref() {
            declared_preset(&self.pin.current(), id)
                .map_err(unavailable)?
                .driver
        } else {
            self.profile(&record.request)?.driver()
        };
        let driver = format!("{driver:?}").to_lowercase();
        Ok(ClaudeBackendOutcome {
            resource: Some(resource),
            events: vec![json!({"type":"host_tab_opened","driver": driver})],
            ..Default::default()
        })
    }
    fn prompt(
        &self,
        _: &odin_kernel::PreparedEffect,
        record: &ClaudeSessionRecord,
        _: &str,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let driver = admitted_driver(&self.pin.current(), &record.request).map_err(|reason| {
            HostToolError::Unavailable {
                tool: "claude_prompt",
                reason,
            }
        })?;
        Err(HostToolError::Unavailable {
            tool: "claude_prompt",
            reason: host_tab_prompt_refusal(driver).into(),
        })
    }
    fn read(&self, record: &ClaudeSessionRecord) -> Result<ClaudeBackendOutcome, HostToolError> {
        Ok(ClaudeBackendOutcome {
            resource: record.resource.clone(),
            ..Default::default()
        })
    }
    fn stop(
        &self,
        _: &odin_kernel::PreparedEffect,
        record: &ClaudeSessionRecord,
        discard: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let resource = self.invoke(&record.request, &record.session, "stop", discard)?;
        let event = if resource.get("no_effect") == Some(&Value::Bool(true)) {
            json!({"type":"host_tab_stopped","no_effect":true})
        } else {
            json!({"type":"host_tab_stopped"})
        };
        Ok(ClaudeBackendOutcome {
            resource: Some(resource),
            events: vec![event],
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::declared_checkout;

    #[test]
    fn a_host_tab_uses_the_checkout_declared_for_that_host() {
        let declared: odin_registry::ClaudeCodeToml = toml::from_str(
            r#"
schema = "odin.registry.v1"
kind = "workload"
enabled = true
description = "host checkout fixture"
harness = "claude-code"
account_kind = "claude-code"
accounts = "discovered"
placement = "host-tab"
host = "pc"
projects = ["odin"]
checkouts = { odin = "/home/colin/pc/odin" }
[image]
reference = "platform"
[resources]
cpu_request = "250m"
cpu_limit = "2"
memory_request = "512Mi"
memory_limit = "4Gi"
storage_limit = "8Gi"
"#,
        )
        .unwrap();
        assert_eq!(
            declared_checkout(&declared, "odin").unwrap(),
            "/home/colin/pc/odin"
        );
        assert!(declared_checkout(&declared, "surtr").is_err());
    }
}
