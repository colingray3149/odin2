//! Human host tabs expose verified, bounded transcript reads, never an agent prompt path.
use crate::claude_host_transport::ClaudeHostTransport;
use crate::claude_sessions::{ClaudeBackendOutcome, ClaudeSessionBackend};
use odin_hermes::runtime::claude::{ClaudeOpenRequest, ClaudeSessionRecord};
use odin_omp::host_tools::HostToolError;
use odin_registry::{AccountKind, SnapshotHandle};
use serde_json::{json, Value};
use std::sync::Arc;

const HOST_WORKLOAD_AMBIGUOUS: &str =
    "host_workload_ambiguous: exactly one declared host-tab workload must match";

const TARGET: &str = include_str!("claude_host_target.py");

pub(crate) struct ClaudeHostBackend {
    pin: Arc<SnapshotHandle>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    transport: ClaudeHostTransport,
}

fn unavailable(cause: impl std::fmt::Display) -> HostToolError {
    HostToolError::unavailable("claude_open", cause)
}
pub(crate) const HOST_TAB_UNPROMPTABLE: &str =
    "host_tab_unpromptable: a host-tab has no agent prompt path";
pub(crate) const OWNER_ONLY: &str = "colin_only: host-tab is never agent-driven";

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
) -> Option<odin_hermes::runtime::claude::ClaudePlacement> {
    match placement {
        odin_registry::ClaudePlacement::Pod => {
            Some(odin_hermes::runtime::claude::ClaudePlacement::Pod)
        }
        odin_registry::ClaudePlacement::HostTab => {
            Some(odin_hermes::runtime::claude::ClaudePlacement::HostTab)
        }
        // The reviewer is not a session placement; presets cannot declare it.
        odin_registry::ClaudePlacement::Review => None,
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
                return Err(HOST_WORKLOAD_AMBIGUOUS.into());
            }
            found = Some(profile.driver());
        }
    }
    found.ok_or_else(|| HOST_WORKLOAD_AMBIGUOUS.into())
}

pub(crate) fn host_tab_prompt_refusal(driver: odin_registry::ClaudeDriver) -> &'static str {
    match driver {
        odin_registry::ClaudeDriver::Sinmara => HOST_TAB_UNPROMPTABLE,
        odin_registry::ClaudeDriver::Owner => OWNER_ONLY,
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

/// A preset tab's working directory: the one asked for, else the preset's
/// default unless a sandboxed tab names its project. An unsandboxed tab never
/// starts inside a project checkout.
fn preset_dir(
    request: &ClaudeOpenRequest,
    preset: &odin_registry::ClaudePresetToml,
) -> Option<String> {
    match &request.dir {
        Some(dir) => Some(dir.clone()),
        None if request.project.is_empty() || preset.unsandboxed => {
            Some(preset.default_dir.clone())
        }
        None => None,
    }
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
            .map_err(|error| unavailable(format!("host_observation_unavailable: {error}")))?;
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
            return Err(unavailable(HOST_WORKLOAD_AMBIGUOUS));
        }
        Ok(profiles.into_iter().next().expect("one matching profile"))
    }

    fn invoke(
        &self,
        request: &ClaudeOpenRequest,
        session: &str,
        op: &str,
        discard: bool,
        transcript: Option<&ClaudeSessionRecord>,
    ) -> Result<Value, HostToolError> {
        if !odin_registry::valid_account_name(&request.account) {
            return Err(HostToolError::Arguments {
                tool: "claude_open",
                detail: "invalid_account_handle".into(),
            });
        }
        let profile = self.profile(request)?;
        let (host, root) = self.target(request)?;
        let payload = if op == "stop" || op == "read" {
            json!({"op": op, "session": session, "root": root, "discard_unpushed": discard,
                "transcript": transcript.is_some(),
                "since": transcript.and_then(|record| record.last_driver_cursor).unwrap_or(0),
                "claude_session_id": transcript.and_then(|record| record.claude_session_id.as_deref()),
                "transcript_source": transcript.and_then(|record| record.resource.as_ref())
                    .and_then(|resource| resource.get("transcript_source"))})
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
                "model": request.model,
                "owns_worktree": owns_worktree, "unsandboxed": unsandboxed})
        };
        let failed = |detail: String| {
            if op == "preflight" {
                unavailable(detail)
            } else {
                HostToolError::Uncertain {
                    tool: match op {
                        "stop" => "claude_stop",
                        "read" => "claude_read",
                        _ => "claude_open",
                    },
                    detail,
                }
            }
        };
        let bytes = self
            .transport
            .run(&host, TARGET, &payload)
            .map_err(&failed)?;
        let reply: Value = serde_json::from_slice(&bytes)
            .map_err(|error| failed(format!("target_reply_invalid: {error}")))?;
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
            resolved.dir = preset_dir(&resolved, &preset);
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
            None,
        )
        .map(|_| ())
    }
    fn open(
        &self,
        _: &odin_kernel::PreparedEffect,
        record: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let resource = self.invoke(&record.request, &record.session, "open", false, None)?;
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
    /// A live tab reports its Remote Control session; a gone one (closed in
    /// the hub, or its Claude exited) is settled like a stop, keeping a
    /// worktree the stop refuses to remove.
    fn read(&self, record: &ClaudeSessionRecord) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.read_status(record, false)
    }
    fn read_transcript(
        &self,
        record: &ClaudeSessionRecord,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        self.read_status(record, true)
    }
    fn stop(
        &self,
        _: &odin_kernel::PreparedEffect,
        record: &ClaudeSessionRecord,
        discard: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let resource = self.invoke(&record.request, &record.session, "stop", discard, None)?;
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

impl ClaudeHostBackend {
    fn read_status(
        &self,
        record: &ClaudeSessionRecord,
        transcript: bool,
    ) -> Result<ClaudeBackendOutcome, HostToolError> {
        let mut status = self.invoke(
            &record.request,
            &record.session,
            "read",
            false,
            transcript.then_some(record),
        )?;
        if status.get("alive") == Some(&Value::Bool(true)) {
            let mut page = status
                .get_mut("transcript")
                .map(Value::take)
                .unwrap_or_default();
            let mut resource = record.resource.clone();
            if let (Some(source), Some(resource)) = (
                page.get_mut("source").map(Value::take),
                resource.as_mut().and_then(Value::as_object_mut),
            ) {
                resource.insert("transcript_source".into(), source);
            }
            let claude_session_id = match page.get_mut("session_id").map(Value::take) {
                Some(Value::String(id)) => Some(id),
                _ => None,
            };
            let events = match page.get_mut("events").map(Value::take) {
                Some(Value::Array(events)) => events,
                _ => Vec::new(),
            };
            return Ok(ClaudeBackendOutcome {
                resource,
                claude_session_id,
                events,
                has_more: page
                    .get("has_more")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                remote_control: status
                    .get_mut("remote_control")
                    .filter(|rc| !rc.is_null())
                    .map(Value::take),
                ..Default::default()
            });
        }
        let (resource, event) =
            match self.invoke(&record.request, &record.session, "stop", false, None) {
                Ok(resource) => (Some(resource), json!({"type":"host_tab_ended"})),
                Err(kept) => (
                    record.resource.clone(),
                    json!({"type":"host_tab_ended","worktree_kept":kept.to_string()}),
                ),
            };
        Ok(ClaudeBackendOutcome {
            resource,
            events: vec![event],
            ended: true,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::preset_dir;

    #[test]
    fn an_unsandboxed_tab_opens_in_its_default_dir_even_for_a_project() {
        let profile: odin_registry::ClaudeCodeToml = toml::from_str(include_str!(
            "../../../../registry/workloads/claude-code-host-pc/profile.toml"
        ))
        .unwrap();
        let mut preset = profile.presets["normal"].clone();
        let mut request: odin_hermes::runtime::claude::ClaudeOpenRequest =
            serde_json::from_value(serde_json::json!({"preset": "normal", "project": "odin"}))
                .unwrap();
        preset.unsandboxed = true;
        assert_eq!(
            preset_dir(&request, &preset),
            Some(preset.default_dir.clone())
        );
        preset.unsandboxed = false;
        assert_eq!(
            preset_dir(&request, &preset),
            None,
            "a sandboxed tab uses the checkout"
        );
        request.dir = Some("/tmp/asked".to_owned());
        assert_eq!(preset_dir(&request, &preset).as_deref(), Some("/tmp/asked"));
    }
}
