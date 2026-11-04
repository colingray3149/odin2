//! `device.run`: one capability for every declared device action.
//!
//! The calling project's sphere admits the named device and action. The
//! fixed argv is rendered from that declaration — `{node}`, `{api}`,
//! `{endpoint}`, `{capsule}`, `{scratch}`, and the action's declared
//! parameters. An executable `{runtime.KEY}` resolves through the runtime
//! manifest. The command runs inside the lane's bwrap. No shell reads it. A
//! path parameter must canonicalize inside the capsule, a declared data
//! root, or the scratch root. A text parameter is one token without
//! whitespace or shell syntax. A device endpoint is declared and bound,
//! never a caller-supplied path. A bound event socket is consumed by its
//! installed device client.

use odin_domain::knowledge::ToolSchema;
use odin_domain::{CapabilityId, Scope};
use odin_kernel::{CapabilityContract, HandlerBinding, PreparedEffect, SchemaCatalog};
use odin_registry::schema::{
    ProjectDeviceActionToml, ProjectDeviceParamKind, ProjectDeviceToml, ProjectSphereToml,
};
use odin_registry::SnapshotHandle;
use serde_json::{json, Map, Value};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use crate::process::{capsule_command_argv, project_sphere, SphereProjection};

use super::{
    HostInvocation, HostTool, HostToolError, HostToolRegistry, InternalBindingKey,
    RpcHostToolDefinition, ToolLoadMode,
};

pub const DEVICE_RUN_CAPABILITY: &str = "device.run";
pub const DEVICE_RUN_HANDLER_ID: &str = "device_run";
pub const DEVICE_RUN_EVIDENCE_ID: &str = "odin_hermes_device_run_evidence";
const TOOL: &str = DEVICE_RUN_HANDLER_ID;
const OUTPUT_TAIL: usize = 16 * 1024;

/// Executes the bubble through the session's registered worker owner.
/// Permit cancellation, expiry, and session retirement stop the whole worker.
pub type DeviceActionRunner =
    dyn Fn(&PreparedEffect, &Scope, &Path, Vec<String>) -> Result<Output, String> + Send + Sync;

/// What the daemon supplies so the rendered argv can run inside the lane bubble.
#[derive(Clone)]
pub struct DeviceRunBinding {
    pub registry: Arc<SnapshotHandle>,
    pub state_root: PathBuf,
    pub run: Arc<DeviceActionRunner>,
    pub tool_path: Vec<PathBuf>,
    pub executables: BTreeMap<String, PathBuf>,
}

struct DeviceRunTool {
    definition: RpcHostToolDefinition,
    binding: DeviceRunBinding,
}

/// One admitted call: the rendered argv, the sphere filesystem, and the
/// one selected device this bubble may open. The shell never receives it.
struct AdmittedAction {
    argv: Vec<String>,
    sphere: SphereProjection,
    node: Option<PathBuf>,
    socket: Option<PathBuf>,
}

impl DeviceRunTool {
    fn new(binding: DeviceRunBinding, schema: ToolSchema) -> Self {
        Self {
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(DEVICE_RUN_HANDLER_ID),
                label: Cow::Borrowed(DEVICE_RUN_CAPABILITY),
                description: Cow::Borrowed(
                    "Run one declared device action of the calling project. The action's fixed \
                     argv is rendered from the project sphere and executed inside the lane \
                     bubble; undeclared devices, actions, and paths are refused.",
                ),
                parameters: schema.canonical_json().clone(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
            binding,
        }
    }
}

impl HostTool for DeviceRunTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        contract: &CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        admit(&self.binding, contract, scope, arguments).map(|_| ())
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!("{DEVICE_RUN_CAPABILITY} requires a kernel-minted prepared operation"),
        })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let admitted = admit(
            &self.binding,
            effect.contract(),
            &invocation.scope,
            &invocation.arguments,
        )?;
        let capsule = capsule_dir(&self.binding.state_root, &invocation.scope)?;
        let mut bubble = capsule_command_argv(
            &capsule,
            &admitted.sphere,
            &[],
            &self.binding.tool_path,
            &admitted.argv,
        )
        .map_err(|detail| HostToolError::Arguments { tool: TOOL, detail })?;
        // The selected device only. The shell and build argv never receive it.
        let dash =
            bubble
                .iter()
                .position(|arg| arg == "--")
                .ok_or_else(|| HostToolError::Arguments {
                    tool: TOOL,
                    detail: "device bubble has no command separator".to_owned(),
                })?;
        let mut device_bind = Vec::new();
        crate::process::push_selected_device(
            &mut device_bind,
            admitted.node.as_deref(),
            admitted.socket.as_deref(),
        )
        .map_err(|detail| HostToolError::Arguments { tool: TOOL, detail })?;
        bubble.splice(dash..dash, device_bind);
        let timeout = effect.contract().timeout_seconds.get();
        let output = (self.binding.run)(effect, &invocation.scope, &capsule, bubble)
            .map_err(|reason| HostToolError::Unavailable { tool: TOOL, reason })?;
        let tail = |bytes: &[u8]| {
            String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(OUTPUT_TAIL)..]).into_owned()
        };
        Ok(json!({
            "device": text_field(&invocation.arguments, "device")?,
            "action": text_field(&invocation.arguments, "action")?,
            "argv": admitted.argv,
            "exitCode": output.status.code(),
            "stdout": tail(&output.stdout),
            "stderr": tail(&output.stderr),
            "timedOut": false,
            "timeoutSeconds": timeout,
        }))
    }
}

/// Registers the model-visible tool, the handler, and the receipt.
pub fn register(
    registry: &mut HostToolRegistry,
    binding: DeviceRunBinding,
    contracts: &BTreeMap<CapabilityId, CapabilityContract>,
    schemas: &dyn SchemaCatalog,
) -> Result<(), HostToolError> {
    let marker = HandlerBinding::Builtin {
        name: DEVICE_RUN_HANDLER_ID.to_owned(),
    };
    let Some(contract) = contracts
        .values()
        .find(|contract| contract.handler == marker)
    else {
        return Ok(());
    };
    let schema = schemas
        .schema(&contract.input_schema_ref)
        .map_err(|error| HostToolError::Catalog {
            detail: format!(
                "{DEVICE_RUN_CAPABILITY} input schema {}: {error}",
                contract.input_schema_ref
            ),
        })?;
    let tool = Arc::new(DeviceRunTool::new(binding, schema));
    registry.register(Arc::clone(&tool) as Arc<dyn HostTool>)?;
    registry.register_internal(
        InternalBindingKey::Builtin(DEVICE_RUN_HANDLER_ID.to_owned()),
        tool,
    )?;
    registry.register_internal(
        InternalBindingKey::Builtin(DEVICE_RUN_EVIDENCE_ID.to_owned()),
        Arc::new(Receipt),
    )
}

struct Receipt;

impl HostTool for Receipt {
    fn definition(&self) -> &RpcHostToolDefinition {
        &RECEIPT_DEFINITION
    }

    fn preflight(
        &self,
        _contract: &CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        Ok(invocation.arguments)
    }
}

static RECEIPT_DEFINITION: std::sync::LazyLock<RpcHostToolDefinition> =
    std::sync::LazyLock::new(|| RpcHostToolDefinition {
        name: Cow::Borrowed(DEVICE_RUN_EVIDENCE_ID),
        label: Cow::Borrowed("device.run receipt"),
        description: Cow::Borrowed("Internal receipt of one device action."),
        parameters: json!({"type": "object", "additionalProperties": false}),
        hidden: true,
        load_mode: ToolLoadMode::Essential,
    });

fn admit(
    binding: &DeviceRunBinding,
    _contract: &CapabilityContract,
    scope: &Scope,
    arguments: &Value,
) -> Result<AdmittedAction, HostToolError> {
    let project = scope.project.as_ref().ok_or(HostToolError::Scope {
        tool: TOOL,
        reason: "device.run requires a project",
    })?;
    let device_name = text_field(arguments, "device")?;
    let action_name = text_field(arguments, "action")?;
    let params = arguments
        .get("params")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let snapshot = binding.registry.current();
    let sphere = project_sphere(snapshot.objects.iter(), project).ok_or_else(|| {
        HostToolError::Arguments {
            tool: TOOL,
            detail: format!("project {project} declares no sphere"),
        }
    })?;
    let device = sphere
        .device(device_name)
        .ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("project {project} does not declare device {device_name:?}"),
        })?;
    let action = device
        .action(action_name)
        .ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("device {device_name:?} does not declare action {action_name:?}"),
        })?;
    let capsule = capsule_dir(&binding.state_root, scope)?;
    if device.api.is_some()
        || device.endpoint.as_deref().is_some_and(|endpoint| {
            endpoint.starts_with("http://") || endpoint.starts_with("https://")
        })
    {
        return Err(HostToolError::Unavailable {
            tool: TOOL,
            reason: format!(
                "device {device_name:?} declares an HTTP endpoint and no HTTP device backend is installed; the action is not run"
            ),
        });
    }
    let argv = render_argv(
        &action.argv,
        device,
        action,
        sphere,
        &capsule,
        &params,
        &binding.executables,
    )?;
    let node = device.node.as_deref().map(PathBuf::from);
    let socket = device
        .endpoint
        .as_deref()
        .and_then(|endpoint| endpoint.strip_prefix("unix://").map(PathBuf::from));
    Ok(AdmittedAction {
        argv,
        sphere: SphereProjection::from_sphere(sphere)
            .map_err(|detail| HostToolError::Arguments { tool: TOOL, detail })?,
        node,
        socket,
    })
}

fn render_argv(
    argv: &[String],
    device: &ProjectDeviceToml,
    action: &ProjectDeviceActionToml,
    sphere: &ProjectSphereToml,
    capsule: &Path,
    params: &Value,
    executables: &BTreeMap<String, PathBuf>,
) -> Result<Vec<String>, HostToolError> {
    let object = params.as_object().ok_or_else(|| HostToolError::Arguments {
        tool: TOOL,
        detail: "params must be an object".to_owned(),
    })?;
    for name in object.keys() {
        if !action.params.contains_key(name) {
            return Err(HostToolError::Arguments {
                tool: TOOL,
                detail: format!("undeclared parameter {name:?}"),
            });
        }
    }
    let mut rendered = Vec::with_capacity(argv.len());
    for (index, token) in argv.iter().enumerate() {
        if index == 0 {
            if let Some(key) = token
                .strip_prefix("{runtime.")
                .and_then(|s| s.strip_suffix('}'))
            {
                let path = executables
                    .get(key)
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool: TOOL,
                        reason: format!("runtime manifest has no executable key {key:?}"),
                    })?;
                rendered.push(
                    path.to_str()
                        .ok_or_else(|| HostToolError::Unavailable {
                            tool: TOOL,
                            reason: format!("runtime executable {key:?} path is not UTF-8"),
                        })?
                        .to_owned(),
                );
                continue;
            }
        }
        rendered.push(substitute(token, device, action, sphere, capsule, object)?);
    }
    if rendered
        .first()
        .is_none_or(|executable| !Path::new(executable).is_absolute())
    {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: "device action argv has no absolute executable".to_owned(),
        });
    }
    Ok(rendered)
}

fn substitute(
    token: &str,
    device: &ProjectDeviceToml,
    action: &ProjectDeviceActionToml,
    sphere: &ProjectSphereToml,
    capsule: &Path,
    params: &Map<String, Value>,
) -> Result<String, HostToolError> {
    let mut rest = token;
    let mut out = String::new();
    while let Some(open) = rest.find('{') {
        let close = rest[open + 1..]
            .find('}')
            .ok_or_else(|| HostToolError::Arguments {
                tool: TOOL,
                detail: format!("malformed placeholder in {token:?}"),
            })?;
        let name = &rest[open + 1..open + 1 + close];
        out.push_str(&rest[..open]);
        out.push_str(&placeholder_value(
            name, device, action, sphere, capsule, params,
        )?);
        rest = &rest[open + close + 2..];
    }
    if rest.contains('}') {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!("malformed placeholder in {token:?}"),
        });
    }
    out.push_str(rest);
    Ok(out)
}

fn placeholder_value(
    name: &str,
    device: &ProjectDeviceToml,
    action: &ProjectDeviceActionToml,
    sphere: &ProjectSphereToml,
    capsule: &Path,
    params: &Map<String, Value>,
) -> Result<String, HostToolError> {
    match name {
        "node" => device.node.clone().ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("device {:?} has no serial node", device.name),
        }),
        "api" => device.api.clone().ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("device {:?} has no API", device.name),
        }),
        "endpoint" => bound_endpoint(device),
        "capsule" => Ok(capsule.display().to_string()),
        "scratch" => Ok(sphere.scratch.clone()),
        other => {
            let kind = action
                .params
                .get(other)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("undeclared placeholder {other:?}"),
                })?;
            let value = params.get(other).and_then(Value::as_str).ok_or_else(|| {
                HostToolError::Arguments {
                    tool: TOOL,
                    detail: format!("parameter {other:?} requires a string"),
                }
            })?;
            match kind {
                ProjectDeviceParamKind::Path => admitted_path(value, capsule, sphere),
                ProjectDeviceParamKind::Text => admitted_text(other, value),
            }
        }
    }
}

/// A unix endpoint is the socket bound at [`crate::process::DEVICE_SOCKET`].
/// The host path stays out of the argv: the bubble does not mount that
/// path's parent. An HTTP(S) endpoint is not a filesystem bind, so it is
/// rendered as declared.
fn bound_endpoint(device: &ProjectDeviceToml) -> Result<String, HostToolError> {
    let endpoint = device
        .endpoint
        .clone()
        .ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("device {:?} has no endpoint", device.name),
        })?;
    if endpoint.starts_with("unix://") {
        Ok(format!("unix://{}", crate::process::DEVICE_SOCKET))
    } else {
        Ok(endpoint)
    }
}
/// A path parameter must canonicalize inside the capsule, a data root, or
/// the scratch root. A device endpoint is declared and bound separately,
/// so a caller cannot name a socket here.
pub(super) fn admitted_path(
    value: &str,
    capsule: &Path,
    sphere: &ProjectSphereToml,
) -> Result<String, HostToolError> {
    let path = Path::new(value);
    // A parent step is refused even where the path does not exist and only its text is checked.
    let steps_up = path
        .components()
        .any(|component| component == std::path::Component::ParentDir);
    if !path.is_absolute() || value.contains('\0') || steps_up {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!("{value:?} is not an absolute sphere path"),
        });
    }
    // A resolved symlink is admitted only at its target. The lexical prefix
    // is not enough: a link inside the scratch root can point at the host.
    let candidate = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => path.to_path_buf(),
    };
    let inside = |root: &Path| candidate.starts_with(root);
    let admitted = inside(capsule)
        || inside(Path::new(&sphere.scratch))
        || sphere.data_roots.iter().any(|root| inside(Path::new(root)));
    if !admitted {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!("{value:?} is outside the project's sphere"),
        });
    }
    Ok(candidate.display().to_string())
}

pub(super) fn admitted_text(name: &str, value: &str) -> Result<String, HostToolError> {
    let refused = value.is_empty()
        || value.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '$' | '`' | ';' | '&' | '|' | '>' | '<' | '\0')
        });
    if refused {
        return Err(HostToolError::Arguments {
            tool: TOOL,
            detail: format!("parameter {name:?} is not one static token"),
        });
    }
    Ok(value.to_owned())
}

fn text_field<'a>(arguments: &'a Value, field: &str) -> Result<&'a str, HostToolError> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| HostToolError::Arguments {
            tool: TOOL,
            detail: format!("{field} requires a non-empty string"),
        })
}

fn capsule_dir(state_root: &Path, scope: &Scope) -> Result<PathBuf, HostToolError> {
    let session = scope.session.as_ref().ok_or(HostToolError::Scope {
        tool: TOOL,
        reason: "device.run requires a session",
    })?;
    let capsule_id = crate::host_tools::operations::session_capsule_id(session).map_err(|_| {
        HostToolError::Scope {
            tool: TOOL,
            reason: "device.run session has no capsule",
        }
    })?;
    let path = state_root
        .join("session-authorities")
        .join(format!("capsule-{}", capsule_id.as_str().replace(':', "-")))
        .join("capsule")
        .join("project");
    if !path.is_dir() {
        return Err(HostToolError::Unavailable {
            tool: TOOL,
            reason: "this session has no workspace capsule".to_owned(),
        });
    }
    Ok(path)
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
