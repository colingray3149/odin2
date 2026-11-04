//! The daemon-bound read-only and resolution surfaces: `terminal.read`,
//! `huginn.read`, and `workspace.connect`, all dispatched through seams
//! the runtime composes unbound — an unbound seam is a typed
//! unavailability, never a fabricated read.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::authority::{HuginnReadRoute, TerminalReadRoute};
use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

#[derive(serde::Serialize)]
struct WorkspaceReceipt {
    command: String,
    kind: &'static str,
    host: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    opened: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ownership: Option<super::authority::WorkspaceOwnership>,
}

/// The bound terminal reader with the call's session and byte limit.
fn terminal_call(
    runtime: &HermesRuntime,
    arguments: &Value,
) -> Result<(Arc<dyn TerminalReadRoute>, String, usize), HostToolError> {
    const MAX_BYTES: u64 = 1_048_576;
    let route = runtime
        .terminal_reader
        .lock()
        .ok()
        .and_then(|cell| cell.clone())
        .ok_or_else(|| HostToolError::Unavailable {
            tool: "terminal_read",
            reason: "the terminal read route is not bound".to_owned(),
        })?;
    let session = parse_string(arguments, "session", 128)?;
    let max_bytes = arguments
        .get("maxBytes")
        .and_then(Value::as_u64)
        .filter(|bytes| (1..=MAX_BYTES).contains(bytes))
        .ok_or_else(|| HostToolError::Arguments {
            tool: "terminal_read",
            detail: format!("maxBytes must be an integer between 1 and {MAX_BYTES}"),
        })?;
    Ok((route, session, max_bytes as usize))
}

/// What one `huginn_read` asks for.
enum ReadKind {
    Status,
    Session(String),
}

impl ReadKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Session(_) => "session",
        }
    }
}

/// The bound Huginn reader with the projection the call asks for.
fn huginn_call(
    runtime: &HermesRuntime,
    scope: &Scope,
    arguments: &Value,
) -> Result<(Arc<dyn HuginnReadRoute>, ReadKind), HostToolError> {
    let route = runtime
        .huginn_reader
        .lock()
        .ok()
        .and_then(|cell| cell.clone())
        .ok_or_else(|| HostToolError::Unavailable {
            tool: "huginn_read",
            reason: "the huginn read route is not bound".to_owned(),
        })?;
    let kind = match parse_string(arguments, "kind", 16)?.as_str() {
        "status" => ReadKind::Status,
        "session" => ReadKind::Session(
            scope
                .session
                .as_ref()
                .ok_or(HostToolError::Scope {
                    tool: "huginn_read",
                    reason: "a bound session is required for the session projection",
                })?
                .to_string(),
        ),
        other => {
            return Err(HostToolError::Arguments {
                tool: "huginn_read",
                detail: format!("kind must be status or session, not {other}"),
            })
        }
    };
    Ok((route, kind))
}

/// Each tool's wording is its capability declaration; an unadmitted capability
/// omits its tool.
pub(super) fn read_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    if let Some(description) = runtime.admitted_description("terminal.read") {
        let handler_runtime = Arc::clone(runtime);
        let gate_runtime = Arc::clone(runtime);
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "terminal_read".into(),
                label: "Read terminal screen".into(),
                description: description.into(),
                parameters: capability_parameters!("terminal.read"),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(move |_scope: Scope, arguments: Value| {
                let (route, session, max_bytes) = terminal_call(&handler_runtime, &arguments)?;
                let read = route.read_screen(&session, max_bytes).map_err(|reason| {
                    HostToolError::Unavailable {
                        tool: "terminal_read",
                        reason,
                    }
                })?;
                Ok(json!({
                    "status": "read",
                    "session": read.session,
                    "content": read.content,
                    "truncated": read.truncated,
                }))
            }),
            // Route availability and arguments are checked before journaling.
            Box::new(move |_scope: &Scope, arguments: &Value| {
                terminal_call(&gate_runtime, arguments).map(|_| ())
            }),
        )));
    }
    if let Some(description) = runtime.admitted_description("huginn.read") {
        let handler_runtime = Arc::clone(runtime);
        let gate_runtime = Arc::clone(runtime);
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "huginn_read".into(),
                label: "Read Huginn status".into(),
                description: description.into(),
                parameters: capability_parameters!("huginn.read"),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(move |scope: Scope, arguments: Value| {
                let (route, kind) = huginn_call(&handler_runtime, &scope, &arguments)?;
                let projection = match &kind {
                    ReadKind::Status => route.status(),
                    ReadKind::Session(session) => route.session_projection(session),
                }
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "huginn_read",
                    reason,
                })?;
                Ok(json!({
                    "status": "ok",
                    "kind": kind.name(),
                    "projection": projection,
                }))
            }),
            // Route, projection kind and session scope are checked before journaling.
            Box::new(move |scope: &Scope, arguments: &Value| {
                huginn_call(&gate_runtime, scope, arguments).map(|_| ())
            }),
        )));
    }
    if let Some(description) = runtime.admitted_description("workspace.connect") {
        let parameters_runtime = Arc::clone(runtime);
        let runtime = Arc::clone(runtime);
        // Resolve read-only before journaling so unknown targets and offline hosts refuse early.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let _ = scope;
                let route = gate_runtime
                    .workspace_connector
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool: "workspace_connect",
                        reason: "the workspace connect route is not bound".to_owned(),
                    })?;
                let host = optional_host(arguments)?;
                let target = parse_string(arguments, "target", 256)?;
                optional_device(arguments)?;
                optional_launch_owner(arguments)?;
                route.connect(host.as_deref(), &target).map_err(|reason| {
                    HostToolError::Unavailable {
                        tool: "workspace_connect",
                        reason,
                    }
                })?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |scope: Scope, arguments: Value| {
            execute_gate(&scope, &arguments)?;
            let route = runtime
                .workspace_connector
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .expect("the gate proved the workspace connect route is bound in this same call");
            let host = optional_host(&arguments)?;
            let target = parse_string(&arguments, "target", 256)?;
            let connection = route.connect(host.as_deref(), &target).map_err(|reason| {
                HostToolError::Unavailable {
                    tool: "workspace_connect",
                    reason,
                }
            })?;
            let launch_owner = optional_launch_owner(&arguments)?;
            let (opened, ownership) = match optional_device(&arguments)? {
                Some(device) => {
                    let result = match launch_owner {
                        Some(owner) => route
                            .open_owned(&connection, &device, owner)
                            .map(|(opened, ownership)| (Some(opened), Some(ownership))),
                        None => route
                            .open(&connection, &device)
                            .map(|opened| (Some(opened), None)),
                    };
                    result.map_err(|reason| HostToolError::Unavailable {
                        tool: "workspace_connect",
                        reason,
                    })?
                }
                None => (None, None),
            };
            Ok(json!(WorkspaceReceipt {
                command: connection.command,
                kind: connection.kind.as_str(),
                host: connection.host,
                target: connection.target,
                opened,
                ownership,
            }))
        };
        tools.push(Arc::new(
            CapabilityTool::plain(
                RpcHostToolDefinition {
                    name: "workspace_connect".into(),
                    label: "Resolve workspace connection".into(),
                    description: description.into(),
                    parameters: capability_parameters!("workspace.connect"),
                    hidden: false,
                    load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
                },
                Box::new(handler),
                Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
            )
            .with_scoped_parameters(move |_scope| {
                let devices: Vec<String> = parameters_runtime
                    .registry_pin()
                    .map(|pin| {
                        pin.current()
                            .listed_objects(odin_registry::RegistryKind::Host)
                            .filter_map(|object| match &object.config {
                                odin_registry::ObjectConfig::Host(host)
                                    if host.enabled && host.enrolled =>
                                {
                                    Some(object.id.clone())
                                }
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                odin_omp::host_tools::schema_compat::resolve_ids(
                    capability_parameters!("workspace.connect"),
                    "/properties/openOn",
                    devices,
                )
            }),
        ));
    }
    if let Some(description) = runtime.admitted_description("fleet.drain") {
        let runtime = Arc::clone(runtime);
        // Resolve host and cluster prerequisites before journaling or requesting approval.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let route = gate_runtime
                    .fleet_drain
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool: "fleet_drain",
                        reason: "the fleet drain route is not bound".to_owned(),
                    })?;
                let host = parse_string(arguments, "host", 64)?;
                route
                    .resolve(&host)
                    .map_err(|reason| HostToolError::Unavailable {
                        tool: "fleet_drain",
                        reason,
                    })?;
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let route = runtime
                .fleet_drain
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .expect("the gate proved the fleet drain route is bound in this same call");
            let host = parse_string(&arguments, "host", 64)?;
            let outcome = route
                .drain(&host)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "fleet_drain",
                    reason,
                })?;
            serde_json::to_value(&outcome).map_err(|error| HostToolError::Unavailable {
                tool: "fleet_drain",
                reason: format!("the drain outcome did not serialize: {error}"),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "fleet_drain".into(),
                label: "Drain one fleet host".into(),
                description: description.into(),
                parameters: capability_parameters!("fleet.drain"),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    if let Some(description) = runtime.admitted_description("fleet.restore") {
        let runtime = Arc::clone(runtime);
        // Restore shares the read-only route checks but requires its own approval.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                let route = gate_runtime
                    .fleet_drain
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool: "fleet_restore",
                        reason: "the fleet drain route is not bound".to_owned(),
                    })?;
                let host = parse_string(arguments, "host", 64)?;
                let resolution =
                    route
                        .resolve(&host)
                        .map_err(|reason| HostToolError::Unavailable {
                            tool: "fleet_restore",
                            reason,
                        })?;
                if !resolution.kube_ready {
                    return Err(HostToolError::Unavailable {
                        tool: "fleet_restore",
                        reason: "the kube surface is not composed on this daemon".to_owned(),
                    });
                }
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let route = runtime
                .fleet_drain
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .expect("the gate proved the fleet drain route is bound in this same call");
            let host = parse_string(&arguments, "host", 64)?;
            let outcome = route
                .restore(&host)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "fleet_restore",
                    reason,
                })?;
            serde_json::to_value(&outcome).map_err(|error| HostToolError::Unavailable {
                tool: "fleet_restore",
                reason: format!("the restore outcome did not serialize: {error}"),
            })
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "fleet_restore".into(),
                label: "Restore one fleet host to schedulable".into(),
                description: description.into(),
                parameters: capability_parameters!("fleet.restore"),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
}

/// Optional `openOn`: absent or null means no device; otherwise require a non-empty string.
fn optional_device(arguments: &Value) -> Result<Option<String>, HostToolError> {
    match arguments.get("openOn") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let device = value.as_str().ok_or_else(|| HostToolError::Arguments {
                tool: "workspace_connect",
                detail: "openOn must be a string".to_owned(),
            })?;
            if device.trim().is_empty() || device.len() > 64 {
                return Err(HostToolError::Arguments {
                    tool: "workspace_connect",
                    detail: "openOn must be 1..=64 bytes".to_owned(),
                });
            }
            Ok(Some(device.trim().to_owned()))
        }
    }
}

fn optional_host(arguments: &Value) -> Result<Option<String>, HostToolError> {
    match arguments.get("host") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let host = value.as_str().ok_or_else(|| HostToolError::Arguments {
                tool: "workspace_connect",
                detail: "host must be a string".to_owned(),
            })?;
            if host.trim().is_empty() || host.len() > 64 {
                return Err(HostToolError::Arguments {
                    tool: "workspace_connect",
                    detail: "host must be 1..=64 bytes".to_owned(),
                });
            }
            Ok(Some(host.to_owned()))
        }
    }
}

fn optional_launch_owner(arguments: &Value) -> Result<Option<&str>, HostToolError> {
    let Some(value) = arguments.get("launchOwner") else {
        return Ok(None);
    };
    let owner = value
        .as_str()
        .filter(|owner| {
            !owner.is_empty()
                && owner.len() <= 64
                && owner.as_bytes()[0].is_ascii_alphanumeric()
                && owner
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .ok_or_else(|| HostToolError::Arguments {
            tool: "workspace_connect",
            detail: "launchOwner must match [a-z0-9][a-z0-9-]{0,63}".to_owned(),
        })?;
    if optional_device(arguments)?.is_none() {
        return Err(HostToolError::Arguments {
            tool: "workspace_connect",
            detail: "launchOwner requires openOn".to_owned(),
        });
    }
    Ok(Some(owner))
}

#[cfg(test)]
mod workspace_ownership_tests {
    use super::*;

    #[test]
    fn ownership_requires_device_and_bounded_safe_token() {
        assert_eq!(optional_launch_owner(&json!({})).unwrap(), None);
        assert_eq!(
            optional_launch_owner(&json!({"openOn":"pc", "launchOwner":"run-123"})).unwrap(),
            Some("run-123")
        );
        assert!(optional_launch_owner(&json!({"launchOwner":"run-123"})).is_err());
        for token in ["", "../foreign", "UPPER", "-leading"] {
            assert!(optional_launch_owner(&json!({"openOn":"pc", "launchOwner":token})).is_err());
        }
        assert!(
            optional_launch_owner(&json!({"openOn":"pc", "launchOwner":"a".repeat(65)})).is_err()
        );
        assert!(optional_launch_owner(&json!({"openOn":"pc", "launchOwner":null})).is_err());
    }
}
