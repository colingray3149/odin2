//! The daemon-bound read-only and resolution surfaces: `terminal.read`,
//! `huginn.read`, and `workspace.connect`, all dispatched through seams
//! the runtime composes unbound — an unbound seam is a typed
//! unavailability, never a fabricated read.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
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

pub(super) fn read_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    {
        let runtime = Arc::clone(runtime);
        // Check route availability and arguments before journaling.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |_scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                if gate_runtime
                    .terminal_reader
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .is_none()
                {
                    return Err(HostToolError::Unavailable {
                        tool: "terminal_read",
                        reason: "the terminal read route is not bound".to_owned(),
                    });
                }
                let _session = parse_string(arguments, "session", 128)?;
                let max_bytes = arguments
                    .get("maxBytes")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| HostToolError::Arguments {
                        tool: "terminal_read",
                        detail: "maxBytes must be an integer between 1 and 1048576".to_owned(),
                    })?;
                if !(1..=1_048_576).contains(&max_bytes) {
                    return Err(HostToolError::Arguments {
                        tool: "terminal_read",
                        detail: "maxBytes must be an integer between 1 and 1048576".to_owned(),
                    });
                }
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |_scope: Scope, arguments: Value| {
            execute_gate(&_scope, &arguments)?;
            let route = runtime
                .terminal_reader
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .expect("the gate proved the terminal read route is bound in this same call");
            let session = parse_string(&arguments, "session", 128)?;
            let max_bytes = arguments
                .get("maxBytes")
                .and_then(Value::as_u64)
                .ok_or_else(|| HostToolError::Arguments {
                    tool: "terminal_read",
                    detail: "maxBytes must be an integer between 1 and 1048576".to_owned(),
                })?;
            if !(1..=1_048_576).contains(&max_bytes) {
                return Err(HostToolError::Arguments {
                    tool: "terminal_read",
                    detail: "maxBytes must be an integer between 1 and 1048576".to_owned(),
                });
            }
            let read = route
                .read_screen(&session, max_bytes as usize)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "terminal_read",
                    reason,
                })?;
            Ok(json!({
                "status": "read",
                "session": read.session,
                "content": read.content,
                "truncated": read.truncated,
            }))
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "terminal_read".into(),
                label: "Read terminal screen".into(),
                description:
                    "One bounded read-only capture of the operator's real terminal session \
                     screen through the daemon's resolved live target. Read-only: no input \
                     injection and no command execution exist on this surface. `session` is \
                     the ZELLIJ TERMINAL SESSION NAME of the daemon's bound live target — \
                     the operator terminal this governed surface runs in — never an Odin \
                     session id, run id, or delegated child id; derive it from the bound \
                     target (or ask the operator) instead of guessing. The capture is the \
                     bounded viewport, never an unchecked full-scroll dump; content beyond \
                     maxBytes is truncated and reported. An unresolvable target is a typed \
                     error, never a fabricated transcript.".into(),
                parameters: object_schema(
                    "terminal_read",
                    json!({
                        "session": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                            "description": "Zellij terminal session name of the daemon's bound live target (an operator terminal). NOT an Odin session id, run id, or delegated child session id."
                        },
                        "maxBytes": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 1048576,
                            "description": "Byte ceiling for the captured viewport content; captures beyond it are truncated and reported, never silently dropped."
                        }
                    }),
                    &["session", "maxBytes"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        // Validate route, projection kind and session scope before journaling.
        let gate_runtime = Arc::clone(&runtime);
        let gate = std::sync::Arc::new(
            move |scope: &Scope, arguments: &Value| -> Result<(), HostToolError> {
                if gate_runtime
                    .huginn_reader
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .is_none()
                {
                    return Err(HostToolError::Unavailable {
                        tool: "huginn_read",
                        reason: "the huginn read route is not bound".to_owned(),
                    });
                }
                let kind = parse_string(arguments, "kind", 16)?;
                match kind.as_str() {
                    "status" => {}
                    "session" => {
                        if scope.session.is_none() {
                            return Err(HostToolError::Scope {
                                tool: "huginn_read",
                                reason: "a bound session is required for the session projection",
                            });
                        }
                    }
                    other => {
                        return Err(HostToolError::Arguments {
                            tool: "huginn_read",
                            detail: format!("kind must be status or session, not {other}"),
                        });
                    }
                }
                Ok(())
            },
        );
        let execute_gate = Arc::clone(&gate);
        let handler = move |scope: Scope, arguments: Value| {
            execute_gate(&scope, &arguments)?;
            let route = runtime
                .huginn_reader
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .expect("the gate proved the huginn read route is bound in this same call");
            let kind = parse_string(&arguments, "kind", 16)?;
            let projection = match kind.as_str() {
                "status" => route.status(),
                "session" => {
                    let session = scope.session.clone().ok_or_else(|| HostToolError::Scope {
                        tool: "huginn_read",
                        reason: "a bound session is required for the session projection",
                    })?;
                    route.session_projection(session.to_string().as_str())
                }
                other => {
                    return Err(HostToolError::Arguments {
                        tool: "huginn_read",
                        detail: format!("kind must be status or session, not {other}"),
                    });
                }
            }
            .map_err(|reason| HostToolError::Unavailable {
                tool: "huginn_read",
                reason,
            })?;
            Ok(json!({
                "status": "ok",
                "kind": kind,
                "projection": projection,
            }))
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "huginn_read".into(),
                label: "Read Huginn status".into(),
                description: "One read-only Huginn query: kind=status returns the daemon status \
                     snapshot; kind=session returns the caller's own governed session \
                     projection. No mutating call is reachable through this capability, and \
                     an unreachable daemon is a typed error, never a synthesized snapshot."
                    .into(),
                parameters: object_schema(
                    "huginn_read",
                    json!({
                        "kind": { "type": "string", "enum": ["status", "session"] }
                    }),
                    &["kind"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
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
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "workspace_connect".into(),
                label: "Resolve workspace connection".into(),
                description: "Open a workspace for Colin: a live zellij session on a \
                     declared fleet host or a declared project's source tree in Zed. With \
                     `openOn` (the device he is at: laptop or pc) it OPENS the window on \
                     that device's screen — a terminal attached to the session, or Zed on \
                     the project over ssh — and `opened` says what opened where; tell him \
                     that, never the raw command. Without `openOn` it only resolves the \
                     command. An unknown target, an undeclared or offline host or device, \
                     no graphical session, or a locked screen is a typed error and nothing \
                     opens.".into(),
                parameters: object_schema(
                    "workspace_connect",
                    json!({
                        "target": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 256,
                            "description": "Zellij session name (as observed in the fleet zellij placements) or declared project id."
                        },
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "Optional declared fleet host (tailscale name) to resolve the connection on."
                        },
                        "openOn": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "The declared fleet device Colin is at (e.g. laptop, pc): open the workspace on its screen."
                        },
                        "launchOwner": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "pattern": "^[a-z0-9][a-z0-9-]{0,63}$",
                            "description": "Optional unique run token: with openOn, launch an isolated owned window and return its cgroup lease; never reuse this token."
                        }
                    }),
                    &["target"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
        let runtime = Arc::clone(runtime);
        let gate_runtime = Arc::clone(&runtime);
        let handler = move |_scope: Scope, arguments: Value| {
            let route = runtime
                .workspace_connector
                .lock()
                .ok()
                .and_then(|cell| cell.clone())
                .ok_or_else(|| HostToolError::Unavailable {
                    tool: "desktop_input",
                    reason: "the desktop route is not bound".to_owned(),
                })?;
            let device = parse_string(&arguments, "device", 64)?;
            let text = parse_string(&arguments, "text", 2000)?;
            let enter = arguments
                .get("enter")
                .map(|enter| {
                    enter.as_bool().ok_or_else(|| HostToolError::Arguments {
                        tool: "desktop_input",
                        detail: "enter must be a boolean".to_owned(),
                    })
                })
                .transpose()?
                .unwrap_or(false);
            route
                .input(&device, &text, enter)
                .map_err(|reason| HostToolError::Unavailable {
                    tool: "desktop_input",
                    reason,
                })?;
            let typed: String = text.chars().take(500).collect();
            Ok(json!({
                "status": "typed",
                "device": device,
                "typed": if enter { format!("{typed} ⏎") } else { typed },
            }))
        };
        tools.push(Arc::new(CapabilityTool::plain(
            RpcHostToolDefinition {
                name: "desktop_input".into(),
                label: "Type on Colin's desktop".into(),
                description: "Type text (and Enter, when asked) into the focused window on \
                     Colin's laptop or pc, as keystrokes in his own desktop session: he sees \
                     it and can type too. Only what he asked to have typed, never a password. \
                     No desktop session or a locked screen is a typed error and nothing is \
                     typed."
                    .into(),
                parameters: object_schema(
                    "desktop_input",
                    json!({
                        "device": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "The declared fleet device whose desktop to type on (laptop, pc)."
                        },
                        "text": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 2000,
                            "description": "The text to type."
                        },
                        "enter": {
                            "type": "boolean",
                            "description": "Press Enter after the text."
                        }
                    }),
                    &["device", "text"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |_scope: &Scope, _arguments: &Value| {
                gate_runtime
                    .workspace_connector
                    .lock()
                    .ok()
                    .and_then(|cell| cell.clone())
                    .map(|_| ())
                    .ok_or_else(|| HostToolError::Unavailable {
                        tool: "desktop_input",
                        reason: "the desktop route is not bound".to_owned(),
                    })
            }),
        )));
    }
    {
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
                description: "Drain every drainable pod off the named declared fleet host's \
                     registry nodes through the daemon's kube surface, bounded and typed: \
                     pods still present at the deadline are REPORTED, never an error. When \
                     the host holds the registry's authoritative state this NEVER touches \
                     the cluster — it returns the ordered authority-move runbook (backup, \
                     restore drill, registry handoff, rehearsal, standby startup, root \
                     provisioning, re-drain) with the declared standby candidates; the real \
                     transition stays operator-run. An unknown host, an offline host, or a \
                     host without kube service is a typed error, never a fabricated \
                     report."
                    .into(),
                parameters: object_schema(
                    "fleet_drain",
                    json!({
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "The declared fleet host to drain."
                        }
                    }),
                    &["host"],
                ),
                hidden: false,
                load_mode: odin_omp::host_tools::ToolLoadMode::Discoverable,
            },
            Box::new(handler),
            Box::new(move |scope: &Scope, arguments: &Value| gate(scope, arguments)),
        )));
    }
    {
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
                description: "Uncordon every registry node of the named declared fleet host \
                     through the daemon's kube surface and report the real post-patch \
                     schedulable state read back from the API server. Bounded and typed; \
                     an unknown host, an offline host, or a daemon without a kube surface \
                     is a typed error, never a fabricated report."
                    .into(),
                parameters: object_schema(
                    "fleet_restore",
                    json!({
                        "host": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "The declared fleet host to restore."
                        }
                    }),
                    &["host"],
                ),
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

    #[test]
    fn ordinary_receipt_omits_owned_launch_wire_field() {
        let receipt = json!(WorkspaceReceipt {
            command: "zr mini odin".to_owned(),
            kind: "zellij",
            host: "mini".to_owned(),
            target: "odin".to_owned(),
            opened: None,
            ownership: None,
        });
        assert!(receipt.get("ownership").is_none());
        assert!(receipt.get("opened").is_none());
    }
}
