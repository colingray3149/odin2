//! Governed Claude driver boundary. Pod sessions are driven through structured
//! events. Host tabs never accept model prompts: a Sinmara host-tab is refused
//! because this target has no agent prompt path, and a Colin tab returns colin_only.
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::tools::CapabilityTool;
use super::HermesRuntime;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaudePlacement {
    #[default]
    Pod,
    HostTab,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeOpenRequest {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<ClaudePlacement>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_permissions: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudePromptRequest {
    pub session: String,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeReadRequest {
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeStopRequest {
    pub session: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub discard_unpushed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeSessionState {
    Opening,
    Running,
    Prompting,
    Stopping,
    Stopped,
    InDoubt,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSessionRecord {
    pub session: String,
    pub request: ClaudeOpenRequest,
    pub owner_run: String,
    pub state: ClaudeSessionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_control: Option<Value>,
    pub cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_driver_cursor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_publication_cursor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSessionEvent {
    pub cursor: u64,
    pub kind: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaudeReadError {
    EventTooLarge { cursor: u64, max_bytes: u64 },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeReadReply {
    pub session: ClaudeSessionRecord,
    pub events: Vec<ClaudeSessionEvent>,
    pub next_cursor: u64,
    pub has_more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ClaudeReadError>,
}

/// Preflights are read-only prerequisite checks. Errors must preserve whether
/// an effect provably did not start or its outcome is uncertain.
pub trait ClaudeSessionRoute: Send + Sync {
    fn preflight_open(
        &self,
        scope: &Scope,
        request: &ClaudeOpenRequest,
    ) -> Result<(), HostToolError>;
    fn open(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: Scope,
        request: ClaudeOpenRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError>;
    fn preflight_prompt(
        &self,
        scope: &Scope,
        request: &ClaudePromptRequest,
    ) -> Result<(), HostToolError>;
    fn prompt(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: Scope,
        request: ClaudePromptRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError>;
    fn preflight_read(
        &self,
        scope: &Scope,
        request: &ClaudeReadRequest,
    ) -> Result<(), HostToolError>;
    fn read(
        &self,
        scope: Scope,
        request: ClaudeReadRequest,
    ) -> Result<ClaudeReadReply, HostToolError>;
    fn preflight_stop(
        &self,
        scope: &Scope,
        request: &ClaudeStopRequest,
    ) -> Result<(), HostToolError>;
    fn stop(
        &self,
        effect: &odin_kernel::operation::PreparedEffect,
        scope: Scope,
        request: ClaudeStopRequest,
    ) -> Result<ClaudeSessionRecord, HostToolError>;
}

fn route(
    runtime: &HermesRuntime,
    tool: &'static str,
) -> Result<Arc<dyn ClaudeSessionRoute>, HostToolError> {
    runtime
        .claude_session_route
        .lock()
        .map_err(|_| HostToolError::Storage {
            tool,
            detail: "Claude route lock poisoned".into(),
        })?
        .clone()
        .ok_or_else(|| HostToolError::Unavailable {
            tool,
            reason: "Claude session route is not bound".into(),
        })
}

fn parse<T: serde::de::DeserializeOwned>(
    tool: &'static str,
    value: Value,
) -> Result<T, HostToolError> {
    if tool == "claude_open"
        && value
            .get("preset")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        for field in ["account", "project"] {
            if value
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(HostToolError::Arguments {
                    tool,
                    detail: format!("{field} is required unless a preset is named"),
                });
            }
        }
        if value.get("dir").is_some() {
            return Err(HostToolError::Arguments {
                tool,
                detail: "dir is only valid for a named preset".into(),
            });
        }
    }
    serde_json::from_value(value).map_err(|error| HostToolError::Arguments {
        tool,
        detail: error.to_string(),
    })
}

fn validate_effect(
    tool: &'static str,
    effect: &odin_kernel::operation::PreparedEffect,
    scope: &Scope,
    arguments: &Value,
) -> Result<(), HostToolError> {
    let capability = match tool {
        "claude_open" => "claude.open",
        "claude_prompt" => "claude.prompt",
        "claude_stop" => "claude.stop",
        _ => {
            return Err(HostToolError::Catalog {
                detail: "unknown Claude effect".into(),
            })
        }
    };
    let bound_scope = effect
        .executor_binding()
        .and_then(|binding| binding.get("scope"));
    let scope_value = serde_json::to_value(scope).map_err(|error| HostToolError::Arguments {
        tool,
        detail: error.to_string(),
    })?;
    if effect.contract().tool_name.as_str() != tool
        || effect.contract().id.as_str() != capability
        || &effect.payload().arguments != arguments
        || bound_scope != Some(&scope_value)
        || scope
            .run
            .as_ref()
            .is_none_or(|run| effect.target().kind != "run" || effect.target().id != run.as_str())
    {
        return Err(HostToolError::Catalog {
            detail: format!("{tool} requires its exact prepared contract, payload and run scope"),
        });
    }
    Ok(())
}

pub(super) fn claude_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    macro_rules! register {
        ($name:literal, $request:ty, $method:ident, $preflight:ident, $description:literal, $schema:literal) => {{
            let handler_runtime = Arc::clone(runtime);
            let preflight_runtime = Arc::clone(runtime);
            tools.push(Arc::new(CapabilityTool::prepared(
                RpcHostToolDefinition {
                    name: $name.into(),
                    label: $name.into(),
                    description: $description.into(),
                    parameters: serde_json::from_str(include_str!($schema))
                        .expect("compiled Claude input schema"),
                    hidden: false,
                    load_mode: ToolLoadMode::Essential,
                },
                Box::new(move |effect, scope, arguments| {
                    validate_effect($name, effect, &scope, &arguments)?;
                    let request: $request = parse($name, arguments)?;
                    let result = route(&handler_runtime, $name)?.$method(effect, scope, request)?;
                    odin_omp::host_tools::response($name, &result)
                }),
                Box::new(move |scope, arguments| {
                    let request: $request = parse($name, arguments.clone())?;
                    route(&preflight_runtime, $name)?.$preflight(scope, &request)
                }),
            )));
        }};
    }
    register!("claude_open", ClaudeOpenRequest, open, preflight_open,
        "Open a declared Claude Code workload: sandboxed pod by default, or Colin-owned host-tab. Only declared account, project and MCP IDs; no seat or ACP delegation.",
        "../../../../schemas/capability/claude.open.input.json");
    register!("claude_prompt", ClaudePromptRequest, prompt, preflight_prompt,
        "Prompt a sandboxed Claude driver through its structured session. Refuses Colin-owned host tabs; never scrape or type into their terminal.",
        "../../../../schemas/capability/claude.prompt.input.json");
    register!("claude_stop", ClaudeStopRequest, stop, preflight_stop,
        "Stop the exact owned Claude session. Refuses unpushed commits unless discard_unpushed is explicit; never bypass ownership or stop authority.",
        "../../../../schemas/capability/claude.stop.input.json");
    let handler_runtime = Arc::clone(runtime);
    let preflight_runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::plain(
        RpcHostToolDefinition {
            name: "claude_read".into(), label: "Claude read".into(),
            description: "Read durable Claude metadata and structured events after a cursor; never scrape a terminal.".into(),
            parameters: serde_json::from_str(include_str!("../../../../schemas/capability/claude.read.input.json")).expect("compiled Claude read schema"),
            hidden: false, load_mode: ToolLoadMode::Essential,
        },
        Box::new(move |scope, arguments| {
            let request: ClaudeReadRequest = parse("claude_read", arguments)?;
            let result = route(&handler_runtime, "claude_read")?.read(scope, request)?;
            odin_omp::host_tools::response("claude_read", &result)
        }),
        Box::new(move |scope, arguments| {
            let request: ClaudeReadRequest = parse("claude_read", arguments.clone())?;
            route(&preflight_runtime, "claude_read")?.preflight_read(scope, &request)
        }),
    )));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn optional_wire_fields_are_absent_and_pod_is_default() {
        let request: ClaudeOpenRequest =
            serde_json::from_value(json!({"account":"default","project":"test"})).unwrap();
        assert_eq!(request.placement.unwrap_or_default(), ClaudePlacement::Pod);
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json!({"account":"default","project":"test"})
        );
        let stop: ClaudeStopRequest = serde_json::from_value(json!({"session":"owned"})).unwrap();
        assert!(!stop.discard_unpushed);
        assert_eq!(
            serde_json::to_value(stop).unwrap(),
            json!({"session":"owned"})
        );
    }

    #[test]
    fn permission_override_preserves_explicit_false_and_true() {
        for enabled in [false, true] {
            let value = json!({"account":"default","project":"test","placement":"host-tab","skip_permissions":enabled});
            let request: ClaudeOpenRequest = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(request.skip_permissions, Some(enabled));
            assert_eq!(serde_json::to_value(request).unwrap(), value);
        }
    }

    #[test]
    fn normal_preset_omits_project_and_account_without_weakening_ordinary_open() {
        for id in ["normal", "break-glass"] {
            let request: ClaudeOpenRequest =
                parse("claude_open", json!({"preset": id, "dir": "/home/colin"})).unwrap();
            assert_eq!(request.preset.as_deref(), Some(id));
            assert!(request.account.is_empty());
            assert!(request.project.is_empty());
            assert_eq!(request.dir.as_deref(), Some("/home/colin"));
        }
        let request: ClaudeOpenRequest = parse(
            "claude_open",
            json!({"preset":"normal","dir":"/home/colin"}),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({"preset":"normal","dir":"/home/colin"})
        );
        for arguments in [
            json!({}),
            json!({"account":"default"}),
            json!({"account":"default","project":"odin","dir":"/tmp"}),
            json!({"preset":""}),
        ] {
            assert!(matches!(
                parse::<ClaudeOpenRequest>("claude_open", arguments),
                Err(HostToolError::Arguments { .. })
            ));
        }
    }

    #[test]
    fn malformed_contract_is_typed_and_rejects_driver_injection() {
        assert!(matches!(
            parse::<ClaudeOpenRequest>(
                "claude_open",
                json!({"account":"default","project":"test","driver":"sinmara"})
            ),
            Err(HostToolError::Arguments {
                tool: "claude_open",
                ..
            })
        ));
        assert!(
            parse::<ClaudeReadRequest>("claude_read", json!({"session":"owned","since":-1}))
                .is_err()
        );
        assert!(parse::<ClaudePromptRequest>("claude_prompt", json!({"session":"owned"})).is_err());
    }
}
