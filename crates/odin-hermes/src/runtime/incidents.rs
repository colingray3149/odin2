//! Incidents appear in Huginn; warnings and above wake the conversation, while only errors and critical incidents page the phone.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;

const TOOL: &str = "incident_raise";

pub trait IncidentRoute: Send + Sync {
    fn raise(
        &self,
        seat: &odin_domain::SeatId,
        severity: &str,
        summary: String,
        detail: String,
        affected: Vec<String>,
    ) -> Result<Value, String>;
}

pub(super) fn incident_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let seat = scope.seat.clone().ok_or(HostToolError::Scope {
            tool: TOOL,
            reason: "a bound seat is required",
        })?;
        let severity = parse_string(&arguments, "severity", 16)?;
        let summary = parse_string(&arguments, "summary", 200)?;
        let detail = parse_string(&arguments, "detail", 2_000)?;
        let affected = arguments
            .get("affected")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .take(8)
                    .map(|item| item.chars().take(128).collect())
                    .collect()
            })
            .unwrap_or_default();
        let route = runtime
            .incident_route()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: TOOL,
                reason: "the incident desk is not composed on this host".to_owned(),
            })?;
        route
            .raise(&seat, &severity, summary, detail, affected)
            .map_err(|reason| HostToolError::Arguments {
                tool: TOOL,
                detail: reason,
            })
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Raise an incident".into(),
            description: "Raises an incident Colin must know about now — something broke, a \
                          limit was breached, work is stuck in a way you cannot fix: it lands \
                          in Huginn; warning and above reach the conversation, while only error \
                          or critical alerts his phone when a sink is declared. Info stays in \
                          Huginn. For routine progress, just report in your answer instead."
                .into(),
            parameters: object_schema(
                TOOL,
                json!({
                    "severity": { "enum": ["info", "warning", "error", "critical"] },
                    "summary": { "type": "string", "minLength": 1, "maxLength": 200 },
                    "detail": { "type": "string", "minLength": 1, "maxLength": 2000 },
                    "affected": {
                        "type": "array",
                        "maxItems": 8,
                        "items": { "type": "string", "minLength": 1, "maxLength": 128 }
                    },
                }),
                &["severity", "summary", "detail"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}
