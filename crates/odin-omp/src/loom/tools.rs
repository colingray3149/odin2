//! A loom session's tools: the seat's admitted host tools, dispatched
//! straight through Odin's operation authority with the session's full
//! execution proof, plus `read` over the scoped URI router (OMP's own
//! `read` of host URIs).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use odin_domain::Scope;
use odin_ledger::Ledger;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use crate::host_tools::operations::{
    HostToolOperations, PreparedToolCall, SessionOperationBinding,
};
use crate::host_tools::runner::{reserve_background, run_detachable, Ran, ToolDispatch};
use crate::uri::{ExecutionBinding, ScopedUriRouter, UriContext, UriScheme};

/// Loom's name for the URI read tool.
pub const READ_TOOL: &str = "read";

pub struct SessionTools {
    pub operations: HostToolOperations,
    pub binding: SessionOperationBinding,
    pub admitted: BTreeSet<String>,
    pub scope: Scope,
    pub uri_router: ScopedUriRouter,
    pub ledger: Arc<Mutex<Ledger>>,
    pub artifact_root: std::path::PathBuf,
    /// Bounds every admitted call of the session, as the side channel does.
    pub permits: Arc<Semaphore>,
}

/// What one call answered, as text for the model.
#[derive(Clone, Debug)]
pub struct Answer {
    pub text: String,
    pub is_error: bool,
    /// Image blocks the result carried (`{type: image, data, mimeType}`).
    pub images: Vec<Value>,
}

impl SessionTools {
    /// The OpenAI tool listing: every admitted, listed host tool (the
    /// deferred `more` tool among them) and `read`.
    pub fn listing(&self) -> Result<Vec<Value>, String> {
        let definitions = self
            .operations
            .projection_view(&self.binding)
            .and_then(|view| view.admitted_definitions(&self.admitted, true, Some(&self.scope)))
            .map_err(|error| format!("tool listing: {error}"))?;
        let mut tools: Vec<Value> = definitions
            .into_iter()
            .filter(|definition| !definition.hidden)
            .map(|definition| {
                json!({"type": "function", "function": {
                    "name": definition.name,
                    "description": definition.description,
                    "parameters": definition.parameters,
                }})
            })
            .collect();
        let schemes: Vec<&str> = UriScheme::ALL
            .iter()
            .map(|scheme| scheme.as_str())
            .collect();
        tools.push(json!({"type": "function", "function": {
            "name": READ_TOOL,
            "description": format!(
                "Read one Odin URI ({}://…) under this session's scope and return its content.",
                schemes.join("://…, ")
            ),
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "The URI to read."}},
                "required": ["path"],
                "additionalProperties": false,
            },
        }}));
        // Sorted by name, so the cached prefix is byte-stable.
        tools.sort_by(|a, b| {
            a["function"]["name"]
                .as_str()
                .cmp(&b["function"]["name"].as_str())
        });
        Ok(tools)
    }

    /// Runs one call through the same admission OMP's side channel uses.
    pub async fn call(
        &self,
        execution: &ExecutionBinding,
        name: &str,
        arguments: &str,
        request_id: &str,
    ) -> Answer {
        let arguments: Value = match serde_json::from_str(arguments) {
            Ok(value) => value,
            Err(error) => return refused(format!("the arguments of {name} are not JSON: {error}")),
        };
        let Ok(_permit) = Arc::clone(&self.permits).acquire_owned().await else {
            return refused("the session's tool admission is closed".to_owned());
        };
        if name == READ_TOOL {
            let Some(url) = arguments["path"].as_str().map(str::to_owned) else {
                return refused("read needs a path".to_owned());
            };
            let router = self.uri_router.clone();
            let context = UriContext::with_execution(self.scope.clone(), execution.clone());
            return match tokio::task::spawn_blocking(move || router.resolve(&context, &url)).await {
                Ok(Ok(resolved)) => {
                    let value = crate::bridge::uri_result_value(&resolved);
                    Answer {
                        text: value["content"].as_str().unwrap_or_default().to_owned(),
                        is_error: false,
                        images: Vec::new(),
                    }
                }
                Ok(Err(error)) => refused(error.to_string()),
                Err(error) => refused(format!("the read's worker failed: {error}")),
            };
        }
        let view = match self.operations.projection_view(&self.binding) {
            Ok(view) => view,
            Err(error) => return refused(error.to_string()),
        };
        let (tool, arguments, ignored) =
            match view.prepare_tool_call(&self.admitted, name, arguments, Some(&self.scope)) {
                Ok(PreparedToolCall::Help(schema)) => {
                    return Answer {
                        text: schema.to_string(),
                        is_error: false,
                        images: Vec::new(),
                    }
                }
                Ok(PreparedToolCall::Call {
                    name,
                    arguments,
                    ignored,
                }) => (name, arguments, ignored),
                Err(error) => return refused(error.to_string()),
            };
        let reserved = reserve_background(&view, &self.scope, &tool, &arguments);
        let dispatch = ToolDispatch {
            operations: view,
            binding: self.binding.clone(),
            session: execution.session_id().clone(),
            scope: self.scope.clone(),
            execution: execution.clone(),
            name: tool.clone(),
            arguments,
            ignored,
            request_id: request_id.to_owned(),
        };
        let result = match run_detachable(&tool, move || dispatch.run(), reserved).await {
            Ran::Detached(result) | Ran::Done(Ok(Ok(result))) => result,
            Ran::Done(Ok(Err(error))) => {
                return refused(crate::bridge::model_error_text(&error.to_string()))
            }
            Ran::Done(Err(error)) => return refused(format!("the call's worker failed: {error}")),
        };
        let blocks = result["content"].as_array().cloned().unwrap_or_default();
        let (images, text): (Vec<Value>, Vec<Value>) = blocks
            .into_iter()
            .partition(|block| block["type"] == "image");
        let text = text
            .iter()
            .map(|block| match block["text"].as_str() {
                Some(text) => text.to_owned(),
                None => format!(
                    "[{} block omitted]",
                    block["type"].as_str().unwrap_or("non-text")
                ),
            })
            .collect::<Vec<_>>()
            .join("\n");
        Answer {
            text,
            is_error: result["isError"].as_bool().unwrap_or(false),
            images,
        }
    }

    /// Stores a long result whole; `artifact.read` pages it back.
    pub fn spill(&self, tool: &str, result: Value) -> Result<String, String> {
        crate::host_tools::result_budget::spill(
            &self.scope,
            &json!({"tool": tool, "result": result}),
            &self.artifact_root,
            &self.ledger,
        )
    }
}

pub fn refused(text: String) -> Answer {
    Answer {
        text,
        is_error: true,
        images: Vec::new(),
    }
}
