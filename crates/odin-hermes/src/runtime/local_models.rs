//! `local.models`: the local model list and GPU modes through the declared `local-models` CLI.
//! The workflow crate runs it; a host other than this one runs it over the fleet's ssh wrapper.

use std::path::Path;
use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_omp::live::harness::ssh_host_argv;
use odin_workflows::{Failure, FailureKind};
use serde_json::Value;

use super::tools::CapabilityTool;
use super::HermesRuntime;

const TOOL: &str = "local_models";

pub(super) fn local_models_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let runtime = Arc::clone(runtime);
    let handler = move |_scope: Scope, arguments: Value| {
        let ctx = runtime
            .tool_context()
            .map_err(|cause| HostToolError::unavailable(TOOL, cause))?;
        odin_workflows::local_models::run(
            ctx,
            |host, words| ssh_host_argv(host, Path::new("."), words, false),
            &arguments,
        )
        .map_err(to_host)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: TOOL.into(),
            label: "Local models and GPU modes".into(),
            description: "Local models and GPU modes of any host: list, load, unload, swap, pull from a name or link, and mode odin/kreate/gaming. Names, sizes and loaded state only."
                .into(),
            parameters: capability_parameters!("local.models"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

fn to_host(failure: Failure) -> HostToolError {
    match failure.kind {
        FailureKind::Arguments => HostToolError::Arguments {
            tool: TOOL,
            detail: failure.cause,
        },
        _ => HostToolError::unavailable(TOOL, failure.cause),
    }
}
