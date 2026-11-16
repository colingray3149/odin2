//! `simulation.read` and `simulation.frame`: what a running pod shows, while it runs.
//!
//! Every Odin pod but a research pod is a mission on odind's simulation board. A read
//! names each mission's stage, node, last status sample, checkpoints, open renders and
//! kept frames, and for one named mission the files its export dir holds so far. A frame
//! is the newest PNG a mission's pod rendered: shared with the caller as an artifact (so
//! `discord.file.send` and `files.drop` send it unchanged) and returned as an image.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::images::{image_block, view_jpeg, TURN_IMAGE_BASE64};
use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

const READ: &str = "simulation_read";
const FRAME: &str = "simulation_frame";

/// The daemon's simulation board. The tools never see the cluster.
pub trait SimulationRoute: Send + Sync {
    /// Every mission, or the one `mission` names (run id, label or workload); with `exports`,
    /// that mission's export files so far.
    fn read(&self, mission: Option<&str>, exports: bool) -> Result<Value, String>;
    /// The newest kept frame of one mission (of `renderer` when named): file name and image bytes.
    fn frame(&self, mission: &str, renderer: Option<&str>) -> Result<(String, Vec<u8>), String>;
}

fn optional(arguments: &Value, key: &str) -> Result<Option<String>, HostToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => parse_string(arguments, key, 253).map(Some),
    }
}

fn route(
    runtime: &HermesRuntime,
    tool: &'static str,
) -> Result<Arc<dyn SimulationRoute>, HostToolError> {
    runtime
        .simulation_route()
        .ok_or_else(|| HostToolError::unavailable(tool, "this daemon has no simulation board"))
}

fn read(runtime: &HermesRuntime, arguments: &Value) -> Result<Value, HostToolError> {
    let mission = optional(arguments, "mission")?;
    let exports = arguments
        .get("exports")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if exports && mission.is_none() {
        return Err(HostToolError::Arguments {
            tool: READ,
            detail: "exports lists one mission's files: name the mission".to_owned(),
        });
    }
    route(runtime, READ)?
        .read(mission.as_deref(), exports)
        .map_err(|reason| HostToolError::unavailable(READ, reason))
}

fn frame(
    runtime: &HermesRuntime,
    scope: &Scope,
    arguments: &Value,
) -> Result<Value, HostToolError> {
    let mission = parse_string(arguments, "mission", 253)?;
    let renderer = optional(arguments, "renderer")?;
    let (name, bytes) = route(runtime, FRAME)?
        .frame(&mission, renderer.as_deref())
        .map_err(|reason| HostToolError::unavailable(FRAME, reason))?;
    let svg = name.to_ascii_lowercase().ends_with(".svg");
    let media_type = if svg { "image/svg+xml" } else { "image/png" };
    let mut result = runtime
        .share_file(scope, &name, media_type, &bytes)
        .map_err(|reason| HostToolError::unavailable(FRAME, reason))?;
    if svg {
        result["note"] = Value::String(format!("{name} is available as an SVG file"));
    } else {
        match view_jpeg(&bytes, TURN_IMAGE_BASE64) {
            Ok(jpeg) => result["images"] = json!([image_block(&jpeg)]),
            Err(reason) => {
                result["note"] = Value::String(format!("{name} cannot be shown: {reason}"))
            }
        }
    }
    Ok(result)
}

pub(super) fn simulation_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    {
        let runtime = Arc::clone(runtime);
        tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
            RpcHostToolDefinition {
                name: READ.into(),
                label: "Read running pods".into(),
                description: "Reads the missions on Odin's board: every pod but research pods, \
                     running or recently ended. Each shows its stage, node, last status sample \
                     (the pod's ODIN-STATUS counters), checkpoints, open renders and kept frames. \
                     Name one mission (run id, label or workload) to read only it; exports true \
                     also lists the files its export dir holds so far. simulation_frame shows a \
                     mission's latest frame."
                    .into(),
                parameters: capability_parameters!("simulation.read"),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
            Box::new(move |_scope, arguments| read(&runtime, &arguments)),
        )));
    }
    let runtime = Arc::clone(runtime);
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: FRAME.into(),
            label: "Show a pod's latest frame".into(),
            description: "Shows the newest PNG or safe SVG frame of one mission or renderer and \
                 shares it with you: the result's artifact goes to discord_file_send or \
                 files_drop to send it to the owner."
                .into(),
            parameters: capability_parameters!("simulation.frame"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(move |scope, arguments| frame(&runtime, &scope, &arguments)),
    )));
}
