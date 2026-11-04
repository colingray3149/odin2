//! Compiles conversation-supplied skeleton values, commits and publishes through
//! the same transaction as project, seat and routine authoring.
//!
//! Three capabilities, one route:
//! - `registry.skeleton.read` (R0): a skeleton's variables, to fill one.
//! - `registry.author` (R2, no approval): kinds that add no authority — a
//!   lane, a container alert or surface, and a watchdog on a pod profile
//!   (`new-alert` with `workload` instead of `container`).
//! - `registry.author.grant` (R3, self-approved by its declaration; journaled): kinds that grant or
//!   reach — capability, provider, host, node, slice, container,
//!   environment, harness — and `remove-environment`, the removal of one
//!   declared environment: the access change its creation declares, in
//!   reverse, journaled.
//!
//! Projects, seats and pod profiles keep their own bounded tools.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::projects::{PROJECT_CREATE_TOOL, SEAT_CREATE_TOOL};
use super::tools::{parse_string, CapabilityTool};
use super::HermesRuntime;

const READ_TOOL: &str = "registry_skeleton_read";
const AUTHOR_TOOL: &str = "registry_author";
const GRANT_TOOL: &str = "registry_author_grant";
/// The grant-tier verb that removes one declared environment.
pub const REMOVE_ENVIRONMENT: &str = "remove-environment";

/// Skeletons `registry.author` fills without an owner question.
pub const OPEN_SKELETONS: &[&str] = &["new-lane", "new-alert", "new-surface"];
/// Skeletons only `registry.author.grant` (operator approval) fills.
pub const GRANT_SKELETONS: &[&str] = &[
    "new-tool",
    "new-provider",
    "new-host",
    "new-node",
    "new-slice",
    "new-container",
    "new-environment",
    "new-harness",
];
/// Enabling a capability updates it, the seat's slice and tool references in one commit.
pub const GRANT_EDITS: &[&str] = &["enable-capability"];
/// Grant-tier removals of one existing declaration (no skeleton folder):
/// `remove-environment` deletes `registry/environments/<id>` in one
/// validated, tombstoned commit — the access change its creation asks
/// the owner for, in reverse.
pub const GRANT_REMOVALS: &[&str] = &[REMOVE_ENVIRONMENT];
/// Skeletons with their own bounded tool.
const OWN_TOOL: &[(&str, &str)] = &[
    ("new-project", PROJECT_CREATE_TOOL),
    ("new-seat", SEAT_CREATE_TOOL),
    ("new-workload", "workload_draft"),
];

/// Which authoring capability a dispatch came through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorTier {
    /// `registry.author`: adds no authority.
    Open,
    /// `registry.author.grant`: the owner approved the exact request.
    Grant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorRequest {
    pub skeleton: String,
    pub id: String,
    /// The skeleton's variables as TOML (`project = "rig"` lines);
    /// empty for a declared removal, and any non-empty text is refused.
    pub values: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorChange {
    pub skeleton: String,
    pub id: String,
    /// The repository path the declaration landed in.
    pub path: String,
    pub published_revision: u64,
    pub commit: String,
}

/// The daemon's authoring route; `caller` is the kernel-admitted seat.
pub trait RegistryAuthorRoute: Send + Sync {
    /// The skeleton's declared variables (name, type, required, meaning).
    fn skeleton(&self, skeleton: &str) -> Result<Value, String>;
    fn author(
        &self,
        caller: &odin_domain::SeatId,
        request: AuthorRequest,
    ) -> Result<AuthorChange, String>;
}

/// Routes specialized kinds to their own tools and requires approval for access changes.
pub fn admit(tier: AuthorTier, skeleton: &str) -> Result<(), String> {
    if let Some((_, tool)) = OWN_TOOL.iter().find(|(kind, _)| *kind == skeleton) {
        return Err(format!("{skeleton} has its own tool: use {tool}"));
    }
    match tier {
        AuthorTier::Open if OPEN_SKELETONS.contains(&skeleton) => Ok(()),
        AuthorTier::Open if GRANT_SKELETONS.contains(&skeleton) => Err(format!(
            "{skeleton} grants or reaches something: use {GRANT_TOOL}, which the declaration self-approves and journals"
        )),
        AuthorTier::Grant
            if GRANT_SKELETONS.contains(&skeleton)
                || GRANT_EDITS.contains(&skeleton)
                || GRANT_REMOVALS.contains(&skeleton) =>
        {
            Ok(())
        }
        AuthorTier::Open if GRANT_EDITS.contains(&skeleton) => Err(format!(
            "{skeleton} grants something: use {GRANT_TOOL}, which the declaration self-approves and journals"
        )),
        AuthorTier::Open if GRANT_REMOVALS.contains(&skeleton) => Err(format!(
            "{skeleton} removes declared access: use {GRANT_TOOL}, which the declaration self-approves and journals"
        )),
        AuthorTier::Grant if OPEN_SKELETONS.contains(&skeleton) => {
            Err(format!("{skeleton} needs no approval: use {AUTHOR_TOOL}"))
        }
        _ => Err(format!("{skeleton:?} is not a skeleton")),
    }
}

fn change_json(change: AuthorChange) -> Value {
    json!({
        "skeleton": change.skeleton,
        "id": change.id,
        "path": change.path,
        "publishedRevision": change.published_revision,
        "commit": change.commit,
    })
}

fn route(
    runtime: &HermesRuntime,
    tool: &'static str,
) -> Result<Arc<dyn RegistryAuthorRoute>, HostToolError> {
    runtime
        .registry_author_route()
        .ok_or_else(|| HostToolError::Unavailable {
            tool,
            reason: "registry authoring is not composed on this host".to_owned(),
        })
}

/// The declared grant schema requires `values` for fills and refuses it for
/// removals; the model is shown `skeleton` and `id` as always required.
fn parameters(tier: AuthorTier) -> Value {
    match tier {
        AuthorTier::Open => capability_parameters!("registry.author"),
        AuthorTier::Grant => {
            let mut parameters = capability_parameters!("registry.author.grant");
            parameters["required"] = json!(["skeleton", "id"]);
            parameters
        }
    }
}

fn author_tool(runtime: &Arc<HermesRuntime>, tier: AuthorTier) -> Arc<dyn HostTool> {
    let (name, label, approval) = match tier {
        AuthorTier::Open => (
            AUTHOR_TOOL,
            "Add a lane, alert or surface",
            "Adds no authority, so no approval: a lane for a project, an alert or a status \
             surface on a container, or a watchdog on a pod profile (new-alert with \
             `workload = \"<profile>\"` instead of `container`; it watches pods launched from \
             then on and after odind's next idle reload).",
        ),
        AuthorTier::Grant => (
            GRANT_TOOL,
            "Add a capability, provider, host, node, slice, container, environment or harness, \
             remove a declared environment, or turn on a capability that is off",
            "These grant or reach something; the declaration self-approves the exact request, which is journaled. \
             enable-capability turns on a declared capability that is off and grants it to one \
             seat: `id` is the capability (e.g. web.search), `values` is `seat = \"<seat>\"`; \
             registry_skeleton_read enable-capability lists the capabilities that are off. \
             remove-environment removes one declared environment: `id` is the environment id \
             (registry_skeleton_read remove-environment lists them) and it takes no `values`.",
        ),
    };
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::unavailable(name, reason);
        let caller = scope
            .seat
            .ok_or_else(|| unavailable("the dispatch carries no admitted seat".to_owned()))?;
        let skeleton = parse_string(&arguments, "skeleton", 32)?;
        admit(tier, &skeleton).map_err(|detail| HostToolError::Arguments { tool: name, detail })?;
        // A declared removal passes any `values` through untouched so the
        // daemon's typed refusal names it; a fill parses its variables.
        let values = if skeleton == REMOVE_ENVIRONMENT {
            arguments
                .get("values")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        } else {
            parse_string(&arguments, "values", 8_192)?
        };
        let request = AuthorRequest {
            skeleton,
            id: parse_string(&arguments, "id", 64)?,
            values,
        };
        route(&runtime, name)?
            .author(&caller, request)
            .map(change_json)
            .map_err(unavailable)
    };
    Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: name.into(),
            label: label.into(),
            description: format!(
                "Fills one registry skeleton and publishes it (committed to odin main). \
                 {approval} First read the skeleton's variables with {READ_TOOL}; `values` \
                 holds them as TOML lines, e.g. `project = \"rig\"` / `seats = [\"gungnir\"]` \
                 / `observation = {{ channel = \"events\" }}`. `id` is the new object's id \
                 (for new-alert / new-surface: the alert or surface id). A refusal names the \
                 field to fix."
            )
            .into(),
            parameters: parameters(tier),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    ))
}

pub(super) fn registry_author_tools(
    runtime: &Arc<HermesRuntime>,
    tools: &mut Vec<Arc<dyn HostTool>>,
) {
    let read_runtime = Arc::clone(runtime);
    let read = move |_scope: Scope, arguments: Value| {
        let skeleton = parse_string(&arguments, "skeleton", 32)?;
        route(&read_runtime, READ_TOOL)?
            .skeleton(&skeleton)
            .map_err(|reason| HostToolError::Unavailable {
                tool: READ_TOOL,
                reason,
            })
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: READ_TOOL.into(),
            label: "Read a registry skeleton".into(),
            description: "The variables one registry skeleton takes (name, type, whether \
                 required, meaning) — read it before registry_author or registry_author_grant."
                .into(),
            parameters: capability_parameters!("registry.skeleton.read"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(read),
    )));
    tools.push(author_tool(runtime, AuthorTier::Open));
    tools.push(author_tool(runtime, AuthorTier::Grant));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tier_law_routes_every_skeleton_kind() {
        use AuthorTier::{Grant, Open};
        // (tier, skeleton, the refusal it must carry, empty when admitted)
        for (tier, skeleton, refusal) in [
            (Open, "new-lane", ""),
            (Grant, "new-lane", AUTHOR_TOOL),
            (Grant, "new-provider", ""),
            (Open, "new-provider", GRANT_TOOL),
            (Grant, "enable-capability", ""),
            (Open, "enable-capability", GRANT_TOOL),
            // Removing access requires the same approval tier as granting it.
            (Grant, REMOVE_ENVIRONMENT, ""),
            (Open, REMOVE_ENVIRONMENT, GRANT_TOOL),
            (Grant, "new-seat", SEAT_CREATE_TOOL),
            (Open, "new-project", PROJECT_CREATE_TOOL),
            (Open, "new-thing", "new-thing"),
        ] {
            match admit(tier, skeleton) {
                Ok(()) => assert!(refusal.is_empty(), "{tier:?} {skeleton} must be refused"),
                Err(why) => assert!(
                    !refusal.is_empty() && why.contains(refusal),
                    "{tier:?} {skeleton}: {why}"
                ),
            }
        }
        // Every skeleton kind the registry knows is covered exactly once.
        let mut covered: Vec<&str> = OPEN_SKELETONS
            .iter()
            .chain(GRANT_SKELETONS)
            .copied()
            .chain(OWN_TOOL.iter().map(|(kind, _)| *kind))
            .collect();
        covered.sort_unstable();
        let mut known: Vec<&str> = odin_registry::SkeletonKind::ALL
            .iter()
            .map(|kind| kind.folder())
            .collect();
        known.sort_unstable();
        assert_eq!(covered, known);
    }
}
