//! Compiles conversation-supplied skeleton values, commits and publishes through
//! the same transaction as project, seat and routine authoring.
//!
//! Three capabilities, one route:
//! - `registry.skeleton.read` (R0): a skeleton's variables, to fill one.
//! - `registry.author` (R2, no approval): kinds that add no authority — a
//!   lane, a container alert or surface, and a watchdog on a pod profile
//!   (`new-alert` with `workload` instead of `container`).
//! - `registry.author.grant` (R3, Colin approves): kinds that grant or
//!   reach — capability, provider, host, node, slice, container,
//!   environment, harness — and `remove-environment`, the removal of one
//!   declared environment: the access change its creation asks Colin for,
//!   in reverse.
//!
//! Projects, seats and pod profiles keep their own bounded tools.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
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
    "new-capability",
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
/// Colin for, in reverse.
pub const GRANT_REMOVALS: &[&str] = &[REMOVE_ENVIRONMENT];
/// Skeletons with their own bounded tool.
const OWN_TOOL: &[(&str, &str)] = &[
    ("new-project", "project_create"),
    ("new-seat", "seat_create"),
    ("new-workload", "workload_draft"),
];

/// Which authoring capability a dispatch came through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorTier {
    /// `registry.author`: adds no authority.
    Open,
    /// `registry.author.grant`: Colin approved the exact request.
    Grant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorRequest {
    pub skeleton: String,
    pub id: String,
    /// The skeleton's variables as TOML (`project = "surtr"` lines);
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
            "{skeleton} grants or reaches something: use {GRANT_TOOL}, which asks Colin"
        )),
        AuthorTier::Grant
            if GRANT_SKELETONS.contains(&skeleton)
                || GRANT_EDITS.contains(&skeleton)
                || GRANT_REMOVALS.contains(&skeleton) =>
        {
            Ok(())
        }
        AuthorTier::Open if GRANT_EDITS.contains(&skeleton) => Err(format!(
            "{skeleton} grants something: use {GRANT_TOOL}, which asks Colin"
        )),
        AuthorTier::Open if GRANT_REMOVALS.contains(&skeleton) => Err(format!(
            "{skeleton} removes declared access: use {GRANT_TOOL}, which asks Colin"
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

/// Approval retries must accept `approvalId`; fills require `values`, removals omit it.
/// Put `allOf`/`oneOf` at the schema root, not in `properties`. Keep optional approval
/// constraints at the root because the model boundary makes properties nullable only there.
fn parameters(tier: AuthorTier, kinds: &[&str]) -> Value {
    let (tool, required): (&'static str, &[&str]) = match tier {
        AuthorTier::Open => (AUTHOR_TOOL, &["skeleton", "id", "values"]),
        AuthorTier::Grant => (GRANT_TOOL, &["skeleton", "id"]),
    };
    let id = json!({ "type": "string", "minLength": 1, "maxLength": 64 });
    let values = json!({ "type": "string", "minLength": 1, "maxLength": 8192 });
    let approval = || json!({ "type": "string", "minLength": 1, "maxLength": 128 });
    let mut properties = json!({
        "skeleton": { "enum": if tier == AuthorTier::Grant {
            kinds
                .iter()
                .chain(GRANT_EDITS)
                .chain(GRANT_REMOVALS)
                .copied()
                .collect::<Vec<&str>>()
        } else {
            kinds.to_owned()
        } },
        "id": id,
        "values": values,
    });
    if tier == AuthorTier::Grant {
        properties["approvalId"] = approval();
    }
    let mut schema = object_schema(tool, properties, required);
    if tier == AuthorTier::Grant {
        let fills: Vec<&str> = kinds.iter().chain(GRANT_EDITS).copied().collect();
        schema["allOf"] = json!([{ "oneOf": [
            {
                "properties": {
                    "skeleton": { "enum": fills },
                },
                "required": ["skeleton", "id", "values"],
            },
            {
                "properties": {
                    "skeleton": { "enum": GRANT_REMOVALS },
                },
                "required": ["skeleton", "id"],
            },
        ] }]);
    }
    schema
}

fn author_tool(runtime: &Arc<HermesRuntime>, tier: AuthorTier) -> Arc<dyn HostTool> {
    let (name, label, kinds, approval) = match tier {
        AuthorTier::Open => (
            AUTHOR_TOOL,
            "Add a lane, alert or surface",
            OPEN_SKELETONS,
            "Adds no authority, so no approval: a lane for a project, an alert or a status \
             surface on a container, or a watchdog on a pod profile (new-alert with \
             `workload = \"<profile>\"` instead of `container`; it watches pods launched from \
             then on and after odind's next idle reload).",
        ),
        AuthorTier::Grant => (
            GRANT_TOOL,
            "Add a capability, provider, host, node, slice, container, environment or harness, \
             remove a declared environment, or turn on a capability that is off",
            GRANT_SKELETONS,
            "These grant or reach something, so Colin approves the exact request first. \
             enable-capability turns on a declared capability that is off and grants it to one \
             seat: `id` is the capability (e.g. web.search), `values` is `seat = \"<seat>\"`; \
             registry_skeleton_read enable-capability lists the capabilities that are off. \
             remove-environment removes one declared environment: `id` is the environment id \
             (registry_skeleton_read remove-environment lists them) and it takes no `values`.",
        ),
    };
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::Unavailable { tool: name, reason };
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
                 holds them as TOML lines, e.g. `project = \"surtr\"` / `seats = [\"gungnir\"]` \
                 / `observation = {{ channel = \"events\" }}`. `id` is the new object's id \
                 (for new-alert / new-surface: the alert or surface id). A refusal names the \
                 field to fix."
            )
            .into(),
            parameters: parameters(tier, kinds),
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
    let all: Vec<&str> = OPEN_SKELETONS
        .iter()
        .chain(GRANT_SKELETONS)
        .chain(GRANT_EDITS)
        .chain(GRANT_REMOVALS)
        .copied()
        .collect();
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: READ_TOOL.into(),
            label: "Read a registry skeleton".into(),
            description: "The variables one registry skeleton takes (name, type, whether \
                 required, meaning) — read it before registry_author or registry_author_grant."
                .into(),
            parameters: object_schema(
                READ_TOOL,
                json!({ "skeleton": { "enum": all } }),
                &["skeleton"],
            ),
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
        for kind in OPEN_SKELETONS {
            assert!(admit(AuthorTier::Open, kind).is_ok(), "{kind}");
            assert!(admit(AuthorTier::Grant, kind).is_err(), "{kind}");
        }
        for kind in GRANT_SKELETONS {
            assert!(admit(AuthorTier::Grant, kind).is_ok(), "{kind}");
            let refused = admit(AuthorTier::Open, kind).unwrap_err();
            assert!(refused.contains(GRANT_TOOL), "{refused}");
        }
        for kind in GRANT_EDITS {
            assert!(admit(AuthorTier::Grant, kind).is_ok(), "{kind}");
            let refused = admit(AuthorTier::Open, kind).unwrap_err();
            assert!(refused.contains(GRANT_TOOL), "{refused}");
        }
        // Removing access requires the same approval tier as granting it.
        for kind in GRANT_REMOVALS {
            assert!(admit(AuthorTier::Grant, kind).is_ok(), "{kind}");
            let refused = admit(AuthorTier::Open, kind).unwrap_err();
            assert!(refused.contains(GRANT_TOOL), "{refused}");
        }
        let pointed = admit(AuthorTier::Grant, "new-seat").unwrap_err();
        assert!(pointed.contains("seat_create"), "{pointed}");
        assert!(admit(AuthorTier::Open, "new-thing").is_err());
        assert!(admit(AuthorTier::Open, "remove-environment").is_err());
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
