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
//!
//! Two more change an existing declaration in place (one route, `edit`):
//! - `registry.edit` (R2, no approval): tunable keys only — pod resources, limits, lifetimes,
//!   monitoring cadence, lane budgets, context sizes, rollover. the owner's request is the yes.
//! - `registry.edit.grant` (R3, owner-decided, `preview = "card"`): any other key — who may do
//!   what (tool_refs, scopes, capabilities). The card shows every key, old and new.

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
const EDIT_TOOL: &str = "registry_edit";
const EDIT_GRANT_TOOL: &str = "registry_edit_grant";
/// The declaration kinds `registry.edit` changes in place.
pub const EDIT_KINDS: &[&str] = &[
    "workload",
    "seat",
    "lane",
    "project",
    "node",
    "context-profile",
];
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
pub const GRANT_EDITS: &[&str] = &["enable-capability", "edit-brain-role"];
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

/// One in-place change of an existing declaration.
#[derive(Clone, Debug, PartialEq)]
pub struct EditRequest {
    pub kind: String,
    pub id: String,
    /// Optional owner-approved seat lifecycle operation (create or delete).
    pub operation: Option<String>,
    /// Exact seat TOML to create or delete, bound to the approval.
    pub declaration: Option<String>,
    /// Dotted keys and their new values, in the order given.
    pub set: Vec<(String, Value)>,
    pub add: Vec<(String, Vec<String>)>,
    pub remove: Vec<(String, Vec<String>)>,
    /// Dotted keys to remove from the declaration.
    pub unset: Vec<String>,
    /// Digest-bound old values for every changed key; null means absent.
    pub expected: Vec<(String, Value)>,
    pub personal: bool,
    pub reason: String,
    /// The approval the owner gave (grant tier), for the commit message.
    pub approval: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditChange {
    pub kind: String,
    pub id: String,
    pub path: String,
    /// The changed lines, `-` old and `+` new.
    pub diff: String,
    pub published_revision: u64,
    pub commit: String,
    pub takes_effect: String,
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
    /// Changes keys of an existing declaration in place, validated and published.
    fn edit(
        &self,
        _caller: &odin_domain::SeatId,
        _request: EditRequest,
    ) -> Result<EditChange, String> {
        Err("in-place registry edits are not composed on this host".to_owned())
    }
}

/// Whether `key` of a `kind` declaration is a tunable: a size, budget, limit, lifetime or
/// cadence that changes how much, never who may do what. Every other key is a permission key
/// and needs the owner's yes; unlisted keys are permission keys, so the law fails closed.
pub fn is_tunable(kind: &str, key: &str) -> bool {
    let under = |table: &str| key.starts_with(&format!("{table}."));
    key == "description"
        || match kind {
            "workload" => {
                under("resources")
                    || under("limits")
                    || under("lifetime")
                    || matches!(
                        key,
                        "monitoring.cadence_seconds" | "monitoring.stall_seconds" | "state.storage"
                    )
            }
            "lane" => under("limits"),
            "seat" => {
                under("limits")
                    || key == "context.max_bundle_tokens"
                    || under("live.rollover")
                    || key == "live.max_sessions"
                    || key == "tools.listing_bytes"
            }
            "project" => under("review.budget") || key == "hub_refresh_seconds",
            "node" => matches!(
                key,
                "simulation_pump_seconds"
                    | "missions_view_seconds"
                    | "missions_preview_max_side"
                    | "root_plan_wake_seconds"
            ),
            "context-profile" => matches!(
                key,
                "core_tokens" | "inject_tokens" | "inject_k" | "per_turn_tokens" | "live_tokens"
            ),
            _ => false,
        }
}

/// The tier law of an edit: the open tool takes tunables only, the grant tool takes a change
/// that holds at least one permission key.
pub fn admit_edit(tier: AuthorTier, request: &EditRequest) -> Result<(), String> {
    if !EDIT_KINDS.contains(&request.kind.as_str()) {
        return Err(format!(
            "{} cannot be edited in place; the kinds are {}",
            request.kind,
            EDIT_KINDS.join(", ")
        ));
    }
    if let Some(operation) = request.operation.as_deref() {
        if tier != AuthorTier::Grant
            || request.kind != "seat"
            || !matches!(operation, "create" | "delete")
        {
            return Err("seat creation and deletion require registry_edit_grant".to_owned());
        }
        if request
            .declaration
            .as_deref()
            .is_none_or(|text| text.trim().is_empty())
            || !request.set.is_empty()
            || !request.add.is_empty()
            || !request.remove.is_empty()
            || !request.unset.is_empty()
            || !request.expected.is_empty()
            || request.personal
        {
            return Err(
                "seat lifecycle requires only operation, declaration, kind, id and reason"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    if request.declaration.is_some() {
        return Err("declaration is only for seat lifecycle operations".to_owned());
    }
    let keys: Vec<&str> = request
        .set
        .iter()
        .map(|(key, _)| key.as_str())
        .chain(request.add.iter().map(|(key, _)| key.as_str()))
        .chain(request.remove.iter().map(|(key, _)| key.as_str()))
        .chain(request.unset.iter().map(String::as_str))
        .collect();
    if keys.is_empty() {
        return Err("name at least one key to set, add, remove or unset".to_owned());
    }
    if let Some(key) = keys
        .iter()
        .find(|key| matches!(**key, "schema" | "kind" | "id"))
    {
        return Err(format!(
            "{key} is the declaration's identity and never changes"
        ));
    }
    if tier == AuthorTier::Grant {
        for key in &keys {
            if !request.expected.iter().any(|(path, _)| path == *key) {
                return Err(format!(
                    "expected must include the current value of {key} (null if absent)"
                ));
            }
        }
        if request
            .expected
            .iter()
            .any(|(path, _)| !keys.contains(&path.as_str()))
        {
            return Err("expected may only contain changed keys".to_owned());
        }
    }
    let permission: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|key| !is_tunable(&request.kind, key))
        .collect();
    match tier {
        AuthorTier::Open if !permission.is_empty() => Err(format!(
            "{} decide{} who may do what: use {EDIT_GRANT_TOOL}, which asks the owner",
            permission.join(", "),
            if permission.len() == 1 { "s" } else { "" }
        )),
        AuthorTier::Grant if permission.is_empty() => Err(format!(
            "these are tunables and need no approval: use {EDIT_TOOL}"
        )),
        _ => Ok(()),
    }
}

/// Decodes an edit call; the declared schema already bounds every field.
pub fn edit_request(arguments: &Value) -> Result<EditRequest, String> {
    let text = |field: &str| {
        arguments
            .get(field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("{field} must be a non-empty string"))
    };
    let lists = |field: &str| -> Result<Vec<(String, Vec<String>)>, String> {
        let Some(map) = arguments.get(field) else {
            return Ok(Vec::new());
        };
        map.as_object()
            .ok_or_else(|| format!("{field} must map keys to lists"))?
            .iter()
            .map(|(key, items)| {
                let items = items
                    .as_array()
                    .ok_or_else(|| format!("{field}.{key} must be a list"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| format!("{field}.{key} holds strings only"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((key.clone(), items))
            })
            .collect()
    };
    let set = match arguments.get("set") {
        None => Vec::new(),
        Some(map) => map
            .as_object()
            .ok_or("set must map keys to values")?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    };
    Ok(EditRequest {
        kind: text("kind")?,
        id: text("id")?,
        operation: arguments
            .get("operation")
            .and_then(Value::as_str)
            .map(str::to_owned),
        declaration: arguments
            .get("declaration")
            .and_then(Value::as_str)
            .map(str::to_owned),
        set,
        add: lists("add")?,
        expected: match arguments.get("expected") {
            None => Vec::new(),
            Some(map) => map
                .as_object()
                .ok_or("expected must map keys to current values")?
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        },
        remove: lists("remove")?,
        unset: match arguments.get("unset") {
            None => Vec::new(),
            Some(paths) => paths
                .as_array()
                .ok_or("unset must be a list of keys")?
                .iter()
                .map(|path| {
                    path.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "unset holds strings only".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?,
        },
        personal: arguments
            .get("personal")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reason: text("reason")?,
        approval: arguments
            .get("approvalId")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn edit_json(change: EditChange) -> Value {
    json!({
        "kind": change.kind,
        "id": change.id,
        "path": change.path,
        "diff": change.diff,
        "publishedRevision": change.published_revision,
        "commit": change.commit,
        "takesEffect": change.takes_effect,
    })
}

fn edit_tool(runtime: &Arc<HermesRuntime>, tier: AuthorTier) -> Arc<dyn HostTool> {
    let (name, label, parameters, approval) = match tier {
        AuthorTier::Open => (
            EDIT_TOOL,
            "Change a tunable of an existing declaration",
            capability_parameters!("registry.edit"),
            "Tunables only (pod resources, limits, lifetime, monitoring cadence; lane limits; \
             seat context and rollover; context-profile sizes): the owner's request is the yes, \
             so no card.",
        ),
        AuthorTier::Grant => (
            EDIT_GRANT_TOOL,
            "Change a permission or create or delete a seat",
            capability_parameters!("registry.edit.grant"),
            "Permission keys require expected current values. To create a seat, use kind seat, \
             operation create and declaration containing the complete new seat.toml. To delete, \
             use operation delete and declaration containing the exact current seat.toml. The \
             card shows the full declaration and the owner's yes applies only to those exact values; \
             references must be removed separately.",
        ),
    };
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let caller = scope.seat.ok_or_else(|| {
            HostToolError::unavailable(name, "the dispatch carries no admitted seat".to_owned())
        })?;
        let request = edit_request(&arguments)
            .and_then(|request| admit_edit(tier, &request).map(|()| request))
            .map_err(|detail| HostToolError::Arguments { tool: name, detail })?;
        route(&runtime, name)?
            .edit(&caller, request)
            .map(edit_json)
            .map_err(|reason| HostToolError::unavailable(name, reason))
    };
    Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: name.into(),
            label: label.into(),
            description: format!(
                "Changes an existing seat, lane, pod profile, project, node or context profile in \
                 place: `set` {{\"limits.pods\": 8}}, `add`/`remove` {{\"read_project_scope\": \
                 [\"example-project\"]}}, or `unset` [\"limits.pods\"]; dotted keys reach tables. \
                 The file keeps its comments and markers, the whole registry is validated, then it \
                 is committed to odin main and \
                 published. {approval} Read the object first with registry.read. A new pod takes \
                 the change at its next launch; seats and lanes after odind's next idle reload \
                 (open sessions keep theirs until they roll over or reopen)."
            )
            .into(),
            parameters,
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    ))
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
             (registry_skeleton_read remove-environment lists them) and it takes no `values`. \
             edit-brain-role replaces one brain role: `id` is the role (parse ocr transcribe \
             extract distil compile review consolidate caption embed rerank), `values` is the \
             COMPLETE new brain-role.toml (read the current one first). Engine is `lane` for chat \
             roles and `local` for parse, transcribe, embed and rerank; any other pair is refused \
             with its cause. Editing embed changes nothing live: it takes effect only at deploy, \
             and a new model, dims or space also needs a re-embed (guide 05-15).",
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
    tools.push(edit_tool(runtime, AuthorTier::Open));
    tools.push(edit_tool(runtime, AuthorTier::Grant));
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
            (Grant, "edit-brain-role", ""),
            (Open, "edit-brain-role", GRANT_TOOL),
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

    #[test]
    fn tunables_need_no_card_and_permissions_do() {
        use AuthorTier::{Grant, Open};
        let edit = |kind: &str, key: &str| EditRequest {
            kind: kind.to_owned(),
            id: "x".to_owned(),
            operation: None,
            declaration: None,
            set: vec![(key.to_owned(), json!(8))],
            add: Vec::new(),
            remove: Vec::new(),
            unset: Vec::new(),
            expected: vec![(key.to_owned(), json!(null))],
            personal: false,
            reason: "test".to_owned(),
            approval: None,
        };
        for (kind, key) in [
            ("lane", "limits.pods"),
            ("workload", "resources.memory"),
            ("workload", "lifetime.deadline_seconds"),
            ("seat", "live.rollover.max_brief_bytes"),
            ("context-profile", "inject_tokens"),
            ("project", "hub_refresh_seconds"),
            ("seat", "tools.listing_bytes"),
            ("node", "simulation_pump_seconds"),
            ("node", "missions_view_seconds"),
            ("node", "missions_preview_max_side"),
            ("node", "root_plan_wake_seconds"),
        ] {
            assert!(admit_edit(Open, &edit(kind, key)).is_ok(), "{kind} {key}");
            assert!(admit_edit(Grant, &edit(kind, key))
                .unwrap_err()
                .contains(EDIT_TOOL));
        }
        for (kind, key) in [
            ("seat", "tool_refs"),
            ("seat", "read_project_scope"),
            ("seat", "knowledge.atlas_sources"),
            ("node", "capabilities"),
            ("workload", "tools"),
            ("lane", "default_seat"),
            ("seat", "enabled"),
            ("seat", "context.consult.lane"),
            ("seat", "context.review_lane"),
        ] {
            assert!(admit_edit(Open, &edit(kind, key))
                .unwrap_err()
                .contains(EDIT_GRANT_TOOL));
            assert!(admit_edit(Grant, &edit(kind, key)).is_ok(), "{kind} {key}");
        }
        assert!(admit_edit(Grant, &edit("seat", "kind")).is_err());
        assert!(admit_edit(Open, &edit("model", "limits.pods")).is_err());
    }

    #[test]
    fn unset_is_parsed_and_admitted_like_other_changes() {
        use AuthorTier::{Grant, Open};
        let arguments = json!({
            "kind": "seat", "id": "x", "reason": "test",
            "unset": ["limits.pods"]
        });
        let mut request = edit_request(&arguments).unwrap();
        assert_eq!(request.unset, ["limits.pods"]);
        assert!(admit_edit(Open, &request).is_ok());
        assert!(admit_edit(Grant, &request).is_err());

        request.unset = vec!["tool_refs".to_owned()];
        assert!(admit_edit(Open, &request)
            .unwrap_err()
            .contains(EDIT_GRANT_TOOL));
        assert!(admit_edit(Grant, &request)
            .unwrap_err()
            .contains("expected"));
        request.expected = vec![("tool_refs".to_owned(), json!(["a"]))];
        assert!(admit_edit(Grant, &request).is_ok());
        request.expected.push(("other".to_owned(), json!(null)));
        assert!(admit_edit(Grant, &request).is_err());
        request.expected.pop();

        // Like set/add/remove, duplicate and overlapping changed paths are admitted;
        // the edit route applies the operations in order.
        request.unset.push("tool_refs".to_owned());
        request.set.push(("tool_refs".to_owned(), json!([])));
        assert!(admit_edit(Grant, &request).is_ok());
        request.unset = vec!["id".to_owned()];
        assert!(admit_edit(Grant, &request)
            .unwrap_err()
            .contains("identity"));

        request.operation = Some("delete".to_owned());
        request.declaration = Some("seat declaration".to_owned());
        request.set.clear();
        request.expected.clear();
        assert!(admit_edit(Grant, &request)
            .unwrap_err()
            .contains("lifecycle"));

        for invalid in [json!("limits.pods"), json!([1])] {
            let mut args = arguments.clone();
            args["unset"] = invalid;
            assert!(edit_request(&args).is_err());
        }
        let mut args = arguments;
        args.as_object_mut().unwrap().remove("unset");
        assert!(edit_request(&args).unwrap().unset.is_empty());
        assert!(admit_edit(Open, &edit_request(&args).unwrap()).is_err());
    }
}
