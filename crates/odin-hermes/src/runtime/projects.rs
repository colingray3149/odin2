//! Project and seat creation request parsing; the daemon route enforces creation
//! permissions, template grants, root locations, commits and publication.

use std::sync::Arc;

use odin_domain::Scope;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use serde_json::{json, Value};

use super::tools::{object_schema, parse_string, CapabilityTool};
use super::HermesRuntime;

pub const PROJECT_CREATE_TOOL: &str = "project_create";
pub const SEAT_CREATE_TOOL: &str = "seat_create";
pub const SEAT_PROPOSE_TOOL: &str = "seat_propose";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCreateRequest {
    pub project: String,
    pub description: String,
    /// `code`, `research`, `operations`, `personal`, or `scientific`.
    pub kind: String,
    /// The worker seats that work on the project.
    pub seats: Vec<String>,
    /// An existing directory under the projects directory; absent means a
    /// new directory named after the project.
    pub root: Option<String>,
    /// Which of Colin's repositories a new root clones; absent means the
    /// one named like the project, when it exists.
    pub repository: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCreated {
    pub project: String,
    pub root: String,
    pub lanes: Vec<String>,
    pub published_revision: u64,
    pub commit: String,
    /// When the project becomes usable (the daemon reloads at idle).
    pub activation: String,
}

/// One seat creation request: a new worker seat that runs and may do
/// exactly what its template seat does, on the named projects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatCreateRequest {
    pub seat: String,
    /// What the seat is for; the coordinator reads it when delegating.
    pub purpose: String,
    /// The existing worker seat whose runtime and grants it copies.
    pub template: String,
    pub projects: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatCreated {
    pub seat: String,
    pub lanes: Vec<String>,
    /// The coordinator's new delegation tool, live after the reload.
    pub ask_tool: String,
    pub published_revision: u64,
    pub commit: String,
    pub activation: String,
}

/// A temporary seat with a subset of template tools (empty means all),
/// retired after its work completes or `ttl_hours` elapses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatProposeRequest {
    pub seat: SeatCreateRequest,
    pub ttl_hours: u32,
    pub tools: Vec<String>,
}

/// The published temporary seat.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatProposed {
    pub created: SeatCreated,
    /// The capabilities it holds.
    pub tools: Vec<String>,
    /// UTC `YYYY-MM-DDTHH:MM:SSZ`.
    pub expires_at: String,
}

/// The daemon-bound creation route. `caller` is the kernel-admitted scope
/// seat of the dispatch, never a model argument.
pub trait ProjectRoute: Send + Sync {
    fn create(
        &self,
        caller: &odin_domain::SeatId,
        request: ProjectCreateRequest,
    ) -> Result<ProjectCreated, String>;

    fn create_seat(
        &self,
        caller: &odin_domain::SeatId,
        request: SeatCreateRequest,
    ) -> Result<SeatCreated, String>;

    fn propose_seat(
        &self,
        caller: &odin_domain::SeatId,
        request: SeatProposeRequest,
    ) -> Result<SeatProposed, String> {
        let _ = (caller, request);
        Err("temporary seats are not composed on this host".to_owned())
    }

    /// Every declared temporary seat with its expiry (Unix seconds).
    fn ephemeral_seats(&self) -> Vec<(String, i64)> {
        Vec::new()
    }

    /// Every declared temporary seat with its expiry and, when declared,
    /// its proposal time (Unix seconds).
    fn ephemeral_proposals(&self) -> Vec<(String, i64, Option<i64>)> {
        self.ephemeral_seats()
            .into_iter()
            .map(|(seat, expires)| (seat, expires, None))
            .collect()
    }

    /// Retires one temporary seat: the exact inverse of its proposal,
    /// committed and published. Returns (published revision, commit).
    fn retire_seat(&self, seat: &str, reason: &str) -> Result<(u64, String), String> {
        let _ = (seat, reason);
        Err("temporary seats are not composed on this host".to_owned())
    }
}

fn parse_list(
    arguments: &Value,
    key: &str,
    tool: &'static str,
) -> Result<Vec<String>, HostToolError> {
    arguments
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| HostToolError::Arguments {
            tool,
            detail: format!("{key} must be a list of ids"),
        })?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| HostToolError::Arguments {
                    tool,
                    detail: format!("every {key} entry must be a string"),
                })
        })
        .collect()
}

fn parse_seat_request(arguments: &Value) -> Result<SeatCreateRequest, HostToolError> {
    Ok(SeatCreateRequest {
        seat: parse_string(arguments, "seat", 31)?,
        purpose: parse_string(arguments, "purpose", 300)?,
        template: parse_string(arguments, "template", 64)?,
        projects: parse_list(arguments, "projects", SEAT_CREATE_TOOL)?,
    })
}

fn parse_propose_request(arguments: &Value) -> Result<SeatProposeRequest, HostToolError> {
    let ttl_hours = arguments
        .get("ttlHours")
        .and_then(Value::as_u64)
        .filter(|hours| (1..=24).contains(hours))
        .ok_or_else(|| HostToolError::Arguments {
            tool: SEAT_PROPOSE_TOOL,
            detail: "ttlHours must be a whole number of hours from 1 to 24".to_owned(),
        })?;
    let tools = match arguments.get("tools") {
        None | Some(Value::Null) => Vec::new(),
        Some(_) => parse_list(arguments, "tools", SEAT_PROPOSE_TOOL)?,
    };
    Ok(SeatProposeRequest {
        seat: SeatCreateRequest {
            seat: parse_string(arguments, "seat", 31)?,
            purpose: parse_string(arguments, "purpose", 300)?,
            template: parse_string(arguments, "template", 64)?,
            projects: parse_list(arguments, "projects", SEAT_PROPOSE_TOOL)?,
        },
        ttl_hours: u32::try_from(ttl_hours).unwrap_or(24),
        tools,
    })
}

fn parse_request(arguments: &Value) -> Result<ProjectCreateRequest, HostToolError> {
    let seats = parse_list(arguments, "seats", PROJECT_CREATE_TOOL)?;
    let optional = |key: &'static str, limit| match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => parse_string(arguments, key, limit).map(Some),
    };
    let root = optional("root", 512)?;
    let repository = optional("repository", 100)?;
    Ok(ProjectCreateRequest {
        project: parse_string(arguments, "project", 41)?,
        description: parse_string(arguments, "description", 300)?,
        kind: parse_string(arguments, "kind", 16)?,
        seats,
        root,
        repository,
    })
}

pub(super) fn project_tools(runtime: &Arc<HermesRuntime>, tools: &mut Vec<Arc<dyn HostTool>>) {
    let seat_runtime = Arc::clone(runtime);
    let runtime = Arc::clone(runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let caller = scope.seat.ok_or_else(|| HostToolError::Unavailable {
            tool: PROJECT_CREATE_TOOL,
            reason: "the dispatch carries no admitted seat".to_owned(),
        })?;
        let route = runtime
            .project_route()
            .ok_or_else(|| HostToolError::Unavailable {
                tool: PROJECT_CREATE_TOOL,
                reason: "project creation is not composed on this host".to_owned(),
            })?;
        let created = route
            .create(&caller, parse_request(&arguments)?)
            .map_err(|reason| HostToolError::Unavailable {
                tool: PROJECT_CREATE_TOOL,
                reason,
            })?;
        Ok(json!({
            "project": created.project,
            "root": created.root,
            "lanes": created.lanes,
            "publishedRevision": created.published_revision,
            "commit": created.commit,
            "activation": created.activation,
        }))
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: PROJECT_CREATE_TOOL.into(),
            label: "Create a project".into(),
            description: "Creates a project for Colin: its own repository under the \
                 projects directory, worked on by the chosen worker seats (builder or judge \
                 seats such as gungnir). If Colin already has a repository named like the \
                 project on his GitHub it is cloned (name another one of his with \
                 `repository`); only otherwise does a new empty repository start. `root` \
                 reuses an existing directory there instead. Ask him what it is for if \
                 unclear. The project is usable after a short reload; tell him that plainly."
                .into(),
            parameters: object_schema(
                PROJECT_CREATE_TOOL,
                json!({
                    "project": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
                    "description": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "kind": { "enum": ["code", "research", "operations", "personal", "scientific"] },
                    "seats": {
                        "type": "array", "minItems": 1, "maxItems": 4, "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1, "maxLength": 64 }
                    },
                    "root": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "repository": { "type": "string", "pattern": "^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$" }
                }),
                &["project", "description", "kind", "seats"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
    let runtime = Arc::clone(&seat_runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::Unavailable {
            tool: SEAT_CREATE_TOOL,
            reason,
        };
        let caller = scope
            .seat
            .ok_or_else(|| unavailable("the dispatch carries no admitted seat".to_owned()))?;
        let route = runtime
            .project_route()
            .ok_or_else(|| unavailable("seat creation is not composed on this host".to_owned()))?;
        let created = route
            .create_seat(&caller, parse_seat_request(&arguments)?)
            .map_err(unavailable)?;
        Ok(json!({
            "seat": created.seat,
            "lanes": created.lanes,
            "askTool": created.ask_tool,
            "publishedRevision": created.published_revision,
            "commit": created.commit,
            "activation": created.activation,
        }))
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: SEAT_CREATE_TOOL.into(),
            label: "Create a seat".into(),
            description: "Creates a new worker seat for Colin: a named helper for a kind of work \
                 (its purpose), which runs and may do exactly what an existing builder or judge \
                 seat does (its template, such as gungnir), on the projects he names. You can \
                 delegate to it after a short reload; tell him that plainly. Prefer an existing \
                 seat when one already fits."
                .into(),
            parameters: object_schema(
                SEAT_CREATE_TOOL,
                json!({
                    "seat": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}$" },
                    "purpose": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "template": { "type": "string", "minLength": 1, "maxLength": 64 },
                    "projects": {
                        "type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1, "maxLength": 64 }
                    }
                }),
                &["seat", "purpose", "template", "projects"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
    let runtime = Arc::clone(&seat_runtime);
    let handler = move |scope: Scope, arguments: Value| {
        let unavailable = |reason: String| HostToolError::Unavailable {
            tool: SEAT_PROPOSE_TOOL,
            reason,
        };
        let caller = scope
            .seat
            .ok_or_else(|| unavailable("the dispatch carries no admitted seat".to_owned()))?;
        let route = runtime
            .project_route()
            .ok_or_else(|| unavailable("seat creation is not composed on this host".to_owned()))?;
        let proposed = route
            .propose_seat(&caller, parse_propose_request(&arguments)?)
            .map_err(unavailable)?;
        Ok(json!({
            "seat": proposed.created.seat,
            "lanes": proposed.created.lanes,
            "askTool": proposed.created.ask_tool,
            "tools": proposed.tools,
            "expiresAt": proposed.expires_at,
            "publishedRevision": proposed.created.published_revision,
            "commit": proposed.created.commit,
            "activation": proposed.created.activation,
        }))
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: SEAT_PROPOSE_TOOL.into(),
            label: "Propose a temporary seat".into(),
            description: "Spins up a temporary helper seat for one job Colin asks for: a copy of \
                 an existing builder or judge seat (its template, such as gungnir) on the \
                 projects he names, limited to the template's tools you list (only what the \
                 job needs; omit for all of them — a helper that changes code needs \
                 capsule.eval.run to read and run anything in its clone, besides \
                 capsule.file.edit, check.run and git.patch.propose; without it every read is \
                 refused), that retires by itself when its delegated \
                 work is done or after ttlHours (1-24), whichever comes first. Delegate the job \
                 to it after the short reload; tell him plainly that it is temporary."
                .into(),
            parameters: object_schema(
                SEAT_PROPOSE_TOOL,
                json!({
                    "seat": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}$" },
                    "purpose": { "type": "string", "minLength": 1, "maxLength": 300 },
                    "template": { "type": "string", "minLength": 1, "maxLength": 64 },
                    "projects": {
                        "type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1, "maxLength": 64 }
                    },
                    "ttlHours": { "type": "integer", "minimum": 1, "maximum": 24 },
                    "tools": {
                        "type": "array", "maxItems": 32, "uniqueItems": true,
                        "items": { "type": "string", "minLength": 1, "maxLength": 128 }
                    }
                }),
                &["seat", "purpose", "template", "projects", "ttlHours"],
            ),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(handler),
    )));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_parses_with_and_without_a_root() {
        let request = parse_request(&json!({
            "project": "surtr", "description": "d", "kind": "code", "seats": ["gungnir"]
        }))
        .unwrap();
        assert_eq!(request.root, None);
        assert_eq!(request.seats, vec!["gungnir".to_owned()]);
        let request = parse_request(&json!({
            "project": "skuld", "description": "d", "kind": "scientific",
            "seats": ["gungnir", "skuld-judge"], "root": "/home/colin/valhalla/skuld"
        }))
        .unwrap();
        assert_eq!(request.root.as_deref(), Some("/home/colin/valhalla/skuld"));
        let request = parse_request(&json!({
            "project": "surtr", "description": "d", "kind": "code", "seats": ["gungnir"],
            "repository": "parsecsurtr"
        }))
        .unwrap();
        assert_eq!(request.repository.as_deref(), Some("parsecsurtr"));
        assert!(
            parse_request(&json!({ "project": "x", "description": "d", "kind": "code" })).is_err()
        );
        let seat = parse_seat_request(&json!({
            "seat": "brokkr", "purpose": "CAD scripting", "template": "gungnir",
            "projects": ["surtr", "skuld"]
        }))
        .unwrap();
        assert_eq!(seat.projects, vec!["surtr".to_owned(), "skuld".to_owned()]);
        assert!(
            parse_seat_request(&json!({ "seat": "b", "purpose": "p", "template": "g" })).is_err()
        );
        let proposed = parse_propose_request(&json!({
            "seat": "helper-a", "purpose": "one fix", "template": "gungnir",
            "projects": ["surtr"], "ttlHours": 2, "tools": ["build.run"]
        }))
        .unwrap();
        assert_eq!((proposed.ttl_hours, proposed.tools.len()), (2, 1));
        assert!(parse_propose_request(&json!({
            "seat": "helper-a", "purpose": "p", "template": "gungnir",
            "projects": ["surtr"], "ttlHours": 25
        }))
        .is_err());
    }
}
