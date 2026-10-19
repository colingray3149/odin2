//! Delegation tool routing and receipt extraction.

use std::borrow::Cow;
use std::sync::Arc;

use odin_domain::huginn::LiveSessionId;
use odin_domain::{LaneId, ProjectId, RunId, Scope, SeatId, SessionId};
use odin_kernel::PreparedEffect;
use serde::Deserialize;
use serde_json::Value;

use crate::host_tools::{
    response, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode,
};

use super::contracts::{
    TASK_CREATE_CAPABILITY, TASK_CREATE_EVIDENCE_ID, TASK_CREATE_TOOL, TASK_PAUSE_CAPABILITY,
    TASK_PAUSE_EVIDENCE_ID, TASK_PAUSE_TOOL, TASK_READ_CAPABILITY, TASK_READ_EVIDENCE_ID,
    TASK_READ_TOOL, TASK_STEER_CAPABILITY, TASK_STEER_EVIDENCE_ID, TASK_STEER_TOOL,
};
use super::owner::TaskOwnerSlot;
use super::vocabulary::{
    TaskControl, TaskControlReport, TaskControlRequest, TaskCreateReceipt, TaskCreateRequest,
    TaskReadReport, TaskReadRequest,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskCreateArguments {
    prompt: String,
    project: ProjectId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskReadArguments {
    #[serde(rename = "childSession")]
    child_session: LiveSessionId,
    #[serde(default)]
    screen: bool,
}

fn delegation_scope(
    tool: &'static str,
    scope: &Scope,
) -> Result<(SessionId, RunId, SeatId, LaneId), HostToolError> {
    let missing = |dimension| HostToolError::Scope {
        tool,
        reason: dimension,
    };
    let seat = scope
        .seat
        .clone()
        .ok_or_else(|| missing("the invocation scope must bind a seat"))?;
    let lane = scope
        .lane
        .clone()
        .ok_or_else(|| missing("the invocation scope must bind a lane"))?;
    let run = scope
        .run
        .clone()
        .ok_or_else(|| missing("the invocation scope must bind a run"))?;
    let session = scope
        .session
        .clone()
        .ok_or_else(|| missing("the invocation scope must bind a session"))?;
    Ok((session, run, seat, lane))
}

fn require_bound_contract(effect: &PreparedEffect, capability: &str) -> Result<(), HostToolError> {
    if effect.contract().id.as_str() != capability {
        return Err(HostToolError::Catalog {
            detail: format!(
                "prepared operation {} binds {}, not {capability}",
                effect.operation_id(),
                effect.contract().id
            ),
        });
    }
    Ok(())
}

fn extractor_output(
    tool: &'static str,
    invocation: &HostInvocation,
) -> Result<Value, HostToolError> {
    invocation
        .arguments
        .get("output")
        .cloned()
        .ok_or_else(|| HostToolError::Arguments {
            tool,
            detail: "extractor input is missing".to_owned(),
        })
}

pub struct TaskCreateTool {
    owner: Arc<TaskOwnerSlot>,
    definition: RpcHostToolDefinition,
}

impl TaskCreateTool {
    pub fn new(owner: Arc<TaskOwnerSlot>) -> Result<Self, HostToolError> {
        let parameters: Value = serde_json::from_str(include_str!(
            "../../../../../schemas/capability/task.create.input.json"
        ))
        .map_err(|error| HostToolError::Catalog {
            detail: format!("{TASK_CREATE_CAPABILITY} input schema is invalid: {error}"),
        })?;
        Ok(Self {
            owner,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(TASK_CREATE_TOOL),
                label: Cow::Borrowed("Task Create"),
                description: Cow::Borrowed(
                    "Delegate one bounded governed implementation worker. The worker model, provider, lifetime, and prompt ceiling are fixed by host configuration; the project must be inside the approved scope; the calling plan must be accepted. The worker cannot delegate further.",
                ),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        })
    }
}

impl HostTool for TaskCreateTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!("{TASK_CREATE_CAPABILITY} requires a kernel-minted prepared operation"),
        })
    }

    /// Checks arguments, scope, and readiness before approval without creating a child.
    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        let (caller_session, caller_run, caller_seat, caller_lane) =
            delegation_scope(TASK_CREATE_TOOL, scope)?;
        let arguments: TaskCreateArguments =
            serde_json::from_value(arguments.clone()).map_err(|error| {
                HostToolError::Arguments {
                    tool: TASK_CREATE_TOOL,
                    detail: format!("arguments violate the task.create schema: {error}"),
                }
            })?;
        self.owner
            .owner()?
            .preflight_task(&TaskCreateRequest {
                caller_session,
                caller_run,
                caller_seat,
                caller_lane,
                project: arguments.project,
                prompt: arguments.prompt,
                title: None,
                target_seat: None,
                launch: None,
            })
            .map_err(|failure| HostToolError::Delegation {
                tool: TASK_CREATE_TOOL,
                detail: format!("{}: {}", failure.kind, failure.detail),
            })
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        require_bound_contract(effect, TASK_CREATE_CAPABILITY)?;
        let (caller_session, caller_run, caller_seat, caller_lane) =
            delegation_scope(TASK_CREATE_TOOL, &invocation.scope)?;
        let arguments: TaskCreateArguments =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: TASK_CREATE_TOOL,
                    detail: format!("arguments violate the task.create schema: {error}"),
                }
            })?;
        let receipt = self
            .owner
            .owner()?
            .create_task(TaskCreateRequest {
                caller_session,
                caller_run,
                caller_seat,
                caller_lane,
                project: arguments.project,
                prompt: arguments.prompt,
                title: None,
                target_seat: None,
                launch: None,
            })
            .map_err(|failure| {
                let detail = format!("{}: {}", failure.kind, failure.detail);
                if failure.effect_may_have_started {
                    HostToolError::Uncertain {
                        tool: TASK_CREATE_TOOL,
                        detail,
                    }
                } else {
                    HostToolError::Delegation {
                        tool: TASK_CREATE_TOOL,
                        detail,
                    }
                }
            })?;
        response(TASK_CREATE_TOOL, &receipt)
    }
}

pub struct TaskReadTool {
    owner: Arc<TaskOwnerSlot>,
    definition: RpcHostToolDefinition,
}

impl TaskReadTool {
    pub fn new(owner: Arc<TaskOwnerSlot>) -> Result<Self, HostToolError> {
        let parameters: Value = serde_json::from_str(include_str!(
            "../../../../../schemas/capability/task.read.input.json"
        ))
        .map_err(|error| HostToolError::Catalog {
            detail: format!("{TASK_READ_CAPABILITY} input schema is invalid: {error}"),
        })?;
        Ok(Self {
            owner,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(TASK_READ_TOOL),
                label: Cow::Borrowed("Task Read"),
                description: Cow::Borrowed(
                    "Read the nonblocking lifecycle truth of one delegated worker: durable phase, supervisor liveness, and the fixed configuration. Only the delegating parent may read a row; an unproven worker is never reported completed.",
                ),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        })
    }
}

impl HostTool for TaskReadTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!("{TASK_READ_CAPABILITY} requires a kernel-minted prepared operation"),
        })
    }

    /// Declared-admissibility preflight, run by the shared dispatch path
    /// before journaling: the exact scope/argument derivation
    /// `invoke_prepared` runs. `task.read` declares NO external readiness
    /// gate: it is a nonblocking R0 read over the durable link row and the
    /// supervisor's lifecycle truth, it mints and consumes nothing, and
    /// its remaining laws (row existence, parent scope, liveness
    /// reconciliation) re-prove against fresh truth at execution — the
    /// reconciliation in particular persists honest phase transitions and
    /// so can never run pre-consume.
    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        delegation_scope(TASK_READ_TOOL, scope)?;
        let _: TaskReadArguments = serde_json::from_value(arguments.clone()).map_err(|error| {
            HostToolError::Arguments {
                tool: TASK_READ_TOOL,
                detail: format!("arguments violate the task.read schema: {error}"),
            }
        })?;
        Ok(())
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        require_bound_contract(effect, TASK_READ_CAPABILITY)?;
        let (caller_session, _run, caller_seat, _lane) =
            delegation_scope(TASK_READ_TOOL, &invocation.scope)?;
        let arguments: TaskReadArguments =
            serde_json::from_value(invocation.arguments).map_err(|error| {
                HostToolError::Arguments {
                    tool: TASK_READ_TOOL,
                    detail: format!("arguments violate the task.read schema: {error}"),
                }
            })?;
        let report = self
            .owner
            .owner()?
            .read_task(TaskReadRequest {
                caller_session,
                caller_seat,
                child: arguments.child_session,
                screen: arguments.screen,
            })
            .map_err(|failure| HostToolError::Delegation {
                tool: TASK_READ_TOOL,
                detail: format!("{}: {}", failure.kind, failure.detail),
            })?;
        response(TASK_READ_TOOL, &report)
    }
}

pub(crate) static TASK_CREATE_EVIDENCE_DEFINITION: RpcHostToolDefinition = RpcHostToolDefinition {
    name: Cow::Borrowed(TASK_CREATE_EVIDENCE_ID),
    label: Cow::Borrowed("Task Create Evidence"),
    description: Cow::Borrowed(
        "Extract validated delegation evidence for one governed worker delegation.",
    ),
    parameters: Value::Null,
    hidden: true,
    load_mode: ToolLoadMode::Essential,
};

pub(crate) static TASK_READ_EVIDENCE_DEFINITION: RpcHostToolDefinition = RpcHostToolDefinition {
    name: Cow::Borrowed(TASK_READ_EVIDENCE_ID),
    label: Cow::Borrowed("Task Read Evidence"),
    description: Cow::Borrowed(
        "Extract validated lifecycle evidence for one governed worker read.",
    ),
    parameters: Value::Null,
    hidden: true,
    load_mode: ToolLoadMode::Essential,
};

/// Registered evidence extractor of `task.create`: validates the handler's
/// receipt shape and re-projects it as the durable evidence.
pub struct TaskCreateEvidenceTool;

impl HostTool for TaskCreateEvidenceTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &TASK_CREATE_EVIDENCE_DEFINITION
    }

    /// Handler output exists only after dispatch, so validation runs at extraction time.
    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let output = extractor_output(TASK_CREATE_EVIDENCE_ID, &invocation)?;
        let receipt: TaskCreateReceipt =
            serde_json::from_value(output).map_err(|error| HostToolError::Arguments {
                tool: TASK_CREATE_EVIDENCE_ID,
                detail: format!("delegation receipt is invalid: {error}"),
            })?;
        if !receipt.plan_accepted {
            return Err(HostToolError::Arguments {
                tool: TASK_CREATE_EVIDENCE_ID,
                detail: "delegation receipt does not record an inherited accepted plan".to_owned(),
            });
        }
        serde_json::to_value(&receipt).map_err(|error| HostToolError::Response {
            tool: TASK_CREATE_EVIDENCE_ID,
            detail: error.to_string(),
        })
    }
}

pub struct TaskReadEvidenceTool;

impl HostTool for TaskReadEvidenceTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &TASK_READ_EVIDENCE_DEFINITION
    }

    /// Handler output exists only after dispatch, so validation runs at extraction time.
    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let output = extractor_output(TASK_READ_EVIDENCE_ID, &invocation)?;
        let report: TaskReadReport =
            serde_json::from_value(output).map_err(|error| HostToolError::Arguments {
                tool: TASK_READ_EVIDENCE_ID,
                detail: format!("delegation lifecycle report is invalid: {error}"),
            })?;
        serde_json::to_value(&report).map_err(|error| HostToolError::Response {
            tool: TASK_READ_EVIDENCE_ID,
            detail: error.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TaskControlKind {
    /// `task.pause`: `{childSession, action: "pause" | "resume" | "stop"}`.
    Pause,
    /// `task.steer`: `{childSession, message}`.
    Steer,
}

impl TaskControlKind {
    fn capability(self) -> &'static str {
        match self {
            Self::Pause => TASK_PAUSE_CAPABILITY,
            Self::Steer => TASK_STEER_CAPABILITY,
        }
    }

    fn tool(self) -> &'static str {
        match self {
            Self::Pause => TASK_PAUSE_TOOL,
            Self::Steer => TASK_STEER_TOOL,
        }
    }

    fn parse(self, arguments: &Value) -> Result<(LiveSessionId, TaskControl), HostToolError> {
        let tool = self.tool();
        let invalid = |detail: String| HostToolError::Arguments { tool, detail };
        let field = |name: &str| {
            arguments
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(format!("{name} is required")))
        };
        let child = LiveSessionId::parse(field("childSession")?)
            .map_err(|error| invalid(format!("childSession is not a session id: {error}")))?;
        let control = match self {
            Self::Pause => match field("action")? {
                "pause" => TaskControl::Pause,
                "resume" => TaskControl::Resume,
                "stop" => TaskControl::Stop,
                other => {
                    return Err(invalid(format!(
                        "action {other:?} is not pause, resume or stop"
                    )))
                }
            },
            Self::Steer => {
                let message = field("message")?.trim();
                if message.is_empty() || message.len() > 4096 {
                    return Err(invalid("message must be 1..=4096 bytes".to_owned()));
                }
                TaskControl::Steer(message.to_owned())
            }
        };
        Ok((child, control))
    }
}

/// The listed `task_pause` / `task_steer` capability tools, under the existing
/// delegating-session, delegating-seat or escalation-target control authority.
pub struct TaskControlTool {
    owner: Arc<TaskOwnerSlot>,
    kind: TaskControlKind,
    definition: RpcHostToolDefinition,
}

impl TaskControlTool {
    pub fn new(owner: Arc<TaskOwnerSlot>, kind: TaskControlKind) -> Result<Self, HostToolError> {
        let (schema, label, description) = match kind {
            TaskControlKind::Pause => (
                include_str!("../../../../../schemas/capability/task.pause.input.json"),
                "Pause, resume or stop a task",
                "Pause a delegated worker (its thinking stops at a safe point and keeps its work), \
                 resume a paused one, or stop it for good (its session, harness and tab close). \
                 Control requires the delegating session, a session of the delegating seat, \
                 or the recorded escalation target seat. Use only this task's exact childSession. \
                 This never pauses a pod, job or service: to pause, resume, restart or stop a \
                 running pod, ask the seat that runs it to do that with its workload tools.",
            ),
            TaskControlKind::Steer => (
                include_str!("../../../../../schemas/capability/task.steer.input.json"),
                "Redirect a task",
                "Change what a delegated worker is doing. The delegating session, a later \
                 session of that seat, or the seat the worker escalated to may send it. A \
                 working worker gets the message mid-task; a paused or finished one continues \
                 with it. childSession is the session task create or the seat ask returned.",
            ),
        };
        let parameters: Value =
            serde_json::from_str(schema).map_err(|error| HostToolError::Catalog {
                detail: format!("{} input schema is invalid: {error}", kind.capability()),
            })?;
        Ok(Self {
            owner,
            kind,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(kind.tool()),
                label: Cow::Borrowed(label),
                description: Cow::Borrowed(description),
                parameters,
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        })
    }
}

impl HostTool for TaskControlTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn invoke(&self, _invocation: HostInvocation) -> Result<Value, HostToolError> {
        Err(HostToolError::Catalog {
            detail: format!(
                "{} requires a kernel-minted prepared operation",
                self.kind.capability()
            ),
        })
    }

    /// Checks scope and arguments here; authority and live state are checked at execution.
    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        delegation_scope(self.kind.tool(), scope)?;
        self.kind.parse(arguments).map(|_| ())
    }

    fn invoke_prepared(
        &self,
        effect: &PreparedEffect,
        invocation: HostInvocation,
    ) -> Result<Value, HostToolError> {
        let tool = self.kind.tool();
        require_bound_contract(effect, self.kind.capability())?;
        let (caller_session, _run, caller_seat, _lane) = delegation_scope(tool, &invocation.scope)?;
        let (child, control) = self.kind.parse(&invocation.arguments)?;
        let report = self
            .owner
            .owner()?
            .control_task(TaskControlRequest {
                caller_session,
                caller_seat,
                child,
                control,
            })
            .map_err(|failure| HostToolError::Delegation {
                tool,
                detail: format!("{}: {}", failure.kind, failure.detail),
            })?;
        response(tool, &report)
    }
}

/// Registered evidence extractor of `task.pause` / `task.steer`: validates
/// the control report and re-projects it as the durable evidence.
pub struct TaskControlEvidenceTool {
    id: &'static str,
    definition: RpcHostToolDefinition,
}

impl TaskControlEvidenceTool {
    pub fn new(kind: TaskControlKind) -> Self {
        let id = match kind {
            TaskControlKind::Pause => TASK_PAUSE_EVIDENCE_ID,
            TaskControlKind::Steer => TASK_STEER_EVIDENCE_ID,
        };
        Self {
            id,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(id),
                label: Cow::Borrowed("Task Control Evidence"),
                description: Cow::Borrowed(
                    "Extract validated evidence of one delegated worker control.",
                ),
                parameters: Value::Null,
                hidden: true,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for TaskControlEvidenceTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let id = self.id;
        let output = extractor_output(id, &invocation)?;
        let report: TaskControlReport =
            serde_json::from_value(output).map_err(|error| HostToolError::Arguments {
                tool: id,
                detail: format!("task control report is invalid: {error}"),
            })?;
        serde_json::to_value(&report).map_err(|error| HostToolError::Response {
            tool: id,
            detail: error.to_string(),
        })
    }
}
