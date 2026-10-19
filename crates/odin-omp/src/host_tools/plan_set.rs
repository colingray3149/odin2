//! `odin_plan_set` — atomically replace a run's plan aggregate.
//!
//! The tool binds to the invocation scope's run; the model never names a run.
//! Input and output are strict camelCase JSON and the ledger replacement is one
//! revisioned transaction. The durable-aggregate projection and the todo status
//! vocabulary below are shared with `odin_todo_update`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::{Scope, TodoId};
use odin_ledger::plan::{Plan, Todo, TodoSpec, TodoStatus};
use odin_ledger::{encode_utc, Ledger, LedgerResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::host_tools::{
    lock_ledger, parse_unix_milliseconds, require_run_scope, response, HostInvocation, HostTool,
    HostToolError, RpcHostToolDefinition, ToolLoadMode,
};

/// Replaces the objective and complete ordered todo set of the bound run as
/// one revisioned aggregate.
pub struct PlanSetTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

impl PlanSetTool {
    pub const NAME: &str = "odin_plan_set";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Plan Set"),
                description: Cow::Borrowed(
                    "Replace the objective and the complete ordered todo set of the run bound to this session as one revisioned aggregate. Pass the plan revision you currently observe; stale revisions, duplicate todo ids, and unknown fields are rejected without writing.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }

    /// Decodes the invocation; duplicate ids and blank titles/objectives are validated by the ledger.
    fn resolve(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<
        (
            odin_domain::RunId,
            String,
            i64,
            OffsetDateTime,
            Vec<TodoSpec>,
        ),
        HostToolError,
    > {
        let run_id = require_run_scope(Self::NAME, scope)?.clone();
        let arguments =
            PlanSetArguments::deserialize(arguments).map_err(|error| HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!("arguments violate the odin_plan_set schema: {error}"),
            })?;
        let timestamp = parse_unix_milliseconds(Self::NAME, arguments.timestamp_ms)?;
        let PlanSetArguments {
            objective,
            todos: decoded,
            expected_revision,
            ..
        } = arguments;
        let todos = decoded
            .into_iter()
            .map(|todo| TodoSpec {
                id: todo.id,
                title: todo.title,
                status: todo.status.into(),
            })
            .collect();
        Ok((run_id, objective, expected_revision, timestamp, todos))
    }
}

impl HostTool for PlanSetTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Check replacement validity and revision without writing; replacement revalidates.
        let (run_id, objective, expected_revision, _timestamp, todos) =
            self.resolve(scope, arguments)?;
        let ledger = lock_ledger(Self::NAME, &self.ledger)?;
        ledger.prepare_plan_replace(&run_id, &objective, &todos, expected_revision)?;
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (run_id, objective, expected_revision, timestamp, todos) =
            self.resolve(&invocation.scope, &invocation.arguments)?;

        let plan = {
            let mut ledger = lock_ledger(Self::NAME, &self.ledger)?;
            ledger.replace_plan(&run_id, &objective, &todos, expected_revision, timestamp)?
        };
        response(Self::NAME, &PlanView::from_plan(&plan)?)
    }
}

fn parameters() -> Value {
    json!({
        "type": "object",
        "properties": {
            "objective": { "type": "string" },
            "todos": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string", "minLength": 1 },
                        "title": { "type": "string", "minLength": 1 },
                        "status": {
                            "enum": ["pending", "active", "blocked", "completed", "cancelled"]
                        }
                    },
                    "required": ["id", "title", "status"],
                    "additionalProperties": false
                }
            },
            "expectedRevision": { "type": "integer", "minimum": 0 },
            "timestampMs": { "type": "integer" }
        },
        "required": ["objective", "todos", "expectedRevision", "timestampMs"],
        "additionalProperties": false
    })
}

/// Model-facing todo status vocabulary, shared by the two plan tools. The
/// strings match the ledger's todo state machine exactly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PlanTodoStatus {
    Pending,
    Active,
    Blocked,
    Completed,
    Cancelled,
}

impl From<PlanTodoStatus> for TodoStatus {
    fn from(status: PlanTodoStatus) -> Self {
        match status {
            PlanTodoStatus::Pending => Self::Pending,
            PlanTodoStatus::Active => Self::Active,
            PlanTodoStatus::Blocked => Self::Blocked,
            PlanTodoStatus::Completed => Self::Completed,
            PlanTodoStatus::Cancelled => Self::Cancelled,
        }
    }
}

impl From<TodoStatus> for PlanTodoStatus {
    fn from(status: TodoStatus) -> Self {
        match status {
            TodoStatus::Pending => Self::Pending,
            TodoStatus::Active => Self::Active,
            TodoStatus::Blocked => Self::Blocked,
            TodoStatus::Completed => Self::Completed,
            TodoStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// The durable plan aggregate projected as model-facing camelCase JSON;
/// timestamps are explicit UTC RFC3339 strings.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlanView {
    run_id: odin_domain::RunId,
    revision: i64,
    objective: String,
    todos: Vec<TodoView>,
    created_at: String,
    updated_at: String,
}

impl PlanView {
    /// Projects the durable aggregate; encoding the UTC timestamps is fallible.
    pub(crate) fn from_plan(plan: &Plan) -> LedgerResult<Self> {
        Ok(Self {
            run_id: plan.run_id.clone(),
            revision: plan.revision,
            objective: plan.objective.clone(),
            todos: plan
                .todos
                .iter()
                .map(TodoView::from_todo)
                .collect::<Result<Vec<_>, _>>()?,
            created_at: encode_utc(plan.created_at)?,
            updated_at: encode_utc(plan.updated_at)?,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TodoView {
    id: TodoId,
    ordinal: i64,
    title: String,
    status: PlanTodoStatus,
    updated_at: String,
}

impl TodoView {
    fn from_todo(todo: &Todo) -> LedgerResult<Self> {
        Ok(Self {
            id: todo.id.clone(),
            ordinal: todo.ordinal,
            title: todo.title.clone(),
            status: todo.status.into(),
            updated_at: encode_utc(todo.updated_at)?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlanSetArguments {
    objective: String,
    todos: Vec<TodoArguments>,
    expected_revision: i64,
    timestamp_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TodoArguments {
    id: TodoId,
    title: String,
    status: PlanTodoStatus,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use odin_domain::{RunId, Scope};
    use odin_ledger::{Ledger, LedgerError};
    use serde_json::{json, Value};

    use super::PlanSetTool;
    use crate::host_tools::fixtures::{fixture_contract, seed_local_omp_run};
    use crate::host_tools::{HostInvocation, HostTool, HostToolError};
    use crate::test_support::ledger;

    const TIMESTAMP_MS: i64 = 1_700_000_000_000;
    const RUN_ID: &str = "run:1700000000000:plan";

    fn bound_scope() -> Scope {
        Scope {
            run: Some(RUN_ID.parse().expect("run id")),
            ..Scope::default()
        }
    }

    fn invocation(scope: Scope, arguments: Value) -> HostInvocation {
        HostInvocation { scope, arguments }
    }

    fn arguments(expected_revision: i64, objective: &str) -> Value {
        json!({
            "objective": objective,
            "todos": [
                {
                    "id": "todo:1700000000000:one",
                    "title": "reassemble frames",
                    "status": "pending"
                },
                {
                    "id": "todo:1700000000000:two",
                    "title": "open the ledger",
                    "status": "active"
                }
            ],
            "expectedRevision": expected_revision,
            "timestampMs": TIMESTAMP_MS
        })
    }

    fn stored_plan(ledger: &Mutex<Ledger>) -> Option<odin_ledger::plan::Plan> {
        let run_id: RunId = RUN_ID.parse().expect("run id");
        ledger
            .lock()
            .expect("ledger lock")
            .plan(&run_id)
            .expect("plan read")
    }

    #[test]
    fn unbound_run_scope_is_rejected_before_any_mutation() {
        let ledger = ledger();
        let tool = PlanSetTool::new(Arc::clone(&ledger));

        let error = tool
            .invoke(invocation(
                Scope::default(),
                arguments(0, "first objective"),
            ))
            .expect_err("an unbound run scope must be rejected");

        assert!(matches!(
            error,
            HostToolError::Scope {
                tool: PlanSetTool::NAME,
                ..
            }
        ));
        assert!(stored_plan(&ledger).is_none());
    }

    #[test]
    fn stale_retry_is_typed_and_never_overwrites() {
        let ledger = ledger();
        seed_local_omp_run(&ledger, &RUN_ID.parse().expect("run id"));
        let tool = PlanSetTool::new(Arc::clone(&ledger));
        let scope = bound_scope();

        let created = tool
            .invoke(invocation(scope.clone(), arguments(0, "first objective")))
            .expect("revision zero creates the plan");
        assert_eq!(created["revision"], 1);
        assert_eq!(created["todos"].as_array().expect("todos array").len(), 2);

        let retried = tool
            .invoke(invocation(scope, arguments(0, "overwriting objective")))
            .expect_err("a retried revision-zero write is stale");

        assert!(matches!(
            retried,
            HostToolError::Ledger(LedgerError::StaleActor {
                expected_revision: 0,
                actual_revision: 1,
                ..
            })
        ));

        let plan = stored_plan(&ledger).expect("plan survives the stale retry");
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.objective, "first objective");
    }

    #[test]
    fn replacement_returns_the_durable_aggregate() {
        let ledger = ledger();
        seed_local_omp_run(&ledger, &RUN_ID.parse().expect("run id"));
        let tool = PlanSetTool::new(Arc::clone(&ledger));
        let scope = bound_scope();

        tool.invoke(invocation(scope.clone(), arguments(0, "first objective")))
            .expect("creation succeeds");

        let replaced = tool
            .invoke(invocation(scope, arguments(1, "second objective")))
            .expect("legal replacement succeeds");

        assert_eq!(replaced["runId"], RUN_ID);
        assert_eq!(replaced["revision"], 2);
        assert_eq!(replaced["objective"], "second objective");
        assert_eq!(replaced["todos"][0]["id"], "todo:1700000000000:one");
        assert_eq!(replaced["todos"][0]["status"], "pending");
        assert_eq!(replaced["todos"][1]["ordinal"], 1);
        assert_eq!(replaced["todos"][1]["status"], "active");
        assert!(replaced["createdAt"]
            .as_str()
            .expect("rfc3339")
            .contains("2023"));
    }

    #[test]
    fn unknown_fields_are_rejected_before_mutation() {
        let ledger = ledger();
        let tool = PlanSetTool::new(Arc::clone(&ledger));

        let mut smuggled = arguments(0, "first objective");
        smuggled["run"] = json!(RUN_ID);
        let error = tool
            .invoke(invocation(bound_scope(), smuggled))
            .expect_err("unknown fields must never smuggle a run binding");

        assert!(matches!(
            error,
            HostToolError::Arguments {
                tool: PlanSetTool::NAME,
                ..
            }
        ));
        assert!(stored_plan(&ledger).is_none());
    }

    #[test]
    fn duplicate_todo_ids_are_rejected_before_mutation() {
        let ledger = ledger();
        let tool = PlanSetTool::new(Arc::clone(&ledger));

        let mut duplicated = arguments(0, "first objective");
        duplicated["todos"][1]["id"] = json!("todo:1700000000000:one");
        let error = tool
            .invoke(invocation(bound_scope(), duplicated))
            .expect_err("duplicate todo ids must be rejected before the ledger is touched");

        // Duplicate-id validation preserves the ledger's typed error.
        assert!(matches!(
            error,
            HostToolError::Ledger(LedgerError::InvalidData { .. })
        ));
        assert!(stored_plan(&ledger).is_none());
    }

    #[test]
    fn preflight_refuses_duplicate_ids_and_stale_revision_before_any_write() {
        let ledger = ledger();
        let tool = PlanSetTool::new(ledger.clone());
        let contract = fixture_contract();
        let duplicate = json!({
            "objective": "ship",
            "todos": [
                {"id": "todo:1700000000000:one", "title": "one", "status": "pending"},
                {"id": "todo:1700000000000:one", "title": "again", "status": "pending"}
            ],
            "expectedRevision": 0,
            "timestampMs": TIMESTAMP_MS
        });
        let error = tool
            .preflight(&contract, &bound_scope(), &duplicate)
            .expect_err("a duplicate todo id refuses preflight");
        assert!(
            matches!(
                error,
                HostToolError::Ledger(LedgerError::InvalidData { .. })
            ),
            "the ledger validator owns the duplicate-id law: {error:?}"
        );
        assert!(
            stored_plan(&ledger).is_none(),
            "a refused preflight never writes the plan"
        );

        let run_id: RunId = RUN_ID.parse().expect("run id");
        seed_local_omp_run(&ledger, &run_id);
        ledger
            .lock()
            .expect("ledger lock")
            .replace_plan(
                &run_id,
                "ship",
                &[odin_ledger::plan::TodoSpec {
                    id: odin_domain::TodoId::new("todo:1700000000000:one").expect("todo id"),
                    title: "one".to_owned(),
                    status: odin_ledger::plan::TodoStatus::Pending,
                }],
                0,
                time::OffsetDateTime::UNIX_EPOCH,
            )
            .expect("seed one-revision plan");
        let stale = arguments(0, "ship");
        let error = tool
            .preflight(&contract, &bound_scope(), &stale)
            .expect_err("a stale observed revision refuses preflight");
        assert!(
            matches!(error, HostToolError::Ledger(LedgerError::StaleActor { .. })),
            "the stale observation surfaces the ledger's StaleActor variant: {error:?}"
        );
    }
}
