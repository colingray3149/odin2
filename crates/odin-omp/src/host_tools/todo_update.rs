//! `odin_todo_update` — transition one todo of the bound run's plan.
//!
//! The tool binds to the invocation scope's run, validates the strict
//! camelCase input, and delegates to the ledger's revisioned, state-machine
//! checked transition. The durable-aggregate projection is shared with
//! `odin_plan_set`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::{Scope, TodoId};
use odin_ledger::plan::TodoStatus;
use odin_ledger::Ledger;
use serde::Deserialize;
use serde_json::Value;

use crate::host_tools::plan_set::{PlanTodoStatus, PlanView};
use crate::host_tools::{
    lock_ledger, parse_unix_milliseconds, require_run_scope, response, HostInvocation, HostTool,
    HostToolError, RpcHostToolDefinition, ToolLoadMode,
};

/// Moves one todo of the bound run's plan to a new status as one revisioned
/// aggregate update.
pub struct TodoUpdateTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

impl TodoUpdateTool {
    pub const NAME: &str = "odin_todo_update";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Todo Update"),
                description: Cow::Borrowed(
                    "Move one todo of the plan bound to this session to a new status. An omitted revision means the current one; illegal transitions and unknown fields are rejected without writing.",
                ),
                parameters: parameters(),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }

    /// Shared run, argument, and timestamp decoding for preflight and invocation.
    fn resolve(
        &self,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<
        (
            odin_domain::RunId,
            TodoUpdateArguments,
            time::OffsetDateTime,
        ),
        HostToolError,
    > {
        let run_id = require_run_scope(Self::NAME, scope)?.clone();
        let mut arguments = TodoUpdateArguments::deserialize(arguments).map_err(|error| {
            HostToolError::Arguments {
                tool: Self::NAME,
                detail: format!("arguments violate the odin_todo_update schema: {error}"),
            }
        })?;
        let timestamp = match arguments.timestamp_ms {
            Some(milliseconds) => parse_unix_milliseconds(Self::NAME, milliseconds)?,
            None => time::OffsetDateTime::now_utc(),
        };
        if arguments.expected_revision.is_none() {
            let plan = lock_ledger(Self::NAME, &self.ledger)?.plan(&run_id)?;
            arguments.expected_revision = Some(plan.map_or(0, |plan| plan.revision));
        }
        Ok((run_id, arguments, timestamp))
    }
}

impl HostTool for TodoUpdateTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        // Check revision, membership, and transition validity without writing; execution revalidates.
        let (run_id, arguments, _timestamp) = self.resolve(scope, arguments)?;
        let ledger = lock_ledger(Self::NAME, &self.ledger)?;
        ledger.prepare_todo_transition(
            &run_id,
            &arguments.todo_id,
            TodoStatus::from(arguments.status),
            arguments.expected_revision.unwrap_or_default(),
        )?;
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (run_id, arguments, timestamp) =
            self.resolve(&invocation.scope, &invocation.arguments)?;

        let mut ledger = lock_ledger(Self::NAME, &self.ledger)?;
        let plan = ledger.transition_todo(
            &run_id,
            &arguments.todo_id,
            TodoStatus::from(arguments.status),
            arguments.expected_revision.unwrap_or_default(),
            timestamp,
        )?;
        response(Self::NAME, &PlanView::from_plan(&ledger, &plan)?)
    }
}

fn parameters() -> Value {
    crate::capability_parameters!("odin.todo_update")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct TodoUpdateArguments {
    todo_id: TodoId,
    status: PlanTodoStatus,
    #[serde(default)]
    expected_revision: Option<i64>,
    #[serde(default)]
    timestamp_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use odin_domain::{RunId, Scope};
    use odin_ledger::plan::{Plan, TodoSpec, TodoStatus};
    use odin_ledger::{Ledger, LedgerError};
    use serde_json::{json, Value};
    use time::OffsetDateTime;

    use super::TodoUpdateTool;
    use crate::host_tools::fixtures::seed_local_omp_run;
    use crate::host_tools::{HostInvocation, HostTool, HostToolError};
    use crate::test_support::ledger;

    const TIMESTAMP_MS: i64 = 1_700_000_000_000;
    const RUN_ID: &str = "run:1700000000000:plan";
    const TODO_ID: &str = "todo:1700000000000:one";

    fn seed_pending_plan(ledger: &Mutex<Ledger>) {
        seed_local_omp_run(ledger, &RUN_ID.parse().expect("run id"));
        ledger
            .lock()
            .expect("ledger lock")
            .replace_plan(
                &RUN_ID.parse().expect("run id"),
                "ship the bridge",
                &[TodoSpec {
                    id: TODO_ID.parse().expect("todo id"),
                    title: "reassemble frames".to_owned(),
                    status: TodoStatus::Pending,
                }],
                0,
                OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("seed instant"),
            )
            .expect("seed plan");
    }

    fn stored_plan(ledger: &Mutex<Ledger>) -> Plan {
        let run_id: RunId = RUN_ID.parse().expect("run id");
        ledger
            .lock()
            .expect("ledger lock")
            .plan(&run_id)
            .expect("plan read")
            .expect("seeded plan survives")
    }

    fn bound_scope() -> Scope {
        Scope {
            run: Some(RUN_ID.parse().expect("run id")),
            ..Scope::default()
        }
    }

    fn invocation(scope: Scope, arguments: Value) -> HostInvocation {
        HostInvocation { scope, arguments }
    }

    fn arguments(expected_revision: i64, status: &str) -> Value {
        json!({
            "todoId": TODO_ID,
            "status": status,
            "expectedRevision": expected_revision,
            "timestampMs": TIMESTAMP_MS
        })
    }

    #[test]
    fn unbound_run_scope_is_rejected_before_any_mutation() {
        let ledger = ledger();
        seed_pending_plan(&ledger);
        let tool = TodoUpdateTool::new(Arc::clone(&ledger));

        let error = tool
            .invoke(invocation(Scope::default(), arguments(1, "active")))
            .expect_err("an unbound run scope must be rejected");

        assert!(matches!(
            error,
            HostToolError::Scope {
                tool: TodoUpdateTool::NAME,
                ..
            }
        ));

        let plan = stored_plan(&ledger);
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.todos[0].status, TodoStatus::Pending);
    }

    #[test]
    fn stale_revision_is_typed_and_transition_is_not_applied() {
        let ledger = ledger();
        seed_pending_plan(&ledger);
        let tool = TodoUpdateTool::new(Arc::clone(&ledger));

        let error = tool
            .invoke(invocation(bound_scope(), arguments(7, "active")))
            .expect_err("a stale revision must be rejected");

        assert!(matches!(
            error,
            HostToolError::Ledger(LedgerError::StaleActor {
                expected_revision: 7,
                actual_revision: 1,
                ..
            })
        ));

        let plan = stored_plan(&ledger);
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.todos[0].status, TodoStatus::Pending);
    }

    #[test]
    fn legal_transition_returns_the_revised_aggregate() {
        let ledger = ledger();
        seed_pending_plan(&ledger);
        let tool = TodoUpdateTool::new(Arc::clone(&ledger));

        let revised = tool
            .invoke(invocation(bound_scope(), arguments(1, "active")))
            .expect("pending to active is legal");

        assert_eq!(revised["revision"], 2);
        assert_eq!(revised["todos"][0]["id"], TODO_ID);
        assert_eq!(revised["todos"][0]["status"], "active");
        assert_eq!(revised["objective"], "ship the bridge");

        let plan = stored_plan(&ledger);
        assert_eq!(plan.revision, 2);
        assert_eq!(plan.todos[0].status, TodoStatus::Active);
    }

    #[test]
    fn illegal_transition_is_typed_and_rolls_back() {
        let ledger = ledger();
        seed_pending_plan(&ledger);
        let tool = TodoUpdateTool::new(Arc::clone(&ledger));

        let error = tool
            .invoke(invocation(bound_scope(), arguments(1, "completed")))
            .expect_err("pending to completed is illegal");

        assert!(matches!(
            error,
            HostToolError::Ledger(LedgerError::InvalidData { .. })
        ));

        let plan = stored_plan(&ledger);
        assert_eq!(plan.revision, 1);
        assert_eq!(plan.todos[0].status, TodoStatus::Pending);
    }
}
