//! `odin_plan_get` — the plan of the run this session belongs to, read-only.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::Scope;
use odin_ledger::Ledger;
use serde_json::{json, Value};

use crate::host_tools::plan_set::PlanView;
use crate::host_tools::{
    lock_ledger, require_run_scope, response, HostInvocation, HostTool, HostToolError,
    RpcHostToolDefinition, ToolLoadMode,
};

/// Reads the bound run's objective, todos and revision; a run without a plan says so.
pub struct PlanGetTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

impl PlanGetTool {
    pub const NAME: &str = "odin_plan_get";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Plan Get"),
                description: Cow::Borrowed(
                    "Reads the plan of the run bound to this session: its objective, todos, revision and whether it is accepted.",
                ),
                parameters: crate::capability_parameters!("odin.plan_get"),
                hidden: false,
                load_mode: ToolLoadMode::Essential,
            },
        }
    }
}

impl HostTool for PlanGetTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        require_run_scope(Self::NAME, scope)?;
        Ok(())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let run_id = require_run_scope(Self::NAME, &invocation.scope)?;
        let ledger = lock_ledger(Self::NAME, &self.ledger)?;
        match ledger.plan(run_id)? {
            Some(plan) => response(Self::NAME, &PlanView::from_plan(&ledger, &plan)?),
            None => response(
                Self::NAME,
                &json!({"revision": 0, "todos": [], "note": "no plan yet; plan set writes one"}),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use odin_domain::Scope;
    use odin_ledger::plan::{TodoSpec, TodoStatus};
    use serde_json::json;
    use time::OffsetDateTime;

    use super::PlanGetTool;
    use crate::host_tools::fixtures::seed_local_omp_run;
    use crate::host_tools::{HostInvocation, HostTool};
    use crate::test_support::ledger;

    const RUN_ID: &str = "run:1700000000000:plan";

    #[test]
    fn reads_the_bound_runs_plan_and_says_when_there_is_none() {
        let ledger = ledger();
        let run: odin_domain::RunId = RUN_ID.parse().unwrap();
        seed_local_omp_run(&ledger, &run);
        let tool = PlanGetTool::new(Arc::clone(&ledger));
        let scope = Scope {
            run: Some(RUN_ID.parse().unwrap()),
            ..Scope::default()
        };
        let read = || {
            tool.invoke(HostInvocation {
                scope: scope.clone(),
                arguments: json!({}),
            })
            .unwrap()
        };
        assert_eq!(read()["revision"], 0);
        ledger
            .lock()
            .unwrap()
            .replace_plan(
                &run,
                "ship wave 2",
                &[TodoSpec {
                    id: "t1".parse().unwrap(),
                    title: "measure".into(),
                    status: TodoStatus::Active,
                }],
                0,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        let plan = read();
        assert_eq!(plan["objective"], "ship wave 2");
        assert_eq!(plan["todos"][0]["status"], "active");
    }
}
