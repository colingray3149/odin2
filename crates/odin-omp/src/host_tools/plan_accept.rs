//! `odin_plan_accept` — the owner accepts another session's plan from his phone or the thread.
//!
//! A seat session the owner opened himself has no owner-accepted plan until someone accepts it.
//! The coordinator names the session with the exact objective and revision it read; the
//! capability is owner-decided, so the first call asks the owner with a card of exactly those
//! values, and only his yes runs it. The run then refuses unless the plan is still that
//! revision with that objective, so a yes never accepts something other than what he saw.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use odin_domain::{RunId, Scope};
use odin_ledger::Ledger;
use serde::Deserialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::host_tools::{
    lock_ledger, response, HostInvocation, HostTool, HostToolError, RpcHostToolDefinition,
    ToolLoadMode,
};

pub struct PlanAcceptTool {
    ledger: Arc<Mutex<Ledger>>,
    definition: RpcHostToolDefinition,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlanAcceptArguments {
    session: String,
    #[serde(default)]
    revision: Option<i64>,
    #[serde(default)]
    objective: Option<String>,
    #[serde(default)]
    approval_id: Option<String>,
}

impl PlanAcceptTool {
    pub const NAME: &str = "odin_plan_accept";

    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self {
            ledger,
            definition: RpcHostToolDefinition {
                name: Cow::Borrowed(Self::NAME),
                label: Cow::Borrowed("Ask the owner to accept a session's plan"),
                description: Cow::Borrowed(
                    "When a seat session the owner opened says it needs an accepted plan: call with its \
                     session id; the answer names its plan's revision and objective, then call again \
                     with exactly those. The owner gets a card; their yes accepts that plan and \
                     the session's side effects run. A delegated worker is re-accepted by its \
                     delegator with task steer reaccept.",
                ),
                parameters: crate::capability_parameters!("odin.plan_accept"),
                hidden: false,
                load_mode: ToolLoadMode::Discoverable,
            },
        }
    }

    /// The target run, once its plan is still exactly the revision and objective named.
    fn resolve(&self, arguments: &Value) -> Result<(RunId, PlanAcceptArguments), HostToolError> {
        let invalid = |detail: String| HostToolError::Arguments {
            tool: Self::NAME,
            detail,
        };
        let arguments = PlanAcceptArguments::deserialize(arguments).map_err(|error| {
            invalid(format!("arguments violate the plan accept schema: {error}"))
        })?;
        let run = RunId::new(format!("run:live:{}", arguments.session))
            .map_err(|error| invalid(format!("session is not a session id: {error}")))?;
        let ledger = lock_ledger(Self::NAME, &self.ledger)?;
        let plan = ledger
            .plan(&run)?
            .ok_or_else(|| invalid(format!("session {} has no plan yet", arguments.session)))?;
        // Named only by session, or named stale: hand back the exact values to call with.
        if arguments.revision != Some(plan.revision)
            || arguments.objective.as_deref() != Some(plan.objective.as_str())
        {
            return Err(invalid(format!(
                "session {}'s plan is revision {} with objective {:?}; call again with exactly \
                 those to ask the owner",
                arguments.session, plan.revision, plan.objective
            )));
        }
        if ledger.plan_is_accepted(&run)? {
            return Err(invalid(format!(
                "session {}'s plan is already accepted",
                arguments.session
            )));
        }
        Ok((run, arguments))
    }
}

impl HostTool for PlanAcceptTool {
    fn definition(&self) -> &RpcHostToolDefinition {
        &self.definition
    }

    fn preflight(
        &self,
        _contract: &odin_kernel::CapabilityContract,
        _scope: &Scope,
        arguments: &Value,
    ) -> Result<(), HostToolError> {
        self.resolve(arguments).map(|_| ())
    }

    fn invoke(&self, invocation: HostInvocation) -> Result<Value, HostToolError> {
        let (run, arguments) = self.resolve(&invocation.arguments)?;
        // The approval that carried the owner's yes names the acceptance, when it fits an actor id.
        let actor = arguments
            .approval_id
            .as_deref()
            .map(|id| format!("owner-card:{id}"))
            .filter(|actor| actor.len() <= 128)
            .unwrap_or_else(|| "owner-card".to_owned());
        let revision = arguments.revision.unwrap_or_default();
        lock_ledger(Self::NAME, &self.ledger)?.accept_plan_exact(
            &run,
            revision,
            arguments.objective.as_deref().unwrap_or_default(),
            &actor,
            OffsetDateTime::now_utc(),
        )?;
        response(
            Self::NAME,
            &json!({
                "session": arguments.session,
                "revision": revision,
                "accepted": true,
                "acceptedBy": actor,
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use odin_domain::Scope;
    use serde_json::json;
    use time::OffsetDateTime;

    use super::PlanAcceptTool;
    use crate::host_tools::fixtures::seed_local_omp_run;
    use crate::host_tools::{HostInvocation, HostTool};
    use crate::test_support::ledger;

    const SESSION: &str = "00000000-0000-4000-8000-0000000000aa";

    #[test]
    fn colins_yes_accepts_exactly_the_plan_the_card_named() {
        let ledger = ledger();
        let run: odin_domain::RunId = format!("run:live:{SESSION}").parse().unwrap();
        seed_local_omp_run(&ledger, &run);
        ledger
            .lock()
            .unwrap()
            .replace_plan(&run, "tidy the README", &[], 0, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let tool = PlanAcceptTool::new(Arc::clone(&ledger));
        let call = |objective: &str| {
            tool.invoke(HostInvocation {
                scope: Scope::default(),
                arguments: json!({
                    "session": SESSION,
                    "revision": 1,
                    "objective": objective,
                    "approvalId": "approval:fixture",
                }),
            })
        };
        let stale = call("rewrite the kernel").unwrap_err().to_string();
        assert!(stale.contains("\"tidy the README\""), "{stale}");
        assert!(!ledger.lock().unwrap().plan_is_accepted(&run).unwrap());
        let accepted = call("tidy the README").unwrap();
        assert_eq!(accepted["acceptedBy"], "owner-card:approval:fixture");
        assert!(ledger.lock().unwrap().plan_is_accepted(&run).unwrap());
        assert!(call("tidy the README").is_err(), "already accepted");
    }
}
