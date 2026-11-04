use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use odin_domain::knowledge::ToolSchema;
use odin_domain::{CapabilityId, Scope};
use odin_kernel::{CapabilityContract, HandlerBinding};
use serde_json::json;

use super::*;
use crate::host_tools::fixtures::{consumed_command, fixture_contract};
use crate::host_tools::operations::StaticSchemaCatalog;

/// Records every capability it runs; `compiled` answers for every id.
struct RecordingRunner {
    compiled: bool,
    ran: Mutex<Vec<String>>,
}

impl WorkflowRunner for RecordingRunner {
    fn compiled(&self, _capability: &CapabilityId) -> bool {
        self.compiled
    }

    fn preflight(
        &self,
        _capability: &CapabilityId,
        _scope: &Scope,
        _arguments: &Value,
    ) -> Result<(), HostToolError> {
        Ok(())
    }

    fn run(
        &self,
        capability: &CapabilityId,
        _scope: &Scope,
        _arguments: &Value,
        consumed: &ConsumedHostCommand,
    ) -> Result<Value, HostToolError> {
        self.ran
            .lock()
            .expect("ran")
            .push(format!("{capability}|{}", consumed.command_id()));
        Ok(json!({"done": "saved one video", "capability": capability.as_str()}))
    }

    fn plan(&self, _capability: &CapabilityId, _arguments: &Value) -> Result<String, String> {
        Ok("plan".to_owned())
    }
}

fn runner(compiled: bool) -> Arc<RecordingRunner> {
    Arc::new(RecordingRunner {
        compiled,
        ran: Mutex::new(Vec::new()),
    })
}

fn contract() -> CapabilityContract {
    let mut contract = fixture_contract();
    contract.id = CapabilityId::new("fixture.run").expect("id");
    contract.handler = HandlerBinding::Builtin {
        name: WORKFLOW_HANDLER_ID.to_owned(),
    };
    contract.evidence_extractor = HandlerBinding::Builtin {
        name: WORKFLOW_RECEIPT_ID.to_owned(),
    };
    contract
}

fn schemas() -> StaticSchemaCatalog {
    StaticSchemaCatalog::new([(
        contract().input_schema_ref,
        ToolSchema::from_value(json!({"type": "object"})).expect("schema"),
    )])
    .expect("catalog")
}

fn tool(runner: Option<Arc<RecordingRunner>>) -> WorkflowTool {
    WorkflowTool {
        binding: WorkflowBinding {
            runner: runner.map(|runner| runner as Arc<dyn WorkflowRunner>),
        },
        definition: marker_definition(WORKFLOW_HANDLER_ID),
    }
}

fn invocation() -> HostInvocation {
    HostInvocation {
        scope: Scope::default(),
        arguments: json!({"url": "a video link"}),
    }
}

#[test]
fn register_refuses_an_uncompiled_workflow() {
    let mut registry = HostToolRegistry::new();
    let error = register(
        &mut registry,
        WorkflowBinding {
            runner: Some(runner(false)),
        },
        &BTreeMap::from([(contract().id, contract())]),
        &schemas(),
    )
    .expect_err("uncompiled workflow")
    .to_string();
    assert!(
        error.contains(
            "workflow capability fixture.run has no compiled workflow; add it to its family's \
             WORKFLOWS table"
        ),
        "{error}"
    );
    let mut registry = HostToolRegistry::new();
    register(
        &mut registry,
        WorkflowBinding {
            runner: Some(runner(true)),
        },
        &BTreeMap::from([(contract().id, contract())]),
        &schemas(),
    )
    .expect("a compiled workflow registers");
}

#[test]
fn consumed_dispatch_reaches_the_runner_with_the_capability_id() {
    let runner = runner(true);
    let tool = tool(Some(Arc::clone(&runner)));
    let consumed = consumed_command("fixture.run", invocation().arguments);
    let result = tool
        .run_consumed(&contract().id, &consumed, &invocation())
        .expect("runs");
    assert_eq!(result["done"], "saved one video");
    let ran = runner.ran.lock().expect("ran").clone();
    assert_eq!(ran, [format!("fixture.run|{}", consumed.command_id())]);
    let refused = tool
        .invoke(invocation())
        .expect_err("unconsumed")
        .to_string();
    assert!(refused.contains("requires a kernel-minted prepared operation"));
}

fn receipt(output: Value) -> Result<Value, HostToolError> {
    WorkflowReceipt {
        definition: marker_definition(WORKFLOW_RECEIPT_ID),
    }
    .invoke(HostInvocation {
        scope: Scope::default(),
        arguments: json!({ "output": output }),
    })
}

#[test]
fn receipt_relays_capability_and_done() {
    let evidence = receipt(json!({
        "capability": "fixture.run",
        "done": "saved one video",
        "artifacts": [],
    }))
    .expect("receipt");
    assert_eq!(
        evidence,
        json!({"capability": "fixture.run", "done": "saved one video"})
    );
}
