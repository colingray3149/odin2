//! The declared `seat.ask` input schema against the payloads the host really
//! dispatches.

use odin_domain::knowledge::ToolSchema;
use odin_kernel::validate_input_arguments;
use serde_json::json;

fn ask_schema() -> ToolSchema {
    let raw = include_str!("../../../schemas/capability/seat.ask.input.json");
    ToolSchema::from_value(serde_json::from_str(raw).expect("schema json")).expect("schema")
}

/// Escalations concern the asker's own project, so the payload omits `project`.
#[test]
fn an_escalation_without_a_project_satisfies_the_declared_ask_schema() {
    let escalation = json!({
        "_delegate_to": "sinmara",
        "subject": "heat1d default BC",
        "question": "Keep Dirichlet as the default or switch to Neumann?",
        "urgency": "low",
        "options": [
            {"label": "Keep Dirichlet (recommended)", "action_ref": "keep-dirichlet"},
            {"label": "Switch to Neumann", "action_ref": "switch-to-neumann"}
        ]
    });
    validate_input_arguments(&ask_schema(), &escalation).expect("an escalation is admitted");
    let refused = validate_input_arguments(
        &ask_schema(),
        &json!({"_delegate_to": "sinmara", "question": "which?", "urgency": "low"}),
    )
    .expect_err("an ask without a subject is refused");
    assert!(
        format!("{refused:?}").contains("subject"),
        "the refusal names the missing field: {refused:?}"
    );
}
