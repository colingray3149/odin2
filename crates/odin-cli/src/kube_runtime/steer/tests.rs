//! Steer admission: the run's admitted control schema decides what may be written.

use super::*;

fn control() -> odin_registry::WorkloadControlToml {
    toml::from_str(
        r#"
max_bytes = 256
[schema]
type = "object"
additionalProperties = false
properties.maxCo = { type = "number", exclusiveMinimum = 0, maximum = 2 }
properties.endTime = { type = "number" }
"#,
    )
    .expect("control fixture")
}

#[test]
fn steer_refuses_a_document_outside_the_profile_schema() {
    let run = RunId::new("steer-run").expect("run id");
    let tool = "kube_workload_steer";
    let admit = |control: Option<&odin_registry::WorkloadControlToml>, document: Value| {
        admit_document(tool, &run, control, &document)
    };
    assert!(admit(Some(&control()), serde_json::json!({"maxCo": 0.5})).is_ok());
    for refused in [
        serde_json::json!({"maxCo": 5}),
        serde_json::json!({"writeNow": true}),
        serde_json::json!({"endTime": "late"}),
    ] {
        assert!(
            admit(Some(&control()), refused.clone()).is_err(),
            "{refused} must be refused"
        );
    }
    let mut small = control();
    small.max_bytes = 4;
    assert!(admit(Some(&small), serde_json::json!({"maxCo": 0.5})).is_err());
    assert!(admit(None, serde_json::json!({})).is_err());
}
