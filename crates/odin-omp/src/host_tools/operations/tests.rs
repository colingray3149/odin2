//! Operation-dispatch tests with a shared fixture in `fixture`.

#[path = "tests/adapter_health.rs"]
mod adapter_health;
#[path = "tests/approval_lifecycle.rs"]
mod approval_lifecycle;
#[path = "tests/argument_seams.rs"]
mod argument_seams;
#[path = "tests/authority_provider.rs"]
mod authority_provider;
#[path = "tests/authorization.rs"]
mod authorization;
#[path = "tests/dispatch_brain.rs"]
mod dispatch_brain;
#[path = "tests/dispatch_core.rs"]
mod dispatch_core;
#[path = "tests/fixture.rs"]
pub(crate) mod fixture;
#[path = "tests/plan_admission.rs"]
mod plan_admission;
#[path = "tests/preflight_gate.rs"]
mod preflight_gate;
#[path = "tests/workload_publish_gate.rs"]
mod workload_publish_gate;
