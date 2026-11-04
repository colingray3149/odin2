//! Workflow capabilities: one compiled Rust function per capability id, run by
//! the authority. The registry only declares the id, schemas and effect; the
//! function lives in a family's WORKFLOWS table in the workflow crates
//! and is checked to exist when odind composes.

/// The `implementation` of a workflow capability.
pub const WORKFLOW_IMPLEMENTATION: &str = "workflow";
/// The reserved handler marker every workflow capability binds.
pub const WORKFLOW_HANDLER_ID: &str = "odin_workflow.run";
/// The reserved evidence marker every workflow capability binds.
pub const WORKFLOW_RECEIPT_ID: &str = "odin_workflow.receipt";
