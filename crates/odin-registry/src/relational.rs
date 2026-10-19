//! Validate relations between registry declarations.

mod capabilities;
mod catalog;
mod containers;
mod context;
#[cfg(test)]
mod fixtures;
mod graph;
mod migration;
mod paths;
mod refs;
mod relations;
mod seats;
mod workloads;

pub use context::{declared_admitted_binding, AdmittedBinding, RelationContext};
pub use migration::{migration_inventory_findings, MigrationRecord, MIGRATION_REGISTRY};
pub(crate) use paths::{ignored, sorted_paths};
pub use relations::validate;
