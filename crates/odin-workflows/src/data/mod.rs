//! Data: SQL over CSV, JSON and Parquet files with DuckDB, and edits of YAML, JSON,
//! XML or TOML that keep comments, with yq. Each call works on copies in its own
//! scratch folder.

mod edit;
mod query;
#[cfg(test)]
mod tests;

use crate::{Workflow, SCRATCH_ROOT};

pub const WORKFLOWS: &[Workflow] = &[
    Workflow {
        capability: "data.edit",
        run: edit::run,
        plan: None,
        executables: &["yq", "diff"],
        roots: &[SCRATCH_ROOT],
        secrets: &[],
        endpoints: &[],
    },
    Workflow {
        capability: "data.query",
        run: query::run,
        plan: None,
        executables: &["duckdb"],
        roots: &[SCRATCH_ROOT],
        secrets: &[],
        endpoints: &[],
    },
];
