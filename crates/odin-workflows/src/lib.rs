//! Kernel workflows: one compiled function per workflow capability. A workflow runs
//! its tools in bwrap through the authority's registered runner, maps every failure
//! to one sentence naming the cause, and returns `done`, a sentence saying exactly
//! what happened.

pub mod args;
#[cfg(test)]
mod bench;
pub mod cause;
pub mod config;
mod ctx;
pub mod desk;
pub mod ffmpeg;
pub mod http;
pub mod local_models;
pub mod paths;
pub mod quarantine;
pub mod sandbox;
pub mod testing;
pub mod time;

// Non-personal families, each owned by one lane.
pub mod data;
pub mod docs;
pub mod world;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;

pub use ctx::{Ctx, OdinFacts, Secret, SCRATCH_ROOT};

/// A workflow's effect: reads the call and arguments, returns `{"done": …}`.
pub type Run = fn(&Ctx, &Call, &Value) -> Result<Value, Failure>;
/// A read-only approval preview and its file-identity prerequisite.
#[derive(Clone, Copy)]
pub struct Plan {
    pub preview: fn(&Ctx, &Call, &Value) -> Result<String, Failure>,
    /// Missing intake SHA-256 is discovered before approval, without other planning IO.
    pub intake_sha256: bool,
}

/// Artifacts one result may list (`"artifacts": [path]`).
pub const MAX_ARTIFACTS: usize = 8;
/// Previews one result may list (`"preview": [path]`).
pub const MAX_PREVIEWS: usize = 4;

/// One workflow capability: its registry id, its function, and what it needs.
pub struct Workflow {
    pub capability: &'static str,
    pub run: Run,
    /// Read-only approval preview for capabilities declaring `preview = "plan"`; None elsewhere.
    pub plan: Option<Plan>,
    /// Keys of services.odin.tools.executables this workflow runs.
    pub executables: &'static [&'static str],
    /// Keys of services.odin.tools.roots it reads or writes.
    pub roots: &'static [&'static str],
    /// Keys of services.odin.tools.secrets it reads.
    pub secrets: &'static [&'static str],
    /// Keys of services.odin.tools.endpoints it calls.
    pub endpoints: &'static [&'static str],
}

/// Non-personal families, each a `WORKFLOWS: &[Workflow]` slice owned by one lane.
pub const FAMILIES: &[&[Workflow]] = &[docs::WORKFLOWS, data::WORKFLOWS, world::WORKFLOWS];

/// Per call: the kernel command id (idempotency key), the calling seat, the
/// owner's time zone and the staged input files.
#[derive(Clone, Debug, Default)]
pub struct Call {
    /// Kernel command id: the idempotency key and the per-call scratch folder name.
    pub key: String,
    pub seat: String,
    /// The owner's current IANA time zone, for due times and "today"; `UTC` when unknown.
    pub tz: String,
    /// Staged input files, read-only to the workflow, in argument order.
    pub files: Vec<PathBuf>,
}

/// Why a workflow did not run or did not finish, in one sentence.
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct Failure {
    pub kind: FailureKind,
    pub cause: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// The arguments name something that does not exist or is not allowed.
    Arguments,
    /// A declaration, service or file the workflow needs is missing.
    Unavailable,
    /// A tool or service ran and failed.
    Upstream,
    /// The effect may have happened; its end was not observed.
    Uncertain,
}

impl Failure {
    pub fn arguments(cause: impl Into<String>) -> Self {
        Self::of(FailureKind::Arguments, cause)
    }

    pub fn unavailable(cause: impl Into<String>) -> Self {
        Self::of(FailureKind::Unavailable, cause)
    }

    pub fn upstream(cause: impl Into<String>) -> Self {
        Self::of(FailureKind::Upstream, cause)
    }

    pub fn uncertain(cause: impl Into<String>) -> Self {
        Self::of(FailureKind::Uncertain, cause)
    }

    fn of(kind: FailureKind, cause: impl Into<String>) -> Self {
        Self {
            kind,
            cause: cause.into(),
        }
    }
}

/// Every compiled workflow by capability id, over the one shared `Ctx`.
pub struct Catalog {
    by_id: BTreeMap<&'static str, &'static Workflow>,
    ctx: Ctx,
}

impl Catalog {
    /// Fails naming a capability id listed twice.
    pub fn new(families: &[&'static [Workflow]], ctx: Ctx) -> Result<Self, String> {
        let mut by_id = BTreeMap::new();
        for workflow in families.iter().flat_map(|family| family.iter()) {
            if by_id.insert(workflow.capability, workflow).is_some() {
                return Err(format!(
                    "workflow capability {} is listed twice in the WORKFLOWS tables",
                    workflow.capability
                ));
            }
        }
        Ok(Self { by_id, ctx })
    }

    pub fn ids(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_id.keys().copied()
    }

    pub fn compiled(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    pub fn workflow(&self, id: &str) -> Option<&'static Workflow> {
        self.by_id.get(id).copied()
    }

    pub fn ctx(&self) -> &Ctx {
        &self.ctx
    }

    /// Composes the owner's desktop into the shared context.
    pub fn with_desk(mut self, desk: Arc<dyn desk::Desk>) -> Self {
        self.ctx = self.ctx.with_desk(desk);
        self
    }

    /// Read-only: every declaration the workflow names exists. A missing one
    /// fails naming the key and where it is declared.
    pub fn preflight(&self, id: &str) -> Result<(), Failure> {
        let workflow = self.get(id)?;
        if !workflow.executables.is_empty() {
            self.ctx.bwrap()?;
        }
        for key in workflow.executables {
            self.ctx.exe(key)?;
        }
        for key in workflow.roots {
            self.ctx.root(key)?;
        }
        for key in workflow.secrets {
            self.ctx.secret_path(key)?;
        }
        for key in workflow.endpoints {
            self.ctx.endpoint(key)?;
        }
        Ok(())
    }

    /// Runs the workflow and checks its result is an object with a `done` line.
    pub fn run(&self, id: &str, call: &Call, args: &Value) -> Result<Value, Failure> {
        let result = (self.get(id)?.run)(&self.ctx, call, args)?;
        let done = result.get("done").and_then(Value::as_str).unwrap_or("");
        if done.trim().is_empty() {
            return Err(Failure::upstream(format!("{id} returned no done line")));
        }
        for (field, limit) in [("artifacts", MAX_ARTIFACTS), ("preview", MAX_PREVIEWS)] {
            let listed = result
                .get(field)
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if listed > limit {
                return Err(Failure::upstream(format!(
                    "{id} listed {listed} {field}; a result carries at most {limit}"
                )));
            }
        }
        Ok(result)
    }

    /// The workflow's read-only plan of the exact effect.
    pub fn plan(&self, id: &str, call: &Call, args: &Value) -> Result<String, Failure> {
        let plan = self.get(id)?.plan.ok_or_else(|| {
            Failure::unavailable(format!(
                "{id} has no plan; its family's WORKFLOWS entry sets plan: Some(..)"
            ))
        })?;
        (plan.preview)(&self.ctx, call, args)
    }

    fn get(&self, id: &str) -> Result<&'static Workflow, Failure> {
        self.workflow(id).ok_or_else(|| {
            Failure::unavailable(format!(
                "no compiled workflow serves {id}; add it to its family's WORKFLOWS table"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::ctx_for;

    fn empty(_: &Ctx, _: &Call, _: &Value) -> Result<Value, Failure> {
        Ok(json!({}))
    }

    const FIXTURE: &[Workflow] = &[Workflow {
        capability: "data.ping",
        run: empty,
        plan: None,
        executables: &["yt-dlp"],
        roots: &[],
        secrets: &[],
        endpoints: &[],
    }];

    fn catalog(dir: &std::path::Path) -> Catalog {
        Catalog::new(&[FIXTURE], ctx_for(dir, &[], &[], &[], &[])).expect("catalog")
    }

    #[test]
    fn run_requires_a_done_line() {
        let dir = tempfile::tempdir().expect("dir");
        let failure = catalog(dir.path())
            .run("data.ping", &Call::default(), &json!({}))
            .expect_err("no done");
        assert_eq!(failure.kind, FailureKind::Upstream);
        assert_eq!(failure.cause, "data.ping returned no done line");
    }

    #[test]
    fn preflight_names_the_missing_declaration() {
        let dir = tempfile::tempdir().expect("dir");
        let failure = catalog(dir.path())
            .preflight("data.ping")
            .expect_err("undeclared");
        assert_eq!(failure.kind, FailureKind::Unavailable);
        assert_eq!(
            failure.cause,
            "the yt-dlp executable is not declared in services.odin.tools.executables"
        );
    }
}
