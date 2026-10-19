use std::io;
use std::path::PathBuf;

#[cfg(test)]
use odin_domain::CommandId;
use odin_ledger::LedgerError;
use serde::Serialize;
use thiserror::Error;

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct CheckRequest {
    /// Active file of the published registry `SnapshotStore`; the only
    /// registry source a production controller may consume.
    pub registry_snapshot: PathBuf,
    pub state_root: PathBuf,
    pub node: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckReport {
    pub schema: String,
    pub node: String,
    pub authoritative_node: String,
    /// Whether this node opened as the snapshot's authoritative node. The
    /// posture is derived from the kernel-verified published snapshot
    /// relation, never from daemon configuration.
    pub authoritative: bool,
    pub restart_count: u64,
    pub materialized_rows: u64,
    pub stopped: bool,
    pub ledger_path: PathBuf,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    pub command_id: CommandId,
    pub inserted: bool,
    pub audit_sequence: Option<i64>,
}

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("controller ledger operation failed: {0}")]
    Ledger(#[from] LedgerError),
    #[error("controller I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("controller JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("controller registry is invalid: {0}")]
    Registry(String),
    #[error("controller data is invalid: {0}")]
    InvalidData(String),
    #[error("local node {local:?} is not authoritative; registry authority is {authoritative:?}")]
    AuthorityMismatch {
        local: String,
        authoritative: String,
    },
    #[error("follower node {local:?} cannot {operation}; registry authority is {authoritative:?}")]
    FollowerRefusal {
        local: String,
        authoritative: String,
        operation: &'static str,
    },
    #[error("controller STOP requested at {0}")]
    Stopped(PathBuf),
}
