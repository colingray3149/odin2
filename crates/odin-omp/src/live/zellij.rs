use odin_domain::huginn::{
    LiveError, LiveSessionId, SessionEpoch, TerminalControlLease, TerminalDelta, TerminalSeq,
    TerminalSnapshot,
};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::{broadcast, Mutex, RwLock};

const MAX_TERMINAL_BYTES: usize = 64 * 1024;
const MAX_LEASE_TTL_SECONDS: u32 = 900;
const TAIL_CAPACITY: usize = 256;

mod cli;
mod control;
mod journal;
mod screen;

pub use cli::{CapturedTerminal, ZellijCliFactory, ZellijCliPane, ZellijPane};
pub use control::TerminalAuditRecord;
pub use journal::{TerminalEventSink, TerminalReadStream, TerminalReplay, TerminalReplayItem};

struct TerminalState {
    head: TerminalSeq,
    snapshots: VecDeque<TerminalSnapshot>,
    deltas: VecDeque<TerminalDelta>,
    lease: Option<TerminalControlLease>,
}

pub struct ZellijLiveAdapter {
    session_id: LiveSessionId,
    epoch: RwLock<SessionEpoch>,
    pane: Arc<dyn ZellijPane>,
    sink: StdRwLock<Option<Arc<dyn TerminalEventSink>>>,
    state: Mutex<TerminalState>,
    /// Serializes control mutations. Held across a pane await so keystrokes
    /// stay ordered, but not the state lock.
    ops: Mutex<()>,
    tail: broadcast::Sender<TerminalReplayItem>,
    lease_path: PathBuf,
    session_root: PathBuf,
    /// Operation-id index and the open segment writer. Built at open.
    audit: std::sync::Mutex<control::AuditLog>,
}

fn limit_error(kind: &str, limit: usize) -> LiveError {
    LiveError::ResourceLimit {
        limit: format!("{kind} bytes {limit}"),
    }
}

fn invalid_terminal(error: impl std::fmt::Display) -> LiveError {
    LiveError::InvalidRequest {
        code: "invalid_terminal".to_owned(),
        message: error.to_string(),
    }
}
#[track_caller]
fn io_error(error: std::io::Error) -> LiveError {
    let location = std::panic::Location::caller();
    LiveError::Unavailable {
        code: format!(
            "zellij_adapter io at {}:{}: {error}",
            location.file(),
            location.line()
        ),
    }
}
fn unavailable() -> LiveError {
    LiveError::Unavailable {
        code: "zellij_adapter".to_owned(),
    }
}
