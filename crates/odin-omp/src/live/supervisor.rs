use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::huginn::{LiveSessionId, LiveSessionSummary};
use odin_domain::SeatId;
use tokio::sync::{Mutex, RwLock};

use super::ledger::LiveLedger;
use super::session_actor::SessionActorHandle;

mod admission;
mod binding;
mod launch;
mod reclaim;
mod terminal;

#[cfg(test)]
mod tests;

pub(crate) use admission::PARK_IDLE_LIMIT;
pub use admission::{session_id_for, LiveSeatBinding, StartSettlement};
pub use binding::{
    BridgeRuntimeFactory, LaunchEffects, LiveBridgeLauncher, LiveSessionLauncher, SessionRuntime,
    WorkloadTurnsBinding,
};

pub struct LiveSupervisor {
    ledger: Arc<dyn LiveLedger>,
    launcher: Arc<dyn LiveSessionLauncher>,
    bindings: RwLock<BTreeMap<SeatId, LiveSeatBinding>>,
    actors: RwLock<BTreeMap<LiveSessionId, SessionActorHandle>>,
    inactive: RwLock<BTreeMap<LiveSessionId, LiveSessionSummary>>,
    open_gate: Mutex<()>,
    /// Sessions admitted and journaled whose actor is still launching
    /// outside the gate, by seat and whether a workload carries them: they
    /// hold their seat slot and roster place, and a reclaim or re-open of
    /// one refuses until its launch settles.
    starting: std::sync::Mutex<BTreeMap<LiveSessionId, (SeatId, bool)>>,
    /// The declared `limits.sessions.max_sessions` composition limit: the
    /// strict upper bound on the live roster this supervisor may hold in
    /// memory. History is owned by the ledger; only live and parked
    /// non-terminal sessions are tracked here, and the live set can never
    /// exceed the declared bound.
    max_sessions: usize,
    /// The daemon-owned runtime that hosts every session actor task. A
    /// caller's runtime can be request-scoped (an intent route's blocking
    /// bridge) and may end the moment the open/prompt reply is delivered;
    /// a task spawned there would take the bridge and the pinned OMP child
    /// down with it after exactly one turn. The supervisor's handle is the
    /// lifetime owner: actors and observation pumps outlive every caller.
    runtime: tokio::runtime::Handle,
    /// The delegated-child completion-event observer (the daemon's governed
    /// task owner): invoked by each session actor exactly when a typed
    /// `Result` event is durably appended. `None` observes nothing.
    completion_observer:
        Option<std::sync::Arc<dyn crate::host_tools::delegation::CompletionEventObserver>>,
    /// The state root whose `session-authorities` capsules are deleted when
    /// their session ends; unset in tests and read-only nodes.
    capsule_root: std::sync::OnceLock<std::path::PathBuf>,
}
