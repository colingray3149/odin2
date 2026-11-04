use std::collections::BTreeMap;
use std::sync::Arc;

use odin_domain::huginn::{LiveSessionId, LiveSessionSummary};
use odin_domain::SeatId;
use tokio::sync::{Mutex, RwLock};

use super::ledger::LiveLedger;
use super::session_actor::SessionActorHandle;

mod admission;
mod binding;
mod capsules;
mod fresh;
mod launch;
mod reclaim;
mod terminal;

#[cfg(test)]
mod tests;

pub(crate) use admission::PARK_IDLE_LIMIT;
pub use admission::{session_id_for, LiveSeatBinding, StartSettlement, WorkloadOpenError};
pub use binding::{
    BridgeRuntimeFactory, LaunchEffects, LiveBridgeLauncher, LiveSessionLauncher, SessionRuntime,
};
pub use fresh::{FreshPlacement, FreshSession};

pub struct LiveSupervisor {
    ledger: Arc<dyn LiveLedger>,
    launcher: Arc<dyn LiveSessionLauncher>,
    bindings: RwLock<BTreeMap<SeatId, LiveSeatBinding>>,
    actors: RwLock<BTreeMap<LiveSessionId, SessionActorHandle>>,
    inactive: RwLock<BTreeMap<LiveSessionId, LiveSessionSummary>>,
    open_gate: Mutex<()>,
    fresh_gate: Mutex<()>,
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
    /// The roots whose session capsules and harness launch directories are
    /// deleted when their session ends; unset in tests and read-only nodes.
    capsule_root: std::sync::OnceLock<crate::live::capsules::SessionRoots>,
    /// Last declared-heartbeat fire per session. A seat with no declared
    /// interval never writes here. Process-local: a restart's first
    /// observation is due, then the interval holds.
    heartbeat_clocks: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<LiveSessionId, std::time::Instant>>,
    >,
    /// Retires a session whose rollover bound is reached. Installed by the
    /// daemon that holds the brain; absent in fixtures.
    fresh_handoff: std::sync::Mutex<Option<std::sync::Arc<dyn crate::live::service::FreshHandoff>>>,
    /// Delegation rows, so a fresh replacement can arm and re-point live
    /// children before the predecessor ends. Absent in fixtures.
    delegation_links: std::sync::Mutex<Option<crate::host_tools::delegation::DelegationLinkLedger>>,
    /// Declared heartbeat interval per seat. A seat absent from the map
    /// is woken only by events.
    heartbeat_intervals:
        std::sync::Mutex<std::collections::HashMap<odin_domain::SeatId, std::time::Duration>>,
    /// Weak handle of this `Arc`. Callbacks upgrade it; they never
    /// downgrade a bare `&Self`.
    self_weak: std::sync::Weak<LiveSupervisor>,
}
