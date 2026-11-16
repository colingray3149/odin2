//! Loom: Odin's in-process lean harness. A seat that declares `[live.loom]`
//! runs its own sessions here instead of OMP (workload pods and pod reviews
//! stay on OMP). A session is a tokio task over an append-only journal;
//! every request is a budgeted view rendered fresh from that journal and
//! the ledger, never an ever-growing thread. Its frames are the canonical
//! session events, so the ledger, Huginn, the view, Hermes history,
//! delegated completion and stop work unchanged.

mod control;
mod gateway;
mod journal;
mod render;
mod session;
mod tools;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, SessionEpoch, SessionManifest};
use odin_domain::SeatId;
use odin_ledger::Ledger;
use odin_registry::schema::SeatLoomToml;
use tokio::sync::{broadcast, Semaphore};

pub use gateway::Gateway;

use crate::bridge::BridgeBinding;
use crate::host_tools::operations::{HostToolOperations, SessionOperationBinding};
use crate::live::control::{BrainTurnContext, LiveControlHooks, TurnImages};
use crate::live::harness::HarnessIncidentSink;
use crate::live::rollover::RolloverChildrenSource;
use crate::live::supervisor::{LaunchEffects, LiveSessionLauncher, SessionRuntime};
use crate::live::target::TerminalTargetAdmin;
use crate::live::zellij::ZellijLiveAdapter;
use crate::uri::ScopedUriRouter;

/// How a model card is asked to think, as OMP's rendered provider asks it.
#[derive(Clone, Debug)]
pub struct LoomLane {
    /// The card's declared default effort, sent as `reasoning_effort`.
    pub effort: Option<String>,
    /// Whether the card takes its earlier reasoning back.
    pub replay_reasoning: bool,
    /// Whether the card takes image input (tool images are sent, not just stored).
    pub image: bool,
}

impl Default for LoomLane {
    fn default() -> Self {
        Self {
            effort: None,
            replay_reasoning: true,
            image: false,
        }
    }
}

/// Everything a loom session needs from the production composition.
pub struct LoomParts {
    pub operations: HostToolOperations,
    pub binding: SessionOperationBinding,
    pub admitted: BTreeSet<String>,
    /// The session's binding, its epoch published in the ledger.
    pub bridge: BridgeBinding,
    pub ledger: Arc<Mutex<Ledger>>,
    pub uri_router: ScopedUriRouter,
    pub artifact_root: PathBuf,
    pub context_trace_root: Option<PathBuf>,
    /// Seat guidance and core memory, frozen for the session.
    pub system: String,
    pub brain: Option<Arc<dyn BrainTurnContext>>,
    pub images: Option<Arc<dyn TurnImages>>,
    pub children: Arc<dyn RolloverChildrenSource>,
    pub hooks: Arc<dyn LiveControlHooks>,
    pub terminal: Option<Arc<ZellijLiveAdapter>>,
}

#[async_trait]
pub trait LoomSource: Send + Sync {
    async fn loom_parts(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
    ) -> Result<LoomParts, LiveError>;
}

/// A seat's cached-prompt share over its declared window; under its floor, one incident.
pub struct CacheWatch {
    seat: String,
    floor: u8,
    span: Duration,
    sink: Arc<dyn HarnessIncidentSink>,
    window: Mutex<(Instant, u64, u64)>,
}

impl CacheWatch {
    pub fn note(&self, prompt: u64, cached: u64) {
        let Ok(mut window) = self.window.lock() else {
            return;
        };
        window.1 += prompt;
        window.2 += cached;
        if window.0.elapsed() < self.span {
            return;
        }
        let (total, hit) = (window.1, window.2);
        *window = (Instant::now(), 0, 0);
        drop(window);
        let share = (hit * 100).checked_div(total).unwrap_or(100);
        if share < u64::from(self.floor) {
            self.sink.raise(
                &self.seat,
                "loom-cache-hit",
                &format!(
                    "{}'s cached prompt share fell to {share}% over {} hours",
                    self.seat,
                    self.span.as_secs() / 3_600
                ),
                &format!(
                    "{hit} of {total} prompt tokens were cached, under the seat's \
                     cache_hit_floor_percent {}; `odin context <session>` shows each request's \
                     prefix hash and cached tokens",
                    self.floor
                ),
            );
        }
    }
}

/// Routes a seat's own sessions to loom when it declares `[live.loom]`;
/// everything else goes to the inner launcher unchanged.
pub struct LoomLauncher {
    inner: Arc<dyn LiveSessionLauncher>,
    source: Arc<dyn LoomSource>,
    seats: BTreeMap<SeatId, SeatLoomToml>,
    /// `Err` names why no gateway is available; loom seats then refuse to open.
    gateway: Result<Gateway, String>,
    lanes: Arc<BTreeMap<String, LoomLane>>,
    root: PathBuf,
    incidents: Option<Arc<dyn HarnessIncidentSink>>,
    watches: Mutex<BTreeMap<SeatId, Arc<CacheWatch>>>,
}

impl LoomLauncher {
    pub fn new(
        inner: Arc<dyn LiveSessionLauncher>,
        source: Arc<dyn LoomSource>,
        seats: BTreeMap<SeatId, SeatLoomToml>,
        gateway: Result<Gateway, String>,
        lanes: BTreeMap<String, LoomLane>,
        root: PathBuf,
    ) -> Self {
        Self {
            inner,
            source,
            seats,
            gateway,
            lanes: Arc::new(lanes),
            root,
            incidents: None,
            watches: Mutex::default(),
        }
    }

    pub fn with_incidents(mut self, sink: Arc<dyn HarnessIncidentSink>) -> Self {
        self.incidents = Some(sink);
        self
    }

    /// The loom budget of a manifest that runs on loom: the seat's own
    /// session, never a workload, a pod review or a named harness.
    pub fn route(&self, manifest: &SessionManifest) -> Option<&SeatLoomToml> {
        if manifest.workload.is_some() || manifest.is_pod_review() || manifest.harness.is_some() {
            return None;
        }
        self.seats.get(&manifest.seat_id)
    }

    fn watch(&self, seat: &SeatId, config: &SeatLoomToml) -> Option<Arc<CacheWatch>> {
        let sink = self.incidents.clone()?;
        let mut watches = self.watches.lock().ok()?;
        Some(Arc::clone(watches.entry(seat.clone()).or_insert_with(
            || {
                Arc::new(CacheWatch {
                    seat: seat.to_string(),
                    floor: config.cache_hit_floor_percent,
                    span: Duration::from_secs(u64::from(config.cache_floor_window_hours) * 3_600),
                    sink,
                    window: Mutex::new((Instant::now(), 0, 0)),
                })
            },
        )))
    }

    async fn open_loom(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        config: SeatLoomToml,
    ) -> Result<SessionRuntime, LiveError> {
        let gateway = self
            .gateway
            .clone()
            .map_err(|reason| LiveError::unavailable("loom_gateway", reason))?;
        let parts = self.source.loom_parts(manifest, epoch).await?;
        let tools = tools::SessionTools {
            operations: parts.operations,
            binding: parts.binding,
            admitted: parts.admitted,
            scope: parts.bridge.dispatch_scope(),
            uri_router: parts.uri_router,
            ledger: Arc::clone(&parts.ledger),
            artifact_root: parts.artifact_root,
            permits: Arc::new(Semaphore::new(crate::bridge::DISPATCH_PERMITS)),
        };
        let listing = tools
            .listing()
            .map_err(|error| LiveError::unavailable("loom_tools", error))?;
        let journal = journal::Journal::open(&self.root, &manifest.session_id.to_string())
            .map_err(|error| LiveError::unavailable("loom_journal", error))?;
        let (frames, observations) = broadcast::channel(1024);
        let session = Arc::new(session::Session {
            manifest: manifest.clone(),
            gateway,
            lanes: Arc::clone(&self.lanes),
            tools,
            listing,
            system: parts.system,
            brain: parts.brain,
            images: parts.images,
            children: parts.children,
            ledger: parts.ledger,
            bridge: Mutex::new(parts.bridge),
            trace_root: parts.context_trace_root,
            frames,
            journal: Mutex::new(journal),
            state: Mutex::new(session::State {
                model: manifest.model.as_str().to_owned(),
                estimate: render::Estimator::default(),
                steer: Vec::new(),
                current: None,
                queue: std::collections::VecDeque::new(),
                images: BTreeMap::new(),
            }),
            cache: self.watch(&manifest.seat_id, &config),
            config,
        });
        session
            .check_prefix()
            .await
            .map_err(|cause| LiveError::InvalidRequest {
                code: "loom_prefix_over_budget".to_owned(),
                message: cause,
            })?;
        // Every open is a fresh context epoch rendered from the same journal.
        session
            .new_epoch()
            .map_err(|error| LiveError::unavailable("loom_journal", error))?;
        tracing::info!(
            "odind: loom open session={} seat={} model={} tools={}",
            manifest.session_id,
            manifest.seat_id,
            manifest.model,
            session.listing.len()
        );
        Ok(SessionRuntime {
            control: control::LoomControl::start(session, parts.hooks),
            terminal: parts.terminal,
            observations: Some(observations),
            failed_notices: None,
        })
    }
}

#[async_trait]
impl LiveSessionLauncher for LoomLauncher {
    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.open_owned(manifest, epoch, reclaim, LaunchEffects::default())
            .await
    }

    async fn open_owned(
        &self,
        manifest: &SessionManifest,
        epoch: SessionEpoch,
        reclaim: bool,
        effects: LaunchEffects,
    ) -> Result<SessionRuntime, LiveError> {
        let Some(config) = self.route(manifest).cloned() else {
            return self
                .inner
                .open_owned(manifest, epoch, reclaim, effects)
                .await;
        };
        effects.mark_started();
        self.open_loom(manifest, epoch, config).await
    }

    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        self.inner.terminal_target_admin()
    }

    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
        self.inner.harness_turns()
    }

    async fn ensure_session_run(&self, manifest: &SessionManifest) -> Result<(), LiveError> {
        self.inner.ensure_session_run(manifest).await
    }

    async fn kernel_session(
        &self,
        manifest: &SessionManifest,
        workspace: &std::path::Path,
    ) -> Result<Arc<dyn crate::live::kernel_mcp::KernelSession>, LiveError> {
        self.inner.kernel_session(manifest, workspace).await
    }
}
