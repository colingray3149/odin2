use std::sync::Arc;

use async_trait::async_trait;
use odin_domain::huginn::{LiveError, SessionManifest};
use tokio::sync::{broadcast, watch};

use crate::bridge::{ObservedFrame, OmpBridge, OmpBridgeConfig};
use crate::host_tools::delegation::ChildStopCoordinator;

use super::admission::unavailable;
use crate::live::control::{
    BrainTurnContext, BridgeControl, LaneContextBudgets, LiveControlBackend, LiveControlHooks,
};
use crate::live::target::TerminalTargetAdmin;
use crate::live::zellij::ZellijLiveAdapter;

pub struct SessionRuntime {
    pub control: Arc<dyn LiveControlBackend>,
    pub terminal: Option<Arc<ZellijLiveAdapter>>,
    pub observations: Option<broadcast::Receiver<ObservedFrame>>,
    /// Typed unexpected-failure notices from the bridge: `Some` carries the
    /// failure reason the moment the pump proves the child cannot carry
    /// traffic. The supervisor turns it into the durable session Failed
    /// transition; a planned stop or reclaim never sends here. `None` for
    /// launchers without a real bridge (fixtures).
    pub failed_notices: Option<watch::Receiver<Option<String>>>,
}

/// Per-open evidence that launch side effects may require asynchronous cleanup.
/// Mark immediately before the first effect, never after an awaited effect.
#[derive(Clone, Default)]
pub struct LaunchEffects(Arc<std::sync::atomic::AtomicBool>);

impl LaunchEffects {
    pub fn mark_started(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn started(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[async_trait]
pub trait LiveSessionLauncher: Send + Sync {
    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError>;

    /// Whether joining a cancelled `open` also proves all resources it
    /// started have terminated. Return true only when future destruction
    /// synchronously terminates every resource: abort-on-drop handles or
    /// detached cleanup threads are not such evidence. Launchers with child
    /// processes or spawned descendants conservatively retain authority until
    /// they provide an explicit descendant-completion ownership protocol.
    fn cancellation_joins_resources(&self) -> bool {
        false
    }

    /// Tracks effects for this particular attempt. Implementations can leave
    /// the marker clear on validated pre-effect rejection. Opaque launchers
    /// conservatively mark before entry: a plain error proves no cleanup.
    async fn open_owned(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
        effects: LaunchEffects,
    ) -> Result<SessionRuntime, LiveError> {
        effects.mark_started();
        self.open(manifest, epoch, reclaim).await
    }

    /// Terminal target administration when this launcher owns a terminal
    /// adapter. The default returns None: no terminal surface is reachable
    /// through this launcher, and the supervisor reports that typed state.
    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        None
    }

    /// Turn tracker for shutdown; wrapping launchers must forward the inner tracker.
    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>>;

    /// Creates (idempotently) the session's durable bridge run
    /// `run:live:<session>` for a session another launcher runs (a non-OMP
    /// harness). Delegation plans and task reads need it for every session.
    /// The default refuses typed: a launcher without a bridge ledger cannot
    /// host delegated harness sessions.
    async fn ensure_session_run(&self, _manifest: &SessionManifest) -> Result<(), LiveError> {
        Err(LiveError::Unsupported {
            operation: "this launcher records no session runs".to_owned(),
        })
    }
    /// Reuses OMP operation policy for a non-OMP session rooted at `workspace`.
    /// Launchers without operation authority refuse by default.
    async fn kernel_session(
        &self,
        _manifest: &SessionManifest,
        _workspace: &std::path::Path,
    ) -> Result<Arc<dyn crate::live::kernel_mcp::KernelSession>, LiveError> {
        Err(LiveError::Unsupported {
            operation: "this launcher composes no kernel sessions".to_owned(),
        })
    }
}

#[async_trait]
pub trait BridgeRuntimeFactory: Send + Sync {
    async fn build(
        &self,
        manifest: &SessionManifest,
        reclaim: bool,
    ) -> Result<
        (
            OmpBridgeConfig,
            Arc<dyn LiveControlHooks>,
            Option<Arc<ZellijLiveAdapter>>,
        ),
        LiveError,
    >;

    /// Tracks the first factory effect; opaque factories conservatively mark
    /// before entry. Production factories override this after pure validation.
    async fn build_owned(
        &self,
        manifest: &SessionManifest,
        reclaim: bool,
        effects: LaunchEffects,
    ) -> Result<
        (
            OmpBridgeConfig,
            Arc<dyn LiveControlHooks>,
            Option<Arc<ZellijLiveAdapter>>,
        ),
        LiveError,
    > {
        effects.mark_started();
        self.build(manifest, reclaim).await
    }

    /// Terminal target administration when this factory owns the terminal
    /// adapter. The default returns None until the runtime owner wires the
    /// adapter; every supervisor target call then reports typed
    /// unavailability instead of guessing a target.
    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        None
    }

    /// The session's durable bridge run, created idempotently (see
    /// [`LiveSessionLauncher::ensure_session_run`]). The default refuses
    /// typed: a factory without a bridge ledger records no runs.
    async fn ensure_session_run(&self, _manifest: &SessionManifest) -> Result<(), LiveError> {
        Err(LiveError::Unsupported {
            operation: "this runtime factory records no session runs".to_owned(),
        })
    }

    /// See [`LiveSessionLauncher::kernel_session`].
    async fn kernel_session(
        &self,
        _manifest: &SessionManifest,
        _workspace: &std::path::Path,
    ) -> Result<Arc<dyn crate::live::kernel_mcp::KernelSession>, LiveError> {
        Err(LiveError::Unsupported {
            operation: "this runtime factory composes no kernel sessions".to_owned(),
        })
    }

    /// The per-turn brain context source for one session manifest and its
    /// durable binding epoch: served exactly when the manifest seat's
    /// published brain policy declares a `[context]` consumer, for a seat
    /// conversation (a workload pod's context is its brief, its inputs and its
    /// own task, so a pod has none). The
    /// default returns `Ok(None)`: factories without brain policies keep
    /// every turn byte-identical, and a seat that declares the context
    /// consumer but cannot bind its serving state fails the launch typed
    /// instead of silently dropping the declared budgets.
    fn brain_turn_source(
        &self,
        _manifest: &SessionManifest,
        _epoch: odin_domain::huginn::SessionEpoch,
    ) -> Result<Option<Arc<dyn BrainTurnContext>>, LiveError> {
        Ok(None)
    }

    /// The session's declared context contracts, one per model it may run
    /// (the seat's launch options that declare a window): identity, window,
    /// compiler-resolved effective output reserve, and context tokenizer.
    /// `Some` only when the launch model itself is declared. The launch
    /// stages the set verbatim into the child's `ODIN_CONTEXT_BUDGET`, and
    /// the live control seam plans and guards against the entry of the
    /// model running now. The default returns `None`: factories without a
    /// declared brain context policy keep dispatch byte-identical.
    fn lane_context_budgets(&self, _manifest: &SessionManifest) -> Option<LaneContextBudgets> {
        None
    }

    /// The source of the image blocks a turn's photo markers name. The
    /// default returns `None`: marker text is sent verbatim.
    fn turn_images(&self) -> Option<Arc<dyn crate::live::control::TurnImages>> {
        None
    }

    /// Effective context window of every selectable model card, by card id.
    /// The default is none: fixtures declare no fractional rollover.
    fn card_windows(&self) -> Option<std::collections::BTreeMap<String, u64>> {
        None
    }
}

pub struct LiveBridgeLauncher {
    factory: Arc<dyn BridgeRuntimeFactory>,
    child_stop: std::sync::Mutex<Option<std::sync::Weak<dyn ChildStopCoordinator>>>,
}

impl LiveBridgeLauncher {
    pub fn new(factory: Arc<dyn BridgeRuntimeFactory>) -> Self {
        Self {
            factory,
            child_stop: std::sync::Mutex::new(None),
        }
    }

    /// Installs the bounded parent-stop coordinator. Every bridge this
    /// launcher opens thereafter awaits its active delegated children inside
    /// its own bounded stop. The hook is held weakly so a runtime owner that
    /// strongly owns the supervisor can never form a reference cycle back
    /// into the bridge through the session actor.
    pub fn with_child_stop_coordinator(
        self,
        coordinator: &Arc<dyn ChildStopCoordinator>,
    ) -> Result<Self, LiveError> {
        *self.child_stop.lock().map_err(unavailable)? = Some(Arc::downgrade(coordinator));
        Ok(self)
    }
}

#[async_trait]
impl LiveSessionLauncher for LiveBridgeLauncher {
    /// OMP sessions run through their bridge's own stop ladder; this
    /// launcher drives no process-harness turn.
    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn ensure_session_run(&self, manifest: &SessionManifest) -> Result<(), LiveError> {
        self.factory.ensure_session_run(manifest).await
    }

    async fn kernel_session(
        &self,
        manifest: &SessionManifest,
        workspace: &std::path::Path,
    ) -> Result<Arc<dyn crate::live::kernel_mcp::KernelSession>, LiveError> {
        self.factory.kernel_session(manifest, workspace).await
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.open_owned(manifest, epoch, reclaim, LaunchEffects::default())
            .await
    }

    async fn open_owned(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
        effects: LaunchEffects,
    ) -> Result<SessionRuntime, LiveError> {
        let (mut config, hooks, terminal) = self
            .factory
            .build_owned(manifest, reclaim, effects.clone())
            .await?;
        // The admission seam: the supervisor's durable epoch becomes the
        // binding epoch `OmpBridge::start` publishes. A row behind is
        // corrected forward, a row at the epoch is re-asserted, and a row
        // ahead is a stale incarnation refused typed (StaleBinding) — the
        // requested durable epoch always reaches the real launched binding
        // or the launch fails typed.
        config.requested_epoch = Some(epoch);
        // A selected card with no composed window refuses before any bridge starts.
        crate::live::control::card_window(
            self.factory.card_windows().as_ref(),
            manifest.provider.as_str(),
            manifest.model.as_str(),
        )?;
        effects.mark_started();
        let bridge = Arc::new(
            OmpBridge::start(config)
                .await
                .map_err(bridge_binding_error)?,
        );
        let coordinator = self
            .child_stop
            .lock()
            .map_err(unavailable)?
            .as_ref()
            .and_then(std::sync::Weak::upgrade);
        // The brain context source binds for every conversation whose seat
        // declares a brain `[context]` policy, with the supervisor's durable
        // binding epoch for turn-identity scoping. The factory fails the
        // launch typed when a declared consumer cannot bind.
        let brain_turns = self.factory.brain_turn_source(manifest, epoch)?;
        if let Some(coordinator) = coordinator {
            bridge
                .set_child_stop_coordinator(&coordinator)
                .map_err(|error| {
                    LiveError::unavailable("omp_bridge_set_child_stop_coordinator", error)
                })?;
        }
        let observations = Some(bridge.subscribe());
        let failed_notices = Some(bridge.failed_notices());
        let control: Arc<dyn LiveControlBackend> = Arc::new(
            BridgeControl::new(bridge, hooks)
                .with_brain_turn_source(brain_turns)
                .with_turn_images(self.factory.turn_images())
                .with_lane_context_budgets(
                    self.factory.lane_context_budgets(manifest),
                    &manifest.provider,
                    &manifest.model,
                )
                .with_card_windows(self.factory.card_windows()),
        );
        Ok(SessionRuntime {
            control,
            terminal,
            observations,
            failed_notices,
        })
    }

    fn terminal_target_admin(&self) -> Option<Arc<dyn TerminalTargetAdmin>> {
        self.factory.terminal_target_admin()
    }
}

/// Typed binding failures: a stale-incarnation epoch refusal is an epoch
/// mismatch for the caller, not a generic unavailability. Epoch values
/// convert through the ONE shared checked conversion (live::control) —
/// negative, zero, or out-of-range binding epochs fail typed, never a
/// defaulted or clamped identity.
fn bridge_binding_error(error: crate::bridge::BridgeError) -> LiveError {
    match error {
        crate::bridge::BridgeError::StaleBinding { requested, actual } => {
            match (
                crate::live::control::checked_session_epoch(requested),
                crate::live::control::checked_session_epoch(actual),
            ) {
                (Ok(expected), Ok(actual)) => LiveError::EpochMismatch { expected, actual },
                (Err(reason), _) | (_, Err(reason)) => {
                    LiveError::unavailable("stale_binding_epoch", reason)
                }
            }
        }
        // The bridge ledger's row ended (a failed first open ends it): the
        // same typed refusal the reclaim surface gives, so a caller derives
        // a fresh session instead of re-driving this one.
        crate::bridge::BridgeError::Ledger(odin_ledger::LedgerError::SessionEnded { id }) => {
            LiveError::Conflict {
                code: "session_ended".to_owned(),
                message: format!(
                    "live session {id} is truthfully ended; a terminal session is never reclaimed"
                ),
            }
        }
        error => LiveError::unavailable("omp_bridge_start", error),
    }
}

#[cfg(test)]
mod binding_error_tests {
    use super::*;

    #[test]
    fn an_ended_bridge_row_is_the_typed_session_ended_conflict() {
        let error = bridge_binding_error(crate::bridge::BridgeError::Ledger(
            odin_ledger::LedgerError::SessionEnded {
                id: "790edd9c".to_owned(),
            },
        ));
        assert!(
            matches!(&error, LiveError::Conflict { code, .. } if code == "session_ended"),
            "{error:?}"
        );
    }

    /// A stale incarnation is the caller's epoch mismatch; an epoch outside the live range is a
    /// named unavailability, never a clamped value.
    #[test]
    fn a_stale_binding_is_an_epoch_mismatch_unless_an_epoch_is_out_of_range() {
        let stale = |requested, actual| {
            bridge_binding_error(crate::bridge::BridgeError::StaleBinding { requested, actual })
        };
        assert!(matches!(stale(3, 5), LiveError::EpochMismatch { .. }));
        for (requested, actual) in [(0, 5), (-1, 5), (3, -1)] {
            let error = stale(requested, actual);
            assert!(
                matches!(&error, LiveError::Unavailable { code, .. } if code == "stale_binding_epoch"),
                "{requested}/{actual}: {error:?}"
            );
        }
    }
}
