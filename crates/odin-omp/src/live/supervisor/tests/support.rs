use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveError, LiveMessage, LiveSessionId, ModelName, PermissionDecision,
    PermissionRequestId, ProviderName, SessionManifest,
};
use odin_domain::{ApprovalId, NodeId};

use super::super::{LiveSessionLauncher, SessionRuntime};
use crate::live::control::LiveControlBackend;

/// A control backend that applies nothing: the launcher-level laws
/// under test never depend on backend effects.
pub(super) struct NullBackend;

#[async_trait]
impl LiveControlBackend for NullBackend {
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn follow_up(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn steer(&self, _: &LiveMessage) -> Result<(), LiveError> {
        Ok(())
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn set_model(&self, _: &ProviderName, _: &ModelName) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_permission(
        &self,
        _: &PermissionRequestId,
        _: PermissionDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _: &ApprovalId,
        _: u64,
        _: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

/// A launcher that records every launch request, so the recovery laws
/// are observable: discovery launches nothing, a reclaim launches
/// exactly one fresh incarnation.
/// One recorded open: (session, epoch, reclaim, provider, model).
type RecordedOpens = Vec<(
    LiveSessionId,
    odin_domain::huginn::SessionEpoch,
    bool,
    ProviderName,
    ModelName,
)>;

pub(super) struct RecordingLaunch {
    opens: std::sync::Mutex<RecordedOpens>,
}

impl RecordingLaunch {
    pub(super) fn new() -> Self {
        Self {
            opens: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn opens(
        &self,
    ) -> Vec<(
        LiveSessionId,
        odin_domain::huginn::SessionEpoch,
        bool,
        ProviderName,
        ModelName,
    )> {
        self.opens.lock().expect("opens").clone()
    }
}

#[async_trait]
impl LiveSessionLauncher for RecordingLaunch {
    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        manifest: &SessionManifest,
        epoch: odin_domain::huginn::SessionEpoch,
        reclaim: bool,
    ) -> Result<SessionRuntime, LiveError> {
        self.opens.lock().expect("opens").push((
            manifest.session_id,
            epoch,
            reclaim,
            manifest.provider.clone(),
            manifest.model.clone(),
        ));
        Ok(SessionRuntime {
            control: Arc::new(NullBackend),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}

/// Stops the actor at a dispatch boundary until its runtime is destroyed.
/// The shared dispatch table models the bridge journal surviving that death.
pub(super) struct InterruptedDispatch {
    pub stage: u8,
    pub entered: tokio::sync::Notify,
    pub calls: Mutex<Vec<(odin_domain::CommandId, bool)>>,
    pub sends: std::sync::atomic::AtomicUsize,
    pub recovering: std::sync::atomic::AtomicBool,
    dispatched: Mutex<Option<bool>>,
}

impl InterruptedDispatch {
    pub(super) fn new(stage: u8) -> Arc<Self> {
        Arc::new(Self {
            stage,
            entered: tokio::sync::Notify::new(),
            calls: Mutex::new(Vec::new()),
            sends: std::sync::atomic::AtomicUsize::new(0),
            recovering: std::sync::atomic::AtomicBool::new(false),
            dispatched: Mutex::new(None),
        })
    }
}

#[async_trait]
impl LiveControlBackend for InterruptedDispatch {
    fn supports_identity_safe_dispatch(&self) -> bool {
        true
    }

    async fn message_outcome(
        &self,
        id: &odin_domain::CommandId,
    ) -> Result<Option<bool>, LiveError> {
        if self.recovering.load(std::sync::atomic::Ordering::SeqCst) {
            let mut calls = self.calls.lock().expect("calls");
            if let Some((_, follow_up)) = calls.first() {
                let follow_up = *follow_up;
                calls.push((id.clone(), follow_up));
            }
        }
        Ok(*self.dispatched.lock().expect("dispatch table"))
    }
    async fn dispatch_message(
        &self,
        id: &odin_domain::CommandId,
        _: &LiveMessage,
        follow_up: bool,
    ) -> Result<bool, LiveError> {
        use std::sync::atomic::Ordering;
        self.calls
            .lock()
            .expect("calls")
            .push((id.clone(), follow_up));
        let recovering = self.recovering.load(Ordering::SeqCst);
        if recovering || self.stage != 0 {
            let mut dispatched = self.dispatched.lock().expect("dispatch table");
            if dispatched.is_none() {
                self.sends.fetch_add(1, Ordering::SeqCst);
                *dispatched = Some(recovering || self.stage == 2);
            }
        }
        if !recovering {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(self
            .dispatched
            .lock()
            .expect("dispatch table")
            .unwrap_or(false))
    }
    async fn bridge_ready(&self) -> bool {
        true
    }
    async fn prompt(&self, _: &LiveMessage) -> Result<(), LiveError> {
        panic!("recovery must use the original dispatch identity")
    }
    async fn follow_up(&self, _: &LiveMessage) -> Result<(), LiveError> {
        panic!("recovery must use the original dispatch identity")
    }
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        NullBackend.steer(message).await
    }
    async fn pause(&self) -> Result<(), LiveError> {
        NullBackend.pause().await
    }
    async fn resume(&self) -> Result<(), LiveError> {
        NullBackend.resume().await
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        NullBackend.checkpoint().await
    }
    async fn restart(&self) -> Result<(), LiveError> {
        NullBackend.restart().await
    }
    async fn rehome(&self, node: &NodeId) -> Result<(), LiveError> {
        NullBackend.rehome(node).await
    }
    async fn set_model(&self, provider: &ProviderName, model: &ModelName) -> Result<(), LiveError> {
        NullBackend.set_model(provider, model).await
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        NullBackend.abort_turn().await
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        NullBackend.abort_session().await
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        NullBackend.shutdown().await
    }
    async fn decide_permission(
        &self,
        id: &PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        NullBackend.decide_permission(id, decision).await
    }
    async fn decide_approval(
        &self,
        id: &ApprovalId,
        revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        NullBackend.decide_approval(id, revision, decision).await
    }
}

pub(super) struct InterruptedDispatchLaunch(pub Arc<InterruptedDispatch>);

#[async_trait]
impl LiveSessionLauncher for InterruptedDispatchLaunch {
    fn harness_turns(&self) -> Option<Arc<crate::live::harness::HarnessTurns>> {
        None
    }

    async fn open(
        &self,
        _: &SessionManifest,
        _: odin_domain::huginn::SessionEpoch,
        _: bool,
    ) -> Result<SessionRuntime, LiveError> {
        Ok(SessionRuntime {
            control: self.0.clone(),
            terminal: None,
            observations: None,
            failed_notices: None,
        })
    }
}
