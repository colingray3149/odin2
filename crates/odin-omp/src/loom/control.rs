//! The live control surface of a loom session: one worker runs queued turns
//! in order; abort and stop cancel the running one and journal why.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveContentBlock, LiveError, LiveMessage, ModelName, PermissionDecision,
    PermissionRequestId, ProviderName,
};
use odin_domain::{ApprovalId, NodeId};
use tokio::sync::{watch, Notify};

use super::session::{Failure, Queued, Session};
use crate::live::control::{LiveControlBackend, LiveControlHooks};

pub struct LoomControl {
    session: Arc<Session>,
    hooks: Arc<dyn LiveControlHooks>,
    wake: Arc<Notify>,
    /// The turn to cancel.
    cancel: watch::Sender<u64>,
    closed: Arc<AtomicBool>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

fn refused(code: &str, message: impl Into<String>) -> LiveError {
    LiveError::Conflict {
        code: code.to_owned(),
        message: message.into(),
    }
}

fn unsupported(operation: &str) -> LiveError {
    LiveError::Unsupported {
        operation: format!("{operation} on a loom session"),
    }
}

impl LoomControl {
    pub(super) fn start(session: Arc<Session>, hooks: Arc<dyn LiveControlHooks>) -> Arc<Self> {
        let (cancel, cancelled) = watch::channel(0);
        let control = Arc::new(Self {
            session,
            hooks,
            wake: Arc::new(Notify::new()),
            cancel,
            closed: Arc::default(),
            worker: Mutex::new(None),
        });
        let worker = tokio::spawn(work(
            Arc::clone(&control.session),
            Arc::clone(&control.wake),
            Arc::clone(&control.closed),
            cancelled,
        ));
        if let Ok(mut slot) = control.worker.lock() {
            *slot = Some(worker);
        }
        control
    }

    fn enqueue(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
        wake: bool,
    ) -> Result<(), LiveError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(refused("loom_session_closed", "the session was stopped"));
        }
        let mut text = Vec::new();
        let mut images = Vec::new();
        for block in &message.content {
            match block {
                LiveContentBlock::Text(value) => text.push(value.clone()),
                LiveContentBlock::Image { mime_type, data } => images.push(
                    serde_json::json!({"type": "image", "mimeType": mime_type, "data": data}),
                ),
                _ => {}
            }
        }
        let mut text = text.join("\n");
        if let Some(source) = &self.session.images {
            let (attached, more) = source.attach(&text);
            text = attached;
            images.extend(more);
        }
        if text.trim().is_empty() && images.is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "loom_prompt_empty".to_owned(),
                message: "the prompt carries no text".to_owned(),
            });
        }
        let mut state = self
            .session
            .state
            .lock()
            .map_err(|error| LiveError::unavailable("loom_queue", error))?;
        let limit = self.session.config.max_queued_turns;
        if state.queue.len() >= limit as usize {
            return Err(refused(
                "loom_queue_full",
                format!("{limit} turns already wait behind the running one (max_queued_turns)"),
            ));
        }
        state.queue.push_back(Queued {
            text,
            owner_text: owner_text.map(str::to_owned),
            images,
            wake,
        });
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Cancels the running turn, if any; it is journaled as stopped.
    fn stop_turn(&self, reason: &str) {
        let current = self
            .session
            .state
            .lock()
            .ok()
            .and_then(|state| state.current);
        if let Some((turn, side)) = current {
            self.session
                .settle(turn, side, Err(Failure::Aborted(reason.to_owned())));
            self.cancel.send_replace(turn);
        }
    }

    /// A fresh context epoch, with the bridge row's epoch advanced as an
    /// OMP restart advances it; returns the new session epoch.
    fn advance(&self) -> Result<i64, LiveError> {
        self.stop_turn("stopped for a restart");
        let mut bridge = self
            .session
            .bridge
            .lock()
            .map_err(|error| LiveError::unavailable("loom_binding", error))?;
        let row = self
            .session
            .ledger
            .lock()
            .map_err(|error| LiveError::unavailable("bridge_ledger_lock", error))?
            .reclaim_live_session(
                &bridge.session_id,
                bridge.epoch,
                time::OffsetDateTime::now_utc(),
            )
            .map_err(|error| LiveError::unavailable("loom_binding", error))?;
        bridge.epoch = row.epoch;
        drop(bridge);
        self.session
            .new_epoch()
            .map_err(|error| LiveError::unavailable("loom_journal", error))?;
        Ok(row.epoch)
    }
}

async fn work(
    session: Arc<Session>,
    wake: Arc<Notify>,
    closed: Arc<AtomicBool>,
    mut cancelled: watch::Receiver<u64>,
) {
    loop {
        let Some((item, turn, side)) = session.begin() else {
            if closed.load(Ordering::Acquire) {
                return;
            }
            wake.notified().await;
            continue;
        };
        tokio::select! {
            () = session.run(turn, side, item) => {}
            _ = cancelled.wait_for(|cancel| *cancel == turn) => {}
        }
    }
}

#[async_trait]
impl LiveControlBackend for LoomControl {
    async fn prompt(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.enqueue(message, owner_text, false)
    }

    /// Hermes's unprompted wake: a side turn when the seat declares them.
    async fn prompt_wake(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
        _follow_up: bool,
    ) -> Result<(), LiveError> {
        self.enqueue(message, owner_text, true)
    }

    async fn follow_up(
        &self,
        message: &LiveMessage,
        owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.enqueue(message, owner_text, false)
    }

    /// Steering words join the running turn's next round (a final round
    /// takes another); with nothing running they are a main prompt.
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let text = message
            .content
            .iter()
            .filter_map(|block| match block {
                LiveContentBlock::Text(text) => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut state = self
            .session
            .state
            .lock()
            .map_err(|error| LiveError::unavailable("loom_state", error))?;
        if state.current.is_none() {
            drop(state);
            return self.enqueue(message, None, false);
        }
        state.steer.push(text);
        Ok(())
    }

    async fn pause(&self) -> Result<(), LiveError> {
        self.stop_turn("paused");
        Ok(())
    }

    /// Nothing runs between turns: the next prompt continues from the journal.
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }

    async fn checkpoint(&self) -> Result<(), LiveError> {
        Err(unsupported("checkpoint"))
    }

    async fn restart(&self) -> Result<(), LiveError> {
        self.advance().map(|_| ())
    }

    /// No transcript to roll: a fresh epoch renders from the same journal.
    async fn rollover_fresh(
        &self,
        _refusal_event: u64,
        selected_model: Option<(&ProviderName, &ModelName)>,
    ) -> Result<i64, LiveError> {
        if let Some((_, model)) = selected_model {
            self.session
                .state
                .lock()
                .map_err(|error| LiveError::unavailable("loom_state", error))?
                .model = model.as_str().to_owned();
        }
        self.advance()
    }

    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Err(unsupported("rehome"))
    }

    async fn set_model(
        &self,
        _provider: &ProviderName,
        model: &ModelName,
    ) -> Result<(), LiveError> {
        self.session
            .state
            .lock()
            .map_err(|error| LiveError::unavailable("loom_state", error))?
            .model = model.as_str().to_owned();
        self.session
            .new_epoch()
            .map_err(|error| LiveError::unavailable("loom_journal", error))
    }

    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.stop_turn("stopped on command");
        Ok(())
    }

    async fn abort_session(&self) -> Result<(), LiveError> {
        self.shutdown().await
    }

    async fn shutdown(&self) -> Result<(), LiveError> {
        self.closed.store(true, Ordering::Release);
        self.stop_turn("the session was stopped");
        if let Ok(mut state) = self.session.state.lock() {
            state.queue.clear();
        }
        self.wake.notify_one();
        let worker = self.worker.lock().ok().and_then(|mut slot| slot.take());
        if let Some(worker) = worker {
            worker.abort();
            let _ = worker.await;
        }
        Ok(())
    }

    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Err(unsupported("permission decisions"))
    }

    async fn decide_approval(
        &self,
        approval_id: &ApprovalId,
        expected_revision: u64,
        decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        self.hooks
            .decide_approval(approval_id, expected_revision, decision)
            .await
    }

    async fn bridge_ready(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
    }

    async fn process_exited(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}
