use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveError, LiveMessage, ModelName, PermissionDecision, PermissionRequestId,
    ProviderName,
};
use odin_domain::{ApprovalId, NodeId};

use super::super::message_text;
use super::unsupported;
use super::TerminalControl;
use crate::live::control::LiveControlBackend;

#[async_trait]
impl LiveControlBackend for TerminalControl {
    async fn prompt(
        &self,
        message: &LiveMessage,
        _owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.start_turn(message).await
    }
    async fn follow_up(
        &self,
        message: &LiveMessage,
        _owner_text: Option<&str>,
    ) -> Result<(), LiveError> {
        self.start_turn(message).await
    }
    /// Typed into the running turn: the agent queues it as a person's
    /// message would be.
    async fn steer(&self, message: &LiveMessage) -> Result<(), LiveError> {
        let text = message_text(message);
        if text.trim().is_empty() {
            return Err(LiveError::InvalidRequest {
                code: "harness_prompt_empty".to_owned(),
                message: "the steer carries no text".to_owned(),
            });
        }
        self.type_line(&text).await
    }
    /// Escape interrupts the agent's turn; its conversation stays.
    async fn pause(&self) -> Result<(), LiveError> {
        self.interrupt_turn().await
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Err(unsupported("checkpoint", &self.route.harness_id))
    }
    async fn restart(&self) -> Result<(), LiveError> {
        self.pause().await
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Err(unsupported("rehome", &self.route.harness_id))
    }
    /// The agent's own model command, typed.
    async fn set_model(
        &self,
        _provider: &ProviderName,
        model: &ModelName,
    ) -> Result<(), LiveError> {
        self.type_line(&format!("/model {model}")).await
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        self.pause().await
    }
    async fn abort_session(&self) -> Result<(), LiveError> {
        self.close().await
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        self.close().await
    }
    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Err(unsupported("permission decisions", &self.route.harness_id))
    }
    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Err(unsupported("approval decisions", &self.route.harness_id))
    }
    async fn bridge_ready(&self) -> bool {
        self.failed.borrow().is_none()
            && self
                .state
                .lock()
                .map(|state| !state.closed)
                .unwrap_or(false)
    }

    fn rollovers_completed(&self) -> u32 {
        self.rollover.completed()
    }

    fn context_window(&self, provider: &str, model: &str) -> Option<u64> {
        if self.manifest.provider.as_str() == provider && self.manifest.model.as_str() == model {
            self.rollover.window()
        } else {
            None
        }
    }

    fn set_fresh_bound(&self, callback: crate::bridge::FreshBound) {
        self.rollover.set_callback(callback);
    }

    async fn note_observed_turn(&self, frame: &serde_json::Value) -> Result<(), LiveError> {
        let Some(next) = self.rollover.note(frame) else {
            return Ok(());
        };
        let rolled = if self.rollover.fresh_due(next) {
            match self.rollover.callback() {
                Some(callback) => callback(next)
                    .await
                    .map_err(|detail| LiveError::unavailable("fresh_handoff", detail)),
                None => Err(LiveError::unavailable(
                    "fresh_handoff",
                    "no fresh handoff is installed",
                )),
            }
        } else {
            self.roll_context().await
        };
        match rolled {
            Ok(()) => {
                if self.rollover.fresh_due(next) {
                    self.rollover.release();
                } else {
                    self.rollover.commit(next);
                }
                Ok(())
            }
            Err(error) => {
                self.rollover.release();
                Err(error)
            }
        }
    }
}
