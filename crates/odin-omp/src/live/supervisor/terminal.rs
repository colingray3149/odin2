use std::sync::Arc;

use odin_domain::huginn::LiveError;

use super::LiveSupervisor;
use crate::live::ledger::live_error;
use crate::live::target::{
    validate_target_name, TerminalTargetAdmin, TerminalTargetSnapshot, TerminalTargetStatus,
};

impl LiveSupervisor {
    /// Explicitly binds the operator chat target: the Zellij session that
    /// hosts the persistent visible tabs. The admin verifies the session is
    /// currently live before binding; nothing is guessed and no session is
    /// ever created to make the target resolve.
    pub async fn bind_terminal_target(
        &self,
        zellij_session: String,
    ) -> Result<TerminalTargetStatus, LiveError> {
        validate_target_name(&zellij_session)?;
        self.terminal_admin()?
            .register_chat_target(zellij_session)
            .await
    }

    /// Drops the chat registration, restoring the declared selector (or an
    /// unbound state). Clearing without a registration is not an error.
    pub async fn clear_terminal_target(&self) -> Result<TerminalTargetStatus, LiveError> {
        self.terminal_admin()?.clear_chat_target().await
    }

    /// Current terminal target binding, without live verification.
    pub async fn terminal_target_status(&self) -> Result<TerminalTargetStatus, LiveError> {
        Ok(self.terminal_admin()?.terminal_target_status().await)
    }

    /// Resolves the effective terminal target and verifies it is live.
    pub async fn terminal_target(&self) -> Result<TerminalTargetSnapshot, LiveError> {
        self.terminal_admin()?.resolve_target().await
    }

    /// Captures one bounded read-only screen dump of the resolved live
    /// terminal target. Read-only: no input injection, no command
    /// execution, and an unresolvable target is a typed unavailability.
    pub async fn capture_terminal_screen(
        &self,
        session: &str,
        max_bytes: usize,
    ) -> Result<crate::live::target::TerminalScreenCapture, LiveError> {
        self.terminal_admin()?
            .capture_screen(session, max_bytes)
            .await
    }

    /// Bounded durable history read over the live ledger; the same source
    /// the wire history surface serves.
    pub async fn history(
        &self,
        query: odin_domain::huginn::HistoryQuery,
    ) -> Result<odin_domain::huginn::HistoryPage, LiveError> {
        self.ledger.history(query).await.map_err(live_error)
    }

    fn terminal_admin(&self) -> Result<Arc<dyn TerminalTargetAdmin>, LiveError> {
        self.launcher
            .terminal_target_admin()
            .ok_or_else(|| LiveError::Unavailable {
                code: "terminal_target_admin_unwired".to_owned(),
            })
    }
}
