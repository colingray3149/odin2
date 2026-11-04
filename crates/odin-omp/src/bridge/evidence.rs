//! Durable observation fan-out shared by every recorded frame.

use super::*;

impl Shared {
    /// Records one observation durably, then onto the broadcast
    /// fan-out. A streaming token update is not durable. If durability fails,
    /// no subscriber is told that an undurable observation was committed.
    pub(super) async fn record_observation(
        &self,
        observed: &ObservedFrame,
    ) -> Result<(), BridgeError> {
        if ephemeral_token_update(observed) {
            // Live subscribers still receive the original frame. The token row is not durable.
            self.publish(observed);
            return Ok(());
        }
        let body = match (&observed.decoded, &observed.rejection) {
            (Some(frame), _) => json!({
                "kind": observed.class.as_str(),
                "active_command": observed.active_command.as_ref().map(|id| id.to_string()),
                "frame": frame.value(),
            }),
            (None, Some(rejection)) => json!({
                "kind": FrameClass::RpcFrameError.as_str(),
                "error": rejection.kind().to_string(),
                "evidence": rejection
                    .evidence()
                    .iter()
                    .map(|line| base64::engine::general_purpose::STANDARD.encode(line))
                    .collect::<Vec<_>>(),
            }),
            (None, None) => json!({"kind": observed.class.as_str()}),
        };
        if let Err(error) = self.append_event(body).await {
            self.mark_failed(&format!("live-event append failed: {error}"))?;
            return Err(error);
        }
        self.publish(observed);
        Ok(())
    }

    /// Fan-out after durability: one send on the bounded broadcast channel.
    pub(super) fn publish(&self, observed: &ObservedFrame) {
        let _ = self.observations.send(observed.clone());
    }

    /// Publishes the startup frames the process boundary consumed — the
    /// ready frame, any auxiliary frames interleaved inside the negotiation
    /// window, and the negotiation response — in exact arrival order, before
    /// any runtime frame is fanned out. They are startup observations, not
    /// live command responses, so they bypass runtime correlation while
    /// retaining their exact physical evidence. The frames arrive as owned
    /// copies extracted from the single-owner process: publishing never
    /// holds the process borrow across a suspension point.
    pub(super) async fn record_process_startup(
        &self,
        startup: Vec<ObservedFrame>,
    ) -> Result<(), BridgeError> {
        for observed in &startup {
            self.record_observation(observed).await?;
        }
        Ok(())
    }
}
