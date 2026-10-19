//! Durable observation fan-out shared by every recorded frame.

use super::*;

impl Shared {
    /// Records one observation durably, then onto the observer/broadcast
    /// fan-out. A streaming token update is not durable. If durability fails,
    /// no subscriber is told that an undurable observation was committed.
    pub(super) async fn record_observation(
        &self,
        observed: &ObservedFrame,
    ) -> Result<(), BridgeError> {
        if ephemeral_token_update(observed) {
            // Live subscribers still receive the original frame. The token row is not durable.
            return self.publish(observed);
        }
        let body = match (&observed.decoded, &observed.rejection) {
            (Some(frame), _) => json!({
                "kind": observed.class.as_str(),
                "active_command": observed.active_command.as_ref().map(|id| id.to_string()),
                "frame": journaled_frame(observed.class, frame.value()),
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
        self.publish(observed)?;
        Ok(())
    }

    /// Fan-out after durability: the typed observers, then the bounded
    /// broadcast channel. With no registered observers the fan-out allocates
    /// nothing. A panicking observer is isolated and removed rather than
    /// taking down the pump.
    pub(super) fn publish(&self, observed: &ObservedFrame) -> Result<(), BridgeError> {
        let observers: Vec<(u64, Arc<dyn BridgeObserver>)> = {
            let registered = shared_lock(&self.observers, "observer")?;
            registered
                .iter()
                .map(|(token, observer)| (*token, Arc::clone(observer)))
                .collect()
        };
        let mut panicked = Vec::new();
        for (token, observer) in observers {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.on_observation(observed);
            }))
            .is_err()
            {
                panicked.push(token);
            }
        }
        if !panicked.is_empty() {
            let mut registered = shared_lock(&self.observers, "observer")?;
            for token in panicked {
                registered.remove(&token);
            }
        }
        let _ = self.observations.send(observed.clone());
        Ok(())
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
