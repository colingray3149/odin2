//! Native confirmation binding: the current-generation table of
//! unanswered `extension_ui_request` confirm dialogs and their
//! physical-write-acknowledged resolution.

use super::*;

pub(super) struct ConfirmationRequest {
    generation: u64,
    expires_at: OffsetDateTime,
    answer: Option<bool>,
}

impl Shared {
    /// Computes the immediate wire reply (if any) demanded by one
    /// `extension_ui_request` before durable observation: the
    /// generation-bound admission of a `confirm` dialog, the typed
    /// cancellation of unsupported text/choice input, or nothing.
    pub(super) fn extension_ui_immediate_reply(
        &self,
        value: &Value,
    ) -> Result<Option<Value>, BridgeError> {
        match value.get("method").and_then(Value::as_str) {
            Some("confirm") => {
                let id =
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| BridgeError::Config {
                            detail: "confirmation request has no identity".to_owned(),
                        })?;
                odin_domain::huginn::PermissionRequestId::new(id).map_err(|error| {
                    BridgeError::Config {
                        detail: error.to_string(),
                    }
                })?;
                let generation = self.generation.load(Ordering::Acquire);
                let mut side = self.side_guard()?;
                side.confirmations
                    .retain(|_, request| request.generation == generation);
                if !side.admission_open
                    || side.confirmations.len() >= SIDE_CHANNEL_HISTORY_CAP
                    || side.confirmations.contains_key(id)
                {
                    return Err(BridgeError::Config {
                        detail: "confirmation admission is closed, full, or duplicated".to_owned(),
                    });
                }
                side.confirmations.insert(
                    id.to_owned(),
                    ConfirmationRequest {
                        generation,
                        expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(5),
                        answer: None,
                    },
                );
                Ok(None)
            }
            Some("select" | "input" | "editor") => {
                let id =
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| BridgeError::Config {
                            detail: "unsupported UI request has no identity".to_owned(),
                        })?;
                Ok(Some(
                    json!({ "type": "extension_ui_response", "id": id, "cancelled": true }),
                ))
            }
            _ => Ok(None),
        }
    }

    /// Replies only to an actual outstanding confirmation of this child.
    /// UI responses are a side channel: they receive a pump write ack, not
    /// a normal RPC response. The live control journal owns the decision.
    pub(super) async fn reply_to_confirmation(
        &self,
        request_id: &odin_domain::huginn::PermissionRequestId,
        confirmed: bool,
    ) -> Result<(), BridgeError> {
        let _lifecycle = self.lifecycle.lock().await;
        match self.status()? {
            BridgeStatus::Ready | BridgeStatus::Blocked { .. } => {}
            BridgeStatus::Stopped => return Err(BridgeError::Stopped),
            state => {
                return Err(BridgeError::NotReady {
                    state: format!("{state:?}"),
                })
            }
        }
        let generation = self.generation.load(Ordering::Acquire);
        {
            let side = self.side_guard()?;
            let request =
                side.confirmations
                    .get(request_id.as_str())
                    .ok_or_else(|| BridgeError::Config {
                        detail: "confirmation is not pending on this child".to_owned(),
                    })?;
            if !side.admission_open
                || request.generation != generation
                || request.expires_at <= OffsetDateTime::now_utc()
            {
                return Err(BridgeError::Config {
                    detail: "confirmation binding is stale or expired".to_owned(),
                });
            }
            if request.answer.is_some() {
                return Err(BridgeError::Config {
                    detail: "confirmation was already resolved".to_owned(),
                });
            }
        }
        let (ack, received) = oneshot::channel();
        self.pump_tx.send(PumpMessage::Send {
            generation,
            frame: json!({ "type": "extension_ui_response", "id": request_id.as_str(), "confirmed": confirmed }),
            ack,
        }).await.map_err(|_| BridgeError::ChannelClosed)?;
        received.await.map_err(|_| BridgeError::ChannelClosed)??;
        let mut side = self.side_guard()?;
        let request = side
            .confirmations
            .get_mut(request_id.as_str())
            .ok_or_else(|| BridgeError::ProcessDown {
                detail: "confirmation ownership disappeared after delivery".to_owned(),
            })?;
        request.answer = Some(confirmed);
        Ok(())
    }
}
