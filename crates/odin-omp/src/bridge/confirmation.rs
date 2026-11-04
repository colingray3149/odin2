//! Native confirmation binding: the current-generation table of
//! unanswered `extension_ui_request` confirm dialogs and their
//! physical-write-acknowledged resolution. The child owns a dialog's
//! timeout; the table keeps a dialog until it is answered or its child
//! generation ends.

use super::*;

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
                    .retain(|_, dialog_generation| *dialog_generation == generation);
                if !side.admission_open || side.confirmations.contains_key(id) {
                    return Err(BridgeError::Config {
                        detail: "confirmation admission is closed or the dialog is duplicated"
                            .to_owned(),
                    });
                }
                side.confirmations.insert(id.to_owned(), generation);
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

    /// Journals a UI response frame the child has already been sent.
    pub(super) async fn journal_ui_response(&self, frame: &Value) -> Result<(), BridgeError> {
        self.append_event(json!({
            "kind": "command_issued",
            "command": "extension_ui_response",
            "frame": frame,
        }))
        .await
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
            let Some(dialog_generation) = side.confirmations.get(request_id.as_str()) else {
                return Err(BridgeError::Config {
                    detail:
                        "confirmation is not pending on this child (unknown or already answered)"
                            .to_owned(),
                });
            };
            if !side.admission_open || *dialog_generation != generation {
                return Err(BridgeError::Config {
                    detail: "confirmation belongs to a child that has since been replaced"
                        .to_owned(),
                });
            }
        }
        let frame = json!({ "type": "extension_ui_response", "id": request_id.as_str(), "confirmed": confirmed });
        let (ack, received) = oneshot::channel();
        self.pump_tx
            .send(PumpMessage::Send {
                generation,
                frame: frame.clone(),
                ack,
            })
            .await
            .map_err(|error| {
                BridgeError::ChannelClosed(format!("sending the confirmation: {error}"))
            })?;
        received.await.map_err(|error| {
            BridgeError::ChannelClosed(format!("awaiting the confirmation ack: {error}"))
        })??;
        if let Err(error) = self.journal_ui_response(&frame).await {
            self.mark_failed(&format!(
                "confirmation response was delivered but not journaled: {error}"
            ))?;
        }
        self.side_guard()?.confirmations.remove(request_id.as_str());
        Ok(())
    }
}
