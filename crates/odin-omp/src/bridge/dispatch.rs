//! Journaled command dispatch and frame entry: queued correlation
//! replies, durable journaling before any wire send, and the routing of
//! one decoded frame into response, side-channel, confirmation, or
//! event handling.

use super::*;

impl Shared {
    /// Correlates one response frame: verifies the exact id+command pair,
    /// journals the response evidence, completes the command exactly once,
    /// and resolves the waiter. A mismatch is durable evidence but never a
    /// completion: the ambiguous journal row blocks later mutating work.
    async fn on_response(&self, frame: DecodedRpcFrame) -> Result<ObservedFrame, BridgeError> {
        let value = frame.value();
        let wire_id = value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let command = value
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let success = value.get("success").and_then(Value::as_bool);
        let data = value.get("data").cloned().unwrap_or(Value::Null);
        let error = value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let code = value.get("code").and_then(Value::as_str).map(str::to_owned);
        let taken = if wire_id.is_empty() {
            None
        } else {
            shared_lock(&self.correlation, "correlation")?.take_pending(&wire_id)
        };

        match taken {
            Some(pending) if pending.command == command && success.is_some() => {
                let accepted = success == Some(true);
                let outcome = if accepted {
                    json!({
                        "kind": "command_response",
                        "command_id": pending.command_id.to_string(),
                        "command": command,
                        "success": true,
                        "data": data,
                    })
                } else {
                    json!({
                        "kind": "command_response",
                        "command_id": pending.command_id.to_string(),
                        "command": command,
                        "success": false,
                        "error": error,
                        "code": code,
                    })
                };
                let mut observed = ObservedFrame::decoded(
                    FrameClass::Response,
                    frame,
                    Some(pending.command_id.clone()),
                );
                if let Err(failure) = self.append_event(outcome.clone()).await {
                    self.mark_failed(&format!("response evidence append failed: {failure}"))?;
                    return Ok(observed);
                }
                if let Err(failure) = self.complete_command(&pending.command_id, outcome).await {
                    self.mark_failed(&format!("command completion failed: {failure}"))?;
                    return Ok(observed);
                }
                shared_lock(&self.correlation, "correlation")?.finish_response(
                    &pending.command_id,
                    &pending.command,
                    accepted,
                );
                // The typed rejection reaches an Awaited caller through
                // the correlated waiter. An Observed dispatch (the
                // open-loop prompt) owns no waiter — its receiver may
                // already be dropped — so the annotation rides the frame
                // and the session journal records it. An UNMATCHED
                // rejection never reaches this arm at all: it stays
                // unannotated `response_unmatched` evidence and can never
                // type a session terminal. Annotation precedes publish so
                // the journal, evidence window, and every subscriber see
                // the same typed frame, exactly once.
                if !accepted && pending.delivery == ReplyDelivery::Observed {
                    observed.journal_failure = Some(TypedFrameFailure {
                        code: code
                            .clone()
                            .unwrap_or_else(|| format!("{command}_rejected")),
                        detail: error
                            .clone()
                            .unwrap_or_else(|| "the model backend rejected the prompt".to_owned()),
                        epoch: self.annotation_epoch(),
                    });
                }
                self.publish(&observed)?;
                let reply = if accepted {
                    Ok(data)
                } else {
                    Err(BridgeError::CommandFailed {
                        command: command.clone(),
                        error: error.unwrap_or_else(|| "unspecified failure".to_owned()),
                        code,
                    })
                };
                let _ = pending.reply.send(reply);
                Ok(observed)
            }
            Some(pending) => {
                let got = if success.is_none() && pending.command == command {
                    format!("{command} (missing boolean success)")
                } else {
                    command
                };
                let outcome = json!({
                    "kind": "response_mismatch",
                    "command_id": pending.command_id.to_string(),
                    "expected": pending.command,
                    "got": got,
                });
                let mut observed = ObservedFrame::decoded(
                    FrameClass::Response,
                    frame,
                    Some(pending.command_id.clone()),
                );
                if let Err(failure) = self.append_event(outcome).await {
                    self.mark_failed(&format!("mismatch evidence append failed: {failure}"))?;
                    return Ok(observed);
                }
                shared_lock(&self.correlation, "correlation")?.finish(&pending.command_id);
                self.block_command(pending.command_id.clone())?;
                // The typed mismatch reaches an Awaited caller through the
                // correlated waiter. An Observed dispatch (the open-loop
                // prompt path) owns no waiter — its receiver may even be
                // dropped only after this response already arrived — so the
                // annotation is decided by the dispatch-time delivery mode,
                // never by receiver timing: the failure rides the frame and
                // the session journal records it.
                let expected = pending.command.clone();
                let _ = pending.reply.send(Err(BridgeError::ResponseMismatch {
                    expected: expected.clone(),
                    got: got.clone(),
                }));
                if pending.delivery == ReplyDelivery::Observed {
                    observed.journal_failure = Some(TypedFrameFailure {
                        code: "response_mismatch".to_owned(),
                        detail: format!(
                            "response/command mismatch: expected `{expected}`, got `{got}`"
                        ),
                        epoch: self.annotation_epoch(),
                    });
                }
                self.publish(&observed)?;
                Ok(observed)
            }
            None => {
                let outcome = json!({
                    "kind": "response_unmatched",
                    "wire_id": wire_id,
                    "command": command,
                });
                let observed = ObservedFrame::decoded(FrameClass::Response, frame, None);
                if let Err(failure) = self.append_event(outcome).await {
                    self.mark_failed(&format!(
                        "unmatched-response evidence append failed: {failure}"
                    ))?;
                    return Ok(observed);
                }
                self.publish(&observed)?;
                Ok(observed)
            }
        }
    }

    fn associated_command(
        &self,
        frame: &DecodedRpcFrame,
    ) -> Result<Option<CommandId>, BridgeError> {
        let wire_id = frame
            .value()
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let correlation = shared_lock(&self.correlation, "correlation")?;
        if !wire_id.is_empty() {
            if let Some(command_id) = correlation.associated(wire_id) {
                return Ok(Some(command_id));
            }
        }
        Ok(correlation.active_mutating())
    }

    /// Reserves request count and bytes before cloning arguments or spawning work.
    /// Rejected requests get an immediate terminal frame without retained state.
    pub(super) async fn observe_decoded(
        self: &Arc<Self>,
        frame: DecodedRpcFrame,
    ) -> Result<(ObservedFrame, Option<Value>), BridgeError> {
        let class = classify_frame(frame.value());
        // Token frames are one per streamed token. The request is already in
        // the transcript; reading it here would open a remote tail on every token.
        let skip_ingest = class == FrameClass::Session
            && frame.value().get("type").and_then(Value::as_str) == Some("message_update");
        let recorded = self.observe_class(class, frame).await?;
        if !skip_ingest {
            if let Err(error) = self.ingest_model_requests().await {
                tracing::error!("odind: model-request ingest did not run: {error}");
            }
        }
        Ok(recorded)
    }

    async fn observe_class(
        self: &Arc<Self>,
        class: FrameClass,
        frame: DecodedRpcFrame,
    ) -> Result<(ObservedFrame, Option<Value>), BridgeError> {
        match class {
            FrameClass::Response => Ok((self.on_response(frame).await?, None)),
            FrameClass::HostTool | FrameClass::HostUri => {
                let associated = self.associated_command(&frame)?;
                let frame_type = frame.value().get("type").and_then(Value::as_str);
                let is_cancel = matches!(
                    frame_type,
                    Some("host_tool_cancel") | Some("host_uri_cancel")
                );
                let preparation = if is_cancel {
                    self.cancel_side_call(frame.value())?;
                    SidePreparation::Ignored
                } else {
                    self.prepare_side_call(&frame, class)?
                };
                let observed = ObservedFrame::decoded(class, frame, associated);
                let recorded = self.record_observation(&observed).await.is_ok();
                let immediate = match preparation {
                    SidePreparation::Ignored => None,
                    SidePreparation::Rejected {
                        request_id,
                        kind,
                        detail,
                    } => Some(side_result_frame(
                        &request_id,
                        kind,
                        &side_error_result(kind, detail),
                    )),
                    SidePreparation::Prepared(prepared) if recorded => {
                        if let Err((prepared, _)) = self.start_side_call(prepared) {
                            self.abandon_prepared_side_call(
                                *prepared,
                                "side-channel admission closed before dispatch",
                            )
                            .await?;
                        }
                        None
                    }
                    SidePreparation::Prepared(prepared) => {
                        self.abandon_prepared_side_call(
                            *prepared,
                            "side-channel request was not durably journaled",
                        )
                        .await?;
                        None
                    }
                };
                Ok((observed, immediate))
            }
            FrameClass::ExtensionUi => {
                let immediate = self.extension_ui_immediate_reply(frame.value())?;
                let associated = self.associated_command(&frame)?;
                let observed = ObservedFrame::decoded(class, frame, associated);
                self.record_observation(&observed).await?;
                Ok((observed, immediate))
            }
            FrameClass::ExtensionError => {
                let associated = self.associated_command(&frame)?;
                let mut observed = ObservedFrame::decoded(class, frame, associated);
                // Authenticate refusal against the launch artifact, event schema, and current turn.
                // Other extension errors remain generic rather than ending the session.
                //
                // Authentication runs BEFORE the observation is recorded:
                // the journaled event, the evidence window, and every live
                // subscriber (the supervisor's ingest pump) must see the
                // SAME annotated frame. Recording an unannotated clone
                // first would broadcast a generic extension error and
                // leave the typed terminal invisible on the subscribe
                // path; annotating after a second record would duplicate
                // the evidence. Exactly one annotated record.
                if let Some(failure) = self.authenticate_context_refusal(&observed)? {
                    observed.journal_failure = Some(failure);
                }
                self.record_observation(&observed).await?;
                Ok((observed, None))
            }
            class => {
                let associated = self.associated_command(&frame)?;
                let observed = ObservedFrame::decoded(class, frame, associated);
                self.record_observation(&observed).await?;
                if let Some(value) = observed.value() {
                    shared_lock(&self.correlation, "correlation")?.settle_frame(value);
                    match value.get("type").and_then(Value::as_str) {
                        Some("agent_end") => self.note_session_turn(value),
                        Some("auto_compaction_end") => self.open_context_epoch(),
                        _ => {}
                    }
                }
                Ok((observed, None))
            }
        }
    }

    pub(super) async fn observe_rejected(
        &self,
        rejection: RpcFrameError,
    ) -> Result<ObservedFrame, BridgeError> {
        let observed = ObservedFrame::rejected(rejection);
        self.record_observation(&observed).await?;
        Ok(observed)
    }

    /// Authenticates the context-refusal marker contract of the trusted
    /// extension guard. EVERY check is host-side; the frame's self-
    /// reported fields are evidence, never trust roots:
    /// 1. the exact trusted extension artifact of this child's launch
    ///    argv (`--trusted-extension`), compared by exact identity —
    ///    never a path suffix;
    /// 2. the pinned `before_provider_request` event name;
    /// 3. the strict marker schema — closed code set, non-empty reason,
    ///    typed numerics; arbitrary provider/plugin error text can never
    ///    satisfy it;
    /// 4. a LIVE turn anchor of the CURRENT binding (the frame attaches
    ///    to an in-flight turn command), and the annotation records that
    ///    binding epoch — a stale-incarnation frame attaches to nothing
    ///    and can never type this incarnation's terminal.
    ///
    /// Any failed check yields `None`: the caller keeps the generic
    /// extension-error path — an honest Uncertain, never a typed refusal
    /// and never a successful terminal.
    fn authenticate_context_refusal(
        &self,
        observed: &ObservedFrame,
    ) -> Result<Option<TypedFrameFailure>, BridgeError> {
        let Some(value) = observed.value() else {
            return Ok(None);
        };
        let Some(trusted) = trusted_extension_from_args(&self.process_spec.explicit_args) else {
            return Ok(None);
        };
        if value.get("extensionPath").and_then(Value::as_str) != Some(trusted.as_str()) {
            return Ok(None);
        }
        if value.get("event").and_then(Value::as_str) != Some("before_provider_request") {
            return Ok(None);
        }
        let Some(command_id) = observed.active_command.clone() else {
            return Ok(None);
        };
        let anchored =
            shared_lock(&self.correlation, "correlation")?.active_turn_anchor(&command_id);
        if !anchored {
            return Ok(None);
        }
        let Some(refusal) = parse_context_refusal(value) else {
            return Ok(None);
        };
        // The binding epoch is bridge-authority state validated at start
        // and reclaim; an unconvertible value here is a typed bridge
        // failure, never a silently degraded annotation (a None epoch
        // would let the normalizer skip its stale-epoch check).
        let epoch =
            u64::try_from(self.binding_snapshot()?.epoch).map_err(|_| BridgeError::Config {
                detail: "context refusal authentication found a binding epoch outside \
                         the durable session epoch range"
                    .to_owned(),
            })?;
        let epoch = Some(odin_domain::huginn::SessionEpoch::new(epoch));
        Ok(Some(TypedFrameFailure {
            code: format!("context_refusal.{}", refusal.code),
            detail: refusal.reason,
            epoch,
        }))
    }
    /// The current binding's epoch as a typed session epoch for frame
    /// annotations; `None` only when the binding cannot be read or its
    /// epoch is outside the durable session epoch range.
    fn annotation_epoch(&self) -> Option<odin_domain::huginn::SessionEpoch> {
        self.binding_snapshot()
            .ok()
            .and_then(|binding| u64::try_from(binding.epoch).ok())
            .map(odin_domain::huginn::SessionEpoch::new)
    }

    /// Journaled command dispatch: the state the lifecycle gate must cover,
    /// ending at the acknowledged pump write. Callers hold the gate; the
    /// correlated response is awaited separately through
    /// [`Shared::await_dispatched`]. `delivery` is chosen here, before the
    /// wire write: awaited callers receive typed failures through the
    /// waiter; observed (open-loop) dispatches annotate them on the frame.
    pub(super) async fn dispatch(
        &self,
        command: &str,
        frame: Value,
        kind: InFlightKind,
        delivery: ReplyDelivery,
    ) -> Result<DispatchedCommand, BridgeError> {
        let binding = self.binding_snapshot()?;
        let command_id = self.mint_command_id(&binding);
        self.dispatch_identified(command_id, command, frame, kind, delivery)
            .await
    }

    pub(super) async fn dispatch_identified(
        &self,
        command_id: CommandId,
        command: &str,
        frame: Value,
        kind: InFlightKind,
        delivery: ReplyDelivery,
    ) -> Result<DispatchedCommand, BridgeError> {
        self.ensure_dispatchable(command)?;
        match (self.status()?, kind) {
            (BridgeStatus::Stopped, _) => return Err(BridgeError::Stopped),
            (BridgeStatus::Failed { reason }, _) => {
                return Err(BridgeError::ProcessDown { detail: reason })
            }
            (BridgeStatus::Starting, InFlightKind::Mutating) => {
                return Err(BridgeError::NotReady {
                    state: "starting".to_owned(),
                })
            }
            _ => {}
        }
        let wire_id = command_id.to_string();
        let frame = with_request_id(frame, &wire_id);
        if let Err(error) = self.journal_command(&command_id, command, &frame).await {
            self.mark_failed(&format!("command journal failed: {error}"))?;
            return Err(error);
        }

        let generation = self.generation.load(Ordering::Acquire);
        let (ack_tx, ack_rx) = oneshot::channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        let registered = {
            let mut correlation = shared_lock(&self.correlation, "correlation")?;
            correlation.register(
                wire_id.clone(),
                command,
                command_id.clone(),
                reply_tx,
                kind,
                delivery,
            )
        };
        if !registered {
            return Err(BridgeError::Config {
                detail: format!("wire request id `{wire_id}` collided before dispatch"),
            });
        }
        let write = self
            .pump_tx
            .send(PumpMessage::Send {
                generation,
                frame,
                ack: ack_tx,
            })
            .await;
        if write.is_err() {
            shared_lock(&self.correlation, "correlation")?.cancel(&wire_id);
            return Err(BridgeError::ChannelClosed);
        }
        match ack_rx.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                shared_lock(&self.correlation, "correlation")?.cancel(&wire_id);
                return Err(error);
            }
            Err(_) => {
                shared_lock(&self.correlation, "correlation")?.cancel(&wire_id);
                return Err(BridgeError::ChannelClosed);
            }
        }
        Ok(DispatchedCommand {
            command_id,
            reply: reply_rx,
        })
    }

    /// Resolves one dispatched command from its correlated response.
    pub(super) async fn await_dispatched(
        dispatched: DispatchedCommand,
    ) -> Result<CommandReceipt, BridgeError> {
        match dispatched.reply.await {
            Ok(Ok(data)) => Ok(CommandReceipt {
                command_id: dispatched.command_id,
                data,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(BridgeError::ProcessDown {
                detail: "response channel dropped before the command completed".to_owned(),
            }),
        }
    }

    pub(super) fn ensure_dispatchable(&self, command: &str) -> Result<(), BridgeError> {
        if MUTATING_COMMANDS.contains(&command) {
            let blocked = self.blocked_snapshot()?;
            if !blocked.is_empty() {
                return Err(BridgeError::BlockedIncomplete { commands: blocked });
            }
        }
        Ok(())
    }

    /// Dispatch path for callers already holding the lifecycle gate
    /// (`checkpoint`, recovery registration, and rollover reinjection).
    pub(super) async fn execute_already_gated(
        &self,
        command: &str,
        frame: Value,
        kind: InFlightKind,
    ) -> Result<CommandReceipt, BridgeError> {
        let dispatched = self
            .dispatch(command, frame, kind, ReplyDelivery::Awaited)
            .await?;
        Shared::await_dispatched(dispatched).await
    }
}
