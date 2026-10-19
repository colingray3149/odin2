//! Validate the manifest before exposing replayed content.

use super::permissions::{kernel_approval_asks, outstanding_permission_asks, permission_ask};
use super::*;

impl<T: HuginnTransport, K: DeviceCredentialStore> Frontend<T, K> {
    pub(super) fn on_plane_event(&mut self, event: PlaneEvent) -> Result<(), RpcError> {
        match event {
            PlaneEvent::Subscribed { session } => {
                if let Some(session) = self.session_by_live_mut(session) {
                    session.subscribed = true;
                    session.stream_owed = false;
                }
            }
            PlaneEvent::SubscribeFailed { session, error } => {
                if let Some(session) = self.session_by_live_mut(session) {
                    session.subscribed = false;
                    session.stream_owed = false;
                    if let Some(setup) = session.setup.take() {
                        self.queue_message(Message::failure(
                            setup.acp_request_id,
                            governed(format!("the backend refused the event stream: {error}")),
                        ));
                    }
                }
            }
            PlaneEvent::Unsubscribed => {}
            PlaneEvent::ReplayBegin { session, .. } => {
                if let Some(session) = self.session_by_live_mut(session) {
                    session.in_replay = true;
                }
            }
            PlaneEvent::Event(event) => self.on_live_event(*event),
            PlaneEvent::ReplayComplete { session, .. } => {
                self.on_replay_complete(session);
            }
            PlaneEvent::Disconnected => {
                let resubscribe: Vec<(live::LiveSessionId, live::EventSeq)> = self
                    .sessions
                    .values()
                    // Include pending subscriptions so interrupted setup can complete.
                    .filter(|session| {
                        session.subscribed || session.stream_owed || session.setup.is_some()
                    })
                    .map(|session| (session.facts.live_session, session.cursor))
                    .collect();
                for (session, cursor) in resubscribe {
                    if let Some(session) = self.session_by_live_mut(session) {
                        session.subscribed = false;
                        session.stream_owed = true;
                    }
                    // Replay from current cursors to reconcile unconfirmed commands.
                    self.order_plane(PlaneOrder::Subscribe {
                        session,
                        after: cursor,
                    });
                }
            }
            PlaneEvent::Unreachable { session } => {
                let owed = self
                    .session_by_live_mut(session)
                    .filter(|owed| owed.stream_owed || owed.setup.is_some())
                    .map(|owed| owed.cursor);
                if let Some(after) = owed {
                    self.order_plane(PlaneOrder::Subscribe { session, after });
                }
            }
            PlaneEvent::Failed(error) => {
                return Err(RpcError::new(
                    RpcError::GOVERNED_REFUSAL,
                    format!("the governed backend failed: {error}"),
                ));
            }
        }
        Ok(())
    }

    fn on_live_event(&mut self, event: live::LiveEvent) {
        let session_key = event.session_id.to_string();
        let Some(session) = self.sessions.get_mut(&session_key) else {
            return;
        };
        // Keep the cursor monotonic so reconnect cannot replay already-applied events.
        if event.sequence > session.cursor {
            session.cursor = event.sequence;
        }
        if event.epoch > session.epoch {
            session.epoch = event.epoch;
            session.pending_permissions.clear();
            session.permission_out.clear();
            session.approval_out.clear();
            session.shown_kernel.clear();
        }

        let mut replies: Vec<Message> = Vec::new();
        let mut sends: Vec<live::LiveCommand> = Vec::new();
        let mut asks: Vec<Message> = Vec::new();
        match &event.body {
            live::LiveEventBody::SessionOpened(opened) => {
                session.bind_manifest(&opened.manifest);
            }
            live::LiveEventBody::UserMessage(message) => {
                if session.exposure_allowed() {
                    for chunk in text_chunks(&message.content) {
                        replies.push(Message::notification(
                            "session/update",
                            acp::user_message_chunk(&session_key, &chunk),
                        ));
                    }
                }
            }
            live::LiveEventBody::AssistantDelta(delta) => {
                session.streaming_text = true;
                if session.exposure_allowed() {
                    replies.push(Message::notification(
                        "session/update",
                        acp::agent_message_chunk(&session_key, &safe_text(&delta.text)),
                    ));
                }
            }
            live::LiveEventBody::AssistantMessage(message) => {
                let replay_as_chunks = !session.streaming_text && session.exposure_allowed();
                if replay_as_chunks {
                    for chunk in text_chunks(&message.content) {
                        replies.push(Message::notification(
                            "session/update",
                            acp::agent_message_chunk(&session_key, &chunk),
                        ));
                    }
                }
                session.streaming_text = false;
                session.last_answer = Some(answer_text(&message.content));
            }
            live::LiveEventBody::ToolStarted(started) => {
                if session.exposure_allowed() {
                    replies.push(Message::notification(
                        "session/update",
                        acp::tool_call(
                            &session_key,
                            &started.tool.tool_use_id,
                            started.tool.capability_id.as_str(),
                            acp::tool_kind(started.tool.capability_id.as_str()),
                            "in_progress",
                            Some(started.tool.arguments.clone()),
                            None,
                        ),
                    ));
                }
            }
            live::LiveEventBody::ToolFinished(finished) => {
                if session.exposure_allowed() {
                    replies.push(Message::notification(
                        "session/update",
                        acp::tool_call_update(
                            &session_key,
                            &finished.result.tool_use_id,
                            if finished.result.is_error {
                                "failed"
                            } else {
                                "completed"
                            },
                            Some(tool_result_content(&finished.result.content)),
                        ),
                    ));
                }
                // Kernel R3 approvals surface through failed tools, not RequiresAction transitions.
                if finished.result.is_error && !session.in_replay && session.manifest_ok {
                    asks.extend(outstanding_permission_asks(
                        session,
                        &mut self.next_outgoing_id,
                        &session_key,
                    ));
                    asks.extend(kernel_approval_asks(
                        session,
                        &self.approvals,
                        &mut self.next_outgoing_id,
                        &session_key,
                    ));
                }
            }
            live::LiveEventBody::PermissionRequested(permission)
                if event.epoch == session.epoch =>
            {
                // Delay replayed requests until ReplayComplete filters out resolved permissions.
                session
                    .pending_permissions
                    .insert(permission.request_id.clone(), permission.clone());
                if !session.in_replay
                    && session.manifest_ok
                    && permission.expires_at > time::OffsetDateTime::now_utc()
                {
                    replies.push(permission_ask(
                        session,
                        permission,
                        &mut self.next_outgoing_id,
                        &session_key,
                    ));
                }
            }
            live::LiveEventBody::PermissionResolved(resolution) if event.epoch == session.epoch => {
                session.pending_permissions.remove(&resolution.request_id);
                session
                    .permission_out
                    .retain(|_, binding| binding.request_id != resolution.request_id);
            }
            live::LiveEventBody::Result(result) => {
                // Avoid displaying a final answer twice when Result repeats the assistant message.
                let repeated = result.summary.as_deref().map(str::trim)
                    == session.last_answer.as_deref().map(str::trim);
                if session.exposure_allowed() && !repeated {
                    if let Some(summary) = &result.summary {
                        replies.push(Message::notification(
                            "session/update",
                            acp::agent_message_chunk(&session_key, &safe_text(summary)),
                        ));
                    }
                }
            }
            live::LiveEventBody::Error(error) => {
                tracing::error!(code = %error.code, message = %error.message, "session error");
                if session.exposure_allowed() {
                    replies.push(Message::notification(
                        "session/update",
                        acp::agent_message_chunk(
                            &session_key,
                            &format!(
                                "[error {}] {}",
                                safe_text(&error.code),
                                safe_text(&error.message)
                            ),
                        ),
                    ));
                }
            }
            live::LiveEventBody::ControlAccepted(receipt) => {
                if let Some(reply) = session.apply_receipt(receipt) {
                    replies.push(reply);
                }
            }
            live::LiveEventBody::ControlCompleted(outcome) => {
                if let Some(reply) = session.apply_outcome(outcome) {
                    replies.push(reply);
                }
            }
            live::LiveEventBody::SessionStateChanged(change) if event.epoch == session.epoch => {
                session.state = change.current;
                // Check approvals before completion so a failed tool's idle state cannot end the turn.
                if matches!(
                    change.current,
                    live::LiveSessionState::Idle | live::LiveSessionState::RequiresAction
                ) && !session.in_replay
                    && session.manifest_ok
                {
                    asks.extend(outstanding_permission_asks(
                        session,
                        &mut self.next_outgoing_id,
                        &session_key,
                    ));
                    asks.extend(kernel_approval_asks(
                        session,
                        &self.approvals,
                        &mut self.next_outgoing_id,
                        &session_key,
                    ));
                }
                if matches!(
                    change.current,
                    live::LiveSessionState::Running | live::LiveSessionState::RequiresAction
                ) {
                    // Honor cancellation received before the running-state event arrived.
                    if let Some(turn) = session.turn.as_mut() {
                        if turn.cancel_requested && turn.abort_command.is_none() {
                            match command_id() {
                                Ok(abort_id) => {
                                    turn.abort_command = Some(abort_id.clone());
                                    sends.push(live::LiveCommand {
                                        command_id: abort_id,
                                        session_id: session.facts.live_session,
                                        expected_epoch: session.epoch,
                                        expected_event_head: None,
                                        body: live::LiveCommandBody::Abort {
                                            scope: live::AbortScope::CurrentTurn,
                                        },
                                    });
                                }
                                Err(error) => {
                                    tracing::error!(%error, "abort not sent");
                                }
                            }
                        }
                    }
                }
                if change.current == live::LiveSessionState::Idle {
                    if let Some(reply) = session.take_idle_reply() {
                        replies.push(reply);
                    }
                } else if change.current == live::LiveSessionState::Failed && !session.in_replay {
                    if let Some(turn) = session.turn.take() {
                        replies.push(finish_turn(
                            turn,
                            TurnOutcome::Failed(governed(
                                "the provider failed this turn; a restart was requested. If it \
                                 stays failed, send Restart",
                            )),
                        ));
                    }
                    match command_id() {
                        Ok(restart_id) => {
                            sends.push(live::LiveCommand {
                                command_id: restart_id,
                                session_id: session.facts.live_session,
                                expected_epoch: session.epoch,
                                expected_event_head: None,
                                body: live::LiveCommandBody::Restart,
                            });
                        }
                        Err(error) => {
                            tracing::error!(%error, "restart not sent; send Restart to continue");
                        }
                    }
                } else if matches!(
                    change.current,
                    live::LiveSessionState::Detached | live::LiveSessionState::Ended
                ) {
                    if let Some(turn) = session.turn.take() {
                        replies.push(finish_turn(turn, TurnOutcome::Stopped(acp::STOP_CANCELLED)));
                    }
                }
            }
            live::LiveEventBody::SessionClosed(_) => {
                session.ended = true;
                if let Some(turn) = session.turn.take() {
                    replies.push(finish_turn(turn, TurnOutcome::Stopped(acp::STOP_CANCELLED)));
                }
            }
            _ => {}
        }
        for message in replies {
            self.queue_message(message);
        }
        for message in asks {
            self.queue_message(message);
        }
        for command in sends {
            let live_session = command.session_id;
            self.send_tracked(live_session, command);
        }
    }

    fn on_replay_complete(&mut self, session_id: live::LiveSessionId) {
        let session_key = session_id.to_string();
        let Some(session) = self.sessions.get_mut(&session_key) else {
            return;
        };
        session.in_replay = false;

        // Both setup paths require the durable manifest's seat and project to match configuration.
        if !session.manifest_ok {
            let reason = match &session.manifest {
                Some(manifest) => format!(
                    "session {} is bound to seat {} project {} in durable history, \
                     not the configured seat {} project {}",
                    session_key,
                    manifest.seat_id,
                    manifest.project_id,
                    session.facts.seat,
                    session.facts.project,
                ),
                None => format!(
                    "session {session_key} has no SessionOpened event in its durable \
                     history; the configured binding cannot be re-proven"
                ),
            };
            let setup = session.setup.take();
            self.sessions.remove(&session_key);
            // The rejected binding must not keep a live subscription.
            self.order_plane(PlaneOrder::Unsubscribe {
                session: session_id,
            });
            if let Some(setup) = setup {
                self.queue_message(Message::failure(setup.acp_request_id, governed(reason)));
            }
            return;
        }

        // Wait for replay to finish because later history may leave the Failed state.
        let failed = session.state == live::LiveSessionState::Failed;
        let restart_inflight = session.restart_inflight.clone();
        let restart_pending = restart_inflight.is_some()
            || session
                .unconfirmed
                .iter()
                .any(|command| matches!(command.body, live::LiveCommandBody::Restart));
        let failure_reply = if failed {
            session.turn.take().map(|turn| {
                finish_turn(
                    turn,
                    TurnOutcome::Failed(governed(
                        "the provider failed this turn; a restart was requested. If it \
                         stays failed, send Restart",
                    )),
                )
            })
        } else {
            None
        };
        let restart = if failed && !restart_pending {
            match command_id() {
                Ok(restart_id) => Some(live::LiveCommand {
                    command_id: restart_id,
                    session_id,
                    expected_epoch: session.epoch,
                    expected_event_head: None,
                    body: live::LiveCommandBody::Restart,
                }),
                Err(error) => {
                    tracing::error!(%error, "restart not sent; send Restart to continue");
                    None
                }
            }
        } else {
            None
        };
        let unconfirmed = std::mem::take(&mut session.unconfirmed);
        if let Some(reply) = failure_reply {
            self.queue_message(reply);
        }
        for command in unconfirmed {
            if restart_inflight.as_ref() == Some(&command.command_id) {
                continue;
            }
            self.send_tracked(session_id, command);
        }
        if let Some(command) = restart {
            self.send_tracked(session_id, command);
        }

        if let Some(setup) = self
            .sessions
            .get_mut(&session_key)
            .and_then(|session| session.setup.take())
        {
            let response = match setup.kind {
                SetupKind::New => json!({ "sessionId": session_key }),
                SetupKind::Load => json!({}),
            };
            self.queue_message(Message::success(setup.acp_request_id, response));
        }

        // Surface only the permissions still outstanding after history folded.
        self.surface_outstanding_permissions(&session_key);
    }

    /// Ask only for permissions and approvals that remain unresolved after replay.
    pub(super) fn surface_outstanding_permissions(&mut self, session_key: &str) {
        let asks = {
            let Some(session) = self.sessions.get_mut(session_key) else {
                return;
            };
            if !session.manifest_ok {
                return;
            }
            let mut asks =
                outstanding_permission_asks(session, &mut self.next_outgoing_id, session_key);
            asks.extend(kernel_approval_asks(
                session,
                &self.approvals,
                &mut self.next_outgoing_id,
                session_key,
            ));
            asks
        };
        for message in asks {
            self.queue_message(message);
        }
    }
}

fn answer_text(content: &[live::LiveContentBlock]) -> String {
    content
        .iter()
        .filter_map(|block| match block {
            live::LiveContentBlock::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn text_chunks(content: &[live::LiveContentBlock]) -> Vec<String> {
    content
        .iter()
        .filter_map(|block| match block {
            live::LiveContentBlock::Text(text) => Some(safe_text(text)),
            _ => None,
        })
        .collect()
}

fn tool_result_content(content: &[live::LiveContentBlock]) -> Value {
    let texts: Vec<Value> = content
        .iter()
        .filter_map(|block| match block {
            live::LiveContentBlock::Text(text) => Some(json!({
                "type": "content",
                "content": { "type": "text", "text": safe_text(text) }
            })),
            _ => None,
        })
        .collect();
    Value::Array(texts)
}
