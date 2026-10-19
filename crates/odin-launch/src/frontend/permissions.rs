//! Match client decisions to outstanding requests so stale replies cannot authorize later actions.

use super::*;

impl<T: HuginnTransport, K: DeviceCredentialStore> Frontend<T, K> {
    pub(super) async fn on_client_response(&mut self, message: Message) -> Result<(), ()> {
        let Some(numeric) = message.id.as_ref().and_then(Value::as_u64) else {
            return Ok(());
        };
        let decision = message
            .result
            .as_ref()
            .and_then(|result| {
                serde_json::from_value::<RequestPermissionResult>(result.clone()).ok()
            })
            .and_then(|result| result.decision());
        let holder = self
            .sessions
            .iter()
            .find(|(_, session)| {
                session.permission_out.contains_key(&numeric)
                    || session.approval_out.contains_key(&numeric)
            })
            .map(|(key, _)| key.clone());
        let Some(session_key) = holder else {
            return Ok(());
        };
        let binding = {
            let session = self
                .sessions
                .get_mut(&session_key)
                .expect("session present");
            session
                .permission_out
                .remove(&numeric)
                .map(LiveOrKernel::Live)
                .or_else(|| {
                    session
                        .approval_out
                        .remove(&numeric)
                        .map(LiveOrKernel::Kernel)
                })
        };
        match binding {
            Some(LiveOrKernel::Live(binding)) => {
                if let Err(error) = self.decide_live_permission(&session_key, binding, decision) {
                    tracing::error!(%error, "permission decision failed");
                }
            }
            Some(LiveOrKernel::Kernel(binding)) => {
                if let Err(error) = self.decide_kernel_approval(&session_key, binding, decision) {
                    tracing::error!(%error, "approval decision failed");
                }
            }
            None => {}
        }
        Ok(())
    }
    /// A malformed answer denies permission because no consent was given.
    fn decide_live_permission(
        &mut self,
        session_key: &str,
        binding: LivePermission,
        decision: Option<DecidedPermission>,
    ) -> Result<(), String> {
        let decision = decision.unwrap_or(DecidedPermission::Deny);
        let decision_command = command_id()?;
        let command = {
            let session = self
                .sessions
                .get_mut(session_key)
                .ok_or_else(|| "session vanished before the decision".to_owned())?;
            if binding.epoch != session.epoch
                || !session
                    .pending_permissions
                    .get(&binding.request_id)
                    .is_some_and(|request| request.expires_at > time::OffsetDateTime::now_utc())
            {
                return Err("the displayed permission is stale or expired".to_owned());
            }
            let command = live::LiveCommand {
                command_id: decision_command,
                session_id: session.facts.live_session,
                expected_epoch: binding.epoch,
                expected_event_head: None,
                body: live::LiveCommandBody::DecidePermission {
                    request_id: binding.request_id,
                    decision: match decision {
                        DecidedPermission::AllowOnce => live::PermissionDecision::AllowOnce,
                        DecidedPermission::Deny => live::PermissionDecision::Deny,
                    },
                },
            };
            if let Some(turn) = session.turn.as_mut() {
                turn.decision_commands.push(command.command_id.clone());
            }
            command
        };
        let live_session = command.session_id;
        self.send_tracked(live_session, command);
        Ok(())
    }

    /// Use the displayed approval revision so a stale answer cannot decide a changed request.
    fn decide_kernel_approval(
        &mut self,
        session_key: &str,
        binding: KernelApproval,
        decision: Option<DecidedPermission>,
    ) -> Result<(), String> {
        let decision = decision.unwrap_or(DecidedPermission::Deny);
        let command = {
            let session = self
                .sessions
                .get_mut(session_key)
                .ok_or_else(|| "session vanished before the decision".to_owned())?;
            if binding.epoch != session.epoch {
                return Err("the displayed approval belongs to an older session epoch".to_owned());
            }
            if !matches!(
                session.state,
                live::LiveSessionState::Idle
                    | live::LiveSessionState::Running
                    | live::LiveSessionState::RequiresAction
            ) {
                // The approval expired while the client was deciding.
                return Ok(());
            }
            let expected_revision = u64::try_from(binding.revision).map_err(|_| {
                format!("approval {} revision is out of range", binding.approval_id)
            })?;
            let command = live::LiveCommand {
                command_id: command_id()?,
                session_id: session.facts.live_session,
                expected_epoch: binding.epoch,
                expected_event_head: None,
                body: live::LiveCommandBody::DecideApproval {
                    approval_id: binding.approval_id,
                    expected_revision,
                    decision: match decision {
                        DecidedPermission::AllowOnce => live::ApprovalDecision::Approve,
                        DecidedPermission::Deny => live::ApprovalDecision::Reject,
                    },
                },
            };
            if let Some(turn) = session.turn.as_mut() {
                turn.decision_commands.push(command.command_id.clone());
            }
            command
        };
        let live_session = command.session_id;
        self.send_tracked(live_session, command);
        Ok(())
    }
}

enum LiveOrKernel {
    Live(LivePermission),
    Kernel(KernelApproval),
}

pub(super) fn numeric_outgoing(counter: &mut u64) -> u64 {
    *counter += 1;
    *counter
}

pub(super) fn permission_ask(
    session: &mut Session,
    permission: &live::PermissionRequest,
    next_outgoing_id: &mut u64,
    session_key: &str,
) -> Message {
    let request_id = numeric_outgoing(next_outgoing_id);
    let payload = acp::request_permission(
        session_key,
        &permission.tool_use_id,
        permission.capability_id.as_str(),
        acp::tool_kind(permission.capability_id.as_str()),
        None,
    );
    session.permission_out.insert(
        request_id,
        LivePermission {
            request_id: permission.request_id.clone(),
            epoch: session.epoch,
        },
    );
    Message::request(json!(request_id), "session/request_permission", payload)
}

pub(super) fn outstanding_permission_asks(
    session: &mut Session,
    next_outgoing_id: &mut u64,
    session_key: &str,
) -> Vec<Message> {
    let mut asks = Vec::new();
    let asked: BTreeSet<live::PermissionRequestId> = session
        .permission_out
        .values()
        .map(|binding| binding.request_id.clone())
        .collect();
    let now = time::OffsetDateTime::now_utc();
    let mut outstanding = Vec::new();
    for permission in session.pending_permissions.values() {
        if asked.contains(&permission.request_id) || permission.expires_at <= now {
            continue;
        }
        outstanding.push(permission.clone());
    }
    for permission in &outstanding {
        asks.push(permission_ask(
            session,
            permission,
            next_outgoing_id,
            session_key,
        ));
    }
    asks
}

/// A failed scoped read must not expose approvals from another session.
pub(super) fn kernel_approval_asks(
    session: &mut Session,
    approvals: &ApprovalsReader,
    next_outgoing_id: &mut u64,
    session_key: &str,
) -> Vec<Message> {
    let mut asks = Vec::new();
    let rows = match approvals(session.facts.live_session) {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                session = %session_key,
                %error,
                "durable approvals could not be proven"
            );
            Vec::new()
        }
    };
    for row in rows {
        if !session.shown_kernel.insert(row.approval_id.clone()) {
            continue;
        }
        let Ok(approval_id) = ApprovalId::new(row.approval_id.clone()) else {
            continue;
        };
        let request_id = numeric_outgoing(next_outgoing_id);
        let payload = acp::request_permission(
            session_key,
            &row.approval_id,
            &row.capability_id,
            "other",
            Some(json!({
                "target": format!("{} {}", row.target_kind, row.target_id),
                "argumentsDigest": row.arguments_digest,
            })),
        );
        session.approval_out.insert(
            request_id,
            KernelApproval {
                approval_id,
                revision: row.revision,
                epoch: session.epoch,
            },
        );
        asks.push(Message::request(
            json!(request_id),
            "session/request_permission",
            payload,
        ));
    }
    asks
}
