//! Recovery and reconciliation: bounded durable scans, listing-derived
//! (re)registration, journal reconciliation without any resend, and the
//! shared recover mechanics.

use super::*;

/// Hard ceiling for one recovery/checkpoint history scan.
const DURABLE_HISTORY_EVENT_CAP: usize = 65_536;
/// Hard ceiling for decoded durable event bodies retained by one scan.
const DURABLE_HISTORY_BYTE_BUDGET: usize = 64 * 1024 * 1024;
/// Hard ceiling for command rows reconciled in one session.
const DURABLE_COMMAND_CAP: usize = 65_536;

/// The respawn conversation of one recover sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RecoverMode {
    /// Resume the harness's own durable transcript: restart and recovery
    /// keep every prior turn.
    Normal,
    /// A new, empty, fully PERSISTED conversation under the same session
    /// identity: every session selector is stripped from the respawn argv
    /// (both carriers), so the pinned harness's default launch starts a
    /// fresh session whose newer transcript supersedes the oversized one
    /// for every later ordinary recovery, and the rollover's one
    /// continuity brief reinitializes the durable prefix and core.
    FreshContext,
}

pub(super) fn validate_existing_live_session(
    ledger: &Ledger,
    expected: &NewLiveSession,
) -> Result<(), LedgerError> {
    type StoredBinding = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        i64,
    );
    let stored: StoredBinding = ledger.connection().query_row(
        "SELECT seat_id,project_id,slice_id,lane_id,target_node_id,provider,model,\
         title_json,manifest_json,open_tab FROM live_sessions WHERE session_id=?1",
        [expected.session_id.to_string()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        },
    )?;
    let expected_title = expected
        .title
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let expected_manifest = serde_json::to_string(&expected.manifest)?;
    let expected_values = (
        expected.seat_id.as_str(),
        expected.project_id.as_str(),
        expected.slice_id.as_str(),
        expected.lane_id.as_str(),
        expected.target_node_id.as_str(),
        expected.provider.as_str(),
        expected.model.as_str(),
        expected_title.as_deref(),
        expected_manifest.as_str(),
        i64::from(expected.open_tab),
    );
    let stored_values = (
        stored.0.as_str(),
        stored.1.as_str(),
        stored.2.as_str(),
        stored.3.as_str(),
        stored.4.as_str(),
        stored.5.as_str(),
        stored.6.as_str(),
        stored.7.as_deref(),
        stored.8.as_str(),
        stored.9,
    );
    if stored_values != expected_values {
        return Err(LedgerError::Conflict(format!(
            "live session {} is already bound to different immutable host metadata",
            expected.session_id
        )));
    }
    Ok(())
}

/// Retained live history through the captured head, oldest first.
/// Covered token deletes leave sequence gaps; those gaps are not
/// corruption. The scan still refuses a journal past the event-count or
/// body-byte ceiling.
pub(super) fn bounded_live_history(
    ledger: &Ledger,
    session_id: &SessionId,
) -> Result<Vec<LiveEvent>, LedgerError> {
    let captured_head = ledger.reconnect_head(session_id)?;
    let (event_count, body_bytes): (i64, i64) = ledger.connection().query_row(
        "SELECT COUNT(*),COALESCE(SUM(length(CAST(body_json AS BLOB))),0) \
         FROM live_events WHERE session_id=?1 AND sequence<=?2",
        (session_id.to_string(), captured_head),
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if event_count > i64::try_from(DURABLE_HISTORY_EVENT_CAP).unwrap_or(i64::MAX) {
        return Err(LedgerError::invalid_data(format!(
            "session {session_id} history exceeds the {DURABLE_HISTORY_EVENT_CAP}-event scan ceiling"
        )));
    }
    if body_bytes > i64::try_from(DURABLE_HISTORY_BYTE_BUDGET).unwrap_or(i64::MAX) {
        return Err(LedgerError::invalid_data(format!(
            "session {session_id} history exceeds the {DURABLE_HISTORY_BYTE_BUDGET}-byte scan ceiling"
        )));
    }
    // Covered token rows are deleted in place. The remaining rows keep
    // their original sequences, so a gap below the captured head is
    // retained history, not a corrupt journal. The ceilings above still
    // bound the scan.
    ledger.live_event_history(session_id, 0, captured_head)
}

/// The journaled issue and response evidence of exactly the `pending`
/// commands — all reconciliation needs. SQLite streams the session's
/// command events, so memory is bounded by the pending set rather than by
/// the session's age: a long-lived conversation vehicle stays recoverable
/// however large its journal grows.
pub(super) fn pending_command_evidence(
    ledger: &Ledger,
    session_id: &SessionId,
    pending: &BTreeSet<CommandId>,
) -> Result<(BTreeSet<CommandId>, HashMap<CommandId, Value>), LedgerError> {
    let mut issued = BTreeSet::new();
    let mut answered = HashMap::new();
    if pending.is_empty() {
        return Ok((issued, answered));
    }
    let mut statement = ledger.connection().prepare(
        "SELECT json_extract(body_json,'$.kind'),json_extract(body_json,'$.command_id'),body_json \
         FROM live_events WHERE session_id=?1 \
         AND json_extract(body_json,'$.kind') IN ('command_issued','command_response') \
         ORDER BY sequence",
    )?;
    let mut rows = statement.query([session_id.to_string()])?;
    while let Some(row) = rows.next()? {
        let Some(id) = row
            .get::<_, Option<String>>(1)?
            .and_then(|id| CommandId::new(id).ok())
            .filter(|id| pending.contains(id))
        else {
            continue;
        };
        if row.get::<_, String>(0)? == "command_issued" {
            issued.insert(id);
        } else {
            answered.insert(id, serde_json::from_str(&row.get::<_, String>(2)?)?);
        }
    }
    Ok((issued, answered))
}

/// The newest journaled events of a session, oldest first: at most
/// `max_events` and at most the scan byte budget. The rollover brief only
/// renders a recent tail, so it never walks (or refuses) older history.
pub(super) fn live_history_tail(
    ledger: &Ledger,
    session_id: &SessionId,
    max_events: usize,
) -> Result<Vec<LiveEvent>, LedgerError> {
    let head = ledger.reconnect_head(session_id)?;
    let mut cursor = head;
    let mut bytes = 0usize;
    let mut statement = ledger.connection().prepare(
        "SELECT sequence,length(CAST(body_json AS BLOB)) FROM live_events \
         WHERE session_id=?1 AND sequence<=?2 ORDER BY sequence DESC LIMIT ?3",
    )?;
    let mut rows = statement.query((
        session_id.to_string(),
        head,
        i64::try_from(max_events).unwrap_or(i64::MAX),
    ))?;
    while let Some(row) = rows.next()? {
        bytes = bytes.saturating_add(usize::try_from(row.get::<_, i64>(1)?).unwrap_or(usize::MAX));
        if bytes > DURABLE_HISTORY_BYTE_BUDGET {
            break;
        }
        cursor = row.get::<_, i64>(0)? - 1;
    }
    ledger.live_event_history(session_id, cursor, head)
}

pub(super) fn session_commands(
    ledger: &Ledger,
    session_id: &SessionId,
) -> Result<Vec<LiveCommand>, LedgerError> {
    let ids = {
        let mut statement = ledger.connection().prepare(
            "SELECT command_id FROM live_commands WHERE session_id=?1 AND completed_at IS NULL \
             ORDER BY issued_at,command_id LIMIT ?2",
        )?;
        let ids = statement
            .query_map(
                (
                    session_id.to_string(),
                    i64::try_from(DURABLE_COMMAND_CAP + 1).unwrap_or(i64::MAX),
                ),
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        ids
    };
    if ids.len() > DURABLE_COMMAND_CAP {
        return Err(LedgerError::invalid_data(format!(
            "session {session_id} has more than {DURABLE_COMMAND_CAP} command rows; bounded recovery refused"
        )));
    }
    ids.into_iter()
        .map(|id| {
            let id = CommandId::new(id).map_err(|error| {
                LedgerError::invalid_data_caused_by(
                    "live command contains an invalid command id",
                    error,
                )
            })?;
            ledger.live_command(&id)
        })
        .collect()
}

pub(super) fn expected_tool_names(admitted: &BTreeSet<String>) -> Vec<String> {
    admitted.iter().cloned().collect()
}

pub(super) fn expected_scheme_names() -> Vec<String> {
    let mut names: Vec<String> = crate::uri::scheme_definitions()
        .iter()
        .map(|d| d.scheme.as_str().to_owned())
        .collect();
    names.sort();
    names
}

pub(super) fn verify_name_set(
    data: &Value,
    field: &str,
    expected: &[String],
) -> Result<(), BridgeError> {
    let mut actual: Vec<String> = data
        .get(field)
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    actual.sort();
    if actual.len() != expected.len() || actual != expected {
        return Err(BridgeError::Config {
            detail: format!(
                "registration response `{field}` mismatch: expected {expected:?}, got {actual:?}"
            ),
        });
    }
    Ok(())
}

impl Shared {
    pub(super) async fn register_host_tools(&self) -> Result<(), BridgeError> {
        let definitions = self
            .operations
            .admitted_definitions(&self.admitted_host_tools, true)?;
        let tools: Vec<Value> = definitions
            .iter()
            .map(|definition: &RpcHostToolDefinition| {
                let mut shown = definition.clone();
                shown.parameters =
                    crate::host_tools::schema_compat::model_parameters(&definition.parameters);
                serde_json::to_value(&shown).map_err(|error| BridgeError::Serialization {
                    detail: error.to_string(),
                })
            })
            .collect::<Result<_, _>>()?;
        let expected = expected_tool_names(&self.admitted_host_tools);
        let listing_bytes = Value::Array(tools.clone()).to_string().len();
        self.listing_bytes.store(
            u64::try_from(listing_bytes).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let frame = json!({ "type": "set_host_tools", "tools": tools });
        let receipt = self
            .execute_already_gated("set_host_tools", frame, InFlightKind::Informational)
            .await?;
        verify_name_set(&receipt.data, "toolNames", &expected)?;
        Ok(())
    }

    pub(super) async fn register_host_uris(&self) -> Result<(), BridgeError> {
        let schemes: Vec<Value> = crate::uri::scheme_definitions()
            .iter()
            .map(|definition| {
                json!({
                    "scheme": definition.scheme.as_str(),
                    "description": definition.source,
                    "writable": false,
                    "immutable": definition.immutable,
                })
            })
            .collect();
        let frame = json!({ "type": "set_host_uri_schemes", "schemes": schemes });
        let receipt = self
            .execute_already_gated("set_host_uri_schemes", frame, InFlightKind::Informational)
            .await?;
        verify_name_set(&receipt.data, "schemes", &expected_scheme_names())?;
        Ok(())
    }

    /// Reconstructs a checkpoint completion only from one committed,
    /// command-anchored checkpoint and its exact artifact metadata/bytes.
    /// Nothing is sent to the child in this crash-window path.
    async fn committed_checkpoint_completion(
        &self,
        binding: &BridgeBinding,
        command_id: &CommandId,
    ) -> Result<Option<Value>, BridgeError> {
        let command_id = command_id.clone();
        let run_id = binding.run_id.clone();
        let record = self
            .ledger_op(move |ledger| load_committed_checkpoint_anchor(ledger, &command_id, &run_id))
            .await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let artifact_root = self.artifact_root.clone();
        let record = tokio::task::spawn_blocking(move || {
            validate_checkpoint_artifact(&artifact_root, &record)?;
            Ok::<CheckpointRecord, BridgeError>(record)
        })
        .await
        .map_err(|error| BridgeError::Serialization {
            detail: format!("checkpoint recovery validator failed: {error}"),
        })??;
        Ok(Some(checkpoint_completion(&record)))
    }

    /// Walks the session's durable history and closes every journaled
    /// command that durable response evidence can complete — without any
    /// resend. Commands left ambiguous block mutating work.
    pub(super) async fn reconcile(&self) -> Result<(Vec<CommandId>, Vec<CommandId>), BridgeError> {
        let binding = self.binding_snapshot()?;
        let session_id = binding.session_id.clone();
        let (commands, issued, answered) = self
            .ledger_op(move |ledger| {
                let commands = session_commands(ledger, &session_id)?;
                let pending = commands
                    .iter()
                    .filter(|command| command.completed_at.is_none())
                    .map(|command| command.command_id.clone())
                    .collect();
                let (issued, answered) = pending_command_evidence(ledger, &session_id, &pending)?;
                Ok((commands, issued, answered))
            })
            .await?;

        let mut reconciled = Vec::new();
        let mut blocked = Vec::new();
        for row in commands
            .into_iter()
            .filter(|command| command.completed_at.is_none())
        {
            let command_id = row.command_id;
            let command = row
                .body
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let outcome = if !issued.contains(&command_id) {
                Some(json!({
                    "kind": "not_dispatched_before_crash",
                    "command_id": command_id.to_string(),
                    "command": command,
                }))
            } else if let Some(response) = answered.get(&command_id) {
                let exact_command =
                    response.get("command").and_then(Value::as_str) == Some(command.as_str());
                let typed_success = response.get("success").and_then(Value::as_bool).is_some();
                (exact_command && typed_success).then(|| response.clone())
            } else if REGISTRATION_COMMANDS.contains(&command.as_str()) {
                Some(json!({
                    "kind": "superseded_by_re_registration",
                    "command_id": command_id.to_string(),
                    "command": command,
                }))
            } else if command == "checkpoint" {
                self.committed_checkpoint_completion(&binding, &command_id)
                    .await?
            } else {
                None
            };
            if let Some(outcome) = outcome {
                self.complete_command(&command_id, outcome).await?;
                reconciled.push(command_id);
            } else {
                blocked.push(command_id);
            }
        }
        blocked.sort();
        blocked.dedup();
        self.set_blocked(blocked.clone())?;
        Ok((reconciled, blocked))
    }

    /// The recover mechanics shared by the public [`crate::OmpBridge::recover`]
    /// and the internal rollover: close admission, re-assert the lease,
    /// retire the child, reclaim the session epoch (same session id,
    /// epoch + 1), respawn with identity check, re-register, and reconcile
    /// without resend. The caller owns the lifecycle gate. Delegated children
    /// and terminal tabs are never touched here.
    ///
    /// The mode picks the respawn conversation: [`RecoverMode::Normal`]
    /// resumes the harness's own durable transcript (restart and recovery
    /// continuity, unchanged); [`RecoverMode::FreshContext`] strips every
    /// session selector from the respawn argv on BOTH carriers, so the
    /// pinned harness's DEFAULT launch starts a NEW, fully persisted
    /// conversation under the same session identity — the typed
    /// context-refusal rollover's fresh window (`--no-session` would be
    /// `SessionManager.inMemory()`: no transcript at all, and a later
    /// ordinary recovery would resurrect the stale oversized transcript).
    pub(super) async fn recover_sequence(
        &self,
        mode: RecoverMode,
    ) -> Result<RecoveryReport, BridgeError> {
        let binding = self.binding_snapshot()?;
        // Close admission before lease or epoch changes; join admitted effects before replacement.
        self.close_side_admission()?;
        self.set_status(BridgeStatus::Starting)?;

        let recovered = async {
            // 1. Lease re-assertion for the same owner; serialize it against
            //    heartbeat and release updates.
            let lease = {
                let _lease_gate = self.lease_gate.lock().await;
                let lease = acquire_lease_record(&self.ledger, &binding, self.lease_ttl).await?;
                self.set_lease(Some(lease.clone()))?;

                lease
            };
            // Freeze the prior generation and join every admitted side effect
            // before changing the durable epoch. No old-epoch worker or frame
            // can cross the transition.
            let (retire_tx, retire_rx) = oneshot::channel();
            self.pump_tx
                .send(PumpMessage::Terminate {
                    reason: "OMP child retired for recovery".to_owned(),
                    planned: true,
                    ack: retire_tx,
                })
                .await
                .map_err(|_| BridgeError::ChannelClosed)?;
            let _retired = tokio::time::timeout(bridge_stop_budget(&self.process_spec), retire_rx)
                .await
                .map_err(|_| BridgeError::ProcessDown {
                    detail: "timed out retiring the prior OMP child for recovery".to_owned(),
                })?
                .map_err(|_| BridgeError::ChannelClosed)??;
            self.set_status(BridgeStatus::Starting)?;

            // 2. Epoch increment through reclaim.
            let session_id = binding.session_id.clone();
            let epoch = binding.epoch;
            let live = self
                .ledger_op(move |ledger| ledger.reclaim_live_session(&session_id, epoch, now_utc()))
                .await?;
            self.update_binding(|updated| {
                updated.epoch = live.epoch;
                updated.lease_id = Some(lease.lease_id.clone());
                updated.lease_expires_at = Some(lease.expires_at);
            })?;
            self.open_side_admission()?;

            // The previous carrier has stopped; local transcripts resume on the host, pod transcripts in the pod.
            let mut spec = self.process_spec.clone();
            if matches!(mode, RecoverMode::FreshContext) {
                super::api::strip_resume_args(&mut spec.explicit_args);
            }
            let child = match self.transport.as_ref() {
                Some(factory) => {
                    // Reuse launch composition, with session selectors removed for FreshContext.
                    let launch_args: Vec<String> = spec.launch_args().collect();
                    let channel = factory
                        .attach(&launch_args, &spec.explicit_env)
                        .await
                        .map_err(|error| BridgeError::RemoteAttach {
                            detail: error.to_string(),
                        })?;
                    OmpProcess::spawn_remote(
                        spec,
                        self.worker.clone(),
                        channel,
                        factory.job_worker_id().clone(),
                        factory.stop_action(),
                    )
                    .await?
                }
                None => {
                    if mode == RecoverMode::Normal {
                        match resumable_transcript(&spec) {
                            Ok(Some(transcript)) => {
                                set_resume_arg(
                                    &mut spec.explicit_args,
                                    &transcript.to_string_lossy(),
                                );
                            }
                            Ok(None) => {}
                            Err(detail) => {
                                // Continuity that exists but cannot be verified
                                // is a typed recovery failure, never a fresh
                                // conversation.
                                return Err(BridgeError::ProcessDown {
                                    detail: format!("transcript continuity check failed: {detail}"),
                                });
                            }
                        }
                    }
                    spec.establish_identity(&self.worker).await?;
                    OmpProcess::spawn(spec, self.worker.clone()).await?
                }
            };
            let (install_tx, install_rx) = oneshot::channel();
            self.pump_tx
                .send(PumpMessage::Install {
                    process: Box::new(child),
                    ack: install_tx,
                })
                .await
                .map_err(|_| BridgeError::ChannelClosed)?;
            install_rx.await.map_err(|_| BridgeError::ChannelClosed)??;

            // 4–5. Re-register, then reconcile from durable rows+history.
            self.register_host_tools().await?;
            self.register_host_uris().await?;
            let (reconciled, blocked) = self.reconcile().await?;
            self.set_status(if blocked.is_empty() {
                BridgeStatus::Ready
            } else {
                BridgeStatus::Blocked {
                    commands: blocked.clone(),
                }
            })?;
            Ok(RecoveryReport {
                epoch: live.epoch,
                reconciled,
                blocked,
            })
        }
        .await;

        if let Err(error) = &recovered {
            self.close_side_admission()?;
            let reason = format!("recovery failed: {error}");
            self.mark_failed(&reason)?;
            let (ack_tx, ack_rx) = oneshot::channel();
            if self
                .pump_tx
                .send(PumpMessage::Terminate {
                    reason,
                    planned: false,
                    ack: ack_tx,
                })
                .await
                .is_ok()
            {
                let _ = tokio::time::timeout(bridge_stop_budget(&self.process_spec), ack_rx).await;
            }
            // Failed replacement must not leave a phantom ready row.
            let _ = self.finish_live_row(LiveSessionExit::Failed).await;
        }
        recovered
    }
}
