//! Authenticated operator recovery of a journaled CFD effect.
use super::RuntimeCommandPort;
use odin_domain::{huginn as live, CapabilityId, Digest};
use odin_ledger::command::{CommandOutcome, CommandSpec, CommandTerminalStatus, RecordCommand};
use odin_types::CorrelationId;
use time::OffsetDateTime;

impl RuntimeCommandPort {
    pub(super) async fn recover_cfd_operation(
        &self,
        device: live::DeviceId,
        command: live::RecoverCfdOperation,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let unavailable = |stage: &'static str, error: String| {
            live::HuginnProtocolError::unavailable(stage, error)
        };
        let factory = self
            .recovery
            .as_ref()
            .ok_or_else(|| {
                unavailable("cfdRecovery", "live operation authority unavailable".into())
            })?
            .clone();
        let now = OffsetDateTime::now_utc();
        let arguments = serde_json::to_value(&command)
            .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?;
        let hash = Digest::hash(
            &serde_json::to_vec(&arguments)
                .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?,
        );
        let spec = CommandSpec {
            id: command.command_id.clone(),
            idempotency_key: command.command_id.to_string(),
            correlation_id: command.operation_id.clone(),
            causation_id: None,
            issuer: device.to_string(),
            approval_id: None,
            target_kind: "operation".into(),
            target_id: command.operation_id.clone(),
            capability_id: CapabilityId::new("operation.recover.cfd")
                .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?,
            capability_version: 1,
            arguments_hash: hash,
            arguments,
            expected_desired_revision: None,
            issued_at: now,
            expires_at: now + time::Duration::minutes(5),
        };
        let (accepted, correlation, already_committed) = {
            let mut ledger = self
                .ledger
                .lock()
                .map_err(|e| unavailable("cfdRecoveryLedger", e.to_string()))?;
            let row = odin_ledger::operation::operation_row_by_id(
                ledger.connection(),
                &command.operation_id,
            )
            .map_err(|e| unavailable("cfdRecoveryJournal", e.to_string()))?
            .ok_or_else(|| unavailable("cfdRecoveryJournal", "operation not found".into()))?;
            if row.effect_state == odin_domain::operation::EffectState::Committed
                && ledger
                    .command(&command.command_id)
                    .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?
                    .is_none()
            {
                return Err(live::HuginnProtocolError::Conflict {
                    code: "operationSettled".into(),
                    message: "operation is already committed".into(),
                });
            }
            let (recorded, replaying) = match ledger
                .record_command(&spec)
                .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?
            {
                RecordCommand::Inserted(recorded) => (recorded, false),
                RecordCommand::Existing(recorded) => {
                    let stored = recorded.command();
                    if stored.arguments_hash != spec.arguments_hash
                        || stored.target_kind != spec.target_kind
                        || stored.target_id != spec.target_id
                        || stored.capability_id != spec.capability_id
                        || stored.issuer != spec.issuer
                    {
                        return Err(live::HuginnProtocolError::Conflict { code: "commandIdReuse".into(), message: "command ID is already bound to different recovery arguments or device".into() });
                    }
                    if stored.terminal_status.is_some() {
                        return Ok(live::HuginnResponse::Command(
                            live::CommandReceipt::Duplicate {
                                command_id: command.command_id,
                                prior_outcome: stored
                                    .terminal_result
                                    .clone()
                                    .and_then(|v| serde_json::from_value(v).ok())
                                    .map(Box::new),
                            },
                        ));
                    }
                    (recorded, true)
                }
            };
            let accepted = ledger
                .accept_command(&recorded, recorded.command().revision, now)
                .map_err(|e| unavailable("cfdRecoveryAccept", e.to_string()))?;
            let correlation = CorrelationId::new(&row.correlation_id)
                .map_err(|e| unavailable("cfdRecoveryJournal", e.to_string()))?;
            (
                accepted,
                correlation,
                replaying && row.effect_state == odin_domain::operation::EffectState::Committed,
            )
        };
        if !already_committed {
            let result = tokio::task::spawn_blocking(move || factory.recover_cfd(&correlation))
                .await
                .map_err(|e| unavailable("cfdRecoveryWorker", e.to_string()))?
                .map_err(|e| unavailable("cfdRecovery", e.to_string()))?;
            if result.state != odin_domain::operation::EffectState::Committed {
                return Err(unavailable(
                    "cfdRecovery",
                    "operation was not committed".into(),
                ));
            }
        }
        let outcome = live::CommandOutcome::Applied {
            command_id: command.command_id.clone(),
        };
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|e| unavailable("cfdRecoveryLedger", e.to_string()))?;
        if let Err(error) = ledger.complete_command(
            &accepted,
            &CommandOutcome {
                status: CommandTerminalStatus::Completed,
                result: serde_json::to_value(&outcome)
                    .map_err(|e| unavailable("cfdRecoveryOutcome", e.to_string()))?,
            },
            accepted.command().revision,
            OffsetDateTime::now_utc(),
        ) {
            let stored = ledger
                .command(&command.command_id)
                .map_err(|e| unavailable("cfdRecoveryCommand", e.to_string()))?;
            if let Some(stored) = stored.filter(|stored| {
                stored.terminal_status == Some(CommandTerminalStatus::Completed)
                    && stored.arguments_hash == spec.arguments_hash
                    && stored.target_kind == spec.target_kind
                    && stored.target_id == spec.target_id
                    && stored.capability_id == spec.capability_id
                    && stored.issuer == spec.issuer
            }) {
                return Ok(live::HuginnResponse::Command(
                    live::CommandReceipt::Duplicate {
                        command_id: command.command_id,
                        prior_outcome: stored
                            .terminal_result
                            .and_then(|value| serde_json::from_value(value).ok())
                            .map(Box::new),
                    },
                ));
            }
            return Err(unavailable("cfdRecoveryComplete", error.to_string()));
        }
        Ok(live::HuginnResponse::Command(
            live::CommandReceipt::Accepted {
                command_id: command.command_id,
            },
        ))
    }
}
