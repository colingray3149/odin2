use std::sync::Arc;

use odin_domain::huginn as live;
use odin_domain::{CommandId, Digest};
use odin_ledger::command::{
    AcceptedCommand, CommandOutcome as LedgerCommandOutcome, CommandSpec, CommandTerminalStatus,
    RecordCommand,
};
use time::OffsetDateTime;

use super::protocol::{conflict, unavailable};
use super::{AuthenticatedCallGuard, BrowserCommandCoordinator, JournalDisposition};

impl BrowserCommandCoordinator {
    pub(super) fn admit_authenticated_call(
        &self,
    ) -> Result<AuthenticatedCallGuard, live::HuginnProtocolError> {
        let mut state = self
            .admission
            .state
            .lock()
            .map_err(|_| unavailable("browserCommandAdmission"))?;
        if !state.open {
            return Err(unavailable("browserCommandShutdown"));
        }
        if state.in_flight >= self.admission.limit.get() {
            return Err(live::HuginnProtocolError::ResourceLimit {
                limit: "browserInFlightCommands".to_owned(),
            });
        }
        state.in_flight += 1;
        drop(state);
        Ok(AuthenticatedCallGuard {
            admission: Arc::clone(&self.admission),
        })
    }

    pub(super) async fn close_admission_and_wait(&self) -> Result<(), live::HuginnProtocolError> {
        loop {
            let notified = self.admission.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let drained = {
                let mut state = self
                    .admission
                    .state
                    .lock()
                    .map_err(|_| unavailable("browserCommandAdmission"))?;
                state.open = false;
                state.in_flight == 0
            };
            if drained {
                return Ok(());
            }
            notified.await;
        }
    }

    pub(super) fn existing_action_command(
        &self,
        command_id: &CommandId,
        arguments_hash: &Digest,
        target_id: &str,
        expected_desired_revision: i64,
    ) -> Result<Option<live::HuginnResponse>, live::HuginnProtocolError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("browserLedgerLock"))?;
        ledger
            .command(command_id)
            .map_err(|_| unavailable("browserCommandJournal"))?
            .map(|stored| {
                Self::duplicate_response_for_binding(
                    &stored,
                    command_id,
                    arguments_hash,
                    target_id,
                    Some(expected_desired_revision),
                )
            })
            .transpose()
    }

    pub(super) fn existing_command(
        &self,
        spec: &CommandSpec,
    ) -> Result<Option<live::HuginnResponse>, live::HuginnProtocolError> {
        let ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("browserLedgerLock"))?;
        ledger
            .command(&spec.id)
            .map_err(|_| unavailable("browserCommandJournal"))?
            .map(|stored| Self::duplicate_response(&stored, spec))
            .transpose()
    }

    fn duplicate_response(
        stored: &odin_ledger::command::Command,
        spec: &CommandSpec,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        Self::duplicate_response_for_binding(
            stored,
            &spec.id,
            &spec.arguments_hash,
            &spec.target_id,
            spec.expected_desired_revision,
        )
    }

    fn duplicate_response_for_binding(
        stored: &odin_ledger::command::Command,
        command_id: &CommandId,
        arguments_hash: &Digest,
        target_id: &str,
        expected_desired_revision: Option<i64>,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        if &stored.arguments_hash != arguments_hash
            || stored.target_id.as_str() != target_id
            || stored.expected_desired_revision != expected_desired_revision
        {
            return Err(conflict(
                "commandIdReuse",
                "command ID is already bound to different browser arguments",
            ));
        }
        let prior_outcome = stored
            .terminal_result
            .clone()
            .and_then(|value| serde_json::from_value(value).ok())
            .map(Box::new);
        Ok(live::HuginnResponse::Command(
            live::CommandReceipt::Duplicate {
                command_id: command_id.clone(),
                prior_outcome,
            },
        ))
    }

    pub(super) fn journal(
        &self,
        spec: CommandSpec,
    ) -> Result<JournalDisposition, live::HuginnProtocolError> {
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("browserLedgerLock"))?;
        match ledger
            .record_command(&spec)
            .map_err(|_| unavailable("browserCommandJournal"))?
        {
            RecordCommand::Existing(recorded) => Ok(JournalDisposition::Duplicate(
                Self::duplicate_response(recorded.command(), &spec)?,
            )),
            RecordCommand::Inserted(recorded) => {
                let revision = recorded.command().revision;
                let accepted = ledger
                    .accept_command(&recorded, revision, OffsetDateTime::now_utc())
                    .map_err(|_| unavailable("browserCommandAccept"))?;
                Ok(JournalDisposition::Accepted(accepted))
            }
        }
    }

    pub(super) fn complete_command(
        &self,
        accepted: &AcceptedCommand,
        status: CommandTerminalStatus,
        outcome: live::CommandOutcome,
    ) -> Result<(), live::HuginnProtocolError> {
        let result =
            serde_json::to_value(outcome).map_err(|_| unavailable("browserCommandOutcome"))?;
        let mut ledger = self
            .ledger
            .lock()
            .map_err(|_| unavailable("browserLedgerLock"))?;
        ledger
            .complete_command(
                accepted,
                &LedgerCommandOutcome { status, result },
                accepted.command().revision,
                OffsetDateTime::now_utc(),
            )
            .map_err(|_| unavailable("browserCommandComplete"))?;
        Ok(())
    }
}
