//! Shared command replay and journaling; domain controls supply admission checks and mutations.

use std::collections::HashMap;
use std::mem;

use odin_domain::huginn::{
    CommandExecutionState, CommandFailure, CommandOutcome, CommandReceipt, CommandStatus,
    HuginnProtocolError,
};
use odin_domain::CommandId;
use time::OffsetDateTime;

/// Maps a protocol error onto the failure code table shared by every control surface.
pub(crate) fn failure_from_error(error: &HuginnProtocolError) -> CommandFailure {
    let (code, retryable) = match error {
        HuginnProtocolError::UnsupportedVersion { .. } => ("unsupportedVersion", false),
        HuginnProtocolError::InvalidRequest { code, .. } => (code.as_str(), false),
        HuginnProtocolError::Unauthenticated => ("unauthenticated", false),
        HuginnProtocolError::Unauthorized => ("unauthorized", false),
        HuginnProtocolError::NotFound { .. } => ("notFound", false),
        HuginnProtocolError::RevisionMismatch { .. } => ("revisionMismatch", false),
        HuginnProtocolError::Conflict { code, .. } => (code.as_str(), false),
        HuginnProtocolError::CursorExpired => ("cursorExpired", false),
        HuginnProtocolError::ResourceLimit { .. } => ("resourceLimit", false),
        HuginnProtocolError::Unsupported { .. } => ("unsupported", false),
        HuginnProtocolError::Unavailable { code } => (code.as_str(), true),
    };
    CommandFailure {
        code: code.to_string(),
        message: error.to_string(),
        retryable,
    }
}

/// In-memory outcomes keyed by command ID and statuses drained by the service layer.
pub(crate) struct ControlJournal {
    outcomes: HashMap<CommandId, CommandOutcome>,
    statuses: Vec<CommandStatus>,
}

impl ControlJournal {
    pub(crate) fn new() -> Self {
        Self {
            outcomes: HashMap::new(),
            statuses: Vec::new(),
        }
    }

    /// Records a rejected verdict and returns the error unchanged for the caller.
    pub(crate) fn journal_rejected(
        &mut self,
        command_id: &CommandId,
        at: OffsetDateTime,
        error: HuginnProtocolError,
    ) -> HuginnProtocolError {
        let outcome = CommandOutcome::Failed {
            command_id: command_id.clone(),
            error: failure_from_error(&error),
        };
        self.outcomes.insert(command_id.clone(), outcome.clone());
        self.statuses.push(CommandStatus {
            command_id: command_id.clone(),
            state: CommandExecutionState::Rejected,
            updated_at: at,
            outcome: Some(outcome),
        });
        error
    }

    pub(crate) fn journal_completed(&mut self, command_id: &CommandId, at: OffsetDateTime) {
        let outcome = CommandOutcome::Applied {
            command_id: command_id.clone(),
        };
        self.outcomes.insert(command_id.clone(), outcome.clone());
        self.statuses.push(CommandStatus {
            command_id: command_id.clone(),
            state: CommandExecutionState::Completed,
            updated_at: at,
            outcome: Some(outcome),
        });
    }

    pub(crate) fn outcome(&self, command_id: &CommandId) -> Option<&CommandOutcome> {
        self.outcomes.get(command_id)
    }

    pub(crate) fn drain_statuses(&mut self) -> Vec<CommandStatus> {
        mem::take(&mut self.statuses)
    }
}

impl Default for ControlJournal {
    fn default() -> Self {
        Self::new()
    }
}

/// Domain admission checks and mutations wrapped by shared replay and journaling.
pub(crate) trait DomainControl {
    type Command<'a>;

    /// Command ID whose journal entry governs idempotent replay.
    fn command_id(command: &Self::Command<'_>) -> CommandId;

    fn journal(&mut self) -> &mut ControlJournal;

    /// Runs this domain's admission gates and verb table. Every gate rejection and every
    /// post-admission failure returns `Err` without touching the journal; the core
    /// records the verdict. `Ok` means the command mutated domain state.
    fn run(
        &mut self,
        command: &Self::Command<'_>,
        at: OffsetDateTime,
    ) -> Result<(), HuginnProtocolError>;
}

/// Replays duplicate outcomes without rerunning admission checks; journals each new outcome.
pub(crate) fn execute_command<D: DomainControl>(
    control: &mut D,
    command: &D::Command<'_>,
    at: OffsetDateTime,
) -> Result<CommandReceipt, HuginnProtocolError> {
    let command_id = D::command_id(command);
    if let Some(prior_outcome) = control.journal().outcome(&command_id).cloned() {
        return Ok(CommandReceipt::Duplicate {
            command_id,
            prior_outcome: Some(Box::new(prior_outcome)),
        });
    }
    match control.run(command, at) {
        Ok(()) => {
            control.journal().journal_completed(&command_id, at);
            Ok(CommandReceipt::Accepted { command_id })
        }
        Err(error) => Err(control.journal().journal_rejected(&command_id, at, error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubCommand {
        id: CommandId,
    }

    struct StubControl {
        journal: ControlJournal,
        gate_open: bool,
    }

    impl StubControl {
        fn new(gate_open: bool) -> Self {
            Self {
                journal: ControlJournal::new(),
                gate_open,
            }
        }
    }

    impl DomainControl for StubControl {
        type Command<'a> = StubCommand;

        fn command_id(command: &StubCommand) -> CommandId {
            command.id.clone()
        }

        fn journal(&mut self) -> &mut ControlJournal {
            &mut self.journal
        }

        fn run(
            &mut self,
            _command: &StubCommand,
            _at: OffsetDateTime,
        ) -> Result<(), HuginnProtocolError> {
            if !self.gate_open {
                return Err(HuginnProtocolError::Conflict {
                    code: "stubGate".to_string(),
                    message: "stub gate closed".to_string(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn execute_post_admission_failure_journals_outcome_and_replays_duplicate() {
        let mut control = StubControl::new(false);
        let command_id = CommandId::new("cmd-stub-fail-1").unwrap();
        let command = StubCommand {
            id: command_id.clone(),
        };
        let at = OffsetDateTime::now_utc();

        let err = execute_command(&mut control, &command, at).unwrap_err();
        assert!(matches!(err, HuginnProtocolError::Conflict { .. }));

        // Even after the failure clears, the duplicate replays the journaled rejection.
        control.gate_open = true;
        match execute_command(&mut control, &command, at).unwrap() {
            CommandReceipt::Duplicate {
                command_id: duplicate_id,
                prior_outcome,
            } => {
                assert_eq!(duplicate_id, command_id);
                assert!(matches!(
                    prior_outcome.as_deref(),
                    Some(CommandOutcome::Failed { .. })
                ));
            }
            other => panic!("expected Duplicate receipt, got {other:?}"),
        }
        let statuses = control.journal.drain_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].command_id, command_id);
        assert_eq!(statuses[0].state, CommandExecutionState::Rejected);

        // A fresh command executes and its duplicate replays the applied outcome.
        let applied_id = CommandId::new("cmd-stub-apply-1").unwrap();
        let applied = StubCommand {
            id: applied_id.clone(),
        };
        match execute_command(&mut control, &applied, at).unwrap() {
            CommandReceipt::Accepted { command_id } => {
                assert_eq!(command_id, applied_id);
            }
            other => panic!("expected Accepted receipt, got {other:?}"),
        }
        match execute_command(&mut control, &applied, at).unwrap() {
            CommandReceipt::Duplicate { prior_outcome, .. } => {
                assert!(matches!(
                    prior_outcome.as_deref(),
                    Some(CommandOutcome::Applied { .. })
                ));
            }
            other => panic!("expected Duplicate receipt, got {other:?}"),
        }
        let statuses = control.journal.drain_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].command_id, applied_id);
        assert_eq!(statuses[0].state, CommandExecutionState::Completed);
    }
}
