use std::str::FromStr;

use odin_domain::{ApprovalId, CapabilityId, CommandId, Digest};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
use time::OffsetDateTime;

use crate::idempotency::{claim, IdempotencyClaim};
use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandTerminalStatus {
    Completed,
    Failed,
    Blocked,
    Cancelled,
    Expired,
    Rejected,
}

impl CommandTerminalStatus {
    const fn as_db(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
    fn from_db(value: &str) -> LedgerResult<Self> {
        match value {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "blocked" => Ok(Self::Blocked),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "rejected" => Ok(Self::Rejected),
            _ => Err(LedgerError::invalid_data(format!(
                "unknown command terminal status {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandSpec {
    pub id: CommandId,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub issuer: String,
    pub approval_id: Option<ApprovalId>,
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub capability_version: i64,
    pub arguments_hash: Digest,
    pub arguments: Value,
    pub expected_desired_revision: Option<i64>,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Command {
    pub id: CommandId,
    pub revision: i64,
    pub idempotency_key: String,
    pub correlation_id: String,
    pub causation_id: Option<String>,
    pub issuer: String,
    pub approval_id: Option<ApprovalId>,
    pub target_kind: String,
    pub target_id: String,
    pub capability_id: CapabilityId,
    pub capability_version: i64,
    pub arguments_hash: Digest,
    pub arguments: Value,
    pub expected_desired_revision: Option<i64>,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
    pub terminal_status: Option<CommandTerminalStatus>,
    pub terminal_result: Option<Value>,
    pub terminal_at: Option<OffsetDateTime>,
}

/// Created only after the command and its idempotency claim are durable.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordedCommand {
    command: Command,
}
impl RecordedCommand {
    pub const fn command(&self) -> &Command {
        &self.command
    }
}

/// Created only after acceptance is durable, before execution may begin.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedCommand {
    command: Command,
}
impl AcceptedCommand {
    pub const fn command(&self) -> &Command {
        &self.command
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RecordCommand {
    Inserted(RecordedCommand),
    Existing(RecordedCommand),
}
impl RecordCommand {
    pub const fn recorded(&self) -> &RecordedCommand {
        match self {
            Self::Inserted(command) | Self::Existing(command) => command,
        }
    }
    pub fn into_recorded(self) -> RecordedCommand {
        match self {
            Self::Inserted(command) | Self::Existing(command) => command,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommandOutcome {
    pub status: CommandTerminalStatus,
    pub result: Value,
}

impl Ledger {
    /// Returns only after the key claim and command insertion commit together.
    pub fn record_command(&mut self, spec: &CommandSpec) -> LedgerResult<RecordCommand> {
        validate_spec(spec)?;
        let issued_at = encode_utc(spec.issued_at)?;
        let expires_at = encode_utc(spec.expires_at)?;
        let arguments = serde_json::to_string(&spec.arguments)?;
        self.with_tx(|tx| match claim(tx, &spec.idempotency_key, &spec.id, spec.issued_at)? {
            IdempotencyClaim::Inserted => {
                tx.execute(
                    "INSERT INTO commands(command_id, revision, idempotency_key, correlation_id, causation_id, issuer, approval_id, target_kind, target_id, capability_id, capability_version, arguments_hash, arguments_json, expected_desired_revision, issued_at, expires_at) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                    (spec.id.to_string(), &spec.idempotency_key, &spec.correlation_id, &spec.causation_id, &spec.issuer, spec.approval_id.as_ref().map(ToString::to_string), &spec.target_kind, &spec.target_id, spec.capability_id.to_string(), spec.capability_version, spec.arguments_hash.to_string(), &arguments, spec.expected_desired_revision, &issued_at, &expires_at),
                )?;
                Ok(RecordCommand::Inserted(RecordedCommand { command: required_command(tx, &spec.id)? }))
            }
            IdempotencyClaim::Existing { command_id } => Ok(RecordCommand::Existing(RecordedCommand { command: load_command(tx, &command_id)?.ok_or_else(|| LedgerError::invalid_data(format!("idempotency key {:?} names missing command {command_id}", spec.idempotency_key)))? })),
        })
    }

    /// Recovery may replay acceptance without advancing revision; execution still requires durable acceptance.
    pub fn accept_command(
        &mut self,
        recorded: &RecordedCommand,
        expected_revision: i64,
        accepted_at: OffsetDateTime,
    ) -> LedgerResult<AcceptedCommand> {
        let timestamp = encode_utc(accepted_at)?;
        let command_id = &recorded.command.id;
        self.with_tx(|tx| {
            let changed = tx.execute("UPDATE commands SET accepted_at = ?1, revision = revision + 1 WHERE command_id = ?2 AND revision = ?3 AND accepted_at IS NULL AND terminal_status IS NULL", (&timestamp, command_id.to_string(), expected_revision))?;
            if changed == 0 {
                let existing = required_command(tx, command_id)?;
                if existing.accepted_at.is_some() && existing.terminal_status.is_none() {
                    // Return without mutation: the original acceptance may have advanced the caller's revision.
                    return Ok(AcceptedCommand { command: existing });
                }
                return Err(command_mutation_error(tx, command_id, expected_revision, "accept")?);
            }
            Ok(AcceptedCommand { command: required_command(tx, command_id)? })
        })
    }

    pub fn reject_command(
        &mut self,
        recorded: &RecordedCommand,
        expected_revision: i64,
        result: Value,
        rejected_at: OffsetDateTime,
    ) -> LedgerResult<Command> {
        let timestamp = encode_utc(rejected_at)?;
        let result = serde_json::to_string(&result)?;
        let command_id = &recorded.command.id;
        self.with_tx(|tx| {
            let changed = tx.execute("UPDATE commands SET terminal_status = 'rejected', terminal_result_json = ?1, terminal_at = ?2, revision = revision + 1 WHERE command_id = ?3 AND revision = ?4 AND accepted_at IS NULL AND terminal_status IS NULL", (&result, &timestamp, command_id.to_string(), expected_revision))?;
            if changed == 0 { return Err(command_mutation_error(tx, command_id, expected_revision, "reject")?); }
            required_command(tx, command_id)
        })
    }

    pub fn complete_command(
        &mut self,
        accepted: &AcceptedCommand,
        outcome: &CommandOutcome,
        expected_revision: i64,
        completed_at: OffsetDateTime,
    ) -> LedgerResult<Command> {
        if outcome.status == CommandTerminalStatus::Rejected {
            return Err(LedgerError::invalid_data(
                "an accepted command cannot complete as rejected".to_owned(),
            ));
        }
        let timestamp = encode_utc(completed_at)?;
        let result = serde_json::to_string(&outcome.result)?;
        let command_id = &accepted.command.id;
        self.with_tx(|tx| {
            let changed = tx.execute("UPDATE commands SET terminal_status = ?1, terminal_result_json = ?2, terminal_at = ?3, revision = revision + 1 WHERE command_id = ?4 AND revision = ?5 AND accepted_at IS NOT NULL AND terminal_status IS NULL", (outcome.status.as_db(), &result, &timestamp, command_id.to_string(), expected_revision))?;
            if changed == 0 { return Err(command_mutation_error(tx, command_id, expected_revision, "complete")?); }
            required_command(tx, command_id)
        })
    }

    /// Recovery reads acceptance without reaccepting; missing, unaccepted, and terminal rows return `None`.
    pub fn accepted_proof(&self, command_id: &CommandId) -> LedgerResult<Option<AcceptedCommand>> {
        let Some(command) = self.command(command_id)? else {
            return Ok(None);
        };
        if command.accepted_at.is_none() || command.terminal_status.is_some() {
            return Ok(None);
        }
        Ok(Some(AcceptedCommand { command }))
    }

    pub fn command(&self, command_id: &CommandId) -> LedgerResult<Option<Command>> {
        load_command(self.connection(), command_id)
    }

    /// Records the original stable host binding of one journaled command,
    /// once: an identical record is a no-op and a different one is a
    /// conflict that never replaces the original. A command whose named
    /// approval is already consumed gains no binding — its original facts
    /// are either recorded or honestly unknown, never rebuilt from a retry.
    pub fn record_host_command_binding(
        &mut self,
        command_id: &CommandId,
        binding: &Value,
    ) -> LedgerResult<()> {
        if !binding.is_object() {
            return Err(LedgerError::invalid_data(
                "host command binding must be a JSON object".to_owned(),
            ));
        }
        let encoded = serde_json::to_string(binding)?;
        self.with_tx(|tx| {
            let command = required_command(tx, command_id)?;
            if let Some(recorded) = load_host_command_binding(tx, command_id)? {
                return if recorded == *binding {
                    Ok(())
                } else {
                    Err(LedgerError::Conflict(format!(
                        "command {command_id} already records a different host binding"
                    )))
                };
            }
            if let Some(approval_id) = &command.approval_id {
                let consumed = tx
                    .query_row(
                        "SELECT status = 'consumed' FROM approvals WHERE approval_id = ?1",
                        [approval_id.to_string()],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                if consumed {
                    return Err(LedgerError::Conflict(format!(
                        "approval {approval_id} is already consumed; command {command_id} \
                         records no new host binding"
                    )));
                }
            }
            tx.execute(
                "INSERT INTO host_command_bindings(command_id, binding_json) VALUES (?1, ?2)",
                (command_id.to_string(), &encoded),
            )?;
            Ok(())
        })
    }

    pub fn host_command_binding(&self, command_id: &CommandId) -> LedgerResult<Option<Value>> {
        load_host_command_binding(self.connection(), command_id)
    }

    /// Every durable command row in id order. Read-only projection feed:
    /// the Hermes status bus scans the whole row set, so a transition
    /// recorded before its bus tracking step still projects.
    pub fn commands(&self) -> LedgerResult<Vec<Command>> {
        let mut statement = self.connection().prepare(
            "SELECT revision, idempotency_key, correlation_id, causation_id, issuer,
                    approval_id, target_kind, target_id, capability_id, capability_version,
                    arguments_hash, arguments_json, expected_desired_revision, issued_at,
                    expires_at, accepted_at, terminal_status, terminal_result_json, terminal_at,
                    command_id
             FROM commands ORDER BY command_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(19)?, read_command_row(row)?))
        })?;
        rows.map(|row| {
            let (id, raw) = row?;
            let command_id = CommandId::new(id).map_err(|error| {
                LedgerError::invalid_data_caused_by("invalid command id", error)
            })?;
            decode_command(command_id, raw)
        })
        .collect()
    }
}

fn validate_spec(spec: &CommandSpec) -> LedgerResult<()> {
    if spec.idempotency_key.trim().is_empty() {
        return Err(LedgerError::invalid_data(
            "command idempotency key must not be empty".to_owned(),
        ));
    }
    if spec.correlation_id.trim().is_empty()
        || spec.issuer.trim().is_empty()
        || spec.target_kind.trim().is_empty()
        || spec.target_id.trim().is_empty()
    {
        return Err(LedgerError::invalid_data(
            "command correlation, issuer, and target fields must not be empty".to_owned(),
        ));
    }
    if spec.capability_version < 1 {
        return Err(LedgerError::invalid_data(
            "command capability version must be positive".to_owned(),
        ));
    }
    if spec.expires_at <= spec.issued_at {
        return Err(LedgerError::invalid_data(
            "command expiry must follow issuance".to_owned(),
        ));
    }
    Ok(())
}

fn required_command(connection: &Connection, command_id: &CommandId) -> LedgerResult<Command> {
    load_command(connection, command_id)?
        .ok_or_else(|| LedgerError::invalid_data(format!("command {command_id} does not exist")))
}

fn command_mutation_error(
    connection: &Connection,
    command_id: &CommandId,
    expected_revision: i64,
    operation: &str,
) -> LedgerResult<LedgerError> {
    let command = required_command(connection, command_id)?;
    if command.revision != expected_revision {
        return Ok(LedgerError::StaleActor {
            actor: format!("command:{command_id}"),
            expected_revision,
            actual_revision: command.revision,
        });
    }
    Ok(LedgerError::invalid_data(format!(
        "command {command_id} cannot {operation} from its current state"
    )))
}

type RawCommand = (
    i64,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    String,
    String,
    String,
    i64,
    String,
    String,
    Option<i64>,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn read_command_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawCommand> {
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
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
    ))
}

fn load_command(connection: &Connection, command_id: &CommandId) -> LedgerResult<Option<Command>> {
    let raw = connection.query_row("SELECT revision, idempotency_key, correlation_id, causation_id, issuer, approval_id, target_kind, target_id, capability_id, capability_version, arguments_hash, arguments_json, expected_desired_revision, issued_at, expires_at, accepted_at, terminal_status, terminal_result_json, terminal_at FROM commands WHERE command_id = ?1", [command_id.to_string()], read_command_row).optional()?;
    raw.map(|raw| decode_command(command_id.clone(), raw))
        .transpose()
}

fn load_host_command_binding(
    connection: &Connection,
    command_id: &CommandId,
) -> LedgerResult<Option<Value>> {
    connection
        .query_row(
            "SELECT binding_json FROM host_command_bindings WHERE command_id = ?1",
            [command_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| serde_json::from_str(&raw).map_err(LedgerError::from))
        .transpose()
}

fn decode_command(command_id: CommandId, raw: RawCommand) -> LedgerResult<Command> {
    Ok(Command {
        id: command_id,
        revision: raw.0,
        idempotency_key: raw.1,
        correlation_id: raw.2,
        causation_id: raw.3,
        issuer: raw.4,
        approval_id: raw
            .5
            .map(|value| {
                ApprovalId::from_str(&value).map_err(|error| {
                    LedgerError::invalid_data_caused_by("invalid command approval id", error)
                })
            })
            .transpose()?,
        target_kind: raw.6,
        target_id: raw.7,
        capability_id: CapabilityId::from_str(&raw.8).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid command capability id", error)
        })?,
        capability_version: raw.9,
        arguments_hash: Digest::from_str(&raw.10).map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid command arguments hash", error)
        })?,
        arguments: serde_json::from_str(&raw.11)?,
        expected_desired_revision: raw.12,
        issued_at: decode_utc(&raw.13)?,
        expires_at: decode_utc(&raw.14)?,
        accepted_at: raw.15.as_deref().map(decode_utc).transpose()?,
        terminal_status: raw
            .16
            .as_deref()
            .map(CommandTerminalStatus::from_db)
            .transpose()?,
        terminal_result: raw.17.as_deref().map(serde_json::from_str).transpose()?,
        terminal_at: raw.18.as_deref().map(decode_utc).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    use super::{
        CommandOutcome, CommandSpec, CommandTerminalStatus, Ledger, LedgerError, RecordCommand,
    };
    use odin_domain::{CapabilityId, CommandId, Digest};
    use serde_json::json;
    use time::{Duration, OffsetDateTime};

    fn spec() -> CommandSpec {
        CommandSpec {
            id: CommandId::new("command:once").unwrap(),
            idempotency_key: "command-once".to_owned(),
            correlation_id: "correlation:once".to_owned(),
            causation_id: None,
            issuer: "test".to_owned(),
            approval_id: None,
            target_kind: "lane".to_owned(),
            target_id: "lane:test".to_owned(),
            capability_id: CapabilityId::new("capability:test").unwrap(),
            capability_version: 1,
            arguments_hash: Digest::hash(br#"{"work":true}"#),
            arguments: json!({"work": true}),
            expected_desired_revision: Some(1),
            issued_at: OffsetDateTime::UNIX_EPOCH,
            expires_at: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        }
    }

    #[test]
    fn commands_use_one_select_and_preserve_rows_on_every_poll() {
        for count in [0, 1, 8, 32] {
            let mut ledger = Ledger::open_in_memory().unwrap();
            let approval_id = odin_domain::ApprovalId::new("approval:commands").unwrap();
            ledger
                .request_approval(crate::approval::NewApproval {
                    approval_id: approval_id.clone(),
                    issuer: "seat:test".to_owned(),
                    scope: crate::approval::ApprovalScope {
                        target_kind: "lane".to_owned(),
                        target_id: "lane:test".to_owned(),
                        capability_id: spec().capability_id,
                        arguments_digest: spec().arguments_hash,
                    },
                    requested_at: OffsetDateTime::UNIX_EPOCH,
                    expires_at: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
                })
                .unwrap();
            let mut expected = Vec::new();
            // Deliberately insert in reverse ID order, with both null and populated fields.
            for index in (0..count).rev() {
                let mut input = spec();
                input.id = CommandId::new(format!("command:poll-{index:03}")).unwrap();
                input.idempotency_key = format!("poll-{index}");
                input.correlation_id = format!("correlation:poll-{index}");
                input.causation_id = (index % 2 == 0).then(|| "event:cause".to_owned());
                input.approval_id = (index % 2 == 0).then(|| approval_id.clone());
                input.expected_desired_revision = (index % 2 == 0).then_some(7);
                input.capability_version = 3;
                input.arguments = json!({"index": index, "nested": [true, null, "value"]});
                input.arguments_hash = Digest::hash(input.arguments.to_string().as_bytes());
                let recorded = ledger.record_command(&input).unwrap().into_recorded();
                if index % 4 == 0 || index % 4 == 1 {
                    let accepted = ledger
                        .accept_command(&recorded, 1, input.issued_at + Duration::seconds(1))
                        .unwrap();
                    if index % 4 == 0 {
                        ledger
                            .complete_command(
                                &accepted,
                                &CommandOutcome {
                                    status: CommandTerminalStatus::Completed,
                                    result: json!({"result": index}),
                                },
                                2,
                                input.issued_at + Duration::seconds(2),
                            )
                            .unwrap();
                    }
                } else if index % 4 == 2 {
                    ledger
                        .reject_command(
                            &recorded,
                            1,
                            json!({"rejected": index}),
                            input.issued_at + Duration::seconds(3),
                        )
                        .unwrap();
                }
                expected.push(ledger.command(&input.id).unwrap().unwrap());
            }
            expected.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));

            let selects = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&selects);
            // These paths prepare uncached statements, so Select counts each query.
            ledger
                .connection()
                .authorizer(Some(move |context: AuthContext<'_>| {
                    if matches!(context.action, AuthAction::Select) {
                        observed.fetch_add(1, Ordering::Relaxed);
                    }
                    Authorization::Allow
                }));
            for _ in 0..2 {
                selects.store(0, Ordering::Relaxed);
                assert_eq!(ledger.commands().unwrap(), expected);
                assert_eq!(selects.load(Ordering::Relaxed), 1, "row count {count}");
            }

            let mut added = spec();
            added.id = CommandId::new("command:added").unwrap();
            let recorded = ledger.record_command(&added).unwrap().into_recorded();
            expected.insert(0, recorded.command().clone());
            selects.store(0, Ordering::Relaxed);
            assert_eq!(ledger.commands().unwrap(), expected);
            assert_eq!(selects.load(Ordering::Relaxed), 1);

            let accepted = ledger
                .accept_command(&recorded, 1, added.issued_at + Duration::seconds(1))
                .unwrap();
            expected[0] = accepted.command().clone();
            selects.store(0, Ordering::Relaxed);
            assert_eq!(ledger.commands().unwrap(), expected);
            assert_eq!(selects.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn commands_preserve_single_row_decode_errors() {
        for update in [
            "UPDATE commands SET approval_id = 'invalid id'",
            "UPDATE commands SET capability_id = 'invalid id'",
            "UPDATE commands SET arguments_hash = 'invalid digest'",
            "UPDATE commands SET arguments_json = '{'",
            "UPDATE commands SET issued_at = 'invalid time'",
            "UPDATE commands SET accepted_at = 'invalid time'",
            "UPDATE commands SET terminal_result_json = '{'",
            "UPDATE commands SET terminal_at = 'invalid time'",
        ] {
            let mut ledger = Ledger::open_in_memory().unwrap();
            ledger.record_command(&spec()).unwrap();
            ledger.connection().execute(update, []).unwrap();
            let single = ledger.command(&spec().id).unwrap_err();
            let bulk = ledger.commands().unwrap_err();
            assert_eq!(
                std::mem::discriminant(&bulk),
                std::mem::discriminant(&single)
            );
            assert_eq!(bulk.to_string(), single.to_string(), "{update}");
        }

        let mut ledger = Ledger::open_in_memory().unwrap();
        ledger.record_command(&spec()).unwrap();
        ledger
            .connection()
            .execute("UPDATE commands SET command_id = 'invalid id'", [])
            .unwrap();
        assert!(matches!(
            ledger.commands(),
            Err(LedgerError::InvalidData { .. })
        ));
    }

    #[test]
    fn duplicate_terminal_outcome_cannot_replace_the_first() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let recorded = match ledger.record_command(&spec()).unwrap() {
            RecordCommand::Inserted(command) => command,
            RecordCommand::Existing(_) => panic!("first claim must insert"),
        };
        let accepted = ledger
            .accept_command(&recorded, 1, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        ledger
            .complete_command(
                &accepted,
                &CommandOutcome {
                    status: CommandTerminalStatus::Completed,
                    result: json!({"answer": 1}),
                },
                2,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        let error = ledger
            .complete_command(
                &accepted,
                &CommandOutcome {
                    status: CommandTerminalStatus::Failed,
                    result: json!({"answer": 2}),
                },
                2,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            LedgerError::StaleActor {
                expected_revision: 2,
                actual_revision: 3,
                ..
            }
        ));
        let stored = ledger.command(&spec().id).unwrap().unwrap();
        assert_eq!(
            stored.terminal_status,
            Some(CommandTerminalStatus::Completed)
        );
        assert_eq!(stored.terminal_result, Some(json!({"answer": 1})));
    }

    /// Recovery reads accepted, nonterminal commands without accepting them again.
    #[test]
    fn accepted_proof_recovers_only_the_midflight_command() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let recorded = match ledger.record_command(&spec()).unwrap() {
            RecordCommand::Inserted(command) => command,
            RecordCommand::Existing(_) => panic!("first claim must insert"),
        };
        assert!(ledger.accepted_proof(&spec().id).unwrap().is_none());
        let missing = CommandId::new("command:missing").unwrap();
        assert!(ledger.accepted_proof(&missing).unwrap().is_none());
        let accepted = ledger
            .accept_command(&recorded, 1, OffsetDateTime::UNIX_EPOCH)
            .unwrap();
        let recovered = ledger
            .accepted_proof(&spec().id)
            .unwrap()
            .expect("the mid-flight row must recover its acceptance proof");
        assert_eq!(recovered.command().id, accepted.command().id);
        assert_eq!(
            recovered.command().arguments_hash,
            accepted.command().arguments_hash
        );
        ledger
            .complete_command(
                &recovered,
                &CommandOutcome {
                    status: CommandTerminalStatus::Completed,
                    result: json!({"resumed": true}),
                },
                recovered.command().revision,
                OffsetDateTime::UNIX_EPOCH,
            )
            .unwrap();
        assert!(ledger.accepted_proof(&spec().id).unwrap().is_none());
    }
}
