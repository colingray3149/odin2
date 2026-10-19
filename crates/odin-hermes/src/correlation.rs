//! Discord message identities map to ledger idempotency keys and durable conversation tasks.
//! Task creation and key claims share one transaction; replays return the recorded task and outcome.

use parking_lot::Mutex;
use std::fmt;

use odin_domain::{CommandId, Correlation, DomainError, SessionId};
use odin_kernel::{ApprovalDecision, ApprovalGate, DecisionOutcome, KernelError};
use odin_ledger::command::{
    AcceptedCommand, Command, CommandOutcome, CommandSpec, RecordCommand, RecordedCommand,
};
use odin_ledger::Ledger;
use rusqlite::OptionalExtension;
use serde_json::Value;
use time::OffsetDateTime;

pub use crate::ingress::OwnerPairing;

const SURFACE_MIRROR_PREFIX: &str = "command:surface-mirror:";

/// A Discord surface identity: the owner DM channel and the message that
/// carries the intent. Snowflake validation keeps the derived correlation key
/// inside the domain metadata bounds.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscordSurface {
    pub channel_id: String,
    pub message_id: String,
}

impl DiscordSurface {
    pub fn new(
        channel_id: impl Into<String>,
        message_id: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let surface = Self {
            channel_id: channel_id.into(),
            message_id: message_id.into(),
        };
        for (field, value) in [
            ("channel", &surface.channel_id),
            ("message", &surface.message_id),
        ] {
            if value.is_empty()
                || value.len() > 32
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(DomainError::InvalidId {
                    kind: "DiscordSurface",
                    value: format!("{field}: {value:?}"),
                    reason: "must be a non-empty decimal snowflake of at most 32 digits",
                });
            }
        }
        Ok(surface)
    }
}

impl fmt::Display for DiscordSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "discord:v1:{}:{}",
            self.channel_id, self.message_id
        )
    }
}

/// The canonical [`Correlation`] for a Discord intent. The idempotency key is
/// the surface display form; the same intent replayed from Discord always
/// produces the identical key.
pub fn surface_correlation(surface: &DiscordSurface) -> Result<Correlation, DomainError> {
    Correlation::new(surface.to_string())
}

/// The Odin session scope a Discord DM channel projects onto. All intents from
/// one DM channel share one [`SessionId`]; message identity stays in the
/// correlation key.
pub fn surface_session(surface: &DiscordSurface) -> Result<SessionId, DomainError> {
    SessionId::new(format!("discord-dm-{}", surface.channel_id))
}

/// Derives a stable task identity from its idempotency key across restarts.
pub fn identity_from_key(key: &str) -> String {
    let digest = odin_domain::Digest::hash(key.as_bytes());
    let hex = digest.to_string();
    // Strip the `blake3:` prefix, keep 32 hex chars.
    hex[7..39].to_owned()
}

/// Atomically records conversation tasks and idempotency claims in the shared ledger.
pub struct ConversationTaskStore {
    ledger: Mutex<Ledger>,
}

impl ConversationTaskStore {
    pub fn new(ledger: Ledger) -> Self {
        Self {
            ledger: Mutex::new(ledger),
        }
    }
    pub(crate) fn ledger_path(&self) -> Option<std::path::PathBuf> {
        self.ledger
            .lock()
            .connection()
            .path()
            .filter(|path| !path.is_empty() && *path != ":memory:")
            .map(std::path::PathBuf::from)
    }

    /// Records the task and claims its idempotency key atomically. An existing
    /// claim returns the originally recorded command.
    pub fn record_task(
        &self,
        spec: &CommandSpec,
    ) -> Result<RecordCommand, odin_ledger::LedgerError> {
        let mut ledger = self.ledger.lock();
        ledger.record_command(spec)
    }

    /// Records acceptance before execution begins.
    pub fn accept_task(
        &self,
        recorded: &RecordedCommand,
        accepted_at: OffsetDateTime,
    ) -> Result<AcceptedCommand, odin_ledger::LedgerError> {
        let mut ledger = self.ledger.lock();
        ledger.accept_command(recorded, recorded.command().revision, accepted_at)
    }

    /// Records a terminal outcome for an accepted task.
    pub fn settle_task(
        &self,
        accepted: &AcceptedCommand,
        outcome: &CommandOutcome,
        completed_at: OffsetDateTime,
    ) -> Result<Command, odin_ledger::LedgerError> {
        let mut ledger = self.ledger.lock();
        match ledger.complete_command(accepted, outcome, accepted.command().revision, completed_at)
        {
            Ok(settled) => Ok(settled),
            // Live and resumed turns may settle the same task; preserve its first terminal result.
            Err(error) => match ledger.command(&accepted.command().id)? {
                Some(existing) if existing.terminal_status.is_some() => {
                    tracing::info!(
                        task = %existing.id,
                        "odin-hermes: task {} was already settled ({:?}); this settle is a no-op",
                        existing.id, existing.terminal_status
                    );
                    Ok(existing)
                }
                _ => Err(error),
            },
        }
    }

    /// Records a terminal rejection for a task that never began execution.
    pub fn reject_task(
        &self,
        recorded: &RecordedCommand,
        result: Value,
        rejected_at: OffsetDateTime,
    ) -> Result<Command, odin_ledger::LedgerError> {
        let mut ledger = self.ledger.lock();
        ledger.reject_command(recorded, recorded.command().revision, result, rejected_at)
    }

    pub fn task(
        &self,
        command_id: &CommandId,
    ) -> Result<Option<Command>, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        ledger.command(command_id)
    }

    /// Every durable task row, id order. The status bus scans the whole
    /// row set so a transition recorded before its tracking step still
    /// projects.
    pub fn tasks(&self) -> Result<Vec<Command>, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        ledger.commands()
    }

    /// Claims a handled decision message without creating an intent so catch-up cannot admit it again.
    pub fn mark_message_handled(
        &self,
        channel_id: &str,
        message_id: &str,
        now: time::OffsetDateTime,
    ) -> Result<(), odin_ledger::LedgerError> {
        let key = format!("discord:v1:{channel_id}:{message_id}");
        let command = odin_domain::CommandId::new(format!(
            "command:discord-decision:{}",
            identity_from_key(&key)
        ))
        .map_err(|error| {
            odin_ledger::LedgerError::invalid_data_caused_by(
                "invalid discord decision command id",
                error,
            )
        })?;
        let mut ledger = self.ledger.lock();
        let transaction = ledger.connection_mut().transaction()?;
        odin_ledger::idempotency::claim(&transaction, &key, &command, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// The command an owner-channel message was admitted as (an intent or a
    /// decision), if it was.
    pub fn message_claim(
        &self,
        channel_id: &str,
        message_id: &str,
    ) -> Result<Option<CommandId>, odin_ledger::LedgerError> {
        self.claim(&format!("discord:v1:{channel_id}:{message_id}"))
    }

    /// The mirror a surface line was posted as, recorded right after the
    /// post: a retry of the same say reuses it instead of posting again.
    pub fn surface_mirror(
        &self,
        say: &CommandId,
    ) -> Result<Option<String>, odin_ledger::LedgerError> {
        Ok(self
            .claim(&format!("surface-say:v1:{say}"))?
            .and_then(|command| {
                command
                    .as_str()
                    .strip_prefix(SURFACE_MIRROR_PREFIX)
                    .map(str::to_owned)
            }))
    }

    /// Reserves one surface say before its mirror is posted: `false` when it
    /// was reserved before (an earlier attempt may have posted it).
    pub fn reserve_surface_say(
        &self,
        say: &CommandId,
        now: OffsetDateTime,
    ) -> Result<bool, odin_ledger::LedgerError> {
        let mut ledger = self.ledger.lock();
        let transaction = ledger.connection_mut().transaction()?;
        let claim = odin_ledger::idempotency::claim(
            &transaction,
            &format!("surface-say:v1:{say}:reserved"),
            say,
            now,
        )?;
        transaction.commit()?;
        Ok(claim == odin_ledger::idempotency::IdempotencyClaim::Inserted)
    }

    /// Gives back a reservation whose post failed: nothing was posted.
    pub fn release_surface_say(&self, say: &CommandId) -> Result<(), odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        ledger.connection().execute(
            "DELETE FROM idempotency_keys WHERE key = ?1",
            [format!("surface-say:v1:{say}:reserved")],
        )?;
        Ok(())
    }

    /// Records the mirror of one surface say; the first record wins.
    pub fn record_surface_mirror(
        &self,
        say: &CommandId,
        message_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, odin_ledger::LedgerError> {
        let mirror =
            CommandId::new(format!("{SURFACE_MIRROR_PREFIX}{message_id}")).map_err(|error| {
                odin_ledger::LedgerError::invalid_data_caused_by(
                    "invalid surface mirror command id",
                    error,
                )
            })?;
        let mut ledger = self.ledger.lock();
        let transaction = ledger.connection_mut().transaction()?;
        let claim = odin_ledger::idempotency::claim(
            &transaction,
            &format!("surface-say:v1:{say}"),
            &mirror,
            now,
        )?;
        transaction.commit()?;
        Ok(match claim {
            odin_ledger::idempotency::IdempotencyClaim::Inserted => message_id.to_owned(),
            odin_ledger::idempotency::IdempotencyClaim::Existing { command_id } => command_id
                .as_str()
                .strip_prefix(SURFACE_MIRROR_PREFIX)
                .unwrap_or(message_id)
                .to_owned(),
        })
    }

    fn claim(&self, key: &str) -> Result<Option<CommandId>, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        let claimed: Option<String> = ledger
            .connection()
            .query_row(
                "SELECT command_id FROM idempotency_keys WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?;
        claimed
            .map(|command| {
                CommandId::new(command).map_err(|error| {
                    odin_ledger::LedgerError::invalid_data_caused_by(
                        "invalid stored command id",
                        error,
                    )
                })
            })
            .transpose()
    }

    /// Returns the greatest claimed message snowflake for reconnect catch-up.
    pub fn latest_discord_message_id(
        &self,
        channel_id: &str,
    ) -> Result<Option<String>, odin_ledger::LedgerError> {
        let prefix = format!("discord:v1:{channel_id}:");
        let ledger = self.ledger.lock();
        let mut statement = ledger
            .connection()
            .prepare("SELECT key FROM idempotency_keys")?;
        let keys = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut latest: Option<u64> = None;
        for key in keys {
            let key = key?;
            let Some(message_id) = key.strip_prefix(&prefix) else {
                continue;
            };
            if let Ok(snowflake) = message_id.parse::<u64>() {
                if latest.is_none_or(|current| snowflake > current) {
                    latest = Some(snowflake);
                }
            }
        }
        Ok(latest.map(|snowflake| snowflake.to_string()))
    }

    /// Runs one closure against the kernel [`ApprovalGate`] over the same
    /// ledger. All approval authority flows through the existing kernel gate —
    /// the adapter never keeps a parallel decision record.
    pub fn with_approval_gate<T>(
        &self,
        operation: impl FnOnce(&mut ApprovalGate<'_>) -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let mut ledger = self.ledger.lock();
        let mut gate = ApprovalGate::new(&mut ledger);
        operation(&mut gate)
    }

    /// Records the operator's decision on an effect approval through the
    /// kernel gate. Approvals and denials both land in the durable approval
    /// ledger; denials always carry their evidence reference.
    pub fn decide_effect_approval(
        &self,
        approval_id: &odin_domain::ApprovalId,
        expected_revision: i64,
        decision: ApprovalDecision,
        decided_by: &str,
        decided_at: OffsetDateTime,
    ) -> Result<DecisionOutcome, KernelError> {
        self.with_approval_gate(|gate| {
            gate.decide(
                approval_id,
                expected_revision,
                decision,
                decided_by,
                decided_at,
            )
        })
    }
}

impl ConversationTaskStore {
    pub fn idempotency_claim_count(&self) -> Result<u64, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        let count =
            ledger
                .connection()
                .query_row("SELECT COUNT(*) FROM idempotency_keys", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }
}

impl ConversationTaskStore {
    /// Loads one durable approval by id. Approval ids for Discord intents
    /// are deterministic, so a replay can restore its gated binding after a
    /// process restart instead of assuming the request never happened.
    pub fn approval(
        &self,
        approval_id: &odin_domain::ApprovalId,
    ) -> Result<Option<odin_ledger::approval::Approval>, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        ledger.approval(approval_id)
    }

    /// Every durable approval row, id order — the bus projection feed.
    pub fn approvals(
        &self,
    ) -> Result<Vec<odin_ledger::approval::Approval>, odin_ledger::LedgerError> {
        let ledger = self.ledger.lock();
        ledger.approvals()
    }
}
