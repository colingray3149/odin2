//! Domain-separated conversation ids and atomic, fsynced 0600 state writes.

use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use odin_domain::huginn::{AbortScope, LiveCommand, LiveCommandBody, LiveSessionId, SessionEpoch};
use odin_domain::{CommandId, Digest};
use time::OffsetDateTime;

use super::{ConversationRecord, ConversationRoot};

/// The canonical encoding domain for every bounded durable identity this
/// module mints. Fields travel u64-be-length-delimited under a per-class
/// domain tag, so `(a:b, c)` and `(a, b:c)` never collide and any valid
/// declaration yields a bounded id.
const IDENTITY_DOMAIN: &str = "odin-hermes/conversation-root/v1";

pub(super) fn bounded_command(class: &str, fields: &[&str]) -> Result<CommandId, String> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(IDENTITY_DOMAIN.as_bytes());
    encoded.extend_from_slice(b"\0class\0");
    push_length_field(&mut encoded, class.as_bytes());
    for field in fields {
        push_length_field(&mut encoded, field.as_bytes());
    }
    CommandId::new(format!("command:{class}:{}", Digest::hash(&encoded)))
        .map_err(|error| format!("bounded command identity rejected: {error}"))
}

fn push_length_field(encoded: &mut Vec<u8>, field: &[u8]) {
    let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(field);
}

/// Derives the same successor for a predecessor so interrupted transitions reuse its identity.
pub(super) fn successor_vehicle_command(
    conversation_id: &str,
    predecessor_session: &str,
) -> Result<CommandId, String> {
    bounded_command(
        "conversation-vehicle-rollover",
        &[conversation_id, predecessor_session],
    )
}

pub(super) fn conversation_root_identity(seat: &str, project: &str) -> String {
    Digest::hash(&identity_tuple(b"root", seat, project)).to_string()
}

fn identity_tuple(class: &[u8], first: &str, second: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(IDENTITY_DOMAIN.as_bytes());
    push_length_field(&mut encoded, class);
    push_length_field(&mut encoded, first.as_bytes());
    push_length_field(&mut encoded, second.as_bytes());
    encoded
}

pub(super) fn now_unix_ms() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

pub(super) fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

impl ConversationRoot {
    pub(super) fn vehicle_command_id(&self) -> Result<CommandId, String> {
        let identity =
            conversation_root_identity(self.binding.seat_id.as_str(), self.project.as_str());
        bounded_command("conversation-open", &[&identity, "0"])
    }

    /// The governed whole-session retirement command of one predecessor at
    /// its observed epoch and attempt. Attempt 0 is the first abort. A later
    /// attempt is a new command id: a failed or unfinished earlier receipt
    /// is a replay and would never re-run the stop.
    pub(super) fn retirement_command(
        &self,
        session_id: LiveSessionId,
        epoch: u64,
        attempt: u32,
    ) -> Result<LiveCommand, String> {
        let command_id = bounded_command(
            "conversation-vehicle-retirement",
            &[
                &session_id.to_string(),
                &epoch.to_string(),
                &attempt.to_string(),
            ],
        )?;
        Ok(LiveCommand {
            command_id,
            session_id,
            expected_epoch: SessionEpoch::new(epoch),
            expected_event_head: None,
            body: LiveCommandBody::Abort {
                scope: AbortScope::Session,
            },
        })
    }

    pub(super) fn verify_record_binding(&self, record: &ConversationRecord) -> Result<(), String> {
        if record.seat.is_empty() {
            return Ok(());
        }
        if record.seat != self.binding.seat_id.as_str()
            || record.project != self.project.as_str()
            || (!record.conversation_id.is_empty()
                && record.conversation_id != self.conversation_id)
        {
            return Err(format!(
                "the durable conversation record {} names seat {:?} project {:?}, but this root \
                 serves seat {:?} project {:?}; refusing to run a torn composition",
                self.state_path.display(),
                record.seat,
                record.project,
                self.binding.seat_id.as_str(),
                self.project.as_str()
            ));
        }
        Ok(())
    }

    pub(super) fn recorded_vehicle_command(
        &self,
        record: &ConversationRecord,
    ) -> Result<CommandId, String> {
        let raw = record
            .vehicle_command_id
            .clone()
            .ok_or_else(|| "the durable record names no vehicle command identity".to_owned())?;
        CommandId::new(raw)
            .map_err(|error| format!("the recorded vehicle command identity is invalid: {error}"))
    }

    /// Loads the durable record; a fresh root starts empty. A corrupted
    /// record is an error, never a silent reset.
    pub(super) fn load_record(&self) -> Result<ConversationRecord, String> {
        match std::fs::read(&self.state_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|error| {
                format!(
                    "the durable conversation record {} is unreadable: {error}",
                    self.state_path.display()
                )
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ConversationRecord {
                rollover: None,
                conversation_id: self.conversation_id.clone(),
                seat: String::new(),
                project: String::new(),
                vehicle_command_id: None,
                session_id: None,
                in_flight: None,
                wakes: Vec::new(),
                last_idempotency_key: None,
                last_projection: None,
                recent_answers: Vec::new(),
                questions: Vec::new(),
                queued: Vec::new(),
                covered: Vec::new(),
                recovery_failures: 0,
                updated_at_unix_ms: 0,
            }),
            Err(error) => Err(format!(
                "could not read the durable conversation record {}: {error}",
                self.state_path.display()
            )),
        }
    }

    /// Persists the record durably: staging file created NEW with 0600,
    /// fsynced, atomically renamed, parent fsynced. Every failure is
    /// returned — continuation state this authority-adjacent must survive
    /// process death, not merely serde-roundtrip.
    pub(super) fn store_record(&self, record: &mut ConversationRecord) -> Result<(), String> {
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "could not create the conversation state directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        record.remember_answer();
        record.updated_at_unix_ms = now_unix_ms();
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| format!("could not serialize the conversation record: {error}"))?;
        let temp = self
            .state_path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let write = || -> Result<(), String> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
                .map_err(|error| {
                    format!(
                        "could not stage the conversation record {}: {error}",
                        temp.display()
                    )
                })?;
            file.write_all(&bytes).map_err(|error| {
                format!("could not write the staged conversation record: {error}")
            })?;
            file.sync_all().map_err(|error| {
                format!("could not sync the staged conversation record: {error}")
            })?;
            std::fs::rename(&temp, &self.state_path).map_err(|error| {
                format!(
                    "could not commit the conversation record {}: {error}",
                    self.state_path.display()
                )
            })?;
            if let Some(parent) = self.state_path.parent() {
                std::fs::File::open(parent)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|error| {
                        format!("could not sync the conversation state directory: {error}")
                    })?;
            }
            Ok(())
        };
        match write() {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                Err(error)
            }
        }
    }
}
