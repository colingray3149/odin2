//! Append-only, mechanically redacted audit events.

use std::str::FromStr;

use odin_domain::{
    Actor, ArtifactId, CheckpointId, CommandId, EventId, IncidentId, Redaction, Scope,
};
use rusqlite::{params, OptionalExtension, Row, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{decode_utc, encode_utc, Ledger, LedgerError, LedgerResult};

const REDACTED: &str = "[REDACTED]";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "id", rename_all = "camelCase")]
pub enum AuditEvidence {
    Artifact(ArtifactId),
    Event(EventId),
    Command(CommandId),
    Incident(IncidentId),
    Checkpoint(CheckpointId),
}

/// JSON which has already had its declared redaction policy applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedPayload {
    value: Value,
    redaction: Redaction,
}

impl RedactedPayload {
    pub fn new(mut value: Value, redaction: Redaction) -> LedgerResult<Self> {
        redaction.validate().map_err(|error| {
            LedgerError::invalid_data_caused_by("invalid audit redaction", error)
        })?;
        match &redaction {
            Redaction::None => {}
            Redaction::Payload => value = Value::String(REDACTED.to_owned()),
            Redaction::Fields { json_pointers } => {
                for pointer in json_pointers {
                    if let Some(field) = value.pointer_mut(pointer) {
                        *field = Value::String(REDACTED.to_owned());
                    }
                }
            }
        }
        Ok(Self { value, redaction })
    }

    pub const fn value(&self) -> &Value {
        &self.value
    }

    pub const fn redaction(&self) -> &Redaction {
        &self.redaction
    }
}

#[derive(Clone, Debug)]
pub struct NewAuditEvent {
    pub event_id: EventId,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub evidence: Vec<AuditEvidence>,
    pub payload: RedactedPayload,
    pub occurred_at: OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: i64,
    pub event_id: EventId,
    pub kind: String,
    pub actor: Actor,
    pub scope: Scope,
    pub evidence: Vec<AuditEvidence>,
    pub payload: Value,
    pub redaction: Redaction,
    pub occurred_at: OffsetDateTime,
}

impl Ledger {
    pub fn append_audit_event(&self, event: NewAuditEvent) -> LedgerResult<AuditEvent> {
        event
            .actor
            .validate()
            .map_err(|error| LedgerError::invalid_data_caused_by("invalid audit actor", error))?;
        let sequence = self.connection().query_row(
            "INSERT INTO audit_events (
                 event_id, kind, actor_json, scope_json, evidence_refs_json,
                 payload_json, redaction_json, occurred_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             RETURNING sequence",
            params![
                event.event_id.to_string(),
                event.kind,
                serde_json::to_string(&event.actor)?,
                serde_json::to_string(&event.scope)?,
                serde_json::to_string(&event.evidence)?,
                serde_json::to_string(event.payload.value())?,
                serde_json::to_string(event.payload.redaction())?,
                encode_utc(event.occurred_at)?,
            ],
            |row| row.get::<_, i64>(0),
        )?;
        self.audit_event_at_sequence(sequence)?.ok_or_else(|| {
            LedgerError::invalid_data(format!(
                "audit event sequence {sequence} was appended but cannot be read"
            ))
        })
    }

    pub fn audit_event(&self, event_id: &EventId) -> LedgerResult<Option<AuditEvent>> {
        let row = self
            .connection()
            .query_row(AUDIT_SELECT_BY_ID, [event_id.to_string()], audit_row)
            .optional()?;
        row.map(decode_audit_event).transpose()
    }

    pub fn audit_events_after(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> LedgerResult<Vec<AuditEvent>> {
        let limit = i64::try_from(limit).map_err(|error| {
            LedgerError::invalid_data_caused_by("audit query limit exceeds SQLite INTEGER", error)
        })?;
        let mut statement = self.connection().prepare(
            "SELECT sequence, event_id, kind, actor_json, scope_json,
                    evidence_refs_json, payload_json, redaction_json, occurred_at
             FROM audit_events WHERE sequence > ?1 ORDER BY sequence ASC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![after_sequence, limit], audit_row)?;
        rows.map(|row| decode_audit_event(row?)).collect()
    }

    pub fn audit_events_in_scope(
        &self,
        parent_scope: &Scope,
        after_sequence: i64,
        limit: usize,
    ) -> LedgerResult<Vec<AuditEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut statement = self.connection().prepare(
            "SELECT sequence, event_id, kind, actor_json, scope_json,
                    evidence_refs_json, payload_json, redaction_json, occurred_at
             FROM audit_events WHERE sequence > ?1 ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map([after_sequence], audit_row)?;
        let mut events = Vec::with_capacity(limit);
        for row in rows {
            let event = decode_audit_event(row?)?;
            if parent_scope.contains(&event.scope) {
                events.push(event);
                if events.len() == limit {
                    break;
                }
            }
        }
        Ok(events)
    }

    fn audit_event_at_sequence(&self, sequence: i64) -> LedgerResult<Option<AuditEvent>> {
        let row = self
            .connection()
            .query_row(
                "SELECT sequence, event_id, kind, actor_json, scope_json,
                    evidence_refs_json, payload_json, redaction_json, occurred_at
             FROM audit_events WHERE sequence = ?1",
                [sequence],
                audit_row,
            )
            .optional()?;
        row.map(decode_audit_event).transpose()
    }
}

/// Appends one audit event inside an already-open immediate transaction so
/// kernel authority-transition can claim an idempotency key and record the
/// matching audit row atomically. Repeating the same `event_id` is a no-op
/// that returns the original sequence and leaves the original row untouched.
pub fn append_audit_event_in_tx(
    transaction: &Transaction<'_>,
    event: NewAuditEvent,
) -> LedgerResult<i64> {
    event
        .actor
        .validate()
        .map_err(|error| LedgerError::invalid_data_caused_by("invalid audit actor", error))?;
    // The immediate transaction serializes writers. Checking replay before
    // INSERT keeps a duplicate from consuming an AUTOINCREMENT number, which
    // would leave a permanent hole in the sequence.
    let existing: Option<i64> = transaction
        .query_row(
            "SELECT sequence FROM audit_events WHERE event_id = ?1",
            [event.event_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(sequence) = existing {
        return Ok(sequence);
    }
    transaction
        .query_row(
            "INSERT INTO audit_events (
                 event_id, kind, actor_json, scope_json, evidence_refs_json,
                 payload_json, redaction_json, occurred_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             RETURNING sequence",
            params![
                event.event_id.as_str(),
                event.kind,
                serde_json::to_string(&event.actor)?,
                serde_json::to_string(&event.scope)?,
                serde_json::to_string(&event.evidence)?,
                serde_json::to_string(event.payload.value())?,
                serde_json::to_string(event.payload.redaction())?,
                encode_utc(event.occurred_at)?,
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

const AUDIT_SELECT_BY_ID: &str = "SELECT sequence, event_id, kind, actor_json, scope_json,
            evidence_refs_json, payload_json, redaction_json, occurred_at
     FROM audit_events WHERE event_id = ?1";

type AuditRow = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

fn audit_row(row: &Row<'_>) -> rusqlite::Result<AuditRow> {
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
    ))
}

fn decode_audit_event(row: AuditRow) -> LedgerResult<AuditEvent> {
    let (sequence, event_id, kind, actor, scope, evidence, payload, redaction, occurred_at) = row;
    Ok(AuditEvent {
        sequence,
        event_id: EventId::from_str(&event_id).map_err(|error| {
            LedgerError::invalid_data_caused_by(
                format!("invalid audit event identifier {event_id:?}"),
                error,
            )
        })?,
        kind,
        actor: serde_json::from_str(&actor)?,
        scope: serde_json::from_str(&scope)?,
        evidence: serde_json::from_str(&evidence)?,
        payload: serde_json::from_str(&payload)?,
        redaction: serde_json::from_str(&redaction)?,
        occurred_at: decode_utc(&occurred_at)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use odin_domain::{Actor, EventId, Redaction, Scope, SeatId};
    use serde_json::{json, Value};
    use time::OffsetDateTime;

    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{append_audit_event_in_tx, NewAuditEvent, RedactedPayload};
    use crate::Ledger;

    fn temp_path() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "odin-audit-replay-{}-{nonce}.sqlite",
            std::process::id()
        ))
    }

    fn remove_ledger_files(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(name));
        }
    }

    fn allocator(ledger: &Ledger) -> i64 {
        ledger
            .connection()
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(seconds).unwrap()
    }

    fn event(id: &str, occurred_at: i64) -> NewAuditEvent {
        NewAuditEvent {
            event_id: EventId::new(id).unwrap(),
            kind: "lane.observed".to_owned(),
            actor: Actor::Seat {
                seat: SeatId::new("seat-a").unwrap(),
                session: None,
            },
            scope: Scope {
                seat: Some(SeatId::new("seat-a").unwrap()),
                ..Scope::default()
            },
            evidence: Vec::new(),
            payload: RedactedPayload::new(
                json!({"public": "kept", "secret": "never persist"}),
                Redaction::Fields {
                    json_pointers: BTreeSet::from(["/secret".to_owned()]),
                },
            )
            .unwrap(),
            occurred_at: at(occurred_at),
        }
    }

    #[test]
    fn audit_query_is_append_ordered_redacted_and_immutable() {
        let ledger = Ledger::open_in_memory().unwrap();
        ledger.append_audit_event(event("event-b", 20)).unwrap();
        ledger.append_audit_event(event("event-a", 10)).unwrap();

        let events = ledger.audit_events_after(0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_id, EventId::new("event-b").unwrap());
        assert_eq!(events[1].event_id, EventId::new("event-a").unwrap());
        assert_eq!(
            events[0].payload["public"],
            Value::String("kept".to_owned())
        );
        assert_eq!(
            events[0].payload["secret"],
            Value::String("[REDACTED]".to_owned())
        );

        assert!(ledger
            .connection()
            .execute(
                "UPDATE audit_events SET kind = 'tampered' WHERE sequence = 1",
                [],
            )
            .is_err());
        assert!(ledger
            .connection()
            .execute("DELETE FROM audit_events WHERE sequence = 1", [],)
            .is_err());
    }

    #[test]
    fn transactional_replay_keeps_original_row_and_does_not_consume_sequence() {
        let path = temp_path();
        let (original, allocator_before) = {
            let mut ledger = Ledger::open(&path).unwrap();
            ledger
                .with_tx(|tx| append_audit_event_in_tx(tx, event("event-a", 10)))
                .unwrap();
            let sequence = ledger
                .with_tx(|tx| append_audit_event_in_tx(tx, event("event-b", 20)))
                .unwrap();
            assert_eq!(sequence, 2);
            let original = ledger
                .audit_event(&EventId::new("event-b").unwrap())
                .unwrap()
                .unwrap();
            (original, allocator(&ledger))
        };
        assert_eq!(allocator_before, 2);

        let mut ledger = Ledger::open(&path).unwrap();
        let mut replay = event("event-b", 99);
        replay.kind = "lane.replayed".to_owned();
        replay.payload =
            RedactedPayload::new(json!({"public": "different"}), Redaction::None).unwrap();
        let replayed = ledger
            .with_tx(|tx| append_audit_event_in_tx(tx, replay.clone()))
            .unwrap();
        assert_eq!(replayed, original.sequence);
        assert_eq!(allocator(&ledger), allocator_before);

        let again = ledger
            .with_tx(|tx| append_audit_event_in_tx(tx, replay))
            .unwrap();
        assert_eq!(again, original.sequence);
        assert_eq!(allocator(&ledger), allocator_before);
        assert_eq!(
            ledger
                .audit_event(&EventId::new("event-b").unwrap())
                .unwrap()
                .unwrap(),
            original
        );

        let next = ledger
            .with_tx(|tx| append_audit_event_in_tx(tx, event("event-c", 30)))
            .unwrap();
        assert_eq!(next, 3);
        drop(ledger);

        let ledger = Ledger::open(&path).unwrap();
        let events = ledger.audit_events_after(0, 10).unwrap();
        assert!(events.iter().map(|event| event.sequence).eq([1, 2, 3]));
        assert_eq!(allocator(&ledger), 3);
        drop(ledger);
        remove_ledger_files(&path);
    }

    #[test]
    fn replay_inside_the_originating_transaction_is_not_a_second_row() {
        let mut ledger = Ledger::open_in_memory().unwrap();
        let (first, second) = ledger
            .with_tx(|tx| {
                let first = append_audit_event_in_tx(tx, event("event-a", 10))?;
                let second = append_audit_event_in_tx(tx, event("event-a", 11))?;
                Ok((first, second))
            })
            .unwrap();
        assert_eq!((first, second), (1, 1));
        assert_eq!(allocator(&ledger), 1);
        let next = ledger
            .with_tx(|tx| append_audit_event_in_tx(tx, event("event-b", 12)))
            .unwrap();
        assert_eq!(next, 2);
        assert_eq!(ledger.audit_events_after(0, 10).unwrap().len(), 2);
    }
}
