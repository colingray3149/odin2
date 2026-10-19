//! Brain audit events through the ledger authority.
//!
//! Durable audit belongs to the ledger (`odin_ledger::audit`); the brain never
//! creates a second audit path. Payloads here are metadata-only (identifiers,
//! digests, counts) so `Redaction::None` is honest; knowledge content never
//! enters an audit payload.

use std::sync::{Arc, Mutex};

use odin_domain::{Actor, Digest, EventId, Redaction, Scope};
use odin_ledger::audit::{AuditEvent, AuditEvidence, NewAuditEvent, RedactedPayload};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::error::{BrainError, BrainResult};

/// A pinned Atlas revision was rebuilt into a new index generation.
pub const AUDIT_KIND_INDEX_REBUILT: &str = "knowledge.index.rebuilt";
/// A governed archive ingest published one approved source revision.
pub const AUDIT_KIND_ARCHIVE_INGESTED: &str = "knowledge.archive.ingested";
/// An archive generation's embedding backfill completed through the
/// declared gateway lane.
pub const AUDIT_KIND_ARCHIVE_EMBEDDED: &str = "knowledge.archive.embedded";

/// One brain-relevant event ready for the ledger audit authority.
#[derive(Clone, Debug)]
pub struct BrainAuditEvent {
    /// Stable audit kind; one of the `AUDIT_KIND_*` constants.
    pub kind: &'static str,
    /// The attributed actor. The brain is infrastructure, not an identity
    /// authority: callers pass the acting seat/system actor through.
    pub actor: Actor,
    /// Scope the event occurred in.
    pub scope: Scope,
    /// Metadata-only payload (identifiers, digests, counts — never content).
    pub payload: serde_json::Value,
    /// Ledger objects evidencing the event.
    pub evidence: Vec<AuditEvidence>,
    /// Optional policy/generation binding digest stamped into the payload.
    pub binding: Option<Digest>,
}

impl BrainAuditEvent {
    /// Stamps the binding digest into the metadata payload without mutating
    /// caller-owned fields.
    fn wire_payload(&self) -> serde_json::Value {
        let mut payload = self.payload.clone();
        if let (Some(binding), Some(object)) = (self.binding.as_ref(), payload.as_object_mut()) {
            object.insert(
                "bindingDigest".to_owned(),
                serde_json::json!(binding.to_string()),
            );
        }
        payload
    }
}

/// Typed sink recording brain-relevant events through `odin_ledger::audit`.
///
/// The ledger handle is shared with the owning runtime (`Arc<Mutex<Ledger>>`)
/// so brain audit and runtime writes serialize on the one durable ledger.
#[derive(Clone)]
pub struct BrainAudit {
    ledger: Arc<Mutex<Ledger>>,
}

impl BrainAudit {
    pub fn new(ledger: Arc<Mutex<Ledger>>) -> Self {
        Self { ledger }
    }

    /// Records one event durably. Event identity is derived from the kind,
    /// actor, scope, payload, and wall clock; a replay of one event (e.g.
    /// two seat services rebuilding the same shared generation within one
    /// millisecond) returns the recorded row, never a UNIQUE violation that
    /// fails the caller.
    pub fn record(&self, event: BrainAuditEvent) -> BrainResult<AuditEvent> {
        let occurred_at = OffsetDateTime::now_utc();
        let now_ms =
            u64::try_from(occurred_at.unix_timestamp_nanos() / 1_000_000).map_err(|_| {
                BrainError::InvalidRequest("audit clock before the Unix epoch".to_owned())
            })?;
        let payload = event.wire_payload();
        let identity = blake3::hash(
            &serde_json::to_vec(&(event.kind, &event.actor, &event.scope, &payload)).map_err(
                |error| {
                    BrainError::InvalidRequest(format!(
                        "audit payload is not serializable: {error}"
                    ))
                },
            )?,
        );
        let event_id = EventId::from_parts(
            "brain",
            now_ms,
            identity
                .to_hex()
                .as_str()
                .get(..16)
                .map(str::to_owned)
                .unwrap_or_default(),
        )?;
        let new_event = NewAuditEvent {
            event_id,
            kind: event.kind.to_owned(),
            actor: event.actor,
            scope: event.scope,
            evidence: event.evidence,
            payload: RedactedPayload::new(payload, Redaction::None)?,
            occurred_at,
        };
        let ledger = self
            .ledger
            .lock()
            .map_err(|poisoned| BrainError::Unavailable {
                component: "brain_audit_ledger",
                reason: format!("ledger mutex poisoned: {poisoned}"),
            })?;
        if let Some(recorded) = ledger
            .audit_event(&new_event.event_id)
            .map_err(BrainError::from)?
        {
            return Ok(recorded);
        }
        ledger
            .append_audit_event(new_event)
            .map_err(BrainError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rebuilt(generation: &str) -> BrainAuditEvent {
        BrainAuditEvent {
            kind: AUDIT_KIND_INDEX_REBUILT,
            actor: Actor::System {
                name: "odin-brain".to_owned(),
            },
            scope: Scope::default(),
            payload: serde_json::json!({ "generationId": generation }),
            evidence: Vec::new(),
            binding: None,
        }
    }

    /// Identical events within one millisecond share a row; distinct events do not.
    #[test]
    fn a_replayed_event_returns_its_recorded_row() {
        let audit = BrainAudit::new(Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())));
        let mut first = None;
        let mut replayed = false;
        for _ in 0..1000 {
            let a = audit.record(rebuilt("g1")).unwrap();
            let b = audit.record(rebuilt("g1")).unwrap();
            if a.occurred_at.unix_timestamp_nanos() / 1_000_000
                == b.occurred_at.unix_timestamp_nanos() / 1_000_000
            {
                assert_eq!(a.sequence, b.sequence);
                replayed = true;
                first = Some(a);
                break;
            }
        }
        assert!(replayed, "two records never landed in one millisecond");
        let other = audit.record(rebuilt("g2")).unwrap();
        assert_ne!(other.sequence, first.unwrap().sequence);
    }
}
