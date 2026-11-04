//! The durable event bus over the shared ledger: status truth comes only
//! from the tracked durable rows plus explicitly published envelopes, with
//! an atomically persisted per-row revision cursor.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use odin_domain::envelope::EventEnvelopeInit;
use odin_domain::{
    Actor, EventEnvelope, EventId, Redaction, Scope, SUBJECT_APPROVAL_CHANGED,
    SUBJECT_COMMAND_CHANGED,
};
use odin_ledger::command::{Command, CommandTerminalStatus};
use time::OffsetDateTime;

use super::{producer, unix_ms, HermesRuntimeError, RUNTIME_ISSUER};
use crate::correlation::ConversationTaskStore;

/// Durable projection cursor: the highest command/approval revision already
/// delivered to a subscriber. Persisted atomically so a daemon restart
/// neither re-notifies nor skips.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct EventCursor {
    commands: BTreeMap<String, i64>,
    approvals: BTreeMap<String, i64>,
}

/// The shared state of the ledger-backed bus: a bounded queue for published
/// envelopes, the tracked durable rows and their cursor, and the inflight
/// set of envelopes handed to the acked egress drain — a delivery is
/// durable-cursor-acked only after its send provably succeeded, so a
/// transport failure never consumes a status event.
struct BusCore {
    store: Arc<ConversationTaskStore>,
    queue: Mutex<VecDeque<EventEnvelope>>,
    queue_capacity: usize,
    cursor: Mutex<EventCursor>,
    cursor_path: PathBuf,
    sequence: AtomicU64,
    /// Envelopes handed out through the acked drain and not yet committed,
    /// keyed by event id. `None` rows are queue-only publications.
    inflight: Mutex<BTreeMap<String, Option<(String, i64)>>>,
}

impl BusCore {
    fn persist_cursor(&self, cursor: &EventCursor) -> Result<(), HermesRuntimeError> {
        let temporary = self.cursor_path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(cursor)
            .map_err(|error| HermesRuntimeError::Cursor(error.to_string()))?;
        std::fs::write(&temporary, bytes)
            .and_then(|()| std::fs::rename(&temporary, &self.cursor_path))
            .map_err(|error| HermesRuntimeError::Cursor(error.to_string()))?;
        Ok(())
    }

    /// The persisted cursor; a bus that never ran starts at zero, but an unreadable file would
    /// re-send every status event ever recorded, so it refuses instead.
    fn load_cursor(&self) -> Result<EventCursor, HermesRuntimeError> {
        let bytes = match std::fs::read(&self.cursor_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(EventCursor::default())
            }
            Err(error) => return Err(self.unreadable_cursor(error)),
        };
        serde_json::from_slice(&bytes).map_err(|error| self.unreadable_cursor(error))
    }

    fn unreadable_cursor(&self, error: impl std::fmt::Display) -> HermesRuntimeError {
        HermesRuntimeError::Cursor(format!(
            "the status cursor {} is unreadable ({error}); delete it to send every status event again",
            self.cursor_path.display()
        ))
    }

    /// Publishes one envelope into the bounded queue. A full queue is a
    /// typed backpressure error — never a silent drop.
    fn publish(&self, event: &EventEnvelope) -> Result<(), HermesRuntimeError> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|error| HermesRuntimeError::Composition(format!("event queue: {error}")))?;
        if queue.len() >= self.queue_capacity {
            return Err(HermesRuntimeError::Composition(format!(
                "event queue is full at its bound of {} envelopes",
                self.queue_capacity
            )));
        }
        queue.push_back(event.clone());
        Ok(())
    }

    /// Acknowledges delivered envelopes: durable-row deliveries advance the
    /// committed cursor (persisted before returning), so an unacked batch is
    /// re-projected on the next drain instead of being lost.
    fn commit(&self, ids: &[String]) -> Result<(), HermesRuntimeError> {
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|error| HermesRuntimeError::Cursor(format!("cursor state: {error}")))?;
        let mut inflight = self
            .inflight
            .lock()
            .map_err(|error| HermesRuntimeError::Cursor(format!("inflight state: {error}")))?;
        for id in ids {
            if let Some(Some((key, revision))) = inflight.remove(id) {
                // Route by the projected event kind: a row the tracking
                // step never saw commits into its own cursor map.
                if id.starts_with("event:command-change:") {
                    cursor.commands.insert(key, revision);
                } else if id.starts_with("event:approval-change:") {
                    cursor.approvals.insert(key, revision);
                }
            }
        }
        self.persist_cursor(&cursor)
    }

    /// The batch-drain projection: queued publications first, then every
    /// durable task/approval row whose revision moved past its committed
    /// baseline — including rows the tracking step never saw, so a crash
    /// between the durable record and the tracking step cannot lose a
    /// status transition. An unacked delivery redelivers on the next
    /// drain: only [`BusCore::commit`] advances the cursor. `batched`
    /// deduplicates within one returned batch.
    fn next_batch_envelope(
        &self,
        kinds: &BTreeSet<String>,
        batched: &mut BTreeSet<String>,
    ) -> Option<EventEnvelope> {
        loop {
            let queued = self
                .queue
                .lock()
                .ok()
                .and_then(|mut queue| queue.pop_front());
            let Some(event) = queued else {
                break;
            };
            if !kinds.contains(&event.kind) {
                continue;
            }
            if let Ok(mut inflight) = self.inflight.lock() {
                inflight.insert(event.id.to_string(), None);
            }
            return Some(event);
        }
        let cursor = self.cursor.lock().ok()?;
        let mut inflight = self.inflight.lock().ok()?;
        for command in self.store.tasks().ok()? {
            let seen = cursor
                .commands
                .get(command.id.as_str())
                .copied()
                .unwrap_or(0);
            if command.revision <= seen {
                continue;
            }
            let Some(envelope) = project_command(&command, &self.sequence) else {
                continue;
            };
            let id = envelope.id.to_string();
            if kinds.contains(&envelope.kind) && batched.insert(id.clone()) {
                inflight.insert(id, Some((command.id.to_string(), command.revision)));
                return Some(envelope);
            }
        }
        for approval in self.store.approvals().ok()? {
            let key = approval.approval_id.to_string();
            let seen = cursor.approvals.get(key.as_str()).copied().unwrap_or(0);
            if approval.revision <= seen {
                continue;
            }
            let Ok(envelope) = project_approval(&approval, &self.sequence) else {
                continue;
            };
            let id = envelope.id.to_string();
            if kinds.contains(&envelope.kind) && batched.insert(id.clone()) {
                inflight.insert(id, Some((key, approval.revision)));
                return Some(envelope);
            }
        }
        None
    }
    fn track_command(&self, command_id: &str, revision: i64) -> Result<(), HermesRuntimeError> {
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|error| HermesRuntimeError::Cursor(format!("cursor state: {error}")))?;
        cursor.commands.insert(command_id.to_owned(), revision);
        self.persist_cursor(&cursor)
    }

    fn track_approval(&self, approval_id: &str, revision: i64) -> Result<(), HermesRuntimeError> {
        let mut cursor = self
            .cursor
            .lock()
            .map_err(|error| HermesRuntimeError::Cursor(format!("cursor state: {error}")))?;
        cursor.approvals.insert(approval_id.to_owned(), revision);
        self.persist_cursor(&cursor)
    }
}

fn command_status(command: &Command) -> String {
    match command.terminal_status {
        Some(status) => match status {
            CommandTerminalStatus::Completed => "completed",
            CommandTerminalStatus::Failed => "failed",
            CommandTerminalStatus::Blocked => "blocked",
            CommandTerminalStatus::Cancelled => "cancelled",
            CommandTerminalStatus::Expired => "expired",
            CommandTerminalStatus::Rejected => "rejected",
        }
        .to_owned(),
        None if command.accepted_at.is_some() => "accepted".to_owned(),
        None => "recorded".to_owned(),
    }
}

fn status_string(status: &odin_domain::ApprovalStatus) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| {
            value.as_str().map(str::to_owned).or_else(|| {
                value
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn project_command(command: &Command, sequence: &AtomicU64) -> Option<EventEnvelope> {
    EventEnvelope::new(EventEnvelopeInit {
        id: EventId::new(format!("event:command-change:{}", command.id)).ok()?,
        sequence: sequence.fetch_add(1, Ordering::Relaxed),
        revision: u64::try_from(command.revision).ok()?,
        occurred_at_ms: unix_ms(OffsetDateTime::now_utc()),
        kind: SUBJECT_COMMAND_CHANGED.to_owned(),
        actor: Actor::system(RUNTIME_ISSUER).ok()?,
        scope: Scope::default(),
        correlation: odin_domain::Correlation::new(command.idempotency_key.clone()).ok()?,
        payload: serde_json::json!({
            "task": command.id.to_string(),
            "status": command_status(command),
        }),
        redaction: Redaction::None,
        producer: producer().ok()?,
    })
    .ok()
}

/// Hash long approval ids to keep the event id within its 128-byte limit.
fn approval_change_event_id(approval_id: &str) -> String {
    let readable = format!("event:approval-change:{approval_id}");
    if readable.len() <= 128 {
        return readable;
    }
    let digest = odin_domain::Digest::hash(approval_id.as_bytes()).to_string();
    format!(
        "event:approval-change:{}",
        &digest.trim_start_matches("blake3:")[..48]
    )
}

fn project_approval(
    approval: &odin_ledger::approval::Approval,
    sequence: &AtomicU64,
) -> Result<EventEnvelope, HermesRuntimeError> {
    Ok(EventEnvelope::new(EventEnvelopeInit {
        id: EventId::new(approval_change_event_id(&approval.approval_id.to_string()))?,
        sequence: sequence.fetch_add(1, Ordering::Relaxed),
        revision: u64::try_from(approval.revision).map_err(|error| {
            HermesRuntimeError::Cursor(format!("approval revision does not fit u64: {error}"))
        })?,
        occurred_at_ms: unix_ms(OffsetDateTime::now_utc()),
        kind: SUBJECT_APPROVAL_CHANGED.to_owned(),
        actor: Actor::system(RUNTIME_ISSUER)?,
        scope: Scope::default(),
        correlation: odin_domain::Correlation::new(format!("approval:{}", approval.approval_id))?,
        payload: serde_json::json!({
            "approval": approval.approval_id.to_string(),
            "status": status_string(&approval.status),
        }),
        redaction: Redaction::None,
        producer: producer()?,
    })?)
}

/// The production event bus of the Hermes surface: status truth comes
/// only from the durable ledger rows it tracks plus envelopes explicitly
/// published into its bounded queue. Delivery is poll batches — the
/// egress pump drains per tick, and the durable cursor keeps delivery
/// deduplicated across restarts.
#[derive(Clone)]
pub struct LedgerEventBus {
    core: Arc<BusCore>,
}

impl LedgerEventBus {
    /// Opens the bus over the shared task store with its durable cursor at
    /// `cursor_path` and a bounded publish queue.
    pub fn open(
        store: Arc<ConversationTaskStore>,
        cursor_path: PathBuf,
        queue_capacity: usize,
    ) -> Result<Self, HermesRuntimeError> {
        if queue_capacity == 0 {
            return Err(HermesRuntimeError::Composition(
                "event queue capacity must be positive".to_owned(),
            ));
        }
        let core = Arc::new(BusCore {
            store,
            queue: Mutex::new(VecDeque::new()),
            queue_capacity,
            cursor: Mutex::new(EventCursor::default()),
            cursor_path,
            sequence: AtomicU64::new(1),
            inflight: Mutex::new(BTreeMap::new()),
        });
        let cursor = core.load_cursor()?;
        *core
            .cursor
            .lock()
            .map_err(|error| HermesRuntimeError::Cursor(format!("cursor state: {error}")))? =
            cursor;
        Ok(Self { core })
    }

    /// Tracks one durable command row so its revision advances project into
    /// status envelopes.
    pub fn track_command(&self, command_id: &str, revision: i64) -> Result<(), HermesRuntimeError> {
        self.core.track_command(command_id, revision)
    }

    /// Tracks one durable approval row so its decisions project into status
    /// envelopes.
    pub fn track_approval(
        &self,
        approval_id: &str,
        revision: i64,
    ) -> Result<(), HermesRuntimeError> {
        self.core.track_approval(approval_id, revision)
    }

    /// Publishes one envelope into the bounded queue.
    pub fn publish(&self, event: &EventEnvelope) -> Result<(), HermesRuntimeError> {
        self.core.publish(event)
    }

    /// Drains up to `max` envelopes for the acked egress pump. Delivery is
    /// at-least-once: the durable scan projects every tracked-or-not row
    /// past its committed baseline, an unacked envelope redelivers on the
    /// next drain, and only [`LedgerEventBus::commit_batch`] acknowledges.
    pub fn drain_batch(&self, kinds: &[&str], max: usize) -> Vec<EventEnvelope> {
        let kinds: BTreeSet<String> = kinds.iter().map(|kind| (*kind).to_owned()).collect();
        let mut batch = Vec::new();
        let mut batched = BTreeSet::new();
        while batch.len() < max {
            let Some(envelope) = self.core.next_batch_envelope(&kinds, &mut batched) else {
                break;
            };
            batch.push(envelope);
        }
        batch
    }

    /// Advances the persisted cursor for this batch; uncommitted batches are redelivered whole.
    pub fn commit_batch(&self, batch: &[EventEnvelope]) -> Result<(), HermesRuntimeError> {
        let ids: Vec<String> = batch
            .iter()
            .map(|envelope| envelope.id.to_string())
            .collect();
        self.core.commit(&ids)
    }
}

#[cfg(test)]
mod approval_event_id_tests {}
