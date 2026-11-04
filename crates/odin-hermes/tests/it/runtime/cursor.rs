//! Uncommitted envelopes redeliver, cursors persist, and R3 wrappers reject direct invocation.

use crate::runtime::fixtures::now;
use odin_domain::{CapabilityId, Correlation};
use odin_hermes::correlation::ConversationTaskStore;
use odin_hermes::runtime::{LedgerEventBus, PURCHASE_APPROVAL_TTL_HOURS};
use odin_ledger::Ledger;
use std::sync::Arc;

#[test]
fn status_bus_is_at_least_once_until_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = task_store();
    let bus = LedgerEventBus::open(Arc::clone(&store), dir.path().join("cursor.json"), 8).unwrap();
    let command_id = record_task(&store, "once");

    // First drain: the durable revision projects exactly one envelope.
    let batch = bus.drain_batch(&[odin_domain::SUBJECT_COMMAND_CHANGED], 8);
    assert_eq!(batch.len(), 1);
    assert_eq!(
        batch[0].correlation.idempotency_key,
        Correlation::new("test:once").unwrap().idempotency_key
    );
    assert!(
        batch[0]
            .payload
            .get("task")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|task| task == command_id.as_str()),
        "the projection carries the task identity"
    );

    // A drain without a commit redelivers the same envelope: nothing is
    // lost by a failed send.
    let redelivered = bus.drain_batch(&[odin_domain::SUBJECT_COMMAND_CHANGED], 8);
    assert_eq!(redelivered.len(), 1);
    assert_eq!(redelivered[0].id, batch[0].id);

    // The commit is the only cursor advance: after it, the revision is
    // fully delivered and the next drain is empty.
    bus.commit_batch(&batch).unwrap();
    assert!(bus
        .drain_batch(&[odin_domain::SUBJECT_COMMAND_CHANGED], 8)
        .is_empty());
}
#[test]
fn an_unreadable_cursor_refuses_the_bus_instead_of_resending_every_status() {
    let dir = tempfile::tempdir().unwrap();
    let cursor_path = dir.path().join("cursor.json");
    std::fs::write(&cursor_path, "").unwrap();
    let error = LedgerEventBus::open(task_store(), cursor_path, 8)
        .err()
        .expect("an empty cursor file is not a fresh start");
    assert!(error.to_string().contains("cursor.json"), "{error}");
}

fn task_store() -> Arc<ConversationTaskStore> {
    Arc::new(ConversationTaskStore::new(
        Ledger::open_in_memory().unwrap(),
    ))
}
fn record_task(store: &ConversationTaskStore, key: &str) -> odin_domain::CommandId {
    let spec = odin_ledger::command::CommandSpec {
        id: odin_domain::CommandId::new(format!("command:test:{key}")).unwrap(),
        idempotency_key: format!("test:{key}"),
        correlation_id: format!("test:{key}"),
        causation_id: None,
        issuer: "odin-hermes.test".to_owned(),
        approval_id: None,
        target_kind: "test".to_owned(),
        target_id: key.to_owned(),
        capability_id: CapabilityId::new("test.probe").unwrap(),
        capability_version: 1,
        arguments_hash: odin_domain::Digest::hash(key.as_bytes()),
        arguments: serde_json::json!({ "probe": key }),
        expected_desired_revision: None,
        issued_at: now(),
        expires_at: now() + time::Duration::hours(PURCHASE_APPROVAL_TTL_HOURS),
    };
    match store.record_task(&spec).unwrap() {
        odin_ledger::command::RecordCommand::Inserted(recorded) => recorded.command().id.clone(),
        odin_ledger::command::RecordCommand::Existing(recorded) => recorded.command().id.clone(),
    }
}

