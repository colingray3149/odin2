//! Uncommitted envelopes redeliver, cursors persist, and R3 wrappers reject direct invocation.

use crate::fixtures::{delegation_tool_names, now, runtime_with_declarations};
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
fn cursor_persists_across_bus_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let cursor_path = dir.path().join("cursor.json");
    let store = task_store();
    let command_id = record_task(&store, "reopening");

    {
        let bus = LedgerEventBus::open(Arc::clone(&store), cursor_path.clone(), 8).unwrap();
        let batch = bus.drain_batch(&[odin_domain::SUBJECT_COMMAND_CHANGED], 8);
        assert_eq!(batch.len(), 1);
        bus.commit_batch(&batch).unwrap();
    }

    // Reopening over the same durable cursor does not redeliver.
    let bus = LedgerEventBus::open(Arc::clone(&store), cursor_path, 8).unwrap();
    assert!(
        bus.drain_batch(&[odin_domain::SUBJECT_COMMAND_CHANGED], 8)
            .is_empty(),
        "the committed revision {command_id} must not redeliver after reopen"
    );
}
#[test]
fn r3_wrappers_fail_closed_without_the_kernel_proof() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with_declarations(dir.path());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);

    let mut names = vec!["email_send", "calendar_propose", "purchase_submit"];
    names.extend(delegation_tool_names());
    for name in names {
        let invocation = odin_omp::host_tools::HostInvocation {
            scope: odin_domain::Scope::default(),
            arguments: serde_json::json!({
                "project": "odin",
                "subject": "probe",
                "question": "probe",
                "urgency": "low",
                "vendor": "probe",
                "item_description": "probe",
                "amount": { "currency": "USD", "minor_units": 1 },
                "approvalId": "approval:probe"
            }),
        };
        let tool = tools
            .iter()
            .find(|tool| tool.definition().name == name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        let error = tool
            .invoke(invocation)
            .expect_err("an R3 wrapper must fail closed on bare invoke");
        assert!(
            matches!(error, odin_omp::host_tools::HostToolError::Catalog { .. }),
            "{name} must refuse with the catalog law, got {error:?}"
        );
    }
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

#[test]
fn a_bound_purchase_backend_is_never_reached_without_the_consumed_approval() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend(AtomicUsize);
    impl odin_hermes::purchase::PurchaseFrameExchange for CountingBackend {
        fn exchange(
            &self,
            _request_line: String,
        ) -> Result<String, odin_hermes::purchase::PurchaseFault> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(odin_hermes::purchase::PurchaseFault::Uncertain)
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let runtime = runtime_with_declarations(dir.path());
    let backend = Arc::new(CountingBackend(AtomicUsize::new(0)));
    runtime
        .bind_purchase_backend(
            odin_hermes::purchase::PurchaseAdapterContract::governed_browser().unwrap(),
            backend.clone(),
        )
        .unwrap();
    assert!(runtime.purchase_transport_deployed());
    let tools = odin_hermes::runtime::hermes_host_tools(&runtime);
    let tool = tools
        .iter()
        .find(|tool| tool.definition().name == "purchase_submit")
        .expect("purchase_submit is registered");
    let arguments = serde_json::json!({
        "vendor": "Shop",
        "item_description": "USB-C cable",
        "amount": { "currency": "USD", "minor_units": 799 },
        "checkout": {
            "product_url": "https://www.shop.example/dp/B0CHEAP",
            "add_to_cart": "#add-to-cart-button",
            "checkout_url": "https://www.shop.example/checkout",
            "place_order": "#place-order"
        },
        "approvalId": "approval:forged-by-the-model"
    });
    let scope = odin_domain::Scope {
        seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
        ..odin_domain::Scope::default()
    };
    tool.preflight(&crate::fixtures::owner_ask_contract(), &scope, &arguments)
        .expect("a well-formed checkout passes the read-only gate");
    let error = tool
        .invoke(odin_omp::host_tools::HostInvocation {
            scope,
            arguments: arguments.clone(),
        })
        .expect_err("a bare purchase invoke must fail closed");
    assert!(matches!(
        error,
        odin_omp::host_tools::HostToolError::Catalog { .. }
    ));
    let mut off_site = arguments;
    off_site["checkout"]["checkout_url"] = serde_json::json!("https://pay.elsewhere.example/c");
    assert!(
        tool.preflight(
            &crate::fixtures::owner_ask_contract(),
            &odin_domain::Scope {
                seat: Some(odin_domain::SeatId::new("sinmara").unwrap()),
                ..odin_domain::Scope::default()
            },
            &off_site
        )
        .is_err(),
        "an off-site checkout never costs Colin an approval question"
    );
    assert_eq!(
        backend.0.load(Ordering::SeqCst),
        0,
        "no purchase frame may reach the backend without the consumed approval"
    );
}
