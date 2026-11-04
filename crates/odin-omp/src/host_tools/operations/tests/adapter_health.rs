//! Only fresh Ready status enables capabilities; cached status is reused within its TTL.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use odin_adapter_core::status::AdapterStatusSnapshot;
use serde_json::{json, Value};

use crate::host_tools::operations::{
    HostAdapterStatusTransport, HostToolOperationError, SupervisedAdapterStatus,
};

use super::fixture::{Fixture, ADMITTED_IDENTITY, SEARCH_ADAPTER, SEARCH_CAPABILITY};

/// Scripted supervised status transport: queued snapshots are handed out in
/// order, and an empty queue is a failing refresh (the unknown state).
struct ScriptedStatusTransport {
    refreshes: AtomicUsize,
    responses: Mutex<
        Vec<Result<AdapterStatusSnapshot, crate::host_tools::operations::HostToolOperationError>>,
    >,
}

impl ScriptedStatusTransport {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            refreshes: AtomicUsize::new(0),
            responses: Mutex::new(Vec::new()),
        })
    }

    fn queue(&self, snapshot: AdapterStatusSnapshot) {
        self.responses
            .lock()
            .expect("script queue lock")
            .push(Ok(snapshot));
    }

    fn refreshes(&self) -> usize {
        self.refreshes.load(Ordering::SeqCst)
    }
}

impl HostAdapterStatusTransport for ScriptedStatusTransport {
    fn refresh_status(
        &self,
        adapter: &str,
    ) -> Result<AdapterStatusSnapshot, crate::host_tools::operations::HostToolOperationError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        let mut responses = self.responses.lock().expect("script queue lock");
        if responses.is_empty() {
            return Err(
                crate::host_tools::operations::HostToolOperationError::AdapterStatus {
                    adapter: adapter.to_owned(),
                    detail: "script exhausted; status unknown".to_owned(),
                },
            );
        }
        responses.remove(0)
    }
}

fn identity_wire(binding_digest: &str) -> Value {
    json!({
        "adapter_id": SEARCH_ADAPTER,
        "version": "1.0.0",
        "binding_digest": binding_digest,
    })
}

/// With `NOW_MS` at 00:00:10 and a five-second TTL, 00:00:02 is stale.
fn status_snapshot(identity: Value, health: &str, observed_at: &str) -> AdapterStatusSnapshot {
    AdapterStatusSnapshot::from_wire(&json!({
        "schema": odin_adapter_core::ADAPTER_STATUS_SCHEMA_NAME,
        "adapter": identity,
        "revision": 1,
        "health": health,
        "taint": "credential_tainted",
        "active_operations": 0,
        "last_failure": null,
        "evidence_refs": [],
        "observed_at": observed_at,
    }))
    .expect("valid status snapshot")
}

fn adapter_stack(transport: &Arc<ScriptedStatusTransport>) -> Fixture {
    let status = Arc::new(SupervisedAdapterStatus::new(
        Arc::clone(transport) as Arc<dyn HostAdapterStatusTransport>,
        BTreeSet::from([SEARCH_ADAPTER.to_owned()]),
        std::time::Duration::from_secs(5),
    ));
    Fixture::for_adapter_search(status)
}

fn lists_search(fixture: &Fixture) -> bool {
    fixture
        .operations
        .session_listing(&fixture.binding, &fixture.session)
        .expect("fresh provisioned token lists")
        .tools
        .iter()
        .any(|tool| tool.capability_id.as_str() == SEARCH_CAPABILITY)
}

#[test]
fn adapter_listing_fails_closed_while_status_is_unknown() {
    let transport = ScriptedStatusTransport::new();
    let fixture = adapter_stack(&transport);
    assert!(
        !lists_search(&fixture),
        "an adapter with no proven status lists nothing"
    );
    assert_eq!(
        transport.refreshes(),
        1,
        "the unknown state triggered exactly one real refresh"
    );
}

#[test]
fn adapter_listing_is_ready_only_and_refreshes_to_ready() {
    let transport = ScriptedStatusTransport::new();
    let fixture = adapter_stack(&transport);

    // Degraded under the admitted identity: unhealthy, refresh really ran.
    transport.queue(status_snapshot(
        identity_wire(ADMITTED_IDENTITY),
        "degraded",
        "1970-01-01T00:00:10Z",
    ));
    assert!(!lists_search(&fixture), "degraded status lists nothing");
    assert_eq!(transport.refreshes(), 1);

    // A Ready snapshot older than the freshness bound stays fail-closed.
    transport.queue(status_snapshot(
        identity_wire(ADMITTED_IDENTITY),
        "ready",
        "1970-01-01T00:00:02Z",
    ));
    assert!(!lists_search(&fixture), "stale status lists nothing");
    assert_eq!(transport.refreshes(), 2);

    transport.queue(status_snapshot(
        identity_wire(ADMITTED_IDENTITY),
        "ready",
        "1970-01-01T00:00:10Z",
    ));
    assert!(
        lists_search(&fixture),
        "fresh Ready status under the admitted identity lists the capability"
    );
    assert_eq!(transport.refreshes(), 3);
    assert!(
        lists_search(&fixture),
        "the fresh Ready snapshot is reused within its bound"
    );
    assert_eq!(
        transport.refreshes(),
        3,
        "no refresh while the snapshot is fresh"
    );
}

/// A snapshot stamped well ahead of the query clock is clock skew, not health.
#[test]
fn a_snapshot_stamped_a_minute_ahead_is_clock_skew_not_health() {
    let skewed = ScriptedStatusTransport::new();
    let fixture = adapter_stack(&skewed);
    skewed.queue(status_snapshot(
        identity_wire(ADMITTED_IDENTITY),
        "ready",
        "1970-01-01T00:01:10Z",
    ));
    assert!(
        !lists_search(&fixture),
        "a snapshot a minute ahead of the query is clock skew, not health"
    );
}

/// An adapter's typed failure reaches the caller as its reason, not as a
/// durable-doubt settlement with the internals.
#[test]
fn an_adapter_typed_failure_reaches_the_caller_as_its_reason() {
    let transport = ScriptedStatusTransport::new();
    let fixture = adapter_stack(&transport);
    transport.queue(status_snapshot(
        identity_wire(ADMITTED_IDENTITY),
        "ready",
        "1970-01-01T00:00:10Z",
    ));
    let error = fixture
        .dispatch_named(
            super::fixture::SEARCH_TOOL,
            Some(fixture.resource.clone()),
            json!({"value": "weno"}),
            "page-not-loaded",
        )
        .expect_err("a page that did not load is a failure");
    assert!(
        matches!(&error, HostToolOperationError::AdapterFailed { message, .. }
            if message.contains(super::fixture::PAGE_NOT_LOADED)),
        "{error:?}"
    );
}
