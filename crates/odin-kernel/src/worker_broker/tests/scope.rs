//! Scope admission checks payload-running records, unit claims, lineage,
//! stop intents, stale connections, and shutdown.

use super::*;
use crate::worker_broker::dispatch::{claim_remote_unit, normalize_remote_naming, scope_owner_row};

#[test]
fn activation_requires_exact_payload_running_owner_proof() {
    let root = test_root("activation");
    let runtime_root = private_child(&root, "run");
    let storage_root = private_child(&root, "store");
    let owner_store = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let worker = mint_worker_id().expect("worker id");
    let identity = identity(worker.clone());
    let correlation = CorrelationId::new("00000000000000000000000000000001").expect("correlation");
    record_payload_running(&owner_store, &identity, &correlation);

    let server = ParentBrokerServer::bind(
        &runtime_root,
        &storage_root,
        test_channel(),
        AllowedParentBindings::default(),
        Arc::clone(&owner_store),
    )
    .expect("broker bound");
    let descriptor = server.prepare_scope(&worker).expect("scope prepared");
    assert!(descriptor.socket_path().starts_with(&runtime_root));
    assert!(descriptor.store_root().starts_with(&storage_root));
    assert_eq!(
        descriptor.store_path(),
        descriptor.store_root().join(SCOPE_LEDGER_NAME)
    );

    let mut wrong_worker = identity.clone();
    wrong_worker.worker_id = mint_worker_id().expect("different worker");
    assert!(server.activate_scope(&worker, &wrong_worker).is_err());

    let mut wrong_proof = identity.clone();
    wrong_proof.leader_start_ticks += 1;
    assert!(server.activate_scope(&worker, &wrong_proof).is_err());

    server
        .activate_scope(&worker, &identity)
        .expect("exact durable proof activates");
    assert!(server.activate_scope(&worker, &identity).is_err());
    drop(server);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn remote_namespace_and_claims_are_scope_bound() {
    let owner = odin_ledger::worker::WorkerRow {
        worker_id: "owner".to_owned(),
        unit: "owner.scope".to_owned(),
        invocation_id: Some("01".repeat(16)),
        correlation_id: "owner-correlation".to_owned(),
        tx_id: "root-transaction".to_owned(),
        wp_id: "root".to_owned(),
        attempt: 1,
        cgroup_path: Some("/owner".to_owned()),
        cgroup_inode: Some(1),
        leader_pid: Some(2),
        leader_start_ticks: Some(3),
        phase: WorkerPhase::PayloadRunning,
        residue_json: "{}".to_owned(),
        created_at: "1970-01-01T00:00:00Z".to_owned(),
        updated_at: "1970-01-01T00:00:00Z".to_owned(),
    };
    let anchors = ScopeAnchors {
        unit: owner.unit.clone(),
        invocation_hex: owner.invocation_id.clone().expect("invocation"),
        cgroup_path: "/owner".to_owned(),
        cgroup_inode: 1,
        leader_pid: 2,
        leader_start_ticks: 3,
    };
    let child = mint_worker_id().expect("child");
    let requested =
        WorkerNaming::new("child-transaction", "omp", 4, child.clone()).expect("child naming");
    let normalized = normalize_remote_naming(&owner, &anchors, requested).expect("normalized");
    assert_eq!(normalized.tx_id, owner.tx_id);
    assert!(normalized.wp_id.starts_with("pa0101"));

    let mut other_anchors = anchors.clone();
    other_anchors.invocation_hex = "02".repeat(16);
    let other = normalize_remote_naming(
        &owner,
        &other_anchors,
        WorkerNaming::new("different", "omp", 4, child.clone()).expect("other naming"),
    )
    .expect("other normalized");
    assert_ne!(normalized.unit(), other.unit());

    let claims = Arc::new(Mutex::new(BTreeMap::new()));
    claim_remote_unit(&claims, &normalized.unit(), "scope-a", &child).expect("first claim");
    assert!(claim_remote_unit(&claims, &normalized.unit(), "scope-b", &child).is_err());
}

#[test]
fn nested_scope_lineage_binds_each_owner_ledger_and_depth() {
    let root = test_root("lineage");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let scopes = Arc::new(Mutex::new(BTreeMap::new()));
    let mut owners = Vec::new();
    let root_worker = mint_worker_id().expect("root worker");
    let root_owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("root owner")));
    prepare_scope_entry(
        &scopes,
        &storage,
        &socket,
        &root_worker,
        Arc::clone(&root_owner),
        None,
        1,
    )
    .expect("root scope");
    owners.push(root_owner);

    let mut parent = root_worker;
    for expected_depth in 2..=MAX_BROKER_NESTING_DEPTH {
        let worker = mint_worker_id().expect("nested worker");
        let owner = Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("nested owner ledger"),
        ));
        prepare_nested_scope(
            &scopes,
            &storage,
            &socket,
            parent.as_str(),
            &worker,
            Arc::clone(&owner),
        )
        .expect("nested scope");
        let table = scopes.lock().expect("scope table");
        let entry = table.get(worker.as_str()).expect("nested entry");
        assert_eq!(entry.depth, expected_depth);
        assert_eq!(entry.parent_scope.as_deref(), Some(parent.as_str()));
        assert!(Arc::ptr_eq(&entry.owner_store, &owner));
        drop(table);
        owners.push(owner);
        parent = worker;
    }
    let too_deep = mint_worker_id().expect("too deep worker");
    assert!(prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        parent.as_str(),
        &too_deep,
        Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("overflow owner")
        )),
    )
    .is_err());
    drop(scopes);
    drop(owners);
    let _ = std::fs::remove_dir_all(root);
}

/// Stop intent and activation checks share the owner-ledger lock.
#[test]
fn activation_refuses_exact_owner_stop_intent() {
    let root = test_root("activation-stop");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let worker = mint_worker_id().expect("worker");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    prepare_scope_entry(
        &scopes,
        &storage,
        &socket,
        &worker,
        Arc::clone(&owner),
        None,
        1,
    )
    .expect("scope prepared");
    let scoped = identity(worker.clone());
    record_payload_running(&owner, &scoped, &correlation());
    record_pending_stop_row(&owner, &worker);
    let error = activate_scope_entry(&scopes, &worker, &scoped)
        .expect_err("a stop intent must refuse activation");
    assert!(error.to_string().contains("stop intent"), "{error}");
    assert!(scopes
        .lock()
        .expect("scope table")
        .get(worker.as_str())
        .expect("entry")
        .anchors
        .is_none());
    record_terminal_stop_row(&owner, &worker, false);
    let error = activate_scope_entry(&scopes, &worker, &scoped)
        .expect_err("settlement must not reopen activation");
    assert!(error.to_string().contains("stop intent"), "{error}");
    assert!(scope_owner_row(&scopes, worker.as_str()).is_err());
    let _ = std::fs::remove_dir_all(root);
}

/// Stop intent is checked before consulting the manager.
#[test]
fn bind_refuses_stale_scope_with_owner_stop_intent() {
    let root = test_root("bind-stale");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let channel = test_channel();
    let own_cgroup = process_cgroup_v2_path(std::process::id()).expect("own cgroup");

    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let worker = mint_worker_id().expect("stale worker");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let mut scoped = identity(worker.clone());
    scoped.cgroup_path = own_cgroup.clone();
    record_payload_running(&owner, &scoped, &correlation());
    prepare_scope_entry(
        &scopes,
        &storage,
        &socket,
        &worker,
        Arc::clone(&owner),
        None,
        1,
    )
    .expect("scope prepared");
    activate_scope_entry(&scopes, &worker, &scoped).expect("activated");
    record_pending_stop_row(&owner, &worker);
    let (stale_stream, _) = UnixStream::pair().expect("socket pair");
    let error = bind_connection(&scopes, &channel, &stale_stream)
        .map(|_| ())
        .expect_err("a stopped scope must refuse admission");
    assert!(error.to_string().contains("stop intent"), "{error}");
    assert!(scopes
        .lock()
        .expect("scope table")
        .get(worker.as_str())
        .expect("entry")
        .authority
        .is_none());

    // Without a stop intent, binding reaches the unavailable manager.
    let live: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let live_worker = mint_worker_id().expect("live worker");
    let live_owner = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("live owner ledger"),
    ));
    let mut live_identity = identity(live_worker.clone());
    live_identity.cgroup_path = own_cgroup;
    record_payload_running(&live_owner, &live_identity, &correlation());
    prepare_scope_entry(
        &live,
        &storage,
        &socket,
        &live_worker,
        Arc::clone(&live_owner),
        None,
        1,
    )
    .expect("live scope prepared");
    activate_scope_entry(&live, &live_worker, &live_identity).expect("live activated");
    let error = bind_connection(&live, &channel, &stale_stream)
        .map(|_| ())
        .expect_err("the absent manager must refuse");
    assert!(error.to_string().contains("manager proof"), "{error}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reservation_apis_refuse_during_shutdown() {
    let root = test_root("shutdown-gates");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        test_channel(),
        AllowedParentBindings::default(),
        owner,
    )
    .expect("broker bound");
    let from = mint_worker_id().expect("source");
    server
        .prepare_scope(&from)
        .expect("prepared before shutdown");
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(from.as_str())
        .expect("entry")
        .handoff = true;
    server.shutdown(Duration::from_secs(2)).expect("shutdown");

    let worker = mint_worker_id().expect("late worker");
    let error = server
        .prepare_scope(&worker)
        .expect_err("no scope may be prepared during shutdown");
    assert!(error.to_string().contains("shutting down"), "{error}");
    let error = server
        .activate_scope(&worker, &identity(worker.clone()))
        .expect_err("no scope may be activated during shutdown");
    assert!(error.to_string().contains("shutting down"), "{error}");
    let to = mint_worker_id().expect("late target");
    let error = server
        .reassign_handed_off_scope(&from, &to, Duration::from_millis(50))
        .expect_err("reassignment must refuse during shutdown");
    assert!(error.to_string().contains("shutting down"), "{error}");
    assert!(!server
        .scopes
        .lock()
        .expect("scope table")
        .contains_key(to.as_str()));
    drop(server);
    let _ = std::fs::remove_dir_all(root);
}
