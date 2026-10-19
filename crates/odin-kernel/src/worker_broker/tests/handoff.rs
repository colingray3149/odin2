//! Handoff freezes and drains subtrees; reassignment requires stopped sources
//! and exclusive target reservations.

use super::*;

#[test]
fn handoff_freezes_scope_effects() {
    let f = subtree_fixture("handoff-freeze", true);
    let b_store = Arc::new(Mutex::new(
        Ledger::open(f.storage.join(f.b_worker.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("host ledger"),
    ));
    let b_authority = Arc::new(StopAuthority::new(Arc::clone(&b_store), f.channel.clone()));
    dispatch_request(
        &f.scopes,
        &f.claims,
        &f.channel,
        &f.storage,
        &f.socket,
        &f.b_worker,
        &b_authority,
        BrokerRequest::HandoffScope {},
    )
    .expect("host hands off");

    // New nested launches under the frozen scope are refused at
    // prepare, atomically with the handoff marking.
    let late_child = mint_worker_id().expect("late child");
    let error = prepare_nested_scope(
        &f.scopes,
        &f.storage,
        &f.socket,
        f.b_worker.as_str(),
        &late_child,
        Arc::clone(&b_store),
    )
    .expect_err("frozen scope must not prepare descendants");
    assert!(error.to_string().contains("handed off"));

    // The frozen scope's own requests are refused at dispatch.
    let stale = dispatch_request(
        &f.scopes,
        &f.claims,
        &f.channel,
        &f.storage,
        &f.socket,
        &f.b_worker,
        &b_authority,
        BrokerRequest::Identity {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    );
    assert!(matches!(stale, Err((BrokerRejectionCode::Scope, _))));
    let _ = std::fs::remove_dir_all(f.root);
}

#[test]
fn reassignment_moves_handoff_scope_and_rejects_old_identity() {
    let root = test_root("reassign");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let correlation = CorrelationId::new(TEST_CORRELATION).expect("test correlation");
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        AllowedParentBindings::default(),
        Arc::clone(&owner),
    )
    .expect("broker bound");

    let from = mint_worker_id().expect("source host");
    let mut from_identity = identity(from.clone());
    from_identity.unit = "tx-wp-attempt-1-reassign-from.scope".to_owned();
    from_identity.cgroup_path = "/user.slice/reassign-from.scope".to_owned();
    record_payload_running(&owner, &from_identity, &correlation);
    let original = server.prepare_scope(&from).expect("source scope prepared");

    // Record the source as Stopped before reassignment.
    record_terminal_stop_row(&owner, &from, false);

    // A pending child scope moves with the reassignment.
    let child = mint_worker_id().expect("child scope");
    prepare_nested_scope(
        &server.scopes,
        &storage,
        server.socket_path(),
        from.as_str(),
        &child,
        Arc::clone(&owner),
    )
    .expect("child scope prepared");

    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let from_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(from.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("source scope ledger"),
    ));
    let from_authority = Arc::new(StopAuthority::new(Arc::clone(&from_store), channel.clone()));
    dispatch_request(
        &server.scopes,
        &claims,
        &channel,
        &storage,
        server.socket_path(),
        &from,
        &from_authority,
        BrokerRequest::HandoffScope {},
    )
    .expect("source host hands off");

    let to = mint_worker_id().expect("target host");
    let fresh = server
        .reassign_handed_off_scope(&from, &to, Duration::from_millis(500))
        .expect("handed-off scope reassigned");
    assert_eq!(fresh.store_root(), original.store_root());
    assert_eq!(fresh.socket_path(), server.socket_path());

    {
        let table = server.scopes.lock().expect("scope table");
        assert!(!table.contains_key(from.as_str()));
        let entry = table.get(to.as_str()).expect("target scope reserved");
        assert!(!entry.handoff);
        assert!(entry.anchors.is_none());
        assert_eq!(entry.depth, 1);
        assert!(entry.parent_scope.is_none());
        assert_eq!(entry.store_root, original.store_root().to_path_buf());
        assert_eq!(
            table
                .get(child.as_str())
                .expect("child entry")
                .parent_scope
                .as_deref(),
            Some(to.as_str())
        );
    }

    // The old authenticated scope key is dead: dispatch under it is
    // refused before any effect.
    let stale = dispatch_request(
        &server.scopes,
        &claims,
        &channel,
        &storage,
        server.socket_path(),
        &from,
        &from_authority,
        BrokerRequest::Identity {
            worker_id: from.as_str().to_owned(),
        },
    );
    assert!(matches!(stale, Err((BrokerRejectionCode::Scope, _))));

    // Activation requires the target's exact durable payload-running record.
    assert!(server.activate_scope(&to, &identity(to.clone())).is_err());
    let mut to_identity = identity(to.clone());
    to_identity.unit = "tx-wp-attempt-1-reassign-to.scope".to_owned();
    to_identity.cgroup_path = "/user.slice/reassign-to.scope".to_owned();
    record_payload_running(&owner, &to_identity, &correlation);
    server
        .activate_scope(&to, &to_identity)
        .expect("activated against exact durable proof");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reassignment_fails_closed_on_bad_targets_sources_and_drain() {
    let root = test_root("reassign-reject");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let correlation = CorrelationId::new(TEST_CORRELATION).expect("test correlation");
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        AllowedParentBindings::default(),
        Arc::clone(&owner),
    )
    .expect("broker bound");
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));

    let handed_off = |worker: &WorkerId| {
        server.prepare_scope(worker).expect("scope prepared");
        let mut scoped = identity(worker.clone());
        scoped.unit = format!("tx-wp-attempt-1-{}.scope", worker.as_str());
        scoped.cgroup_path = format!("/user.slice/{}.scope", worker.as_str());
        record_payload_running(&owner, &scoped, &correlation);
        record_terminal_stop_row(&owner, worker, false);
        let scope_store = Arc::new(Mutex::new(
            Ledger::open(storage.join(worker.as_str()).join(SCOPE_LEDGER_NAME))
                .expect("scope ledger"),
        ));
        let scope_authority = Arc::new(StopAuthority::new(
            Arc::clone(&scope_store),
            channel.clone(),
        ));
        dispatch_request(
            &server.scopes,
            &claims,
            &channel,
            &storage,
            server.socket_path(),
            worker,
            &scope_authority,
            BrokerRequest::HandoffScope {},
        )
        .expect("handoff");
    };

    // Unknown source scope.
    let unknown = mint_worker_id().expect("unknown");
    let fresh_a = mint_worker_id().expect("fresh a");
    assert!(server
        .reassign_handed_off_scope(&unknown, &fresh_a, Duration::from_millis(50))
        .is_err());

    // Source that never handed off.
    let live = mint_worker_id().expect("live");
    server.prepare_scope(&live).expect("live scope prepared");
    assert!(server
        .reassign_handed_off_scope(&live, &fresh_a, Duration::from_millis(50))
        .is_err());

    // Target id already used in the owner ledger.
    let target_used = mint_worker_id().expect("used target");
    let mut used_identity = identity(target_used.clone());
    used_identity.unit = "tx-wp-attempt-1-used-target.scope".to_owned();
    used_identity.cgroup_path = "/user.slice/used-target.scope".to_owned();
    record_payload_running(&owner, &used_identity, &correlation);
    let handed_a = mint_worker_id().expect("handed a");
    handed_off(&handed_a);
    assert!(server
        .reassign_handed_off_scope(&handed_a, &target_used, Duration::from_millis(50))
        .is_err());

    // Source with no stop record or manager identity.
    let ghost = mint_worker_id().expect("ghost");
    server.prepare_scope(&ghost).expect("ghost scope prepared");
    let ghost_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(ghost.as_str()).join(SCOPE_LEDGER_NAME)).expect("ghost ledger"),
    ));
    let ghost_authority = Arc::new(StopAuthority::new(
        Arc::clone(&ghost_store),
        channel.clone(),
    ));
    dispatch_request(
        &server.scopes,
        &claims,
        &channel,
        &storage,
        server.socket_path(),
        &ghost,
        &ghost_authority,
        BrokerRequest::HandoffScope {},
    )
    .expect("ghost hands off");
    let fresh_b = mint_worker_id().expect("fresh b");
    assert!(server
        .reassign_handed_off_scope(&ghost, &fresh_b, Duration::from_millis(50))
        .is_err());

    // In-flight requests block the transfer until they drain.
    let handed_b = mint_worker_id().expect("handed b");
    handed_off(&handed_b);
    let fresh_c = mint_worker_id().expect("fresh c");
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(handed_b.as_str())
        .expect("handed entry")
        .in_flight
        .fetch_add(1, Ordering::AcqRel);
    let blocked = server.reassign_handed_off_scope(&handed_b, &fresh_c, Duration::from_millis(80));
    let blocked_message = blocked
        .expect_err("in-flight requests must block reassignment")
        .to_string();
    assert!(blocked_message.contains("timed out"), "{blocked_message}");
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(handed_b.as_str())
        .expect("handed entry")
        .in_flight
        .fetch_sub(1, Ordering::AcqRel);
    let drained = server
        .reassign_handed_off_scope(&handed_b, &fresh_c, Duration::from_millis(500))
        .expect("drained reassignment succeeds");
    assert_eq!(drained.store_root(), storage.join(handed_b.as_str()));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reassignment_demands_proved_stopped_source() {
    let root = test_root("reassign-proof");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        AllowedParentBindings::default(),
        Arc::clone(&owner),
    )
    .expect("broker bound");
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let fresh = mint_worker_id().expect("fresh target");

    let hand_off = |worker: &WorkerId| {
        let scope_store = Arc::new(Mutex::new(
            Ledger::open(storage.join(worker.as_str()).join(SCOPE_LEDGER_NAME))
                .expect("scope ledger"),
        ));
        let scope_authority = Arc::new(StopAuthority::new(
            Arc::clone(&scope_store),
            channel.clone(),
        ));
        dispatch_request(
            &server.scopes,
            &claims,
            &channel,
            &storage,
            server.socket_path(),
            worker,
            &scope_authority,
            BrokerRequest::HandoffScope {},
        )
        .expect("handoff");
    };

    // Failed stops without identity anchors cannot be inspected or reassigned.
    let residual = mint_worker_id().expect("residual scope");
    server.prepare_scope(&residual).expect("scope prepared");
    record_child_row(&owner, &residual, false);
    record_terminal_stop_row(&owner, &residual, true);
    hand_off(&residual);
    let error = server
        .reassign_handed_off_scope(&residual, &fresh, Duration::from_millis(50))
        .expect_err("residual stop must not transfer");
    assert!(
        error.to_string().contains("durable Stopped stop record"),
        "{error}"
    );

    // Recorded manager identity cannot replace a live cleanup inspection.
    let residual_proven = mint_worker_id().expect("residual proven scope");
    server
        .prepare_scope(&residual_proven)
        .expect("scope prepared");
    let mut residual_identity = identity(residual_proven.clone());
    residual_identity.unit = format!("tx-wp-attempt-1-{}.scope", residual_proven.as_str());
    residual_identity.cgroup_path = format!("/user.slice/{}.scope", residual_proven.as_str());
    record_payload_running(&owner, &residual_identity, &correlation());
    server
        .activate_scope(&residual_proven, &residual_identity)
        .expect("anchors set");
    record_terminal_stop_row(&owner, &residual_proven, true);
    hand_off(&residual_proven);
    let error = server
        .reassign_handed_off_scope(&residual_proven, &fresh, Duration::from_millis(50))
        .expect_err("failed stop with residue must not transfer");
    assert!(error.to_string().contains("cannot prove"), "{error}");

    // A Requested stop is not a completed stop.
    let pending = mint_worker_id().expect("pending scope");
    server.prepare_scope(&pending).expect("scope prepared");
    let mut pending_identity = identity(pending.clone());
    pending_identity.unit = format!("tx-wp-attempt-1-{}.scope", pending.as_str());
    pending_identity.cgroup_path = format!("/user.slice/{}.scope", pending.as_str());
    record_payload_running(&owner, &pending_identity, &correlation());
    server
        .activate_scope(&pending, &pending_identity)
        .expect("anchors set");
    record_pending_stop_row(&owner, &pending);
    hand_off(&pending);
    let error = server
        .reassign_handed_off_scope(&pending, &fresh, Duration::from_millis(50))
        .expect_err("pending stop must not transfer");
    assert!(error.to_string().contains("cannot prove"), "{error}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn reassignment_drains_the_whole_handed_off_subtree() {
    let root = test_root("reassign-subtree");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        AllowedParentBindings::default(),
        Arc::clone(&owner),
    )
    .expect("broker bound");
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));

    let from = mint_worker_id().expect("source host");
    server.prepare_scope(&from).expect("scope prepared");
    record_child_row(&owner, &from, false);
    record_terminal_stop_row(&owner, &from, false);
    let child = mint_worker_id().expect("child scope");
    prepare_nested_scope(
        &server.scopes,
        &storage,
        server.socket_path(),
        from.as_str(),
        &child,
        Arc::clone(&owner),
    )
    .expect("child scope prepared");

    let from_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(from.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("source scope ledger"),
    ));
    let from_authority = Arc::new(StopAuthority::new(Arc::clone(&from_store), channel.clone()));
    dispatch_request(
        &server.scopes,
        &claims,
        &channel,
        &storage,
        server.socket_path(),
        &from,
        &from_authority,
        BrokerRequest::HandoffScope {},
    )
    .expect("source host hands off");

    // A descendant connection that is still dispatching blocks the
    // transfer of the whole subtree, not just of the root.
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(child.as_str())
        .expect("child entry")
        .in_flight
        .fetch_add(1, Ordering::AcqRel);
    let to = mint_worker_id().expect("target host");
    let blocked = server.reassign_handed_off_scope(&from, &to, Duration::from_millis(80));
    let message = blocked
        .expect_err("a dispatching descendant must block reassignment")
        .to_string();
    assert!(message.contains("timed out"), "{message}");
    {
        let table = server.scopes.lock().expect("scope table");
        assert!(table.contains_key(from.as_str()));
        assert_eq!(
            table[child.as_str()].parent_scope.as_deref(),
            Some(from.as_str())
        );
    }

    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(child.as_str())
        .expect("child entry")
        .in_flight
        .fetch_sub(1, Ordering::AcqRel);
    server
        .reassign_handed_off_scope(&from, &to, Duration::from_millis(500))
        .expect("drained subtree reassigns");
    let table = server.scopes.lock().expect("scope table");
    assert!(!table.contains_key(from.as_str()));
    assert!(!table[to.as_str()].handoff);
    assert_eq!(
        table[child.as_str()].parent_scope.as_deref(),
        Some(to.as_str())
    );
    assert!(table[child.as_str()].handoff);
    drop(table);
    let _ = std::fs::remove_dir_all(root);
}
#[test]
fn handoff_linearizes_with_in_flight_effects() {
    let f = subtree_fixture("handoff-linearize", true);
    let b_store = Arc::new(Mutex::new(
        Ledger::open(f.storage.join(f.b_worker.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("host ledger"),
    ));
    let b_authority = Arc::new(StopAuthority::new(Arc::clone(&b_store), f.channel.clone()));

    // A reserved launch prevents handoff until it drains or the wait expires.
    f.scopes
        .lock()
        .expect("scope table")
        .get_mut(f.b_worker.as_str())
        .expect("host entry")
        .in_flight
        .fetch_add(1, Ordering::AcqRel);
    let stopping = Arc::new(AtomicBool::new(false));
    let stopper = Arc::clone(&stopping);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(120));
        stopper.store(true, Ordering::Release);
    });
    let blocked = dispatch_request_with(
        &f.scopes,
        &f.claims,
        &f.channel,
        &AllowedParentBindings::default(),
        &f.storage,
        &f.socket,
        &f.b_worker,
        &b_authority,
        &stopping,
        BrokerRequest::HandoffScope {},
    );
    let (code, error) = blocked.expect_err("an in-flight effect must block the handoff");
    assert_eq!(code, BrokerRejectionCode::State, "{error}");
    assert!(
        !f.scopes
            .lock()
            .expect("scope table")
            .get(f.b_worker.as_str())
            .expect("host entry")
            .handoff
    );

    // Once the effect drains, the mark lands and covers the lineage.
    f.scopes
        .lock()
        .expect("scope table")
        .get_mut(f.b_worker.as_str())
        .expect("host entry")
        .in_flight
        .fetch_sub(1, Ordering::AcqRel);
    let quiet_stopping = AtomicBool::new(false);
    dispatch_request_with(
        &f.scopes,
        &f.claims,
        &f.channel,
        &AllowedParentBindings::default(),
        &f.storage,
        &f.socket,
        &f.b_worker,
        &b_authority,
        &quiet_stopping,
        BrokerRequest::HandoffScope {},
    )
    .expect("quiesced scope hands off");
    let table = f.scopes.lock().expect("scope table");
    for worker in [&f.b_worker, &f.c_worker, &f.d_worker] {
        assert!(table[worker.as_str()].handoff);
    }
    drop(table);
    let _ = std::fs::remove_dir_all(f.root);
}

/// Check reservations, scopes, and the source owner ledger atomically;
/// release the target after failed transfer.
#[test]
fn reassignment_target_reservation_is_atomic_and_released_on_failure() {
    let root = test_root("reassign-reserve");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("root owner ledger"),
    ));
    let server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        AllowedParentBindings::default(),
        Arc::clone(&owner),
    )
    .expect("broker bound");
    let parent = mint_worker_id().expect("parent host");
    server.prepare_scope(&parent).expect("parent scope");
    // A nested source host: its durable identity lives in its parent's
    // ledger, not in the server root ledger.
    let source = mint_worker_id().expect("nested source host");
    let source_owner = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("source owner ledger"),
    ));
    let mut source_identity = identity(source.clone());
    source_identity.unit = format!("tx-wp-attempt-1-{}.scope", source.as_str());
    source_identity.cgroup_path = format!("/user.slice/{}.scope", source.as_str());
    record_payload_running(&source_owner, &source_identity, &correlation());
    prepare_nested_scope(
        &server.scopes,
        &storage,
        server.socket_path(),
        parent.as_str(),
        &source,
        Arc::clone(&source_owner),
    )
    .expect("nested source scope");
    record_terminal_stop_row(&source_owner, &source, false);
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(source.as_str())
        .expect("source entry")
        .handoff = true;

    // Target freshness is checked in the source's ledger, not the server root ledger.
    let used = mint_worker_id().expect("used target");
    let mut used_identity = identity(used.clone());
    used_identity.unit = format!("tx-wp-attempt-1-{}.scope", used.as_str());
    used_identity.cgroup_path = format!("/user.slice/{}.scope", used.as_str());
    record_payload_running(&source_owner, &used_identity, &correlation());
    let error = server
        .reassign_handed_off_scope(&source, &used, Duration::from_millis(50))
        .expect_err("source owner ledger must decide freshness");
    assert!(error.to_string().contains("durable owner row"), "{error}");

    // A target reserved by a concurrent launch admission refuses too,
    // and the refusal never touches the existing reservation.
    let reserved_target = mint_worker_id().expect("reserved target");
    server
        .worker_reservations
        .lock()
        .expect("reservations")
        .insert(reserved_target.as_str().to_owned(), "elsewhere".to_owned());
    let error = server
        .reassign_handed_off_scope(&source, &reserved_target, Duration::from_millis(50))
        .expect_err("a reserved target must be refused");
    assert!(error.to_string().contains("already reserved"), "{error}");
    assert_eq!(
        server
            .worker_reservations
            .lock()
            .expect("reservations")
            .get(reserved_target.as_str())
            .map(String::as_str),
        Some("elsewhere")
    );

    // A failed transfer (drain timeout) releases its own reservation;
    // the retry with the same target id then commits.
    let retry = mint_worker_id().expect("retry target");
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(source.as_str())
        .expect("source entry")
        .in_flight
        .fetch_add(1, Ordering::AcqRel);
    let blocked = server.reassign_handed_off_scope(&source, &retry, Duration::from_millis(80));
    assert!(blocked
        .expect_err("in-flight requests must block")
        .to_string()
        .contains("timed out"));
    assert!(!server
        .worker_reservations
        .lock()
        .expect("reservations")
        .contains_key(retry.as_str()));
    server
        .scopes
        .lock()
        .expect("scope table")
        .get_mut(source.as_str())
        .expect("source entry")
        .in_flight
        .fetch_sub(1, Ordering::AcqRel);
    server
        .reassign_handed_off_scope(&source, &retry, Duration::from_millis(500))
        .expect("drained transfer commits");
    assert!(server
        .worker_reservations
        .lock()
        .expect("reservations")
        .contains_key(retry.as_str()));
    assert!(server
        .scopes
        .lock()
        .expect("scope table")
        .contains_key(retry.as_str()));
    drop(server);
    let _ = std::fs::remove_dir_all(root);
}
