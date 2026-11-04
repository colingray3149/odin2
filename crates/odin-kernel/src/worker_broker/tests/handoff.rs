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
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
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
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
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
        quiet_context(
            &server.scopes,
            &claims,
            &channel,
            &storage,
            server.socket_path(),
        ),
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
        quiet_context(
            &server.scopes,
            &claims,
            &channel,
            &storage,
            server.socket_path(),
        ),
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
            quiet_context(
                &server.scopes,
                &claims,
                &channel,
                &storage,
                server.socket_path(),
            ),
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
    // A stopping broker stops waiting for the in-flight effect and refuses the handoff.
    let blocked = dispatch_request(
        ConnectionContext {
            stopping: Arc::new(AtomicBool::new(true)),
            ..quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket)
        },
        &f.b_worker,
        &b_authority,
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
    dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.b_worker,
        &b_authority,
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
