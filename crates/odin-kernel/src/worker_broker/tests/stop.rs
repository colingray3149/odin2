//! Stop and shutdown behavior tests: scoped subtree settlement, recovery,
//! drain-before-revoke, and managed server shutdown accounting.

use super::*;

#[test]
fn shutdown_deadline_bounds_blocked_scope_lock_and_invalidates_retry() {
    let root = test_root("shutdown-deadline-lock");
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
    let scopes = Arc::clone(&server.scopes);
    let guard = scopes.lock().expect("hold scope lock");
    let started = Instant::now();
    let deadline = started + Duration::from_millis(30);
    let error = server
        .shutdown_until(deadline)
        .expect_err("blocked writer lacks stop proof");
    assert!(error.to_string().contains("deadline"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(!server.shutdown_complete.load(Ordering::Acquire));
    drop(guard);
    let error = server
        .shutdown_until(Instant::now() + Duration::from_secs(1))
        .expect_err("timeout proof remains invalid after worker is released");
    assert!(
        error.to_string().contains("stop proof unavailable"),
        "{error}"
    );
    let started = Instant::now();
    drop(server);
    assert!(started.elapsed() < Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn scoped_stop_revokes_descendants_and_keeps_sibling() {
    let f = subtree_fixture("scoped-stop", true);
    let response = dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    )
    .expect("scoped stop succeeds");
    let (BrokerResponse::Stopped { outcome }, None) = response else {
        panic!("expected a stopped response");
    };
    assert_eq!(outcome.worker_id, f.b_worker.as_str());
    assert_eq!(outcome.verdict, StopVerdict::Stopped);

    let table = f.scopes.lock().expect("scope table");
    assert!(!table.contains_key(f.b_worker.as_str()));
    assert!(!table.contains_key(f.c_worker.as_str()));
    assert!(!table.contains_key(f.d_worker.as_str()));
    assert!(table.contains_key(f.p_worker.as_str()));
    assert_eq!(
        table[f.s_worker.as_str()].parent_scope.as_deref(),
        Some(f.p_worker.as_str())
    );
    drop(table);

    // The owner stop was durable before descendant settlement, and the
    // sibling host's ledger rows stay untouched.
    assert!(stop_intent_row(&f.p_store, &f.b_worker));
    assert!(!stop_intent_row(&f.p_store, &f.s_worker));

    // Durable scope stores stay behind exactly as in managed shutdown.
    for worker in [&f.b_worker, &f.c_worker, &f.d_worker] {
        assert!(f.storage.join(worker.as_str()).is_dir());
    }

    // A stale authenticated connection from the revoked scope is
    // refused at dispatch before any effect.
    let stale = dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.b_worker,
        &f.p_authority,
        BrokerRequest::Identity {
            worker_id: f.c_worker.as_str().to_owned(),
        },
    );
    assert!(matches!(stale, Err((BrokerRejectionCode::Scope, _))));

    // A child without descendants revokes only its own scope.
    dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.s_worker.as_str().to_owned(),
        },
    )
    .expect("plain child stop succeeds");
    let table = f.scopes.lock().expect("scope table");
    assert_eq!(table.len(), 1);
    assert!(table.contains_key(f.p_worker.as_str()));
    drop(table);
    let _ = std::fs::remove_dir_all(f.root);
}

#[test]
fn scoped_stop_reports_failed_child_cleanup_instead_of_stopped() {
    let f = subtree_fixture("scoped-stop-failure", true);
    let ledger_path = f.storage.join(f.c_worker.as_str()).join(SCOPE_LEDGER_NAME);
    let backup = f.root.join("child-backup.sqlite3");
    Ledger::open(&ledger_path)
        .expect("child ledger")
        .backup(&backup)
        .expect("consistent backup");
    std::fs::remove_file(&ledger_path).expect("remove fixture ledger");
    std::fs::create_dir(&ledger_path).expect("make ledger unavailable");

    let error = dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    )
    .expect_err("failed child cleanup must not report a complete stop");
    let (code, error) = error;
    assert_eq!(code, BrokerRejectionCode::Scope);
    let message = error.to_string();
    assert!(
        message.contains(f.c_worker.as_str()),
        "failure must name the broken scope: {message}"
    );

    // The owner stop was still attempted and journaled first.
    assert!(stop_intent_row(&f.p_store, &f.b_worker));

    // Keep failed scopes frozen with their ledger so cleanup can retry.
    let table = f.scopes.lock().expect("scope table");
    assert!(!table.contains_key(f.b_worker.as_str()));
    assert!(!table.contains_key(f.d_worker.as_str()));
    assert!(
        table
            .get(f.c_worker.as_str())
            .expect("failed scope retained")
            .settling
    );
    assert!(table.contains_key(f.s_worker.as_str()));
    drop(table);
    std::fs::remove_dir(&ledger_path).expect("remove injected fault");
    std::fs::copy(&backup, &ledger_path).expect("restore child ledger");
    let (response, fds) = dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    )
    .expect("retained cleanup can retry");
    assert!(fds.is_none());
    assert!(
        matches!(response, BrokerResponse::Stopped { outcome } if outcome.verdict == StopVerdict::Stopped)
    );
    assert!(!f
        .scopes
        .lock()
        .expect("scope table")
        .contains_key(f.c_worker.as_str()));
    let _ = std::fs::remove_dir_all(f.root);
}

#[test]
fn scoped_stop_preserves_explicit_handoff_subtree() {
    let f = subtree_fixture("scoped-stop-handoff", false);
    // The host scope B hands itself (and everything below it) off
    // through the real dispatch path.
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

    // Stopping the handed-off host stops the host itself but must not
    // settle or revoke the handoff subtree: its pending rows stay
    // exactly as they are for root-run adoption.
    let response = dispatch_request(
        quiet_context(&f.scopes, &f.claims, &f.channel, &f.storage, &f.socket),
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    )
    .expect("handed-off host stop succeeds");
    let (BrokerResponse::Stopped { outcome }, None) = response else {
        panic!("expected a stopped response");
    };
    assert_eq!(outcome.worker_id, f.b_worker.as_str());
    assert!(stop_intent_row(&f.p_store, &f.b_worker));

    let table = f.scopes.lock().expect("scope table");
    for worker in [&f.b_worker, &f.c_worker, &f.d_worker] {
        let entry = table.get(worker.as_str()).expect("handoff entry preserved");
        assert!(entry.handoff);
    }
    assert!(table.contains_key(f.s_worker.as_str()));
    drop(table);

    // No settlement touched the handed-off ledgers.
    let b_ledger = b_store.lock().expect("host ledger lock");
    assert_eq!(
        nonterminal_ids(&b_ledger),
        vec![f.c_worker.as_str().to_owned()]
    );
    drop(b_ledger);
    let _ = std::fs::remove_dir_all(f.root);
}

#[test]
fn settlement_freezes_and_drains_before_revocation() {
    let f = subtree_fixture("settle-drain", true);

    // A dispatch still running on the doomed host blocks its subtree
    // settlement: no entry may revoke while the drain is unfinished.
    f.scopes
        .lock()
        .expect("scope table")
        .get_mut(f.b_worker.as_str())
        .expect("host entry")
        .in_flight
        .fetch_add(1, Ordering::AcqRel);
    // The broker is already stopping, so the unfinished drain gives up instead of waiting out its deadline.
    let stopping = Arc::new(AtomicBool::new(true));
    let blocked = dispatch_request(
        ConnectionContext {
            scopes: Arc::clone(&f.scopes),
            unit_claims: Arc::clone(&f.claims),
            worker_reservations: empty_reservations(),
            allowed: Arc::new(AllowedParentBindings::default()),
            channel: f.channel.clone(),
            storage_root: f.storage.to_path_buf(),
            socket_path: f.socket.to_path_buf(),
            stopping: Arc::clone(&stopping),
        },
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    );
    let (code, error) = blocked.expect_err("an in-flight dispatch must block settlement");
    assert_eq!(code, BrokerRejectionCode::Scope, "{error}");
    assert!(error.to_string().contains("aborted"), "{error}");
    {
        let table = f.scopes.lock().expect("scope table");
        let entry = table.get(f.b_worker.as_str()).expect("host kept");
        assert!(entry.settling, "incomplete cleanup must remain quarantined");
    }

    // Drained, the same stop revokes and settles the whole subtree.
    f.scopes
        .lock()
        .expect("scope table")
        .get_mut(f.b_worker.as_str())
        .expect("host entry")
        .in_flight
        .fetch_sub(1, Ordering::AcqRel);
    let quiet_stopping = Arc::new(AtomicBool::new(false));
    dispatch_request(
        ConnectionContext {
            scopes: Arc::clone(&f.scopes),
            unit_claims: Arc::clone(&f.claims),
            worker_reservations: empty_reservations(),
            allowed: Arc::new(AllowedParentBindings::default()),
            channel: f.channel.clone(),
            storage_root: f.storage.to_path_buf(),
            socket_path: f.socket.to_path_buf(),
            stopping: Arc::clone(&quiet_stopping),
        },
        &f.p_worker,
        &f.p_authority,
        BrokerRequest::Stop {
            worker_id: f.b_worker.as_str().to_owned(),
        },
    )
    .expect("drained stop settles the subtree");
    let table = f.scopes.lock().expect("scope table");
    for worker in [&f.b_worker, &f.c_worker, &f.d_worker] {
        assert!(!table.contains_key(worker.as_str()));
    }
    assert!(table.contains_key(f.s_worker.as_str()));
    drop(table);
    let _ = std::fs::remove_dir_all(f.root);
}

#[test]
fn first_drop_fallback_settles_ordinary_scope() {
    let root = test_root("drop-settles-scope");
    let runtime = private_child(&root, "run");
    let storage = private_child(&root, "storage");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let mut server = ParentBrokerServer::bind(
        &runtime,
        &storage,
        test_channel(),
        AllowedParentBindings::default(),
        owner,
    )
    .expect("broker bound");
    let ordinary = mint_worker_id().expect("ordinary scope");
    server.prepare_scope(&ordinary).expect("ordinary prepared");
    let scopes = Arc::clone(&server.scopes);
    let complete = Arc::clone(&server.shutdown_complete);
    let socket = server.socket_path().to_path_buf();
    let (sender, receiver) = std::sync::mpsc::channel();
    server.shutdown_observer = Some(sender);
    drop(server);
    receiver
        .recv_timeout(BROKER_GRACE + Duration::from_secs(30))
        .expect("fallback shutdown worker did not report completion")
        .expect("fallback did not settle ordinary scope");
    assert!(complete.load(Ordering::Acquire));
    assert!(scopes.lock().expect("scopes").is_empty());
    assert!(!socket.exists());
    let _ = std::fs::remove_dir_all(root);
}
