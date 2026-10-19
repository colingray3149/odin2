//! Launch behavior tests: the parent execution catalog, profile ceilings,
//! worker-id collision and reservation atomicity, and launch admission
//! refusals.

use super::*;

#[test]
fn launch_profiles_honor_requested_isolation_ceiling() {
    let root = test_root("launch-profiles");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let channel = test_channel();
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));

    // An isolated-only entry, plus a registered host entry whose
    // identity is a symlink alias kept verbatim.
    let plain_dir = private_child(&root, "plain");
    let plain_bin = plain_dir.join("tool");
    std::fs::write(&plain_bin, b"payload").expect("plain program");
    let plain_bin = std::fs::canonicalize(&plain_bin).expect("canonical plain");
    let host_target = root.join("host-real");
    std::fs::write(&host_target, b"host payload").expect("host program");
    let alias = root.join("host-alias");
    std::os::unix::fs::symlink(&host_target, &alias).expect("symlink alias");
    let digest = format!("{:064x}", 7);
    let isolated_binding = ParentExecutableBinding::isolated(plain_bin.clone(), digest.clone())
        .expect("isolated binding");
    let host_binding = ParentExecutableBinding::registered_service(alias.clone(), digest.clone())
        .expect("registered binding")
        .with_parent_authority()
        .expect("host role");
    let allowed =
        AllowedParentBindings::new(vec![isolated_binding, host_binding]).expect("catalog");

    let scope_worker = mint_worker_id().expect("scope worker");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let scope_authority =
        activated_scope(&scopes, &storage, &socket, &scope_worker, &owner, &channel);
    let stopping = AtomicBool::new(false);
    let run = |child: &WorkerId, executable: &Path, profile: BrokerLaunchProfile| {
        dispatch_request_with(
            &scopes,
            &claims,
            &channel,
            &allowed,
            &storage,
            &socket,
            &scope_worker,
            &scope_authority,
            &stopping,
            launch_request(executable, child, profile),
        )
    };

    // Unknown executable: denied before any effect.
    let stranger = plain_dir.join("stranger-bin");
    std::fs::write(&stranger, b"stranger").expect("stranger program");
    let stranger = std::fs::canonicalize(&stranger).expect("canonical stranger");
    let stranger_child = mint_worker_id().expect("stranger child");
    let (code, _) = run(&stranger_child, &stranger, BrokerLaunchProfile::Isolated)
        .expect_err("unknown executable denied");
    assert_eq!(code, BrokerRejectionCode::Forbidden);

    // Registered request over an isolated-only entry: the ceiling is
    // refused; no claim, no scope, no launch.
    let plain_child = mint_worker_id().expect("plain child");
    let (code, _) = run(
        &plain_child,
        &plain_bin,
        BrokerLaunchProfile::RegisteredService,
    )
    .expect_err("registered profile must not be granted on an isolated entry");
    assert_eq!(code, BrokerRejectionCode::Forbidden);
    assert!(claims.lock().expect("claims").is_empty());

    // Isolation suppresses nested-scope preparation even for registered hosts.
    let host_child_a = mint_worker_id().expect("host child a");
    let (code, _) = run(&host_child_a, &alias, BrokerLaunchProfile::Isolated)
        .expect_err("launch needs a manager bus");
    assert_eq!(code, BrokerRejectionCode::Worker);
    assert!(!scopes
        .lock()
        .expect("table")
        .contains_key(host_child_a.as_str()));
    assert!(!storage.join(host_child_a.as_str()).exists());

    // Registered request over the registered host entry: admitted past
    // the catalog, the prepared nested scope is discarded and the claim
    // released when the launch cannot complete.
    let host_child_b = mint_worker_id().expect("host child b");
    let (code, _) = run(
        &host_child_b,
        &alias,
        BrokerLaunchProfile::RegisteredService,
    )
    .expect_err("launch needs a manager bus");
    assert_eq!(code, BrokerRejectionCode::Worker);
    assert!(!scopes
        .lock()
        .expect("table")
        .contains_key(host_child_b.as_str()));
    assert!(!storage.join(host_child_b.as_str()).exists());
    assert!(claims.lock().expect("claims").is_empty());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn launch_rejects_worker_id_collisions_across_scopes_and_ledgers() {
    let root = test_root("id-collisions");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let channel = test_channel();
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));

    let plain_dir = private_child(&root, "plain");
    let plain_bin = plain_dir.join("tool");
    std::fs::write(&plain_bin, b"payload").expect("plain program");
    let plain_bin = std::fs::canonicalize(&plain_bin).expect("canonical plain");
    let allowed = AllowedParentBindings::new(vec![ParentExecutableBinding::isolated(
        plain_bin.clone(),
        format!("{:064x}", 3),
    )
    .expect("isolated binding")])
    .expect("catalog built");

    let root_worker = mint_worker_id().expect("root worker");
    prepare_scope_entry(
        &scopes,
        &storage,
        &socket,
        &root_worker,
        Arc::clone(&owner),
        None,
        1,
    )
    .expect("root scope");
    let scope_worker = mint_worker_id().expect("requesting scope");
    let mut scope_identity = identity(scope_worker.clone());
    scope_identity.unit = format!("tx-wp-attempt-1-{}.scope", scope_worker.as_str());
    scope_identity.cgroup_path = format!("/user.slice/{}.scope", scope_worker.as_str());
    record_payload_running(&owner, &scope_identity, &correlation());
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        root_worker.as_str(),
        &scope_worker,
        Arc::clone(&owner),
    )
    .expect("requesting scope");
    activate_scope_entry(&scopes, &scope_worker, &scope_identity).expect("scope activated");
    let sibling = mint_worker_id().expect("sibling scope");
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        root_worker.as_str(),
        &sibling,
        Arc::clone(&owner),
    )
    .expect("sibling scope");

    // The requesting scope ledger already records this child.
    let scope_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(scope_worker.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("scope ledger"),
    ));
    let previous_child = mint_worker_id().expect("previous child");
    record_child_row(&scope_store, &previous_child, false);
    let scope_authority = Arc::new(StopAuthority::new(
        Arc::clone(&scope_store),
        channel.clone(),
    ));
    let stopping = AtomicBool::new(false);
    let attempt = |child: &WorkerId| {
        dispatch_request_with(
            &scopes,
            &claims,
            &channel,
            &allowed,
            &storage,
            &socket,
            &scope_worker,
            &scope_authority,
            &stopping,
            launch_request(&plain_bin, child, BrokerLaunchProfile::Isolated),
        )
    };

    for collision in [&root_worker, &scope_worker, &sibling] {
        let (code, _) =
            attempt(collision).expect_err("broker scope keys must be rejected as child ids");
        assert_eq!(code, BrokerRejectionCode::State, "{collision}");
    }
    let (code, _) =
        attempt(&previous_child).expect_err("own-ledger rows must be rejected as child ids");
    assert_eq!(code, BrokerRejectionCode::State);

    // A fresh ID reaches launch, which fails because the manager bus is unavailable.
    let fresh = mint_worker_id().expect("fresh child");
    let (code, _) = attempt(&fresh).expect_err("launch needs a manager bus");
    assert_eq!(code, BrokerRejectionCode::Worker);
    assert!(claims.lock().expect("claims").is_empty());
    let _ = std::fs::remove_dir_all(root);
}

/// Concurrent sibling launches admit one request per worker ID;
/// the reservation survives launch failure.
#[test]
fn concurrent_sibling_launches_cannot_reuse_a_worker_id() {
    let root = test_root("concurrent-ids");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let channel = test_channel();
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let reservations = empty_reservations();

    let plain_dir = private_child(&root, "plain");
    let plain_bin = plain_dir.join("tool");
    std::fs::write(&plain_bin, b"payload").expect("plain program");
    let plain_bin = std::fs::canonicalize(&plain_bin).expect("canonical plain");
    let allowed = Arc::new(
        AllowedParentBindings::new(vec![ParentExecutableBinding::isolated(
            plain_bin.clone(),
            format!("{:064x}", 5),
        )
        .expect("isolated binding")])
        .expect("catalog built"),
    );

    let mut siblings = Vec::new();
    for tag in 0..2 {
        let worker = mint_worker_id().expect("sibling worker");
        let owner = Arc::new(Mutex::new(
            Ledger::open_in_memory().expect("sibling owner ledger"),
        ));
        let mut scoped = identity(worker.clone());
        scoped.unit = format!("tx-wp-attempt-1-s{tag}-{}.scope", worker.as_str());
        scoped.cgroup_path = format!("/user.slice/s{tag}-{}.scope", worker.as_str());
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
        .expect("sibling scope");
        activate_scope_entry(&scopes, &worker, &scoped).expect("sibling activated");
        siblings.push((worker, Arc::new(StopAuthority::new(owner, channel.clone()))));
    }

    let child = mint_worker_id().expect("contested child");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (worker, authority) in &siblings {
        let barrier = Arc::clone(&barrier);
        let scopes = Arc::clone(&scopes);
        let claims = Arc::clone(&claims);
        let reservations = Arc::clone(&reservations);
        let allowed = Arc::clone(&allowed);
        let worker = worker.clone();
        let authority = Arc::clone(authority);
        let child = child.clone();
        let channel = channel.clone();
        let storage = storage.clone();
        let socket = socket.clone();
        let plain_bin = plain_bin.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            dispatch_request_reservations(
                &scopes,
                &claims,
                &reservations,
                &channel,
                &allowed,
                &storage,
                &socket,
                &worker,
                &authority,
                &AtomicBool::new(false),
                launch_request(&plain_bin, &child, BrokerLaunchProfile::Isolated),
            )
        }));
    }
    let mut admitted = 0;
    let mut refused = 0;
    for handle in handles {
        let (code, error) = handle
            .join()
            .expect("launch thread")
            .expect_err("no manager bus exists");
        match code {
            BrokerRejectionCode::Worker => admitted += 1,
            BrokerRejectionCode::State => {
                refused += 1;
                assert!(error.to_string().contains("already reserved"), "{error}");
            }
            other => panic!("unexpected rejection {other:?}: {error}"),
        }
    }
    assert_eq!(
        (admitted, refused),
        (1, 1),
        "exactly one sibling may pass the collision scan"
    );
    assert!(claims.lock().expect("claims").is_empty());
    assert!(reservations
        .lock()
        .expect("reservations")
        .contains_key(child.as_str()));
    // Reuse from either scope stays refused even after both effects
    // failed: the reservation tombstone is permanent.
    for (worker, authority) in &siblings {
        let (code, _) = dispatch_request_reservations(
            &scopes,
            &claims,
            &reservations,
            &channel,
            &allowed,
            &storage,
            &socket,
            worker,
            authority,
            &AtomicBool::new(false),
            launch_request(&plain_bin, &child, BrokerLaunchProfile::Isolated),
        )
        .expect_err("a reserved id is never reusable");
        assert_eq!(code, BrokerRejectionCode::State);
    }
    let _ = std::fs::remove_dir_all(root);
}

/// Failed launches release claims and prepared scopes but retain worker-ID reservations.
#[test]
fn failed_prelaunch_launch_rolls_back_claim_and_prepared_scope() {
    let root = test_root("prelaunch-rollback");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let reservations = empty_reservations();
    let plain_dir = private_child(&root, "plain");
    let plain_bin = plain_dir.join("tool");
    std::fs::write(&plain_bin, b"payload").expect("plain program");
    let plain_bin = std::fs::canonicalize(&plain_bin).expect("canonical plain");
    let allowed = Arc::new(
        AllowedParentBindings::new(vec![ParentExecutableBinding::registered_service(
            plain_bin.clone(),
            format!("{:064x}", 6),
        )
        .expect("registered binding")
        .with_parent_authority()
        .expect("host role")])
        .expect("catalog built"),
    );
    // Fail GetUnit after admission and nested-scope preparation to exercise cleanup.
    let bus = FakeManagerBus::start(BTreeMap::from([(
        "GetUnit".to_owned(),
        "org.odin.test.ManagerUnavailable".to_owned(),
    )]));
    let channel = bus.channel();
    let scope_worker = mint_worker_id().expect("scope worker");
    let owner = Arc::new(Mutex::new(
        Ledger::open_in_memory().expect("scope owner ledger"),
    ));
    let scope_authority =
        activated_scope(&scopes, &storage, &socket, &scope_worker, &owner, &channel);
    let attempt = |child: &WorkerId| {
        dispatch_request_reservations(
            &scopes,
            &claims,
            &reservations,
            &channel,
            &allowed,
            &storage,
            &socket,
            &scope_worker,
            &scope_authority,
            &AtomicBool::new(false),
            launch_request(&plain_bin, child, BrokerLaunchProfile::RegisteredService),
        )
    };

    let child = mint_worker_id().expect("child");
    let (code, error) = attempt(&child).expect_err("GetUnit must fail honestly");
    assert_eq!(code, BrokerRejectionCode::Worker, "{error}");
    assert!(claims.lock().expect("claims").is_empty());
    assert!(!scopes.lock().expect("table").contains_key(child.as_str()));
    assert!(!storage.join(child.as_str()).exists());
    assert!(reservations
        .lock()
        .expect("reservations")
        .contains_key(child.as_str()));
    let (code, error) = attempt(&child).expect_err("the spent id is never reusable");
    assert_eq!(code, BrokerRejectionCode::State, "{error}");
    assert!(error.to_string().contains("already reserved"), "{error}");
    assert!(claims.lock().expect("claims").is_empty());

    // A nested prepare failure after the claim lands unrolls the same
    // way: the pre-created store root refuses the preparation.
    let child_two = mint_worker_id().expect("child two");
    std::fs::create_dir(storage.join(child_two.as_str())).expect("pre-created store");
    let (code, _) = attempt(&child_two).expect_err("prepare must fail");
    assert_eq!(code, BrokerRejectionCode::Scope);
    assert!(claims.lock().expect("claims").is_empty());
    assert!(!scopes
        .lock()
        .expect("table")
        .contains_key(child_two.as_str()));
    assert!(reservations
        .lock()
        .expect("reservations")
        .contains_key(child_two.as_str()));
    std::fs::remove_dir(storage.join(child_two.as_str())).expect("cleanup store");
    let _ = std::fs::remove_dir_all(root);
}

/// Check stop intent before taking claims or reservations.
#[test]
fn launch_refuses_scope_owner_stop_intent() {
    let root = test_root("launch-stop");
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let channel = test_channel();
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let reservations = empty_reservations();
    let plain_dir = private_child(&root, "plain");
    let plain_bin = plain_dir.join("tool");
    std::fs::write(&plain_bin, b"payload").expect("plain program");
    let plain_bin = std::fs::canonicalize(&plain_bin).expect("canonical plain");
    let allowed = AllowedParentBindings::new(vec![ParentExecutableBinding::isolated(
        plain_bin.clone(),
        format!("{:064x}", 8),
    )
    .expect("isolated binding")])
    .expect("catalog built");
    let scope_worker = mint_worker_id().expect("scope worker");
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let scope_authority =
        activated_scope(&scopes, &storage, &socket, &scope_worker, &owner, &channel);
    record_pending_stop_row(&owner, &scope_worker);
    let child = mint_worker_id().expect("child");
    let (code, error) = dispatch_request_with(
        &scopes,
        &claims,
        &channel,
        &allowed,
        &storage,
        &socket,
        &scope_worker,
        &scope_authority,
        &AtomicBool::new(false),
        launch_request(&plain_bin, &child, BrokerLaunchProfile::Isolated),
    )
    .expect_err("a stopped owner must refuse fresh launches");
    assert_eq!(code, BrokerRejectionCode::State, "{error}");
    assert!(error.to_string().contains("stop intent"), "{error}");
    assert!(claims.lock().expect("claims").is_empty());
    assert!(!reservations
        .lock()
        .expect("reservations")
        .contains_key(child.as_str()));
    let _ = std::fs::remove_dir_all(root);
}
