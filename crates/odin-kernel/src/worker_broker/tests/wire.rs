//! Wire behavior tests: serde round-trips with unknown-field denial, the
//! remote runtime-budget and frame-codec ceilings, and the parent
//! binding catalog's fail-closed validation of private roots.

use super::*;

#[test]
fn wire_is_lossless_and_deny_unknown() {
    let worker = mint_worker_id().expect("minted worker id");
    let request = BrokerRequest::Launch {
        correlation_id: "corr".to_owned(),
        naming: BrokerNaming {
            tx_id: "tx".to_owned(),
            wp_id: "wp".to_owned(),
            attempt: 1,
            worker_id: worker.as_str().to_owned(),
        },
        spec: BrokerSpec {
            argv: vec![b"/bin/true".to_vec()],
            current_dir: "/".to_owned(),
            environment: vec![BrokerEnvironmentEntry {
                key: "CORRELATION_ID".to_owned(),
                value: vec![0xff, 0xfe],
            }],
        },
        limits: BrokerLimits {
            runtime_max_millis: std::num::NonZeroU64::new(1_000).expect("positive ceiling"),
            timeout_stop_millis: 1_000,
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        },
        profile: BrokerLaunchProfile::Isolated,
    };
    let encoded = serde_json::to_vec(&request).expect("request encodes");
    assert_eq!(
        serde_json::from_slice::<BrokerRequest>(&encoded).expect("request decodes"),
        request
    );
    // The requested ceiling is a strict enum: unknown profiles are
    // denied at the codec, never interpreted as isolation upgrades.
    assert!(serde_json::from_str::<BrokerRequest>(
        r#"{"op":"launch","correlation_id":"c","naming":{"tx_id":"tx","wp_id":"wp",
                "attempt":1,"worker_id":"w"},"spec":{"argv":[],"current_dir":"/",
                "environment":[]},"limits":{"runtime_max_millis":1,"timeout_stop_millis":1,
                "memory_high":null,"memory_max":null,"tasks_max":null},
                "profile":"host_network"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<BrokerRequest>(
        r#"{"op":"close_stdin","worker_id":"abc","extra":1}"#
    )
    .is_err());

    let response = BrokerResponse::Stopped {
        outcome: BrokerStopOutcome {
            worker_id: worker.as_str().to_owned(),
            verdict: StopVerdict::Failed(StopResidue {
                unit_active: true,
                cgroup_present: true,
                processes: vec![StopResidueProcess {
                    pid: 1,
                    start_time_ticks: 2,
                }],
            }),
            evidence: StopEvidence::new(worker.as_str(), "unit", "/cgroup"),
            trace: Vec::new(),
            replay: false,
        },
    };
    let encoded = serde_json::to_vec(&response).expect("response encodes");
    assert_eq!(
        serde_json::from_slice::<BrokerResponse>(&encoded).expect("response decodes"),
        response
    );
    assert!(
        serde_json::from_str::<BrokerResponse>(r#"{"op":"written","count":1,"extra":1}"#).is_err()
    );
}

#[test]
fn remote_jobs_cannot_disable_their_runtime_budget() {
    let finite = serde_json::json!({"runtime_max_millis": 90_000, "timeout_stop_millis": 1_000});
    let decoded: BrokerLimits = serde_json::from_value(finite.clone()).expect("finite ceiling");
    assert_eq!(
        limits_from_wire(&decoded)
            .expect("validated budget")
            .lifetime,
        ScopeLifetime::Bounded(Duration::from_secs(90))
    );
    for invalid in [serde_json::Value::Null, serde_json::json!(0)] {
        let mut input = finite.clone();
        input["runtime_max_millis"] = invalid;
        assert!(serde_json::from_value::<BrokerLimits>(input).is_err());
    }
    let mut missing = finite;
    missing
        .as_object_mut()
        .expect("object")
        .remove("runtime_max_millis");
    assert!(serde_json::from_value::<BrokerLimits>(missing).is_err());
    let oversized: BrokerLimits = serde_json::from_value(serde_json::json!({
        "runtime_max_millis": u64::MAX, "timeout_stop_millis": 1_000
    }))
    .expect("unsigned duration");
    assert!(limits_from_wire(&oversized).is_err());
    for lifetime in [
        ScopeLifetime::Bounded(Duration::from_nanos(1)),
        ScopeLifetime::OwnerUnit,
    ] {
        assert!(limits_to_wire(&ScopeLimits {
            lifetime,
            ..ScopeLimits::default()
        })
        .is_err());
    }
}

#[test]
fn frame_codec_handles_fragmentation_descriptors_and_ceiling() {
    let payload = br#"{"op":"written"}"#.to_vec();

    let (mut writer, mut reader) = UnixStream::pair().expect("socket pair");
    let length = u32::try_from(payload.len())
        .expect("small payload")
        .to_be_bytes();
    let fragment_payload = payload.clone();
    let fragmented = std::thread::spawn(move || {
        writer
            .write_all(&length[..2])
            .expect("first header fragment");
        std::thread::sleep(Duration::from_millis(5));
        writer
            .write_all(&length[2..])
            .expect("second header fragment");
        writer.write_all(&fragment_payload).expect("payload");
    });
    let (decoded, fds) = read_frame(&mut reader).expect("fragmented frame");
    assert_eq!(decoded, payload);
    assert!(fds.is_empty());
    fragmented.join().expect("fragment writer joined");

    let (mut writer, mut reader) = UnixStream::pair().expect("descriptor socket pair");
    let send_fd = reader.as_fd();
    write_frame(&mut writer, &payload, Some(&[send_fd])).expect("descriptor frame");
    let (decoded, fds) = read_frame(&mut reader).expect("descriptor frame read");
    assert_eq!(decoded, payload);
    assert_eq!(fds.len(), 1);

    let (mut writer, mut reader) = UnixStream::pair().expect("ceiling socket pair");
    writer
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .expect("oversized header");
    assert!(matches!(
        read_frame(&mut reader),
        Err(ParentAuthorityError::Protocol(_))
    ));
}

#[test]
fn binding_catalog_and_private_roots_fail_closed() {
    assert!(ParentExecutableBinding::isolated(PathBuf::from("bin/tool"), "a".repeat(64)).is_err());

    let root = test_root("binding");
    let program = root.join("tool");
    std::fs::write(&program, b"not executed").expect("program written");
    let canonical = std::fs::canonicalize(&program).expect("canonical program");
    assert!(ParentExecutableBinding::isolated(canonical.clone(), "ab".to_owned()).is_err());
    let digest = format!("{:064x}", 9);
    let isolated = ParentExecutableBinding::isolated(canonical.clone(), digest.clone())
        .expect("valid isolated binding");
    let catalog = AllowedParentBindings::new(vec![isolated.clone()]).expect("valid catalog");
    let observed = catalog.binding_for(&canonical).expect("catalog entry");
    assert_eq!(observed.profile(), ParentExecutableProfile::Isolated);
    assert_eq!(observed.compiled_binding_blake3(), digest);
    assert!(catalog.binding_for(Path::new("/bin/other")).is_none());
    assert!(AllowedParentBindings::new(vec![isolated.clone(), isolated]).is_err());

    // Preserve invocation aliases verbatim while verifying executable bytes at launch.
    let alias_target = root.join("tool-real");
    std::fs::write(&alias_target, b"not executed either").expect("alias target");
    let alias = root.join("tool-alias");
    std::os::unix::fs::symlink(&canonical, &alias).expect("symlink alias");
    let alias_binding =
        ParentExecutableBinding::isolated(alias.clone(), digest.clone()).expect("alias binding");
    assert_eq!(alias_binding.executable(), alias.as_path());
    let alias_catalog = AllowedParentBindings::new(vec![alias_binding]).expect("alias catalog");
    assert!(alias_catalog.binding_for(&alias).is_some());
    assert!(alias_catalog.binding_for(&canonical).is_none());

    // A broken alias resolves to nothing and fails closed.
    let broken = root.join("broken-alias");
    std::os::unix::fs::symlink(root.join("missing-target"), &broken).expect("broken alias");
    assert!(ParentExecutableBinding::isolated(broken, digest.clone()).is_err());

    let public = private_child(&root, "public");
    std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).expect("public mode");
    assert!(validate_private_root("test", &public).is_err());
    let private = private_child(&root, "private");
    assert_eq!(
        validate_private_root("test", &private).expect("private root"),
        std::fs::canonicalize(&private).expect("canonical private root")
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn abandoned_broker_refuses_a_decoded_launch_before_dispatch() {
    use super::super::scope::revalidate_and_reserve;
    use super::super::transport::{serve_bound_connection, ConnectionContext, BEFORE_DISPATCH};

    let root = test_root("abandon-buffered");
    let runtime = private_child(&root, "runtime");
    let storage = private_child(&root, "storage");
    let channel = test_channel();
    let owner = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let executable = root.join("tool");
    std::fs::write(&executable, b"payload").expect("program");
    let allowed = AllowedParentBindings::new(vec![ParentExecutableBinding::isolated(
        executable.clone(),
        "a".repeat(64),
    )
    .expect("binding")])
    .expect("catalog");
    let broker = ParentBrokerServer::bind(
        &runtime,
        &storage,
        channel.clone(),
        allowed.clone(),
        Arc::clone(&owner),
    )
    .expect("broker");
    let worker = mint_worker_id().expect("scope worker");
    let child = mint_worker_id().expect("child worker");
    let authority = activated_scope(
        &broker.scopes,
        &storage,
        broker.socket_path(),
        &worker,
        &owner,
        &channel,
    );
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    // Keep this wire pair open and its loop flag unset deliberately: the
    // scope freeze, not stream closure or the next loop check, must reject.
    let stopping = Arc::new(AtomicBool::new(false));
    let context = ConnectionContext {
        scopes: Arc::clone(&broker.scopes),
        unit_claims: Arc::clone(&claims),
        worker_reservations: Arc::clone(&broker.worker_reservations),
        allowed: Arc::new(allowed),
        channel,
        storage_root: storage.clone(),
        socket_path: broker.socket_path().to_path_buf(),
        stopping: Arc::clone(&stopping),
    };
    let (mut client, server) = UnixStream::pair().expect("wire pair");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read bound");
    let (decoded_tx, decoded_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    let scope_worker = worker.as_str().to_owned();
    // Authentication is already supplied by the activated-scope fixture;
    // decoding, binding checks, dispatch and effect admission are production.
    let handler = std::thread::spawn(move || {
        BEFORE_DISPATCH.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                decoded_tx.send(()).expect("decoded witness");
                resume_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("resume");
            }));
        });
        serve_bound_connection(context, server, scope_worker, authority);
    });
    let envelope = BrokerEnvelope {
        scope_worker: worker.as_str().to_owned(),
        store_root: storage.join(worker.as_str()).to_string_lossy().into_owned(),
        request: launch_request(&executable, &child, BrokerLaunchProfile::Isolated),
    };
    write_frame(
        &mut client,
        &serde_json::to_vec(&envelope).expect("envelope"),
        None,
    )
    .expect("request frame");
    decoded_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("decoded boundary");
    broker.abandon();
    // Even a request admitted before the freeze cannot reserve a new effect.
    let (code, _) = revalidate_and_reserve(&broker.scopes, worker.as_str())
        .err()
        .expect("effect admission frozen");
    assert_eq!(code, BrokerRejectionCode::Scope);
    resume_tx.send(()).expect("resume handler");
    let (response, fds) = read_frame(&mut client).expect("rejection frame");
    assert!(fds.is_empty());
    assert!(matches!(
        serde_json::from_slice::<BrokerResponse>(&response).expect("response"),
        BrokerResponse::Rejected {
            code: BrokerRejectionCode::Scope,
            ..
        }
    ));
    drop(client);
    handler.join().expect("handler joined");
    assert!(broker
        .worker_reservations
        .lock()
        .expect("reservations")
        .is_empty());
    assert!(claims.lock().expect("claims").is_empty());
    let table = broker.scopes.lock().expect("scopes");
    assert_eq!(table.len(), 1);
    let entry = table.get(worker.as_str()).expect("authority retained");
    assert!(entry.authority.is_some());
    assert!(entry.settling);
    assert_eq!(entry.in_flight.load(Ordering::Acquire), 0);
    drop(table);
    drop(broker);
    assert!(storage
        .join(worker.as_str())
        .join(SCOPE_LEDGER_NAME)
        .exists());
    let _ = std::fs::remove_dir_all(root);
}
