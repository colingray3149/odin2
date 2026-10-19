//! Owned launch and admission invariants: registered naming and channel
//! validation, scope properties proven before the payload, owner-unit and
//! bounded-lifetime admission gates, pending-start-job disambiguation,
//! collision rejection, and the supervisor consuming the authority.

use super::*;

#[test]
fn naming_rejects_unsafe_components() {
    assert!(WorkerNaming::new("tx", "wp", 0, mint_worker_id().unwrap()).is_ok());
    let error = WorkerNaming::new("tx id", "wp", 0, mint_worker_id().unwrap())
        .expect_err("space must be rejected");
    assert_eq!(error.code(), WorkerErrorCode::ChannelInvalid);
    assert!(WorkerNaming::new("", "wp", 0, mint_worker_id().unwrap()).is_err());
    let naming = WorkerNaming::new("tx0123456789abcdef", "wp-11a", 7, mint_worker_id().unwrap())
        .expect("naming");
    let unit = naming.unit();
    assert!(unit.starts_with("tx0123456789abcdef-wp\\x2d11a-attempt-7-"));
    assert!(unit.ends_with(".scope"));
}

#[test]
fn channel_rejects_relative_registered_paths() {
    let bus = BusAddress::unix_socket("/tmp/bus".into()).expect("bus");
    assert!(WorkerChannel::new(bus.clone(), "relative/bin".into(), "/bin/x".into()).is_err());
    assert!(WorkerChannel::new(bus, "/bin/x".into(), "".into()).is_err());
}

#[test]
fn cgroup_sets_id_escape() {
    let fixture = cgroup_fixture();
    let manager = FakeManager::start(&fixture);
    let channel = manager.channel();
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "family"),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");

    // The leader identity is still live immediately after the gate and
    // is exactly the pre-gate proof.
    let proven_pid = authority.identity().leader_pid;
    authority
        .verify_leader(proven_pid)
        .expect("proven leader identity");
    let unit = authority.identity().unit.clone();

    let mut stdout = authority.leader().stdout.take().expect("payload stdout");
    let mut raw = String::new();
    let _ = stdout.read_to_string(&mut raw);
    let status = authority.leader().wait().expect("payload exits");
    assert!(status.success(), "payload failed: {status}");
    authority.mark_reaped();
    let lines = parse_payload_output(&raw);

    let (leader_pid, leader_pgid, leader_sid) = identity_of("LEADER", &lines);
    let middle_pid = unsigned_of("MIDDLE_PID", &lines);
    let (leaf_pid, leaf_pgid, leaf_sid) = identity_of("LEAF", &lines);
    assert_eq!(leader_pid, proven_pid);
    assert_eq!(leader_sid as u32, leader_pid, "the helper called setsid");
    assert_eq!(leader_pgid as u32, leader_pid, "the leader owns its group");
    // The deepest generation performed its own daemon-style escape:
    // new session and new group, unreachable by a leader-group signal.
    assert_eq!(leaf_sid as u32, leaf_pid);
    assert_eq!(leaf_pgid as u32, leaf_pid);
    assert_ne!(leaf_sid, leader_sid);
    assert_ne!(leaf_pid, middle_pid);
    // Despite ancestry/session/group escape, cgroup membership is
    // inherited and unchanged.
    assert_eq!(
        string_of("LEADER_CGROUP", &lines),
        string_of("LEAF_CGROUP", &lines),
        "setsid/double-fork must not leave the owned cgroup"
    );

    let report = authority.stop().expect("stop");
    assert!(report.stopped);
    assert!(report.residual.is_none());
    assert_eq!(manager.unit_active(&unit).as_deref(), Some("inactive"));
}

#[test]
fn spawn_fails_when_scope_cgroup_lacks_the_leader() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    manager.config.lock().expect("config").detach_new_units = true;
    // A manager that never attached the registered process offers no
    // MainPID to fall back on — scopes have none — so the exact
    // cgroup membership proof must fail the spawn closed.
    let error = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect_err("a scope without its leader must fail the spawn");
    assert_eq!(error.code(), WorkerErrorCode::IdentityProof);
}

#[test]
fn scope_properties_are_proven_before_the_payload() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits {
            lifetime: crate::ScopeLifetime::Bounded(Duration::from_secs(90)),
            timeout_stop: Duration::from_secs(3),
            memory_high: Some(1 << 30),
            memory_max: None,
            tasks_max: Some(128),
        },
    )
    .expect("worker spawn");
    {
        let config = manager.config.lock().expect("config");
        let unit = config
            .units
            .get(&authority.identity().unit)
            .expect("scope recorded");
        // KillMode and delegation are exactly as the record demands.
        assert_eq!(unit.kill_mode, "control-group");
        assert!(!unit.delegate);
        // The parked helper is the scope's registered PIDs member,
        // attached into `cgroup.procs`; a scope reports no MainPID.
        assert_eq!(unit.attached_pid, authority.identity().leader_pid);
        // Limits traveled to the manager.
        assert_eq!(
            unit.properties.get("RuntimeMaxUSec"),
            Some(&Value::Uint64(90_000_000))
        );
        assert_eq!(
            unit.properties.get("TimeoutStopUSec"),
            Some(&Value::Uint64(3_000_000))
        );
        assert_eq!(
            unit.properties.get("MemoryHigh"),
            Some(&Value::Uint64(1 << 30))
        );
        assert_eq!(unit.properties.get("TasksMax"), Some(&Value::Uint64(128)));
        assert!(!unit.properties.contains_key("MemoryMax"));
    }
    authority.stop().expect("stop");
}

/// An unprovable owner must refuse before creating any scope or payload.
#[test]
fn owner_bound_scope_requires_a_proven_owner() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let initial_units = manager
        .config
        .lock()
        .expect("config")
        .units
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let error = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits {
            lifetime: crate::ScopeLifetime::OwnerUnit,
            timeout_stop: Duration::from_secs(3),
            ..crate::ScopeLimits::default()
        },
    )
    .expect_err("an unprovable owner must fail the spawn");
    assert_eq!(error.code(), WorkerErrorCode::IdentityProof);
    assert_eq!(
        manager
            .config
            .lock()
            .expect("config")
            .units
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        initial_units,
        "an unprovable owner must never create a scope"
    );
}

#[test]
fn bounded_runtime_rejects_disabled_timer_encodings() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let initial_units = manager
        .config
        .lock()
        .expect("config")
        .units
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for duration in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_micros(u64::MAX),
    ] {
        let error = WorkerAuthority::spawn(
            &channel,
            naming(),
            &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
            crate::ScopeLimits {
                lifetime: crate::ScopeLifetime::Bounded(duration),
                ..crate::ScopeLimits::default()
            },
        )
        .expect_err("a bounded lifetime cannot encode a disabled systemd timer");
        assert_eq!(error.code(), WorkerErrorCode::IdentityProof);
        assert_eq!(
            manager
                .config
                .lock()
                .expect("config")
                .units
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            initial_units,
            "a rejected ceiling must never create a scope"
        );
    }
}

#[test]
fn scope_activation_waits_only_for_its_pending_start_job() {
    let manager = FakeManager::start(&cgroup_fixture());
    let name = "odin-worker-seed.scope";
    let job = "/org/freedesktop/systemd1/job/17";
    {
        let mut config = manager.config.lock().expect("config");
        config.activate_after_queries = 3;
        let unit = config.units.get_mut(name).expect("seed scope");
        unit.active_state = "inactive".to_owned();
        unit.properties.insert(
            "Job".to_owned(),
            Value::Struct(vec![Value::Uint32(17), Value::ObjectPath(job.to_owned())]),
        );
    }
    let mut client = ManagerClient::connect(&manager.address).expect("manager");
    let state = wait_scope_active(&mut client, name, Some(job)).expect("queued start completes");
    assert_eq!(
        state.get("ActiveState"),
        Some(&Value::String("active".to_owned()))
    );
    for (id, path) in [(0, "/"), (18, "/org/freedesktop/systemd1/job/18")] {
        {
            let mut config = manager.config.lock().expect("config");
            let unit = config.units.get_mut(name).expect("seed scope");
            unit.active_state = "inactive".to_owned();
            unit.properties.insert(
                "Job".to_owned(),
                Value::Struct(vec![Value::Uint32(id), Value::ObjectPath(path.to_owned())]),
            );
        }
        let error =
            wait_scope_active(&mut client, name, Some(job)).expect_err("not our pending start");
        assert_eq!(error.code(), WorkerErrorCode::ScopeRejected);
        assert!(error.to_string().contains("entered inactive"), "{error}");
    }
}

#[test]
fn scope_collision_fails_the_spawn() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    // A pre-existing unit with the target name makes StartTransientUnit
    // fail closed: no pre-existing unit is ever adopted or operated.
    let naming = naming();
    let unit = naming.unit();
    {
        let mut config = manager.config.lock().expect("config");
        let invocation = config
            .units
            .get("odin-worker-seed.scope")
            .expect("seed")
            .invocation;
        let cgroup = config.cgroup_root.clone();
        config.units.insert(
            unit.clone(),
            FakeUnit {
                invocation,
                attached_pid: 0,
                attached_start_ticks: None,
                cgroup,
                active_state: "active".to_owned(),
                sub_state: "running".to_owned(),
                kill_mode: "control-group".to_owned(),
                delegate: false,
                properties: BTreeMap::new(),
            },
        );
    }
    let error = WorkerAuthority::spawn(
        &channel,
        naming,
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect_err("a colliding unit must fail the spawn");
    assert_eq!(error.code(), WorkerErrorCode::ScopeRejected);
}

#[test]
fn supervisor_run_consumes_the_worker_authority() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let mut supervisor = ProcessSupervisor::new(
        ProcessLimits::default(),
        crate::runner::channel_transport(channel),
    )
    .expect("supervisor");
    let token = crate::CancellationToken::new();
    let outcome = supervisor
        .run(
            &worker_spec(env_allowlist(&[("LANG", "C")]), "family"),
            &token,
        )
        .expect("worker run");
    // The runner path ran the payload inside the owned scope: the
    // outcome is a normal exit with captured output and kernel
    // identity.
    assert!(matches!(
        outcome.disposition,
        crate::ExitDisposition::Exited(0)
    ));
    assert!(
        outcome
            .stdout
            .as_bytes()
            .windows(b"ODIN_PAYLOAD_BEGIN".len())
            .any(|window| window == b"ODIN_PAYLOAD_BEGIN"),
        "the payload output must be captured by the supervisor"
    );
    assert!(outcome.identity.pid > 0);
    {
        let config = manager.config.lock().expect("config");
        let unit = config
            .units
            .values()
            .find(|unit| unit.attached_pid == outcome.identity.pid)
            .expect("runner must register the outcome leader");
        assert_eq!(unit.kill_mode, "control-group");
        assert!(!unit.delegate);
    }
    let teardown = supervisor
        .cleanup(&crate::ScanCriteria::new("", ""), &crate::SurvivorScanner)
        .expect("cleanup");
    assert!(teardown.scan_complete);
    assert!(teardown.stopped);
}

#[test]
fn a_truncated_capture_is_a_reaped_exit_or_a_proved_output_limit_stop() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let limits = ProcessLimits {
        max_stdout_bytes: 24,
        ..ProcessLimits::default()
    };
    let mut supervisor = ProcessSupervisor::new(limits, crate::runner::channel_transport(channel))
        .expect("supervisor");
    let outcome = supervisor
        .run(
            &worker_spec(env_allowlist(&[("LANG", "C")]), "burst"),
            &crate::CancellationToken::new(),
        )
        .expect("worker run");
    assert!(outcome.stdout.truncated());
    assert!(!outcome.stdout.as_bytes().is_empty());
    assert!(outcome.stdout.as_bytes().len() <= 24);
    match outcome.disposition {
        crate::ExitDisposition::Exited(code) | crate::ExitDisposition::Signaled(code) => {
            assert!(
                outcome.stop.is_none(),
                "a reaped status {code} has no stop evidence"
            );
        }
        crate::ExitDisposition::OutputLimit { .. } => {
            assert!(
                outcome.stop.is_some(),
                "OutputLimit without a stop is the misclassified finished exit"
            );
        }
        other => panic!("unexpected disposition {other:?}"),
    }
}
