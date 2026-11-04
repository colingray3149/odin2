//! Owned launch and admission invariants: registered naming and channel
//! validation, scope properties proven before the payload, owner-unit and
//! bounded-lifetime admission gates, pending-start-job disambiguation,
//! collision rejection, and the supervisor consuming the authority.

use super::*;

#[test]
fn spawn_fails_when_scope_cgroup_lacks_the_leader() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager
        .channel()
        .with_proof_deadline(Duration::from_millis(20));
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
fn a_registered_service_runs_only_its_bound_executable() {
    let dir = tempfile::tempdir().expect("scratch directory");
    let binary = dir.path().join("service");
    std::fs::write(&binary, b"").expect("service file");
    let digest = "0".repeat(64);
    for refused in [dir.path().to_path_buf(), "service".into()] {
        let error = crate::RegisteredServiceBinding::new(refused, digest.clone())
            .expect_err("a directory or relative path cannot be a bound service");
        assert_eq!(error.code(), WorkerErrorCode::ChannelInvalid);
    }
    let binding = crate::RegisteredServiceBinding::new(binary, digest).expect("binding");

    let manager = FakeManager::start(&cgroup_fixture());
    let units_before = manager.config.lock().expect("config").units.len();
    let error = WorkerAuthority::prepare_registered_service(
        &manager.channel(),
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
        &binding,
    )
    .expect_err("the test harness is not the bound executable");
    assert_eq!(error.code(), WorkerErrorCode::ChannelInvalid);
    assert_eq!(
        manager.config.lock().expect("config").units.len(),
        units_before,
        "a refused service creates no scope"
    );
}

/// Runs one payload through a supervisor on a fresh fake manager, then tears it down.
fn supervised(
    limits: ProcessLimits,
    payload: &str,
    token: &crate::CancellationToken,
) -> crate::ProcessOutcome {
    let manager = FakeManager::start(&cgroup_fixture());
    let mut supervisor =
        ProcessSupervisor::new(limits, crate::runner::channel_transport(manager.channel()))
            .expect("supervisor");
    let outcome = supervisor
        .run(
            &worker_spec(env_allowlist(&[("LANG", "C")]), payload),
            token,
        )
        .expect("worker run");
    let teardown = supervisor
        .cleanup(&crate::ScanCriteria::new("", ""), &crate::SurvivorScanner)
        .expect("cleanup");
    assert!(teardown.stopped, "{teardown:?}");
    outcome
}

#[test]
fn a_worker_past_its_timeout_is_stopped_and_reported_as_timed_out() {
    let limits = ProcessLimits {
        timeout: Duration::from_millis(300),
        ..ProcessLimits::default()
    };
    let outcome = supervised(limits, "hang", &crate::CancellationToken::new());
    assert!(matches!(
        outcome.disposition,
        crate::ExitDisposition::TimedOut { .. }
    ));
    assert!(outcome
        .stop
        .expect("a stop request leaves evidence")
        .stopped());
}

#[test]
fn a_cancelled_run_stops_its_worker_and_reports_it_interrupted() {
    let token = crate::CancellationToken::new();
    token.cancel();
    let outcome = supervised(ProcessLimits::default(), "hang", &token);
    assert!(matches!(
        outcome.disposition,
        crate::ExitDisposition::Interrupted { .. }
    ));
    assert!(outcome
        .stop
        .expect("a stop request leaves evidence")
        .stopped());
}

#[test]
fn output_past_the_cap_stops_a_running_worker_with_the_capture_bounded() {
    let limits = ProcessLimits {
        max_stdout_bytes: 24,
        ..ProcessLimits::default()
    };
    let outcome = supervised(limits, "hang", &crate::CancellationToken::new());
    assert!(matches!(
        outcome.disposition,
        crate::ExitDisposition::OutputLimit { .. }
    ));
    assert!(outcome.stop.is_some());
    assert!(outcome.stdout.truncated());
    assert!(outcome.stdout.as_bytes().len() <= 24);
}
