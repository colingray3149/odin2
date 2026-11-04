//! Authoritative stop, InvocationID recovery, and residue invariants:
//! dropped authorities leave nothing alive, failed queries never look like
//! success, recovery re-proves every durable anchor without a
//! Service.MainPID, retired scopes must independently prove absence, and
//! a same-PGID decoy never verifies as the leader.

use super::*;

#[test]
fn parent_crash_leaves_no_residue() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let unit;
    let leader_pid;
    {
        let authority = WorkerAuthority::spawn(
            &channel,
            naming(),
            &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
            crate::ScopeLimits::default(),
        )
        .expect("worker spawn");
        unit = authority.identity().unit.clone();
        leader_pid = authority.identity().leader_pid;
        // Simulate the authority's process crash by dropping it.
        drop(authority);
    }
    assert!(
        wait_until(
            || !std::path::Path::new(&format!("/proc/{leader_pid}")).exists(),
            Duration::from_secs(15)
        ),
        "crashed authority must not leave the leader alive"
    );
    assert!(
        wait_until(
            || {
                manager
                    .config
                    .lock()
                    .expect("config")
                    .units
                    .get(&unit)
                    .is_some_and(|unit| unit.active_state == "inactive")
            },
            Duration::from_secs(5)
        ),
        "crashed authority must stop the scope"
    );
    let processes = scan_cgroup_residue(&unit).expect("residue scan");
    assert!(
        processes.iter().all(|identity| identity.pid != leader_pid),
        "no worker process may survive the crash"
    );
}

#[test]
fn explicit_incomplete_abandonment_does_not_kill_live_worker_on_drop() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");
    let identity = authority.identity().clone();
    // Keep an explicit reap owner solely for test cleanup. The production
    // incomplete path instead records process-exit recovery, not a join.
    let mut child = authority.leader.take().expect("live child");
    authority.abandon();
    drop(authority);
    let still_running = child.try_wait().expect("child status").is_none();
    let scope_active = manager
        .config
        .lock()
        .expect("config")
        .units
        .get(&identity.unit)
        .expect("registered unit")
        .active_state
        == "active";
    child.kill().expect("probe cleanup kill");
    child.wait().expect("probe cleanup reap");
    assert!(
        still_running,
        "abandoned Drop must not terminate the leader"
    );
    assert!(
        scope_active,
        "abandoned Drop must not stop the registered scope"
    );
}

/// A freeze refusal on a still-loaded scope must not skip the cgroup kill.
/// The descendant outlives the leader and dies only with that kill.
#[test]
fn refused_freeze_still_kills_owned_descendants() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = cgroup_fixture();
    let pid_file = fixture.join("descendant");
    let manager = FakeManager::start(&fixture);
    let mut authority = WorkerAuthority::spawn(
        &manager.channel(),
        naming(),
        &worker_spec(
            env_allowlist(&[
                ("LANG", "C"),
                (DECOY_FILE_VAR, pid_file.to_string_lossy().as_ref()),
            ]),
            "hang-tree",
        ),
        crate::ScopeLimits::default(),
    )?;
    let leader = authority.identity().leader_pid;
    assert!(
        wait_until(|| pid_file.exists(), Duration::from_secs(5)),
        "the owned descendant must appear before stop"
    );
    let descendant: u32 = std::fs::read_to_string(&pid_file)?.trim().parse()?;
    manager.config.lock().expect("config").freeze_refused = true;
    let report = authority.stop()?;
    assert!(
        report.cgroup_kill,
        "freeze refusal must still request the cgroup kill"
    );
    assert!(
        report.stopped && report.residual.is_none(),
        "owned tree must be proved stopped, got {report:?}"
    );
    assert!(
        wait_until(
            || !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            Duration::from_secs(5)
        ),
        "leader must be dead"
    );
    assert!(
        wait_until(
            || !std::path::Path::new(&format!("/proc/{descendant}")).exists(),
            Duration::from_secs(5)
        ),
        "descendant must be dead"
    );
    Ok(())
}

#[test]
fn unavailable_query_fails_closed() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    manager.config.lock().expect("config").fail_queries = true;
    let error = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect_err("an unavailable query must fail the spawn");
    assert!(
        matches!(
            error.code(),
            WorkerErrorCode::ScopeRejected | WorkerErrorCode::BusQuery
        ),
        "unexpected error code {:?}",
        error.code()
    );
    // Recovery through the same channel is an error, never an empty
    // success.
    let invocation = InvocationId::from_raw([7; 16]);
    let recovered = WorkerAuthority::recover_by_invocation(&channel, "odin-worker", &invocation);
    assert!(
        recovered.is_err(),
        "a failed query must not look like success"
    );
}

#[test]
fn recover_rejects_live_leader_outside_its_cgroup() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");
    let identity = authority.identity().clone();

    // Identity drift: the leader is still live with its exact start
    // identity, but it is no longer a member of the proven cgroup.
    // With no Service.MainPID to cross-check, the membership proof is
    // the only PID anchor and must reject the adoption.
    let directory = cgroup_directory(&channel, &identity.cgroup_path, &identity.unit)
        .expect("proven cgroup directory");
    let members_path = directory.join("cgroup.procs");
    let members = std::fs::read_to_string(&members_path).expect("cgroup members");
    let without_leader = members
        .lines()
        .filter(|member| member.trim() != identity.leader_pid.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&members_path, format!("{without_leader}\n")).expect("rewrite cgroup members");
    let error = WorkerAuthority::recover(
        &channel,
        identity.worker_id.clone(),
        &identity.unit,
        &identity.invocation_id,
        RecoveryAnchors {
            cgroup_path: identity.cgroup_path.clone(),
            cgroup_inode: identity.cgroup_inode,
            leader_pid: identity.leader_pid,
            leader_start_ticks: identity.leader_start_ticks,
        },
    )
    .expect_err("a live leader outside its cgroup must not be adopted");
    assert_eq!(error.code(), WorkerErrorCode::IdentityProof);

    // Ownership never moved: the original authority still stops the
    // exact scope cleanly.
    let report = authority.stop().expect("stop after failed adoption");
    assert!(report.stopped);
    assert_eq!(
        manager.unit_active(&identity.unit).as_deref(),
        Some("inactive")
    );
}

#[test]
fn pgid_reuse_decoy() {
    let fixture = cgroup_fixture();
    let decoy_file = fixture.join("decoy-identity");
    let decoy_file_text = decoy_file.to_string_lossy().into_owned();
    let manager = FakeManager::start(&fixture);
    let channel = manager.channel();
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(
            env_allowlist(&[("LANG", "C"), (DECOY_FILE_VAR, decoy_file_text.as_str())]),
            "decoy",
        ),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");

    let leader_pid = authority.identity().leader_pid;
    authority
        .verify_leader(leader_pid)
        .expect("leader verifies");
    assert!(
        wait_until(|| decoy_file.exists(), Duration::from_secs(5)),
        "same-PGID decoy must publish its live identity"
    );
    let raw_identity = std::fs::read_to_string(&decoy_file).expect("read decoy identity");
    let values = raw_identity
        .split_whitespace()
        .map(|value| value.parse::<i64>().expect("numeric identity"))
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    let decoy_pid = u32::try_from(values[0]).expect("decoy pid");
    let decoy_pgid = i32::try_from(values[1]).expect("decoy pgid");
    let leader = read_process_identity(leader_pid).expect("leader identity");
    assert_eq!(
        leader.process_group, decoy_pgid,
        "the live decoy shares the leader's process group exactly"
    );
    let error = authority
        .verify_leader(decoy_pid)
        .expect_err("same-PGID decoy must not verify");
    assert_eq!(error.code(), WorkerErrorCode::IdentityProof);

    let mut stdout = authority.leader().stdout.take().expect("payload stdout");
    let mut raw = String::new();
    let _ = stdout.read_to_string(&mut raw);
    let status = authority.leader().wait().expect("payload exits");
    assert!(status.success(), "payload failed: {status}");
    authority.mark_reaped();
    let lines = parse_payload_output(&raw);
    let (_, printed_leader_group, _) = identity_of("DECOY_LEADER", &lines);
    let (_, printed_decoy_group, _) = identity_of("DECOY_CHILD", &lines);
    assert_eq!(printed_leader_group, printed_decoy_group);

    let report = authority.stop().expect("stop");
    assert!(report.stopped);
}

/// A spawned `sleep 61` that must never outlive its test: a failed
/// proof or a panicked assertion still reaps the process in `Drop`.
struct ParkedLeader(std::process::Child);

impl ParkedLeader {
    fn spawn() -> Self {
        Self(
            Command::new("sleep")
                .arg("61")
                .spawn()
                .expect("parked leader process"),
        )
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn start_ticks(&self) -> u64 {
        read_process_identity(self.pid())
            .expect("leader /proc identity")
            .start_time_ticks
    }
}

impl Drop for ParkedLeader {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A main process outside the recorded cgroup is identity drift, and a
/// unit that never reaches active is refused — both never yield a proof.
#[test]
fn unit_identity_proof_refuses_drift_and_nonactivation() {
    let cgroup_root = cgroup_fixture();
    let manager = FakeManager::start(&cgroup_root);
    let channel = manager.channel();
    let outsider = ParkedLeader::spawn();
    let outsider_pid = outsider.pid();
    let unit = "odin-term-9a8b7c6d.service";
    // The manager reports the cgroup hierarchy-relative; the fixture
    // directory is its resolution, so the membership proof below runs
    // against exactly this directory.
    let cgroup = format!("/{unit}");
    let directory = cgroup_root.join(unit);
    std::fs::create_dir_all(&directory).expect("unit cgroup directory");
    // The cgroup exists but holds no member: an empty unit cgroup, or one
    // whose main process lives elsewhere.
    std::fs::write(directory.join("cgroup.procs"), "").expect("empty members");
    let make_unit = |active_state: &str| FakeUnit {
        invocation: [0x3C; 16],
        attached_pid: outsider_pid,
        attached_start_ticks: None,
        cgroup: cgroup.clone(),
        active_state: active_state.to_owned(),
        sub_state: "running".to_owned(),
        kill_mode: "control-group".to_owned(),
        delegate: false,
        properties: BTreeMap::from([("MainPID".to_owned(), Value::Uint32(outsider_pid))]),
    };
    manager
        .config
        .lock()
        .expect("config")
        .units
        .insert(unit.to_owned(), make_unit("active"));
    let error = WorkerAuthority::prove_unit_identity(&channel, unit)
        .expect_err("a main process outside the cgroup is no identity");
    assert_eq!(error.code(), WorkerErrorCode::IdentityProof);
    // The refusal is the membership drift itself: the proof reached this
    // exact resolved directory and rejected the outsider's PID — never a
    // path that failed to resolve.
    let detail = error.to_string();
    assert!(
        detail.contains(&outsider_pid.to_string())
            && detail.contains(&directory.display().to_string()),
        "the drift refusal must name the outsider and its cgroup: {detail}"
    );

    manager
        .config
        .lock()
        .expect("config")
        .units
        .insert(unit.to_owned(), make_unit("failed"));
    let error = WorkerAuthority::prove_unit_identity(&channel, unit)
        .expect_err("a failed unit is never adopted");
    assert_eq!(error.code(), WorkerErrorCode::ScopeRejected);
}

/// A terminal-sandbox transient `.service` recovers and stops exactly
/// like an owned scope: the durable anchors are re-proved through the
/// concrete Service interface — the fake refuses the Scope interface
/// for a service exactly like the real manager, so any scope-only
/// property read fails this test instead of masking the divergence on
/// a live systemd.
#[test]
fn terminal_service_unit_recovers_and_stops_through_the_service_interface() {
    let cgroup_root = cgroup_fixture();
    let manager = FakeManager::start(&cgroup_root);
    let channel = manager.channel();
    let leader = ParkedLeader::spawn();
    let leader_pid = leader.pid();
    let leader_ticks = leader.start_ticks();
    let unit = "odin-term-5f6e7a8b.service";
    // The manager reports the cgroup hierarchy-relative under its root;
    // the on-disk fixture directory is that path resolved by the channel.
    let cgroup = format!("/{unit}");
    let directory = cgroup_root.join(unit);
    std::fs::create_dir_all(&directory).expect("unit cgroup directory");
    std::fs::write(directory.join("cgroup.procs"), format!("{leader_pid}\n"))
        .expect("cgroup members");
    use std::os::unix::fs::MetadataExt;
    let cgroup_inode = std::fs::metadata(&directory)
        .expect("cgroup metadata")
        .ino();
    manager.config.lock().expect("config").units.insert(
        unit.to_owned(),
        FakeUnit {
            invocation: [0x6A; 16],
            attached_pid: leader_pid,
            attached_start_ticks: Some(leader_ticks),
            cgroup: cgroup.clone(),
            active_state: "active".to_owned(),
            sub_state: "running".to_owned(),
            kill_mode: "control-group".to_owned(),
            delegate: false,
            properties: BTreeMap::from([("MainPID".to_owned(), Value::Uint32(leader_pid))]),
        },
    );

    // The manager really refuses the Scope interface for a service: the
    // fixture must never answer it flat and hide the divergence.
    {
        let mut client =
            crate::systemd::ManagerClient::connect(channel.bus()).expect("manager connection");
        let unit_path = client
            .get_unit(unit)
            .expect("unit query")
            .expect("terminal unit");
        let refused = client
            .unit_properties(&unit_path, "org.freedesktop.systemd1.Scope")
            .expect_err("a service never answers the Scope interface");
        assert!(
            refused
                .to_string()
                .contains("org.freedesktop.DBus.Error.UnknownInterface"),
            "the Scope interface must refuse a service unit: {refused}"
        );
    }

    let invocation = InvocationId::from_raw([0x6A; 16]);
    let mut recovered = WorkerAuthority::recover(
        &channel,
        mint_worker_id().expect("terminal worker id"),
        unit,
        &invocation,
        RecoveryAnchors {
            cgroup_path: cgroup.clone(),
            cgroup_inode,
            leader_pid,
            leader_start_ticks: leader_ticks,
        },
    )
    .expect("terminal service recovery")
    .expect("terminal service adopted by InvocationID");
    assert!(recovered.is_recovered());
    assert_eq!(recovered.identity().unit, unit);
    assert_eq!(recovered.identity().invocation_id, invocation);
    assert_eq!(recovered.identity().cgroup_path, cgroup);
    assert_eq!(recovered.identity().cgroup_inode, cgroup_inode);
    assert_eq!(recovered.identity().leader_pid, leader_pid);
    assert_eq!(recovered.identity().leader_start_ticks, leader_ticks);

    // The stop ladder proves the same ownership through the Service
    // interface before any signal, then takes the whole unit down.
    let report = recovered.stop().expect("terminal service stop");
    assert!(report.stopped, "the terminal service must stop cleanly");
    assert_eq!(
        manager.unit_active(unit),
        Some("inactive".to_owned()),
        "the stopped terminal service must leave its unit"
    );
    assert!(
        !directory.exists(),
        "the stopped terminal service must leave its cgroup"
    );
}
