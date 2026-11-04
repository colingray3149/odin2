//! Bootstrap protocol invariants: bus-authority stripping before spawn,
//! preserved namespace identity with every bootstrap capability dropped,
//! and an environment that survives two execs without the bus endpoint.

use super::*;

#[test]
fn strip_removes_every_bus_authority_variable() {
    let environment = env_allowlist(&[
        ("LANG", "C"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        (
            "DBUS_SYSTEM_BUS_ADDRESS",
            "unix:path=/run/dbus/system_bus_socket",
        ),
        ("ODIN_WORKER_BUS", "unix:path=/run/user/1000/bus"),
        ("ODIN_CORRELATION_ID", "0123456789abcdef0123456789abcdef"),
    ]);
    let stripped = strip_bus_authority(&environment);
    assert!(stripped.get("DBUS_SESSION_BUS_ADDRESS").is_none());
    assert!(stripped.get("DBUS_SYSTEM_BUS_ADDRESS").is_none());
    assert!(stripped.get("ODIN_WORKER_BUS").is_none());
    assert_eq!(
        stripped.get("ODIN_CORRELATION_ID"),
        Some("0123456789abcdef0123456789abcdef".as_ref())
    );
    assert_eq!(stripped.get("LANG"), Some("C".as_ref()));
}

#[test]
fn namespace_preserves_identity_and_drops_bootstrap_capabilities() {
    let manager = FakeManager::start(&cgroup_fixture());
    let mut authority = WorkerAuthority::spawn(
        &manager.channel(),
        naming(),
        &worker_spec(env_allowlist(&[("LANG", "C")]), "credentials"),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");
    let mut stdout = authority.leader().stdout.take().expect("stdout");
    let mut raw = String::new();
    stdout.read_to_string(&mut raw).expect("payload output");
    let status = authority.leader().wait().expect("payload exits");
    assert!(status.success(), "payload failed: {status}");
    authority.mark_reaped();
    let lines = parse_payload_output(&raw);
    assert!(lines.contains(&format!("UID {}", rustix::process::geteuid().as_raw())));
    assert!(lines.contains(&format!("GID {}", rustix::process::getegid().as_raw())));
    for field in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let line = lines
            .iter()
            .find(|line| line.starts_with(field))
            .expect("capability field");
        assert_eq!(line.split_whitespace().nth(1), Some("0000000000000000"));
    }
    assert!(authority.stop().expect("stop").stopped);
}

#[test]
fn bus_stripping() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let bus_address = manager.address.to_string();
    // The caller wrongly allowlists every bus-authority variable; the
    // authority strips them before the payload can ever see them, and
    // the environment passes through two execs (unshare, bootstrap).
    let mut authority = WorkerAuthority::spawn(
        &channel,
        naming(),
        &worker_spec(
            env_allowlist(&[
                ("LANG", "C"),
                ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
                ("ODIN_WORKER_BUS", bus_address.as_str()),
            ]),
            "env-dump",
        ),
        crate::ScopeLimits::default(),
    )
    .expect("worker spawn");

    let mut stdout = authority.leader().stdout.take().expect("payload stdout");
    let mut raw = String::new();
    let _ = stdout.read_to_string(&mut raw);
    let status = authority.leader().wait().expect("payload exits");
    assert!(status.success(), "payload failed: {status}");
    authority.mark_reaped();
    let lines = parse_payload_output(&raw);
    assert!(!lines.is_empty(), "payload printed no environment");
    for line in &lines {
        let Some(key) = line.strip_prefix("ENV ") else {
            panic!("unexpected payload line {line:?}");
        };
        assert_ne!(key, "DBUS_SESSION_BUS_ADDRESS", "bus endpoint leaked");
        assert_ne!(key, "DBUS_SYSTEM_BUS_ADDRESS", "bus endpoint leaked");
        assert_ne!(key, "ODIN_WORKER_BUS", "bus endpoint leaked");
    }
    authority.stop().expect("stop");
}
