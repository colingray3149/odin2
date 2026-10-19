//! Shared worker test helpers re-execute the harness through unshare, bootstrap,
//! and exec; submodules exercise worker lifecycle behavior.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use odin_domain::worker::InvocationId;

use super::identity::cgroup_directory;
use super::launch::wait_scope_active;
use super::{
    mint_worker_id, read_process_identity, scan_cgroup_residue, strip_bus_authority,
    RecoveryAnchors, WorkerAuthority, WorkerChannel, WorkerErrorCode, WorkerNaming,
};
use crate::systemd::{BusAddress, ManagerClient, Value};
use crate::test_support::{FakeUnit, RegisteredWorkerFixture as FakeManager};
use crate::{CommandSpec, EnvironmentBuilder, FrozenArgv, ProcessLimits, ProcessSupervisor};

const PAYLOAD_MODE_VAR: &str = "ODIN_WORKER_TEST_PAYLOAD";
const DECOY_FILE_VAR: &str = "ODIN_WORKER_TEST_DECOY_FILE";
// `--exact` matches the full test path on this toolchain, so the
// re-executed harness filters must use the complete test names.
const HARNESS_ARGS: [&str; 5] = [
    "--exact",
    "worker::tests::payload_test",
    "--test-threads",
    "1",
    "--nocapture",
];

mod bootstrap;
mod io;
mod launch;
mod stop;

// ------------------------------------------------------------------
// Test payload protocol: the test harness re-executes itself through
// the full unshare + bootstrap + exec chain. The re-executed harness
// runs exactly one filter, whose body switches to payload mode on the
// environment variable and exits; cargo test does not build standalone
// bins, so this is how the real chain is exercised end to end.
// ------------------------------------------------------------------

fn parse_payload_output(raw: &str) -> Vec<String> {
    raw.lines()
        .skip_while(|line| !line.starts_with("ODIN_PAYLOAD_BEGIN"))
        .skip(1)
        .take_while(|line| !line.starts_with("ODIN_PAYLOAD_END"))
        .map(str::to_owned)
        .collect()
}

fn collect(child: &mut std::process::Child) -> (Vec<String>, std::process::ExitStatus) {
    let mut raw = String::new();
    if let Some(pipe) = child.stdout.as_mut() {
        let _ = pipe.read_to_string(&mut raw);
    }
    let status = child.wait().expect("payload exits");
    (parse_payload_output(&raw), status)
}

/// The payload body. Called from the single test the re-executed
/// harness runs; always exits the process.
fn payload_main(mode: &str) -> ! {
    println!("\nODIN_PAYLOAD_BEGIN");
    match mode {
        "credentials" => {
            println!("UID {}", rustix::process::geteuid().as_raw());
            println!("GID {}", rustix::process::getegid().as_raw());
            let status = std::fs::read_to_string("/proc/self/status").expect("status");
            for line in status.lines().filter(|line| {
                ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
                    .iter()
                    .any(|key| line.starts_with(key))
            }) {
                println!("{line}");
            }
        }
        "env-dump" => {
            let mut keys: Vec<String> = std::env::vars().map(|(key, _)| key).collect();
            keys.sort();
            for key in keys {
                println!("ENV {key}");
            }
        }
        "family" => {
            // The production bootstrap already called setsid before this
            // payload existed.
            print_identity("LEADER");
            let middle = Command::new(std::env::current_exe().expect("exe"))
                .args(HARNESS_ARGS)
                .env(PAYLOAD_MODE_VAR, "middle")
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn middle");
            println!("MIDDLE_PID {}", middle.id());
            let mut middle = middle;
            let (lines, status) = collect(&mut middle);
            assert!(status.success(), "middle failed: {status}");
            for line in lines {
                println!("{line}");
            }
        }
        "middle" => {
            print_identity("MIDDLE");
            let leaf = Command::new(std::env::current_exe().expect("exe"))
                .args(HARNESS_ARGS)
                .env(PAYLOAD_MODE_VAR, "leaf")
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn leaf");
            println!("LEAF_PID {}", leaf.id());
            let mut leaf = leaf;
            let (lines, status) = collect(&mut leaf);
            assert!(status.success(), "leaf failed: {status}");
            for line in lines {
                println!("{line}");
            }
        }
        "leaf" => {
            // The deepest generation performs its own setsid: the full
            // daemon-style escape — new session, new process group —
            // inside the owned cgroup.
            rustix::process::setsid().expect("leaf setsid");
            print_identity("LEAF");
        }
        "decoy" => {
            print_identity("DECOY_LEADER");
            let child = Command::new(std::env::current_exe().expect("exe"))
                .args(HARNESS_ARGS)
                .env(PAYLOAD_MODE_VAR, "same-group-child")
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn same-group child");
            println!("CHILD_PID {}", child.id());
            let mut child = child;
            let (lines, status) = collect(&mut child);
            assert!(status.success(), "child failed: {status}");
            for line in lines {
                println!("{line}");
            }
        }
        "same-group-child" => {
            print_identity("DECOY_CHILD");
            if let Some(path) = std::env::var_os(DECOY_FILE_VAR) {
                let (pid, pgrp, session) = current_identity();
                std::fs::write(path, format!("{pid} {pgrp} {session}"))
                    .expect("write decoy identity");
                // Stay live long enough for the authority-side identity
                // check; the parent waits and owns the eventual reap.
                std::thread::sleep(Duration::from_secs(2));
            }
        }
        "hang-tree" => {
            // Wait on the descendant so both remain owned until the scope kill.
            let mut descendant = Command::new(std::env::current_exe().expect("exe"))
                .args(HARNESS_ARGS)
                .env(PAYLOAD_MODE_VAR, "hang")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn hang descendant");
            if let Some(path) = std::env::var_os(DECOY_FILE_VAR) {
                std::fs::write(&path, descendant.id().to_string()).expect("write descendant pid");
            }
            print_identity("HANG");
            let _ = descendant.wait();
        }
        "hang" => {
            print_identity("HANG");
            std::thread::sleep(Duration::from_secs(300));
        }
        "burst" => {
            // Exit immediately after more bytes than a small capture ceiling.
            println!("{}", "x".repeat(64));
        }
        other => {
            eprintln!("unknown payload mode {other}");
            std::process::exit(123);
        }
    }
    println!("ODIN_PAYLOAD_END");
    std::process::exit(0);
}

fn current_identity() -> (u32, i32, i32) {
    let pid = std::process::id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let after = stat.rsplit(')').next().expect("stat fields").trim();
    let fields: Vec<&str> = after.split_whitespace().collect();
    let pgrp = fields[2].parse().expect("pgrp");
    let session = fields[3].parse().expect("session");
    (pid, pgrp, session)
}

fn print_identity(tag: &str) {
    let (pid, pgrp, session) = current_identity();
    let cgroup = super::process_cgroup_line(pid).expect("cgroup");
    println!("{tag} PID {pid} PGID {pgrp} SID {session}");
    println!("{tag}_CGROUP {cgroup}");
}

fn identity_of(tag: &str, lines: &[String]) -> (u32, i32, i32) {
    let line = lines
        .iter()
        .find(|line| line.split_whitespace().next() == Some(tag))
        .unwrap_or_else(|| panic!("missing {tag} in {lines:?}"));
    let fields: Vec<&str> = line.split_whitespace().collect();
    let value = |name: &str| {
        fields[fields.iter().position(|field| *field == name).expect(name) + 1]
            .parse()
            .expect(name)
    };
    (
        value("PID"),
        i32::try_from(value("PGID")).expect("PGID fits i32"),
        i32::try_from(value("SID")).expect("SID fits i32"),
    )
}

fn string_of(tag: &str, lines: &[String]) -> String {
    let line = lines
        .iter()
        .find(|line| line.starts_with(tag))
        .unwrap_or_else(|| panic!("missing {tag} in {lines:?}"));
    line.split_once(' ')
        .map(|(_, value)| value.to_owned())
        .expect("tag value")
}

fn unsigned_of(tag: &str, lines: &[String]) -> u32 {
    let line = lines
        .iter()
        .find(|line| line.starts_with(tag))
        .unwrap_or_else(|| panic!("missing {tag} in {lines:?}"));
    line.split_whitespace()
        .last()
        .expect("pid")
        .parse()
        .expect("pid")
}

// ------------------------------------------------------------------
// Helpers for driving real spawns through the authority.
// ------------------------------------------------------------------

fn env_allowlist(entries: &[(&str, &str)]) -> crate::AllowlistedEnvironment {
    let mut builder = EnvironmentBuilder::new(entries.iter().map(|(key, _)| *key)).expect("keys");
    for (key, value) in entries {
        builder = builder.set(key, value).expect("value");
    }
    builder.build()
}

fn worker_spec(environment: crate::AllowlistedEnvironment, payload_mode: &str) -> CommandSpec {
    let exe = std::env::current_exe().expect("exe");
    let argv: Vec<String> = std::iter::once(exe.to_string_lossy().into_owned())
        .chain(HARNESS_ARGS.iter().map(|arg| (*arg).to_owned()))
        .collect();
    let mut builder = EnvironmentBuilder::new(
        environment
            .iter()
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .chain([PAYLOAD_MODE_VAR.to_owned()]),
    )
    .expect("allowlist");
    for (key, value) in environment.iter() {
        builder = builder
            .set(
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
            .expect("entry");
    }
    builder = builder
        .set(PAYLOAD_MODE_VAR, payload_mode)
        .expect("payload mode");
    CommandSpec {
        argv: FrozenArgv::new(&argv, 64, 8192).expect("argv"),
        environment: builder.build(),
        current_dir: std::env::temp_dir(),
    }
}

fn naming() -> WorkerNaming {
    WorkerNaming::new(
        "tx0123456789abcdef",
        "wp-11a",
        1,
        mint_worker_id().expect("worker id"),
    )
    .expect("naming")
}

fn cgroup_fixture() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "odin-worker-cgroup-fixture-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create cgroup fixture");
    dir
}

fn wait_until(predicate: impl Fn() -> bool, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    predicate()
}

/// The libtest entry used when the test harness stands in for the
/// packaged bootstrap binary. It enters the exact production bootstrap
/// function and never returns.
#[test]
fn bootstrap_test() {
    crate::test_support::run_bootstrap_if_active();
}

/// The single libtest entry the re-executed harness runs. It switches
/// on the payload-mode environment variable; when absent it is a no-op
/// so the outer test list stays meaningful.
#[test]
fn payload_test() {
    if let Some(mode) = std::env::var(PAYLOAD_MODE_VAR)
        .ok()
        .filter(|mode| !mode.is_empty())
    {
        payload_main(&mode);
    }
}
