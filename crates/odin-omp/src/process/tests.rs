use super::launch::launch_for_test_fixture;
use super::*;
use crate::probe::PINNED_OMP_SOURCE_REVISION;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// A bounded fake OMP (ready, v2 negotiation, stdin echo, goodbye) that, like
/// the pinned harness, speaks RPC only when its argv has exactly one --mode rpc pair.
const FIXTURE_SCRIPT: &str = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
	printf 'omp/fixture-1.0.0\n'
	exit 0
fi
mode_pairs=0
malformed_mode=0
previous=""
for argument in "$@"; do
	if [ "$previous" = "--mode" ]; then
		if [ "$argument" = "rpc" ]; then
			mode_pairs=$((mode_pairs + 1))
		else
			malformed_mode=1
		fi
	fi
	previous="$argument"
done
if [ "$previous" = "--mode" ]; then
	malformed_mode=1
fi
if [ "$mode_pairs" -ne 1 ] || [ "$malformed_mode" -ne 0 ]; then
	printf 'fixture: expected exactly one host-owned --mode rpc pair, saw %s (malformed %s)\n' "$mode_pairs" "$malformed_mode" >&2
	exit 2
fi
printf '%s\n' '{"type":"ready","protocolVersion":1,"supportedProtocolVersions":[1,2],"maxFrameBytes":1048576,"maxReassembledFrameBytes":67108864}'
IFS= read -r request
printf '%s\n' '{"id":"odin-omp-negotiate-protocol","type":"response","command":"negotiate_protocol","success":true,"data":{"protocolVersion":2}}'
while IFS= read -r line; do
	printf '%s\n' "{\"id\":\"echo\",\"type\":\"response\",\"command\":\"echo\",\"success\":true,\"data\":${line}}"
done
printf '%s\n' '{"id":"drain","type":"response","command":"drain","success":true,"data":{"phase":"goodbye"}}'
"#;

/// The exact ready physical line the fixture prints, including its newline.
const FIXTURE_READY_LINE: &[u8] = b"{\"type\":\"ready\",\"protocolVersion\":1,\"supportedProtocolVersions\":[1,2],\"maxFrameBytes\":1048576,\"maxReassembledFrameBytes\":67108864}\n";

/// Ready payload advertising v1 only, so no negotiation round follows.
const READY_V1_JSON: &str =
    "{\"type\":\"ready\",\"protocolVersion\":1,\"supportedProtocolVersions\":[1],\"maxFrameBytes\":1048576,\"maxReassembledFrameBytes\":67108864}";
/// Ready payload advertising v1 and v2, so the negotiation round runs.
const READY_V2_JSON: &str =
    "{\"type\":\"ready\",\"protocolVersion\":1,\"supportedProtocolVersions\":[1,2],\"maxFrameBytes\":1048576,\"maxReassembledFrameBytes\":67108864}";
/// Successful v2 negotiation response to the deterministic request.
const NEGOTIATE_V2_JSON: &str =
    "{\"id\":\"odin-omp-negotiate-protocol\",\"type\":\"response\",\"command\":\"negotiate_protocol\",\"success\":true,\"data\":{\"protocolVersion\":2}}";

/// Re-entry point for the real worker bootstrap inside this test binary.
#[test]
fn worker_bootstrap_fixture_entry() {
    odin_process::test_support::run_bootstrap_if_active();
}

/// A bounded fake OMP whose startup interleaves auxiliary frames around
/// the negotiation round-trip: one before the request is read, two after.
const AUX_INTERLEAVE_SCRIPT: &str = r#"#!/bin/sh
printf '%s\n' '{"type":"ready","protocolVersion":1,"supportedProtocolVersions":[1,2],"maxFrameBytes":1048576,"maxReassembledFrameBytes":67108864}'
printf '%s\n' '{"id":"ui-1","type":"extension_ui_request","method":"select","title":"pick one"}'
IFS= read -r request
printf '%s\n' '{"type":"session_info_update","sessionId":"fixture"}'
printf '%s\n' '{"type":"available_commands_update","commands":[]}'
printf '%s\n' '{"id":"odin-omp-negotiate-protocol","type":"response","command":"negotiate_protocol","success":true,"data":{"protocolVersion":2}}'
while IFS= read -r line; do
	printf '%s\n' "{\"id\":\"echo\",\"type\":\"response\",\"command\":\"echo\",\"success\":true,\"data\":${line}}"
done
"#;

fn fixture_spec(executable: PathBuf, cwd: PathBuf) -> OmpProcessSpec {
    OmpProcessSpec {
        executable,
        cwd,
        explicit_args: Vec::new(),
        explicit_env: vec![("ODIN_FIXTURE".to_owned(), "1".to_owned())],
        expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: Duration::from_secs(10),
        drain_timeout: Duration::from_secs(10),
        kill_timeout: Duration::from_secs(10),
    }
}
fn launch_for(executable: &Path) -> OmpWorkerLaunch {
    launch_for_test_fixture(executable, "process-test")
}

/// Recovery-only contract for rejection tests that never spawn: the
/// in-memory authority has no bootstrap executable, so any spawn must
/// fail closed with `SpawnFailed`.
fn recovery_launch_for(executable: &Path) -> OmpWorkerLaunch {
    let canonical = fs::canonicalize(executable).expect("fixture executable");
    let digest = blake3::hash(&fs::read(&canonical).expect("hash fixture"))
        .to_hex()
        .to_string();
    let binding = RegisteredServiceBinding::new(canonical, digest).expect("fixture binding");
    let ledger = odin_ledger::Ledger::open_in_memory().expect("in-memory ledger");
    let bus = odin_process::BusAddress::parse("unix:path=/run/user/1/bus").expect("recovery bus");
    let channel = odin_process::WorkerChannel::for_recovery(bus).expect("recovery channel");
    let authority = Arc::new(StopAuthority::new(Arc::new(Mutex::new(ledger)), channel));
    let correlation =
        CorrelationId::new("0123456789abcdef0123456789abcdef").expect("test correlation");
    OmpWorkerLaunch::new(
        authority,
        correlation,
        "odin-omp",
        "process-recovery",
        1,
        binding,
        ScopeLimits::default(),
    )
    .expect("recovery worker launch")
}

fn write_script(name: &str, script: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("odin-omp-process-{name}-{}.sh", std::process::id()));
    fs::write(&path, script).expect("write fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fixture");
    path
}

fn write_fixture(name: &str) -> PathBuf {
    write_script(name, FIXTURE_SCRIPT)
}

/// Waits until the pid file the fixture writes appears, then parses it.
#[cfg(unix)]
async fn read_pid_file(path: &Path) -> u32 {
    for _ in 0..100 {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse() {
                return pid;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("pid file {} never appeared", path.display());
}

/// Polls procfs until `pid` is gone: dead and reaped, not a zombie.
#[cfg(unix)]
async fn wait_until_dead(pid: u32) -> bool {
    for _ in 0..100 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

mod lifecycle;
mod startup;
mod streams;

/// Remote transport or stop completion can establish termination without a local status.
#[test]
fn a_clean_remote_exit_proves_termination_without_a_local_status() {
    let record = |status, remote| OmpExitRecord {
        status,
        stderr_tail: Vec::new(),
        unfinished: None,
        remote,
    };
    let clean = OmpRemoteExit::from_transport(remote::RemoteExit {
        status: Some(0),
        clean: true,
        failure: None,
    });
    let broken = OmpRemoteExit::from_transport(remote::RemoteExit {
        status: None,
        clean: false,
        failure: Some("channel reset".to_owned()),
    });
    assert!(record(None, Some(clean)).termination_proven());
    assert!(record(None, Some(OmpRemoteExit::stopped())).termination_proven());
    assert!(!record(None, Some(broken)).termination_proven());
    assert!(!record(None, None).termination_proven());
    use std::os::unix::process::ExitStatusExt;
    assert!(record(Some(ExitStatus::from_raw(0)), None).termination_proven());
}
