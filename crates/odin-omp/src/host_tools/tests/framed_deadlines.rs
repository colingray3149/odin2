//! Framed-exec deadline and pipe cleanup tests using registered workers.
//!
//! The worker environment carries no PATH: the scripts use shell builtins, and
//! the one program they need (`sleep`) is passed as an absolute path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use odin_adapter_core::transport::{
    AdapterTransport, AdapterTransportFault, JsonRpcOutcome, JsonRpcRequest, RpcMethod,
};
use odin_domain::Scope;
use odin_kernel::HandlerBinding;
use serde_json::{json, Value};

use crate::host_tools::adapter::FramedExecAdapterTransport;
use crate::host_tools::binding::FramedExecTool;
use crate::host_tools::{HostInvocation, HostTool, HostToolError};
use crate::process::OmpWorkerLaunch;

/// Allow launch and stop overhead beyond the call deadline, below the five-second stdin budget.
const STOP_MARGIN: Duration = Duration::from_secs(3);

fn shell() -> PathBuf {
    std::fs::canonicalize("/bin/sh").expect("/bin/sh resolves")
}

/// The first absolute `name` on the runner's PATH.
fn on_path(name: &str) -> String {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join(name))
                .find(|candidate| candidate.is_absolute() && candidate.is_file())
        })
        .unwrap_or_else(|| panic!("no absolute {name} on PATH"))
        .to_string_lossy()
        .into_owned()
}

/// Whether the process recorded as `pid` with start ticks `start` still runs;
/// a zombie has already been killed.
fn alive(pid: &str, start: &str) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, fields)) = stat.rsplit_once(')') else {
        return false;
    };
    let fields: Vec<&str> = fields.split_whitespace().collect();
    fields.get(19) == Some(&start) && !matches!(fields.first(), Some(&"Z" | &"X"))
}

/// The `pid start` pair a script recorded in `file`.
fn recorded(file: &Path) -> Option<(String, String)> {
    let text = std::fs::read_to_string(file).ok()?;
    let (pid, start) = text.trim().split_once(' ')?;
    Some((pid.to_owned(), start.to_owned()))
}

fn leader_running(fixture: &Fixture) -> bool {
    recorded(&fixture.root.path().join("leader")).is_some_and(|(pid, start)| alive(&pid, &start))
}

/// Records the leader's pid and start ticks, then never reads its frame: the
/// parent's write fills the pipe.
const NEVER_READS: &str = r#"dir=$1; sleep=$2; read -r stat < /proc/self/stat; set -- $stat; printf '%s %s\n' "$$" "${22}" > "$dir/leader"; exec "$sleep" 30"#;

/// Reads its frame, writes 256 KiB to stderr, then replies `reply`.
fn floods_stderr(reply: &str) -> String {
    let line = "e".repeat(1024);
    format!(
        r#"IFS= read -r _; i=0; while [ "$i" -lt 256 ]; do printf '%s\n' '{line}' >&2; i=$((i+1)); done; printf '%s\n' '{reply}'"#
    )
}

/// One case's private launch and everything it started, released on every
/// exit path, a failed assertion included: each worker the authority has not
/// settled is stopped through that authority, and each recorded escaped
/// holder is killed by its exact pid and start ticks.
struct Fixture {
    launch: OmpWorkerLaunch,
    ledger: Arc<Mutex<odin_ledger::Ledger>>,
    root: tempfile::TempDir,
    holders: Vec<(String, String)>,
}

impl Fixture {
    fn new() -> Self {
        let (launch, ledger) = crate::process::launch_with_ledger_for_fixture(&shell());
        Self {
            launch,
            ledger,
            root: tempfile::tempdir().expect("private case root"),
            holders: Vec::new(),
        }
    }

    fn argv(&self, script: &str) -> Vec<String> {
        vec![
            "-c".to_owned(),
            script.to_owned(),
            "framed-fixture".to_owned(),
            self.root.path().display().to_string(),
            on_path("sleep"),
        ]
    }

    fn adapter_call(
        &self,
        script: &str,
        timeout: Duration,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcOutcome, AdapterTransportFault> {
        let binding = HandlerBinding::Exec {
            executable: shell().to_string_lossy().into_owned(),
            argv: self.argv(script),
        };
        FramedExecAdapterTransport::new(self.launch.clone()).call(&binding, timeout, request)
    }

    fn exec_call(
        &self,
        script: &str,
        timeout: Duration,
        arguments: Value,
    ) -> Result<Value, HostToolError> {
        FramedExecTool::with_timeout(
            shell().to_string_lossy().into_owned(),
            self.argv(script),
            timeout,
            self.launch.clone(),
        )
        .invoke(HostInvocation {
            scope: Scope::default(),
            arguments,
        })
    }

    /// The workers the authority launched and has not settled.
    fn unsettled(&self) -> Vec<String> {
        let ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        odin_ledger::worker::nonterminal_rows(ledger.connection(), None)
            .map(|rows| rows.into_iter().map(|row| row.worker_id).collect())
            .unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (pid, start) in &self.holders {
            if alive(pid, start) {
                if let Some(pid) = pid.parse().ok().and_then(rustix::process::Pid::from_raw) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                }
            }
        }
        for worker in self.unsettled() {
            if let Ok(worker) = odin_types::WorkerId::new(&worker) {
                let deadline = Instant::now() + Duration::from_secs(10);
                let _ = self.launch.authority.stop_worker_bounded(&worker, deadline);
            }
        }
    }
}

/// A frame larger than any pipe buffer, so a child that never reads it
/// stalls the write.
fn oversized_input() -> Value {
    json!({ "blob": "s".repeat(512 * 1024) })
}

/// A timed-out request remains `DispatchedUnknown` even after its worker is stopped.
#[test]
fn an_adapter_call_whose_frame_is_never_read_stops_its_worker_by_its_deadline() {
    let fixture = Fixture::new();
    let request = JsonRpcRequest::new(
        "stall",
        RpcMethod::parse("fixture.stall").expect("operation kind"),
        oversized_input(),
    )
    .expect("request");
    let timeout = Duration::from_millis(500);
    let started = Instant::now();
    let result = fixture.adapter_call(NEVER_READS, timeout, &request);
    let elapsed = started.elapsed();
    let unsettled = fixture.unsettled();
    let leader = leader_running(&fixture);
    assert!(
        matches!(result, Err(AdapterTransportFault::DispatchedUnknown { .. })),
        "{result:?}"
    );
    assert!(
        unsettled.is_empty() && !leader,
        "the call returned with its worker {unsettled:?} unsettled (leader running: {leader})"
    );
    assert!(
        elapsed < timeout + STOP_MARGIN,
        "the call outlived its {timeout:?} deadline: {elapsed:?}"
    );
}

#[test]
fn an_adapter_backend_flooding_stderr_still_answers_its_frame() {
    let fixture = Fixture::new();
    let reply = r#"{"id":"flood","jsonrpc":"2.0","result":{"ok":true}}"#;
    let outcome = fixture.adapter_call(
        &floods_stderr(reply),
        Duration::from_secs(10),
        &JsonRpcRequest::status("flood"),
    );
    assert!(
        matches!(&outcome, Ok(JsonRpcOutcome::Success { result, .. }) if result["ok"] == true),
        "{outcome:?}"
    );
    assert!(fixture.unsettled().is_empty());
}

#[test]
fn an_exec_call_whose_frame_is_never_read_answers_by_its_deadline() {
    let fixture = Fixture::new();
    let timeout = Duration::from_millis(500);
    let started = Instant::now();
    let result = fixture.exec_call(NEVER_READS, timeout, oversized_input());
    let elapsed = started.elapsed();
    assert!(
        matches!(result, Err(HostToolError::Uncertain { .. })),
        "{result:?}"
    );
    assert!(fixture.unsettled().is_empty() && !leader_running(&fixture));
    assert!(
        elapsed < timeout + STOP_MARGIN,
        "the call outlived its {timeout:?} deadline: {elapsed:?}"
    );
}
