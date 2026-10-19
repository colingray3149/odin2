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

fn leader_running(custody: &Custody) -> bool {
    recorded(&custody.root.path().join("leader")).is_some_and(|(pid, start)| alive(&pid, &start))
}

/// Whether this test process still holds a descriptor of the pipe `pid`
/// writes its stdout into.
fn host_reads_stdout_of(pid: &str) -> bool {
    let pipe =
        std::fs::read_link(format!("/proc/{pid}/fd/1")).expect("the holder's stdout is observable");
    assert!(
        pipe.to_string_lossy().starts_with("pipe:"),
        "the holder's stdout is the call's pipe, not {pipe:?}"
    );
    std::fs::read_dir("/proc/self/fd")
        .expect("own descriptors")
        .filter_map(Result::ok)
        .any(|entry| std::fs::read_link(entry.path()).is_ok_and(|target| target == pipe))
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

/// Reads its frame and leaves a descendant outside the leader's tree that
/// holds the same stdout (recorded by pid and start ticks), then replies
/// `reply` and exits.
fn escapes_holding_stdout(reply: &str) -> String {
    format!(
        r#"dir=$1; sleep=$2; IFS= read -r _; ( exec </dev/null 2>/dev/null; "$sleep" 30 & read -r stat < /proc/$!/stat; set -- $stat; printf '%s %s\n' "$!" "${{22}}" > "$dir/holder" ); printf '%s\n' '{reply}'"#
    )
}

/// One case's private launch and everything it started, released on every
/// exit path, a failed assertion included: each worker the authority has not
/// settled is stopped through that authority, and each recorded escaped
/// holder is killed by its exact pid and start ticks.
struct Custody {
    launch: OmpWorkerLaunch,
    ledger: Arc<Mutex<odin_ledger::Ledger>>,
    root: tempfile::TempDir,
    holders: Vec<(String, String)>,
}

impl Custody {
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

    /// Registers the escaped holder for cleanup when this fixture drops.
    fn hold(&mut self) -> String {
        let holder = recorded(&self.root.path().join("holder"))
            .expect("the script recorded its escaped holder");
        self.holders.push(holder.clone());
        holder.0
    }
}

impl Drop for Custody {
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
    let custody = Custody::new();
    let request = JsonRpcRequest::new(
        "stall",
        RpcMethod::parse("fixture.stall").expect("operation kind"),
        oversized_input(),
    )
    .expect("request");
    let timeout = Duration::from_millis(500);
    let started = Instant::now();
    let result = custody.adapter_call(NEVER_READS, timeout, &request);
    let elapsed = started.elapsed();
    let unsettled = custody.unsettled();
    let leader = leader_running(&custody);
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
    let custody = Custody::new();
    let reply = r#"{"id":"flood","jsonrpc":"2.0","result":{"ok":true}}"#;
    let outcome = custody.adapter_call(
        &floods_stderr(reply),
        Duration::from_secs(10),
        &JsonRpcRequest::status("flood"),
    );
    assert!(
        matches!(&outcome, Ok(JsonRpcOutcome::Success { result, .. }) if result["ok"] == true),
        "{outcome:?}"
    );
    assert!(custody.unsettled().is_empty());
}

/// An escaped stdout holder leaves the result unknown but must not leave a reader blocked.
#[test]
fn an_adapter_call_leaves_no_reader_on_a_pipe_an_escaped_descendant_holds() {
    let mut custody = Custody::new();
    let reply = r#"{"id":"held","jsonrpc":"2.0","result":{"ok":true}}"#;
    let outcome = custody.adapter_call(
        &escapes_holding_stdout(reply),
        Duration::from_secs(3),
        &JsonRpcRequest::status("held"),
    );
    let holder = custody.hold();
    assert!(
        matches!(
            outcome,
            Err(AdapterTransportFault::DispatchedUnknown { .. })
        ),
        "without end of output the reply is unproved: {outcome:?}"
    );
    assert!(
        !host_reads_stdout_of(&holder),
        "a reader of the call's stdout outlived the call"
    );
}

#[test]
fn an_exec_call_whose_frame_is_never_read_answers_by_its_deadline() {
    let custody = Custody::new();
    let timeout = Duration::from_millis(500);
    let started = Instant::now();
    let result = custody.exec_call(NEVER_READS, timeout, oversized_input());
    let elapsed = started.elapsed();
    assert!(
        matches!(result, Err(HostToolError::Uncertain { .. })),
        "{result:?}"
    );
    assert!(custody.unsettled().is_empty() && !leader_running(&custody));
    assert!(
        elapsed < timeout + STOP_MARGIN,
        "the call outlived its {timeout:?} deadline: {elapsed:?}"
    );
}

#[test]
fn an_exec_child_flooding_stderr_still_answers_its_frame() {
    let custody = Custody::new();
    let reply = custody.exec_call(
        &floods_stderr(r#"{"ok":true}"#),
        Duration::from_secs(10),
        json!({}),
    );
    assert!(
        matches!(&reply, Ok(value) if value["ok"] == true),
        "{reply:?}"
    );
    assert!(custody.unsettled().is_empty());
}

#[test]
fn an_exec_call_leaves_no_reader_on_a_pipe_an_escaped_descendant_holds() {
    let mut custody = Custody::new();
    let outcome = custody.exec_call(
        &escapes_holding_stdout(r#"{"ok":true}"#),
        Duration::from_secs(3),
        json!({}),
    );
    let holder = custody.hold();
    assert!(
        matches!(outcome, Err(HostToolError::Uncertain { .. })),
        "without end of output the reply is unproved: {outcome:?}"
    );
    assert!(
        !host_reads_stdout_of(&holder),
        "a reader of the call's stdout outlived the call"
    );
}

#[test]
fn an_expired_exchange_does_not_grant_its_stop_a_fresh_term_grace() {
    let custody = Custody::new();
    let script = r#"sleep=$2; trap '' TERM; IFS= read -r _;
printf '%s\n' '{"id":"stubborn","jsonrpc":"2.0","result":{"ok":true}}';
exec 1>&- 2>&-; while :; do "$sleep" 30; done"#;
    let started = Instant::now();
    let outcome = custody.adapter_call(
        script,
        Duration::from_millis(250),
        &JsonRpcRequest::status("stubborn"),
    );
    let spent = started.elapsed();
    assert!(matches!(
        outcome,
        Err(AdapterTransportFault::DispatchedUnknown { .. })
    ));
    assert!(
        spent < Duration::from_secs(1),
        "the completed exchange budget acquired a fresh stop grace: {spent:?}"
    );
}
