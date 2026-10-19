//! MCP bridge executable tests through [`RegisteredWorkerFixture`] and
//! [`FramedExecAdapterTransport`], using a private POSIX-sh MCP server.
//! Failures reach both the caller and durable storage, so they must not contain upstream payloads or URLs.
//!
//! The server scripts use shell builtins only, because the worker
//! environment carries no PATH; a program one needs is resolved to an
//! absolute path here. Each script leaves a witness file when it emits a
//! canary, so a fixture that never ran cannot pass for a clean frame.
//!
//! The fake manager cannot kill reparented descendants, so that case requires
//! a systemd user session via [`RegisteredWorkerFixture::new_delegated`].

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_adapter_core::transport::{
    AdapterErrorCode, AdapterTransport, JsonRpcOutcome, JsonRpcRequest, RpcMethod,
};
use odin_kernel::{HandlerBinding, StopAuthority};
use odin_omp::host_tools::adapter::FramedExecAdapterTransport;
use odin_omp::process::OmpWorkerLaunch;
use odin_process::test_support::RegisteredWorkerFixture;
use odin_process::{RegisteredServiceBinding, ScopeLimits};
use odin_types::CorrelationId;
use serde_json::{json, Value};

/// Exceeds the bridge's 35 s operation deadline.
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// The token an upstream error carries, at both ends of a 64 KiB payload.
const UPSTREAM_CANARY: &str = "odin-t17-upstream-canary";

/// The host every document URL of the page cases names.
const URL_CANARY: &str = "url-canary-t17";

/// Re-entry point for the real worker bootstrap inside this test binary.
/// The fixture's generated wrapper re-executes the harness at exactly this
/// test; on the ordinary outer run it is a no-op.
#[test]
fn adapter_worker_bootstrap_entry() {
    odin_process::test_support::run_bootstrap_if_active();
}

/// The first absolute `name` on the listed path variables, in order.
fn on_path(name: &str, variables: &[&str]) -> PathBuf {
    for variable in variables {
        if let Some(paths) = std::env::var_os(variable) {
            if let Some(found) = std::env::split_paths(&paths)
                .map(|directory| directory.join(name))
                .find(|candidate| candidate.is_absolute() && candidate.is_file())
            {
                return found;
            }
        }
    }
    panic!("no absolute {name} on {variables:?}")
}

/// The governed transport over one registered-worker fixture: production
/// `StopAuthority`, in-memory ledger, and the bridge binary Cargo built
/// for this test. Returns the transport and the executable the Exec
/// binding must name.
fn governed_transport(fixture: &RegisteredWorkerFixture) -> (FramedExecAdapterTransport, String) {
    let harness = std::env::current_exe().expect("libtest harness path");
    let channel = fixture
        .channel_for_harness(
            &harness,
            "adapter_worker_bootstrap_entry",
            &on_path("unshare", &["ODIN_TEST_WORKER_UNSHARE", "PATH"]),
        )
        .expect("isolated registered-worker channel");
    let canonical = fs::canonicalize(env!("CARGO_BIN_EXE_odin-adapter-mcp"))
        .expect("canonical bridge executable");
    let mut hasher = blake3::Hasher::new();
    hasher
        .update_reader(fs::File::open(&canonical).expect("open bridge executable"))
        .expect("hash bridge executable");
    let digest = hasher.finalize().to_hex().to_string();
    let binding =
        RegisteredServiceBinding::new(canonical.clone(), digest).expect("registered binding");
    let ledger = odin_ledger::Ledger::open_in_memory().expect("in-memory ledger");
    let authority = Arc::new(StopAuthority::new(Arc::new(Mutex::new(ledger)), channel));
    let correlation =
        CorrelationId::new("0123456789abcdef0123456789abcdef").expect("test correlation");
    let launch = OmpWorkerLaunch::new(
        authority,
        correlation,
        "odin-omp",
        "adapter-mcp",
        1,
        binding,
        ScopeLimits::default(),
    )
    .expect("governed worker launch");
    (
        FramedExecAdapterTransport::new(launch),
        canonical.to_string_lossy().into_owned(),
    )
}

/// A private stdio MCP server in POSIX sh with builtins only, the protocol
/// of the crate's shell fixtures: it answers `initialize`, then `arms`,
/// further `case` arms over each request `$line` with its `$id` parsed and
/// `answer` printing one result. `arguments` follow the script.
fn server(root: &Path, prelude: &str, arms: &str, arguments: &[&str]) -> Vec<String> {
    let script = format!(
        r#"{prelude}
answer() {{ printf '{{"jsonrpc":"2.0","id":%s,"result":%s}}\n' "$id" "$1"; }}
while IFS= read -r line; do
  rest=${{line#*\"id\":}}; id=${{rest%%[!0-9]*}}
  case "$line" in
    *'"initialize"'*) answer '{{"protocolVersion":"2025-06-18","capabilities":{{}},"serverInfo":{{"name":"fake","version":"1"}}}}' ;;
{arms}
  esac
done
"#
    );
    let path = root.join("governed-mcp.sh");
    fs::write(&path, script).expect("server script written");
    let mut argv = vec!["/bin/sh".to_owned(), path.to_string_lossy().into_owned()];
    argv.extend(arguments.iter().map(|argument| (*argument).to_owned()));
    argv
}

/// The bridge's Exec binding: its declaration flags, then the server argv.
fn bridge(executable: &str, flags: &[&str], server: Vec<String>) -> HandlerBinding {
    let mut argv: Vec<String> = flags.iter().map(|flag| (*flag).to_owned()).collect();
    argv.push("--".to_owned());
    argv.extend(server);
    HandlerBinding::Exec {
        executable: executable.to_owned(),
        argv,
    }
}

fn operation(id: &str, kind: &str, input: Value) -> JsonRpcRequest {
    JsonRpcRequest::new(
        id,
        RpcMethod::parse(kind).expect("operation kind"),
        json!({
            "operation_id": format!("op.{id}"),
            "idempotency_key": format!("{id}-key"),
            "input": input,
        }),
    )
    .expect("operation request")
}

/// One governed dispatch: launch, one request frame, one reply frame and a
/// proved stop. A transport fault here means the bridge did not settle.
fn dispatch(
    transport: &FramedExecAdapterTransport,
    binding: &HandlerBinding,
    request: &JsonRpcRequest,
    timeout: Duration,
) -> JsonRpcOutcome {
    let outcome = transport
        .call(binding, timeout, request)
        .expect("the governed bridge settles with one frame and a proved stop");
    assert_eq!(outcome.id(), request.id.as_str());
    outcome
}

/// Failed calls must redact upstream data and keep the error message within 1 KiB.
fn assert_owner_safe(label: &str, outcome: &JsonRpcOutcome, leaked: &[&str]) {
    let JsonRpcOutcome::Error { code, message, .. } = outcome else {
        panic!("{label}: a failed upstream call must be a typed failure, got {outcome:?}");
    };
    assert!(
        matches!(code, AdapterErrorCode::InternalError),
        "{label}: {code:?}"
    );
    let wire = serde_json::to_string(&outcome.to_wire()).expect("outcome JSON");
    for canary in leaked {
        assert!(
            !wire.contains(canary),
            "{label}: the owner-facing frame ({} bytes) echoes {canary:?}",
            wire.len()
        );
    }
    assert!(
        message.len() <= 1024,
        "{label}: a {}-byte message is not bounded",
        message.len()
    );
}

/// An upstream JSON-RPC error, a tool's own error text and a failed listing
/// reach the owner as typed failures that carry none of the payload, while
/// the same server's good call still answers.
#[test]
fn an_upstream_error_never_reaches_the_owner_through_the_governed_bridge() {
    let fixture = RegisteredWorkerFixture::new().expect("isolated registered workers");
    let (transport, executable) = governed_transport(&fixture);
    let root = tempfile::tempdir().expect("private server root");
    let directory = root.path().to_string_lossy().into_owned();
    let prelude = format!(
        r#"dir=$1; mode=$2; canary={UPSTREAM_CANARY}
chunk=x; i=0; while [ "$i" -lt 16 ]; do chunk=$chunk$chunk; i=$((i+1)); done
payload=$canary$chunk$canary"#
    );
    let arms = r#"    *'"tools/list"'*)
      if [ "$mode" = list-error ]; then
        : > "$dir/emitted-list"
        printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"%s","data":{"detail":"%s"}}}\n' "$id" "$payload" "$payload"
      else
        answer '{"tools":[{"name":"get_current_time","annotations":{"readOnlyHint":true}},{"name":"fail_rpc"},{"name":"fail_tool"}]}'
      fi ;;
    *'"get_current_time"'*) answer '{"content":[{"type":"text","text":"12:00"}]}' ;;
    *'"fail_rpc"'*)
      : > "$dir/emitted-rpc"
      printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"%s","data":{"detail":"%s"}}}\n' "$id" "$payload" "$payload" ;;
    *'"fail_tool"'*)
      : > "$dir/emitted-tool"
      answer "{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"$payload\"}]}" ;;"#;
    let flags = [
        "--adapter",
        "mcp-fixture",
        "--kind-prefix",
        "fixture",
        "--read-only",
        "get_current_time",
    ];
    let calls = bridge(
        &executable,
        &flags,
        server(root.path(), &prelude, arms, &[directory.as_str(), "calls"]),
    );

    let good = dispatch(
        &transport,
        &calls,
        &operation("good", "fixture.get_current_time", json!({})),
        DISPATCH_TIMEOUT,
    );
    assert!(
        matches!(&good, JsonRpcOutcome::Success { result, .. }
            if result["content"][0]["text"] == "12:00"),
        "the fixture's good call answers: {good:?}"
    );
    for (label, kind, witness) in [
        ("rpc error", "fixture.fail_rpc", "emitted-rpc"),
        ("tool error", "fixture.fail_tool", "emitted-tool"),
    ] {
        let outcome = dispatch(
            &transport,
            &calls,
            &operation(witness, kind, json!({})),
            DISPATCH_TIMEOUT,
        );
        assert!(
            root.path().join(witness).exists(),
            "{label}: the server never emitted its canary"
        );
        assert_owner_safe(label, &outcome, &[UPSTREAM_CANARY]);
    }

    let listing = bridge(
        &executable,
        &flags,
        server(
            root.path(),
            &prelude,
            arms,
            &[directory.as_str(), "list-error"],
        ),
    );
    let described = dispatch(
        &transport,
        &listing,
        &JsonRpcRequest::describe("describe-error"),
        DISPATCH_TIMEOUT,
    );
    assert!(
        root.path().join("emitted-list").exists(),
        "describe: the server never emitted its canary"
    );
    assert_owner_safe("describe", &described, &[UPSTREAM_CANARY]);
}

/// A page that did not load and a PDF whose converter failed stay typed
/// failures that name neither the document URL nor the upstream text, while
/// the same declaration still reads a loaded page and converts a PDF.
#[test]
fn a_failed_page_or_pdf_never_names_its_url_through_the_governed_bridge() {
    let fixture = RegisteredWorkerFixture::new().expect("isolated registered workers");
    let (transport, executable) = governed_transport(&fixture);
    let root = tempfile::tempdir().expect("private server root");
    let directory = root.path().to_string_lossy().into_owned();
    let converter = root.path().join("pdf-text.sh");
    fs::write(
        &converter,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$1" >> '{directory}/converted'
case "$1" in
  *exit3*) exit 3 ;;
  *exit65*) exit 65 ;;
esac
printf 'converted text\n'
"#
        ),
    )
    .expect("converter written");
    fs::set_permissions(
        &converter,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("converter executable");
    let prelude = format!("dir=$1; canary={UPSTREAM_CANARY}; page=none");
    let arms = r##"    *'"tools/list"'*) answer '{"tools":[{"name":"browser_navigate","inputSchema":{"properties":{"url":{}}}},{"name":"browser_markdown","inputSchema":{"properties":{"max_chars":{}}}},{"name":"browser_network_requests","inputSchema":{"properties":{}}}]}' ;;
    *'"browser_navigate"'*)
      rest=${line#*\"url\":\"}; page=${rest%%\"*}
      printf '%s\n' "$page" >> "$dir/navigated"
      case "$page" in
        *unreachable*) answer "{\"isError\":true,\"content\":[{\"type\":\"text\",\"text\":\"Error: Network error: $page: $canary\"}]}" ;;
        *) answer '{"content":[{"type":"text","text":"Navigated"}]}' ;;
      esac ;;
    *'"browser_network_requests"'*)
      case "$page" in
        *missing*) log="[404] GET $page (7229B)" ;;
        *) log="[200] GET $page (1B)" ;;
      esac
      answer "{\"content\":[{\"type\":\"text\",\"text\":\"$log\"}]}" ;;
    *'"browser_markdown"'*)
      case "$page" in
        *empty*) text="  " ;;
        *.pdf) text="%PDF-1.7 raw" ;;
        *) text="# loaded" ;;
      esac
      answer "{\"content\":[{\"type\":\"text\",\"text\":\"$text\"}]}" ;;"##;
    let converter = converter.to_string_lossy().into_owned();
    let binding = bridge(
        &executable,
        &[
            "--adapter",
            "obscura",
            "--kind-prefix",
            "web",
            "--read-only",
            "browser_navigate",
            "--read-only",
            "browser_markdown",
            "--read-only",
            "browser_network_requests",
            "--sequence",
            "read=browser_navigate,browser_markdown",
            "--load-check",
            "browser_network_requests",
            "--pdf-text",
            converter.as_str(),
        ],
        server(root.path(), &prelude, arms, &[directory.as_str()]),
    );
    let url = |case: &str| format!("https://{URL_CANARY}.invalid/{case}");
    let read = |case: &str| {
        dispatch(
            &transport,
            &binding,
            &operation(
                &case.replace('.', "-"),
                "web.read",
                json!({ "url": url(case) }),
            ),
            DISPATCH_TIMEOUT,
        )
    };
    let witnessed = |file: &str, case: &str| {
        fs::read_to_string(root.path().join(file))
            .unwrap_or_default()
            .lines()
            .any(|line| line == url(case))
    };

    for (case, text) in [("page", "# loaded"), ("paper.pdf", "converted text\n")] {
        let outcome = read(case);
        assert!(
            matches!(&outcome, JsonRpcOutcome::Success { result, .. }
                if result["content"][0]["text"] == text),
            "{case}: the declaration reads a good page: {outcome:?}"
        );
    }
    for case in ["missing", "unreachable", "empty", "exit3.pdf", "exit65.pdf"] {
        let outcome = read(case);
        assert!(
            witnessed("navigated", case),
            "{case}: the URL never reached the server"
        );
        if case.ends_with(".pdf") {
            assert!(
                witnessed("converted", case),
                "{case}: the URL never reached the converter"
            );
        }
        assert_owner_safe(case, &outcome, &[URL_CANARY, UPSTREAM_CANARY]);
    }
}

/// Whether the process recorded as `pid` with start ticks `start` still
/// runs; a zombie has already been killed.
fn alive(pid: &str, start: &str) -> bool {
    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, fields)) = stat.rsplit_once(')') else {
        return false;
    };
    let fields: Vec<&str> = fields.split_whitespace().collect();
    fields.get(19) == Some(&start) && !matches!(fields.first(), Some(&"Z" | &"X"))
}

/// The server leaves a descendant that outlives it — reparented once the
/// bridge stops the server, still holding the server's output — and the
/// governed call settles anyway, before the descendant would exit on its
/// own, with that descendant gone: the proved stop of the bridge's worker
/// covers its whole tree, not just the server the bridge waited for.
#[test]
fn a_reparented_server_descendant_is_gone_when_the_governed_call_settles() {
    let fixture = RegisteredWorkerFixture::new_delegated().expect(
        "the caller's systemd user session is required: only a real cgroup proves a \
         reparented descendant gone",
    );
    let (transport, executable) = governed_transport(&fixture);
    let root = tempfile::tempdir().expect("private server root");
    let directory = root.path().to_string_lossy().into_owned();
    let sleep = on_path("sleep", &["PATH"]).to_string_lossy().into_owned();
    let arms = r#"    *'"tools/call"'*)
      /bin/sh -c 'out=$1; sleep=$2; read -r stat < /proc/self/stat; set -- $stat; printf "%s %s\n" "$$" "${22}" > "$out"; exec "$sleep" 30' descendant "$dir/descendant" "$sleep" &
      n=0; while [ ! -s "$dir/descendant" ] && [ "$n" -lt 1000000 ]; do n=$((n+1)); done
      answer '{"content":[{"type":"text","text":"spawned"}]}' ;;"#;
    let binding = bridge(
        &executable,
        &[
            "--adapter",
            "mcp-fixture",
            "--kind-prefix",
            "fixture",
            "--read-only",
            "spawn",
        ],
        server(
            root.path(),
            "dir=$1; sleep=$2",
            arms,
            &[directory.as_str(), sleep.as_str()],
        ),
    );
    // Under the descendant's own 30 s: a bridge that waits for the output
    // the descendant holds faults here instead of settling late.
    let outcome = dispatch(
        &transport,
        &binding,
        &operation("descendant", "fixture.spawn", json!({})),
        Duration::from_secs(20),
    );
    assert!(
        matches!(&outcome, JsonRpcOutcome::Success { result, .. }
            if result["content"][0]["text"] == "spawned"),
        "{outcome:?}"
    );
    let recorded = fs::read_to_string(root.path().join("descendant"))
        .expect("the server recorded its descendant before answering");
    let (pid, start) = recorded
        .trim()
        .split_once(' ')
        .expect("descendant pid and start ticks");
    assert!(
        !alive(pid, start),
        "descendant {pid} outlived the proved stop of the bridge's worker"
    );
}
