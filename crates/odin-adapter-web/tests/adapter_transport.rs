//! Web adapter executable tests through [`RegisteredWorkerFixture`] and
//! [`FramedExecAdapterTransport`], using temporary configuration rather than production secrets.
//!
//! The missing-credential case checks status, typed failure, framing, and worker shutdown.
//! The fallback case uses private loopback SearXNG and Brave responders with an ephemeral CA;
//! it requires Python 3 and OpenSSL on PATH.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_adapter_core::ids::AdapterWireId;
use odin_adapter_core::operation::IdempotencyKey;
use odin_adapter_core::transport::{
    encode_frame, AdapterErrorCode, AdapterTransport, AdapterTransportFault, JsonRpcOutcome,
    JsonRpcRequest, WebSearchInput, MAX_FRAME_BYTES,
};
use odin_kernel::{HandlerBinding, StopAuthority};
use odin_omp::host_tools::adapter::FramedExecAdapterTransport;
use odin_omp::process::OmpWorkerLaunch;
use odin_process::test_support::RegisteredWorkerFixture;
use odin_process::{RegisteredServiceBinding, ScopeLimits};
use odin_types::CorrelationId;

/// Per-dispatch deadline. The synthetic missing-credential scenario
/// replies after one bounded local read; the StopAuthority escalation
/// stays far behind.
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(90);

/// Re-entry point for the real worker bootstrap inside this test binary.
/// The fixture's generated wrapper re-executes the harness at exactly this
/// test; on the ordinary outer run it is a no-op.
#[test]
fn adapter_worker_bootstrap_entry() {
    odin_process::test_support::run_bootstrap_if_active();
}

/// The backend under test: this crate's binary, built by Cargo.
fn backend_executable() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_odin-adapter-web"))
}

/// Resolves the absolute `unshare` binary exactly like the established
/// worker fixtures: an explicit override environment first, then the
/// runner's PATH — absolute file paths only, no PATH discovery inside the
/// worker's cleared environment.
fn fixture_unshare() -> PathBuf {
    for variable in ["ODIN_TEST_WORKER_UNSHARE", "PATH"] {
        if let Some(paths) = std::env::var_os(variable) {
            if let Some(found) = std::env::split_paths(&paths)
                .map(|directory| directory.join("unshare"))
                .find(|candidate| candidate.is_absolute() && candidate.is_file())
            {
                return found;
            }
        }
    }
    panic!(
        "no absolute unshare found; set ODIN_TEST_WORKER_UNSHARE to the absolute \
         unshare binary (e.g. /run/current-system/sw/bin/unshare)"
    )
}

/// Composes the governed transport over one isolated registered-worker
/// fixture: production `StopAuthority`, in-memory ledger, and the exact
/// manifest-built static argv. Returns the transport plus the canonical
/// executable string the pinned Exec binding must carry byte-for-byte.
fn governed_transport(
    fixture: &RegisteredWorkerFixture,
    executable: &Path,
) -> (FramedExecAdapterTransport, String) {
    let harness = std::env::current_exe().expect("libtest harness path");
    let channel = fixture
        .channel_for_harness(
            &harness,
            "adapter_worker_bootstrap_entry",
            &fixture_unshare(),
        )
        .expect("isolated registered-worker channel");
    let canonical = fs::canonicalize(executable).expect("canonical backend executable");
    let digest = blake3::hash(&fs::read(&canonical).expect("read backend executable"))
        .to_hex()
        .to_string();
    let binding =
        RegisteredServiceBinding::new(canonical.clone(), digest).expect("registered binding");
    let ledger = odin_ledger::Ledger::open_in_memory().expect("in-memory ledger");
    let authority = Arc::new(StopAuthority::new(Arc::new(Mutex::new(ledger)), channel));
    let correlation =
        CorrelationId::new("fedcba9876543210fedcba9876543210").expect("test correlation");
    let launch = OmpWorkerLaunch::new(
        authority,
        correlation,
        "odin-omp",
        "adapter-transport",
        1,
        binding,
        ScopeLimits::default(),
    )
    .expect("governed worker launch");
    let executable = canonical.to_string_lossy().into_owned();
    (FramedExecAdapterTransport::new(launch), executable)
}

/// Writes the synthetic private deployment configuration into the private
/// temporary root: one `web-search` adapter whose credential names an
/// absent file in the same tree. The real `/run/odin` deployment and any
/// real secret are unreachable by construction — the backend reads only
/// this file.
fn synthetic_private_config(root: &Path) -> PathBuf {
    let deployment = serde_json::json!({
        "backend": "brave",
        "endpoint": "https://127.0.0.1:9/v1",
        "credential": {
            "handle": "cred:transportsmoke",
            "path": root.join("absent-credential").display().to_string(),
        },
        "request_timeout_ms": 5_000u64,
        "max_results": 3u32,
        "max_response_bytes": 1_048_576u64,
    });
    let config = serde_json::json!({
        "schema": odin_adapter_core::config::ADAPTER_BACKEND_CONFIG_SCHEMA,
        "adapters": { "web-search": deployment },
    });
    let path = root.join("adapter-deployment.json");
    fs::write(
        &path,
        serde_json::to_vec(&config).expect("synthetic deployment config serializes"),
    )
    .expect("write synthetic deployment configuration");
    path
}

/// The Exec binding for the harness-launched backend: the compiled
/// executable under test with a `--config` argv naming exactly the
/// synthetic private temporary deployment file — never the pinned
/// `/run/odin` production path, never a request-supplied path.
fn pinned_exec(executable: &str, config_path: &Path) -> HandlerBinding {
    HandlerBinding::Exec {
        executable: executable.to_owned(),
        argv: vec![
            "--config".to_owned(),
            config_path.to_string_lossy().into_owned(),
        ],
    }
}

/// Checks framing and request-id echo after the registered worker stops.
fn dispatch(
    transport: &FramedExecAdapterTransport,
    binding: &HandlerBinding,
    request: &JsonRpcRequest,
) -> JsonRpcOutcome {
    let outcome = transport.call(binding, DISPATCH_TIMEOUT, request).expect(
        "governed dispatch must yield an outcome, not a transport fault: a fault here \
         means the registered launch, the bounded canonical framing, or the proved \
         stop law broke",
    );
    assert_eq!(
        outcome.id(),
        request.id.as_str(),
        "the reply id must echo the request id byte-for-byte"
    );
    let wire = outcome.to_wire();
    let encoded = encode_frame(&wire).expect("reply wire encodes canonically");
    assert!(
        encoded.len() <= MAX_FRAME_BYTES,
        "reply frame {} bytes exceeds the {MAX_FRAME_BYTES}-byte single-frame bound",
        encoded.len()
    );
    outcome
}

/// A ready status or config error would mean the isolated missing-credential setup was bypassed.
fn assert_status_law(outcome: &JsonRpcOutcome) {
    let JsonRpcOutcome::Success { result, .. } = outcome else {
        panic!(
            "status must be a canonical snapshot over the synthetic deployment, \
             got {outcome:?}"
        )
    };
    assert_eq!(
        result["adapter"]["adapter_id"], "web-search",
        "the snapshot must name the admitted web-search adapter"
    );
    assert_eq!(
        result["taint"], "credential_tainted",
        "a credential-bearing adapter is always credential-tainted; success \
         never resets the monotonic taint"
    );
    let health = result["health"]
        .as_str()
        .expect("snapshot health is a string");
    assert_eq!(
        health, "unavailable",
        "the synthetic credential is absent, so health must be honestly \
         unavailable; ready would mean a real secret was read"
    );
    assert_eq!(
        result["last_failure"]["code"], "credentials_unavailable",
        "a missing credential is reported with the typed failure code"
    );
    assert_eq!(
        result["last_failure"]["retryable"], true,
        "a credential absence is retryable, not permanent"
    );
}

/// Missing credentials must fail without exposing credential or deployment material.
fn assert_search_law(outcome: &JsonRpcOutcome, deployment_root: &Path) {
    match outcome {
        JsonRpcOutcome::Error {
            code: AdapterErrorCode::CredentialsUnavailable,
            message,
            data,
            ..
        } => {
            let root_text = deployment_root.to_string_lossy();
            let forbidden = [
                root_text.as_ref(),
                "cred:transportsmoke",
                "https://127.0.0.1:9/v1",
                "/run/odin",
            ];
            let data_text = data
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .ok()
                .flatten()
                .unwrap_or_default();
            for value in forbidden {
                assert!(
                    !message.contains(value) && !data_text.contains(value),
                    "the typed credential failure must not carry secret or \
                     deployment material: leaked {value:?} in {message:?} / \
                     {data_text:?}"
                );
            }
        }
        other => panic!(
            "the controlled missing-credential search must answer exactly the \
             typed credentials_unavailable failure, got {other:?}"
        ),
    }
}

#[test]
fn governed_adapter_backend_serves_typed_unavailable_over_registered_workers() {
    let executable = backend_executable();
    let fixture = RegisteredWorkerFixture::new().expect("start isolated registered-worker fixture");
    let deployment_root = tempfile::tempdir().expect("private synthetic deployment root");
    let config_path = synthetic_private_config(deployment_root.path());
    let (transport, executable) = governed_transport(&fixture, &executable);
    let binding = pinned_exec(&executable, &config_path);

    // A builtin binding must be rejected before spawning a worker or sending a frame.
    let builtin = HandlerBinding::Builtin {
        name: "odin_adapter.web_search_evidence".to_owned(),
    };
    let fault = transport
        .call(
            &builtin,
            DISPATCH_TIMEOUT,
            &JsonRpcRequest::status("no-frame"),
        )
        .expect_err("a builtin adapter binding dispatches no frame");
    assert!(
        matches!(fault, AdapterTransportFault::NotDispatched { .. }),
        "a builtin binding is proven not-dispatched, got {fault:?}"
    );

    // Canonical status probe over a registered worker: launch, one bounded
    // stdin frame, one bounded canonical stdout frame, proved stop, reap.
    let status = dispatch(
        &transport,
        &binding,
        &JsonRpcRequest::status("adapter-transport-status"),
    );
    assert_status_law(&status);

    // Canonical web.search with the credential genuinely absent from the
    // harness: the typed unavailable verdict is the honest settlement —
    // no real HTTP account is required to prove it, and no fake results
    // may appear.
    let request = JsonRpcRequest::web_search(
        "adapter-transport-search",
        AdapterWireId::new("op.adapter.transport.smoke").expect("operation id fits the grammar"),
        IdempotencyKey::new("adapter-transport-smoke-key").expect("idempotency key fits"),
        WebSearchInput::new("odin governed adapter transport", 3).expect("bounded search input"),
    )
    .expect("canonical search request");
    let search = dispatch(&transport, &binding, &request);
    assert_search_law(&search, deployment_root.path());

    // Reap evidence: the same authority completes another full
    // launch/prove-stop cycle. A leaked worker, unproved stop, or poisoned
    // actuator from either earlier dispatch would fail this one.
    let again = dispatch(
        &transport,
        &binding,
        &JsonRpcRequest::status("adapter-transport-status-2"),
    );
    assert_status_law(&again);
}

/// Owns the isolated upstream helper. Closing stdin stops both listeners;
/// Drop also kills/reaps on assertion failure, before the tempdir disappears.
struct PrivateUpstreams {
    child: std::process::Child,
    root: tempfile::TempDir,
    ready: serde_json::Value,
}

impl PrivateUpstreams {
    fn start() -> Self {
        let root = tempfile::tempdir().expect("private upstream root");
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/private_web_fixture.py");
        let child = std::process::Command::new("python3")
            .arg(helper)
            .arg("--root")
            .arg(root.path())
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start private Python TLS helper (requires openssl)");
        let mut fixture = Self {
            child,
            root,
            ready: serde_json::Value::Null,
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(65);
        loop {
            if let Ok(bytes) = fs::read(fixture.root.path().join("ready.json")) {
                if let Ok(ready) = serde_json::from_slice(&bytes) {
                    fixture.ready = ready;
                    return fixture;
                }
            }
            assert!(
                fixture.child.try_wait().expect("helper state").is_none(),
                "private TLS helper exited before readiness"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "private TLS helper readiness timed out"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn events(&self) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(self.root.path().join("events.json")).expect("read upstream evidence"),
        )
        .expect("parse upstream evidence")
    }

    fn mode(&mut self, mode: &str) {
        use std::io::Write;
        let ack = self.root.path().join("ack");
        if ack.exists() {
            fs::remove_file(&ack).expect("clear previous acknowledgement");
        }
        writeln!(
            self.child.stdin.as_mut().expect("helper stdin"),
            "{}",
            serde_json::json!({"mode": mode})
        )
        .expect("set helper mode");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if fs::read_to_string(&ack).is_ok_and(|reply| reply == mode) {
                break;
            }
            assert!(
                self.child.try_wait().expect("helper state").is_none(),
                "helper exited"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "helper acknowledgement timed out"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn config(&self, missing_credential: bool) -> PathBuf {
        let credential = if missing_credential {
            self.root.path().join("absent-credential")
        } else {
            PathBuf::from(self.ready["credential"].as_str().expect("credential path"))
        };
        let config = serde_json::json!({
            "schema": odin_adapter_core::config::ADAPTER_BACKEND_CONFIG_SCHEMA,
            "adapters": {"web-search": {
                "backend": "searxng", "endpoint": self.ready["primary"],
                "request_timeout_ms": 5000, "max_results": 3,
                "max_response_bytes": 1048576,
                "fallback": {
                    "backend": "brave", "endpoint": self.ready["fallback"],
                    "ca_bundle_path": self.ready["ca"],
                    "credential": {"handle": "cred:privatefixture", "path": credential},
                    "request_timeout_ms": 5000, "max_results": 3,
                    "max_response_bytes": 1048576
                }
            }}
        });
        let path = self.root.path().join("deployment.json");
        fs::write(
            &path,
            serde_json::to_vec(&config).expect("private config JSON"),
        )
        .expect("write private config");
        path
    }
}

impl Drop for PrivateUpstreams {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while self.child.try_wait().ok().flatten().is_none() && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn governed_searxng_to_brave_private_tls_fallback() {
    let mut upstreams = PrivateUpstreams::start();
    let fixture = RegisteredWorkerFixture::new().expect("isolated registered workers");
    let (transport, executable) = governed_transport(&fixture, &backend_executable());
    let config = upstreams.config(false);
    let binding = pinned_exec(&executable, &config);
    let query = format!(
        "private fallback {}",
        upstreams.ready["nonce"].as_str().expect("nonce")
    );
    let request = JsonRpcRequest::web_search(
        "private-fallback",
        AdapterWireId::new("op.private.fallback").expect("operation id"),
        IdempotencyKey::new("private-fallback-key").expect("key"),
        WebSearchInput::new(&query, 2).expect("input"),
    )
    .expect("request");
    let primary_event = serde_json::json!({"backend": "searxng", "path": "/search",
        "query": {"q": [&query], "format": ["json"]}, "authenticated": false, "has_auth": false, "status": 503});
    let fallback_event = serde_json::json!({"backend": "brave", "path": "/search",
        "query": {"q": [&query], "count": ["2"]}, "authenticated": true, "has_auth": true, "status": 200});

    // The same HTTPS endpoint must fail verification with default public
    // roots. No credential-bearing HTTP fallback or insecure TLS bypass.
    let mut untrusted: serde_json::Value =
        serde_json::from_slice(&fs::read(&config).expect("private config")).expect("config JSON");
    untrusted["adapters"]["web-search"]["fallback"]
        .as_object_mut()
        .expect("fallback object")
        .remove("ca_bundle_path");
    fs::write(
        &config,
        serde_json::to_vec(&untrusted).expect("untrusted config JSON"),
    )
    .expect("write untrusted config");
    let rejected_tls = dispatch(&transport, &binding, &request);
    assert!(matches!(
        rejected_tls,
        JsonRpcOutcome::Error {
            code: AdapterErrorCode::InternalError,
            ..
        }
    ));
    assert_eq!(upstreams.events(), serde_json::json!([primary_event]));
    upstreams.config(false);
    upstreams.mode("fallback");

    let outcome = dispatch(&transport, &binding, &request);
    let JsonRpcOutcome::Success { result, .. } = &outcome else {
        panic!("controlled fallback must succeed: {outcome:?}");
    };
    assert_eq!(result["backend"], "brave");
    assert_eq!(
        result["results"][0]["url"],
        format!(
            "https://fixture.invalid/{}",
            upstreams.ready["nonce"].as_str().expect("nonce")
        )
    );
    assert_eq!(result["results"].as_array().expect("result array").len(), 1);
    assert_eq!(
        result["results"][0]["title"],
        format!(
            "private-{}",
            upstreams.ready["nonce"].as_str().expect("nonce")
        )
    );
    assert_eq!(
        result["results"][0]["description"],
        format!(
            "controlled-{}",
            upstreams.ready["nonce"].as_str().expect("nonce")
        )
    );
    assert_eq!(
        upstreams.events(),
        serde_json::json!([primary_event, fallback_event])
    );
    let token =
        fs::read_to_string(upstreams.root.path().join("credential")).expect("synthetic token");
    assert!(!serde_json::to_string(&outcome.to_wire())
        .expect("outcome JSON")
        .contains(&token));

    upstreams.mode("healthy");
    let healthy = dispatch(&transport, &binding, &request);
    assert!(
        matches!(healthy, JsonRpcOutcome::Success { ref result, .. } if result["backend"] == "searxng")
    );
    let mut healthy_event = primary_event.clone();
    healthy_event["status"] = serde_json::json!(200);
    assert_eq!(upstreams.events(), serde_json::json!([healthy_event]));

    upstreams.mode("fallback");
    let mut invalid = request.clone();
    invalid.params["input"]["query"] = serde_json::json!("");
    let rejected = dispatch(&transport, &binding, &invalid);
    assert!(matches!(
        rejected,
        JsonRpcOutcome::Error {
            code: AdapterErrorCode::InvalidParams,
            ..
        }
    ));
    assert_eq!(upstreams.events(), serde_json::json!([]));

    upstreams.config(true);
    let missing = dispatch(&transport, &binding, &request);
    assert_search_law(&missing, upstreams.root.path());
    assert_eq!(upstreams.events(), serde_json::json!([primary_event]));

    upstreams.config(false);
    upstreams.mode("both-down");
    let failed = dispatch(&transport, &binding, &request);
    assert!(matches!(
        failed,
        JsonRpcOutcome::Error {
            code: AdapterErrorCode::InternalError,
            ..
        }
    ));
    let mut failed_event = fallback_event.clone();
    failed_event["status"] = serde_json::json!(503);
    assert_eq!(
        upstreams.events(),
        serde_json::json!([primary_event, failed_event])
    );
    println!("ODIN_PRIVATE_WEB_FALLBACK_V1: verified");
}
