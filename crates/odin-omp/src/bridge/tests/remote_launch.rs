//! Exercises remote RPC startup and re-attach, including failed-start publication cleanup.
//! A settled live row alone does not establish removal of cluster resources.

use super::fixture::{fixture_context, row_for};
use super::*;

use async_trait::async_trait;

use crate::probe::CaseContext;
use crate::process::{
    HarnessStdin, RemoteAttachError, RemoteExit, RemoteExitWait, RemoteHarnessAdmission,
    RemoteHarnessChannel,
};

/// The remote `OmpProcessSpec` a workload session carries: the in-image
/// verifier as `executable` and the whole odind argv as `explicit_args`, ending
/// at the single `--` separator with the launcher token and its own flags.
pub(super) fn remote_spec(launcher: &Path, cwd: PathBuf) -> OmpProcessSpec {
    let launcher = launcher.to_string_lossy().into_owned();
    OmpProcessSpec {
        executable: PathBuf::from("/odin/bin/odind"),
        cwd,
        explicit_args: vec![
            "workload-exec".to_owned(),
            "--agent-dir".to_owned(),
            "/state/.omp-agent/fixture".to_owned(),
            "--working-dir".to_owned(),
            "/state".to_owned(),
            "--trusted-extension".to_owned(),
            launcher.clone(),
            "--".to_owned(),
            launcher.clone(),
            "--trusted-extension".to_owned(),
            launcher,
            "--no-skills".to_owned(),
            "--no-rules".to_owned(),
            "--no-tools".to_owned(),
            "--no-lsp".to_owned(),
            "--no-pty".to_owned(),
        ],
        explicit_env: Vec::new(),
        expected_source_revision: crate::probe::PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: Duration::from_secs(10),
        drain_timeout: Duration::from_secs(10),
        kill_timeout: Duration::from_secs(10),
    }
}

/// The launcher's own argv as the in-pod verifier reconstructs it: everything
/// after odind's single `--` separator. A run mode inserted anywhere before that
/// separator would be an odind flag, not a launcher argument.
fn launcher_argv(args: &[String]) -> Vec<String> {
    let separators: Vec<usize> = args
        .iter()
        .enumerate()
        .filter(|(_, argument)| argument.as_str() == "--")
        .map(|(index, _)| index)
        .collect();
    assert_eq!(
        separators.len(),
        1,
        "the odind argv carries exactly one `--` separator: {args:?}"
    );
    args[separators[0] + 1..].to_vec()
}

/// Writes directly to the child; shutdown drops stdin to send EOF.
struct PipeStdin(Option<tokio::process::ChildStdin>);

#[async_trait]
impl HarnessStdin for PipeStdin {
    async fn write_all(&mut self, bytes: Vec<u8>) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self.0.as_mut() {
            Some(stdin) => stdin.write_all(&bytes).await,
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "carrier stdin is closed",
            )),
        }
    }

    fn shutdown(mut self: Box<Self>) -> std::io::Result<()> {
        drop(self.0.take());
        Ok(())
    }
}

/// Spawns the launcher argv as a raw child over raw pipes — the exec channel's
/// stream shape: no authority stdin, terminal status through a one-shot waiter.
fn spawn_carrier(argv: &[String]) -> RemoteHarnessChannel {
    use std::process::Stdio;

    let mut command = tokio::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        // Fallback for a panicking test: an unretired carrier is killed with
        // its handle instead of leaking past the case.
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn the remote fixture carrier");
    let stdin = child.stdin.take().expect("carrier stdin");
    let stdout = child.stdout.take().expect("carrier stdout");
    let stderr = child.stderr.take().expect("carrier stderr");
    let exit: RemoteExitWait = Box::pin(async move {
        match child.wait().await {
            Ok(status) => RemoteExit {
                status: status.code(),
                clean: status.success(),
                failure: None,
            },
            Err(error) => RemoteExit {
                status: None,
                clean: false,
                failure: Some(format!("carrier status wait failed: {error}")),
            },
        }
    });
    RemoteHarnessChannel {
        stdin: Box::new(PipeStdin(Some(stdin))),
        stdout: Box::new(stdout),
        stderr: Some(Box::new(stderr)),
        exit,
    }
}

/// The host-admitted remote transport: counts the attach attempts it is asked
/// for, refuses typed when configured, and otherwise serves a real fixture
/// carrier.
pub(super) struct FakeRemoteTransport {
    spec: OmpProcessSpec,
    job_worker: odin_types::WorkerId,
    admission: RemoteHarnessAdmission,
    refuse: Option<String>,
    attaches: Mutex<usize>,
    /// The launcher argv of every attach, in order.
    seen_args: Mutex<Vec<Vec<String>>>,
}

impl FakeRemoteTransport {
    pub(super) fn new(spec: OmpProcessSpec, refuse: Option<String>) -> Self {
        Self {
            spec,
            job_worker: odin_process::mint_worker_id().expect("minted carrier job worker id"),
            admission: RemoteHarnessAdmission {
                profile: "odind-kubert-fixture".to_owned(),
                image: "registry.example/odin-fixture@sha256:0".to_owned(),
            },
            refuse,
            attaches: Mutex::new(0),
            seen_args: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn attaches(&self) -> usize {
        *self.attaches.lock().expect("attach counter")
    }

    /// The launcher argv of the `index`-th attach (0-based).
    pub(super) fn attach_args(&self, index: usize) -> Option<Vec<String>> {
        self.seen_args
            .lock()
            .expect("attach args")
            .get(index)
            .cloned()
    }
}

#[async_trait]
impl RemoteHarnessFactory for FakeRemoteTransport {
    async fn attach(
        &self,
        args: &[String],
        _env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError> {
        *self.attaches.lock().expect("attach counter") += 1;
        self.seen_args
            .lock()
            .expect("attach args")
            .push(args.to_vec());
        if let Some(detail) = &self.refuse {
            return Err(RemoteAttachError {
                detail: detail.clone(),
            });
        }
        Ok(spawn_carrier(&launcher_argv(args)))
    }

    fn job_worker_id(&self) -> &odin_types::WorkerId {
        &self.job_worker
    }

    fn stop_action(&self) -> odin_ledger::stop::JobStopAction {
        odin_ledger::stop::JobStopAction::Delete
    }

    fn admission(&self) -> &RemoteHarnessAdmission {
        &self.admission
    }

    fn process_spec(&self) -> OmpProcessSpec {
        self.spec.clone()
    }
}

/// The workload-shaped bridge configuration for one case, served by the
/// admitted fake transport.
pub(super) fn remote_bridge_config(
    context: &CaseContext,
    transport: Arc<FakeRemoteTransport>,
) -> OmpBridgeConfig {
    let mut config = context
        .bridge_config(context.session_descriptor())
        .expect("bridge configuration");
    config.process = transport.spec.clone();
    config.transport = Some(transport as Arc<dyn RemoteHarnessFactory>);
    config
}

// The fixture's stdin EOF stops its real subprocess without a cluster backend.
pub(super) async fn retire(bridge: &OmpBridge) {
    bridge
        .kill_child_for_probe()
        .await
        .expect("the test-owned carrier retires on stdin EOF");
}

/// The durable retirement stamp of one live row.
fn retired_at(ledger: &Ledger, session: &SessionId) -> Option<String> {
    ledger
        .connection()
        .query_row(
            "SELECT retired_at FROM live_sessions WHERE session_id=?1",
            [session.to_string()],
            |row| row.get(0),
        )
        .expect("live session row exists")
}

/// Whether the session still carries an ACTIVE lease row. A released lease is
/// what admits the next owner; the row itself is retained as history.
fn has_active_lease(ledger: &Ledger, session: &SessionId) -> bool {
    let count: i64 = ledger
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM leases WHERE object_kind=?1 AND object_id=?2 \
             AND released_logical IS NULL",
            [LEASE_OBJECT_KIND.to_owned(), session.to_string()],
            |row| row.get(0),
        )
        .expect("lease rows readable");
    count > 0
}

/// The case's remote launcher (the shared fixture) and its remote spec.
pub(super) fn case_launcher(context: &CaseContext) -> PathBuf {
    context.config().omp.executable.clone()
}

#[tokio::test]
async fn fresh_remote_attach_receives_the_host_owned_rpc_mode() {
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 11, "remote-fresh").await;
    let transport = Arc::new(FakeRemoteTransport::new(
        remote_spec(&case_launcher(&context), context.work_dir().to_path_buf()),
        None,
    ));
    // The fixture refuses to speak the protocol without exactly one host-owned
    // `--mode rpc`, and the bridge completes only on an answered handshake.
    let bridge = OmpBridge::start(remote_bridge_config(&context, Arc::clone(&transport)))
        .await
        .expect("a remote workload launch starts when the transport carries the host mode");

    let state = bridge
        .state()
        .await
        .expect("a real RPC request round-trips");
    assert_eq!(
        state.get("waiting").and_then(Value::as_bool),
        Some(false),
        "the child's get_state answer reaches the caller: {state}"
    );
    assert_eq!(transport.attaches(), 1, "exactly one attach for one launch");

    retire(&bridge).await;
    drop(bridge);
}

#[tokio::test]
async fn kube_exec_frames_skip_transcript_ingest_without_home() {
    let root = tempfile::tempdir().expect("tempdir");
    let context = fixture_context(root.path(), 11, "remote-no-transcript").await;
    let spec = remote_spec(&case_launcher(&context), context.work_dir().to_path_buf());
    assert!(spec.explicit_env.is_empty());
    let transport = Arc::new(FakeRemoteTransport::new(spec, None));
    let bridge = OmpBridge::start(remote_bridge_config(&context, transport))
        .await
        .expect("remote bridge starts without HOME");
    bridge.state().await.expect("remote frame round-trip");
    retire(&bridge).await;

    let ledger = context.ledger();
    let guard = ledger.lock().expect("case ledger lock");
    let trace_errors: i64 = guard
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM live_events WHERE session_id=?1 \
             AND json_extract(body_json,'$.kind')='trace_error'",
            [context.ids().session.to_string()],
            |row| row.get(0),
        )
        .expect("read trace errors");
    assert_eq!(trace_errors, 0);
    assert!(guard
        .trace_cursor(&context.ids().session)
        .expect("trace cursor")
        .is_none());
}

#[tokio::test]
async fn recovery_reattach_receives_the_same_host_owned_rpc_mode() {
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 12, "remote-recovery").await;
    let transport = Arc::new(FakeRemoteTransport::new(
        remote_spec(&case_launcher(&context), context.work_dir().to_path_buf()),
        None,
    ));
    let bridge = OmpBridge::start(remote_bridge_config(&context, Arc::clone(&transport)))
        .await
        .expect("fresh remote launch");

    let report = bridge
        .recover()
        .await
        .expect("remote recovery re-attaches a new launcher");
    assert_eq!(report.epoch, 2, "the respawn carries the reclaimed epoch");

    // The RECOVERED child answers a real request: the respawned channel is
    // live and speaking the protocol, not merely installed.
    let state = bridge
        .state()
        .await
        .expect("the recovered child answers an RPC request");
    assert_eq!(
        state.get("waiting").and_then(Value::as_bool),
        Some(false),
        "the recovered child's get_state answer reaches the caller: {state}"
    );
    assert_eq!(transport.attaches(), 2, "recovery re-attaches exactly once");

    retire(&bridge).await;
    drop(bridge);
}

#[tokio::test]
async fn a_refused_remote_attach_retires_the_live_row_instead_of_leaving_it_ready() {
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 13, "remote-refused").await;
    let spec = remote_spec(&case_launcher(&context), context.work_dir().to_path_buf());
    let transport = Arc::new(FakeRemoteTransport::new(
        spec,
        Some("carrier is gone from the cluster".to_owned()),
    ));
    let error = match OmpBridge::start(remote_bridge_config(&context, Arc::clone(&transport))).await
    {
        Err(error) => error,
        Ok(_) => panic!("a refused attach fails the launch"),
    };
    assert!(
        matches!(error, BridgeError::RemoteAttach { .. }),
        "the typed transport refusal is preserved, got {error}"
    );

    let session = context.ids().session.clone();
    let ledger = context.ledger();
    let guard = ledger.lock().expect("case ledger lock");
    let row = guard
        .live_session(&session)
        .expect("the launch published a row");
    assert_eq!(row.state, "failed", "a child that never ran is not `ready`");
    assert_eq!(row.epoch, 1, "the settlement is CAS'd on the owned epoch");
    assert!(
        retired_at(&guard, &session).is_some(),
        "the durable row leaves the approval-live set"
    );
    assert!(
        !has_active_lease(&guard, &session),
        "the failed attempt released its exclusive lease"
    );
}

#[tokio::test]
async fn a_stale_epoch_refusal_leaves_the_newer_incarnation_untouched() {
    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 14, "epoch-stale-settlement").await;
    let descriptor = context.session_descriptor();
    {
        let ledger = context.ledger();
        let mut guard = ledger.lock().expect("case ledger lock");
        guard
            .create_live_session_at(&row_for(&context, &descriptor), 5)
            .unwrap();
    }

    let mut config = context
        .bridge_config(descriptor)
        .expect("bridge configuration");
    config.requested_epoch = Some(odin_domain::huginn::SessionEpoch::new(3));
    let error = match OmpBridge::start(config).await {
        Err(error) => error,
        Ok(_) => panic!("a stale incarnation is refused typed"),
    };
    match error {
        BridgeError::StaleBinding { requested, actual } => {
            assert_eq!(requested, 3);
            assert_eq!(actual, 5);
        }
        error => panic!("expected the typed stale-binding refusal, got {error}"),
    }

    // A refused launch retires only what it owns: the newer incarnation's
    // publication and epoch stay exactly as published.
    let session = context.ids().session.clone();
    let ledger = context.ledger();
    let guard = ledger.lock().expect("case ledger lock");
    let row = guard.live_session(&session).expect("newer row");
    assert_eq!((row.epoch, row.state.as_str()), (5, "ready"));
    assert!(retired_at(&guard, &session).is_none());
    assert!(
        !has_active_lease(&guard, &session),
        "the refused launch released the lease it had acquired"
    );
}

/// Keeps the real carrier's EOF/exit under explicit test ownership. A launcher
/// JoinError cannot close this stdin or manufacture the child's terminal status.
struct HeldCarrier {
    transport: FakeRemoteTransport,
    stdin: Arc<parking_lot::Mutex<Option<Box<dyn HarnessStdin>>>>,
    exit: parking_lot::Mutex<Option<tokio::task::JoinHandle<RemoteExit>>>,
    ready: tokio::sync::Notify,
    held_stdout: parking_lot::Mutex<Option<tokio::io::DuplexStream>>,
}

impl Drop for HeldCarrier {
    fn drop(&mut self) {
        // Panic fallback only; the successful case closes stdin and joins
        // the actual waiter explicitly before making its verdict assertions.
        self.stdin.lock().take();
        if let Some(worker) = self.exit.lock().take() {
            worker.abort();
        }
    }
}

struct RefusedCarrierStdin {
    stdin: Arc<parking_lot::Mutex<Option<Box<dyn HarnessStdin>>>>,
}

#[async_trait]
impl HarnessStdin for RefusedCarrierStdin {
    async fn write_all(&mut self, _bytes: Vec<u8>) -> std::io::Result<()> {
        panic!("the ready frame is held before any protocol writes")
    }

    fn shutdown(self: Box<Self>) -> std::io::Result<()> {
        assert!(self.stdin.lock().is_some());
        Err(std::io::Error::other("test-owned carrier stop is held"))
    }
}

#[async_trait]
impl RemoteHarnessFactory for HeldCarrier {
    async fn attach(
        &self,
        args: &[String],
        _env: &[(String, String)],
    ) -> Result<RemoteHarnessChannel, RemoteAttachError> {
        use tokio::io::AsyncBufReadExt;

        let channel = spawn_carrier(&launcher_argv(args));
        *self.stdin.lock() = Some(channel.stdin);
        let (terminal, observed_terminal) = tokio::sync::oneshot::channel();
        let exit = tokio::spawn(async move {
            let exit = channel.exit.await;
            let _ = terminal.send(exit.clone());
            exit
        });
        *self.exit.lock() = Some(exit);
        let mut stdout = tokio::io::BufReader::new(channel.stdout);
        let mut frame = String::new();
        stdout
            .read_line(&mut frame)
            .await
            .expect("real carrier ready frame");
        let frame: serde_json::Value = serde_json::from_str(&frame).expect("ready JSON");
        assert_eq!(frame["type"], "ready");
        // Withhold the actual ready frame: production startup is now waiting
        // on its real carrier handshake, rather than a gated fake launcher.
        let (held, reader) = tokio::io::duplex(1024);
        *self.held_stdout.lock() = Some(held);
        self.ready.notify_one();
        Ok(RemoteHarnessChannel {
            stdin: Box::new(RefusedCarrierStdin {
                stdin: Arc::clone(&self.stdin),
            }),
            stdout: Box::new(reader),
            stderr: channel.stderr,
            // Forward only the actual wait result, never a fabricated status.
            exit: Box::pin(async move { observed_terminal.await.expect("carrier exit owner") }),
        })
    }

    fn job_worker_id(&self) -> &odin_types::WorkerId {
        self.transport.job_worker_id()
    }

    fn stop_action(&self) -> odin_ledger::stop::JobStopAction {
        self.transport.stop_action()
    }

    fn admission(&self) -> &RemoteHarnessAdmission {
        self.transport.admission()
    }

    fn process_spec(&self) -> OmpProcessSpec {
        self.transport.process_spec()
    }
}

struct CarrierRuntimeFactory(parking_lot::Mutex<Option<OmpBridgeConfig>>);

struct UnreachableCarrierHooks;

#[async_trait]
impl crate::live::control::LiveControlHooks for UnreachableCarrierHooks {
    async fn pause(&self) -> Result<(), odin_domain::huginn::LiveError> {
        panic!("cancelled handshake has no actor")
    }
    async fn resume(&self) -> Result<(), odin_domain::huginn::LiveError> {
        panic!("cancelled handshake has no actor")
    }
    async fn rehome(&self, _: &odin_domain::NodeId) -> Result<(), odin_domain::huginn::LiveError> {
        panic!("cancelled handshake has no actor")
    }
    async fn decide_approval(
        &self,
        _: &odin_domain::ApprovalId,
        _: u64,
        _: odin_domain::huginn::ApprovalDecision,
    ) -> Result<(), odin_domain::huginn::LiveError> {
        panic!("cancelled handshake has no actor")
    }
}

#[async_trait]
impl crate::live::supervisor::BridgeRuntimeFactory for CarrierRuntimeFactory {
    async fn build(
        &self,
        _: &odin_domain::huginn::SessionManifest,
        _: bool,
    ) -> Result<
        (
            OmpBridgeConfig,
            Arc<dyn crate::live::control::LiveControlHooks>,
            Option<Arc<crate::live::zellij::ZellijLiveAdapter>>,
        ),
        odin_domain::huginn::LiveError,
    > {
        Ok((
            self.0.lock().take().expect("one launch"),
            Arc::new(UnreachableCarrierHooks),
            None,
        ))
    }
}

#[tokio::test]
async fn cancelled_real_carrier_handshake_retains_authority_until_owned_stop() {
    use crate::live::supervisor::{LiveBridgeLauncher, LiveSeatBinding, LiveSupervisor};
    use odin_domain::huginn::{LiveError, LiveLaunchOption, OpenSessionRequest};

    let root = tempfile::tempdir().unwrap();
    let context = fixture_context(root.path(), 15, "held-carrier-cancellation").await;
    let spec = remote_spec(&case_launcher(&context), root.path().to_path_buf());
    let carrier = Arc::new(HeldCarrier {
        transport: FakeRemoteTransport::new(spec.clone(), None),
        stdin: Arc::new(parking_lot::Mutex::new(None)),
        exit: parking_lot::Mutex::new(None),
        ready: tokio::sync::Notify::new(),
        held_stdout: parking_lot::Mutex::new(None),
    });
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.process = spec;
    config.transport = Some(carrier.clone());
    let launcher = Arc::new(LiveBridgeLauncher::new(Arc::new(CarrierRuntimeFactory(
        parking_lot::Mutex::new(Some(config)),
    ))));
    let ledger = Arc::new(
        crate::live::ledger::fs::FsLiveLedger::open(root.path().join("live-ledger")).unwrap(),
    );
    let supervisor = LiveSupervisor::new(ledger, launcher, 2, None);
    let request: OpenSessionRequest = serde_json::from_value(serde_json::json!({
        "commandId":"held-carrier-cancellation", "seatId":"architect",
        "sliceId":"architect-engine", "projectId":"odin", "provider":"openai-codex",
        "model":"gpt-6-astra", "title":null, "targetNode":"laptop",
        "openTab":false, "initialPrompt":null
    }))
    .unwrap();
    let option: LiveLaunchOption = serde_json::from_value(serde_json::json!({
        "provider":"openai-codex", "model":"gpt-6-astra",
        "skeletonRef":"omp", "containerId":"omp"
    }))
    .unwrap();
    supervisor
        .bind(LiveSeatBinding {
            seat_id: request.seat_id.clone(),
            slice_id: request.slice_id.clone(),
            display_name: "Architect".to_owned(),
            launch_options: vec![option],
            allowed_nodes: vec![request.target_node.clone()],
            max_sessions: 2,
            turn_budget: None,
        })
        .await
        .unwrap();
    let (cancel, cancellation) = tokio::sync::watch::channel(false);
    let open = tokio::spawn(async move { supervisor.open_owned(request, cancellation).await });
    tokio::time::timeout(Duration::from_secs(5), carrier.ready.notified())
        .await
        .unwrap();
    assert!(!open.is_finished(), "real handshake is held");
    assert!(!carrier.exit.lock().as_ref().unwrap().is_finished());
    cancel.send(true).unwrap();
    let (result, retain_authority) = tokio::time::timeout(Duration::from_secs(5), open)
        .await
        .unwrap()
        .unwrap();

    // Reap the worker explicitly; a launcher JoinError does not establish child exit.
    let still_running = !carrier.exit.lock().as_ref().unwrap().is_finished();
    carrier.stdin.lock().take().unwrap().shutdown().unwrap();
    let worker = carrier.exit.lock().take().unwrap();
    let exit = tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap();
    carrier.held_stdout.lock().take();
    assert!(
        matches!(result, Err(LiveError::Unavailable { code }) if code == "open_launcher_join_failed")
    );
    assert!(
        retain_authority,
        "unknown carrier stop cannot release authority"
    );
    assert!(
        still_running,
        "cancelled launcher did not terminate the real carrier"
    );
    assert!(exit.clean, "test owner observed actual EOF exit: {exit:?}");
}
