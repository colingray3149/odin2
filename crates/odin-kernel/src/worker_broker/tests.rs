use super::dispatch::dispatch;
use super::*;

use odin_domain::{
    StopAudit, StopEvidence, StopResidue, StopResidueProcess, StopVerdictTag,
    WORKER_STOP_EVIDENCE_SCHEMA,
};
use odin_process::{
    marshal_value, mint_worker_id, parse_message, BusAddress, Value, MESSAGE_KIND_ERROR,
    MESSAGE_KIND_METHOD_RETURN,
};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_root(tag: &str) -> PathBuf {
    let serial = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let runtime = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("private test runtime"));
    let root = runtime.join(format!("b-{}-{serial}", std::process::id()));
    std::fs::create_dir(&root).unwrap_or_else(|error| panic!("create test root {tag}: {error}"));
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("test root private");
    root
}

fn private_child(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    std::fs::create_dir(&path).expect("private child created");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("private child mode");
    path
}

fn test_channel() -> WorkerChannel {
    let bus = BusAddress::unix_socket(PathBuf::from("/tmp/odin-broker-test-bus.sock"))
        .expect("test bus address");
    WorkerChannel::for_recovery(bus).expect("recovery channel")
}

fn identity(worker: WorkerId) -> WorkerIdentity {
    let unit = format!("tx-wp-attempt-1-{}.scope", worker.as_str());
    let invocation_id = InvocationId::from_hex(worker.as_str()).expect("minted fixture identity");
    WorkerIdentity {
        worker_id: worker,
        cgroup_path: format!("/user.slice/{unit}"),
        unit,
        invocation_id,
        cgroup_inode: 44,
        leader_pid: 1234,
        leader_start_ticks: 5678,
    }
}

fn record_payload_running(
    owner_store: &Arc<Mutex<Ledger>>,
    identity: &WorkerIdentity,
    correlation: &CorrelationId,
) {
    let invocation = identity.invocation_id.to_hex();
    let mut ledger = owner_store.lock().expect("owner ledger lock");
    ledger
        .with_tx(|tx| {
            let registered = odin_ledger::worker::register_worker(
                tx,
                &odin_ledger::worker::NewWorker {
                    worker_id: identity.worker_id.as_str(),
                    unit: &identity.unit,
                    correlation_id: correlation.as_str(),
                    tx_id: "tx",
                    wp_id: "wp",
                    attempt: 1,
                    now: time::OffsetDateTime::now_utc(),
                },
            )?;
            assert!(matches!(
                registered,
                odin_ledger::worker::RegisterOutcome::Inserted
            ));
            let _ = odin_ledger::worker::record_scope_proof(
                tx,
                identity.worker_id.as_str(),
                &odin_ledger::worker::ScopeProof {
                    invocation_id: &invocation,
                    cgroup_path: &identity.cgroup_path,
                    cgroup_inode: identity.cgroup_inode,
                    leader_pid: identity.leader_pid,
                    leader_start_ticks: identity.leader_start_ticks,
                },
                time::OffsetDateTime::now_utc(),
            )?;
            let _ = odin_ledger::worker::mark_payload_running(
                tx,
                identity.worker_id.as_str(),
                time::OffsetDateTime::now_utc(),
            )?;
            Ok(())
        })
        .expect("durable payload-running row");
}

const TEST_CORRELATION: &str = "00000000000000000000000000000001";

#[allow(clippy::too_many_arguments)]
fn dispatch_request(
    scopes: &SharedScopes,
    claims: &SharedUnitClaims,
    channel: &WorkerChannel,
    storage_root: &Path,
    socket_path: &Path,
    scope_worker: &WorkerId,
    authority: &Arc<StopAuthority>,
    request: BrokerRequest,
) -> Result<(BrokerResponse, Option<(OwnedFd, OwnedFd)>), DispatchError> {
    let reservations = empty_reservations();
    dispatch_request_reservations(
        scopes,
        claims,
        &reservations,
        channel,
        &AllowedParentBindings::default(),
        storage_root,
        socket_path,
        scope_worker,
        authority,
        &AtomicBool::new(false),
        request,
    )
}

fn empty_reservations() -> SharedWorkerReservations {
    Arc::new(Mutex::new(BTreeMap::new()))
}

#[allow(clippy::too_many_arguments)]
fn dispatch_request_reservations(
    scopes: &SharedScopes,
    claims: &SharedUnitClaims,
    reservations: &SharedWorkerReservations,
    channel: &WorkerChannel,
    allowed: &AllowedParentBindings,
    storage_root: &Path,
    socket_path: &Path,
    scope_worker: &WorkerId,
    authority: &Arc<StopAuthority>,
    stopping: &AtomicBool,
    request: BrokerRequest,
) -> Result<(BrokerResponse, Option<(OwnedFd, OwnedFd)>), DispatchError> {
    dispatch(
        scopes,
        claims,
        reservations,
        allowed,
        channel,
        storage_root,
        socket_path,
        scope_worker.as_str(),
        authority,
        stopping,
        request,
    )
}

/// Uses the public wire codec, completes SASL and Hello, then returns injected D-Bus errors.
/// Stop-aware reads let Drop join every handler even when clients remain connected.
struct FakeManagerBus {
    address: BusAddress,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
    handlers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl FakeManagerBus {
    fn start(member_errors: BTreeMap<String, String>) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fake-bus-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&dir).expect("fake bus dir");
        let socket = dir.join("bus.sock");
        let listener = UnixListener::bind(&socket).expect("fake bus bound");
        listener
            .set_nonblocking(true)
            .expect("nonblocking fake bus");
        let stop = Arc::new(AtomicBool::new(false));
        let handlers: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let server_stop = Arc::clone(&stop);
        let server_handlers = Arc::clone(&handlers);
        let server = std::thread::Builder::new()
            .name("fake-manager-bus".to_owned())
            .spawn(move || {
                while !server_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let member_errors = member_errors.clone();
                            let stop = Arc::clone(&server_stop);
                            if let Ok(mut tracked) = server_handlers.lock() {
                                if let Ok(handler) = std::thread::Builder::new()
                                    .name("fake-manager-connection".to_owned())
                                    .spawn(move || fake_bus_serve(stream, &member_errors, &stop))
                                {
                                    tracked.push(handler);
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
            .expect("fake bus thread");
        let address = BusAddress::unix_socket(socket).expect("fake bus address");
        Self {
            address,
            stop,
            server: Some(server),
            handlers,
        }
    }

    fn channel(&self) -> WorkerChannel {
        WorkerChannel::for_recovery(self.address.clone()).expect("fake bus channel")
    }
}

impl Drop for FakeManagerBus {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let BusAddress::UnixSocket(path) = &self.address;
        let _ = UnixStream::connect(path);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        // No new handlers can appear after the accept thread joins; the
        // stop-aware reads guarantee every handler can finish.
        let tracked = self
            .handlers
            .lock()
            .map(|mut handlers| std::mem::take(&mut *handlers))
            .unwrap_or_default();
        for handler in tracked {
            let _ = handler.join();
        }
        let _ = std::fs::remove_file(path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

fn fake_bus_serve(
    mut stream: UnixStream,
    member_errors: &BTreeMap<String, String>,
    stop: &AtomicBool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    // SASL EXTERNAL, byte-by-byte so a coalesced BEGIN is never lost.
    let Some(auth) = fake_bus_line(&mut stream, stop) else {
        return;
    };
    if !auth.contains("AUTH EXTERNAL") {
        return;
    }
    if stream
        .write_all(b"OK 0d0a0d0a0d0a0d0a0d0a0d0a0d0a0d0a\r\n")
        .is_err()
    {
        return;
    }
    if fake_bus_line(&mut stream, stop).as_deref() != Some("BEGIN") {
        return;
    }
    let mut serial = 0_u32;
    loop {
        let mut header = [0_u8; 16];
        if !fake_bus_read_exact(&mut stream, stop, &mut header) {
            return;
        }
        let fields_len =
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
        let body_start = (16 + fields_len + 7) & !7;
        let body_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let mut message = header.to_vec();
        message.resize(body_start + body_len, 0);
        if !fake_bus_read_exact(&mut stream, stop, &mut message[16..]) {
            return;
        }
        let Ok(request) = parse_message(&message) else {
            return;
        };
        serial += 1;
        let member = request.member.as_deref().unwrap_or_default();
        let reply = if member == "Hello" {
            fake_bus_reply(
                MESSAGE_KIND_METHOD_RETURN,
                request.serial,
                serial,
                None,
                "s",
                vec![Value::String(":1.fake".to_owned())],
            )
        } else {
            let error_name = member_errors
                .get(member)
                .cloned()
                .unwrap_or_else(|| "org.odin.test.MemberUnavailable".to_owned());
            fake_bus_reply(
                MESSAGE_KIND_ERROR,
                request.serial,
                serial,
                Some(&error_name),
                "s",
                vec![Value::String("the fake manager refused".to_owned())],
            )
        };
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

/// Fills the buffer or returns false on EOF, error, or shutdown so teardown can join handlers.
fn fake_bus_read_exact(stream: &mut UnixStream, stop: &AtomicBool, buffer: &mut [u8]) -> bool {
    let mut filled = 0;
    while filled < buffer.len() {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return false,
            Ok(read) => filled += read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return false,
        }
    }
    true
}

fn fake_bus_line(stream: &mut UnixStream, stop: &AtomicBool) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if !fake_bus_read_exact(stream, stop, &mut byte) {
            return None;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' && byte[0] != 0 {
            line.push(byte[0]);
        }
        if line.len() > 4096 {
            return None;
        }
    }
    String::from_utf8(line).ok()
}

/// Marshals one reply exactly like `marshal_method_call` frames its
/// fields: fixed 12-byte prefix, the field array at offset 12, 8-byte
/// alignment, then the body.
fn fake_bus_reply(
    kind: u8,
    reply_serial: u32,
    serial: u32,
    error_name: Option<&str>,
    signature: &str,
    body_values: Vec<Value>,
) -> Vec<u8> {
    let mut body = Vec::new();
    for value in &body_values {
        marshal_value(&mut body, value).expect("fake bus body marshals");
    }
    let field = |code: u8, value: Value| {
        Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))])
    };
    let mut fields = vec![field(5, Value::Uint32(reply_serial))];
    if let Some(name) = error_name {
        fields.push(field(4, Value::String(name.to_owned())));
    }
    if !signature.is_empty() {
        fields.push(field(8, Value::Signature(signature.to_owned())));
    }
    let mut message = Vec::new();
    message.extend_from_slice(b"l");
    message.push(kind);
    message.push(0);
    message.push(1);
    message.extend_from_slice(&[0_u8; 4]);
    message.extend_from_slice(&serial.to_le_bytes());
    marshal_value(&mut message, &Value::Array("(yv)".to_owned(), fields))
        .expect("fake bus fields marshal");
    while message.len() % 8 != 0 {
        message.push(0);
    }
    let body_len = (body.len() as u32).to_le_bytes();
    message[4..8].copy_from_slice(&body_len);
    message.extend_from_slice(&body);
    message
}

#[allow(clippy::too_many_arguments)]
fn dispatch_request_with(
    scopes: &SharedScopes,
    claims: &SharedUnitClaims,
    channel: &WorkerChannel,
    allowed: &AllowedParentBindings,
    storage_root: &Path,
    socket_path: &Path,
    scope_worker: &WorkerId,
    authority: &Arc<StopAuthority>,
    stopping: &AtomicBool,
    request: BrokerRequest,
) -> Result<(BrokerResponse, Option<(OwnedFd, OwnedFd)>), DispatchError> {
    let reservations = empty_reservations();
    dispatch_request_reservations(
        scopes,
        claims,
        &reservations,
        channel,
        allowed,
        storage_root,
        socket_path,
        scope_worker,
        authority,
        stopping,
        request,
    )
}

fn correlation() -> CorrelationId {
    CorrelationId::new(TEST_CORRELATION).expect("test correlation")
}

fn stop_audit_evidence(worker: &WorkerId, verdict: StopVerdictTag, failed: bool) -> String {
    let (residue, missing, leader_reaped, descendants, complete) = if failed {
        (
            Some(StopResidue {
                unit_active: true,
                cgroup_present: true,
                processes: vec![StopResidueProcess {
                    pid: 42,
                    start_time_ticks: 99,
                }],
            }),
            None,
            true,
            1,
            true,
        )
    } else {
        (None, None, true, 0, true)
    };
    serde_json::to_string(&StopAudit {
        verdict,
        recovered: false,
        term_sent: false,
        cgroup_kill: false,
        unit_identity_verified: verdict == StopVerdictTag::Stopped,
        residue,
        missing,
        evidence: StopEvidence {
            schema: WORKER_STOP_EVIDENCE_SCHEMA.to_owned(),
            worker_id: worker.as_str().to_owned(),
            unit: format!("tx-wp-attempt-1-{}.scope", worker.as_str()),
            cgroup: format!("/user.slice/{}.scope", worker.as_str()),
            leader_reaped,
            cgroup_descendants: descendants,
            evidence_complete: complete,
            fault_probes: Vec::new(),
        },
        trace: Vec::new(),
    })
    .expect("stop audit serializes")
}

fn record_pending_stop_row(store: &Arc<Mutex<Ledger>>, worker: &WorkerId) {
    let requested = stop_audit_evidence(worker, StopVerdictTag::Requested, false);
    let mut ledger = store.lock().expect("ledger lock");
    ledger
        .with_tx(|tx| {
            let _ = odin_ledger::stop::request_stop(
                tx,
                worker.as_str(),
                TEST_CORRELATION,
                &requested,
                time::OffsetDateTime::now_utc(),
            )?;
            Ok(())
        })
        .expect("pending stop row recorded");
}

/// Records Stopped without residue or Failed with residue, without contacting the manager.
fn record_terminal_stop_row(store: &Arc<Mutex<Ledger>>, worker: &WorkerId, failed: bool) {
    let requested = stop_audit_evidence(worker, StopVerdictTag::Requested, false);
    let terminal = stop_audit_evidence(
        worker,
        if failed {
            StopVerdictTag::Failed
        } else {
            StopVerdictTag::Stopped
        },
        failed,
    );
    let mut ledger = store.lock().expect("ledger lock");
    ledger
        .with_tx(|tx| {
            let _ = odin_ledger::stop::request_stop(
                tx,
                worker.as_str(),
                TEST_CORRELATION,
                &requested,
                time::OffsetDateTime::now_utc(),
            )?;
            let _ = odin_ledger::stop::settle_stop(
                tx,
                worker.as_str(),
                if failed {
                    StopState::Failed
                } else {
                    StopState::Stopped
                },
                &terminal,
                time::OffsetDateTime::now_utc(),
            )?;
            Ok(())
        })
        .expect("terminal stop row recorded");
}

fn activated_scope(
    scopes: &SharedScopes,
    storage: &Path,
    socket: &Path,
    worker: &WorkerId,
    owner_store: &Arc<Mutex<Ledger>>,
    channel: &WorkerChannel,
) -> Arc<StopAuthority> {
    prepare_scope_entry(
        scopes,
        storage,
        socket,
        worker,
        Arc::clone(owner_store),
        None,
        1,
    )
    .expect("scope prepared");
    let scoped_identity = identity(worker.clone());
    record_payload_running(owner_store, &scoped_identity, &correlation());
    activate_scope_entry(scopes, worker, &scoped_identity).expect("scope activated");
    // Cache an authority for the scope's ledger, not the parent's owner store.
    let ledger =
        Ledger::open(storage.join(worker.as_str()).join(SCOPE_LEDGER_NAME)).expect("scope ledger");
    let authority = Arc::new(StopAuthority::new(
        Arc::new(Mutex::new(ledger)),
        channel.clone(),
    ));
    scopes
        .lock()
        .expect("scope table")
        .get_mut(worker.as_str())
        .expect("scope entry")
        .authority = Some(Arc::clone(&authority));
    authority
}

fn launch_request(
    executable: &Path,
    child: &WorkerId,
    profile: BrokerLaunchProfile,
) -> BrokerRequest {
    BrokerRequest::Launch {
        correlation_id: TEST_CORRELATION.to_owned(),
        naming: BrokerNaming {
            tx_id: "tx".to_owned(),
            wp_id: "wp".to_owned(),
            attempt: 1,
            worker_id: child.as_str().to_owned(),
        },
        spec: BrokerSpec {
            argv: vec![executable.as_os_str().as_bytes().to_vec()],
            current_dir: "/".to_owned(),
            environment: vec![BrokerEnvironmentEntry {
                key: CORRELATION_ENV.to_owned(),
                value: TEST_CORRELATION.as_bytes().to_vec(),
            }],
        },
        limits: BrokerLimits {
            runtime_max_millis: std::num::NonZeroU64::new(1_000).expect("positive ceiling"),
            timeout_stop_millis: 1_000,
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        },
        profile,
    }
}

/// Mark settled children terminal so subtree cleanup needs no manager access.
fn record_child_row(store: &Arc<Mutex<Ledger>>, worker: &WorkerId, settled: bool) {
    let mut proof = identity(worker.clone());
    proof.unit = format!("tx-wp-attempt-1-{}.scope", worker.as_str());
    proof.cgroup_path = format!("/odin-broker-fixture/{}", proof.unit);
    proof.invocation_id =
        InvocationId::from_hex(mint_worker_id().expect("invocation nonce").as_str())
            .expect("canonical invocation nonce");
    proof.leader_pid = 2_000_000_000;
    record_payload_running(
        store,
        &proof,
        &CorrelationId::new(TEST_CORRELATION).expect("correlation"),
    );
    if settled {
        store
            .lock()
            .expect("ledger lock")
            .with_tx(|tx| {
                let outcome = odin_ledger::worker::settle_worker(
                    tx,
                    worker.as_str(),
                    WorkerPhase::PayloadRunning,
                    odin_ledger::worker::Settlement::Stopped,
                    "{}",
                    time::OffsetDateTime::now_utc(),
                )?;
                assert!(matches!(
                    outcome,
                    odin_ledger::worker::WorkerTransitionOutcome::Applied
                ));
                Ok(())
            })
            .expect("child settled");
    }
}

fn stop_intent_row(store: &Arc<Mutex<Ledger>>, worker: &WorkerId) -> bool {
    let ledger = store.lock().expect("ledger lock");
    odin_ledger::stop::stop_row(ledger.connection(), worker.as_str())
        .expect("stop row query")
        .is_some()
}

fn nonterminal_ids(ledger: &Ledger) -> Vec<String> {
    odin_ledger::worker::nonterminal_rows(ledger.connection(), None)
        .expect("nonterminal rows")
        .into_iter()
        .map(|row| row.worker_id)
        .collect()
}

/// Build P -> B -> C -> D plus sibling S; manager absence still requires process and cgroup checks.
fn subtree_fixture(tag: &str, chain_settled: bool) -> SubtreeFixture {
    let root = test_root(tag);
    let storage = private_child(&root, "storage");
    let socket = root.join("authority.sock");
    let manager = FakeManagerBus::start(BTreeMap::from([
        (
            "GetUnit".to_owned(),
            "org.freedesktop.systemd1.NoSuchUnit".to_owned(),
        ),
        (
            "GetUnitByInvocationID".to_owned(),
            "org.freedesktop.systemd1.NoUnitForInvocationID".to_owned(),
        ),
    ]));
    let channel = manager.channel();
    let scopes: SharedScopes = Arc::new(Mutex::new(BTreeMap::new()));
    let claims: SharedUnitClaims = Arc::new(Mutex::new(BTreeMap::new()));
    let p_worker = mint_worker_id().expect("caller scope worker");
    let owner_store = Arc::new(Mutex::new(Ledger::open_in_memory().expect("owner ledger")));
    let p_authority = activated_scope(
        &scopes,
        &storage,
        &socket,
        &p_worker,
        &owner_store,
        &channel,
    );
    let p_store = p_authority.store();
    let b_worker = mint_worker_id().expect("host worker");
    record_child_row(&p_store, &b_worker, false);
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        p_worker.as_str(),
        &b_worker,
        Arc::clone(&p_store),
    )
    .expect("host scope");
    let b_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(b_worker.as_str()).join(SCOPE_LEDGER_NAME)).expect("host ledger"),
    ));
    let c_worker = mint_worker_id().expect("nested worker");
    record_child_row(&b_store, &c_worker, chain_settled);
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        b_worker.as_str(),
        &c_worker,
        Arc::clone(&b_store),
    )
    .expect("nested scope");
    let c_store = Arc::new(Mutex::new(
        Ledger::open(storage.join(c_worker.as_str()).join(SCOPE_LEDGER_NAME))
            .expect("nested ledger"),
    ));
    let d_worker = mint_worker_id().expect("leaf worker");
    record_child_row(&c_store, &d_worker, chain_settled);
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        c_worker.as_str(),
        &d_worker,
        Arc::clone(&c_store),
    )
    .expect("leaf scope");
    let s_worker = mint_worker_id().expect("sibling worker");
    record_child_row(&p_store, &s_worker, false);
    prepare_nested_scope(
        &scopes,
        &storage,
        &socket,
        p_worker.as_str(),
        &s_worker,
        Arc::clone(&p_store),
    )
    .expect("sibling scope");
    SubtreeFixture {
        root,
        storage,
        socket,
        channel,
        scopes,
        claims,
        p_worker,
        p_store,
        p_authority,
        b_worker,
        c_worker,
        d_worker,
        s_worker,
        _manager: manager,
    }
}

struct SubtreeFixture {
    root: PathBuf,
    storage: PathBuf,
    socket: PathBuf,
    channel: WorkerChannel,
    scopes: SharedScopes,
    claims: SharedUnitClaims,
    p_worker: WorkerId,
    p_store: Arc<Mutex<Ledger>>,
    p_authority: Arc<StopAuthority>,
    b_worker: WorkerId,
    c_worker: WorkerId,
    d_worker: WorkerId,
    s_worker: WorkerId,
    _manager: FakeManagerBus,
}

mod handoff;
mod identity;
mod launch;
mod scope;
mod stop;
mod wire;
