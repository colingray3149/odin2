//! Isolated registered-worker fixture for downstream crate tests.
//!
//! This module is compiled only for `odin-process` tests or when a downstream
//! development dependency explicitly enables the `test-support` feature. It
//! exercises the real [`crate::WorkerAuthority`] launch, identity, stop, and
//! recovery paths against a private manager socket and fake cgroup hierarchy;
//! it never mutates process-wide worker-channel environment variables and it
//! never substitutes a direct-spawn authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::systemd::{
    decode_body, marshal_value, parse_message, values, BusAddress, Message, Value,
    MESSAGE_KIND_ERROR, MESSAGE_KIND_METHOD_RETURN,
};
use rustix::process::{
    pidfd_open, pidfd_send_signal, waitid, Pid, PidfdFlags, Signal, WaitId, WaitIdOptions,
};

use crate::identity::read_process_identity;
use crate::worker::{
    bootstrap_run, WorkerChannel, WorkerError, WorkerErrorCode, BOOTSTRAP_ACTIVE_VAR,
};

static NEXT_FIXTURE_ROOT: AtomicU64 = AtomicU64::new(0);

/// Child-only marker the fixture wrapper exports before exec'ing the
/// libtest harness. It never exists in the outer test process, and the
/// helper removes it before the production bootstrap execs the payload.
const STDIO_SWAP_MARKER_VAR: &str = "ODIN_WORKER_FIXTURE_STDIO_SWAPPED";

pub(crate) struct FakeUnit {
    pub(crate) invocation: [u8; 16],
    pub(crate) attached_pid: u32,
    pub(crate) attached_start_ticks: Option<u64>,
    pub(crate) cgroup: String,
    pub(crate) active_state: String,
    pub(crate) sub_state: String,
    pub(crate) kill_mode: String,
    pub(crate) delegate: bool,
    pub(crate) properties: BTreeMap<String, Value>,
}

/// A private-manager retirement boundary; real systemd is never altered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeRetirement {
    Freeze,
    UnitProperties,
    ScopeProperties,
    InactiveProperties,
}

pub(crate) struct FakeConfig {
    pub(crate) fail_queries: bool,
    pub(crate) leak_on_stop: bool,
    /// FreezeUnit fails while the unit stays loaded, as a deactivating scope does.
    pub(crate) freeze_refused: bool,
    pub(crate) retire_next: Option<ScopeRetirement>,
    /// Collected objects can still answer property reads as not-found
    /// placeholders without remaining addressable as live manager units.
    collected_readback: Option<(String, FakeUnit)>,
    /// Models a manager that never attached the registered process: new
    /// scopes get a `cgroup.procs` without the registered PID.
    pub(crate) detach_new_units: bool,
    pub(crate) activate_after_queries: usize,
    /// Every answered manager call after `Hello`, refused ones included, so
    /// a test can prove a cached unit read costs no second query.
    pub(crate) queries: usize,
    pub(crate) cgroup_root: String,
    pub(crate) units: BTreeMap<String, FakeUnit>,
}

/// A private manager endpoint plus its fake cgroup hierarchy.
///
/// The manager implements the exact D-Bus operations used by registered
/// worker launch, proof, stop, and recovery. The returned channel still goes
/// through the production bootstrap, namespace, manager, pidfd, and
/// StopAuthority paths; only the manager and cgroup observations are isolated
/// inside this owned fixture.
pub struct RegisteredWorkerFixture {
    pub(crate) address: BusAddress,
    root: PathBuf,
    cgroup_root: PathBuf,
    /// The fixture's own SHORT owner-private gate runtime root, created
    /// lazily: a gate socket path must stay well under the 108-byte Unix
    /// socket bound, and nesting under the fixture state root (already
    /// long, longer with a long TMPDIR) leaves no margin. Never the
    /// production XDG namespace.
    gate_root: std::sync::OnceLock<PathBuf>,
    /// The fake manager's mutable state. Private: downstream fixtures drive
    /// it only through the preset methods below, never around the D-Bus
    /// surface the production code speaks.
    pub(crate) config: Arc<Mutex<FakeConfig>>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
    delegated: bool,
}

impl RegisteredWorkerFixture {
    /// Starts one isolated manager and private cgroup hierarchy.
    pub fn new() -> Result<Self, WorkerError> {
        let root = create_fixture_root("odin-worker-fixture")?;
        let cgroup_root = root.join("cgroup");
        if let Err(error) = std::fs::create_dir(&cgroup_root) {
            let _ = std::fs::remove_dir_all(&root);
            return Err(fixture_io("cannot create fake cgroup root", error));
        }
        match Self::start_at(root.clone(), cgroup_root.clone()) {
            Ok(fixture) => Ok(fixture),
            Err(error) => {
                let _ = std::fs::remove_dir_all(&root);
                Err(error)
            }
        }
    }

    /// Binds the caller's real systemd user session for delegated
    /// integration: scope creation, broker peer proof, stop, and residue
    /// checks then run through the untouched production worker authority
    /// against the real manager and the real cgroup hierarchy. The fixture
    /// owns only its temporary wrapper root; it never creates, moves, or
    /// removes anything under /sys/fs/cgroup, and a missing session bus is
    /// an honest refusal, never a fallback to the fake manager.
    pub fn new_delegated() -> Result<Self, WorkerError> {
        let uid = std::fs::metadata("/proc/self")
            .map_err(|error| fixture_io("cannot read the fixture uid", error))?
            .uid();
        let bus = PathBuf::from(format!("/run/user/{uid}/bus"));
        if let Err(error) = std::fs::metadata(&bus) {
            return Err(fixture_io(
                &format!(
                    "the delegated registered-worker fixture requires the caller's \
                     systemd user bus at {}",
                    bus.display()
                ),
                error,
            ));
        }
        let address = BusAddress::unix_socket(bus)
            .map_err(|error| WorkerError::new(WorkerErrorCode::ChannelInvalid, error))?;
        let root = create_fixture_root("odin-worker-fixture")?;
        Ok(Self {
            address,
            cgroup_root: root.join("cgroup"),
            gate_root: std::sync::OnceLock::new(),
            config: Arc::new(Mutex::new(FakeConfig {
                fail_queries: false,
                leak_on_stop: false,
                freeze_refused: false,
                retire_next: None,
                collected_readback: None,
                detach_new_units: false,
                activate_after_queries: 0,
                queries: 0,
                cgroup_root: root.to_string_lossy().into_owned(),
                units: BTreeMap::new(),
            })),
            root,
            stop: Arc::new(AtomicBool::new(false)),
            server: None,
            delegated: true,
        })
    }

    /// Builds a registered channel whose bootstrap is a fixture-owned
    /// wrapper that swaps stdout/stderr before exec'ing the current libtest
    /// harness re-entered at one exact helper test. The re-executed harness
    /// would otherwise print its "running 1 test" banner into the worker's
    /// captured stdout frame channel; the wrapper sends it to the
    /// diagnostic stderr instead, and the helper restores the original
    /// stdio pair before the production bootstrap execs the payload. This
    /// is the same mechanism odin-process's own end-to-end worker tests
    /// use, so a focused downstream `cargo test` needs no separately built
    /// helper bin.
    /// The wrapper uses the absolute bash the established worker fixtures
    /// already pin (`/run/current-system/sw/bin/unshare` convention), so it
    /// runs under the worker's cleared environment without PATH discovery.
    pub fn channel_for_harness(
        &self,
        current_exe: &Path,
        exact_test_name: &str,
        unshare: &Path,
    ) -> Result<WorkerChannel, WorkerError> {
        if exact_test_name.is_empty() || exact_test_name.as_bytes().contains(&0) {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "worker fixture bootstrap test name must be nonempty and contain no NUL",
            ));
        }
        let wrapper = self.root.join("worker-bootstrap-stdio-swap.sh");
        let script = format!(
            "#!/run/current-system/sw/bin/bash\n\
             # Generated by odin-process test_support: the dynamic duplicate\n\
             # is closed again immediately, so no descriptor is inherited or\n\
             # leaked. The helper swaps the pair back before the\n\
             # production bootstrap execs the payload.\n\
             set -u\n\
             exec {{odin_tmp_fd}}>&1\n\
             exec 1>&2\n\
             exec 2>&\"$odin_tmp_fd\"\n\
             exec {{odin_tmp_fd}}>&-\n\
             export {STDIO_SWAP_MARKER_VAR}=1\n\
             exec {} --exact {} --test-threads 1 --nocapture\n",
            shell_single_quoted(&current_exe.to_string_lossy()),
            shell_single_quoted(exact_test_name),
        );
        std::fs::write(&wrapper, script)
            .map_err(|error| fixture_io("cannot write fixture bootstrap wrapper", error))?;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                fixture_io(
                    "cannot make the fixture bootstrap wrapper executable",
                    error,
                )
            },
        )?;
        // The gate socket path must stay well under the 108-byte Unix
        // socket bound; the fixture state root (longer with a long TMPDIR)
        // leaves no margin. The fixture pins its own SHORT owner-private
        // root — still per-fixture, still 0700, never the production XDG
        // namespace — so a delegated daemon's RuntimeDirectory= cleanup
        // can never reach fixture gates either.
        let gate_root = match self.gate_root.get() {
            Some(existing) => existing.clone(),
            None => {
                let created = create_fixture_root("odin-worker-gates")?;
                let _ = self.gate_root.set(created.clone());
                let pinned = self.gate_root.get().expect("gate root just set");
                if pinned != &created {
                    let _ = std::fs::remove_dir_all(&created);
                }
                pinned.clone()
            }
        };
        std::fs::set_permissions(&gate_root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| fixture_io("cannot protect fixture gate runtime root", error))?;
        if self.delegated {
            // The real session owns everything else: the channel keeps the
            // production cgroup root and construction path untouched. The
            // gate root is still fixture-private: a delegated daemon's
            // RuntimeDirectory= cleanup must never reach fixture gates.
            return Ok(
                WorkerChannel::new(self.address.clone(), wrapper, unshare.to_path_buf())?
                    .with_gate_runtime_root(gate_root),
            );
        }
        Ok(WorkerChannel::for_test_support(
            self.address.clone(),
            wrapper,
            unshare.to_path_buf(),
            self.cgroup_root.clone(),
            Vec::new(),
        )?
        .with_gate_runtime_root(gate_root))
    }

    fn start_at(root: PathBuf, cgroup_root: PathBuf) -> Result<Self, WorkerError> {
        if !root.is_absolute() || !cgroup_root.is_absolute() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "registered worker fixture roots must be absolute",
            ));
        }
        let socket = root.join("fake-bus.sock");
        let listener = UnixListener::bind(&socket)
            .map_err(|error| fixture_io("cannot bind fake manager socket", error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| fixture_io("cannot make fake manager listener nonblocking", error))?;
        let address = BusAddress::unix_socket(socket)
            .map_err(|error| WorkerError::new(WorkerErrorCode::ChannelInvalid, error))?;
        let invocation = [0xEE; 16];
        let config = Arc::new(Mutex::new(FakeConfig {
            fail_queries: false,
            leak_on_stop: false,
            freeze_refused: false,
            retire_next: None,
            collected_readback: None,
            detach_new_units: false,
            activate_after_queries: 0,
            queries: 0,
            cgroup_root: cgroup_root.to_string_lossy().into_owned(),
            units: BTreeMap::from([(
                "odin-worker-seed.scope".to_owned(),
                FakeUnit {
                    invocation,
                    attached_pid: 0,
                    attached_start_ticks: None,
                    cgroup: cgroup_root.to_string_lossy().into_owned(),
                    active_state: "active".to_owned(),
                    sub_state: "running".to_owned(),
                    kill_mode: "control-group".to_owned(),
                    delegate: false,
                    properties: BTreeMap::new(),
                },
            )]),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let server_config = Arc::clone(&config);
        let server_stop = Arc::clone(&stop);
        let server = std::thread::Builder::new()
            .name("odin-worker-fixture-manager".to_owned())
            .spawn(move || {
                let mut handlers = Vec::new();
                while !server_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let config = Arc::clone(&server_config);
                            if let Ok(handler) = std::thread::Builder::new()
                                .name("odin-worker-fixture-connection".to_owned())
                                .spawn(move || serve_connection(stream, config))
                            {
                                handlers.push(handler);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
                for handler in handlers {
                    let _ = handler.join();
                }
            })
            .map_err(|error| fixture_io("cannot start fake manager server", error))?;
        Ok(Self {
            address,
            root,
            cgroup_root,
            gate_root: std::sync::OnceLock::new(),
            config,
            stop,
            server: Some(server),
            delegated: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn start(cgroup_root: &Path) -> Self {
        std::fs::create_dir_all(cgroup_root).expect("create cgroup fixture");
        let root = create_fixture_root("odin-worker-fake-bus").expect("create fake bus root");
        Self::start_at(root, cgroup_root.to_path_buf()).expect("start fake manager")
    }

    #[cfg(test)]
    pub(crate) fn channel(&self) -> WorkerChannel {
        let current_exe = std::env::current_exe().expect("test harness path");
        self.channel_for_harness(
            &current_exe,
            "worker::tests::bootstrap_test",
            Path::new("/run/current-system/sw/bin/unshare"),
        )
        .expect("fake channel")
    }

    #[cfg(test)]
    pub(crate) fn unit_active(&self, name: &str) -> Option<String> {
        self.config
            .lock()
            .expect("fake config")
            .units
            .get(name)
            .map(|unit| unit.active_state.clone())
    }

    /// Presets one unit's readback state for downstream property-read tests:
    /// the unit answers `LoadUnit`/`GetUnit`, and `Properties.GetAll` serves
    /// `LoadState` and the given active/sub states on the `Unit` interface
    /// and every supplied extra property on the unit type's own interface
    /// (implied by the unit suffix), each exactly as planted.
    pub fn plant_unit(
        &self,
        unit: &str,
        load_state: &str,
        active_state: &str,
        sub_state: &str,
        properties: &[(&str, Value)],
    ) {
        let digest = blake3::hash(unit.as_bytes());
        let mut invocation = [0_u8; 16];
        invocation.copy_from_slice(&digest.as_bytes()[..16]);
        let mut planted =
            BTreeMap::from([("LoadState".to_owned(), Value::String(load_state.to_owned()))]);
        for (key, value) in properties {
            planted.insert((*key).to_owned(), value.clone());
        }
        self.config.lock().expect("fake config").units.insert(
            unit.to_owned(),
            FakeUnit {
                invocation,
                attached_pid: 0,
                attached_start_ticks: None,
                cgroup: String::new(),
                active_state: active_state.to_owned(),
                sub_state: sub_state.to_owned(),
                kill_mode: "control-group".to_owned(),
                delegate: false,
                properties: planted,
            },
        );
    }

    /// Makes every manager call after `Hello` answer with a remote error:
    /// the refused-manager case a caller must report as unreadable, never
    /// paper over.
    pub fn refuse_queries(&self, refuse: bool) {
        self.config.lock().expect("fake config").fail_queries = refuse;
    }

    /// Retires the next private scope at the selected RPC boundary.
    /// The real leader exits first; the caller must still reap it.
    pub fn retire_before_next(&self, boundary: ScopeRetirement) -> Result<(), WorkerError> {
        if self.delegated {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "scope collection injection requires the private manager",
            ));
        }
        self.config
            .lock()
            .map_err(|_| WorkerError::new(WorkerErrorCode::Io, "fixture manager lock poisoned"))?
            .retire_next = Some(boundary);
        Ok(())
    }

    /// How many manager calls (after `Hello`) this fixture has answered,
    /// refused ones included, so a test can prove a second read of the same
    /// unit costs no queries.
    pub fn queries(&self) -> usize {
        self.config.lock().expect("fake config").queries
    }

    /// The registered endpoint a `ManagerClient` connects to.
    pub fn bus(&self) -> &BusAddress {
        &self.address
    }
}

impl Drop for RegisteredWorkerFixture {
    fn drop(&mut self) {
        if self.server.is_some() {
            self.stop.store(true, Ordering::Release);
            // Wake the nonblocking listener promptly if it is between
            // checks; an incomplete connection exits without changing state.
            let BusAddress::UnixSocket(path) = &self.address;
            let _ = UnixStream::connect(path);
            if let Some(server) = self.server.take() {
                let _ = server.join();
            }
        }
        if !self.delegated {
            // Only the fake mode owns a mock hierarchy. The delegated mode
            // borrows the real one and must never remove anything from it.
            let _ = std::fs::remove_dir_all(&self.cgroup_root);
        }
        if let Some(gate_root) = self.gate_root.get() {
            let _ = std::fs::remove_dir_all(gate_root);
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Enters the production bootstrap only in a worker-bootstrap re-execution.
/// Calling this from the ordinary outer test run is a no-op.
pub fn run_bootstrap_if_active() {
    if std::env::var_os(BOOTSTRAP_ACTIVE_VAR).is_none() {
        return;
    }
    if std::env::var_os(STDIO_SWAP_MARKER_VAR).is_some() {
        if !restore_swapped_stdio() {
            std::process::exit(125);
        }
        // Child-only cleanup: the payload exec must not inherit the marker.
        std::env::remove_var(STDIO_SWAP_MARKER_VAR);
    }
    bootstrap_run();
}

/// Swaps the wrapper's stdout/stderr exchange back. After the wrapper,
/// fd 1 holds the worker's diagnostic stderr and fd 2 holds the original
/// stdout frame channel. A safe duplicate of fd 1 is taken first because an
/// in-place exchange would clobber the only copy of the diagnostic stderr.
fn restore_swapped_stdio() -> bool {
    use rustix::stdio::{dup2_stderr, dup2_stdout};
    use std::os::fd::AsFd as _;

    let Ok(saved_diagnostics) = std::io::stdout().as_fd().try_clone_to_owned() else {
        return false;
    };
    if dup2_stdout(std::io::stderr().as_fd()).is_err() {
        return false;
    }
    if dup2_stderr(saved_diagnostics.as_fd()).is_err() {
        return false;
    }
    // Dropping the duplicate closes the temporary descriptor.
    true
}

/// Single-quotes one literal for safe embedding in the generated wrapper.
fn shell_single_quoted(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

pub(crate) fn create_fixture_root(prefix: &str) -> Result<PathBuf, WorkerError> {
    let base = std::env::temp_dir();
    if !base.is_absolute() {
        return Err(WorkerError::new(
            WorkerErrorCode::ChannelInvalid,
            "temporary directory for registered worker fixture must be absolute",
        ));
    }
    for _ in 0..1_024 {
        let sequence = NEXT_FIXTURE_ROOT.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("{prefix}-{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                if let Err(error) =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                {
                    let _ = std::fs::remove_dir(&candidate);
                    return Err(fixture_io("cannot protect fixture root", error));
                }
                return std::fs::canonicalize(&candidate)
                    .map_err(|error| fixture_io("cannot canonicalize fixture root", error));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(fixture_io("cannot create fixture root", error)),
        }
    }
    Err(WorkerError::new(
        WorkerErrorCode::Io,
        "could not reserve a unique registered worker fixture root",
    ))
}

fn fixture_io(action: &str, error: std::io::Error) -> WorkerError {
    WorkerError::new(WorkerErrorCode::Io, format!("{action}: {error}"))
}

fn serve_connection(mut stream: UnixStream, config: Arc<Mutex<FakeConfig>>) {
    // SASL EXTERNAL handshake. Read byte-by-byte so a coalesced BEGIN and
    // first binary message never gets discarded.
    let Some(auth) = fake_read_line(&mut stream) else {
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
    if fake_read_line(&mut stream).as_deref() != Some("BEGIN") {
        return;
    }
    let mut serial = 0_u32;
    loop {
        let mut header = [0_u8; 16];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let fields_len =
            u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as usize;
        let body_start = (16 + fields_len + 7) & !7;
        let body_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let mut message = header.to_vec();
        message.resize(body_start + body_len, 0);
        if stream.read_exact(&mut message[16..]).is_err() {
            return;
        }
        let Ok(request) = parse_message(&message) else {
            return;
        };
        serial += 1;
        let reply = {
            let mut config = config.lock().expect("fake config");
            dispatch(&request, &mut config, serial)
        };
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

fn fake_read_line(stream: &mut UnixStream) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if stream.read_exact(&mut byte).is_err() {
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

fn dispatch(request: &Message, config: &mut FakeConfig, serial: u32) -> Vec<u8> {
    let member = request.member.clone().unwrap_or_default();
    let interface = request.interface.clone().unwrap_or_default();
    if member != "Hello" {
        config.queries = config.queries.saturating_add(1);
    }
    if config.fail_queries && member != "Hello" {
        return error_reply(
            request.serial,
            serial,
            "org.odin.test.QueryUnavailable",
            "the fake manager is unavailable",
        );
    }
    let values_in = match decode_body(request) {
        Ok(values) => values,
        Err(error) => {
            return error_reply(
                request.serial,
                serial,
                "org.odin.test.BadRequest",
                error.to_string(),
            )
        }
    };
    match (interface.as_str(), member.as_str()) {
        ("org.freedesktop.DBus", "Hello") => reply_message(
            request.serial,
            serial,
            "s",
            &[Value::String(":1.fake".to_owned())],
        ),
        ("org.freedesktop.systemd1.Manager", "LoadUnit") => {
            let Some(Value::String(name)) = values_in.first() else {
                return error_reply(request.serial, serial, "org.odin.test.BadRequest", "name");
            };
            if !config.units.contains_key(name.as_str()) {
                // Like the real manager: a unit it cannot find still loads a
                // stub whose readback says `LoadState=not-found`, so a
                // missing unit is an answer, never an unreadable manager.
                let digest = blake3::hash(name.as_bytes());
                let mut invocation = [0_u8; 16];
                invocation.copy_from_slice(&digest.as_bytes()[..16]);
                config.units.insert(
                    name.clone(),
                    FakeUnit {
                        invocation,
                        attached_pid: 0,
                        attached_start_ticks: None,
                        cgroup: String::new(),
                        active_state: "inactive".to_owned(),
                        sub_state: "dead".to_owned(),
                        kill_mode: "control-group".to_owned(),
                        delegate: false,
                        properties: BTreeMap::from([(
                            "LoadState".to_owned(),
                            Value::String("not-found".to_owned()),
                        )]),
                    },
                );
            }
            reply_message(
                request.serial,
                serial,
                "o",
                &[Value::ObjectPath(unit_object_path(name))],
            )
        }
        ("org.freedesktop.systemd1.Manager", "StartTransientUnit") => {
            let Some(Value::String(name)) = values_in.first() else {
                return error_reply(request.serial, serial, "org.odin.test.BadRequest", "name");
            };
            let digest = blake3::hash(name.as_bytes());
            let mut invocation = [0_u8; 16];
            invocation.copy_from_slice(&digest.as_bytes()[..16]);
            let mut unit = FakeUnit {
                invocation,
                attached_pid: 0,
                attached_start_ticks: None,
                cgroup: String::new(),
                active_state: "active".to_owned(),
                sub_state: "running".to_owned(),
                kill_mode: "control-group".to_owned(),
                delegate: false,
                properties: BTreeMap::new(),
            };
            if let Some(Value::Array(_, entries)) = values_in.get(2) {
                for entry in entries {
                    let Value::Struct(pair) = entry else {
                        continue;
                    };
                    let (Value::String(key), Value::Variant(value)) = (&pair[0], &pair[1]) else {
                        continue;
                    };
                    match key.as_str() {
                        "PIDs" => {
                            if let Value::Array(_, pids) = value.as_ref() {
                                if let Some(Value::Uint32(pid)) = pids.first() {
                                    unit.attached_pid = *pid;
                                }
                            }
                        }
                        "KillMode" => {
                            if let Value::String(mode) = value.as_ref() {
                                unit.kill_mode = mode.clone();
                            }
                        }
                        "Delegate" => {
                            if let Value::Bool(delegate) = value.as_ref() {
                                unit.delegate = *delegate;
                            }
                        }
                        other => {
                            unit.properties.insert(other.to_owned(), (**value).clone());
                        }
                    }
                }
            }
            unit.attached_start_ticks =
                read_process_identity(unit.attached_pid).map(|identity| identity.start_time_ticks);
            if config.units.contains_key(name.as_str()) {
                return error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.UnitExists",
                    format!("Unit {name} already exists."),
                );
            }
            let cgroup = format!("/odin-test/{name}");
            let directory = PathBuf::from(&config.cgroup_root).join(cgroup.trim_start_matches('/'));
            // A detached unit models a manager that never moved the registered
            // process into the new scope's cgroup: the membership proof must
            // then fail, never succeed.
            let attached = if config.detach_new_units {
                0
            } else {
                unit.attached_pid
            };
            if std::fs::create_dir_all(&directory).is_err()
                || std::fs::write(directory.join("cgroup.procs"), format!("{attached}\n")).is_err()
            {
                return error_reply(
                    request.serial,
                    serial,
                    "org.odin.test.CgroupFailure",
                    "cannot create fake cgroup",
                );
            }
            unit.cgroup = cgroup;
            config.units.insert(name.clone(), unit);
            reply_message(
                request.serial,
                serial,
                "o",
                &[Value::ObjectPath(unit_object_path(name))],
            )
        }
        ("org.freedesktop.systemd1.Manager", "FreezeUnit" | "ThawUnit") => {
            let Some(Value::String(name)) = values_in.first() else {
                return error_reply(request.serial, serial, "org.odin.test.BadRequest", "name");
            };
            if member == "FreezeUnit" && config.retire_next == Some(ScopeRetirement::Freeze) {
                config.retire_next = None;
                if let Err(error) = collect_fixture_unit(config, name) {
                    return error_reply(
                        request.serial,
                        serial,
                        "org.odin.test.CollectionFailure",
                        error,
                    );
                }
            }
            if member == "FreezeUnit" && config.freeze_refused {
                return error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.UnitNotActive",
                    format!("Unit {name} is deactivating."),
                );
            }
            if !config.units.contains_key(name.as_str()) {
                return error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.NoSuchUnit",
                    format!("Unit {name} not loaded."),
                );
            }
            reply_message(request.serial, serial, "", &[])
        }
        ("org.freedesktop.systemd1.Manager", "StopUnit") => {
            let Some(Value::String(name)) = values_in.first() else {
                return error_reply(request.serial, serial, "org.odin.test.BadRequest", "name");
            };
            if !config.leak_on_stop {
                let cgroup_root = config.cgroup_root.clone();
                if let Some(unit) = config.units.get_mut(name.as_str()) {
                    if let Err(error) = kill_fixture_process_tree(unit) {
                        return error_reply(
                            request.serial,
                            serial,
                            "org.odin.test.CgroupKillFailure",
                            error,
                        );
                    }
                    unit.active_state = "inactive".to_owned();
                    unit.sub_state = "dead".to_owned();
                    let directory =
                        PathBuf::from(cgroup_root).join(unit.cgroup.trim_start_matches('/'));
                    let _ = std::fs::remove_dir_all(directory);
                }
            }
            reply_message(
                request.serial,
                serial,
                "o",
                &[Value::ObjectPath(format!(
                    "/org/freedesktop/systemd1/job/{serial}"
                ))],
            )
        }
        ("org.freedesktop.systemd1.Manager", "GetUnit") => {
            let Some(Value::String(name)) = values_in.first() else {
                return error_reply(request.serial, serial, "org.odin.test.BadRequest", "name");
            };
            if config.units.contains_key(name.as_str()) {
                reply_message(
                    request.serial,
                    serial,
                    "o",
                    &[Value::ObjectPath(unit_object_path(name))],
                )
            } else {
                error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.NoSuchUnit",
                    format!("Unit {name} not loaded."),
                )
            }
        }
        ("org.freedesktop.systemd1.Manager", "GetUnitByInvocationID") => {
            let Some(Value::Array(element, bytes)) = values_in.first() else {
                return error_reply(
                    request.serial,
                    serial,
                    "org.odin.test.BadRequest",
                    "InvocationID",
                );
            };
            let found = config.units.iter().find(|(_, unit)| {
                element == "y"
                    && bytes.len() == unit.invocation.len()
                    && bytes.iter().zip(unit.invocation).all(|(value, expected)| {
                        matches!(value, Value::Byte(actual) if *actual == expected)
                    })
            });
            match found {
                Some((name, _)) => reply_message(
                    request.serial,
                    serial,
                    "o",
                    &[Value::ObjectPath(unit_object_path(name))],
                ),
                None => error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.NoUnitForInvocationID",
                    "No unit has that InvocationID.",
                ),
            }
        }
        ("org.freedesktop.DBus.Properties", "GetAll") => {
            let Some(Value::String(requested)) = values_in.first() else {
                return error_reply(
                    request.serial,
                    serial,
                    "org.odin.test.BadRequest",
                    "interface",
                );
            };
            let name = unit_name_from_path(request.path.as_deref().unwrap_or_default());
            let retire = match config.retire_next {
                Some(ScopeRetirement::UnitProperties | ScopeRetirement::InactiveProperties) => {
                    requested == UNIT_INTERFACE
                }
                Some(ScopeRetirement::ScopeProperties) => requested == SCOPE_INTERFACE,
                _ => false,
            };
            if retire {
                let inactive = config.retire_next == Some(ScopeRetirement::InactiveProperties);
                config.retire_next = None;
                match collect_fixture_unit(config, &name) {
                    Ok(Some((name, mut unit))) => {
                        unit.cgroup.clear();
                        unit.active_state = "inactive".to_owned();
                        unit.sub_state = "dead".to_owned();
                        if inactive {
                            config.units.insert(name, unit);
                        } else {
                            unit.properties.insert(
                                "LoadState".to_owned(),
                                Value::String("not-found".to_owned()),
                            );
                            config.collected_readback = Some((name, unit));
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return error_reply(
                            request.serial,
                            serial,
                            "org.odin.test.CollectionFailure",
                            error,
                        )
                    }
                }
            }
            let activate = if config.activate_after_queries > 0 {
                config.activate_after_queries -= 1;
                config.activate_after_queries == 0
            } else {
                false
            };
            let Some(unit) = config.units.get_mut(&name).or_else(|| {
                config
                    .collected_readback
                    .as_mut()
                    .and_then(|(found, unit)| (found == &name).then_some(unit))
            }) else {
                return error_reply(
                    request.serial,
                    serial,
                    "org.freedesktop.systemd1.NoSuchUnit",
                    format!("Unit {name} not loaded."),
                );
            };
            if activate {
                unit.active_state = "active".to_owned();
            }
            // Real systemd partitions properties per interface: the shared
            // `Unit` interface carries identity and load/active state, the
            // unit type's own interface carries the type-owned properties.
            // One flat dictionary on every interface would let a reader
            // that asks the wrong interface — or never issues the second
            // `GetAll` — pass every behavioral test and break only on a
            // live manager.
            let entries = match (requested.as_str(), unit_type_interface(&name)) {
                (UNIT_INTERFACE, _) => {
                    let mut entries = unit_interface_entries(unit, &name);
                    entries.extend(planted_entries(unit, true));
                    entries
                }
                (SERVICE_INTERFACE, Some(SERVICE_INTERFACE))
                | (SOCKET_INTERFACE, Some(SOCKET_INTERFACE))
                | (SCOPE_INTERFACE, Some(SCOPE_INTERFACE)) => {
                    let mut entries = unit_type_entries(unit);
                    entries.extend(planted_entries(unit, false));
                    entries
                }
                // A type interface the unit's own type does not implement
                // is refused exactly like the real manager refuses it —
                // never answered from another interface's properties.
                (SERVICE_INTERFACE, Some(_))
                | (SOCKET_INTERFACE, Some(_))
                | (SCOPE_INTERFACE, Some(_)) => {
                    return error_reply(
                        request.serial,
                        serial,
                        "org.freedesktop.DBus.Error.UnknownInterface",
                        format!("Unknown interface {requested}."),
                    );
                }
                // Any other interface keeps the flat single-dictionary
                // reply the odin-process scope fixtures were written
                // against: unit state and type properties together.
                _ => {
                    let mut entries = unit_interface_entries(unit, &name);
                    entries.extend(unit_type_entries(unit));
                    entries.extend(planted_entries(unit, true));
                    entries.extend(planted_entries(unit, false));
                    entries
                }
            };
            reply_message(
                request.serial,
                serial,
                "a{sv}",
                &[Value::Array("(sv)".to_owned(), entries)],
            )
        }
        _ => error_reply(
            request.serial,
            serial,
            "org.odin.test.UnknownMethod",
            format!("{interface}.{member}"),
        ),
    }
}

/// Collects an exited private scope at a controlled RPC boundary. The real
/// child is killed and observed exited before the manager reports absence;
/// its owning `Child` still has to be reaped by the stop caller.
fn collect_fixture_unit(
    config: &mut FakeConfig,
    name: &str,
) -> Result<Option<(String, FakeUnit)>, String> {
    let Some(unit) = config.units.get(name) else {
        return Ok(None);
    };
    kill_fixture_process_tree(unit)?;
    let leader = Pid::from_raw(
        i32::try_from(unit.attached_pid)
            .map_err(|error| format!("invalid collected fixture leader PID: {error}"))?,
    )
    .ok_or_else(|| "collected fixture leader PID must be positive".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // A /proc zombie can precede waitability. Observe the completed exit
        // without consuming it: only the authority's Child owns the reap.
        match waitid(
            WaitId::Pid(leader),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(_)) => break,
            Ok(None) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(format!("cannot observe collected fixture leader: {error}")),
        }
        if Instant::now() >= deadline {
            return Err("collected fixture leader did not exit".to_owned());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let directory = PathBuf::from(&config.cgroup_root).join(unit.cgroup.trim_start_matches('/'));
    std::fs::remove_dir_all(directory)
        .map_err(|error| format!("cannot collect private cgroup: {error}"))?;
    Ok(config.units.remove_entry(name))
}

/// Emulates systemd's `KillMode=control-group` inside the fixture without
/// signaling by a caller-supplied PID or process-group name. The manager
/// captured the bootstrap leader's immutable start identity at registration;
/// from that anchor it takes a bounded `/proc` descendant snapshot, opens
/// pidfds for the exact live identities, then kills the leader first so it
/// cannot fork while the retained descendants are killed.
fn kill_fixture_process_tree(unit: &FakeUnit) -> Result<(), String> {
    const PROCESS_SCAN_CAP: usize = 131_072;
    const TREE_CAP: usize = 4_096;

    if unit.attached_pid == 0 {
        return Ok(());
    }
    let Some(expected_start_ticks) = unit.attached_start_ticks else {
        return match read_process_identity(unit.attached_pid) {
            Some(_) => Err(format!(
                "registered leader {} has no captured start identity",
                unit.attached_pid
            )),
            None => Ok(()),
        };
    };
    let Some(root) = read_process_identity(unit.attached_pid) else {
        return Ok(());
    };
    if root.start_time_ticks != expected_start_ticks {
        return Err(format!(
            "registered leader {} changed identity before cgroup kill",
            unit.attached_pid
        ));
    }

    let mut identities = BTreeMap::new();
    let mut children: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    let mut scanned = 0_usize;
    let entries =
        std::fs::read_dir("/proc").map_err(|error| format!("cannot enumerate /proc: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read /proc entry: {error}"))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        scanned += 1;
        if scanned > PROCESS_SCAN_CAP {
            return Err(format!(
                "fixture process scan exceeds {PROCESS_SCAN_CAP} entries"
            ));
        }
        let Some(identity) = read_process_identity(pid) else {
            continue;
        };
        children
            .entry(identity.parent_pid)
            .or_default()
            .insert(identity.pid);
        identities.insert(identity.pid, identity);
    }
    identities.insert(root.pid, root);

    let mut ordered = Vec::new();
    let mut pending = vec![unit.attached_pid];
    let mut visited = BTreeSet::new();
    while let Some(pid) = pending.pop() {
        if !visited.insert(pid) {
            continue;
        }
        if ordered.len() >= TREE_CAP {
            return Err(format!(
                "fixture worker tree rooted at {} exceeds {TREE_CAP} processes",
                unit.attached_pid
            ));
        }
        ordered.push(pid);
        if let Some(descendants) = children.get(&pid) {
            pending.extend(descendants.iter().rev().copied());
        }
    }

    let mut pidfds: Vec<(u32, OwnedFd)> = Vec::with_capacity(ordered.len());
    for pid in ordered {
        let Some(expected) = identities.get(&pid) else {
            continue;
        };
        let Some(live) = read_process_identity(pid) else {
            continue;
        };
        if live.start_time_ticks != expected.start_time_ticks {
            if pid == unit.attached_pid {
                return Err(format!(
                    "registered leader {pid} changed identity during cgroup kill"
                ));
            }
            continue;
        }
        let raw_pid =
            i32::try_from(pid).map_err(|_| format!("fixture descendant PID {pid} is invalid"))?;
        let Some(process) = Pid::from_raw(raw_pid) else {
            return Err(format!("fixture descendant PID {pid} is invalid"));
        };
        match pidfd_open(process, PidfdFlags::empty()) {
            Ok(pidfd) => pidfds.push((pid, pidfd)),
            Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(format!("pidfd_open failed for worker PID {pid}: {error}")),
        }
    }
    for (pid, pidfd) in pidfds {
        match pidfd_send_signal(&pidfd, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => {
                return Err(format!(
                    "pidfd KILL failed for fixture worker PID {pid}: {error}"
                ))
            }
        }
    }
    Ok(())
}

fn unit_object_path(name: &str) -> String {
    format!(
        "/org/freedesktop/systemd1/unit/{}",
        name.replace('.', "_2e")
    )
}

fn unit_name_from_path(path: &str) -> String {
    path.rsplit('/')
        .next()
        .unwrap_or_default()
        .replace("_2e", ".")
}

fn property_entry(key: &str, value: Value) -> Value {
    Value::Struct(vec![
        Value::String(key.to_owned()),
        Value::Variant(Box::new(value)),
    ])
}

/// The interfaces the fake partitions `Properties.GetAll` by — the exact
/// set the real manager serves a loaded unit on.
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const SOCKET_INTERFACE: &str = "org.freedesktop.systemd1.Socket";
const SCOPE_INTERFACE: &str = "org.freedesktop.systemd1.Scope";

/// The unit type's own interface a unit name implies, the partition the
/// real manager serves `GetAll` by. `None` leaves the fake's flat reply in
/// place for that unit (the odin-process scope fixtures' contract).
fn unit_type_interface(name: &str) -> Option<&'static str> {
    if name.ends_with(".service") {
        Some(SERVICE_INTERFACE)
    } else if name.ends_with(".socket") {
        Some(SOCKET_INTERFACE)
    } else if name.ends_with(".scope") {
        Some(SCOPE_INTERFACE)
    } else {
        None
    }
}

/// The identity and state properties the shared
/// `org.freedesktop.systemd1.Unit` interface serves; `LoadState` arrives
/// planted with the unit.
fn unit_interface_entries(unit: &FakeUnit, name: &str) -> Vec<Value> {
    vec![
        property_entry("Id", Value::String(name.to_owned())),
        property_entry(
            "InvocationID",
            if matches!(
                unit.properties.get("LoadState"), Some(Value::String(state)) if state == "not-found"
            ) {
                Value::Array("y".to_owned(), Vec::new())
            } else {
                values::invocation_bytes(&unit.invocation)
            },
        ),
        property_entry("ActiveState", Value::String(unit.active_state.clone())),
        property_entry("SubState", Value::String(unit.sub_state.clone())),
    ]
}

/// The ownership properties the unit type's own interface serves
/// (`ControlGroup`, `KillMode`, `Delegate`), not the shared `Unit` one.
fn unit_type_entries(unit: &FakeUnit) -> Vec<Value> {
    vec![
        property_entry("ControlGroup", Value::String(unit.cgroup.clone())),
        property_entry("KillMode", Value::String(unit.kill_mode.clone())),
        property_entry("Delegate", Value::Bool(unit.delegate)),
    ]
}

/// The planted readback properties, split by the interface that owns them:
/// `LoadState` belongs to the shared `Unit` interface, every other planted
/// property to the unit type's own interface.
fn planted_entries(unit: &FakeUnit, unit_interface: bool) -> Vec<Value> {
    unit.properties
        .iter()
        .filter(|(key, _)| unit_property_is_unit_interface(key) == unit_interface)
        .map(|(key, value)| property_entry(key, value.clone()))
        .collect()
}

fn unit_property_is_unit_interface(key: &str) -> bool {
    matches!(key, "LoadState")
}

fn wire_message(
    kind: u8,
    reply_serial: Option<u32>,
    error_name: Option<&str>,
    serial: u32,
    signature: &str,
    body: &[u8],
) -> Vec<u8> {
    let field = |code: u8, value: Value| {
        Value::Struct(vec![Value::Byte(code), Value::Variant(Box::new(value))])
    };
    let mut fields = Vec::new();
    if let Some(reply_serial) = reply_serial {
        fields.push(field(5, Value::Uint32(reply_serial)));
    }
    if let Some(error_name) = error_name {
        fields.push(field(4, Value::String(error_name.to_owned())));
    }
    if !signature.is_empty() {
        fields.push(field(8, Value::Signature(signature.to_owned())));
    }
    let mut message = vec![b'l', kind, 0, 1];
    message.extend_from_slice(&(body.len() as u32).to_le_bytes());
    message.extend_from_slice(&serial.to_le_bytes());
    marshal_value(&mut message, &Value::Array("(yv)".to_owned(), fields))
        .expect("reply fields marshal");
    while message.len() % 8 != 0 {
        message.push(0);
    }
    message.extend_from_slice(body);
    message
}

fn reply_message(reply_serial: u32, serial: u32, signature: &str, body: &[Value]) -> Vec<u8> {
    let mut encoded = Vec::new();
    for value in body {
        marshal_value(&mut encoded, value).expect("fake reply body");
    }
    wire_message(
        MESSAGE_KIND_METHOD_RETURN,
        Some(reply_serial),
        None,
        serial,
        signature,
        &encoded,
    )
}

fn error_reply(reply_serial: u32, serial: u32, name: &str, text: impl Into<String>) -> Vec<u8> {
    let mut encoded = Vec::new();
    marshal_value(&mut encoded, &Value::String(text.into())).expect("fake error body");
    wire_message(
        MESSAGE_KIND_ERROR,
        Some(reply_serial),
        Some(name),
        serial,
        "s",
        &encoded,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::ManagerClient;

    /// The fake partitions `GetAll` per interface exactly like the real
    /// manager, so a downstream reader that reads a type-owned property
    /// from the `Unit` interface — or stops issuing the second `GetAll` to
    /// the type interface — fails its behavioral tests here, not in
    /// production against a live systemd.
    #[test]
    fn get_all_serves_service_properties_only_on_the_service_interface() {
        let manager = RegisteredWorkerFixture::new().expect("fake manager");
        manager.plant_unit(
            "litellm.service",
            "loaded",
            "active",
            "running",
            &[("MainPID", Value::Uint32(4242))],
        );
        let mut client = ManagerClient::connect(manager.bus()).expect("client connects");
        let path = client.load_unit("litellm.service").expect("the unit loads");

        let unit = client
            .unit_properties(&path, "org.freedesktop.systemd1.Unit")
            .expect("the Unit interface answers");
        assert_eq!(
            unit.get("LoadState").and_then(Value::as_str),
            Some("loaded")
        );
        assert_eq!(
            unit.get("ActiveState").and_then(Value::as_str),
            Some("active")
        );
        assert!(
            !unit.contains_key("MainPID"),
            "MainPID is Service-owned; the Unit interface must not answer it"
        );

        let service = client
            .unit_properties(&path, "org.freedesktop.systemd1.Service")
            .expect("the Service interface answers");
        assert_eq!(service.get("MainPID"), Some(&Value::Uint32(4242)));
        assert!(
            !service.contains_key("LoadState"),
            "LoadState is Unit-owned; the Service interface must not answer it"
        );

        let refused = client
            .unit_properties(&path, "org.freedesktop.systemd1.Socket")
            .expect_err("a service unit does not implement the Socket interface");
        assert!(
            refused
                .to_string()
                .contains("org.freedesktop.DBus.Error.UnknownInterface"),
            "the wrong type interface is refused: {refused}"
        );
    }

    /// The same partition for sockets: `Listen` is served on the `Socket`
    /// interface only, in the real `a(ss)` shape the relay bind proof
    /// parses.
    #[test]
    fn get_all_serves_socket_properties_only_on_the_socket_interface() {
        let manager = RegisteredWorkerFixture::new().expect("fake manager");
        manager.plant_unit(
            "litellm-gateway.socket",
            "loaded",
            "active",
            "running",
            &[(
                "Listen",
                Value::Array(
                    "(ss)".to_owned(),
                    vec![Value::Struct(vec![
                        Value::String("Stream".to_owned()),
                        Value::String("127.0.0.1:4000".to_owned()),
                    ])],
                ),
            )],
        );
        let mut client = ManagerClient::connect(manager.bus()).expect("client connects");
        let path = client
            .load_unit("litellm-gateway.socket")
            .expect("the unit loads");

        let unit = client
            .unit_properties(&path, "org.freedesktop.systemd1.Unit")
            .expect("the Unit interface answers");
        assert_eq!(
            unit.get("LoadState").and_then(Value::as_str),
            Some("loaded")
        );
        assert!(
            !unit.contains_key("Listen"),
            "Listen is Socket-owned; the Unit interface must not answer it"
        );

        let socket = client
            .unit_properties(&path, "org.freedesktop.systemd1.Socket")
            .expect("the Socket interface answers");
        assert_eq!(
            socket.get("Listen"),
            Some(&Value::Array(
                "(ss)".to_owned(),
                vec![Value::Struct(vec![
                    Value::String("Stream".to_owned()),
                    Value::String("127.0.0.1:4000".to_owned()),
                ])],
            ))
        );
    }

    /// The same partition for scopes: `ControlGroup` and `KillMode` are
    /// served on the `Scope` interface only, and a scope never answers
    /// `Service` — so a reader of the wrong interface, or one that
    /// expects the Scope interface to answer for a service, fails here
    /// instead of on a live manager.
    #[test]
    fn get_all_serves_scope_properties_only_on_the_scope_interface() {
        let manager = RegisteredWorkerFixture::new().expect("fake manager");
        manager.config.lock().expect("fake config").units.insert(
            "tx0123456789abcdef-wp-attempt-1-tag.scope".to_owned(),
            FakeUnit {
                invocation: [0x51; 16],
                attached_pid: 0,
                attached_start_ticks: None,
                cgroup: "/odin-test/owned.scope".to_owned(),
                active_state: "active".to_owned(),
                sub_state: "running".to_owned(),
                kill_mode: "control-group".to_owned(),
                delegate: false,
                properties: BTreeMap::new(),
            },
        );
        let mut client = ManagerClient::connect(manager.bus()).expect("client connects");
        let path = client
            .load_unit("tx0123456789abcdef-wp-attempt-1-tag.scope")
            .expect("the unit loads");

        let unit = client
            .unit_properties(&path, "org.freedesktop.systemd1.Unit")
            .expect("the Unit interface answers");
        assert_eq!(
            unit.get("Id").and_then(Value::as_str),
            Some("tx0123456789abcdef-wp-attempt-1-tag.scope")
        );
        assert!(
            !unit.contains_key("ControlGroup"),
            "ControlGroup is Scope-owned; the Unit interface must not answer it"
        );

        let scope = client
            .unit_properties(&path, "org.freedesktop.systemd1.Scope")
            .expect("the Scope interface answers");
        assert_eq!(
            scope.get("ControlGroup"),
            Some(&Value::String("/odin-test/owned.scope".to_owned()))
        );
        assert_eq!(
            scope.get("KillMode"),
            Some(&Value::String("control-group".to_owned()))
        );
        assert!(
            !scope.contains_key("Id"),
            "Id is Unit-owned; the Scope interface must not answer it"
        );

        let refused = client
            .unit_properties(&path, "org.freedesktop.systemd1.Service")
            .expect_err("a scope unit does not implement the Service interface");
        assert!(
            refused
                .to_string()
                .contains("org.freedesktop.DBus.Error.UnknownInterface"),
            "the wrong type interface is refused: {refused}"
        );
    }
}
