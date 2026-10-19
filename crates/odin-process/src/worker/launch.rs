//! Keep the payload parked until the kernel persists its systemd scope identity.

use std::ffi::OsString;
use std::io::Write as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::worker::InvocationId;
use odin_types::WorkerId;
use rustix::rand::getrandom;

use super::bootstrap::{
    bootstrap_arg_var, bus_mask_path, strip_bus_authority, BOOTSTRAP_ACTIVE_VAR,
    BOOTSTRAP_ARGC_VAR, BOOTSTRAP_GATE_VAR, BOOTSTRAP_MASK_VAR, BOOTSTRAP_PAYLOAD_VAR,
    BOOTSTRAP_VAR, BUS_ADDRESS_VAR, UNSHARE_VAR,
};
use super::identity::{leader_pidfd, process_cgroup_line, prove_cgroup_membership};
use super::stop::REAP_POLL;
use super::{WorkerAuthority, WorkerError, WorkerErrorCode};
use crate::identity::read_process_identity;
use crate::systemd::{self, values, BusAddress, ManagerClient, Value};
use crate::CommandSpec;

/// Explicit paths prevent launch from discovering a different bus or executable.
#[derive(Clone, Debug)]
pub struct WorkerChannel {
    bus: BusAddress,
    bootstrap: PathBuf,
    unshare: PathBuf,
    cgroup_root: PathBuf,
    // Production helper binaries need no prefix. Tests set a libtest filter
    // here so the re-executed test harness enters the same bootstrap function.
    bootstrap_args: Vec<OsString>,
    /// Explicit owner-private runtime root for this channel's payload
    /// gates. `None` resolves `XDG_RUNTIME_DIR` at launch (production);
    /// test fixtures pin a per-fixture directory so their gates never
    /// share a namespace a daemon unit manages via `RuntimeDirectory=`.
    gate_runtime_root: Option<PathBuf>,
}

impl WorkerChannel {
    pub fn new(bus: BusAddress, bootstrap: PathBuf, unshare: PathBuf) -> Result<Self, WorkerError> {
        for (role, path) in [("bootstrap", &bootstrap), ("unshare", &unshare)] {
            if path.as_os_str().is_empty() {
                return Err(WorkerError::new(
                    WorkerErrorCode::ChannelInvalid,
                    format!("{role} program path must not be empty"),
                ));
            }
            if !path.is_absolute() {
                return Err(WorkerError::new(
                    WorkerErrorCode::ChannelInvalid,
                    format!("{role} program path {} must be absolute", path.display()),
                ));
            }
        }
        Ok(Self {
            bus,
            bootstrap,
            unshare,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            bootstrap_args: Vec::new(),
            gate_runtime_root: None,
        })
    }

    /// Recovery needs no executables; launch methods reject this channel.
    pub fn for_recovery(bus: BusAddress) -> Result<Self, WorkerError> {
        Ok(Self {
            bus,
            bootstrap: PathBuf::new(),
            unshare: PathBuf::new(),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            bootstrap_args: Vec::new(),
            gate_runtime_root: None,
        })
    }

    /// Pins an explicit owner-private runtime root for this channel's
    /// payload gates. Production callers leave this unset and the launch
    /// resolves `XDG_RUNTIME_DIR`; isolated test fixtures pin a
    /// per-fixture directory so a daemon unit's `RuntimeDirectory=`
    /// cleanup can never unlink their live gates.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_gate_runtime_root(mut self, root: PathBuf) -> Self {
        self.gate_runtime_root = Some(root);
        self
    }

    pub(super) fn gate_runtime_root(&self) -> Option<&Path> {
        self.gate_runtime_root.as_deref()
    }

    /// Require configured bus, bootstrap, and unshare paths rather than discovering defaults.
    pub fn from_registered_env() -> Result<Self, WorkerError> {
        let missing = |name: &str| {
            WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                format!("registered worker channel variable {name} is not set"),
            )
        };
        let bus_raw = std::env::var(BUS_ADDRESS_VAR).map_err(|_| missing(BUS_ADDRESS_VAR))?;
        let bus = BusAddress::parse(&bus_raw)
            .map_err(|error| WorkerError::new(WorkerErrorCode::ChannelInvalid, error))?;
        let bootstrap =
            PathBuf::from(std::env::var(BOOTSTRAP_VAR).map_err(|_| missing(BOOTSTRAP_VAR))?);
        let unshare = PathBuf::from(std::env::var(UNSHARE_VAR).map_err(|_| missing(UNSHARE_VAR))?);
        Self::new(bus, bootstrap, unshare)
    }

    /// Internal construction seam for the feature-gated registered-worker
    /// fixture. Production constructors continue to pin the live cgroup root
    /// and packaged bootstrap argv.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn for_test_support(
        bus: BusAddress,
        bootstrap: PathBuf,
        unshare: PathBuf,
        cgroup_root: PathBuf,
        bootstrap_args: Vec<OsString>,
    ) -> Result<Self, WorkerError> {
        if cgroup_root.as_os_str().is_empty() || !cgroup_root.is_absolute() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                format!(
                    "worker fixture cgroup root {} must be absolute",
                    cgroup_root.display()
                ),
            ));
        }
        let mut channel = Self::new(bus, bootstrap, unshare)?;
        channel.cgroup_root = cgroup_root;
        channel.bootstrap_args = bootstrap_args;
        Ok(channel)
    }

    pub fn bus(&self) -> &BusAddress {
        &self.bus
    }

    pub fn bootstrap(&self) -> &Path {
        &self.bootstrap
    }

    pub fn unshare(&self) -> &Path {
        &self.unshare
    }

    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    pub(super) fn bootstrap_args(&self) -> &[OsString] {
        &self.bootstrap_args
    }
}

/// This type is not wire-decodable so callers cannot select the network-enabled launch path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredServiceBinding {
    canonical_executable: PathBuf,
    compiled_binding_blake3: String,
}

impl RegisteredServiceBinding {
    /// Recheck the configured executable at spawn so caller input cannot enable networking.
    pub fn new(
        canonical_executable: PathBuf,
        compiled_binding_blake3: impl Into<String>,
    ) -> Result<Self, WorkerError> {
        if !canonical_executable.is_absolute() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "registered service executable must be an absolute canonical path",
            ));
        }
        let digest = compiled_binding_blake3.into();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "registered service binding digest must be 64 lowercase hex characters",
            ));
        }
        let metadata = std::fs::metadata(&canonical_executable).map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                format!(
                    "registered service executable {} is unreadable: {error}",
                    canonical_executable.display()
                ),
            )
        })?;
        if !metadata.is_file() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                format!(
                    "registered service executable {} is not a file",
                    canonical_executable.display()
                ),
            ));
        }
        Ok(Self {
            canonical_executable,
            compiled_binding_blake3: digest,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.canonical_executable
    }

    pub fn compiled_binding_blake3(&self) -> &str {
        &self.compiled_binding_blake3
    }
}

/// The worker-id suffix distinguishes concurrent attempts within the transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerNaming {
    pub tx_id: String,
    pub wp_id: String,
    pub attempt: u32,
    pub worker_id: WorkerId,
}

impl WorkerNaming {
    /// Names must be safe IDs because they become systemd unit-name components.
    pub fn new(
        tx_id: impl Into<String>,
        wp_id: impl Into<String>,
        attempt: u32,
        worker_id: WorkerId,
    ) -> Result<Self, WorkerError> {
        let tx_id = tx_id.into();
        let wp_id = wp_id.into();
        for (role, value) in [("tx_id", &tx_id), ("wp_id", &wp_id)] {
            if value.is_empty() {
                return Err(WorkerError::new(
                    WorkerErrorCode::ChannelInvalid,
                    format!("{role} must not be empty"),
                ));
            }
            if !value.chars().all(odin_types::ids::is_safe) {
                return Err(WorkerError::new(
                    WorkerErrorCode::ChannelInvalid,
                    format!("{role} {value:?} must use the safe identifier charset"),
                ));
            }
        }
        Ok(Self {
            tx_id,
            wp_id,
            attempt,
            worker_id,
        })
    }

    pub fn unit(&self) -> String {
        let suffix: String = self.worker_id.as_str().chars().take(8).collect();
        systemd::compose_scope_unit_name(&self.tx_id, &self.wp_id, self.attempt, &suffix)
    }
}

pub fn mint_worker_id() -> Result<WorkerId, WorkerError> {
    let mut bytes = [0_u8; 16];
    getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty()).map_err(|error| {
        WorkerError::new(WorkerErrorCode::Io, format!("getrandom failed: {error}"))
    })?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    WorkerId::new(&hex).map_err(|error| {
        WorkerError::new(WorkerErrorCode::Io, format!("worker id rejected: {error}"))
    })
}

/// `OwnerUnit` follows its owner's lifetime without an independent timer that could kill a live service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeLifetime {
    OwnerUnit,
    Bounded(Duration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeLimits {
    pub lifetime: ScopeLifetime,
    pub timeout_stop: Duration,
    pub memory_high: Option<u64>,
    pub memory_max: Option<u64>,
    pub tasks_max: Option<u64>,
}

impl Default for ScopeLimits {
    fn default() -> Self {
        Self {
            lifetime: ScopeLifetime::Bounded(Duration::from_secs(600)),
            timeout_stop: Duration::from_secs(2),
            memory_high: None,
            memory_max: None,
            tasks_max: None,
        }
    }
}

/// Capture identity before releasing the payload so it can be persisted before execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerIdentity {
    pub worker_id: WorkerId,
    pub unit: String,
    pub invocation_id: InvocationId,
    pub cgroup_path: String,
    pub cgroup_inode: u64,
    pub leader_pid: u32,
    pub leader_start_ticks: u64,
}

impl WorkerAuthority {
    /// Test-only spawn convenience for the process unit contracts and the
    /// cfg(test) channel transport. Production launch goes through the
    /// kernel authority, which persists the worker intent and scope proof
    /// before release.
    #[cfg(test)]
    pub(crate) fn spawn(
        channel: &WorkerChannel,
        naming: WorkerNaming,
        spec: &CommandSpec,
        scope_limits: ScopeLimits,
    ) -> Result<Self, WorkerError> {
        let mut authority = Self::prepare(channel, naming, spec, scope_limits)?;
        authority.release_payload()?;
        authority.close_stdin()?;
        Ok(authority)
    }

    /// The kernel must persist the returned identity before releasing the payload gate.
    pub fn prepare(
        channel: &WorkerChannel,
        naming: WorkerNaming,
        spec: &CommandSpec,
        scope_limits: ScopeLimits,
    ) -> Result<Self, WorkerError> {
        Self::prepare_inner(channel, naming, spec, scope_limits, true)
    }

    /// Only a configured executable binding permits a worker to retain networking.
    pub fn prepare_registered_service(
        channel: &WorkerChannel,
        naming: WorkerNaming,
        spec: &CommandSpec,
        scope_limits: ScopeLimits,
        binding: &RegisteredServiceBinding,
    ) -> Result<Self, WorkerError> {
        if spec.argv.executable() != binding.executable().as_os_str() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                format!(
                    "registered service executable {:?} does not match compiled binding {}",
                    spec.argv.executable(),
                    binding.executable().display()
                ),
            ));
        }
        Self::prepare_inner(channel, naming, spec, scope_limits, false)
    }

    fn prepare_inner(
        channel: &WorkerChannel,
        naming: WorkerNaming,
        spec: &CommandSpec,
        scope_limits: ScopeLimits,
        isolate_network: bool,
    ) -> Result<Self, WorkerError> {
        if channel.bootstrap().as_os_str().is_empty() || channel.unshare().as_os_str().is_empty() {
            return Err(WorkerError::new(
                WorkerErrorCode::ChannelInvalid,
                "a recovery-only worker channel cannot spawn processes",
            ));
        }
        if !spec.current_dir.is_absolute() {
            return Err(WorkerError::new(
                WorkerErrorCode::Spawn,
                "worker current_dir must be absolute",
            ));
        }
        let unit = naming.unit();
        let worker_id = naming.worker_id.clone();
        let environment = strip_bus_authority(&spec.environment);
        let correlation = correlation_of(spec);
        let mask_path = bus_mask_path(channel.bus().socket_path())?;
        let (listener, gate_root, gate_path) = create_payload_gate(channel, &worker_id)?;

        // A separate gate leaves stdin available for payload input after registration.
        let mut command = Command::new(channel.unshare());
        // Preserve the caller UID because Chromium rejects namespace-root browsers.
        command.args(["--user", "--map-current-user", "--keep-caps", "--mount"]);
        if isolate_network {
            command.arg("--net");
        }
        command
            .arg(channel.bootstrap())
            .args(channel.bootstrap_args())
            .current_dir(&spec.current_dir)
            .env_clear()
            .envs(environment.iter())
            .env(BOOTSTRAP_ACTIVE_VAR, "1")
            .env(BOOTSTRAP_MASK_VAR, &mask_path)
            .env(BOOTSTRAP_GATE_VAR, &gate_path)
            .env(BOOTSTRAP_PAYLOAD_VAR, spec.argv.executable())
            .env(BOOTSTRAP_ARGC_VAR, spec.argv.arguments().len().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (index, argument) in spec.argv.arguments().iter().enumerate() {
            command.env(bootstrap_arg_var(index), argument);
        }
        let mut leader = match command.spawn() {
            Ok(leader) => leader,
            Err(error) => {
                cleanup_payload_gate(&gate_root, &gate_path);
                return Err(WorkerError::new(
                    WorkerErrorCode::Spawn,
                    format!("cannot spawn worker bootstrap: {error}"),
                ));
            }
        };
        // Retain launch details to distinguish a slow helper from one that exited before connecting.
        let helper_probe = format!(
            "{:?} ({} argv)",
            channel.bootstrap(),
            channel.bootstrap_args().len()
        );
        let gate = match accept_payload_gate(&listener, &mut leader, &gate_path, &helper_probe) {
            Ok(gate) => gate,
            Err(error) => {
                cleanup_payload_gate(&gate_root, &gate_path);
                let _ = leader.kill();
                // A nonblocking drain cannot hang on stderr held open by a surviving descendant.
                let reaped = leader.wait().ok();
                let stderr_detail = match leader.stderr.take() {
                    Some(mut stderr) => crate::runner::set_nonblocking(&stderr)
                        .ok()
                        .and_then(|()| {
                            let mut collector = crate::output::OutputCollector::new(4096);
                            match collector.drain(&mut stderr) {
                                Ok(()) => Some(collector.finish()),
                                Err(_) => None,
                            }
                        })
                        .filter(|captured| !captured.as_bytes().is_empty())
                        .map(|captured| {
                            String::from_utf8_lossy(captured.as_bytes())
                                .trim()
                                .to_owned()
                        }),
                    None => None,
                };
                let mut merged = error.to_string();
                if let Some(status) = reaped {
                    merged.push_str(&format!("; helper exit: {status}"));
                }
                if let Some(detail) = stderr_detail {
                    merged.push_str("; bootstrap stderr: ");
                    merged.push_str(&detail);
                }
                return Err(WorkerError::new(error.code(), merged));
            }
        };
        cleanup_payload_gate(&gate_root, &gate_path);
        let leader_pid = leader.id();
        let leader_pidfd = match leader_pidfd(leader_pid) {
            Ok(pidfd) => pidfd,
            Err(error) => {
                let _ = leader.kill();
                let _ = leader.wait();
                return Err(error);
            }
        };

        let prepared =
            Self::prove_scope(channel, naming, &unit, worker_id, &scope_limits, leader_pid);
        match prepared {
            Ok(identity) => Ok(Self {
                channel: channel.clone(),
                identity,
                correlation,
                stdin_serial: Arc::new(Mutex::new(())),
                leader: Some(leader),
                leader_pidfd: Some(leader_pidfd),
                payload_gate: Some(gate),
                payload_released: false,
                recovered: false,
                exited: false,
                stopped: false,
                abandoned: false,
                abandonment: None,
            }),
            Err(error) => {
                drop(gate);
                if let Ok(mut client) = ManagerClient::connect(channel.bus()) {
                    let _ = client.stop_unit(&unit, "replace");
                }
                let _ = leader.kill();
                let _ = leader.wait();
                Err(error)
            }
        }
    }

    fn prove_scope(
        channel: &WorkerChannel,
        naming: WorkerNaming,
        unit: &str,
        worker_id: WorkerId,
        scope_limits: &ScopeLimits,
        leader_pid: u32,
    ) -> Result<WorkerIdentity, WorkerError> {
        let timeout_stop_usec = duration_usec(scope_limits.timeout_stop, "timeout_stop")?;
        let mut client = ManagerClient::connect(channel.bus())?;
        let mut properties: Vec<(&'static str, Value)> = vec![
            ("PIDs", values::pids(&[leader_pid])),
            ("KillMode", values::kill_mode_control_group()),
            ("Delegate", values::delegate_false()),
            (
                "Description",
                Value::String(format!(
                    "Odin worker {} {} attempt {}",
                    naming.tx_id, naming.wp_id, naming.attempt
                )),
            ),
        ];
        if let Some(memory_high) = scope_limits.memory_high {
            properties.push(("MemoryHigh", Value::Uint64(memory_high)));
        }
        if let Some(memory_max) = scope_limits.memory_max {
            properties.push(("MemoryMax", Value::Uint64(memory_max)));
        }
        if let Some(tasks_max) = scope_limits.tasks_max {
            properties.push(("TasksMax", Value::Uint64(tasks_max)));
        }
        push_lifetime_properties(&mut client, scope_limits, &mut properties)?;
        properties.push(("TimeoutStopUSec", Value::Uint64(timeout_stop_usec)));
        let start_job = client.start_transient_unit(unit, &properties)?;

        // Scopes have no Service.MainPID, so validate the retained leader against cgroup membership.
        let state = wait_scope_active(&mut client, unit, Some(&start_job))?;
        let id = property_string(&state, "Id", unit)?;
        if id != unit {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("manager returned scope id {id:?}, expected {unit:?}"),
            ));
        }
        let invocation_id = invocation_from_properties(&state, unit)?;
        let kill_mode = property_string(&state, "KillMode", unit)?;
        if kill_mode != systemd::KILL_MODE_CONTROL_GROUP {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("scope {unit} KillMode is {kill_mode:?}, not control-group"),
            ));
        }
        let delegate = property_bool(&state, "Delegate", unit)?;
        if delegate {
            return Err(WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("scope {unit} is delegated; owned workers are never delegated"),
            ));
        }
        let cgroup_path = property_string(&state, "ControlGroup", unit)?;
        let cgroup_inode = prove_cgroup_membership(channel, &cgroup_path, unit, leader_pid)?;
        let identity = read_process_identity(leader_pid).ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::IdentityProof,
                format!("cannot read /proc identity for leader {leader_pid}"),
            )
        })?;

        // Only release the gate after the kernel persists this identity.

        Ok(WorkerIdentity {
            worker_id,
            unit: unit.to_owned(),
            invocation_id,
            cgroup_path,
            cgroup_inode,
            leader_pid,
            leader_start_ticks: identity.start_time_ticks,
        })
    }

    /// Release only after persisting the scope identity; a second release is rejected.
    pub fn release_payload(&mut self) -> Result<(), WorkerError> {
        if self.payload_released {
            return Err(WorkerError::new(
                WorkerErrorCode::PayloadGate,
                "worker payload gate was already released",
            ));
        }
        let mut gate = self.payload_gate.take().ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::PayloadGate,
                "worker payload gate is missing",
            )
        })?;
        gate.write_all(b"\x01").map_err(|error| {
            WorkerError::new(
                WorkerErrorCode::PayloadGate,
                format!("cannot release the payload gate: {error}"),
            )
        })?;
        drop(gate);
        self.payload_released = true;
        Ok(())
    }
}

fn create_payload_gate(
    channel: &WorkerChannel,
    worker_id: &WorkerId,
) -> Result<(UnixListener, PathBuf, PathBuf), WorkerError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    // Production resolves XDG_RUNTIME_DIR per launch; isolated callers (test
    // fixtures) pin an explicit owner-private root so their gates never
    // share a namespace a daemon unit manages via RuntimeDirectory=.
    let runtime_root = match channel.gate_runtime_root() {
        Some(root) => root.to_path_buf(),
        None => std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| {
                WorkerError::new(
                    WorkerErrorCode::Spawn,
                    "XDG_RUNTIME_DIR is required for worker gates",
                )
            })?,
    };
    let metadata = std::fs::symlink_metadata(&runtime_root).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Spawn,
            format!("cannot inspect worker runtime root: {error}"),
        )
    })?;
    if !runtime_root.is_absolute()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(WorkerError::new(
            WorkerErrorCode::Spawn,
            "worker runtime root must be an absolute owner-private directory",
        ));
    }
    let gate_parent = runtime_root.join("odin");
    std::fs::create_dir_all(&gate_parent).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "cannot create odin runtime directory {}: {error}",
                gate_parent.display()
            ),
        )
    })?;
    if let Err(error) =
        std::fs::set_permissions(&gate_parent, std::fs::Permissions::from_mode(0o700))
    {
        return Err(WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "cannot protect odin runtime directory {}: {error}",
                gate_parent.display()
            ),
        ));
    }
    let identity = blake3::hash(worker_id.as_str().as_bytes()).to_hex();
    let root = gate_parent.join(format!(
        ".og-{}-{}",
        std::process::id(),
        &identity.as_str()[..16]
    ));
    let path = root.join("gate.sock");
    if path.as_os_str().as_bytes().len() >= 108 {
        return Err(WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "worker gate socket {} is {} bytes; a Unix socket path must be under 108",
                path.display(),
                path.as_os_str().as_bytes().len()
            ),
        ));
    }
    std::fs::create_dir(&root).map_err(|error| {
        WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "cannot create private worker gate {}: {error}",
                root.display()
            ),
        )
    })?;
    if let Err(error) = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)) {
        let _ = std::fs::remove_dir(&root);
        return Err(WorkerError::new(
            WorkerErrorCode::Spawn,
            format!(
                "cannot protect private worker gate {}: {error}",
                root.display()
            ),
        ));
    }
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = std::fs::remove_dir(&root);
            return Err(WorkerError::new(
                WorkerErrorCode::Spawn,
                format!("cannot bind worker gate {}: {error}", path.display()),
            ));
        }
    };
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(|error| {
        cleanup_payload_gate(&root, &path);
        WorkerError::new(
            WorkerErrorCode::Spawn,
            format!("cannot protect worker gate socket: {error}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|error| {
        cleanup_payload_gate(&root, &path);
        WorkerError::new(
            WorkerErrorCode::Spawn,
            format!("cannot bound worker gate accept: {error}"),
        )
    })?;
    Ok((listener, root, path))
}

fn accept_payload_gate(
    listener: &UnixListener,
    leader: &mut Child,
    gate_path: &Path,
    helper_probe: &str,
) -> Result<UnixStream, WorkerError> {
    const GATE_CONNECT_BACKSTOP: Duration = Duration::from_secs(5);
    let started = Instant::now();
    let deadline = started + GATE_CONNECT_BACKSTOP;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                match leader.try_wait() {
                    Ok(Some(status)) => {
                        return Err(WorkerError::new(
                            WorkerErrorCode::PayloadGate,
                            format!(
                                "worker bootstrap exited (status {status}) before connecting \
                                 to its private gate (leader pid {} after {:?}; helper \
                                 {helper_probe}; gate {} present={})",
                                leader.id(),
                                started.elapsed(),
                                gate_path.display(),
                                gate_path.exists(),
                            ),
                        ))
                    }
                    Ok(None) => {}
                    Err(error) => {
                        return Err(WorkerError::new(
                            WorkerErrorCode::PayloadGate,
                            format!("worker gate accept failed: {error}"),
                        ))
                    }
                }
                if Instant::now() >= deadline {
                    return Err(WorkerError::new(
                        WorkerErrorCode::PayloadGate,
                        format!(
                            "worker bootstrap did not connect to its private gate within \
                             {GATE_CONNECT_BACKSTOP:?} (leader pid {} still alive after \
                             {:?}; helper {helper_probe}; gate {} present={})",
                            leader.id(),
                            started.elapsed(),
                            gate_path.display(),
                            gate_path.exists(),
                        ),
                    ));
                }
                std::thread::sleep(REAP_POLL);
            }
            Err(error) => {
                return Err(WorkerError::new(
                    WorkerErrorCode::PayloadGate,
                    format!("worker gate accept failed: {error}"),
                ));
            }
        }
    }
}

fn cleanup_payload_gate(root: &Path, path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(root);
}

fn correlation_of(spec: &CommandSpec) -> Option<String> {
    spec.environment
        .get(crate::CORRELATION_ENV)
        .map(|value| value.to_string_lossy().into_owned())
}

pub(super) fn duration_usec(duration: Duration, name: &str) -> Result<u64, WorkerError> {
    u64::try_from(duration.as_micros()).map_err(|_| {
        WorkerError::new(
            WorkerErrorCode::ChannelInvalid,
            format!("{name} exceeds systemd's microsecond ceiling"),
        )
    })
}

/// Omit `After=` because owners can launch child scopes synchronously before signaling readiness.
pub(super) fn push_lifetime_properties(
    client: &mut ManagerClient,
    scope_limits: &ScopeLimits,
    properties: &mut Vec<(&'static str, Value)>,
) -> Result<(), WorkerError> {
    match scope_limits.lifetime {
        ScopeLifetime::Bounded(runtime_max) => {
            let runtime_usec = duration_usec(runtime_max, "runtime_max")?;
            if runtime_usec == 0 || runtime_usec == u64::MAX {
                return Err(WorkerError::new(
                    WorkerErrorCode::IdentityProof,
                    "a bounded scope requires a finite, positive microsecond ceiling".to_owned(),
                ));
            }
            properties.push(("RuntimeMaxUSec", Value::Uint64(runtime_usec)));
        }
        ScopeLifetime::OwnerUnit => {
            let owner = prove_owner_unit(client)?;
            properties.push(("BindsTo", values::unit_names(std::slice::from_ref(&owner))));
        }
    }
    Ok(())
}

/// Query the manager so environment variables cannot substitute another owner.
fn prove_owner_unit(client: &mut ManagerClient) -> Result<String, WorkerError> {
    let failure = |detail: String| {
        WorkerError::new(
            WorkerErrorCode::IdentityProof,
            format!("owner unit proof failed: {detail}"),
        )
    };
    let pid = std::process::id();
    let self_cgroup = process_cgroup_line(pid)
        .ok_or_else(|| failure("the launcher cgroup is unreadable".to_owned()))?;
    let by_pid = client
        .get_unit_by_pid(pid)
        .map_err(|error| failure(error.to_string()))?
        .ok_or_else(|| failure("the manager has no unit for the launcher pid".to_owned()))?;
    // ControlGroup is on the concrete Service or Scope interface, not Unit.
    let properties = client
        .ownership_properties(&by_pid)
        .map_err(|error| failure(error.to_string()))?;
    let id = properties
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("the owner unit has no readable Id".to_owned()))?;
    if !matches!(
        properties.get("ActiveState").and_then(Value::as_str),
        Some("activating" | "active" | "reloading")
    ) {
        return Err(failure(
            "the owner unit is not starting or active".to_owned(),
        ));
    }
    if properties.get("ControlGroup").and_then(Value::as_str) != Some(self_cgroup.as_str()) {
        return Err(failure(
            "the owner unit does not contain the launcher cgroup".to_owned(),
        ));
    }
    let invocation =
        invocation_from_properties(&properties, id).map_err(|error| failure(error.to_string()))?;
    let by_invocation = client
        .get_unit_by_invocation(invocation.as_bytes())
        .map_err(|error| failure(error.to_string()))?
        .ok_or_else(|| failure("the owner invocation is no longer present".to_owned()))?;
    // Invocation-addressed aliases can have different object paths for the same unit.
    let incarnation = client
        .unit_properties(&by_invocation, "org.freedesktop.systemd1.Unit")
        .map_err(|error| failure(error.to_string()))?;
    let current = client
        .get_unit_by_pid(pid)
        .map_err(|error| failure(error.to_string()))?;
    if incarnation.get("Id").and_then(Value::as_str) != Some(id)
        || invocation_from_properties(&incarnation, id)
            .map_err(|error| failure(error.to_string()))?
            != invocation
        || current.as_deref() != Some(by_pid.as_str())
    {
        return Err(failure(
            "the launcher owner changed during identity proof".to_owned(),
        ));
    }
    Ok(id.to_owned())
}

pub(super) fn wait_scope_active(
    client: &mut ManagerClient,
    unit: &str,
    start_job: Option<&str>,
) -> Result<std::collections::BTreeMap<String, Value>, WorkerError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(unit_path) = client.get_unit(unit)? {
            let state = client.scope_properties(&unit_path)?;
            let active = property_string(&state, "ActiveState", unit)?;
            match active.as_str() {
                "active" => return Ok(state),
                // StartTransientUnit queues a job, so an inactive unit with that pending job has not failed.
                "inactive"
                    if matches!(
                        state.get("Job"),
                        Some(Value::Struct(fields)) if matches!(fields.as_slice(),
                            [Value::Uint32(id), Value::ObjectPath(path)]
                                if *id != 0 && Some(path.as_str()) == start_job)
                    ) => {}
                "failed" | "inactive" | "deactivating" => {
                    return Err(WorkerError::new(
                        WorkerErrorCode::ScopeRejected,
                        format!("scope {unit} entered {active} before the payload gate"),
                    ));
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(WorkerError::new(
                WorkerErrorCode::ScopeRejected,
                format!("scope {unit} did not become active before the proof deadline"),
            ));
        }
        std::thread::sleep(REAP_POLL);
    }
}

pub(super) fn property_string(
    state: &std::collections::BTreeMap<String, Value>,
    name: &str,
    unit: &str,
) -> Result<String, WorkerError> {
    state
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            WorkerError::new(
                WorkerErrorCode::BusQuery,
                format!("unit {unit} property {name} is missing or not a string"),
            )
        })
}

pub(super) fn property_bool(
    state: &std::collections::BTreeMap<String, Value>,
    name: &str,
    unit: &str,
) -> Result<bool, WorkerError> {
    match state.get(name) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(WorkerError::new(
            WorkerErrorCode::BusQuery,
            format!("scope {unit} property {name} is missing or not a boolean"),
        )),
    }
}

pub(super) fn invocation_from_properties(
    state: &std::collections::BTreeMap<String, Value>,
    unit: &str,
) -> Result<InvocationId, WorkerError> {
    let raw = state.get("InvocationID").ok_or_else(|| {
        WorkerError::new(
            WorkerErrorCode::BusQuery,
            format!("scope {unit} has no InvocationID property"),
        )
    })?;
    let Value::Array(element, bytes) = raw else {
        return Err(WorkerError::new(
            WorkerErrorCode::BusQuery,
            format!("scope {unit} InvocationID is not a byte array"),
        ));
    };
    if element != "y" {
        return Err(WorkerError::new(
            WorkerErrorCode::BusQuery,
            format!("scope {unit} InvocationID does not contain bytes"),
        ));
    }
    if bytes.len() != 16 {
        return Err(WorkerError::new(
            WorkerErrorCode::BusQuery,
            format!("scope {unit} InvocationID is {} bytes, not 16", bytes.len()),
        ));
    }
    let mut decoded = [0_u8; 16];
    for (index, byte) in bytes.iter().enumerate() {
        let Value::Byte(value) = byte else {
            return Err(WorkerError::new(
                WorkerErrorCode::BusQuery,
                format!("scope {unit} InvocationID byte {index} is not a byte"),
            ));
        };
        decoded[index] = *value;
    }
    Ok(InvocationId::from_raw(decoded))
}

#[cfg(test)]
mod gate_isolation_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::test_support::create_fixture_root;

    /// Removes the fixture root on every exit path, panics included: an
    /// assertion failure must never leak the owner-private tree.
    struct OwnedRoot(PathBuf);

    impl Drop for OwnedRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A daemon unit's `RuntimeDirectory=odin` cleanup must never reach a
    /// fixture's gates: the fixture pins an explicit per-fixture runtime
    /// root (0700, owner-private), and deleting/recreating the daemon's
    /// own namespace under the same parent leaves the bound gate socket
    /// present and the handshake readable. Pre-fix (gates inside the
    /// daemon-managed dir) this test fails at the existence assertion and
    /// the connect.
    #[test]
    fn fixture_gate_survives_daemon_runtime_dir_churn() {
        // A compact root: the gate socket path must stay under the
        // 108-byte Unix socket bound, and a long TMPDIR (nix develop)
        // eats most of the margin. The owned root is removed on every
        // exit path, panics included.
        let root = OwnedRoot(create_fixture_root("odin-worker-gates").expect("fixture root"));
        // The daemon-managed namespace and the fixture-private gate root
        // share one parent, exactly like production's runtime dir.
        let daemon_dir = root.0.join("odin");
        std::fs::create_dir(&daemon_dir).expect("daemon namespace");
        let fixture_gates = root.0.join("worker-gates");
        std::fs::create_dir(&fixture_gates).expect("fixture gate root");
        std::fs::set_permissions(&fixture_gates, std::fs::Permissions::from_mode(0o700))
            .expect("fixture gate root 0700");

        let bus_socket = root.0.join("bus.sock");
        let _bus = std::os::unix::net::UnixListener::bind(&bus_socket).expect("bus socket");
        let channel =
            WorkerChannel::for_recovery(BusAddress::unix_socket(bus_socket).expect("bus address"))
                .expect("recovery channel")
                .with_gate_runtime_root(fixture_gates);

        let worker_id = WorkerId::new("0123456789abcdef0123456789abcdef").expect("worker id");
        let (gate_listener, gate_dir, gate_path) =
            create_payload_gate(&channel, &worker_id).expect("gate binds");
        assert!(gate_path.exists(), "the gate socket is bound");
        let gate_mode = std::fs::metadata(&gate_dir)
            .expect("gate dir")
            .permissions()
            .mode();
        assert_eq!(gate_mode & 0o777, 0o700, "the gate dir stays 0700");
        let socket_mode = std::fs::metadata(&gate_path)
            .expect("gate socket")
            .permissions()
            .mode();
        assert_eq!(socket_mode & 0o777, 0o600, "the gate socket stays 0600");

        // The daemon unit stops (RuntimeDirectory= cleanup removes its
        // namespace recursively) and a Restart= unit recreates it:
        std::fs::remove_dir_all(&daemon_dir).expect("daemon cleanup");
        std::fs::create_dir(&daemon_dir).expect("daemon recreation");

        assert!(
            gate_path.exists(),
            "daemon namespace churn must not remove the fixture's gate"
        );
        // The handshake is bounded, the production convention: the child's
        // gate connect is a plain AF_UNIX connect — against a live listener
        // it completes immediately or fails typed, so a vanished socket
        // fails the test instead of hanging — and the gate listener is
        // already nonblocking, so the accept below is deadline-bounded.
        const ACCEPT_BOUND: Duration = Duration::from_secs(5);
        let _client = UnixStream::connect(&gate_path).expect("the gate connects after the churn");
        let deadline = Instant::now() + ACCEPT_BOUND;
        let (_stream, _) = loop {
            match gate_listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "the gate accept did not observe the connection within \
                         {ACCEPT_BOUND:?}"
                    );
                    std::thread::sleep(REAP_POLL);
                }
                Err(error) => panic!("the gate accept failed: {error}"),
            }
        };
    }
}
