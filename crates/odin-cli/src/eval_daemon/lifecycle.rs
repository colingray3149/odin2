//! Starts session sidecars and stops their registered workers.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead as _, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use odin_domain::extension_policy::ExtensionPolicyBinding;
use odin_domain::SeatToken;
use odin_huginn::{OdindConfig, RuntimeManifest};
use odin_kernel::{
    AllowedParentBindings, ParentBrokerServer, ParentExecutableBinding, StopAuthority,
};
use odin_process::{BusAddress, WorkerChannel};
use odin_registry::Snapshot;
use odin_sidecar::{Provisioning, SidecarClient};
use odin_types::{CapsuleId, WorkerId};

use crate::eval_protocol::authority_wire_limits;

use super::bindings::{
    decode_ready, sandbox_tool_path, WorkerLaunchSpec, WorkerLauncher, COMMAND_OUTPUT_MAX_BYTES,
    READY_MAX_BYTES, SIDE_CAR_READY_TIMEOUT, SIDE_CAR_REQUESTS, SIDE_CAR_SPEND,
    SIDE_CAR_STATE_BYTES,
};
use super::path_text;
use super::provisioning::{create_private_dir, extension_policy};

const SESSION_SIDE_CAR_RUNTIME: Duration = Duration::from_secs(6 * 3600);

/// The exact private worker-launch surface the per-session authority pool
/// reuses. Construction, storage, and lifecycle rules are identical to the
/// packaged eval path; only ownership moves to the session pool.
pub struct SessionWorkerLauncher {
    inner: WorkerLauncher,
}

impl SessionWorkerLauncher {
    pub fn open(
        config: &OdindConfig,
        manifest: &RuntimeManifest,
        authority_root: &Path,
    ) -> Result<Self, String> {
        Ok(Self {
            inner: WorkerLauncher::open(config, manifest, authority_root)?,
        })
    }

    fn launcher(&self) -> &WorkerLauncher {
        &self.inner
    }
}

/// Writes one session's sidecar extension policy under its private state
/// root with the same publish/verify contract as the packaged path.
pub fn session_extension_policy(
    config: &OdindConfig,
    snapshot: &Snapshot,
    session_state: &Path,
) -> Result<ExtensionPolicyBinding, String> {
    extension_policy(config, snapshot, session_state)
}

pub struct SessionSidecarLifecycle {
    parent_broker: Option<ParentBrokerServer>,
    authority: Arc<StopAuthority>,
    worker_id: Option<WorkerId>,
    socket_root: PathBuf,
    abandoned: bool,
    retirement: Option<Result<(), String>>,
}

impl SessionSidecarLifecycle {
    pub(crate) fn new(
        parent_broker: Option<ParentBrokerServer>,
        authority: Arc<StopAuthority>,
        worker_id: Option<WorkerId>,
        socket_root: PathBuf,
    ) -> Self {
        Self {
            parent_broker,
            authority,
            worker_id,
            socket_root,
            abandoned: false,
            retirement: None,
        }
    }

    pub fn retire_bounded(&mut self, deadline: Instant) -> Result<(), String> {
        if let Some(result) = &self.retirement {
            return result.clone();
        }
        if self.abandoned {
            return Err("session sidecar retirement was abandoned".to_owned());
        }
        self.abandoned = true;
        if Instant::now() >= deadline {
            let result = Err("session sidecar stop budget was already spent".to_owned());
            self.retirement = Some(result.clone());
            self.abandon();
            return result;
        }
        let mut failures = Vec::new();
        if let Some(worker_id) = self.worker_id.clone() {
            let authority = Arc::clone(&self.authority);
            if let Err(error) = bounded_retirement(deadline, move || {
                let outcome = authority
                    .stop_worker_bounded(&worker_id, deadline)
                    .map_err(|error| format!("session sidecar stop failed: {error}"))?;
                if outcome.verdict != odin_domain::StopVerdict::Stopped {
                    return Err(format!(
                        "session sidecar stop returned {:?}",
                        outcome.verdict
                    ));
                }
                Ok(())
            }) {
                failures.push(error);
            }
        }
        if let Some(broker) = &self.parent_broker {
            match broker.shutdown_until(deadline) {
                Ok(summary) if summary.scopes_handed_off == 0 => {}
                Ok(_) => failures.push("session parent broker left a handed-off scope".to_owned()),
                Err(error) => {
                    failures.push(format!("session parent broker shutdown failed: {error}"))
                }
            }
        }
        if failures.is_empty() {
            let socket_root = self.socket_root.clone();
            if let Err(error) = bounded_retirement(deadline, move || {
                fs::remove_file(socket_root.join("authority.sock"))
                    .or_else(|error| {
                        (error.kind() == std::io::ErrorKind::NotFound)
                            .then_some(())
                            .ok_or(error)
                    })
                    .map_err(|error| format!("private sidecar socket cleanup failed: {error}"))?;
                fs::remove_dir(socket_root)
                    .map_err(|error| format!("private sidecar socket root cleanup failed: {error}"))
            }) {
                failures.push(error);
            }
        }
        let result = if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        };
        if result.is_err() {
            self.abandon();
        } else {
            self.worker_id = None;
        }
        self.retirement = Some(result.clone());
        result
    }

    pub fn abandon(&mut self) {
        if let Some(broker) = self.parent_broker.as_ref() {
            broker.abandon();
        }
        self.authority.abandon();
        self.abandoned = true;
    }
}

impl Drop for SessionSidecarLifecycle {
    fn drop(&mut self) {
        if self.abandoned {
            self.abandon();
            return;
        }
        if let Err(error) = self.retire_bounded(Instant::now() + Duration::from_secs(10)) {
            tracing::error!("stop session sidecar failed: {error}");
        }
    }
}

pub(crate) fn bounded_retirement(
    deadline: Instant,
    stop: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    // Spawn failure must not run captured authority destructors on the caller.
    let stop = std::mem::ManuallyDrop::new(stop);
    if Instant::now() >= deadline {
        return Err("session retirement budget was already spent".to_owned());
    }
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    thread::Builder::new()
        .name("session-retirement".to_owned())
        .spawn(move || {
            let stop = std::mem::ManuallyDrop::into_inner(stop);
            let _ = send.send(stop());
        })
        .map_err(|error| format!("session retirement worker failed: {error}"))?;
    receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| format!("wait for session worker stop failed: {error}"))?
}

pub struct SessionSidecarCapsule<'a> {
    pub capsule_id: &'a CapsuleId,
    pub capsule_root: &'a Path,
    pub source_commit: &'a str,
    pub source_kind: &'a str,
    pub projection_path: &'a Path,
    pub extension_policy: &'a ExtensionPolicyBinding,
}

pub struct SessionSidecarRoots<'a> {
    pub socket_root: &'a Path,
    pub session_state: &'a Path,
}

pub fn launch_session_sidecar(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    launcher: &SessionWorkerLauncher,
    capsule: &SessionSidecarCapsule<'_>,
    roots: &SessionSidecarRoots<'_>,
    token: &SeatToken,
    signing_key: &[u8],
) -> Result<(SidecarClient, SessionSidecarLifecycle), String> {
    let &SessionSidecarCapsule {
        capsule_id,
        capsule_root,
        source_commit,
        source_kind,
        projection_path,
        extension_policy,
    } = capsule;
    let &SessionSidecarRoots {
        socket_root,
        session_state,
    } = roots;
    let policy = extension_policy
        .load()
        .map_err(|error| format!("session extension policy rejected: {error}"))?;
    let mut resolved = BTreeMap::new();
    for key in ["odin-effector", "git", "python3", "bun", "bwrap"] {
        resolved.insert(
            key,
            manifest
                .executable(key)
                .map_err(|error| error.to_string())?,
        );
    }
    let sandbox_tool_path = sandbox_tool_path(manifest)?;
    let sandbox_cache_root = session_state.join("sandbox");
    create_private_dir(&sandbox_cache_root)?;
    for directory in ["cargo-home", "target", "home"] {
        create_private_dir(&sandbox_cache_root.join(directory))?;
    }
    let mut args = vec![
        "--state-root".to_owned(),
        path_text(session_state)?,
        "--socket-root".to_owned(),
        path_text(socket_root)?,
        "--capsule-id".to_owned(),
        capsule_id.as_str().to_owned(),
        "--peer-pid".to_owned(),
        std::process::id().to_string(),
        "--extension-policy".to_owned(),
        path_text(&extension_policy.path)?,
        "--extension-policy-digest".to_owned(),
        extension_policy.digest.clone(),
        "--accept-timeout-ms".to_owned(),
        policy.sidecar.accept_timeout_ms.to_string(),
        "--projection-file".to_owned(),
        path_text(projection_path)?,
        "--limits-requests".to_owned(),
        SIDE_CAR_REQUESTS.to_string(),
        "--limits-stops".to_owned(),
        "0".to_owned(),
        "--limits-spend".to_owned(),
        SIDE_CAR_SPEND.to_string(),
        "--max-request-bytes".to_owned(),
        authority_wire_limits().max_request_bytes().to_string(),
        "--max-frame-bytes".to_owned(),
        authority_wire_limits().max_frame_bytes().to_string(),
        "--max-state-bytes".to_owned(),
        SIDE_CAR_STATE_BYTES.to_string(),
        "--effector".to_owned(),
        path_text(&resolved["odin-effector"].path)?,
        "--effector-digest".to_owned(),
        resolved["odin-effector"].digest.clone(),
        "--capsule-root".to_owned(),
        path_text(capsule_root)?,
        "--source-commit".to_owned(),
        source_commit.to_owned(),
        "--source-kind".to_owned(),
        source_kind.to_owned(),
        "--git-bin".to_owned(),
        path_text(&resolved["git"].path)?,
        "--python-bin".to_owned(),
        path_text(&resolved["python3"].path)?,
        "--bun-bin".to_owned(),
        path_text(&resolved["bun"].path)?,
        "--bwrap-bin".to_owned(),
        path_text(&resolved["bwrap"].path)?,
        "--sandbox-cache-root".to_owned(),
        path_text(&sandbox_cache_root)?,
        "--sandbox-tool-path".to_owned(),
        sandbox_tool_path,
    ];
    for (flag, path) in [
        (
            "--sandbox-context-root",
            &config.paths.operator_context_root,
        ),
        ("--cargo-registry-cache", &config.paths.cargo_registry_cache),
        ("--cargo-git-cache", &config.paths.cargo_git_cache),
        ("--nix-config-root", &config.paths.nix_config_root),
    ] {
        if let Some(path) = path {
            args.extend([flag.to_owned(), path_text(path)?]);
        }
    }
    // The sidecar cannot use the manager bus masked by worker isolation.
    // Give it a fresh scoped broker owned by this session's root controller.
    let parent_broker = if launcher.launcher().nested {
        None
    } else {
        Some(session_parent_broker(
            config,
            manifest,
            launcher.launcher(),
            socket_root,
            session_state,
        )?)
    };
    let launch_spec = WorkerLaunchSpec {
        executable_id: "odin-sidecar",
        role: "session-sidecar",
        parent_broker: parent_broker.as_ref(),
        args,
        // The broker needs a private runtime root; do not inherit the host bus environment.
        environment: vec![("XDG_RUNTIME_DIR".to_owned(), path_text(socket_root)?)],
        current_dir: session_state,
        runtime_max: SESSION_SIDE_CAR_RUNTIME,
    };
    let (launch, _) = launcher.launcher().launch(manifest, launch_spec)?;
    let worker_id = launch.identity.worker_id.clone();
    // Own cleanup immediately, including provisioning/readiness failures.
    let lifecycle = SessionSidecarLifecycle::new(
        parent_broker,
        Arc::clone(&launcher.launcher().authority),
        Some(worker_id.clone()),
        socket_root.to_path_buf(),
    );
    let mut provisioning = Vec::new();
    let sealed = Provisioning::new(token.clone(), signing_key.to_vec())
        .map_err(|error| format!("session provisioning rejected: {error}"))?;
    sealed
        .write_to(&mut provisioning)
        .map_err(|error| format!("session provisioning encode failed: {error}"))?;
    if let Err(error) = launcher
        .launcher()
        .authority
        .write_worker_stdin(&worker_id, &provisioning)
    {
        return Err(format!("session provisioning write failed: {error}"));
    }
    launcher
        .launcher()
        .authority
        .close_worker_stdin(&worker_id)
        .map_err(|error| format!("session provisioning close failed: {error}"))?;

    // Forward bounded sidecar diagnostics to the daemon journal.
    let stderr = launch.stderr;
    let worker_label = worker_id.to_string();
    thread::spawn(move || {
        for line in BufReader::new(stderr.take(COMMAND_OUTPUT_MAX_BYTES as u64 + 1))
            .lines()
            .map_while(Result::ok)
        {
            tracing::debug!("session-sidecar worker={worker_label}: {line}");
        }
    });
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let stdout = launch.stdout;
    thread::spawn(move || {
        let mut line = Vec::new();
        let result = BufReader::new(stdout)
            .take(READY_MAX_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map(|_| line);
        let _ = ready_tx.send(result);
    });
    let ready = ready_rx
        .recv_timeout(SIDE_CAR_READY_TIMEOUT)
        .map_err(|error| format!("wait for session sidecar readiness failed: {error}"))?
        .map_err(|error| format!("session sidecar readiness read failed: {error}"))?;
    let ready = decode_ready(&ready)?;
    let expected_socket = socket_root.join("authority.sock");
    if ready.socket_path != expected_socket {
        return Err("session sidecar readiness socket contradicts its socket root".to_owned());
    }
    let client = SidecarClient::connect(&ready.socket_path, authority_wire_limits())
        .map_err(|error| format!("could not connect session sidecar client: {error}"))?;
    Ok((client, lifecycle))
}

fn session_parent_broker(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
    launcher: &WorkerLauncher,
    socket_root: &Path,
    session_state: &Path,
) -> Result<ParentBrokerServer, String> {
    let mut bindings = Vec::new();
    for key in ["odin-effector", "git", "bwrap", "python3", "bun"] {
        let executable = manifest
            .executable(key)
            .map_err(|error| error.to_string())?;
        let digest = executable
            .digest
            .strip_prefix("blake3:")
            .ok_or_else(|| format!("{key} binding is not BLAKE3"))?
            .to_owned();
        let binding = if key == "odin-effector" {
            ParentExecutableBinding::registered_service(executable.path.clone(), digest)
                .and_then(ParentExecutableBinding::with_parent_authority)
        } else {
            ParentExecutableBinding::isolated(executable.path.clone(), digest)
        }
        .map_err(|error| error.to_string())?;
        bindings.push(binding);
    }
    let allowed = AllowedParentBindings::new(bindings).map_err(|error| error.to_string())?;
    let bus = BusAddress::parse(&config.worker_bus).map_err(|error| error.to_string())?;
    let bootstrap = manifest
        .executable("worker_bootstrap")
        .map_err(|error| error.to_string())?;
    let unshare = manifest
        .executable("unshare")
        .map_err(|error| error.to_string())?;
    let channel = WorkerChannel::new(bus, bootstrap.path.clone(), unshare.path.clone())
        .map_err(|error| error.to_string())?;
    let stores = session_state.join("parent-scopes");
    create_private_dir(&stores)?;
    let server = ParentBrokerServer::bind(
        socket_root,
        &stores,
        channel,
        allowed,
        launcher.authority.store(),
    )
    .map_err(|error| format!("session parent broker failed: {error}"))?;
    server
        .start()
        .map_err(|error| format!("session parent broker start failed: {error}"))?;
    Ok(server)
}

#[cfg(test)]
mod abandonment_tests {
    use super::*;
    use odin_kernel::recovery_worker_channel;
    use odin_ledger::Ledger;
    use odin_process::mint_worker_id;
    use std::sync::Mutex;

    #[test]
    fn incomplete_shutdown_preserves_broker_authority_after_lifecycle_drop() {
        assert_retained_after_shutdown(false);
    }

    #[test]
    fn expired_shared_deadline_disarms_lifecycle_and_broker_drop() {
        assert_retained_after_shutdown(true);
    }

    fn assert_retained_after_shutdown(expired: bool) {
        let temporary = tempfile::TempDir::new().expect("probe root");
        let runtime = temporary.path().join("runtime");
        let storage = temporary.path().join("storage");
        let sockets = temporary.path().join("sockets");
        for root in [&runtime, &storage, &sockets] {
            create_private_dir(root).expect("private root");
        }
        // Match the path-based Unix bus address required by recovery channels.
        let channel = recovery_worker_channel("unix:path=/tmp/odin-abandon-probe.sock")
            .expect("worker channel");
        let ledger = Arc::new(Mutex::new(Ledger::open_in_memory().expect("ledger")));
        let broker = ParentBrokerServer::bind(
            &runtime,
            &storage,
            channel.clone(),
            AllowedParentBindings::default(),
            Arc::clone(&ledger),
        )
        .expect("broker");
        let worker = mint_worker_id().expect("worker id");
        broker.prepare_scope(&worker).expect("scope");
        let broker_socket = broker.socket_path().to_path_buf();
        let mut lifecycle = SessionSidecarLifecycle {
            parent_broker: Some(broker),
            authority: Arc::new(StopAuthority::new(ledger, channel)),
            worker_id: Some(worker.clone()),
            socket_root: sockets.clone(),
            abandoned: false,
            retirement: None,
        };
        if expired {
            let deadline = Instant::now() - Duration::from_secs(1);
            let error = lifecycle
                .retire_bounded(deadline)
                .expect_err("spent deadline");
            assert!(error.contains("budget was already spent"));
            assert!(lifecycle.abandoned);
            // No explicit abandon: the failed deadline-owned call itself must
            // prevent broker and worker retirement from reappearing in Drop.
        } else {
            lifecycle.abandon();
            assert!(lifecycle.parent_broker.as_ref().unwrap().start().is_err());
        }
        drop(lifecycle);
        // Unguarded broker Drop settles the empty scope successfully and
        // removes its capability socket: merely skipping retire_all fails.
        assert!(broker_socket.exists());
        assert!(storage.join(worker.as_str()).exists());
        assert!(sockets.exists());
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;

    #[test]
    fn blocked_stop_does_not_block_retirement_caller() {
        let (release, blocked) = std::sync::mpsc::channel();
        let (finished, completed) = std::sync::mpsc::channel();
        let started = Instant::now();
        let result = bounded_retirement(started + Duration::from_millis(20), move || {
            blocked.recv().unwrap();
            finished.send(()).unwrap();
            Ok(())
        });
        assert!(result
            .unwrap_err()
            .contains("wait for session worker stop failed"));
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        completed.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn stop_failure_is_not_converted_to_success() {
        let result = bounded_retirement(Instant::now() + Duration::from_secs(1), || {
            Err("worker stop refused".to_owned())
        });
        assert_eq!(result, Err("worker stop refused".to_owned()));
    }
}
