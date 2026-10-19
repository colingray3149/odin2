//! Shared odind test fixtures: the committed single-node registry
//! publication harness and the strict fixture config/manifest builders.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use odin_registry::{RegistryKind, SnapshotStore};

use crate::controller;
use crate::test_support::{commit_all, git};

pub(super) fn manifest_identity_fixture(key: &str, path: &Path) -> odin_huginn::RuntimeManifest {
    let mut executables = std::collections::BTreeMap::new();
    executables.insert(
        key.to_owned(),
        odin_huginn::PathDigestRef {
            path: path.to_path_buf(),
            digest: format!("blake3:{}", "a".repeat(64)),
        },
    );
    odin_huginn::RuntimeManifest {
        schema: odin_huginn::RUNTIME_MANIFEST_SCHEMA.to_owned(),
        executables,
        odind_config: odin_huginn::PathDigestRef {
            path: std::path::PathBuf::from("/tmp/odind-binding-odind.toml"),
            digest: format!("blake3:{}", "b".repeat(64)),
        },
    }
}

pub(super) fn odind_node_toml(id: &str, authoritative: bool) -> String {
    format!(
        "schema = \"odin.registry.v1\"\n\
             kind = \"node\"\n\
             enabled = true\n\
             description = \"odind snapshot-only fixture\"\n\
             host = \"{id}-host\"\n\
             role = \"control\"\n\
             capabilities = []\n\
             allow_workloads = false\n\
             authoritative_state = {authoritative}\n"
    )
}

pub(super) fn odind_host_toml(id: &str) -> String {
    format!(
        "schema = \"odin.registry.v1\"\n\
             kind = \"host\"\n\
             enabled = true\n\
             description = \"odind snapshot-only fixture host\"\n\
             hardware = \"fixture\"\n\
             role = \"control\"\n\
             tailscale = \"{id}-host\"\n\
             enrolled = true\n"
    )
}

/// Publishes a committed single-node registry through the production
/// `publish_committed` path and hands out the resulting store.
pub(super) struct PublishedStore {
    pub(super) temporary: TempDir,
    pub(super) worktree: std::path::PathBuf,
    pub(super) snapshot_path: std::path::PathBuf,
}

impl PublishedStore {
    pub(super) fn new(node: &str, authoritative: bool) -> Self {
        let temporary = TempDir::new().expect("create odind fixture root");
        let worktree = temporary.path().join("authoring");
        fs::create_dir(&worktree).expect("create authoring worktree");
        git(&worktree, &["-c", "init.defaultBranch=main", "init"]);
        let registry = worktree.join("registry");
        for kind in RegistryKind::ALL {
            let directory = registry.join(kind.directory());
            fs::create_dir_all(&directory).expect("create kind directory");
            fs::write(directory.join(".gitkeep"), b"").expect("write kind placeholder");
        }
        let node_directory = registry.join("nodes").join(node);
        fs::create_dir_all(&node_directory).expect("create node directory");
        fs::write(
            node_directory.join("node.toml"),
            odind_node_toml(node, authoritative),
        )
        .expect("write node config");
        let host_directory = registry.join("hosts").join(format!("{node}-host"));
        fs::create_dir_all(&host_directory).expect("create host directory");
        fs::write(host_directory.join("host.toml"), odind_host_toml(node))
            .expect("write host config");
        fs::create_dir_all(worktree.join("schemas")).expect("create schemas root");
        fs::write(worktree.join("schemas/.gitkeep"), b"").expect("write schemas placeholder");
        let commit = commit_all(&worktree, "odind snapshot-only fixture");
        let candidate = odin_registry::ValidatedSnapshotCandidate::from_committed_worktree(
            &worktree,
            &commit,
            Vec::<odin_registry::relational::AdmittedBinding>::new(),
        )
        .expect("committed odind fixture candidate");
        let snapshot_path = temporary.path().join("state/registry/snapshot.json");
        SnapshotStore::new(&snapshot_path)
            .publish_committed(&candidate, 1)
            .expect("publish odind fixture");
        Self {
            temporary,
            worktree,
            snapshot_path,
        }
    }

    pub(super) fn store(&self) -> SnapshotStore {
        SnapshotStore::new(&self.snapshot_path)
    }

    pub(super) fn check(&self, node: &str) -> Result<controller::CheckReport, String> {
        let state_root = self.temporary.path().join(format!("state-{}", node));
        fs::create_dir_all(&state_root).expect("create controller state root");
        controller::check(&controller::CheckRequest {
            registry_snapshot: self.snapshot_path.clone(),
            state_root,
            node: node.to_owned(),
        })
        .map_err(|error| error.to_string())
    }
}

pub(super) fn fixture_config_text(root: &Path, snapshot: &Path) -> String {
    format!(
            "schema = 'odin.odind-config.v1'\n\
             revision = 1\n\
             worker_bus = 'unix:path={0}/worker-bus.sock'\n\
             [identity]\nnode = 'laptop'\n\
             [paths]\n\
             registry_root = '{0}/registry'\n\
             state_root = '{0}/state'\n\
             registry_snapshot = '{1}'\n\
             authority_token_root = '{0}/state/authority/tokens'\n\
             authority_verification_key_file = '{0}/authority/verification.key'\n\
             [listener]\naddress = '127.0.0.1:18421'\n\
             [executables]\nomp_bin = '{0}/omp'\nomp_revision = '{2}'\nextension = '{0}/index.ts'\nzellij_bin = '{0}/zellij'\nzellij_session = 'odin'\n\
             [catalogs.gateway_projection]\npath = '{0}/projection.json'\ndigest = 'blake3:{3}'\n\
             [publish]\nrender_session = 'live-1'\nfile_lane = 'lane-file'\nrender_lane = 'lane-render'\n\
             [capacity]\n",
            root.display(),
            snapshot.display(),
            "a".repeat(40),
            "c".repeat(64)
        )
}

/// The libtest entry the registered-worker fixtures of this binary re-execute
/// as the real worker bootstrap.
const WORKER_BOOTSTRAP_ENTRY: &str =
    "coding_route::tests::scoped_test_fixture::worker_bootstrap_fixture_entry";

/// The first absolute `name` on the runner's PATH.
pub(crate) fn on_path(name: &str) -> Option<std::path::PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_absolute() && path.is_file())
}

fn pinned(path: std::path::PathBuf) -> odin_huginn::PathDigestRef {
    odin_huginn::PathDigestRef {
        digest: format!(
            "blake3:{}",
            blake3::hash(&fs::read(&path).expect("pinned executable")).to_hex()
        ),
        path,
    }
}

/// A session pool whose lifecycle owner launches real registered workers —
/// the pinned `git`, and `ssh` when the runner has one — on `worker`'s
/// channel: the owner of the permitless lifecycles (generic harness
/// hand-back, claim carry, repository watch). Dropping it retires the pool
/// under a bounded deadline before the worker fixture goes.
pub(crate) struct LifecyclePool {
    pub(crate) pool: std::sync::Arc<crate::live_authority::SessionAuthorityPool>,
    pub(crate) handle: crate::live_authority::SessionPoolHandle,
    _config: crate::authority_fixture::Fixture,
    _worker: odin_process::test_support::RegisteredWorkerFixture,
}

impl LifecyclePool {
    pub(crate) fn new(
        state_root: &Path,
        worker: odin_process::test_support::RegisteredWorkerFixture,
    ) -> Self {
        let fixture = crate::authority_fixture::fixture();
        let channel = worker
            .channel_for_harness(
                &std::env::current_exe().expect("test harness"),
                WORKER_BOOTSTRAP_ENTRY,
                &on_path("unshare").expect("an absolute unshare on PATH"),
            )
            .expect("registered worker channel");
        let mut executables = std::collections::BTreeMap::from([
            (
                "git".to_owned(),
                pinned(on_path("git").expect("an absolute git on PATH")),
            ),
            (
                "worker_bootstrap".to_owned(),
                pinned(channel.bootstrap().to_path_buf()),
            ),
            (
                "unshare".to_owned(),
                pinned(channel.unshare().to_path_buf()),
            ),
        ]);
        if let Some(ssh) = on_path("ssh") {
            executables.insert("ssh".to_owned(), pinned(ssh));
        }
        let manifest = odin_huginn::RuntimeManifest {
            schema: "odin.runtime-manifest.v1".into(),
            executables,
            odind_config: pinned(on_path("true").expect("an absolute true on PATH")),
        };
        let mut config = fixture.config.clone();
        config.worker_bus = channel.bus().to_string();
        config.paths.state_root = state_root.to_path_buf();
        let pool = crate::live_authority::SessionAuthorityPool::open_with_worker_channel(
            &config,
            &manifest,
            vec![42; 32],
            channel,
        )
        .expect("lifecycle pool");
        let handle: crate::live_authority::SessionPoolHandle =
            std::sync::Arc::new(std::sync::OnceLock::new());
        handle
            .set(std::sync::Arc::downgrade(&pool))
            .expect("pool handle");
        Self {
            pool,
            handle,
            _config: fixture,
            _worker: worker,
        }
    }
}

impl Drop for LifecyclePool {
    fn drop(&mut self) {
        let _ = self
            .pool
            .retire_all(std::time::Instant::now() + std::time::Duration::from_secs(10));
    }
}

/// A private loopback `git://` remote that accepts every connection and
/// never answers: a transport that hangs. Each accepted connection is kept,
/// so a test can see whether the client that opened it is gone (its end of
/// the connection closed). Dropping it stops and joins its accept thread.
pub(crate) struct SilentRemote {
    address: std::net::SocketAddr,
    accepted: std::sync::Arc<std::sync::Mutex<Vec<std::net::TcpStream>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SilentRemote {
    pub(crate) fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("private listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let address = listener.local_addr().expect("listener address");
        let accepted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let accepted = std::sync::Arc::clone(&accepted);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => accepted.lock().expect("accepted").push(stream),
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                    }
                }
            })
        };
        Self {
            address,
            accepted,
            stop,
            thread: Some(thread),
        }
    }

    pub(crate) fn url(&self) -> String {
        format!("git://{}/silent.git", self.address)
    }

    pub(crate) fn connections(&self) -> usize {
        self.accepted.lock().expect("accepted").len()
    }

    pub(crate) fn reached(&self, count: usize, bound: std::time::Duration) -> bool {
        let until = std::time::Instant::now() + bound;
        while self.connections() < count {
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        true
    }

    /// Whether every accepted connection's client end closed within `bound`
    /// (its request bytes are read past; only end-of-stream counts).
    pub(crate) fn all_closed_within(&self, bound: std::time::Duration) -> bool {
        use std::io::Read;
        let until = std::time::Instant::now() + bound;
        let streams: Vec<std::net::TcpStream> = self
            .accepted
            .lock()
            .expect("accepted")
            .iter()
            .map(|stream| stream.try_clone().expect("stream clone"))
            .collect();
        streams.into_iter().all(|mut stream| {
            let _ = stream.set_nonblocking(false);
            let mut buffer = [0; 4096];
            loop {
                let remaining = until.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                let poll = remaining.min(std::time::Duration::from_millis(100));
                let _ = stream.set_read_timeout(Some(poll));
                match stream.read(&mut buffer) {
                    Ok(0) => return true,
                    Ok(_) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return true,
                }
            }
        })
    }
}

impl Drop for SilentRemote {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Preserve raw Git output for byte-exact hashing; failures panic with argv and stderr.
pub(super) fn git_bytes(worktree: &Path, args: &[&str]) -> Vec<u8> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
