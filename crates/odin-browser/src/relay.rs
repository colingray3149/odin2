//! Relayed worker transport: the exact bounded JSONL worker protocol driven
//! over an established byte stream to a remote odin-browser worker the host
//! does not own as a local process — the governed workload pod's browser
//! worker.
//!
//! The relay carries the protocol and nothing else. The remote process, its
//! display, and its pod lifecycle are never owned from here: the host side
//! can write protocol lines, read them, close its half of the stream (the
//! remote worker exits on stdin EOF), and take bounded remote-exit evidence.
//! Closing a relay never stops its carrier pod.
//!
//! A relayed session uses the same policy snapshots, safety gate, CAS-persisted
//! control generation, frame stream, download manager surface, and takeover
//! coordinator as a local session. Only the worker transport differs, so a
//! workload pod browser is the existing browser mechanism at a different
//! address — never a second browser implementation.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use odin_domain::huginn::ids::BrowserSessionId;

use crate::config::{ResourceLimits, Viewport, MAX_VIEWPORT_DIMENSION};

/// Hard mechanical ceiling on retained remote-exit evidence bytes: the
/// evidence is a short status descriptor, never a log. Teardown truncates
/// to this bound before projecting it anywhere.
pub const REMOTE_EXIT_EVIDENCE_MAX_BYTES: usize = 256;

/// Hard mechanical ceiling on the declared navigation-host allowlist of one
/// relayed launch. A launch declaring more is refused before the relay is
/// split.
pub const MAX_RELAYED_NAVIGATE_HOSTS: usize = 64;

/// Bounded remote-exit evidence: resolves exactly once, when the remote
/// worker is gone, with a short descriptor of how the remote side ended
/// (`None` when the transport ended without a status). Dropping it never
/// stops anything the channel needs.
pub type RemoteExit = Pin<Box<dyn Future<Output = Option<String>> + Send>>;

/// The write half, read half, and exit evidence of one established relay.
/// Produced exactly once by [`WorkerRelay::split`].
pub struct RelayedStreams {
    /// Protocol lines to the remote worker. Closing it is the graceful
    /// remote stop: the worker exits on stdin EOF.
    pub stdin: Box<dyn AsyncWrite + Unpin + Send>,
    /// Protocol lines and typed events from the remote worker.
    pub stdout: Box<dyn AsyncRead + Unpin + Send>,
    /// Resolves with bounded exit evidence when the remote worker is gone.
    pub exit: RemoteExit,
    /// Remote diagnostic output. The relayed runtime drains it without
    /// bound-doubling: a blocked side channel would backpressure the whole
    /// transport, so the consumer discards it after a bounded prefix.
    pub stderr: Box<dyn AsyncRead + Unpin + Send>,
}

/// Implementations verify remote identity and address before handing over streams and exit evidence.
pub trait WorkerRelay: Send + 'static {
    /// Splits the established transport. Called exactly once, at session
    /// launch; a second split is unrepresentable by construction.
    fn split(self: Box<Self>) -> RelayedStreams;
}

/// The remote worker's launch paths: absolute paths inside the remote
/// carrier, host-composed from the published profile's pinned runtime
/// declarations and the pod plan's declared mounts. The model never
/// supplies any part of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayedWorkerPaths {
    /// Remote playwright module root the worker resolves its driver from.
    pub playwright_module_root: String,
    /// Remote Chromium executable the worker launches.
    pub chromium_executable: String,
    /// Remote per-session Chromium user data directory.
    pub user_data_dir: String,
    /// Remote download staging root the worker writes into. The host side
    /// never reads it: relayed downloads are admitted only through the
    /// host staging root below, so an unscanned remote file is rejected,
    /// never trusted.
    pub download_root: String,
}

impl RelayedWorkerPaths {
    /// Derives the deterministic per-session remote paths from the state
    /// dir the pod plan declares. The in-pod supervisor creates the same
    /// tree through `IsolatedProfile::create_for_session`, so the host
    /// composes these before the pod exists and they are identical when
    /// the worker reads them. `playwright` and `chromium` are the pinned
    /// in-image bindings the launch carries.
    pub fn for_session(
        state_dir: &Path,
        session: &BrowserSessionId,
        playwright_module_root: String,
        chromium_executable: String,
    ) -> Self {
        let root = crate::profile::session_profile_dir(state_dir, session);
        Self {
            playwright_module_root,
            chromium_executable,
            user_data_dir: root.join("chromium-user-data").display().to_string(),
            download_root: root.join("downloads").display().to_string(),
        }
    }
}

/// Everything one relayed session launch needs: the established relay, the
/// remote launch paths, the same resource bounds a local session enforces,
/// and the host-side staging root the download manager scans.
pub struct RelayedWorkerLaunch {
    /// The established relay; split exactly once.
    pub relay: Box<dyn WorkerRelay>,
    /// Remote launch paths, host-composed from declarations.
    pub paths: RelayedWorkerPaths,
    /// Viewport geometry handed to Chromium via `--window-size`.
    pub viewport: Viewport,
    /// The same resource ceilings a local session runs under.
    pub limits: ResourceLimits,
    /// Startup deadline budget (handshake and browser launch).
    pub startup: Duration,
    /// Per-command deadline carried into the session limits surface.
    pub command: Duration,
    /// Teardown deadline budget for the bounded remote-stop ladder.
    pub shutdown: Duration,
    /// Control-lease lifetime of one held remote takeover.
    pub takeover_lease: Duration,
    /// Host-side download staging root: an existing private directory the
    /// host owns and scans. Remote files never enter it, so relayed
    /// downloads are typed-rejected at staging confirmation — an honest
    /// refusal, never a fake admission.
    pub download_staging_root: PathBuf,
    /// Opaque bounded identity projected to session views; never a path.
    pub identity: String,
    /// Declared navigation allowlist enforced per action (exact host
    /// equality). `None` admits every navigation, exactly like a local
    /// session with no declared scope.
    pub navigate_hosts: Option<Vec<String>>,
}

impl std::fmt::Debug for RelayedWorkerLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayedWorkerLaunch")
            .field("paths", &self.paths)
            .field("viewport", &self.viewport)
            .field("limits", &self.limits)
            .field("startup", &self.startup)
            .field("command", &self.command)
            .field("shutdown", &self.shutdown)
            .field("takeover_lease", &self.takeover_lease)
            .field(
                "download_staging_root",
                &self.download_staging_root.display().to_string(),
            )
            .field("identity", &self.identity)
            .field("navigate_hosts", &self.navigate_hosts)
            .finish_non_exhaustive()
    }
}

impl RelayedWorkerLaunch {
    /// Validates deadlines, resource limits, staging root, identity, and host allowlist
    /// before consuming the relay.
    pub fn validate(&self) -> Result<(), String> {
        const MAX_DEADLINE: Duration = Duration::from_secs(900);
        for (what, value) in [
            ("startup", self.startup),
            ("command", self.command),
            ("shutdown", self.shutdown),
            ("takeover_lease", self.takeover_lease),
        ] {
            if value.is_zero() || value > MAX_DEADLINE {
                return Err(format!(
                    "relayed launch {what} deadline is zero or beyond the mechanical ceiling"
                ));
            }
        }
        if self.limits.worker.max_message_bytes.get()
            > crate::config::MAX_WORKER_MESSAGE_BYTES_CEILING
        {
            return Err(
                "relayed launch worker message ceiling is beyond the mechanical bound".to_owned(),
            );
        }
        if self.limits.frame.max_decoded_frame_bytes.get()
            >= self.limits.frame.max_encoded_frame_bytes.get() * 4
        {
            return Err("relayed launch frame limits are inconsistent".to_owned());
        }
        if self.limits.download.max_file_bytes > self.limits.download.max_total_bytes {
            return Err("relayed launch download limits are inconsistent".to_owned());
        }
        if self.viewport.width.get() > MAX_VIEWPORT_DIMENSION
            || self.viewport.height.get() > MAX_VIEWPORT_DIMENSION
        {
            return Err("relayed launch viewport exceeds the mechanism bound".to_owned());
        }
        for (what, path) in [
            ("playwright module root", &self.paths.playwright_module_root),
            ("chromium executable", &self.paths.chromium_executable),
            ("user data dir", &self.paths.user_data_dir),
            ("download root", &self.paths.download_root),
        ] {
            if path.is_empty() || !path.starts_with('/') {
                return Err(format!(
                    "relayed launch {what} is not an absolute remote path"
                ));
            }
        }
        if !self.download_staging_root.is_absolute() {
            return Err("relayed launch download staging root is not absolute".to_owned());
        }
        let metadata = std::fs::symlink_metadata(&self.download_staging_root).map_err(|error| {
            format!(
                "relayed launch download staging root {}: {error}",
                self.download_staging_root.display()
            )
        })?;
        if metadata.is_symlink() || !metadata.is_dir() {
            return Err("relayed launch download staging root is not a real directory".to_owned());
        }
        if self.identity.is_empty() || self.identity.len() > 128 {
            return Err("relayed launch identity is empty or beyond the bounded length".to_owned());
        }
        if let Some(hosts) = &self.navigate_hosts {
            if hosts.len() > MAX_RELAYED_NAVIGATE_HOSTS {
                return Err(format!(
                    "relayed launch declares {} navigate hosts: beyond the mechanical bound of {MAX_RELAYED_NAVIGATE_HOSTS}",
                    hosts.len()
                ));
            }
            for host in hosts {
                if host.is_empty()
                    || host.len() > 253
                    || !host.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || byte == b'-'
                            || byte == b'.'
                    })
                {
                    return Err(format!(
                        "relayed launch navigate host {host:?} is not a declared bare hostname"
                    ));
                }
            }
        }
        Ok(())
    }

    /// The bounded allowlist as a lookup set for the per-action admission.
    pub(crate) fn navigate_host_set(&self) -> Option<std::collections::BTreeSet<String>> {
        self.navigate_hosts
            .as_ref()
            .map(|hosts| hosts.iter().cloned().collect())
    }
}
