//! Validated Huginn configuration: private listener, bounded resource limits, and
//! runtime state folders.

use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::Duration;

/// A listener address is either loopback or an explicit tailnet address.
/// Tailscale owns IPv4 CGNAT `100.64.0.0/10` and IPv6 ULA `fd7a:115c:a1e0::/48`;
/// wildcard, LAN, link-local, and public addresses are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindScope {
    Loopback,
    Tailnet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedBindAddress {
    address: SocketAddr,
    scope: BindScope,
}

impl ValidatedBindAddress {
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub const fn scope(&self) -> BindScope {
        self.scope
    }
}

/// The single private listener. One explicit address and port; no discovery, no
/// campus-LAN surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HuginnBindConfig {
    pub address: SocketAddr,
}

impl HuginnBindConfig {
    pub const fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    /// Rejects port 0 and every address that is neither loopback nor explicit
    /// Tailscale.
    pub fn validate(&self) -> Result<ValidatedBindAddress, ConfigError> {
        if self.address.port() == 0 {
            return Err(ConfigError::EphemeralListenPort {
                address: self.address,
            });
        }
        let scope = classify_bind(self.address.ip())?;
        Ok(ValidatedBindAddress {
            address: self.address,
            scope,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    #[error("listen address {address} is not a loopback or explicit tailscale address")]
    UnsupportedListenAddress { address: IpAddr },
    #[error("listen address {address} must use an explicit port, not port 0")]
    EphemeralListenPort { address: SocketAddr },
    #[error("state root path is required")]
    StateRootRequired,
    #[error("declared mutable state {key} = {path} is outside the declared state root {root}")]
    StatePathOutsideStateRoot {
        key: String,
        path: PathBuf,
        root: PathBuf,
    },
    #[error("limit {field} = {value} is outside the supported range [{minimum}, {maximum}]")]
    LimitOutOfRange {
        field: &'static str,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
    #[error("configuration could not be read from {path:?}: {message}")]
    Io { path: PathBuf, message: String },
    #[error("configuration TOML is invalid: {0}")]
    Toml(String),
    #[error("configuration is invalid: {0}")]
    Invalid(String),
}

fn classify_bind(ip: IpAddr) -> Result<BindScope, ConfigError> {
    let scope = match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            if octets[0] == 127 {
                BindScope::Loopback
            } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                BindScope::Tailnet
            } else {
                return Err(ConfigError::UnsupportedListenAddress { address: ip });
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            if v6.is_loopback() {
                BindScope::Loopback
            } else if segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0 {
                BindScope::Tailnet
            } else {
                return Err(ConfigError::UnsupportedListenAddress { address: ip });
            }
        }
    };
    Ok(scope)
}

pub(super) fn range(
    field: &'static str,
    value: i64,
    minimum: i64,
    maximum: i64,
) -> Result<(), ConfigError> {
    if value < minimum || value > maximum {
        Err(ConfigError::LimitOutOfRange {
            field,
            value,
            minimum,
            maximum,
        })
    } else {
        Ok(())
    }
}

pub(super) fn range_secs(
    field: &'static str,
    value: Duration,
    minimum: i64,
    maximum: i64,
) -> Result<(), ConfigError> {
    range(field, value.whole_seconds(), minimum, maximum)
}

/// Top-level configuration. Every limit is nonzero by construction (`NonZero*`
/// fields) and bounded by `validate`; the state root is always explicit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HuginnConfig {
    pub bind: HuginnBindConfig,
    #[serde(default)]
    pub limits: HuginnLimits,
    pub state_root: PathBuf,
}

impl HuginnConfig {
    pub fn validate(&self) -> Result<ValidatedHuginnConfig, ConfigError> {
        let bind = self.bind.validate()?;
        self.limits.validate()?;
        let state = HuginnStatePaths::new(self.state_root.clone())?;
        Ok(ValidatedHuginnConfig {
            bind,
            limits: self.limits.clone(),
            state,
        })
    }
}

/// A configuration that has passed every bound and listener check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHuginnConfig {
    bind: ValidatedBindAddress,
    limits: HuginnLimits,
    state: HuginnStatePaths,
}

impl ValidatedHuginnConfig {
    pub const fn bind(&self) -> ValidatedBindAddress {
        self.bind
    }

    pub const fn limits(&self) -> &HuginnLimits {
        &self.limits
    }

    pub const fn state(&self) -> &HuginnStatePaths {
        &self.state
    }
}

/// Runtime folders under `$ODIN_STATE/huginn`; storage code owns
/// modes (0600 files, 0700 directories).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HuginnStatePaths {
    root: PathBuf,
}

impl HuginnStatePaths {
    pub fn new(root: PathBuf) -> Result<Self, ConfigError> {
        if root.as_os_str().is_empty() {
            Err(ConfigError::StateRootRequired)
        } else {
            Ok(Self { root })
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn devices_db(&self) -> PathBuf {
        self.root.join("devices.sqlite3")
    }

    /// The local device-admin socket the daemon binds (0600) and the CLI
    /// dials for loopback device administration.
    pub fn admin_socket(&self) -> PathBuf {
        self.root.join("admin.sock")
    }

    pub fn read_model_db(&self) -> PathBuf {
        self.root.join("read-model.sqlite3")
    }

    pub fn streams_dir(&self) -> PathBuf {
        self.root.join("streams")
    }

    pub fn renders_dir(&self) -> PathBuf {
        self.root.join("renders")
    }

    pub fn previews_dir(&self) -> PathBuf {
        self.root.join("previews")
    }
}

/// Declared queue, transfer, render, session, and stream resource limits. Every
/// field is nonzero; `validate` enforces the declared ranges.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HuginnLimits {
    #[serde(default)]
    pub connections: ConnectionLimits,
    #[serde(default)]
    pub sessions: SessionLimits,
    #[serde(default)]
    pub streams: StreamLimits,
    #[serde(default)]
    pub transfers: TransferLimits,
    #[serde(default)]
    pub renders: RenderLimits,
    #[serde(default)]
    pub files: FileLimits,
    #[serde(default)]
    pub terminal: TerminalLimits,
}

impl HuginnLimits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.connections.validate()?;
        self.sessions.validate()?;
        self.streams.validate()?;
        self.transfers.validate()?;
        self.renders.validate()?;
        self.files.validate()?;
        self.terminal.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLimits {
    /// Concurrent authenticated connections per device.
    pub max_connections: NonZeroUsize,
    pub max_subscriptions_per_connection: NonZeroUsize,
    /// Unanswered requests per connection before backpressure closes it.
    pub max_inflight_requests: NonZeroUsize,
    /// Inbound request queue depth; overflow rejects with a queue-flood error.
    pub request_queue_depth: NonZeroUsize,
    pub max_frame_bytes: NonZeroUsize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: NonZeroUsize::new(8).expect("nonzero"),
            max_subscriptions_per_connection: NonZeroUsize::new(64).expect("nonzero"),
            max_inflight_requests: NonZeroUsize::new(32).expect("nonzero"),
            request_queue_depth: NonZeroUsize::new(1024).expect("nonzero"),
            max_frame_bytes: NonZeroUsize::new(1024 * 1024).expect("nonzero"),
        }
    }
}

impl ConnectionLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.connections.max_connections",
            self.max_connections.get() as i64,
            1,
            64,
        )?;
        range(
            "limits.connections.max_subscriptions_per_connection",
            self.max_subscriptions_per_connection.get() as i64,
            1,
            1024,
        )?;
        range(
            "limits.connections.max_inflight_requests",
            self.max_inflight_requests.get() as i64,
            1,
            1024,
        )?;
        range(
            "limits.connections.request_queue_depth",
            self.request_queue_depth.get() as i64,
            16,
            16384,
        )?;
        range(
            "limits.connections.max_frame_bytes",
            self.max_frame_bytes.get() as i64,
            4096,
            16 * 1024 * 1024,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLimits {
    /// Tracked live sessions across all seats.
    pub max_sessions: NonZeroUsize,
    /// `GetHistory`/list page caps (protocol limits are `NonZeroU16`).
    pub max_history_page: NonZeroU16,
    pub max_list_page: NonZeroU16,
    /// Durable command/outcome journal depth per session.
    pub command_journal_depth: NonZeroUsize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: NonZeroUsize::new(32).expect("nonzero"),
            max_history_page: NonZeroU16::new(100).expect("nonzero"),
            max_list_page: NonZeroU16::new(100).expect("nonzero"),
            command_journal_depth: NonZeroUsize::new(4096).expect("nonzero"),
        }
    }
}

impl SessionLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.sessions.max_sessions",
            self.max_sessions.get() as i64,
            1,
            256,
        )?;
        range(
            "limits.sessions.max_history_page",
            self.max_history_page.get() as i64,
            1,
            1000,
        )?;
        range(
            "limits.sessions.max_list_page",
            self.max_list_page.get() as i64,
            1,
            1000,
        )?;
        range(
            "limits.sessions.command_journal_depth",
            self.command_journal_depth.get() as i64,
            64,
            65536,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamLimits {
    /// Per-subscription buffered events beyond the replay head before the
    /// subscription (only) is closed.
    pub replay_buffer_events: NonZeroUsize,
    pub frame_queue_depth: NonZeroUsize,
    pub max_frames_per_second: NonZeroU32,
    /// Single stream frame payload bound (kube/browser/simulation/terminal).
    pub max_stream_frame_bytes: NonZeroUsize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            replay_buffer_events: NonZeroUsize::new(4096).expect("nonzero"),
            frame_queue_depth: NonZeroUsize::new(256).expect("nonzero"),
            max_frames_per_second: NonZeroU32::new(30).expect("nonzero"),
            max_stream_frame_bytes: NonZeroUsize::new(256 * 1024).expect("nonzero"),
        }
    }
}

impl StreamLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.streams.replay_buffer_events",
            self.replay_buffer_events.get() as i64,
            64,
            65536,
        )?;
        range(
            "limits.streams.frame_queue_depth",
            self.frame_queue_depth.get() as i64,
            16,
            16384,
        )?;
        range(
            "limits.streams.max_frames_per_second",
            self.max_frames_per_second.get() as i64,
            1,
            240,
        )?;
        range(
            "limits.streams.max_stream_frame_bytes",
            self.max_stream_frame_bytes.get() as i64,
            1024,
            8 * 1024 * 1024,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferLimits {
    pub max_transfer_bytes: NonZeroU64,
    pub chunk_bytes: NonZeroU32,
    pub max_concurrent_transfers: NonZeroUsize,
    pub download_credit_chunks: NonZeroU16,
    /// Content-ticket lifetime; tickets are short-lived and single-source.
    pub ticket_ttl: Duration,
    pub queue_depth: NonZeroUsize,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            max_transfer_bytes: NonZeroU64::new(512 * 1024 * 1024).expect("nonzero"),
            chunk_bytes: NonZeroU32::new(256 * 1024).expect("nonzero"),
            max_concurrent_transfers: NonZeroUsize::new(8).expect("nonzero"),
            download_credit_chunks: NonZeroU16::new(16).expect("nonzero"),
            ticket_ttl: Duration::seconds(60),
            queue_depth: NonZeroUsize::new(256).expect("nonzero"),
        }
    }
}

impl TransferLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.transfers.max_transfer_bytes",
            self.max_transfer_bytes.get() as i64,
            1024 * 1024,
            8 * 1024 * 1024 * 1024,
        )?;
        range(
            "limits.transfers.chunk_bytes",
            self.chunk_bytes.get() as i64,
            16 * 1024,
            4 * 1024 * 1024,
        )?;
        range(
            "limits.transfers.max_concurrent_transfers",
            self.max_concurrent_transfers.get() as i64,
            1,
            64,
        )?;
        range(
            "limits.transfers.download_credit_chunks",
            self.download_credit_chunks.get() as i64,
            1,
            1024,
        )?;
        range_secs("limits.transfers.ticket_ttl", self.ticket_ttl, 1, 3600)?;
        range(
            "limits.transfers.queue_depth",
            self.queue_depth.get() as i64,
            16,
            16384,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenderLimits {
    /// Rendered output byte ceiling.
    pub max_render_bytes: NonZeroU64,
    pub max_concurrent_renders: NonZeroUsize,
    pub queue_depth: NonZeroUsize,
    pub timeout: Duration,
}

impl Default for RenderLimits {
    fn default() -> Self {
        Self {
            max_render_bytes: NonZeroU64::new(256 * 1024 * 1024).expect("nonzero"),
            max_concurrent_renders: NonZeroUsize::new(4).expect("nonzero"),
            queue_depth: NonZeroUsize::new(64).expect("nonzero"),
            timeout: Duration::seconds(120),
        }
    }
}

impl RenderLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.renders.max_render_bytes",
            self.max_render_bytes.get() as i64,
            1024 * 1024,
            2 * 1024 * 1024 * 1024,
        )?;
        range(
            "limits.renders.max_concurrent_renders",
            self.max_concurrent_renders.get() as i64,
            1,
            32,
        )?;
        range(
            "limits.renders.queue_depth",
            self.queue_depth.get() as i64,
            16,
            16384,
        )?;
        range_secs("limits.renders.timeout", self.timeout, 1, 600)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileLimits {
    pub max_read_chunk_bytes: NonZeroU32,
    pub max_browse_page: NonZeroU16,
    pub max_watch_streams: NonZeroUsize,
    pub watch_queue_depth: NonZeroUsize,
    /// Rejects oversized and traversal-probing paths early.
    pub max_path_bytes: NonZeroUsize,
}

impl Default for FileLimits {
    fn default() -> Self {
        Self {
            max_read_chunk_bytes: NonZeroU32::new(256 * 1024).expect("nonzero"),
            max_browse_page: NonZeroU16::new(500).expect("nonzero"),
            max_watch_streams: NonZeroUsize::new(32).expect("nonzero"),
            watch_queue_depth: NonZeroUsize::new(256).expect("nonzero"),
            max_path_bytes: NonZeroUsize::new(1024).expect("nonzero"),
        }
    }
}

impl FileLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.files.max_read_chunk_bytes",
            self.max_read_chunk_bytes.get() as i64,
            16 * 1024,
            4 * 1024 * 1024,
        )?;
        range(
            "limits.files.max_browse_page",
            self.max_browse_page.get() as i64,
            1,
            10000,
        )?;
        range(
            "limits.files.max_watch_streams",
            self.max_watch_streams.get() as i64,
            1,
            256,
        )?;
        range(
            "limits.files.watch_queue_depth",
            self.watch_queue_depth.get() as i64,
            16,
            16384,
        )?;
        range(
            "limits.files.max_path_bytes",
            self.max_path_bytes.get() as i64,
            128,
            4096,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalLimits {
    /// Snapshot size is measured after compression.
    pub max_snapshot_bytes: NonZeroU32,
    pub max_delta_bytes: NonZeroU32,
    pub max_frames_per_second: NonZeroU32,
    /// Operator control lease lifetime; raw PTY input requires a live lease.
    pub control_lease_ttl: Duration,
}

impl Default for TerminalLimits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: NonZeroU32::new(1024 * 1024).expect("nonzero"),
            max_delta_bytes: NonZeroU32::new(64 * 1024).expect("nonzero"),
            max_frames_per_second: NonZeroU32::new(60).expect("nonzero"),
            control_lease_ttl: Duration::seconds(300),
        }
    }
}

impl TerminalLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        range(
            "limits.terminal.max_snapshot_bytes",
            self.max_snapshot_bytes.get() as i64,
            16 * 1024,
            8 * 1024 * 1024,
        )?;
        range(
            "limits.terminal.max_delta_bytes",
            self.max_delta_bytes.get() as i64,
            1024,
            1024 * 1024,
        )?;
        range(
            "limits.terminal.max_frames_per_second",
            self.max_frames_per_second.get() as i64,
            1,
            240,
        )?;
        range_secs(
            "limits.terminal.control_lease_ttl",
            self.control_lease_ttl,
            1,
            3600,
        )
    }
}
