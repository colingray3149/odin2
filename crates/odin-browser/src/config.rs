//! Mechanism and resource configuration for the browser arm.
//!
//! This module owns *mechanism only*: binary paths, the isolated profile parent,
//! the display source, viewport geometry, resource ceilings, and deadlines.
//! It deliberately contains no browsing, site, effect, or approval policy;
//! all changeable policy lives in [`crate::policy`] and is supplied per session.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use odin_kernel::StopAuthority;
use odin_process::RegisteredServiceBinding;
use serde::{Deserialize, Serialize};

/// Hard mechanical ceiling on a single worker JSONL message, in bytes.
/// Nothing in configuration may raise this above the frame this process can
/// honestly buffer.
pub const MAX_WORKER_MESSAGE_BYTES_CEILING: u32 = 256 * 1024 * 1024;

/// Node and playwright-core locations embedded by the Nix build. Absolute
/// fallbacks keep non-Nix defaults structurally safe; validation still
/// requires the selected paths to exist with the expected kind.
const DEFAULT_NODE_BINARY: &str = match option_env!("ODIN_BROWSER_NODE_BIN") {
    Some(path) => path,
    None => "/usr/bin/node",
};
const DEFAULT_PLAYWRIGHT_MODULE_ROOT: &str = match option_env!("ODIN_BROWSER_PLAYWRIGHT_MODULE") {
    Some(path) => path,
    None => "/usr/lib/node_modules/playwright-core",
};

/// Hard mechanical ceiling on viewport geometry per axis.
pub const MAX_VIEWPORT_DIMENSION: u32 = 8192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DisplaySource {
    /// Reuse an already running X display. The browser arm owns nothing about
    /// its lifecycle and never starts or stops it.
    Existing {
        /// X11 display string such as `:0` or `:1`.
        display: String,
        /// Optional Xauthority file; when absent no `XAUTHORITY` is exported.
        authority_file: Option<PathBuf>,
    },
    /// Start Xvfb in the session process group and reap it during teardown.
    Virtual {
        /// Absolute path to the `Xvfb` binary.
        xvfb_binary: PathBuf,
        /// Lowest display number the arm may probe upward from.
        display_base: u16,
        /// Xvfb screen spec such as `1920x1080x24`.
        screen: String,
    },
}

impl DisplaySource {
    /// Returns the X11 display string this source will provide, if resolved
    /// without probing. Virtual displays resolve during launch.
    pub fn existing_display(&self) -> Option<&str> {
        match self {
            Self::Existing { display, .. } => Some(display),
            Self::Virtual { .. } => None,
        }
    }
}

/// Viewport geometry handed to Chromium via `--window-size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Viewport {
    pub width: NonZeroU32,
    pub height: NonZeroU32,
}

impl Viewport {
    pub const fn new(width: NonZeroU32, height: NonZeroU32) -> Self {
        Self { width, height }
    }

    /// Screen string in the `WxH` form Chromium and Xvfb accept.
    pub fn screen_spec(&self) -> String {
        format!("{}x{}", self.width.get(), self.height.get())
    }
}

impl Default for Viewport {
    fn default() -> Self {
        Self::new(
            NonZeroU32::new(1920).expect("non-zero"),
            NonZeroU32::new(1080).expect("non-zero"),
        )
    }
}

/// Ceilings for the bounded JSONL worker channel. Every queue and buffer the
/// control plane touches is bounded by one of these numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerLimits {
    /// Maximum simultaneously outstanding worker calls. Additional calls fail
    /// fast with an overload error instead of queueing without bound.
    pub max_in_flight_requests: NonZeroU32,
    /// Maximum bytes for one JSONL message in either direction.
    pub max_message_bytes: NonZeroU32,
    /// Maximum queued worker events before the client drops the newest.
    pub max_event_queue_depth: NonZeroU32,
}

impl Default for WorkerLimits {
    fn default() -> Self {
        Self {
            max_in_flight_requests: NonZeroU32::new(64).expect("non-zero"),
            max_message_bytes: NonZeroU32::new(64 * 1024 * 1024).expect("non-zero"),
            max_event_queue_depth: NonZeroU32::new(2048).expect("non-zero"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrameLimits {
    /// Maximum encoded frame bytes (the base64 transport payload envelope).
    pub max_encoded_frame_bytes: NonZeroU32,
    /// Maximum decoded frame bytes accepted into the frame stream.
    pub max_decoded_frame_bytes: NonZeroU32,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            max_encoded_frame_bytes: NonZeroU32::new(16 * 1024 * 1024).expect("non-zero"),
            max_decoded_frame_bytes: NonZeroU32::new(12 * 1024 * 1024).expect("non-zero"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DownloadLimits {
    /// Maximum concurrently active downloads per session.
    pub max_active_downloads: NonZeroU32,
    pub max_file_bytes: u64,
    /// Maximum cumulative staged bytes for the session.
    pub max_total_bytes: u64,
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            max_active_downloads: NonZeroU32::new(4).expect("non-zero"),
            max_file_bytes: 512 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceLimits {
    pub worker: WorkerLimits,
    pub frame: FrameLimits,
    pub download: DownloadLimits,
}

/// Startup, per-command, and teardown deadlines, plus the control-lease
/// lifetime of one held remote takeover.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Deadlines {
    /// Time allowed from worker spawn through its answered launch handshake.
    #[serde(with = "duration_millis")]
    pub startup: Duration,
    /// Default time allowed for one worker-backed command.
    #[serde(with = "duration_millis")]
    pub command: Duration,
    /// Leaves time for daemon cleanup after browser teardown finishes.
    #[serde(with = "duration_millis")]
    pub shutdown: Duration,
    /// Lifetime of one held remote takeover control lease. The local session
    /// supervisor retires a held lease once this lifetime has passed.
    #[serde(default = "default_takeover_lease", with = "duration_millis")]
    pub takeover_lease: Duration,
}

fn default_takeover_lease() -> Duration {
    crate::takeover::DEFAULT_TAKEOVER_LEASE_TTL
}

/// Screen string for a running X display, e.g. `1920x1080x24`.
pub(crate) fn valid_screen_spec(screen: &str) -> bool {
    let parts: Vec<&str> = screen.split('x').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            startup: Duration::from_secs(120),
            command: Duration::from_secs(20),
            shutdown: Duration::from_secs(5),
            takeover_lease: crate::takeover::DEFAULT_TAKEOVER_LEASE_TTL,
        }
    }
}

/// Playwright worker launch mechanism. Paths are selected at compile time by
/// the Nix build rather than from the runtime environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlaywrightLaunch {
    /// Absolute path to the Node.js executable used for the bundled worker.
    pub node_binary: PathBuf,
    /// Absolute path to the playwright-core module root.
    pub module_root: PathBuf,
}

impl Default for PlaywrightLaunch {
    fn default() -> Self {
        Self {
            node_binary: PathBuf::from(DEFAULT_NODE_BINARY),
            module_root: PathBuf::from(DEFAULT_PLAYWRIGHT_MODULE_ROOT),
        }
    }
}

/// Chromium launch mechanism. Flags here are mechanism only; the launcher
/// always appends its own isolation flags and never emits `--headless` or
/// `--no-sandbox`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChromiumLaunch {
    /// Absolute path to the headed Chromium binary.
    pub binary: PathBuf,
    /// Extra mechanism arguments (font flags, window class, and similar).
    pub extra_arguments: Vec<String>,
}

impl Default for ChromiumLaunch {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("/usr/bin/chromium"),
            extra_arguments: Vec::new(),
        }
    }
}

/// Complete mechanism/resource configuration for one browser arm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserConfig {
    pub playwright: PlaywrightLaunch,
    pub chromium: ChromiumLaunch,
    /// Parent directory beneath which isolated profiles are created.
    pub profile_parent: PathBuf,
    pub display: Option<DisplaySource>,
    pub viewport: Viewport,
    pub limits: ResourceLimits,
    pub deadlines: Deadlines,
}

/// Callers supply the stop authority, transaction names, and compiled Playwright binding.
/// The browser needs network egress and runs as a trusted service; scanner and Xvfb
/// workers are isolated. No launch dependency is discovered from the environment.
#[derive(Clone)]
pub struct BrowserStopHost {
    pub authority: Arc<StopAuthority>,
    pub tx_id: String,
    pub wp_id: String,
    pub attempt: u32,
    pub worker_binding: RegisteredServiceBinding,
}

impl BrowserConfig {
    /// Validates the mechanism configuration without consulting any policy.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_non_root()?;
        self.validate_playwright()?;
        self.validate_chromium()?;
        self.validate_profile_parent()?;
        self.validate_display()?;
        self.validate_viewport()?;
        self.validate_limits()?;
        self.validate_deadlines()?;
        Ok(())
    }

    /// Headed Chromium never runs as root. Both the real and the effective
    /// uid are checked so `sudo`/setuid contexts cannot slip through; this
    /// is a mechanism precondition of the sandboxed launch, not policy.
    fn validate_non_root(&self) -> Result<(), ConfigError> {
        if rustix::process::getuid().is_root() || rustix::process::geteuid().is_root() {
            return Err(ConfigError::RunningAsRoot);
        }
        Ok(())
    }

    fn validate_playwright(&self) -> Result<(), ConfigError> {
        ensure_executable_file("node binary", &self.playwright.node_binary)?;
        ensure_directory("playwright module root", &self.playwright.module_root)
    }

    fn validate_chromium(&self) -> Result<(), ConfigError> {
        ensure_executable_file("chromium binary", &self.chromium.binary)?;
        for argument in &self.chromium.extra_arguments {
            if reserved_flag(argument).is_some() {
                return Err(ConfigError::ReservedFlag(argument.clone()));
            }
            if argument.len() > 4096 {
                return Err(ConfigError::ArgumentTooLong(argument.len()));
            }
        }
        Ok(())
    }

    fn validate_profile_parent(&self) -> Result<(), ConfigError> {
        if !self.profile_parent.is_absolute() {
            return Err(ConfigError::NotAbsolute {
                what: "profile parent",
                path: self.profile_parent.clone(),
            });
        }
        Ok(())
    }

    fn validate_display(&self) -> Result<(), ConfigError> {
        match &self.display {
            None => Err(ConfigError::MissingDisplay),
            Some(DisplaySource::Existing {
                display,
                authority_file,
            }) => {
                let number = display
                    .strip_prefix(':')
                    .ok_or_else(|| ConfigError::BadDisplay(display.clone()))?;
                if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ConfigError::BadDisplay(display.clone()));
                }
                if let Some(authority) = authority_file {
                    if !authority.is_absolute() {
                        return Err(ConfigError::NotAbsolute {
                            what: "display authority file",
                            path: authority.clone(),
                        });
                    }
                }
                Ok(())
            }
            Some(DisplaySource::Virtual {
                xvfb_binary,
                display_base,
                screen,
            }) => {
                ensure_executable_file("xvfb binary", xvfb_binary)?;
                if !(10..=1000).contains(display_base) {
                    return Err(ConfigError::DisplayBaseOutOfRange(*display_base));
                }
                if !valid_screen_spec(screen) {
                    return Err(ConfigError::BadScreenSpec(screen.clone()));
                }
                Ok(())
            }
        }
    }

    fn validate_viewport(&self) -> Result<(), ConfigError> {
        if self.viewport.width.get() > MAX_VIEWPORT_DIMENSION
            || self.viewport.height.get() > MAX_VIEWPORT_DIMENSION
        {
            return Err(ConfigError::ViewportTooLarge {
                width: self.viewport.width.get(),
                height: self.viewport.height.get(),
            });
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<(), ConfigError> {
        if self.limits.worker.max_message_bytes.get() > MAX_WORKER_MESSAGE_BYTES_CEILING {
            return Err(ConfigError::WorkerMessageCeiling(
                self.limits.worker.max_message_bytes.get(),
            ));
        }
        if self.limits.frame.max_decoded_frame_bytes.get()
            >= self.limits.frame.max_encoded_frame_bytes.get() * 4
        {
            return Err(ConfigError::FrameLimitInconsistent);
        }
        if self.limits.download.max_file_bytes > self.limits.download.max_total_bytes {
            return Err(ConfigError::DownloadLimitInconsistent);
        }
        Ok(())
    }

    fn validate_deadlines(&self) -> Result<(), ConfigError> {
        const MAX: Duration = Duration::from_secs(900);
        for (what, value) in [
            ("startup", self.deadlines.startup),
            ("command", self.deadlines.command),
            ("shutdown", self.deadlines.shutdown),
            ("takeoverLease", self.deadlines.takeover_lease),
        ] {
            if value.is_zero() || value > MAX {
                return Err(ConfigError::DeadlineOutOfRange { what, value });
            }
        }
        Ok(())
    }
}

/// Ensures a launcher binary path is absolute, existing, a regular file,
/// and carries an executable bit. Applies equally to the Node, Chromium, and
/// Xvfb binaries; filesystem probing here is mechanism validation, not policy.
pub(crate) fn ensure_executable_file(what: &'static str, path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::NotAbsolute {
            what,
            path: path.to_path_buf(),
        });
    }
    let metadata = std::fs::metadata(path).map_err(|source| ConfigError::PathUnreadable {
        what,
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::NotAFile {
            what,
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(ConfigError::NotExecutable {
                path: path.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Ensures a module root is absolute, readable, and a directory.
fn ensure_directory(what: &'static str, path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::NotAbsolute {
            what,
            path: path.to_path_buf(),
        });
    }
    let metadata = std::fs::metadata(path).map_err(|source| ConfigError::PathUnreadable {
        what,
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() {
        return Err(ConfigError::NotADirectory {
            what,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Flags the launcher reserves for itself. Configuration cannot smuggle them
/// in: they would break process isolation or integrity, which is a mechanism
/// boundary, not policy.
fn reserved_flag(argument: &str) -> Option<&'static str> {
    const RESERVED: [&str; 8] = [
        "--headless",
        "--no-sandbox",
        "--user-data-dir",
        "--remote-debugging-port",
        "--remote-debugging-pipe",
        "--remote-debugging-address",
        "--remote-debugging-ws",
        "--display",
    ];
    let name = argument.split('=').next().unwrap_or(argument);
    let lowered = name.to_ascii_lowercase();
    RESERVED
        .into_iter()
        .find(|reserved| lowered.eq_ignore_ascii_case(reserved))
}

/// Mechanism configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{what} path must be absolute: {path}")]
    NotAbsolute { what: &'static str, path: PathBuf },
    #[error("{what} unreadable at {path}: {source}")]
    PathUnreadable {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{what} is not a regular file: {path}")]
    NotAFile { what: &'static str, path: PathBuf },
    #[error("{what} is not a directory: {path}")]
    NotADirectory { what: &'static str, path: PathBuf },
    #[error("binary is not executable: {path}")]
    NotExecutable { path: PathBuf },
    #[error("extra argument reserves a launcher-controlled flag: {0}")]
    ReservedFlag(String),
    #[error("extra argument exceeds 4096 bytes: {0}")]
    ArgumentTooLong(usize),
    #[error("headed Chromium requires an existing or virtual display source")]
    MissingDisplay,
    #[error("display string must look like ':N' with a numeric N: {0}")]
    BadDisplay(String),
    #[error("display_base must be within 10..=1000: {0}")]
    DisplayBaseOutOfRange(u16),
    #[error("screen spec must look like 'WxHxD' numeric: {0}")]
    BadScreenSpec(String),
    #[error("viewport too large: {width}x{height}")]
    ViewportTooLarge { width: u32, height: u32 },
    #[error("worker message limit {0} exceeds the mechanical ceiling")]
    WorkerMessageCeiling(u32),
    #[error("decoded frame bound must stay below 4x the encoded bound")]
    FrameLimitInconsistent,
    #[error("per-file download bound must not exceed the session total")]
    DownloadLimitInconsistent,
    #[error("{what} deadline out of range (non-zero, at most 900s): {value:?}")]
    DeadlineOutOfRange { what: &'static str, value: Duration },
    #[error("the browser arm never runs as root; headed Chromium requires an unprivileged user")]
    RunningAsRoot,
}

/// Serializes [`Duration`] fields as unsigned milliseconds.
pub(crate) mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_millis().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}
