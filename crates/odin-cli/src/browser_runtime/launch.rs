//! On-demand composition of the governed local browser runtime.
//!
//! [`BrowserRuntimeConfig::prepare`] validates every operator-supplied input
//! and composes the pod-browser opener without launching any browser. The
//! governed local session itself opens lazily through
//! [`PreparedBrowserRuntime`]: the first governed browser call or checkout
//! launches a fresh durable session, and the owning [`super::local::LocalBrowser`]
//! closes it after the declared idle-close window.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use odin_browser::capability::ArtifactPublisher;
use odin_browser::config::{
    BrowserConfig, ChromiumLaunch, Deadlines, DisplaySource, PlaywrightLaunch, ResourceLimits,
    Viewport,
};
use odin_browser::safety::BrowserSafetyGate;
use odin_browser::session::{BrowserSession, FrameWiring, SessionLimits};
use odin_browser::{BrowserStopHost, ExecutableMalwareScanner};
use odin_domain::huginn as live;
use odin_domain::{CapabilityId, EffectClass};
use odin_huginn::browser::{BrowserProjection, BrowserProjectionConfig};
use odin_huginn::read_model::MaterializedReadModel;
use odin_huginn::service::{FsExternalContentIndex, FsPublishedArtifactStore};
use odin_huginn::streams::BoundedMultiplexer;
use odin_kernel::StopAuthority;
use odin_ledger::Ledger;
use odin_process::RegisteredServiceBinding;
use odin_registry::RegistryObject;
use thiserror::Error;

use super::coordinator::BrowserCommandCoordinator;
use super::inputs::{
    load_policy_input, load_protected_values, policy_from_input, validate_registry_capability,
};
use super::pods::PodBrowserOpener;
use crate::browser_runtime::{BROWSER_INTERACT_CAPABILITY, BROWSER_INTERACT_VERSION};

pub struct BrowserRuntimeConfig {
    pub node_binary: PathBuf,
    pub playwright_module_root: PathBuf,
    pub chromium_binary: PathBuf,
    pub display: DisplaySource,
    pub profile_root: PathBuf,
    pub policy_file: PathBuf,
    pub protected_values_file: PathBuf,
    pub scanner_binary: PathBuf,
    pub scanner_arguments: Vec<OsString>,
    pub stream_id: live::StreamId,
    pub projection: BrowserProjectionConfig,
    pub max_pending_actions: NonZeroUsize,
    pub max_stream_frame_bytes: NonZeroUsize,
    pub takeover_lease: std::time::Duration,
    pub idle_close: std::time::Duration,
    pub stop_authority: Arc<StopAuthority>,
    pub worker_binding: RegisteredServiceBinding,
}
#[derive(Debug, Error)]
pub enum BrowserRuntimeError {
    #[error("browser mechanism configuration is invalid: {0}")]
    MechanismConfiguration(String),
    #[error("browser policy input could not be read: {0}")]
    PolicyRead(String),
    #[error("browser policy input is invalid: {0}")]
    PolicyInvalid(String),
    #[error("browser policy references an unavailable or mismatched capability: {0}")]
    PolicyCapability(String),
    #[error("browser interaction capability is unavailable or mismatched: {0}")]
    InteractionCapability(String),
    #[error("browser protected-values input could not be read securely: {0}")]
    ProtectedValuesRead(String),
    #[error("browser protected-values input must be a regular mode-0600 file")]
    ProtectedValuesPermissions,
    #[error("browser protected-values input is invalid: {0}")]
    ProtectedValuesInvalid(String),
    #[error("browser scanner configuration is invalid: {0}")]
    ScannerConfiguration(String),
}

/// How one governed local session opens: the real launch seam the lazy
/// lifecycle drives. Production is [`GovernedSessionLaunch`]; tests script
/// it over the same session/projection/coordinator composition.
#[async_trait]
pub trait LocalSessionLaunch: Send + Sync {
    /// The durable session identity every launch of this runtime reopens.
    fn session_id(&self) -> live::BrowserSessionId;

    /// Opens one fresh session: durable control generation, projection
    /// pump, and the coordinator that serves its commands.
    async fn launch_session(
        &self,
    ) -> Result<(BrowserProjection, BrowserCommandCoordinator), String>;
}

/// The validated governed local browser, not yet launched.
pub struct PreparedBrowserRuntime {
    /// Opens pod browsers under the same validated inputs.
    pub pods: PodBrowserOpener,
    /// The declared idle-close window the owning lifecycle closes after.
    pub idle_close: std::time::Duration,
    launch: Arc<GovernedSessionLaunch>,
}

impl PreparedBrowserRuntime {
    /// The lazy governed local browser over the validated inputs.
    pub fn local_browser(self) -> super::local::LocalBrowser {
        super::local::LocalBrowser::new(self.launch, self.idle_close)
    }

    /// The durable identity every launch of this runtime reopens.
    pub fn session_id(&self) -> live::BrowserSessionId {
        self.launch.session_id()
    }

    /// Seeds the owner-preview ids every launched coordinator serves.
    pub fn set_owner_preview(&mut self, ids: BTreeSet<String>) {
        Arc::get_mut(&mut self.launch)
            .expect("the prepared browser runtime is not yet shared")
            .owner_preview = ids;
    }
}

/// The production launch seam: every input the durable session opens with,
/// validated once at composition and reused by each lazy (re)launch.
struct GovernedSessionLaunch {
    mechanism: BrowserConfig,
    stop_host: BrowserStopHost,
    policy: odin_browser::policy::BrowserPolicySnapshot,
    safety: Arc<BrowserSafetyGate>,
    stream_id: live::StreamId,
    frame_limits: odin_browser::config::FrameLimits,
    session_limits: SessionLimits,
    artifacts: Arc<FsPublishedArtifactStore>,
    ledger: Arc<Mutex<Ledger>>,
    read_model: Arc<MaterializedReadModel>,
    multiplexer: Arc<BoundedMultiplexer>,
    external_content: Arc<FsExternalContentIndex>,
    projection: BrowserProjectionConfig,
    max_pending_actions: NonZeroUsize,
    owner_preview: BTreeSet<String>,
}

#[async_trait]
impl LocalSessionLaunch for GovernedSessionLaunch {
    fn session_id(&self) -> live::BrowserSessionId {
        self.policy.session_id()
    }

    async fn launch_session(
        &self,
    ) -> Result<(BrowserProjection, BrowserCommandCoordinator), String> {
        let publisher: Arc<dyn ArtifactPublisher> = self.artifacts.clone();
        let session = BrowserSession::open_durable(
            self.mechanism.clone(),
            self.stop_host.clone(),
            self.policy.clone(),
            Arc::clone(&self.safety),
            FrameWiring {
                stream_id: self.stream_id,
                limits: self.frame_limits,
                publisher,
                stream: true,
            },
            self.session_limits,
            Arc::clone(&self.ledger),
        )
        .await
        .map_err(|error| format!("{error:?}"))?;
        let projection = BrowserProjection::spawn(
            session,
            Arc::clone(&self.read_model),
            Arc::clone(&self.multiplexer),
            Arc::clone(&self.artifacts),
            Arc::clone(&self.external_content),
            self.projection,
        );
        let mut coordinator = BrowserCommandCoordinator::new(
            Arc::clone(&self.ledger),
            Arc::clone(&self.read_model),
            projection.handle(),
            self.max_pending_actions,
        );
        coordinator.set_owner_preview(self.owner_preview.clone());
        Ok((projection, coordinator))
    }
}

impl BrowserRuntimeConfig {
    /// Validates every operator-supplied input and composes the pod-browser
    /// opener without launching any browser. The governed local session
    /// opens lazily through the returned [`PreparedBrowserRuntime`].
    pub fn prepare(
        self,
        registry: &[RegistryObject],
        ledger: Arc<Mutex<Ledger>>,
        read_model: Arc<MaterializedReadModel>,
        multiplexer: Arc<BoundedMultiplexer>,
        artifacts: Arc<FsPublishedArtifactStore>,
        external_content: Arc<FsExternalContentIndex>,
    ) -> Result<PreparedBrowserRuntime, BrowserRuntimeError> {
        let max_frame_bytes = self.max_stream_frame_bytes.get();
        let decoded_frame_bytes = u32::try_from(max_frame_bytes).map_err(|error| {
            BrowserRuntimeError::MechanismConfiguration(format!(
                "stream frame limit {max_frame_bytes} does not fit u32: {error}"
            ))
        })?;
        let encoded_frame_bytes = decoded_frame_bytes
            .checked_add(2)
            .and_then(|bytes| bytes.checked_div(3))
            .and_then(|groups| groups.checked_mul(4))
            .ok_or_else(|| {
                BrowserRuntimeError::MechanismConfiguration(format!(
                    "stream frame limit {decoded_frame_bytes} overflows its base64 encoding"
                ))
            })?;
        let mut resource_limits = ResourceLimits::default();
        let zero_frames =
            || BrowserRuntimeError::MechanismConfiguration("stream frame limit is zero".to_owned());
        resource_limits.frame.max_decoded_frame_bytes =
            NonZeroU32::new(decoded_frame_bytes).ok_or_else(zero_frames)?;
        resource_limits.frame.max_encoded_frame_bytes =
            NonZeroU32::new(encoded_frame_bytes).ok_or_else(zero_frames)?;
        let deadlines = Deadlines {
            takeover_lease: self.takeover_lease,
            idle_close: self.idle_close,
            ..Deadlines::default()
        };
        let mechanism = BrowserConfig {
            playwright: PlaywrightLaunch {
                node_binary: self.node_binary,
                module_root: self.playwright_module_root,
            },
            chromium: ChromiumLaunch {
                binary: self.chromium_binary,
                extra_arguments: Vec::new(),
            },
            profile_parent: self.profile_root,
            display: Some(self.display),
            viewport: Viewport::default(),
            limits: resource_limits,
            deadlines,
        };
        mechanism
            .validate()
            .map_err(|error| BrowserRuntimeError::MechanismConfiguration(error.to_string()))?;

        let policy_input = load_policy_input(&self.policy_file)?;
        let policy = policy_from_input(policy_input, registry)?;
        validate_registry_capability(
            registry,
            &CapabilityId::new(BROWSER_INTERACT_CAPABILITY)
                .map_err(|error| BrowserRuntimeError::InteractionCapability(error.to_string()))?,
            BROWSER_INTERACT_VERSION,
            EffectClass::R2,
            false,
        )
        .map_err(BrowserRuntimeError::InteractionCapability)?;
        let protected = load_protected_values(&self.protected_values_file)?;

        let stop_host = BrowserStopHost {
            authority: self.stop_authority,
            tx_id: "odind".to_owned(),
            wp_id: "browser".to_owned(),
            attempt: 1,
            worker_binding: self.worker_binding,
        };
        let scanner = ExecutableMalwareScanner::new(
            self.scanner_binary,
            self.scanner_arguments,
            stop_host.clone(),
        )
        .map_err(|error| BrowserRuntimeError::ScannerConfiguration(error.to_string()))?;
        let safety = Arc::new(BrowserSafetyGate::new(protected, Box::new(scanner)));

        let frame_limits = mechanism.limits.frame;
        let command_deadline = mechanism.deadlines.command;
        let session_limits = SessionLimits {
            read: command_deadline,
            preflight: command_deadline,
            dispatch: command_deadline,
            max_screenshot_bytes: usize::try_from(frame_limits.max_decoded_frame_bytes.get())
                .map_err(|error| {
                    BrowserRuntimeError::MechanismConfiguration(format!(
                        "decoded frame limit does not fit usize: {error}"
                    ))
                })?,
        };
        // Pod browsers open under exactly these validated inputs; their
        // host-side download staging lives beside the local profiles.
        let staging_parent = mechanism
            .profile_parent
            .parent()
            .ok_or_else(|| {
                BrowserRuntimeError::MechanismConfiguration(format!(
                    "profile root {} has no parent for pod staging",
                    mechanism.profile_parent.display()
                ))
            })?
            .join("pod-staging");
        let pods = PodBrowserOpener {
            rules: policy.rules().clone(),
            safety: Arc::clone(&safety),
            stop_host: stop_host.clone(),
            resource_limits: mechanism.limits,
            frame_limits,
            session_limits,
            startup: mechanism.deadlines.startup,
            command: mechanism.deadlines.command,
            shutdown: mechanism.deadlines.shutdown,
            takeover_lease: mechanism.deadlines.takeover_lease,
            staging_parent,
            ledger: Arc::clone(&ledger),
            read_model: Arc::clone(&read_model),
            multiplexer: Arc::clone(&multiplexer),
            artifacts: Arc::clone(&artifacts),
            external_content: Arc::clone(&external_content),
            projection: self.projection,
            max_pending_actions: self.max_pending_actions,
        };
        let launch = Arc::new(GovernedSessionLaunch {
            mechanism,
            stop_host,
            policy,
            safety,
            stream_id: self.stream_id,
            frame_limits,
            session_limits,
            artifacts,
            ledger,
            read_model,
            multiplexer,
            external_content,
            projection: self.projection,
            max_pending_actions: self.max_pending_actions,
            owner_preview: BTreeSet::new(),
        });
        Ok(PreparedBrowserRuntime {
            pods,
            idle_close: self.idle_close,
            launch,
        })
    }
}
