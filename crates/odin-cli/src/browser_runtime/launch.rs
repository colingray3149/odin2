use std::ffi::OsString;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_browser::capability::ArtifactPublisher;
use odin_browser::config::{
    BrowserConfig, ChromiumLaunch, Deadlines, DisplaySource, PlaywrightLaunch, ResourceLimits,
    Viewport,
};
use odin_browser::safety::BrowserSafetyGate;
use odin_browser::session::{BrowserSession, FrameWiring, SessionError, SessionLimits};
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
    pub stop_authority: Arc<StopAuthority>,
    pub worker_binding: RegisteredServiceBinding,
}

#[derive(Debug, Error)]
pub enum BrowserRuntimeError {
    #[error("browser mechanism configuration is invalid")]
    MechanismConfiguration,
    #[error("browser policy input could not be read")]
    PolicyRead,
    #[error("browser policy input is invalid")]
    PolicyInvalid,
    #[error("browser policy references an unavailable or mismatched capability")]
    PolicyCapability,
    #[error("browser interaction capability is unavailable or mismatched")]
    InteractionCapability,
    #[error("browser protected-values input could not be read securely")]
    ProtectedValuesRead,
    #[error("browser protected-values input must be a regular mode-0600 file")]
    ProtectedValuesPermissions,
    #[error("browser protected-values input is invalid")]
    ProtectedValuesInvalid,
    #[error("browser scanner configuration is invalid")]
    ScannerConfiguration,
    #[error("browser session launch failed: {source:?}")]
    SessionLaunch {
        #[source]
        source: Box<SessionError>,
    },
}

impl BrowserRuntimeError {}

pub struct BrowserRuntimeLaunch {
    pub projection: BrowserProjection,
    pub coordinator: BrowserCommandCoordinator,
    /// Opens pod browsers under the same validated inputs.
    pub pods: PodBrowserOpener,
}

impl BrowserRuntimeConfig {
    pub async fn launch(
        self,
        registry: &[RegistryObject],
        ledger: Arc<Mutex<Ledger>>,
        read_model: Arc<MaterializedReadModel>,
        multiplexer: Arc<BoundedMultiplexer>,
        artifacts: Arc<FsPublishedArtifactStore>,
        external_content: Arc<FsExternalContentIndex>,
    ) -> Result<BrowserRuntimeLaunch, BrowserRuntimeError> {
        let decoded_frame_bytes = u32::try_from(self.max_stream_frame_bytes.get())
            .map_err(|_| BrowserRuntimeError::MechanismConfiguration)?;
        let encoded_frame_bytes = decoded_frame_bytes
            .checked_add(2)
            .and_then(|bytes| bytes.checked_div(3))
            .and_then(|groups| groups.checked_mul(4))
            .ok_or(BrowserRuntimeError::MechanismConfiguration)?;
        let mut resource_limits = ResourceLimits::default();
        resource_limits.frame.max_decoded_frame_bytes = NonZeroU32::new(decoded_frame_bytes)
            .ok_or(BrowserRuntimeError::MechanismConfiguration)?;
        resource_limits.frame.max_encoded_frame_bytes = NonZeroU32::new(encoded_frame_bytes)
            .ok_or(BrowserRuntimeError::MechanismConfiguration)?;
        let deadlines = Deadlines {
            takeover_lease: self.takeover_lease,
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
            .map_err(|_| BrowserRuntimeError::MechanismConfiguration)?;

        let policy_input = load_policy_input(&self.policy_file)?;
        let policy = policy_from_input(policy_input, registry)?;
        validate_registry_capability(
            registry,
            &CapabilityId::new(BROWSER_INTERACT_CAPABILITY)
                .map_err(|_| BrowserRuntimeError::InteractionCapability)?,
            BROWSER_INTERACT_VERSION,
            EffectClass::R2,
            false,
        )
        .map_err(|_| BrowserRuntimeError::InteractionCapability)?;
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
        .map_err(|_| BrowserRuntimeError::ScannerConfiguration)?;
        let safety = Arc::new(BrowserSafetyGate::new(protected, Box::new(scanner)));

        let frame_limits = mechanism.limits.frame;
        let command_deadline = mechanism.deadlines.command;
        let session_limits = SessionLimits {
            read: command_deadline,
            preflight: command_deadline,
            dispatch: command_deadline,
            max_screenshot_bytes: usize::try_from(frame_limits.max_decoded_frame_bytes.get())
                .map_err(|_| BrowserRuntimeError::MechanismConfiguration)?,
        };
        // Pod browsers open under exactly these validated inputs; their
        // host-side download staging lives beside the local profiles.
        let staging_parent = mechanism
            .profile_parent
            .parent()
            .ok_or(BrowserRuntimeError::MechanismConfiguration)?
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
        let publisher: Arc<dyn ArtifactPublisher> = artifacts.clone();
        let session = BrowserSession::open_durable(
            mechanism,
            stop_host,
            policy,
            safety,
            FrameWiring {
                stream_id: self.stream_id,
                limits: frame_limits,
                publisher,
                stream: true,
            },
            session_limits,
            Arc::clone(&ledger),
        )
        .await
        .map_err(|source| BrowserRuntimeError::SessionLaunch {
            source: Box::new(source),
        })?;

        let projection = BrowserProjection::spawn(
            session,
            read_model.clone(),
            multiplexer,
            artifacts,
            external_content,
            self.projection,
        );
        let coordinator = BrowserCommandCoordinator::new(
            ledger,
            read_model,
            projection.handle(),
            self.max_pending_actions,
        );
        Ok(BrowserRuntimeLaunch {
            projection,
            coordinator,
            pods,
        })
    }
}

impl BrowserRuntimeLaunch {
    pub fn into_parts(self) -> (BrowserProjection, BrowserCommandCoordinator) {
        (self.projection, self.coordinator)
    }
}
