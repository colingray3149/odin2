//! Huginn / Remote backend. The wire protocol and client live in
//! `odin-huginn-client` and are re-exported here as `client` and `protocol`.
//!
//! Domain vocabulary — IDs, protocol requests/responses, and the ports
//! (`HuginnReadModel`, `HuginnCommandPort`, `HuginnStreamSource`, `FileGateway`,
//! `RenderGateway`, `OmpLivePlane`) — is owned by `odin_domain::huginn` and reused
//! here; this crate never redefines it.

pub mod approvals;
pub mod auth;
pub mod browser;
pub mod config;
mod control_core;
pub mod devices;
pub mod dispatch;
pub mod feed;
pub mod files;
pub mod fleet;
pub mod incidents;
pub mod kube;
pub mod private_network;
pub mod read_model;
pub mod renders;
pub mod router;
pub mod service;
pub mod sessions;
pub mod simulation;
pub mod state;
pub mod streams;

pub use odin_huginn_client::{client, protocol};

pub use crate::auth::{AuthError, TailnetAuthenticator};
pub use crate::client::{ClientError, RemoteClient, DeviceCredentialStore, LiveConnection};
pub use crate::config::{
    adapter_executable_key, BrowserDisplaySource, ConfigError, HuginnConfig, HuginnLimits,
    OdindAdapterBackend, OdindBrainConfig, OdindBrainEmbeddingConfig, OdindBrainRerankConfig,
    OdindBrowserConfig, OdindCatalogsConfig, OdindConfig, OdindCountedLaneWindow,
    OdindDisplayConfig, OdindExecutablesConfig, OdindGatewayHostCredential, OdindIdentityConfig,
    OdindKubeConfig, OdindLaneBinding, OdindLaneWindow, OdindListenerConfig, OdindModelCost,
    OdindModelLaneConfig, OdindPathsConfig, OdindProjectConfig, OdindPublishConfig,
    OdindResearchConfig, OdindSeatBinding, OdindServingModelConfig, OdindVpnTransport,
    PathDigestRef, RuntimeManifest, ValidatedBindAddress, ValidatedHuginnConfig,
    REQUIRED_RUNTIME_MANIFEST_KEYS, RUNTIME_MANIFEST_SCHEMA,
};
pub use crate::devices::{
    DeviceAdmin, DeviceGrant, DeviceRecord, DeviceStoreError, DeviceTrustStore, GrantClaim,
    NewDeviceGrant, NewDeviceRecord,
};
pub use crate::dispatch::{ConnectionRegistry, LiveDispatcher};
pub use crate::files::HuginnFileService;
pub use crate::private_network::{TailnetError, TailnetVerifier, VerifiedTailnetPeer};
pub use crate::renders::HuginnRenderService;
pub use crate::service::HuginnService;
pub use crate::state::{HuginnLiveState, NodePosture};
