//! Listener and resource configuration, generated controller config, and runtime manifests.

mod google_reconnect;
mod huginn;
mod manifest;
mod odind;
mod validate;

#[cfg(test)]
mod strict_config_tests;

pub use huginn::{
    ConfigError, ConnectionLimits, FileLimits, HuginnBindConfig, HuginnConfig, HuginnLimits,
    HuginnStatePaths, RenderLimits, SessionLimits, StreamLimits, TerminalLimits, TransferLimits,
    ValidatedBindAddress, ValidatedHuginnConfig, CONNECTIONS_CEILING, SESSIONS_CEILING,
};
pub use manifest::{
    adapter_executable_key, PathDigestRef, RuntimeManifest, REQUIRED_RUNTIME_MANIFEST_KEYS,
    RUNTIME_MANIFEST_SCHEMA,
};
pub use odind::{
    BrowserDisplaySource, OdindAdapterBackend, OdindAlertsConfig, OdindBrainConfig,
    OdindBrainEmbeddingConfig, OdindBrainRerankConfig, OdindBrainSourceConfig, OdindBrowserConfig,
    OdindCatalogsConfig, OdindConfig, OdindConsultAgyConfig, OdindConsultConfig,
    OdindCountedLaneWindow, OdindDelegationConfig, OdindDisplayConfig, OdindExecutablesConfig,
    OdindGatewayCredential, OdindGatewayHostCredential, OdindGoogleReconnectConfig,
    OdindHermesAccountConfig, OdindHermesConfig, OdindHermesDiscordConfig,
    OdindHermesFinanceConfig, OdindHermesMailTls,
    OdindHermesProviderConfig, OdindHermesVaultConfig, OdindIdentityConfig, OdindKubeConfig,
    OdindLaneBinding, OdindLaneWindow, OdindListenerConfig, OdindModelCost, OdindModelLaneConfig,
    OdindPathsConfig, OdindProjectConfig, OdindPublishConfig, OdindResearchConfig,
    OdindSeatBinding, OdindServingModelConfig, OdindVpnTransport, ODIND_CONFIG_SCHEMA,
};
