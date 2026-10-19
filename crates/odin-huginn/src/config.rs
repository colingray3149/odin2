//! Listener and resource configuration, generated controller config, runtime manifests, and fixtures.

mod fixture;
mod huginn;
mod manifest;
mod odind;
mod validate;

#[cfg(test)]
mod sanctioned_fixture_override_tests;
#[cfg(test)]
mod strict_config_tests;

pub use fixture::{
    validate_sanctioned_fixture_overrides, OdindFixtureDisplay, OdindFixtureOverrides,
};
pub use huginn::{
    BindScope, ConfigError, ConnectionLimits, FileLimits, HuginnBindConfig, HuginnConfig,
    HuginnLimits, HuginnStatePaths, RenderLimits, SessionLimits, StreamLimits, TerminalLimits,
    TransferLimits, ValidatedBindAddress, ValidatedHuginnConfig,
};
pub use manifest::{
    adapter_executable_key, PathDigestRef, RuntimeManifest, REQUIRED_RUNTIME_MANIFEST_KEYS,
    RUNTIME_MANIFEST_SCHEMA,
};
pub use odind::{
    BrowserDisplaySource, OdindAdapterBackend, OdindAlertsConfig, OdindBrainConfig,
    OdindBrainEmbeddingConfig, OdindBrainSourceConfig, OdindBrowserConfig, OdindCatalogsConfig,
    OdindConfig, OdindCountedLaneWindow, OdindDelegationConfig, OdindDisplayConfig,
    OdindExecutablesConfig, OdindGatewayCredential, OdindGatewayHostCredential,
    OdindHermesAccountConfig, OdindHermesConfig, OdindHermesDiscordConfig,
    OdindHermesFinanceConfig, OdindHermesImmichConfig, OdindHermesMailTls,
    OdindHermesProviderConfig, OdindHermesVaultConfig, OdindIdentityConfig, OdindKubeConfig,
    OdindLaneBinding, OdindLaneWindow, OdindListenerConfig, OdindPathsConfig, OdindProjectConfig,
    OdindPublishConfig, OdindSeatBinding, OdindServingModelConfig, ODIND_CONFIG_SCHEMA,
};
