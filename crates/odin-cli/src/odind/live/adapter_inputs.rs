//! Adapter runtime inputs: the declared backends feed both the dispatcher
//! and the health tracker, so both speak to the same backend under the same
//! descriptor identity.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_omp::host_tools::adapter::DeclaredAdapterBackends;

pub(super) struct AdapterInputs {
    pub(super) adapters: Arc<DeclaredAdapterBackends>,
    pub(super) adapter_status_ttl: StdDuration,
}

pub(super) fn compose(
    config: &odin_huginn::OdindConfig,
    manifest: &odin_huginn::RuntimeManifest,
) -> Result<AdapterInputs, String> {
    Ok(AdapterInputs {
        adapters: crate::adapter::declared_adapter_backends(config, manifest)?,
        adapter_status_ttl: crate::adapter::ADAPTER_STATUS_TTL,
    })
}
