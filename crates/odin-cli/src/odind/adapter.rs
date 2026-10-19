//! Each `[adapter_backends.<id>]` uses the manifest executable `adapter.<id>`
//! and static argv through StopAuthority; adding a backend needs only declarations.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use odin_huginn::{adapter_executable_key, OdindConfig, RuntimeManifest};
use odin_omp::host_tools::adapter::{DeclaredAdapterBackend, DeclaredAdapterBackends};
use odin_omp::process::OmpWorkerLaunch;
use odin_process::{ScopeLifetime, ScopeLimits};
use odin_types::CorrelationId;

use crate::composition::{open_stop_authority, registered_runtime_binding};

pub(super) const ADAPTER_STATUS_TTL: StdDuration = StdDuration::from_secs(120);

/// Missing declarations leave capabilities unavailable; missing executables fail startup.
pub(super) fn declared_adapter_backends(
    config: &OdindConfig,
    manifest: &RuntimeManifest,
) -> Result<Arc<DeclaredAdapterBackends>, String> {
    if config.adapter_backends.is_empty() {
        return Ok(Arc::new(DeclaredAdapterBackends::none()));
    }
    // Validate every executable before opening any backend.
    let mut declared = Vec::new();
    for (id, backend) in &config.adapter_backends {
        let key = adapter_executable_key(id);
        let executable = manifest
            .executable(&key)
            .map_err(|error| format!("adapter {id}: {error}"))?
            .path
            .clone();
        declared.push((id, key, executable, backend.argv.clone()));
    }
    let stop_authority = open_stop_authority(
        manifest,
        &config.worker_bus,
        &config.paths.state_root.join("adapter-authority"),
        "adapter",
    )?;
    let mut backends = BTreeMap::new();
    for (id, key, executable, argv) in declared {
        let correlation_seed = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
        let correlation =
            CorrelationId::new(correlation_seed.as_str()).map_err(|error| error.to_string())?;
        let worker = OmpWorkerLaunch::new(
            Arc::clone(&stop_authority),
            correlation,
            "odind",
            key.as_str(),
            1,
            registered_runtime_binding(manifest, &key, &executable)?,
            ScopeLimits {
                lifetime: ScopeLifetime::Bounded(StdDuration::from_secs(24 * 60 * 60)),
                timeout_stop: StdDuration::from_secs(5),
                ..ScopeLimits::default()
            },
        )
        .map_err(|error| format!("adapter {id}: worker launch binding rejected: {error}"))?;
        tracing::info!(
            "adapter backend declared id={id} executable={} argv={}",
            executable.display(),
            argv.len()
        );
        let backend =
            DeclaredAdapterBackend::new(worker, executable.to_string_lossy().into_owned(), argv)
                .map_err(|error| format!("adapter {id}: {error}"))?;
        backends.insert(id.clone(), backend);
    }
    Ok(Arc::new(DeclaredAdapterBackends::new(backends)))
}

#[cfg(test)]
#[path = "tests/adapter.rs"]
mod tests;
