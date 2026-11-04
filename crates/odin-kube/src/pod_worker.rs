//! What every Odin pod worker shares: the stop authority's Kubernetes pod
//! backend, the launch/recovery lock, and the worker identity a pod carries.
use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use odin_kernel::stop::{CorrelationId, StopAuthority, WorkerId};

use crate::client::KubeError;

mod backend;
pub use backend::KubernetesPodBackend;

// Running pods carry these names; they outlived the terminal pods they were made for.
const WORKER_ANNOTATION: &str = "odin.dev/terminal-worker";
const CORRELATION_ANNOTATION: &str = "odin.dev/terminal-correlation";

// Launches share a lock with startup cleanup of rows left by an earlier process.
pub type PodLifecycle = tokio::sync::Mutex<bool>;

pub async fn pod_lifecycle_guard<'a>(
    stops: &StopAuthority,
    lifecycle: &'a PodLifecycle,
) -> Result<tokio::sync::MutexGuard<'a, bool>, odin_kernel::stop::StopAuthorityError> {
    let mut recovered = lifecycle.lock().await;
    if !*recovered {
        for outcome in stops.recover_pending_pods(None)? {
            tracing::info!(
                "pod worker recovered worker={} verdict={:?}",
                outcome.worker_id,
                outcome.verdict
            );
        }
        *recovered = true;
    }
    Ok(recovered)
}

/// The stop correlation of a live session's pod: the same at launch and stop.
pub fn pod_correlation(session: &str) -> Result<CorrelationId, KubeError> {
    CorrelationId::new(&session.replace('-', ""))
        .map_err(|error| KubeError::rejected(error.to_string()))
}

pub(crate) fn label_worker(
    metadata: &mut ObjectMeta,
    worker: &WorkerId,
    correlation: &CorrelationId,
) {
    let annotations = metadata.annotations.get_or_insert_with(BTreeMap::new);
    annotations.insert(WORKER_ANNOTATION.to_owned(), worker.as_str().to_owned());
    annotations.insert(
        CORRELATION_ANNOTATION.to_owned(),
        correlation.as_str().to_owned(),
    );
}

pub(crate) fn stop_error(error: odin_kernel::stop::StopAuthorityError) -> KubeError {
    KubeError::Storage {
        reason: format!("pod ledger operation failed: {error}"),
    }
}

#[cfg(test)]
mod tests {}
