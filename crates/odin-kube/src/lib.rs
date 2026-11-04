//! Kubernetes Job execution, ledger-backed content transport, and observed projections.
//! Worker launch and stop remain under [`odin_kernel::StopAuthority`].
//! Missing configuration or cluster connectivity produces typed unavailability.

mod admission;
pub mod artifacts;
pub use admission::{
    admit_lane_pod_budget, admit_lane_wall, admit_parallel_run, declared_lane_pods,
    refuse_lane_pods, LANE_POD_LIMIT_KEY, PARALLEL_RUN_LIMIT_KEY,
};
mod backend;
pub mod claude_pod;
pub mod client;
pub mod config;
pub mod exec;
pub mod health;
pub mod inventory;
pub mod job;
pub mod journal;
pub mod node_admin;
mod object_wait;
pub mod placement;
pub mod pod_phase;
pub mod pod_worker;
pub mod reconciler;
pub mod state_carry;
pub mod status;
pub mod telemetry;
#[cfg(test)]
mod test_api;
pub mod watch;
pub mod workload;

pub use crate::client::{KubeClient, KubeError};
pub use crate::config::{KubeConfig, VpnTransportBinding};
pub use crate::job::{JobAction, JobLaunch, JobObservation};
pub use crate::journal::stored_launch;
pub use crate::reconciler::{JobReconciler, OrphanVerdict};
pub use crate::workload::{
    company_directory, GatewayProbeError, ResolvedEgress, WorkloadCredentialEnv,
    WorkloadDisplayPlan, WorkloadGatewayTarget, WorkloadPlacement, WorkloadPodPlan,
    WorkloadStateBinding,
};

/// Builds the host-only Job actuator installed under the kernel's sole stop authority.
pub fn job_worker_backend(
    client: KubeClient,
) -> Result<std::sync::Arc<dyn odin_kernel::JobWorkerBackend>, KubeError> {
    Ok(std::sync::Arc::new(backend::KubernetesJobBackend::new(
        client,
    )?))
}
