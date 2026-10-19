//! Kubernetes Job execution, ledger-backed content transport, and observed projections.
//! Worker launch and stop remain under [`odin_kernel::StopAuthority`].
//! Missing configuration or cluster connectivity produces typed unavailability.

pub mod artifacts;
mod backend;
pub mod claude_pod;
pub mod client;
pub mod config;
pub mod exec;
pub mod health;
pub mod job;
pub mod journal;
pub mod node_admin;
mod object_wait;
pub mod placement;
pub mod pod_phase;
pub mod reconciler;
pub mod state_carry;
pub mod status;
pub mod telemetry;
pub mod terminal_pod;
pub mod watch;
pub mod workload;

pub use crate::client::{KubeClient, KubeError};
pub use crate::config::KubeConfig;
pub use crate::job::{JobAction, JobLaunch, JobObservation};
pub use crate::journal::stored_launch;
pub use crate::reconciler::{JobReconciler, OrphanVerdict};
pub use crate::workload::{
    GatewayProbeError, ResolvedEgress, WorkloadCredentialEnv, WorkloadDisplayPlan,
    WorkloadGatewayTarget, WorkloadPlacement, WorkloadPodPlan, WorkloadStateCustody,
};

/// Builds the host-only Job actuator installed under the kernel's sole stop authority.
pub fn job_worker_backend(
    client: KubeClient,
) -> Result<std::sync::Arc<dyn odin_kernel::JobWorkerBackend>, KubeError> {
    Ok(std::sync::Arc::new(backend::KubernetesJobBackend::new(
        client,
    )?))
}
