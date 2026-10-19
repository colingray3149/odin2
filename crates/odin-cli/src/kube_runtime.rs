//! The real kube capability owner: every compiled `kube.workload.*` /
//! `kube.snapshot.read` handler executes against the actual batch/v1 Jobs of
//! the configured k3s cluster through the daemon's
//! [`KubeControl`](odin_huginn::kube::KubeControl) surface.
//!
//! Authorization constraints (shared with `browser_runtime`):
//!
//! - Model-visible invocation is never raw. The only production route is the
//!   kernel-minted `PreparedEffect` permit decoded by the compiled adapter in
//!   `odin-omp`; this owner receives the host-bound
//!   [`HostInvocation`](odin_omp::host_tools::HostInvocation) scope
//!   and never trusts model-named authority dimensions.
//! - Scope: every binding requires a seat-bound invocation. `create` derives
//!   the run, project, and lane from the bound scope (the model names only an
//!   admitted published profile); `snapshot.read` addresses the bound run.
//!   Run-addressed mutations take the schema-sanctioned run id and the exact
//!   opaque `expectedResourceVersion` observed at admission — the
//!   compare-and-swap, passed to the reconciler verbatim and never
//!   re-fetched after the permit — while every ownership gate runs against
//!   the authoritative cluster observation before any mutation.
//! - Identity: the image is the published profile's identity-bearing `base`,
//!   the argv is the published identity-bearing `scripts`, the worker
//!   incarnation is host-minted, operation identities are the kernel-minted
//!   permit's (the sole durable settlement key), and idempotency digests
//!   derive from the admitted operation content — never from model
//!   arguments beyond the published schema.
//! - Evidence: extractor bindings validate the recorded handler output
//!   against the exact wire contract and never re-execute the capability.
//!
//! Failure typing follows effect provenance: pre-actuation refusals (an
//! unconfigured cell, a missing published binding, a failed connect, or
//! configured bounds exceeding the published capability timeout) are
//! typed `HostToolError::Unavailable` — no effect attempted, no fake
//! success — while anything reported after dispatch (a reconciler
//! unavailability verdict, an elapsed actuation bound, a journaled
//! unavailable rejection) is `HostToolError::Uncertain`, because the
//! settlement state cannot be proven. Reads yield the schema's
//! `unavailable` settlement, and no simulated cluster or fabricated
//! response exists.
//!
//! The owner is split along its authority boundaries:
//!
//! - [`admission`] handles invocation, scope checks, arguments, deadlines, and permit replay.
//! - [`launch`] owns trusted-host identity derivation and published-profile
//!   launch construction.
//! - [`execution`] owns the mutation and read handlers that actuate or
//!   observe the real cluster through the control surface.
//! - [`evidence`] owns the wire contracts, the settlement projection, and
//!   the evidence extractors.
//!
//! Public paths of this module are the canonical API surface consumed by
//! `odind`; they are preserved verbatim through re-exports.

use thiserror::Error;

mod admission;
mod evidence;
mod execution;
mod extension;
mod launch;
mod models_config;
mod scoped_registration;

pub use admission::KubeCommandCoordinator;

/// The trusted-host launch inputs of one admitted workload profile,
/// resolved by the daemon through the SHARED pinned-snapshot handle —
/// post-publish adoption is immediate, no restart, no stale seam.
#[derive(Clone, Debug)]
pub struct WorkloadLaunchInputs {
    pub profile: odin_registry::ComposedWorkloadProfile,
    pub provider: String,
    pub model: String,
    pub slice_id: odin_domain::SliceId,
    pub seat: odin_domain::SeatId,
    pub project: odin_domain::ProjectId,
    pub lane: odin_domain::LaneId,
    pub target_node: odin_domain::NodeId,
    /// The snapshot revision that admitted the profile: recorded in the
    /// session's durable workload binding.
    pub snapshot_revision: u64,
    /// Maps the route's credential handle to a Secret key and carrier environment
    /// variable. Changing the gateway endpoint does not change this mapping.
    pub credential: odin_kube::workload::WorkloadCredentialEnv,
    /// The explicitly selected target node's declared gateway endpoint,
    /// parsed once by the owning node-declaration seam: the staged model
    /// config carries its URI as `baseUrl` and the egress pin derives the
    /// same host and effective port — never a second lookup or a default.
    pub gateway: odin_registry::schema::NodeGatewayEndpoint,
    /// The declared input artifacts this launch stages read-only into the
    /// agent pod, in staging order with their exact in-pod paths.
    /// Empty from resolution; the create dispatch fills it once each named
    /// artifact is proven in the ledger.
    pub staged_inputs: Vec<odin_domain::huginn::WorkloadInputBinding>,
}

/// The resolution verdict for one `kube.workload.create` profile id:
/// `NotWorkload` falls through to the container-profile path, `Launch`
/// carries the admitted inputs, and `Refused` is a typed refusal that
/// already names the declared fallback offer where one exists.
pub enum WorkloadResolve {
    NotWorkload,
    Launch(Box<WorkloadLaunchInputs>),
    /// A script pod: the declared command runs in the
    /// declared image; no agent, no session, no model route.
    Script(Box<ScriptLaunchInputs>),
    Refused(String),
}

/// The admitted inputs of one script pod launch.
#[derive(Clone, Debug)]
pub struct ScriptLaunchInputs {
    pub profile: odin_registry::ComposedWorkloadProfile,
    pub seat: odin_domain::SeatId,
    pub project: odin_domain::ProjectId,
    /// The bound seat's session lane on the declared project.
    pub lane: odin_domain::LaneId,
}

/// Typed failure of the post-create workload session open. Every failure
/// at this port is strictly post-effect — the carrier Job already landed
/// durably — so this error only ever reports the agent attachment, never
/// the cluster mutation. The owning surface's typed attach code and reason
/// stay structured through the port boundary instead of laundering into a
/// flat invalid-arguments string.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("workload session attach failed [{code}]: {detail}")]
pub struct WorkloadSessionOpenError {
    /// The typed attach code from the owning surface (for example the
    /// supervisor bridge's `omp_bridge_start` refusal), preserved verbatim.
    pub code: String,
    /// The attach failure reason; names the carrier pod and its phase when
    /// the underlying surface classification provides them.
    pub detail: String,
}

/// The daemon-side workload launch port the create dispatch consumes. The
/// port owns the shared snapshot handle, the composed workload surface,
/// and the supervisor session open; the dispatch owns the R3-governed
/// cluster actuation through the existing control surface.
#[async_trait::async_trait]
pub trait WorkloadLaunchPort: Send + Sync {
    /// The pure route verdict for one published profile: read-only over the
    /// shared snapshot, the composed surface, and the pinned projection.
    fn resolve_launch(&self, profile_id: &str) -> WorkloadResolve;

    /// Opens the session with its workload manifest only after creating the carrier Job.
    async fn open_session(
        &self,
        inputs: &WorkloadLaunchInputs,
        run_id: &odin_domain::RunId,
        operation_id: &odin_types::OperationId,
    ) -> Result<(), WorkloadSessionOpenError>;
}
