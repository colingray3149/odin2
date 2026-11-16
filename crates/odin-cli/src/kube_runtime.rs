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
mod create_many;
mod evidence;
mod execution;
mod extension;
#[cfg(test)]
#[path = "kube_runtime/tests/fake_api.rs"]
pub(crate) mod fake_api;
mod launch;
mod launch_queue;
mod models_config;
mod scoped_registration;
pub(crate) mod stage;
mod steer;

pub use admission::KubeCommandCoordinator;
pub use launch_queue::{LaunchQueue, QueuedLaunch, VramProbe};

/// Metered lane usage and effective caps, shared by snapshot reads and the view publisher.
pub(crate) fn budget_rows(
    snapshot: &odin_registry::Snapshot,
    huginn_root: &std::path::Path,
    now_ms: u64,
) -> Result<Vec<serde_json::Value>, String> {
    use odin_registry::{ComputeUsage, LaneBudgetKind, ObjectConfig, RaisedLaneBudgets};

    let usage = ComputeUsage::load(huginn_root)?;
    let raised = RaisedLaneBudgets::load(huginn_root)?;
    Ok(snapshot
        .objects
        .iter()
        .filter_map(|object| {
            let ObjectConfig::Lane(lane) = &object.config else {
                return None;
            };
            let used = usage.used(&object.id, lane.limits.window_days(), now_ms);
            let dimension = |kind: LaneBudgetKind| {
                let declared = kind.declared(&lane.limits);
                let cap = raised
                    .as_ref()
                    .and_then(|r| r.effective(&object.id, declared, kind))
                    .or(declared);
                serde_json::json!({"used": used.in_limit_units(kind), "cap": cap})
            };
            Some(serde_json::json!({
                "lane": object.id,
                "windowDays": lane.limits.window_days(),
                "coreHours": dimension(LaneBudgetKind::CoreHours),
                "gpuHours": dimension(LaneBudgetKind::GpuHours),
                "computeUsd": dimension(LaneBudgetKind::ComputeUsd),
            }))
        })
        .collect())
}

#[cfg(test)]
mod budget_view_tests {
    #[test]
    fn lane_rows_show_metered_hours_and_declared_caps() {
        let root = tempfile::tempdir().unwrap();
        let lane = odin_registry::schema::parse_object_toml(
            odin_registry::RegistryKind::Lane, "sweep", "lanes/sweep/lane.toml",
            "schema = 'odin.registry.v1'\nkind = 'lane'\nenabled = true\ndescription = 'test'\nproject = 'odin'\ndefault_seat = 'kubert'\nrequires_independent_review = false\n[limits]\ncore_hours = 10\ngpu_hours = 8\ncompute_usd = 20\nbudget_window_days = 7\n",
        ).unwrap();
        let snapshot = odin_registry::Snapshot::build(1, vec![lane]).unwrap();
        odin_registry::ComputeUsage::update(root.path(), |usage| {
            usage.charge_interval(&["sweep".to_owned()], 0, 3_600_000, 2.0, 1.0, 0.5);
        })
        .unwrap();
        let rows = super::budget_rows(&snapshot, root.path(), 3_600_000).unwrap();
        assert_eq!(rows[0]["lane"], "sweep");
        assert_eq!(
            rows[0]["coreHours"],
            serde_json::json!({"used": 2.0, "cap": 10})
        );
        assert_eq!(
            rows[0]["gpuHours"],
            serde_json::json!({"used": 1.0, "cap": 8})
        );
        assert_eq!(
            rows[0]["computeUsd"],
            serde_json::json!({"used": 0.5, "cap": 20})
        );
    }
}

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
    /// The run limits this launch resolved: the profile's declared values with
    /// the launch's overrides. Empty from resolution; the create dispatch fills it.
    pub limits: odin_domain::huginn::WorkloadLimits,
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
    /// The launch prompt text, staged as the last input. The create fills it
    /// from the caller; the pod's opening message quotes its head.
    pub opening_prompt: Option<String>,
    /// What the run is about; recon runs on them when the pod is up. The create fills it.
    pub seeds: Vec<String>,
    /// Declared egress hosts the launch left out because they did not
    /// resolve, with the cause. Empty from resolution; the create fills it
    /// from the Job's egress resolution so the pod's brief names them.
    pub unresolved_hosts: std::collections::BTreeMap<String, String>,
}

/// The launch prompt's share of a pod's opening message, in characters. A
/// longer prompt is cut here and the rest is read from its staged input.
pub(crate) const OPENING_PROMPT_CHARS: usize = 16_000;

/// The opening message of an admitted agent pod carrying its launch prompt:
/// the prompt verbatim up to [`OPENING_PROMPT_CHARS`], then a pointer to the
/// staged input that holds all of it.
pub(crate) fn opening_prompt_text(prompt: &str, staged_path: &str) -> String {
    let body = match prompt.char_indices().nth(OPENING_PROMPT_CHARS) {
        None => prompt.to_owned(),
        Some((cut, _)) => format!(
            "{}\n[continued in {staged_path}: read it with :raw]",
            &prompt[..cut]
        ),
    };
    format!(
        "Workload session admitted. Your task brief from the launcher follows; the profile \
         brief is in your session guidance.\n\n{body}"
    )
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
    /// The declared `seat.gateway_lane`, resolved as an agent pod's gateway is.
    pub gateway: Option<ScriptGateway>,
}

/// A script pod's gateway lane, resolved at admission from the serving node's
/// declared endpoint and the lane's Secret binding.
#[derive(Clone, Debug)]
pub struct ScriptGateway {
    pub lane: Option<String>,
    /// The project's `[agents]` role → lane pairs; nonempty means the project's own key.
    pub roles: std::collections::BTreeMap<String, String>,
    pub endpoint: odin_registry::schema::NodeGatewayEndpoint,
    pub credential: odin_kube::workload::WorkloadCredentialEnv,
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
    /// True only when the open boundary proves no session was created or started.
    pub refused_before_open: bool,
}

/// The daemon-side workload launch port the create dispatch consumes. The
/// port owns the shared snapshot handle, the composed workload surface,
/// and the supervisor session open; the dispatch owns the R3-governed
/// cluster actuation through the existing control surface.
#[async_trait::async_trait]
pub trait WorkloadLaunchPort: Send + Sync {
    /// Published profiles available for model-facing schema narrowing, independent of cluster health.
    fn launchable_profiles(&self) -> Vec<odin_omp::host_tools::LaunchableProfile>;

    /// The pure route verdict for one published profile: read-only over the
    /// shared snapshot, the composed surface, and the pinned projection.
    fn resolve_launch(&self, profile_id: &str) -> WorkloadResolve;

    /// Opens the child after creating its carrier, recording the caller's exact run for reports.
    async fn open_session(
        &self,
        inputs: &WorkloadLaunchInputs,
        launching_run: &odin_domain::RunId,
        operation_id: &odin_types::OperationId,
    ) -> Result<(), WorkloadSessionOpenError>;
}
