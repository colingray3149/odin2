//! Lazy k3s connections, durable R3 command admission, and posture-gated journal recovery.

use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use async_trait::async_trait;

use odin_cli::browser_runtime;
use odin_domain::huginn as live;
use odin_domain::ApprovalId;
use odin_huginn::dispatch::AuthenticatedCommandPort;
use odin_huginn::NodePosture;
use odin_kernel::{ApprovalCommand, ApprovalGate, ApprovalRedirect, ConsumeOutcome, StopAuthority};

use odin_ledger::approval::{Approval, ApprovalScope, NewApproval};
use odin_ledger::Ledger;
use time::OffsetDateTime;

use crate::huginn_conformance;

#[path = "kube_bindings.rs"]
mod bindings;
pub use bindings::{KubeLaunchBinding, WorkloadDeploymentFacts, WorkloadExtensionIdentity};
#[path = "kube_spheres.rs"]
pub(super) mod spheres;

/// Production kube surface identities: one bounded surface artifact capsule
/// and one durable kube-events stream shared by every kube projection.
pub(super) const KUBE_SURFACE_SESSION: &str = "00000000-0000-4000-8000-000000000631";
pub(super) const KUBE_SURFACE_LANE: &str = "odin-kube-surface";
const KUBE_EVENTS_STREAM: &str = "00000000-0000-4000-8000-000000000625";

/// Lazily-connected k3s runtime cell for one configured cluster. A
/// configured surface that starts unavailable (k3s down) retries on every
/// use and every pump tick; once the API server appears it connects exactly
/// once and stays connected. Nothing here mutates the cluster and no
/// in-memory fallback cluster exists.
pub(super) struct KubeRuntimeCell {
    config: odin_kube::config::KubeConfig,
    ledger: Arc<Mutex<Ledger>>,
    stops: Arc<StopAuthority>,
    pod_lifecycle: Arc<odin_kube::pod_worker::PodLifecycle>,
    artifact_root: PathBuf,
    snapshot: Arc<odin_registry::Snapshot>,
    published: Option<Arc<odin_registry::SnapshotHandle>>,
    /// The generated controller config revision, pinned once at composition
    /// — the admitted generation's revision, never a value re-read at call
    /// time.
    config_revision: u64,
    launch_binding: Option<KubeLaunchBinding>,
    /// The pinned declared image identity of this deployment. Required with
    /// kube composition; workload admission refuses without one.
    workload_identity: WorkloadExtensionIdentity,
    connected:
        tokio::sync::Mutex<Option<(Arc<odin_huginn::kube::KubeControl>, odin_kube::KubeClient)>>,
    jobs: odin_kube::watch::JobCache,
    offload: Arc<Mutex<Option<Arc<crate::live::offload::Offload>>>>,
}
pub(super) struct CellInputs {
    pub config: odin_kube::config::KubeConfig,
    pub ledger: Arc<Mutex<Ledger>>,
    pub stops: Arc<StopAuthority>,
    pub artifact_root: PathBuf,
    pub snapshot: Arc<odin_registry::Snapshot>,
    pub config_revision: u64,
    pub launch_binding: Option<KubeLaunchBinding>,
    pub workload_identity: WorkloadExtensionIdentity,
}

impl KubeRuntimeCell {
    #[cfg(test)]
    pub(super) fn new(inputs: CellInputs) -> Arc<Self> {
        Self::with_publication(inputs, None)
    }

    pub(super) fn new_published(
        inputs: CellInputs,
        published: Arc<odin_registry::SnapshotHandle>,
    ) -> Arc<Self> {
        Self::with_publication(inputs, Some(published))
    }

    fn with_publication(
        inputs: CellInputs,
        published: Option<Arc<odin_registry::SnapshotHandle>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: inputs.config,
            ledger: inputs.ledger,
            stops: inputs.stops,
            pod_lifecycle: Arc::default(),
            artifact_root: inputs.artifact_root,
            snapshot: inputs.snapshot,
            published,
            config_revision: inputs.config_revision,
            launch_binding: inputs.launch_binding,
            workload_identity: inputs.workload_identity,
            connected: tokio::sync::Mutex::new(None),
            jobs: odin_kube::watch::JobCache::default(),
            offload: Arc::default(),
        })
    }
    pub(super) fn set_offload(&self, offload: Arc<crate::live::offload::Offload>) {
        *self.offload.lock().expect("offload binding") = Some(offload);
    }

    /// The connected cluster client (connected once, shared).
    pub(crate) async fn client(&self) -> Result<odin_kube::KubeClient, odin_kube::KubeError> {
        self.parts().await.map(|(_, client)| client)
    }

    pub(crate) fn stop_authority(&self) -> Arc<StopAuthority> {
        Arc::clone(&self.stops)
    }

    pub(crate) async fn pod_lifecycle(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, bool>, odin_kernel::stop::StopAuthorityError> {
        odin_kube::pod_worker::pod_lifecycle_guard(&self.stops, &self.pod_lifecycle).await
    }

    /// Caller holds [`Self::pod_lifecycle`] until the object exists.
    pub(crate) async fn admit_parallel_run(
        &self,
        client: &odin_kube::KubeClient,
        seat: &odin_domain::SeatId,
    ) -> Result<(), odin_kube::KubeError> {
        odin_kube::admit_parallel_run(client, &self.snapshot(), seat, None).await
    }

    /// Caller holds [`Self::pod_lifecycle`] until the object exists.
    /// Refuses when the lane's `limits.pods` — the declaration, or a typed
    /// `task.steer` raise above it — is already filled by the lane's live
    /// Jobs and Claude pods.
    pub(crate) async fn admit_lane_pod_budget(
        &self,
        client: &odin_kube::KubeClient,
        lane: &odin_domain::LaneId,
    ) -> Result<(), odin_kube::KubeError> {
        let huginn = self.artifact_root.parent();
        odin_kube::admit_lane_pod_budget(client, &self.snapshot(), lane, huginn, None).await
    }

    /// Refuses when a live worker of this lane has filled `limits.wall_seconds`.
    /// The clock is the lease beside `artifact_root`'s parent, the huginn root.
    pub(crate) fn admit_lane_wall(
        &self,
        lane: &odin_domain::LaneId,
    ) -> Result<(), odin_kube::KubeError> {
        odin_kube::admit_lane_wall(&self.snapshot(), lane, self.artifact_root.parent())
    }

    /// Where lane budgets, raises and metered compute usage live.
    pub(crate) fn huginn_root(&self) -> Option<&std::path::Path> {
        self.artifact_root.parent()
    }

    pub fn workload_identity(&self) -> &WorkloadExtensionIdentity {
        &self.workload_identity
    }

    /// The controller configuration revision pinned at composition — the
    /// admitted generation's revision for every launch this cell admits.
    pub fn config_revision(&self) -> u64 {
        self.config_revision
    }

    /// An artifact store over this cell's ledger and confined root, for
    /// digest-verified reads of registered admission artifacts.
    pub fn artifact_store(&self) -> odin_kube::artifacts::ArtifactStore {
        odin_kube::artifacts::ArtifactStore::new(
            Arc::clone(&self.ledger),
            self.artifact_root.clone(),
        )
    }

    /// The durable artifact ledger this cell registers admission material
    /// into: the same ledger the artifact store above wraps, handed to the
    /// workload producers so generated admission material binds to the
    /// launching run at registration time.
    pub fn ledger(&self) -> Arc<Mutex<Ledger>> {
        Arc::clone(&self.ledger)
    }

    /// The cell's declared cluster binding: the ownership coordinates the
    /// admission journal scopes its stored run definitions by.
    pub fn kube_config(&self) -> &odin_kube::KubeConfig {
        &self.config
    }

    /// Owned Jobs from the live job watch; `None` while that watch is down.
    pub fn job_cache(&self) -> &odin_kube::watch::JobCache {
        &self.jobs
    }

    /// Currently connected control, if any. `None` means the cell has not
    /// connected yet, or a connect is in progress: not a per-run release
    /// failure. Callers that need to force a connect use [`Self::parts`].
    pub fn control(&self) -> Option<Arc<odin_huginn::kube::KubeControl>> {
        self.connected
            .try_lock()
            .ok()?
            .as_ref()
            .map(|(control, _)| Arc::clone(control))
    }

    /// Connected control, waiting out a connect already in progress. `None`
    /// only when the cell has not connected yet.
    pub async fn connected_control(&self) -> Option<Arc<odin_huginn::kube::KubeControl>> {
        self.connected
            .lock()
            .await
            .as_ref()
            .map(|(control, _)| Arc::clone(control))
    }

    /// The current published container profile by registry id. Only enabled
    /// declarations are candidates; the caller owns seat/capability checks.
    pub fn container_profile(&self, name: &str) -> Option<odin_registry::schema::ContainerToml> {
        let snapshot = self.snapshot();
        let object = snapshot.object(odin_registry::RegistryKind::Container, name)?;
        match &object.config {
            odin_registry::schema::ObjectConfig::Container(container) if container.enabled => {
                Some(container.as_ref().clone())
            }
            _ => None,
        }
    }

    /// Every enabled published profile with its container identity — the
    /// digest its Jobs carry — for the monitoring kernel's profile lookup.
    pub fn monitored_profiles(
        &self,
    ) -> Vec<(odin_domain::Digest, odin_registry::schema::ContainerToml)> {
        self.snapshot()
            .objects
            .iter()
            .filter_map(|object| match &object.config {
                odin_registry::schema::ObjectConfig::Container(container) if container.enabled => {
                    odin_registry::ContainerIdentity::calculate(container)
                        .ok()
                        .map(|identity| (identity.digest(), (**container).clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Every enabled workload profile that declares `[monitoring]`, keyed by
    /// the bounded label value its pods carry (`odin.dev/workload`).
    pub fn monitored_workloads(
        &self,
    ) -> Vec<(String, odin_registry::schema::WorkloadMonitoringToml)> {
        odin_registry::compose_workload_profiles(&self.snapshot().objects)
            .into_iter()
            .filter_map(|profile| {
                let monitoring = profile.profile.monitoring?;
                Some((odin_kube::job::bounded_label_value(&profile.id), monitoring))
            })
            .collect()
    }

    /// Enabled profiles with executable images, in registry order.
    pub fn launchable_profiles(&self) -> Vec<odin_omp::host_tools::LaunchableProfile> {
        spheres::launchable_profiles(&self.snapshot())
    }

    /// Pin the current published snapshot for the duration of a request.
    pub fn snapshot(&self) -> Arc<odin_registry::Snapshot> {
        self.published
            .as_ref()
            .map_or_else(|| Arc::clone(&self.snapshot), |handle| handle.current())
    }

    /// Real label composition context for Job creation, or `None` when the
    /// daemon cannot resolve it without fabrication.
    pub fn launch_binding(&self) -> Option<KubeLaunchBinding> {
        self.launch_binding.clone()
    }

    /// The deployment's declared kube bounds: `(request_timeout,
    /// teardown_timeout)`. The cell is the composition root's only seam for
    /// these config facts — the coordinator derives its mutation deadlines
    /// from them instead of fabricating constants.
    pub fn kube_bounds(&self) -> (StdDuration, StdDuration) {
        (self.config.request_timeout, self.config.teardown_timeout)
    }

    pub(super) async fn parts(
        &self,
    ) -> Result<(Arc<odin_huginn::kube::KubeControl>, odin_kube::KubeClient), odin_kube::KubeError>
    {
        let mut guard = self.connected.lock().await;
        if let Some(connected) = &*guard {
            return Ok((Arc::clone(&connected.0), connected.1.clone()));
        }
        let client = odin_kube::client::KubeClient::connect(self.config.clone()).await?;
        self.stops
            .register_pod_backend(Arc::new(odin_kube::pod_worker::KubernetesPodBackend::new(
                client.clone(),
                self.config.cluster.clone(),
                self.config.namespace.clone(),
            )?))
            .map_err(|error| odin_kube::KubeError::unavailable(error.to_string()))?;
        let mut reconciler = odin_kube::JobReconciler::new(
            client.clone(),
            Arc::clone(&self.ledger),
            Arc::clone(&self.stops),
            Arc::clone(&self.pod_lifecycle),
            self.artifact_root.clone(),
        )?;
        if let Some(published) = &self.published {
            reconciler = reconciler.with_seat_limits(Arc::clone(published));
        }
        let offload = Arc::clone(&self.offload);
        reconciler = reconciler.with_external_compute(Arc::new(move |lane, exempt| {
            let binding = offload.lock().expect("offload binding");
            binding.as_ref().map_or((0.0, 0.0, 0.0), |offload| {
                offload
                    .runs()
                    .iter()
                    .filter(|run| {
                        !run.state.finished()
                            && exempt != Some(&run.run_id)
                            && run.lanes.iter().any(|id| id == lane.as_str())
                    })
                    .fold((0.0, 0.0, 0.0), |(cores, gpus, usd), run| {
                        let seconds = run.remaining_seconds() as f64;
                        (
                            cores + f64::from(run.cores) * seconds,
                            gpus + f64::from(run.gpus) * seconds,
                            usd + run.usd_per_hour * seconds / 3_600.0,
                        )
                    })
            })
        }));

        let session = live::LiveSessionId::parse(KUBE_SURFACE_SESSION)
            .map_err(|error| odin_kube::KubeError::unavailable(error.to_string()))?;
        let lane = odin_domain::LaneId::new(KUBE_SURFACE_LANE)
            .map_err(|error| odin_kube::KubeError::unavailable(error.to_string()))?;
        let catalog = odin_huginn::kube::KubeCatalog::new(
            odin_huginn::kube::SurfaceArtifacts::new(
                session,
                lane,
                const { NonZeroU64::new(65_536).expect("nonzero bound") },
                const { NonZeroU64::new(1_048_576).expect("nonzero bound") },
            ),
            const { NonZeroUsize::new(256).expect("nonzero bound") },
            const { NonZeroU64::new(16_384).expect("nonzero bound") },
            const { NonZeroU64::new(128).expect("nonzero bound") },
        );
        let control = Arc::new(odin_huginn::kube::KubeControl::new(
            catalog,
            Arc::new(reconciler),
            Arc::clone(&self.ledger),
            client.clone(),
        ));
        *guard = Some((Arc::clone(&control), client.clone()));
        Ok((control, client))
    }
}

/// Ledger-only outcome of one kube admission pass.
#[derive(Debug)]
enum KubeAdmission {
    /// The approval exists but nothing consumed it yet: the paired device
    /// still owes its decision.
    Pending(Approval),
    /// The exact command binding consumed the approval exactly once.
    Consumed(Approval),
}

pub(super) struct RuntimeCommandPort {
    ledger: Arc<Mutex<Ledger>>,
    read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    browser: Option<Arc<browser_runtime::BrowserRoutes>>,
    streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
    kube: Option<Arc<KubeRuntimeCell>>,
    kube_backpressure: live::StreamBackpressureLimits,
    kube_frame_sequence: AtomicU64,
    conversation: Option<Arc<crate::conversation_surface::ConversationSurface>>,
    live: Option<Arc<dyn live::OmpLivePlane>>,
    recovery: Option<Arc<odin_omp::live::runtime::ProductionBridgeRuntimeFactory>>,
    /// Without a board, simulation commands return unavailable.
    simulation: Option<Arc<crate::simulation::SimulationDesk>>,
    project_events: Option<Arc<crate::project_event::ProjectIntake>>,
    /// The device-bound session authority; without it, an authenticated
    /// open answers a typed unavailable.
    device_open: Option<Arc<super::device_open::DeviceOpenAuthority>>,
    catalog: Option<Arc<super::model_catalog::ModelCatalog>>,
    /// `hermes.model_gateway`, for spend reads.
    gateway: Option<String>,
    /// Shares the single declared Claude session store; never opens a second transcript source.
    claude_runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    /// Pinned registry and this daemon's node, for the compute fan-out.
    registry: Option<Arc<odin_registry::SnapshotHandle>>,
    local_node: Option<String>,
    /// Registered SSH executable. Remote samples die with the request.
    ssh: Option<std::path::PathBuf>,
    owner_preview: std::collections::BTreeSet<String>,
    /// The features refresh pair; `FeaturesRefresh` wakes the pump through it.
    features: Option<crate::features::FeatureRefresh>,
}


impl RuntimeCommandPort {
    pub(super) fn new(
        ledger: Arc<Mutex<Ledger>>,
        read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
        browser: Option<Arc<browser_runtime::BrowserRoutes>>,
        streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
        kube: Option<Arc<KubeRuntimeCell>>,
        kube_backpressure: live::StreamBackpressureLimits,
    ) -> Self {
        Self {
            ledger,
            read_model,
            browser,
            streams,
            kube,
            kube_backpressure,
            kube_frame_sequence: AtomicU64::new(0),
            conversation: None,
            live: None,
            recovery: None,
            simulation: None,
            project_events: None,
            device_open: None,
            catalog: None,
            gateway: None,
            claude_runtime: None,
            registry: None,
            local_node: None,
            ssh: None,
            owner_preview: std::collections::BTreeSet::new(),
            features: None,
        }
    }

    pub(super) fn with_recovery(
        mut self,
        factory: Arc<odin_omp::live::runtime::ProductionBridgeRuntimeFactory>,
    ) -> Self {
        self.recovery = Some(factory);
        self
    }

    pub(super) fn with_features(mut self, features: crate::features::FeatureRefresh) -> Self {
        self.features = Some(features);
        self
    }

    pub(super) fn with_owner_preview(mut self, ids: std::collections::BTreeSet<String>) -> Self {
        self.owner_preview = ids;
        self
    }

    pub(super) fn with_claude_runtime(
        mut self,
        runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    ) -> Self {
        self.claude_runtime = runtime;
        self
    }



    pub(super) fn with_project_events(
        mut self,
        intake: Option<Arc<crate::project_event::ProjectIntake>>,
    ) -> Self {
        self.project_events = intake;
        self
    }

    pub(super) fn with_simulation(
        mut self,
        simulation: Option<Arc<crate::simulation::SimulationDesk>>,
    ) -> Self {
        self.simulation = simulation;
        self
    }

    /// Pause, resume, and abort require kube approval; other commands use the board.
    async fn execute_simulation(
        &self,
        device: live::DeviceId,
        command: live::SimulationCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let desk = self.simulation.as_ref().ok_or_else(|| {
            live::HuginnProtocolError::unavailable(
                "simulationUnavailable",
                "this plane has no simulation desk",
            )
        })?;
        let read_model = &self.read_model;
        let kube_revision = |resource: &live::KubeResourceRef| {
            read_model
                .get(&live::ObjectRef {
                    kind: live::ObjectKind::KubeResource,
                    id: odin_huginn::kube::view::kube_object_id(resource),
                })
                .ok()
                .flatten()
                .map(|snapshot| snapshot.revision.get())
        };
        match desk.kube_command(&command, kube_revision)? {
            Some(kube) => self.execute_kube(device, kube).await,
            None => desk
                .execute_board(&command, OffsetDateTime::now_utc())
                .map(live::HuginnResponse::Command),
        }
    }

    pub(super) fn with_live(mut self, plane: Arc<dyn live::OmpLivePlane>) -> Self {
        self.live = Some(plane);
        self
    }

    /// Binds the device-bound session authority: an authenticated open
    /// mints, claims, and opens under the calling device's identity.
    pub(super) fn with_device_open(
        mut self,
        device_open: Option<Arc<super::device_open::DeviceOpenAuthority>>,
    ) -> Self {
        self.device_open = device_open;
        self
    }

    /// The conversation surface, or the typed refusal every conversation request gets without one.
    fn conversation(
        &self,
    ) -> Result<&Arc<crate::conversation_surface::ConversationSurface>, live::HuginnProtocolError>
    {
        self.conversation.as_ref().ok_or_else(|| {
            live::HuginnProtocolError::unavailable(
                "conversationUnavailable",
                "this plane has no conversation surface",
            )
        })
    }

    pub(super) fn with_conversation(
        mut self,
        conversation: Option<Arc<crate::conversation_surface::ConversationSurface>>,
    ) -> Self {
        self.conversation = conversation;
        self
    }
    pub(super) fn with_gateway(mut self, gateway: Option<String>) -> Self {
        self.gateway = gateway;
        self
    }
    pub(super) fn with_catalog(
        mut self,
        catalog: Option<Arc<super::model_catalog::ModelCatalog>>,
    ) -> Self {
        self.catalog = catalog;
        self
    }
    pub(super) fn with_compute(
        mut self,
        registry: Arc<odin_registry::SnapshotHandle>,
        local_node: String,
        ssh: std::path::PathBuf,
    ) -> Self {
        self.registry = Some(registry);
        self.local_node = Some(local_node);
        self.ssh = Some(ssh);
        self
    }

    /// Runs the durable R3 admission gate for one kube command against the
    /// ledger alone. First sight requests the approval with the submitting
    /// device as its immutable issuer; a re-issue journals the exact command
    /// through the one canonical kube spec and then consumes the approval at
    /// the exact stored revision — the consumption names the journaled row
    /// through `approvals.consumed_by_command_id`; any other device is
    /// refused before the gate can mutate or consume; an exact replay of
    /// the already consumed command by its own issuer returns the stored
    /// consumption untouched.
    fn admit_kube_command(
        ledger: &Mutex<Ledger>,
        device: &live::DeviceId,
        command: &live::KubeCommand,
    ) -> Result<KubeAdmission, live::HuginnProtocolError> {
        let command_id = command.command_id().clone();
        let approval_id = ApprovalId::new(format!("kube-{command_id}")).map_err(|error| {
            live::HuginnProtocolError::unavailable("kubeApprovalIdentity", error)
        })?;
        let now = OffsetDateTime::now_utc();
        let issuer = device.to_string();
        // One canonical durable kube command spec — the exact journaled row
        // an approval consumption names — with the gate scope derived from
        // it, so the approval binding and the command binding are one
        // construction and cannot diverge.
        let spec = odin_huginn::kube::kube_command_spec(command, &approval_id, now)
            .map_err(|error| live::HuginnProtocolError::unavailable("kubeCommandSpec", error))?;
        let scope = ApprovalScope {
            target_kind: spec.target_kind.clone(),
            target_id: spec.target_id.clone(),
            capability_id: spec.capability_id.clone(),
            arguments_digest: spec.arguments_hash,
        };

        let mut ledger = ledger
            .lock()
            .map_err(|error| live::HuginnProtocolError::unavailable("kubeLedgerLock", error))?;
        let approval = ledger
            .approval(&approval_id)
            .map_err(|error| live::HuginnProtocolError::unavailable("kubeApprovalLookup", error))?;
        let approval = match approval {
            None => {
                ApprovalGate::new(&mut ledger)
                    .request(NewApproval {
                        approval_id: approval_id.clone(),
                        issuer: issuer.clone(),
                        scope: scope.clone(),
                        requested_at: now,
                        expires_at: now + time::Duration::minutes(15),
                    })
                    .map_err(|error| {
                        live::HuginnProtocolError::unavailable("kubeApprovalRequest", error)
                    })?;
                ledger
                    .approval(&approval_id)
                    .map_err(|error| {
                        live::HuginnProtocolError::unavailable("kubeApprovalLookup", error)
                    })?
                    .ok_or_else(|| {
                        live::HuginnProtocolError::unavailable(
                            "kubeApprovalLookup",
                            format!("approval {approval_id} was not stored"),
                        )
                    })?
            }
            Some(approval) => {
                if approval.issuer != issuer {
                    // The approval is bound to the device that requested
                    // it. No other device may consume, replay, or redirect
                    // it — including after consumption.
                    return Err(live::HuginnProtocolError::Conflict {
                        code: "kubeApprovalIssuer".to_owned(),
                        message: "kube approval was requested by a different device".to_owned(),
                    });
                }
                if approval.status == odin_domain::ApprovalStatus::Consumed
                    && approval.consumed_by_command_id.as_ref() == Some(&command_id)
                    && approval.scope == scope
                {
                    // Exact replay of the already admitted command by its
                    // own issuer: the stored consumption is the standing
                    // authority. The persisted record is returned without
                    // re-consumption, re-approval, or new authority.
                    return Ok(KubeAdmission::Consumed(approval));
                }
                // The consumption names this command as a durable foreign
                // key (`approvals.consumed_by_command_id` references
                // `commands`), so the exact command is journaled through the
                // one canonical spec after the approval exists and before
                // the gate consumes — and only after the issuer check,
                // never on the read-only exact-replay path. An identical
                // retry reclaims the same row; a different payload cannot
                // overwrite it and stays denied by the exact-scope gate
                // below.
                ledger.record_command(&spec).map_err(|error| {
                    live::HuginnProtocolError::unavailable("kubeCommandJournal", error)
                })?;
                let consumed = ApprovalGate::new(&mut ledger)
                    .authorize_command(
                        odin_domain::EffectClass::R3,
                        ApprovalCommand {
                            command_id: &command_id,
                            approval_id: Some(&approval_id),
                            scope: &scope,
                            expected_revision: Some(approval.revision),
                            now,
                        },
                    )
                    .map_err(|error| {
                        live::HuginnProtocolError::unavailable("kubeApprovalConsume", error)
                    })?;
                match consumed {
                    ConsumeOutcome::Consumed(approval) => approval,
                    ConsumeOutcome::Redirect(ApprovalRedirect::Denied(_)) => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalDenied".to_owned(),
                            message: "kube approval was denied".to_owned(),
                        });
                    }
                    ConsumeOutcome::Redirect(_) => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalRedirect".to_owned(),
                            message: "kube approval did not authorize this command binding"
                                .to_owned(),
                        });
                    }
                    // Workload mutations are R3 and cannot bypass approval.
                    ConsumeOutcome::NotRequired => {
                        return Err(live::HuginnProtocolError::Conflict {
                            code: "kubeApprovalRequired".to_owned(),
                            message: "kube mutation requires an exact approval".to_owned(),
                        });
                    }
                }
            }
        };
        drop(ledger);
        if approval.consumed_by_command_id.is_none() {
            Ok(KubeAdmission::Pending(approval))
        } else {
            Ok(KubeAdmission::Consumed(approval))
        }
    }

    /// Consume exact device/run/arguments/revision approval before cluster contact.
    /// First requests return pending approval; only the issuing device can consume it.
    /// Applied commands publish revision deltas and durable event frames.
    async fn execute_kube(
        &self,
        device: live::DeviceId,
        command: live::KubeCommand,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        let cell = match &self.kube {
            Some(cell) => cell,
            None => {
                return Err(live::HuginnProtocolError::unavailable(
                    "kubeUnavailable",
                    "this plane has no kube cell",
                ))
            }
        };
        let control = cell
            .parts()
            .await
            .map(|(control, _)| control)
            .map_err(|error| live::HuginnProtocolError::unavailable("kubeUnavailable", error))?;

        // Exact-revision admission under the ledger lock. Nothing in this
        // phase touches KubeControl or the cluster.
        let approval = match Self::admit_kube_command(&self.ledger, &device, &command)? {
            KubeAdmission::Pending(approval) => {
                self.publish_approval(&approval)?;
                // Pending: the paired device decides through the existing
                // approval route, then re-issues this identical command.
                return Ok(live::HuginnResponse::Command(
                    live::CommandReceipt::Accepted {
                        command_id: command.command_id().clone(),
                    },
                ));
            }
            KubeAdmission::Consumed(approval) => approval,
        };
        self.publish_approval(&approval)?;

        // Recheck run ownership and revision, journal the verdict, then mutate the cluster.
        let receipt = control
            .execute(&command, &approval.approval_id, OffsetDateTime::now_utc())
            .await?;
        for note in control.publish(&self.read_model, []).await {
            tracing::info!("kube command publication {note:?}");
        }
        for frame in control.drain_events().await {
            let sequence = self.kube_frame_sequence.fetch_add(1, Ordering::SeqCst) + 1;
            huginn_conformance::publish_frame(
                &self.streams,
                huginn_conformance::StreamFrameSpec {
                    stream_id: live::StreamId::parse(KUBE_EVENTS_STREAM).map_err(|error| {
                        live::HuginnProtocolError::unavailable("kubeStreamIdentity", error)
                    })?,
                    kind: live::LiveStreamKind::KubeEvents,
                    mode: live::LiveStreamMode::Durable,
                    sequence,
                    control_revision: frame.event.revision,
                    content: frame.content,
                },
                &self.kube_backpressure,
                OffsetDateTime::now_utc(),
            )
            .map_err(|error| live::HuginnProtocolError::unavailable("kubeFrame", error))?;
        }
        let _ = control.drain_statuses().await;
        Ok(live::HuginnResponse::Command(receipt))
    }

    /// Publishes one approval projection through the shared read model.
    fn publish_approval(&self, approval: &Approval) -> Result<(), live::HuginnProtocolError> {
        odin_huginn::approvals::ApprovalProjection::new(Arc::clone(&self.read_model))
            .publish(
                odin_huginn::approvals::ApprovalView::try_from(approval)?,
                std::iter::empty(),
                std::iter::empty(),
            )
            .map(|_delta| ())
    }
}

#[async_trait]
impl live::HuginnCommandPort for RuntimeCommandPort {
    async fn execute(
        &self,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match request {
            live::HuginnRequest::BrowserObserve(_)
            | live::HuginnRequest::BrowserCommand(_)
            | live::HuginnRequest::KubeCommand(_)
            | live::HuginnRequest::ApprovalDecision(_)
            | live::HuginnRequest::RecoverCfdOperation(_)
            | live::HuginnRequest::ConversationStatus
            | live::HuginnRequest::ConversationThread(_)
            | live::HuginnRequest::ConversationSay(_)
            | live::HuginnRequest::ConversationReply(_)
            | live::HuginnRequest::SeatModelSet(_)
            | live::HuginnRequest::Spend(_)
            | live::HuginnRequest::ModelCatalog
            | live::HuginnRequest::Models
            | live::HuginnRequest::FeaturesRefresh
            | live::HuginnRequest::Jobs
            | live::HuginnRequest::Compute
            | live::HuginnRequest::LaneCommand(_)
            | live::HuginnRequest::SimulationCommand(_)
            | live::HuginnRequest::ProjectEvent(_)
            | live::HuginnRequest::OpenSession(_)
            | live::HuginnRequest::EmergencyStop(_) => {
                Err(live::HuginnProtocolError::Unauthenticated)
            }
            _ => Err(unsupported("misrouted Huginn request")),
        }
    }
}

#[async_trait]
impl AuthenticatedCommandPort for RuntimeCommandPort {
    async fn execute_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        // Register the continuation before deciding so it resumes from the durable decision.
        match (&self.conversation, request) {
            (Some(conversation), live::HuginnRequest::ApprovalDecision(command)) => {
                let approval_id = command.approval_id.clone();
                let approved = command.decision == live::ApprovalDecision::Approve;
                conversation
                    .decide(
                        &approval_id,
                        approved,
                        self.route_authenticated(
                            device,
                            live::HuginnRequest::ApprovalDecision(command),
                        ),
                    )
                    .await
            }
            (_, request) => self.route_authenticated(device, request).await,
        }
    }
}

impl RuntimeCommandPort {
    async fn route_authenticated(
        &self,
        device: live::DeviceId,
        request: live::HuginnRequest,
    ) -> Result<live::HuginnResponse, live::HuginnProtocolError> {
        match (&self.browser, request) {
            (Some(browser), live::HuginnRequest::ApprovalDecision(command)) => {
                if browser.serves_decision(&command.approval_id, self.ledger.as_ref()) {
                    browser
                        .execute_authenticated(
                            device,
                            live::HuginnRequest::ApprovalDecision(command),
                        )
                        .await
                } else {
                    self.decide_approval(command, device)
                }
            }
            (
                Some(browser),
                request @ (live::HuginnRequest::BrowserObserve(_)
                | live::HuginnRequest::BrowserCommand(_)),
            ) => browser.execute_authenticated(device, request).await,
            (None, live::HuginnRequest::ApprovalDecision(command)) => {
                self.decide_approval(command, device)
            }
            (None, live::HuginnRequest::BrowserObserve(_))
            | (None, live::HuginnRequest::BrowserCommand(_)) => {
                Err(unsupported("browser command adapter"))
            }
            (_, live::HuginnRequest::KubeCommand(command)) => {
                self.execute_kube(device, command).await
            }
            (_, live::HuginnRequest::RecoverCfdOperation(command)) => {
                self.recover_cfd_operation(device, command).await
            }
            (_, live::HuginnRequest::SimulationCommand(command)) => {
                self.execute_simulation(device, command).await
            }
            (_, live::HuginnRequest::ConversationStatus) => self.conversation()?.status(None).await,
            (_, live::HuginnRequest::ConversationThread(request)) => {
                self.conversation()?.thread(request).await
            }
            (_, live::HuginnRequest::ConversationSay(request)) => {
                self.conversation()?.say(device, request).await
            }
            (_, live::HuginnRequest::ConversationReply(request)) => {
                self.conversation()?.committed_reply(&request.command_id)
            }
            (_, live::HuginnRequest::SeatModelSet(request)) => {
                self.conversation()?.set_model(device, request).await
            }
            (_, live::HuginnRequest::Spend(request)) => {
                let root = self
                    .claude_runtime
                    .as_ref()
                    .and_then(|runtime| runtime.compute_usage_root())
                    .or_else(|| {
                        self.kube
                            .as_ref()
                            .and_then(|cell| cell.huginn_root().map(std::path::Path::to_path_buf))
                    });
                crate::huginn_spend::read(self.gateway.clone(), request, root.as_deref()).await
            }
            (_, live::HuginnRequest::Models) => {
                crate::huginn_spend::models(self.gateway.clone()).await
            }
            (_, live::HuginnRequest::FeaturesRefresh) => {
                crate::features::refresh(self.features.as_ref()).await
            }
            (_, live::HuginnRequest::Jobs) => {
                let runtime = self.claude_runtime.clone().ok_or_else(|| {
                    live::HuginnProtocolError::unavailable(
                        "jobsUnavailable",
                        "background job board is not bound",
                    )
                })?;
                Ok(live::HuginnResponse::Jobs(serde_json::json!({
                    "running": runtime.running_jobs(),
                })))
            }
            (_, live::HuginnRequest::Compute) => {
                crate::compute_route::answer(
                    self.registry.as_ref(),
                    self.local_node.as_deref(),
                    self.ssh.as_deref(),
                    self.kube.as_ref(),
                )
                .await
            }
            (_, live::HuginnRequest::ClaudeTranscript(request)) => {
                let runtime = self.claude_runtime.clone().ok_or_else(|| {
                    live::HuginnProtocolError::unavailable(
                        "claudeTranscriptUnavailable",
                        "Claude session store is not bound",
                    )
                })?;
                tokio::task::spawn_blocking(move || {
                    let reply = odin_hermes::runtime::claude::read_owner_transcript(
                        &runtime,
                        odin_hermes::runtime::claude::ClaudeReadRequest {
                            session: request.session,
                            since: request.since,
                        },
                    )
                    .map_err(|error| {
                        live::HuginnProtocolError::unavailable("claudeTranscriptUnavailable", error)
                    })?;
                    serde_json::to_value(reply)
                        .map(live::HuginnResponse::ClaudeTranscript)
                        .map_err(|error| {
                            live::HuginnProtocolError::unavailable(
                                "claudeTranscriptUnavailable",
                                error,
                            )
                        })
                })
                .await
                .map_err(|error| {
                    live::HuginnProtocolError::unavailable("claudeTranscriptUnavailable", error)
                })?
            }
            (_, live::HuginnRequest::ModelCatalog) => match &self.catalog {
                Some(catalog) => catalog.read().await,
                None => Err(live::HuginnProtocolError::unavailable(
                    "modelCatalog",
                    "this plane has no model catalog",
                )),
            },
            (_, live::HuginnRequest::EmergencyStop(request)) => {
                crate::emergency_stop::start(device, &request)
            }
            (_, live::HuginnRequest::ProjectEvent(report)) => match &self.project_events {
                Some(intake) => intake.report(device, report).await,
                None => Err(live::HuginnProtocolError::unavailable(
                    "projectEventUnavailable",
                    "this plane has no project event router",
                )),
            },
            (_, live::HuginnRequest::LaneCommand(command)) => match &self.live {
                Some(plane) => crate::lane_command::execute(&self.ledger, plane, command).await,
                None => Err(live::HuginnProtocolError::unavailable(
                    "livePlaneUnavailable",
                    "this plane has no live plane",
                )),
            },
            (_, live::HuginnRequest::OpenSession(request)) => match &self.device_open {
                Some(authority) => authority
                    .open_session_for_device(device, request)
                    .await
                    .map(live::HuginnResponse::SessionOpened)
                    .map_err(odin_huginn::state::live_error_into_protocol),
                None => Err(live::HuginnProtocolError::unavailable(
                    "deviceSessionAuthority",
                    "this plane has no device session authority",
                )),
            },
            (_, request) => <Self as live::HuginnCommandPort>::execute(self, request).await,
        }
    }
}

/// The journal pass before each kube watch opens. `recover()` re-drives
/// admitted but unsettled journal operations against the real cluster —
/// replayed creates and restarts — so it is armed ONLY for the snapshot
/// authority: a demoted node still carries pending journal rows from before
/// demotion, and replaying them here would re-drive cluster mutations
/// without authority. Observation — the watch's own list — stays live on
/// every posture and feeds only the local read model.
pub(super) async fn kube_reconcile_tick(
    posture: NodePosture,
    control: &odin_huginn::kube::KubeControl,
    log: &mut crate::pumps::WatchLog,
) {
    if posture == NodePosture::Authoritative {
        if let Err(error) = control.recover().await {
            log.note(format!("journal recovery failed: {error}"));
        }
        // Recovery returns before cleanup when a replay is unavailable.
        // Outstanding marked residue only — not every registered run.
        if let Err(error) = control
            .reconciler()
            .reap_marked_residue(time::OffsetDateTime::now_utc())
            .await
        {
            log.note(format!("finished-run cleanup failed: {error}"));
        }
    }
}

fn unsupported(operation: &str) -> live::HuginnProtocolError {
    live::HuginnProtocolError::Unsupported {
        operation: operation.to_owned(),
    }
}

#[path = "kube_approval.rs"]
mod approval;
#[path = "kube_recovery.rs"]
mod recovery;

#[cfg(test)]
#[path = "tests/kube.rs"]
mod tests;

#[path = "kube_browser.rs"]
mod browser;
use browser::open_pod_browser;
#[path = "kube_pod_exec.rs"]
mod pod_exec;
#[cfg(test)]
#[path = "kube_pod_lifecycle_tests.rs"]
mod pod_lifecycle_tests;
pub(crate) use pod_exec::KubePodWorkerExec;

#[path = "kube_carrier.rs"]
mod carrier;
pub(crate) use carrier::KubeWorkloadCarrier;
