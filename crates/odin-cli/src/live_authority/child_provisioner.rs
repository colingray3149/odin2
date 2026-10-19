use std::sync::{Arc, Mutex};

use odin_domain::huginn::LiveSessionId;
use odin_domain::{LaneId, SeatId};
use odin_huginn::OdindConfig;

use super::{block_on, SessionAuthorityPool, SupervisorHandle};
use crate::authority_provision::LaunchSelection;

/// Real governed-child provisioning over the pool: the parent's pinned
/// snapshot composition, a minted child token through the operator write
/// path, the child's exact capsule authority, and an idle child session
/// opened through the live supervisor with the governance-fixed worker
/// provider/model. The request can never choose the model.
pub struct PoolChildProvisioner {
    _pool: Arc<SessionAuthorityPool>,
    config: OdindConfig,
    provider: String,
    model: String,
    token_ttl_seconds: u64,
    supervisor: SupervisorHandle,
    bridge_ledger: Arc<Mutex<odin_ledger::Ledger>>,
}

impl PoolChildProvisioner {
    pub fn new(
        pool: Arc<SessionAuthorityPool>,
        config: &OdindConfig,
        provider: String,
        model: String,
        token_ttl_seconds: u64,
        supervisor: SupervisorHandle,
        bridge_ledger: Arc<Mutex<odin_ledger::Ledger>>,
    ) -> Self {
        Self {
            _pool: pool,
            config: config.clone(),
            provider,
            model,
            token_ttl_seconds,
            supervisor,
            bridge_ledger,
        }
    }
}

impl PoolChildProvisioner {
    /// The parent's accepted plan is the operator approval that authorizes
    /// delegation. Checked before minting any child authority; the
    /// delegation owner inherits that acceptance into the child run after
    /// the idle session opens and before its first prompt.
    fn verify_parent_plan(&self, parent_session: &odin_domain::SessionId) -> Result<(), String> {
        let ledger = self
            .bridge_ledger
            .lock()
            .map_err(|_| "bridge ledger lock poisoned".to_owned())?;
        let parent_run = odin_domain::RunId::new(format!("run:live:{}", parent_session.as_str()))
            .map_err(|error| format!("parent run id is invalid: {error}"))?;
        if !ledger
            .plan_is_accepted(&parent_run)
            .map_err(|error| format!("parent plan verdict failed: {error}"))?
        {
            return Err("the parent run has no accepted plan; delegation is refused".to_owned());
        }
        Ok(())
    }

    /// Opens the composed child session through the live supervisor with the
    /// exact pinned provider/model the caller derived from declaration. The
    /// request can never choose the model.
    fn open_child(
        &self,
        composition: &crate::authority_provision::SessionComposition,
        provider: &str,
        model: &str,
        title: &str,
        open_tab: bool,
    ) -> Result<LiveSessionId, String> {
        // supervisor.open calls the factory, which performs registration-only
        // pool.open_session for the exact child binding/root before process
        // launch. No eager private backend or socket is created here.
        let supervisor = self
            .supervisor
            .get()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| "live supervisor is not running".to_owned())?;
        let request = odin_domain::huginn::OpenSessionRequest {
            command_id: composition.command_id.clone(),
            seat_id: composition.seat.clone(),
            project_id: composition.project.clone(),
            slice_id: composition.slice.clone(),
            provider: odin_domain::huginn::ProviderName::new(provider)
                .map_err(|error| format!("configured worker provider is invalid: {error}"))?,
            model: odin_domain::huginn::ModelName::new(model)
                .map_err(|error| format!("configured worker model is invalid: {error}"))?,
            // The child's purpose names its session and its Zellij tab.
            title: Some(title.to_owned()).filter(|title| !title.is_empty()),
            target_node: odin_domain::NodeId::new(&self.config.identity.node)
                .map_err(|error| format!("controller node id is invalid: {error}"))?,
            open_tab,
            initial_prompt: None,
            workload: None,
            served_revision: Some(composition.snapshot_revision),
        };
        // The child token was minted before this call (provision_child), so
        // the open is admitted against the exact ensured authority.
        let summary = block_on(supervisor.open(request))?;
        if summary.session_id != composition.live_session {
            return Err(format!(
                "supervisor opened session {} but provisioning derived {}",
                summary.session_id, composition.live_session
            ));
        }
        Ok(composition.live_session)
    }
}

impl odin_omp::host_tools::delegation::ChildAuthorityProvisioner for PoolChildProvisioner {
    fn provision_child(
        &self,
        parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &odin_domain::SessionId,
        child: odin_omp::host_tools::delegation::ChildOpen<'_>,
    ) -> Result<LiveSessionId, String> {
        let _ = (parent_lane, parent_session);
        self.verify_parent_plan(parent_session)?;
        // The child opens with the governance-fixed worker pair; the
        // composition is derived from that same selection, proven one of the
        // parent seat's declared launch options before any token exists.
        let composition = crate::authority_provision::compose(
            &self.config,
            parent_seat.as_str(),
            child.project.as_str(),
            child.command,
            LaunchSelection::new(&self.provider, &self.model),
        )?;
        crate::authority_provision::mint_for_child_session(
            &self.config,
            &composition,
            self.token_ttl_seconds,
        )?;
        self.open_child(
            &composition,
            &self.provider,
            &self.model,
            child.title,
            false,
        )
    }

    /// Resolves the target seat's declared worker profile from the strict
    /// configuration. The resolution is positional — the seat's first
    /// declared launch option — and the pair it returns is passed explicitly
    /// into composition, minting, and the open, so nothing downstream
    /// re-derives or reorders it.
    fn seat_worker_profile(
        &self,
        target_seat: &odin_domain::SeatId,
        requested: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(String, String), String> {
        let binding = self
            .config
            .seats
            .iter()
            .find(|seat| seat.seat == *target_seat)
            .ok_or_else(|| {
                format!(
                    "target seat {target_seat} has no configured seat binding; \
                     cross-seat delegation is declaration-driven and refuses \
                     unconfigured seats"
                )
            })?;
        // A delegation override must be declared and must not change the seat's saved choice.
        if let Some(requested) = requested {
            let declared = binding.launch_options.iter().any(|option| {
                option.provider.as_str() == requested.provider
                    && option.model.as_str() == requested.model
            });
            if !declared {
                return Err(format!(
                    "{requested} is not a declared launch option of seat {target_seat}; it \
                     declares {}",
                    binding
                        .launch_options
                        .iter()
                        .map(|option| format!("{}/{}", option.provider, option.model))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            tracing::info!(
                "delegation launch seat={target_seat} launch={requested} \
                 scope=this-delegation"
            );
            return Ok((requested.provider.clone(), requested.model.clone()));
        }
        // Use the saved launch, falling back to the first declared option.
        let launch =
            odin_omp::live::seat_launch::SeatLaunchStore::new(&self.config.paths.state_root)
                .select(target_seat.as_str(), &binding.launch_options)
                .ok_or_else(|| format!("target seat {target_seat} declares no launch options"))?;
        Ok((launch.provider.to_string(), launch.model.to_string()))
    }

    /// Checks the parent plan, declared launch, composition, and cross-seat
    /// terminal availability before approval without creating resources.
    fn preflight_child(
        &self,
        parent_seat: &SeatId,
        _parent_lane: &LaneId,
        parent_session: &odin_domain::SessionId,
        child_project: &odin_domain::ProjectId,
        target_seat: Option<&odin_domain::SeatId>,
        launch: Option<&odin_omp::host_tools::delegation::WorkerLane>,
    ) -> Result<(), String> {
        self.verify_parent_plan(parent_session)?;
        // Compose from the parent seat for same-seat work, otherwise the target.
        let readiness = match target_seat {
            // Same-seat workers use the fixed worker launch selection.
            None => crate::authority_provision::preflight_compose(
                &self.config,
                parent_seat.as_str(),
                child_project.as_str(),
                LaunchSelection::new(&self.provider, &self.model),
            )?,
            Some(target_seat) => {
                // The target seat's declared worker profile is resolved
                // first, then passed into the derivation, which proves it
                // one of the target seat's declared launch options: a
                // profile the seat does not declare refuses typed, before
                // any surface observation.
                let (declared_provider, declared_model) =
                    self.seat_worker_profile(target_seat, launch)?;
                let readiness = crate::authority_provision::preflight_compose(
                    &self.config,
                    target_seat.as_str(),
                    child_project.as_str(),
                    LaunchSelection::new(&declared_provider, &declared_model),
                )?;
                // The cross-seat route opens a visible governed tab
                // (`open_tab = true`), and `open_terminal` requires the
                // declared attach client: an unconfigured attach command
                // refuses typed here, exactly as the open would.
                if self.config.executables.attach_command.is_empty() {
                    return Err(
                        "terminal attach command is unconfigured; the governed cross-seat \
                         tab cannot open (terminal_attach_command_unconfigured)"
                            .to_owned(),
                    );
                }
                readiness
            }
        };
        let _ = readiness;
        // The supervisor is execution's next hard prerequisite
        // (`open_child` refuses typed when it is not running).
        let supervisor = self
            .supervisor
            .get()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| "live supervisor is not running".to_owned())?;
        // Only cross-seat work opens a terminal; check the declared live target
        // through the supervisor without creating a session or guessing socket paths.
        if target_seat.is_some() {
            block_on(supervisor.terminal_target()).map(|_| ())
        } else {
            Ok(())
        }
    }

    fn provision_child_for_seat(
        &self,
        parent_seat: &SeatId,
        parent_lane: &LaneId,
        parent_session: &odin_domain::SessionId,
        child: odin_omp::host_tools::delegation::ChildOpen<'_>,
        target_seat: &odin_domain::SeatId,
    ) -> Result<LiveSessionId, String> {
        self.verify_parent_plan(parent_session)?;
        let _ = (parent_seat, parent_lane);
        // The target seat's declared worker profile is resolved ONCE, up
        // front: the durable delegation link row is built from this exact
        // pair, so the same pair composes, mints, and opens below.
        let (declared_provider, declared_model) =
            self.seat_worker_profile(target_seat, child.launch)?;
        // The child composes from the TARGET seat's pinned composition —
        // its own slice, lane, and project root — never the parent's. The
        // derivation proves the resolved pair one of that seat's declared
        // launch options before any token exists.
        let composition = crate::authority_provision::compose(
            &self.config,
            target_seat.as_str(),
            child.project.as_str(),
            child.command,
            LaunchSelection::new(&declared_provider, &declared_model),
        )?;
        if composition.seat != *target_seat {
            return Err(format!(
                "composed child seat {} does not name the requested target seat {target_seat}",
                composition.seat
            ));
        }
        crate::authority_provision::mint_for_child_session(
            &self.config,
            &composition,
            self.token_ttl_seconds,
        )?;
        // open_tab=true: the delegated target-seat child is visible as a
        // governed tab of the SAME session surface; a configured attach
        // client is required or the open fails typed, never phantom.
        self.open_child(
            &composition,
            &declared_provider,
            &declared_model,
            child.title,
            true,
        )
    }
}
