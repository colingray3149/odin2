//! Declared Hermes runtime and its governed daemon bindings.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_cli::browser_runtime::LocalBrowser;
use odin_domain::{CapabilityId, LaneId, ProjectId, SeatId};
use odin_huginn::{NodePosture, OdindConfig};
use odin_kernel::CapabilityContract;
use odin_ledger::Ledger;
use odin_omp::host_tools::delegation::{GovernedTaskOwner, TaskOwner};
use odin_omp::live::supervisor::LiveSeatBinding;
use odin_registry::{RegistryObject, SnapshotHandle};

use crate::authority::{declared_conversation_binding, DeclaredConversationBinding};
use crate::hermes::{hermes_settings, DaemonIntakeAuthority};

pub(super) struct HermesComposition {
    pub(super) route: Option<DeclaredConversationBinding>,
    pub(super) ledger_path: PathBuf,
    pub(super) runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
}

pub(super) struct ConversationAuthority<'a> {
    pub(super) registry: &'a [RegistryObject],
    pub(super) contracts: &'a BTreeMap<CapabilityId, CapabilityContract>,
    pub(super) seat_bindings: &'a [LiveSeatBinding],
    pub(super) session_lanes: &'a BTreeMap<(SeatId, ProjectId), LaneId>,
    pub(super) posture: NodePosture,
}

pub(super) fn compose(
    config: &OdindConfig,
    authority: ConversationAuthority<'_>,
    task_owner: &Option<Arc<GovernedTaskOwner>>,
    bridge_ledger: &Arc<Mutex<Ledger>>,
) -> Result<HermesComposition, String> {
    let ConversationAuthority {
        registry,
        contracts,
        seat_bindings,
        session_lanes,
        posture,
    } = authority;
    // The declared surfaces share the governed authority, ledger, and task owner.
    let settings = config.hermes.as_ref().map(hermes_settings).transpose()?;
    let route = settings
        .as_ref()
        .and_then(|settings| settings.discord.as_ref())
        .map(|discord| {
            declared_conversation_binding(
                registry,
                contracts,
                seat_bindings,
                session_lanes,
                discord,
                posture,
            )
        })
        .transpose()?;
    let ledger_path = config.paths.state_root.join("ledger.sqlite3");
    let runtime = match settings {
        Some(settings) => {
            let hermes_ledger = Ledger::open(&ledger_path)
                .map_err(|error| format!("could not open hermes ledger: {error}"))?;
            let adapter_ledger = Ledger::open(&ledger_path)
                .map_err(|error| format!("could not open hermes adapter ledger: {error}"))?;
            let max_prompt_bytes = config
                .delegation
                .as_ref()
                .map(|delegation| delegation.max_prompt_bytes.get() as usize)
                .unwrap_or(0);
            let task_owner: Option<Arc<dyn TaskOwner>> =
                task_owner.clone().map(|owner| owner as Arc<dyn TaskOwner>);
            let mut seat_bound_projects: BTreeMap<SeatId, BTreeSet<ProjectId>> = BTreeMap::new();
            for (seat, project) in session_lanes.keys() {
                seat_bound_projects
                    .entry(seat.clone())
                    .or_default()
                    .insert(project.clone());
            }
            Some(
                odin_hermes::runtime::HermesRuntime::open(
                    settings,
                    odin_hermes::runtime::HermesLedgers {
                        conversation: hermes_ledger,
                        adapter: Arc::new(parking_lot::Mutex::new(adapter_ledger)),
                        purchase: Arc::clone(bridge_ledger),
                    },
                    contracts,
                    task_owner,
                    max_prompt_bytes,
                    seat_bound_projects,
                    route.as_ref().map(|route| route.ownership.clone()),
                )
                .map_err(|error| error.to_string())?,
            )
        }
        None => None,
    };
    Ok(HermesComposition {
        route,
        ledger_path,
        runtime,
    })
}

pub(super) fn bind_authorities(
    runtime: &Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    browser: &Option<LocalBrowser>,
    config: &OdindConfig,
    bridge_ledger: &Arc<Mutex<Ledger>>,
    posture: NodePosture,
    seat_bindings: &[LiveSeatBinding],
    snapshot_handle: &Arc<SnapshotHandle>,
) -> Result<(), String> {
    // Checkout uses the signed-in browser only after exact kernel approval is consumed.
    if let Some(runtime) = runtime {
        runtime.set_intake_authority(Arc::new(DaemonIntakeAuthority {
            ledger: Arc::clone(bridge_ledger),
            token_root: config.paths.authority_token_root.clone(),
            posture,
        }));
        // Pinned launch declarations and registry serve the model-facing tools.
        runtime.set_model_launch_declaration(
            odin_hermes::runtime::ModelLaunchDeclaration::from_bindings(seat_bindings),
        );
        runtime.set_registry_pin(Arc::clone(snapshot_handle));
    }
    Ok(())
}
