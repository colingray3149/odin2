//! Pump arming for `serve_huginn_async`: the long-running pumps the daemon starts once its
//! egress lanes are armed. The order and conditions are the ones `serve_huginn_async` always
//! used; the inputs arrive as one struct so the arming function stays within clippy's argument cap.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use odin_domain::SeatId;
use odin_huginn::{NodePosture, OdindConfig};
use odin_ledger::Ledger;
use tokio::task::JoinSet;

use super::{brain_bindings, deferred_delegations, repo_watch, workload_monitor, workload_watch};
use crate::child_report::arm_child_report_pump;
use crate::huginn_spend::arm_spend_pump;
use crate::kube::KubeRuntimeCell;
use crate::pumps::{
    arm_brain_warm_pump, arm_device_activity_pump, arm_durable_feed_pump, arm_fleet,
    arm_render_pump, arm_service_pumps, arm_stream_expiry_pump,
};
use crate::state_knowledge;

/// What the pump-arming block reads, moved in from `serve_huginn_async`.
pub(super) struct PumpInputs {
    pub(super) config: OdindConfig,
    pub(super) posture: NodePosture,
    pub(super) hermes_runtime: Option<Arc<odin_hermes::runtime::HermesRuntime>>,
    pub(super) kube_cell: Option<Arc<KubeRuntimeCell>>,
    pub(super) read_model: Arc<odin_huginn::read_model::MaterializedReadModel>,
    pub(super) snapshot_handle: Arc<odin_registry::SnapshotHandle>,
    pub(super) fleet_ssh: PathBuf,
    pub(super) local_node: String,
    pub(super) declared_gateway: Option<String>,
    pub(super) features_trigger: crate::features::FeatureTrigger,
    pub(super) durable_feed_pump: Arc<odin_huginn::feed::DurableFeedPump>,
    pub(super) device_activity: (
        Arc<odin_huginn::devices::SqliteDeviceTrustStore>,
        odin_huginn::ConnectionRegistry,
    ),
    pub(super) device_admin:
        Arc<odin_huginn::devices::DeviceAdmin<odin_huginn::devices::SqliteDeviceTrustStore>>,
    pub(super) bridge_ledger: Arc<Mutex<Ledger>>,
    pub(super) render_activity: Arc<odin_huginn::HuginnRenderService>,
    pub(super) expiring_streams: Arc<odin_huginn::streams::BoundedMultiplexer>,
    pub(super) brain_warm_targets: Vec<brain_bindings::WarmTarget>,
    pub(super) incident_desk: Arc<crate::incidents::IncidentDesk>,
    pub(super) simulation_desk: Option<Arc<crate::simulation::SimulationDesk>>,
    pub(super) omp: Arc<odin_omp::live::service::OmpLiveService>,
    pub(super) conversation_seats: BTreeSet<SeatId>,
    pub(super) conversation_ledger_path: PathBuf,
    pub(super) task_owner: Option<Arc<odin_omp::host_tools::delegation::GovernedTaskOwner>>,
    pub(super) session_capsule_authority: Arc<crate::live_authority::SessionAuthorityPool>,
    pub(super) state_heads: Option<state_knowledge::StateRebuildHeads>,
    pub(super) state_rebuild_brains: BTreeMap<SeatId, Arc<odin_brain::service::BrainService>>,
}

pub(super) fn arm_pumps(pumps: &mut JoinSet<Result<(), String>>, inputs: PumpInputs) {
    let PumpInputs {
        config,
        posture,
        hermes_runtime,
        kube_cell,
        read_model,
        snapshot_handle,
        fleet_ssh,
        local_node,
        declared_gateway,
        features_trigger,
        durable_feed_pump,
        device_activity,
        device_admin,
        bridge_ledger,
        render_activity,
        expiring_streams,
        brain_warm_targets,
        incident_desk,
        simulation_desk,
        omp,
        conversation_seats,
        conversation_ledger_path,
        task_owner,
        session_capsule_authority,
        state_heads,
        state_rebuild_brains,
    } = inputs;
    arm_service_pumps(pumps, posture, &hermes_runtime, &kube_cell, &read_model);
    crate::features::arm_features_pump(
        pumps,
        posture,
        Arc::clone(&read_model),
        crate::features::FeatureSources {
            snapshot: Arc::clone(&snapshot_handle),
            registry_snapshot: config.paths.registry_snapshot.clone(),
            state_root: config.paths.state_root.clone(),
            ssh: fleet_ssh.clone(),
            gateway: declared_gateway.clone(),
            local_node,
        },
        features_trigger,
    );
    arm_fleet(
        pumps,
        Arc::clone(&snapshot_handle),
        Arc::clone(&read_model),
        Arc::new(odin_huginn::fleet::TcpFleetProbe),
        Arc::new(crate::fleet_probe::SshZellijProbe { ssh: fleet_ssh }),
    );
    arm_durable_feed_pump(pumps, posture, Arc::clone(&durable_feed_pump));
    let connections = device_activity.1.clone();
    arm_device_activity_pump(
        pumps,
        device_activity,
        Arc::clone(&read_model),
        Arc::clone(&device_admin),
        Arc::clone(&bridge_ledger),
    );
    arm_render_pump(pumps, render_activity, Arc::clone(&read_model));
    arm_stream_expiry_pump(pumps, expiring_streams);
    arm_spend_pump(pumps, posture, Arc::clone(&read_model), declared_gateway);
    crate::ci_runs::arm_ci_pump(
        pumps,
        posture,
        Arc::clone(&read_model),
        Arc::clone(&snapshot_handle),
        connections,
    );
    arm_brain_warm_pump(pumps, brain_warm_targets);
    crate::unit_failures::arm_unit_failure_pump(pumps, Arc::clone(&incident_desk));
    if let (Some(desk), Some(cell)) = (&simulation_desk, &kube_cell) {
        crate::simulation::arm_simulation_pump(
            pumps,
            Arc::clone(desk),
            Arc::clone(cell),
            Arc::clone(&snapshot_handle),
        );
    }
    if posture != NodePosture::Follower {
        if posture == NodePosture::Authoritative {
            if let (Some(cell), Some(runtime)) = (&kube_cell, &hermes_runtime) {
                super::workload_review::arm(
                    pumps,
                    config.clone(),
                    Arc::clone(cell),
                    Arc::clone(&omp),
                    Arc::clone(runtime),
                );
            }
        }
        crate::project_authoring::arm_reload_pump(
            pumps,
            Arc::clone(&omp),
            hermes_runtime.clone(),
            conversation_seats.clone(),
        );
        if let Some(runtime) = &hermes_runtime {
            crate::project_authoring::arm_seat_retire_pump(
                pumps,
                Arc::clone(&omp),
                Arc::clone(runtime),
                conversation_seats.clone(),
            );
        }
        crate::retention::arm_retention_pump(pumps, conversation_ledger_path.clone());
        crate::retention::arm_approval_expiry_pump(
            pumps,
            conversation_ledger_path.clone(),
            task_owner.clone(),
            hermes_runtime.clone(),
        );
    }
    if let (Some(runtime), Some(owner)) = (&hermes_runtime, &task_owner) {
        if posture == NodePosture::Authoritative {
            deferred_delegations::arm_deferred_delegations(
                pumps,
                Arc::clone(runtime),
                Arc::clone(owner),
                config.paths.state_root.clone(),
            );
        }
        if let Some(discord) = runtime.settings().discord.as_ref() {
            arm_child_report_pump(
                pumps,
                Arc::clone(runtime),
                Arc::clone(owner),
                discord.seat.clone(),
                crate::child_report::PumpTiming {
                    every: crate::child_report::CHILD_REPORT_TICK,
                    child_lifetime: config.delegation.as_ref().map(|delegation| {
                        (
                            std::time::Duration::from_secs(delegation.child_timeout_seconds.get()),
                            delegation
                                .child_idle_seconds
                                .map(|idle| std::time::Duration::from_secs(idle.get())),
                            delegation
                                .child_stall_seconds
                                .map(|stall| std::time::Duration::from_secs(stall.get())),
                        )
                    }),
                },
                kube_cell.clone(),
                Arc::clone(&incident_desk),
            );
            if posture == NodePosture::Authoritative {
                workload_watch::arm_workload_watch(
                    pumps,
                    Arc::clone(&read_model),
                    Arc::clone(owner),
                    Arc::clone(runtime),
                    kube_cell.clone(),
                    config.paths.state_root.clone(),
                    discord.seat.clone(),
                );
                repo_watch::arm_repo_watch(
                    pumps,
                    Arc::clone(runtime),
                    &config.projects,
                    config.paths.state_root.clone(),
                    Arc::clone(&session_capsule_authority),
                );
                if let Some(cell) = kube_cell.as_ref() {
                    workload_monitor::arm_workload_monitor(
                        pumps,
                        Arc::clone(&read_model),
                        Arc::clone(cell),
                        Arc::clone(owner),
                        Arc::clone(runtime),
                        Arc::clone(&incident_desk),
                        config.paths.state_root.clone(),
                    );
                }
            }
        }
    }
    if let Some(heads) = state_heads {
        state_knowledge::arm_state_rebuild_pump(pumps, state_rebuild_brains, heads);
    }
}
