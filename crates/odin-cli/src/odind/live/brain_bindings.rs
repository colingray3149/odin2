//! What the composed factory's seat brains hand on: the Hermes runtime's vault, memory and review bindings, and the
//! brain warm pump's targets.

use std::collections::BTreeMap;
use std::sync::Arc;

use odin_brain::retrieval::QueryEmbedder;
use odin_brain::service::BrainService;
use odin_domain::SeatId;
use odin_hermes::runtime::HermesRuntime;
use odin_huginn::{NodePosture, OdindConfig};
use odin_omp::live::ledger::LiveLedger;
use odin_omp::live::runtime::ProductionBridgeRuntimeFactory;

use crate::learning::FactoryVaultWriteGate;

pub(super) type WarmTarget = (SeatId, Arc<BrainService>, Arc<QueryEmbedder>);

pub(super) fn bind_hermes_brains(
    runtime: &HermesRuntime,
    factory: &ProductionBridgeRuntimeFactory,
    live_ledger: &Arc<dyn LiveLedger>,
) -> Result<(), String> {
    if let Some(vault) = runtime.vault() {
        for (seat, brain) in factory.brains() {
            crate::knowledge_vault::attach(brain, seat, vault)
                .map_err(|error| format!("knowledge vault for seat {seat}: {error}"))?;
        }
        // Knowledge no live seat projects (retired seats, dropped
        // sources, disabled projects) is pruned off the startup path. The
        // prune rides the publication runtime's blocking pool — never a
        // detached native thread — so the shutdown gate's thread
        // accounting owns this vault writer and a prune still running at
        // shutdown refuses capture instead of mutating the vault behind
        // the publication fence.
        let vault = vault.clone();
        let views: BTreeMap<SeatId, _> = factory
            .brains()
            .iter()
            .map(|(seat, brain)| (seat.clone(), brain.projected_views()))
            .collect();
        tokio::task::spawn_blocking(move || {
            match crate::knowledge_vault::prune_knowledge_tree(&vault, &views) {
                Ok(0) => {}
                Ok(removed) => {
                    tracing::info!("knowledge prune removed={removed} reason=unprojected-views")
                }
                Err(error) => tracing::error!("knowledge prune failed: {error}"),
            }
        });
    }
    // Where each seat remembers per project: the project's single
    // declared memory namespace (`memory.<name>`), else its own.
    runtime.set_project_memory(
        factory
            .brains()
            .iter()
            .flat_map(|(seat, brain)| {
                let policy = brain.policy();
                policy
                    .project_memory
                    .iter()
                    .filter_map(|(project, declared)| {
                        let mut memories = declared
                            .iter()
                            .filter_map(|id| id.as_str().strip_prefix("memory."));
                        match (memories.next(), memories.next()) {
                            (Some(name), None) => {
                                Some(((seat.clone(), project.clone()), name.to_owned()))
                            }
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
    );
    runtime.set_memory_grants(
        factory
            .brains()
            .iter()
            .map(|(seat, brain)| {
                let grant = brain.policy().memory_write_grant(seat);
                (
                    seat.clone(),
                    odin_hermes::runtime::MemoryGrant {
                        own: grant.own,
                        profile: grant.profile,
                    },
                )
            })
            .collect(),
    );
    runtime.set_profile_namespace(factory.brains().values().find_map(|brain| {
        brain.policy().profile_namespace.as_ref().map(|id| {
            id.as_str()
                .strip_prefix("memory.")
                .unwrap_or(id.as_str())
                .to_owned()
        })
    }));
    runtime.set_review_lanes(
        factory
            .brains()
            .iter()
            .filter_map(|(seat, brain)| {
                brain
                    .policy()
                    .review_lane
                    .clone()
                    .map(|lane| (seat.clone(), lane))
            })
            .collect(),
    );
    // Pre-write scoping: the generated write refuses typed before any
    // IO unless the writing session's project declares exactly one
    // reachable memory namespace.
    runtime.set_vault_write_gate(Arc::new(FactoryVaultWriteGate::new(
        factory.brains().clone(),
        Arc::clone(live_ledger),
        // The authoritative generated namespace of the validated vault
        // singleton: the gate reserves `<gen>/memories/<seat>` for the
        // writing seat and refuses sibling reserved paths. Absent vault
        // composes a gate without a reserved tree to enforce.
        runtime
            .vault()
            .as_ref()
            .map(|vault| vault.config().generated_namespace.clone()),
    )));
    Ok(())
}

/// Deletes the brain store of every seat no brain is composed for (a retired
/// or temporary seat) and releases its PostgreSQL holds. Authoritative only:
/// a follower composes no brains and must not touch the stores.
pub(super) fn prune_retired_brain_stores(
    posture: NodePosture,
    factory: &ProductionBridgeRuntimeFactory,
) {
    if posture == NodePosture::Follower {
        return;
    }
    let Some(brain) = factory.brains().values().next() else {
        return;
    };
    let Some(root) = brain.config().store_root.parent().map(ToOwned::to_owned) else {
        return;
    };
    let live: std::collections::BTreeSet<_> = factory
        .brains()
        .values()
        .map(|brain| brain.config().store_root.clone())
        .collect();
    let postgres = brain.config().postgres.clone();
    tokio::task::spawn_blocking(move || {
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::error!(
                    "brain store prune could not list {}: {error}",
                    root.display()
                );
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || live.contains(&path) {
                continue;
            }
            match odin_brain::index::store::IndexStore::remove(&path, postgres.as_deref()) {
                Ok(()) => tracing::info!("brain store of retired seat removed: {}", path.display()),
                Err(error) => {
                    tracing::error!("brain store prune failed for {}: {error}", path.display())
                }
            }
        }
    });
}

/// Each seat brain warms through its declared session lane (the lowest bound lane id when a seat serves several
/// projects). Authoritative only.
pub(super) fn brain_warm_targets(
    posture: NodePosture,
    config: &OdindConfig,
    factory: &ProductionBridgeRuntimeFactory,
) -> Vec<WarmTarget> {
    if posture == NodePosture::Follower {
        Vec::new()
    } else {
        factory
            .brains()
            .iter()
            .filter_map(|(seat, brain)| {
                let lane = config
                    .lane_bindings
                    .iter()
                    .filter(|binding| &binding.seat == seat)
                    .map(|binding| binding.lane.clone())
                    .min()?;
                match factory.bind_session_embedder(&lane) {
                    Ok(embedder) => {
                        embedder.map(|embedder| (seat.clone(), Arc::clone(brain), embedder))
                    }
                    Err(error) => {
                        tracing::warn!("brain warm for seat {seat} stays off: {error}");
                        None
                    }
                }
            })
            .collect()
    }
}
