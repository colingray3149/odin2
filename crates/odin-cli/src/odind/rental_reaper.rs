//! Reconcile provider leases and drain SSH targets before reaping them.
use crate::{
    incidents::{IncidentDesk, RaisedIncident},
    live::offload::Offload,
    provider_transport,
};
use odin_huginn::incidents::IncidentSeverityView;
use odin_registry::{
    ComputeUsage, LaneBudgetKind, ObjectConfig, RaisedLaneBudgets, RentalApprovals, RentalLease,
    RentalLeaseState, RentalLeases, RentalTargets, SnapshotHandle,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

fn alert(desk: &IncidentDesk, id: &str, detail: String) {
    desk.raise(RaisedIncident {
        source: "rental reaper".into(),
        severity: IncidentSeverityView::Error,
        summary: format!("Rental {id} needs attention"),
        detail,
        affected: vec![id.into()],
        signature: format!("rental:{id}"),
    });
}

fn idle_since(lease: &RentalLease, offload: &Offload) -> Option<u64> {
    let mut last = lease.started_ms;
    for run in offload
        .runs()
        .into_iter()
        .filter(|run| Some(run.target.as_str()) == lease.target_id.as_deref())
    {
        if !run.state.finished() {
            return None;
        }
        last = last.max(u64::try_from(run.finished_at?.unix_timestamp_nanos() / 1_000_000).ok()?);
    }
    lease.target_id.as_ref()?;
    Some(last)
}

fn budget_spent(
    root: &Path,
    snapshot: &odin_registry::Snapshot,
    lease: &RentalLease,
    now: u64,
) -> Result<bool, String> {
    let lane = snapshot
        .objects
        .iter()
        .find_map(|object| match &object.config {
            ObjectConfig::Lane(lane) if object.id == lease.lane => Some(lane),
            _ => None,
        })
        .ok_or("leasing lane is unavailable")?;
    let Some(floor) = LaneBudgetKind::ComputeUsd.declared(&lane.limits) else {
        return Ok(false);
    };
    let raised = RaisedLaneBudgets::load(root)?;
    let cap = raised
        .as_ref()
        .and_then(|r| r.effective(&lease.lane, Some(floor), LaneBudgetKind::ComputeUsd))
        .unwrap_or(floor);
    Ok(ComputeUsage::load(root)?
        .used(&lease.lane, lane.limits.window_days(), now)
        .usd
        >= f64::from(cap))
}

fn finalize(root: &Path, lease: &RentalLease, ended: u64) -> Result<(), String> {
    ComputeUsage::update(root, |usage| {
        usage.charge_source(
            &format!("lease:{}", lease.id),
            std::slice::from_ref(&lease.lane),
            lease.started_ms..ended,
            0.0,
            0.0,
            lease.usd_per_hour,
        )
    })?;
    RentalApprovals::settle(
        root,
        &lease.approval_id,
        &lease.operation,
        ended.saturating_sub(lease.started_ms) as f64 / 3_600_000.0 * lease.usd_per_hour,
        ended,
    )
}

async fn round(
    root: &Path,
    snapshot: &odin_registry::Snapshot,
    offload: Option<&Offload>,
    desk: &IncidentDesk,
    now: u64,
) -> Result<(), String> {
    let leases = RentalLeases::list(root)?;
    for lease in leases.iter().filter(|lease| {
        matches!(
            lease.state,
            RentalLeaseState::PendingIdentity
                | RentalLeaseState::Enrolling
                | RentalLeaseState::DestroyingPendingIdentity
                | RentalLeaseState::Active
                | RentalLeaseState::Destroying
        )
    }) {
        let end = lease.destroyed_ms.unwrap_or(now);
        ComputeUsage::update(root, |usage| {
            usage.charge_source(
                &format!("lease:{}", lease.id),
                std::slice::from_ref(&lease.lane),
                lease.started_ms..end,
                0.0,
                0.0,
                lease.usd_per_hour,
            )
        })?;
    }
    let mut providers = Vec::new();
    for object in &snapshot.objects {
        if let ObjectConfig::ComputeProvider(provider) = &object.config {
            providers.push((object.id.clone(), provider.as_ref().clone()));
        }
    }
    for lease in leases
        .iter()
        .filter(|lease| lease.state != RentalLeaseState::Destroyed)
    {
        if let Some(provider) = &lease.provider_snapshot {
            if !providers
                .iter()
                .any(|(id, existing)| id == &lease.provider && existing == provider)
            {
                providers.push((lease.provider.clone(), provider.clone()));
            }
        } else if !providers.iter().any(|(id, _)| id == &lease.provider) {
            alert(
                desk,
                &lease.id,
                format!(
                    "Provider {} is missing and no original card was retained",
                    lease.provider
                ),
            );
        }
    }
    for (provider_id, provider) in &providers {
        let idle_minutes = snapshot
            .objects
            .iter()
            .find_map(|object| match &object.config {
                ObjectConfig::ComputeProvider(current) if object.id == *provider_id => {
                    Some(current.idle_destroy_minutes.get())
                }
                _ => None,
            })
            .unwrap_or(provider.idle_destroy_minutes.get());
        let credential = std::env::var(&provider.key)
            .ok()
            .filter(|key| !key.is_empty());
        let servers = if let Some(key) = credential.as_deref() {
            match provider_transport::list(provider, key).await {
                Ok(servers) => Some(servers),
                Err(error) => {
                    alert(desk, provider_id, error);
                    None
                }
            }
        } else {
            if leases
                .iter()
                .any(|l| l.provider == *provider_id && l.state != RentalLeaseState::Destroyed)
            {
                alert(
                    desk,
                    provider_id,
                    format!("Provider credential {} unavailable", provider.key),
                );
            }
            None
        };
        for server in servers.iter().flatten() {
            if !leases.iter().any(|l| {
                l.provider == *provider_id
                    && l.id == server.lease_id
                    && l.state != RentalLeaseState::Destroyed
            }) {
                alert(
                    desk,
                    &server.lease_id,
                    format!(
                        "Orphan server {} reported by {}; not deleted automatically",
                        server.id, provider_id
                    ),
                );
            }
        }
        for lease in leases.iter().filter(|l| l.provider == *provider_id && l.state != RentalLeaseState::Destroyed
            && l.provider_snapshot.as_ref().map_or_else(|| snapshot.objects.iter().any(|o| o.id == *provider_id && matches!(&o.config, ObjectConfig::ComputeProvider(current) if current.as_ref() == provider)), |original| original == provider)) {
            let lock_root = root.to_path_buf();
            let lock_id = lease.id.clone();
            let _guard = tokio::task::spawn_blocking(move || RentalLeases::lock_operation(&lock_root, &lock_id))
                .await.map_err(|error| format!("lease lock task failed: {error}"))??;
            let Some(current) = RentalLeases::by_operation(root, &lease.operation)? else { continue; };
            let lease = &current;
            if lease.state == RentalLeaseState::Destroyed { continue; }
            let found: Vec<_> = servers
                .iter()
                .flatten()
                .filter(|s| s.lease_id == lease.id)
                .collect();
            if found.len() > 1 {
                alert(
                    desk,
                    &lease.id,
                    "Multiple matching servers; manual reconciliation required".into(),
                );
            }
            if lease.state == RentalLeaseState::Creating {
                if found.len() > 1 {
                    continue;
                }
                if let Some(server) = found.first() {
                    RentalLeases::activate(root, &lease.id, &server.id)?;
                } else {
                    alert(
                        desk,
                        &lease.id,
                        "Create outcome unresolved; do not retry".into(),
                    );
                }
                continue;
            }
            let expiry = now >= lease.expires_ms;
            let budget = match budget_spent(root, snapshot, lease, now) { Ok(value) => value, Err(error) => { alert(desk, &lease.id, error); false } };
            let idle = offload.and_then(|o| idle_since(lease, o)).is_some_and(|since| now.saturating_sub(since) >= u64::from(idle_minutes) * 60_000);
            if !expiry && !budget && !idle && !matches!(lease.state, RentalLeaseState::Destroying | RentalLeaseState::DestroyingPendingIdentity) { continue; }
            if found.len() > 1 && matches!(lease.state, RentalLeaseState::PendingIdentity | RentalLeaseState::DestroyingPendingIdentity) { continue; }
            if matches!(lease.state, RentalLeaseState::PendingIdentity | RentalLeaseState::DestroyingPendingIdentity) {
                let server_id = match lease.server_id.as_deref() {
                    Some(id) => id,
                    None if lease.state == RentalLeaseState::DestroyingPendingIdentity => {
                        let Some(server) = found.first() else { alert(desk, &lease.id, "Provider identity unresolved; destroy remains pending".into()); continue; };
                        RentalLeases::bind_destroying_server(root, &lease.id, &server.id)?;
                        server.id.as_str()
                    }
                    None => { alert(desk, &lease.id, "Provider identity unresolved".into()); continue; }
                };
                RentalLeases::destroying(root, &lease.id)?;
                if lease.destroyed_ms.is_none() {
                    let Some(credential) = credential.as_deref() else {
                        continue;
                    };
                    if let Err(error) =
                        provider_transport::destroy(provider, credential, server_id).await
                    {
                        alert(
                            desk,
                            &lease.id,
                            format!("Destruction failed or uncertain: {error}"),
                        );
                        continue;
                    }
                }
                let ended =
                    RentalLeases::confirm_end(root, &lease.id, odin_registry::unix_millis())?;
                finalize(root, lease, ended)?;
                RentalLeases::destroyed(root, &lease.id)?;
                continue;
            }
            let (Some(target), Some(alias), Some(offload), Some(server_id)) = (
                &lease.target_id,
                &lease.target_alias,
                offload,
                &lease.server_id,
            ) else {
                alert(
                    desk,
                    &lease.id,
                    "Cannot reap without authenticated target and drain authority".into(),
                );
                continue;
            };
            if !offload.drain_target(target).await? {
                if expiry || budget {
                    alert(
                        desk,
                        &lease.id,
                        "Expired or over-budget lease has active work; cancellation requested"
                            .into(),
                    );
                    for run in offload
                        .runs()
                        .into_iter()
                        .filter(|run| run.target == *target && !run.state.finished())
                    {
                        if let Err(error) = offload.stop(&run.run_id).await {
                            alert(
                                desk,
                                &lease.id,
                                format!("Could not stop run {}: {error}", run.run_id),
                            );
                        }
                    }
                }
                continue;
            }
            if idle && !expiry && !budget && lease.state != RentalLeaseState::Destroying
                && !idle_since(lease, offload).is_some_and(|since| now.saturating_sub(since) >= u64::from(idle_minutes) * 60_000)
            {
                offload.release_target(target).await?;
                continue;
            }
            if found.len() > 1 {
                continue;
            }
            RentalLeases::destroying(root, &lease.id)?;
            if lease.destroyed_ms.is_none() {
                let Some(credential) = credential.as_deref() else {
                    continue;
                };
                if let Err(error) =
                    provider_transport::destroy(provider, credential, server_id).await
                {
                    alert(
                        desk,
                        &lease.id,
                        format!("Destruction failed or uncertain: {error}"),
                    );
                    continue;
                }
            }
            let ended = RentalLeases::confirm_end(root, &lease.id, odin_registry::unix_millis())?;
            finalize(root, lease, ended)?;
            RentalTargets::remove(root, target, alias)?;
            offload.release_target(target).await?;
            RentalLeases::destroyed(root, &lease.id)?;
        }
    }
    Ok(())
}

pub(super) fn arm(
    pumps: &mut tokio::task::JoinSet<Result<(), String>>,
    root: PathBuf,
    snapshot: Arc<SnapshotHandle>,
    offload: Option<Arc<Offload>>,
    desk: Arc<IncidentDesk>,
) {
    pumps.spawn(async move {
        loop {
            let current = snapshot.current();
            let cadence = current
                .objects
                .iter()
                .filter_map(|object| match &object.config {
                    ObjectConfig::ComputeProvider(provider) if provider.enabled => {
                        Some(provider.reap_seconds.get())
                    }
                    _ => None,
                })
                .min()
                .unwrap_or(60);
            if let Err(error) = round(
                &root,
                &current,
                offload.as_deref(),
                &desk,
                odin_registry::unix_millis(),
            )
            .await
            {
                alert(&desk, "reaper", error);
            }
            tokio::time::sleep(std::time::Duration::from_secs(u64::from(cadence))).await;
        }
    });
}
