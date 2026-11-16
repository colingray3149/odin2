//! Durable owner approvals and account reservations for cloud rentals.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::lane_budget::RaiseLock;
use super::ComputeProviderToml;

const FILE: &str = "rental-approvals.json";

/// An owner-approved spending request. The ID is the durable approval identity, not caller text.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RentalApproval {
    pub id: String,
    pub project: String,
    pub provider: String,
    pub hours: u32,
    pub estimated_usd: f64,
    pub approved_cap_usd: f64,
}

impl RentalApproval {
    /// Validate the exact terms before the approved external effect is issued.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.provider.is_empty()
            || self.project.is_empty()
            || self.hours == 0
            || !valid_money(self.estimated_usd)
            || !valid_money(self.approved_cap_usd)
            || self.estimated_usd > self.approved_cap_usd
        {
            return Err("invalid rental approval".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Reservation {
    operation: String,
    reserved_usd: f64,
    settled_usd: Option<f64>,
    settled_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Entry {
    approval: RentalApproval,
    reservation: Option<Reservation>,
}

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Store {
    entries: BTreeMap<String, Entry>,
    #[serde(default)]
    pub(super) leases: BTreeMap<String, super::rental_leases::RentalLease>,
}

/// All modifications lock and replace one file, so approvals and reservations cannot race.
pub struct RentalApprovals;

impl RentalApprovals {
    /// Record only after the owner has actually approved the exact request.
    pub fn record(root: &Path, approval: RentalApproval) -> Result<(), String> {
        approval.validate()?;
        update(root, |store| {
            if let Some(existing) = store.entries.get(&approval.id) {
                return if existing.approval == approval {
                    Ok(())
                } else {
                    Err("approval identity already bound to different terms".into())
                };
            }
            store.entries.insert(
                approval.id.clone(),
                Entry {
                    approval,
                    reservation: None,
                },
            );
            Ok(())
        })
    }

    /// Consume an approval and reserve the maximum lease cost under the current account cap.
    /// A retry with the same operation and terms returns the same reservation.
    pub fn reserve(
        root: &Path,
        lease: super::rental_leases::RentalLease,
        provider: &ComputeProviderToml,
        hours: u32,
        usd: f64,
        now_ms: u64,
    ) -> Result<bool, String> {
        super::rental_leases::validate_intent(&lease)?;
        if lease.provider_snapshot.as_ref() != Some(provider) {
            return Err("lease provider snapshot does not match reservation".into());
        }
        if lease.operation.is_empty() || !valid_money(usd) || hours == 0 {
            return Err("invalid rental reservation".into());
        }
        let offer = provider
            .offers
            .get(&lease.offer)
            .ok_or("unknown provider offer")?;
        let duration = lease
            .expires_ms
            .checked_sub(lease.started_ms)
            .ok_or("invalid lease duration")?;
        if duration != u64::from(hours) * 3_600_000
            || lease.usd_per_hour != offer.usd_per_hour
            || usd != offer.usd_per_hour * f64::from(hours)
        {
            return Err("reservation does not match declared offer and lease duration".into());
        }
        if !provider.enabled
            || !provider.allowed_projects.contains(&lease.project)
            || hours > provider.max_lease_hours.get()
            || !valid_money(provider.max_hourly_usd)
            || usd > provider.max_hourly_usd * f64::from(hours)
        {
            return Err("rental exceeds provider policy".into());
        }
        let cap = provider
            .account_max_usd
            .filter(|v| valid_money(*v))
            .ok_or("provider account_max_usd is not declared")?;
        let days = provider
            .account_window_days
            .ok_or("provider account_window_days is not declared")?
            .get();
        let cutoff = now_ms.saturating_sub(u64::from(days).saturating_mul(86_400_000));
        update(root, |store| {
            let approval_id = lease.approval_id.as_str();
            let operation = lease.operation.as_str();
            let provider_id = lease.provider.as_str();
            let project = lease.project.as_str();
            let entry = store
                .entries
                .get(approval_id)
                .ok_or("unknown rental approval")?;
            if entry.approval.provider != provider_id
                || entry.approval.project != project
                || entry.approval.hours != hours
                || usd > entry.approval.estimated_usd
            {
                return Err("rental terms exceed or differ from approval".into());
            }
            if let Some(reservation) = &entry.reservation {
                return if reservation.operation == operation
                    && reservation.reserved_usd == usd
                    && store.leases.get(&lease.id).is_some_and(|existing| {
                        existing.operation == lease.operation
                            && existing.approval_id == lease.approval_id
                            && existing.provider == lease.provider
                            && existing.offer == lease.offer
                            && existing.project == lease.project
                            && existing.lane == lease.lane
                            && existing.expires_ms.saturating_sub(existing.started_ms) == duration
                            && existing.usd_per_hour == lease.usd_per_hour
                    }) {
                    Ok(false)
                } else {
                    Err("rental approval already consumed".into())
                };
            }
            if store
                .entries
                .values()
                .filter_map(|entry| entry.reservation.as_ref())
                .any(|r| r.operation == operation)
            {
                return Err("rental operation already bound to another approval".into());
            }
            if store.leases.contains_key(&lease.id)
                || store
                    .leases
                    .values()
                    .any(|item| item.operation == operation)
            {
                return Err("lease or operation already bound".into());
            }
            if store
                .leases
                .values()
                .filter(|item| {
                    item.provider == provider_id
                        && item.state != super::rental_leases::RentalLeaseState::Destroyed
                })
                .count()
                >= provider.max_concurrent_leases.get() as usize
            {
                return Err("provider concurrent lease cap reached".into());
            }
            let used: f64 = store
                .entries
                .values()
                .filter(|entry| entry.approval.provider == provider_id)
                .filter_map(|entry| entry.reservation.as_ref())
                .map(
                    |reservation| match (reservation.settled_usd, reservation.settled_ms) {
                        (Some(amount), Some(at)) if at >= cutoff => amount,
                        (Some(_), Some(_)) => 0.0,
                        _ => reservation.reserved_usd,
                    },
                )
                .sum();
            if !used.is_finite() || used + usd > cap {
                return Err("provider account spending cap exceeded".into());
            }
            store
                .entries
                .get_mut(approval_id)
                .expect("approval exists")
                .reservation = Some(Reservation {
                operation: operation.to_owned(),
                reserved_usd: usd,
                settled_usd: None,
                settled_ms: None,
            });
            store.leases.insert(lease.id.clone(), lease);
            Ok(true)
        })
    }

    /// Atomically settle a definitively refused create without releasing an uncertain intent.
    pub fn refused_create(
        root: &Path,
        id: &str,
        operation: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        update(root, |store| {
            let lease = store.leases.get(id).ok_or("unknown rental lease")?;
            if lease.operation != operation
                || lease.state != super::rental_leases::RentalLeaseState::Creating
                || lease.server_id.is_some()
            {
                return Err("refused create is no longer an unresolved intent".into());
            }
            let approval_id = lease.approval_id.clone();
            let reservation = store
                .entries
                .get_mut(&approval_id)
                .and_then(|entry| entry.reservation.as_mut())
                .ok_or("unknown rental reservation")?;
            if reservation.operation != operation || reservation.settled_usd.is_some() {
                return Err("refused create reservation is not unsettled".into());
            }
            reservation.settled_usd = Some(0.0);
            reservation.settled_ms = Some(now_ms);
            let lease = store.leases.get_mut(id).expect("lease checked above");
            lease.destroyed_ms = Some(now_ms);
            lease.state = super::rental_leases::RentalLeaseState::Destroyed;
            Ok(())
        })
    }

    /// Replace a reservation with its actual final cost after confirmed provider destruction.
    pub fn settle(
        root: &Path,
        approval_id: &str,
        operation: &str,
        actual_usd: f64,
        now_ms: u64,
    ) -> Result<(), String> {
        if !valid_money(actual_usd) {
            return Err("invalid actual cost".into());
        }
        update(root, |store| {
            let reservation = store
                .entries
                .get_mut(approval_id)
                .and_then(|entry| entry.reservation.as_mut())
                .ok_or("unknown rental reservation")?;
            if reservation.operation != operation {
                return Err("reservation belongs to another operation".into());
            }
            if let Some(previous) = reservation.settled_usd {
                return if previous == actual_usd {
                    Ok(())
                } else {
                    Err("reservation already settled".into())
                };
            }
            reservation.settled_usd = Some(actual_usd);
            reservation.settled_ms = Some(now_ms);
            Ok(())
        })
    }
}

fn valid_money(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

pub(super) fn update<T>(
    root: &Path,
    change: impl FnOnce(&mut Store) -> Result<T, String>,
) -> Result<T, String> {
    let _lock = RaiseLock::acquire_file(root, ".rental-approvals.lock")?;
    let path = root.join(FILE);
    let mut store: Store = match crate::snapshot::read_regular_file(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} is malformed: {e}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Store::default(),
        Err(e) => return Err(format!("{} is unreadable: {e}", path.display())),
    };
    let result = change(&mut store)?;
    let bytes = serde_json::to_vec(&store).map_err(|e| e.to_string())?;
    crate::snapshot::atomic_write(&path, &bytes)
        .map_err(|e| format!("{} {}: {}", e.action, e.path.display(), e.source))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_scoped_idempotent_and_cannot_be_rebound() {
        let root = tempfile::tempdir().unwrap();
        let approval = RentalApproval {
            id: "approval-1".into(),
            project: "project-1".into(),
            provider: "provider-1".into(),
            hours: 1,
            estimated_usd: 1.0,
            approved_cap_usd: 2.0,
        };
        RentalApprovals::record(root.path(), approval.clone()).unwrap();
        RentalApprovals::record(root.path(), approval.clone()).unwrap();
        let mut changed = approval;
        changed.project = "other".into();
        assert!(RentalApprovals::record(root.path(), changed).is_err());
    }

    #[test]
    fn approval_only_store_remains_readable_after_lease_journal_cutover() {
        let root = tempfile::tempdir().unwrap();
        let approval = RentalApproval {
            id: "approval".into(),
            project: "p".into(),
            provider: "cloud".into(),
            hours: 1,
            estimated_usd: 1.0,
            approved_cap_usd: 1.0,
        };
        let old = serde_json::json!({ "entries": { "approval": { "approval": approval, "reservation": null } } });
        std::fs::write(root.path().join(FILE), serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(super::super::rental_leases::RentalLeases::list(root.path())
            .unwrap()
            .is_empty());
        RentalApprovals::record(root.path(), approval).unwrap();
    }

    #[test]
    fn lease_intent_and_reservation_are_atomic_and_replayable() {
        let root = tempfile::tempdir().unwrap();
        let provider: ComputeProviderToml = toml::from_str(
            r#"
schema = "odin.compute-provider.v1"
kind = "compute-provider"
enabled = true
description = "test provider"
api = "hetzner"
key = "KEY"
max_hourly_usd = 3.0
account_max_usd = 4.0
account_window_days = 30
max_lease_hours = 2
max_concurrent_leases = 1
idle_destroy_minutes = 10
reap_seconds = 30
join = "ssh-target"
allowed_projects = ["p"]
[offers.small]
machine = "small"
image = "image"
usd_per_hour = 1.0
cores = 1
"#,
        )
        .unwrap();
        let approval = RentalApproval {
            id: "approval".into(),
            project: "p".into(),
            provider: "cloud".into(),
            hours: 1,
            estimated_usd: 1.0,
            approved_cap_usd: 1.0,
        };
        RentalApprovals::record(root.path(), approval).unwrap();
        let lease = super::super::rental_leases::RentalLease {
            id: "lease-1".into(),
            operation: "op-1".into(),
            approval_id: "approval".into(),
            provider: "cloud".into(),
            provider_snapshot: Some(provider.clone()),
            offer: "small".into(),
            project: "p".into(),
            lane: "lane".into(),
            started_ms: 1,
            expires_ms: 3_600_001,
            usd_per_hour: 1.0,
            state: super::super::rental_leases::RentalLeaseState::Creating,
            server_id: None,
            target_id: None,
            target_alias: None,
            destroyed_ms: None,
            enrollment: None,
        };
        RentalApprovals::reserve(root.path(), lease.clone(), &provider, 1, 1.0, 1).unwrap();
        RentalApprovals::reserve(root.path(), lease.clone(), &provider, 1, 1.0, 2).unwrap();
        let other_approval = RentalApproval {
            id: "approval-2".into(),
            project: "p".into(),
            provider: "cloud".into(),
            hours: 1,
            estimated_usd: 1.0,
            approved_cap_usd: 1.0,
        };
        RentalApprovals::record(root.path(), other_approval).unwrap();
        let mut other = lease.clone();
        other.id = "lease-2".into();
        other.operation = "op-2".into();
        other.approval_id = "approval-2".into();
        assert!(
            RentalApprovals::reserve(root.path(), other.clone(), &provider, 1, 1.0, 2).is_err()
        );
        assert!(
            super::super::rental_leases::RentalLeases::by_operation(root.path(), "op-2")
                .unwrap()
                .is_none()
        );
        other.project = "other".into();
        assert!(RentalApprovals::reserve(root.path(), other, &provider, 1, 1.0, 2).is_err());
        use super::super::rental_leases::{RentalLeaseState, RentalLeases};
        assert_eq!(
            RentalLeases::by_operation(root.path(), "op-1").unwrap(),
            Some(lease.clone())
        );
        RentalLeases::activate(root.path(), &lease.id, "server-1").unwrap();
        let recovered = RentalLeases::by_operation(root.path(), "op-1")
            .unwrap()
            .unwrap();
        assert_eq!(recovered.state, RentalLeaseState::PendingIdentity);
        assert_eq!(recovered.server_id.as_deref(), Some("server-1"));
        let identity = super::super::rental_leases::RentalEnrollment {
            server_id: "server-1".into(),
            ssh_host: "192.0.2.1".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            known_host: "ssh-ed25519 AAAA".into(),
        };
        let mut injected = identity.clone();
        injected.known_host = "ssh-ed25519 AAAA\nother ssh-ed25519 BBBB".into();
        assert!(injected.validate().is_err());
        injected = identity.clone();
        injected.ssh_user = "-option".into();
        assert!(injected.validate().is_err());
        let mut wrong = identity.clone();
        wrong.server_id = "server-2".into();
        assert!(RentalLeases::bind_enrollment(
            root.path(),
            &lease.id,
            wrong,
            "rental-1",
            "template"
        )
        .is_err());
        RentalLeases::bind_enrollment(
            root.path(),
            &lease.id,
            identity.clone(),
            "rental-1",
            "template",
        )
        .unwrap();
        RentalLeases::bind_enrollment(
            root.path(),
            &lease.id,
            identity.clone(),
            "rental-1",
            "template",
        )
        .unwrap();
        let pending = RentalLeases::by_operation(root.path(), "op-1")
            .unwrap()
            .unwrap();
        assert_eq!(pending.state, RentalLeaseState::Enrolling);
        assert_eq!(pending.target_id.as_deref(), Some("rental-1"));
        assert_eq!(pending.target_alias.as_deref(), Some("template"));
        assert!(RentalLeases::bind_enrollment(
            root.path(),
            &lease.id,
            identity.clone(),
            "rental-2",
            "template"
        )
        .is_err());
        assert!(RentalLeases::enrolled(root.path(), &lease.id, "rental-2", "template").is_err());
        let mut changed = identity;
        changed.known_host = "ssh-ed25519 BBBB".into();
        assert!(RentalLeases::bind_enrollment(
            root.path(),
            &lease.id,
            changed,
            "rental-1",
            "template"
        )
        .is_err());
        RentalLeases::destroying(root.path(), &lease.id).unwrap();
        assert_eq!(
            RentalLeases::confirm_end(root.path(), &lease.id, 100).unwrap(),
            100
        );
        assert_eq!(
            RentalLeases::confirm_end(root.path(), &lease.id, 200).unwrap(),
            100
        );
        RentalApprovals::settle(root.path(), "approval", "op-1", 1.0, 100).unwrap();
        RentalApprovals::settle(root.path(), "approval", "op-1", 1.0, 100).unwrap();
        RentalLeases::destroyed(root.path(), &lease.id).unwrap();
        assert_eq!(
            RentalLeases::by_operation(root.path(), "op-1")
                .unwrap()
                .unwrap()
                .state,
            RentalLeaseState::Destroyed
        );
    }

    #[test]
    fn concurrent_reservations_obey_account_cap_and_replay_once() {
        use super::super::rental_leases::{RentalLease, RentalLeaseState, RentalLeases};
        use std::sync::{Arc, Barrier};

        let root = tempfile::tempdir().unwrap();
        let provider: ComputeProviderToml = toml::from_str(
            r#"
schema = "odin.compute-provider.v1"
kind = "compute-provider"
enabled = true
description = "test provider"
api = "hetzner"
key = "KEY"
max_hourly_usd = 1.0
account_max_usd = 1.0
account_window_days = 30
max_lease_hours = 1
max_concurrent_leases = 4
idle_destroy_minutes = 10
reap_seconds = 30
join = "ssh-target"
allowed_projects = ["p"]
[offers.small]
machine = "small"
image = "image"
usd_per_hour = 1.0
cores = 1
"#,
        )
        .unwrap();
        let intent = |id: &str, operation: &str, approval: &str, started_ms| RentalLease {
            id: id.into(),
            operation: operation.into(),
            approval_id: approval.into(),
            provider: "cloud".into(),
            provider_snapshot: Some(provider.clone()),
            offer: "small".into(),
            project: "p".into(),
            lane: "lane".into(),
            started_ms,
            expires_ms: started_ms + 3_600_000,
            usd_per_hour: 1.0,
            state: RentalLeaseState::Creating,
            server_id: None,
            target_id: None,
            target_alias: None,
            destroyed_ms: None,
            enrollment: None,
        };
        for id in ["approval-1", "approval-2"] {
            RentalApprovals::record(
                root.path(),
                RentalApproval {
                    id: id.into(),
                    project: "p".into(),
                    provider: "cloud".into(),
                    hours: 1,
                    estimated_usd: 1.0,
                    approved_cap_usd: 1.0,
                },
            )
            .unwrap();
        }
        let leases = [
            intent("lease-1", "op-1", "approval-1", 1),
            intent("lease-2", "op-2", "approval-2", 1),
        ];
        let barrier = Arc::new(Barrier::new(2));
        let results = std::thread::scope(|threads| {
            let handles: Vec<_> = leases
                .iter()
                .cloned()
                .map(|lease| {
                    let barrier = Arc::clone(&barrier);
                    let provider = &provider;
                    let root = root.path();
                    threads.spawn(move || {
                        barrier.wait();
                        RentalApprovals::reserve(root, lease, provider, 1, 1.0, 1)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(true)))
                .count(),
            1
        );
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let winner = RentalLeases::list(root.path()).unwrap().pop().unwrap();
        assert!(
            RentalApprovals::refused_create(root.path(), &winner.id, "different-operation", 2)
                .is_err()
        );
        RentalApprovals::refused_create(root.path(), &winner.id, &winner.operation, 2).unwrap();
        assert_eq!(
            RentalLeases::by_operation(root.path(), &winner.operation)
                .unwrap()
                .unwrap()
                .state,
            RentalLeaseState::Destroyed
        );
        let loser = leases
            .iter()
            .find(|lease| lease.id != winner.id)
            .unwrap()
            .clone();
        assert!(RentalApprovals::reserve(root.path(), loser, &provider, 1, 1.0, 3).unwrap());
        let replay_root = tempfile::tempdir().unwrap();
        RentalApprovals::record(
            replay_root.path(),
            RentalApproval {
                id: winner.approval_id.clone(),
                project: "p".into(),
                provider: "cloud".into(),
                hours: 1,
                estimated_usd: 1.0,
                approved_cap_usd: 1.0,
            },
        )
        .unwrap();
        assert!(
            RentalApprovals::reserve(replay_root.path(), winner.clone(), &provider, 1, 1.0, 1)
                .unwrap()
        );
        let mut retry = winner.clone();
        retry.started_ms += 5;
        retry.expires_ms += 5;
        RentalLeases::activate(replay_root.path(), &winner.id, "server-1").unwrap();
        assert!(RentalApprovals::refused_create(
            replay_root.path(),
            &winner.id,
            &winner.operation,
            6
        )
        .is_err());
        assert!(
            !RentalApprovals::reserve(replay_root.path(), retry, &provider, 1, 1.0, 6).unwrap()
        );
        assert_eq!(RentalLeases::list(replay_root.path()).unwrap().len(), 1);
    }
}
