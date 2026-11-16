//! Durable lifecycle records for cloud leases. The lease identity is persisted before any
//! provider create request, so an interrupted request must be reconciled rather than retried.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::rental_approvals::update;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentalLeaseState {
    /// Intent persisted; provider create may have been sent and must be reconciled.
    Creating,
    /// The server exists but has not yet been authenticated or enrolled.
    PendingIdentity,
    /// Enrollment has started; a node or target may already be active.
    Enrolling,
    /// An un-enrolled server is being destroyed.
    DestroyingPendingIdentity,
    Active,
    /// The provider may still be billing; retry and reconcile until absence is confirmed.
    Destroying,
    Destroyed,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RentalLease {
    pub id: String,
    pub operation: String,
    pub approval_id: String,
    pub provider: String,
    /// Provider authority captured at reservation, retained if the card is removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_snapshot: Option<super::ComputeProviderToml>,
    pub offer: String,
    pub project: String,
    pub lane: String,
    pub started_ms: u64,
    pub expires_ms: u64,
    pub usd_per_hour: f64,
    pub state: RentalLeaseState,
    pub server_id: Option<String>,
    pub target_id: Option<String>,
    pub target_alias: Option<String>,
    pub destroyed_ms: Option<u64>,
    /// Owner-verified per-lease SSH identity bound before bootstrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<RentalEnrollment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RentalEnrollment {
    pub server_id: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub known_host: String,
}
impl RentalEnrollment {
    /// Validate fields before using them in an SSH destination or known-hosts file.
    pub fn validate(&self) -> Result<(), String> {
        let valid_atom = |s: &str| {
            s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        };
        let Some((kind, blob)) = self.known_host.split_once(' ') else {
            return Err("invalid enrollment identity".into());
        };
        if !valid_atom(&self.ssh_host)
            || !valid_atom(&self.ssh_user)
            || self.ssh_port == 0
            || !(kind.starts_with("ssh-") || kind.starts_with("ecdsa-"))
            || !kind
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.'))
            || blob.is_empty()
            || !blob
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err("invalid enrollment identity".into());
        }
        Ok(())
    }
}

pub(super) fn validate_intent(lease: &RentalLease) -> Result<(), String> {
    if !super::valid_id(&lease.id)
        || lease.operation.is_empty()
        || lease.approval_id.is_empty()
        || lease.provider.is_empty()
        || lease.offer.is_empty()
        || lease.project.is_empty()
        || lease.lane.is_empty()
        || lease.expires_ms <= lease.started_ms
        || !lease.usd_per_hour.is_finite()
        || lease.usd_per_hour < 0.0
        || lease.state != RentalLeaseState::Creating
        || lease.server_id.is_some()
        || lease.destroyed_ms.is_some()
        || lease.enrollment.is_some()
    {
        return Err("invalid lease intent".into());
    }
    Ok(())
}

/// Held across enrollment or teardown, including their remote effects.
pub struct RentalLeaseGuard {
    _lock: super::lane_budget::RaiseLock,
}

/// Serializes the lifecycle journal across daemon and tool processes.
pub struct RentalLeases;

impl RentalLeases {
    /// Acquire on a blocking thread; callers must retain the guard through the effect.
    pub fn lock_operation(root: &Path, id: &str) -> Result<RentalLeaseGuard, String> {
        if !super::valid_id(id) {
            return Err("invalid lease identity".into());
        }
        Ok(RentalLeaseGuard {
            _lock: super::lane_budget::RaiseLock::acquire_file(
                root,
                &format!(".rental-operation-{id}.lock"),
            )?,
        })
    }

    pub fn list(root: &Path) -> Result<Vec<RentalLease>, String> {
        update(root, |store| Ok(store.leases.values().cloned().collect()))
    }

    /// Recover the existing intent before re-reading policy or issuing any provider request.
    pub fn by_operation(root: &Path, operation: &str) -> Result<Option<RentalLease>, String> {
        update(root, |store| {
            Ok(store
                .leases
                .values()
                .find(|lease| lease.operation == operation)
                .cloned())
        })
    }

    /// Provider-confirmed identity following create or reconciliation.
    pub fn activate(root: &Path, id: &str, server_id: &str) -> Result<(), String> {
        if server_id.is_empty() {
            return Err("empty provider server ID".into());
        }
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            match lease.state {
                RentalLeaseState::Creating => {
                    lease.server_id = Some(server_id.to_owned());
                    lease.state = RentalLeaseState::PendingIdentity;
                    Ok(())
                }
                RentalLeaseState::PendingIdentity | RentalLeaseState::Active
                    if lease.server_id.as_deref() == Some(server_id) =>
                {
                    Ok(())
                }
                _ => Err("invalid lease activation".into()),
            }
        })
    }

    /// Bind a uniquely reconciled server to a destroy intent without resurrecting it.
    pub fn bind_destroying_server(root: &Path, id: &str, server_id: &str) -> Result<(), String> {
        if server_id.is_empty() {
            return Err("empty provider server ID".into());
        }
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            if lease.state != RentalLeaseState::DestroyingPendingIdentity {
                return Err("lease is not pending destruction".into());
            }
            if lease
                .server_id
                .as_deref()
                .is_some_and(|existing| existing != server_id)
            {
                return Err("provider server identity mismatch".into());
            }
            lease.server_id = Some(server_id.to_owned());
            Ok(())
        })
    }

    /// Bind the exact SSH identity and target before it can become schedulable.
    pub fn bind_enrollment(
        root: &Path,
        id: &str,
        identity: RentalEnrollment,
        target: &str,
        alias: &str,
    ) -> Result<(), String> {
        identity.validate()?;
        if !super::valid_id(target) || !super::valid_id(alias) || target == alias {
            return Err("invalid enrollment target".into());
        }
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            if lease.server_id.as_deref() != Some(identity.server_id.as_str())
                || !matches!(
                    lease.state,
                    RentalLeaseState::PendingIdentity | RentalLeaseState::Enrolling
                )
            {
                return Err("enrollment server or lease state mismatch".into());
            }
            if lease
                .target_id
                .as_deref()
                .is_some_and(|existing| existing != target)
                || lease
                    .target_alias
                    .as_deref()
                    .is_some_and(|existing| existing != alias)
            {
                return Err("enrollment target already bound".into());
            }
            if let Some(existing) = &lease.enrollment {
                if existing != &identity {
                    return Err("enrollment identity already bound".into());
                }
            } else {
                lease.enrollment = Some(identity);
            }
            lease.target_id = Some(target.to_owned());
            lease.target_alias = Some(alias.to_owned());
            lease.state = RentalLeaseState::Enrolling;
            Ok(())
        })
    }

    /// Transition only after the caller has authenticated and registered this target.
    pub fn enrolled(root: &Path, id: &str, target: &str, alias: &str) -> Result<(), String> {
        if !super::valid_id(target) || !super::valid_id(alias) {
            return Err("invalid target identity".into());
        }
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            match lease.state {
                RentalLeaseState::Enrolling
                    if lease.target_id.as_deref() == Some(target)
                        && lease.target_alias.as_deref() == Some(alias) =>
                {
                    lease.state = RentalLeaseState::Active;
                    Ok(())
                }
                RentalLeaseState::Active
                    if lease.target_id.as_deref() == Some(target)
                        && lease.target_alias.as_deref() == Some(alias) =>
                {
                    Ok(())
                }
                _ => Err("invalid lease enrollment".into()),
            }
        })
    }

    /// Mark before sending a destroy request; this transition never resurrects a lease.
    pub fn destroying(root: &Path, id: &str) -> Result<(), String> {
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            match lease.state {
                RentalLeaseState::Creating | RentalLeaseState::PendingIdentity => {
                    lease.state = RentalLeaseState::DestroyingPendingIdentity
                }
                RentalLeaseState::Enrolling | RentalLeaseState::Active => {
                    lease.state = RentalLeaseState::Destroying
                }
                RentalLeaseState::Destroying | RentalLeaseState::DestroyingPendingIdentity => {}
                RentalLeaseState::Destroyed => return Err("lease already destroyed".into()),
            }
            Ok(())
        })
    }

    /// Persist provider-confirmed billing end before settlement, keeping the first observation.
    pub fn confirm_end(root: &Path, id: &str, now_ms: u64) -> Result<u64, String> {
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            if !matches!(
                lease.state,
                RentalLeaseState::Destroying | RentalLeaseState::DestroyingPendingIdentity
            ) {
                return Err("lease was not being destroyed".into());
            }
            Ok(*lease.destroyed_ms.get_or_insert(now_ms))
        })
    }

    /// Mark terminal only after confirmed-end accounting has been settled.
    pub fn destroyed(root: &Path, id: &str) -> Result<(), String> {
        update(root, |store| {
            let lease = store.leases.get_mut(id).ok_or("unknown lease")?;
            match lease.state {
                RentalLeaseState::Destroying | RentalLeaseState::DestroyingPendingIdentity
                    if lease.destroyed_ms.is_some() =>
                {
                    lease.state = RentalLeaseState::Destroyed;
                    Ok(())
                }
                RentalLeaseState::Destroyed => Ok(()),
                _ => Err("lease was not being destroyed".into()),
            }
        })
    }
}
