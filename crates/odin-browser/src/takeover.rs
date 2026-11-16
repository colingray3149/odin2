//! Serialized remote takeover state for one browser session.
//!
//! Authenticated devices can acquire or release only their own identity.
//! Remote commands cannot produce `ReclaimedLocally`: that transition requires
//! a sealed witness constructed only by the local session supervisor. The
//! coordinator stores no capability, policy, approval, or artifact authority;
//! takeover changes controller truth and nothing else.
//!
//! A held takeover is a bounded control lease. The coordinator owns its
//! holder, local takeover revision, and deadline; the serialized session owner
//! binds the lease to the durable control-revision token. When the deadline
//! passes, the local session supervisor retires the lease through the sealed
//! witness: holder and token stop surviving, the revision advances, and
//! controller truth becomes available.
//! A fresh coordinator after a real session restart
//! holds nothing and restarts its revision, so no lease can be resurrected.

use std::time::Duration;

use odin_domain::huginn::browser::{
    BrowserTakeoverCommand, BrowserTakeoverStatus, BrowserTakeoverView,
};
use odin_domain::huginn::ids::{BrowserSessionId, DeviceId};
use thiserror::Error;
use time::OffsetDateTime;

/// Limits how long an absent remote holder can lock the session.
pub const DEFAULT_TAKEOVER_LEASE_TTL: Duration = Duration::from_secs(15 * 60);

mod sealed {
    pub(crate) struct Local;
}

/// Unforgeable witness that a transition originated in the local session
/// supervisor rather than the authenticated remote command path.
pub struct LocalReclaim {
    _sealed: sealed::Local,
}

impl LocalReclaim {
    /// Only crate-local session/process supervision can mint this witness.
    pub(crate) fn local() -> Self {
        Self {
            _sealed: sealed::Local,
        }
    }
}

/// Rejected controller transitions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TakeoverError {
    #[error("verified device {actor} may not act as device {commanded}")]
    ActorMismatch {
        actor: DeviceId,
        commanded: DeviceId,
    },
    #[error("browser takeover is already held by device {holder}")]
    AlreadyHeld { holder: DeviceId },
    #[error("browser takeover is not held")]
    NotHeld,
    #[error("device {actor} cannot release takeover held by {holder}")]
    NotHolder { actor: DeviceId, holder: DeviceId },
    #[error("browser takeover is reclaimed locally")]
    ReclaimedLocally,
    #[error("browser takeover has already been reclaimed locally")]
    AlreadyReclaimed,
    #[error("browser takeover is not in locally reclaimed state")]
    NotReclaimed,
    #[error("browser takeover revision overflowed")]
    RevisionOverflow,
}

/// Serialized controller truth for one browser session.
///
/// The session actor owns this value mutably; there is no independent frame
/// or delivery state that can change its truth.
#[derive(Clone)]
pub struct TakeoverCoordinator {
    session_id: BrowserSessionId,
    revision: u64,
    status: BrowserTakeoverStatus,
    updated_at: OffsetDateTime,
    lease_ttl: Duration,
}

/// Exact internal retirement facts carried into the public session expiry
/// observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetiredLease {
    pub(crate) holder: DeviceId,
    pub(crate) view: BrowserTakeoverView,
}

impl TakeoverCoordinator {
    /// Starts with no remote controller at revision one and the supplied
    /// control-lease lifetime. Production sessions pass their validated
    /// mechanism deadline; explicit clocks and lifetimes keep transition tests
    /// deterministic.
    pub fn with_lease_ttl(
        session_id: BrowserSessionId,
        lease_ttl: Duration,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            session_id,
            revision: 1,
            status: BrowserTakeoverStatus::Available,
            updated_at: now,
            lease_ttl,
        }
    }

    /// Applies a remote acquire/release command only when its embedded device
    /// is the authenticated actor. This is the only public remote transition
    /// entry point and cannot manufacture a local-reclaim transition.
    pub fn apply_authenticated(
        &mut self,
        actor: DeviceId,
        command: &BrowserTakeoverCommand,
        now: OffsetDateTime,
    ) -> Result<BrowserTakeoverView, TakeoverError> {
        match command {
            BrowserTakeoverCommand::Acquire { device_id } => {
                self.require_self(actor, *device_id)?;
                self.acquire(*device_id, now)?;
            }
            BrowserTakeoverCommand::Release { device_id } => {
                self.require_self(actor, *device_id)?;
                self.release(*device_id, now)?;
            }
        }
        Ok(self.view())
    }

    /// Crate-local acquire after authenticated actor binding.
    pub(crate) fn acquire(
        &mut self,
        device_id: DeviceId,
        now: OffsetDateTime,
    ) -> Result<BrowserTakeoverStatus, TakeoverError> {
        match &self.status {
            BrowserTakeoverStatus::Available => {
                self.transition(
                    BrowserTakeoverStatus::Held {
                        device_id,
                        acquired_at: now,
                    },
                    now,
                )?;
                Ok(self.status.clone())
            }
            BrowserTakeoverStatus::Held { device_id, .. } => {
                Err(TakeoverError::AlreadyHeld { holder: *device_id })
            }
            BrowserTakeoverStatus::ReclaimedLocally { .. } => Err(TakeoverError::ReclaimedLocally),
        }
    }

    /// Crate-local release after authenticated actor binding.
    pub(crate) fn release(
        &mut self,
        device_id: DeviceId,
        now: OffsetDateTime,
    ) -> Result<BrowserTakeoverStatus, TakeoverError> {
        match &self.status {
            BrowserTakeoverStatus::Held {
                device_id: holder, ..
            } if *holder == device_id => {
                self.transition(BrowserTakeoverStatus::Available, now)?;
                Ok(self.status.clone())
            }
            BrowserTakeoverStatus::Held {
                device_id: holder, ..
            } => Err(TakeoverError::NotHolder {
                actor: device_id,
                holder: *holder,
            }),
            BrowserTakeoverStatus::Available => Err(TakeoverError::NotHeld),
            BrowserTakeoverStatus::ReclaimedLocally { .. } => Err(TakeoverError::ReclaimedLocally),
        }
    }

    /// Deadline at which the currently held control lease expires. `None`
    /// while no lease is held.
    pub fn lease_deadline(&self) -> Option<OffsetDateTime> {
        match &self.status {
            BrowserTakeoverStatus::Held { acquired_at, .. } => {
                let lease_ttl = time::Duration::try_from(self.lease_ttl).ok()?;
                acquired_at.checked_add(lease_ttl)
            }
            _ => None,
        }
    }

    /// Retires the held control lease once its deadline has passed. Sealed to
    /// the local session supervisor, so no remotely decoded command can
    /// trigger or mimic it. A due lease loses its holder and token, the
    /// revision advances, and controller truth becomes available. Returns
    /// `None` while the lease is unexpired or nothing is held, so repeated
    /// timer and admission checks are harmless.
    pub(crate) fn expire_lease_if_due(
        &mut self,
        _witness: LocalReclaim,
        now: OffsetDateTime,
    ) -> Result<Option<RetiredLease>, TakeoverError> {
        let Some(holder) = self.due_lease(now) else {
            return Ok(None);
        };
        self.retire_held_lease(holder, now).map(Some)
    }

    /// Retires the held control lease immediately, whether or not the
    /// deadline has passed. Sealed like timed expiry: local supervision may
    /// end the lease at any moment and runs the identical retirement path.
    pub(crate) fn expire_lease_now(
        &mut self,
        _witness: LocalReclaim,
        now: OffsetDateTime,
    ) -> Result<Option<RetiredLease>, TakeoverError> {
        let Some(holder) = self.holder() else {
            return Ok(None);
        };
        self.retire_held_lease(holder, now).map(Some)
    }

    fn holder(&self) -> Option<DeviceId> {
        match &self.status {
            BrowserTakeoverStatus::Held { device_id, .. } => Some(*device_id),
            _ => None,
        }
    }

    fn due_lease(&self, now: OffsetDateTime) -> Option<DeviceId> {
        let deadline = self.lease_deadline()?;
        (now >= deadline).then(|| self.holder()).flatten()
    }

    /// Assumes a lease is held: transitions to available, retires the token,
    /// and reports the exact retired facts.
    fn retire_held_lease(
        &mut self,
        holder: DeviceId,
        now: OffsetDateTime,
    ) -> Result<RetiredLease, TakeoverError> {
        self.transition(BrowserTakeoverStatus::Available, now)?;
        Ok(RetiredLease {
            holder,
            view: self.view(),
        })
    }

    pub fn status(&self) -> &BrowserTakeoverStatus {
        &self.status
    }

    pub fn view(&self) -> BrowserTakeoverView {
        BrowserTakeoverView {
            session_id: self.session_id,
            revision: self.revision,
            status: self.status.clone(),
            updated_at: self.updated_at,
        }
    }

    fn require_self(&self, actor: DeviceId, commanded: DeviceId) -> Result<(), TakeoverError> {
        if actor == commanded {
            Ok(())
        } else {
            Err(TakeoverError::ActorMismatch { actor, commanded })
        }
    }

    fn transition(
        &mut self,
        status: BrowserTakeoverStatus,
        now: OffsetDateTime,
    ) -> Result<(), TakeoverError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(TakeoverError::RevisionOverflow)?;
        self.status = status;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration as TimeDuration;

    const SESSION_ID: &str = "00000000-0000-4000-8000-000000000008";
    const HOLDER_ID: &str = "00000000-0000-4000-8000-0000000000a1";
    const FOREIGN_ID: &str = "00000000-0000-4000-8000-0000000000a2";

    fn fixture() -> (BrowserSessionId, DeviceId, DeviceId) {
        (
            BrowserSessionId::parse(SESSION_ID).expect("session id"),
            DeviceId::parse(HOLDER_ID).expect("holder device id"),
            DeviceId::parse(FOREIGN_ID).expect("foreign device id"),
        )
    }

    /// One deterministic clock: minutes past a fixed epoch instant.
    fn at(minutes: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("fixed epoch")
            .checked_add(TimeDuration::minutes(minutes))
            .expect("fixture instant")
    }

    fn coordinator(
        lease_ttl: Duration,
    ) -> (TakeoverCoordinator, BrowserSessionId, DeviceId, DeviceId) {
        let (session_id, holder, foreign) = fixture();
        let coordinator = TakeoverCoordinator::with_lease_ttl(session_id, lease_ttl, at(0));
        (coordinator, session_id, holder, foreign)
    }

    fn acquire(coordinator: &mut TakeoverCoordinator, device: DeviceId, at: OffsetDateTime) {
        coordinator
            .apply_authenticated(
                device,
                &BrowserTakeoverCommand::Acquire { device_id: device },
                at,
            )
            .expect("authenticated acquire");
    }

    /// Only the authenticated holder, acting as itself, changes a held lease.
    #[test]
    fn takeover_admits_only_the_authenticated_holder() {
        let (mut coordinator, _session, holder, foreign) = coordinator(DEFAULT_TAKEOVER_LEASE_TTL);
        let acquired = coordinator
            .apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Acquire { device_id: holder },
                at(1),
            )
            .expect("acquire");
        assert!(matches!(
            acquired.status,
            BrowserTakeoverStatus::Held { .. }
        ));
        assert_eq!(acquired.revision, 2);

        // A foreign device cannot release the holder's lease, and the holder
        // alone may release.
        assert!(matches!(
            coordinator.apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Release { device_id: foreign },
                at(2),
            ),
            Err(TakeoverError::NotHolder { .. })
        ));
        assert_eq!(coordinator.view().revision, 2);

        // A device may act only as itself: naming the holder from another
        // device's authenticated session changes nothing.
        assert!(matches!(
            coordinator.apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Acquire { device_id: holder },
                at(2),
            ),
            Err(TakeoverError::ActorMismatch { .. })
        ));
        assert_eq!(coordinator.view().revision, 2);
    }

    /// Real expiry: a due lease retires holder and token in one transition,
    /// leaves no surviving holder, and rejects every replay of the retired
    /// lease; before the deadline nothing happens.
    #[test]
    fn lease_expiry_retires_holder_and_token() {
        let (mut coordinator, _session, holder, foreign) = coordinator(Duration::from_secs(60));
        acquire(&mut coordinator, holder, at(0));
        let lease_revision = coordinator.view().revision;
        assert_eq!(coordinator.lease_deadline(), Some(at(1)));

        // One minute before the deadline the lease still stands.
        assert!(coordinator
            .expire_lease_if_due(LocalReclaim::local(), at(0) + TimeDuration::seconds(59),)
            .expect("pre-deadline expiry check")
            .is_none());
        assert!(matches!(
            coordinator.status(),
            BrowserTakeoverStatus::Held { .. }
        ));

        // At the deadline the timed retirement is exact.
        let retired = coordinator
            .expire_lease_if_due(LocalReclaim::local(), at(1))
            .expect("expiry transition")
            .expect("due lease retired");
        assert_eq!(retired.holder, holder);
        assert!(matches!(
            &retired.view.status,
            BrowserTakeoverStatus::Available
        ));
        assert!(retired.view.revision > lease_revision);

        // Zero surviving holder. Repeated timer checks do nothing, and a
        // release carrying the retired lease's identity is rejected.
        assert!(matches!(
            coordinator.status(),
            BrowserTakeoverStatus::Available
        ));
        assert!(coordinator
            .expire_lease_if_due(LocalReclaim::local(), at(2))
            .expect("repeat expiry check")
            .is_none());
        assert!(matches!(
            coordinator.apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Release { device_id: holder },
                at(2),
            ),
            Err(TakeoverError::NotHeld)
        ));

        // The forced supervision path is the same retirement as the timer's, and the
        // second racer finds nothing left to retire.
        acquire(&mut coordinator, holder, at(3));
        let forced = coordinator
            .expire_lease_now(LocalReclaim::local(), at(3) + TimeDuration::seconds(1))
            .expect("forced expiry")
            .expect("forced retirement");
        assert_eq!(forced.holder, holder);
        assert!(coordinator
            .expire_lease_now(LocalReclaim::local(), at(3) + TimeDuration::seconds(1))
            .expect("second racer")
            .is_none());

        // A later acquire is a new lease generation, never resurrection of
        // the retired token.
        let reacquired = coordinator
            .apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Acquire { device_id: foreign },
                at(5),
            )
            .expect("new lease after expiry");
        assert!(matches!(
            &reacquired.status,
            BrowserTakeoverStatus::Held { .. }
        ));
        assert!(reacquired.revision > forced.view.revision);
    }
}
