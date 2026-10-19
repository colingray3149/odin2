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
    pub(crate) lease_revision: u64,
    pub(crate) view: BrowserTakeoverView,
}

impl TakeoverCoordinator {
    /// Starts with no remote controller at revision one and the default
    /// control-lease lifetime.
    pub fn new(session_id: BrowserSessionId, now: OffsetDateTime) -> Self {
        Self::with_lease_ttl(session_id, DEFAULT_TAKEOVER_LEASE_TTL, now)
    }

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

    /// Locally reclaims a held remote controller. The sealed witness makes
    /// this transition unavailable to all remotely decoded command values.
    pub(crate) fn reclaim_locally(
        &mut self,
        _witness: LocalReclaim,
        now: OffsetDateTime,
    ) -> Result<BrowserTakeoverStatus, TakeoverError> {
        match &self.status {
            BrowserTakeoverStatus::Held { .. } => {
                self.transition(
                    BrowserTakeoverStatus::ReclaimedLocally { reclaimed_at: now },
                    now,
                )?;
                Ok(self.status.clone())
            }
            BrowserTakeoverStatus::Available => Err(TakeoverError::NotHeld),
            BrowserTakeoverStatus::ReclaimedLocally { .. } => Err(TakeoverError::AlreadyReclaimed),
        }
    }

    /// Returns a completed local reclaim to the available state. Also sealed;
    /// a remote device cannot clear a local reclaim and reacquire control.
    pub(crate) fn make_available_locally(
        &mut self,
        _witness: LocalReclaim,
        now: OffsetDateTime,
    ) -> Result<BrowserTakeoverStatus, TakeoverError> {
        match &self.status {
            BrowserTakeoverStatus::ReclaimedLocally { .. } => {
                self.transition(BrowserTakeoverStatus::Available, now)?;
                Ok(self.status.clone())
            }
            _ => Err(TakeoverError::NotReclaimed),
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
        let Some((holder, token)) = self.due_lease(now) else {
            return Ok(None);
        };
        self.retire_held_lease(holder, token, now).map(Some)
    }

    /// Retires the held control lease immediately, whether or not the
    /// deadline has passed. Sealed like timed expiry: local supervision may
    /// end the lease at any moment and runs the identical retirement path.
    pub(crate) fn expire_lease_now(
        &mut self,
        _witness: LocalReclaim,
        now: OffsetDateTime,
    ) -> Result<Option<RetiredLease>, TakeoverError> {
        let (holder, lease_revision) = match &self.status {
            BrowserTakeoverStatus::Held { device_id, .. } => (*device_id, self.revision),
            _ => return Ok(None),
        };
        self.retire_held_lease(holder, lease_revision, now)
            .map(Some)
    }

    fn due_lease(&self, now: OffsetDateTime) -> Option<(DeviceId, u64)> {
        let deadline = self.lease_deadline()?;
        if now < deadline {
            return None;
        }
        match &self.status {
            BrowserTakeoverStatus::Held { device_id, .. } => Some((*device_id, self.revision)),
            _ => None,
        }
    }

    /// Assumes a lease is held: transitions to available, retires the token,
    /// and reports the exact retired facts.
    fn retire_held_lease(
        &mut self,
        holder: DeviceId,
        lease_revision: u64,
        now: OffsetDateTime,
    ) -> Result<RetiredLease, TakeoverError> {
        self.transition(BrowserTakeoverStatus::Available, now)?;
        Ok(RetiredLease {
            holder,
            lease_revision,
            view: self.view(),
        })
    }

    pub fn status(&self) -> &BrowserTakeoverStatus {
        &self.status
    }

    pub fn revision(&self) -> u64 {
        self.revision
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

    /// Reclaim is local-only, advances the revision, and prevents the remote holder from returning.
    #[test]
    fn takeover_reclaim() {
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
        assert_eq!(coordinator.revision(), 2);

        // The sealed local witness reclaims; remote commands cannot.
        let reclaimed = coordinator
            .reclaim_locally(LocalReclaim::local(), at(3))
            .expect("local reclaim");
        assert!(matches!(
            reclaimed,
            BrowserTakeoverStatus::ReclaimedLocally { .. }
        ));
        assert_eq!(coordinator.revision(), 3);
        assert!(matches!(
            coordinator.apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Acquire { device_id: holder },
                at(4),
            ),
            Err(TakeoverError::ReclaimedLocally)
        ));

        // Only the sealed local release reopens the session for takeover.
        coordinator
            .make_available_locally(LocalReclaim::local(), at(5))
            .expect("local release");
        let reacquired = coordinator
            .apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Acquire { device_id: foreign },
                at(6),
            )
            .expect("reacquire after local release");
        assert!(matches!(
            reacquired.status,
            BrowserTakeoverStatus::Held { .. }
        ));
        assert_eq!(reacquired.revision, 5);
    }

    /// Real expiry: a due lease retires holder and token in one transition,
    /// leaves no surviving holder, and rejects every replay of the retired
    /// lease; before the deadline nothing happens.
    #[test]
    fn lease_expiry_retires_holder_and_token() {
        let (mut coordinator, _session, holder, foreign) = coordinator(Duration::from_secs(60));
        acquire(&mut coordinator, holder, at(0));
        let lease_revision = coordinator.revision();
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
        assert_eq!(retired.lease_revision, lease_revision);
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

        // A later acquire is a new lease generation, never resurrection of
        // the retired token.
        let reacquired = coordinator
            .apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Acquire { device_id: foreign },
                at(3),
            )
            .expect("new lease after expiry");
        assert!(matches!(
            &reacquired.status,
            BrowserTakeoverStatus::Held { .. }
        ));
        assert_ne!(reacquired.revision, retired.lease_revision);
        assert_eq!(coordinator.revision(), lease_revision + 2);
    }

    /// Restart truth: a real restart builds a fresh coordinator that holds
    /// nothing at a restarted revision below the pre-restart value, and no
    /// command from the previous generation's lease can act on it.
    #[test]
    fn restart_truth_fresh_coordinator_holds_nothing() {
        let (mut coordinator, _session, holder, _foreign) = coordinator(DEFAULT_TAKEOVER_LEASE_TTL);
        acquire(&mut coordinator, holder, at(0));
        let pre_restart_revision = coordinator.revision();
        assert!(matches!(
            coordinator.view().status,
            BrowserTakeoverStatus::Held { .. }
        ));

        // The host/session restart: the coordinator instance is not carried
        // across; nothing survives it.
        let (session_id, holder, _foreign) = fixture();
        let mut restarted = TakeoverCoordinator::new(session_id, at(30));
        assert_eq!(restarted.revision(), 1);
        assert!(restarted.revision() < pre_restart_revision);
        assert!(matches!(
            restarted.status(),
            BrowserTakeoverStatus::Available
        ));
        assert!(restarted.lease_deadline().is_none());

        // The old generation's holder cannot release or re-enter: its lease
        // never survived the restart.
        assert!(matches!(
            restarted.apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Release { device_id: holder },
                at(31),
            ),
            Err(TakeoverError::NotHeld)
        ));
    }

    /// Race and replay bounds: whichever supervisor path reaches a held lease
    /// first retires it exactly once; the forced path is the same transition
    /// the timer runs; remote commands can retire nothing.
    #[test]
    fn lease_expiry_race_and_replay_are_bounded() {
        let (mut coordinator, _session, holder, foreign) = coordinator(Duration::from_secs(60));
        acquire(&mut coordinator, holder, at(0));

        // Forced supervision expiry before the deadline: identical retirement
        // facts as the timed path.
        let forced = coordinator
            .expire_lease_now(LocalReclaim::local(), at(0) + TimeDuration::seconds(1))
            .expect("expiry transition")
            .expect("forced retirement");
        assert_eq!(forced.holder, holder);
        assert!(matches!(
            &forced.view.status,
            BrowserTakeoverStatus::Available
        ));

        // The second racer observes nothing left to retire.
        assert!(coordinator
            .expire_lease_if_due(LocalReclaim::local(), at(0) + TimeDuration::seconds(1),)
            .expect("timed racer")
            .is_none());
        assert!(coordinator
            .expire_lease_now(LocalReclaim::local(), at(0) + TimeDuration::seconds(1),)
            .expect("forced racer")
            .is_none());

        // The old release is rejected. A later authenticated acquire mints a
        // strictly newer lease instead of reviving the old token.
        assert!(matches!(
            coordinator.apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Release { device_id: holder },
                at(1),
            ),
            Err(TakeoverError::NotHeld)
        ));
        let reacquired = coordinator
            .apply_authenticated(
                foreign,
                &BrowserTakeoverCommand::Acquire { device_id: foreign },
                at(1),
            )
            .expect("new lease after racing expiry");
        assert!(reacquired.revision > forced.lease_revision);
    }
}
