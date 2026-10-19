//! Durable browser control generation: the browser-owned canonical control
//! state persisted opaquely by `odin-ledger` through compare-and-swap.
//!
//! Every control-generation commit is durably fenced before it becomes
//! visible in memory, so a replacement host can always evict a stale writer.

use std::sync::{Arc, Mutex as StdMutex};

use odin_domain::huginn::browser::BrowserTakeoverStatus;
use odin_domain::huginn::ids::BrowserSessionId;
use odin_ledger::browser_control::{BrowserControlStateRow, OpenBrowserControlState};
use odin_ledger::{Ledger, LedgerError};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::takeover::TakeoverCoordinator;

use super::SessionError;

const BROWSER_CONTROL_STATE_SCHEMA: &str = "odin.browser.control-state.v1";

/// Browser-owned canonical payload persisted opaquely by `odin-ledger`.
/// `materialized_status.revision` must exactly equal `control_revision`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DurableBrowserControlState {
    schema: String,
    session_id: BrowserSessionId,
    control_revision: u64,
    takeover_revision: u64,
    takeover: BrowserTakeoverStatus,
    lease_token: Option<u64>,
    lease_expires_at: Option<OffsetDateTime>,
}

pub(super) struct DurableControlOwner {
    pub(super) ledger: Arc<StdMutex<Ledger>>,
    pub(super) row_revision: i64,
}

/// Control initialization facts for a session launch: the control revision
/// the fresh session starts from and, when it owns a durable control
/// generation, its ledger-backed owner.
pub(super) struct ControlInit {
    pub(super) initial_control_revision: u64,
    pub(super) durable_control: Option<DurableControlOwner>,
}

impl DurableBrowserControlState {
    pub(super) fn available(session_id: BrowserSessionId, control_revision: u64) -> Self {
        Self {
            schema: BROWSER_CONTROL_STATE_SCHEMA.to_owned(),
            session_id,
            control_revision,
            takeover_revision: 1,
            takeover: BrowserTakeoverStatus::Available,
            lease_token: None,
            lease_expires_at: None,
        }
    }

    pub(super) fn from_control(
        session_id: BrowserSessionId,
        control_revision: u64,
        takeover: &TakeoverCoordinator,
        lease_token: Option<u64>,
    ) -> Self {
        let view = takeover.view();
        Self {
            schema: BROWSER_CONTROL_STATE_SCHEMA.to_owned(),
            session_id,
            control_revision,
            takeover_revision: view.revision,
            takeover: view.status,
            lease_token,
            lease_expires_at: takeover.lease_deadline(),
        }
    }

    pub(super) fn canonical_json(&self) -> Result<String, SessionError> {
        self.validate_invariants()?;
        serde_json::to_string(self).map_err(|_| SessionError::DurableControlInvalid)
    }

    fn validate_invariants(&self) -> Result<(), SessionError> {
        if self.schema != BROWSER_CONTROL_STATE_SCHEMA
            || self.control_revision == 0
            || self.takeover_revision == 0
            || self.takeover_revision > self.control_revision
        {
            return Err(SessionError::DurableControlInvalid);
        }
        match (&self.takeover, self.lease_token, self.lease_expires_at) {
            (
                BrowserTakeoverStatus::Held { acquired_at, .. },
                Some(lease_token),
                Some(expires_at),
            ) if lease_token > 0
                && lease_token <= self.control_revision
                && expires_at > *acquired_at =>
            {
                Ok(())
            }
            (
                BrowserTakeoverStatus::Available | BrowserTakeoverStatus::ReclaimedLocally { .. },
                None,
                None,
            ) => Ok(()),
            _ => Err(SessionError::DurableControlInvalid),
        }
    }
}

pub(super) fn decode_durable_control_row(
    row: &BrowserControlStateRow,
    expected_session_id: BrowserSessionId,
) -> Result<DurableBrowserControlState, SessionError> {
    let state: DurableBrowserControlState =
        serde_json::from_str(&row.state_json).map_err(|_| SessionError::DurableControlInvalid)?;
    state.validate_invariants()?;
    if state.session_id != expected_session_id
        || i64::try_from(state.control_revision)
            .ok()
            .is_none_or(|revision| revision != row.revision)
    {
        return Err(SessionError::DurableControlInvalid);
    }
    let canonical = state.canonical_json()?;
    if canonical != row.state_json {
        return Err(SessionError::DurableControlInvalid);
    }
    Ok(state)
}

pub(super) fn open_durable_control_owner(
    ledger: Arc<StdMutex<Ledger>>,
    session_id: BrowserSessionId,
    at: OffsetDateTime,
) -> Result<(u64, DurableControlOwner), SessionError> {
    let initial = DurableBrowserControlState::available(session_id, 1);
    let initial_json = initial.canonical_json()?;
    let object_id = session_id.to_string();
    let mut guard = ledger
        .lock()
        .map_err(|_| SessionError::DurableControlUnavailable)?;
    let opened = guard
        .open_browser_control_state(&object_id, &initial_json, at)
        .map_err(control_store_error)?;
    let (control_revision, row) = match opened {
        OpenBrowserControlState::Created(row) => {
            let state = decode_durable_control_row(&row, session_id)?;
            if state != initial || row.revision != 1 {
                return Err(SessionError::DurableControlInvalid);
            }
            (1, row)
        }
        OpenBrowserControlState::Existing(row) => {
            let prior = decode_durable_control_row(&row, session_id)?;
            let next_control_revision = prior
                .control_revision
                .checked_add(1)
                .ok_or(SessionError::ControlRevisionOverflow)?;
            let restarted =
                DurableBrowserControlState::available(session_id, next_control_revision);
            let restarted_json = restarted.canonical_json()?;
            let row = guard
                .cas_browser_control_state(&object_id, row.revision, &restarted_json, at)
                .map_err(control_store_error)?;
            let persisted = decode_durable_control_row(&row, session_id)?;
            if persisted != restarted {
                return Err(SessionError::DurableControlInvalid);
            }
            (next_control_revision, row)
        }
    };
    drop(guard);
    Ok((
        control_revision,
        DurableControlOwner {
            ledger,
            row_revision: row.revision,
        },
    ))
}

pub(super) fn control_store_error(error: LedgerError) -> SessionError {
    match error {
        LedgerError::StaleActor { .. } | LedgerError::NotFound { .. } => {
            SessionError::DurableControlStale
        }
        LedgerError::InvalidData { .. } | LedgerError::Json(_) | LedgerError::TimestampParse(_) => {
            SessionError::DurableControlInvalid
        }
        _ => SessionError::DurableControlUnavailable,
    }
}
#[cfg(test)]
mod durable_control_tests {
    use odin_domain::huginn::ids::DeviceId;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use odin_domain::huginn::browser::{BrowserTakeoverCommand, BrowserTakeoverStatus};
    use odin_ledger::{Ledger, LedgerError};

    use super::*;

    const SESSION_ID: &str = "00000000-0000-4000-8000-000000000008";
    const HOLDER_ID: &str = "00000000-0000-4000-8000-0000000000a1";

    fn session_id() -> BrowserSessionId {
        BrowserSessionId::parse(SESSION_ID).expect("session id")
    }

    fn holder_id() -> DeviceId {
        DeviceId::parse(HOLDER_ID).expect("holder id")
    }

    fn at(second: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_312_000 + second).expect("fixture timestamp")
    }

    #[test]
    fn durable_control_reopen_invalidates_holder_and_advances_revision() {
        let session_id = session_id();
        let holder = holder_id();
        let ledger = Arc::new(StdMutex::new(Ledger::open_in_memory().expect("ledger")));
        let (initial_revision, initial_owner) =
            open_durable_control_owner(Arc::clone(&ledger), session_id, at(0))
                .expect("fresh durable control");
        assert_eq!(initial_revision, 1);
        assert_eq!(initial_owner.row_revision, 1);

        // Commit an actually held generation to the real SQLite owner.
        let mut takeover =
            TakeoverCoordinator::with_lease_ttl(session_id, Duration::from_secs(60), at(1));
        takeover
            .apply_authenticated(
                holder,
                &BrowserTakeoverCommand::Acquire { device_id: holder },
                at(1),
            )
            .expect("acquire");
        let held = DurableBrowserControlState::from_control(session_id, 2, &takeover, Some(2));
        let held_json = held.canonical_json().expect("canonical held state");
        {
            let mut guard = ledger.lock().expect("ledger lock");
            let held_row = guard
                .cas_browser_control_state(SESSION_ID, 1, &held_json, at(2))
                .expect("persist held generation");
            assert_eq!(held_row.revision, 2);
        }
        drop(initial_owner);

        // A real reopen CAS-advances the durable generation and deliberately
        // persists no holder, token, or deadline before the new host runs.
        let (reopened_revision, reopened_owner) =
            open_durable_control_owner(Arc::clone(&ledger), session_id, at(3))
                .expect("durable reopen");
        assert_eq!(reopened_revision, 3);
        assert_eq!(reopened_owner.row_revision, 3);
        let reopened_row = ledger
            .lock()
            .expect("ledger lock")
            .browser_control_state(SESSION_ID)
            .expect("read")
            .expect("row");
        let reopened =
            decode_durable_control_row(&reopened_row, session_id).expect("valid reopened state");
        assert_eq!(reopened.control_revision, 3);
        assert_eq!(reopened.takeover_revision, 1);
        assert!(matches!(
            reopened.takeover,
            BrowserTakeoverStatus::Available
        ));
        assert!(reopened.lease_token.is_none());
        assert!(reopened.lease_expires_at.is_none());

        // The crashed holder's generation cannot overwrite the replacement.
        let stale = ledger
            .lock()
            .expect("ledger lock")
            .cas_browser_control_state(SESSION_ID, 2, &held_json, at(4));
        assert!(matches!(
            stale,
            Err(LedgerError::StaleActor {
                expected_revision: 2,
                actual_revision: 3,
                ..
            })
        ));
    }

    #[test]
    fn durable_control_reopen_rejects_noncanonical_payload() {
        let session_id = session_id();
        let ledger = Arc::new(StdMutex::new(Ledger::open_in_memory().expect("ledger")));
        let initial = DurableBrowserControlState::available(session_id, 1);
        let noncanonical = format!(" {}", initial.canonical_json().expect("canonical"));
        ledger
            .lock()
            .expect("ledger lock")
            .open_browser_control_state(SESSION_ID, &noncanonical, at(0))
            .expect("ledger accepts caller-owned object");

        assert!(matches!(
            open_durable_control_owner(ledger, session_id, at(1)),
            Err(SessionError::DurableControlInvalid)
        ));
    }
}
