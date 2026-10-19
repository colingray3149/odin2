//! Serialized session control truth: lifecycle guards, control-revision
//! persistence through the durable CAS owner, takeover-lease expiry, and the
//! public session-view builder. Guarded by one tokio mutex in the facade so
//! each control operation and each delivered event are routed serially.

use time::OffsetDateTime;

use odin_domain::huginn::browser::{
    BrowserSessionState, BrowserSessionView, BrowserTakeoverStatus,
};
use odin_domain::huginn::ids::DeviceId;

use crate::capability::PolicyBinding;
use crate::takeover::{LocalReclaim, TakeoverCoordinator};

use super::actions;
use super::control::{control_store_error, decode_durable_control_row, DurableBrowserControlState};
use super::reads;
use super::runtime;
use super::{
    AbandonedAction, ObservedPage, SessionError, SessionPhase, State, TakeoverLeaseExpiry,
};

/// Bounded static view text for the terminal uncertain-input state. Static
/// by construction: never worker or page text.
const INPUT_UNCERTAIN_SUMMARY: &str =
    "paired input release could not be confirmed; input state is uncertain";

impl State {
    pub(super) fn require_live(&self) -> Result<(), SessionError> {
        match self.phase {
            SessionPhase::Live => Ok(()),
            SessionPhase::TargetClosed => Err(SessionError::TargetClosed),
            SessionPhase::InputUncertain => Err(SessionError::InputUncertain),
            SessionPhase::Stopped => Err(SessionError::Stopped),
        }
    }

    pub(super) fn require_active(&self) -> Result<(), SessionError> {
        match self.phase {
            SessionPhase::Stopped => Err(SessionError::Stopped),
            SessionPhase::Live | SessionPhase::TargetClosed | SessionPhase::InputUncertain => {
                Ok(())
            }
        }
    }

    pub(super) fn runtime_mut(&mut self) -> Result<&mut runtime::BrowserRuntime, SessionError> {
        self.runtime.as_mut().ok_or(SessionError::Stopped)
    }

    pub(super) fn next_control_revision(&self) -> Result<u64, SessionError> {
        self.control_revision
            .checked_add(1)
            .ok_or(SessionError::ControlRevisionOverflow)
    }

    /// Persists one proposed control generation by durable CAS before it is
    /// installed in memory or exposed to callers.
    fn persist_control_snapshot(
        &mut self,
        next_control_revision: u64,
        takeover: &TakeoverCoordinator,
        lease_token: Option<u64>,
        at: OffsetDateTime,
    ) -> Result<(), SessionError> {
        let Some(owner) = self.durable_control.as_mut() else {
            return Ok(());
        };
        let session_id = self.policy.session_id();
        let state = DurableBrowserControlState::from_control(
            session_id,
            next_control_revision,
            takeover,
            lease_token,
        );
        let state_json = state.canonical_json()?;
        let current_row_revision = i64::try_from(self.control_revision)
            .map_err(|_| SessionError::ControlRevisionOverflow)?;
        let next_row_revision = i64::try_from(next_control_revision)
            .map_err(|_| SessionError::ControlRevisionOverflow)?;
        if current_row_revision.checked_add(1) != Some(next_row_revision) {
            return Err(SessionError::DurableControlInvalid);
        }
        if owner.row_revision != current_row_revision {
            return Err(SessionError::DurableControlStale);
        }
        let object_id = session_id.to_string();
        let row = {
            let mut ledger = owner
                .ledger
                .lock()
                .map_err(|_| SessionError::DurableControlUnavailable)?;
            ledger
                .cas_browser_control_state(&object_id, owner.row_revision, &state_json, at)
                .map_err(control_store_error)?
        };
        let persisted = decode_durable_control_row(&row, session_id)?;
        if row.revision != next_row_revision || persisted != state {
            return Err(SessionError::DurableControlInvalid);
        }
        owner.row_revision = row.revision;
        Ok(())
    }

    pub(super) fn commit_takeover_transition(
        &mut self,
        takeover: TakeoverCoordinator,
        lease_token: Option<u64>,
        next_control_revision: u64,
        at: OffsetDateTime,
    ) -> Result<(), SessionError> {
        if self.next_control_revision()? != next_control_revision {
            return Err(SessionError::DurableControlInvalid);
        }
        self.persist_control_snapshot(next_control_revision, &takeover, lease_token, at)?;
        self.takeover = takeover;
        self.takeover_lease_token = lease_token;
        self.control_revision = next_control_revision;
        Ok(())
    }

    pub(super) fn bump_control_revision(&mut self, at: OffsetDateTime) -> Result<(), SessionError> {
        let next_control_revision = self.next_control_revision()?;
        let takeover = self.takeover.clone();
        self.persist_control_snapshot(
            next_control_revision,
            &takeover,
            self.takeover_lease_token,
            at,
        )?;
        self.control_revision = next_control_revision;
        Ok(())
    }

    /// Fences a replaced host before any worker-backed mutation. The durable
    /// row must still be the exact generation this session owns.
    fn require_durable_current(&self) -> Result<(), SessionError> {
        let Some(owner) = self.durable_control.as_ref() else {
            return Ok(());
        };
        let session_id = self.policy.session_id();
        let expected = DurableBrowserControlState::from_control(
            session_id,
            self.control_revision,
            &self.takeover,
            self.takeover_lease_token,
        );
        let object_id = session_id.to_string();
        let row = {
            let ledger = owner
                .ledger
                .lock()
                .map_err(|_| SessionError::DurableControlUnavailable)?;
            ledger
                .browser_control_state(&object_id)
                .map_err(control_store_error)?
                .ok_or(SessionError::DurableControlStale)?
        };
        let persisted = decode_durable_control_row(&row, session_id)?;
        if row.revision != owner.row_revision || persisted != expected {
            return Err(SessionError::DurableControlStale);
        }
        Ok(())
    }

    pub(super) async fn require_durable_admission(&mut self) -> Result<(), SessionError> {
        if let Err(error) = self.require_durable_current() {
            // A replaced host sheds its sole pending action immediately; the
            // durable generation fence guarantees it can never dispatch.
            if let Some(pending) = self.pending.take() {
                let _ = self.release_action_binding(&pending.preflight).await;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn current_policy_binding(&self) -> PolicyBinding {
        PolicyBinding::of(&self.policy)
    }

    pub(super) async fn release_action_binding(
        &self,
        preflight: &actions::ActionPreflight,
    ) -> Result<(), SessionError> {
        let runtime = self.runtime.as_ref().ok_or(SessionError::Stopped)?;
        actions::release_action_binding(runtime.client(), preflight, self.limits.preflight).await
    }

    /// Production takeover-lease expiry path. Retires the held control lease
    /// — only once it is due when `due_only` — through a sealed local
    /// transition unavailable to remotely decoded commands, cancels the
    /// holder's in-flight owner work with it, advances the control revision,
    /// and rebuilds the public view. `None` while no lease (or no due lease)
    /// is held, so timer and admission checks are harmless when idle.
    pub(super) async fn expire_takeover_lease(
        &mut self,
        now: OffsetDateTime,
        due_only: bool,
    ) -> Result<Option<TakeoverLeaseExpiry>, SessionError> {
        if self.lease_expiry_unreported.is_some() {
            return Ok(None);
        }
        let mut proposed_takeover = self.takeover.clone();
        let retired = if due_only {
            proposed_takeover.expire_lease_if_due(LocalReclaim::local(), now)?
        } else {
            proposed_takeover.expire_lease_now(LocalReclaim::local(), now)?
        };
        let Some(retired) = retired else {
            return Ok(None);
        };
        let lease_token = self
            .takeover_lease_token
            .ok_or(SessionError::DurableControlInvalid)?;
        let next_control_revision = self.next_control_revision()?;
        // Durable CAS fences the old holder before controller truth becomes
        // visible in memory. A replaced host can never commit this transition.
        self.commit_takeover_transition(proposed_takeover, None, next_control_revision, now)?;

        // The holder's in-flight owner work is cancelled with the retired
        // lease: the pending action is released and terminalized here, never
        // dispatched under a holder that no longer exists. Release failures
        // never mask durable retirement; the session slot still disappears.
        let cancelled_action = match self.pending.as_ref() {
            Some(pending) => {
                let action_id = pending.id;
                let _ = self.release_action_binding(&pending.preflight).await;
                self.pending = None;
                Some(AbandonedAction { action_id })
            }
            None => None,
        };
        let holder_after_expiry = remote_takeover_holder(&retired.view.status);
        let outstanding_after_expiry = if self.pending.is_some() { 1 } else { 0 };
        self.observe_view();
        let observation = TakeoverLeaseExpiry {
            holder: retired.holder,
            lease_token,
            view: retired.view,
            holder_after_expiry,
            cancelled_action,
            outstanding_after_expiry,
            control_revision: self.control_revision,
        };
        self.lease_expiry_unreported = Some(observation.clone());
        Ok(Some(observation))
    }

    /// Rebuilds, retains, and marks unreported the public session view from
    /// current facts. No worker call: used at launch and for lifecycle
    /// transitions.
    pub(super) fn observe_view(&mut self) -> BrowserSessionView {
        self.view_revision = self.view_revision.saturating_add(1);
        let (view_state, stale, failure) = match self.phase {
            SessionPhase::Live => (BrowserSessionState::Active, false, None),
            SessionPhase::TargetClosed => (BrowserSessionState::Closed, false, None),
            SessionPhase::InputUncertain => (
                BrowserSessionState::Failed,
                true,
                Some(INPUT_UNCERTAIN_SUMMARY.to_owned()),
            ),
            SessionPhase::Stopped => (BrowserSessionState::Closed, false, None),
        };
        if matches!(
            self.phase,
            SessionPhase::TargetClosed | SessionPhase::Stopped
        ) {
            // The page is gone; no page facts can be current.
            self.page = None;
        }
        let view = BrowserSessionView {
            session_id: self.policy.session_id(),
            revision: self.view_revision,
            state: view_state,
            isolated_profile: self.profile_id.clone(),
            current_url: self.page.as_ref().map(|page| page.url_display.clone()),
            current_origin: self.page.as_ref().map(|page| page.origin.clone()),
            page_title: self.page.as_ref().map(|page| page.title.clone()),
            frame_stream_id: self.stream_id,
            takeover: self.takeover.view().status,
            // The action timeline artifact is assembled by the composing
            // layer from observed results; the facade never mints one.
            action_timeline: None,
            opened_at: self.opened_at,
            updated_at: OffsetDateTime::now_utc(),
            stale,
            failure,
        };
        self.view = Some(view.clone());
        self.view_unreported = true;
        view
    }

    /// Bounded page observation (read deadline) feeding the session view.
    /// On success the redacted page facts refresh; on failure they clear,
    /// because the view only ever reports the latest observed page, never a
    /// stale guess.
    pub(super) async fn refresh_page_view(&mut self) {
        let observation = match self.runtime.as_ref() {
            Some(runtime) => {
                let deadline = self.limits.read;
                reads::observe_page(runtime.client(), deadline).await
            }
            None => Err(SessionError::Stopped),
        };
        self.page = observation.ok().map(|observed| ObservedPage {
            url_display: observed.provenance.source_url.display_url().to_owned(),
            origin: observed.provenance.origin.clone(),
            title: observed.page_title,
        });
        self.observe_view();
    }

    /// Terminalizes the session in place for explicit shutdown and returns
    /// the runtime for bounded teardown. The final stopped view is built
    /// before the runtime is removed.
    pub(super) fn begin_shutdown(&mut self) -> Option<runtime::BrowserRuntime> {
        self.pending = None;
        self.phase = SessionPhase::Stopped;
        self.observe_view();
        self.runtime.take()
    }
}

pub(super) fn remote_takeover_holder(status: &BrowserTakeoverStatus) -> Option<DeviceId> {
    match status {
        BrowserTakeoverStatus::Held { device_id, .. } => Some(*device_id),
        BrowserTakeoverStatus::Available | BrowserTakeoverStatus::ReclaimedLocally { .. } => None,
    }
}
