//! Conversation vehicle composition, startup, recovery and plan acceptance.

use std::sync::Arc;

use odin_domain::huginn::{
    LiveError, LiveSessionId, LiveSessionState, LiveSessionSummary, OpenSessionRequest,
    SessionListQuery,
};

use odin_domain::RunId;
use odin_ledger::Ledger;

use super::history::page_limit;
use super::identity::{conversation_root_identity, now_utc};
use super::seams::ConversationRootConfig;
use super::{ConversationRecord, ConversationRoot};
use crate::runtime::IntentFailure;

/// Initialization retries reuse the original command and session ids;
/// terminal closure and exhausted successor attempts refuse further opens.
#[derive(Debug, thiserror::Error)]
pub enum InitializeError {
    #[error("the conversation runtime is stopping")]
    Stopping,
    #[error(
        "the conversation vehicle {session} is terminally closed; refusing to \
         reopen or replace it (the closed lifecycle stays final)"
    )]
    TerminalClosed { session: String },
    #[error(
        "{attempts} conversation successor(s) ended before serving; the next is due at unix ms \
         {retry_at_unix_ms}"
    )]
    SuccessorBackoff {
        attempts: u32,
        retry_at_unix_ms: u64,
    },
    #[error("{attempts} conversation successors ended before serving; no further one is minted")]
    SuccessorExhausted { attempts: u32 },
    #[error("{0}")]
    Failed(String),
}

impl From<IntentFailure> for InitializeError {
    fn from(failure: IntentFailure) -> Self {
        match failure {
            IntentFailure::SuccessorStartBackoff {
                attempts,
                retry_at_unix_ms,
            } => Self::SuccessorBackoff {
                attempts,
                retry_at_unix_ms,
            },
            IntentFailure::SuccessorStartExhausted { attempts } => {
                Self::SuccessorExhausted { attempts }
            }
            other => Self::Failed(other.to_string()),
        }
    }
}

impl ConversationRoot {
    /// Composes and validates the root. Launch and node membership are
    /// verified against the seat binding; the owner surface must be fully
    /// declared.
    pub fn open(config: ConversationRootConfig) -> Result<Arc<Self>, String> {
        if config.owner.owner_user_id.trim().is_empty()
            || config.owner.channel_id.trim().is_empty()
            || config.owner.actor.trim().is_empty()
        {
            return Err(
                "the conversation owner surface must name the paired owner, channel, and actor"
                    .to_owned(),
            );
        }
        if config
            .binding
            .declared_launch_option(&config.provider, &config.model)
            .is_none()
        {
            return Err(format!(
                "launch {}/{} is not one of seat {}'s declared launch options; the conversation \
                 vehicle cannot open an undeclared launch",
                config.provider, config.model, config.binding.seat_id
            ));
        }
        if !config.binding.allowed_nodes.contains(&config.target_node) {
            return Err(format!(
                "node {} is not one of seat {}'s declared allowed nodes; the conversation \
                 vehicle cannot open elsewhere",
                config.target_node, config.binding.seat_id
            ));
        }
        config.rollover.validate()?;
        if config.answer_bound.is_zero() || config.poll_interval.is_zero() {
            return Err(
                "the conversation answer bound and poll interval must both be non-zero".to_owned(),
            );
        }
        let identity =
            conversation_root_identity(config.binding.seat_id.as_str(), config.project.as_str());
        Ok(Arc::new_cyclic(|self_weak| ConversationRoot {
            binding: config.binding,
            project: config.project,
            lane: config.lane,
            provider: config.provider,
            model: config.model,
            target_node: config.target_node,
            owner: config.owner,
            answer_bound: config.answer_bound,
            poll_interval: config.poll_interval,
            plane: config.plane,
            authority: config.authority,
            egress: config.egress,
            approvals: config.approvals,
            ledger_path: config.ledger_path,
            state_path: config.state_path,
            rollover: config.rollover,
            clock: config.clock,
            delegation_links: config.delegation_links,
            conversation_id: format!("conversation:{identity}"),
            lock: Arc::new(tokio::sync::Mutex::new(())),
            background: tokio::sync::Mutex::new(std::collections::BTreeMap::new()),
            closing: std::sync::atomic::AtomicBool::new(false),
            handle: tokio::runtime::Handle::current(),
            self_weak: self_weak.clone(),
        }))
    }

    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    pub async fn current_vehicle_session(&self) -> Result<Option<LiveSessionId>, String> {
        let record = self.load_record()?;
        record
            .session_id
            .as_deref()
            .map(LiveSessionId::parse)
            .transpose()
            .map_err(|error| format!("the recorded conversation session is invalid: {error}"))
    }

    /// Verifies authority and persists vehicle identity before prompting, then resumes wakes.
    /// Missing manifests retry the original open; parked nonterminal vehicles recover;
    /// ended vehicles refuse.
    pub async fn initialize(&self) -> Result<(), InitializeError> {
        let _guard = self.lock.lock().await;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err(InitializeError::Stopping);
        }
        let mut record = self.load_record().map_err(InitializeError::Failed)?;
        self.verify_record_binding(&record)
            .map_err(InitializeError::Failed)?;
        // Completed queued handoffs owe only terminal replay, even if the
        // vehicle cannot be recovered or its question is no longer decidable.
        let wake_count = record.wakes.len();
        record
            .wakes
            .retain(|wake| self.replay_wake_completion(wake).is_none());
        if record.wakes.len() != wake_count {
            self.store_record(&mut record)
                .map_err(InitializeError::Failed)?;
        }
        if record.session_id.is_none() {
            self.open_first_vehicle(&mut record).await?;
        } else {
            let session_raw = record
                .session_id
                .clone()
                .ok_or_else(|| InitializeError::Failed("unreachable".to_owned()))?;
            let parsed = LiveSessionId::parse(&session_raw).map_err(|error| {
                InitializeError::Failed(format!("the recorded session is invalid: {error}"))
            })?;
            // A PENDING successor transition routes every entrypoint
            // through the same idempotent resume, whether the record
            // still names the predecessor or already names the successor.
            // A completed (Open) slot is history: it never blocks the
            // next publication.
            if matches!(
                record.rollover.as_ref().map(|slot| slot.phase),
                Some(crate::conversation::rollover::SuccessorPhase::Pending)
            ) {
                self.resume_successor(&mut record).await?;
                self.resume_deliveries()
                    .map_err(|error| InitializeError::Failed(error.to_string()))?;
                self.resume_wakes(&record).await;
                return Ok(());
            }
            let vehicle_command = self
                .recorded_vehicle_command(&record)
                .map_err(InitializeError::Failed)?;
            let ensured = self
                .authority
                .ensure(&vehicle_command, parsed)
                .await
                .map_err(|error| {
                    InitializeError::Failed(format!(
                        "conversation authority ensure failed at startup: {error}"
                    ))
                })?;
            let listing = self.find_session(parsed, true).await.map_err(|error| {
                InitializeError::Failed(format!("conversation session listing failed: {error}"))
            })?;
            if listing
                .as_ref()
                .is_some_and(|summary| summary.state == LiveSessionState::Ended)
            {
                return Err(InitializeError::TerminalClosed {
                    session: session_raw,
                });
            }
            let manifest_present =
                self.plane
                    .session_manifest_present(parsed)
                    .await
                    .map_err(|error| {
                        InitializeError::Failed(format!(
                            "conversation manifest lookup failed: {error}"
                        ))
                    })?;
            if manifest_present {
                if ensured.lags() {
                    // The ensured bound lags the current pin: arm and run
                    // the governed fresh-generation successor instead of
                    // a reclaim that would refuse frozen.
                    self.begin_successor(
                        &mut record,
                        listing.as_ref().map(|summary| summary.epoch.get()),
                        listing.as_ref().map(|summary| summary.event_head.get()),
                    )
                    .await?;
                } else {
                    // Present parked nonterminal OR failed: reclaim
                    // converts it to a live incarnation with the
                    // transcript resumed.
                    // The same wedge escape as an intent's reclaim: the
                    // open lane retries, and a vehicle that never comes
                    // back rolls to a successor instead of keeping the
                    // conversation closed forever.
                    self.reclaim_or_escape(
                        &mut record,
                        parsed,
                        listing.as_ref().map(|summary| summary.epoch.get()),
                        listing.as_ref(),
                        "startup reclaim",
                    )
                    .await?;
                }
            } else {
                // The open never completed admission: the idempotent
                // original open, same command id and session identity.
                self.open_first_vehicle(&mut record).await?;
            }
        }
        self.resume_deliveries()
            .map_err(|error| InitializeError::Failed(error.to_string()))?;
        self.resume_wakes(&record).await;
        Ok(())
    }

    /// The deterministic first open: same command id, same derived
    /// session id, on every retry.
    async fn open_first_vehicle(
        &self,
        record: &mut ConversationRecord,
    ) -> Result<(), InitializeError> {
        let vehicle_command = self.vehicle_command_id().map_err(InitializeError::Failed)?;
        let session_id =
            odin_omp::live::supervisor::session_id_for(&vehicle_command).map_err(|error| {
                InitializeError::Failed(format!(
                    "conversation vehicle session identity rejected: {error}"
                ))
            })?;
        let ensured = self
            .authority
            .ensure(&vehicle_command, session_id)
            .await
            .map_err(|error| {
                InitializeError::Failed(format!(
                    "conversation vehicle {} (command {}) has no usable authority: {error}",
                    session_id, vehicle_command
                ))
            })?;
        self.open_vehicle(record, &vehicle_command, session_id, ensured.bound)
            .await
    }

    /// Persist the fresh identity before opening its frozen-generation vehicle.
    pub(super) async fn open_vehicle(
        &self,
        record: &mut ConversationRecord,
        vehicle_command: &odin_domain::CommandId,
        session_id: LiveSessionId,
        served_revision: u64,
    ) -> Result<(), InitializeError> {
        record.conversation_id = self.conversation_id.clone();
        record.seat = self.binding.seat_id.as_str().to_owned();
        record.project = self.project.as_str().to_owned();
        record.vehicle_command_id = Some(vehicle_command.to_string());
        record.session_id = Some(session_id.to_string());
        self.store_record(record).map_err(InitializeError::Failed)?;
        let summary = self
            .plane
            .open_session(OpenSessionRequest {
                command_id: vehicle_command.clone(),
                seat_id: self.binding.seat_id.clone(),
                project_id: self.project.clone(),
                slice_id: self.binding.slice_id.clone(),
                provider: self.provider.clone(),
                model: self.model.clone(),
                title: Some(format!(
                    "{}{}",
                    super::VEHICLE_TITLE_PREFIX,
                    self.conversation_id
                )),
                target_node: self.target_node.clone(),
                open_tab: false,
                initial_prompt: None,
                workload: None,
                served_revision: Some(served_revision),
            })
            .await
            .map_err(|error| {
                InitializeError::Failed(format!(
                    "conversation vehicle open failed (the identity is durable; the next \
                     initialize converges on the same session): {error}"
                ))
            })?;
        if summary.session_id != session_id {
            return Err(InitializeError::Failed(format!(
                "the supervisor opened conversation session {}, but the vehicle command {} \
                 derived {}; nothing rides the mismatched session",
                summary.session_id, vehicle_command, session_id
            )));
        }
        Ok(())
    }

    /// Finds the recorded session in the seat's listing. `include_ended`
    /// exposes Failed and Ended rows so a recoverable failure and a
    /// terminal closure are distinguishable.
    pub(super) async fn find_session(
        &self,
        session_id: LiveSessionId,
        include_ended: bool,
    ) -> Result<Option<LiveSessionSummary>, LiveError> {
        let mut cursor = None;
        loop {
            let page = self
                .plane
                .sessions(SessionListQuery {
                    seat_id: Some(self.binding.seat_id.clone()),
                    include_ended,
                    cursor,
                    limit: page_limit(),
                })
                .await?;
            if let Some(summary) = page
                .sessions
                .iter()
                .find(|summary| summary.session_id == session_id)
            {
                return Ok(Some(summary.clone()));
            }
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => return Ok(None),
            }
        }
    }

    /// Resolves the root's current vehicle for one more use: proves
    /// authority, recovers a failed child in place, and refuses a
    /// terminally closed vehicle typed.
    pub(super) async fn resolve_vehicle(
        &self,
        record: &mut ConversationRecord,
    ) -> Result<LiveSessionSummary, IntentFailure> {
        let session_raw = record.session_id.clone().ok_or_else(|| {
            IntentFailure::Other("the conversation vehicle is not initialized".to_owned())
        })?;
        let session_id = LiveSessionId::parse(&session_raw)
            .map_err(|error| IntentFailure::Other(format!("recorded session invalid: {error}")))?;
        let vehicle_command = self
            .recorded_vehicle_command(record)
            .map_err(IntentFailure::Other)?;
        // A durably Pending transition routes through the ONE resume
        // implementation before anything else touches the vehicle; a
        // completed slot (phase Open) is history and never resumes.
        if record
            .rollover
            .as_ref()
            .is_some_and(|slot| slot.phase == super::rollover::SuccessorPhase::Pending)
        {
            let successor = self.resume_successor(record).await?;
            return self
                .find_session(successor, false)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
                .ok_or(IntentFailure::HistoryUnavailable);
        }
        let ensured = self
            .authority
            .ensure(&vehicle_command, session_id)
            .await
            .map_err(|error| {
                IntentFailure::Other(format!("conversation authority ensure failed: {error}"))
            })?;
        if let Some(digest) = ensured.kept_composition() {
            tracing::info!(
                session = %session_id,
                "odin-hermes: publication composition unchanged; vehicle kept \
                 session={session_id} bound={} current={} digest={digest}",
                ensured.bound, ensured.current
            );
        }
        match self
            .find_session(session_id, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?
        {
            Some(summary) if summary.state == LiveSessionState::Ended => {
                Err(IntentFailure::ConversationClosed)
            }
            Some(summary)
                if matches!(
                    summary.state,
                    LiveSessionState::Failed | LiveSessionState::Detached
                ) =>
            {
                self.recover_vehicle(record, Some(summary.epoch.get()))
                    .await
            }
            // Defer rollover while children run: retiring the parent revokes them.
            Some(summary) if ensured.lags() && self.holds_live_children(session_id).await => {
                tracing::warn!(
                    session = %session_id,
                    "odin-hermes: vehicle {session_id} lags the publication; rollover waits for \
                     its live delegated work"
                );
                Ok(summary)
            }
            // Keep the healthy vehicle until reload makes the successor's publication runnable.
            Some(summary) if ensured.lags() && self.authority.rollover_deferred() => {
                tracing::warn!(
                    session = %session_id,
                    "odin-hermes: vehicle {session_id} lags the publication; rollover waits for \
                     the pending reload"
                );
                Ok(summary)
            }
            Some(summary) if ensured.lags() => {
                let successor = self
                    .begin_successor(
                        record,
                        Some(summary.epoch.get()),
                        Some(summary.event_head.get()),
                    )
                    .await?;
                self.find_session(successor, false)
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?
                    .ok_or(IntentFailure::HistoryUnavailable)
            }
            Some(summary) => Ok(summary),
            None => self.recover_vehicle(record, None).await,
        }
    }

    async fn holds_live_children(&self, vehicle: LiveSessionId) -> bool {
        let Some(links) = &self.delegation_links else {
            return false;
        };
        let Ok(parent) = odin_domain::SessionId::new(vehicle.to_string()) else {
            return false;
        };
        let children = match links.children_of(&parent) {
            Ok(children) => children,
            Err(error) => {
                tracing::error!(error = %error, "odin-hermes: delegated children of {vehicle} unreadable: {error}");
                return false;
            }
        };
        for link in children {
            if let Ok(Some(summary)) = self.find_session(link.child, false).await {
                if !matches!(
                    summary.state,
                    LiveSessionState::Ended | LiveSessionState::Failed
                ) {
                    return true;
                }
            }
        }
        false
    }

    /// Recovers the recorded vehicle in place through the plane's reclaim
    /// surface: same session id, epoch bump, durable transcript resumed.
    pub(super) async fn recover_vehicle(
        &self,
        record: &mut ConversationRecord,
        observed_epoch: Option<u64>,
    ) -> Result<LiveSessionSummary, IntentFailure> {
        let session_raw = record.session_id.clone().ok_or_else(|| {
            IntentFailure::Other("the conversation vehicle is not initialized".to_owned())
        })?;
        let session_id = LiveSessionId::parse(&session_raw)
            .map_err(|error| IntentFailure::Other(format!("recorded session invalid: {error}")))?;
        let vehicle_command = self
            .recorded_vehicle_command(record)
            .map_err(IntentFailure::Other)?;
        let ensured = self
            .authority
            .ensure(&vehicle_command, session_id)
            .await
            .map_err(|error| {
                IntentFailure::Other(format!("conversation authority ensure failed: {error}"))
            })?;
        // Canonical terminal FIRST, whatever entrypoint drove the
        // recovery (a Failed or Detached listing, a vanished row, or a
        // VehicleDown settle): a truthfully Ended vehicle is a closed
        // lifecycle — it is never reclaimed and never superseded, so a
        // lagging generation can never replace it with a fresh session.
        let canonical = self
            .find_session(session_id, true)
            .await
            .map_err(|_| IntentFailure::HistoryUnavailable)?;
        if canonical
            .as_ref()
            .is_some_and(|summary| summary.state == LiveSessionState::Ended)
        {
            return Err(IntentFailure::ConversationClosed);
        }
        if ensured.lags() {
            // The ensured bound lags the current pin: the governed
            // fresh-generation successor replaces the frozen-bound
            // reclaim, which would refuse typed. The canonical summary
            // supplies the journal head the brief tail is cut at — never
            // a zero head that would carry the oldest page instead of
            // the recent tail.
            let successor = self
                .begin_successor(
                    record,
                    observed_epoch.or_else(|| canonical.as_ref().map(|s| s.epoch.get())),
                    canonical.as_ref().map(|summary| summary.event_head.get()),
                )
                .await?;
            return self
                .find_session(successor, false)
                .await
                .map_err(|_| IntentFailure::HistoryUnavailable)?
                .ok_or(IntentFailure::HistoryUnavailable);
        }
        self.reclaim_or_escape(
            record,
            session_id,
            observed_epoch,
            canonical.as_ref(),
            "vehicle reclaim",
        )
        .await
    }

    /// One in-place reclaim under the wedge escape (GAP 5): a vehicle whose
    /// in-place recovery keeps failing — its transcript or bridge will not
    /// come back — does not refuse every turn (or, at startup, every open)
    /// forever. Consecutive failures are counted durably; at
    /// [`WEDGE_ESCAPE_AFTER`] the conversation rolls to a governed successor
    /// (a fresh session carrying the continuity brief) and the count resets
    /// on any success. Startup and intents share this one path.
    pub(super) async fn reclaim_or_escape(
        &self,
        record: &mut ConversationRecord,
        session_id: LiveSessionId,
        observed_epoch: Option<u64>,
        canonical: Option<&LiveSessionSummary>,
        step: &'static str,
    ) -> Result<LiveSessionSummary, IntentFailure> {
        match self.recover_session(session_id, observed_epoch, step).await {
            Ok(summary) => {
                if record.recovery_failures != 0 {
                    record.recovery_failures = 0;
                    self.store_record(record).map_err(IntentFailure::Other)?;
                }
                Ok(summary)
            }
            Err(IntentFailure::VehicleRecoveryFailed { source, .. })
                if record.recovery_failures + 1 >= WEDGE_ESCAPE_AFTER =>
            {
                tracing::warn!(
                    session = %session_id,
                    "odin-hermes: vehicle {session_id} failed in-place recovery {} times \
                     (last: {step}: {source}); rolling to a successor",
                    record.recovery_failures + 1
                );
                record.recovery_failures = 0;
                let successor = self
                    .begin_successor(
                        record,
                        observed_epoch.or_else(|| canonical.map(|s| s.epoch.get())),
                        canonical.map(|summary| summary.event_head.get()),
                    )
                    .await?;
                self.find_session(successor, false)
                    .await
                    .map_err(|_| IntentFailure::HistoryUnavailable)?
                    .ok_or(IntentFailure::HistoryUnavailable)
            }
            Err(failure @ IntentFailure::VehicleRecoveryFailed { .. }) => {
                record.recovery_failures += 1;
                self.store_record(record).map_err(IntentFailure::Other)?;
                tracing::warn!(
                    session = %session_id,
                    "odin-hermes: vehicle {session_id} in-place recovery failed \
                     ({step}, {} of {WEDGE_ESCAPE_AFTER} before the escape): {failure}",
                    record.recovery_failures
                );
                Err(failure)
            }
            Err(failure) => Err(failure),
        }
    }

    pub(super) async fn recover_session(
        &self,
        session_id: LiveSessionId,
        observed_epoch: Option<u64>,
        step: &'static str,
    ) -> Result<LiveSessionSummary, IntentFailure> {
        self.plane
            .recover_session(session_id)
            .await
            .map_err(|error| match error {
                // The typed conflict code from the reclaim surface: a
                // truthfully ended session refuses before any effect.
                LiveError::Conflict { code, .. } if code == "session_ended" => {
                    IntentFailure::ConversationClosed
                }
                source => IntentFailure::VehicleRecoveryFailed {
                    session: session_id,
                    epoch: observed_epoch.or(match &source {
                        LiveError::EpochMismatch { actual, .. } => Some(actual.get()),
                        _ => None,
                    }),
                    step,
                    source,
                },
            })
    }

    /// The gated first prompt of a vehicle run: the authenticated owner's
    /// intent becomes the bounded plan objective, the acceptance records
    /// the paired owner as the actor against the SAME durable ledger the
    /// interactive client uses, and the gate is verified before any prompt.
    pub(super) fn ensure_plan_accepted(
        &self,
        summary: &LiveSessionSummary,
        intent_content: &str,
    ) -> Result<(), IntentFailure> {
        let run_id = RunId::new(format!("run:live:{}", summary.session_id)).map_err(|error| {
            IntentFailure::Other(format!("live run identity rejected: {error}"))
        })?;
        let mut ledger = Ledger::open(&self.ledger_path).map_err(|error| {
            IntentFailure::Other(format!("could not open the session state ledger: {error}"))
        })?;
        let run = odin_ledger::lane_run::read_run(ledger.connection(), &run_id)
            .map_err(|error| {
                IntentFailure::Other(format!("conversation run lookup failed: {error}"))
            })?
            .ok_or_else(|| IntentFailure::Other("conversation has no durable run".to_owned()))?;
        if run.lane_id != self.lane {
            return Err(IntentFailure::Other(
                "conversation run differs from its declared lane".to_owned(),
            ));
        }
        match ledger.plan_is_accepted(&run_id) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => {
                return Err(IntentFailure::Other(format!(
                    "could not verify the vehicle plan acceptance: {error}"
                )));
            }
        }
        let observed_revision = ledger
            .plan(&run_id)
            .map_err(|error| {
                IntentFailure::Other(format!("could not read the vehicle plan: {error}"))
            })?
            .map(|plan| plan.revision)
            .unwrap_or(0);
        let plan = ledger
            .replace_plan(&run_id, intent_content, &[], observed_revision, now_utc())
            .map_err(|error| {
                IntentFailure::Other(format!(
                    "could not persist the owner intent as the vehicle plan: {error}"
                ))
            })?;
        ledger
            .accept_plan(&run_id, plan.revision, &self.owner.actor, now_utc())
            .map_err(|error| {
                IntentFailure::Other(format!(
                    "could not record the owner acceptance of the vehicle plan: {error}"
                ))
            })?;
        let accepted = ledger.plan_is_accepted(&run_id).map_err(|error| {
            IntentFailure::Other(format!(
                "could not verify the vehicle plan acceptance: {error}"
            ))
        })?;
        if !accepted {
            return Err(IntentFailure::Other(
                "the vehicle plan was recorded but does not verify as accepted; refusing to \
                 prompt"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Consecutive failed in-place recoveries after which the vehicle rolls to
/// a successor instead of refusing every turn.
pub(super) const WEDGE_ESCAPE_AFTER: u32 = 3;
