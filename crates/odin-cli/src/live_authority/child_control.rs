use std::sync::Arc;
use std::time::Duration;

use odin_domain::huginn::{EventSeq, LiveError, LiveSessionId};
use odin_domain::SessionId;
use odin_omp::host_tools::delegation::{DeliveryVerdict, WorkloadRest, INDETERMINATE_DELIVERY};
use odin_omp::host_tools::operations::session_capsule_id;

use super::{block_on, wait, SessionAuthorityPool, SessionPoolHandle, SupervisorHandle};

/// The journaled failure of `command`, when its outcome among `events`
/// says it failed.
fn failed_outcome(
    events: &[odin_domain::huginn::LiveEvent],
    command: &odin_domain::CommandId,
) -> Option<odin_domain::huginn::CommandFailure> {
    events.iter().find_map(|event| match &event.body {
        odin_domain::huginn::LiveEventBody::ControlCompleted(
            odin_domain::huginn::CommandOutcome::Failed { command_id, error },
        ) if command_id == command => Some(error.clone()),
        _ => None,
    })
}

/// Finds this command's applied, cancelled, or failed completion, excluding denials.
fn completed_outcome(
    events: &[odin_domain::huginn::LiveEvent],
    command: &odin_domain::CommandId,
) -> Option<odin_domain::huginn::CommandOutcome> {
    events.iter().find_map(|event| match &event.body {
        odin_domain::huginn::LiveEventBody::ControlCompleted(outcome)
            if matches!(
                outcome,
                odin_domain::huginn::CommandOutcome::Applied { command_id }
                    | odin_domain::huginn::CommandOutcome::Cancelled { command_id, .. }
                    | odin_domain::huginn::CommandOutcome::Failed { command_id, .. }
                        if command_id == command
            ) =>
        {
            Some(outcome.clone())
        }
        _ => None,
    })
}

/// The delivery verdict of a replayed (`Duplicate`) command. A journaled
/// outcome — the receipt's own, or a durable completion event for the
/// exact command id — is the command's answer: an applied command was
/// delivered; a failed or cancelled one was not. An id journaled WITHOUT
/// any completion (a crash between the command's admission and its
/// journaled outcome) is INDETERMINATE: it is never reported delivered —
/// the caller's delivery intent must not be marked on a guess — and it
/// is never resolved here by re-issuing the command under a fresh id,
/// which would decide an ambiguous effect by duplicating it.
fn duplicate_verdict(
    prior_outcome: Option<&odin_domain::huginn::CommandOutcome>,
    journaled: Option<&odin_domain::huginn::CommandOutcome>,
) -> DeliveryVerdict {
    match prior_outcome.or(journaled) {
        Some(odin_domain::huginn::CommandOutcome::Applied { .. }) => DeliveryVerdict::Delivered,
        Some(odin_domain::huginn::CommandOutcome::Failed { error, .. }) => {
            DeliveryVerdict::Refused(format!("failed: {}: {}", error.code, error.message))
        }
        Some(odin_domain::huginn::CommandOutcome::Cancelled { reason, .. }) => {
            DeliveryVerdict::Refused(format!(
                "was cancelled before it could take effect: {reason}"
            ))
        }
        // A denial probe settles with a durable receipt that NOTHING
        // executed: refused, never delivered, never indeterminate.
        Some(odin_domain::huginn::CommandOutcome::ToolDenied { receipt, .. }) => {
            DeliveryVerdict::Refused(format!(
                "tool denial probe {}: nothing executed: {}",
                receipt.request_id.as_str(),
                receipt.error
            ))
        }
        None => DeliveryVerdict::Unsettled,
    }
}

/// The durable completion of `child`'s journaled `command_id`, read from
/// the whole bounded transcript: the reconciliation evidence for a replay
/// whose journal row never completed. A read failure is indeterminate —
/// never absence.
fn journaled_completion(
    supervisor: &Arc<odin_omp::live::supervisor::LiveSupervisor>,
    child: LiveSessionId,
    command_id: &odin_domain::CommandId,
) -> Result<Option<odin_domain::huginn::CommandOutcome>, String> {
    let mut found = None;
    let mut after = odin_domain::huginn::EventSeq::new(0);
    while found.is_none() {
        let page = block_on(supervisor.history(odin_domain::huginn::HistoryQuery {
            session_id: child,
            after,
            limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
        }))?;
        if page.events.is_empty() {
            break;
        }
        after = page
            .events
            .last()
            .map(|event| event.sequence)
            .unwrap_or(after);
        found = completed_outcome(&page.events, command_id);
    }
    Ok(found)
}

/// Supervisor-backed lifecycle control for the governed delegation owner.
pub struct SupervisorChildControl {
    supervisor: SupervisorHandle,
    pool: SessionPoolHandle,
    reload_gate: Option<ReloadGate>,
    branch_reader: Option<BranchReader>,
}

/// Reads one registered capsule's change against its base, through the pool's lifecycle workers.
pub type BranchReader = Box<
    dyn Fn(
            &super::SessionAuthorityPool,
            &super::RegisteredCodeCapsule,
        ) -> Result<odin_omp::host_tools::delegation::TaskBranchReport, String>
        + Send
        + Sync,
>;

/// The daemon's pending-reload probe and where deferred delegations are
/// recorded for the post-restart wake.
pub struct ReloadGate {
    pub pending: Box<dyn Fn() -> bool + Send + Sync>,
    pub deferred_file: std::path::PathBuf,
}

impl SupervisorChildControl {
    pub fn new(supervisor: SupervisorHandle, pool: SessionPoolHandle) -> Self {
        Self {
            supervisor,
            pool,
            reload_gate: None,
            branch_reader: None,
        }
    }

    /// `task_read` reports a child's branch diff only with a reader.
    pub fn with_branch_reader(mut self, reader: BranchReader) -> Self {
        self.branch_reader = Some(reader);
        self
    }

    /// Delegations refuse while a reload is pending and are recorded in
    /// `gate.deferred_file` (one JSON object per line).
    pub fn with_reload_gate(mut self, gate: ReloadGate) -> Self {
        self.reload_gate = Some(gate);
        self
    }

    fn supervisor(&self) -> Result<Arc<odin_omp::live::supervisor::LiveSupervisor>, String> {
        self.supervisor
            .get()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| "live supervisor is not running".to_owned())
    }

    fn pool(&self) -> Result<Arc<SessionAuthorityPool>, String> {
        self.pool
            .get()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| "session authority pool is not running".to_owned())
    }

    /// Retires the child's exact capsule after the OMP teardown receipt. The
    /// private sidecar backend lives in the global pool and outlives the OMP
    /// process, so the stop is only complete once the pool's StopAuthority
    /// lifecycle has retired it.
    fn retire_capsule(
        &self,
        child: LiveSessionId,
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        let pool = self.pool()?;
        let session = SessionId::new(child.to_string())
            .map_err(|error| format!("child session {child} is invalid: {error}"))?;
        let capsule_id = session_capsule_id(&session).map_err(|error| error.to_string())?;
        if pool.retire_session_until(&capsule_id, deadline)? {
            Ok(())
        } else {
            Err(format!(
                "capsule {capsule_id} was not registered in the session authority pool"
            ))
        }
    }
}

/// Attempts a child command makes when the session moved under it.
const HEAD_RACE_ATTEMPTS: u32 = 4;

/// The newest bytes of a worker's screen a `task_read` carries.
const SCREEN_BYTES: usize = 4096;

/// Only event-head races are retryable; all other refusals are final.
fn retries_head_race(reason: &odin_domain::huginn::CommandRejection, attempt: u32) -> bool {
    matches!(
        reason,
        odin_domain::huginn::CommandRejection::EventHeadMismatch { .. }
    ) && attempt < HEAD_RACE_ATTEMPTS
}

/// Settlement time in Unix milliseconds; later diagnostics must not move `failed_at`.
fn settled_since_ms(summary: &odin_domain::huginn::LiveSessionSummary) -> Option<u64> {
    match summary.state {
        odin_domain::huginn::LiveSessionState::Idle => Some(summary.updated_at),
        odin_domain::huginn::LiveSessionState::Failed => summary.failed_at,
        _ => None,
    }
    .map(|at| u64::try_from(at.unix_timestamp_nanos() / 1_000_000).unwrap_or(0))
}

impl odin_omp::host_tools::delegation::ChildSessionControl for SupervisorChildControl {
    fn branch(
        &self,
        child: LiveSessionId,
    ) -> Result<Option<odin_omp::host_tools::delegation::TaskBranchReport>, String> {
        let Some(read) = &self.branch_reader else {
            return Ok(None);
        };
        let pool = self.pool()?;
        let session = SessionId::new(child.to_string())
            .map_err(|error| format!("child session {child} is invalid: {error}"))?;
        match pool.registered_code_capsule(&session)? {
            Some(capsule) => read(&pool, &capsule)
                .map(Some)
                .map_err(|error| format!("read child {child}'s branch diff: {error}")),
            None => Ok(None),
        }
    }

    fn reload_pending(&self) -> bool {
        self.reload_gate
            .as_ref()
            .is_some_and(|gate| (gate.pending)())
    }

    fn defer_until_reload(
        &self,
        deferred: &odin_omp::host_tools::delegation::DeferredDelegation,
    ) -> Result<(), String> {
        use std::io::Write as _;
        let gate = self
            .reload_gate
            .as_ref()
            .ok_or("no reload gate is composed")?;
        let mut line = serde_json::to_vec(deferred).map_err(|error| error.to_string())?;
        line.push(b'\n');
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&gate.deferred_file)
            .and_then(|mut file| file.write_all(&line))
            .map_err(|error| format!("{}: {error}", gate.deferred_file.display()))?;
        tracing::warn!(
            "delegation deferred until reload seat={} target={:?} title={:?}",
            deferred.caller_seat,
            deferred.target_seat,
            deferred.title
        );
        Ok(())
    }

    fn snapshot(
        &self,
        child: LiveSessionId,
    ) -> Result<odin_omp::host_tools::delegation::ChildLifecycleSnapshot, String> {
        let supervisor = self.supervisor()?;
        // Liveness is actor ownership, not summary presence: `summaries()`
        // also lists the durable inactive history of ended sessions.
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        match wait(&runtime, supervisor.actor(child)) {
            Ok(actor) => {
                let summary = actor.summary().map_err(|error| error.to_string())?;
                let epoch = i64::try_from(summary.epoch.get())
                    .map_err(|_| "child session epoch exceeds i64".to_owned())?;
                let quiet_since_ms =
                    (summary.state == odin_domain::huginn::LiveSessionState::Running).then(|| {
                        u64::try_from(summary.updated_at.unix_timestamp_nanos() / 1_000_000)
                            .unwrap_or(0)
                    });
                // Both idle and failed children can have provider faults in their journal.
                let provider_fault = if matches!(
                    summary.state,
                    odin_domain::huginn::LiveSessionState::Idle
                        | odin_domain::huginn::LiveSessionState::Failed
                ) {
                    const TAIL: u16 = 24;
                    let after = odin_domain::huginn::EventSeq::new(
                        summary.event_head.get().saturating_sub(u64::from(TAIL)),
                    );
                    wait(
                        &runtime,
                        supervisor.history(odin_domain::huginn::HistoryQuery {
                            session_id: child,
                            after,
                            limit: std::num::NonZeroU16::new(TAIL)
                                .unwrap_or(std::num::NonZeroU16::MIN),
                        }),
                    )
                    .ok()
                    .and_then(|page| {
                        odin_omp::host_tools::delegation::provider_turn_fault(&page.events)
                    })
                } else {
                    None
                };
                Ok(odin_omp::host_tools::delegation::ChildLifecycleSnapshot {
                    active: true,
                    state: Some(summary.state),
                    epoch: Some(epoch),
                    settled_since_ms: settled_since_ms(&summary),
                    quiet_since_ms,
                    provider_fault,
                })
            }
            Err(LiveError::NotFound { .. }) => {
                // No live actor. Report the durable history's last known
                // state without liveness; no history row means unknown.
                let summaries =
                    wait(&runtime, supervisor.summaries()).map_err(|error| error.to_string())?;
                match summaries
                    .into_iter()
                    .find(|summary| summary.session_id == child)
                {
                    Some(summary) => {
                        let epoch = i64::try_from(summary.epoch.get())
                            .map_err(|_| "child session epoch exceeds i64".to_owned())?;
                        Ok(odin_omp::host_tools::delegation::ChildLifecycleSnapshot {
                            active: false,
                            state: Some(summary.state),
                            epoch: Some(epoch),
                            settled_since_ms: None,
                            quiet_since_ms: None,
                            provider_fault: None,
                        })
                    }
                    None => Ok(odin_omp::host_tools::delegation::ChildLifecycleSnapshot {
                        active: false,
                        state: None,
                        epoch: None,
                        settled_since_ms: None,
                        quiet_since_ms: None,
                        provider_fault: None,
                    }),
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn prompt(&self, child: LiveSessionId, message: &str) -> Result<(), String> {
        let message = odin_domain::huginn::LiveMessage::new(vec![
            odin_domain::huginn::LiveContentBlock::Text(message.to_owned()),
        ])
        .map_err(|error| format!("worker prompt is invalid: {error}"))?;
        self.command(
            child,
            odin_domain::huginn::LiveCommandBody::Prompt { message },
        )
    }

    fn command(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<(), String> {
        let supervisor = self.supervisor()?;
        let actor = block_on(supervisor.actor(child))?;
        let kind = body.kind();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let summary = actor.summary().map_err(|error| error.to_string())?;
            let command = odin_domain::huginn::LiveCommand {
                command_id: crate::authority_provision::random_command_uuid()?,
                session_id: child,
                expected_epoch: summary.epoch,
                expected_event_head: Some(summary.event_head),
                body: body.clone(),
            };
            match block_on(actor.command(command))? {
                odin_domain::huginn::CommandReceipt::Rejected { reason, .. }
                    if retries_head_race(&reason, attempt) =>
                {
                    std::thread::sleep(Duration::from_millis(200));
                }
                odin_domain::huginn::CommandReceipt::Rejected { reason, .. } => {
                    return Err(format!(
                        "{kind:?} to worker {child} (state {:?}) was rejected: {reason:?}",
                        summary.state
                    ))
                }
                odin_domain::huginn::CommandReceipt::Accepted { command_id } => {
                    // Acceptance is not application; read the command's journaled outcome.
                    let page = block_on(supervisor.history(odin_domain::huginn::HistoryQuery {
                        session_id: child,
                        after: summary.event_head,
                        limit: std::num::NonZeroU16::new(256).ok_or("history limit")?,
                    }))
                    .map_err(|error| {
                        format!(
                            "{INDETERMINATE_DELIVERY}: the accepted outcome of \
                             {command_id} is unread: {error}"
                        )
                    })?;
                    return match failed_outcome(&page.events, &command_id) {
                        Some(failure) => Err(format!(
                            "{kind:?} to worker {child} failed: {}: {}",
                            failure.code, failure.message
                        )),
                        None => Ok(()),
                    };
                }
                odin_domain::huginn::CommandReceipt::Duplicate {
                    command_id,
                    prior_outcome,
                } => {
                    // A replayed id is answered from durable evidence only.
                    // When the journal row never completed (a crash between
                    // the command's admission and its journaled outcome),
                    // the receipt alone is INDETERMINATE: reconcile against
                    // the transcript's journaled completion for THIS id.
                    let journaled = if prior_outcome.is_some() {
                        None
                    } else {
                        journaled_completion(&supervisor, child, &command_id)?
                    };
                    return match duplicate_verdict(prior_outcome.as_deref(), journaled.as_ref()) {
                        DeliveryVerdict::Delivered => Ok(()),
                        DeliveryVerdict::Refused(reason) => Err(reason),
                        DeliveryVerdict::Unsettled => Err(format!(
                            "{INDETERMINATE_DELIVERY}: {kind:?} to worker {child} is journaled \
                             without a durable outcome: whether it ran is indeterminate, so it \
                             is neither reported delivered nor re-sent under a fresh id"
                        )),
                    };
                }
            }
        }
    }

    fn open_delivery(
        &self,
        child: LiveSessionId,
        body: odin_domain::huginn::LiveCommandBody,
    ) -> Result<odin_domain::huginn::LiveCommand, String> {
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        let summary = match wait(&runtime, supervisor.actor(child)) {
            Ok(actor) => actor.summary().map_err(|error| error.to_string())?,
            // No process: a parked session is reopened by `deliver`.
            Err(LiveError::NotFound { .. }) => match block_on(supervisor.durable_summary(child))? {
                Some(summary) if summary.state != odin_domain::huginn::LiveSessionState::Ended => {
                    summary
                }
                _ => {
                    return Err(format!(
                        "{}: session {child} has ended",
                        odin_omp::host_tools::delegation::TARGET_ENDED
                    ))
                }
            },
            Err(error) => return Err(error.to_string()),
        };
        Ok(odin_domain::huginn::LiveCommand {
            command_id: crate::authority_provision::random_command_uuid()?,
            session_id: child,
            expected_epoch: summary.epoch,
            expected_event_head: Some(summary.event_head),
            body,
        })
    }

    /// Replays the exact recorded command. Missing outcomes or unavailable
    /// history leave the attempt unsettled, including across recovery.
    fn deliver(
        &self,
        command: odin_domain::huginn::LiveCommand,
    ) -> Result<DeliveryVerdict, String> {
        let supervisor = self.supervisor()?;
        let child = command.session_id;
        let kind = command.body.kind();
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        let receipt = match wait(&runtime, async {
            match supervisor.actor(child).await {
                Ok(actor) => actor.command(command).await,
                Err(LiveError::NotFound { .. }) => {
                    supervisor.recover_parked_report_command(command).await
                }
                Err(error) => Err(error),
            }
        }) {
            Ok(receipt) => receipt,
            // An ended session cannot execute the command.
            Err(LiveError::Conflict { code, message }) if code == "session_ended" => {
                return Ok(DeliveryVerdict::Refused(format!(
                    "{kind:?} to worker {child} was refused: {message}"
                )))
            }
            Err(error) => return Err(error.to_string()),
        };
        match receipt {
            odin_domain::huginn::CommandReceipt::Rejected { reason, .. } => {
                Ok(DeliveryVerdict::Refused(format!(
                    "{kind:?} to worker {child} was rejected: {reason:?}"
                )))
            }
            odin_domain::huginn::CommandReceipt::Accepted { command_id } => {
                let journaled = journaled_completion(&supervisor, child, &command_id)?;
                Ok(duplicate_verdict(None, journaled.as_ref()))
            }
            odin_domain::huginn::CommandReceipt::Duplicate {
                command_id,
                prior_outcome,
            } => {
                let journaled = if prior_outcome.is_some() {
                    None
                } else {
                    journaled_completion(&supervisor, child, &command_id).unwrap_or(None)
                };
                Ok(duplicate_verdict(
                    prior_outcome.as_deref(),
                    journaled.as_ref(),
                ))
            }
        }
    }

    fn next_launch_option(
        &self,
        child: LiveSessionId,
        current: &odin_omp::host_tools::delegation::WorkerLane,
    ) -> Result<Option<odin_omp::host_tools::delegation::WorkerLane>, String> {
        let supervisor = self.supervisor()?;
        let seat = block_on(supervisor.actor(child))?
            .summary()
            .map_err(|error| error.to_string())?
            .seat_id;
        let binding = block_on(async { Ok::<_, String>(supervisor.bindings().await) })?
            .into_iter()
            .find(|binding| binding.seat_id == seat)
            .ok_or_else(|| format!("worker {child}: seat {seat} has no live binding"))?;
        Ok(odin_omp::host_tools::delegation::next_switchable_lane(
            &binding.launch_options,
            current,
        ))
    }

    fn rollover(&self, child: LiveSessionId, refusal_event: u64) -> Result<u64, String> {
        let actor = block_on(self.supervisor()?.actor(child))?;
        let summary = block_on(actor.rollover_fresh(refusal_event))?;
        Ok(summary.epoch.get())
    }

    fn stop_child(
        &self,
        child: LiveSessionId,
    ) -> Result<odin_omp::host_tools::delegation::ChildStop, String> {
        let supervisor = self.supervisor()?;
        match block_on(async { Ok::<_, String>(supervisor.actor(child).await) })? {
            Ok(actor) => {
                // The actor receipt awaits the child bridge stop
                // (worker/effect cleanup, lease release, and the child's own
                // capsule retirement through the shared stop coordinator):
                // the OMP half of the stop. The child is over, so it ends
                // rather than merely stopping.
                block_on(actor.end())?;
                Ok(odin_omp::host_tools::delegation::ChildStop::Ended)
            }
            Err(LiveError::NotFound { .. }) => {
                // No live incarnation: a pod reported after a daemon
                // restart, or a child whose daemon died with its actor. The
                // journal, not the actor, settles the end — durably, exactly
                // once, so the caller never retries the absence.
                match block_on(supervisor.settle_absent_session(
                    child,
                    "reported settled with no live session: the daemon that ran it never \
                     ended it, so its journal takes the terminal transition",
                )) {
                    Ok(true) => Ok(odin_omp::host_tools::delegation::ChildStop::SettledAbsent),
                    Ok(false) => Ok(odin_omp::host_tools::delegation::ChildStop::AlreadyTerminal),
                    Err(error) => Err(error.to_string()),
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn await_stop(&self, child: LiveSessionId, budget: Duration) -> Result<bool, String> {
        let deadline = std::time::Instant::now() + budget;
        loop {
            if !self.snapshot(child)?.active {
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn retire_capsule_on_stop(
        &self,
        session: LiveSessionId,
        deadline: std::time::Instant,
    ) -> Result<(), String> {
        self.retire_capsule(session, deadline)
    }

    fn resting_workload_sessions(
        &self,
    ) -> Result<Vec<(LiveSessionId, String, WorkloadRest)>, String> {
        use odin_domain::huginn::LiveSessionState;
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        let summaries =
            wait(&runtime, supervisor.summaries()).map_err(|error| error.to_string())?;
        let mut resting = Vec::new();
        for summary in summaries {
            // A pod session parked by a restart lists Detached; its pod rests
            // in whatever state its journal recorded.
            let state = match summary.state {
                LiveSessionState::Detached => wait(&runtime, supervisor.parked(summary.session_id))
                    .map_err(|error| error.to_string())?
                    .map_or(summary.state, |parked| parked.state),
                state => state,
            };
            let rest = match state {
                LiveSessionState::Idle => WorkloadRest::Idle,
                LiveSessionState::Failed => WorkloadRest::Failed {
                    // Pre-field journals carry no `failed_at`;
                    // `updated_at` stays the fallback.
                    since_ms: u64::try_from(
                        summary
                            .failed_at
                            .unwrap_or(summary.updated_at)
                            .unix_timestamp_nanos()
                            / 1_000_000,
                    )
                    .unwrap_or(0),
                },
                _ => continue,
            };
            if let Some(operation) =
                wait(&runtime, supervisor.workload_operation(summary.session_id))
                    .map_err(|error| error.to_string())?
            {
                resting.push((summary.session_id, operation, rest));
            }
        }
        Ok(resting)
    }

    fn ended_workload_sessions(&self) -> Result<Vec<(LiveSessionId, String)>, String> {
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        wait(&runtime, supervisor.ended_workload_sessions()).map_err(|error| error.to_string())
    }

    fn screen(&self, child: LiveSessionId) -> Result<Option<String>, String> {
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        let actor = match wait(&runtime, supervisor.actor(child)) {
            Ok(actor) => actor,
            Err(LiveError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let Some(terminal) = actor.terminal().cloned() else {
            return Ok(None);
        };
        let screen = wait(&runtime, terminal.screen(SCREEN_BYTES))
            .map_err(|error| format!("the worker's screen could not be read: {error}"))?;
        tracing::debug!(
            "task screen read child={child} bytes={} lines={}",
            screen.len(),
            screen.lines().count()
        );
        Ok(Some(screen))
    }

    fn last_answer(
        &self,
        child: LiveSessionId,
        epoch: Option<i64>,
    ) -> Result<Option<String>, String> {
        let epoch = epoch
            .map(u64::try_from)
            .transpose()
            .map_err(|error| format!("invalid captured session epoch: {error}"))?;
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        // Read the captured incarnation, or the whole retained history for
        // workload reports. A restart must not make old failed prose look
        // like an answer from the fresh incarnation.
        let mut after = EventSeq::new(0);
        let mut answer: Option<String> = None;
        loop {
            let page = wait(
                &runtime,
                supervisor.history(odin_domain::huginn::HistoryQuery {
                    session_id: child,
                    after,
                    limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
                }),
            )
            .map_err(|error| error.to_string())?;
            if page.events.is_empty() {
                break;
            }
            for event in page.events {
                after = event.sequence;
                if epoch.is_some_and(|epoch| event.epoch.get() != epoch) {
                    continue;
                }
                if let odin_domain::huginn::LiveEventBody::AssistantMessage(message) = event.body {
                    let text = message
                        .content
                        .iter()
                        .filter_map(|block| match block {
                            odin_domain::huginn::LiveContentBlock::Text(text) => {
                                Some(text.as_str())
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !text.trim().is_empty() {
                        answer = Some(text);
                    }
                }
            }
        }
        // Preserve the authoritative answer; presentation limits belong to
        // task.read, not the report pump's durable source.
        Ok(answer)
    }

    /// The child's last structured completion result, read the only honest
    /// way: a bounded walk of the durable history keeping the LAST typed
    /// `Result` event — verbatim summary and declared artifacts, bound to
    /// the exact event sequence. No prose scraping; a read failure is
    /// returned, never papered over.
    fn last_result(
        &self,
        child: LiveSessionId,
    ) -> Result<Option<odin_omp::host_tools::delegation::TaskResultReport>, String> {
        use odin_omp::host_tools::delegation::TaskResultReport;
        let supervisor = self.supervisor()?;
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "no tokio runtime for supervisor control".to_owned())?;
        let mut after = EventSeq::new(0);
        let mut result: Option<TaskResultReport> = None;
        loop {
            let page = wait(
                &runtime,
                supervisor.history(odin_domain::huginn::HistoryQuery {
                    session_id: child,
                    after,
                    limit: std::num::NonZeroU16::new(128).expect("128 is non-zero"),
                }),
            )
            .map_err(|error| error.to_string())?;
            if page.events.is_empty() {
                break;
            }
            for event in page.events {
                after = event.sequence;
                if let odin_domain::huginn::LiveEventBody::Result(summary) = event.body {
                    result = Some(TaskResultReport {
                        summary: summary
                            .summary
                            .map(|text| text.chars().take(8192).collect::<String>()),
                        artifacts: summary
                            .artifacts
                            .iter()
                            .map(|artifact| artifact.to_string())
                            .collect(),
                        event_sequence: after.get(),
                    });
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod head_race_tests {
    use super::*;
    use odin_domain::huginn::{CommandRejection, EventSeq, LiveCommandKind, LiveSessionState};

    #[test]
    fn only_the_head_race_is_retried_and_only_boundedly() {
        let race = CommandRejection::EventHeadMismatch {
            expected: EventSeq::new(57),
            actual: EventSeq::new(58),
        };
        assert!(retries_head_race(&race, 1));
        assert!(retries_head_race(&race, HEAD_RACE_ATTEMPTS - 1));
        assert!(!retries_head_race(&race, HEAD_RACE_ATTEMPTS));
        let refused = CommandRejection::InvalidState {
            command: LiveCommandKind::Prompt,
            state: LiveSessionState::Ended,
        };
        assert!(!retries_head_race(&refused, 1));
    }
}

#[cfg(test)]
mod settled_since_tests {
    use odin_domain::huginn::{
        EventSeq, LiveSessionId, LiveSessionState, LiveSessionSummary, ModelName, ProviderName,
        SessionEpoch, TerminalSeq,
    };
    use time::{Duration, OffsetDateTime};

    use super::settled_since_ms;

    fn summary(
        state: LiveSessionState,
        updated_at: OffsetDateTime,
        failed_at: Option<OffsetDateTime>,
    ) -> LiveSessionSummary {
        LiveSessionSummary {
            session_id: LiveSessionId::new(uuid::Uuid::new_v4()).expect("session"),
            epoch: SessionEpoch::new(1),
            seat_id: odin_domain::SeatId::new("seat.architect").expect("seat"),
            provider: ProviderName::new("gateway").expect("provider"),
            model: ModelName::new("grok").expect("model"),
            title: None,
            state,
            started_at: OffsetDateTime::UNIX_EPOCH,
            updated_at,
            failed_at,
            event_head: EventSeq::new(3),
            terminal_head: TerminalSeq::new(0),
            pending_permission_count: 0,
        }
    }

    /// A provider-failed child rests `Failed`, not `Idle`, so it held its
    /// worker place and outlived `child_idle_seconds` while it had no
    /// settled instant. It settles from its first failure: a late
    /// diagnostic or partial message moves `updated_at`, never that
    /// instant. A working or ended child has none.
    #[test]
    fn a_failed_child_settles_from_its_first_failure() {
        let failed_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(1_000);
        let late = failed_at + Duration::minutes(5);
        let ms = |at: OffsetDateTime| u64::try_from(at.unix_timestamp_nanos() / 1_000_000).ok();
        assert_eq!(
            settled_since_ms(&summary(LiveSessionState::Failed, late, Some(failed_at))),
            ms(failed_at)
        );
        assert_eq!(
            settled_since_ms(&summary(LiveSessionState::Idle, late, None)),
            ms(late)
        );
        for state in [LiveSessionState::Running, LiveSessionState::Ended] {
            assert_eq!(settled_since_ms(&summary(state, late, None)), None);
        }
    }
}

#[cfg(test)]
mod command_outcome_tests {
    use odin_domain::huginn::{
        CommandFailure, CommandOutcome, EventSeq, LiveEvent, LiveEventBody, LiveSessionId,
        SessionEpoch, ToolDenial, ToolDenialReceipt,
    };
    use odin_domain::{CommandId, EventId};
    use odin_omp::host_tools::delegation::DeliveryVerdict;

    use super::{completed_outcome, duplicate_verdict, failed_outcome};

    fn completed(session: LiveSessionId, sequence: u64, outcome: CommandOutcome) -> LiveEvent {
        LiveEvent {
            schema_version: 1,
            event_id: EventId::new(format!("e{sequence}")).expect("event id"),
            session_id: session,
            epoch: SessionEpoch::new(1),
            sequence: EventSeq::new(sequence),
            occurred_at: time::OffsetDateTime::UNIX_EPOCH,
            body: LiveEventBody::ControlCompleted(outcome),
        }
    }

    #[test]
    fn the_command_s_own_journaled_failure_is_its_answer() {
        let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");
        let ours = CommandId::new("cmd-ours").expect("id");
        let other = CommandId::new("cmd-other").expect("id");
        let failure = CommandFailure {
            code: "control_failed".to_owned(),
            message: "pause is not available under the codex harness".to_owned(),
            retryable: false,
        };
        let events = vec![
            completed(
                session,
                1,
                CommandOutcome::Failed {
                    command_id: other.clone(),
                    error: failure.clone(),
                },
            ),
            completed(
                session,
                2,
                CommandOutcome::Failed {
                    command_id: ours.clone(),
                    error: failure.clone(),
                },
            ),
        ];
        assert_eq!(failed_outcome(&events, &ours), Some(failure));
        let applied = vec![completed(
            session,
            3,
            CommandOutcome::Applied {
                command_id: ours.clone(),
            },
        )];
        assert_eq!(failed_outcome(&applied, &ours), None);
        assert_eq!(failed_outcome(&events[..1], &ours), None);
    }

    // Missing outcomes remain unsettled; a fresh command ID must not resolve them.
    #[test]
    fn an_incomplete_duplicate_is_indeterminate_and_a_journaled_failure_is_not_success() {
        let session = LiveSessionId::new(uuid::Uuid::new_v4()).expect("session");
        let ours = CommandId::new("cmd-ours").expect("id");
        let failure = CommandFailure {
            code: "control_failed".to_owned(),
            message: "the harness refused the prompt".to_owned(),
            retryable: false,
        };
        let applied = CommandOutcome::Applied {
            command_id: ours.clone(),
        };
        let failed = CommandOutcome::Failed {
            command_id: ours.clone(),
            error: failure,
        };
        let cancelled = CommandOutcome::Cancelled {
            command_id: ours.clone(),
            reason: "the turn was aborted".to_owned(),
        };
        let denied = CommandOutcome::ToolDenied {
            command_id: ours.clone(),
            receipt: ToolDenialReceipt {
                request_id: ours.clone(),
                tool_name: "kube_workload_create".to_owned(),
                denial: ToolDenial::UnknownTool,
                error: "unknown tool".to_owned(),
            },
        };
        // A journaled completion is delivered, wherever it was read from.
        assert_eq!(
            duplicate_verdict(Some(&applied), None),
            DeliveryVerdict::Delivered
        );
        assert_eq!(
            duplicate_verdict(None, Some(&applied)),
            DeliveryVerdict::Delivered
        );
        // A journaled failure or cancellation executed and did not deliver:
        // never a success.
        for refused in [
            duplicate_verdict(Some(&failed), None),
            duplicate_verdict(None, Some(&failed)),
            duplicate_verdict(Some(&cancelled), None),
        ] {
            assert!(matches!(refused, DeliveryVerdict::Refused(_)));
        }
        // A denial probe settles durably with NOTHING executed: refused,
        // never delivered, never indeterminate.
        assert!(matches!(
            duplicate_verdict(Some(&denied), None),
            DeliveryVerdict::Refused(_)
        ));
        assert!(matches!(
            duplicate_verdict(None, Some(&denied)),
            DeliveryVerdict::Refused(_)
        ));
        // Denial does not mean the command executed.
        let denied_event = vec![completed(session, 3, denied.clone())];
        assert_eq!(completed_outcome(&denied_event, &ours), None);
        // An id journaled without any completion is Unsettled: not
        // delivered, and never decided by a fresh id.
        assert_eq!(duplicate_verdict(None, None), DeliveryVerdict::Unsettled);
        // Only a completion for this command can settle its delivery.
        assert_eq!(completed_outcome(&[], &ours), None);
        let other = CommandId::new("cmd-other").expect("id");
        let unrelated = vec![completed(
            session,
            1,
            CommandOutcome::Applied { command_id: other },
        )];
        assert_eq!(completed_outcome(&unrelated, &ours), None);
        // Use the first matching completion in transcript order.
        for proof in [cancelled, failed, applied] {
            let page = vec![completed(session, 2, proof.clone())];
            assert_eq!(completed_outcome(&page, &ours), Some(proof));
        }
    }
}
