use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_domain::{StopAudit, StopState, StopTraceEvent, StopTraceRow, StopVerdict, WorkerPhase};
use odin_ledger::stop as stop_store;
use odin_ledger::worker as worker_store;
use odin_ledger::LedgerError;
use odin_process::{
    mint_worker_id, CommandSpec, RegisteredServiceBinding, ScopeLimits, WorkerAuthority,
    WorkerIdentity, WorkerNaming, WorkerStopReport, STDIN_WRITE_TIMEOUT,
};
use odin_types::{CorrelationId, WorkerId};
use time::OffsetDateTime;

use crate::worker_broker;

use super::evidence::{
    actuate_concrete, audit_from_inspection, indeterminate_audit, outcome_from_audit,
    outcome_from_row, parse_recovery, push_trace, record_from_row, requested_audit,
    validate_worker_id,
};
use super::{StopAuthority, StopAuthorityError, WorkerLaunch};

impl StopAuthority {
    pub fn worker_identity(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<WorkerIdentity>, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_identity(&self.client, worker_id);
        }
        let Some(authority) = self.active_worker(worker_id)? else {
            return Ok(None);
        };
        let authority = authority
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
        Ok(Some(authority.identity().clone()))
    }

    pub fn write_worker_stdin(
        &self,
        worker_id: &WorkerId,
        bytes: &[u8],
    ) -> Result<(), StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_write_stdin(&self.client, worker_id, bytes);
        }
        self.write_worker_stdin_timeout(worker_id, bytes, STDIN_WRITE_TIMEOUT)
            .map(|_| ())
    }

    pub fn write_worker_stdin_timeout(
        &self,
        worker_id: &WorkerId,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<usize, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_write_stdin_timeout(
                &self.client,
                worker_id,
                bytes,
                timeout,
            );
        }
        let authority = self.require_active_worker(worker_id)?;
        let mut writer = {
            let mut authority = authority
                .lock()
                .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
            authority.stdin_writer()?
        };
        writer.write_timeout(bytes, timeout).map_err(Into::into)
    }

    pub fn close_worker_stdin(&self, worker_id: &WorkerId) -> Result<(), StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_close_stdin(&self.client, worker_id);
        }
        let authority = self.require_active_worker(worker_id)?;
        authority
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?
            .close_stdin()?;
        Ok(())
    }

    pub fn try_wait_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<ExitStatus>, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_try_wait(&self.client, worker_id);
        }
        let authority = self.require_active_worker(worker_id)?;
        let status = authority
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?
            .try_wait()?;
        Ok(status)
    }

    pub fn launch_worker(
        &self,
        naming: WorkerNaming,
        correlation_id: &CorrelationId,
        spec: &CommandSpec,
        limits: ScopeLimits,
    ) -> Result<WorkerLaunch, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_launch_worker(
                &self.client,
                naming,
                correlation_id,
                spec,
                limits,
            );
        }
        self.launch_inner(naming, correlation_id, spec, limits, None)
    }

    pub fn launch_registered_service(
        &self,
        naming: WorkerNaming,
        correlation_id: &CorrelationId,
        spec: &CommandSpec,
        limits: ScopeLimits,
        binding: &RegisteredServiceBinding,
    ) -> Result<WorkerLaunch, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_launch_registered_service(
                &self.client,
                naming,
                correlation_id,
                spec,
                limits,
                binding,
            );
        }
        self.launch_inner(naming, correlation_id, spec, limits, Some(binding))
    }

    fn launch_inner(
        &self,
        naming: WorkerNaming,
        correlation_id: &CorrelationId,
        spec: &CommandSpec,
        limits: ScopeLimits,
        binding: Option<&RegisteredServiceBinding>,
    ) -> Result<WorkerLaunch, StopAuthorityError> {
        let worker_id = naming.worker_id.clone();
        let unit = naming.unit();
        let tx_id = naming.tx_id.clone();
        let wp_id = naming.wp_id.clone();
        let attempt = naming.attempt;
        let payload_correlation = spec
            .environment
            .get(odin_process::CORRELATION_ENV)
            .map(|value| value.to_string_lossy().into_owned());
        if payload_correlation.as_deref() != Some(correlation_id.as_str()) {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "worker {} payload correlation does not match durable correlation {}",
                worker_id.as_str(),
                correlation_id.as_str()
            )));
        }
        let channel = self.local_channel()?;
        let mut authority = match binding {
            Some(binding) => {
                WorkerAuthority::prepare_registered_service(channel, naming, spec, limits, binding)?
            }
            None => WorkerAuthority::prepare(channel, naming, spec, limits)?,
        };
        authority.bind_abandonment(Arc::clone(&self.abandoned));
        let identity = authority.identity().clone();
        authority.release_payload()?;
        let registration = (|| {
            let mut ledger = self.lock_store()?;
            ledger.with_tx(|tx| {
                let registered = worker_store::register_worker(
                    tx,
                    &worker_store::NewWorker {
                        worker_id: worker_id.as_str(),
                        unit: &unit,
                        correlation_id: correlation_id.as_str(),
                        tx_id: &tx_id,
                        wp_id: &wp_id,
                        attempt,
                        now: OffsetDateTime::now_utc(),
                    },
                )?;
                if matches!(registered, worker_store::RegisterOutcome::Replay { .. }) {
                    return Err(LedgerError::Conflict(format!(
                        "register launched worker {}: worker already exists",
                        worker_id.as_str()
                    )));
                }
                worker_store::record_scope_proof(
                    tx,
                    worker_id.as_str(),
                    &worker_store::ScopeProof {
                        invocation_id: &identity.invocation_id.to_hex(),
                        cgroup_path: &identity.cgroup_path,
                        cgroup_inode: identity.cgroup_inode,
                        leader_pid: identity.leader_pid,
                        leader_start_ticks: identity.leader_start_ticks,
                    },
                    OffsetDateTime::now_utc(),
                )?;
                worker_store::mark_payload_running(
                    tx,
                    worker_id.as_str(),
                    OffsetDateTime::now_utc(),
                )?;
                Ok(())
            })?;
            Ok::<_, StopAuthorityError>(())
        })();
        if let Err(error) = registration {
            if let Err(stop_error) = authority.stop() {
                tracing::error!(worker_id = %worker_id.as_str(), error = %stop_error, "Stop unregistered worker failed");
            }
            return Err(error);
        }
        let stdout = authority.take_stdout()?;
        let stderr = authority.take_stderr()?;
        let shared = Arc::new(Mutex::new(authority));
        let mut active = self
            .active
            .lock()
            .map_err(|_| StopAuthorityError::WorkerRegistryLock)?;
        if self.abandoned.load(std::sync::atomic::Ordering::Acquire) {
            shared
                .lock()
                .map_err(|_| StopAuthorityError::WorkerRegistryLock)?
                .abandon();
        }
        if active.contains_key(worker_id.as_str()) {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "worker {} already has a live authority",
                worker_id.as_str()
            )));
        }
        active.insert(worker_id.as_str().to_owned(), shared);
        drop(active);
        Ok(WorkerLaunch {
            identity,
            stdout,
            stderr,
        })
    }

    pub fn register_terminal_intent(
        &self,
        unit: &str,
        correlation_id: &CorrelationId,
    ) -> Result<WorkerId, StopAuthorityError> {
        if self.client.is_remote() {
            return Err(StopAuthorityError::InvalidWorker(
                "terminal unit registration is root-local; the parent broker exposes no external-unit operation"
                    .to_owned(),
            ));
        }
        let worker_id = mint_worker_id()?;
        let naming = WorkerNaming::new(correlation_id.as_str(), "term", 1, worker_id.clone())
            .map_err(StopAuthorityError::Worker)?;
        let mut ledger = self.lock_store()?;
        let registered =
            worker_store::nonterminal_rows(ledger.connection(), Some(correlation_id.as_str()))?
                .iter()
                .any(|row| row.unit == unit);
        if registered {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "unit {unit} already has a nonterminal row under correlation {}",
                correlation_id.as_str()
            )));
        }
        let registration = ledger.with_tx(|tx| {
            worker_store::register_worker(
                tx,
                &worker_store::NewWorker {
                    worker_id: worker_id.as_str(),
                    unit,
                    correlation_id: correlation_id.as_str(),
                    tx_id: &naming.tx_id,
                    wp_id: &naming.wp_id,
                    attempt: naming.attempt,
                    now: OffsetDateTime::now_utc(),
                },
            )
        })?;
        if matches!(registration, worker_store::RegisterOutcome::Replay { .. }) {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "terminal worker {} registration already exists",
                worker_id.as_str()
            )));
        }
        Ok(worker_id)
    }

    pub fn prove_terminal_unit(
        &self,
        worker_id: &WorkerId,
        unit: &str,
    ) -> Result<WorkerIdentity, StopAuthorityError> {
        if self.client.is_remote() {
            return Err(StopAuthorityError::InvalidWorker(
                "terminal unit proof is root-local".to_owned(),
            ));
        }
        let proof = WorkerAuthority::prove_unit_identity(self.local_channel()?, unit)?;
        self.attach_terminal_proof(worker_id, unit, proof)
    }

    pub(crate) fn attach_terminal_proof(
        &self,
        worker_id: &WorkerId,
        unit: &str,
        proof: odin_process::UnitIdentityProof,
    ) -> Result<WorkerIdentity, StopAuthorityError> {
        let row = {
            let ledger = self.lock_store()?;
            worker_store::worker_row(ledger.connection(), worker_id.as_str())?
                .ok_or_else(|| StopAuthorityError::UnknownWorker(worker_id.as_str().to_owned()))?
        };
        if row.unit != unit {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "terminal worker {} names unit {:?}, not {unit:?}",
                worker_id.as_str(),
                row.unit
            )));
        }
        if row.invocation_id.is_some() {
            return Err(StopAuthorityError::InvalidWorker(format!(
                "terminal worker {} already carries a proof; recover it instead of re-proving",
                worker_id.as_str()
            )));
        }
        let invocation_hex = proof.invocation_id.to_hex();
        {
            let mut ledger = self.lock_store()?;
            ledger.with_tx(|tx| {
                if stop_store::stop_row(tx, worker_id.as_str())?.is_some() {
                    return Err(LedgerError::Conflict(format!(
                        "terminal worker {} was stopped before its proof became durable",
                        worker_id.as_str()
                    )));
                }
                worker_store::record_scope_proof(
                    tx,
                    worker_id.as_str(),
                    &worker_store::ScopeProof {
                        invocation_id: &invocation_hex,
                        cgroup_path: &proof.cgroup_path,
                        cgroup_inode: proof.cgroup_inode,
                        leader_pid: proof.leader_pid,
                        leader_start_ticks: proof.leader_start_ticks,
                    },
                    OffsetDateTime::now_utc(),
                )?;
                let _ = worker_store::mark_payload_running(
                    tx,
                    worker_id.as_str(),
                    OffsetDateTime::now_utc(),
                )?;
                Ok(())
            })?;
        }
        Ok(WorkerIdentity {
            worker_id: worker_id.clone(),
            unit: unit.to_owned(),
            invocation_id: proof.invocation_id,
            cgroup_path: proof.cgroup_path,
            cgroup_inode: proof.cgroup_inode,
            leader_pid: proof.leader_pid,
            leader_start_ticks: proof.leader_start_ticks,
        })
    }

    pub fn stop_worker(
        &self,
        worker_id: &WorkerId,
    ) -> Result<super::StopOutcome, StopAuthorityError> {
        self.stop_worker_inner(worker_id, None)
    }

    pub fn stop_worker_bounded(
        &self,
        worker_id: &WorkerId,
        deadline: Instant,
    ) -> Result<super::StopOutcome, StopAuthorityError> {
        self.stop_worker_inner(worker_id, Some(deadline))
    }

    fn stop_worker_inner(
        &self,
        worker_id: &WorkerId,
        deadline: Option<Instant>,
    ) -> Result<super::StopOutcome, StopAuthorityError> {
        if self.client.is_remote() {
            return match deadline {
                None => worker_broker::remote_stop_worker(&self.client, &self.store, worker_id),
                Some(deadline) => worker_broker::remote_stop_worker_bounded(
                    &self.client,
                    &self.store,
                    worker_id,
                    deadline,
                ),
            };
        }
        let row = {
            let ledger = self.lock_store()?;
            worker_store::worker_row(ledger.connection(), worker_id.as_str())?
                .ok_or_else(|| StopAuthorityError::UnknownWorker(worker_id.as_str().to_owned()))?
        };
        validate_worker_id(worker_id, &row)?;

        let requested = requested_audit(&row);
        let requested_json = serde_json::to_string(&requested)?;
        let request = {
            let mut ledger = self.lock_store()?;
            ledger.with_tx(|tx| {
                stop_store::request_stop(
                    tx,
                    worker_id.as_str(),
                    &row.correlation_id,
                    &requested_json,
                    OffsetDateTime::now_utc(),
                )
            })?
        };
        let previous_verdict =
            if let stop_store::StopIntentOutcome::Replay { row: existing } = request {
                if existing.state.is_terminal() {
                    let outcome = outcome_from_row(*existing, true)?;
                    self.remove_active(worker_id)?;
                    return Ok(outcome);
                }
                Some(outcome_from_row(*existing, true)?.verdict)
            } else {
                None
            };

        if row.invocation_id.is_none() {
            let channel = self.local_channel()?;
            // Keep failed queries pending with their cause for the next start.
            let unit_absent = match WorkerAuthority::unit_absent(channel, &row.unit) {
                Ok(absent) => absent,
                Err(error) => {
                    let reason = format!(
                        "query terminal unit {} before stop failed: {error}",
                        row.unit
                    );
                    let audit =
                        indeterminate_audit(&row, requested.trace, false, false, false, reason);
                    self.persist_attempt(&row, &audit)?;
                    let outcome = outcome_from_audit(worker_id.clone(), audit, false)?;
                    if previous_verdict.as_ref() != Some(&outcome.verdict) {
                        tracing::error!(worker_id = %worker_id.as_str(), cause = ?outcome.verdict, "worker stop failed");
                    }
                    return Ok(outcome);
                }
            };
            let abandoned = super::evidence::abandoned_registration_audit(
                &row,
                OffsetDateTime::now_utc(),
                || unit_absent,
            )?;
            let Some(audit) = abandoned else {
                let audit = indeterminate_audit(
                    &row,
                    requested.trace,
                    false,
                    false,
                    false,
                    "stop worker failed: terminal registration has no process identity".to_owned(),
                );
                self.persist_attempt(&row, &audit)?;
                let outcome = outcome_from_audit(worker_id.clone(), audit, false)?;
                if previous_verdict.as_ref() != Some(&outcome.verdict) {
                    tracing::error!(worker_id = %worker_id.as_str(), cause = ?outcome.verdict, "worker stop failed");
                }
                return Ok(outcome);
            };
            self.persist_attempt(&row, &audit)?;
            self.remove_active(worker_id)?;
            return outcome_from_audit(worker_id.clone(), audit, false);
        }

        let audit = self.actuate(worker_id, &row, requested.trace.clone(), deadline);
        self.persist_attempt(&row, &audit)?;
        let outcome = outcome_from_audit(worker_id.clone(), audit, false)?;
        if outcome.verdict != StopVerdict::Stopped
            && previous_verdict.as_ref() != Some(&outcome.verdict)
        {
            tracing::error!(worker_id = %worker_id.as_str(), cause = ?outcome.verdict, "worker stop failed");
        }
        if outcome.verdict.settle_state().is_some() {
            self.remove_active(worker_id)?;
        }
        Ok(outcome)
    }

    pub fn recover_pending(
        &self,
        correlation_id: Option<&CorrelationId>,
    ) -> Result<Vec<super::StopOutcome>, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_recover_pending(&self.client, correlation_id);
        }
        let rows = {
            let ledger = self.lock_store()?;
            worker_store::nonterminal_rows(
                ledger.connection(),
                correlation_id.map(CorrelationId::as_str),
            )?
        };
        let mut outcomes = Vec::with_capacity(rows.len());
        for row in rows {
            let worker_id = WorkerId::new(&row.worker_id).map_err(|error| {
                StopAuthorityError::InvalidWorker(format!(
                    "worker id {:?} is invalid: {error}",
                    row.worker_id
                ))
            })?;
            outcomes.push(self.stop_worker(&worker_id)?);
        }
        Ok(outcomes)
    }

    pub fn stop_record(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<super::StopEvidenceRecord>, StopAuthorityError> {
        if self.client.is_remote() {
            return worker_broker::remote_stop_record(&self.client, worker_id);
        }
        let row = {
            let ledger = self.lock_store()?;
            stop_store::stop_row(ledger.connection(), worker_id.as_str())?
        };
        row.map(record_from_row).transpose()
    }

    fn actuate(
        &self,
        worker_id: &WorkerId,
        row: &worker_store::WorkerRow,
        mut trace: Vec<StopTraceRow>,
        deadline: Option<Instant>,
    ) -> StopAudit {
        push_trace(&mut trace, &row.worker_id, StopTraceEvent::Cooperative);
        let (invocation, anchors) = match parse_recovery(row) {
            Ok(parsed) => parsed,
            Err(reason) => return indeterminate_audit(row, trace, false, false, false, reason),
        };

        match self.active_worker(worker_id) {
            Ok(Some(authority)) => {
                return match authority.lock() {
                    Ok(mut authority) => {
                        actuate_concrete(row, trace, false, &mut authority, deadline)
                    }
                    Err(_) => indeterminate_audit(
                        row,
                        trace,
                        false,
                        false,
                        false,
                        "live worker authority lock is poisoned".to_owned(),
                    ),
                }
            }
            Ok(None) => {}
            Err(error) => {
                return indeterminate_audit(row, trace, false, false, false, error.to_string())
            }
        }

        let channel = match self.local_channel() {
            Ok(channel) => channel,
            Err(error) => {
                return indeterminate_audit(row, trace, false, false, false, error.to_string())
            }
        };
        match WorkerAuthority::recover(
            channel,
            worker_id.clone(),
            &row.unit,
            &invocation,
            anchors.clone(),
        ) {
            Err(error) => indeterminate_audit(
                row,
                trace,
                true,
                false,
                false,
                format!("worker identity recovery failed: {error}"),
            ),
            Ok(None) => {
                match WorkerAuthority::inspect_recorded(channel, &row.unit, &invocation, &anchors) {
                    Ok(inspection) => {
                        if inspection.leader_reaped {
                            push_trace(&mut trace, &row.worker_id, StopTraceEvent::Reap);
                        }
                        push_trace(&mut trace, &row.worker_id, StopTraceEvent::ResidueQuery);
                        audit_from_inspection(
                            row,
                            trace,
                            true,
                            WorkerStopReport::default(),
                            inspection,
                        )
                    }
                    Err(error) => indeterminate_audit(
                        row,
                        trace,
                        true,
                        false,
                        false,
                        format!("inspect stopped worker failed: {error}"),
                    ),
                }
            }
            Ok(Some(mut authority)) => actuate_concrete(row, trace, true, &mut authority, deadline),
        }
    }

    fn persist_attempt(
        &self,
        original: &worker_store::WorkerRow,
        audit: &StopAudit,
    ) -> Result<(), StopAuthorityError> {
        let evidence_json = serde_json::to_string(audit)?;
        let mut ledger = self.lock_store()?;
        ledger.with_tx(|tx| {
            let current = worker_store::worker_row(tx, &original.worker_id)?.ok_or_else(|| {
                LedgerError::NotFound {
                    kind: "worker",
                    id: original.worker_id.clone(),
                }
            })?;
            match audit.stop_verdict().map_err(|error| {
                LedgerError::invalid_data_caused_by(
                    format!("stop audit for {} is invalid", original.worker_id),
                    error,
                )
            })? {
                StopVerdict::Requested => {}
                StopVerdict::Indeterminate(_) => {
                    let _ = stop_store::record_indeterminate(
                        tx,
                        &original.worker_id,
                        &evidence_json,
                        OffsetDateTime::now_utc(),
                    )?;
                }
                StopVerdict::Stopped => {
                    if current.phase.is_nonterminal() {
                        let settlement = if current.phase == WorkerPhase::PayloadRunning {
                            worker_store::Settlement::Stopped
                        } else {
                            worker_store::Settlement::Failed
                        };
                        let _ = worker_store::settle_worker(
                            tx,
                            &current.worker_id,
                            current.phase,
                            settlement,
                            "{}",
                            OffsetDateTime::now_utc(),
                        )?;
                    }
                    let _ = stop_store::settle_stop(
                        tx,
                        &original.worker_id,
                        StopState::Stopped,
                        &evidence_json,
                        OffsetDateTime::now_utc(),
                    )?;
                }
                StopVerdict::Failed(residue) => {
                    if current.phase.is_nonterminal() {
                        let residue_json = serde_json::to_string(&residue)?;
                        let _ = worker_store::settle_worker(
                            tx,
                            &current.worker_id,
                            current.phase,
                            worker_store::Settlement::Residual,
                            &residue_json,
                            OffsetDateTime::now_utc(),
                        )?;
                    }
                    let _ = stop_store::settle_stop(
                        tx,
                        &original.worker_id,
                        StopState::Failed,
                        &evidence_json,
                        OffsetDateTime::now_utc(),
                    )?;
                }
            }
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stop::recovery_worker_channel;
    use odin_domain::InvocationId;
    use odin_ledger::Ledger;

    fn test_stop_authority(store: &Arc<Mutex<Ledger>>) -> StopAuthority {
        let channel =
            recovery_worker_channel("unix:path=/tmp/odin-stop-authority-test-absent-bus.sock")
                .expect("recovery channel");
        StopAuthority::new(Arc::clone(store), channel)
    }

    fn durable_worker_row_count(store: &Arc<Mutex<Ledger>>) -> usize {
        let ledger = store.lock().expect("ledger");
        worker_store::nonterminal_rows(ledger.connection(), None)
            .expect("worker rows")
            .len()
    }

    #[test]
    fn terminal_stop_query_error_keeps_worker_for_next_start() {
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let authority = test_stop_authority(&store);
        let correlation = CorrelationId::new("44444444444444444444444444444444").unwrap();
        let worker = authority
            .register_terminal_intent("odin-term-query-error.service", &correlation)
            .unwrap();

        let outcome = authority.stop_worker(&worker).unwrap();
        let StopVerdict::Indeterminate(missing) = &outcome.verdict else {
            panic!("failed terminal query must remain pending: {outcome:?}");
        };
        assert!(missing
            .reason
            .contains("query terminal unit odin-term-query-error.service before stop failed"));
        assert!(missing.reason.contains("cannot connect"));
        assert!(missing
            .reason
            .contains("/tmp/odin-stop-authority-test-absent-bus.sock"));
        assert_eq!(durable_worker_row_count(&store), 1);
        let record = authority.stop_record(&worker).unwrap().unwrap();
        assert_eq!(record.state, StopState::Requested);
        assert_eq!(record.attempts, 1);
        assert!(record.settled_at.is_none());
        assert_eq!(record.evidence.missing.as_ref(), Some(missing));
    }

    #[test]
    fn terminal_intent_precedes_launch_and_the_proof_completes_the_row() {
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let authority = test_stop_authority(&store);
        let correlation = CorrelationId::new("33333333333333333333333333333333").unwrap();
        let worker_id = authority
            .register_terminal_intent("odin-term-a1b2c3d4.service", &correlation)
            .expect("prelaunch intent");
        let row = {
            let ledger = store.lock().unwrap();
            worker_store::worker_row(ledger.connection(), worker_id.as_str())
                .expect("row query")
                .expect("terminal row")
        };
        assert_eq!(row.unit, "odin-term-a1b2c3d4.service");
        assert_eq!(row.phase, WorkerPhase::Registered);
        assert_eq!(row.invocation_id, None, "the intent precedes any proof");

        let proof = odin_process::UnitIdentityProof {
            invocation_id: InvocationId::from_raw([0x4D; 16]),
            cgroup_path: "/sys/fs/cgroup/odin-term-a1b2c3d4.service".to_owned(),
            cgroup_inode: 4242,
            leader_pid: 4243,
            leader_start_ticks: 99,
        };
        let identity = authority
            .attach_terminal_proof(&worker_id, "odin-term-a1b2c3d4.service", proof.clone())
            .expect("proof attach");
        assert_eq!(identity.worker_id, worker_id);
        assert_eq!(identity.invocation_id, InvocationId::from_raw([0x4D; 16]));
        let row = {
            let ledger = store.lock().unwrap();
            worker_store::worker_row(ledger.connection(), worker_id.as_str())
                .expect("row query")
                .expect("terminal row")
        };
        assert_eq!(row.phase, WorkerPhase::PayloadRunning);
        assert_eq!(
            row.invocation_id.as_deref(),
            Some(InvocationId::from_raw([0x4D; 16]).to_hex().as_str())
        );
        assert_eq!(row.cgroup_inode, Some(4242));
        assert_eq!(row.leader_pid, Some(4243));
        let (parsed_invocation, anchors) = parse_recovery(&row).expect("recovery parse");
        assert_eq!(parsed_invocation, InvocationId::from_raw([0x4D; 16]));
        assert_eq!(anchors.cgroup_path, proof.cgroup_path);
        assert_eq!(anchors.leader_start_ticks, 99);

        let second = authority
            .register_terminal_intent("odin-term-a1b2c3d4.service", &correlation)
            .expect_err("a live unit is never registered twice");
        assert!(matches!(second, StopAuthorityError::InvalidWorker(_)));
        let wrong_unit = authority
            .attach_terminal_proof(&worker_id, "odin-term-0ddba11.service", proof.clone())
            .expect_err("a proof names exactly its own unit");
        assert!(matches!(wrong_unit, StopAuthorityError::InvalidWorker(_)));
        assert!(matches!(
            authority.attach_terminal_proof(&worker_id, "odin-term-a1b2c3d4.service", proof),
            Err(StopAuthorityError::InvalidWorker(_))
        ));
        assert_eq!(
            durable_worker_row_count(&store),
            1,
            "the refused operations must leave exactly the one row"
        );
    }

    #[test]
    fn terminal_registration_and_proof_refuse_a_remote_authority() {
        let store = Arc::new(Mutex::new(Ledger::open_in_memory().unwrap()));
        let channel =
            recovery_worker_channel("unix:path=/tmp/odin-stop-authority-test-absent-bus.sock")
                .expect("recovery channel");
        let descriptor = worker_broker::ParentAuthorityDescriptor::new(
            mint_worker_id().expect("worker id"),
            std::path::PathBuf::from("/tmp/odin-term-remote-broker.sock"),
            std::path::PathBuf::from("/tmp/odin-term-remote-store-root"),
        )
        .expect("remote descriptor");
        let remote = StopAuthority::open(
            Arc::clone(&store),
            channel,
            worker_broker::ParentAuthorityClient::remote(descriptor),
        );
        let correlation = CorrelationId::new("55555555555555555555555555555555").unwrap();
        assert!(matches!(
            remote.register_terminal_intent("odin-term-c3d4e5f6.service", &correlation),
            Err(StopAuthorityError::InvalidWorker(_))
        ));
        let worker_id = mint_worker_id().expect("worker id");
        assert!(matches!(
            remote.prove_terminal_unit(&worker_id, "odin-term-c3d4e5f6.service"),
            Err(StopAuthorityError::InvalidWorker(_))
        ));
        assert_eq!(
            durable_worker_row_count(&store),
            0,
            "the remote path must write nothing"
        );
    }
}
