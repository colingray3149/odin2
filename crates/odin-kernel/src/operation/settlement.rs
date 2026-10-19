//! Reconcile recorded effects without replay, revalidating observations after reacquiring the ledger lock.

use std::collections::BTreeMap;
use std::sync::MutexGuard;

use odin_domain::operation::{EffectState, Usage};
use odin_domain::Digest;
use odin_ledger::operation as store;
use odin_ledger::{Ledger, LedgerError};
use odin_types::{CapsuleId, CorrelationId, OperationId};

use crate::token::{FreshAuthority, SeatAuthority};

use super::model::{
    charged_stop, utc, AuthorityResult, CapsuleOutcome, CloseMode, OperationDecision,
    OperationRejection, Payload, PreWorld, ReconcileOutcome, Reconciliation, RecordedBinding, Step,
    StopIntentOutcome,
};
use super::OperationAuthority;

/// Revalidate the recorded row before settlement so a stale observation cannot overwrite a concurrent change.
struct RowObservation {
    correlation_id: String,
    effect_state: EffectState,
    binding_digest: String,
    request_json: String,
    observed: PreWorld,
}

impl RowObservation {
    fn matches(&self, live: &store::OperationRow) -> bool {
        self.correlation_id == live.correlation_id
            && self.effect_state == live.effect_state
            && self.binding_digest == live.binding_digest
            && self.request_json == live.request_json
    }
}

impl OperationAuthority {
    pub fn reconcile(
        &self,
        fresh: FreshAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        operation_id: &OperationId,
    ) -> AuthorityResult<ReconcileOutcome> {
        let now_ms = self.now_ms();
        let row = self.bound_row(
            fresh.get(),
            capsule_id,
            correlation_id,
            operation_id,
            now_ms,
        )?;
        let payload = self.payload_from_row(&row);
        let recorded = RecordedBinding::parse(&row);
        let observed = match (&recorded, &payload) {
            (Some(recorded), Some(payload)) => self
                .executor
                .observe(&recorded.contract, payload)
                .map_err(OperationRejection::Executor)?,
            _ => PreWorld::Absent,
        };
        let decision = self.reconcile_row(&row, recorded.as_ref(), payload.as_ref(), now_ms)?;
        Ok(ReconcileOutcome { decision, observed })
    }

    /// Unresolved effects keep the capsule open; abort can settle only effects known not to have occurred.
    pub fn close_capsule(
        &self,
        fresh: FreshAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        mode: CloseMode,
    ) -> AuthorityResult<CapsuleOutcome> {
        let now_ms = self.now_ms();
        let authority = fresh.get();
        self.check_authority(authority, now_ms)?;
        let now = utc(now_ms)?;
        // Release the ledger lock before executor callbacks, which may re-enter the same ledger.
        let rows = {
            let ledger = self.lock_store()?;
            let lease = store::lease_row(ledger.connection(), capsule_id.as_str())?;
            let lease = match lease {
                Some(lease) => lease,
                None => {
                    return Err(OperationRejection::UnknownOperation {
                        correlation_id: correlation_id.clone(),
                    })
                }
            };
            let bound = Self::lease_bound(&lease, authority);
            if !bound {
                return Err(OperationRejection::AuthorityMismatch {
                    correlation_id: correlation_id.clone(),
                });
            }
            if lease.state != "open" {
                return Ok(CapsuleOutcome {
                    capsule_id: capsule_id.clone(),
                    drained: 0,
                    replay: true,
                });
            }
            store::nonterminal_rows(ledger.connection(), Some(capsule_id.as_str()))?
        };
        let observations = self.observe_rows(&rows)?;
        // Revalidate after observation because another close or stop may have changed the lease.
        let mut ledger = self.lock_store()?;
        self.check_authority(authority, now_ms)?;
        let lease = store::lease_row(ledger.connection(), capsule_id.as_str())?;
        let lease = match lease {
            Some(lease) => lease,
            None => {
                return Err(OperationRejection::UnknownOperation {
                    correlation_id: correlation_id.clone(),
                })
            }
        };
        if !Self::lease_bound(&lease, authority) {
            return Err(OperationRejection::AuthorityMismatch {
                correlation_id: correlation_id.clone(),
            });
        }
        if lease.state != "open" {
            drop(ledger);
            return Ok(CapsuleOutcome {
                capsule_id: capsule_id.clone(),
                drained: 0,
                replay: true,
            });
        }
        let fresh_rows = store::nonterminal_rows(ledger.connection(), Some(capsule_id.as_str()))?;
        let mut drained = 0_u64;
        let mut unresolved = 0_u64;
        for row in &rows {
            // A concurrently settled row must not be overwritten by a stale observation.
            if !fresh_rows
                .iter()
                .any(|fresh| fresh.correlation_id == row.correlation_id)
            {
                drained += 1;
            }
        }
        for row in &fresh_rows {
            let resolved = self.settle_row(
                row,
                observations.get(&row.correlation_id),
                mode,
                now_ms,
                &mut ledger,
            )?;
            match resolved {
                Some(_) => drained += 1,
                None => unresolved += 1,
            }
        }
        if unresolved > 0 {
            return Err(OperationRejection::CapsuleBlocked {
                capsule_id: capsule_id.clone(),
                blocked: unresolved,
            });
        }
        let closed = ledger.with_tx(|tx| {
            store::close_lease(tx, capsule_id.as_str(), mode.as_str(), drained as i64, now)
        })?;
        drop(ledger);
        if !closed {
            return Ok(CapsuleOutcome {
                capsule_id: capsule_id.clone(),
                drained: 0,
                replay: true,
            });
        }
        Ok(CapsuleOutcome {
            capsule_id: capsule_id.clone(),
            drained,
            replay: false,
        })
    }

    fn lease_bound(lease: &store::CapsuleLeaseRow, authority: &SeatAuthority) -> bool {
        lease.seat_id == authority.seat().as_str()
            && lease.token_id == authority.token_id().as_str()
            && lease.session_id == authority.session().as_str()
            && lease.policy_digest == authority.capability_policy_digest().to_string()
    }

    /// Keep stop intent pending until the executor reports an outcome; signalling alone is not a verdict.
    pub fn stop_intent(
        &self,
        fresh: FreshAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        operation_id: Option<OperationId>,
    ) -> AuthorityResult<StopIntentOutcome> {
        let now_ms = self.now_ms();
        let authority = fresh.get();
        self.check_authority(authority, now_ms)?;
        // Resolve by operation ID because the stop correlation identifies its own journal row.
        let row = match &operation_id {
            Some(operation_id) => {
                let ledger = self.lock_store()?;
                let row = store::operation_row_by_id(ledger.connection(), operation_id.as_str())?;
                let row = row.ok_or_else(|| OperationRejection::UnknownOperation {
                    correlation_id: correlation_id.clone(),
                })?;
                Some(Self::bind_row_authority(
                    row,
                    authority,
                    capsule_id,
                    correlation_id,
                )?)
            }
            None => None,
        };
        let now = utc(now_ms)?;
        let recorded_fresh = {
            let mut ledger = self.lock_store()?;
            // Charge atomically with insertion so concurrent stops cannot spend the same budget.
            let step = ledger.with_tx(|tx| {
                let lease = store::lease_row(tx, capsule_id.as_str())?;
                match lease {
                    Some(lease)
                        if lease.state == "open"
                            && lease.seat_id == authority.seat().as_str()
                            && lease.token_id == authority.token_id().as_str()
                            && lease.session_id == authority.session().as_str()
                            && lease.policy_digest
                                == authority.capability_policy_digest().to_string() => {}
                    Some(lease) if lease.state == "open" => {
                        return Ok(Step::Reject(OperationRejection::CapsuleAuthorityMismatch {
                            capsule_id: capsule_id.clone(),
                        }))
                    }
                    _ => {
                        return Ok(Step::Reject(OperationRejection::CapsuleClosed {
                            capsule_id: capsule_id.clone(),
                        }))
                    }
                }
                let stop_charge = charged_stop();
                let usage = store::usage(tx, authority.session().as_str())?;
                if let Err(error) = self.limits.apply(
                    Usage {
                        requests: usage.requests,
                        stops: usage.stops,
                        spend: usage.spend,
                    },
                    stop_charge,
                ) {
                    return Ok(Step::Reject(OperationRejection::BudgetDenied {
                        detail: error.to_string(),
                    }));
                }
                let authority_cols = store::LeaseAuthority {
                    token_issued_at_ms: authority.issued_at_ms(),
                    seat_id: authority.seat().as_str(),
                    token_id: authority.token_id().as_str(),
                    session_id: authority.session().as_str(),
                    policy_digest: &authority.capability_policy_digest().to_string(),
                    listing_digest: &row
                        .as_ref()
                        .map(|row| row.listing_digest.clone())
                        .unwrap_or_default(),
                };
                let recorded = store::record_stop(
                    tx,
                    capsule_id.as_str(),
                    &authority_cols,
                    correlation_id.as_str(),
                    operation_id.as_ref().map(OperationId::as_str),
                    now,
                )?;
                if matches!(recorded, store::StopRecordOutcome::Recorded) {
                    store::bump_usage(
                        tx,
                        authority.session().as_str(),
                        stop_charge.requests,
                        stop_charge.stops,
                        stop_charge.spend,
                        now,
                    )?;
                }
                Ok(Step::Done(recorded))
            })?;
            step.into_result()?
        };
        let durable_only = matches!(recorded_fresh, store::StopRecordOutcome::Existing { .. });
        let handle = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(correlation_id.as_str())
            .cloned();
        let process = handle.as_ref().map(|handle| {
            handle.cancel();
            handle.registered_process()
        });
        let process = process.unwrap_or(None);
        let row = {
            let ledger = self.lock_store()?;
            store::stop_row(ledger.connection(), correlation_id.as_str())?
        };
        let state = row
            .as_ref()
            .map(|row| row.state.clone())
            .unwrap_or_else(|| "requested".to_owned());
        let durable_operation_id = row.as_ref().and_then(|row| {
            row.operation_id
                .as_ref()
                .and_then(|value| OperationId::new(value).ok())
        });
        let replay = handle.is_some()
            || durable_only
            || matches!(
                row.as_ref().map(|row| row.state.as_str()),
                Some("stopped") | Some("failed")
            );
        Ok(StopIntentOutcome {
            correlation_id: correlation_id.clone(),
            operation_id: operation_id.or(durable_operation_id),
            state,
            replay,
            process,
        })
    }

    pub(super) fn bound_row(
        &self,
        authority: &SeatAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        operation_id: &OperationId,
        now_ms: u64,
    ) -> AuthorityResult<store::OperationRow> {
        self.check_authority(authority, now_ms)?;
        let row = {
            let ledger = self.lock_store()?;
            store::operation_row(ledger.connection(), correlation_id.as_str())?
        };
        let row = row.ok_or_else(|| OperationRejection::UnknownOperation {
            correlation_id: correlation_id.clone(),
        })?;
        // The correlation names the row; the presented operation id must be
        // the one this row was prepared under.
        if row.operation_id != operation_id.as_str() {
            return Err(OperationRejection::AuthorityMismatch {
                correlation_id: correlation_id.clone(),
            });
        }
        Self::bind_row_authority(row, authority, capsule_id, correlation_id)
    }

    /// All row operations require the capsule and original seat, token, session, and policy digest.
    fn bind_row_authority(
        row: store::OperationRow,
        authority: &SeatAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
    ) -> AuthorityResult<store::OperationRow> {
        if row.capsule_id != capsule_id.as_str()
            || row.seat_id != authority.seat().as_str()
            || row.token_id != authority.token_id().as_str()
            || row.session_id != authority.session().as_str()
            || row.policy_digest != authority.capability_policy_digest().to_string()
        {
            return Err(OperationRejection::AuthorityMismatch {
                correlation_id: correlation_id.clone(),
            });
        }
        Ok(row)
    }

    pub(super) fn payload_from_row(&self, row: &store::OperationRow) -> Option<Payload> {
        let parsed: serde_json::Value = serde_json::from_str(&row.request_json).ok()?;
        let arguments = parsed.get("arguments")?.clone();
        let digest = parsed
            .get("arguments_digest")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| Digest::parse(value).ok())?;
        Some(Payload { arguments, digest })
    }

    fn parse_row_ids(
        row: &store::OperationRow,
    ) -> AuthorityResult<(CorrelationId, OperationId, CapsuleId)> {
        let correlation_id = CorrelationId::new(&row.correlation_id).map_err(|error| {
            OperationRejection::Durable(LedgerError::invalid_data_caused_by(
                "invalid correlation id",
                error,
            ))
        })?;
        let operation_id = OperationId::new(&row.operation_id).map_err(|error| {
            OperationRejection::Durable(LedgerError::invalid_data_caused_by(
                "invalid operation id",
                error,
            ))
        })?;
        let capsule_id = CapsuleId::new(&row.capsule_id).map_err(|error| {
            OperationRejection::Durable(LedgerError::invalid_data_caused_by(
                "invalid capsule id",
                error,
            ))
        })?;
        Ok((correlation_id, operation_id, capsule_id))
    }

    pub(super) fn reconcile_row(
        &self,
        row: &store::OperationRow,
        recorded: Option<&RecordedBinding>,
        payload: Option<&Payload>,
        now_ms: u64,
    ) -> AuthorityResult<OperationDecision> {
        let now = utc(now_ms)?;
        let (correlation_id, operation_id, capsule_id) = Self::parse_row_ids(row)?;
        let decision = |state: EffectState, replay: bool| OperationDecision {
            correlation_id: correlation_id.clone(),
            operation_id: operation_id.clone(),
            capsule_id: capsule_id.clone(),
            state,
            replay,
        };
        match row.effect_state {
            EffectState::Committed | EffectState::Aborted => {
                return Ok(decision(row.effect_state, true));
            }
            EffectState::Prepared => {
                // Re-read under lock before aborting: dispatch may have started since the snapshot.
                let mut ledger = self.lock_store()?;
                let (live, _) = self.reread_row(&ledger, row)?;
                if let Some(live) = live {
                    if live.effect_state != EffectState::Prepared {
                        return Ok(decision(live.effect_state, true));
                    }
                }
                if self.is_in_flight(correlation_id.as_str()) {
                    return Ok(decision(EffectState::Prepared, true));
                }
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        &row.correlation_id,
                        EffectState::Prepared,
                        EffectState::Aborted,
                        None,
                        now,
                    )
                })?;
                return Ok(decision(EffectState::Aborted, true));
            }
            EffectState::EffectStarted | EffectState::InDoubt => {}
        }
        // Only live dispatch may settle its effect; observing early could falsely report no output.
        if self.is_in_flight(correlation_id.as_str()) {
            return Ok(decision(row.effect_state, true));
        }

        // Use the recorded execution inputs; missing or altered records cannot be replaced.
        let Some(recorded) = recorded else {
            return Ok(decision(row.effect_state, true));
        };
        let contract = &recorded.contract;
        if !self.catalog.resolves(&contract.handler)
            || !self.catalog.resolves(&contract.evidence_extractor)
        {
            return Ok(decision(row.effect_state, true));
        }
        let Some(payload) = payload else {
            return Ok(decision(row.effect_state, true));
        };
        let reconciliation = Reconciliation::decode(&row.reconciliation_json);
        let Some(expected) = reconciliation.expected_post_world else {
            return Ok(decision(row.effect_state, true));
        };
        let observed = self
            .executor
            .observe(contract, payload)
            .map_err(OperationRejection::Executor)?;
        let next = if observed == PreWorld::Digest(expected) {
            Some(EffectState::Committed)
        } else if observed == reconciliation.pre_world {
            Some(EffectState::Aborted)
        } else {
            None
        };
        let Some(next) = next else {
            return Ok(decision(row.effect_state, true));
        };
        let mut ledger = self.lock_store()?;
        // Revalidate after unlocked observation so stale results cannot overwrite concurrent settlement.
        let (live, valid) = self.reread_row(&ledger, row)?;
        if !valid {
            let state = live
                .map(|live| live.effect_state)
                .unwrap_or(row.effect_state);
            return Ok(decision(state, true));
        }
        // Preserve captured evidence; the predicted post-world hash is not an execution receipt.
        ledger.with_tx(|tx| {
            store::transition_operation(tx, &row.correlation_id, row.effect_state, next, None, now)
        })?;
        Ok(decision(next, true))
    }

    fn reread_row(
        &self,
        ledger: &Ledger,
        snapshot: &store::OperationRow,
    ) -> AuthorityResult<(Option<store::OperationRow>, bool)> {
        let live = store::operation_row(ledger.connection(), &snapshot.correlation_id)?;
        let valid = live.as_ref().is_some_and(|live| {
            live.effect_state == snapshot.effect_state
                && live.binding_digest == snapshot.binding_digest
                && live.request_json == snapshot.request_json
        });
        Ok((live, valid))
    }

    /// Observe without the ledger lock because executor callbacks may re-enter the ledger.
    fn observe_rows(
        &self,
        rows: &[store::OperationRow],
    ) -> AuthorityResult<BTreeMap<String, RowObservation>> {
        let mut observations = BTreeMap::new();
        for row in rows {
            match row.effect_state {
                EffectState::Prepared | EffectState::Committed | EffectState::Aborted => continue,
                EffectState::EffectStarted | EffectState::InDoubt => {}
            }
            if self.is_in_flight(&row.correlation_id) {
                // Live dispatch may still settle this row; observation would race it.
                continue;
            }
            let Some(recorded) = RecordedBinding::parse(row) else {
                continue;
            };
            if recorded.reconciliation.pre_world == PreWorld::Absent
                && recorded.reconciliation.expected_post_world.is_none()
            {
                // Without measurable world state, absence of an effect cannot be established.
                continue;
            }
            if !self.catalog.resolves(&recorded.contract.handler)
                || !self.catalog.resolves(&recorded.contract.evidence_extractor)
            {
                continue;
            }
            let Some(payload) = self.payload_from_row(row) else {
                continue;
            };
            let observed = self
                .executor
                .observe(&recorded.contract, &payload)
                .map_err(OperationRejection::Executor)?;
            observations.insert(
                row.correlation_id.clone(),
                RowObservation {
                    correlation_id: row.correlation_id.clone(),
                    effect_state: row.effect_state,
                    binding_digest: row.binding_digest.clone(),
                    request_json: row.request_json.clone(),
                    observed,
                },
            );
        }
        Ok(observations)
    }

    /// Settle only an unchanged snapshot; `None` leaves the capsule close blocked.
    fn settle_row(
        &self,
        row: &store::OperationRow,
        observation: Option<&RowObservation>,
        mode: CloseMode,
        now_ms: u64,
        ledger: &mut MutexGuard<'_, Ledger>,
    ) -> AuthorityResult<Option<EffectState>> {
        let now = utc(now_ms)?;
        match row.effect_state {
            EffectState::Prepared => {
                let outcome = ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        &row.correlation_id,
                        EffectState::Prepared,
                        EffectState::Aborted,
                        None,
                        now,
                    )
                });
                return match outcome {
                    Ok(_) => Ok(Some(EffectState::Aborted)),
                    Err(LedgerError::InvalidData { .. }) => Ok(None),
                    Err(error) => Err(OperationRejection::Durable(error)),
                };
            }
            EffectState::EffectStarted | EffectState::InDoubt => {
                // Leave live effects unresolved so close cannot race their dispatch settlement.
                if self.is_in_flight(&row.correlation_id) {
                    return Ok(None);
                }
            }
            EffectState::Committed | EffectState::Aborted => return Ok(Some(row.effect_state)),
        }
        // A changed row invalidates the observation, so leave it unresolved.
        let Some(observation) = observation.filter(|observation| observation.matches(row)) else {
            return Ok(None);
        };
        let Some(recorded) = RecordedBinding::parse(row) else {
            return Ok(None);
        };
        let reconciliation = recorded.reconciliation;
        let from = row.effect_state;
        match (observation.observed, reconciliation.expected_post_world) {
            (PreWorld::Digest(actual), Some(expected)) if actual == expected => {
                if mode == CloseMode::Abort {
                    // An effect that provably landed cannot be aborted.
                    return Ok(None);
                }
                // Preserve captured evidence rather than replacing it with the observed world hash.
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        &row.correlation_id,
                        from,
                        EffectState::Committed,
                        None,
                        now,
                    )
                })?;
                Ok(Some(EffectState::Committed))
            }
            (observed, expected)
                if observed == reconciliation.pre_world
                    && (matches!(observed, PreWorld::Digest(_)) || expected.is_some()) =>
            {
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        &row.correlation_id,
                        from,
                        EffectState::Aborted,
                        None,
                        now,
                    )
                })?;
                Ok(Some(EffectState::Aborted))
            }
            _ => Ok(None),
        }
    }
}
