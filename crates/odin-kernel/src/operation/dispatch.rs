//! Register dispatch until durable settlement so concurrent reconciliation cannot settle a live effect.

use std::collections::BTreeSet;
use std::sync::Arc;

use odin_domain::operation::{CapabilityClass, EffectState, Grant};
use odin_domain::EffectClass;
use odin_ledger::operation as store;
use odin_ledger::LedgerError;
use odin_types::{CapsuleLeaseId, CorrelationId, OperationId};

use crate::capability::CapabilityContract;

use super::model::{
    charged_invocation, utc, AuthorityResult, ExecutorFault, InvokeRequest, OperationDecision,
    OperationRejection, Payload, PreparedEffect, PreparedEffectFields, Reconciliation, StopHandle,
    Target,
};
use super::OperationAuthority;

pub(super) struct DispatchPlan {
    pub(super) contract: CapabilityContract,
    pub(super) payload: Payload,
    pub(super) reconciliation: Reconciliation,
    pub(super) timeout_ms: u64,
    pub(super) identity_expires_at_ms: u64,
    pub(super) request_digest: odin_domain::Digest,
    pub(super) operation_id: OperationId,
    pub(super) target: Target,
    pub(super) executor_binding: Option<serde_json::Value>,
    pub(super) now_ms: u64,
}

fn grant_classes(effect_class: EffectClass) -> BTreeSet<CapabilityClass> {
    match effect_class {
        EffectClass::R0 => BTreeSet::from([CapabilityClass::Read]),
        EffectClass::R1 | EffectClass::R2 => BTreeSet::from([CapabilityClass::Write]),
        EffectClass::R3 => BTreeSet::from([CapabilityClass::Execute]),
    }
}

/// Keep the registration through settlement, including a failed prepare commit.
pub(super) struct InFlightRegistration<'a> {
    pub(super) authority: &'a OperationAuthority,
    pub(super) correlation_id: &'a str,
}

impl Drop for InFlightRegistration<'_> {
    fn drop(&mut self) {
        self.authority.unregister_in_flight(self.correlation_id);
    }
}

impl OperationAuthority {
    pub(super) fn dispatch(
        &self,
        request: &InvokeRequest,
        plan: DispatchPlan,
        stop_handle: Arc<StopHandle>,
    ) -> AuthorityResult<OperationDecision> {
        let DispatchPlan {
            contract,
            payload,
            reconciliation,
            timeout_ms,
            identity_expires_at_ms,
            request_digest,
            operation_id,
            target,
            executor_binding,
            now_ms,
        } = plan;
        // Caller ceilings cannot increase the reservation carried by the permit.
        let charged = charged_invocation();
        let grant = Grant::new(
            grant_classes(contract.effect_class),
            charged.stops,
            charged.spend,
        );
        let lease = {
            let ledger = self.lock_store()?;
            store::lease_row(ledger.connection(), request.capsule_id.as_str())?
                .filter(|lease| lease.state == "open")
                .and_then(|lease| CapsuleLeaseId::new(&lease.lease_id).ok())
        };
        let resources = contract
            .adapter
            .iter()
            .map(|adapter| format!("adapter:{adapter}"))
            .collect::<Vec<_>>();
        let effect = PreparedEffect::new(
            request.correlation_id.clone(),
            operation_id.clone(),
            request.capsule_id.clone(),
            self.executor.id(),
            PreparedEffectFields {
                contract,
                payload,
                target,
                executor_binding,
                pre_world: reconciliation.pre_world,
                grant,
                resources,
                lease,
                expires_at_ms: now_ms.saturating_add(timeout_ms),
                reconciliation,
            },
            stop_handle,
        )
        .with_child_custody_context(
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
            identity_expires_at_ms,
            request_digest,
        );

        // Persist EffectStarted before dispatch so crashes cannot cause silent effect replay.
        let now = utc(now_ms)?;
        {
            let mut ledger = self.lock_store()?;
            let lease_open = store::lease_row(ledger.connection(), request.capsule_id.as_str())?
                .map(|lease| lease.state == "open")
                .unwrap_or(false);
            if !lease_open {
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        request.correlation_id.as_str(),
                        EffectState::Prepared,
                        EffectState::Aborted,
                        None,
                        now,
                    )
                })?;
                drop(ledger);
                return Err(OperationRejection::CapsuleClosed {
                    capsule_id: request.capsule_id.clone(),
                });
            }
            let pending_stops =
                store::stop_intents_for_operation(ledger.connection(), operation_id.as_str())?;
            if !pending_stops.is_empty() {
                // A capsule-wide stop stays pending while any sibling operation remains nonterminal.
                let capsule_pending_excl_self =
                    odin_ledger::operation::capsule_wide_stop_may_settle_excluding(
                        ledger.connection(),
                        request.capsule_id.as_str(),
                        request.correlation_id.as_str(),
                    )?;
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        request.correlation_id.as_str(),
                        EffectState::Prepared,
                        EffectState::Aborted,
                        None,
                        now,
                    )?;
                    for row in &pending_stops {
                        if row.operation_id.is_some() {
                            store::settle_stop(
                                tx,
                                &row.correlation_id,
                                "stopped",
                                r#"{"pre_effect":true}"#,
                                now,
                            )?;
                        } else if capsule_pending_excl_self {
                            store::settle_stop(
                                tx,
                                &row.correlation_id,
                                "stopped",
                                r#"{"pre_effect":true,"capsule_wide":true}"#,
                                now,
                            )?;
                        }
                    }
                    Ok(())
                })?;
                drop(ledger);
                return Err(OperationRejection::Executor(ExecutorFault::Rejected {
                    detail: "stop intent recorded before the effect started".to_owned(),
                }));
            }
            ledger.with_tx(|tx| {
                store::transition_operation(
                    tx,
                    request.correlation_id.as_str(),
                    EffectState::Prepared,
                    EffectState::EffectStarted,
                    None,
                    now,
                )
            })?;
        }

        let executed = self.executor.execute(effect);
        match executed {
            Ok(outcome) => {
                // Resolve stops by operation ID; their correlation IDs identify different journal rows.
                let stop_correlations: Vec<(CorrelationId, bool)> = {
                    let ledger = self.lock_store()?;
                    store::stop_intents_for_operation(ledger.connection(), operation_id.as_str())?
                        .into_iter()
                        .filter(|row| row.state == "requested")
                        .map(|row| {
                            let capsule_wide = row.operation_id.is_none();
                            let correlation =
                                CorrelationId::new(&row.correlation_id).map_err(|error| {
                                    OperationRejection::Durable(
                                        LedgerError::invalid_data_caused_by(
                                            "invalid stop correlation id",
                                            error,
                                        ),
                                    )
                                })?;
                            Ok((correlation, capsule_wide))
                        })
                        .collect::<Result<Vec<_>, OperationRejection>>()?
                };
                // Transition first so the capsule-wide stop check sees this row as terminal.
                let mut ledger = self.lock_store()?;
                let evidence = Some(outcome.evidence_digest.to_string());
                let next = match (reconciliation.expected_post_world, outcome.post_world) {
                    (Some(expected), Some(actual)) if actual == expected => EffectState::Committed,
                    (Some(_), Some(_)) | (Some(_), None) => {
                        // A post-image mismatch cannot justify successful settlement.
                        EffectState::InDoubt
                    }
                    (None, _) => EffectState::Committed,
                };
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        request.correlation_id.as_str(),
                        EffectState::EffectStarted,
                        next,
                        evidence.as_deref(),
                        now,
                    )
                })?;
                for (stop_correlation_id, capsule_wide) in &stop_correlations {
                    if *capsule_wide {
                        let may = odin_ledger::operation::capsule_wide_stop_may_settle(
                            ledger.connection(),
                            request.capsule_id.as_str(),
                        )?;
                        if !may {
                            continue;
                        }
                    }
                    if let Some(stop) = outcome.stop.as_ref() {
                        let stop_now = utc(self.now_ms())?;
                        let state = if stop.stopped { "stopped" } else { "failed" };
                        let stop_evidence = serde_json::json!({
                            "process": stop.process,
                            "survivors": stop.survivors,
                        })
                        .to_string();
                        ledger.with_tx(|tx| {
                            store::settle_stop(
                                tx,
                                stop_correlation_id.as_str(),
                                state,
                                &stop_evidence,
                                stop_now,
                            )?;
                            Ok(())
                        })?;
                    }
                }
                drop(ledger);
                Ok(OperationDecision {
                    correlation_id: request.correlation_id.clone(),
                    operation_id,
                    capsule_id: request.capsule_id.clone(),
                    state: next,
                    replay: false,
                })
            }
            Err(ExecutorFault::Rejected { detail }) => {
                let mut ledger = self.lock_store()?;
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        request.correlation_id.as_str(),
                        EffectState::EffectStarted,
                        EffectState::Aborted,
                        None,
                        now,
                    )
                })?;
                Err(OperationRejection::Executor(ExecutorFault::Rejected {
                    detail,
                }))
            }
            Err(
                fault @ (ExecutorFault::Uncertain { .. }
                | ExecutorFault::PostEffectUncertain { .. }),
            ) => {
                // Save captured evidence atomically with uncertainty; pre-output failures have none.
                let captured_evidence = match &fault {
                    ExecutorFault::PostEffectUncertain {
                        evidence_digest, ..
                    } => Some(evidence_digest.to_string()),
                    _ => None,
                };
                let mut ledger = self.lock_store()?;
                ledger.with_tx(|tx| {
                    store::transition_operation(
                        tx,
                        request.correlation_id.as_str(),
                        EffectState::EffectStarted,
                        EffectState::InDoubt,
                        captured_evidence.as_deref(),
                        now,
                    )
                })?;
                Err(OperationRejection::Executor(fault))
            }
        }
    }

    /// Live dispatch alone may settle its effect; concurrent observations could precede its output.
    pub(super) fn is_in_flight(&self, correlation_id: &str) -> bool {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(correlation_id)
    }

    pub(super) fn register_in_flight(&self, correlation_id: &str) -> Arc<StopHandle> {
        let handle = Arc::new(StopHandle::default());
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(correlation_id.to_owned(), Arc::clone(&handle));
        handle
    }

    fn unregister_in_flight(&self, correlation_id: &str) {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(correlation_id);
    }
}
