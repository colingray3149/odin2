//! Prepare and charge atomically; duplicate correlations must match the complete original request.

use std::sync::Arc;

use odin_domain::knowledge::ToolSchema;
use odin_domain::operation::{EffectState, RequestCost, Usage};
use odin_domain::{CapabilityId, Digest};
use odin_ledger::operation as store;
use odin_ledger::LedgerError;
use odin_types::{CapsuleId, CorrelationId, OperationId};

use crate::capability::{AuthorizedInvocation, CapabilityContract, HandlerBinding};
use crate::token::{FreshAuthority, SeatAuthority};

use super::dispatch::{DispatchPlan, InFlightRegistration};
use super::model::{
    charged_invocation, utc, validate_input_payload, AuthorityResult, InvokeRequest,
    OperationDecision, OperationRejection, Payload, PreWorld, PreWorldRecord, PreparedBinding,
    Reconciliation, RecordedBinding, Step, StopHandle, Target,
};
use super::OperationAuthority;

/// Retain the admitted snapshot revision and digest to prevent contract substitution.
#[derive(Clone, Debug)]
pub struct AdmittedCapability {
    pub contract: CapabilityContract,
    pub snapshot_revision: i64,
    pub snapshot_digest: Digest,
}

/// Catalog resolution supplies contracts, not authorization.
pub trait OperationCatalog: Send + Sync {
    fn admitted(&self, capability: &CapabilityId) -> Option<AdmittedCapability>;

    fn resolves(&self, binding: &HandlerBinding) -> bool;

    /// Operator-only capabilities are published but do not require a kernel dispatch handler.
    fn is_operator_owned(&self, _capability: &CapabilityId) -> bool {
        false
    }

    /// Hosts may accept composition-identical revisions while still requiring exact contract equality.
    fn admits_policy_digest(&self, admitted: &AdmittedCapability, digest: Digest) -> bool {
        admitted.snapshot_digest == digest
    }
}

enum Prepared<'a> {
    Fresh {
        operation_id: OperationId,
        stop_handle: Arc<StopHandle>,
        registration: InFlightRegistration<'a>,
    },
    Replayed(Box<store::OperationRow>),
}

impl OperationAuthority {
    /// Started operations without outcomes become in-doubt so recovery cannot replay their effects.
    pub fn recover(&self) -> AuthorityResult<u64> {
        let now = utc(self.now_ms())?;
        let mut ledger = self.lock_store()?;
        let mut recovered = 0_u64;
        ledger.with_tx(|tx| {
            for row in store::nonterminal_rows(tx, None)? {
                if row.effect_state == EffectState::EffectStarted {
                    store::transition_operation(
                        tx,
                        &row.correlation_id,
                        EffectState::EffectStarted,
                        EffectState::InDoubt,
                        None,
                        now,
                    )?;
                    recovered += 1;
                }
            }
            Ok(())
        })?;
        Ok(recovered)
    }

    pub fn invoke_authorized(
        &self,
        authorized: AuthorizedInvocation,
        request: &InvokeRequest,
    ) -> AuthorityResult<OperationDecision> {
        let now_ms = self.now_ms();
        let authority = authorized.authority();
        self.check_authority(authority, now_ms)?;
        let invocation = authorized.invocation();
        let contract = authorized.contract().clone();
        let capability = contract.id.to_string();
        let admitted = self.catalog.admitted(&contract.id).ok_or_else(|| {
            OperationRejection::UnknownCapability {
                capability: capability.clone(),
            }
        })?;
        if !self
            .catalog
            .admits_policy_digest(&admitted, authority.capability_policy_digest())
        {
            return Err(OperationRejection::NotAdmitted {
                capability: capability.clone(),
                detail: format!(
                    "admission snapshot {} does not match the authorized policy digest {}",
                    admitted.snapshot_digest,
                    authority.capability_policy_digest()
                ),
            });
        }
        if admitted.contract != contract {
            return Err(OperationRejection::NotAdmitted {
                capability: capability.clone(),
                detail: "authorized contract tuple differs from the admitted snapshot".to_owned(),
            });
        }
        if !self.catalog.resolves(&contract.handler)
            || !self.catalog.resolves(&contract.evidence_extractor)
        {
            return Err(OperationRejection::NotAdmitted {
                capability: capability.clone(),
                detail: "handler or evidence extractor binding is not registered".to_owned(),
            });
        }

        let schema = self
            .schemas
            .schema(&contract.input_schema_ref)
            .map_err(|error| OperationRejection::NotAdmitted {
                capability: capability.clone(),
                detail: format!("input schema unavailable: {error}"),
            })?;
        let payload = Payload::from_arguments(&invocation.arguments);
        self.validate_payload(&schema, &payload)?;
        if !contract.arguments_bind_declared_target(&payload.arguments) {
            return Err(OperationRejection::SchemaInvalid {
                detail: "canonical delegation target differs from the admitted contract".to_owned(),
            });
        }
        if payload.digest != invocation.arguments_digest {
            return Err(OperationRejection::PayloadDigestMismatch);
        }

        // Caller ceilings can restrict the reservation, never increase it.
        let charged = charged_invocation();
        if request.requested_ceiling.requests < charged.requests
            || request.requested_ceiling.stops < charged.stops
            || request.requested_ceiling.spend < charged.spend
        {
            return Err(OperationRejection::BudgetDenied {
                detail: format!(
                    "requested ceiling ({}, {}, {}) denies the authority reservation (1, 0, 0)",
                    request.requested_ceiling.requests,
                    request.requested_ceiling.stops,
                    request.requested_ceiling.spend
                ),
            });
        }
        let request_digest = self.request_digest(
            request,
            charged,
            payload.digest,
            invocation.executor_binding.as_ref(),
            authority,
        );
        let request_json = self.request_json(invocation, &payload, request.requested_ceiling);
        let now = utc(now_ms)?;

        // Resolve replays before mutable world observations can change their admission.
        let existing = {
            let ledger = self.lock_store()?;
            store::operation_row(ledger.connection(), request.correlation_id.as_str())?
        };
        // Release the store lock before reconciliation, which reacquires and revalidates the row.
        if let Some(row) = existing {
            let identical = Self::is_exact_replay(
                &row,
                request,
                &request_digest.to_string(),
                &request_json,
                authority,
                &invocation.listing_digest.to_string(),
                capability.as_str(),
            );
            if identical {
                return self.drive_existing(row, now_ms);
            }
            return Err(OperationRejection::DuplicateConflict {
                correlation_id: request.correlation_id.clone(),
            });
        }

        // Reject pre-image mismatches before persisting an incomplete operation.
        let reconciliation = self.reconciliation_for(&contract, &payload)?;

        let prepared = {
            let mut ledger = self.lock_store()?;
            let step = ledger.with_tx(|tx| {
                // Another request may have inserted this correlation since the lookup.
                if let Some(row) = store::operation_row(tx, request.correlation_id.as_str())? {
                    let identical = Self::is_exact_replay(
                        &row,
                        request,
                        &request_digest.to_string(),
                        &request_json,
                        authority,
                        &invocation.listing_digest.to_string(),
                        capability.as_str(),
                    );
                    if identical {
                        return Ok(Step::Done(Prepared::Replayed(Box::new(row))));
                    }
                    return Ok(Step::Reject(OperationRejection::DuplicateConflict {
                        correlation_id: request.correlation_id.clone(),
                    }));
                }
                // Charge atomically with prepare so concurrent requests cannot spend the same budget.
                let usage = store::usage(tx, authority.session().as_str())?;
                if let Err(error) = self.limits.apply(
                    Usage {
                        requests: usage.requests,
                        stops: usage.stops,
                        spend: usage.spend,
                    },
                    charged,
                ) {
                    return Ok(Step::Reject(OperationRejection::BudgetDenied {
                        detail: error.to_string(),
                    }));
                }
                let lease_id = Self::mint_lease_id(&request.capsule_id, authority);
                if let Err(error) = store::open_lease(
                    tx,
                    request.capsule_id.as_str(),
                    &store::LeaseAuthority {
                        seat_id: authority.seat().as_str(),
                        token_id: authority.token_id().as_str(),
                        session_id: authority.session().as_str(),
                        policy_digest: &authority.capability_policy_digest().to_string(),
                        listing_digest: &invocation.listing_digest.to_string(),
                        token_issued_at_ms: authority.issued_at_ms(),
                    },
                    &lease_id,
                    now,
                ) {
                    return match error {
                        LedgerError::LeaseClosed { capsule_id } => {
                            let capsule_id = CapsuleId::new(&capsule_id).map_err(|error| {
                                LedgerError::invalid_data_caused_by("invalid capsule id", error)
                            })?;
                            Ok(Step::Reject(OperationRejection::CapsuleClosed {
                                capsule_id,
                            }))
                        }
                        LedgerError::LeaseAuthorityMismatch { capsule_id, .. } => {
                            let capsule_id = CapsuleId::new(&capsule_id).map_err(|error| {
                                LedgerError::invalid_data_caused_by("invalid capsule id", error)
                            })?;
                            Ok(Step::Reject(OperationRejection::CapsuleAuthorityMismatch {
                                capsule_id,
                            }))
                        }
                        // Unresolved effects prevent lease rotation.
                        LedgerError::LeaseRebindBlocked {
                            capsule_id,
                            pending,
                        } => {
                            let capsule_id = CapsuleId::new(&capsule_id).map_err(|error| {
                                LedgerError::invalid_data_caused_by("invalid capsule id", error)
                            })?;
                            let blocked = u64::try_from(pending).map_err(|error| {
                                LedgerError::invalid_data_caused_by(
                                    "negative unresolved operation count",
                                    error,
                                )
                            })?;
                            Ok(Step::Reject(OperationRejection::CapsuleBlocked {
                                capsule_id,
                                blocked,
                            }))
                        }
                        other => Err(other),
                    };
                }
                let binding = PreparedBinding {
                    contract: contract.clone(),
                    executor_id: self.executor.id().to_owned(),
                    handler_key: contract.handler.canonical_key(),
                    extractor_key: contract.evidence_extractor.canonical_key(),
                    target: Target {
                        kind: invocation.target.kind.clone(),
                        id: invocation.target.id.clone(),
                    },
                    executor_binding: invocation.executor_binding.clone(),
                    pre_world: PreWorldRecord {
                        absent: reconciliation.pre_world == PreWorld::Absent,
                        digest: reconciliation.pre_world.encode(),
                    },
                    expected_post_world: reconciliation
                        .expected_post_world
                        .map(|digest| digest.to_string()),
                    lease: Some(
                        store::lease_row(tx, request.capsule_id.as_str())?
                            .ok_or_else(|| {
                                LedgerError::invalid_data("opened lease missing".to_owned())
                            })?
                            .lease_id,
                    ),
                    expires_at_ms: now_ms
                        .saturating_add(u64::from(contract.timeout_seconds.get()) * 1_000),
                    snapshot_revision: admitted.snapshot_revision,
                    snapshot_digest: admitted.snapshot_digest.to_string(),
                };
                let binding_json = serde_json::to_string(&binding).map_err(|error| {
                    LedgerError::invalid_data_caused_by("binding serialization", error)
                })?;
                let binding_digest = Digest::hash(binding_json.as_bytes()).to_string();
                let new = store::NewOperation {
                    capsule_id: request.capsule_id.as_str(),
                    seat_id: authority.seat().as_str(),
                    token_id: authority.token_id().as_str(),
                    session_id: authority.session().as_str(),
                    policy_digest: &authority.capability_policy_digest().to_string(),
                    listing_digest: &invocation.listing_digest.to_string(),
                    executor_id: self.executor.id(),
                    prepared_binding: &binding_json,
                    binding_digest: &binding_digest,
                    correlation_id: request.correlation_id.as_str(),
                    capability: contract.id.as_str(),
                    request_digest: &request_digest.to_string(),
                    request_json: &request_json,
                    reconciliation_json: &reconciliation.encode(),
                    now,
                };
                match store::prepare_operation(tx, &new) {
                    Ok(store::PrepareOutcome::Prepared { operation_id }) => {
                        store::bump_usage(
                            tx,
                            authority.session().as_str(),
                            charged.requests,
                            charged.stops,
                            charged.spend,
                            now,
                        )?;
                        let operation_id = OperationId::new(&operation_id).map_err(|error| {
                            LedgerError::invalid_data_caused_by("invalid operation id", error)
                        })?;
                        // The live owner must exist before Prepared becomes visible.
                        let stop_handle = self.register_in_flight(request.correlation_id.as_str());
                        Ok(Step::Done(Prepared::Fresh {
                            operation_id,
                            stop_handle,
                            registration: InFlightRegistration {
                                authority: self,
                                correlation_id: request.correlation_id.as_str(),
                            },
                        }))
                    }
                    Ok(store::PrepareOutcome::Replay { row }) => {
                        Ok(Step::Done(Prepared::Replayed(row)))
                    }
                    Err(LedgerError::Conflict(_)) => {
                        Ok(Step::Reject(OperationRejection::DuplicateConflict {
                            correlation_id: request.correlation_id.clone(),
                        }))
                    }
                    Err(error) => Err(error),
                }
            })?;
            step.into_result()?
        };

        match prepared {
            Prepared::Replayed(row) => {
                self.assert_row_authority(&row, authority)?;
                if row.capsule_id != request.capsule_id.as_str() {
                    return Err(OperationRejection::DuplicateConflict {
                        correlation_id: request.correlation_id.clone(),
                    });
                }
                self.drive_existing(*row, now_ms)
            }
            Prepared::Fresh {
                operation_id,
                stop_handle,
                registration,
            } => {
                let timeout_ms = u64::from(contract.timeout_seconds.get().saturating_mul(1_000));
                let target = Target {
                    kind: invocation.target.kind.clone(),
                    id: invocation.target.id.clone(),
                };
                let outcome = self.dispatch(
                    request,
                    DispatchPlan {
                        contract,
                        payload,
                        reconciliation,
                        timeout_ms,
                        operation_id,
                        target,
                        executor_binding: invocation.executor_binding.clone(),
                        now_ms,
                        identity_expires_at_ms: authority.expires_at_ms(),
                        request_digest,
                    },
                    stop_handle,
                );
                drop(registration);
                outcome
            }
        }
    }

    /// Require the original seat, token, session, and policy digest without replaying the effect.
    pub fn resume(
        &self,
        fresh: FreshAuthority,
        capsule_id: &CapsuleId,
        correlation_id: &CorrelationId,
        operation_id: &OperationId,
    ) -> AuthorityResult<OperationDecision> {
        let now_ms = self.now_ms();
        let row = self.bound_row(
            fresh.get(),
            capsule_id,
            correlation_id,
            operation_id,
            now_ms,
        )?;
        self.drive_existing(row, now_ms)
    }

    fn validate_payload(&self, schema: &ToolSchema, payload: &Payload) -> AuthorityResult<()> {
        validate_input_payload(schema, payload)
    }

    pub(super) fn request_digest(
        &self,
        request: &InvokeRequest,
        charged: RequestCost,
        arguments_digest: Digest,
        executor_binding: Option<&serde_json::Value>,
        authority: &SeatAuthority,
    ) -> Digest {
        let mut material = serde_json::json!({
            "capsule_id": request.capsule_id.as_str(),
            "correlation_id": request.correlation_id.as_str(),
            "charged": {
                "requests": charged.requests,
                "stops": charged.stops,
                "spend": charged.spend,
            },
            "requested_ceiling": {
                "requests": request.requested_ceiling.requests,
                "stops": request.requested_ceiling.stops,
                "spend": request.requested_ceiling.spend,
            },
            "seat": authority.seat().as_str(),
            "token": authority.token_id().as_str(),
            "session": authority.session().as_str(),
            "policy_digest": authority.capability_policy_digest().to_string(),
            "arguments_digest": arguments_digest.to_string(),
        });
        if let Some(executor_binding) = executor_binding {
            material
                .as_object_mut()
                .expect("request digest material is an object")
                .insert("executor_binding".to_owned(), executor_binding.clone());
        }
        Digest::hash(material.to_string().as_bytes())
    }

    pub(super) fn request_json(
        &self,
        invocation: &crate::capability::ToolInvocation,
        payload: &Payload,
        requested_ceiling: RequestCost,
    ) -> String {
        let mut request = serde_json::json!({
            "arguments": payload.arguments,
            "arguments_digest": payload.digest.to_string(),
            "command_id": invocation.command_id.as_str(),
            "target": invocation.target,
            "requested_ceiling": {
                "requests": requested_ceiling.requests,
                "stops": requested_ceiling.stops,
                "spend": requested_ceiling.spend,
            },
        });
        if let Some(executor_binding) = &invocation.executor_binding {
            request
                .as_object_mut()
                .expect("operation request is an object")
                .insert("executor_binding".to_owned(), executor_binding.clone());
        }
        request.to_string()
    }

    fn mint_lease_id(capsule_id: &CapsuleId, authority: &SeatAuthority) -> String {
        let digest = Digest::hash(
            format!(
                "odin.capsule_lease.v1\0{}\0{}",
                authority.session().as_str(),
                capsule_id.as_str()
            )
            .as_bytes(),
        );
        let hex = digest.to_string();
        let hex = hex.trim_start_matches("blake3:");
        format!("lease-{}", hex.get(..32).unwrap_or(hex))
    }

    fn is_exact_replay(
        row: &store::OperationRow,
        request: &InvokeRequest,
        request_digest: &str,
        request_json: &str,
        authority: &SeatAuthority,
        listing_digest: &str,
        capability: &str,
    ) -> bool {
        row.request_digest == request_digest
            && row.request_json == request_json
            && row.capsule_id == request.capsule_id.as_str()
            && row.seat_id == authority.seat().as_str()
            && row.token_id == authority.token_id().as_str()
            && row.session_id == authority.session().as_str()
            && row.policy_digest == authority.capability_policy_digest().to_string()
            && row.listing_digest == listing_digest
            && row.capability == capability
    }

    fn assert_row_authority(
        &self,
        row: &store::OperationRow,
        authority: &SeatAuthority,
    ) -> AuthorityResult<()> {
        if row.seat_id != authority.seat().as_str()
            || row.token_id != authority.token_id().as_str()
            || row.session_id != authority.session().as_str()
        {
            let correlation_id = CorrelationId::new(&row.correlation_id).map_err(|error| {
                OperationRejection::Durable(LedgerError::invalid_data_caused_by(
                    "invalid correlation id",
                    error,
                ))
            })?;
            return Err(OperationRejection::AuthorityMismatch { correlation_id });
        }
        Ok(())
    }

    /// Observe and validate the pre-image before prepare so mismatches leave no durable row.
    pub(super) fn reconciliation_for(
        &self,
        contract: &CapabilityContract,
        payload: &Payload,
    ) -> AuthorityResult<Reconciliation> {
        let declared = self
            .executor
            .declared_pre_world(contract, payload)
            .map_err(OperationRejection::Executor)?;
        let observed = self
            .executor
            .observe(contract, payload)
            .map_err(OperationRejection::Executor)?;
        if let Some(expected) = declared {
            if observed != expected {
                return Err(OperationRejection::PreWorldMismatch {
                    detail: format!(
                        "declared pre-world {:?} does not match the observed world {:?}",
                        expected.encode(),
                        observed.encode()
                    ),
                });
            }
        }
        let expected_post_world = self
            .executor
            .expected_post_world(contract, payload)
            .map_err(OperationRejection::Executor)?;
        Ok(Reconciliation {
            pre_world: observed,
            expected_post_world,
        })
    }

    fn drive_existing(
        &self,
        row: store::OperationRow,
        now_ms: u64,
    ) -> AuthorityResult<OperationDecision> {
        let payload = self.payload_from_row(&row);
        let recorded = RecordedBinding::parse(&row);
        self.reconcile_row(&row, recorded.as_ref(), payload.as_ref(), now_ms)
    }
}
