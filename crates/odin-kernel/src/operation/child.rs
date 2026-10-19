//! Child effects retain the original lease and registered target so later requests cannot widen access.

use std::sync::{Arc, Mutex};

use odin_domain::operation::{CapabilityClass, EffectState};
use odin_domain::Digest;
use odin_ledger::{operation as store, Ledger, LedgerError};
use odin_types::CorrelationId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use super::{Clock, PreparedBinding, PreparedEffect, RecordedBinding, Target};

const REGISTRATION: &str = "odin.child.registration.v1";
const REQUEST: &str = "odin.child.request.v1";

pub struct ChildEffectRequest {
    pub correlation_id: CorrelationId,
    pub target: Target,
    pub arguments: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    parent_operation: String,
    parent_binding: String,
    parent_request: String,
    lease: String,
    expires_at_ms: u64,
    target: Target,
}

/// Clones share the same durable replay barrier.
#[derive(Clone)]
pub struct ChildEffectGrant {
    store: Arc<Mutex<Ledger>>,
    clock: Clock,
    registration_id: String,
    target: Target,
}

fn refused(reason: &str) -> LedgerError {
    LedgerError::Conflict(format!("child effect refused: {reason}"))
}

fn timestamp(ms: u64) -> Result<OffsetDateTime, LedgerError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).map_err(|error| {
        LedgerError::invalid_data_caused_by("operation timestamp is out of range", error)
    })
}

fn valid_lease(parent: &store::OperationRow, lease: &store::CapsuleLeaseRow, id: &str) -> bool {
    lease.state == "open"
        && lease.lease_id == id
        && lease.capsule_id == parent.capsule_id
        && lease.seat_id == parent.seat_id
        && lease.token_id == parent.token_id
        && lease.session_id == parent.session_id
        && lease.policy_digest == parent.policy_digest
        && lease.listing_digest == parent.listing_digest
}

fn new_row<'a>(
    parent: &'a store::OperationRow,
    correlation: &'a str,
    kind: &'a str,
    request: &'a str,
    digest: &'a str,
    now: OffsetDateTime,
) -> store::NewOperation<'a> {
    store::NewOperation {
        capsule_id: &parent.capsule_id,
        seat_id: &parent.seat_id,
        token_id: &parent.token_id,
        session_id: &parent.session_id,
        policy_digest: &parent.policy_digest,
        listing_digest: &parent.listing_digest,
        // A child is not a replayable invocation of the parent's handler.
        executor_id: &parent.executor_id,
        prepared_binding: request,
        binding_digest: digest,
        correlation_id: correlation,
        capability: kind,
        request_digest: digest,
        request_json: request,
        reconciliation_json: store::RECONCILIATION_UNRESOLVABLE,
        now,
    }
}

impl ChildEffectGrant {
    /// Derive the target from the validated execution context, not later worker requests.
    pub fn from_prepared(parent: &PreparedEffect, target: Target) -> Result<Self, LedgerError> {
        let (store, clock, expires_at_ms, request_digest) = parent
            .child_custody_context()
            .ok_or_else(|| refused("permit has no live custody context"))?;
        if parent.executor_id() != PreparedEffect::OMP_HOST_EXECUTOR
            || !parent.grant().allows(CapabilityClass::Write)
            || !matches!(
                parent.contract().effect_class,
                odin_domain::EffectClass::R2 | odin_domain::EffectClass::R3
            )
            || parent.stop_handle().is_cancelled()
        {
            return Err(refused("parent cannot delegate writes"));
        }
        let now_ms = clock();
        if now_ms >= expires_at_ms || now_ms >= parent.expires_at_ms() {
            return Err(refused("parent expired"));
        }
        let lease_id = parent
            .lease()
            .ok_or_else(|| refused("parent has no lease"))?;
        let mut ledger = store.lock().map_err(|_| refused("store poisoned"))?;
        let registration_id = ledger.with_tx(|tx| {
            let row = store::operation_row_by_id(tx, parent.operation_id().as_str())?
                .ok_or_else(|| refused("parent missing"))?;
            let binding: PreparedBinding = serde_json::from_str(&row.prepared_binding)
                .map_err(|_| refused("invalid parent binding"))?;
            let request: Value = serde_json::from_str(&row.request_json)
                .map_err(|_| refused("invalid parent request"))?;
            if RecordedBinding::parse(&row).is_none()
                || row.effect_state != EffectState::EffectStarted
                || row.correlation_id != parent.correlation_id().as_str()
                || row.capsule_id != parent.capsule_id().as_str()
                || row.executor_id != parent.executor_id()
                || row.capability != parent.contract().id.as_str()
                || row.request_digest != request_digest.to_string()
                || request.get("arguments") != Some(&parent.payload().arguments)
                || request.get("arguments_digest").and_then(Value::as_str)
                    != Some(parent.payload().digest.to_string().as_str())
                || binding.target != *parent.target()
                || binding.executor_binding.as_ref() != parent.executor_binding()
                || binding.lease.as_deref() != Some(lease_id.as_str())
            {
                return Err(refused("parent permit mismatch"));
            }
            if crate::token::ledger_token_is_revoked(tx, &row.token_id)? {
                return Err(refused("original token revoked"));
            }
            let lease =
                store::lease_row(tx, &row.capsule_id)?.ok_or_else(|| refused("lease missing"))?;
            if !valid_lease(&row, &lease, lease_id.as_str()) {
                return Err(refused("lease closed or rebound"));
            }
            let registration = Registration {
                parent_operation: row.operation_id.clone(),
                parent_binding: row.binding_digest.clone(),
                parent_request: row.request_digest.clone(),
                lease: lease_id.as_str().to_owned(),
                expires_at_ms,
                target: target.clone(),
            };
            let request = serde_json::to_string(&registration).map_err(|error| {
                LedgerError::invalid_data_caused_by("child registration serialization", error)
            })?;
            let digest = Digest::hash(request.as_bytes()).to_string();
            // One registration per parent: no later target substitution.
            let correlation = format!("child-registration:{}", row.operation_id);
            let now = timestamp(now_ms)?;
            match store::prepare_operation(
                tx,
                &new_row(&row, &correlation, REGISTRATION, &request, &digest, now),
            )? {
                store::PrepareOutcome::Prepared { .. } => {}
                store::PrepareOutcome::Replay { .. } => return Err(refused("registration replay")),
            }
            store::transition_operation(
                tx,
                &correlation,
                EffectState::Prepared,
                EffectState::EffectStarted,
                None,
                now,
            )?;
            store::transition_operation(
                tx,
                &correlation,
                EffectState::EffectStarted,
                EffectState::Committed,
                Some(&digest),
                now,
            )?;
            Ok(correlation)
        })?;
        drop(ledger);
        Ok(Self {
            store,
            clock,
            registration_id,
            target,
        })
    }

    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }
    pub fn target(&self) -> &Target {
        &self.target
    }

    /// Recover the journaled registration without accepting replacement scope or identity.
    pub fn recover(
        store: Arc<Mutex<Ledger>>,
        clock: Clock,
        registration_id: &str,
    ) -> Result<Self, LedgerError> {
        let mut ledger = store.lock().map_err(|_| refused("store poisoned"))?;
        let target = ledger.with_tx(|tx| {
            let (_, registration) = load_registration(tx, registration_id, clock())?;
            Ok(registration.target)
        })?;
        drop(ledger);
        Ok(Self {
            store,
            clock,
            registration_id: registration_id.to_owned(),
            target,
        })
    }

    /// Failure leaves the request in-doubt; it does not permit retrying the closure.
    pub fn run(
        &self,
        request: ChildEffectRequest,
        effect: impl FnOnce() -> Result<Value, String>,
    ) -> Result<Value, LedgerError> {
        if request.target != self.target {
            return Err(refused("target mismatch"));
        }
        let request_json = serde_json::json!({
            "registration": self.registration_id, "target": request.target,
            "arguments": request.arguments,
        })
        .to_string();
        let digest = Digest::hash(request_json.as_bytes()).to_string();
        let correlation = format!(
            "child-request:{}:{}",
            self.registration_id,
            request.correlation_id.as_str()
        );
        let replay = {
            let mut ledger = self.store.lock().map_err(|_| refused("store poisoned"))?;
            ledger.with_tx(|tx| {
                let now_ms = (self.clock)();
                let (parent, registration) = load_registration(tx, &self.registration_id, now_ms)?;
                if registration.target != self.target {
                    return Err(refused("registration changed"));
                }
                let now = timestamp(now_ms)?;
                match store::prepare_operation(
                    tx,
                    &new_row(&parent, &correlation, REQUEST, &request_json, &digest, now),
                )? {
                    store::PrepareOutcome::Prepared { .. } => {}
                    store::PrepareOutcome::Replay { row } => {
                        if row.effect_state != EffectState::Committed {
                            return Err(refused("request replay is unresolved"));
                        }
                        let saved =
                            store::operation_row(tx, &format!("child-result:{correlation}"))?
                                .ok_or_else(|| refused("committed result missing"))?;
                        let result_digest = Digest::hash(saved.request_json.as_bytes()).to_string();
                        if saved.capability != "odin.child.result.v1"
                            || saved.effect_state != EffectState::Committed
                            || saved.request_digest != result_digest
                            || saved.evidence_digest.as_deref() != Some(result_digest.as_str())
                            || row.evidence_digest.as_deref() != Some(result_digest.as_str())
                            || saved.prepared_binding != saved.request_json
                            || saved.binding_digest != result_digest
                            || saved.capsule_id != row.capsule_id
                            || saved.token_id != row.token_id
                            || saved.session_id != row.session_id
                        {
                            return Err(refused("committed result mismatch"));
                        }
                        let result: Result<Value, String> =
                            serde_json::from_str(&saved.request_json)
                                .map_err(|_| refused("invalid committed result"))?;
                        return result
                            .map(Some)
                            .map_err(|_| refused("committed result is failure"));
                    }
                }
                store::transition_operation(
                    tx,
                    &correlation,
                    EffectState::Prepared,
                    EffectState::EffectStarted,
                    None,
                    now,
                )?;
                Ok(None)
            })?
        };
        if let Some(result) = replay {
            return Ok(result);
        }
        let result = effect();
        let evidence = serde_json::to_string(&result).map_err(|error| {
            LedgerError::invalid_data_caused_by("child effect evidence serialization", error)
        })?;
        let digest = Digest::hash(evidence.as_bytes()).to_string();
        let mut ledger = self.store.lock().map_err(|_| refused("store poisoned"))?;
        ledger.with_tx(|tx| {
            let row = store::operation_row(tx, &correlation)?
                .ok_or_else(|| refused("started request missing"))?;
            let result_id = format!("child-result:{correlation}");
            let now = timestamp((self.clock)())?;
            match store::prepare_operation(
                tx,
                &new_row(
                    &row,
                    &result_id,
                    "odin.child.result.v1",
                    &evidence,
                    &digest,
                    now,
                ),
            )? {
                store::PrepareOutcome::Prepared { .. } => {}
                store::PrepareOutcome::Replay { .. } => {
                    return Err(refused("result already recorded"))
                }
            }
            store::transition_operation(
                tx,
                &result_id,
                EffectState::Prepared,
                EffectState::EffectStarted,
                None,
                now,
            )?;
            store::transition_operation(
                tx,
                &result_id,
                EffectState::EffectStarted,
                EffectState::Committed,
                Some(&digest),
                now,
            )?;
            store::transition_operation(
                tx,
                &correlation,
                EffectState::EffectStarted,
                if result.is_ok() {
                    EffectState::Committed
                } else {
                    EffectState::InDoubt
                },
                Some(&digest),
                timestamp((self.clock)())?,
            )?;
            Ok(())
        })?;
        result.map_err(|error| refused(&format!("effect in doubt: {error}")))
    }
}

fn load_registration(
    conn: &rusqlite::Connection,
    id: &str,
    now_ms: u64,
) -> Result<(store::OperationRow, Registration), LedgerError> {
    let row = store::operation_row(conn, id)?.ok_or_else(|| refused("registration missing"))?;
    if row.capability != REGISTRATION
        || row.effect_state != EffectState::Committed
        || row.request_digest != Digest::hash(row.request_json.as_bytes()).to_string()
        || row.evidence_digest.as_deref() != Some(row.request_digest.as_str())
    {
        return Err(refused("registration is not committed authority"));
    }
    let registration: Registration =
        serde_json::from_str(&row.request_json).map_err(|_| refused("invalid registration"))?;
    if now_ms >= registration.expires_at_ms {
        return Err(refused("original identity expired"));
    }
    let parent = store::operation_row_by_id(conn, &registration.parent_operation)?
        .ok_or_else(|| refused("original parent missing"))?;
    if !matches!(
        parent.effect_state,
        EffectState::EffectStarted | EffectState::Committed
    ) || RecordedBinding::parse(&parent).is_none()
        || parent.binding_digest != registration.parent_binding
        || parent.request_digest != registration.parent_request
        || row.capsule_id != parent.capsule_id
        || row.seat_id != parent.seat_id
        || row.token_id != parent.token_id
        || row.session_id != parent.session_id
        || row.policy_digest != parent.policy_digest
        || row.listing_digest != parent.listing_digest
        || row.executor_id != parent.executor_id
        || id != format!("child-registration:{}", parent.operation_id)
    {
        return Err(refused("original parent binding changed"));
    }
    if crate::token::ledger_token_is_revoked(conn, &parent.token_id)? {
        return Err(refused("original token revoked"));
    }
    let lease = store::lease_row(conn, &parent.capsule_id)?
        .ok_or_else(|| refused("original lease missing"))?;
    if !valid_lease(&parent, &lease, &registration.lease) {
        return Err(refused("original lease closed or rebound"));
    }
    Ok((parent, registration))
}

#[cfg(test)]
mod tests {
    fn factory_permit(
        grant: &ChildEffectGrant,
        effect_class: odin_domain::EffectClass,
        executor: &'static str,
        with_lease: bool,
        with_context: bool,
    ) -> PreparedEffect {
        use super::super::model::PreparedEffectFields;
        let mut ledger = grant
            .store
            .lock()
            .unwrap_or_else(|_| panic!("test store poisoned"));
        let row = store::operation_row(ledger.connection(), "parent")
            .unwrap()
            .unwrap();
        let mut binding: PreparedBinding = serde_json::from_str(&row.prepared_binding).unwrap();
        binding.contract.effect_class = effect_class;
        ledger.with_tx(|tx| {
            tx.execute("DELETE FROM operation_journal WHERE correlation_id != 'parent'", [])?;
            tx.execute("UPDATE operation_journal SET effect_state = 'effect_started' WHERE correlation_id = 'parent'", [])?;
            Ok(())
        }).unwrap();
        drop(ledger);
        let permit = PreparedEffect::new(
            CorrelationId::new("00112233445566778899aabbccddee01").unwrap(),
            odin_types::OperationId::new(&row.operation_id).unwrap(),
            odin_types::CapsuleId::new(&row.capsule_id).unwrap(),
            executor,
            PreparedEffectFields {
                contract: binding.contract,
                payload: super::super::Payload::from_arguments(&serde_json::json!({})),
                target: binding.target,
                executor_binding: None,
                pre_world: super::super::PreWorld::Absent,
                grant: odin_domain::operation::Grant::new([CapabilityClass::Write], 1, 1),
                resources: vec![],
                lease: with_lease.then(|| odin_types::CapsuleLeaseId::new("lease").unwrap()),
                expires_at_ms: 100,
                reconciliation: super::super::Reconciliation {
                    pre_world: super::super::PreWorld::Absent,
                    expected_post_world: None,
                },
            },
            Arc::new(super::super::StopHandle::default()),
        );
        if with_context {
            permit.with_child_custody_context(
                Arc::clone(&grant.store),
                Arc::clone(&grant.clock),
                100,
                Digest::hash(b"fixture request"),
            )
        } else {
            permit
        }
    }

    #[test]
    fn factory_refuses_read_only_foreign_executor_and_missing_custody() {
        for (class, executor, lease, context, reason) in [
            (
                odin_domain::EffectClass::R0,
                PreparedEffect::OMP_HOST_EXECUTOR,
                true,
                true,
                "cannot delegate writes",
            ),
            (
                odin_domain::EffectClass::R2,
                PreparedEffect::SIDECAR_EXECUTOR,
                true,
                true,
                "cannot delegate writes",
            ),
            (
                odin_domain::EffectClass::R2,
                PreparedEffect::OMP_HOST_EXECUTOR,
                true,
                false,
                "no live custody context",
            ),
            (
                odin_domain::EffectClass::R2,
                PreparedEffect::OMP_HOST_EXECUTOR,
                false,
                true,
                "no lease",
            ),
            (
                odin_domain::EffectClass::R2,
                PreparedEffect::OMP_HOST_EXECUTOR,
                true,
                true,
                "permit mismatch",
            ),
        ] {
            let grant = granted();
            let permit = factory_permit(&grant, class, executor, lease, context);
            let error = ChildEffectGrant::from_prepared(&permit, grant.target.clone())
                .err()
                .unwrap();
            assert!(error.to_string().contains(reason), "{error}");
        }
    }

    fn granted() -> ChildEffectGrant {
        use crate::capability::{CapabilityContract, HandlerBinding};
        let contract = CapabilityContract {
            id: odin_domain::CapabilityId::new("claude.open").unwrap(),
            delegate_to: None,
            version: 1,
            tool_name: odin_domain::knowledge::ToolName::new("claude_open").unwrap(),
            description: "open".into(),
            handler: HandlerBinding::Builtin {
                name: "open".into(),
            },
            input_schema_ref: "input".into(),
            output_schema_ref: "output".into(),
            effect_class: odin_domain::EffectClass::R2,
            seat_tags: Default::default(),
            timeout_seconds: std::num::NonZeroU32::new(1).unwrap(),
            idempotency: crate::capability::IdempotencyPolicy::Required,
            retry: crate::capability::RetryPolicy { max_attempts: 1 },
            approval: crate::capability::ApprovalRequirement::None,
            evidence_extractor: HandlerBinding::Builtin {
                name: "evidence".into(),
            },
            adapter: None,
            preview: None,
            batchable: false,
            batch: None,
        };
        let binding = PreparedBinding {
            contract,
            executor_id: PreparedEffect::OMP_HOST_EXECUTOR.into(),
            handler_key: "open".into(),
            extractor_key: "evidence".into(),
            target: Target {
                kind: "project".into(),
                id: "project".into(),
            },
            executor_binding: None,
            pre_world: super::super::PreWorldRecord {
                absent: true,
                digest: None,
            },
            expected_post_world: None,
            lease: Some("lease".into()),
            expires_at_ms: 1,
            snapshot_revision: 1,
            snapshot_digest: "snapshot".into(),
        };
        let mut parent = parent();
        parent.prepared_binding = serde_json::to_string(&binding).unwrap();
        parent.binding_digest = Digest::hash(parent.prepared_binding.as_bytes()).to_string();
        let mut ledger = Ledger::open_in_memory().unwrap();
        let target = Target {
            kind: "publication".into(),
            id: "session/project/claude/one".into(),
        };
        let registration_id = ledger
            .with_tx(|tx| {
                let mut new = new_row(
                    &parent,
                    "parent",
                    "claude.open",
                    "{}",
                    "request",
                    timestamp(1).unwrap(),
                );
                new.prepared_binding = &parent.prepared_binding;
                new.binding_digest = &parent.binding_digest;
                let store::PrepareOutcome::Prepared { operation_id } =
                    store::prepare_operation(tx, &new)?
                else {
                    panic!("fresh parent")
                };
                store::transition_operation(
                    tx,
                    "parent",
                    EffectState::Prepared,
                    EffectState::EffectStarted,
                    None,
                    timestamp(1).unwrap(),
                )?;
                store::transition_operation(
                    tx,
                    "parent",
                    EffectState::EffectStarted,
                    EffectState::Committed,
                    None,
                    timestamp(1).unwrap(),
                )?;
                store::open_lease(
                    tx,
                    "capsule",
                    &store::LeaseAuthority {
                        seat_id: "seat",
                        token_id: "token",
                        session_id: "session",
                        policy_digest: "policy",
                        listing_digest: "listing",
                        token_issued_at_ms: 1,
                    },
                    "lease",
                    timestamp(1).unwrap(),
                )?;
                let registration = Registration {
                    parent_operation: operation_id.clone(),
                    parent_binding: parent.binding_digest.clone(),
                    parent_request: parent.request_digest.clone(),
                    lease: "lease".into(),
                    expires_at_ms: 100,
                    target: target.clone(),
                };
                let json = serde_json::to_string(&registration).unwrap();
                let digest = Digest::hash(json.as_bytes()).to_string();
                let id = format!("child-registration:{operation_id}");
                store::prepare_operation(
                    tx,
                    &new_row(
                        &parent,
                        &id,
                        REGISTRATION,
                        &json,
                        &digest,
                        timestamp(1).unwrap(),
                    ),
                )?;
                store::transition_operation(
                    tx,
                    &id,
                    EffectState::Prepared,
                    EffectState::EffectStarted,
                    None,
                    timestamp(1).unwrap(),
                )?;
                store::transition_operation(
                    tx,
                    &id,
                    EffectState::EffectStarted,
                    EffectState::Committed,
                    Some(&digest),
                    timestamp(1).unwrap(),
                )?;
                Ok(id)
            })
            .unwrap();
        ChildEffectGrant::recover(
            Arc::new(Mutex::new(ledger)),
            Arc::new(|| 2),
            &registration_id,
        )
        .unwrap()
    }

    fn request(grant: &ChildEffectGrant) -> ChildEffectRequest {
        ChildEffectRequest {
            correlation_id: CorrelationId::new("00112233445566778899aabbccddee01").unwrap(),
            target: grant.target.clone(),
            arguments: serde_json::json!({"commit":"exact", "bytes":17}),
        }
    }

    #[test]
    fn committed_result_replays_without_repeating_effect() {
        let grant = granted();
        let expected = serde_json::json!({"published":"exact", "bytes":17});
        assert_eq!(
            grant.run(request(&grant), || Ok(expected.clone())).unwrap(),
            expected
        );
        assert_eq!(
            grant
                .run(request(&grant), || panic!("must not replay"))
                .unwrap(),
            expected
        );
        let mut changed = request(&grant);
        changed.arguments["bytes"] = serde_json::json!(18);
        assert!(grant
            .run(changed, || panic!("mismatch must not execute"))
            .is_err());
    }

    #[test]
    fn in_doubt_result_refuses_retry() {
        let grant = granted();
        assert!(grant
            .run(request(&grant), || Err("uncertain".into()))
            .is_err());
        assert!(grant
            .run(request(&grant), || panic!("uncertain must not replay"))
            .is_err());
    }

    #[test]
    fn started_request_refuses_replay_after_interruption() {
        let grant = granted();
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = grant.run(request(&grant), || panic!("interrupted external effect"));
        }));
        assert!(interrupted.is_err());
        assert!(grant
            .run(request(&grant), || panic!(
                "started request must not replay"
            ))
            .is_err());
    }

    #[test]
    fn revoked_lease_refuses_next_effect() {
        let grant = granted();
        let mut ledger = grant
            .store
            .lock()
            .unwrap_or_else(|_| panic!("test store poisoned"));
        assert!(ledger
            .with_tx(|tx| store::close_lease(tx, "capsule", "drain", 1, timestamp(2)?))
            .unwrap());
        drop(ledger);
        assert!(grant
            .run(request(&grant), || panic!("revoked lease must not execute"))
            .is_err());
    }

    #[test]
    fn changed_parent_binding_refuses_effect() {
        let grant = granted();
        grant.store.lock().unwrap_or_else(|_| panic!("test store poisoned")).connection().execute(
            "UPDATE operation_journal SET binding_digest = 'changed' WHERE correlation_id = 'parent'", []).unwrap();
        assert!(grant
            .run(request(&grant), || panic!(
                "changed parent must not execute"
            ))
            .is_err());
    }

    #[test]
    fn failed_or_uncertain_parent_refuses_recovery_and_effect() {
        for state in ["aborted", "in_doubt"] {
            let grant = granted();
            let ledger = grant
                .store
                .lock()
                .unwrap_or_else(|_| panic!("test store poisoned"));
            ledger.connection().execute(
                "UPDATE operation_journal SET effect_state = ?1 WHERE correlation_id = 'parent'",
                [state],
            ).unwrap();
            drop(ledger);
            assert!(ChildEffectGrant::recover(
                Arc::clone(&grant.store),
                Arc::clone(&grant.clock),
                grant.registration_id()
            )
            .is_err());
            assert!(grant
                .run(request(&grant), || panic!("failed parent must not execute"))
                .is_err());
        }
    }

    #[test]
    fn branch_mismatch_never_invokes_effect() {
        let grant = ChildEffectGrant {
            store: Arc::new(Mutex::new(Ledger::open_in_memory().unwrap())),
            clock: Arc::new(|| 1),
            registration_id: "recorded".into(),
            target: Target {
                kind: "publication".into(),
                id: "session/project/claude/one".into(),
            },
        };
        let result = grant.run(
            ChildEffectRequest {
                correlation_id: CorrelationId::new("00112233445566778899aabbccddee01").unwrap(),
                target: Target {
                    kind: "publication".into(),
                    id: "session/project/claude/two".into(),
                },
                arguments: serde_json::json!({"commit":"exact", "bytes":1}),
            },
            || panic!("refused branch must not execute"),
        );
        assert!(result.is_err());
    }
    use super::*;

    fn parent() -> store::OperationRow {
        store::OperationRow {
            correlation_id: "parent".into(),
            operation_id: "op-parent".into(),
            capsule_id: "capsule".into(),
            seat_id: "seat".into(),
            token_id: "token".into(),
            session_id: "session".into(),
            policy_digest: "policy".into(),
            listing_digest: "listing".into(),
            capability: "claude.open".into(),
            request_digest: "request".into(),
            request_json: "{}".into(),
            effect_state: EffectState::Committed,
            reconciliation_json: "{}".into(),
            evidence_digest: None,
            executor_id: PreparedEffect::OMP_HOST_EXECUTOR.into(),
            prepared_binding: "{}".into(),
            binding_digest: "binding".into(),
            updated_at: "".into(),
        }
    }

    fn lease() -> store::CapsuleLeaseRow {
        store::CapsuleLeaseRow {
            capsule_id: "capsule".into(),
            seat_id: "seat".into(),
            token_id: "token".into(),
            session_id: "session".into(),
            policy_digest: "policy".into(),
            listing_digest: "listing".into(),
            lease_id: "lease".into(),
            state: "open".into(),
            close_mode: None,
            drained: 0,
            token_issued_at_ms: Some(1),
        }
    }

    #[test]
    fn closed_and_rebound_original_lease_are_refused() {
        let parent = parent();
        let mut lease = lease();
        assert!(valid_lease(&parent, &lease, "lease"));
        lease.state = "closed".into();
        assert!(!valid_lease(&parent, &lease, "lease"));
        lease.state = "open".into();
        lease.token_id = "new-token".into();
        assert!(!valid_lease(&parent, &lease, "lease"));
    }

    #[test]
    fn cross_session_and_replaced_lease_are_refused() {
        let parent = parent();
        let mut lease = lease();
        lease.session_id = "another-session".into();
        assert!(!valid_lease(&parent, &lease, "lease"));
        lease.session_id = parent.session_id.clone();
        assert!(!valid_lease(&parent, &lease, "replacement-lease"));
    }

    #[test]
    fn uncommitted_registration_is_not_recoverable() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        odin_ledger::migration::migrate(&mut conn).unwrap();
        let parent = parent();
        let registration = Registration {
            parent_operation: parent.operation_id.clone(),
            parent_binding: parent.binding_digest.clone(),
            parent_request: parent.request_digest.clone(),
            lease: "lease".into(),
            expires_at_ms: 100,
            target: Target {
                kind: "publication".into(),
                id: "session/project/claude/name".into(),
            },
        };
        let request = serde_json::to_string(&registration).unwrap();
        let digest = Digest::hash(request.as_bytes()).to_string();
        let tx = conn.transaction().unwrap();
        store::prepare_operation(
            &tx,
            &new_row(
                &parent,
                "registration",
                REGISTRATION,
                &request,
                &digest,
                timestamp(1).unwrap(),
            ),
        )
        .unwrap();
        tx.commit().unwrap();
        assert!(load_registration(&conn, "registration", 2).is_err());
        assert!(load_registration(&conn, "unrecorded", 2).is_err());
        let tx = conn.transaction().unwrap();
        store::transition_operation(
            &tx,
            "registration",
            EffectState::Prepared,
            EffectState::EffectStarted,
            None,
            timestamp(1).unwrap(),
        )
        .unwrap();
        store::transition_operation(
            &tx,
            "registration",
            EffectState::EffectStarted,
            EffectState::Committed,
            Some(&digest),
            timestamp(1).unwrap(),
        )
        .unwrap();
        tx.commit().unwrap();
        let error = load_registration(&conn, "registration", 100).err().unwrap();
        assert!(error.to_string().contains("original identity expired"));
    }
}
