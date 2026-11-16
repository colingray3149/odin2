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
const RESULT: &str = "odin.child.result.v1";

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

fn refused(reason: impl std::fmt::Display) -> LedgerError {
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
            .child_dispatch_context()
            .ok_or_else(|| refused("permit has no live dispatch context"))?;
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
        let mut ledger = store
            .lock()
            .map_err(|error| refused(format!("store poisoned: {error}")))?;
        let registration_id = ledger.with_tx(|tx| {
            let row = store::operation_row_by_id(tx, parent.operation_id().as_str())?
                .ok_or_else(|| refused("parent missing"))?;
            let binding: PreparedBinding = serde_json::from_str(&row.prepared_binding)
                .map_err(|error| refused(format!("invalid parent binding: {error}")))?;
            let request: Value = serde_json::from_str(&row.request_json)
                .map_err(|error| refused(format!("invalid parent request: {error}")))?;
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
        let mut ledger = store
            .lock()
            .map_err(|error| refused(format!("store poisoned: {error}")))?;
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
        let mut fence = {
            let ledger = self
                .store
                .lock()
                .map_err(|error| refused(format!("store poisoned: {error}")))?;
            ledger
                .try_operation_fence(&correlation)?
                .ok_or_else(|| refused("child request is in flight"))?
        };
        let replay = {
            let mut ledger = self
                .store
                .lock()
                .map_err(|error| refused(format!("store poisoned: {error}")))?;
            ledger.with_tx(|tx| {
                fence.claim(tx)?;
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
                        if saved.capability != RESULT
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
                            serde_json::from_str(&saved.request_json).map_err(|error| {
                                refused(format!("invalid committed result: {error}"))
                            })?;
                        return result.map(Some).map_err(|error| {
                            refused(format!("committed result is failure: {error}"))
                        });
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
        let mut ledger = self
            .store
            .lock()
            .map_err(|error| refused(format!("store poisoned: {error}")))?;
        ledger.with_tx(|tx| {
            fence.check(tx)?;
            let row = store::operation_row(tx, &correlation)?
                .ok_or_else(|| refused("started request missing"))?;
            let result_id = format!("child-result:{correlation}");
            let now = timestamp((self.clock)())?;
            match store::prepare_operation(
                tx,
                &new_row(&row, &result_id, RESULT, &evidence, &digest, now),
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
        result.map_err(|error| refused(format!("effect in doubt: {error}")))
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
    let registration: Registration = serde_json::from_str(&row.request_json)
        .map_err(|error| refused(format!("invalid registration: {error}")))?;
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

    fn granted() -> ChildEffectGrant {
        use crate::capability::{CapabilityContract, HandlerBinding};
        let contract = CapabilityContract {
            id: odin_domain::CapabilityId::new("claude.open").unwrap(),
            toolset: None,
            op: None,
            expose: None,
            seat_ops: Default::default(),
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
            recovery_evidence_digest: None,
            executor_id: PreparedEffect::OMP_HOST_EXECUTOR.into(),
            prepared_binding: "{}".into(),
            binding_digest: "binding".into(),
            updated_at: "".into(),
        }
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
