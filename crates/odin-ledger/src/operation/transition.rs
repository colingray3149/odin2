//! Compare-and-set effect-state lifecycle and reconciliation: a transition
//! applies only against the exact durable state it was decided against, and
//! observed evidence is immutable.

use odin_domain::operation::EffectState;
use rusqlite::{params, Transaction};
use time::OffsetDateTime;

use super::prepare::query_row;
use super::row::{state_text, TransitionOutcome};
use crate::{encode_utc, LedgerError, LedgerResult};

/// Compare-and-set state transition: applies `from -> to` only when the
/// durable row is still in `from`. Replays when it already reached `to` and
/// fails with the actual state otherwise. Observed evidence is immutable:
/// a transition that names a digest while the row already holds a
/// conflicting one is rejected — never overwritten — and `None` preserves
/// whatever evidence is already recorded.
#[doc(hidden)]
pub fn transition_operation(
    tx: &Transaction<'_>,
    correlation_id: &str,
    from: EffectState,
    to: EffectState,
    evidence_digest: Option<&str>,
    now: OffsetDateTime,
) -> LedgerResult<TransitionOutcome> {
    if !odin_domain::operation::can_transition(from, to) {
        return Err(invalid_transition(from, "transition"));
    }
    let updated = tx
        .prepare_cached(
            "UPDATE operation_journal SET effect_state = ?1, evidence_digest = \
             COALESCE(?2, evidence_digest), updated_at = ?3 \
             WHERE correlation_id = ?4 AND effect_state = ?5 \
             AND (evidence_digest IS NULL OR ?2 IS NULL OR evidence_digest = ?2)",
        )?
        .execute(params![
            state_text(to),
            evidence_digest,
            encode_utc(now)?,
            correlation_id,
            state_text(from),
        ])?;
    if updated == 1 {
        return Ok(TransitionOutcome::Applied);
    }
    let row = query_row(tx, correlation_id)?.ok_or_else(|| LedgerError::NotFound {
        kind: "operation",
        id: correlation_id.to_owned(),
    })?;
    if row.effect_state == to {
        return Ok(TransitionOutcome::Replay);
    }
    if row.effect_state == from {
        // A matching state with a rejected update means the digest conflicts with recorded evidence.
        let recorded = row.evidence_digest.as_deref().unwrap_or("-");
        let claimed = evidence_digest.unwrap_or("-");
        return Err(LedgerError::Conflict(format!(
            "operation {correlation_id} transition {} -> {} rejected: recorded evidence \
             digest {recorded} conflicts with the claimed {claimed}; observed evidence \
             is immutable",
            state_text(from),
            state_text(to),
        )));
    }
    Err(invalid_transition(row.effect_state, "transition"))
}

fn invalid_transition(state: EffectState, action: &'static str) -> LedgerError {
    LedgerError::invalid_data_caused_by(
        "illegal operation transition",
        odin_domain::operation::OperationError::InvalidTransition {
            state: state.as_str(),
            action,
        },
    )
}

#[cfg(test)]
mod transition_evidence_immutability {
    use super::*;
    use crate::migration;
    use crate::operation::{operation_row, prepare_operation, NewOperation, PrepareOutcome};
    use rusqlite::Connection;

    const CORRELATION: &str = "00112233445566778899aabbccddee01";

    fn journal() -> Connection {
        let mut connection = Connection::open_in_memory().unwrap();
        migration::migrate(&mut connection).unwrap();
        connection
    }

    fn new_operation() -> NewOperation<'static> {
        NewOperation {
            capsule_id: "capsule-a",
            seat_id: "seat.one",
            token_id: "token.one",
            session_id: "session.one",
            policy_digest: "policy.one",
            listing_digest: "listing.one",
            executor_id: "odin.omp.host_tools",
            prepared_binding: "{\"binding\":true}",
            binding_digest: "binding-digest",
            correlation_id: CORRELATION,
            capability: "tool.write",
            request_digest: "request-digest",
            request_json: "{}",
            reconciliation_json: "{}",
            now: OffsetDateTime::from_unix_timestamp(1_000).unwrap(),
        }
    }

    fn now_at(second: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(second).unwrap()
    }

    /// Prepares one operation and drives it to `effect_started` with no
    /// evidence bound — the durable shape of a dispatched effect.
    fn prepared(connection: &mut Connection) {
        let tx = connection.transaction().unwrap();
        assert!(matches!(
            prepare_operation(&tx, &new_operation()).unwrap(),
            PrepareOutcome::Prepared { .. }
        ));
        transition_operation(
            &tx,
            CORRELATION,
            EffectState::Prepared,
            EffectState::EffectStarted,
            None,
            now_at(1_100),
        )
        .unwrap();
        tx.commit().unwrap();
    }

    fn row_effect(connection: &Connection) -> (EffectState, Option<String>) {
        let row = operation_row(connection, CORRELATION)
            .unwrap()
            .expect("operation row exists");
        (row.effect_state, row.evidence_digest)
    }

    /// Conflicting digests are rejected; absent evidence and replays preserve the recorded digest.
    #[test]
    fn conflicting_observed_digest_is_rejected_and_never_overwritten() {
        let mut connection = journal();
        prepared(&mut connection);
        let genuine = format!("blake3:{}", "1".repeat(64));
        let forged = format!("blake3:{}", "2".repeat(64));

        let tx = connection.transaction().unwrap();
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::EffectStarted,
                EffectState::InDoubt,
                Some(&genuine),
                now_at(1_200),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        tx.commit().unwrap();
        assert_eq!(
            row_effect(&connection),
            (EffectState::InDoubt, Some(genuine.clone()))
        );

        let tx = connection.transaction().unwrap();
        let error = transition_operation(
            &tx,
            CORRELATION,
            EffectState::InDoubt,
            EffectState::Committed,
            Some(&forged),
            now_at(1_300),
        )
        .unwrap_err();
        tx.commit().unwrap();
        assert!(
            matches!(error, LedgerError::Conflict(_)),
            "conflicting evidence claims must conflict, got {error:?}"
        );
        assert_eq!(
            row_effect(&connection),
            (EffectState::InDoubt, Some(genuine.clone()))
        );

        let tx = connection.transaction().unwrap();
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::InDoubt,
                EffectState::Committed,
                None,
                now_at(1_400),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        tx.commit().unwrap();
        assert_eq!(
            row_effect(&connection),
            (EffectState::Committed, Some(genuine.clone()))
        );

        let tx = connection.transaction().unwrap();
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::EffectStarted,
                EffectState::Committed,
                Some(&forged),
                now_at(1_500),
            )
            .unwrap(),
            TransitionOutcome::Replay
        );
        tx.commit().unwrap();
        assert_eq!(
            row_effect(&connection),
            (EffectState::Committed, Some(genuine))
        );
    }

    /// An equal-digest claim is an idempotent restatement of the same
    /// observation, and a no-output uncertain flow passes no evidence at
    /// all: absence stays absent end to end.
    #[test]
    fn equal_digest_claim_is_idempotent_and_absent_evidence_stays_absent() {
        let mut connection = journal();
        prepared(&mut connection);
        let genuine = format!("blake3:{}", "3".repeat(64));

        let tx = connection.transaction().unwrap();
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::EffectStarted,
                EffectState::InDoubt,
                Some(&genuine),
                now_at(1_200),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::InDoubt,
                EffectState::Committed,
                Some(&genuine),
                now_at(1_300),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        tx.commit().unwrap();
        assert_eq!(
            row_effect(&connection),
            (EffectState::Committed, Some(genuine))
        );

        let mut connection = journal();
        prepared(&mut connection);
        let tx = connection.transaction().unwrap();
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::EffectStarted,
                EffectState::InDoubt,
                None,
                now_at(1_200),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        assert_eq!(
            transition_operation(
                &tx,
                CORRELATION,
                EffectState::InDoubt,
                EffectState::Aborted,
                None,
                now_at(1_300),
            )
            .unwrap(),
            TransitionOutcome::Applied
        );
        tx.commit().unwrap();
        assert_eq!(row_effect(&connection), (EffectState::Aborted, None));
    }
}
