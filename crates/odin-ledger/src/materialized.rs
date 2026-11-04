use rusqlite::Transaction;

use crate::{Ledger, LedgerResult};

const OWNED_KINDS: [&str; 6] = [
    "lane",
    "run",
    "approval",
    "incident",
    "provider_lease",
    "live_session",
];

/// Rebuilds the status projection from its authoritative ledger tables.
///
/// Only rows owned by this projection are replaced. In particular, controller
/// metadata and extension-defined object kinds in `materialized_status` survive
/// a rebuild unchanged.
pub fn rebuild(ledger: &mut Ledger) -> LedgerResult<usize> {
    ledger.with_tx(rebuild_in_transaction)
}

fn rebuild_in_transaction(transaction: &Transaction<'_>) -> LedgerResult<usize> {
    transaction.execute(
        "DELETE FROM materialized_status
         WHERE object_kind IN (?1, ?2, ?3, ?4, ?5, ?6)",
        OWNED_KINDS,
    )?;

    // The source marker is deterministic because these tables do not retain
    // the event that produced their current revision. It identifies the exact
    // source row and revision from which the projection was reconstructed.
    let rebuilt = transaction.execute(
        "INSERT INTO materialized_status (
             object_kind, object_id, revision, status_json,
             source_event_id, updated_at, stale_after
         )
         SELECT 'lane', lane_id, revision,
                json_object('state', status),
                'source:lane:' || lane_id || ':revision:' || revision,
                updated_at, NULL
         FROM lanes
         UNION ALL
         SELECT 'run', run_id, revision,
                json_object('state', status),
                'source:run:' || run_id || ':revision:' || revision,
                updated_at, NULL
         FROM runs
         UNION ALL
         SELECT 'approval', approval_id, revision,
                json_object('state', status),
                'source:approval:' || approval_id || ':revision:' || revision,
                COALESCE(decided_at, requested_at), NULL
         FROM approvals
         UNION ALL
         SELECT 'incident', incident_id, revision,
                json_object('state', status),
                'source:incident:' || incident_id || ':revision:' || revision,
                last_observed_at, NULL
         FROM incidents
         UNION ALL
         SELECT 'provider_lease', provider_lease_id, revision,
                json_object(
                    'state', CASE WHEN ended_at IS NULL THEN 'active' ELSE 'ended' END
                ),
                'source:provider_lease:' || provider_lease_id || ':revision:' || revision,
                COALESCE(ended_at, started_at), NULL
         FROM provider_leases
         UNION ALL
         SELECT 'live_session', session_id, revision,
                json_object('state', state),
                'source:live_session:' || session_id || ':revision:' || revision,
                updated_at, NULL
         FROM live_sessions",
        [],
    )?;

    Ok(rebuilt)
}

impl Ledger {
    pub fn rebuild_materialized_status(&mut self) -> LedgerResult<usize> {
        rebuild(self)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    struct TestDatabase {
        _scratch: tempfile::TempDir,
        path: PathBuf,
    }

    impl TestDatabase {
        fn new() -> Self {
            let scratch = tempfile::tempdir().unwrap();
            let path = scratch.path().join("materialized.sqlite3");
            Self {
                _scratch: scratch,
                path,
            }
        }
    }

    fn insert_sources(ledger: &Ledger) {
        ledger
            .connection()
            .execute_batch(
                "INSERT INTO lanes (
                     lane_id, seat_id, template_id, backend, status, revision,
                     desired_revision, created_by, created_at, updated_at
                 ) VALUES (
                     'lane:one', 'seat:one', 'template:one', 'local_omp',
                     'running', 7, 1, 'test', '2026-08-31T10:00:00Z',
                     '2026-08-31T10:01:00Z'
                 );
                 INSERT INTO runs (
                     run_id, lane_id, attempt_number, status, revision,
                     input_hash, created_at, updated_at
                 ) VALUES (
                     'run:one', 'lane:one', 1, 'completed', 8,
                     'input-hash', '2026-08-31T10:02:00Z', '2026-08-31T10:03:00Z'
                 );
                 INSERT INTO approvals (
                     approval_id, status, issuer, target_kind, target_id,
                     capability_id, arguments_hash, requested_at, expires_at,
                     decided_at, decided_by, revision
                 ) VALUES (
                     'approval:one', 'approved', 'test', 'lane', 'lane:one',
                     'capability:test', 'arguments-hash', '2026-08-31T10:04:00Z',
                     '2026-08-31T11:04:00Z', '2026-08-31T10:05:00Z', 'operator', 9
                 );
                 INSERT INTO incidents (
                     incident_id, run_id, severity, confidence_micros, deviation,
                     failure_signature, expected_state_json, observed_state_json,
                     affected_objects_json, evidence_refs_json,
                     allowed_capabilities_json, attempt_ids_json,
                     recommended_next_action, escalation_target, first_observed_at,
                     last_observed_at, status, revision
                 ) VALUES (
                     'incident:one', 'run:one', 'high', 900000, 'deviation',
                     'failure-signature', '{}', '{}', '[]', '[]', '[]', '[]',
                     'inspect', 'operator', '2026-08-31T10:06:00Z',
                     '2026-08-31T10:07:00Z', 'recovering', 10
                 );
                 INSERT INTO provider_leases (
                     provider_lease_id, lane_id, provider_id, account_handle, model,
                     role, affinity_key, quota_snapshot_json, selection_reason,
                     started_at, ended_at, end_reason, revision
                 ) VALUES (
                     'provider-lease:one', 'lane:one', 'provider:one', 'account',
                     'model', 'worker', 'affinity', '{}', 'selected',
                     '2026-08-31T10:08:00Z', '2026-08-31T10:09:00Z', 'complete', 11
                 );
                 INSERT INTO live_sessions (
                     session_id, seat_id, project_id, slice_id, lane_id,
                     target_node_id, provider, model, epoch, event_head,
                     terminal_head, open_tab, state, created_at, updated_at,
                     revision
                 ) VALUES (
                     'session:one', 'seat:one', 'project:one', 'slice:one',
                     'lane:one', 'node:one', 'provider', 'model', 1, 0, 0, 1,
                     'attached', '2026-08-31T10:10:00Z',
                     '2026-08-31T10:11:00Z', 12
                 );",
            )
            .expect("insert authoritative source rows");
    }

    #[test]
    fn rebuild_is_idempotent_and_survives_reopen() {
        let database = TestDatabase::new();
        {
            let mut ledger = Ledger::open(&database.path).expect("open ledger");
            insert_sources(&ledger);

            assert_eq!(ledger.rebuild_materialized_status().expect("rebuild"), 6);
            assert_eq!(
                ledger.rebuild_materialized_status().expect("rebuild again"),
                6
            );
        }

        let ledger = Ledger::open(&database.path).expect("reopen ledger");
        let rows = ledger
            .connection()
            .prepare(
                "SELECT object_kind, revision, status_json, source_event_id, updated_at
                 FROM materialized_status
                 ORDER BY object_kind",
            )
            .expect("prepare projection query")
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .expect("query projection")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("read projection");

        assert_eq!(
            rows,
            vec![
                (
                    "approval".into(),
                    9,
                    r#"{"state":"approved"}"#.into(),
                    "source:approval:approval:one:revision:9".into(),
                    "2026-08-31T10:05:00Z".into(),
                ),
                (
                    "incident".into(),
                    10,
                    r#"{"state":"recovering"}"#.into(),
                    "source:incident:incident:one:revision:10".into(),
                    "2026-08-31T10:07:00Z".into(),
                ),
                (
                    "lane".into(),
                    7,
                    r#"{"state":"running"}"#.into(),
                    "source:lane:lane:one:revision:7".into(),
                    "2026-08-31T10:01:00Z".into(),
                ),
                (
                    "live_session".into(),
                    12,
                    r#"{"state":"attached"}"#.into(),
                    "source:live_session:session:one:revision:12".into(),
                    "2026-08-31T10:11:00Z".into(),
                ),
                (
                    "provider_lease".into(),
                    11,
                    r#"{"state":"ended"}"#.into(),
                    "source:provider_lease:provider-lease:one:revision:11".into(),
                    "2026-08-31T10:09:00Z".into(),
                ),
                (
                    "run".into(),
                    8,
                    r#"{"state":"completed"}"#.into(),
                    "source:run:run:one:revision:8".into(),
                    "2026-08-31T10:03:00Z".into(),
                ),
            ]
        );
    }
}
