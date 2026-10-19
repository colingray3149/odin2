//! Canonical migration, extension and durable reopen invariants.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;
use crate::Ledger;

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

fn database_path(label: &str) -> PathBuf {
    let serial = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "odin-ledger-{label}-{}-{serial}.sqlite3",
        std::process::id()
    ))
}

fn digest(sql: &str) -> String {
    blake3::hash(sql.as_bytes()).to_hex().to_string()
}

const EXTENSION_SQL: &str = "CREATE TABLE extension_probe (value TEXT NOT NULL) STRICT;";
const EXTENSION_DRIFT_SQL: &str =
    "CREATE TABLE extension_probe (value TEXT NOT NULL, extra TEXT) STRICT;";
const EXTENSION_PATH: &str = "schemas/0008_extension.sql";

/// Builds a below-version-3 database with canonical migration names and
/// checksums so `Ledger::open` can apply later migrations. Old names and
/// null checksums are refused.
fn write_precompatibility_database(path: &std::path::Path) -> Connection {
    let connection = Connection::open(path).expect("open fixture database");
    connection
        .execute_batch(CONTROL_PLANE_SCHEMA)
        .expect("apply control plane schema");
    connection
        .execute_batch(LANE_RUN_SCHEMA)
        .expect("apply lane ledger schema");
    connection
        .execute(
            "UPDATE schema_migrations SET name = ?1, checksum = ?2 WHERE version = 1",
            params![BUILTIN_MIGRATIONS[0].path, BUILTIN_MIGRATIONS[0].checksum()],
        )
        .expect("record canonical migration 1");
    connection
        .execute(
            "INSERT INTO schema_migrations(version, applied_at, name, checksum) \
                 VALUES (2, '2026-01-01T00:00:00Z', ?1, ?2)",
            params![BUILTIN_MIGRATIONS[1].path, BUILTIN_MIGRATIONS[1].checksum()],
        )
        .expect("record migration 2");
    connection
}

fn insert_legacy_lane(connection: &Connection, lane_id: &str, state: &str) {
    connection
        .execute(
            "INSERT INTO lanes(lane_id, seat_id, template_id, backend, state, \
                 created_by, created_at, updated_at) \
                 VALUES (?1, 'seat:test', 'template:test', 'local_omp', ?2, \
                 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![lane_id, state],
        )
        .expect("insert legacy lane");
}

fn insert_legacy_run(connection: &Connection, run_id: &str, lane_id: &str, state: &str) {
    connection
        .execute(
            "INSERT INTO runs(run_id, lane_id, attempt_number, workflow_id, \
                 workflow_version, state, input_hash, created_at, updated_at) \
                 VALUES (?1, ?2, 1, NULL, NULL, ?3, 'hash', \
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            params![run_id, lane_id, state],
        )
        .expect("insert legacy run");
}

#[test]
fn failed_extension_is_atomic() {
    let path = database_path("extension-atomic");
    let before: i64 = {
        let ledger = Ledger::open(&path).expect("open ledger");
        ledger
            .connection()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read version")
    };
    let broken_sql = "CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY) STRICT; \
             INSERT INTO table_that_does_not_exist(id) VALUES (1);";
    let broken_checksum = digest(broken_sql);
    let broken = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        "schemas/0008_broken.sql",
        &broken_checksum,
        broken_sql,
    );
    assert!(Ledger::open_with_migrations(&path, &[broken]).is_err());
    {
        let ledger = Ledger::open(&path).expect("reopen ledger");
        let after: i64 = ledger
            .connection()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read version after failure");
        let exists: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE type='table' AND name='rollback_probe'",
                [],
                |row| row.get(0),
            )
            .expect("inspect rollback");
        assert_eq!((before, exists), (after, 0));
    }
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn migration_reopens_with_canonical_checksums() {
    let path = database_path("reopen");
    {
        let ledger = Ledger::open(&path).expect("create ledger");
        let tracked: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE checksum IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("count checksums");
        assert_eq!(tracked, LATEST_SCHEMA_VERSION);
    }
    Ledger::open(&path).expect("reopen ledger");
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn checksum_drift_fails_closed_on_reopen() {
    let path = database_path("drift");
    {
        let ledger = Ledger::open(&path).expect("create ledger");
        ledger
            .connection()
            .execute(
                "UPDATE schema_migrations SET checksum = 'drifted' WHERE version = 1",
                [],
            )
            .expect("corrupt checksum");
    }
    assert!(matches!(
        Ledger::open(&path),
        Err(LedgerError::ChecksumDrift { version: 1, .. })
    ));
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn newer_database_fails_closed_on_reopen() {
    let path = database_path("newer");
    {
        let ledger = Ledger::open(&path).expect("create ledger");
        ledger
            .connection()
            .execute(
                "INSERT INTO schema_migrations(version, applied_at, name, checksum) \
                 VALUES (99, '2026-01-01T00:00:00Z', 'future', 'future')",
                [],
            )
            .expect("add future migration");
    }
    assert!(matches!(
        Ledger::open(&path),
        Err(LedgerError::NewerSchema {
            found: 99,
            supported: LATEST_SCHEMA_VERSION
        })
    ));
    std::fs::remove_file(path).expect("remove test database");
}

/// (pre-compatibility state, expected lane status, expected run status)
const LEGACY_STATE_MAPPING: [(&str, &str, &str); 11] = [
    ("desired", "desired", "pending"),
    ("provisioning", "provisioning", "planning"),
    ("ready", "ready", "planning"),
    ("running", "running", "running"),
    ("waiting_approval", "waitingApproval", "waitingApproval"),
    ("paused", "paused", "paused"),
    ("recovering", "recovering", "recovering"),
    ("completed", "succeeded", "succeeded"),
    ("failed", "failed", "failed"),
    ("blocked", "blocked", "blocked"),
    ("cancelled", "cancelled", "cancelled"),
];

#[test]
fn compatibility_maps_all_legacy_states() {
    let path = database_path("compatibility-states");
    {
        let connection = write_precompatibility_database(&path);
        for (index, (state, _, _)) in LEGACY_STATE_MAPPING.iter().enumerate() {
            let lane_id = format!("lane:{index}");
            insert_legacy_lane(&connection, &lane_id, state);
            insert_legacy_run(&connection, &format!("run:{index}"), &lane_id, state);
        }
        insert_legacy_lane(&connection, "lane:nondefault", "desired");
        insert_legacy_run(&connection, "run:nondefault", "lane:nondefault", "desired");
        // Writers on later schema versions already stored canonical
        // statuses on these rows: the compatibility migration must
        // preserve them against their contradicting legacy state values.
        connection
            .execute(
                "UPDATE lanes SET status = 'running', revision = 4 \
                     WHERE lane_id = 'lane:nondefault'",
                [],
            )
            .expect("make lane nondefault");
        connection
            .execute(
                "UPDATE runs SET status = 'planning', revision = 6 \
                     WHERE run_id = 'run:nondefault'",
                [],
            )
            .expect("make run nondefault");
    }
    {
        let ledger = Ledger::open(&path).expect("apply compatibility migration");
        for (index, (state, lane_status, run_status)) in LEGACY_STATE_MAPPING.iter().enumerate() {
            let (lane, run): (String, String) = ledger
                .connection()
                .query_row(
                    "SELECT (SELECT status FROM lanes WHERE lane_id = ?1), \
                         (SELECT status FROM runs WHERE run_id = ?2)",
                    params![format!("lane:{index}"), format!("run:{index}")],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap_or_else(|error| panic!("read mapped statuses for {state}: {error}"));
            assert_eq!(
                (lane.as_str(), run.as_str()),
                (*lane_status, *run_status),
                "legacy state {state} must map to its canonical statuses"
            );
        }
        let (lane_revision, lane_status): (i64, String) = ledger
            .connection()
            .query_row(
                "SELECT revision, status FROM lanes WHERE lane_id = 'lane:nondefault'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read nondefault lane");
        assert_eq!((lane_revision, lane_status.as_str()), (4, "running"));
        let (run_revision, run_status): (i64, String) = ledger
            .connection()
            .query_row(
                "SELECT revision, status FROM runs WHERE run_id = 'run:nondefault'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read nondefault run");
        assert_eq!((run_revision, run_status.as_str()), (6, "planning"));
        let legacy_columns: i64 = ledger
            .connection()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM pragma_table_info('lanes') WHERE name = 'state') \
                     + (SELECT COUNT(*) FROM pragma_table_info('runs') WHERE name = 'state')",
                [],
                |row| row.get(0),
            )
            .expect("inspect dropped columns");
        assert_eq!(legacy_columns, 0, "legacy state columns must be dropped");
    }
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn checkpoint_requires_artifact() {
    let repaired = database_path("checkpoint-repair");
    {
        let connection = write_precompatibility_database(&repaired);
        insert_legacy_lane(&connection, "lane:checkpoint", "running");
        insert_legacy_run(&connection, "run:checkpoint", "lane:checkpoint", "running");
        connection
            .execute_batch(
                "INSERT INTO checkpoints(checkpoint_id, run_id, compatibility_key, \
                     artifact_ref, state_hash, created_at) \
                     VALUES ('checkpoint:zero', 'run:checkpoint', 'runtime:v1', \
                     'artifact:present', 'state-digest', '2026-01-01T00:00:00Z'); \
                     INSERT INTO checkpoints(checkpoint_id, run_id, compatibility_key, \
                     artifact_ref, artifact_digest, state_hash, created_at) \
                     VALUES ('checkpoint:explicit', 'run:checkpoint', 'runtime:v1', \
                     'artifact:present', 'explicit-digest', 'state-digest', \
                     '2026-01-01T00:00:00Z'); \
                     INSERT INTO artifacts(artifact_ref, content_digest, size_bytes, media_type, \
                     storage_path, retention_class, created_at) \
                     VALUES ('artifact:present', 'canonical-digest', 4, \
                     'application/octet-stream', 'a/b', 'canonical', '2026-01-01T00:00:00Z');",
            )
            .expect("seed legacy checkpoints");
    }
    {
        let ledger = Ledger::open(&repaired).expect("repair zero checkpoint");
        let zero: String = ledger
            .connection()
            .query_row(
                "SELECT artifact_digest FROM checkpoints \
                     WHERE checkpoint_id = 'checkpoint:zero'",
                [],
                |row| row.get(0),
            )
            .expect("read repaired checkpoint");
        assert_eq!(zero, "canonical-digest");
        let explicit: String = ledger
            .connection()
            .query_row(
                "SELECT artifact_digest FROM checkpoints \
                     WHERE checkpoint_id = 'checkpoint:explicit'",
                [],
                |row| row.get(0),
            )
            .expect("read explicit checkpoint");
        assert_eq!(explicit, "explicit-digest");
    }
    std::fs::remove_file(repaired).expect("remove test database");

    let orphan = database_path("checkpoint-orphan");
    {
        let connection = write_precompatibility_database(&orphan);
        insert_legacy_lane(&connection, "lane:orphan", "running");
        insert_legacy_run(&connection, "run:orphan", "lane:orphan", "running");
        connection
            .execute(
                "INSERT INTO checkpoints(checkpoint_id, run_id, compatibility_key, \
                     artifact_ref, state_hash, created_at) \
                     VALUES ('checkpoint:orphan', 'run:orphan', 'runtime:v1', \
                     'artifact:ghost', 'state-digest', '2026-01-01T00:00:00Z')",
                [],
            )
            .expect("seed orphan checkpoint");
    }
    let error = match Ledger::open(&orphan) {
        Ok(_) => panic!("a zero checkpoint with a nonexistent artifact must abort migration"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("artifact_digest"),
        "orphan must fail on the artifact digest repair: {error}"
    );
    {
        let connection = Connection::open(&orphan).expect("reopen failed database");
        let version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read version after aborted migration");
        let legacy_columns: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('lanes') WHERE name = 'state'",
                [],
                |row| row.get(0),
            )
            .expect("inspect legacy column");
        assert_eq!((version, legacy_columns), (2, 1));
    }
    std::fs::remove_file(orphan).expect("remove test database");
}

#[test]
fn extension_reopens_with_same_set() {
    let path = database_path("extension-reopen");
    let backup = database_path("extension-reopen-backup");
    let restored = database_path("extension-reopen-restored");
    let drifted_dest = database_path("extension-reopen-drifted");
    let extension_checksum = digest(EXTENSION_SQL);
    let drifted_checksum = digest(EXTENSION_DRIFT_SQL);
    let extension = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        EXTENSION_PATH,
        &extension_checksum,
        EXTENSION_SQL,
    );
    let drifted = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        EXTENSION_PATH,
        &drifted_checksum,
        EXTENSION_DRIFT_SQL,
    );
    {
        let mut ledger = Ledger::open_with_migrations(&path, &[extension])
            .expect("open with the complete migration set");
        ledger
            .connection()
            .execute("INSERT INTO extension_probe (value) VALUES ('durable')", [])
            .expect("write through extension schema");
        ledger
            .backup(&backup)
            .expect("snapshot the extension-opened ledger with its complete set");
    }
    {
        let ledger = Ledger::open_with_migrations(&path, &[extension])
            .expect("reopen with the same migration set");
        let version: i64 = ledger
            .connection()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read version");
        let tracked: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE checksum IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .expect("count checksums");
        let value: String = ledger
            .connection()
            .query_row("SELECT value FROM extension_probe", [], |row| row.get(0))
            .expect("read durable value");
        assert_eq!(
            (version, tracked, value.as_str()),
            (
                LATEST_SCHEMA_VERSION + 1,
                LATEST_SCHEMA_VERSION + 1,
                "durable"
            ),
        );
        ledger
            .connection()
            .execute("INSERT INTO extension_probe (value) VALUES ('again')", [])
            .expect("write after reopen");
    }
    {
        let restored_ledger = Ledger::restore_with_migrations(&backup, &restored, &[extension])
            .expect("restore_with_migrations must reuse the same complete set");
        let value: String = restored_ledger
            .connection()
            .query_row("SELECT value FROM extension_probe", [], |row| row.get(0))
            .expect("read restored durable value");
        assert_eq!(value, "durable");
        assert_eq!(restored_ledger.additional_migrations().len(), 1);
    }
    assert!(matches!(
        Ledger::restore_with_migrations(&backup, &drifted_dest, &[drifted]),
        Err(LedgerError::ChecksumDrift { version, .. }) if version == LATEST_SCHEMA_VERSION + 1
    ));
    assert!(
        !drifted_dest.exists(),
        "drifted restore must not publish a destination"
    );
    assert!(matches!(
        Ledger::open(&path),
        Err(LedgerError::NewerSchema {
            found,
            supported: LATEST_SCHEMA_VERSION
        }) if found == LATEST_SCHEMA_VERSION + 1
    ));
    let memory = Ledger::open_in_memory_with_migrations(&[extension])
        .expect("in-memory open accepts the complete migration set");
    memory
        .connection()
        .execute("INSERT INTO extension_probe (value) VALUES ('memory')", [])
        .expect("write through in-memory extension schema");
    std::fs::remove_file(path).expect("remove test database");
    std::fs::remove_file(backup).expect("remove backup");
    std::fs::remove_file(restored).expect("remove restored");
}

#[test]
fn extension_checksum_drift() {
    let path = database_path("extension-drift");
    let backup = database_path("extension-drift-backup");
    let drifted_dest = database_path("extension-drift-restored");
    let original_checksum = digest(EXTENSION_SQL);
    let original = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        EXTENSION_PATH,
        &original_checksum,
        EXTENSION_SQL,
    );
    {
        let mut ledger =
            Ledger::open_with_migrations(&path, &[original]).expect("open with extension");
        ledger
            .backup(&backup)
            .expect("snapshot the original complete set");
    }
    let drifted_checksum = digest(EXTENSION_DRIFT_SQL);
    let drifted = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        EXTENSION_PATH,
        &drifted_checksum,
        EXTENSION_DRIFT_SQL,
    );
    let mismatched = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        EXTENSION_PATH,
        &original_checksum,
        EXTENSION_DRIFT_SQL,
    );
    Ledger::open_with_migrations(&path, &[original])
        .expect("reopen with the original complete set");
    assert!(matches!(
        Ledger::open_with_migrations(&path, &[mismatched]),
        Err(LedgerError::ChecksumDrift { version, .. }) if version == LATEST_SCHEMA_VERSION + 1
    ));
    assert!(matches!(
        Ledger::open_with_migrations(&path, &[drifted]),
        Err(LedgerError::ChecksumDrift { version, .. }) if version == LATEST_SCHEMA_VERSION + 1
    ));
    assert!(matches!(
        Ledger::restore_with_migrations(&backup, &drifted_dest, &[drifted]),
        Err(LedgerError::ChecksumDrift { version, .. }) if version == LATEST_SCHEMA_VERSION + 1
    ));
    assert!(
        !drifted_dest.exists(),
        "drifted restore must not publish a destination"
    );
    let gapped_checksum = digest(EXTENSION_SQL);
    let gapped = Migration::register(
        12,
        "schemas/0012_extension.sql",
        &gapped_checksum,
        EXTENSION_SQL,
    );
    assert!(matches!(
        Ledger::open_with_migrations(&path, &[gapped]),
        Err(LedgerError::InvalidMigrations(_))
    ));
    std::fs::remove_file(path).expect("remove test database");
    std::fs::remove_file(backup).expect("remove backup");
}

#[test]
fn rejects_whitespace_and_duplicate_paths() {
    let sql = "CREATE TABLE extension_probe (value TEXT NOT NULL) STRICT;";
    let checksum = digest(sql);
    let whitespace = Migration::register(
        LATEST_SCHEMA_VERSION + 1,
        " schemas/0008_x.sql",
        &checksum,
        sql,
    );
    assert!(matches!(
        Ledger::open_with_migrations(
            database_path("whitespace-path"),
            &[whitespace]
        ),
        Err(LedgerError::InvalidMigrations(message))
            if message.contains("canonical schema path")
    ));
    // Distinct versions, one canonical path: the path-reuse contract.
    let duplicate = [
        Migration::register(
            LATEST_SCHEMA_VERSION + 1,
            "schemas/0008_x.sql",
            &checksum,
            sql,
        ),
        Migration::register(
            LATEST_SCHEMA_VERSION + 2,
            "schemas/0008_x.sql",
            &checksum,
            sql,
        ),
    ];
    assert!(matches!(
        Ledger::open_with_migrations(database_path("duplicate-path"), &duplicate),
        Err(LedgerError::InvalidMigrations(message))
            if message.contains("reuses canonical path")
    ));
}

#[test]
fn rejects_old_migration_names_and_null_checksums() {
    let legacy = database_path("legacy-name-drift");
    {
        let connection = write_precompatibility_database(&legacy);
        connection
            .execute(
                "UPDATE schema_migrations SET name = 'm1_ledger' WHERE version = 2",
                [],
            )
            .expect("restore old migration name");
    }
    assert!(matches!(
        Ledger::open(&legacy),
        Err(LedgerError::InvalidMigrations(message))
            if message.contains("stored name") && message.contains("m1_ledger")
    ));
    std::fs::remove_file(legacy).expect("remove legacy drift database");

    let missing = database_path("legacy-null-checksum");
    {
        let connection = write_precompatibility_database(&missing);
        connection
            .execute(
                "UPDATE schema_migrations SET checksum = NULL WHERE version = 1",
                [],
            )
            .expect("clear migration checksum");
    }
    assert!(matches!(
        Ledger::open(&missing),
        Err(LedgerError::ChecksumDrift { found, .. }) if found == "<null>"
    ));
    std::fs::remove_file(missing).expect("remove null-checksum database");
}

#[test]
fn effect_receipt_migration_upgrades_v6_and_reopens() {
    let path = database_path("effect-receipt-upgrade");
    {
        // Build a genuine v6 ledger: the runner applies exactly the
        // first six builtin migrations, so the reopen below replays the
        // real effect-receipt migration on top of a real v6 shape.
        let mut connection = Connection::open(&path).expect("open v6 fixture");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin v6 fixture transaction");
        apply_migrations(&transaction, &BUILTIN_MIGRATIONS[..6], 6)
            .expect("apply migrations 1 through 6");
        transaction.commit().expect("commit v6 fixture");
        let version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read downgraded version");
        assert_eq!(version, 6);
    }
    {
        let ledger = Ledger::open(&path).expect("upgrade v6 ledger");
        let applied: (String, String) = ledger
            .connection()
            .query_row(
                "SELECT name, checksum FROM schema_migrations WHERE version = 7",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read receipt migration identity");
        assert_eq!(
            applied,
            (
                "schemas/0007_m85_effect_receipts.sql".to_owned(),
                EFFECT_RECEIPTS_CHECKSUM.to_owned(),
            )
        );
        let exists: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'effect_receipts'",
                [],
                |row| row.get(0),
            )
            .expect("inspect receipt table");
        assert_eq!(exists, 1);
    }
    Ledger::open(&path).expect("reopen upgraded receipt ledger");
    std::fs::remove_file(path).expect("remove receipt upgrade database");
}

#[test]
fn policy_ledger_tables_are_installed_on_open() {
    let path = database_path("policy-tables");
    let ledger = Ledger::open(&path).expect("open ledger with policy schema");
    let version: i64 = ledger
        .connection()
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .expect("read schema version");
    assert_eq!(version, LATEST_SCHEMA_VERSION);
    for table in ["budget_accounts", "budget_reservations"] {
        let exists: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("inspect {table}: {error}"));
        assert_eq!(exists, 1, "{table} must exist after Ledger::open");
    }
    for (table, column) in [
        ("leases", "acquired_logical"),
        ("leases", "expires_logical"),
        ("heartbeats", "observed_logical"),
        ("provider_leases", "started_logical"),
        ("incidents", "recovery_policy_revision"),
        ("incidents", "recovery_policy_digest"),
    ] {
        let exists: i64 = ledger
            .connection()
            .query_row(
                &format!("SELECT COUNT(*) FROM pragma_table_info('{table}') WHERE name=?1"),
                [column],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("inspect {table}.{column}: {error}"));
        assert_eq!(exists, 1, "{table}.{column} must exist after Ledger::open");
    }
    std::fs::remove_file(path).expect("remove test database");
}

/// The real migration engine upgrades a populated v12 ledger carrying the
/// historical kube-operation shape — one terminal-rejected operation and
/// its replayed alias receipt — to the current-operation schema: the
/// rebuilt table keeps every operation and attempt column byte-identical
/// (timestamps included), the attempt foreign key survives the parent
/// swap through a real COMMIT with zero violations, and the family rule
/// moves from "one row of any state forever" to "one current pending or
/// applied operation, with rejection history allowed to grow".
#[test]
fn kube_operation_current_migration_preserves_rejected_history_and_receipts() {
    let path = database_path("kube-operation-current-upgrade");
    let operation_fingerprint = "blake3:11eb8e06fingerprint";
    {
        // Build a genuine v12 ledger and populate it with the exact
        // historical upgrade shape: the rejected create and the alias
        // receipt that replayed it.
        let mut connection = Connection::open(&path).expect("open v12 fixture");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enforce the production foreign-key posture");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin v12 fixture transaction");
        apply_migrations(&transaction, &BUILTIN_MIGRATIONS[..12], 12)
            .expect("apply migrations 1 through 12");
        transaction
            .execute(
                "INSERT INTO kube_job_runs(run_id,cluster,namespace,launch_json,created_at) \
                 VALUES('run-live','test-cluster','test-namespace','{\"launch\":true}',\
                        '2026-09-24T07:42:35.394Z')",
                [],
            )
            .expect("seed admitted run");
        transaction
            .execute(
                "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
                     idempotency_digest,fingerprint,request_json,state,result_json,\
                     failure_kind,failure_reason,created_at,updated_at) \
                 VALUES('op-cfbd36ed','run-live','test-cluster','test-namespace','create',\
                        'blake3:b6a2digest',?1,'{\"workload\":{\"name\":\"probe\"}}','rejected',\
                        NULL,'rejected','proved rejection before any write',\
                        '2026-09-24T07:42:35.392Z','2026-09-24T07:42:35.566Z')",
                [operation_fingerprint],
            )
            .expect("seed rejected operation");
        transaction
            .execute(
                "INSERT INTO kube_job_attempts(attempt_id,operation_id,canonical_operation_id,\
                     request_fingerprint,verdict,reason,created_at) \
                 VALUES(1,'op-cfbd36ed','op-cfbd36ed',?1,'rejected',\
                        'proved rejection before any write','2026-09-24T07:42:35.566Z')",
                [operation_fingerprint],
            )
            .expect("seed canonical receipt");
        transaction
            .execute(
                "INSERT INTO kube_job_attempts(attempt_id,operation_id,canonical_operation_id,\
                     request_fingerprint,verdict,reason,created_at) \
                 VALUES(2,'op-a4e7f042','op-cfbd36ed',?1,'replayed',NULL,\
                        '2026-09-24T11:57:07.986Z')",
                [operation_fingerprint],
            )
            .expect("seed replayed alias receipt");
        transaction.commit().expect("commit v12 fixture");
    }
    {
        // The real engine performs the upgrade: the table rebuild, its
        // deferred foreign-key obligations, and the schema_migrations
        // bookkeeping all survive one genuine COMMIT.
        let ledger = Ledger::open(&path).expect("upgrade v12 ledger");
        let version: i64 = ledger
            .connection()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read upgraded version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let applied: (String, String) = ledger
            .connection()
            .query_row(
                "SELECT name, checksum FROM schema_migrations WHERE version = 13",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read current-operation migration identity");
        assert_eq!(
            applied,
            (
                "schemas/0013_kube_operation_current.sql".to_owned(),
                KUBE_OPERATION_CURRENT_CHECKSUM.to_owned(),
            )
        );
        // Every operation column — settled verdict and timestamps
        // included — is byte-identical to the pre-upgrade row.
        let operation: (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            String,
        ) = ledger
            .connection()
            .query_row(
                "SELECT run_id,cluster,namespace,fingerprint,state,failure_kind,failure_reason,\
                     updated_at FROM kube_job_operations WHERE operation_id='op-cfbd36ed'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("rejected operation survives");
        assert_eq!(
            operation,
            (
                "run-live".to_owned(),
                "test-cluster".to_owned(),
                "test-namespace".to_owned(),
                operation_fingerprint.to_owned(),
                "rejected".to_owned(),
                Some("rejected".to_owned()),
                Some("proved rejection before any write".to_owned()),
                "2026-09-24T07:42:35.566Z".to_owned(),
            )
        );
        // Both receipts keep their identity, verdict, and ordering.
        let receipts: Vec<(i64, String, String, String)> = ledger
            .connection()
            .prepare(
                "SELECT attempt_id,operation_id,canonical_operation_id,verdict \
                     FROM kube_job_attempts ORDER BY attempt_id",
            )
            .expect("prepare receipt read")
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("read receipts")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect receipts");
        assert_eq!(
            receipts,
            vec![
                (
                    1,
                    "op-cfbd36ed".to_owned(),
                    "op-cfbd36ed".to_owned(),
                    "rejected".to_owned()
                ),
                (
                    2,
                    "op-a4e7f042".to_owned(),
                    "op-cfbd36ed".to_owned(),
                    "replayed".to_owned()
                ),
            ]
        );
        let violations: i64 = ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("run foreign key check");
        assert_eq!(violations, 0, "the upgraded ledger has no FK violations");
        // The attempt alias mapping stays indexed for per-admission
        // lookups.
        let alias_index: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE type = 'index' AND name = 'kube_job_attempt_alias'",
                [],
                |row| row.get(0),
            )
            .expect("inspect the alias mapping index");
        assert_eq!(
            alias_index, 1,
            "the attempt alias mapping must stay indexed"
        );
        // The family rule: rejection history may grow, but the family
        // keeps at most one current (pending or applied) operation.
        ledger
            .connection()
            .execute(
                "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
                     idempotency_digest,fingerprint,request_json,state,failure_kind,\
                     failure_reason,created_at,updated_at) \
                 VALUES('op-history-second','run-live','test-cluster','test-namespace','create',\
                        'blake3:b6a2digest','blake3:11eb8e06fingerprint',\
                        '{\"workload\":{\"name\":\"probe\"}}','rejected','rejected',\
                        'another proved rejection',\
                        '2026-09-24T12:00:00.000Z','2026-09-24T12:00:00.000Z')",
                [],
            )
            .expect("a second rejection joins the family history");
        // A fresh id over an only-rejected history legitimately mints
        // the family's single current operation.
        ledger
            .connection()
            .execute(
                "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
                     idempotency_digest,fingerprint,request_json,state,created_at,updated_at) \
                 VALUES('op-current-first','run-live','test-cluster','test-namespace','create',\
                        'blake3:b6a2digest','blake3:11eb8e06fingerprint',\
                        '{\"workload\":{\"name\":\"probe\"}}','pending',\
                        '2026-09-24T12:00:01.000Z','2026-09-24T12:00:01.000Z')",
                [],
            )
            .expect("a fresh id mints the family's current operation");
        let duplicate = ledger
            .connection()
            .execute(
                "INSERT INTO kube_job_operations(operation_id,run_id,cluster,namespace,kind,\
                     idempotency_digest,fingerprint,request_json,state,created_at,updated_at) \
                 VALUES('op-current-second','run-live','test-cluster','test-namespace','create',\
                        'blake3:b6a2digest','blake3:11eb8e06fingerprint',\
                        '{\"workload\":{\"name\":\"probe\"}}','pending',\
                        '2026-09-24T12:00:02.000Z','2026-09-24T12:00:02.000Z')",
                [],
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
            .expect_err("a second current operation violates the family identity");
        assert!(
            duplicate.contains("UNIQUE constraint failed"),
            "the partial unique index must refuse a second current row: {duplicate}"
        );
    }
    Ledger::open(&path).expect("reopen upgraded ledger");
    std::fs::remove_file(path).expect("remove upgrade database");
}

/// Migration 14 admits the terminal sandbox's transient service units
/// into the worker registry beside the scopes it has always owned. A
/// genuine v13 ledger upgrades through the real engine: every worker and
/// stop-intent row survives byte-identically with its foreign key, the
/// terminal service namespace registers, and every other service name
/// stays refused.
#[test]
fn terminal_service_units_migration_preserves_workers_and_intents() {
    let invocation_id = "0123456789abcdef0123456789abcdef";
    let path = database_path("terminal-service-units-upgrade");
    {
        // Build a v13 ledger with a running scope and a settled stop intent.
        let mut connection = Connection::open(&path).expect("open v13 fixture");
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .expect("enforce the production foreign-key posture");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin v13 fixture transaction");
        apply_migrations(&transaction, &BUILTIN_MIGRATIONS[..13], 13)
            .expect("apply migrations 1 through 13");
        transaction
            .execute(
                "INSERT INTO worker_registry(worker_id,unit,invocation_id,correlation_id,tx_id,\
                     wp_id,attempt,cgroup_path,cgroup_inode,leader_pid,leader_start_ticks,\
                     state,residue_json,created_at,updated_at) \
                 VALUES('wk-3333','e60ff7b2-1111-4222-8333-444455556666-attempt-1-7.scope',\
                        ?1,'corr-live','e60ff7b2-1111-4222',\
                        '4222',1,'/sys/fs/cgroup/.../7.scope',4242,4243,99,'payload_running',\
                        '{\"intent\":\"terminal\"}','2026-10-06T00:00:00Z',\
                        '2026-10-06T00:00:01Z')",
                [invocation_id],
            )
            .expect("seed proven scope row");
        transaction
            .execute(
                "INSERT INTO worker_stop_intent(worker_id,correlation_id,state,evidence_json,\
                     attempts,requested_at,updated_at,settled_at) \
                 VALUES('wk-3333','corr-live','stopped','{\"verdict\":\"stopped\"}',1,\
                        '2026-10-06T00:00:02Z','2026-10-06T00:00:03Z','2026-10-06T00:00:03Z')",
                [],
            )
            .expect("seed settled stop intent");
        transaction.commit().expect("commit v13 fixture");
    }
    {
        // The real engine performs the upgrade: the CHECK-only table
        // rebuild, the stop-intent foreign key, and the schema_migrations
        // bookkeeping all survive one genuine COMMIT.
        let ledger = Ledger::open(&path).expect("upgrade v13 ledger");
        let version: i64 = ledger
            .connection()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("read upgraded version");
        assert_eq!(version, LATEST_SCHEMA_VERSION);
        let applied: (String, String) = ledger
            .connection()
            .query_row(
                "SELECT name, checksum FROM schema_migrations WHERE version = 14",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read terminal-service migration identity");
        assert_eq!(
            applied,
            (
                "schemas/0014_terminal_service_units.sql".to_owned(),
                TERMINAL_SERVICE_UNITS_CHECKSUM.to_owned(),
            )
        );
        // Every worker column survives byte-identically.
        let worker: (String, Option<String>, String, i64, String) = ledger
            .connection()
            .query_row(
                "SELECT unit,invocation_id,state,cgroup_inode,residue_json \
                     FROM worker_registry WHERE worker_id='wk-3333'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("proven scope survives");
        assert_eq!(
            worker,
            (
                "e60ff7b2-1111-4222-8333-444455556666-attempt-1-7.scope".to_owned(),
                Some(invocation_id.to_owned()),
                "payload_running".to_owned(),
                4242,
                "{\"intent\":\"terminal\"}".to_owned(),
            )
        );
        // The stop intent keeps its row and its foreign key.
        let intent: (String, String, Option<String>) = ledger
            .connection()
            .query_row(
                "SELECT state,evidence_json,settled_at FROM worker_stop_intent \
                     WHERE worker_id='wk-3333'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("settled stop intent survives");
        assert_eq!(
            intent,
            (
                "stopped".to_owned(),
                "{\"verdict\":\"stopped\"}".to_owned(),
                Some("2026-10-06T00:00:03Z".to_owned()),
            )
        );
        let violations: i64 = ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .expect("run foreign key check");
        assert_eq!(violations, 0, "the upgraded ledger has no FK violations");
        // The registry index survives the rebuild.
        let correlation_index: i64 = ledger
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema \
                     WHERE type = 'index' AND name = 'worker_registry_correlation'",
                [],
                |row| row.get(0),
            )
            .expect("inspect the registry correlation index");
        assert_eq!(correlation_index, 1);
        // The new admission: exactly the terminal sandbox's service
        // namespace joins the scopes.
        ledger
            .connection()
            .execute(
                "INSERT INTO worker_registry(worker_id,unit,correlation_id,tx_id,wp_id,attempt,\
                     state,residue_json,created_at,updated_at) \
                 VALUES('wk-4444','odin-term-e60ff7b2.service','corr-term','term','term',1,\
                        'registered','{}','2026-10-06T00:00:04Z','2026-10-06T00:00:04Z')",
                [],
            )
            .expect("a terminal service unit registers beside the scopes");
        let refused = ledger
            .connection()
            .execute(
                "INSERT INTO worker_registry(worker_id,unit,correlation_id,tx_id,wp_id,attempt,\
                     state,residue_json,created_at,updated_at) \
                 VALUES('wk-5555','agent-harness.service','corr-stray','stray','stray',1,\
                        'registered','{}','2026-10-06T00:00:05Z','2026-10-06T00:00:05Z')",
                [],
            )
            .map(|_| ())
            .map_err(|error| error.to_string());
        assert!(
            refused
                .expect_err("a service outside the terminal namespace is refused")
                .contains("CHECK constraint failed"),
            "the unit CHECK must keep refusing stray services"
        );
    }
    Ledger::open(&path).expect("reopen upgraded ledger");
    std::fs::remove_file(path).expect("remove upgrade database");
}

#[test]
fn pod_worker_migration_upgrades_v13_and_reopens_durable_intent() {
    let path = database_path("pod-worker-v13");
    {
        let mut connection = Connection::open(&path).unwrap();
        let transaction = connection.transaction().unwrap();
        apply_migrations(&transaction, &BUILTIN_MIGRATIONS[..13], 13).unwrap();
        transaction.commit().unwrap();
    }
    let worker = "wkr0123456789abcdef0123456789abcdea";
    let identity = crate::pod::PodWorkerIdentity {
        cluster: "cluster".to_owned(),
        namespace: "namespace".to_owned(),
        pod_name: "terminal".to_owned(),
        pod_uid: None,
        policy_name: "terminal-egress".to_owned(),
        policy_uid: None,
        secret_name: None,
        secret_uid: None,
        correlation_id: "22222222222222222222222222222222".to_owned(),
    };
    {
        let mut ledger = Ledger::open(&path).unwrap();
        let checksum: String = ledger
            .connection()
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version=15",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(checksum, POD_WORKERS_CHECKSUM);
        assert_eq!(digest(POD_WORKERS_SCHEMA), POD_WORKERS_CHECKSUM);
        ledger
            .with_tx(|tx| {
                crate::pod::register_worker(tx, worker, &identity, time::OffsetDateTime::now_utc())
            })
            .unwrap();
        ledger
            .with_tx(|tx| {
                crate::pod::record_proof(
                    tx,
                    worker,
                    None,
                    Some("policy-uid"),
                    time::OffsetDateTime::now_utc(),
                )
            })
            .unwrap();
    }
    {
        let ledger = Ledger::open(&path).unwrap();
        let row = crate::pod::worker_row(ledger.connection(), worker)
            .unwrap()
            .unwrap();
        assert_eq!(row.phase, "registered");
        assert_eq!(row.identity.pod_uid, None);
        assert_eq!(row.identity.policy_uid.as_deref(), Some("policy-uid"));
        assert_eq!(
            crate::pod::pending_rows(ledger.connection(), None).unwrap(),
            vec![row]
        );
        let violations: i64 = ledger
            .connection()
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn secret_migration_preserves_v15_intent_and_reopens_uid_proof() {
    let path = database_path("pod-secret-v15");
    let worker = "wkr0123456789abcdef0123456789abcdea";
    {
        let mut connection = Connection::open(&path).unwrap();
        let tx = connection.transaction().unwrap();
        apply_migrations(&tx, &BUILTIN_MIGRATIONS[..15], 15).unwrap();
        tx.execute("INSERT INTO pod_worker_registry(worker_id,cluster,namespace,pod_name,policy_name,correlation_id,state,created_at,updated_at) VALUES (?1,'cluster','namespace','terminal','policy','correlation','registered','now','now')", [worker]).unwrap();
        tx.commit().unwrap();
    }
    {
        let mut ledger = Ledger::open(&path).unwrap();
        assert_eq!(digest(POD_SECRETS_SCHEMA), POD_SECRETS_CHECKSUM);
        let old = crate::pod::worker_row(ledger.connection(), worker)
            .unwrap()
            .unwrap();
        assert!(old.identity.secret_name.is_none() && old.identity.secret_uid.is_none());
        let mut identity = old.identity;
        identity.pod_name = "claude".to_owned();
        identity.policy_name = "claude-egress".to_owned();
        identity.correlation_id = "claude-correlation".to_owned();
        identity.secret_name = Some("claude-account-and-mcp".to_owned());
        let now = time::OffsetDateTime::now_utc();
        ledger
            .with_tx(|tx| {
                crate::pod::register_worker(tx, "secret-worker", &identity, now)?;
                crate::pod::record_secret_proof(tx, "secret-worker", Some("secret-uid"), now)
            })
            .unwrap();
    }
    {
        let ledger = Ledger::open(&path).unwrap();
        let row = crate::pod::worker_row(ledger.connection(), "secret-worker")
            .unwrap()
            .unwrap();
        assert_eq!(
            row.identity.secret_name.as_deref(),
            Some("claude-account-and-mcp")
        );
        assert_eq!(row.identity.secret_uid.as_deref(), Some("secret-uid"));
        assert_eq!(row.phase, "registered");
        assert!(crate::pod::pending_rows(ledger.connection(), None)
            .unwrap()
            .contains(&row));
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn retention_migration_preserves_ambiguous_secret_carriers_but_not_terminals() {
    let mut connection = Connection::open_in_memory().unwrap();
    migrate_inventory(&mut connection, &BUILTIN_MIGRATIONS[..16]).unwrap();
    connection.execute_batch(
        "INSERT INTO pod_worker_registry(worker_id,cluster,namespace,pod_name,policy_name,correlation_id,secret_name,pod_uid,policy_uid,state,created_at,updated_at)
         VALUES ('claude','cluster','namespace','claude','claude-egress','claude-correlation','account',NULL,NULL,'registered','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
                ('terminal','cluster','namespace','terminal','terminal-egress','terminal-correlation',NULL,'terminal-pod-uid','terminal-policy-uid','released','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z');"
    ).unwrap();
    migrate(&mut connection).unwrap();
    let retained = crate::pod::worker_row(&connection, "claude")
        .unwrap()
        .unwrap();
    assert!(retained.retained_workspace);
    assert!(retained.release_attempted);
    assert!(retained.stop_requires_admission());
    let disposable = crate::pod::worker_row(&connection, "terminal")
        .unwrap()
        .unwrap();
    assert!(!disposable.retained_workspace);
    assert!(!disposable.stop_requires_admission());
}
