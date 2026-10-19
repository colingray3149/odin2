use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::{LedgerError, LedgerResult};

pub const CONTROL_PLANE_SCHEMA: &str = include_str!("../../../schemas/0001_control_plane.sql");
pub const LANE_RUN_SCHEMA: &str = include_str!("../../../schemas/0002_m1_ledger.sql");
pub const COMPATIBILITY_SCHEMA: &str = include_str!("../../../schemas/0003_m1_compatibility.sql");
pub const AUTHORITY_SCHEMA: &str = include_str!("../../../schemas/0004_m85_authority.sql");
pub const WORKER_SCHEMA: &str = include_str!("../../../schemas/0005_m85_worker.sql");
pub const POLICY_LEDGER_SCHEMA: &str = include_str!("../../../schemas/0006_m85_policy_ledger.sql");
pub const EFFECT_RECEIPTS_SCHEMA: &str =
    include_str!("../../../schemas/0007_m85_effect_receipts.sql");
pub const JOBS_SCHEMA: &str = include_str!("../../../schemas/0008_m9_jobs.sql");
pub const KUBE_OPERATIONS_SCHEMA: &str =
    include_str!("../../../schemas/0009_m9_kube_operations.sql");
pub const CAPSULE_LEASE_REBIND_SCHEMA: &str =
    include_str!("../../../schemas/0010_capsule_lease_rebind.sql");
pub const APPROVAL_FEED_SCHEMA: &str = include_str!("../../../schemas/0011_approval_feed.sql");
pub const KUBE_STAGED_PATHS_SCHEMA: &str =
    include_str!("../../../schemas/0012_kube_staged_paths.sql");
pub const KUBE_OPERATION_CURRENT_SCHEMA: &str =
    include_str!("../../../schemas/0013_kube_operation_current.sql");
pub const TERMINAL_SERVICE_UNITS_SCHEMA: &str =
    include_str!("../../../schemas/0014_terminal_service_units.sql");
pub const POD_WORKERS_SCHEMA: &str = include_str!("../../../schemas/0015_pod_workers.sql");
pub const POD_SECRETS_SCHEMA: &str = include_str!("../../../schemas/0016_pod_secrets.sql");
pub const POD_SECRETS_CHECKSUM: &str =
    "00041d814b7f8b18e369af4b16462957c95f3b01ef77f45cec15ca8ee0110abb";
pub const POD_RETENTION_SCHEMA: &str = include_str!("../../../schemas/0017_pod_retention.sql");
pub const POD_RETENTION_CHECKSUM: &str =
    "c9eb62919f075e3e194d6fb9283f6546f664d85b434cecb054ab3e8fadcd3002";
pub const APPROVAL_OWNER_DECISIONS_SCHEMA: &str =
    include_str!("../../../schemas/0018_approval_owner_decisions.sql");
pub const APPROVAL_OWNER_DECISIONS_CHECKSUM: &str =
    "ed13c7e60623a4c4eb6733f0aaffa7759181c4adfd10346a62a99e3020feee9b";
pub const HOST_COMMAND_BINDINGS_SCHEMA: &str =
    include_str!("../../../schemas/0019_host_command_bindings.sql");
pub const HOST_COMMAND_BINDINGS_CHECKSUM: &str =
    "7711296e8308d191d59229fc3bd4f962ad0985fd01e36d509d3798f11a78a951";
pub const TRACE_SCHEMA: &str = include_str!("../../../schemas/0020_trace.sql");
pub const TRACE_CHECKSUM: &str = "b51e9ec3d783009df1b9b6934bd7a540ec2b6b4c6a704540e66c3d898e9e1e74";
pub const TRACE_CALL_SCHEMA: &str = include_str!("../../../schemas/0021_trace_call.sql");
pub const TRACE_CALL_CHECKSUM: &str =
    "c38575ea68f368d4b20b659c08d9887950604647e501889f1906c32821bf17af";

#[derive(Clone, Copy, Debug)]
pub struct Migration<'a> {
    pub version: i64,
    /// Repository-relative schema path, e.g. `schemas/0001_control_plane.sql`.
    pub path: &'a str,
    /// Independent expected BLAKE3; never derived from `sql` in production.
    pub checksum: &'a str,
    pub sql: &'a str,
}

pub const CONTROL_PLANE_CHECKSUM: &str =
    "a53ed5f9fe76f07dda3c700eee4264b2aa494d63004dd0119cddd94dda3e0e70";
pub const LANE_RUN_CHECKSUM: &str =
    "9fe371da8045f7097c370c63b163c48db16fdce596f2b922e7f70461851b4484";
pub const COMPATIBILITY_CHECKSUM: &str =
    "1fc13489cf4817447a379de92c1a5c51ca0f449d18a9ad952b4b7542b7ff074b";
pub const AUTHORITY_CHECKSUM: &str =
    "b854d8cb30f827f8baedf6ed8208fc7ef467370c32f97e1f0ee25d9314b03f9f";
pub const WORKER_CHECKSUM: &str =
    "4fb45048268de69af221fbe9b782729900efa5deb73052e9e1c2ba099040e0d8";
pub const POLICY_LEDGER_CHECKSUM: &str =
    "60eb8fea7db4e6830812f6a536d3ba56840c52b439af7926c38babea105907f8";
pub const EFFECT_RECEIPTS_CHECKSUM: &str =
    "be3ab3014d291fd3626aaeb630ac76c8ccae2e1ab98aa956622e6a0d6118d364";
pub const JOBS_CHECKSUM: &str = "bf804b564b3e54775fe20d25a4f4dd06a7206a5224c6cecd85a6c5535f2fa5a3";
pub const KUBE_OPERATIONS_CHECKSUM: &str =
    "3a4ba2935d63f93a2ad87f7486e61d36039c8480d738302294875b5c9342ead3";
pub const CAPSULE_LEASE_REBIND_CHECKSUM: &str =
    "c5ddc09d596beeeb5f2860b029ad5d693ba5b804bac26a22a6c25d5cde233306";
pub const APPROVAL_FEED_CHECKSUM: &str =
    "bf1100ef79a1276d5d1e56787b3e9685d0fb731ab88548cd55297eb283db4947";
pub const KUBE_STAGED_PATHS_CHECKSUM: &str =
    "78d0ce84546752d4a435dc47fb0aa20aa2a6dc3b32927731b19dd030db463b7e";
pub const KUBE_OPERATION_CURRENT_CHECKSUM: &str =
    "c5d2f13d4cef72cb08a229ea034c3f4bfcf5930d59464e4c25346a2338cc9119";
pub const TERMINAL_SERVICE_UNITS_CHECKSUM: &str =
    "802f156ef9e6183e74f95e802a63d49bd088fb6ee0577426045a44563e4aecf1";
pub const POD_WORKERS_CHECKSUM: &str =
    "7afd2f0fb4503ecb4be7ec1bd53795e3cba878632404c8cef923585a929b0a9f";

impl<'a> Migration<'a> {
    pub const fn register(version: i64, path: &'a str, checksum: &'a str, sql: &'a str) -> Self {
        Self {
            version,
            path,
            checksum,
            sql,
        }
    }

    pub fn checksum(self) -> String {
        self.checksum.to_owned()
    }
}

/// Owned copy of a caller-supplied extension migration so backup/restore can
/// reopen a snapshot against the same complete inventory the ledger was opened
/// with. Builtin migrations stay in [`BUILTIN_MIGRATIONS`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnedMigration {
    version: i64,
    path: String,
    checksum: String,
    sql: String,
}

impl OwnedMigration {
    pub(crate) fn capture(migrations: &[Migration<'_>]) -> Vec<Self> {
        migrations
            .iter()
            .map(|migration| Self {
                version: migration.version,
                path: migration.path.to_owned(),
                checksum: migration.checksum.to_owned(),
                sql: migration.sql.to_owned(),
            })
            .collect()
    }

    pub(crate) fn as_migration(&self) -> Migration<'_> {
        Migration::register(self.version, &self.path, &self.checksum, &self.sql)
    }
}

pub const BUILTIN_MIGRATIONS: [Migration<'static>; 21] = [
    Migration::register(
        1,
        "schemas/0001_control_plane.sql",
        CONTROL_PLANE_CHECKSUM,
        CONTROL_PLANE_SCHEMA,
    ),
    Migration::register(
        2,
        "schemas/0002_m1_ledger.sql",
        LANE_RUN_CHECKSUM,
        LANE_RUN_SCHEMA,
    ),
    Migration::register(
        3,
        "schemas/0003_m1_compatibility.sql",
        COMPATIBILITY_CHECKSUM,
        COMPATIBILITY_SCHEMA,
    ),
    Migration::register(
        4,
        "schemas/0004_m85_authority.sql",
        AUTHORITY_CHECKSUM,
        AUTHORITY_SCHEMA,
    ),
    Migration::register(
        5,
        "schemas/0005_m85_worker.sql",
        WORKER_CHECKSUM,
        WORKER_SCHEMA,
    ),
    Migration::register(
        6,
        "schemas/0006_m85_policy_ledger.sql",
        POLICY_LEDGER_CHECKSUM,
        POLICY_LEDGER_SCHEMA,
    ),
    Migration::register(
        7,
        "schemas/0007_m85_effect_receipts.sql",
        EFFECT_RECEIPTS_CHECKSUM,
        EFFECT_RECEIPTS_SCHEMA,
    ),
    Migration::register(8, "schemas/0008_m9_jobs.sql", JOBS_CHECKSUM, JOBS_SCHEMA),
    Migration::register(
        9,
        "schemas/0009_m9_kube_operations.sql",
        KUBE_OPERATIONS_CHECKSUM,
        KUBE_OPERATIONS_SCHEMA,
    ),
    Migration::register(
        10,
        "schemas/0010_capsule_lease_rebind.sql",
        CAPSULE_LEASE_REBIND_CHECKSUM,
        CAPSULE_LEASE_REBIND_SCHEMA,
    ),
    Migration::register(
        11,
        "schemas/0011_approval_feed.sql",
        APPROVAL_FEED_CHECKSUM,
        APPROVAL_FEED_SCHEMA,
    ),
    Migration::register(
        12,
        "schemas/0012_kube_staged_paths.sql",
        KUBE_STAGED_PATHS_CHECKSUM,
        KUBE_STAGED_PATHS_SCHEMA,
    ),
    Migration::register(
        13,
        "schemas/0013_kube_operation_current.sql",
        KUBE_OPERATION_CURRENT_CHECKSUM,
        KUBE_OPERATION_CURRENT_SCHEMA,
    ),
    Migration::register(
        14,
        "schemas/0014_terminal_service_units.sql",
        TERMINAL_SERVICE_UNITS_CHECKSUM,
        TERMINAL_SERVICE_UNITS_SCHEMA,
    ),
    Migration::register(
        15,
        "schemas/0015_pod_workers.sql",
        POD_WORKERS_CHECKSUM,
        POD_WORKERS_SCHEMA,
    ),
    Migration::register(
        16,
        "schemas/0016_pod_secrets.sql",
        POD_SECRETS_CHECKSUM,
        POD_SECRETS_SCHEMA,
    ),
    Migration::register(
        17,
        "schemas/0017_pod_retention.sql",
        POD_RETENTION_CHECKSUM,
        POD_RETENTION_SCHEMA,
    ),
    Migration::register(
        18,
        "schemas/0018_approval_owner_decisions.sql",
        APPROVAL_OWNER_DECISIONS_CHECKSUM,
        APPROVAL_OWNER_DECISIONS_SCHEMA,
    ),
    Migration::register(
        19,
        "schemas/0019_host_command_bindings.sql",
        HOST_COMMAND_BINDINGS_CHECKSUM,
        HOST_COMMAND_BINDINGS_SCHEMA,
    ),
    Migration::register(20, "schemas/0020_trace.sql", TRACE_CHECKSUM, TRACE_SCHEMA),
    Migration::register(
        21,
        "schemas/0021_trace_call.sql",
        TRACE_CALL_CHECKSUM,
        TRACE_CALL_SCHEMA,
    ),
];

/// The schema version every builtin migration reaches. Snapshot extensions
/// register above it; reopening above the supported version fails closed.
pub const LATEST_SCHEMA_VERSION: i64 = 21;

pub fn migrate(connection: &mut Connection) -> LedgerResult<()> {
    migrate_with(connection, &[])
}

pub fn migrate_with(connection: &mut Connection, additional: &[Migration<'_>]) -> LedgerResult<()> {
    let mut migrations = Vec::with_capacity(BUILTIN_MIGRATIONS.len() + additional.len());
    migrations.extend(BUILTIN_MIGRATIONS);
    migrations.extend_from_slice(additional);
    migrate_inventory(connection, &migrations)
}

/// Applies a complete independent migration inventory atomically.
pub(crate) fn migrate_inventory(
    connection: &mut Connection,
    migrations: &[Migration<'_>],
) -> LedgerResult<()> {
    validate_migrations(migrations)?;
    let supported = migrations.last().map_or(0, |migration| migration.version);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    apply_migrations(&transaction, migrations, supported)?;
    transaction.commit()?;
    Ok(())
}

fn validate_migrations(migrations: &[Migration<'_>]) -> LedgerResult<()> {
    let mut seen_paths = std::collections::BTreeSet::new();
    for (index, migration) in migrations.iter().enumerate() {
        let expected = i64::try_from(index + 1)
            .map_err(|_| LedgerError::InvalidMigrations("too many migrations".to_owned()))?;
        if migration.version != expected {
            return Err(LedgerError::InvalidMigrations(format!(
                "expected version {expected}, found {}",
                migration.version
            )));
        }
        if migration.path.trim() != migration.path || !is_registered_path(migration.path) {
            return Err(LedgerError::InvalidMigrations(format!(
                "migration {} path {:?} is not a canonical schema path",
                migration.version, migration.path
            )));
        }
        if !seen_paths.insert(migration.path) {
            return Err(LedgerError::InvalidMigrations(format!(
                "migration {} reuses canonical path {:?}",
                migration.version, migration.path
            )));
        }
        if migration.sql.trim().is_empty() {
            return Err(LedgerError::InvalidMigrations(format!(
                "migration {} has an empty SQL body",
                migration.version
            )));
        }
        if !is_blake3_hex(migration.checksum) {
            return Err(LedgerError::InvalidMigrations(format!(
                "migration {} checksum is not a BLAKE3 hex digest",
                migration.version
            )));
        }
        let found = blake3::hash(migration.sql.as_bytes()).to_hex().to_string();
        if found != migration.checksum {
            return Err(LedgerError::ChecksumDrift {
                version: migration.version,
                expected: migration.checksum.to_owned(),
                found,
            });
        }
    }
    Ok(())
}

fn is_registered_path(path: &str) -> bool {
    path.starts_with("schemas/")
        && path.ends_with(".sql")
        && !path.contains("..")
        && !path.contains("//")
}

fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn apply_migrations(
    transaction: &Transaction<'_>,
    migrations: &[Migration<'_>],
    supported: i64,
) -> LedgerResult<()> {
    let applied = read_applied_migrations(transaction)?;
    let found = applied.last().map_or(0, |entry| entry.version);
    if found > supported {
        return Err(LedgerError::NewerSchema { found, supported });
    }
    for (index, entry) in applied.iter().enumerate() {
        let expected_version = i64::try_from(index + 1).map_err(|_| {
            LedgerError::InvalidMigrations("too many applied migrations".to_owned())
        })?;
        if entry.version != expected_version {
            return Err(LedgerError::InvalidMigrations(format!(
                "database migration history has a gap before version {}",
                entry.version
            )));
        }
        let migration = migrations
            .get(index)
            .ok_or(LedgerError::NewerSchema { found, supported })?;
        if !stored_name_matches(entry, *migration)? {
            return Err(LedgerError::InvalidMigrations(format!(
                "migration {} stored name {:?} does not match canonical path {:?}",
                entry.version, entry.name, migration.path
            )));
        }
        if let Some(found_checksum) = &entry.checksum {
            let expected = migration.checksum();
            if *found_checksum != expected {
                return Err(LedgerError::ChecksumDrift {
                    version: entry.version,
                    expected,
                    found: found_checksum.clone(),
                });
            }
        } else {
            return Err(LedgerError::ChecksumDrift {
                version: entry.version,
                expected: migration.checksum(),
                found: "<null>".to_owned(),
            });
        }
    }

    let mut current = found;
    for migration in migrations
        .iter()
        .filter(|migration| migration.version > found)
    {
        transaction.execute_batch(transactional_sql(*migration)?)?;
        current = migration.version;
        if migration_metadata_available(transaction)? {
            record_migration(transaction, *migration)?;
        }
    }
    if migration_metadata_available(transaction)? {
        // Re-record applied rows so a repaired checksum is the frozen digest.
        for migration in migrations
            .iter()
            .filter(|migration| migration.version <= current)
        {
            record_migration(transaction, *migration)?;
        }
    }
    Ok(())
}

fn stored_name_matches(entry: &AppliedMigration, migration: Migration<'_>) -> LedgerResult<bool> {
    Ok(entry.name.as_deref() == Some(migration.path))
}

/// Strips migration 1's embedded transaction preamble (its standalone
/// PRAGMA statements) exactly: the runner already opens its own immediate
/// transaction, so the canonical text must never execute a nested one, and
/// `configure_connection` owns those pragmas. Every other migration applies
/// its full registered body.
fn transactional_sql(migration: Migration<'_>) -> LedgerResult<&str> {
    if migration.path != "schemas/0001_control_plane.sql" {
        return Ok(migration.sql);
    }
    migration.sql.find("CREATE TABLE").map_or_else(
        || {
            Err(LedgerError::InvalidMigrations(
                "canonical migration 1 contains no schema body".to_owned(),
            ))
        },
        |start| Ok(&migration.sql[start..]),
    )
}

struct AppliedMigration {
    version: i64,
    name: Option<String>,
    checksum: Option<String>,
}

fn read_applied_migrations(transaction: &Transaction<'_>) -> LedgerResult<Vec<AppliedMigration>> {
    if !table_exists(transaction, "schema_migrations")? {
        return Ok(Vec::new());
    }
    let sql = if migration_metadata_available(transaction)? {
        "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
    } else {
        "SELECT version, NULL, NULL FROM schema_migrations ORDER BY version"
    };
    let mut statement = transaction.prepare(sql)?;
    let rows = statement.query_map([], |row| {
        Ok(AppliedMigration {
            version: row.get(0)?,
            name: row.get(1)?,
            checksum: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn table_exists(transaction: &Transaction<'_>, table: &str) -> LedgerResult<bool> {
    Ok(transaction
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn migration_metadata_available(transaction: &Transaction<'_>) -> LedgerResult<bool> {
    if !table_exists(transaction, "schema_migrations")? {
        return Ok(false);
    }
    let mut statement = transaction.prepare("PRAGMA table_info(schema_migrations)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|column| column == "name")
        && columns.iter().any(|column| column == "checksum"))
}

fn record_migration(transaction: &Transaction<'_>, migration: Migration<'_>) -> LedgerResult<()> {
    transaction.execute(
        "INSERT INTO schema_migrations(version, applied_at, name, checksum) \
         VALUES (?1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?2, ?3) \
         ON CONFLICT(version) DO UPDATE SET name = excluded.name, checksum = excluded.checksum",
        params![migration.version, migration.path, migration.checksum],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
