use super::*;

pub(super) fn run_sys_08(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-08", sys_08_body, context, deadline)
}

const REQUIRED_LEDGER_TABLES: [&str; 4] = ["commands", "audit_events", "idempotency_keys", "lanes"];

const ALLOWED_TERMINAL_STATUSES: [&str; 6] = [
    "completed",
    "failed",
    "blocked",
    "cancelled",
    "expired",
    "rejected",
];

fn sys_08_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let (_, config) = require_config(context)?;
    ledger_integrity(&config.paths.state_root.join("ledger.sqlite3"), deadline)
}

/// Six fixed phases share the existing eight-note evidence budget with the
/// ledger path and audit cursor summary. No row contents or SQL are diagnostic
/// payloads.
struct LedgerPhases {
    evidence: Vec<String>,
    current: Option<(&'static str, Instant)>,
}

impl LedgerPhases {
    fn next(&mut self, phase: &'static str) {
        self.finish("ok");
        self.current = Some((phase, Instant::now()));
    }

    fn finish(&mut self, outcome: &str) {
        if let Some((phase, started)) = self.current.take() {
            note_evidence(
                &mut self.evidence,
                format!(
                    "phase={phase} elapsed_ms={} outcome={outcome}",
                    elapsed_millis(started)
                ),
            );
        }
    }
}

fn ledger_integrity(ledger_path: &Path, deadline: Instant) -> Outcome {
    ledger_integrity_with_setup(ledger_path, deadline, |_, _| {})
}

fn ledger_integrity_with_setup(
    ledger_path: &Path,
    deadline: Instant,
    setup: impl FnOnce(&Connection, &Arc<std::sync::atomic::AtomicBool>),
) -> Outcome {
    let mut phases = LedgerPhases {
        evidence: Vec::new(),
        current: None,
    };
    if !ledger_path.is_file() {
        return Err(CheckFailure::fail(
            "ledger-absent",
            format!("the configured ledger {} is absent", ledger_path.display()),
        ));
    }
    note_evidence(
        &mut phases.evidence,
        format!("ledger={}", ledger_path.display()),
    );
    let Some(budget) = deadline.checked_duration_since(Instant::now()) else {
        phases.next("open");
        phases.finish("interrupted");
        return Err(CheckFailure {
            evidence: phases.evidence,
            ..ledger_timeout()
        });
    };

    // Strictly read-only: the production ledger is opened through SQLite's
    // read-only mode; no migration, write, or checkpoint ever runs here.
    let opened = Instant::now();
    let connection = Connection::open_with_flags(
        ledger_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| {
        phases.current = Some(("open", opened));
        phases.finish("failed");
        CheckFailure {
            evidence: std::mem::take(&mut phases.evidence),
            ..CheckFailure::fail(
                "ledger-open-failed",
                format!("the ledger is corrupt or unreadable: {error}"),
            )
        }
    })?;
    let _ = connection.busy_timeout(budget);
    let interrupt_handle = connection.get_interrupt_handle();
    let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired = Arc::clone(&interrupted);
    setup(&connection, &interrupted);
    let (finished, watchdog) = mpsc::channel::<()>();
    thread::spawn(move || {
        if watchdog.recv_timeout(budget).is_err() {
            interrupt_ledger(&interrupt_handle, &fired);
        }
    });
    let verdict = ledger_checks(&connection, &mut phases);
    let _ = finished.send(());
    let timed_out = interrupted.load(std::sync::atomic::Ordering::SeqCst);
    phases.finish(if verdict.is_ok() {
        "ok"
    } else if timed_out {
        "interrupted"
    } else {
        "failed"
    });
    match verdict {
        Err(failure) if timed_out => Err(CheckFailure {
            summary: format!("{} ({})", ledger_timeout().summary, failure.summary),
            evidence: phases.evidence,
            ..ledger_timeout()
        }),
        Err(failure) => Err(CheckFailure {
            evidence: phases.evidence,
            ..failure
        }),
        Ok(()) => CheckOutcome::pass(
            "the configured production ledger passes read-only integrity, schema, sequence, and state checks",
            phases.evidence,
        ),
    }
}

fn interrupt_ledger(handle: &rusqlite::InterruptHandle, fired: &std::sync::atomic::AtomicBool) {
    fired.store(true, std::sync::atomic::Ordering::SeqCst);
    handle.interrupt();
}

fn ledger_timeout() -> CheckFailure {
    CheckFailure::fail(
        "ledger-integrity-timeout",
        "the ledger integrity check did not finish before the check deadline",
    )
}

fn ledger_checks(connection: &Connection, phases: &mut LedgerPhases) -> Result<(), CheckFailure> {
    phases.next("integrity");
    let integrity: String = connection
        .query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))
        .map_err(|error| {
            CheckFailure::fail(
                "ledger-integrity-failed",
                format!("the ledger failed SQLite integrity checking: {error}"),
            )
        })?;
    if integrity != "ok" {
        return Err(CheckFailure::fail(
            "ledger-integrity-failed",
            format!("the ledger failed SQLite integrity checking: {integrity}"),
        ));
    }
    phases.next("schema");
    for table in REQUIRED_LEDGER_TABLES {
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .map_err(|error| {
                CheckFailure::fail(
                    "ledger-schema-query-failed",
                    format!("ledger schema query for {table} failed: {error}"),
                )
            })?;
        if present != 1 {
            return Err(CheckFailure::fail(
                "ledger-schema-mismatch",
                format!("the ledger is missing required table {table:?}"),
            ));
        }
    }
    phases.next("foreign-keys");
    {
        let mut statement = connection
            .prepare("PRAGMA foreign_key_check")
            .map_err(|error| {
                CheckFailure::fail(
                    "ledger-schema-query-failed",
                    format!("ledger foreign-key check failed to prepare: {error}"),
                )
            })?;
        let mut rows = statement.query([]).map_err(|error| {
            CheckFailure::fail(
                "ledger-schema-query-failed",
                format!("ledger foreign-key check failed: {error}"),
            )
        })?;
        if rows
            .next()
            .map_err(|error| CheckFailure::fail("ledger-schema-query-failed", error.to_string()))?
            .is_some()
        {
            return Err(CheckFailure::fail(
                "ledger-foreign-key-violation",
                "the ledger contains dangling foreign-key references",
            ));
        }
    }
    phases.next("audit-sequence");
    // Audit sequences are positive append-order cursors, not dense counts; the allocator must cover every stored sequence.
    // SQLite conflicts can consume positions without rows, so gaps neither establish nor rule out lost events; report them without repair.
    let (audit_count, audit_min, audit_max, allocator): (
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    ) = connection
        .query_row(
            "SELECT COUNT(*), MIN(sequence), MAX(sequence),
                    (SELECT seq FROM sqlite_sequence WHERE name='audit_events')
             FROM audit_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| {
            CheckFailure::fail(
                "ledger-audit-query-failed",
                format!("ledger audit sequence query failed: {error}"),
            )
        })?;
    let audit_note = match (audit_min, audit_max) {
        (Some(first), Some(last)) => {
            if first < 1 {
                return Err(CheckFailure::fail(
                    "ledger-audit-sequence-invalid",
                    format!(
                        "an audit row sits at sequence {first}, at or below the read cursor origin"
                    ),
                ));
            }
            let Some(allocator) = allocator.filter(|allocator| *allocator >= last) else {
                return Err(CheckFailure::fail(
                    "ledger-audit-allocator-inconsistent",
                    format!(
                        "the audit sequence allocator ({allocator:?}) does not cover the last audit sequence {last}"
                    ),
                ));
            };
            format!(
                "audit-events={audit_count} first={first} last={last} unoccupied-in-span={} allocator={allocator}",
                last - first + 1 - audit_count
            )
        }
        _ => format!("audit-events={audit_count} allocator={allocator:?}"),
    };
    phases.next("command-state");
    {
        let mut statement = connection
            .prepare("SELECT DISTINCT terminal_status FROM commands")
            .map_err(|error| {
                CheckFailure::fail(
                    "ledger-command-query-failed",
                    format!("ledger command status query failed to prepare: {error}"),
                )
            })?;
        let statuses = statement
            .query_map([], |row| row.get::<_, Option<String>>(0))
            .map_err(|error| {
                CheckFailure::fail(
                    "ledger-command-query-failed",
                    format!("ledger command status query failed: {error}"),
                )
            })?;
        for status in statuses {
            let status = status.map_err(|error| {
                CheckFailure::fail(
                    "ledger-command-query-failed",
                    format!("ledger command status query failed: {error}"),
                )
            })?;
            if let Some(status) = status {
                if !ALLOWED_TERMINAL_STATUSES.contains(&status.as_str()) {
                    return Err(CheckFailure::fail(
                        "ledger-terminal-status-invalid",
                        format!("the ledger records unknown terminal command status {status:?}"),
                    ));
                }
            }
        }
    }
    phases.next("lane-state");
    let unlabeled_lanes: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM lanes WHERE status IS NULL OR status=''",
            [],
            |row| row.get(0),
        )
        .map_err(|error| {
            CheckFailure::fail(
                "ledger-lane-query-failed",
                format!("ledger lane query failed: {error}"),
            )
        })?;
    if unlabeled_lanes != 0 {
        return Err(CheckFailure::fail(
            "ledger-lane-state-invalid",
            format!("{unlabeled_lanes} lane row(s) carry no status"),
        ));
    }
    note_evidence(&mut phases.evidence, audit_note);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger_fixture(dir: &Path) -> PathBuf {
        let path = dir.join("ledger.sqlite3");
        let connection = Connection::open(&path).expect("fixture ledger opens");
        connection
            .execute_batch(
                "CREATE TABLE commands (command_id TEXT PRIMARY KEY, terminal_status TEXT);
                 CREATE TABLE audit_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE);
                 CREATE TABLE idempotency_keys (key TEXT PRIMARY KEY);
                 CREATE TABLE lanes (lane TEXT PRIMARY KEY, status TEXT);
                 CREATE TABLE left (value TEXT UNIQUE);
                 CREATE TABLE right (value TEXT UNIQUE);
                 INSERT INTO audit_events (event_id) VALUES ('a'), ('b');
                 INSERT INTO commands VALUES ('c1', 'completed');
                 INSERT INTO left VALUES ('l1'), ('l2');
                 INSERT INTO right VALUES ('r1'), ('r2');",
            )
            .expect("fixture schema applies");
        path
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn a_consistent_ledger_passes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ledger_fixture(dir.path());
        let before = std::fs::read(&path).expect("ledger bytes");
        let result = bake(
            "SYS-08",
            "ledger",
            Instant::now(),
            ledger_integrity(&path, deadline()),
        );
        assert_eq!(result.status, CheckStatus::Pass);
        for phase in [
            "integrity",
            "schema",
            "foreign-keys",
            "audit-sequence",
            "command-state",
            "lane-state",
        ] {
            assert_phase(&result, phase, "ok");
        }
        assert_eq!(result.evidence.len(), 8);
        assert_eq!(std::fs::read(&path).expect("ledger bytes"), before);
    }

    fn assert_phase(result: &CheckResult, phase: &str, outcome: &str) {
        let prefix = format!("phase={phase} elapsed_ms=");
        let suffix = format!(" outcome={outcome}");
        let note = result
            .evidence
            .iter()
            .find(|note| note.starts_with(&prefix))
            .expect("phase evidence survives bake");
        note.strip_prefix(&prefix)
            .unwrap()
            .strip_suffix(&suffix)
            .unwrap()
            .parse::<u64>()
            .expect("bounded numeric elapsed time");
        assert!(result.evidence.len() <= 8);
        assert!(result
            .evidence
            .iter()
            .all(|note| note.chars().count() <= 200));
    }

    #[test]
    fn ledger_connection_rejects_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ledger_fixture(dir.path());
        let before = std::fs::read(&path).unwrap();
        ledger_integrity_with_setup(&path, deadline(), |connection, _| {
            let error = connection
                .execute("DELETE FROM commands", [])
                .expect_err("read-only ledger");
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ReadOnly)
            );
        })
        .expect("read-only checks pass");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn an_index_that_disagrees_with_its_table_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ledger_fixture(dir.path());
        {
            let connection = Connection::open(&path).expect("fixture reopens");
            let root = |name: &str| -> i64 {
                connection
                    .query_row(
                        "SELECT rootpage FROM sqlite_master WHERE name=?1",
                        [name],
                        |row| row.get(0),
                    )
                    .expect("autoindex exists")
            };
            let (left, right) = (
                root("sqlite_autoindex_left_1"),
                root("sqlite_autoindex_right_1"),
            );
            connection
                .execute_batch(&format!(
                    "PRAGMA writable_schema=ON;
                     UPDATE sqlite_master SET rootpage={right} WHERE name='sqlite_autoindex_left_1';
                     UPDATE sqlite_master SET rootpage={left} WHERE name='sqlite_autoindex_right_1';
                     PRAGMA writable_schema=OFF;"
                ))
                .expect("swap the two unique indexes");
        }
        let quick: String = Connection::open(&path)
            .unwrap()
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            quick, "ok",
            "quick_check cannot see index/table disagreement"
        );
        let failure = ledger_integrity(&path, deadline()).expect_err("indexes disagree");
        assert_eq!(
            failure.reason, "ledger-integrity-failed",
            "{}",
            failure.summary
        );
    }

    #[test]
    fn a_spent_deadline_fails_instead_of_running_unbounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = ledger_fixture(dir.path());
        let failure = ledger_integrity(&path, Instant::now() - Duration::from_millis(1))
            .expect_err("no budget left");
        assert_eq!(failure.reason, "ledger-integrity-timeout");
    }
}
