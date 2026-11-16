use crate::Ledger;

#[test]
fn memory_guards_are_per_operation_and_release_on_drop() {
    let ledger = Ledger::open_in_memory().unwrap();
    let first = ledger.try_operation_fence("a").unwrap().unwrap();
    assert!(ledger.try_operation_fence("a").unwrap().is_none());
    let other = ledger.try_operation_fence("b").unwrap().unwrap();
    drop(first);
    assert!(ledger.try_operation_fence("a").unwrap().is_some());
    drop(other);
}

#[test]
fn independent_connections_exclude_and_advance_durable_claims() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let mut first = Ledger::open(&path).unwrap();
    let mut second = Ledger::open(&path).unwrap();
    let mut guard = first.try_operation_fence("op").unwrap().unwrap();
    assert!(second.try_operation_fence("op").unwrap().is_none());
    assert!(second.try_operation_fence("other").unwrap().is_some());
    first.with_tx(|tx| guard.claim(tx)).unwrap();
    second.with_tx(|tx| guard.check(tx)).unwrap();
    drop(guard);
    let mut next = second.try_operation_fence("op").unwrap().unwrap();
    second.with_tx(|tx| next.claim(tx)).unwrap();
    second.with_tx(|tx| next.check(tx)).unwrap();
    let generation: i64 = first
        .connection()
        .query_row(
            "SELECT generation FROM operation_fences WHERE correlation_id = 'op'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(generation, 2);
}

#[test]
fn rolled_back_claim_and_superseded_generation_are_rejected() {
    let mut ledger = Ledger::open_in_memory().unwrap();
    let mut guard = ledger.try_operation_fence("op").unwrap().unwrap();
    {
        let tx = ledger.connection_mut().transaction().unwrap();
        guard.claim(&tx).unwrap();
        tx.rollback().unwrap();
    }
    assert!(ledger.with_tx(|tx| guard.check(tx)).is_err());
    ledger.with_tx(|tx| guard.claim(tx)).unwrap();
    ledger.with_tx(|tx| {
        tx.execute("UPDATE operation_fences SET generation = generation + 1 WHERE correlation_id = 'op'", [])?;
        Ok(())
    }).unwrap();
    assert!(ledger.with_tx(|tx| guard.check(tx)).is_err());
}

// The test executable doubles as a child so the held lock is released by the
// OS on process exit, without destructors running for its guard.
#[test]
fn process_exit_releases_file_lock() {
    const ENV: &str = "ODIN_FENCE_CHILD_DATABASE";
    if let Some(path) = std::env::var_os(ENV) {
        let ledger = Ledger::open(path).unwrap();
        if std::env::var_os("ODIN_FENCE_EXPECT_BUSY").is_some() {
            assert!(ledger.try_operation_fence("crash").unwrap().is_none());
            return;
        }
        let _guard = ledger.try_operation_fence("crash").unwrap().unwrap();
        std::process::exit(0);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.sqlite");
    let ledger = Ledger::open(&path).unwrap();
    let guard = ledger.try_operation_fence("crash").unwrap().unwrap();
    let busy = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "operation_fence::tests::process_exit_releases_file_lock",
        ])
        .env(ENV, &path)
        .env("ODIN_FENCE_EXPECT_BUSY", "1")
        .status()
        .unwrap();
    assert!(busy.success());
    drop(guard);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "operation_fence::tests::process_exit_releases_file_lock",
        ])
        .env(ENV, &path)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(ledger.try_operation_fence("crash").unwrap().is_some());
}
