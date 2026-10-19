//! Bounded payload-stdin invariants: a full pipe times out with an honest
//! partial count, and a long in-flight write never delays or blocks a
//! concurrent authoritative stop.

use super::*;

#[test]
fn stdin_write_timeout_and_stop_remain_bounded() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let worker_id = mint_worker_id().expect("worker id");
    let naming = WorkerNaming::new("tx-stdin-bound", "wp1", 1, worker_id).expect("naming");
    // prepare + release keeps the stdin pipe open; spawn would close it.
    let mut authority = WorkerAuthority::prepare(
        &channel,
        naming,
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect("prepare worker");
    authority.release_payload().expect("release payload");

    // A payload that never reads stdin fills the pipe. The bounded
    // write must expire with an honest partial count instead of
    // blocking, so the authority can never be held indefinitely.
    let payload = vec![0x5A_u8; 1024 * 1024];
    let started = std::time::Instant::now();
    let error = authority
        .write_stdin_timeout(&payload, Duration::from_millis(300))
        .expect_err("a full pipe must time out");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), WorkerErrorCode::WriteTimeout);
    assert!(
        error
            .to_string()
            .contains(&format!("of {} bytes", payload.len())),
        "the timeout must name the exact requested size: {error}"
    );
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(5),
        "the bounded write must honor its deadline without hanging: {elapsed:?}"
    );

    // Stop stays independently bounded and completes the ladder.
    let report = authority.stop().expect("stop after timed-out write");
    assert!(report.stopped);
}

#[test]
fn pending_wait_and_long_stdin_write_do_not_block_stop() {
    let manager = FakeManager::start(&cgroup_fixture());
    let channel = manager.channel();
    let worker_id = mint_worker_id().expect("worker id");
    let naming = WorkerNaming::new("tx-concurrent-stop", "wp1", 1, worker_id).expect("naming");
    let mut authority = WorkerAuthority::prepare(
        &channel,
        naming,
        &worker_spec(env_allowlist(&[("LANG", "C")]), "hang"),
        crate::ScopeLimits::default(),
    )
    .expect("prepare worker");
    authority.release_payload().expect("release payload");
    let shared = Arc::new(Mutex::new(authority));

    // Duplicate the writer while holding the actuator briefly, then
    // perform a deliberately long-budget, pipe-filling write elsewhere.
    let mut writer = shared
        .lock()
        .expect("authority lock")
        .stdin_writer()
        .expect("stdin writer");
    let write_payload = vec![0xA5_u8; 16 * 1024 * 1024];
    let writer_started = Arc::new(AtomicBool::new(false));
    let writer_started_thread = Arc::clone(&writer_started);
    let (writer_tx, writer_rx) = std::sync::mpsc::channel();
    let writer_thread = std::thread::spawn(move || {
        writer_started_thread.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        let result = writer.write_timeout(&write_payload, Duration::from_secs(20));
        let _ = writer_tx.send((result, started.elapsed()));
    });
    assert!(wait_until(
        || writer_started.load(Ordering::SeqCst),
        Duration::from_secs(2)
    ));

    // A waiter uses the same lock-release polling contract as the kernel
    // StopAuthority. It must not monopolize the actuator either.
    let waiting = Arc::clone(&shared);
    let (wait_tx, wait_rx) = std::sync::mpsc::channel();
    let wait_thread = std::thread::spawn(move || loop {
        let observed = waiting.lock().expect("wait authority lock").try_wait();
        match observed {
            Ok(Some(status)) => {
                let _ = wait_tx.send(Ok(status));
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                let _ = wait_tx.send(Err(error));
                return;
            }
        }
    });

    std::thread::sleep(Duration::from_millis(100));
    let stop_started = std::time::Instant::now();
    let report = shared
        .lock()
        .expect("stop authority lock")
        .stop()
        .expect("concurrent stop");
    let stop_elapsed = stop_started.elapsed();
    assert!(report.stopped);
    assert!(
        stop_elapsed < Duration::from_secs(10),
        "stop waited on an unrelated stdin deadline: {stop_elapsed:?}"
    );

    let (write_result, write_elapsed) = writer_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stopping the reader must wake the pending writer");
    assert!(
        write_result.is_err(),
        "the killed reader cannot accept the full frame"
    );
    assert!(
        write_elapsed < Duration::from_secs(20),
        "writer slept until its deadline instead of waking on stop: {write_elapsed:?}"
    );
    writer_thread.join().expect("writer thread");

    wait_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter must observe the concurrent stop")
        .expect("waiter observes a real exit status");
    wait_thread.join().expect("wait thread");
}
