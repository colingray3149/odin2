use super::{
    fixture_spec, launch_for, read_pid_file, recovery_launch_for, recovery_launch_with_ids,
    wait_until_dead, write_fixture, write_script, NEGOTIATE_V2_JSON, READY_V2_JSON,
};
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError, OmpProcessSpec};
use odin_process::CORRELATION_ENV;
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn incomplete_reap_is_typed_and_retains_nonterminal_worker() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "incomplete-reap");
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    process.state = OmpLifecycleState::Ready;
    let error = process
        .kill()
        .await
        .expect_err("missing worker cannot prove tree death");
    assert!(matches!(
        error,
        OmpProcessError::ReapIncomplete {
            root_reaped: false,
            ref worker_id,
            ..
        } if worker_id == "unassigned"
    ));
    assert_eq!(process.state(), OmpLifecycleState::Draining);
    assert!(process.worker_id().is_none());
    assert!(process.exit_record().is_none());
}

#[tokio::test]
async fn kill_proves_termination_through_the_stop_authority() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "kill");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    let record = timeout(Duration::from_secs(10), process.kill())
        .await
        .unwrap()
        .expect("StopAuthority kill must prove a terminal record");
    assert!(record.termination_proven());
    assert_eq!(process.state(), OmpLifecycleState::Exited);
    assert!(process.worker_id().is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn failed_startup_kills_and_reaps_the_child_group() {
    let scratch = tempfile::tempdir().unwrap();
    let pidfile = scratch.path().join("child.pid");
    let script = format!(
        "#!/bin/sh\necho $$ > {pidfile}\nprintf '%s\\n' 'fixture-stderr-diagnostics' >&2\nprintf '%s\\n' '{{\"type\":\"not-ready\"}}'\nIFS= read -r keepalive\n",
        pidfile = pidfile.display()
    );
    let path = write_script(scratch.path(), "startup-fail", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let error = OmpProcess::spawn(spec, launch_for(&path))
        .await
        .unwrap_err();
    let OmpProcessError::StartupFailed {
        inner,
        stderr_tail,
        startup_frames,
        cleanup,
    } = error
    else {
        panic!("expected StartupFailed, got {error:?}");
    };
    assert!(matches!(*inner, OmpProcessError::InvalidReadyFrame { .. }));
    // The malformed ready frame never entered retention: its exact
    // physical bytes ride inside `InvalidReadyFrame`.
    assert!(startup_frames.is_empty());
    assert!(cleanup.is_none());
    assert!(
        String::from_utf8_lossy(&stderr_tail).contains("fixture-stderr-diagnostics"),
        "the bounded drainer join completed before the tail was snapshotted"
    );
    // The failed child was killed and reaped before spawn returned, so an
    // immediate retry cannot race it or its session lock.
    let pid = read_pid_file(&pidfile).await;
    assert!(
        wait_until_dead(pid).await,
        "the failed-startup child must be reaped"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn forced_stop_reaches_held_descendants_through_authority() {
    // Hold both processes on a private FIFO, not stdin: shutdown closes
    // stdin before escalation and background shell jobs otherwise read EOF.
    let scratch = tempfile::tempdir().unwrap();
    let pidfile = scratch.path().join("group.pid");
    let fifo = pidfile.with_extension("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .expect("private hold FIFO");
    let script = format!(
        "#!/bin/sh\ntrap '' INT TERM\nexec 3<> {fifo}\nprintf '%s\\n' '{ready}'\nIFS= read -r request\nprintf '%s\\n' '{negotiation}'\n( IFS= read -r hold <&3 ) &\necho $! > {pidfile}\nIFS= read -r hold <&3\n",
        ready = READY_V2_JSON,
        negotiation = NEGOTIATE_V2_JSON,
        pidfile = pidfile.display(),
        fifo = fifo.display(),
    );
    let path = write_script(scratch.path(), "group-kill", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    let descendant = read_pid_file(&pidfile).await;
    assert!(
        Path::new(&format!("/proc/{descendant}")).exists(),
        "held descendant must start live"
    );
    let _record = timeout(Duration::from_secs(10), process.kill())
        .await
        .unwrap()
        .unwrap();
    // Manager-confirmed termination need not retain a wait status; descendants must still be gone.
    assert_eq!(process.state(), OmpLifecycleState::Exited);
    assert!(process.worker_id().is_none());
    assert!(
        wait_until_dead(descendant).await,
        "the in-group descendant must not survive the supervisor's forced stop"
    );
}

#[tokio::test]
async fn spawn_refuses_what_the_registration_does_not_bind_before_starting_anything() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "bound");
    let spec = || fixture_spec(path.clone(), std::env::temp_dir());
    let spawn = |spec: OmpProcessSpec| async {
        OmpProcess::spawn(spec, recovery_launch_for(&path))
            .await
            .expect_err("spawn is refused")
    };

    // The same bytes at another path are not the registered executable.
    let copy = write_fixture(scratch.path(), "copy");
    let error = spawn(fixture_spec(copy, std::env::temp_dir())).await;
    assert!(
        matches!(&error, OmpProcessError::InvalidSpec { detail } if detail.contains("registered binding")),
        "{error:?}"
    );

    // A payload correlation must be the durable one.
    let mut mismatched = spec();
    mismatched
        .explicit_env
        .push((CORRELATION_ENV.to_owned(), "f".repeat(32)));
    let error = spawn(mismatched).await;
    assert!(
        matches!(&error, OmpProcessError::InvalidSpec { detail } if detail.contains("correlation")),
        "{error:?}"
    );

    // A recovery-only channel has no executable authority, so nothing falls back to a raw spawn.
    let error = spawn(spec()).await;
    assert!(
        matches!(error, OmpProcessError::SpawnFailed { .. }),
        "{error:?}"
    );

    let plain = scratch.path().join("plain");
    std::fs::write(&plain, "").unwrap();
    let error = spawn(fixture_spec(plain, std::env::temp_dir())).await;
    assert!(
        matches!(error, OmpProcessError::ExecutableUnavailable { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_launch_names_only_safe_unit_identifiers() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "ids");
    for (tx_id, wp_id) in [("", "wp"), ("tx", "not safe!")] {
        let launch = recovery_launch_with_ids(&path, tx_id, wp_id);
        assert!(
            matches!(launch, Err(OmpProcessError::InvalidSpec { .. })),
            "{tx_id:?} {wp_id:?}"
        );
    }
}
