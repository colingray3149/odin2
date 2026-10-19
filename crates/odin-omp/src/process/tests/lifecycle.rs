use super::{
    fixture_spec, launch_for, read_pid_file, recovery_launch_for, wait_until_dead, write_fixture,
    write_script, NEGOTIATE_V2_JSON, READY_V1_JSON, READY_V2_JSON,
};
use crate::frames::{RpcFrameErrorKind, RpcProtocolVersion, MAX_FRAME_BYTES};
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[test]
fn spec_validation_rejects_host_mode_ownership_and_degenerate_bounds() {
    let base = fixture_spec(PathBuf::from("/bin/true"), std::env::temp_dir());
    base.validate().unwrap();

    let mut mode_arg = base.clone();
    mode_arg.explicit_args = vec!["--mode".to_owned(), "rpc".to_owned()];
    assert!(matches!(
        mode_arg.validate(),
        Err(OmpProcessError::InvalidSpec { .. })
    ));

    let mut mode_inline = base.clone();
    mode_inline.explicit_args = vec!["--mode=tui".to_owned()];
    assert!(matches!(
        mode_inline.validate(),
        Err(OmpProcessError::InvalidSpec { .. })
    ));

    let mut zero_timeout = base.clone();
    zero_timeout.kill_timeout = Duration::ZERO;
    assert!(matches!(
        zero_timeout.validate(),
        Err(OmpProcessError::InvalidSpec { .. })
    ));

    let mut nul_value = base.clone();
    nul_value.explicit_env = vec![("ODIN".to_owned(), "a\0b".to_owned())];
    assert!(matches!(
        nul_value.validate(),
        Err(OmpProcessError::InvalidSpec { .. })
    ));
}

#[tokio::test]
async fn stopped_process_rejects_every_transition() {
    let path = write_fixture("stopped");
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    assert_eq!(process.state(), OmpLifecycleState::Stopped);
    assert!(matches!(
        process.send_json(&json!({"type": "prompt"})).await,
        Err(OmpProcessError::InvalidTransition {
            operation: "send_json",
            from: OmpLifecycleState::Stopped
        })
    ));
    assert!(matches!(
        process.next_frame().await,
        Err(OmpProcessError::InvalidTransition {
            operation: "next_frame",
            from: OmpLifecycleState::Stopped
        })
    ));
    assert!(matches!(
        process.close_stdin(),
        Err(OmpProcessError::InvalidTransition {
            operation: "close_stdin",
            from: OmpLifecycleState::Stopped
        })
    ));
    assert!(matches!(
        process.graceful_stop().await,
        Err(OmpProcessError::InvalidTransition {
            operation: "graceful_stop",
            from: OmpLifecycleState::Stopped
        })
    ));
    assert!(matches!(
        process.kill().await,
        Err(OmpProcessError::InvalidTransition {
            operation: "kill",
            from: OmpLifecycleState::Stopped
        })
    ));
    assert!(process.worker_id().is_none());
    assert!(process.ready_frame().is_none());
    assert!(process.negotiation_frame().is_none());
    assert!(process.exit_record().is_none());
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn incomplete_reap_is_typed_and_retains_nonterminal_worker() {
    let path = write_fixture("incomplete-reap");
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    process.state = OmpLifecycleState::Ready(RpcProtocolVersion::V1);
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
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn kill_records_stop_verdict_not_pgid() {
    let path = write_fixture("kill");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    match OmpProcess::spawn(spec, launch_for(&path)).await {
        Ok(mut process) => {
            let _record = timeout(Duration::from_secs(10), process.kill())
                .await
                .unwrap()
                .expect("StopAuthority kill must prove a terminal record");
            assert_eq!(process.state(), OmpLifecycleState::Exited);
            assert!(process.worker_id().is_none());
        }
        Err(error) => {
            assert!(
                matches!(error, OmpProcessError::SpawnFailed { .. }),
                "recovery-only channel must fail closed without Command spawn: {error}"
            );
        }
    }
    let _ = fs::remove_file(&path);
}

#[cfg(unix)]
#[tokio::test]
async fn version_probe_join_stays_bounded_when_a_descendant_holds_stderr() {
    // The background writer inherits the stderr pipe and never exits on
    // its own; the probe root exits cleanly, so only the bounded, aborted
    // drainer join keeps the probe inside its budgets. Dropping the pipe
    // then SIGPIPEs the descendant away.
    let pidfile = std::env::temp_dir().join(format!("odin-omp-probe-{}.pid", std::process::id()));
    let script = format!(
        "#!/bin/sh\n( while :; do printf x; done ) >&2 &\necho $! > {pidfile}\nprintf 'omp/fixture-1.0.0\\n'\nexit 0\n",
        pidfile = pidfile.display()
    );
    let path = write_script("probe-join", &script);
    let mut spec = fixture_spec(path.clone(), std::env::temp_dir());
    spec.startup_timeout = Duration::from_secs(2);
    spec.kill_timeout = Duration::from_secs(1);
    let started = Instant::now();
    let identity = spec.establish_identity(&launch_for(&path)).await.unwrap();
    assert_eq!(identity.version(), "omp/fixture-1.0.0");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the drainer join must stay bounded while a descendant holds stderr"
    );
    let descendant = read_pid_file(&pidfile).await;
    assert!(
        wait_until_dead(descendant).await,
        "dropping the aborted drainer closes the pipe"
    );
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&pidfile);
}

#[cfg(unix)]
#[tokio::test]
async fn failed_startup_kills_and_reaps_the_child_group() {
    let pidfile =
        std::env::temp_dir().join(format!("odin-omp-startup-fail-{}.pid", std::process::id()));
    let script = format!(
        "#!/bin/sh\necho $$ > {pidfile}\nprintf '%s\\n' 'fixture-stderr-diagnostics' >&2\nprintf '%s\\n' '{{\"type\":\"not-ready\"}}'\nIFS= read -r keepalive\n",
        pidfile = pidfile.display()
    );
    let path = write_script("startup-fail", &script);
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
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&pidfile);
}

#[cfg(unix)]
#[tokio::test]
async fn forced_stop_reaches_held_descendants_through_authority() {
    // Hold both processes on a private FIFO, not stdin: shutdown closes
    // stdin before escalation and background shell jobs otherwise read EOF.
    let pidfile =
        std::env::temp_dir().join(format!("odin-omp-group-kill-{}.pid", std::process::id()));
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
        "#!/bin/sh\ntrap '' INT TERM\nexec 3<> {fifo}\nprintf '%s\\n' '{ready}'\n( IFS= read -r hold <&3 ) &\necho $! > {pidfile}\nIFS= read -r hold <&3\n",
        ready = READY_V1_JSON,
        pidfile = pidfile.display(),
        fifo = fifo.display(),
    );
    let path = write_script("group-kill", &script);
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
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&pidfile);
    fs::remove_file(&fifo).expect("remove hold FIFO");
}

#[cfg(unix)]
#[tokio::test]
async fn dropping_a_live_process_terminates_the_group() {
    let pidfile =
        std::env::temp_dir().join(format!("odin-omp-group-drop-{}.pid", std::process::id()));
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\n( IFS= read -r hold ) &\necho $! > {pidfile}\nIFS= read -r hold\n",
        ready = READY_V1_JSON,
        pidfile = pidfile.display()
    );
    let path = write_script("group-drop", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    let descendant = read_pid_file(&pidfile).await;
    drop(process);
    assert!(
        wait_until_dead(descendant).await,
        "the drop path must kill the whole group, not only the root child"
    );
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&pidfile);
}

#[tokio::test]
async fn stdout_eof_surfaces_unfinished_chunk_evidence() {
    // The pinned v2 encoder is interrupted after one chunk: EOF must
    // finalize the decoder and surface the violation plus the raw chunk
    // line inside the exit record instead of dropping them.
    let chunk = serde_json::json!({
        "type": "rpc_chunk",
        "chunkId": "interrupted",
        "index": 0,
        "count": 2,
        "byteLength": (2 * MAX_FRAME_BYTES) as u64,
        "data": "aGVsbG8=",
    });
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nIFS= read -r request\nprintf '%s\\n' '{negotiation}'\nprintf '%s\\n' '{chunk}'\n",
        ready = READY_V2_JSON,
        negotiation = NEGOTIATE_V2_JSON,
        chunk = chunk,
    );
    let path = write_script("eof-unfinished", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(
        process.state(),
        OmpLifecycleState::Ready(RpcProtocolVersion::V2)
    );
    let error = timeout(Duration::from_secs(10), process.next_frame())
        .await
        .expect("EOF arrives within the bound")
        .expect_err("an interrupted chunk sequence cannot decode");
    let OmpProcessError::StdoutClosed { exit } = error else {
        panic!("expected StdoutClosed, got {error:?}");
    };
    let unfinished = exit
        .unfinished_sequence()
        .expect("the interrupted sequence is retained as exit evidence");
    assert!(matches!(
        unfinished.kind(),
        RpcFrameErrorKind::UnfinishedChunkSequence { chunk_id, next_index: 1, count: 2, received: 5, .. }
        if chunk_id.as_str() == "interrupted"
    ));
    assert_eq!(unfinished.evidence().len(), 1);
    assert!(unfinished.evidence()[0].ends_with(b"\n"));
    assert_eq!(process.state(), OmpLifecycleState::Exited);
    assert_eq!(
        process.exit_record().unwrap().unfinished_sequence(),
        Some(unfinished)
    );
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn lifecycle_stop_authority() {
    let path = write_fixture("lifecycle-stop");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let error = OmpProcess::spawn(spec, recovery_launch_for(&path))
        .await
        .expect_err("a recovery-only channel has no spawn executable authority");
    assert!(
        matches!(error, OmpProcessError::SpawnFailed { .. }),
        "production spawn must not fall back to raw Command/PID/PGID: {error}"
    );
    let mut process = OmpProcess::new(
        fixture_spec(path.clone(), std::env::temp_dir()),
        recovery_launch_for(&path),
    );
    process.state = OmpLifecycleState::Ready(RpcProtocolVersion::V1);
    let error = process.kill().await.expect_err("no WorkerId means no stop");
    match error {
        OmpProcessError::ReapIncomplete {
            root_reaped: false,
            worker_id,
            ..
        } => assert_eq!(worker_id, "unassigned"),
        other => panic!("expected ReapIncomplete worker evidence, got {other:?}"),
    }
    assert!(process.exit_record().is_none());
    let _ = fs::remove_file(&path);
}
