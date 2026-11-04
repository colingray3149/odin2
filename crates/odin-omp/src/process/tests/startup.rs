use super::{
    fixture_spec, launch_for, write_fixture, write_script, AUX_INTERLEAVE_SCRIPT,
    FIXTURE_READY_LINE, READY_V1_JSON, READY_V2_JSON,
};
use crate::frames::DecodedRpcFrame;
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError, NEGOTIATE_REQUEST_ID};
use serde_json::json;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn spawn_negotiates_v2_round_trips_and_drains() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_fixture(scratch.path(), "spawn");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(process.state(), OmpLifecycleState::Ready);
    assert!(process.worker_id().is_some());
    let ready = process.ready_frame().unwrap();
    assert_eq!(ready.value()["type"], "ready");
    assert_eq!(ready.lines().len(), 1);
    assert_eq!(ready.lines()[0], FIXTURE_READY_LINE);
    // The negotiation response is retained as startup evidence too.
    let negotiation = process.negotiation_frame().unwrap();
    assert_eq!(negotiation.value()["type"], "response");
    assert_eq!(negotiation.value()["command"], "negotiate_protocol");
    assert_eq!(negotiation.value()["id"], NEGOTIATE_REQUEST_ID);
    assert_eq!(negotiation.lines().len(), 1);
    assert!(negotiation.lines()[0].ends_with(b"\n"));

    let request = json!({"type": "prompt", "message": "hi"});
    process.send_json(&request).await.unwrap();
    let frame = timeout(Duration::from_secs(10), process.next_frame())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.value()["command"], "echo");
    assert_eq!(frame.value()["data"]["message"], "hi");
    assert_eq!(frame.lines().len(), 1);
    assert!(frame.lines()[0].ends_with(b"\n"));

    process.close_stdin().unwrap();
    assert_eq!(process.state(), OmpLifecycleState::Draining);
    let shutdown = timeout(Duration::from_secs(10), process.graceful_stop())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(shutdown.frames().len(), 1);
    assert_eq!(shutdown.frames()[0].value()["data"]["phase"], "goodbye");
    assert!(shutdown.exit().success());
    assert_eq!(process.state(), OmpLifecycleState::Exited);
    assert!(process.exit_record().unwrap().success());
    assert_eq!(process.exit_record().unwrap().code(), Some(0));
}

#[tokio::test]
async fn startup_tolerates_and_retains_interleaved_aux_frames() {
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "startup-aux", AUX_INTERLEAVE_SCRIPT);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(process.state(), OmpLifecycleState::Ready);
    let ready = process.ready_frame().unwrap().clone();
    assert_eq!(ready.value()["type"], "ready");
    let negotiation = process.negotiation_frame().unwrap().clone();
    assert_eq!(negotiation.value()["command"], "negotiate_protocol");
    // Ordered startup evidence: ready, the interleaved auxiliary frames
    // in arrival order, then the exact negotiation response.
    let startup: Vec<&DecodedRpcFrame> = process.startup_frames().collect();
    assert_eq!(startup.len(), 5);
    assert_eq!(startup[0], &ready);
    assert_eq!(startup[1].value()["type"], "extension_ui_request");
    assert_eq!(startup[1].value()["id"], "ui-1");
    assert_eq!(startup[2].value()["type"], "session_info_update");
    assert_eq!(startup[3].value()["type"], "available_commands_update");
    assert_eq!(startup[4], &negotiation);
    // Retained aux frames consumed no stream state: the negotiated v2
    // channel round-trips normally.
    let request = json!({"type": "prompt", "message": "hi"});
    process.send_json(&request).await.unwrap();
    let frame = timeout(Duration::from_secs(10), process.next_frame())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.value()["command"], "echo");
    assert_eq!(frame.value()["data"]["message"], "hi");
    process.kill().await.unwrap();
}

#[tokio::test]
async fn startup_rejects_a_response_with_the_wrong_id_after_aux_frames() {
    let aux = "{\"type\":\"session_info_update\",\"sessionId\":\"fixture\"}";
    let response = "{\"id\":\"odin-omp-negotiate-other\",\"type\":\"response\",\"command\":\"negotiate_protocol\",\"success\":true,\"data\":{\"protocolVersion\":2}}";
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nprintf '%s\\n' '{aux}'\nIFS= read -r request\nprintf '%s\\n' '{response}'\n",
        ready = READY_V2_JSON,
        aux = aux,
        response = response,
    );
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "startup-wrong-id", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let error = OmpProcess::spawn(spec, launch_for(&path))
        .await
        .unwrap_err();
    let OmpProcessError::StartupFailed {
        inner,
        startup_frames,
        cleanup,
        ..
    } = error
    else {
        panic!("expected StartupFailed, got {error:?}");
    };
    assert!(cleanup.is_none());
    let OmpProcessError::NegotiationMismatch { detail, lines } = *inner else {
        panic!("expected NegotiationMismatch, got {inner:?}");
    };
    assert!(detail.contains(NEGOTIATE_REQUEST_ID));
    assert_eq!(lines.len(), 1);
    assert!(lines[0].ends_with(b"\n"));
    // The typed failure owns the exact ordered startup bytes: the ready
    // frame, the interleaved auxiliary, and the offending response
    // itself, decoded and never discarded.
    assert_eq!(startup_frames.len(), 3);
    assert_eq!(startup_frames[0].value()["type"], "ready");
    assert_eq!(startup_frames[1].value()["type"], "session_info_update");
    assert_eq!(startup_frames[2].value()["id"], "odin-omp-negotiate-other");
    let observed: Vec<u8> = startup_frames
        .iter()
        .flat_map(|frame| frame.lines().iter().flatten().copied())
        .collect();
    assert_eq!(
        observed,
        format!("{READY_V2_JSON}\n{aux}\n{response}\n").into_bytes()
    );
    assert_eq!(startup_frames[2].lines(), lines.as_slice());
}

#[tokio::test]
async fn a_v1_only_peer_fails_startup() {
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nIFS= read -r hold\n",
        ready = READY_V1_JSON,
    );
    let scratch = tempfile::tempdir().unwrap();
    let path = write_script(scratch.path(), "startup-v1-only", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let error = OmpProcess::spawn(spec, launch_for(&path))
        .await
        .expect_err("a peer without v2 must not start");
    let OmpProcessError::StartupFailed { inner, .. } = &error else {
        panic!("expected StartupFailed, got {error:?}");
    };
    match inner.as_ref() {
        OmpProcessError::InvalidReadyFrame { detail, lines } => {
            assert!(detail.contains("v2"), "{detail}");
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0], format!("{READY_V1_JSON}\n").into_bytes());
        }
        other => panic!("expected InvalidReadyFrame, got {other:?}"),
    }
}
