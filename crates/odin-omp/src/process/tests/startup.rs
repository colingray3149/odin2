use super::{
    fixture_spec, launch_for, write_fixture, write_script, AUX_INTERLEAVE_SCRIPT,
    FIXTURE_READY_LINE, NEGOTIATE_V2_JSON, READY_V1_JSON, READY_V2_JSON,
};
use crate::frames::{DecodedRpcFrame, RpcProtocolVersion, MAX_FRAME_BYTES};
use crate::probe::PINNED_OMP_SOURCE_REVISION;
use crate::process::startup::{NEGOTIATE_COMMAND, STARTUP_AUX_BYTE_CAP, STARTUP_AUX_FRAME_CAP};
use crate::process::{OmpLifecycleState, OmpProcess, OmpProcessError, NEGOTIATE_REQUEST_ID};
use serde_json::json;
use std::fs;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn identity_probe_captures_version_and_configured_revision() {
    let path = write_fixture("identity");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let identity = spec.establish_identity(&launch_for(&path)).await.unwrap();
    assert_eq!(identity.version(), "omp/fixture-1.0.0");
    assert_eq!(identity.source_revision(), PINNED_OMP_SOURCE_REVISION);
    assert_eq!(identity.canonical_path(), fs::canonicalize(&path).unwrap());
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn spawn_negotiates_v2_round_trips_and_drains() {
    let path = write_fixture("spawn");
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(
        process.state(),
        OmpLifecycleState::Ready(RpcProtocolVersion::V2)
    );
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
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_tolerates_and_retains_interleaved_aux_frames() {
    let path = write_script("startup-aux", AUX_INTERLEAVE_SCRIPT);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(
        process.state(),
        OmpLifecycleState::Ready(RpcProtocolVersion::V2)
    );
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
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_aux_count_cap_retains_the_in_cap_window() {
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\ni=0\nwhile [ $i -lt {flood} ]; do\n\tprintf '{{\"type\":\"extension_ui_request\",\"id\":\"ui-%s\"}}\\n' \"$i\"\n\ti=$((i+1))\ndone\nIFS= read -r request\nprintf '%s\\n' '{negotiation}'\n",
        ready = READY_V2_JSON,
        flood = STARTUP_AUX_FRAME_CAP + 1,
        negotiation = NEGOTIATE_V2_JSON,
    );
    let path = write_script("startup-aux-count", &script);
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
    // The ready frame moved into the startup failure with its exact
    // physical bytes; the auxiliary window rides inside the typed inner
    // error, so the retention caps are never duplicated.
    assert!(cleanup.is_none());
    assert_eq!(startup_frames.len(), 1);
    assert_eq!(
        startup_frames[0].lines(),
        &[format!("{READY_V2_JSON}\n").into_bytes()]
    );
    let OmpProcessError::StartupAuxLimit {
        frames,
        bytes,
        overflow,
    } = *inner
    else {
        panic!("expected StartupAuxLimit, got {inner:?}");
    };
    // The in-cap window and the offending frame are both retained
    // exactly; nothing is discarded.
    assert_eq!(frames.len(), STARTUP_AUX_FRAME_CAP);
    let retained: usize = frames.iter().map(|frame| frame.raw().len()).sum();
    assert_eq!(retained, bytes);
    // The window reconstructs in arrival order with exact physical
    // bytes: every in-cap frame, then the offending overflow frame.
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(
            frame.lines(),
            &[
                format!("{{\"type\":\"extension_ui_request\",\"id\":\"ui-{index}\"}}\n")
                    .into_bytes()
            ]
        );
    }
    assert_eq!(
        overflow.lines(),
        &[
            format!(
                "{{\"type\":\"extension_ui_request\",\"id\":\"ui-{STARTUP_AUX_FRAME_CAP}\"}}\n"
            )
            .into_bytes()
        ]
    );
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_aux_byte_cap_overflows_before_the_count_cap() {
    // Five same-size aux frames cross the byte ceiling on the fifth while
    // the count cap is nowhere near. The padding comes from the shell
    // printf field-width specifier — a builtin — so the cleared child
    // environment (no PATH, hence no head/tr) cannot shrink the frames
    // and no giant shell variable is ever materialized. Each frame is one
    // physical line: the exact envelope, AUX_PAD_BYTES spaces, and the
    // newline — under the 1 MiB transport ceiling. Four frames fit the
    // 4 MiB byte ceiling; the fifth overflows it.
    const AUX_PAD_BYTES: usize = 900_000;
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\ni=0\nwhile [ $i -lt {flood} ]; do\n\tprintf '{{\"type\":\"extension_ui_request\",\"id\":\"ui-%s\",\"pad\":\"%{pad}s\"}}\\n' \"$i\" ''\n\ti=$((i+1))\ndone\nIFS= read -r request\nprintf '%s\\n' '{negotiation}'\n",
        ready = READY_V2_JSON,
        flood = 5,
        pad = AUX_PAD_BYTES,
        negotiation = NEGOTIATE_V2_JSON,
    );
    // The exact logical bytes of the aux frame at `index`: the JSON
    // envelope padded with AUX_PAD_BYTES spaces, no transport newline.
    let expected_raw = |index: usize| -> Vec<u8> {
        let mut raw =
            format!("{{\"type\":\"extension_ui_request\",\"id\":\"ui-{index}\",\"pad\":\"")
                .into_bytes();
        raw.resize(raw.len() + AUX_PAD_BYTES, b' ');
        raw.extend_from_slice(b"\"}");
        raw
    };
    // The fixture geometry itself must cross the byte cap first: every id
    // is one digit, so all five frames share one exact size.
    let frame_raw_len = expected_raw(0).len();
    assert_eq!(frame_raw_len, expected_raw(4).len());
    assert!(frame_raw_len < MAX_FRAME_BYTES);
    assert!(4 * frame_raw_len <= STARTUP_AUX_BYTE_CAP);
    assert!(5 * frame_raw_len > STARTUP_AUX_BYTE_CAP);
    let path = write_script("startup-aux-bytes", &script);
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
    // Same ownership split as the count cap: the ready frame rides with
    // the startup failure, the auxiliary window inside the inner error,
    // and the failed-startup child is provably reaped.
    assert!(cleanup.is_none());
    assert_eq!(startup_frames.len(), 1);
    assert_eq!(
        startup_frames[0].lines(),
        &[format!("{READY_V2_JSON}\n").into_bytes()]
    );
    let OmpProcessError::StartupAuxLimit {
        frames,
        bytes,
        overflow,
    } = *inner
    else {
        panic!("expected StartupAuxLimit, got {inner:?}");
    };
    // Exactly four in-cap frames: the byte ceiling stopped the window
    // while the count cap was nowhere near.
    assert_eq!(frames.len(), 4);
    assert!(frames.len() < STARTUP_AUX_FRAME_CAP);
    // The window reconstructs in arrival order with exact per-frame sizes
    // and exact physical bytes: padded envelope, newline-terminated.
    for (index, frame) in frames.iter().enumerate() {
        let raw = expected_raw(index);
        let mut line = raw.clone();
        line.push(b'\n');
        assert_eq!(frame.raw().len(), frame_raw_len);
        assert_eq!(frame.raw(), raw.as_slice());
        assert_eq!(frame.lines(), &[line]);
        assert_eq!(frame.value()["type"], "extension_ui_request");
        assert_eq!(frame.value()["id"].as_str().unwrap(), format!("ui-{index}"));
    }
    let retained: usize = frames.iter().map(|frame| frame.raw().len()).sum();
    assert_eq!(retained, bytes);
    assert_eq!(bytes, 4 * frame_raw_len);
    assert!(bytes <= STARTUP_AUX_BYTE_CAP);
    // The fifth frame is the exact overflow evidence: the same padded
    // envelope at ui-4, and its addition crosses the byte ceiling.
    let overflow_raw = expected_raw(4);
    let mut overflow_line = overflow_raw.clone();
    overflow_line.push(b'\n');
    assert_eq!(overflow.raw().len(), frame_raw_len);
    assert_eq!(overflow.raw(), overflow_raw.as_slice());
    assert_eq!(overflow.lines(), &[overflow_line]);
    assert_eq!(overflow.value()["type"], "extension_ui_request");
    assert_eq!(overflow.value()["id"].as_str().unwrap(), "ui-4");
    assert!(bytes + overflow.raw().len() > STARTUP_AUX_BYTE_CAP);
    let _ = fs::remove_file(&path);
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
    let path = write_script("startup-wrong-id", &script);
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
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_rejects_a_response_for_another_command_after_aux_frames() {
    let aux = "{\"type\":\"extension_ui_request\",\"id\":\"ui-1\"}";
    let response = "{\"id\":\"odin-omp-negotiate-protocol\",\"type\":\"response\",\"command\":\"get_state\",\"success\":true,\"data\":{}}";
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nprintf '%s\\n' '{aux}'\nIFS= read -r request\nprintf '%s\\n' '{response}'\n",
        ready = READY_V2_JSON,
        aux = aux,
        response = response,
    );
    let path = write_script("startup-wrong-command", &script);
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
    let OmpProcessError::UnexpectedStartupFrame { detail, lines } = *inner else {
        panic!("expected UnexpectedStartupFrame, got {inner:?}");
    };
    assert!(detail.contains(NEGOTIATE_COMMAND));
    assert_eq!(lines.len(), 1);
    // The typed failure owns the exact ordered startup bytes through the
    // response that named the wrong command.
    assert_eq!(startup_frames.len(), 3);
    assert_eq!(startup_frames[0].value()["type"], "ready");
    assert_eq!(startup_frames[1].value()["id"], "ui-1");
    assert_eq!(startup_frames[2].value()["command"], "get_state");
    let observed: Vec<u8> = startup_frames
        .iter()
        .flat_map(|frame| frame.lines().iter().flatten().copied())
        .collect();
    assert_eq!(
        observed,
        format!("{READY_V2_JSON}\n{aux}\n{response}\n").into_bytes()
    );
    assert_eq!(startup_frames[2].lines(), lines.as_slice());
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_timeout_after_aux_frames_retains_the_window() {
    // The child answers the ready frame, interleaves one auxiliary,
    // reads the negotiation request, and then never responds: the
    // deadline fires inside the negotiation window with the window
    // moved into the typed failure.
    let aux = "{\"type\":\"session_info_update\",\"sessionId\":\"fixture\"}";
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nprintf '%s\\n' '{aux}'\nIFS= read -r request\nIFS= read -r hold\n",
        ready = READY_V2_JSON,
        aux = aux,
    );
    let path = write_script("startup-timeout-aux", &script);
    let mut spec = fixture_spec(path.clone(), std::env::temp_dir());
    spec.startup_timeout = Duration::from_secs(2);
    spec.kill_timeout = Duration::from_secs(1);
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
    assert!(
        matches!(*inner, OmpProcessError::StartupTimeout),
        "expected StartupTimeout, got {inner:?}"
    );
    assert!(cleanup.is_none(), "startup cleanup failed: {cleanup:?}");
    // The exact ordered bytes survive the process drop: ready, then aux.
    assert_eq!(startup_frames.len(), 2);
    assert_eq!(startup_frames[0].value()["type"], "ready");
    assert_eq!(startup_frames[1].value()["type"], "session_info_update");
    let observed: Vec<u8> = startup_frames
        .iter()
        .flat_map(|frame| frame.lines().iter().flatten().copied())
        .collect();
    assert_eq!(observed, format!("{READY_V2_JSON}\n{aux}\n").into_bytes());
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn startup_eof_after_aux_frames_retains_the_window() {
    // The child answers the ready frame, interleaves one auxiliary,
    // reads the negotiation request, and exits: stdout EOF closes the
    // negotiation window with the exact exit record as inner evidence
    // and the retained window moved into the typed failure.
    let aux = "{\"type\":\"available_commands_update\",\"commands\":[]}";
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nprintf '%s\\n' '{aux}'\nIFS= read -r request\nexit 0\n",
        ready = READY_V2_JSON,
        aux = aux,
    );
    let path = write_script("startup-eof-aux", &script);
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
    let OmpProcessError::StdoutClosed { exit } = *inner else {
        panic!("expected StdoutClosed, got {inner:?}");
    };
    assert!(exit.success());
    assert!(cleanup.is_none());
    // The exact ordered bytes survive the process drop: ready, then aux.
    assert_eq!(startup_frames.len(), 2);
    assert_eq!(startup_frames[0].value()["type"], "ready");
    assert_eq!(
        startup_frames[1].value()["type"],
        "available_commands_update"
    );
    let observed: Vec<u8> = startup_frames
        .iter()
        .flat_map(|frame| frame.lines().iter().flatten().copied())
        .collect();
    assert_eq!(observed, format!("{READY_V2_JSON}\n{aux}\n").into_bytes());
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn v1_startup_frames_are_exactly_the_ready_frame() {
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' '{ready}'\nIFS= read -r hold\n",
        ready = READY_V1_JSON,
    );
    let path = write_script("startup-v1-frames", &script);
    let spec = fixture_spec(path.clone(), std::env::temp_dir());
    let mut process = OmpProcess::spawn(spec, launch_for(&path)).await.unwrap();
    assert_eq!(
        process.state(),
        OmpLifecycleState::Ready(RpcProtocolVersion::V1)
    );
    assert!(process.negotiation_frame().is_none());
    let startup: Vec<&DecodedRpcFrame> = process.startup_frames().collect();
    assert_eq!(startup.len(), 1);
    assert_eq!(startup[0], process.ready_frame().unwrap());
    process.kill().await.unwrap();
    let _ = fs::remove_file(&path);
}
