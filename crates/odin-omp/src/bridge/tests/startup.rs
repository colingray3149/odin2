use super::*;

use crate::probe::PINNED_OMP_SOURCE_REVISION;
#[cfg(unix)]
#[tokio::test]
async fn startup_frames_are_classified_and_ordered_before_fanout() {
    use std::os::unix::fs::PermissionsExt;

    let mut path = std::env::temp_dir();
    path.push(format!("odin-omp-bridge-startup-{}.sh", std::process::id()));
    let script = r#"#!/bin/sh
printf '%s\n' '{"type":"ready","protocolVersion":1,"supportedProtocolVersions":[1,2],"maxFrameBytes":1048576,"maxReassembledFrameBytes":67108864}'
printf '%s\n' '{"id":"ui-1","type":"extension_ui_request","method":"select","title":"pick one"}'
IFS= read -r request
printf '%s\n' '{"type":"session_info_update","sessionId":"fixture"}'
printf '%s\n' '{"id":"odin-omp-negotiate-protocol","type":"response","command":"negotiate_protocol","success":true,"data":{"protocolVersion":2}}'
IFS= read -r keepalive
"#;
    fs::write(&path, script).expect("write fixture");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fixture");
    let spec = OmpProcessSpec {
        executable: path.clone(),
        cwd: std::env::temp_dir(),
        explicit_args: Vec::new(),
        explicit_env: Vec::new(),
        expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
        startup_timeout: Duration::from_secs(10),
        drain_timeout: Duration::from_secs(10),
        kill_timeout: Duration::from_secs(10),
    };
    let mut process = OmpProcess::spawn(spec, crate::process::launch_for_fixture(&path))
        .await
        .expect("startup completes");
    let observed = startup_observations(&process);
    // Every startup frame is classified through the single vocabulary and
    // recorded in exact arrival order, with no runtime correlation.
    let classes: Vec<FrameClass> = observed.iter().map(|frame| frame.class).collect();
    assert_eq!(
        classes,
        vec![
            FrameClass::Ready,
            FrameClass::ExtensionUi,
            FrameClass::SessionInfo,
            FrameClass::Response,
        ]
    );
    assert!(observed
        .iter()
        .all(|frame| frame.active_command.is_none() && frame.rejection.is_none()));
    let decoded: Vec<&DecodedRpcFrame> = observed
        .iter()
        .map(|frame| frame.decoded.as_ref().expect("startup frame decoded"))
        .collect();
    assert_eq!(decoded[0].value()["type"], "ready");
    assert_eq!(decoded[1].value()["id"], "ui-1");
    assert_eq!(
            decoded[1].lines()[0],
            b"{\"id\":\"ui-1\",\"type\":\"extension_ui_request\",\"method\":\"select\",\"title\":\"pick one\"}\n"
        );
    assert_eq!(decoded[2].value()["type"], "session_info_update");
    assert_eq!(decoded[3].value()["command"], "negotiate_protocol");
    assert_eq!(
        decoded[3].value()["id"],
        crate::process::NEGOTIATE_REQUEST_ID
    );
    process.kill().await.expect("kill fixture child");
    let _ = fs::remove_file(&path);
}
