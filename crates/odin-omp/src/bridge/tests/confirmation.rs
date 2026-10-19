use super::*;
use std::os::unix::fs::PermissionsExt;

use crate::probe::{
    CaseContext, ConformanceCaseId, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
    PINNED_OMP_SOURCE_REVISION,
};

async fn observed(receiver: &mut broadcast::Receiver<ObservedFrame>, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = receiver.recv().await.expect("bridge observation");
            if let Some(value) = frame.value() {
                if value.get("type").and_then(Value::as_str) == Some(kind) {
                    return value.clone();
                }
            }
        }
    })
    .await
    .expect("bounded observation")
}

#[tokio::test]
async fn confirmation_replies_reach_only_the_current_pending_dialog_once() {
    let root = tempfile::tempdir().unwrap();
    let python = std::process::Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("fixture interpreter");
    assert!(python.status.success());
    let interpreter = String::from_utf8(python.stdout).unwrap();
    let executable = root.path().join("confirmation-child.py");
    let script = format!(
        "#!{}\n{}",
        interpreter.trim(),
        r#"
import json, sys
if '--version' in sys.argv:
    print('omp confirmation fixture')
    sys.exit(0)
def emit(value):
    print(json.dumps(value), flush=True)
pending = None
approved = denied = cancelled_inputs = 0
emit({'type':'ready','protocolVersion':1,'supportedProtocolVersions':[1,2],
      'maxFrameBytes':1048576,'maxReassembledFrameBytes':67108864})
for line in sys.stdin:
    command = json.loads(line)
    kind = command['type']
    if kind == 'extension_ui_response':
        assert pending is not None and command['id'] == pending['id']
        if pending['method'] == 'confirm':
            assert isinstance(command.get('confirmed'), bool)
            if command['confirmed']:
                approved += 1
            else:
                denied += 1
        else:
            assert command.get('cancelled') is True
            cancelled_inputs += 1
        pending = None
        emit({'type':'session_info_update','continuation':'completed'})
        emit({'type':'agent_end'})
        continue
    data = {}
    if kind == 'negotiate_protocol':
        data = {'protocolVersion':2}
    elif kind == 'set_host_tools':
        data = {'toolNames':[tool['name'] for tool in command['tools']]}
    elif kind == 'set_host_uri_schemes':
        data = {'schemes':[scheme['scheme'] for scheme in command['schemes']]}
    elif kind == 'get_state':
        data = {'approvedActions':approved,'deniedActions':denied,
                'cancelledInputs':cancelled_inputs,'waiting':pending is not None}
    emit({'type':'response','id':command['id'],'command':kind,'success':True,'data':data})
    if kind == 'prompt':
        confirm = command['message'] == 'confirm'
        emit({'type':'agent_start'})
        pending = {'id':'ui-confirm' if confirm else 'ui-input',
                   'method':'confirm' if confirm else 'input'}
        emit({'type':'extension_ui_request',**pending,'title':'fixture question'})
"#
    );
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let atlas_root = root.path().join("atlas");
    for directory in ["crates", "extension", "registry", "skeletons"] {
        fs::create_dir_all(atlas_root.join(directory)).unwrap();
    }
    let atlas = Arc::new(odin_atlas::build(odin_atlas::AtlasSources::new(&atlas_root)).unwrap());
    let worker = crate::process::launch_for_fixture(&executable);
    let config = Arc::new(ProbeConfig::new(
        OmpLaunchTemplate {
            executable: executable.clone(),
            explicit_args: Vec::new(),
            explicit_env: Vec::new(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(10),
            worker: worker.clone(),
        },
        FaultFixtureRuntime {
            bun: executable,
            explicit_env: Vec::new(),
            worker,
        },
        root.path().join("work"),
        atlas,
    ));
    let context =
        CaseContext::for_case(&config, ConformanceCaseId::new(1), "confirmation-wire").unwrap();
    let bridge_config = context.bridge_config(context.session_descriptor()).unwrap();
    let bridge = OmpBridge::start(bridge_config).await.unwrap();
    let mut receiver = bridge.subscribe();
    bridge.prompt(Prompt::text("confirm")).await.unwrap();
    let question = observed(&mut receiver, "extension_ui_request").await;
    let id =
        odin_domain::huginn::PermissionRequestId::new(question["id"].as_str().unwrap()).unwrap();
    let foreign = odin_domain::huginn::PermissionRequestId::new("not-requested").unwrap();
    assert!(bridge.reply_to_confirmation(&foreign, true).await.is_err());
    bridge.reply_to_confirmation(&id, true).await.unwrap();
    observed(&mut receiver, "session_info_update").await;
    assert!(bridge.reply_to_confirmation(&id, true).await.is_err());
    assert!(bridge.reply_to_confirmation(&id, false).await.is_err());
    let state = bridge.state().await.unwrap();
    assert_eq!(state["approvedActions"], 1);
    assert_eq!(state["deniedActions"], 0);
    assert_eq!(state["waiting"], false);

    bridge.prompt(Prompt::text("input")).await.unwrap();
    observed(&mut receiver, "session_info_update").await;
    let state = bridge.state().await.unwrap();
    assert_eq!(state["approvedActions"], 1);
    assert_eq!(state["cancelledInputs"], 1);
    assert_eq!(state["waiting"], false);
    bridge.stop().await.unwrap();
    assert!(bridge.reply_to_confirmation(&id, true).await.is_err());
}
