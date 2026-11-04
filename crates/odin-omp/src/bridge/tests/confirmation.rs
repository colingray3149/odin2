use super::fixture::child_context;
use super::*;

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

const SCRIPT: &str = r#"
import json, sys
if '--version' in sys.argv:
    print('omp confirmation fixture')
    sys.exit(0)
def emit(value):
    print(json.dumps(value), flush=True)
pending = None
asked = approved = denied = cancelled_inputs = 0
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
        asked += 1
        pending = {'id':('ui-confirm-%d' if confirm else 'ui-input-%d') % asked,
                   'method':'confirm' if confirm else 'input'}
        emit({'type':'extension_ui_request',**pending,'title':'fixture question'})
"#;

#[tokio::test]
async fn confirmation_replies_reach_only_the_current_pending_dialog_once() {
    let root = tempfile::tempdir().unwrap();
    let context = child_context(root.path(), 1, "confirmation-wire", SCRIPT, Vec::new());
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .unwrap();
    let mut receiver = bridge.subscribe();
    let pending_id = |question: &Value| {
        odin_domain::huginn::PermissionRequestId::new(question["id"].as_str().unwrap()).unwrap()
    };
    bridge.prompt(Prompt::text("confirm")).await.unwrap();
    let id = pending_id(&observed(&mut receiver, "extension_ui_request").await);
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

    // The next dialog of the same child is answered on its own; answered dialogs leave the table.
    bridge.prompt(Prompt::text("confirm")).await.unwrap();
    let second = pending_id(&observed(&mut receiver, "extension_ui_request").await);
    assert_ne!(second, id);
    bridge.reply_to_confirmation(&second, false).await.unwrap();
    observed(&mut receiver, "session_info_update").await;
    assert!(bridge
        .shared_for_test()
        .side_guard()
        .unwrap()
        .confirmations
        .is_empty());
    assert_eq!(bridge.state().await.unwrap()["deniedActions"], 1);

    bridge.prompt(Prompt::text("input")).await.unwrap();
    observed(&mut receiver, "session_info_update").await;
    let state = bridge.state().await.unwrap();
    assert_eq!(state["approvedActions"], 1);
    assert_eq!(state["cancelledInputs"], 1);
    assert_eq!(state["waiting"], false);
    bridge.stop().await.unwrap();
    assert!(bridge.reply_to_confirmation(&id, true).await.is_err());
}
