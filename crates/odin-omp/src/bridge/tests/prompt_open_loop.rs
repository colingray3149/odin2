//! The live control path's prompt is open-loop: its completion is the
//! journaled, write-acknowledged dispatch, never the turn's correlated
//! response. Awaiting that response inline parks the session actor for the
//! whole turn and starves every turn-scoped mechanism — the declared turn
//! budget's give-up, a mid-turn abort — that must act WHILE the turn is
//! live. This fixture pins the seam with a real bridge over a pinned-child
//! script that holds the prompt's correlated response: `prompt_open_loop`
//! must return while the child is still holding.

use super::fixture::child_context;
use super::*;
use std::time::{Duration, Instant};

use crate::probe::CaseContext;

/// One real bridge fixture whose child answers the startup handshake and
/// then handles every prompt with `prompt_handler` (Python source for the
/// `if kind == 'prompt':` branch), exactly like a model backend driving the
/// prompt's correlated response.
pub(super) async fn context_with_prompt_handler(
    root: &std::path::Path,
    name: &'static str,
    prompt_handler: &str,
    explicit_args: Vec<String>,
) -> CaseContext {
    let script = format!(
        r#"import json, sys, time
if '--version' in sys.argv:
    print('omp {name} fixture')
    sys.exit(0)
def emit(value):
    print(json.dumps(value), flush=True)
emit({{'type':'ready','protocolVersion':1,'supportedProtocolVersions':[1,2],
      'maxFrameBytes':1048576,'maxReassembledFrameBytes':67108864}})
for line in sys.stdin:
    command = json.loads(line)
    kind = command['type']
    data = {{}}
    answered = False
    if kind == 'prompt':
{prompt_handler}
    elif kind == 'negotiate_protocol':
        data = {{'protocolVersion':2}}
    elif kind == 'set_host_tools':
        data = {{'toolNames':[tool['name'] for tool in command['tools']]}}
    elif kind == 'set_host_uri_schemes':
        data = {{'schemes':[scheme['scheme'] for scheme in command['schemes']]}}
    elif kind == 'get_state':
        data = {{'approvedActions':0,'deniedActions':0,
                'cancelledInputs':0,'waiting':False}}
    if not answered:
        emit({{'type':'response','id':command['id'],'command':kind,'success':True,'data':data}})
"#
    );
    child_context(root, 21, name, &script, explicit_args)
}

/// One real bridge fixture whose child answers the startup handshake and
/// then HOLDS every prompt's correlated response, exactly like a model
/// backend that has not finished the turn.
async fn hold_context(root: &std::path::Path) -> CaseContext {
    context_with_prompt_handler(
        root,
        "prompt-hold",
        // Hold the turn open: the correlated response is deliberately never
        // sent promptly, so a turn-awaiting caller parks for the whole hold.
        "        time.sleep(30)\n",
        Vec::new(),
    )
    .await
}

#[tokio::test]
async fn prompt_open_loop_returns_while_the_turn_is_still_in_flight() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let context = hold_context(&root).await;
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .expect("bridge starts");
    let began = Instant::now();
    // The child holds the correlated response for 30s; the live control
    // path's completion is the dispatch, so this must return in seconds.
    // Awaiting the turn here (the pre-fix behavior) would park past the
    // timeout and fail the test.
    tokio::time::timeout(
        Duration::from_secs(10),
        bridge.prompt_open_loop(Prompt::text("hold this turn open")),
    )
    .await
    .expect("prompt_open_loop must not await the turn's completion")
    .expect("prompt dispatch succeeds");
    assert!(
        began.elapsed() < Duration::from_secs(10),
        "prompt_open_loop returned only after {:?}",
        began.elapsed()
    );
    drop(bridge);
}

/// The authenticated context refusal must be annotated BEFORE the
/// observation is journaled and fanned out: a live subscriber (the
/// supervisor's ingest pump) receives the SAME typed frame the session
/// actor journals — never a generic extension error followed by an
/// unobservable local annotation.
#[tokio::test]
async fn authenticated_context_refusal_is_annotated_before_the_subscribe_fanout() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let context = context_with_prompt_handler(
        &root,
        "refusal-fanout",
        // Hold the turn open (no correlated response) so the prompt stays
        // the live turn anchor, and emit the trusted extension's refusal
        // marker as the very next frame.
        "        emit({'type':'extension_error','extensionPath':\
'/nix/store/trusted-odin-extension/index.ts','event':'before_provider_request',\
'error':'odin.context_refusal.v1|{\"code\":\"window_exceeded\",\"reason\":\
\"measured 9000 + input 2500 + reserve 500 = 12000 exceeds the declared window 10000\",\
\"request_bytes\":9000,\"window\":10000,\"reserve\":500}'})\n        answered = True\n",
        vec![
            "--trusted-extension".to_owned(),
            "/nix/store/trusted-odin-extension/index.ts".to_owned(),
        ],
    )
    .await;
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .expect("bridge starts");
    // Subscribe BEFORE dispatch: the subscriber is the contract under
    // test, not the returned frame.
    let mut observations = bridge.subscribe();
    bridge
        .prompt_open_loop(Prompt::text("run an oversized turn"))
        .await
        .expect("prompt dispatch succeeds");
    let observed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = observations.recv().await.expect("bridge observation");
            if frame
                .value()
                .and_then(|value| value.get("type").and_then(Value::as_str))
                == Some("extension_error")
            {
                break frame;
            }
        }
    })
    .await
    .expect("the refusal frame is observed");
    let failure = observed
        .journal_failure
        .expect("the authenticated refusal reaches the subscriber ANNOTATED");
    assert_eq!(failure.code, "context_refusal.window_exceeded");
    assert!(
        failure.detail.contains("12000") && failure.detail.contains("10000"),
        "the authenticated reason is preserved: {}",
        failure.detail
    );
    assert!(
        failure.epoch.is_some(),
        "the annotation records the current binding epoch"
    );
    assert!(
        observed.active_command.is_some(),
        "the refusal anchors to the live open-loop turn command"
    );
    drop(bridge);
}

#[tokio::test]
async fn identified_prompt_recovers_exact_durable_delivery_without_resending() {
    for (name, response) in [
        ("identified-pending", None),
        ("identified-success", Some(true)),
        ("identified-failure", Some(false)),
    ] {
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().to_path_buf();
        fs::create_dir_all(&root).unwrap();
        let writes = root.join("prompts.jsonl");
        let mut handler = format!(
            "        with open({}, 'a') as log:\n            log.write(json.dumps(command) + '\\n')\n        answered = True\n",
            serde_json::to_string(&writes.to_string_lossy()).unwrap()
        );
        if let Some(success) = response {
            handler.push_str(&format!(
                "        emit({{'type':'response','id':command['id'],'command':'prompt','success':{},'error':'delivery rejected','code':'rejected'}})\n",
                if success { "True" } else { "False" }
            ));
        }
        let context = context_with_prompt_handler(&root, name, &handler, Vec::new()).await;
        let config = context.bridge_config(context.session_descriptor()).unwrap();
        let ledger = config.ledger.clone();
        let bridge = OmpBridge::start(config).await.expect("bridge starts");
        let id = CommandId::from_parts("live-report", 1, name).unwrap();
        assert_eq!(bridge.identified_prompt_outcome(&id).await.unwrap(), None);
        assert!(bridge
            .prompt_open_loop_identified(&id, Prompt::text("child report"))
            .await
            .expect("first delivery is dispatched"));
        bridge.state().await.expect("child consumed the prompt");
        let row = shared_lock(&ledger, "ledger")
            .unwrap()
            .live_command(&id)
            .unwrap();
        assert_eq!(row.body["id"], id.as_str());
        assert_eq!(row.body["message"], "child report");
        assert_eq!(row.completed_at.is_some(), response.is_some());
        let recovered = bridge
            .prompt_open_loop_identified(&id, Prompt::text("newly prepared child report"))
            .await;
        match response {
            None => assert!(!recovered.expect("pending is indeterminate")),
            Some(true) => assert!(recovered.expect("durable response proves delivery")),
            Some(false) => assert!(matches!(
                recovered,
                Err(BridgeError::CommandFailed { command, error, code })
                    if command == "prompt" && error == "delivery rejected"
                        && code.as_deref() == Some("rejected")
            )),
        }
        bridge.state().await.expect("all writes consumed");
        let written = fs::read_to_string(&writes).unwrap();
        let requests: Vec<Value> = written
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(requests, vec![row.body]);
        drop(bridge);
    }
}
