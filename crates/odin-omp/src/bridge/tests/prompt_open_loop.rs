//! The live control path's prompt is open-loop: its completion is the
//! journaled, write-acknowledged dispatch, never the turn's correlated
//! response. Awaiting that response inline parks the session actor for the
//! whole turn and starves every turn-scoped mechanism — the declared turn
//! budget's give-up, a mid-turn abort — that must act WHILE the turn is
//! live. This fixture pins the seam with a real bridge over a pinned-child
//! script that holds the prompt's correlated response: `prompt_open_loop`
//! must return while the child is still holding.

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use crate::probe::{
    CaseContext, ConformanceCaseId, FaultFixtureRuntime, OmpLaunchTemplate, ProbeConfig,
    PINNED_OMP_SOURCE_REVISION,
};

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
    let python = std::process::Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("fixture interpreter");
    assert!(python.status.success());
    let interpreter = String::from_utf8(python.stdout).unwrap();
    let executable = root.join(format!("{name}-child.py"));
    let script = format!(
        "#!{}\n{}",
        interpreter.trim(),
        &format!(
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
"#,
            name = name,
            prompt_handler = prompt_handler,
        ),
    );
    std::fs::write(&executable, &script).expect("child script");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755))
        .expect("child script executable bit");
    let atlas_root = root.join("atlas");
    for directory in ["crates", "extension", "registry", "skeletons"] {
        fs::create_dir_all(atlas_root.join(directory)).unwrap();
    }
    let atlas = Arc::new(odin_atlas::build(odin_atlas::AtlasSources::new(&atlas_root)).unwrap());
    // Recovery must check a real, isolated HOME rather than inherit the
    // developer's transcript store. An unsent first prompt legitimately has
    // no transcript yet; missing HOME is instead unverifiable continuity.
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let explicit_env = vec![("HOME".to_owned(), home.to_string_lossy().into_owned())];
    let worker = crate::process::launch_for_fixture(&executable);
    let config = Arc::new(ProbeConfig::new(
        OmpLaunchTemplate {
            executable: executable.clone(),
            explicit_args,
            explicit_env: explicit_env.clone(),
            expected_source_revision: PINNED_OMP_SOURCE_REVISION.to_owned(),
            startup_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(10),
            kill_timeout: Duration::from_secs(10),
            worker: worker.clone(),
        },
        FaultFixtureRuntime {
            bun: executable,
            explicit_env,
            worker,
        },
        root.join("work"),
        atlas,
    ));
    CaseContext::for_case(&config, ConformanceCaseId::new(21), name).unwrap()
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
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-prompt-hold-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn open_loop_prompt_mismatch_response_is_annotated_for_the_session_journal() {
    // The immediate-response case: the child answers the prompt's
    // correlated response WITHOUT holding it, so the response can be
    // correlated while prompt_open_loop's receiver is still alive — a
    // receiver-timing annotation (send-failure detection) would deliver
    // the failure into a receiver that is then dropped unread and lose it.
    // The dispatch-time ReplyDelivery::Observed mode decides the
    // annotation before the wire write, independent of that race.
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-prompt-mismatch-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let context = context_with_prompt_handler(
        &root,
        "prompt-mismatch",
        // Answer the prompt with a DIFFERENT command name than the pending
        // request: the correlated response is a mismatch, and the open-loop
        // dispatch has no waiter to receive the typed failure.
        "        emit({'type':'response','id':command['id'],'command':'steer',\
'success':True,'data':{}})\n        answered = True\n",
        Vec::new(),
    )
    .await;
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .expect("bridge starts");
    // Subscribe BEFORE dispatch so the mismatched response cannot be
    // missed; prompt_open_loop drops its response waiter when it returns.
    let mut observations = bridge.subscribe();
    bridge
        .prompt_open_loop(Prompt::text("answer with a mismatched response"))
        .await
        .expect("prompt dispatch succeeds");
    let mismatched = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = observations.recv().await.expect("bridge observation");
            if frame.journal_failure.is_some() {
                break frame;
            }
        }
    })
    .await
    .expect("the mismatched response is observed");
    let failure = mismatched
        .journal_failure
        .expect("the dropped waiter failure annotates the frame");
    assert_eq!(failure.code, "response_mismatch");
    assert!(
        failure.detail.contains("expected `prompt`") && failure.detail.contains("got `steer`"),
        "the expected versus answered command is preserved: {}",
        failure.detail
    );
    // The ambiguous command is durable evidence: later mutating work is
    // refused rather than replayed.
    assert!(
        matches!(
            bridge.steer("redirect".to_owned(), Vec::new()).await,
            Err(BridgeError::BlockedIncomplete { .. })
        ),
        "a mismatched open-loop response blocks later mutating work"
    );
    drop(bridge);
    let _ = std::fs::remove_dir_all(&root);
}

/// The authenticated context refusal must be annotated BEFORE the
/// observation is journaled and fanned out: a live subscriber (the
/// supervisor's ingest pump) receives the SAME typed frame the session
/// actor journals — never a generic extension error followed by an
/// unobservable local annotation.
#[tokio::test]
async fn authenticated_context_refusal_is_annotated_before_the_subscribe_fanout() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-refusal-fanout-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}

/// At the dispatch boundary, annotation follows CORRELATION, never raw
/// payload shape: the matched open-loop rejection rides the frame typed,
/// while an otherwise-identical rejection with no pending command stays
/// unannotated evidence that can never type a session terminal.
#[tokio::test]
async fn open_loop_rejection_annotation_requires_correlation() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-reject-correlation-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let context = context_with_prompt_handler(
        &root,
        "reject-correlation",
        // Answer the prompt's own id with a matched rejection, then emit
        // the same rejection shape under an id that was never dispatched.
        "        emit({'type':'response','id':command['id'],'command':'prompt',\
'success':False,'code':'over_budget','error':'no provider capacity'})\n        \
emit({'type':'response','id':'never-dispatched','command':'prompt',\
'success':False,'code':'stale','error':'stale rejection'})\n        answered = True\n",
        Vec::new(),
    )
    .await;
    let bridge = OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
        .await
        .expect("bridge starts");
    let mut observations = bridge.subscribe();
    bridge
        .prompt_open_loop(Prompt::text("answer with a rejection"))
        .await
        .expect("prompt dispatch succeeds");
    let (matched, unmatched) = tokio::time::timeout(Duration::from_secs(10), async {
        let mut matched = None;
        let mut unmatched = None;
        while matched.is_none() || unmatched.is_none() {
            let frame = observations.recv().await.expect("bridge observation");
            let Some(value) = frame.value() else {
                continue;
            };
            if value.get("type").and_then(Value::as_str) != Some("response") {
                continue;
            }
            match value.get("id").and_then(Value::as_str) {
                Some("never-dispatched") => unmatched = Some(frame),
                Some(_) if frame.active_command.is_some() => matched = Some(frame),
                _ => {}
            }
        }
        (matched.unwrap(), unmatched.unwrap())
    })
    .await
    .expect("both responses are observed");
    // The correlated open-loop rejection is typed for the session journal.
    let failure = matched
        .journal_failure
        .expect("the correlated rejection is annotated");
    assert_eq!(failure.code, "over_budget");
    assert!(failure.detail.contains("no provider capacity"));
    assert!(failure.epoch.is_some());
    // The unmatched one — identical payload shape — stays evidence only.
    assert!(
        unmatched.journal_failure.is_none(),
        "an unmatched rejection never carries a typed annotation"
    );
    assert!(unmatched.active_command.is_none());
    drop(bridge);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn identified_prompt_recovers_exact_durable_delivery_without_resending() {
    for (name, response) in [
        ("identified-pending", None),
        ("identified-success", Some(true)),
        ("identified-failure", Some(false)),
    ] {
        let root = std::env::temp_dir().join(format!("odin-omp-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
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
        let _ = fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn identified_prompt_proven_unsent_recovery_refuses_old_attempt_and_allows_replacement() {
    let root =
        std::env::temp_dir().join(format!("odin-omp-identified-unsent-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let writes = root.join("prompts.jsonl");
    let handler = format!(
        "        with open({}, 'a') as log:\n            log.write(json.dumps(command) + '\\n')\n",
        serde_json::to_string(&writes.to_string_lossy()).unwrap()
    );
    let context =
        context_with_prompt_handler(&root, "identified-unsent", &handler, Vec::new()).await;
    let config = context.bridge_config(context.session_descriptor()).unwrap();
    let ledger = config.ledger.clone();
    let bridge = OmpBridge::start(config).await.expect("bridge starts");
    let id = CommandId::from_parts("live-report", 1, "unsent").unwrap();

    // Fail issued-event append after command commit so recovery must recognize no dispatch.
    shared_lock(&ledger, "ledger")
        .unwrap()
        .connection()
        .execute_batch(
            "CREATE TEMP TRIGGER fail_prompt_issued BEFORE INSERT ON live_events
             WHEN json_extract(NEW.body_json, '$.kind') = 'command_issued'
              AND json_extract(NEW.body_json, '$.command') = 'prompt'
             BEGIN SELECT RAISE(ABORT, 'injected prompt issued-event failure'); END;",
        )
        .unwrap();
    assert!(bridge
        .prompt_open_loop_identified(&id, Prompt::text("child report"))
        .await
        .is_err());
    {
        let ledger = shared_lock(&ledger, "ledger").unwrap();
        let row = ledger.live_command(&id).unwrap();
        assert_eq!(row.body["id"], id.as_str());
        assert!(row.completed_at.is_none());
        assert!(row.outcome.is_none());
        let (issued, answered) =
            pending_command_evidence(&ledger, &row.session_id, &BTreeSet::from([id.clone()]))
                .unwrap();
        assert!(issued.is_empty());
        assert!(answered.is_empty());
        ledger
            .connection()
            .execute_batch("DROP TRIGGER fail_prompt_issued;")
            .unwrap();
    }
    assert_eq!(
        bridge.identified_prompt_outcome(&id).await.unwrap(),
        Some(false)
    );
    assert!(
        !writes.exists(),
        "the interrupted attempt never reached the child"
    );

    bridge
        .recover()
        .await
        .expect("real bridge recovery completes the unsent row");
    let row = shared_lock(&ledger, "ledger")
        .unwrap()
        .live_command(&id)
        .unwrap();
    assert!(row.completed_at.is_some());
    assert_eq!(
        row.outcome,
        Some(json!({
            "kind": "not_dispatched_before_crash",
            "command_id": id.as_str(),
            "command": "prompt",
        }))
    );
    for result in [
        bridge.identified_prompt_outcome(&id).await,
        bridge
            .prompt_open_loop_identified(&id, Prompt::text("must not resend"))
            .await
            .map(Some),
    ] {
        assert!(
            matches!(result, Err(BridgeError::CommandFailed { command, code, .. })
            if command == "prompt" && code.as_deref() == Some("not_dispatched_before_crash"))
        );
    }
    assert!(
        !writes.exists(),
        "recovery and outcome lookup never resend the old ID"
    );

    let replacement = CommandId::from_parts("live-report", 2, "replacement").unwrap();
    assert!(bridge
        .prompt_open_loop_identified(&replacement, Prompt::text("child report"))
        .await
        .expect("a new attempt is dispatchable"));
    bridge.state().await.expect("child consumes replacement");
    assert_eq!(
        bridge
            .identified_prompt_outcome(&replacement)
            .await
            .unwrap(),
        Some(true)
    );
    let requests: Vec<Value> = fs::read_to_string(&writes)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], replacement.as_str());
    bridge.stop().await.expect("bridge stops");
    drop(bridge);
    let _ = fs::remove_dir_all(&root);
}
