//! A session restarted over its lane window still serves its next prompt.
//!
//! The incident this pins: a parked session resumed by `session restart`
//! with a stored context (42k qwen3 tokens) already past its lane window
//! (32768). The dispatched prompt drove the pinned harness into pre-prompt
//! context maintenance, whose own compaction request the trusted extension
//! refused; the refusal's user-interrupt abort dropped the pending prompt
//! silently — no provider request, no frame, no typed terminal, the session
//! "Running" forever. The dispatch guard now refuses the cannot-fit turn
//! host-side and the fresh-context rollover answers it, so the turn runs on
//! a fresh conversation and the model request goes out.

use super::fixture::child_context;
use super::*;
use std::time::Duration;

use odin_domain::huginn::{LiveContentBlock, LiveMessage, ModelName, ProviderName};

use crate::live::control::{
    BridgeControl, LaneContextBudget, LaneContextBudgets, LiveControlBackend,
};
use crate::live::rollover::{RolloverPolicy, RolloverRuntimeConfig, ROLLOVER_PROMPT_MARKER};
use crate::probe::CaseContext;
use odin_brain::context::QWEN3_TOKENIZER_ID;
use odin_domain::knowledge::ids::TokenizerId;

/// One real bridge fixture whose child plays the resumed-over-window
/// harness: launched with `--resume` it reports a context usage that no
/// turn can fit and drops every prompt silently (the pre-prompt maintenance
/// wedge); launched fresh — the rollover's selector-stripped respawn — it
/// reports a fitting context, records every prompt it serves, and answers.
fn resumed_over_window_context(
    root: &std::path::Path,
    name: &'static str,
    transcript: &std::path::Path,
    log: &std::path::Path,
) -> CaseContext {
    let script = format!(
        r#"import json, os, sys
if '--version' in sys.argv:
    print('omp {name} fixture')
    sys.exit(0)
resumed = '--resume' in sys.argv
log_path = sys.argv[sys.argv.index('--prompt-log') + 1]
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
        if resumed:
            # Pre-prompt context maintenance on a context that cannot fit:
            # the compaction request is refused and aborted, the pending
            # prompt is dropped — no response, no frames, nothing served.
            answered = True
        else:
            with open(log_path, 'a') as log:
                log.write(command['message'] + '\n')
    elif kind == 'negotiate_protocol':
        data = {{'protocolVersion':2}}
    elif kind == 'set_host_tools':
        data = {{'toolNames':[tool['name'] for tool in command['tools']]}}
    elif kind == 'set_host_uri_schemes':
        data = {{'schemes':[scheme['scheme'] for scheme in command['schemes']]}}
    elif kind == 'get_state':
        usage = 8500 if resumed else 100
        data = {{'model': {{'provider':'gateway','id':'kubert-mini',
                          'contextWindow':8000,'tokenizer':'qwen3'}},
                'contextUsage': {{'tokens': usage, 'contextWindow': 8000}}}}
    if not answered:
        emit({{'type':'response','id':command['id'],'command':kind,'success':True,'data':data}})
"#
    );
    std::fs::write(transcript, b"{}\n").expect("resumed transcript");
    // The park-resume relaunch carries the harness transcript.
    child_context(
        root,
        21,
        name,
        &script,
        vec![
            "--resume".to_owned(),
            transcript.to_string_lossy().into_owned(),
            "--prompt-log".to_owned(),
            log.to_string_lossy().into_owned(),
        ],
    )
}

#[tokio::test]
#[cfg(unix)]
async fn a_restarted_session_over_its_window_rolls_fresh_and_serves_the_prompt() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let log = root.join("served-prompts.log");
    let transcript = root.join("transcript.jsonl");
    let context = resumed_over_window_context(&root, "parked-resume", &transcript, &log);
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(super::rollover_fresh::NoDelegatedChildren));
    let bridge = Arc::new(
        OmpBridge::start(config)
            .await
            .expect("the resumed bridge starts"),
    );
    let epoch_before = bridge.binding().unwrap().epoch;
    let control = BridgeControl::new(Arc::clone(&bridge), Arc::new(super::context_epoch::NoHooks))
        .with_lane_context_budgets(
            Some(
                LaneContextBudgets::new(vec![LaneContextBudget {
                    provider: "gateway".to_owned(),
                    model: "kubert-mini".to_owned(),
                    window: 8000,
                    reserve: 1024,
                    tokenizer: TokenizerId::new(QWEN3_TOKENIZER_ID).expect("qwen3 tokenizer id"),
                }])
                .expect("declared lane"),
            ),
            &ProviderName::new("gateway").expect("provider"),
            &ModelName::new("kubert-mini").expect("model"),
        );

    // The operator's prompt after the restart: before the fix this
    // dispatched into the wedged resumed context and nothing was ever
    // served; now it refuses cannot-fit, rolls a fresh context, and the
    // turn runs there.
    let message = LiveMessage {
        content: vec![LiveContentBlock::Text("still there?".to_owned())],
    };
    control
        .prompt(&message, Some("still there?"))
        .await
        .expect("the prompt is served on a fresh context");

    // The fresh incarnation — the only one that ever writes the log —
    // serves the rollover's continuity brief and then the prompt itself.
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(text) = std::fs::read_to_string(&log) {
                let lines: Vec<String> = text.lines().map(str::to_owned).collect();
                if lines.iter().any(|line| line.contains("still there?"))
                    && lines
                        .iter()
                        .any(|line| line.starts_with(ROLLOVER_PROMPT_MARKER))
                {
                    return lines;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the model request goes out on the fresh context");
    assert!(
        served.iter().any(|line| line.contains("still there?")),
        "the operator's turn reached a serving context: {served:?}"
    );
    // The rollover advanced the session epoch, and the durable journal
    // names the guard's context-refusal trigger.
    let binding = bridge.binding().unwrap();
    assert_eq!(
        binding.epoch,
        epoch_before + 1,
        "the rollover advanced the epoch"
    );
    let ledger = context.ledger();
    let events = {
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    assert!(
        events.iter().any(|event| {
            event.body["kind"] == "rollover_completed" && event.body["trigger"] == "context_refusal"
        }),
        "the journal records the guard-triggered rollover"
    );
    drop(control);
}
