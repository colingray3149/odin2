//! Fresh-context rollover removes session selectors for local and remote launches.
//! Default launch preserves transcripts; adding `--no-session` would lose them.

use super::*;
use crate::live::rollover::{
    PodRollover, RolloverChildState, RolloverChildrenSource, RolloverPolicy, RolloverRuntimeConfig,
};

pub(super) struct NoDelegatedChildren;

#[async_trait::async_trait]
impl RolloverChildrenSource for NoDelegatedChildren {
    async fn children(
        &self,
        _parent: &SessionId,
        _cap: usize,
    ) -> Result<Vec<RolloverChildState>, String> {
        Ok(Vec::new())
    }
    async fn assignment(&self, _session: &SessionId) -> Result<Option<String>, String> {
        Ok(None)
    }
}

#[tokio::test]
#[cfg(unix)]
async fn a_context_refusal_rollover_respawns_a_fresh_incarnation_with_one_brief() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        &root,
        "rollover-fresh",
        // The fresh incarnation answers its one continuity prompt.
        "        pass\n",
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");

    let epoch_before = bridge.binding().unwrap().epoch;
    let epoch_after = bridge
        .rollover_context_refusal(209, None)
        .await
        .expect("the typed rollover respawns a fresh incarnation");
    assert_eq!(epoch_after, epoch_before + 1);
    assert_eq!(bridge.binding().unwrap().epoch, epoch_after);

    // The durable journal carries the typed trigger, the completion, and
    // exactly ONE reinjection prompt starting with the rollover marker.
    let ledger = context.ledger();
    let events = {
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    let triggered = events
        .iter()
        .filter(|event| {
            event.body.get("kind").and_then(Value::as_str) == Some("rollover_triggered")
        })
        .count();
    let completed = events
        .iter()
        .filter(|event| {
            event.body.get("kind").and_then(Value::as_str) == Some("rollover_completed")
        })
        .count();
    assert_eq!(triggered, 1, "one rollover_triggered: {events:?}");
    assert_eq!(completed, 1, "one rollover_completed: {events:?}");
    let prompts: Vec<&Value> = events
        .iter()
        .filter(|event| {
            event.body.get("kind").and_then(Value::as_str) == Some("command_issued")
                && event.body.get("command").and_then(Value::as_str) == Some("prompt")
        })
        .map(|event| &event.body)
        .collect();
    assert_eq!(prompts.len(), 1, "ONE journaled reinjection: {prompts:?}");
    let message = prompts[0]["frame"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("[ODIN ROLLOVER"),
        "the reinjection starts with the marker: {message}"
    );
    assert!(
        message.contains("trigger=context_refusal]") && message.contains("epoch="),
        "the reinjection header names the trigger and the epoch swap: {message}"
    );

    // The fresh incarnation really speaks the protocol (a real respawned
    // carrier over the selector-stripped argv answered the handshake).
    let state = bridge.state().await.expect("the fresh incarnation answers");
    assert_eq!(state.get("waiting").and_then(Value::as_bool), Some(false));
    bridge.stop().await.unwrap();
}

/// Settled turns past the declared watermark roll the session over on their own:
/// one trigger, one fresh incarnation with one brief, and the measured usage record.
#[tokio::test]
#[cfg(unix)]
async fn settled_turns_past_the_threshold_roll_the_session_over_once() {
    let root_dir = tempfile::tempdir().unwrap();
    let marker = serde_json::to_string(crate::live::rollover::ROLLOVER_PROMPT_MARKER).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        root_dir.path(),
        "rollover-threshold",
        // Every prompt settles a turn; the continuity brief's turn is small, the rest are large.
        &format!(
            "        emit({{'type':'response','id':command['id'],'command':'prompt',\
'success':True,'data':{{}}}})\n        answered = True\n        \
usage = 100 if command['message'].startswith({marker}) else 5000\n        \
emit({{'type':'agent_start'}})\n        \
emit({{'type':'agent_end','usage':{{'input':usage,'output':10}}}})\n"
        ),
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    let policy = RolloverPolicy {
        threshold_tokens: 1_000,
        ..RolloverPolicy::default()
    };
    config.rollover = Some(RolloverRuntimeConfig::new(policy).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");
    let epoch_before = bridge.binding().unwrap().epoch;
    let mut observations = bridge.subscribe();
    for text in ["first", "second"] {
        bridge.prompt(Prompt::text(text)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let frame = observations.recv().await.expect("bridge observation");
                if frame
                    .value()
                    .is_some_and(|value| value["type"] == "agent_end")
                {
                    break;
                }
            }
        })
        .await
        .expect("the turn settles");
    }

    let ledger = context.ledger();
    let session = context.ids().session.clone();
    let events = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let events = {
                let guard = ledger.lock().expect("case ledger lock");
                let head = guard.reconnect_head(&session).unwrap();
                guard.live_event_history(&session, 0, head).unwrap()
            };
            if events
                .iter()
                .any(|event| event.body["kind"] == "rollover_completed")
            {
                break events;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the threshold rollover completes");
    let kinds = |kind: &str| -> Vec<&Value> {
        events
            .iter()
            .map(|event| &event.body)
            .filter(|body| body["kind"] == kind)
            .collect()
    };
    assert_eq!(kinds("rollover_triggered").len(), 1);
    let completed = kinds("rollover_completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["trigger"], "threshold");
    assert_eq!(
        completed[0]["settled"], true,
        "the reinjection turn settled"
    );
    assert_eq!(completed[0]["epoch_after"], epoch_before + 1);
    assert_eq!(bridge.binding().unwrap().epoch, epoch_before + 1);
    assert!(
        completed[0]["usage_digest"].is_string(),
        "the measured usage artifact is recorded"
    );
    bridge.stop().await.unwrap();
}

/// The journaled model selection rides INTO the rollover: the re-assert
/// is journaled AFTER the fresh respawn and BEFORE the reinjection
/// prompt, so the incarnation's first turn runs the selected model and
/// its context budget — never the launch pair with a correction after
/// the turn was already admitted.
#[tokio::test]
#[cfg(unix)]
async fn a_rollover_reasserts_the_selected_model_before_the_reinjection() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        &root,
        "rollover-model",
        "        pass\n",
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");

    let epoch_before = bridge.binding().unwrap().epoch;
    let epoch_after = bridge
        .rollover_context_refusal(401, Some(("gateway".to_owned(), "kimi-k31".to_owned())))
        .await
        .expect("the typed rollover respawns fresh on the selected model");
    assert_eq!(epoch_after, epoch_before + 1);

    let events = {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    let commands: Vec<(usize, &str, &Value)> = events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            (event.body.get("kind").and_then(Value::as_str) == Some("command_issued"))
                .then(|| {
                    let command = event.body.get("command").and_then(Value::as_str)?;
                    Some((index, command, event.body.get("frame")?))
                })
                .flatten()
        })
        .collect();
    let model_at = commands
        .iter()
        .find(|(_, command, _)| *command == "set_model")
        .expect("the rollover journals one set_model re-assert");
    assert_eq!(
        model_at.2.get("provider").and_then(Value::as_str),
        Some("gateway"),
        "the re-assert names the selected provider: {model_at:?}"
    );
    assert_eq!(
        model_at.2.get("modelId").and_then(Value::as_str),
        Some("kimi-k31")
    );
    let reinjection_at = commands
        .iter()
        .rev()
        .find(|(_, command, _)| *command == "prompt")
        .expect("the reinjection prompt is journaled");
    assert!(
        reinjection_at.2["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("[ODIN ROLLOVER"),
        "the last prompt is the reinjection"
    );
    assert!(
        model_at.0 < reinjection_at.0,
        "the model re-assert precedes the reinjection: set_model@{} < prompt@{}",
        model_at.0,
        reinjection_at.0
    );
    assert_eq!(
        commands
            .iter()
            .filter(|(_, command, _)| *command == "set_model")
            .count(),
        1,
        "exactly one re-assert — none after the turn"
    );
    bridge.stop().await.unwrap();
}

/// A rejected reinjection response is TYPED evidence, never a silent
/// completion: the refusal trigger returns at the journaled dispatch
/// admission, so its reinjection owns no waiter — Observed delivery
/// annotates the rejected correlated response on the frame for the
/// session journal, where the actor's normalizer turns it into the typed
/// failure the kernel answers, instead of an error sent to a dropped
/// receiver.
#[tokio::test]
#[cfg(unix)]
async fn a_rejected_reinjection_is_typed_evidence_not_a_silent_completion() {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().to_path_buf();
    std::fs::create_dir_all(&root).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        &root,
        "rollover-reject",
        "        emit({'type':'response','id':command['id'],'command':'prompt','success':False,\
         'error':'the provider refused the turn','code':'provider_overload'})\n\
         \x20       answered = True\n",
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");
    let mut observations = bridge.subscribe();
    let epoch_after = bridge
        .rollover_context_refusal(402, None)
        .await
        .expect("the rollover itself completes at the dispatch admission");

    // The rejected correlated response arrives as an ANNOTATED observed
    // frame — the typed evidence the actor normalizes.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let annotated = loop {
        let frame = tokio::time::timeout_at(deadline.into(), observations.recv())
            .await
            .expect("the rejected reinjection response arrives")
            .expect("observation channel stays open");
        if frame
            .value()
            .and_then(|value| value.get("success").and_then(Value::as_bool))
            == Some(false)
            && frame
                .value()
                .and_then(|value| value.get("command"))
                .and_then(Value::as_str)
                == Some("prompt")
        {
            break frame;
        }
    };
    let failure = annotated
        .journal_failure
        .expect("the rejection is annotated on the observed frame");
    assert_eq!(failure.code, "provider_overload");

    // The journal carries the typed rejection durably, and the rollover
    // completion stays truthful about what completed.
    let events = {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    assert!(events.iter().any(|event| {
        event.body.get("kind").and_then(Value::as_str) == Some("command_response")
            && event.body.get("command").and_then(Value::as_str) == Some("prompt")
            && event.body.get("success").and_then(Value::as_bool) == Some(false)
    }));
    assert_eq!(
        events
            .iter()
            .filter(|event| {
                event.body.get("kind").and_then(Value::as_str) == Some("rollover_completed")
            })
            .count(),
        1,
        "the completion names only the rollover, beside the typed turn failure"
    );
    assert_eq!(
        epoch_after, 2,
        "the fresh incarnation still advanced one epoch"
    );
    bridge.stop().await.unwrap();
}

/// A pod's rollover contract: the checkpoint at 70% of the card window, the
/// given budget, and one staged launch input.
fn pod_config(max_rollovers: Option<u8>) -> RolloverRuntimeConfig {
    let policy = RolloverPolicy {
        window_fraction: Some(70),
        ..RolloverPolicy::default()
    };
    let pod = PodRollover {
        max_rollovers,
        launch_inputs: vec!["/var/run/odin/staging/input-1".to_owned()],
    };
    RolloverRuntimeConfig::for_pod(policy, pod).unwrap()
}

/// The session's durable journal bodies, oldest first.
fn journal(context: &crate::probe::CaseContext) -> Vec<Value> {
    let ledger = context.ledger();
    let guard = ledger.lock().expect("case ledger lock");
    let session = context.ids().session.clone();
    let head = guard.reconnect_head(&session).unwrap();
    guard
        .live_event_history(&session, 0, head)
        .unwrap()
        .into_iter()
        .map(|event| event.body)
        .collect()
}

/// The journaled prompt or steer frames of one command name.
fn commands_named(bodies: &[Value], command: &str) -> Vec<Value> {
    bodies
        .iter()
        .filter(|body| {
            body.get("kind").and_then(Value::as_str) == Some("command_issued")
                && body.get("command").and_then(Value::as_str) == Some(command)
        })
        .filter_map(|body| body.get("frame").cloned())
        .collect()
}

/// A pod's mid-loop usage past its checkpoint steers its running turn, once
/// per context epoch, to write its notes; the turn itself is left running.
#[tokio::test]
#[cfg(unix)]
async fn a_pod_checkpoint_steers_its_running_turn_once_per_epoch() {
    let root_dir = tempfile::tempdir().unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        root_dir.path(),
        "pod-checkpoint",
        // Two mid-loop frames past the checkpoint and no terminal frame.
        concat!(
            "        emit({'type':'response','id':command['id'],'command':'prompt',",
            "'success':True,'data':{}})\n",
            "        answered = True\n",
            "        emit({'type':'agent_start'})\n",
            "        emit({'type':'turn_end','message':{'role':'assistant',",
            "'usage':{'input':9000,'output':10}}})\n",
            "        emit({'type':'turn_end','message':{'role':'assistant',",
            "'usage':{'input':9100,'output':10}}})\n",
        ),
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(pod_config(Some(4)));
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");
    bridge
        .bind_rollover_card(10_000, 9_000)
        .expect("the card window binds");
    bridge
        .prompt_open_loop(Prompt::text("work the brief"))
        .await
        .expect("the turn starts");

    tokio::time::timeout(Duration::from_secs(10), async {
        while commands_named(&journal(&context), "steer").is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the checkpoint steer is journaled");
    // The second mid-loop frame stays in the same epoch: no second steer.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let steers = commands_named(&journal(&context), "steer");
    assert_eq!(steers.len(), 1, "one steer per epoch: {steers:?}");
    let message = steers[0]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("/export/notes.md") && message.contains("90%"),
        "the steer names the notes and the context share: {message}"
    );
    bridge.stop().await.unwrap();
}

/// An authenticated window refusal in a pod is one rollover: a fresh
/// incarnation resumes from the notes and the launch input.
#[tokio::test]
#[cfg(unix)]
async fn a_pod_window_refusal_rolls_over_once_with_the_notes_continuation() {
    let root_dir = tempfile::tempdir().unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        root_dir.path(),
        "pod-rollover",
        "        pass\n",
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(pod_config(Some(2)));
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");

    let epoch_before = bridge.binding().unwrap().epoch;
    let epoch_after = bridge
        .rollover_context_refusal(209, None)
        .await
        .expect("the pod rolls over its window refusal");
    assert_eq!(epoch_after, epoch_before + 1);

    let bodies = journal(&context);
    let triggered = bodies
        .iter()
        .filter(|body| body.get("kind").and_then(Value::as_str) == Some("rollover_triggered"))
        .count();
    assert_eq!(triggered, 1, "one rollover_triggered: {bodies:?}");
    let prompts = commands_named(&bodies, "prompt");
    assert_eq!(prompts.len(), 1, "ONE reinjection: {prompts:?}");
    let message = prompts[0]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("[ODIN ROLLOVER")
            && message.contains("/export/notes.md")
            && message.contains("/var/run/odin/staging/input-1")
            && !message.contains("ready."),
        "the pod continuation names its notes and input, and orders work: {message}"
    );
    assert!(
        !message.contains("/export/report.md"),
        "the first of two rollovers does not order the report: {message}"
    );
    bridge.stop().await.unwrap();
}

/// A pod whose rollover budget is spent is not rolled over again. The last
/// allowed rollover orders the report; the refusal after it changes nothing.
#[tokio::test]
#[cfg(unix)]
async fn a_pod_past_its_rollover_budget_is_not_rolled_over() {
    let root_dir = tempfile::tempdir().unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        root_dir.path(),
        "pod-budget",
        // The reinjection turn answers and settles, as a real turn does.
        concat!(
            "        emit({'type':'response','id':command['id'],'command':'prompt',",
            "'success':True,'data':{}})\n",
            "        answered = True\n",
            "        emit({'type':'agent_end','usage':{'input':10,'output':1}})\n",
        ),
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(pod_config(Some(1)));
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");

    let last = bridge
        .rollover_context_refusal(209, None)
        .await
        .expect("the one allowed rollover runs");
    let prompts = commands_named(&journal(&context), "prompt");
    assert!(
        prompts[0]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("/export/report.md"),
        "the last allowed rollover orders the report: {prompts:?}"
    );

    // A real second refusal arrives a whole turn later; retry until the
    // reinjection turn settles and releases its in-flight prompt.
    let refused = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match bridge.rollover_context_refusal(210, None).await {
                Err(error) if error.to_string().contains("in flight") => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                other => break other,
            }
        }
    })
    .await
    .expect("the reinjection turn settles")
    .expect_err("the spent budget refuses the next rollover");
    assert!(
        refused.to_string().contains("budget spent"),
        "the refusal names the spent budget: {refused}"
    );
    assert_eq!(bridge.binding().unwrap().epoch, last, "no respawn happened");
    let triggered = journal(&context)
        .iter()
        .filter(|body| body.get("kind").and_then(Value::as_str) == Some("rollover_triggered"))
        .count();
    assert_eq!(triggered, 1, "the refused rollover is not admitted");
    bridge.stop().await.unwrap();
}
