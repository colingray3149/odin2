//! Fresh-context rollover removes session selectors for local and remote launches.
//! Default launch preserves transcripts; adding `--no-session` would lose them.

use super::*;
use crate::live::rollover::{
    RolloverChildState, RolloverChildrenSource, RolloverPolicy, RolloverRuntimeConfig,
};

struct NoDelegatedChildren;

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

/// Remove all selector forms while preserving unrelated flags and their values.
#[test]
fn a_fresh_context_respawn_argv_carries_no_session_selector() {
    let mut args = vec![
        "workload-exec".to_owned(),
        "--resume".to_owned(),
        "/state/transcript.jsonl".to_owned(),
        "--model".to_owned(),
        "grok".to_owned(),
        "--resume=/state/older.jsonl".to_owned(),
        "--continue".to_owned(),
        "-c".to_owned(),
        "--session".to_owned(),
        "0f1e".to_owned(),
        "--fork=/state/branch.jsonl".to_owned(),
        "--from-codex".to_owned(),
        "--session-dir".to_owned(),
        "/state/other-sessions".to_owned(),
        "--trusted-extension".to_owned(),
        "/odin/ext.js".to_owned(),
    ];
    super::super::api::strip_resume_args(&mut args);
    assert_eq!(
        args,
        vec![
            "workload-exec".to_owned(),
            "--model".to_owned(),
            "grok".to_owned(),
            "--trusted-extension".to_owned(),
            "/odin/ext.js".to_owned(),
        ],
        "every session selector is stripped; flags and values survive"
    );
    // The resume installer and the stripper are exact inverses over one
    // resume pair, and a bare picker form is removed without eating the
    // flag behind it.
    super::super::api::set_resume_arg(&mut args, "/state/next.jsonl");
    assert!(args
        .windows(2)
        .any(|pair| pair == ["--resume", "/state/next.jsonl"]));
    super::super::api::strip_resume_args(&mut args);
    assert!(!args.iter().any(|argument| argument.starts_with("--resume")));
    args.insert(1, "--resume".to_owned());
    super::super::api::strip_resume_args(&mut args);
    assert_eq!(
        args,
        vec![
            "workload-exec".to_owned(),
            "--model".to_owned(),
            "grok".to_owned(),
            "--trusted-extension".to_owned(),
            "/odin/ext.js".to_owned(),
        ],
        "a bare picker --resume never consumes the flag behind it"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn a_context_refusal_rollover_respawns_a_fresh_incarnation_with_one_brief() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-rollover-fresh-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}

/// A delegated worker's rollover reinjection is the canonical continue
/// turn: through the real bridge (declared configuration, fresh respawn,
/// ONE journaled dispatch) the fresh incarnation's single prompt carries
/// the continue work order, the verbatim durable assignment, and the
/// bounded progress summary — the original requirements arrive even
/// though the fresh conversation never contained them, so the same worker
/// resumes the interrupted unit instead of idling after an absorption
/// acknowledgement.
#[tokio::test]
#[cfg(unix)]
async fn a_delegated_workers_rollover_reinjection_orders_the_work_continued() {
    struct DelegatedAssignment;
    #[async_trait::async_trait]
    impl RolloverChildrenSource for DelegatedAssignment {
        async fn children(
            &self,
            _parent: &SessionId,
            _cap: usize,
        ) -> Result<Vec<RolloverChildState>, String> {
            Ok(Vec::new())
        }

        async fn assignment(&self, _session: &SessionId) -> Result<Option<String>, String> {
            Ok(Some(
                "Implement the governed worker lifecycle end to end, rollover bound included."
                    .to_owned(),
            ))
        }
    }
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-rollover-continue-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        &root,
        "rollover-continue",
        // Every prompt this script answers — the seeded progress turn and
        // the fresh incarnation's one continue turn — SETTLES before its
        // dispatch is acked: a terminal agent_end clears the turn's
        // mutating correlation anchor first (a turn-command anchor
        // otherwise survives its successful response), then the
        // correlated response resolves the awaiting dispatch, so
        // `prompt()` returning proves the turn boundary the rollover
        // gate requires — never a race against a live turn.
        concat!(
            "        emit({'type':'agent_start'})\n",
            "        emit({'type':'agent_end'})\n",
            "        emit({'type':'response','id':command['id'],'command':'prompt',",
            "'success':True,'data':{}})\n",
            "        answered = True\n",
        ),
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(DelegatedAssignment));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");

    // Progress the successor must inherit: one settled turn of real work
    // journaled into the conversation the rollover brief reads.
    bridge
        .prompt(Prompt::text("progress checkpoint: the parser lands typed"))
        .await
        .expect("seeded progress turn settles");

    let epoch_before = bridge.binding().unwrap().epoch;
    let epoch_after = bridge
        .rollover_context_refusal(311, None)
        .await
        .expect("the typed rollover respawns the delegated worker fresh");
    assert_eq!(epoch_after, epoch_before + 1);

    let events = {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    let reinjections: Vec<&Value> = events
        .iter()
        .filter(|event| {
            event.body.get("kind").and_then(Value::as_str) == Some("command_issued")
                && event.body.get("command").and_then(Value::as_str) == Some("prompt")
        })
        .map(|event| &event.body)
        .collect();
    assert_eq!(
        reinjections.len(),
        2,
        "the seeded progress turn and ONE rollover reinjection: {reinjections:?}"
    );
    let message = reinjections[1]["frame"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(message.starts_with("[ODIN ROLLOVER"), "marker: {message}");
    assert!(
        message.contains(crate::live::rollover::ROLLOVER_CONTINUE_INSTRUCTION),
        "the reinjection is the continue work order: {message}"
    );
    assert!(
        !message.contains(crate::live::rollover::ROLLOVER_ABSORB_INSTRUCTION),
        "a delegated worker is never told to merely absorb: {message}"
    );
    assert!(
        message.contains(
            "Implement the governed worker lifecycle end to end, rollover bound included."
        ),
        "the durable assignment rides the turn verbatim: {message}"
    );
    assert!(
        message.contains("progress checkpoint: the parser lands typed"),
        "the bounded progress summary rides the same turn: {message}"
    );
    bridge.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// The journaled model selection rides INTO the rollover: the re-assert
/// is journaled AFTER the fresh respawn and BEFORE the reinjection
/// prompt, so the incarnation's first turn runs the selected model and
/// its context budget — never the launch pair with a correction after
/// the turn was already admitted.
#[tokio::test]
#[cfg(unix)]
async fn a_rollover_reasserts_the_selected_model_before_the_reinjection() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-rollover-model-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
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
        .rollover_context_refusal(401, Some(("gateway".to_owned(), "kimi-k28".to_owned())))
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
        Some("kimi-k28")
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
    let _ = std::fs::remove_dir_all(&root);
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
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-rollover-reject-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
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
    let _ = std::fs::remove_dir_all(&root);
}

/// A mismatched reinjection response (the id answers, the command does
/// not) is the same typed evidence: annotated on the observed frame and
/// journaled, never discarded to a dropped waiter.
#[tokio::test]
#[cfg(unix)]
async fn a_mismatched_reinjection_response_is_typed_evidence() {
    let root = std::env::temp_dir().join(format!(
        "odin-omp-bridge-rollover-mismatch-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let context = super::prompt_open_loop::context_with_prompt_handler(
        &root,
        "rollover-mismatch",
        "        emit({'type':'response','id':command['id'],'command':'get_state',\
         'success':True,'data':{}})\n\
         \x20       answered = True\n",
        Vec::new(),
    )
    .await;
    let mut config = context.bridge_config(context.session_descriptor()).unwrap();
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("bridge starts");
    let mut observations = bridge.subscribe();
    bridge
        .rollover_context_refusal(403, None)
        .await
        .expect("the rollover itself completes at the dispatch admission");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let annotated = loop {
        let frame = tokio::time::timeout_at(deadline.into(), observations.recv())
            .await
            .expect("the mismatched response arrives")
            .expect("observation channel stays open");
        if frame
            .value()
            .and_then(|value| value.get("command").and_then(Value::as_str))
            == Some("get_state")
        {
            break frame;
        }
    };
    let failure = annotated
        .journal_failure
        .expect("the mismatch is annotated on the observed frame");
    assert_eq!(failure.code, "response_mismatch");

    let events = {
        let ledger = context.ledger();
        let guard = ledger.lock().expect("case ledger lock");
        let session = context.ids().session.clone();
        let head = guard.reconnect_head(&session).unwrap();
        guard.live_event_history(&session, 0, head).unwrap()
    };
    assert!(events.iter().any(|event| {
        event.body.get("kind").and_then(Value::as_str) == Some("response_mismatch")
            && event.body.get("expected").and_then(Value::as_str) == Some("prompt")
            && event.body.get("got").and_then(Value::as_str) == Some("get_state")
    }));
    bridge.stop().await.unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

/// The remote carrier rides the SAME fresh contract: the respawn argv is
/// the composed launcher argv minus every session selector — nothing added,
/// nothing rewritten in the launcher section — so the pod harness's default
/// launch is a NEW, persisted conversation, and the typed rollover
/// completes (fresh epoch, re-attach, ONE journaled brief).
#[tokio::test]
#[cfg(unix)]
async fn a_fresh_context_rollover_respawns_a_remote_carrier_with_no_session_selector() {
    let root = tempfile::tempdir().unwrap();
    let context = super::fixture::fixture_context(root.path(), 12, "remote-rollover").await;
    let mut spec = super::remote_launch::remote_spec(
        &super::remote_launch::case_launcher(&context),
        context.work_dir().to_path_buf(),
    );
    // The launch-composed resume selector a carried-over conversation
    // would have staged (assembly re-asserts it on every reclaim): the
    // fresh respawn must strip exactly this, and add nothing.
    spec.explicit_args.push("--resume".to_owned());
    spec.explicit_args
        .push("/state/stale-transcript.jsonl".to_owned());
    let transport = Arc::new(super::remote_launch::FakeRemoteTransport::new(spec, None));
    let mut config = super::remote_launch::remote_bridge_config(&context, Arc::clone(&transport));
    config.rollover = Some(RolloverRuntimeConfig::new(RolloverPolicy::default()).unwrap());
    config.rollover_children = Some(Arc::new(NoDelegatedChildren));
    let bridge = OmpBridge::start(config).await.expect("remote launch");

    let epoch_before = bridge.binding().unwrap().epoch;
    let epoch_after = bridge
        .rollover_context_refusal(209, None)
        .await
        .expect("the typed rollover respawns the remote carrier fresh");
    assert_eq!(epoch_after, epoch_before + 1);
    assert_eq!(transport.attaches(), 2, "the rollover re-attaches once");
    let respawn_args = transport
        .attach_args(1)
        .expect("the re-attach argv is recorded");
    assert!(
        !respawn_args
            .iter()
            .any(|argument| argument.starts_with("--resume")),
        "no session selector survives the fresh respawn: {respawn_args:?}"
    );
    assert!(
        !respawn_args
            .iter()
            .any(|argument| argument.starts_with("--no-session")),
        "persistence is never disabled: {respawn_args:?}"
    );

    // The fresh remote incarnation speaks the protocol.
    let state = bridge.state().await.expect("the fresh carrier answers");
    assert_eq!(state.get("waiting").and_then(Value::as_bool), Some(false));
    super::remote_launch::retire(&bridge).await;
    drop(bridge);
}
