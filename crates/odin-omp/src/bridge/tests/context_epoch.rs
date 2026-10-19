//! Brain context rides the first turn of each context epoch — session
//! start and after a compaction — and not ordinary turns: a real bridge over
//! a scripted child that records every prompt and compacts after the second.

use super::prompt_open_loop::context_with_prompt_handler;
use super::*;
use std::time::Duration;

use odin_domain::huginn::{ApprovalDecision, LiveContentBlock, LiveError, LiveMessage};
use odin_domain::{ApprovalId, CommandId, NodeId};

use crate::live::control::{BrainTurnContext, BridgeControl, LiveControlBackend, LiveControlHooks};

struct NoHooks;

#[async_trait::async_trait]
impl LiveControlHooks for NoHooks {
    async fn pause(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Ok(())
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Ok(())
    }
    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Ok(())
    }
}

/// A profile with no per-turn tail: context only when an epoch starts.
struct EpochBrain;

impl BrainTurnContext for EpochBrain {
    fn prefetch(&self, _text: &str, epoch_start: bool) -> Result<Option<String>, LiveError> {
        Ok(epoch_start.then(|| "BRAIN-CONTEXT".to_owned()))
    }
}

#[tokio::test]
async fn brain_context_rides_session_start_and_compaction_not_ordinary_turns() {
    let root = std::env::temp_dir().join(format!("odin-omp-context-epoch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let log = root.join("prompts.jsonl");
    let handler = format!(
        "        open({log:?}, 'a').write(json.dumps(command.get('message')) + '\\n')\n\
         \x20       emit({{'type':'response','id':command['id'],'command':'prompt','success':True,'data':{{}}}})\n\
         \x20       answered = True\n\
         \x20       if sum(1 for _ in open({log:?})) == 2:\n\
         \x20           emit({{'type':'auto_compaction_end','result':None,'aborted':False,'willRetry':False}})\n"
    );
    let context = context_with_prompt_handler(&root, "context-epoch", &handler, Vec::new()).await;
    let bridge = Arc::new(
        OmpBridge::start(context.bridge_config(context.session_descriptor()).unwrap())
            .await
            .expect("bridge starts"),
    );
    let control = BridgeControl::new(Arc::clone(&bridge), Arc::new(NoHooks))
        .with_brain_turn_source(Some(Arc::new(EpochBrain)));
    for turn in 1..=3 {
        if turn == 3 {
            tokio::time::timeout(Duration::from_secs(10), async {
                while bridge.context_epoch() == 0 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("the compaction opens a new context epoch");
        }
        let message = LiveMessage {
            content: vec![LiveContentBlock::Text(format!("turn {turn}"))],
        };
        control
            .dispatch_message(
                &CommandId::new(format!("turn-{turn}")).unwrap(),
                &message,
                false,
            )
            .await
            .expect("turn dispatches");
    }
    // Dispatch is open-loop: wait for the child to record the third prompt.
    let prompts: Vec<String> = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.lines().count() == 3 {
                break text
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the child records three prompts");
    assert!(
        prompts[0].starts_with("BRAIN-CONTEXT") && prompts[0].ends_with("turn 1"),
        "{prompts:?}"
    );
    assert_eq!(
        prompts[1], "turn 2",
        "an ordinary turn carries no injected context"
    );
    assert!(
        prompts[2].starts_with("BRAIN-CONTEXT"),
        "after compaction: {prompts:?}"
    );
    drop(control);
    let _ = std::fs::remove_dir_all(&root);
}
