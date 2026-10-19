//! Real process-backed terminal controls through the actor and filesystem journal.
use super::*;
use crate::live::ledger::LiveLedger;
use crate::live::session_actor::tests::{spawn_fixture_with_control, Fixture};
use odin_domain::huginn::{
    AbortScope, CommandOutcome, CommandReceipt, EventSeq, HistoryQuery, LiveCommand,
    LiveCommandBody, LiveContentBlock, LiveEventBody, LiveSessionState,
};
use odin_domain::CommandId;
use odin_registry::*;
use std::num::NonZeroU16;

struct NoPods;
#[async_trait]
impl super::super::PodTerminals for NoPods {
    async fn start(
        &self,
        _: super::super::PodTerminalRequest,
    ) -> Result<super::super::PodTerminal, LiveError> {
        unreachable!("fixture transport already exists")
    }
    async fn stop(&self, _: &str) -> Result<(), LiveError> {
        Ok(())
    }
}

#[derive(Default)]
struct GatedHandBack {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl HarnessWorkspace for GatedHandBack {
    async fn prepare(&self, _: &SessionManifest, _: &HarnessRoute) -> Result<PathBuf, LiveError> {
        unreachable!("workspace is already prepared")
    }

    async fn hand_back(
        &self,
        _: &SessionManifest,
        _: &HarnessRoute,
        _: &Path,
    ) -> Result<Option<String>, LiveError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(None)
    }
}

fn running(control: &TerminalControl) -> Option<String> {
    match control.state.lock() {
        Ok(state) => state.running.clone(),
        Err(_) => panic!("terminal fixture state was poisoned"),
    }
}

fn route(manifest: &SessionManifest) -> HarnessRoute {
    HarnessRoute {
        harness_id: "terminal-fixture".into(),
        environment_id: "terminal-fixture".into(),
        account: None,
        harness: HarnessToml {
            schema: "odin.registry.v1".into(),
            kind: RegistryKind::Harness,
            enabled: true,
            description: "terminal interruption regression".into(),
            protocol: HarnessProtocol::Terminal,
            governance: HarnessGovernance::Observed,
            command: vec!["sh".into()],
            prompt: HarnessPrompt::Keys,
            output: HarnessOutput::ClaudeStreamJson,
            model_arg: None,
            mcp_config_arg: None,
            resume_args: vec![],
            state_paths: vec![],
            account: None,
            brief: None,
            transcripts: None,
            pod: false,
            stop: HarnessStopToml {
                signal: "SIGTERM".into(),
                grace_seconds: 1,
            },
        },
        environment: EnvironmentToml {
            schema: "odin.registry.v1".into(),
            kind: RegistryKind::Environment,
            enabled: true,
            description: "scripted terminal transport".into(),
            transport: EnvironmentTransport::K3sPod,
            host: None,
            credential: None,
            seats: vec![manifest.seat_id.clone()],
            observation: EnvironmentObservationToml {
                channel: ObservationChannel::Events,
                path: None,
                format: None,
            },
            sandbox: Default::default(),
            watchdogs: vec![],
            pod: Some(Default::default()),
            git_mirror: None,
        },
    }
}

async fn apply(fixture: &Fixture, name: &str, body: LiveCommandBody) -> CommandReceipt {
    let head = fixture.ledger.head(fixture.session_id).await.unwrap();
    fixture
        .handle
        .command(LiveCommand {
            command_id: CommandId::new(name).unwrap(),
            session_id: fixture.session_id,
            expected_epoch: fixture.epoch,
            expected_event_head: Some(head),
            body,
        })
        .await
        .unwrap()
}

fn prompt() -> LiveCommandBody {
    LiveCommandBody::Prompt {
        message: LiveMessage::new(vec![LiveContentBlock::Text(
            "continue the assigned unit".into(),
        )])
        .unwrap(),
    }
}

async fn drain(fixture: &Fixture, frames: &mut broadcast::Receiver<ObservedFrame>) {
    loop {
        match frames.try_recv() {
            Ok(frame) => {
                fixture.handle.ingest_omp(frame).await.unwrap();
            }
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(error) => panic!("terminal observations lost: {error}"),
        }
    }
}

async fn bodies(fixture: &Fixture) -> Vec<LiveEventBody> {
    fixture
        .ledger
        .history(HistoryQuery {
            session_id: fixture.session_id,
            after: EventSeq::new(0),
            limit: NonZeroU16::new(256).unwrap(),
        })
        .await
        .unwrap()
        .events
        .into_iter()
        .map(|event| event.body)
        .collect()
}

#[tokio::test]
async fn real_terminal_abort_retires_without_failure_or_answer_and_fences_old_completion() {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("tmux.sh");
    let log = temp.path().join("calls");
    let reject = temp.path().join("reject-escape");
    tokio::fs::write(
        &script,
        r#"log=$1
reject=$2
shift 2
printf '%s\n' "$*" >> "$log"
case "$1" in
 capture-pane) printf '%s\n' '? for shortcuts' ;;
 load-buffer) cat >/dev/null ;;
 paste-buffer|has-session) ;;
 send-keys) if [ "$4" = Escape ] && [ -e "$reject" ]; then exit 1; fi ;;
 *) exit 2 ;;
esac
"#,
    )
    .await
    .unwrap();
    let (frames, mut received) = broadcast::channel(64);
    let (failed, _failed_rx) = watch::channel(None);
    let (stop_follow, _stop_rx) = watch::channel(false);
    let mut terminal = None;
    let fixture = spawn_fixture_with_control(|manifest, root| {
        let control = Arc::new(TerminalControl {
            manifest: manifest.clone(),
            route: route(manifest),
            workspace: root.to_path_buf(),
            transport: TerminalTransport::Pod {
                terminal: super::super::PodTerminal {
                    pod: "scripted-terminal".into(),
                    exec: vec![
                        "sh".into(),
                        script.display().to_string(),
                        log.display().to_string(),
                        reject.display().to_string(),
                    ],
                    attach: vec![],
                },
                pods: Arc::new(NoPods),
                session: manifest.session_id.to_string(),
            },
            frames,
            failed,
            state: Arc::new(Mutex::new(TermState {
                turns: 0,
                running: None,
                briefed: false,
                closed: false,
            })),
            stop_follow,
            stopped: tokio::sync::Mutex::new(false),
            incidents: None,
            _kernel: None,
        });
        terminal = Some(control.clone());
        control
    })
    .await;
    let terminal = terminal.unwrap();
    assert!(matches!(
        apply(&fixture, "first-prompt", prompt()).await,
        CommandReceipt::Accepted { .. }
    ));
    drain(&fixture, &mut received).await;
    let old = running(&terminal).unwrap();
    let hand_back = Arc::new(GatedHandBack::default());
    let pending = {
        let terminal = terminal.clone();
        let hand_back = hand_back.clone();
        let old = old.clone();
        tokio::spawn(async move {
            terminal
                .finish_turn(&old, "stale answer".into(), hand_back.as_ref())
                .await;
        })
    };
    tokio::time::timeout(Duration::from_secs(5), hand_back.entered.notified())
        .await
        .unwrap();

    // A failed real Escape must not retire the working turn or claim success.
    tokio::fs::write(&reject, b"reject").await.unwrap();
    apply(
        &fixture,
        "failed-abort",
        LiveCommandBody::Abort {
            scope: AbortScope::CurrentTurn,
        },
    )
    .await;
    assert_eq!(running(&terminal).as_deref(), Some(old.as_str()));
    assert!(bodies(&fixture).await.iter().any(|body| matches!(body,
        LiveEventBody::ControlCompleted(CommandOutcome::Failed { command_id, .. })
            if command_id.as_str() == "failed-abort")));
    tokio::fs::remove_file(&reject).await.unwrap();
    assert!(matches!(
        apply(
            &fixture,
            "abort",
            LiveCommandBody::Abort {
                scope: AbortScope::CurrentTurn,
            }
        )
        .await,
        CommandReceipt::Accepted { .. }
    ));
    assert!(running(&terminal).is_none());
    // Drain exactly as the supervisor pump does after command completion.
    drain(&fixture, &mut received).await;
    assert!(!bodies(&fixture)
        .await
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_) | LiveEventBody::Result(_))));
    assert!(matches!(
        apply(&fixture, "continue", prompt()).await,
        CommandReceipt::Accepted { .. }
    ));
    drain(&fixture, &mut received).await;
    let next = running(&terminal).unwrap();
    assert_ne!(old, next);
    // Release the actual production hand-back await after a new turn starts.
    hand_back.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(running(&terminal).as_deref(), Some(next.as_str()));
    assert!(matches!(
        received.try_recv(),
        Err(broadcast::error::TryRecvError::Empty)
    ));

    assert!(matches!(
        apply(&fixture, "pause", LiveCommandBody::Pause).await,
        CommandReceipt::Accepted { .. }
    ));
    drain(&fixture, &mut received).await;
    assert!(bodies(&fixture).await.iter().any(|body| matches!(body,
        LiveEventBody::SessionStateChanged(change) if change.current == LiveSessionState::Detached)));
    assert!(matches!(
        apply(&fixture, "resume", LiveCommandBody::Resume).await,
        CommandReceipt::Accepted { .. }
    ));
    assert!(matches!(
        apply(&fixture, "final-prompt", prompt()).await,
        CommandReceipt::Accepted { .. }
    ));
    drain(&fixture, &mut received).await;
    let final_turn = running(&terminal).unwrap();
    terminal.end_matching_turn(&final_turn, "genuine answer".into());
    drain(&fixture, &mut received).await;
    assert_eq!(
        bodies(&fixture)
            .await
            .iter()
            .filter(|body| matches!(body, LiveEventBody::Result(_)))
            .count(),
        1
    );
    assert!(matches!(
        apply(
            &fixture,
            "stop",
            LiveCommandBody::Abort {
                scope: AbortScope::Session
            }
        )
        .await,
        CommandReceipt::Accepted { .. }
    ));
    drain(&fixture, &mut received).await;
    assert!(matches!(
        apply(&fixture, "cannot-reopen", prompt()).await,
        CommandReceipt::Rejected { .. }
    ));
    assert!(!bodies(&fixture)
        .await
        .iter()
        .any(|body| matches!(body, LiveEventBody::Error(_))));
    let calls = tokio::fs::read_to_string(log).await.unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| *line == "send-keys -t main Escape")
            .count(),
        3
    );
    fixture.handle.stop().await.unwrap();
    tokio::fs::remove_dir_all(fixture.root).await.unwrap();
}
