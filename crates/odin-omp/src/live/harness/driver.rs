//! Runs a process-harness turn through stop, reap, stderr drain, and hand-back.
//! Unconfirmed teardown retains the turn and workspace while the driver waits for exit.

use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use odin_domain::huginn::SessionManifest;
use odin_registry::{EnvironmentTransport, HarnessProtocol};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::time::Instant;

use super::decode::{Decoded, OutputDecoder};
use super::{acp, retire, HarnessRoute, HarnessWorkspace, TurnState};
use crate::bridge::ObservedFrame;

/// How a turn's teardown runs: the unit manager's stop argv (the unit is
/// appended) and how long the agent and its stderr have to end. Tests
/// substitute both.
#[derive(Clone, Copy)]
pub(super) struct Teardown {
    pub(super) stop_unit: &'static [&'static str],
    pub(super) reap_within: Duration,
}

pub(super) const TEARDOWN: Teardown = Teardown {
    stop_unit: &["systemctl", "--user", "stop"],
    reap_within: Duration::from_secs(30),
};

impl Teardown {
    /// Allows the unit's declared stop grace followed by the reap timeout.
    pub(super) fn stop_within(&self, route: &HarnessRoute) -> Duration {
        let unit = route.environment.transport == EnvironmentTransport::FleetHost;
        let grace = if unit {
            route.harness.stop.grace_seconds
        } else {
            0
        };
        self.reap_within + Duration::from_secs(u64::from(grace))
    }
}

/// ssh's own failure status: the connection ended, not the remote command.
const SSH_FAILED: i32 = 255;

pub(super) struct TurnDriver {
    pub(super) manifest: SessionManifest,
    pub(super) route: HarnessRoute,
    pub(super) workspace: PathBuf,
    pub(super) hand_back: Arc<dyn HarnessWorkspace>,
    pub(super) frames: broadcast::Sender<ObservedFrame>,
    pub(super) state: Arc<Mutex<TurnState>>,
    pub(super) turn: u64,
    pub(super) done: watch::Sender<Option<Result<(), String>>>,
    pub(super) teardown: Teardown,
    pub(super) turn_id: String,
    pub(super) unit: Option<String>,
    /// The turn's prompt when the harness speaks ACP.
    pub(super) acp: Option<AcpPrompt>,
    /// The turn's prompt when the agent reads it from stdin.
    pub(super) stdin_prompt: Option<String>,
}

pub(super) struct AcpPrompt {
    pub(super) prompt: String,
    pub(super) agent_session: Option<String>,
    /// The session's kernel MCP bridge, offered in `session/new`.
    pub(super) mcp_servers: Vec<Value>,
}

/// Writes and closes stdin, reporting failure so a missing prompt is visible.
async fn write_prompt(mut stdin: ChildStdin, prompt: String, session: String, harness: String) {
    use tokio::io::AsyncWriteExt as _;
    if let Err(error) = stdin.write_all(prompt.as_bytes()).await {
        tracing::error!(
            "odind: harness prompt-write-failed session={session} harness={harness} \
             error={error}"
        );
    }
}

/// Keeps the last 4 000 bytes of the agent's stderr for a failure's report.
async fn read_tail(stderr: ChildStderr, tail: Arc<Mutex<String>>) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Ok(mut tail) = tail.lock() {
            tail.push_str(&line);
            tail.push('\n');
            if tail.len() > 4_000 {
                let cut = tail.len() - 4_000;
                let cut = (cut..tail.len())
                    .find(|index| tail.is_char_boundary(*index))
                    .unwrap_or(cut);
                tail.drain(..cut);
            }
        }
    }
}

impl TurnDriver {
    fn emit(&self, mut frame: Value) {
        if let Some(object) = frame.as_object_mut() {
            object
                .entry("turnId")
                .or_insert_with(|| Value::String(self.turn_id.clone()));
        }
        let _ = self.frames.send(ObservedFrame::harness_event(frame));
    }

    pub(super) async fn run(mut self, mut child: Child, mut stop: oneshot::Receiver<()>) {
        let stderr_tail = Arc::new(Mutex::new(String::new()));
        // Teardown joins the reader, aborting it first if necessary.
        let mut stderr = child
            .stderr
            .take()
            .map(|stderr| tokio::spawn(read_tail(stderr, Arc::clone(&stderr_tail))));
        // Teardown also aborts and joins the writer.
        let writer = match (self.stdin_prompt.take(), child.stdin.take()) {
            (Some(prompt), Some(stdin)) => Some(tokio::spawn(write_prompt(
                stdin,
                prompt,
                self.manifest.session_id.to_string(),
                self.route.harness_id.clone(),
            ))),
            (_, stdin) => {
                child.stdin = stdin;
                None
            }
        };
        let (outcome, mut stopped) = match self.acp.take() {
            Some(acp) => self.converse_acp(&mut child, acp, &mut stop).await,
            None => self.decode_lines(&mut child, &mut stop).await,
        };
        // One absolute deadline for the agent's exit and its stderr's end: a
        // natural end gets the reap budget, a stop its own budget from when
        // it is seen, its manager's stop included.
        let mut deadline = Some(Instant::now() + self.teardown.reap_within);
        let mut doubt = None;
        if stopped {
            let stop_by = self.stop_deadline();
            deadline = Some(stop_by);
            doubt = self.stop_agent(&mut child, stop_by).await;
        }
        let reaped = self
            .reap(
                &mut child,
                &mut stop,
                &mut stopped,
                &mut doubt,
                &mut deadline,
            )
            .await;
        if let Some(writer) = writer {
            writer.abort();
            let _ = writer.await;
        }
        let mut quiet = matches!(reaped, Some(Ok(_)));
        if let (true, Some(reader), Some(by)) = (quiet, stderr.as_mut(), deadline) {
            quiet = tokio::time::timeout_at(by, reader).await.is_ok();
        }
        if quiet {
            stderr = None;
        }
        // ssh exits 255 when its connection ended, not the remote agent.
        let remote = self.route.environment.transport == EnvironmentTransport::SshHost;
        let lost = matches!(&reaped, Some(Ok(status)) if status.code() == Some(SSH_FAILED));
        if remote && lost && doubt.is_none() {
            doubt = Some("ssh ended without the remote agent's status".to_owned());
        }
        let unproven = doubt.clone().or_else(|| {
            (!quiet).then(|| match &reaped {
                Some(Ok(_)) => "a writer still holds the agent's stderr open".to_owned(),
                Some(Err(error)) => format!("the agent could not be reaped: {error}"),
                None => "the agent outlived its teardown deadline".to_owned(),
            })
        });
        // An explicit stop cannot see the remote command's end, and a
        // killed client did not report whether that command was admitted.
        let ssh_stop = stopped && remote;
        if ssh_stop {
            if let Some(reason) = &unproven {
                tracing::warn!(
                    "odind: harness ssh stop unproven session={} harness={} turn={} \
                     reason=\"{reason}\"",
                    self.manifest.session_id,
                    self.route.harness_id,
                    self.turn
                );
            }
        }
        // An ACP turn's verdict is its prompt answer; the agent exits on
        // stdin closing, however it chooses to.
        let exit_ok = self.route.harness.protocol == HarnessProtocol::Acp
            || matches!(&reaped, Some(Ok(status)) if status.success());
        if let Some(session) = &outcome.agent_session {
            if let Ok(mut state) = self.state.lock() {
                state.agent_session = Some(session.clone());
            }
        }
        // Hand back even failed work, but only after the agent can no longer write.
        let handed = match &unproven {
            None => {
                self.hand_back
                    .hand_back(&self.manifest, &self.route, &self.workspace)
                    .await
            }
            Some(_) => Ok(None),
        };
        let hand_note = match handed {
            Ok(note) => note,
            Err(error) => Some(format!("The work could not be handed back: {error:?}")),
        };
        let failure = if ssh_stop {
            None
        } else if let Some(reason) = &unproven {
            Some(format!(
                "its teardown was not proven ({reason}); its work stays in the workspace"
            ))
        } else if stopped {
            Some("stopped on command".to_owned())
        } else if outcome.failed.is_some() || !exit_ok {
            Some(outcome.failed.clone().unwrap_or_else(|| {
                let tail = stderr_tail
                    .lock()
                    .map(|tail| tail.clone())
                    .unwrap_or_default();
                format!(
                    "{} exited with {:?}: {}",
                    self.route.harness_id,
                    reaped.as_ref().and_then(|status| status.as_ref().ok()),
                    tail.trim()
                )
            }))
        } else {
            None
        };
        tracing::info!(
            "odind: harness turn_end session={} harness={} unit={} ok={} stopped={stopped} \
             handed_back={}",
            self.manifest.session_id,
            self.route.harness_id,
            self.unit.as_deref().unwrap_or("ssh"),
            failure.is_none(),
            hand_note.is_some()
        );
        let mut summary = outcome.final_text.unwrap_or_default();
        if let Some(note) = &hand_note {
            if !summary.is_empty() {
                summary.push_str("\n\n");
            }
            summary.push_str(note);
        }
        match &failure {
            None => self.emit(json!({"type": "agent_end", "stopReason": "stop"})),
            Some(reason) => self
                .emit(json!({"type": "agent_end", "stopReason": "error", "errorMessage": reason})),
        }
        if let Some(reason) = &failure {
            if !summary.is_empty() {
                summary.push_str("\n\n");
            }
            summary.push_str(&format!("The turn did not finish: {reason}."));
        }
        self.emit(json!({"type": "prompt_result", "text": summary}));
        if ssh_stop {
            // Local SSH EOF cannot confirm remote exit; retain the workspace and turn.
            if let Some(reader) = stderr {
                reader.abort();
                let _ = reader.await;
            }
            if reaped.is_none() {
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            }
            let reason = unproven
                .unwrap_or_else(|| "the remote agent's end is not observed over ssh".to_owned());
            let _ = self.done.send_replace(Some(Err(reason)));
            return;
        }
        // Natural SSH failure retains its error but releases the turn for later prompts.
        if remote && unproven.is_some() {
            retire(&self.state, self.turn);
        }
        let Some(reason) = unproven else {
            retire(&self.state, self.turn);
            let _ = self.done.send_replace(Some(Ok(())));
            return;
        };
        // Retain unresolved local turns and keep reaping; later stops can still signal them.
        let _ = self.done.send_replace(Some(Err(reason)));
        let status = match reaped {
            Some(status) => Some(status),
            None => {
                self.reap(&mut child, &mut stop, &mut stopped, &mut doubt, &mut None)
                    .await
            }
        };
        if let Some(reader) = stderr {
            reader.abort();
            let _ = reader.await;
        }
        tracing::info!(
            "odind: harness turn_owner_end session={} harness={} turn={} status={status:?}",
            self.manifest.session_id,
            self.route.harness_id,
            self.turn
        );
    }

    fn stop_deadline(&self) -> Instant {
        Instant::now() + self.teardown.stop_within(&self.route)
    }

    /// Stops by the deadline and returns any uncertainty; timed-out managers are killed and reaped.
    async fn stop_agent(&self, child: &mut Child, stop_by: Instant) -> Option<String> {
        let mut doubt = None;
        if let Some(unit) = &self.unit {
            let stop = self.teardown.stop_unit;
            let manager = Command::new(stop[0])
                .args(&stop[1..])
                .arg(unit)
                .kill_on_drop(true)
                .spawn();
            let status = match manager {
                Ok(mut manager) => match tokio::time::timeout_at(stop_by, manager.wait()).await {
                    Ok(status) => status.map_err(|error| error.to_string()),
                    Err(_elapsed) => {
                        let _ = manager.start_kill();
                        Err("no answer by the stop deadline".to_owned())
                    }
                },
                Err(error) => Err(error.to_string()),
            };
            if !status.as_ref().is_ok_and(|status| status.success()) {
                doubt = Some(format!(
                    "the manager did not confirm stopping {unit}: {status:?}"
                ));
            }
        }
        // ssh: the client's end hangs up the remote group, but nothing here
        // observes the remote agent's own end.
        if self.route.environment.transport == EnvironmentTransport::SshHost {
            doubt = Some("the remote agent's end is not observed over ssh".to_owned());
        }
        let _ = child.start_kill();
        doubt
    }

    /// Waits for the agent to exit by `deadline`, or however long it takes
    /// without one (`None` back: the deadline passed first). A stop arriving
    /// meanwhile stops it, and the stop's own deadline then bounds the wait.
    async fn reap(
        &self,
        child: &mut Child,
        stop: &mut oneshot::Receiver<()>,
        stopped: &mut bool,
        doubt: &mut Option<String>,
        deadline: &mut Option<Instant>,
    ) -> Option<std::io::Result<ExitStatus>> {
        loop {
            let expiry = *deadline;
            let expired = async move {
                match expiry {
                    Some(by) => tokio::time::sleep_until(by).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                status = child.wait() => return Some(status),
                () = expired => return None,
                _ = &mut *stop, if !*stopped => {
                    *stopped = true;
                    let stop_by = self.stop_deadline();
                    if deadline.is_some() {
                        *deadline = Some(stop_by);
                    }
                    if let Some(reason) = self.stop_agent(child, stop_by).await {
                        *doubt = Some(reason);
                    }
                }
            }
        }
    }

    /// A line-speaking agent: its stdout decoded line by line until it
    /// exits or the turn is stopped.
    async fn decode_lines(
        &self,
        child: &mut Child,
        stop: &mut oneshot::Receiver<()>,
    ) -> (Decoded, bool) {
        let mut decoder = OutputDecoder::new(self.route.harness.output, &self.route.harness_id);
        let mut stopped = false;
        if let Some(stdout) = child.stdout.take() {
            let mut lines = BufReader::new(stdout).lines();
            loop {
                tokio::select! {
                    line = lines.next_line() => match line {
                        Ok(Some(line)) => {
                            for frame in decoder.line(line.trim_end_matches('\r')).frames {
                                self.emit(frame);
                            }
                        }
                        Ok(None) | Err(_) => break,
                    },
                    _ = &mut *stop => {
                        stopped = true;
                        break;
                    }
                }
            }
        }
        (decoder.finish(), stopped)
    }

    /// An ACP agent: one conversation over its stdio.
    async fn converse_acp(
        &self,
        child: &mut Child,
        acp: AcpPrompt,
        stop: &mut oneshot::Receiver<()>,
    ) -> (Decoded, bool) {
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return (
                Decoded {
                    failed: Some("the agent's stdio was not piped".to_owned()),
                    ..Decoded::default()
                },
                false,
            );
        };
        let session = self.manifest.session_id.to_string();
        let turn = acp::AcpTurn {
            session,
            harness: &self.route.harness_id,
            workspace: &self.workspace,
            agent_session: acp.agent_session,
            brief: self.route.harness.brief.as_deref(),
            prompt: acp.prompt,
            mcp_servers: acp.mcp_servers,
        };
        let emit = |frame: Value| self.emit(frame);
        acp::converse(stdin, stdout, turn, stop, &emit).await
    }
}
