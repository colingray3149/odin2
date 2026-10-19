//! Observe-and-monitor: a `remote-session` environment is an agent Odin did
//! not start and cannot confine or stop. Odin follows its
//! newest transcript file over ssh, decodes it with the declared output
//! family into the session journal (Huginn and the Zellij tab show it like
//! any session), and evaluates the environment's declared watchdogs in code
//! — a hit raises an incident (Huginn card, phone, a Sinmara wake). Nothing
//! here can steer, pause or stop the agent: every such command is refused
//! as unsupported, which is the truth.

use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use odin_domain::huginn::{
    ApprovalDecision, LiveError, LiveMessage, ModelName, PermissionDecision, PermissionRequestId,
    ProviderName, SessionManifest,
};
use odin_domain::{ApprovalId, NodeId};
use odin_registry::{EnvironmentWatchdogToml, HarnessOutput};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{broadcast, watch};

use super::{HarnessRoute, OutputDecoder};
use crate::bridge::ObservedFrame;
use crate::live::control::LiveControlBackend;

/// Where a watchdog hit goes (the daemon's incident desk).
pub trait HarnessIncidentSink: Send + Sync {
    fn raise(&self, environment: &str, watchdog: &str, summary: &str, detail: &str);
}

/// How often the newest transcript is re-checked (a new agent session
/// starts a new file).
const RESCAN: Duration = Duration::from_secs(20);

pub(super) struct ObserveControl {
    pub(super) environment: String,
    pub(super) stopped: watch::Sender<bool>,
}

fn refused(operation: &str, environment: &str) -> LiveError {
    LiveError::Unsupported {
        operation: format!(
            "{operation}: {environment} is a remote session Odin only observes; it cannot \
             steer, pause or stop it"
        ),
    }
}

#[async_trait]
impl LiveControlBackend for ObserveControl {
    async fn prompt(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Err(refused("prompt", &self.environment))
    }
    async fn follow_up(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Err(refused("follow-up", &self.environment))
    }
    async fn steer(&self, _message: &LiveMessage) -> Result<(), LiveError> {
        Err(refused("steer", &self.environment))
    }
    async fn pause(&self) -> Result<(), LiveError> {
        Err(refused("pause", &self.environment))
    }
    async fn resume(&self) -> Result<(), LiveError> {
        Err(refused("resume", &self.environment))
    }
    async fn checkpoint(&self) -> Result<(), LiveError> {
        Err(refused("checkpoint", &self.environment))
    }
    async fn restart(&self) -> Result<(), LiveError> {
        Err(refused("restart", &self.environment))
    }
    async fn rehome(&self, _target_node: &NodeId) -> Result<(), LiveError> {
        Err(refused("rehome", &self.environment))
    }
    async fn set_model(
        &self,
        _provider: &ProviderName,
        _model: &ModelName,
    ) -> Result<(), LiveError> {
        Err(refused("model switch", &self.environment))
    }
    async fn abort_turn(&self) -> Result<(), LiveError> {
        Err(refused("stop", &self.environment))
    }
    /// Ending the observed session stops Odin's watching, not the agent.
    async fn abort_session(&self) -> Result<(), LiveError> {
        let _ = self.stopped.send(true);
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), LiveError> {
        let _ = self.stopped.send(true);
        Ok(())
    }
    async fn decide_permission(
        &self,
        _request_id: &PermissionRequestId,
        _decision: PermissionDecision,
    ) -> Result<(), LiveError> {
        Err(refused("permission decision", &self.environment))
    }
    async fn decide_approval(
        &self,
        _approval_id: &ApprovalId,
        _expected_revision: u64,
        _decision: ApprovalDecision,
    ) -> Result<(), LiveError> {
        Err(refused("approval decision", &self.environment))
    }
    async fn bridge_ready(&self) -> bool {
        !*self.stopped.borrow()
    }
}

/// The remote command that names the newest transcript under the declared
/// path (a directory: newest file in it or one level down; else the file).
fn newest_script(path: &str) -> String {
    let path = path.strip_prefix("~/").map_or_else(
        || format!("'{}'", path.replace('\'', "'\\''")),
        |rest| format!("\"$HOME\"/'{}'", rest.replace('\'', "'\\''")),
    );
    format!(
        "p={path}; if [ -d \"$p\" ]; then ls -t \"$p\"/*/*.jsonl \"$p\"/*.jsonl \"$p\"/*.log \
         2>/dev/null | head -1; else echo \"$p\"; fi"
    )
}

/// Separates replayed backlog from live lines so watchdogs do not repeat old actions.
const LIVE_MARK: &str = "odin-observe: live";

/// Tails `quoted` (a shell-quoted path): the last 40 lines written so far,
/// [`LIVE_MARK`] on a line of its own, then every byte written after the
/// size was read — none dropped or repeated between the two.
fn follow_script(quoted: &str) -> String {
    format!(
        "f={quoted}; s=$(stat -c %s \"$f\") || exit 1; head -c \"$s\" \"$f\" | tail -n 40; \
         printf '\\n%s\\n' '{LIVE_MARK}'; exec tail -c +$((s + 1)) -F \"$f\""
    )
}

fn ssh(host: &str, script: &str) -> Command {
    let mut command = Command::new("ssh");
    command
        .args(super::SSH_OPTIONS)
        .args([host, "--"])
        .arg(format!("bash -lc '{}'", script.replace('\'', "'\\''")))
        .stdin(Stdio::null())
        .kill_on_drop(true);
    command
}

/// Which transcript identity has already been announced. Same-file
/// reattachment does not log again.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FollowLog {
    followed: Option<String>,
    live: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Notice {
    Following,
    Live,
    Quiet,
}

impl FollowLog {
    fn select(&mut self, newest: &str) -> Notice {
        if self.followed.as_deref() == Some(newest) {
            Notice::Quiet
        } else {
            self.followed = Some(newest.to_owned());
            Notice::Following
        }
    }

    fn live(&mut self, current: &str) -> Notice {
        if self.live.as_deref() == Some(current) {
            Notice::Quiet
        } else {
            self.live = Some(current.to_owned());
            Notice::Live
        }
    }
}

/// One watchdog's running state.
struct Dog {
    declared: EnvironmentWatchdogToml,
    last_fired: Option<Instant>,
}

/// The match watchdogs one decoded frame fires, as (name, needle): none for
/// a backlog line, and each dog at most once a minute.
fn matched(dogs: &mut [Dog], text: &str, live: bool) -> Vec<(String, String)> {
    if !live {
        return Vec::new();
    }
    let mut fired = Vec::new();
    for dog in dogs.iter_mut() {
        let Some(needle) = &dog.declared.matches else {
            continue;
        };
        let cooled = dog
            .last_fired
            .is_none_or(|at| at.elapsed() > Duration::from_secs(60));
        if cooled && text.contains(needle.as_str()) {
            dog.last_fired = Some(Instant::now());
            fired.push((dog.declared.name.clone(), needle.clone()));
        }
    }
    fired
}

pub(super) struct Watchdogs {
    dogs: Vec<Dog>,
    open_tool: Option<(String, Instant)>,
}

impl Watchdogs {
    pub(super) fn new(route: &HarnessRoute) -> Self {
        Self {
            dogs: route
                .environment
                .watchdogs
                .iter()
                .cloned()
                .map(|declared| Dog {
                    declared,
                    last_fired: None,
                })
                .collect(),
            open_tool: None,
        }
    }

    pub(super) fn reset_transcript(&mut self) {
        self.open_tool = None;
    }

    pub(super) fn frame(
        &mut self,
        frame: &Value,
        live: bool,
        sink: &Option<Arc<dyn HarnessIncidentSink>>,
        route: &HarnessRoute,
        transcript: Option<&str>,
    ) {
        if !live || self.dogs.is_empty() {
            return;
        }
        match frame.get("type").and_then(Value::as_str) {
            Some("tool_execution_start") => {
                let name = frame
                    .get("toolName")
                    .and_then(Value::as_str)
                    .unwrap_or("tool");
                self.open_tool = Some((name.to_owned(), Instant::now()));
            }
            Some("tool_execution_end") => self.open_tool = None,
            _ => {}
        }
        let text = frame.to_string();
        for (name, needle) in matched(&mut self.dogs, &text, true) {
            let excerpt: String = text.chars().take(400).collect();
            fire(
                sink,
                route,
                transcript,
                &name,
                &format!("the observed agent's output contained {needle:?}: {excerpt}"),
            );
        }
    }

    pub(super) fn tick(
        &mut self,
        sink: &Option<Arc<dyn HarnessIncidentSink>>,
        route: &HarnessRoute,
        transcript: Option<&str>,
    ) {
        let Some((tool, since)) = &self.open_tool else {
            return;
        };
        for dog in &mut self.dogs {
            let Some(seconds) = dog.declared.silent_seconds else {
                continue;
            };
            if since.elapsed() >= Duration::from_secs(u64::from(seconds))
                && dog.last_fired.is_none_or(|at| at < *since)
            {
                dog.last_fired = Some(Instant::now());
                fire(sink, route, transcript, &dog.declared.name, &format!(
                    "the observed agent's tool call {tool} has made no progress for over the declared window"
                ));
            }
        }
    }
}

/// The follow loop: newest file, tail it, decode, journal, watch.
pub(super) async fn follow(
    manifest: SessionManifest,
    route: HarnessRoute,
    frames: broadcast::Sender<ObservedFrame>,
    sink: Option<Arc<dyn HarnessIncidentSink>>,
    mut stopped: watch::Receiver<bool>,
) {
    let host = route.environment.host.clone().unwrap_or_default();
    let path = route
        .environment
        .observation
        .path
        .clone()
        .unwrap_or_default();
    let family = match route.environment.observation.format.as_deref() {
        Some("codex-json") => HarnessOutput::CodexJson,
        Some("text") => HarnessOutput::Text,
        Some("claude-stream-json") => HarnessOutput::ClaudeStreamJson,
        _ => unreachable!("observed launch validates the environment transcript format"),
    };
    let emit = |frame: Value| {
        let _ = frames.send(ObservedFrame::harness_event(frame));
    };
    let mut watchdogs = Watchdogs::new(&route);
    emit(json!({"type": "agent_start", "turnId": "observe"}));
    let mut current: Option<String> = None;
    let mut follow_log = FollowLog::default();
    let mut tail: Option<tokio::process::Child> = None;
    let mut lines: Option<tokio::io::Lines<BufReader<tokio::process::ChildStdout>>> = None;
    let mut live = false;
    let mut decoder = OutputDecoder::new(family, &route.harness_id);
    let mut rescan = tokio::time::interval(RESCAN);
    let mut last_failure: Option<String> = None;
    loop {
        tokio::select! {
            _ = stopped.changed() => {
                if *stopped.borrow() {
                    break;
                }
            }
            _ = rescan.tick() => {
                // The stop races the rescan ssh: a hung connection must
                // never hold the follow loop past a daemon shutdown. The
                // losing ssh child is killed when its future drops.
                let mut cancelled = stopped.clone();
                let scan = tokio::select! {
                    _ = cancelled.changed() => break,
                    output = ssh(&host, &newest_script(&path)).output() => match output {
                        Ok(output) if output.status.success() => {
                            Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
                        }
                        Ok(output) => {
                            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
                        }
                        Err(error) => Err(format!("ssh could not run: {error}")),
                    },
                };
                // Logged once per change of reachability, not every rescan.
                let failure = scan.as_ref().err().cloned();
                if failure != last_failure {
                    match &failure {
                        Some(reason) => tracing::error!(
                            "odind: observe environment={} rescan failing: {reason}",
                            route.environment_id
                        ),
                        None => tracing::info!(
                            "odind: observe environment={} rescan reachable again",
                            route.environment_id
                        ),
                    }
                    last_failure = failure;
                }
                let Ok(newest) = scan else { continue };
                if !newest.is_empty() && current.as_deref() != Some(newest.as_str()) {
                    if follow_log.select(&newest) == Notice::Following {
                        tracing::info!(
                            "odind: observe environment={} session={} following={newest}",
                            route.environment_id, manifest.session_id
                        );
                    }
                    let quoted = format!("'{}'", newest.replace('\'', "'\\''"));
                    let spawned = ssh(&host, &follow_script(&quoted))
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn();
                    match spawned {
                        Ok(mut child) => {
                            lines = child.stdout.take().map(|out| BufReader::new(out).lines());
                            tail = Some(child);
                            decoder = OutputDecoder::new(family, &route.harness_id);
                            live = false;
                            watchdogs.reset_transcript();
                            emit(json!({
                                "type": "message_end",
                                "message": {"role": "assistant", "content": [{
                                    "type": "text",
                                    "text": format!("[observing {newest} on {host}: read-only, Odin cannot confine or stop this agent]")
                                }]},
                            }));
                            current = Some(newest);
                        }
                        Err(error) => tracing::error!("odind: observe tail spawn failed: {error}"),
                    }
                }
                watchdogs.tick(&sink, &route, current.as_deref());
            }
            line = async {
                match lines.as_mut() {
                    Some(lines) => lines.next_line().await,
                    None => std::future::pending().await,
                }
            } => {
                match line {
                    Ok(Some(line)) if line == LIVE_MARK => {
                        live = true;
                        if let Some(path) = current.as_deref() {
                            if follow_log.live(path) == Notice::Live {
                                tracing::info!(
                                    "odind: observe live environment={} session={} following={path}",
                                    route.environment_id, manifest.session_id
                                );
                            }
                        }
                    }
                    Ok(Some(line)) => {
                        for frame in decoder.line(&line).frames {
                            watchdogs.frame(&frame, live, &sink, &route, current.as_deref());
                            emit(frame);
                        }
                    }
                    Ok(None) | Err(_) => {
                        // The tail ended. The next rescan re-follows the newest
                        // file. Same-file reattachment is not a new announcement.
                        lines = None;
                        tail = None;
                        current = None;
                        watchdogs.reset_transcript();
                    }
                }
            }
        }
    }
    if let Some(mut child) = tail {
        let _ = child.start_kill();
    }
    emit(json!({"type": "agent_end", "stopReason": "stop"}));
    tracing::info!(
        "odind: observe environment={} session={} stopped",
        route.environment_id,
        manifest.session_id
    );
}

fn fire(
    sink: &Option<Arc<dyn HarnessIncidentSink>>,
    route: &HarnessRoute,
    transcript: Option<&str>,
    watchdog: &str,
    detail: &str,
) {
    tracing::info!(
        "odind: observe watchdog environment={} watchdog={watchdog} fired transcript={}",
        route.environment_id,
        transcript.unwrap_or_default()
    );
    match sink {
        Some(sink) => sink.raise(
            &route.environment_id,
            watchdog,
            &format!(
                "Watchdog {watchdog} fired on the observed session {} ({}) transcript={}",
                route.environment_id,
                route.environment.host.as_deref().unwrap_or("?"),
                transcript.unwrap_or_default()
            ),
            detail,
        ),
        None => tracing::error!("odind: observe watchdog has no incident sink; logged only"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn force_push_dog() -> Dog {
        Dog {
            declared: EnvironmentWatchdogToml {
                name: "force-push".to_owned(),
                matches: Some("push --force".to_owned()),
                silent_seconds: None,
            },
            last_fired: None,
        }
    }

    #[test]
    fn pod_terminal_watchdog_uses_declared_trigger_and_exact_transcript() {
        struct Sink(std::sync::mpsc::Sender<(String, String, String)>);
        impl HarnessIncidentSink for Sink {
            fn raise(&self, environment: &str, watchdog: &str, summary: &str, _: &str) {
                self.0
                    .send((
                        environment.to_owned(),
                        watchdog.to_owned(),
                        summary.to_owned(),
                    ))
                    .unwrap();
            }
        }
        let route = HarnessRoute {
            harness_id: "fixture-process".to_owned(),
            harness: super::super::tests::process_fixture(),
            environment_id: "pod-authority".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/pod-authority/environment.toml"
            ))
            .unwrap(),
            account: None,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let sink: Option<Arc<dyn HarnessIncidentSink>> = Some(Arc::new(Sink(tx)));
        let mut watchdogs = Watchdogs::new(&route);
        assert_eq!(
            watchdogs.dogs[0].declared.matches.as_deref(),
            Some("push --force")
        );
        let frame = json!({"type":"message_end", "message":{"role":"assistant", "content":[{"type":"text", "text":"push --force"}]}});
        watchdogs.frame(&frame, false, &sink, &route, Some("/old.jsonl"));
        assert!(rx.try_recv().is_err(), "history never raises an incident");
        watchdogs.reset_transcript();
        watchdogs.frame(&frame, true, &sink, &route, Some("/owned/new.jsonl"));
        let (environment, dog, receipt) = rx.try_recv().unwrap();
        assert_eq!(environment, "pod-authority");
        assert_eq!(dog, "force-push");
        assert!(receipt.ends_with("transcript=/owned/new.jsonl"));
        assert!(!receipt.contains("/old.jsonl"));
        watchdogs.frame(&frame, true, &sink, &route, Some("/owned/new.jsonl"));
        assert!(
            rx.try_recv().is_err(),
            "declared evaluator cooldown is shared"
        );
        watchdogs.open_tool = Some(("old-tool".to_owned(), Instant::now()));
        watchdogs.reset_transcript();
        assert!(watchdogs.open_tool.is_none());
    }

    #[test]
    fn fire_forwards_the_current_transcript_without_old_path_leakage() {
        #[derive(Default)]
        struct RecordingSink {
            incidents: std::sync::Mutex<Vec<(String, String, String, String)>>,
        }

        impl HarnessIncidentSink for RecordingSink {
            fn raise(&self, environment: &str, watchdog: &str, summary: &str, detail: &str) {
                self.incidents.lock().expect("incidents lock").push((
                    environment.to_owned(),
                    watchdog.to_owned(),
                    summary.to_owned(),
                    detail.to_owned(),
                ));
            }
        }

        let route = HarnessRoute {
            harness_id: "observe".to_owned(),
            harness: super::super::tests::observe_fixture(),
            environment_id: "pc-claude-session".to_owned(),
            environment: toml::from_str(include_str!(
                "../../../../../registry/environments/pc-claude-session/environment.toml"
            ))
            .expect("declared pc-claude-session environment parses"),
            account: None,
        };
        let recorder = Arc::new(RecordingSink::default());
        let sink: Option<Arc<dyn HarnessIncidentSink>> = Some(recorder.clone());
        let transcripts = ["/sessions/old.jsonl", "/sessions/new.jsonl"];
        let watchdog = "force-push";
        let detail = "push --force";

        for transcript in transcripts {
            fire(&sink, &route, Some(transcript), watchdog, detail);
        }

        let incidents = recorder.incidents.lock().expect("incidents lock");
        assert_eq!(incidents.len(), 2);
        for (incident, transcript) in incidents.iter().zip(transcripts) {
            assert_eq!(incident.0, route.environment_id);
            assert_eq!(incident.1, watchdog);
            assert_eq!(
                incident.2,
                format!(
                    "Watchdog {watchdog} fired on the observed session {} ({}) transcript={transcript}",
                    route.environment_id,
                    route.environment.host.as_deref().unwrap_or("?")
                )
            );
            assert_eq!(incident.3, detail);
        }
        assert!(!incidents[1].2.contains(transcripts[0]));
    }

    #[tokio::test]
    async fn passive_controls_refuse_agent_mutation_and_only_stop_the_watcher() {
        let (stopped, receiver) = watch::channel(false);
        let control = ObserveControl {
            environment: "remote-fixture".to_owned(),
            stopped,
        };
        assert!(matches!(
            control.pause().await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(matches!(
            control.resume().await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(matches!(
            control.restart().await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(matches!(
            control.checkpoint().await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(matches!(
            control.abort_turn().await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(matches!(
            control
                .set_model(
                    &ProviderName::new("observed").unwrap(),
                    &ModelName::new("transcript").unwrap()
                )
                .await,
            Err(LiveError::Unsupported { .. })
        ));
        assert!(!*receiver.borrow());
        control.abort_session().await.unwrap();
        assert!(*receiver.borrow());
    }

    #[test]
    fn same_file_reattachment_does_not_announce_again() {
        let mut log = FollowLog::default();
        assert_eq!(log.select("a.jsonl"), Notice::Following);
        assert_eq!(log.live("a.jsonl"), Notice::Live);
        // The tail dropped. The next rescan selects the same file.
        assert_eq!(log.select("a.jsonl"), Notice::Quiet);
        assert_eq!(log.live("a.jsonl"), Notice::Quiet);
        assert_eq!(log.select("b.jsonl"), Notice::Following);
        assert_eq!(log.live("b.jsonl"), Notice::Live);
    }

    /// A restart must not replay the transcript backlog into a match
    /// watchdog.
    #[test]
    fn only_live_lines_fire_a_match_watchdog() {
        let mut dogs = vec![force_push_dog()];
        let line = r#"{"command":"git push --force origin main"}"#;
        assert!(matched(&mut dogs, line, false).is_empty());
        assert_eq!(
            matched(&mut dogs, line, true),
            vec![("force-push".to_owned(), "push --force".to_owned())]
        );
        assert!(
            matched(&mut dogs, line, true).is_empty(),
            "cools for a minute"
        );
    }

    /// The script splits backlog from live at one byte offset, marker between.
    #[test]
    fn the_follow_script_marks_where_the_live_tail_begins() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("t.jsonl");
        std::fs::write(&path, "old one\nold two\n").expect("write");
        let quoted = format!("'{}'", path.display());
        let script = follow_script(&quoted).replace("exec tail -c", "exec timeout 1 tail -c");
        let writer = {
            let path = path.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .open(path)
                    .expect("open");
                std::io::Write::write_all(&mut file, b"new three\n").expect("append");
            })
        };
        let output = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .expect("bash");
        writer.join().expect("writer");
        let lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(lines, ["old one", "old two", LIVE_MARK, "new three"]);
    }
}
