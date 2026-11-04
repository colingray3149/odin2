//! `odin_deploy` and `odin_deploy_status`: a merged commit goes to the fleet.
//!
//! A project declares where it ships (`deploy = { host, checkout, targets }`).
//! The deploy is `tools/ship.sh` from that very commit on that host: the gate,
//! then `tools/deploy.sh`. It runs detached there, holding the deploy lock, so
//! it outlives the odind it restarts; odind starts it, journals it, and reads
//! the progress line it keeps. The restart ends `odin_deploy`'s job, and
//! `odin_deploy_status` tells how it finished.

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use odin_ledger::Ledger;
use odin_omp::capability_parameters;
use odin_omp::host_tools::{HostTool, HostToolError, RpcHostToolDefinition, ToolLoadMode};
use odin_omp::redact::redact_text;
use odin_registry::{ObjectConfig, RegistryKind};
use serde_json::{json, Value};
use time::OffsetDateTime;

use super::super::tools::CapabilityTool;
use super::super::HermesRuntime;

const DEPLOY_TOOL: &str = "odin_deploy";
const STATUS_TOOL: &str = "odin_deploy_status";
const STATUS_CAPABILITY: &str = "odin.deploy.status";
const STARTED_KIND: &str = "odin.deploy.started";
const FINISHED_KIND: &str = "odin.deploy.finished";
const POLL: Duration = Duration::from_secs(15);
/// Odin's state on the deploy host, relative to home. `tools/deploy.sh`
/// takes the same `deploy.lock` when it runs on its own.
const STATE: &str = ".local/state/odin";

/// `$1` commit, `$2` checkout, `$3` worktree, `$4` progress file, `$5` lock
/// (all relative to home). A deploy of the commit that is running or done is followed, not started
/// again; one that failed or died runs anew.
const START: &str = r#"set -eu
c=$1 checkout=$HOME/$2 w=$HOME/$3 progress=$HOME/$4 lock=$HOME/$5
if [ -e "$progress" ]; then
  [ "$(jq -r .stage "$progress")" = done ] && exit 0
  kill -0 "$(jq -r .pid "$progress")" 2>/dev/null && exit 0
fi
mkdir -p "$(dirname "$progress")" "$(dirname "$lock")"
exec 9>"$lock"
flock -n 9 || { echo "another deploy is running (it holds $lock)" >&2; exit 1; }
rm -f "$progress"
cd "$checkout"
git fetch -q origin
main=$(git rev-parse origin/main)
if [ "$main" != "$c" ]; then
  # Odin commits its own runtime registry declarations to main: a tip that only adds those on top of $c ships.
  if ! { git merge-base --is-ancestor "$c" "$main" && git diff --quiet "$c" "$main" -- . ':!registry'; }; then
    echo "origin/main is $main, not $c" >&2
    exit 1
  fi
fi
if [ -d "$w" ]; then
  git -C "$w" checkout -qf --detach "$c" && git -C "$w" clean -qfd
else
  git worktree add -q --detach "$w" "$c"
fi
setsid -f "$w/tools/ship.sh" "$c" "$progress" </dev/null >/dev/null 2>&1
"#;

/// Prints the progress line `$1` (or the newest matching the glob `$2`),
/// then whether the ship that writes it still runs.
const READ: &str = r#"set -eu
f=${1:+$HOME/$1}
f=${f:-$(ls -t $HOME/$2 2>/dev/null | head -n 1)}
[ -n "$f" ] && [ -e "$f" ] || { echo "no deploy has run${1:+ for this commit}" >&2; exit 1; }
head -n 1 "$f"
kill -0 "$(jq -r .pid "$f")" 2>/dev/null && echo alive || echo gone
"#;

/// The subject of commit `$2` in the checkout `$1`.
const SUBJECT: &str = r#"set -eu
cd "$HOME/$1"
git fetch -q origin
git log -1 --format=%s "$2"
"#;

/// The files commit `$2` changes in the checkout `$1`, as `git show --stat` lists them.
const STAT: &str = r#"set -eu
cd "$HOME/$1"
git fetch -q origin
git show --stat --format= "$2"
"#;

/// Where one project ships, from its declaration.
struct Target {
    project: String,
    ssh: String,
    checkout: String,
    targets: Vec<String>,
}

impl Target {
    fn worktree(&self) -> String {
        format!("{STATE}/ship/{}", self.project)
    }
    fn progress(&self, commit: &str) -> String {
        format!("{STATE}/deploys/{}-{commit}.json", self.project)
    }
    fn newest(&self) -> String {
        format!("{STATE}/deploys/{}-*.json", self.project)
    }
}

/// Where a deploy stands: its progress line, sorted by whether it ended.
enum Outcome {
    Done(Value),
    Failed(Value),
    Running(Value),
}

/// The project's declared deploy host (its tailnet name), checkout and targets.
fn target(
    tool: &'static str,
    runtime: &HermesRuntime,
    project: &str,
) -> Result<Target, HostToolError> {
    let pin = runtime
        .registry_pin()
        .ok_or_else(|| HostToolError::unavailable(tool, "no registry snapshot is pinned"))?;
    let snapshot = pin.current();
    let Some(ObjectConfig::Project(declared)) = snapshot
        .object(RegistryKind::Project, project)
        .map(|object| &object.config)
    else {
        return Err(HostToolError::unavailable(
            tool,
            format!("project {project} is not declared"),
        ));
    };
    let deploy = declared.deploy.as_ref().ok_or_else(|| {
        HostToolError::unavailable(tool, format!("project {project} declares no deploy"))
    })?;
    let Some(ObjectConfig::Host(host)) = snapshot
        .object(RegistryKind::Host, &deploy.host)
        .map(|object| &object.config)
    else {
        return Err(HostToolError::unavailable(
            tool,
            format!(
                "project {project} deploys from host {}, which is not declared",
                deploy.host
            ),
        ));
    };
    Ok(Target {
        project: project.to_owned(),
        ssh: host.tailscale.clone(),
        checkout: deploy.checkout.clone(),
        targets: deploy.targets.clone(),
    })
}

/// Runs `script` on the deploy host with `args`; stdout, or the script's own stderr as the cause.
fn on_host(
    tool: &'static str,
    target: &Target,
    script: &str,
    args: &[&str],
) -> Result<String, HostToolError> {
    let host = &target.ssh;
    // ssh hands the remote shell one string: each argument goes single-quoted.
    let quoted: Vec<String> = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', r"'\''")))
        .collect();
    let mut child = Command::new("ssh")
        .args(odin_omp::live::harness::SSH_OPTIONS)
        .args(["--", host])
        .arg(format!("bash -s -- {}", quoted.join(" ")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            HostToolError::unavailable(tool, format!("ssh to {host} could not start: {error}"))
        })?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(script.as_bytes())
        .map_err(|error| HostToolError::unavailable(tool, format!("ssh to {host}: {error}")))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| HostToolError::unavailable(tool, format!("ssh to {host}: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(HostToolError::unavailable(
            tool,
            if stderr.is_empty() {
                format!("{host} answered with exit {:?}", output.status.code())
            } else {
                redact_text(&stderr)
            },
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Sorts one progress read; a ship that is gone before `done` or `failed` failed.
fn outcome(target: &Target, out: &str) -> Option<Outcome> {
    let mut lines = out.lines();
    let mut value: Value = serde_json::from_str(lines.next()?).ok()?;
    value.as_object_mut()?.remove("pid");
    let alive = lines.next().map(str::trim) == Some("alive");
    value["line"] = json!(redact_text(value["line"].as_str().unwrap_or("")));
    Some(match value["stage"].as_str().unwrap_or("") {
        "done" => Outcome::Done(value),
        "failed" => Outcome::Failed(value),
        _ if alive => Outcome::Running(value),
        stage => {
            value["line"] = json!(format!(
                "the deploy stopped while {stage} without finishing (its process on {} is \
                 gone): {}",
                target.ssh,
                value["line"].as_str().unwrap_or("")
            ));
            value["stage"] = json!("failed");
            Outcome::Failed(value)
        }
    })
}

/// The progress of one deploy (or the project's newest).
fn progress(
    tool: &'static str,
    target: &Target,
    commit: Option<&str>,
) -> Result<Outcome, HostToolError> {
    let file = commit
        .map(|commit| target.progress(commit))
        .unwrap_or_default();
    let out = on_host(tool, target, READ, &[&file, &target.newest()])?;
    outcome(target, &out).ok_or_else(|| {
        HostToolError::unavailable(
            tool,
            format!("the progress file on {} is unreadable", target.ssh),
        )
    })
}

/// Follows a deploy until it ends or `deadline` passes, journaling its end once.
fn follow(
    tool: &'static str,
    runtime: &HermesRuntime,
    target: &Target,
    commit: &str,
    deadline: Duration,
) -> Result<Outcome, HostToolError> {
    let started = Instant::now();
    loop {
        let outcome = progress(tool, target, Some(commit))?;
        let ended = match &outcome {
            Outcome::Running(_) if started.elapsed() + POLL < deadline => {
                std::thread::sleep(POLL);
                continue;
            }
            Outcome::Running(_) => return Ok(outcome),
            Outcome::Done(value) | Outcome::Failed(value) => value,
        };
        journal(
            &runtime.purchase_ledger,
            FINISHED_KIND,
            &target.project,
            commit,
            json!({ "stage": ended["stage"], "line": ended["line"] }),
            Vec::new(),
        )
        .map_err(|error| HostToolError::unavailable(tool, error))?;
        return Ok(outcome);
    }
}

/// One audit row per deploy and kind in the authority ledger; a repeat keeps the first.
fn journal(
    ledger: &Mutex<Ledger>,
    kind: &str,
    project: &str,
    commit: &str,
    mut payload: Value,
    evidence: Vec<odin_ledger::audit::AuditEvidence>,
) -> Result<(), String> {
    use odin_ledger::audit::{NewAuditEvent, RedactedPayload};
    let event_id = odin_domain::EventId::new(format!("{kind}:{project}:{commit}"))
        .map_err(|error| error.to_string())?;
    let ledger = ledger
        .lock()
        .map_err(|error| format!("the authority ledger lock: {error}"))?;
    if ledger
        .audit_event(&event_id)
        .map_err(|error| format!("the deploy journal is unreadable: {error}"))?
        .is_some()
    {
        return Ok(());
    }
    payload["project"] = json!(project);
    payload["commit"] = json!(commit);
    ledger
        .append_audit_event(NewAuditEvent {
            event_id,
            kind: kind.to_owned(),
            actor: odin_domain::Actor::system(super::super::RUNTIME_ISSUER)
                .map_err(|error| error.to_string())?,
            scope: odin_domain::Scope {
                project: odin_domain::ProjectId::new(project).ok(),
                ..Default::default()
            },
            evidence,
            payload: RedactedPayload::new(payload, odin_domain::Redaction::None)
                .map_err(|error| error.to_string())?,
            occurred_at: OffsetDateTime::now_utc(),
        })
        .map_err(|error| format!("the deploy was not journaled: {error}"))?;
    Ok(())
}

/// The changed-file summary the card shows: at most 20 file lines, then
/// "… N more files", then git's own totals line.
fn stat_block(stat: &str) -> String {
    const SHOWN: usize = 20;
    let lines: Vec<&str> = stat
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let Some((totals, files)) = lines.split_last() else {
        return String::new();
    };
    let mut shown: Vec<&str> = files.iter().take(SHOWN).copied().collect();
    let more = (files.len() > SHOWN).then(|| format!("… {} more files", files.len() - SHOWN));
    shown.extend(more.as_deref());
    shown.push(totals);
    shown.join("\n")
}

/// What the owner approves: the project, the commit and its subject, where it
/// is gated, which hosts it switches, and the files it changes.
fn card(target: &Target, commit: &str, subject: &str, stat: &str) -> String {
    let head = format!(
        "Deploy {} at {} (\"{subject}\"): gate it on {}, then switch {}.",
        target.project,
        &commit[..12],
        target.ssh,
        target.targets.join(", ")
    );
    if stat.is_empty() {
        head
    } else {
        format!("{head}\n{stat}")
    }
}

/// The approval card's detail for one exact `odin.deploy` request.
pub(in crate::runtime) fn question_detail(
    runtime: &HermesRuntime,
    request: &Value,
) -> Result<String, String> {
    let project = project_argument(DEPLOY_TOOL, request).map_err(|error| error.to_string())?;
    let commit = commit_argument(DEPLOY_TOOL, request)
        .map_err(|error| error.to_string())?
        .ok_or("the deploy request names no commit")?;
    let target = target(DEPLOY_TOOL, runtime, &project).map_err(|error| error.to_string())?;
    let subject = on_host(DEPLOY_TOOL, &target, SUBJECT, &[&target.checkout, &commit])
        .map_err(|error| error.to_string())?;
    let stat = on_host(DEPLOY_TOOL, &target, STAT, &[&target.checkout, &commit])
        .map_err(|error| error.to_string())?;
    Ok(card(&target, &commit, subject.trim(), &stat_block(&stat)))
}

fn commit_argument(tool: &'static str, arguments: &Value) -> Result<Option<String>, HostToolError> {
    match arguments.get("commit") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(commit))
            if commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Ok(Some(commit.to_ascii_lowercase()))
        }
        Some(_) => Err(HostToolError::Arguments {
            tool,
            detail: "commit must be a full 40-character commit id".to_owned(),
        }),
    }
}

fn project_argument(tool: &'static str, arguments: &Value) -> Result<String, HostToolError> {
    arguments
        .get("project")
        .and_then(Value::as_str)
        .filter(|project| !project.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| HostToolError::Arguments {
            tool,
            detail: "project is required".to_owned(),
        })
}

fn timeout(contract: &odin_kernel::CapabilityContract) -> Duration {
    Duration::from_secs(u64::from(contract.timeout_seconds.get()))
}

pub(in crate::runtime) fn deploy_tools(
    runtime: &Arc<HermesRuntime>,
    tools: &mut Vec<Arc<dyn HostTool>>,
) {
    let deploy_runtime = Arc::clone(runtime);
    let consumed = Box::new(
        move |effect: &odin_kernel::operation::PreparedEffect,
              consumed: &odin_omp::host_tools::ConsumedHostCommand,
              _,
              arguments: Value| {
            let project = project_argument(DEPLOY_TOOL, &arguments)?;
            let commit = commit_argument(DEPLOY_TOOL, &arguments)?.ok_or_else(|| {
                HostToolError::Arguments {
                    tool: DEPLOY_TOOL,
                    detail: "commit is required".to_owned(),
                }
            })?;
            let target = target(DEPLOY_TOOL, &deploy_runtime, &project)?;
            let lock = format!("{STATE}/deploy.lock");
            on_host(
                DEPLOY_TOOL,
                &target,
                START,
                &[
                    &commit,
                    &target.checkout,
                    &target.worktree(),
                    &target.progress(&commit),
                    &lock,
                ],
            )?;
            journal(
                &deploy_runtime.purchase_ledger,
                STARTED_KIND,
                &project,
                &commit,
                json!({
                    "approvalId": arguments.get("approvalId"),
                    "host": target.ssh,
                    "targets": target.targets,
                }),
                vec![odin_ledger::audit::AuditEvidence::Command(
                    consumed.command_id().clone(),
                )],
            )
            .map_err(|error| HostToolError::unavailable(DEPLOY_TOOL, error))?;
            let deadline = timeout(effect.contract());
            match follow(DEPLOY_TOOL, &deploy_runtime, &target, &commit, deadline)? {
                Outcome::Done(value) => Ok(value),
                Outcome::Failed(value) => Err(HostToolError::unavailable(
                    DEPLOY_TOOL,
                    format!(
                        "the deploy failed: {}",
                        value["line"].as_str().unwrap_or("")
                    ),
                )),
                Outcome::Running(value) => Err(HostToolError::unavailable(
                    DEPLOY_TOOL,
                    format!(
                        "the deploy is still {} after {} min: {}; odin_deploy_status follows it",
                        value["stage"].as_str().unwrap_or(""),
                        deadline.as_secs() / 60,
                        value["line"].as_str().unwrap_or("")
                    ),
                )),
            }
        },
    );
    let preflight_runtime = Arc::clone(runtime);
    let preflight = Box::new(move |_: &odin_domain::Scope, arguments: &Value| {
        commit_argument(DEPLOY_TOOL, arguments)?;
        target(
            DEPLOY_TOOL,
            &preflight_runtime,
            &project_argument(DEPLOY_TOOL, arguments)?,
        )
        .map(|_| ())
    });
    tools.push(Arc::new(CapabilityTool::approved(
        RpcHostToolDefinition {
            name: DEPLOY_TOOL.into(),
            label: "Deploy a merged commit".into(),
            description: "Deploy a project's merged commit (the tip of its origin/main, as \
                git_branch_merge left it). Odin asks the owner first and shows him the commit \
                and the hosts. On the project's declared deploy host it runs the full gate on \
                that commit, then switches the project's declared target hosts once your \
                conversation is between turns, which restarts Odin. It takes 20 to 40 minutes \
                and becomes a background job. The restart ends that job (its report says it \
                ended when Odin stopped): then call odin_deploy_status with the project, \
                commit and wait to learn how it finished, and tell him. A failed gate or \
                deploy comes back with its cause; nothing is retried."
                .into(),
            parameters: capability_parameters!("odin.deploy"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        "odin.deploy",
        consumed,
        preflight,
    )));
    let status_runtime = Arc::clone(runtime);
    let status = move |_, arguments: Value| {
        let target = target(
            STATUS_TOOL,
            &status_runtime,
            &project_argument(STATUS_TOOL, &arguments)?,
        )?;
        let commit = commit_argument(STATUS_TOOL, &arguments)?;
        let outcome = match (arguments.get("wait").and_then(Value::as_bool), commit) {
            (Some(true), Some(commit)) => {
                let deadline = odin_domain::CapabilityId::new(STATUS_CAPABILITY)
                    .ok()
                    .and_then(|id| status_runtime.contracts.get(&id))
                    .map(timeout)
                    .ok_or_else(|| {
                        HostToolError::unavailable(
                            STATUS_TOOL,
                            format!("{STATUS_CAPABILITY} is not admitted"),
                        )
                    })?;
                follow(STATUS_TOOL, &status_runtime, &target, &commit, deadline)?
            }
            (Some(true), None) => {
                return Err(HostToolError::Arguments {
                    tool: STATUS_TOOL,
                    detail: "wait needs the commit".to_owned(),
                })
            }
            (_, commit) => progress(STATUS_TOOL, &target, commit.as_deref())?,
        };
        let (Outcome::Done(value) | Outcome::Failed(value) | Outcome::Running(value)) = outcome;
        Ok(value)
    };
    tools.push(Arc::new(CapabilityTool::plain_without_prerequisites(
        RpcHostToolDefinition {
            name: STATUS_TOOL.into(),
            label: "How a deploy is going".into(),
            description: "Where one deploy of a project stands (its newest when commit is left \
                out): stage gate, deploying, done or failed, a plain line saying what happened, \
                and when. wait (with commit) follows it until it is done or failed, as a \
                background job; a deploy still under way when the wait ends keeps its stage."
                .into(),
            parameters: capability_parameters!("odin.deploy.status"),
            hidden: false,
            load_mode: ToolLoadMode::Discoverable,
        },
        Box::new(status),
    )));
}

#[cfg(test)]
mod tests {
    use super::*;

    const C: &str = "0123456789abcdef0123456789abcdef01234567";

    fn target() -> Target {
        Target {
            project: "odin".to_owned(),
            ssh: "builder".to_owned(),
            checkout: "valhalla/odin".to_owned(),
            targets: vec!["authority".to_owned(), "builder".to_owned()],
        }
    }

    /// A start and an end are journaled once each, with the command that
    /// carried the approval; a second read of the same end adds nothing.
    #[test]
    fn a_deploy_is_journaled_once_per_start_and_end() {
        let ledger = Mutex::new(Ledger::open_in_memory().expect("ledger"));
        let command = odin_domain::CommandId::new("command:deploy-1").expect("command");
        journal(
            &ledger,
            STARTED_KIND,
            "odin",
            C,
            json!({ "approvalId": "approval:1", "targets": ["authority", "builder"] }),
            vec![odin_ledger::audit::AuditEvidence::Command(command.clone())],
        )
        .expect("start journaled");
        for _ in 0..2 {
            journal(
                &ledger,
                FINISHED_KIND,
                "odin",
                C,
                json!({ "stage": "done", "line": "deploy: pin=… skipped=none odind=active huginn=ok" }),
                Vec::new(),
            )
            .expect("end journaled");
        }
        let events = ledger
            .lock()
            .unwrap()
            .audit_events_after(0, 10)
            .expect("audit rows");
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(events[0].kind, STARTED_KIND);
        assert_eq!(events[0].payload["approvalId"], "approval:1");
        assert_eq!(events[0].payload["commit"], C);
        assert_eq!(
            events[0].evidence,
            vec![odin_ledger::audit::AuditEvidence::Command(command)]
        );
        assert_eq!(events[1].kind, FINISHED_KIND);
        assert_eq!(events[1].payload["stage"], "done");
    }

    /// A progress line whose ship is gone before it ended reads as failed;
    /// a live one is still running, never done.
    #[test]
    fn a_vanished_ship_is_failed_and_a_live_one_still_running() {
        let line = json!({ "commit": C, "stage": "gate", "line": "gating", "at": "t", "pid": 7 });
        match outcome(&target(), &format!("{line}\ngone\n")) {
            Some(Outcome::Failed(value)) => {
                assert!(value["line"]
                    .as_str()
                    .unwrap()
                    .contains("stopped while gate"));
                assert!(value.get("pid").is_none());
            }
            _ => panic!("a gone ship is failed"),
        }
        assert!(matches!(
            outcome(&target(), &format!("{line}\nalive\n")),
            Some(Outcome::Running(_))
        ));
    }

    fn run(dir: &std::path::Path, program: &str, args: &[&str]) {
        let status = Command::new(program)
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
            .expect("command starts");
        assert!(status.success(), "{program} {args:?}");
    }

    /// Runs START as the deploy host's shell would, with `home` as its home.
    fn start(home: &std::path::Path, commit: &str) {
        let mut child = Command::new("bash")
            .args([
                "-s",
                "--",
                commit,
                "checkout",
                "ship",
                "deploys/p.json",
                "deploy.lock",
            ])
            .env("HOME", home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bash starts");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(START.as_bytes())
            .expect("script written");
        let output = child.wait_with_output().expect("script ends");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Waits for the detached ship to leave a progress line in `stage`.
    fn wait_for_stage(home: &std::path::Path, stage: &str) {
        let progress = home.join("deploys/p.json");
        for _ in 0..100 {
            let text = std::fs::read_to_string(&progress).unwrap_or_default();
            if text.contains(&format!("\"stage\":\"{stage}\"")) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the ship never reached {stage}");
    }

    /// An approved retry of a commit whose deploy failed runs the ship again; a deploy that is
    /// done is followed, not run twice.
    #[test]
    fn an_approved_retry_of_a_failed_deploy_runs_it_again() {
        let home = tempfile::tempdir().expect("home");
        let path = home.path();
        std::fs::create_dir_all(path.join("seed/tools")).expect("seed");
        std::fs::write(
            path.join("seed/tools/ship.sh"),
            "#!/usr/bin/env bash\necho run >>\"$HOME/ships\"\n\
             stage=done; [ \"$(wc -l <\"$HOME/ships\")\" -gt 1 ] || stage=failed\n\
             jq -cn --arg stage $stage --argjson pid $$ '{stage: $stage, line: \"x\", pid: $pid}' >\"$2\"\n",
        )
        .expect("ship stub");
        let seed = path.join("seed");
        run(&seed, "git", &["init", "-q", "-b", "main"]);
        run(&seed, "chmod", &["+x", "tools/ship.sh"]);
        run(&seed, "git", &["add", "."]);
        run(
            &seed,
            "git",
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-qm",
                "ship",
            ],
        );
        run(path, "git", &["clone", "-q", "seed", "checkout"]);
        let commit = String::from_utf8(
            Command::new("git")
                .args(["-C", "seed", "rev-parse", "HEAD"])
                .current_dir(path)
                .output()
                .expect("rev-parse")
                .stdout,
        )
        .expect("utf8");
        let commit = commit.trim();
        let ships = || {
            std::fs::read_to_string(path.join("ships"))
                .unwrap_or_default()
                .lines()
                .count()
        };

        start(path, commit);
        wait_for_stage(path, "failed");
        assert_eq!(ships(), 1);
        start(path, commit);
        wait_for_stage(path, "done");
        assert_eq!(ships(), 2, "the failed deploy ran anew");
        start(path, commit);
        assert_eq!(ships(), 2, "a finished deploy is followed, not run again");
    }
}
