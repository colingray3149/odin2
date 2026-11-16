//! Official-client consult drivers behind `model.consult`'s model choices:
//! Opus 5.5 through Claude Code on this Claude host, Antigravity models
//! through the installed agy.
//!
//! Both lanes are one question with no tools, returned through the same
//! consult result. Claude Code runs `claude -p` under the claude-review
//! workload's declared binary and account, with session records landing in
//! that account's own Claude directory so ccusage attributes the spend;
//! Odin never touches another account and never rotates. agy runs under
//! the one aisw antigravity profile the configuration pins and refuses
//! when a different profile is active — switching accounts is the owner's act,
//! never the daemon's.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use odin_hermes::runtime::consult::{
    OfficialConsultModel, OfficialConsultOutcome, OfficialConsultRoute,
};
use odin_huginn::config::OdindConsultAgyConfig;
use odin_registry::schema::{
    AGY_ROUTE, CHAT_CAPABILITY, CLAUDE_ROUTE, FRONTIER_TIER, GATEWAY_ROUTE,
};
use odin_registry::{
    AccountKind, ClaudePlacement, ClaudeReviewToml, ObjectConfig, RegistryKind, SnapshotHandle,
};
use serde_json::{json, Value};

/// The effort official clients consult at when the card declares no
/// thinking default. Opus 5.5 consults at high.
const DEFAULT_EFFORT: &str = "high";
const DEFAULT_CONSULT_TIMEOUT: Duration = Duration::from_secs(300);
const CLAUDE_EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];

const EMPTY_MCP: &[u8] = b"{\"mcpServers\":{}}";

pub(crate) struct DaemonConsultRoute {
    pub pin: Arc<SnapshotHandle>,
    pub state_root: PathBuf,
    pub agy: Option<OdindConsultAgyConfig>,
}

/// The Claude Code engine a claude-code card consults through: the
/// claude-review workload's declared binary and account on this host.
fn claude_engine(snapshot: &odin_registry::Snapshot) -> Result<ClaudeReviewToml, String> {
    let workload = snapshot
        .object(RegistryKind::Workload, "claude-review")
        .filter(|object| object.enabled())
        .ok_or("the claude-review workload is disabled or missing")?;
    let ObjectConfig::ClaudeCode(profile) = &workload.config else {
        return Err("the claude-review workload is disabled or missing".to_owned());
    };
    if profile.placement != ClaudePlacement::Review {
        return Err("the claude-review workload is disabled or missing".to_owned());
    }
    profile
        .review
        .clone()
        .ok_or_else(|| "the claude-review workload is disabled or missing".to_owned())
}

/// The `model.consult` capability's declared timeout.
fn consult_timeout(snapshot: &odin_registry::Snapshot) -> Duration {
    snapshot
        .object(RegistryKind::Capability, "model.consult")
        .and_then(|object| match &object.config {
            ObjectConfig::Capability(capability) => Some(capability.timeout_seconds.get()),
            _ => None,
        })
        .map_or(DEFAULT_CONSULT_TIMEOUT, |seconds| {
            Duration::from_secs(u64::from(seconds))
        })
}

/// The effort a card consults at: its thinking default, else high.
fn effort(card: &odin_registry::schema::ModelCardToml) -> String {
    card.thinking
        .as_ref()
        .and_then(|thinking| thinking.default.clone())
        .unwrap_or_else(|| DEFAULT_EFFORT.to_owned())
}

/// The model identity an official client is invoked with: an `agy` card's
/// served value verbatim, a `claude-code` card's served value without its
/// provider prefix.
fn official_model(card: &odin_registry::schema::ModelCardToml) -> Option<&str> {
    match card.route.as_str() {
        AGY_ROUTE => card.served.as_deref(),
        CLAUDE_ROUTE => card
            .served
            .as_deref()
            .map(|served| served.split_once('/').map_or(served, |(_, model)| model)),
        _ => None,
    }
}

impl OfficialConsultRoute for DaemonConsultRoute {
    fn models(&self) -> Vec<OfficialConsultModel> {
        let snapshot = self.pin.current();
        // Claude Code consults through the claude-review workload's
        // declared engine; agy through the pinned aisw profile.
        if claude_engine(&snapshot).is_err() && self.agy.is_none() {
            return Vec::new();
        }
        let mut models = Vec::new();
        for object in &snapshot.objects {
            let ObjectConfig::Model(card) = &object.config else {
                continue;
            };
            if !object.enabled()
                || card.capability != CHAT_CAPABILITY
                || card.tier.as_deref() != Some(FRONTIER_TIER)
                || card.route == GATEWAY_ROUTE
            {
                continue;
            }
            let Some(model) = official_model(card) else {
                continue;
            };
            let serves = match card.route.as_str() {
                CLAUDE_ROUTE => claude_engine(&snapshot).is_ok(),
                AGY_ROUTE => self.agy.is_some(),
                _ => false,
            };
            if !serves {
                continue;
            }
            models.push(OfficialConsultModel {
                id: card.id.clone(),
                route: card.route.clone(),
                model: model.to_owned(),
                effort: effort(card),
                strengths: card.strengths.clone(),
            });
        }
        models
    }

    fn consult(
        &self,
        _seat: &str,
        model: &OfficialConsultModel,
        question: &str,
        material: Option<&str>,
    ) -> Result<OfficialConsultOutcome, String> {
        match model.route.as_str() {
            CLAUDE_ROUTE => self.consult_claude(model, question, material),
            AGY_ROUTE => self.consult_agy(model, question, material),
            route => Err(format!("no official consult driver serves route {route:?}")),
        }
    }
}

/// The Claude Code consult invocation: one question, no tools, the card's
/// model and effort, sessions persisted for ccusage.
fn claude_consult_argv(model: &str, effort: &str, run: &Path) -> Vec<String> {
    [
        "-p",
        "--model",
        model,
        "--effort",
        effort,
        "--tools",
        "",
        "--allowedTools",
        "",
        "--restricted",
        "--permission-prompts",
        "none",
        "--strict-mcp-config",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        "--mcp-config".to_owned(),
        run.join("mcp.json").to_string_lossy().into_owned(),
        "--settings".to_owned(),
        run.join("settings.json").to_string_lossy().into_owned(),
        "--append-system-prompt".to_owned(),
        CONSULT_SYSTEM.to_owned(),
        "--output-format".to_owned(),
        "json".to_owned(),
    ])
    .collect()
}

impl DaemonConsultRoute {
    fn run_dir(&self, lane: &str) -> Result<PathBuf, String> {
        let id = odin_process::mint_worker_id().map_err(|error| error.to_string())?;
        let run = self.state_root.join("consult").join(lane).join(id.as_str());
        std::fs::create_dir_all(&run).map_err(|error| format!("consult run dir: {error}"))?;
        Ok(run)
    }

    fn user_prompt(question: &str, material: Option<&str>) -> String {
        match material {
            Some(material) => format!("{question}\n\nMaterial for the question:\n{material}"),
            None => question.to_owned(),
        }
    }

    /// Opus 5.5 through Claude Code: `claude -p` on this Claude host, no
    /// tools, at the card's effort. Session records persist in the declared
    /// account's own Claude directory, so ccusage attributes the spend.
    fn consult_claude(
        &self,
        model: &OfficialConsultModel,
        question: &str,
        material: Option<&str>,
    ) -> Result<OfficialConsultOutcome, String> {
        let snapshot = self.pin.current();
        let engine = claude_engine(&snapshot)?;
        let timeout = consult_timeout(&snapshot);
        if !CLAUDE_EFFORTS.contains(&model.effort.as_str()) {
            return Err(format!(
                "Claude Code effort {:?} is not one of {}",
                model.effort,
                CLAUDE_EFFORTS.join(", ")
            ));
        }
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        let home = PathBuf::from(home);
        let layout = AccountKind::ClaudeCode.layout(&engine.account);
        let config_dir = home.join(&layout.dir);
        let run = self.run_dir("claude")?;
        let outcome = (|| -> Result<OfficialConsultOutcome, String> {
            let prompt = Self::user_prompt(question, material);
            private_file(&run.join("mcp.json"), EMPTY_MCP)?;
            let settings = json!({
                "permissions": {"deny": ["Read", "Edit", "Write", "Bash", "WebFetch", "WebSearch"]},
                "env": {
                    "DISABLE_AUTOUPDATER": "1",
                    "DISABLE_TELEMETRY": "1",
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                },
            });
            private_file(&run.join("settings.json"), settings.to_string().as_bytes())?;
            let binary = std::fs::canonicalize(&engine.binary)
                .map_err(|error| format!("claude binary {}: {error}", engine.binary))?;
            let mut command = Command::new(&binary);
            command
                .args(claude_consult_argv(&model.model, &model.effort, &run))
                .current_dir(&run)
                .env_clear()
                .env("HOME", &home)
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("CLAUDE_CONFIG_DIR", &config_dir);
            let started = Instant::now();
            let value = run_bounded(command, Some(prompt), timeout, "claude")?;
            if value["is_error"] == true {
                return Err(format!(
                    "the {} consult failed: {}",
                    model.id, value["result"]
                ));
            }
            let answer = value["result"]
                .as_str()
                .filter(|answer| !answer.trim().is_empty())
                .ok_or_else(|| format!("the {} consult returned no answer", model.id))?
                .to_owned();
            let served_model = value["modelUsage"]
                .as_object()
                .and_then(|models| models.keys().next().cloned())
                .or_else(|| Some(model.model.clone()));
            let session = value["session_id"].as_str().map(str::to_owned);
            let cost = value["total_cost_usd"].as_f64();
            let input_tokens = value.pointer("/usage/input_tokens").and_then(Value::as_u64);
            let output_tokens = value
                .pointer("/usage/output_tokens")
                .and_then(Value::as_u64);
            // The session record in the account's own directory is what
            // ccusage attributes; name it so the spend is traceable.
            tracing::info!(
                "odind: consult claude account={} session={} input_tokens={} output_tokens={} \
                 cost_usd={}",
                engine.account,
                session.as_deref().unwrap_or("unknown"),
                input_tokens.map_or("unknown".to_owned(), |n| n.to_string()),
                output_tokens.map_or("unknown".to_owned(), |n| n.to_string()),
                cost.map_or("unknown".to_owned(), |c| format!("{c:.4}")),
            );
            Ok(OfficialConsultOutcome {
                answer,
                served_model,
                seconds: started.elapsed().as_secs(),
                input_tokens,
                output_tokens,
                cost_usd: cost,
            })
        })();
        let _ = std::fs::remove_dir_all(&run);
        outcome
    }

    /// An Antigravity model through agy, under the one pinned aisw
    /// antigravity profile. A different active profile is a refusal, never
    /// a switch: the owner rotates accounts himself.
    fn consult_agy(
        &self,
        model: &OfficialConsultModel,
        question: &str,
        material: Option<&str>,
    ) -> Result<OfficialConsultOutcome, String> {
        let config = self
            .agy
            .as_ref()
            .ok_or("the agy consult lane is not configured on this host ([hermes.consult.agy])")?;
        let snapshot = self.pin.current();
        let timeout = consult_timeout(&snapshot);
        let active = active_antigravity_profile(&config.aisw)?;
        if active.as_deref() != Some(config.profile.as_str()) {
            return Err(format!(
                "the active antigravity profile is {:?}, not the pinned {:?}; consult uses \
                 exactly one account and never switches — run: aisw use antigravity {}",
                active.unwrap_or_else(|| "none".to_owned()),
                config.profile,
                config.profile
            ));
        }
        let run = self.run_dir("agy")?;
        let outcome = (|| -> Result<OfficialConsultOutcome, String> {
            let prompt = Self::user_prompt(question, material);
            let binary = std::fs::canonicalize(&config.binary)
                .map_err(|error| format!("agy binary {}: {error}", config.binary.display()))?;
            let mut command = Command::new(&binary);
            command
                .arg("-p")
                .arg(&prompt)
                .arg("--model")
                .arg(&model.model)
                .arg("--effort")
                .arg(&model.effort)
                .arg("--output-format")
                .arg("json")
                .arg("--sandbox")
                .current_dir(&run)
                .env_clear()
                .env("HOME", std::env::var_os("HOME").unwrap_or_default())
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
            let started = Instant::now();
            let value = run_bounded(command, None, timeout, "agy")?;
            if value["status"] == "ERROR" {
                let reason = value["error"]
                    .as_str()
                    .filter(|reason| !reason.is_empty())
                    .unwrap_or("agy reported an error");
                return Err(format!("the {} consult failed: {reason}", model.id));
            }
            let answer = value["response"]
                .as_str()
                .filter(|answer| !answer.trim().is_empty())
                .ok_or_else(|| format!("the {} consult returned no answer", model.id))?
                .to_owned();
            let seconds = value["duration_seconds"]
                .as_f64()
                .map_or_else(|| started.elapsed().as_secs(), |seconds| seconds as u64);
            Ok(OfficialConsultOutcome {
                answer,
                served_model: value["model"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| Some(model.model.clone())),
                seconds,
                input_tokens: value.pointer("/usage/input_tokens").and_then(Value::as_u64),
                output_tokens: value
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64),
                // agy reports no cost; the subscription's own readings
                // carry the spend.
                cost_usd: None,
            })
        })();
        let _ = std::fs::remove_dir_all(&run);
        outcome
    }
}

/// The framing every consulted model sees. Same contract as the gateway
/// consult's system message.
const CONSULT_SYSTEM: &str = "Another agent is consulting you on a question it judged hard. The \
answer comes back as its result: the result first, then the reasoning that supports it, with the \
steps a reader needs to check it, in under 600 words. Where you are unsure, or the question lacks \
a fact, say so, and name the sources and numbers the answer rests on.";

/// The active antigravity profile aisw reports, if it answers at all.
fn active_antigravity_profile(aisw: &Path) -> Result<Option<String>, String> {
    let output = Command::new(aisw)
        .args(["list", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("could not run {}: {error}", aisw.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} list --json exited {}: {}",
            aisw.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("{} list --json: {error}", aisw.display()))?;
    Ok(value
        .pointer("/agy/active")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// The longest answer a consulted client may print, how much of its stderr
/// a failure keeps, and how much stderr is read at all.
const ANSWER_LIMIT: usize = 4 << 20;
const STDERR_TAIL: usize = 300;
const STDERR_LIMIT: usize = 64 << 10;

/// Runs one official client to completion, feeding it the prompt when
/// given, inside the declared timeout. Stdin is otherwise null so an
/// authentication wait fails fast instead of hanging.
fn run_bounded(
    mut command: Command,
    prompt: Option<String>,
    timeout: Duration,
    client: &str,
) -> Result<Value, String> {
    let output = odin_process::run_bounded(
        &mut command,
        prompt.map(String::into_bytes),
        odin_process::ChildBounds {
            timeout,
            max_stdout_bytes: ANSWER_LIMIT,
            max_stderr_bytes: STDERR_LIMIT,
        },
    )
    .map_err(|error| format!("could not run {client}: {error}"))?;
    let status = output
        .status
        .ok_or_else(|| format!("{client} exceeded the declared timeout"))?;
    if !status.success() {
        let stderr = output.stderr.as_bytes();
        let tail = String::from_utf8_lossy(&stderr[stderr.len().saturating_sub(STDERR_TAIL)..]);
        return Err(match tail.trim() {
            "" => format!("{client} exited {status}"),
            tail => format!("{client} exited {status}: {tail}"),
        });
    }
    if output.stdout.truncated() {
        return Err(format!(
            "{client} exceeded the {ANSWER_LIMIT} byte answer bound"
        ));
    }
    serde_json::from_slice(output.stdout.as_bytes())
        .map_err(|error| format!("{client} answered without JSON: {error}"))
}

#[cfg(test)]
#[path = "consult_official_tests.rs"]
mod tests;
