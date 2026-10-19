//! Distinguish kernel-governed tools from external agents that Odin can only observe and stop.

use serde::{Deserialize, Serialize};

use super::object::RegistryKind;

pub const HARNESS_MAX_ARGS: usize = 32;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessToml {
    pub schema: String,
    pub kind: RegistryKind,
    pub enabled: bool,
    pub description: String,
    pub protocol: HarnessProtocol,
    pub governance: HarnessGovernance,
    /// Absent for omp's pinned launcher and observe, which launches nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    pub prompt: HarnessPrompt,
    pub output: HarnessOutput,
    /// Without a model flag, reject model selection and use the agent default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_arg: Option<String>,
    /// Process and terminal agents receive the MCP config flag; ACP receives the bridge in session/new.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_config_arg: Option<String>,
    /// Substitute the reported agent_session ID; absence starts a new conversation per prompt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resume_args: Vec<String>,
    /// Home-relative writable state paths; confinement leaves other home paths read-only or hidden.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state_paths: Vec<String>,
    /// Resolve account at launch from option, project, then default; claude-code accounts require the workload driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<super::AccountKind>,
    /// Explain hand-back and available tools before the first prompt; omp uses its extension brief.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brief: Option<String>,
    /// Expand home, account, and workspace_slug in transcript paths; command also expands home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcripts: Option<String>,
    /// Pod admission requires script or an enabled harness with this permission.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pod: bool,
    pub stop: HarnessStopToml,
}

pub const HARNESS_MAX_BRIEF_BYTES: usize = 2048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HarnessProtocol {
    Omp,
    Acp,
    /// Start one process per prompt and decode output line by line.
    Process,
    /// Keep the terminal agent for the session, typing prompts and following its transcript.
    Terminal,
    /// Observe existing sessions without launching an agent.
    Observe,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HarnessGovernance {
    /// Every tool call passes the kernel (grants, approvals, ledger).
    Governed,
    /// Observe and stop unmediated tools; only the environment provides confinement.
    Observed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HarnessPrompt {
    Argv,
    /// Close stdin after writing the prompt.
    Stdin,
    Rpc,
    Keys,
    /// Observation-only harnesses cannot receive prompts.
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessOutput {
    OmpRpc,
    Acp,
    ClaudeStreamJson,
    CodexJson,
    /// Treat every plain-text line as assistant output.
    Text,
    /// Use the remote environment's declared output format.
    Environment,
}

impl HarnessOutput {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OmpRpc => "omp-rpc",
            Self::Acp => "acp",
            Self::ClaudeStreamJson => "claude-stream-json",
            Self::CodexJson => "codex-json",
            Self::Text => "text",
            Self::Environment => "environment",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessStopToml {
    /// First stop signal: SIGTERM or SIGINT.
    pub signal: String,
    pub grace_seconds: u16,
}

impl HarnessToml {
    pub fn check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        // Admit Claude Code accounts only through the workload driver, not executable-name filtering.
        if self.account == Some(super::AccountKind::ClaudeCode) {
            problems.push(
                "a harness cannot sign in with a claude-code account: Claude Code is driven \
                 only by the claude.* workload driver (claude.open/prompt/read/stop)"
                    .to_owned(),
            );
        }
        if let Some(flag) = &self.mcp_config_arg {
            if !matches!(
                self.protocol,
                HarnessProtocol::Process | HarnessProtocol::Terminal
            ) {
                problems.push(
                    "mcp_config_arg is for a process or terminal harness (an acp agent gets \
                     the bridge in session/new)"
                        .to_owned(),
                );
            }
            if !flag.starts_with("--") || flag.contains(char::is_whitespace) {
                problems
                    .push("mcp_config_arg is one long flag such as \"--mcp-config\"".to_owned());
            }
        }
        match self.protocol {
            HarnessProtocol::Observe => {
                if self.prompt != HarnessPrompt::None
                    || self.output != HarnessOutput::Environment
                    || self.governance != HarnessGovernance::Observed
                {
                    problems.push("an observe harness takes prompt = \"none\", output = \"environment\", governance = \"observed\"".to_owned());
                }
                if !self.command.is_empty()
                    || self.model_arg.is_some()
                    || self.account.is_some()
                    || !self.resume_args.is_empty()
                    || !self.state_paths.is_empty()
                    || self.brief.is_some()
                {
                    problems.push("an observe harness declares no command, model_arg, account, resume_args, state_paths or brief".to_owned());
                }
            }
            HarnessProtocol::Omp => {
                if !self.command.is_empty() {
                    problems.push(
                        "an omp harness runs the manifest-pinned OMP and declares no command"
                            .to_owned(),
                    );
                }
                if self.prompt != HarnessPrompt::Rpc || self.output != HarnessOutput::OmpRpc {
                    problems.push(
                        "an omp harness takes prompt = \"rpc\", output = \"omp-rpc\"".to_owned(),
                    );
                }
                if self.governance != HarnessGovernance::Governed {
                    problems
                        .push("an omp harness is governed (its tools pass the kernel)".to_owned());
                }
            }
            HarnessProtocol::Acp => {
                if self.prompt != HarnessPrompt::Rpc || self.output != HarnessOutput::Acp {
                    problems
                        .push("an acp harness takes prompt = \"rpc\", output = \"acp\"".to_owned());
                }
            }
            HarnessProtocol::Terminal => {
                if self.prompt != HarnessPrompt::Keys
                    || matches!(self.output, HarnessOutput::OmpRpc | HarnessOutput::Acp)
                {
                    problems.push(
                        "a terminal harness takes prompt = \"keys\" and the line output family \
                         of its transcript files"
                            .to_owned(),
                    );
                }
                if self.governance != HarnessGovernance::Observed {
                    problems.push(
                        "a terminal harness is observed: Odin types into the agent, it cannot \
                         mediate the agent's own tools"
                            .to_owned(),
                    );
                }
                if !self.transcripts.as_deref().is_some_and(|path| {
                    (path.starts_with("{home}/")
                        || (path.starts_with("{account}/") && self.account.is_some()))
                        && !path.contains("..")
                }) {
                    problems.push(
                        "a terminal harness declares transcripts = \"{home}/…\" or, with an \
                         account, \"{account}/…\" (no '..')"
                            .to_owned(),
                    );
                }
            }
            HarnessProtocol::Process => {
                if self.prompt == HarnessPrompt::Rpc
                    || self.prompt == HarnessPrompt::Keys
                    || matches!(self.output, HarnessOutput::OmpRpc | HarnessOutput::Acp)
                {
                    problems.push(
                        "a process harness takes prompt = \"argv\" or \"stdin\" and a line \
                         output family (claude-stream-json, codex-json, text)"
                            .to_owned(),
                    );
                }
                // External CLI tools bypass the kernel, so they cannot claim kernel governance.
                if self.governance != HarnessGovernance::Observed {
                    problems.push(
                        "a process harness is observed: Odin cannot mediate a CLI agent's own \
                         tools"
                            .to_owned(),
                    );
                }
            }
        }
        if self.protocol != HarnessProtocol::Observe
            && (self.prompt == HarnessPrompt::None || self.output == HarnessOutput::Environment)
        {
            problems.push(
                "only an observe harness takes prompt = none or output = environment".to_owned(),
            );
        }
        if !matches!(
            self.protocol,
            HarnessProtocol::Omp | HarnessProtocol::Observe
        ) {
            if self.command.is_empty() || self.command.len() > HARNESS_MAX_ARGS {
                problems.push(format!(
                    "command must name the program and at most {} arguments",
                    HARNESS_MAX_ARGS - 1
                ));
            }
            if self
                .command
                .iter()
                .chain(&self.resume_args)
                .any(|argument| argument.is_empty() || argument.contains('\0'))
            {
                problems.push("arguments must be non-empty and free of NUL".to_owned());
            }
        }
        if !self.resume_args.is_empty()
            && !self
                .resume_args
                .iter()
                .any(|argument| argument.contains("{agent_session}"))
        {
            problems.push("resume_args must carry {agent_session}".to_owned());
        }
        if self
            .model_arg
            .as_deref()
            .is_some_and(|flag| !flag.starts_with('-'))
        {
            problems.push("model_arg must be a flag such as --model".to_owned());
        }
        for path in &self.state_paths {
            if path.is_empty() || path.starts_with('/') || path.split('/').any(|part| part == "..")
            {
                problems.push(format!(
                    "state path {path:?} must be relative to $HOME without '..'"
                ));
            }
        }
        if let Some(brief) = &self.brief {
            if self.protocol == HarnessProtocol::Omp {
                problems.push(
                    "an omp harness takes its brief from the extension, not brief".to_owned(),
                );
            }
            if brief.trim().is_empty() || brief.len() > HARNESS_MAX_BRIEF_BYTES {
                problems.push(format!(
                    "brief must hold 1 to {HARNESS_MAX_BRIEF_BYTES} bytes of text"
                ));
            }
        }
        if self.transcripts.is_some() && self.protocol != HarnessProtocol::Terminal {
            problems.push("only a terminal harness declares transcripts".to_owned());
        }
        if !matches!(self.stop.signal.as_str(), "SIGTERM" | "SIGINT" | "SIGHUP") {
            problems.push("stop.signal must be SIGTERM, SIGINT or SIGHUP".to_owned());
        }
        if self.stop.grace_seconds == 0 || self.stop.grace_seconds > 300 {
            problems.push("stop.grace_seconds must be 1..=300".to_owned());
        }
        problems
    }
}
