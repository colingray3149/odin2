//! The fixed config-free Git, Nix and SSH steps of coding operations and
//! permitless lifecycles, each run as a registered worker of the session pool.
use std::path::Path;
use std::time::{Duration, Instant};

use odin_cli::live_authority::{Capture, Captured, OwnedProgram, OwnedStep};
use odin_domain::Scope;
use odin_kernel::operation::PreparedEffect;

use super::DaemonCodingRoute;

/// How one caller runs a fixed config-free Git step: no global or system
/// config, so hooks, filters or signing settings never apply to these
/// host-side commands.
pub(crate) trait GitRunner {
    /// The completed run with its exact exit status and what `capture` kept
    /// of each stream. An error only when it did not run to completion
    /// (refused, cancelled, expired, unstopped) or a `Complete` stream
    /// outgrew the capture bound.
    fn run_git_captured(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
        remote: bool,
        capture: Capture,
    ) -> Result<Captured, String>;

    /// The completed run with its whole output and exact exit status.
    fn run_git(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
        remote: bool,
    ) -> Result<std::process::Output, String> {
        self.run_git_captured(directory, args, identity, remote, Capture::default())
            .map(|captured| captured.output)
    }

    /// Stdout of a successful run; any other exit is an error naming it.
    fn git(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
    ) -> Result<String, String> {
        succeeded(args, self.run_git(directory, args, identity, false)?)
    }

    /// Git that talks to a project's remote (GitHub) over the authoring
    /// transport: bounded, batch, no user ssh config.
    fn git_remote(&self, directory: &Path, args: &[&str]) -> Result<String, String> {
        succeeded(args, self.run_git(directory, args, None, true)?)
    }

    /// Whether a predicate command (`merge-base --is-ancestor`, `diff
    /// --quiet`) holds. Only its real exit 1 is `false`; any other exit, a
    /// cancellation or an expiry is an error.
    fn git_holds(&self, directory: &Path, args: &[&str]) -> Result<bool, String> {
        let output = self.run_git(directory, args, None, false)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => succeeded(args, output).map(|_| true),
        }
    }
}

fn succeeded(args: &[&str], output: std::process::Output) -> Result<String, String> {
    if !output.status.success() {
        // The exit status names a child killed mid-call (odind shutdown or
        // reload: "signal: 15 (SIGTERM)") when git itself printed nothing.
        return Err(format!(
            "git {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The fixed environment of one Git step: config-free and prompt-free, the
/// daemon's own lookup and transport (`PATH`, `HOME`, `SSH_AUTH_SOCK`) so
/// ssh, merge drivers and hooks resolve as they always have, the authoring
/// ssh transport for a remote, and a commit identity when one is named.
fn git_environment(identity: Option<&str>, remote: bool) -> Vec<(String, String)> {
    let mut environment: Vec<(String, String)> = [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect();
    for key in ["PATH", "HOME", "SSH_AUTH_SOCK"] {
        if let Ok(value) = std::env::var(key) {
            environment.push((key.to_owned(), value));
        }
    }
    if remote {
        environment.push((
            "GIT_SSH_COMMAND".to_owned(),
            crate::workload_authoring::GIT_SSH.to_owned(),
        ));
    }
    if let Some(name) = identity {
        for key in ["GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"] {
            environment.push((key.to_owned(), format!("{name} via Odin")));
        }
        for key in ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"] {
            environment.push((key.to_owned(), "odin@localhost".to_owned()));
        }
    }
    environment
}

/// Git run directly, for unit tests below the pool that owns every
/// production step: admitted operations run [`Owned`], permitless lifecycles
/// [`Lifecycle`].
#[cfg(test)]
pub(crate) struct Unowned;

#[cfg(test)]
impl GitRunner for Unowned {
    fn run_git_captured(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
        remote: bool,
        _: Capture,
    ) -> Result<Captured, String> {
        std::process::Command::new(super::program("git"))
            .arg("-C")
            .arg(directory)
            .args(args)
            .envs(git_environment(identity, remote))
            .output()
            .map(|output| Captured {
                output,
                stdout_cut: false,
                stderr_cut: false,
            })
            .map_err(|error| format!("could not run git: {error}"))
    }
}

/// The daemon's own lookup, identity and agent an `ssh` step runs with, as
/// the registered Claude host transport does.
const SSH_ENVIRONMENT: [&str; 7] = [
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "SSH_AUTH_SOCK",
];

/// Fixed Git/SSH steps without an admitted permit use the pool's registered
/// lifecycle workers. One deadline and cancellation cover every step; a closed
/// pool or expired lifecycle launches nothing and waits for running work to stop.
pub(crate) struct Lifecycle<'a> {
    /// Absent on a host without a session pool: then every step refuses.
    pool: Option<&'a odin_cli::live_authority::SessionAuthorityPool>,
    cancel: &'a std::sync::atomic::AtomicBool,
    deadline: Instant,
}

impl<'a> Lifecycle<'a> {
    pub(crate) fn new(
        pool: Option<&'a odin_cli::live_authority::SessionAuthorityPool>,
        cancel: &'a std::sync::atomic::AtomicBool,
        bound: Duration,
    ) -> Self {
        Self {
            pool,
            cancel,
            deadline: Instant::now() + bound,
        }
    }

    fn run(&self, step: OwnedStep<'_>) -> Result<Captured, String> {
        self.pool
            .ok_or("this lifecycle has no session pool to own its workers")?
            .run_lifecycle_step(step, self.cancel, self.deadline)
    }

    /// One `ssh` run of the registered client with `args`, from
    /// `directory`: its complete output and real exit status.
    pub(crate) fn ssh(
        &self,
        directory: &Path,
        args: Vec<String>,
    ) -> Result<std::process::Output, String> {
        let environment = SSH_ENVIRONMENT
            .iter()
            .filter_map(|key| {
                std::env::var(key)
                    .ok()
                    .map(|value| ((*key).to_owned(), value))
            })
            .collect();
        self.run(OwnedStep {
            program: OwnedProgram::Ssh,
            args,
            environment,
            current_dir: directory,
            capture: Capture::default(),
        })
        .map(|captured| captured.output)
    }
}

impl GitRunner for Lifecycle<'_> {
    fn run_git_captured(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
        remote: bool,
        capture: Capture,
    ) -> Result<Captured, String> {
        let mut argv = vec!["-C".to_owned(), directory.display().to_string()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        self.run(OwnedStep {
            program: OwnedProgram::Git,
            args: argv,
            environment: git_environment(identity, remote),
            current_dir: directory,
            capture,
        })
    }
}

/// Registered Git/Nix workers share a deadline no later than the permit's;
/// a cancelled or expired permit launches no further steps.
pub(crate) struct Owned<'a> {
    /// Absent on a host without a session pool: then every step refuses.
    pool: Option<&'a odin_cli::live_authority::SessionAuthorityPool>,
    effect: &'a PreparedEffect,
    scope: &'a Scope,
    deadline: Instant,
}

impl<'a> Owned<'a> {
    pub(super) fn new(
        route: &'a DaemonCodingRoute,
        effect: &'a PreparedEffect,
        scope: &'a Scope,
        bound: Duration,
    ) -> Result<Self, String> {
        let pool = route.session_pool.as_deref();
        let deadline = odin_cli::live_authority::permit_deadline(effect, Instant::now() + bound)?;
        Ok(Self {
            pool,
            effect,
            scope,
            deadline,
        })
    }

    pub(super) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    pub(super) fn cancelled(&self) -> bool {
        self.effect.stop_handle().is_cancelled()
    }

    fn run(
        &self,
        program: OwnedProgram,
        directory: &Path,
        args: Vec<String>,
        environment: Vec<(String, String)>,
        capture: Capture,
    ) -> Result<Captured, String> {
        let step = OwnedStep {
            program,
            args,
            environment,
            current_dir: directory,
            capture,
        };
        self.pool
            .ok_or("this operation has no session owner")?
            .run_owned_step(self.effect, self.scope, step, self.deadline)
    }

    /// One fixed Nix run in `directory` (its own private fetcher cache), its
    /// whole output captured.
    pub(super) fn nix(
        &self,
        directory: &Path,
        args: Vec<String>,
    ) -> Result<std::process::Output, String> {
        self.nix_captured(directory, args, Capture::default())
            .map(|captured| captured.output)
    }

    /// One fixed Nix run whose text diagnostics keep what `capture` says.
    pub(super) fn nix_captured(
        &self,
        directory: &Path,
        args: Vec<String>,
        capture: Capture,
    ) -> Result<Captured, String> {
        self.run(OwnedProgram::Nix, directory, args, Vec::new(), capture)
    }
}

impl GitRunner for Owned<'_> {
    fn run_git_captured(
        &self,
        directory: &Path,
        args: &[&str],
        identity: Option<&str>,
        remote: bool,
        capture: Capture,
    ) -> Result<Captured, String> {
        let mut argv = vec!["-C".to_owned(), directory.display().to_string()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        let environment = git_environment(identity, remote);
        self.run(OwnedProgram::Git, directory, argv, environment, capture)
    }
}
