//! Session capsules: where a session's authority directory lives, its
//! deletion when the session ends, and the bounded git helpers. Every git
//! invocation runs config-free (hooks and the fsmonitor daemon disabled)
//! with a hard deadline that kills and reaps the child's whole process
//! group, so a stuck repository never leaves a background writer behind.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

#[cfg(test)]
use std::sync::Mutex;

use odin_domain::huginn::LiveSessionId;

/// Where a session's host-side directories live: its capsule beneath the
/// state root and its harness launch directories beneath the Huginn root.
#[derive(Clone, Debug)]
pub struct SessionRoots {
    pub state_root: PathBuf,
    pub huginn_root: PathBuf,
}

/// The directory beneath the Huginn root that holds every launch's private
/// working directory, `harness/<session>/<launch>`.
pub const HARNESS_DIR: &str = "harness";

/// The beneath-the-state-root directory that holds every session's authority directory, and the
/// name prefix that marks one.
const AUTHORITIES_DIR: &str = "session-authorities";
const CAPSULE_DIR_PREFIX: &str = "capsule-capsule-";

/// The authority directory of one session beneath the state root.
pub fn capsule_authority(state_root: &Path, session: &str) -> PathBuf {
    state_root
        .join(AUTHORITIES_DIR)
        .join(format!("{CAPSULE_DIR_PREFIX}{}", session.replace(':', "-")))
}

/// Deletes one session's capsule, harness launch directories and injected
/// context trace, keeping nothing: the branches it pushed and its transcripts
/// are the durable result. A missing directory is not an error. Returns
/// whether everything is gone; each failure is logged with its path.
pub fn remove_capsule(roots: &SessionRoots, session: LiveSessionId) -> bool {
    let mut clean = true;
    let paths = [
        capsule_authority(&roots.state_root, &session.to_string()),
        roots
            .huginn_root
            .join(HARNESS_DIR)
            .join(session.to_string()),
    ];
    for path in paths {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => tracing::info!(
                "session dir removed session={session} path={}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                clean = false;
                tracing::error!(
                    "session dir not removed session={session} path={}: {error}",
                    path.display()
                );
            }
        }
    }
    if let Err(error) = crate::live::context_trace::remove(
        &crate::live::context_trace::root(&roots.state_root),
        session,
    ) {
        clean = false;
        tracing::error!("injected context not removed session={session}: {error}");
    }
    clean
}

/// The sessions that have a capsule or harness directory under `roots`.
pub fn capsule_sessions(roots: &SessionRoots) -> Result<Vec<LiveSessionId>, String> {
    let listings = [
        (roots.state_root.join(AUTHORITIES_DIR), CAPSULE_DIR_PREFIX),
        (roots.huginn_root.join(HARNESS_DIR), ""),
    ];
    let mut sessions = std::collections::BTreeSet::new();
    for (root, prefix) in listings {
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("could not list {}: {error}", root.display())),
        };
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("could not list {}: {error}", root.display()))?;
            if let Some(session) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix(prefix))
                .and_then(|id| LiveSessionId::parse(id).ok())
            {
                sessions.insert(session);
            }
        }
    }
    Ok(sessions.into_iter().collect())
}

/// Hard per-stream output ceiling. A stream that grows past it is drained
/// and discarded and the call fails conservatively, so neither a huge
/// repository nor a hostile child can grow the reclaimer's memory.
const GIT_OUTPUT_LIMIT: usize = 8 * 1024 * 1024;

#[cfg(test)]
static TEST_GIT_PROGRAM: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Config-free git in `directory` under `bound`: stdout on success, the
/// trimmed stderr on failure.
pub fn bounded_git_in(directory: &Path, args: &[&str], bound: Duration) -> Result<String, String> {
    git_bound(Some(directory), args, bound).and_then(|outcome| outcome.into_result())
}

/// One finished bounded git invocation: the exit status plus both
/// captured streams. The String helpers translate it through
/// [`GitOutcome::into_result`]; exit-code-sensitive callers read the
/// status directly.
#[derive(Debug)]
struct GitOutcome {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl GitOutcome {
    /// The bounded helpers' contract: stdout on success, trimmed stderr
    /// on failure.
    fn into_result(self) -> Result<String, String> {
        if self.status.success() {
            return Ok(self.stdout);
        }
        Err(self.stderr.trim().to_owned())
    }
}

/// Runs one git invocation under `bound`. A `directory` of `None` runs
/// against the process working directory.
fn git_bound(
    directory: Option<&Path>,
    args: &[&str],
    bound: Duration,
) -> Result<GitOutcome, String> {
    let subcommand = args.first().unwrap_or(&"");
    let output = odin_process::run_bounded(
        &mut hardened_git(directory, args),
        None,
        odin_process::ChildBounds {
            timeout: bound,
            max_stdout_bytes: GIT_OUTPUT_LIMIT,
            max_stderr_bytes: GIT_OUTPUT_LIMIT,
        },
    )
    .map_err(|error| format!("git {subcommand}: {error}"))?;
    let status = output.status.ok_or_else(|| {
        format!(
            "git {subcommand} exceeded its {}s bound and was killed",
            bound.as_secs()
        )
    })?;
    if output.stdout.truncated() || output.stderr.truncated() {
        return Err(format!(
            "git {subcommand} output exceeded its {GIT_OUTPUT_LIMIT} byte cap"
        ));
    }
    Ok(GitOutcome {
        status,
        stdout: output.stdout_text(),
        stderr: output.stderr_text(),
    })
}

/// One hardened git spawn: config beyond the repository's own is
/// silenced, hooks point at a guaranteed-empty directory, and the
/// fsmonitor daemon is off. The bounded runner closes stdin and makes the
/// child lead its own process group, so the deadline kills the entire tree.
fn hardened_git(directory: Option<&Path>, args: &[&str]) -> Command {
    let mut command = Command::new(git_program());
    if let Some(directory) = directory {
        command.arg("-C").arg(directory);
    }
    command
        // Scalar overrides the repository-local config cannot win: hooks
        // resolve against a directory that cannot hold any (`/dev/null` is
        // not a directory), and the fsmonitor daemon and hook are off.
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        // Same transport as authoring pushes: odind's service sandbox shows the
        // Home Manager ~/.ssh/config as foreign-owned and ssh refuses it, so
        // remote reads (repo-watch ls-remote) ignore the user ssh config.
        .env("GIT_SSH_COMMAND", super::harness::git_ssh_command())
        // The audits stay read-only on the tree: no opportunistic index
        // refresh, nothing that takes a lock.
        .env("GIT_OPTIONAL_LOCKS", "0");
    command
}

fn git_program() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(program) = TEST_GIT_PROGRAM.lock().expect("test git lock").clone() {
            return program;
        }
    }
    let system = Path::new("/run/current-system/sw/bin").join("git");
    if system.exists() {
        system
    } else {
        PathBuf::from("git")
    }
}

/// Test seam for the kill path: points every later bounded git spawn at a
/// fixture program, or back at the real lookup with `None`. The static is
/// compile-gated to test builds, so production never consults it.
#[cfg(test)]
fn set_git_program_for_tests(program: Option<PathBuf>) {
    *TEST_GIT_PROGRAM.lock().expect("test git lock") = program;
}

#[cfg(test)]
#[path = "capsule_git_tests.rs"]
mod tests;
