//! Shared `#[cfg(test)]` fixture helpers for the Odin CLI test suites.

use std::path::Path;

/// The identity every fixture commit carries.
const TEST_NAME: &str = "Odin Test";
const TEST_EMAIL: &str = "odin-test@example.invalid";

/// Runs `git` inside `worktree`, ignoring host config, and returns trimmed stdout.
/// Commits made through it carry the Odin test identity.
///
/// Panics when `git` cannot be spawned or exits nonzero, naming the failed
/// argument list and the captured standard error.
pub(crate) fn git(worktree: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", TEST_NAME)
        .env("GIT_AUTHOR_EMAIL", TEST_EMAIL)
        .env("GIT_COMMITTER_NAME", TEST_NAME)
        .env("GIT_COMMITTER_EMAIL", TEST_EMAIL)
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output is UTF-8")
        .trim_end()
        .to_owned()
}

/// Stages every change in `worktree`, creates a fixture commit as the Odin
/// test identity with signing disabled, and returns the new HEAD hash.
pub(crate) fn commit_all(worktree: &Path, message: &str) -> String {
    git(worktree, &["add", "-A"]);
    git(
        worktree,
        &["-c", "commit.gpgsign=false", "commit", "-m", message],
    );
    git(worktree, &["rev-parse", "HEAD"])
}
