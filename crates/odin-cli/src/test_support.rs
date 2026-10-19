//! Shared `#[cfg(test)]` fixture helpers for the Odin CLI test suites.

use std::path::Path;

/// Runs `git` inside `worktree`, ignoring host config, and returns trimmed stdout.
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
        &[
            "-c",
            "user.name=Odin Test",
            "-c",
            "user.email=odin-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
    git(worktree, &["rev-parse", "HEAD"])
}
