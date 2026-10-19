//! The authority's runtime authoring worktree: a private linked worktree of
//! the declared Odin repository (`paths.authoring_repository`), so a runtime
//! publication is a real commit on Odin `main`.
//!
//! Each runtime mutation is one ordinary child of fetched `origin/main`.
//! The store projects only that mutation onto the verified active registry;
//! unrelated unpublished content stays on main until deployment. Validation
//! precedes the push, and the push precedes publication. A failed push is
//! fetched and checked before an ambiguous success can be retried.

use std::path::{Path, PathBuf};

use odin_hermes::runtime::WorkloadAuthoringFailure as Failure;

use super::git;

/// `-F none` avoids sandbox ownership checks on the store-backed SSH config;
/// the default key and known_hosts still apply, with non-interactive transport.
pub(crate) const GIT_SSH: &str = "ssh -F none -o BatchMode=yes -o ConnectTimeout=10";

#[derive(Clone, Debug)]
pub(crate) struct AuthoringSync {
    /// The declared repository the worktree is linked from (its `origin`
    /// is the shared `main` every host and deploy reads).
    pub(crate) repository: PathBuf,
}

impl AuthoringSync {
    /// Creates the linked worktree at `origin/main` when it does not exist.
    pub(crate) fn ensure(&self, worktree: &Path) -> Result<(), Failure> {
        if worktree.join(".git").exists() {
            return Ok(());
        }
        let invalid = |reason: String| Failure::WorktreeInvalid { reason };
        if let Some(parent) = worktree.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| invalid(format!("authoring worktree parent: {error}")))?;
        }
        remote(&self.repository, &["fetch", "--quiet", "origin", "main"]).map_err(invalid)?;
        // A worktree directory removed by hand stays registered until pruned.
        git(&self.repository, &["worktree", "prune"]).map_err(invalid)?;
        let path = worktree
            .to_str()
            .ok_or_else(|| invalid("authoring worktree path is not UTF-8".to_owned()))?;
        git(
            &self.repository,
            &["worktree", "add", "--detach", path, "origin/main"],
        )
        .map(|_| ())
        .map_err(invalid)
    }

    pub(crate) fn fetch(&self, worktree: &Path) -> Result<String, Failure> {
        remote(worktree, &["fetch", "--quiet", "origin", "main"])
            .and_then(|_| git(worktree, &["rev-parse", "origin/main"]))
            .map_err(|reason| Failure::PublicationRefused {
                reason: format!("could not fetch odin main: {reason}"),
            })
    }

    /// Moves the worktree onto `origin` unless HEAD is this publication's own
    /// pending commit (`pending`: the crash-resume scope). Unpushed work for
    /// anything else is discarded: it was never on `main` nor published.
    pub(crate) fn sync(
        &self,
        worktree: &Path,
        anchor: &str,
        origin: &str,
        pending: impl Fn(&Path) -> bool,
    ) -> Result<(), Failure> {
        let refused = |reason: String| Failure::PublicationRefused { reason };
        if !is_ancestor(worktree, anchor, origin) {
            return Err(refused(format!(
                "odin main ({origin}) does not contain the published commit {anchor}; \
                 the next deploy reconciles them"
            )));
        }
        let head = git(worktree, &["rev-parse", "HEAD"]).map_err(refused)?;
        if head == origin
            || (pending(worktree)
                && git(worktree, &["rev-parse", "HEAD^1"]).as_deref() == Ok(origin))
        {
            return Ok(());
        }
        let force = !is_ancestor(worktree, &head, origin);
        let mut args = vec!["checkout", "--quiet", "--detach"];
        if force {
            args.push("--force");
        }
        args.push(origin);
        git(worktree, &args).map(|_| ()).map_err(refused)
    }

    /// Pushes one ordinary mutation. A transport failure may follow a
    /// successful remote update, so confirm reachability before retrying.
    /// Only a confirmed concurrent rejection discards the pending commit.
    pub(crate) fn push(&self, worktree: &Path, commit: &str, origin: &str) -> Result<(), Failure> {
        let refspec = format!("{commit}:refs/heads/main");
        let Err(reason) = remote(worktree, &["push", "--quiet", "origin", &refspec]) else {
            return Ok(());
        };
        let current = self.fetch(worktree)?;
        if is_ancestor(worktree, commit, &current) {
            return Ok(());
        }
        if current != origin {
            git(
                worktree,
                &["checkout", "--quiet", "--detach", "--force", &current],
            )
            .map_err(|reason| Failure::PublicationRefused { reason })?;
        }
        Err(Failure::PublicationRefused {
            reason: format!("could not push odin publication; retry: {reason}"),
        })
    }
}

/// Where a project's repository comes from: Colin's own repositories live
/// beside the declared odin repository's `origin` (same owner, same host).
impl AuthoringSync {
    /// The `origin` URL of the declared repository with its last path
    /// segment replaced by `<name>.git`.
    pub(crate) fn sibling_remote(&self, name: &str) -> Result<String, String> {
        let origin = git(&self.repository, &["remote", "get-url", "origin"])?;
        let cut = origin
            .rfind(['/', ':'])
            .ok_or_else(|| format!("odin's origin {origin:?} has no owner path"))?;
        Ok(format!("{}{name}.git", &origin[..=cut]))
    }

    /// Whether `url` names an existing repository. Only a definite "not
    /// found" answer is absence; any other failure (offline, auth) refuses,
    /// so an unreachable GitHub never yields an empty duplicate.
    pub(crate) fn remote_exists(&self, url: &str) -> Result<bool, String> {
        match remote(&self.repository, &["ls-remote", "--heads", "--", url]) {
            Ok(_) => Ok(true),
            Err(error)
                if error.contains("Repository not found")
                    || error.contains("does not appear to be a git repository") =>
            {
                Ok(false)
            }
            Err(error) => Err(format!(
                "could not check {url} for an existing repository: {error}"
            )),
        }
    }

    pub(crate) fn clone_into(&self, url: &str, into: &Path) -> Result<(), String> {
        let into = into.to_str().ok_or("the project root is not valid UTF-8")?;
        remote(&self.repository, &["clone", "--quiet", "--", url, into]).map(|_| ())
    }
}

fn is_ancestor(worktree: &Path, ancestor: &str, descendant: &str) -> bool {
    git(
        worktree,
        &["merge-base", "--is-ancestor", ancestor, descendant],
    )
    .is_ok()
}

/// A git command that talks to the remote, with the bounded transport.
fn remote(directory: &Path, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .env("GIT_SSH_COMMAND", GIT_SSH)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .map_err(|error| format!("could not spawn git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    /// The authoring transport never reads the user ssh config (see
    /// [`super::GIT_SSH`]): odind's sandbox makes that file unreadable to ssh.
    #[test]
    fn the_authoring_transport_ignores_the_user_ssh_config() {
        let args: Vec<&str> = super::GIT_SSH.split_whitespace().collect();
        assert!(args.windows(2).any(|pair| pair == ["-F", "none"]));
        assert!(args.contains(&"BatchMode=yes"));
    }
}
