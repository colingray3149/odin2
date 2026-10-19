//! A failed transport reply may still have updated the remote ref. Readback
//! uses the caller's GitRunner; cancellation prevents readback and leaves
//! the publication outcome uncertain.
use std::path::Path;

use odin_hermes::runtime::coding::ProposalFailure;
use serde_json::{json, Value};

use super::claims::{Claim, Pending};
use super::{stage_change_locked, staging, Capsule, GitRunner};

pub(crate) struct PublicationOutcome {
    pub(crate) report: Value,
    pub(crate) uncertain: bool,
    /// Every configured destination already held the captured commit.
    pub(crate) unchanged: bool,
}

struct RefPublication {
    pushed: bool,
    uncertain: bool,
    reconciled: bool,
    unchanged: bool,
    reason: Option<String>,
}

pub(crate) fn full_commit(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64) && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Capture the actual push destination, not the possibly different fetch
/// URL. A missing remote is distinct from unreadable or ambiguous configuration.
pub(crate) fn destination(
    runner: &dyn GitRunner,
    project: &Path,
) -> Result<Option<String>, String> {
    let urls = ["remote", "get-url", "--push", "--all", "origin"];
    match runner.git(project, &urls, None) {
        Ok(urls) => {
            let mut urls = urls.lines();
            match (urls.next(), urls.next()) {
                (Some(url), None) if !url.is_empty() => Ok(Some(url.to_owned())),
                _ => Err("publication requires one exact origin push destination".to_owned()),
            }
        }
        Err(error) => {
            let remotes = runner.git(project, &["remote"], None)?;
            if remotes.lines().any(|remote| remote == "origin") {
                Err(error)
            } else {
                Ok(None)
            }
        }
    }
}

pub(super) fn ref_head(
    runner: &dyn GitRunner,
    project: &Path,
    target: &str,
    reference: &str,
) -> Result<Option<String>, String> {
    let output = runner.git_remote(project, &["ls-remote", "--heads", "--", target, reference])?;
    parse_ref_head(&output, reference).map(|commit| commit.map(str::to_owned))
}

pub(crate) fn parse_ref_head<'a>(
    output: &'a str,
    reference: &str,
) -> Result<Option<&'a str>, String> {
    let mut lines = output.lines();
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    let (commit, observed_ref) = line
        .split_once('\t')
        .ok_or_else(|| "publication ref readback is malformed".to_owned())?;
    if observed_ref != reference || !full_commit(commit) || lines.next().is_some() {
        return Err("publication ref readback does not name one exact ref".to_owned());
    }
    Ok(Some(commit))
}

fn push_exact(
    runner: &dyn GitRunner,
    project: &Path,
    target: &str,
    branch: &str,
    commit: &str,
) -> Result<RefPublication, String> {
    if !full_commit(commit) {
        return Err("publication requires a full commit identity".to_owned());
    }
    let reference = format!("refs/heads/{branch}");
    if ref_head(runner, project, target, &reference)?.as_deref() == Some(commit) {
        return Ok(RefPublication {
            pushed: true,
            uncertain: false,
            reconciled: true,
            unchanged: true,
            reason: None,
        });
    }
    let refspec = format!("{commit}:{reference}");
    let pushed = runner.git_remote(project, &["push", "--quiet", "--", target, &refspec]);
    match ref_head(runner, project, target, &reference) {
        Ok(Some(observed)) if observed == commit => Ok(RefPublication {
            pushed: true,
            uncertain: false,
            reconciled: pushed.is_err(),
            unchanged: false,
            reason: None,
        }),
        Ok(observed) => Ok(RefPublication {
            pushed: false,
            uncertain: false,
            reconciled: false,
            unchanged: false,
            reason: Some(format!(
                "publication ref is {observed:?}, not captured commit {commit}; push={pushed:?}"
            )),
        }),
        Err(error) => Ok(RefPublication {
            pushed: false,
            uncertain: true,
            reconciled: false,
            unchanged: false,
            reason: Some(format!(
                "publication outcome is unproved after push: {error}; push={pushed:?}"
            )),
        }),
    }
}

pub(crate) fn publish_destination(
    runner: &dyn GitRunner,
    project: &Path,
    branch: &str,
    commit: &str,
    target: Option<&str>,
) -> PublicationOutcome {
    let Some(target) = target else {
        return PublicationOutcome {
            report: json!({"pushed":false,"uncertain":false,"reason":"the project has no remote"}),
            uncertain: false,
            unchanged: true,
        };
    };
    match push_exact(runner, project, target, branch, commit) {
        Ok(outcome) => PublicationOutcome {
            report: json!({
                "pushed":outcome.pushed,"uncertain":outcome.uncertain,
                "reconciled":outcome.reconciled,"url":target,"reason":outcome.reason,
            }),
            uncertain: outcome.uncertain,
            unchanged: outcome.unchanged,
        },
        // A retry can arrive after an earlier push lost its reply. An
        // unreadable ref cannot turn that uncertainty into known failure.
        Err(reason) => PublicationOutcome {
            report: json!({"pushed":false,"uncertain":true,"url":target,"reason":reason}),
            uncertain: true,
            unchanged: false,
        },
    }
}

/// Publish only the captured commit, first into the project and then to the
/// captured origin. Exact readback resolves an interrupted first-leg response too.
pub(crate) fn publish_prepared(
    runner: &dyn GitRunner,
    source: &Path,
    project_root: &Path,
    branch: &str,
    commit: &str,
    changed: bool,
    origin: Option<&str>,
) -> Result<PublicationOutcome, String> {
    let project = project_root
        .to_str()
        .ok_or("the project root is not valid UTF-8")?;
    let local = push_exact(runner, source, project, branch, commit)?;
    let remote = if local.pushed {
        publish_destination(runner, project_root, branch, commit, origin)
    } else {
        PublicationOutcome {
            report: json!({"pushed":false,"uncertain":false,"reason":"project publication was not proved; origin was not attempted"}),
            uncertain: false,
            unchanged: true,
        }
    };
    let files: Vec<String> = if changed {
        runner
            .git(source, &["show", "--name-only", "--format=", commit], None)?
            .lines()
            .take(200)
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    Ok(PublicationOutcome {
        report: json!({
            "branch":branch,"commit":commit,"files":files,"changed":changed,"remote":remote.report,
            "local": {
                "pushed":local.pushed,"uncertain":local.uncertain,
                "reconciled":local.reconciled,"url":project,"reason":local.reason,
            },
        }),
        uncertain: local.uncertain || remote.uncertain,
        unchanged: local.unchanged && remote.unchanged,
    })
}

/// The unreviewed lane keeps its existing commit semantics; post-commit
/// failures are uncertainty, never a claim that nothing changed.
pub(super) fn propose_capsule(
    runner: &dyn GitRunner,
    capsule: &Capsule,
    summary: &str,
    branch: Option<&str>,
    claim: &mut Claim,
) -> Result<Value, ProposalFailure> {
    let requested_branch = branch.unwrap_or(&capsule.branch);
    if matches!(claim.pending(), Some(Pending::Direct { .. })) {
        return publish_claimed(runner, capsule, requested_branch, false, claim);
    }
    if claim.unresolved()? {
        return Err(ProposalFailure::Refused(
            "this ref retains a preparation owned by another publication route".to_owned(),
        ));
    }
    let branch = match branch {
        Some(branch) => {
            let head = runner.git(&capsule.path, &["rev-parse", "HEAD"], None)?;
            guard_seat_branch(runner, &capsule.project_root, branch, &head, &capsule.path)?;
            branch
        }
        None => &capsule.branch,
    };
    let origin = destination(runner, &capsule.project_root)?;
    let staging = staging();
    stage_change_locked(runner, &capsule.path)?;
    // Nothing is committed yet: a failed or cancelled check refuses.
    let changed = !runner.git_holds(&capsule.path, &["diff", "--cached", "--quiet"])?;
    if changed {
        runner
            .git(
                &capsule.path,
                &["commit", "--quiet", "--no-verify", "-m", summary],
                Some(&capsule.seat),
            )
            .map_err(ProposalFailure::Uncertain)?;
    }
    let commit = runner
        .git(&capsule.path, &["rev-parse", "HEAD"], None)
        .map_err(ProposalFailure::Uncertain)?;
    drop(staging);
    claim
        .prepare(Pending::Direct {
            commit,
            origin,
            source: capsule.path.clone(),
        })
        .map_err(ProposalFailure::Uncertain)?;
    publish_claimed(runner, capsule, branch, changed, claim)
}

fn publish_claimed(
    runner: &dyn GitRunner,
    capsule: &Capsule,
    branch: &str,
    changed: bool,
    claim: &mut Claim,
) -> Result<Value, ProposalFailure> {
    let Some(Pending::Direct {
        commit,
        origin,
        source,
    }) = claim.pending()
    else {
        return Err(ProposalFailure::Refused(
            "this pending publication requires its original workspace route".to_owned(),
        ));
    };
    let outcome = publish_prepared(
        runner,
        source,
        &capsule.project_root,
        branch,
        commit,
        changed,
        origin.as_deref(),
    )
    .map_err(ProposalFailure::Uncertain)?;
    if outcome.uncertain {
        return Err(ProposalFailure::Uncertain(format!(
            "commit {commit} is retained; publication is unproved"
        )));
    }
    claim.complete().map_err(ProposalFailure::Uncertain)?;
    Ok(outcome.report)
}

/// A named branch is new, already this head, or an ancestor of it. The
/// subsequent non-force push remains the authority against a racing update.
pub(crate) fn guard_seat_branch(
    runner: &dyn GitRunner,
    project_root: &Path,
    branch: &str,
    head: &str,
    ancestry_repo: &Path,
) -> Result<(), String> {
    let existing = runner.git(
        project_root,
        &[
            "for-each-ref",
            "--format=%(objectname)",
            &format!("refs/heads/{branch}"),
        ],
        None,
    )?;
    let existing = existing.trim();
    if existing.is_empty() || existing == head {
        return Ok(());
    }
    let fetched = runner
        .git(
            ancestry_repo,
            &[
                "fetch",
                "--quiet",
                &project_root.display().to_string(),
                &format!("refs/heads/{branch}"),
            ],
            None,
        )
        .is_ok();
    let behind = fetched
        && runner.git_holds(
            ancestry_repo,
            &["merge-base", "--is-ancestor", existing, head],
        )?;
    if behind || !fetched {
        return Ok(());
    }
    let short: String = existing.chars().take(8).collect();
    Err(format!("branch {branch} already holds other work at {short}: refusing to overwrite it; choose another branch name"))
}

/// A normal non-force push whose advertised old main must be the checked
/// base. Git then atomically verifies that advertised old OID on the server.
/// A pre-push hook checks the expected base without granting force-push permission.
/// Cancellation or timeout prevents readback; retain the merge so a fresh admitted
/// retry can inspect the remote.
pub(super) fn push_merged(
    runner: &dyn GitRunner,
    worktree: &Path,
    target: &str,
    base: &str,
    commit: &str,
) -> Result<(), ProposalFailure> {
    use std::os::unix::fs::PermissionsExt;
    if !full_commit(base) || !full_commit(commit) {
        return Err("merge publication requires full commit identities"
            .to_owned()
            .into());
    }
    runner.git(
        worktree,
        &["merge-base", "--is-ancestor", base, commit],
        None,
    )?;
    let original_hook = worktree.join(runner.git(
        worktree,
        &["rev-parse", "--git-path", "hooks/pre-push"],
        None,
    )?);
    let quote = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
    let original_hook = quote(
        original_hook
            .to_str()
            .ok_or_else(|| "the configured pre-push hook path is not UTF-8".to_owned())?,
    );
    let original_parameters = match std::env::var("GIT_CONFIG_PARAMETERS") {
        Ok(parameters) => format!("export GIT_CONFIG_PARAMETERS={}", quote(&parameters)),
        Err(std::env::VarError::NotPresent) => "unset GIT_CONFIG_PARAMETERS".to_owned(),
        Err(error) => return Err(error.to_string().into()),
    };
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let hooks = worktree.join(format!(".odin-merge-push-{nonce}"));
    std::fs::create_dir(&hooks).map_err(|error| error.to_string())?;
    let hook = hooks.join("pre-push");
    std::fs::write(&hook, format!(
        "#!/bin/sh\n\
         read -r local_ref local_oid remote_ref remote_oid || exit 1\n\
         [ \"$local_oid\" = '{commit}' ] && [ \"$remote_ref\" = 'refs/heads/main' ] && \
         [ \"$remote_oid\" = '{base}' ] || {{ : > \"$0.refused\"; echo 'main changed since the checked base' >&2; exit 1; }}\n\
         if read -r extra; then : > \"$0.refused\"; exit 1; fi\n\
         if [ -x {original_hook} ]; then\n\
           {original_parameters}\n\
           printf '%s %s %s %s\\n' \"$local_ref\" \"$local_oid\" \"$remote_ref\" \"$remote_oid\" | {original_hook} origin \"$2\"\n\
         fi\n"
    )).map_err(|error| error.to_string())?;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())?;
    let retained = format!("refs/odin/merge-publications/{nonce}");
    runner.git(worktree, &["update-ref", &retained, commit, ""], None)?;
    let pushed = runner.git_remote(
        worktree,
        &[
            "-c",
            &format!("core.hooksPath={}", hooks.display()),
            "push",
            "--quiet",
            "--",
            target,
            &format!("{commit}:refs/heads/main"),
        ],
    );
    match ref_head(runner, worktree, target, "refs/heads/main") {
        Ok(Some(observed)) if observed == commit => {
            if let Err(error) = runner.git(
                worktree,
                &["update-ref", "-d", &retained, commit],
                None,
            ) {
                tracing::warn!("merge retention remains ref={retained} commit={commit} error={error}");
            }
            Ok(())
        }
        observed if hook.with_extension("refused").is_file() => Err(ProposalFailure::Refused(format!(
            "push refused before dispatch because its advertised base changed; checked merge {commit} retained at {retained}; main={observed:?}"
        ))),
        observed => Err(ProposalFailure::Uncertain(format!(
            "publication of checked merge {commit} is unproved; retained at {retained}; main={observed:?}; push={pushed:?}"
        ))),
    }
}
