use super::*;

const NIX_PROFILES_ROOT: &str = "/nix/var/nix/profiles";
const MAX_SYSTEM_GENERATIONS: usize = 5;

pub(super) fn run_sys_12(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-12", sys_12_body, context, deadline)
}

fn sys_12_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let scratch = command_scratch(context, "SYS-12")?;
    let root = &context.odin_root;
    let store_source = is_store_source(root);

    // A real checkout inventories through git; a store source is a git
    // archive whose file tree is exactly the tracked set, so the same
    // hygiene predicates walk it directly.
    let tracked = if store_source {
        store_source_tracked_paths(root)?
    } else {
        let git = require_tool("git", None)?;
        git_tracked_paths(&git, &scratch, root, deadline)?
    };
    note_evidence(&mut evidence, format!("tracked-files={}", tracked.len()));

    for path in &tracked {
        if let Some(class) = tracked_hygiene_violation(path, root) {
            return Err(CheckFailure::fail(
                "workspace-hygiene-violation",
                format!("tracked path {path:?} violates Git hygiene ({class})"),
            ));
        }
    }

    // The dotfiles checkout gets the same hygiene.
    let dotfiles_tracked = if is_store_source(&context.dotfiles_root) {
        store_source_tracked_paths(&context.dotfiles_root)?
    } else {
        let git = require_tool("git", None)?;
        git_tracked_paths(&git, &scratch, &context.dotfiles_root, deadline)?
    };
    note_evidence(
        &mut evidence,
        format!("dotfiles-tracked-files={}", dotfiles_tracked.len()),
    );
    for path in &dotfiles_tracked {
        if is_log_or_jsonl_path(path) {
            return Err(CheckFailure::fail(
                "tracked-log-or-jsonl",
                format!(
                    "tracked path {path:?} in the dotfiles checkout {} is a log or output capture file",
                    context.dotfiles_root.display()
                ),
            ));
        }
    }

    // The ignore contract governs untracked worktree files. A store source
    // is a git archive with no worktree, so the contract structurally
    // cannot exist there; the skip is recorded, never silent.
    if store_source {
        note_evidence(
            &mut evidence,
            "gitignore-contract=not-applicable (a store source is a git archive with no worktree ignore contract)",
        );
    } else {
        let gitignore_path = root.join(".gitignore");
        let gitignore =
            String::from_utf8_lossy(&read_bounded(&gitignore_path).map_err(|error| {
                CheckFailure::fail(
                    "gitignore-missing",
                    format!(
                        ".gitignore {} is missing or unreadable: {error}",
                        gitignore_path.display()
                    ),
                )
            })?)
            .into_owned();
        let missing_rules = gitignore_missing_rules(&gitignore);
        if !missing_rules.is_empty() {
            return Err(CheckFailure::fail(
                "gitignore-contract-mismatch",
                format!(".gitignore is missing required rules: {:?}", missing_rules),
            ));
        }
    }

    if let Some(path) = find_stray_dotenv(root)
        .map_err(|error| {
            CheckFailure::fail(
                "workspace-walk-unbounded",
                format!("workspace dotenv inventory could not be bounded: {error}"),
            )
        })?
        .into_iter()
        .next()
    {
        return Err(CheckFailure::fail(
            "stray-dotenv",
            format!("an untracked .env file sits in the worktree at {path:?}"),
        ));
    }

    // Deployment and maintenance retain at most five system generations.
    let generations = system_generation_links(Path::new(NIX_PROFILES_ROOT))?;
    note_evidence(
        &mut evidence,
        format!("system-generations={}", generations.len()),
    );
    if let Some(failure) = excess_system_generations(&generations) {
        return Err(failure);
    }

    // A capture entry is leftover exactly when its session's live journal
    // is terminal or holds no such session.
    let state_root = session_state_root()?;
    let capture_root = terminal_capture_root(&state_root);
    let captures = session_capture_entries(&capture_root)?.unwrap_or_default();
    note_evidence(
        &mut evidence,
        format!("session-captures={}", captures.len()),
    );
    let leftover = leftover_captures(&live_journal_root(&state_root), &captures)?;
    if !leftover.is_empty() {
        return Err(CheckFailure::fail(
            "leftover-session-state",
            format!(
                "{} leftover per-session capture {} ({}) beneath {} outlived {}; the session-end cleanup must remove it",
                leftover.len(),
                if leftover.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                leftover
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                capture_root.display(),
                if leftover.len() == 1 {
                    "its session"
                } else {
                    "their sessions"
                },
            ),
        ));
    }
    CheckOutcome::pass(
        if store_source {
            "store-source content inventory, dotenv files, dotfiles logs, system generations, and per-session captures are clean; no worktree ignore contract applies"
        } else {
            "tracked content, ignore rules, result links, and dotenv files are clean; the dotfiles checkout tracks no log or output capture, system generations stay within five, and no per-session capture outlives its session"
        },
        evidence,
    )
}

/// `XDG_STATE_HOME`/odin, defaulting to `~/.local/state/odin`.
fn session_state_root() -> Result<PathBuf, CheckFailure> {
    let state_home = env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        })
        .ok_or_else(|| {
            CheckFailure::blocked(
                "home-unavailable",
                "XDG_STATE_HOME and HOME are both unset; the per-session state root cannot be resolved",
            )
        })?;
    Ok(state_home.join("odin"))
}

fn excess_system_generations(generations: &[String]) -> Option<CheckFailure> {
    if generations.len() <= MAX_SYSTEM_GENERATIONS {
        return None;
    }
    Some(CheckFailure::fail(
        "excess-system-generations",
        format!(
            "{} system generations sit in {} ({}); only {MAX_SYSTEM_GENERATIONS} are kept — retire the oldest with the generation collector",
            generations.len(),
            NIX_PROFILES_ROOT,
            generations.join(", "),
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One disposable store-source-looking root. No `.git` anywhere, so the
    /// inventory must take the bounded walk branch.
    #[test]
    fn store_source_inventory_applies_the_hygiene_predicates() {
        let root = tempfile::tempdir().expect("store fixture root is creatable");
        let path = |relative: &str| root.path().join(relative);
        fs::create_dir_all(path("src")).expect("src dir is creatable");
        fs::create_dir_all(path("config")).expect("config dir is creatable");
        fs::create_dir_all(path("state")).expect("state dir is creatable");
        fs::write(path("src/main.rs"), "fn main() {}\n").expect("source file is writable");
        fs::write(path("state/ledger.sqlite3"), "runtime").expect("state file is writable");
        fs::write(path("config/.env.local"), "KEY=value\n").expect("dotenv file is writable");
        fs::write(path("target-file"), "residue").expect("result target is writable");
        #[cfg(unix)]
        std::os::unix::fs::symlink("target-file", path("result"))
            .expect("result symlink is creatable");

        assert!(
            !is_store_source(root.path()),
            "a root without .git outside /nix/store is a broken checkout, not a store source"
        );
        let tracked = store_source_tracked_paths(root.path())
            .expect("the bounded walk inventories the store source");
        for expected in [
            "src/main.rs",
            "state/ledger.sqlite3",
            "config/.env.local",
            "result",
            "target-file",
        ] {
            assert!(
                tracked.iter().any(|entry| entry == expected),
                "the inventory must contain {expected}: {:?}",
                tracked
            );
        }
        assert_eq!(tracked.len(), 5, "directories are never inventoried");

        let violations: Vec<&str> = tracked
            .iter()
            .filter_map(|entry| tracked_hygiene_violation(entry, root.path()))
            .collect();
        assert_eq!(
            violations.len(),
            3,
            "state content, tracked dotenv, and the result symlink must each violate: {:?}",
            violations
        );
        assert_eq!(tracked_hygiene_violation("src/main.rs", root.path()), None);
        assert_eq!(
            tracked_hygiene_violation("target-file", root.path()),
            None,
            "a file merely named like target is plain content"
        );
    }

    #[test]
    fn tracked_log_or_jsonl_fails_then_passes_when_removed() {
        for violating in ["run.log", "logs/events.jsonl", "docs/TRACE.LOG"] {
            assert_eq!(
                tracked_hygiene_violation(violating, Path::new("/unused")),
                Some("tracked-log-or-jsonl"),
                "{violating} must violate the no-garbage law"
            );
        }
        for clean in ["src/logging.rs", "notes/log.txt", "jsonl", "a.log.bak"] {
            assert_eq!(
                tracked_hygiene_violation(clean, Path::new("/unused")),
                None,
                "{clean} is plain content"
            );
        }

        let root = tempfile::tempdir().expect("fixture root is creatable");
        fs::write(root.path().join("run.log"), "residue\n").expect("log is writable");
        let tracked = store_source_tracked_paths(root.path()).expect("the store walk inventories");
        assert_eq!(
            tracked
                .iter()
                .filter_map(|path| tracked_hygiene_violation(path, root.path()))
                .collect::<Vec<_>>(),
            vec!["tracked-log-or-jsonl"],
            "the tracked log fails before the cleanup"
        );
        fs::remove_file(root.path().join("run.log")).expect("log is removable");
        let tracked = store_source_tracked_paths(root.path()).expect("the store walk inventories");
        assert!(
            tracked
                .iter()
                .all(|path| tracked_hygiene_violation(path, root.path()).is_none()),
            "the inventory passes after the tracked log is removed"
        );
    }

    #[test]
    #[cfg(unix)]
    fn system_generations_fail_above_five_and_pass_at_five() {
        let root = tempfile::tempdir().expect("profile fixture root is creatable");
        let link = |name: &str, target: &str| {
            std::os::unix::fs::symlink(target, root.path().join(name))
                .expect("the generation link is creatable");
        };
        for generation in 5..=9 {
            link(
                &format!("system-{generation}-link"),
                &format!("/nix/store/gen-{generation}"),
            );
        }
        link("system", "/nix/store/gen-9");
        link("profile", "/nix/store/profile");
        fs::create_dir(root.path().join("channels")).expect("foreign dir is creatable");

        let kept = system_generation_links(root.path()).expect("the profile root reads");
        assert_eq!(
            kept,
            [
                "system-5-link",
                "system-6-link",
                "system-7-link",
                "system-8-link",
                "system-9-link",
            ]
            .map(str::to_owned)
        );
        assert!(excess_system_generations(&kept).is_none());

        link("system-10-link", "/nix/store/gen-10");
        let residue = system_generation_links(root.path()).expect("the profile root reads");
        let failure =
            excess_system_generations(&residue).expect("six generations must fail the check");
        assert_eq!(failure.reason, "excess-system-generations");

        // A dangling generation link still counts.
        link("system-11-link", "/nix/store/never-built");
        assert_eq!(
            system_generation_links(root.path())
                .expect("the profile root reads")
                .len(),
            MAX_SYSTEM_GENERATIONS + 2
        );

        // Remove the old and dangling generation links.
        for name in ["system-5-link", "system-11-link"] {
            fs::remove_file(root.path().join(name)).expect("link is removable");
        }
        let kept = system_generation_links(root.path()).expect("the profile root reads");
        assert_eq!(kept.len(), MAX_SYSTEM_GENERATIONS);
        assert!(excess_system_generations(&kept).is_none());

        let unreadable = system_generation_links(&root.path().join("absent"))
            .expect_err("an unreadable profile root is a typed failure");
        assert_eq!(unreadable.reason, "generations-profile-unreadable");
    }
}
