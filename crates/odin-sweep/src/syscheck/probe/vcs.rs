use super::*;

pub(in crate::syscheck) fn git_head(
    git: &Path,
    scratch: &Path,
    root: &Path,
    deadline: Instant,
) -> Result<String, CheckFailure> {
    let outcome = run_bounded(
        git,
        &[
            OsString::from("-C"),
            root.as_os_str().to_owned(),
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        scratch,
        root,
        deadline,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "git-head-unavailable",
            format!(
                "could not resolve the revision of {}: {error}",
                root.display()
            ),
        )
    })?;
    if let Some(problem) = command_problem(&outcome) {
        return Err(CheckFailure::fail(
            "git-head-unavailable",
            format!(
                "could not resolve the revision of {}: {problem}",
                root.display()
            ),
        ));
    }
    let revision = trimmed_stdout(&outcome);
    if lower_hex(&revision, 40) {
        Ok(revision)
    } else {
        Err(CheckFailure::fail(
            "git-head-malformed",
            format!("git returned a malformed revision for {}", root.display()),
        ))
    }
}

/// One file's bytes at one revision (`git show <rev>:<path>`): the
/// declared source, never whatever the checkout happens to have out.
pub(in crate::syscheck) fn git_show(
    git: &Path,
    scratch: &Path,
    root: &Path,
    revision: &str,
    path: &str,
    deadline: Instant,
) -> Result<Vec<u8>, CheckFailure> {
    let unavailable = |detail: String| {
        CheckFailure::fail(
            "git-show-unavailable",
            format!(
                "could not read {path} at {revision} in {}: {detail}",
                root.display()
            ),
        )
    };
    let outcome = run_bounded(
        git,
        &[
            OsString::from("-C"),
            root.as_os_str().to_owned(),
            OsString::from("show"),
            OsString::from(format!("{revision}:{path}")),
        ],
        scratch,
        root,
        deadline,
    )
    .map_err(|error| unavailable(error.to_string()))?;
    if let Some(problem) = command_problem(&outcome) {
        return Err(unavailable(problem));
    }
    if outcome.stdout_truncated > 0 {
        return Err(unavailable("the file exceeds the bounded read".to_owned()));
    }
    Ok(outcome.stdout)
}

/// A pinned flake-input store copy: a `/nix/store` path without a `.git`
/// worktree, so git inventory commands structurally cannot run against it.
/// Its file tree is the flake's declared source fileset — exactly the
/// tracked set. Any other root without `.git` is a broken checkout.
pub(in crate::syscheck) fn is_store_source(root: &Path) -> bool {
    root.starts_with("/nix/store") && !root.join(".git").exists()
}

/// Inventories a store source (a git archive of the flake's declared
/// fileset) with a bounded recursive walk. Paths are workspace-relative
/// UTF-8, exactly the shape `git ls-files -z` returns, so the same hygiene
/// predicates consume both inventories.
pub(in crate::syscheck) fn store_source_tracked_paths(
    root: &Path,
) -> Result<Vec<String>, CheckFailure> {
    let mut paths = Vec::new();
    let mut examined = 0_usize;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.depth() == 0 || entry.file_name() != OsStr::new(".git"))
    {
        let entry = entry.map_err(|error| {
            CheckFailure::fail(
                "tracked-inventory-failed",
                format!(
                    "store-source inventory could not walk {}: {error}",
                    root.display()
                ),
            )
        })?;
        examined += 1;
        if examined > WALK_ENTRY_CAP {
            return Err(CheckFailure::fail(
                "tracked-inventory-failed",
                "store-source inventory exceeded its entry cap",
            ));
        }
        let file_type = entry.file_type();
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }
        if paths.len() == TRACKED_ROW_CAP {
            return Err(CheckFailure::fail(
                "tracked-row-cap",
                "store-source tracked-file inventory exceeded its row cap",
            ));
        }
        paths.push(
            entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .to_string(),
        );
    }
    Ok(paths)
}

/// The tracked-path inventory for one repository root: real checkouts
/// answer through `git ls-files`; a store source is inventoried by the
/// same bounded filesystem walk discipline as every other read.
pub(in crate::syscheck) fn tracked_inventory(
    git: &Path,
    scratch: &Path,
    root: &Path,
    deadline: Instant,
) -> Result<Vec<String>, CheckFailure> {
    if is_store_source(root) {
        store_source_tracked_paths(root)
    } else {
        git_tracked_paths(git, scratch, root, deadline)
    }
}

pub(in crate::syscheck) fn git_tracked_paths(
    git: &Path,
    scratch: &Path,
    root: &Path,
    deadline: Instant,
) -> Result<Vec<String>, CheckFailure> {
    let outcome = run_bounded(
        git,
        &[
            OsString::from("-C"),
            root.as_os_str().to_owned(),
            OsString::from("ls-files"),
            OsString::from("-z"),
        ],
        scratch,
        root,
        deadline,
    )
    .map_err(|error| {
        CheckFailure::fail(
            "tracked-inventory-failed",
            format!(
                "tracked-file inventory could not execute in {}: {error}",
                root.display()
            ),
        )
    })?;
    if let Some(problem) = command_problem(&outcome) {
        return Err(CheckFailure::fail(
            "tracked-inventory-failed",
            format!(
                "tracked-file inventory failed in {}: {problem}",
                root.display()
            ),
        ));
    }
    let mut paths = Vec::new();
    for bytes in outcome
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
    {
        let path = std::str::from_utf8(bytes).map_err(|_| {
            CheckFailure::fail(
                "tracked-path-non-utf8",
                "tracked-file inventory contains a non-UTF-8 path",
            )
        })?;
        if paths.len() == TRACKED_ROW_CAP {
            return Err(CheckFailure::fail(
                "tracked-row-cap",
                "tracked-file inventory exceeded its row cap",
            ));
        }
        paths.push(path.to_owned());
    }
    Ok(paths)
}

/// Credential-shaped tracked paths are flagged by name only — no content is
/// ever read. Sops-encrypted declarations (for example `secrets.yaml`) are
/// deliberately not matched.
pub(in crate::syscheck) fn is_credential_shaped_path(path: &str) -> bool {
    let Some(name) = Path::new(path).file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == ".env"
        || lower.starts_with(".env.")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.starts_with("id_rsa")
        || lower.starts_with("id_ecdsa")
        || lower.starts_with("id_ed25519")
        || lower == ".git-credentials"
        || lower == ".netrc"
        || lower.ends_with(".kdbx")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
}

/// Tracked log or output capture files, matched case-insensitively on the leaf name.
pub(in crate::syscheck) fn is_log_or_jsonl_path(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(OsStr::to_str)
        .map(|name| {
            let lower = name.to_ascii_lowercase();
            lower.ends_with(".log") || lower.ends_with(".jsonl")
        })
        .unwrap_or(false)
}

pub(in crate::syscheck) fn gitignore_missing_rules(content: &str) -> Vec<&'static str> {
    let lines: BTreeSet<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    [
        "/target/",
        "/state/",
        "/artifacts/",
        "/result",
        "/result-*",
        ".direnv/",
    ]
    .into_iter()
    .filter(|rule| !lines.contains(rule))
    .collect()
}

/// One tracked-path hygiene violation class, if the tracked path violates the
/// workspace contract.
pub(in crate::syscheck) fn tracked_hygiene_violation(
    path: &str,
    root: &Path,
) -> Option<&'static str> {
    // Mirrors the required .gitignore rules: cargo `target` anywhere, but the
    // runtime `/state/` and `/artifacts/` trees only at the workspace root, so
    // source modules that merely model state (e.g. `src/source/state/`) are not
    // runtime content.
    let root_component = path.split('/').next().unwrap_or_default();
    if path_has_component(path, "target") || matches!(root_component, "state" | "artifacts") {
        return Some("tracked-runtime-content");
    }
    let name = Path::new(path).file_name().and_then(OsStr::to_str)?;
    if name == ".env" || name.starts_with(".env.") {
        return Some("tracked-dotenv");
    }
    if is_log_or_jsonl_path(path) {
        return Some("tracked-log-or-jsonl");
    }
    if (name == "result" || name.starts_with("result-"))
        && fs::symlink_metadata(root.join(path))
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    {
        return Some("tracked-result-symlink");
    }
    None
}

/// Nested Git checkouts are separate workspaces and excluded from this inventory.
fn is_nested_worktree(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_dir() && entry.path().join(".git").exists()
}

/// Real `.env` files sitting in the worktree, outside declared build residue.
pub(in crate::syscheck) fn find_stray_dotenv(root: &Path) -> io::Result<Vec<String>> {
    let mut paths = Vec::new();
    let mut examined = 0_usize;
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || (!matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "target" | "state" | "artifacts" | "node_modules" | ".direnv")
                ) && !is_nested_worktree(entry))
        })
    {
        let entry = entry.map_err(io::Error::other)?;
        examined += 1;
        if examined > WALK_ENTRY_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "workspace walk exceeded entry cap",
            ));
        }
        if entry.file_type().is_file() && entry.file_name() == OsStr::new(".env") {
            paths.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(entry.path())
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod nested_worktree_tests {
    use super::find_stray_dotenv;

    /// Nested checkouts do not consume the walk limit or contribute `.env` findings.
    #[test]
    fn a_nested_worktree_is_not_part_of_the_inventory() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join(".env"), "A=1").expect("root env");
        let nested = root.path().join(".claude/worktrees/agent-x");
        std::fs::create_dir_all(&nested).expect("nested");
        std::fs::write(nested.join(".git"), "gitdir: /elsewhere").expect("git file");
        std::fs::write(nested.join(".env"), "B=2").expect("nested env");
        for index in 0..(super::super::super::WALK_ENTRY_CAP + 10) {
            std::fs::write(nested.join(format!("f{index}")), "").expect("file");
        }
        let found = find_stray_dotenv(root.path()).expect("walk stays under the cap");
        assert_eq!(found, vec![".env".to_owned()]);
    }
}
