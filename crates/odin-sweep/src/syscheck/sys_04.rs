use super::*;

pub(super) fn run_sys_04(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-04", sys_04_body, context, deadline)
}

fn sys_04_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let git = require_tool("git", None)?;
    let scratch = command_scratch(context, "SYS-04")?;
    let facts = load_host_facts()?;

    // Check secret metadata, following symlinks only to regular files and enforcing repository exclusion.
    // Never read secret contents; declared host facts add rendered directories to the walk roots.
    let rendered_root = env::var_os("SOPS_RENDERED_SECRETS_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".config/sops-nix/secrets/rendered"))
        });
    let Some(rendered_root) = rendered_root else {
        return Err(CheckFailure::fail(
            "rendered-secrets-root-unavailable",
            "the rendered-secrets root could not be resolved",
        ));
    };
    // Both sops-nix and Odin rendered-secret roots must be owned by the current user.
    let user = rustix::process::getuid().as_raw();
    let mut roots = vec![(rendered_root, Some(user))];
    if let Some(odin) = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(|home| PathBuf::from(home).join(ODIN_RENDERED_SECRETS))
        .filter(|odin| odin.exists())
    {
        roots.push((odin, Some(user)));
    }
    if let Some(facts) = &facts {
        for directory in &facts.sops_rendered_dirs {
            if !roots.iter().any(|(root, _)| root == directory) {
                roots.push((directory.clone(), None));
            }
        }
        note_evidence(
            &mut evidence,
            format!("rendered-secrets-roots={}", roots.len()),
        );
    }
    let canonical_odin = fs::canonicalize(&context.odin_root).ok();
    let canonical_dotfiles = fs::canonicalize(&context.dotfiles_root).ok();
    let mut rendered_files = 0_usize;
    for (root, owner) in &roots {
        if !root.is_dir() {
            return Err(CheckFailure::fail(
                "rendered-secrets-root-missing",
                format!("the rendered-secrets root {} is absent", root.display()),
            ));
        }
        rendered_files += audit_rendered_root(
            root,
            *owner,
            canonical_odin.as_deref(),
            canonical_dotfiles.as_deref(),
        )?;
    }
    if rendered_files == 0 {
        return Err(CheckFailure::fail(
            "rendered-secrets-empty",
            "no rendered secret files were found",
        ));
    }
    note_evidence(
        &mut evidence,
        format!("rendered-secrets-checked={rendered_files}"),
    );

    // Tracked-path hygiene: no credential-shaped path may be tracked in either
    // repository. This is a pure path check; file contents are not read. A
    // store source is inventoried by its bounded walk (its file tree is the
    // tracked set).
    for (label, root) in [
        ("odin", &context.odin_root),
        ("dotfiles", &context.dotfiles_root),
    ] {
        let tracked = tracked_inventory(&git, &scratch, root, deadline)?;
        for path in &tracked {
            if is_credential_shaped_path(path) {
                return Err(CheckFailure::fail(
                    "tracked-credential-path",
                    format!("{label} repository tracks credential-shaped path {path:?}"),
                ));
            }
        }
        note_evidence(
            &mut evidence,
            format!("{label}-tracked-paths-clean={}", tracked.len()),
        );
    }

    CheckOutcome::pass(
        "rendered secret metadata, modes, and tracked paths are secret-clean; no credential content was read",
        evidence,
    )
}

const ODIN_RENDERED_SECRETS: &str = ".config/odin/secrets/rendered";

/// Audits one rendered-secrets root: every regular-file entry — directly
/// or through a symlink — must be mode 0400 or 0600, owned by `owner` when
/// one is required, and must not canonicalize inside a tracked repository. Returns the number of
/// rendered secrets counted. Type and mode come from follow-metadata, so a
/// symlink to a regular file is judged by its real target.
fn audit_rendered_root(
    root: &Path,
    owner: Option<u32>,
    canonical_odin: Option<&Path>,
    canonical_dotfiles: Option<&Path>,
) -> Result<usize, CheckFailure> {
    let entries = walk_entries(root, 6).map_err(|error| {
        CheckFailure::fail(
            "rendered-secrets-unbounded",
            format!("rendered secret metadata could not be bounded: {error}"),
        )
    })?;
    let mut rendered_files = 0_usize;
    for entry in entries {
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
            continue;
        }
        let metadata = match fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(CheckFailure::fail(
                    "rendered-secret-unreadable",
                    format!(
                        "rendered secret target {} is unreadable: {error}",
                        entry.path().display()
                    ),
                ));
            }
        };
        if !metadata.is_file() {
            continue;
        }
        rendered_files += 1;
        let mode = metadata.permissions().mode() & 0o7777;
        if !matches!(mode, 0o400 | 0o600) {
            return Err(CheckFailure::fail(
                "rendered-secret-mode-violation",
                format!(
                    "rendered secret {} is mode {:04o}; only 0400 or 0600 is allowed",
                    entry.path().display(),
                    mode
                ),
            ));
        }
        if owner.is_some_and(|owner| owner != metadata.uid()) {
            return Err(CheckFailure::fail(
                "rendered-secret-owner-violation",
                format!(
                    "rendered secret {} is owned by uid {}, not the user",
                    entry.path().display(),
                    metadata.uid()
                ),
            ));
        }
        if let Ok(canonical) = fs::canonicalize(entry.path()) {
            if canonical_odin.is_some_and(|repo_root| canonical.starts_with(repo_root))
                || canonical_dotfiles.is_some_and(|repo_root| canonical.starts_with(repo_root))
            {
                return Err(CheckFailure::fail(
                    "rendered-secret-committed",
                    format!(
                        "rendered secret {} resolves inside a tracked repository",
                        entry.path().display()
                    ),
                ));
            }
        }
    }
    Ok(rendered_files)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One rendered entry through a symlink to a regular file must count,
    /// with its real target mode enforced — the sops-nix layout.
    #[test]
    fn a_symlink_to_a_regular_file_counts_as_rendered() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        let generation = tempfile::tempdir().expect("generation dir is creatable");
        let secret = generation.path().join("litellm-env");
        fs::write(&secret, b"provider").expect("secret target is writable");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o400))
            .expect("secret mode is settable");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, root.path().join("litellm-env"))
            .expect("rendered symlink is creatable");

        let counted = audit_rendered_root(root.path(), None, None, None)
            .expect("a symlink to a 0400 regular file counts");
        assert_eq!(counted, 1, "the symlink entry must count as rendered");
    }

    /// Odin's rendered root (the fleet kubeconfig moved there) is audited
    /// like sops-nix's, and a user root's secret owned by anyone else fails.
    #[test]
    fn a_user_rendered_secret_owned_by_another_uid_fails() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        let secret = root.path().join("odin-fleet-kubeconfig");
        fs::write(&secret, b"kubeconfig").expect("secret is writable");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o400))
            .expect("secret mode is settable");
        let mine = fs::metadata(&secret).expect("metadata").uid();
        assert_eq!(
            audit_rendered_root(root.path(), Some(mine), None, None).expect("owned by the user"),
            1
        );
        let failure = audit_rendered_root(root.path(), Some(mine.wrapping_add(1)), None, None)
            .expect_err("another owner fails");
        assert_eq!(failure.reason, "rendered-secret-owner-violation");
        assert_eq!(ODIN_RENDERED_SECRETS, ".config/odin/secrets/rendered");
    }

    #[test]
    fn a_direct_regular_file_still_counts_and_directories_do_not() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        let secret = root.path().join("plain-env");
        fs::write(&secret, b"provider").expect("secret is writable");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600))
            .expect("secret mode is settable");
        fs::create_dir(root.path().join("nested")).expect("dir is creatable");
        let counted =
            audit_rendered_root(root.path(), None, None, None).expect("the direct file counts");
        assert_eq!(counted, 1);
    }

    #[test]
    fn a_loose_symlink_target_mode_is_a_typed_violation() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        let generation = tempfile::tempdir().expect("generation dir is creatable");
        let secret = generation.path().join("hermes-env");
        fs::write(&secret, b"provider").expect("secret target is writable");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))
            .expect("loose mode is settable");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, root.path().join("hermes-env"))
            .expect("rendered symlink is creatable");
        let failure = audit_rendered_root(root.path(), None, None, None)
            .expect_err("a 0644 target must violate the mode law");
        assert_eq!(failure.reason, "rendered-secret-mode-violation");
    }

    #[test]
    fn a_broken_symlink_is_a_typed_failure_never_a_silent_skip() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            root.path().join("missing-target"),
            root.path().join("dangling"),
        )
        .expect("dangling symlink is creatable");
        let failure = audit_rendered_root(root.path(), None, None, None)
            .expect_err("a dangling rendered secret must fail closed");
        assert_eq!(failure.reason, "rendered-secret-unreadable");
    }

    #[test]
    fn a_secret_resolving_inside_a_tracked_repository_is_flagged() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        let repo = tempfile::tempdir().expect("repo root is creatable");
        let canonical_repo = fs::canonicalize(repo.path()).expect("repo canonicalizes");
        let secret = repo.path().join("committed-env");
        fs::write(&secret, b"provider").expect("secret is writable");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o400))
            .expect("secret mode is settable");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&secret, root.path().join("committed-env"))
            .expect("rendered symlink is creatable");
        let failure = audit_rendered_root(root.path(), None, Some(&canonical_repo), None)
            .expect_err("a secret inside a tracked repository must fail");
        assert_eq!(failure.reason, "rendered-secret-committed");
    }

    #[test]
    fn an_empty_rendered_root_counts_zero() {
        let root = tempfile::tempdir().expect("rendered root is creatable");
        assert_eq!(
            audit_rendered_root(root.path(), None, None, None).expect("an empty root is walkable"),
            0
        );
    }
}
