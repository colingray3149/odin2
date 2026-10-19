use super::*;

pub(super) fn run_sys_02(context: &SystemContext, deadline: Instant) -> CheckResult {
    super::run_check("SYS-02", sys_02_body, context, deadline)
}

fn sys_02_body(context: &SystemContext, deadline: Instant) -> Outcome {
    let mut evidence = Vec::new();
    let scratch = command_scratch(context, "SYS-02")?;

    // Source pins: the odin source revision and the dotfiles flake lock
    // agree. A real checkout answers through git; a pinned flake-input
    // store copy has no `.git`, so its declared package-build revision is
    // the resolved source revision — a dirtyRev store copy stays a typed
    // failure, and git stays required exactly when the checkout can
    // answer it.
    let runtime = require_manifest(context, CheckStatus::Fail)?;
    let head = if is_store_source(&context.odin_root) {
        let row = runtime.executables.get("sweep").ok_or_else(|| {
            CheckFailure::fail(
                "sweep-runtime-unverified",
                "the runtime manifest does not bind the sweep executable, so the store source has no declared revision",
            )
        })?;
        let store_root = nix_store_root(&row.path).ok_or_else(|| {
            CheckFailure::fail(
                "executable-not-store-bound",
                format!(
                    "runtime executable sweep at {} is not package-store bound",
                    row.path.display()
                ),
            )
        })?;
        let head = store_source_head(&store_root)?;
        note_evidence(
            &mut evidence,
            format!("odin-head={head} (declared store-source revision)"),
        );
        head
    } else {
        let git = require_tool("git", None)?;
        let head = git_head(&git, &scratch, &context.odin_root, deadline)?;
        note_evidence(&mut evidence, format!("odin-head={head}"));
        head
    };
    // Read the declared candidate revision's lock, not a possibly different checkout revision.
    let declared_rev = load_host_facts()?
        .map(|facts| facts.candidate_revision)
        .filter(|revision| lower_hex(revision, 40));
    let lock_bytes = match &declared_rev {
        Some(revision) => {
            let git = require_tool("git", None)?;
            note_evidence(
                &mut evidence,
                format!("dotfiles-lock@{revision} (declared)"),
            );
            git_show(
                &git,
                &scratch,
                &context.dotfiles_root,
                revision,
                "flake.lock",
                deadline,
            )?
        }
        None => {
            let lock_path = context.dotfiles_root.join("flake.lock");
            read_bounded(&lock_path).map_err(|error| {
                CheckFailure::fail(
                    "dotfiles-lock-unreadable",
                    format!(
                        "dotfiles flake.lock {} is unreadable: {error}",
                        lock_path.display()
                    ),
                )
            })?
        }
    };
    let lock: JsonValue = serde_json::from_slice(&lock_bytes).map_err(|_| {
        CheckFailure::fail(
            "dotfiles-lock-malformed",
            "dotfiles flake.lock is malformed JSON",
        )
    })?;
    let lock_odin = flake_locked_revision(&lock, "odin").ok_or_else(|| {
        CheckFailure::fail(
            "dotfiles-odin-pin-missing",
            "dotfiles flake.lock has no pinned odin revision",
        )
    })?;
    let lock_omp = flake_locked_revision(&lock, "omp").ok_or_else(|| {
        CheckFailure::fail(
            "dotfiles-omp-pin-missing",
            "dotfiles flake.lock has no pinned omp revision",
        )
    })?;
    if !lower_hex(&lock_odin, 40) || !lower_hex(&lock_omp, 40) {
        return Err(CheckFailure::fail(
            "dotfiles-pin-malformed",
            "dotfiles flake.lock pins are not 40-hex revisions",
        ));
    }
    check_odin_pin(&lock_odin, &head)?;
    note_evidence(&mut evidence, "dotfiles-odin-pin=matches-head");
    note_evidence(&mut evidence, format!("dotfiles-omp-pin={lock_omp}"));

    // Runtime pins: every first-party runtime-manifest executable must match
    // its retained package-build identity inside its own store package.
    let executed = env::current_exe().map_err(|error| {
        CheckFailure::fail(
            "sweep-executable-unresolved",
            format!("the executed sweep binary could not be resolved: {error}"),
        )
    })?;
    let executed_canonical = fs::canonicalize(&executed).unwrap_or_else(|_| executed.clone());
    let mut verified = Vec::new();
    for (id, row) in &runtime.executables {
        let Some((package, basename)) = repository_build_contract(id) else {
            continue;
        };
        let store_root = nix_store_root(&row.path).ok_or_else(|| {
            CheckFailure::fail(
                "executable-not-store-bound",
                format!(
                    "runtime executable {id} at {} is not package-store bound",
                    row.path.display()
                ),
            )
        })?;
        let metadata_path = package_build_metadata_path(&store_root, package);
        let bytes = read_bounded(&metadata_path).map_err(|error| {
            CheckFailure::fail(
                "package-metadata-unreadable",
                format!(
                    "package build identity for {id} at {} is unreadable: {error}",
                    metadata_path.display()
                ),
            )
        })?;
        let metadata: PackageBuildMetadata = serde_json::from_slice(&bytes).map_err(|_| {
            CheckFailure::fail(
                "package-metadata-malformed",
                format!("package build identity for {id} is malformed"),
            )
        })?;
        if metadata.schema != PACKAGE_BUILD_SCHEMA
            || metadata.repository != "odin"
            || metadata.cargo_package != package
            || !lower_hex(&metadata.revision, 40)
        {
            return Err(CheckFailure::fail(
                "package-metadata-contradicts-contract",
                format!(
                    "package build identity for {id} contradicts the registered source/build contract"
                ),
            ));
        }
        if metadata.revision != head {
            return Err(CheckFailure::fail(
                "package-revision-mismatch",
                format!(
                    "package build identity for {id} was built from {}, but the checkout is at {head}",
                    metadata.revision
                ),
            ));
        }
        let installed = metadata.executables.get(basename).ok_or_else(|| {
            CheckFailure::fail(
                "package-metadata-omits-executable",
                format!("package metadata for {id} omits installed executable {basename:?}"),
            )
        })?;
        if installed.path != row.path || installed.blake3 != row.digest {
            return Err(CheckFailure::fail(
                "runtime-manifest-contradicts-package",
                format!("installed executable {id} contradicts its runtime manifest row"),
            ));
        }
        if installed.path.file_name().and_then(OsStr::to_str) != Some(basename) {
            return Err(CheckFailure::fail(
                "installed-basename-mismatch",
                format!("installed executable {id} has the wrong package basename"),
            ));
        }
        verify_store_artifact(
            &installed.path,
            &installed.blake3,
            &store_root,
            &format!("installed executable {id}"),
        )?;
        if let Some(payload) = &installed.payload {
            let expected_payload = format!(".{basename}-wrapped");
            if payload.path.file_name().and_then(OsStr::to_str) != Some(expected_payload.as_str()) {
                return Err(CheckFailure::fail(
                    "payload-name-mismatch",
                    format!("installed executable {id} has a malformed wrapped payload name"),
                ));
            }
            verify_store_artifact(
                &payload.path,
                &payload.blake3,
                &store_root,
                &format!("wrapped payload {id}"),
            )?;
            if id == "sweep"
                && executed_canonical
                    == fs::canonicalize(&payload.path).unwrap_or_else(|_| payload.path.clone())
            {
                note_evidence(&mut evidence, "executed-subject=sweep-payload");
            }
        }
        if id == "sweep"
            && executed_canonical
                == fs::canonicalize(&installed.path).unwrap_or_else(|_| installed.path.clone())
        {
            note_evidence(&mut evidence, "executed-subject=sweep-wrapper");
        }
        verified.push(id.clone());
    }
    if !verified.iter().any(|id| id == "sweep") {
        return Err(CheckFailure::fail(
            "sweep-runtime-unverified",
            "the runtime manifest does not bind the sweep executable to its package identity",
        ));
    }
    note_evidence(
        &mut evidence,
        format!("runtime-ids-verified={}", verified.join(",")),
    );

    CheckOutcome::pass(
        format!(
            "source revision, flake lock, and {} first-party runtime package identities agree",
            verified.len()
        ),
        evidence,
    )
}

/// The declared revision of the executed sweep package, retained inside
/// its own store package as the package-build identity.
fn declared_store_revision(store_root: &Path) -> Result<String, CheckFailure> {
    let metadata_path = package_build_metadata_path(store_root, "odin-sweep");
    let bytes = read_bounded(&metadata_path).map_err(|error| {
        CheckFailure::fail(
            "package-metadata-unreadable",
            format!(
                "package build identity for sweep at {} is unreadable: {error}",
                metadata_path.display()
            ),
        )
    })?;
    let metadata: PackageBuildMetadata = serde_json::from_slice(&bytes).map_err(|_| {
        CheckFailure::fail(
            "package-metadata-malformed",
            "package build identity for sweep is malformed",
        )
    })?;
    if metadata.repository != "odin" || metadata.cargo_package != "odin-sweep" {
        return Err(CheckFailure::fail(
            "package-metadata-contradicts-contract",
            "package build identity for sweep contradicts the registered source/build contract",
        ));
    }
    Ok(metadata.revision)
}

/// A store source has no HEAD to query: its declared package-build
/// revision is the resolved source revision exactly when it is a pinned
/// 40-hex revision. A dirtyRev store copy is unverifiable and stays a
/// typed failure.
fn store_source_head(store_root: &Path) -> Result<String, CheckFailure> {
    let declared = declared_store_revision(store_root)?;
    if !lower_hex(&declared, 40) {
        return Err(CheckFailure::fail(
            "store-source-revision-undeclared",
            format!(
                "the store source package identity declares revision {declared:?}; a pinned 40-hex revision is required to verify a store copy"
            ),
        ));
    }
    Ok(declared)
}

/// The dotfiles lock must pin exactly the resolved odin source revision —
/// the cross-check that keeps a store-source fallback honest.
fn check_odin_pin(lock_odin: &str, head: &str) -> Result<(), CheckFailure> {
    if lock_odin != head {
        return Err(CheckFailure::fail(
            "pin-mismatch",
            format!("dotfiles flake.lock pins odin {lock_odin}, but the checkout is at {head}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_fixture(revision: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("store fixture root is creatable");
        let metadata_dir = root.path().join("share/odin/odin-sweep");
        fs::create_dir_all(&metadata_dir).expect("package metadata dir is creatable");
        let identity = json!({
            "schema": PACKAGE_BUILD_SCHEMA,
            "repository": "odin",
            "revision": revision,
            "cargo_package": "odin-sweep",
            "executables": {},
        });
        fs::write(
            metadata_dir.join("package-build.json"),
            serde_json::to_vec(&identity).expect("identity serializes"),
        )
        .expect("package-build fixture is writable");
        root
    }

    #[test]
    fn the_lock_is_read_at_the_declared_revision_not_the_checkout() {
        let repo = tempfile::tempdir().expect("repo");
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .status()
                .expect("git runs");
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "--quiet"]);
        fs::write(repo.path().join("flake.lock"), "declared\n").expect("lock");
        git(&["add", "flake.lock"]);
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "pin",
        ]);
        let revision = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .expect("rev-parse")
                .stdout,
        )
        .expect("utf8")
        .trim()
        .to_owned();
        fs::write(repo.path().join("flake.lock"), "stale checkout\n").expect("lock");
        let scratch = tempfile::tempdir().expect("scratch");
        let bytes = git_show(
            &which_git(),
            scratch.path(),
            repo.path(),
            &revision,
            "flake.lock",
            Instant::now() + std::time::Duration::from_secs(30),
        )
        .expect("the declared revision's lock reads");
        assert_eq!(bytes, b"declared\n");
    }

    fn which_git() -> std::path::PathBuf {
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH"))
            .map(|dir| dir.join("git"))
            .find(|path| path.is_file())
            .expect("git on PATH")
    }

    #[test]
    fn a_store_source_resolves_its_head_from_the_declared_package_identity() {
        let revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root = store_fixture(revision);
        assert_eq!(
            store_source_head(root.path()).expect("the declared revision resolves"),
            revision
        );
    }

    #[test]
    fn a_dirty_store_source_revision_stays_a_typed_failure() {
        let root = store_fixture("e1dea4b27bd15f90cf3b03652183b4aebbe7b16-dirty");
        let failure =
            store_source_head(root.path()).expect_err("a dirtyRev store copy is unverifiable");
        assert_eq!(failure.status, CheckStatus::Fail);
        assert_eq!(failure.reason, "store-source-revision-undeclared");
    }

    #[test]
    fn a_store_identity_contradicting_the_registered_contract_fails() {
        let root = tempfile::tempdir().expect("store fixture root is creatable");
        let metadata_dir = root.path().join("share/odin/odin-sweep");
        fs::create_dir_all(&metadata_dir).expect("package metadata dir is creatable");
        let identity = json!({
            "schema": PACKAGE_BUILD_SCHEMA,
            "repository": "somewhere-else",
            "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "cargo_package": "odin-sweep",
            "executables": {},
        });
        fs::write(
            metadata_dir.join("package-build.json"),
            serde_json::to_vec(&identity).expect("identity serializes"),
        )
        .expect("package-build fixture is writable");
        let failure =
            store_source_head(root.path()).expect_err("a foreign repository identity must fail");
        assert_eq!(failure.reason, "package-metadata-contradicts-contract");
    }

    #[test]
    fn the_flake_lock_pin_must_name_the_resolved_store_head() {
        let head = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(check_odin_pin(head, head).is_ok());
        let mismatch = check_odin_pin("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", head)
            .expect_err("a stale pin must fail the source agreement");
        assert_eq!(mismatch.status, CheckStatus::Fail);
        assert_eq!(mismatch.reason, "pin-mismatch");
        assert!(mismatch.summary.contains(head));
    }
}
