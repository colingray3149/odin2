//! Share installation across CLI and conversation authoring so neither stages unrelated index changes.

use std::path::Path;

use super::contracts::issue as authoring_issue;
use super::{AuthoringErrors, StagedFillBatch};

/// On failure, retain staging and worktree contents for caller cleanup rather than deleting work.
pub fn install_staged_batch(
    worktree: &Path,
    staged: &StagedFillBatch,
) -> Result<Vec<String>, AuthoringErrors> {
    let issue = |message: String| {
        AuthoringErrors::single(authoring_issue(
            "authoring-install-failed",
            worktree,
            None::<String>,
            message,
        ))
    };
    let run_git = |args: &[&str]| -> Result<String, AuthoringErrors> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(worktree)
            .args(args)
            .output()
            .map_err(|error| issue(format!("could not spawn git {}: {error}", args.join(" "))))?;
        if !output.status.success() {
            return Err(issue(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map(|stdout| stdout.trim().to_owned())
            .map_err(|error| issue(format!("git stdout is not UTF-8: {error}")))
    };

    let mut generated = Vec::new();
    for change in staged.changes.iter() {
        let relative = &change.metadata.destination;
        let target = worktree.join(relative);
        let parent = target.parent().ok_or_else(|| {
            issue(format!(
                "generated path {} has no parent",
                relative.display()
            ))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|error| issue(format!("could not create {}: {error}", parent.display())))?;
        let bytes = crate::snapshot::read_regular_file(&change.staged_path).map_err(|error| {
            issue(format!(
                "could not read staged {}: {error}",
                relative.display()
            ))
        })?;
        if odin_domain::Digest::hash(&bytes) != change.metadata.after_digest {
            return Err(issue(format!(
                "staged {} no longer holds the validated bytes",
                relative.display()
            )));
        }
        if let Err(error) = crate::snapshot::atomic_write_exact(&target, &bytes) {
            return Err(issue(format!(
                "could not atomically replace {}: {}: {}",
                relative.display(),
                error.action,
                error.source
            )));
        }
        generated.push(relative.to_string_lossy().to_string());
    }

    let mut add_args = vec!["add", "--"];
    add_args.extend(generated.iter().map(String::as_str));
    run_git(&add_args)?;
    let indexed = run_git(&["diff", "--cached", "--name-only"])?;
    let mut indexed: Vec<String> = indexed.lines().map(str::to_owned).collect();
    indexed.sort();
    let mut expected = generated.clone();
    expected.sort();
    if indexed != expected {
        return Err(AuthoringErrors::single(authoring_issue(
            "authoring-install-index",
            worktree,
            None::<String>,
            format!(
                "author stage index contains paths other than the exact generated set: {indexed:?}"
            ),
        )));
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use odin_domain::Digest;
    use tempfile::{tempdir, TempDir};

    use super::super::{
        SkeletonKind, StagedChange, StagedDiffMetadata, StagedFill, StagedFillBatch,
    };
    use super::install_staged_batch;

    fn initialized_worktree() -> TempDir {
        let worktree = tempdir().expect("worktree root");
        std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(worktree.path())
            .output()
            .expect("git init spawn");
        worktree
    }

    fn staged_batch(staging: &Path, bytes: &[u8]) -> StagedFillBatch {
        let staged_path = staging.join("staged.toml");
        std::fs::write(&staged_path, bytes).expect("staged bytes");
        StagedFillBatch {
            staging_root: staging.to_path_buf(),
            batch_digest: Digest::hash(bytes),
            changes: vec![StagedFill {
                staged_path,
                unified_diff: String::new(),
                metadata: StagedDiffMetadata {
                    skeleton: SkeletonKind::NewProject,
                    destination: PathBuf::from("objects/fixture/project.toml"),
                    change: StagedChange::Create,
                    before_digest: None,
                    after_digest: Digest::hash(bytes),
                    canonical_bytes: u64::try_from(bytes.len()).expect("byte length"),
                },
            }],
        }
    }

    fn temporary_entries(directory: &Path) -> Vec<PathBuf> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("destination listing")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".project.toml.tmp."))
            })
            .collect();
        entries.sort();
        entries
    }

    /// Installation stages only generated targets and leaves no temporary files.
    #[test]
    fn install_lands_staged_bytes_at_target_and_stages_them() {
        let worktree = initialized_worktree();
        let staging = tempdir().expect("staging root");
        let bytes = b"[object]\nname = \"fixture\"\n";
        let batch = staged_batch(staging.path(), bytes);

        let installed =
            install_staged_batch(worktree.path(), &batch).expect("install must succeed");

        assert_eq!(installed, vec!["objects/fixture/project.toml".to_owned()]);
        let landed = std::fs::read(worktree.path().join("objects/fixture/project.toml"))
            .expect("target path must exist");
        assert_eq!(landed, bytes);
        let listed = std::process::Command::new("git")
            .arg("-C")
            .arg(worktree.path())
            .args(["ls-files"])
            .output()
            .expect("git ls-files spawn");
        assert!(listed.status.success());
        assert!(String::from_utf8_lossy(&listed.stdout)
            .lines()
            .any(|path| path == "objects/fixture/project.toml"));
        let strays = temporary_entries(&worktree.path().join("objects/fixture"));
        assert!(
            strays.is_empty(),
            "stray temp files left behind: {strays:?}"
        );
    }

    #[test]
    fn install_refuses_staged_bytes_that_changed_or_moved_behind_a_symlink() {
        let worktree = initialized_worktree();
        let staging = tempdir().expect("staging root");
        let batch = staged_batch(staging.path(), b"[object]\nname = \"fixture\"\n");
        let staged = &batch.changes[0].staged_path;

        std::fs::write(staged, b"[object]\nname = \"swapped\"\n").expect("swap bytes");
        let error = install_staged_batch(worktree.path(), &batch).expect_err("changed bytes");
        assert!(error.issues[0]
            .message
            .contains("no longer holds the validated bytes"));

        let elsewhere = staging.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, b"[object]\nname = \"fixture\"\n").expect("link target");
        std::fs::remove_file(staged).expect("unlink staged");
        std::os::unix::fs::symlink(&elsewhere, staged).expect("symlink staged");
        let error = install_staged_batch(worktree.path(), &batch).expect_err("symlinked staged");
        assert!(error.issues[0].message.contains("could not read staged"));
        assert!(!worktree
            .path()
            .join("objects/fixture/project.toml")
            .exists());
    }
}
