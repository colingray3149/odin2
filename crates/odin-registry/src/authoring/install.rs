//! Share installation across CLI and conversation authoring so neither stages unrelated index changes.

use std::io::Write;
use std::path::Path;

use super::{AuthoringErrors, StagedFillBatch};

/// On failure, retain staging and worktree contents for caller cleanup rather than deleting work.
pub fn install_staged_batch(
    worktree: &Path,
    staged: &StagedFillBatch,
) -> Result<Vec<String>, AuthoringErrors> {
    let issue = |message: String| {
        AuthoringErrors::single(super::AuthoringIssue {
            code: "authoring-install-failed".to_owned(),
            path: worktree.to_path_buf(),
            variable: None,
            message,
        })
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
            .map_err(|_| issue("git stdout is not UTF-8".to_owned()))
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
        if let Err(error) = replace_atomically(&target, parent, &bytes) {
            return Err(issue(format!(
                "could not atomically replace {}: {error}",
                relative.display()
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
        return Err(AuthoringErrors::single(super::AuthoringIssue {
            code: "authoring-install-index".to_owned(),
            path: worktree.to_path_buf(),
            variable: None,
            message: format!(
                "author stage index contains paths other than the exact generated set: {indexed:?}"
            ),
        }));
    }
    Ok(expected)
}

/// Create exclusively beside the target, then fsync and rename to avoid symlinks and cross-filesystem moves.
fn replace_atomically(target: &Path, parent: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let (temporary, mut file) = create_temporary(parent)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(source) = written {
        // Remove only the temporary entry this call created.
        let _ = std::fs::remove_file(&temporary);
        return Err(source);
    }
    drop(file);
    if let Err(source) = std::fs::rename(&temporary, target) {
        // Remove only the temporary entry this call created.
        let _ = std::fs::remove_file(&temporary);
        return Err(source);
    }
    // Rename succeeded; an fsync failure must leave the replacement in place.
    std::fs::File::open(parent)?.sync_all()
}

fn create_temporary(directory: &Path) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    let process = std::process::id();
    for sequence in 0..100u8 {
        let path = directory.join(format!(".odin-author-{process}-{sequence}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(source),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "could not allocate a unique authoring temporary file in {}",
            directory.display()
        ),
    ))
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
                    .is_some_and(|name| name.to_string_lossy().starts_with(".odin-author-"))
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
    fn install_skips_preexisting_temporary_collisions_without_truncating_or_following() {
        let worktree = initialized_worktree();
        let staging = tempdir().expect("staging root");
        let bytes = b"[object]\nname = \"fixture\"\n";
        let batch = staged_batch(staging.path(), bytes);

        let destination = worktree.path().join("objects/fixture");
        std::fs::create_dir_all(&destination).expect("destination directory");
        let process = std::process::id();
        let collision = destination.join(format!(".odin-author-{process}-0"));
        std::fs::write(&collision, b"foreign bytes").expect("collision file");
        #[cfg(unix)]
        let link = {
            let canary = destination.join("canary");
            std::fs::write(&canary, b"canary bytes").expect("canary file");
            let link = destination.join(format!(".odin-author-{process}-1"));
            std::os::unix::fs::symlink(&canary, &link).expect("collision symlink");
            link
        };

        install_staged_batch(worktree.path(), &batch).expect("install must succeed");

        assert_eq!(
            std::fs::read(&collision).expect("collision file readable"),
            b"foreign bytes"
        );
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(&link).expect("collision symlink intact"),
                destination.join("canary")
            );
            assert_eq!(
                std::fs::read(destination.join("canary")).expect("canary readable"),
                b"canary bytes"
            );
        }
        assert_eq!(
            std::fs::read(worktree.path().join("objects/fixture/project.toml"))
                .expect("target path must exist"),
            bytes
        );
        let mut planted = vec![collision];
        #[cfg(unix)]
        planted.push(link);
        assert_eq!(temporary_entries(&destination), planted);
    }

    #[test]
    fn failed_install_leaves_no_temporary_and_no_foreign_loss() {
        let worktree = tempdir().expect("worktree root");
        let staging = tempdir().expect("staging root");
        let bytes = b"[object]\nname = \"fixture\"\n";
        let batch = staged_batch(staging.path(), bytes);

        // A directory occupies the target, so the final rename must fail
        // after the temporary has been created and written.
        let destination = worktree.path().join("objects/fixture");
        std::fs::create_dir_all(destination.join("project.toml")).expect("decoy directory");
        let foreign = destination.join("keep-me.txt");
        std::fs::write(&foreign, b"keep me").expect("foreign file");

        let error =
            install_staged_batch(worktree.path(), &batch).expect_err("decoy target must fail");

        assert_eq!(error.issues[0].code, "authoring-install-failed");
        assert!(
            temporary_entries(&destination).is_empty(),
            "faulted install left temporaries behind"
        );
        assert!(
            destination.join("project.toml").is_dir(),
            "decoy directory must survive untouched"
        );
        assert_eq!(
            std::fs::read(&foreign).expect("foreign file readable"),
            b"keep me"
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
        assert_eq!(error.issues[0].code, "authoring-install-failed");

        let elsewhere = staging.path().join("elsewhere.toml");
        std::fs::write(&elsewhere, b"[object]\nname = \"fixture\"\n").expect("link target");
        std::fs::remove_file(staged).expect("unlink staged");
        std::os::unix::fs::symlink(&elsewhere, staged).expect("symlink staged");
        let error = install_staged_batch(worktree.path(), &batch).expect_err("symlinked staged");
        assert_eq!(error.issues[0].code, "authoring-install-failed");
        assert!(!worktree
            .path()
            .join("objects/fixture/project.toml")
            .exists());
    }
}
