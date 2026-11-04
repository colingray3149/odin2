//! Paths inside declared roots: a relative path never leaves its root, and a
//! new file never replaces an existing one.

use std::path::{Component, Path, PathBuf};

use crate::config::Root;
use crate::{Ctx, Failure};

/// `rel` inside `root`. Rejects empty, absolute, `..` and `.` paths; creates
/// missing parent folders only in a writable root.
pub fn child(root: &Root, rel: &str) -> Result<PathBuf, Failure> {
    let relative = Path::new(rel);
    let plain = relative
        .components()
        .all(|component| matches!(component, Component::Normal(_)));
    let Some(name) = relative.file_name().filter(|_| plain && !rel.is_empty()) else {
        return Err(Failure::arguments(format!(
            "{rel:?} is not a plain relative path inside its root"
        )));
    };
    if root.writable {
        std::fs::create_dir_all(&root.path).map_err(|error| {
            Failure::unavailable(format!("could not create {}: {error}", root.path.display()))
        })?;
    }
    let canonical_root = root.path.canonicalize().map_err(|error| {
        Failure::unavailable(format!(
            "the root {} is unreadable: {error}",
            root.path.display()
        ))
    })?;
    let mut parent = canonical_root.clone();
    for component in relative.parent().unwrap_or(Path::new("")).components() {
        let candidate = parent.join(component);
        if root.writable && !candidate.exists() {
            std::fs::create_dir(&candidate)
                .or_else(|error| {
                    if error.kind() == std::io::ErrorKind::AlreadyExists {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(|error| {
                    Failure::unavailable(format!(
                        "could not create {}: {error}",
                        candidate.display()
                    ))
                })?;
        }
        let canonical = candidate
            .canonicalize()
            .map_err(|_| Failure::arguments(format!("{rel} is not in its root")))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(Failure::arguments(format!(
                "{rel} leads outside its root through a link"
            )));
        }
        parent = canonical;
    }
    Ok(parent.join(name))
}

/// `dir/name`, or `dir/name (2).ext`, `(3)`, … when it already exists.
pub fn unique(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if std::fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem, format!(".{extension}")),
        _ => (name, String::new()),
    };
    let mut n = 2;
    loop {
        let candidate = dir.join(format!("{stem} ({n}){extension}"));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
        n += 1;
    }
}

/// A staged file's text. A file that is not UTF-8 is the caller's mistake, named with
/// `expected`; any other read failure names its own cause.
pub fn read_text(path: &Path, expected: &str) -> Result<String, Failure> {
    std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            Failure::arguments(format!("{} is not UTF-8 text; {expected}", file_name(path)))
        } else {
            Failure::unavailable(format!("could not read {}: {error}", file_name(path)))
        }
    })
}

/// The last component of `path`, or the whole path when it has none.
pub fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// Moves a file into a writable root without replacing an existing file,
/// preserving its permissions even across filesystems.
/// Returns the absolute destination and its path relative to the root.
pub fn file_into(
    ctx: &Ctx,
    key: &str,
    rel: &str,
    from: &Path,
) -> Result<(PathBuf, String), Failure> {
    let root = ctx.root(key)?;
    if !root.writable {
        return Err(Failure::unavailable(format!("the {key} root is read-only")));
    }
    let wanted = child(root, rel)?;
    let parent = wanted.parent().expect("child has a parent");
    let name = wanted
        .file_name()
        .expect("child has a name")
        .to_string_lossy();
    let metadata =
        std::fs::symlink_metadata(from).map_err(|error| moved_badly(from, &wanted, &error))?;
    if !metadata.file_type().is_file() {
        return Err(Failure::arguments(format!(
            "{} is not a regular file",
            from.display()
        )));
    }
    let target = loop {
        let target = unique(parent, &name);
        match std::fs::hard_link(from, &target) {
            Ok(()) => break target,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
                let mut output = match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(moved_badly(from, &target, &error)),
                };
                let copied = output
                    .set_permissions(metadata.permissions())
                    .and_then(|()| std::fs::File::open(from))
                    .and_then(|mut input| std::io::copy(&mut input, &mut output));
                if let Err(error) = copied {
                    let _ = std::fs::remove_file(&target);
                    return Err(moved_badly(from, &target, &error));
                }
                break target;
            }
            Err(error) => return Err(moved_badly(from, &target, &error)),
        }
    };
    std::fs::remove_file(from).map_err(|error| moved_badly(from, &target, &error))?;
    let base = root
        .path
        .canonicalize()
        .map_err(|error| moved_badly(from, &target, &error))?;
    let relative = target
        .strip_prefix(base)
        .expect("child stays inside its root")
        .to_string_lossy()
        .into_owned();
    Ok((target, relative))
}

fn moved_badly(from: &Path, to: &Path, error: &std::io::Error) -> Failure {
    Failure::unavailable(format!(
        "could not move {} to {}: {error}",
        from.display(),
        to.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_refuses_a_symlink_escape_before_creating_directories() {
        let dir = tempfile::tempdir().expect("dir");
        let outside = tempfile::tempdir().expect("outside");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).expect("link");
        let root = Root {
            path: dir.path().to_owned(),
            writable: true,
        };
        let failure = child(&root, "escape/new/sub/file.txt").expect_err("escape");
        assert_eq!(failure.kind, crate::FailureKind::Arguments);
        assert!(
            !outside.path().join("new").exists(),
            "no directory may be created outside the root"
        );
        let inside = child(&root, "safe/new/file.txt").expect("inside");
        assert_eq!(
            inside,
            dir.path()
                .canonicalize()
                .expect("root")
                .join("safe/new/file.txt")
        );
        assert!(dir.path().join("safe/new").is_dir());
    }

    #[test]
    fn filing_preserves_existing_files_and_refuses_read_only_roots() {
        let dir = tempfile::tempdir().expect("dir");
        let shelf = dir.path().join("shelf");
        let ctx = crate::testing::ctx_for(dir.path(), &[], &[("shelf", &shelf, true)], &[], &[]);
        let source = dir.path().join("source");
        std::fs::write(&source, b"first").expect("source");
        let (first, relative) =
            file_into(&ctx, "shelf", "author/book.epub", &source).expect("file");
        assert_eq!(relative, "author/book.epub");
        assert!(!source.exists());
        std::fs::write(&source, b"second").expect("source");
        let (second, relative) =
            file_into(&ctx, "shelf", "author/book.epub", &source).expect("second");
        assert_eq!(relative, "author/book (2).epub");
        assert_eq!(std::fs::read(first).expect("first"), b"first");
        assert_eq!(std::fs::read(second).expect("second"), b"second");
        let ctx = crate::testing::ctx_for(dir.path(), &[], &[("shelf", &shelf, false)], &[], &[]);
        std::fs::write(&source, b"stay").expect("source");
        assert!(file_into(&ctx, "shelf", "blocked.epub", &source).is_err());
        assert_eq!(std::fs::read(source).expect("source"), b"stay");
    }
}
