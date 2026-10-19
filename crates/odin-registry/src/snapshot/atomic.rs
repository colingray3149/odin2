use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::contract::SnapshotError;

impl SnapshotError {
    pub(super) fn from_atomic(error: AtomicWriteError) -> Self {
        Self::Io {
            action: error.action,
            path: error.path,
            source: error.source,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AtomicWriteError {
    pub(crate) action: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) source: std::io::Error,
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|source| AtomicWriteError {
        action: "create publication directory",
        path: parent.to_path_buf(),
        source,
    })?;

    let file_name = path.file_name().ok_or_else(|| AtomicWriteError {
        action: "resolve publication filename for",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "publication path has no filename",
        ),
    })?;
    let file_name = file_name.to_string_lossy();
    let mut temporary = None;
    for attempt in 0..16_u8 {
        let candidate = parent.join(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(AtomicWriteError {
                    action: "create temporary publication",
                    path: candidate,
                    source,
                });
            }
        }
    }
    let (temporary_path, mut file) = temporary.ok_or_else(|| AtomicWriteError {
        action: "allocate temporary publication beside",
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "all temporary publication names are occupied",
        ),
    })?;
    let result = write_and_rename(&mut file, &temporary_path, path, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn write_and_rename(
    file: &mut File,
    temporary_path: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), AtomicWriteError> {
    file.write_all(bytes).map_err(|source| AtomicWriteError {
        action: "write temporary publication",
        path: temporary_path.to_path_buf(),
        source,
    })?;
    file.write_all(b"\n").map_err(|source| AtomicWriteError {
        action: "finish temporary publication",
        path: temporary_path.to_path_buf(),
        source,
    })?;
    file.sync_all().map_err(|source| AtomicWriteError {
        action: "sync temporary publication",
        path: temporary_path.to_path_buf(),
        source,
    })?;
    fs::rename(temporary_path, path).map_err(|source| AtomicWriteError {
        action: "publish",
        path: path.to_path_buf(),
        source,
    })?;
    let parent = path.parent().unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| AtomicWriteError {
            action: "sync publication directory",
            path: parent.to_path_buf(),
            source,
        })
}

/// Match the opened inode to lstat so reads cannot follow a substituted symlink.
pub(crate) fn read_regular_file(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let linked = fs::symlink_metadata(path)?;
    if !linked.file_type().is_file() {
        return Err(not_regular(path));
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
        return Err(not_regular(path));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(opened.len()).unwrap_or(0));
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn not_regular(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{} is not a regular file", path.display()),
    )
}
