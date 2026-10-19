use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

use crate::{SidecarError, SidecarErrorCode};

pub(crate) fn create_private_directory(path: &Path) -> Result<(), SidecarError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => verify_private(path, &metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|error| SidecarError::filesystem(path, error))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|error| SidecarError::filesystem(path, error))?;
            Ok(())
        }
        Err(error) => Err(SidecarError::filesystem(path, error)),
    }
}

pub(crate) fn verify_private_directory(path: &Path) -> Result<(), SidecarError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| SidecarError::filesystem(path, error))?;
    verify_private(path, &metadata)
}

fn verify_private(path: &Path, metadata: &fs::Metadata) -> Result<(), SidecarError> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(SidecarError::new(
            SidecarErrorCode::Filesystem,
            format!("{} must be a private real directory", path.display()),
        ));
    }
    Ok(())
}

/// Reject symlinks during open so a path swap cannot redirect the read.
pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SidecarError> {
    let file = File::from(
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| SidecarError::filesystem(path, error.into()))?,
    );
    let metadata = file
        .metadata()
        .map_err(|error| SidecarError::filesystem(path, error))?;
    if !metadata.is_file() {
        return Err(SidecarError::new(
            SidecarErrorCode::Filesystem,
            format!("{} must be a regular file", path.display()),
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(SidecarError::new(
            SidecarErrorCode::Filesystem,
            format!("{} exceeds the {max_bytes} byte ceiling", path.display()),
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| SidecarError::filesystem(path, error))?;
    if bytes.len() > max_bytes {
        return Err(SidecarError::new(
            SidecarErrorCode::Filesystem,
            format!(
                "{} grew past the {max_bytes} byte ceiling while reading",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

/// Retain imported state for inspection without allowing it to be imported again.
pub(crate) fn archive(source: &Path, suffix: &str) -> Result<PathBuf, SidecarError> {
    let file_name = source
        .file_name()
        .map(|name| name.to_owned())
        .ok_or_else(|| {
            SidecarError::new(
                SidecarErrorCode::Filesystem,
                format!("{} has no file name", source.display()),
            )
        })?;
    let mut archived = file_name.as_os_str().to_owned();
    archived.push(suffix);
    let destination = source.with_file_name(archived);
    if destination.exists() {
        return Err(SidecarError::new(
            SidecarErrorCode::LegacyImport,
            format!(
                "legacy archive {} already exists; refusing to overwrite",
                destination.display()
            ),
        ));
    }
    fs::rename(source, &destination).map_err(|error| SidecarError::filesystem(source, error))?;
    Ok(destination)
}
