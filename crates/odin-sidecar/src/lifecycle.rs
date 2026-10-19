//! Exclusive single-authority lifetime lock held inside the private state root.

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fd::OwnedFd;
use rustix::fs::{flock, fstat, open, FlockOperation, Mode, OFlags};

use crate::storage;
use crate::{SidecarError, SidecarErrorCode};

const LOCK_FILE: &str = "authority.lock";

const FILE_TYPE_MASK: u32 = 0o170_000;
const REGULAR_FILE_TYPE: u32 = 0o100_000;

/// The open file description keeps the lock held until its last shared handle is dropped.
#[derive(Debug)]
pub(crate) struct LifecycleLock {
    file: File,
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::NonBlockingUnlock);
    }
}

impl LifecycleLock {
    pub(crate) fn acquire(state_root: &Path, create_directory: bool) -> Result<Self, SidecarError> {
        if create_directory {
            storage::create_private_directory(state_root)?;
        } else {
            storage::verify_private_directory(state_root)?;
        }
        let lock_path = state_root.join(LOCK_FILE);
        let fd: OwnedFd = open(
            &lock_path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| SidecarError::filesystem(&lock_path, error.into()))?;
        let stat =
            fstat(&fd).map_err(|error| SidecarError::filesystem(&lock_path, error.into()))?;
        if stat.st_mode & FILE_TYPE_MASK != REGULAR_FILE_TYPE || stat.st_mode & 0o077 != 0 {
            return Err(SidecarError::new(
                SidecarErrorCode::Filesystem,
                format!("{} must be a private regular file", lock_path.display()),
            ));
        }
        let path_metadata = fs::symlink_metadata(&lock_path)
            .map_err(|error| SidecarError::filesystem(&lock_path, error))?;
        if path_metadata.dev() != stat.st_dev || path_metadata.ino() != stat.st_ino {
            return Err(SidecarError::new(
                SidecarErrorCode::Filesystem,
                format!(
                    "{} changed identity while opening the lifecycle lock",
                    lock_path.display()
                ),
            ));
        }
        if let Err(error) = flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            return Err(SidecarError::new(
                SidecarErrorCode::Lifecycle,
                if error == rustix::io::Errno::WOULDBLOCK {
                    format!(
                        "another sidecar authority already holds the lifecycle lock in {}",
                        state_root.display()
                    )
                } else {
                    format!("lifecycle lock in {}: {error}", state_root.display())
                },
            ));
        }
        Ok(Self {
            file: File::from(fd),
        })
    }
}
