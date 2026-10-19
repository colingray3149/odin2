//! Read metadata from open descriptors so later path replacement cannot change the observed object.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
}

impl Identity {
    pub fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatInfo {
    pub identity: Identity,
    /// File length in bytes.
    pub size: u64,
    /// Full Unix mode from `fstat(2)`.
    pub mode: u32,
    pub nlink: u64,
    pub is_file: bool,
    pub is_dir: bool,
}

impl StatInfo {
    pub fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            identity: Identity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            size: metadata.size(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
            is_file: metadata.is_file(),
            is_dir: metadata.is_dir(),
        })
    }
}
