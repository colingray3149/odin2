//! Confined, locked per-transfer receipts close the destination-write/ack gap.
use std::fs::File;
use std::path::Path;

use odin_domain::huginn::{FileRoot, HuginnProtocolError, RelativePath};
use odin_domain::Digest;
use serde::{Deserialize, Serialize};

use super::super::roots::{
    create_beneath, invalid_file, open_beneath, open_or_create_dir, open_root_dir,
};

#[derive(Deserialize, Serialize)]
struct Record {
    folder: Option<RelativePath>,
    name: String,
    byte_len: u64,
    digest: Digest,
    saved: Option<RelativePath>,
}

pub(super) struct Receipt {
    _lock: File,
    directory: File,
    record: Record,
    key: String,
}

impl Receipt {
    pub(super) fn open(
        root: &FileRoot,
        folder: Option<&RelativePath>,
        name: &str,
        byte_len: u64,
        digest: Digest,
        id: uuid::Uuid,
    ) -> Result<Self, HuginnProtocolError> {
        let open = || -> std::io::Result<Self> {
            let root = open_root_dir(&root.canonical_path)?;
            let directory = open_or_create_dir(&root, ".odin-saves")?;
            let key = format!("{id}.json");
            let lock_key = format!("{id}.lock");
            match create_beneath(&directory, &lock_key) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
            let lock = open_beneath(
                &directory,
                Path::new(&lock_key),
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
            )?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
            let record = match open_beneath(
                &directory,
                Path::new(&key),
                super::super::roots::read_flags(),
            ) {
                Ok(file) => {
                    if file.metadata()?.len() > 16 * 1024 {
                        return Err(std::io::Error::other("save receipt exceeds its bound"));
                    }
                    serde_json::from_reader(file).map_err(std::io::Error::other)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Record {
                    folder: folder.cloned(),
                    name: name.to_owned(),
                    byte_len,
                    digest,
                    saved: None,
                },
                Err(error) => return Err(error),
            };
            if record.folder.as_ref() != folder
                || record.name != name
                || record.byte_len != byte_len
                || record.digest != digest
            {
                return Err(std::io::Error::other(
                    "transfer id already names a different save",
                ));
            }
            let mut receipt = Self {
                _lock: lock,
                directory,
                record,
                key,
            };
            receipt.persist()?;
            root.sync_all()?;
            Ok(receipt)
        };
        open().map_err(|error| invalid_file(format!("save receipt could not be opened: {error}")))
    }

    fn persist(&mut self) -> std::io::Result<()> {
        let staging = format!("{}.tmp", uuid::Uuid::new_v4());
        let mut file = create_beneath(&self.directory, &staging)?;
        let written = serde_json::to_writer(&mut file, &self.record)
            .map_err(std::io::Error::other)
            .and_then(|()| file.sync_all())
            .and_then(|()| {
                rustix::fs::renameat(&self.directory, &staging, &self.directory, &self.key)
                    .map_err(Into::into)
            });
        if let Err(error) = written {
            let _ = rustix::fs::unlinkat(&self.directory, &staging, rustix::fs::AtFlags::empty());
            return Err(error);
        }
        self.directory.sync_all()
    }

    pub(super) fn reserve(&mut self, saved: &str) -> std::io::Result<()> {
        self.record.saved = Some(RelativePath::parse(saved).map_err(std::io::Error::other)?);
        self.persist()
    }

    pub(super) fn verified_destination(
        &self,
        root: &FileRoot,
    ) -> Result<Option<RelativePath>, HuginnProtocolError> {
        let Some(saved) = &self.record.saved else {
            return Ok(None);
        };
        let (metadata, mut file) = match super::super::browse::open_from_root(root, saved) {
            Ok(opened) => opened,
            // A destination that is gone or no longer a valid save is not a verified one.
            // A read that failed for another reason must not become a second numbered copy.
            Err(error @ HuginnProtocolError::Unavailable { .. }) => return Err(error),
            Err(_) => return Ok(None),
        };
        if metadata.byte_len != self.record.byte_len {
            return Ok(None);
        }
        let mut digest = blake3::Hasher::new();
        digest.update_reader(&mut file).map_err(|error| {
            invalid_file(format!("saved destination cannot be verified: {error}"))
        })?;
        Ok((digest.finalize().as_bytes() == self.record.digest.as_bytes()).then(|| saved.clone()))
    }
}
