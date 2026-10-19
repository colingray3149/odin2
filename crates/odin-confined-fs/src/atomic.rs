use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};

use crate::error::{map_errno, map_io_error};
use crate::path::display_component;
use crate::walk::open_leaf;
use crate::{ConfinedError, Identity};

const CREATE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// Inspect symlinks themselves rather than opening their targets.
const NAME_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
const MAX_TEMP_ATTEMPTS: usize = 32;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn create_exclusive(
    parent: &File,
    leaf: &OsStr,
    permission: u32,
) -> Result<File, ConfinedError> {
    let mode = checked_mode(permission)?;
    let file = open_leaf(parent, leaf, CREATE_FLAGS, mode)?;
    if let Err(error) = rustix::fs::fchmod(&file, mode) {
        drop(file);
        remove_idempotent(parent, leaf)?;
        return Err(map_errno(error, &display_component(leaf)));
    }
    Ok(file)
}

pub(crate) fn remove_idempotent(parent: &File, leaf: &OsStr) -> Result<(), ConfinedError> {
    match rustix::fs::unlinkat(parent, leaf, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(map_errno(error, &display_component(leaf))),
    }
}

/// Retain the replaced leaf under a temporary name until the caller settles or withdraws the write.
pub(crate) fn write_atomic(
    parent: &File,
    leaf: &OsStr,
    data: &[u8],
    permission: u32,
    before_publish: impl FnOnce(),
) -> Result<Published, ConfinedError> {
    let mode = checked_mode(permission)?;
    let (temporary_name, mut temporary) = create_temporary(parent, mode)?;

    let write_result = temporary
        .write_all(data)
        .and_then(|()| temporary.sync_all())
        .and_then(|()| Identity::from_file(&temporary));
    let written = match write_result {
        Ok(written) => written,
        Err(error) => {
            drop(temporary);
            cleanup_after_failure(parent, &temporary_name)?;
            return Err(map_io_error(error, Some(&temporary_name)));
        }
    };
    drop(temporary);

    let renamed = named_entry(parent, leaf).and_then(|entry| {
        let replaced = match entry {
            Some(metadata) if metadata.is_dir() => {
                return Err(ConfinedError::NotADirectory {
                    component: display_component(leaf),
                });
            }
            entry => entry.as_ref().map(entry_identity),
        };
        let flags = if replaced.is_some() {
            RenameFlags::EXCHANGE
        } else {
            RenameFlags::NOREPLACE
        };
        before_publish();
        rustix::fs::renameat_with(parent, temporary_name.as_str(), parent, leaf, flags)
            .map(|()| replaced)
            .map_err(|error| map_errno(error, &display_component(leaf)))
    });
    let replaced = match renamed {
        Ok(replaced) => replaced,
        Err(error) => {
            cleanup_after_failure(parent, &temporary_name)?;
            return Err(error);
        }
    };

    let published = Published {
        name: temporary_name,
        replaced,
        written,
    };
    if let Err(error) = parent.sync_all() {
        let reason = format!("parent sync after publication failed: {error}");
        return Err(match published.replaced {
            Some(_) => published.retained(&reason),
            None => ConfinedError::Io {
                component: display_component(leaf),
                reason,
            },
        });
    }
    Ok(published)
}

/// Retain replaced contents until the caller checks parent and leaf identities.
pub(crate) struct Published {
    name: String,
    replaced: Option<Identity>,
    written: Identity,
}

impl Published {
    /// Check the installed leaf before discarding the retained previous contents.
    pub(crate) fn settle(self, parent: &File, leaf: &OsStr) -> Result<(), ConfinedError> {
        if named_identity(parent, leaf) != Some(self.written) {
            return Err(self.leaf_changed(leaf));
        }
        let Some(replaced) = self.replaced else {
            return Ok(());
        };
        if named_identity(parent, OsStr::new(&self.name)) != Some(replaced) {
            return Err(self.retained("retained previous leaf changed; left in place"));
        }
        cleanup_after_failure(parent, &self.name)?;
        sync_parent(parent)
    }

    /// Restore retained contents only while the destination still names this call's file.
    pub(crate) fn withdraw(self, parent: &File, leaf: &OsStr) -> Result<(), ConfinedError> {
        if named_identity(parent, leaf) != Some(self.written) {
            return Err(self.leaf_changed(leaf));
        }
        let Some(replaced) = self.replaced else {
            remove_idempotent(parent, leaf)?;
            return sync_parent(parent);
        };
        if named_identity(parent, OsStr::new(&self.name)) != Some(replaced) {
            return Err(self.retained("retained previous leaf changed; nothing restored"));
        }
        if let Err(error) = rustix::fs::renameat_with(
            parent,
            self.name.as_str(),
            parent,
            leaf,
            RenameFlags::EXCHANGE,
        ) {
            return Err(self.retained(&format!("restore failed: {error}")));
        }
        if named_identity(parent, OsStr::new(&self.name)) != Some(self.written) {
            return Err(self.retained("restored leaf; unexpected entry left in place"));
        }
        cleanup_after_failure(parent, &self.name)?;
        sync_parent(parent)
    }

    fn leaf_changed(&self, leaf: &OsStr) -> ConfinedError {
        match self.replaced {
            Some(_) => self.retained("published leaf changed; previous leaf retained"),
            None => ConfinedError::FinalLeafRace {
                path: display_component(leaf),
            },
        }
    }

    fn retained(&self, reason: &str) -> ConfinedError {
        ConfinedError::AtomicCleanupFailed {
            component: self.name.clone(),
            reason: reason.to_owned(),
        }
    }
}

/// Inspect the entry without following symlinks; absence alone returns `None`.
fn named_entry(parent: &File, name: &OsStr) -> Result<Option<Metadata>, ConfinedError> {
    match open_leaf(parent, name, NAME_FLAGS, Mode::empty()) {
        Ok(file) => file
            .metadata()
            .map(Some)
            .map_err(|error| map_io_error(error, Some(&display_component(name)))),
        Err(ConfinedError::ComponentMissing { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

fn named_identity(parent: &File, name: &OsStr) -> Option<Identity> {
    match named_entry(parent, name) {
        Ok(Some(metadata)) if !metadata.is_dir() => Some(entry_identity(&metadata)),
        _ => None,
    }
}

fn entry_identity(metadata: &Metadata) -> Identity {
    Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    }
}

fn sync_parent(parent: &File) -> Result<(), ConfinedError> {
    parent
        .sync_all()
        .map_err(|error| map_io_error(error, Some("<private-parent-fd>")))
}

fn checked_mode(permission: u32) -> Result<Mode, ConfinedError> {
    if permission & !0o777 != 0 {
        return Err(ConfinedError::InvalidMode(permission));
    }
    Ok(Mode::from_raw_mode(permission))
}

fn create_temporary(parent: &File, mode: Mode) -> Result<(String, File), ConfinedError> {
    let mut last_name = String::new();
    for _ in 0..MAX_TEMP_ATTEMPTS {
        let name = temporary_name();
        match open_leaf(parent, OsStr::new(&name), CREATE_FLAGS, mode) {
            Ok(file) => {
                if let Err(error) = rustix::fs::fchmod(&file, mode) {
                    drop(file);
                    cleanup_after_failure(parent, &name)?;
                    return Err(map_errno(error, &name));
                }
                return Ok((name, file));
            }
            Err(ConfinedError::AlreadyExists { .. }) => last_name = name,
            Err(error) => return Err(error),
        }
    }
    Err(ConfinedError::AlreadyExists {
        component: last_name,
    })
}

fn temporary_name() -> String {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!(".odin-atomic-{}-{timestamp}-{sequence}", std::process::id())
}

fn cleanup_after_failure(parent: &File, temporary_name: &str) -> Result<(), ConfinedError> {
    match rustix::fs::unlinkat(parent, temporary_name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(ConfinedError::AtomicCleanupFailed {
            component: temporary_name.to_owned(),
            reason: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_created_after_the_absence_check_survives_and_refuses() {
        let temp =
            std::env::temp_dir().join(format!("odin-confined-competing-{}", std::process::id()));
        std::fs::create_dir(&temp).expect("exclusive fixture root");
        let parent = File::open(&temp).expect("parent");
        let result = write_atomic(&parent, OsStr::new("page.md"), b"ours", 0o600, || {
            std::fs::write(temp.join("page.md"), b"competitor").expect("competing creator");
        });
        let competitor = std::fs::read(temp.join("page.md"));
        let entries = std::fs::read_dir(&temp).expect("parent").count();
        std::fs::remove_dir_all(&temp).expect("fixture cleanup");
        assert!(matches!(result, Err(ConfinedError::AlreadyExists { .. })));
        assert_eq!(competitor.expect("competitor survives"), b"competitor");
        assert_eq!(entries, 1, "no temporary may remain");
    }
}
