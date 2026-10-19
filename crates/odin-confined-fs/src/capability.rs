//! Distinct write capabilities prevent read-only roots from gaining mutation access.

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{AtFlags, Mode};

use crate::atomic;
use crate::error::{map_errno, map_io_error};
use crate::path::{display_component, display_path, relative_components, validate_relative_path};
use crate::walk::{
    identity, is_symlink, open_absolute_mount_root, open_absolute_root, open_leaf,
    open_leaf_beneath, walk_to_parent, DIRECTORY_FLAGS, READ_FLAGS, RESOLVE_MOUNT_BENEATH,
    SEARCH_FLAGS, WRITE_FLAGS,
};
use crate::{ConfinedError, Identity, StatInfo};

#[derive(Debug)]
pub struct Capability {
    root: File,
    root_identity: Identity,
}

impl Capability {
    pub fn seal(root: &Path) -> Result<Self, ConfinedError> {
        Self::seal_with_barrier(root, || {})
    }

    /// Open the root, run `barrier`, reopen the name, and reject replacement.
    pub fn seal_with_barrier<F>(root: &Path, barrier: F) -> Result<Self, ConfinedError>
    where
        F: FnOnce(),
    {
        let first = open_absolute_root(root, SEARCH_FLAGS)?;
        let expected = identity(&first, "<root-fd>")?;
        barrier();
        let verified = open_absolute_root(root, SEARCH_FLAGS)?;
        let actual = identity(&verified, "<root-fd>")?;
        if actual != expected {
            return Err(ConfinedError::RootSwapped { expected, actual });
        }
        Ok(Self {
            root: verified,
            root_identity: actual,
        })
    }

    pub const fn root_identity(&self) -> Identity {
        self.root_identity
    }

    /// Recheck the declared name so a replaced root cannot keep serving from an orphaned descriptor.
    pub fn verify_declared_root(&self, root: &Path) -> Result<(), ConfinedError> {
        let current = open_absolute_root(root, SEARCH_FLAGS)?;
        let actual = identity(&current, "<root-fd>")?;
        if actual != self.root_identity {
            return Err(ConfinedError::RootSwapped {
                expected: self.root_identity,
                actual,
            });
        }
        Ok(())
    }

    pub fn open_read(&self, path: &Path) -> Result<File, ConfinedError> {
        self.open_read_with_parent_barrier(path, || {})
    }

    /// Use [`Self::open_read`] outside race tests; the barrier permits checking parent replacement.
    pub fn open_read_with_parent_barrier<F>(
        &self,
        path: &Path,
        barrier: F,
    ) -> Result<File, ConfinedError>
    where
        F: FnOnce(),
    {
        validate_relative_path(path)?;
        let (parent, leaf) = walk_to_parent(&self.root, path, SEARCH_FLAGS)?;
        let parent_identity = identity(&parent, &display_path(path))?;
        barrier();
        let file = open_regular_leaf(&parent, leaf, false)?;
        let leaf_identity = identity(&file, &display_component(leaf))?;
        verify_named_parent(&self.root, path, parent_identity)?;
        verify_named_leaf(&self.root, path, leaf_identity)?;
        Ok(file)
    }

    pub fn stat(&self, path: &Path) -> Result<StatInfo, ConfinedError> {
        let file = self.open_read(path)?;
        StatInfo::from_file(&file).map_err(|error| map_io_error(error, Some(&display_path(path))))
    }

    /// Test hook: open the leaf, pause, then reject any observed leaf replacement.
    pub fn stat_with_leaf_barrier<F>(
        &self,
        path: &Path,
        barrier: F,
    ) -> Result<StatInfo, ConfinedError>
    where
        F: FnOnce(),
    {
        validate_relative_path(path)?;
        let (parent, leaf) = walk_to_parent(&self.root, path, SEARCH_FLAGS)?;
        let parent_identity = identity(&parent, &display_path(path))?;
        let file = open_regular_leaf(&parent, leaf, false)?;
        let leaf_identity = identity(&file, &display_component(leaf))?;
        barrier();
        verify_named_parent(&self.root, path, parent_identity)?;
        verify_named_leaf(&self.root, path, leaf_identity)?;
        StatInfo::from_file(&file).map_err(|error| map_io_error(error, Some(&display_path(path))))
    }

    /// Allow ordinary mount-path symlinks while rejecting magic links and root replacement.
    pub fn seal_mount(root: &Path) -> Result<Self, ConfinedError> {
        let first = open_absolute_mount_root(root)?;
        let expected = identity(&first, "<mount-root-fd>")?;
        let verified = open_absolute_mount_root(root)?;
        let actual = identity(&verified, "<mount-root-fd>")?;
        if actual != expected {
            return Err(ConfinedError::RootSwapped { expected, actual });
        }
        Ok(Self {
            root: verified,
            root_identity: actual,
        })
    }

    /// Allow in-root ConfigMap links; inspect only the returned descriptor to avoid path races.
    pub fn open_read_beneath(&self, path: &Path) -> Result<File, ConfinedError> {
        validate_relative_path(path)?;
        let file = open_leaf_beneath(&self.root, path)?;
        let metadata = file
            .metadata()
            .map_err(|error| map_io_error(error, Some(&display_path(path))))?;
        if !metadata.is_file() {
            return Err(ConfinedError::NotARegularFile {
                component: display_path(path),
            });
        }
        Ok(file)
    }
}

/// Preserve root permissions, but require declared-root rechecks before generated-state writes.
#[derive(Debug)]
pub struct GeneratedCapability {
    inner: Capability,
}

impl GeneratedCapability {
    /// Preserve existing directory permissions while rejecting symlinks.
    pub fn seal(root: &Path) -> Result<Self, ConfinedError> {
        let file = open_absolute_root(root, DIRECTORY_FLAGS)?;
        let root_identity = identity(&file, "<root-fd>")?;
        let inner = Capability {
            root: file,
            root_identity,
        };
        inner.verify_declared_root(root)?;
        Ok(Self { inner })
    }

    pub fn verify_declared_root(&self, root: &Path) -> Result<(), ConfinedError> {
        self.inner.verify_declared_root(root)
    }

    pub fn open_read(&self, path: &Path) -> Result<File, ConfinedError> {
        self.inner.open_read(path)
    }

    pub fn create_dirs(&self, path: &Path, permission: u32) -> Result<(), ConfinedError> {
        create_dirs_under(&self.inner.root, path, permission)
    }

    /// Do not follow the replaced leaf's contents.
    pub fn write_atomic(
        &self,
        path: &Path,
        data: &[u8],
        permission: u32,
    ) -> Result<(), ConfinedError> {
        write_atomic_under(&self.inner.root, path, data, permission, || {})
    }

    /// Absence is success; directories cannot be removed here.
    pub fn remove(&self, path: &Path) -> Result<(), ConfinedError> {
        remove_under(&self.inner.root, path)
    }
}

/// A separate write type keeps [`Capability`] read-only; group and other permissions are rejected.
#[derive(Debug)]
pub struct PrivateCapability {
    root: File,
    root_identity: Identity,
}

impl PrivateCapability {
    /// Require a private mode-0700 root before granting write access.
    pub fn seal(root: &Path) -> Result<Self, ConfinedError> {
        let root = open_absolute_root(root, DIRECTORY_FLAGS)?;
        let metadata = root
            .metadata()
            .map_err(|error| map_io_error(error, Some("<private-root-fd>")))?;
        let permission = metadata.mode() & 0o777;
        if permission != 0o700 {
            return Err(ConfinedError::PrivateRootNotPrivate { mode: permission });
        }
        let root_identity = identity(&root, "<private-root-fd>")?;
        Ok(Self {
            root,
            root_identity,
        })
    }

    pub const fn root_identity(&self) -> Identity {
        self.root_identity
    }

    pub fn open_read(&self, path: &Path) -> Result<File, ConfinedError> {
        validate_relative_path(path)?;
        let (parent, leaf) = walk_to_parent(&self.root, path, DIRECTORY_FLAGS)?;
        let parent_identity = identity(&parent, &display_path(path))?;
        let file = open_regular_leaf(&parent, leaf, false)?;
        let leaf_identity = identity(&file, &display_component(leaf))?;
        verify_named_parent(&self.root, path, parent_identity)?;
        verify_named_leaf(&self.root, path, leaf_identity)?;
        Ok(file)
    }

    /// Preserve any existing entry, including a concurrent creator's file.
    pub fn create_exclusive(&self, path: &Path, permission: u32) -> Result<File, ConfinedError> {
        validate_relative_path(path)?;
        let (parent, leaf) = walk_to_parent(&self.root, path, DIRECTORY_FLAGS)?;
        let parent_identity = identity(&parent, &display_path(path))?;
        let result = atomic::create_exclusive(&parent, leaf, permission)?;
        if let Err(error) = verify_named_parent(&self.root, path, parent_identity) {
            atomic::remove_idempotent(&parent, leaf)?;
            return Err(error);
        }
        Ok(result)
    }

    pub fn write_atomic(
        &self,
        path: &Path,
        data: &[u8],
        permission: u32,
    ) -> Result<(), ConfinedError> {
        self.write_atomic_with_barrier(path, data, permission, || {})
    }

    /// Restore or remove the written leaf if its parent moves away during publication.
    fn write_atomic_with_barrier(
        &self,
        path: &Path,
        data: &[u8],
        permission: u32,
        barrier: impl FnOnce(),
    ) -> Result<(), ConfinedError> {
        write_atomic_under(&self.root, path, data, permission, barrier)
    }

    /// Exclusive creation preserves concurrent entries; cleanup touches only this call's entry.
    pub fn create_atomic(
        &self,
        path: &Path,
        data: &[u8],
        permission: u32,
    ) -> Result<(), ConfinedError> {
        validate_relative_path(path)?;
        let (parent, leaf) = walk_to_parent(&self.root, path, DIRECTORY_FLAGS)?;
        let parent_identity = identity(&parent, &display_path(path))?;
        let mut file = atomic::create_exclusive(&parent, leaf, permission)?;
        let written = file
            .write_all(data)
            .and_then(|()| file.sync_all())
            .map_err(|error| map_io_error(error, Some(&display_component(leaf))));
        drop(file);
        if let Err(error) = written {
            atomic::remove_idempotent(&parent, leaf)?;
            return Err(error);
        }
        parent
            .sync_all()
            .map_err(|error| map_io_error(error, Some("<private-parent-fd>")))?;
        verify_named_parent(&self.root, path, parent_identity)
    }

    /// Preserve existing directories and reject symlinks while creating missing components.
    pub fn create_dirs(&self, path: &Path, permission: u32) -> Result<(), ConfinedError> {
        create_dirs_under(&self.root, path, permission)
    }

    /// Absence is success; directories cannot be removed here.
    pub fn remove(&self, path: &Path) -> Result<(), ConfinedError> {
        remove_under(&self.root, path)
    }

    pub fn stat(&self, path: &Path) -> Result<StatInfo, ConfinedError> {
        let file = self.open_read(path)?;
        StatInfo::from_file(&file).map_err(|error| map_io_error(error, Some(&display_path(path))))
    }

    /// Seal from held descriptors so rewalking an absolute mount path cannot escape the root.
    pub fn ensure_dir(root: &Path, relative: &Path) -> Result<Self, ConfinedError> {
        validate_relative_path(relative)?;
        let mut current = open_absolute_mount_root(root)?;
        for component in relative_components(relative)? {
            match rustix::fs::mkdirat(&current, component, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    // Sync the directory entry before publishing anything inside it.
                    current
                        .sync_all()
                        .map_err(|error| map_io_error(error, Some("<private-parent-fd>")))?;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(map_errno(error, &display_component(component))),
            }
            let label = display_component(component);
            // O_DIRECTORY | O_NOFOLLOW reports symlinks as ENOTDIR; refine the error without following.
            let descriptor = rustix::fs::openat2(
                &current,
                component,
                DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_MOUNT_BENEATH,
            )
            .map_err(|error| match error {
                rustix::io::Errno::NOTDIR if is_symlink(&current, component) => {
                    ConfinedError::SymlinkEncountered { component: label }
                }
                error => map_errno(error, &label),
            })?;
            current = File::from(descriptor);
        }
        let metadata = current
            .metadata()
            .map_err(|error| map_io_error(error, Some("<private-root-fd>")))?;
        let permission = metadata.mode() & 0o777;
        if permission != 0o700 {
            return Err(ConfinedError::PrivateRootNotPrivate { mode: permission });
        }
        let root_identity = identity(&current, "<private-root-fd>")?;
        Ok(Self {
            root: current,
            root_identity,
        })
    }

    /// Check the linked inode before syncing; concurrent source replacement must not be published.
    pub fn install_exclusive(&self, from: &Path, to: &Path) -> Result<(), ConfinedError> {
        validate_relative_path(from)?;
        validate_relative_path(to)?;
        let (from_parent, from_leaf) = walk_to_parent(&self.root, from, DIRECTORY_FLAGS)?;
        let source = open_regular_leaf(&from_parent, from_leaf, false)?;
        let source_identity = identity(&source, &display_component(from_leaf))?;
        drop(source);
        let (to_parent, to_leaf) = walk_to_parent(&self.root, to, DIRECTORY_FLAGS)?;
        let to_parent_identity = identity(&to_parent, &display_path(to))?;
        if let Err(error) = rustix::fs::linkat(
            &from_parent,
            from_leaf,
            &to_parent,
            to_leaf,
            AtFlags::empty(),
        ) {
            return Err(map_errno(error, &display_component(to_leaf)));
        }
        // Reopen the destination to detect a source swap between opening and linking.
        let installed = match open_regular_leaf(&to_parent, to_leaf, false) {
            Ok(file) => file,
            Err(error) => {
                let _ = atomic::remove_idempotent(&to_parent, to_leaf);
                let _ = to_parent.sync_all();
                return Err(error);
            }
        };
        let installed_identity = identity(&installed, &display_component(to_leaf))?;
        drop(installed);
        if installed_identity != source_identity {
            atomic::remove_idempotent(&to_parent, to_leaf)?;
            to_parent
                .sync_all()
                .map_err(|error| map_io_error(error, Some("<private-parent-fd>")))?;
            return Err(ConfinedError::FinalLeafRace {
                path: display_path(to),
            });
        }
        to_parent
            .sync_all()
            .map_err(|error| map_io_error(error, Some("<private-parent-fd>")))?;
        verify_named_parent(&self.root, to, to_parent_identity)
    }
}

fn write_atomic_under(
    root: &File,
    path: &Path,
    data: &[u8],
    permission: u32,
    barrier: impl FnOnce(),
) -> Result<(), ConfinedError> {
    validate_relative_path(path)?;
    let (parent, leaf) = walk_to_parent(root, path, DIRECTORY_FLAGS)?;
    let parent_identity = identity(&parent, &display_path(path))?;
    let published = atomic::write_atomic(&parent, leaf, data, permission, || {})?;
    barrier();
    if let Err(error) = verify_named_parent(root, path, parent_identity) {
        published.withdraw(&parent, leaf)?;
        return Err(error);
    }
    published.settle(&parent, leaf)
}

fn create_dirs_under(root: &File, path: &Path, permission: u32) -> Result<(), ConfinedError> {
    validate_relative_path(path)?;
    let mut current = root
        .try_clone()
        .map_err(|error| map_io_error(error, Some("<write-root-fd>")))?;
    for component in relative_components(path)? {
        match rustix::fs::mkdirat(&current, component, Mode::from_raw_mode(permission)) {
            Ok(()) => current
                .sync_all()
                .map_err(|error| map_io_error(error, Some("<write-parent-fd>")))?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(map_errno(error, &display_component(component))),
        }
        current = open_leaf(&current, component, DIRECTORY_FLAGS, Mode::empty())?;
    }
    Ok(())
}

fn remove_under(root: &File, path: &Path) -> Result<(), ConfinedError> {
    validate_relative_path(path)?;
    let (parent, leaf) = walk_to_parent(root, path, DIRECTORY_FLAGS)?;
    let parent_identity = identity(&parent, &display_path(path))?;
    atomic::remove_idempotent(&parent, leaf)?;
    verify_named_parent(root, path, parent_identity)
}

fn open_regular_leaf(
    parent: &File,
    leaf: &std::ffi::OsStr,
    writable: bool,
) -> Result<File, ConfinedError> {
    let flags = if writable { WRITE_FLAGS } else { READ_FLAGS };
    let file = open_leaf(parent, leaf, flags, Mode::empty())?;
    let metadata = file
        .metadata()
        .map_err(|error| map_io_error(error, Some(&display_component(leaf))))?;
    if !metadata.is_file() {
        return Err(ConfinedError::NotARegularFile {
            component: display_component(leaf),
        });
    }
    Ok(file)
}

fn verify_named_parent(root: &File, path: &Path, expected: Identity) -> Result<(), ConfinedError> {
    let actual = walk_to_parent(root, path, SEARCH_FLAGS)
        .and_then(|(parent, _)| identity(&parent, &display_path(path)))
        .map_err(|_| ConfinedError::RenameRace {
            path: display_path(path),
        })?;
    if actual != expected {
        return Err(ConfinedError::RenameRace {
            path: display_path(path),
        });
    }
    Ok(())
}

fn verify_named_leaf(root: &File, path: &Path, expected: Identity) -> Result<(), ConfinedError> {
    let actual = walk_to_parent(root, path, SEARCH_FLAGS)
        .and_then(|(parent, leaf)| open_regular_leaf(&parent, leaf, false))
        .and_then(|file| identity(&file, &display_path(path)))
        .map_err(|_| ConfinedError::FinalLeafRace {
            path: display_path(path),
        })?;
    if actual != expected {
        return Err(ConfinedError::FinalLeafRace {
            path: display_path(path),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_write_into_a_parent_moved_away_is_unlinked_and_refused() {
        let temp = std::env::temp_dir().join(format!("odin-confined-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        let root = temp.join("private");
        std::fs::create_dir_all(root.join("dir")).expect("dirs");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let capability = PrivateCapability::seal(&root).expect("seal");
        let moved = temp.join("moved");
        let refused =
            capability.write_atomic_with_barrier(Path::new("dir/leaf"), b"data", 0o600, || {
                std::fs::rename(root.join("dir"), &moved).expect("move the parent away");
                std::fs::create_dir(root.join("dir")).expect("plant a replacement");
            });
        let leftovers = (moved.join("leaf").exists(), root.join("dir/leaf").exists());
        let _ = std::fs::remove_dir_all(&temp);
        assert!(refused.is_err());
        assert_eq!(leftovers, (false, false));
    }

    #[test]
    fn refused_replacement_restores_existing_page_in_moved_parent() {
        let temp =
            std::env::temp_dir().join(format!("odin-confined-existing-{}", std::process::id()));
        std::fs::create_dir(&temp).expect("exclusive fixture root");
        let root = temp.join("generated");
        std::fs::create_dir_all(root.join("ns")).expect("namespace");
        std::fs::write(root.join("ns/page.md"), b"owner page").expect("owner page");
        let capability = GeneratedCapability::seal(&root).expect("seal");
        let moved = temp.join("moved");
        let result = write_atomic_under(
            &capability.inner.root,
            Path::new("ns/page.md"),
            b"replacement",
            0o600,
            || {
                std::fs::rename(root.join("ns"), &moved).expect("move namespace");
                std::fs::create_dir(root.join("ns")).expect("replacement namespace");
            },
        );
        let original = std::fs::read(moved.join("page.md"));
        let moved_entries = std::fs::read_dir(&moved).expect("moved namespace").count();
        let replacement_entries = std::fs::read_dir(root.join("ns"))
            .expect("namespace")
            .count();
        std::fs::remove_dir_all(&temp).expect("fixture cleanup");
        assert!(matches!(result, Err(ConfinedError::RenameRace { .. })));
        assert_eq!(
            original.expect("original page must survive refusal"),
            b"owner page"
        );
        assert_eq!(
            moved_entries, 1,
            "no replacement or retained temporary may remain"
        );
        assert_eq!(replacement_entries, 0);
    }
}
