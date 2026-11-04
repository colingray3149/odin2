//! Walk through descriptors so path replacement cannot redirect traversal outside the root.

use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags};

use crate::error::{map_errno, map_io_error};
use crate::path::{absolute_components, display_component, display_path, relative_components};
use crate::{ConfinedError, Identity};

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
/// Allow ordinary mount-path symlinks while excluding Linux magic links.
const RESOLVE_MOUNT: ResolveFlags = ResolveFlags::NO_MAGICLINKS;
pub(crate) const RESOLVE_MOUNT_BENEATH: ResolveFlags =
    ResolveFlags::BENEATH.union(ResolveFlags::NO_MAGICLINKS);
const MOUNT_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
pub(crate) const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// Search-only directories need execute permission, not read permission, to reach a secret file.
pub(crate) const SEARCH_FLAGS: OFlags = OFlags::PATH
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
/// NONBLOCK prevents a planted FIFO from hanging before its file type can be checked.
pub(crate) const MOUNT_READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
pub(crate) const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
pub(crate) const WRITE_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// Allow ordinary mount-path symlinks while keeping subsequent child access descriptor-relative.
pub(crate) fn open_absolute_mount_root(path: &Path) -> Result<File, ConfinedError> {
    let components = absolute_components(path)?;
    let mut current = File::open("/").map_err(|error| map_io_error(error, Some("/")))?;
    for component in components {
        let label = display_component(component);
        let descriptor = rustix::fs::openat2(
            &current,
            component,
            MOUNT_DIRECTORY_FLAGS,
            Mode::empty(),
            RESOLVE_MOUNT,
        )
        .map_err(|error| map_errno(error, &label))?;
        current = File::from(descriptor);
    }
    Ok(current)
}

/// Permit in-root ConfigMap `..data` links while rejecting escapes and magic links.
pub(crate) fn open_leaf_beneath(root: &File, path: &Path) -> Result<File, ConfinedError> {
    let label = display_path(path);
    let descriptor = rustix::fs::openat2(
        root,
        path,
        MOUNT_READ_FLAGS,
        Mode::empty(),
        RESOLVE_MOUNT_BENEATH,
    )
    .map_err(|error| map_errno(error, &label))?;
    Ok(File::from(descriptor))
}

/// Intermediate directories need search permission only; `last` controls access to the root.
pub(crate) fn open_absolute_root(path: &Path, last: OFlags) -> Result<File, ConfinedError> {
    let components = absolute_components(path)?;
    let mut current = File::open("/").map_err(|error| map_io_error(error, Some("/")))?;
    let count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let flags = if index + 1 == count {
            last
        } else {
            SEARCH_FLAGS
        };
        current = open_component(&current, component, flags)?;
    }
    Ok(current)
}

/// Intermediate directories need search permission only; `last` controls access to the parent.
pub(crate) fn walk_to_parent<'a>(
    root: &File,
    path: &'a Path,
    last: OFlags,
) -> Result<(File, &'a OsStr), ConfinedError> {
    let mut components = relative_components(path)?;
    let leaf = components.pop().ok_or(ConfinedError::EmptyPath)?;
    let mut current = root
        .try_clone()
        .map_err(|error| map_io_error(error, Some("<root-fd>")))?;
    let count = components.len();
    for (index, component) in components.into_iter().enumerate() {
        let flags = if index + 1 == count {
            last
        } else {
            SEARCH_FLAGS
        };
        current = open_component(&current, component, flags)?;
    }
    Ok((current, leaf))
}

pub(crate) fn open_leaf(
    parent: &File,
    leaf: &OsStr,
    flags: OFlags,
    mode: Mode,
) -> Result<File, ConfinedError> {
    open_component_with_mode(parent, leaf, flags, mode)
}

pub(crate) fn identity(file: &File, component: &str) -> Result<Identity, ConfinedError> {
    Identity::from_file(file).map_err(|error| map_io_error(error, Some(component)))
}

fn open_component(parent: &File, component: &OsStr, flags: OFlags) -> Result<File, ConfinedError> {
    open_component_with_mode(parent, component, flags, Mode::empty())
}

fn open_component_with_mode(
    parent: &File,
    component: &OsStr,
    flags: OFlags,
    mode: Mode,
) -> Result<File, ConfinedError> {
    let label = display_component(component);
    match rustix::fs::openat2(parent, component, flags, mode, RESOLVE) {
        Ok(descriptor) => Ok(File::from(descriptor)),
        Err(error) if error == rustix::io::Errno::NOTDIR && is_symlink(parent, component) => {
            Err(ConfinedError::SymlinkEncountered { component: label })
        }
        Err(error) => Err(map_errno(error, &label)),
    }
}

/// Refine ENOTDIR into a symlink error only after the security-enforcing open has failed.
pub(crate) fn is_symlink(parent: &File, component: &OsStr) -> bool {
    const FILE_TYPE_MASK: u32 = 0o170_000;
    const SYMLINK_TYPE: u32 = 0o120_000;
    rustix::fs::statat(parent, component, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|stat| stat.st_mode & FILE_TYPE_MASK == SYMLINK_TYPE)
}
