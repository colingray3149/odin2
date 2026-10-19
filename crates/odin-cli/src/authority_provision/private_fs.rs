use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::OsStr;
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};

use super::entropy::{hex_string, os_random_bytes};

/// Rejects any provisioning root that must never hold private authority
/// material: the Nix store and anything inside a Git worktree.
pub(super) fn reject_unprovisionable_root(path: &Path, role: &str) -> Result<(), String> {
    if path.starts_with("/nix/store") {
        return Err(format!(
            "{role} {} is inside the Nix store; private authority material never lives there",
            path.display()
        ));
    }
    let mut ancestor = Some(path);
    while let Some(current) = ancestor {
        if current.join(".git").exists() {
            return Err(format!(
                "{role} {} is inside the Git worktree at {}; private authority material never lives in a repository",
                path.display(),
                current.display()
            ));
        }
        ancestor = current.parent();
    }
    Ok(())
}

/// Opens the private 0700 directory at `path`, creating the missing tail.
///
/// Every path component is resolved through its own link target: a symlinked
/// component aborts provisioning instead of being provisioned through. An
/// existing directory owned by this operator is tightened to 0700 as part of
/// the user-approved private provisioning; a root this account cannot protect
/// fails instead.
pub(super) fn open_private_dir(path: &Path, role: &str) -> Result<bool, String> {
    let mut walked = PathBuf::new();
    let mut created = false;
    for component in path.components() {
        walked.push(component.as_os_str());
        match fs::symlink_metadata(&walked) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "{role} {} passes through the symlink {}; refusing to provision through it",
                        path.display(),
                        walked.display()
                    ));
                }
                if !metadata.is_dir() {
                    return Err(format!(
                        "{role} component {} is not a directory",
                        walked.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&walked)
                    .map_err(|error| {
                        format!(
                            "could not create private directory {}: {error}",
                            walked.display()
                        )
                    })?;
                fs::set_permissions(&walked, fs::Permissions::from_mode(0o700)).map_err(
                    |error| {
                        format!(
                            "could not protect private directory {}: {error}",
                            walked.display()
                        )
                    },
                )?;
                created = true;
            }
            Err(error) => {
                return Err(format!("could not inspect {}: {error}", walked.display()));
            }
        }
    }
    // The chmod is unconditional even at 0700: a directory this account does
    // not own refuses chmod outright, so the call is also the explicit
    // ownership gate. Ancestor directories are never re-permissioned.
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "{role} {} is not controlled by this account; refusing to provision a private root this account cannot protect",
                path.display()
            )
        } else {
            format!("could not protect {}: {error}", path.display())
        }
    })?;
    Ok(!created)
}

/// Installs `bytes` at `path` as one 0600 file through a same-directory
/// temporary file, `fsync`, and an atomic rename.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} is not a plain file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", hex_string(&os_random_bytes(8)?)));
    let result = (|| -> Result<(), String> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temporary).map_err(|error| {
            format!(
                "could not create the private temporary file at {}: {error}",
                temporary.display()
            )
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("could not protect {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| format!("could not atomically install {}: {error}", path.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("could not sync {}: {error}", parent.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Installs `bytes` as one new 0600 file without ever replacing an existing
/// target. A same-directory hard link is the atomic no-clobber commit point;
/// `false` means another initializer installed the target first.
pub(super) fn write_private_new(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} is not a plain file name", path.display()))?;
    let temporary = parent.join(format!(".{name}.{}.tmp", hex_string(&os_random_bytes(8)?)));
    let result = (|| -> Result<bool, String> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&temporary).map_err(|error| {
            format!(
                "could not create the private temporary file at {}: {error}",
                temporary.display()
            )
        })?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("could not protect {}: {error}", temporary.display()))?;
        file.write_all(bytes)
            .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
        file.sync_all()
            .map_err(|error| format!("could not sync {}: {error}", temporary.display()))?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(false);
            }
            Err(error) => {
                return Err(format!(
                    "could not atomically install the new private file {}: {error}",
                    path.display()
                ));
            }
        }
        fs::remove_file(&temporary)
            .map_err(|error| format!("could not unlink {}: {error}", temporary.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("could not sync {}: {error}", parent.display()))?;
        Ok(true)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

/// One directory held open by descriptor: the retained anchor that every
/// descriptor-relative credential operation below resolves through.
pub(super) struct PrivateDir {
    pub(super) dir: fs::File,
    pub(super) path: PathBuf,
}

/// Opens the parent directory of `file`, keeping one descriptor per
/// component on the way.
///
/// Every component is opened `O_NOFOLLOW|O_DIRECTORY`, so a component
/// swapped to a symlink can never be provisioned through — the kernel
/// refuses it structurally instead of a pathname validation that a mutable
/// ancestor could invalidate afterwards. Missing components are created
/// 0700 by `mkdirat` mode (the umask can only restrict further), and the
/// final directory must be owned by this account and already no broader
/// than 0700 — both validated on the descriptor with `fstat`, never on a
/// re-resolved pathname.
pub(super) fn open_private_parent(file: &Path) -> Result<PrivateDir, String> {
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    let parent = match file.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut current = if parent.is_absolute() {
        fs::File::open("/")
    } else {
        fs::File::open(".")
    }
    .map_err(|error| {
        format!(
            "could not open the private credential parent {}: {error}",
            parent.display()
        )
    })?;
    let mut walked = PathBuf::new();
    for component in parent.components() {
        let name = match component {
            Component::Prefix(_) => continue,
            Component::RootDir | Component::CurDir => {
                walked.push(component.as_os_str());
                continue;
            }
            Component::Normal(name) => name,
            Component::ParentDir => component.as_os_str(),
        };
        walked.push(name);
        match rustix::fs::openat(&current, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => current = fs::File::from(descriptor),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rustix::fs::mkdirat(&current, name, Mode::RWXU).map_err(|error| {
                    format!(
                        "could not create the private credential directory {}: {error}",
                        walked.display()
                    )
                })?;
                current = fs::File::from(
                    rustix::fs::openat(&current, name, DIRECTORY_FLAGS, Mode::empty()).map_err(
                        |error| format!("could not inspect {}: {error}", walked.display()),
                    )?,
                );
            }
            Err(error) => match fs::symlink_metadata(&walked) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(format!(
                        "refusing to enroll through the symlinked directory {}",
                        walked.display()
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(format!("{} is not a directory", walked.display()));
                }
                _ => return Err(format!("could not inspect {}: {error}", walked.display())),
            },
        }
    }
    // Ownership and mode are read off the held descriptor: a directory this
    // account does not own could be re-permissioned or repopulated behind
    // the walk, so the descriptor is the only thing the check can trust.
    let metadata = current
        .metadata()
        .map_err(|error| format!("could not inspect {}: {error}", walked.display()))?;
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(format!(
            "the credential parent {} is not controlled by this account; enroll into a directory this account owns",
            walked.display()
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(format!(
            "the credential parent {} is broader than 0700; enroll into a private directory",
            walked.display()
        ));
    }
    Ok(PrivateDir {
        dir: current,
        path: parent.to_path_buf(),
    })
}

/// One credential staged inside a `PrivateDir`: created at a fresh
/// same-directory name through the descriptors (`O_EXCL|O_NOFOLLOW` at
/// 0600), re-permissioned to exactly 0600 on its own descriptor so the
/// umask cannot leave it narrower, written, and fsynced. Nothing exists at
/// the final credential name yet; a staged file that never installs is
/// removed when dropped.
pub(super) struct StagedFile {
    slot: fs::File,
    slot_path: PathBuf,
    staged_name: String,
}

/// Stages `bytes` for the credential `name` inside `slot` without touching
/// anything at `name` itself.
pub(super) fn stage_private_new(
    slot: &PrivateDir,
    name: &OsStr,
    bytes: &[u8],
) -> Result<StagedFile, String> {
    let name = name.to_str().ok_or_else(|| {
        format!(
            "{} is not a plain file name",
            slot.path.join(name).display()
        )
    })?;
    let staged_name = format!(".{name}.{}.staged", hex_string(&os_random_bytes(8)?));
    let staged = (|| {
        let file = fs::File::from(
            rustix::fs::openat(
                &slot.dir,
                &staged_name,
                OFlags::WRONLY
                    .union(OFlags::CREATE)
                    .union(OFlags::EXCL)
                    .union(OFlags::NOFOLLOW)
                    .union(OFlags::CLOEXEC),
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| {
                format!(
                    "could not create the private staged credential in {}: {error}",
                    slot.path.display()
                )
            })?,
        );
        // Protection lands on the actual created descriptor — never a
        // reopened pathname — before any byte is written.
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(|error| {
            format!(
                "could not protect the private staged credential in {}: {error}",
                slot.path.display()
            )
        })?;
        (&file).write_all(bytes).map_err(|error| {
            format!(
                "could not write the private staged credential in {}: {error}",
                slot.path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "could not sync the private staged credential in {}: {error}",
                slot.path.display()
            )
        })?;
        Ok::<(), String>(())
    })();
    if let Err(error) = staged {
        let _ = rustix::fs::unlinkat(&slot.dir, &staged_name, AtFlags::empty());
        return Err(error);
    }
    let slot_file = slot.dir.try_clone().map_err(|error| {
        let _ = rustix::fs::unlinkat(&slot.dir, &staged_name, AtFlags::empty());
        format!(
            "could not hold the credential directory {}: {error}",
            slot.path.display()
        )
    })?;
    Ok(StagedFile {
        slot: slot_file,
        slot_path: slot.path.clone(),
        staged_name,
    })
}

/// What one staged-file install produced.
pub(super) enum InstallOutcome {
    /// The final name was already occupied; nothing was installed.
    Occupied,
    /// The staged file is installed and the directory entry is durable.
    Durable,
    /// The staged file is installed — the credential is in place, and the
    /// file's own bytes were fsynced at stage time — but the directory
    /// entry's durability could not be confirmed. This is reported, never
    /// rolled back: the in-place credential is valid and stays.
    DurabilityUncertain(String),
}

impl StagedFile {
    /// The one commit step: atomically installs the staged file at `name`
    /// in the slot by renaming through the held descriptors, then fsyncs
    /// the directory descriptor. An occupied `name` is replaced wholesale;
    /// no pathname is ever re-resolved. The install is reported as soon as
    /// the rename lands — a directory-fsync failure is a durability
    /// warning about an installed credential, not a failed install.
    pub(super) fn install_replacing(self, name: &str) -> Result<InstallOutcome, String> {
        rustix::fs::renameat(&self.slot, &self.staged_name, &self.slot, name).map_err(|error| {
            format!(
                "could not install the new credential in {}: {error}",
                self.slot_path.display()
            )
        })?;
        Ok(match self.slot.sync_all() {
            Ok(()) => InstallOutcome::Durable,
            Err(error) => InstallOutcome::DurabilityUncertain(format!(
                "could not sync the credential directory {}: {error}",
                self.slot_path.display()
            )),
        })
    }

    /// Atomically installs the staged file at `name` with a no-clobber
    /// link through the held descriptors, then fsyncs the directory
    /// descriptor. `Occupied` means `name` was already occupied — by a
    /// file, a directory, or a symlink, none of which is ever followed or
    /// replaced. Like `install_replacing`, the install is reported as soon
    /// as the link lands; a directory-fsync failure is a durability
    /// warning about an installed credential, not a failed install.
    pub(super) fn install_new(self, name: &str) -> Result<InstallOutcome, String> {
        match rustix::fs::linkat(
            &self.slot,
            &self.staged_name,
            &self.slot,
            name,
            AtFlags::empty(),
        ) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(InstallOutcome::Occupied);
            }
            Err(error) => {
                return Err(format!(
                    "could not install the new credential in {}: {error}",
                    self.slot_path.display()
                ));
            }
        }
        let _ = rustix::fs::unlinkat(&self.slot, &self.staged_name, AtFlags::empty());
        Ok(match self.slot.sync_all() {
            Ok(()) => InstallOutcome::Durable,
            Err(error) => InstallOutcome::DurabilityUncertain(format!(
                "could not sync the credential directory {}: {error}",
                self.slot_path.display()
            )),
        })
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        // Whatever still exists under the staged name is scratch.
        let _ = rustix::fs::unlinkat(&self.slot, &self.staged_name, AtFlags::empty());
    }
}
