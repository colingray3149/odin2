//! Pin credential directories and validate open files to prevent symlink escapes and replacement races.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use odin_adapter_core::config::AdapterCredential;
use odin_confined_fs::{Capability, ConfinedError};
use thiserror::Error;

const MAX_CREDENTIAL_FILE_BYTES: usize = 16 * 1024;

const ALLOWED_FILE_MODES: [u32; 2] = [0o400, 0o600];

/// Redacted Debug output prevents credential leakage in diagnostics.
pub struct Secret {
    value: String,
}

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

/// Errors omit file contents so diagnostics cannot expose credentials.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error(
        "credential `{handle}`: configured path `{}` is inside the Nix store",
        .path.display()
    )]
    StorePath { handle: String, path: PathBuf },
    #[error("credential `{handle}`: file `{}` does not exist", .path.display())]
    Missing { handle: String, path: PathBuf },
    #[error("credential `{handle}`: `{}` is not a regular file", .path.display())]
    NotRegularFile { handle: String, path: PathBuf },
    #[error(
        "credential `{handle}`: symlink `{}` resolves to `{}` outside the canonical secret root `{}`",
        .path.display(),
        .resolved.display(),
        .root.display()
    )]
    SymlinkEscape {
        handle: String,
        path: PathBuf,
        resolved: PathBuf,
        root: PathBuf,
    },
    #[error(
        "credential `{handle}`: canonical secret root `{}` is not a numeric sops generation directory",
        .root.display()
    )]
    NotGenerationRoot { handle: String, root: PathBuf },
    #[error(
        "credential `{handle}`: file `{}` has mode {mode:#o}; owner-only 0400 or 0600 required",
        .path.display()
    )]
    InsecurePermissions {
        handle: String,
        path: PathBuf,
        mode: u32,
    },
    #[error(
        "credential `{handle}`: directory `{}` changed while being pinned",
        .path.display()
    )]
    FileReplaced { handle: String, path: PathBuf },
    #[error("credential `{handle}`: file exceeds the {limit}-byte credential ceiling")]
    TooLarge { handle: String, limit: usize },
    #[error("credential `{handle}`: file is not valid UTF-8")]
    InvalidUtf8 { handle: String },
    #[error("credential `{handle}`: file holds an empty credential")]
    EmptyValue { handle: String },
    #[error(
        "credential `{handle}`: filesystem access to `{}` failed",
        .path.display()
    )]
    Io {
        handle: String,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "credential `{handle}`: confined filesystem access to `{}` failed",
        .path.display()
    )]
    Confined {
        handle: String,
        path: PathBuf,
        #[source]
        source: ConfinedError,
    },
}

impl CredentialError {
    /// Strip handles and paths before reporting failures outside the backend host.
    pub fn cause(&self) -> String {
        match self {
            Self::StorePath { .. } => "store_path".to_owned(),
            Self::Missing { .. } => "missing".to_owned(),
            Self::NotRegularFile { .. } => "not_regular_file".to_owned(),
            Self::SymlinkEscape { .. } => "symlink_escape".to_owned(),
            Self::NotGenerationRoot { .. } => "not_generation_root".to_owned(),
            Self::InsecurePermissions { mode, .. } => format!("insecure_mode {mode:o}"),
            Self::FileReplaced { .. } => "file_replaced".to_owned(),
            Self::TooLarge { .. } => "too_large".to_owned(),
            Self::InvalidUtf8 { .. } => "invalid_utf8".to_owned(),
            Self::EmptyValue { .. } => "empty_value".to_owned(),
            Self::Io { source, .. } => format!("io {}", source.kind()),
            Self::Confined { source, .. } => format!("confined {}", source.code()),
        }
    }
}

/// Validate the parent before the leaf so symlinks cannot hide credentials in the public Nix store.
pub fn resolve(credential: &AdapterCredential) -> Result<Secret, CredentialError> {
    let handle = String::from(credential.handle().clone());
    let path = credential.path();
    if is_nix_store_path(path) {
        return Err(CredentialError::StorePath {
            handle,
            path: path.to_path_buf(),
        });
    }

    // Check the canonical parent first so even missing files under store symlinks are rejected.
    let stable_root = path
        .parent()
        .ok_or_else(|| CredentialError::NotRegularFile {
            handle: handle.clone(),
            path: path.to_path_buf(),
        })?;
    let canonical_root = match fs::canonicalize(stable_root) {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CredentialError::Missing {
                handle,
                path: path.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(CredentialError::Io {
                handle,
                path: stable_root.to_path_buf(),
                source: error,
            });
        }
    };
    if is_nix_store_path(&canonical_root) {
        return Err(CredentialError::StorePath {
            handle,
            path: canonical_root,
        });
    }

    let stable = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CredentialError::Missing {
                handle,
                path: path.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(CredentialError::Io {
                handle,
                path: path.to_path_buf(),
                source: error,
            });
        }
    };

    let leaf: OsString = if stable.is_symlink() {
        verify_sops_generation_link(&handle, path, &canonical_root)?
    } else {
        path.file_name()
            .ok_or_else(|| CredentialError::NotRegularFile {
                handle: handle.clone(),
                path: path.to_path_buf(),
            })?
            .to_os_string()
    };
    read_verified(&handle, &canonical_root, &leaf)
}

/// Only sops generation links within the canonical secret root are permitted.
fn verify_sops_generation_link(
    handle: &str,
    path: &Path,
    canonical_root: &Path,
) -> Result<OsString, CredentialError> {
    if !is_numeric_generation_dir(canonical_root) {
        return Err(CredentialError::NotGenerationRoot {
            handle: handle.to_owned(),
            root: canonical_root.to_path_buf(),
        });
    }

    let resolved = fs::canonicalize(path).map_err(|error| CredentialError::Io {
        handle: handle.to_owned(),
        path: path.to_path_buf(),
        source: error,
    })?;
    let resolved_parent = resolved
        .parent()
        .ok_or_else(|| CredentialError::SymlinkEscape {
            handle: handle.to_owned(),
            path: path.to_path_buf(),
            resolved: resolved.clone(),
            root: canonical_root.to_path_buf(),
        })?;
    if resolved_parent != canonical_root {
        return Err(CredentialError::SymlinkEscape {
            handle: handle.to_owned(),
            path: path.to_path_buf(),
            resolved,
            root: canonical_root.to_path_buf(),
        });
    }
    Ok(resolved
        .file_name()
        .ok_or_else(|| CredentialError::SymlinkEscape {
            handle: handle.to_owned(),
            path: path.to_path_buf(),
            resolved: resolved.clone(),
            root: canonical_root.to_path_buf(),
        })?
        .to_os_string())
}

/// Validate directory identity and the open descriptor to detect path replacement during resolution.
fn read_verified(
    handle: &str,
    canonical_root: &Path,
    leaf: &OsStr,
) -> Result<Secret, CredentialError> {
    let io_error = |path: &Path, source| CredentialError::Io {
        handle: handle.to_owned(),
        path: path.to_path_buf(),
        source,
    };
    let confined_error = |path: &Path, source| CredentialError::Confined {
        handle: handle.to_owned(),
        path: path.to_path_buf(),
        source,
    };

    let capability =
        Capability::seal(canonical_root).map_err(|error| confined_error(canonical_root, error))?;
    let pinned = capability.root_identity();
    let current = fs::metadata(canonical_root).map_err(|error| io_error(canonical_root, error))?;
    if pinned.dev != current.dev() || pinned.ino != current.ino() {
        return Err(CredentialError::FileReplaced {
            handle: handle.to_owned(),
            path: canonical_root.to_path_buf(),
        });
    }

    let file = capability
        .open_read(Path::new(leaf))
        .map_err(|error| confined_error(canonical_root, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error(canonical_root, error))?;
    let mode = opened.permissions().mode() & 0o777;
    if !ALLOWED_FILE_MODES.contains(&mode) {
        return Err(CredentialError::InsecurePermissions {
            handle: handle.to_owned(),
            path: canonical_root.join(leaf),
            mode,
        });
    }
    if opened.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
        return Err(CredentialError::TooLarge {
            handle: handle.to_owned(),
            limit: MAX_CREDENTIAL_FILE_BYTES,
        });
    }

    let mut bounded = Vec::new();
    // Read an extra byte to detect growth after the size check rather than silently truncating.
    (&file)
        .take(MAX_CREDENTIAL_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bounded)
        .map_err(|error| io_error(canonical_root, error))?;
    if bounded.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(CredentialError::TooLarge {
            handle: handle.to_owned(),
            limit: MAX_CREDENTIAL_FILE_BYTES,
        });
    }
    let raw = String::from_utf8(bounded).map_err(|_| CredentialError::InvalidUtf8 {
        handle: handle.to_owned(),
    })?;
    let value = raw.trim_end();
    if value.is_empty() {
        return Err(CredentialError::EmptyValue {
            handle: handle.to_owned(),
        });
    }
    Ok(Secret {
        value: value.to_owned(),
    })
}

fn is_nix_store_path(path: &Path) -> bool {
    let mut components = path.components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::RootDir), Some(Component::Normal(first))) if first == OsStr::new("nix")
    ) && components
        .next()
        .is_some_and(|component| component.as_os_str() == OsStr::new("store"))
}

fn is_numeric_generation_dir(canonical_root: &Path) -> bool {
    canonical_root
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use odin_adapter_core::OpaqueCredentialHandle;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn credential(path: &Path) -> AdapterCredential {
        AdapterCredential::new(
            OpaqueCredentialHandle::new("cred:web-search.test").expect("handle parses"),
            path.to_path_buf(),
        )
        .expect("credential builds")
    }

    fn write_mode(path: &Path, contents: &[u8], mode: u32) {
        fs::write(path, contents).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn resolves_plain_owner_only_file_and_trims_trailing_newline() {
        let dir = tempdir().expect("tempdir");
        let key = dir.path().join("brave.key");
        write_mode(&key, b"sk-live-abc123\n", 0o600);

        let secret = resolve(&credential(&key)).expect("resolves");
        assert_eq!(secret.as_str(), "sk-live-abc123");
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
        assert!(!format!("{secret:?}").contains("sk-live-abc123"));
    }

    #[test]
    fn owner_read_only_0400_file_is_accepted() {
        let dir = tempdir().expect("tempdir");
        let key = dir.path().join("brave.key");
        write_mode(&key, b"sk-read-only\n", 0o400);
        let secret = resolve(&credential(&key)).expect("0400 resolves");
        assert_eq!(secret.as_str(), "sk-read-only");
    }

    #[test]
    fn missing_file_is_typed_unavailable() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("absent.key");
        assert!(matches!(
            resolve(&credential(&missing)),
            Err(CredentialError::Missing { .. })
        ));
    }

    #[test]
    fn group_or_world_readable_file_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let key = dir.path().join("loose.key");
        write_mode(&key, b"sk-loose\n", 0o644);
        assert!(matches!(
            resolve(&credential(&key)),
            Err(CredentialError::InsecurePermissions { mode: 0o644, .. })
        ));
    }

    #[test]
    fn executable_or_write_only_owner_modes_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let executable = dir.path().join("exec.key");
        write_mode(&executable, b"sk-exec\n", 0o700);
        assert!(matches!(
            resolve(&credential(&executable)),
            Err(CredentialError::InsecurePermissions { mode: 0o700, .. })
        ));

        let write_only = dir.path().join("writeonly.key");
        write_mode(&write_only, b"sk-writeonly\n", 0o200);
        // Read-open of a write-only file fails with EACCES inside the
        // confined open before the mode policy runs; rejection — not the
        // incidental error variant — is the contract here.
        assert!(resolve(&credential(&write_only)).is_err());
    }

    #[test]
    fn directory_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("mkdir");
        // The confined open descriptor-stats every leaf and rejects
        // non-regular leaves itself; rejection — not the surfaced variant —
        // is the contract.
        assert!(resolve(&credential(&nested)).is_err());
    }

    #[test]
    fn empty_file_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let key = dir.path().join("empty.key");
        write_mode(&key, b"\n", 0o600);
        assert!(matches!(
            resolve(&credential(&key)),
            Err(CredentialError::EmptyValue { .. })
        ));
    }

    #[test]
    fn oversized_file_is_rejected_but_the_ceiling_is_accepted() {
        let dir = tempdir().expect("tempdir");
        let over = dir.path().join("over.key");
        write_mode(&over, &[b'a'; MAX_CREDENTIAL_FILE_BYTES + 1], 0o600);
        assert!(matches!(
            resolve(&credential(&over)),
            Err(CredentialError::TooLarge { .. })
        ));

        let exact = dir.path().join("exact.key");
        write_mode(&exact, &[b'a'; MAX_CREDENTIAL_FILE_BYTES], 0o600);
        let secret = resolve(&credential(&exact)).expect("ceiling size resolves");
        assert_eq!(secret.as_str().len(), MAX_CREDENTIAL_FILE_BYTES);
    }

    #[test]
    fn nix_store_paths_are_rejected_before_any_filesystem_access() {
        let store_key = Path::new("/nix/store/0000000000-key");
        assert!(matches!(
            resolve(&credential(store_key)),
            Err(CredentialError::StorePath { .. })
        ));
    }
    #[test]
    fn nix_store_prefix_grammar_is_exact() {
        assert!(is_nix_store_path(Path::new("/nix/store")));
        assert!(is_nix_store_path(Path::new("/nix/store/abc-key")));
        assert!(!is_nix_store_path(Path::new("/nix/storex/abc-key")));
        assert!(!is_nix_store_path(Path::new("/nix/store.d/abc-key")));
        assert!(!is_nix_store_path(Path::new("/etc/nix/store/abc-key")));
    }

    #[test]
    fn parent_symlink_into_the_nix_store_yields_no_credential() {
        // Public policy: a credential reached through a symlinked stable
        // parent into /nix/store is never returned, whether the canonical
        // parent rejection or the leaf lookup fires first. No store leaf is
        // creatable synthetically, so no credential is the assertion.
        let dir = tempdir().expect("tempdir");
        symlink(Path::new("/nix/store"), dir.path().join("stable")).expect("symlink stable root");
        let through = dir.path().join("stable/brave.key");
        assert!(resolve(&credential(&through)).is_err());
    }

    #[test]
    fn stable_symlink_into_numeric_generation_directory_is_accepted() {
        let dir = tempdir().expect("tempdir");
        let generation = dir.path().join("secrets.d/1");
        fs::create_dir_all(&generation).expect("mkdir -p");
        let key = generation.join("brave.key");
        write_mode(&key, b"sk-generation\n", 0o600);

        // Layout 1: sops-nix stable root `/secrets` -> `/secrets.d/1`,
        // configured leaf stays a regular file through the root symlink.
        symlink(dir.path().join("secrets.d/1"), dir.path().join("secrets"))
            .expect("symlink stable root");
        let through_root = dir.path().join("secrets/brave.key");
        let secret = resolve(&credential(&through_root)).expect("root symlink resolves");
        assert_eq!(secret.as_str(), "sk-generation");

        // Layout 2: stable per-secret symlink resolving inside the same
        // canonical numeric generation directory.
        let alias = generation.join("brave-alias");
        symlink(&key, &alias).expect("symlink alias");
        let secret = resolve(&credential(&alias)).expect("generation symlink resolves");
        assert_eq!(secret.as_str(), "sk-generation");
    }

    /// sops-nix secret directories may allow traversal without directory reads.
    #[test]
    fn a_search_only_sops_generation_resolves() {
        let dir = tempdir().expect("tempdir");
        let generation = dir.path().join("secrets.d/12");
        fs::create_dir_all(&generation).expect("mkdir -p");
        write_mode(&generation.join("BRAVE_API_KEY"), b"sk-brave\n", 0o400);
        symlink(&generation, dir.path().join("secrets")).expect("symlink stable root");
        for search_only in [dir.path().join("secrets.d"), generation.clone()] {
            fs::set_permissions(&search_only, fs::Permissions::from_mode(0o311)).expect("chmod");
        }
        let resolved = resolve(&credential(&dir.path().join("secrets/BRAVE_API_KEY")));
        for readable in [generation, dir.path().join("secrets.d")] {
            fs::set_permissions(&readable, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        assert_eq!(
            resolved.expect("search permission suffices").as_str(),
            "sk-brave"
        );
    }

    #[test]
    fn symlink_escape_outside_the_secret_root_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let other = tempdir().expect("tempdir");
        let generation = dir.path().join("secrets.d/1");
        fs::create_dir_all(&generation).expect("mkdir -p");

        let real = other.path().join("real.key");
        write_mode(&real, b"sk-elsewhere\n", 0o600);
        let link = generation.join("escaped.key");
        symlink(&real, &link).expect("symlink escape");
        assert!(matches!(
            resolve(&credential(&link)),
            Err(CredentialError::SymlinkEscape { .. })
        ));
    }

    #[test]
    fn symlink_through_non_numeric_generation_root_is_rejected() {
        let dir = tempdir().expect("tempdir");
        let plain = dir.path().join("plain");
        fs::create_dir_all(&plain).expect("mkdir");
        let key = plain.join("brave.key");
        write_mode(&key, b"sk-plain\n", 0o600);

        let link = dir.path().join("brave-alias");
        symlink(&key, &link).expect("symlink alias");
        assert!(matches!(
            resolve(&credential(&link)),
            Err(CredentialError::NotGenerationRoot { .. })
        ));
    }
}
