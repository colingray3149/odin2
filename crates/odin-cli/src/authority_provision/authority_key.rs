use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use odin_huginn::OdindConfig;
use serde::Serialize;

use super::entropy::os_random_bytes;
use super::private_fs::{open_private_dir, reject_unprovisionable_root, write_private_new};

/// Minimum entropy of the provisioning signing key, enforced identically by
/// the server-side authority provider.
const MIN_SIGNING_KEY_BYTES: usize = 32;
/// Entropy of a freshly generated signing key.
const GENERATED_KEY_BYTES: usize = 48;

/// What `odin authority init` provisioned. Paths only; never key material.
#[derive(Debug, Serialize)]
pub struct AuthorityInitReport {
    pub state_root: PathBuf,
    pub token_root: PathBuf,
    pub verification_key_file: PathBuf,
    pub state_root_created: bool,
    pub token_root_created: bool,
    pub key_created: bool,
    pub key_bytes: usize,
}

/// Provisions the private token directory and verification key described by
/// the strict controller configuration.
///
/// Idempotent and reset-free: an existing regular key file is preserved
/// byte-for-byte and only tightened to 0600, a short or symlinked existing key
/// fails instead of being replaced, and no output ever carries key bytes.
pub fn init(config: &OdindConfig) -> Result<AuthorityInitReport, String> {
    config
        .validate()
        .map_err(|error| format!("controller configuration is invalid: {error}"))?;
    let state_root = config.paths.state_root.as_path();
    let token_root = config.paths.authority_token_root.as_path();
    let key_file = config.paths.authority_verification_key_file.as_path();
    reject_unprovisionable_root(state_root, "runtime state root")?;
    reject_unprovisionable_root(token_root, "authority token root")?;
    reject_unprovisionable_root(key_file, "verification key file")?;
    let state_root_created = !open_private_dir(state_root, "runtime state root")?;
    let token_root_created = !open_private_dir(token_root, "authority token root")?;
    if let Some(key_parent) = key_file.parent() {
        if key_parent != token_root {
            open_private_dir(key_parent, "verification key directory")?;
        }
    }
    let (key_created, key_bytes) = provision_verification_key(key_file)?;
    Ok(AuthorityInitReport {
        state_root: state_root.to_path_buf(),
        token_root: token_root.to_path_buf(),
        verification_key_file: key_file.to_path_buf(),
        token_root_created,
        state_root_created,
        key_created,
        key_bytes,
    })
}

fn provision_verification_key(key_file: &Path) -> Result<(bool, usize), String> {
    loop {
        match fs::symlink_metadata(key_file) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "verification key {} is a symlink; refusing to provision through it",
                        key_file.display()
                    ));
                }
                if !metadata.is_file() {
                    return Err(format!(
                        "verification key {} is not a regular file",
                        key_file.display()
                    ));
                }
                if metadata.nlink() != 1 {
                    return Err(format!(
                        "verification key {} has multiple hard links; refusing authority material that may be exposed elsewhere",
                        key_file.display()
                    ));
                }
                // Unconditional chmod doubles as the ownership gate: a file
                // this account does not own refuses chmod outright.
                fs::set_permissions(key_file, fs::Permissions::from_mode(0o600)).map_err(
                    |error| {
                        if error.kind() == std::io::ErrorKind::PermissionDenied {
                            format!(
                                "verification key {} is not controlled by this account; refusing to provision a key this account cannot protect",
                                key_file.display()
                            )
                        } else {
                            format!("could not protect {}: {error}", key_file.display())
                        }
                    },
                )?;
                let bytes = fs::read(key_file).map_err(|error| {
                    format!(
                        "could not read the existing verification key {}: {error}",
                        key_file.display()
                    )
                })?;
                if bytes.len() < MIN_SIGNING_KEY_BYTES {
                    return Err(format!(
                        "the existing verification key {} holds {} bytes but at least {MIN_SIGNING_KEY_BYTES} are required; replace it explicitly as the operator",
                        key_file.display(),
                        bytes.len()
                    ));
                }
                return Ok((false, bytes.len()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = os_random_bytes(GENERATED_KEY_BYTES)?;
                if write_private_new(key_file, &key)? {
                    return Ok((true, GENERATED_KEY_BYTES));
                }
                // A concurrent initializer won the no-clobber install. Loop
                // once through the existing-key checks and preserve its key.
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect the verification key {}: {error}",
                    key_file.display()
                ));
            }
        }
    }
}

/// Loads the operator-provisioned signing key without ever exposing it in
/// errors beyond its path and length.
pub fn load_signing_key(config: &OdindConfig) -> Result<Vec<u8>, String> {
    let key_file = config.paths.authority_verification_key_file.as_path();
    reject_unprovisionable_root(key_file, "verification key file")?;
    let metadata = fs::symlink_metadata(key_file).map_err(|error| {
        format!(
            "the verification key {} is not provisioned yet; run `odin authority init` first ({error})",
            key_file.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "the verification key {} is a symlink; refusing to read authority material through it",
            key_file.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "the verification key {} is not a regular file",
            key_file.display()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "the verification key {} has multiple hard links; refusing authority material that may be exposed elsewhere",
            key_file.display()
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(format!(
            "the verification key {} does not have mode 0600; run `odin authority init` to protect it",
            key_file.display()
        ));
    }
    let bytes = fs::read(key_file).map_err(|error| {
        format!(
            "could not read the verification key {}: {error}",
            key_file.display()
        )
    })?;
    if bytes.len() < MIN_SIGNING_KEY_BYTES {
        return Err(format!(
            "the verification key {} holds {} bytes but at least {MIN_SIGNING_KEY_BYTES} are required",
            key_file.display(),
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "authority_key_tests.rs"]
mod tests;
