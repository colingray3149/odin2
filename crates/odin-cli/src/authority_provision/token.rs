use std::fs;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use odin_domain::{CommandId, SeatToken, SeatTokenId};
use odin_huginn::OdindConfig;
use odin_kernel::{FreshAuthority, MemoryRevocations, MintRequest, TokenIssuer};
use rustix::fs::{flock, FlockOperation};
use serde::Serialize;

use super::authority_key::load_signing_key;
use super::composition::{compose, expected_bindings, LaunchSelection, SessionComposition};
use super::ensure::TokenReissueReason;
use super::entropy::{os_random_bytes, unix_millis};
use super::private_fs::{open_private_dir, reject_unprovisionable_root, write_private_atomic};
use super::MAX_TOKEN_TTL_SECONDS;

/// Entropy hashed into every token identity.
pub(super) const MINT_ENTROPY_BYTES: usize = 32;

/// What one mint provisioned. Identifiers and paths only; never token bytes.
#[derive(Debug, Serialize)]
pub struct MintReport {
    pub command_id: String,
    pub session: String,
    pub token_id: String,
    pub token_path: PathBuf,
    pub seat: String,
    pub slice: String,
    pub lane: String,
    pub ttl_seconds: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Must match the durable session's generation; `None` denotes legacy authority.
    pub served_revision: Option<u64>,
    pub renewed: bool,
    pub reused_existing: bool,
    /// Absent for first mint, explicit `--renew`, and byte-for-byte reuse.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_reason: Option<TokenReissueReason>,
}

/// Serializes same-session token read/classify/replace across processes:
/// the shared ensure and the operator mint hold this lock so a renewal
/// never interleaves with another writer on the same session.
pub(super) struct SessionTokenLock {
    file: fs::File,
}

impl SessionTokenLock {
    /// Bounded exclusive acquisition: one writer at a time, never an
    /// unbounded wait.
    pub(super) fn acquire(token_root: &Path, session: &str) -> Result<Self, String> {
        let lock_path = token_root.join(format!("{session}.json.lock"));
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&lock_path)
            .map_err(|error| {
                format!(
                    "could not open the session token lock {}: {error}",
                    lock_path.display()
                )
            })?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("could not inspect session token lock: {error}"))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err("session token lock must be one private regular 0600 file".to_owned());
        }
        for _ in 0..50 {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(Self { file }),
                Err(error) if error == rustix::io::Errno::WOULDBLOCK => {}
                Err(error) => {
                    return Err(format!("could not lock session token authority: {error}"))
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(format!(
            "the session token lock {} stayed held by another writer; no authority was read or replaced",
            lock_path.display()
        ))
    }
}

impl Drop for SessionTokenLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::NonBlockingUnlock);
    }
}

/// Removes only the private session token still owned by `token_id`.
///
/// Rollback shares the mint/ensure lock: a renewed token is never removed
/// by an earlier opener. Missing, malformed, unrelated, or unsafe files
/// are preserved and return `false`; I/O and lock failures return errors.
pub fn remove_session_token_if_owned(
    token_path: &Path,
    token_id: &SeatTokenId,
) -> Result<bool, String> {
    let token_root = token_path
        .parent()
        .ok_or_else(|| format!("{} has no token directory", token_path.display()))?;
    let session = token_path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".json"))
        .filter(|session| odin_domain::SessionId::parse(session).is_ok())
        .ok_or_else(|| format!("{} is not a session token filename", token_path.display()))?;
    // Do not create a missing root just to roll back an absent token.
    match fs::symlink_metadata(token_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("could not inspect token directory: {error}")),
        Ok(_) => {}
    }
    reject_unprovisionable_root(token_root, "authority token root")?;
    open_private_dir(token_root, "authority token root")?;
    let _lock = SessionTokenLock::acquire(token_root, session)?;
    let metadata = match fs::symlink_metadata(token_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("could not inspect session token: {error}")),
    };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Ok(false);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(token_path)
        .map_err(|error| format!("could not open session token for rollback: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("could not inspect opened session token: {error}"))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Ok(false);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("could not read session token for rollback: {error}"))?;
    let Ok(token) = serde_json::from_slice::<SeatToken>(&bytes) else {
        return Ok(false);
    };
    if &token.token_id != token_id || token.session.as_str() != session {
        return Ok(false);
    }
    fs::remove_file(token_path)
        .map_err(|error| format!("could not remove owned session token: {error}"))?;
    Ok(true)
}

/// Why the bounded mint refused. Operator callers flatten this to its
/// display; the shared ensure maps it onto its own typed refusals.
#[derive(Debug)]
pub(super) enum MintRejection {
    Provisioning(String),
    /// The exact authenticated previous token was not the file on disk at
    /// replacement time: another writer won and nothing was replaced.
    Superseded {
        token_path: PathBuf,
    },
}

impl std::fmt::Display for MintRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provisioning(message) => formatter.write_str(message),
            Self::Superseded { token_path } => write!(
                formatter,
                "the token at {} changed while the renewal was being minted; no authority was replaced — re-read and retry",
                token_path.display()
            ),
        }
    }
}

/// Mints one bounded signed seat token for an exact session composition.
///
/// The token is written as `<session-id>.json` under the configured private
/// token root — the exact path the server-side authority provider re-reads
/// on every dispatch. An existing token for the same session is replaced
/// only by the explicit `--renew` operator choice, atomically, with fresh
/// entropy and a fresh token identity; there is no automatic renewal and no
/// path around a revoked token other than that explicit replacement. A
/// replacement is issued strictly after the AUTHENTICATED token it replaces
/// — the kernel lease gate orders a same-session re-bind by verified
/// issuance — and never carries a future timestamp: an unpassed prior
/// issuance refuses the mint.
pub fn mint_for_composition(
    config: &OdindConfig,
    composition: &SessionComposition,
    ttl_seconds: u64,
    renew: bool,
) -> Result<MintReport, String> {
    let token_root = config.paths.authority_token_root.as_path();
    reject_unprovisionable_root(token_root, "authority token root")?;
    open_private_dir(token_root, "authority token root")?;
    let _lock = SessionTokenLock::acquire(token_root, composition.session.as_str())?;
    mint_locked(config, composition, ttl_seconds, renew, None).map_err(|error| error.to_string())
}

/// The mint body under the held session lock. `expected_prior` pins the
/// exact previous file a caller authenticated: when it is no longer on disk
/// at replacement time, the mint writes nothing and reports `Superseded`.
pub(super) fn mint_locked(
    config: &OdindConfig,
    composition: &SessionComposition,
    ttl_seconds: u64,
    renew: bool,
    expected_prior: Option<&[u8]>,
) -> Result<MintReport, MintRejection> {
    if ttl_seconds == 0 {
        return Err(MintRejection::Provisioning(
            "ttl-seconds must be positive".to_owned(),
        ));
    }
    if ttl_seconds > MAX_TOKEN_TTL_SECONDS {
        return Err(MintRejection::Provisioning(format!(
            "ttl-seconds {ttl_seconds} exceeds the one-shot ceiling of {MAX_TOKEN_TTL_SECONDS} seconds"
        )));
    }
    let signing_key = load_signing_key(config).map_err(MintRejection::Provisioning)?;
    let token_root = config.paths.authority_token_root.as_path();
    reject_unprovisionable_root(token_root, "authority token root")
        .map_err(MintRejection::Provisioning)?;
    open_private_dir(token_root, "authority token root").map_err(MintRejection::Provisioning)?;
    let token_path = token_root.join(format!("{}.json", composition.session.as_str()));
    let renewed = match fs::symlink_metadata(&token_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(MintRejection::Provisioning(format!(
                    "the token path {} is a symlink; refusing to write authority material through it",
                    token_path.display()
                )));
            }
            if !metadata.is_file() {
                return Err(MintRejection::Provisioning(format!(
                    "the token path {} is not a regular file",
                    token_path.display()
                )));
            }
            if metadata.nlink() != 1 {
                return Err(MintRejection::Provisioning(format!(
                    "the token path {} has multiple hard links; refusing authority material that may be exposed elsewhere",
                    token_path.display()
                )));
            }
            if metadata.permissions().mode() & 0o777 != 0o600 {
                fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).map_err(
                    |error| {
                        MintRejection::Provisioning(format!(
                            "could not protect {}: {error}",
                            token_path.display()
                        ))
                    },
                )?;
            }
            if !renew {
                return Err(MintRejection::Provisioning(format!(
                    "a provisioned token already exists at {}; pass --renew to replace it explicitly",
                    token_path.display()
                )));
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(MintRejection::Provisioning(format!(
                "could not inspect the token path {}: {error}",
                token_path.display()
            )));
        }
    };
    let issued_at_ms = unix_millis().map_err(MintRejection::Provisioning)?;
    if renewed {
        let prior_bytes = fs::read(&token_path).map_err(|error| {
            MintRejection::Provisioning(format!(
                "could not read the replaced token {}: {error}",
                token_path.display()
            ))
        })?;
        // Only a token that authenticates under the provisioning key sets
        // the monotonic floor — a forged file must not steer issuance — and
        // no future-dated authority is ever minted: an unpassed prior
        // issuance refuses the mint instead.
        if let Ok(prior) = serde_json::from_slice::<odin_domain::SeatToken>(&prior_bytes) {
            if prior.verify_signature(&signing_key).is_ok() && issued_at_ms <= prior.issued_at_ms {
                return Err(MintRejection::Provisioning(format!(
                    "the system clock has not passed the replaced token's issuance ({} ms); no future-dated authority is minted — retry",
                    prior.issued_at_ms
                )));
            }
        }
    }
    let expires_at_ms = issued_at_ms.saturating_add(ttl_seconds.saturating_mul(1_000));
    let entropy = os_random_bytes(MINT_ENTROPY_BYTES).map_err(MintRejection::Provisioning)?;
    let token = TokenIssuer::new(signing_key.clone())
        .map_err(|error| {
            MintRejection::Provisioning(format!("token issuer rejected the signing key: {error}"))
        })?
        // Every provisioned token is session-generation bound: the claims
        // carry the published snapshot revision the composition derived its
        // policy digests from, so the verifying daemon recomposes exactly
        // that generation — never its startup material, never current.
        .mint_bound(
            MintRequest {
                seat: composition.seat.clone(),
                slice: composition.slice.clone(),
                lane: composition.lane.clone(),
                session: composition.session.clone(),
                seat_revision: composition.policy.policy.seat_revision,
                slice_revision: composition.policy.policy.slice_revision,
                capability_policy_digest: composition.policy.policy.capability_policy_digest,
                context_policy_digest: composition.policy.context_policy_digest,
                issued_at_ms,
                expires_at_ms,
                entropy: &entropy,
            },
            composition.snapshot_revision,
        )
        .map_err(|error| MintRejection::Provisioning(format!("seat token mint failed: {error}")))?;
    // The minted token must verify against the exact composition it was
    // derived from before it is ever offered to the daemon.
    FreshAuthority::verify(
        &token,
        expected_bindings(composition),
        signing_key,
        MemoryRevocations::default(),
        issued_at_ms,
    )
    .map_err(|error| {
        MintRejection::Provisioning(format!(
            "minted token failed its own composition check: {error}"
        ))
    })?;
    let bytes = serde_json::to_vec_pretty(&token).map_err(|error| {
        MintRejection::Provisioning(format!("could not serialize the seat token: {error}"))
    })?;
    // Serialize the replacement against the exact previous file: another
    // writer winning the window means nothing is written.
    if let Some(expected) = expected_prior {
        let current = fs::read(&token_path).map_err(|error| {
            MintRejection::Provisioning(format!(
                "could not re-read the replaced token {}: {error}",
                token_path.display()
            ))
        })?;
        if current != expected {
            return Err(MintRejection::Superseded {
                token_path: token_path.clone(),
            });
        }
    }
    write_private_atomic(&token_path, &bytes).map_err(MintRejection::Provisioning)?;
    Ok(MintReport {
        command_id: composition.command_id.to_string(),
        session: composition.session.to_string(),
        token_id: token.token_id.to_string(),
        token_path,
        seat: composition.seat.to_string(),
        slice: composition.slice.to_string(),
        lane: composition.lane.to_string(),
        ttl_seconds,
        issued_at_ms,
        expires_at_ms,
        served_revision: token.served_revision,
        renewed,
        reused_existing: false,
        renewal_reason: None,
    })
}

/// Composes and mints in one step: the operator `odin authority mint` path.
/// The operator names the declared launch it provisions authority for; the
/// derivation proves the pair is one the seat declares before any token is
/// written.
pub fn mint(
    config: &OdindConfig,
    seat: &str,
    project: &str,
    command_id: &CommandId,
    selection: LaunchSelection<'_>,
    ttl_seconds: u64,
    renew: bool,
) -> Result<MintReport, String> {
    let composition = compose(config, seat, project, command_id, selection)?;
    mint_for_composition(config, &composition, ttl_seconds, renew)
}

#[cfg(test)]
#[path = "token_tests.rs"]
mod tests;
