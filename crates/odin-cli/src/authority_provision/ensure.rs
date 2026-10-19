// ---------------------------------------------------------------------------
// Ensure and renewal
// ---------------------------------------------------------------------------

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use odin_domain::DomainError;
use odin_huginn::OdindConfig;
use odin_kernel::{FreshAuthority, LedgerRevocations, RevocationStore as _, TokenError};
use odin_ledger::Ledger;
use odin_omp::host_tools::operations::RevisionMaterialSource;

use super::authority_key::load_signing_key;
use super::composition::{expected_bindings, SessionComposition};
use super::entropy::unix_millis;
use super::private_fs::{open_private_dir, reject_unprovisionable_root};
use super::token::{mint_locked, MintRejection, MintReport, SessionTokenLock};
use super::MAX_TOKEN_TTL_SECONDS;

/// Why an installed token that still authenticates is re-issued: typed by
/// construction, never recovered from formatted error text.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenReissueReason {
    /// Lifetime ended; signature, claims, identity, ledger standing hold.
    Expired { expires_at_ms: u64, now_ms: u64 },
    /// The published snapshot rolled under the token; seat/slice/lane/
    /// session identity still matches, so renewal never widens authority.
    PublishedPolicyDrift {
        stale_bindings: Vec<StalePublishedBinding>,
    },
}

/// One published binding an installed token carries that the current
/// composition no longer names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StalePublishedBinding {
    SeatRevision,
    SliceRevision,
    CapabilityPolicy,
    ContextPolicy,
}

impl std::fmt::Display for StalePublishedBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SeatRevision => "seat revision",
            Self::SliceRevision => "slice revision",
            Self::CapabilityPolicy => "capability policy",
            Self::ContextPolicy => "context policy",
        })
    }
}

impl std::fmt::Display for TokenReissueReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired {
                expires_at_ms,
                now_ms,
            } => write!(
                formatter,
                "the token expired at {expires_at_ms} ms (current time {now_ms} ms)"
            ),
            Self::PublishedPolicyDrift { stale_bindings } => {
                let names = stale_bindings
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    formatter,
                    "the published policy rolled under the token: {names} no longer match"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRenewalPolicy {
    /// Operator-driven authority only: expiry and drift refuse typed; the
    /// explicit `odin authority mint --renew` replacement is the only
    /// re-issue.
    OperatorOnly,
    /// Durable-session renewal: once the token authenticates (signature,
    /// claims, seat/slice/lane/session identity, revocation ledger), an
    /// expired or drifted token is re-issued once per call against the
    /// current composition — bounded, same session, issuance strictly after
    /// the replaced token. Revoked, malformed, foreign, and overlong
    /// authority is never re-issued.
    BoundedSameSession,
}

/// Why ensure refused to provision, reuse, or renew the installed token.
/// Every variant names its owning seam; none is ever matched as text.
#[derive(Debug, thiserror::Error)]
pub enum EnsureSessionTokenError {
    /// The token root or installed token file is not the one private
    /// regular 0600 file this seam provisions.
    #[error(
        "the installed token path {token_path} is not one private regular 0600 file: {reason}"
    )]
    UnprovisionedTokenPath { token_path: PathBuf, reason: String },
    #[error("the existing token {token_path} is invalid JSON: {source}")]
    MalformedJson {
        token_path: PathBuf,
        source: serde_json::Error,
    },
    /// The token outlives the one-shot ceiling; it was not provisioned by
    /// this seam and is never reused or renewed.
    #[error(
        "the existing token {token_path} lives {lifetime_seconds} s and exceeds the {max_seconds} s one-shot ceiling; review it and replace it explicitly"
    )]
    Overlong {
        token_path: PathBuf,
        lifetime_seconds: u64,
        max_seconds: u64,
    },
    /// The bytes are not authentic seat authority: signature, claims, or
    /// structure fail. Never re-issued — there is no verified identity to
    /// renew.
    #[error(
        "the installed token {token_path} is not authentic seat authority: {reason}; authority is never re-issued for an unauthentic token"
    )]
    Malformed { token_path: PathBuf, reason: String },
    /// The revocation ledger revoked this token identity. Closed stays
    /// closed: ensure never re-issues revoked authority.
    #[error(
        "seat token {token_id} is revoked in the authority ledger; ensure never re-issues revoked authority (the explicit `odin authority mint --renew` replacement is the only path)"
    )]
    Revoked { token_id: String },
    /// The token binds a different seat, slice, lane, or session than the
    /// composition: foreign authority for this seam, never re-issued even
    /// when expired.
    #[error(
        "the installed token binds {field} {actual} but the composition requires {expected}; foreign authority is never re-issued"
    )]
    ForeignBinding {
        field: &'static str,
        expected: String,
        actual: String,
    },
    /// Automatic renewal is disabled; use `odin authority mint --renew`.
    #[error(
        "the installed token {token_path} was not re-issued ({reason}); no authority was renewed (review it before an explicit `odin authority mint --renew`)"
    )]
    RenewalNotPermitted {
        token_path: PathBuf,
        reason: TokenReissueReason,
    },
    /// The session's bound generation cannot be recomposed from the
    /// retained store (a later declaration moved its launch selection, e.g.
    /// to a provider that revision never knew): the session cannot be
    /// re-armed at its own generation and must be re-opened at the current
    /// revision. Typed so a conversation rolls to a successor instead of
    /// failing every open.
    #[error(
        "the session's bound generation {bound} could not be recomposed from the retained store: {detail}; re-open the session under the current revision"
    )]
    BoundGenerationUnavailable { bound: u64, detail: String },
    #[error("authority provisioning key is unusable: {0}")]
    SigningKey(String),
    #[error("could not use the authority revocation ledger: {0}")]
    Ledger(String),
    #[error("could not read the installed token {token_path}: {source}")]
    Io {
        token_path: PathBuf,
        source: std::io::Error,
    },
    /// The bounded wait for the wall clock to pass the replaced token's
    /// authenticated issuance expired: no future-dated authority is minted.
    #[error(
        "the system clock did not advance past the replaced token's issuance ({prior_issued_at_ms} ms) within {waited_ms} ms; no renewal was minted"
    )]
    ClockBehind {
        prior_issued_at_ms: u64,
        waited_ms: u64,
    },
    /// Another writer replaced the token between classification and
    /// replacement; nothing was written.
    #[error(
        "the token at {token_path} changed while the renewal was being minted; no authority was replaced — retry the ensure"
    )]
    Superseded { token_path: PathBuf },
    /// Operator configuration and token-root provisioning refusals that
    /// precede any token inspection.
    #[error("{0}")]
    Provisioning(String),
}

/// What the layered classification decided about the installed token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InstalledTokenVerdict {
    /// Every binding and the full lifetime still hold; the token is reused
    /// byte-for-byte behind the kernel verifier's final gate.
    Current,
    /// The token authenticates — signature, claims, identity, and ledger
    /// standing — but is expired or carries stale published policy; the
    /// attached typed reason is the only thing a renewal decision may see.
    ReissueEligible(TokenReissueReason),
}

/// The shared authority seam every session uses: the operator `odin session`
/// open, a host-provisioned child, and a recovered durable session all
/// compose against the current published snapshot and ensure their token
/// here. A missing token is minted once. An existing token is reused
/// byte-for-byte only when it fully authenticates against the current
/// composition, revocation ledger, and clock; any re-issue is governed by
/// `renewal` and never happens for revoked, malformed, foreign, or overlong
/// authority. The read/classify/mint path holds the per-session lock.
pub fn ensure_session_token(
    config: &OdindConfig,
    composition: &SessionComposition,
    ttl_seconds: u64,
    renewal: TokenRenewalPolicy,
) -> Result<MintReport, EnsureSessionTokenError> {
    if ttl_seconds == 0 {
        return Err(EnsureSessionTokenError::Provisioning(
            "ttl-seconds must be positive".to_owned(),
        ));
    }
    if ttl_seconds > MAX_TOKEN_TTL_SECONDS {
        return Err(EnsureSessionTokenError::Provisioning(format!(
            "ttl-seconds {ttl_seconds} exceeds the one-shot ceiling of {MAX_TOKEN_TTL_SECONDS} seconds"
        )));
    }
    let token_root = config.paths.authority_token_root.as_path();
    reject_unprovisionable_root(token_root, "authority token root")
        .map_err(EnsureSessionTokenError::Provisioning)?;
    open_private_dir(token_root, "authority token root")
        .map_err(EnsureSessionTokenError::Provisioning)?;
    let _lock = SessionTokenLock::acquire(token_root, composition.session.as_str())
        .map_err(EnsureSessionTokenError::Provisioning)?;
    ensure_locked(config, composition, ttl_seconds, renewal)
}

/// The ensure body under the held session lock: read, classify, reuse
/// behind the kernel verifier, or re-issue through the bounded mint.
fn ensure_locked(
    config: &OdindConfig,
    composition: &SessionComposition,
    ttl_seconds: u64,
    renewal: TokenRenewalPolicy,
) -> Result<MintReport, EnsureSessionTokenError> {
    let token_root = config.paths.authority_token_root.as_path();
    let token_path = token_root.join(format!("{}.json", composition.session.as_str()));
    let metadata = match fs::symlink_metadata(&token_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return mint_locked(config, composition, ttl_seconds, false, None)
                .map_err(map_mint_rejection);
        }
        Err(error) => {
            return Err(EnsureSessionTokenError::Io {
                token_path,
                source: error,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(EnsureSessionTokenError::UnprovisionedTokenPath {
            token_path: token_path.clone(),
            reason: "it is not one regular file".to_owned(),
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(EnsureSessionTokenError::UnprovisionedTokenPath {
            token_path: token_path.clone(),
            reason: format!("its mode is {:o}", metadata.permissions().mode() & 0o777),
        });
    }
    let signing_key = load_signing_key(config).map_err(EnsureSessionTokenError::SigningKey)?;
    let bytes = fs::read(&token_path).map_err(|source| EnsureSessionTokenError::Io {
        token_path: token_path.clone(),
        source,
    })?;
    let token: odin_domain::SeatToken = serde_json::from_slice(&bytes).map_err(|source| {
        EnsureSessionTokenError::MalformedJson {
            token_path: token_path.clone(),
            source,
        }
    })?;
    // The kernel authenticates tokens but does not enforce this lifetime ceiling.
    let lifetime_ms = token.expires_at_ms.saturating_sub(token.issued_at_ms);
    if lifetime_ms > MAX_TOKEN_TTL_SECONDS.saturating_mul(1_000) {
        return Err(EnsureSessionTokenError::Overlong {
            token_path: token_path.clone(),
            lifetime_seconds: lifetime_ms / 1_000,
            max_seconds: MAX_TOKEN_TTL_SECONDS,
        });
    }
    // Session-generation retention: an installed token binds the session's
    // persisted authority generation, and every decision below — reuse or
    // bounded renewal — recomposes THAT retained snapshot from the durable
    // store instead of the caller's current revision. A genuinely new
    // session (no installed token) uses the caller's composition once. A
    // legacy claim-less token keeps its generation only when the retained
    // publications prove it uniquely; a pruned bound generation refuses
    // typed with the re-open remedy — it is never silently moved to
    // current.
    let retained;
    let composition: &SessionComposition =
        if token.served_revision == Some(composition.snapshot_revision) {
            composition
        } else {
            let bound = match token.served_revision {
                Some(revision) => revision,
                None => {
                    let source = crate::runtime_bindings::StoreRevisionMaterial::new(
                        odin_registry::SnapshotStore::new(&config.paths.registry_snapshot),
                        config.clone(),
                    );
                    source.resolve_legacy(&token).map_err(|detail| {
                        EnsureSessionTokenError::Provisioning(format!(
                            "the installed token predates revision binding and no retained \
                             publication proves its generation: {detail}; re-open the session \
                             under the current revision"
                        ))
                    })?
                }
            };
            retained = crate::authority_provision::compose_for_session_at_revision(
                config,
                composition.seat.as_str(),
                composition.project.as_str(),
                &composition.command_id,
                composition.live_session,
                bound,
                crate::authority_provision::LaunchSelection::new(
                    composition.provider.as_str(),
                    composition.model.as_str(),
                ),
            )
            .map_err(
                |error| EnsureSessionTokenError::BoundGenerationUnavailable {
                    bound,
                    detail: error.to_string(),
                },
            )?;
            &retained
        };
    let now_ms = unix_millis().map_err(EnsureSessionTokenError::Provisioning)?;
    let ledger = Ledger::open(config.paths.state_root.join("ledger.sqlite3"))
        .map_err(|error| EnsureSessionTokenError::Ledger(error.to_string()))?;
    let verdict = classify_installed_token(
        &token,
        composition,
        &signing_key,
        &ledger,
        now_ms,
        &token_path,
    )?;
    match verdict {
        InstalledTokenVerdict::Current => {
            // The kernel verifier is the final reuse gate; a disagreement
            // with the classification still fails closed, typed.
            FreshAuthority::verify(
                &token,
                expected_bindings(composition),
                signing_key,
                LedgerRevocations::new(&ledger),
                now_ms,
            )
            .map_err(|error| mapped_kernel_refusal(token_path.clone(), error))?;
            Ok(MintReport {
                command_id: composition.command_id.to_string(),
                session: composition.session.to_string(),
                token_id: token.token_id.to_string(),
                token_path,
                seat: composition.seat.to_string(),
                slice: composition.slice.to_string(),
                lane: composition.lane.to_string(),
                ttl_seconds: lifetime_ms / 1_000,
                issued_at_ms: token.issued_at_ms,
                expires_at_ms: token.expires_at_ms,
                served_revision: token.served_revision,
                renewed: false,
                reused_existing: true,
                renewal_reason: None,
            })
        }
        InstalledTokenVerdict::ReissueEligible(reason) => match renewal {
            TokenRenewalPolicy::OperatorOnly => {
                Err(EnsureSessionTokenError::RenewalNotPermitted { token_path, reason })
            }
            TokenRenewalPolicy::BoundedSameSession => {
                // A same-millisecond renewal waits, bounded, for the wall
                // clock to pass the authenticated prior's issuance: no
                // future-dated authority is ever minted.
                let wait_started = Instant::now();
                while unix_millis().map_err(EnsureSessionTokenError::Provisioning)?
                    <= token.issued_at_ms
                {
                    if wait_started.elapsed() > Duration::from_millis(200) {
                        return Err(EnsureSessionTokenError::ClockBehind {
                            prior_issued_at_ms: token.issued_at_ms,
                            waited_ms: u64::try_from(wait_started.elapsed().as_millis())
                                .unwrap_or(u64::MAX),
                        });
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                // Linearize renewal with revocation: a concurrent revoke either
                // wins before this check or follows the committed replacement.
                let revocation_guard = rusqlite::Transaction::new_unchecked(
                    ledger.connection(),
                    rusqlite::TransactionBehavior::Immediate,
                )
                .map_err(|error| EnsureSessionTokenError::Ledger(error.to_string()))?;
                if LedgerRevocations::new(&ledger)
                    .is_revoked(&token.token_id)
                    .map_err(|error| EnsureSessionTokenError::Ledger(error.to_string()))?
                {
                    return Err(EnsureSessionTokenError::Revoked {
                        token_id: token.token_id.to_string(),
                    });
                }
                let mut report = mint_locked(config, composition, ttl_seconds, true, Some(&bytes))
                    .map_err(map_mint_rejection)?;
                revocation_guard
                    .commit()
                    .map_err(|error| EnsureSessionTokenError::Ledger(error.to_string()))?;
                report.renewal_reason = Some(reason);
                Ok(report)
            }
        },
    }
}

fn map_mint_rejection(rejection: MintRejection) -> EnsureSessionTokenError {
    match rejection {
        MintRejection::Superseded { token_path } => {
            EnsureSessionTokenError::Superseded { token_path }
        }
        MintRejection::Provisioning(message) => EnsureSessionTokenError::Provisioning(message),
    }
}

/// Classifies the installed token in kernel-verifier order — authenticity,
/// revocation, identity bindings, lifetime, published policy — so a
/// re-issue decision is made only about a token whose signature, identity,
/// and ledger standing verified first. Revoked, malformed, and foreign
/// authority refuses here, never renewed even when also expired.
fn classify_installed_token(
    token: &odin_domain::SeatToken,
    composition: &SessionComposition,
    signing_key: &[u8],
    ledger: &Ledger,
    now_ms: u64,
    token_path: &Path,
) -> Result<InstalledTokenVerdict, EnsureSessionTokenError> {
    let expired = match token.verify_at(signing_key, now_ms) {
        Ok(()) => None,
        Err(DomainError::TokenExpired {
            expires_at_ms,
            now_ms,
        }) => Some(TokenReissueReason::Expired {
            expires_at_ms,
            now_ms,
        }),
        Err(error) => {
            return Err(EnsureSessionTokenError::Malformed {
                token_path: token_path.to_path_buf(),
                reason: error.to_string(),
            });
        }
    };
    if LedgerRevocations::new(ledger)
        .is_revoked(&token.token_id)
        .map_err(|error| EnsureSessionTokenError::Ledger(error.to_string()))?
    {
        return Err(EnsureSessionTokenError::Revoked {
            token_id: token.token_id.to_string(),
        });
    }
    let identity = [
        ("seat", token.seat.as_str(), composition.seat.as_str()),
        ("slice", token.slice.as_str(), composition.slice.as_str()),
        ("lane", token.lane.as_str(), composition.lane.as_str()),
        (
            "session",
            token.session.as_str(),
            composition.session.as_str(),
        ),
    ];
    for (field, actual, expected) in identity {
        if actual != expected {
            return Err(EnsureSessionTokenError::ForeignBinding {
                field,
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }
    let mut stale_bindings = Vec::new();
    if token.seat_revision != composition.policy.policy.seat_revision {
        stale_bindings.push(StalePublishedBinding::SeatRevision);
    }
    if token.slice_revision != composition.policy.policy.slice_revision {
        stale_bindings.push(StalePublishedBinding::SliceRevision);
    }
    if token.capability_policy_digest != composition.policy.policy.capability_policy_digest {
        stale_bindings.push(StalePublishedBinding::CapabilityPolicy);
    }
    if token.context_policy_digest != composition.policy.context_policy_digest {
        stale_bindings.push(StalePublishedBinding::ContextPolicy);
    }
    if let Some(reason) = expired {
        // Kernel precedence: a lifetime failure outranks drift reporting,
        // and one bounded re-issue cures both against the same identity.
        return Ok(InstalledTokenVerdict::ReissueEligible(reason));
    }
    if !stale_bindings.is_empty() {
        return Ok(InstalledTokenVerdict::ReissueEligible(
            TokenReissueReason::PublishedPolicyDrift { stale_bindings },
        ));
    }
    Ok(InstalledTokenVerdict::Current)
}

/// Maps the kernel verifier's typed refusal onto this seam's typed error:
/// a classification/verifier disagreement still fails closed, typed.
fn mapped_kernel_refusal(token_path: PathBuf, error: TokenError) -> EnsureSessionTokenError {
    match error {
        TokenError::EmptySigningKey => {
            EnsureSessionTokenError::SigningKey("the signing key must not be empty".to_owned())
        }
        TokenError::EmptyEntropy => EnsureSessionTokenError::Provisioning(
            "the seat-token mint entropy must not be empty".to_owned(),
        ),
        TokenError::InvalidToken(error) => EnsureSessionTokenError::Malformed {
            token_path,
            reason: error.to_string(),
        },
        TokenError::Expired {
            expires_at_ms,
            now_ms,
        } => EnsureSessionTokenError::RenewalNotPermitted {
            token_path,
            reason: TokenReissueReason::Expired {
                expires_at_ms,
                now_ms,
            },
        },
        TokenError::Revoked { token_id } => EnsureSessionTokenError::Revoked {
            token_id: token_id.to_string(),
        },
        TokenError::WrongSeat { expected, actual } => foreign_binding("seat", expected, actual),
        TokenError::WrongSlice { expected, actual } => foreign_binding("slice", expected, actual),
        TokenError::WrongLane { expected, actual } => foreign_binding("lane", expected, actual),
        TokenError::WrongSession { expected, actual } => {
            foreign_binding("session", expected, actual)
        }
        TokenError::StaleSeatRevision { .. } => {
            policy_drift(token_path, StalePublishedBinding::SeatRevision)
        }
        TokenError::StaleSliceRevision { .. } => {
            policy_drift(token_path, StalePublishedBinding::SliceRevision)
        }
        TokenError::StaleCapabilityPolicy { .. } => {
            policy_drift(token_path, StalePublishedBinding::CapabilityPolicy)
        }
        TokenError::StaleContextPolicy { .. } => {
            policy_drift(token_path, StalePublishedBinding::ContextPolicy)
        }
        TokenError::InvalidTimestamp(ms) => EnsureSessionTokenError::Malformed {
            token_path,
            reason: format!("millisecond timestamp {ms} is outside the supported UTC range"),
        },
        TokenError::Ledger(error) => EnsureSessionTokenError::Ledger(error.to_string()),
    }
}

fn foreign_binding(
    field: &'static str,
    expected: impl std::fmt::Display,
    actual: impl std::fmt::Display,
) -> EnsureSessionTokenError {
    EnsureSessionTokenError::ForeignBinding {
        field,
        expected: expected.to_string(),
        actual: actual.to_string(),
    }
}

fn policy_drift(token_path: PathBuf, stale: StalePublishedBinding) -> EnsureSessionTokenError {
    EnsureSessionTokenError::RenewalNotPermitted {
        token_path,
        reason: TokenReissueReason::PublishedPolicyDrift {
            stale_bindings: vec![stale],
        },
    }
}

#[cfg(test)]
#[path = "ensure_tests.rs"]
mod tests;
