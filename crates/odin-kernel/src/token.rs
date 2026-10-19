//! Kernel ownership of seat-token issuance, validation, and revocation.

use std::collections::BTreeMap;

use odin_domain::token::SeatTokenClaims;
use odin_domain::{
    Digest, DomainError, LaneId, SeatId, SeatToken, SeatTokenId, SessionId, SliceId,
};
use odin_ledger::{encode_utc, Ledger, LedgerError};
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;

const REVOCATION_KIND: &str = "seat_token_revocation";

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("seat-token signing key must not be empty")]
    EmptySigningKey,
    #[error("seat-token entropy must not be empty")]
    EmptyEntropy,
    #[error("invalid seat token: {0}")]
    InvalidToken(#[source] DomainError),
    #[error("seat token expired at {expires_at_ms} ms (current time {now_ms} ms)")]
    Expired { expires_at_ms: u64, now_ms: u64 },
    #[error("seat token {token_id} is revoked")]
    Revoked { token_id: SeatTokenId },
    #[error("seat token belongs to seat {actual}, expected {expected}")]
    WrongSeat { expected: SeatId, actual: SeatId },
    #[error("seat token belongs to slice {actual}, expected {expected}")]
    WrongSlice { expected: SliceId, actual: SliceId },
    #[error("seat token belongs to lane {actual}, expected {expected}")]
    WrongLane { expected: LaneId, actual: LaneId },
    #[error("seat token belongs to session {actual}, expected {expected}")]
    WrongSession {
        expected: SessionId,
        actual: SessionId,
    },
    #[error("seat token has stale seat revision {actual}, expected {expected}")]
    StaleSeatRevision { expected: Digest, actual: Digest },
    #[error("seat token has stale slice revision {actual}, expected {expected}")]
    StaleSliceRevision { expected: Digest, actual: Digest },
    #[error("seat token has stale capability policy {actual}, expected {expected}")]
    StaleCapabilityPolicy { expected: Digest, actual: Digest },
    #[error("seat token has stale context policy {actual}, expected {expected}")]
    StaleContextPolicy { expected: Digest, actual: Digest },
    #[error("millisecond timestamp {0} is outside the supported UTC range")]
    InvalidTimestamp(u64),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
}

/// Callers supply unique, unpredictable entropy because issuance has no random source.
pub struct MintRequest<'a> {
    pub seat: SeatId,
    pub slice: SliceId,
    pub lane: LaneId,
    pub session: SessionId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub capability_policy_digest: Digest,
    pub context_policy_digest: Digest,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub entropy: &'a [u8],
}

#[derive(Clone, Copy)]
pub struct ExpectedBindings<'a> {
    pub seat: &'a SeatId,
    pub slice: &'a SliceId,
    pub lane: &'a LaneId,
    pub session: &'a SessionId,
    pub seat_revision: Digest,
    pub slice_revision: Digest,
    pub capability_policy_digest: Digest,
    pub context_policy_digest: Digest,
}

/// Verified authority. Construction is confined to this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeatAuthority {
    seat: SeatId,
    slice: SliceId,
    lane: LaneId,
    session: SessionId,
    token_id: SeatTokenId,
    seat_revision: Digest,
    slice_revision: Digest,
    capability_policy_digest: Digest,
    context_policy_digest: Digest,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl SeatAuthority {
    #[must_use]
    pub const fn seat(&self) -> &SeatId {
        &self.seat
    }

    #[must_use]
    pub const fn slice(&self) -> &SliceId {
        &self.slice
    }

    #[must_use]
    pub const fn lane(&self) -> &LaneId {
        &self.lane
    }

    #[must_use]
    pub const fn session(&self) -> &SessionId {
        &self.session
    }

    #[must_use]
    pub const fn token_id(&self) -> &SeatTokenId {
        &self.token_id
    }

    #[must_use]
    pub const fn seat_revision(&self) -> Digest {
        self.seat_revision
    }

    #[must_use]
    pub const fn slice_revision(&self) -> Digest {
        self.slice_revision
    }

    #[must_use]
    pub const fn capability_policy_digest(&self) -> Digest {
        self.capability_policy_digest
    }

    #[must_use]
    pub const fn context_policy_digest(&self) -> Digest {
        self.context_policy_digest
    }

    #[must_use]
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    fn from_verified(token: &SeatToken) -> Self {
        Self {
            seat: token.seat.clone(),
            slice: token.slice.clone(),
            lane: token.lane.clone(),
            session: token.session.clone(),
            token_id: token.token_id.clone(),
            seat_revision: token.seat_revision,
            slice_revision: token.slice_revision,
            capability_policy_digest: token.capability_policy_digest,
            context_policy_digest: token.context_policy_digest,
            issued_at_ms: token.issued_at_ms,
            expires_at_ms: token.expires_at_ms,
        }
    }
}

/// Verify on construction and consume by value so authorization cannot survive later revocation.
pub struct FreshAuthority {
    inner: SeatAuthority,
}

impl FreshAuthority {
    pub fn verify<R: RevocationStore>(
        token: &SeatToken,
        expected: ExpectedBindings<'_>,
        signing_key: Vec<u8>,
        revocations: R,
        now_ms: u64,
    ) -> Result<Self, TokenError> {
        let verifier = TokenVerifier::new(signing_key, revocations)?;
        let inner = verifier.verify(token, expected, now_ms)?;
        Ok(Self { inner })
    }

    pub fn get(&self) -> &SeatAuthority {
        &self.inner
    }
}

pub struct TokenIssuer {
    signing_key: Vec<u8>,
}

impl TokenIssuer {
    pub fn new(signing_key: Vec<u8>) -> Result<Self, TokenError> {
        if signing_key.is_empty() {
            return Err(TokenError::EmptySigningKey);
        }
        Ok(Self { signing_key })
    }

    pub fn mint(&self, request: MintRequest<'_>) -> Result<SeatToken, TokenError> {
        self.mint_with(request, None)
    }

    /// Include the snapshot revision so verification can reconstruct the same policy generation.
    pub fn mint_bound(
        &self,
        request: MintRequest<'_>,
        served_revision: u64,
    ) -> Result<SeatToken, TokenError> {
        self.mint_with(request, Some(served_revision))
    }

    fn mint_with(
        &self,
        request: MintRequest<'_>,
        served_revision: Option<u64>,
    ) -> Result<SeatToken, TokenError> {
        if request.entropy.is_empty() {
            return Err(TokenError::EmptyEntropy);
        }
        let entropy_digest = Digest::hash(request.entropy);
        let token_id = SeatTokenId::from_parts("seat-token", request.issued_at_ms, entropy_digest)
            .map_err(TokenError::InvalidToken)?;
        SeatToken::sign(
            SeatTokenClaims {
                seat: request.seat,
                slice: request.slice,
                lane: request.lane,
                session: request.session,
                token_id,
                seat_revision: request.seat_revision,
                slice_revision: request.slice_revision,
                capability_policy_digest: request.capability_policy_digest,
                context_policy_digest: request.context_policy_digest,
                served_revision,
                issued_at_ms: request.issued_at_ms,
                expires_at_ms: request.expires_at_ms,
            },
            &self.signing_key,
        )
        .map_err(TokenError::InvalidToken)
    }
}

/// Revocation authority used by token verification and queue cancellation.
pub trait RevocationStore {
    fn is_revoked(&self, token_id: &SeatTokenId) -> Result<bool, TokenError>;

    /// Records revocation durably before returning to the caller.
    fn revoke(&mut self, token_id: &SeatTokenId, revoked_at_ms: u64) -> Result<(), TokenError>;
}

#[derive(Default)]
pub struct MemoryRevocations {
    revoked: BTreeMap<SeatTokenId, u64>,
}

impl MemoryRevocations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn revoked_at_ms(&self, token_id: &SeatTokenId) -> Option<u64> {
        self.revoked.get(token_id).copied()
    }
}

impl RevocationStore for MemoryRevocations {
    fn is_revoked(&self, token_id: &SeatTokenId) -> Result<bool, TokenError> {
        Ok(self.revoked.contains_key(token_id))
    }

    fn revoke(&mut self, token_id: &SeatTokenId, revoked_at_ms: u64) -> Result<(), TokenError> {
        self.revoked
            .entry(token_id.clone())
            .or_insert(revoked_at_ms);
        Ok(())
    }
}

pub struct LedgerRevocations<'a> {
    ledger: &'a Ledger,
}

impl<'a> LedgerRevocations<'a> {
    #[must_use]
    pub const fn new(ledger: &'a Ledger) -> Self {
        Self { ledger }
    }
}

#[derive(Serialize)]
struct RevocationStatus<'a> {
    token_id: &'a SeatTokenId,
    revoked_at_ms: u64,
}

/// Share revocation lookup so operation transactions and token verification cannot disagree.
pub(crate) fn ledger_token_is_revoked(
    conn: &rusqlite::Connection,
    token_id: &str,
) -> Result<bool, LedgerError> {
    let mut statement = conn.prepare(
        "SELECT 1 FROM materialized_status WHERE object_kind = ?1 AND object_id = ?2 LIMIT 1",
    )?;
    let mut rows = statement.query((REVOCATION_KIND, token_id))?;
    Ok(rows.next()?.is_some())
}

impl RevocationStore for LedgerRevocations<'_> {
    fn is_revoked(&self, token_id: &SeatTokenId) -> Result<bool, TokenError> {
        Ok(ledger_token_is_revoked(
            self.ledger.connection(),
            token_id.as_str(),
        )?)
    }

    fn revoke(&mut self, token_id: &SeatTokenId, revoked_at_ms: u64) -> Result<(), TokenError> {
        let timestamp = timestamp_from_ms(revoked_at_ms)?;
        let status_json = serde_json::to_string(&RevocationStatus {
            token_id,
            revoked_at_ms,
        })
        .map_err(LedgerError::from)?;
        let source_event_id = format!("seat-token-revocation:{token_id}");
        self.ledger
            .connection()
            .execute(
                "INSERT INTO materialized_status (\n                     object_kind, object_id, revision, status_json,\n                     source_event_id, updated_at, stale_after\n                 ) VALUES (?1, ?2, 1, ?3, ?4, ?5, NULL)\n                 ON CONFLICT(object_kind, object_id) DO NOTHING",
                (
                    REVOCATION_KIND,
                    token_id.as_str(),
                    status_json.as_str(),
                    source_event_id.as_str(),
                    timestamp.as_str(),
                ),
            )
            .map_err(LedgerError::from)?;
        Ok(())
    }
}

fn timestamp_from_ms(timestamp_ms: u64) -> Result<String, TokenError> {
    let nanos = i128::from(timestamp_ms) * 1_000_000;
    let timestamp = OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| TokenError::InvalidTimestamp(timestamp_ms))?;
    encode_utc(timestamp).map_err(TokenError::Ledger)
}

pub struct TokenVerifier<R> {
    signing_key: Vec<u8>,
    revocations: R,
}

impl<R: RevocationStore> TokenVerifier<R> {
    pub fn new(signing_key: Vec<u8>, revocations: R) -> Result<Self, TokenError> {
        if signing_key.is_empty() {
            return Err(TokenError::EmptySigningKey);
        }
        Ok(Self {
            signing_key,
            revocations,
        })
    }

    pub fn verify(
        &self,
        token: &SeatToken,
        expected: ExpectedBindings<'_>,
        now_ms: u64,
    ) -> Result<SeatAuthority, TokenError> {
        match token.verify_at(&self.signing_key, now_ms) {
            Ok(()) => {}
            Err(DomainError::TokenExpired {
                expires_at_ms,
                now_ms,
            }) => {
                return Err(TokenError::Expired {
                    expires_at_ms,
                    now_ms,
                });
            }
            Err(error) => return Err(TokenError::InvalidToken(error)),
        }

        if self.revocations.is_revoked(&token.token_id)? {
            return Err(TokenError::Revoked {
                token_id: token.token_id.clone(),
            });
        }
        check_bindings(token, expected)?;
        Ok(SeatAuthority::from_verified(token))
    }

    pub fn revocations(&self) -> &R {
        &self.revocations
    }
}

fn check_bindings(token: &SeatToken, expected: ExpectedBindings<'_>) -> Result<(), TokenError> {
    if &token.seat != expected.seat {
        return Err(TokenError::WrongSeat {
            expected: expected.seat.clone(),
            actual: token.seat.clone(),
        });
    }
    if &token.slice != expected.slice {
        return Err(TokenError::WrongSlice {
            expected: expected.slice.clone(),
            actual: token.slice.clone(),
        });
    }
    if &token.lane != expected.lane {
        return Err(TokenError::WrongLane {
            expected: expected.lane.clone(),
            actual: token.lane.clone(),
        });
    }
    if &token.session != expected.session {
        return Err(TokenError::WrongSession {
            expected: expected.session.clone(),
            actual: token.session.clone(),
        });
    }
    if token.seat_revision != expected.seat_revision {
        return Err(TokenError::StaleSeatRevision {
            expected: expected.seat_revision,
            actual: token.seat_revision,
        });
    }
    if token.slice_revision != expected.slice_revision {
        return Err(TokenError::StaleSliceRevision {
            expected: expected.slice_revision,
            actual: token.slice_revision,
        });
    }
    if token.capability_policy_digest != expected.capability_policy_digest {
        return Err(TokenError::StaleCapabilityPolicy {
            expected: expected.capability_policy_digest,
            actual: token.capability_policy_digest,
        });
    }
    if token.context_policy_digest != expected.context_policy_digest {
        return Err(TokenError::StaleContextPolicy {
            expected: expected.context_policy_digest,
            actual: token.context_policy_digest,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"kernel seat-token signing key";

    fn seat(value: &str) -> SeatId {
        SeatId::new(value).unwrap()
    }

    fn slice(value: &str) -> SliceId {
        SliceId::new(value).unwrap()
    }

    fn lane(value: &str) -> LaneId {
        LaneId::new(value).unwrap()
    }

    fn session(value: &str) -> SessionId {
        SessionId::new(value).unwrap()
    }

    fn mint() -> SeatToken {
        TokenIssuer::new(KEY.to_vec())
            .unwrap()
            .mint(MintRequest {
                seat: seat("seat.alpha"),
                slice: slice("slice.build"),
                lane: lane("lane.primary"),
                session: session("session-1"),
                seat_revision: Digest::hash(b"seat revision"),
                slice_revision: Digest::hash(b"slice revision"),
                capability_policy_digest: Digest::hash(b"capability policy"),
                context_policy_digest: Digest::hash(b"context policy"),
                issued_at_ms: 100,
                expires_at_ms: 200,
                entropy: b"caller supplied entropy",
            })
            .unwrap()
    }

    fn expected<'a>(
        seat: &'a SeatId,
        slice: &'a SliceId,
        lane: &'a LaneId,
        session: &'a SessionId,
    ) -> ExpectedBindings<'a> {
        ExpectedBindings {
            seat,
            slice,
            lane,
            session,
            seat_revision: Digest::hash(b"seat revision"),
            slice_revision: Digest::hash(b"slice revision"),
            capability_policy_digest: Digest::hash(b"capability policy"),
            context_policy_digest: Digest::hash(b"context policy"),
        }
    }

    #[test]
    fn mint_is_deterministic_from_caller_time_and_entropy() {
        let first = mint();
        let second = mint();
        assert_eq!(first.token_id, second.token_id);
        assert_eq!(first.signature, second.signature);
        assert!(first
            .token_id
            .as_str()
            .starts_with("seat-token:100:blake3:"));
    }

    #[test]
    fn valid_token_yields_read_only_authority() {
        let token = mint();
        let seat = seat("seat.alpha");
        let slice = slice("slice.build");
        let lane = lane("lane.primary");
        let session = session("session-1");
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        let authority = verifier
            .verify(&token, expected(&seat, &slice, &lane, &session), 150)
            .unwrap();
        assert_eq!(authority.seat(), &seat);
        assert_eq!(authority.slice(), &slice);
        assert_eq!(authority.lane(), &lane);
        assert_eq!(authority.session(), &session);
        assert_eq!(authority.token_id(), &token.token_id);
        assert_eq!(authority.expires_at_ms(), 200);
    }

    #[test]
    fn tamper_is_rejected_as_invalid_token() {
        let mut token = mint();
        token.slice_revision = Digest::hash(b"tampered");
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        assert!(matches!(
            verifier.verify(
                &token,
                expected(
                    &seat("seat.alpha"),
                    &slice("slice.build"),
                    &lane("lane.primary"),
                    &session("session-1")
                ),
                150
            ),
            Err(TokenError::InvalidToken(_))
        ));
    }

    #[test]
    fn cross_seat_is_rejected_distinctly() {
        let token = mint();
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        assert!(matches!(
            verifier.verify(
                &token,
                expected(
                    &seat("seat.beta"),
                    &slice("slice.build"),
                    &lane("lane.primary"),
                    &session("session-1")
                ),
                150
            ),
            Err(TokenError::WrongSeat { .. })
        ));
    }

    #[test]
    fn wrong_session_is_rejected_distinctly() {
        let token = mint();
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        assert!(matches!(
            verifier.verify(
                &token,
                expected(
                    &seat("seat.alpha"),
                    &slice("slice.build"),
                    &lane("lane.primary"),
                    &session("session-2")
                ),
                150
            ),
            Err(TokenError::WrongSession { .. })
        ));
    }

    #[test]
    fn stale_policy_is_rejected_distinctly() {
        let token = mint();
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        let seat = seat("seat.alpha");
        let slice = slice("slice.build");
        let lane = lane("lane.primary");
        let session = session("session-1");
        let mut bindings = expected(&seat, &slice, &lane, &session);
        bindings.capability_policy_digest = Digest::hash(b"new capability policy");
        assert!(matches!(
            verifier.verify(&token, bindings, 150),
            Err(TokenError::StaleCapabilityPolicy { .. })
        ));
    }

    #[test]
    fn expired_token_is_rejected_distinctly() {
        let token = mint();
        let verifier = TokenVerifier::new(KEY.to_vec(), MemoryRevocations::new()).unwrap();
        assert!(matches!(
            verifier.verify(
                &token,
                expected(
                    &seat("seat.alpha"),
                    &slice("slice.build"),
                    &lane("lane.primary"),
                    &session("session-1")
                ),
                200
            ),
            Err(TokenError::Expired {
                expires_at_ms: 200,
                now_ms: 200
            })
        ));
    }

    #[test]
    fn revoked_token_is_rejected_before_binding_use() {
        let token = mint();
        let mut revocations = MemoryRevocations::new();
        revocations.revoke(&token.token_id, 140).unwrap();
        let verifier = TokenVerifier::new(KEY.to_vec(), revocations).unwrap();
        assert!(matches!(
            verifier.verify(
                &token,
                expected(
                    &seat("seat.beta"),
                    &slice("slice.build"),
                    &lane("lane.primary"),
                    &session("session-1")
                ),
                150
            ),
            Err(TokenError::Revoked { .. })
        ));
    }

    #[test]
    fn ledger_revocation_uses_materialized_status_and_is_idempotent() {
        let token = mint();
        let ledger = Ledger::open_in_memory().unwrap();
        let mut revocations = LedgerRevocations::new(&ledger);
        revocations.revoke(&token.token_id, 140).unwrap();
        revocations.revoke(&token.token_id, 150).unwrap();
        assert!(revocations.is_revoked(&token.token_id).unwrap());

        let (revision, status): (i64, String) = ledger
            .connection()
            .query_row(
                "SELECT revision, status_json FROM materialized_status\n                 WHERE object_kind = ?1 AND object_id = ?2",
                (REVOCATION_KIND, token.token_id.as_str()),
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(revision, 1);
        assert!(status.contains("\"revoked_at_ms\":140"));
    }
}
